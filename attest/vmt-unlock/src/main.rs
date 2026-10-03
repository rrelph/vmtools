//! vmt-unlock: verify a stage 0 guest's attestation report, then, and only
//! then, release its disk key (design/attested-unlock-design.md, sections 7
//! and 8).

mod config;
mod expiry;
mod explain;
mod kds;
mod ssh;
mod ui;

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use snp::binding::NONCE_LEN;
use snp::certs::AmdChain;
use snp::codec::{hex, unhex};
use snp::report::{Report, Tcb};
use snp::sshkey::{ed25519_blob_from_line, fingerprint};
use snp::verify::{Expectations, verify};

use ui::Ui;

const USAGE: &str = "\
usage: vmt-unlock [options] <server>
       vmt-unlock [options] [user@]host

  <server> is a folder of yours, ~/.config/vmt-unlock/<server>/, whose
  `config` names the VM, your key, the server unlock key and the accepted
  measurements (one per line; a rollover adds one). Options given here
  override it. Without one, give host and every required option.

  --step              explain each stage and check, and wait for Enter
                      before each one (for your first unlock)
  -p, --port N        the unlock service's port (default 2222)
  -J, --jump DEST     reach it through DEST (ssh -J); nothing depends on DEST
  -i, --identity FILE your SSH key; its certificate is FILE-cert.pub unless
                      --certificate says otherwise
      --certificate FILE your certificate from the server unlock key. With
                      none, when your key IS the server unlock key (a solo
                      server), one valid for five minutes is signed for this
                      unlock through your SSH agent
      --unlock-key FILE the server unlock key, public half (required): the
                      VM must have been started for exactly this key
                      (--org-ca is the same option, by its old name)
      --measurement HEX an accepted launch measurement (required; repeat
                      for more than one)
      --min-tcb B:T:S:M minimum bootloader:tee:snp:microcode (required)
      --min-abi MAJ.MIN minimum guest policy ABI (default 0.0)
      --no-smt        refuse a policy that allows SMT
      --chip-id HEX   accept only this chip (repeatable; default any)
      --key-file FILE read the disk passphrase from FILE, byte for byte
                      (- for standard input). Otherwise it comes from
                      $VMT_UNLOCK_PASSPHRASE if set, or is asked for, once
                      every check has passed.
      --vcek-cache DIR default $XDG_CACHE_HOME/vmt-unlock/vcek
      --kds-proxy URL curl --proxy for AMD KDS, e.g. socks5h://127.0.0.1:9050
      --offline       use saved AMD certificates only; never contact AMD
      --save DIR      keep the nonce, report, host key and verdict in DIR.
                      On a failed check they are kept anyway, in
                      ./vmt-unlock-evidence-<time>/ unless --save is given.
  -h, --help          this text
  -V, --version       the version

exit status: 0 unlocked; 1 a check failed, nothing sent; 2 usage;
3 connection or protocol error, nothing sent; 4 the VM did not unlock
(it refused the passphrase, or could not start the unlocked system)
";

/// Where the disk passphrase comes from. Read only after every check passes,
/// except a file, which is read first so a wrong path fails before anything
/// connects.
enum KeySource {
    File(PathBuf),
    Stdin,
    Env,
    Prompt,
}

const PASSPHRASE_ENV: &str = "VMT_UNLOCK_PASSPHRASE";

struct Opts {
    step: bool,
    /// The <server> whose config was read, if any.
    server: Option<String>,
    target: ssh::Target,
    key: KeySource,
    /// host_data the report must carry, from the server unlock key.
    host_data: [u8; 32],
    measurements: Vec<[u8; 48]>,
    min_tcb: Tcb,
    min_abi: (u8, u8),
    smt_allowed: bool,
    chip_ids: Vec<[u8; 64]>,
    kds: kds::Kds,
    save: Option<PathBuf>,
    #[cfg(feature = "fault-injection")]
    inject_stale_nonce: bool,
}

enum Fail {
    Usage(String),
    Checks,
    Transport(String),
    Refused(String),
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("vmt-unlock {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let t0 = Instant::now();
    let r = parse_args(args).and_then(run);
    let code = match r {
        Ok(()) => 0,
        Err(Fail::Usage(m)) => {
            eprintln!("vmt-unlock: {m}\n(vmt-unlock --help lists the options)");
            2
        }
        Err(Fail::Checks) => {
            eprintln!("vmt-unlock: VERIFICATION FAILED. The disk passphrase was not sent.");
            1
        }
        Err(Fail::Transport(m)) => {
            eprintln!("vmt-unlock: {m}\nvmt-unlock: the disk passphrase was not sent.");
            3
        }
        Err(Fail::Refused(m)) => {
            eprintln!("vmt-unlock: the VM did not unlock: {m}");
            4
        }
    };
    println!("vmt-unlock: total {} ms", t0.elapsed().as_millis());
    ExitCode::from(code)
}

fn parse_args(args: Vec<String>) -> Result<Opts, Fail> {
    let u = |m: &str| Fail::Usage(m.to_string());
    let mut it = args.into_iter();
    let (mut step, mut port, mut jump, mut identity, mut key_file, mut dest) =
        (false, None, None, None, None, None);
    let (mut unlock_key, mut certificate): (Option<PathBuf>, Option<PathBuf>) = (None, None);
    let (mut measurements, mut min_tcb, mut min_abi, mut smt_allowed, mut chip_ids): (
        Vec<String>,
        _,
        _,
        _,
        _,
    ) = (vec![], None, (0, 0), true, vec![]);
    let (mut cache, mut proxy, mut offline, mut save) = (kds::default_cache(), None, false, None);
    #[cfg(feature = "fault-injection")]
    let mut inject_stale_nonce = false;
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or_else(|| Fail::Usage(format!("{a} needs a value")));
        match a.as_str() {
            "--step" => step = true,
            "-p" | "--port" => port = Some(val()?.parse().map_err(|_| u("bad --port"))?),
            "-J" | "--jump" => jump = Some(val()?),
            "-i" | "--identity" => identity = Some(PathBuf::from(val()?)),
            "--certificate" => certificate = Some(PathBuf::from(val()?)),
            "--key-file" => key_file = Some(val()?),
            "--unlock-key" | "--org-ca" => unlock_key = Some(PathBuf::from(val()?)),
            "--measurement" => measurements.push(val()?),
            "--min-tcb" => min_tcb = Some(val()?),
            "--min-abi" => {
                let v = val()?;
                let (a, b) = v.split_once('.').ok_or_else(|| u("--min-abi: MAJOR.MINOR"))?;
                min_abi =
                    (a.parse().map_err(|_| u("bad --min-abi"))?, b.parse().map_err(|_| u("bad --min-abi"))?);
            }
            "--no-smt" => smt_allowed = false,
            "--chip-id" => chip_ids.push(
                unhex(&val()?)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| u("--chip-id: 128 hex digits"))?,
            ),
            "--vcek-cache" => cache = PathBuf::from(val()?),
            "--kds-proxy" => proxy = Some(val()?),
            "--offline" => offline = true,
            "--save" => save = Some(PathBuf::from(val()?)),
            #[cfg(feature = "fault-injection")]
            "--inject" => match val()?.as_str() {
                "stale-nonce" => inject_stale_nonce = true,
                other => return Err(Fail::Usage(format!("--inject: unknown fault {other:?}"))),
            },
            s if s.starts_with('-') => return Err(Fail::Usage(format!("unknown option {s}"))),
            _ if dest.is_none() => dest = Some(a),
            _ => return Err(u("more than one destination")),
        }
    }
    let dest = dest.ok_or_else(|| u("no server or destination given"))?;

    // <server>: a config of the owner's, which options given here override.
    // Measurements given here replace the config's rather than adding to them.
    let server = match config::find(&dest) {
        Some(f) => Some(config::load(&dest, &f).map_err(Fail::Usage)?),
        None => None,
    };
    let (mut user, host) = match (&server, dest.split_once('@')) {
        (Some(s), _) => (s.user.clone(), s.host.clone()),
        (None, Some((u, h))) => (Some(u.to_string()), h.to_string()),
        (None, None) => (None, dest.clone()),
    };
    if let Some(s) = &server {
        port = port.or(s.port);
        jump = jump.or_else(|| s.jump.clone());
        identity = identity.or_else(|| s.identity.clone());
        unlock_key = unlock_key.or_else(|| s.unlock_key.clone());
        certificate = certificate.or_else(|| s.certificate.clone());
        min_tcb = min_tcb.or_else(|| s.min_tcb.clone());
        if measurements.is_empty() {
            measurements = s.measurements.clone();
        }
    }
    let user = user.take().unwrap_or_else(|| "root".to_string());
    let where_ = server.as_ref().map(|s| format!(" (in {})", s.file.display())).unwrap_or_default();

    let measurements = measurements
        .iter()
        .map(|m| {
            unhex(m)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| Fail::Usage(format!("measurement{where_}: expected 96 hex digits, got {m:?}")))
        })
        .collect::<Result<Vec<[u8; 48]>, Fail>>()?;
    if measurements.is_empty() {
        return Err(Fail::Usage(format!("at least one measurement is required{where_}")));
    }
    let min_tcb = min_tcb.ok_or_else(|| Fail::Usage(format!("--min-tcb is required{where_}")))?;
    let min_tcb = Tcb::parse(&min_tcb).ok_or_else(|| u("min-tcb: B:T:S:M, decimal"))?;
    let unlock_key = unlock_key
        .ok_or_else(|| Fail::Usage(format!("the server unlock key is required (--unlock-key){where_}")))?;
    let ca_blob = one_key(&unlock_key)?;
    let host_data = snp::binding::host_data_for_ca(&ca_blob);

    // An organization server's certificate ends on a date. Say so before it
    // does, and refuse once it has, naming the date, rather than leave the
    // reader a bare "permission denied" from the connection.
    if let Some(c) = &certificate {
        check_certificate_expiry(c)?;
    }

    // A solo server: the owner's own SSH key is the server unlock key, and no
    // certificate is configured, so one is signed for this unlock through the
    // agent (ssh.rs). Only when the key really is the unlock key: anyone else
    // needs a certificate from whoever holds it.
    let solo = match (&certificate, &identity) {
        (None, Some(id)) => {
            let pubf = PathBuf::from(format!("{}.pub", id.display()));
            fs::metadata(&pubf).is_ok() && one_key(&pubf)? == ca_blob
        }
        _ => false,
    };
    let key = match key_file.as_deref() {
        Some("-") => KeySource::Stdin,
        Some(f) => KeySource::File(PathBuf::from(f)),
        None if std::env::var_os(PASSPHRASE_ENV).is_some() => KeySource::Env,
        None => KeySource::Prompt,
    };
    Ok(Opts {
        step,
        server: server.map(|s| s.name),
        target: ssh::Target {
            user,
            host,
            port: port.unwrap_or(2222),
            jump,
            identity,
            certificate,
            solo: solo.then_some(unlock_key),
        },
        key,
        host_data,
        measurements,
        min_tcb,
        min_abi,
        smt_allowed,
        chip_ids,
        kds: kds::Kds { cache, proxy, offline },
        save,
        #[cfg(feature = "fault-injection")]
        inject_stale_nonce,
    })
}

/// Warn when the certificate in `f` ends within 30 days; refuse once it has
/// ended. A file that cannot be read or is not a certificate is left to
/// OpenSSH, which names what is wrong with it.
fn check_certificate_expiry(f: &std::path::Path) -> Result<(), Fail> {
    let Ok(text) = fs::read_to_string(f) else {
        return Ok(());
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    match expiry::check(&text, now) {
        expiry::Expiry::Fine => {}
        expiry::Expiry::Soon { date, days } => eprintln!(
            "vmt-unlock: warning: your certificate ({}) ends on {date}, in {days} day{}. \
             Whoever holds the server unlock key must sign you a new one before then.",
            f.display(),
            if days == 1 { "" } else { "s" }
        ),
        expiry::Expiry::Over { date } => {
            return Err(Fail::Usage(format!(
                "your certificate ({}) ended on {date}, so the VM would refuse it. \
                 Whoever holds the server unlock key must sign you a new one.",
                f.display()
            )));
        }
    }
    Ok(())
}

/// The one ssh-ed25519 public key in a file, as its wire blob.
fn one_key(f: &std::path::Path) -> Result<Vec<u8>, Fail> {
    let text = fs::read_to_string(f).map_err(|e| Fail::Usage(format!("{}: {e}", f.display())))?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let [line] = lines[..] else {
        return Err(Fail::Usage(format!("{}: expected exactly one public key line", f.display())));
    };
    ed25519_blob_from_line(line)
        .ok_or_else(|| Fail::Usage(format!("{}: not an ssh-ed25519 public key", f.display())))
}

fn nonce() -> Result<Vec<u8>, Fail> {
    let mut n = vec![0; NONCE_LEN];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut n))
        .map_err(|e| Fail::Transport(format!("/dev/urandom: {e}")))?;
    Ok(n)
}

/// `attest <nonce>` over the session: the report, and the host key the guest
/// says it bound (for comparison only; the binding is checked against the
/// session's key).
fn attest(s: &ssh::Session, nonce: &[u8]) -> Result<(Vec<u8>, String), Fail> {
    let out = s.run(&["attest", &hex(nonce)], None).map_err(Fail::Transport)?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Fail::Transport(format!("attest failed: {}", err.trim())));
    }
    parse_attest_reply(&text)
        .ok_or_else(|| Fail::Transport("attest: the reply is not in the stage 0 format".into()))
}

/// Exactly three lines: `stage0-attest 1`, `host-key <type> <base64>`,
/// `report <hex>`. Anything else is refused whole.
fn parse_attest_reply(text: &str) -> Option<(Vec<u8>, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let [first, key, report] = lines[..] else { return None };
    if first != "stage0-attest 1" {
        return None;
    }
    let key = key.strip_prefix("host-key ")?;
    let report = unhex(report.strip_prefix("report ")?)?;
    Some((report, key.to_string()))
}

fn read_key(src: &KeySource) -> Result<Vec<u8>, Fail> {
    let k = match src {
        KeySource::File(p) => fs::read(p).map_err(|e| Fail::Usage(format!("{}: {e}", p.display())))?,
        KeySource::Stdin => {
            let mut v = Vec::new();
            std::io::stdin().read_to_end(&mut v).map_err(|e| Fail::Usage(format!("stdin: {e}")))?;
            v
        }
        KeySource::Env => std::env::var(PASSPHRASE_ENV)
            .map_err(|_| Fail::Usage(format!("{PASSPHRASE_ENV} is not valid text")))?
            .into_bytes(),
        KeySource::Prompt => ui::read_passphrase("Disk passphrase: ").map_err(Fail::Usage)?,
    };
    if k.is_empty() {
        return Err(Fail::Usage("the disk passphrase is empty".into()));
    }
    Ok(k)
}

fn run(o: Opts) -> Result<(), Fail> {
    let mut ui = Ui::new(o.step);
    // A file is read first, so a wrong path fails before anything connects.
    // The other sources are read only once every check has passed.
    let mut early_key = match &o.key {
        KeySource::File(_) => Some(read_key(&o.key)?),
        _ => None,
    };
    let chain = AmdChain::milan().map_err(|e| Fail::Transport(format!("pinned AMD certificates: {e}")))?;
    if o.step {
        println!("{}", explain::INTRO);
    }

    let t = &o.target;
    ui.stage("connecting to your VM", explain::CONNECT);
    if let Some(name) = &o.server {
        ui.say(&format!("server {name}"));
    }
    if t.solo.is_some() {
        ui.say("a solo server: signing this unlock's certificate with your key, through your SSH agent");
    }
    let via = t.jump.as_ref().map(|j| format!(" via {j}")).unwrap_or_default();
    ui.say(&format!("connecting to {}@{}:{}{via}", t.user, t.host, t.port));
    let tc = Instant::now();
    let s = ssh::Session::open(o.target.clone()).map_err(Fail::Transport)?;
    let ms_connect = tc.elapsed().as_millis();
    ui.say(&format!("this session's host key: {}", fingerprint(&s.host_key)));

    ui.stage("asking your VM to prove what it is", explain::ATTEST);
    #[cfg_attr(not(feature = "fault-injection"), allow(unused_mut))]
    let mut n = nonce()?;
    let ta = Instant::now();
    ui.say(&format!("attest, nonce {}", hex(&n)));
    let (raw, claimed) = attest(&s, &n)?;
    #[cfg(feature = "fault-injection")]
    if o.inject_stale_nonce {
        // A genuine report from this guest and session, but for an earlier
        // nonce: what a replay would present. Take a second one for a fresh
        // nonce and check the first against it.
        n = nonce()?;
        ui.say(&format!(
            "INJECTED FAULT stale-nonce: second attest, nonce {}; checking the first report against it",
            hex(&n)
        ));
        let _ = attest(&s, &n)?;
    }
    let ms_attest = ta.elapsed().as_millis();
    let r = match Report::parse(&raw) {
        Ok(r) => r,
        Err(e) => {
            // Not a connection problem: the VM sent something that is not a
            // report this tool can check. That is a failed verification.
            ui.say(&format!("the report cannot be read: {e}"));
            ui.alert("STOP: the report cannot be checked", explain::FAILED);
            keep_evidence(&ui, &o, &n, &raw, &s, None, None)?;
            return Err(Fail::Checks);
        }
    };
    match ed25519_blob_from_line(&claimed) {
        Some(b) if b == s.host_key => {}
        Some(b) => ui.say(&format!(
            "WARNING: the VM says its host key is {}, but this session is talking to {}",
            fingerprint(&b),
            fingerprint(&s.host_key)
        )),
        None => ui.say("WARNING: the VM's claimed host key is not an Ed25519 key"),
    }
    ui.say(&format!("report: version {}, measurement {}", r.version, hex(&r.measurement)));

    ui.stage("getting AMD's certificate for your VM's processor", explain::VCEK);
    let tv = Instant::now();
    let (vcek, src) = o.kds.vcek(&r, &chain).map_err(Fail::Transport)?;
    let ms_vcek = tv.elapsed().as_millis();
    match &src {
        kds::Source::Cache(p) => ui.say(&format!("VCEK from the cache: {}", p.display())),
        kds::Source::Fetched(u) => ui.say(&format!("VCEK fetched from AMD KDS: {u}")),
    }

    ui.stage("checking the proof", explain::CHECKS);
    let exp = Expectations {
        host_data: o.host_data,
        nonce: n,
        session_host_key: s.host_key.clone(),
        measurements: o.measurements.clone(),
        min_tcb: o.min_tcb,
        min_abi: o.min_abi,
        smt_allowed: o.smt_allowed,
        chip_ids: o.chip_ids.clone(),
    };
    let tc = Instant::now();
    let verdict = verify(&r, &vcek, &chain, &exp);
    let ms_verify = tc.elapsed().as_millis();
    ui.say("checks:");
    ui.checks(&verdict.checks);
    let timing = |ui: &Ui, ms_unlock: &str| {
        ui.say(&format!(
            "timing: connect {ms_connect} ms, attest {ms_attest} ms, VCEK {ms_vcek} ms, verify {ms_verify} ms{ms_unlock}"
        ))
    };
    if !verdict.passed() {
        ui.alert("STOP: a check failed", explain::FAILED);
        keep_evidence(&ui, &o, &exp.nonce, &raw, &s, Some(&vcek), Some(&verdict.to_string()))?;
        timing(&ui, "");
        return Err(Fail::Checks);
    }
    if let Some(d) = &o.save {
        save(d, &exp.nonce, &raw, &s, Some(&vcek), Some(&verdict.to_string()))?;
    }

    ui.stage("sending your disk passphrase", explain::PASSED);
    ui.say("every check passed; sending the disk passphrase");
    let mut key = match early_key.take() {
        Some(k) => k,
        None => read_key(&o.key)?,
    };
    let tu = Instant::now();
    let out = s.run(&["unlock"], Some(&key));
    key.fill(0);
    let out = out.map_err(Fail::Transport)?;
    timing(&ui, &format!(", unlock {} ms", tu.elapsed().as_millis()));
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !text.starts_with("stage0-unlock 1\nunlocked ") {
        return Err(Fail::Refused(String::from_utf8_lossy(&out.stderr).trim().to_string()));
    }
    ui.say(&format!("VM: {}", text.lines().nth(1).unwrap_or("")));
    ui.note(explain::DONE);
    Ok(())
}

fn save(
    d: &std::path::Path,
    nonce: &[u8],
    raw: &[u8],
    s: &ssh::Session,
    vcek: Option<&[u8]>,
    verdict: Option<&str>,
) -> Result<(), Fail> {
    let w =
        |n: &str, b: &[u8]| fs::write(d.join(n), b).map_err(|e| Fail::Transport(format!("saving {n}: {e}")));
    fs::create_dir_all(d).map_err(|e| Fail::Transport(format!("{}: {e}", d.display())))?;
    w("nonce.bin", nonce)?;
    w("report.bin", raw)?;
    w("session-hostkey.pub", format!("{}\n", s.host_key_line).as_bytes())?;
    if let Some(v) = vcek {
        w("vcek.der", v)?;
    }
    if let Some(v) = verdict {
        w("verdict.txt", v.as_bytes())?;
    }
    Ok(())
}

/// On a failed check: keep what the tool saw, where --save said, or in a new
/// directory under the current one.
fn keep_evidence(
    ui: &Ui,
    o: &Opts,
    nonce: &[u8],
    raw: &[u8],
    s: &ssh::Session,
    vcek: Option<&[u8]>,
    verdict: Option<&str>,
) -> Result<(), Fail> {
    let d = o.save.clone().unwrap_or_else(|| {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        PathBuf::from(format!("vmt-unlock-evidence-{t}"))
    });
    save(&d, nonce, raw, s, vcek, verdict)?;
    ui.say(&format!("evidence kept in {}", d.display()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_attest_reply;

    #[test]
    fn attest_reply_is_parsed_strictly() {
        let good = "stage0-attest 1\nhost-key ssh-ed25519 AAAA\nreport 00ff\n";
        assert_eq!(parse_attest_reply(good), Some((vec![0, 0xff], "ssh-ed25519 AAAA".to_string())));
        for bad in [
            "stage0-attest 2\nhost-key ssh-ed25519 AAAA\nreport 00ff\n",
            "stage0-attest 1\nhost-key ssh-ed25519 AAAA\nreport 0g\n",
            "stage0-attest 1\nreport 00ff\nhost-key ssh-ed25519 AAAA\n",
            "stage0-attest 1\nhost-key ssh-ed25519 AAAA\nreport 00ff\nextra\n",
            "",
        ] {
            assert_eq!(parse_attest_reply(bad), None, "{bad:?}");
        }
    }
}
