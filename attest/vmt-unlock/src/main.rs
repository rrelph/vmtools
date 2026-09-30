//! vmt-unlock: verify a stage 0 guest's attestation report, then, and only
//! then, release its disk key (design/attested-unlock-design.md, sections 7
//! and 8).

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
usage: vmt-unlock [options] [user@]host

  --step              explain each stage and check, and wait for Enter
                      before each one (for your first unlock)
  -p, --port N        the unlock service's port (default 2222)
  -J, --jump DEST     reach it through DEST (ssh -J); nothing depends on DEST
  -i, --identity FILE your member key; its certificate is FILE-cert.pub
      --org-ca FILE   your organization's CA public key (required): the VM
                      must have been started for exactly this CA
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
3 connection or protocol error, nothing sent; 4 the VM refused the passphrase
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
    target: ssh::Target,
    key: KeySource,
    /// host_data the report must carry, from --org-ca.
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
        (false, 2222u16, None, None, None, None);
    let mut org_ca: Option<PathBuf> = None;
    let (mut measurements, mut min_tcb, mut min_abi, mut smt_allowed, mut chip_ids) =
        (vec![], None, (0, 0), true, vec![]);
    let (mut cache, mut proxy, mut offline, mut save) = (kds::default_cache(), None, false, None);
    #[cfg(feature = "fault-injection")]
    let mut inject_stale_nonce = false;
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or_else(|| Fail::Usage(format!("{a} needs a value")));
        match a.as_str() {
            "--step" => step = true,
            "-p" | "--port" => port = val()?.parse().map_err(|_| u("bad --port"))?,
            "-J" | "--jump" => jump = Some(val()?),
            "-i" | "--identity" => identity = Some(PathBuf::from(val()?)),
            "--key-file" => key_file = Some(val()?),
            "--org-ca" => org_ca = Some(PathBuf::from(val()?)),
            "--measurement" => measurements.push(
                unhex(&val()?)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| u("--measurement: 96 hex digits"))?,
            ),
            "--min-tcb" => {
                min_tcb = Some(Tcb::parse(&val()?).ok_or_else(|| u("--min-tcb: B:T:S:M, decimal"))?)
            }
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
    let dest = dest.ok_or_else(|| u("no destination given"))?;
    let (user, host) = match dest.split_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => ("root".to_string(), dest),
    };
    if measurements.is_empty() {
        return Err(u("at least one --measurement is required"));
    }
    let org_ca = org_ca.ok_or_else(|| u("--org-ca is required: your organization's CA public key"))?;
    let ca_text =
        fs::read_to_string(&org_ca).map_err(|e| Fail::Usage(format!("{}: {e}", org_ca.display())))?;
    let ca_lines: Vec<&str> = ca_text.lines().filter(|l| !l.trim().is_empty()).collect();
    let [ca_line] = ca_lines[..] else {
        return Err(Fail::Usage(format!("{}: expected exactly one public key line", org_ca.display())));
    };
    let ca_blob = ed25519_blob_from_line(ca_line)
        .ok_or_else(|| Fail::Usage(format!("{}: not an ssh-ed25519 public key", org_ca.display())))?;
    let host_data = snp::binding::host_data_for_ca(&ca_blob);
    let key = match key_file.as_deref() {
        Some("-") => KeySource::Stdin,
        Some(f) => KeySource::File(PathBuf::from(f)),
        None if std::env::var_os(PASSPHRASE_ENV).is_some() => KeySource::Env,
        None => KeySource::Prompt,
    };
    Ok(Opts {
        step,
        target: ssh::Target { user, host, port, jump, identity },
        key,
        host_data,
        measurements,
        min_tcb: min_tcb.ok_or_else(|| u("--min-tcb is required"))?,
        min_abi,
        smt_allowed,
        chip_ids,
        kds: kds::Kds { cache, proxy, offline },
        save,
        #[cfg(feature = "fault-injection")]
        inject_stale_nonce,
    })
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
    for c in &verdict.checks {
        ui.check(c);
    }
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
