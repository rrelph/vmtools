//! stage0-agent: the only program a guest owner can reach in stage 0.
//!
//! sshd runs it as its ForceCommand, so the one input it takes from the
//! network is `SSH_ORIGINAL_COMMAND`, plus stdin for `unlock`
//! (design/attested-unlock-design.md, section 7):
//!
//!   attest <64 hex digits>   REPORT_DATA = SHA-512(nonce || host key blob),
//!                            a report at VMPL 0 through configfs-tsm; prints
//!                            the host public key and the report. No
//!                            certificates: the guest owner fetches those.
//!   unlock                   the disk key on stdin, straight into
//!                            `cryptsetup open`; then checks that the root
//!                            holds this kernel's modules (section 10.1),
//!                            locking the disk again if not; prints the result.
//!
//! It writes nothing that outlives it except, after a successful unlock, the
//! flag that releases the boot (`UNLOCKED`), which holds no secret. The key is
//! never written to a file: it goes from the SSH channel to cryptsetup's
//! stdin. Stage 0's init-bottom script removes everything under `/run/stage0`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use snp::binding::{NONCE_LEN, host_data_for_ca, report_data_for};
use snp::codec::{hex, unhex};
use snp::report::Report;
use snp::sshkey::ed25519_blob_from_line;

const HOST_KEY_PUB: &str = "/run/stage0/host_ed25519.pub";
const LOCK: &str = "/run/stage0/unlock.lock";
const UNLOCKED: &str = "/run/stage0/unlocked";
const TSM_REPORTS: &str = "/sys/kernel/config/tsm/report";
const CRYPTSETUP: &str = "/usr/sbin/cryptsetup";
const LVM: &str = "/usr/sbin/lvm";
const MOUNT: &str = "/usr/bin/mount";
const UMOUNT: &str = "/usr/bin/umount";
/// Where the unlocked root is mounted, read-only, for the modules check.
const ROOT_CHECK: &str = "/run/stage0/root-check";
/// Stage 0 opens the volume under its own name; init-bottom renames it to
/// the name the guest's /etc/crypttab expects, once that is readable.
const MAPPER_NAME: &str = "stage0_crypt";
const MAX_KEY: usize = 8192;
/// Output format version, first line of every successful reply.
const PROTOCOL: &str = "1";

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    // Two ways in. sshd's ForceCommand runs the agent with no arguments, and
    // the request comes in SSH_ORIGINAL_COMMAND. Stage 0's own boot script
    // runs it with --check-host-data, before sshd exists; no SSH session can
    // pass arguments, so that mode is not reachable from the network.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = if let [flag, ca] = &args[..]
        && flag == "--check-host-data"
    {
        check_host_data(Path::new(ca))
    } else if !args.is_empty() {
        Err("usage: stage0-agent [--check-host-data <org CA public key file>]".into())
    } else {
        let cmd = std::env::var("SSH_ORIGINAL_COMMAND").unwrap_or_default();
        let words: Vec<&str> = cmd.split_ascii_whitespace().collect();
        match words[..] {
            ["attest", nonce] => attest(nonce),
            ["unlock"] => unlock(),
            _ => Err("usage: attest <64 hex digits> | unlock".into()),
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stage0: error: {e}");
            kmsg(&format!("request refused: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// A line on the guest's kernel log, which the serial console shows. Never
/// anything secret.
fn kmsg(msg: &str) {
    // One write per record: /dev/kmsg makes a log line of each write(2).
    if let Ok(mut k) = OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = k.write_all(format!("<5>stage0-agent: {msg}\n").as_bytes());
    }
}

fn attest(nonce_hex: &str) -> Result<()> {
    let nonce = unhex(nonce_hex).filter(|n| n.len() == NONCE_LEN).ok_or("the nonce must be 64 hex digits")?;
    let line = fs::read_to_string(HOST_KEY_PUB).map_err(|e| format!("{HOST_KEY_PUB}: {e}"))?;
    let blob = ed25519_blob_from_line(&line).ok_or("the host key is not an Ed25519 public key")?;
    let rd = report_data_for(&nonce, &blob);
    let raw = tsm_report(&rd)?;

    // Not a security check (the guest owner makes those), only a guard
    // against returning a report that cannot be what was asked for.
    let r = Report::parse(&raw).map_err(|e| e.to_string())?;
    if r.report_data != rd || r.vmpl != 0 {
        return Err("the firmware returned a report for other REPORT_DATA or VMPL".into());
    }

    let mut key_fields = line.split_whitespace();
    let (kt, kb) = (key_fields.next().unwrap_or(""), key_fields.next().unwrap_or(""));
    let mut out = io::stdout().lock();
    writeln!(out, "stage0-attest {PROTOCOL}")
        .and_then(|_| writeln!(out, "host-key {kt} {kb}"))
        .and_then(|_| writeln!(out, "report {}", hex(&raw)))
        .and_then(|_| out.flush())
        .map_err(|e| format!("writing the reply: {e}"))?;
    kmsg("attestation report served");
    Ok(())
}

/// Stage 0's self-check (design section 6, step 3.3): the org CA the host
/// passed in fw_cfg must be the one whose hash the host put in host_data at
/// launch, which this guest's own report states. A mismatch means sshd would
/// trust a CA other than the one the guest owner will check for, so stage 0
/// stops before starting it.
fn check_host_data(ca_file: &Path) -> Result<()> {
    let text = fs::read_to_string(ca_file).map_err(|e| format!("{}: {e}", ca_file.display()))?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let [line] = lines[..] else {
        return Err(format!(
            "{}: expected exactly one public key line, found {}",
            ca_file.display(),
            lines.len()
        ));
    };
    let blob = ed25519_blob_from_line(line).ok_or("the org CA is not an ssh-ed25519 public key")?;
    let want = host_data_for_ca(&blob);
    // Any REPORT_DATA will do: only host_data is read. Fresh, so the report
    // is this launch's.
    let raw = tsm_report(&[0; 64])?;
    let r = Report::parse(&raw).map_err(|e| e.to_string())?;
    if r.vmpl != 0 {
        return Err("the report is not from VMPL 0".into());
    }
    if r.host_data != want {
        return Err(format!(
            "the org CA from fw_cfg hashes to {}, but this guest's host_data is {}",
            hex(&want),
            hex(&r.host_data)
        ));
    }
    kmsg(&format!("org CA matches host_data {}", hex(&want)));
    Ok(())
}

/// Removes its configfs directory however the request ends.
struct TsmEntry(PathBuf);

impl Drop for TsmEntry {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

/// One report through configfs-tsm (Documentation/ABI/testing/configfs-tsm).
fn tsm_report(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let dir = Path::new(TSM_REPORTS).join(format!("stage0-{}", std::process::id()));
    fs::create_dir(&dir)
        .map_err(|e| format!("{}: {e} (is configfs mounted and tsm_report loaded?)", dir.display()))?;
    let entry = TsmEntry(dir);
    let attr = |name: &str| entry.0.join(name);
    let read_trim = |name: &str| fs::read_to_string(attr(name)).map(|s| s.trim().to_string());

    let provider = read_trim("provider").map_err(|e| format!("provider: {e}"))?;
    if provider != "sev_guest" {
        return Err(format!("the report provider is {provider:?}, not sev_guest"));
    }
    fs::write(attr("privlevel"), "0").map_err(|e| format!("privlevel: {e}"))?;
    fs::write(attr("inblob"), report_data).map_err(|e| format!("inblob: {e}"))?;
    let before = read_trim("generation").map_err(|e| format!("generation: {e}"))?;
    let raw = fs::read(attr("outblob")).map_err(|e| format!("outblob: {e}"))?;
    let after = read_trim("generation").map_err(|e| format!("generation: {e}"))?;
    if before != after {
        return Err("the report request was changed while it was read".into());
    }
    Ok(raw)
}

fn unlock() -> Result<()> {
    // One unlock at a time. The lock file is empty.
    let lock = File::create(LOCK).map_err(|e| format!("{LOCK}: {e}"))?;
    lock.lock().map_err(|e| format!("{LOCK}: {e}"))?;
    if Path::new(UNLOCKED).exists() {
        return Err("the disk is already unlocked".into());
    }

    let mut key = Vec::with_capacity(MAX_KEY + 1);
    let n = io::stdin().take(MAX_KEY as u64 + 1).read_to_end(&mut key);
    let r = match n {
        Err(e) => Err(format!("reading the key: {e}")),
        Ok(0) => Err("no key on stdin".into()),
        Ok(n) if n > MAX_KEY => Err(format!("the key is longer than {MAX_KEY} bytes")),
        Ok(_) => find_luks().and_then(|dev| open_luks(&dev, &key).map(|()| dev)),
    };
    wipe(&mut key);
    let dev = r?;

    // The guest runs this kernel for its whole life (design section 10.1), so
    // its root must carry this kernel's modules. Without them it would come up
    // with no drivers; refuse now, with the reason, and keep waiting.
    if let Err(e) = check_modules() {
        let undo = close_luks();
        return Err(match undo {
            Ok(()) => format!("{e}. The disk has been locked again; this VM keeps waiting"),
            Err(u) => format!("{e}. Locking the disk again failed too: {u}"),
        });
    }

    // Reply first: the flag releases the boot, and teardown then stops sshd.
    // A reply that cannot be written does not undo the unlock.
    let mut out = io::stdout().lock();
    let _ = write!(out, "stage0-unlock {PROTOCOL}\nunlocked {}\n", dev.display()).and_then(|_| out.flush());
    kmsg(&format!("{} opened as {MAPPER_NAME}", dev.display()));
    fs::write(UNLOCKED, format!("{MAPPER_NAME} {}\n", dev.display())).map_err(|e| format!("{UNLOCKED}: {e}"))
}

/// Unmounts its directory however the check ends. A mount left behind would
/// sit inside /run/stage0, which teardown removes.
struct Mounted(&'static str);

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = run(UMOUNT, &[self.0]);
        let _ = fs::remove_dir(self.0);
    }
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("{prog}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{prog}: {} ({})", String::from_utf8_lossy(&out.stderr).trim(), out.status))
    }
}

/// `/lib/modules/<this kernel>` on the unlocked root, read-only. The root is
/// the command line's `root=`, which is measured.
fn check_modules() -> Result<()> {
    let release =
        fs::read_to_string("/proc/sys/kernel/osrelease").map_err(|e| format!("kernel release: {e}"))?;
    let release = release.trim();
    let cmdline = fs::read_to_string("/proc/cmdline").map_err(|e| format!("/proc/cmdline: {e}"))?;
    let root = cmdline
        .split_ascii_whitespace()
        .find_map(|w| w.strip_prefix("root="))
        .filter(|r| r.starts_with("/dev/"))
        .ok_or("the kernel command line has no root=/dev/... to check")?;

    run(LVM, &["vgchange", "-a", "y", "--sysinit"])?;
    // No udev in stage 0: LVM makes the node itself, but not always at once.
    let mut tries = 0;
    while !Path::new(root).exists() {
        if tries == 50 {
            return Err(format!("{root} did not appear after the unlock"));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        tries += 1;
    }
    fs::create_dir(ROOT_CHECK).map_err(|e| format!("{ROOT_CHECK}: {e}"))?;
    run(MOUNT, &["-o", "ro", root, ROOT_CHECK]).inspect_err(|_| {
        let _ = fs::remove_dir(ROOT_CHECK);
    })?;
    let mounted = Mounted(ROOT_CHECK);
    let found = Path::new(mounted.0).join("lib/modules").join(release).is_dir();
    drop(mounted);
    if Path::new(ROOT_CHECK).exists() {
        return Err(format!("{ROOT_CHECK} could not be unmounted"));
    }
    if !found {
        kmsg(&format!("the unlocked root has no /lib/modules/{release}; not starting it"));
        return Err(format!(
            "this VM's system has no modules for the unlock system's kernel {release} \
             (/lib/modules/{release} is missing on its disk), so it would start without its drivers. \
             Ask your provider to roll the unlock system back, unlock again, and let the VM install \
             its kernel updates"
        ));
    }
    Ok(())
}

/// Undo an unlock: deactivate LVM on the volume and close it.
fn close_luks() -> Result<()> {
    run(LVM, &["vgchange", "-a", "n", "--sysinit"])?;
    run(CRYPTSETUP, &["close", MAPPER_NAME])
}

fn wipe(buf: &mut Vec<u8>) {
    let cap = buf.capacity();
    buf.resize(cap, 0);
    for b in buf.iter_mut() {
        // Volatile so the compiler cannot drop a store to memory that is
        // about to be freed.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    buf.clear();
}

/// The one block device with a LUKS header. More than one, or none, is an
/// error: stage 0 does not guess.
fn find_luks() -> Result<PathBuf> {
    let mut found = Vec::new();
    let entries = fs::read_dir("/sys/class/block").map_err(|e| format!("/sys/class/block: {e}"))?;
    for e in entries.flatten() {
        let dev = Path::new("/dev").join(e.file_name());
        let mut magic = [0u8; 6];
        if File::open(&dev).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"LUKS\xba\xbe" {
            found.push(dev);
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("no LUKS volume found".into()),
        _ => Err(format!("more than one LUKS volume: {found:?}")),
    }
}

fn open_luks(dev: &Path, key: &[u8]) -> Result<()> {
    let mut child = Command::new(CRYPTSETUP)
        .args(["open", "--type", "luks", "--key-file=-"])
        .arg(dev)
        .arg(MAPPER_NAME)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{CRYPTSETUP}: {e}"))?;
    // Write, then close stdin: cryptsetup reads a key file to EOF.
    let wrote = child.stdin.take().expect("piped").write_all(key);
    let out = child.wait_with_output().map_err(|e| format!("{CRYPTSETUP}: {e}"))?;
    wrote.map_err(|e| format!("passing the key to cryptsetup: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr);
        Err(format!("cryptsetup: {} ({})", msg.trim(), out.status))
    }
}
