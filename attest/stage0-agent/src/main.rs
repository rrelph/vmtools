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
//!                            `cryptsetup open`; then loads the guest's own
//!                            kernel and initrd from the unlocked root for
//!                            kexec, the key in an archive in front of that
//!                            initrd (section 10.2), and locks the disk again;
//!                            prints the result. Any failure locks the disk
//!                            again and leaves the VM waiting.
//!
//! It writes nothing that outlives it except, after a successful unlock, the
//! flag that releases the boot (`UNLOCKED`), which holds no secret. The key is
//! never written to a file: it goes from the SSH channel to cryptsetup's
//! stdin, and into the memory-only initrd the kernel copies for kexec. Stage
//! 0's local-top script then stops sshd and runs `stage0-agent --kexec`, which
//! starts the loaded kernel; nothing of stage 0 survives that but the loaded
//! kernel, initrd and command line.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
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
/// Where the unlocked root is mounted, read-only, while the guest's kernel,
/// initrd and crypttab are read from it.
const GUEST_ROOT: &str = "/run/stage0/root";
/// Stage 0 opens the volume under its own name, and closes it again before
/// the handoff: the guest's own initramfs opens it under its crypttab name.
const MAPPER_NAME: &str = "stage0_crypt";
/// The key file in the guest's initramfs, without the leading slash: the
/// archive stage 0 puts in front of the guest's initrd holds it, and
/// `cryptopts=...,key=/cryptroot/stage0.key` on the guest's command line
/// points its cryptroot script there instead of its crypttab.
const KEY_DIR: &str = "cryptroot";
const KEY_FILE: &str = "cryptroot/stage0.key";
const KEXEC_LOADED: &str = "/sys/kernel/kexec_loaded";
const MAX_KEY: usize = 8192;
/// Output format version, first line of every successful reply.
const PROTOCOL: &str = "1";

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    // Two ways in. sshd's ForceCommand runs the agent with no arguments, and
    // the request comes in SSH_ORIGINAL_COMMAND. Stage 0's own boot scripts
    // run it with --check-host-data, before sshd exists, and with --kexec,
    // after sshd has stopped; no SSH session can pass arguments, so neither
    // mode is reachable from the network.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = if let [flag, ca] = &args[..]
        && flag == "--check-host-data"
    {
        check_host_data(Path::new(ca))
    } else if let [flag] = &args[..]
        && flag == "--kexec"
    {
        start_loaded_kernel()
    } else if !args.is_empty() {
        Err("usage: stage0-agent [--check-host-data <org CA public key file> | --kexec]".into())
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
    let opened = match n {
        Err(e) => Err(format!("reading the key: {e}")),
        Ok(0) => Err("no key on stdin".into()),
        Ok(n) if n > MAX_KEY => Err(format!("the key is longer than {MAX_KEY} bytes")),
        Ok(_) => find_luks().and_then(|dev| open_luks(&dev, &key).map(|()| dev)),
    };
    let dev = match opened {
        Ok(dev) => dev,
        Err(e) => {
            wipe(&mut key);
            return Err(e);
        }
    };

    // The key opened the volume. The guest boots its own kernel, from its own
    // disk (design section 10.2): load it now, while the key is at hand for
    // the guest's initramfs, which opens the volume again.
    let loaded = load_guest(&dev, &key);
    wipe(&mut key);
    let closed = close_luks();
    let kernel = match loaded {
        Ok(k) => k,
        Err(e) => {
            return Err(match closed {
                Ok(()) => format!("{e}. The disk has been locked again; this VM keeps waiting"),
                Err(u) => format!("{e}. Locking the disk again failed too: {u}"),
            });
        }
    };
    // The kexec discards stage 0's mapping with the rest of its kernel, so a
    // volume left open here does not stop the handoff. Say so on the console.
    if let Err(e) = closed {
        kmsg(&format!("closing {MAPPER_NAME} before the handoff failed: {e}"));
    }

    // Reply first: the flag releases the boot, and local-top then stops sshd.
    // A reply that cannot be written does not undo the unlock.
    let mut out = io::stdout().lock();
    let _ = write!(out, "stage0-unlock {PROTOCOL}\nunlocked {}\n", dev.display()).and_then(|_| out.flush());
    kmsg(&format!("{} unlocked; the guest's {kernel} is loaded to start", dev.display()));
    fs::write(UNLOCKED, format!("{}\n", dev.display())).map_err(|e| {
        unload_kernel();
        format!("{UNLOCKED}: {e}")
    })
}

/// Unmounts its directory however the handoff's preparation ends. A mount
/// left behind would keep the volume from closing.
struct Mounted(&'static str);

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = run(UMOUNT, &[self.0]);
        let _ = fs::remove_dir(self.0);
    }
}

fn run_output(prog: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("{prog}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("{prog}: {} ({})", String::from_utf8_lossy(&out.stderr).trim(), out.status))
    }
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    run_output(prog, args).map(|_| ())
}

/// Loads the guest's own kernel for kexec: `/boot/vmlinuz` and
/// `/boot/initrd.img` from the unlocked root, read-only, with this boot's
/// command line and a `cryptopts=` naming the volume as the guest's
/// /etc/crypttab does, and the key in an archive in front of the initrd.
/// The root is the command line's `root=`, which is measured. Returns the
/// kernel's file name, for the console.
fn load_guest(dev: &Path, key: &[u8]) -> Result<String> {
    let uuid = run_output(CRYPTSETUP, &["luksUUID", path_str(dev)?])?.trim().to_string();
    let cmdline = fs::read_to_string("/proc/cmdline").map_err(|e| format!("/proc/cmdline: {e}"))?;
    let root = cmdline
        .split_ascii_whitespace()
        .find_map(|w| w.strip_prefix("root="))
        .filter(|r| r.starts_with("/dev/"))
        .ok_or("the kernel command line has no root=/dev/... to mount")?;

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
    fs::create_dir(GUEST_ROOT).map_err(|e| format!("{GUEST_ROOT}: {e}"))?;
    run(MOUNT, &["-o", "ro", root, GUEST_ROOT]).inspect_err(|_| {
        let _ = fs::remove_dir(GUEST_ROOT);
    })?;
    let mounted = Mounted(GUEST_ROOT);
    let root_dir = Path::new(mounted.0);

    let crypttab = fs::read_to_string(root_dir.join("etc/crypttab"))
        .map_err(|e| format!("this VM's system has no readable /etc/crypttab: {e}"))?;
    let entry = crypttab_entry(&crypttab, &uuid)?;
    let boot_cmdline = stage1_cmdline(&cmdline, &entry, &uuid)?;
    let (kernel_name, kernel) = boot_file(root_dir, "vmlinuz")?;
    let (initrd_name, mut initrd) = boot_file(root_dir, "initrd.img")?;
    // Ubuntu keeps the two links on one version; a pair that disagrees is a
    // half-finished kernel update, and the kernel would start without its
    // initramfs's modules.
    let version = kernel_name.strip_prefix("vmlinuz-");
    if version.is_none() || version != initrd_name.strip_prefix("initrd.img-") {
        return Err(format!(
            "this VM's /boot/vmlinuz is {kernel_name} but its /boot/initrd.img is {initrd_name}; \
             they must be vmlinuz-<version> and initrd.img-<version>, the same version"
        ));
    }

    let mut staged = memfd("stage0-initrd")?;
    let mut archive = key_archive(key);
    let assembled = staged
        .write_all(&archive)
        .and_then(|()| io::copy(&mut initrd, &mut staged).map(|_| ()))
        .map_err(|e| format!("assembling the initrd: {e}"));
    let loaded = assembled.and_then(|()| kexec_file_load(&kernel, &staged, &boot_cmdline));
    // The kernel has its own copy now, or none. Zero the key in this one, and
    // in the archive, before their memory goes back.
    let _ = staged.write_all_at(&vec![0; archive.len()], 0);
    wipe(&mut archive);
    drop(staged);
    // Closed before the unmount, which a file still open would make fail,
    // and the volume could then not be locked again (2026-10-09).
    drop(kernel);
    drop(initrd);
    loaded?;
    drop(mounted);
    Ok(kernel_name)
}

fn path_str(p: &Path) -> Result<&str> {
    p.to_str().ok_or_else(|| format!("{} is not UTF-8", p.display()))
}

/// The guest's crypttab line for the volume with this LUKS UUID: its name
/// and options. The booted system's systemd matches the open volume to its
/// crypttab by name, so the guest's initramfs must open it under that name;
/// any other and systemd would ask for the passphrase again.
#[derive(Debug, PartialEq)]
struct CryptEntry {
    name: String,
    options: String,
}

fn crypttab_entry(crypttab: &str, uuid: &str) -> Result<CryptEntry> {
    let mut found = Vec::new();
    for line in crypttab.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        let (name, source) = match fields[..] {
            [first, ..] if first.starts_with('#') => continue,
            [name, source, ..] => (name, source),
            _ => continue,
        };
        let id = source.strip_prefix("UUID=").or_else(|| source.strip_prefix("/dev/disk/by-uuid/"));
        if id.is_some_and(|id| id.eq_ignore_ascii_case(uuid)) {
            found.push(CryptEntry {
                name: name.to_string(),
                options: fields.get(3).unwrap_or(&"").to_string(),
            });
        }
    }
    let entry = match found.len() {
        1 => found.remove(0),
        0 => return Err(format!("this VM's /etc/crypttab has no line for its disk (UUID={uuid})")),
        _ => {
            return Err(format!("this VM's /etc/crypttab has more than one line for its disk (UUID={uuid})"));
        }
    };
    // Both go on the kernel command line, inside one comma-separated word.
    let plain = |s: &str, extra: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b) || extra.as_bytes().contains(&b))
    };
    if !plain(&entry.name, "") {
        return Err(format!(
            "this VM's /etc/crypttab names its disk {:?}, which stage 0 cannot pass on",
            entry.name
        ));
    }
    if !entry.options.is_empty() && !plain(&entry.options, "=,:/") {
        return Err(format!(
            "this VM's /etc/crypttab has options {:?}, which stage 0 cannot pass on",
            entry.options
        ));
    }
    for opt in entry.options.split(',') {
        let word = opt.split('=').next().unwrap_or("");
        if ["keyscript", "plain", "tcrypt", "bitlk"].contains(&word) {
            return Err(format!(
                "this VM's /etc/crypttab has the option {opt:?} for its disk, which stage 0 cannot honor"
            ));
        }
    }
    Ok(entry)
}

/// The guest kernel's command line: this boot's, which is measured, less the
/// `initrd=` the firmware adds for its own loader, plus the `cryptopts=`
/// that has the guest's initramfs open the volume with the key stage 0
/// passes, instead of asking.
fn stage1_cmdline(cmdline: &str, entry: &CryptEntry, uuid: &str) -> Result<String> {
    if !uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') || uuid.is_empty() {
        return Err(format!("the disk's LUKS UUID {uuid:?} is not a UUID"));
    }
    let mut words: Vec<&str> = Vec::new();
    for w in cmdline.split_ascii_whitespace() {
        if w.starts_with("cryptopts=") {
            return Err("this boot's command line already has a cryptopts=".into());
        }
        if !w.starts_with("initrd=") {
            words.push(w);
        }
    }
    let mut options: Vec<&str> = entry.options.split(',').filter(|o| !o.is_empty()).collect();
    if !options.contains(&"luks") {
        options.push("luks");
    }
    let opts =
        format!("cryptopts=target={},source=UUID={uuid},key=/{KEY_FILE},{}", entry.name, options.join(","));
    words.push(&opts);
    Ok(words.join(" "))
}

/// `/boot/<link>` on the guest's root: Ubuntu's link to the current kernel or
/// initrd, which must point at a file beside it in /boot. Anything else
/// (an absolute target would resolve in stage 0's own tree) is refused.
fn boot_file(root: &Path, link: &str) -> Result<(String, File)> {
    let boot = root.join("boot");
    let target = fs::read_link(boot.join(link)).map_err(|e| format!("this VM's /boot/{link}: {e}"))?;
    let name = target
        .to_str()
        .filter(|t| !t.is_empty() && !t.contains('/') && *t != "." && *t != "..")
        .ok_or_else(|| {
            format!("this VM's /boot/{link} points to {}, not to a file in /boot", target.display())
        })?
        .to_string();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(boot.join(&name))
        .map_err(|e| format!("this VM's /boot/{name}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("this VM's /boot/{name}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("this VM's /boot/{name} is not a file"));
    }
    Ok((name, file))
}

/// A newc cpio archive holding the key, the format the kernel unpacks into
/// the initramfs. It goes in front of the guest's initrd: the kernel unpacks
/// concatenated archives in order, and the guest's does not touch the file.
fn key_archive(key: &[u8]) -> Vec<u8> {
    fn entry(out: &mut Vec<u8>, ino: u32, mode: u32, nlink: u32, name: &str, data: &[u8]) {
        let fields = [ino, mode, 0, 0, nlink, 0, data.len() as u32, 0, 0, 0, 0, name.len() as u32 + 1, 0];
        out.extend_from_slice(b"070701");
        for f in fields {
            out.extend_from_slice(format!("{f:08X}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.resize(out.len().next_multiple_of(4), 0);
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(4), 0);
    }
    let mut out = Vec::with_capacity(512 + key.len());
    entry(&mut out, 1, 0o040700, 2, KEY_DIR, &[]);
    entry(&mut out, 2, 0o100400, 1, KEY_FILE, key);
    entry(&mut out, 0, 0, 1, "TRAILER!!!", &[]);
    out
}

/// An anonymous file in memory: never in any file system.
fn memfd(name: &str) -> Result<File> {
    let c = CString::new(name).map_err(|_| "memfd name".to_string())?;
    // SAFETY: c is a valid NUL-terminated string for the call's duration.
    let fd = unsafe { libc::memfd_create(c.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd_create: {}", io::Error::last_os_error()));
    }
    // SAFETY: fd is a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// kexec_file_load(2): the kernel reads both files and checks the kernel's
/// format itself; nothing runs until `--kexec`.
fn kexec_file_load(kernel: &File, initrd: &File, cmdline: &str) -> Result<()> {
    let c = CString::new(cmdline).map_err(|_| "the command line has a NUL".to_string())?;
    let len = c.as_bytes_with_nul().len();
    // SAFETY: the descriptors are open for the call, and c outlives it.
    let r = unsafe {
        libc::syscall(
            libc::SYS_kexec_file_load,
            kernel.as_raw_fd() as libc::c_long,
            initrd.as_raw_fd() as libc::c_long,
            len as libc::c_ulong,
            c.as_ptr(),
            0 as libc::c_ulong,
        )
    };
    if r != 0 {
        return Err(format!("loading the guest's kernel (kexec_file_load): {}", io::Error::last_os_error()));
    }
    Ok(())
}

/// Drops a loaded kernel, so a later unlock starts clean.
fn unload_kernel() {
    // SAFETY: no pointers are passed.
    unsafe {
        libc::syscall(
            libc::SYS_kexec_file_load,
            -1 as libc::c_long,
            -1 as libc::c_long,
            0 as libc::c_ulong,
            std::ptr::null::<libc::c_char>(),
            libc::KEXEC_FILE_UNLOAD as libc::c_ulong,
        );
    }
}

/// `--kexec`, from local-top once sshd has stopped: start the kernel `unlock`
/// loaded. Returns only on failure.
fn start_loaded_kernel() -> Result<()> {
    let loaded = fs::read_to_string(KEXEC_LOADED).map_err(|e| format!("{KEXEC_LOADED}: {e}"))?;
    if loaded.trim() != "1" {
        return Err("no kernel is loaded".into());
    }
    kmsg("starting the guest's own kernel");
    // SAFETY: no pointers; reboot(2) returns only if it failed.
    unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_KEXEC) };
    Err(format!("starting the loaded kernel: {}", io::Error::last_os_error()))
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

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "0d9f8c2e-6b1a-4c3d-9e2f-1a2b3c4d5e6f";

    fn entry(name: &str, options: &str) -> CryptEntry {
        CryptEntry { name: name.into(), options: options.into() }
    }

    #[test]
    fn crypttab_finds_the_disk_by_uuid() {
        let tab = format!("# <target> <source> <key> <options>\ndm_crypt-0 UUID={UUID} none luks,discard\n");
        assert_eq!(crypttab_entry(&tab, UUID).unwrap(), entry("dm_crypt-0", "luks,discard"));
        let by_path = format!("root /dev/disk/by-uuid/{} none\n", UUID.to_uppercase());
        assert_eq!(crypttab_entry(&by_path, UUID).unwrap(), entry("root", ""));
    }

    #[test]
    fn crypttab_refuses_what_it_cannot_pass_on() {
        let other = "dm_crypt-0 UUID=11111111-2222-3333-4444-555555555555 none luks\n";
        assert!(crypttab_entry(other, UUID).unwrap_err().contains("no line"));
        let twice = format!("a UUID={UUID} none luks\nb UUID={UUID} none luks\n");
        assert!(crypttab_entry(&twice, UUID).unwrap_err().contains("more than one"));
        let commented = format!("#a UUID={UUID} none luks\n");
        assert!(crypttab_entry(&commented, UUID).is_err());
        for bad in ["luks,keyscript=/bin/x", "plain", "luks,tries=3;reboot"] {
            let tab = format!("a UUID={UUID} none {bad}\n");
            assert!(crypttab_entry(&tab, UUID).is_err(), "{bad}");
        }
        let comma_name = format!("a,b UUID={UUID} none luks\n");
        assert!(crypttab_entry(&comma_name, UUID).is_err());
    }

    #[test]
    fn stage1_cmdline_is_this_boots_with_cryptopts() {
        let cmdline =
            "initrd=initrd root=/dev/mapper/ubuntu--vg-ubuntu--lv ro panic=-1 console=ttyS0,115200\n";
        assert_eq!(
            stage1_cmdline(cmdline, &entry("dm_crypt-0", "discard"), UUID).unwrap(),
            format!(
                "root=/dev/mapper/ubuntu--vg-ubuntu--lv ro panic=-1 console=ttyS0,115200 \
                 cryptopts=target=dm_crypt-0,source=UUID={UUID},key=/cryptroot/stage0.key,discard,luks"
            )
        );
        assert!(stage1_cmdline("root=/dev/x cryptopts=source=y", &entry("a", "luks"), UUID).is_err());
        assert!(stage1_cmdline("root=/dev/x", &entry("a", "luks"), "not a uuid").is_err());
    }

    /// Reads a newc archive back: (name, mode, data) per entry, up to the
    /// trailer, which must end the archive on a 4-byte boundary.
    fn parse_newc(mut a: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
        let field = |h: &[u8], i: usize| {
            u32::from_str_radix(std::str::from_utf8(&h[6 + 8 * i..14 + 8 * i]).unwrap(), 16).unwrap()
        };
        let mut out = Vec::new();
        let total = a.len();
        loop {
            assert_eq!(&a[..6], b"070701");
            let (mode, size, namesize) = (field(a, 1), field(a, 6) as usize, field(a, 11) as usize);
            let name = std::str::from_utf8(&a[110..110 + namesize - 1]).unwrap().to_string();
            assert_eq!(a[110 + namesize - 1], 0);
            let data_at = (110 + namesize).next_multiple_of(4);
            let data = a[data_at..data_at + size].to_vec();
            a = &a[(data_at + size).next_multiple_of(4).min(a.len())..];
            if name == "TRAILER!!!" {
                assert!(a.is_empty(), "bytes after the trailer");
                assert_eq!(total % 4, 0);
                return out;
            }
            out.push((name, mode, data));
        }
    }

    #[test]
    fn key_archive_holds_the_key_and_nothing_else() {
        for key in [&b"x"[..], b"correct horse battery staple", &[0xff; 8192]] {
            let got = parse_newc(&key_archive(key));
            assert_eq!(
                got,
                vec![
                    ("cryptroot".to_string(), 0o040700, vec![]),
                    ("cryptroot/stage0.key".to_string(), 0o100400, key.to_vec()),
                ]
            );
        }
    }

    #[test]
    fn boot_links_must_stay_in_boot() {
        let root = std::env::temp_dir().join(format!("stage0-agent-test-{}", std::process::id()));
        let boot = root.join("boot");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&boot).unwrap();
        fs::write(boot.join("vmlinuz-7.0.0-38-generic"), b"kernel").unwrap();
        std::os::unix::fs::symlink("vmlinuz-7.0.0-38-generic", boot.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", boot.join("initrd.img")).unwrap();
        std::os::unix::fs::symlink("../etc", boot.join("config")).unwrap();
        fs::write(boot.join("plain"), b"not a link").unwrap();

        let (name, mut f) = boot_file(&root, "vmlinuz").unwrap();
        let mut body = String::new();
        f.read_to_string(&mut body).unwrap();
        assert_eq!((name.as_str(), body.as_str()), ("vmlinuz-7.0.0-38-generic", "kernel"));
        assert!(boot_file(&root, "initrd.img").unwrap_err().contains("not to a file in /boot"));
        assert!(boot_file(&root, "config").is_err());
        assert!(boot_file(&root, "plain").is_err());
        assert!(boot_file(&root, "missing").is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
