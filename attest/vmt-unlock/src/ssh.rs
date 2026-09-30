//! One SSH connection to stage 0, through OpenSSH (design section 12,
//! question 9: this answers it with the OpenSSH client).
//!
//! The master connection records whatever host key the far end presents into
//! a private known_hosts file: that recorded key, not anything the guest says
//! about itself, is what REPORT_DATA must bind. `attest` and `unlock` then run
//! as sessions multiplexed over that connection. If the multiplexer were ever
//! bypassed, a fresh connection would still have to present the recorded key
//! (StrictHostKeyChecking=yes against the same file), and only the attested
//! stage 0 holds its private half.

use std::fs::{self, DirBuilder};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use snp::codec::hex;
use snp::sshkey::ed25519_blob_from_line;

#[derive(Clone)]
pub struct Target {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub jump: Option<String>,
    pub identity: Option<PathBuf>,
}

/// The single known_hosts entry for host:port, as OpenSSH writes it with
/// HashKnownHosts=no (`[host]:port` unless the port is 22). None, several, or
/// a key that is not Ed25519 are all refused.
fn key_for(known_hosts: &str, host: &str, port: u16) -> Result<(String, Vec<u8>), String> {
    let name = if port == 22 { host.to_string() } else { format!("[{host}]:{port}") };
    let mut found = known_hosts.lines().filter_map(|l| {
        let (hosts, key) = l.split_once(' ')?;
        hosts.split(',').any(|h| h == name).then(|| key.to_string())
    });
    let key = found.next().ok_or("the connection recorded no host key")?;
    if found.next().is_some() {
        return Err("the connection recorded more than one host key".into());
    }
    let blob = ed25519_blob_from_line(&key).ok_or("the recorded host key is not Ed25519")?;
    Ok((key, blob))
}

pub struct Session {
    dir: PathBuf,
    target: Target,
    /// The host key blob recorded from this connection.
    pub host_key: Vec<u8>,
    pub host_key_line: String,
}

fn random_hex(n: usize) -> Result<String, String> {
    let mut b = vec![0; n];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(hex(&b))
}

impl Session {
    fn base(&self) -> Command {
        let t = &self.target;
        let mut c = Command::new("ssh");
        c.args(["-o", "BatchMode=yes"])
            .arg("-o")
            .arg(format!("ControlPath={}", self.dir.join("c").display()))
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.dir.join("known_hosts").display()))
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .args(["-o", "HostKeyAlgorithms=ssh-ed25519"])
            .args(["-o", "HashKnownHosts=no", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no"])
            .args(["-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=10"])
            .args(["-o", "RequestTTY=no", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes"])
            .arg("-p")
            .arg(t.port.to_string());
        if let Some(id) = &t.identity {
            c.arg("-i").arg(id).args(["-o", "IdentitiesOnly=yes"]);
        }
        if let Some(j) = &t.jump {
            c.arg("-J").arg(j);
        }
        c
    }

    fn dest(&self) -> String {
        format!("{}@{}", self.target.user, self.target.host)
    }

    /// Connect, authenticate, and record the host key.
    pub fn open(target: Target) -> Result<Session, String> {
        let base = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        // Short: a ControlPath must fit in a Unix socket address.
        let dir = base.join(format!("vmtu-{}", random_hex(6)?));
        DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut s = Session { dir, target, host_key: vec![], host_key_line: String::new() };

        // -f backgrounds the master once it has authenticated. The background
        // process keeps whatever stdout and stderr it was given, so they go to
        // a file, not a pipe: a pipe would never reach EOF.
        let log_path = s.dir.join("master.log");
        let log = fs::File::create(&log_path).map_err(|e| format!("{}: {e}", log_path.display()))?;
        let status = s
            .base()
            .args(["-o", "ControlMaster=yes", "-o", "StrictHostKeyChecking=accept-new", "-N", "-f"])
            .arg(s.dest())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .status()
            .map_err(|e| format!("ssh: {e}"))?;
        if !status.success() {
            let err = fs::read_to_string(&log_path).unwrap_or_default();
            return Err(format!("ssh could not connect: {}", err.trim()));
        }
        (s.host_key_line, s.host_key) = s.recorded_key()?;
        Ok(s)
    }

    /// The one known_hosts entry for this destination, written by the master.
    fn recorded_key(&self) -> Result<(String, Vec<u8>), String> {
        let text =
            fs::read_to_string(self.dir.join("known_hosts")).map_err(|e| format!("known_hosts: {e}"))?;
        key_for(&text, &self.target.host, self.target.port)
    }

    /// Run one command as a session on the master connection.
    pub fn run(&self, words: &[&str], stdin: Option<&[u8]>) -> Result<Output, String> {
        let check = self.base().arg("-O").arg("check").arg(self.dest()).output();
        if !check.map(|o| o.status.success()).unwrap_or(false) {
            return Err("the SSH connection has gone away".into());
        }
        let mut child = self
            .base()
            .args(["-o", "ControlMaster=no", "-o", "StrictHostKeyChecking=yes", "-T"])
            .arg(self.dest())
            .args(words)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("ssh: {e}"))?;
        if let Some(input) = stdin {
            // Dropped at the end of the statement: stdin closes, the agent
            // sees EOF.
            child.stdin.take().expect("piped").write_all(input).map_err(|e| format!("ssh stdin: {e}"))?;
        }
        child.wait_with_output().map_err(|e| format!("ssh: {e}"))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.base().arg("-O").arg("exit").arg(self.dest()).stderr(Stdio::null()).output();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::key_for;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/fixtures/snp/");

    #[test]
    fn known_hosts_entry_for_this_destination_only() {
        let pub_line = std::fs::read_to_string(format!("{FIX}binding-hostkey.pub")).unwrap();
        let key: String = pub_line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let blob = std::fs::read(format!("{FIX}binding-hostkey.blob")).unwrap();

        let one = format!("[192.168.122.115]:2222 {key}\n");
        assert_eq!(key_for(&one, "192.168.122.115", 2222).unwrap().1, blob);
        // The jump host's entry, or the same address on another port, is not it.
        assert!(key_for(&one, "192.168.122.115", 22).is_err());
        let other = format!("192.168.50.136 {key}\n");
        assert!(key_for(&other, "192.168.122.115", 2222).is_err());
        // Two entries for the destination: refuse rather than pick one.
        let two = format!("{one}{one}");
        assert!(key_for(&two, "192.168.122.115", 2222).is_err());
    }
}
