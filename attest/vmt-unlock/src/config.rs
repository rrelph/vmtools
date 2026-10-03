//! Per-server configuration: `vmt-unlock <server>` reads
//! `$XDG_CONFIG_HOME/vmt-unlock/<server>/config` (`~/.config/…` without it).
//!
//! One `key = value` per line; `#` starts a comment, to the end of the line;
//! blank lines (a trailing one from pressing Return before Control-D too),
//! CRLF line endings and non-breaking spaces, which mail clients put in
//! settings that are copied out of them, are all accepted. Every key but `measurement` may appear once:
//!
//!   host = 192.0.2.10          the VM's address (required)
//!   port = 2222                stage 0's port (default 2222)
//!   user = root                (default root)
//!   jump = user@bastion        reach it through this host (ssh -J)
//!   identity = ~/.ssh/id_ed25519_cvm    your SSH key (private half)
//!   unlock-key = ~/.ssh/id_ed25519_cvm.pub   the server unlock key (public)
//!   certificate = cert.pub     your certificate from the unlock key; without
//!                              one, and when `identity` IS the unlock key,
//!                              one is signed for this unlock through the SSH
//!                              agent (a solo server)
//!   min-tcb = 4:0:28:222       the oldest AMD firmware accepted (required)
//!   measurement = <96 hex>     an accepted launch measurement; one line each,
//!                              at least one; a rollover adds a line
//!
//! Paths may start with `~/` (your home folder); other relative paths are
//! relative to the server's folder. The folder is the server's: its config,
//! and a member's certificate. The unlock key's private half, where anyone
//! keeps one, is never needed here.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Server {
    pub name: String,
    pub file: PathBuf,
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub jump: Option<String>,
    pub identity: Option<PathBuf>,
    pub unlock_key: Option<PathBuf>,
    pub certificate: Option<PathBuf>,
    pub min_tcb: Option<String>,
    pub measurements: Vec<String>,
}

/// The folder all servers' folders live in.
pub fn root() -> Option<PathBuf> {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => Some(PathBuf::from(x).join("vmt-unlock")),
        _ => std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/vmt-unlock")),
    }
}

/// A server name is a folder name: letters, digits, `.`, `_` and `-`, not
/// starting with `.`.
fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with('.')
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The config file for `name`, if there is one.
pub fn find(name: &str) -> Option<PathBuf> {
    if !valid_name(name) {
        return None;
    }
    let f = root()?.join(name).join("config");
    f.is_file().then_some(f)
}

fn expand(v: &str, dir: &Path) -> PathBuf {
    if let Some(rest) = v.strip_prefix("~/")
        && let Some(h) = std::env::var_os("HOME")
    {
        return PathBuf::from(h).join(rest);
    }
    let p = PathBuf::from(v);
    if p.is_absolute() { p } else { dir.join(p) }
}

pub fn load(name: &str, file: &Path) -> Result<Server, String> {
    let text = fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    parse(name, file, &text)
}

fn parse(name: &str, file: &Path, text: &str) -> Result<Server, String> {
    let dir = file.parent().unwrap_or(Path::new("."));
    let mut s = Server {
        name: name.to_string(),
        file: file.to_path_buf(),
        host: String::new(),
        port: None,
        user: None,
        jump: None,
        identity: None,
        unlock_key: None,
        certificate: None,
        min_tcb: None,
        measurements: vec![],
    };
    let mut seen: Vec<String> = vec![];
    for (i, raw) in text.lines().enumerate() {
        let at = |m: &str| format!("{}:{}: {m}", file.display(), i + 1);
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or_else(|| at("expected key = value"))?;
        let (k, v) = (k.trim(), v.trim());
        if v.is_empty() {
            return Err(at(&format!("{k} has no value")));
        }
        if k != "measurement" {
            if seen.iter().any(|x| x == k) {
                return Err(at(&format!("{k} appears more than once")));
            }
            seen.push(k.to_string());
        }
        match k {
            "host" => s.host = v.to_string(),
            "port" => s.port = Some(v.parse().map_err(|_| at("port: a number"))?),
            "user" => s.user = Some(v.to_string()),
            "jump" => s.jump = Some(v.to_string()),
            "identity" => s.identity = Some(expand(v, dir)),
            "unlock-key" => s.unlock_key = Some(expand(v, dir)),
            "certificate" => s.certificate = Some(expand(v, dir)),
            "min-tcb" => s.min_tcb = Some(v.to_string()),
            "measurement" => s.measurements.push(v.to_string()),
            other => return Err(at(&format!("unknown key {other:?}"))),
        }
    }
    if s.host.is_empty() {
        return Err(format!("{}: no host", file.display()));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "\
# my VM
host = 192.0.2.10
identity = ~/.ssh/id_ed25519_cvm
unlock-key = ~/.ssh/id_ed25519_cvm.pub   # solo: the same key
certificate = cert.pub
min-tcb = 4:0:28:222
measurement = aa   # the current unlock system
measurement = bb   # the next one, during a rollover
";

    #[test]
    fn parses_a_config() {
        let s = parse("vm", Path::new("/c/vm/config"), GOOD).unwrap();
        assert_eq!(s.host, "192.0.2.10");
        assert_eq!(s.measurements, ["aa", "bb"]);
        assert_eq!(s.certificate.unwrap(), PathBuf::from("/c/vm/cert.pub"));
        assert!(s.identity.unwrap().ends_with(".ssh/id_ed25519_cvm"));
        assert_eq!(s.min_tcb.as_deref(), Some("4:0:28:222"));
    }

    #[test]
    fn pasted_settings_are_tolerated() {
        let f = Path::new("/c/vm/config");
        let want = parse("vm", f, GOOD).unwrap();
        // Blank lines, including a trailing one and one of only spaces.
        let blank = format!("\n\n{GOOD}\n   \n\n");
        assert_eq!(parse("vm", f, &blank).unwrap().measurements, want.measurements);
        // CRLF line endings.
        let crlf = GOOD.replace('\n', "\r\n");
        let s = parse("vm", f, &crlf).unwrap();
        assert_eq!((s.host.as_str(), s.min_tcb.as_deref()), ("192.0.2.10", Some("4:0:28:222")));
        assert_eq!(s.measurements, want.measurements);
        // Non-breaking spaces (U+00A0) indenting, around `=`, and trailing.
        let nbsp = GOOD.replace(" = ", "\u{a0}=\u{a0}").replace('\n', "\u{a0}\n\u{a0}\u{a0}");
        let s = parse("vm", f, &nbsp).unwrap();
        assert_eq!(s.host, "192.0.2.10");
        assert_eq!(s.min_tcb.as_deref(), Some("4:0:28:222"));
        assert_eq!(s.measurements, want.measurements);
    }

    #[test]
    fn refuses_what_it_does_not_know() {
        let f = Path::new("/c/vm/config");
        assert!(parse("vm", f, "host = a\nhost = b\n").unwrap_err().contains("more than once"));
        assert!(parse("vm", f, "host = a\ncolour = blue\n").unwrap_err().contains("unknown key"));
        assert!(parse("vm", f, "host = a\nport\n").unwrap_err().contains("key = value"));
        assert!(parse("vm", f, "port = 22\n").unwrap_err().contains("no host"));
        assert!(parse("vm", f, "host = a\nmeasurement =\n").unwrap_err().contains("no value"));
    }

    #[test]
    fn names_are_folder_names() {
        assert!(valid_name("my-vm.2"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name(""));
    }
}
