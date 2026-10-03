//! The certificate an organization server's people unlock with, read from its
//! file before anything connects. A certificate the VM would refuse (ended,
//! signed with another key, for another SSH key, without the `unlock`
//! principal) is refused here, saying which, instead of surfacing as ssh's
//! "Permission denied (publickey)"; one about to end is warned about at every
//! unlock, while there is still time to sign a new one.
//!
//! Format (OpenSSH PROTOCOL.certkeys), after `ssh-ed25519-cert-v01@openssh.com`
//! and the base64 blob: string type, string nonce, string pk (Ed25519: the 32
//! bytes), uint64 serial, uint32 type (1 user, 2 host), string key id, string
//! principals (strings, packed), uint64 valid after, uint64 valid before,
//! string critical options, string extensions, string reserved, string
//! signature key (the CA's wire blob), string signature. The signature itself
//! is the VM's to check, not ours: here it only names the key that made it.

use snp::codec::unbase64;

const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";
const USER: u32 = 1;
/// The one principal stage 0 accepts.
pub const PRINCIPAL: &str = "unlock";
const DAY: u64 = 86_400;
/// Warn when a certificate ends within this many days.
pub const WARN_DAYS: u64 = 30;

#[derive(Debug, PartialEq, Eq)]
pub struct Cert {
    /// The certified Ed25519 public key, 32 bytes.
    pub key: Vec<u8>,
    pub user: bool,
    pub principals: Vec<String>,
    /// Seconds since the epoch; u64::MAX for a certificate valid forever.
    pub valid_before: u64,
    /// The wire blob of the key that signed it.
    pub signed_by: Vec<u8>,
}

/// What a certificate the VM would refuse has wrong with it.
#[derive(Debug, PartialEq, Eq)]
pub enum Problem {
    Host,
    NoUnlock,
    OtherKey,
    OtherSigner,
    Ended(u64),
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// The certificate in `text`, a `-cert.pub` file's contents. None if it is
/// not an Ed25519 certificate this reads; OpenSSH then says what is wrong.
pub fn parse(text: &str) -> Option<Cert> {
    let line = text.lines().find(|l| !l.trim().is_empty())?;
    let mut f = line.split_whitespace();
    if f.next()? != CERT_TYPE {
        return None;
    }
    let blob = unbase64(f.next()?)?;
    let mut r = Reader(&blob);
    if r.string()? != CERT_TYPE.as_bytes() {
        return None;
    }
    r.string()?; // nonce
    let key = r.string()?.to_vec();
    if key.len() != 32 {
        return None;
    }
    r.u64()?; // serial
    let user = r.u32()? == USER;
    r.string()?; // key id
    let mut packed = Reader(r.string()?);
    let mut principals = vec![];
    while !packed.0.is_empty() {
        principals.push(String::from_utf8_lossy(packed.string()?).into_owned());
    }
    r.u64()?; // valid after
    let valid_before = r.u64()?;
    r.string()?; // critical options
    r.string()?; // extensions
    r.string()?; // reserved
    let signed_by = r.string()?.to_vec();
    Some(Cert { key, user, principals, valid_before, signed_by })
}

/// Whether the VM would take `c` from the holder of `identity` (an Ed25519
/// wire blob, when the public half could be read) at a server whose unlock
/// key is `unlock_key` (its wire blob), at `now`. Ok(Some(end)) when it ends
/// within WARN_DAYS.
pub fn judge(c: &Cert, unlock_key: &[u8], identity: Option<&[u8]>, now: u64) -> Result<Option<u64>, Problem> {
    if !c.user {
        return Err(Problem::Host);
    }
    if !c.principals.iter().any(|p| p == PRINCIPAL) {
        return Err(Problem::NoUnlock);
    }
    if c.signed_by != unlock_key {
        return Err(Problem::OtherSigner);
    }
    if let Some(id) = identity
        && id.len() >= 32
        && id[id.len() - 32..] != c.key[..]
    {
        return Err(Problem::OtherKey);
    }
    if c.valid_before == u64::MAX {
        return Ok(None);
    }
    if c.valid_before <= now {
        return Err(Problem::Ended(c.valid_before));
    }
    Ok((c.valid_before - now <= WARN_DAYS * DAY).then_some(c.valid_before))
}

/// `SHA256:…` for a key's wire blob, as `ssh-keygen -l` prints it.
pub fn fingerprint_or_unknown(blob: &[u8]) -> String {
    if blob.is_empty() { "an unknown key".to_string() } else { snp::sshkey::fingerprint(blob) }
}

/// Whole days from `now` to `t`, rounded up: "in 1 day" for a few hours left.
pub fn days_until(t: u64, now: u64) -> u64 {
    t.saturating_sub(now).div_ceil(DAY)
}

/// `YYYY-MM-DD` for `t` in this computer's time zone, as `ssh-keygen -L`
/// prints a certificate's dates; in UTC if the zone cannot be read.
pub fn local_date(t: u64) -> String {
    if let Ok(tt) = libc::time_t::try_from(t) {
        // SAFETY: localtime_r writes only into `tm`, which outlives the call,
        // and reports failure with a null pointer.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            return format!("{:04}-{:02}-{:02}", i64::from(tm.tm_year) + 1900, tm.tm_mon + 1, tm.tm_mday);
        }
    }
    utc_date(t)
}

/// `YYYY-MM-DD` in UTC (Howard Hinnant's days-to-civil algorithm).
pub fn utc_date(t: u64) -> String {
    let z = (t / DAY) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use snp::sshkey::ed25519_blob_from_line;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/fixtures/vmt-unlock/");
    // 2026-01-01T00:00:00Z and 2027-01-01T00:00:00Z: year-cert.pub's validity.
    const START: u64 = 1_767_225_600;
    const END: u64 = 1_798_761_600;

    fn read(name: &str) -> String {
        std::fs::read_to_string(format!("{FIX}{name}")).unwrap()
    }
    fn blob(name: &str) -> Vec<u8> {
        ed25519_blob_from_line(&read(name)).unwrap()
    }
    fn cert(name: &str) -> Cert {
        parse(&read(name)).unwrap()
    }

    #[test]
    fn reads_what_ssh_keygen_wrote() {
        let c = cert("year-cert.pub");
        assert!(c.user);
        assert_eq!(c.principals, ["unlock"]);
        assert_eq!(c.valid_before, END);
        assert_eq!(c.signed_by, blob("unlock-key.pub"));
        assert_eq!(c.key[..], blob("owner.pub")[19..]);
        assert_eq!(cert("forever-cert.pub").valid_before, u64::MAX);
        assert!(!cert("host-cert.pub").user);
        assert_eq!(cert("root-cert.pub").principals, ["root"]);
    }

    #[test]
    fn other_files_are_left_to_openssh() {
        assert_eq!(parse(&read("owner.pub")), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("ssh-ed25519-cert-v01@openssh.com AAAA"), None);
        // A certificate cut short.
        let whole = read("year-cert.pub");
        let b64 = whole.split_whitespace().nth(1).unwrap();
        assert_eq!(parse(&format!("{CERT_TYPE} {}", &b64[..200])), None);
    }

    #[test]
    fn a_good_certificate_passes_and_warns_only_near_its_end() {
        let (c, ca, me) = (cert("year-cert.pub"), blob("unlock-key.pub"), blob("owner.pub"));
        assert_eq!(judge(&c, &ca, Some(&me), START + DAY), Ok(None));
        assert_eq!(judge(&c, &ca, Some(&me), END - WARN_DAYS * DAY - 1), Ok(None));
        assert_eq!(judge(&c, &ca, Some(&me), END - WARN_DAYS * DAY), Ok(Some(END)));
        assert_eq!(judge(&c, &ca, Some(&me), END - 1), Ok(Some(END)));
        // Without the SSH key's public half, the rest is still checked.
        assert_eq!(judge(&c, &ca, None, END - 1), Ok(Some(END)));
        assert_eq!(judge(&cert("forever-cert.pub"), &ca, Some(&me), u64::MAX - 1), Ok(None));
    }

    #[test]
    fn what_the_vm_would_refuse_is_refused() {
        let (ca, me) = (blob("unlock-key.pub"), blob("owner.pub"));
        let now = START + DAY;
        assert_eq!(judge(&cert("year-cert.pub"), &ca, Some(&me), END), Err(Problem::Ended(END)));
        assert_eq!(judge(&cert("other-ca-cert.pub"), &ca, Some(&me), now), Err(Problem::OtherSigner));
        assert_eq!(judge(&cert("root-cert.pub"), &ca, Some(&me), now), Err(Problem::NoUnlock));
        assert_eq!(judge(&cert("host-cert.pub"), &ca, Some(&me), now), Err(Problem::Host));
        assert_eq!(
            judge(&cert("year-cert.pub"), &ca, Some(&blob("someone.pub")), now),
            Err(Problem::OtherKey)
        );
        // Signed with a different unlock key from the one the config names.
        assert_eq!(
            judge(&cert("year-cert.pub"), &blob("other-unlock-key.pub"), Some(&me), now),
            Err(Problem::OtherSigner)
        );
    }

    #[test]
    fn days_and_dates() {
        assert_eq!(days_until(END, END - 1), 1);
        assert_eq!(days_until(END, END - DAY), 1);
        assert_eq!(days_until(END, END - DAY - 1), 2);
        assert_eq!(days_until(END, END + 5), 0);
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951_782_400), "2000-02-29");
        assert_eq!(utc_date(START), "2026-01-01");
        assert_eq!(utc_date(END - 1), "2026-12-31");
    }
}
