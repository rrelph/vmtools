//! When an OpenSSH user certificate stops being valid: read from the
//! certificate file itself, so the unlock tool can warn before it expires and
//! refuse once it has, rather than leave OpenSSH to fail at connection.
//!
//! Layout (PROTOCOL.certkeys): `ssh-ed25519-cert-v01@openssh.com BASE64
//! comment`; the blob is the type string, a nonce, the public key (one string
//! for Ed25519), a u64 serial, a u32 type, the key id, the principals, then
//! u64 valid-after and u64 valid-before, in seconds since the epoch.

use snp::codec::unbase64;

/// Warn when a certificate ends within this many days.
pub const WARN_DAYS: u64 = 30;

const DAY: u64 = 86_400;
const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";

/// What the certificate's end date means today.
#[derive(Debug, PartialEq, Eq)]
pub enum Expiry {
    /// Valid for longer than the warning period (or without end).
    Fine,
    /// Ends within the warning period: the date, and whole days left.
    Soon { date: String, days: u64 },
    /// Has ended: the date.
    Over { date: String },
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        (self.0.len() >= n).then(|| {
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            a
        })
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

/// The `valid before` time, in seconds since the epoch, of the certificate in
/// `text` (the contents of a `-cert.pub` file). None if it is not one.
pub fn valid_before(text: &str) -> Option<u64> {
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
    r.string()?; // public key
    r.u64()?; // serial
    r.u32()?; // type
    r.string()?; // key id
    r.string()?; // principals
    r.u64()?; // valid after
    r.u64()
}

/// `YYYY-MM-DD` (UTC) for a time in seconds since the epoch.
pub fn date(t: u64) -> String {
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
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

/// Judge the certificate in `text` against `now` (seconds since the epoch).
/// A file that is not an Ed25519 certificate is `Fine` here: OpenSSH says
/// what is wrong with it.
pub fn check(text: &str, now: u64) -> Expiry {
    let Some(end) = valid_before(text) else {
        return Expiry::Fine;
    };
    if end == u64::MAX {
        Expiry::Fine
    } else if end <= now {
        Expiry::Over { date: date(end) }
    } else if end - now <= WARN_DAYS * DAY {
        Expiry::Soon { date: date(end), days: (end - now).div_ceil(DAY) }
    } else {
        Expiry::Fine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend((s.len() as u32).to_be_bytes());
        out.extend(s);
    }

    /// A certificate line ending at `before`, built to the format above.
    fn cert(before: u64) -> String {
        let mut b = vec![];
        string(&mut b, CERT_TYPE.as_bytes());
        string(&mut b, &[7; 32]); // nonce
        string(&mut b, &[9; 32]); // public key
        b.extend(0u64.to_be_bytes()); // serial
        b.extend(1u32.to_be_bytes()); // type: user
        string(&mut b, b"alice");
        string(&mut b, b"\0\0\0\x06unlock"); // principals
        b.extend(0u64.to_be_bytes()); // valid after
        b.extend(before.to_be_bytes());
        string(&mut b, b""); // critical options
        format!("{CERT_TYPE} {} alice@host\n", base64(&b))
    }

    fn base64(b: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |n, (i, x)| n | (u32::from(*x) << (16 - 8 * i)));
            for i in 0..=c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
            for _ in c.len()..3 {
                s.push('=');
            }
        }
        s
    }

    const NOW: u64 = 1_790_000_000; // 2026-09-21

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(NOW), "2026-09-21");
    }

    #[test]
    fn reads_the_end_of_a_certificate() {
        assert_eq!(valid_before(&cert(NOW + 5)), Some(NOW + 5));
        assert_eq!(valid_before("ssh-ed25519 AAAA key\n"), None);
        assert_eq!(valid_before(""), None);
    }

    #[test]
    fn a_long_validity_is_fine() {
        assert_eq!(check(&cert(NOW + 300 * DAY), NOW), Expiry::Fine);
        assert_eq!(check(&cert(NOW + 31 * DAY), NOW), Expiry::Fine);
        assert_eq!(check(&cert(u64::MAX), NOW), Expiry::Fine);
    }

    #[test]
    fn within_thirty_days_warns_with_the_end_date() {
        assert_eq!(check(&cert(NOW + 30 * DAY), NOW), Expiry::Soon { date: date(NOW + 30 * DAY), days: 30 });
        assert_eq!(
            check(&cert(NOW + 3 * DAY - 10), NOW),
            Expiry::Soon { date: date(NOW + 3 * DAY - 10), days: 3 }
        );
    }

    #[test]
    fn an_ended_certificate_is_refused() {
        assert_eq!(check(&cert(NOW), NOW), Expiry::Over { date: date(NOW) });
        assert_eq!(check(&cert(NOW - 40 * DAY), NOW), Expiry::Over { date: date(NOW - 40 * DAY) });
    }

    #[test]
    fn something_that_is_not_a_certificate_is_left_to_openssh() {
        assert_eq!(check("not a cert", NOW), Expiry::Fine);
    }
}
