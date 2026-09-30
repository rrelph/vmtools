//! Hex and base64, strict, because every value that crosses the wire is
//! either one or the other and a lenient decoder is a place for two
//! different inputs to mean the same thing.

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

/// Lower- or upper-case hex, even length, nothing else.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.chunks(2).map(|p| Some(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

/// Standard alphabet, canonical padding required (RFC 4648 section 4).
pub fn unbase64(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let last = s.len() / 4 - 1;
    for (i, q) in s.chunks(4).enumerate() {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i != last) {
            return None;
        }
        let mut n: u32 = 0;
        for &c in &q[..4 - pad] {
            n = n << 6 | u32::from(val(c)?);
        }
        n <<= 6 * pad as u32;
        let b = n.to_be_bytes();
        // Reject non-canonical encodings: the bits under the padding are zero.
        let keep = 3 - pad;
        if b[1 + keep..].iter().any(|&x| x != 0) {
            return None;
        }
        out.extend_from_slice(&b[1..1 + keep]);
    }
    Some(out)
}

/// PEM to DER for one `CERTIFICATE` block.
pub fn pem_certificate(pem: &str) -> Option<Vec<u8>> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem.find(begin)? + begin.len();
    let stop = start + pem[start..].find(end)?;
    let b64: String = pem[start..stop].split_whitespace().collect();
    unbase64(&b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let v: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&v)).unwrap(), v);
        assert_eq!(unhex("0aFf").unwrap(), vec![0x0a, 0xff]);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn base64_vectors() {
        // RFC 4648 section 10
        for (plain, enc) in [
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(unbase64(enc).unwrap(), plain.as_bytes(), "{enc}");
        }
        assert!(unbase64("Zm9").is_none(), "unpadded");
        assert!(unbase64("Zh==").is_none(), "non-canonical trailing bits");
        assert!(unbase64("Zg==Zg==").is_none(), "padding mid-stream");
        assert!(unbase64("Zm9v!A==").is_none(), "bad character");
    }
}
