//! Small codecs the Python version gets from its standard library: hex,
//! base64 and little-endian GUIDs. Written out here to keep the measurement
//! calculator's only dependency a SHA-2 implementation.

use crate::{Error, Result};

pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// Like Python's `bytes.fromhex`: pairs of hex digits, ASCII whitespace
/// allowed between pairs.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let hi = nibble(bytes[i]);
        let lo = bytes.get(i + 1).copied().and_then(nibble);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
            _ => {
                return Err(Error::new(format!(
                    "non-hexadecimal number found in fromhex() arg at position {i}"
                )));
            }
        }
        i += 2;
    }
    Ok(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for (k, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if k <= chunk.len() {
                s.push(B64[(n >> shift & 0x3f) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// Strict standard base64 with padding. Python's `b64decode` (used without
/// `validate=True`) silently drops characters outside the alphabet; this
/// refuses them instead.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let bad = || Error::new("invalid base64 input");
    let s = s.as_bytes();
    if !s.len().is_multiple_of(4) {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for (ci, chunk) in s.chunks(4).enumerate() {
        let last = ci == s.len() / 4 - 1;
        let mut n: u32 = 0;
        let mut pad = 0;
        for (k, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' && last && k >= 2 {
                pad += 1;
                0
            } else if pad > 0 {
                return Err(bad());
            } else {
                B64.iter().position(|&a| a == c).ok_or_else(bad)? as u32
            };
            n = n << 6 | v;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Ok(out)
}

/// A GUID's mixed-endian byte form (Python's `uuid.UUID(...).bytes_le`),
/// from its canonical string. Only called on the constants in this crate.
pub const fn guid_le(s: &str) -> [u8; 16] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit in GUID"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len() == 36, "GUID must be 36 characters");
    let mut be = [0u8; 16];
    let mut i = 0;
    let mut j = 0;
    while i < 36 {
        if s[i] == b'-' {
            i += 1;
            continue;
        }
        be[j] = nib(s[i]) << 4 | nib(s[i + 1]);
        j += 1;
        i += 2;
    }
    assert!(j == 16, "GUID must have 32 hex digits");
    [
        be[3], be[2], be[1], be[0], be[5], be[4], be[7], be[6], be[8], be[9], be[10], be[11], be[12], be[13],
        be[14], be[15],
    ]
}

/// `int.from_bytes(b[:4], 'little')`: fewer than four bytes read as a
/// shorter integer, exactly as Python does.
pub fn le_u32_prefix(b: &[u8]) -> u32 {
    b.iter().take(4).enumerate().fold(0u32, |n, (i, &x)| n | (x as u32) << (8 * i))
}

pub fn le_u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

pub fn le_u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_decode("00 AB ff").unwrap(), vec![0x00, 0xab, 0xff]);
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn base64_roundtrip() {
        for (raw, enc) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(raw), enc);
            assert_eq!(base64_decode(enc).unwrap(), raw);
        }
        assert!(base64_decode("Zg=").is_err());
        assert!(base64_decode("Z=g=").is_err());
        assert!(base64_decode("Zg==Zg==").is_err());
        assert!(base64_decode("Zm9v!A==").is_err());
    }

    #[test]
    fn guid_bytes_le() {
        // uuid.UUID("{96b582de-1fb2-45f7-baea-a366c55a082d}").bytes_le
        assert_eq!(
            guid_le("96b582de-1fb2-45f7-baea-a366c55a082d"),
            [0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d]
        );
    }

    #[test]
    fn short_le_prefix() {
        assert_eq!(le_u32_prefix(&[1, 2]), 0x0201);
        assert_eq!(le_u32_prefix(&[1, 2, 3, 4, 5]), 0x04030201);
        assert_eq!(le_u32_prefix(&[]), 0);
    }
}
