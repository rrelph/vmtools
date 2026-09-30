//! The SEV-SNP `ATTESTATION_REPORT` structure (AMD SEV-SNP ABI
//! specification, table "ATTESTATION_REPORT Structure"), versions 2 to 5.
//!
//! Parsing reads fields; it trusts none of them. Nothing here is meaningful
//! until `verify` has checked the signature over `signed_bytes()`.

use core::fmt;

pub const REPORT_LEN: usize = 0x4A0;
/// The report versions whose layout this parser knows: every field it reads
/// sits at the same offset in all of them. Anything else is refused at parse
/// time, before a single field is trusted or shown.
pub const KNOWN_VERSIONS: core::ops::RangeInclusive<u32> = 2..=5;
/// Bytes 0x000..0x2A0 are covered by the signature.
pub const SIGNED_LEN: usize = 0x2A0;

/// A TCB_VERSION as Milan and Genoa lay it out: bootloader in byte 0, TEE in
/// byte 1, SNP in byte 6, microcode in byte 7. (Turin moves fields; this
/// verifier is pinned to Milan.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl Tcb {
    pub fn from_u64(v: u64) -> Tcb {
        let b = v.to_le_bytes();
        Tcb { bootloader: b[0], tee: b[1], snp: b[6], microcode: b[7] }
    }

    /// Every component at or above `min`.
    pub fn meets(&self, min: &Tcb) -> bool {
        self.bootloader >= min.bootloader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
    }

    /// `bootloader:tee:snp:microcode`, decimal.
    pub fn parse(s: &str) -> Option<Tcb> {
        let v: Vec<u8> = s.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
        match v[..] {
            [bootloader, tee, snp, microcode] => Some(Tcb { bootloader, tee, snp, microcode }),
            _ => None,
        }
    }
}

impl fmt::Display for Tcb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bootloader {} tee {} snp {} microcode {}",
            self.bootloader, self.tee, self.snp, self.microcode
        )
    }
}

#[derive(Clone, Debug)]
pub struct Report {
    raw: [u8; REPORT_LEN],
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: Tcb,
    pub platform_info: u64,
    /// Bit 0 AUTHOR_KEY_EN, bit 1 MASK_CHIP_KEY, bits 2-4 SIGNING_KEY.
    pub key_info: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub reported_tcb: Tcb,
    pub chip_id: [u8; 64],
    pub committed_tcb: Tcb,
    pub launch_tcb: Tcb,
    /// Firmware version as (major, minor, build).
    pub current_fw: (u8, u8, u8),
    /// ECDSA P-384 r and s, big-endian (the report stores them little-endian,
    /// zero-extended to 72 bytes).
    pub sig_r: [u8; 48],
    pub sig_s: [u8; 48],
    /// False if the 72-byte fields carried anything past 48 bytes, or the
    /// reserved remainder of the signature area is not zero.
    pub sig_well_formed: bool,
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn arr<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    b[o..o + N].try_into().unwrap()
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Length(usize),
    Version(u32),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Length(n) => write!(f, "report is {n} bytes, expected {REPORT_LEN}"),
            ParseError::Version(v) => write!(
                f,
                "report version {v} is not one this parser knows ({}-{})",
                KNOWN_VERSIONS.start(),
                KNOWN_VERSIONS.end()
            ),
        }
    }
}

impl Report {
    pub fn parse(b: &[u8]) -> Result<Report, ParseError> {
        let raw: [u8; REPORT_LEN] = b.try_into().map_err(|_| ParseError::Length(b.len()))?;
        let version = u32_at(&raw, 0x00);
        if !KNOWN_VERSIONS.contains(&version) {
            return Err(ParseError::Version(version));
        }
        let le72_to_be48 = |o: usize| {
            let mut v: [u8; 48] = arr(&raw, o);
            v.reverse();
            (v, raw[o + 48..o + 72].iter().all(|&x| x == 0))
        };
        let (sig_r, r_ok) = le72_to_be48(0x2A0);
        let (sig_s, s_ok) = le72_to_be48(0x2A0 + 72);
        let rest_ok = raw[0x2A0 + 144..].iter().all(|&x| x == 0);
        Ok(Report {
            version,
            guest_svn: u32_at(&raw, 0x04),
            policy: u64_at(&raw, 0x08),
            vmpl: u32_at(&raw, 0x30),
            signature_algo: u32_at(&raw, 0x34),
            current_tcb: Tcb::from_u64(u64_at(&raw, 0x38)),
            platform_info: u64_at(&raw, 0x40),
            key_info: u32_at(&raw, 0x48),
            report_data: arr(&raw, 0x50),
            measurement: arr(&raw, 0x90),
            host_data: arr(&raw, 0xC0),
            reported_tcb: Tcb::from_u64(u64_at(&raw, 0x180)),
            chip_id: arr(&raw, 0x1A0),
            committed_tcb: Tcb::from_u64(u64_at(&raw, 0x1E0)),
            current_fw: (raw[0x1EA], raw[0x1E9], raw[0x1E8]),
            launch_tcb: Tcb::from_u64(u64_at(&raw, 0x1F0)),
            sig_r,
            sig_s,
            sig_well_formed: r_ok && s_ok && rest_ok,
            raw,
        })
    }

    pub fn raw(&self) -> &[u8; REPORT_LEN] {
        &self.raw
    }

    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw[..SIGNED_LEN]
    }

    /// 0 = VCEK, 1 = VLEK, 7 = none.
    pub fn signing_key(&self) -> u32 {
        (self.key_info >> 2) & 7
    }

    pub fn mask_chip_key(&self) -> bool {
        self.key_info & 2 != 0
    }
}

/// Guest policy bits (SNP ABI, "GUEST_POLICY").
pub mod policy {
    pub const ABI_MINOR: u64 = 0xff;
    pub const ABI_MAJOR: u64 = 0xff << 8;
    pub const SMT: u64 = 1 << 16;
    pub const RESERVED_ONE: u64 = 1 << 17;
    pub const MIGRATE_MA: u64 = 1 << 18;
    pub const DEBUG: u64 = 1 << 19;
    pub const SINGLE_SOCKET: u64 = 1 << 20;
    pub const CXL_ALLOW: u64 = 1 << 21;
    pub const MEM_AES_256_XTS: u64 = 1 << 22;
    pub const RAPL_DIS: u64 = 1 << 23;
    pub const CIPHERTEXT_HIDING: u64 = 1 << 24;
    pub const PAGE_SWAP_DISABLE: u64 = 1 << 25;

    /// Bits that only ever restrict the guest further. Anything outside this
    /// set, other than SMT, is either a weakening (DEBUG, MIGRATE_MA,
    /// CXL_ALLOW) or unknown to this verifier; both are refused.
    pub const HARDENING: u64 = ABI_MINOR
        | ABI_MAJOR
        | RESERVED_ONE
        | SINGLE_SOCKET
        | MEM_AES_256_XTS
        | RAPL_DIS
        | CIPHERTEXT_HIDING
        | PAGE_SWAP_DISABLE;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcb_layout_and_order() {
        let t = Tcb::from_u64(u64::from_le_bytes([4, 0, 0, 0, 0, 0, 28, 222]));
        assert_eq!(t, Tcb { bootloader: 4, tee: 0, snp: 28, microcode: 222 });
        assert!(t.meets(&Tcb::parse("4:0:28:222").unwrap()));
        assert!(t.meets(&Tcb::parse("3:0:27:200").unwrap()));
        assert!(!t.meets(&Tcb::parse("4:0:29:222").unwrap()));
        assert!(!t.meets(&Tcb::parse("4:1:28:222").unwrap()));
        assert!(Tcb::parse("4:0:28").is_none());
        assert!(Tcb::parse("4:0:28:256").is_none());
    }

    #[test]
    fn wrong_length_is_refused() {
        assert_eq!(Report::parse(&[0; 1183]).unwrap_err(), ParseError::Length(1183));
    }

    #[test]
    fn unknown_versions_are_refused() {
        let mut b = [0u8; REPORT_LEN];
        for v in [0u32, 1, 6, 7, 0xffff_ffff] {
            b[..4].copy_from_slice(&v.to_le_bytes());
            assert_eq!(Report::parse(&b).unwrap_err(), ParseError::Version(v), "{v}");
        }
        for v in KNOWN_VERSIONS {
            b[..4].copy_from_slice(&v.to_le_bytes());
            assert!(Report::parse(&b).is_ok(), "{v}");
        }
    }
}
