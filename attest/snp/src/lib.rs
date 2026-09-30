//! SEV-SNP attestation for the attested unlock: parse a report, check it
//! against the pinned AMD chain and the guest owner's expectations
//! (design/attested-unlock-design.md, section 8).

pub mod binding;
#[cfg(feature = "verify")]
pub mod certs;
pub mod codec;
pub mod report;
pub mod sshkey;
#[cfg(feature = "verify")]
pub mod verify;
