//! Calculate AMD SEV, SEV-ES and SEV-SNP guest launch measurements.
//!
//! A Rust port of virtee/sev-snp-measure (Python), version 0.0.13 plus the
//! one later upstream commit (8f2b337, "Allow zero as value for vcpu sig &
//! family"). Module for module it follows the Python package `sevsnpmeasure`;
//! where it deliberately differs, the difference is noted at the spot and
//! listed in the README.

pub mod gctx;
pub mod guest;
#[cfg(feature = "id-block")]
pub mod id_block;
pub mod ovmf;
pub mod sev_hashes;
pub mod sev_mode;
pub mod util;
pub mod vcpu_types;
pub mod vmm_types;
pub mod vmsa;

use std::fmt;

/// Every failure the library reports. Python raises RuntimeError,
/// ValueError, AssertionError or an IndexError from a slice for these; here
/// they are all one type carrying the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Error(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
