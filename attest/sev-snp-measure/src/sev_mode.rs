//! Python: `sev_mode.py`.

use std::fmt;
use std::str::FromStr;

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SevMode {
    Sev,
    SevEs,
    SevSnp,
    SevSnpSvsm,
}

impl SevMode {
    /// The Python enum member's name, which `--verbose` prints.
    pub fn name(self) -> &'static str {
        match self {
            SevMode::Sev => "SEV",
            SevMode::SevEs => "SEV_ES",
            SevMode::SevSnp => "SEV_SNP",
            SevMode::SevSnpSvsm => "SEV_SNP_SVSM",
        }
    }
}

impl fmt::Display for SevMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for SevMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "sev" | "SEV" => SevMode::Sev,
            "seves" | "sev-es" | "SEVES" | "SEV-ES" => SevMode::SevEs,
            "snp" | "sev-snp" | "SNP" | "SEV-SNP" => SevMode::SevSnp,
            _ if ["snp:svsm", "sev-snp:svsm"].contains(&s.to_lowercase().as_str()) => SevMode::SevSnpSvsm,
            _ => return Err(Error::new("illegal SEV mode")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Python: tests/test_sev_mode.py
    #[test]
    fn from_str() {
        for s in ["sev", "SEV"] {
            assert_eq!(s.parse::<SevMode>().unwrap(), SevMode::Sev);
        }
        for s in ["seves", "SEVES", "sev-es", "SEV-ES"] {
            assert_eq!(s.parse::<SevMode>().unwrap(), SevMode::SevEs);
        }
        for s in ["snp", "SNP", "sev-snp", "SEV-SNP"] {
            assert_eq!(s.parse::<SevMode>().unwrap(), SevMode::SevSnp);
        }
        for s in ["snp:svsm", "SnP:sVsM", "SNP:SVSM", "sev-SnP:sVsM"] {
            assert_eq!(s.parse::<SevMode>().unwrap(), SevMode::SevSnpSvsm);
        }
        assert!("foo".parse::<SevMode>().is_err());
    }
}
