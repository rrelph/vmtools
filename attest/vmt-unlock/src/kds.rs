//! VCEKs from AMD KDS, by chip_id and reported_tcb, with a local cache
//! (design section 8, check 1).
//!
//! The fetch goes through curl. Its transport security is a convenience, not
//! a check: the VCEK must chain to the pinned ASK and ARK, and a wrong one
//! simply fails. A VCEK enters the cache only after it has chained, keyed by
//! chip and TCB, so most unlocks make no request to AMD at all, and AMD
//! learns less about when and from where a guest owner unlocks.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use snp::certs::AmdChain;
use snp::codec::hex;
use snp::report::Report;

pub struct Kds {
    pub cache: PathBuf,
    pub proxy: Option<String>,
    pub offline: bool,
}

pub enum Source {
    Cache(PathBuf),
    Fetched(String),
}

impl Kds {
    pub fn vcek(&self, r: &Report, chain: &AmdChain) -> Result<(Vec<u8>, Source), String> {
        let t = r.reported_tcb;
        let chip = hex(&r.chip_id);
        let path = self.cache.join(format!(
            "milan-{chip}-{:02}-{:02}-{:02}-{:02}.der",
            t.bootloader, t.tee, t.snp, t.microcode
        ));
        if let Ok(der) = fs::read(&path) {
            return Ok((der, Source::Cache(path)));
        }
        if self.offline {
            return Err(format!(
                "no cached VCEK for this chip and TCB ({}) and --offline is set",
                path.display()
            ));
        }
        if r.chip_id == [0; 64] {
            return Err("chip_id is zero: there is no VCEK to fetch".into());
        }
        let url = format!(
            "https://kdsintf.amd.com/vcek/v1/Milan/{chip}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            t.bootloader, t.tee, t.snp, t.microcode
        );
        fs::create_dir_all(&self.cache).map_err(|e| format!("{}: {e}", self.cache.display()))?;
        let tmp = path.with_extension(format!("part{}", std::process::id()));
        let mut c = Command::new("curl");
        c.args(["-sSf", "--proto", "=https", "--max-time", "30", "-o"]).arg(&tmp).arg(&url);
        if let Some(p) = &self.proxy {
            c.arg("--proxy").arg(p);
        }
        let out = c.output().map_err(|e| format!("curl: {e}"))?;
        if !out.status.success() {
            let _ = fs::remove_file(&tmp);
            return Err(format!(
                "fetching the VCEK from AMD KDS: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let der = fs::read(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        // Cache only what chains; the verdict re-checks it either way.
        if chain.verify_vcek(&der).is_ok() {
            fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
        } else {
            let _ = fs::remove_file(&tmp);
        }
        Ok((der, Source::Fetched(url)))
    }
}

pub fn default_cache() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("vmt-unlock").join("vcek")
}
