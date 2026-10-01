//! The SEV hashes table QEMU places in guest memory for measured direct
//! boot (Python: `sev_hashes.py`).

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::util::guid_le;
use crate::{Error, Result};

const SEV_HASH_TABLE_HEADER_GUID: [u8; 16] = guid_le("9438d606-4f22-4cc9-b479-a793d411fd21");
const SEV_KERNEL_ENTRY_GUID: [u8; 16] = guid_le("4de79437-abd2-427f-b835-d5b172d2045b");
const SEV_INITRD_ENTRY_GUID: [u8; 16] = guid_le("44baf731-3a2f-4bd7-9af1-41e29169781d");
const SEV_CMDLINE_ENTRY_GUID: [u8; 16] = guid_le("97d02dd8-bd20-4c94-aa78-e7714d36ab2a");

/// guid (16) + length (u16) + SHA-256 (32), packed.
const ENTRY_SIZE: usize = 16 + 2 + 32;
/// guid (16) + length (u16) + three entries, packed.
const TABLE_SIZE: usize = 16 + 2 + 3 * ENTRY_SIZE;
/// The table padded to a multiple of 16 bytes.
pub const PADDED_TABLE_SIZE: usize = (TABLE_SIZE + 15) & !15;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SevHashes {
    pub kernel_hash: [u8; 32],
    pub initrd_hash: [u8; 32],
    pub cmdline_hash: [u8; 32],
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| Error::new(format!("{}: {e}", path.display())))
}

impl SevHashes {
    /// `append` is the kernel command line as bytes (Python encodes the
    /// `str` as UTF-8; on Unix a command-line argument is already bytes).
    pub fn new(kernel: &Path, initrd: Option<&Path>, append: Option<&[u8]>) -> Result<Self> {
        let kernel_hash = Sha256::digest(read(kernel)?).into();
        let initrd_data = match initrd {
            Some(p) => read(p)?,
            None => Vec::new(),
        };
        let initrd_hash = Sha256::digest(initrd_data).into();
        let mut cmdline = append.unwrap_or_default().to_vec();
        cmdline.push(0);
        let cmdline_hash = Sha256::digest(cmdline).into();
        Ok(SevHashes { kernel_hash, initrd_hash, cmdline_hash })
    }

    /// Generate the SEV hashes area - this must be *identical* to the way
    /// QEMU generates this info in order for the measurement to match.
    pub fn construct_table(&self) -> [u8; PADDED_TABLE_SIZE] {
        let mut t = [0u8; PADDED_TABLE_SIZE];
        t[0..16].copy_from_slice(&SEV_HASH_TABLE_HEADER_GUID);
        t[16..18].copy_from_slice(&(TABLE_SIZE as u16).to_le_bytes());
        let entries = [
            (SEV_CMDLINE_ENTRY_GUID, &self.cmdline_hash),
            (SEV_INITRD_ENTRY_GUID, &self.initrd_hash),
            (SEV_KERNEL_ENTRY_GUID, &self.kernel_hash),
        ];
        for (i, (guid, hash)) in entries.into_iter().enumerate() {
            let e = &mut t[18 + i * ENTRY_SIZE..18 + (i + 1) * ENTRY_SIZE];
            e[0..16].copy_from_slice(&guid);
            e[16..18].copy_from_slice(&(ENTRY_SIZE as u16).to_le_bytes());
            e[18..50].copy_from_slice(hash);
        }
        t
    }

    /// One 4 KiB page with the table at `offset`.
    pub fn construct_page(&self, offset: usize) -> Result<[u8; 4096]> {
        // Python asserts offset < 4096 and that the page comes out at 4096
        // bytes, which fails when the table would cross the page end.
        if offset + PADDED_TABLE_SIZE > 4096 {
            return Err(Error::new(format!(
                "SEV hashes table at page offset {offset:#x} does not fit in the page"
            )));
        }
        let mut page = [0u8; 4096];
        page[offset..offset + PADDED_TABLE_SIZE].copy_from_slice(&self.construct_table());
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_ctypes() {
        assert_eq!(ENTRY_SIZE, 50);
        assert_eq!(TABLE_SIZE, 168);
        assert_eq!(PADDED_TABLE_SIZE, 176);
    }
}
