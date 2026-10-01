//! SNP guest context: the running launch digest (Python: `gctx.py`).

use sha2::{Digest, Sha384};

use crate::{Error, Result};

pub const LD_SIZE: usize = 48;
pub const ZEROS: [u8; LD_SIZE] = [0; LD_SIZE];
const PAGE: usize = 4096;

pub fn sha384(buf: &[u8]) -> [u8; LD_SIZE] {
    Sha384::digest(buf).into()
}

/// SNP Guest Context
#[derive(Clone, Debug)]
pub struct Gctx {
    ld: [u8; LD_SIZE],
}

impl Default for Gctx {
    fn default() -> Self {
        Gctx { ld: ZEROS }
    }
}

impl Gctx {
    /// The VMSA page is recorded in the RMP table with GPA (u64)(-1).
    /// However, the address is page-aligned, and also all the bits above
    /// 51 are cleared.
    pub const VMSA_GPA: u64 = 0xFFFF_FFFF_F000;

    pub fn new(seed: [u8; LD_SIZE]) -> Self {
        Gctx { ld: seed }
    }

    pub fn ld(&self) -> [u8; LD_SIZE] {
        self.ld
    }

    pub fn hex_ld(&self) -> String {
        crate::util::hex_encode(&self.ld)
    }

    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8; LD_SIZE]) {
        const PAGE_INFO_LEN: u16 = 0x70;
        let is_imi = 0u8;
        let (vmpl3_perms, vmpl2_perms, vmpl1_perms) = (0u8, 0u8, 0u8);
        // SNP spec 8.17.2 Table 67 Layout of the PAGE_INFO structure
        let mut page_info = [0u8; PAGE_INFO_LEN as usize];
        page_info[0..48].copy_from_slice(&self.ld);
        page_info[48..96].copy_from_slice(contents);
        page_info[96..98].copy_from_slice(&PAGE_INFO_LEN.to_le_bytes());
        page_info[98] = page_type;
        page_info[99] = is_imi;
        page_info[100] = vmpl3_perms;
        page_info[101] = vmpl2_perms;
        page_info[102] = vmpl1_perms;
        page_info[103] = 0;
        page_info[104..112].copy_from_slice(&gpa.to_le_bytes());
        // Update the launch digest
        self.ld = sha384(&page_info);
    }

    fn page_gpas(gpa: u64, length_bytes: u64) -> Result<impl Iterator<Item = u64>> {
        if !length_bytes.is_multiple_of(PAGE as u64) {
            return Err(Error::new(format!(
                "length {length_bytes:#x} at GPA {gpa:#x} is not a whole number of 4 KiB pages"
            )));
        }
        // The last page's GPA goes into a u64 (Python: le64), so it must fit.
        if length_bytes > 0 {
            gpa.checked_add(length_bytes - PAGE as u64)
                .ok_or_else(|| Error::new(format!("GPA range at {gpa:#x} overflows 64 bits")))?;
        }
        Ok((0..length_bytes).step_by(PAGE).map(move |off| gpa + off))
    }

    pub fn update_normal_pages(&mut self, start_gpa: u64, data: &[u8]) -> Result<()> {
        let gpas = Self::page_gpas(start_gpa, data.len() as u64)?;
        for (gpa, page) in gpas.zip(data.chunks(PAGE)) {
            self.update(0x01, gpa, &sha384(page));
        }
        Ok(())
    }

    pub fn update_vmsa_page(&mut self, data: &[u8; PAGE]) {
        self.update(0x02, Self::VMSA_GPA, &sha384(data));
    }

    pub fn update_zero_pages(&mut self, gpa: u64, length_bytes: u64) -> Result<()> {
        for gpa in Self::page_gpas(gpa, length_bytes)? {
            self.update(0x03, gpa, &ZEROS);
        }
        Ok(())
    }

    pub fn update_unmeasured_pages(&mut self, gpa: u64, length_bytes: u64) -> Result<()> {
        for gpa in Self::page_gpas(gpa, length_bytes)? {
            self.update(0x04, gpa, &ZEROS);
        }
        Ok(())
    }

    pub fn update_secrets_page(&mut self, gpa: u64) {
        self.update(0x05, gpa, &ZEROS);
    }

    pub fn update_cpuid_page(&mut self, gpa: u64) {
        self.update(0x06, gpa, &ZEROS);
    }
}
