//! OVMF (and Coconut SVSM) firmware images: the GUIDed footer table and the
//! SEV metadata it points to (Python: `ovmf.py`).

use std::collections::HashMap;
use std::path::Path;

use crate::util::{guid_le, le_u16_at, le_u32_at, le_u32_prefix};
use crate::{Error, Result};

pub const FOUR_GB: u64 = 0x1_0000_0000;

/// Types of sections declared by OVMF SEV Metadata, as appears in:
/// https://github.com/tianocore/edk2/blob/edk2-stable202205/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionType {
    SnpSecMem = 1,
    SnpSecrets = 2,
    Cpuid = 3,
    SvsmCaa = 4,
    SnpKernelHashes = 0x10,
}

impl SectionType {
    pub fn from_u32(v: u32) -> Result<Self> {
        Ok(match v {
            1 => SectionType::SnpSecMem,
            2 => SectionType::SnpSecrets,
            3 => SectionType::Cpuid,
            4 => SectionType::SvsmCaa,
            0x10 => SectionType::SnpKernelHashes,
            // Python: ValueError "N is not a valid SectionType", raised
            // only when the section is used, as here.
            _ => return Err(Error::new(format!("{v} is not a valid SectionType"))),
        })
    }
}

/// One entry of the SEV metadata (12 bytes, little-endian, packed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OvmfSevMetadataSectionDesc {
    pub gpa: u32,
    pub size: u32,
    pub section_type_int: u32,
}

impl OvmfSevMetadataSectionDesc {
    pub const SIZE: usize = 12;

    pub fn section_type(&self) -> Result<SectionType> {
        SectionType::from_u32(self.section_type_int)
    }
}

const METADATA_HEADER_SIZE: usize = 16;
const FOOTER_ENTRY_HEADER_SIZE: usize = 18; // u16 size + 16-byte GUID

pub const OVMF_TABLE_FOOTER_GUID: [u8; 16] = guid_le("96b582de-1fb2-45f7-baea-a366c55a082d");
pub const SEV_HASH_TABLE_RV_GUID: [u8; 16] = guid_le("7255371f-3a3b-4b04-927b-1da6efa8d454");
pub const SEV_ES_RESET_BLOCK_GUID: [u8; 16] = guid_le("00f771de-1a7e-4fcb-890e-68c77e2fb44e");
pub const OVMF_SEV_META_DATA_GUID: [u8; 16] = guid_le("dc886566-984a-4798-a75e-5585a7bf67cc");
pub const SVSM_INFO_GUID: [u8; 16] = guid_le("a789a612-0597-4c4b-a49f-cbb1fe9d1ddd");

/// A firmware image placed so that it ends at `end_at` in guest physical
/// memory (4 GiB for OVMF).
#[derive(Clone, Debug)]
pub struct Ovmf {
    data: Vec<u8>,
    gpa: u64,
    table: HashMap<[u8; 16], Vec<u8>>,
    metadata_items: Vec<OvmfSevMetadataSectionDesc>,
}

impl Ovmf {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_ending_at(path, FOUR_GB)
    }

    pub fn load_ending_at(path: impl AsRef<Path>, end_at: u64) -> Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|e| Error::new(format!("{}: {e}", path.display())))?;
        Self::from_bytes(data, end_at)
    }

    pub fn from_bytes(data: Vec<u8>, end_at: u64) -> Result<Self> {
        let gpa = end_at.checked_sub(data.len() as u64).ok_or_else(|| {
            Error::new(format!("firmware image of {} bytes does not fit below {end_at:#x}", data.len()))
        })?;
        let mut ovmf = Ovmf { data, gpa, table: HashMap::new(), metadata_items: Vec::new() };
        ovmf.parse_footer_table()?;
        ovmf.parse_sev_metadata()?;
        Ok(ovmf)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn end_gpa(&self) -> u64 {
        self.gpa + self.size()
    }

    pub fn gpa(&self) -> u64 {
        self.gpa
    }

    pub fn table_item(&self, guid: &[u8; 16]) -> Option<&[u8]> {
        self.table.get(guid).map(Vec::as_slice)
    }

    pub fn metadata_items(&self) -> &[OvmfSevMetadataSectionDesc] {
        &self.metadata_items
    }

    pub fn has_metadata_section(&self, section_type: SectionType) -> Result<bool> {
        // Python's any() stops at the first match, and raises on an
        // unknown type only if it reaches one first.
        for s in &self.metadata_items {
            if s.section_type()? == section_type {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn is_sev_hashes_table_supported(&self) -> bool {
        self.table.contains_key(&SEV_HASH_TABLE_RV_GUID)
            && self.sev_hashes_table_gpa().map(|g| g != 0).unwrap_or(false)
    }

    pub fn sev_hashes_table_gpa(&self) -> Result<u32> {
        let entry = self
            .table
            .get(&SEV_HASH_TABLE_RV_GUID)
            .ok_or_else(|| Error::new("Can't find SEV_HASH_TABLE_RV_GUID entry in OVMF table"))?;
        Ok(le_u32_prefix(entry))
    }

    pub fn sev_es_reset_eip(&self) -> Result<u32> {
        let entry = self
            .table
            .get(&SEV_ES_RESET_BLOCK_GUID)
            .ok_or_else(|| Error::new("Can't find SEV_ES_RESET_BLOCK_GUID entry in OVMF table"))?;
        Ok(le_u32_prefix(entry))
    }

    /// For a Coconut SVSM image (Python: `SVSM.sev_es_reset_eip`). See
    /// https://github.com/coconut-svsm/qemu/blob/0e64fb84eeeb86e2b263068c098a64d2f3d5a661/target/i386/sev.c#L2175
    pub fn svsm_reset_eip(&self) -> Result<u64> {
        let entry = self
            .table
            .get(&SVSM_INFO_GUID)
            .ok_or_else(|| Error::new("Can't find SVSM_INFO_GUID entry in SVSM table"))?;
        Ok(le_u32_prefix(entry) as u64 + self.gpa)
    }

    fn parse_footer_table(&mut self) -> Result<()> {
        let size = self.data.len();
        let ehs = FOOTER_ENTRY_HEADER_SIZE;
        // The OVMF table ends 32 bytes before the end of the firmware binary
        let start_of_footer_table = size
            .checked_sub(32 + ehs)
            .ok_or_else(|| Error::new(format!("firmware image of {size} bytes is too small")))?;
        let footer = &self.data[start_of_footer_table..start_of_footer_table + ehs];
        if footer[2..18] != OVMF_TABLE_FOOTER_GUID {
            return Ok(());
        }
        let footer_size = le_u16_at(footer, 0) as usize;
        let Some(table_size) = footer_size.checked_sub(ehs) else {
            return Ok(());
        };
        // Python slices here with a possibly negative start and gets a
        // shorter table; a table that claims to begin before the image does
        // is refused instead.
        let table_start = start_of_footer_table
            .checked_sub(table_size)
            .ok_or_else(|| Error::new("OVMF footer table extends before start of image"))?;
        let mut table_bytes = &self.data[table_start..start_of_footer_table];
        while table_bytes.len() >= ehs {
            let entry = &table_bytes[table_bytes.len() - ehs..];
            let entry_size = le_u16_at(entry, 0) as usize;
            // Python checks only the lower bound and slices past the start of
            // the table for an oversized entry; that is refused here too.
            if entry_size < ehs || entry_size > table_bytes.len() {
                return Err(Error::new("Invalid entry size"));
            }
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&entry[2..18]);
            let entry_data = &table_bytes[table_bytes.len() - entry_size..table_bytes.len() - ehs];
            // Later (lower-addressed) duplicates replace earlier ones, as in
            // Python's dict assignment.
            self.table.insert(guid, entry_data.to_vec());
            table_bytes = &table_bytes[..table_bytes.len() - entry_size];
        }
        Ok(())
    }

    fn parse_sev_metadata(&mut self) -> Result<()> {
        let Some(entry) = self.table.get(&OVMF_SEV_META_DATA_GUID) else {
            return Ok(());
        };
        let bad = || Error::new("SEV metadata lies outside the firmware image");
        let offset_from_end = le_u32_prefix(entry) as usize;
        let start = self.data.len().checked_sub(offset_from_end).ok_or_else(bad)?;
        let header = self.data.get(start..start + METADATA_HEADER_SIZE).ok_or_else(bad)?;
        if header[0..4] != *b"ASEV" {
            return Err(Error::new("Wrong SEV metadata signature"));
        }
        let header_size = le_u32_at(header, 4) as usize;
        let version = le_u32_at(header, 8);
        let num_items = le_u32_at(header, 12) as usize;
        if version != 1 {
            return Err(Error::new("Wrong SEV metadata version"));
        }
        // Python: data[start+16 : start+header.size], which clamps at the end
        // of the image.
        let items_end = start.saturating_add(header_size).min(self.data.len());
        let items = self.data.get(start + METADATA_HEADER_SIZE..items_end).unwrap_or(&[]);
        let desc = OvmfSevMetadataSectionDesc::SIZE;
        for i in 0..num_items {
            let item = items
                .get(i * desc..(i + 1) * desc)
                .ok_or_else(|| Error::new("SEV metadata has more items than fit in it"))?;
            self.metadata_items.push(OvmfSevMetadataSectionDesc {
                gpa: le_u32_at(item, 0),
                size: le_u32_at(item, 4),
                section_type_int: le_u32_at(item, 8),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn amdsev_suffix_parses() {
        let o = Ovmf::load(fixture("ovmf_AmdSev_suffix.bin")).unwrap();
        assert_eq!(o.gpa(), FOUR_GB - 4096);
        assert!(o.is_sev_hashes_table_supported());
        assert!(o.has_metadata_section(SectionType::SnpKernelHashes).unwrap());
        assert_ne!(o.sev_es_reset_eip().unwrap(), 0);
    }

    #[test]
    fn ovmfx64_suffix_has_no_hashes_table() {
        let o = Ovmf::load(fixture("ovmf_OvmfX64_suffix.bin")).unwrap();
        assert!(!o.is_sev_hashes_table_supported());
        assert!(!o.has_metadata_section(SectionType::SnpKernelHashes).unwrap());
    }

    #[test]
    fn no_footer_means_empty_table() {
        let o = Ovmf::from_bytes(vec![0; 4096], FOUR_GB).unwrap();
        assert!(o.metadata_items().is_empty());
        assert!(o.sev_es_reset_eip().is_err());
    }

    #[test]
    fn tiny_image_is_refused() {
        assert!(Ovmf::from_bytes(vec![0; 49], FOUR_GB).is_err());
    }
}
