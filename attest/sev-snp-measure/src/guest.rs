//! The launch digest calculations themselves (Python: `guest.py`).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::gctx::{Gctx, LD_SIZE};
use crate::ovmf::{Ovmf, OvmfSevMetadataSectionDesc, SectionType};
use crate::sev_hashes::SevHashes;
use crate::sev_mode::SevMode;
use crate::util::hex_decode;
use crate::vmm_types::VmmType;
use crate::vmsa::{VMSA_SIZE, Vmsa, VmsaSvsm};
use crate::{Error, Result};

const PAGE_MASK: u32 = 0xfff;

/// The inputs to [`calc_launch_digest`], named as the Python function's
/// parameters are.
#[derive(Clone, Debug)]
pub struct Params<'a> {
    pub mode: SevMode,
    /// Ignored in SEV mode.
    pub vcpus: u32,
    /// Ignored in SEV mode, and by the ec2 and gce VMM types.
    pub vcpu_sig: u32,
    pub ovmf_file: &'a Path,
    pub kernel: Option<&'a Path>,
    pub initrd: Option<&'a Path>,
    /// The kernel command line, as bytes.
    pub append: Option<&'a [u8]>,
    pub guest_features: u64,
    /// A precalculated OVMF hash (hex), SNP mode only.
    pub snp_ovmf_hash: Option<&'a str>,
    pub vmm_type: VmmType,
    /// Where to write the measured VMSA pages as `vmsa<N>.bin`, if anywhere.
    /// (Python writes them to the working directory when `dump_vmsa` is
    /// true; the command-line tool passes `.`.)
    pub dump_vmsa: Option<&'a Path>,
    pub svsm_file: Option<&'a Path>,
    pub ovmf_vars_size: u64,
}

impl<'a> Params<'a> {
    /// The defaults Python's keyword arguments have.
    pub fn new(mode: SevMode, ovmf_file: &'a Path) -> Self {
        Params {
            mode,
            vcpus: 0,
            vcpu_sig: 0,
            ovmf_file,
            kernel: None,
            initrd: None,
            append: None,
            guest_features: 0x1,
            snp_ovmf_hash: None,
            vmm_type: VmmType::Qemu,
            dump_vmsa: None,
            svsm_file: None,
            ovmf_vars_size: 0,
        }
    }
}

/// The launch digest: 48 bytes (SHA-384) for SNP modes, 32 (SHA-256) for
/// SEV and SEV-ES.
pub fn calc_launch_digest(p: &Params) -> Result<Vec<u8>> {
    // Python tests the hash string's truthiness: an empty one counts as none.
    let snp_ovmf_hash = p.snp_ovmf_hash.filter(|s| !s.is_empty());
    if snp_ovmf_hash.is_some() && p.mode != SevMode::SevSnp {
        return Err(Error::new("SNP OVMF hash only works with SNP"));
    }

    match p.mode {
        SevMode::SevSnp => snp_calc_launch_digest(
            p.vcpus,
            p.vcpu_sig,
            p.ovmf_file,
            p.kernel,
            p.initrd,
            p.append,
            p.guest_features,
            snp_ovmf_hash,
            p.vmm_type,
            p.dump_vmsa,
        )
        .map(|ld| ld.to_vec()),
        SevMode::SevEs => seves_calc_launch_digest(
            p.vcpus,
            p.vcpu_sig,
            p.ovmf_file,
            p.kernel,
            p.initrd,
            p.append,
            p.vmm_type,
            p.dump_vmsa,
        )
        .map(|ld| ld.to_vec()),
        SevMode::Sev => {
            sev_calc_launch_digest(p.ovmf_file, p.kernel, p.initrd, p.append).map(|ld| ld.to_vec())
        }
        SevMode::SevSnpSvsm => {
            if p.vmm_type != VmmType::Qemu {
                return Err(Error::new("SVSM mode is only implemented for Qemu."));
            }
            let svsm_file = p.svsm_file.ok_or_else(|| Error::new("snp:svsm mode requires an SVSM binary"))?;
            svsm_calc_launch_digest(
                p.vcpus,
                p.vcpu_sig,
                p.ovmf_file,
                p.ovmf_vars_size,
                svsm_file,
                p.dump_vmsa,
            )
            .map(|ld| ld.to_vec())
        }
    }
}

fn nonempty_path(p: Option<&Path>) -> Option<&Path> {
    p.filter(|p| !p.as_os_str().is_empty())
}

fn sev_hashes(
    kernel: Option<&Path>,
    initrd: Option<&Path>,
    append: Option<&[u8]>,
) -> Result<Option<SevHashes>> {
    // Python tests the arguments' truthiness, so an empty string is none.
    let Some(kernel) = nonempty_path(kernel) else {
        return Ok(None);
    };
    let append = append.filter(|a| !a.is_empty());
    SevHashes::new(kernel, nonempty_path(initrd), append).map(Some)
}

/// The hashes table SEV and SEV-ES measure after the firmware, or nothing
/// without a kernel. Support is checked before any file is read, as in
/// Python.
fn sev_hashes_table(
    ovmf: &Ovmf,
    kernel: Option<&Path>,
    initrd: Option<&Path>,
    append: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if nonempty_path(kernel).is_none() {
        return Ok(Vec::new());
    }
    if !ovmf.is_sev_hashes_table_supported() {
        return Err(Error::new(
            "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement",
        ));
    }
    let hashes = sev_hashes(kernel, initrd, append)?.expect("kernel is present");
    Ok(hashes.construct_table().to_vec())
}

fn dump(dir: Option<&Path>, i: usize, page: &[u8; VMSA_SIZE]) -> Result<()> {
    if let Some(dir) = dir {
        let path: PathBuf = dir.join(format!("vmsa{i}.bin"));
        std::fs::write(&path, page).map_err(|e| Error::new(format!("{}: {e}", path.display())))?;
    }
    Ok(())
}

fn snp_update_kernel_hashes(
    gctx: &mut Gctx,
    ovmf: &Ovmf,
    sev_hashes: Option<&SevHashes>,
    gpa: u64,
    size: u64,
) -> Result<()> {
    match sev_hashes {
        Some(sev_hashes) => {
            let sev_hashes_table_gpa = ovmf.sev_hashes_table_gpa()?;
            let offset_in_page = sev_hashes_table_gpa & PAGE_MASK;
            let sev_hashes_page = sev_hashes.construct_page(offset_in_page as usize)?;
            if size != sev_hashes_page.len() as u64 {
                return Err(Error::new(format!(
                    "SNP_KERNEL_HASHES section is {size:#x} bytes, not one page"
                )));
            }
            gctx.update_normal_pages(gpa, &sev_hashes_page)
        }
        None => gctx.update_zero_pages(gpa, size),
    }
}

fn snp_update_section(
    desc: &OvmfSevMetadataSectionDesc,
    gctx: &mut Gctx,
    ovmf: &Ovmf,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VmmType,
) -> Result<()> {
    let (gpa, size) = (desc.gpa as u64, desc.size as u64);
    match desc.section_type()? {
        SectionType::SnpSecMem => {
            if vmm_type == VmmType::Gce {
                gctx.update_unmeasured_pages(gpa, size)?
            } else {
                gctx.update_zero_pages(gpa, size)?
            }
        }
        SectionType::SnpSecrets => gctx.update_secrets_page(gpa),
        SectionType::Cpuid => {
            if vmm_type != VmmType::Ec2 {
                gctx.update_cpuid_page(gpa)
            }
        }
        SectionType::SnpKernelHashes => snp_update_kernel_hashes(gctx, ovmf, sev_hashes, gpa, size)?,
        SectionType::SvsmCaa => gctx.update_zero_pages(gpa, size)?,
    }
    Ok(())
}

fn snp_update_metadata_pages(
    gctx: &mut Gctx,
    ovmf: &Ovmf,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VmmType,
) -> Result<()> {
    for desc in ovmf.metadata_items() {
        snp_update_section(desc, gctx, ovmf, sev_hashes, vmm_type)?;
    }

    if vmm_type == VmmType::Ec2 {
        for desc in ovmf.metadata_items() {
            if desc.section_type()? == SectionType::Cpuid {
                gctx.update_cpuid_page(desc.gpa as u64);
            }
        }
    }

    if sev_hashes.is_some() && !ovmf.has_metadata_section(SectionType::SnpKernelHashes)? {
        return Err(Error::new(
            "Kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section",
        ));
    }
    Ok(())
}

/// The OVMF part of an SNP launch digest (`--mode snp:ovmf-hash`).
pub fn calc_snp_ovmf_hash(ovmf_file: &Path) -> Result<[u8; LD_SIZE]> {
    let ovmf = Ovmf::load(ovmf_file)?;

    let mut gctx = Gctx::default();
    gctx.update_normal_pages(ovmf.gpa(), ovmf.data())?;
    Ok(gctx.ld())
}

#[allow(clippy::too_many_arguments)]
pub fn snp_calc_launch_digest(
    vcpus: u32,
    vcpu_sig: u32,
    ovmf_file: &Path,
    kernel: Option<&Path>,
    initrd: Option<&Path>,
    append: Option<&[u8]>,
    guest_features: u64,
    ovmf_hash_str: Option<&str>,
    vmm_type: VmmType,
    dump_vmsa: Option<&Path>,
) -> Result<[u8; LD_SIZE]> {
    let ovmf = Ovmf::load(ovmf_file)?;

    // Allow users to provide a precalculated OVMF hash.
    // Ignores the contents of the OVMF file in front of us.
    let mut gctx = match ovmf_hash_str.filter(|s| !s.is_empty()) {
        Some(s) => {
            let seed: [u8; LD_SIZE] = hex_decode(s)?.try_into().map_err(|v: Vec<u8>| {
                Error::new(format!("precalculated OVMF hash is {} bytes; it must be {LD_SIZE}", v.len()))
            })?;
            Gctx::new(seed)
        }
        None => {
            let mut g = Gctx::default();
            g.update_normal_pages(ovmf.gpa(), ovmf.data())?;
            g
        }
    };

    let sev_hashes = sev_hashes(kernel, initrd, append)?;

    snp_update_metadata_pages(&mut gctx, &ovmf, sev_hashes.as_ref(), vmm_type)?;

    let vmsa = Vmsa::new(SevMode::SevSnp, ovmf.sev_es_reset_eip()?, vcpu_sig, guest_features, vmm_type);
    for (i, vmsa_page) in vmsa.pages(vcpus)?.into_iter().enumerate() {
        gctx.update_vmsa_page(vmsa_page);
        dump(dump_vmsa, i, vmsa_page)?;
    }

    Ok(gctx.ld())
}

pub fn svsm_calc_launch_digest(
    vcpus: u32,
    vcpu_sig: u32,
    ovmf_file: &Path,
    ovmf_vars_size: u64,
    svsm_file: &Path,
    dump_vmsa: Option<&Path>,
) -> Result<[u8; LD_SIZE]> {
    let ovmf = Ovmf::load(ovmf_file)?;
    let end_at = ovmf
        .gpa()
        .checked_sub(ovmf_vars_size)
        .ok_or_else(|| Error::new("OVMF_VARS size places the SVSM below address 0"))?;
    let svsm = Ovmf::load_ending_at(svsm_file, end_at)?;

    let eip = svsm.svsm_reset_eip()?;

    let mut gctx = Gctx::default();
    gctx.update_normal_pages(ovmf.gpa(), ovmf.data())?;
    gctx.update_normal_pages(svsm.gpa(), svsm.data())?;

    snp_update_metadata_pages(&mut gctx, &svsm, None, VmmType::Qemu)?;

    let vmsa = VmsaSvsm::new(eip, vcpu_sig, VmmType::Qemu);
    for (i, vmsa_page) in vmsa.pages(vcpus).into_iter().enumerate() {
        gctx.update_vmsa_page(vmsa_page);
        dump(dump_vmsa, i, vmsa_page)?;
    }

    Ok(gctx.ld())
}

#[allow(clippy::too_many_arguments)]
pub fn seves_calc_launch_digest(
    vcpus: u32,
    vcpu_sig: u32,
    ovmf_file: &Path,
    kernel: Option<&Path>,
    initrd: Option<&Path>,
    append: Option<&[u8]>,
    vmm_type: VmmType,
    dump_vmsa: Option<&Path>,
) -> Result<[u8; 32]> {
    let ovmf = Ovmf::load(ovmf_file)?;
    let mut launch_hash = Sha256::new();
    launch_hash.update(ovmf.data());
    launch_hash.update(sev_hashes_table(&ovmf, kernel, initrd, append)?);
    let vmsa = Vmsa::new(SevMode::SevEs, ovmf.sev_es_reset_eip()?, vcpu_sig, 0x0, vmm_type);
    for (i, vmsa_page) in vmsa.pages(vcpus)?.into_iter().enumerate() {
        launch_hash.update(vmsa_page);
        dump(dump_vmsa, i, vmsa_page)?;
    }
    Ok(launch_hash.finalize().into())
}

pub fn sev_calc_launch_digest(
    ovmf_file: &Path,
    kernel: Option<&Path>,
    initrd: Option<&Path>,
    append: Option<&[u8]>,
) -> Result<[u8; 32]> {
    let ovmf = Ovmf::load(ovmf_file)?;
    let mut launch_hash = Sha256::new();
    launch_hash.update(ovmf.data());
    launch_hash.update(sev_hashes_table(&ovmf, kernel, initrd, append)?);
    Ok(launch_hash.finalize().into())
}
