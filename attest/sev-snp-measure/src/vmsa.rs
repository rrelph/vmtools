//! VMSA pages: each vCPU's initial register state (Python: `vmsa.py`).
//!
//! The Python version lays out `struct sev_es_work_area` from the Linux
//! kernel (https://github.com/AMDESE/linux/blob/sev-snp-v12/arch/x86/include/asm/svm.h#L318,
//! after AMD APM Vol 2 Table B-4) as a packed ctypes structure. Here the
//! page is a byte array and each field the code sets is written at its
//! offset in that structure; every other byte stays zero, as it does in
//! the ctypes structure.

use crate::sev_mode::SevMode;
use crate::vmm_types::VmmType;
use crate::{Error, Result};

pub const VMSA_SIZE: usize = 4096;

/// Field offsets in the save area (packed, so each is the running sum of
/// the sizes before it in the Python structure).
mod off {
    pub const ES: usize = 0x000;
    pub const CS: usize = 0x010;
    pub const SS: usize = 0x020;
    pub const DS: usize = 0x030;
    pub const FS: usize = 0x040;
    pub const GS: usize = 0x050;
    pub const GDTR: usize = 0x060;
    pub const LDTR: usize = 0x070;
    pub const IDTR: usize = 0x080;
    pub const TR: usize = 0x090;
    pub const EFER: usize = 0x0d0;
    pub const CR4: usize = 0x148;
    pub const CR0: usize = 0x158;
    pub const DR7: usize = 0x160;
    pub const DR6: usize = 0x168;
    pub const RFLAGS: usize = 0x170;
    pub const RIP: usize = 0x178;
    pub const G_PAT: usize = 0x268;
    pub const RDX: usize = 0x310;
    pub const SEV_FEATURES: usize = 0x3b0;
    pub const XCR0: usize = 0x3e8;
    pub const MXCSR: usize = 0x408;
    pub const X87_FCW: usize = 0x410;
}

/// VMCB Segment (struct vmcb_seg in the Linux kernel).
#[derive(Clone, Copy)]
struct VmcbSeg {
    selector: u16,
    attrib: u16,
    limit: u32,
    base: u64,
}

const fn seg(selector: u16, attrib: u16, limit: u32, base: u64) -> VmcbSeg {
    VmcbSeg { selector, attrib, limit, base }
}

/// The fields the Python version sets; everything else is zero.
struct SaveArea {
    es: VmcbSeg,
    cs: VmcbSeg,
    ss: VmcbSeg,
    ds: VmcbSeg,
    fs: VmcbSeg,
    gs: VmcbSeg,
    gdtr: VmcbSeg,
    idtr: VmcbSeg,
    ldtr: VmcbSeg,
    tr: VmcbSeg,
    efer: u64,
    cr4: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,
    g_pat: u64,
    rdx: u64,
    sev_features: u64,
    xcr0: u64,
    mxcsr: u32,
    x87_fcw: u16,
}

impl SaveArea {
    fn to_page(&self) -> Box<[u8; VMSA_SIZE]> {
        let mut p = Box::new([0u8; VMSA_SIZE]);
        let mut put = |at: usize, bytes: &[u8]| p[at..at + bytes.len()].copy_from_slice(bytes);
        for (at, s) in [
            (off::ES, self.es),
            (off::CS, self.cs),
            (off::SS, self.ss),
            (off::DS, self.ds),
            (off::FS, self.fs),
            (off::GS, self.gs),
            (off::GDTR, self.gdtr),
            (off::LDTR, self.ldtr),
            (off::IDTR, self.idtr),
            (off::TR, self.tr),
        ] {
            put(at, &s.selector.to_le_bytes());
            put(at + 2, &s.attrib.to_le_bytes());
            put(at + 4, &s.limit.to_le_bytes());
            put(at + 8, &s.base.to_le_bytes());
        }
        for (at, v) in [
            (off::EFER, self.efer),
            (off::CR4, self.cr4),
            (off::CR0, self.cr0),
            (off::DR7, self.dr7),
            (off::DR6, self.dr6),
            (off::RFLAGS, self.rflags),
            (off::RIP, self.rip),
            (off::G_PAT, self.g_pat),
            (off::RDX, self.rdx),
            (off::SEV_FEATURES, self.sev_features),
            (off::XCR0, self.xcr0),
        ] {
            put(at, &v.to_le_bytes());
        }
        put(off::MXCSR, &self.mxcsr.to_le_bytes());
        put(off::X87_FCW, &self.x87_fcw.to_le_bytes());
        p
    }
}

/// Initial register state for SEV-ES and SEV-SNP guests.
pub struct Vmsa {
    bsp: Box<[u8; VMSA_SIZE]>,
    ap: Option<Box<[u8; VMSA_SIZE]>>,
}

impl Vmsa {
    pub const BSP_EIP: u32 = 0xffff_fff0;

    fn build_save_area(
        eip: u32,
        sev_features: u64,
        vcpu_sig: u32,
        vmm_type: VmmType,
    ) -> Box<[u8; VMSA_SIZE]> {
        // QEMU, EC2, and GCE differ slightly on initial register state
        let mut g_pat = 0x7040600070406; // PAT MSR: See AMD APM Vol 2, Section A.3
        let (cs_flags, ss_flags, tr_flags, rdx, mxcsr, fcw);
        match vmm_type {
            VmmType::Qemu => {
                cs_flags = 0x9b;
                ss_flags = 0x93;
                tr_flags = 0x8b;
                rdx = vcpu_sig as u64;
                mxcsr = 0x1f80;
                fcw = 0x37f;
            }
            VmmType::Ec2 => {
                cs_flags = if eip == 0xffff_fff0 { 0x9a } else { 0x9b };
                ss_flags = 0x92;
                tr_flags = 0x83;
                rdx = 0x600;
                mxcsr = 0;
                fcw = 0;
            }
            VmmType::Gce => {
                cs_flags = 0x9b;
                ss_flags = 0x93;
                tr_flags = 0x8b;
                g_pat = 0x00070106; // GCE hypervisor overwrites default g_pat
                rdx = 0x600;
                mxcsr = 0;
                fcw = 0;
            }
        }

        SaveArea {
            es: seg(0, 0x93, 0xffff, 0),
            cs: seg(0xf000, cs_flags, 0xffff, (eip & 0xffff_0000) as u64),
            ss: seg(0, ss_flags, 0xffff, 0),
            ds: seg(0, 0x93, 0xffff, 0),
            fs: seg(0, 0x93, 0xffff, 0),
            gs: seg(0, 0x93, 0xffff, 0),
            gdtr: seg(0, 0, 0xffff, 0),
            idtr: seg(0, 0, 0xffff, 0),
            ldtr: seg(0, 0x82, 0xffff, 0),
            tr: seg(0, tr_flags, 0xffff, 0),
            efer: 0x1000, // KVM enables EFER_SVME
            cr4: 0x40,    // KVM enables X86_CR4_MCE
            cr0: 0x10,
            dr7: 0x400,
            dr6: 0xffff0ff0,
            rflags: 0x2,
            rip: (eip & 0xffff) as u64,
            g_pat,
            rdx,
            sev_features,
            xcr0: 0x1,
            mxcsr,
            x87_fcw: fcw,
        }
        .to_page()
    }

    /// `sev_mode` is accepted, and ignored, as in the Python version.
    pub fn new(
        _sev_mode: SevMode,
        ap_eip: u32,
        vcpu_sig: u32,
        guest_features: u64,
        vmm_type: VmmType,
    ) -> Self {
        let bsp = Self::build_save_area(Self::BSP_EIP, guest_features, vcpu_sig, vmm_type);
        let ap = (ap_eip != 0).then(|| Self::build_save_area(ap_eip, guest_features, vcpu_sig, vmm_type));
        Vmsa { bsp, ap }
    }

    /// The VMSA pages for `vcpus` vCPUs, the boot processor's first.
    pub fn pages(&self, vcpus: u32) -> Result<Vec<&[u8; VMSA_SIZE]>> {
        (0..vcpus)
            .map(|i| {
                if i == 0 {
                    Ok(&*self.bsp)
                } else {
                    // Python fails here with an AttributeError.
                    self.ap.as_deref().ok_or_else(|| {
                        Error::new("firmware has no AP reset EIP, so it cannot start more than one vCPU")
                    })
                }
            })
            .collect()
    }
}

/// Initial register state for SNP guests under Coconut SVSM.
pub struct VmsaSvsm {
    save_area: Box<[u8; VMSA_SIZE]>,
}

impl VmsaSvsm {
    pub const BSP_EIP: u32 = 0xffff_fff0;

    fn build_save_area(
        eip: u64,
        sev_features: u64,
        vcpu_sig: u32,
        vmm_type: VmmType,
    ) -> Box<[u8; VMSA_SIZE]> {
        let mxcsr = if vmm_type == VmmType::Qemu { 0x1f80 } else { 0 };
        SaveArea {
            es: seg(16, 0xc93, 0xffffffff, 0),
            cs: seg(8, 0xc9b, 0xffffffff, 0),
            ss: seg(16, 0xc93, 0xffffffff, 0),
            ds: seg(16, 0xc93, 0xffffffff, 0),
            fs: seg(16, 0xc93, 0xffffffff, 0),
            gs: seg(0, 0x093, 0xffff, 0),
            gdtr: seg(0, 0, 0xffff, 0),
            idtr: seg(0, 0, 0xffff, 0),
            ldtr: seg(0, 0x82, 0xffff, 0),
            tr: seg(0, 0x8b, 0xffff, 0),
            efer: 0x1000,
            cr4: 0x40,
            cr0: 0x11,
            dr7: 0x400,
            dr6: 0xffff0ff0,
            rflags: 0x2,
            rip: eip,
            g_pat: 0x7040600070406, // PAT MSR: See AMD APM Vol 2, Section A.3
            rdx: vcpu_sig as u64,
            sev_features,
            xcr0: 0x1,
            mxcsr,
            // The Python version passes `fcw=fcw` here, which is not a
            // field of the structure: ctypes sets it as a plain attribute
            // and x87_fcw stays 0 in the page. The upstream SVSM test
            // vectors, taken from a real QEMU launch, match only with 0.
            x87_fcw: 0,
        }
        .to_page()
    }

    pub fn new(ap_eip: u64, vcpu_sig: u32, vmm_type: VmmType) -> Self {
        let sev_features = 0x1;
        VmsaSvsm { save_area: Self::build_save_area(ap_eip, sev_features, vcpu_sig, vmm_type) }
    }

    pub fn pages(&self, vcpus: u32) -> Vec<&[u8; VMSA_SIZE]> {
        (0..vcpus).map(|_| &*self.save_area).collect()
    }
}
