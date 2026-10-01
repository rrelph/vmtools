//! Python: `vcpu_types.py`.

/// Compute the 32-bit CPUID signature from family, model, and stepping.
///
/// This computation is described in AMD's CPUID Specification, publication
/// #25481 (https://www.amd.com/system/files/TechDocs/25481.pdf), section
/// "CPUID Fn0000_0001_EAX Family, Model, Stepping Identifiers".
pub const fn cpu_sig(family: u32, model: u32, stepping: u32) -> u32 {
    let (family_low, family_high) = if family > 0xf { (0xf, (family - 0x0f) & 0xff) } else { (family, 0) };

    let model_low = model & 0xf;
    let model_high = (model >> 4) & 0xf;

    let stepping_low = stepping & 0xf;

    (family_high << 20) | (model_high << 16) | (family_low << 8) | (model_low << 4) | stepping_low
}

/// The CPU types that appear in QEMU's builtin_x86_defs, in the Python
/// dict's order (which `--help` prints).
pub const CPU_SIGS: [(&str, u32); 16] = [
    ("EPYC", cpu_sig(23, 1, 2)),
    ("EPYC-v1", cpu_sig(23, 1, 2)),
    ("EPYC-v2", cpu_sig(23, 1, 2)),
    ("EPYC-IBPB", cpu_sig(23, 1, 2)),
    ("EPYC-v3", cpu_sig(23, 1, 2)),
    ("EPYC-v4", cpu_sig(23, 1, 2)),
    ("EPYC-Rome", cpu_sig(23, 49, 0)),
    ("EPYC-Rome-v1", cpu_sig(23, 49, 0)),
    ("EPYC-Rome-v2", cpu_sig(23, 49, 0)),
    ("EPYC-Rome-v3", cpu_sig(23, 49, 0)),
    ("EPYC-Milan", cpu_sig(25, 1, 1)),
    ("EPYC-Milan-v1", cpu_sig(25, 1, 1)),
    ("EPYC-Milan-v2", cpu_sig(25, 1, 1)),
    ("EPYC-Genoa", cpu_sig(25, 17, 0)),
    ("EPYC-Genoa-v1", cpu_sig(25, 17, 0)),
    ("EPYC-Turin", cpu_sig(26, 0, 0)),
];

pub fn cpu_sig_for(name: &str) -> Option<u32> {
    CPU_SIGS.iter().find(|(n, _)| *n == name).map(|&(_, s)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Python: tests/test_vcpu_types.py
    #[test]
    fn known_signatures() {
        assert_eq!(cpu_sig_for("EPYC"), Some(0x800f12));
        assert_eq!(cpu_sig_for("EPYC-Rome"), Some(0x830f10));
        assert_eq!(cpu_sig_for("EPYC-Milan"), Some(0xa00f11));
        assert_eq!(cpu_sig_for("EPYC-Genoa"), Some(0xa10f10));
        assert_eq!(cpu_sig_for("EPYC-Turin"), Some(0xb00f00));
        assert_eq!(cpu_sig_for("Opteron"), None);
    }

    #[test]
    fn low_and_high_family() {
        assert_eq!(cpu_sig(14, 1, 2), 0x0e12);
        assert_eq!(cpu_sig(23, 1, 2), 0x800f12);
    }
}
