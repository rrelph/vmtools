//! The upstream test suite's launch-digest vectors (Python:
//! tests/test_guest.py), one test per Python test, same inputs, same
//! expected values. Generated from that file by script, then reviewed.

use std::path::{Path, PathBuf};

use sev_snp_measure::guest::{self, Params};
use sev_snp_measure::sev_mode::SevMode;
use sev_snp_measure::util::hex_encode;
use sev_snp_measure::vcpu_types::cpu_sig_for;
use sev_snp_measure::vmm_types::VmmType;

fn fx(rel: &str) -> PathBuf {
    if rel.starts_with('/') {
        return PathBuf::from(rel);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// A directory removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sev-snp-measure-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn snp_ovmf_hash_gen_default() {
    let ovmf_hash =
        "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74"
            .to_string();
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: Some(ovmf_hash.as_str()),
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "329c8ce0972ae52343b64d34a434a86f245dfd74f5ed7aae15d22efc78fb9683632b9b50e4e1d7fa41179ef98a7ef198"
    );
}

#[test]
fn snp_ovmf_hash_gen_feature_snp_only() {
    let ovmf_hash =
        "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74"
            .to_string();
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: Some(ovmf_hash.as_str()),
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "ddc5224521617a536ee7ce9dd6224d1b58a8d4fda1c741f3ac99fc4bfa04ba6e9fc98646d4a07a9079397fa3852819b5"
    );
}

#[test]
fn snp_ovmf_hash_full_default() {
    let ovmf_hash =
        hex_encode(&guest::calc_snp_ovmf_hash(&fx("tests/fixtures/ovmf_AmdSev_suffix.bin")).unwrap());
    assert_eq!(
        ovmf_hash,
        "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74"
    );
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"console=ttyS0 loglevel=7".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: Some(ovmf_hash.as_str()),
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb28c653360fe4b3aba7e534442e7e1e17895dfe778d0228977"
    );
}

#[test]
fn snp_ovmf_hash_full_feature_snp_only() {
    let ovmf_hash =
        hex_encode(&guest::calc_snp_ovmf_hash(&fx("tests/fixtures/ovmf_AmdSev_suffix.bin")).unwrap());
    assert_eq!(
        ovmf_hash,
        "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74"
    );
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"console=ttyS0 loglevel=7".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: Some(ovmf_hash.as_str()),
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa"
    );
}

#[test]
fn snp_ec2_default() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Ec2,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "0ce9ccc06bab55eebe8abc234f3df6514883977a68a591b71052498ab52b2f1aa415db338033946ef93aa8278c0d67fb"
    );
}

#[test]
fn snp_ec2_feature_snp_only() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Ec2,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "0883bd0eeb716e65b7b977a321c278d1e51b33b5c655fab985443bbcc65c086b9c15e8a0bd8811050dec7e24964e5056"
    );
}

#[test]
fn snp_gce_default() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: 0,
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Gce,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "5da7106cf14cf46b1725ebab123eb9e53bd46a1e9f400cd0c08e7827b04b688ea8b4e403c8404efed4397ea5d5d0722e"
    );
}

#[test]
fn snp_gce_with_multiple_vcpus_default() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 4,
        vcpu_sig: 0,
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Gce,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "5c5debf100fc339f90276e761ee1f1658d08922c3b20e2a2e6c7a6c3370b2452a15a00eae11886a93d6fd1e7ab81e29d"
    );
}

#[test]
fn snp_default() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"console=ttyS0 loglevel=7".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb28c653360fe4b3aba7e534442e7e1e17895dfe778d0228977"
    );
}

#[test]
fn snp_guest_feature_snp_only() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"console=ttyS0 loglevel=7".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa"
    );
}

#[test]
fn snp_without_kernel_default() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "e1e1ca029dd7973ab9513295be68198472dcd4fc834bd9af9b63f6e8a1674dbf281a9278a4a2ebe0eed9f22adbcd0e2b"
    );
}

#[test]
fn snp_without_kernel_feature_snp_only() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "19358ba9a7615534a9a1e2f0dfc29384dcd4dcb7062ff9c6013b26869a5fc6ecabe033c48dd6f6db5d6d76e7c5df632d"
    );
}

#[test]
fn snp_with_multiple_vcpus_default() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 4,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "4953b1fb416fa874980e8442b3706d345926d5f38879134e00813c5d7abcbe78eafe7b422907be0b4698e2414a631942"
    );
}

#[test]
fn snp_with_multiple_vcpus_feature_snp_only() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 4,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "5061fffb019493a903613d56d54b94912a1a2f9e4502385f5c194616753720a92441310ba6c4933de877c36e23046ad5"
    );
}

#[test]
fn snp_with_ovmfx64_without_default() {
    let ovmf = fx("tests/fixtures/ovmf_OvmfX64_suffix.bin");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "28797ae0afaba4005a81e629acebfb59e6687949d6be44007cd5506823b0dd66f146aaae26ff291eed7b493d8a64c385"
    );
}

#[test]
fn snp_with_ovmfx64_without_kernel_feature_snp_only() {
    let ovmf = fx("tests/fixtures/ovmf_OvmfX64_suffix.bin");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "da0296de8193586a5512078dcd719eccecbd87e2b825ad4148c44f665dc87df21e5b49e21523a9ad993afdb6a30b4005"
    );
}

#[test]
fn snp_with_ovmfx64_and_kernel_should_fail() {
    let ovmf = fx("tests/fixtures/ovmf_OvmfX64_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    assert_eq!(
        guest::calc_launch_digest(&p).unwrap_err().to_string(),
        "Kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section"
    );
}

#[test]
fn seves() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x1,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevEs, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "13810ae661ea11e2bb205621f582fee268f0367c8f97bc297b7fadef3e12002c"
    );
}

#[test]
fn seves_with_multiple_vcpus() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 4,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevEs, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "0dccbcaba8e90b261bd0d2e1863a2f9da714768b7b2a19363cd6ae35aa90de91"
    );
}

#[test]
fn seves_dump_vmsa() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let tmp = TempDir::new();
    let p = Params {
        vcpus: 4,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: Some(tmp.path()),
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevEs, &ovmf)
    };
    guest::calc_launch_digest(&p).unwrap();
    assert!(tmp.path().join("vmsa0.bin").exists());
    assert!(tmp.path().join("vmsa1.bin").exists());
    assert!(tmp.path().join("vmsa2.bin").exists());
    assert!(tmp.path().join("vmsa3.bin").exists());
    assert!(!tmp.path().join("vmsa4.bin").exists());
}

#[test]
fn seves_with_ovmfx64_and_kernel_should_fail() {
    let ovmf = fx("tests/fixtures/ovmf_OvmfX64_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: 0,
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevEs, &ovmf)
    };
    assert_eq!(
        guest::calc_launch_digest(&p).unwrap_err().to_string(),
        "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
    );
}

#[test]
fn sev() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: 0,
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"console=ttyS0 loglevel=7".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::Sev, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "82a3ee5d537c3620628270c292ae30cb40c3c878666a7890ee7ef2a08fb535ff"
    );
}

#[test]
fn sev_with_kernel_without_initrd_and_append() {
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: 0,
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::Sev, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "77f613d7bbcdf12a73782ea9e88b0172aeda50d1a54201cb903594ff52846898"
    );
}

#[test]
fn sev_with_ovmfx64_and_kernel_should_fail() {
    let ovmf = fx("tests/fixtures/ovmf_OvmfX64_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: 0,
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::Sev, &ovmf)
    };
    assert_eq!(
        guest::calc_launch_digest(&p).unwrap_err().to_string(),
        "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
    );
}

#[test]
fn snp_dump_vmsa() {
    let ovmf_hash =
        "cab7e085874b3acfdbe2d96dcaa3125111f00c35c6fc9708464c2ae74bfdb048a198cb9a9ccae0b3e5e1a33f5f249819"
            .to_string();
    let ovmf = fx("tests/fixtures/ovmf_AmdSev_suffix.bin");
    let kernel: Option<PathBuf> = Some(fx("/dev/null"));
    let initrd: Option<PathBuf> = Some(fx("/dev/null"));
    let svsm: Option<PathBuf> = None;
    let tmp = TempDir::new();
    let p = Params {
        vcpus: 1,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: Some(b"".as_slice()),
        guest_features: 0x21,
        snp_ovmf_hash: Some(ovmf_hash.as_str()),
        vmm_type: VmmType::Qemu,
        dump_vmsa: Some(tmp.path()),
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::SevSnp, &ovmf)
    };
    guest::calc_launch_digest(&p).unwrap();
    assert!(tmp.path().join("vmsa0.bin").exists());
    assert!(!tmp.path().join("vmsa1.bin").exists());
}

#[test]
fn sev_with_ovmfx64_without_kernel() {
    let ovmf = fx("tests/fixtures/ovmf_OvmfX64_suffix.bin");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = None;
    let p = Params {
        vcpus: 1,
        vcpu_sig: 0,
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 0,
        ..Params::new(SevMode::Sev, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "b4c021e085fb83ceffe6571a3d357b4a98773c83c474e47f76c876708fe316da"
    );
}

#[test]
fn snp_svsm_4_vcpus() {
    let ovmf = fx("tests/fixtures/svsm_ovmf.fd");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = Some(fx("tests/fixtures/svsm.bin"));
    let p = Params {
        vcpus: 4,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 540672,
        ..Params::new(SevMode::SevSnpSvsm, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "27d154c27b7b359c935e250ec6fee72aa0ae8c1225e3b0e1cf46a9567e938066d7d6f94bbdc4a857818bdb79277a44b2"
    );
}

#[test]
fn snp_svsm_2_vcpus() {
    let ovmf = fx("tests/fixtures/svsm_ovmf.fd");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = Some(fx("tests/fixtures/svsm.bin"));
    let p = Params {
        vcpus: 2,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: None,
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 540672,
        ..Params::new(SevMode::SevSnpSvsm, &ovmf)
    };
    assert_eq!(
        hex_encode(&guest::calc_launch_digest(&p).unwrap()),
        "9b94745036aafddf4f7f8b00c7513abb5b7703178cb95aaa57928bd963d68d3bfcb715d6019b9167ee2517b11b0d9be7"
    );
}

#[test]
fn snp_svsm_dump_vmsa() {
    let ovmf = fx("tests/fixtures/svsm_ovmf.fd");
    let kernel: Option<PathBuf> = None;
    let initrd: Option<PathBuf> = None;
    let svsm: Option<PathBuf> = Some(fx("tests/fixtures/svsm.bin"));
    let tmp = TempDir::new();
    let p = Params {
        vcpus: 2,
        vcpu_sig: cpu_sig_for("EPYC-v4").unwrap(),
        kernel: kernel.as_deref(),
        initrd: initrd.as_deref(),
        append: None,
        guest_features: 0x21,
        snp_ovmf_hash: None,
        vmm_type: VmmType::Qemu,
        dump_vmsa: Some(tmp.path()),
        svsm_file: svsm.as_deref(),
        ovmf_vars_size: 540672,
        ..Params::new(SevMode::SevSnpSvsm, &ovmf)
    };
    guest::calc_launch_digest(&p).unwrap();
    assert!(tmp.path().join("vmsa0.bin").exists());
    assert!(tmp.path().join("vmsa1.bin").exists());
    assert!(!tmp.path().join("vmsa2.bin").exists());
}
