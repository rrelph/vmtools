//! The section 8 checks against the genuine Phase 0 reports in
//! test/fixtures/snp/ (its README says what each should produce), and
//! against tampered copies of them.

use snp::certs::AmdChain;
use snp::codec::{pem_certificate, unhex};
use snp::report::{Report, Tcb};
use snp::verify::{Expectations, Outcome, Verdict, verify};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/fixtures/snp/");

const OVMF_ONLY: &str =
    "2cef0b36c9a6d7b19912ce2131c938c6b0fac0a422bc778e435a1a0b1c59847680a3e6506370debf875416f9a4b119c5";
const DIRECT_BOOT: &str =
    "9f2af610c3117241388d18af9c98356566ea1d2a5d555df44ceb07c6fe75021a8c29b4a6a370e530f2827a01972b1cf5";

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIX}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn vcek() -> Vec<u8> {
    pem_certificate(&String::from_utf8(read("certs/vcek.pem")).unwrap()).unwrap()
}

fn m(h: &str) -> [u8; 48] {
    unhex(h).unwrap().try_into().unwrap()
}

/// Expectations under which the binding fixture passes everything: the
/// fixture's own nonce and host key, both genuine measurements, the TCB it
/// was captured at.
fn exp() -> Expectations {
    Expectations {
        // The Phase 0 reports were launched with no host_data.
        host_data: [0; 32],
        nonce: read("binding-nonce.bin"),
        session_host_key: read("binding-hostkey.blob"),
        measurements: vec![m(OVMF_ONLY), m(DIRECT_BOOT)],
        min_tcb: Tcb { bootloader: 4, tee: 0, snp: 28, microcode: 222 },
        min_abi: (0, 0),
        smt_allowed: true,
        chip_ids: vec![],
    }
}

fn run(report: &[u8], e: &Expectations) -> Verdict {
    let chain = AmdChain::milan().unwrap();
    verify(&Report::parse(report).unwrap(), &vcek(), &chain, e)
}

fn failed(v: &Verdict) -> Vec<u8> {
    v.checks.iter().filter(|c| matches!(c.outcome, Outcome::Fail(_))).map(|c| c.number).collect()
}

const ALL_REPORTS: [&str; 7] = [
    "report-zero-vmpl0.bin",
    "report-ff-vmpl0.bin",
    "report-counting-vmpl0.bin",
    "report-counting-vmpl1.bin",
    "report-binding-vmpl0.bin",
    "report-binding-tsm.bin",
    "report-zero-vmpl0-directboot.bin",
];

#[test]
fn every_fixture_parses_as_described() {
    for name in ALL_REPORTS {
        let r = Report::parse(&read(name)).unwrap();
        assert_eq!((r.version, r.signature_algo), (5, 1), "{name}");
        assert_eq!(r.policy, 0x30000, "{name}");
        assert_eq!(r.reported_tcb, Tcb { bootloader: 4, tee: 0, snp: 28, microcode: 222 }, "{name}");
        assert_eq!(r.host_data, [0; 32], "{name}");
        let want_vmpl = if name.contains("vmpl1") { 1 } else { 0 };
        assert_eq!(r.vmpl, want_vmpl, "{name}");
        let want_m = if name.contains("directboot") { DIRECT_BOOT } else { OVMF_ONLY };
        assert_eq!(r.measurement, m(want_m), "{name}");
    }
}

#[test]
fn report_data_matches_its_input_file() {
    for (report, rd) in [
        ("report-zero-vmpl0.bin", "rd-zero.bin"),
        ("report-ff-vmpl0.bin", "rd-ff.bin"),
        ("report-counting-vmpl0.bin", "rd-counting.bin"),
        ("report-counting-vmpl1.bin", "rd-counting.bin"),
        ("report-binding-vmpl0.bin", "rd-binding.bin"),
        ("report-binding-tsm.bin", "rd-binding.bin"),
        ("report-zero-vmpl0-directboot.bin", "rd-zero.bin"),
    ] {
        assert_eq!(Report::parse(&read(report)).unwrap().report_data.to_vec(), read(rd), "{report}");
    }
}

#[test]
fn signatures_and_chain_pass_for_every_genuine_report() {
    // Checks 1-3 are the ones that do not depend on expectations.
    for name in ALL_REPORTS {
        let v = run(&read(name), &exp());
        for n in [1, 2, 3] {
            assert_eq!(v.outcome(n), &Outcome::Pass, "{name} check {n}\n{v}");
        }
    }
}

#[test]
fn binding_fixture_passes_everything() {
    for name in ["report-binding-vmpl0.bin", "report-binding-tsm.bin"] {
        let v = run(&read(name), &exp());
        assert!(v.passed(), "{name}\n{v}");
        assert_eq!(v.outcome(8), &Outcome::Pass);
    }
}

#[test]
fn vmpl1_is_genuinely_signed_and_caught_only_by_check_7() {
    // Its REPORT_DATA is the counting pattern, so bind to that by giving an
    // expectation whose hash it is: there is none, so check 4 fails as well.
    // Look at 7 on its own, then at a counting VMPL-0 report for contrast.
    let v1 = run(&read("report-counting-vmpl1.bin"), &exp());
    let v0 = run(&read("report-counting-vmpl0.bin"), &exp());
    assert_eq!(v1.outcome(2), &Outcome::Pass, "{v1}");
    assert!(matches!(v1.outcome(7), Outcome::Fail(_)), "{v1}");
    assert_eq!(v0.outcome(7), &Outcome::Pass, "{v0}");
    let mut f1 = failed(&v1);
    f1.retain(|&n| n != 7);
    assert_eq!(f1, failed(&v0), "VMPL 1 differs from VMPL 0 only in check 7");
}

#[test]
fn a_stale_nonce_fails_check_4_only() {
    let mut e = exp();
    e.nonce[0] ^= 1;
    let v = run(&read("report-binding-vmpl0.bin"), &e);
    assert_eq!(failed(&v), vec![4], "{v}");
}

#[test]
fn another_host_key_fails_check_4_only() {
    let mut e = exp();
    let n = e.session_host_key.len();
    e.session_host_key[n - 1] ^= 1;
    let v = run(&read("report-binding-vmpl0.bin"), &e);
    assert_eq!(failed(&v), vec![4], "{v}");
}

#[test]
fn a_measurement_outside_the_set_fails_check_5_only() {
    let mut e = exp();
    e.measurements = vec![m(DIRECT_BOOT)];
    let v = run(&read("report-binding-vmpl0.bin"), &e);
    assert_eq!(failed(&v), vec![5], "{v}");
    // And the direct-boot report is told apart from the OVMF-only one.
    let v = run(&read("report-zero-vmpl0-directboot.bin"), &e);
    assert_eq!(v.outcome(5), &Outcome::Pass);
}

#[test]
fn tcb_minimums_fail_check_9_only() {
    let mut e = exp();
    e.min_tcb = Tcb { bootloader: 4, tee: 0, snp: 29, microcode: 222 };
    let v = run(&read("report-binding-vmpl0.bin"), &e);
    assert_eq!(failed(&v), vec![9], "{v}");
}

#[test]
fn policy_minimums_and_smt_fail_check_6_only() {
    let mut e = exp();
    e.smt_allowed = false;
    assert_eq!(failed(&run(&read("report-binding-vmpl0.bin"), &e)), vec![6]);
    let mut e = exp();
    e.min_abi = (1, 0);
    assert_eq!(failed(&run(&read("report-binding-vmpl0.bin"), &e)), vec![6]);
}

#[test]
fn chip_allowlist_is_check_10() {
    let r = Report::parse(&read("report-binding-vmpl0.bin")).unwrap();
    let mut e = exp();
    e.chip_ids = vec![r.chip_id];
    assert!(run(r.raw(), &e).passed());
    e.chip_ids = vec![[7; 64]];
    assert_eq!(failed(&run(r.raw(), &e)), vec![10]);
}

/// Flip one bit at `off` in a copy of the binding report.
fn flipped(off: usize) -> Vec<u8> {
    let mut b = read("report-binding-vmpl0.bin");
    b[off] ^= 1;
    b
}

#[test]
fn any_flipped_bit_in_the_signed_region_fails_the_signature() {
    // One bit in each field the checks read, plus reserved bytes.
    for (off, field) in [
        (0x00, "version"),
        (0x08, "policy"),
        (0x30, "vmpl"),
        (0x4c, "reserved"),
        (0x50, "report_data"),
        (0x90, "measurement"),
        (0xc0, "host_data"),
        (0x180, "reported_tcb"),
        (0x1a0, "chip_id"),
        (0x29f, "last signed byte"),
    ] {
        let v = run(&flipped(off), &exp());
        assert!(matches!(v.outcome(2), Outcome::Fail(_)), "{field} at {off:#x}\n{v}");
        assert!(!v.passed(), "{field}");
    }
}

#[test]
fn a_flipped_bit_in_the_signature_fails_it() {
    for off in [0x2a0, 0x2a0 + 47, 0x2a0 + 72, 0x2a0 + 72 + 47] {
        let v = run(&flipped(off), &exp());
        assert!(matches!(v.outcome(2), Outcome::Fail(_)), "{off:#x}\n{v}");
    }
    // Bytes past the 48 that matter must be zero.
    let v = run(&flipped(0x2a0 + 60), &exp());
    assert!(matches!(v.outcome(2), Outcome::Fail(_)), "{v}");
}

#[test]
fn a_field_changed_consistently_still_fails_the_signature() {
    // What an attacker would actually do: set VMPL to 0 in the VMPL-1 report,
    // or clear DEBUG. The field check then passes, and only the signature
    // stands in the way.
    let mut b = read("report-counting-vmpl1.bin");
    b[0x30] = 0;
    let v = run(&b, &exp());
    assert_eq!(v.outcome(7), &Outcome::Pass);
    assert!(matches!(v.outcome(2), Outcome::Fail(_)), "{v}");
}

#[test]
fn a_vcek_for_another_tcb_is_refused() {
    // A genuine VCEK for the same chip at SNP SPL 27, fetched from AMD KDS
    // (fixture README): it chains, but it is not this report's VCEK.
    let other = read("certs/vcek-snp27.der");
    let chain = AmdChain::milan().unwrap();
    let r = Report::parse(&read("report-binding-vmpl0.bin")).unwrap();
    let v = verify(&r, &other, &chain, &exp());
    let Outcome::Fail(why) = v.outcome(1) else { panic!("{v}") };
    assert!(why.contains("TCB"), "{why}");
    assert!(matches!(v.outcome(2), Outcome::Fail(_)), "{v}");
}

#[test]
fn garbage_for_a_vcek_fails_checks_1_and_2() {
    let chain = AmdChain::milan().unwrap();
    let r = Report::parse(&read("report-binding-vmpl0.bin")).unwrap();
    let v = verify(&r, b"not a certificate", &chain, &exp());
    assert_eq!(failed(&v), vec![1, 2], "{v}");
}

// --- check 8: host_data is the organization's CA (Phase 3) ---

fn test_ca_host_data() -> [u8; 32] {
    let line = String::from_utf8(read("test-org-ca.pub")).unwrap();
    snp::binding::host_data_for_ca(&snp::sshkey::ed25519_blob_from_line(&line).unwrap())
}

#[test]
fn check_8_passes_for_the_ca_the_guest_was_launched_with() {
    let mut e = exp();
    e.host_data = test_ca_host_data();
    let v = run(&read("report-hostdata-vmpl0.bin"), &e);
    assert_eq!(v.outcome(8), &Outcome::Pass, "{v}");
    // Genuinely signed, like every other fixture.
    assert_eq!(v.outcome(2), &Outcome::Pass, "{v}");
}

#[test]
fn check_8_fails_for_any_other_ca_and_never_skips() {
    let mut e = exp();
    // Another CA: the binding fixture's host key stands in for one.
    e.host_data = snp::binding::host_data_for_ca(&read("binding-hostkey.blob"));
    let v = run(&read("report-hostdata-vmpl0.bin"), &e);
    assert!(matches!(v.outcome(8), Outcome::Fail(_)), "{v}");
    // A guest launched with no CA at all fails for an owner who has one.
    let v = run(&read("report-binding-vmpl0.bin"), &e);
    assert_eq!(failed(&v), vec![8], "{v}");
    for name in ALL_REPORTS {
        let v = run(&read(name), &e);
        assert!(!matches!(v.outcome(8), Outcome::Skip(_)), "{name}: check 8 skipped");
    }
}

// --- the four TCB fields, told apart (Phase 3, item 13) ---

#[test]
fn four_distinct_tcbs_are_each_read_from_their_own_field() {
    // Every genuine fixture has the same value in all four TCB fields, so
    // reading one in place of another passes on them. Here each is different.
    // The signature is broken by this and does not matter: only parsing is
    // under test.
    let tcb = |bootloader, tee, snp, microcode| Tcb { bootloader, tee, snp, microcode };
    let enc = |t: Tcb| u64::from_le_bytes([t.bootloader, t.tee, 0, 0, 0, 0, t.snp, t.microcode]);
    let (current, reported, committed, launch) =
        (tcb(1, 2, 3, 4), tcb(5, 6, 7, 8), tcb(9, 10, 11, 12), tcb(13, 14, 15, 16));
    let mut b = read("report-binding-vmpl0.bin");
    for (off, t) in [(0x38, current), (0x180, reported), (0x1e0, committed), (0x1f0, launch)] {
        b[off..off + 8].copy_from_slice(&enc(t).to_le_bytes());
    }
    let r = Report::parse(&b).unwrap();
    assert_eq!(r.current_tcb, current, "current_tcb");
    assert_eq!(r.reported_tcb, reported, "reported_tcb");
    assert_eq!(r.committed_tcb, committed, "committed_tcb");
    assert_eq!(r.launch_tcb, launch, "launch_tcb");
    // And check 9 judges the reported one.
    let mut e = exp();
    e.min_tcb = tcb(5, 6, 7, 8);
    assert_eq!(verify(&r, &vcek(), &AmdChain::milan().unwrap(), &e).outcome(9), &Outcome::Pass);
    e.min_tcb = tcb(5, 6, 7, 9);
    assert!(matches!(verify(&r, &vcek(), &AmdChain::milan().unwrap(), &e).outcome(9), Outcome::Fail(_)));
}
