//! Arbitrary bytes as an attestation report: the parser must never panic,
//! must accept only what its contract says, and the full verifier must never
//! panic on whatever it accepts.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use snp::certs::AmdChain;
use snp::codec::pem_certificate;
use snp::report::{KNOWN_VERSIONS, REPORT_LEN, Report, Tcb};
use snp::verify::{Expectations, verify};

const VCEK_PEM: &str = include_str!("../../../test/fixtures/snp/certs/vcek.pem");

fn fixed() -> &'static (AmdChain, Vec<u8>) {
    static F: OnceLock<(AmdChain, Vec<u8>)> = OnceLock::new();
    F.get_or_init(|| (AmdChain::milan().unwrap(), pem_certificate(VCEK_PEM).unwrap()))
}

fuzz_target!(|data: &[u8]| {
    let Ok(r) = Report::parse(data) else {
        return;
    };
    assert_eq!(data.len(), REPORT_LEN);
    assert!(KNOWN_VERSIONS.contains(&r.version));
    let (chain, vcek) = fixed();
    let exp = Expectations {
        host_data: [0; 32],
        nonce: vec![0; 32],
        session_host_key: vec![0; 51],
        measurements: vec![r.measurement],
        min_tcb: Tcb { bootloader: 0, tee: 0, snp: 0, microcode: 0 },
        min_abi: (0, 0),
        smt_allowed: true,
        chip_ids: vec![],
    };
    // A random report is not signed by the fixture VCEK, so the verdict must
    // never pass.
    assert!(!verify(&r, vcek, chain, &exp).passed());
});
