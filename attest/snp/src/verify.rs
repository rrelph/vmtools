//! The guest owner's checks on a report (design section 8), numbered as the
//! design numbers them. Every check runs and is reported, so a failure says
//! everything that is wrong at once; the verdict passes only if none fails.

use core::fmt;

use crate::certs::AmdChain;
use crate::codec::hex;
use crate::report::{Report, Tcb, policy};
use p384::ecdsa::Signature;
use p384::ecdsa::signature::Verifier;

pub use crate::binding::report_data_for;

/// What the guest owner accepts.
pub struct Expectations {
    /// host_data the report must carry: `binding::host_data_for_ca` of the
    /// guest owner's organization CA.
    pub host_data: [u8; 32],
    /// The nonce this tool generated for this attempt.
    pub nonce: Vec<u8>,
    /// The host key blob observed on this SSH session, not the one the guest
    /// claims.
    pub session_host_key: Vec<u8>,
    /// The accepted launch measurements (section 10.3).
    pub measurements: Vec<[u8; 48]>,
    pub min_tcb: Tcb,
    /// Minimum guest policy ABI, (major, minor).
    pub min_abi: (u8, u8),
    pub smt_allowed: bool,
    /// Check 10: empty means any chip.
    pub chip_ids: Vec<[u8; 64]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(String),
    /// Not checked, and why. Never counts as a pass.
    Skip(String),
}

#[derive(Clone, Debug)]
pub struct Check {
    /// The design's section 8 number.
    pub number: u8,
    pub name: &'static str,
    pub outcome: Outcome,
    /// What was compared, for the reader.
    pub detail: String,
}

pub struct Verdict {
    pub checks: Vec<Check>,
}

impl Verdict {
    pub fn passed(&self) -> bool {
        !self.checks.iter().any(|c| matches!(c.outcome, Outcome::Fail(_)))
    }

    pub fn outcome(&self, number: u8) -> &Outcome {
        &self.checks.iter().find(|c| c.number == number).expect("every check is recorded").outcome
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            let (tag, why) = match &c.outcome {
                Outcome::Pass => ("PASS", String::new()),
                Outcome::Fail(w) => ("FAIL", format!(": {w}")),
                Outcome::Skip(w) => ("SKIP", format!(": {w}")),
            };
            writeln!(f, "  [{tag}] {:>2}. {}{why}", c.number, c.name)?;
            for line in c.detail.lines() {
                writeln!(f, "          {line}")?;
            }
        }
        Ok(())
    }
}

fn check(number: u8, name: &'static str, detail: String, fails: Vec<String>) -> Check {
    let outcome = if fails.is_empty() { Outcome::Pass } else { Outcome::Fail(fails.join("; ")) };
    Check { number, name, outcome, detail }
}

/// Run checks 1–10 on `report`, with `vcek_der` as the VCEK fetched for its
/// chip_id and reported_tcb.
pub fn verify(report: &Report, vcek_der: &[u8], chain: &AmdChain, exp: &Expectations) -> Verdict {
    let mut checks = Vec::new();

    // 1. Certificate chain. The pinned ARK and ASK were checked when `chain`
    // was built; here the VCEK must chain to them and be the one for this
    // report's chip and TCB.
    let vcek = chain.verify_vcek(vcek_der);
    let mut fails = Vec::new();
    if report.chip_id == [0; 64] {
        fails.push("chip_id is zero (MaskChipId): the VCEK cannot be looked up".into());
    }
    let detail = match &vcek {
        Err(e) => {
            fails.push(e.clone());
            String::new()
        }
        Ok(v) => {
            if v.hwid != report.chip_id {
                fails.push("VCEK was issued for a different chip_id".into());
            }
            if v.tcb != report.reported_tcb {
                fails.push(format!("VCEK was issued for TCB {}, report has {}", v.tcb, report.reported_tcb));
            }
            if !v.product.contains("Milan") {
                fails.push(format!("VCEK product is {:?}, expected Milan", v.product));
            }
            format!(
                "VCEK {} for chip_id {}…, TCB {}\nsigned by the pinned ASK, itself signed by the pinned ARK",
                v.product,
                &hex(&v.hwid)[..16],
                v.tcb
            )
        }
    };
    checks.push(check(1, "certificate chain VCEK -> ASK -> ARK", detail, fails));

    // 2. Signature, under that VCEK.
    let mut fails = Vec::new();
    if report.signing_key() != 0 {
        fails.push(format!("report is not signed by a VCEK (SIGNING_KEY = {})", report.signing_key()));
    }
    if report.mask_chip_key() {
        fails.push("MASK_CHIP_KEY is set: the report carries no signature".into());
    }
    if !report.sig_well_formed {
        fails.push("signature field has non-zero bytes where zero is required".into());
    }
    match (&vcek, Signature::from_scalars(report.sig_r, report.sig_s)) {
        (Err(_), _) => fails.push("no valid VCEK to check it with".into()),
        (_, Err(_)) => fails.push("signature r or s is out of range".into()),
        (Ok(v), Ok(sig)) => {
            if v.key.verify(report.signed_bytes(), &sig).is_err() {
                fails.push("ECDSA P-384 signature does not verify".into());
            }
        }
    }
    checks.push(check(2, "report signature", "ECDSA P-384 / SHA-384 over bytes 0x000-0x29f".into(), fails));

    // 3. Version and signature algorithm.
    let mut fails = Vec::new();
    // Report::parse refuses other versions; this can only fail if that
    // guard is ever removed.
    if !crate::report::KNOWN_VERSIONS.contains(&report.version) {
        fails.push(format!("report version {} is not one this verifier knows", report.version));
    }
    if report.signature_algo != 1 {
        fails.push(format!(
            "signature algorithm {} is not 1 (ECDSA P-384 with SHA-384)",
            report.signature_algo
        ));
    }
    let detail = format!("version {}, signature algorithm {}", report.version, report.signature_algo);
    checks.push(check(3, "report version and signature algorithm", detail, fails));

    // 4. REPORT_DATA binds this nonce and this session's host key.
    let want = report_data_for(&exp.nonce, &exp.session_host_key);
    let fails = if report.report_data == want {
        vec![]
    } else {
        vec![
            "REPORT_DATA is not SHA-512(this nonce || this session's host key): \
              a stale report, or not the guest this session is connected to"
                .into(),
        ]
    };
    let detail = format!("expected {}\nreported {}", hex(&want), hex(&report.report_data));
    checks.push(check(4, "REPORT_DATA binding", detail, fails));

    // 5. Measurement in the accepted set.
    let fails = if exp.measurements.contains(&report.measurement) {
        vec![]
    } else {
        vec!["measurement is not in the accepted set".into()]
    };
    let mut detail = format!("reported {}", hex(&report.measurement));
    for m in &exp.measurements {
        detail.push_str(&format!("\naccepted {}", hex(m)));
    }
    checks.push(check(5, "launch measurement", detail, fails));

    // 6. Policy.
    let p = report.policy;
    let mut fails = Vec::new();
    if p & policy::DEBUG != 0 {
        fails.push("DEBUG is allowed: the host can read and change guest memory".into());
    }
    if p & policy::MIGRATE_MA != 0 {
        fails.push("a migration agent is allowed".into());
    }
    if p & policy::CXL_ALLOW != 0 {
        fails.push("CXL memory is allowed".into());
    }
    if p & policy::RESERVED_ONE == 0 {
        fails.push("reserved bit 17 is clear: not a valid SNP policy".into());
    }
    if p & policy::SMT != 0 && !exp.smt_allowed {
        fails.push("SMT is allowed, and the service policy forbids it".into());
    }
    let unknown =
        p & !(policy::HARDENING | policy::SMT | policy::DEBUG | policy::MIGRATE_MA | policy::CXL_ALLOW);
    if unknown != 0 {
        fails.push(format!("policy has bits this verifier does not know: {unknown:#x}"));
    }
    let abi = (((p & policy::ABI_MAJOR) >> 8) as u8, (p & policy::ABI_MINOR) as u8);
    if abi < exp.min_abi {
        fails.push(format!(
            "policy ABI {}.{} is below the minimum {}.{}",
            abi.0, abi.1, exp.min_abi.0, exp.min_abi.1
        ));
    }
    let yes_no = |bit| if p & bit != 0 { "allowed" } else { "not allowed" };
    let detail = format!(
        "policy {p:#x}: debugging {}, migration agent {}, SMT {}, ABI {}.{} (minimum {}.{})",
        yes_no(policy::DEBUG),
        yes_no(policy::MIGRATE_MA),
        yes_no(policy::SMT),
        abi.0,
        abi.1,
        exp.min_abi.0,
        exp.min_abi.1
    );
    checks.push(check(6, "guest policy", detail, fails));

    // 7. VMPL.
    let fails = if report.vmpl == 0 {
        vec![]
    } else {
        vec![format!("report was requested at VMPL {}, not 0", report.vmpl)]
    };
    checks.push(check(7, "VMPL", format!("VMPL {}", report.vmpl), fails));

    // 8. host_data: the organization's CA. Stage 0 refuses to start sshd
    // unless the CA it was given hashes to this; this check is the guest
    // owner's own confirmation, and it can only pass or fail.
    let fails = if report.host_data == exp.host_data {
        vec![]
    } else {
        vec!["host_data is not your organization's CA: this VM was started for a different CA".into()]
    };
    let fp = crate::sshkey::fingerprint_of_digest;
    let detail = format!(
        "expected {} (your CA, {})\nreported {} ({})",
        hex(&exp.host_data),
        fp(&exp.host_data),
        hex(&report.host_data),
        fp(&report.host_data)
    );
    checks.push(check(8, "host_data (org CA binding)", detail, fails));

    // 9. TCB minimums.
    let fails = if report.reported_tcb.meets(&exp.min_tcb) {
        vec![]
    } else {
        vec![format!("reported TCB is below the minimum {}", exp.min_tcb)]
    };
    let detail = format!("reported {}\nminimum  {}", report.reported_tcb, exp.min_tcb);
    checks.push(check(9, "TCB minimums", detail, fails));

    // 10. chip_id allowlist, if the guest owner keeps one.
    checks.push(if exp.chip_ids.is_empty() {
        Check {
            number: 10,
            name: "chip_id allowlist",
            outcome: Outcome::Skip("no allowlist given".into()),
            detail: format!("chip_id {}", hex(&report.chip_id)),
        }
    } else {
        let fails = if exp.chip_ids.contains(&report.chip_id) {
            vec![]
        } else {
            vec!["chip_id is not in the allowlist".into()]
        };
        check(10, "chip_id allowlist", format!("chip_id {}", hex(&report.chip_id)), fails)
    });

    Verdict { checks }
}
