//! Differential test: this crate's parse of every report fixture against
//! snpguest 0.10.0's (`snpguest display report`), recorded in
//! test/fixtures/snp/snpguest-display/ by snpguest-display.sh there.
//!
//! snpguest is the independent implementation the customer attestation guide
//! already uses. Agreement on every field the checks read means a layout
//! mistake here would have to be one snpguest makes too.

use snp::codec::hex;
use snp::report::{Report, Tcb};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/fixtures/snp/");

struct Display(Vec<String>);

impl Display {
    fn load(report: &str) -> Display {
        let p = format!("{FIX}snpguest-display/{}.txt", report.trim_end_matches(".bin"));
        let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
        Display(text.lines().map(|l| l.trim_end().to_string()).collect())
    }

    fn at(&self, header: &str) -> usize {
        self.0.iter().position(|l| l.trim_start() == header).unwrap_or_else(|| panic!("no {header:?}"))
    }

    /// The value after `label:` on the line that starts with it.
    fn value(&self, label: &str) -> String {
        let l =
            self.0.iter().find(|l| l.trim_start().starts_with(label)).unwrap_or_else(|| panic!("{label}"));
        l.trim_start()[label.len()..].trim().to_string()
    }

    /// Lines of space-separated hex bytes after `header`, up to a blank line
    /// or anything else.
    fn bytes(&self, header: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in &self.0[self.at(header) + 1..] {
            let words: Vec<&str> = l.split_whitespace().collect();
            let is_byte = |w: &&str| w.len() == 2 && w.bytes().all(|c| c.is_ascii_hexdigit());
            if words.is_empty() || !words.iter().all(is_byte) {
                break;
            }
            for w in words {
                out.push(u8::from_str_radix(w, 16).unwrap());
            }
        }
        out
    }

    /// The TCB block after `header` ("Reported TCB:" and so on).
    fn tcb(&self, header: &str) -> Tcb {
        let rest = &self.0[self.at(header) + 1..];
        let field = |name: &str| -> u8 {
            let l = rest.iter().find(|l| l.trim_start().starts_with(name)).unwrap();
            l.trim_start()[name.len()..].trim().parse().unwrap()
        };
        Tcb {
            bootloader: field("Boot Loader:"),
            tee: field("TEE:"),
            snp: field("SNP:"),
            microcode: field("Microcode:"),
        }
    }
}

const REPORTS: [&str; 8] = [
    "report-zero-vmpl0.bin",
    "report-ff-vmpl0.bin",
    "report-counting-vmpl0.bin",
    "report-counting-vmpl1.bin",
    "report-binding-vmpl0.bin",
    "report-binding-tsm.bin",
    "report-zero-vmpl0-directboot.bin",
    "report-hostdata-vmpl0.bin",
];

#[test]
fn recorded_output_is_from_the_pinned_snpguest() {
    let v = std::fs::read_to_string(format!("{FIX}snpguest-display/VERSION")).unwrap();
    assert_eq!(v.trim(), "snpguest 0.10.0");
}

#[test]
fn every_field_the_checks_read_agrees_with_snpguest() {
    for name in REPORTS {
        let r = Report::parse(&std::fs::read(format!("{FIX}{name}")).unwrap()).unwrap();
        let d = Display::load(name);
        assert_eq!(d.value("Version:"), r.version.to_string(), "{name} version");
        assert_eq!(d.value("VMPL:"), r.vmpl.to_string(), "{name} vmpl");
        assert_eq!(d.value("Signature Algorithm:"), r.signature_algo.to_string(), "{name} algo");
        assert_eq!(d.value("Guest SVN:"), r.guest_svn.to_string(), "{name} svn");
        assert_eq!(d.value("Guest Policy"), format!("({:#x}):", r.policy), "{name} policy");
        assert_eq!(d.value("Platform Info"), format!("({}):", r.platform_info), "{name} platform info");
        let fw = r.current_fw;
        assert_eq!(d.value("Current Version:"), format!("{}.{}.{}", fw.0, fw.1, fw.2), "{name} firmware");
        assert_eq!(d.value("mask chip key:"), r.mask_chip_key().to_string(), "{name} mask chip key");
        assert_eq!(d.value("signing key:"), if r.signing_key() == 0 { "vcek" } else { "?" }, "{name}");
        assert_eq!(d.bytes("Report Data:"), r.report_data, "{name} report data");
        assert_eq!(d.bytes("Measurement:"), r.measurement, "{name} measurement");
        assert_eq!(d.bytes("Host Data:"), r.host_data, "{name} host data");
        assert_eq!(d.bytes("Chip ID:"), r.chip_id, "{name} chip id");
        assert_eq!(d.tcb("Reported TCB:"), r.reported_tcb, "{name} reported tcb");
        assert_eq!(d.tcb("Current TCB:"), r.current_tcb, "{name} current tcb");
        assert_eq!(d.tcb("Committed TCB:"), r.committed_tcb, "{name} committed tcb");
        assert_eq!(d.tcb("Launch TCB:"), r.launch_tcb, "{name} launch tcb");
        // snpguest prints r and s as stored: 72 bytes, little-endian. This
        // crate keeps the 48 that matter, big-endian.
        for (header, ours) in [("R:", r.sig_r), ("S:", r.sig_s)] {
            let theirs = d.bytes(header);
            assert_eq!(theirs.len(), 72, "{name} {header}");
            let mut be = theirs[..48].to_vec();
            be.reverse();
            assert_eq!(hex(&be), hex(&ours), "{name} signature {header}");
            assert!(theirs[48..].iter().all(|&b| b == 0), "{name} {header} padding");
        }
    }
}
