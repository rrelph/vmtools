//! sev-snp-measure: calculate AMD SEV/SEV-ES/SEV-SNP guest launch
//! measurement (Python: `cli.py`).
//!
//! Arguments are parsed by hand, to the same rules as the Python version's
//! argparse for everything that tool documents: `--opt VALUE` and
//! `--opt=VALUE`, the last repeat of an option wins, usage errors exit 2.
//! Unlike argparse it does not accept abbreviated option names
//! (`--vcpu-t` for `--vcpu-type`).

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sev_snp_measure::guest::{self, Params};
use sev_snp_measure::sev_mode::SevMode;
use sev_snp_measure::util::{base64_encode, hex_encode};
use sev_snp_measure::vcpu_types::{CPU_SIGS, cpu_sig, cpu_sig_for};
use sev_snp_measure::vmm_types::VmmType;

const PROG: &str = "sev-snp-measure";
const UPSTREAM_VERSION: &str = "0.0.13";
const MODES: [&str; 5] = ["sev", "seves", "snp", "snp:ovmf-hash", "snp:svsm"];

const USAGE: &str = "\
usage: sev-snp-measure [-h] [--version] [-v] --mode {sev,seves,snp,snp:ovmf-hash,snp:svsm}
                       [--vcpus N] [--vcpu-type CPUTYPE] [--vcpu-sig VALUE]
                       [--vcpu-family FAMILY] [--vcpu-model MODEL]
                       [--vcpu-stepping STEPPING] [--vmm-type VMMTYPE] --ovmf PATH
                       [--kernel PATH] [--initrd PATH] [--append CMDLINE]
                       [--guest-features VALUE] [--output-format {hex,base64}]
                       [--snp-ovmf-hash HASH] [--dump-vmsa] [--svsm PATH]
                       [--vars-size SIZE | --vars-file PATH]";

fn help() -> String {
    let types: Vec<&str> = CPU_SIGS.iter().map(|(n, _)| *n).collect();
    format!(
        "{USAGE}

Calculate AMD SEV/SEV-ES/SEV-SNP guest launch measurement

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose
  --mode {{sev,seves,snp,snp:ovmf-hash,snp:svsm}}
                        Guest mode
  --vcpus N             Number of guest vcpus
  --vcpu-type CPUTYPE   Type of guest vcpu ({types})
  --vcpu-sig VALUE      Guest vcpu signature value
  --vcpu-family FAMILY  Guest vcpu family
  --vcpu-model MODEL    Guest vcpu model
  --vcpu-stepping STEPPING
                        Guest vcpu stepping
  --vmm-type VMMTYPE    Type of guest vmm ({vmms})
  --ovmf PATH           OVMF file to calculate hash from
  --kernel PATH         Kernel file to calculate hash from
  --initrd PATH         Initrd file to calculate hash from (use with --kernel)
  --append CMDLINE      Kernel command line to calculate hash from (use with --kernel)
  --guest-features VALUE
                        Hex representation of the guest kernel features expected to be included
                        (defaults to 0x1); see README.md for possible values
  --output-format {{hex,base64}}
                        Measurement output format
  --snp-ovmf-hash HASH  Precalculated hash of the OVMF binary (hex string)
  --dump-vmsa           Write measured VMSAs to vmsa<N>.bin (seves, snp, and snp:svsm modes only)

snp:svsm Mode:
  AMD SEV-SNP with Coconut-SVSM. This mode additionally requires --svsm and either
  --vars-file or --vars-size to be set.

  --svsm PATH           SVSM binary
  --vars-size SIZE      Size of the OVMF_VARS file in bytes (conflicts with --vars-file)
  --vars-file PATH      OVMF_VARS file (conflicts with --vars-size)
",
        types = types.join(", "),
        vmms = VmmType::NAMES.join(", "),
    )
}

/// A usage error: argparse prints the usage line and the message, exit 2.
struct Usage(String);

fn usage_err<T>(msg: impl Into<String>) -> Result<T, Usage> {
    Err(Usage(msg.into()))
}

#[derive(Default)]
struct Args {
    verbose: bool,
    mode: Option<String>,
    vcpus: Option<u32>,
    vcpu_type: Option<String>,
    vcpu_sig: Option<u32>,
    vcpu_family: Option<u32>,
    vcpu_model: Option<u32>,
    vcpu_stepping: Option<u32>,
    vmm_type: Option<String>,
    ovmf: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    append: Option<OsString>,
    guest_features: Option<u64>,
    output_format: Option<String>,
    snp_ovmf_hash: Option<String>,
    dump_vmsa: bool,
    svsm: Option<PathBuf>,
    vars_size: Option<u64>,
    vars_file: Option<PathBuf>,
}

/// Python's `int(s)`: decimal, optional sign and surrounding whitespace,
/// `_` between digits. Negative values are refused here, where Python
/// would carry them into the arithmetic.
fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    let t = t.strip_prefix('+').unwrap_or(t);
    parse_digits(t, 10)
}

/// Python's `int(s, 0)`: `0x`/`0o`/`0b` prefixes, otherwise decimal with no
/// leading zero (except zero itself).
fn parse_auto_int(s: &str) -> Option<u64> {
    let t = s.trim();
    let t = t.strip_prefix('+').unwrap_or(t);
    let lower = t.to_ascii_lowercase();
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            // int('0x_1f', 0) is allowed: one underscore after the prefix.
            return parse_digits(rest.strip_prefix('_').unwrap_or(rest), radix);
        }
    }
    if t.len() > 1 && t.starts_with('0') && t.trim_start_matches(['0', '_']).is_empty() {
        return parse_digits(t, 10); // "00", "0_0": zero
    }
    if t.starts_with('0') && t.len() > 1 {
        return None;
    }
    parse_digits(t, 10)
}

fn parse_digits(t: &str, radix: u32) -> Option<u64> {
    if t.is_empty() || t.starts_with('_') || t.ends_with('_') || t.contains("__") {
        return None;
    }
    let digits: String = t.chars().filter(|&c| c != '_').collect();
    if !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(&digits, radix).ok()
}

fn looks_like_option(v: &OsStr) -> bool {
    let b = v.as_encoded_bytes();
    b.starts_with(b"-") && b.len() > 1 && !b.contains(&b' ')
}

fn as_str<'a>(opt: &str, v: &'a OsStr) -> Result<&'a str, Usage> {
    v.to_str().ok_or_else(|| Usage(format!("argument {opt}: invalid value: {}", v.to_string_lossy())))
}

fn int_arg<T: TryFrom<u64>>(opt: &str, v: &OsStr, auto: bool) -> Result<T, Usage> {
    let s = as_str(opt, v)?;
    let parsed = if auto { parse_auto_int(s) } else { parse_int(s) };
    let kind = if auto { "<lambda>" } else { "int" };
    parsed
        .and_then(|n| T::try_from(n).ok())
        .ok_or_else(|| Usage(format!("argument {opt}: invalid {kind} value: '{s}'")))
}

fn choice(opt: &str, v: &OsStr, choices: &[&str]) -> Result<String, Usage> {
    let s = as_str(opt, v)?;
    if choices.contains(&s) {
        Ok(s.to_owned())
    } else {
        let list: Vec<String> = choices.iter().map(|c| format!("'{c}'")).collect();
        usage_err(format!("argument {opt}: invalid choice: '{s}' (choose from {})", list.join(", ")))
    }
}

enum Parsed {
    Run(Box<Args>),
    Exit(String),
}

fn parse_args(argv: impl IntoIterator<Item = OsString>) -> Result<Parsed, Usage> {
    let mut a = Args::default();
    let mut it = argv.into_iter();
    let vcpu_types: Vec<&str> = CPU_SIGS.iter().map(|(n, _)| *n).collect();
    let mut vars_seen: Option<&str> = None;

    while let Some(arg) = it.next() {
        let bytes = arg.as_encoded_bytes();
        // Split `--opt=value`; the option name is ASCII, so splitting the
        // OsStr at the first '=' is sound.
        let (name, inline): (String, Option<OsString>) = match bytes.iter().position(|&b| b == b'=') {
            Some(eq) if bytes.starts_with(b"--") => {
                // SAFETY: both halves split at an ASCII byte of a valid
                // OsStr encoding, so each is itself valid.
                let (n, v) = unsafe {
                    (
                        OsStr::from_encoded_bytes_unchecked(&bytes[..eq]),
                        OsStr::from_encoded_bytes_unchecked(&bytes[eq + 1..]),
                    )
                };
                (n.to_string_lossy().into_owned(), Some(v.to_owned()))
            }
            _ => (arg.to_string_lossy().into_owned(), None),
        };

        match name.as_str() {
            "-h" | "--help" | "--version" | "-v" | "--verbose" | "--dump-vmsa" if inline.is_some() => {
                return usage_err(format!("argument {name}: ignored explicit argument"));
            }
            "-h" | "--help" => return Ok(Parsed::Exit(help())),
            "--version" => {
                return Ok(Parsed::Exit(format!(
                    "{PROG} {} (Rust port of sev-snp-measure {UPSTREAM_VERSION})\n",
                    env!("CARGO_PKG_VERSION")
                )));
            }
            "-v" | "--verbose" => {
                a.verbose = true;
                continue;
            }
            "--dump-vmsa" => {
                a.dump_vmsa = true;
                continue;
            }
            _ => {}
        }

        let takes_value = matches!(
            name.as_str(),
            "--mode"
                | "--vcpus"
                | "--vcpu-type"
                | "--vcpu-sig"
                | "--vcpu-family"
                | "--vcpu-model"
                | "--vcpu-stepping"
                | "--vmm-type"
                | "--ovmf"
                | "--kernel"
                | "--initrd"
                | "--append"
                | "--guest-features"
                | "--output-format"
                | "--snp-ovmf-hash"
                | "--svsm"
                | "--vars-size"
                | "--vars-file"
        );
        if !takes_value {
            return usage_err(format!("unrecognized arguments: {}", arg.to_string_lossy()));
        }
        let value = match inline {
            Some(v) => v,
            None => match it.next() {
                // argparse takes a following "-x" as another option, not a
                // value, unless it is "-" alone or contains a space.
                Some(v) if !looks_like_option(&v) => v,
                _ => return usage_err(format!("argument {name}: expected one argument")),
            },
        };
        let v = value.as_os_str();
        let n = name.as_str();
        match n {
            "--mode" => a.mode = Some(choice(n, v, &MODES)?),
            "--vcpus" => a.vcpus = Some(int_arg(n, v, false)?),
            "--vcpu-type" => a.vcpu_type = Some(choice(n, v, &vcpu_types)?),
            "--vcpu-sig" => a.vcpu_sig = Some(int_arg(n, v, true)?),
            "--vcpu-family" => a.vcpu_family = Some(int_arg(n, v, false)?),
            "--vcpu-model" => a.vcpu_model = Some(int_arg(n, v, false)?),
            "--vcpu-stepping" => a.vcpu_stepping = Some(int_arg(n, v, false)?),
            "--vmm-type" => a.vmm_type = Some(as_str(n, v)?.to_owned()),
            "--ovmf" => a.ovmf = Some(PathBuf::from(value)),
            "--kernel" => a.kernel = Some(PathBuf::from(value)),
            "--initrd" => a.initrd = Some(PathBuf::from(value)),
            "--append" => a.append = Some(value),
            "--guest-features" => a.guest_features = Some(int_arg(n, v, true)?),
            "--output-format" => a.output_format = Some(choice(n, v, &["hex", "base64"])?),
            "--snp-ovmf-hash" => a.snp_ovmf_hash = Some(as_str(n, v)?.to_owned()),
            "--svsm" => a.svsm = Some(PathBuf::from(value)),
            "--vars-size" | "--vars-file" => {
                if let Some(other) = vars_seen.filter(|o| *o != n) {
                    return usage_err(format!("argument {n}: not allowed with argument {other}"));
                }
                vars_seen = Some(if n == "--vars-size" { "--vars-size" } else { "--vars-file" });
                if n == "--vars-size" {
                    a.vars_size = Some(int_arg(n, v, false)?);
                } else {
                    a.vars_file = Some(PathBuf::from(value));
                }
            }
            _ => unreachable!(),
        }
    }

    let mut missing = Vec::new();
    if a.mode.is_none() {
        missing.push("--mode");
    }
    if a.ovmf.is_none() {
        missing.push("--ovmf");
    }
    if !missing.is_empty() {
        return usage_err(format!("the following arguments are required: {}", missing.join(", ")));
    }
    Ok(Parsed::Run(Box::new(a)))
}

fn get_vcpu_sig(a: &Args, vmm_type: VmmType) -> Result<Option<u32>, Usage> {
    let mode = a.mode.as_deref().unwrap_or_default();
    if mode == "sev" {
        Ok(Some(0))
    } else if let Some(family) = a.vcpu_family {
        // Python fails with a TypeError when model or stepping is missing.
        match (a.vcpu_model, a.vcpu_stepping) {
            (Some(model), Some(stepping)) => Ok(Some(cpu_sig(family, model, stepping))),
            _ => usage_err("--vcpu-family requires --vcpu-model and --vcpu-stepping"),
        }
    } else if let Some(sig) = a.vcpu_sig {
        Ok(Some(sig))
    } else if let Some(t) = a.vcpu_type.as_deref() {
        Ok(cpu_sig_for(t))
    } else if vmm_type == VmmType::Qemu {
        usage_err(format!("missing --vcpu-type or --vcpu-sig or --vcpu-family in guest mode '{mode}'"))
    } else {
        Ok(None)
    }
}

/// Runtime failures print `Error: ...` and exit 1, as Python does for a
/// RuntimeError. (Python lets its other exceptions escape as a traceback,
/// also exit 1.)
enum Fail {
    Usage(Usage),
    Runtime(String),
}

impl From<Usage> for Fail {
    fn from(u: Usage) -> Self {
        Fail::Usage(u)
    }
}

impl From<sev_snp_measure::Error> for Fail {
    fn from(e: sev_snp_measure::Error) -> Self {
        Fail::Runtime(e.0)
    }
}

fn run(a: Args) -> Result<String, Fail> {
    let mode_str = a.mode.as_deref().expect("required");
    let ovmf = a.ovmf.as_deref().expect("required");

    if mode_str == "snp:ovmf-hash" {
        return Ok(hex_encode(&guest::calc_snp_ovmf_hash(ovmf)?) + "\n");
    }

    // Python tests these for truthiness: an empty --initrd or --append
    // passes without --kernel.
    let nonempty = |p: &Option<PathBuf>| p.as_ref().is_some_and(|p| !p.as_os_str().is_empty());
    if nonempty(&a.initrd) && a.kernel.is_none() {
        return Err(Usage("--kernel required when using --initrd".into()).into());
    }
    if a.append.as_ref().is_some_and(|s| !s.is_empty()) && a.kernel.is_none() {
        return Err(Usage("--kernel required when using --append".into()).into());
    }
    if mode_str != "sev" && a.vcpus.is_none() {
        return Err(Usage(format!("missing --vcpus N in guest mode '{mode_str}'")).into());
    }

    let vmm_name = a.vmm_type.as_deref().unwrap_or("QEMU");
    let vmm_type =
        VmmType::from_name(vmm_name).ok_or_else(|| Usage(format!("unknown VMM type '{vmm_name}'")))?;

    // With ec2 or gce and no signature Python passes None along; those VMM
    // types never use the value.
    let vcpu_sig = get_vcpu_sig(&a, vmm_type)?.unwrap_or(0);

    let sev_mode: SevMode = mode_str.parse()?;
    let mut vars_size = 0;
    if sev_mode == SevMode::SevSnpSvsm {
        if let Some(f) = a.vars_file.as_deref().filter(|f| !f.as_os_str().is_empty()) {
            vars_size =
                std::fs::metadata(f).map_err(|e| Fail::Runtime(format!("{}: {e}", f.display())))?.len();
        } else if let Some(n) = a.vars_size.filter(|&n| n != 0) {
            vars_size = n;
        } else {
            return Err(Usage("snp:svsm mode requires --vars-size or --vars-file".into()).into());
        }
    }

    if a.dump_vmsa && !matches!(sev_mode, SevMode::SevEs | SevMode::SevSnp | SevMode::SevSnpSvsm) {
        return Err(Usage("--dump-vmsa is not availibe in the selected mode".into()).into());
    }

    #[cfg(unix)]
    let append: Option<&[u8]> = {
        use std::os::unix::ffi::OsStrExt;
        a.append.as_deref().map(OsStr::as_bytes)
    };
    #[cfg(not(unix))]
    let append_owned = a
        .append
        .as_deref()
        .map(|s| s.to_str().map(|s| s.as_bytes().to_vec()))
        .transpose()
        .ok_or_else(|| Usage("argument --append: not valid UTF-8".into()))?;
    #[cfg(not(unix))]
    let append: Option<&[u8]> = append_owned.as_deref();

    let params = Params {
        mode: sev_mode,
        vcpus: a.vcpus.unwrap_or(0),
        vcpu_sig,
        ovmf_file: ovmf,
        kernel: a.kernel.as_deref(),
        initrd: a.initrd.as_deref(),
        append,
        guest_features: a.guest_features.unwrap_or(0x1),
        snp_ovmf_hash: a.snp_ovmf_hash.as_deref(),
        vmm_type,
        dump_vmsa: a.dump_vmsa.then_some(Path::new(".")),
        svsm_file: a.svsm.as_deref(),
        ovmf_vars_size: vars_size,
    };
    let ld = guest::calc_launch_digest(&params)?;

    let measurement = match a.output_format.as_deref().unwrap_or("hex") {
        "base64" => base64_encode(&ld),
        _ => hex_encode(&ld),
    };
    Ok(if a.verbose {
        format!("Calculated {} guest measurement: {measurement}\n", sev_mode.name())
    } else {
        measurement + "\n"
    })
}

fn main() -> ExitCode {
    let result = match parse_args(std::env::args_os().skip(1)) {
        Ok(Parsed::Exit(text)) => Ok(text),
        Ok(Parsed::Run(a)) => run(*a),
        Err(u) => Err(Fail::Usage(u)),
    };
    match result {
        Ok(out) => {
            let mut stdout = std::io::stdout().lock();
            if stdout.write_all(out.as_bytes()).and_then(|_| stdout.flush()).is_err() {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(Fail::Usage(Usage(msg))) => {
            eprintln!("{USAGE}\n{PROG}: error: {msg}");
            ExitCode::from(2)
        }
        Err(Fail::Runtime(msg)) => {
            eprintln!("Error: {msg}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Args {
        match parse_args(v.iter().map(OsString::from)) {
            Ok(Parsed::Run(a)) => *a,
            _ => panic!("did not parse"),
        }
    }

    #[test]
    fn python_int_forms() {
        assert_eq!(parse_auto_int("0x21"), Some(0x21));
        assert_eq!(parse_auto_int("0X21"), Some(0x21));
        assert_eq!(parse_auto_int("33"), Some(33));
        assert_eq!(parse_auto_int("0"), Some(0));
        assert_eq!(parse_auto_int("00"), Some(0));
        assert_eq!(parse_auto_int("0b101"), Some(5));
        assert_eq!(parse_auto_int("0o17"), Some(15));
        assert_eq!(parse_auto_int("1_000"), Some(1000));
        assert_eq!(parse_auto_int("010"), None);
        assert_eq!(parse_auto_int("0x"), None);
        assert_eq!(parse_auto_int("-1"), None);
        assert_eq!(parse_int("010"), Some(10));
        assert_eq!(parse_int(" 4 "), Some(4));
        assert_eq!(parse_int("0x4"), None);
    }

    // Python: tests/test_cli.py
    #[test]
    fn vcpu_sig_zero() {
        let a = args(&["--mode", "snp", "--ovmf", "x", "--vcpu-sig", "0"]);
        assert_eq!(get_vcpu_sig(&a, VmmType::Qemu).ok(), Some(Some(0)));
    }

    #[test]
    fn vcpu_sig_none_qemu_errors() {
        let a = args(&["--mode", "snp", "--ovmf", "x"]);
        assert!(get_vcpu_sig(&a, VmmType::Qemu).is_err());
    }

    #[test]
    fn vcpu_sig_from_type() {
        let a = args(&["--mode=snp", "--ovmf=x", "--vcpu-type=EPYC-Milan"]);
        assert_eq!(get_vcpu_sig(&a, VmmType::Qemu).ok(), Some(cpu_sig_for("EPYC-Milan")));
    }

    #[test]
    fn vcpu_sig_from_family() {
        let a = args(&[
            "--mode",
            "snp",
            "--ovmf",
            "x",
            "--vcpu-family",
            "25",
            "--vcpu-model",
            "1",
            "--vcpu-stepping",
            "1",
        ]);
        assert_eq!(get_vcpu_sig(&a, VmmType::Qemu).ok(), Some(Some(cpu_sig(25, 1, 1))));
    }

    #[test]
    fn last_repeat_wins_and_conflicts_refused() {
        let a = args(&["--mode", "sev", "--mode", "snp", "--ovmf", "x"]);
        assert_eq!(a.mode.as_deref(), Some("snp"));
        assert!(
            parse_args(
                ["--mode", "snp:svsm", "--ovmf", "x", "--vars-size", "1", "--vars-file", "y"]
                    .map(OsString::from)
            )
            .is_err()
        );
    }
}
