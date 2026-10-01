//! snp-create-id-block: calculate AMD SEV-SNP guest id block (Python:
//! `id_block.main`).

use std::path::PathBuf;
use std::process::ExitCode;

use sev_snp_measure::id_block::{load_private_key_from_pem_file, snp_calc_id_block};
use sev_snp_measure::util::base64_decode;

const PROG: &str = "snp-create-id-block";
const USAGE: &str = "usage: snp-create-id-block [-h] [--measurement VALUE] [--idkey PATH] [--authorkey PATH]";
const HELP: &str = "

Calculate AMD SEV-SNP guest id block

options:
  -h, --help           show this help message and exit
  --measurement VALUE  Guest launch measurement in Base64 encoding
  --idkey PATH         id private key file
  --authorkey PATH     author private key file";

enum Fail {
    Usage(String),
    Runtime(String),
}

fn run() -> Result<Option<String>, Fail> {
    let (mut measurement, mut idkey, mut authorkey) = (None, None, None);
    let mut it = std::env::args_os().skip(1);
    while let Some(arg) = it.next() {
        let arg = arg
            .into_string()
            .map_err(|a| Fail::Usage(format!("unrecognized arguments: {}", a.to_string_lossy())))?;
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
            _ => (arg.clone(), None),
        };
        if name == "-h" || name == "--help" {
            return Ok(None);
        }
        let slot = match name.as_str() {
            "--measurement" => &mut measurement,
            "--idkey" => &mut idkey,
            "--authorkey" => &mut authorkey,
            _ => return Err(Fail::Usage(format!("unrecognized arguments: {arg}"))),
        };
        let value = match inline {
            Some(v) => v,
            None => it
                .next()
                .and_then(|v| v.into_string().ok())
                .filter(|v| !(v.starts_with('-') && v.len() > 1 && !v.contains(' ')))
                .ok_or_else(|| Fail::Usage(format!("argument {name}: expected one argument")))?,
        };
        *slot = Some(value);
    }

    let (Some(idkey), Some(authorkey)) = (idkey, authorkey) else {
        return Err(Fail::Usage("missing key files for id block".into()));
    };
    // Python fails with a TypeError without --measurement, and takes the
    // first 48 bytes of a longer one.
    let measurement = measurement.ok_or_else(|| Fail::Usage("missing --measurement".into()))?;
    let ld: [u8; 48] = base64_decode(&measurement)
        .map_err(|e| Fail::Runtime(format!("--measurement: {e}")))?
        .try_into()
        .map_err(|v: Vec<u8>| Fail::Runtime(format!("--measurement is {} bytes; it must be 48", v.len())))?;
    let load = |p: String| load_private_key_from_pem_file(&PathBuf::from(p)).map_err(|e| Fail::Runtime(e.0));
    let id_key = load(idkey)?;
    let author_key = load(authorkey)?;
    Ok(Some(snp_calc_id_block(&ld, &id_key, &author_key)))
}

fn main() -> ExitCode {
    match run() {
        Ok(Some(out)) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("{USAGE}{HELP}");
            ExitCode::SUCCESS
        }
        Err(Fail::Usage(msg)) => {
            eprintln!("{USAGE}\n{PROG}: error: {msg}");
            ExitCode::from(2)
        }
        Err(Fail::Runtime(msg)) => {
            eprintln!("Error: {msg}");
            ExitCode::from(1)
        }
    }
}
