//! vmt-unzstd: decompress a zstd file.
//!
//! Ubuntu compresses the contents of its .deb packages with zstd, which
//! macOS's tar cannot read. The measurement guide unpacks the kernel and
//! firmware packages with Apple's `ar` and `tar`; this does the one step
//! between them, turning `data.tar.zst` into `data.tar`.
//!
//!   vmt-unzstd IN.zst OUT
//!
//! Every frame must carry a content checksum, and each is checked: a frame
//! without one, a wrong checksum, a truncated frame or trailing bytes after
//! the last frame are all refused. OUT is written to `OUT.partial` and
//! renamed only once everything has been checked, so a failure never
//! leaves a file at OUT. OUT, if it exists, must be a regular file: renaming
//! over a device such as `/dev/null` would replace the device.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ruzstd::decoding::StreamingDecoder;

const USAGE: &str = "usage: vmt-unzstd IN.zst OUT";

/// Decompresses every frame of `input` into `output`, checking each
/// frame's checksum. Returns the number of frames.
pub fn decompress(input: impl io::Read, output: &mut impl Write) -> Result<usize, String> {
    let mut source = BufReader::new(input);
    let mut frames = 0;
    loop {
        let more = source.fill_buf().map_err(|e| format!("reading input: {e}"))?;
        if more.is_empty() {
            break;
        }
        let mut decoder =
            StreamingDecoder::new(&mut source).map_err(|e| format!("frame {}: {e}", frames + 1))?;
        io::copy(&mut decoder, output).map_err(|e| format!("frame {}: {e}", frames + 1))?;
        let (_, frame) = decoder.into_parts();
        if !frame.is_finished() {
            return Err(format!("frame {}: input ends inside the frame", frames + 1));
        }
        match (frame.get_checksum_from_data(), frame.get_calculated_checksum()) {
            (Some(stored), Some(computed)) if stored == computed => {}
            (Some(stored), Some(computed)) => {
                return Err(format!(
                    "frame {}: checksum mismatch: stored {stored:08x}, computed {computed:08x}",
                    frames + 1
                ));
            }
            _ => return Err(format!("frame {}: no content checksum to check", frames + 1)),
        }
        frames += 1;
    }
    if frames == 0 {
        return Err("input is empty".into());
    }
    Ok(frames)
}

/// Refuses a path that exists and is anything but a regular file: a
/// directory, a device such as `/dev/null`, or a symbolic link. Renaming
/// over one would replace it.
fn regular_or_absent(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => Ok(true),
        Ok(_) => Err(format!("{}: exists and is not a regular file", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn run(input: &Path, output: &Path) -> Result<(), String> {
    let file = File::open(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let mut partial = output.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    regular_or_absent(output)?;
    // A leftover from an interrupted run is replaced; anything else is not.
    if regular_or_absent(&partial)? {
        std::fs::remove_file(&partial).map_err(|e| format!("{}: {e}", partial.display()))?;
    }
    let out = File::options()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| format!("{}: {e}", partial.display()))?;
    let result = (|| {
        let mut out = BufWriter::new(out);
        decompress(file, &mut out)?;
        let out = out.into_inner().map_err(|e| format!("{}: {}", partial.display(), e.error()))?;
        out.sync_all().map_err(|e| format!("{}: {e}", partial.display()))?;
        std::fs::rename(&partial, output).map_err(|e| format!("{}: {e}", output.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [a] if a == "--version" => {
            println!("vmt-unzstd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [a] if a == "-h" || a == "--help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        [input, output] => match run(Path::new(input), Path::new(output)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vmt-unzstd: error: {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// The control archive of Ubuntu's ovmf-amdsev 2025.11-3ubuntu7.2,
    /// exactly as `ar x` takes it out of the package: one zstd frame with a
    /// checksum, as dpkg-deb writes them.
    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/ovmf-amdsev_2025.11-3ubuntu7.2.control.tar.zst");
    /// Its decompressed length and SHA-256, from libzstd (the C reference
    /// implementation, through Python's `zstandard`), not from this crate.
    const PLAIN_LEN: usize = 10240;
    const PLAIN_SHA256: &str = "2055ccecceecba2801c0b5d80e548171c99dc1d79dc1c3d3181141933c0981b2";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unzstd(input: &[u8]) -> Result<(Vec<u8>, usize), String> {
        let mut out = Vec::new();
        decompress(input, &mut out).map(|n| (out, n))
    }

    #[test]
    fn matches_the_reference_decoder() {
        let (out, frames) = unzstd(FIXTURE).unwrap();
        assert_eq!(frames, 1);
        assert_eq!(out.len(), PLAIN_LEN);
        assert_eq!(hex(&Sha256::digest(&out)), PLAIN_SHA256);
    }

    #[test]
    fn concatenated_frames_are_all_decoded() {
        let (out, frames) = unzstd(&[FIXTURE, FIXTURE].concat()).unwrap();
        assert_eq!(frames, 2);
        assert_eq!(out.len(), 2 * PLAIN_LEN);
        assert_eq!(out[..PLAIN_LEN], out[PLAIN_LEN..]);
    }

    #[test]
    fn a_wrong_checksum_is_refused() {
        // The last four bytes of a frame are its checksum.
        let mut bad = FIXTURE.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        let err = unzstd(&bad).unwrap_err();
        assert!(err.contains("checksum mismatch"), "{err}");
    }

    #[test]
    fn a_frame_without_a_checksum_is_refused() {
        // The frame header descriptor's bit 2 is the checksum flag; clearing
        // it makes the last four bytes trailing garbage, not a checksum.
        let mut bad = FIXTURE.to_vec();
        bad[4] &= !0x04;
        assert!(unzstd(&bad).is_err());
    }

    #[test]
    fn truncation_is_refused_at_every_length() {
        for len in 1..FIXTURE.len() {
            assert!(unzstd(&FIXTURE[..len]).is_err(), "accepted the first {len} bytes");
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        assert!(unzstd(&[FIXTURE, b"junk"].concat()).is_err());
    }

    #[test]
    fn empty_input_is_refused() {
        assert_eq!(unzstd(b"").unwrap_err(), "input is empty");
    }

    #[test]
    fn a_failure_leaves_no_output() {
        let dir = std::env::temp_dir().join(format!("vmt-unzstd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (input, output) = (dir.join("in.zst"), dir.join("out"));
        std::fs::write(&input, &FIXTURE[..FIXTURE.len() - 1]).unwrap();
        assert!(run(&input, &output).is_err());
        assert!(!output.exists());
        assert!(!dir.join("out.partial").exists());
        std::fs::write(&input, FIXTURE).unwrap();
        run(&input, &output).unwrap();
        assert_eq!(hex(&Sha256::digest(std::fs::read(&output).unwrap())), PLAIN_SHA256);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An earlier draft renamed its output over `/dev/null` when asked to
    /// write there, replacing the device with a regular file.
    #[cfg(unix)]
    #[test]
    fn only_regular_files_are_replaced() {
        use std::os::unix::fs::FileTypeExt;

        let dir = std::env::temp_dir().join(format!("vmt-unzstd-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("in.zst");
        std::fs::write(&input, FIXTURE).unwrap();

        // A socket stands in for a device: not a regular file, and safe to
        // lose if this guard ever regresses (a real /dev/null is not).
        let socket = dir.join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let err = run(&input, &socket).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        assert!(std::fs::symlink_metadata(&socket).unwrap().file_type().is_socket());
        assert!(!dir.join("socket.partial").exists());

        let subdir = dir.join("sub");
        std::fs::create_dir(&subdir).unwrap();
        assert!(run(&input, &subdir).is_err());
        assert!(subdir.is_dir());

        let target = dir.join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(run(&input, &link).is_err());
        assert!(run(&input, &dir.join("out")).is_ok());
        // A symbolic link where OUT.partial goes is refused, not followed.
        std::os::unix::fs::symlink(&target, dir.join("x.partial")).unwrap();
        assert!(run(&input, &dir.join("x")).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");

        // A regular OUT, and a leftover regular OUT.partial, are replaced.
        std::fs::write(dir.join("out.partial"), b"stale").unwrap();
        run(&input, &dir.join("out")).unwrap();
        assert!(!dir.join("out.partial").exists());
        assert_eq!(std::fs::read(dir.join("out")).unwrap().len(), PLAIN_LEN);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
