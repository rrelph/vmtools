//! OpenSSH public keys: the one-line `.pub`/known_hosts form and the wire
//! blob that REPORT_DATA binds (design section 7, step 3).

use crate::codec::unbase64;

/// The wire blob of an `ssh-ed25519` key line, checked for shape:
/// string "ssh-ed25519", then a 32-byte string. Other key types are refused;
/// stage 0 makes only Ed25519 host keys.
pub fn ed25519_blob_from_line(line: &str) -> Option<Vec<u8>> {
    let mut f = line.split_whitespace();
    if f.next()? != "ssh-ed25519" {
        return None;
    }
    let blob = unbase64(f.next()?)?;
    ed25519_blob_ok(&blob).then_some(blob)
}

pub fn ed25519_blob_ok(blob: &[u8]) -> bool {
    const NAME: &[u8] = b"ssh-ed25519";
    blob.len() == 4 + NAME.len() + 4 + 32
        && blob[..4] == (NAME.len() as u32).to_be_bytes()
        && &blob[4..4 + NAME.len()] == NAME
        && blob[4 + NAME.len()..8 + NAME.len()] == 32u32.to_be_bytes()
}

/// `SHA256:…` as `ssh-keygen -l` prints it (unpadded base64).
pub fn fingerprint(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    fingerprint_of_digest(&Sha256::digest(blob).into())
}

/// A SHA-256 digest written as an OpenSSH fingerprint. host_data for an org
/// CA is exactly this digest, so it reads as the CA's `ssh-keygen -l`.
pub fn fingerprint_of_digest(d: &[u8; 32]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::from("SHA256:");
    for c in d.chunks(3) {
        let n = c.iter().fold(0u32, |n, &b| n << 8 | u32::from(b)) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/fixtures/snp/");

    #[test]
    fn fixture_line_gives_fixture_blob() {
        let line = std::fs::read_to_string(format!("{FIX}binding-hostkey.pub")).unwrap();
        let blob = std::fs::read(format!("{FIX}binding-hostkey.blob")).unwrap();
        assert_eq!(ed25519_blob_from_line(&line).unwrap(), blob);
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        // `ssh-keygen -l -f test/fixtures/snp/test-org-ca.pub` prints
        // 256 SHA256:7JjyLNLHRd6H8UJi2vBQM92ERwcbO1aNQdSuH23X1ZQ no comment (ED25519)
        let line = std::fs::read_to_string(format!("{FIX}test-org-ca.pub")).unwrap();
        let blob = ed25519_blob_from_line(&line).unwrap();
        assert_eq!(fingerprint(&blob), "SHA256:7JjyLNLHRd6H8UJi2vBQM92ERwcbO1aNQdSuH23X1ZQ");
    }

    #[test]
    fn other_types_and_bad_shapes_are_refused() {
        assert!(ed25519_blob_from_line("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7").is_none());
        // Right type name, but the blob inside names another type.
        assert!(ed25519_blob_from_line("ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7").is_none());
        assert!(!ed25519_blob_ok(&[0; 51]));
    }
}
