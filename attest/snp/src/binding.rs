//! The binding between a report and an SSH session (design section 7): one
//! definition, used by stage 0 to make REPORT_DATA and by the unlock tool to
//! check it.

use sha2::{Digest, Sha256, Sha512};

/// The nonce is exactly this long: 32 random bytes from the unlock tool.
pub const NONCE_LEN: usize = 32;

/// `SHA-512(nonce || ssh_host_pubkey_blob)`, where the blob is the OpenSSH
/// wire form of stage 0's host key.
pub fn report_data_for(nonce: &[u8], host_key_blob: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(nonce);
    h.update(host_key_blob);
    h.finalize().into()
}

/// The report's host_data for an organization's CA (design section 9, open
/// question 6): SHA-256 of the CA's OpenSSH wire-format public key blob, the
/// base64 field of its `.pub` line, decoded. The blob, not the line, so a
/// comment or whitespace cannot change it. The host sets it at launch; stage 0
/// checks the CA it was given against it, and so does the guest owner.
pub fn host_data_for_ca(ca_blob: &[u8]) -> [u8; 32] {
    Sha256::digest(ca_blob).into()
}

#[cfg(test)]
mod tests {
    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/fixtures/snp/");

    #[test]
    fn matches_the_fixture_made_with_sha512sum() {
        let r = |n: &str| std::fs::read(format!("{FIX}{n}")).unwrap();
        let rd = super::report_data_for(&r("binding-nonce.bin"), &r("binding-hostkey.blob"));
        assert_eq!(rd.to_vec(), r("rd-binding.bin"));
    }

    #[test]
    fn ca_host_data_is_the_value_the_host_set_on_milan() {
        // The Phase 3 fixture was captured from a guest launched with the
        // host_data install.sh computes for this CA.
        let line = std::fs::read_to_string(format!("{FIX}test-org-ca.pub")).unwrap();
        let blob = crate::sshkey::ed25519_blob_from_line(&line).unwrap();
        let report = std::fs::read(format!("{FIX}report-hostdata-vmpl0.bin")).unwrap();
        assert_eq!(super::host_data_for_ca(&blob).to_vec(), report[0xC0..0xE0].to_vec());
    }
}
