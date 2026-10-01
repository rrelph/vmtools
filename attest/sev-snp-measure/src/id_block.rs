//! SEV-SNP ID block and ID authentication structure (Python: `id_block.py`).
//!
//! Signatures are ECDSA P-384 over SHA-384, as in Python. Python's
//! `cryptography` picks a random nonce; RustCrypto derives it
//! deterministically (RFC 6979). Both are valid signatures, so `id-auth`
//! differs from Python's output on every run of either, while `id-block`
//! and the two key digests are byte-identical.

use std::path::Path;

use p384::SecretKey;
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::pkcs8::DecodePrivateKey;

use crate::gctx::{LD_SIZE, sha384};
use crate::util::base64_encode;
use crate::{Error, Result};

pub const DEFAULT_IDS: [u8; 0x20] = [0; 0x20];
pub const DEFAULT_VERSION: u32 = 1;
pub const DEFAULT_GUEST_SVN: [u8; 4] = [0; 4];
pub const DEFAULT_POLICY: u64 = 196608; // [0,0,3,0,0,0,0,0]
pub const DEFAULT_KEY_ALGO: u32 = 1;
pub const CURVE_P384: u32 = 2;
pub const EC_KEY_LENGTH: usize = 1028;
pub const EC_SIG_LENGTH: usize = 512;
pub const SNP_SIG_LENGTH: usize = 72;

pub const ID_BLOCK_SIZE: usize = 96;
pub const ID_AUTH_SIZE: usize = 4096;

/// The ID block (struct sev_snp_id_block): launch digest, family and image
/// IDs, version, guest SVN, policy. 96 bytes, little-endian.
pub fn id_block_bytes(ld: &[u8; LD_SIZE]) -> [u8; ID_BLOCK_SIZE] {
    let mut b = [0u8; ID_BLOCK_SIZE];
    b[0..48].copy_from_slice(ld);
    b[48..80].copy_from_slice(&DEFAULT_IDS);
    b[80..84].copy_from_slice(&DEFAULT_VERSION.to_le_bytes());
    b[84..88].copy_from_slice(&DEFAULT_GUEST_SVN);
    b[88..96].copy_from_slice(&DEFAULT_POLICY.to_le_bytes());
    b
}

/// A big-endian scalar as SNP's 72-byte little-endian field.
fn le72(be: &[u8]) -> [u8; SNP_SIG_LENGTH] {
    let mut out = [0u8; SNP_SIG_LENGTH];
    for (o, b) in out.iter_mut().zip(be.iter().rev()) {
        *o = *b;
    }
    out
}

/// The public key in SNP's format: curve, Qx, Qy (little-endian, 72 bytes
/// each), reserved. 1028 bytes.
pub fn marshal_ec_public_key(key: &SecretKey) -> [u8; EC_KEY_LENGTH] {
    let point = key.public_key().to_encoded_point(false);
    let mut out = [0u8; EC_KEY_LENGTH];
    out[0..4].copy_from_slice(&CURVE_P384.to_le_bytes());
    out[4..76].copy_from_slice(&le72(point.x().expect("uncompressed point")));
    out[76..148].copy_from_slice(&le72(point.y().expect("uncompressed point")));
    out
}

/// An ECDSA P-384/SHA-384 signature in SNP's format: R, S (little-endian,
/// 72 bytes each), reserved. 512 bytes.
pub fn sign_in_snp_format(key: &SecretKey, data: &[u8]) -> [u8; EC_SIG_LENGTH] {
    let sig: Signature = SigningKey::from(key).sign(data);
    let (r, s) = sig.split_bytes();
    let mut out = [0u8; EC_SIG_LENGTH];
    out[0..72].copy_from_slice(&le72(&r));
    out[72..144].copy_from_slice(&le72(&s));
    out
}

/// The first PEM block with this label, from its BEGIN line to its END
/// line. `openssl ecparam -genkey` without `-noout` writes an `EC
/// PARAMETERS` block before the key, which the key decoders would refuse.
fn pem_block<'a>(pem: &'a str, label: &str) -> Option<&'a str> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin)?;
    let stop = pem[start..].find(&end)? + start + end.len();
    Some(&pem[start..stop])
}

/// An unencrypted P-384 private key, PEM-encoded as SEC 1 (`EC PRIVATE
/// KEY`, what `openssl ecparam -genkey` writes) or PKCS #8 (`PRIVATE KEY`).
pub fn load_private_key_from_pem(pem: &str) -> Result<SecretKey> {
    let not_p384 = || Error::new("The provided PEM file does not contain a P-384 EC private key.");
    if let Some(block) = pem_block(pem, "EC PRIVATE KEY") {
        SecretKey::from_sec1_pem(block).map_err(|_| not_p384())
    } else if let Some(block) = pem_block(pem, "PRIVATE KEY") {
        // Fails for any key that is not EC on P-384. (Python accepts other
        // curves here and refuses them later: "SNP only supports the EC
        // curve P-384".)
        SecretKey::from_pkcs8_pem(block).map_err(|_| not_p384())
    } else {
        Err(Error::new("The provided PEM file does not contain an unencrypted EC private key."))
    }
}

pub fn load_private_key_from_pem_file(path: &Path) -> Result<SecretKey> {
    let pem = std::fs::read_to_string(path).map_err(|e| Error::new(format!("{}: {e}", path.display())))?;
    load_private_key_from_pem(&pem)
}

/// SHA-384 of the marshalled public key: what an attestation report
/// carries as ID_KEY_DIGEST or AUTHOR_KEY_DIGEST.
pub fn pub_to_digest(key: &SecretKey) -> [u8; 48] {
    sha384(&marshal_ec_public_key(key))
}

/// The ID authentication information structure. 4096 bytes.
pub fn id_auth_bytes(
    id_block: &[u8; ID_BLOCK_SIZE],
    id_key: &SecretKey,
    author_key: &SecretKey,
) -> [u8; ID_AUTH_SIZE] {
    let id_pub = marshal_ec_public_key(id_key);
    let mut a = [0u8; ID_AUTH_SIZE];
    a[0..4].copy_from_slice(&DEFAULT_KEY_ALGO.to_le_bytes()); // id_key_algo
    a[4..8].copy_from_slice(&DEFAULT_KEY_ALGO.to_le_bytes()); // auth_key_algo
    // reserved1: 56 bytes
    a[64..576].copy_from_slice(&sign_in_snp_format(id_key, id_block)); // block_sig
    a[576..1604].copy_from_slice(&id_pub); // id_key
    // reserved2: 60 bytes
    a[1664..2176].copy_from_slice(&sign_in_snp_format(author_key, &id_pub)); // id_key_sig
    a[2176..3204].copy_from_slice(&marshal_ec_public_key(author_key)); // author_key
    // reserved3: 892 bytes
    a
}

/// The text `snp-create-id-block` prints (without its final newline):
/// QEMU's `id-block=…,id-auth=…` and the two key digests, all base64.
pub fn snp_calc_id_block(ld: &[u8; LD_SIZE], id_key: &SecretKey, author_key: &SecretKey) -> String {
    let id_block = id_block_bytes(ld);
    let id_auth = id_auth_bytes(&id_block, id_key, author_key);
    // key digests for attestation report validating
    let id_key_digest = pub_to_digest(id_key);
    let author_key_digest = pub_to_digest(author_key);
    format!(
        "id-block={},id-auth={}\nid_key_hash: {}\nauthor_key: {}",
        base64_encode(&id_block),
        base64_encode(&id_auth),
        base64_encode(&id_key_digest),
        base64_encode(&author_key_digest),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::base64_decode;
    use p384::ecdsa::VerifyingKey;
    use p384::ecdsa::signature::Verifier;

    fn key(name: &str) -> SecretKey {
        let path = format!("{}/tests/keyfile/{name}", env!("CARGO_MANIFEST_DIR"));
        load_private_key_from_pem_file(Path::new(&path)).unwrap()
    }

    fn from_le72(b: &[u8]) -> [u8; 48] {
        assert!(b[48..72].iter().all(|&x| x == 0));
        let mut out = [0u8; 48];
        for (o, x) in out.iter_mut().zip(b[..48].iter().rev()) {
            *o = *x;
        }
        out
    }

    // Python: tests/test_id_block.py
    #[test]
    fn id_block_matches_python() {
        let ld: [u8; 48] = base64_decode("B28FLQi9p6cAqipgjFyqawDrrSl7bWioWkWx5mmlWLZ+G5HShKMB/mPE+gdQRn7t")
            .unwrap()
            .try_into()
            .unwrap();
        let block = snp_calc_id_block(&ld, &key("id_key_test.pem"), &key("author_key_test.pem"));
        assert!(block.contains(
            "id-block=B28FLQi9p6cAqipgjFyqawDrrSl7bWioWkWx5mmlWLZ+G5HShKMB/mPE+gdQRn7t\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAwAAAAAA"
        ));
        assert!(
            block.contains("id_key_hash: hwt+NcU/inLQ0yL3WrKvgmJ5Kq9leWIs5BMcPyHyied8sFYKXjuQs5MuZ07HCcsU")
        );
        assert!(
            block.contains("author_key: YxEcNLv8Ckk4+aAJvQdJgNgXIyPmFZnJ/TNtqGcySOHcqY0L6PdjdqEGuK/UwKBX")
        );
    }

    /// Python's test cannot check the signatures (they are randomized); this
    /// one does, reading them back out of the structure.
    #[test]
    fn id_auth_signatures_verify() {
        let (id, author) = (key("id_key_test.pem"), key("author_key_test.pem"));
        let block = id_block_bytes(&[7u8; 48]);
        let auth = id_auth_bytes(&block, &id, &author);

        let sig_at = |off: usize| {
            Signature::from_scalars(from_le72(&auth[off..off + 72]), from_le72(&auth[off + 72..off + 144]))
                .unwrap()
        };
        VerifyingKey::from(id.public_key()).verify(&block, &sig_at(64)).unwrap();
        VerifyingKey::from(author.public_key()).verify(&auth[576..1604], &sig_at(1664)).unwrap();
        assert_eq!(auth[576..1604], marshal_ec_public_key(&id));
        assert_eq!(auth[2176..3204], marshal_ec_public_key(&author));
        // A signature over anything else does not verify.
        assert!(VerifyingKey::from(id.public_key()).verify(&[0u8; 96], &sig_at(64)).is_err());
    }

    #[test]
    fn wrong_key_types_are_refused() {
        assert!(load_private_key_from_pem("not a key").is_err());
        assert!(
            load_private_key_from_pem("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")
                .is_err()
        );
    }
}
