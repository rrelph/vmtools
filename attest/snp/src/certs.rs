//! The AMD certificate chain: ARK → ASK → VCEK (design section 8, check 1).
//!
//! ARK and ASK for Milan are pinned: the DER files in `pins/`, compiled in,
//! and their SHA-256 checked against the constants below before use. They
//! were fetched from AMD KDS twice, once inside the Phase 0 test guest and
//! once on the guest owner's workstation, and were byte-identical.
//! (design/phase1-findings.md, "Pinned certificates".)

use rsa::pkcs1::{DecodeRsaPublicKey, RsaPssParams};
use rsa::signature::Verifier;
use rsa::{RsaPublicKey, pss};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::Certificate;
use x509_cert::der::asn1::OctetString;
use x509_cert::der::oid::ObjectIdentifier as Oid;
use x509_cert::der::{Decode, Encode};

use crate::codec::hex;
use crate::report::Tcb;

pub const ARK_MILAN_DER: &[u8] = include_bytes!("../pins/ark-milan.der");
pub const ASK_MILAN_DER: &[u8] = include_bytes!("../pins/ask-milan.der");
pub const ARK_MILAN_SHA256: &str = "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd";
pub const ASK_MILAN_SHA256: &str = "67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b";

const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
const RSASSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
const SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
const EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
const SECP384R1: Oid = Oid::new_unwrap("1.3.132.0.34");
// AMD's VCEK extensions (AMD "Versioned Chip Endorsement Key" specification).
const AMD_PRODUCT_NAME: Oid = Oid::new_unwrap("1.3.6.1.4.1.3704.1.2");
const AMD_BL_SPL: Oid = Oid::new_unwrap("1.3.6.1.4.1.3704.1.3.1");
const AMD_TEE_SPL: Oid = Oid::new_unwrap("1.3.6.1.4.1.3704.1.3.2");
const AMD_SNP_SPL: Oid = Oid::new_unwrap("1.3.6.1.4.1.3704.1.3.3");
const AMD_UCODE_SPL: Oid = Oid::new_unwrap("1.3.6.1.4.1.3704.1.3.8");
const AMD_HWID: Oid = Oid::new_unwrap("1.3.6.1.4.1.3704.1.4");

pub type Error = String;

fn parse(der: &[u8], what: &str) -> Result<Certificate, Error> {
    Certificate::from_der(der).map_err(|e| format!("{what}: not a DER X.509 certificate: {e}"))
}

fn rsa_key(cert: &Certificate, what: &str) -> Result<RsaPublicKey, Error> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != RSA_ENCRYPTION && spki.algorithm.oid != RSASSA_PSS {
        return Err(format!("{what}: public key is not RSA ({})", spki.algorithm.oid));
    }
    RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes())
        .map_err(|e| format!("{what}: bad RSA public key: {e}"))
}

/// `child` is signed by `issuer_key` with RSASSA-PSS, SHA-384, salt 48, and
/// names `issuer` as its issuer.
fn check_pss(
    child: &Certificate,
    issuer: &Certificate,
    issuer_key: &RsaPublicKey,
    what: &str,
) -> Result<(), Error> {
    let alg = &child.signature_algorithm;
    if alg.oid != RSASSA_PSS {
        return Err(format!("{what}: signature algorithm is {}, expected RSASSA-PSS", alg.oid));
    }
    let params = alg.parameters.as_ref().ok_or_else(|| format!("{what}: PSS parameters missing"))?;
    let params = params.to_der().map_err(|e| format!("{what}: {e}"))?;
    let params =
        RsaPssParams::try_from(&params[..]).map_err(|e| format!("{what}: bad PSS parameters: {e}"))?;
    if params.hash.oid != SHA384 || params.salt_len != 48 {
        return Err(format!("{what}: PSS parameters are not SHA-384 with a 48-byte salt"));
    }
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(format!("{what}: issuer name does not match the issuing certificate's subject"));
    }
    let tbs = child.tbs_certificate.to_der().map_err(|e| format!("{what}: {e}"))?;
    let sig = child
        .signature
        .as_bytes()
        .ok_or_else(|| format!("{what}: signature is not a whole number of bytes"))?;
    let sig = pss::Signature::try_from(sig).map_err(|e| format!("{what}: {e}"))?;
    pss::VerifyingKey::<Sha384>::new(issuer_key.clone())
        .verify(&tbs, &sig)
        .map_err(|_| format!("{what}: signature does not verify"))
}

/// The pinned ARK and ASK, checked: digests match the pins, the ARK is
/// self-signed, the ASK is signed by the ARK.
pub struct AmdChain {
    ask: Certificate,
    ask_key: RsaPublicKey,
}

impl AmdChain {
    pub fn milan() -> Result<AmdChain, Error> {
        Self::from_der(ARK_MILAN_DER, ASK_MILAN_DER, ARK_MILAN_SHA256, ASK_MILAN_SHA256)
    }

    fn from_der(ark_der: &[u8], ask_der: &[u8], ark_pin: &str, ask_pin: &str) -> Result<AmdChain, Error> {
        if hex(&Sha256::digest(ark_der)) != ark_pin {
            return Err("pinned ARK does not match its SHA-256 pin".into());
        }
        if hex(&Sha256::digest(ask_der)) != ask_pin {
            return Err("pinned ASK does not match its SHA-256 pin".into());
        }
        let ark = parse(ark_der, "ARK")?;
        let ask = parse(ask_der, "ASK")?;
        let ark_key = rsa_key(&ark, "ARK")?;
        check_pss(&ark, &ark, &ark_key, "ARK (self-signed)")?;
        check_pss(&ask, &ark, &ark_key, "ASK (signed by ARK)")?;
        let ask_key = rsa_key(&ask, "ASK")?;
        Ok(AmdChain { ask, ask_key })
    }

    /// A VCEK, checked as signed by the pinned ASK, with its P-384 key and the
    /// TCB and chip id it was issued for.
    pub fn verify_vcek(&self, der: &[u8]) -> Result<Vcek, Error> {
        let cert = parse(der, "VCEK")?;
        check_pss(&cert, &self.ask, &self.ask_key, "VCEK (signed by ASK)")?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let curve = spki.algorithm.parameters.as_ref().and_then(|a| a.decode_as::<Oid>().ok());
        if spki.algorithm.oid != EC_PUBLIC_KEY || curve != Some(SECP384R1) {
            return Err("VCEK: public key is not EC P-384".into());
        }
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
            .map_err(|_| "VCEK: bad P-384 public key".to_string())?;

        let mut spl = [None::<u8>; 4];
        let mut hwid = None;
        let mut product = None;
        for ext in cert.tbs_certificate.extensions.iter().flatten() {
            let v = ext.extn_value.as_bytes();
            let int = || {
                u8::from_der(v).map_err(|_| format!("VCEK: extension {} is not a small INTEGER", ext.extn_id))
            };
            match ext.extn_id {
                id if id == AMD_BL_SPL => spl[0] = Some(int()?),
                id if id == AMD_TEE_SPL => spl[1] = Some(int()?),
                id if id == AMD_SNP_SPL => spl[2] = Some(int()?),
                id if id == AMD_UCODE_SPL => spl[3] = Some(int()?),
                // Milan and Genoa VCEKs carry the 64 raw bytes; accept a DER
                // OCTET STRING too, as later products use.
                id if id == AMD_HWID => {
                    let raw = if v.len() == 64 {
                        v.to_vec()
                    } else {
                        OctetString::from_der(v).map_err(|_| "VCEK: bad hwID".to_string())?.into_bytes()
                    };
                    hwid = Some(
                        <[u8; 64]>::try_from(raw).map_err(|_| "VCEK: hwID is not 64 bytes".to_string())?,
                    );
                }
                id if id == AMD_PRODUCT_NAME => {
                    // An IA5String; keep what is printable for messages.
                    product = Some(v.iter().filter(|c| c.is_ascii_graphic()).map(|&c| c as char).collect());
                }
                _ => {}
            }
        }
        let [Some(bootloader), Some(tee), Some(snp), Some(microcode)] = spl else {
            return Err("VCEK: missing one of its TCB extensions".into());
        };
        Ok(Vcek {
            key,
            tcb: Tcb { bootloader, tee, snp, microcode },
            hwid: hwid.ok_or("VCEK: missing hwID extension")?,
            product: product.unwrap_or_default(),
        })
    }
}

pub struct Vcek {
    pub key: p384::ecdsa::VerifyingKey,
    pub tcb: Tcb,
    pub hwid: [u8; 64],
    pub product: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::pem_certificate;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/fixtures/snp/");

    fn fixture_pem(name: &str) -> Vec<u8> {
        pem_certificate(&std::fs::read_to_string(format!("{FIX}certs/{name}")).unwrap()).unwrap()
    }

    #[test]
    fn pins_are_the_fixture_certificates() {
        assert_eq!(fixture_pem("ark.pem"), ARK_MILAN_DER);
        assert_eq!(fixture_pem("ask.pem"), ASK_MILAN_DER);
    }

    #[test]
    fn pinned_chain_verifies_and_fixture_vcek_chains_to_it() {
        let chain = AmdChain::milan().unwrap();
        let vcek = chain.verify_vcek(&fixture_pem("vcek.pem")).unwrap();
        assert_eq!(vcek.tcb, Tcb { bootloader: 4, tee: 0, snp: 28, microcode: 222 });
        assert!(vcek.product.contains("Milan"), "{}", vcek.product);
    }

    #[test]
    fn a_tampered_pin_is_refused() {
        let mut ark = ARK_MILAN_DER.to_vec();
        let n = ark.len();
        ark[n - 10] ^= 1;
        let e = AmdChain::from_der(&ark, ASK_MILAN_DER, ARK_MILAN_SHA256, ASK_MILAN_SHA256).err().unwrap();
        assert!(e.contains("pin"), "{e}");
        // Right digests for the tampered bytes: the signature is what fails.
        let e = AmdChain::from_der(&ark, ASK_MILAN_DER, &hex(&Sha256::digest(&ark)), ASK_MILAN_SHA256)
            .err()
            .unwrap();
        assert!(e.contains("ARK"), "{e}");
    }

    #[test]
    fn the_ask_is_not_a_vcek_and_a_flipped_vcek_bit_fails() {
        let chain = AmdChain::milan().unwrap();
        // The ASK is signed by the ARK, not by the ASK.
        assert!(chain.verify_vcek(ASK_MILAN_DER).is_err());
        let mut v = fixture_pem("vcek.pem");
        let i = v.len() / 2; // inside the TBS
        v[i] ^= 0x01;
        assert!(chain.verify_vcek(&v).is_err());
    }
}
