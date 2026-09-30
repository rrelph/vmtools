//! The strict decoders on text from the wire: never panic, and whatever
//! they accept must round-trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use snp::codec::{hex, unbase64, unhex};
use snp::sshkey::ed25519_blob_from_line;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(b) = unhex(s) {
        assert_eq!(hex(&b), s.to_ascii_lowercase());
    }
    let _ = unbase64(s);
    if let Some(blob) = ed25519_blob_from_line(s) {
        assert_eq!(blob.len(), 51);
    }
});
