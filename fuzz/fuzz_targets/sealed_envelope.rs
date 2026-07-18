#![no_main]
//! The sealed-envelope parser.
//!
//! The envelope holds the TPM-wrapped release secret and lives on disk as
//! root-only JSON. `SealedEnvelope::load` runs
//! `serde_json::from_str::<SealedEnvelope>()`; this target calls that
//! deserialization on fuzzer bytes. Defense in depth: a tampered file must not
//! crash the root daemon, whatever the on-disk permissions.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<irlume_core::envelope::SealedEnvelope>(s);
    }
});
