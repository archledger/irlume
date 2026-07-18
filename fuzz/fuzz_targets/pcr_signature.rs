#![no_main]
//! The PCR-policy signature parser.
//!
//! systemd writes `.pcrsig` files; irlume parses them at unseal time with
//! `pcrsig::parse_signatures(text, bank)`. A tampered or malformed file must
//! fail cleanly. The bank string is config-derived, so the first input byte
//! selects it and the rest is the file text.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (bank, text) = match data.split_first() {
        Some((b, rest)) => (
            match b % 3 {
                0 => "sha256",
                1 => "sha384",
                _ => "sha1",
            },
            rest,
        ),
        None => ("sha256", data),
    };
    if let Ok(s) = std::str::from_utf8(text) {
        let _ = irlume_core::pcrsig::parse_signatures(s, bank);
    }
});
