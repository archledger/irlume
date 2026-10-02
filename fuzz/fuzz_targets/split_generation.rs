#![no_main]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! The split-authorization generation parser.
//!
//! Generation files are root-written but their text is parsed by every
//! reader of a publication; a panic would take down the parse. This target
//! replays `parse_generation` on fuzzer input: it must report Malformed on
//! garbage, never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = irlume_common::split_schema::parse_generation(s);
    }
});
