#![no_main]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! The canonical split-pair key text parser.
//!
//! `split_pair` in `cameras.conf` is root-owned text, but the same decoder
//! will read keys from daemon requests and authorization records later, and
//! a panic in it is a denial of service against a root daemon. This target
//! replays `SplitPairKey::parse_canonical` on fuzzer input: it must return
//! Err on garbage, never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = irlume_common::split_key::SplitPairKey::parse_canonical(s);
    }
});
