#![no_main]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! The firmware event log parser behind `irlume doctor`'s `pcr7-binding`.
//!
//! doctor runs it as root over /sys/kernel/security/tpm0/binary_bios_measurements.
//! Firmware writes that log, but some event data comes from devices (device
//! paths, option ROM descriptions), so the parser must answer on every byte
//! string, the same way each time, with every event inside the input, and
//! read PCR 7 from a log only when it replays and each event matches its
//! digest.
use irlume_common::event_log::{authority_certificate, events, pcr7, replay, verified_pcr7};
use irlume_common::secureboot::microsoft_certificate;
use libfuzzer_sys::fuzz_target;

/// A valid Spec ID Event03 header declaring SHA-1 and SHA-256, so the bytes
/// after it reach the event parser instead of failing the header check.
fn header() -> Vec<u8> {
    let mut spec = b"Spec ID Event03\0".to_vec();
    spec.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 2]);
    spec.extend_from_slice(&2u32.to_le_bytes());
    spec.extend_from_slice(&[0x04, 0x00, 20, 0x00, 0x0b, 0x00, 32, 0x00, 0]);
    let mut out = 0u32.to_le_bytes().to_vec();
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&[0; 20]);
    out.extend_from_slice(&(spec.len() as u32).to_le_bytes());
    out.extend_from_slice(&spec);
    out
}

fn check(log: &[u8]) {
    let parsed = events(log);
    assert_eq!(parsed, events(log), "parsing is deterministic");
    let Some((list, complete)) = parsed else {
        return;
    };
    let range = log.as_ptr_range();
    for event in &list {
        assert!(
            range.contains(&event.data.as_ptr()) || event.data.is_empty(),
            "event data lies inside the log"
        );
        assert!(event.data.len() <= log.len());
        if let Some(digest) = event.sha256 {
            assert!(range.contains(&digest.as_ptr()) && digest.len() == 32);
        }
    }
    let measured = pcr7(&list);
    assert_eq!(measured, pcr7(&list));
    // Checked against the value its own digests replay to, a complete log is
    // read exactly when every PCR 7 event it reads matches its digest and
    // parses.
    if let (true, Some(value)) = (complete, replay(&list, 7)) {
        let clean = measured.unverified == 0 && measured.malformed == 0;
        match verified_pcr7(log, &value) {
            Ok(verified) => assert!(verified == measured && clean),
            Err(_) => assert!(!clean),
        }
    }
    for authority in &measured.authorities {
        if let Some(certificate) = authority_certificate(authority) {
            assert_eq!(
                microsoft_certificate(certificate),
                microsoft_certificate(certificate)
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    let mut framed = header();
    let start = framed.len();
    framed.extend_from_slice(data);
    assert!(
        events(&framed).is_some(),
        "a valid header is always recognized"
    );
    check(&framed);
    assert_eq!(framed.len() - start, data.len());
});
