#![no_main]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! The EK certificate readers and chain verifier behind the
//! `tpm-endorsement` doctor check (ADR-0036).
//!
//! irlumed, as root, reads the EK certificate NV indices and the chain
//! indices from 0x01C00100. Where the owner hierarchy has no authorization,
//! any process that may open the TPM can define an index in the chain range,
//! so those bytes are untrusted: every input must answer without a panic.
//! The first two bytes split the rest into the certificate index and the
//! joined chain indices.
use irlume_core::ek_cert::{certificate_in_nv, chain_certificates, Anchors, EkCertificate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (split, rest) = match data {
        [hi, lo, rest @ ..] => (usize::from(u16::from_be_bytes([*hi, *lo])), rest),
        _ => (0, data),
    };
    let (index, chain) = rest.split_at(split.min(rest.len()));
    let chain = chain_certificates(chain);
    if let Ok(der) = certificate_in_nv(index) {
        if let Ok(ek) = EkCertificate::from_der(der) {
            let _ = ek.public_key();
            // "STM " as TPM_PT_MANUFACTURER.
            let _ = ek.verify(&chain, Anchors::shipped(), 0x5354_4D20);
        }
    }
});
