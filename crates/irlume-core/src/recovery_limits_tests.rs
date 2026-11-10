// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::cell::Cell;

fn envelope() -> RecoveryEnvelope {
    RecoveryEnvelope {
        version: 1,
        kdf: "argon2id".into(),
        salt: STANDARD.encode([0; 16]),
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
        wrapped: STANDARD.encode([0; 60]),
        uid: None,
    }
}

fn refuses_before_derivation(env: &RecoveryEnvelope) {
    let called = Cell::new(false);
    let result = unwrap_with(b"synthetic passphrase", env, |_, _, _, _, _| {
        called.set(true);
        Err(Error::Policy("test derivation must not be reached".into()))
    });
    assert!(result.is_err());
    assert!(!called.get(), "invalid envelope reached key derivation");
}

#[test]
fn unsupported_costs_are_rejected_before_derivation() {
    for (m, t, p) in [
        (19_457, 2, 1),
        (19_456, 3, 1),
        (19_456, 2, 2),
        (u32::MAX, 2, 1),
        (19_456, u32::MAX, 1),
        (19_456, 2, u32::MAX),
        (0, 2, 1),
        (19_456, 0, 1),
        (19_456, 2, 0),
    ] {
        let mut env = envelope();
        (env.m_cost, env.t_cost, env.p_cost) = (m, t, p);
        refuses_before_derivation(&env);
    }
}

#[test]
fn invalid_encoded_and_decoded_lengths_are_rejected_before_derivation() {
    for size in [0, 15, 17, 4096] {
        let mut env = envelope();
        env.salt = STANDARD.encode(vec![0; size]);
        refuses_before_derivation(&env);
    }
    // 284 and 285 bytes both encode to 380 characters: the decoded cap matters.
    for size in [0, 27, 285, 288, 4096] {
        let mut env = envelope();
        env.wrapped = STANDARD.encode(vec![0; size]);
        refuses_before_derivation(&env);
    }
    for invalid in ["%".repeat(24), "!".repeat(80)] {
        let mut env = envelope();
        env.wrapped = invalid;
        refuses_before_derivation(&env);
    }
}

#[test]
fn supported_boundaries_reach_derivation_and_decrypt() {
    let derived = Zeroizing::new(vec![31; crypto::KEY_LEN]);
    for size in [0, 32, 64, 256] {
        let payload = Zeroizing::new(vec![42; size]);
        let mut env = envelope();
        env.wrapped = STANDARD.encode(crypto::encrypt(&derived, &payload).unwrap());
        let called = Cell::new(false);
        let restored = unwrap_with(b"1234", &env, |password, salt, m, t, p| {
            called.set(true);
            assert_eq!(password, b"1234");
            assert_eq!(salt.len(), 16);
            assert_eq!((m, t, p), (19_456, 2, 1));
            Ok(Zeroizing::new(derived.to_vec()))
        })
        .unwrap();
        assert!(called.get());
        assert_eq!(*restored, *payload);
    }
}

#[test]
fn emitted_schema_and_legacy_short_passphrases_still_round_trip() {
    let payload = Zeroizing::new(vec![3; 64]);
    let env = wrap(b"1234", &payload).unwrap();
    assert_eq!(env.version, 1);
    assert_eq!(env.kdf, "argon2id");
    assert_eq!((env.m_cost, env.t_cost, env.p_cost), (19_456, 2, 1));
    assert_eq!(env.uid, None);
    assert_eq!(STANDARD.decode(&env.salt).unwrap().len(), 16);
    assert_eq!(*unwrap(b"1234", &env).unwrap(), *payload);
}

#[test]
fn wrap_refuses_257_bytes_without_changing_the_256_byte_boundary() {
    assert!(wrap(b"synthetic", &[7; 257]).is_err());
    let env = wrap(b"synthetic", &[7; 256]).unwrap();
    assert_eq!(&*unwrap(b"synthetic", &env).unwrap(), &[7; 256]);
}
