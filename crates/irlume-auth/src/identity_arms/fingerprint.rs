// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{decision_grid, Coverage};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FingerprintError {
    InvalidDigest,
}

/// A well-formed decision digest produced by this module's builder.
#[derive(Debug)]
pub(crate) struct DecisionFingerprint(String);

impl DecisionFingerprint {
    fn from_digest(value: String) -> Result<Self, FingerprintError> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(FingerprintError::InvalidDigest)
        }
    }
}

impl AsRef<str> for DecisionFingerprint {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<DecisionFingerprint> for String {
    fn from(value: DecisionFingerprint) -> Self {
        value.0
    }
}

/// Compute the current decision stream as a checked digest.
///
/// # Errors
/// Returns `InvalidDigest` if construction does not yield a complete
/// lowercase SHA-256 representation.
pub(crate) fn try_decision_fingerprint() -> Result<DecisionFingerprint, FingerprintError> {
    let mut hasher = Sha256::new();
    decision_grid(
        &mut |bytes: &[u8]| {
            hasher.update((bytes.len() as u32).to_le_bytes());
            hasher.update(bytes);
        },
        &mut Coverage::default(),
    );
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    DecisionFingerprint::from_digest(digest)
}

fn public_value(result: Result<DecisionFingerprint, FingerprintError>) -> String {
    result.map(String::from).unwrap_or_default()
}

/// The recognition decision's fingerprint (ADR-0022 §3): the SHA-256 of
/// everything the production decision code returns over a fixed synthetic
/// grid: RGB matching, the IR matcher with and without a fitted
/// calibration, the RGB-primary, fusion, IR-fallback and calibrated-centroid
/// arms, the dark path's arms, and the Platt scaling, brightness weighting
/// and template-count scaling inside them. A change to any of it changes
/// the fingerprint, and a certification entry bound to the old one no
/// longer applies.
///
/// Returns an empty string if construction cannot provide a valid digest.
/// Accelerator admission uses the checked result instead of this wrapper.
pub fn decision_fingerprint() -> String {
    public_value(try_decision_fingerprint())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_fingerprint_accepts_only_full_lowercase_sha256_text() {
        for text in ["0".repeat(64), "abcdef0123456789".repeat(4)] {
            let checked = DecisionFingerprint::from_digest(text.clone()).unwrap();
            assert_eq!(checked.as_ref(), text);
        }
        for text in [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            assert_eq!(
                DecisionFingerprint::from_digest(text).unwrap_err(),
                FingerprintError::InvalidDigest
            );
        }
    }

    #[test]
    fn public_wrapper_cannot_turn_failure_into_a_digest() {
        assert!(public_value(Err(FingerprintError::InvalidDigest)).is_empty());
        let checked = DecisionFingerprint::from_digest("1".repeat(64)).unwrap();
        assert_eq!(public_value(Ok(checked)), "1".repeat(64));
    }
}
