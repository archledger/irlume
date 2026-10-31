// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{decision_grid, thresholds, witnesses, Coverage};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FingerprintError {
    InvalidDigest,
    SizeOverflow,
    Threshold(thresholds::ThresholdError),
    Witness(witnesses::WitnessError),
}

#[cfg(test)]
pub(crate) fn test_errors() -> [FingerprintError; 10] {
    use thresholds::ThresholdError as T;
    use witnesses::WitnessError as W;
    [
        FingerprintError::InvalidDigest,
        FingerprintError::SizeOverflow,
        FingerprintError::Threshold(T::InvalidScale),
        FingerprintError::Threshold(T::CapUnreachable),
        FingerprintError::Threshold(T::CountBudgetExceeded),
        FingerprintError::Threshold(T::RecordBudgetExceeded),
        FingerprintError::Threshold(T::InvalidThreshold),
        FingerprintError::Witness(W::SizeOverflow),
        FingerprintError::Witness(W::BudgetExceeded),
        FingerprintError::Witness(W::MissingCoverage),
    ]
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
/// Returns a threshold, witness or size error when coverage is incomplete,
/// or `InvalidDigest` for a malformed final SHA-256 representation.
pub(crate) fn try_decision_fingerprint() -> Result<DecisionFingerprint, FingerprintError> {
    build_checked(
        thresholds::generate(thresholds::Domain::Enrollable),
        thresholds::generate(thresholds::Domain::Complete),
        witnesses::build(),
    )
}

fn build_checked(
    enrollment: Result<thresholds::ThresholdSet, thresholds::ThresholdError>,
    complete: Result<thresholds::ThresholdSet, thresholds::ThresholdError>,
    witnesses: Result<Vec<witnesses::Record>, witnesses::WitnessError>,
) -> Result<DecisionFingerprint, FingerprintError> {
    let enrollment = enrollment.map_err(FingerprintError::Threshold)?;
    let complete = complete.map_err(FingerprintError::Threshold)?;
    let witnesses = witnesses.map_err(FingerprintError::Witness)?;
    let mut hasher = Sha256::new();
    frame(&mut hasher, b"domain", b"irlume-decision-fingerprint/2")?;
    frame(&mut hasher, b"legacy-arm-grid-sha256", &legacy_digest())?;
    frame(
        &mut hasher,
        b"threshold-constants-sha256",
        &constants_digest()?,
    )?;
    frame(
        &mut hasher,
        b"enrollment-thresholds-sha256",
        &threshold_digest(&enrollment)?,
    )?;
    frame(
        &mut hasher,
        b"complete-thresholds-sha256",
        &threshold_digest(&complete)?,
    )?;
    let mut composed = Sha256::new();
    count(&mut composed, witnesses.len())?;
    for record in witnesses {
        composed.update([record.family]);
        count(&mut composed, record.index)?;
        frame(&mut composed, b"record", &record.bytes)?;
    }
    frame(&mut hasher, b"composed-witnesses-sha256", &finish(composed))?;
    let digest = finish(hasher)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    DecisionFingerprint::from_digest(digest)
}

fn finish(hasher: Sha256) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&hasher.finalize());
    bytes
}

fn count(hasher: &mut Sha256, value: usize) -> Result<(), FingerprintError> {
    hasher.update(
        u64::try_from(value)
            .map_err(|_| FingerprintError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn frame(hasher: &mut Sha256, name: &[u8], value: &[u8]) -> Result<(), FingerprintError> {
    count(hasher, name.len())?;
    hasher.update(name);
    count(hasher, value.len())?;
    hasher.update(value);
    Ok(())
}

fn threshold_digest(set: &thresholds::ThresholdSet) -> Result<[u8; 32], FingerprintError> {
    let thresholds::ThresholdSet {
        saturation,
        records,
        rgb,
        ir,
        fusion_probability,
        fusion_modality_floor,
    } = set;
    let mut h = Sha256::new();
    count(&mut h, *saturation)?;
    count(&mut h, records.len())?;
    for thresholds::Point {
        role,
        adapter,
        count: n,
        value,
    } in records
    {
        let role = match role {
            thresholds::Role::Rgb => 0,
            thresholds::Role::LitFallback => 1,
            thresholds::Role::LitCentroid => 2,
            thresholds::Role::DarkBest => 3,
            thresholds::Role::DarkCentroid => 4,
        };
        h.update([role, u8::from(*adapter)]);
        count(&mut h, *n)?;
        h.update(value.to_bits().to_le_bytes());
    }
    for values in [rgb, ir] {
        count(&mut h, values.len())?;
        for value in values {
            h.update(value.to_bits().to_le_bytes());
        }
    }
    for value in [fusion_probability, fusion_modality_floor] {
        h.update(value.to_bits().to_le_bytes());
    }
    Ok(finish(h))
}

fn constants_digest() -> Result<[u8; 32], FingerprintError> {
    use irlume_core::{fusion, storage};
    let mut h = Sha256::new();
    for (name, value) in [
        ("rgb", irlume_core::RGB_MATCH_THRESHOLD),
        ("ir", irlume_core::IR_MATCH_THRESHOLD),
        ("dark", irlume_core::IR_DARK_MATCH_THRESHOLD),
        ("adapted", irlume_core::IR_ADAPTED_MATCH_THRESHOLD),
        ("fallback-margin", irlume_core::IR_FALLBACK_MARGIN),
        ("scale-step", irlume_core::TEMPLATE_SCALE_STEP),
        ("scale-cap", irlume_core::TEMPLATE_SCALE_MAX_BUMP),
        ("fusion-threshold", fusion::FUSION_PROB_THRESHOLD),
        ("fusion-floor", fusion::FUSION_MIN_PER_MODALITY_PROB),
        ("rgb-platt-a", fusion::RGB_PLATT_A),
        ("rgb-platt-b", fusion::RGB_PLATT_B),
        ("ir-platt-a", fusion::IR_PLATT_A),
        ("ir-platt-b", fusion::IR_PLATT_B),
    ] {
        frame(&mut h, name.as_bytes(), &value.to_bits().to_le_bytes())?;
    }
    for (name, value) in [
        ("max-profiles", storage::MAX_PROFILES),
        ("max-scans", storage::MAX_SCANS_PER_PROFILE),
        ("count-budget", thresholds::MAX_TEMPLATE_COUNT),
        ("threshold-budget", thresholds::MAX_THRESHOLD_RECORDS),
        ("witness-budget", witnesses::MAX_COMPOSED_CASES),
    ] {
        frame(
            &mut h,
            name.as_bytes(),
            &u64::try_from(value)
                .map_err(|_| FingerprintError::SizeOverflow)?
                .to_le_bytes(),
        )?;
    }
    Ok(finish(h))
}

fn legacy_digest() -> [u8; 32] {
    let mut hasher = Sha256::new();
    decision_grid(
        &mut |bytes: &[u8]| {
            hasher.update((bytes.len() as u32).to_le_bytes());
            hasher.update(bytes);
        },
        &mut Coverage::default(),
    );
    finish(hasher)
}

#[cfg(test)]
pub(super) fn arm_grid_fingerprint() -> String {
    legacy_digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn public_value(result: Result<DecisionFingerprint, FingerprintError>) -> String {
    result.map(String::from).unwrap_or_default()
}

/// The recognition decision's fingerprint (ADR-0022 §3): the SHA-256 of
/// a versioned transcript binding the legacy arm grid, bounded threshold
/// records and projections, and checked composed-decision witnesses. Each
/// named section binds its SHA-256 digest with explicit length framing.
/// A changed fingerprint invalidates a certification bound to the old one.
///
/// Returns an empty string if construction cannot provide a valid digest.
/// NPU admission uses the checked result instead of this wrapper.
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
        for error in test_errors() {
            assert!(public_value(Err(error)).is_empty());
        }
        let checked = DecisionFingerprint::from_digest("1".repeat(64)).unwrap();
        assert_eq!(public_value(Ok(checked)), "1".repeat(64));
    }

    #[test]
    fn v2_is_distinct_from_the_preserved_legacy_grid() {
        let current = try_decision_fingerprint().unwrap();
        assert_ne!(current.as_ref(), arm_grid_fingerprint());
        assert_eq!(current.as_ref().len(), 64);
    }

    // First recorded on Fedora 44 x86_64 GNU with Rust 1.88.0. The legacy
    // section contains native-size/libm results; cross-host checks are required.
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    #[test]
    fn v2_fingerprint_matches_the_recorded_reference() {
        assert_eq!(
            try_decision_fingerprint().unwrap().as_ref(),
            "ea3527ae667c0c42dde5e176b9cf090f25c77f3c032d4faa6c5a104b19c006cc"
        );
    }

    #[test]
    fn section_framing_distinguishes_name_and_payload_boundaries() {
        let mut a = Sha256::new();
        let mut b = Sha256::new();
        frame(&mut a, b"ab", b"c").unwrap();
        frame(&mut b, b"a", b"bc").unwrap();
        assert_ne!(finish(a), finish(b));
    }

    #[test]
    fn incomplete_coverage_never_yields_a_checked_digest() {
        let checked = build_checked(
            Err(super::super::thresholds::ThresholdError::CountBudgetExceeded),
            super::super::thresholds::generate(super::super::thresholds::Domain::Complete),
            super::super::witnesses::build(),
        );
        assert_eq!(
            checked.unwrap_err(),
            FingerprintError::Threshold(
                super::super::thresholds::ThresholdError::CountBudgetExceeded
            )
        );
        let checked = build_checked(
            super::super::thresholds::generate(super::super::thresholds::Domain::Enrollable),
            super::super::thresholds::generate(super::super::thresholds::Domain::Complete),
            Err(super::super::witnesses::WitnessError::MissingCoverage),
        );
        assert_eq!(
            checked.unwrap_err(),
            FingerprintError::Witness(super::super::witnesses::WitnessError::MissingCoverage)
        );
    }
}
