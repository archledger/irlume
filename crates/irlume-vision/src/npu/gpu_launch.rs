// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Supplied candidate child-environment inputs, not native loading admission.
//!
//! A checked description cannot establish launcher ancestry, native dependency
//! closure, confinement, affinity, cache behavior, identity or certification.
//! No current-process environment, filesystem or native runtime is consulted.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

/// The sole candidate child-environment policy described by this module.
pub const POLICY_ID: &str = "gpu-candidate-inputs-v1";

/// The candidate's declared persistent compiler-cache policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeoCachePolicy {
    /// The child environment explicitly requests NEO_CACHE_PERSISTENT=0.
    Disabled,
}

/// Why supplied inputs do not describe the candidate policy, in precedence
/// order. These categories contain no caller-supplied names or values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuLaunchInputError {
    /// The supplied policy identifier is not exactly [`POLICY_ID`].
    UnknownPolicy,
    /// An entry count, name or value exceeds the policy's raw-byte bound.
    Bounds,
    /// An environment name does not follow the policy's ASCII grammar.
    MalformedName,
    /// An environment name occurs more than once, even with equal values.
    DuplicateName,
    /// A well-formed name is outside the three-entry policy allowlist.
    UnsupportedName,
    /// An allowed name has a value other than its exact allowed bytes.
    InvalidValue,
    /// The required explicit NEO cache-off entry is absent.
    MissingCacheIntent,
}

/// A consistent input description, never a launch or eligibility capability.
/// Only the static policy identifier and declared cache policy are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedGpuLaunchInputs {
    policy_id: &'static str,
    neo_cache_policy: NeoCachePolicy,
}

impl CheckedGpuLaunchInputs {
    /// The static identifier of the validated candidate-input policy.
    pub fn policy_id(&self) -> &'static str {
        self.policy_id
    }

    /// The candidate's declared policy, not an observation of cache behavior.
    pub fn neo_cache_policy(&self) -> NeoCachePolicy {
        self.neo_cache_policy
    }
}

/// Check a supplied candidate child environment without inspecting the host.
///
/// The policy requires exactly one `NEO_CACHE_PERSISTENT=0`, permits optional
/// `LANG=C` and `LC_ALL=C`, and refuses every other name. Inputs are borrowed,
/// compared as raw bytes, and never retained. Success is only input consistency,
/// not native loading admission, measured cache behavior or device eligibility.
///
/// # Errors
///
/// Returns the first applicable category in [`GpuLaunchInputError`]'s documented
/// order, independent of entry order: unknown policy, bounds (16 entries, 64-byte
/// names, 4096-byte values), malformed name, duplicate name, unsupported name,
/// invalid allowed value, then missing explicit cache-off intent.
pub fn validate(
    policy: &OsStr,
    environment: &[(&OsStr, &OsStr)],
) -> Result<CheckedGpuLaunchInputs, GpuLaunchInputError> {
    if policy != OsStr::new(POLICY_ID) {
        return Err(GpuLaunchInputError::UnknownPolicy);
    }
    if environment.len() > 16
        || environment
            .iter()
            .any(|(name, value)| name.as_bytes().len() > 64 || value.as_bytes().len() > 4096)
    {
        return Err(GpuLaunchInputError::Bounds);
    }
    // Each complete pass precedes the next category; returning at the first
    // invalid entry in a combined pass would make the result order-dependent.
    if environment.iter().any(|(name, _)| {
        let bytes = name.as_bytes();
        !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_uppercase() || *byte == b'_')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    }) {
        return Err(GpuLaunchInputError::MalformedName);
    }
    for (index, (name, _)) in environment.iter().enumerate() {
        if environment[..index]
            .iter()
            .any(|(previous, _)| previous == name)
        {
            return Err(GpuLaunchInputError::DuplicateName);
        }
    }
    if environment.iter().any(|(name, _)| {
        !matches!(
            name.as_bytes(),
            b"NEO_CACHE_PERSISTENT" | b"LANG" | b"LC_ALL"
        )
    }) {
        return Err(GpuLaunchInputError::UnsupportedName);
    }
    for (name, value) in environment {
        let expected = if name.as_bytes() == b"NEO_CACHE_PERSISTENT" {
            b"0"
        } else {
            // Only LANG and LC_ALL remain after the allowlist pass.
            b"C"
        };
        if value.as_bytes() != expected {
            return Err(GpuLaunchInputError::InvalidValue);
        }
    }
    if !environment
        .iter()
        .any(|(name, _)| name.as_bytes() == b"NEO_CACHE_PERSISTENT")
    {
        return Err(GpuLaunchInputError::MissingCacheIntent);
    }
    Ok(CheckedGpuLaunchInputs {
        policy_id: POLICY_ID,
        neo_cache_policy: NeoCachePolicy::Disabled,
    })
}

#[cfg(test)]
#[path = "gpu_launch_tests.rs"]
mod tests;
