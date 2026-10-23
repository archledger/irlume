// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Pure consistency checks over supplied descriptions and observations.

use super::{
    CheckedDescription, EnvironmentEntry, FileRole, MeasurementProfile, ProfileError,
    ProfileObservations, SuppliedPathTrust, DESCRIPTION_VERSION, MAX_ENVIRONMENT_ENTRIES,
    MAX_FILES, MAX_NAME_BYTES, MAX_TEXT_BYTES,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Component, Path};

/// Check bounded declarations against supplied file and environment snapshots.
///
/// No facts are collected here: even an acceptable path-trust label is a caller
/// assertion, not authenticated evidence. Success verifies only consistency of
/// the supplied facts, never native closure completeness, filesystem stability,
/// confinement, certification or permission to load or launch anything.
///
/// Limits are checked before members. Declarations are checked before file
/// observations, and each environment list before comparing their contents.
/// Comparisons use exact OS strings, without path or environment normalization.
/// Observations with identical resolved-path bytes must report the same digest;
/// agreeing aliases remain descriptions, not proof of a shared file or inode.
///
/// # Errors
/// Returns a value-redacted [`ProfileError`] for invalid headers, oversized or
/// conflicting declarations, missing or unacceptable file observations, or
/// invalid, duplicate or mismatched environment entries.
pub fn check_description<'a>(
    profile: &'a MeasurementProfile,
    observations: &'a ProfileObservations,
) -> Result<CheckedDescription<'a>, ProfileError> {
    if profile.files.len() > MAX_FILES || observations.files.len() > MAX_FILES {
        return Err(ProfileError::TooManyFiles);
    }
    if profile.environment.len() > MAX_ENVIRONMENT_ENTRIES
        || observations.environment.len() > MAX_ENVIRONMENT_ENTRIES
    {
        return Err(ProfileError::TooManyEnvironmentEntries);
    }
    if profile.version != DESCRIPTION_VERSION {
        return Err(ProfileError::UnsupportedVersion);
    }
    if profile.id.is_empty()
        || profile.id.len() > MAX_NAME_BYTES
        || !profile
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProfileError::InvalidProfileId);
    }
    if !sha256_text(&profile.build_sha256) {
        return Err(ProfileError::InvalidBuildDigest);
    }
    check_files(profile, observations)?;
    if environment(&profile.environment)? != environment(&observations.environment)? {
        return Err(ProfileError::EnvironmentMismatch);
    }
    Ok(CheckedDescription {
        profile,
        _observations: observations,
    })
}

fn check_files(
    profile: &MeasurementProfile,
    observations: &ProfileObservations,
) -> Result<(), ProfileError> {
    let mut declared = BTreeMap::new();
    for (file, entry) in profile.files.iter().enumerate() {
        if !file_path(&entry.path) {
            return Err(ProfileError::InvalidFilePath { file });
        }
        if !sha256_text(&entry.sha256) {
            return Err(ProfileError::InvalidFileDigest { file });
        }
        if declared.insert(entry.path.as_os_str(), file).is_some() {
            return Err(ProfileError::DuplicateFilePath { file });
        }
    }
    for role in [
        FileRole::Executable,
        FileRole::OrtRuntime,
        FileRole::LiteRtRuntime,
        FileRole::OpenVinoC,
    ] {
        match profile
            .files
            .iter()
            .filter(|file| file.role == role)
            .count()
        {
            0 => return Err(ProfileError::MissingRole(role)),
            1 => {}
            _ => return Err(ProfileError::DuplicateRole(role)),
        }
    }

    let mut observed = BTreeMap::new();
    for (observation, entry) in observations.files.iter().enumerate() {
        if observed.insert(entry.path.as_os_str(), entry).is_some() {
            return Err(ProfileError::DuplicateObservation { observation });
        }
        if !declared.contains_key(entry.path.as_os_str()) {
            return Err(ProfileError::UndeclaredObservation { observation });
        }
    }
    for (file, entry) in profile.files.iter().enumerate() {
        let observation = observed
            .get(entry.path.as_os_str())
            .ok_or(ProfileError::MissingObservation { file })?;
        if observation.path_trust != SuppliedPathTrust::Acceptable {
            return Err(ProfileError::UntrustedObservation { file });
        }
        if !observation.regular_file {
            return Err(ProfileError::NonRegularFile { file });
        }
        if !file_path(&observation.resolved_path) || observation.sha256 != entry.sha256 {
            return Err(ProfileError::ObservationMismatch { file });
        }
    }
    let mut aliases = BTreeMap::new();
    for (observation, entry) in observations.files.iter().enumerate() {
        if aliases
            .insert(entry.resolved_path.as_os_str(), entry.sha256.as_str())
            .is_some_and(|previous| previous != entry.sha256.as_str())
        {
            return Err(ProfileError::ConflictingAliasObservation { observation });
        }
    }
    Ok(())
}

fn file_path(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.len() <= MAX_TEXT_BYTES
            && !text.contains('\0')
            && path.is_absolute()
            && !path.components().any(|part| part == Component::ParentDir)
    })
}

fn sha256_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn environment(entries: &[EnvironmentEntry]) -> Result<BTreeMap<&OsStr, &OsStr>, ProfileError> {
    let mut result = BTreeMap::new();
    for (entry, item) in entries.iter().enumerate() {
        let valid_name = item.name.to_str().is_some_and(|name| {
            !name.is_empty()
                && name.len() <= MAX_NAME_BYTES
                && name.bytes().enumerate().all(|(position, byte)| {
                    byte.is_ascii_alphabetic()
                        || byte == b'_'
                        || (position > 0 && byte.is_ascii_digit())
                })
                && !name.starts_with("LD_")
                && name != "IRLUME_TEST_ALLOW_UNCERTIFIED_EP"
        });
        let valid_value = item
            .value
            .to_str()
            .is_some_and(|value| value.len() <= MAX_TEXT_BYTES && !value.contains('\0'));
        if !valid_name || !valid_value {
            return Err(ProfileError::InvalidEnvironment { entry });
        }
        if result
            .insert(item.name.as_os_str(), item.value.as_os_str())
            .is_some()
        {
            return Err(ProfileError::DuplicateEnvironment { entry });
        }
    }
    Ok(result)
}
