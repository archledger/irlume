// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Synthetic descriptions and supplied observations only. These tests neither
//! inspect installed files nor establish the authenticity of an observation.

use super::*;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

fn fixture() -> (MeasurementProfile, ProfileObservations) {
    let files = [
        (FileRole::Executable, "/fixture/measure"),
        (FileRole::OrtRuntime, "/fixture/libonnxruntime.so"),
        (FileRole::LiteRtRuntime, "/fixture/libtensorflowlite_c.so"),
        (FileRole::OpenVinoC, "/fixture/libopenvino_c.so.2621"),
    ]
    .into_iter()
    .map(|(role, path)| DeclaredFile {
        role,
        path: path.into(),
        sha256: "a".repeat(64),
    })
    .collect::<Vec<_>>();
    let observed = ProfileObservations {
        files: files
            .iter()
            .map(|file| FileObservation {
                path: file.path.clone(),
                resolved_path: file.path.clone(),
                sha256: file.sha256.clone(),
                regular_file: true,
                path_trust: SuppliedPathTrust::Acceptable,
            })
            .collect(),
        environment: vec![],
    };
    let profile = MeasurementProfile {
        version: DESCRIPTION_VERSION,
        id: "synthetic-description".into(),
        build_sha256: "b".repeat(64),
        files,
        environment: vec![],
    };
    (profile, observed)
}

fn env(name: &str, value: &str) -> EnvironmentEntry {
    EnvironmentEntry {
        name: name.into(),
        value: value.into(),
    }
}

#[test]
fn valid_description_is_not_a_launch_capability() {
    let (profile, observed) = fixture();
    let checked: CheckedDescription<'_> = check_description(&profile, &observed).unwrap();
    assert_eq!(checked.profile_id(), profile.id);
    assert_eq!(checked.declared_file_count(), 4);

    // These are supplied assertions, including the trust labels. Success is
    // consistency of this description, not a verified host or native closure.
    // No filesystem, launcher, production context or certification is involved.
}

#[test]
fn rejects_untrusted_file_observations() {
    for trust in [SuppliedPathTrust::Rejected, SuppliedPathTrust::Unknown] {
        let (profile, mut observed) = fixture();
        observed.files[1].path_trust = trust;
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::UntrustedObservation { file: 1 })
        );
    }
}

#[test]
fn rejects_invalid_environment_description() {
    for entry in [
        env("LD_PRELOAD", ""),
        env("LD_LIBRARY_PATH", "/fixture"),
        env("LD_AUDIT", "/fixture/audit.so"),
        env("IRLUME_TEST_ALLOW_UNCERTIFIED_EP", ""),
        env("", "value"),
        env("BAD=NAME", "value"),
        env("LANG", "C\0suffix"),
        EnvironmentEntry {
            name: OsString::from_vec(vec![0xff]),
            value: "value".into(),
        },
        EnvironmentEntry {
            name: "LANG".into(),
            value: OsString::from_vec(vec![0xff]),
        },
    ] {
        let (mut profile, mut observed) = fixture();
        profile.environment.push(entry.clone());
        observed.environment.push(entry);
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::InvalidEnvironment { entry: 0 })
        );
        profile.environment.clear();
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::InvalidEnvironment { entry: 0 })
        );
    }
}

#[test]
fn rejects_omitted_or_conflicting_roles() {
    for role in [
        FileRole::Executable,
        FileRole::OrtRuntime,
        FileRole::LiteRtRuntime,
        FileRole::OpenVinoC,
    ] {
        let (mut profile, mut observed) = fixture();
        let index = profile
            .files
            .iter()
            .position(|file| file.role == role)
            .unwrap();
        profile.files.remove(index);
        observed.files.remove(index);
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::MissingRole(role))
        );

        let (mut profile, mut observed) = fixture();
        let mut duplicate = profile.files[index].clone();
        duplicate.path = "/fixture/other-file".into();
        let mut observation = observed.files[index].clone();
        observation.path = duplicate.path.clone();
        observation.resolved_path = duplicate.path.clone();
        profile.files.push(duplicate);
        observed.files.push(observation);
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::DuplicateRole(role))
        );
    }
}

#[test]
fn description_requires_exact_observation_and_digest() {
    let (profile, mut observed) = fixture();
    observed.files.remove(1);
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::MissingObservation { file: 1 })
    );

    let (profile, mut observed) = fixture();
    observed.files[1].sha256 = "c".repeat(64);
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::ObservationMismatch { file: 1 })
    );

    let (profile, mut observed) = fixture();
    observed.files[1].regular_file = false;
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::NonRegularFile { file: 1 })
    );
}

#[test]
fn rejects_duplicate_and_undeclared_observations() {
    let (profile, mut observed) = fixture();
    observed.files.push(observed.files[0].clone());
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::DuplicateObservation { observation: 4 })
    );

    let (profile, mut observed) = fixture();
    let mut extra = observed.files[0].clone();
    extra.path = "/fixture/not-declared".into();
    extra.resolved_path = extra.path.clone();
    observed.files.push(extra);
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::UndeclaredObservation { observation: 4 })
    );
}

#[test]
fn rejects_invalid_paths_without_lossy_normalization() {
    for path in [
        PathBuf::from("relative/library.so"),
        PathBuf::from("/fixture/../library.so"),
        PathBuf::from("/fixture/lib\0.so"),
        PathBuf::from(OsString::from_vec(b"/fixture/\xff.so".to_vec())),
    ] {
        let (mut profile, mut observed) = fixture();
        profile.files[0].path = path.clone();
        observed.files[0].path = path;
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::InvalidFilePath { file: 0 })
        );
    }

    let (profile, mut observed) = fixture();
    observed.files[0].resolved_path = "relative/resolved".into();
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::ObservationMismatch { file: 0 })
    );
}

#[test]
fn rejects_duplicate_declared_paths() {
    let (mut profile, observed) = fixture();
    profile.files[1].path = profile.files[0].path.clone();
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::DuplicateFilePath { file: 1 })
    );
}

#[test]
fn environment_is_exact_and_preserves_absent_empty_and_duplicates() {
    let (mut profile, mut observed) = fixture();
    profile.environment = vec![env("LANG", "C"), env("OPTIONAL_EMPTY", "")];
    observed.environment = vec![env("OPTIONAL_EMPTY", ""), env("LANG", "C")];
    assert!(check_description(&profile, &observed).is_ok());

    observed.environment.remove(0);
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::EnvironmentMismatch)
    );
    observed.environment = vec![env("LANG", "C"), env("OPTIONAL_EMPTY", "other")];
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::EnvironmentMismatch)
    );
    observed.environment = profile.environment.clone();
    observed.environment.push(env("UNDECLARED", ""));
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::EnvironmentMismatch)
    );

    let (mut profile, mut observed) = fixture();
    profile.environment = vec![env("LANG", "C"), env("LANG", "C")];
    observed.environment = vec![env("LANG", "C")];
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::DuplicateEnvironment { entry: 1 })
    );
    profile.environment.pop();
    observed.environment.push(env("LANG", "C"));
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::DuplicateEnvironment { entry: 1 })
    );
}

#[test]
fn rejects_invalid_header_and_noncanonical_digests() {
    let (mut profile, observed) = fixture();
    profile.version += 1;
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::UnsupportedVersion)
    );
    profile.version = DESCRIPTION_VERSION;
    profile.id.clear();
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::InvalidProfileId)
    );

    for hash in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
        let (mut profile, observed) = fixture();
        profile.build_sha256 = hash.clone();
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::InvalidBuildDigest)
        );
        profile.build_sha256 = "b".repeat(64);
        profile.files[0].sha256 = hash;
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::InvalidFileDigest { file: 0 })
        );
    }
}

#[test]
fn rejects_oversized_descriptions_before_member_validation() {
    let (mut profile, observed) = fixture();
    profile.files = vec![profile.files[0].clone(); MAX_FILES + 1];
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::TooManyFiles)
    );

    let (profile, mut observed) = fixture();
    observed.files = vec![observed.files[0].clone(); MAX_FILES + 1];
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::TooManyFiles)
    );

    let (mut profile, mut observed) = fixture();
    for on_profile in [true, false] {
        profile.environment.clear();
        observed.environment.clear();
        let entries = vec![env("LANG", "C"); MAX_ENVIRONMENT_ENTRIES + 1];
        if on_profile {
            profile.environment = entries;
        } else {
            observed.environment = entries;
        }
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::TooManyEnvironmentEntries)
        );
    }
}

#[test]
fn bounds_apply_to_names_values_and_paths() {
    let (mut profile, observed) = fixture();
    profile.id = "x".repeat(MAX_NAME_BYTES + 1);
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::InvalidProfileId)
    );

    let (mut profile, observed) = fixture();
    profile.files[0].path = format!("/{}", "x".repeat(MAX_TEXT_BYTES)).into();
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::InvalidFilePath { file: 0 })
    );

    for entry in [
        env(&"X".repeat(MAX_NAME_BYTES + 1), ""),
        env("LANG", &"C".repeat(MAX_TEXT_BYTES + 1)),
    ] {
        let (mut profile, mut observed) = fixture();
        profile.environment.push(entry.clone());
        observed.environment.push(entry);
        assert_eq!(
            check_description(&profile, &observed).err(),
            Some(ProfileError::InvalidEnvironment { entry: 0 })
        );
    }
}

#[test]
fn rejects_conflicting_alias_observations() {
    let (mut profile, mut observed) = fixture();
    // Each observation matches its own declaration, but both names claim the
    // same resolved endpoint with different bytes. These are supplied facts,
    // not symlinks followed by the checker.
    observed.files[1].resolved_path = observed.files[0].resolved_path.clone();
    profile.files[1].sha256 = "c".repeat(64);
    observed.files[1].sha256 = profile.files[1].sha256.clone();
    assert_eq!(
        check_description(&profile, &observed).err(),
        Some(ProfileError::ConflictingAliasObservation { observation: 1 })
    );
}

#[test]
fn accepts_matching_alias_observations() {
    let (profile, mut observed) = fixture();
    observed.files[1].resolved_path = observed.files[0].resolved_path.clone();
    let checked = check_description(&profile, &observed).unwrap();
    assert_eq!(checked.declared_file_count(), 4);
}

#[test]
fn accepts_description_at_maximum_bounds() {
    let (mut profile, mut observed) = fixture();
    profile.id = "x".repeat(MAX_NAME_BYTES);
    for index in profile.files.len()..MAX_FILES {
        // One slash plus the padding plus three digits is MAX_TEXT_BYTES.
        profile.files.push(DeclaredFile {
            role: FileRole::NativeDependency,
            path: format!("/{}{:03}", "x".repeat(MAX_TEXT_BYTES - 4), index).into(),
            sha256: "a".repeat(64),
        });
        let declared = profile.files.last().unwrap();
        observed.files.push(FileObservation {
            path: declared.path.clone(),
            resolved_path: declared.path.clone(),
            sha256: declared.sha256.clone(),
            regular_file: true,
            path_trust: SuppliedPathTrust::Acceptable,
        });
    }
    for index in 0..MAX_ENVIRONMENT_ENTRIES {
        profile.environment.push(EnvironmentEntry {
            name: format!("V{}{:03}", "X".repeat(MAX_NAME_BYTES - 4), index).into(),
            value: "C".repeat(MAX_TEXT_BYTES).into(),
        });
    }
    observed.environment = profile.environment.clone();
    let checked = check_description(&profile, &observed).unwrap();
    assert_eq!(checked.profile_id().len(), MAX_NAME_BYTES);
    assert_eq!(checked.declared_file_count(), MAX_FILES);
}
