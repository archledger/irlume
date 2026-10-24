// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::measurement_profile::SuppliedPathTrust;
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::{symlink, FileExt, MetadataExt, PermissionsExt};
use std::path::Path;

fn fixture() -> (tempfile::TempDir, FixtureScope) {
    let directory = tempfile::tempdir().unwrap();
    let scope = FixtureScope {
        root: directory.path().to_path_buf(),
        expected_uid: directory.path().metadata().unwrap().uid(),
    };
    (directory, scope)
}

fn input(scope: &FixtureScope, name: &str, bytes: &[u8]) -> FixtureFile {
    let path = scope.root.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    FixtureFile {
        declared_path: path.clone(),
        file: File::open(path).unwrap(),
    }
}

fn tiny() -> ObservationLimits {
    ObservationLimits {
        per_file_bytes: 16,
        total_bytes: 32,
        read_calls: 32,
    }
}

#[test]
fn observes_fixture_bytes_and_retains_hash_allocation() {
    let (_directory, scope) = fixture();
    let file = input(&scope, "one", b"fixture-content");
    let mut hooks = PointerHook { pointer: 0 };
    let result = observe_with(&scope, vec![file], tiny(), &mut hooks).unwrap();
    let observed = &result.files()[0];
    assert_eq!(observed.bytes(), b"fixture-content");
    assert_eq!(observed.bytes().as_ptr() as usize, hooks.pointer);
    assert_eq!(
        observed.observation().sha256,
        irlume_common::sha256_hex(observed.bytes())
    );
    assert_eq!(
        observed.observation().path_trust,
        SuppliedPathTrust::Acceptable
    );
    assert!(observed.file.metadata().unwrap().is_file());
}

struct PointerHook {
    pointer: usize,
}
impl ObservationIo for PointerHook {
    fn buffer_ready(&mut self, _file: usize, bytes: &[u8]) {
        self.pointer = bytes.as_ptr() as usize;
    }
}

#[test]
fn preserves_supplied_descriptor_cursor() {
    let (_directory, scope) = fixture();
    let mut file = input(&scope, "one", b"abcdef");
    file.file.seek(SeekFrom::Start(3)).unwrap();
    let mut other = file.file.try_clone().unwrap();
    let result = observe_fixture_files(&scope, vec![file], tiny()).unwrap();
    assert_eq!(result.files()[0].bytes(), b"abcdef");
    assert_eq!(other.stream_position().unwrap(), 3);
}

#[test]
fn rejects_path_descriptor_identity_mismatch() {
    let (_directory, scope) = fixture();
    let mut one = input(&scope, "one", b"same");
    let two = input(&scope, "two", b"same");
    one.declared_path = two.declared_path;
    assert_eq!(
        observe_fixture_files(&scope, vec![one], tiny()).unwrap_err(),
        ObservationError::DescriptorMismatch { file: 0 }
    );
}

struct MutateHook {
    path: PathBuf,
    phase: Phase,
    action: u8,
    done: bool,
}
impl ObservationIo for MutateHook {
    fn checkpoint(&mut self, _file: usize, phase: Phase) {
        if phase != self.phase || self.done {
            return;
        }
        self.done = true;
        match self.action {
            0 => {
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o400)).unwrap();
            }
            1 => {
                let replacement = self.path.with_extension("new");
                fs::write(&replacement, b"abc").unwrap();
                fs::rename(replacement, &self.path).unwrap();
            }
            _ => {
                fs::write(&self.path, b"xyz").unwrap();
            }
        }
    }
}

#[test]
fn rejects_changed_metadata_or_endpoint() {
    for action in 0..3 {
        let (_directory, scope) = fixture();
        let file = input(&scope, "one", b"abc");
        let mut hooks = MutateHook {
            path: file.declared_path.clone(),
            phase: Phase::AfterRead,
            action,
            done: false,
        };
        assert_eq!(
            observe_with(&scope, vec![file], tiny(), &mut hooks).unwrap_err(),
            ObservationError::Changed { file: 0 }
        );
    }
}

#[test]
fn final_batch_recheck_rejects_earlier_file_change() {
    let (_directory, scope) = fixture();
    let one = input(&scope, "one", b"abc");
    let two = input(&scope, "two", b"def");
    let mut hooks = MutateHook {
        path: one.declared_path.clone(),
        phase: Phase::BeforeFinalCheck,
        action: 0,
        done: false,
    };
    assert_eq!(
        observe_with(&scope, vec![one, two], tiny(), &mut hooks).unwrap_err(),
        ObservationError::Changed { file: 0 }
    );
}

fn alias(scope: &FixtureScope, original: &Path, name: &str, hard: bool) -> FixtureFile {
    let path = scope.root.join(name);
    if hard {
        fs::hard_link(original, &path).unwrap();
    } else {
        symlink(original, &path).unwrap();
    }
    FixtureFile {
        declared_path: path.clone(),
        file: File::open(path).unwrap(),
    }
}

#[test]
fn accepts_matching_symlink_and_hardlink_aliases() {
    let (_directory, scope) = fixture();
    let one = input(&scope, "one", b"abc");
    let link = alias(&scope, &one.declared_path, "link", false);
    let hard = alias(&scope, &one.declared_path, "hard", true);
    let result = observe_fixture_files(&scope, vec![one, link, hard], tiny()).unwrap();
    assert_eq!(result.files().len(), 3);
    assert!(result.files().iter().all(|file| file.bytes() == b"abc"));
    assert_eq!(
        result.files()[0].observation().resolved_path,
        result.files()[1].observation().resolved_path
    );
}

struct CorruptAliasHook {
    calls: usize,
}
impl ObservationIo for CorruptAliasHook {
    fn read_at(&mut self, file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        self.calls += 1;
        let n = file.read_at(bytes, offset)?;
        if self.calls == 3 && n > 0 {
            bytes[0] ^= 1;
        }
        Ok(n)
    }
}

#[test]
fn rejects_conflicting_alias_snapshots() {
    for hard in [false, true] {
        let (_directory, scope) = fixture();
        let one = input(&scope, "one", b"abc");
        let other = alias(&scope, &one.declared_path, "alias", hard);
        assert_eq!(
            observe_with(
                &scope,
                vec![one, other],
                tiny(),
                &mut CorruptAliasHook { calls: 0 }
            )
            .unwrap_err(),
            ObservationError::AliasConflict { file: 1 }
        );
    }
}

#[test]
fn preserves_runtime_trust_and_symlink_refusals() {
    let (_directory, scope) = fixture();
    let target = input(&scope, "target", b"a");
    let secure = scope.root.join("secure");
    fs::create_dir(&secure).unwrap();
    fs::create_dir(secure.join("child")).unwrap();
    fs::write(secure.join("target"), b"a").unwrap();
    let current = scope.root.join("current");
    symlink("secure/child", &current).unwrap();
    let selected = current.join("../target");
    let file = FixtureFile {
        declared_path: selected,
        file: File::open(secure.join("target")).unwrap(),
    };
    assert!(observe_fixture_files(&scope, vec![file], tiny()).is_ok());

    let outside = tempfile::tempdir().unwrap();
    symlink(&target.declared_path, outside.path().join("hop")).unwrap();
    for (name, to) in [
        ("outside", outside.path().join("hop")),
        ("dangling", scope.root.join("missing")),
        ("cycle", scope.root.join("cycle")),
    ] {
        let path = scope.root.join(name);
        symlink(to, &path).unwrap();
        let file = FixtureFile {
            declared_path: path,
            file: target.file.try_clone().unwrap(),
        };
        assert_eq!(
            observe_fixture_files(&scope, vec![file], tiny()).unwrap_err(),
            ObservationError::PathRefused { file: 0 }
        );
    }
    let mut previous = target.declared_path.clone();
    for i in 1..=41 {
        let path = scope.root.join(format!("hop{i}"));
        symlink(&previous, &path).unwrap();
        let file = FixtureFile {
            declared_path: path.clone(),
            file: target.file.try_clone().unwrap(),
        };
        let result = observe_fixture_files(&scope, vec![file], tiny());
        if i <= 40 {
            assert!(result.is_ok(), "hop {i}");
        } else {
            assert_eq!(
                result.unwrap_err(),
                ObservationError::PathRefused { file: 0 }
            );
        }
        previous = path;
    }
}

struct CountHook {
    calls: Cell<usize>,
}
impl ObservationIo for CountHook {
    fn read_at(&mut self, file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        file.read_at(bytes, offset)
    }
}

#[test]
fn rejects_nonregular_or_untrusted_descriptors_before_read() {
    let (_directory, mut scope) = fixture();
    let directory = FixtureFile {
        declared_path: scope.root.clone(),
        file: File::open(&scope.root).unwrap(),
    };
    let mut hooks = CountHook {
        calls: Cell::new(0),
    };
    assert_eq!(
        observe_with(&scope, vec![directory], tiny(), &mut hooks).unwrap_err(),
        ObservationError::NotRegular { file: 0 }
    );
    let file = input(&scope, "one", b"a");
    scope.expected_uid = scope.expected_uid.wrapping_add(1);
    assert_eq!(
        observe_with(&scope, vec![file], tiny(), &mut hooks).unwrap_err(),
        ObservationError::UntrustedFile { file: 0 }
    );
    scope.expected_uid = scope.root.metadata().unwrap().uid();
    let file = input(&scope, "two", b"a");
    fs::set_permissions(&file.declared_path, fs::Permissions::from_mode(0o620)).unwrap();
    assert_eq!(
        observe_with(&scope, vec![file], tiny(), &mut hooks).unwrap_err(),
        ObservationError::UntrustedFile { file: 0 }
    );
    assert_eq!(hooks.calls.get(), 0);
}

struct ShortHook {
    interrupted: usize,
}
impl ObservationIo for ShortHook {
    fn read_at(&mut self, file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        if self.interrupted > 0 {
            self.interrupted -= 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        file.read_at(&mut bytes[..1], offset)
    }
}

#[test]
fn handles_short_reads_and_bounded_eintr() {
    let (_directory, scope) = fixture();
    let file = input(&scope, "one", b"ab");
    let limits = ObservationLimits {
        read_calls: 6,
        ..tiny()
    };
    let result = observe_with(
        &scope,
        vec![file],
        limits,
        &mut ShortHook { interrupted: 3 },
    )
    .unwrap();
    assert_eq!(result.files()[0].bytes(), b"ab");
    let file = input(&scope, "two", b"ab");
    assert_eq!(
        observe_with(
            &scope,
            vec![file],
            limits,
            &mut ShortHook { interrupted: 10 }
        )
        .unwrap_err(),
        ObservationError::ReadLimit { file: 0 }
    );
}

struct ResizeHook {
    path: PathBuf,
    grow: bool,
    done: bool,
}
impl ObservationIo for ResizeHook {
    fn read_at(&mut self, file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        if !self.done {
            self.done = true;
            if self.grow {
                OpenOptions::new()
                    .append(true)
                    .open(&self.path)
                    .unwrap()
                    .write_all(b"c")
                    .unwrap();
            } else {
                OpenOptions::new()
                    .write(true)
                    .open(&self.path)
                    .unwrap()
                    .set_len(1)
                    .unwrap();
            }
        }
        file.read_at(bytes, offset)
    }
}

#[test]
fn rejects_truncation_growth_and_budget_exhaustion() {
    for grow in [false, true] {
        let (_directory, scope) = fixture();
        let file = input(&scope, "one", b"ab");
        let mut hooks = ResizeHook {
            path: file.declared_path.clone(),
            grow,
            done: false,
        };
        assert_eq!(
            observe_with(&scope, vec![file], tiny(), &mut hooks).unwrap_err(),
            ObservationError::Changed { file: 0 }
        );
    }
    let (_directory, scope) = fixture();
    let file = input(&scope, "large", b"abc");
    assert_eq!(
        observe_fixture_files(
            &scope,
            vec![file],
            ObservationLimits {
                per_file_bytes: 2,
                ..tiny()
            }
        )
        .unwrap_err(),
        ObservationError::FileTooLarge { file: 0 }
    );
    let one = input(&scope, "one", b"a");
    let two = input(&scope, "two", b"b");
    assert_eq!(
        observe_fixture_files(
            &scope,
            vec![one, two],
            ObservationLimits {
                read_calls: 3,
                ..tiny()
            }
        )
        .unwrap_err(),
        ObservationError::ReadLimit { file: 1 }
    );
}

#[test]
fn aliases_charge_each_retained_allocation() {
    let (_directory, scope) = fixture();
    let one = input(&scope, "one", b"ab");
    let two = alias(&scope, &one.declared_path, "alias", false);
    assert_eq!(
        observe_fixture_files(
            &scope,
            vec![one, two],
            ObservationLimits {
                total_bytes: 3,
                ..tiny()
            }
        )
        .unwrap_err(),
        ObservationError::TotalTooLarge { file: 1 }
    );
}

#[test]
fn accepts_exact_fixture_budget_boundaries() {
    let (_directory, scope) = fixture();
    let one = input(&scope, "one", b"ab");
    let empty = input(&scope, "empty", b"");
    let limits = ObservationLimits {
        per_file_bytes: 2,
        total_bytes: 2,
        read_calls: 3,
    };
    assert_eq!(
        observe_fixture_files(&scope, vec![one, empty], limits)
            .unwrap()
            .files()
            .len(),
        2
    );
    assert_eq!(
        ObservationLimits::default(),
        ObservationLimits {
            per_file_bytes: 64 * 1024 * 1024,
            total_bytes: 256 * 1024 * 1024,
            read_calls: 8192
        }
    );
}

struct ReserveFailure;
impl ObservationIo for ReserveFailure {
    fn reserve(&mut self, _bytes: &mut Vec<u8>, _length: usize) -> Result<(), ObservationError> {
        Err(ObservationError::AllocationFailed)
    }
    fn read_at(&mut self, _file: &File, _bytes: &mut [u8], _offset: u64) -> io::Result<usize> {
        panic!("must refuse before reading");
    }
}

#[test]
fn reports_reservation_failure_without_partial_result() {
    let (_directory, scope) = fixture();
    let file = input(&scope, "one", b"a");
    assert_eq!(
        observe_with(&scope, vec![file], tiny(), &mut ReserveFailure).unwrap_err(),
        ObservationError::AllocationFailed
    );
}

#[test]
fn rejects_invalid_paths_and_oversized_limits_without_reading() {
    let (_directory, scope) = fixture();
    for limits in [
        ObservationLimits {
            per_file_bytes: 256 * 1024 * 1024 + 1,
            ..tiny()
        },
        ObservationLimits {
            total_bytes: 1024 * 1024 * 1024 + 1,
            ..tiny()
        },
        ObservationLimits {
            read_calls: 65537,
            ..tiny()
        },
    ] {
        assert_eq!(
            observe_fixture_files(&scope, vec![], limits).unwrap_err(),
            ObservationError::InvalidLimits
        );
    }
    let mut file = input(&scope, "one", b"a");
    file.declared_path = "relative".into();
    assert_eq!(
        observe_fixture_files(&scope, vec![file], tiny()).unwrap_err(),
        ObservationError::InvalidPath { file: 0 }
    );
}

#[test]
fn observer_result_is_non_authorizing_and_debug_is_redacted() {
    let (_directory, scope) = fixture();
    let file = input(&scope, "private-path", b"private-content");
    let result = observe_fixture_files(&scope, vec![file], tiny()).unwrap();
    let debug = format!("{result:?} {:?}", result.files()[0]);
    for secret in [
        "private-path",
        "private-content",
        result.files()[0].observation().sha256.as_str(),
    ] {
        assert!(!debug.contains(secret));
    }
    let _: &[u8] = result.files()[0].bytes();
    let _: &FileObservation = result.files()[0].observation();
}

struct RetargetAlias {
    alias: PathBuf,
    target: PathBuf,
    phase: Phase,
    done: bool,
}

impl ObservationIo for RetargetAlias {
    fn checkpoint(&mut self, _file: usize, phase: Phase) {
        if phase == self.phase && !self.done {
            self.done = true;
            fs::remove_file(&self.alias).unwrap();
            symlink(self.target.join("."), &self.alias).unwrap();
        }
    }
}

#[test]
fn rejects_unresolvable_original_path_spelling() {
    let (_directory, scope) = fixture();
    let regular = input(&scope, "regular", b"abc");
    let target = regular.declared_path.clone();
    let retained = regular.file.try_clone().unwrap();
    assert!(observe_fixture_files(&scope, vec![regular], tiny()).is_ok());

    let link = alias(&scope, &target, "valid-alias", false);
    assert!(observe_fixture_files(&scope, vec![link], tiny()).is_ok());

    for suffix in ["/", "/."] {
        let spelling = PathBuf::from(format!("{}{suffix}", target.display()));
        assert_eq!(
            fs::metadata(&spelling).unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
        let file = FixtureFile {
            declared_path: spelling,
            file: retained.try_clone().unwrap(),
        };
        assert_eq!(
            observe_fixture_files(&scope, vec![file], tiny()).unwrap_err(),
            ObservationError::MetadataRead { file: 0 }
        );
    }

    let bad_alias = scope.root.join("unresolvable-alias");
    symlink(target.join("."), &bad_alias).unwrap();
    assert_eq!(
        fs::metadata(&bad_alias).unwrap_err().raw_os_error(),
        Some(libc::ENOTDIR)
    );
    let file = FixtureFile {
        declared_path: bad_alias,
        file: retained.try_clone().unwrap(),
    };
    assert_eq!(
        observe_fixture_files(&scope, vec![file], tiny()).unwrap_err(),
        ObservationError::MetadataRead { file: 0 }
    );

    // The endpoint remains the same after component normalization. Both
    // recheck phases must nevertheless notice that the original spelling no
    // longer resolves, rather than trusting only the normalized endpoint.
    for (name, phase) in [
        ("after-read", Phase::AfterRead),
        ("final", Phase::BeforeFinalCheck),
    ] {
        let file = alias(&scope, &target, name, false);
        let mut hooks = RetargetAlias {
            alias: file.declared_path.clone(),
            target: target.clone(),
            phase,
            done: false,
        };
        assert_eq!(
            observe_with(&scope, vec![file], tiny(), &mut hooks).unwrap_err(),
            ObservationError::Changed { file: 0 }
        );
    }
}
