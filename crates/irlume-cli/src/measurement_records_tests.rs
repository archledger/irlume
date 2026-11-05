// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("record-boundary-{:032x}", rand::random::<u128>()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn artifact(&self) -> FreshArtifact {
        let dir = self.0.join("output");
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        FreshArtifact {
            root_path: self.0.clone(),
            root: directory(&self.0).unwrap(),
            path: dir.join(LEAF),
            dir: directory(&dir).unwrap(),
            name: "output".into(),
            observed: None,
            finished: false,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn write_private(path: &Path) {
    use std::io::Write;
    let round = irlume_camera::measurement::RateRound::from_window_facts(30, 1_000_000, 0, 0, true)
        .unwrap();
    let record = irlume_camera::pair_sample_measurement_record(
        "sequential",
        &irlume_camera::PairSample {
            rounds: 1,
            rgb_rate_rounds: vec![round],
            ir_rate_rounds: vec![round],
            ..Default::default()
        },
        1,
        "synthetic",
    )
    .unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&[record]).unwrap())
        .unwrap();
}

#[test]
fn reads_the_private_regular_file_and_removes_only_its_directory() {
    let fixture = Fixture::new();
    let mut artifact = fixture.artifact();
    assert!(!artifact.path.exists());
    write_private(&artifact.path);
    assert_eq!(artifact.read().unwrap().len(), 1);
    artifact.finish().unwrap();
    assert!(!fixture.0.join("output").exists());
    assert!(fixture.0.exists());
}

#[test]
fn missing_output_can_be_cleaned_without_touching_other_entries() {
    let fixture = Fixture::new();
    let mut artifact = fixture.artifact();
    fs::write(fixture.0.join("unrelated"), "retain").unwrap();
    assert!(artifact.read().is_err());
    artifact.finish().unwrap();
    assert_eq!(
        fs::read_to_string(fixture.0.join("unrelated")).unwrap(),
        "retain"
    );
}

#[test]
fn malformed_regular_file_fails_validation_but_is_owned_for_cleanup() {
    use std::io::Write;
    let fixture = Fixture::new();
    let mut artifact = fixture.artifact();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&artifact.path)
        .unwrap();
    file.write_all(b"not json").unwrap();
    assert!(artifact.read().is_err());
    artifact.finish().unwrap();
}

#[test]
fn symlink_output_is_neither_followed_nor_removed() {
    let fixture = Fixture::new();
    let mut artifact = fixture.artifact();
    let target = fixture.0.join("target");
    write_private(&target);
    let original = fs::read(&target).unwrap();
    symlink(&target, &artifact.path).unwrap();
    assert!(artifact.read().is_err());
    let output = artifact.path.clone();
    assert!(artifact.finish().is_err());
    assert!(fs::symlink_metadata(output)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(target).unwrap(), original);
}

#[test]
fn fifo_output_does_not_block_and_is_retained() {
    let fixture = Fixture::new();
    let mut artifact = fixture.artifact();
    let path = std::ffi::CString::new(artifact.path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: path is a live NUL-terminated byte string; mkfifo retains no pointer.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(artifact.read().is_err());
    let output = artifact.path.clone();
    assert!(artifact.finish().is_err());
    assert!(output.exists());
}

#[test]
fn unsafe_permissions_and_unexpected_files_are_retained() {
    for unexpected in [false, true] {
        let fixture = Fixture::new();
        let mut artifact = fixture.artifact();
        write_private(&artifact.path);
        if unexpected {
            artifact.read().unwrap();
            fs::write(artifact.path.parent().unwrap().join("extra"), "retain").unwrap();
        } else {
            fs::set_permissions(&artifact.path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(artifact.read().is_err());
        }
        let output = artifact.path.clone();
        assert!(artifact.finish().is_err());
        assert!(output.exists());
    }
}

#[test]
fn replaced_file_or_directory_is_not_removed() {
    for replace_directory in [false, true] {
        let fixture = Fixture::new();
        let mut artifact = fixture.artifact();
        write_private(&artifact.path);
        artifact.read().unwrap();
        let held = File::open(&artifact.path).unwrap();
        if replace_directory {
            fs::rename(fixture.0.join("output"), fixture.0.join("original")).unwrap();
            fs::create_dir(fixture.0.join("output")).unwrap();
        } else {
            fs::remove_file(&artifact.path).unwrap();
            write_private(&artifact.path);
        }
        let output = artifact.path.clone();
        assert!(artifact.finish().is_err());
        assert!(output.parent().unwrap().exists());
        assert!(held.metadata().unwrap().is_file());
    }
}

#[test]
fn reference_input_has_a_size_bound_and_must_contain_records() {
    let fixture = Fixture::new();
    let path = fixture.0.join("reference");
    fs::write(&path, "[]").unwrap();
    assert!(read_reference(path.to_str().unwrap()).is_err());
    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.set_len(MAX_BYTES + 1).unwrap();
    assert_eq!(
        read_reference(path.to_str().unwrap()).unwrap_err(),
        "measurement artifact exceeds 16 MiB"
    );
    assert!(read_reference(fixture.0.to_str().unwrap()).is_err());
}

#[test]
fn noncanonical_modes_and_hardlinks_are_not_accepted_or_removed() {
    for mode in [0o400, 0o700, 0o4600] {
        let fixture = Fixture::new();
        let mut artifact = fixture.artifact();
        write_private(&artifact.path);
        fs::set_permissions(&artifact.path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(artifact.read().is_err(), "accepted mode {mode:o}");
        assert!(artifact.finish().is_err(), "removed mode {mode:o}");
    }
    let fixture = Fixture::new();
    let mut artifact = fixture.artifact();
    write_private(&artifact.path);
    fs::hard_link(&artifact.path, fixture.0.join("another-link")).unwrap();
    assert!(artifact.read().is_err());
    assert!(artifact.finish().is_err());
    assert!(fixture.0.join("another-link").exists());
}

#[test]
fn descriptor_open_failure_removes_only_an_empty_created_directory() {
    let fixture = Fixture::new();
    for populated in [false, true] {
        let path = fixture
            .0
            .join(if populated { "populated" } else { "empty" });
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        if populated {
            fs::write(path.join("retain"), "untouched").unwrap();
        }
        let error =
            open_created_directory(&path, &path, Err("synthetic EMFILE".into())).unwrap_err();
        assert!(error.contains("synthetic EMFILE"));
        assert_eq!(path.exists(), populated);
        if populated {
            assert!(error.contains("retained"));
        }
    }
}

#[test]
fn opened_file_owned_by_another_uid_is_rejected() {
    let fixture = Fixture::new();
    let path = fixture.0.join("file");
    write_private(&path);
    let metadata = fs::metadata(path).unwrap();
    assert!(private_file(&metadata, metadata.uid()));
    assert!(!private_file(&metadata, metadata.uid().wrapping_add(1)));
}
