// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::measurement_profile::observe::{
    observe_fixture_files, FixtureFile, FixtureScope, ObservationLimits,
};
use crate::native_generation::{
    tests::{description, Image},
    NodeId,
};
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn real_observer_buffers_feed_sparse_ids_with_explicit_path_remapping() {
    let temp = tempfile::tempdir().unwrap();
    let b = Image::default().bytes();
    let path = temp.path().join("physical-not-logical");
    fs::write(&path, &b).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let observed = observe_fixture_files(
        &FixtureScope {
            root: temp.path().to_path_buf(),
            expected_uid: fs::metadata(temp.path()).unwrap().uid(),
        },
        vec![FixtureFile {
            declared_path: path,
            file: File::open(temp.path().join("physical-not-logical")).unwrap(),
        }],
        ObservationLimits::default(),
    )
    .unwrap();
    let d = description(&[(65535, "lib/logical.so", &b)], &[65535]);
    let g = check_observed(&d, &observed, &[(0, NodeId(65535))]).unwrap();
    assert_eq!(
        g.nodes()[0].bytes().as_ptr(),
        observed.files()[0].bytes().as_ptr()
    );
    for bindings in [
        vec![],
        vec![(1, NodeId(65535))],
        vec![(0, NodeId(2))],
        vec![(0, NodeId(65535)), (0, NodeId(65535))],
    ] {
        assert_eq!(
            check_observed(&d, &observed, &bindings).err(),
            Some(FixtureGraphError::Bindings)
        );
    }
}

#[test]
fn complete_observation_bijections_reject_repeated_indices_and_ids() {
    let temp = tempfile::tempdir().unwrap();
    let a = Image {
        needed: &["b.so"],
        ..Image::default()
    }
    .bytes();
    let b = Image::default().bytes();
    let mut files = Vec::new();
    for (name, bytes) in [("physical-a", &a), ("physical-b", &b)] {
        let path = temp.path().join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        files.push(FixtureFile {
            file: File::open(&path).unwrap(),
            declared_path: path,
        });
    }
    let observed = observe_fixture_files(
        &FixtureScope {
            root: temp.path().to_path_buf(),
            expected_uid: fs::metadata(temp.path()).unwrap().uid(),
        },
        files,
        ObservationLimits::default(),
    )
    .unwrap();
    let mut d = description(&[(65535, "lib/a.so", &a), (0, "lib/b.so", &b)], &[65535]);
    let bindings = [(1, NodeId(0)), (0, NodeId(65535))];
    let graph = check_observed(&d, &observed, &bindings).unwrap();
    assert_eq!(graph.edges()[0].to, NodeId(0));
    for bad in [
        [(0, NodeId(0)), (0, NodeId(65535))],
        [(0, NodeId(65535)), (1, NodeId(65535))],
        [(2, NodeId(0)), (0, NodeId(65535))],
        [(1, NodeId(1)), (0, NodeId(65535))],
    ] {
        assert_eq!(
            check_observed(&d, &observed, &bad).err(),
            Some(FixtureGraphError::Bindings)
        );
    }
    assert_eq!(
        check_observed(&d, &observed, &bindings[..1]).err(),
        Some(FixtureGraphError::Bindings)
    );
    d.nodes[0].sha256 = "0".repeat(64);
    assert_eq!(
        check_observed(&d, &observed, &bindings).err(),
        Some(FixtureGraphError::Graph(GraphError::DigestMismatch))
    );
}
