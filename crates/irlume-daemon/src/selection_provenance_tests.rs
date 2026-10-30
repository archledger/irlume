// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{
    npu_placement::SettingsSnapshot,
    recognizer_selection::{self, Plan, Selection},
};
use irlume_common::recognizer_selection::{
    RecognizerSelectionIssue as Issue, RecognizerSelectionProvenance as Provenance,
    RecognizerSelectionSource as Source,
};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

#[test]
fn selection_provenance_preserves_existing_source_precedence() {
    let _env = crate::test_support::env_read();
    for (env, bytes, selection, source, issue) in [
        (
            None,
            b"".as_slice(),
            Selection::Auto,
            Source::Default,
            Issue::None,
        ),
        (
            None,
            b"gpu=off",
            Selection::Auto,
            Source::Default,
            Issue::None,
        ),
        (
            None,
            b"recognizer_device= GPU ",
            Selection::Auto,
            Source::Settings,
            Issue::InvalidValue,
        ),
        (
            Some(OsStr::new("npu")),
            b"recognizer_device=cpu",
            Selection::Npu,
            Source::Environment,
            Issue::None,
        ),
        (
            Some(OsStr::new("")),
            b"recognizer_device=cpu",
            Selection::Auto,
            Source::Environment,
            Issue::InvalidValue,
        ),
        (
            Some(OsStr::new("/private/invalid")),
            b"recognizer_device=cpu",
            Selection::Auto,
            Source::Environment,
            Issue::InvalidValue,
        ),
        (
            Some(OsStr::from_bytes(b"\xff")),
            b"recognizer_device=cpu",
            Selection::Auto,
            Source::Environment,
            Issue::InvalidValue,
        ),
        (
            None,
            b"recognizer_device: cpu",
            Selection::Auto,
            Source::Settings,
            Issue::InvalidValue,
        ),
        (
            None,
            b"recognizer_device=cpu\nrecognizer_device=cpu",
            Selection::Auto,
            Source::Settings,
            Issue::DuplicateKey,
        ),
        (
            None,
            b"recognizer_device=cpu\n\xff",
            Selection::Auto,
            Source::Settings,
            Issue::UnreadableSettings,
        ),
    ] {
        let plan = Plan::resolve(env, &SettingsSnapshot::Bytes(bytes.to_vec()));
        assert_eq!(plan.selection(), selection);
        assert_eq!(plan.provenance(), Provenance { source, issue });
        assert_eq!(plan.warning().is_some(), issue != Issue::None);
    }
    assert_eq!(
        Plan::resolve(None, &SettingsSnapshot::Absent).provenance(),
        Provenance {
            source: Source::Default,
            issue: Issue::None
        }
    );
    assert_eq!(
        Plan::resolve(None, &SettingsSnapshot::Unreadable).provenance(),
        Provenance {
            source: Source::Settings,
            issue: Issue::UnreadableSettings
        }
    );
    assert_eq!(
        Plan::resolve(Some(OsStr::new("cpu")), &SettingsSnapshot::Unreadable).provenance(),
        Provenance {
            source: Source::Environment,
            issue: Issue::None
        }
    );
}

#[test]
fn selection_provenance_stamps_one_copied_plan_despite_newer_publication() {
    let _env = crate::tests::env_lock();
    let _restore = recognizer_selection::preserve_publication();
    let old = Plan::resolve(
        Some(OsStr::new("cpu")),
        &SettingsSnapshot::Bytes(b"gpu=off".to_vec()),
    );
    recognizer_selection::publish(old);
    let copied = recognizer_selection::current_plan();
    recognizer_selection::publish(Plan::resolve(
        None,
        &SettingsSnapshot::Bytes(b"recognizer_device=npu".to_vec()),
    ));
    let mut placement = irlume_common::RecognizerPlacement {
        reason: Some("original engine reason".into()),
        ..Default::default()
    };
    super::stamp_recognizer_selection(&mut placement, copied);
    assert_eq!(placement.selection.as_deref(), Some("cpu"));
    assert_eq!(
        placement.selection_provenance,
        Some(Provenance {
            source: Source::Environment,
            issue: Issue::None
        })
    );
    #[cfg(not(feature = "npu"))]
    assert_eq!(
        placement.reason.as_deref(),
        Some(irlume_common::RECOGNIZER_CPU_SELECTED_REASON)
    );
    #[cfg(feature = "npu")]
    assert_eq!(placement.reason.as_deref(), Some("original engine reason"));
}

#[test]
fn selection_provenance_resolution_alone_does_not_publish_replacement_metadata() {
    let _env = crate::tests::env_lock();
    let _restore = recognizer_selection::preserve_publication();
    let old = Plan::resolve(
        None,
        &SettingsSnapshot::Bytes(b"recognizer_device=npu".to_vec()),
    );
    recognizer_selection::publish(old);
    let replacement = Plan::resolve(Some(OsStr::new("invalid")), &SettingsSnapshot::Absent);
    assert_ne!(replacement.provenance(), old.provenance());
    let mut placement = irlume_common::RecognizerPlacement::default();
    super::stamp_recognizer_selection(&mut placement, recognizer_selection::current_plan());
    assert_eq!(placement.selection.as_deref(), Some("npu"));
    assert_eq!(placement.selection_provenance, Some(old.provenance()));
    // Check the actual construction boundary without constructing an engine.
    let source = include_str!("main.rs");
    let build = source
        .split("fn build_engine_from_config(")
        .nth(1)
        .unwrap()
        .split("\nfn ")
        .next()
        .unwrap();
    assert!(build.contains("engine.inspect(|_| recognizer_selection::publish(plan))"));
}

#[test]
fn selection_provenance_retirement_preserves_intent_and_peer_privacy() {
    let _env = crate::test_support::env_read();
    let plan = Plan::resolve(
        None,
        &SettingsSnapshot::Bytes(b"recognizer_device=auto".to_vec()),
    );
    let mut before = irlume_common::RecognizerPlacement {
        device: "npu".into(),
        ..Default::default()
    };
    super::stamp_recognizer_selection(&mut before, Some(plan));
    let mut retired = before.clone();
    retired.device = "cpu".into();
    retired.reason = Some("NPU failed /private/provider serial=private-fixture".into());
    retired.runtime_available = Some(true);
    super::stamp_recognizer_selection(&mut retired, Some(plan));
    assert_eq!(retired.selection, before.selection);
    assert_eq!(retired.selection_provenance, before.selection_provenance);
    let ordinary = super::recognizer_for_peer(&retired, 12345);
    assert_eq!(ordinary.selection_provenance, before.selection_provenance);
    assert!(!serde_json::to_string(&ordinary)
        .unwrap()
        .contains("private"));
    assert!(super::recognizer_for_peer(&retired, 0)
        .reason
        .unwrap()
        .contains("private"));
}

#[test]
fn selection_provenance_without_publication_remains_unreported() {
    let mut placement = irlume_common::RecognizerPlacement::default();
    super::stamp_recognizer_selection(&mut placement, None);
    assert_eq!(placement.selection, None);
    assert_eq!(placement.selection_provenance, None);
}
