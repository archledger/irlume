// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::RecognizerSelectionSource as Source;
use super::{RecognizerSelectionIssue as Issue, RecognizerSelectionProvenance as Provenance};
use crate::RecognizerPlacement;
use serde::Deserialize;
use serde_json::json;

#[test]
fn selection_provenance_known_values_round_trip_as_strings() {
    for (source, word) in [
        (Source::Default, "default"),
        (Source::Settings, "settings"),
        (Source::Environment, "environment"),
        (Source::Unknown, "unknown"),
    ] {
        assert_eq!(serde_json::to_value(source).unwrap(), json!(word));
        assert_eq!(
            serde_json::from_value::<Source>(json!(word)).unwrap(),
            source
        );
    }
    for (issue, word) in [
        (Issue::None, "none"),
        (Issue::InvalidValue, "invalid_value"),
        (Issue::DuplicateKey, "duplicate_key"),
        (Issue::UnreadableSettings, "unreadable_settings"),
        (Issue::Unknown, "unknown"),
    ] {
        assert_eq!(serde_json::to_value(issue).unwrap(), json!(word));
        assert_eq!(serde_json::from_value::<Issue>(json!(word)).unwrap(), issue);
    }
}

#[test]
fn selection_provenance_outer_absence_is_not_a_default_selection() {
    for value in [
        json!({"device":"cpu"}),
        json!({"device":"cpu","selection_provenance":null}),
    ] {
        let placement: RecognizerPlacement = serde_json::from_value(value).unwrap();
        assert_eq!(placement.selection_provenance, None);
        assert!(serde_json::to_value(placement)
            .unwrap()
            .get("selection_provenance")
            .is_none());
    }
    assert_eq!(RecognizerPlacement::default().selection_provenance, None);
}

#[test]
fn selection_provenance_missing_members_are_unknown_not_default_or_none() {
    for (value, expected) in [
        (json!({}), Provenance::default()),
        (
            json!({"source":"default"}),
            Provenance {
                source: Source::Default,
                issue: Issue::Unknown,
            },
        ),
        (
            json!({"issue":"none"}),
            Provenance {
                source: Source::Unknown,
                issue: Issue::None,
            },
        ),
    ] {
        let provenance: Provenance = serde_json::from_value(value).unwrap();
        assert_eq!(provenance, expected);
    }
    assert_eq!(Provenance::default().source, Source::Unknown);
    assert_eq!(Provenance::default().issue, Issue::Unknown);
}

#[test]
fn selection_provenance_future_strings_normalize_without_retaining_raw_values() {
    let provenance: Provenance = serde_json::from_value(json!({
        "source":"future-source-private", "issue":"future-issue-private"
    }))
    .unwrap();
    assert_eq!(provenance, Provenance::default());
    assert_eq!(
        serde_json::to_value(provenance).unwrap(),
        json!({"source":"unknown","issue":"unknown"})
    );
    assert!(!format!("{provenance:?}").contains("private"));
}

#[test]
fn selection_provenance_wrong_member_types_are_errors() {
    for value in [
        json!(null),
        json!(true),
        json!(42),
        json!([]),
        json!({}),
        json!({"settings":null}),
        json!({"none":null}),
    ] {
        assert!(
            serde_json::from_value::<Source>(value.clone()).is_err(),
            "{value}"
        );
        assert!(
            serde_json::from_value::<Issue>(value.clone()).is_err(),
            "{value}"
        );
        for member in ["source", "issue"] {
            let mut object = json!({"source":"default", "issue":"none"});
            object[member] = value.clone();
            assert!(
                serde_json::from_value::<Provenance>(object).is_err(),
                "{member}: {value}"
            );
        }
    }
}

#[test]
fn selection_provenance_wrong_outer_types_are_errors() {
    for value in [json!(true), json!(42), json!([]), json!("settings")] {
        assert!(serde_json::from_value::<RecognizerPlacement>(json!({
            "device":"cpu", "selection_provenance":value
        }))
        .is_err());
    }
}

#[test]
fn selection_provenance_unknown_object_fields_are_forward_compatible() {
    let provenance: Provenance = serde_json::from_value(json!({
        "source":"settings", "issue":"none", "future_detail":{"new":true}
    }))
    .unwrap();
    assert_eq!(
        provenance,
        Provenance {
            source: Source::Settings,
            issue: Issue::None
        }
    );
}

#[test]
fn selection_provenance_new_fields_are_ignored_by_a_legacy_reader() {
    #[derive(Deserialize)]
    struct LegacyPlacement {
        device: String,
        selection: Option<String>,
    }
    let placement = RecognizerPlacement {
        device: "cpu".into(),
        selection: Some("auto".into()),
        selection_provenance: Some(Provenance {
            source: Source::Environment,
            issue: Issue::InvalidValue,
        }),
        ..Default::default()
    };
    let legacy: LegacyPlacement =
        serde_json::from_value(serde_json::to_value(placement).unwrap()).unwrap();
    assert_eq!(legacy.device, "cpu");
    assert_eq!(legacy.selection.as_deref(), Some("auto"));
}

#[test]
fn selection_provenance_explicit_default_is_distinct_from_missing_data() {
    let placement: RecognizerPlacement = serde_json::from_value(json!({
        "device":"cpu", "selection":"auto", "selection_provenance":{"source":"default","issue":"none"}
    })).unwrap();
    assert_eq!(
        placement.selection_provenance,
        Some(Provenance {
            source: Source::Default,
            issue: Issue::None
        })
    );
}
