// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use irlume_common::recognizer_selection::{
    RecognizerSelectionIssue as Issue, RecognizerSelectionProvenance as Provenance,
    RecognizerSelectionSource as Source,
};
use irlume_common::RecognizerPlacement;
use serde_json::json;

#[test]
fn selection_provenance_status_omits_unreported_data() {
    assert_eq!(
        super::machine::recognizer_json(None),
        json!({"known":false})
    );
    let value = super::machine::recognizer_json(Some(RecognizerPlacement {
        device: "cpu".into(),
        ..Default::default()
    }));
    assert_eq!(value, json!({"known":true,"device":"cpu"}));
}

#[test]
fn selection_provenance_status_reports_known_and_future_values() {
    for (source, issue) in [("settings", "none"), ("future-source", "future-issue")] {
        let placement: RecognizerPlacement = serde_json::from_value(json!({
            "device":"cpu", "selection":"npu",
            "selection_provenance":{"source":source,"issue":issue}
        }))
        .unwrap();
        let value = super::machine::recognizer_json(Some(placement));
        let expected = if source == "settings" {
            json!({"source":"settings","issue":"none"})
        } else {
            json!({"source":"unknown","issue":"unknown"})
        };
        assert_eq!(value["selection_provenance"], expected);
        assert_eq!(value["device"], "cpu");
    }
}

#[test]
fn selection_provenance_doctor_distinguishes_default_unknown_and_unreported() {
    use super::doctor_report::State;
    let (state, absent) = super::recognizer_selection_report(Some("auto"), None);
    assert_eq!(state, State::Info);
    assert!(absent.contains("source not reported"));
    let (state, unknown) =
        super::recognizer_selection_report(Some("auto"), Some(&Provenance::default()));
    assert_eq!(state, State::Info);
    assert!(unknown.contains("source: unknown; issue: unknown"));
    let (state, default) = super::recognizer_selection_report(
        Some("auto"),
        Some(&Provenance {
            source: Source::Default,
            issue: Issue::None,
        }),
    );
    assert_eq!(state, State::Info);
    assert!(default.contains("source: default; issue: none"));
    assert_ne!(absent, default);
    assert_eq!(
        super::recognizer_selection_report(None, None).0,
        State::Unknown
    );
}

#[test]
fn selection_provenance_doctor_issues_do_not_change_existing_severity() {
    use super::doctor_report::State;
    for (issue, text) in [
        (Issue::None, "none"),
        (Issue::InvalidValue, "invalid value"),
        (Issue::DuplicateKey, "duplicate key"),
        (Issue::UnreadableSettings, "unreadable settings"),
        (Issue::Unknown, "unknown"),
    ] {
        let (state, line) = super::recognizer_selection_report(
            Some("auto"),
            Some(&Provenance {
                source: Source::Environment,
                issue,
            }),
        );
        assert_eq!(state, State::Info);
        assert!(line.ends_with(&format!("source: environment; issue: {text}")));
    }
}

#[test]
fn selection_provenance_schema_matches_emitted_strings() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/machine-api-v1.schema.json")).unwrap();
    let object = &schema["$defs"]["statusData"]["properties"]["recognizer"]["properties"]
        ["selection_provenance"];
    assert_eq!(object["type"], "object");
    assert_eq!(object["required"], json!(["source", "issue"]));
    assert_eq!(
        object["properties"]["source"]["enum"],
        json!(["default", "settings", "environment", "unknown"])
    );
    assert_eq!(
        object["properties"]["issue"]["enum"],
        json!([
            "none",
            "invalid_value",
            "duplicate_key",
            "unreadable_settings",
            "unknown"
        ])
    );
    let required = schema["$defs"]["statusData"]["properties"]["recognizer"]["required"]
        .as_array()
        .unwrap();
    assert!(!required.contains(&json!("selection_provenance")));
}
