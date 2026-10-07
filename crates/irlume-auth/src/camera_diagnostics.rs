// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Camera diagnostics follow the saved camera selection (ADR-0032,
//! selection-aware diagnostics amendment).
//!
//! On a split-only machine the daemon's standing camera is the first RGB node
//! it finds, usually the selected split's own RGB side, with no IR. Measuring
//! that node would report the configured pair's IR as missing. With a split
//! pair selected and no ordinary environment override, the report is the
//! selected pair's instead, measured under one split Diagnostics operation.
//! Diagnostics is not a trust kind, so the split activation gate is not
//! involved: nothing here can enroll, authenticate or grant.

use irlume_common::split_publish::SplitReadState;
use irlume_common::{CameraDiagnosticsReport, CameraRoleDiagnostic};

/// What a diagnostics request measures.
enum Target {
    /// The standing devices, as every diagnostics request did before.
    Standing,
    /// The selected split pair, resolved exactly once in a Current view.
    Split(Box<irlume_camera::SplitPair>),
    /// A selected split pair that is not connected exactly once.
    NotConnected,
    /// A split publication or inventory that cannot say what is selected.
    Unverified,
}

/// Delivered-rate diagnostics for the configured pair (#462, #568).
///
/// The configured pair is the standing `rgb`/`ir` devices unless the coherent
/// camera selection names a split pair and no ordinary environment override
/// is set. Then both original split sides are measured, RGB then IR, under
/// one split Diagnostics operation, and never the standing fallback device:
/// a selected pair that is not connected reads as missing, and split
/// configuration or inventory that cannot be verified reads as unknown, with
/// no camera opened. A `cameras.conf` with no split key at all keeps the
/// standing devices, as before, even when it is unreadable or malformed.
///
/// # Errors
/// As [`irlume_camera::camera_rate_diagnostics`] for the standing devices; a
/// split target always returns a report.
pub fn camera_diagnostics(
    rgb: &str,
    ir: Option<&str>,
) -> irlume_common::Result<CameraDiagnosticsReport> {
    let role = |state: &str| CameraRoleDiagnostic {
        known: true,
        state: state.into(),
        evidence: None,
    };
    match target() {
        Target::Standing => irlume_camera::camera_rate_diagnostics(rgb, ir),
        Target::Split(pair) => Ok(irlume_camera::split_camera_rate_diagnostics(&pair)),
        Target::NotConnected => Ok(irlume_camera::unmeasured_pair_report(role("missing"))),
        Target::Unverified => Ok(irlume_camera::unmeasured_pair_report(role("unknown"))),
    }
}

fn target() -> Target {
    // An explicit ordinary pair decides, as it does for every request.
    if crate::request_preparation::ordinary_environment_pair().is_some() {
        return Target::Standing;
    }
    let snapshot = irlume_common::split_publish::read_camera_selection();
    // Without any split key the configured pair is the standing one, as it
    // always was, whatever else the file holds.
    if matches!(
        snapshot.observation().split,
        irlume_common::config::SplitConfObservation::None
    ) {
        return Target::Standing;
    }
    let (records, key) = match snapshot.split() {
        SplitReadState::Absent | SplitReadState::Valid { selected: None, .. } => {
            return Target::Standing;
        }
        SplitReadState::Valid {
            records,
            selected: Some(key),
            ..
        } => (records, key),
        // Split keys are present but cannot say what is selected.
        SplitReadState::Unreadable
        | SplitReadState::Malformed
        | SplitReadState::MalformedGeneration { .. }
        | SplitReadState::UnresolvedSelection { .. }
        | SplitReadState::DigestMismatch { .. } => return Target::Unverified,
    };
    let view = irlume_camera::connected_pairs_with_split(records);
    if view.ordinary.state != irlume_common::live_camera::CameraInventoryState::Current {
        return Target::Unverified;
    }
    let mut selected = view
        .split_pairs
        .into_iter()
        .filter(|pair| pair.pair_key().is_ok_and(|candidate| candidate == *key));
    match (selected.next(), selected.next()) {
        (Some(pair), None) => Target::Split(Box::new(pair)),
        _ => Target::NotConnected,
    }
}
