// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Shared preference observations for CLI status and the TUI background poll.
use irlume_common::{PreferencesState, Request, Response};

pub(crate) fn daemon_state() -> Option<PreferencesState> {
    match irlume_common::client::request_poll(&Request::PreferencesStatus) {
        Ok(Response::PreferencesStatus(state)) => Some(state),
        _ => None,
    }
}

pub(crate) fn observed() -> (PreferencesState, &'static str) {
    match daemon_state() {
        Some(state) => (state, "daemon observed"),
        None => (
            PreferencesState::observe(),
            "local observation; daemon preferences unavailable",
        ),
    }
}

pub(crate) fn toggle_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "ON",
        Some(false) => "OFF",
        None => "UNKNOWN",
    }
}
