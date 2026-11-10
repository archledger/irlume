// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::process::{Command, Stdio};

#[test]
fn wallet_arguments_accept_the_capability_marker_without_starting_a_wallet() {
    for args in [
        vec!["synthetic-user"],
        vec!["synthetic-user", "--strict-runtime"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_irlume-kwallet-init"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        // Empty stdin fails before account lookup, backend selection or launch.
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("expected 56 bytes"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn mixed_or_unknown_arguments_fail_as_usage_errors() {
    for args in [
        vec![],
        vec!["--read-salt"],
        vec!["synthetic-user", "--unknown"],
        vec!["--strict-runtime", "synthetic-user"],
        vec!["synthetic-user", "--strict-runtime", "extra"],
        vec!["--read-salt", "synthetic-user", "--strict-runtime"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_irlume-kwallet-init"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
