// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Exercise the real entry point without looking up a real target account or
//! starting any keyring daemon. Accepted input stops at a nonexistent user.

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

const NO_SUCH_USER: &str = "irlume-test-no-such-user-5c1e";

fn helper(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irlume-gkr-unlock"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn explicit_password_mode_accepts_pam_bytes_without_ever_starting_a_daemon() {
    for input in [
        &b" synthetic password \xc3\xa9\xff\n"[..],
        &vec![b' '; 4096][..],
    ] {
        let out = helper(&["--password", NO_SUCH_USER], input);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("no such user"));
        assert!(!out.stderr.windows(input.len()).any(|part| part == input));
    }
}

#[test]
fn default_token_and_invalid_passwords_fail_before_account_lookup() {
    for (args, input, why) in [
        (
            vec![NO_SUCH_USER],
            &b"synthetic password"[..],
            "non-printable",
        ),
        (
            vec![NO_SUCH_USER],
            &b"synthetic\xc3\xa9"[..],
            "non-printable",
        ),
        (vec![NO_SUCH_USER], &vec![b'a'; 257][..], "longer than 256"),
        (vec!["--password", NO_SUCH_USER], &b""[..], "empty password"),
        (
            vec!["--password", NO_SUCH_USER],
            &b"synthetic\0password"[..],
            "contains NUL",
        ),
        (
            vec!["--password", NO_SUCH_USER],
            &vec![b'a'; 4097][..],
            "longer than 4096",
        ),
    ] {
        let out = helper(&args, input);
        assert_eq!(out.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(why), "unexpected error: {stderr}");
        assert!(
            !stderr.contains("no such user"),
            "input was not refused first"
        );
    }
}

#[test]
fn unknown_flags_are_usage_errors() {
    let out = helper(&["--password-typo", NO_SUCH_USER], b"");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown option"));
}
