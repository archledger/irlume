// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::time::{Duration, Instant};

const SERVICE: &str = "cosmic-greeter";
const CHOICE: &str = "Password or yes for face: ";

fn run(
    h: &Harness,
    service: &str,
    input: &str,
    cached: Option<&str>,
    drop_empty: bool,
) -> (bool, String) {
    let driver = h.root.join("cosmic-conversation");
    let built = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cosmic_conversation.c"))
        .args(["-lpam", "-o"])
        .arg(&driver)
        .output()
        .expect("C compiler for real-PAM conversation fixture");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let mut command = Command::new(driver);
    command
        .args([
            service,
            "tester",
            if drop_empty { "cosmic" } else { "direct" },
        ])
        .env("LD_PRELOAD", &h.wrapper)
        .env("PAM_WRAPPER", "1")
        .env("PAM_WRAPPER_SERVICE_DIR", &h.service_dir)
        .env("IRLUME_CONFIG_DIR", &h.config_dir)
        .env("IRLUME_SOCKET", &h.socket)
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("PAM_AUTHTOK")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(token) = cached {
        command.env("PAM_AUTHTOK", token);
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("COSMIC conversation exceeded its test deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !text.contains("PROMPT_VISIBLE"),
        "password input must remain hidden: {text}"
    );
    assert!(
        !text.contains(FIXED_TEST_TOKEN) && !text.contains(WRONG_TEST_TOKEN),
        "response leaked: {text}"
    );
    (output.status.success(), text)
}

fn stack(h: &Harness, expected: &str, cached: bool) {
    let checker = h.token_checker("cosmic-password", expected);
    let mut lines = Vec::new();
    if cached {
        lines.push(format!(
            "auth [success=ignore default=bad] {}",
            h.set_items.display()
        ));
    }
    lines.push(h.auth_line("sufficient", "unseal ondemand kr"));
    lines.push(format!(
        "auth required pam_exec.so expose_authtok {}",
        checker.display()
    ));
    h.write_service(SERVICE, &lines);
}

fn face_response(request: &Request) -> Response {
    match request {
        Request::UnsealPassword { service, .. } => {
            assert_eq!(service.as_deref(), Some(SERVICE));
            Response::UnsealUnavailable {
                reason: "synthetic identity-only test".into(),
            }
        }
        Request::Authenticate { service, .. } => {
            assert_eq!(service.as_deref(), Some(SERVICE));
            grant()
        }
        _ => panic!("unexpected request"),
    }
}

#[test]
#[ignore = "needs pam_wrapper + pamtester + cc (CI installs them)"]
fn cosmic_nonempty_choice_reaches_identity_only_face_after_empty_is_dropped() {
    let h = Harness::try_new("cosmic-choice").expect("explicitly requested PAM dependencies");
    stack(&h, FIXED_TEST_TOKEN, false);
    let log = serve(&h.socket, face_response);
    let (ok, output) = run(&h, SERVICE, "\nyes\n", None, true);
    assert!(ok, "explicit choice must reach face: {output}");
    assert_eq!(output.matches("EMPTY_DROPPED").count(), 1);
    assert_eq!(output.matches(CHOICE).count(), 1);
    assert_eq!(output.matches("PROMPT_HIDDEN").count(), 1);
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(matches!(&requests[0], Request::UnsealPassword { .. }));
    assert!(matches!(&requests[1], Request::Authenticate { .. }));
}

#[test]
#[ignore = "needs pam_wrapper + pamtester + cc (CI installs them)"]
fn cosmic_password_is_used_once_without_any_face_request() {
    for (index, token, succeeds) in [(0, FIXED_TEST_TOKEN, true), (1, WRONG_TEST_TOKEN, false)] {
        let h = Harness::try_new(&format!("cosmic-password-{index}")).unwrap();
        stack(&h, FIXED_TEST_TOKEN, false);
        let log = serve(&h.socket, |_| panic!("password must never request face"));
        let (ok, output) = run(&h, SERVICE, &format!("\n{token}\n"), None, true);
        assert_eq!(ok, succeeds, "{output}");
        assert_eq!(output.matches(CHOICE).count(), 1);
        assert_eq!(output.matches("PROMPT_HIDDEN").count(), 1);
        assert_eq!(output.matches("EMPTY_DROPPED").count(), 1);
        assert!(log.lock().unwrap().is_empty());
    }
}

#[test]
#[ignore = "needs pam_wrapper + pamtester + cc (CI installs them)"]
fn cosmic_cached_yes_is_a_password_not_fresh_consent() {
    let h = Harness::try_new("cosmic-cached").unwrap();
    stack(&h, "yes", true);
    let log = serve(&h.socket, |_| {
        panic!("cached password must never request face")
    });
    let (ok, output) = run(&h, SERVICE, "", Some("yes"), true);
    assert!(ok, "{output}");
    assert!(
        !output.contains("PROMPT_"),
        "cached token must need no prompt: {output}"
    );
    assert!(log.lock().unwrap().is_empty());
}

#[test]
#[ignore = "needs pam_wrapper + pamtester + cc (CI installs them)"]
fn cosmic_cached_empty_token_requires_a_fresh_nonempty_choice() {
    let h = Harness::try_new("cosmic-cached-empty").unwrap();
    stack(&h, FIXED_TEST_TOKEN, true);
    let log = serve(&h.socket, face_response);
    let (ok, output) = run(&h, SERVICE, "yes\n", Some(""), true);
    assert!(ok, "fresh explicit selection must be requested: {output}");
    assert_eq!(output.matches(CHOICE).count(), 1);
    assert_eq!(output.matches("PROMPT_HIDDEN").count(), 1);
    assert_eq!(log.lock().unwrap().len(), 2);
}

#[test]
#[ignore = "needs pam_wrapper + pamtester + cc (CI installs them)"]
fn cosmic_face_denial_consumes_choice_before_fresh_password() {
    for (index, token, succeeds) in [
        (0, FIXED_TEST_TOKEN, true),
        (1, WRONG_TEST_TOKEN, false),
        (2, "yes", false),
    ] {
        let h = Harness::try_new(&format!("cosmic-denial-{index}")).unwrap();
        stack(&h, FIXED_TEST_TOKEN, false);
        let log = serve(&h.socket, |request| match request {
            Request::UnsealPassword { .. } => Response::UnsealUnavailable {
                reason: "synthetic refusal".into(),
            },
            Request::Authenticate { .. } => Response::AuthResult {
                granted: false,
                live: false,
                score: 0.0,
                reason: "synthetic denial".into(),
                refused_by_policy: false,
                declined_by_gesture: false,
                situation: String::new(),
            },
            _ => panic!("unexpected request"),
        });
        let (ok, output) = run(&h, SERVICE, &format!("yes\n{token}\n"), None, true);
        assert_eq!(ok, succeeds, "{output}");
        assert_eq!(output.matches(CHOICE).count(), 1);
        assert_eq!(
            output.matches("PROMPT_HIDDEN").count(),
            2,
            "fresh password required: {output}"
        );
        assert_eq!(log.lock().unwrap().len(), 2);
    }
}

#[test]
#[ignore = "needs pam_wrapper + pamtester + cc (CI installs them)"]
fn cosmic_empty_or_cancelled_conversation_never_selects_face() {
    for (index, drop_empty, input) in [(0, true, "\n"), (1, true, ""), (2, false, "\n")] {
        let h = Harness::try_new(&format!("cosmic-empty-{index}")).unwrap();
        stack(&h, FIXED_TEST_TOKEN, false);
        let log = serve(&h.socket, face_response);
        let (ok, output) = run(&h, SERVICE, input, None, drop_empty);
        assert!(!ok, "missing explicit consent must not grant: {output}");
        assert!(log.lock().unwrap().is_empty());
    }
}
