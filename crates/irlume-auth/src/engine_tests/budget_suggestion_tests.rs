// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use irlume_common::config::FaceSensorPolicy::{Dual, IrOnlyExperimental};
use std::cell::Cell;
use std::time::{Duration, Instant};

struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Environment {
    fn new() -> Self {
        let keys = [
            "IRLUME_PRIVILEGED_GROUPED_PAD",
            "IRLUME_GRACE_MS",
            "IRLUME_SEQUENTIAL_CAPTURE",
            "IRLUME_CONFIG_DIR",
        ];
        let result = Self(
            keys.iter()
                .map(|key| (*key, std::env::var_os(key)))
                .collect(),
        );
        for key in keys {
            std::env::remove_var(key);
        }
        result
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

struct ReadyEngine<'a> {
    engine: &'a mut Engine,
    old_ir: bool,
    old_vit: Option<irlume_vision::PadVit>,
}
impl<'a> ReadyEngine<'a> {
    fn new(engine: &'a mut Engine) -> Self {
        let model =
            irlume_vision::PadVit::load_from_file(&model_path("liveness_vit.onnx")).unwrap();
        let old_vit = engine.vit_pad.replace(model);
        let old_ir = std::mem::replace(&mut engine.ir_available, true);
        assert!(engine.has_pad_ir());
        Self {
            engine,
            old_ir,
            old_vit,
        }
    }
}
impl Drop for ReadyEngine<'_> {
    fn drop(&mut self) {
        self.engine.ir_available = self.old_ir;
        self.engine.vit_pad = self.old_vit.take();
    }
}

#[test]
fn budget_hint_is_not_evaluated_for_excluded_requests() {
    let _guard = env_guard();
    let _env = Environment::new();
    let mut s = shared();
    let ready = ReadyEngine::new(&mut s.engine);
    for (enabled, policy, purpose, service, expected) in [
        ("0", Dual, AuthenticationPurpose::Verify, "sudo", 5_000),
        (
            "1",
            IrOnlyExperimental,
            AuthenticationPurpose::Verify,
            "sudo",
            5_000,
        ),
        (
            "1",
            Dual,
            AuthenticationPurpose::CredentialRelease,
            "sudo",
            5_000,
        ),
        ("1", Dual, AuthenticationPurpose::Verify, "kde", 15_000),
        ("1", Dual, AuthenticationPurpose::Verify, "sshd", 15_000),
    ] {
        std::env::set_var("IRLUME_PRIVILEGED_GROUPED_PAD", enabled);
        let window = ready.engine.authentication_window_from_with_hint(
            Instant::now(),
            Some(service),
            purpose,
            policy,
            || panic!("excluded request evaluated the hint"),
        );
        assert_eq!(window.milliseconds, expected);
    }
    std::env::set_var("IRLUME_PRIVILEGED_GROUPED_PAD", "1");
    for value in ["0", "5000", "8000", "60000"] {
        std::env::set_var("IRLUME_GRACE_MS", value);
        let window = ready.engine.authentication_window_from_with_hint(
            Instant::now(),
            Some("sudo"),
            AuthenticationPurpose::Verify,
            Dual,
            || panic!("explicit override evaluated the hint"),
        );
        assert_eq!(window.milliseconds, value.parse::<u64>().unwrap());
    }
    std::env::remove_var("IRLUME_GRACE_MS");
    for value in ["0", "1", ""] {
        std::env::set_var("IRLUME_SEQUENTIAL_CAPTURE", value);
        let window = ready.engine.authentication_window_from_with_hint(
            Instant::now(),
            Some("sudo"),
            AuthenticationPurpose::Verify,
            Dual,
            || panic!("forced capture schedule evaluated the hint"),
        );
        assert_eq!(window.milliseconds, 5_000);
    }
    std::env::remove_var("IRLUME_SEQUENTIAL_CAPTURE");
    ready.engine.ir_available = false;
    let window = ready.engine.authentication_window_from_with_hint(
        Instant::now(),
        Some("sudo"),
        AuthenticationPurpose::Verify,
        Dual,
        || panic!("missing IR evaluated the hint"),
    );
    assert_eq!(window.milliseconds, 5_000);
    ready.engine.ir_available = true;
    let old_vit = ready.engine.vit_pad.take();
    let calls = Cell::new(0);
    let window = ready.engine.authentication_window_from_with_hint(
        Instant::now(),
        Some("sudo"),
        AuthenticationPurpose::Verify,
        Dual,
        || {
            calls.set(calls.get() + 1);
            true
        },
    );
    ready.engine.vit_pad = old_vit;
    assert_eq!(calls.get(), 0);
    assert_eq!(window.milliseconds, 5_000);
    let old_ir_pad = ready.engine.pad_ir.take();
    let window = ready.engine.authentication_window_from_with_hint(
        Instant::now(),
        Some("sudo"),
        AuthenticationPurpose::Verify,
        Dual,
        || {
            calls.set(calls.get() + 1);
            true
        },
    );
    ready.engine.pad_ir = old_ir_pad;
    assert_eq!(calls.get(), 0);
    assert_eq!(window.milliseconds, 5_000);
}

#[test]
fn budget_hint_reserves_time_once_and_never_resets_request_origin() {
    let _guard = env_guard();
    let _env = Environment::new();
    let mut s = shared();
    let ready = ReadyEngine::new(&mut s.engine);
    std::env::set_var("IRLUME_PRIVILEGED_GROUPED_PAD", "1");
    for service in ["sudo", "polkit-1"] {
        for hint in [false, true] {
            let started = Instant::now() - Duration::from_secs(2);
            let calls = Cell::new(0);
            let window = ready.engine.authentication_window_from_with_hint(
                started,
                Some(service),
                AuthenticationPurpose::for_service(Some(service)),
                Dual,
                || {
                    calls.set(calls.get() + 1);
                    hint
                },
            );
            let expected = if hint { 15_000 } else { 5_000 };
            assert_eq!(calls.get(), 1);
            assert_eq!(window.milliseconds, expected);
            assert_eq!(window.deadline, started + Duration::from_millis(expected));
        }
    }
    let window = ready.engine.authentication_window_from_with_hint(
        Instant::now(),
        Some("sudo"),
        AuthenticationPurpose::Verify,
        Dual,
        || {
            std::env::set_var("IRLUME_GRACE_MS", "0");
            true
        },
    );
    assert_eq!(
        window.milliseconds, 15_000,
        "the entry override snapshot must not be reread after the hint"
    );
}

#[test]
fn budget_convenience_entry_keeps_refusal_state_and_cancellation_precedence() {
    let _guard = env_guard();
    let _env = Environment::new();
    let mut s = shared();
    let dir = std::env::temp_dir().join(format!("irlume-budget-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("settings.conf"), "face_sensor_policy=invalid\n").unwrap();
    std::env::set_var("IRLUME_CONFIG_DIR", &dir);
    s.engine.last_attempt_situation = Some(AttemptSituation::NoFace);
    let result = s.engine.authenticate_for_with_diagnostics(
        "budget-fixture",
        Some("sudo"),
        AuthenticationPurpose::Verify,
        &(),
    );
    assert!(result.is_err());
    assert!(s.engine.last_attempt_situation.is_none());
    let prior = s
        .engine
        .request_cancelled
        .replace(std::sync::Arc::new(|| true));
    let result = s.engine.authenticate_for_with_diagnostics(
        "budget-fixture",
        Some("sudo"),
        AuthenticationPurpose::Verify,
        &(),
    );
    s.engine.request_cancelled = prior;
    std::fs::remove_dir_all(dir).unwrap();
    assert!(matches!(result, Err(irlume_common::Error::Preempted(_))));
}

#[test]
fn budget_selection_cost_can_expire_window_but_zero_stays_one_shot() {
    let _guard = env_guard();
    let _env = Environment::new();
    let mut s = shared();
    let ready = ReadyEngine::new(&mut s.engine);
    std::env::set_var("IRLUME_PRIVILEGED_GROUPED_PAD", "1");
    let started = Instant::now() - Duration::from_secs(20);
    let window = ready.engine.authentication_window_from_with_hint(
        started,
        Some("sudo"),
        AuthenticationPurpose::Verify,
        Dual,
        || true,
    );
    assert!(
        window.check().is_err(),
        "metadata lookup must not grant a fresh 15 seconds afterward"
    );
    std::env::set_var("IRLUME_GRACE_MS", "0");
    let window = ready.engine.authentication_window_from_with_hint(
        started,
        Some("sudo"),
        AuthenticationPurpose::Verify,
        Dual,
        || panic!("one-shot evaluated hint"),
    );
    assert!(window.remaining().is_none());
    assert!(window.check().is_ok());
}
