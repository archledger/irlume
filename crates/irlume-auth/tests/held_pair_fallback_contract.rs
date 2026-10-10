// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn function<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("start function");
    let end = source[start..]
        .find(end)
        .map(|offset| start + offset)
        .expect("end function");
    &source[start..end]
}

fn assert_scoped_pair_assessment(source: &str) {
    let assessment = function(
        source,
        "    fn assess_with_fresh_pair_finish<T>(",
        "\n    fn assess_full_with_operation(",
    );
    let owner = assessment
        .find("with_owned_pair(pair,")
        .expect("own both sessions");
    let capture = assessment
        .find("self.assess_full_with_finish(Some((rgb, ir))")
        .expect("paired assessment");
    assert!(
        owner < capture,
        "capture must finish inside the session owner scope"
    );
    assert!(assessment.contains("Result<T, CapturePathError>"));
    assert!(assessment.contains("diagnostics, finish)"));
    assert!(assessment.contains("arm_pair_transactionally("));
    assert!(assessment.contains("establish_pair_rate(rgb, ir)"));
}

#[test]
fn held_concurrent_failure_is_returned_to_the_pair_owner() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let assess = function(
        &source,
        "    fn assess_full_with_finish<T>(",
        "\n    pub fn authenticate(",
    );

    assert!(assess.contains("CapturePathError::ConcurrentPair"));
    assert!(assess.contains("concurrent_pair_requires_fallback"));
    assert!(assess.contains("runtime_contract"));
    // #1033: a held-side capture fault fails the pair over at once. The two
    // held capture helpers stay, their fault arms invalidate the faulted
    // role's ADR-0021 rate-evidence entry explicitly, and no stream is ever
    // recovered in place before the mandatory sequential fallback.
    assert!(assess.contains("fn held_rgb_capture("));
    assert!(assess.contains("fn held_ir_capture("));
}

fn assess_span(source: &str) -> &str {
    function(
        source,
        "    fn assess_full_with_finish<T>(",
        "\n    pub fn authenticate(",
    )
}

fn auth_source() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source")
}

#[test]
fn held_capture_faults_invalidate_rate_evidence_explicitly() {
    let source = auth_source();
    let assess = assess_span(&source);
    assert!(
        assess.contains("invalidate_rate_evidence"),
        "a held-side fault must invalidate the faulted role's rate evidence"
    );
}

#[test]
fn held_captures_never_recover_a_stream_in_place() {
    let source = auth_source();
    let assess = assess_span(&source);
    assert!(
        !assess.contains(".recover()"),
        "a held capture must never recover its stream in place"
    );
    assert!(
        !assess.contains("recovered_side"),
        "the recovered-side relabel leaves with in-place recovery"
    );
    // The acceptance bar is crate-wide: no `recover(` anywhere under
    // crates/irlume-auth/src, tests or not.
    fn walk(dir: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read auth src dir") {
            let path = entry.expect("auth src entry").path();
            if path.is_dir() {
                walk(&path, hits);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).expect("read auth src file");
                if text.contains(".recover()") {
                    hits.push(path.display().to_string());
                }
            }
        }
    }
    let mut hits = Vec::new();
    walk(
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut hits,
    );
    assert!(
        hits.is_empty(),
        "no recover( call may survive under crates/irlume-auth/src: {hits:?}"
    );
}

#[test]
fn held_pair_refuses_the_sequential_schedule() {
    let source = auth_source();
    let assess = assess_span(&source);
    assert!(
        assess.contains("held pair capture requires the concurrent schedule"),
        "a held pair refuses the sequential schedule instead of capturing on it"
    );
}

#[test]
fn held_pair_failure_returns_the_side_original_error() {
    let source = auth_source();
    assert!(
        source.contains("fn held_pair_side_error("),
        "the pair-failure error is the winning side's original error"
    );
    let assess = assess_span(&source);
    assert!(
        assess.contains("held_pair_side_error(rgb_error, ir_error)"),
        "the held pair-failure path must return the winning side's original error"
    );
}

#[test]
fn managed_pair_faults_invalidate_rate_evidence_explicitly() {
    let source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/managed_pad.rs"))
            .expect("read managed_pad source");
    let sample = function(&source, "    fn prepare_managed_concurrent_sample(", "\n}");
    assert!(
        sample.contains("invalidate_rate_evidence"),
        "a managed pair side fault must revoke the faulted role's rate evidence too"
    );
    assert!(
        sample.contains("fault_revokes_rate_evidence"),
        "the managed revocation must stay gated on the non-cancellation predicate"
    );
    assert!(
        sample.contains("Preempted") && sample.contains("DeadlineExpired"),
        "cancellations must stay outside the rate-evidence revocation"
    );
}

#[test]
fn authentication_fallback_drops_the_entire_held_pair_before_retry() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let authenticate = function(
        &source,
        "    pub fn authenticate_for(",
        "\n    fn authenticate_once(",
    );

    // Streams belong to the assessment scope now, not the retry loop. The
    // runtime owner tests cover Drop on success/error/panic; pin both callers
    // to that scope so moving streams back outside the loop cannot pass.
    assert_scoped_pair_assessment(&source);
    let attempt = function(
        &source,
        "    fn authenticate_once(",
        "\n    pub fn identify(",
    );
    assert!(attempt.contains("self.assess_with_fresh_pair_finish("));
    assert!(attempt
        .contains("self.assess_full_with_finish(None, mode, operation, diagnostics, finish)"));
    let captured = attempt
        .find("let prepared = if let Some((rgb, ir)) = cameras")
        .unwrap();
    let decision = attempt.find("self.finish_pair_authentication(").unwrap();
    assert!(
        captured < decision,
        "identity admission follows the returning owner scope"
    );
    assert!(attempt[..captured].contains(".prepare_ordinary_pair_authentication_with("));
    assert!(!authenticate.contains("RgbSession"));
    assert!(!authenticate.contains("IrSession"));
    let fallback = authenticate
        .split("let error = first_result.expect_err")
        .nth(1)
        .expect("concurrent failure fallback");
    let release = fallback.find("drop(held_cams)").expect("release handles");
    let retry = fallback
        .find("self.authentication_attempt_loop(")
        .expect("sequential retry");
    assert!(
        release < retry,
        "fallback must release handles before reopening"
    );
    assert!(fallback[..retry].contains("demote_after_concurrent_capture_failure"));
}

#[test]
fn public_and_enrollment_pair_wrappers_still_finish_with_eager_identity() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    for (start, end, finish) in [
        (
            "    fn assess_with_fresh_pair(",
            "    fn assess_with_fresh_pair_finish<T>(",
            "self.assess_with_fresh_pair_finish(",
        ),
        (
            "    fn assess_full_with(",
            "    fn assess_full_with_finish<T>(",
            "self.assess_full_with_finish(",
        ),
    ] {
        let wrapper = function(&source, start, end);
        assert!(wrapper.contains("Result<Assessment, CapturePathError>"));
        assert!(wrapper.contains(finish));
        assert!(wrapper.contains(".materialize_pair_identity(evidence, diagnostics)"));
        assert!(!wrapper.contains("prepare_pair_authentication_with"));
        assert!(!wrapper.contains("qualify_rgb_pad_evidence"));
    }
    let capture = function(
        &source,
        "    fn assess_full_with_finish<T>(",
        "    fn detect_rgb_assessment(",
    );
    assert!(
        capture.find("self.assess_captured_pair(").unwrap()
            < capture.find("finish(self, evidence)").unwrap()
    );
}

#[test]
fn enrollment_fallback_restarts_without_held_sessions() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let capture = function(
        &source,
        "    fn capture_scans_observed(",
        "\n    fn capture_scan_loop(",
    );

    assert!(capture.contains("CapturePathError::ConcurrentPair"));
    assert!(capture.contains("demote_after_concurrent_capture_failure"));
    assert_scoped_pair_assessment(&source);
    assert!(!capture.contains("RgbSession"));
    assert!(!capture.contains("IrSession"));
    let release = capture.find("drop(cams)").expect("release handles");
    let retry = capture
        .rfind("self.capture_scan_loop(")
        .expect("sequential retry");
    assert!(
        release < retry,
        "fallback must release handles before reopening"
    );
    let scan_loop = function(&source, "    fn capture_scan_loop(", "\n    ///");
    assert!(scan_loop.contains("self.assess_with_fresh_pair("));
}

#[test]
fn support_probe_runs_every_dual_camera_assessment_inside_its_operation() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let probe = function(
        &source,
        "    pub fn support_probe(",
        "\n    /// RGB-only capture",
    );

    assert_eq!(
        probe.matches("self.assess_full_with_operation(").count(),
        2,
        "the concurrent and sequential probe paths must both install the held operation"
    );
    assert!(
        !probe.contains("self.assess_full_with("),
        "a raw dual-camera assessment reacquires the probe's own lease and times out"
    );
}

#[test]
fn support_probe_publishes_and_traces_the_rgb_only_camera() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let probe = function(
        &source,
        "    pub fn support_probe(",
        "\n    /// RGB-only capture",
    );

    assert!(probe.contains("rgb.diagnostic_camera_context()"));
    assert!(probe.contains("publish_rgb_only_support_context("));
    assert!(probe.contains("TraceEventKind::StreamContract"));
    assert!(probe.contains("self.assess_rgb_only_with_diagnostics(&probe_sink)"));
    assert!(
        !probe.contains("irlume_camera::capture_rgb_denoised_with_progress("),
        "the bare RGB capture omits detector, liveness, and stage trace evidence"
    );
}
