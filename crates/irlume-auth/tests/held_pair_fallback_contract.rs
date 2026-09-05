// SPDX-License-Identifier: GPL-3.0-or-later

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
        "    fn assess_with_fresh_pair(",
        "\n    fn assess_full_with_operation(",
    );
    let owner = assessment
        .find("with_owned_pair(pair,")
        .expect("own both sessions");
    let capture = assessment
        .find("self.assess_full_with(Some((rgb, ir))")
        .expect("paired assessment");
    assert!(
        owner < capture,
        "capture must finish inside the session owner scope"
    );
    assert!(assessment.contains("Result<Assessment, CapturePathError>"));
    assert!(assessment.contains("arm_pair_transactionally("));
    assert!(assessment.contains("establish_pair_rate(rgb, ir)"));
}

#[test]
fn held_concurrent_failure_is_returned_to_the_pair_owner() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let assess = function(
        &source,
        "    fn assess_full_with(",
        "\n    pub fn capture_pose_samples(",
    );

    assert!(assess.contains("CapturePathError::ConcurrentPair"));
    assert!(assess.contains("concurrent_pair_requires_fallback"));
    assert!(assess.contains("runtime_contract"));
    assert!(assess.contains("recovered_side"));
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
    assert!(attempt.contains("self.assess_with_fresh_pair(rgb, ir, mode, operation, diagnostics)"));
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
fn enrollment_fallback_restarts_without_held_sessions() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let capture = function(
        &source,
        "    fn capture_scans(",
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
