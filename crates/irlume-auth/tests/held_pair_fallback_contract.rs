// SPDX-License-Identifier: GPL-3.0-or-later

fn function<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("start function");
    let end = source[start..]
        .find(end)
        .map(|offset| start + offset)
        .expect("end function");
    &source[start..end]
}

#[test]
fn held_concurrent_failure_is_returned_to_the_pair_owner() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read auth source");
    let assess = function(
        &source,
        "    fn assess_full_with(",
        "\n    fn run_passive_liveness(",
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

    for release in ["drop(held_rgb)", "drop(held_ir)", "drop(held_cams)"] {
        assert!(authenticate.contains(release), "missing {release}");
    }
    assert!(authenticate.contains("demote_after_concurrent_capture_failure"));
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
    assert!(capture.contains("drop(rs)"));
    assert!(capture.contains("drop(is)"));
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
