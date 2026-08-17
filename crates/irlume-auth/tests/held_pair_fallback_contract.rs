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
