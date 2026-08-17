// SPDX-License-Identifier: GPL-3.0-or-later

#[test]
fn qualification_owns_one_operation_across_context_and_both_arms() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read camera source");
    let start = source
        .find("pub fn measure_capture_qualification_with_progress(")
        .expect("qualification entry point");
    let end = source[start..]
        .find("\nfn collect_qualification_context(")
        .map(|offset| start + offset)
        .expect("next helper");
    let body = &source[start..end];

    assert_eq!(
        body.matches("acquire_camera_operation(").count(),
        1,
        "the qualification transaction must acquire exactly one pair operation"
    );
    assert!(body.contains("collect_qualification_context_in_operation("));
    assert!(body.contains("measure_contention_in_operation("));
    assert!(!body.contains("measure_contention_with_qualification_context("));
}
