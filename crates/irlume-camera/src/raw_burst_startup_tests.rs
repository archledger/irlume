// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The raw IR burst (`burst_dump`, the nightly's camera stage) starts the way
// the product's fixed IR session starts. These run the same measured
// first-session timings through that startup.

#[test]
fn raw_burst_startup_delivers_on_the_measured_first_session_after_one_recheck() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let refused = start_raw_ir_burst("fixture", &mut stream, || true)
        .unwrap()
        .expect("the first window missed its floor, so the recheck is reported");
    // The window the fill established. Without the recheck the first delivery
    // would be refused on the window after it, 2,068,121 us.
    assert_eq!(refused.requested, (1, 30));
    assert_eq!(refused.accepted, (1, 30));
    assert_eq!(refused.window_count, 30);
    assert_eq!(refused.window_span_us, 2_088_113);
    assert_eq!(refused.max_inter_frame_gap_us, 95_945);
    assert_eq!(refused.floor, (15, 1));
    assert_eq!(refused.tolerance_percent, 97);
    assert_eq!(
        (refused.delivered.0, refused.delivered.1),
        (30_000_000, 2_088_113)
    );
    // The same frame the product's fixed startup delivers first.
    assert_eq!(stream.accounting().0, 40);
    let (_, frame, _, _, evidence) = stream.next().unwrap();
    assert_eq!(frame.sequence_raw(), 41);
    assert_eq!(evidence.window_count(), 30);
    assert_eq!(evidence.window_span_us(), 2_028_086);
    assert!(evidence.meets_floor());
}

#[test]
fn raw_burst_startup_keeps_the_original_refusal_on_an_unmeasured_profile() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    assert_eq!(
        start_raw_ir_burst("fixture", &mut stream, || false).unwrap(),
        None
    );
    assert_eq!(stream.accounting().0, 37);
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("unknown profiles must not get a startup recheck");
    };
    assert_eq!(evidence.window_span_us, 2_068_121);
}

#[test]
fn raw_burst_startup_refuses_a_stream_slow_in_both_windows() {
    let mut stream = ir_startup_timing_fixture(&[71_429; 42]);
    let refused = start_raw_ir_burst("fixture", &mut stream, || true)
        .unwrap()
        .expect("the first window missed its floor");
    assert_eq!(refused.window_span_us, 30 * 71_429);
    assert_eq!(refused.max_inter_frame_gap_us, 71_429);
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("a stream that stays below its floor must get a typed rate refusal");
    };
    assert_eq!(evidence.window_span_us, 30 * 71_429);
    assert!(!evidence.meets_floor);
}

#[test]
fn raw_burst_startup_does_not_check_the_profile_on_a_healthy_session() {
    let mut stream = ir_startup_timing_fixture(&SECOND_IR_SESSION_US);
    assert_eq!(
        start_raw_ir_burst("fixture", &mut stream, || {
            panic!("healthy startup must not check the profile")
        })
        .unwrap(),
        None
    );
    let (_, frame, _, _, evidence) = stream.next().unwrap();
    assert_eq!(frame.sequence_raw(), 38);
    assert_eq!(evidence.window_span_us(), 2_028_098);
}

#[test]
fn raw_burst_startup_with_a_sequence_gap_gets_no_recheck() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    for frame in stream.stream_mut().unwrap().metadata.iter_mut().skip(9) {
        frame.sequence += 1;
    }
    assert_eq!(
        start_raw_ir_burst("fixture", &mut stream, || {
            panic!("startup had a sequence gap")
        })
        .unwrap(),
        None
    );
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("expected the original rate refusal");
    };
    assert_eq!(evidence.cumulative_drops, 1);
}

#[test]
fn raw_burst_startup_reports_the_recheck_once_per_stream() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    assert!(start_raw_ir_burst("fixture", &mut stream, || true)
        .unwrap()
        .is_some());
    let (_, frame, _, _, _) = stream.next().unwrap();
    let delivered = frame.sequence_raw();
    assert_eq!(
        start_raw_ir_burst("fixture", &mut stream, || true).unwrap(),
        None,
        "a later startup call on the same stream has no recheck to report"
    );
    let (_, frame, _, _, evidence) = stream.next().unwrap();
    assert_eq!(frame.sequence_raw(), delivered + 2);
    assert!(evidence.meets_floor());
}
