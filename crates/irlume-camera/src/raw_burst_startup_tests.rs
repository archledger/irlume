// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The raw IR burst (`burst_dump`, the nightly's camera stage) starts the way
// the product's fixed IR session starts. These run the same measured
// first-session timings through that startup.

#[test]
fn raw_burst_startup_delivers_on_the_measured_first_session_after_one_recheck() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let mut reported = None;
    start_raw_ir_burst("fixture", &mut stream, || true, |window| reported = Some(window)).unwrap();
    let refused = reported.expect("the first window missed its floor, so the recheck is reported");
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
    let mut reported = None;
    start_raw_ir_burst("fixture", &mut stream, || false, |window| reported = Some(window)).unwrap();
    assert_eq!(reported, None);
    assert_eq!(stream.accounting().0, 37);
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("unknown profiles must not get a startup recheck");
    };
    assert_eq!(evidence.window_span_us, 2_068_121);
}

#[test]
fn raw_burst_startup_refuses_a_stream_slow_in_both_windows() {
    let mut stream = ir_startup_timing_fixture(&[71_429; 42]);
    let mut reported = None;
    start_raw_ir_burst("fixture", &mut stream, || true, |window| reported = Some(window)).unwrap();
    let refused = reported.expect("the first window missed its floor");
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
    let mut reported = None;
    start_raw_ir_burst("fixture", &mut stream, || panic!("healthy startup must not check the profile"), {
        |window| reported = Some(window)
    })
    .unwrap();
    assert_eq!(reported, None);
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
    let mut reported = None;
    start_raw_ir_burst("fixture", &mut stream, || panic!("startup had a sequence gap"), {
        |window| reported = Some(window)
    })
    .unwrap();
    assert_eq!(reported, None);
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("expected the original rate refusal");
    };
    assert_eq!(evidence.cumulative_drops, 1);
}

#[test]
fn raw_burst_startup_reports_the_recheck_once_per_stream() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let mut reported = None;
    start_raw_ir_burst("fixture", &mut stream, || true, |window| reported = Some(window)).unwrap();
    assert!(reported.is_some());
    let (_, frame, _, _, _) = stream.next().unwrap();
    let delivered = frame.sequence_raw();
    let mut later = None;
    start_raw_ir_burst("fixture", &mut stream, || true, |window| later = Some(window)).unwrap();
    assert_eq!(
        later, None,
        "a later startup call on the same stream has no recheck to report"
    );
    let (_, frame, _, _, evidence) = stream.next().unwrap();
    assert_eq!(frame.sequence_raw(), delivered + 2);
    assert!(evidence.meets_floor());
}

#[test]
fn raw_burst_startup_reports_the_replaced_window_when_a_recheck_dequeue_fails() {
    // 38 frames: the warm-up, the flush, the fill, then one frame of the
    // three the recheck discards.
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    stream.stream_mut().unwrap().metadata.truncate(38);
    let mut reported = None;
    let result =
        start_raw_ir_burst("fixture", &mut stream, || true, |window| reported = Some(window));
    assert!(result.is_err(), "the second recheck dequeue finds no frame");
    assert_eq!(stream.accounting().0, 38);
    let refused = reported.expect("the replaced window is reported before the failure");
    assert_eq!(refused.window_span_us, 2_088_113);
}

// The whole raw burst, startup and deliveries, the way
// `capture_raw_burst_with_startup` drives it: what it reports and delivers,
// in order.
#[derive(Debug, PartialEq, Eq)]
enum RawBurstEvent {
    FirstWindowRefused(u64),
    AcceptedAfterRecheck(u64, bool),
    Delivered(u32),
}

fn record_raw_burst(
    stream: &mut TrackedStream<QueuedContinuityFixture>,
    frames: usize,
    measured_profile: impl FnOnce() -> bool,
) -> (irlume_common::Result<Vec<u32>>, Vec<RawBurstEvent>) {
    let events = std::cell::RefCell::new(Vec::new());
    let result = run_raw_ir_burst(
        "fixture",
        stream,
        frames,
        measured_profile,
        |report| {
            events.borrow_mut().push(match report {
                StartupRecheckReport::FirstWindowRefused(window) => {
                    RawBurstEvent::FirstWindowRefused(window.window_span_us)
                }
                StartupRecheckReport::AcceptedAfterRecheck(evidence) => {
                    RawBurstEvent::AcceptedAfterRecheck(
                        evidence.window_span_us(),
                        evidence.meets_floor(),
                    )
                }
            });
        },
        |_, facts, _, _, _| {
            events
                .borrow_mut()
                .push(RawBurstEvent::Delivered(facts.sequence_raw()));
            Ok(facts.sequence_raw())
        },
    );
    (result, events.into_inner())
}

#[test]
fn raw_burst_reports_the_accepted_window_before_the_first_frame_is_used() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let (result, events) = record_raw_burst(&mut stream, 3, || true);
    assert_eq!(result.unwrap(), [41, 42, 43]);
    assert_eq!(
        events,
        [
            RawBurstEvent::FirstWindowRefused(2_088_113),
            RawBurstEvent::AcceptedAfterRecheck(2_028_086, true),
            RawBurstEvent::Delivered(41),
            RawBurstEvent::Delivered(42),
            RawBurstEvent::Delivered(43),
        ]
    );
}

#[test]
fn raw_burst_reports_the_accepted_window_before_a_later_window_misses() {
    // A 140 ms stall after frame 41: the window that admitted frame 41
    // passes, the one at frame 42 does not.
    let mut deltas = FIRST_IR_SESSION_US;
    deltas[40] = 140_000;
    let mut stream = ir_startup_timing_fixture(&deltas);
    let (result, events) = record_raw_burst(&mut stream, 3, || true);
    let Err(Error::DeliveredRate(evidence)) = result else {
        panic!("the window at frame 42 must get a typed rate refusal");
    };
    assert_eq!(evidence.window_span_us, 2_028_086 - 67_874 + 140_000);
    assert_eq!(
        events,
        [
            RawBurstEvent::FirstWindowRefused(2_088_113),
            RawBurstEvent::AcceptedAfterRecheck(2_028_086, true),
            RawBurstEvent::Delivered(41),
        ]
    );
}

#[test]
fn raw_burst_refused_at_the_recheck_window_reports_no_accepted_window() {
    let mut stream = ir_startup_timing_fixture(&[71_429; 42]);
    let (result, events) = record_raw_burst(&mut stream, 3, || true);
    let Err(Error::DeliveredRate(evidence)) = result else {
        panic!("a stream that stays below its floor must get a typed rate refusal");
    };
    assert_eq!(evidence.window_span_us, 30 * 71_429);
    assert_eq!(events, [RawBurstEvent::FirstWindowRefused(30 * 71_429)]);
}

#[test]
fn raw_burst_without_a_recheck_delivers_without_reports() {
    let mut stream = ir_startup_timing_fixture(&SECOND_IR_SESSION_US);
    let (result, events) = record_raw_burst(&mut stream, 3, || {
        panic!("healthy startup must not check the profile")
    });
    assert_eq!(result.unwrap(), [38, 39, 40]);
    assert_eq!(
        events,
        [
            RawBurstEvent::Delivered(38),
            RawBurstEvent::Delivered(39),
            RawBurstEvent::Delivered(40),
        ]
    );
}

#[test]
fn raw_burst_of_zero_frames_dequeues_nothing() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let (result, events) = record_raw_burst(&mut stream, 0, || panic!("nothing to deliver"));
    assert!(result.unwrap().is_empty());
    assert!(events.is_empty());
    assert_eq!(stream.accounting().0, 0);
}
