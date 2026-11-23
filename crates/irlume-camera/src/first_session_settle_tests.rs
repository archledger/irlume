// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// First 42 driver timestamp deltas in the two 2026-11-22 NexiGo N930W
// probe sessions. These are relative timings only; no image is used.
const FIRST_IR_SESSION_US: [i64; 42] = [
    432_010, 68_003, 67_987, 68_020, 80_010, 83_990, 88_063, 95_945, 80_003, 64_022, 67_874,
    67_949, 68_159, 68_030, 67_986, 67_996, 64_025, 68_002, 67_998, 68_010, 68_006, 67_998,
    71_998, 64_011, 67_991, 68_009, 67_887, 68_115, 68_006, 67_996, 64_014, 67_999, 68_011,
    67_998, 67_999, 68_013, 68_071, 63_994, 67_900, 68_041, 67_983, 67_841,
];
const SECOND_IR_SESSION_US: [i64; 42] = [
    164_029, 67_807, 68_221, 71_967, 72_088, 71_809, 68_118, 68_008, 67_992, 67_985, 68_000,
    64_045, 67_993, 67_989, 67_996, 68_032, 67_977, 67_975, 64_052, 67_993, 67_898, 72_115,
    67_988, 67_902, 68_027, 64_094, 68_004, 67_870, 68_141, 67_996, 68_071, 67_888, 64_046,
    68_006, 68_012, 67_882, 68_121, 67_990, 67_907, 64_011, 68_100, 67_874,
];

fn ir_startup_timing_fixture(deltas: &[i64; 42]) -> TrackedStream<QueuedContinuityFixture> {
    let mut stream = rate_fill_fixture(contracts::StreamRole::Ir, 43, 66_667);
    let interval = frame_interval::FrameInterval::new(1, 30).unwrap();
    stream.rate_config =
        rate_gate::StreamRateConfig::new(contracts::StreamRole::Ir, interval, interval);
    let mut micros = 1_000_000;
    let metadata = &mut stream.stream_mut().unwrap().metadata;
    metadata[0].timestamp = v4l::timestamp::Timestamp::new(1, 0);
    for (frame, delta) in metadata.iter_mut().skip(1).zip(deltas) {
        micros += delta;
        frame.timestamp = v4l::timestamp::Timestamp::new(micros / 1_000_000, micros % 1_000_000);
    }
    stream
}

#[test]
fn first_session_settle_fixed_startup_delivers_on_the_measured_first_session() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let startup = IrSessionStartup::Fixed;
    startup
        .warm_up("fixture", &mut stream, &no_progress())
        .unwrap();
    startup.fill_with_recheck(&mut stream, || true).unwrap();
    assert_eq!(stream.accounting().0, 40);
    // Calling the fill again cannot recheck another window in this session.
    startup
        .fill_with_recheck(&mut stream, || panic!("already filled"))
        .unwrap();
    let (_, frame, _, _, evidence) = stream.next().unwrap();
    assert_eq!(frame.sequence_raw(), 41);
    assert_eq!(evidence.window_count(), 30);
    assert_eq!(evidence.window_span_us(), 2_028_086);
}

#[test]
fn first_session_settle_recheck_does_not_admit_a_uniformly_slow_stream() {
    let mut stream = ir_startup_timing_fixture(&[71_429; 42]);
    let startup = IrSessionStartup::Fixed;
    startup
        .warm_up("fixture", &mut stream, &no_progress())
        .unwrap();
    startup.fill_with_recheck(&mut stream, || true).unwrap();
    assert_eq!(stream.accounting().0, 40);
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("a uniformly slow IR stream must get a typed rate refusal");
    };
    assert_eq!(evidence.window_count, 30);
    assert_eq!(evidence.floor_num, 15);
    assert_eq!(evidence.tolerance_percent, 97);
    assert_eq!(evidence.window_span_us, 30 * 71_429);
    assert!(!evidence.meets_floor);
}

#[test]
fn first_session_settle_unrecognized_profile_gets_the_original_typed_refusal() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let startup = IrSessionStartup::Fixed;
    startup
        .warm_up("fixture", &mut stream, &no_progress())
        .unwrap();
    startup.fill_with_recheck(&mut stream, || false).unwrap();
    assert_eq!(stream.accounting().0, 37);
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("unknown profiles must not get a startup recheck");
    };
    assert_eq!(evidence.window_span_us, 2_068_121);
}

#[test]
fn first_session_settle_fixed_startup_delivers_at_the_original_offset_on_the_measured_second_session() {
    let mut stream = ir_startup_timing_fixture(&SECOND_IR_SESSION_US);
    let startup = IrSessionStartup::Fixed;
    startup
        .warm_up("fixture", &mut stream, &no_progress())
        .unwrap();
    startup
        .fill_with_recheck(&mut stream, || panic!("healthy startup must not check the profile"))
        .unwrap();
    let (_, frame, _, _, evidence) = stream.next().unwrap();
    assert_eq!(frame.sequence_raw(), 38);
    assert_eq!(evidence.window_count(), 30);
    assert_eq!(evidence.window_span_us(), 2_028_098);
}

#[test]
fn first_session_settle_a_startup_sequence_gap_does_not_get_a_recheck() {
    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    for frame in stream.stream_mut().unwrap().metadata.iter_mut().skip(9) {
        frame.sequence += 1;
    }
    let startup = IrSessionStartup::Fixed;
    startup
        .warm_up("fixture", &mut stream, &no_progress())
        .unwrap();
    startup
        .fill_with_recheck(&mut stream, || panic!("startup had a sequence gap"))
        .unwrap();
    let Err(DeliveryError::BelowFloor(evidence)) = stream.next() else {
        panic!("expected the original rate refusal");
    };
    assert_eq!(evidence.cumulative_drops, 1);
}

#[test]
fn first_session_settle_recheck_honors_cancellation_before_dequeue() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut stream = ir_startup_timing_fixture(&FIRST_IR_SESSION_US);
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let signal = std::sync::Arc::clone(&cancelled);
    stream.control =
        CaptureControl::new(no_progress(), std::sync::Arc::new(move || signal.load(Ordering::Acquire)));
    let startup = IrSessionStartup::Fixed;
    startup
        .warm_up("fixture", &mut stream, &no_progress())
        .unwrap();
    let error = startup
        .fill_with_recheck(&mut stream, || {
            cancelled.store(true, Ordering::Release);
            true
        })
        .unwrap_err();
    assert!(capture_control::is_cancelled(&error));
    assert_eq!(stream.accounting().0, 37);
}

#[test]
fn first_session_settle_recheck_matches_only_the_measured_contract() {
    let grey = v4l::Format::new(640, 360, FourCC::new(b"GREY"));
    let fps30 = frame_interval::FrameInterval::new(1, 30).unwrap();
    let fps15 = frame_interval::FrameInterval::new(1, 15).unwrap();
    assert!(nexigo_ir_recheck_contract(&grey, fps30, fps30));
    assert!(!nexigo_ir_recheck_contract(&grey, fps15, fps30));
    assert!(!nexigo_ir_recheck_contract(&grey, fps30, fps15));
    for other in [
        v4l::Format::new(640, 360, FourCC::new(b"YUYV")),
        v4l::Format::new(640, 480, FourCC::new(b"GREY")),
    ] {
        assert!(!nexigo_ir_recheck_contract(&other, fps30, fps30));
    }
}

#[test]
fn first_session_settle_recheck_matches_only_the_recorded_usb_endpoint_and_link() {
    let context = || uvc_descriptor::FdCameraContext {
        identity: uvc_descriptor::CameraIdentity {
            vid: 0x3443,
            pid: 0xc803,
            active_configuration: 1,
            interface_number: 2,
            descriptors: include_bytes!("../tests/fixtures/nexigo-3443-c803.descriptors").to_vec(),
            serial: None,
            usb_devpath: "/devices/usb1/1-3.1".to_owned(),
        },
        connection: uvc_descriptor::UsbConnectionFacts {
            controller_devpath: "/devices/controller".to_owned(),
            speed_millimbps: 480_000,
            driver: "uvcvideo".to_owned(),
        },
    };
    assert!(nexigo_ir_recheck_endpoint(&context()));
    for alter in [
        (|facts: &mut uvc_descriptor::FdCameraContext| facts.identity.pid = 0x930d)
            as fn(&mut uvc_descriptor::FdCameraContext),
        |facts| facts.identity.vid = 0x046d,
        |facts| facts.identity.interface_number = 0,
        |facts| facts.identity.active_configuration = 2,
        |facts| facts.identity.descriptors[12] ^= 1,
        |facts| facts.connection.speed_millimbps = 5_000_000,
        |facts| facts.connection.driver = "v4l2loopback".to_owned(),
    ] {
        let mut facts = context();
        alter(&mut facts);
        assert!(!nexigo_ir_recheck_endpoint(&facts));
    }
}
