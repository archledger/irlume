// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#[test]
fn probe_bounds_corrupt_single_stream_does_not_drain_every_buffer() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let node = "/dev/video-bounded-single-test";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    let mut stream =
        rate_fill_fixture(contracts::StreamRole::Rgb, 256, 200_000).with_rate_amortization(node);
    for metadata in stream.stream_mut().unwrap().metadata.iter_mut().skip(6) {
        metadata.flags |= v4l::buffer::Flags::ERROR;
    }
    let result = stream.fill_rate_evidence();
    let cached = rate_amortization::amortizable(&key);
    rate_amortization::test_support::force_completion(key, None);
    assert!(result.is_err());
    assert!(
        stream.observations <= (2 * MAX_RATE_FILL_ATTEMPTS) as u64,
        "consumed {} observations, exceeding probe plus fill",
        stream.observations
    );
    assert!(!cached, "failed evidence must not remain reusable");
}

#[test]
fn probe_bounds_corrupt_paired_stream_does_not_drain_every_buffer() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let node = "/dev/video-bounded-paired-test";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    let mut stream =
        rate_fill_fixture(contracts::StreamRole::Rgb, 256, 200_000).with_rate_amortization(node);
    for metadata in stream.stream_mut().unwrap().metadata.iter_mut().skip(6) {
        metadata.flags |= v4l::buffer::Flags::ERROR;
    }
    let result = drain_until_both_ready(
        &mut stream,
        &std::sync::atomic::AtomicUsize::new(0),
        &std::sync::atomic::AtomicBool::new(false),
        &mut 0,
    );
    let cached = rate_amortization::amortizable(&key);
    rate_amortization::test_support::force_completion(key, None);
    assert!(result.is_err());
    assert!(
        stream.observations <= (3 * MAX_RATE_FILL_ATTEMPTS) as u64,
        "consumed {} observations, exceeding probe plus paired fill",
        stream.observations
    );
    assert!(!cached, "failed evidence must not remain reusable");
}

#[test]
fn probe_bounds_healthy_single_stream_still_admits() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let node = "/dev/video-bounded-single-control";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    let mut stream =
        rate_fill_fixture(contracts::StreamRole::Rgb, 120, 30_000).with_rate_amortization(node);
    let result = stream.fill_rate_evidence();
    rate_amortization::test_support::force_completion(key, None);
    result.unwrap();
    assert!(stream.health_admitted);
    assert!(stream.observations < MAX_RATE_FILL_ATTEMPTS as u64);
}

#[test]
fn probe_bounds_healthy_paired_stream_still_admits() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let node = "/dev/video-bounded-paired-control";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    let mut stream =
        rate_fill_fixture(contracts::StreamRole::Rgb, 120, 30_000).with_rate_amortization(node);
    let ready = std::sync::atomic::AtomicUsize::new(1);
    let result = drain_until_both_ready(
        &mut stream,
        &ready,
        &std::sync::atomic::AtomicBool::new(false),
        &mut 0,
    );
    rate_amortization::test_support::force_completion(key, None);
    result.unwrap();
    assert!(stream.health_admitted);
    assert_eq!(ready.load(std::sync::atomic::Ordering::Acquire), 2);
    assert!(stream.observations < MAX_RATE_FILL_ATTEMPTS as u64);
}

fn probe_bounds_escalating_stream(node: &str) -> TrackedStream<QueuedContinuityFixture> {
    let mut stream =
        rate_fill_fixture(contracts::StreamRole::Rgb, 64, 20_000).with_rate_amortization(node);
    let mut first = rate_gate::RateWindow::new();
    for (i, metadata) in stream.stream_mut().unwrap().metadata.iter_mut().enumerate() {
        let micros = if i <= 5 {
            1_000_000 + i as i64 * 200_000
        } else {
            2_000_000 + (i as i64 - 5) * 20_000
        };
        metadata.timestamp = v4l::timestamp::Timestamp::new(micros / 1_000_000, micros % 1_000_000);
        if i <= 5 {
            first.observe_success(micros).unwrap();
        }
    }
    let policy = stream.rate_config.policy();
    assert_eq!(first.count(), rate_amortization::CONTINUITY_PROBE_DELTAS);
    assert!(!first.meets_floor(
        policy.floor_num(),
        policy.floor_den(),
        policy.tolerance_percent()
    ));
    stream
}

#[test]
fn probe_bounds_single_stream_can_recover_during_escalation() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let node = "/dev/video-escalating-single-control";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    let mut stream = probe_bounds_escalating_stream(node);
    let result = stream.fill_rate_evidence();
    rate_amortization::test_support::force_completion(key, None);
    result.unwrap();
    assert!(stream.health_admitted);
    assert!(stream.rate_window.count() > rate_amortization::CONTINUITY_PROBE_DELTAS);
    assert!(stream.rate_window.count() <= rate_amortization::CONTINUITY_PROBE_ESCALATED_DELTAS);
}

#[test]
fn probe_bounds_paired_stream_can_recover_during_escalation() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let node = "/dev/video-escalating-paired-control";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    let mut stream = probe_bounds_escalating_stream(node);
    let ready = std::sync::atomic::AtomicUsize::new(1);
    let result = drain_until_both_ready(
        &mut stream,
        &ready,
        &std::sync::atomic::AtomicBool::new(false),
        &mut 0,
    );
    rate_amortization::test_support::force_completion(key, None);
    result.unwrap();
    assert!(stream.health_admitted);
    assert_eq!(ready.load(std::sync::atomic::Ordering::Acquire), 2);
    assert!(stream.rate_window.count() > rate_amortization::CONTINUITY_PROBE_DELTAS);
    assert!(stream.rate_window.count() <= rate_amortization::CONTINUITY_PROBE_ESCALATED_DELTAS);
}
