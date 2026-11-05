// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Pin the cold-establishment counts used by validate-slice4-hardware.py.
// Single-fill fixtures are cold; the concurrent IR sequence starts cold and
// explicitly exercises its newly cached completion before recovery.
#[test]
fn native_validator_rgb_single_fill_includes_warmup() {
    assert_eq!(rate_gate::RATE_WINDOW_CAPACITY, 30);
    assert_eq!(2 * (1 + AE_WARMUP), 14);
    let mut rgb = rate_fill_fixture(contracts::StreamRole::Rgb, 64, 66_667);
    for _ in 0..1 + AE_WARMUP {
        rgb.next_discarded().unwrap();
    }
    rgb.fill_rate_evidence().unwrap();
    assert_eq!(rgb.accounting().1, 31);
    assert_eq!(2 * rgb.accounting().1, 62);
}

#[test]
fn native_validator_rgb_paired_fill_excludes_warmup() {
    let mut rgb = rate_fill_fixture(contracts::StreamRole::Rgb, 64, 66_667);
    for _ in 0..1 + AE_WARMUP {
        rgb.next_discarded().unwrap();
    }
    let ready = std::sync::atomic::AtomicUsize::new(1);
    drain_until_both_ready(
        &mut rgb,
        &ready,
        &std::sync::atomic::AtomicBool::new(false),
        &mut 0,
    )
    .unwrap();
    assert_eq!(rgb.accounting().1, 38);
    assert_eq!(2 * rgb.accounting().1, 76);
}

#[test]
fn native_validator_ir_fill_pays_five_frame_flush() {
    assert_eq!(rate_gate::startup_flush(contracts::StreamRole::Ir), 5);
    let mut ir = rate_fill_fixture(contracts::StreamRole::Ir, 64, 66_667);
    ir.fill_rate_evidence().unwrap();
    assert_eq!(ir.accounting().1, 36);
    // IR warms once at session creation, not again after recovery.
    assert_eq!(1 + 2 * ir.accounting().1, 73);
}

#[test]
fn native_validator_concurrent_ir_includes_initial_session_fill() {
    let _lock = crate::testenv::env_lock();
    for reuse in [true, false] {
        let _env = if reuse {
            crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION")
        } else {
            crate::testenv::EnvGuard::set("IRLUME_RATE_AMORTIZATION", "0")
        };
        let node = "/dev/video-native-validator-concurrent-ir";
        let key = rate_amortization::Key::new(node, contracts::StreamRole::Ir);
        rate_amortization::test_support::force_completion(key.clone(), None);
        let mut ir =
            rate_fill_fixture(contracts::StreamRole::Ir, 96, 66_667).with_rate_amortization(node);
        IrSessionStartup::Fixed
            .warm_up(node, &mut ir, &no_progress())
            .unwrap();
        IrSessionStartup::Fixed.fill(&mut ir).unwrap();
        assert_eq!(ir.accounting().1, 37);

        let ready = std::sync::atomic::AtomicUsize::new(1);
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        drain_until_both_ready(&mut ir, &ready, &cancelled, &mut 0).unwrap();
        assert_eq!(ir.accounting().1, if reuse { 48 } else { 73 });
        assert_eq!(ir.health_admitted, reuse);

        ir.take();
        let mut replacement = rate_fill_fixture(contracts::StreamRole::Ir, 64, 66_667).take();
        ir.install_recovered(&mut replacement).unwrap();
        assert!(rate_amortization::test_support::completion_instant(&key).is_none());
        ready.store(1, std::sync::atomic::Ordering::Release);
        drain_until_both_ready(&mut ir, &ready, &cancelled, &mut 0).unwrap();
        assert_eq!(ir.accounting().1, if reuse { 84 } else { 109 });
        rate_amortization::test_support::force_completion(key, None);
    }
}
