// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! NPU tests of the `onnx` module (ADR-0022): enrollment on CPU, the
//! CPU reference fingerprint, and the ignored hardware measurements.
//! A child of `onnx`, so the tests can place a model on the NPU directly.

use super::*;

mod npu_enrollment_tests {
    use super::*;

    /// An "NPU" that answers a constant embedding, so where an answer
    /// came from is visible.
    struct Constant;

    impl crate::npu::Infer for Constant {
        fn infer(&mut self, _input: &[f32]) -> Result<Vec<f32>, String> {
            Ok(vec![1.0; EMBED_DIM])
        }
    }

    /// The digest [`Constant`] gives for the reference inputs.
    fn constant_digest() -> String {
        let bits: Vec<u8> = (0..3)
            .flat_map(|_| vec![1.0f32; EMBED_DIM])
            .flat_map(f32::to_le_bytes)
            .collect();
        irlume_common::sha256_hex(&bits)
    }

    fn test_entry(
        bytes: &[u8],
        cpu_reference_digest: String,
        npu_reference_digest: String,
    ) -> &'static crate::npu::Certification {
        Box::leak(Box::new(crate::npu::Certification {
            model_sha256: "test",
            role: crate::npu::Role::Recognizer,
            identity_digest: "test",
            onnx_runtime: "test",
            thresholds: &[],
            decision_fingerprint: "test",
            fingerprint: Box::leak(
                npu_reference_fingerprint(crate::npu::Role::Recognizer, bytes)
                    .unwrap()
                    .into_boxed_slice(),
            ),
            cpu_reference_digest: Box::leak(cpu_reference_digest.into_boxed_str()),
            npu_reference_digest: Box::leak(npu_reference_digest.into_boxed_str()),
            evidence: "test",
        }))
    }

    /// An "NPU" that answers [`Constant`]'s output until `changed` is set,
    /// then another one, as a resumed device returning other bits would.
    struct Changing {
        changed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::npu::Infer for Changing {
        fn infer(&mut self, _input: &[f32]) -> Result<Vec<f32>, String> {
            let changed = self.changed.load(std::sync::atomic::Ordering::SeqCst);
            Ok(vec![if changed { 2.0 } else { 1.0 }; EMBED_DIM])
        }
    }

    /// An "NPU" during whose next inference the system suspends, returning
    /// [`Constant`]'s output or, once `changed` is set, another one.
    struct SuspendsDuring {
        suspend: std::sync::Arc<std::sync::atomic::AtomicBool>,
        changed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::npu::Infer for SuspendsDuring {
        fn infer(&mut self, _input: &[f32]) -> Result<Vec<f32>, String> {
            use std::sync::atomic::Ordering::SeqCst;
            if self.suspend.swap(false, SeqCst) {
                crate::npu::simulate_suspend(std::time::Duration::from_secs(2));
            }
            let changed = self.changed.load(SeqCst);
            Ok(vec![if changed { 2.0 } else { 1.0 }; EMBED_DIM])
        }
    }

    /// A suspend during an NPU inference discards its output: the digest is
    /// checked again and that call is computed on CPU (ADR-0022 §8).
    #[test]
    fn an_inference_that_spans_a_suspend_is_not_used() {
        use std::sync::atomic::Ordering::SeqCst;
        let path = format!("{}/../../models/glintr100.onnx", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("models/glintr100.onnx (scripts/fetch-models.sh)");
        let mut cpu = Embedder::load_from_memory(&bytes).unwrap();
        let suspend = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut embedder = Embedder {
            session: build(&bytes).unwrap(),
            npu: crate::npu::Slot::certified(
                Box::new(SuspendsDuring {
                    suspend: suspend.clone(),
                    changed: changed.clone(),
                }),
                test_entry(
                    &bytes,
                    cpu.cpu_reference_digest().unwrap(),
                    constant_digest(),
                ),
            ),
        };
        embedder.check_npu_parity().unwrap();
        assert_eq!(embedder.npu_device(), crate::npu::Device::Npu);
        let chip = npu_reference::chip(1);
        let (expected, _) = cpu.embed_preprocessed_with_norm(&chip).unwrap();
        let from_cpu = |answer: &Embedding| {
            answer
                .iter()
                .zip(&expected)
                .all(|(a, b)| a.to_bits() == b.to_bits())
        };

        // Same bits after the suspend: the recheck passes and the model
        // stays on the NPU, but this call's answer comes from CPU.
        suspend.store(true, SeqCst);
        let (answer, _) = embedder.embed_preprocessed_with_norm(&chip).unwrap();
        assert!(
            from_cpu(&answer),
            "the output that spanned a suspend was used"
        );
        assert_eq!(embedder.npu_device(), crate::npu::Device::Npu);
        assert!(!embedder.npu.resumed_since_check());
        let (answer, _) = embedder.embed_preprocessed_with_norm(&chip).unwrap();
        assert!(!from_cpu(&answer), "the next call answers from the NPU");

        // Other bits after the suspend: retired to CPU.
        suspend.store(true, SeqCst);
        changed.store(true, SeqCst);
        let (answer, _) = embedder.embed_preprocessed_with_norm(&chip).unwrap();
        assert!(from_cpu(&answer));
        assert!(
            matches!(
                embedder.npu_device(),
                crate::npu::Device::Cpu(crate::npu::CpuReason::ParityMismatch(ref why))
                    if why.starts_with("after a system resume")
            ),
            "{:?}",
            embedder.npu_device()
        );
    }

    /// A suspend during the parity check itself leaves the next call to
    /// check again: the baseline is read before the first reference
    /// inference.
    #[test]
    fn a_suspend_during_the_parity_check_is_seen() {
        use std::sync::atomic::Ordering::SeqCst;
        let path = format!("{}/../../models/glintr100.onnx", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("models/glintr100.onnx (scripts/fetch-models.sh)");
        let mut cpu = Embedder::load_from_memory(&bytes).unwrap();
        let suspend = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut embedder = Embedder {
            session: build(&bytes).unwrap(),
            npu: crate::npu::Slot::certified(
                Box::new(SuspendsDuring {
                    suspend: suspend.clone(),
                    changed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                }),
                test_entry(
                    &bytes,
                    cpu.cpu_reference_digest().unwrap(),
                    constant_digest(),
                ),
            ),
        };
        embedder.check_npu_parity().unwrap();
        assert!(
            !suspend.load(SeqCst),
            "the suspend happened inside the check"
        );
        assert_eq!(embedder.npu_device(), crate::npu::Device::Npu);
        assert!(
            embedder.npu.resumed_since_check(),
            "the suspend inside the check is not hidden by its baseline"
        );
        embedder
            .embed_preprocessed_with_norm(&npu_reference::chip(1))
            .unwrap();
        assert!(!embedder.npu.resumed_since_check());
    }

    /// An "NPU" whose second inference fails.
    struct FailsSecond {
        calls: usize,
    }

    impl crate::npu::Infer for FailsSecond {
        fn infer(&mut self, _input: &[f32]) -> Result<Vec<f32>, String> {
            self.calls += 1;
            if self.calls == 2 {
                return Err("injected failure".into());
            }
            Ok(vec![1.0; EMBED_DIM])
        }
    }

    /// A TTA embedding is whole on one device: when the flipped half fails
    /// on the NPU, both halves are computed on CPU.
    #[test]
    fn a_tta_embedding_is_never_mixed() {
        let path = format!("{}/../../models/glintr100.onnx", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("models/glintr100.onnx (scripts/fetch-models.sh)");
        let mut cpu = Embedder::load_from_memory(&bytes).unwrap();
        let mut embedder = Embedder {
            session: build(&bytes).unwrap(),
            npu: crate::npu::Slot::npu(Box::new(FailsSecond { calls: 0 })),
        };
        let n = align::OUT_SIZE as usize;
        let chip: Vec<u8> = (0..n * n * 3).map(|i| (i * 17 % 253) as u8).collect();
        let answer = embedder.embed_tta(&chip).unwrap();
        assert!(matches!(
            embedder.npu_device(),
            crate::npu::Device::Cpu(crate::npu::CpuReason::Retired(_))
        ));
        let expected = cpu.embed_tta(&chip).unwrap();
        assert!(
            answer
                .iter()
                .zip(&expected)
                .all(|(a, b)| a.to_bits() == b.to_bits()),
            "both halves came from CPU"
        );
    }

    /// After a system resume the NPU must reproduce its reference digest
    /// again before it answers (ADR-0022 §8); between resumes it is not
    /// rechecked.
    #[test]
    fn a_resumed_npu_reproduces_its_digest_before_it_answers() {
        let path = format!("{}/../../models/glintr100.onnx", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("models/glintr100.onnx (scripts/fetch-models.sh)");
        let mut cpu = Embedder::load_from_memory(&bytes).unwrap();
        let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut embedder = Embedder {
            session: build(&bytes).unwrap(),
            npu: crate::npu::Slot::certified(
                Box::new(Changing {
                    changed: changed.clone(),
                }),
                test_entry(
                    &bytes,
                    cpu.cpu_reference_digest().unwrap(),
                    constant_digest(),
                ),
            ),
        };
        embedder.check_npu_parity().unwrap();
        assert_eq!(embedder.npu_device(), crate::npu::Device::Npu);
        assert!(!embedder.npu.resumed_since_check());
        let chip = npu_reference::chip(1);

        // No resume: the NPU answers without a new check, whatever it
        // returns (a change here is the per-call fallback's business).
        changed.store(true, std::sync::atomic::Ordering::SeqCst);
        let (answer, _) = embedder.embed_preprocessed_with_norm(&chip).unwrap();
        let two = 1.0 / (EMBED_DIM as f32).sqrt();
        assert!(answer.iter().all(|v| (v - two).abs() < 1e-6));
        assert_eq!(embedder.npu_device(), crate::npu::Device::Npu);

        // A resume with unchanged bits: rechecked, still on the NPU.
        changed.store(false, std::sync::atomic::Ordering::SeqCst);
        embedder.npu.forget_check();
        assert!(embedder.npu.resumed_since_check());
        embedder.embed_preprocessed_with_norm(&chip).unwrap();
        assert_eq!(embedder.npu_device(), crate::npu::Device::Npu);
        assert!(
            !embedder.npu.resumed_since_check(),
            "the recheck is recorded"
        );

        // A resume after which the NPU returns other bits: retired to CPU
        // before it answers, and this call is computed on CPU.
        changed.store(true, std::sync::atomic::Ordering::SeqCst);
        embedder.npu.forget_check();
        let (answer, _) = embedder.embed_preprocessed_with_norm(&chip).unwrap();
        assert!(
            matches!(
                embedder.npu_device(),
                crate::npu::Device::Cpu(crate::npu::CpuReason::ParityMismatch(ref why))
                    if why.starts_with("after a system resume")
            ),
            "{:?}",
            embedder.npu_device()
        );
        let (expected, _) = cpu.embed_preprocessed_with_norm(&chip).unwrap();
        assert!(answer
            .iter()
            .zip(&expected)
            .all(|(a, b)| a.to_bits() == b.to_bits()));
    }

    /// Enrollment embeds on CPU even with the recognizer on the NPU
    /// (ADR-0022 §2), and an authentication probe goes to the NPU.
    #[test]
    fn the_cpu_view_never_asks_the_npu() {
        let path = format!("{}/../../models/glintr100.onnx", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("models/glintr100.onnx (scripts/fetch-models.sh)");
        let mut reference = Embedder::load_from_memory(&bytes).unwrap();
        let mut placed = Embedder {
            session: build(&bytes).unwrap(),
            npu: crate::npu::Slot::npu(Box::new(Constant)),
        };
        let n = align::OUT_SIZE as usize;
        let chip: Vec<u8> = (0..n * n * 3).map(|i| (i * 31 % 251) as u8).collect();

        let cpu = reference.embed(&chip).unwrap();
        let viewed = placed.on_cpu().embed(&chip).unwrap();
        assert!(cpu
            .iter()
            .zip(&viewed)
            .all(|(a, b)| a.to_bits() == b.to_bits()));
        let tta = placed.on_cpu().embed_tta(&chip).unwrap();
        let reference_tta = reference.embed_tta(&chip).unwrap();
        assert!(tta
            .iter()
            .zip(&reference_tta)
            .all(|(a, b)| a.to_bits() == b.to_bits()));

        let probe = placed.embed(&chip).unwrap();
        assert_eq!(placed.npu_device(), crate::npu::Device::Npu);
        // With the CPU digest reproduced, an NPU that does not reproduce
        // its certified reference digest fails the parity check; so does a
        // CPU session that does not reproduce its digest bit for bit.
        // Either leaves the model on CPU before it answers any request.
        let cpu_digest = Embedder::load_from_memory(&bytes)
            .unwrap()
            .cpu_reference_digest()
            .unwrap();
        for (cpu_digest, npu_digest, what) in [
            (
                cpu_digest.clone(),
                "not the constant's digest".to_owned(),
                "reference output",
            ),
            (
                "not the CPU digest".to_owned(),
                constant_digest(),
                "CPU reference",
            ),
        ] {
            let mut checked = Embedder {
                session: build(&bytes).unwrap(),
                npu: crate::npu::Slot::certified(
                    Box::new(Constant),
                    test_entry(&bytes, cpu_digest, npu_digest),
                ),
            };
            checked.check_npu_parity().unwrap();
            assert!(
                matches!(
                    checked.npu_device(),
                    crate::npu::Device::Cpu(crate::npu::CpuReason::ParityMismatch(ref why))
                        if why.starts_with(what)
                ),
                "{what}: {:?}",
                checked.npu_device()
            );
        }
        // Both reproduced: the model answers from the NPU.
        let mut passing = Embedder {
            session: build(&bytes).unwrap(),
            npu: crate::npu::Slot::certified(
                Box::new(Constant),
                test_entry(&bytes, cpu_digest, constant_digest()),
            ),
        };
        passing.check_npu_parity().unwrap();
        assert_eq!(passing.npu_device(), crate::npu::Device::Npu);
        let constant = 1.0 / (EMBED_DIM as f32).sqrt();
        assert!(
            probe.iter().all(|v| (v - constant).abs() < 1e-6),
            "the probe came from the NPU"
        );
        let certified_probe = passing.embed(&chip).unwrap();
        assert!(
            certified_probe.iter().all(|v| (v - constant).abs() < 1e-6),
            "the certified embedder answered from the NPU"
        );
        assert_eq!(passing.npu_device(), crate::npu::Device::Npu);
        assert_eq!(placed.npu_device(), crate::npu::Device::Npu);
    }
}

mod npu_reference_tests {
    use super::*;

    /// Every certified entry still describes the current CPU reference:
    /// a change to preprocessing, decoding or the ONNX Runtime output
    /// moves the fingerprint, and the entry must be certified again or
    /// removed (ADR-0022 §3). The thresholds an entry records are pinned
    /// where the constants live, in `irlume-auth`.
    #[test]
    fn certified_entries_match_their_cpu_reference() {
        let models = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models");
        for entry in crate::npu::CERTIFIED {
            assert!(!entry.onnx_runtime.is_empty() && !entry.evidence.is_empty());
            let path = std::fs::read_dir(&models)
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|path| {
                    std::fs::read(path)
                        .is_ok_and(|bytes| irlume_common::sha256_hex(&bytes) == entry.model_sha256)
                })
                .unwrap_or_else(|| panic!("no model with digest {}", entry.model_sha256));
            let bytes = std::fs::read(path).unwrap();
            let now = npu_reference_fingerprint(entry.role, &bytes).unwrap();
            assert_eq!(now.len(), entry.fingerprint.len(), "{}", entry.model_sha256);
            for (now, then) in now.iter().zip(entry.fingerprint) {
                assert!(
                    (now - then).abs() <= npu_reference::FINGERPRINT_TOLERANCE,
                    "{}: {now} vs {then}",
                    entry.model_sha256
                );
            }
        }
    }

    #[test]
    fn the_reference_inputs_are_fixed() {
        // The fingerprint means nothing if its inputs drift: both are
        // pinned by digest (computed independently, little-endian f32
        // for the chip).
        let chip = npu_reference::chip(0);
        let bytes: Vec<u8> = chip.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            irlume_common::sha256_hex(&bytes),
            "9a91f1f7135fdea10c61809da8f2142738d7286de12f7caff66ddb76a1384293"
        );
        let raw = npu_reference::raw_chip();
        assert_eq!(
            irlume_common::sha256_hex(&raw),
            "6ca09bfb23b07c6e1614b1a47d8836cc029e45c820cbca8d0ea6bdabe4ca495b"
        );
        let (frame, w, h) = npu_reference::frame();
        assert_eq!((w, h), (640, 480));
        assert_eq!(
            irlume_common::sha256_hex(&frame),
            "7ccd41f090cf5d0444b7e236725873e1cf3e06895b56c437d2b894e47667c850"
        );
    }
}

/// The models on a real NPU, through the same struct paths production
/// uses, against their ONNX Runtime CPU sessions. Placement bypasses
/// [`crate::npu::CERTIFIED`] on purpose: this is the evidence a
/// certification starts from, not a certification. Run on a Lunar Lake
/// host with the 2026.2.0 stack and core dumps off:
/// `ulimit -c 0; cargo test -p irlume-vision --features npu --release --lib -- --ignored npu_hw_ --test-threads 1 --nocapture`
/// (`IRLUME_NPU_TEST_MODELS` overrides `/usr/share/irlume/models`;
/// `IRLUME_NPU_EVAL_DIR` names the recorded evaluation frames). As a
/// normal user the firmware build cannot be read, so the tests label it
/// "unverified"; root reads the real one.
mod npu_hardware {
    use super::*;
    use crate::npu::{boot_id, Cache, Device, Platform, Slot};
    use std::time::{Duration, Instant};

    fn model(name: &str) -> irlume_common::HashedModel {
        let dir = std::env::var("IRLUME_NPU_TEST_MODELS")
            .unwrap_or_else(|_| "/usr/share/irlume/models".into());
        let path = std::path::Path::new(&dir).join(name);
        irlume_common::HashedModel::new(
            std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
        )
    }

    /// The platform, with the real firmware build for root and an
    /// "unverified" label otherwise.
    /// A debugfs stand-in with an unverified firmware build, for a normal
    /// user who cannot read the kernel's.
    fn fake_debugfs(scratch: &std::path::Path) -> std::path::PathBuf {
        let bus = std::fs::canonicalize("/sys/class/accel/accel0/device").unwrap();
        let entry = scratch.join("debugfs").join(bus.file_name().unwrap());
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("fw_version"), "unverified (not root)\n").unwrap();
        scratch.join("debugfs")
    }

    fn platform(scratch: &std::path::Path) -> Platform {
        let mut platform = Platform::open().unwrap_or_else(|_| {
            Platform::open_with_debugfs(&fake_debugfs(scratch), true).expect("NPU platform")
        });
        // An experiment outside the certified configuration, e.g. "f32".
        if let Ok(precision) = std::env::var("IRLUME_NPU_TEST_PRECISION") {
            platform.set_npu_property("INFERENCE_PRECISION_HINT", &precision);
            eprintln!("experiment: INFERENCE_PRECISION_HINT={precision}");
        }
        platform
    }

    fn placed(
        platform: &mut Platform,
        cache: &Cache,
        model: &irlume_common::HashedModel,
    ) -> (Slot, Duration) {
        let started = Instant::now();
        let compiled = platform
            .compile(cache, model.bytes(), model.sha256())
            .unwrap_or_else(|reason| panic!("{}: {reason}", model.sha256()));
        (Slot::npu(compiled), started.elapsed())
    }

    fn rss_mib() -> f64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let kib: f64 = status
            .lines()
            .find(|l| l.starts_with("VmRSS:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap();
        kib / 1024.0
    }

    /// Resident anonymous, file-backed and shared-memory MiB (the NPU
    /// driver's buffers are shmem-backed GEM objects).
    fn rss_parts() -> [f64; 3] {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let field = |name: &str| -> f64 {
            status
                .lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0)
                / 1024.0
        };
        [field("RssAnon:"), field("RssFile:"), field("RssShmem:")]
    }

    /// Process CPU time (user + system).
    fn cpu_time() -> Duration {
        // SAFETY: getrusage writes one rusage struct for RUSAGE_SELF.
        let usage = unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut usage);
            usage
        };
        let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
        tv(usage.ru_utime) + tv(usage.ru_stime)
    }

    fn dir_bytes(dir: &std::path::Path) -> u64 {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    fn wait_runtime_suspended() -> bool {
        let status = "/sys/class/accel/accel0/device/power/runtime_status";
        (0..50).any(|_| {
            std::thread::sleep(Duration::from_millis(100));
            std::fs::read_to_string(status).is_ok_and(|s| s.trim() == "suspended")
        })
    }

    /// Mean wall and CPU time of `runs` calls after one warm-up.
    fn time(runs: u32, run: &mut dyn FnMut()) -> (Duration, Duration) {
        run();
        let (wall, cpu) = (Instant::now(), cpu_time());
        for _ in 0..runs {
            run();
        }
        (wall.elapsed() / runs, (cpu_time() - cpu) / runs)
    }

    #[test]
    #[ignore = "needs a Lunar Lake NPU, the OpenVINO 2026.2.0 stack and the shipped models"]
    fn npu_hw_models_compile_on_the_npu_and_track_cpu() {
        let scratch = tempfile::tempdir().unwrap();
        let rss_start = rss_mib();
        let started = Instant::now();
        let mut platform = platform(scratch.path());
        let identity = platform.identity().clone();
        eprintln!("platform opened in {:?}", started.elapsed());
        eprintln!("identity {identity:?}\ndigest {}", identity.digest());
        let cache_dir = scratch.path().join("cache");
        let cache = Cache::prepare(&cache_dir, &identity, &boot_id().unwrap()).unwrap();
        let rss_platform = rss_mib();

        // Recognizer: CPU session build time, cold NPU compile, parity.
        let glint = model("glintr100.onnx");
        let t = Instant::now();
        let mut cpu = Embedder::load_from_memory(glint.bytes()).unwrap();
        let glint_cpu_build = t.elapsed();
        let rss_cpu_glint = rss_mib();
        let (slot, glint_cold) = placed(&mut platform, &cache, &glint);
        let rss_npu_glint = rss_mib();
        let mut npu = Embedder {
            session: build(glint.bytes()).unwrap(),
            npu: slot,
        };
        eprintln!(
            "recognizer: CPU session {glint_cpu_build:?} (+{:.0} MiB), NPU cold compile {glint_cold:?} (+{:.0} MiB)",
            rss_cpu_glint - rss_platform,
            rss_npu_glint - rss_cpu_glint
        );
        // The NPU repeats its reference bits, so a certification can record
        // them and the parity check passes on the same identity.
        let digest = npu.npu_reference_digest().expect("on the NPU");
        assert_eq!(npu.npu_reference_digest().as_deref(), Some(digest.as_str()));
        eprintln!("NPU reference digest {digest}");
        let entry: &'static crate::npu::Certification =
            Box::leak(Box::new(crate::npu::Certification {
                model_sha256: "hardware test",
                role: crate::npu::Role::Recognizer,
                identity_digest: "hardware test",
                onnx_runtime: "hardware test",
                thresholds: &[],
                decision_fingerprint: "hardware test",
                fingerprint: Box::leak(
                    npu_reference_fingerprint(crate::npu::Role::Recognizer, glint.bytes())
                        .unwrap()
                        .into_boxed_slice(),
                ),
                cpu_reference_digest: Box::leak(
                    cpu.cpu_reference_digest().unwrap().into_boxed_str(),
                ),
                npu_reference_digest: Box::leak(digest.into_boxed_str()),
                evidence: "hardware test",
            }));
        let mut certified = Embedder {
            session: build(glint.bytes()).unwrap(),
            npu: Slot::certified(
                platform
                    .compile(&cache, glint.bytes(), glint.sha256())
                    .unwrap(),
                entry,
            ),
        };
        certified.check_npu_parity().unwrap();
        assert_eq!(
            certified.npu_device(),
            Device::Npu,
            "the real NPU reproduces its reference digest"
        );
        // The recheck a system resume triggers passes on the real NPU.
        certified.npu.forget_check();
        certified
            .embed_preprocessed_with_norm(&npu_reference::chip(2))
            .unwrap();
        assert_eq!(certified.npu_device(), Device::Npu);
        assert!(!certified.npu.resumed_since_check());
        eprintln!(
            "suspended so far this boot: {:?}",
            crate::npu::suspended(crate::npu::Bound::AtLeast)
        );
        let (a, _) = cpu
            .embed_preprocessed_with_norm(&npu_reference::chip(0))
            .unwrap();
        let (b, _) = npu
            .embed_preprocessed_with_norm(&npu_reference::chip(0))
            .unwrap();
        assert_eq!(npu.npu_device(), Device::Npu, "the NPU answered");
        let cosine: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        eprintln!("recognizer cosine CPU vs NPU {cosine:.7}");
        assert!(cosine > 0.999, "{cosine}");

        // One infer request, several inputs in an interleaved order:
        // every NPU answer tracks a fresh CPU answer, and a repeated
        // input gives the same bits, so no state carries over between
        // inferences (Frigate re-creates the request for ArcFace models
        // over "state pollution").
        let chips: Vec<Vec<f32>> = (1..=3).map(npu_reference::chip).collect();
        let mut first_seen: Vec<Option<Embedding>> = vec![None; chips.len()];
        for &k in &[0usize, 1, 2, 0, 2, 1, 1, 0] {
            let (cpu_k, _) = cpu.embed_preprocessed_with_norm(&chips[k]).unwrap();
            let (npu_k, _) = npu.embed_preprocessed_with_norm(&chips[k]).unwrap();
            let cosine: f32 = cpu_k.iter().zip(&npu_k).map(|(x, y)| x * y).sum();
            assert!(cosine > 0.999, "input {k}: {cosine}");
            match &first_seen[k] {
                None => first_seen[k] = Some(npu_k),
                Some(earlier) => assert!(
                    earlier
                        .iter()
                        .zip(&npu_k)
                        .all(|(x, y)| x.to_bits() == y.to_bits()),
                    "input {k} answered differently the second time"
                ),
            }
        }
        let distinct: f32 = first_seen[0]
            .unwrap()
            .iter()
            .zip(&first_seen[1].unwrap())
            .map(|(x, y)| x * y)
            .sum();
        assert!(
            distinct < 0.999,
            "the inputs must differ for the check to mean anything"
        );
        eprintln!(
            "interleaved inputs: repeatable bit for bit, distinct inputs cosine {distinct:.4}"
        );
        assert_eq!(npu.npu_device(), Device::Npu);

        let (data, width, height) = npu_reference::frame();
        let view = align::RgbView {
            data: &data,
            width,
            height,
        };
        let bbox = npu_reference::BBOX;

        let vit = model("liveness_vit.onnx");
        let t = Instant::now();
        let mut cpu_vit = PadVit::load_from_memory(vit.bytes()).unwrap();
        let vit_cpu_build = t.elapsed();
        let (slot, vit_cold) = placed(&mut platform, &cache, &vit);
        let mut npu_vit = PadVit {
            session: build(vit.bytes()).unwrap(),
            npu: slot,
        };
        let (a_vit, b_vit) = (
            cpu_vit.p_spoof(&view, &bbox).unwrap(),
            npu_vit.p_spoof(&view, &bbox).unwrap(),
        );
        assert_eq!(npu_vit.npu_device(), Device::Npu);
        eprintln!(
            "ViT: CPU session {vit_cpu_build:?}, NPU cold compile {vit_cold:?}; P(spoof) CPU {a_vit:.6} NPU {b_vit:.6} delta {:.6}",
            (a_vit - b_vit).abs()
        );
        assert!((a_vit - b_vit).abs() < 0.01);

        let flir = model("flir.onnx");
        let mut cpu_flir = PadIr::load_from_memory(flir.bytes()).unwrap();
        let (slot, flir_cold) = placed(&mut platform, &cache, &flir);
        let mut npu_flir = PadIr {
            session: build(flir.bytes()).unwrap(),
            npu: slot,
        };
        let (a_flir, b_flir) = (
            cpu_flir.p_fake(&view, &bbox).unwrap(),
            npu_flir.p_fake(&view, &bbox).unwrap(),
        );
        assert_eq!(npu_flir.npu_device(), Device::Npu);
        eprintln!(
            "FLIR: NPU cold compile {flir_cold:?}; P(fake) CPU {a_flir:.6} NPU {b_flir:.6} delta {:.6}",
            (a_flir - b_flir).abs()
        );
        assert!((a_flir - b_flir).abs() < 0.01);

        let blobs = cache.blobs();
        eprintln!(
            "cache: {} blobs, {:.0} MiB on disk",
            std::fs::read_dir(&blobs).unwrap().count(),
            dir_bytes(&blobs) as f64 / 1048576.0
        );
        for entry in std::fs::read_dir(&blobs).unwrap().filter_map(Result::ok) {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            eprintln!("  blob {:.0} MiB", size as f64 / 1048576.0);
        }

        // Runtime suspend: the NPU powers down within its autosuspend
        // delay, so each authentication starts from a suspended device.
        let suspended = wait_runtime_suspended();
        let t = Instant::now();
        let again = npu_vit.p_spoof(&view, &bbox).unwrap();
        let wake = t.elapsed();
        assert_eq!(
            again.to_bits(),
            b_vit.to_bits(),
            "same answer after runtime suspend"
        );
        let (warm_wall, _) = time(5, &mut || {
            npu_vit.p_spoof(&view, &bbox).unwrap();
        });
        eprintln!("ViT after runtime suspend ({suspended}): {wake:?}; back to back: {warm_wall:?}");

        // Warm cache: compiling the same models again imports blobs.
        for (name, cold, model) in [
            ("recognizer", glint_cold, &glint),
            ("ViT", vit_cold, &vit),
            ("FLIR", flir_cold, &flir),
        ] {
            let (_, warm) = placed(&mut platform, &cache, model);
            eprintln!("{name}: cold {cold:?}, from the warm cache {warm:?}");
        }

        // Latency and CPU time per call, CPU session vs NPU.
        let chip = npu_reference::chip(0);
        let (cpu_wall, cpu_cpu) = time(10, &mut || {
            cpu.embed_preprocessed_with_norm(&chip).unwrap();
        });
        let (npu_wall, npu_cpu) = time(10, &mut || {
            npu.embed_preprocessed_with_norm(&chip).unwrap();
        });
        eprintln!("recognizer per call: CPU {cpu_wall:?} wall / {cpu_cpu:?} CPU time, NPU {npu_wall:?} wall / {npu_cpu:?} CPU time");
        let (cpu_wall, cpu_cpu) = time(10, &mut || {
            cpu_vit.p_spoof(&view, &bbox).unwrap();
        });
        let (npu_wall, npu_cpu) = time(10, &mut || {
            npu_vit.p_spoof(&view, &bbox).unwrap();
        });
        eprintln!("ViT per call: CPU {cpu_wall:?} wall / {cpu_cpu:?} CPU time, NPU {npu_wall:?} wall / {npu_cpu:?} CPU time");
        let (cpu_wall, _) = time(20, &mut || {
            cpu_flir.p_fake(&view, &bbox).unwrap();
        });
        let (npu_wall, _) = time(20, &mut || {
            npu_flir.p_fake(&view, &bbox).unwrap();
        });
        eprintln!("FLIR per call: CPU {cpu_wall:?}, NPU {npu_wall:?}");
        eprintln!("RSS: start {rss_start:.0} MiB, end {:.0} MiB", rss_mib());

        // The production mesh through OpenVINO's TFLite frontend.
        let mesh = model("face_landmarks_detector.tflite");
        match platform.compile(&cache, mesh.bytes(), mesh.sha256()) {
            Ok(mut compiled) => {
                let n = 256 * 256 * 3;
                let input: Vec<f32> = (0..n).map(|i| (i % 255) as f32 / 255.0).collect();
                let out = compiled.infer(&input);
                eprintln!(
                    "TFLite mesh on the NPU: compiled, first output {} values",
                    out.map(|o| o.len()).unwrap_or(0)
                );
            }
            Err(reason) => eprintln!("TFLite mesh on the NPU: {reason}"),
        }
    }

    /// Resident memory of each model's CPU session and of its NPU
    /// session, so the cost of keeping both (ADR-0022 §9) is measured.
    /// The FLIR is compiled first so the plugin and compiler libraries
    /// are not counted against the recognizer.
    #[test]
    #[ignore = "needs a Lunar Lake NPU, the OpenVINO 2026.2.0 stack and the shipped models"]
    fn npu_hw_memory() {
        let scratch = tempfile::tempdir().unwrap();
        let mut platform = platform(scratch.path());
        let identity = platform.identity().clone();
        let cache = Cache::prepare(
            &scratch.path().join("cache"),
            &identity,
            &boot_id().unwrap(),
        )
        .unwrap();
        let flir = model("flir.onnx");
        let _warm_up = placed(&mut platform, &cache, &flir);
        for name in ["glintr100.onnx", "liveness_vit.onnx"] {
            let weights = model(name);
            let before = rss_mib();
            let cpu = build(weights.bytes()).unwrap();
            let with_cpu = rss_mib();
            let parts_before = rss_parts();
            let (npu, cold) = placed(&mut platform, &cache, &weights);
            let with_npu = rss_mib();
            let parts_after = rss_parts();
            eprintln!(
                "{name}: NPU compile resident delta anon {:+.0} file {:+.0} shmem {:+.0} MiB",
                parts_after[0] - parts_before[0],
                parts_after[1] - parts_before[1],
                parts_after[2] - parts_before[2]
            );
            drop(npu);
            let after_npu_drop = rss_mib();
            let (npu, warm) = placed(&mut platform, &cache, &weights);
            let with_warm_npu = rss_mib();
            drop(npu);
            drop(cpu);
            eprintln!(
                "{name}: CPU session +{:.0} MiB; NPU cold compile ({cold:?}) +{:.0} MiB, {:.0} MiB freed on drop; NPU from the warm cache ({warm:?}) +{:.0} MiB",
                with_cpu - before,
                with_npu - with_cpu,
                with_npu - after_npu_drop,
                with_warm_npu - after_npu_drop
            );
        }
    }

    /// Which NPU compiler the plugin uses by default, which values it
    /// accepts, and whether the recognizer's output depends on the choice.
    #[test]
    #[ignore = "needs a Lunar Lake NPU, the OpenVINO 2026.2.0 stack and the shipped models"]
    fn npu_hw_compiler_type() {
        let glint = model("glintr100.onnx");
        let mut cpu = Embedder::load_from_memory(glint.bytes()).unwrap();
        let chip = npu_reference::chip(0);
        let (reference, _) = cpu.embed_preprocessed_with_norm(&chip).unwrap();
        let mut outputs = Vec::new();
        for kind in ["default", "PLUGIN", "DRIVER"] {
            let scratch = tempfile::tempdir().unwrap();
            // The default case leaves OpenVINO's own compiler type, which
            // the production open would force to PLUGIN.
            let mut platform = if kind == "default" {
                Platform::open_with_debugfs(&fake_debugfs(scratch.path()), false)
                    .expect("NPU platform")
            } else {
                platform(scratch.path())
            };
            eprintln!(
                "{kind}: before setting, NPU_COMPILER_TYPE reads {:?}",
                platform.npu_property("NPU_COMPILER_TYPE")
            );
            if kind != "default" {
                platform.set_npu_property("NPU_COMPILER_TYPE", kind);
                eprintln!(
                    "{kind}: after setting, reads {:?}",
                    platform.npu_property("NPU_COMPILER_TYPE")
                );
            }
            let identity = platform.identity().clone();
            let cache = Cache::prepare(
                &scratch.path().join("cache"),
                &identity,
                &boot_id().unwrap(),
            )
            .unwrap();
            match platform.compile(&cache, glint.bytes(), glint.sha256()) {
                Ok(model) => {
                    let mut npu = Embedder {
                        session: build(glint.bytes()).unwrap(),
                        npu: Slot::npu(model),
                    };
                    let (out, _) = npu.embed_preprocessed_with_norm(&chip).unwrap();
                    let cosine: f32 = reference.iter().zip(&out).map(|(a, b)| a * b).sum();
                    eprintln!("{kind}: compiled; cosine to CPU {cosine:.7}");
                    outputs.push((kind, out));
                }
                Err(reason) => eprintln!("{kind}: {reason}"),
            }
        }
        for (kind, out) in &outputs[1..] {
            let same = out
                .iter()
                .zip(&outputs[0].1)
                .all(|(a, b)| a.to_bits() == b.to_bits());
            eprintln!("{kind} output identical to {}: {same}", outputs[0].0);
        }
    }

    /// The CPU session's exact output bits for the reference inputs, to
    /// compare across processes, core types and thread placement.
    #[test]
    #[ignore = "needs the shipped models"]
    fn npu_hw_cpu_reference_is_exact() {
        let glint = model("glintr100.onnx");
        let mut digests = Vec::new();
        for _ in 0..3 {
            let mut cpu = Embedder::load_from_memory(glint.bytes()).unwrap();
            digests.push(cpu.cpu_reference_digest().unwrap());
            digests.push(cpu.cpu_reference_digest().unwrap());
        }
        eprintln!("CPU reference digest {}", digests[0]);
        assert!(
            digests.iter().all(|d| d == &digests[0]),
            "the CPU session repeats its bits: {digests:?}"
        );
    }

    /// What a fresh process maps after the platform opens and after the
    /// first compile, and the exact bits the NPU returns for the reference
    /// inputs, to compare across processes.
    #[test]
    #[ignore = "needs a Lunar Lake NPU, the OpenVINO 2026.2.0 stack and the shipped models"]
    fn npu_hw_mapped_runtime_and_determinism() {
        fn mapped() -> Vec<String> {
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            let mut libs: Vec<String> = maps
                .lines()
                .filter_map(|l| l.split_whitespace().nth(5))
                .filter(|p| {
                    p.contains(".so")
                        && (p.contains("openvino") || p.contains("libze") || p.contains("npu"))
                })
                .map(str::to_owned)
                .collect();
            libs.sort();
            libs.dedup();
            libs
        }
        let scratch = tempfile::tempdir().unwrap();
        let mut platform = platform(scratch.path());
        eprintln!("mapped after open: {:#?}", mapped());
        let identity = platform.identity().clone();
        let cache = Cache::prepare(
            &scratch.path().join("cache"),
            &identity,
            &boot_id().unwrap(),
        )
        .unwrap();
        let glint = model("glintr100.onnx");
        let mut npu = Embedder {
            session: build(glint.bytes()).unwrap(),
            npu: placed(&mut platform, &cache, &glint).0,
        };
        eprintln!("mapped after compile: {:#?}", mapped());
        let mut cpu = Embedder::load_from_memory(glint.bytes()).unwrap();
        for k in 0..3 {
            let chip = npu_reference::chip(k);
            let (n, _) = npu.embed_preprocessed_with_norm(&chip).unwrap();
            let (c, _) = cpu.embed_preprocessed_with_norm(&chip).unwrap();
            let bits: Vec<u8> = n.iter().flat_map(|v| v.to_le_bytes()).collect();
            let distance = n
                .iter()
                .zip(&c)
                .map(|(a, b)| (a - b) * (a - b))
                .sum::<f32>()
                .sqrt();
            eprintln!(
                "reference {k}: NPU bits sha256 {} distance to CPU {distance:.7}",
                &irlume_common::sha256_hex(&bits)[..16]
            );
        }
    }

    fn pnm(raw: &[u8]) -> Option<(char, u32, u32, &[u8])> {
        let kind = match raw.get(..2)? {
            b"P5" => 'g',
            b"P6" => 'c',
            _ => return None,
        };
        let mut fields = Vec::new();
        let mut i = 2;
        while fields.len() < 3 {
            while raw.get(i)?.is_ascii_whitespace() {
                i += 1;
            }
            if raw[i] == b'#' {
                while raw.get(i)? != &b'\n' {
                    i += 1;
                }
                continue;
            }
            let start = i;
            while raw.get(i)?.is_ascii_digit() {
                i += 1;
            }
            fields.push(
                std::str::from_utf8(&raw[start..i])
                    .ok()?
                    .parse::<u32>()
                    .ok()?,
            );
        }
        let (w, h) = (fields[0], fields[1]);
        let data = raw.get(i + 1..)?;
        let need = (w * h) as usize * if kind == 'g' { 1 } else { 3 };
        (fields[2] == 255 && data.len() >= need).then(|| (kind, w, h, &data[..need]))
    }

    #[derive(Default)]
    struct Stats {
        n: usize,
        max_delta: f32,
        sum_delta: f64,
        flips: usize,
        /// Flips where the CPU score was at or above the threshold and
        /// the NPU score below it.
        flips_down: usize,
        /// Closest CPU score to the threshold, as a distance.
        nearest: f32,
    }

    impl Stats {
        fn add(&mut self, cpu: f32, npu: f32, threshold: f32) {
            if self.n == 0 {
                self.nearest = f32::INFINITY;
            }
            self.n += 1;
            let delta = (cpu - npu).abs();
            self.max_delta = self.max_delta.max(delta);
            self.sum_delta += f64::from(delta);
            if (cpu >= threshold) != (npu >= threshold) {
                self.flips += 1;
                if cpu >= threshold {
                    self.flips_down += 1;
                }
            }
            self.nearest = self.nearest.min((cpu - threshold).abs());
        }

        fn line(&self, name: &str) -> String {
            if self.n == 0 {
                return format!("{name}: no samples");
            }
            format!(
                "{name}: n {} max |delta| {:.6} mean |delta| {:.6} flips {} (CPU at or above, NPU below: {}) nearest CPU score to threshold {:.4}",
                self.n,
                self.max_delta,
                self.sum_delta / self.n as f64,
                self.flips,
                self.flips_down,
                self.nearest
            )
        }
    }

    fn is_attack(dir: &str) -> bool {
        dir.starts_with("spoof-")
            || dir.contains("banner")
            || dir.contains("phone")
            || dir.contains("screen")
            || dir.contains("replay")
    }

    /// Real recorded frames, CPU vs NPU at the wired thresholds: the
    /// FLIR at 0.9 and the recognizer at 0.55 on IR frames, the ViT at
    /// 0.55 on RGB frames. Frames are read into memory only; only these
    /// aggregate numbers are printed.
    #[test]
    #[ignore = "needs a Lunar Lake NPU, the shipped models and recorded evaluation frames"]
    fn npu_hw_real_frames_track_cpu() {
        let root = std::path::PathBuf::from(
            std::env::var("IRLUME_NPU_EVAL_DIR")
                .unwrap_or_else(|_| format!("{}/irlume-suncal", std::env::var("HOME").unwrap())),
        );
        let scratch = tempfile::tempdir().unwrap();
        let mut platform = platform(scratch.path());
        let identity = platform.identity().clone();
        let cache = Cache::prepare(
            &scratch.path().join("cache"),
            &identity,
            &boot_id().unwrap(),
        )
        .unwrap();
        let mut detector =
            Detector::load_from_memory(model("face_detection_yunet_2023mar.onnx").bytes()).unwrap();
        let glint = model("glintr100.onnx");
        let mut cpu_emb = Embedder::load_from_memory(glint.bytes()).unwrap();
        let mut npu_emb = Embedder {
            session: build(glint.bytes()).unwrap(),
            npu: placed(&mut platform, &cache, &glint).0,
        };
        let flir = model("flir.onnx");
        let mut cpu_flir = PadIr::load_from_memory(flir.bytes()).unwrap();
        let mut npu_flir = PadIr {
            session: build(flir.bytes()).unwrap(),
            npu: placed(&mut platform, &cache, &flir).0,
        };
        let vit = model("liveness_vit.onnx");
        let mut cpu_vit = PadVit::load_from_memory(vit.bytes()).unwrap();
        let mut npu_vit = PadVit {
            session: build(vit.bytes()).unwrap(),
            npu: placed(&mut platform, &cache, &vit).0,
        };

        let mut dirs: Vec<std::path::PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&root).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "flir-candidate") {
                    dirs.extend(
                        std::fs::read_dir(&path)
                            .unwrap()
                            .filter_map(Result::ok)
                            .map(|e| e.path())
                            .filter(|p| p.is_dir()),
                    );
                } else {
                    dirs.push(path);
                }
            }
        }
        dirs.sort();

        let (mut flir_live, mut flir_attack) = (Stats::default(), Stats::default());
        let (mut vit_live, mut vit_attack) = (Stats::default(), Stats::default());
        let mut match_stats = Stats::default();
        let (mut match_ir_attack, mut match_rgb_live, mut match_rgb_attack) =
            (Stats::default(), Stats::default(), Stats::default());
        let mut cosine_min = f32::INFINITY;
        let mut reference: Option<Embedding> = None;
        let mut reference_rgb: Option<Embedding> = None;
        // The recognizer on one face, CPU and NPU, scored against the first
        // genuine frame of the same modality (the owner, as an enrolled
        // template would be).
        // RGB goes through the TTA embedding production authenticates RGB
        // with; IR through the plain one.
        let mut recognize = |view: &align::RgbView<'_>,
                             landmarks: &crate::Landmarks5,
                             reference: &mut Option<Embedding>,
                             attack: bool,
                             stats: &mut Stats,
                             cosine_min: &mut f32,
                             tta: bool| {
            let Ok(chip) = align::align_to_arcface(view, landmarks) else {
                return;
            };
            let (ce, ne) = if tta {
                (
                    cpu_emb.embed_tta(&chip).unwrap(),
                    npu_emb.embed_tta(&chip).unwrap(),
                )
            } else {
                let data = align::preprocess_arcface(&chip);
                (
                    cpu_emb.embed_preprocessed_with_norm(&data).unwrap().0,
                    npu_emb.embed_preprocessed_with_norm(&data).unwrap().0,
                )
            };
            let cosine: f32 = ce.iter().zip(&ne).map(|(x, y)| x * y).sum();
            *cosine_min = cosine_min.min(cosine);
            if reference.is_none() && attack {
                return; // no genuine reference yet
            }
            let reference = *reference.get_or_insert(ce);
            let score =
                |e: &Embedding| -> f32 { e.iter().zip(&reference).map(|(x, y)| x * y).sum() };
            stats.add(score(&ce), score(&ne), 0.55);
        };
        let (mut frames, mut faces) = (0usize, 0usize);
        for dir in &dirs {
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            let attack = is_attack(&name);
            let mut files: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect();
            files.sort();
            for file in files {
                let ext = file
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase());
                let rgb: Vec<u8>;
                let (width, height, ir) = match ext.as_deref() {
                    Some("pgm") | Some("ppm") => {
                        let raw = std::fs::read(&file).unwrap();
                        let Some((kind, w, h, data)) = pnm(&raw) else {
                            continue;
                        };
                        rgb = if kind == 'g' {
                            data.iter().flat_map(|&g| [g, g, g]).collect()
                        } else {
                            data.to_vec()
                        };
                        (w, h, kind == 'g')
                    }
                    Some("jpg") | Some("jpeg") => {
                        let Ok(img) = image::open(&file) else {
                            continue;
                        };
                        let img = img.to_rgb8();
                        let (w, h) = img.dimensions();
                        rgb = img.into_raw();
                        (w, h, false)
                    }
                    _ => continue,
                };
                frames += 1;
                let view = align::RgbView {
                    data: &rgb,
                    width,
                    height,
                };
                let Ok(found) = detector.detect(&view) else {
                    continue;
                };
                let Some(face) = found
                    .into_iter()
                    .filter(crate::detection_is_finite)
                    .max_by(|a, b| a.score.total_cmp(&b.score))
                else {
                    continue;
                };
                faces += 1;
                if ir {
                    let (c, n) = (
                        cpu_flir.p_fake(&view, &face.bbox).unwrap(),
                        npu_flir.p_fake(&view, &face.bbox).unwrap(),
                    );
                    if attack {
                        flir_attack.add(c, n, 0.9)
                    } else {
                        flir_live.add(c, n, 0.9)
                    }
                    let stats = if attack {
                        &mut match_ir_attack
                    } else {
                        &mut match_stats
                    };
                    recognize(
                        &view,
                        &face.landmarks,
                        &mut reference,
                        attack,
                        stats,
                        &mut cosine_min,
                        false,
                    );
                } else {
                    let (c, n) = (
                        cpu_vit.p_spoof(&view, &face.bbox).unwrap(),
                        npu_vit.p_spoof(&view, &face.bbox).unwrap(),
                    );
                    if attack {
                        vit_attack.add(c, n, 0.55)
                    } else {
                        vit_live.add(c, n, 0.55)
                    }
                    let stats = if attack {
                        &mut match_rgb_attack
                    } else {
                        &mut match_rgb_live
                    };
                    recognize(
                        &view,
                        &face.landmarks,
                        &mut reference_rgb,
                        attack,
                        stats,
                        &mut cosine_min,
                        true,
                    );
                }
            }
        }
        for device in [
            npu_emb.npu_device(),
            npu_flir.npu_device(),
            npu_vit.npu_device(),
        ] {
            assert_eq!(device, Device::Npu, "every NPU model stayed on the NPU");
        }
        eprintln!(
            "frames {frames}, with a face {faces}, directories {}",
            dirs.len()
        );
        eprintln!("{}", flir_live.line("FLIR genuine IR at 0.9"));
        eprintln!("{}", flir_attack.line("FLIR attack IR at 0.9"));
        eprintln!(
            "{}",
            match_stats.line("recognizer genuine IR vs first frame at 0.55")
        );
        eprintln!(
            "{}",
            match_ir_attack.line("recognizer IR attacks vs first genuine IR frame at 0.55")
        );
        eprintln!(
            "{}",
            match_rgb_live.line("recognizer TTA genuine RGB vs first genuine RGB frame at 0.55")
        );
        eprintln!(
            "{}",
            match_rgb_attack.line("recognizer TTA RGB attacks vs first genuine RGB frame at 0.55")
        );
        eprintln!("recognizer CPU vs NPU embedding cosine, lowest {cosine_min:.6}");
        eprintln!("{}", vit_live.line("ViT genuine RGB at 0.55"));
        eprintln!("{}", vit_attack.line("ViT attack RGB at 0.55"));
        // A measurement on a partial corpus, not a certification: each
        // model's verdict against section 7 rules 4 and 5 (the
        // allowances from today's measured windows) is reported.
        for (name, stats, allowance) in [
            ("FLIR", [&flir_live, &flir_attack], 0.0020f32),
            ("ViT", [&vit_live, &vit_attack], 0.0022),
        ] {
            let flips: usize = stats.iter().map(|s| s.flips).sum();
            let max = stats.iter().map(|s| s.max_delta).fold(0.0f32, f32::max);
            eprintln!(
                "{name}: flips {flips}, max |delta| {max:.6} against an allowance of {allowance}: {}",
                if flips == 0 && max <= allowance { "within rules 4 and 5" } else { "outside rules 4 and 5" }
            );
        }
        let new_grants: usize = [&match_ir_attack, &match_rgb_attack]
            .iter()
            .map(|s| s.flips - s.flips_down)
            .sum();
        eprintln!(
            "recognizer: genuine flips {}, new grants on presentation attacks {new_grants}; zero-effort impostor pairs need the recognition corpora",
            match_stats.flips + match_rgb_live.flips
        );
    }
}
