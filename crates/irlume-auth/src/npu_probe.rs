// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Where the recognizer computes an embedding (ADR-0022 §2).
//!
//! Every stored template comes from the CPU reference, and each new scan
//! records that reference as its producer. Only an authentication probe can
//! run on the NPU, and only when every scan of the user's enrollment carries
//! the producer the NPU was certified against; enrollment, self-tests and
//! every other path embed on CPU.

use super::Engine;

#[cfg(feature = "npu")]
fn with_decision_fingerprint<T>(
    fingerprint: Result<
        super::identity_arms::fingerprint::DecisionFingerprint,
        super::identity_arms::fingerprint::FingerprintError,
    >,
    refused: T,
    open: impl FnOnce(&str) -> T,
) -> T {
    match fingerprint {
        Ok(fingerprint) => open(fingerprint.as_ref()),
        Err(_) => refused,
    }
}

impl Engine {
    /// The RGB embedding of an aligned chip, through test-time augmentation:
    /// on the NPU inside an authentication that admitted it, otherwise on the
    /// CPU reference.
    pub(super) fn embed_rgb_probe(
        &mut self,
        chip: &[u8],
    ) -> irlume_common::Result<irlume_vision::Embedding> {
        if self.npu_probe {
            self.emb.embed_tta(chip)
        } else {
            self.emb.on_cpu().embed_tta(chip)
        }
    }

    /// The raw IR embedding of an aligned chip, before any adapter: on the
    /// NPU inside an authentication that admitted it, otherwise on the CPU
    /// reference.
    pub(super) fn embed_ir_probe(
        &mut self,
        chip: &[u8],
    ) -> irlume_common::Result<irlume_vision::Embedding> {
        if self.npu_probe {
            self.emb.embed(chip)
        } else {
            self.emb.on_cpu().embed(chip)
        }
    }

    /// The producer tag this engine stamps on new scans (ADR-0022 §2):
    /// the recognizer digest, the loaded ONNX Runtime version and the digest
    /// of the CPU session's exact outputs on the fixed reference inputs.
    /// Computed once; `None` while it cannot be, and the scan then records
    /// no producer, which keeps it on CPU probes.
    pub(super) fn embed_producer(&mut self) -> Option<String> {
        if self.embed_producer.is_none() {
            let recognizer = self.embed_space.strip_prefix("embed:")?.to_owned();
            let runtime = irlume_vision::onnx_runtime_version()?;
            let digest = self.emb.cpu_reference_digest().ok()?;
            self.embed_producer = Some(irlume_core::storage::embed_producer(
                &recognizer,
                &runtime,
                &digest,
            ));
        }
        self.embed_producer.clone()
    }

    /// Whether this authentication's probes may run on the NPU: the
    /// recognizer is placed there, no IR adapter is in play, and every scan
    /// of `enrollment` was produced by this engine's CPU reference.
    pub(super) fn npu_probe_admitted(
        &mut self,
        enrollment: &irlume_core::storage::Enrollment,
    ) -> bool {
        let refusal = if !self.recognizer_on_accelerator() {
            Some("the recognizer is on CPU")
        } else if self.ir_adapter.is_some() || self.ir_adapter_required {
            Some("an IR adapter is configured")
        } else {
            match self.embed_producer() {
                None => Some("this engine's producer is unknown"),
                Some(producer) if !every_scan_from(enrollment, &self.embed_space, &producer) => {
                    Some("a scan of this enrollment comes from another CPU reference")
                }
                Some(_) => None,
            }
        };
        match refusal {
            None => irlume_common::dlog!(
                "npu: this authentication's probes run on the {}",
                self.accelerator_name()
            ),
            Some(why) => {
                irlume_common::dlog!("npu: this authentication's probes run on CPU: {why}")
            }
        }
        refusal.is_none()
    }

    /// Whether this engine's probes could ever run on the NPU: an IR
    /// adapter, loaded or required, keeps the recognizer on CPU (ADR-0022
    /// §2), so the daemon does not open the NPU for it.
    pub fn npu_eligible(&self) -> bool {
        self.ir_adapter.is_none() && !self.ir_adapter_required
    }

    /// Whether the recognizer is placed on an accelerator, the NPU or the
    /// GPU: the producer and IR-adapter rules of ADR-0022 §2 admit probes on
    /// either alike (ADR-0033 section 1).
    #[cfg(feature = "npu")]
    fn recognizer_on_accelerator(&self) -> bool {
        matches!(
            self.emb.npu_device(),
            irlume_vision::npu::Device::Npu | irlume_vision::npu::Device::Gpu
        )
    }

    #[cfg(not(feature = "npu"))]
    fn recognizer_on_accelerator(&self) -> bool {
        false
    }

    #[cfg(feature = "npu")]
    fn accelerator_name(&self) -> &'static str {
        if self.emb.npu_device() == irlume_vision::npu::Device::Gpu {
            "GPU"
        } else {
            "NPU"
        }
    }

    #[cfg(not(feature = "npu"))]
    fn accelerator_name(&self) -> &'static str {
        "CPU"
    }

    /// The wired thresholds that consume the recognizer's output, by
    /// constant name, at this engine's values: an NPU entry applies only at
    /// these operating points (ADR-0022 §3). The adapter threshold is absent
    /// because an IR adapter keeps the recognizer on CPU.
    pub fn npu_thresholds(&self) -> [(&'static str, f32); 6] {
        [
            ("RGB_MATCH_THRESHOLD", self.rgb_threshold),
            ("IR_MATCH_THRESHOLD", irlume_core::IR_MATCH_THRESHOLD),
            (
                "IR_DARK_MATCH_THRESHOLD",
                irlume_core::IR_DARK_MATCH_THRESHOLD,
            ),
            ("IR_FALLBACK_MARGIN", irlume_core::IR_FALLBACK_MARGIN),
            (
                "FUSION_PROB_THRESHOLD",
                irlume_core::fusion::FUSION_PROB_THRESHOLD,
            ),
            (
                "FUSION_MIN_PER_MODALITY_PROB",
                irlume_core::fusion::FUSION_MIN_PER_MODALITY_PROB,
            ),
        ]
    }

    /// Where the recognizer runs, for status and `doctor` (ADR-0022 §13).
    #[cfg(feature = "npu")]
    pub fn recognizer_device(&self) -> irlume_vision::npu::Device {
        self.emb.npu_device()
    }

    /// Where the recognizer runs and, on CPU, why, with the NPU platform it
    /// was placed for (ADR-0022 §13).
    pub fn recognizer_placement(&self) -> irlume_common::RecognizerPlacement {
        #[cfg(feature = "npu")]
        let (device, accelerator, reason) = match self.emb.npu_device() {
            _ if self.ir_adapter.is_some() || self.ir_adapter_required => (
                "cpu",
                None,
                Some("an IR adapter is configured, which keeps the recognizer on CPU".to_owned()),
            ),
            irlume_vision::npu::Device::Npu => ("npu", Some("npu"), None),
            // The legacy field keeps the values released clients know; the
            // precise placement travels in `accelerator` (daemon AGENTS.md,
            // wire compatibility).
            irlume_vision::npu::Device::Gpu => (
                "cpu",
                Some("gpu"),
                Some(irlume_common::RECOGNIZER_ON_GPU_REASON.to_owned()),
            ),
            // The reason can carry runtime or driver error text: one bounded
            // line before it reaches the journal, Health or doctor.
            irlume_vision::npu::Device::Cpu(reason) => (
                "cpu",
                None,
                Some(irlume_common::single_line(&reason.to_string(), 300)),
            ),
        };
        #[cfg(not(feature = "npu"))]
        let (device, accelerator, reason) = (
            "cpu",
            None::<&str>,
            Some("not built with NPU support".to_owned()),
        );
        #[cfg(feature = "npu")]
        let (runtime_available, gpu_runtime_available, gpu_platform) = (
            self.npu_runtime_available,
            self.gpu_runtime_available,
            self.gpu_platform.clone(),
        );
        #[cfg(not(feature = "npu"))]
        let (runtime_available, gpu_runtime_available, gpu_platform) = (None, None, None);
        let qualified = runtime_available
            .filter(|available| *available)
            .map(|_| accelerator == Some("npu"));
        let gpu_qualified = gpu_runtime_available
            .filter(|available| *available)
            .map(|_| accelerator == Some("gpu"));
        irlume_common::RecognizerPlacement {
            device: device.into(),
            reason,
            platform: self.npu_platform.clone(),
            runtime_available,
            qualified,
            // The daemon stamps the governing device selection after the
            // engine reports; the engine itself never reads settings.
            selection: None,
            accelerator: accelerator.map(str::to_owned),
            gpu_platform,
            gpu_runtime_available,
            gpu_qualified,
        }
    }

    /// Open the NPU runtime for this engine's recognizer under `cache_base`,
    /// as a consumer with this engine's wired thresholds, the recognition
    /// decision fingerprint and the loaded ONNX Runtime (ADR-0022 §3). A
    /// failure is kept in the context as the reason the recognizer stays on
    /// CPU.
    #[cfg(feature = "npu")]
    pub fn open_npu_context(&self, cache_base: &std::path::Path) -> irlume_vision::npu::Context {
        self.open_npu_context_with_runtime(
            cache_base,
            &irlume_vision::npu::RuntimeSelection::Automatic,
        )
    }

    /// Open an administrator-selected provider runtime for this CPU consumer.
    /// Discovery does not bypass the recognizer's qualification or parity.
    /// Invalid decision-fingerprint construction returns a not-certified
    /// context without calling the runtime opener.
    #[cfg(feature = "npu")]
    pub fn open_npu_context_with_runtime(
        &self,
        cache_base: &std::path::Path,
        selection: &irlume_vision::npu::RuntimeSelection,
    ) -> irlume_vision::npu::Context {
        let runtime = irlume_vision::onnx_runtime_version().unwrap_or_default();
        let thresholds = self.npu_thresholds();
        with_decision_fingerprint(
            super::identity_arms::fingerprint::try_decision_fingerprint(),
            irlume_vision::npu::Context::not_selected(irlume_vision::npu::CpuReason::NotCertified),
            |fingerprint| {
                irlume_vision::npu::Context::open_with_runtime(
                    cache_base,
                    &irlume_vision::npu::Consumer {
                        onnx_runtime: &runtime,
                        thresholds: &thresholds,
                        decision_fingerprint: fingerprint,
                    },
                    selection,
                )
            },
        )
    }

    /// Place the recognizer for `npu`: on the NPU when its entry certifies
    /// this platform and consumer and it compiles and reproduces the entry's
    /// digests, on CPU with the reason otherwise (ADR-0022 §3, §8, §9). The
    /// CPU session is kept, not rebuilt. The producer is computed now, so an
    /// authentication never pays for it.
    ///
    /// # Errors
    ///
    /// When `weights` are not the loaded recognizer's, or its CPU session
    /// fails the parity check's reference inputs; the recognizer then stays
    /// on CPU and the engine stays usable.
    #[cfg(feature = "npu")]
    pub fn place_recognizer_on_npu(
        &mut self,
        weights: &irlume_common::HashedModel,
        npu: &mut irlume_vision::npu::Context,
    ) -> irlume_common::Result<()> {
        if format!("embed:{}", weights.sha256()) != self.embed_space {
            return Err(irlume_common::Error::Policy(
                "the NPU recognizer must be the loaded recognizer".into(),
            ));
        }
        self.npu_runtime_available = npu.runtime_available();
        self.npu_platform = npu
            .identity()
            .ok()
            .map(irlume_vision::npu::Identity::digest);
        self.emb.place_on_npu(weights, npu)?;
        let _ = self.embed_producer();
        Ok(())
    }
}

#[cfg(feature = "npu")]
impl Engine {
    /// Open the GPU runtime for this engine's recognizer under
    /// `cache_base`, as the same CPU consumer the NPU context gets
    /// (ADR-0033 section 5). The loading admission comes first: while it
    /// refuses, nothing is loaded or written and the context carries that
    /// refusal.
    /// An invalid decision fingerprint instead returns a not-certified
    /// context before runtime discovery or cache preparation.
    pub fn open_gpu_context_with_runtime(
        &self,
        cache_base: &std::path::Path,
        selection: &irlume_vision::npu::RuntimeSelection,
    ) -> irlume_vision::npu::gpu::Context {
        let runtime = irlume_vision::onnx_runtime_version().unwrap_or_default();
        let thresholds = self.npu_thresholds();
        with_decision_fingerprint(
            super::identity_arms::fingerprint::try_decision_fingerprint(),
            irlume_vision::npu::gpu::Context::not_selected(irlume_vision::npu::CpuReason::Gpu(
                irlume_vision::npu::gpu::GpuReason::NotCertified,
            )),
            |fingerprint| {
                irlume_vision::npu::gpu::Context::open_with_runtime(
                    cache_base,
                    &irlume_vision::npu::Consumer {
                        onnx_runtime: &runtime,
                        thresholds: &thresholds,
                        decision_fingerprint: fingerprint,
                    },
                    selection,
                )
            },
        )
    }

    /// [`Self::place_recognizer_on_npu`] for the GPU: on the GPU when an
    /// entry certifies this platform's numerics key and consumer and it
    /// compiles and passes its engine-build checks, on CPU with the GPU
    /// reason otherwise (ADR-0033 phase 3).
    ///
    /// # Errors
    ///
    /// When `weights` are not the loaded recognizer's, or its CPU session
    /// fails the parity check's reference inputs; the recognizer then stays
    /// on CPU and the engine stays usable.
    pub fn place_recognizer_on_gpu(
        &mut self,
        weights: &irlume_common::HashedModel,
        gpu: &mut irlume_vision::npu::gpu::Context,
    ) -> irlume_common::Result<()> {
        if format!("embed:{}", weights.sha256()) != self.embed_space {
            return Err(irlume_common::Error::Policy(
                "the GPU recognizer must be the loaded recognizer".into(),
            ));
        }
        self.gpu_runtime_available = gpu.runtime_available();
        self.gpu_platform = gpu
            .identity()
            .ok()
            .map(irlume_vision::npu::gpu::Identity::digest);
        self.emb.place_on_gpu(weights, gpu)?;
        let _ = self.embed_producer();
        Ok(())
    }
}

/// Whether `enrollment` has scans this engine's recognizer (`embed_space`)
/// can match, and every one of them records `producer`. A scan from another
/// recognizer never takes part in this engine's matching, so it neither
/// admits nor refuses the NPU.
fn every_scan_from(
    enrollment: &irlume_core::storage::Enrollment,
    embed_space: &str,
    producer: &str,
) -> bool {
    let mut scans = enrollment
        .profiles
        .iter()
        .flat_map(|profile| &profile.scans)
        .filter(|scan| {
            irlume_core::storage::recognizer_space_matches(scan.embed_space.as_deref(), embed_space)
        })
        .peekable();
    scans.peek().is_some() && scans.all(|scan| scan.embed_producer.as_deref() == Some(producer))
}

#[cfg(test)]
mod tests {
    use super::every_scan_from;
    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};

    #[test]
    fn accelerator_contexts_use_checked_decision_fingerprints() {
        let source = include_str!("npu_probe.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();
        for name in [
            "open_npu_context_with_runtime",
            "open_gpu_context_with_runtime",
        ] {
            let marker = format!("pub fn {name}(");
            let body = source
                .split(&marker)
                .nth(1)
                .unwrap()
                .split("\n    }")
                .next()
                .unwrap();
            assert!(body.contains("with_decision_fingerprint("), "{name}");
            assert!(
                body.contains("fingerprint::try_decision_fingerprint()"),
                "{name}"
            );
            assert!(body.contains("NotCertified"), "{name}");
            assert!(!body.contains("super::decision_fingerprint()"), "{name}");
            assert!(
                !body.contains(".unwrap()") && !body.contains(".expect("),
                "{name}"
            );
        }
    }

    #[cfg(feature = "npu")]
    #[test]
    fn invalid_decision_fingerprint_refuses_before_either_context_opens() {
        use crate::identity_arms::fingerprint::FingerprintError;
        use irlume_vision::npu::{gpu::GpuReason, Context, CpuReason};

        let npu = super::with_decision_fingerprint(
            Err(FingerprintError::InvalidDigest),
            Context::not_selected(CpuReason::NotCertified),
            |_| panic!("invalid fingerprint reached NPU discovery/cache/open"),
        );
        assert!(matches!(npu.identity(), Err(CpuReason::NotCertified)));
        assert_eq!(npu.runtime_available(), None);
        let gpu = super::with_decision_fingerprint(
            Err(FingerprintError::InvalidDigest),
            irlume_vision::npu::gpu::Context::not_selected(CpuReason::Gpu(GpuReason::NotCertified)),
            |_| panic!("invalid fingerprint reached GPU discovery/cache/open"),
        );
        assert!(matches!(
            gpu.identity(),
            Err(CpuReason::Gpu(GpuReason::NotCertified))
        ));
        assert_eq!(gpu.runtime_available(), None);
    }

    #[cfg(feature = "npu")]
    #[test]
    fn checked_decision_fingerprint_reaches_the_opener_unchanged() {
        let fingerprint = crate::identity_arms::fingerprint::try_decision_fingerprint().unwrap();
        let expected = fingerprint.as_ref().to_owned();
        let opened = super::with_decision_fingerprint(Ok(fingerprint), false, |value| {
            assert_eq!(value, expected);
            true
        });
        assert!(opened);
    }

    fn scan(producer: Option<&str>) -> FaceScan {
        scan_in("embed:test", producer)
    }

    fn scan_in(space: &str, producer: Option<&str>) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.0; 4],
            ir: None,
            ir_space: None,
            embed_space: Some(space.into()),
            embed_producer: producer.map(str::to_owned),
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
            captured_at: None,
        }
    }

    fn enrollment(profiles: &[&[Option<&str>]]) -> Enrollment {
        let mut enrollment = Enrollment::new("u");
        for (i, scans) in profiles.iter().enumerate() {
            enrollment.profiles.push(FaceProfile {
                name: format!("p{i}"),
                scans: scans.iter().map(|producer| scan(*producer)).collect(),
                ir_calib: None,
                ir_calibs: std::collections::BTreeMap::new(),
            });
        }
        enrollment
    }

    /// The NPU probe is certified against templates from one CPU reference,
    /// so one scan from another producer, or from before the field, keeps
    /// the whole authentication on CPU (ADR-0022 §2).
    #[test]
    fn only_an_enrollment_entirely_from_the_producer_admits_the_npu() {
        let producer = "cpu:a:ort-1.28.1:c";
        let ours = Some(producer);
        let space = "embed:test";
        assert!(every_scan_from(
            &enrollment(&[&[ours, ours], &[ours]]),
            space,
            producer
        ));
        assert!(!every_scan_from(
            &enrollment(&[&[ours, None]]),
            space,
            producer
        ));
        assert!(!every_scan_from(
            &enrollment(&[&[ours], &[Some("cpu:a:ort-1.27.0:d")]]),
            space,
            producer
        ));
        assert!(
            !every_scan_from(&enrollment(&[]), space, producer),
            "no scans"
        );
        assert!(
            !every_scan_from(&enrollment(&[&[]]), space, producer),
            "an empty profile"
        );
        // A scan from another recognizer cannot be matched, so it does not
        // refuse the NPU; an enrollment with only such scans does not admit it.
        let mut mixed = enrollment(&[&[ours, ours]]);
        mixed.profiles[0].scans.push(scan_in("embed:other", None));
        assert!(every_scan_from(&mixed, space, producer));
        let mut foreign = enrollment(&[]);
        foreign.profiles.push(irlume_core::storage::FaceProfile {
            name: "f".into(),
            scans: vec![scan_in("embed:other", ours)],
            ir_calib: None,
            ir_calibs: std::collections::BTreeMap::new(),
        });
        assert!(
            !every_scan_from(&foreign, space, producer),
            "nothing this engine can match"
        );
    }

    /// Production code embeds only through the two probe helpers or the CPU
    /// view, so no path but an admitted authentication reaches the NPU.
    #[test]
    fn production_embeds_only_through_the_probe_helpers_or_the_cpu_view() {
        fn check_sources(dir: &std::path::Path, checked: &mut Vec<std::path::PathBuf>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            for path in entries {
                let name = path.file_name().unwrap().to_str().unwrap();
                if name == "engine_tests"
                    || name.starts_with("test_support")
                    || name.ends_with("_tests.rs")
                {
                    continue;
                }
                if path.is_dir() {
                    check_sources(&path, checked);
                    continue;
                }
                if path.extension().and_then(|s| s.to_str()) != Some("rs") || name == "npu_probe.rs"
                {
                    continue;
                }
                // Include inline test modules too: this is a conservative
                // superset of production code, not a Rust parser that might
                // silently discard a production item after a test module.
                let source: String = std::fs::read_to_string(&path)
                    .unwrap()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                for call in [".emb.embed(", ".emb.embed_tta(", ".emb.embed_with_norm("] {
                    assert!(
                        !source.contains(call),
                        "{} calls {call} directly",
                        path.display()
                    );
                }
                checked.push(path);
            }
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut checked = Vec::new();
        check_sources(&src, &mut checked);
        assert!(checked.contains(&src.join("lib.rs")));
        assert!(checked.contains(&src.join("ir_assessment.rs")));
        // Only these two admitted helpers may use the placed recognizer.
        let helpers: String = include_str!("npu_probe.rs")
            .split_once("\n#[cfg(test)]\nmod tests {")
            .unwrap()
            .0
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert_eq!(helpers.matches("self.emb.embed_tta(chip)").count(), 1);
        assert_eq!(helpers.matches("self.emb.embed(chip)").count(), 1);
        assert_eq!(helpers.matches(".emb.embed_tta(").count(), 1);
        assert_eq!(helpers.matches(".emb.embed(").count(), 1);
        assert_eq!(helpers.matches(".emb.embed_with_norm(").count(), 0);
        let source = include_str!("lib.rs")
            .split("\nmod tests {")
            .next()
            .unwrap();
        for call in [".emb.embed(", ".emb.embed_tta(", ".emb.embed_with_norm("] {
            assert!(!source.contains(call), "lib.rs calls {call} directly");
        }
        assert!(source.contains("self.embed_rgb_probe("));
        assert!(source.contains("self.embed_ir_probe("));
        // Only the admission sets the flag, and the request scope clears it.
        assert_eq!(source.matches("self.npu_probe = ").count(), 1);
        assert!(source.contains("self.npu_probe = self.npu_probe_admitted(&enr);"));
        // The experimental IR-only route always uses the CPU reference.
        let ir_only = include_str!("ir_assessment.rs");
        assert_eq!(ir_only.matches("self.npu_probe = ").count(), 0);
        assert!(include_str!("authentication_window.rs").contains("self.engine.npu_probe = false;"));
    }

    /// The experimental IR-only route has no certified accelerator decision.
    #[test]
    fn ir_only_embeddings_use_the_cpu_reference() {
        let source: String = include_str!("ir_assessment.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert!(
            source.contains("self.engine.emb.on_cpu().embed(&aligned)"),
            "IR-only inference must use the CPU reference even when the recognizer is placed"
        );
        assert!(
            !source.contains("self.npu_probe="),
            "the IR-only route must not admit accelerator probes"
        );
    }

    /// Every enrollment path that embeds a scan stamps its producer.
    #[test]
    fn every_enrolled_scan_records_its_producer() {
        let source = include_str!("lib.rs")
            .split("\nmod tests {")
            .next()
            .unwrap();
        let spaces = source
            .matches("embed_space: Some(self.embed_space.clone()),")
            .count();
        assert!(spaces >= 3);
        assert_eq!(
            source
                .matches("embed_producer: embed_producer.clone(),")
                .count(),
            spaces
        );
        assert_eq!(
            source
                .matches("let embed_producer = self.embed_producer();")
                .count(),
            spaces
        );
    }
}
