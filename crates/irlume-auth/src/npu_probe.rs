//! Where the recognizer computes an embedding (ADR-0022 §2).
//!
//! Every stored template comes from the CPU reference, and each new scan
//! records that reference as its producer. Only an authentication probe can
//! run on the NPU, and only when every scan of the user's enrollment carries
//! the producer the NPU was certified against; enrollment, self-tests and
//! every other path embed on CPU.

use super::Engine;

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
            let runtime = irlume_vision::runtime_resolution().1.ok()?;
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
        if !self.recognizer_on_npu() || self.ir_adapter.is_some() || self.ir_adapter_required {
            return false;
        }
        let Some(producer) = self.embed_producer() else {
            return false;
        };
        every_scan_from(enrollment, &producer)
    }

    #[cfg(feature = "npu")]
    fn recognizer_on_npu(&self) -> bool {
        self.emb.npu_device() == irlume_vision::npu::Device::Npu
    }

    #[cfg(not(feature = "npu"))]
    fn recognizer_on_npu(&self) -> bool {
        false
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

    /// Place the recognizer for `npu`: on the NPU when its entry certifies
    /// this platform and consumer and it compiles and reproduces the entry's
    /// digests, on CPU with the reason otherwise (ADR-0022 §3, §8, §9). The
    /// producer is computed now, so an authentication never pays for it.
    ///
    /// # Errors
    ///
    /// When the CPU session cannot be rebuilt from `weights`.
    #[cfg(feature = "npu")]
    pub fn with_npu_recognizer(
        mut self,
        weights: &irlume_common::HashedModel,
        npu: &mut irlume_vision::npu::Context,
    ) -> irlume_common::Result<Self> {
        if format!("embed:{}", weights.sha256()) != self.embed_space {
            return Err(irlume_common::Error::Policy(
                "the NPU recognizer must be the loaded recognizer".into(),
            ));
        }
        self.emb = irlume_vision::Embedder::load_with_npu(weights, npu)?;
        self.embed_producer = None;
        let _ = self.embed_producer();
        Ok(self)
    }
}

/// Whether `enrollment` has scans and every one records `producer`.
fn every_scan_from(enrollment: &irlume_core::storage::Enrollment, producer: &str) -> bool {
    let mut scans = enrollment
        .profiles
        .iter()
        .flat_map(|profile| &profile.scans)
        .peekable();
    scans.peek().is_some() && scans.all(|scan| scan.embed_producer.as_deref() == Some(producer))
}

#[cfg(test)]
mod tests {
    use super::every_scan_from;
    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};

    fn scan(producer: Option<&str>) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.0; 4],
            ir: None,
            ir_space: None,
            embed_space: Some("embed:test".into()),
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
        assert!(every_scan_from(
            &enrollment(&[&[ours, ours], &[ours]]),
            producer
        ));
        assert!(!every_scan_from(&enrollment(&[&[ours, None]]), producer));
        assert!(!every_scan_from(
            &enrollment(&[&[ours], &[Some("cpu:a:ort-1.27.0:d")]]),
            producer
        ));
        assert!(!every_scan_from(&enrollment(&[]), producer), "no scans");
        assert!(
            !every_scan_from(&enrollment(&[&[]]), producer),
            "an empty profile"
        );
    }

    /// Production code embeds only through the two probe helpers or the CPU
    /// view, so no path but an admitted authentication reaches the NPU.
    #[test]
    fn production_embeds_only_through_the_probe_helpers_or_the_cpu_view() {
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
        assert!(include_str!("authentication_window.rs").contains("self.engine.npu_probe = false;"));
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
