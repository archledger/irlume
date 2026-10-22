// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Production GPU placement for the recognizer (ADR-0033 phase 3): the
//! loading admission before anything else, discovery and the platform
//! cache behind the same markers as the NPU, and a slot only for a model
//! the certification table names for this numerics key and consumer.

use super::certification::{self, RuntimeWitness};
use super::{gpu_reason, GpuPlatform, GpuReason, Identity, RuntimeGuard, Sources};
use crate::npu::{prepare_runtime, private_dir, runtime, Cache, Consumer, CpuReason, Slot};
use std::path::{Path, PathBuf};

/// The GPU platform opened for placement, or the reason every model runs
/// on CPU.
pub struct Context {
    state: Result<Open, CpuReason>,
    discovery: Option<Result<Identity, CpuReason>>,
}

struct Open {
    platform: GpuPlatform,
    cache: Cache,
    drm: PathBuf,
    onnx_runtime: String,
    thresholds: Vec<(String, f32)>,
    decision_fingerprint: String,
}

impl Context {
    /// GPU placement is not attempted because the administrator selected a
    /// different outcome or the GPU switch is off: every model gets
    /// `reason`. Discovery is not run.
    pub fn not_selected(reason: CpuReason) -> Self {
        Self {
            state: Err(reason),
            discovery: None,
        }
    }

    /// Open the selected runtime's GPU for a caller that consumes the
    /// recognizer's output as `consumer` says, with its cache under
    /// `cache_base`. The loading admission comes first: while it refuses,
    /// nothing is resolved, loaded or written, and every model gets that
    /// refusal (ADR-0033 section 4).
    pub fn open_with_runtime(
        cache_base: &Path,
        consumer: &Consumer<'_>,
        selection: &runtime::RuntimeSelection,
    ) -> Self {
        if runtime::admit_loading().is_err() {
            return Self::not_selected(CpuReason::Gpu(GpuReason::LoadingNotAdmitted));
        }
        Self::open_admitted_with(cache_base, consumer, || {
            let warm = cache_base.join("warmup");
            private_dir(&warm).map_err(|error| {
                CpuReason::Gpu(GpuReason::CompileFailed(format!(
                    "warm-up dir {}: {error}",
                    warm.display()
                )))
            })?;
            let platform = GpuPlatform::open(selection, &Sources::default(), &warm)?;
            // The warm-up's blobs serve no later compile.
            super::super::discard_blobs(&warm).map_err(|error| {
                CpuReason::Gpu(GpuReason::CompileFailed(format!(
                    "warm-up dir {}: {error}",
                    warm.display()
                )))
            })?;
            Ok(platform)
        })
    }

    /// Everything after the admission, with the platform opener injected.
    fn open_admitted_with(
        cache_base: &Path,
        consumer: &Consumer<'_>,
        open: impl FnOnce() -> Result<GpuPlatform, CpuReason>,
    ) -> Self {
        let mut discovery = None;
        let state = prepare_runtime(cache_base, &mut discovery, || {
            let platform = open()?;
            let identity = platform.identity().clone();
            Ok((platform, identity))
        })
        .map_err(gpu_reason)
        .map(|(platform, cache)| Open {
            platform,
            cache,
            drm: PathBuf::from("/sys/class/drm"),
            onnx_runtime: consumer.onnx_runtime.to_owned(),
            thresholds: consumer
                .thresholds
                .iter()
                .map(|(name, value)| ((*name).to_owned(), *value))
                .collect(),
            decision_fingerprint: consumer.decision_fingerprint.to_owned(),
        });
        Self {
            state,
            discovery: discovery.map(|observed| observed.map_err(gpu_reason)),
        }
    }

    /// Whether GPU discovery was attempted and completed. Missing means no
    /// runtime observation, as for an admission refusal.
    pub fn runtime_available(&self) -> Option<bool> {
        self.discovery.as_ref().map(Result::is_ok)
    }

    /// The observed GPU identity, or why there is none.
    ///
    /// # Errors
    ///
    /// The reason every model runs on CPU.
    pub fn identity(&self) -> Result<&Identity, &CpuReason> {
        match &self.discovery {
            Some(Ok(identity)) => Ok(identity),
            _ => self.state.as_ref().map(|open| open.platform.identity()),
        }
    }

    /// Place one model: on the GPU when an entry certifies it for this
    /// platform's numerics key and consumer and it compiles, on CPU with
    /// the GPU reason otherwise. An entry certified through the driver
    /// hold arms the runtime-suspend guard (ADR-0033 amendments of
    /// 2026-10-22).
    pub fn slot(&mut self, model: &[u8], model_sha256: &str) -> Slot {
        let open = match &mut self.state {
            Ok(open) => open,
            Err(reason) => return Slot::cpu(reason.clone()),
        };
        let key = match open.platform.identity().certification_key() {
            Ok(key) => key,
            Err(error) => {
                return Slot::cpu(CpuReason::Gpu(GpuReason::UnclassifiedLibrary(
                    error.to_string(),
                )))
            }
        };
        let thresholds: Vec<(&str, f32)> = open
            .thresholds
            .iter()
            .map(|(name, value)| (name.as_str(), *value))
            .collect();
        let consumer = Consumer {
            onnx_runtime: &open.onnx_runtime,
            thresholds: &thresholds,
            decision_fingerprint: &open.decision_fingerprint,
        };
        let Some(matched) = certification::certification(model_sha256, &key, &consumer) else {
            return Slot::cpu(CpuReason::Gpu(GpuReason::NotCertified));
        };
        let compiled = match open
            .platform
            .compile_certified(&open.cache, model, model_sha256)
        {
            Ok(compiled) => compiled,
            Err(reason) => return Slot::cpu(reason),
        };
        let guard = match matched.entry.runtime_witness {
            RuntimeWitness::ObservedRuntimeSuspend => None,
            RuntimeWitness::DriverHold => {
                match RuntimeGuard::arm(&open.drm, &open.platform.identity().render_node) {
                    Ok(guard) => Some(guard),
                    Err(reason) => return Slot::cpu(CpuReason::Gpu(reason)),
                }
            }
        };
        Slot::gpu_certified(compiled, matched, guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npu::Device;

    fn consumer() -> Consumer<'static> {
        Consumer {
            onnx_runtime: "1.28.1",
            thresholds: &[],
            decision_fingerprint: "x",
        }
    }

    #[test]
    fn a_gpu_context_refuses_at_the_admission_before_any_native_entry_or_write() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("gpu");
        let selection = runtime::RuntimeSelection::Automatic;
        let mut context = Context::open_with_runtime(&base, &consumer(), &selection);
        // No discovery was attempted and nothing was created on disk.
        assert_eq!(context.runtime_available(), None);
        assert!(!base.exists());
        let refusal = CpuReason::Gpu(GpuReason::LoadingNotAdmitted);
        assert_eq!(context.identity().unwrap_err(), &refusal);
        let slot = context.slot(b"model", "sha");
        assert_eq!(slot.device(), Device::Cpu(refusal.clone()));
        assert!(refusal.to_string().contains("GPU"), "{refusal}");
    }

    #[test]
    fn a_failed_gpu_discovery_is_observed_and_worded_for_the_gpu() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("gpu");
        let context = Context::open_admitted_with(&base, &consumer(), || {
            Err(CpuReason::RuntimeAbsent("no plugin".into()))
        });
        assert_eq!(context.runtime_available(), Some(false));
        let reason = context.identity().unwrap_err();
        assert_eq!(
            reason,
            &CpuReason::Gpu(GpuReason::RuntimeAbsent("no plugin".into()))
        );
        assert!(!reason.to_string().contains("NPU"), "{reason}");
    }

    #[test]
    fn a_gpu_discovery_that_did_not_return_this_boot_is_not_repeated() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("gpu");
        // A discovery marker from this boot: the earlier attempt never
        // returned.
        std::fs::create_dir_all(base.join("markers")).unwrap();
        std::fs::write(
            base.join("markers/discovery"),
            crate::npu::boot_id().unwrap(),
        )
        .unwrap();
        let mut called = false;
        let context = Context::open_admitted_with(&base, &consumer(), || {
            called = true;
            Err(CpuReason::RuntimeAbsent("unreached".into()))
        });
        assert!(!called, "the opener must not run again this boot");
        assert_eq!(
            context.identity().unwrap_err(),
            &CpuReason::Gpu(GpuReason::DidNotReturn)
        );
    }

    #[test]
    fn selection_outcomes_keep_their_own_reason() {
        for reason in [CpuReason::GpuDisabled, CpuReason::CpuSelected] {
            let mut context = Context::not_selected(reason.clone());
            assert_eq!(context.runtime_available(), None);
            assert_eq!(
                context.slot(b"m", "s").device(),
                Device::Cpu(reason.clone())
            );
            assert_eq!(gpu_reason(reason.clone()), reason);
        }
        assert_eq!(
            gpu_reason(CpuReason::DidNotReturn),
            CpuReason::Gpu(GpuReason::DidNotReturn)
        );
    }
}
