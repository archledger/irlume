// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Why a recognizer is not on the GPU, and the runtime-suspend guard of an
//! entry certified through the driver hold (ADR-0033 amendment of
//! 2026-10-22, "the runtime-suspend arm where the driver holds the
//! device").

use super::RenderNode;
use std::fmt;
use std::path::{Path, PathBuf};

/// Why the recognizer runs on CPU instead of the GPU (ADR-0033 section 3 to
/// 5 and its amendments). Every text names the GPU, so doctor and the
/// journal never attribute a GPU refusal to the NPU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GpuReason {
    /// No reviewed installation and launch profile admits loading the GPU
    /// runtime (ADR-0033 section 4); checked before `dlopen`.
    LoadingNotAdmitted,
    /// The system exposes no GPU.
    Absent,
    /// More than one GPU is exposed; no reviewed rule selects one.
    MultipleGpus(Vec<String>),
    /// The OpenVINO C API, the ONNX Runtime reference or the GPU plugin is
    /// not there.
    RuntimeAbsent(String),
    /// The GPU identity could not be read in full.
    IdentityUnreadable(String),
    /// A mapped library is on neither reviewed list, or the library
    /// manifest is ambiguous (ADR-0033 amendment of 2026-10-22).
    UnclassifiedLibrary(String),
    /// No entry certifies the model for this numerics key and CPU
    /// reference.
    NotCertified,
    /// The model's inputs do not meet the fixed configuration.
    Ineligible(String),
    /// Reading or compiling the model for the GPU failed.
    CompileFailed(String),
    /// A compile or an inference of this model on this identity did not
    /// return earlier in this boot.
    DidNotReturn,
    /// The GPU failed an inference; the model stays on CPU from then on.
    Retired(String),
    /// The startup parity check against the CPU session failed.
    ParityMismatch(String),
    /// The support set differs from the certified one and the extended
    /// reference set did not reproduce, or did not repeat.
    ExtendedParityMismatch(String),
    /// The bound device runtime-suspended with the model retained under an
    /// entry certified through the driver hold.
    RuntimeSuspended(String),
    /// The runtime-suspend counter of an entry certified through the driver
    /// hold could not be read, or the device binding changed.
    RuntimeCounter(String),
}

impl fmt::Display for GpuReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadingNotAdmitted => {
                f.write_str("the GPU loading profile has not been admitted; using CPU")
            }
            Self::Absent => f.write_str("no GPU on this system"),
            Self::MultipleGpus(devices) => write!(
                f,
                "more than one GPU ({}); no reviewed rule selects one",
                devices.join(", ")
            ),
            Self::RuntimeAbsent(why) => write!(f, "no GPU runtime: {why}"),
            Self::IdentityUnreadable(why) => write!(f, "GPU identity unreadable: {why}"),
            Self::UnclassifiedLibrary(why) => write!(f, "GPU not keyed: {why}"),
            Self::NotCertified => {
                f.write_str("not certified for this GPU platform and CPU reference")
            }
            Self::Ineligible(why) => write!(f, "not eligible for the GPU: {why}"),
            Self::CompileFailed(why) => write!(f, "GPU compile failed: {why}"),
            Self::DidNotReturn => f.write_str(
                "a GPU compile or inference of this model did not return earlier in this boot",
            ),
            Self::Retired(why) => write!(f, "GPU retired after an inference error: {why}"),
            Self::ParityMismatch(why) => write!(f, "GPU output differs from CPU: {why}"),
            Self::ExtendedParityMismatch(why) => {
                write!(f, "GPU extended reference check failed: {why}")
            }
            Self::RuntimeSuspended(why) => write!(
                f,
                "GPU runtime-suspended with the model retained, which its certification \
                 did not measure; re-certify this platform: {why}"
            ),
            Self::RuntimeCounter(why) => write!(f, "GPU runtime-suspend guard failed: {why}"),
        }
    }
}

/// The bound PCI device's runtime-suspended time, watched while a model
/// certified through the driver hold is retained. Growth means a runtime
/// suspend happened with the model retained, which that certification
/// never measured; a system suspend does not grow it.
#[derive(Debug)]
pub struct RuntimeGuard {
    /// `<drm>/<renderD>/device`, re-resolved at every check.
    device_link: PathBuf,
    /// Its canonical target when the guard was armed.
    device: PathBuf,
    /// `power/runtime_suspended_time` when the guard was armed, in ms.
    baseline_ms: u64,
}

/// The largest value the kernel's millisecond counters reach in practice;
/// anything larger is malformed.
const MAX_RUNTIME_MS: u64 = u64::MAX / 1_000_000;

fn parse_ms(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().filter(|v| *v <= MAX_RUNTIME_MS)
}

fn read_id(device: &Path, name: &str) -> Result<String, GpuReason> {
    std::fs::read_to_string(device.join(name))
        .map(|text| text.trim().to_ascii_lowercase())
        .map_err(|error| GpuReason::RuntimeCounter(format!("{name}: {error}")))
}

impl RuntimeGuard {
    /// Arm the guard on the PCI device behind `node`, under `drm`
    /// (`/sys/class/drm` in production). The device's vendor and device
    /// identifiers must be the identity's, and the counter must read.
    ///
    /// # Errors
    ///
    /// [`GpuReason::RuntimeCounter`] when the binding or the counter cannot
    /// be read, or the device is not the identity's.
    pub fn arm(drm: &Path, node: &RenderNode) -> Result<Self, GpuReason> {
        let suffix = node.name.strip_prefix("renderD").unwrap_or_default();
        if suffix.is_empty() || !suffix.bytes().all(|v| v.is_ascii_digit()) {
            return Err(GpuReason::RuntimeCounter(format!(
                "invalid render node {}",
                node.name
            )));
        }
        let device_link = drm.join(&node.name).join("device");
        let device = device_link
            .canonicalize()
            .map_err(|error| GpuReason::RuntimeCounter(format!("device binding: {error}")))?;
        let pci = device.file_name().and_then(|name| name.to_str());
        if pci != Some(node.pci.as_str())
            || read_id(&device, "vendor")? != node.vendor
            || read_id(&device, "device")? != node.device
        {
            return Err(GpuReason::RuntimeCounter(
                "the bound device is not the identity's".into(),
            ));
        }
        let mut guard = Self {
            device_link,
            device,
            baseline_ms: 0,
        };
        guard.baseline_ms = guard.read()?;
        Ok(guard)
    }

    fn read(&self) -> Result<u64, GpuReason> {
        let now = self
            .device_link
            .canonicalize()
            .map_err(|error| GpuReason::RuntimeCounter(format!("device binding: {error}")))?;
        if now != self.device {
            return Err(GpuReason::RuntimeCounter(
                "the device binding changed".into(),
            ));
        }
        let path = self.device.join("power").join("runtime_suspended_time");
        let text = std::fs::read_to_string(&path).map_err(|error| {
            GpuReason::RuntimeCounter(format!("runtime_suspended_time: {error}"))
        })?;
        parse_ms(&text).ok_or_else(|| {
            GpuReason::RuntimeCounter(format!(
                "malformed runtime_suspended_time {:?}",
                text.trim()
            ))
        })
    }

    /// Whether the device has runtime-suspended since the guard was armed.
    ///
    /// # Errors
    ///
    /// [`GpuReason::RuntimeSuspended`] when the counter grew,
    /// [`GpuReason::RuntimeCounter`] when it cannot be read or the binding
    /// changed; either retires the GPU.
    pub fn check(&self) -> Result<(), GpuReason> {
        let now = self.read()?;
        if now == self.baseline_ms {
            Ok(())
        } else {
            Err(GpuReason::RuntimeSuspended(format!(
                "runtime_suspended_time {} ms, armed at {} ms",
                now, self.baseline_ms
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _dir: tempfile::TempDir,
        drm: PathBuf,
        device: PathBuf,
        node: RenderNode,
    }

    fn fixture(counter: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("devices/pci0000:00/0000:00:02.0");
        std::fs::create_dir_all(device.join("power")).unwrap();
        std::fs::write(device.join("vendor"), "0x8086\n").unwrap();
        std::fs::write(device.join("device"), "0x64a0\n").unwrap();
        std::fs::write(device.join("power/runtime_suspended_time"), counter).unwrap();
        let drm = dir.path().join("class/drm");
        let render = drm.join("renderD128");
        std::fs::create_dir_all(render.join("power")).unwrap();
        // A decoy: the render node's own counter must never be read.
        std::fs::write(render.join("power/runtime_suspended_time"), "999999\n").unwrap();
        symlink(&device, render.join("device")).unwrap();
        Fixture {
            drm,
            device,
            node: RenderNode {
                name: "renderD128".into(),
                pci: "0000:00:02.0".into(),
                vendor: "0x8086".into(),
                device: "0x64a0".into(),
            },
            _dir: dir,
        }
    }

    #[test]
    fn the_counter_is_read_from_the_pci_device_not_the_render_node() {
        let f = fixture("173292\n");
        let guard = RuntimeGuard::arm(&f.drm, &f.node).unwrap();
        assert_eq!(guard.baseline_ms, 173_292);
        assert_eq!(guard.check(), Ok(()));
        // The decoy changing changes nothing.
        std::fs::write(f.drm.join("renderD128/power/runtime_suspended_time"), "1\n").unwrap();
        assert_eq!(guard.check(), Ok(()));
    }

    #[test]
    fn growth_of_the_counter_is_a_runtime_suspend() {
        let f = fixture("173292\n");
        let guard = RuntimeGuard::arm(&f.drm, &f.node).unwrap();
        std::fs::write(f.device.join("power/runtime_suspended_time"), "174566\n").unwrap();
        let error = guard.check().unwrap_err();
        assert!(matches!(error, GpuReason::RuntimeSuspended(_)), "{error}");
        assert!(error.to_string().contains("re-certify"), "{error}");
    }

    #[test]
    fn an_unreadable_or_malformed_counter_fails_the_guard() {
        let f = fixture("10\n");
        let guard = RuntimeGuard::arm(&f.drm, &f.node).unwrap();
        for bad in ["", "-1\n", "12 ms\n", "0x10\n"] {
            std::fs::write(f.device.join("power/runtime_suspended_time"), bad).unwrap();
            assert!(
                matches!(guard.check(), Err(GpuReason::RuntimeCounter(_))),
                "{bad:?}"
            );
        }
        std::fs::remove_file(f.device.join("power/runtime_suspended_time")).unwrap();
        assert!(matches!(guard.check(), Err(GpuReason::RuntimeCounter(_))));
        assert!(matches!(
            RuntimeGuard::arm(&f.drm, &f.node),
            Err(GpuReason::RuntimeCounter(_))
        ));
    }

    #[test]
    fn a_changed_binding_or_foreign_device_fails_the_guard() {
        let f = fixture("10\n");
        let guard = RuntimeGuard::arm(&f.drm, &f.node).unwrap();
        // Rebind the render node to another device with the same counter.
        let other = f.device.parent().unwrap().join("0000:00:03.0");
        std::fs::create_dir_all(other.join("power")).unwrap();
        std::fs::write(other.join("power/runtime_suspended_time"), "10\n").unwrap();
        let link = f.drm.join("renderD128/device");
        std::fs::remove_file(&link).unwrap();
        symlink(&other, &link).unwrap();
        assert!(matches!(guard.check(), Err(GpuReason::RuntimeCounter(_))));
        // Arming on a device whose identifiers or position differ refuses.
        let f = fixture("10\n");
        for mutate in [
            |n: &mut RenderNode| n.vendor = "0x1002".into(),
            |n: &mut RenderNode| n.device = "0xa7a1".into(),
            |n: &mut RenderNode| n.pci = "0000:00:03.0".into(),
            |n: &mut RenderNode| n.name = "card0".into(),
            |n: &mut RenderNode| n.name = "renderD".into(),
        ] {
            let mut node = f.node.clone();
            mutate(&mut node);
            assert!(
                matches!(
                    RuntimeGuard::arm(&f.drm, &node),
                    Err(GpuReason::RuntimeCounter(_))
                ),
                "{node:?}"
            );
        }
    }

    #[test]
    fn every_gpu_reason_names_the_gpu() {
        for reason in [
            GpuReason::LoadingNotAdmitted,
            GpuReason::Absent,
            GpuReason::MultipleGpus(vec!["a".into(), "b".into()]),
            GpuReason::RuntimeAbsent("x".into()),
            GpuReason::IdentityUnreadable("x".into()),
            GpuReason::UnclassifiedLibrary("x".into()),
            GpuReason::NotCertified,
            GpuReason::Ineligible("x".into()),
            GpuReason::CompileFailed("x".into()),
            GpuReason::DidNotReturn,
            GpuReason::Retired("x".into()),
            GpuReason::ParityMismatch("x".into()),
            GpuReason::ExtendedParityMismatch("x".into()),
            GpuReason::RuntimeSuspended("x".into()),
            GpuReason::RuntimeCounter("x".into()),
        ] {
            let text = reason.to_string();
            assert!(text.contains("GPU"), "{text}");
            assert!(!text.contains("NPU"), "{text}");
        }
    }
}
