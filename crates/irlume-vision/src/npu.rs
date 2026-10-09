// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Optional NPU inference under per-model certification (ADR-0022).
//!
//! CPU stays the reference. A model runs on the NPU only when its SHA-256,
//! the running platform identity and the loaded ONNX Runtime all match an
//! entry of [`CERTIFIED`] (ADR-0022 §3, §4); every other combination, and
//! every failure, leaves it on its ONNX Runtime CPU session. The NPU only
//! computes the model's output tensor: the caller decodes it with the same
//! code as the CPU output, and every threshold stays where it is (§2).
//!
//! The OpenVINO C API is loaded at run time from an absolute path (§5);
//! absence is a recoverable "no NPU" answer, never an error. Compilation
//! happens when a model is loaded, with the batch fixed to 1 (§6, §8). A
//! marker around every compile and inference bounds a crash or a hang to one
//! daemon restart (§10), and compiled blobs go to a root-only cache per
//! identity (§11).

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Read as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

mod identity;
mod maps;
mod runtime;
pub use runtime::{library_setting, LibrarySetting, RuntimeSelection};

/// The original reviewed OpenVINO C API soname (2026.2.0), retained for
/// callers and the legacy runtime. The resolver also accepts the reviewed
/// patch release in `REVIEWED_OPENVINO_C_SONAMES` (ADR-0022 section 5).
pub const OPENVINO_C_SONAME: &str = "libopenvino_c.so.2620";

/// Reviewed C declarations, not certified model/platform triples. Prefer
/// 2026.2.1 when both releases are installed. Its whole C-header directory
/// (20 file/tree entries) is Git-object-identical to 2026.2.0:
/// https://github.com/openvinotoolkit/openvino/tree/2026.2.1/src/bindings/c/include/openvino/c
/// Runtime/library hashes still produce a new identity and require a new
/// certification; accepting a soname never places a model on the NPU.
const REVIEWED_OPENVINO_C_SONAMES: &[&str] = &["libopenvino_c.so.2621", OPENVINO_C_SONAME];

/// Standard system and administrator source-install roots. An explicit
/// [`RuntimeSelection`] supports other root-managed provider locations.
/// The loader always receives a validated absolute file, never a bare
/// loader name or the user's library-search environment (ADR-0022 section 5).
pub const OPENVINO_LIBRARY_DIRS: &[&str] = &[
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib",
    "/usr/local/lib64",
    "/usr/local/lib/x86_64-linux-gnu",
    "/usr/local/lib",
];

/// How every model is compiled for the NPU (ADR-0022 §6). It changes
/// outputs, so it is part of [`Identity`]: editing it moves the digest and
/// leaves no certification entry matching until the models are certified
/// again. The compiler is forced to the plugin's own (`PREFER_PLUGIN`, the
/// default, may fall back to the driver's, a different NPU program; the
/// 1.38.0 driver offers none). The plugin's default precision is f16, the
/// only floating-point value it accepts (2026.2.0: "Supported values: f16,
/// i8"). `NPU_TURBO` stays unset: OpenVINO documents it as raising power and
/// not meant for sustained use.
pub const COMPILE_CONFIGURATION: &str = "batch=1;NPU_COMPILER_TYPE=PLUGIN;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=default(f16);NPU_TURBO=unset";

/// The compiler [`COMPILE_CONFIGURATION`] forces.
const COMPILER_TYPE: &str = "PLUGIN";

/// Where [`Platform::open`] reads the platform facts.
struct Sources<'a> {
    library_dirs: &'a [&'a str],
    accel_class: &'a Path,
    debugfs_accel: &'a Path,
    maps: &'a Path,
    /// Apply `NPU_COMPILER_TYPE` from [`COMPILE_CONFIGURATION`]; only a
    /// hardware experiment measuring OpenVINO's default leaves it.
    force_compiler: bool,
}

/// The platform a compiled NPU model depends on (ADR-0022 §4). Any field
/// that differs is a different identity. The kernel release is deliberately
/// not a field: the kernel driver does not compute outputs, Fedora ships a
/// kernel every few days, and §10 bounds a crash it might cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The selected absolute OpenVINO C API path, preserving the legacy
    /// soname alias. Native loading uses its validated canonical endpoint.
    pub library: String,
    /// OpenVINO's runtime build string.
    pub openvino_build: String,
    /// The NPU plugin's build string.
    pub npu_plugin: String,
    /// The plugin's `NPU_DRIVER_VERSION`.
    pub driver_version: String,
    /// The plugin's `NPU_COMPILER_VERSION` (major in the high 16 bits).
    pub compiler_version: String,
    /// The plugin's `DEVICE_ARCHITECTURE`.
    pub architecture: String,
    /// PCI `vendor:device` of the accelerator node, lower-case hex.
    pub pci_id: String,
    /// The build of the firmware the kernel loaded, from the device's
    /// `fw_version` debugfs entry.
    pub firmware: String,
    /// [`COMPILE_CONFIGURATION`].
    pub configuration: String,
    /// `path sha256` of every OpenVINO and Level Zero library the daemon
    /// maps once the NPU is enumerated, plus the NPU compiler and ONNX
    /// frontend that compiling loads, one line each, sorted: a rebuilt
    /// library that keeps its version string is still a different identity.
    pub libraries: String,
}

impl Identity {
    fn fields(&self) -> [&str; 10] {
        [
            &self.library,
            &self.openvino_build,
            &self.npu_plugin,
            &self.driver_version,
            &self.compiler_version,
            &self.architecture,
            &self.pci_id,
            &self.firmware,
            &self.configuration,
            &self.libraries,
        ]
    }

    /// SHA-256 over the fields, each prefixed by its byte length, so no
    /// two different identities share a digest by moving text between
    /// adjacent fields. Names the cache directory and keys [`CERTIFIED`].
    pub fn digest(&self) -> String {
        let mut encoded = Vec::new();
        for field in self.fields() {
            encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
            encoded.extend_from_slice(field.as_bytes());
        }
        irlume_common::sha256_hex(&encoded)
    }
}

/// Which model an entry certifies, so its CPU reference fingerprint can be
/// recomputed from the current code. Only the recognizer is eligible
/// (ADR-0022 §3): the PAD cues are deny-only evidence with narrow attack
/// margins, and on the qualified stack their NPU drift exceeded the
/// allowance (the NPU offers no f32 inference); the detectors and meshes
/// stay on CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The recognizer ([`crate::Embedder`]).
    Recognizer,
}

/// One certified (model, platform identity, CPU reference) triple
/// (ADR-0022 §3, §7).
#[derive(Clone, Copy, Debug)]
pub struct Certification {
    /// SHA-256 of the model file, as in `models/SHA256SUMS`.
    pub model_sha256: &'static str,
    /// Which model it is.
    pub role: Role,
    /// The qualified execution key from [`Identity::execution_digest`], or
    /// a legacy exact [`Identity::digest`]. Both bind all numerical content;
    /// only execution keys can cover equivalent installation relocations.
    pub identity_digest: &'static str,
    /// The ONNX Runtime version of the CPU reference.
    pub onnx_runtime: &'static str,
    /// The wired thresholds that consume the output, by constant name, at
    /// their certified values.
    pub thresholds: &'static [(&'static str, f32)],
    /// The recognition decision downstream of the output, as irlume-auth
    /// fingerprints it: the SHA-256 of what the production decision code
    /// (IR calibration, Platt scaling, brightness weighting, fusion,
    /// template selection and the grant verdicts) returns for fixed
    /// synthetic scores and brightness weights (ADR-0022 §3).
    pub decision_fingerprint: &'static str,
    /// The decoded CPU outputs for the fixed synthetic inputs of
    /// `npu_reference_fingerprint`, at certification; tests on any host
    /// compare them within a tolerance to catch preprocessing changes.
    pub fingerprint: &'static [f32],
    /// SHA-256 of the CPU session's raw output bits for the same reference
    /// inputs, at certification. The CPU session is deterministic on one
    /// host and runtime, so every engine build requires these exact bits
    /// before the model answers from the NPU (ADR-0022 §3).
    pub cpu_reference_digest: &'static str,
    /// SHA-256 of the NPU's raw output bits for the same reference inputs,
    /// at certification. The NPU is deterministic across processes on the
    /// qualified stack, so every engine build requires these exact bits
    /// before the model answers from the NPU (ADR-0022 §8).
    pub npu_reference_digest: &'static str,
    /// Where the certification evidence is recorded.
    pub evidence: &'static str,
}

/// Every certified triple. Empty until certification evidence lands
/// (ADR-0022 Phasing 3), so every model runs on CPU on every platform.
pub const CERTIFIED: &[Certification] = &[];

/// How the caller consumes the recognizer's output, live (ADR-0022 §3):
/// the ONNX Runtime its CPU sessions load, the wired thresholds by constant
/// name, and the fingerprint of its recognition decision code. An entry
/// applies only when all of it matches: its measured drift was judged at
/// its own operating points and through its own decision code.
#[derive(Clone, Copy, Debug)]
pub struct Consumer<'a> {
    /// The loaded ONNX Runtime version.
    pub onnx_runtime: &'a str,
    /// The wired thresholds that consume the output, by constant name.
    pub thresholds: &'a [(&'a str, f32)],
    /// [`Certification::decision_fingerprint`], computed now.
    pub decision_fingerprint: &'a str,
}

/// The entry certifying `model_sha256` for `identity` and `consumer`, if
/// any (ADR-0022 §3). This legacy API matches only exact identities; portable
/// matching additionally requires a platform's complete execution inventory.
pub fn certification(
    model_sha256: &str,
    identity: &Identity,
    consumer: &Consumer<'_>,
) -> Option<&'static Certification> {
    certification_for_identity(CERTIFIED, model_sha256, identity, None, consumer)
}

fn certification_for_identity<'t>(
    table: &'t [Certification],
    model_sha256: &str,
    identity: &Identity,
    execution_manifest: Option<&str>,
    consumer: &Consumer<'_>,
) -> Option<&'t Certification> {
    // Preserve already reviewed exact keys; a new execution key is an
    // explicitly qualified alternative, not an automatic widening of them.
    if let Some(entry) = certification_in(table, model_sha256, &identity.digest(), consumer) {
        return Some(entry);
    }
    let execution = identity
        .execution_digest_from_manifest(execution_manifest?)
        .ok()?;
    certification_in(table, model_sha256, &execution, consumer)
}

fn certification_in<'t>(
    table: &'t [Certification],
    model_sha256: &str,
    identity_digest: &str,
    consumer: &Consumer<'_>,
) -> Option<&'t Certification> {
    table.iter().find(|entry| {
        entry.model_sha256 == model_sha256
            && entry.identity_digest == identity_digest
            && entry.onnx_runtime == consumer.onnx_runtime
            && same_thresholds(entry.thresholds, consumer.thresholds)
            && entry.decision_fingerprint == consumer.decision_fingerprint
    })
}

/// The same names, each once on both sides, with bit-identical values, in
/// any order.
fn same_thresholds(certified: &[(&str, f32)], wired: &[(&str, f32)]) -> bool {
    let once = |list: &[(&str, f32)], name: &str| {
        list.iter().filter(|(listed, _)| *listed == name).count() == 1
    };
    certified.len() == wired.len()
        && certified.iter().all(|(name, value)| {
            once(certified, name)
                && once(wired, name)
                && wired.iter().any(|(wired_name, wired_value)| {
                    wired_name == name && wired_value.to_bits() == value.to_bits()
                })
        })
}

/// What `settings.conf` holds for the `npu` key.
#[derive(Clone, Copy, Debug)]
pub enum Setting<'a> {
    /// No `settings.conf`, or no `npu` key in it.
    Absent,
    /// The key's raw value.
    Value(&'a [u8]),
    /// `settings.conf` exists but cannot be read.
    Unreadable,
}

/// The `npu` key of a `settings.conf` file's bytes: absent when no line
/// names it; otherwise the first value that does not allow the NPU, or else
/// the first value, so any line switching it off wins. A file that is not
/// UTF-8 is unreadable, which selects CPU (ADR-0022 §12).
pub fn settings_conf_value(bytes: &[u8]) -> Setting<'_> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Setting::Unreadable;
    };
    let values: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| key.trim() == "npu")
        .map(|(_, value)| value.trim())
        .collect();
    let off = values
        .iter()
        .find(|value| !switch_allows(None, Setting::Value(value.as_bytes())));
    match off.or(values.first()) {
        Some(value) => Setting::Value(value.as_bytes()),
        None => Setting::Absent,
    }
}

/// The `IRLUME_NPU` / `npu` switch (ADR-0022 §12): `true` leaves the table
/// to decide, `false` keeps every model on CPU. Only an absent source or a
/// recognized on value (`1`, `true`, `yes`, `on`, trimmed, any ASCII case)
/// allows the NPU; an off value, an empty, malformed or non-UTF-8 value and
/// an unreadable `settings.conf` all select the reference path, and either
/// source disabling wins.
pub fn switch_allows(env: Option<&OsStr>, setting: Setting<'_>) -> bool {
    fn on(raw: &[u8]) -> bool {
        std::str::from_utf8(raw).is_ok_and(|text| {
            matches!(
                text.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
    }
    let env_allows = env.is_none_or(|value| on(value.as_bytes()));
    let setting_allows = match setting {
        Setting::Absent => true,
        Setting::Value(raw) => on(raw),
        Setting::Unreadable => false,
    };
    env_allows && setting_allows
}

/// Why a model runs on CPU (ADR-0022 §13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpuReason {
    /// NPU use is switched off, or the model was loaded without an NPU
    /// context.
    Disabled,
    /// No reviewed installation/launch profile admits native loading. This
    /// is independent of model certification and is checked before dlopen.
    LoadingNotAdmitted,
    /// The OpenVINO C API, the ONNX Runtime reference or the NPU is not
    /// there.
    RuntimeAbsent(String),
    /// The platform identity could not be read in full.
    IdentityUnreadable(String),
    /// The model is not certified for this identity and CPU reference.
    NotCertified,
    /// The model's inputs do not meet ADR-0022 §6.
    Ineligible(String),
    /// Reading or compiling the model for the NPU failed.
    CompileFailed(String),
    /// A compile or an inference of this model on this identity did not
    /// return earlier in this boot.
    DidNotReturn,
    /// The NPU failed an inference; the model stays on CPU from then on.
    Retired(String),
    /// The startup parity check against the CPU session failed.
    ParityMismatch(String),
}

impl fmt::Display for CpuReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("NPU use is disabled"),
            Self::LoadingNotAdmitted => {
                f.write_str("the NPU loading profile has not been admitted; using CPU")
            }
            Self::RuntimeAbsent(why) => write!(f, "no NPU runtime: {why}"),
            Self::IdentityUnreadable(why) => write!(f, "NPU identity unreadable: {why}"),
            Self::NotCertified => {
                f.write_str("not certified for this NPU platform and CPU reference")
            }
            Self::Ineligible(why) => write!(f, "not eligible for the NPU: {why}"),
            Self::CompileFailed(why) => write!(f, "NPU compile failed: {why}"),
            Self::DidNotReturn => f.write_str(
                "an NPU compile or inference of this model did not return earlier in this boot",
            ),
            Self::Retired(why) => write!(f, "NPU retired after an inference error: {why}"),
            Self::ParityMismatch(why) => write!(f, "NPU output differs from CPU: {why}"),
        }
    }
}

/// Where a model runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Device {
    /// On the NPU.
    Npu,
    /// On its CPU session, and why.
    Cpu(CpuReason),
}

/// An NPU-compiled model: one `f32` input in, its first `f32` output back.
pub trait Infer: Send {
    /// Run one inference.
    ///
    /// # Errors
    ///
    /// Any runtime failure, as text for [`CpuReason::Retired`].
    fn infer(&mut self, input: &[f32]) -> Result<Vec<f32>, String>;
}

/// A model's place on the NPU, or the reason it has none.
pub struct Slot {
    state: State,
}

enum State {
    Cpu(CpuReason),
    Npu {
        model: Box<dyn Infer>,
        entry: Option<&'static Certification>,
        /// [`suspended`] when the entry's digests were last reproduced;
        /// `None` until the first check.
        checked_at: Option<Duration>,
    },
}

impl Slot {
    /// A model that runs on CPU for `reason`.
    pub fn cpu(reason: CpuReason) -> Self {
        Self {
            state: State::Cpu(reason),
        }
    }

    /// A model compiled for the NPU without a certified reference digest:
    /// the hardware tests' placements only.
    #[cfg(test)]
    pub(crate) fn npu(model: Box<dyn Infer>) -> Self {
        Self {
            state: State::Npu {
                model,
                entry: None,
                checked_at: None,
            },
        }
    }

    /// A model compiled for the NPU under `entry`, whose CPU fingerprint and
    /// NPU reference digest must both be reproduced before it answers
    /// (ADR-0022 §3, §8).
    pub(crate) fn certified(model: Box<dyn Infer>, entry: &'static Certification) -> Self {
        Self {
            state: State::Npu {
                model,
                entry: Some(entry),
                checked_at: None,
            },
        }
    }

    /// Record that the entry's digests were reproduced by a check that
    /// started at `baseline`, a [`Bound::AtMost`] reading taken before its
    /// first inference, so a suspend during or after the check is seen.
    pub(crate) fn note_checked(&mut self, baseline: Option<Duration>) {
        if let State::Npu { checked_at, .. } = &mut self.state {
            *checked_at = baseline;
        }
    }

    /// Whether a certified model must reproduce its NPU reference digest
    /// again before it answers: the system has suspended since the last
    /// check, or the clocks cannot be read (ADR-0022 §8).
    pub(crate) fn resumed_since_check(&self) -> bool {
        let State::Npu {
            entry: Some(_),
            checked_at,
            ..
        } = &self.state
        else {
            return false;
        };
        match (checked_at, suspended(Bound::AtLeast)) {
            (Some(then), Some(now)) => now > *then + RESUME_GRANULARITY,
            _ => true,
        }
    }

    /// Forget the last check, as a system resume would, for tests.
    #[cfg(test)]
    pub(crate) fn forget_check(&mut self) {
        if let State::Npu { checked_at, .. } = &mut self.state {
            *checked_at = None;
        }
    }

    /// The entry the model is on the NPU under, if any.
    pub fn certification(&self) -> Option<&'static Certification> {
        match &self.state {
            State::Npu { entry, .. } => *entry,
            State::Cpu(_) => None,
        }
    }

    /// Where the model runs now.
    pub fn device(&self) -> Device {
        match &self.state {
            State::Cpu(reason) => Device::Cpu(reason.clone()),
            State::Npu { .. } => Device::Npu,
        }
    }

    /// Run `input` on the NPU and decode the output with the caller's CPU
    /// decoder. `None` means "use the CPU session": the model is not on the
    /// NPU, or the NPU or the decoder failed, in which case the model is
    /// retired to CPU for the rest of its life and the caller computes this
    /// same call on CPU (ADR-0022 §9).
    pub fn run<T>(
        &mut self,
        input: &[f32],
        decode: impl FnOnce(&[f32]) -> irlume_common::Result<T>,
    ) -> Option<T> {
        let State::Npu { model, .. } = &mut self.state else {
            return None;
        };
        let outcome = model
            .infer(input)
            .and_then(|raw| decode(&raw).map_err(|error| error.to_string()));
        match outcome {
            Ok(value) => Some(value),
            Err(why) => {
                self.state = State::Cpu(CpuReason::Retired(why));
                None
            }
        }
    }
}

impl Default for Slot {
    fn default() -> Self {
        Self::cpu(CpuReason::Disabled)
    }
}

/// Growth of [`suspended`] below this is read jitter, not a suspend.
const RESUME_GRANULARITY: Duration = Duration::from_millis(1);

/// Which side of the true value a [`suspended`] reading may fall on.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Bound {
    /// Never more than the time suspended: for the baseline of a check.
    AtMost,
    /// Never less than the time suspended: for the comparison against it.
    AtLeast,
}

/// How long the system has been suspended since boot: `CLOCK_BOOTTIME`
/// counts suspended time and `CLOCK_MONOTONIC` does not (clock_gettime(2)).
/// The NPU's runtime power-down while idle is not a system suspend and does
/// not count. A delay between the two reads, such as a preemption, moves
/// the result toward `bound`: reading `CLOCK_BOOTTIME` first can only
/// understate, and `CLOCK_MONOTONIC` first can only overstate. A baseline
/// read [`Bound::AtMost`] and a later reading [`Bound::AtLeast`] therefore
/// never hide a suspend; a delay can only cause an extra check.
pub(crate) fn suspended(bound: Bound) -> Option<Duration> {
    fn read(clock: libc::clockid_t) -> Option<Duration> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a writable timespec and the clock IDs are Linux
        // clocks.
        if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
            return None;
        }
        Some(Duration::new(
            u64::try_from(ts.tv_sec).ok()?,
            u32::try_from(ts.tv_nsec).ok()?,
        ))
    }
    let (boottime, monotonic) = match bound {
        Bound::AtMost => {
            let boottime = read(libc::CLOCK_BOOTTIME)?;
            (boottime, read(libc::CLOCK_MONOTONIC)?)
        }
        Bound::AtLeast => {
            let monotonic = read(libc::CLOCK_MONOTONIC)?;
            (read(libc::CLOCK_BOOTTIME)?, monotonic)
        }
    };
    let measured = boottime.saturating_sub(monotonic);
    #[cfg(test)]
    let measured = measured + SIMULATED_SUSPEND.with(std::cell::Cell::get);
    Some(measured)
}

#[cfg(test)]
thread_local! {
    /// Suspended time added to [`suspended`] on this thread, for tests.
    static SIMULATED_SUSPEND: std::cell::Cell<Duration> =
        const { std::cell::Cell::new(Duration::ZERO) };
}

/// Pretend this thread's system suspended for `duration`, for tests.
#[cfg(test)]
pub(crate) fn simulate_suspend(duration: Duration) {
    SIMULATED_SUSPEND.with(|suspended| suspended.set(suspended.get() + duration));
}

/// The boot this process runs in, for markers.
///
/// # Errors
///
/// When `/proc/sys/kernel/random/boot_id` cannot be read.
pub fn boot_id() -> io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

/// What a marker says about an earlier compile or inference (ADR-0022 §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    /// Nothing is outstanding.
    Absent,
    /// A compile or an inference started in this boot and never returned.
    CurrentBoot,
    /// One started in an earlier boot and never returned.
    EarlierBoot,
}

/// One model's marker file: armed with the boot ID before a compile or an
/// inference, removed when it returns.
struct MarkerFile {
    path: PathBuf,
    boot_id: String,
}

impl MarkerFile {
    /// A marker that exists but cannot be read, or holds no boot ID, counts
    /// as one from this boot (ADR-0022 §10).
    fn state(&self) -> Marker {
        match fs::read_to_string(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Marker::Absent,
            Ok(written) if is_boot_id(written.trim()) && written.trim() != self.boot_id => {
                Marker::EarlierBoot
            }
            _ => Marker::CurrentBoot,
        }
    }

    /// Commit the marker before OpenVINO is entered: a temporary file renamed
    /// into place and read back, so a failure leaves no half-written marker
    /// and is an error the caller turns into CPU.
    fn arm(&self) -> io::Result<()> {
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, &self.boot_id)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temporary, &self.path)?;
        if fs::read_to_string(&self.path)?.trim() != self.boot_id {
            return Err(io::Error::other("the marker did not read back"));
        }
        Ok(())
    }

    fn disarm(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

/// The daemon-owned cache of one platform identity (ADR-0022 §11):
/// `<base>/<identity digest>/blobs/` holds OpenVINO's compiled blobs and
/// `<base>/markers/` the markers of every identity, so a marker outlives a
/// switch to another identity and back within one boot (§10). Every
/// directory is 0700. With `CACHE_DIR` set, the NPU plugin
/// bypasses the driver's own blob cache, so this is the only one; a blob
/// OpenVINO cannot import is deleted and compiled again by OpenVINO itself.
pub struct Cache {
    dir: PathBuf,
    markers: PathBuf,
    digest: String,
    boot_id: String,
}

impl Cache {
    /// Create (or reuse) the directory for `identity` under `base`, remove
    /// the blob directories of other identities and the markers of earlier
    /// boots.
    ///
    /// # Errors
    ///
    /// When a directory cannot be created, restricted to 0700 or listed.
    pub fn prepare(base: &Path, identity: &Identity, boot_id: &str) -> io::Result<Self> {
        let digest = identity.digest();
        private_dir(base)?;
        for entry in fs::read_dir(base)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Only directories this cache made: 64 hex digits. Anything
            // else under the base is left alone.
            if name != digest.as_str() && is_identity_digest(&name) && entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            }
        }
        let dir = base.join(&digest);
        private_dir(&dir)?;
        private_dir(&dir.join("blobs"))?;
        let markers = base.join("markers");
        private_dir(&markers)?;
        for entry in fs::read_dir(&markers)? {
            let path = entry?.path();
            // A leftover temporary file was never renamed, so OpenVINO was
            // not entered; an earlier boot's marker allows one new attempt
            // anyway. A marker that cannot be read stays, and counts as
            // current.
            let stale = path.extension().is_some_and(|e| e == "tmp")
                || fs::read_to_string(&path)
                    .is_ok_and(|written| is_boot_id(written.trim()) && written.trim() != boot_id);
            if stale {
                fs::remove_file(&path)?;
            }
        }
        Ok(Self {
            dir,
            markers,
            digest,
            boot_id: boot_id.to_owned(),
        })
    }

    /// The directory OpenVINO writes compiled blobs to.
    pub fn blobs(&self) -> PathBuf {
        self.dir.join("blobs")
    }

    fn marker_file(&self, model_sha256: &str) -> MarkerFile {
        MarkerFile {
            path: self.markers.join(format!("{}-{model_sha256}", self.digest)),
            boot_id: self.boot_id.clone(),
        }
    }

    /// The state of `model_sha256`'s marker.
    pub fn marker(&self, model_sha256: &str) -> Marker {
        self.marker_file(model_sha256).state()
    }
}

/// A boot ID as the kernel writes it (a UUID), or as the tests name one.
fn is_boot_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_identity_digest(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn private_dir(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error),
        _ => {}
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

/// Compile behind the marker (ADR-0022 §10): a marker from this boot means
/// a compile or an inference never returned, so `compile` is not called;
/// otherwise the marker is armed for the duration of `compile` and removed
/// when it returns, whatever it returned.
fn compile_guarded<T>(
    marker: &MarkerFile,
    compile: impl FnOnce() -> Result<T, CpuReason>,
) -> Result<T, CpuReason> {
    run_guarded(marker, || (compile(), true))
}

/// [`compile_guarded`] for an operation that can leave state a later
/// attempt must not trust: when it answers `false` with its result, the
/// marker stays armed, so the model stays on CPU for the rest of the boot
/// (ADR-0022 §10).
fn run_guarded<T>(
    marker: &MarkerFile,
    operation: impl FnOnce() -> (Result<T, CpuReason>, bool),
) -> Result<T, CpuReason> {
    if marker.state() == Marker::CurrentBoot {
        return Err(CpuReason::DidNotReturn);
    }
    marker
        .arm()
        .map_err(|error| CpuReason::CompileFailed(format!("cannot write the marker: {error}")))?;
    let (result, clear) = operation();
    if clear {
        marker.disarm().map_err(|error| {
            CpuReason::CompileFailed(format!("cannot clear the marker: {error}"))
        })?;
    }
    result
}

/// Remove every file a rejected compile left in `blobs`; any failure is
/// returned, not ignored.
fn discard_blobs(blobs: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(blobs) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        entries => entries?,
    };
    for entry in entries {
        fs::remove_file(entry?.path())?;
    }
    Ok(())
}

/// An NPU model whose every inference is bracketed by its marker, so a
/// crash or a watchdog kill mid-inference keeps the model on CPU after the
/// restart (ADR-0022 §10).
struct Marked {
    inner: Box<dyn Infer>,
    marker: MarkerFile,
}

impl Infer for Marked {
    fn infer(&mut self, input: &[f32]) -> Result<Vec<f32>, String> {
        self.marker
            .arm()
            .map_err(|error| format!("cannot write the marker: {error}"))?;
        let output = self.inner.infer(input);
        self.marker
            .disarm()
            .map_err(|error| format!("cannot clear the marker: {error}"))?;
        output
    }
}

/// The input shape compiled for the NPU: the model's own shape with a
/// dynamic batch fixed to 1 (ADR-0022 §6). `None` is a dynamic dimension.
/// Only the batch may be dynamic; a batch fixed at anything but 1, or any
/// other dynamic dimension, makes the model ineligible.
fn fixed_batch_shape(dimensions: &[Option<i64>]) -> Result<Vec<i64>, CpuReason> {
    let Some((batch, rest)) = dimensions.split_first() else {
        return Err(CpuReason::Ineligible("the input has rank 0".into()));
    };
    match batch {
        None | Some(1) => {}
        Some(other) => {
            return Err(CpuReason::Ineligible(format!(
                "the input batch is fixed at {other}"
            )))
        }
    }
    let mut shape = vec![1];
    for (index, dimension) in rest.iter().enumerate() {
        match dimension {
            Some(size) if *size > 0 => shape.push(*size),
            _ => {
                return Err(CpuReason::Ineligible(format!(
                    "input dimension {} is not static",
                    index + 1
                )))
            }
        }
    }
    Ok(shape)
}

/// Turn a panic inside the binding (it panics on a symbol it cannot find
/// or a device name it does not know) into a CPU answer.
fn catch_binding<T>(
    operation: impl FnOnce() -> Result<T, CpuReason>,
    on_panic: CpuReason,
) -> Result<T, CpuReason> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or(Err(on_panic))
}

/// A reviewed soname from a listed directory, always an absolute path.
/// Newer reviewed patch releases precede the legacy runtime.
#[cfg(test)]
fn resolve_library(dirs: &[&str]) -> Result<PathBuf, CpuReason> {
    REVIEWED_OPENVINO_C_SONAMES
        .iter()
        .flat_map(|soname| dirs.iter().map(move |dir| Path::new(dir).join(soname)))
        .find(|path| path.is_absolute() && path.is_file())
        .ok_or_else(|| {
            CpuReason::RuntimeAbsent(format!(
                "{} is in none of {}",
                REVIEWED_OPENVINO_C_SONAMES.join(" or "),
                dirs.join(", ")
            ))
        })
}

/// Prove the library at absolute `path` loads before the binding sees it,
/// and keep the handle for the life of the process, as the ONNX Runtime
/// probe does: the binding then opens the same object, and a library that
/// does not load is an error message instead of a binding panic.
fn probe_library(path: &Path) -> Result<(), CpuReason> {
    if !path.is_absolute() {
        return Err(CpuReason::RuntimeAbsent(format!(
            "{} is not an absolute path",
            path.display()
        )));
    }
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| CpuReason::RuntimeAbsent(format!("{} contains a NUL byte", path.display())))?;
    // SAFETY: dlopen and dlerror with a valid NUL-terminated absolute path;
    // the error string is copied out before any other dl call. The handle
    // is deliberately never closed (see above).
    unsafe {
        let handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let why = libc::dlerror();
            let why = if why.is_null() {
                "dlopen failed with no message".to_owned()
            } else {
                std::ffi::CStr::from_ptr(why).to_string_lossy().into_owned()
            };
            return Err(CpuReason::RuntimeAbsent(why));
        }
    }
    Ok(())
}

/// The only accelerator node: its PCI `vendor:device` and bus address.
/// More than one node is not a platform anything is certified for.
fn accelerator(class: &Path) -> Result<(String, String), CpuReason> {
    let unreadable = |why: String| CpuReason::IdentityUnreadable(why);
    let mut nodes = fs::read_dir(class)
        .map_err(|error| unreadable(format!("{}: {error}", class.display())))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("accel"))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    if nodes.len() != 1 {
        return Err(unreadable(format!(
            "{} accelerator nodes under {}",
            nodes.len(),
            class.display()
        )));
    }
    let device = nodes.remove(0).join("device");
    let read = |name: &str| {
        let path = device.join(name);
        fs::read_to_string(&path)
            .map_err(|error| unreadable(format!("{}: {error}", path.display())))
            .map(|text| text.trim().trim_start_matches("0x").to_ascii_lowercase())
    };
    let pci_id = format!("{}:{}", read("vendor")?, read("device")?);
    let bus_address = fs::canonicalize(&device)
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .ok_or_else(|| unreadable(format!("{}: no bus address", device.display())))?;
    Ok((pci_id, bus_address))
}

/// The firmware build the kernel loaded for the device at `bus_address`,
/// from its read-only `fw_version` debugfs entry (root only; readable under
/// `ProtectKernelTunables=` and kernel lockdown).
fn firmware_build(debugfs_accel: &Path, bus_address: &str) -> Result<String, CpuReason> {
    let path = debugfs_accel.join(bus_address).join("fw_version");
    let build = fs::read_to_string(&path)
        .map_err(|error| {
            CpuReason::IdentityUnreadable(format!("firmware build {}: {error}", path.display()))
        })?
        .trim()
        .to_owned();
    if build.is_empty() {
        return Err(CpuReason::IdentityUnreadable(format!(
            "firmware build {} is empty",
            path.display()
        )));
    }
    Ok(build)
}

/// A runtime library as the identity hashed it: the file the bytes were read
/// from, by inode. Not by device: on btrfs `stat` reports the subvolume's
/// anonymous device and `/proc/self/maps` the filesystem's (0:37 and 00:23
/// on the measured host). An update renames a new file into place, created
/// while the old inode is still allocated, so it always has a new inode.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HashedLibrary {
    path: PathBuf,
    inode: u64,
}

fn is_runtime_library(path: &str) -> bool {
    // Frozen legacy identity membership. Never use this path-spelling rule
    // for portable qualification or the complete loaded-code check.
    path.starts_with('/') && (path.contains("openvino") || path.contains("/libze_"))
}

#[derive(Clone, Copy)]
enum InventoryScope {
    Legacy,
    Execution,
}

impl InventoryScope {
    fn includes(self, mapping: &maps::Mapping<'_>) -> bool {
        match self {
            Self::Legacy => is_runtime_library(mapping.path),
            // Conservatively bind ALL file-backed executable mappings,
            // including the process binary and unrelated native libraries.
            // This avoids guessing the transitive dependency/plugin closure.
            Self::Execution => mapping.executable && Path::new(mapping.path).is_absolute(),
        }
    }
}

/// Every OpenVINO and Level Zero library the process has mapped must be one
/// the identity hashed and still the same file, by inode (ADR-0022 §4), so
/// a package update between hashing and loading cannot run bytes the
/// identity does not name.
#[cfg(test)]
fn loaded_as_hashed(maps: &str, hashed: &[HashedLibrary]) -> Result<(), String> {
    verify_mappings(maps, hashed, InventoryScope::Legacy)
}

fn execution_loaded_as_hashed(maps: &str, hashed: &[HashedLibrary]) -> Result<(), String> {
    verify_mappings(maps, hashed, InventoryScope::Execution)
}

fn verify_mappings(
    maps: &str,
    hashed: &[HashedLibrary],
    scope: InventoryScope,
) -> Result<(), String> {
    for line in maps.lines() {
        let Some(mapping) = maps::mapping(line) else {
            continue;
        };
        let path = mapping.path;
        if !scope.includes(&mapping)
            && !hashed
                .iter()
                .any(|library| library.path.as_os_str() == OsStr::new(path))
        {
            continue;
        }
        let library = hashed
            .iter()
            .find(|library| library.path.as_os_str() == OsStr::new(path))
            .ok_or_else(|| format!("{path} is mapped but was not hashed"))?;
        if mapping.inode.parse::<u64>().ok() != Some(library.inode) || mapping.deleted {
            return Err(format!("{path} is not the file that was hashed"));
        }
    }
    Ok(())
}

/// The runtime libraries of the identity, from the process's memory map:
/// every mapped OpenVINO and Level Zero library, plus the NPU compiler loader
/// beside the NPU plugin, which applying the compile configuration loads, and
/// the NPU compiler beside the plugin and the IR and ONNX frontends beside
/// the core, which compiling loads. The C API, the core, the NPU plugin, the Level Zero
/// loader and the NPU user-mode driver must all be there, and every mapped
/// one must be the file that was hashed.
fn runtime_libraries(maps: &str) -> Result<(String, Vec<HashedLibrary>), CpuReason> {
    library_inventory(maps, InventoryScope::Legacy)
}

fn execution_libraries(
    maps: &str,
    executable: &Path,
) -> Result<(String, Vec<HashedLibrary>), CpuReason> {
    let (manifest, hashed) = library_inventory(maps, InventoryScope::Execution)?;
    let mut libraries = String::new();
    let mut found_executable = false;
    for line in manifest.lines() {
        let (path, _) = line.rsplit_once(' ').ok_or_else(|| {
            CpuReason::IdentityUnreadable("malformed executable inventory".into())
        })?;
        if Path::new(path) == executable {
            found_executable = true;
        } else {
            libraries.push_str(line);
            libraries.push('\n');
        }
    }
    if !found_executable {
        return Err(CpuReason::IdentityUnreadable(
            "the process executable is absent from the mapped inventory".into(),
        ));
    }
    // Keep the main executable's mapping/inode check, but not its content in
    // a key compiled into that same executable. CPU producer/decision/parity
    // bindings still apply; every shared native library remains in this key.
    Ok((libraries, hashed))
}

fn library_inventory(
    maps: &str,
    scope: InventoryScope,
) -> Result<(String, Vec<HashedLibrary>), CpuReason> {
    let unreadable = |why: String| CpuReason::IdentityUnreadable(why);
    let mut paths: Vec<PathBuf> = maps
        .lines()
        .filter_map(maps::mapping)
        .filter(|mapping| scope.includes(mapping))
        .map(|mapping| mapping.path)
        .map(PathBuf::from)
        .collect();
    let named = |prefix: &str| {
        paths
            .iter()
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
            })
            .cloned()
    };
    for required in [
        "libopenvino_c.so.",
        "libze_loader.so.",
        "libze_intel_npu.so.",
    ] {
        named(required).ok_or_else(|| unreadable(format!("no {required} mapped")))?;
    }
    let plugin = named("libopenvino_intel_npu_plugin.so")
        .ok_or_else(|| unreadable("no NPU plugin mapped".into()))?;
    let core =
        named("libopenvino.so.").ok_or_else(|| unreadable("no OpenVINO core mapped".into()))?;
    let version = core
        .file_name()
        .and_then(|name| {
            name.to_string_lossy()
                .strip_prefix("libopenvino.so.")
                .map(str::to_owned)
        })
        .ok_or_else(|| unreadable("unversioned OpenVINO core".into()))?;
    paths.push(plugin.with_file_name("libopenvino_intel_npu_compiler_loader.so"));
    paths.push(plugin.with_file_name("libopenvino_intel_npu_compiler.so"));
    paths.push(core.with_file_name(format!("libopenvino_ir_frontend.so.{version}")));
    paths.push(core.with_file_name(format!("libopenvino_onnx_frontend.so.{version}")));
    paths.sort();
    paths.dedup();
    let mut lines = String::new();
    let mut hashed = Vec::with_capacity(paths.len());
    for path in &paths {
        // Hashed through one open file, whose inode is kept.
        let failed = |error: io::Error| unreadable(format!("{}: {error}", path.display()));
        let mut file = fs::File::open(path).map_err(failed)?;
        let metadata = file.metadata().map_err(failed)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(failed)?;
        lines.push_str(&format!(
            "{} {}\n",
            path.display(),
            irlume_common::sha256_hex(&bytes)
        ));
        hashed.push(HashedLibrary {
            path: path.clone(),
            inode: metadata.ino(),
        });
    }
    verify_mappings(maps, &hashed, scope).map_err(unreadable)?;
    Ok((lines, hashed))
}

/// The OpenVINO runtime and the NPU behind it.
pub struct Platform {
    core: openvino::Core,
    identity: Identity,
    libraries: Vec<HashedLibrary>,
    execution_manifest: String,
    maps: PathBuf,
}

impl Platform {
    /// Load the certified OpenVINO C API and read the NPU's identity.
    ///
    /// # Errors
    ///
    /// [`CpuReason::RuntimeAbsent`] when the library, the binding or the
    /// NPU device is missing; [`CpuReason::IdentityUnreadable`] when a
    /// field of [`Identity`] cannot be read.
    pub fn open() -> Result<Self, CpuReason> {
        Self::open_with_runtime(&RuntimeSelection::Automatic)
    }

    /// Open an administrator-selected upstream, distro or source runtime.
    /// Provider branding is not an eligibility field.
    ///
    /// # Errors
    ///
    /// A rejected/untrusted selection, an absent reviewed C API or NPU, or
    /// unreadable platform identity fields. A rejected explicit selection
    /// never falls through to another installed provider.
    pub fn open_with_runtime(selection: &RuntimeSelection) -> Result<Self, CpuReason> {
        let sources = Sources {
            library_dirs: OPENVINO_LIBRARY_DIRS,
            accel_class: Path::new("/sys/class/accel"),
            debugfs_accel: Path::new("/sys/kernel/debug/accel"),
            maps: Path::new("/proc/self/maps"),
            force_compiler: true,
        };
        let library =
            runtime::resolve_library(selection, sources.library_dirs, &runtime::Trust::default())?;
        Self::open_library(&sources, library.canonical, library.selected)
    }

    #[cfg(test)]
    fn open_with(sources: &Sources<'_>) -> Result<Self, CpuReason> {
        let library = resolve_library(sources.library_dirs)?;
        Self::open_library(sources, library.clone(), library)
    }

    fn open_library(
        sources: &Sources<'_>,
        library: PathBuf,
        selected: PathBuf,
    ) -> Result<Self, CpuReason> {
        use openvino::{DeviceType, PropertyKey, RwPropertyKey};
        runtime::admit_loading()?;
        probe_library(&library)?;
        let (pci_id, bus_address) = accelerator(sources.accel_class)?;
        let firmware = firmware_build(sources.debugfs_accel, &bus_address)?;
        catch_binding(
            || {
                let absent = |why: String| CpuReason::RuntimeAbsent(why);
                openvino_sys::library::load_from(&library).map_err(absent)?;
                let mut core = openvino::Core::new().map_err(|error| absent(error.to_string()))?;
                let devices = core
                    .available_devices()
                    .map_err(|error| absent(error.to_string()))?;
                if !devices.iter().any(|device| device.as_ref() == "NPU") {
                    return Err(absent("OpenVINO lists no NPU device".into()));
                }
                let unreadable = |what: &str, error: &dyn fmt::Display| {
                    CpuReason::IdentityUnreadable(format!("{what}: {error}"))
                };
                let property = |key: &'static str| {
                    core.get_property(&DeviceType::NPU, &PropertyKey::Other(key.into()))
                        .map_err(|error| unreadable(key, &error))
                };
                let npu_plugin = core
                    .versions("NPU")
                    .map_err(|error| unreadable("NPU plugin version", &error))?
                    .into_iter()
                    .map(|(_, version)| version.build_number)
                    .next()
                    .ok_or_else(|| CpuReason::IdentityUnreadable("no NPU plugin version".into()))?;
                let maps = fs::read_to_string(sources.maps)
                    .map_err(|error| CpuReason::IdentityUnreadable(format!("maps: {error}")))?;
                let (libraries, _) = runtime_libraries(&maps)?;
                let executable = fs::read_link("/proc/self/exe").map_err(|error| {
                    CpuReason::IdentityUnreadable(format!("process executable: {error}"))
                })?;
                let (execution_manifest, hashed) = execution_libraries(&maps, &executable)?;
                let identity = Identity {
                    library: selected.display().to_string(),
                    openvino_build: openvino::version().build_number,
                    npu_plugin,
                    driver_version: property("NPU_DRIVER_VERSION")?,
                    compiler_version: property("NPU_COMPILER_VERSION")?,
                    architecture: property("DEVICE_ARCHITECTURE")?,
                    pci_id,
                    firmware,
                    configuration: COMPILE_CONFIGURATION.to_owned(),
                    libraries,
                };
                // COMPILE_CONFIGURATION, applied: the plugin compiler, read
                // back so a fallback cannot pass for it, and the latency
                // hint; the default precision and no NPU_TURBO are left as
                // they are.
                if sources.force_compiler {
                    core.set_property(
                        &DeviceType::NPU,
                        &RwPropertyKey::Other("NPU_COMPILER_TYPE".into()),
                        COMPILER_TYPE,
                    )
                    .map_err(|error| absent(format!("NPU_COMPILER_TYPE: {error}")))?;
                    let compiler = core
                        .get_property(
                            &DeviceType::NPU,
                            &PropertyKey::Other("NPU_COMPILER_TYPE".into()),
                        )
                        .map_err(|error| absent(format!("NPU_COMPILER_TYPE: {error}")))?;
                    if compiler != COMPILER_TYPE {
                        return Err(absent(format!(
                            "NPU_COMPILER_TYPE reads {compiler:?}, not {COMPILER_TYPE}"
                        )));
                    }
                }
                core.set_property(
                    &DeviceType::NPU,
                    &RwPropertyKey::HintPerformanceMode,
                    "LATENCY",
                )
                .map_err(|error| absent(format!("PERFORMANCE_HINT: {error}")))?;
                Ok(Self {
                    core,
                    identity,
                    libraries: hashed,
                    execution_manifest,
                    maps: sources.maps.to_path_buf(),
                })
            },
            CpuReason::RuntimeAbsent("the OpenVINO binding panicked while loading".into()),
        )
    }

    /// [`Self::open`] with the firmware build read from `debugfs_accel`
    /// instead of the kernel's debugfs, for the hardware tests a normal user
    /// runs, and with `force_compiler` false to leave OpenVINO's default
    /// compiler type for an experiment that measures it.
    #[cfg(test)]
    pub(crate) fn open_with_debugfs(
        debugfs_accel: &Path,
        force_compiler: bool,
    ) -> Result<Self, CpuReason> {
        Self::open_with(&Sources {
            library_dirs: OPENVINO_LIBRARY_DIRS,
            accel_class: Path::new("/sys/class/accel"),
            debugfs_accel,
            maps: Path::new("/proc/self/maps"),
            force_compiler,
        })
    }

    /// Set one NPU compile property outside [`COMPILE_CONFIGURATION`], for
    /// hardware experiments only.
    #[cfg(test)]
    pub(crate) fn set_npu_property(&mut self, key: &'static str, value: &str) {
        self.core
            .set_property(
                &openvino::DeviceType::NPU,
                &openvino::RwPropertyKey::Other(key.into()),
                value,
            )
            .unwrap();
    }

    /// Read one NPU property, for hardware experiments only.
    #[cfg(test)]
    pub(crate) fn npu_property(&self, key: &'static str) -> Result<String, String> {
        self.core
            .get_property(
                &openvino::DeviceType::NPU,
                &openvino::PropertyKey::Other(key.into()),
            )
            .map_err(|error| error.to_string())
    }

    /// The platform identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Portable key from the full observed file-backed executable inventory,
    /// plus the known compiler/frontends loaded during compilation. This
    /// conservatively binds unrelated native libraries too. The main executable
    /// is omitted from this key to avoid self-reference with the compiled table,
    /// but remains in the mapped-file verification inventory.
    ///
    /// # Errors
    ///
    /// Empty, malformed or duplicate-basename inventory entries.
    pub fn execution_digest(&self) -> Result<String, &'static str> {
        self.identity
            .execution_digest_from_manifest(&self.execution_manifest)
    }

    /// Compile `model` for the NPU with the batch fixed to 1, into `cache`,
    /// behind its marker; every inference of the result is bracketed by the
    /// same marker (ADR-0022 §6, §10, §11).
    ///
    /// # Errors
    ///
    /// The [`CpuReason`] that keeps the model on CPU.
    pub fn compile(
        &mut self,
        cache: &Cache,
        model: &[u8],
        model_sha256: &str,
    ) -> Result<Box<dyn Infer>, CpuReason> {
        let marker = cache.marker_file(model_sha256);
        // The marker stays armed until the loaded libraries are validated
        // and anything a compile with other bytes wrote is discarded; if that
        // cannot be removed, it stays armed for the rest of the boot.
        let inner = run_guarded(&marker, || {
            let inner = match catch_binding(
                || self.compile_unguarded(cache, model),
                CpuReason::CompileFailed("the OpenVINO binding panicked while compiling".into()),
            ) {
                Ok(inner) => inner,
                // Refused before OpenVINO compiled anything.
                Err(reason @ CpuReason::Ineligible(_)) => return (Err(reason), true),
                // A compile that failed after OpenVINO may have written its
                // cache output (a failed device query or infer request)
                // leaves nothing to import.
                Err(reason) => {
                    return match discard_blobs(&cache.blobs()) {
                        Ok(()) => (Err(reason), true),
                        Err(error) => (
                            Err(CpuReason::CompileFailed(format!(
                                "{reason}; its cache output could not be removed ({error}), so \
                                 its marker stays for this boot"
                            ))),
                            false,
                        ),
                    };
                }
            };
            // The libraries compiling loaded must be the ones the identity
            // hashed (ADR-0022 §4).
            let loaded = fs::read_to_string(&self.maps)
                .map_err(|error| format!("maps: {error}"))
                .and_then(|maps| execution_loaded_as_hashed(&maps, &self.libraries));
            if let Err(why) = loaded {
                drop(inner);
                return match discard_blobs(&cache.blobs()) {
                    Ok(()) => (Err(CpuReason::CompileFailed(why)), true),
                    Err(error) => (
                        Err(CpuReason::CompileFailed(format!(
                            "{why}; its cache output could not be removed ({error}), so its \
                             marker stays for this boot"
                        ))),
                        false,
                    ),
                };
            }
            (Ok(inner), true)
        })?;
        Ok(Box::new(Marked { inner, marker }))
    }

    fn compile_unguarded(
        &mut self,
        cache: &Cache,
        model_bytes: &[u8],
    ) -> Result<Box<dyn Infer>, CpuReason> {
        use openvino::{DeviceType, PartialShape, PropertyKey, RwPropertyKey};
        let failed = |what: &str, error: &dyn fmt::Display| {
            CpuReason::CompileFailed(format!("{what}: {error}"))
        };
        let mut model = self
            .core
            .read_model_from_buffer(model_bytes, None)
            .map_err(|error| failed("read", &error))?;
        let inputs = model
            .get_inputs_len()
            .map_err(|error| failed("inputs", &error))?;
        if inputs != 1 {
            return Err(CpuReason::Ineligible(format!(
                "the model has {inputs} inputs"
            )));
        }
        let partial = model
            .get_input_by_index(0)
            .and_then(|input| input.get_partial_shape())
            .map_err(|error| failed("input shape", &error))?;
        if partial.get_rank().is_dynamic() {
            return Err(CpuReason::Ineligible("the input rank is dynamic".into()));
        }
        let dimensions = partial
            .get_dimensions()
            .iter()
            .map(|dimension| (!dimension.is_dynamic()).then(|| dimension.get_min()))
            .collect::<Vec<_>>();
        let input_shape = fixed_batch_shape(&dimensions)?;
        if partial.is_dynamic() {
            let fixed = PartialShape::new_static(input_shape.len() as i64, &input_shape)
                .map_err(|error| failed("fixed shape", &error))?;
            model
                .reshape_single_input(&fixed)
                .map_err(|error| failed("reshape", &error))?;
        }
        let blobs = cache.blobs();
        let blobs = blobs
            .to_str()
            .ok_or_else(|| CpuReason::CompileFailed("the cache path is not UTF-8".into()))?;
        self.core
            .set_property(&DeviceType::NPU, &RwPropertyKey::CacheDir, blobs)
            .map_err(|error| failed("CACHE_DIR", &error))?;
        let mut compiled = self
            .core
            .compile_model(&model, DeviceType::NPU)
            .map_err(|error| failed("compile", &error))?;
        let assignment = compiled
            .get_property(&PropertyKey::Other("EXECUTION_DEVICES".into()))
            .map_err(|error| failed("EXECUTION_DEVICES", &error))?;
        if assignment.trim() != "NPU" {
            return Err(CpuReason::CompileFailed(format!(
                "OpenVINO assigned {:?}, not NPU",
                assignment.trim()
            )));
        }
        let request = compiled
            .create_infer_request()
            .map_err(|error| failed("infer request", &error))?;
        Ok(Box::new(NpuModel {
            _compiled: compiled,
            request,
            input_shape,
        }))
    }
}

struct NpuModel {
    // Owns the compiled model the request runs; dropped after it.
    _compiled: openvino::CompiledModel,
    request: openvino::InferRequest,
    input_shape: Vec<i64>,
}

impl Infer for NpuModel {
    fn infer(&mut self, input: &[f32]) -> Result<Vec<f32>, String> {
        use openvino::{ElementType, Shape, Tensor};
        let outcome = catch_binding(
            || {
                let failed = |what: &str, error: &dyn fmt::Display| {
                    CpuReason::Retired(format!("{what}: {error}"))
                };
                let shape =
                    Shape::new(&self.input_shape).map_err(|error| failed("shape", &error))?;
                let mut tensor = Tensor::new(ElementType::F32, &shape)
                    .map_err(|error| failed("input tensor", &error))?;
                let target = tensor
                    .get_data_mut::<f32>()
                    .map_err(|error| failed("input data", &error))?;
                if target.len() != input.len() {
                    return Err(CpuReason::Retired(format!(
                        "input has {} values, the compiled model takes {}",
                        input.len(),
                        target.len()
                    )));
                }
                target.copy_from_slice(input);
                self.request
                    .set_input_tensor(&tensor)
                    .map_err(|error| failed("set input", &error))?;
                self.request
                    .infer()
                    .map_err(|error| failed("infer", &error))?;
                // The C API hands back a new wrapper the caller frees
                // (`ov_infer_request_get_output_tensor_by_index`, 2026.2.0),
                // so dropping it is right; `Tensor::set_shape`, which aliases
                // its pointer (intel/openvino-rs#184), is never called.
                let output = self
                    .request
                    .get_output_tensor_by_index(0)
                    .map_err(|error| failed("output", &error))?;
                if output
                    .get_element_type()
                    .map_err(|error| failed("output type", &error))?
                    != ElementType::F32
                {
                    return Err(CpuReason::Retired("the output is not f32".into()));
                }
                Ok(output
                    .get_data::<f32>()
                    .map_err(|error| failed("output data", &error))?
                    .to_vec())
            },
            CpuReason::Retired("the OpenVINO binding panicked during inference".into()),
        );
        outcome.map_err(|reason| match reason {
            CpuReason::Retired(why) => why,
            other => other.to_string(),
        })
    }
}

/// What a daemon needs to put models on the NPU: the platform, its cache and
/// the CPU reference's ONNX Runtime version, or why there are none.
pub struct Context {
    state: Result<Open, CpuReason>,
    discovery: Option<Result<Identity, CpuReason>>,
}

struct Open {
    platform: Platform,
    cache: Cache,
    onnx_runtime: String,
    thresholds: Vec<(String, f32)>,
    decision_fingerprint: String,
}

impl Context {
    /// NPU use is off: every model gets [`CpuReason::Disabled`].
    pub fn disabled() -> Self {
        Self {
            state: Err(CpuReason::Disabled),
            discovery: None,
        }
    }

    /// Open the platform and prepare its cache under `cache_base`, for a
    /// caller that consumes the recognizer's output as `consumer` says. A
    /// failure is kept as the reason every model then runs on CPU.
    pub fn open(cache_base: &Path, consumer: &Consumer<'_>) -> Self {
        Self::open_with_runtime(cache_base, consumer, &RuntimeSelection::Automatic)
    }

    /// Open the selected root-managed runtime with this CPU consumer.
    /// Discovery is separate from model qualification; failures preserve CPU.
    pub fn open_with_runtime(
        cache_base: &Path,
        consumer: &Consumer<'_>,
        selection: &RuntimeSelection,
    ) -> Self {
        let mut discovery = None;
        let state = prepare_runtime(cache_base, &mut discovery, || {
            let platform = Platform::open_with_runtime(selection)?;
            let identity = platform.identity().clone();
            Ok((platform, identity))
        })
        .map(|(platform, cache)| Open {
            platform,
            cache,
            onnx_runtime: consumer.onnx_runtime.to_owned(),
            thresholds: consumer
                .thresholds
                .iter()
                .map(|(name, value)| ((*name).to_owned(), *value))
                .collect(),
            decision_fingerprint: consumer.decision_fingerprint.to_owned(),
        });
        Self { state, discovery }
    }

    /// Whether discovery was attempted and completed successfully. Missing
    /// means no runtime observation, independently of model placement.
    pub fn runtime_available(&self) -> Option<bool> {
        self.discovery.as_ref().map(Result::is_ok)
    }

    /// The observed platform identity, or why there is none. A later cache or
    /// marker-cleanup failure does not discard an already observed identity.
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

    /// Place one model: on the NPU when it is certified for this platform
    /// and consumer and compiles, on CPU with the reason otherwise
    /// (ADR-0022 §3, §9).
    pub fn slot(&mut self, model: &[u8], model_sha256: &str) -> Slot {
        let open = match &mut self.state {
            Ok(open) => open,
            Err(reason) => return Slot::cpu(reason.clone()),
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
        let Some(entry) = certification_for_identity(
            CERTIFIED,
            model_sha256,
            open.platform.identity(),
            Some(&open.platform.execution_manifest),
            &consumer,
        ) else {
            return Slot::cpu(CpuReason::NotCertified);
        };
        match open.platform.compile(&open.cache, model, model_sha256) {
            Ok(compiled) => Slot::certified(compiled, entry),
            Err(reason) => Slot::cpu(reason),
        }
    }
}

/// Run the real marker/cache state machine around a discovery boundary. The
/// generic payload lets filesystem regressions exercise it without native code.
fn prepare_runtime<P>(
    cache_base: &Path,
    observation: &mut Option<Result<Identity, CpuReason>>,
    discover: impl FnOnce() -> Result<(P, Identity), CpuReason>,
) -> Result<(P, Cache), CpuReason> {
    *observation = None;
    let state = (|| {
        let boot = boot_id()
            .map_err(|error| CpuReason::IdentityUnreadable(format!("boot id: {error}")))?;
        let markers = cache_base.join("markers");
        private_dir(cache_base)
            .and_then(|()| private_dir(&markers))
            .map_err(|error| {
                CpuReason::CompileFailed(format!("cache {}: {error}", cache_base.display()))
            })?;
        let marker = MarkerFile {
            path: markers.join("discovery"),
            boot_id: boot.clone(),
        };
        let (platform, identity) = compile_guarded(&marker, || {
            let result = discover();
            // Record the observation at its boundary, before marker cleanup
            // or cache preparation can fail. Admission refusal observed no
            // runtime; a discovery failure did attempt it.
            if !matches!(result, Err(CpuReason::LoadingNotAdmitted)) {
                *observation = Some(
                    result
                        .as_ref()
                        .map(|(_, identity)| identity.clone())
                        .map_err(Clone::clone),
                );
            }
            result
        })?;
        let cache = Cache::prepare(cache_base, &identity, &boot).map_err(|error| {
            CpuReason::CompileFailed(format!("cache {}: {error}", cache_base.display()))
        })?;
        Ok((platform, cache, identity))
    })();
    state.map(|(platform, cache, _)| (platform, cache))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_prefix_spaces_preserve_loaded_library_inode_and_deletion_checks() {
        let path = PathBuf::from("/opt/provider runtime/libopenvino.so.2026.2.1");
        let hashed = [HashedLibrary {
            path: path.clone(),
            inode: 42,
        }];
        let line = format!("0000-1000 r-xp 00000000 00:23 42 {}\n", path.display());
        assert_eq!(loaded_as_hashed(&line, &hashed), Ok(()));
        let changed = line.replace("00:23 42", "00:23 43");
        assert!(loaded_as_hashed(&changed, &hashed).is_err());
        let deleted = format!("{} (deleted)\n", line.trim_end());
        assert!(loaded_as_hashed(&deleted, &hashed).is_err());
    }

    fn portable_identity() -> Identity {
        let mut value = identity();
        value.libraries = format!(
            "/usr/lib64/libopenvino_c.so.2026.2.1 {}\n/usr/lib64/openvino-2026.2.1/libopenvino_intel_npu_plugin.so {}\n",
            "a".repeat(64), "b".repeat(64)
        );
        value
    }

    #[test]
    fn execution_identity_is_layout_portable_without_changing_full_identity() {
        let original = portable_identity();
        let mut moved = original.clone();
        moved.library = "/opt/upstream/runtime/lib/libopenvino_c.so.2621".into();
        moved.libraries = original
            .libraries
            .replace("/usr/lib64", "/opt/upstream/runtime/lib");
        assert_ne!(original.digest(), moved.digest());
        assert_eq!(
            original.execution_digest().unwrap(),
            moved.execution_digest().unwrap()
        );
    }

    #[test]
    fn execution_identity_keeps_all_numerical_and_library_content_fields() {
        let original = portable_identity();
        let before = original.execution_digest().unwrap();
        let edits: [fn(&mut Identity); 9] = [
            |i| i.openvino_build.push('x'),
            |i| i.npu_plugin.push('x'),
            |i| i.driver_version.push('x'),
            |i| i.compiler_version.push('x'),
            |i| i.architecture.push('x'),
            |i| i.pci_id.push('x'),
            |i| i.firmware.push('x'),
            |i| i.configuration.push('x'),
            |i| i.libraries = i.libraries.replace(&"a".repeat(64), &"c".repeat(64)),
        ];
        for edit in edits {
            let mut different = original.clone();
            edit(&mut different);
            assert_ne!(different.execution_digest().unwrap(), before);
        }
    }

    #[test]
    fn ambiguous_or_malformed_content_manifests_cannot_be_qualified() {
        let mut value = portable_identity();
        for bad in [
            "".to_owned(),
            "/lib/library.so no-hash\n".into(),
            format!(
                "/first/library.so {}\n/second/library.so {}\n",
                "a".repeat(64),
                "a".repeat(64)
            ),
            format!("relative/library.so {}\n", "a".repeat(64)),
        ] {
            value.libraries = bad;
            assert!(value.execution_digest().is_err());
        }
    }

    fn entry(key: String) -> Certification {
        Certification {
            model_sha256: "model",
            role: Role::Recognizer,
            identity_digest: Box::leak(key.into_boxed_str()),
            onnx_runtime: "1.28.1",
            thresholds: &[],
            decision_fingerprint: "decision",
            fingerprint: &[],
            cpu_reference_digest: "cpu",
            npu_reference_digest: "npu",
            evidence: "synthetic",
        }
    }

    #[test]
    fn portable_qualification_matches_equivalent_layout_but_legacy_keys_stay_exact() {
        let original = portable_identity();
        let mut moved = original.clone();
        moved.library = "/usr/local/lib/libopenvino_c.so.2621".into();
        moved.libraries = original.libraries.replace("/usr/lib64", "/usr/local/lib");
        let consumer = Consumer {
            onnx_runtime: "1.28.1",
            thresholds: &[],
            decision_fingerprint: "decision",
        };
        let portable = [entry(original.execution_digest().unwrap())];
        assert!(certification_for_identity(
            &portable,
            "model",
            &moved,
            Some(&moved.libraries),
            &consumer
        )
        .is_some());
        assert!(
            certification_for_identity(&portable, "model", &moved, None, &consumer).is_none(),
            "legacy inventory cannot admit a portable key"
        );
        let legacy = [entry(original.digest())];
        assert!(certification_for_identity(&legacy, "model", &original, None, &consumer).is_some());
        assert!(certification_for_identity(
            &legacy,
            "model",
            &moved,
            Some(&moved.libraries),
            &consumer
        )
        .is_none());
        let mut modified = moved.clone();
        modified.libraries = moved.libraries.replace(&"b".repeat(64), &"c".repeat(64));
        assert!(certification_for_identity(
            &portable,
            "model",
            &modified,
            Some(&modified.libraries),
            &consumer
        )
        .is_none());
        assert!(certification_for_identity(
            &portable,
            "model",
            &moved,
            Some(&moved.libraries),
            &Consumer {
                onnx_runtime: "1.29.0",
                ..consumer
            }
        )
        .is_none());
    }

    #[test]
    fn the_header_identical_patch_runtime_resolves_from_a_listed_directory() {
        let listed = tempfile::tempdir().unwrap();
        let patch = listed.path().join("libopenvino_c.so.2621");
        fs::write(&patch, b"").unwrap();
        assert_eq!(
            resolve_library(&[listed.path().to_str().unwrap()]),
            Ok(patch)
        );
    }

    #[test]
    fn the_patch_runtime_is_preferred_and_the_reviewed_legacy_runtime_still_resolves() {
        let listed = tempfile::tempdir().unwrap();
        let legacy = listed.path().join(OPENVINO_C_SONAME);
        let patch = listed.path().join("libopenvino_c.so.2621");
        fs::write(&legacy, b"").unwrap();
        fs::write(&patch, b"").unwrap();
        assert_eq!(
            resolve_library(&[listed.path().to_str().unwrap()]),
            Ok(patch.clone())
        );
        fs::remove_file(patch).unwrap();
        assert_eq!(
            resolve_library(&[listed.path().to_str().unwrap()]),
            Ok(legacy)
        );
    }

    fn identity() -> Identity {
        Identity {
            library: format!("/usr/lib64/{OPENVINO_C_SONAME}"),
            openvino_build: "2026.2.0-000--".into(),
            npu_plugin: "2026.2.0-000--".into(),
            driver_version: "1788996950".into(),
            compiler_version: "524290".into(),
            architecture: "4000".into(),
            pci_id: "8086:643e".into(),
            firmware: "Aug 20 2026*NPU40xx*build".into(),
            configuration: COMPILE_CONFIGURATION.into(),
            libraries: "/usr/lib64/libze_loader.so.1.32.0 00\n".into(),
        }
    }

    #[test]
    fn identity_digest_changes_with_every_field_and_cannot_shift_text() {
        let base = identity();
        let digest = base.digest();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, identity().digest(), "deterministic");
        let edits: [fn(&mut Identity); 10] = [
            |i| i.library.push('x'),
            |i| i.openvino_build.push('x'),
            |i| i.npu_plugin.push('x'),
            |i| i.driver_version.push('x'),
            |i| i.compiler_version.push('x'),
            |i| i.architecture.push('x'),
            |i| i.pci_id.push('x'),
            |i| i.firmware.push('x'),
            |i| i.configuration.push('x'),
            |i| i.libraries.push('x'),
        ];
        for edit in edits {
            let mut changed = base.clone();
            edit(&mut changed);
            assert_ne!(changed.digest(), digest);
        }
        // Moving a character from one field to the next is a different
        // identity, not the same bytes under a different split.
        let mut left = base.clone();
        left.driver_version = "17889969".into();
        left.compiler_version = "50524290".into();
        let mut right = base;
        right.driver_version = "1788996950".into();
        right.compiler_version = "524290".into();
        assert_ne!(left.digest(), right.digest());
    }

    #[test]
    fn the_shipped_table_certifies_nothing() {
        // Changes only with certification evidence (ADR-0022 Phasing 3).
        assert_eq!(CERTIFIED.len(), 0);
        let consumer = Consumer {
            onnx_runtime: "1.28.1",
            thresholds: &[],
            decision_fingerprint: "",
        };
        assert!(certification(&"0".repeat(64), &identity(), &consumer).is_none());
    }

    #[test]
    fn certification_matches_only_the_exact_triple() {
        let model = "a".repeat(64);
        let digest = identity().digest();
        let leaked_model: &'static str = Box::leak(model.clone().into_boxed_str());
        let leaked_digest: &'static str = Box::leak(digest.clone().into_boxed_str());
        let table = [Certification {
            model_sha256: leaked_model,
            role: Role::Recognizer,
            identity_digest: leaked_digest,
            onnx_runtime: "1.28.1",
            thresholds: &[("RGB_MATCH_THRESHOLD", 0.55)],
            decision_fingerprint: "decision",
            fingerprint: &[0.5],
            cpu_reference_digest: "c",
            npu_reference_digest: "d",
            evidence: "test",
        }];
        let wired = [("RGB_MATCH_THRESHOLD", 0.55)];
        let consumer = Consumer {
            onnx_runtime: "1.28.1",
            thresholds: &wired,
            decision_fingerprint: "decision",
        };
        let found = certification_in(&table, &model, &digest, &consumer);
        assert_eq!(found.map(|entry| entry.role), Some(Role::Recognizer));
        assert_eq!(found.map(|entry| entry.npu_reference_digest), Some("d"));
        assert!(certification_in(&table, &"b".repeat(64), &digest, &consumer).is_none());
        assert!(
            certification_in(
                &table,
                &model,
                &digest,
                &Consumer {
                    onnx_runtime: "1.29.0",
                    ..consumer
                }
            )
            .is_none(),
            "another CPU reference is not certified"
        );
        assert!(
            certification_in(
                &table,
                &model,
                &digest,
                &Consumer {
                    decision_fingerprint: "changed decision code",
                    ..consumer
                }
            )
            .is_none(),
            "changed decision code is not certified"
        );
        let mut other = identity();
        other.firmware = "another firmware build".into();
        assert!(certification_in(&table, &model, &other.digest(), &consumer).is_none());
        // A moved threshold, an added one, a missing one or a renamed one
        // is another operating point.
        for wired in [
            &[("RGB_MATCH_THRESHOLD", 0.56)][..],
            &[("RGB_MATCH_THRESHOLD", 0.55), ("IR_MATCH_THRESHOLD", 0.5)][..],
            &[][..],
            &[("IR_MATCH_THRESHOLD", 0.55)][..],
            &[("RGB_MATCH_THRESHOLD", 0.55), ("RGB_MATCH_THRESHOLD", 0.55)][..],
        ] {
            assert!(
                certification_in(
                    &table,
                    &model,
                    &digest,
                    &Consumer {
                        thresholds: wired,
                        ..consumer
                    }
                )
                .is_none(),
                "{wired:?}"
            );
        }
        // A name listed twice in an entry cannot stand in for a missing one.
        assert!(!same_thresholds(
            &[("RGB_MATCH_THRESHOLD", 0.55), ("RGB_MATCH_THRESHOLD", 0.55)],
            &[("RGB_MATCH_THRESHOLD", 0.55), ("IR_MATCH_THRESHOLD", 0.5)],
        ));
        assert!(same_thresholds(
            &[("RGB_MATCH_THRESHOLD", 0.55), ("IR_MATCH_THRESHOLD", 0.5)],
            &[("IR_MATCH_THRESHOLD", 0.5), ("RGB_MATCH_THRESHOLD", 0.55)],
        ));
    }

    #[test]
    fn the_settings_file_selects_cpu_unless_every_npu_line_allows_it() {
        let allows = |file: &[u8]| switch_allows(None, settings_conf_value(file));
        assert!(allows(b""), "no npu line: the table decides");
        assert!(allows(b"pad_vit=0\n# npu=0\n"));
        assert!(allows(b"npu=1\n"));
        assert!(allows(b" npu = on \n"));
        assert!(!allows(b"npu=0\n"));
        assert!(!allows(b"npu=\n"), "an empty value");
        assert!(!allows(b"npu=maybe\n"), "a value not understood");
        assert!(!allows(b"npu=1\nnpu=off\n"), "any line off wins");
        assert!(!allows(b"npu=1\n\xff\n"), "not UTF-8");
        assert!(matches!(settings_conf_value(b"other=1"), Setting::Absent));
    }

    #[test]
    fn the_switch_allows_the_npu_only_when_every_source_is_understood_and_on() {
        let on = [&b"1"[..], b"true", b" YES ", b"On\n"];
        let off = [&b"0"[..], b"false", b"no", b"OFF"];
        let malformed = [&b""[..], b"  ", b"2", b"enabled", b"\xff\xfe"];
        assert!(switch_allows(None, Setting::Absent));
        for value in on {
            assert!(switch_allows(
                Some(OsStr::from_bytes(value)),
                Setting::Absent
            ));
            assert!(switch_allows(None, Setting::Value(value)));
        }
        for value in off.iter().chain(&malformed) {
            assert!(
                !switch_allows(Some(OsStr::from_bytes(value)), Setting::Absent),
                "{value:?}"
            );
            assert!(!switch_allows(None, Setting::Value(value)), "{value:?}");
        }
        assert!(!switch_allows(None, Setting::Unreadable));
        assert!(
            !switch_allows(Some(OsStr::new("1")), Setting::Value(b"0")),
            "either source disabling wins"
        );
        assert!(!switch_allows(Some(OsStr::new("0")), Setting::Value(b"1")));
    }

    #[test]
    fn only_a_dynamic_or_unit_batch_is_fixed_to_one() {
        assert_eq!(
            fixed_batch_shape(&[None, Some(3), Some(112), Some(112)]),
            Ok(vec![1, 3, 112, 112])
        );
        assert_eq!(
            fixed_batch_shape(&[Some(1), Some(3), Some(112), Some(112)]),
            Ok(vec![1, 3, 112, 112])
        );
        assert!(matches!(
            fixed_batch_shape(&[Some(2), Some(3)]),
            Err(CpuReason::Ineligible(_))
        ));
        assert!(matches!(
            fixed_batch_shape(&[None, None, Some(112)]),
            Err(CpuReason::Ineligible(_))
        ));
        assert!(matches!(
            fixed_batch_shape(&[None, Some(0)]),
            Err(CpuReason::Ineligible(_))
        ));
        assert!(matches!(
            fixed_batch_shape(&[]),
            Err(CpuReason::Ineligible(_))
        ));
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_cache_is_private_per_identity_and_drops_other_identities() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("npu");
        let stale = root.join("f".repeat(64));
        fs::create_dir_all(stale.join("blobs")).unwrap();
        let unrelated = root.join("README");
        fs::write(&unrelated, "kept").unwrap();
        let odd_dir = root.join("not-a-digest");
        fs::create_dir_all(&odd_dir).unwrap();

        let cache = Cache::prepare(&root, &identity(), "boot-a").unwrap();
        let dir = root.join(identity().digest());
        for path in [&root, &dir, &dir.join("blobs"), &root.join("markers")] {
            assert_eq!(mode(path), 0o700, "{}", path.display());
        }
        assert_eq!(cache.blobs(), dir.join("blobs"));
        assert!(!stale.exists(), "another identity's cache is removed");
        assert!(
            unrelated.exists() && odd_dir.exists(),
            "only digest dirs go"
        );
        assert!(
            root.join("markers").exists(),
            "the markers are not a digest dir"
        );

        // Reuse keeps this identity's contents.
        fs::write(dir.join("blobs").join("x.blob"), "blob").unwrap();
        Cache::prepare(&root, &identity(), "boot-a").unwrap();
        assert!(dir.join("blobs").join("x.blob").exists());
    }

    #[test]
    fn a_current_boot_marker_stops_the_compile_and_an_earlier_boot_allows_it() {
        let base = tempfile::tempdir().unwrap();
        let sha = "c".repeat(64);
        let earlier = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        earlier.marker_file(&sha).arm().unwrap();
        assert_eq!(mode(&earlier.marker_file(&sha).path), 0o600);

        assert_eq!(earlier.marker(&sha), Marker::CurrentBoot);
        let now = Cache::prepare(base.path(), &identity(), "boot-b").unwrap();
        assert_eq!(
            now.marker(&sha),
            Marker::Absent,
            "an earlier boot's marker is pruned, so the model gets a new attempt"
        );
        let mut armed_during = Marker::Absent;
        let result = compile_guarded(&now.marker_file(&sha), || {
            armed_during = now.marker(&sha);
            Ok(7)
        });
        assert_eq!(result, Ok(7));
        assert_eq!(armed_during, Marker::CurrentBoot, "armed while compiling");
        assert_eq!(now.marker(&sha), Marker::Absent, "cleared when it returns");

        now.marker_file(&sha).arm().unwrap();
        let mut called = false;
        let result: Result<(), _> = compile_guarded(&now.marker_file(&sha), || {
            called = true;
            Ok(())
        });
        assert_eq!(result, Err(CpuReason::DidNotReturn));
        assert!(!called, "a compile that never returned is not retried");
    }

    #[test]
    fn a_current_boot_marker_survives_a_switch_to_another_identity_and_back() {
        let base = tempfile::tempdir().unwrap();
        let sha = "f".repeat(64);
        let a = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        a.marker_file(&sha).arm().unwrap();
        let mut other = identity();
        other.firmware = "an update".into();
        let b = Cache::prepare(base.path(), &other, "boot-a").unwrap();
        assert_eq!(b.marker(&sha), Marker::Absent, "markers are per identity");
        let back = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        assert_eq!(
            back.marker(&sha),
            Marker::CurrentBoot,
            "the rollback still sees it"
        );
    }

    #[test]
    fn a_marker_that_cannot_be_read_or_holds_no_boot_id_counts_as_current() {
        let base = tempfile::tempdir().unwrap();
        let cache = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        let sha = "1".repeat(64);
        let marker = cache.marker_file(&sha);
        fs::write(&marker.path, "").unwrap();
        assert_eq!(cache.marker(&sha), Marker::CurrentBoot, "empty");
        fs::write(&marker.path, "not a boot id!").unwrap();
        assert_eq!(cache.marker(&sha), Marker::CurrentBoot, "garbage");
        // Kept across a restart in the same or a later boot: it is not a
        // well-formed earlier-boot marker.
        let restarted = Cache::prepare(base.path(), &identity(), "boot-b").unwrap();
        assert_eq!(restarted.marker(&sha), Marker::CurrentBoot);
        // A directory where the marker should be cannot be read as one.
        fs::remove_file(&marker.path).unwrap();
        fs::create_dir(&marker.path).unwrap();
        assert_eq!(restarted.marker(&sha), Marker::CurrentBoot, "unreadable");
        let result: Result<(), _> = compile_guarded(&restarted.marker_file(&sha), || Ok(()));
        assert_eq!(result, Err(CpuReason::DidNotReturn));
    }

    #[test]
    fn a_marker_is_committed_atomically_and_leftovers_are_cleared() {
        let base = tempfile::tempdir().unwrap();
        let cache = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        let sha = "2".repeat(64);
        let marker = cache.marker_file(&sha);
        marker.arm().unwrap();
        assert!(
            !marker.path.with_extension("tmp").exists(),
            "renamed into place"
        );
        assert_eq!(fs::read_to_string(&marker.path).unwrap(), "boot-a");
        marker.disarm().unwrap();
        fs::write(marker.path.with_extension("tmp"), "boot-a").unwrap();
        Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        assert!(
            !marker.path.with_extension("tmp").exists(),
            "a temporary file that was never renamed is cleared"
        );
        assert_eq!(cache.marker(&sha), Marker::Absent);
    }

    #[test]
    fn a_suspend_baseline_never_exceeds_a_later_reading() {
        for _ in 0..1000 {
            let baseline = suspended(Bound::AtMost).unwrap();
            let later = suspended(Bound::AtLeast).unwrap();
            assert!(baseline <= later, "{baseline:?} > {later:?}");
        }
    }

    /// The cost of the marker around every NPU inference, on the shipped
    /// path (`arm`: temporary file, permissions, rename, read-back; then
    /// `disarm`), in a directory on the home filesystem, or on the one
    /// `IRLUME_NPU_MARKER_DIR` names.
    #[test]
    #[ignore = "a filesystem measurement, not a check"]
    fn npu_hw_marker_cost() {
        let base = std::env::var_os("IRLUME_NPU_MARKER_DIR")
            .or_else(|| std::env::var_os("HOME"))
            .unwrap();
        let dir = tempfile::tempdir_in(base).unwrap();
        let cache = Cache::prepare(dir.path(), &identity(), &boot_id().unwrap()).unwrap();
        let marker = cache.marker_file(&"4".repeat(64));
        for _ in 0..100 {
            marker.arm().unwrap();
            marker.disarm().unwrap();
        }
        let mut each = Vec::with_capacity(5);
        for _ in 0..5 {
            let started = std::time::Instant::now();
            for _ in 0..1000 {
                marker.arm().unwrap();
                marker.disarm().unwrap();
            }
            each.push(started.elapsed() / 1000);
        }
        each.sort();
        eprintln!(
            "marker arm + disarm on the shipped path: median {:?}, range {:?} to {:?} (5 runs of 1,000)",
            each[2], each[0], each[4]
        );
    }

    #[test]
    fn an_operation_that_leaves_untrusted_state_keeps_its_marker() {
        let base = tempfile::tempdir().unwrap();
        let cache = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        let sha = "3".repeat(64);
        let result: Result<(), _> = run_guarded(&cache.marker_file(&sha), || {
            (Err(CpuReason::CompileFailed("rejected".into())), false)
        });
        assert!(result.is_err());
        assert_eq!(cache.marker(&sha), Marker::CurrentBoot, "kept armed");
        let again: Result<(), _> = compile_guarded(&cache.marker_file(&sha), || Ok(()));
        assert_eq!(again, Err(CpuReason::DidNotReturn), "not retried this boot");

        // A cleanup that cannot remove what the compile left reports it.
        let blobs = base.path().join("leftover");
        fs::create_dir_all(blobs.join("a directory, not a blob")).unwrap();
        assert!(discard_blobs(&blobs).is_err());
        fs::remove_dir(blobs.join("a directory, not a blob")).unwrap();
        fs::write(blobs.join("model.blob"), b"x").unwrap();
        assert!(discard_blobs(&blobs).is_ok());
        assert_eq!(fs::read_dir(&blobs).unwrap().count(), 0);
        assert!(discard_blobs(&base.path().join("absent")).is_ok());
    }

    #[test]
    fn a_failed_compile_clears_its_marker() {
        let base = tempfile::tempdir().unwrap();
        let sha = "d".repeat(64);
        let cache = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        let result: Result<(), _> = compile_guarded(&cache.marker_file(&sha), || {
            Err(CpuReason::CompileFailed("x".into()))
        });
        assert_eq!(result, Err(CpuReason::CompileFailed("x".into())));
        assert_eq!(cache.marker(&sha), Marker::Absent);
    }

    struct Fake {
        replies: Vec<Result<Vec<f32>, String>>,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        seen: Option<(PathBuf, std::sync::Arc<std::sync::Mutex<Vec<bool>>>)>,
    }

    impl Infer for Fake {
        fn infer(&mut self, _input: &[f32]) -> Result<Vec<f32>, String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some((marker, seen)) = &self.seen {
                seen.lock().unwrap().push(marker.exists());
            }
            self.replies.remove(0)
        }
    }

    type Calls = std::sync::Arc<std::sync::atomic::AtomicUsize>;

    fn fake(replies: Vec<Result<Vec<f32>, String>>) -> (Slot, Calls) {
        let calls = Calls::default();
        let slot = Slot::npu(Box::new(Fake {
            replies,
            calls: calls.clone(),
            seen: None,
        }));
        (slot, calls)
    }

    fn first(raw: &[f32]) -> irlume_common::Result<f32> {
        raw.first()
            .copied()
            .ok_or_else(|| irlume_common::Error::Hardware("empty".into()))
    }

    #[test]
    fn the_npu_answers_while_it_works() {
        let (mut slot, calls) = fake(vec![Ok(vec![0.25]), Ok(vec![0.5])]);
        assert_eq!(slot.device(), Device::Npu);
        assert_eq!(slot.run(&[1.0], first), Some(0.25));
        assert_eq!(slot.run(&[1.0], first), Some(0.5));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn an_inference_error_retires_the_npu_for_good() {
        let (mut slot, calls) = fake(vec![Err("device lost".into()), Ok(vec![0.5])]);
        assert_eq!(slot.run(&[1.0], first), None, "the caller runs CPU");
        assert_eq!(
            slot.device(),
            Device::Cpu(CpuReason::Retired("device lost".into()))
        );
        assert_eq!(slot.run(&[1.0], first), None);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a retired NPU is not called again"
        );
    }

    #[test]
    fn an_undecodable_output_retires_the_npu_too() {
        let (mut slot, _) = fake(vec![Ok(vec![])]);
        assert_eq!(slot.run(&[1.0], first), None);
        assert!(matches!(slot.device(), Device::Cpu(CpuReason::Retired(_))));
    }

    #[test]
    fn a_cpu_slot_never_answers() {
        let mut slot = Slot::cpu(CpuReason::NotCertified);
        assert_eq!(slot.run(&[1.0], first), None);
        assert_eq!(slot.device(), Device::Cpu(CpuReason::NotCertified));
        assert_eq!(Slot::default().device(), Device::Cpu(CpuReason::Disabled));
    }

    #[test]
    fn every_inference_is_bracketed_by_the_marker() {
        let base = tempfile::tempdir().unwrap();
        let sha = "e".repeat(64);
        let cache = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        let marker = cache.marker_file(&sha);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut marked = Marked {
            inner: Box::new(Fake {
                replies: vec![Ok(vec![1.0]), Err("lost".into())],
                calls: Calls::default(),
                seen: Some((marker.path.clone(), seen.clone())),
            }),
            marker: cache.marker_file(&sha),
        };
        assert_eq!(marked.infer(&[0.0]), Ok(vec![1.0]));
        assert_eq!(cache.marker(&sha), Marker::Absent, "cleared after a return");
        assert_eq!(marked.infer(&[0.0]), Err("lost".into()));
        assert_eq!(
            cache.marker(&sha),
            Marker::Absent,
            "cleared after an error too"
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![true, true],
            "armed during each call"
        );

        // What a crash or a watchdog kill mid-inference leaves behind: the
        // armed marker, which keeps the model off the NPU after the restart.
        marker.arm().unwrap();
        let restarted = Cache::prepare(base.path(), &identity(), "boot-a").unwrap();
        let result: Result<(), _> = compile_guarded(&restarted.marker_file(&sha), || Ok(()));
        assert_eq!(result, Err(CpuReason::DidNotReturn));
    }

    #[test]
    fn a_marker_that_cannot_be_written_keeps_the_npu_from_answering() {
        let base = tempfile::tempdir().unwrap();
        let mut marked = Marked {
            inner: Box::new(Fake {
                replies: vec![Ok(vec![1.0])],
                calls: Calls::default(),
                seen: None,
            }),
            marker: MarkerFile {
                path: base.path().join("missing-dir").join("marker"),
                boot_id: "boot-a".into(),
            },
        };
        assert!(marked.infer(&[0.0]).is_err());
    }

    #[test]
    fn a_disabled_context_places_every_model_on_cpu() {
        let mut context = Context::disabled();
        assert_eq!(context.identity().err(), Some(&CpuReason::Disabled));
        let slot = context.slot(b"model", &"e".repeat(64));
        assert_eq!(slot.device(), Device::Cpu(CpuReason::Disabled));
    }

    #[test]
    fn the_runtime_libraries_are_hashed_and_the_compile_time_ones_added() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let plugins = d.join("openvino-2026.2.0");
        fs::create_dir_all(&plugins).unwrap();
        let files = [
            d.join("libopenvino_c.so.2026.2.0"),
            d.join("libopenvino.so.2026.2.0"),
            d.join("libopenvino_ir_frontend.so.2026.2.0"),
            d.join("libopenvino_onnx_frontend.so.2026.2.0"),
            d.join("libze_loader.so.1.32.0"),
            d.join("libze_intel_npu.so.1.38.0"),
            plugins.join("libopenvino_intel_npu_plugin.so"),
            plugins.join("libopenvino_intel_npu_compiler.so"),
            plugins.join("libopenvino_intel_npu_compiler_loader.so"),
        ];
        for (i, file) in files.iter().enumerate() {
            fs::write(file, vec![i as u8; 8]).unwrap();
        }
        // The frontends and the compiler are not mapped yet; libc is ignored.
        let open = [&files[0], &files[1], &files[4], &files[5], &files[6]];
        let maps = |mapped: &[&PathBuf]| -> String {
            mapped
                .iter()
                .map(|path| map_line(path))
                .chain(std::iter::once(
                    "7f20-7f30 r-xp 0 00:1f 7   /usr/lib64/libc.so.6\n".into(),
                ))
                .collect()
        };
        let (libraries, hashed) = runtime_libraries(&maps(&open)).unwrap();
        assert_eq!(libraries.lines().count(), 9, "{libraries}");
        assert_eq!(hashed.len(), 9);
        assert!(libraries.contains("libopenvino_intel_npu_compiler.so"));
        assert!(libraries.contains("libopenvino_intel_npu_compiler_loader.so"));
        assert!(libraries.contains("libopenvino_ir_frontend.so.2026.2.0"));
        assert!(libraries.contains("libopenvino_onnx_frontend.so.2026.2.0"));
        assert!(!libraries.contains("libc.so"));
        // After a compile maps the rest, they are the files that were hashed.
        let compiled: Vec<&PathBuf> = files.iter().collect();
        assert_eq!(loaded_as_hashed(&maps(&compiled), &hashed), Ok(()));
        let before = libraries.clone();
        fs::write(&files[4], b"a rebuilt loader").unwrap();
        assert_ne!(
            runtime_libraries(&maps(&open)).unwrap().0,
            before,
            "a rebuild changes it"
        );

        let without_driver = maps(&[&files[0], &files[1], &files[4], &files[6]]);
        assert!(matches!(
            runtime_libraries(&without_driver),
            Err(CpuReason::IdentityUnreadable(_))
        ));
    }

    #[test]
    fn complete_runtime_manifest_survives_provider_prefix_relocation() {
        let directory = tempfile::tempdir().unwrap();
        let build = |prefix: &str| {
            let root = directory.path().join(prefix);
            fs::create_dir(&root).unwrap();
            let names = [
                "libopenvino_c.so.2026.2.0",
                "libopenvino.so.2026.2.0",
                "libze_loader.so.1",
                "libze_intel_npu.so.1",
                "libopenvino_intel_npu_plugin.so",
                "libopenvino_intel_npu_compiler.so",
                "libopenvino_intel_npu_compiler_loader.so",
                "libopenvino_ir_frontend.so.2026.2.0",
                "libopenvino_onnx_frontend.so.2026.2.0",
                "libtbb.so.12",
                "libprovider_math.so.1",
                "irlumed",
            ];
            let paths: Vec<_> = names
                .iter()
                .map(|name| {
                    if *name == "libtbb.so.12" || *name == "libprovider_math.so.1" {
                        root.join("runtime/3rdparty").join(name)
                    } else {
                        root.join("runtime/lib").join(name)
                    }
                })
                .collect();
            for path in &paths {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
            }
            for path in &paths {
                fs::write(path, path.file_name().unwrap().as_bytes()).unwrap();
            }
            let maps: String = paths.iter().map(|path| map_line(path)).collect();
            let (manifest, hashed) =
                execution_libraries(&maps, &root.join("runtime/lib/irlumed")).unwrap();
            let mut result = identity();
            result.libraries = manifest;
            (result, hashed, root, maps)
        };
        let (original, _, _, _) = build("openvino");
        let (relocated, hashed, root, maps) = build("provider");
        assert_eq!(
            original.execution_digest().unwrap(),
            relocated.execution_digest().unwrap()
        );
        assert!(relocated.libraries.contains("libtbb.so.12"));
        assert!(relocated.libraries.contains("libprovider_math.so.1"));
        assert!(
            !relocated.libraries.contains("/irlumed "),
            "a key embedded in the executable cannot also hash that executable"
        );
        let executable = root.join("runtime/lib/irlumed");
        fs::write(&executable, relocated.execution_digest().unwrap()).unwrap();
        let mut with_entry = relocated.clone();
        with_entry.libraries = execution_libraries(&maps, &executable).unwrap().0;
        assert_eq!(with_entry.execution_digest(), relocated.execution_digest());
        assert!(
            hashed.iter().any(|library| library.path == executable),
            "executable still receives mapped-file checks"
        );
        let replacement = root.join("replacement");
        fs::write(&replacement, b"changed dependency").unwrap();
        fs::rename(replacement, root.join("runtime/3rdparty/libtbb.so.12")).unwrap();
        let updated = maps
            .lines()
            .filter(|line| !line.contains("libtbb.so.12"))
            .map(|line| format!("{line}\n"))
            .collect::<String>()
            + &map_line(&root.join("runtime/3rdparty/libtbb.so.12"));
        assert!(execution_loaded_as_hashed(&updated, &hashed).is_err());
        let mut changed = relocated.clone();
        let (manifest, updated_hashes) =
            execution_libraries(&updated, &root.join("runtime/lib/irlumed")).unwrap();
        changed.libraries = manifest;
        assert_eq!(
            execution_loaded_as_hashed(&updated, &updated_hashes),
            Ok(())
        );
        assert_ne!(
            changed.execution_digest().unwrap(),
            relocated.execution_digest().unwrap()
        );
        let deleted = format!(
            "{updated}{} (deleted)\n",
            map_line(&root.join("runtime/3rdparty/libtbb.so.12")).trim_end()
        );
        assert!(execution_loaded_as_hashed(&deleted, &updated_hashes).is_err());
        let outside = directory.path().join("external-dependency.so");
        fs::write(&outside, b"late native dependency").unwrap();
        assert!(execution_loaded_as_hashed(
            &format!("{updated}{}", map_line(&outside)),
            &updated_hashes
        )
        .is_err_and(|error| error.contains("not hashed")));
    }

    #[test]
    fn legacy_manifest_ignores_unrelated_colocated_mappings() {
        let directory = tempfile::tempdir().unwrap();
        let names = [
            "libopenvino_c.so.2026.2.0",
            "libopenvino.so.2026.2.0",
            "libze_loader.so.1",
            "libze_intel_npu.so.1",
            "libopenvino_intel_npu_plugin.so",
            "libopenvino_intel_npu_compiler.so",
            "libopenvino_intel_npu_compiler_loader.so",
            "libopenvino_ir_frontend.so.2026.2.0",
            "libopenvino_onnx_frontend.so.2026.2.0",
        ];
        let mut expected = String::new();
        let mut paths: Vec<_> = names
            .iter()
            .map(|name| directory.path().join(name))
            .collect();
        paths.sort();
        for path in &paths {
            fs::write(path, b"fixture").unwrap();
            expected.push_str(&format!(
                "{} {}\n",
                path.display(),
                irlume_common::sha256_hex(b"fixture")
            ));
        }
        let mut maps: String = paths.iter().map(|path| map_line(path)).collect();
        for name in ["libc.so.6", "libonnxruntime.so.1"] {
            let path = directory.path().join(name);
            fs::write(&path, b"unrelated").unwrap();
            maps.push_str(&map_line(&path));
        }
        let (manifest, _) = runtime_libraries(&maps).unwrap();
        assert_eq!(manifest, expected);
        let mut legacy = identity();
        legacy.libraries = expected;
        let mut current = legacy.clone();
        current.libraries = manifest;
        assert_eq!(legacy.digest(), current.digest());
    }

    /// A mapping as btrfs shows it: the filesystem's device, which `stat`
    /// does not report, and the file's inode.
    fn map_line(path: &Path) -> String {
        format!(
            "7f00-7f10 r-xp 00000000 00:23 {}   {}\n",
            fs::metadata(path).unwrap().ino(),
            path.display()
        )
    }

    #[test]
    fn a_runtime_library_must_be_loaded_as_it_was_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let files = [
            d.join("libopenvino_c.so.2026.2.0"),
            d.join("libopenvino.so.2026.2.0"),
            d.join("libze_loader.so.1.32.0"),
            d.join("libze_intel_npu.so.1.38.0"),
            d.join("libopenvino_intel_npu_plugin.so"),
            d.join("libopenvino_intel_npu_compiler.so"),
            d.join("libopenvino_ir_frontend.so.2026.2.0"),
            d.join("libopenvino_onnx_frontend.so.2026.2.0"),
            d.join("libopenvino_intel_npu_compiler_loader.so"),
        ];
        for (i, file) in files.iter().enumerate() {
            fs::write(file, vec![i as u8; 8]).unwrap();
        }
        let open: String = files[..5].iter().map(|path| map_line(path)).collect();
        let (_, hashed) = runtime_libraries(&open).unwrap();
        let compiler = map_line(&files[5]);

        // The compiler is replaced by a package update after it was hashed
        // and before compiling loads it: a new inode at the same path.
        let staged = d.join("staged");
        fs::write(&staged, b"another compiler").unwrap();
        fs::rename(&staged, &files[5]).unwrap();
        let loaded = format!("{open}{}", map_line(&files[5]));
        assert!(
            loaded_as_hashed(&loaded, &hashed).is_err_and(|why| why.contains("not the file")),
            "a library replaced after hashing"
        );
        // The file that was hashed, now deleted while mapped.
        let deleted = format!("{open}{} (deleted)\n", compiler.trim_end());
        assert!(loaded_as_hashed(&deleted, &hashed).is_err());
        // A runtime library the identity never hashed.
        let stray = d.join("libopenvino_tensorflow_frontend.so.2026.2.0");
        fs::write(&stray, b"x").unwrap();
        let unhashed = format!("{open}{}", map_line(&stray));
        assert!(loaded_as_hashed(&unhashed, &hashed).is_err_and(|why| why.contains("not hashed")));
        // A library swapped between mapping and hashing fails at open.
        let staged = d.join("staged");
        fs::write(&staged, b"another loader").unwrap();
        let mapped_before = map_line(&files[2]);
        fs::rename(&staged, &files[2]).unwrap();
        let swapped = open.replace(&map_line(&files[2]), &mapped_before);
        assert!(matches!(
            runtime_libraries(&swapped),
            Err(CpuReason::IdentityUnreadable(_))
        ));
    }

    #[test]
    fn a_discovery_that_did_not_return_this_boot_is_not_repeated() {
        let base = tempfile::tempdir().unwrap();
        fs::create_dir_all(base.path().join("markers")).unwrap();
        fs::write(
            base.path().join("markers").join("discovery"),
            boot_id().unwrap(),
        )
        .unwrap();
        let context = Context::open(
            base.path(),
            &Consumer {
                onnx_runtime: "1.28.1",
                thresholds: &[],
                decision_fingerprint: "",
            },
        );
        assert_eq!(context.identity().err(), Some(&CpuReason::DidNotReturn));
    }

    #[test]
    fn cache_failure_before_discovery_is_unreported() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("not-a-directory");
        fs::write(&base, b"fixture").unwrap();
        let mut observation = None;
        let result = prepare_runtime(
            &base,
            &mut observation,
            || -> Result<((), Identity), CpuReason> {
                panic!("discovery must not run before its marker is ready")
            },
        );
        assert!(result.is_err());
        assert!(observation.is_none());
    }

    #[test]
    fn cache_failure_after_discovery_retains_platform_observation() {
        let directory = tempfile::tempdir().unwrap();
        let expected = identity();
        fs::write(
            directory.path().join(expected.digest()),
            b"blocks cache directory",
        )
        .unwrap();
        let mut observation = None;
        let result = prepare_runtime(directory.path(), &mut observation, || {
            Ok(((), expected.clone()))
        });
        assert!(matches!(result, Err(CpuReason::CompileFailed(_))));
        assert_eq!(observation, Some(Ok(expected.clone())));
        let mut context = Context {
            state: Err(result.err().unwrap()),
            discovery: observation,
        };
        assert_eq!(context.runtime_available(), Some(true));
        assert_eq!(context.identity().unwrap().digest(), expected.digest());
        assert!(matches!(
            context.slot(b"model", "unused").device(),
            Device::Cpu(CpuReason::CompileFailed(_))
        ));
    }

    #[test]
    fn discovery_observations_distinguish_refusal_failure_and_success() {
        let directory = tempfile::tempdir().unwrap();
        let mut observation = None;
        let failed = CpuReason::RuntimeAbsent("no runtime".into());
        assert!(
            prepare_runtime::<()>(directory.path(), &mut observation, || Err(failed.clone()))
                .is_err()
        );
        assert_eq!(observation, Some(Err(failed)));
        observation = None;
        assert!(
            prepare_runtime::<()>(directory.path(), &mut observation, || Err(
                CpuReason::LoadingNotAdmitted
            ))
            .is_err()
        );
        assert!(
            observation.is_none(),
            "admission refusal is not a runtime observation"
        );
        let expected = identity();
        assert!(prepare_runtime(directory.path(), &mut observation, || Ok((
            (),
            expected.clone()
        )))
        .is_ok());
        assert_eq!(observation, Some(Ok(expected)));
    }

    #[test]
    fn marker_cleanup_failure_after_discovery_retains_observation() {
        let directory = tempfile::tempdir().unwrap();
        let mut observation = None;
        let expected = identity();
        let result = prepare_runtime(directory.path(), &mut observation, || {
            let marker = directory.path().join("markers/discovery");
            fs::remove_file(&marker).unwrap();
            fs::create_dir(&marker).unwrap();
            Ok(((), expected.clone()))
        });
        assert!(
            matches!(result, Err(CpuReason::CompileFailed(ref why)) if why.contains("cannot clear the marker"))
        );
        assert_eq!(observation, Some(Ok(expected)));
    }

    #[test]
    fn the_library_comes_only_from_the_listed_directories() {
        let dir = tempfile::tempdir().unwrap();
        let listed = dir.path().join("lib64");
        fs::create_dir_all(&listed).unwrap();
        let listed_str = listed.to_str().unwrap();
        assert!(matches!(
            resolve_library(&[listed_str]),
            Err(CpuReason::RuntimeAbsent(_))
        ));
        fs::write(listed.join(OPENVINO_C_SONAME), b"").unwrap();
        assert_eq!(
            resolve_library(&["/nonexistent-irlume-dir", listed_str]),
            Ok(listed.join(OPENVINO_C_SONAME))
        );
        assert!(
            matches!(
                resolve_library(&["relative/dir"]),
                Err(CpuReason::RuntimeAbsent(_))
            ),
            "a relative directory never names the library"
        );
        assert!(matches!(
            probe_library(Path::new(OPENVINO_C_SONAME)),
            Err(CpuReason::RuntimeAbsent(ref why)) if why.contains("absolute")
        ));
    }

    #[test]
    fn unreviewed_loading_profile_is_refused_before_any_native_entry() {
        let directory = tempfile::tempdir().unwrap();
        // An invalid ELF would reach dlopen in the former path. The admission
        // refusal must win before the dynamic loader or device queries run.
        fs::write(directory.path().join(OPENVINO_C_SONAME), b"not executable").unwrap();
        let paths = [directory.path().to_str().unwrap()];
        let result = Platform::open_with(&Sources {
            library_dirs: &paths,
            accel_class: directory.path(),
            debugfs_accel: directory.path(),
            maps: directory.path(),
            force_compiler: true,
        });
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("loading profile has not been admitted"));
    }

    #[test]
    fn an_absent_runtime_is_a_cpu_answer_not_a_panic() {
        let empty = tempfile::tempdir().unwrap();
        let empty_str = empty.path().to_str().unwrap();
        let Err(reason) = Platform::open_with(&Sources {
            library_dirs: &[empty_str],
            accel_class: Path::new("/sys/class/accel"),
            debugfs_accel: Path::new("/sys/kernel/debug/accel"),
            maps: Path::new("/proc/self/maps"),
            force_compiler: true,
        }) else {
            panic!("an absent library cannot open");
        };
        assert!(
            matches!(reason, CpuReason::RuntimeAbsent(ref why) if why.contains(OPENVINO_C_SONAME)),
            "{reason:?}"
        );
        let bad = empty.path().join(OPENVINO_C_SONAME);
        fs::write(&bad, b"not a library").unwrap();
        assert!(matches!(
            probe_library(&bad),
            Err(CpuReason::RuntimeAbsent(_))
        ));
    }

    fn accel_fixture(class: &Path, devices: &Path, name: &str, bus: &str) {
        let device = devices.join(bus);
        fs::create_dir_all(&device).unwrap();
        fs::write(device.join("vendor"), "0x8086\n").unwrap();
        fs::write(device.join("device"), "0x643E\n").unwrap();
        fs::create_dir_all(class.join(name)).unwrap();
        std::os::unix::fs::symlink(&device, class.join(name).join("device")).unwrap();
    }

    #[test]
    fn the_pci_id_and_bus_address_come_from_the_only_accelerator_node() {
        let root = tempfile::tempdir().unwrap();
        let class = root.path().join("class");
        let devices = root.path().join("devices");
        accel_fixture(&class, &devices, "accel0", "0000:00:0b.0");
        assert_eq!(
            accelerator(&class),
            Ok(("8086:643e".into(), "0000:00:0b.0".into()))
        );
        accel_fixture(&class, &devices, "accel1", "0000:00:0c.0");
        assert!(matches!(
            accelerator(&class),
            Err(CpuReason::IdentityUnreadable(_))
        ));
        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            accelerator(empty.path()),
            Err(CpuReason::IdentityUnreadable(_))
        ));
    }

    #[test]
    fn an_unreadable_or_empty_firmware_build_is_an_unreadable_identity() {
        let debugfs = tempfile::tempdir().unwrap();
        assert!(matches!(
            firmware_build(debugfs.path(), "0000:00:0b.0"),
            Err(CpuReason::IdentityUnreadable(_))
        ));
        let entry = debugfs.path().join("0000:00:0b.0");
        fs::create_dir_all(&entry).unwrap();
        fs::write(entry.join("fw_version"), "\n").unwrap();
        assert!(matches!(
            firmware_build(debugfs.path(), "0000:00:0b.0"),
            Err(CpuReason::IdentityUnreadable(_))
        ));
        fs::write(entry.join("fw_version"), "Aug 20 2026*NPU40xx*build\n").unwrap();
        assert_eq!(
            firmware_build(debugfs.path(), "0000:00:0b.0"),
            Ok("Aug 20 2026*NPU40xx*build".into())
        );
    }
}
