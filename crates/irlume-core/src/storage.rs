// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Per-user face enrollment: up to 3 named face profiles, each holding multiple
//! named scans (Windows-Hello-style "improve recognition"). Stored as JSON under
//! the state dir (`IRLUME_STATE_DIR`, else `$HOME/.local/share/irlume` for dev,
//! else `/var/lib/irlume`), mode 0600. We store L2-normalized embeddings, never
//! raw images. The old single-profile format is migrated transparently on load.

use crate::account::{Account, Owner, Record};
use crate::{crypto, template_key};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Max face profiles per account, one per person (e.g. self / a partner / a
/// trusted person). A face can only own one profile, so appearance variants
/// (glasses, lighting) are extra scans on that person's profile, not new
/// profiles. A 4th person requires deleting one.
pub const MAX_PROFILES: usize = 3;
/// Max scans per profile: one fresh enrollment plus four improve-recognition
/// rounds ([`DEFAULT_ENROLL_SCANS`] + 4 x [`IMPROVE_SCANS`]). Raised from 5:
/// scans now also feed the per-profile IR calibration fit (ADR-0004). The cap
/// is set where the 2026-07-15 enrollment-size sweep plateaued: calibrated
/// FRR at the production threshold improves steeply from 5 scans (25%) to 15
/// (17%) and flattens by 30 (16%), while past ~30 the fit's growing rank
/// starts to nudge impostor scores upward (FAR@0.40 0.14%→0.42% by 50) for
/// zero FRR gain. Best-of-N FAR inflation stays bounded by
/// [`crate::scaled_threshold`] (+0.074 at 30, under the +0.10 cap).
pub const MAX_SCANS_PER_PROFILE: usize = 30;
/// Scans captured by a fresh enrollment to bootstrap solid recognition and a
/// usable first calibration fit. 10 is the measured knee, not a round number:
/// the 2026-07-15 calibrated cross-condition sweep improves FRR steeply from
/// 5 scans (25%) through ~10 and plateaus by 15 (17%); the 2026-08-23 CBSR
/// deployment-shaped OR-arm N-sweep (dark-path bars, within-session split)
/// is N-insensitive from 5-13 (FAR 3.5-4.0e-4, FRR 0.5-0.7% — noise), so the
/// binding constraint is CROSS-CONDITION coverage + the per-user calibration
/// fit (k=5 fit pairs beat k=3, ADR-0004 Tufts arm), which need headroom
/// above the MIN_FIT_PAIRS floor. Lowering to 5 buys ~15s of enrollment time
/// and costs ~7-8pp of hard-condition FRR; do not.
pub const DEFAULT_ENROLL_SCANS: usize = 10;
/// Scans added per improve-recognition round.
pub const IMPROVE_SCANS: usize = 5;

/// One quality-gated capture under a profile. `rgb` is a 512-D L2-normalized
/// AuraFace embedding; `ir` is the IR-face embedding for dark operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceScan {
    pub name: String,
    pub rgb: Vec<f32>,
    #[serde(default)]
    pub ir: Option<Vec<f32>>,
    /// Embedding space `ir` lives in: `"raw"` (no adapter) or
    /// `"adapter:<sha256 prefix>"` of the adapter that produced it. Templates
    /// only match probes from the same space, so swapping or removing the
    /// adapter can never silently score against stale-space templates.
    /// `None` = unknown IR pipeline; retained for loading old enrollments,
    /// but excluded from IR matching and calibration.
    #[serde(default)]
    pub ir_space: Option<String>,
    /// The RECOGNIZER that produced `rgb` (and, before any adapter, `ir`),
    /// as `"embed:<sha256>"` of its weights (full digest: this tag exists to
    /// resist an adversarial model, and a truncated hash halves per character).
    ///
    /// Cosine similarity is only meaningful WITHIN one embedding space. A
    /// different recognizer produces a different space, so comparing a fresh
    /// probe against these templates yields a number with no interpretation
    /// that may land either side of the threshold, granting or denying at
    /// random. `ir_space` already guards the adapter for the same reason;
    /// this guards the model underneath it, which #276 needs before any
    /// user-supplied recognizer can be considered and which a change to the
    /// shipped weights would need regardless.
    ///
    /// `None` = scan predates this tagging, which means exactly one recognizer
    /// can have produced it: the historically shipped one. Compatibility is
    /// decided by [`recognizer_space_matches`], which accepts `None` only when
    /// the running recognizer IS [`LEGACY_RECOGNIZER_SPACE`]. IR adapter
    /// provenance is independent: an absent `ir_space` remains unknown.
    #[serde(default)]
    pub embed_space: Option<String>,
    /// The CPU reference that computed this scan's embeddings, from
    /// [`embed_producer`]: the recognizer digest, the ONNX Runtime version and
    /// the digest of that session's exact outputs on fixed inputs.
    ///
    /// `embed_space` names the model; this names the arithmetic. An NPU
    /// probe is certified against templates from one CPU reference only, so
    /// an authentication uses the NPU only when every scan it can match
    /// carries the certified producer (ADR-0022 §2). `None`: a scan from
    /// before the field, or one whose producer could not be computed; such a
    /// scan matches exactly as before, with a CPU probe. Absent, it is not
    /// written, so a scan without it re-serialises byte for byte (see
    /// `captured_at`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embed_producer: Option<String>,
    /// Per-scan IR liveness calibration: the center/edge brightness ratio of the
    /// face region at capture, and the face brightness. The on-disk key stays
    /// `ir_depth` (the name it shipped under) so an enrollment written here still
    /// loads on an older binary; renaming the key would make a downgrade read the
    /// field as absent, which silently drops this user's fitted ratio floor.
    #[serde(default, rename = "ir_depth")]
    pub ir_center_edge_ratio: f32,
    #[serde(default)]
    pub ir_brightness: f32,
    /// Head `pitch_frac` at capture. The median across scans is this user's
    /// frontal neutral, used to CENTRE the enrollment framing band on their
    /// camera (a below-eye laptop cam reads pitch high even when level). 0.0 =
    /// not recorded (pre-calibration scan); ignored by [`Enrollment::pitch_neutral`].
    #[serde(default)]
    pub pitch: f32,
    /// When the scan was captured, in unix seconds (ADR-0030 §2: Faces shows
    /// each camera's capture date range). Display metadata, never a matching
    /// input. `None` for a scan that predates the field or was captured with
    /// the clock before the epoch. Omitted when absent, so an older scan
    /// re-serialises byte for byte: on a host without a TPM key the file is
    /// that plaintext, and a rewrite that changes nothing else leaves the
    /// bytes the added cameras' snapshot binding hashes as they were (an
    /// encrypted store changes on every write through its fresh nonce, a
    /// cost ADR-0024 accepts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<u64>,
}

/// Now as unix seconds for a scan's [`FaceScan::captured_at`]; `None` when
/// the clock reads before the epoch, so a broken clock records no date
/// rather than 1970.
#[must_use]
pub fn capture_time_now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
        .filter(|&secs| secs > 0)
}

/// A face profile: a named set of scans of one face.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceProfile {
    pub name: String,
    pub scans: Vec<FaceScan>,
    /// The LEGACY single calibration slot: the shipped recognizer's
    /// calibration, and the only one an irlume older than per-model keying
    /// can read. Kept in step with `ir_calibs[LEGACY_RECOGNIZER_SPACE]` so a
    /// downgrade still finds it. New code reads [`Self::calib_for`].
    #[serde(default)]
    pub ir_calib: Option<crate::calib::IrCalibration>,
    /// Per-profile IR calibration (ADR-0004) KEYED BY RECOGNIZER, fitted from
    /// this profile's own scan pairs at enroll/add-scan time. Only fitted and
    /// applied when no global IR adapter is loaded (raw embedding space).
    ///
    /// Keyed because a calibration maps one recognizer's IR embeddings onto
    /// its own RGB embeddings: applying model A's calibration to model B's
    /// templates puts uninterpretable numbers into the matcher. A single slot
    /// was silently overwritten by a refit under whichever model happened to
    /// be loaded (#288), which is what made switching models corrupt the
    /// calibration of the model you switched away from.
    #[serde(default)]
    pub ir_calibs: std::collections::BTreeMap<String, crate::calib::IrCalibration>,
}

impl FaceProfile {
    /// How many of this profile's scans belong to `space`.
    ///
    /// The scan limit is counted per recognizer, not per profile, because the
    /// limit exists to bound false-accept inflation from taking the best of N
    /// templates, and a comparison only ever ranges over one embedding space
    /// (#288). Ten scans under each of two recognizers is two independent
    /// best-of-ten operations, and a profile full of one model's scans must
    /// still be able to hold another's.
    pub fn scans_in(&self, space: &str) -> usize {
        self.scans
            .iter()
            .filter(|s| recognizer_space_matches(s.embed_space.as_deref(), space))
            .count()
    }

    /// This profile's calibration for `space`, or `None`.
    ///
    /// Falls back to the legacy single slot for the shipped recognizer, so a
    /// profile written before per-model keying keeps its calibration. Withhold
    /// both slots while this recognizer has untagged IR: older fits admitted
    /// those scans and the cache does not record which pairs produced it.
    /// Tagged templates can still match without calibration. This read never
    /// changes stored scans or calibration; adding tagged scans alone does not
    /// establish the provenance of a cache in a mixed legacy profile.
    pub fn calib_for(&self, space: &str) -> Option<&crate::calib::IrCalibration> {
        if self.scans.iter().any(|s| {
            s.ir.is_some()
                && s.ir_space.is_none()
                && recognizer_space_matches(s.embed_space.as_deref(), space)
        }) {
            return None;
        }
        self.ir_calibs.get(space).or_else(|| {
            (space == LEGACY_RECOGNIZER_SPACE)
                .then_some(self.ir_calib.as_ref())
                .flatten()
        })
    }

    /// Record (or clear) this profile's calibration for `space`, leaving every
    /// other recognizer's calibration untouched.
    pub fn set_calib_for(&mut self, space: &str, calib: Option<crate::calib::IrCalibration>) {
        match &calib {
            Some(c) => {
                self.ir_calibs.insert(space.to_string(), c.clone());
            }
            None => {
                self.ir_calibs.remove(space);
            }
        }
        // Mirror the shipped recognizer's calibration into the legacy slot so
        // an older irlume reading this file still finds it.
        if space == LEGACY_RECOGNIZER_SPACE {
            self.ir_calib = calib;
        }
    }
}

/// The role-labelled camera binding captured at enrollment for anti-swap checks.
/// Ordinary bindings retain optional `irlume_camera::device_identity` strings;
/// split bindings retain both unit keys. Identity-only matching never admits split.
pub use irlume_common::binding_key::PairBinding as CameraBinding;

#[cfg(test)]
#[path = "binding_contract_tests.rs"]
mod binding_contract_tests;

/// All face data for one OS user.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Enrollment {
    pub user: String,
    /// The uid of the account this enrollment was written for
    /// ([`crate::account`]). A loader treats an enrollment recorded for
    /// another uid as absent. `None` for an enrollment written before it was
    /// recorded: accepted, and [`save`] records it on the next write. Inside
    /// the ciphertext on an encrypted store. Older releases ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// The uid of the account the load that returned this enrollment was
    /// for: the uid its records record ([`load`] checks the enrollment and
    /// its template key), or, when neither records one, the uid the name
    /// resolved to at the load. `None` for an enrollment built in memory, or
    /// loaded when the name resolved to no account or could not be resolved.
    /// Never stored or read from a file. [`save`] writes the enrollment only
    /// for this uid (or the one it records), so an enrollment loaded for one
    /// account is not saved for an account that took the name in between,
    /// even when neither the enrollment nor its key records a uid yet.
    #[serde(skip)]
    pub loaded_for: Option<u32>,
    pub profiles: Vec<FaceProfile>,
    /// Retired eyes-open policy, retained for one release so old files load and
    /// the explicit OFF cleanup can clear it. New saves omit it.
    #[serde(default, skip_serializing)]
    pub require_eyes_open: bool,
    /// Camera identity captured at enroll, verified at auth (anti-swap). `None`
    /// for pre-binding enrollments; enforcement only kicks in once bound.
    #[serde(default)]
    pub camera_binding: Option<CameraBinding>,
    /// Retired eye-closure calibration, retained for one release so old files
    /// load. New saves omit it.
    #[serde(default, skip_serializing)]
    pub closure_calibration: Option<(f32, f32)>,
}

/// The one recognizer irlume ever shipped before templates recorded their
/// producer: `glintr100.onnx` (AuraFace), as `"embed:<sha256>"` of its weights,
/// pinned in `models/SHA256SUMS`. Every scan that deserializes with
/// `embed_space: None` was produced by it, because no other recognizer existed
/// when those scans were written.
pub const LEGACY_RECOGNIZER_SPACE: &str =
    "embed:a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60";

/// Is a template tagged `have` comparable with embeddings from the recognizer
/// whose space is `want`?
///
/// Cosine similarity is only meaningful inside one embedding space, so a
/// mismatch means the comparison must not happen at all. An untagged template
/// (`None`) is comparable ONLY when the running recognizer is the historical
/// shipped one: grandfathering it into any space would hand every pre-tagging
/// enrollment to whatever model is loaded, which is the exact hole the tag
/// exists to close.
pub fn recognizer_space_matches(have: Option<&str>, want: &str) -> bool {
    match have {
        Some(have) => have == want,
        None => want == LEGACY_RECOGNIZER_SPACE,
    }
}

/// The producer tag of a scan embedded by the recognizer with weights
/// `recognizer_sha256` on ONNX Runtime `onnx_runtime`, whose CPU session
/// gives `cpu_reference_digest` on the fixed reference inputs (ADR-0022 §2).
pub fn embed_producer(
    recognizer_sha256: &str,
    onnx_runtime: &str,
    cpu_reference_digest: &str,
) -> String {
    format!("cpu:{recognizer_sha256}:ort-{onnx_runtime}:{cpu_reference_digest}")
}

/// The IR embedding space of the shipped pipeline with no adapter loaded.
/// Untagged legacy scans may instead predate the adapter removal (ADR-0004).
pub const IR_RAW_SPACE: &str = "raw";

impl Enrollment {
    pub fn new(user: &str) -> Self {
        Self {
            user: user.into(),
            uid: None,
            loaded_for: None,
            profiles: Vec::new(),
            require_eyes_open: false,
            camera_binding: None,
            closure_calibration: None,
        }
    }

    /// Total scans across all profiles (drives threshold scaling).
    pub fn total_scans(&self) -> usize {
        self.profiles.iter().map(|p| p.scans.len()).sum()
    }

    /// Every RGB template with its (profile, scan) labels, unfiltered.
    ///
    /// Diagnostic/export callers only. Anything that COMPARES vectors must go
    /// through [`Self::rgb_scans_in`]: this accessor returns templates from
    /// every embedding space, and a cosine across spaces is meaningless.
    pub fn rgb_scans(&self) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans
                    .iter()
                    .map(move |s| (p.name.as_str(), s.name.as_str(), s.rgb.as_slice()))
            })
            .collect()
    }

    /// Every RGB template that lives in `space`, with (profile, scan) labels.
    ///
    /// Drops scans from a DIFFERENT recognizer: their vectors are in another
    /// embedding space and a cosine against them is a number with no
    /// interpretation, free to land either side of the threshold. Untagged
    /// scans are compatible only with [`LEGACY_RECOGNIZER_SPACE`], the one
    /// recognizer that can have produced them (#276).
    pub fn rgb_scans_in(&self, space: &str) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans.iter().filter_map(move |s| {
                    recognizer_space_matches(s.embed_space.as_deref(), space).then_some((
                        p.name.as_str(),
                        s.name.as_str(),
                        s.rgb.as_slice(),
                    ))
                })
            })
            .collect()
    }

    /// Every IR template (dark path), with (profile, scan) labels.
    pub fn ir_scans(&self) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans.iter().filter_map(move |s| {
                    s.ir.as_ref()
                        .map(|ir| (p.name.as_str(), s.name.as_str(), ir.as_slice()))
                })
            })
            .collect()
    }

    /// IR templates with an explicit matching pipeline tag and the same
    /// dimensionality as the probe. Recognizer filtering is the caller's job.
    /// Wrong-dimension or foreign-adapter templates never reach this selector's
    /// consumers for comparison.
    pub fn ir_scans_for(&self, space: &str, dim: usize) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans.iter().filter_map(move |s| {
                    let ir = s.ir.as_ref()?;
                    if ir.len() != dim {
                        return None;
                    }
                    (s.ir_space.as_deref() == Some(space)).then_some((
                        p.name.as_str(),
                        s.name.as_str(),
                        ir.as_slice(),
                    ))
                })
            })
            .collect()
    }

    /// IR scans with an unknown or different pipeline tag. These cannot be
    /// selected by [`Enrollment::ir_scans_for`]; fresh captures are needed to
    /// use this pipeline. Stored RGB data remains available.
    pub fn stale_ir_scans(&self, live_space: &str) -> usize {
        self.profiles
            .iter()
            .flat_map(|p| &p.scans)
            .filter(|s| s.ir.is_some())
            .filter(|s| s.ir_space.as_deref() != Some(live_space))
            .count()
    }

    /// IR scans explicitly tagged with the live pipeline. This is the
    /// complement of [`Enrollment::stale_ir_scans`], for compatibility notices;
    /// it does not check recognizer or dimension and is not an auth decision.
    pub fn usable_ir_scans(&self, live_space: &str) -> usize {
        self.profiles
            .iter()
            .flat_map(|p| &p.scans)
            .filter(|s| s.ir.is_some())
            .filter(|s| s.ir_space.as_deref() == Some(live_space))
            .count()
    }

    /// Retired migration, retained as a no-op for source compatibility.
    ///
    /// Old releases shipped raw and adapted IR before tags existed (ADR-0004).
    /// Neither the live pipeline nor the vector dimension proves which one
    /// produced an untagged scan. Never invent that provenance: preserve all
    /// data and return zero. Fresh enrollment captures carry an explicit tag.
    pub fn retag_untagged_ir(&mut self, _space: &str, _dim: usize) -> usize {
        0
    }

    /// Per-user floor on the IR center/edge brightness ratio for the
    /// anti-screen/photo gate: 75% of the weakest ratio this user enrolled with.
    /// Needs ≥2 IR scans. RATIO ONLY; the former per-user IR *brightness* floor
    /// was removed: IR face brightness is strongly ambient-dependent (emitter-only
    /// ~40 in the dark vs ~140 in a lit room, measured on the ASUS Hello cam), so a
    /// brightness floor derived from lit enrollment false-rejects a genuine
    /// dim/night login as a "screen/photo". The global liveness gate (`evaluate`)
    /// already enforces an ambient-tolerant IR brightness floor
    /// (`IR_FACE_MIN_BRIGHTNESS`) and the global ratio floor
    /// (`MIN_CENTER_EDGE_RATIO`); this personalizes the ratio floor on top.
    pub fn ir_center_edge_ratio_floor(&self) -> Option<f32> {
        let mut ratios = Vec::new();
        for p in &self.profiles {
            for s in &p.scans {
                if s.ir.is_some() && s.ir_center_edge_ratio > 0.0 {
                    ratios.push(s.ir_center_edge_ratio);
                }
            }
        }
        if ratios.len() < 2 {
            return None;
        }
        let min = ratios.iter().copied().fold(f32::INFINITY, f32::min);
        Some(min * 0.75)
    }

    /// This user's frontal pitch neutral (the median of the per-scan capture
    /// pitches), or `None` until at least two calibrated scans exist. Lets the
    /// framing guide + capture gate centre on where a LEVEL face actually reads
    /// on this camera instead of a hand-tuned global constant. Scans with pitch
    /// 0.0 (pre-calibration) are ignored, so it stays backward-compatible.
    pub fn pitch_neutral(&self) -> Option<f32> {
        let mut v: Vec<f32> = self
            .profiles
            .iter()
            .flat_map(|p| p.scans.iter())
            .map(|s| s.pitch)
            .filter(|&p| p > 0.0)
            .collect();
        if v.len() < 2 {
            return None;
        }
        v.sort_by(f32::total_cmp);
        Some(v[v.len() / 2])
    }

    /// Default name for the next profile ("Face Profile N", first free slot).
    pub fn next_profile_name(&self) -> String {
        for n in 1..=MAX_PROFILES {
            let cand = format!("Face Profile {n}");
            if !self.profiles.iter().any(|p| p.name == cand) {
                return cand;
            }
        }
        format!("Face Profile {}", self.profiles.len() + 1)
    }
}

impl FaceProfile {
    /// Default name for the next scan ("Face Scan N", first free slot).
    pub fn next_scan_name(&self) -> String {
        for n in 1..=(MAX_SCANS_PER_PROFILE + 1) {
            let cand = format!("Face Scan {n}");
            if !self.scans.iter().any(|s| s.name == cand) {
                return cand;
            }
        }
        format!("Face Scan {}", self.scans.len() + 1)
    }
}

// --- legacy (pre-multi-profile) format, for transparent migration ---
#[derive(Deserialize)]
struct LegacyProfile {
    user: String,
    #[serde(default)]
    templates: Vec<Vec<f32>>,
    #[serde(default)]
    ir_templates: Vec<Vec<f32>>,
    #[serde(default)]
    ir_depth_samples: Vec<f32>,
    #[serde(default)]
    ir_brightness_samples: Vec<f32>,
}

fn migrate(old: LegacyProfile) -> Enrollment {
    let scans = old
        .templates
        .iter()
        .enumerate()
        .map(|(i, t)| FaceScan {
            name: format!("Face Scan {}", i + 1),
            rgb: t.clone(),
            ir: old.ir_templates.get(i).cloned(),
            ir_space: None,    // legacy scans predate space tagging
            embed_space: None, // and predate recognizer tagging

            ir_center_edge_ratio: old.ir_depth_samples.get(i).copied().unwrap_or(0.0),
            embed_producer: None,
            ir_brightness: old.ir_brightness_samples.get(i).copied().unwrap_or(0.0),
            pitch: 0.0,        // legacy scans predate pitch calibration
            captured_at: None, // and record no capture time
        })
        .collect();
    Enrollment {
        user: old.user,
        uid: None,
        loaded_for: None,
        profiles: vec![FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "Face Profile 1".into(),
            scans,
        }],
        require_eyes_open: false,
        camera_binding: None,
        closure_calibration: None,
    }
}

fn state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("IRLUME_STATE_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(home) = std::env::var("HOME") {
        // A `sudo irlume ...` run keeps HOME at the invoking user's home on
        // default sudoers (env_keep). Writing user state from the ROOT uid
        // leaves root-owned files in $HOME that later user-mode runs cannot
        // touch (found on the 2026-08-23 fleet audit: a root-owned
        // ~/.local/share/irlume/<user>.json from July). The dev fallback is
        // for the HUMAN running as themselves; privilege-mismatched HOME is
        // never a dev sandbox, so it resolves to the system state dir instead.
        if !sudo_writing_into_user_home(&home) {
            return PathBuf::from(home).join(".local/share/irlume");
        }
        return PathBuf::from(irlume_common::STATE_DIR);
    }
    PathBuf::from(irlume_common::STATE_DIR)
}

/// True when this process is privileged but $HOME belongs to a non-root user
/// (the `sudo irlume` shape). libc-free: /proc/self/status is Linux-standard.
fn privileged_with_foreign_home(euid: u32, home: &str) -> bool {
    if euid == 0 {
        // Root's own $HOME (/root) is fine; any other HOME means env_keep
        // carried the invoking user's home into the privileged process.
        return home != "/root";
    }
    false
}

fn sudo_writing_into_user_home(home: &str) -> bool {
    let euid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| {
                l.split_whitespace()
                    .nth(2)
                    .and_then(|v| v.parse::<u32>().ok())
            })
        });
    euid.is_some_and(|euid| privileged_with_foreign_home(euid, home))
}

pub fn profile_path(user: &str) -> PathBuf {
    state_dir().join(format!("{user}.json"))
}

/// On-disk wrapper for an encrypted enrollment (historical version 2 or current
/// version 3). The plaintext under `enc` is the same JSON an unencrypted
/// `Enrollment` serializes to.
#[derive(Serialize, Deserialize)]
struct EncEnvelope {
    version: u32,
    /// Public identifier of the random template key. It is not a password
    /// verifier: template keys have 256 bits of entropy. This distinguishes a
    /// mismatched persisted key from damaged GCM data without logging a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    /// base64 of `crypto`'s `nonce ‖ ciphertext+tag`.
    enc: String,
}

/// Version written into new [`EncEnvelope`]s.
const ENC_ENVELOPE_VERSION: u32 = 3;
const LEGACY_ENC_ENVELOPE_VERSION: u32 = 2;

fn is_encrypted_enrollment(v: &serde_json::Value) -> irlume_common::Result<bool> {
    if v.get("enc").is_none() {
        return Ok(false);
    }
    let version = v.get("version").and_then(serde_json::Value::as_u64);
    if matches!(version, Some(version) if version == u64::from(LEGACY_ENC_ENVELOPE_VERSION) || version == u64::from(ENC_ENVELOPE_VERSION))
    {
        return Ok(true);
    }
    let version = version.map_or_else(|| "missing or invalid".to_string(), |v| v.to_string());
    Err(irlume_common::Error::Protocol(format!(
        "unsupported encrypted enrollment version: {version}"
    )))
}

/// Serialize an enrollment, encrypting under `key` when one is supplied (TPM
/// host) or emitting pretty plaintext when not (dev / no-TPM). Pure; tested
/// without a TPM.
/// The on-disk bytes of `e`: the sealed envelope under `key`, or plaintext.
/// Public for fixtures that write a store without touching a TPM.
///
/// # Errors
/// Returns an error when serialization or encryption fails.
pub fn serialize_enrollment(e: &Enrollment, key: Option<&[u8]>) -> irlume_common::Result<Vec<u8>> {
    match key {
        Some(k) => {
            // The serialized enrollment is template plaintext; keep it zeroized
            // once the encrypted blob exists (mirrors the load path).
            let json = Zeroizing::new(
                serde_json::to_vec(e)
                    .map_err(|er| irlume_common::Error::Protocol(er.to_string()))?,
            );
            let blob = crypto::encrypt(k, &json)?;
            let env = EncEnvelope {
                version: ENC_ENVELOPE_VERSION,
                key_id: Some(irlume_common::sha256_hex(k)),
                enc: STANDARD.encode(blob),
            };
            serde_json::to_vec_pretty(&env)
                .map_err(|er| irlume_common::Error::Protocol(er.to_string()))
        }
        None => serde_json::to_vec_pretty(e)
            .map_err(|er| irlume_common::Error::Protocol(er.to_string())),
    }
}

/// Parse on-disk bytes into an `Enrollment`, handling all three formats:
/// encrypted (v2/v3, needs `key`), plaintext multi-profile, and the legacy
/// single-profile layout (migrated). Pure; tested without a TPM.
fn deserialize_enrollment(data: &[u8], key: Option<&[u8]>) -> irlume_common::Result<Enrollment> {
    let v: serde_json::Value =
        serde_json::from_slice(data).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
    if is_encrypted_enrollment(&v)? {
        let env: EncEnvelope =
            serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
        let key = key.ok_or_else(|| {
            irlume_common::Error::Policy(
                "enrollment is encrypted but no template key is available".into(),
            )
        })?;
        if env
            .key_id
            .as_deref()
            .is_some_and(|expected| expected != irlume_common::sha256_hex(key))
        {
            return Err(irlume_common::Error::Policy(
                "template key does not match enrollment; preserve state and try recovery restore"
                    .into(),
            ));
        }
        let blob = STANDARD
            .decode(env.enc.as_bytes())
            .map_err(|e| irlume_common::Error::Protocol(format!("bad enc blob: {e}")))?;
        let plain = crypto::decrypt(key, &blob)?;
        serde_json::from_slice(&plain).map_err(|e| irlume_common::Error::Protocol(e.to_string()))
    } else if v.get("profiles").is_some() {
        serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))
    } else {
        let old: LegacyProfile =
            serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
        Ok(migrate(old))
    }
}

/// Resolve the key to encrypt `user`'s templates with: the TPM-sealed template
/// key on a TPM host (generated on first save, and replaced when it was
/// sealed for another uid or the records coupled to it show it is another
/// account's, [`key_is_another_accounts`]), or `None` on a no-TPM host
/// (plaintext fallback so dev boxes still work). `account` is the save's view
/// of the account.
fn save_key(
    user: &str,
    account: &mut Account<'_>,
) -> irlume_common::Result<Option<template_key::WriteKey>> {
    if template_key::tpm_available() {
        Ok(Some(template_key::ensure_enrollment_key_unlocked(
            user,
            account,
            &key_is_another_accounts,
        )?))
    } else {
        Ok(None)
    }
}

/// Whether `key`, the template key sealed for `user`, is another account's
/// as `account` resolves it ([`template_key::KeyIsAnotherAccounts`]). A key
/// an earlier release sealed without a uid carries no uid of its own to
/// check, so the records coupled to it decide:
///
/// - the enrollment stored for `user`, read with `key`, records one once it
///   has been written again, and one recorded for another uid makes the key
///   that account's, whatever the key records;
/// - when that enrollment records no uid either (or none is stored, or `key`
///   does not read it), the recovery envelope does: a setup records the uid
///   it wrapped the key for
///   ([`template_key::unbound_key_has_another_accounts_recovery`]), and one
///   that is stored but cannot be read is an error.
///
/// A write for this account then does not reuse the key: it protects that
/// account's templates, and that account's recovery envelope restores it.
/// An enrollment write replaces the key; an added-camera store write is
/// refused ([`template_key::ensure_camera_store_key`]). An error refuses
/// either write.
pub(crate) fn key_is_another_accounts(
    user: &str,
    key: &[u8],
    account: &mut Account<'_>,
) -> irlume_common::Result<bool> {
    match account.owner(stored_enrollment_uid(user, Some(key))) {
        Owner::Other { .. } => Ok(true),
        Owner::Unrecorded => template_key::unbound_key_has_another_accounts_recovery(user, account),
        Owner::Current | Owner::Unknown { .. } => Ok(false),
    }
}

/// Whether the enrollment stored for `user`, read with `key` (`None`: only a
/// plaintext one reads), records a uid that `account` resolves as another
/// account's. `false` when no enrollment is stored or `key` does not read it.
fn stored_enrollment_is_another_accounts(
    user: &str,
    key: Option<&[u8]>,
    account: &mut Account<'_>,
) -> bool {
    matches!(
        account.owner(stored_enrollment_uid(user, key)),
        Owner::Other { .. }
    )
}

/// The uid the enrollment stored for `user` records, read with `key`
/// (`None`: only a plaintext one reads). `None` when no enrollment is
/// stored, `key` does not read it, or it records no uid.
pub(crate) fn stored_enrollment_uid(user: &str, key: Option<&[u8]>) -> Option<u32> {
    let data = fs::read(profile_path(user)).ok()?;
    deserialize_enrollment(&data, key).ok()?.uid
}

/// Publish `bytes` as the enrollment at `path`; [`publication_result`] turns
/// the outcome into the write's result.
fn persist_enrollment(
    path: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<irlume_common::AtomicWrite> {
    irlume_common::write_atomic_reporting(path, bytes, 0o600)
}

fn publication_result(
    result: std::io::Result<irlume_common::AtomicWrite>,
) -> irlume_common::Result<()> {
    match result {
        Ok(irlume_common::AtomicWrite::Durable) => Ok(()),
        Ok(irlume_common::AtomicWrite::VisibleNotDurable(error)) => Err(irlume_common::Error::Io(
            format!("enrollment was published, but durability could not be confirmed: {error}; inspect profiles before retrying"),
        )),
        Err(error) => Err(irlume_common::Error::Io(error.to_string())),
    }
}

#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn save(e: &Enrollment) -> irlume_common::Result<()> {
    save_with_key(e, save_key)
}

/// Save using a late atomic publisher after state locking and key preparation.
/// The publisher must preserve owner-only atomic-write and receipt semantics.
///
/// # Errors
/// Returns preparation or publication errors; replacement settlement still runs
/// when the publisher refuses before writing.
pub fn save_with_publisher(
    e: &Enrollment,
    publish: impl FnOnce(&Path, &[u8]) -> irlume_common::Result<irlume_common::AtomicWrite>,
) -> irlume_common::Result<()> {
    save_with_key_and_publisher(e, save_key, publish)
}

/// Publish a replacement enrollment, preserving an existing template key and
/// recovery envelope. An encrypted store cannot become plaintext if its key
/// is missing or the TPM becomes unavailable.
///
/// # Errors
/// Returns key, serialization, or filesystem errors. If publication succeeded
/// but directory synchronization failed, the error explicitly says so.
pub fn save_replacement(e: &Enrollment) -> irlume_common::Result<()> {
    save_replacement_with_publisher(e, |path, bytes| {
        persist_enrollment(path, bytes).map_err(|error| irlume_common::Error::Io(error.to_string()))
    })
}

/// Replacement save with admission at the final atomic publication boundary.
/// Existing template-key retention, rollback and durability settlement apply.
///
/// # Errors
/// Returns key, serialization or publisher errors without skipping settlement.
pub fn save_replacement_with_publisher(
    e: &Enrollment,
    publish: impl FnOnce(&Path, &[u8]) -> irlume_common::Result<irlume_common::AtomicWrite>,
) -> irlume_common::Result<()> {
    save_with_key_and_publisher(
        e,
        |user, account| {
            replacement_key(
                user,
                account,
                template_key::load_key_unmoved_as,
                template_key::move_kept_key,
                save_key,
            )
        },
        publish,
    )
}

/// The key a replacement enrollment is written under; `account` is the
/// save's view of the account. The existing key is loaded with
/// `load_existing`, which writes nothing, and moves to a stronger TPM policy
/// (`move_kept`) only once the write keeps it: a write refused over the key
/// leaves the key file as it was, and `first_save` sets aside a key it
/// replaces as it was.
fn replacement_key(
    user: &str,
    account: &mut Account<'_>,
    load_existing: impl FnOnce(&str, &mut Account<'_>) -> irlume_common::Result<Zeroizing<Vec<u8>>>,
    move_kept: impl FnOnce(&str, &[u8]),
    first_save: impl FnOnce(
        &str,
        &mut Account<'_>,
    ) -> irlume_common::Result<Option<template_key::WriteKey>>,
) -> irlume_common::Result<Option<template_key::WriteKey>> {
    // Probe first even when a key exists: the probe admits the stored format,
    // and short-circuiting it would let replacement overwrite a future schema.
    let encrypted_store = store_is_encrypted(user)? == Some(true);
    // A key sealed for another uid protects that account's enrollment, which
    // this one replaces: the first-save path gives the account its own key
    // (`template_key::ensure_enrollment_key_unlocked`) and never unseals the
    // other.
    if template_key::key_is_for_another_account(user, account) {
        return first_save(user, account);
    }
    if template_key::has_key(user) || encrypted_store {
        // Never mint a replacement key or fall back to plaintext on unseal
        // failure. The user can restore recovery or explicitly delete state.
        let key = load_existing(user, account)?;
        // A key that opens an enrollment recorded for another uid, or whose
        // recovery envelope records one while neither it nor its enrollment
        // does (a key an earlier release sealed without a uid), is that
        // account's key: the first-save path replaces it, as it does a key
        // sealed for another uid. A recovery envelope that cannot be read
        // refuses the write.
        if key_is_another_accounts(user, &key, account)? {
            return first_save(user, account);
        }
        move_kept(user, &key);
        Ok(Some(template_key::WriteKey::kept(key)))
    } else {
        first_save(user, account)
    }
}

fn save_with_key(
    e: &Enrollment,
    resolve_key: impl FnOnce(
        &str,
        &mut Account<'_>,
    ) -> irlume_common::Result<Option<template_key::WriteKey>>,
) -> irlume_common::Result<()> {
    save_with_key_and_publisher(e, resolve_key, |path, bytes| {
        persist_enrollment(path, bytes).map_err(|error| irlume_common::Error::Io(error.to_string()))
    })
}

fn save_with_key_and_publisher(
    e: &Enrollment,
    resolve_key: impl FnOnce(
        &str,
        &mut Account<'_>,
    ) -> irlume_common::Result<Option<template_key::WriteKey>>,
    publish: impl FnOnce(&Path, &[u8]) -> irlume_common::Result<irlume_common::AtomicWrite>,
) -> irlume_common::Result<()> {
    let _state = template_key::UserStateLock::acquire(&e.user)?;
    let dir = state_dir();
    fs::create_dir_all(&dir).map_err(|er| irlume_common::Error::Io(er.to_string()))?;
    let path = profile_path(&e.user);
    // The uid this enrollment belongs to: the one it records, or else the uid
    // of the account its load was for (`loaded_for`). The write keeps it, and
    // is refused with nothing written when the name now resolves to another
    // uid or to no account, so a load and the save after it act for one
    // account. A new enrollment, or one without a uid loaded while the name
    // resolved to no uid, records the current uid. When the uid cannot be
    // resolved the enrollment keeps the one it has, and one without a uid is
    // not written. The key is chosen against the same resolution.
    let mut account = Account::new(&e.user);
    let uid = account.uid_to_record(Record::Enrollment, e.uid.or(e.loaded_for))?;
    let key = resolve_key(&e.user, &mut account)?;
    // Whether this write replaces another account's enrollment: its key was
    // replaced as another uid's (the replacement is recorded already), or
    // the stored enrollment is plaintext and records another uid (a host
    // without a TPM), which is recorded here before anything is written.
    let key_replaces = key
        .as_ref()
        .is_some_and(template_key::WriteKey::replaces_another);
    let replaces_other =
        key_replaces || stored_enrollment_is_another_accounts(&e.user, None, &mut account);
    if replaces_other && !key_replaces {
        crate::replacement::begin(&e.user, None)?;
    }
    let stamped;
    let e = if uid == e.uid {
        e
    } else {
        stamped = Enrollment { uid, ..e.clone() };
        &stamped
    };
    let written = serialize_enrollment(e, key.as_ref().map(template_key::WriteKey::as_slice))
        .map(|bytes| publish(&path, &bytes));
    let published = match &written {
        Ok(Ok(published)) => Some(published),
        _ => None,
    };
    // A replacement becomes final only once this enrollment is durable: the
    // replaced key's recovery envelope and the replaced enrollment's
    // added-camera store go then. A write that published nothing puts the
    // replaced key back. One that may not survive a power loss keeps its
    // record, which the next acquisition of the state lock settles.
    let settled = match key {
        Some(key) if key_replaces => key.settle(published),
        _ if replaces_other => match published {
            Some(irlume_common::AtomicWrite::Durable) => crate::replacement::finish(&e.user),
            Some(irlume_common::AtomicWrite::VisibleNotDurable(_)) => Ok(()),
            None => crate::replacement::undo(&e.user),
        },
        _ => Ok(()),
    };
    settled?;
    publication_result(Ok(written??))
}

/// Load an enrollment, transparently decrypting v2/v3 and migrating the legacy
/// single-profile format. A plaintext file loads without touching the TPM; an
/// encrypted file unseals the template key (and fails cleanly, with face auth
/// falling back to the password, if the seal can no longer be satisfied).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn load(user: &str) -> irlume_common::Result<Option<Enrollment>> {
    load_with(
        user,
        template_key::UserStateLock::acquire_for_load,
        template_key::load_key_as,
    )
    .map(|loaded| loaded.map(|(enrollment, _)| enrollment))
}

/// Load an enrollment before a possible write without moving its sealed key
/// to a stronger TPM policy. The write moves a key only after deciding to keep
/// it, so a refused mutation leaves the key envelope as it was.
///
/// # Errors
/// As [`load`].
pub fn load_unmoved(user: &str) -> irlume_common::Result<Option<Enrollment>> {
    load_with(
        user,
        template_key::UserStateLock::acquire_for_load,
        template_key::load_key_unmoved_as,
    )
    .map(|loaded| loaded.map(|(enrollment, _)| enrollment))
}

/// An enrollment together with the template key its load unsealed (`None`
/// for a plaintext store).
pub type LoadedEnrollment = (Enrollment, Option<Zeroizing<Vec<u8>>>);

/// [`load`] that also returns the template key it unsealed (`None` for a
/// plaintext store), so the rest of an authentication request can lend that
/// key to its later encrypted reads instead of unsealing again (ADR-0025).
/// Unlike [`load`], it never moves the key to a stronger TPM policy, whose
/// round trip would unseal it a second time; irlumed does that at startup.
///
/// # Errors
/// As [`load`].
pub fn load_with_key(user: &str) -> irlume_common::Result<Option<LoadedEnrollment>> {
    load_with(
        user,
        template_key::UserStateLock::acquire_for_load,
        template_key::load_key_for_authentication_as,
    )
}

/// Load an enrollment without writing enrollment, key, recovery, or lock files
/// or initializing a persistent TPM storage root key. Legacy migration happens
/// only in memory; encrypted stores still require successful TPM unsealing.
///
/// # Errors
/// Returns an error if the existing user lock is absent, or on a read, unseal,
/// or decryption failure. This diagnostic path does not initialize state.
pub fn load_read_only(user: &str) -> irlume_common::Result<Option<Enrollment>> {
    load_with(
        user,
        template_key::UserStateLock::acquire_read_only,
        template_key::load_key_read_only_as,
    )
    .map(|loaded| loaded.map(|(enrollment, _)| enrollment))
}

/// A primary enrollment together with the key its load unsealed and the
/// exact bytes it was parsed from. The IR-only route pins its primary
/// scope by these bytes' digest, offers them to the secondary store's
/// activation check without a second read, and lends the key to the
/// request so nothing unseals twice (ADR-0028 §4-5).
pub struct PrimarySnapshot {
    pub enrollment: Enrollment,
    /// `None` for a plaintext store.
    pub key: Option<Zeroizing<Vec<u8>>>,
    /// The file's bytes as parsed (ciphertext for an encrypted store).
    pub bytes: Vec<u8>,
}

/// [`load_with_key`] as a [`PrimarySnapshot`].
///
/// # Errors
/// As [`load_with_key`].
pub fn load_snapshot(user: &str) -> irlume_common::Result<Option<PrimarySnapshot>> {
    load_snapshot_with(
        user,
        template_key::UserStateLock::acquire_for_load,
        template_key::load_key_for_authentication_as,
    )
}

/// [`load_read_only`] as a [`PrimarySnapshot`], keeping the key it unsealed.
///
/// # Errors
/// As [`load_read_only`].
pub fn load_snapshot_read_only(user: &str) -> irlume_common::Result<Option<PrimarySnapshot>> {
    load_snapshot_with(
        user,
        template_key::UserStateLock::acquire_read_only,
        template_key::load_key_read_only_as,
    )
}

fn load_with(
    user: &str,
    acquire_lock: impl FnOnce(&str) -> irlume_common::Result<template_key::UserStateLock>,
    load_key: impl FnOnce(&str, &mut Account<'_>) -> irlume_common::Result<Zeroizing<Vec<u8>>>,
) -> irlume_common::Result<Option<LoadedEnrollment>> {
    load_snapshot_with(user, acquire_lock, load_key)
        .map(|loaded| loaded.map(|snapshot| (snapshot.enrollment, snapshot.key)))
}

fn load_snapshot_with(
    user: &str,
    acquire_lock: impl FnOnce(&str) -> irlume_common::Result<template_key::UserStateLock>,
    load_key: impl FnOnce(&str, &mut Account<'_>) -> irlume_common::Result<Zeroizing<Vec<u8>>>,
) -> irlume_common::Result<Option<PrimarySnapshot>> {
    let _state = acquire_lock(user)?;
    let path = profile_path(user);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    // Validate the encrypted format before resolving a key: on TPM hosts,
    // key resolution can open a TPM context and attempt an unseal.
    let is_enc = match serde_json::from_slice::<serde_json::Value>(&data) {
        Ok(value) => is_encrypted_enrollment(&value)?,
        Err(_) => false,
    };
    // An enrollment, or the key it is encrypted under, recorded for another
    // uid reads as absent: the account is not enrolled (`crate::account`).
    let mut account = Account::new(user);
    let key = if is_enc {
        let loaded = load_key(user, &mut account);
        match account.absent_if_other(loaded)? {
            Some(key) => Some(key),
            None => return Ok(None),
        }
    } else {
        None
    };
    let mut enrollment = deserialize_enrollment(&data, key.as_ref().map(|k| k.as_slice()))?;
    let checked = account.require(Record::Enrollment, enrollment.uid);
    if account.absent_if_other(checked)?.is_none() {
        return Ok(None);
    }
    // The uid the checks above held the enrollment and its key to, carried
    // to a save of this enrollment ([`Enrollment::loaded_for`]). When neither
    // records one, the uid the name resolves to now: the save is then held
    // to the account this load was for, not to one that takes the name in
    // between.
    enrollment.loaded_for = account.current_uid();
    Ok(Some(PrimarySnapshot {
        enrollment,
        key,
        bytes: data,
    }))
}

/// Parses the enrollment at an explicit path WITHOUT acquiring the user
/// state lock (ADR-0024 §1.1 note: the coordinator's pin and grant
/// boundary run after the authentication-flow loader, which held the
/// lock; a concurrent legacy write can at worst change the file's bytes,
/// which the snapshot-digest binding treats as a change - fail-closed).
///
/// Same parse semantics as [`load`]: legacy-format files migrate in
/// memory, sealed envelopes require a loadable template key for `user`.
/// A missing file is `Ok(None)`.
///
/// # Errors
/// Returns an error on read, envelope-version, key-load, or parse
/// failure - never a plaintext fallback for an encrypted store.
pub fn load_path_unlocked(
    user: &str,
    path: &std::path::Path,
) -> irlume_common::Result<Option<Enrollment>> {
    load_path_with_source(
        user,
        path,
        &mut template_key::RequestTemplateKey::production(),
    )
}

/// [`load_path_unlocked`] with the request's key source (ADR-0025): an
/// encrypted store borrows the key the request already holds, or has the
/// source unseal once; a plaintext store never asks for a key. An encrypted
/// store on a host whose source lends no key fails closed.
///
/// # Errors
/// As [`load_path_unlocked`].
pub fn load_path_with_source(
    user: &str,
    path: &std::path::Path,
    keys: &mut dyn template_key::TemplateKeySource,
) -> irlume_common::Result<Option<Enrollment>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    let is_enc = match serde_json::from_slice::<serde_json::Value>(&data) {
        Ok(value) => is_encrypted_enrollment(&value)?,
        Err(_) => false,
    };
    let enrollment = if is_enc {
        // The key source checks the sealed key's uid before it unseals.
        let Some(key) = keys.template_key(user)? else {
            return Err(irlume_common::Error::Policy(format!(
                "no template key is available to read '{user}'s encrypted store"
            )));
        };
        deserialize_enrollment(&data, Some(key))?
    } else {
        deserialize_enrollment(&data, None)?
    };
    // Recorded for another uid: absent, as in `load`.
    let mut account = Account::new(user);
    let checked = account.require(Record::Enrollment, enrollment.uid);
    if account.absent_if_other(checked)?.is_none() {
        return Ok(None);
    }
    Ok(Some(Enrollment {
        loaded_for: account.current_uid(),
        ..enrollment
    }))
}

/// Whether the on-disk store for `user` is encrypted, `Ok(None)` when there
/// is no store at all, and `Err` when a store exists but cannot be read.
///
/// Read from the file's own `enc` envelope, NOT from whether a template key
/// exists. Those two answers disagree in exactly one state, and it is the state
/// the user most needs told about: an encrypted store whose key has been lost.
/// Reporting that as "plaintext at rest" both understates the privacy posture
/// and hides the data loss, and it points the user at `recovery setup` when the
/// only remaining move is to re-enroll.
///
/// An unreadable store is NOT the same as an absent one: collapsing it to
/// `None` would deny "not enrolled" where the caller's full load reports an
/// error (and the password fallback). Unparseable bytes read as plaintext so
/// that full load surfaces the real parse error instead of this probe.
///
/// # Errors
/// `Io` when a store exists but cannot be read.
pub fn store_is_encrypted(user: &str) -> irlume_common::Result<Option<bool>> {
    let path = profile_path(user);
    match fs::read(&path) {
        Ok(data) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(value) => is_encrypted_enrollment(&value).map(Some),
            Err(_) => Ok(Some(false)),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(irlume_common::Error::Io(e.to_string())),
    }
}

/// What [`delete`] found and removed for one account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deleted {
    /// The primary enrollment file existed and was removed.
    pub enrollment: bool,
    /// The added cameras' store (`cameras/<user>.json`), its commit journal
    /// or a staging file one of their writers left existed and was removed.
    pub camera_store: bool,
}

/// Deletes all of `user`'s face data under the user state lock: the added
/// cameras' store, its commit journal and any staging file an interrupted
/// write of either left beside them (removing the account's face data
/// covers every camera group, ADR-0024 §4.2), then the primary enrollment,
/// then the now-orphaned template key and recovery envelope (a fresh
/// enrollment mints a new key).
///
/// The camera store goes first, its journal before it: a journal left
/// behind would let the next authentication's commit recovery rewrite the
/// store from it. A failure part way leaves the primary enrollment in place,
/// so the same request can be repeated, rather than an unenrolled account
/// whose camera store no request removes any more.
///
/// # Errors
/// Returns the lock error, or the I/O error of the first removal or
/// directory sync that fails; whatever was removed before it stays removed.
pub fn delete(user: &str) -> irlume_common::Result<Deleted> {
    delete_with(user, sync_directory)
}

/// [`delete`] with the camera directory's sync supplied (tests fail it).
fn delete_with(
    user: &str,
    mut sync_dir: impl FnMut(&Path) -> std::io::Result<()>,
) -> irlume_common::Result<Deleted> {
    let _state = template_key::UserStateLock::acquire(user)?;
    let camera_store = delete_camera_store_unlocked(user, &mut sync_dir)?;
    let path = profile_path(user);
    let existed = path.exists();
    if existed {
        fs::remove_file(&path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    }
    template_key::forget_key_unlocked(user)?;
    template_key::forget_recovery_unlocked(user)?;
    Ok(Deleted {
        enrollment: existed,
        camera_store,
    })
}

/// Removes `user`'s added-camera commit journal, then the store, then the
/// staging files their writers left ([`camera_staging_files`]), syncing the
/// directory after each removal so the journal cannot outlive the store
/// after a crash. The caller holds the user state lock. `Ok(true)` when any
/// of these files existed.
///
/// When every file is already gone the directory is synced anyway: an
/// earlier attempt may have removed the last of them and then failed to
/// sync, and the primary enrollment must not go while a power loss could
/// still bring that file back. Only a missing directory skips the sync.
fn delete_camera_store_unlocked(
    user: &str,
    sync_dir: &mut impl FnMut(&Path) -> std::io::Result<()>,
) -> irlume_common::Result<bool> {
    let store = crate::multi_camera::secondary_store_path(user);
    let dir = store.parent().unwrap_or_else(|| Path::new("."));
    let mut paths = vec![
        crate::multi_camera::commit::intent_path_for(&store),
        store.clone(),
    ];
    paths.extend(camera_staging_files(&store, dir)?);
    let sync_error =
        |e: std::io::Error| irlume_common::Error::Io(format!("sync {}: {e}", dir.display()));
    let mut removed = false;
    for path in &paths {
        match fs::remove_file(path) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(irlume_common::Error::Io(format!(
                    "remove {}: {e}",
                    path.display()
                )))
            }
        }
        sync_dir(dir).map_err(sync_error)?;
    }
    if !removed {
        match sync_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(sync_error(e)),
        }
    }
    Ok(removed)
}

/// Makes the removals in `dir` durable.
fn sync_directory(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// The staging files in `dir` that a writer of the added cameras' store at
/// `store`, or of its commit journal, left before its rename: an interrupted
/// or failed write keeps the new store bytes there
/// ([`crate::multi_camera::is_staging_file_of`]). A missing directory has
/// none.
fn camera_staging_files(store: &Path, dir: &Path) -> irlume_common::Result<Vec<PathBuf>> {
    let list_error =
        |e: std::io::Error| irlume_common::Error::Io(format!("list {}: {e}", dir.display()));
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(list_error(e)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(list_error)?;
        if crate::multi_camera::is_staging_file_of(store, &entry.file_name()) {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// Has the startup IR compatibility sweep already run for this space?
/// The historical name and marker format are retained for compatibility;
/// the daemon no longer retags enrollment data.
///
/// Reading scan metadata is not free. The answer lives inside the
/// encrypted enrollment, so the daemon used to unseal every user's TPM-sealed
/// template key at startup just to find nothing to do. On a discrete TPM that
/// is seconds per user, it happens on every boot, and the TPM serializes, so it
/// collided with the login it was delaying: a keyring unseal measured 2.70s on a
/// quiet daemon and 18.97s against that startup (#249).
///
/// The marker records the embedding space the sweep completed for. It only ever
/// SKIPS WORK: a missing, stale or unreadable marker runs the sweep, and no
/// security decision reads it. Its absence costs a slow startup, never a wrong
/// answer.
pub fn retag_done_for(space: &str) -> bool {
    fs::read_to_string(retag_marker_path())
        .map(|s| s.trim() == space)
        .unwrap_or(false)
}

/// Record that the sweep finished for `space`. Best-effort: failing to write it
/// costs a repeated sweep next boot, which is the pre-existing behaviour.
pub fn mark_retag_done(space: &str) {
    let path = retag_marker_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    // 0600 like every other state file: the content is only a space tag, but
    // a state-dir override can point at a looser directory than production's
    // root-only /var/lib/irlume, and a plain `fs::write` lands 0644 there
    // (found by the 2026-09-17 sandbox battery).
    let _ = irlume_common::write_0600_atomic(&path, format!("{space}\n").as_bytes());
}

fn retag_marker_path() -> PathBuf {
    state_dir().join(".ir-retag-space")
}

/// Every OS user with an enrollment on this host (the `<user>.json` stems in the
/// state dir), sorted. For 1:N identify and status reporting. Returns an empty
/// list if the state dir doesn't exist yet.
pub fn list_users() -> Vec<String> {
    list_users_at(&state_dir())
}

/// [`list_users`] against an explicit state directory, for callers that sweep
/// state the process environment does not carry (the uninstaller's
/// source-install roots under `~/.local/share/irlume`).
pub fn list_users_at(dir: &Path) -> Vec<String> {
    let mut users = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    users.push(stem.to_string());
                }
            }
        }
    }
    users.sort();
    users
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_scan_records_its_producer_and_older_scans_load_without_one() {
        // ADR-0022 §2: additive and optional, so an older binary ignores the
        // field and a scan written before it loads with none.
        let producer = embed_producer("abc", "1.28.1", "d1g3st");
        assert_eq!(producer, "cpu:abc:ort-1.28.1:d1g3st");
        let mut scan = scan("s", 0.5, Some("embed:x"));
        scan.embed_producer = Some(producer.clone());
        let json = serde_json::to_string(&scan).unwrap();
        let back: FaceScan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.embed_producer.as_deref(), Some(producer.as_str()));
        let mut old: serde_json::Value = serde_json::from_str(&json).unwrap();
        old.as_object_mut().unwrap().remove("embed_producer");
        let legacy: FaceScan = serde_json::from_value(old).unwrap();
        assert_eq!(legacy.embed_producer, None);
        // Absent, it is not written: an older scan rewrites to its own bytes.
        assert!(!serde_json::to_string(&legacy).unwrap().contains("embed_producer"));
    }
    #[test]
    fn retag_marker_is_written_no_looser_than_0600() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("retag-marker-mode"));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        mark_retag_done("embed:test");
        std::env::remove_var("IRLUME_STATE_DIR");
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.join(".ir-retag-space"))
            .expect("marker written")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the retag marker must not be group/world readable"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_users_at_reads_only_the_named_dir() {
        let dir = PathBuf::from(crate::test_tmp_dir("list-users-at"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("cameras")).unwrap();
        fs::write(dir.join("bob.json"), b"{}").unwrap();
        fs::write(dir.join("cameras/bob.json"), b"{}").unwrap();
        fs::write(dir.join("note.txt"), b"").unwrap();
        assert_eq!(list_users_at(&dir), vec!["bob".to_string()]);
        assert!(
            list_users_at(&dir.join("nonexistent")).is_empty(),
            "a missing dir is no users, never an error"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Plants `u`'s enrollment (plaintext), added-camera store and journal,
    /// sealed-key and recovery files, plus another account's camera store,
    /// under a fresh state dir. Returns (primary, store, journal, other).
    fn plant_account_state(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let _ = fs::remove_dir_all(dir);
        std::env::set_var("IRLUME_STATE_DIR", dir);
        let primary = profile_path("u");
        fs::create_dir_all(primary.parent().unwrap()).unwrap();
        fs::write(&primary, serialize_enrollment(&sample(), None).unwrap()).unwrap();
        let store = crate::multi_camera::secondary_store_path("u");
        let journal = crate::multi_camera::commit::intent_path_for(&store);
        let other = crate::multi_camera::secondary_store_path("v");
        fs::create_dir_all(store.parent().unwrap()).unwrap();
        for path in [&store, &journal, &other] {
            fs::write(path, b"{}").unwrap();
        }
        for path in [
            template_key::key_path("u"),
            template_key::recovery_path("u"),
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"{}").unwrap();
        }
        (primary, store, journal, other)
    }

    #[test]
    fn deleting_an_account_removes_its_added_camera_store_and_journal() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("delete-camera-store"));
        let (primary, store, journal, other) = plant_account_state(&dir);

        assert_eq!(
            delete("u").unwrap(),
            Deleted {
                enrollment: true,
                camera_store: true
            }
        );
        for path in [
            primary,
            store.clone(),
            journal,
            template_key::key_path("u"),
            template_key::recovery_path("u"),
        ] {
            assert!(!path.exists(), "{} outlived the deletion", path.display());
        }
        assert!(
            other.exists(),
            "another account's camera store is untouched"
        );

        // A camera store left without its enrollment goes on the next
        // deletion too, and a deletion with nothing left is a no-op.
        fs::write(&store, b"{}").unwrap();
        assert_eq!(
            delete("u").unwrap(),
            Deleted {
                enrollment: false,
                camera_store: true
            }
        );
        assert!(!store.exists());
        assert_eq!(delete("u").unwrap(), Deleted::default());
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_camera_journal_that_cannot_be_removed_keeps_the_store_and_the_enrollment() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("delete-camera-journal"));
        let (primary, store, journal, _) = plant_account_state(&dir);
        // A directory in the journal's place cannot be unlinked, even by root.
        fs::remove_file(&journal).unwrap();
        fs::create_dir_all(journal.join("blocker")).unwrap();

        delete("u").expect_err("a journal that stays must fail the deletion");
        assert!(store.exists(), "the store goes only after its journal");
        assert!(
            primary.exists(),
            "the enrollment stays so the deletion can be repeated"
        );
        assert!(template_key::key_path("u").exists());

        fs::remove_dir_all(&journal).unwrap();
        assert_eq!(
            delete("u").unwrap(),
            Deleted {
                enrollment: true,
                camera_store: true
            }
        );
        assert!(!store.exists() && !primary.exists());
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_repeated_deletion_syncs_the_camera_directory_before_the_enrollment_goes() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("delete-camera-resync"));
        let (primary, store, journal, _) = plant_account_state(&dir);
        let cameras = store.parent().unwrap().to_path_buf();
        let failed = || std::io::Error::other("sync failed");

        // The journal's removal is synced, the store's is not: both files
        // are gone, but a power loss could still bring the store back.
        let mut syncs = 0;
        delete_with("u", |_| {
            syncs += 1;
            if syncs == 1 {
                Ok(())
            } else {
                Err(failed())
            }
        })
        .expect_err("a failed sync must fail the deletion");
        assert!(!journal.exists() && !store.exists());
        assert!(primary.exists(), "the enrollment stays after a failed sync");

        // The repeated request finds nothing left to remove in the camera
        // directory and still syncs it; a failure keeps the enrollment.
        delete_with("u", |_| Err(failed()))
            .expect_err("the camera directory must be synced before the enrollment goes");
        assert!(primary.exists() && template_key::key_path("u").exists());

        let mut synced = Vec::new();
        assert_eq!(
            delete_with("u", |dir| {
                synced.push(dir.to_path_buf());
                Ok(())
            })
            .unwrap(),
            Deleted {
                enrollment: true,
                camera_store: false
            }
        );
        assert_eq!(synced, [cameras.clone()]);
        assert!(!primary.exists());

        // Without a camera directory there is nothing to sync.
        fs::remove_dir_all(&cameras).unwrap();
        assert_eq!(
            delete_with("u", sync_directory).unwrap(),
            Deleted::default()
        );
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn deleting_an_account_removes_the_staging_files_its_camera_store_writers_left() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("delete-camera-staging"));
        let (primary, store, journal, other) = plant_account_state(&dir);
        fs::remove_file(&store).unwrap();
        fs::remove_file(&journal).unwrap();
        let cameras = store.parent().unwrap();
        // What an interrupted save_secondary, and an interrupted commit of
        // the store or of its journal, leave: the store's bytes under a
        // staging name.
        let left = [
            ".u.json.tmp-4242",
            ".u.json.commit-tmp-17",
            ".u.json.intent.commit-tmp-17",
        ];
        // Another account's staging files ("v", and "u.json" whose store is
        // u.json.json), and names that only resemble u's.
        let kept = [
            ".v.json.tmp-4242",
            ".u.json.json.tmp-17",
            ".u.json.tmp-",
            ".u.json.tmp-17.swp",
            "u.json.tmp-17",
            ".u.json.bak",
        ];
        for name in left.iter().chain(&kept) {
            fs::write(cameras.join(name), b"{}").unwrap();
        }

        assert_eq!(
            delete("u").unwrap(),
            Deleted {
                enrollment: true,
                camera_store: true
            }
        );
        for name in left {
            assert!(!cameras.join(name).exists(), "{name} outlived the deletion");
        }
        for name in kept {
            assert!(cameras.join(name).exists(), "{name} is not u's and stays");
        }
        assert!(!primary.exists() && other.exists());
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_only_plaintext_load_preserves_enrollment_and_missing_state() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("readonly-store"));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        assert!(load_read_only("u").is_err());
        assert!(!dir.exists());
        drop(template_key::UserStateLock::acquire("u").unwrap());
        assert!(load_read_only("u").unwrap().is_none());
        let path = profile_path("u");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = serialize_enrollment(&sample(), None).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(load_read_only("u").unwrap().unwrap().user, "u");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        std::env::remove_var("IRLUME_STATE_DIR");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protected_load_decrypts_without_rewriting_enrollment() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("readonly-encrypted-store"));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        drop(template_key::UserStateLock::acquire("u").unwrap());
        let path = profile_path("u");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = serialize_enrollment(&sample(), Some(&[42; 32])).unwrap();
        fs::write(&path, &bytes).unwrap();
        let loaded = load_with(
            "u",
            template_key::UserStateLock::acquire_read_only,
            |user, _| {
                assert_eq!(user, "u");
                Ok(Zeroizing::new(vec![42; 32]))
            },
        )
        .unwrap()
        .unwrap();
        let (loaded, key) = loaded;
        assert_eq!(
            key.as_deref().map(Vec::as_slice),
            Some(&[42u8; 32][..]),
            "the key the load unsealed is returned for the request to lend"
        );
        assert_eq!(
            loaded.profiles[0].scans[0].ir.as_deref(),
            Some(&[0.5, 0.6][..])
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(load_with(
            "u",
            template_key::UserStateLock::acquire_read_only,
            |_, _| {
                Err(irlume_common::Error::Policy(
                    "synthetic unseal refusal".into(),
                ))
            }
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        std::env::remove_var("IRLUME_STATE_DIR");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_ir_retag_preserves_all_scan_data_in_every_live_space() {
        let mut enr = Enrollment::new("u");
        enr.profiles.push(FaceProfile {
            name: "p".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: vec![
                scan_in_space("legacy", 4, None),
                scan_in_space("tagged", 4, Some("raw")),
                scan_in_space("adapter", 4, Some("adapter:old")),
                scan_in_space("old-dimension", 2, None),
            ],
        });
        let before = serde_json::to_value(&enr).unwrap();
        for space in ["adapter:new", IR_RAW_SPACE] {
            for dim in [2, 4, 512] {
                assert_eq!(enr.retag_untagged_ir(space, dim), 0);
                assert_eq!(serde_json::to_value(&enr).unwrap(), before);
            }
        }
    }

    #[test]
    fn unknown_ir_withholds_both_calibration_slots_only_for_its_recognizer() {
        let c = crate::calib::IrCalibration {
            m: vec![vec![1.0]],
            n_rows: vec![vec![1.0]],
            lambda: 0.1,
            fitted_pairs: 5,
        };
        let mut p = FaceProfile {
            name: "p".into(),
            scans: vec![scan_in_space("legacy", 4, None)],
            ir_calib: Some(c.clone()),
            ir_calibs: Default::default(),
        };
        // Old calibration may have fitted this unknown IR, even though newly
        // tagged templates are the only templates that matching will admit.
        assert!(p.calib_for(LEGACY_RECOGNIZER_SPACE).is_none());
        p.set_calib_for(LEGACY_RECOGNIZER_SPACE, Some(c.clone()));
        assert!(p.calib_for(LEGACY_RECOGNIZER_SPACE).is_none());
        p.set_calib_for("embed:other", Some(c));
        assert!(p.calib_for("embed:other").is_some());
        let before = serde_json::to_value(&p).unwrap();
        assert!(p.calib_for(LEGACY_RECOGNIZER_SPACE).is_none());
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            before,
            "read preserves stored data"
        );
        p.scans[0].embed_space = Some("embed:other".into());
        assert!(p.calib_for(LEGACY_RECOGNIZER_SPACE).is_some());
        assert!(p.calib_for("embed:other").is_none());
        p.scans[0].ir = None;
        assert!(
            p.calib_for("embed:other").is_some(),
            "RGB-only is not unknown IR"
        );
    }

    fn scan(name: &str, v: f32, space: Option<&str>) -> FaceScan {
        FaceScan {
            name: name.into(),
            rgb: vec![v; 4],
            ir: None,
            ir_space: None,
            embed_space: space.map(str::to_string),
            embed_producer: None,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
            captured_at: None,
        }
    }

    #[test]
    fn rgb_templates_from_another_recognizer_are_not_offered_for_matching() {
        // Cosine is only meaningful inside one embedding space, so a template
        // tagged with a different recognizer must not reach the comparison at
        // all, and an untagged scan is comparable only with the one recognizer
        // that can have produced it (#276).
        let enr = Enrollment {
            user: "u".into(),
            profiles: vec![FaceProfile {
                name: "p".into(),
                scans: vec![
                    scan("same", 1.0, Some("embed:aaaaaaaaaaaa")),
                    scan("other", 2.0, Some("embed:bbbbbbbbbbbb")),
                    scan("legacy", 3.0, None),
                ],
                ir_calib: None,
                ir_calibs: Default::default(),
            }],
            ..Default::default()
        };
        let names = |v: Vec<(&str, &str, &[f32])>| {
            v.into_iter()
                .map(|(_, n, _)| n.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(enr.rgb_scans_in("embed:aaaaaaaaaaaa")),
            vec!["same"],
            "a foreign tag and an untagged scan must both be excluded \
             under a non-legacy recognizer"
        );
        assert_eq!(
            names(enr.rgb_scans_in(LEGACY_RECOGNIZER_SPACE)),
            vec!["legacy"],
            "an untagged scan is comparable only with the legacy recognizer"
        );
        // The unfiltered accessor is for diagnostics and keeps everything.
        assert_eq!(names(enr.rgb_scans()), vec!["same", "other", "legacy"]);
        // A recognizer nothing was enrolled under gets NO templates: matching
        // must come up empty rather than score across spaces.
        assert!(enr.rgb_scans_in("embed:cccccccccccc").is_empty());
    }

    #[test]
    fn scans_are_counted_per_recognizer() {
        // #288: the scan limit bounds best-of-N false-accept inflation, and a
        // comparison only ranges over one space, so a profile full of one
        // model's scans must still be able to hold another's.
        let p = FaceProfile {
            name: "p".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: vec![
                scan("a", 1.0, Some("embed:model-a")),
                scan("b", 2.0, Some("embed:model-a")),
                scan("c", 3.0, Some("embed:model-b")),
                scan("legacy", 4.0, None),
            ],
        };
        assert_eq!(p.scans_in("embed:model-a"), 2);
        assert_eq!(p.scans_in("embed:model-b"), 1);
        // Untagged scans belong to the shipped recognizer, the same rule
        // matching applies, so they count there and nowhere else.
        assert_eq!(p.scans_in(LEGACY_RECOGNIZER_SPACE), 1);
        assert_eq!(p.scans_in("embed:model-c"), 0);
        // And the total is not the per-recognizer count.
        assert_eq!(p.scans.len(), 4);
    }

    #[test]
    fn calibrations_are_per_recognizer_and_the_legacy_slot_still_reads() {
        use crate::calib::IrCalibration;
        let calib = |pairs: usize| IrCalibration {
            m: vec![vec![1.0]],
            n_rows: vec![vec![1.0]],
            lambda: 0.1,
            fitted_pairs: pairs,
        };
        let mut p = FaceProfile {
            name: "p".into(),
            scans: Vec::new(),
            ir_calib: None,
            ir_calibs: Default::default(),
        };

        // A profile written before per-model keying carries only the legacy
        // slot; it must still read under the shipped recognizer, and must NOT
        // be handed to another model.
        p.ir_calib = Some(calib(5));
        assert_eq!(
            p.calib_for(LEGACY_RECOGNIZER_SPACE).map(|c| c.fitted_pairs),
            Some(5)
        );
        assert!(p.calib_for("embed:model-b").is_none());

        // Recording model B's calibration must leave the shipped one intact.
        // This is the #288 bug: one slot, overwritten by whichever model was
        // loaded at refit, so switching back applied B's calibration to A's
        // templates.
        p.set_calib_for("embed:model-b", Some(calib(7)));
        assert_eq!(
            p.calib_for("embed:model-b").map(|c| c.fitted_pairs),
            Some(7)
        );
        assert_eq!(
            p.calib_for(LEGACY_RECOGNIZER_SPACE).map(|c| c.fitted_pairs),
            Some(5),
            "another model's refit must not touch the shipped calibration"
        );

        // Recording the shipped recognizer's calibration mirrors into the
        // legacy slot, so an older irlume reading this file still finds it.
        p.set_calib_for(LEGACY_RECOGNIZER_SPACE, Some(calib(9)));
        assert_eq!(p.ir_calib.as_ref().map(|c| c.fitted_pairs), Some(9));
        assert_eq!(
            p.calib_for("embed:model-b").map(|c| c.fitted_pairs),
            Some(7)
        );

        // Clearing is per model, and clears the mirror for the shipped one.
        p.set_calib_for("embed:model-b", None);
        assert!(p.calib_for("embed:model-b").is_none());
        assert_eq!(
            p.calib_for(LEGACY_RECOGNIZER_SPACE).map(|c| c.fitted_pairs),
            Some(9)
        );
        p.set_calib_for(LEGACY_RECOGNIZER_SPACE, None);
        assert!(p.ir_calib.is_none());
        assert!(p.calib_for(LEGACY_RECOGNIZER_SPACE).is_none());
    }

    #[test]
    fn an_enrollment_written_before_keying_still_deserializes() {
        // On-disk compatibility: the keyed map is additive, so a file from an
        // older irlume (legacy slot only, no ir_calibs key) must load and keep
        // its calibration.
        let json = r#"{"user":"u","profiles":[{"name":"p","scans":[],
            "ir_calib":{"m":[[1.0]],"n_rows":[[1.0]],"lambda":0.1,"fitted_pairs":4}}]}"#;
        let enr: Enrollment = serde_json::from_str(json).expect("old file must load");
        let p = &enr.profiles[0];
        assert!(p.ir_calibs.is_empty());
        assert_eq!(
            p.calib_for(LEGACY_RECOGNIZER_SPACE).map(|c| c.fitted_pairs),
            Some(4)
        );
    }

    #[test]
    fn recognizer_space_matching_pins_the_legacy_concession() {
        // Tagged scans compare by equality.
        assert!(recognizer_space_matches(Some("embed:aa"), "embed:aa"));
        assert!(!recognizer_space_matches(Some("embed:aa"), "embed:bb"));
        // Untagged scans belong to the one recognizer that predates tagging,
        // and to nothing else: `None` under an arbitrary model would hand every
        // pre-tagging enrollment to whatever weights are loaded.
        assert!(recognizer_space_matches(None, LEGACY_RECOGNIZER_SPACE));
        assert!(!recognizer_space_matches(None, "embed:aa"));
        // The pinned digest is the full 64-hex sha256 of glintr100.onnx from
        // models/SHA256SUMS; a truncated pin would weaken every comparison
        // above.
        assert_eq!(LEGACY_RECOGNIZER_SPACE.len(), "embed:".len() + 64);
    }
    use super::*;

    /// The retag marker skips work and answers a question about work only.
    ///
    /// It exists because ASKING whether a user needs a retag costs a TPM unseal,
    /// and doing that per user at startup collided with the login it delayed
    /// (#249). Its whole contract: it matches only the space it recorded, an
    /// absent or unreadable marker means "sweep", and a different embedding
    /// space means "sweep again". Nothing security-relevant may ever read it,
    /// which is why it lives beside the enrollments rather than inside one.
    #[test]
    fn the_retag_marker_only_matches_the_space_it_recorded() {
        // Held across the whole test, not just the set_var: every assertion
        // below reads a path derived from IRLUME_STATE_DIR, and another test
        // repointing it mid-run makes those reads describe a different
        // directory than the one just written.
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-retag-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);

        // Nothing recorded yet: the sweep must run.
        assert!(
            !retag_done_for("raw"),
            "an absent marker must not skip the sweep"
        );

        mark_retag_done("raw");
        assert!(
            retag_done_for("raw"),
            "the recorded space must be recognised"
        );

        // An adapter change moves the space, so the sweep is owed again.
        assert!(
            !retag_done_for("adapter:deadbeef"),
            "a different embedding space must run the sweep again"
        );

        // Garbage on disk is not a match, so it fails towards doing the work.
        fs::write(dir.join(".ir-retag-space"), b"\x00not a space").unwrap();
        assert!(
            !retag_done_for("raw"),
            "an unreadable or unexpected marker must fall back to sweeping"
        );

        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_format_migrates_to_one_profile() {
        let old = LegacyProfile {
            user: "u".into(),
            templates: vec![vec![0.1; 4], vec![0.2; 4]],
            ir_templates: vec![vec![0.3; 4]],
            ir_depth_samples: vec![1.4],
            ir_brightness_samples: vec![90.0],
        };
        let e = migrate(old);
        assert_eq!(e.profiles.len(), 1);
        assert_eq!(e.profiles[0].name, "Face Profile 1");
        assert_eq!(e.profiles[0].scans.len(), 2);
        assert_eq!(e.profiles[0].scans[0].name, "Face Scan 1");
        assert_eq!(e.profiles[0].scans[0].ir.as_ref().unwrap().len(), 4);
        assert!(e.profiles[0].scans[1].ir.is_none()); // only one ir template
        assert_eq!(e.total_scans(), 2);
        assert!(!e.require_eyes_open);
    }

    fn sample() -> Enrollment {
        Enrollment {
            user: "u".into(),
            uid: None,
            loaded_for: None,
            profiles: vec![FaceProfile {
                ir_calib: None,
                ir_calibs: Default::default(),
                name: "Face Profile 1".into(),
                scans: vec![FaceScan {
                    name: "Face Scan 1".into(),
                    rgb: vec![0.1, 0.2, 0.3, 0.4],
                    ir: Some(vec![0.5, 0.6]),
                    ir_space: None,
                    embed_space: None,
                    embed_producer: None,
                    ir_center_edge_ratio: 1.4,
                    ir_brightness: 90.0,
                    pitch: 0.52,
                    captured_at: None,
                }],
            }],
            require_eyes_open: true,
            camera_binding: None,
            closure_calibration: None,
        }
    }

    /// `sample()` as `user`'s plaintext enrollment recording `uid`.
    fn plant_plaintext(dir: &Path, user: &str, uid: Option<u32>) -> Vec<u8> {
        let mut enrollment = sample();
        enrollment.user = user.into();
        enrollment.uid = uid;
        let bytes = serialize_enrollment(&enrollment, None).unwrap();
        fs::create_dir_all(dir).unwrap();
        fs::write(profile_path(user), &bytes).unwrap();
        bytes
    }

    /// A fresh state dir for one uid test, under `IRLUME_STATE_DIR`.
    fn uid_sandbox(name: &str) -> PathBuf {
        let dir = PathBuf::from(crate::test_tmp_dir(name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        dir
    }

    fn leave_uid_sandbox(dir: &Path) {
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(dir);
    }

    /// Plant a synthetic added-camera store for `user` and the commit journal
    /// beside it; returns both paths.
    fn plant_camera_store(user: &str) -> (PathBuf, PathBuf) {
        let store = crate::multi_camera::secondary_store_path(user);
        let journal = crate::multi_camera::commit::intent_path_for(&store);
        fs::create_dir_all(store.parent().unwrap()).unwrap();
        fs::write(&store, b"synthetic camera store").unwrap();
        fs::write(&journal, b"synthetic commit journal").unwrap();
        (store, journal)
    }

    struct PublicationSandbox {
        dir: PathBuf,
        previous: Option<std::ffi::OsString>,
    }
    impl PublicationSandbox {
        fn new(tag: &str) -> Self {
            let previous = std::env::var_os("IRLUME_STATE_DIR");
            Self {
                dir: uid_sandbox(tag),
                previous,
            }
        }
    }
    impl Drop for PublicationSandbox {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("IRLUME_STATE_DIR", value),
                None => std::env::remove_var("IRLUME_STATE_DIR"),
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn late_publisher_refuses_loss_during_key_preparation_without_replacing_primary() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let sandbox = PublicationSandbox::new("late-key-loss");
        let user = "late-key-loss";
        let _account = crate::account::remember(user, 6811);
        let before = plant_plaintext(&sandbox.dir, user, Some(6811));
        let current = std::cell::Cell::new(true);
        let calls = std::cell::Cell::new(0);
        let mut replacement = sample();
        replacement.user = user.into();
        replacement.uid = Some(6811);
        replacement.profiles[0].name = "New profile".into();
        let error = save_with_key_and_publisher(
            &replacement,
            |_, _| {
                current.set(false); // The retained admission is lost during blocking preparation.
                Ok(None)
            },
            |_, _| {
                calls.set(calls.get() + 1);
                assert!(!current.get(), "the publisher ran before key preparation");
                Err(irlume_common::Error::Policy(
                    "camera continuity lost".into(),
                ))
            },
        )
        .unwrap_err();
        assert!(
            matches!(error, irlume_common::Error::Policy(ref message) if message == "camera continuity lost")
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(fs::read(profile_path(user)).unwrap(), before);
        assert!(!crate::replacement::record_path(user).exists());
    }

    #[test]
    fn late_publisher_refusal_restores_another_accounts_key_before_returning() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let _sandbox = PublicationSandbox::new("late-key-rollback");
        let user = "late-key-rollback";
        let key_before = plant_replaced(user, &[41u8; 32], 6821);
        let primary_before = fs::read(profile_path(user)).unwrap();
        let recovery = template_key::recovery_path(user);
        let store = crate::multi_camera::secondary_store_path(user);
        let intent = crate::multi_camera::commit::intent_path_for(&store);
        let recovery_before = fs::read(&recovery).unwrap();
        let store_before = fs::read(&store).unwrap();
        let intent_before = fs::read(&intent).unwrap();
        let _account = crate::account::remember(user, 6822);
        let mut replacement = sample();
        replacement.user = user.into();
        replacement.uid = Some(6822);
        let error = save_with_key_and_publisher(
            &replacement,
            |user, account| {
                template_key::ensure_key_with(
                    user,
                    account,
                    Some(&key_is_another_accounts),
                    fake_load,
                    no_move,
                    fake_seal,
                )
                .map(Some)
            },
            |_, _| {
                assert!(
                    fs::read(template_key::key_path(user)).unwrap() != key_before,
                    "key preparation did not replace the other account's key"
                );
                assert!(crate::replacement::record_path(user).exists());
                Err(irlume_common::Error::Policy("late camera refusal".into()))
            },
        )
        .unwrap_err();
        assert!(
            matches!(error, irlume_common::Error::Policy(ref message) if message == "late camera refusal")
        );
        assert!(
            fs::read(template_key::key_path(user)).unwrap() == key_before,
            "the refused publication did not restore the original key"
        );
        assert!(
            fs::read(profile_path(user)).unwrap() == primary_before,
            "primary changed on refusal"
        );
        assert!(
            fs::read(recovery).unwrap() == recovery_before,
            "recovery changed on refusal"
        );
        assert!(
            fs::read(store).unwrap() == store_before,
            "secondary changed on refusal"
        );
        assert!(
            fs::read(intent).unwrap() == intent_before,
            "intent changed on refusal"
        );
        assert!(
            !crate::replacement::record_path(user).exists(),
            "rollback must precede the refusal return"
        );
    }

    #[test]
    fn late_publisher_visible_receipt_keeps_replacement_pending_instead_of_rollback() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let _sandbox = PublicationSandbox::new("late-visible-receipt");
        let user = "late-visible-receipt";
        let key_before = plant_replaced(user, &[42u8; 32], 6831);
        let primary_before = fs::read(profile_path(user)).unwrap();
        let _account = crate::account::remember(user, 6832);
        let mut replacement = sample();
        replacement.user = user.into();
        replacement.uid = Some(6832);
        let error = save_with_key_and_publisher(
            &replacement,
            |user, account| {
                template_key::ensure_key_with(
                    user,
                    account,
                    Some(&key_is_another_accounts),
                    fake_load,
                    no_move,
                    fake_seal,
                )
                .map(Some)
            },
            |path, bytes| {
                assert!(matches!(
                    persist_enrollment(path, bytes)
                        .map_err(|error| irlume_common::Error::Io(error.to_string()))?,
                    irlume_common::AtomicWrite::Durable
                ));
                Ok(irlume_common::AtomicWrite::VisibleNotDurable(
                    std::io::Error::other("injected directory sync failure"),
                ))
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("published") && error.contains("durability"),
            "{error}"
        );
        assert!(
            fs::read(profile_path(user)).unwrap() != primary_before,
            "the receipt describes no visible primary change"
        );
        assert!(
            fs::read(template_key::key_path(user)).unwrap() != key_before,
            "the visible publication rolled back its key"
        );
        assert!(crate::replacement::record_path(user).exists());
        assert!(template_key::recovery_path(user).exists());
        assert!(crate::multi_camera::secondary_store_path(user).exists());
        drop(template_key::UserStateLock::acquire(user).unwrap());
        assert!(!crate::replacement::record_path(user).exists());
        assert!(!template_key::recovery_path(user).exists());
        assert!(!crate::multi_camera::secondary_store_path(user).exists());
        assert!(
            fs::read(template_key::key_path(user)).unwrap() != key_before,
            "settlement rolled back the published key"
        );
    }

    /// An enrollment records the uid it was written for. Every loader reads
    /// one recorded for another uid as absent (not enrolled), and the file
    /// stays on disk; the same file loads for the uid it records.
    #[test]
    fn an_enrollment_recorded_for_another_uid_reads_as_not_enrolled() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-other-enrollment");
        let user = "uid-other-owner";
        let bytes = plant_plaintext(&dir, user, Some(4601));
        {
            let _now = crate::account::remember(user, 4602);
            assert!(load(user).unwrap().is_none());
            assert!(load_read_only(user).unwrap().is_none());
            assert!(load_with_key(user).unwrap().is_none());
            assert!(load_snapshot(user).unwrap().is_none());
            assert!(load_snapshot_read_only(user).unwrap().is_none());
            assert!(load_path_unlocked(user, &profile_path(user))
                .unwrap()
                .is_none());
            assert_eq!(fs::read(profile_path(user)).unwrap(), bytes, "kept");
            assert_eq!(store_is_encrypted(user).unwrap(), Some(false));
        }
        {
            // No account has the name any more: not enrolled either.
            let _gone =
                crate::account::remember_resolution(user, crate::account::Resolution::NoAccount);
            assert!(load(user).unwrap().is_none());
        }
        let _then = crate::account::remember(user, 4601);
        assert_eq!(load(user).unwrap().unwrap().uid, Some(4601));
        leave_uid_sandbox(&dir);
    }

    /// An enrollment written before the uid was recorded loads for any uid,
    /// and its next write records the account's uid. A write for a name no
    /// account has records none (writes never fail on the lookup).
    #[test]
    fn an_enrollment_without_a_uid_loads_and_its_next_write_records_the_uid() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-legacy-enrollment");
        let user = "uid-legacy-owner";
        plant_plaintext(&dir, user, None);
        let _now = crate::account::remember(user, 4701);
        let loaded = load(user).unwrap().expect("a legacy enrollment loads");
        assert_eq!(loaded.uid, None);
        assert_eq!(
            loaded.loaded_for,
            Some(4701),
            "loaded for the uid the name resolved to"
        );
        // A plaintext write, as on a host without a TPM.
        save_with_key(&loaded, |_, _| Ok(None)).unwrap();
        let on_disk: serde_json::Value =
            serde_json::from_slice(&fs::read(profile_path(user)).unwrap()).unwrap();
        assert_eq!(on_disk["uid"], 4701);
        assert_eq!(load(user).unwrap().unwrap().uid, Some(4701));

        let missing = "irlume-test-no-such-account";
        save_with_key(&Enrollment::new(missing), |_, _| Ok(None)).unwrap();
        let on_disk: serde_json::Value =
            serde_json::from_slice(&fs::read(profile_path(missing)).unwrap()).unwrap();
        assert!(on_disk.get("uid").is_none(), "{on_disk}");
        leave_uid_sandbox(&dir);
    }

    /// When the account's uid cannot be resolved, an enrollment that records
    /// a uid is an error (the password fallback), never a grant or "not
    /// enrolled"; one without a uid needs no lookup.
    #[test]
    fn an_enrollment_with_a_uid_is_an_error_when_the_account_cannot_be_resolved() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-unknown-enrollment");
        let user = "uid-unknown-owner";
        let _unknown =
            crate::account::remember_resolution(user, crate::account::Resolution::Unknown);
        plant_plaintext(&dir, user, Some(4801));
        let error = load(user).unwrap_err().to_string();
        assert!(error.contains("could not be resolved"), "{error}");
        assert!(load_with_key(user).is_err());
        plant_plaintext(&dir, user, None);
        assert!(load(user).unwrap().is_some());
        leave_uid_sandbox(&dir);
    }

    /// When the account's uid cannot be resolved, an enrollment write keeps
    /// the uid the enrollment carries, and one without a uid is refused
    /// before anything is written: it would otherwise be a record that any
    /// later account of the same name accepts.
    #[test]
    fn an_enrollment_without_a_uid_is_not_written_when_the_account_cannot_be_resolved() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-unknown-write");
        let user = "uid-unknown-writer";
        let _unknown =
            crate::account::remember_resolution(user, crate::account::Resolution::Unknown);
        let mut enrollment = Enrollment::new(user);
        enrollment.profiles = sample().profiles;
        let error = save_with_key(&enrollment, |_, _| {
            panic!("no key is resolved for a write that is refused")
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("could not be resolved") && error.contains("face enrollment"),
            "{error}"
        );
        assert!(!profile_path(user).exists(), "nothing was written");

        enrollment.uid = Some(4811);
        save_with_key(&enrollment, |_, _| Ok(None)).unwrap();
        let on_disk: serde_json::Value =
            serde_json::from_slice(&fs::read(profile_path(user)).unwrap()).unwrap();
        assert_eq!(on_disk["uid"], 4811);
        leave_uid_sandbox(&dir);
    }

    /// A seal for [`template_key::ensure_key_with`] in the replacement tests.
    type FakeSeal = dyn Fn(&str, &[u8], Option<u32>) -> irlume_common::Result<()>;

    /// The fake TPM of the replacement tests: the "sealed blob" is the key.
    fn fake_seal(user: &str, key: &[u8], uid: Option<u32>) -> irlume_common::Result<()> {
        let mut env: crate::envelope::SealedEnvelope =
            serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#).unwrap();
        env.private = key.to_vec();
        env.uid = uid;
        env.save(&template_key::key_path(user))
    }

    fn fake_load(
        user: &str,
        account: &mut Account<'_>,
    ) -> irlume_common::Result<Zeroizing<Vec<u8>>> {
        template_key::load_key_with(
            user,
            account,
            template_key::KeyLoadPolicy::Keep,
            |env| Ok(Zeroizing::new(env.private.clone())),
            |_| false,
            |_| panic!("a replacement does not move a key to another policy"),
        )
    }

    /// The move of a kept key to a stronger policy in the tests where none
    /// is available.
    fn no_move(_: &str, _: &[u8]) {}

    /// The move of a kept key to a stronger policy
    /// ([`template_key::move_kept_key`]) in the replacement tests.
    type FakeMove = dyn Fn(&str, &[u8]);

    /// The move of a kept key when the fake TPM always has a stronger
    /// policy: it seals the key under pcrlock, as the ladder would.
    fn fake_move(user: &str, key: &[u8]) {
        template_key::move_kept_key_with(
            user,
            key,
            |_| true,
            |key| {
                let mut env: crate::envelope::SealedEnvelope =
                    serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#)
                        .unwrap();
                env.policy = crate::envelope::PolicyKind::PcrlockNv {
                    nv_index: crate::tpm::tests::PredictionFixture::NV,
                };
                env.private = key.to_vec();
                Ok(env)
            },
        );
    }

    /// Save `e` with the key choice of `save_replacement` (`replacing`) or of
    /// `save`, sealing a new key with `reseal`.
    fn save_choosing_key(
        e: &Enrollment,
        replacing: bool,
        reseal: &FakeSeal,
    ) -> irlume_common::Result<()> {
        save_moving_kept_key(e, replacing, reseal, &no_move)
    }

    /// [`save_choosing_key`], moving a key the write keeps with `move_kept`.
    fn save_moving_kept_key(
        e: &Enrollment,
        replacing: bool,
        reseal: &FakeSeal,
        move_kept: &FakeMove,
    ) -> irlume_common::Result<()> {
        let enrollment_key = |user: &str, account: &mut Account<'_>| {
            template_key::ensure_key_with(
                user,
                account,
                Some(&key_is_another_accounts),
                fake_load,
                move_kept,
                reseal,
            )
            .map(Some)
        };
        save_with_key(e, |user, account| {
            if replacing {
                replacement_key(user, account, fake_load, move_kept, enrollment_key)
            } else {
                enrollment_key(user, account)
            }
        })
    }

    /// The files of a replacement of `user`'s enrollment, sealed for uid
    /// `old_uid` under `old_key`, with a recovery envelope and an
    /// added-camera store beside it. Returns the key file's bytes.
    fn plant_replaced(user: &str, old_key: &[u8], old_uid: u32) -> Vec<u8> {
        let mut old = sample();
        old.user = user.into();
        old.uid = Some(old_uid);
        fs::write(
            profile_path(user),
            serialize_enrollment(&old, Some(old_key)).unwrap(),
        )
        .unwrap();
        fake_seal(user, old_key, Some(old_uid)).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        fs::write(&recovery, b"synthetic recovery of the replaced key").unwrap();
        plant_camera_store(user);
        fs::read(template_key::key_path(user)).unwrap()
    }

    /// Seal a new key over `user`'s, as an enrollment write that replaces
    /// another uid's does, under the state lock, and stop there: the key is
    /// never settled.
    fn replace_key_and_stop(user: &str) -> Zeroizing<Vec<u8>> {
        let _state = template_key::UserStateLock::acquire(user).unwrap();
        let key = template_key::ensure_key_with(
            user,
            &mut Account::new(user),
            Some(&key_is_another_accounts),
            fake_load,
            no_move,
            fake_seal,
        )
        .unwrap();
        assert!(key.replaces_another());
        Zeroizing::new(key.as_slice().to_vec())
    }

    /// An enrollment write that replaces another uid's records the
    /// replacement durably before it seals the new key. When it stops
    /// before the new enrollment is published, the next acquisition of the
    /// state lock puts the replaced key back and leaves the replaced
    /// enrollment, its recovery envelope and its added-camera store as they
    /// were.
    #[test]
    fn a_replacement_that_stops_before_its_enrollment_is_published_is_undone() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("replace-stop-early");
        let user = "replace-stop-early";
        let key_before = plant_replaced(user, &[31u8; 32], 6201);
        let enrollment_before = fs::read(profile_path(user)).unwrap();
        let record = crate::replacement::record_path(user);
        let _now = crate::account::remember(user, 6202);

        replace_key_and_stop(user);
        assert!(record.exists(), "recorded before the new key");
        assert_ne!(fs::read(template_key::key_path(user)).unwrap(), key_before);

        drop(template_key::UserStateLock::acquire(user).unwrap());
        assert_eq!(
            fs::read(template_key::key_path(user)).unwrap(),
            key_before,
            "the replaced key is back"
        );
        assert_eq!(fs::read(profile_path(user)).unwrap(), enrollment_before);
        assert!(template_key::recovery_path(user).exists());
        assert!(crate::multi_camera::secondary_store_path(user).exists());
        assert!(!record.exists(), "settled");
        leave_uid_sandbox(&dir);
    }

    /// When the write stops after the new enrollment is published, or its
    /// enrollment may not survive a power loss, the record stays, and the
    /// next acquisition of the state lock finishes the replacement: the
    /// replaced key's recovery envelope and the replaced enrollment's
    /// added-camera store go, and the new key stays. A file written since
    /// the replacement began is not the replaced one and stays.
    #[test]
    fn a_replacement_that_stops_after_its_enrollment_is_published_is_finished() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("replace-stop-late");
        let user = "replace-stop-late";
        let record = crate::replacement::record_path(user);
        let recovery = template_key::recovery_path(user);
        let store = crate::multi_camera::secondary_store_path(user);
        let journal = crate::multi_camera::commit::intent_path_for(&store);
        let _now = crate::account::remember(user, 6302);
        let mut new = Enrollment::new(user);
        new.profiles = sample().profiles;
        new.uid = Some(6302);
        let publish = |key: &[u8]| {
            fs::write(
                profile_path(user),
                serialize_enrollment(&new, Some(key)).unwrap(),
            )
            .unwrap();
        };

        for rewritten_store in [false, true] {
            plant_replaced(user, &[32u8; 32], 6301);
            let key = replace_key_and_stop(user);
            publish(&key);
            if rewritten_store {
                fs::write(&store, b"a store written since").unwrap();
            }
            assert!(record.exists());
            drop(template_key::UserStateLock::acquire(user).unwrap());
            assert!(!record.exists(), "settled");
            assert!(
                !recovery.exists(),
                "the replaced key's recovery envelope goes"
            );
            assert_eq!(
                store.exists(),
                rewritten_store,
                "only the replaced store goes"
            );
            assert!(!journal.exists(), "the replaced store's journal goes");
            let sealed =
                crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
            assert_eq!(sealed.private, *key, "the new key stays");
            let _ = fs::remove_file(&store);
            let _ = fs::remove_file(&journal);
        }

        // Published but maybe not durable: the write keeps the record.
        plant_replaced(user, &[33u8; 32], 6301);
        let written = {
            let _state = template_key::UserStateLock::acquire(user).unwrap();
            let key = template_key::ensure_key_with(
                user,
                &mut Account::new(user),
                Some(&key_is_another_accounts),
                fake_load,
                no_move,
                fake_seal,
            )
            .unwrap();
            publish(key.as_slice());
            let written = Zeroizing::new(key.as_slice().to_vec());
            key.settle(Some(&irlume_common::AtomicWrite::VisibleNotDurable(
                std::io::Error::other("synthetic sync failure"),
            )))
            .unwrap();
            written
        };
        assert!(record.exists(), "kept while it may not last");
        assert!(recovery.exists() && store.exists());
        drop(template_key::UserStateLock::acquire(user).unwrap());
        assert!(!record.exists() && !recovery.exists() && !store.exists());
        let sealed = crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
        assert_eq!(sealed.private, *written);
        leave_uid_sandbox(&dir);
    }

    /// A replacement whose added-camera store cannot be removed keeps its
    /// record: the next writer of the account is refused while the removal
    /// fails, a load goes on, and the next acquisition of the state lock
    /// once the removal can succeed removes the store. On a host without a
    /// TPM, where no key is replaced, a plaintext enrollment's replacement
    /// is recorded the same way and leaves the recovery envelope alone.
    #[test]
    fn a_camera_store_a_replacement_could_not_remove_goes_on_the_next_change() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("replace-store-pending");
        let user = "replace-store-pending";
        let record = crate::replacement::record_path(user);
        let recovery = template_key::recovery_path(user);
        let store = crate::multi_camera::secondary_store_path(user);
        let journal = crate::multi_camera::commit::intent_path_for(&store);
        let _now = crate::account::remember(user, 6402);
        let mut new = Enrollment::new(user);
        new.profiles = sample().profiles;
        new.uid = Some(6402);
        // A directory where the store's commit journal was: the removal
        // fails there, as it would in a damaged or read-only directory.
        let block_removal = || {
            fs::remove_file(&journal).unwrap();
            fs::create_dir_all(journal.join("blocked")).unwrap();
        };
        let pending = || {
            assert!(
                template_key::UserStateLock::acquire(user).is_err(),
                "a writer is refused while the removal fails"
            );
            drop(template_key::UserStateLock::acquire_for_load(user).unwrap());
            assert!(record.exists(), "the removal stays pending");
            assert!(store.exists());
        };

        plant_replaced(user, &[34u8; 32], 6401);
        let key = replace_key_and_stop(user);
        fs::write(
            profile_path(user),
            serialize_enrollment(&new, Some(&key)).unwrap(),
        )
        .unwrap();
        block_removal();
        pending();
        fs::remove_dir_all(&journal).unwrap();
        drop(template_key::UserStateLock::acquire(user).unwrap());
        assert!(!store.exists(), "removed on the next change");
        assert!(!record.exists() && !recovery.exists());

        // No TPM and no key: a plaintext enrollment of another uid.
        let _ = fs::remove_file(template_key::key_path(user));
        let mut old = sample();
        old.user = user.into();
        old.uid = Some(6401);
        fs::write(
            profile_path(user),
            serialize_enrollment(&old, None).unwrap(),
        )
        .unwrap();
        fs::write(&recovery, b"a recovery envelope of this account's own").unwrap();
        plant_camera_store(user);
        {
            let _state = template_key::UserStateLock::acquire(user).unwrap();
            crate::replacement::begin(user, None).unwrap();
        }
        fs::write(
            profile_path(user),
            serialize_enrollment(&new, None).unwrap(),
        )
        .unwrap();
        block_removal();
        pending();
        fs::remove_dir_all(&journal).unwrap();
        drop(template_key::UserStateLock::acquire(user).unwrap());
        assert!(!store.exists() && !record.exists());
        assert!(recovery.exists(), "no key was replaced");
        leave_uid_sandbox(&dir);
    }

    /// A write whose enrollment published nothing puts the replaced key
    /// back and drops the record. A put-back that fails keeps the record,
    /// and the next acquisition of the state lock puts the key back.
    #[test]
    fn a_replaced_key_goes_back_when_nothing_was_published_even_after_a_failed_put_back() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("replace-put-back");
        let user = "replace-put-back";
        let record = crate::replacement::record_path(user);
        let key_path = template_key::key_path(user);
        let _now = crate::account::remember(user, 6602);

        let before = plant_replaced(user, &[36u8; 32], 6601);
        {
            let _state = template_key::UserStateLock::acquire(user).unwrap();
            let key = template_key::ensure_key_with(
                user,
                &mut Account::new(user),
                Some(&key_is_another_accounts),
                fake_load,
                no_move,
                fake_seal,
            )
            .unwrap();
            assert!(record.exists());
            key.settle(None).unwrap();
        }
        assert_eq!(fs::read(&key_path).unwrap(), before, "put back");
        assert!(!record.exists());

        replace_key_and_stop(user);
        // A directory where the key goes: the put-back fails there.
        fs::remove_file(&key_path).unwrap();
        fs::create_dir(&key_path).unwrap();
        assert!(template_key::UserStateLock::acquire(user).is_err());
        assert!(record.exists(), "kept while the put-back fails");
        fs::remove_dir(&key_path).unwrap();
        drop(template_key::UserStateLock::acquire(user).unwrap());
        assert_eq!(
            fs::read(&key_path).unwrap(),
            before,
            "put back on the next change"
        );
        assert!(!record.exists());
        leave_uid_sandbox(&dir);
    }

    /// Finishing a replacement removes the replaced key's recovery envelope
    /// only while it is the one recorded: an envelope written since stays.
    #[test]
    fn a_recovery_envelope_written_since_the_replacement_began_stays() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("replace-recovery-since");
        let user = "replace-recovery-since";
        let recovery = template_key::recovery_path(user);
        let _now = crate::account::remember(user, 6702);
        let mut new = Enrollment::new(user);
        new.profiles = sample().profiles;
        new.uid = Some(6702);

        plant_replaced(user, &[37u8; 32], 6701);
        let key = replace_key_and_stop(user);
        fs::write(
            profile_path(user),
            serialize_enrollment(&new, Some(&key)).unwrap(),
        )
        .unwrap();
        fs::write(&recovery, b"an envelope written since").unwrap();
        drop(template_key::UserStateLock::acquire(user).unwrap());
        assert_eq!(fs::read(&recovery).unwrap(), b"an envelope written since");
        assert!(!crate::multi_camera::secondary_store_path(user).exists());
        assert!(!crate::replacement::record_path(user).exists());
        leave_uid_sandbox(&dir);
    }

    /// A record that cannot be read refuses every writer of the account,
    /// naming the record, and changes nothing.
    #[test]
    fn an_unreadable_replacement_record_refuses_the_account_s_writers() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("replace-record-unreadable");
        let user = "replace-record-unreadable";
        let key_before = plant_replaced(user, &[35u8; 32], 6501);
        let record = crate::replacement::record_path(user);
        fs::write(&record, b"not a record").unwrap();
        let error = template_key::UserStateLock::acquire(user)
            .err()
            .expect("refused")
            .to_string();
        assert!(
            error.contains(&record.display().to_string()) && error.contains("move the record away"),
            "{error}"
        );
        assert_eq!(fs::read(template_key::key_path(user)).unwrap(), key_before);
        assert!(record.exists());
        assert!(crate::multi_camera::secondary_store_path(user).exists());
        leave_uid_sandbox(&dir);
    }

    /// Replacing a template key sealed for another uid is final only once
    /// the new enrollment is published under the new key. A failed seal, or
    /// an enrollment write that publishes nothing, leaves that account's key,
    /// enrollment and recovery envelope as they were; a published one
    /// removes the recovery envelope, which can only restore the replaced
    /// key.
    #[test]
    fn a_failed_replacement_leaves_the_replaced_key_and_its_recovery_in_place() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-replace-settle");
        let user = "uid-replace-owner";
        let old_key = [7u8; 32];
        let mut old = sample();
        old.user = user.into();
        old.uid = Some(6101);
        let enrollment_before = serialize_enrollment(&old, Some(&old_key)).unwrap();
        fs::write(profile_path(user), &enrollment_before).unwrap();
        fake_seal(user, &old_key, Some(6101)).unwrap();
        let key_before = fs::read(template_key::key_path(user)).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        fs::write(&recovery, b"synthetic recovery of the replaced key").unwrap();
        let _now = crate::account::remember(user, 6102);
        let mut replacement = Enrollment::new(user);
        replacement.profiles = sample().profiles;
        let replace = |reseal: &FakeSeal| {
            save_with_key(&replacement, |user, account| {
                template_key::ensure_key_with(
                    user,
                    account,
                    Some(&key_is_another_accounts),
                    fake_load,
                    no_move,
                    reseal,
                )
                .map(Some)
            })
        };
        let unchanged = |what: &str| {
            assert_eq!(
                fs::read(template_key::key_path(user)).unwrap(),
                key_before,
                "{what}: the replaced key"
            );
            assert!(recovery.exists(), "{what}: its recovery envelope");
            assert!(
                !crate::replacement::record_path(user).exists(),
                "{what}: the replacement is undone"
            );
        };

        let error =
            replace(&|_, _, _| Err(irlume_common::Error::Policy("injected seal failure".into())))
                .unwrap_err()
                .to_string();
        assert!(error.contains("injected seal failure"), "{error}");
        unchanged("a failed seal");
        assert_eq!(fs::read(profile_path(user)).unwrap(), enrollment_before);

        // The new key is sealed, but the enrollment write publishes nothing:
        // a directory stands where the enrollment goes.
        fs::remove_file(profile_path(user)).unwrap();
        fs::create_dir(profile_path(user)).unwrap();
        assert!(replace(&fake_seal).is_err());
        unchanged("an unpublished enrollment");
        fs::remove_dir(profile_path(user)).unwrap();
        fs::write(profile_path(user), &enrollment_before).unwrap();

        replace(&fake_seal).unwrap();
        let key = crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
        assert_eq!(key.uid, Some(6102), "the account has a key of its own");
        assert_ne!(key.private, old_key);
        assert!(
            !recovery.exists(),
            "the replaced key's recovery envelope goes"
        );
        let saved =
            deserialize_enrollment(&fs::read(profile_path(user)).unwrap(), Some(&key.private))
                .unwrap();
        assert_eq!(saved.uid, Some(6102));
        assert!(
            !crate::replacement::record_path(user).exists(),
            "the replacement is finished"
        );
        leave_uid_sandbox(&dir);
    }

    /// A template key an earlier release sealed without a uid records none,
    /// but the enrollment under it records the uid its last write recorded.
    /// Once the name resolves to another uid, neither a replacement
    /// enrollment nor a first save for that account reuses the key: the
    /// account gets a key of its own, and the old key's recovery envelope
    /// goes once the new enrollment is published. A failed seal leaves the
    /// key, the enrollment and the recovery envelope as they were. Under the
    /// same key, an enrollment recorded for the current uid, or for none,
    /// keeps the key and its recovery envelope. The added-camera store beside
    /// the enrollment, and its commit journal, are removed when the recovery
    /// envelope is, and kept when it is kept.
    #[test]
    fn a_key_without_a_uid_is_replaced_when_its_enrollment_records_another_uid() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-unbound-key");
        let user = "uid-unbound-key";
        let old_key = [5u8; 32];
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        // A recovery envelope of the key that records no uid, as an earlier
        // release wrote it.
        let wrapped =
            serde_json::to_vec(&crate::recovery::wrap(b"a recovery passphrase", &old_key).unwrap())
                .unwrap();
        // The enrollment under `old_key` records `uid`; the key records none.
        let plant = |uid: Option<u32>| {
            let mut old = sample();
            old.user = user.into();
            old.uid = uid;
            let enrollment = serialize_enrollment(&old, Some(&old_key)).unwrap();
            fs::write(profile_path(user), &enrollment).unwrap();
            fake_seal(user, &old_key, None).unwrap();
            fs::write(&recovery, &wrapped).unwrap();
            plant_camera_store(user);
            (enrollment, fs::read(template_key::key_path(user)).unwrap())
        };
        let (store, journal) = plant_camera_store(user);
        let _now = crate::account::remember(user, 6602);
        let mut replacement = Enrollment::new(user);
        replacement.profiles = sample().profiles;
        let write_with =
            |replacing: bool, reseal: &FakeSeal| save_choosing_key(&replacement, replacing, reseal);
        let failing_seal: &FakeSeal =
            &|_, _, _| Err(irlume_common::Error::Policy("injected seal failure".into()));
        let no_seal: &FakeSeal = &|_, _, _| panic!("a key this account may use is kept");

        for (what, replacing) in [("a replacement", true), ("a first save", false)] {
            let write = |reseal: &FakeSeal| write_with(replacing, reseal);
            let (enrollment_before, key_before) = plant(Some(6601));
            let error = write(failing_seal).unwrap_err().to_string();
            assert!(error.contains("injected seal failure"), "{what}: {error}");
            assert_eq!(
                fs::read(template_key::key_path(user)).unwrap(),
                key_before,
                "{what}: a failed seal keeps the key"
            );
            assert_eq!(fs::read(profile_path(user)).unwrap(), enrollment_before);
            assert!(recovery.exists(), "{what}: and its recovery envelope");
            assert!(
                store.exists() && journal.exists(),
                "{what}: and the camera store"
            );

            write(&fake_seal).unwrap();
            let key = crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
            assert_eq!(key.uid, Some(6602), "{what}: a key of the account's own");
            assert_ne!(key.private, old_key, "{what}");
            assert!(
                !recovery.exists(),
                "{what}: the old key's recovery envelope goes"
            );
            assert!(
                !store.exists() && !journal.exists(),
                "{what}: so does the camera store and its journal"
            );
            let saved =
                deserialize_enrollment(&fs::read(profile_path(user)).unwrap(), Some(&key.private))
                    .unwrap();
            assert_eq!(saved.uid, Some(6602), "{what}");

            for uid in [Some(6602), None] {
                let (_, key_before) = plant(uid);
                write(no_seal).unwrap();
                assert_eq!(
                    fs::read(template_key::key_path(user)).unwrap(),
                    key_before,
                    "{what}: an enrollment recorded for {uid:?} keeps the key"
                );
                assert!(recovery.exists(), "{what}: {uid:?}");
                assert!(store.exists() && journal.exists(), "{what}: {uid:?}");
                let saved =
                    deserialize_enrollment(&fs::read(profile_path(user)).unwrap(), Some(&old_key))
                        .unwrap();
                assert_eq!(saved.uid, Some(6602), "{what}: {uid:?}");
            }
        }
        leave_uid_sandbox(&dir);
    }

    /// A template key an earlier release sealed without a uid, under an
    /// enrollment that records none (or none stored), belongs to the account
    /// its recovery envelope records: a recovery setup wraps the key for the
    /// uid it records. Once the name resolves to another uid, neither a
    /// replacement enrollment nor a first save for that account reuses the
    /// key: the account gets a key of its own, and the recovery envelope,
    /// which restores the old key, goes once the new enrollment is published,
    /// with the added-camera store beside the replaced enrollment. A failed
    /// seal leaves the key, the enrollment, the recovery envelope and the
    /// store as they were. A recovery envelope recorded for the current uid,
    /// or for none, keeps the key, and so does one recorded for another uid
    /// beside a key recorded for the current uid (the envelope then wraps an
    /// earlier key).
    #[test]
    fn a_key_without_a_uid_is_replaced_when_its_recovery_envelope_records_another_uid() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-unbound-key-recovery");
        let user = "uid-unbound-key-recovery";
        let old_key = [11u8; 32];
        let wrapped = crate::recovery::wrap(b"a recovery passphrase", &old_key).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        // The key records `key_uid` and the recovery envelope wrapping it
        // `recovery_uid`; with `enrolled`, an enrollment that records no uid
        // is stored under the key.
        let plant = |key_uid: Option<u32>, enrolled: bool, recovery_uid: Option<u32>| {
            let _ = fs::remove_file(profile_path(user));
            if enrolled {
                let mut old = sample();
                old.user = user.into();
                old.uid = None;
                let bytes = serialize_enrollment(&old, Some(&old_key)).unwrap();
                fs::write(profile_path(user), bytes).unwrap();
            }
            fake_seal(user, &old_key, key_uid).unwrap();
            let mut envelope = wrapped.clone();
            envelope.uid = recovery_uid;
            fs::write(&recovery, serde_json::to_vec(&envelope).unwrap()).unwrap();
            plant_camera_store(user);
            (
                fs::read(profile_path(user)).ok(),
                fs::read(template_key::key_path(user)).unwrap(),
                fs::read(&recovery).unwrap(),
            )
        };
        let (store, journal) = plant_camera_store(user);
        let _now = crate::account::remember(user, 6902);
        let mut replacement = Enrollment::new(user);
        replacement.profiles = sample().profiles;
        let failing_seal: &FakeSeal =
            &|_, _, _| Err(irlume_common::Error::Policy("injected seal failure".into()));
        let no_seal: &FakeSeal = &|_, _, _| panic!("a key this account may use is kept");

        for (what, replacing) in [("a replacement", true), ("a first save", false)] {
            let write = |reseal: &FakeSeal| save_choosing_key(&replacement, replacing, reseal);
            for enrolled in [true, false] {
                let case = format!("{what}, enrolled {enrolled}");
                let (enrollment_before, key_before, recovery_before) =
                    plant(None, enrolled, Some(6901));
                let error = write(failing_seal).unwrap_err().to_string();
                assert!(error.contains("injected seal failure"), "{case}: {error}");
                assert_eq!(
                    fs::read(template_key::key_path(user)).unwrap(),
                    key_before,
                    "{case}: a failed seal keeps the key"
                );
                assert_eq!(
                    fs::read(profile_path(user)).ok(),
                    enrollment_before,
                    "{case}"
                );
                assert_eq!(
                    fs::read(&recovery).unwrap(),
                    recovery_before,
                    "{case}: and the recovery envelope"
                );
                assert!(store.exists() && journal.exists(), "{case}: and the store");

                write(&fake_seal).unwrap();
                let key =
                    crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
                assert_eq!(key.uid, Some(6902), "{case}: a key of the account's own");
                assert_ne!(key.private, old_key, "{case}");
                assert!(
                    !recovery.exists(),
                    "{case}: the old key's recovery envelope goes"
                );
                assert!(
                    !store.exists() && !journal.exists(),
                    "{case}: so does the camera store and its journal"
                );
                let saved = deserialize_enrollment(
                    &fs::read(profile_path(user)).unwrap(),
                    Some(&key.private),
                )
                .unwrap();
                assert_eq!(saved.uid, Some(6902), "{case}");
            }

            for (key_uid, recovery_uid) in
                [(None, Some(6902)), (None, None), (Some(6902), Some(6901))]
            {
                let case = format!("{what}, key {key_uid:?}, recovery {recovery_uid:?}");
                let (_, key_before, recovery_before) = plant(key_uid, true, recovery_uid);
                write(no_seal).unwrap();
                assert_eq!(
                    fs::read(template_key::key_path(user)).unwrap(),
                    key_before,
                    "{case}: the key is kept"
                );
                assert_eq!(fs::read(&recovery).unwrap(), recovery_before, "{case}");
                assert!(store.exists() && journal.exists(), "{case}");
                let saved =
                    deserialize_enrollment(&fs::read(profile_path(user)).unwrap(), Some(&old_key))
                        .unwrap();
                assert_eq!(saved.uid, Some(6902), "{case}");
            }
        }
        leave_uid_sandbox(&dir);
    }

    /// A template key an earlier release sealed without a uid, under an
    /// enrollment that records none (or none stored), is reused only when
    /// its recovery envelope shows no other uid. An envelope that is stored
    /// but cannot be read (not JSON, not an envelope, not a file) cannot
    /// show that, so neither a replacement enrollment nor a first save is
    /// written: nothing is sealed, and the key, the enrollment, the envelope
    /// and the added-camera store stay as they were. The refusal names
    /// `irlume recovery forget` for a file, which it removes, and otherwise
    /// says to move the path away. With no envelope stored the key is
    /// reused, as before. Beside a key or an enrollment that records the
    /// current uid the envelope is not needed, and the write goes ahead.
    #[test]
    fn an_unreadable_recovery_envelope_refuses_a_write_that_would_reuse_an_unbound_key() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-unreadable-recovery");
        let user = "uid-unreadable-recovery";
        let old_key = [13u8; 32];
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        let clear_recovery = || {
            let _ = fs::remove_file(&recovery);
            let _ = fs::remove_dir(&recovery);
        };
        // The key records `key_uid`; with `enrolled`, an enrollment that
        // records the uid it holds is stored under the key.
        let plant = |key_uid: Option<u32>, enrolled: Option<Option<u32>>| {
            clear_recovery();
            let _ = fs::remove_file(profile_path(user));
            if let Some(uid) = enrolled {
                let mut old = sample();
                old.user = user.into();
                old.uid = uid;
                let bytes = serialize_enrollment(&old, Some(&old_key)).unwrap();
                fs::write(profile_path(user), bytes).unwrap();
            }
            fake_seal(user, &old_key, key_uid).unwrap();
            (
                fs::read(profile_path(user)).ok(),
                fs::read(template_key::key_path(user)).unwrap(),
            )
        };
        let not_json = || fs::write(&recovery, b"synthetic, not an envelope").unwrap();
        let not_an_envelope = || fs::write(&recovery, br#"{"version":1}"#).unwrap();
        let not_a_file = || fs::create_dir(&recovery).unwrap();
        // Whether `irlume recovery forget` removes what is at the path, and
        // so whether the refusal names it.
        let unreadable: [(&str, &dyn Fn(), bool); 3] = [
            ("not JSON", &not_json, true),
            ("not an envelope", &not_an_envelope, true),
            ("not a file", &not_a_file, false),
        ];
        let (store, journal) = plant_camera_store(user);
        let _now = crate::account::remember(user, 7102);
        let mut replacement = Enrollment::new(user);
        replacement.profiles = sample().profiles;
        let no_seal: &FakeSeal = &|_, _, _| panic!("no key is sealed");

        for (what, replacing) in [("a replacement", true), ("a first save", false)] {
            let write = || save_choosing_key(&replacement, replacing, no_seal);
            for enrolled in [Some(None), None] {
                for (kind, make_unreadable, forget_removes) in unreadable {
                    let case = format!("{what}, enrolled {enrolled:?}, recovery {kind}");
                    let (enrollment_before, key_before) = plant(None, enrolled);
                    make_unreadable();
                    let error = write().unwrap_err().to_string();
                    assert!(
                        error.contains("recovery envelope") && error.contains("cannot be read"),
                        "{case}: {error}"
                    );
                    let next_step = if forget_removes {
                        format!(
                            "remove it with `irlume recovery forget`, or move {} away",
                            recovery.display()
                        )
                    } else {
                        format!(
                            "{} is not a file that `irlume recovery forget` removes, so move it \
                             away",
                            recovery.display()
                        )
                    };
                    assert!(error.ends_with(&next_step), "{case}: {error}");
                    assert_eq!(
                        fs::read(template_key::key_path(user)).unwrap(),
                        key_before,
                        "{case}: the key is kept"
                    );
                    assert_eq!(
                        fs::read(profile_path(user)).ok(),
                        enrollment_before,
                        "{case}: no enrollment is written"
                    );
                    assert!(recovery.exists(), "{case}: the envelope stays");
                    assert!(store.exists() && journal.exists(), "{case}: and the store");
                }

                let case = format!("{what}, enrolled {enrolled:?}, no recovery envelope");
                let (_, key_before) = plant(None, enrolled);
                write().unwrap();
                assert_eq!(
                    fs::read(template_key::key_path(user)).unwrap(),
                    key_before,
                    "{case}: the key is reused"
                );
                let saved =
                    deserialize_enrollment(&fs::read(profile_path(user)).unwrap(), Some(&old_key))
                        .unwrap();
                assert_eq!(saved.uid, Some(7102), "{case}");
                assert!(store.exists() && journal.exists(), "{case}");
            }

            for (key_uid, enrollment_uid) in [(Some(7102), None), (None, Some(7102))] {
                let case = format!("{what}, key {key_uid:?}, enrollment {enrollment_uid:?}");
                let (_, key_before) = plant(key_uid, Some(enrollment_uid));
                not_json();
                write().unwrap();
                assert_eq!(
                    fs::read(template_key::key_path(user)).unwrap(),
                    key_before,
                    "{case}: the key is reused"
                );
                assert_eq!(
                    fs::read(&recovery).unwrap(),
                    b"synthetic, not an envelope",
                    "{case}: the envelope is left alone"
                );
            }
        }
        clear_recovery();
        leave_uid_sandbox(&dir);
    }

    /// An added-camera store write uses the account's template key only
    /// when an enrollment write would reuse it too. A key that opens an
    /// enrollment recorded for another uid, or that records no uid under an
    /// enrollment that records none (or none stored) while its recovery
    /// envelope records another uid, is refused with nothing sealed: the
    /// store write does not replace the key, since the enrollment beside the
    /// store is encrypted under it. So is such a key when its recovery
    /// envelope cannot be read, and a key sealed for another uid. The key is
    /// used when those records show the current uid or none, and a new key
    /// is sealed for the account when none is stored.
    #[test]
    fn an_added_camera_store_write_refuses_a_key_an_enrollment_write_would_replace() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-camera-store-key");
        let user = "uid-camera-store-key";
        let old_key = [17u8; 32];
        let wrapped = crate::recovery::wrap(b"a recovery passphrase", &old_key).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        // The key records `key_uid`; with `enrolled`, an enrollment that
        // records the uid it holds is stored under it; with `recovery_uid`, a
        // recovery envelope that records the uid it holds is stored.
        let plant = |key_uid: Option<u32>,
                     enrolled: Option<Option<u32>>,
                     recovery_uid: Option<Option<u32>>| {
            let _ = fs::remove_file(profile_path(user));
            let _ = fs::remove_file(&recovery);
            if let Some(uid) = enrolled {
                let mut old = sample();
                old.user = user.into();
                old.uid = uid;
                let bytes = serialize_enrollment(&old, Some(&old_key)).unwrap();
                fs::write(profile_path(user), bytes).unwrap();
            }
            fake_seal(user, &old_key, key_uid).unwrap();
            if let Some(uid) = recovery_uid {
                let mut envelope = wrapped.clone();
                envelope.uid = uid;
                fs::write(&recovery, serde_json::to_vec(&envelope).unwrap()).unwrap();
            }
            (
                fs::read(profile_path(user)).ok(),
                fs::read(template_key::key_path(user)).unwrap(),
                fs::read(&recovery).ok(),
            )
        };
        let _now = crate::account::remember(user, 7202);
        let no_seal: &FakeSeal = &|_, _, _| panic!("no key is sealed over an existing one");
        let store_key = |reseal: &FakeSeal| {
            template_key::camera_store_key_with(
                user,
                &mut Account::new(user),
                &key_is_another_accounts,
                fake_load,
                no_move,
                reseal,
            )
        };

        let refused = [
            (
                "its enrollment records another uid",
                None,
                Some(Some(7201)),
                Some(None),
                "belongs to another uid",
            ),
            (
                "its enrollment records another uid, the key the current one",
                Some(7202),
                Some(Some(7201)),
                None,
                "belongs to another uid",
            ),
            (
                "its recovery envelope records another uid",
                None,
                Some(None),
                Some(Some(7201)),
                "belongs to another uid",
            ),
            (
                "no enrollment, its recovery envelope records another uid",
                None,
                None,
                Some(Some(7201)),
                "belongs to another uid",
            ),
            (
                "the key records another uid",
                Some(7201),
                Some(None),
                None,
                "uid 7201",
            ),
        ];
        for (case, key_uid, enrolled, recovery_uid, expected) in refused {
            let before = plant(key_uid, enrolled, recovery_uid);
            let error = store_key(no_seal).unwrap_err().to_string();
            assert!(error.contains(expected), "{case}: {error}");
            assert_eq!(
                (
                    fs::read(profile_path(user)).ok(),
                    fs::read(template_key::key_path(user)).unwrap(),
                    fs::read(&recovery).ok(),
                ),
                before,
                "{case}: nothing changes"
            );
        }

        let (_, key_before, _) = plant(None, Some(None), None);
        fs::write(&recovery, b"synthetic, not an envelope").unwrap();
        let error = store_key(no_seal).unwrap_err().to_string();
        assert!(error.contains("cannot be read"), "{error}");
        assert_eq!(fs::read(template_key::key_path(user)).unwrap(), key_before);

        let kept = [
            (
                "its enrollment records the current uid",
                None,
                Some(Some(7202)),
                Some(Some(7201)),
            ),
            (
                "the key records the current uid",
                Some(7202),
                Some(None),
                Some(Some(7201)),
            ),
            (
                "its recovery envelope records the current uid",
                None,
                Some(None),
                Some(Some(7202)),
            ),
            ("nothing records a uid", None, Some(None), Some(None)),
            ("no recovery envelope", None, None, None),
        ];
        for (case, key_uid, enrolled, recovery_uid) in kept {
            let before = plant(key_uid, enrolled, recovery_uid);
            let key = store_key(no_seal).unwrap();
            assert_eq!(&*key, &old_key, "{case}: the key is used");
            assert_eq!(
                fs::read(template_key::key_path(user)).unwrap(),
                before.1,
                "{case}"
            );
        }

        let _ = fs::remove_file(profile_path(user));
        let _ = fs::remove_file(&recovery);
        fs::remove_file(template_key::key_path(user)).unwrap();
        let key = store_key(&fake_seal).unwrap();
        let sealed = crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
        assert_eq!(sealed.private, key.to_vec(), "a new key is sealed");
        assert_eq!(sealed.uid, Some(7202), "for the account");
        leave_uid_sandbox(&dir);
    }

    /// The production loader for a read before a possible write must not
    /// upgrade a sealed key before the write decides whether to keep it.
    #[test]
    fn a_read_before_a_write_uses_the_unmoved_key_loader() {
        let source = include_str!("storage.rs");
        let loader = source
            .split_once("pub fn load_unmoved(user: &str)")
            .expect("the production read-before-write loader exists")
            .1
            .split_once("/// An enrollment together with the template key")
            .expect("the loader ends before the next public API")
            .0;
        assert!(loader.contains("template_key::load_key_unmoved_as"));
        assert!(!loader.contains("template_key::load_key_as,"));
    }

    /// A write moves an existing template key to a stronger TPM policy only
    /// once it keeps the key as the account's: the key is checked on a load
    /// that writes nothing. So a write refused over the key (an enrollment
    /// write over an unreadable recovery envelope, an added-camera store
    /// write or a recovery setup over a key whose records name another uid)
    /// leaves the key file byte for byte as it was, although a stronger
    /// policy is available. Nor does a key an enrollment write replaces as
    /// another account's move: a failed replacement puts it back as it was.
    /// A key each write keeps moves, and keeps the uid it records.
    #[test]
    fn a_write_moves_a_template_key_to_a_stronger_policy_only_once_it_keeps_it() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let prediction = crate::tpm::tests::PredictionFixture::new();
        prediction.write(&[7]);
        let dir = uid_sandbox("uid-kept-key-move");
        let user = "uid-kept-key-move";
        let old_key = [19u8; 32];
        let passphrase: &[u8] = b"a recovery passphrase";
        let wrapped = crate::recovery::wrap(passphrase, &old_key).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        // What is stored at the recovery path.
        #[derive(Clone, Copy, Debug)]
        enum Recovery {
            Absent,
            Records(Option<u32>),
            Unreadable,
        }
        // The key records `key_uid`; with `enrolled`, an enrollment that
        // records the uid it holds is stored under it. Returns the key file.
        let plant = |key_uid: Option<u32>, enrolled: Option<Option<u32>>, stored: Recovery| {
            let _ = fs::remove_file(profile_path(user));
            let _ = fs::remove_file(&recovery);
            if let Some(uid) = enrolled {
                let mut old = sample();
                old.user = user.into();
                old.uid = uid;
                let bytes = serialize_enrollment(&old, Some(&old_key)).unwrap();
                fs::write(profile_path(user), bytes).unwrap();
            }
            fake_seal(user, &old_key, key_uid).unwrap();
            match stored {
                Recovery::Absent => {}
                Recovery::Records(uid) => {
                    let mut envelope = wrapped.clone();
                    envelope.uid = uid;
                    fs::write(&recovery, serde_json::to_vec(&envelope).unwrap()).unwrap();
                }
                Recovery::Unreadable => {
                    fs::write(&recovery, b"synthetic, not an envelope").unwrap();
                }
            }
            fs::read(template_key::key_path(user)).unwrap()
        };
        let _now = crate::account::remember(user, 7302);
        let mut replacement = Enrollment::new(user);
        replacement.profiles = sample().profiles;
        let no_seal: &FakeSeal = &|_, _, _| panic!("no key is sealed over one the write checks");
        let enrollment = || save_moving_kept_key(&replacement, false, no_seal, &fake_move);
        let replacing = || save_moving_kept_key(&replacement, true, no_seal, &fake_move);
        let camera_store = || {
            template_key::camera_store_key_with(
                user,
                &mut Account::new(user),
                &key_is_another_accounts,
                fake_load,
                fake_move,
                no_seal,
            )
            .map(drop)
        };
        let recovery_setup =
            || template_key::setup_recovery_with(user, passphrase, fake_load, fake_move);
        type Write<'w> = &'w dyn Fn() -> irlume_common::Result<()>;
        // The write, the enrollment and recovery envelope beside a key that
        // records no uid, and the refusal expected.
        type Refused<'w> = (&'w str, Write<'w>, Option<Option<u32>>, Recovery, &'w str);

        let refused: [Refused<'_>; 9] = [
            (
                "an enrollment write",
                &enrollment,
                Some(None),
                Recovery::Unreadable,
                "cannot be read",
            ),
            (
                "an enrollment write",
                &enrollment,
                None,
                Recovery::Unreadable,
                "cannot be read",
            ),
            (
                "a replacement enrollment write",
                &replacing,
                Some(None),
                Recovery::Unreadable,
                "cannot be read",
            ),
            (
                "a replacement enrollment write",
                &replacing,
                None,
                Recovery::Unreadable,
                "cannot be read",
            ),
            (
                "an added-camera store write",
                &camera_store,
                Some(Some(7301)),
                Recovery::Absent,
                "belongs to another uid",
            ),
            (
                "an added-camera store write",
                &camera_store,
                Some(None),
                Recovery::Records(Some(7301)),
                "belongs to another uid",
            ),
            (
                "an added-camera store write",
                &camera_store,
                Some(None),
                Recovery::Unreadable,
                "cannot be read",
            ),
            (
                "a recovery setup",
                &recovery_setup,
                Some(Some(7301)),
                Recovery::Absent,
                "face enrollment",
            ),
            (
                "a recovery setup",
                &recovery_setup,
                Some(None),
                Recovery::Records(Some(7301)),
                "recovery envelope",
            ),
        ];
        for (what, write, enrolled, stored, expected) in refused {
            let case = format!("{what}, enrolled {enrolled:?}, recovery {stored:?}");
            let before = plant(None, enrolled, stored);
            let error = write().unwrap_err().to_string();
            assert!(error.contains(expected), "{case}: {error}");
            assert_eq!(
                fs::read(template_key::key_path(user)).unwrap(),
                before,
                "{case}: the key file is as it was"
            );
        }

        // An enrollment write replaces a key whose enrollment records another
        // uid, and a failed seal of the new key puts back the replaced key
        // exactly as it was: it was not moved before it was set aside.
        let failing_seal: &FakeSeal =
            &|_, _, _| Err(irlume_common::Error::Policy("injected seal failure".into()));
        for replacing in [false, true] {
            let before = plant(None, Some(Some(7301)), Recovery::Absent);
            let error = save_moving_kept_key(&replacement, replacing, failing_seal, &fake_move)
                .unwrap_err()
                .to_string();
            assert!(error.contains("injected seal failure"), "{error}");
            assert_eq!(
                fs::read(template_key::key_path(user)).unwrap(),
                before,
                "replacing {replacing}: the replaced key is put back as it was"
            );
        }

        let kept: [(&str, Write<'_>); 4] = [
            ("an enrollment write", &enrollment),
            ("a replacement enrollment write", &replacing),
            ("an added-camera store write", &camera_store),
            ("a recovery setup", &recovery_setup),
        ];
        for (what, write) in kept {
            for key_uid in [None, Some(7302)] {
                let case = format!("{what}, key {key_uid:?}");
                let before = plant(key_uid, Some(None), Recovery::Absent);
                write().unwrap();
                assert_ne!(
                    fs::read(template_key::key_path(user)).unwrap(),
                    before,
                    "{case}: the kept key moved"
                );
                let moved =
                    crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
                assert!(
                    matches!(moved.policy, crate::envelope::PolicyKind::PcrlockNv { .. }),
                    "{case}"
                );
                assert_eq!(moved.private, old_key.to_vec(), "{case}: the same key");
                assert_eq!(moved.uid, key_uid, "{case}: and the uid it records");
            }
        }
        let _ = fs::remove_file(&recovery);
        leave_uid_sandbox(&dir);
    }

    /// A recovery setup wraps the template key for the account only when the
    /// records coupled to the key do not show it is another account's. An
    /// enrollment under the key recorded for another uid refuses it, whatever
    /// the key records. Under a key that records no uid, with an enrollment
    /// that records none (or none stored), a recovery envelope recorded for
    /// another uid refuses it too. A refusal keeps the envelope as it was.
    /// An enrollment recorded for the account's uid, or a key recorded for
    /// it, lets the envelope be replaced whatever it records. A restore seals
    /// nothing when the enrollment the restored key opens records another
    /// uid, and otherwise seals the key for the account.
    #[test]
    fn recovery_setup_and_restore_check_the_enrollment_a_key_opens() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-recovery-owner");
        let user = "uid-recovery-owner";
        let key = [13u8; 32];
        let passphrase: &[u8] = b"a recovery passphrase";
        let wrapped = crate::recovery::wrap(passphrase, &key).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        // The enrollment under `key` records `enrollment_uid` (`None` for the
        // outer option: no enrollment), the key `key_uid`, and the recovery
        // envelope wrapping it `recovery_uid`.
        let plant = |key_uid: Option<u32>,
                     enrollment_uid: Option<Option<u32>>,
                     recovery_uid: Option<u32>| {
            let _ = fs::remove_file(profile_path(user));
            if let Some(uid) = enrollment_uid {
                let mut enrollment = sample();
                enrollment.user = user.into();
                enrollment.uid = uid;
                let bytes = serialize_enrollment(&enrollment, Some(&key)).unwrap();
                fs::write(profile_path(user), bytes).unwrap();
            }
            fake_seal(user, &key, key_uid).unwrap();
            let mut envelope = wrapped.clone();
            envelope.uid = recovery_uid;
            fs::write(&recovery, serde_json::to_vec(&envelope).unwrap()).unwrap();
            fs::read(&recovery).unwrap()
        };
        let recovery_uid = || {
            serde_json::from_slice::<crate::recovery::RecoveryEnvelope>(
                &fs::read(&recovery).unwrap(),
            )
            .unwrap()
            .uid
        };
        let _now = crate::account::remember(user, 6802);

        for (key_uid, enrollment_uid, recovery_before, refused_as) in [
            (None, Some(Some(6801)), Some(6801), "face enrollment"),
            (None, Some(Some(6801)), None, "face enrollment"),
            (Some(6802), Some(Some(6801)), None, "face enrollment"),
            (None, Some(None), Some(6801), "recovery envelope"),
            (None, None, Some(6801), "recovery envelope"),
        ] {
            let case = format!("{key_uid:?} {enrollment_uid:?} {recovery_before:?}");
            let before = plant(key_uid, enrollment_uid, recovery_before);
            let error = template_key::setup_recovery_with(user, passphrase, fake_load, no_move)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("no recovery passphrase was set")
                    && error.contains(refused_as)
                    && error.contains("uid 6801")
                    && error.contains("now uid 6802")
                    && error.contains("irlume enroll"),
                "{case}: {error}"
            );
            assert!(!error.contains('\u{2014}'));
            assert_eq!(fs::read(&recovery).unwrap(), before, "{case}: kept");
        }
        // Nor can the envelope be erased first to get past that check.
        let before = plant(None, None, Some(6801));
        let error = template_key::forget_recovery(user).unwrap_err().to_string();
        assert!(
            error.contains("recovery envelope") && error.contains("uid 6801"),
            "{error}"
        );
        assert_eq!(fs::read(&recovery).unwrap(), before, "forget kept it");
        for (key_uid, enrollment_uid, recovery_before) in [
            (None, Some(Some(6802)), Some(6801)),
            (None, Some(None), None),
            (Some(6802), Some(None), Some(6801)),
        ] {
            plant(key_uid, enrollment_uid, recovery_before);
            template_key::setup_recovery_with(user, passphrase, fake_load, no_move).unwrap();
            assert_eq!(
                recovery_uid(),
                Some(6802),
                "{key_uid:?} {enrollment_uid:?} {recovery_before:?}"
            );
        }

        // A restore from a recovery file that records no uid, over a key
        // that records none.
        plant(None, Some(Some(6801)), None);
        let key_before = fs::read(template_key::key_path(user)).unwrap();
        let recovery_before = fs::read(&recovery).unwrap();
        let error = template_key::restore_with(user, passphrase, |_, _, _| {
            panic!("a key whose enrollment records another uid is not sealed")
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("was not restored")
                && error.contains("face enrollment")
                && error.contains("uid 6801")
                && error.contains("irlume enroll"),
            "{error}"
        );
        assert_eq!(fs::read(template_key::key_path(user)).unwrap(), key_before);
        assert_eq!(fs::read(&recovery).unwrap(), recovery_before);
        for enrollment_uid in [Some(Some(6802)), Some(None), None] {
            plant(None, enrollment_uid, None);
            template_key::restore_with(user, passphrase, fake_seal).unwrap();
            let sealed =
                crate::envelope::SealedEnvelope::load(&template_key::key_path(user)).unwrap();
            assert_eq!(sealed.uid, Some(6802), "{enrollment_uid:?}");
            assert_eq!(sealed.private, key);
        }
        leave_uid_sandbox(&dir);
    }

    /// On a host without a TPM, an enrollment write over a plaintext
    /// enrollment recorded for another uid removes the added-camera store
    /// beside it, and its commit journal, once the new enrollment is durable:
    /// the store was captured for the replaced enrollment. A write that
    /// publishes nothing leaves the store, and so does a write over an
    /// enrollment recorded for the current uid or for none.
    #[test]
    fn a_write_over_another_uids_plaintext_enrollment_removes_its_camera_store() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-other-camera-store");
        let user = "uid-other-camera-store";
        let _now = crate::account::remember(user, 6702);
        let mut replacement = Enrollment::new(user);
        replacement.profiles = sample().profiles;

        for uid in [Some(6702), None] {
            plant_plaintext(&dir, user, uid);
            let (store, journal) = plant_camera_store(user);
            save_with_key(&replacement, |_, _| Ok(None)).unwrap();
            assert!(store.exists() && journal.exists(), "recorded for {uid:?}");
        }

        let before = plant_plaintext(&dir, user, Some(6701));
        let (store, journal) = plant_camera_store(user);
        // Root writes into a read-only directory, so only another user can
        // make the publication fail this way.
        if fs::metadata(&dir).unwrap().uid() != 0 {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
            let failed = save_with_key(&replacement, |_, _| Ok(None));
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            let error = failed.expect_err("the state dir takes no new file");
            assert_eq!(fs::read(profile_path(user)).unwrap(), before, "{error}");
            assert!(store.exists() && journal.exists(), "{error}");
        }
        save_with_key(&replacement, |_, _| Ok(None)).unwrap();
        assert!(!store.exists(), "the store goes");
        assert!(
            !journal.exists(),
            "and its journal, so recovery cannot restore it"
        );
        let on_disk: serde_json::Value =
            serde_json::from_slice(&fs::read(profile_path(user)).unwrap()).unwrap();
        assert_eq!(on_disk["uid"], 6702);
        leave_uid_sandbox(&dir);
    }

    /// An encrypted enrollment whose template key was sealed for another uid
    /// reads as not enrolled without an unseal; under a key for the current
    /// uid, the enrollment inside is checked as well.
    #[test]
    fn an_encrypted_enrollment_under_a_key_sealed_for_another_uid_is_not_unsealed() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-other-key");
        let user = "uid-key-owner";
        let _now = crate::account::remember(user, 4902);
        let write = |key_uid: Option<u32>, enrollment_uid: Option<u32>| {
            let mut enrollment = sample();
            enrollment.user = user.into();
            enrollment.uid = enrollment_uid;
            fs::write(
                profile_path(user),
                serialize_enrollment(&enrollment, Some(&[42; 32])).unwrap(),
            )
            .unwrap();
            let mut key: crate::envelope::SealedEnvelope =
                serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#)
                    .unwrap();
            key.uid = key_uid;
            key.save(&template_key::key_path(user)).unwrap();
        };
        let load_keyed = |unsealed: bool| {
            load_with(
                user,
                template_key::UserStateLock::acquire,
                |user, account| {
                    template_key::load_key_with(
                        user,
                        account,
                        template_key::KeyLoadPolicy::Keep,
                        |_| {
                            assert!(
                                unsealed,
                                "a key sealed for another uid must not be unsealed"
                            );
                            Ok(Zeroizing::new(vec![42; 32]))
                        },
                        |_| panic!("an authentication load does not probe upgrades"),
                        |_| panic!("an authentication load does not seal"),
                    )
                },
            )
        };

        write(Some(4901), None);
        assert!(load_keyed(false).unwrap().is_none());
        write(Some(4902), Some(4901));
        assert!(load_keyed(true).unwrap().is_none());
        for (key_uid, enrollment_uid) in [(Some(4902), Some(4902)), (None, None)] {
            write(key_uid, enrollment_uid);
            let (enrollment, key) = load_keyed(true).unwrap().expect("loads");
            assert_eq!(enrollment.uid, enrollment_uid);
            assert!(key.is_some());
        }
        leave_uid_sandbox(&dir);
    }

    /// A replacement enrollment never unseals a key sealed for another uid:
    /// it takes the first-save path, which gives the account its own key.
    #[test]
    fn a_replacement_never_unseals_a_key_sealed_for_another_uid() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-replacement");
        let user = "uid-replacement-owner";
        let _now = crate::account::remember(user, 5202);
        let mut old = sample();
        old.user = user.into();
        old.uid = Some(5201);
        fs::write(
            profile_path(user),
            serialize_enrollment(&old, Some(&[7; 32])).unwrap(),
        )
        .unwrap();
        let mut key: crate::envelope::SealedEnvelope =
            serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#).unwrap();
        key.uid = Some(5201);
        key.save(&template_key::key_path(user)).unwrap();
        assert!(load(user).unwrap().is_none());

        let mut replacement = Enrollment::new(user);
        replacement.profiles = sample().profiles;
        let mut first_saves = 0;
        save_with_key(&replacement, |user, account| {
            replacement_key(
                user,
                account,
                |_, _| panic!("a key sealed for another uid must not be unsealed"),
                no_move,
                |_, _| {
                    first_saves += 1;
                    Ok(None)
                },
            )
        })
        .unwrap();
        assert_eq!(first_saves, 1);
        assert_eq!(load(user).unwrap().unwrap().uid, Some(5202));
        leave_uid_sandbox(&dir);
    }

    /// A load-modify-save (adding scans, renaming a profile) writes the
    /// enrollment for the uid it was loaded for. When the name resolves to
    /// another uid by the save, or to no account, the save is refused before
    /// any key is chosen and the enrollment stays as it was: the new uid is
    /// never recorded on the loaded enrollment. The same save goes through
    /// once the name resolves to the loaded uid again.
    #[test]
    fn a_save_after_the_name_resolves_to_another_uid_writes_nothing() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-owner-changed");
        let user = "uid-owner-changed";
        let before = plant_plaintext(&dir, user, Some(6201));
        let _then = crate::account::remember(user, 6201);
        let mut loaded = load(user).unwrap().expect("loads for its own uid");
        assert_eq!(loaded.loaded_for, Some(6201));
        loaded.profiles[0].name = "Renamed".into();
        let refused = |loaded: &Enrollment| {
            save_with_key(loaded, |_, _| {
                panic!("no key is chosen for a write that is refused")
            })
            .unwrap_err()
            .to_string()
        };
        {
            let _recreated = crate::account::remember(user, 6202);
            let error = refused(&loaded);
            assert!(
                error.contains("belongs to uid 6201")
                    && error.contains("now uid 6202")
                    && error.contains("nothing was written"),
                "{error}"
            );
            assert_eq!(fs::read(profile_path(user)).unwrap(), before);
        }
        {
            let _gone =
                crate::account::remember_resolution(user, crate::account::Resolution::NoAccount);
            let error = refused(&loaded);
            assert!(error.contains("no account named"), "{error}");
            assert_eq!(fs::read(profile_path(user)).unwrap(), before);
        }
        save_with_key(&loaded, |_, _| Ok(None)).unwrap();
        let saved = load(user).unwrap().unwrap();
        assert_eq!(saved.uid, Some(6201));
        assert_eq!(saved.profiles[0].name, "Renamed");
        leave_uid_sandbox(&dir);
    }

    /// An enrollment written before the uid was recorded, under a template
    /// key that records one, is loaded for the key's uid. A save after the
    /// name resolved to another uid is refused: it neither records the new
    /// uid on the enrollment nor replaces the key, so the templates never
    /// move to the other account. For the key's uid, the save records that
    /// uid on the enrollment and keeps the key.
    #[test]
    fn a_save_keeps_the_uid_an_enrollment_was_loaded_for_under_its_key() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-loaded-for");
        let user = "uid-loaded-for";
        let key = [9u8; 32];
        let mut legacy = sample();
        legacy.user = user.into();
        let enrollment_before = serialize_enrollment(&legacy, Some(&key)).unwrap();
        fs::write(profile_path(user), &enrollment_before).unwrap();
        fake_seal(user, &key, Some(6301)).unwrap();
        let key_before = fs::read(template_key::key_path(user)).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        fs::write(&recovery, b"synthetic recovery of the key").unwrap();

        let _then = crate::account::remember(user, 6301);
        let (mut loaded, _) = load_with(user, template_key::UserStateLock::acquire, fake_load)
            .unwrap()
            .expect("loads for the key's uid");
        assert_eq!(loaded.uid, None, "the enrollment itself records none");
        assert_eq!(loaded.loaded_for, Some(6301));
        loaded.profiles[0].name = "Renamed".into();
        let save = |loaded: &Enrollment| {
            save_with_key(loaded, |user, account| {
                template_key::ensure_key_with(
                    user,
                    account,
                    Some(&key_is_another_accounts),
                    fake_load,
                    no_move,
                    fake_seal,
                )
                .map(Some)
            })
        };
        {
            let _recreated = crate::account::remember(user, 6302);
            let error = save(&loaded).unwrap_err().to_string();
            assert!(
                error.contains("belongs to uid 6301") && error.contains("now uid 6302"),
                "{error}"
            );
            assert_eq!(fs::read(template_key::key_path(user)).unwrap(), key_before);
            assert_eq!(fs::read(profile_path(user)).unwrap(), enrollment_before);
            assert!(recovery.exists());
        }
        save(&loaded).unwrap();
        assert_eq!(fs::read(template_key::key_path(user)).unwrap(), key_before);
        assert!(recovery.exists());
        let saved =
            deserialize_enrollment(&fs::read(profile_path(user)).unwrap(), Some(&key)).unwrap();
        assert_eq!(saved.uid, Some(6301));
        assert_eq!(saved.profiles[0].name, "Renamed");
        leave_uid_sandbox(&dir);
    }

    /// An enrollment an earlier release wrote, with no template key (a host
    /// without a TPM) or under a key that records no uid either, is loaded
    /// for the uid the name resolves to at the load. A save after the name
    /// resolved to another uid is refused before any key is chosen, and the
    /// enrollment, the key and its recovery envelope stay as they were: the
    /// other uid is never recorded on these templates. For the uid it was
    /// loaded for, the save records that uid and keeps the key.
    #[test]
    fn a_save_of_an_enrollment_loaded_without_any_uid_is_held_to_the_load() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _tpm = crate::testenv::NoTpm::set();
        let dir = uid_sandbox("uid-loaded-unbound");
        let user = "uid-loaded-unbound";
        let refused = |loaded: &Enrollment| {
            let _recreated = crate::account::remember(user, 6502);
            save_with_key(loaded, |_, _| {
                panic!("no key is chosen for a write that is refused")
            })
            .unwrap_err()
            .to_string()
        };
        let loaded_as_the_first_account = |load: &dyn Fn() -> Enrollment| {
            let _then = crate::account::remember(user, 6501);
            let mut loaded = load();
            assert_eq!(loaded.uid, None, "the enrollment records none");
            assert_eq!(loaded.loaded_for, Some(6501));
            loaded.profiles[0].name = "Renamed".into();
            loaded
        };

        // Plaintext, no key.
        let before = plant_plaintext(&dir, user, None);
        let loaded = loaded_as_the_first_account(&|| load(user).unwrap().unwrap());
        loaded_as_the_first_account(&|| {
            load_path_unlocked(user, &profile_path(user))
                .unwrap()
                .unwrap()
        });
        let error = refused(&loaded);
        assert!(
            error.contains("belongs to uid 6501") && error.contains("now uid 6502"),
            "{error}"
        );
        assert_eq!(fs::read(profile_path(user)).unwrap(), before);

        // Encrypted under a key that records no uid.
        let key = [11u8; 32];
        let mut legacy = sample();
        legacy.user = user.into();
        let enrollment_before = serialize_enrollment(&legacy, Some(&key)).unwrap();
        fs::write(profile_path(user), &enrollment_before).unwrap();
        fake_seal(user, &key, None).unwrap();
        let key_before = fs::read(template_key::key_path(user)).unwrap();
        let recovery = template_key::recovery_path(user);
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        // A recovery envelope of the key that records no uid either.
        let wrapped = crate::recovery::wrap(b"a recovery passphrase", &key).unwrap();
        fs::write(&recovery, serde_json::to_vec(&wrapped).unwrap()).unwrap();
        let loaded = loaded_as_the_first_account(&|| {
            load_with(user, template_key::UserStateLock::acquire, fake_load)
                .unwrap()
                .unwrap()
                .0
        });
        let error = refused(&loaded);
        assert!(
            error.contains("belongs to uid 6501") && error.contains("now uid 6502"),
            "{error}"
        );
        assert_eq!(fs::read(template_key::key_path(user)).unwrap(), key_before);
        assert_eq!(fs::read(profile_path(user)).unwrap(), enrollment_before);
        assert!(recovery.exists());

        let _then = crate::account::remember(user, 6501);
        save_with_key(&loaded, |user, account| {
            template_key::ensure_key_with(
                user,
                account,
                Some(&key_is_another_accounts),
                fake_load,
                no_move,
                |_, _, _| panic!("the key of the loaded account is kept"),
            )
            .map(Some)
        })
        .unwrap();
        assert_eq!(fs::read(template_key::key_path(user)).unwrap(), key_before);
        assert!(recovery.exists());
        let saved =
            deserialize_enrollment(&fs::read(profile_path(user)).unwrap(), Some(&key)).unwrap();
        assert_eq!(saved.uid, Some(6501));
        assert_eq!(saved.profiles[0].name, "Renamed");
        leave_uid_sandbox(&dir);
    }

    /// The uid a load checked is never written to or read from a file.
    #[test]
    fn the_uid_a_load_checked_is_never_stored() {
        let mut enrollment = sample();
        enrollment.loaded_for = Some(6401);
        let bytes = serialize_enrollment(&enrollment, None).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("loaded_for").is_none(), "{value}");
        let mut forged = value;
        forged["loaded_for"] = 6402.into();
        let read = deserialize_enrollment(&serde_json::to_vec(&forged).unwrap(), None).unwrap();
        assert_eq!(read.loaded_for, None);
    }

    #[test]
    fn encrypted_round_trip_with_key() {
        let key = crypto::generate_key();
        let e = sample();
        let bytes = serialize_enrollment(&e, Some(&key)).unwrap();
        // The ciphertext must not leak the embeddings or the user in cleartext.
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("\"enc\""));
        assert!(!text.contains("Face Profile 1"));
        let back = deserialize_enrollment(&bytes, Some(&key)).unwrap();
        assert_eq!(back.user, "u");
        assert_eq!(back.total_scans(), 1);
        assert!(!back.require_eyes_open);
        assert_eq!(back.profiles[0].scans[0].rgb, vec![0.1, 0.2, 0.3, 0.4]);
    }

    #[test]
    fn plaintext_save_lazily_removes_retired_eye_fields() {
        let old = r#"{"user":"u","profiles":[],"require_eyes_open":true,
            "closure_calibration":[0.24,0.05]}"#;
        let loaded = deserialize_enrollment(old.as_bytes(), None).expect("old plaintext loads");
        assert!(loaded.require_eyes_open);
        assert_eq!(loaded.closure_calibration, Some((0.24, 0.05)));

        let saved = serialize_enrollment(&loaded, None).expect("next plaintext save");
        let saved: serde_json::Value = serde_json::from_slice(&saved).expect("saved enrollment");
        assert!(saved.get("require_eyes_open").is_none());
        assert!(saved.get("closure_calibration").is_none());
    }

    #[test]
    fn encrypted_save_lazily_removes_retired_eye_fields() {
        let key = crypto::generate_key();
        let old = br#"{"user":"u","profiles":[],"require_eyes_open":true,
            "closure_calibration":[0.24,0.05]}"#;
        let envelope = EncEnvelope {
            version: ENC_ENVELOPE_VERSION,
            key_id: Some(irlume_common::sha256_hex(&key)),
            enc: STANDARD.encode(crypto::encrypt(&key, old).expect("encrypt old payload")),
        };
        let envelope = serde_json::to_vec(&envelope).expect("old envelope");
        let loaded = deserialize_enrollment(&envelope, Some(&key)).expect("old encrypted loads");
        assert!(loaded.require_eyes_open);
        assert_eq!(loaded.closure_calibration, Some((0.24, 0.05)));

        let saved = serialize_enrollment(&loaded, Some(&key)).expect("next encrypted save");
        let envelope: EncEnvelope = serde_json::from_slice(&saved).expect("new envelope");
        let blob = STANDARD.decode(envelope.enc).expect("encoded ciphertext");
        let plaintext = crypto::decrypt(&key, &blob).expect("decrypt new payload");
        let saved: serde_json::Value = serde_json::from_slice(&plaintext).expect("inner payload");
        assert!(saved.get("require_eyes_open").is_none());
        assert!(saved.get("closure_calibration").is_none());
    }

    #[test]
    fn encrypted_envelope_binds_itself_to_the_template_key() {
        let key = crypto::generate_key();
        let bytes = serialize_enrollment(&sample(), Some(&key)).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["version"], 3);
        assert_eq!(
            value["key_id"],
            irlume_common::sha256_hex(key.as_slice()),
            "the public key identifier lets load distinguish key divergence from ciphertext damage"
        );
    }

    #[test]
    fn encrypted_enrollment_accepts_historical_and_current_versions() {
        let key = crypto::generate_key();
        let plain = serde_json::to_vec(&sample()).unwrap();
        for version in [2, ENC_ENVELOPE_VERSION] {
            let envelope = EncEnvelope {
                version,
                key_id: (version == ENC_ENVELOPE_VERSION).then(|| irlume_common::sha256_hex(&key)),
                enc: STANDARD.encode(crypto::encrypt(&key, &plain).unwrap()),
            };
            let bytes = serde_json::to_vec(&envelope).unwrap();
            let loaded = deserialize_enrollment(&bytes, Some(&key)).unwrap();
            assert_eq!(loaded.user, "u");
            assert_eq!(loaded.total_scans(), 1);
        }
    }

    #[test]
    fn encrypted_enrollment_rejects_unknown_versions_before_payload_processing() {
        for version in [0, 1, ENC_ENVELOPE_VERSION + 1] {
            let bytes = format!(r#"{{"version":{version},"enc":"not base64"}}"#);
            assert!(matches!(
                deserialize_enrollment(bytes.as_bytes(), Some(&[42; 32])),
                Err(irlume_common::Error::Protocol(message))
                    if message.contains("unsupported encrypted enrollment version")
            ));
        }
    }

    #[test]
    fn load_rejects_unknown_encrypted_version_before_loading_key_and_preserves_file() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("unknown-encrypted-version"));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        drop(template_key::UserStateLock::acquire("u").unwrap());
        let path = profile_path("u");
        let bytes = br#"{"version":4,"enc":"not base64"}"#;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            load_with("u", template_key::UserStateLock::acquire_read_only, |_, _| {
                panic!("unknown versions must be rejected before key loading")
            }),
            Err(irlume_common::Error::Protocol(message))
                if message.contains("unsupported encrypted enrollment version")
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);

        std::env::remove_var("IRLUME_STATE_DIR");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn plaintext_round_trip_without_key() {
        let e = sample();
        let bytes = serialize_enrollment(&e, None).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("Face Profile 1"));
        let back = deserialize_enrollment(&bytes, None).unwrap();
        assert_eq!(back.total_scans(), 1);
    }

    #[test]
    fn encrypted_file_needs_a_key_to_load() {
        let key = crypto::generate_key();
        let bytes = serialize_enrollment(&sample(), Some(&key)).unwrap();
        assert!(deserialize_enrollment(&bytes, None).is_err());
        let err = deserialize_enrollment(&bytes, Some(&crypto::generate_key())).unwrap_err();
        assert!(
            err.to_string()
                .contains("template key does not match enrollment"),
            "a known key mismatch must be diagnosed before the generic GCM check: {err}"
        );
    }

    fn scan_with_ir(ratio: f32, bright: f32) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.1; 4],
            ir: Some(vec![0.2; 4]),
            ir_space: None,
            embed_space: None,
            embed_producer: None,
            ir_center_edge_ratio: ratio,
            ir_brightness: bright,
            pitch: 0.0,
            captured_at: None,
        }
    }

    fn scan_with_pitch(pitch: f32) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.1; 4],
            ir: None,
            ir_space: None,
            embed_space: None,
            embed_producer: None,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch,
            captured_at: None,
        }
    }

    #[test]
    fn pitch_neutral_is_median_of_calibrated_scans() {
        let mut e = Enrollment::new("u");
        // One calibrated scan -> not enough.
        e.profiles.push(FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "p".into(),
            scans: vec![scan_with_pitch(0.60)],
        });
        assert!(e.pitch_neutral().is_none());
        // Add more -> median of {0.60, 0.58, 0.62} = 0.60.
        e.profiles[0].scans.push(scan_with_pitch(0.58));
        e.profiles[0].scans.push(scan_with_pitch(0.62));
        assert!((e.pitch_neutral().unwrap() - 0.60).abs() < 1e-6);
        // Pre-calibration scans (pitch 0.0) are ignored.
        e.profiles[0].scans.push(scan_with_pitch(0.0));
        assert!((e.pitch_neutral().unwrap() - 0.60).abs() < 1e-6);
    }

    #[test]
    fn ir_calibration_needs_two_scans_then_floors_below_weakest() {
        // One IR scan -> not enough to characterise the user's rig.
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "p".into(),
            scans: vec![scan_with_ir(1.5, 100.0)],
        });
        assert!(e.ir_center_edge_ratio_floor().is_none());

        // Two+ scans -> floor at 75% of the weakest enrolled ratio.
        // (brightness is intentionally NOT floored per-user; it is ambient-dependent.)
        e.profiles[0].scans.push(scan_with_ir(1.2, 80.0));
        let depth_floor = e.ir_center_edge_ratio_floor().unwrap();
        assert!((depth_floor - 1.2 * 0.75).abs() < 1e-5);
    }

    fn scan_in_space(name: &str, dim: usize, space: Option<&str>) -> FaceScan {
        FaceScan {
            name: name.into(),
            rgb: vec![0.1; 4],
            ir: Some(vec![0.2; dim]),
            ir_space: space.map(Into::into),
            embed_space: None,
            embed_producer: None,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
            captured_at: None,
        }
    }

    #[test]
    fn unknown_ir_selection_requires_a_tag_and_matching_dimension() {
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "p".into(),
            scans: vec![
                scan_in_space("legacy-untagged", 4, None),
                scan_in_space("raw", 4, Some("raw")),
                scan_in_space("v3", 4, Some("adapter:abc123")),
                scan_in_space("v1-256", 2, None), // unknown regardless of width
                scan_in_space("tagged-short", 2, Some("raw")),
            ],
        });
        // Only the explicitly matching tag is admitted in either pipeline.
        let raw: Vec<_> = e.ir_scans_for("raw", 4).iter().map(|s| s.1).collect();
        assert_eq!(raw, vec!["raw"]);
        // A matching adapter tag remains usable.
        let v3: Vec<_> = e
            .ir_scans_for("adapter:abc123", 4)
            .iter()
            .map(|s| s.1)
            .collect();
        assert_eq!(v3, vec!["v3"]);
        // Unknown provenance cannot substitute for a different adapter build.
        assert!(e.ir_scans_for("adapter:zzz999", 4).is_empty());
        // The unfiltered accessor still reports every IR-bearing scan.
        assert_eq!(e.ir_scans().len(), 5);
        assert_eq!(
            e.ir_scans_for("raw", 2)
                .iter()
                .map(|s| s.1)
                .collect::<Vec<_>>(),
            vec!["tagged-short"]
        );
    }

    #[test]
    fn scan_json_without_ir_space_loads_as_untagged() {
        // Enrollments written before space tagging must load unchanged.
        let json = r#"{"name":"s","rgb":[0.1],"ir":[0.2]}"#;
        let s: FaceScan = serde_json::from_str(json).unwrap();
        assert!(s.ir_space.is_none());
        assert_eq!(s.ir.as_ref().unwrap().len(), 1);
    }

    /// ADR-0030 §2: a scan's capture time is optional display metadata. A
    /// scan written before it loads as undated and re-serialises without the
    /// key, byte for byte (on a host without a TPM key that plaintext is the
    /// file an added camera's snapshot binding hashes), while a dated scan
    /// keeps its time through both store forms.
    #[test]
    fn capture_time_is_optional_and_absent_times_leave_the_bytes_alone() {
        let old = r#"{"name":"s","rgb":[0.1],"ir":null,"ir_space":null,"embed_space":null,"ir_depth":0.0,"ir_brightness":0.0,"pitch":0.0}"#;
        let scan: FaceScan = serde_json::from_str(old).unwrap();
        assert_eq!(scan.captured_at, None);
        assert_eq!(serde_json::to_string(&scan).unwrap(), old);

        let mut e = sample();
        let before = serialize_enrollment(&e, None).unwrap();
        assert!(!String::from_utf8_lossy(&before).contains("captured_at"));
        assert_eq!(
            serialize_enrollment(&deserialize_enrollment(&before, None).unwrap(), None).unwrap(),
            before,
            "an undated enrollment rewrites to the same bytes"
        );
        e.profiles[0].scans[0].captured_at = Some(1_790_000_000);
        for key in [None, Some(crypto::generate_key())] {
            let key = key.as_ref().map(|key| key.as_slice());
            let bytes = serialize_enrollment(&e, key).unwrap();
            let back = deserialize_enrollment(&bytes, key).unwrap();
            assert_eq!(back.profiles[0].scans[0].captured_at, Some(1_790_000_000));
        }
        assert!(capture_time_now().is_some_and(|now| now > 1_700_000_000));
    }

    #[test]
    fn ir_calibration_ignores_scans_without_ir() {
        // RGB-only scans (no IR) must not count toward the floor.
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "p".into(),
            scans: vec![
                FaceScan {
                    name: "a".into(),
                    rgb: vec![0.1; 4],
                    ir: None,
                    ir_space: None,
                    embed_space: None,
                    embed_producer: None,
                    ir_center_edge_ratio: 0.0,
                    ir_brightness: 0.0,
                    pitch: 0.0,
                    captured_at: None,
                },
                scan_with_ir(1.5, 100.0),
            ],
        });
        assert!(e.ir_center_edge_ratio_floor().is_none()); // only one IR-bearing scan
    }

    #[test]
    fn default_names_fill_first_free_slot() {
        let mut e = Enrollment::new("u");
        assert_eq!(e.next_profile_name(), "Face Profile 1");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "Face Profile 1".into(),
            scans: vec![],
        });
        assert_eq!(e.next_profile_name(), "Face Profile 2");
        let p = &e.profiles[0];
        assert_eq!(p.next_scan_name(), "Face Scan 1");
    }

    // Regression: 0be786b. write_0600 is the save-path primitive that closes
    // the world-readable window: the file must be born 0600, not chmodded
    // after the bytes are already on disk.
    #[test]
    #[cfg(unix)]
    fn write_0600_creates_owner_only_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("irlume-core-w600-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.bin");
        irlume_common::write_0600(&p, b"secret bytes").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "profile files must never be world-readable");
        assert_eq!(fs::read(&p).unwrap(), b"secret bytes");
        let _ = fs::remove_dir_all(&dir);
    }

    // A fixed `<user>.json.tmp` pathname lets a stale directory or planted
    // entry block every future save. The save primitive must use create-new,
    // call-unique temporary names and publish with one durable rename.
    #[test]
    #[cfg(unix)]
    fn enrollment_publication_ignores_a_stale_fixed_temp_path() {
        let dir =
            std::env::temp_dir().join(format!("irlume-core-unique-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alice.json");
        fs::write(&path, b"old").unwrap();
        fs::create_dir(path.with_extension("json.tmp")).unwrap();

        persist_enrollment(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert!(path.with_extension("json.tmp").is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn publication_error_distinguishes_visible_replacement() {
        use irlume_common::AtomicWrite;
        let failure = || std::io::Error::other("injected storage failure");
        assert!(publication_result(Ok(AtomicWrite::Durable)).is_ok());
        let before = publication_result(Err(failure())).unwrap_err().to_string();
        assert!(!before.contains("published"), "{before}");
        let after = publication_result(Ok(AtomicWrite::VisibleNotDurable(failure())))
            .unwrap_err()
            .to_string();
        assert!(after.contains("published"), "{after}");
        assert!(after.contains("durability"), "{after}");
    }

    #[test]
    fn replacement_reuses_key_and_preserves_state_on_key_failure() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-replacement-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("template-keys")).unwrap();
        fs::create_dir_all(dir.join("recovery")).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        let mut old = sample();
        old.user = "replacement-test".into();
        let key = vec![7u8; 32]; // Synthetic, never sealed against a real TPM.
        let path = profile_path(&old.user);
        let key_path = template_key::key_path(&old.user);
        let recovery_path = dir.join("recovery/replacement-test.json");
        let before = serialize_enrollment(&old, Some(&key)).unwrap();
        fs::write(&path, &before).unwrap();
        fs::write(&key_path, b"synthetic sealed key").unwrap();
        fs::write(&recovery_path, b"synthetic recovery").unwrap();
        let mut replacement = sample();
        replacement.user = old.user.clone();
        replacement.profiles[0].name = "Replacement".into();

        // Exercise the same lock, key selection, encryption and publication as
        // save_replacement; replace only the real TPM operation.
        let err = save_with_key(&replacement, |user, account| {
            replacement_key(
                user,
                account,
                |_, _| {
                    Err(irlume_common::Error::Policy(
                        "injected unseal failure".into(),
                    ))
                },
                no_move,
                |_, _| panic!("an existing key must not be replaced"),
            )
        })
        .unwrap_err();
        assert!(err.to_string().contains("injected unseal failure"));
        assert_eq!(fs::read(&path).unwrap(), before);

        save_with_key(&replacement, |user, account| {
            replacement_key(
                user,
                account,
                |_, _| Ok(Zeroizing::new(key.clone())),
                no_move,
                |_, _| panic!("an existing key must not be replaced"),
            )
        })
        .unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .get("enc")
            .is_some());
        assert_eq!(
            deserialize_enrollment(&bytes, Some(&key)).unwrap().profiles[0].name,
            "Replacement"
        );
        assert_eq!(fs::read(&key_path).unwrap(), b"synthetic sealed key");
        assert_eq!(fs::read(&recovery_path).unwrap(), b"synthetic recovery");

        // Even with no key file, an encrypted enrollment cannot enter the
        // first-save/plaintext fallback path. The real missing-key gate is
        // safe to call: it refuses before touching the TPM.
        fs::remove_file(&key_path).unwrap();
        assert!(save_with_key(&old, |user, account| replacement_key(
            user,
            account,
            template_key::load_key_unmoved_as,
            template_key::move_kept_key,
            |_, _| panic!("an encrypted store must not generate a new key"),
        ))
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!key_path.exists());
        assert_eq!(fs::read(&recovery_path).unwrap(), b"synthetic recovery");
        // First enrollment and a plaintext store without a sealed key retain
        // the existing first-save policy, represented here by a no-TPM result.
        for plaintext_exists in [true, false] {
            if plaintext_exists {
                fs::write(&path, serialize_enrollment(&old, None).unwrap()).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
            save_with_key(&replacement, |user, account| {
                replacement_key(
                    user,
                    account,
                    |_, _| panic!("there is no existing key to unseal"),
                    no_move,
                    |_, _| Ok(None),
                )
            })
            .unwrap();
            assert_eq!(
                deserialize_enrollment(&fs::read(&path).unwrap(), None)
                    .unwrap()
                    .profiles[0]
                    .name,
                "Replacement"
            );
        }
        std::env::remove_var("IRLUME_STATE_DIR");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replacement_rejects_unknown_version_before_key_selection_and_preserves_state() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir =
            std::env::temp_dir().join(format!("irlume-replacement-version-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        let before = br#"{"version":4,"enc":"future ciphertext"}"#;

        for (user, has_key) in [("with-key", true), ("without-key", false)] {
            let path = profile_path(user);
            fs::write(&path, before).unwrap();
            if has_key {
                let key_path = template_key::key_path(user);
                fs::create_dir_all(key_path.parent().unwrap()).unwrap();
                fs::write(key_path, b"synthetic sealed key").unwrap();
            }
            let mut replacement = sample();
            replacement.user = user.into();

            let error = save_with_key(&replacement, |user, account| {
                replacement_key(
                    user,
                    account,
                    |_, _| panic!("unknown versions must be rejected before loading a key"),
                    no_move,
                    |_, _| panic!("unknown versions must be rejected before creating a key"),
                )
            })
            .unwrap_err();
            assert!(matches!(
                error,
                irlume_common::Error::Protocol(message)
                    if message.contains("unsupported encrypted enrollment version")
            ));
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        std::env::remove_var("IRLUME_STATE_DIR");
        fs::remove_dir_all(dir).unwrap();
    }

    // Regression: 0be786b. save() used fs::write straight onto the profile
    // path: a crash mid-write left a truncated profile and the umask window
    // made it briefly world-readable. The fix writes a 0600 temp file and
    // renames it in, so a failed save leaves the existing profile untouched
    // and a successful one leaves no temp residue.
    #[test]
    #[cfg(unix)]
    fn save_writes_temp_then_rename_and_survives_a_failed_save() {
        use std::os::unix::fs::PermissionsExt;
        // See the sibling test: this one writes through save() and then stats
        // profile_path(), two reads of the same process-global. Without the
        // lock a concurrent test that repoints IRLUME_STATE_DIR makes the stat
        // look for a file under a directory nothing wrote to, which surfaces
        // as a NotFound unwrap far from the cause.
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The no-TPM plaintext path is the one exercisable in a unit test; on
        // a box with /dev/tpm* present, save() would try to seal a real key.
        if crate::template_key::tpm_available() {
            eprintln!("skipping: TPM present; save() would touch real hardware");
            return;
        }
        let dir = std::env::temp_dir().join(format!("irlume-core-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);

        let mut e = sample();
        e.user = "atomic-save-test".into();
        save(&e).unwrap();
        let path = profile_path(&e.user);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            !path.with_extension("json.tmp").exists(),
            "a successful save must leave no temp file behind"
        );
        let before = fs::read(&path).unwrap();

        // Simulated failure: the dir refuses new files, so the temp file
        // cannot be created. The old in-place fs::write would still open the
        // (writable) profile file and replace it; temp+rename must instead
        // fail cleanly and leave the previous profile byte-for-byte intact.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::write(dir.join("probe"), b"x").is_ok() {
            // Running with CAP_DAC_OVERRIDE (root/container): the simulation
            // cannot bite; restore and bail rather than assert a non-failure.
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            std::env::remove_var("IRLUME_STATE_DIR");
            let _ = fs::remove_dir_all(&dir);
            eprintln!("skipping failure phase: dir permissions not enforced here");
            return;
        }
        let mut e2 = e.clone();
        e2.require_eyes_open = true;
        assert!(
            save(&e2).is_err(),
            "save must fail when the temp file cannot be created"
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "a failed save must not disturb the existing profile"
        );
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_ir_counts_as_stale_and_counts_partition_the_scans() {
        let ir_scan = |name: &str, space: Option<&str>| FaceScan {
            name: name.into(),
            rgb: vec![0.0; 4],
            ir: Some(vec![0.0; 4]),
            ir_space: space.map(String::from),
            embed_space: None,
            embed_producer: None,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
            captured_at: None,
        };
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "P".into(),
            scans: vec![
                ir_scan("adapter-era", Some("adapter:deadbeef0123")),
                ir_scan("fresh", Some("raw")),
                ir_scan("legacy-untagged", None),
            ],
        });
        // The upgrade-outage notice keys off this split: stale>0 AND usable==0.
        assert_eq!(e.stale_ir_scans("raw"), 2);
        assert_eq!(e.usable_ir_scans("raw"), 1);
        // Everything stale, nothing usable -> notice.
        e.profiles[0].scans.retain(|s| s.name == "adapter-era");
        assert_eq!(e.stale_ir_scans("raw"), 1);
        assert_eq!(e.usable_ir_scans("raw"), 0);
        // An RGB-only scan (no ir) counts for neither side.
        e.profiles[0].scans.push(FaceScan {
            ir: None,
            ..ir_scan("rgb-only", None)
        });
        assert_eq!(e.usable_ir_scans("raw"), 0);
    }

    #[test]
    fn store_is_encrypted_distinguishes_absent_shape_and_unreadable() {
        // Held across the whole test: every assertion reads a path derived
        // from IRLUME_STATE_DIR (same pattern as the retag-marker test).
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-enc-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);

        // Absent: Ok(None), the "not enrolled" answer.
        assert_eq!(store_is_encrypted("absent").unwrap(), None);

        // Plaintext JSON: Ok(Some(false)) — the synchronous pre-camera path.
        fs::write(dir.join("plain.json"), br#"{"user":"plain"}"#).unwrap();
        assert_eq!(store_is_encrypted("plain").unwrap(), Some(false));

        // Encrypted envelope: Ok(Some(true)) — detection is the `enc` field.
        fs::write(dir.join("sealed.json"), br#"{"version":3,"enc":"AAAA"}"#).unwrap();
        assert_eq!(store_is_encrypted("sealed").unwrap(), Some(true));

        for (user, version) in [("zero", 0), ("future", ENC_ENVELOPE_VERSION + 1)] {
            fs::write(
                dir.join(format!("{user}.json")),
                format!(r#"{{"version":{version},"enc":"AAAA"}}"#),
            )
            .unwrap();
            assert!(matches!(
                store_is_encrypted(user),
                Err(irlume_common::Error::Protocol(message))
                    if message.contains("unsupported encrypted enrollment version")
            ));
        }

        // Unparseable bytes read as plaintext so the FULL load reports the
        // real parse error instead of this probe.
        fs::write(dir.join("garbage.json"), b"\x00not json").unwrap();
        assert_eq!(store_is_encrypted("garbage").unwrap(), Some(false));

        // A store that exists but cannot be read is an ERROR, not "absent":
        // collapsing it to None would deny "not enrolled" where the
        // caller's load reports an error (and the password fallback).
        fs::create_dir(dir.join("locked.json")).unwrap();
        assert!(store_is_encrypted("locked").is_err());

        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(test)]
    mod sudo_state_dir_tests {
        use super::*;

        #[test]
        fn sudo_with_env_keep_home_resolves_to_the_system_state_dir() {
            // The pure decision: root euid + the invoking user's HOME is the
            // `sudo irlume` env_keep shape and must NOT use $HOME.
            assert!(privileged_with_foreign_home(0, "/home/wisbfime"));
            // Root's own home is legitimate.
            assert!(!privileged_with_foreign_home(0, "/root"));
            // Unprivileged processes (the dev fallback's actual audience) are
            // never the sudo shape, whatever HOME is.
            assert!(!privileged_with_foreign_home(1000, "/home/wisbfime"));
        }
    }
}
