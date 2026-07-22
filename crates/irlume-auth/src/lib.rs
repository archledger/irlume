// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Shared authentication orchestration: the one place the security-critical
//! pipeline lives. Both the CLI and the `irlumed` daemon drive this.
//!
//! Flow: capture RGB + IR (firing the IR emitter) → detect → align → embed (RGB)
//! and run the liveness gate on the cross-spectrum signals → on Live, match the
//! embedding against the user's enrolled templates at the fixed threshold.

use irlume_liveness::{LivenessGate, Signals, Verdict};
use irlume_vision::{align, Adapter, Detection, Detector, Embedder, Landmarks5, EMBED_DIM};

/// Auto-select the RGB+IR camera pair (built-in or external Hello webcam).
/// Re-exported so the daemon can pick devices without depending on the camera
/// crate directly. See [`irlume_camera::select_pair`].
pub use irlume_camera::{capabilities, select_pair};
/// IR-emitter auto-setup (integrated linux-enable-ir-emitter), re-exported for
/// the daemon. See [`irlume_camera::setup_ir_emitter`].
pub use irlume_camera::{ensure_ir_emitter, list_ir_controls, setup_ir_emitter};

/// Loaded models + camera device selection. Build once, reuse per request.
pub struct Engine {
    det: Detector,
    emb: Embedder,
    /// Optional IR domain-adaptation MLP (applied to IR embeddings in the dark).
    ir_adapter: Option<Adapter>,
    /// Embedding space IR probes (and new IR scans) live in: `"raw"` without an
    /// adapter, else `"adapter:<sha256 prefix>"` of the loaded adapter file.
    /// Stored on every new scan and matched against at verify, so an adapter
    /// swap/removal degrades to "re-enroll" instead of scoring across spaces.
    ir_space: String,
    /// Optional MediaPipe FaceMesh: dense landmarks for the passive EAR blink
    /// liveness (ADR-0002). Loaded iff the model file is present; `None` disables
    /// the opt-in passive-liveness gate (it can't run without landmarks).
    mesh: Option<irlume_vision::FaceMesh>,
    /// Optional BlazeFace short-range RESCUE detector: runs only when YuNet
    /// finds no face (saturated outdoor backgrounds; 2026-07-15 bench: 96.9%
    /// vs YuNet's 76.9% on the sunlight walking bursts). Needs `mesh` to
    /// refine its coarse box into alignment landmarks.
    blaze: Option<irlume_vision::BlazeRescue>,
    /// Optional third-party PAD cue (opt-in via `irlume models`, catalog in
    /// `irlume_common::thirdparty`): (classifier, threshold, catalog name).
    /// Consulted DENY-ONLY on the lit IR strobe frame; it may downgrade a
    /// Live verdict to Spoof, never the reverse (see `thirdparty_downgrades`).
    tp_pad: Option<(irlume_vision::PadIr, f32, String)>,
    gate: LivenessGate,
    rgb_dev: String,
    ir_dev: String,
    /// Smart-Auto: true when a real RGB+IR Hello camera is present. False = an
    /// RGB-only device → face runs in CONVENIENCE tier (lock-screen unlock only,
    /// RGB-only liveness, never releases credentials / logs in / elevates).
    ir_available: bool,
}

/// Assurance tier of this engine, derived from the available camera hardware.
pub use irlume_core::biopolicy::Tier;

/// What one capture+assessment produced.
pub struct Assessment {
    pub verdict: Verdict,
    pub reason: String,
    /// RGB-face embedding (visible light), the primary identity.
    pub embedding: Option<[f32; EMBED_DIM]>,
    /// IR-face embedding (for dark operation), if a face was found in IR:
    /// adapter-transformed when the IR adapter is loaded (the deployed adapter
    /// contract is 512→512, see [`Engine::ir_dim`]), else raw 512-D.
    pub ir_embedding: Option<Vec<f32>>,
    pub signals: Signals,
    pub ir_depth: f32,
    pub ir_brightness: f32,
    /// Both eyes read open (IR corneal-glint heuristic). Used only when a profile
    /// opts into the require-eyes-open gate. `false` if eyes couldn't be verified.
    pub eyes_open: bool,
    /// P(fake) from the opt-in third-party PAD cue, when one is loaded and an
    /// IR face was present. Deny-only: consulted by both the cross-spectrum
    /// verdict (in `assess_full`) and the dark path.
    pub thirdparty_fake: Option<f32>,
}

/// The authentication decision for a user.
// Debug is diagnostic-only (tests, dlog); derives add no behavior.
#[derive(Debug)]
pub struct Outcome {
    pub granted: bool,
    pub live: bool,
    pub score: f32,
    pub reason: String,
    /// Typed class of this outcome, set where the outcome is built, so
    /// [`presence_retryable`] branches on a field instead of parsing the
    /// `reason` prose. Engine-internal: the daemon maps `Outcome` to the wire
    /// `Response` field by field, and `kind` never crosses the socket.
    pub kind: OutcomeKind,
}

/// Grant/failure class of an [`Outcome`]. The
/// `grace_retries_only_presence_failures` test pins the kind assigned to every
/// reason shape the engine produces against the legacy prefix contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// Access granted.
    Granted,
    /// No usable face in frame (nobody there, or the detector missed).
    NoFace,
    /// Liveness gate returned Uncertain (framing/quality, not an attack).
    Uncertain,
    /// Spoof verdict raised only because RGB saw a face and IR did not. Both a
    /// screen attack and a genuine user mid-settle produce it, so it is the
    /// one Spoof class the grace window may retry (see [`presence_retryable`]).
    SpoofNoIrFace,
    /// Any other Spoof verdict (flat/2D, PAD cue): a caught attack.
    Spoof,
    /// A real match verdict landed below the threshold.
    BelowThreshold,
    /// Every other refusal: pre-camera policy/state denials, camera-binding
    /// mismatches, challenge-gate failures.
    OtherDeny,
}

impl Outcome {
    /// Refusal with no live face: `live: false, score: 0.0`.
    fn deny(kind: OutcomeKind, reason: impl Into<String>) -> Self {
        Self {
            granted: false,
            live: false,
            score: 0.0,
            reason: reason.into(),
            kind,
        }
    }

    /// Refusal of a live face that produced a real match score.
    fn deny_live(kind: OutcomeKind, score: f32, reason: impl Into<String>) -> Self {
        Self {
            granted: false,
            live: true,
            score,
            reason: reason.into(),
            kind,
        }
    }

    /// Grant: always live, kind [`OutcomeKind::Granted`].
    fn grant(score: f32, reason: impl Into<String>) -> Self {
        Self {
            granted: true,
            live: true,
            score,
            reason: reason.into(),
            kind: OutcomeKind::Granted,
        }
    }
}

/// The result of a 1:N identification ("who is this?"). `user`/`profile` are set
/// only on a live, above-threshold match against some enrolled face.
// Debug is diagnostic-only (tests, dlog); derives add no behavior.
#[derive(Debug)]
pub struct IdentifyOutcome {
    pub user: Option<String>,
    pub profile: Option<String>,
    pub score: f32,
    pub live: bool,
    pub reason: String,
}

/// One live enrollment scan, as captured by [`Engine::capture_scans`].
struct CapturedScan {
    /// RGB-face embedding, the primary identity template.
    rgb: Vec<f32>,
    /// IR-face embedding, when an IR face was captured (engine `ir_space`).
    ir: Option<Vec<f32>>,
    /// IR center/edge depth ratio at capture (feeds the per-user depth floor).
    depth: f32,
    /// Mean IR face brightness at capture (0-255 grey).
    brightness: f32,
    /// Head pitch fraction at capture (calibrates this user's pitch neutral).
    pitch: f32,
}

/// Presence grace window after the consent gesture, milliseconds, for the
/// login and lock-screen path. The user pressed Enter (usually already in
/// frame), so this is a "keep looking" window that tolerates walking up /
/// settling before it gives up to the password (~15s, roughly 10 capture
/// attempts at ~1.1-1.5s each). It retries ONLY presence failures (no matcher
/// ran), so a longer window costs no false-accept resistance. Override with
/// `IRLUME_GRACE_MS` (0 = legacy one-shot).
pub const GRACE_WINDOW_MS: u64 = 15000;
/// Shorter window for `sudo` (and `su`): at a terminal the user is already
/// looking at the screen, so a match lands on the first attempt; if they look
/// away they want a quick drop to the password prompt, not a long freeze.
pub const SUDO_GRACE_WINDOW_MS: u64 = 5000;

/// True for the sudo/su family of PAM services, which take the shorter window.
fn is_sudo_like(service: &str) -> bool {
    matches!(
        service,
        "sudo" | "sudo-i" | "su" | "su-l" | "runuser" | "runuser-l"
    )
}

/// Grace window for a given PAM service. `IRLUME_GRACE_MS` overrides everything
/// (testing); otherwise sudo/su and polkit get the short window (the user is
/// already at the machine, and the KDE polkit agent re-runs the stack up to 3
/// times on failure, so a long window would just hold its dialog busy) and
/// every login/lock service (and an unknown/absent service) gets the full
/// login window.
fn grace_window_ms(service: Option<&str>) -> u64 {
    if let Some(v) = std::env::var("IRLUME_GRACE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return v;
    }
    match service {
        Some(s) if is_sudo_like(s) || s == "polkit-1" || s == "polkit" => SUDO_GRACE_WINDOW_MS,
        _ => GRACE_WINDOW_MS,
    }
}

/// Escape hatch for the forced polkit blink gate: default ON; disable with
/// `IRLUME_POLKIT_GESTURE=0` or `polkit_gesture=0` in settings.conf. Verify
/// stays face-gated either way; this only controls the extra blink.
fn consent_gesture_enabled() -> bool {
    let falsy = |v: &str| matches!(v.trim(), "0" | "false" | "no" | "off");
    if let Ok(v) = std::env::var("IRLUME_POLKIT_GESTURE") {
        return !falsy(&v);
    }
    !irlume_common::config::read_kv("settings.conf", "polkit_gesture").is_some_and(|v| falsy(&v))
}

/// Whether this PAM service forces the passive blink gate even without the
/// per-enrollment opt-in (polkit prompts; see
/// `biopolicy::requires_consent_gesture`). Unlike the opt-in flag, a forced
/// gate FAILS CLOSED when it can't run (no IR / no mesh model). Computed per
/// [`Engine::authenticate`] call and threaded down explicitly, so a polkit
/// verify can never leak the flag into a later login/lock verify.
fn forced_consent_for(service: Option<&str>) -> bool {
    service.is_some_and(|s| {
        irlume_core::biopolicy::requires_consent_gesture(irlume_core::biopolicy::classify(
            s,
            irlume_core::biopolicy::SessionState::Cold,
        )) && consent_gesture_enabled()
    })
}

/// True for a presence-class failure: the attempt never reached a match
/// verdict because no usable face was in frame (absent, off-angle, or missing
/// in one spectrum).
///
/// These are the ONLY outcomes the grace window may retry: they are
/// FAR-neutral (no matcher ran) and give an attacker nothing. The daemon
/// throttle must NOT count them as failed attempts either. A real rejection
/// (wrong person, a caught spoof that produced a live face) is NOT
/// presence-retryable, and a below-threshold MATCH is never retried (that
/// would multiply FAR).
///
/// The `no face in IR` Spoof ([`OutcomeKind::SpoofNoIrFace`]) is included
/// deliberately. It fires when RGB sees a face but IR does not: BOTH a
/// screen/print attack (no 850nm return) AND a genuine user mid-settle (IR
/// field/timing hasn't caught them yet). Retrying is safe against the attack:
/// a real screen never grows an IR face, so it keeps producing this Spoof
/// until the window expires and the denial stands; a genuine user's IR
/// catches up within a retry or two. Live-found 2026-07-15: without this,
/// settling into frame can be denied on the transient mismatch. Other Spoof
/// reasons (flat/depth/2D) are NOT retried.
pub fn presence_retryable(o: &Outcome) -> bool {
    matches!(
        o.kind,
        OutcomeKind::NoFace | OutcomeKind::Uncertain | OutcomeKind::SpoofNoIrFace
    )
}

/// Kind of a non-Live cross-spectrum gate verdict on the RGB primary path.
/// The `no face in IR` reason is singled out because it is the retryable
/// RGB-yes/IR-no transient; the prefix is pinned against the string
/// irlume-liveness produces by `grace_retries_only_presence_failures`.
fn liveness_deny_kind(verdict: Verdict, reason: &str) -> OutcomeKind {
    match verdict {
        Verdict::Uncertain => OutcomeKind::Uncertain,
        Verdict::Spoof if reason.starts_with("no face in IR") => OutcomeKind::SpoofNoIrFace,
        Verdict::Spoof => OutcomeKind::Spoof,
        // Callers only classify rejections; a Live verdict never reaches here.
        Verdict::Live => OutcomeKind::OtherDeny,
    }
}

/// Calibration-aware IR match result (see [`ir_match_in`]).
struct IrMatch {
    best: f32,
    best_who: String,
    n_templates: usize,
    /// Best per-profile calibrated-centroid score, only from profiles with a
    /// fitted calibration under a raw pipeline: (score, profile name).
    centroid: Option<(f32, String)>,
}

/// IR matching across profiles, calibration-aware. Per profile: when a
/// fitted calibration exists (and no global adapter is loaded), both the
/// probe and that profile's templates are calibrated before scoring, and the
/// calibrated template CENTROID is scored too, the mean-template protocol
/// the 2026-07-15 prototype validated at the BASE threshold (a single mean
/// template carries no best-of-N FAR inflation).
fn ir_match_in(
    space: &str,
    adapter_loaded: bool,
    enr: &irlume_core::storage::Enrollment,
    probe: &[f32],
) -> IrMatch {
    let mut m = IrMatch {
        best: f32::NEG_INFINITY,
        best_who: String::new(),
        n_templates: 0,
        centroid: None,
    };
    for p in &enr.profiles {
        let tmpls: Vec<&[f32]> = p
            .scans
            .iter()
            .filter_map(|s| {
                let ir = s.ir.as_ref()?;
                if ir.len() != probe.len() {
                    return None;
                }
                match &s.ir_space {
                    Some(sp) if sp != space => None,
                    _ => Some(ir.as_slice()),
                }
            })
            .collect();
        if tmpls.is_empty() {
            continue;
        }
        m.n_templates += tmpls.len();
        let calib = if adapter_loaded {
            None
        } else {
            p.ir_calib.as_ref()
        };
        let cprobe = calib.and_then(|c| c.apply(probe));
        if let (Some(c), Some(cprobe)) = (calib, &cprobe) {
            let mut centroid = vec![0.0f32; probe.len()];
            let mut used = 0usize;
            for t in &tmpls {
                let Some(ct) = c.apply(t) else { continue };
                let s = align::cosine(cprobe, &ct);
                if s > m.best {
                    m.best = s;
                    m.best_who = p.name.clone();
                }
                for (a, b) in centroid.iter_mut().zip(&ct) {
                    *a += b;
                }
                used += 1;
            }
            if used > 0 {
                let norm = centroid.iter().map(|v| v * v).sum::<f32>().sqrt() + 1e-9;
                for v in centroid.iter_mut() {
                    *v /= norm;
                }
                let cs = align::cosine(cprobe, &centroid);
                if m.centroid.as_ref().is_none_or(|(s, _)| cs > *s) {
                    m.centroid = Some((cs, p.name.clone()));
                }
            }
        } else {
            for t in &tmpls {
                let s = align::cosine(probe, t);
                if s > m.best {
                    m.best = s;
                    m.best_who = p.name.clone();
                }
            }
        }
    }
    m
}

/// Deny-only rule for the opt-in third-party PAD cue: fires (downgrades to
/// Spoof) ONLY when the built-in gate already said Live AND the cue's P(fake)
/// clears the threshold. A non-Live verdict is never touched, and an absent
/// score never fires, so the cue cannot rescue an attack or mask a gate
/// rejection; enabling it can only tighten.
pub fn thirdparty_downgrades(verdict: Verdict, p_fake: Option<f32>, threshold: f32) -> bool {
    verdict == Verdict::Live && p_fake.is_some_and(|p| p >= threshold)
}

/// Highest-scoring detection: the face every pipeline stage keys on when a
/// frame holds more than one.
fn top_detection(faces: &[Detection]) -> Option<&Detection> {
    faces.iter().max_by(|a, b| a.score.total_cmp(&b.score))
}

impl Engine {
    pub fn load(det_path: &str, model_path: &str) -> irlume_common::Result<Self> {
        Ok(Self {
            det: Detector::load_from_file(det_path)?,
            emb: Embedder::load_from_file(model_path)?,
            ir_adapter: None,
            ir_space: "raw".into(),
            mesh: None,
            blaze: None,
            tp_pad: None,
            gate: LivenessGate::new(),
            rgb_dev: irlume_camera::DEFAULT_RGB_DEVICE.into(),
            ir_dev: irlume_camera::DEFAULT_IR_DEVICE.into(),
            ir_available: irlume_camera::capabilities().ir_pair,
        })
    }

    /// Assurance tier from the hardware: `Secure` with a real RGB+IR camera,
    /// `Convenience` on an RGB-only device.
    pub fn tier(&self) -> Tier {
        if self.ir_available {
            Tier::Secure
        } else {
            Tier::Convenience
        }
    }

    /// Whether a real IR+RGB Hello camera is present (full face auth available).
    pub fn ir_available(&self) -> bool {
        self.ir_available
    }

    pub fn with_devices(mut self, rgb: &str, ir: &str) -> Self {
        self.rgb_dev = rgb.into();
        self.ir_dev = ir.into();
        self
    }

    /// The selected IR camera device path (for emitter auto-setup).
    pub fn ir_device(&self) -> &str {
        &self.ir_dev
    }

    /// The selected RGB camera device path.
    pub fn rgb_device(&self) -> &str {
        &self.rgb_dev
    }

    /// Switch the active camera pair at runtime (TUI camera picker). The next
    /// capture uses the new devices.
    pub fn set_devices(&mut self, rgb: &str, ir: &str) {
        self.rgb_dev = rgb.into();
        self.ir_dev = ir.into();
    }

    /// Load the IR domain-adaptation adapter (improves dark recognition). If the
    /// file is absent this is a no-op (raw IR embeddings are used).
    pub fn with_ir_adapter(mut self, path: &str) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.ir_adapter = Some(Adapter::load_from_file(path)?);
            let bytes = std::fs::read(path)
                .map_err(|e| irlume_common::Error::Io(format!("{path}: {e}")))?;
            let digest = irlume_common::thirdparty::sha256_hex(&bytes);
            self.ir_space = format!("adapter:{}", &digest[..12]);
        }
        Ok(self)
    }

    pub fn has_ir_adapter(&self) -> bool {
        self.ir_adapter.is_some()
    }

    /// The IR embedding space this engine produces and matches in.
    pub fn ir_space(&self) -> &str {
        &self.ir_space
    }

    /// Dimensionality of the IR embeddings this engine emits. The recognizer
    /// emits 512-D and the deployed adapter contract is 512→512; an adapter
    /// with a different output width must change this too (the per-scan dim
    /// check in `ir_scans_for` quarantines templates either way).
    pub fn ir_dim(&self) -> usize {
        irlume_vision::EMBED_DIM
    }

    /// Fit (or refresh) a profile's per-enrollment IR calibration (ADR-0004)
    /// from its own scan pairs. Raw space only: with a global adapter loaded
    /// the stored IR embeddings are adapter-space, and the calibration stays
    /// `None` (matching then behaves exactly as before the feature).
    fn refit_profile_calib(&self, prof: &mut irlume_core::storage::FaceProfile) {
        if self.ir_adapter.is_some() {
            return;
        }
        let dim = self.ir_dim();
        let (mut ir_rows, mut rgb_rows) = (Vec::new(), Vec::new());
        for s in &prof.scans {
            let Some(ir) = &s.ir else { continue };
            if ir.len() != dim || s.rgb.len() != dim {
                continue;
            }
            if matches!(&s.ir_space, Some(sp) if sp != &self.ir_space) {
                continue;
            }
            ir_rows.push(ir.clone());
            rgb_rows.push(s.rgb.clone());
        }
        prof.ir_calib = irlume_core::calib::fit(&ir_rows, &rgb_rows);
        if let Some(c) = &prof.ir_calib {
            irlume_common::dlog!(
                "calib: fitted '{}' from {} scan pairs",
                prof.name,
                c.fitted_pairs
            );
        }
    }

    /// Method wrapper over [`ir_match_in`], bound to the engine's space and
    /// adapter state.
    fn ir_match(&self, enr: &irlume_core::storage::Enrollment, probe: &[f32]) -> IrMatch {
        ir_match_in(&self.ir_space, self.ir_adapter.is_some(), enr, probe)
    }

    /// Load MediaPipe FaceMesh for the passive EAR blink liveness (ADR-0002). If
    /// the file is absent this is a no-op; the opt-in passive gate then can't run
    /// and is skipped (logged), so face auth keeps working.
    pub fn with_mesh(mut self, path: &str) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.mesh = Some(irlume_vision::FaceMesh::load_from_file(path)?);
        }
        Ok(self)
    }

    /// Load the BlazeFace short-range rescue detector (improves detection on
    /// saturated outdoor frames). No-op if the file is absent.
    pub fn with_blaze_rescue(mut self, path: &str) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.blaze = Some(irlume_vision::BlazeRescue::load_from_file(path)?);
        }
        Ok(self)
    }

    pub fn has_blaze_rescue(&self) -> bool {
        self.blaze.is_some()
    }

    /// Load an opt-in third-party PAD classifier (deny-only cue on the lit IR
    /// frame). No-op if the file is absent, so a deleted model degrades to the
    /// built-in gate, never to a startup failure.
    pub fn with_thirdparty_pad(
        mut self,
        path: &str,
        threshold: f32,
        name: &str,
    ) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.tp_pad = Some((
                irlume_vision::PadIr::load_from_file(path)?,
                threshold,
                name.to_string(),
            ));
        }
        Ok(self)
    }

    pub fn has_thirdparty_pad(&self) -> bool {
        self.tp_pad.is_some()
    }

    /// Catalog name of the loaded third-party PAD cue, if any.
    pub fn thirdparty_pad_name(&self) -> Option<&str> {
        self.tp_pad.as_ref().map(|(_, _, n)| n.as_str())
    }

    /// Detection rescue (cascade stage 2): when YuNet returns no face, try
    /// BlazeFace and refine its coarse box into the 5 alignment landmarks
    /// with FaceMesh (BlazeFace has no mouth corners and its eyes measured
    /// 0.087 NME vs YuNet's 0.053; never align from its own keypoints).
    /// Returns a Detection shaped exactly like YuNet's, or None when either
    /// optional model is absent or no face clears the threshold.
    fn rescue_detect(&mut self, view: &align::RgbView<'_>, tag: &str) -> Option<Detection> {
        let blaze = self.blaze.as_mut()?;
        let mesh = self.mesh.as_mut()?;
        let (bbox, score) = blaze.detect_top(view).ok().flatten()?;
        let lm = mesh.landmarks(view, &bbox, 0.25).ok()?;
        if lm.len() < irlume_vision::MESH_N {
            return None;
        }
        let center = |idx: &[usize; 6]| {
            let (mut x, mut y) = (0.0f32, 0.0f32);
            for &i in idx {
                x += lm[i].0;
                y += lm[i].1;
            }
            (x / 6.0, y / 6.0)
        };
        let e1 = center(&irlume_vision::EAR_LEFT);
        let e2 = center(&irlume_vision::EAR_RIGHT);
        let (le, re) = if e1.0 <= e2.0 { (e1, e2) } else { (e2, e1) };
        let (m1, m2) = (lm[61], lm[291]);
        let (ml, mr) = if m1.0 <= m2.0 { (m1, m2) } else { (m2, m1) };
        irlume_common::dlog!("detect({tag}): blaze rescue fired (score {score:.2})");
        Some(Detection {
            bbox,
            score,
            landmarks: [le, re, lm[1], ml, mr],
        })
    }

    pub fn has_mesh(&self) -> bool {
        self.mesh.is_some()
    }

    /// One capture: RGB+IR → liveness verdict + (if a face) its embedding.
    /// Capture + assess, choosing the path from the hardware: full cross-spectrum
    /// (RGB+IR) when an IR camera is present, else RGB-only (convenience).
    pub fn assess(&mut self) -> irlume_common::Result<Assessment> {
        if self.ir_available {
            self.assess_full()
        } else {
            self.assess_rgb_only()
        }
    }

    /// RGB-only capture + algorithmic (no-IR) liveness, the convenience-tier
    /// path for devices without an IR camera. Anti-spoof here is DETERRENT-grade
    /// (well-lit + frontal + screen/glare heuristic), which is why this tier is
    /// limited to lock-screen unlock and never releases credentials.
    fn assess_rgb_only(&mut self) -> irlume_common::Result<Assessment> {
        let rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev)?;
        let rgb_view = align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        };
        let rgb_faces = self.det.detect(&rgb_view)?;
        let rgb_top = top_detection(&rgb_faces).cloned();
        let (rgb_brightness, rgb_specular) = rgb_top
            .as_ref()
            .map(|f| rgb_luma_stats(&rgb.data, rgb.width, rgb.height, &f.bbox))
            .unwrap_or((0.0, 0.0));
        // 2D-FFT moiré / pixel-grid cue (screen-replay deterrent).
        let rgb_moire = rgb_top
            .as_ref()
            .map(|f| {
                irlume_vision::moire::moire_score(&irlume_vision::moire::face_gray_n(
                    &rgb.data, rgb.width, rgb.height, &f.bbox,
                ))
            })
            .unwrap_or(0.0);
        let pose = rgb_top
            .as_ref()
            .map(|f| irlume_vision::head_pose(&f.landmarks));
        let signals = Signals {
            rgb_face: rgb_top.as_ref().map(|f| irlume_liveness::FaceBox {
                cx: (f.bbox[0] + f.bbox[2]) / 2.0 / rgb.width as f32,
                cy: (f.bbox[1] + f.bbox[3]) / 2.0 / rgb.height as f32,
                score: f.score,
            }),
            ir_face: None,
            ir_face_brightness: 0.0,
            ir_center_edge_ratio: 0.0,
            ir_eye_glint: 0.0,
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            ir_ambient: 0.0, // RGB-only path: no IR burst to measure
            rgb_face_brightness: rgb_brightness,
            rgb_specular_frac: rgb_specular,
            rgb_moire_score: rgb_moire,
        };
        let (verdict, _cues, reason) = self.gate.evaluate_rgb_only(&signals);
        irlume_common::dlog!(
            "liveness(rgb-only): {verdict:?} ({reason}); bright={:.0} specular={:.2} moire={:.0}",
            signals.rgb_face_brightness,
            signals.rgb_specular_frac,
            signals.rgb_moire_score
        );
        let embedding = match &rgb_top {
            Some(f) => Some(
                self.emb
                    .embed_tta(&align::align_to_arcface(&rgb_view, &f.landmarks)?)?,
            ),
            None => None,
        };
        Ok(Assessment {
            verdict,
            reason,
            embedding,
            ir_embedding: None,
            signals,
            ir_depth: 0.0,
            ir_brightness: 0.0,
            eyes_open: false,
            thirdparty_fake: None,
        })
    }

    fn assess_full(&mut self) -> irlume_common::Result<Assessment> {
        // Median-denoise the RGB frame so a single blurry/over-exposed frame
        // can't false-reject a genuine user (IR is already brightest-of-burst).
        //
        // The two captures OVERLAP on separate threads: measured on the ASUS
        // built-in and the NexiGo N930W (examples/concurrency_probe.rs in
        // irlume-camera), both deliver frames concurrently, ~0.7 s (ASUS) to
        // ~1.3 s (NexiGo) faster than back-to-back. Two degradation modes are
        // handled: a HARD capture failure is retried alone just below; a
        // SILENT one (the NexiGo's RGB returns Ok but too dim for detection,
        // measured mean ~71 vs ~120 sequential, so YuNet finds no face) is
        // caught after detection by the cross-spectrum self-heal further down
        // (IR-has-a-face while RGB-does-not => recapture RGB alone). The ASUS
        // never triggers either path. `IRLUME_SEQUENTIAL_CAPTURE=1` forces
        // strict back-to-back capture (RGB, then IR only if RGB succeeded) to
        // isolate a suspected concurrency problem.
        let sequential = std::env::var("IRLUME_SEQUENTIAL_CAPTURE").is_ok_and(|v| v.trim() == "1");
        let (rgb_res, rgb_ms, ir_res, ir_ms) = if sequential {
            let t = std::time::Instant::now();
            let rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev);
            let rgb_ms = t.elapsed().as_millis();
            // Match the old short-circuit: don't fire the IR emitter after an
            // RGB fault (privacy switch, missing node); the shared retry below
            // surfaces the RGB error.
            if rgb.is_err() {
                (rgb, rgb_ms, Ok(None), 0)
            } else {
                let t = std::time::Instant::now();
                let ir = irlume_camera::capture_ir_with_stats(&self.ir_dev);
                (rgb, rgb_ms, ir.map(Some), t.elapsed().as_millis())
            }
        } else {
            std::thread::scope(|s| {
                let ir_dev = self.ir_dev.clone();
                let ir_thread = s.spawn(move || {
                    let t = std::time::Instant::now();
                    (
                        irlume_camera::capture_ir_with_stats(&ir_dev),
                        t.elapsed().as_millis(),
                    )
                });
                let t = std::time::Instant::now();
                let rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev);
                let rgb_ms = t.elapsed().as_millis();
                let (ir, ir_ms) = ir_thread.join().unwrap_or_else(|_| {
                    (
                        Err(irlume_common::Error::Hardware(
                            "IR capture thread panicked".into(),
                        )),
                        0,
                    )
                });
                (rgb, rgb_ms, ir.map(Some), ir_ms)
            })
        };
        // Retry a hard-failed side alone: with the other stream stopped, a
        // bandwidth-starved capture succeeds; a genuine fault (privacy
        // switch, missing node) fails again with the same error. Logged so a
        // silent retry can't make the timing lines below lie about a slow login.
        let mut rgb_hard_retried = false;
        let mut rgb = match rgb_res {
            Ok(f) => f,
            Err(e) => {
                irlume_common::dlog!("assess: rgb capture retry (concurrent failed: {e})");
                rgb_hard_retried = true;
                irlume_camera::capture_rgb_denoised(&self.rgb_dev)?
            }
        };
        let mut rgb_faces = self.det.detect(&align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        })?;
        let mut rgb_top = top_detection(&rgb_faces).cloned();
        irlume_common::dlog!(
            "assess: rgb {}x{} in {rgb_ms}ms, faces={} top-det={:.2}",
            rgb.width,
            rgb.height,
            rgb_faces.len(),
            rgb_top.as_ref().map(|f| f.score).unwrap_or(0.0)
        );
        if rgb_top.is_none() {
            rgb_top = self.rescue_detect(
                &align::RgbView {
                    data: &rgb.data,
                    width: rgb.width,
                    height: rgb.height,
                },
                "rgb",
            );
        }

        // `None` = sequential mode skipped IR after an RGB fault; the RGB `?`
        // above already returned, so reaching here with `None` is unreachable,
        // but capture alone rather than unwrap to stay panic-free.
        let (ir, ir_stats) = match ir_res {
            Ok(Some(f)) => f,
            Ok(None) => irlume_camera::capture_ir_with_stats(&self.ir_dev)?,
            Err(e) => {
                irlume_common::dlog!("assess: ir capture retry (concurrent failed: {e})");
                irlume_camera::capture_ir_with_stats(&self.ir_dev)?
            }
        };
        let ir_grey_rgb = irlume_camera::grey_to_rgb(&ir.data);
        let ir_view = align::RgbView {
            data: &ir_grey_rgb,
            width: ir.width,
            height: ir.height,
        };
        let ir_faces = self.det.detect(&ir_view)?;
        let mut ir_top = top_detection(&ir_faces).cloned();
        irlume_common::dlog!(
            "assess: ir {}x{} in {ir_ms}ms, faces={} top-det={:.2}",
            ir.width,
            ir.height,
            ir_faces.len(),
            ir_top.as_ref().map(|f| f.score).unwrap_or(0.0)
        );
        if ir_top.is_none() {
            let iv = align::RgbView {
                data: &ir_grey_rgb,
                width: ir.width,
                height: ir.height,
            };
            ir_top = self.rescue_detect(&iv, "ir");
        }

        // Cross-spectrum self-heal for overlapped-capture RGB dimming. Some
        // Hello modules (measured: NexiGo N930W) starve the RGB stream when
        // both are read at once: the frame arrives without error but too dim
        // for YuNet to find the face, which would silently deny to password.
        // IR is unaffected, so IR-has-a-face while RGB-does-not is the
        // degradation signature (a genuinely absent user shows no face in
        // either, so this does not fire). Recapture RGB alone on the idle
        // link. Skipped in sequential mode and if RGB was already re-fetched.
        if rgb_top.is_none() && ir_top.is_some() && !sequential && !rgb_hard_retried {
            irlume_common::dlog!(
                "assess: RGB has no face but IR does; recapturing RGB alone (dim overlapped frame?)"
            );
            rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev)?;
            rgb_faces = self.det.detect(&align::RgbView {
                data: &rgb.data,
                width: rgb.width,
                height: rgb.height,
            })?;
            rgb_top = top_detection(&rgb_faces).cloned();
            irlume_common::dlog!(
                "assess: rgb (recaptured) {}x{}, faces={} top-det={:.2}",
                rgb.width,
                rgb.height,
                rgb_faces.len(),
                rgb_top.as_ref().map(|f| f.score).unwrap_or(0.0)
            );
        }

        let fbox = |f: &Detection, w: u32, h: u32| irlume_liveness::FaceBox {
            cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
            cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
            score: f.score,
        };
        let ir_brightness = ir_top
            .as_ref()
            .map(|f| mean_in_bbox(&ir.data, ir.width, ir.height, &f.bbox))
            .unwrap_or(0.0);
        let ir_depth = ir_top
            .as_ref()
            .map(|f| center_edge_ratio(&ir.data, ir.width, ir.height, &f.bbox))
            .unwrap_or(0.0);
        // Head orientation from the RGB face landmarks (Windows-Hello-style
        // frontality gate). Defaults to frontal when there's no RGB face.
        let pose = rgb_top
            .as_ref()
            .map(|f| irlume_vision::head_pose(&f.landmarks));
        // Real RGB face luma: the cross-spectrum liveness gate does not read it,
        // but stage-2 fusion's `rgb_quality_weight` does. Hardcoding 0.0 here
        // made fusion always treat the RGB modality as pitch-dark (minimal
        // weight), collapsing the fused score toward IR regardless of actual
        // ambient light and weakening the "must fool both modalities" bound.
        // Measure it exactly as the RGB-only path does. The PAD-specific
        // moiré/specular cues stay 0.0 (the IR gate doesn't use them).
        let rgb_brightness = rgb_top
            .as_ref()
            .map(|f| rgb_luma_stats(&rgb.data, rgb.width, rgb.height, &f.bbox).0)
            .unwrap_or(0.0);
        let signals = Signals {
            rgb_face: rgb_top.as_ref().map(|f| fbox(f, rgb.width, rgb.height)),
            ir_face: ir_top.as_ref().map(|f| fbox(f, ir.width, ir.height)),
            ir_face_brightness: ir_brightness,
            ir_center_edge_ratio: ir_depth,
            ir_eye_glint: ir_top
                .as_ref()
                .map(|f| eye_glint(&ir.data, ir.width, ir.height, &f.landmarks))
                .unwrap_or(0.0),
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            ir_ambient: ir_stats.ambient_mean,
            rgb_face_brightness: rgb_brightness,
            rgb_moire_score: 0.0,
            rgb_specular_frac: 0.0,
        };
        let (verdict, _cues, reason) = self.gate.evaluate(&signals);
        // Log the cue values on PASS too; a near-miss on a genuine user is
        // invisible in the outcome line but obvious here.
        irlume_common::dlog!(
            "liveness(cross-spectrum): {verdict:?} ({reason}); ir_bright={:.0} ir_depth={:.2} glint={:.2} ambient={:.0} yaw_asym={:.2} pitch={:.2}",
            signals.ir_face_brightness, signals.ir_center_edge_ratio, signals.ir_eye_glint,
            signals.ir_ambient, signals.head_yaw_asym, signals.head_pitch_frac);
        // Opt-in third-party PAD cue: score whenever an IR face is present (the
        // `ir` frame is the brightest strobe phase, i.e. the LIT frame, which is
        // the regime the cue was measured in), so the dark path can consult the
        // result too. DENY-ONLY: it can downgrade Live to Spoof and nothing else.
        let thirdparty_fake = match (self.tp_pad.as_mut(), ir_top.as_ref()) {
            (Some((pad, _, _)), Some(f)) => match pad.p_fake(&ir_view, &f.bbox) {
                Ok(p) => Some(p),
                Err(e) => {
                    irlume_common::dlog!("thirdparty-pad: inference failed ({e}); cue skipped");
                    None
                }
            },
            _ => None,
        };
        let (verdict, reason) = if let Some((_, thr, name)) = self.tp_pad.as_ref() {
            if thirdparty_downgrades(verdict, thirdparty_fake, *thr) {
                let pf = thirdparty_fake.unwrap_or(1.0);
                irlume_common::dlog!(
                    "thirdparty-pad('{name}'): p_fake {pf:.3} >= {thr:.2}; downgrading Live to Spoof"
                );
                (
                    Verdict::Spoof,
                    format!("third-party PAD cue '{name}' flags a spoof; use your password"),
                )
            } else {
                (verdict, reason)
            }
        } else {
            (verdict, reason)
        };

        // Rebuild the view against the final RGB frame (it may have been
        // recaptured by the cross-spectrum self-heal above).
        let rgb_view = align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        };
        let embedding = match &rgb_top {
            Some(f) => {
                let chip = align::align_to_arcface(&rgb_view, &f.landmarks)?;
                Some(self.emb.embed_tta(&chip)?) // TTA flip-average (RGB only; cuts FRR)
            }
            None => None,
        };
        // IR-face embedding (for dark operation): align + embed the IR image,
        // then apply the domain-adaptation adapter if loaded.
        let ir_embedding = match &ir_top {
            Some(f) => {
                let chip = align::align_to_arcface(&ir_view, &f.landmarks)?;
                let raw = self.emb.embed(&chip)?;
                Some(match &mut self.ir_adapter {
                    Some(a) => a.apply(&raw)?,
                    None => raw.to_vec(),
                })
            }
            None => None,
        };
        // Eyes-open (IR corneal-glint heuristic), for the opt-in require-eyes-open
        // gate. Needs an IR face (the emitter lights the cornea); conservative:
        // false when it can't be verified.
        let eyes_open = ir_top
            .as_ref()
            .map(|f| both_eyes_open(&ir.data, ir.width, ir.height, &f.landmarks))
            .unwrap_or(false);
        Ok(Assessment {
            verdict,
            reason,
            embedding,
            ir_embedding,
            signals,
            ir_depth,
            ir_brightness,
            eyes_open,
            thirdparty_fake,
        })
    }

    /// Passive blink liveness (opt-in, ADR-0002): capture a short IR sequence and
    /// look for a NATURAL blink via EAR: no prompt, no deliberate action. Per frame
    /// we run FaceMesh (from the detected face crop) and take the smaller eye's EAR;
    /// [`irlume_liveness::detect_blink`] then finds a dip below the open baseline. A
    /// static print holds EAR flat and never dips. Live-validated 2026-07-01: genuine
    /// natural blink → Blinked, static vinyl banner → NoBlink.
    fn run_passive_liveness(&mut self) -> irlume_common::Result<irlume_liveness::BlinkResult> {
        // ~5s window at the raw ~15 fps rate.
        const SAMPLES: usize = 75;
        // No landmark model → no samples → `detect_blink` reads NoEyes, which is
        // the historical no-mesh result (the caller decides what to do with it).
        let samples = self.capture_ear_samples(SAMPLES)?;
        Ok(irlume_liveness::detect_blink(&samples))
    }

    /// Capture a temporal IR sequence and compute the per-frame [`EarSample`]s
    /// that the blink / deliberate-closure detectors consume. Public so the
    /// blink-tuning capture tool records the EXACT samples the live gate sees.
    ///
    /// Raw frame rate (~15 fps, no de-strobe burst): the detector separates
    /// emitter-lit from ambient-only frames itself, and a ~150 ms natural blink
    /// spans only 2-3 raw frames; halving the rate loses it (measured
    /// 2026-07-01). Frames with no detected face carry `ear = None` (a missed
    /// detection must not masquerade as a blink) but keep their brightness so the
    /// detector can classify the emitter strobe. Returns an empty vec when the
    /// FaceMesh model is not loaded (the gate cannot run).
    pub fn capture_ear_samples(
        &mut self,
        samples: usize,
    ) -> irlume_common::Result<Vec<irlume_liveness::EarSample>> {
        if self.mesh.is_none() {
            return Ok(Vec::new());
        }
        let frames = irlume_camera::capture_ir_sequence(&self.ir_dev, samples, 1)?;
        let mesh = self.mesh.as_mut().expect("mesh present (checked above)");
        let mut out = Vec::with_capacity(frames.len());
        for (i, f) in frames.iter().enumerate() {
            let bri = f.data.iter().map(|&p| p as f32).sum::<f32>() / f.data.len().max(1) as f32;
            let grey_rgb = irlume_camera::grey_to_rgb(&f.data);
            let view = align::RgbView {
                data: &grey_rgb,
                width: f.width,
                height: f.height,
            };
            let mut ear = None;
            let (mut cx, mut cy, mut fsize, mut contrast) = (0.0, 0.0, 0.0, 0.0);
            let faces = self.det.detect(&view)?;
            if let Some(t) = top_detection(&faces) {
                let lm = mesh.landmarks(&view, &t.bbox, 0.25)?;
                let l = irlume_vision::eye_ear(&lm, &irlume_vision::EAR_LEFT);
                let r = irlume_vision::eye_ear(&lm, &irlume_vision::EAR_RIGHT);
                ear = Some(l.min(r));
                cx = (t.bbox[0] + t.bbox[2]) * 0.5;
                cy = (t.bbox[1] + t.bbox[3]) * 0.5;
                fsize = (t.bbox[2] - t.bbox[0]).max(0.0);
                // Corneal specular contrast from the IR frame at the eye
                // landmarks (the second liveness cue: collapses on a real blink).
                contrast = eye_glint_contrast(&f.data, f.width, f.height, &t.landmarks);
            }
            out.push(irlume_liveness::EarSample {
                idx: i,
                ear,
                bri,
                cx,
                cy,
                fsize,
                contrast,
            });
        }
        Ok(out)
    }

    /// If the passive blink gate is wanted and we're about to grant, require a
    /// natural blink before releasing anything. Wanted = the user's enrollment
    /// opted in (`require_challenge`) OR the current service forces it
    /// (`forced_consent`, polkit prompts). Failure downgrades to a non-grant
    /// with an Uncertain-style reason (PAM cascades to the password fallback,
    /// never a lockout). When IR or the FaceMesh model is missing the opt-in
    /// path logs and skips (never lock a user out of an undeployed model); the
    /// forced path fails closed instead.
    fn challenge_if_required(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        forced_consent: bool,
        outcome: Outcome,
    ) -> irlume_common::Result<Outcome> {
        if !outcome.granted || !(enr.require_challenge || forced_consent) {
            return Ok(outcome);
        }
        // The gate needs IR frames and the FaceMesh model. When either is
        // missing, the per-enrollment OPT-IN keeps its historical skip (never
        // lock a user out of an undeployed model), but a FORCED gate (polkit
        // consent) fails closed: the blink is the whole point of allowing face
        // on that service, so without it the grant is withdrawn and PAM
        // cascades to the password.
        if !self.ir_available || self.mesh.is_none() {
            if forced_consent {
                return Ok(Outcome {
                    granted: false, live: outcome.live, score: outcome.score,
                    reason: "consent gesture required for this service but the blink gate can't run (IR or face_landmark.onnx missing); use your password".into(),
                    kind: OutcomeKind::OtherDeny,
                });
            }
            if self.ir_available {
                eprintln!("irlumed: passive liveness (require-challenge) is on but face_landmark.onnx is not loaded; skipping (set IRLUME_MESH_MODEL)");
            }
            return Ok(outcome);
        }
        use irlume_liveness::BlinkResult;
        Ok(match self.run_passive_liveness()? {
            BlinkResult::Blinked => outcome,
            BlinkResult::NoBlink => Outcome::deny_live(
                OutcomeKind::OtherDeny,
                outcome.score,
                "passive liveness: no natural blink in the window; look at the camera a moment longer",
            ),
            BlinkResult::NoEyes => Outcome {
                granted: false, live: false, score: outcome.score,
                reason: "passive liveness: no live eyes (looks like a print/no face)".into(),
                kind: OutcomeKind::OtherDeny,
            },
        })
    }

    /// Authenticate `user`: liveness gate FIRST (a spoof never reaches matching),
    /// then 1:N cosine match against every scan in every enrolled face profile
    /// (any enrolled face unlocks). Threshold scales with the total scan count.
    ///
    /// Runs under a presence GRACE WINDOW. The consent gesture (blank
    /// password + Enter) already granted camera consent, so instead of
    /// failing instantly when the user is not yet in frame (leaning over the
    /// keyboard they just pressed), capture attempts repeat until a face is
    /// assessed or [`GRACE_WINDOW_MS`] elapses.
    ///
    /// SECURITY INVARIANT: only PRESENCE-class failures retry (no face found,
    /// liveness Uncertain framing rejections, cases where no match verdict
    /// was reached). A real match verdict below threshold never retries (each
    /// extra matcher attempt multiplies FAR), and a Spoof verdict never
    /// retries (no free attack retries). See [`presence_retryable`].
    ///
    /// `service` (the PAM service name) selects the window: `sudo`/`su` get the
    /// shorter [`SUDO_GRACE_WINDOW_MS`]; login and lock services (and `None`)
    /// get the full [`GRACE_WINDOW_MS`]. `IRLUME_GRACE_MS` overrides both.
    pub fn authenticate(
        &mut self,
        user: &str,
        service: Option<&str>,
    ) -> irlume_common::Result<Outcome> {
        // Consent-class services (polkit) force the passive blink gate for
        // this call; see `challenge_if_required` and `forced_consent_for`.
        let forced_consent = forced_consent_for(service);
        let window = grace_window_ms(service);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(window);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let out = self.authenticate_once(user, forced_consent)?;
            if !presence_retryable(&out) || std::time::Instant::now() >= deadline {
                if attempt > 1 {
                    irlume_common::dlog!(
                        "grace: settled after {attempt} attempts ({}ms window)",
                        window
                    );
                }
                return Ok(out);
            }
            irlume_common::dlog!(
                "grace: attempt {attempt} found no usable face ({}); retrying within window",
                out.reason
            );
        }
    }

    fn authenticate_once(
        &mut self,
        user: &str,
        forced_consent: bool,
    ) -> irlume_common::Result<Outcome> {
        // Fingerprint mode: face is disabled so pam_fprintd drives; never engage
        // the camera, decline so the PAM stack cascades to fingerprint/password.
        if irlume_core::policy::method().face_disabled() {
            return Ok(Outcome::deny(
                OutcomeKind::OtherDeny,
                "face disabled (fingerprint mode)",
            ));
        }
        let Some(enr) = irlume_core::storage::load(user)? else {
            return Ok(Outcome::deny(
                OutcomeKind::OtherDeny,
                format!("'{user}' is not enrolled"),
            ));
        };
        if enr.profiles.iter().all(|p| p.scans.is_empty()) {
            return Ok(Outcome::deny(
                OutcomeKind::OtherDeny,
                format!("'{user}' has no face scans enrolled"),
            ));
        }
        // Anti-swap: refuse if the live camera no longer matches the one this
        // user enrolled on (only enforced once an enrollment carries a binding).
        if let Some(bind) = &enr.camera_binding {
            if let Some(reason) = self.binding_mismatch(bind) {
                return Ok(Outcome::deny(OutcomeKind::OtherDeny, reason));
            }
        }
        let a = self.assess()?;

        // Opt-in hard gate: never unlock unless both eyes read open.
        if enr.require_eyes_open && !a.eyes_open {
            return Ok(Outcome::deny(
                OutcomeKind::OtherDeny,
                "eyes not detected open (require-eyes-open is on)",
            ));
        }

        // best match over a labeled set of templates -> (score, profile name).
        let best = |probe: &[f32], scans: &[(&str, &str, &[f32])]| -> (f32, String) {
            // Fold over borrowed names and allocate only the winner's String, not
            // one per template. `>` keeps the first template on a tie (unchanged).
            let (score, who) = scans
                .iter()
                .map(|(prof, _scan, t)| (align::cosine(probe, t), *prof))
                .fold(
                    (f32::NEG_INFINITY, ""),
                    |acc, x| if x.0 > acc.0 { x } else { acc },
                );
            (score, who.to_string())
        };

        // Primary path: a visible-light (RGB) face -> full cross-spectrum gate +
        // RGB recognition across all profiles' scans.
        if let Some(probe) = a.embedding {
            if a.verdict != Verdict::Live {
                return Ok(Outcome::deny(
                    liveness_deny_kind(a.verdict, &a.reason),
                    format!("liveness {:?}: {}", a.verdict, a.reason),
                ));
            }
            // Per-user IR-liveness DEPTH floor (anti-screen/photo, calibrated to
            // this user's enrolled 3D face structure): the live frame must clear the
            // enrolled depth floor. Depth only: a per-user IR *brightness* floor was
            // removed because IR face brightness is ambient-dependent (emitter-only
            // ~40 in the dark vs ~140 lit) and a lit-enrollment floor false-rejected
            // genuine dim/night logins as "screen/photo". The global gate above
            // (`evaluate`) already enforces an ambient-tolerant IR brightness floor.
            // Only meaningful when IR was actually captured (skip on RGB-only).
            if let Some(depth_floor) = enr.ir_depth_floor().filter(|_| self.ir_available) {
                irlume_common::dlog!(
                    "gate(per-user depth floor): live {:.2} vs floor {:.2}",
                    a.ir_depth,
                    depth_floor
                );
                if a.ir_depth < depth_floor {
                    return Ok(Outcome::deny(
                        OutcomeKind::Spoof,
                        format!(
                            "IR depth {:.2} below your calibrated floor {:.2}; looks 2D (screen/photo)",
                            a.ir_depth, depth_floor
                        ),
                    ));
                }
            }
            let scans = enr.rgb_scans();
            let thr = irlume_core::scaled_threshold(irlume_core::RGB_MATCH_THRESHOLD, scans.len());
            let (score, who) = best(&probe, &scans);
            irlume_common::dlog!(
                "match(rgb): best {score:.3} vs thr {thr:.3} ({} scans, best profile '{who}')",
                scans.len()
            );
            if score >= thr {
                return self.challenge_if_required(
                    &enr,
                    forced_consent,
                    Outcome::grant(score, format!("match: {who} (rgb)")),
                );
            }
            // Stage-2 lighting-adaptive fusion: RGB recognition missed (poor ambient
            // light or a marginal angle). If we also captured an IR face and the user
            // enrolled IR templates, fuse the two CALIBRATED scores, each weighted by
            // its modality's capture quality; a marginal RGB + marginal IR can jointly
            // grant while FMR stays bounded (an impostor must fool BOTH at once). The
            // cross-spectrum liveness gate + per-user IR floor already passed above.
            // This is the bright→RGB / dark→IR / dim→FUSE story.
            if let Some(ir_probe) = &a.ir_embedding {
                let m = self.ir_match(&enr, ir_probe);
                if m.n_templates > 0 {
                    let (ir_score, ir_who) = (m.best, m.best_who.clone());
                    // (a) calibrated quality-weighted fusion: the dim/mixed-light path.
                    let f = irlume_core::fusion::fuse(
                        irlume_core::fusion::rgb_genuine_prob(score),
                        irlume_core::fusion::rgb_quality_weight(a.signals.rgb_face_brightness),
                        irlume_core::fusion::ir_genuine_prob(ir_score),
                        irlume_core::fusion::ir_quality_weight(true, a.ir_brightness),
                    );
                    irlume_common::dlog!("match(fusion): p={:.3} grant={} (rgb {score:.3} bright {:.0} / ir {ir_score:.3} bright {:.0})",
                        f.prob, f.grant, a.signals.rgb_face_brightness, a.ir_brightness);
                    if f.grant {
                        let who = if ir_score >= score { ir_who } else { who };
                        return self.challenge_if_required(&enr, forced_consent, Outcome::grant(f.prob,
                            format!("match: {who} (rgb+ir fusion p={:.2}; rgb {score:.2}/ir {ir_score:.2})", f.prob)));
                    }
                    // (b) pure IR fallback: still valid when IR alone is clearly strong
                    // (e.g. IR-only enrollment, or RGB template absent). Stricter than the
                    // dark path (+IR_FALLBACK_MARGIN) for the second-modality risk.
                    let ir_base = if self.ir_adapter.is_some() {
                        irlume_core::IR_ADAPTED_MATCH_THRESHOLD
                    } else {
                        irlume_core::IR_MATCH_THRESHOLD
                    };
                    let ir_thr = irlume_core::scaled_threshold(ir_base, m.n_templates)
                        + irlume_core::IR_FALLBACK_MARGIN;
                    irlume_common::dlog!(
                        "match(ir-fallback): {ir_score:.3} vs thr {ir_thr:.3} (adapter={})",
                        self.ir_adapter.is_some()
                    );
                    if ir_score >= ir_thr {
                        return self.challenge_if_required(&enr, forced_consent, Outcome::grant(ir_score,
                            format!("match: {ir_who} (ir-fallback, dim light; rgb {score:.2}<{thr:.2})")));
                    }
                    // (c) calibrated-centroid fallback (ADR-0004): the mean-
                    // template score carries no best-of-N FAR inflation, so it
                    // uses the base threshold scaled only by profile count.
                    if let Some((cs, cwho)) = &m.centroid {
                        let cthr = irlume_core::scaled_threshold(ir_base, enr.profiles.len())
                            + irlume_core::IR_FALLBACK_MARGIN;
                        irlume_common::dlog!("match(ir-centroid): {cs:.3} vs thr {cthr:.3}");
                        if *cs >= cthr {
                            return self.challenge_if_required(&enr, forced_consent, Outcome::grant(*cs,
                                format!("match: {cwho} (calibrated centroid, dim light; rgb {score:.2}<{thr:.2})")));
                        }
                    }
                }
            }
            // The reason keeps the exact score: it reaches only the session's
            // own TUI/CLI (coaching a genuine false reject); the daemon redacts
            // measurements before this line touches the journal (anti-oracle).
            return Ok(Outcome::deny_live(
                OutcomeKind::BelowThreshold,
                score,
                format!("below threshold (rgb {score:.2}, fusion+ir-fallback miss)"),
            ));
        }

        // Dark path: no RGB face, but an IR face -> IR-only liveness + IR
        // recognition (Windows-Hello-style dark operation) across all profiles.
        if let Some(probe) = a.ir_embedding {
            let m = self.ir_match(&enr, &probe);
            if m.n_templates == 0 {
                let reason = if enr.ir_scans().is_empty() {
                    "dark, but no IR scans enrolled; re-enroll to enable dark unlock"
                } else {
                    "dark, but the enrolled IR scans are from a different IR \
                     pipeline (adapter changed); re-enroll to refresh dark unlock"
                };
                return Ok(Outcome::deny(OutcomeKind::OtherDeny, reason));
            }
            let (verdict, _cues, reason) = self.gate.evaluate_ir_only(&a.signals);
            irlume_common::dlog!("liveness(ir-only/dark): {verdict:?} ({reason}); ir_bright={:.0} ir_depth={:.2} glint={:.2} ambient={:.0}",
                a.signals.ir_face_brightness, a.signals.ir_center_edge_ratio, a.signals.ir_eye_glint,
                a.signals.ir_ambient);
            if verdict != Verdict::Live {
                // Dark-path kinds: Uncertain retries under grace, any Spoof
                // does not (the retryable RGB-yes/IR-no transient cannot occur
                // here: this path only runs when RGB saw no face).
                let kind = if verdict == Verdict::Uncertain {
                    OutcomeKind::Uncertain
                } else {
                    OutcomeKind::Spoof
                };
                return Ok(Outcome::deny(
                    kind,
                    format!("dark liveness {verdict:?}: {reason}"),
                ));
            }
            // Per-user calibrated IR depth floor, same as the RGB primary path.
            // `evaluate_ir_only` uses the lenient global DEPTH_MIN_RATIO; the
            // per-user floor is stricter and ambient-independent, so a curved
            // warm spoof that sits between the global ratio and this user's
            // enrolled 3D structure is caught in lit conditions but must not
            // slip through in the dark. Apply it here too before the IR match.
            if let Some(depth_floor) = enr.ir_depth_floor().filter(|_| self.ir_available) {
                irlume_common::dlog!(
                    "gate(per-user depth floor, dark): live {:.2} vs floor {:.2}",
                    a.ir_depth,
                    depth_floor
                );
                if a.ir_depth < depth_floor {
                    return Ok(Outcome::deny(
                        OutcomeKind::Spoof,
                        format!(
                            "IR depth {:.2} below your calibrated floor {:.2}; looks 2D (screen/photo)",
                            a.ir_depth, depth_floor
                        ),
                    ));
                }
            }
            // Opt-in third-party PAD cue, deny-only (scored in assess_full on
            // the lit IR frame; the dark path re-derives its own gate verdict,
            // so it must consult the cue explicitly too).
            if let Some((_, thr, name)) = self.tp_pad.as_ref() {
                if thirdparty_downgrades(verdict, a.thirdparty_fake, *thr) {
                    let pf = a.thirdparty_fake.unwrap_or(1.0);
                    irlume_common::dlog!(
                        "thirdparty-pad('{name}'): dark path p_fake {pf:.3} >= {thr:.2}; denying"
                    );
                    return Ok(Outcome::deny(
                        OutcomeKind::Spoof,
                        format!(
                            "dark liveness: third-party PAD cue '{name}' flags a spoof; use your password"
                        ),
                    ));
                }
            }
            let ir_base = if self.ir_adapter.is_some() {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                irlume_core::IR_MATCH_THRESHOLD
            };
            let ir_thr = irlume_core::scaled_threshold(ir_base, m.n_templates);
            let (score, who) = (m.best, m.best_who.clone());
            irlume_common::dlog!(
                "match(ir/dark): best {score:.3} vs thr {ir_thr:.3} ({} scans, adapter={}, calib_centroid={:?})",
                m.n_templates,
                self.ir_adapter.is_some(),
                m.centroid.as_ref().map(|(s, _)| *s)
            );
            // Grant on best-of-N at the scaled threshold, or on the
            // calibrated centroid at the base threshold (no best-of-N FAR
            // inflation; the prototype-validated mean-template protocol).
            if score >= ir_thr {
                return self.challenge_if_required(
                    &enr,
                    forced_consent,
                    Outcome::grant(score, format!("match: {who} (ir/dark)")),
                );
            }
            if let Some((cs, cwho)) = &m.centroid {
                let cthr = irlume_core::scaled_threshold(ir_base, enr.profiles.len());
                irlume_common::dlog!("match(ir/dark centroid): {cs:.3} vs thr {cthr:.3}");
                if *cs >= cthr {
                    return self.challenge_if_required(
                        &enr,
                        forced_consent,
                        Outcome::grant(
                            *cs,
                            format!("match: {cwho} (ir/dark, calibrated centroid)"),
                        ),
                    );
                }
            }
            return self.challenge_if_required(
                &enr,
                forced_consent,
                Outcome::deny_live(OutcomeKind::BelowThreshold, score, "below threshold (ir)"),
            );
        }

        Ok(Outcome::deny(
            OutcomeKind::NoFace,
            format!("no face: {}", a.reason),
        ))
    }

    /// 1:N identify ("who is this?"): one live capture, matched against every
    /// enrolled user's RGB profiles (no claimed identity).
    ///
    /// Liveness-gated like auth; reports the best above-threshold (user,
    /// profile, score). RGB primary path only: a diagnostic, not a dark-mode
    /// unlock. The full cross-user search is an admin/testing capability; the
    /// daemon restricts a non-root caller to [`Self::identify_within`] so the
    /// returned score can't become a hill-climbing oracle against other
    /// users' templates.
    pub fn identify(&mut self) -> irlume_common::Result<IdentifyOutcome> {
        self.identify_impl(None)
    }

    /// Identify scoped to a single enrolled user ("is this `user`?"). Same
    /// liveness gate and RGB match as [`Self::identify`], but the search set is
    /// just this one account: what a non-root peer is allowed to ask about itself.
    pub fn identify_within(&mut self, user: &str) -> irlume_common::Result<IdentifyOutcome> {
        self.identify_impl(Some(user))
    }

    fn identify_impl(&mut self, restrict: Option<&str>) -> irlume_common::Result<IdentifyOutcome> {
        if irlume_core::policy::method().face_disabled() {
            return Ok(IdentifyOutcome {
                user: None,
                profile: None,
                score: 0.0,
                live: false,
                reason: "face disabled (fingerprint mode)".into(),
            });
        }
        let a = self.assess()?;
        let Some(probe) = a.embedding else {
            return Ok(IdentifyOutcome {
                user: None,
                profile: None,
                score: 0.0,
                live: false,
                reason: format!("no RGB face: {}", a.reason),
            });
        };
        if a.verdict != Verdict::Live {
            return Ok(IdentifyOutcome {
                user: None,
                profile: None,
                score: 0.0,
                live: false,
                reason: format!("liveness {:?}: {}", a.verdict, a.reason),
            });
        }
        let mut best: Option<(f32, String, String)> = None; // (score, user, profile)
        let candidates: Vec<String> = match restrict {
            Some(u) => vec![u.to_string()],
            None => irlume_core::storage::list_users(),
        };
        for user in candidates {
            let Some(enr) = irlume_core::storage::load(&user)? else {
                continue;
            };
            let scans = enr.rgb_scans();
            if scans.is_empty() {
                continue;
            }
            let thr = irlume_core::scaled_threshold(irlume_core::RGB_MATCH_THRESHOLD, scans.len());
            let (score, who) = scans
                .iter()
                .map(|(prof, _scan, t)| (align::cosine(&probe, t), *prof))
                .fold(
                    (f32::NEG_INFINITY, ""),
                    |acc, x| if x.0 > acc.0 { x } else { acc },
                );
            if score >= thr && best.as_ref().is_none_or(|b| score > b.0) {
                best = Some((score, user.clone(), who.to_string()));
            }
        }
        match best {
            Some((score, user, profile)) => Ok(IdentifyOutcome {
                user: Some(user),
                profile: Some(profile),
                score,
                live: true,
                reason: "match".into(),
            }),
            None => Ok(IdentifyOutcome {
                user: None,
                profile: None,
                score: 0.0,
                live: true,
                reason: "live face, but no enrolled match".into(),
            }),
        }
    }

    /// IR liveness self-test: capture and run the algorithmic PAD gate, reporting
    /// the verdict plus the cues behind it. Backs the TUI Calibrate screen and
    /// `Request::SelfTest { Liveness }`.
    pub fn liveness_selftest(&mut self) -> irlume_common::Result<(bool, String)> {
        let a = self.assess()?;
        let s = &a.signals;
        let live = a.verdict == Verdict::Live;
        let detail = if live {
            format!(
                "Live: RGB face {}, IR face {} · IR brightness {:.0}, depth {:.2}, glint {:.0}",
                if s.rgb_face.is_some() { "✓" } else { "✗" },
                if s.ir_face.is_some() { "✓" } else { "✗" },
                a.ir_brightness,
                a.ir_depth,
                s.ir_eye_glint,
            )
        } else {
            format!("{:?}: {}", a.verdict, a.reason)
        };
        Ok((live, detail))
    }

    /// Alignment-determinism self-test: embed the same aligned chip twice; the
    /// cosine MUST be ~1.0. Catches the AuraFace alignment/normalization trap
    /// (the "identical images score 0.6" failure). `Request::SelfTest { AlignmentIdentity }`.
    pub fn alignment_selftest(&mut self) -> irlume_common::Result<(bool, String)> {
        let rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev)?;
        let view = align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        };
        let faces = self.det.detect(&view)?;
        let Some(f) = top_detection(&faces) else {
            return Ok((
                false,
                "no RGB face detected; face the camera and retry".into(),
            ));
        };
        let chip = align::align_to_arcface(&view, &f.landmarks)?;
        let emb_first = self.emb.embed(&chip)?;
        let emb_second = self.emb.embed(&chip)?;
        let cos = align::cosine(&emb_first, &emb_second);
        Ok((
            cos > 0.999,
            format!("alignment determinism cosine {cos:.6} (want ≈ 1.000000)"),
        ))
    }

    /// Capture `want` LIVE, frontal scans (best-effort, with a retry budget).
    /// Each Live capture yields one [`CapturedScan`]. No enrolling from a
    /// photo; the liveness gate rejects spoofs. `pitch_neutral` centres the
    /// frontal gate on this user's camera (None on first enroll).
    fn capture_scans(
        &mut self,
        want: usize,
        pitch_neutral: Option<f32>,
    ) -> irlume_common::Result<Vec<CapturedScan>> {
        let mut out = Vec::new();
        // Budget (was ×4) absorbs the added frontality gate (a frame grabbed the
        // instant the user drifts off-angle is rejected, not saved) with enough
        // retries that a brief drift near the capture moment doesn't abort enroll.
        for _ in 0..(want * 10) {
            if out.len() >= want {
                break;
            }
            let a = self.assess()?;
            // Authoritative capture gate: LIVE *and* squarely frontal. The guided
            // TUI only decides when to START the 3-2-1; this is what actually
            // decides whether the frame is kept, so a turned/tilted (but live)
            // face can't be saved as a bad template even if the user moved during
            // the countdown. Same bounds (and neutral) the enrollment guide uses.
            if a.verdict == Verdict::Live && frontal_signals(&a.signals, pitch_neutral) {
                if let Some(e) = a.embedding {
                    out.push(CapturedScan {
                        rgb: e.to_vec(),
                        ir: a.ir_embedding.clone(),
                        depth: a.ir_depth,
                        brightness: a.ir_brightness,
                        pitch: a.signals.head_pitch_frac,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Enroll `want` scans (capped at MAX_SCANS_PER_PROFILE). If the captured
    /// face already owns a profile, the scans are merged into it (a face can
    /// never own two profiles, so that is always what the user meant, and it
    /// is the 0.2.0 upgrade remedy, fresh scans reviving dark/dim login after
    /// an embedding-space change). A novel face gets a NEW profile; that errors
    /// if the account is already at MAX_PROFILES.
    pub fn enroll_profile(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
    ) -> irlume_common::Result<EnrollOutcome> {
        use irlume_core::storage::{
            self, Enrollment, FaceProfile, FaceScan, MAX_PROFILES, MAX_SCANS_PER_PROFILE,
        };
        let mut enr = storage::load(user)?.unwrap_or_else(|| Enrollment::new(user));
        let want = want.clamp(1, MAX_SCANS_PER_PROFILE);
        // Fail fast on an explicit duplicate name, before the camera opens. The
        // auto-generated name can't collide.
        if let Some(n) = &profile_name {
            if enr.profiles.iter().any(|p| p.name == *n) {
                return Err(irlume_common::Error::Protocol(format!(
                    "a face profile named '{n}' already exists"
                )));
            }
        }
        // Probe scan first: it decides whether this face merges into an existing
        // profile, and therefore how many scans to capture at all. A profile
        // with 5 free slots gets a 5-scan top-up instead of a 10-scan session
        // that discards half, and a full profile is refused after one scan
        // instead of ten. (First enroll: no neutral yet → capture_scans falls
        // back to the global default band; the scans' pitches become this
        // user's neutral for next time.)
        let probe = self
            .capture_scans(1, enr.pitch_neutral())?
            .into_iter()
            .next()
            .ok_or_else(|| {
                irlume_common::Error::Protocol(
                    "no live scan captured; check lighting and framing".into(),
                )
            })?;
        let goal = match enroll_merge_target(&enr, &[probe.rgb.as_slice()])? {
            Some(target) => {
                let have = enr
                    .profiles
                    .iter()
                    .find(|p| p.name == target)
                    .map_or(0, |p| p.scans.len());
                let room = MAX_SCANS_PER_PROFILE - have;
                if room == 0 {
                    return Err(irlume_common::Error::Protocol(format!(
                        "this face is already enrolled as '{target}', which is at the max \
                         {MAX_SCANS_PER_PROFILE} scans; delete some of its scans first"
                    )));
                }
                want.min(room)
            }
            None => want,
        };
        let mut captured = vec![probe];
        if goal > 1 {
            captured.extend(self.capture_scans(goal - 1, enr.pitch_neutral())?);
        }
        if captured.len() < goal {
            return Err(irlume_common::Error::Protocol(format!(
                "only {} live scans (need {goal}); check lighting and framing",
                captured.len()
            )));
        }
        // Final disposition over the whole capture: catches a second person
        // drifting into frame after the probe, and a borderline probe that only
        // crosses the identity threshold on a later scan.
        let rgbs: Vec<&[f32]> = captured.iter().map(|s| s.rgb.as_slice()).collect();
        if let Some(target) = enroll_merge_target(&enr, &rgbs)? {
            // The face already owns a profile: merge the capture into it.
            let idx = enr
                .profiles
                .iter()
                .position(|p| p.name == target)
                .expect("merge target came from these profiles");
            let room = MAX_SCANS_PER_PROFILE - enr.profiles[idx].scans.len();
            if room == 0 {
                return Err(irlume_common::Error::Protocol(format!(
                    "this face is already enrolled as '{target}', which is at the max \
                     {MAX_SCANS_PER_PROFILE} scans; delete some of its scans first"
                )));
            }
            let added = captured.len().min(room);
            let mut added_scans = Vec::with_capacity(added);
            for s in captured.into_iter().take(room) {
                let sname = enr.profiles[idx].next_scan_name();
                added_scans.push(sname.clone());
                let ir_space = s.ir.as_ref().map(|_| self.ir_space.clone());
                enr.profiles[idx].scans.push(FaceScan {
                    name: sname,
                    rgb: s.rgb,
                    ir: s.ir,
                    ir_space,
                    ir_depth: s.depth,
                    ir_brightness: s.brightness,
                    pitch: s.pitch,
                });
            }
            self.refit_profile_calib(&mut enr.profiles[idx]);
            let total = enr.profiles[idx].scans.len();
            storage::save(&enr)?;
            return Ok(EnrollOutcome::Merged {
                name: target,
                added,
                total,
                added_scans,
            });
        }
        if enr.profiles.len() >= MAX_PROFILES {
            return Err(irlume_common::Error::Protocol(format!(
                "at the max of {MAX_PROFILES} face profiles; delete one first"
            )));
        }
        let name = profile_name.unwrap_or_else(|| enr.next_profile_name());
        let mut prof = FaceProfile {
            ir_calib: None,
            name: name.clone(),
            scans: Vec::new(),
        };
        for s in captured {
            let sname = prof.next_scan_name();
            let ir_space = s.ir.as_ref().map(|_| self.ir_space.clone());
            prof.scans.push(FaceScan {
                name: sname,
                rgb: s.rgb,
                ir: s.ir,
                ir_space,
                ir_depth: s.depth,
                ir_brightness: s.brightness,
                pitch: s.pitch,
            });
        }
        let n = prof.scans.len();
        self.refit_profile_calib(&mut prof);
        enr.profiles.push(prof);
        if enr.camera_binding.is_none() {
            enr.camera_binding = Some(self.current_binding());
        }
        storage::save(&enr)?;
        Ok(EnrollOutcome::New { name, scans: n })
    }

    /// Snapshot the identity of the cameras this engine is bound to, for
    /// anti-swap verification at auth.
    fn current_binding(&self) -> irlume_core::storage::CameraBinding {
        irlume_core::storage::CameraBinding {
            rgb: irlume_camera::device_identity(&self.rgb_dev),
            ir: irlume_camera::device_identity(&self.ir_dev),
        }
    }

    /// If the live cameras no longer match the enrolled binding, return a reason
    /// to refuse (anti-swap). A bound device that now reads differently, or an
    /// enrolled IR camera that's gone, fails; an unbound side is not checked.
    fn binding_mismatch(&self, bind: &irlume_core::storage::CameraBinding) -> Option<String> {
        if let Some(want) = &bind.rgb {
            if irlume_camera::device_identity(&self.rgb_dev).as_ref() != Some(want) {
                return Some("camera changed since enrollment (RGB device identity differs); re-enroll on this camera".into());
            }
        }
        if let Some(want) = &bind.ir {
            if irlume_camera::device_identity(&self.ir_dev).as_ref() != Some(want) {
                return Some(
                    "IR camera changed or absent since enrollment; re-enroll on this camera".into(),
                );
            }
        }
        None
    }

    /// Add one scan to an existing profile ("improve recognition"). Errors if the
    /// profile is missing or already at MAX_SCANS_PER_PROFILE.
    pub fn add_scan(
        &mut self,
        user: &str,
        profile_name: &str,
    ) -> irlume_common::Result<(String, usize)> {
        use irlume_core::storage::{self, FaceScan, MAX_SCANS_PER_PROFILE};
        let mut enr = storage::load(user)?
            .ok_or_else(|| irlume_common::Error::Protocol(format!("'{user}' is not enrolled")))?;
        let idx = enr
            .profiles
            .iter()
            .position(|p| p.name == profile_name)
            .ok_or_else(|| {
                irlume_common::Error::Protocol(format!("no face profile '{profile_name}'"))
            })?;
        if enr.profiles[idx].scans.len() >= MAX_SCANS_PER_PROFILE {
            return Err(irlume_common::Error::Protocol(format!(
                "'{profile_name}' already has the max {MAX_SCANS_PER_PROFILE} scans"
            )));
        }
        let captured = self
            .capture_scans(1, enr.pitch_neutral())?
            .into_iter()
            .next()
            .ok_or_else(|| {
                irlume_common::Error::Protocol(
                    "no live scan captured; check lighting and framing".into(),
                )
            })?;
        // Anti-mixing: reject a scan whose face belongs to a different profile.
        if let Some((other, score)) = colliding_profile(&enr, &captured.rgb, Some(profile_name)) {
            let cnt = enr
                .profiles
                .iter()
                .find(|p| p.name == other)
                .map_or(0, |p| p.scans.len());
            let hint = if cnt < MAX_SCANS_PER_PROFILE {
                format!("if you want this face, add the scan to '{other}' (it has {cnt}/{MAX_SCANS_PER_PROFILE})")
            } else {
                format!("'{other}' is already at the max {MAX_SCANS_PER_PROFILE} scans")
            };
            return Err(irlume_common::Error::Protocol(format!(
                "the scanned face belongs to '{other}' (match {score:.2}), not '{profile_name}'; {hint}. \
                 Scans of different faces can't be mixed in one profile."
            )));
        }
        let sname = enr.profiles[idx].next_scan_name();
        let ir_space = captured.ir.as_ref().map(|_| self.ir_space.clone());
        enr.profiles[idx].scans.push(FaceScan {
            name: sname.clone(),
            rgb: captured.rgb,
            ir: captured.ir,
            ir_space,
            ir_depth: captured.depth,
            ir_brightness: captured.brightness,
            pitch: captured.pitch,
        });
        self.refit_profile_calib(&mut enr.profiles[idx]);
        if enr.camera_binding.is_none() {
            enr.camera_binding = Some(self.current_binding());
        }
        let total = enr.profiles[idx].scans.len();
        storage::save(&enr)?;
        Ok((sname, total))
    }

    /// One framing-guide sample for guided enrollment: capture, detect, and
    /// report how the user is positioned (no enrollment, no auth). The gates
    /// mirror the enroll/auth path so `well_framed` implies a capture will take.
    /// `user` (the account being enrolled) tunes the pitch band to that user's
    /// calibrated neutral when they already have scans, so the guide coaches to
    /// the same window the capture gate will accept.
    pub fn position_sample(
        &mut self,
        user: Option<&str>,
    ) -> irlume_common::Result<irlume_common::PositionReport> {
        use irlume_common::PositionReport;
        // Face width as a fraction of frame width.
        const MIN_FRAC: f32 = 0.12;
        const MAX_FRAC: f32 = 0.55;
        // Max face-center offset from frame center, fraction of frame size.
        const CENTER_TOL: f32 = 0.18;
        // Mean face luma bounds, 0-255 BT.601.
        const DIM: f32 = 55.0;
        const BRIGHT: f32 = 235.0;
        // This user's calibrated pitch neutral, if any (read-only; absent = global default).
        let pitch_neutral = user
            .and_then(|u| irlume_core::storage::load(u).ok().flatten())
            .and_then(|e| e.pitch_neutral());

        let rgb = irlume_camera::capture_rgb(&self.rgb_dev)?;
        let view = align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        };
        let faces = self.det.detect(&view)?;
        let top = top_detection(&faces);
        // NB: the framing guide is RGB-only so it stays fast enough to poll (the
        // IR burst would make each sample multi-second). IR readiness is checked
        // at the actual capture, not in the guide.
        let ir_ok = false;
        let (fw, fh) = (rgb.width as f32, rgb.height as f32);
        let Some(f) = top else {
            return Ok(PositionReport {
                ir_ok,
                guidance: "No face detected; look straight at the camera and center yourself"
                    .into(),
                ..Default::default()
            });
        };
        let [x1, y1, x2, y2] = f.bbox;
        let face_frac = (x2 - x1).max(0.0) / fw;
        let centered = ((x1 + x2) / 2.0 - fw / 2.0).abs() <= CENTER_TOL * fw
            && ((y1 + y2) / 2.0 - fh / 2.0).abs() <= CENTER_TOL * fh;
        let pose = irlume_vision::head_pose(&f.landmarks);
        let brightness = luma_in_bbox(&rgb.data, rgb.width, rgb.height, &f.bbox);

        // Quality starts at 100 and the first failing gate deducts by
        // severity: 45 for too-far (smallest face, least usable capture), 30
        // for the mid-tier framing/pose/darkness faults, 20 for over-bright
        // (the mildest; recognition still works under glare more often than
        // under the other faults).
        let mut q = 100i32;
        let mut guidance = "Hold still, looking good".to_string();
        let mut well = true;
        let (plo, phi) = pitch_band(pitch_neutral);
        let frontal = pose.yaw_asym <= FRAME_YAW_ASYM_MAX && (plo..=phi).contains(&pose.pitch_frac);
        // Live pose numbers for calibrating the framing bounds to a given camera
        // (`IRLUME_LOG=debug`); `neutral` is this user's calibrated centre (or -).
        irlume_common::dlog!("framing: yaw_asym={:.2} yaw_signed={:.2} pitch={:.2} band=[{:.2},{:.2}] neutral={} face_frac={:.2} bright={:.0}",
            pose.yaw_asym, pose.yaw_signed, pose.pitch_frac, plo, phi,
            pitch_neutral.map(|n| format!("{n:.2}")).unwrap_or_else(|| "-".into()), face_frac, brightness);
        if face_frac < MIN_FRAC {
            guidance = "Move closer".into();
            well = false;
            q -= 45;
        } else if face_frac > MAX_FRAC {
            guidance = "Move back a little".into();
            well = false;
            q -= 30;
        } else if !centered {
            guidance = "Center your face in the frame".into();
            well = false;
            q -= 30;
        } else if !frontal {
            guidance = frontality_hint(&pose, pitch_neutral);
            well = false;
            q -= 30;
        } else if brightness < DIM {
            guidance = "Too dark: add light or face a window".into();
            well = false;
            q -= 30;
        } else if brightness > BRIGHT {
            guidance = "Too bright: reduce glare/backlight".into();
            well = false;
            q -= 20;
        }
        Ok(PositionReport {
            face: true,
            face_frac,
            centered,
            yaw_asym: pose.yaw_asym,
            pitch_frac: pose.pitch_frac,
            brightness,
            ir_ok,
            quality: q.clamp(0, 100) as u8,
            well_framed: well,
            guidance,
        })
    }
}

/// Framing-guide frontality bounds: deliberately STRICTER than the liveness
/// anti-spoof gate (yaw 0.40 / pitch 0.20–0.80). The wide liveness pitch band
/// meant a normal chin tilt never left "frontal", so "lift/lower your chin"
/// almost never fired, and by the time a tilt was steep enough to trip the
/// liveness band, the detector had already lost the face ("no face detected").
/// A tighter band makes the up/down cue fire at a MODERATE, still-detectable
/// tilt. Low pitch = looking up, high pitch = looking down (live-verified). A
/// below-eye-level laptop camera looks UP at the face, biasing neutral toward
/// the LOW (looking-up) end. This is the UNCALIBRATED bootstrap band, used only
/// until a user has ≥2 enrolled scans: it is deliberately WIDE so a FIRST
/// enrollment succeeds on any camera geometry: a below-eye laptop cam can read
/// a level face at ~0.72, an eye-level cam at ~0.45, so the window must span both
/// or first enroll could loop with no escape. Once calibrated, [`pitch_band`]
/// recentres a tighter `neutral ± PITCH_TOL` window on the user's own camera.
/// Yaw is camera-independent (0 = frontal on any rig) so it stays moderately tight.
const FRAME_YAW_ASYM_MAX: f32 = 0.36;
const FRAME_PITCH_MIN: f32 = 0.28;
const FRAME_PITCH_MAX: f32 = 0.75;
/// Half-width of the pitch window once the user's neutral is known. Tighter than
/// the wide bootstrap band because it's centred on the camera's actual level
/// reading; coaches a squarely-frontal capture without nagging a level face.
const PITCH_TOL: f32 = 0.13;

/// The pitch acceptance window: `neutral ± PITCH_TOL` once this user has a
/// calibrated neutral (from prior enrollment scans), else the hand-tuned global
/// default. Shared by the guide and the capture gate so they never disagree.
fn pitch_band(pitch_neutral: Option<f32>) -> (f32, f32) {
    match pitch_neutral {
        Some(n) => (n - PITCH_TOL, n + PITCH_TOL),
        None => (FRAME_PITCH_MIN, FRAME_PITCH_MAX),
    }
}

/// True when a head pose is squarely-frontal enough to enroll: the capture-time
/// gate (in [`Engine::capture_scans`]) and the guide's `well_framed` share these
/// bounds (and the same `pitch_neutral`), so what the guide coaches to is exactly
/// what gets saved.
fn frontal_signals(s: &Signals, pitch_neutral: Option<f32>) -> bool {
    let (lo, hi) = pitch_band(pitch_neutral);
    s.head_yaw_asym <= FRAME_YAW_ASYM_MAX && (lo..=hi).contains(&s.head_pitch_frac)
}

/// Turn a non-frontal head pose into a directional enrollment instruction, told
/// in the USER's own frame. On irlume's non-mirrored capture, nose-toward-image-
/// left (`yaw_signed < 0`) means the person is looking to THEIR right, so we ask
/// them to turn left. For pitch (live-verified): a LOW `pitch_frac` means the
/// nose has risen toward the eye line = looking UP → ask them to lower the chin;
/// a HIGH `pitch_frac` means looking DOWN → ask them to lift the chin. When both
/// axes are off the more-severe one wins, so the user is corrected on one thing
/// at a time instead of being bounced around.
fn frontality_hint(pose: &irlume_vision::HeadPose, pitch_neutral: Option<f32>) -> String {
    let (lo, hi) = pitch_band(pitch_neutral);
    let mid = (lo + hi) / 2.0;
    let yaw_off = pose.yaw_asym > FRAME_YAW_ASYM_MAX;
    let pitch_off = pose.pitch_frac < lo || pose.pitch_frac > hi;
    let yaw_sev = pose.yaw_asym / FRAME_YAW_ASYM_MAX;
    let pitch_sev = (pose.pitch_frac - mid).abs() / ((hi - lo) / 2.0);
    if yaw_off && (!pitch_off || yaw_sev >= pitch_sev) {
        // Nose toward image-left → looking to their right → turn left, and vice versa.
        if pose.yaw_signed < 0.0 {
            "Turn your head left to face the camera".into()
        } else {
            "Turn your head right to face the camera".into()
        }
    } else if pose.pitch_frac < lo {
        // Below neutral = nose toward eye line = looking up → bring the chin down.
        "Lower your chin, look down a little".into()
    } else if pose.pitch_frac > hi {
        // Above neutral = nose toward mouth = looking down → bring the chin up.
        "Lift your chin, look up a little".into()
    } else {
        "Look straight at the camera".into()
    }
}

/// Mean BT.601 luma (0–255) of the RGB8 face region.
fn luma_in_bbox(rgb: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    let x1 = (bbox[0].max(0.0) as u32).min(w.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(h.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut sum, mut n) = (0f64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            let i = ((y * w + x) * 3) as usize;
            if i + 2 < rgb.len() {
                sum +=
                    0.299 * rgb[i] as f64 + 0.587 * rgb[i + 1] as f64 + 0.114 * rgb[i + 2] as f64;
                n += 1;
            }
        }
    }
    if n == 0 {
        0.0
    } else {
        (sum / n as f64) as f32
    }
}

/// What [`Engine::enroll_profile`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// A new face profile was created.
    New { name: String, scans: usize },
    /// The captured face already owned `name`, so the capture was added to that
    /// profile instead (`added` new scans, `total` scans now) and the
    /// per-enrollment calibration was refitted. This is what makes `irlume
    /// enroll` idempotent for the same person: a face can never own two
    /// profiles, so merging is always what the user meant. It is also the
    /// 0.2.0 upgrade remedy (fresh current-space scans revive dark/dim login
    /// after an embedding-space change strands the old IR templates).
    Merged {
        name: String,
        added: usize,
        total: usize,
        /// Names of the scans this capture appended, so a caller can undo the
        /// merge by deleting exactly them (the TUI does this on a declined
        /// "add to the existing profile?" confirm).
        added_scans: Vec<String>,
    },
}

/// Decide what an enroll capture means. `Ok(None)`: novel face, create the new
/// profile. `Ok(Some(name))`: the face already owns `name`; merge the capture
/// into that profile (a face can never own two profiles, so refusing would
/// only force the user to redo this by hand via add-scan). `Err`: the capture
/// matched two different profiles (two people in frame across the scans).
fn enroll_merge_target(
    enr: &irlume_core::storage::Enrollment,
    captured_rgb: &[&[f32]],
) -> irlume_common::Result<Option<String>> {
    let mut hit: Option<String> = None;
    for rgb in captured_rgb {
        let Some((other, _score)) = colliding_profile(enr, rgb, None) else {
            continue;
        };
        match &hit {
            Some(first) if *first != other => {
                return Err(irlume_common::Error::Protocol(format!(
                    "the captured scans match two different profiles ('{first}' and '{other}'); \
                     re-run enrollment with one person in frame"
                )));
            }
            Some(_) => {}
            None => hit = Some(other),
        }
    }
    Ok(hit)
}

/// Best-matching OTHER profile for `probe` (excluding `exclude`), if it reaches
/// the identity threshold, i.e. this face already belongs to a different
/// profile. Stops the same person's scans being split across profiles (which
/// would corrupt recognition and the 1:N unlock model).
fn colliding_profile(
    enr: &irlume_core::storage::Enrollment,
    probe: &[f32],
    exclude: Option<&str>,
) -> Option<(String, f32)> {
    let mut best: Option<(String, f32)> = None;
    for p in &enr.profiles {
        if Some(p.name.as_str()) == exclude {
            continue;
        }
        for s in &p.scans {
            let c = align::cosine(probe, &s.rgb);
            if c >= irlume_core::RGB_MATCH_THRESHOLD && best.as_ref().is_none_or(|b| c > b.1) {
                best = Some((p.name.clone(), c));
            }
        }
    }
    best
}

/// Minimum peak grey level (0-255) in the per-eye window to count as a
/// corneal glint from the 850nm emitter.
const EYE_OPEN_PEAK_MIN: f32 = 200.0;

/// Per-eye open check (IR corneal-glint heuristic): an open eye reflects the
/// 850nm emitter as a bright specular point near the eye landmark; a closed
/// eyelid does not. Conservative: requires the glint, so an unverifiable eye
/// reads closed (auth falls back to password). Heuristic; used only when a
/// profile opts into the require-eyes-open gate.
pub fn both_eyes_open(grey: &[u8], w: u32, h: u32, lm: &irlume_vision::Landmarks5) -> bool {
    let iod = ((lm[1].0 - lm[0].0).powi(2) + (lm[1].1 - lm[0].1).powi(2)).sqrt();
    let r = (iod * 0.20).max(2.0) as i32;
    eye_open_at(grey, w, h, lm[0], r) && eye_open_at(grey, w, h, lm[1], r)
}

fn eye_open_at(grey: &[u8], w: u32, h: u32, (ex, ey): (f32, f32), r: i32) -> bool {
    let (cx, cy) = (ex as i32, ey as i32);
    let mut peak = 0u8;
    for dy in -r..=r {
        for dx in -r..=r {
            let (x, y) = (cx + dx, cy + dy);
            if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                peak = peak.max(grey[(y as u32 * w + x as u32) as usize]);
            }
        }
    }
    peak as f32 >= EYE_OPEN_PEAK_MIN
}

/// Mean luma (0–255) and the fraction of near-white ("hot") pixels inside `bbox`
/// of an RGB image. The hot fraction is a basic RGB-PAD cue: emissive screens
/// and glossy prints blow out highlights, so an unusually high fraction is a
/// (deterrent-grade) screen/glare signal.
fn rgb_luma_stats(rgb: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> (f32, f32) {
    let x1 = (bbox[0].max(0.0) as u32).min(w.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(h.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut sum, mut n, mut hot) = (0u64, 0u64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            let i = ((y * w + x) * 3) as usize;
            if i + 2 < rgb.len() {
                let luma =
                    (rgb[i] as u32 * 299 + rgb[i + 1] as u32 * 587 + rgb[i + 2] as u32 * 114)
                        / 1000;
                sum += luma as u64;
                if luma >= 250 {
                    hot += 1;
                }
                n += 1;
            }
        }
    }
    if n == 0 {
        (0.0, 0.0)
    } else {
        (sum as f32 / n as f32, hot as f32 / n as f32)
    }
}

/// Mean grey level (0-255) inside `bbox` of a `w`x`h` 8-bit IR frame; the
/// bbox is clamped to the frame. Returns 0.0 for a degenerate region or a
/// frame shorter than `w*h`.
pub fn mean_in_bbox(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    // The pixel loop assumes grey.len() == w*h (the invariant the camera crate
    // upholds). Guard once so a truncated/mismatched IR frame degrades to 0.0
    // (treated as "too dark", a safe deny) instead of panicking the daemon.
    if grey.len() < (w as usize).saturating_mul(h as usize) {
        return 0.0;
    }
    let x1 = (bbox[0].max(0.0) as u32).min(w.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(h.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut sum, mut n) = (0u64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            sum += grey[(y * w + x) as usize] as u64;
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        sum as f32 / n as f32
    }
}

/// The IR depth cue: ratio of the center-box mean to the edge-ring mean of
/// the IR face crop (grey 0-255). A real 3D face lit by the near-coaxial
/// emitter is brighter at the center/nose and falls off at the rim (ratio
/// above 1); a flat screen/photo reads ~1. Returns 0.0 on a degenerate bbox
/// or a near-black edge (no signal, never inf).
pub fn center_edge_ratio(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    let (bw, bh) = (bbox[2] - bbox[0], bbox[3] - bbox[1]);
    if bw <= 4.0 || bh <= 4.0 {
        return 0.0;
    }
    let inner = [
        bbox[0] + bw * 0.25,
        bbox[1] + bh * 0.25,
        bbox[2] - bw * 0.25,
        bbox[3] - bh * 0.25,
    ];
    let center = mean_in_bbox(grey, w, h, &inner);
    let whole = mean_in_bbox(grey, w, h, bbox);
    // The 25%-per-side inset makes the center box 50%x50% = 25% of the bbox
    // area, so whole = 0.25*center + 0.75*edge; solve for the edge-ring mean.
    let edge = (whole - center * 0.25) / 0.75;
    if edge <= 1.0 {
        0.0
    } else {
        center / edge
    }
}

/// Half-width (pixels) of the square search window around each eye landmark
/// for the corneal glint peak. A fixed radius, not IOD-scaled: the glint is a
/// point highlight near the landmark at typical login distances, and the gate
/// consuming this cue (`GLINT_MIN`) was calibrated against it.
const GLINT_SEARCH_RADIUS_PX: i32 = 8;

/// Peak grey level (0-255) near the eye landmarks of an IR frame: the
/// emitter's specular corneal glint. Supporting liveness cue only (feeds
/// `Signals::ir_eye_glint`); 0.0 when the landmarks fall outside the frame.
pub fn eye_glint(grey: &[u8], w: u32, h: u32, landmarks: &Landmarks5) -> f32 {
    let mut peak = 0u8;
    for &(ex, ey) in &landmarks[0..2] {
        let r = GLINT_SEARCH_RADIUS_PX;
        for dy in -r..=r {
            for dx in -r..=r {
                let x = ex as i32 + dx;
                let y = ey as i32 + dy;
                if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                    peak = peak.max(grey[(y as u32 * w + x as u32) as usize]);
                }
            }
        }
    }
    peak as f32
}

/// Specular contrast at the eyes = peak − local-mean brightness, max over both
/// eyes. A live OPEN eye makes a sharp corneal specular spike (high contrast); a
/// CLOSED lid (or a printed/vinyl "eye") is diffuse (low). This is the basis of
/// the ADR-0002 blink challenge and has far better SNR than raw peak glint: a
/// closed lid still reflects 850nm, so peak alone barely drops, but the specular
/// spike (hence contrast) collapses. Live-validated 2026-06-30: genuine open-eye
/// contrast ≈120, a static vinyl banner ≈70 (flat).
pub fn eye_glint_contrast(grey: &[u8], w: u32, h: u32, landmarks: &Landmarks5) -> f32 {
    let iod = ((landmarks[1].0 - landmarks[0].0).powi(2)
        + (landmarks[1].1 - landmarks[0].1).powi(2))
    .sqrt();
    let r = (iod * 0.20).max(2.0) as i32;
    let at = |(ex, ey): (f32, f32)| -> f32 {
        let (cx, cy) = (ex as i32, ey as i32);
        let (mut peak, mut sum, mut cnt) = (0u8, 0u64, 0u64);
        for dy in -r..=r {
            for dx in -r..=r {
                let (x, y) = (cx + dx, cy + dy);
                if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                    let v = grey[(y as u32 * w + x as u32) as usize];
                    peak = peak.max(v);
                    sum += v as u64;
                    cnt += 1;
                }
            }
        }
        if cnt == 0 {
            0.0
        } else {
            peak as f32 - sum as f32 / cnt as f32
        }
    };
    at(landmarks[0]).max(at(landmarks[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};

    /// Serializes access to process-wide env vars (`IRLUME_GRACE_MS`,
    /// `IRLUME_STATE_DIR`, `IRLUME_METHOD_CONF`, ...) across this binary's
    /// parallel test threads. Engine tests share it via `super::tests`.
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn unit(mut v: Vec<f32>) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-9;
        v.iter_mut().for_each(|x| *x /= n);
        v
    }

    /// Profile whose scans carry paired RGB/IR embeddings shaped like real
    /// enrollment data: one identity base pattern, small per-scan noise, and
    /// a consistent spectral-shift direction between the two domains. The
    /// fitted calibration's job is to remove that shift.
    fn calibrated_profile(dim: usize) -> (FaceProfile, Vec<f32>) {
        let mk = |i: usize, spectral: f32| -> Vec<f32> {
            unit(
                (0..dim)
                    .map(|j| {
                        let base = (j as f32 * 0.7).sin();
                        let noise = 0.05 * (i as f32 * 1.3 + j as f32).sin();
                        let shift = spectral * (j as f32 * 0.9).cos();
                        base + noise + shift
                    })
                    .collect(),
            )
        };
        let ir_rows: Vec<Vec<f32>> = (0..5).map(|i| mk(i, 0.4)).collect();
        let rgb_rows: Vec<Vec<f32>> = (0..5).map(|i| mk(i, -0.4)).collect();
        let calib = irlume_core::calib::fit(&ir_rows, &rgb_rows);
        assert!(calib.is_some());
        let scans = ir_rows
            .iter()
            .zip(&rgb_rows)
            .map(|(ir, rgb)| FaceScan {
                name: "s".into(),
                rgb: rgb.clone(),
                ir: Some(ir.clone()),
                ir_space: Some("raw".into()),
                ir_depth: 0.0,
                ir_brightness: 0.0,
                pitch: 0.0,
            })
            .collect();
        // an unseen genuine IR probe: same identity base, fresh noise
        let probe = mk(6, 0.4);
        (
            FaceProfile {
                name: "p".into(),
                scans,
                ir_calib: calib,
            },
            probe,
        )
    }

    #[test]
    fn ir_match_uses_calibration_and_scores_centroid() {
        let (prof, probe) = calibrated_profile(16);
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        let raw = ir_match_in("raw", false, &enr, &probe);
        assert_eq!(raw.n_templates, 5);
        let (cs, who) = raw.centroid.as_ref().expect("centroid expected");
        assert_eq!(who, "p");
        assert!(cs.is_finite() && raw.best.is_finite());
        // Calibrated genuine matching must stay strong (efficacy across
        // conditions is proven in calib.rs and the offline prototype; here
        // probe and templates share a condition, so raw is already high and
        // the wiring must not degrade it).
        assert!(raw.best > 0.8, "calibrated best degraded: {}", raw.best);
        assert!(*cs > 0.8, "centroid degraded: {cs}");
        // With the adapter loaded the calibration must be ignored entirely.
        let with_adapter = ir_match_in("raw", true, &enr, &probe);
        assert!(with_adapter.centroid.is_none());
        assert!(with_adapter.best.is_finite());
    }

    fn denied(kind: OutcomeKind, reason: &str, live: bool) -> Outcome {
        Outcome {
            granted: false,
            live,
            score: 0.0,
            reason: reason.into(),
            kind,
        }
    }

    /// The prefix contract `presence_retryable` used before `Outcome.kind`
    /// existed, kept as the regression oracle: every (kind, reason) pair the
    /// engine can produce must classify the same way under both.
    fn legacy_prefix_retryable(o: &Outcome) -> bool {
        !o.granted
            && !o.live
            && (o.reason.starts_with("no face:")
                || o.reason.starts_with("liveness Uncertain:")
                || o.reason.starts_with("dark liveness Uncertain:")
                || o.reason.starts_with("liveness Spoof: no face in IR"))
    }

    /// Assert both the typed and the legacy prefix classification.
    fn assert_retryable(o: &Outcome, expected: bool) {
        assert_eq!(presence_retryable(o), expected, "kind path: {}", o.reason);
        assert_eq!(
            legacy_prefix_retryable(o),
            expected,
            "string<->kind drift: {}",
            o.reason
        );
    }

    #[test]
    fn grace_window_shorter_for_sudo_than_login() {
        // Env override off for this check (guarded: another test sets it).
        let _g = env_guard();
        std::env::remove_var("IRLUME_GRACE_MS");
        assert_eq!(grace_window_ms(Some("sudo")), SUDO_GRACE_WINDOW_MS);
        assert_eq!(grace_window_ms(Some("su")), SUDO_GRACE_WINDOW_MS);
        // Login/lock services and an unknown/absent service get the full window.
        assert_eq!(grace_window_ms(Some("plasmalogin")), GRACE_WINDOW_MS);
        assert_eq!(grace_window_ms(Some("kde")), GRACE_WINDOW_MS);
        assert_eq!(grace_window_ms(Some("gdm-password")), GRACE_WINDOW_MS);
        assert_eq!(grace_window_ms(None), GRACE_WINDOW_MS);
    }

    #[test]
    fn grace_retries_only_presence_failures() {
        use irlume_liveness::Verdict;
        // Retryable: the user simply was not usably in frame yet. Strings are
        // built exactly as the authenticate path builds them, and kinds come
        // from the same classifier the construction sites use, so this test
        // pins string<->kind agreement (via `assert_retryable`'s legacy
        // prefix oracle).
        assert_retryable(
            &denied(OutcomeKind::NoFace, "no face: no face in RGB", false),
            true,
        );
        assert_retryable(
            &denied(
                liveness_deny_kind(Verdict::Uncertain, "not facing the camera"),
                &format!("liveness {:?}: not facing the camera", Verdict::Uncertain),
                false,
            ),
            true,
        );
        assert_retryable(
            &denied(
                OutcomeKind::Uncertain,
                &format!("dark liveness {:?}: one-sided", Verdict::Uncertain),
                false,
            ),
            true,
        );
        // Retryable: the RGB-yes/IR-no transient a genuine user produces while
        // settling into frame (safe: a real screen never grows an IR face).
        assert_retryable(
            &denied(
                liveness_deny_kind(Verdict::Spoof, "no face in IR: a real face reflects 850nm"),
                &format!(
                    "liveness {:?}: no face in IR: a real face reflects 850nm",
                    Verdict::Spoof
                ),
                false,
            ),
            true,
        );
        // NEVER retryable: a real spoof verdict (flat/2D, free attack retries)...
        assert_retryable(
            &denied(
                liveness_deny_kind(Verdict::Spoof, "flat 2D surface"),
                &format!("liveness {:?}: flat 2D surface", Verdict::Spoof),
                false,
            ),
            false,
        );
        assert_retryable(
            &denied(
                OutcomeKind::Spoof,
                &format!("dark liveness {:?}: flat", Verdict::Spoof),
                false,
            ),
            false,
        );
        // ...a real match verdict below threshold (FAR multiplication)...
        assert_retryable(
            &Outcome::deny_live(
                OutcomeKind::BelowThreshold,
                0.23,
                "below threshold (rgb 0.23, fusion+ir-fallback miss)",
            ),
            false,
        );
        assert_retryable(
            &Outcome::deny_live(OutcomeKind::BelowThreshold, 0.1, "below threshold (ir)"),
            false,
        );
        // ...pre-camera refusals and grants.
        assert_retryable(
            &denied(OutcomeKind::OtherDeny, "'u' is not enrolled", false),
            false,
        );
        assert_retryable(
            &denied(
                OutcomeKind::OtherDeny,
                "face disabled (fingerprint mode)",
                false,
            ),
            false,
        );
        assert_retryable(&Outcome::grant(0.9, "match: p (rgb)"), false);
    }

    #[test]
    fn ir_match_skips_foreign_space_templates() {
        let (mut prof, probe) = calibrated_profile(16);
        for s in &mut prof.scans {
            s.ir_space = Some("adapter:deadbeef0123".into());
        }
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        let m = ir_match_in("raw", false, &enr, &probe);
        assert_eq!(m.n_templates, 0);
        assert!(m.centroid.is_none());
    }

    fn scan(v: Vec<f32>) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: v,
            ir: None,
            ir_space: None,
            ir_depth: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        }
    }

    #[test]
    fn frontal_signals_gates_capture() {
        let s = |yaw: f32, pitch: f32| Signals {
            head_yaw_asym: yaw,
            head_pitch_frac: pitch,
            ..Default::default()
        };
        // Uncalibrated (None) → wide bootstrap band [0.28, 0.75].
        assert!(
            frontal_signals(&s(0.0, 0.50), None),
            "square-on should pass"
        );
        assert!(
            frontal_signals(&s(0.20, 0.72), None),
            "a low laptop-cam neutral still bootstraps"
        );
        assert!(
            !frontal_signals(&s(0.45, 0.50), None),
            "clearly turned is rejected"
        );
        assert!(
            !frontal_signals(&s(0.0, 0.20), None),
            "looking up is rejected"
        );
        assert!(
            !frontal_signals(&s(0.0, 0.82), None),
            "clearly looking down is rejected"
        );
        // Calibrated to a high (laptop-biased) neutral 0.62 → band recentres to
        // 0.62 ± 0.13 = [0.49, 0.75], so a level face reading 0.62 passes and a clear tilt does not.
        assert!(
            frontal_signals(&s(0.0, 0.62), Some(0.62)),
            "at the calibrated neutral passes"
        );
        assert!(
            !frontal_signals(&s(0.0, 0.40), Some(0.62)),
            "well below the neutral is rejected"
        );
    }

    #[test]
    fn frontality_hint_is_directional() {
        use irlume_vision::HeadPose;
        // Turned so the nose sits image-left (yaw_signed<0) → they're looking to
        // their right → we tell them to turn LEFT (non-mirrored capture).
        let p = HeadPose {
            yaw_asym: 0.6,
            yaw_signed: -0.6,
            pitch_frac: 0.5,
        };
        assert_eq!(
            frontality_hint(&p, None),
            "Turn your head left to face the camera"
        );
        // Nose image-right → looking to their left → turn RIGHT.
        let p = HeadPose {
            yaw_asym: 0.6,
            yaw_signed: 0.6,
            pitch_frac: 0.5,
        };
        assert_eq!(
            frontality_hint(&p, None),
            "Turn your head right to face the camera"
        );
        // Looking UP (low pitch = nose toward eye line) → lower chin.
        let p = HeadPose {
            yaw_asym: 0.0,
            yaw_signed: 0.0,
            pitch_frac: 0.10,
        };
        assert!(frontality_hint(&p, None).starts_with("Lower your chin"));
        // Looking DOWN (high pitch = nose toward mouth) → lift chin.
        let p = HeadPose {
            yaw_asym: 0.0,
            yaw_signed: 0.0,
            pitch_frac: 0.90,
        };
        assert!(frontality_hint(&p, None).starts_with("Lift your chin"));
        // Both off: the more-severe axis wins (yaw far past its limit) → yaw
        // guidance, not pitch; holds up under small bound tweaks.
        let p = HeadPose {
            yaw_asym: 0.95,
            yaw_signed: 0.95,
            pitch_frac: 0.82,
        };
        assert_eq!(
            frontality_hint(&p, None),
            "Turn your head right to face the camera"
        );
    }

    #[test]
    fn collision_blocks_same_face_in_another_profile() {
        let face1 = vec![1.0, 0.0, 0.0];
        let face2 = vec![0.0, 1.0, 0.0];
        let enr = Enrollment {
            user: "u".into(),
            require_eyes_open: false,
            require_challenge: false,
            camera_binding: None,
            profiles: vec![
                FaceProfile {
                    ir_calib: None,
                    name: "Face Profile 1".into(),
                    scans: vec![scan(face1.clone())],
                },
                FaceProfile {
                    ir_calib: None,
                    name: "Face Profile 2".into(),
                    scans: vec![scan(face2.clone())],
                },
            ],
        };
        // Adding face1 under Face Profile 2 -> flagged as belonging to Profile 1.
        assert_eq!(
            colliding_profile(&enr, &face1, Some("Face Profile 2")).map(|(n, _)| n),
            Some("Face Profile 1".to_string())
        );
        // A novel face collides with nothing.
        assert!(colliding_profile(&enr, &[0.0, 0.0, 1.0], None).is_none());
        // Same face into its OWN profile (excluded) is fine; that's improving it.
        assert!(colliding_profile(&enr, &face1, Some("Face Profile 1")).is_none());
    }

    #[test]
    fn enroll_merge_target_dispositions() {
        let face1 = vec![1.0, 0.0, 0.0];
        let face2 = vec![0.0, 1.0, 0.0];
        let novel = vec![0.0, 0.0, 1.0];
        let ir_scan = |v: Vec<f32>, space: Option<&str>| FaceScan {
            ir: Some(vec![0.5; 3]),
            ir_space: space.map(String::from),
            ..scan(v)
        };
        let enr_with = |scans: Vec<FaceScan>| {
            let mut enr = Enrollment::new("u");
            enr.profiles.push(FaceProfile {
                ir_calib: None,
                name: "P1".into(),
                scans,
            });
            enr
        };

        // Novel face: no collision, create the new profile.
        let enr = enr_with(vec![ir_scan(face1.clone(), Some("raw"))]);
        assert_eq!(enroll_merge_target(&enr, &[&novel]).unwrap(), None);

        // Same face merges into its profile regardless of IR-template state:
        // healthy current-space templates...
        assert_eq!(
            enroll_merge_target(&enr, &[&face1]).unwrap(),
            Some("P1".into())
        );
        // ...untagged legacy templates...
        let enr = enr_with(vec![ir_scan(face1.clone(), None)]);
        assert_eq!(
            enroll_merge_target(&enr, &[&face1]).unwrap(),
            Some("P1".into())
        );
        // ...templates stranded by an adapter removal (the 0.2.0 upgrade case)...
        let enr = enr_with(vec![
            ir_scan(face1.clone(), Some("adapter:deadbeef0123")),
            ir_scan(face1.clone(), Some("adapter:deadbeef0123")),
        ]);
        assert_eq!(
            enroll_merge_target(&enr, &[&face1]).unwrap(),
            Some("P1".into())
        );
        // ...or a profile that never had IR scans at all.
        let enr = enr_with(vec![scan(face1.clone())]);
        assert_eq!(
            enroll_merge_target(&enr, &[&face1]).unwrap(),
            Some("P1".into())
        );

        // Captures matching two different profiles: refused outright.
        let mut enr = enr_with(vec![ir_scan(face1.clone(), Some("adapter:deadbeef0123"))]);
        enr.profiles.push(FaceProfile {
            ir_calib: None,
            name: "P2".into(),
            scans: vec![ir_scan(face2.clone(), Some("adapter:deadbeef0123"))],
        });
        let err = enroll_merge_target(&enr, &[&face1, &face2]).unwrap_err();
        assert!(err.to_string().contains("two different profiles"));
    }

    #[test]
    fn grace_env_override_beats_the_service_table() {
        let _g = env_guard();
        // A parseable value wins for every service class.
        std::env::set_var("IRLUME_GRACE_MS", "1234");
        assert_eq!(grace_window_ms(Some("sudo")), 1234);
        assert_eq!(grace_window_ms(Some("plasmalogin")), 1234);
        assert_eq!(grace_window_ms(None), 1234);
        // 0 = legacy one-shot.
        std::env::set_var("IRLUME_GRACE_MS", "0");
        assert_eq!(grace_window_ms(None), 0);
        // Unparseable values fall back to the service table.
        std::env::set_var("IRLUME_GRACE_MS", "abc");
        assert_eq!(grace_window_ms(Some("sudo")), SUDO_GRACE_WINDOW_MS);
        assert_eq!(grace_window_ms(None), GRACE_WINDOW_MS);
        std::env::set_var("IRLUME_GRACE_MS", "");
        assert_eq!(grace_window_ms(Some("su-l")), SUDO_GRACE_WINDOW_MS);
        // Negative numbers don't parse as u64 either.
        std::env::set_var("IRLUME_GRACE_MS", "-5");
        assert_eq!(grace_window_ms(Some("runuser")), SUDO_GRACE_WINDOW_MS);
        std::env::remove_var("IRLUME_GRACE_MS");
    }

    #[test]
    fn pitch_band_recentres_on_a_calibrated_neutral() {
        // Uncalibrated: the wide bootstrap band.
        assert_eq!(pitch_band(None), (FRAME_PITCH_MIN, FRAME_PITCH_MAX));
        // Calibrated: neutral ± PITCH_TOL, tighter than the bootstrap band.
        let (lo, hi) = pitch_band(Some(0.62));
        assert!((lo - (0.62 - PITCH_TOL)).abs() < 1e-6);
        assert!((hi - (0.62 + PITCH_TOL)).abs() < 1e-6);
        assert!(hi - lo < FRAME_PITCH_MAX - FRAME_PITCH_MIN);
    }

    #[test]
    fn threshold_ladder_orderings_the_decision_paths_rely_on() {
        use irlume_core::*;
        // The adapter space uses a lower bar than raw IR (its scores are
        // recalibrated), and the mixed-light IR fallback is stricter than the
        // dark path by exactly the margin.
        // Constant relations the decision paths assume; checked at compile time.
        const { assert!(IR_ADAPTED_MATCH_THRESHOLD < IR_MATCH_THRESHOLD) };
        const { assert!(IR_FALLBACK_MARGIN > 0.0) };
        for n in [1usize, 5, 30, 90] {
            let dark = scaled_threshold(IR_MATCH_THRESHOLD, n);
            assert!(dark >= IR_MATCH_THRESHOLD);
            assert!((dark + IR_FALLBACK_MARGIN) > dark);
            // Scaling never exceeds base + cap.
            assert!(dark <= IR_MATCH_THRESHOLD + TEMPLATE_SCALE_MAX_BUMP + 1e-6);
        }
        // More templates never lowers the bar (best-of-N FAR compensation).
        assert!(
            scaled_threshold(RGB_MATCH_THRESHOLD, 30) >= scaled_threshold(RGB_MATCH_THRESHOLD, 5)
        );
    }

    #[test]
    fn fusion_decision_table_matches_the_stage2_gate() {
        use irlume_core::fusion::*;
        // Both modalities strong at full quality: grant, prob = weighted mean.
        let f = fuse(0.9, 1.0, 0.8, 1.0);
        assert!(f.grant);
        assert!((f.prob - 0.85).abs() < 1e-6);
        // One modality at pure-noise probability vetoes the grant even when the
        // other is certain (anti single-modality-spoof floor).
        let f = fuse(0.99, 1.0, FUSION_MIN_PER_MODALITY_PROB - 0.01, 1.0);
        assert!(!f.grant);
        // No IR capture (weight 0) never grants, whatever the probabilities.
        let f = fuse(0.99, 1.0, 0.99, 0.0);
        assert!(!f.grant);
        // Boundary: the fused probability at exactly the threshold grants (>=).
        let f = fuse(FUSION_PROB_THRESHOLD, 1.0, FUSION_PROB_THRESHOLD, 1.0);
        assert!(f.grant);
        // Quality weighting: dim RGB shifts the fused prob toward IR.
        let dim = fuse(
            0.2,
            rgb_quality_weight(0.0),
            0.9,
            ir_quality_weight(true, 120.0),
        );
        let lit = fuse(
            0.2,
            rgb_quality_weight(200.0),
            0.9,
            ir_quality_weight(true, 120.0),
        );
        assert!(dim.prob > lit.prob, "{} vs {}", dim.prob, lit.prob);
    }

    #[test]
    fn ir_match_quarantines_wrong_dimension_templates() {
        let (prof, probe) = calibrated_profile(16);
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        // A probe of a different width matches nothing (adapter-contract change).
        let short_probe = vec![0.5f32; 8];
        let m = ir_match_in("raw", false, &enr, &short_probe);
        assert_eq!(m.n_templates, 0);
        assert!(m.centroid.is_none());
        assert_eq!(m.best, f32::NEG_INFINITY);
        // The right width still matches.
        assert_eq!(ir_match_in("raw", false, &enr, &probe).n_templates, 5);
    }

    #[test]
    fn ir_match_grandfathers_untagged_templates_into_any_space() {
        let (mut prof, probe) = calibrated_profile(16);
        for s in &mut prof.scans {
            s.ir_space = None; // pre-tagging enrollment
        }
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        for space in ["raw", "adapter:deadbeef0123"] {
            let m = ir_match_in(space, false, &enr, &probe);
            assert_eq!(m.n_templates, 5, "untagged templates must match in {space}");
        }
    }

    #[test]
    fn ir_match_uncalibrated_profile_scores_raw_and_names_the_winner() {
        // Two profiles without calibration: plain cosine, winner labelled.
        let a = unit(vec![1.0, 0.0, 0.0, 0.0]);
        let b = unit(vec![0.0, 1.0, 0.0, 0.0]);
        let mk_prof = |name: &str, v: &[f32]| FaceProfile {
            name: name.into(),
            ir_calib: None,
            scans: vec![FaceScan {
                name: "s".into(),
                rgb: vec![0.0; 4],
                ir: Some(v.to_vec()),
                ir_space: Some("raw".into()),
                ir_depth: 0.0,
                ir_brightness: 0.0,
                pitch: 0.0,
            }],
        };
        let mut enr = Enrollment::new("u");
        enr.profiles.push(mk_prof("A", &a));
        enr.profiles.push(mk_prof("B", &b));
        let m = ir_match_in("raw", false, &enr, &b);
        assert_eq!(m.n_templates, 2);
        assert_eq!(m.best_who, "B");
        assert!((m.best - 1.0).abs() < 1e-5);
        // No calibration anywhere -> no centroid protocol.
        assert!(m.centroid.is_none());
    }

    #[test]
    fn luma_in_bbox_means_and_clamps() {
        // 4x4 frame: left half black, right half (100,100,100).
        let (w, h) = (4u32, 4u32);
        let mut rgb = vec![0u8; (w * h * 3) as usize];
        for y in 0..h {
            for x in 2..w {
                let i = ((y * w + x) * 3) as usize;
                rgb[i] = 100;
                rgb[i + 1] = 100;
                rgb[i + 2] = 100;
            }
        }
        // Right half only: BT.601 luma of (100,100,100) is 100.
        assert!((luma_in_bbox(&rgb, w, h, &[2.0, 0.0, 4.0, 4.0]) - 100.0).abs() < 0.5);
        // Whole frame: half black, half 100 -> 50.
        assert!((luma_in_bbox(&rgb, w, h, &[0.0, 0.0, 4.0, 4.0]) - 50.0).abs() < 0.5);
        // A bbox hanging off the frame clamps instead of reading out of bounds.
        assert!((luma_in_bbox(&rgb, w, h, &[-10.0, -10.0, 100.0, 100.0]) - 50.0).abs() < 0.5);
        // Zero-area region -> 0.
        assert_eq!(luma_in_bbox(&rgb, w, h, &[1.0, 1.0, 1.0, 1.0]), 0.0);
    }

    #[test]
    fn rgb_luma_stats_reports_mean_and_hot_fraction() {
        // 2x2: three black pixels + one blown-out white one.
        let (w, h) = (2u32, 2u32);
        let mut rgb = vec![0u8; 12];
        rgb[0] = 255;
        rgb[1] = 255;
        rgb[2] = 255;
        let (mean, hot) = rgb_luma_stats(&rgb, w, h, &[0.0, 0.0, 2.0, 2.0]);
        assert!((mean - 63.75).abs() < 1.0, "mean {mean}");
        assert!((hot - 0.25).abs() < 1e-6, "hot {hot}");
        // No blown pixels -> hot fraction 0.
        let grey = vec![128u8; 12];
        let (_, hot) = rgb_luma_stats(&grey, w, h, &[0.0, 0.0, 2.0, 2.0]);
        assert_eq!(hot, 0.0);
        // Degenerate region -> (0, 0).
        assert_eq!(
            rgb_luma_stats(&rgb, w, h, &[1.0, 1.0, 1.0, 1.0]),
            (0.0, 0.0)
        );
    }

    #[test]
    fn mean_in_bbox_averages_and_clamps() {
        let (w, h) = (4u32, 2u32);
        let grey = [10u8, 20, 30, 40, 50, 60, 70, 80];
        assert!((mean_in_bbox(&grey, w, h, &[0.0, 0.0, 4.0, 2.0]) - 45.0).abs() < 1e-4);
        assert!((mean_in_bbox(&grey, w, h, &[0.0, 0.0, 2.0, 1.0]) - 15.0).abs() < 1e-4);
        // Out-of-frame bbox clamps to the frame.
        assert!((mean_in_bbox(&grey, w, h, &[-9.0, -9.0, 99.0, 99.0]) - 45.0).abs() < 1e-4);
        assert_eq!(mean_in_bbox(&grey, w, h, &[3.0, 1.0, 3.0, 1.0]), 0.0);
        // A frame shorter than w*h (truncated/mismatched capture) must degrade
        // to 0.0, not panic on the out-of-bounds index.
        assert_eq!(mean_in_bbox(&grey[..3], w, h, &[0.0, 0.0, 4.0, 2.0]), 0.0);
    }

    #[test]
    fn center_edge_ratio_reads_depth_from_center_emphasis() {
        let (w, h) = (40u32, 40u32);
        let bbox = [0.0f32, 0.0, 40.0, 40.0];
        // Emitter-lit 3D face: the center quarter markedly brighter than the rim.
        let mut face = vec![40u8; (w * h) as usize];
        for y in 10..30 {
            for x in 10..30 {
                face[(y * w + x) as usize] = 200;
            }
        }
        let deep = center_edge_ratio(&face, w, h, &bbox);
        assert!(deep > 1.5, "center-lit face must read deep, got {deep}");
        // Flat 2D surface (screen/photo): uniform -> ratio ~1.
        let flat = vec![120u8; (w * h) as usize];
        let flat_r = center_edge_ratio(&flat, w, h, &bbox);
        assert!((flat_r - 1.0).abs() < 0.05, "flat ratio {flat_r}");
        assert!(deep > flat_r, "monotonic: 3D > 2D");
        // Degenerate boxes and black frames return 0 (no signal, never inf).
        assert_eq!(center_edge_ratio(&face, w, h, &[0.0, 0.0, 3.0, 3.0]), 0.0);
        let black = vec![0u8; (w * h) as usize];
        assert_eq!(center_edge_ratio(&black, w, h, &bbox), 0.0);
    }

    /// 64x48 IR frame with optional specular glints at the two eye landmarks.
    fn ir_frame_with_glints(left: bool, right: bool) -> (Vec<u8>, Landmarks5) {
        let (w, h) = (64usize, 48usize);
        let mut grey = vec![60u8; w * h];
        let lm: Landmarks5 = [
            (20.0, 20.0),
            (44.0, 20.0),
            (32.0, 28.0),
            (24.0, 36.0),
            (40.0, 36.0),
        ];
        if left {
            grey[20 * w + 20] = 250;
        }
        if right {
            grey[20 * w + 44] = 250;
        }
        (grey, lm)
    }

    #[test]
    fn eye_glint_finds_the_specular_peak() {
        let (grey, lm) = ir_frame_with_glints(true, true);
        assert_eq!(eye_glint(&grey, 64, 48, &lm), 250.0);
        // No glint: the diffuse background level is the peak.
        let (grey, lm) = ir_frame_with_glints(false, false);
        assert_eq!(eye_glint(&grey, 64, 48, &lm), 60.0);
        // Landmarks fully outside the frame: nothing sampled, peak 0.
        let far: Landmarks5 = [(-500.0, -500.0); 5];
        assert_eq!(eye_glint(&grey, 64, 48, &far), 0.0);
    }

    #[test]
    fn both_eyes_open_requires_a_glint_at_each_eye() {
        let (grey, lm) = ir_frame_with_glints(true, true);
        assert!(both_eyes_open(&grey, 64, 48, &lm));
        // One closed lid (no specular point) fails the gate, conservatively.
        let (grey, lm) = ir_frame_with_glints(true, false);
        assert!(!both_eyes_open(&grey, 64, 48, &lm));
        let (grey, lm) = ir_frame_with_glints(false, false);
        assert!(!both_eyes_open(&grey, 64, 48, &lm));
    }

    #[test]
    fn eye_glint_contrast_collapses_without_a_specular_spike() {
        // Sharp corneal spike on a diffuse background: high contrast.
        let (grey, lm) = ir_frame_with_glints(true, true);
        let sharp = eye_glint_contrast(&grey, 64, 48, &lm);
        assert!(sharp > 100.0, "specular contrast {sharp}");
        // Uniform lid/print: peak == mean -> contrast 0.
        let (flat, lm) = ir_frame_with_glints(false, false);
        let dull = eye_glint_contrast(&flat, 64, 48, &lm);
        assert_eq!(dull, 0.0);
        assert!(sharp > dull, "blink/liveness signal must be monotonic");
    }
}

#[cfg(test)]
mod thirdparty_cue_tests {
    use super::thirdparty_downgrades;
    use irlume_liveness::Verdict;

    #[test]
    fn fires_only_on_live_plus_confident_fake() {
        assert!(thirdparty_downgrades(Verdict::Live, Some(0.9), 0.5));
        assert!(thirdparty_downgrades(Verdict::Live, Some(0.5), 0.5)); // at threshold
        assert!(!thirdparty_downgrades(Verdict::Live, Some(0.49), 0.5));
        assert!(!thirdparty_downgrades(Verdict::Live, None, 0.5));
    }

    #[test]
    fn never_touches_a_non_live_verdict() {
        // The deny-only property: a gate rejection or non-response stands even
        // if the cue is confident the presentation is genuine or a spoof; the
        // cue can tighten the gate, never loosen or reshape it.
        for v in [Verdict::Spoof, Verdict::Uncertain] {
            for p in [None, Some(0.0), Some(0.49), Some(0.5), Some(1.0)] {
                assert!(!thirdparty_downgrades(v, p, 0.5));
            }
        }
    }
}

/// Engine tests against the REAL shipped models (Git LFS under `models/`), with
/// the camera devices pointed at nonexistent nodes so no capture can ever run:
/// everything from the capture boundary inward errors with "no camera found",
/// and everything decided BEFORE the camera (enrollment state, bindings,
/// policy, builder wiring) is asserted for real. The engine is expensive to
/// build (the 512-D recognizer session), so one instance is shared.
#[cfg(test)]
mod engine_tests {
    use super::tests::env_guard;
    use super::*;
    use irlume_core::storage::{CameraBinding, Enrollment, FaceProfile, FaceScan};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    const NO_RGB: &str = "/dev/irlume-test-none-rgb";
    const NO_IR: &str = "/dev/irlume-test-none-ir";

    fn model_path(name: &str) -> String {
        format!("{}/../../models/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Point `ort` (load-dynamic) at the packaged onnxruntime when the test
    /// env doesn't already provide `ORT_DYLIB_PATH`.
    fn ort_init() {
        if std::env::var_os("ORT_DYLIB_PATH").is_some() {
            return;
        }
        for cand in [
            "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
            "/usr/lib64/libonnxruntime.so",
            "/usr/lib/libonnxruntime.so",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
        ] {
            if std::path::Path::new(cand).exists() {
                std::env::set_var("ORT_DYLIB_PATH", cand);
                return;
            }
        }
    }

    struct Shared {
        engine: Engine,
        /// `ir_space()` observed right after loading a real adapter file, for
        /// the digest-naming assertion (the shared engine then reverts to raw).
        adapter_space: String,
    }

    /// LOCK ORDER: every engine test takes env_guard() FIRST, then shared().
    /// The initializer itself must NOT lock (the caller already holds the env
    /// guard, and std Mutex is not reentrant); it only touches env vars no
    /// other test reads (`IRLUME_FORCE_NO_IR`, `ORT_DYLIB_PATH`).
    fn shared() -> MutexGuard<'static, Shared> {
        static S: OnceLock<Mutex<Shared>> = OnceLock::new();
        S.get_or_init(|| {
            ort_init();
            // Deterministic hardware probe on any machine: no IR pair, so the
            // engine sits in convenience tier. Left set for the whole process.
            std::env::set_var("IRLUME_FORCE_NO_IR", "1");
            let e = Engine::load(
                &model_path("face_detection_yunet_2023mar.onnx"),
                &model_path("glintr100.onnx"),
            )
            .expect("engine load")
            .with_devices(NO_RGB, NO_IR);
            // Absent optional model files are a no-op for every builder.
            let e = e
                .with_ir_adapter("/nonexistent/adapter.onnx")
                .unwrap()
                .with_mesh("/nonexistent/mesh.onnx")
                .unwrap()
                .with_blaze_rescue("/nonexistent/blaze.onnx")
                .unwrap()
                .with_thirdparty_pad("/nonexistent/pad.onnx", 0.5, "absent")
                .unwrap();
            assert!(
                !e.has_ir_adapter()
                    && !e.has_mesh()
                    && !e.has_blaze_rescue()
                    && !e.has_thirdparty_pad(),
                "absent model files must leave the engine bare"
            );
            assert_eq!(e.ir_space(), "raw");
            // A present adapter file flips the IR space to its digest name. Any
            // valid ONNX serves; `apply` is never called (BlazeFace here).
            let blaze = model_path("blaze_face_short_range.onnx");
            let e = e.with_ir_adapter(&blaze).unwrap();
            assert!(e.has_ir_adapter());
            let adapter_space = e.ir_space().to_string();
            let mut e = e
                .with_mesh(&model_path("face_landmark.onnx"))
                .unwrap()
                .with_blaze_rescue(&blaze)
                .unwrap()
                .with_thirdparty_pad(&blaze, 0.75, "test-pad")
                .unwrap();
            // Shared baseline is the raw (no-adapter) space; tests needing an
            // adapter set one temporarily and restore.
            e.ir_adapter = None;
            e.ir_space = "raw".into();
            Mutex::new(Shared {
                engine: e,
                adapter_space,
            })
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    }

    /// Fresh state sandbox: temp IRLUME_STATE_DIR + a method conf pointing at a
    /// missing file (=> Auto). Caller must hold the env guard.
    fn state_sandbox(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("irlume-auth-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("no-method-conf"));
        dir
    }

    fn teardown_sandbox(dir: &std::path::Path) {
        std::env::remove_var("IRLUME_STATE_DIR");
        std::env::remove_var("IRLUME_METHOD_CONF");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Write a PLAINTEXT enrollment (what a no-TPM host stores); never goes
    /// through storage::save, which would touch this machine's real TPM.
    fn write_enrollment(dir: &std::path::Path, e: &Enrollment) {
        std::fs::write(
            dir.join(format!("{}.json", e.user)),
            serde_json::to_vec(e).unwrap(),
        )
        .unwrap();
    }

    fn unit512(seed: usize) -> Vec<f32> {
        let mut v: Vec<f32> = (0..512)
            .map(|j| (j as f32 * 0.7).sin() + 0.05 * (seed as f32 * 1.3 + j as f32).sin())
            .collect();
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-9;
        v.iter_mut().for_each(|x| *x /= n);
        v
    }

    fn scan512(seed: usize, ir: bool, space: Option<&str>) -> FaceScan {
        FaceScan {
            name: format!("Face Scan {seed}"),
            rgb: unit512(seed),
            ir: ir.then(|| unit512(seed + 100)),
            ir_space: space.map(String::from),
            ir_depth: 1.3,
            ir_brightness: 90.0,
            pitch: 0.5,
        }
    }

    #[test]
    fn builder_wiring_tier_and_adapter_digest_naming() {
        let _g = env_guard();
        let s = shared();
        let e = &s.engine;
        // Forced no-IR hardware: convenience tier, no dark path.
        assert_eq!(e.tier(), Tier::Convenience);
        assert!(!e.ir_available());
        assert_eq!(e.rgb_device(), NO_RGB);
        assert_eq!(e.ir_device(), NO_IR);
        assert_eq!(e.ir_dim(), irlume_vision::EMBED_DIM);
        assert_eq!(e.ir_space(), "raw");
        // Loaded optional models.
        assert!(e.has_mesh() && e.has_blaze_rescue() && e.has_thirdparty_pad());
        assert_eq!(e.thirdparty_pad_name(), Some("test-pad"));
        // Adapter space naming: "adapter:" + first 12 hex of the file's sha256,
        // computed independently here from the same bytes.
        let bytes = std::fs::read(model_path("blaze_face_short_range.onnx")).unwrap();
        let digest = irlume_common::thirdparty::sha256_hex(&bytes);
        assert_eq!(s.adapter_space, format!("adapter:{}", &digest[..12]));
    }

    #[test]
    fn set_devices_switches_the_pair_at_runtime() {
        let _g = env_guard();
        let mut s = shared();
        s.engine
            .set_devices("/dev/irlume-test-alt-rgb", "/dev/irlume-test-alt-ir");
        assert_eq!(s.engine.rgb_device(), "/dev/irlume-test-alt-rgb");
        assert_eq!(s.engine.ir_device(), "/dev/irlume-test-alt-ir");
        s.engine.set_devices(NO_RGB, NO_IR); // restore the shared baseline
    }

    #[test]
    fn refit_profile_calib_fits_skips_and_defers_to_the_adapter() {
        let _g = env_guard();
        let mut s = shared();
        // Healthy paired 512-D scans in the current space: calibration fits.
        let mut prof = FaceProfile {
            name: "p".into(),
            ir_calib: None,
            scans: (0..5).map(|i| scan512(i, true, Some("raw"))).collect(),
        };
        s.engine.refit_profile_calib(&mut prof);
        let calib = prof.ir_calib.as_ref().expect("calibration fitted");
        assert_eq!(calib.fitted_pairs, 5);
        // Wrong-dimension IR templates are quarantined: nothing to fit.
        let mut bad = FaceProfile {
            name: "bad".into(),
            ir_calib: None,
            scans: (0..5)
                .map(|i| FaceScan {
                    ir: Some(vec![0.1; 256]),
                    ..scan512(i, true, Some("raw"))
                })
                .collect(),
        };
        s.engine.refit_profile_calib(&mut bad);
        assert!(bad.ir_calib.is_none());
        // Foreign-space templates (stranded by an adapter change) are skipped.
        let mut foreign = FaceProfile {
            name: "foreign".into(),
            ir_calib: None,
            scans: (0..5)
                .map(|i| scan512(i, true, Some("adapter:deadbeef0123")))
                .collect(),
        };
        s.engine.refit_profile_calib(&mut foreign);
        assert!(foreign.ir_calib.is_none());
        // With a global adapter loaded, refit is a no-op: an existing
        // calibration is left untouched and none is fitted.
        let adapter = Adapter::load_from_file(&model_path("blaze_face_short_range.onnx")).unwrap();
        s.engine.ir_adapter = Some(adapter);
        let before = prof.ir_calib.clone().unwrap();
        s.engine.refit_profile_calib(&mut prof);
        assert_eq!(
            prof.ir_calib.as_ref().map(|c| c.fitted_pairs),
            Some(before.fitted_pairs),
            "adapter mode must not refit"
        );
        let mut fresh = FaceProfile {
            name: "fresh".into(),
            ir_calib: None,
            scans: (0..5).map(|i| scan512(i, true, Some("raw"))).collect(),
        };
        s.engine.refit_profile_calib(&mut fresh);
        assert!(fresh.ir_calib.is_none(), "adapter mode must not fit anew");
        s.engine.ir_adapter = None; // restore the shared baseline
    }

    #[test]
    fn binding_mismatch_refuses_swapped_or_vanished_cameras() {
        let _g = env_guard();
        let s = shared();
        // Nonexistent devices carry no USB identity.
        let bind = s.engine.current_binding();
        assert_eq!(
            bind,
            CameraBinding {
                rgb: None,
                ir: None
            }
        );
        // Unbound sides are not checked (pre-binding enrollments keep working).
        assert_eq!(s.engine.binding_mismatch(&bind), None);
        // A bound RGB identity that no longer matches (or is gone) refuses.
        let bind = CameraBinding {
            rgb: Some("dead:beef".into()),
            ir: None,
        };
        let msg = s.engine.binding_mismatch(&bind).expect("must refuse");
        assert!(msg.contains("RGB device identity differs"), "{msg}");
        // Same for a bound IR camera that is absent now.
        let bind = CameraBinding {
            rgb: None,
            ir: Some("dead:beef".into()),
        };
        let msg = s.engine.binding_mismatch(&bind).expect("must refuse");
        assert!(msg.contains("IR camera changed or absent"), "{msg}");
    }

    #[test]
    fn authenticate_refuses_before_the_camera_on_state_and_policy() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("auth");

        // Fingerprint mode: face declines instantly (pam_fprintd drives).
        std::fs::write(dir.join("method"), "fingerprint").unwrap();
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("method"));
        let o = s.engine.authenticate("anyone", Some("sudo")).unwrap();
        assert!(!o.granted && !o.live);
        assert_eq!(o.reason, "face disabled (fingerprint mode)");
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("no-method-conf"));

        // Unknown user.
        let o = s.engine.authenticate("irlume-test-ghost", None).unwrap();
        assert!(!o.granted);
        assert_eq!(o.reason, "'irlume-test-ghost' is not enrolled");

        // Enrolled but with zero scans.
        let mut e = Enrollment::new("irlume-test-empty");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![],
            ir_calib: None,
        });
        write_enrollment(&dir, &e);
        let o = s.engine.authenticate("irlume-test-empty", None).unwrap();
        assert!(!o.granted);
        assert_eq!(o.reason, "'irlume-test-empty' has no face scans enrolled");

        // Camera binding mismatch: anti-swap refusal before any capture.
        let mut e = Enrollment::new("irlume-test-bound");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
        });
        e.camera_binding = Some(CameraBinding {
            rgb: Some("dead:beef".into()),
            ir: None,
        });
        write_enrollment(&dir, &e);
        let o = s.engine.authenticate("irlume-test-bound", None).unwrap();
        assert!(!o.granted && !o.live);
        assert!(
            o.reason.contains("camera changed since enrollment"),
            "{}",
            o.reason
        );

        // A healthy enrollment reaches the capture boundary, which fails hard
        // on the nonexistent device (never a silent grant/deny).
        let mut e = Enrollment::new("irlume-test-cam");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
        });
        write_enrollment(&dir, &e);
        let err = s.engine.authenticate("irlume-test-cam", None).unwrap_err();
        assert!(err.to_string().contains("no camera found"), "{err}");

        teardown_sandbox(&dir);
    }

    #[test]
    fn polkit_service_forces_the_consent_gesture_and_it_fails_closed() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("consent");

        // authenticate() derives the forced flag from the service class,
        // fresh per call, via forced_consent_for: polkit-1 sets it, sudo (and
        // None) do not.
        assert!(forced_consent_for(Some("polkit-1")));
        assert!(!forced_consent_for(Some("sudo")));
        assert!(!forced_consent_for(None));
        // Escape hatch: IRLUME_POLKIT_GESTURE=0 turns the forcing off.
        std::env::set_var("IRLUME_POLKIT_GESTURE", "0");
        assert!(!forced_consent_for(Some("polkit-1")));
        std::env::remove_var("IRLUME_POLKIT_GESTURE");

        // The shared engine runs IR-less (IRLUME_FORCE_NO_IR), where the blink
        // gate cannot run. A FORCED gate must then withdraw the grant (fail
        // closed) while the per-enrollment opt-in keeps its historical skip.
        let enr = Enrollment::new("irlume-test-consent");
        let granted = || Outcome::grant(0.9, "match");
        let out = s
            .engine
            .challenge_if_required(&enr, true, granted())
            .unwrap();
        assert!(!out.granted, "forced gate must fail closed without IR");
        assert!(out.reason.contains("consent gesture"), "{}", out.reason);
        let mut opt_in = Enrollment::new("irlume-test-consent");
        opt_in.require_challenge = true;
        let out = s
            .engine
            .challenge_if_required(&opt_in, false, granted())
            .unwrap();
        assert!(
            out.granted,
            "opt-in path keeps its skip when the gate can't run"
        );

        teardown_sandbox(&dir);
    }

    #[test]
    fn identify_respects_fingerprint_mode_and_needs_a_camera() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("identify");
        std::fs::write(dir.join("method"), "fingerprint").unwrap();
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("method"));
        let o = s.engine.identify().unwrap();
        assert!(o.user.is_none() && !o.live);
        assert_eq!(o.reason, "face disabled (fingerprint mode)");
        let o = s.engine.identify_within("someone").unwrap();
        assert!(o.user.is_none());
        assert_eq!(o.reason, "face disabled (fingerprint mode)");
        // Back in Auto, identify needs a real capture.
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("no-method-conf"));
        let err = s.engine.identify().unwrap_err();
        assert!(err.to_string().contains("no camera found"), "{err}");
        teardown_sandbox(&dir);
    }

    #[test]
    fn enroll_profile_pre_camera_guards() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("enroll");
        // Duplicate explicit profile name fails BEFORE the camera opens.
        let mut e = Enrollment::new("irlume-test-enroll");
        e.profiles.push(FaceProfile {
            name: "Work Laptop".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
        });
        write_enrollment(&dir, &e);
        let err = s
            .engine
            .enroll_profile("irlume-test-enroll", Some("Work Laptop".into()), 3)
            .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        // A novel name proceeds to the probe capture, which needs the camera.
        let err = s
            .engine
            .enroll_profile("irlume-test-enroll", Some("New Face".into()), 3)
            .unwrap_err();
        assert!(err.to_string().contains("no camera found"), "{err}");
        teardown_sandbox(&dir);
    }

    #[test]
    fn add_scan_pre_camera_guards() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("addscan");
        // Unknown user.
        let err = s.engine.add_scan("irlume-test-ghost", "P1").unwrap_err();
        assert!(err.to_string().contains("is not enrolled"), "{err}");
        // Known user, unknown profile.
        let mut e = Enrollment::new("irlume-test-add");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
        });
        write_enrollment(&dir, &e);
        let err = s.engine.add_scan("irlume-test-add", "nope").unwrap_err();
        assert!(err.to_string().contains("no face profile 'nope'"), "{err}");
        // Full profile: refused before any capture.
        let mut e = Enrollment::new("irlume-test-full");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: (0..irlume_core::storage::MAX_SCANS_PER_PROFILE)
                .map(|i| scan512(i, false, None))
                .collect(),
            ir_calib: None,
        });
        write_enrollment(&dir, &e);
        let err = s.engine.add_scan("irlume-test-full", "P1").unwrap_err();
        assert!(err.to_string().contains("already has the max"), "{err}");
        // Room in the profile: proceeds to the capture boundary.
        let err = s.engine.add_scan("irlume-test-add", "P1").unwrap_err();
        assert!(err.to_string().contains("no camera found"), "{err}");
        teardown_sandbox(&dir);
    }

    #[test]
    fn challenge_gate_only_arms_when_grant_flag_and_hardware_align() {
        let _g = env_guard();
        let mut s = shared();
        let enr_flag = |flag: bool| {
            let mut e = Enrollment::new("u");
            e.require_challenge = flag;
            e
        };
        let grant = || Outcome::grant(0.9, "match: p (rgb)");
        // A denial is never escalated into a challenge.
        let denied = Outcome::deny_live(OutcomeKind::BelowThreshold, 0.0, "below threshold (ir)");
        let o = s
            .engine
            .challenge_if_required(&enr_flag(true), false, denied)
            .unwrap();
        assert!(!o.granted);
        // Grant without the opt-in flag: passes through untouched.
        let o = s
            .engine
            .challenge_if_required(&enr_flag(false), false, grant())
            .unwrap();
        assert!(o.granted);
        // Flag on but no IR hardware (convenience tier): the blink challenge
        // cannot run; the grant stands.
        assert!(!s.engine.ir_available);
        let o = s
            .engine
            .challenge_if_required(&enr_flag(true), false, grant())
            .unwrap();
        assert!(o.granted);
        // Flag on + IR + no mesh model deployed: logged skip, grant stands.
        s.engine.ir_available = true;
        let mesh = s.engine.mesh.take();
        let o = s
            .engine
            .challenge_if_required(&enr_flag(true), false, grant())
            .unwrap();
        assert!(o.granted);
        // Flag on + IR + mesh loaded: the passive-liveness capture actually
        // runs, and fails hard without a camera (a grant is never released on
        // an unverifiable challenge).
        s.engine.mesh = mesh;
        let err = s
            .engine
            .challenge_if_required(&enr_flag(true), false, grant())
            .unwrap_err();
        assert!(err.to_string().contains("no camera found"), "{err}");
        s.engine.ir_available = false; // restore the shared baseline
    }

    #[test]
    fn passive_liveness_without_mesh_reports_no_eyes() {
        let _g = env_guard();
        let mut s = shared();
        let mesh = s.engine.mesh.take();
        let r = s.engine.run_passive_liveness().unwrap();
        assert_eq!(r, irlume_liveness::BlinkResult::NoEyes);
        s.engine.mesh = mesh;
    }

    #[test]
    fn rescue_detect_declines_faceless_frames_and_missing_models() {
        let _g = env_guard();
        let mut s = shared();
        let (w, h) = (64u32, 64u32);
        let flat = vec![127u8; (w * h * 3) as usize];
        let view = align::RgbView {
            data: &flat,
            width: w,
            height: h,
        };
        // Both rescue models loaded, but no face in the frame.
        assert!(s.engine.has_blaze_rescue() && s.engine.has_mesh());
        assert!(s.engine.rescue_detect(&view, "test").is_none());
        // With BlazeFace missing the cascade stage is simply absent.
        let blaze = s.engine.blaze.take();
        assert!(s.engine.rescue_detect(&view, "test").is_none());
        s.engine.blaze = blaze;
        // Same when only the mesh refiner is missing.
        let mesh = s.engine.mesh.take();
        assert!(s.engine.rescue_detect(&view, "test").is_none());
        s.engine.mesh = mesh;
    }

    #[test]
    fn selftests_and_position_sample_need_a_camera() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("selftest");
        for msg in [
            s.engine.liveness_selftest().unwrap_err().to_string(),
            s.engine.alignment_selftest().unwrap_err().to_string(),
            s.engine.position_sample(None).unwrap_err().to_string(),
            // The user-scoped variant first consults that user's pitch neutral.
            s.engine
                .position_sample(Some("irlume-test-ghost"))
                .unwrap_err()
                .to_string(),
        ] {
            assert!(msg.contains("no camera found"), "{msg}");
        }
        teardown_sandbox(&dir);
    }

    /// Full `authenticate()` through the LIVE capture pipeline, against the
    /// v4l2loopback feeder nodes CI provides: opens both devices, runs the
    /// parallel RGB+IR capture, detection, and the deny mapping. The ffmpeg
    /// test pattern holds no face, so the outcome must be a clean denial,
    /// not an error, with a face-shaped reason. Env-gated like the camera
    /// crate's loopback tests.
    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_authenticate_denies_without_a_face() {
        let (Ok(rgb), Ok(ir)) = (
            std::env::var("IRLUME_TEST_RGB_DEVICE"),
            std::env::var("IRLUME_TEST_IR_DEVICE"),
        ) else {
            return;
        };
        let _g = env_guard();
        ort_init();
        // Legacy one-shot: a single capture pass instead of a grace window,
        // so a no-face run finishes in one camera round.
        std::env::set_var("IRLUME_GRACE_MS", "0");
        let dir = state_sandbox("loopback-auth");
        write_enrollment(
            &dir,
            &Enrollment {
                user: "lbuser".into(),
                require_eyes_open: false,
                require_challenge: false,
                camera_binding: None,
                profiles: vec![FaceProfile {
                    ir_calib: None,
                    name: "Face Profile 1".into(),
                    scans: vec![scan512(1, false, None)],
                }],
            },
        );

        let mut e = Engine::load(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &model_path("glintr100.onnx"),
        )
        .expect("engine load")
        .with_devices(&rgb, &ir);

        let out = e
            .authenticate("lbuser", None)
            .expect("a faceless frame is a denial, not a hardware error");
        assert!(!out.granted, "no face on the feed must never grant");
        assert!(!out.live);
        let reason = out.reason.to_lowercase();
        assert!(
            reason.contains("face"),
            "denial should name the missing face, got: {}",
            out.reason
        );

        std::env::remove_var("IRLUME_GRACE_MS");
        teardown_sandbox(&dir);
    }
}
