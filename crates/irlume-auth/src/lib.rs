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

/// IR-emitter auto-setup (integrated linux-enable-ir-emitter), re-exported for
/// the daemon. See [`irlume_camera::setup_ir_emitter`].
pub use irlume_camera::{
    apply_known_ir_emitter, list_ir_controls, measure_contention, measure_contention_with_progress,
    no_progress, setup_ir_emitter, store_capture_mode, store_capture_mode_if_absent,
    stored_capture_mode, CaptureMode, ContentionReport, PairSample, Progress, StoreIfAbsent,
};
/// Auto-select the RGB+IR camera pair (built-in or external Hello webcam), plus
/// the stable per-device identity the daemon records alongside a persisted pair
/// so select_pair can survive a udev renumber. Re-exported so the daemon can pick
/// devices without depending on the camera crate directly. See
/// [`irlume_camera::select_pair`].
pub use irlume_camera::{capabilities, device_identity, select_pair};
/// Enumerate the Hello camera pairs. Re-exported for the daemon's
/// camera-class `ListCameras` arm: clients must not enumerate for themselves
/// (#187), so this is the only path to a listing.
pub use irlume_camera::{list_pairs, privacy_engaged, CameraPair};

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
    /// The recognizer's own embedding space, `"embed:<sha256 prefix>"` of its
    /// weights. Stamped onto every scan enrolled and required to match at
    /// verification: cosine scores are only meaningful inside one space.
    embed_space: String,
    /// The RGB match threshold for THIS recognizer. The shipped constant for
    /// the shipped model; a third-party recognizer brings its own measured
    /// value (#276), because a threshold is a property of one model's cosine
    /// scale and applying another model's number to it is a guess.
    rgb_threshold: f32,
    /// Name of the loaded third-party recognizer (None = shipped). Display
    /// and Health reporting only; the POLICY lives in rgb_threshold and
    /// ir_matching.
    thirdparty_recognizer: Option<String>,
    /// Whether IR matching (fusion, IR fallback, calibrated centroid, dark
    /// IR-only auth) may run. False under a third-party recognizer: the IR
    /// thresholds and the fusion Platt calibration are measurements of the
    /// SHIPPED model's cosine scale, and no catalog entry carries IR-side
    /// measurements yet. RGB-only matching stays; the dark path refuses with
    /// its own reason and falls back to the password.
    ir_matching: bool,
    /// Optional MediaPipe FaceMesh: dense landmarks for the passive EAR blink
    /// liveness (ADR-0002). Loaded iff the model file is present; `None` disables
    /// the opt-in passive-liveness gate (it can't run without landmarks).
    mesh: Option<irlume_vision::FaceMesh>,
    /// Optional BlazeFace short-range RESCUE detector: runs only when YuNet
    /// finds no face (saturated outdoor backgrounds; 2026-07-15 bench: 96.9%
    /// vs YuNet's 76.9% on the sunlight walking bursts). Needs `mesh` to
    /// refine its coarse box into alignment landmarks.
    blaze: Option<Rescue>,
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
    /// Did the pre-match consent watch see the gesture for the authentication
    /// currently in flight?
    ///
    /// Set by [`Engine::authenticate_for`] and cleared there when it returns, so
    /// it never outlives one call. It is engine state rather than a parameter
    /// because the grant sites that consult it are spread across the matcher and
    /// threading a flag through every one of them would obscure them for no gain.
    /// The gate treats `false` as "not seen yet", which is the fail-closed
    /// reading: the worst a stale `false` can do is ask for another gesture.
    gesture_seen_before_match: bool,
    /// True when a headshake was detected during the consent watch. A shake
    /// cancels the request: the user explicitly denied consent. Set in
    /// [`Self::consent_watch`], read in [`Self::consent_gesture_gate`], cleared
    /// in [`Self::authenticate_for`].
    gesture_cancelled: bool,
    /// Asked between whole captures: "should this long operation stop now?".
    ///
    /// The daemon points this at its arbiter so an enrolment yields the camera
    /// to an authentication. `None` (the CLI, tests) never stops. It is polled
    /// only at a boundary where nothing is half-written, never mid-capture and
    /// never mid-inference: stopping an operation is a scheduling decision, not
    /// a way to abandon a device or a session.
    stop_requested: Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
}

/// The rescue-slot detector (cascade stage 2): the shipped short-range
/// BlazeFace on ONNX, or an enabled third-party full-range BlazeFace running
/// its published .tflite unconverted on the bundled TFLite runtime (#295).
/// One slot, one enum: a second Option field would be the two-sources-of-
/// truth shape behind #281 and #285. The full-range variant carries its
/// catalog entry's measured threshold rather than the shipped constant,
/// because an operating point travels with the artifact it was measured on.
enum Rescue {
    ShortRange(irlume_vision::BlazeRescue),
    FullRange {
        det: irlume_vision::blaze_full::FullRangeBlaze,
        threshold: f32,
        name: String,
    },
}

impl Rescue {
    fn detect_top(
        &mut self,
        view: &align::RgbView<'_>,
    ) -> irlume_common::Result<Option<([f32; 4], f32)>> {
        match self {
            Rescue::ShortRange(b) => b.detect_top(view),
            Rescue::FullRange { det, threshold, .. } => det.detect_top_at(view, *threshold),
        }
    }
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
    pub ir_center_edge_ratio: f32,
    pub ir_brightness: f32,
    /// How much of the IR burst's lit-frame brightness the ROOM supplied:
    /// `ambient_mean / lit_mean` from the same burst. `None` when nothing
    /// OBSERVED an emitter-off frame (no camera-classified dark frame, or
    /// the RGB-only path): the fallback ambient is just the burst minimum,
    /// which converges toward the lit mean on a steady emitter and would
    /// read as "the room did it" in a pitch-dark room (#312 review). Near 0
    /// means the emitter's proven contribution lit the face; near 1 means
    /// the scene did, and such scans have never proven they work without
    /// that scene light.
    pub ir_ambient_share: Option<f32>,
    /// Mean of every byte in the RGB frame, whole-frame rather than the face
    /// region: the enrolment starvation probe needs a reading from a frame where
    /// no face was found, which is exactly when `signals.rgb_face_brightness` is
    /// 0.0 by construction. Computed with `irlume_camera::frame_mean`, the same
    /// statistic `CONCLUSIVE_SCENE_BRIGHTNESS` and `CONCURRENT_SIGNAL_FLOOR` were
    /// measured against (#389).
    pub rgb_frame_mean: f32,
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
    /// IR center/edge brightness ratio at capture (feeds the per-user floor).
    center_edge_ratio: f32,
    /// Mean IR face brightness at capture (0-255 grey).
    brightness: f32,
    /// Head pitch fraction at capture (calibrates this user's pitch neutral).
    pitch: f32,
    /// Room's share of the IR lit-frame brightness at capture
    /// ([`Assessment::ir_ambient_share`]); `None` = no emitter-off frame
    /// was observed, which never counts as ambient-lit.
    ambient_share: Option<f32>,
}

/// What one add-scan capture stored, with everything the daemon's reply
/// needs: the appended scan names (undo target), the per-recognizer counts,
/// and the ambient-lit count the completion note is built from (#312).
#[derive(Debug)]
pub struct AddScanOutcome {
    pub added_scans: Vec<String>,
    pub total: usize,
    /// Remaining scans allowed in the LOADED recognizer's space.
    pub room: usize,
    /// Scans among `added_scans` whose IR burst the room at least half lit.
    pub ambient_lit: usize,
}

/// A scan whose IR burst the ROOM at least half lit counts as ambient-lit:
/// the emitter's own proven contribution was the minority, so the scan has
/// never demonstrated it works without that scene light (#312). Anchors,
/// measured: a working emitter in a dark or indoor room reads a share near 0
/// (NexiGo ambient 0; Zenbook night bursts 0.5 ambient against 35-70 lit);
/// the #187 lockout enrolled on an emitterless USB2 Brio under daylight,
/// share near 1, and the next dark identify was denied every time.
pub const AMBIENT_LIT_SHARE: f32 = 0.5;

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

/// The longest a capture path wired through [`irlume_camera::Progress`] can go
/// without reporting watchdog progress (#336), against ANY defined camera
/// failure, a frameless device included.
///
/// The warm-up heartbeats after every completed silent window, so the silent
/// pieces left are the windows nothing reports: a post-warm-up burst dequeue
/// errors out on its FIRST timeout (one unreported window), the seam to the
/// retry then runs detection or a reopen, and the retry's own first warm-up
/// window ends with the next heartbeat. Two windows plus one seam; no code
/// path stacks a third unreported window, because every warm-up window
/// heartbeats and every burst loop propagates its first timeout.
///
/// The window term is PROVEN arithmetic (the poll timeout the camera crate
/// sets). The seam term is an ALLOWANCE, stated as such: detection and
/// embedding inference and device re-open ioctls have no deadline in code, so
/// no constant can bound them; 10s is over double the slowest full sequential
/// RGB+IR pair measured on hardware here (~3.6s, NexiGo N930W, the
/// `MAX_CROSS_SPECTRUM_SKEW` record), and the daemon test's margin sits on
/// top of it.
///
/// An `irlume-daemon` test holds this constant against the `WatchdogSec` in
/// `packaging/systemd/irlumed.service`, so lengthening a dequeue window (or
/// shrinking the watchdog) past what the other tolerates fails the suite.
pub const CAPTURE_MAX_SILENT_STRETCH_MS: u64 =
    2 * irlume_camera::CAPTURE_SILENT_WINDOW_WORST_MS + RETRY_SEAM_ALLOWANCE_MS;

/// The seam term of [`CAPTURE_MAX_SILENT_STRETCH_MS`]; see there.
const RETRY_SEAM_ALLOWANCE_MS: u64 = 10_000;

/// How far apart the RGB and IR frames of ONE decision may be captured.
///
/// The cross-spectrum cues treat the two frames as one scene: the face must sit
/// in the same place in both, and the RGB head pose is used to judge a decision
/// made largely on the IR frame. Nothing else bounds the distance between them,
/// so this does. It is a ceiling on the pathological case, not a tuning knob:
/// the normal paths sit far below it, since the concurrent captures OVERLAP
/// (gap zero) and a sequential capture runs the two bursts back to back (the
/// windows abut, so the gap is again near zero). The distance only grows when
/// captures stack up: a hard retry of one side, or the dimming self-heal
/// recapturing RGB after IR finished. Measured worst single capture on the
/// hardware we have is the NexiGo N930W at ~3.6s for a full sequential pair, so
/// 3s of GAP between two windows means something went wrong rather than slow.
///
/// Exceeding it is [`Verdict::Uncertain`], never Spoof: a stale pair is a
/// capture fault and says nothing about the person in front of the camera. That
/// kind is presence-retryable, so the grace window just captures again.
const MAX_CROSS_SPECTRUM_SKEW: std::time::Duration = std::time::Duration::from_secs(3);

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
    // From the shared table, not a local list. The list this replaced was
    // missing `doas`, which is Elevation for the policy, so a doas prompt held
    // the camera for the 15s login window instead of the 5s one (#362).
    match service.and_then(irlume_common::pam_service::classify) {
        Some(kind) if kind.wants_short_grace() => SUDO_GRACE_WINDOW_MS,
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

/// The consent verdict once the watch's stream has ended: what the in-loop
/// cadence already found, or a gesture visible only on the COMPLETE take.
///
/// The in-loop check runs every `CHECK_EVERY` poses, so a take whose length is
/// not a multiple of it ends with unevaluated trailing poses, and a gesture
/// completing in exactly those frames was refused with whole-take evidence
/// that passes every gate (measured 2026-08-04, #101: two 20-pose windows at
/// pitch_range 0.077-0.085 against the 0.075 floor, last in-loop check at
/// pose 18; one cost a real trial its release). A pure function rather than
/// inline in `consent_watch`, because this boolean directly satisfies the
/// consent gate for credential release and a test must be able to fail if the
/// completed-take evaluation is removed.
fn completed_consent_take_hit(
    hit_in_loop: bool,
    allow_nod: bool,
    poses: &[irlume_liveness::PoseSample],
    ears: &[irlume_liveness::EarSample],
    closure_cal: Option<&irlume_liveness::ClosureCalibration>,
) -> bool {
    hit_in_loop
        || (allow_nod && irlume_liveness::detect_nod(poses) == irlume_liveness::HeadGesture::Nod)
        || closure_cal.is_some_and(|cal| {
            irlume_liveness::detect_deliberate_closure(ears, cal)
                == irlume_liveness::BlinkResult::Blinked
        })
}

/// Resolve a consent watch's verdict from what the stream reported.
///
/// `stream_hit` is `capture_ir_streaming`'s break value: `Some(true)` an accepted
/// nod/closure, `Some(false)` a head-shake decline, `None` the budget ran out with
/// no in-loop verdict. A `Some(_)` outcome is TERMINAL and returned as-is; the
/// decline in particular must never be re-examined, or a completed-take nod/closure
/// reading would overturn it into a grant. `completed_take_hit` is consulted, and
/// evaluated, ONLY for `None`: it is what closes the trailing-poses boundary the
/// in-loop cadence leaves (#101). Kept pure so a test can prove a decline stays a
/// decline; the call site's own coverage cannot reach the camera.
fn resolve_consent_watch(
    stream_hit: Option<bool>,
    completed_take_hit: impl FnOnce() -> bool,
) -> bool {
    match stream_hit {
        Some(accepted) => accepted,
        None => completed_take_hit(),
    }
}

// The consent-gesture mode is defined in irlume_common::config so the PAM module
// can name the SAME gesture it tells the user to perform; see `ConsentGesture`.
use irlume_common::config::{consent_gesture_mode, ConsentGesture};

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

/// What this authentication is FOR, which decides what has to happen on top of
/// the face match before the outcome is granted.
///
/// The caller states the purpose; the engine never infers "this is a credential
/// release" from a service name. A service string is PAM wiring (a misconfigured
/// or hostile stack can claim any name), whereas the request kind that reached
/// the daemon is structural: `UnsealPassword` releases a credential, `Authenticate`
/// does not, and nothing in between can blur the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationPurpose {
    /// Prove identity for a session (login, lock screen, sudo). Only the
    /// per-enrollment `require_challenge` opt-in adds a gate. Unchanged behaviour.
    Verify,
    /// Approve one application request (a polkit prompt). Requires the deliberate
    /// consent gesture, because the user is answering a prompt they did not type
    /// a password into.
    AppConsent,
    /// Release a stored credential: the TPM-sealed login-keyring password. A spoof
    /// here yields a reusable secret rather than one session, so by default it
    /// requires the same deliberate gesture as [`Self::AppConsent`].
    ///
    /// `temporal_challenge` carries the live `credential_release_challenge`
    /// setting (default on; see
    /// [`irlume_common::config::credential_release_challenge`]). The daemon reads
    /// it per request so a toggle needs no restart, and the engine stays free of
    /// policy lookups it cannot test in isolation.
    CredentialRelease { temporal_challenge: bool },
}

impl AuthenticationPurpose {
    /// The purpose a plain [`Engine::authenticate`] runs under: consent-class
    /// services (polkit) get [`Self::AppConsent`], everything else [`Self::Verify`].
    fn for_service(service: Option<&str>) -> Self {
        if forced_consent_for(service) {
            Self::AppConsent
        } else {
            Self::Verify
        }
    }

    /// Whether the deliberate consent gesture is required regardless of the
    /// user's per-enrollment opt-in.
    ///
    /// `service` is the PAM service name when available (e.g. `sudo`, `polkit-1`).
    /// It is consulted for per-service overrides in `settings.conf` under
    /// `service_gesture.<service>`. When absent, the per-purpose default is used.
    fn demands_gesture(self, service: Option<&str>) -> bool {
        match self {
            Self::Verify => {
                // Elevation services (sudo, su, doas) default to gesture ON.
                // The user can override per-service in settings.conf.
                service.is_some_and(|s| {
                    irlume_common::config::service_gesture(s)
                        .unwrap_or_else(|| irlume_common::config::service_gesture_default(s))
                })
            }
            Self::AppConsent => true,
            Self::CredentialRelease { temporal_challenge } => {
                // Per-service override for the credential-release path
                // (special token "credential_release"), then the global
                // credential_release_challenge fallback.
                if let Some(v) = irlume_common::config::service_gesture("credential_release") {
                    return v;
                }
                temporal_challenge
            }
        }
    }
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
/// reasons (a flat-reading face region) are NOT retried.
pub fn presence_retryable(o: &Outcome) -> bool {
    matches!(
        o.kind,
        OutcomeKind::NoFace | OutcomeKind::Uncertain | OutcomeKind::SpoofNoIrFace
    )
}

/// Start of the reason irlume-liveness produces when the IR format defines no
/// sensor ceiling. Pinned against that text by
/// `an_unmeasurable_exposure_is_not_retryable`, the same way the `no face in IR`
/// prefix below is pinned.
const EXPOSURE_UNMEASURABLE_PREFIX: &str = "IR exposure unmeasurable";

/// Kind of a non-Live cross-spectrum gate verdict on the RGB primary path.
/// The `no face in IR` reason is singled out because it is the retryable
/// RGB-yes/IR-no transient; the prefix is pinned against the string
/// irlume-liveness produces by `grace_retries_only_presence_failures`.
fn liveness_deny_kind(verdict: Verdict, reason: &str) -> OutcomeKind {
    match verdict {
        // Uncertain normally means framing or quality, which the grace window
        // retries. An unmeasurable IR format is neither: it is a property of
        // the camera that will hold for every frame, so retrying spends the
        // whole window to reach the same answer while telling the user to
        // adjust something that cannot help (#358). OtherDeny is the
        // non-retryable class for a state refusal like this.
        Verdict::Uncertain if reason.starts_with(EXPOSURE_UNMEASURABLE_PREFIX) => {
            OutcomeKind::OtherDeny
        }
        Verdict::Uncertain => OutcomeKind::Uncertain,
        Verdict::Spoof if reason.starts_with("no face in IR") => OutcomeKind::SpoofNoIrFace,
        Verdict::Spoof => OutcomeKind::Spoof,
        // Callers only classify rejections; a Live verdict never reaches here.
        Verdict::Live => OutcomeKind::OtherDeny,
    }
}

/// Which gestures a consent mode permits: `(nod, closure)`.
///
/// Extracted so the decision can be tested. It is written as POSITIVE
/// membership, never `!= Closure` / `!= Nod`: those read as YES for any state
/// that is neither, so `Misconfigured` would enable BOTH gestures, which is the
/// exact failure that state exists to prevent. A nod would then release the
/// TPM-sealed keyring secret on a system whose operator asked for eye closure
/// and mistyped it (#365).
///
/// This lived inline in `consent_gesture_inputs`, which needs an `Engine` and an
/// `Enrollment` to call, so nothing in the workspace tested it and reverting the
/// two lines left the whole suite green (#365 review).
const fn gestures_permitted_by(mode: ConsentGesture) -> (bool, bool) {
    (
        matches!(mode, ConsentGesture::Nod | ConsentGesture::Either),
        matches!(mode, ConsentGesture::Closure | ConsentGesture::Either),
    )
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
    embed_space: &str,
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
                // The RECOGNIZER produces the raw IR embedding, so a template
                // from another recognizer is in a foreign space regardless of
                // its adapter tag. This matcher feeds fusion, IR fallback, the
                // calibrated centroid, and dark IR-only auth — all of them
                // grant, so all of them get the same filter RGB matching has.
                if !irlume_core::storage::recognizer_space_matches(
                    s.embed_space.as_deref(),
                    embed_space,
                ) {
                    return None;
                }
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
        // The calibration for THIS recognizer: a profile can hold scans (and
        // calibrations) from several, and applying one model's calibration to
        // another's templates puts uninterpretable numbers into the matcher
        // (#288).
        let calib = if adapter_loaded {
            None
        } else {
            p.calib_for(embed_space)
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

/// True when the cue scored in the band where neither genuine faces nor attacks
/// were measured: above the highest genuine reading, below the deny threshold.
///
/// Nothing acts on this. It exists so an out-of-domain score is visible in the
/// log instead of silently doing nothing, because the frequency of these is what
/// says whether the cue still suits the hardware it is running on.
pub fn thirdparty_abstains(p_fake: Option<f32>, threshold: f32) -> bool {
    p_fake
        .is_some_and(|p| p >= irlume_common::thirdparty::MEASURED_GENUINE_CEILING && p < threshold)
}

/// IR availability for a caller-selected IR device path.
///
/// The path half answers #281 (the selection, not a racy probe, is the truth);
/// the forced-off half preserves `IRLUME_FORCE_NO_IR=1`, the documented
/// drop-to-convenience override, which must outrank the selection exactly as
/// it outranks `capabilities()` — the first cut of #282 overwrote it and
/// silently re-secured a forced-convenience machine whose IR node existed.
fn selected_ir_available(ir: &str) -> bool {
    ir_selection_available(
        std::path::Path::new(ir).exists(),
        irlume_camera::ir_forced_off(),
    )
}

/// The decision itself, as a value: testable without touching the
/// process-wide override the engine test suite keeps set.
fn ir_selection_available(ir_exists: bool, forced_off: bool) -> bool {
    ir_exists && !forced_off
}

/// Should a top-level Uncertain verdict deny before either matching path?
///
/// Yes for every Uncertain EXCEPT the dark-login shape: no RGB embedding
/// while an IR embedding exists. The cross-spectrum gate cannot say Live
/// without an RGB face, so that shape always arrives as Uncertain, and
/// short-circuiting it made the dark IR-only path unreachable in the exact
/// condition it exists for (#284; observed live 2026-08-05: rgb faces=0, ir
/// faces=1 at 0.92, emitter lit, denied "no face in RGB"). The dark branch
/// re-derives its own verdict via evaluate_ir_only, so nothing is granted on
/// the strength of the Uncertain that fell through.
fn uncertain_short_circuits(
    verdict: Verdict,
    has_rgb_embedding: bool,
    has_ir_embedding: bool,
) -> bool {
    let dark_login_shape = has_ir_embedding && !has_rgb_embedding;
    verdict == Verdict::Uncertain && !dark_login_shape
}

/// Highest-scoring detection: the face every pipeline stage keys on when a
/// frame holds more than one.
fn top_detection(faces: &[Detection]) -> Option<&Detection> {
    faces.iter().max_by(|a, b| a.score.total_cmp(&b.score))
}

/// Whether captures on this RGB+IR pair should run one stream at a time, and
/// where that answer came from. Order of authority: the explicit env
/// override, then what `irlume camera-tune` measured on THIS pairing
/// (cameras.conf, keyed by both camera identities; contention belongs to the
/// pairing, not to the RGB module alone), then the sequential default.
///
/// One resolver for every consumer, because the two halves of the answer must
/// agree: the ASSESS path uses it to order its reads, and the ENROLL path
/// uses it to decide whether both streams may be armed at once. When they
/// disagreed, "sequential" ordered the reads of two streams that were both
/// live anyway, which on a bandwidth-starved camera is indistinguishable
/// from concurrent (#187).
fn sequential_capture_selected(rgb_dev: &str, ir_dev: &str) -> (bool, &'static str) {
    capture_mode_decision(
        std::env::var("IRLUME_SEQUENTIAL_CAPTURE").ok().as_deref(),
        irlume_camera::stored_capture_mode(rgb_dev, ir_dev),
    )
}

/// The decision itself, pure over its two observations so every arm is
/// testable without a camera or an environment mutation: a set env var
/// decides alone (even when it says concurrent, because setting it is an
/// explicit instruction and the stored answer must not outrank it), then the
/// stored per-camera measurement, then the sequential default.
///
/// Sequential is the unmeasured fallback because the wrong-direction costs
/// are lopsided (camera-stack research, 2026-08-07). A wrong concurrent
/// default broke an enrollment outright on the Brio (#308: STREAMON
/// succeeds, no RGB frame ever arrives, the queue dies with QBUF EINVAL)
/// and dims the NexiGo's RGB to 42-56% of its real brightness in a lit
/// room without any error at all. A wrong sequential default costs 0.7 s
/// (ASUS) to 1.3 s (NexiGo) of capture latency, and only until a measured
/// verdict is stored; enrollment now probes an unmeasured pair, so most
/// installs leave this arm at their first enrollment (#340).
fn capture_mode_decision(
    env: Option<&str>,
    stored: Option<irlume_camera::CaptureMode>,
) -> (bool, &'static str) {
    match env {
        Some(v) => (v.trim() == "1", ENV_CAPTURE_MODE_SOURCE),
        None => match stored {
            Some(m) => (m == irlume_camera::CaptureMode::Sequential, "cameras.conf"),
            None => (true, "default"),
        },
    }
}

/// May the cross-spectrum self-heal recapture RGB on its own?
///
/// Pure over its five observations, so the one clause that keeps costing
/// people their enrolment is testable without a camera.
///
/// The first four are the degradation signature: the overlapped RGB frame lost
/// the face, IR kept it (so the user is present), the capture was concurrent,
/// and RGB has not already been re-fetched.
///
/// `held_sessions` is the clause this function exists for. The recapture is a
/// STANDALONE reopen of the RGB node, and enrolment holds both streams open for
/// the whole capture loop, so under held sessions it opens a device this very
/// process is already streaming. Most UVC modules permit that second open and
/// nothing is visible; a module that answers EBUSY fails the enrolment outright,
/// which is #187: a Chicony 04f2:b874 that never completed one capture cycle and
/// reported the camera busy. The hard retry a hundred lines above already
/// refuses a standalone reopen for exactly this reason and says so; this path
/// was written later and did not inherit the rule.
///
/// Skipping the recovery when sessions are held costs little: the caller is a
/// loop that captures repeatedly, so the next scan gets a fresh pair of frames
/// anyway. Authentication is unaffected — it captures one-shot, holds nothing,
/// and still self-heals exactly as before.
fn self_heal_may_recapture(
    rgb_lost_the_face: bool,
    ir_kept_the_face: bool,
    sequential: bool,
    rgb_hard_retried: bool,
    held_sessions: bool,
) -> bool {
    rgb_lost_the_face && ir_kept_the_face && !sequential && !rgb_hard_retried && !held_sessions
}

/// The `mode_source` string [`capture_mode_decision`] returns when the operator
/// set the env var. Named once so the guard that refuses to LEARN from an
/// operator-forced mode binds to the same spelling that produces it, instead of
/// two string literals that a rename would silently separate.
const ENV_CAPTURE_MODE_SOURCE: &str = "IRLUME_SEQUENTIAL_CAPTURE";

/// Consecutive dimming self-heals on one camera pairing before irlume stops
/// asking that pairing to capture concurrently (#100).
///
/// THREE, CHOSEN BY THE REPO OWNER, NOT MEASURED. Every other number this rule
/// leans on was earned on hardware and says so in its own doc comment
/// ([`irlume_camera::CONCURRENT_SIGNAL_FLOOR`] at 0.80,
/// [`irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS`] at 100.0, the NexiGo's
/// measured 42-56% retention). Nothing in this repo has ever counted self-heal
/// firings, because the only trace they leave is a `dlog!` that is off unless
/// `IRLUME_LOG` is set, so there is no rate to fit a threshold to. That is
/// precisely why every clause around this number errs toward UNDER-counting:
/// not switching costs one extra RGB capture per login, which is the behaviour
/// that already ships, while switching wrongly taxes every later capture.
const SELF_HEAL_SWITCH_AFTER: u32 = 3;

/// What one assessment observed about capturing both sensors at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // used in capture_mode_switch_tests
enum CaptureModeSignal {
    /// The overlapped RGB frame lost the face AND arrived measurably dimmer
    /// than the same camera's solo frame: the contention signature.
    Dimming,
    /// The overlapped RGB frame found the face on its own. Counter-evidence.
    Clean,
    /// Neither established: says nothing, changes nothing.
    Inconclusive,
}

/// Did this self-heal measure the fault the switch exists for?
///
/// Pure over the two RGB frame means the enrolment path already holds, so the
/// rule is testable without a camera. Two clauses, and BOTH are needed:
///
/// `recovered` alone is not the signature. `rgb_top.is_none() && ir_top.is_some()`
/// is also the shape of a legitimate DARK login, which this codebase supports on
/// purpose (see `uncertain_short_circuits`, observed live: rgb faces=0, ir
/// faces=1 at 0.92). It is equally the shape of a user still walking up, where
/// the solo recapture succeeds ~700ms later because the person stopped moving,
/// not because the link went idle. Counting either would demote a healthy camera.
///
/// So the second clause asks the question the probe asks: did the overlapped
/// frame arrive DIM? That is `CONCURRENT_SIGNAL_FLOOR`, applied to one round
/// instead of the probe's six, which is what counting to three compensates for.
/// The `CONCLUSIVE_SCENE_BRIGHTNESS` floor throws away the light level where the
/// repo has already measured this reading to be worthless: the same NexiGo read
/// 0.42-0.56 retention against a sequential arm at 117-143, then 0.91 an hour
/// later in a dark room against an arm at 62. A dark scene hides the fault, so
/// it must not be allowed to manufacture it either.
#[allow(dead_code)] // used in capture_mode_switch_tests
fn self_heal_is_dimming(recovered: bool, concurrent_mean: f32, solo_mean: f32) -> bool {
    recovered
        && solo_mean >= irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS
        && concurrent_mean < solo_mean * irlume_camera::CONCURRENT_SIGNAL_FLOOR
}

/// Fold one observation into the consecutive streak.
///
/// `Clean` resets to zero rather than merely not incrementing: a capture that
/// found the face with both sensors running is direct counter-evidence, and an
/// action that OVERWRITES an operator's measurement must not be reached by
/// summing coincidences a healthy camera produced weeks apart.
#[allow(dead_code)] // used in capture_mode_switch_tests
fn self_heal_streak(prev: u32, signal: CaptureModeSignal) -> u32 {
    match signal {
        CaptureModeSignal::Dimming => prev.saturating_add(1),
        CaptureModeSignal::Clean => 0,
        CaptureModeSignal::Inconclusive => prev,
    }
}

/// Is a switch due? Pure over the two things that decide it.
///
/// An operator-forced mode is never learned from. `IRLUME_SEQUENTIAL_CAPTURE=0`
/// is the only env value that can reach a self-heal at all (`=1` makes the
/// capture sequential, and the self-heal only runs on concurrent captures), and
/// [`capture_mode_decision`] already states the authority rule: a set env var
/// "decides alone ... because setting it is an explicit instruction and the
/// stored answer must not outrank it". Writing a persistent verdict inferred
/// from a mode the operator forced for one debugging session inverts that rule
/// from the other side: the write would sit inert while the var is set, then
/// take effect the moment it is unset.
#[allow(dead_code)] // used in capture_mode_switch_tests
fn capture_mode_switch_due(mode_source: &str, streak: u32) -> bool {
    mode_source != ENV_CAPTURE_MODE_SOURCE && streak >= SELF_HEAL_SWITCH_AFTER
}

/// The one journal line the switch leaves behind, or `None` when there is
/// nothing to say.
///
/// Pure over the write's outcome, so the wording AND the rule that a failed
/// write never fails the enrolment are both testable without a camera or root.
/// The signature is the pin: this takes a `&Result` and returns text, so there
/// is no way for the write's error to propagate into the enrolment.
fn capture_mode_switch_line(
    events: u32,
    stored: &irlume_common::Result<irlume_camera::StoreIfConcurrent>,
) -> Option<String> {
    match stored {
        Ok(irlume_camera::StoreIfConcurrent::Stored) => Some(format!(
            "capture mode switched to sequential for this camera pair after {events} consecutive \
             concurrent-capture RGB losses; captures are slower and reliable. Measure this camera \
             directly with `sudo irlume camera-tune` to replace this with a measurement."
        )),
        // Already what the switch wanted: nothing changed, nothing to announce.
        Ok(irlume_camera::StoreIfConcurrent::Superseded(Some(
            irlume_camera::CaptureMode::Sequential,
        ))) => None,
        Ok(irlume_camera::StoreIfConcurrent::Superseded(other)) => Some(format!(
            "capture mode: {events} consecutive concurrent-capture RGB losses on this camera pair, \
             but the stored verdict changed underneath ({other:?}); left it alone"
        )),
        Err(e) => Some(format!(
            "capture mode: could not persist the sequential switch for this camera pair after \
             {events} consecutive concurrent-capture RGB losses ({e}); run `sudo irlume doctor` \
             to see the mode in force"
        )),
    }
}

#[cfg(test)]
mod capture_mode_decision_tests {
    use super::{capture_mode_decision, ENV_CAPTURE_MODE_SOURCE};
    use irlume_camera::CaptureMode;

    #[test]
    fn a_set_env_var_decides_alone_in_both_directions() {
        assert_eq!(
            capture_mode_decision(Some("1"), None),
            (true, ENV_CAPTURE_MODE_SOURCE)
        );
        // Explicit concurrent outranks a stored sequential: setting the var
        // is an instruction, and a mutant that consults `stored` here would
        // sequentialize a run the operator forced concurrent.
        assert_eq!(
            capture_mode_decision(Some("0"), Some(CaptureMode::Sequential)),
            (false, ENV_CAPTURE_MODE_SOURCE)
        );
        assert_eq!(
            capture_mode_decision(Some(" 1 "), Some(CaptureMode::Concurrent)),
            (true, ENV_CAPTURE_MODE_SOURCE)
        );
    }

    #[test]
    fn the_stored_measurement_decides_when_no_env_is_set() {
        // Both directions, because a mutant flipping the comparison passes
        // any test that only checks one of them.
        assert_eq!(
            capture_mode_decision(None, Some(CaptureMode::Sequential)),
            (true, "cameras.conf")
        );
        assert_eq!(
            capture_mode_decision(None, Some(CaptureMode::Concurrent)),
            (false, "cameras.conf")
        );
    }

    #[test]
    fn nothing_stored_defaults_to_sequential() {
        // The unmeasured fallback is the safe direction (#340): a wrong
        // sequential answer costs at most 1.3 s per capture, while the old
        // concurrent fallback broke an enrollment on hardware that cannot
        // stream both nodes (#308).
        assert_eq!(capture_mode_decision(None, None), (true, "default"));
    }

    #[test]
    fn the_self_heal_never_reopens_a_camera_the_caller_is_streaming() {
        use super::self_heal_may_recapture;
        // The degradation signature, on the one-shot path the self-heal was
        // written for: RGB lost the face, IR kept it, captured concurrently,
        // nothing re-fetched yet.
        assert!(self_heal_may_recapture(true, true, false, false, false));
        // The same signature during ENROLMENT, which holds both streams open
        // for the whole capture loop. Recapturing here opens a device this
        // process is already streaming, and a module that answers EBUSY to the
        // second open fails the enrolment outright (#187). The hard retry
        // above refuses for exactly this reason; so must this.
        assert!(!self_heal_may_recapture(true, true, false, false, true));
        // The rest of the signature still has to hold.
        assert!(!self_heal_may_recapture(false, true, false, false, false));
        assert!(!self_heal_may_recapture(true, false, false, false, false));
        assert!(!self_heal_may_recapture(true, true, true, false, false));
        assert!(!self_heal_may_recapture(true, true, false, true, false));
    }

    #[test]
    fn a_stored_concurrent_verdict_outranks_the_sequential_default() {
        // Fail-closed check for the #340 flip in isolation: flipping the
        // unmeasured default must not touch what a MEASURED concurrent
        // camera does, or the flip would tax every healthy tuned install.
        assert_eq!(
            capture_mode_decision(None, Some(CaptureMode::Concurrent)),
            (false, "cameras.conf")
        );
    }
}

#[cfg(test)]
mod capture_mode_switch_tests {
    use super::*;
    use irlume_camera::{CaptureMode, StoreIfConcurrent};

    /// Both clauses are required, and neither is sufficient. The four rows are
    /// the four situations this rule exists to separate, each with numbers the
    /// repo has already measured on hardware.
    #[test]
    fn a_counted_event_needs_recovery_and_measured_dimming() {
        // The NexiGo shape: concurrent parks near 60 while the solo arm tracks
        // the lit room at 117-143. This is the fault the switch exists for.
        assert!(self_heal_is_dimming(true, 60.0, 130.0));
        // The recapture did not recover the face, so nothing was demonstrated:
        // the frame may simply not have held one.
        assert!(!self_heal_is_dimming(false, 60.0, 130.0));
        // The dark-login shape. A night login legitimately shows a face in IR
        // and none in RGB, and the same camera measured 0.91 retention in a dark
        // room, so a ratio taken here says nothing. Counting it would demote a
        // healthy camera for anyone who logs in after dark.
        assert!(!self_heal_is_dimming(true, 30.0, 62.0));
        // The healthy/settling shape: the user was still moving, and the solo
        // frame is no dimmer than the overlapped one (the ASUS measured 1.04).
        assert!(!self_heal_is_dimming(true, 125.0, 130.0));
    }

    /// Both boundaries in both directions, so a mutant that relaxes `<` to `<=`
    /// or `>=` to `>` dies, and the constants stay the camera crate's rather
    /// than drifting local copies.
    #[test]
    fn the_dimming_test_is_the_probes_own_rule_at_both_boundaries() {
        assert_eq!(irlume_camera::CONCURRENT_SIGNAL_FLOOR, 0.80);
        assert_eq!(irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS, 100.0);
        // The scene-brightness floor: a solo arm at the floor can be judged, one
        // just under it cannot.
        assert!(self_heal_is_dimming(true, 79.9, 100.0));
        assert!(!self_heal_is_dimming(true, 79.9, 99.9));
        // The retention floor: exactly 80% retained is not a loss; a hair under is.
        assert!(!self_heal_is_dimming(true, 80.0, 100.0));
        assert!(self_heal_is_dimming(true, 79.99, 100.0));
    }

    /// The threshold itself, pinned in both directions so a mutant that changes
    /// the constant OR moves the comparison dies.
    #[test]
    fn the_switch_lands_on_the_third_consecutive_event_and_not_before() {
        assert_eq!(
            SELF_HEAL_SWITCH_AFTER, 3,
            "three was chosen by the repo owner in #100; nothing here measures it"
        );
        assert_eq!(
            (0..=4)
                .map(|n| capture_mode_switch_due("cameras.conf", n))
                .collect::<Vec<_>>(),
            vec![false, false, false, true, true]
        );
        // The premise that makes the self-heal reachable at all: an unmeasured
        // pair already captures sequentially, so only a stored concurrent verdict
        // (or the env override) can put a camera where this rule applies. If that
        // default is ever flipped back, this rule needs rethinking, and this
        // assertion is where that surfaces.
        assert!(
            capture_mode_decision(None, None).0,
            "the unmeasured default is sequential"
        );
    }

    /// The three-way split matters: a mutant that folds `Inconclusive` into
    /// either neighbour changes when a camera gets demoted.
    #[test]
    fn a_clean_concurrent_capture_clears_the_streak() {
        let fold = |signals: &[CaptureModeSignal]| {
            signals
                .iter()
                .fold(0u32, |acc, s| self_heal_streak(acc, *s))
        };
        use CaptureModeSignal::{Clean, Dimming, Inconclusive};
        // Counter-evidence in the middle resets, so this never reaches three.
        assert_eq!(fold(&[Dimming, Dimming, Clean, Dimming, Dimming]), 2);
        // Inconclusive is neutral in both directions.
        assert_eq!(
            fold(&[Dimming, Inconclusive, Dimming, Inconclusive, Dimming]),
            3
        );
        assert_eq!(self_heal_streak(2, Clean), 0);
        assert_eq!(self_heal_streak(2, Inconclusive), 2);
        assert_eq!(self_heal_streak(2, Dimming), 3);
    }

    /// A mode the operator forced is never learned from, at any streak length.
    #[test]
    fn an_operator_forced_mode_is_never_written_back() {
        for n in [1, SELF_HEAL_SWITCH_AFTER, SELF_HEAL_SWITCH_AFTER + 1, 99] {
            assert!(
                !capture_mode_switch_due(ENV_CAPTURE_MODE_SOURCE, n),
                "streak {n} under an operator-forced mode must not switch"
            );
        }
        // Bind the guard to the one place that produces the string, so a rename
        // breaks this test instead of silently disabling the guard.
        assert_eq!(
            capture_mode_decision(Some("0"), Some(CaptureMode::Concurrent)).1,
            ENV_CAPTURE_MODE_SOURCE
        );
        // And the one mode the switch may act on.
        assert_eq!(
            capture_mode_decision(None, Some(CaptureMode::Concurrent)),
            (false, "cameras.conf")
        );
        assert!(capture_mode_switch_due(
            "cameras.conf",
            SELF_HEAL_SWITCH_AFTER
        ));
    }

    /// The journal line is checked by RETURN VALUE, never by capturing stderr:
    /// the debug-log switch freezes in a `OnceLock`, which is why the comparable
    /// notes in this codebase return their text instead of printing it.
    #[test]
    fn the_switch_announces_itself_and_names_the_override() {
        let line = capture_mode_switch_line(3, &Ok(StoreIfConcurrent::Stored))
            .expect("a completed switch says so");
        assert!(line.contains("sequential"), "names the new mode: {line}");
        assert!(line.contains('3'), "names the evidence: {line}");
        assert!(
            line.contains("camera-tune"),
            "names how to replace it with a measurement: {line}"
        );
    }

    /// A verdict that changed under us is left alone, and the line says which
    /// happened. Silence is only correct when the stored mode already agrees.
    #[test]
    fn a_verdict_that_changed_under_us_is_left_alone() {
        assert_eq!(
            capture_mode_switch_line(
                3,
                &Ok(StoreIfConcurrent::Superseded(Some(CaptureMode::Sequential)))
            ),
            None,
            "already sequential: nothing was done and nothing needs saying"
        );
        let line = capture_mode_switch_line(3, &Ok(StoreIfConcurrent::Superseded(None)))
            .expect("a verdict that vanished is worth a line");
        assert!(
            !line.contains("switched to sequential"),
            "must not claim a write that did not happen: {line}"
        );
    }

    /// A failed write is reported and never claims the mode changed. The
    /// signature is the real pin: taking a `&Result` and returning text means
    /// the error has no path into the enrolment's own result.
    #[test]
    fn a_failed_write_is_reported_and_never_claims_the_mode() {
        let line = capture_mode_switch_line(
            3,
            &Err(irlume_common::Error::Hardware(
                "cannot identify the RGB camera".into(),
            )),
        )
        .expect("a failed write must be visible");
        assert!(line.contains("could not persist"), "{line}");
        assert!(line.contains("cannot identify the RGB camera"), "{line}");
        assert!(
            !line.contains("switched to sequential"),
            "must not claim the switch landed: {line}"
        );
    }
}

impl Engine {
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn load(det_path: &str, model_path: &str) -> irlume_common::Result<Self> {
        // Identify the recognizer by its weights, not its path: a file swapped
        // in place under the same name is a different embedding space and must
        // not silently score against templates from the old one. Read the file
        // ONCE and hand those bytes to the weights loader below.
        let model_bytes = std::fs::read(model_path)
            .map_err(|e| irlume_common::Error::Io(format!("{model_path}: {e}")))?;
        Self::load_with_recognizer_weights(det_path, &irlume_common::HashedModel::new(model_bytes))
    }

    /// [`Self::load`], from recognizer weights the CALLER already holds.
    ///
    /// For callers that verified those weights against a pin: re-reading a path
    /// here would let a swap between their check and this load pair the new
    /// weights with a threshold measured for the old ones. The digest below
    /// would honestly tag the new space, but the POLICY attached to the engine
    /// would belong to a different artifact. One
    /// [`irlume_common::HashedModel`] flows from the caller's checksum through
    /// the embedding-space tag into the ONNX session, so the three can never
    /// disagree, and the 260MB hash happens once per start rather than once
    /// here and once at the caller (#346).
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn load_with_recognizer_weights(
        det_path: &str,
        model: &irlume_common::HashedModel,
    ) -> irlume_common::Result<Self> {
        // Full digest: the tag resists an adversarial model, and truncation
        // halves its strength per dropped character.
        let embed_space = format!("embed:{}", model.sha256());
        Ok(Self {
            det: Detector::load_from_file(det_path)?,
            emb: Embedder::load_from_memory(model.bytes())?,
            ir_adapter: None,
            ir_space: "raw".into(),
            embed_space,
            rgb_threshold: irlume_core::RGB_MATCH_THRESHOLD,
            thirdparty_recognizer: None,
            ir_matching: true,
            mesh: None,
            blaze: None,
            tp_pad: None,
            gate: LivenessGate::new(),
            rgb_dev: irlume_camera::DEFAULT_RGB_DEVICE.into(),
            ir_dev: irlume_camera::DEFAULT_IR_DEVICE.into(),
            // From the DEFAULT selection's mere existence, not a probe.
            // `capabilities()` opens every /dev/video* node to classify it, and
            // every shipped caller then chains `.with_devices(...)`, which
            // recomputes this field the non-probing way and throws the probed
            // answer away. So it was pure dead work of exactly the shape that
            // races the daemon's own capture (#187), and it used the racy
            // source #281 removed everywhere else. Same helper as
            // `with_devices`, so `IRLUME_FORCE_NO_IR=1` still outranks it.
            ir_available: selected_ir_available(irlume_camera::DEFAULT_IR_DEVICE),
            gesture_seen_before_match: false,
            gesture_cancelled: false,
            stop_requested: None,
        })
    }

    /// Point the engine at a signal asked between whole captures, so a long
    /// operation can yield the camera to an authentication.
    ///
    /// Only the daemon sets this. It is a request, not a kill: the check happens
    /// at boundaries where nothing is half-written, so a stopped operation
    /// persists nothing and the caller retries.
    pub fn set_stop_signal(&mut self, signal: std::sync::Arc<dyn Fn() -> bool + Send + Sync>) {
        self.stop_requested = Some(signal);
    }

    /// True when something has asked this operation to stop.
    fn should_stop(&self) -> bool {
        self.stop_requested.as_ref().is_some_and(|f| f())
    }

    /// Report a between-captures boundary without acting on the yield request.
    ///
    /// Polling the stop signal is what marks watchdog progress in the daemon
    /// (#141: its closure notes progress, then answers), and the grace loop
    /// needs that mark between attempts: `IRLUME_GRACE_MS` can stretch the
    /// window arbitrarily, and a window of healthy no-face captures followed
    /// by one frameless capture chain summed past `WatchdogSec` with no
    /// progress reported anywhere between (#336). The answer itself is
    /// deliberately dropped: only a queued authentication raises it, and
    /// cutting a RUNNING authentication's grace window for a queued one would
    /// hand the first user a password prompt whenever a polkit verify races
    /// the lock screen. Enrolment keeps honoring it via [`Self::should_stop`].
    fn note_capture_boundary(&self) {
        let _ = self.should_stop();
    }

    /// The per-window heartbeat handed into camera captures (#336).
    ///
    /// Polls the same daemon closure [`Self::note_capture_boundary`] does, for
    /// the same effect: the daemon marks watchdog progress on every poll, so a
    /// frameless camera reporting each returned dequeue window never looks
    /// wedged, while a driver call that never returns still does. The yield
    /// answer is dropped for the boundary's reason too, and one more: this
    /// fires INSIDE a capture, where nothing can safely stop anyway. Owned
    /// (`Arc`) so the concurrent capture pair can carry it across scoped
    /// threads without borrowing the engine.
    fn capture_progress(&self) -> irlume_camera::Progress {
        match &self.stop_requested {
            Some(f) => {
                let f = std::sync::Arc::clone(f);
                std::sync::Arc::new(move || {
                    let _ = f();
                })
            }
            None => irlume_camera::no_progress(),
        }
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
        // The caller's selection is the truth about IR availability (#281).
        // Engine::load's one-shot capabilities() probe can lose a startup race
        // against the emitter setup holding the IR node, and then the engine
        // sits in convenience tier for its whole life while the daemon logs
        // secure tier from ITS selection. The daemon already defines "usable"
        // as the selected path existing (its tier log uses exactly that), so
        // the engine adopts the same definition when devices are handed to it;
        // the NO_IR test sentinel is a nonexistent path and keeps reading as
        // unavailable, and the operator's forced-convenience override outranks
        // the selection exactly as it outranks the probe (#282 review).
        self.ir_available = selected_ir_available(ir);
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
        // Same rule as with_devices: the selection carries IR availability, so
        // a runtime camera switch to (or from) an IR-less pair retiers the
        // engine instead of trusting the load-time snapshot (#281).
        self.ir_available = selected_ir_available(ir);
    }

    /// Load the IR domain-adaptation adapter (improves dark recognition). If the
    /// file is absent this is a no-op (raw IR embeddings are used).
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_ir_adapter(mut self, path: &str) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            // One read feeds both the digest and the session, so the tag always
            // describes the weights that are running (same reasoning as the
            // recognizer in `load`). The 12-hex prefix is the format existing
            // enrollments carry in `ir_space`; changing it would orphan them.
            let bytes = std::fs::read(path)
                .map_err(|e| irlume_common::Error::Io(format!("{path}: {e}")))?;
            let digest = irlume_common::thirdparty::sha256_hex(&bytes);
            self.ir_adapter = Some(Adapter::load_from_memory(&bytes)?);
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

    /// The recognizer embedding space this engine produces and matches in.
    pub fn embed_space(&self) -> &str {
        &self.embed_space
    }

    /// Configure this engine for a THIRD-PARTY recognizer (#276 stage 4): the
    /// entry's measured RGB threshold replaces the shipped constant, and IR
    /// matching is disabled wholesale — fusion, IR fallback, the calibrated
    /// centroid, and dark IR-only auth are all measurements of the shipped
    /// model's cosine scale (thresholds and Platt calibration alike), and no
    /// catalog entry carries IR-side measurements. The liveness gate is
    /// unaffected: it reads pixels, not embeddings. Dark logins refuse with
    /// their own reason and fall back to the password.
    pub fn with_thirdparty_recognizer(mut self, rgb_threshold: f32, name: &str) -> Self {
        self.rgb_threshold = rgb_threshold;
        self.ir_matching = false;
        self.thirdparty_recognizer = Some(name.to_string());
        self
    }

    /// Name of the loaded third-party recognizer, if any; the daemon publishes
    /// this in Health so an unprivileged TUI sees the authoritative state.
    pub fn thirdparty_recognizer_name(&self) -> Option<&str> {
        self.thirdparty_recognizer.as_deref()
    }

    /// The RGB grant threshold for a comparison against `n_templates`
    /// templates: this recognizer's measured base, scaled for best-of-N FAR
    /// inflation. The ONE place both RGB match paths get their bar, so a
    /// third-party recognizer's threshold cannot reach one path and miss the
    /// other.
    fn rgb_grant_threshold(&self, n_templates: usize) -> f32 {
        irlume_core::scaled_threshold(self.rgb_threshold, n_templates)
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
        // A third-party recognizer's IR matching never runs, so fitting a
        // calibration over its embeddings would only produce an artifact that
        // LOOKS like dark support exists.
        if !self.ir_matching {
            return;
        }
        let dim = self.ir_dim();
        let (mut ir_rows, mut rgb_rows) = (Vec::new(), Vec::new());
        for s in &prof.scans {
            // A pair from another recognizer would fit one calibration across
            // incompatible embedding spaces; skip it like matching does.
            if !irlume_core::storage::recognizer_space_matches(
                s.embed_space.as_deref(),
                &self.embed_space,
            ) {
                continue;
            }
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
        // Recorded against THIS recognizer only: a single slot was overwritten
        // by whichever model happened to be loaded at refit, which silently
        // replaced the calibration of the model the user switched away from
        // (#288).
        let fitted = irlume_core::calib::fit(&ir_rows, &rgb_rows);
        if let Some(c) = &fitted {
            irlume_common::dlog!(
                "calib: fitted '{}' from {} scan pairs (space {})",
                prof.name,
                c.fitted_pairs,
                self.embed_space
            );
        }
        prof.set_calib_for(&self.embed_space, fitted);
    }

    /// Method wrapper over [`ir_match_in`], bound to the engine's space and
    /// adapter state.
    fn ir_match(&self, enr: &irlume_core::storage::Enrollment, probe: &[f32]) -> IrMatch {
        // The choke point for the third-party-recognizer policy: with IR
        // matching disabled, no caller — present or future — can score an IR
        // template, because every IR grant path funnels through here. The
        // call sites additionally check `ir_matching` where a specific
        // refusal reason is owed to the user (the dark path).
        if !self.ir_matching {
            return IrMatch {
                best: f32::NEG_INFINITY,
                best_who: String::new(),
                n_templates: 0,
                centroid: None,
            };
        }
        ir_match_in(
            &self.ir_space,
            &self.embed_space,
            self.ir_adapter.is_some(),
            enr,
            probe,
        )
    }

    /// Load MediaPipe FaceMesh for the passive EAR blink liveness (ADR-0002). If
    /// the file is absent this is a no-op; the opt-in passive gate then can't run
    /// and is skipped (logged), so face auth keeps working.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_mesh(mut self, path: &str) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.mesh = Some(irlume_vision::FaceMesh::load_from_file(path)?);
        }
        Ok(self)
    }

    /// Load the BlazeFace short-range rescue detector (improves detection on
    /// saturated outdoor frames). No-op if the file is absent.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_blaze_rescue(mut self, path: &str) -> irlume_common::Result<Self> {
        // Shipped short-range rescue (ONNX).
        if std::path::Path::new(path).exists() {
            self.blaze = Some(Rescue::ShortRange(
                irlume_vision::BlazeRescue::load_from_file(path)?,
            ));
        }
        Ok(self)
    }

    /// Wire an enabled third-party FULL-RANGE detector into the rescue slot
    /// (#295): takes the VERIFIED bytes (the daemon checked the catalog pin;
    /// the session constructor re-checks the same buffer), the entry's
    /// measured operating threshold, and its catalog name for reporting.
    /// Replaces whatever rescue was loaded: one slot, one occupant.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_full_range_rescue(
        mut self,
        bytes: &[u8],
        threshold: f32,
        name: &str,
    ) -> irlume_common::Result<Self> {
        self.blaze = Some(Rescue::FullRange {
            det: irlume_vision::blaze_full::FullRangeBlaze::from_pinned_bytes(bytes)?,
            threshold,
            name: name.to_string(),
        });
        Ok(self)
    }

    pub fn has_blaze_rescue(&self) -> bool {
        self.blaze.is_some()
    }

    /// The enabled third-party detector's catalog name, or None when the
    /// rescue slot holds the shipped short-range model (or nothing).
    pub fn thirdparty_detector_name(&self) -> Option<&str> {
        match &self.blaze {
            Some(Rescue::FullRange { name, .. }) => Some(name),
            _ => None,
        }
    }

    /// Load an opt-in third-party PAD classifier (deny-only cue on the lit IR
    /// frame). No-op if the file is absent, so a deleted model degrades to the
    /// built-in gate, never to a startup failure.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
        // (both rescue variants return the same coarse-box contract; the
        // mesh refine below is what turns either into alignment landmarks)
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
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
        let rgb = irlume_camera::capture_rgb_denoised_with_progress(
            &self.rgb_dev,
            &self.capture_progress(),
        )?;
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
            // RGB-only path: no IR frame exists to glint.
            ir_eye_glint: None,
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            ir_ambient: 0.0, // RGB-only path: no IR burst to measure
            face_frac: face_frac_of(rgb_top.as_ref().map(|f| &f.bbox), rgb.width),
            // RGB-only path: no IR frame exists to clip.
            ir_saturated_frac: None,
            ir_ceiling_known: false,
            rgb_face_brightness: rgb_brightness,
            rgb_specular_frac: rgb_specular,
            rgb_moire_score: rgb_moire,
        };
        let (verdict, _cues, reason) = self.gate.evaluate_rgb_only(&signals);
        irlume_common::dlog!(
            "liveness(rgb-only): {verdict:?} ({reason}); bright={:.0} specular={:.2} moire={:.0} face_frac={:.3} (recorded for #174, gates nothing)",
            signals.rgb_face_brightness,
            signals.rgb_specular_frac,
            signals.rgb_moire_score,
            signals.face_frac
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
            rgb_frame_mean: irlume_camera::frame_mean(&rgb.data),
            ir_embedding: None,
            signals,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            ir_ambient_share: None, // RGB-only path: no IR burst to measure
            eyes_open: false,
            thirdparty_fake: None,
        })
    }

    /// Streams held open across a run of captures, so a loop pays the open,
    /// format negotiation, buffer mapping, STREAMON and auto-exposure warm-up
    /// once instead of per capture. Measured on the ASUS built-in: ~700ms of
    /// every RGB capture is that setup.
    ///
    /// Only handed to loops that capture repeatedly under one request, never
    /// held across requests: an idle stream reserves the camera against other
    /// applications, keeps the capture LED lit, and would go stale across a
    /// suspend.
    fn assess_full(&mut self) -> irlume_common::Result<Assessment> {
        self.assess_full_with(None, None)
    }

    /// [`Self::assess_full`], optionally reusing already-streaming cameras.
    fn assess_full_with(
        &mut self,
        held: Option<(
            &mut irlume_camera::RgbSession<'_>,
            &mut irlume_camera::IrSession<'_>,
        )>,
        capture_mode: Option<(bool, &'static str)>,
    ) -> irlume_common::Result<Assessment> {
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
        // Order of authority: an explicit env override, then what the
        // capture-mode probe measured on THIS camera (`irlume camera-tune`,
        // stored per camera identity in cameras.conf), then the sequential
        // default. The probe exists because the dimming above is a property of
        // the hardware, not of irlume: the NexiGo N930W keeps 56% of its RGB
        // brightness when both of its interfaces stream, the ASUS built-in keeps
        // all of it, and only a measurement on the actual camera can tell which
        // kind is plugged in.
        // The caller's snapshot when sessions are HELD, a fresh read only when
        // this call opens one-shot. Two reads of cameras.conf around one held
        // capture are a check-to-act window (#313 review): the first read
        // arms both streams for concurrent, a config write lands, and the
        // second read orders "sequential" reads over two already-live
        // streams, the exact state the mode exists to prevent.
        let (sequential, mode_source) = capture_mode
            .unwrap_or_else(|| sequential_capture_selected(&self.rgb_dev, &self.ir_dev));
        // Name the mode AND where it came from. Without this the only way to
        // tell which path ran is to infer it from timings, which is exactly the
        // guessing this measurement work exists to remove.
        irlume_common::dlog!(
            "assess: capture mode {} (from {mode_source})",
            if sequential {
                "sequential"
            } else {
                "concurrent"
            }
        );
        // With held sessions the streams are already running, so a capture is
        // just the frames. Every RETRY below deliberately stays on the one-shot
        // path: a retry exists because something went wrong with this capture,
        // and re-opening is what makes a broken stream recoverable.
        // One denoised capture from a HELD session, recovering the stream in
        // place on a mid-stream fault. The broken stream owns the device's
        // buffer queue, so the standalone-reopen retry below answers EBUSY
        // from our own handle and surfaces as "camera busy, close that app"
        // with nothing to close (#187 hardware session: Brio QBUF EINVAL at
        // .266366, retry's S_FMT EBUSY at .269393, no close between).
        // Recovery renegotiates on the fd the session already holds.
        fn held_rgb_capture(
            rgb_s: &mut irlume_camera::RgbSession<'_>,
        ) -> irlume_common::Result<irlume_camera::Frame> {
            match rgb_s.denoised() {
                Ok(f) => Ok(f),
                Err(e) => {
                    irlume_common::dlog!(
                        "assess: held rgb stream broke ({e}); recovering it in place"
                    );
                    rgb_s.recover()?;
                    rgb_s.denoised()
                }
            }
        }
        // One IR capture from a HELD session, recovering the stream in place
        // on a mid-stream fault. Mirrors held_rgb_capture; the same EBUSY
        // reasoning applies: a standalone reopen would collide with the held
        // session's own fd on a double-open-rejecting camera.
        fn held_ir_capture(
            ir_s: &mut irlume_camera::IrSession<'_>,
        ) -> irlume_common::Result<(irlume_camera::Frame, irlume_camera::IrCaptureStats)> {
            match ir_s.capture_with_stats() {
                Ok(f) => Ok(f),
                Err(e) => {
                    irlume_common::dlog!(
                        "assess: held ir stream broke ({e}); recovering it in place"
                    );
                    ir_s.recover()?;
                    ir_s.capture_with_stats()
                }
            }
        }
        let held_sessions = held.is_some();
        // Every one-shot capture below carries the per-window heartbeat
        // (#336); held sessions already carry theirs from `capture_scans`.
        let progress = self.capture_progress();
        let (rgb_res, rgb_ms, ir_res, ir_ms) = if let Some((rgb_s, ir_s)) = held {
            if sequential {
                let t = std::time::Instant::now();
                let rgb = held_rgb_capture(rgb_s);
                let rgb_ms = t.elapsed().as_millis();
                if rgb.is_err() {
                    (rgb, rgb_ms, Ok(None), 0)
                } else {
                    let t = std::time::Instant::now();
                    let ir = held_ir_capture(ir_s);
                    (rgb, rgb_ms, ir.map(Some), t.elapsed().as_millis())
                }
            } else {
                std::thread::scope(|s| {
                    let ir_thread = s.spawn(move || {
                        let t = std::time::Instant::now();
                        (held_ir_capture(ir_s), t.elapsed().as_millis())
                    });
                    let t = std::time::Instant::now();
                    let rgb = held_rgb_capture(rgb_s);
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
            }
        } else if sequential {
            let t = std::time::Instant::now();
            let rgb = irlume_camera::capture_rgb_denoised_with_progress(&self.rgb_dev, &progress);
            let rgb_ms = t.elapsed().as_millis();
            // Match the old short-circuit: don't fire the IR emitter after an
            // RGB fault (privacy switch, missing node); the shared retry below
            // surfaces the RGB error.
            if rgb.is_err() {
                (rgb, rgb_ms, Ok(None), 0)
            } else {
                let t = std::time::Instant::now();
                let ir = irlume_camera::capture_ir_with_stats_and_progress(&self.ir_dev, &progress);
                (rgb, rgb_ms, ir.map(Some), t.elapsed().as_millis())
            }
        } else {
            std::thread::scope(|s| {
                let ir_dev = self.ir_dev.clone();
                let ir_progress = progress.clone();
                let ir_thread = s.spawn(move || {
                    let t = std::time::Instant::now();
                    (
                        irlume_camera::capture_ir_with_stats_and_progress(&ir_dev, &ir_progress),
                        t.elapsed().as_millis(),
                    )
                });
                let t = std::time::Instant::now();
                let rgb =
                    irlume_camera::capture_rgb_denoised_with_progress(&self.rgb_dev, &progress);
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
            // Standalone reopen is only safe when THIS call opened one-shot:
            // with held sessions the device queue belongs to the caller's
            // stream, the in-place recovery above already had its attempt,
            // and a reopen here meets our own handle as EBUSY (#187).
            Err(e) if !held_sessions => {
                irlume_common::dlog!(
                    "assess: rgb capture retry ({} capture failed: {e})",
                    if sequential {
                        "sequential"
                    } else {
                        "concurrent"
                    }
                );
                rgb_hard_retried = true;
                irlume_camera::capture_rgb_denoised_with_progress(&self.rgb_dev, &progress)?
            }
            Err(e) => return Err(e),
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
            Ok(None) => irlume_camera::capture_ir_with_stats_and_progress(&self.ir_dev, &progress)?,
            Err(e) => {
                irlume_common::dlog!("assess: ir capture retry (concurrent failed: {e})");
                irlume_camera::capture_ir_with_stats_and_progress(&self.ir_dev, &progress)?
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
        if self_heal_may_recapture(
            rgb_top.is_none(),
            ir_top.is_some(),
            sequential,
            rgb_hard_retried,
            held_sessions,
        ) {
            irlume_common::dlog!(
                "assess: RGB has no face but IR does; recapturing RGB alone (dim overlapped frame?)"
            );
            rgb = irlume_camera::capture_rgb_denoised_with_progress(&self.rgb_dev, &progress)?;
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

        // How far apart in time the two frames are. The cross-spectrum cues
        // (same face co-located in RGB and IR, RGB pose judged against the IR
        // face) only mean something if both frames show the SAME moment, and
        // nothing upstream bounds that: the two captures race on separate
        // threads, either side can retry alone, and the dimming self-heal above
        // recaptures RGB after IR is long finished. Measure it, then refuse a
        // pair too stale to compare.
        let skew = rgb.captured.gap_to(ir.captured);
        irlume_common::dlog!(
            "assess: rgb/ir capture skew {}ms (rgb span {}ms, ir span {}ms)",
            skew.as_millis(),
            rgb.captured
                .end
                .duration_since(rgb.captured.start)
                .as_millis(),
            ir.captured
                .end
                .duration_since(ir.captured.start)
                .as_millis()
        );
        if skew > MAX_CROSS_SPECTRUM_SKEW {
            // Uncertain, not Spoof: a stale pair is a capture-quality problem and
            // says nothing about the person. `OutcomeKind::Uncertain` is
            // presence-retryable, so a caller inside the grace window simply
            // captures again, which is exactly the fix.
            return Ok(Assessment {
                verdict: Verdict::Uncertain,
                rgb_frame_mean: irlume_camera::frame_mean(&rgb.data),
                reason: format!(
                    "RGB and IR frames are {}ms apart (limit {}ms); they may not show the same moment",
                    skew.as_millis(),
                    MAX_CROSS_SPECTRUM_SKEW.as_millis()
                ),
                embedding: None,
                ir_embedding: None,
                signals: Default::default(),
                ir_center_edge_ratio: 0.0,
                ir_brightness: 0.0,
                ir_ambient_share: None,
                eyes_open: false,
                thirdparty_fake: None,
            });
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
        let ir_center_edge_ratio = ir_top
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
            ir_center_edge_ratio,
            // Same RAW-frame rule as `ir_saturated_frac` below, for the same
            // reason: the ceiling test has to see the samples that actually
            // railed, and subtraction moves a 255 to 254 (#238 review).
            ir_eye_glint: eye_glint_of(
                ir_stats.saturation_frame.as_deref().unwrap_or(&ir.data),
                ir.width,
                ir.height,
                ir_top.as_ref().map(|f| &f.landmarks),
                ir_stats.white_level,
            ),
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            ir_ambient: ir_stats.ambient_mean,
            // From the IR frame, because the IR cues are measured there.
            face_frac: face_frac_of(ir_top.as_ref().map(|f| &f.bbox), ir.width),
            // Measured on the RAW gate frame. `ir.data` is the subtracted image
            // when ambient subtraction is on, and subtraction drops every
            // ceiling sample below the ceiling, so a 25%-clipped face would
            // report 0% and the exposure gate would pass a frame carrying
            // nothing (#238 review).
            ir_saturated_frac: saturated_frac_of(
                ir_stats.saturation_frame.as_deref().unwrap_or(&ir.data),
                ir.width,
                ir.height,
                ir_top.as_ref().map(|f| &f.bbox),
                ir_stats.white_level,
            ),
            // Whether the FORMAT could be measured, which is not the same
            // question as whether this capture produced a number: the call
            // above also yields None when no face was found (#358).
            ir_ceiling_known: ir_stats.white_level.is_some(),
            rgb_face_brightness: rgb_brightness,
            rgb_moire_score: 0.0,
            rgb_specular_frac: 0.0,
        };
        let (verdict, _cues, reason) = self.gate.evaluate(&signals);
        // Log the cue values on PASS too; a near-miss on a genuine user is
        // invisible in the outcome line but obvious here.
        irlume_common::dlog!(
            "liveness(cross-spectrum): {verdict:?} ({reason}); ir_bright={:.0} ir_center_edge_ratio={:.2} glint={} ambient={:.0} yaw_asym={:.2} pitch={:.2} face_frac={:.3} ir_clipped={} (face_frac #174, recorded only; clipped #237, refused past the limit)",
            signals.ir_face_brightness, signals.ir_center_edge_ratio,
            // Same "n/a" rule as ir_clipped: a peak that railed measured
            // nothing, and printing a number would claim otherwise (#222).
            signals
                .ir_eye_glint
                .map(|g| format!("{g:.2}"))
                .unwrap_or_else(|| "n/a".into()),
            signals.ir_ambient, signals.head_yaw_asym, signals.head_pitch_frac,
            signals.face_frac,
            // "n/a" is a real answer: this format cannot say where its ceiling
            // is, so no percentage printed here would mean anything.
            signals
                .ir_saturated_frac
                .map(|f| format!("{:.1}%", f * 100.0))
                .unwrap_or_else(|| "n/a".into()));
        // Opt-in third-party PAD cue: score whenever an IR face is present (the
        // `ir` frame is a LIT strobe phase, since #221 the brightest one that
        // is not clipped, which is closer to the regime the cue was measured in
        // than a blown exposure), so the dark path can consult the result too.
        // DENY-ONLY: it can downgrade Live to Spoof and nothing else.
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
            if thirdparty_abstains(thirdparty_fake, *thr) {
                irlume_common::dlog!(
                    "thirdparty-pad('{name}'): p_fake {:.3} is between the measured genuine \
                     ceiling and the deny threshold {thr:.2}; abstaining",
                    thirdparty_fake.unwrap_or(0.0)
                );
            }
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
        //
        // Same RAW-frame and ceiling pair its two siblings above take, and for
        // the same reasons: subtraction moves a railed 255 to 254 so the
        // clipping test must see `saturation_frame`, and a railed eye window
        // reads the lens rather than the cornea (#386, #238 review). This call
        // passed `&ir.data` with no ceiling until then, which is both halves of
        // that mistake at once.
        let eyes_open = ir_top
            .as_ref()
            .map(|f| {
                eyes_open_from_capture(
                    &ir.data,
                    ir_stats.saturation_frame.as_deref(),
                    ir.width,
                    ir.height,
                    &f.landmarks,
                    ir_stats.white_level,
                )
            })
            .unwrap_or(false);
        Ok(Assessment {
            verdict,
            reason,
            embedding,
            rgb_frame_mean: irlume_camera::frame_mean(&rgb.data),
            ir_embedding,
            signals,
            ir_center_edge_ratio,
            ir_brightness,
            // The share the room supplied of the burst's lit-frame mean,
            // only when an emitter-off frame was actually observed; the
            // denominator floor keeps a black burst (lit ~0) reading as 0
            // share rather than dividing to noise.
            ir_ambient_share: ir_stats
                .ambient_observed
                .then(|| ir_stats.ambient_mean / ir_stats.lit_mean.max(1.0)),
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
    // Production-dead since the blink `require_challenge` gate was removed (nod/
    // shake supersede it). `require_eyes_open` gates on the per-frame `eyes_open`
    // flag, not this blink-window detector. Kept for its tests and because it is
    // the worked example of the EAR path `capture_ear_samples` (still used by the
    // eyes-open calibration) drives.
    #[allow(dead_code)]
    fn run_passive_liveness(&mut self) -> irlume_common::Result<irlume_liveness::BlinkResult> {
        // ~5s window at the raw ~15 fps rate.
        const SAMPLES: usize = 75;
        // No landmark model → no samples → `detect_blink` reads NoEyes, which is
        // the historical no-mesh result (the caller decides what to do with it).
        let samples = self.capture_ear_samples(SAMPLES)?;
        // A window this short is a capture fault, not evidence about the user:
        // the camera returned frozen or unusable frames until the attempt budget
        // ran out. Judging it would report "no blink" for a hardware problem, so
        // separate the two in the log; the verdict itself stays fail-closed
        // because too few samples cannot show a dip either way.
        if !samples.is_empty() && samples.len() < SAMPLES / 3 {
            irlume_common::dlog!(
                "liveness(blink): only {}/{SAMPLES} usable frames arrived; treating as \
                 inconclusive capture, not as a missing blink",
                samples.len()
            );
        }
        Ok(irlume_liveness::detect_blink(&samples))
    }

    /// Capture a temporal IR sequence and compute the per-frame [`irlume_liveness::EarSample`]s
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
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    #[expect(
        clippy::missing_panics_doc,
        reason = "cannot panic: the `self.mesh.is_none()` guard above returns early, \
                  so `expect(\"mesh present\")` runs only when it is Some"
    )]
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
                cx = (t.bbox[0] + t.bbox[2]) * 0.5;
                cy = (t.bbox[1] + t.bbox[3]) * 0.5;
                fsize = (t.bbox[2] - t.bbox[0]).max(0.0);
                // A mesh refusal is one MISSING observation (ear stays None),
                // never an abort: `?` here turned a single refused frame into
                // the loss of the whole capture window.
                if let Some(e) = irlume_vision::mesh_min_ear(mesh, &view, &t.bbox) {
                    ear = Some(e);
                    // Corneal specular contrast from the IR frame at the eye
                    // landmarks (the second liveness cue: collapses on a real blink).
                    contrast = eye_glint_contrast(&f.data, f.width, f.height, &t.landmarks);
                }
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

    /// Capture a temporal IR sequence and record per-frame HEAD POSE (pitch and
    /// yaw from the DETECTOR's 5-point landmarks) for the head-nod consent
    /// gesture. Needs only the detector, not the FaceMesh, so it works at head
    /// angles and in IR-only light where the eye-based EAR gesture collapses. A
    /// frame with no detected face carries `None` pose.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn capture_pose_samples(
        &mut self,
        samples: usize,
    ) -> irlume_common::Result<Vec<irlume_liveness::PoseSample>> {
        let frames = irlume_camera::capture_ir_sequence(&self.ir_dev, samples, 1)?;
        let mut out = Vec::with_capacity(frames.len());
        for (i, f) in frames.iter().enumerate() {
            let bri = f.data.iter().map(|&p| p as f32).sum::<f32>() / f.data.len().max(1) as f32;
            let grey_rgb = irlume_camera::grey_to_rgb(&f.data);
            let view = align::RgbView {
                data: &grey_rgb,
                width: f.width,
                height: f.height,
            };
            let (mut pitch_frac, mut yaw_signed) = (None, None);
            let faces = self.det.detect(&view)?;
            if let Some(t) = top_detection(&faces) {
                let pose = irlume_vision::head_pose(&t.landmarks);
                pitch_frac = Some(pose.pitch_frac);
                yaw_signed = Some(pose.yaw_signed);
            }
            out.push(irlume_liveness::PoseSample {
                idx: i,
                pitch_frac,
                yaw_signed,
                bri,
            });
        }
        Ok(out)
    }

    /// Process one decoded IR frame into BOTH a head-pose sample (nod gesture)
    /// and an EAR sample (closure gesture): the detector runs always (pose), the
    /// FaceMesh only when loaded (EAR, else `None`). Shared by the fixed-window
    /// capture and the rolling consent watch.
    fn frame_to_consent_samples(
        &mut self,
        frame: &irlume_camera::Frame,
        idx: usize,
    ) -> irlume_common::Result<(irlume_liveness::PoseSample, irlume_liveness::EarSample)> {
        let bri =
            frame.data.iter().map(|&p| p as f32).sum::<f32>() / frame.data.len().max(1) as f32;
        let grey_rgb = irlume_camera::grey_to_rgb(&frame.data);
        let view = align::RgbView {
            data: &grey_rgb,
            width: frame.width,
            height: frame.height,
        };
        let (mut pitch_frac, mut yaw_signed) = (None, None);
        let mut ear = None;
        let (mut cx, mut cy, mut fsize, mut contrast) = (0.0, 0.0, 0.0, 0.0);
        let faces = self.det.detect(&view)?;
        if let Some(t) = top_detection(&faces) {
            let pose = irlume_vision::head_pose(&t.landmarks);
            pitch_frac = Some(pose.pitch_frac);
            yaw_signed = Some(pose.yaw_signed);
            cx = (t.bbox[0] + t.bbox[2]) * 0.5;
            cy = (t.bbox[1] + t.bbox[3]) * 0.5;
            fsize = (t.bbox[2] - t.bbox[0]).max(0.0);
            if let Some(mesh) = self.mesh.as_mut() {
                // Same missing-observation rule as capture_ear_samples: a
                // refused frame costs one EAR reading, not the consent watch.
                if let Some(e) = irlume_vision::mesh_min_ear(mesh, &view, &t.bbox) {
                    ear = Some(e);
                    contrast =
                        eye_glint_contrast(&frame.data, frame.width, frame.height, &t.landmarks);
                }
            }
        }
        Ok((
            irlume_liveness::PoseSample {
                idx,
                pitch_frac,
                yaw_signed,
                bri,
            },
            irlume_liveness::EarSample {
                idx,
                ear,
                bri,
                cx,
                cy,
                fsize,
                contrast,
            },
        ))
    }

    /// Total frames the consent gesture may be watched for across ONE
    /// authentication, split between a watch before the face match and one
    /// after. `IRLUME_CONSENT_MAX_FRAMES` overrides. At the IR node's ~15fps the
    /// default is roughly 8 seconds.
    fn consent_budget() -> usize {
        std::env::var("IRLUME_CONSENT_MAX_FRAMES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v >= 24)
            .unwrap_or(120)
    }

    /// Watch for the consent gesture BEFORE the face is captured.
    ///
    /// The greeter tells the user to nod and then this daemon spends several
    /// seconds capturing and matching a face, so a watch that only opens after
    /// the match starts looking well after a cooperative user has already
    /// nodded and stopped. Measured on hardware 2026-07-25: holding still was
    /// correctly refused, nodding CONTINUOUSLY released in 6s, and nodding ONCE
    /// when the prompt appeared was refused, which is indistinguishable from a
    /// broken gate to the person doing it.
    ///
    /// It takes a share of the same budget rather than adding to it, so the
    /// worst case is no slower than before, and it runs ONCE per authentication
    /// rather than per grace-window retry.
    fn early_consent_watch(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
    ) -> irlume_common::Result<bool> {
        if !self.ir_available {
            return Ok(false);
        }
        let (allow_nod, closure_cal) = self.consent_gesture_inputs(enr);
        if !allow_nod && closure_cal.is_none() {
            return Ok(false);
        }
        let seen = self.consent_watch(Self::consent_budget() / 3, allow_nod, closure_cal)?;
        irlume_common::dlog!(
            "consent: pre-match watch {}",
            if seen {
                "saw the gesture"
            } else {
                "saw nothing yet; will watch again after the match"
            }
        );
        Ok(seen)
    }

    /// Which gestures this enrollment can be asked for: the nod unless the
    /// operator restricted the mode, and the eye closure only when the mesh is
    /// loaded and the user has a usable calibration.
    fn consent_gesture_inputs(
        &self,
        enr: &irlume_core::storage::Enrollment,
    ) -> (bool, Option<irlume_liveness::ClosureCalibration>) {
        let mode = consent_gesture_mode();
        let (allow_nod, closure_allowed) = gestures_permitted_by(mode);
        let closure_cal = (closure_allowed && self.mesh.is_some())
            .then(|| {
                enr.closure_calibration.and_then(|(ear_open, ear_closed)| {
                    let cal = irlume_liveness::ClosureCalibration {
                        ear_open,
                        ear_closed,
                    };
                    cal.is_usable().then_some(cal)
                })
            })
            .flatten();
        (allow_nod, closure_cal)
    }

    /// Rolling consent watch: drive a held-open IR stream, process each frame,
    /// and return as SOON as an accepted gesture is seen (`nod` or, when
    /// `closure_cal` supplies a usable calibration, an eye closure), instead of
    /// draining a fixed window and letting the polkit agent re-run the whole
    /// prompt. Bounded by `max_frames`. Returns whether a gesture was accepted.
    /// `closure_cal` is `Some(cal)` only when the closure gesture is eligible.
    fn consent_watch(
        &mut self,
        max_frames: usize,
        allow_nod: bool,
        closure_cal: Option<irlume_liveness::ClosureCalibration>,
    ) -> irlume_common::Result<bool> {
        // Re-check the accumulated gestures every few frames (not every frame:
        // the detectors need a small window, and running them per frame is waste).
        const CHECK_EVERY: usize = 6;
        let ir_dev = self.ir_dev.clone();
        let mut poses: Vec<irlume_liveness::PoseSample> = Vec::new();
        let mut ears: Vec<irlume_liveness::EarSample> = Vec::new();
        let mut err: Option<irlume_common::Error> = None;
        let hit = irlume_camera::capture_ir_streaming(&ir_dev, max_frames, |sf| {
            let idx = poses.len();
            match self.frame_to_consent_samples(&sf.frame, idx) {
                Ok((pose, ear)) => {
                    poses.push(pose);
                    ears.push(ear);
                }
                Err(e) => {
                    err = Some(e);
                    return std::ops::ControlFlow::Break(true);
                }
            }
            if !poses.len().is_multiple_of(CHECK_EVERY) {
                return std::ops::ControlFlow::Continue(());
            }
            if allow_nod {
                let g = irlume_liveness::detect_nod(&poses);
                if !matches!(
                    g,
                    irlume_liveness::HeadGesture::Nod | irlume_liveness::HeadGesture::None
                ) {
                    irlume_common::dlog!(
                        "consent: detect_nod returned {g:?} at frame {}",
                        poses.len()
                    );
                }
                match g {
                    irlume_liveness::HeadGesture::Nod => {
                        return std::ops::ControlFlow::Break(true);
                    }
                    irlume_liveness::HeadGesture::Shake => {
                        self.gesture_cancelled = true;
                        return std::ops::ControlFlow::Break(false);
                    }
                    _ => {}
                }
            }
            if let Some(cal) = &closure_cal {
                if irlume_liveness::detect_deliberate_closure(&ears, cal)
                    == irlume_liveness::BlinkResult::Blinked
                {
                    return std::ops::ControlFlow::Break(true);
                }
            }
            std::ops::ControlFlow::Continue(())
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        // Resolve the take. A stream that broke in the loop is TERMINAL, whether
        // it accepted (`Some(true)`, a nod or closure) or declined (`Some(false)`,
        // a head-shake, which also set `gesture_cancelled`). Only a budget-
        // exhausted `None` consults the completed take, to catch a gesture that
        // finished inside the trailing poses the in-loop cadence never checked
        // (measured 2026-08-04, #101: two 20-pose windows at pitch_range
        // 0.077-0.085 against the 0.075 floor, last in-loop check at pose 18; one
        // cost a real trial its release). The decline must NOT reach that check:
        // re-reading the whole take (which holds the shake motion) as a nod, or
        // letting `detect_deliberate_closure` fire on the eye geometry a head-turn
        // produces, would overturn an explicit decline into a grant.
        let stream_hit = hit;
        let hit = resolve_consent_watch(stream_hit, || {
            completed_consent_take_hit(false, allow_nod, &poses, &ears, closure_cal.as_ref())
        });
        if stream_hit.is_none() && hit {
            // Observable in the journal so a hardware replay can show THIS
            // path fired, not just that a trial released.
            irlume_common::dlog!(
                "consent: gesture found on the completed take ({} poses; the \
                 in-loop cadence had last checked at pose {})",
                poses.len(),
                (poses.len() / CHECK_EVERY) * CHECK_EVERY,
            );
        }
        // A gesture that never arrives is otherwise silent: the caller waits out
        // its deadline and denies, which reads the same whether the user did
        // nothing or nodded in a way the detector did not count. Say which.
        // Report the evidence on BOTH outcomes, not just a miss. A refusal
        // explains itself from the numbers that fell short, but an ACCEPT is the
        // one that needs auditing: measured 2026-07-27 on real hardware, the gate
        // fired on a user sitting still 2 times in 8, and on a hand-held printed
        // face 2 times in 14. Without the numbers behind an accept there is no way
        // to tell which reading cleared which bar, and thresholds get argued over
        // instead of measured. Debug-level, numbers only, never frames.
        {
            let (_, ev) = irlume_liveness::detect_nod_with_evidence(&poses);
            // Raw pitch/yaw series, for developing a better discriminator than
            // peak-to-peak pitch (#101). Summary statistics cannot show SHAPE:
            // a deliberate nod and a slow postural drift can reach the same
            // range, and the difference between them lives in the trajectory.
            // Behind its own flag rather than IRLUME_LOG, because it is a long
            // line nobody wants in an ordinary debug capture. Pose angles only,
            // the same class of number the line above already prints, never
            // frames or embeddings.
            if std::env::var("IRLUME_DUMP_POSE_SERIES").is_ok_and(|v| v == "1") {
                let pitch: Vec<String> = poses
                    .iter()
                    .map(|p| p.pitch_frac.map_or("-".into(), |v| format!("{v:.4}")))
                    .collect();
                let yaw: Vec<String> = poses
                    .iter()
                    .map(|p| p.yaw_signed.map_or("-".into(), |v| format!("{v:.4}")))
                    .collect();
                irlume_common::dlog!("consent-series: pitch={}", pitch.join(","));
                irlume_common::dlog!("consent-series: yaw={}", yaw.join(","));
            }
            // Every threshold printed here comes from the evidence or a constant
            // the gate itself reads, never a restatement: `pitch_min` is carried
            // because IRLUME_NOD_PITCH_MIN can override the constant, and a line
            // naming a limit the run did not apply is worse than no line.
            irlume_common::dlog!(
                "consent: {} in {} frames; nod evidence: usable_pitch_frames={} (need {}) \
                 pitch_range={:.3} (need {:.3}) yaw_range={:.2} (max {:.2}) crossings={} (need {}) \
                 mean_step={:.4} (recorded for #101, gates nothing)",
                if hit {
                    "GESTURE ACCEPTED"
                } else {
                    "no gesture"
                },
                poses.len(),
                ev.frames,
                irlume_liveness::NOD_MIN_FACE_FRAMES,
                ev.pitch_range,
                ev.pitch_min,
                ev.yaw_range,
                irlume_liveness::NOD_YAW_MAX,
                ev.crossings,
                irlume_liveness::NOD_MIN_CROSSINGS,
                ev.mean_step,
            );
        }
        Ok(hit)
    }

    /// Apply whatever gate the purpose and the enrollment ask for on top of the
    /// match, just before granting.
    ///
    /// Two different gates live here:
    ///
    /// * The DELIBERATE consent gesture (nod / calibrated eye closure), required
    ///   by [`AuthenticationPurpose::AppConsent`] (polkit) and, by default, by
    ///   [`AuthenticationPurpose::CredentialRelease`]. A gesture is intent, not
    ///   just liveness, and it fails closed.
    /// * The per-enrollment passive natural-blink opt-in (`require_challenge`,
    ///   ADR-0002), unchanged.
    ///
    /// Every failure downgrades to a non-grant with an Uncertain-style reason, so
    /// PAM cascades to the typed password; nothing here can lock a user out. When
    /// IR or the FaceMesh model is missing, both gates fail closed to the password
    /// rather than hand back a grant weaker than what was asked for.
    fn challenge_if_required(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        outcome: Outcome,
    ) -> irlume_common::Result<Outcome> {
        if !outcome.granted {
            return Ok(outcome);
        }
        if purpose.demands_gesture(service) {
            let seen = self.gesture_seen_before_match;
            return self.consent_gesture_gate(enr, outcome, seen);
        }
        // Credential release with the challenge switched OFF, and no per-enrollment
        // gate either: the operator chose this, so honour it, but say so on every
        // release. A journal line is the only durable record that a stored
        // credential left the TPM behind a gate the operator weakened. A global
        // opt-out does NOT cancel a user's own `require_challenge`, which still
        // runs below, so the warning is limited to the genuinely ungated case.
        if !enr.require_challenge
            && matches!(
                purpose,
                AuthenticationPurpose::CredentialRelease {
                    temporal_challenge: false
                }
            )
        {
            eprintln!(
                "irlumed: WARNING: credential release WITHOUT a temporal challenge \
                 ({key}=off): a static IR print that passes the face checks can \
                 release this password. Re-enable: sudo irlume \
                 credential-release-challenge on",
                key = irlume_common::config::CREDENTIAL_RELEASE_CHALLENGE_KEY
            );
        }
        // The per-enrollment require_challenge (passive blink liveness) gate is
        // removed. Gesture-based intent (nod/shake) proves both liveness and
        // intent; a print cannot produce a coherent head pose sequence. The
        // consent gesture gate above already covers the AppConsent and
        // CredentialRelease paths; the Verify path never demanded a gesture.
        // The passive liveness infrastructure (run_passive_liveness,
        // capture_ear_samples) stays for require_eyes_open.
        Ok(outcome)
    }

    /// The forced consent gate: require a DELIBERATE gesture before approving a
    /// polkit prompt, accepting EITHER a head NOD or an eye CLOSURE so the user
    /// does whichever suits their position. One capture feeds both detectors:
    ///
    /// * A head nod (pose-defined) always works and needs no calibration, so it
    ///   is the universal path, including reclined where EAR collapses.
    /// * An eye closure ("close ~1s, then open") is ALSO accepted when the user
    ///   has calibrated it and the FaceMesh is loaded, for those who prefer it
    ///   sitting upright. It cannot false-fire reclined (EAR stays flat, no
    ///   reopen), so accepting it is safe.
    ///
    /// `consent_gesture=nod` or `=closure` in settings.conf restricts to one;
    /// unset accepts either. FAILS CLOSED (PAM cascades to the password) when no
    /// accepted gesture is seen.
    fn consent_gesture_gate(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        outcome: Outcome,
        already_seen: bool,
    ) -> irlume_common::Result<Outcome> {
        // The gesture was already made, before the face capture. Nothing is
        // gained by asking for a second one; it is the same person in the same
        // authentication, seconds apart.
        if already_seen {
            irlume_common::dlog!("consent: gesture already seen before the match");
            return Ok(outcome);
        }
        // Rolling watch deadline: keep watching and return the INSTANT a gesture
        // appears, so the user can nod whenever without a fixed window to miss
        // (which made the fixed-window version slow and unreliable as the polkit
        // agent re-ran the whole prompt). A quick nod returns in ~2-3s; only a
        // no-gesture window pays the full deadline before the password fallback.
        // This is the REMAINDER of the budget, the rest having been spent
        // watching before the match.
        let budget = Self::consent_budget();
        let max_frames = budget - budget / 3;
        let (live, score) = (outcome.live, outcome.score);
        let deny = |reason: &str| Outcome {
            granted: false,
            live,
            score,
            reason: reason.into(),
            kind: OutcomeKind::OtherDeny,
        };
        if !self.ir_available {
            return Ok(deny(
                "consent gesture required but no IR camera; use your password",
            ));
        }
        let mode = consent_gesture_mode();
        let (allow_nod, closure_cal) = self.consent_gesture_inputs(enr);
        if self.consent_watch(max_frames, allow_nod, closure_cal)? {
            irlume_common::dlog!("consent: gesture seen after the match");
            Ok(outcome)
        } else if self.gesture_cancelled {
            irlume_common::dlog!("consent: head shake cancelled the request");
            Ok(deny("head shake cancelled the request"))
        } else {
            Ok(deny(match mode {
                ConsentGesture::Nod => "keep nodding your head to approve",
                ConsentGesture::Closure => {
                    "close your eyes for about a second, then open, to approve"
                }
                // Names only the nod, for the reason given on
                // `ConsentGesture::instruction`: a denial is the worst possible
                // moment to offer the gesture that needs a calibration to work.
                ConsentGesture::Either => "keep nodding your head to approve",
                // No gesture is enabled, so no gesture could have been seen and
                // none is worth suggesting. Name the setting: the person who can
                // clear this is whoever typed it (#365).
                ConsentGesture::Misconfigured => {
                    "consent_gesture is set to a value irlume does not recognise                      (expected nod or closure); use your password"
                }
            }))
        }
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
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn authenticate(
        &mut self,
        user: &str,
        service: Option<&str>,
    ) -> irlume_common::Result<Outcome> {
        self.authenticate_for(user, service, AuthenticationPurpose::for_service(service))
    }

    /// [`Self::authenticate`] with the purpose stated explicitly, for callers that
    /// know something the service name does not say: the daemon's `UnsealPassword`
    /// arm passes [`AuthenticationPurpose::CredentialRelease`] so releasing the
    /// sealed keyring password gets the deliberate-gesture gate.
    ///
    /// The purpose is computed once per call and threaded down, so a polkit verify
    /// can never leak its gate into a later login, and a credential release can
    /// never be mistaken for a plain verify.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    #[expect(
        clippy::missing_panics_doc,
        reason = "unwrap on a logically impossible state"
    )]
    pub fn authenticate_for(
        &mut self,
        user: &str,
        service: Option<&str>,
        purpose: AuthenticationPurpose,
    ) -> irlume_common::Result<Outcome> {
        let window = grace_window_ms(service);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(window);
        // Fingerprint mode: face is disabled so pam_fprintd drives; never engage
        // the camera, decline so the PAM stack cascades to fingerprint/password.
        if irlume_core::policy::method().face_disabled() {
            return Ok(Outcome::deny(
                OutcomeKind::OtherDeny,
                "face disabled (fingerprint mode)",
            ));
        }
        // Load the enrollment once per authentication, not once per retry.
        // Every retry in the loop below was re-reading the profile file and
        // re-calling template_key::load_key → tpm::unseal. On a discrete TPM
        // that unseal costs 2.7s quiet and 18.97s contended, and TPM and
        // camera are independent devices, so it can leave the critical path
        // entirely. The key is dropped inside load; only the decrypted
        // Enrollment is held, which is already plaintext in memory during
        // each authenticate_once today.
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
        // Watch for the consent gesture BEFORE the first capture, so a user who
        // nods when the greeter asks is not ignored for the seconds it takes to
        // capture and match a face. Once per authentication, never per retry: a
        // grace window can hold several attempts and none of them should re-ask
        // for a gesture already given.
        self.gesture_seen_before_match = false;
        self.gesture_cancelled = false;
        if purpose.demands_gesture(service) {
            self.gesture_seen_before_match = self.early_consent_watch(&enr)?;
            // A head-shake during the pre-match watch is an explicit decline.
            // Close the request now: do not spend the capture and match only to
            // deny after a second post-match watch, and do not let a later cue
            // override the decline. `early_consent_watch` sets `gesture_cancelled`
            // via `consent_watch` when the shake fires.
            if self.gesture_cancelled {
                irlume_common::dlog!("consent: head shake before the match cancelled the request");
                return Ok(Outcome::deny(
                    OutcomeKind::OtherDeny,
                    "head shake cancelled the request",
                ));
            }
        }
        // Hold the camera sessions across the grace window's retries. Every retry
        // otherwise re-opens, re-negotiates, re-maps and re-warms both streams
        // (~700ms of setup per attempt, 58% of a one-shot capture). The enrolment
        // path already holds sessions for its whole capture loop; the auth path
        // extends that to the retry loop. The shape matches capture_scans: open
        // the devices, create sessions from them, fall back to per-capture when
        // the session path cannot hold them (sequential mode, or a camera that
        // cannot be opened).
        //
        // The cameras are only opened when sessions will be created. Opening them
        // unconditionally would leave them held in `cams` while the one-shot path
        // below tries to open the same device again, which is EBUSY on a
        // single-consumer camera and on any v4l2loopback node with a producer
        // attached.
        let (rgb_dev, ir_dev) = (self.rgb_dev.clone(), self.ir_dev.clone());
        let (sequential, _mode_source) = sequential_capture_selected(&rgb_dev, &ir_dev);
        // Declared in reverse drop order: `held` borrows from `_rs`/`_is` which
        // borrow from `cams`. Rust drops locals in reverse declaration order, so
        // `held` drops first (releasing the borrow), then the sessions, then the
        // cameras.
        let mut _cams: Option<(irlume_camera::RgbCamera, irlume_camera::IrCamera)> = None;
        let mut _rs: Option<irlume_camera::RgbSession<'_>> = None;
        let mut _is: Option<irlume_camera::IrSession<'_>> = None;
        let mut held: Option<(
            &mut irlume_camera::RgbSession<'_>,
            &mut irlume_camera::IrSession<'_>,
        )> = None;
        if !sequential && self.ir_available {
            if let (Ok(r), Ok(i)) = (
                irlume_camera::RgbCamera::open(&rgb_dev),
                irlume_camera::IrCamera::open(&ir_dev),
            ) {
                _cams = Some((r, i));
                let progress = self.capture_progress();
                // SAFETY: _cams is Some, and _rs/_is borrow from it. _cams is
                // declared before _rs/_is so it outlives them.
                let (ref cam_r, ref cam_i) = _cams.as_ref().unwrap();
                if let (Ok(rs), Ok(is)) = (
                    cam_r.session_with_progress(&progress),
                    cam_i.session_with_progress(&progress),
                ) {
                    _rs = Some(rs);
                    _is = Some(is);
                    held = Some((_rs.as_mut().unwrap(), _is.as_mut().unwrap()));
                }
            }
        }
        let mut attempt = 0u32;
        let out = loop {
            attempt += 1;
            let out = self.authenticate_once(&enr, purpose, service, &mut held)?;
            if !presence_retryable(&out) || std::time::Instant::now() >= deadline {
                if attempt > 1 {
                    irlume_common::dlog!(
                        "grace: settled after {attempt} attempts ({}ms window)",
                        window
                    );
                }
                break out;
            }
            irlume_common::dlog!(
                "grace: attempt {attempt} found no usable face ({}); retrying within window",
                out.reason
            );
            // A whole capture ended and another is about to start: the safe
            // boundary the watchdog counts as progress (#336). Without it the
            // entire grace window is one silent stretch on the daemon's clock.
            self.note_capture_boundary();
        };
        // The gesture belongs to the authentication that just ended.
        self.gesture_seen_before_match = false;
        Ok(out)
    }

    fn authenticate_once(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        held: &mut Option<(
            &mut irlume_camera::RgbSession<'_>,
            &mut irlume_camera::IrSession<'_>,
        )>,
    ) -> irlume_common::Result<Outcome> {
        let a = if let Some((ref mut rs, ref mut is)) = held {
            self.assess_full_with(Some((*rs, *is)), None)?
        } else {
            self.assess()?
        };

        // An unreadable frame is reported as unreadable BEFORE anything derived
        // from it is consulted. The eye cue below is computed from the same IR
        // pixels, so a blown frame that hides the corneal glints would deny with
        // OtherDeny, which is NOT presence-retryable: the grace window would
        // stop instead of letting exposure settle, turning a retryable quality
        // refusal into a terminal one for anybody with require_eyes_open on
        // (#238 review). Uncertain is the only verdict this promotes; a Spoof
        // still reaches its own branch below with its own reason.
        //
        // ONE Uncertain shape falls through (#284): no RGB face while an IR
        // face exists. The cross-spectrum gate reports Uncertain there because
        // it needs both spectra, but that situation is exactly the dark
        // IR-only path's entry condition, and #238's blanket early return made
        // Windows-Hello-style dark login unreachable in the condition it was
        // written for. Falling through loses no gating: the RGB branch is
        // skipped (no embedding), and the dark branch derives its own verdict
        // via evaluate_ir_only, which shares the exposure refusal, so an
        // unreadable IR frame in the dark is still refused there — with the
        // dark path's own retryability kinds.
        if uncertain_short_circuits(a.verdict, a.embedding.is_some(), a.ir_embedding.is_some()) {
            return Ok(Outcome::deny(
                liveness_deny_kind(a.verdict, &a.reason),
                format!("liveness {:?}: {}", a.verdict, a.reason),
            ));
        }

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
            // Per-user floor on the IR center/edge brightness ratio
            // (anti-screen/photo, calibrated to how this user's face reads under
            // the emitter): the live frame must clear the enrolled floor. Ratio
            // only: a per-user IR *brightness* floor was removed because IR face
            // brightness is ambient-dependent (emitter-only ~40 in the dark vs ~140
            // lit) and a lit-enrollment floor false-rejected genuine dim/night
            // logins as "screen/photo". The global gate above (`evaluate`) already
            // enforces an ambient-tolerant IR brightness floor. Only meaningful
            // when IR was actually captured (skip on RGB-only).
            if let Some(ratio_floor) = enr
                .ir_center_edge_ratio_floor()
                .filter(|_| self.ir_available)
            {
                irlume_common::dlog!(
                    "gate(per-user IR center/edge floor): live {:.2} vs floor {:.2}",
                    a.ir_center_edge_ratio,
                    ratio_floor
                );
                if a.ir_center_edge_ratio < ratio_floor {
                    return Ok(Outcome::deny(
                        OutcomeKind::Spoof,
                        format!(
                            "IR center/edge {:.2} below your calibrated floor {:.2}; the face region is flatter than your enrolled face (screen/photo)",
                            a.ir_center_edge_ratio, ratio_floor
                        ),
                    ));
                }
            }
            let scans = enr.rgb_scans_in(&self.embed_space);
            let thr = self.rgb_grant_threshold(scans.len());
            let (score, who) = best(&probe, &scans);
            irlume_common::dlog!(
                "match(rgb): best {score:.3} vs thr {thr:.3} ({} scans, best profile '{who}')",
                scans.len()
            );
            if score >= thr {
                *held = None;
                return self.challenge_if_required(
                    enr,
                    purpose,
                    service,
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
            // With a third-party recognizer the whole IR side is unmeasured
            // (thresholds AND the fusion Platt calibration are shipped-model
            // measurements), so a marginal RGB miss ends here: password.
            if let Some(ir_probe) = a.ir_embedding.as_ref().filter(|_| self.ir_matching) {
                let m = self.ir_match(enr, ir_probe);
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
                        *held = None;
                        return self.challenge_if_required(
                    enr,
                    purpose,
                    service,
                    Outcome::grant(f.prob,
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
                        *held = None;
                        return self.challenge_if_required(
                    enr,
                    purpose,
                    service,
                    Outcome::grant(ir_score,
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
                            *held = None;
                            return self.challenge_if_required(
                    enr,
                    purpose,
                    service,
                    Outcome::grant(*cs,
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
            // Fail-closed, with the real reason: dark unlock is an IR MATCH,
            // and no third-party recognizer has a measured IR threshold. A
            // generic "no match" here would send the user debugging their
            // enrollment instead of reading the actual limitation.
            if !self.ir_matching {
                return Ok(Outcome::deny(
                    OutcomeKind::OtherDeny,
                    "dark unlock unavailable with a third-party recognizer (its IR \
                     matching is unmeasured); use the password, or switch back to \
                     the shipped recognizer",
                ));
            }
            let m = self.ir_match(enr, &probe);
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
            irlume_common::dlog!("liveness(ir-only/dark): {verdict:?} ({reason}); ir_bright={:.0} ir_center_edge_ratio={:.2} glint={} ambient={:.0}",
                a.signals.ir_face_brightness, a.signals.ir_center_edge_ratio,
                a.signals
                    .ir_eye_glint
                    .map(|g| format!("{g:.2}"))
                    .unwrap_or_else(|| "n/a".into()),
                a.signals.ir_ambient);
            if verdict != Verdict::Live {
                // Dark-path kinds: Uncertain retries under grace, any Spoof
                // does not (the retryable RGB-yes/IR-no transient cannot occur
                // here: this path only runs when RGB saw no face).
                //
                // Routed through the shared classifier rather than mapped
                // inline. `exposure_refusal` is deliberately shared by BOTH
                // evaluators, so the unmeasurable-format refusal arrives here
                // as Uncertain too, and an inline map would leave it in the
                // retryable class on exactly the camera this gate exists for:
                // six full captures reaching the identical answer, every dark
                // login, forever. The classifier holds the one prefix rule
                // (#358 review).
                //
                // `reason` here is the raw liveness string; the "dark liveness"
                // prefix is applied in the `format!` below, after this call, so
                // the prefix match still sees what irlume-liveness produced.
                let kind = liveness_deny_kind(verdict, &reason);
                return Ok(Outcome::deny(
                    kind,
                    format!("dark liveness {verdict:?}: {reason}"),
                ));
            }
            // Per-user calibrated center/edge floor, same as the RGB primary path.
            // `evaluate_ir_only` uses the lenient global MIN_CENTER_EDGE_RATIO; the
            // per-user floor is stricter and ambient-independent, so a curved
            // warm spoof that sits between the global ratio and this user's
            // enrolled falloff is caught in lit conditions but must not slip
            // through in the dark. Apply it here too before the IR match.
            if let Some(ratio_floor) = enr
                .ir_center_edge_ratio_floor()
                .filter(|_| self.ir_available)
            {
                irlume_common::dlog!(
                    "gate(per-user IR center/edge floor, dark): live {:.2} vs floor {:.2}",
                    a.ir_center_edge_ratio,
                    ratio_floor
                );
                if a.ir_center_edge_ratio < ratio_floor {
                    return Ok(Outcome::deny(
                        OutcomeKind::Spoof,
                        format!(
                            "IR center/edge {:.2} below your calibrated floor {:.2}; the face region is flatter than your enrolled face (screen/photo)",
                            a.ir_center_edge_ratio, ratio_floor
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
                *held = None;
                return self.challenge_if_required(
                    enr,
                    purpose,
                    service,
                    Outcome::grant(score, format!("match: {who} (ir/dark)")),
                );
            }
            if let Some((cs, cwho)) = &m.centroid {
                let cthr = irlume_core::scaled_threshold(ir_base, enr.profiles.len());
                irlume_common::dlog!("match(ir/dark centroid): {cs:.3} vs thr {cthr:.3}");
                if *cs >= cthr {
                    *held = None;
                    return self.challenge_if_required(
                        enr,
                        purpose,
                        service,
                        Outcome::grant(
                            *cs,
                            format!("match: {cwho} (ir/dark, calibrated centroid)"),
                        ),
                    );
                }
            }
            *held = None;
            return self.challenge_if_required(
                enr,
                purpose,
                service,
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
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn identify(&mut self) -> irlume_common::Result<IdentifyOutcome> {
        self.identify_impl(None)
    }

    /// Identify scoped to a single enrolled user ("is this `user`?"). Same
    /// liveness gate and RGB match as [`Self::identify`], but the search set is
    /// just this one account: what a non-root peer is allowed to ask about itself.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
            let scans = enr.rgb_scans_in(&self.embed_space);
            if scans.is_empty() {
                continue;
            }
            let thr = self.rgb_grant_threshold(scans.len());
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
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn liveness_selftest(&mut self) -> irlume_common::Result<(bool, String)> {
        let a = self.assess()?;
        let s = &a.signals;
        let live = a.verdict == Verdict::Live;
        let detail = if live {
            format!(
                "Live: RGB face {}, IR face {} · IR brightness {:.0}, center/edge {:.2}, glint {}",
                if s.rgb_face.is_some() { "✓" } else { "✗" },
                if s.ir_face.is_some() { "✓" } else { "✗" },
                a.ir_brightness,
                a.ir_center_edge_ratio,
                s.ir_eye_glint
                    .map(|g| format!("{g:.0}"))
                    .unwrap_or_else(|| "n/a".into()),
            )
        } else {
            format!("{:?}: {}", a.verdict, a.reason)
        };
        Ok((live, detail))
    }

    /// Alignment-determinism self-test: embed the same aligned chip twice; the
    /// cosine MUST be ~1.0. Catches the AuraFace alignment/normalization trap
    /// (the "identical images score 0.6" failure). `Request::SelfTest { AlignmentIdentity }`.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn alignment_selftest(&mut self) -> irlume_common::Result<(bool, String)> {
        let rgb = irlume_camera::capture_rgb_denoised_with_progress(
            &self.rgb_dev,
            &self.capture_progress(),
        )?;
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
        observed: &mut CaptureShape,
    ) -> irlume_common::Result<Vec<CapturedScan>> {
        // Hold the cameras open for the whole loop. This is the heaviest repeated
        // capture in the codebase (the budget below is ten assessments per wanted
        // scan), and every one of them otherwise re-opened, re-negotiated,
        // re-mapped and re-warmed both streams, plus blinked the capture LED.
        // Measured on the ASUS built-in with examples/session_bench.rs: an
        // RGB+IR pair costs 1912ms per-call against 797ms on a held session,
        // so 1115ms of every attempt was setup (58%). Safe to hold
        // for a burst this long because the emitter does not go dark: measured at
        // a flat lit level for 30s of continuous streaming on both modules we
        // have (examples/ir_refire_probe.rs).
        //
        // A camera that cannot be opened is NOT fatal here: fall back to the
        // per-capture path, which is exactly today's behaviour, so enrolment
        // still works on hardware the session path cannot hold.
        // Asked to yield before the first frame: do not even open the device.
        // A queued enrolment that already knows an authentication is waiting has
        // no business claiming the camera for the moment it takes to notice.
        if self.should_stop() {
            return Err(irlume_common::Error::Preempted(
                "an authentication needed the camera; nothing was saved, please retry".into(),
            ));
        }
        let (rgb_dev, ir_dev) = (self.rgb_dev.clone(), self.ir_dev.clone());
        let cams = if self.ir_available {
            match (
                irlume_camera::RgbCamera::open(&rgb_dev),
                irlume_camera::IrCamera::open(&ir_dev),
            ) {
                (Ok(r), Ok(i)) => Some((r, i)),
                _ => None,
            }
        } else {
            None
        };
        // Fast path: hold both streams for the whole loop.
        //
        // NOT under sequential capture mode. A held session arms its stream
        // at creation, so holding both means both stream at once and
        // "sequential" only orders the reads. Measured on a Logitech Brio on
        // a USB2 link (#187 hardware session, strace + dmesg): with the IR
        // stream armed, the RGB stream gets no isochronous bandwidth at all;
        // STREAMON succeeds, no frame ever arrives, and the queue dies with
        // QBUF EINVAL ("Failed to resubmit video URB" in dmesg). Sequential
        // mode exists for exactly the cameras that cannot sustain both
        // streams, so on them this loop takes the per-frame path, which
        // opens one stream at a time and releases it before the other.
        let (sequential, mode_source) = sequential_capture_selected(&rgb_dev, &ir_dev);
        if sequential {
            irlume_common::dlog!(
                "enroll: sequential capture mode (from {mode_source}); not holding \
                 both streams, capturing per-frame"
            );
        } else if let Some((r, i)) = &cams {
            let progress = self.capture_progress();
            if let (Ok(mut rs), Ok(mut is)) = (
                r.session_with_progress(&progress),
                i.session_with_progress(&progress),
            ) {
                return self.capture_scan_loop(
                    want,
                    pitch_neutral,
                    Some((&mut rs, &mut is)),
                    Some((sequential, mode_source)),
                    observed,
                );
            }
        }
        // No held session. RELEASE THE DEVICES FIRST. The per-frame path below
        // re-opens both nodes itself, and `cams` still holds them: on a module
        // that permits a second open (both of ours do, measured) that is merely
        // wasteful, but a module that answers EBUSY turns it into enrolment
        // failing on its first capture and naming irlumed as the holder of its
        // own camera (#187). Dropping here also MOVES `cams`, so the fallback
        // below cannot reach the handles even by mistake.
        drop(cams);
        irlume_common::dlog!(
            "enroll: capturing per-frame (no held camera session; released the devices first)"
        );
        // The same snapshot as the held path: one enrollment, one policy. A
        // config flip mid-loop would otherwise change the one-shot capture
        // shape between scans, which on a starvation-prone camera turns some
        // scans into the failure the stored mode exists to avoid.
        self.capture_scan_loop(
            want,
            pitch_neutral,
            None,
            Some((sequential, mode_source)),
            observed,
        )
    }

    /// The enrolment capture loop, over held streams when `sessions` is given
    /// and re-opening per frame when it is not.
    ///
    /// Split out from [`Self::capture_scans`] so the per-frame path runs with
    /// the held cameras already dropped: the two capture strategies must never
    /// have the devices open at the same time (#187).
    fn capture_scan_loop(
        &mut self,
        want: usize,
        pitch_neutral: Option<f32>,
        mut sessions: Option<(
            &mut irlume_camera::RgbSession<'_>,
            &mut irlume_camera::IrSession<'_>,
        )>,
        capture_mode: Option<(bool, &'static str)>,
        observed: &mut CaptureShape,
    ) -> irlume_common::Result<Vec<CapturedScan>> {
        let mut out = Vec::new();
        // Read once, before the loop: `sessions` is borrowed per iteration but
        // never taken, so this is the whole loop's answer (#389).
        let mut shape = CaptureShape {
            held_sessions: sessions.is_some(),
            ..CaptureShape::default()
        };
        // Budget (was ×4) absorbs the added frontality gate (a frame grabbed the
        // instant the user drifts off-angle is rejected, not saved) with enough
        // retries that a brief drift near the capture moment doesn't abort enroll.
        for _ in 0..(want * 10) {
            if out.len() >= want {
                break;
            }
            // The safe boundary: between whole captures, before the next one
            // opens. Nothing is written until the caller finishes, so returning
            // here leaves no partial profile behind and no device mid-stream.
            if self.should_stop() {
                return Err(irlume_common::Error::Preempted(
                    "an authentication needed the camera; nothing was saved, please retry".into(),
                ));
            }
            let a = match &mut sessions {
                Some((rs, is)) => self.assess_full_with(Some((rs, is)), capture_mode)?,
                None => self.assess()?,
            };
            observe_attempt(
                &mut shape,
                a.embedding.as_ref(),
                a.ir_embedding.as_ref(),
                a.rgb_frame_mean,
            );
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
                        center_edge_ratio: a.ir_center_edge_ratio,
                        brightness: a.ir_brightness,
                        pitch: a.signals.head_pitch_frac,
                        ambient_share: a.ir_ambient_share,
                    });
                }
            }
        }
        observed.include(shape);
        Ok(out)
    }

    /// One solo RGB frame after the held sessions were released, to say whether
    /// concurrent streaming was starving this camera (#389).
    ///
    /// `None` when it did not run: either the observation does not have the
    /// shape worth spending a capture on, or the capture itself failed. A
    /// failed probe must never turn a failed enrolment into a different error,
    /// so every error path here answers `None` and the caller keeps the message
    /// it would have written anyway.
    ///
    /// Safe where the cross-spectrum self-heal is not. That recapture is
    /// forbidden while sessions are held, because reopening a node this process
    /// streams answers EBUSY on some modules (#187, #381). By the time this
    /// runs, `capture_scans` has returned and both sessions are dropped.
    ///
    /// Costs one RGB open, measured at 146ms to 173ms on the NexiGo, and only
    /// on a capture loop that has already failed.
    fn solo_rgb_starvation_probe(&mut self, shape: CaptureShape) -> Option<StarvationProbeResult> {
        // Only where the ambiguity exists: the held path, every attempt IR-only.
        concurrent_starvation_hint(shape)?;
        if shape.attempts == 0 {
            return None;
        }
        let held_mean = shape.rgb_mean_sum / shape.attempts as f32;
        let frame = irlume_camera::capture_rgb(&self.rgb_dev).ok()?;
        let solo_mean = irlume_camera::frame_mean(&frame.data);
        let view = align::RgbView {
            data: &frame.data,
            width: frame.width,
            height: frame.height,
        };
        // A detector ERROR is not an observation that no face was there, and
        // collapsing the two would let a broken detector read as a refutation.
        // Nothing is confirmed without a detection that actually ran.
        let found = match self.det.detect(&view) {
            Ok(faces) => faces.iter().any(irlume_vision::detection_is_finite),
            Err(e) => {
                irlume_common::dlog!("enroll: solo RGB probe: detector failed ({e}); no verdict");
                return None;
            }
        };
        irlume_common::dlog!(
            "enroll: solo RGB probe after release: held mean {held_mean:.1}, solo mean \
             {solo_mean:.1}, face {found}"
        );
        Some(StarvationProbeResult {
            confirmed: solo_probe_confirms_starvation(held_mean, solo_mean, found),
            held_mean,
            solo_mean,
        })
    }

    /// The A/B/A check: after the solo probe confirms dimming, reopen the
    /// sessions and take one more concurrent capture to verify the camera is
    /// pinned rather than tracking a light that changed (#100).
    ///
    /// A/B (held vs solo) is wrong in the adversarial cell: a lamp turning on
    /// between the held and solo phases produces a bright solo frame that reads
    /// like recovered signal, and the camera is demoted for a room, not a fault.
    /// A/B/A adds a second held phase after the solo one: a healthy camera
    /// tracks the light (A' ≈ B, both bright), while a starved camera is pinned
    /// (A' ≈ A, both dim). This check answers true only when the camera is
    /// pinned.
    ///
    /// Cost: one session open+close, paid only when the solo probe has already
    /// confirmed. A failed open is not an error: the probe cannot be certain
    /// enough to act without the second held phase, so it retreats.
    fn aba_check_confirms(&mut self, held_mean: f32, solo_mean: f32) -> bool {
        let (rgb_dev, ir_dev) = (self.rgb_dev.clone(), self.ir_dev.clone());
        if !self.ir_available {
            return false;
        }
        let cams = match (
            irlume_camera::RgbCamera::open(&rgb_dev),
            irlume_camera::IrCamera::open(&ir_dev),
        ) {
            (Ok(r), Ok(i)) => (r, i),
            _ => return false,
        };
        let progress = self.capture_progress();
        let sessions = cams
            .0
            .session_with_progress(&progress)
            .and_then(|rs| cams.1.session_with_progress(&progress).map(|is| (rs, is)));
        let (mut rs, mut is) = match sessions {
            Ok(pair) => pair,
            Err(_) => return false,
        };
        let (rgb, ir) = std::thread::scope(|scope| {
            let ir_thread = scope.spawn(|| is.capture_with_stats());
            let rgb = rs.denoised();
            let ir = match ir_thread.join() {
                Ok(result) => result,
                Err(_) => Err(irlume_common::Error::Hardware(
                    "IR capture thread panicked".into(),
                )),
            };
            (rgb, ir)
        });
        let (Ok(rgb), Ok(_)) = (&rgb, &ir) else {
            return false;
        };
        let concurrent_mean = irlume_camera::frame_mean(&rgb.data);
        irlume_common::dlog!(
            "enroll: A/B/A check: held mean {held_mean:.1}, solo mean {solo_mean:.1}, \
             reopened held mean {concurrent_mean:.1}"
        );
        // The reopened held frame must still be pinned to the original held
        // mean, not tracking the solo mean. Same rule the probe uses.
        concurrent_mean < solo_mean * irlume_camera::CONCURRENT_SIGNAL_FLOOR
    }

    /// Stop asking this pairing to capture concurrently once the enrolment loop
    /// has seen enough evidence and the solo probe and A/B/A check both confirm
    /// the camera is dimming under concurrent load (#100).
    ///
    /// A failed write is reported and dropped. This runs at the tail of an
    /// enrolment that has already reached its verdict, and read-only `/etc` must
    /// not turn a successful enrolment into an error.
    fn maybe_switch_capture_mode_from_enrolment(
        &mut self,
        consecutive_ir_only: usize,
        held_mean: f32,
        solo_mean: f32,
    ) {
        if consecutive_ir_only < SELF_HEAL_SWITCH_AFTER as usize {
            return;
        }
        let (_, mode_source) = sequential_capture_selected(&self.rgb_dev, &self.ir_dev);
        if mode_source == ENV_CAPTURE_MODE_SOURCE {
            return;
        }
        if irlume_camera::capture_mode_pair_identity(&self.rgb_dev, &self.ir_dev).is_none() {
            return;
        }
        if !self.aba_check_confirms(held_mean, solo_mean) {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let stored =
            irlume_camera::store_sequential_if_still_concurrent(&self.rgb_dev, &self.ir_dev, now);
        if let Some(line) = capture_mode_switch_line(SELF_HEAL_SWITCH_AFTER, &stored) {
            eprintln!("irlumed: {line}");
        }
    }

    /// Enroll `want` scans (capped at MAX_SCANS_PER_PROFILE). If the captured
    /// face already owns a profile, the scans are merged into it (a face can
    /// never own two profiles, so that is always what the user meant, and it
    /// is the 0.2.0 upgrade remedy, fresh scans reviving dark/dim login after
    /// an embedding-space change). A novel face gets a NEW profile; that errors
    /// if the account is already at MAX_PROFILES.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    #[expect(
        clippy::missing_panics_doc,
        reason = "cannot panic: `target` is a profile name returned by \
                  `enroll_merge_target` from this same `enr`, so the `position` \
                  lookup that follows always finds it"
    )]
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
        // ONE tally for the whole enrolment, handed to every capture loop it
        // runs. The loops fold into it, so a second loop cannot replace what
        // the first observed and the message cannot claim "on every attempt"
        // about a subset of them.
        let mut observed = CaptureShape::default();
        let probe_scans = self.capture_scans(1, enr.pitch_neutral(), &mut observed)?;
        let solo_probe = if probe_scans.is_empty() {
            self.solo_rgb_starvation_probe(observed)
        } else {
            None
        };
        if let Some(probe) = solo_probe {
            if probe.confirmed {
                self.maybe_switch_capture_mode_from_enrolment(
                    observed.consecutive_ir_only,
                    probe.held_mean,
                    probe.solo_mean,
                );
            }
        }
        let probe = probe_scans.into_iter().next().ok_or_else(|| {
            let advice = capture_advice(observed, solo_probe);
            irlume_common::Error::Protocol(format!("no live scan captured; {advice}"))
        })?;
        let goal = match enroll_merge_target(
            &enr,
            &[probe.rgb.as_slice()],
            &self.embed_space,
            self.rgb_threshold,
        )? {
            Some(target) => {
                let room = enr
                    .profiles
                    .iter()
                    .find(|p| p.name == target)
                    .map_or(MAX_SCANS_PER_PROFILE, |p| {
                        scan_room_in(p, &self.embed_space)
                    });
                if room == 0 {
                    return Err(irlume_common::Error::Protocol(format!(
                        "this face is already enrolled as '{target}', which is at the max \
                         {MAX_SCANS_PER_PROFILE} scans for the loaded recognizer; delete \
                         some of its scans first"
                    )));
                }
                want.min(room)
            }
            None => want,
        };
        let mut captured = vec![probe];
        if goal > 1 {
            captured.extend(self.capture_scans(goal - 1, enr.pitch_neutral(), &mut observed)?);
        }
        if captured.len() < goal {
            let solo_probe = self.solo_rgb_starvation_probe(observed);
            if let Some(probe) = solo_probe {
                if probe.confirmed {
                    self.maybe_switch_capture_mode_from_enrolment(
                        observed.consecutive_ir_only,
                        probe.held_mean,
                        probe.solo_mean,
                    );
                }
            }
            let advice = capture_advice(observed, solo_probe);
            return Err(irlume_common::Error::Protocol(format!(
                "only {} live scans (need {goal}); {advice}",
                captured.len()
            )));
        }
        // Final disposition over the whole capture: catches a second person
        // drifting into frame after the probe, and a borderline probe that only
        // crosses the identity threshold on a later scan.
        let rgbs: Vec<&[f32]> = captured.iter().map(|s| s.rgb.as_slice()).collect();
        if let Some(target) =
            enroll_merge_target(&enr, &rgbs, &self.embed_space, self.rgb_threshold)?
        {
            // The face already owns a profile: merge the capture into it.
            let idx = enr
                .profiles
                .iter()
                .position(|p| p.name == target)
                .expect("merge target came from these profiles");
            let room = scan_room_in(&enr.profiles[idx], &self.embed_space);
            if room == 0 {
                return Err(irlume_common::Error::Protocol(format!(
                    "this face is already enrolled as '{target}', which is at the max \
                     {MAX_SCANS_PER_PROFILE} scans for the loaded recognizer; delete \
                     some of its scans first"
                )));
            }
            let added = captured.len().min(room);
            let mut added_scans = Vec::with_capacity(added);
            let mut ambient_lit = 0usize;
            for s in captured.into_iter().take(room) {
                if s.ambient_share.is_some_and(|v| v >= AMBIENT_LIT_SHARE) {
                    ambient_lit += 1;
                }
                let sname = enr.profiles[idx].next_scan_name();
                added_scans.push(sname.clone());
                let ir_space = s.ir.as_ref().map(|_| self.ir_space.clone());
                enr.profiles[idx].scans.push(FaceScan {
                    name: sname,
                    rgb: s.rgb,
                    ir: s.ir,
                    ir_space,
                    embed_space: Some(self.embed_space.clone()),
                    ir_center_edge_ratio: s.center_edge_ratio,
                    ir_brightness: s.brightness,
                    pitch: s.pitch,
                });
            }
            self.refit_profile_calib(&mut enr.profiles[idx]);
            let total = enr.profiles[idx].scans.len();
            // The budget the caller may still spend is per RECOGNIZER
            // (#290), so compute it from the same helper enrollment itself
            // uses rather than leaving a client to derive it from `total`.
            let room = scan_room_in(&enr.profiles[idx], &self.embed_space);
            storage::save(&enr)?;
            return Ok(EnrollOutcome::Merged {
                name: target,
                added,
                total,
                room,
                added_scans,
                ambient_lit,
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
            ir_calibs: Default::default(),
            name: name.clone(),
            scans: Vec::new(),
        };
        let mut ambient_lit = 0usize;
        for s in captured {
            if s.ambient_share.is_some_and(|v| v >= AMBIENT_LIT_SHARE) {
                ambient_lit += 1;
            }
            let sname = prof.next_scan_name();
            let ir_space = s.ir.as_ref().map(|_| self.ir_space.clone());
            prof.scans.push(FaceScan {
                name: sname,
                rgb: s.rgb,
                ir: s.ir,
                ir_space,
                embed_space: Some(self.embed_space.clone()),
                ir_center_edge_ratio: s.center_edge_ratio,
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
        Ok(EnrollOutcome::New {
            name,
            scans: n,
            ambient_lit,
        })
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

    /// Add scans to an existing profile ("improve recognition"). Errors if the
    /// profile is missing or already at MAX_SCANS_PER_PROFILE.
    /// Add `count` scans (at least one) to an existing profile, in the LOADED recognizer's
    /// space. This is also how a profile gains templates for a second
    /// recognizer without re-enrolling as a new person: the operator names
    /// the profile, which is the only way the link can be made, since
    /// comparing vectors across embedding spaces is meaningless (#288).
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn add_scan(
        &mut self,
        user: &str,
        profile_name: &str,
        count: usize,
    ) -> irlume_common::Result<AddScanOutcome> {
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
        // Counted for THIS recognizer: a profile holding another model's
        // scans must still accept this one's, and the limit's false-accept
        // rationale is about templates compared in one operation (#288).
        let room = scan_room_in(&enr.profiles[idx], &self.embed_space);
        if room == 0 {
            return Err(irlume_common::Error::Protocol(format!(
                "'{profile_name}' already has the max {MAX_SCANS_PER_PROFILE} scans for the \
                 loaded recognizer"
            )));
        }
        let want = count.clamp(1, room);
        let mut observed = CaptureShape::default();
        let captured = self.capture_scans(want, enr.pitch_neutral(), &mut observed)?;
        let solo_probe = if captured.len() < want {
            self.solo_rgb_starvation_probe(observed)
        } else {
            None
        };
        if let Some(probe) = solo_probe {
            if probe.confirmed {
                self.maybe_switch_capture_mode_from_enrolment(
                    observed.consecutive_ir_only,
                    probe.held_mean,
                    probe.solo_mean,
                );
            }
        }
        if let Some(why) = short_capture_refusal(captured.len(), want, observed, solo_probe) {
            return Err(irlume_common::Error::Protocol(why));
        }
        // Anti-mixing: reject scans whose face belongs to a different profile.
        let rgbs: Vec<&[f32]> = captured.iter().map(|c| c.rgb.as_slice()).collect();
        if let Some((other, score)) = foreign_owner_in_capture(
            &enr,
            &rgbs,
            profile_name,
            &self.embed_space,
            self.rgb_threshold,
        ) {
            let cnt = enr
                .profiles
                .iter()
                .find(|p| p.name == other)
                .map_or(0, |p| p.scans_in(&self.embed_space));
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
        let mut added = Vec::with_capacity(captured.len());
        let mut ambient_lit = 0usize;
        for c in captured {
            if c.ambient_share.is_some_and(|v| v >= AMBIENT_LIT_SHARE) {
                ambient_lit += 1;
            }
            let sname = enr.profiles[idx].next_scan_name();
            let ir_space = c.ir.as_ref().map(|_| self.ir_space.clone());
            enr.profiles[idx].scans.push(FaceScan {
                name: sname.clone(),
                rgb: c.rgb,
                ir: c.ir,
                ir_space,
                embed_space: Some(self.embed_space.clone()),
                ir_center_edge_ratio: c.center_edge_ratio,
                ir_brightness: c.brightness,
                pitch: c.pitch,
            });
            added.push(sname);
        }
        self.refit_profile_calib(&mut enr.profiles[idx]);
        if enr.camera_binding.is_none() {
            enr.camera_binding = Some(self.current_binding());
        }
        let total = enr.profiles[idx].scans_in(&self.embed_space);
        let room = scan_room_in(&enr.profiles[idx], &self.embed_space);
        storage::save(&enr)?;
        Ok(AddScanOutcome {
            added_scans: added,
            total,
            room,
            ambient_lit,
        })
    }

    /// One framing-guide sample for guided enrollment: capture, detect, and
    /// report how the user is positioned (no enrollment, no auth). The gates
    /// mirror the enroll/auth path so `well_framed` implies a capture will take.
    /// `user` (the account being enrolled) tunes the pitch band to that user's
    /// calibrated neutral when they already have scans, so the guide coaches to
    /// the same window the capture gate will accept.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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

        let rgb = irlume_camera::capture_rgb_burst_with_progress(
            &self.rgb_dev,
            1,
            &self.capture_progress(),
        )?
        .pop()
        .ok_or_else(|| irlume_common::Error::Hardware("no frames captured".into()))?;
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
    let x1 = (bbox[0].max(0.0) as u32).min(w);
    let y1 = (bbox[1].max(0.0) as u32).min(h);
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
    /// A new face profile was created. `ambient_lit` counts the scans whose
    /// IR burst the room at least half lit ([`AMBIENT_LIT_SHARE`]): above
    /// zero, dark-room login is unverified for this enrollment (#312).
    New {
        name: String,
        scans: usize,
        ambient_lit: usize,
    },
    /// The captured face already owned `name`, so the capture was added to that
    /// profile instead (`added` new scans, `total` scans now) and the
    /// per-enrollment calibration was refitted. This is what makes `irlume
    /// enroll` idempotent for the same person: a face can never own two
    /// profiles, so merging is always what the user meant. It is also the
    /// 0.2.0 upgrade remedy (fresh current-space scans revive dark/dim login
    /// after an embedding-space change strands the old IR templates).
    Merged {
        name: String,
        /// Remaining scans allowed in the LOADED recognizer's space.
        room: usize,
        added: usize,
        total: usize,
        /// Names of the scans this capture appended, so a caller can undo the
        /// merge by deleting exactly them (the TUI does this on a declined
        /// "add to the existing profile?" confirm).
        added_scans: Vec<String>,
        /// Scans among `added` whose IR burst the room at least half lit
        /// ([`AMBIENT_LIT_SHARE`]); above zero, dark-room login is
        /// unverified for the new scans (#312).
        ambient_lit: usize,
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
    embed_space: &str,
    threshold: f32,
) -> irlume_common::Result<Option<String>> {
    let mut hit: Option<String> = None;
    for rgb in captured_rgb {
        let Some((other, _score)) = colliding_profile(enr, rgb, None, embed_space, threshold)
        else {
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

/// Why a capture that came back short must be refused, or `None` when it is
/// complete.
///
/// `capture_scans` is best-effort and may return fewer scans than asked for.
/// A partial save would report success while leaving the recognizer
/// under-enrolled, so the refusal happens before anything is written, exactly
/// as enrollment does. A value because the capture it guards sits behind a
/// camera, so this is the only shape a test can observe.
/// What an enrolment capture loop OBSERVED, kept so a loop that captures
/// nothing can say why without guessing (#389).
/// What the solo RGB starvation probe found after the held sessions were
/// released (#389, #100).
#[derive(Clone, Copy, Debug, PartialEq)]
struct StarvationProbeResult {
    /// The probe confirmed the camera was dimming under concurrent load.
    confirmed: bool,
    /// The mean of the held (concurrent) RGB frames from the enrolment loop.
    held_mean: f32,
    /// The mean of the solo RGB frame captured after releasing the sessions.
    solo_mean: f32,
}

// No `Eq`: the brightness sum is an f32. `PartialEq` is what the tests compare
// with, and an exact comparison is right for them because every value they use
// is constructed literally rather than accumulated.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct CaptureShape {
    /// The loop ran over held streams, which is the clause that suppresses the
    /// cross-spectrum self-heal in [`self_heal_may_recapture`]. It matters to
    /// the message because on the OTHER path the self-heal recaptures RGB
    /// standalone and reassigns `rgb_top`, so an IR-only attempt there means
    /// RGB found no face with the sensor to itself, which rules concurrent
    /// starvation out rather than in.
    held_sessions: bool,
    /// Attempts made. Distinguishes "every attempt looked like this" from
    /// "one did", and a zero here means the loop never ran.
    attempts: usize,
    /// Whole-frame RGB brightness summed over the attempts, so a mean can be
    /// taken without keeping every reading. Only meaningful alongside
    /// `attempts`, and only used when every attempt had the IR-only shape.
    rgb_mean_sum: f32,
    /// Attempts holding an IR embedding and no RGB one. This is the
    /// dark-login shape [`uncertain_short_circuits`] is named for, and on the
    /// held path it is ALSO the shape a camera makes when streaming both
    /// sensors starves its RGB node. Nothing here separates the two.
    ir_only_attempts: usize,
    /// CONSECUTIVE (not total) attempts with the IR-only shape. A clean
    /// attempt (RGB found a face) resets this to zero. This is the trigger for
    /// the capture-mode auto-switch (#100): three consecutive IR-only attempts
    /// within one held enrolment loop, and the solo probe confirms the
    /// camera is dimming under concurrent capture.
    consecutive_ir_only: usize,
}

impl CaptureShape {
    /// Fold another loop's observations into this one.
    ///
    /// One enrolment can run the loop twice: a probe scan, then a top-up. The
    /// message says "on every attempt", and every attempt means every attempt
    /// of the ENROLMENT, so the counts sum. Replacing instead of folding let a
    /// run whose probe captured an RGB face, which it must have to reach the
    /// top-up at all, still report that the colour sensor found none.
    ///
    /// `held_sessions` ANDs because the diagnosis needs every contributing loop
    /// to have suppressed the self-heal. One fallback loop in the operation
    /// means the standalone RGB recapture ran for those attempts and found no
    /// face with the sensor to itself, which argues against starvation.
    fn include(&mut self, other: Self) {
        if self.attempts == 0 {
            // Nothing observed yet. ANDing `held_sessions` against a default
            // that has never seen a loop would zero it on the first fold and
            // the hint could never fire.
            *self = other;
            return;
        }
        self.held_sessions &= other.held_sessions;
        self.attempts += other.attempts;
        self.ir_only_attempts += other.ir_only_attempts;
        self.rgb_mean_sum += other.rgb_mean_sum;
        // The LAST loop's consecutive streak is the one that matters: the
        // top-up loop runs after the probe loop, and the writer needs the
        // streak from the loop that just failed. Summing would let the probe
        // loop's streak (which was broken by a successful probe capture) pad
        // the top-up loop's, overcounting.
        self.consecutive_ir_only = other.consecutive_ir_only;
    }
}

/// Fold one attempt's outcome into the running shape.
///
/// Takes the embeddings themselves rather than two bools. Two `bool` arguments
/// would let a swapped call site compile and invert the meaning silently, and a
/// mutation proved no test could catch that; these two types differ, so the
/// swap is a compile error instead. It takes them rather than the whole
/// `Assessment` so it can be tested without a camera.
fn observe_attempt(
    shape: &mut CaptureShape,
    rgb_embedding: Option<&[f32; EMBED_DIM]>,
    ir_embedding: Option<&Vec<f32>>,
    rgb_frame_mean: f32,
) {
    shape.attempts += 1;
    shape.rgb_mean_sum += rgb_frame_mean;
    // The dark-login shape. An attempt with NEITHER embedding saw no face at
    // all, which is the ordinary framing failure and not this.
    if ir_embedding.is_some() && rgb_embedding.is_none() {
        shape.ir_only_attempts += 1;
        shape.consecutive_ir_only = shape.consecutive_ir_only.saturating_add(1);
    } else if rgb_embedding.is_some() {
        // A clean capture (RGB found a face) is direct counter-evidence: reset
        // the consecutive streak. An attempt with neither embedding is a
        // framing failure that says nothing about the camera, so it is neutral.
        shape.consecutive_ir_only = 0;
    }
}

/// Did a solo RGB frame, taken after the held sessions were released, come back
/// bright with a face where the held attempts came back dark without one (#389)?
///
/// ⛔ This does NOT establish that concurrency caused the difference, and the
/// message it feeds must not say so. Nothing here records that the light, the
/// framing or the person stayed the same between the two observations: a lamp
/// switching on, or the subject stepping back into frame, produces this reading
/// with no camera fault at all. What it establishes is that two captures
/// seconds apart, one overlapped and one not, disagreed.
///
/// That is still worth having, because it is the shape a camera that cannot
/// sustain both streams makes, and because `camera-tune` measures the thing
/// directly. It is not worth asserting a cause over.
///
/// While both streams run, an unlit room and a starved RGB interface are the
/// same reading: no RGB face, IR face present. They differ after the release,
/// and the three clauses below are `irlume_camera`'s own contention rule,
/// reused rather than reinvented.
///
/// Measured on a NexiGo HelloCam N930W, 2026-08-10, ten runs across three
/// conditions, `frame_mean` throughout so these constants are compared against
/// the statistic they were fitted to:
///
/// | condition | held mean | solo | verdict |
/// |---|---|---|---|
/// | lit room, starved | 51.7, 51.1 | face at 0.95, mean 146.9 | confirms |
/// | dark room | 46.5 to 47.2 | no face, mean 18.0 | refuses |
/// | healthy module (ASUS), lit | 160 to 163, face in 6 of 6 | face, mean 157 | refuses |
///
/// The dark room is refused twice over, which is why this does not rest on the
/// brightness floor alone: with the emitter firing during the held phase its
/// light leaks into the RGB sensor, so the held frames read BRIGHTER than the
/// solo one (46.6 against 18.0) and the dimming clause fails on its own.
fn solo_probe_confirms_starvation(held_mean: f32, solo_mean: f32, solo_found_face: bool) -> bool {
    solo_found_face
        && solo_mean >= irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS
        && held_mean < solo_mean * irlume_camera::CONCURRENT_SIGNAL_FLOOR
}

/// The second reading to offer when an enrolment captured nothing, or `None`
/// when the evidence does not support offering one (#389).
///
/// Deliberately an ADDITION to the lighting advice at every call site, never a
/// replacement. The two causes are indistinguishable from here: an unlit room
/// and a camera dimming its colour stream under concurrent load both produce
/// an IR face with no RGB face, and this repository already records the first
/// one observed live (`uncertain_short_circuits`, rgb faces=0 / ir faces=1 at
/// 0.92). Naming only the camera would assert a cause the code cannot
/// establish, and dropping the room advice would be wrong far more often,
/// since the shipped capture default is sequential and only a stored
/// `concurrent` verdict reaches the starvation case at all.
///
/// The remedy says "in a lit room" on purpose. `camera-tune` stores its
/// verdict unconditionally under `ProbeStore::Always`, and `conclusive()`
/// records retention reading 121%, 122% and 126% at an RGB mean of 17, which
/// is arithmetic on noise rather than a camera gaining signal. Advising a
/// re-measure without that qualifier would talk a user in a dark room into
/// persisting exactly the wrong verdict.
fn concurrent_starvation_hint(shape: CaptureShape) -> Option<&'static str> {
    // Held path only, and only when EVERY attempt had the shape. One attempt
    // out of ten is a user who blinked or turned away; ten out of ten on a
    // held pair is the structural case #389 measured, where the loop cannot
    // recover because each attempt fails identically.
    let every_attempt = shape.attempts > 0 && shape.ir_only_attempts == shape.attempts;
    (shape.held_sessions && every_attempt).then_some(
        "The infrared sensor found a face on every attempt and the colour sensor found none. \
         If the room was lit, this camera may be dimming its colour stream while both sensors \
         run; re-run `sudo irlume camera-tune` in a lit room to re-measure it.",
    )
}

/// The advice tail every enrolment capture failure ends with.
///
/// One function because all three failure sites say the same thing and drifted
/// apart is how one of them keeps blaming the room after the others learn not
/// to. The lighting clause is unconditional; [`concurrent_starvation_hint`]
/// only ever appends.
fn capture_advice(shape: CaptureShape, solo_probe: Option<StarvationProbeResult>) -> String {
    // A refutation is deliberately treated as no probe at all. It would
    // otherwise DELETE a correct hint on the strength of an observation that
    // may have tested a different scene: a user who turned away before the solo
    // frame refutes a camera that really is starving. Only the confirming
    // direction changes anything, and even that names an observation rather
    // than a cause.
    match solo_probe.filter(|r| r.confirmed) {
        // The probe ran and confirmed it. The lighting clause is DROPPED here,
        // which #414 forbade for good reason at the time: darkness and
        // contention were the same reading, so naming one asserted a cause the
        // code could not establish. A confirmation now includes
        // `solo_mean >= CONCLUSIVE_SCENE_BRIGHTNESS`, so the room being lit is
        // measured rather than assumed, and telling this user to check their
        // lighting would send them after the wrong thing.
        // The light comes FIRST, and that ordering is measured rather than
        // stylistic. On a healthy camera in a dark room with a lamp coming on
        // between the two captures, this branch fires wrongly: 4 runs of 4 on
        // 2026-08-10, held 28.9 to 31.8 with no face, solo 163 with one. Naming
        // the camera first would put the wrong cause at the front of the
        // sentence in every one of them. The second held phase that WOULD
        // separate the two is what #379's config write needs; a message does
        // not earn a second pair of session opens on a failed enrolment.
        Some(_) => String::from(
            "the colour frame was dark on every attempt while both sensors were streaming, and \
             a capture taken straight afterwards with only the colour sensor running found a \
             face. If the light changed between those two moments, that is the explanation. If \
             it did not, this is the shape of a camera that cannot sustain both streams, and \
             `sudo irlume camera-tune` in a lit room measures that directly",
        ),
        // Not confirmed, whether the probe refuted it or never ran. Unchanged
        // from #414: offer both readings, assert neither.
        None => {
            let mut advice = String::from("check lighting and framing");
            if let Some(hint) = concurrent_starvation_hint(shape) {
                advice.push_str(". ");
                advice.push_str(hint);
            }
            advice
        }
    }
}

fn short_capture_refusal(
    got: usize,
    want: usize,
    shape: CaptureShape,
    solo_probe: Option<StarvationProbeResult>,
) -> Option<String> {
    (got < want).then(|| {
        let scans = if got == 1 { "scan" } else { "scans" };
        let advice = capture_advice(shape, solo_probe);
        format!("only {got} live {scans} captured (need {want}); nothing was saved, {advice}")
    })
}

/// How many more scans this profile may hold for `space`.
///
/// Saturating, and counted per recognizer: a profile may legally hold the
/// limit under each of several recognizers (#288), so subtracting the total
/// from the limit underflows once a second model's templates exist. Every
/// site that decides room uses this one function, because the enroll merge
/// path had two more subtractions that the first cut of the per-space change
/// missed entirely.
fn scan_room_in(profile: &irlume_core::storage::FaceProfile, space: &str) -> usize {
    irlume_core::storage::MAX_SCANS_PER_PROFILE.saturating_sub(profile.scans_in(space))
}

/// The first captured scan whose face belongs to a DIFFERENT profile, if any.
///
/// Every capture is checked, not just the first, so a second person stepping
/// into frame partway through an add-scan session is caught; the enroll path
/// checks its whole capture for the same reason. Extracted as a value because
/// the loop it guards sits behind a camera, so this is the only shape a test
/// can observe.
fn foreign_owner_in_capture(
    enr: &irlume_core::storage::Enrollment,
    captured_rgb: &[&[f32]],
    exclude: &str,
    embed_space: &str,
    threshold: f32,
) -> Option<(String, f32)> {
    captured_rgb
        .iter()
        .find_map(|rgb| colliding_profile(enr, rgb, Some(exclude), embed_space, threshold))
}

/// Best-matching OTHER profile for `probe` (excluding `exclude`), if it reaches
/// the identity threshold, i.e. this face already belongs to a different
/// profile. Stops the same person's scans being split across profiles (which
/// would corrupt recognition and the 1:N unlock model).
fn colliding_profile(
    enr: &irlume_core::storage::Enrollment,
    probe: &[f32],
    exclude: Option<&str>,
    embed_space: &str,
    threshold: f32,
) -> Option<(String, f32)> {
    let mut best: Option<(String, f32)> = None;
    for p in &enr.profiles {
        if Some(p.name.as_str()) == exclude {
            continue;
        }
        for s in &p.scans {
            // A template from another recognizer is in a foreign embedding
            // space; a cosine against it could merge a stranger's scans into
            // this profile or reject a legitimate add-scan, so it does not
            // get compared at all.
            if !irlume_core::storage::recognizer_space_matches(
                s.embed_space.as_deref(),
                embed_space,
            ) {
                continue;
            }
            let c = align::cosine(probe, &s.rgb);
            if c >= threshold && best.as_ref().is_none_or(|b| c > b.1) {
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
///
/// `white` is the negotiated format's ceiling, and passing it is what stops
/// this gate reading a lens instead of an eye. [`eye_glint_of`] next door
/// already refuses a railed peak, and its doc records why: the repo's own
/// measurements pin the peak at 255 in all 30 frames with glasses on, where it
/// reads the lens specular rather than the cornea. This function sampled the
/// same statistic and never got the same treatment, so on 2026-08-08 it
/// GRANTED 3/3 with the eyes CLOSED behind glasses while denying 5/5 bare-eyed
/// with them open (#386). A maximum is exactly the statistic clipping
/// destroys: a railed window says the true value was at least the ceiling and
/// never what it was, so no eyelid state can be read out of it.
///
/// Unlike `eye_glint_of`, which answers `None` for "not established", this gate
/// is deny-only and returns a bool, so unreadable collapses to `false`. That is
/// the fail-safe direction for a gate whose whole purpose is refusing a
/// sleeping or unconscious user.
///
/// `white` of `None` means the format named no ceiling (`Grey16`, `Nv12Luma`,
/// `YuyvLuma`) and the peak passes through unchanged, which is #237's settled
/// precedent and the same choice `eye_glint_of` makes.
///
/// Pass the RAW frame. Ambient subtraction moves a railed 255 to 254, so a
/// subtracted frame stops reading as railed and this refusal would not fire;
/// the callers of `eye_glint_of` and `saturated_frac_of` already pass
/// `saturation_frame` for that reason (#238 review) and this one now does too.
/// Which buffer the eyes-open gate measures, as a value a test can observe.
///
/// This exists because the ceiling refusal and the choice of frame are two
/// independently necessary halves, and a test that calls [`both_eyes_open`]
/// with an already-railed buffer proves only the first. Revert the selection to
/// the returned frame and the fail-open comes straight back with every such
/// test still green: ambient subtraction moves a railed 255 to 254, which is
/// under the ceiling and over `EYE_OPEN_PEAK_MIN`, so both eyes report open
/// (#397 review).
///
/// `saturation_frame` is the RAW gate frame, preserved by `capture_with_stats`
/// precisely so a clipping test can see the samples that actually railed. It is
/// `None` when nothing replaced the payload, and then the returned frame IS the
/// raw one.
fn eyes_open_from_capture(
    returned: &[u8],
    saturation_frame: Option<&[u8]>,
    w: u32,
    h: u32,
    lm: &irlume_vision::Landmarks5,
    white: Option<u8>,
) -> bool {
    both_eyes_open(saturation_frame.unwrap_or(returned), w, h, lm, white)
}

pub fn both_eyes_open(
    grey: &[u8],
    w: u32,
    h: u32,
    lm: &irlume_vision::Landmarks5,
    white: Option<u8>,
) -> bool {
    // Same w*h invariant guard as eye_glint/mean_in_bbox: eye_open_at's in-bounds
    // test is against the logical w/h, so a truncated IR frame (buffer < w*h)
    // would index past the slice and panic the root daemon. A short frame reads
    // "eyes not verified" (closed), the safe fail-closed for this gate.
    if grey.len() < (w as usize).saturating_mul(h as usize) {
        return false;
    }
    // A NaN eye coordinate saturates to pixel (0,0) at the cast below, so a
    // broken landmark source would have this gate reading the frame corner as
    // an open eye (measured in examples/landmark_failure_probe.rs: a corner
    // hotspot answered `true`). Eyes we cannot place are eyes we cannot
    // verify: fail closed.
    if !lm[0..2]
        .iter()
        .all(|&(x, y)| x.is_finite() && y.is_finite())
    {
        return false;
    }
    let iod = ((lm[1].0 - lm[0].0).powi(2) + (lm[1].1 - lm[0].1).powi(2)).sqrt();
    let r = (iod * 0.20).max(2.0) as i32;
    // BOTH eyes, so one readable eye cannot vouch for a railed one. Same
    // whole-set rule `eye_glint_contrast` states for unplaceable landmarks.
    eye_open_at(grey, w, h, lm[0], r, white) && eye_open_at(grey, w, h, lm[1], r, white)
}

fn eye_open_at(
    grey: &[u8],
    w: u32,
    h: u32,
    (ex, ey): (f32, f32),
    r: i32,
    white: Option<u8>,
) -> bool {
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
    match white {
        // Railed: the window carries the sensor's limit, not the eye. Checked
        // BEFORE the threshold, because a railed peak clears
        // EYE_OPEN_PEAK_MIN by construction and that is precisely the path
        // that granted with closed eyes (#386).
        Some(ceiling) if peak >= ceiling => false,
        _ => peak as f32 >= EYE_OPEN_PEAK_MIN,
    }
}

/// Mean luma (0–255) and the fraction of near-white ("hot") pixels inside `bbox`
/// of an RGB image. The hot fraction is a basic RGB-PAD cue: emissive screens
/// and glossy prints blow out highlights, so an unusually high fraction is a
/// (deterrent-grade) screen/glare signal.
fn rgb_luma_stats(rgb: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> (f32, f32) {
    let x1 = (bbox[0].max(0.0) as u32).min(w);
    let y1 = (bbox[1].max(0.0) as u32).min(h);
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
    let x1 = (bbox[0].max(0.0) as u32).min(w);
    let y1 = (bbox[1].max(0.0) as u32).min(h);
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

/// Fraction (0-1) of pixels at or above `white` inside `bbox`: how much of the
/// face region the sensor clipped.
///
/// `white` comes from the capture rather than from here, because what counts
/// as the ceiling depends on the negotiated format: a native 8-bit grey clips
/// at 255, limited-range YUV puts nominal white at 235, and the Y16 family is
/// rescaled by a shift taken from the frame's own maximum, so a decoded 255
/// there means "the brightest pixel in this frame" and not a clipped sensor.
/// See `IrCaptureStats::white_level`.
///
/// A clipped centre cannot read brighter than a clipped rim, so saturation
/// compresses [`center_edge_ratio`] toward 1 exactly as an ambient pedestal
/// does. irlume guards the ambient end (`IR_AMBIENT_FLOOD`) and has nothing at
/// this one, and the recorded corpora show the case is reachable: in both
/// `depth_real_*` sessions the first capture read ~235 mean with a ratio of
/// 1.06 and 1.12, against a 1.03 spoof floor and 1.19-1.42 for every later
/// capture (#221). The whole-frame equivalent already exists in the camera
/// crate; this is the face region, which is what the cues are measured on.
pub fn saturated_frac_in_bbox(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4], white: u8) -> f32 {
    // Same guard and clamping as mean_in_bbox: a truncated frame degrades to
    // 0.0 rather than panicking the daemon.
    if grey.len() < (w as usize).saturating_mul(h as usize) {
        return 0.0;
    }
    // Both corners clamp to the frame, so a box wholly past the right or
    // bottom edge collapses to an empty region and measures nothing, which is
    // what it saw. `mean_in_bbox` and its siblings clamp the same way since
    // #225; before that they left a one-pixel strip of an unrelated edge.
    let x1 = (bbox[0].max(0.0) as u32).min(w);
    let y1 = (bbox[1].max(0.0) as u32).min(h);
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut clipped, mut n) = (0u64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            if grey[(y * w + x) as usize] >= white {
                clipped += 1;
            }
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        clipped as f32 / n as f32
    }
}

/// [`Signals::ir_saturated_frac`] for a capture, or `None` when the reading
/// cannot be taken: no face was detected, or the negotiated format cannot say
/// where its ceiling is (`white` is `None`).
///
/// Both absences are the same kind of fact, and neither is zero clipping. A
/// corpus recording 0.0 for "not measured" would answer #221 wrongly on
/// exactly the cameras where the question is hardest to see.
pub fn saturated_frac_of(
    grey: &[u8],
    w: u32,
    h: u32,
    bbox: Option<&[f32; 4]>,
    white: Option<u8>,
) -> Option<f32> {
    Some(saturated_frac_in_bbox(grey, w, h, bbox?, white?))
}

/// Face width as a fraction of frame width: the framing guide's `face_frac`,
/// computed from a detection box so the liveness path can record the same
/// quantity the guide judges seating distance by (#174).
pub fn bbox_width_frac(bbox: &[f32; 4], frame_width: u32) -> f32 {
    if frame_width == 0 {
        return 0.0;
    }
    (bbox[2] - bbox[0]).max(0.0) / frame_width as f32
}

/// `Signals::face_frac` for a capture: the top detection's width fraction, or
/// 0.0 when nothing was detected.
///
/// Separated from the two call sites so the DECISION (no face means no
/// distance signal, not a fabricated one) is a value a test can construct.
/// What remains untestable off hardware is only which frame each caller
/// hands in, one expression per path.
pub fn face_frac_of(bbox: Option<&[f32; 4]>, frame_width: u32) -> f32 {
    bbox.map(|b| bbox_width_frac(b, frame_width)).unwrap_or(0.0)
}

/// The IR center/edge cue: ratio of the center-box mean to the edge-ring mean
/// of the IR face crop (grey 0-255). A real 3D face lit by the near-coaxial
/// emitter is brighter at the center/nose and falls off at the rim (ratio
/// above 1); a flat matte screen/photo reads ~1. This is a brightness ratio,
/// not a range measurement: a glossy print with a hot specular center clears
/// it (docs/pad-results/2026-06-30-ir-liveness-selftest.md), which is why it is
/// one cue and not a liveness proof. Returns 0.0 on a degenerate bbox or a
/// near-black edge (no signal, never inf).
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
    // The in-bounds test below is against the logical w/h, so a frame buffer
    // shorter than w*h would still index past the slice. Same guard as
    // mean_in_bbox: a truncated IR frame degrades to 0.0 (no glint cue, a safe
    // fail-closed for liveness) instead of panicking the root daemon.
    if grey.len() < (w as usize).saturating_mul(h as usize) {
        return 0.0;
    }
    // NaN saturates to (0,0) at the casts below, and a landmark set with ONE
    // unplaceable eye is a set the producer got wrong, not half a
    // measurement: score 0.0 for the whole set rather than letting the valid
    // eye vouch for it (#293 review; skipping per eye left that hole).
    if !landmarks[0..2]
        .iter()
        .all(|&(x, y)| x.is_finite() && y.is_finite())
    {
        return 0.0;
    }
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

/// [`eye_glint`], but honest about a reading that reached the sensor's ceiling.
///
/// `None` means the peak established nothing, for one of three reasons, and it
/// is NOT a dark eye. Same distinction [`saturated_frac_of`] draws next door,
/// and for the same reason: a number nobody could measure must not be recorded
/// as a number that was measured.
///
/// - No IR face (`landmarks` is `None`), so no eye window exists to sample.
/// - The peak reached `white`, the negotiated format's ceiling. A clipped
///   sample tells you the true value was AT LEAST that, never what it was, and
///   a maximum is exactly the statistic that destroys. This is the #222
///   reading: the repo's own measurements have the peak pinned at 255 in all
///   30 frames with glasses on, where it is reading the lens specular rather
///   than the cornea, and 8 of 8 `glint_present` records in
///   `docs/pad-results/2026-08-04-occluder-gate.jsonl` are railed at exactly
///   255. In that corpus "glint present" and "the peak railed" are the same
///   set, so the cue records the sensor's limit rather than the eye.
///
/// `white` of `None` means the format could not name a ceiling (`Grey16`,
/// `Nv12Luma`, `YuyvLuma`), and there the peak passes through unchanged. That
/// is #237's settled precedent, not a fresh judgement: refusing on a number
/// nobody produced would deny every module that does not negotiate GREY8.
///
/// Note the ceiling test wants the RAW frame. Ambient subtraction moves a
/// railed 255 to 254, so a subtracted frame would quietly stop reading as
/// railed; callers pass the same unsubtracted samples `saturated_frac_of` gets.
pub fn eye_glint_of(
    grey: &[u8],
    w: u32,
    h: u32,
    landmarks: Option<&Landmarks5>,
    white: Option<u8>,
) -> Option<f32> {
    // Delegates so the truncated-frame and NaN-landmark guards above are
    // inherited rather than copied; a second copy would drift.
    let peak = eye_glint(grey, w, h, landmarks?);
    match white {
        Some(ceiling) if peak >= f32::from(ceiling) => None,
        _ => Some(peak),
    }
}

/// Specular contrast at the eyes = peak − local-mean brightness, max over both
/// eyes. A live OPEN eye makes a sharp corneal specular spike (high contrast); a
/// CLOSED lid (or a printed/vinyl "eye") is diffuse (low). This is the basis of
/// the ADR-0002 blink challenge and has far better SNR than raw peak glint: a
/// closed lid still reflects 850nm, so peak alone barely drops, but the specular
/// spike (hence contrast) collapses. Live-validated 2026-06-30: genuine open-eye
/// contrast ≈120, a static vinyl banner ≈70 (flat).
pub fn eye_glint_contrast(grey: &[u8], w: u32, h: u32, landmarks: &Landmarks5) -> f32 {
    // See eye_glint: guard the w*h invariant so a truncated IR frame returns 0.0
    // (flat contrast, fail-closed) rather than indexing past the slice.
    if grey.len() < (w as usize).saturating_mul(h as usize) {
        return 0.0;
    }
    // Whole-set rule, same as eye_glint: one unplaceable eye means the set's
    // producer got it wrong, and `.max()` over the two eyes would let the
    // valid one vouch for it (#293 review).
    if !landmarks[0..2]
        .iter()
        .all(|&(x, y)| x.is_finite() && y.is_finite())
    {
        return 0.0;
    }
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
    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan, LEGACY_RECOGNIZER_SPACE};

    /// Serializes access to process-wide env vars (`IRLUME_GRACE_MS`,
    /// `IRLUME_STATE_DIR`, `IRLUME_METHOD_CONF`, ...) across this binary's
    /// parallel test threads. Engine tests share it via `super::tests`.
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A head-shake decline is TERMINAL: `resolve_consent_watch` returns the
    /// stream's `Some(false)` verdict without evaluating the completed-take
    /// closure, so a completed-take nod or closure reading can never overturn a
    /// decline into a grant. The panicking closures prove the completed take is
    /// not consulted for either `Some` outcome; before the fix a shake fell
    /// through to it and a take carrying the shake motion could be re-read as an
    /// approval. Only a budget-exhausted `None` consults the boundary check.
    #[test]
    fn shake_decline_is_terminal_and_skips_completed_take() {
        assert!(
            !resolve_consent_watch(Some(false), || panic!(
                "a decline must not evaluate the completed take"
            )),
            "a head-shake decline must resolve to false"
        );
        assert!(
            resolve_consent_watch(Some(true), || panic!(
                "an in-loop accept must not evaluate the completed take"
            )),
            "an in-loop accept must resolve to true"
        );
        assert!(
            resolve_consent_watch(None, || true),
            "budget exhausted defers to the completed-take check"
        );
        assert!(
            !resolve_consent_watch(None, || false),
            "budget exhausted with no completed-take gesture is a miss"
        );
    }

    /// `Misconfigured` permits NO gesture, which is the entire reason the
    /// variant exists.
    ///
    /// This had no test. The decision lived inline in `consent_gesture_inputs`,
    /// which needs an `Engine` and an `Enrollment` to call, so restoring the old
    /// `mode != ConsentGesture::Closure` left `cargo test --workspace` green
    /// while a head nod alone released the TPM-sealed keyring password on a
    /// system configured for eye closure by an operator who typed `clousure`
    /// (#365 review).
    #[test]
    fn misconfigured_enables_no_gesture() {
        use irlume_common::config::ConsentGesture;

        assert_eq!(
            gestures_permitted_by(ConsentGesture::Misconfigured),
            (false, false),
            "an unreadable setting must not permit a nod OR a closure"
        );

        // Every other mode is unchanged, so the fail-closed state cannot have
        // been bought by breaking the working ones.
        assert_eq!(gestures_permitted_by(ConsentGesture::Nod), (true, false));
        assert_eq!(
            gestures_permitted_by(ConsentGesture::Closure),
            (false, true)
        );
        assert_eq!(gestures_permitted_by(ConsentGesture::Either), (true, true));

        // The negative form this function must never be written in. `!= Closure`
        // answers YES for Misconfigured, and that is the whole defect; asserting
        // the two disagree pins the difference rather than the spelling.
        let negative_form_would_allow_nod =
            ConsentGesture::Misconfigured != ConsentGesture::Closure;
        assert!(
            negative_form_would_allow_nod,
            "precondition: the negative form really does permit a nod here"
        );
        assert_ne!(
            gestures_permitted_by(ConsentGesture::Misconfigured).0,
            negative_form_would_allow_nod,
            "the decision has been rewritten in the negative form the comment forbids"
        );
    }

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
                embed_space: None,
                ir_center_edge_ratio: 0.0,
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
                ir_calibs: Default::default(),
            },
            probe,
        )
    }

    #[test]
    fn ir_match_uses_calibration_and_scores_centroid() {
        let (prof, probe) = calibrated_profile(16);
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        let raw = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &probe);
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
        let with_adapter = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, true, &enr, &probe);
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
        assert_eq!(
            grace_window_ms(Some("service-invented-tomorrow")),
            GRACE_WINDOW_MS,
            "an unrecognised service takes the long window, not a shortcut"
        );
    }

    /// Every service the policy calls Elevation must also take the SHORT
    /// window, which is the invariant the two hard-coded lists broke (#362).
    ///
    /// `doas` is the instance that was live: Elevation in
    /// `biopolicy::classify`, absent from the grace list, so it held the camera
    /// and the worker for 15s instead of 5s on a request this project already
    /// classifies as terminal elevation. Walking the shared table rather than
    /// naming doas alone means the next name added cannot reintroduce the split.
    #[test]
    fn every_elevation_and_consent_service_takes_the_short_window() {
        let _g = env_guard();
        std::env::remove_var("IRLUME_GRACE_MS");
        use irlume_common::pam_service::{ServiceKind, SERVICES};
        let mut checked = 0;
        for (name, kind) in SERVICES {
            let want = if kind.wants_short_grace() {
                SUDO_GRACE_WINDOW_MS
            } else {
                GRACE_WINDOW_MS
            };
            assert_eq!(grace_window_ms(Some(name)), want, "{name} ({kind:?})");
            checked += 1;
        }
        assert!(checked >= 30, "the table shrank to {checked} rows");
        // The two that motivated this, named so a reader sees them.
        assert_eq!(grace_window_ms(Some("doas")), SUDO_GRACE_WINDOW_MS);
        assert_eq!(grace_window_ms(Some("polkit-1")), SUDO_GRACE_WINDOW_MS);
        assert_eq!(
            irlume_common::pam_service::classify("doas"),
            Some(ServiceKind::Elevation)
        );
    }

    /// An unmeasurable IR exposure must NOT be retried (#358).
    ///
    /// It arrives as `Verdict::Uncertain`, which is the retryable class, and
    /// that is the trap: the condition is a property of the camera's negotiated
    /// format, identical on every frame. Retrying spends the entire grace
    /// window to reach the same answer and then falls back to the password
    /// anyway, while the user is told to adjust something that cannot help.
    #[test]
    fn an_unmeasurable_exposure_is_not_retryable() {
        use irlume_liveness::Verdict;
        // Built from the real producer's wording, not a literal, so a reword in
        // irlume-liveness that drops the prefix fails here instead of silently
        // making the refusal retryable again.
        let mut sig = irlume_liveness::Signals {
            rgb_face: Some(irlume_liveness::FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.9,
            }),
            ir_face: Some(irlume_liveness::FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.9,
            }),
            ir_face_brightness: 90.0,
            ir_center_edge_ratio: 1.2,
            // Option since #222: a railed peak records as absent, so the
            // readable case has to say so.
            ir_eye_glint: Some(220.0),
            ..Default::default()
        };
        sig.ir_ceiling_known = false;
        let (verdict, _, reason) = irlume_liveness::LivenessGate::new().evaluate(&sig);
        assert_eq!(verdict, Verdict::Uncertain, "precondition for this test");
        assert!(
            reason.starts_with(EXPOSURE_UNMEASURABLE_PREFIX),
            "the prefix this routing keys on moved: {reason}"
        );

        let kind = liveness_deny_kind(verdict, &reason);
        assert_eq!(
            kind,
            OutcomeKind::OtherDeny,
            "must leave the retryable class"
        );
        assert!(
            !presence_retryable(&denied(kind, &reason, false)),
            "retrying an unmeasurable format burns the grace window for nothing"
        );

        // A blown-out frame IS still retryable: moving back really can fix it,
        // so this change must not have swept the ordinary case out with it.
        let mut blown = sig.clone();
        blown.ir_ceiling_known = true;
        blown.ir_saturated_frac = Some(0.9);
        let (bv, _, br) = irlume_liveness::LivenessGate::new().evaluate(&blown);
        let bk = liveness_deny_kind(bv, &br);
        assert_eq!(bk, OutcomeKind::Uncertain, "{br}");
        assert!(presence_retryable(&denied(bk, &br, false)), "{br}");

        // The DARK evaluator reaches the same refusal, because
        // `exposure_refusal` is deliberately shared by both. The first version
        // of this fix routed only the cross-spectrum site and left the dark
        // site mapping inline, so on the one camera class this gate exists for
        // a dark login burned the whole grace window reaching this answer
        // repeatedly (#358 review).
        let (dv, _, dr) = irlume_liveness::LivenessGate::new().evaluate_ir_only(&sig);
        assert_eq!(dv, Verdict::Uncertain, "precondition: {dr}");
        assert!(
            dr.starts_with(EXPOSURE_UNMEASURABLE_PREFIX),
            "the dark evaluator stopped producing the pinned prefix: {dr}"
        );
        let dk = liveness_deny_kind(dv, &dr);
        assert_eq!(dk, OutcomeKind::OtherDeny, "{dr}");
        assert!(!presence_retryable(&denied(dk, &dr, false)), "{dr}");

        // And the dark path's ordinary refusals stay exactly as they were, so
        // routing it through the shared classifier changed nothing else.
        let mut dark_flat = sig.clone();
        dark_flat.ir_ceiling_known = true;
        dark_flat.ir_saturated_frac = Some(0.0);
        dark_flat.ir_center_edge_ratio = 0.1;
        let (fv, _, fr) = irlume_liveness::LivenessGate::new().evaluate_ir_only(&dark_flat);
        assert_eq!(fv, Verdict::Spoof, "precondition: {fr}");
        assert_eq!(liveness_deny_kind(fv, &fr), OutcomeKind::Spoof, "{fr}");
    }

    /// Every liveness verdict becomes an `OutcomeKind` through
    /// [`liveness_deny_kind`], never through a comparison written at the call
    /// site.
    ///
    /// The rule exists because the failure mode is a NEW deny site, or an old
    /// one nobody revisited, classifying inline. `liveness_deny_kind` is where
    /// the retryability rules live; a site that maps `Verdict::Uncertain`
    /// itself silently opts out of all of them. That is exactly what happened
    /// with the dark path in #358: the classifier gained the unmeasurable arm,
    /// the dark site kept `let kind = if verdict == Verdict::Uncertain`, and no
    /// behavioural test could see it because the refusal is only reachable
    /// with a camera whose format names no ceiling.
    #[test]
    fn no_deny_site_classifies_a_liveness_verdict_by_hand() {
        let src = include_str!("lib.rs");
        let offenders: Vec<(usize, &str)> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let l = l.trim();
                // The shape that was removed, and the shape a future site would
                // most naturally reintroduce.
                (l.starts_with("let kind = if") || l.starts_with("let kind = match"))
                    && !l.contains("liveness_deny_kind")
            })
            .map(|(i, l)| (i + 1, l.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "these sites classify a liveness verdict by hand instead of calling \
             liveness_deny_kind, so they do not inherit its retryability rules: {offenders:?}"
        );
        // Not vacuous: the call site must actually be there, or this test
        // would pass by having nothing to look at. The needle is assembled
        // from pieces so it does not appear verbatim in the file it scans;
        // spelled inline, the assertion matched its own source and stayed
        // green with the real call site deleted.
        let needle = concat!("liveness_deny_kind", "(verdict, &reason)");
        assert!(
            src.matches(needle).count() >= 2,
            "the deny sites that route through liveness_deny_kind are gone; \
             the rule this test pins has nothing left to hold"
        );
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
    fn uncertain_short_circuit_spares_only_the_dark_login_shape() {
        use irlume_liveness::Verdict;
        // Every Uncertain shape short-circuits (deny before the matching
        // paths, presence-retryable) EXCEPT no-RGB-face-with-IR-face, which
        // is dark login's entry condition (#284):
        // RGB face present (blown/unreadable frame, the #238 case): deny.
        assert!(uncertain_short_circuits(Verdict::Uncertain, true, true));
        assert!(uncertain_short_circuits(Verdict::Uncertain, true, false));
        // No face in either spectrum: deny ("present your face").
        assert!(uncertain_short_circuits(Verdict::Uncertain, false, false));
        // The dark-login shape falls through to the dark branch, which
        // derives its own verdict via evaluate_ir_only.
        assert!(!uncertain_short_circuits(Verdict::Uncertain, false, true));
        // Non-Uncertain verdicts never take this path at all.
        assert!(!uncertain_short_circuits(Verdict::Live, false, true));
        assert!(!uncertain_short_circuits(Verdict::Spoof, true, true));
    }

    #[test]
    fn ir_match_skips_foreign_space_templates() {
        let (mut prof, probe) = calibrated_profile(16);
        for s in &mut prof.scans {
            s.ir_space = Some("adapter:deadbeef0123".into());
        }
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        let m = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &probe);
        assert_eq!(m.n_templates, 0);
        assert!(m.centroid.is_none());
    }

    #[test]
    fn the_matcher_picks_the_calibration_by_recognizer_space() {
        // #288: a profile can hold calibrations for several recognizers, and
        // ir_match_in must apply the LOADED one. Discriminated by presence:
        // with the calibration filed under a different space, the loaded
        // recognizer has none, so the calibrated-centroid protocol does not
        // run at all. Reaching for any available calibration instead of the
        // keyed one puts another model's transform on these templates.
        let (mut prof, probe) = calibrated_profile(16);
        // Control: the calibration is in the legacy slot and the scans are
        // untagged, so the shipped recognizer finds it and scores a centroid.
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof.clone());
        let m = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &probe);
        assert!(
            m.centroid.is_some(),
            "control: the shipped recognizer's own calibration must apply"
        );

        // Same scans, but the only calibration on file belongs to another
        // recognizer: the loaded one must score raw.
        let calib = prof.ir_calib.take().expect("fixture calibration");
        prof.ir_calibs.insert("embed:model-b".into(), calib);
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        let m = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &probe);
        assert_eq!(m.n_templates, 5, "the templates still score");
        assert!(
            m.centroid.is_none(),
            "another recognizer's calibration must not be applied"
        );
    }

    #[test]
    fn ir_match_skips_templates_from_another_recognizer() {
        // The recognizer produces the raw IR embedding, so its identity gates
        // IR matching exactly like RGB matching: a foreign tag is excluded, a
        // matching tag scores, and an untagged scan belongs to the legacy
        // recognizer only. This matcher feeds fusion, IR fallback, the
        // calibrated centroid, and dark IR-only auth, so the one filter covers
        // all four grant paths.
        let (prof, probe) = calibrated_profile(16);
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);

        // Untagged (legacy) templates: comparable ONLY under the legacy space.
        let m = ir_match_in("raw", "embed:not-the-legacy-model", false, &enr, &probe);
        assert_eq!(
            m.n_templates, 0,
            "untagged scans must not reach a foreign recognizer"
        );
        assert!(m.centroid.is_none());
        assert_eq!(m.best, f32::NEG_INFINITY);

        // Tagged templates: comparable exactly under their own space.
        for s in &mut enr.profiles[0].scans {
            s.embed_space = Some("embed:model-b".into());
        }
        let m = ir_match_in("raw", "embed:model-b", false, &enr, &probe);
        assert_eq!(
            m.n_templates, 5,
            "same-recognizer templates must still score"
        );
        let m = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &probe);
        assert_eq!(
            m.n_templates, 0,
            "tagged scans must not reach the legacy recognizer"
        );
    }

    fn scan(v: Vec<f32>) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: v,
            ir: None,
            ir_space: None,
            embed_space: None,
            ir_center_edge_ratio: 0.0,
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
            closure_calibration: None,
            profiles: vec![
                FaceProfile {
                    ir_calib: None,
                    ir_calibs: Default::default(),
                    name: "Face Profile 1".into(),
                    scans: vec![scan(face1.clone())],
                },
                FaceProfile {
                    ir_calib: None,
                    ir_calibs: Default::default(),
                    name: "Face Profile 2".into(),
                    scans: vec![scan(face2.clone())],
                },
            ],
        };
        // Adding face1 under Face Profile 2 -> flagged as belonging to Profile 1.
        assert_eq!(
            colliding_profile(
                &enr,
                &face1,
                Some("Face Profile 2"),
                LEGACY_RECOGNIZER_SPACE,
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .map(|(n, _)| n),
            Some("Face Profile 1".to_string())
        );
        // A novel face collides with nothing.
        assert!(colliding_profile(
            &enr,
            &[0.0, 0.0, 1.0],
            None,
            LEGACY_RECOGNIZER_SPACE,
            irlume_core::RGB_MATCH_THRESHOLD
        )
        .is_none());
        // Same face into its OWN profile (excluded) is fine; that's improving it.
        assert!(colliding_profile(
            &enr,
            &face1,
            Some("Face Profile 1"),
            LEGACY_RECOGNIZER_SPACE,
            irlume_core::RGB_MATCH_THRESHOLD
        )
        .is_none());
    }

    #[test]
    fn an_attempt_counts_as_ir_only_when_ir_saw_a_face_and_rgb_did_not() {
        // The tally that feeds the hint. Its two arguments have DIFFERENT
        // types on purpose, so a swapped call site is a compile error rather
        // than a silent inversion; each combination is pinned here.
        let rgb = [0.0f32; EMBED_DIM];
        let ir = vec![0.0f32; 8];
        let mut shape = CaptureShape::default();
        observe_attempt(&mut shape, None, Some(&ir), 50.0); // the shape #389 is about
        assert_eq!((shape.attempts, shape.ir_only_attempts), (1, 1));
        observe_attempt(&mut shape, Some(&rgb), Some(&ir), 50.0); // both saw a face
        assert_eq!((shape.attempts, shape.ir_only_attempts), (2, 1));
        observe_attempt(&mut shape, Some(&rgb), None, 50.0); // RGB only: not this shape
        assert_eq!((shape.attempts, shape.ir_only_attempts), (3, 1));
        // The brightness accumulates over every attempt, not only the IR-only
        // ones, because the mean it feeds describes what the held loop saw.
        assert_eq!(shape.rgb_mean_sum, 150.0);
        observe_attempt(&mut shape, None, None, 50.0); // no face at all: framing
        assert_eq!(
            (shape.attempts, shape.ir_only_attempts),
            (4, 1),
            "an attempt that saw no face anywhere is an ordinary miss, not starvation"
        );
    }

    #[test]
    fn folding_two_loops_keeps_the_probes_successful_attempt() {
        // The defect this closes: an enrolment reaches its top-up only by
        // capturing a probe scan, and a scan is only captured when
        // `a.embedding` was Some, so RGB demonstrably worked at least once.
        // Replacing the tally with the top-up's let the message still say the
        // colour sensor found a face on no attempt.
        let probe = CaptureShape {
            held_sessions: true,
            attempts: 1,
            ir_only_attempts: 0, // the attempt that produced the scan
            ..CaptureShape::default()
        };
        let top_up = CaptureShape {
            held_sessions: true,
            attempts: 90,
            ir_only_attempts: 90,
            ..CaptureShape::default()
        };
        let mut folded = probe;
        folded.include(top_up);
        assert_eq!((folded.attempts, folded.ir_only_attempts), (91, 90));
        assert!(
            concurrent_starvation_hint(folded).is_none(),
            "one attempt found an RGB face, so 'on every attempt' would be false"
        );

        // Two loops that BOTH only ever saw IR still qualify.
        let mut both_starved = top_up;
        both_starved.include(top_up);
        assert!(concurrent_starvation_hint(both_starved).is_some());

        // Folding into a fresh tally ADOPTS it. Every enrolment starts from a
        // default, and ANDing `held_sessions` against one that has never seen a
        // loop would zero it on the first fold, so the hint could never fire.
        let mut fresh = CaptureShape::default();
        fresh.include(top_up);
        assert_eq!(fresh, top_up);
        assert!(concurrent_starvation_hint(fresh).is_some());

        // A single fallback loop anywhere in the operation disqualifies it: the
        // self-heal recaptured RGB standalone for those attempts.
        let mut mixed = top_up;
        mixed.include(CaptureShape {
            held_sessions: false,
            ..top_up
        });
        assert!(
            concurrent_starvation_hint(mixed).is_none(),
            "held_sessions must AND across the loops, not stay true from the first"
        );
    }

    /// A clean capture (RGB face found) resets the consecutive streak to zero,
    /// so the auto-switch is never reached by summing coincidences weeks apart.
    #[test]
    fn a_clean_capture_resets_the_consecutive_ir_only_streak() {
        let mut shape = CaptureShape::default();
        // Three IR-only attempts in a row.
        observe_attempt(&mut shape, None, Some(&vec![1.0; 512]), 50.0);
        observe_attempt(&mut shape, None, Some(&vec![1.0; 512]), 51.0);
        observe_attempt(&mut shape, None, Some(&vec![1.0; 512]), 52.0);
        assert_eq!(shape.consecutive_ir_only, 3);
        // A clean capture resets.
        observe_attempt(&mut shape, Some(&[0.0; 512]), None, 140.0);
        assert_eq!(shape.consecutive_ir_only, 0);
        // A framing failure (neither embedding) is neutral.
        observe_attempt(&mut shape, None, Some(&vec![1.0; 512]), 50.0);
        assert_eq!(shape.consecutive_ir_only, 1);
        observe_attempt(&mut shape, None, None, 50.0);
        assert_eq!(shape.consecutive_ir_only, 1);
        observe_attempt(&mut shape, None, Some(&vec![1.0; 512]), 50.0);
        assert_eq!(shape.consecutive_ir_only, 2);
    }

    /// When folding two loops, the LAST loop's consecutive streak is the one
    /// that matters, because the top-up runs after the probe.
    #[test]
    fn include_takes_the_last_loops_consecutive_streak() {
        let probe = CaptureShape {
            consecutive_ir_only: 5,
            attempts: 5,
            ir_only_attempts: 5,
            ..CaptureShape::default()
        };
        let top_up = CaptureShape {
            consecutive_ir_only: 3,
            attempts: 3,
            ir_only_attempts: 3,
            ..CaptureShape::default()
        };
        let mut folded = probe;
        folded.include(top_up);
        assert_eq!(
            folded.consecutive_ir_only, 3,
            "the last loop's streak replaces, not sums"
        );
    }

    #[test]
    fn the_starvation_hint_needs_the_held_path_and_every_attempt() {
        // #389: on a pair stored `concurrent` whose camera starves RGB, every
        // enrolment attempt comes back with an IR face and no RGB face, and the
        // message blamed the room. The hint is offered only where the evidence
        // permits it.
        let held_all = CaptureShape {
            held_sessions: true,
            attempts: 10,
            ir_only_attempts: 10,
            ..CaptureShape::default()
        };
        assert!(concurrent_starvation_hint(held_all).is_some());

        // NOT on the fallback path. There `self_heal_may_recapture` returns
        // true, RGB is recaptured standalone and `rgb_top` reassigned, so an
        // IR-only attempt means RGB found no face WITH THE SENSOR TO ITSELF.
        // That rules concurrent starvation out; offering it would assert a
        // cause the code just disproved.
        assert!(concurrent_starvation_hint(CaptureShape {
            held_sessions: false,
            ..held_all
        })
        .is_none());

        // NOT when only some attempts had the shape: that is a user who moved,
        // and the loop recovers from it. The structural case fails identically
        // every time, which is why it exhausts the budget.
        assert!(concurrent_starvation_hint(CaptureShape {
            ir_only_attempts: 9,
            ..held_all
        })
        .is_none());

        // NOT when the loop never ran. Zero of zero is vacuously "every
        // attempt", which is the permissive default this guard must not have.
        assert!(concurrent_starvation_hint(CaptureShape {
            attempts: 0,
            ir_only_attempts: 0,
            ..held_all
        })
        .is_none());
    }

    #[test]
    fn the_solo_probe_reproduces_all_three_measured_cells() {
        // The numbers are the 2026-08-10 NexiGo and ASUS runs, not invented
        // fixtures: ten runs across three conditions, `frame_mean` throughout.
        // The point of pinning them is that a future edit to the rule has to
        // explain itself against hardware rather than against taste.

        // Lit room, starved module: the fault this exists for.
        assert!(solo_probe_confirms_starvation(51.7, 146.9, true));
        assert!(solo_probe_confirms_starvation(51.1, 146.6, true));

        // Dark room, same module. Refused TWICE over, which is why the rule
        // does not lean on the brightness floor alone: the emitter fires during
        // the held phase and leaks into the RGB sensor, so the held frames read
        // BRIGHTER than the solo one and the dimming clause fails by itself.
        assert!(!solo_probe_confirms_starvation(46.6, 18.0, false));
        assert!(
            !solo_probe_confirms_starvation(46.6, 18.0, true),
            "even if a face were found, 18.0 is not a lit scene"
        );
        // The inversion stated in the rule's own arithmetic: with solo at 18.0
        // the dimming bar is 14.4, and the held frames at 46.6 sit far above
        // it, so that clause refuses on its own before the light is consulted.
        // (the arithmetic: 18.0 * 0.80 = 14.4, and the held frames read 46.6)
        // The cell that isolates the brightness floor. A dim room where the solo
        // frame IS brighter than the held ones, so the dimming clause passes and
        // only `lit` refuses. Without this the floor could be deleted and every
        // test here would still pass, because the measured dark cell is refused
        // twice over by the inversion above.
        // (the arithmetic: 30.0 * 0.80 = 24.0, and 5.0 is under it, so the
        // dimming clause passes and only the floor can refuse)
        assert!(
            !solo_probe_confirms_starvation(5.0, 30.0, true),
            "a scene under the brightness floor cannot confirm, however it dims"
        );

        // A lit scene where nothing is being starved: held above the bar.
        assert!(
            !solo_probe_confirms_starvation(130.0, 150.0, true),
            "held above 0.80 of solo is not dimming"
        );

        // Healthy module, lit room: the solo frame is no brighter, because
        // nothing was being starved.
        assert!(!solo_probe_confirms_starvation(161.0, 157.7, true));
        assert!(!solo_probe_confirms_starvation(163.0, 156.0, true));

        // A solo frame that finds nothing confirms nothing, whatever the means.
        assert!(!solo_probe_confirms_starvation(51.7, 146.9, false));
    }

    #[test]
    fn a_confirmed_probe_reports_an_observation_and_a_refutation_changes_nothing() {
        let held_all = CaptureShape {
            held_sessions: true,
            attempts: 10,
            ir_only_attempts: 10,
            ..CaptureShape::default()
        };

        // Confirmed: the message reports what was OBSERVED and names the
        // remedy. It must NOT assert a cause. Nothing recorded that the light,
        // the framing or the person held still between the held attempts and
        // the solo frame, so a lamp switching on produces this same reading
        // with no camera fault at all, and the message has to say so.
        let confirmed = capture_advice(
            held_all,
            Some(StarvationProbeResult {
                confirmed: true,
                held_mean: 51.0,
                solo_mean: 147.0,
            }),
        );
        assert!(
            confirmed.contains("cannot sustain both streams"),
            "{confirmed}"
        );
        assert!(confirmed.contains("camera-tune"), "{confirmed}");
        // The confound is named FIRST, because on a healthy camera in a dark
        // room with a lamp switching on this branch fires wrongly in 4 runs of
        // 4. Leading with the camera would put the wrong cause at the front of
        // the sentence every one of those times.
        let light = confirmed
            .find("If the light changed")
            .expect("names the light");
        let camera = confirmed
            .find("cannot sustain both streams")
            .expect("names the camera");
        assert!(
            light < camera,
            "the explanation that cannot be ruled out must come first: {confirmed}"
        );
        assert!(
            !confirmed.contains("so it is dimming"),
            "the message must not assert a mechanism it did not establish: {confirmed}"
        );

        // Refuted: treated as no probe at all. It must NOT delete the hint,
        // because a user who turned away before the solo frame refutes a camera
        // that really is starving.
        let refuted = capture_advice(
            held_all,
            Some(StarvationProbeResult {
                confirmed: false,
                held_mean: 51.0,
                solo_mean: 147.0,
            }),
        );
        let unprobed = capture_advice(held_all, None);
        assert_eq!(
            refuted, unprobed,
            "a refutation may not suppress a hint it did not disprove"
        );

        // No probe: unchanged from #414, both readings, neither asserted.
        assert!(
            unprobed.contains("check lighting and framing"),
            "{unprobed}"
        );
        assert!(unprobed.contains("dimming its colour stream"), "{unprobed}");
    }

    #[test]
    fn the_capture_advice_always_keeps_the_lighting_clause() {
        // The two causes are indistinguishable from here. An unlit room
        // produces the identical shape, and this repository records it observed
        // live (`uncertain_short_circuits`: rgb faces=0, ir faces=1 at 0.92).
        // So the hint ADDS a second reading and never replaces the first.
        //
        // Deliberately NOT asserted anywhere: that some message omits the word
        // lighting. Such an assertion would pin the regression in place, making
        // the removal of correct dark-room advice a requirement to stay green.
        let held_all = CaptureShape {
            held_sessions: true,
            attempts: 10,
            ir_only_attempts: 10,
            ..CaptureShape::default()
        };
        let with_hint = capture_advice(held_all, None);
        assert!(
            with_hint.contains("check lighting and framing"),
            "the room advice must survive the hint: {with_hint}"
        );
        assert!(
            with_hint.contains("dimming its colour stream"),
            "the second reading must be offered: {with_hint}"
        );
        // The remedy is qualified on purpose. `camera-tune` stores under
        // `ProbeStore::Always` without consulting `conclusive()`, and retention
        // reads 121-126% at an RGB mean of 17, so advising a re-measure without
        // "lit room" talks a user in the dark into persisting a Concurrent
        // verdict computed from noise.
        assert!(
            with_hint.contains("in a lit room"),
            "the re-measure advice must name the lighting it needs: {with_hint}"
        );
        assert!(
            !with_hint.contains("  "),
            "doubled space in a user-facing string: {with_hint}"
        );

        let plain = capture_advice(CaptureShape::default(), None);
        assert_eq!(
            plain, "check lighting and framing",
            "without the evidence the message is unchanged"
        );
    }

    #[test]
    fn a_short_capture_is_refused_before_anything_is_saved() {
        // capture_scans is best-effort, so a request for ten that yields one
        // must refuse rather than save a partial set and report success
        // (#290 review). The capture sits behind a camera, so the decision is
        // the observable shape.
        // A default shape adds nothing: this test is about the count, and the
        // starvation hint has its own.
        let plain = CaptureShape::default();
        assert!(short_capture_refusal(3, 3, plain, None).is_none());
        assert!(short_capture_refusal(1, 1, plain, None).is_none());
        let why = short_capture_refusal(1, 10, plain, None).expect("a short capture must refuse");
        assert!(why.contains("only 1 live scan captured (need 10)"), "{why}");
        assert!(
            why.contains("nothing was saved"),
            "the refusal must say the enrollment is unchanged: {why}"
        );
        // The message reaches a user mid-enrollment, so it must read as a
        // sentence: no run of spaces, and the noun agreeing with the count.
        assert!(
            !why.contains("  "),
            "doubled space in a user-facing string: {why}"
        );
        let plural =
            short_capture_refusal(2, 10, plain, None).expect("a short capture must refuse");
        assert!(plural.contains("only 2 live scans captured"), "{plural}");
        // Zero is short too, which is the case that always refused.
        assert!(short_capture_refusal(0, 1, plain, None).is_some());
    }

    #[test]
    fn room_is_counted_in_the_loaded_space_and_never_underflows() {
        // The bug the per-space limit created: a profile may legally hold the
        // limit under each of several recognizers, so subtracting the TOTAL
        // from the limit underflows once a second model's templates exist,
        // which panics a checked build and wraps to a huge room in release,
        // bypassing the cap. The enroll merge path had two such subtractions
        // (#290 review).
        let mut profile = FaceProfile {
            name: "P1".into(),
            scans: Vec::new(),
            ir_calib: None,
            ir_calibs: Default::default(),
        };
        profile.scans.extend(
            (0..irlume_core::storage::MAX_SCANS_PER_PROFILE).map(|i| FaceScan {
                embed_space: Some("embed:model-a".into()),
                ..scan(vec![i as f32, 0.0, 0.0])
            }),
        );
        profile.scans.extend((0..5).map(|i| FaceScan {
            embed_space: Some("embed:model-b".into()),
            ..scan(vec![0.0, i as f32, 0.0])
        }));
        assert_eq!(
            profile.scans.len(),
            irlume_core::storage::MAX_SCANS_PER_PROFILE + 5,
            "more total scans than the per-recognizer limit, which is legal"
        );
        assert_eq!(scan_room_in(&profile, "embed:model-a"), 0);
        assert_eq!(
            scan_room_in(&profile, "embed:model-b"),
            irlume_core::storage::MAX_SCANS_PER_PROFILE - 5
        );
        // A recognizer with nothing enrolled has the full allowance, and the
        // computation never underflows for any space.
        assert_eq!(
            scan_room_in(&profile, "embed:model-c"),
            irlume_core::storage::MAX_SCANS_PER_PROFILE
        );
    }

    #[test]
    fn every_capture_is_checked_for_a_foreign_owner_not_only_the_first() {
        // A second person stepping into frame partway through an add-scan
        // session must be caught. The loop sits behind a camera, so the
        // decision is the testable shape: a capture whose FIRST scan is clean
        // and whose second belongs to another profile must still refuse.
        let mine = unit(vec![1.0, 0.0, 0.0]);
        let theirs = unit(vec![0.0, 1.0, 0.0]);
        let enr = Enrollment {
            user: "u".into(),
            profiles: vec![
                FaceProfile {
                    ir_calib: None,
                    ir_calibs: Default::default(),
                    name: "Mine".into(),
                    scans: vec![scan(mine.clone())],
                },
                FaceProfile {
                    ir_calib: None,
                    ir_calibs: Default::default(),
                    name: "Theirs".into(),
                    scans: vec![scan(theirs.clone())],
                },
            ],
            ..Default::default()
        };
        let thr = irlume_core::RGB_MATCH_THRESHOLD;
        // All mine: nothing to refuse.
        assert!(foreign_owner_in_capture(
            &enr,
            &[&mine, &mine],
            "Mine",
            LEGACY_RECOGNIZER_SPACE,
            thr
        )
        .is_none());
        // The intruder arrives on the SECOND capture: checking only the first
        // would miss it.
        assert_eq!(
            foreign_owner_in_capture(
                &enr,
                &[&mine, &theirs],
                "Mine",
                LEGACY_RECOGNIZER_SPACE,
                thr
            )
            .map(|(n, _)| n),
            Some("Theirs".to_string())
        );
        // And on the first, the case that always worked.
        assert_eq!(
            foreign_owner_in_capture(
                &enr,
                &[&theirs, &mine],
                "Mine",
                LEGACY_RECOGNIZER_SPACE,
                thr
            )
            .map(|(n, _)| n),
            Some("Theirs".to_string())
        );
    }

    #[test]
    fn collision_uses_the_engines_threshold_not_the_shipped_constant() {
        // A third-party recognizer brings its own measured threshold, and the
        // enrollment anti-mixing decision must use it: a pair that counts as
        // "same person" on the shipped scale may be strangers on another
        // model's scale. cos(a,b) here is ~0.6: a collision at the shipped
        // 0.55, not a collision at a stricter 0.8.
        // Exact by construction: cos(a,b) = 0.65 for unit a=[1,0,0] and
        // b=[0.65, sqrt(1-0.65^2), 0].
        let a = unit(vec![1.0, 0.0, 0.0]);
        let b = unit(vec![0.65, (1.0f32 - 0.65 * 0.65).sqrt(), 0.0]);
        let c = align::cosine(&a, &b);
        assert!(c > 0.55 && c < 0.8, "fixture cosine drifted: {c}");
        let enr = Enrollment {
            user: "u".into(),
            profiles: vec![FaceProfile {
                ir_calib: None,
                ir_calibs: Default::default(),
                name: "P1".into(),
                scans: vec![scan(b)],
            }],
            ..Default::default()
        };
        assert!(
            colliding_profile(&enr, &a, None, LEGACY_RECOGNIZER_SPACE, 0.55).is_some(),
            "must collide at the shipped threshold"
        );
        assert!(
            colliding_profile(&enr, &a, None, LEGACY_RECOGNIZER_SPACE, 0.8).is_none(),
            "must not collide at a stricter model threshold"
        );
    }

    #[test]
    fn collision_never_compares_across_recognizer_spaces() {
        // A template from another recognizer must not decide enrollment
        // dispositions, even when its raw vector is IDENTICAL to the probe:
        // a foreign-space cosine could merge a stranger into an unrelated
        // profile or reject a legitimate add-scan.
        let face = vec![1.0, 0.0, 0.0];
        let mut foreign = scan(face.clone());
        foreign.embed_space = Some("embed:model-b".into());
        let enr = Enrollment {
            user: "u".into(),
            profiles: vec![FaceProfile {
                ir_calib: None,
                ir_calibs: Default::default(),
                name: "P1".into(),
                scans: vec![foreign],
            }],
            ..Default::default()
        };
        // Under any OTHER recognizer the identical vector is invisible...
        assert!(colliding_profile(
            &enr,
            &face,
            None,
            LEGACY_RECOGNIZER_SPACE,
            irlume_core::RGB_MATCH_THRESHOLD
        )
        .is_none());
        assert_eq!(
            enroll_merge_target(
                &enr,
                &[&face],
                LEGACY_RECOGNIZER_SPACE,
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .unwrap(),
            None
        );
        // ...and under its own recognizer it collides as it always did (the
        // positive control that proves the filter, not the vector, decided).
        assert_eq!(
            colliding_profile(
                &enr,
                &face,
                None,
                "embed:model-b",
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .map(|(n, _)| n),
            Some("P1".to_string())
        );
    }

    #[test]
    fn enroll_merge_target_dispositions() {
        let face1 = vec![1.0, 0.0, 0.0];
        let face2 = vec![0.0, 1.0, 0.0];
        let novel = vec![0.0, 0.0, 1.0];
        let ir_scan = |v: Vec<f32>, space: Option<&str>| FaceScan {
            ir: Some(vec![0.5; 3]),
            ir_space: space.map(String::from),
            embed_space: None,
            ..scan(v)
        };
        let enr_with = |scans: Vec<FaceScan>| {
            let mut enr = Enrollment::new("u");
            enr.profiles.push(FaceProfile {
                ir_calib: None,
                ir_calibs: Default::default(),
                name: "P1".into(),
                scans,
            });
            enr
        };

        // Novel face: no collision, create the new profile.
        let enr = enr_with(vec![ir_scan(face1.clone(), Some("raw"))]);
        assert_eq!(
            enroll_merge_target(
                &enr,
                &[&novel],
                LEGACY_RECOGNIZER_SPACE,
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .unwrap(),
            None
        );

        // Same face merges into its profile regardless of IR-template state:
        // healthy current-space templates...
        assert_eq!(
            enroll_merge_target(
                &enr,
                &[&face1],
                LEGACY_RECOGNIZER_SPACE,
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .unwrap(),
            Some("P1".into())
        );
        // ...untagged legacy templates...
        let enr = enr_with(vec![ir_scan(face1.clone(), None)]);
        assert_eq!(
            enroll_merge_target(
                &enr,
                &[&face1],
                LEGACY_RECOGNIZER_SPACE,
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .unwrap(),
            Some("P1".into())
        );
        // ...templates stranded by an adapter removal (the 0.2.0 upgrade case)...
        let enr = enr_with(vec![
            ir_scan(face1.clone(), Some("adapter:deadbeef0123")),
            ir_scan(face1.clone(), Some("adapter:deadbeef0123")),
        ]);
        assert_eq!(
            enroll_merge_target(
                &enr,
                &[&face1],
                LEGACY_RECOGNIZER_SPACE,
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .unwrap(),
            Some("P1".into())
        );
        // ...or a profile that never had IR scans at all.
        let enr = enr_with(vec![scan(face1.clone())]);
        assert_eq!(
            enroll_merge_target(
                &enr,
                &[&face1],
                LEGACY_RECOGNIZER_SPACE,
                irlume_core::RGB_MATCH_THRESHOLD
            )
            .unwrap(),
            Some("P1".into())
        );

        // Captures matching two different profiles: refused outright.
        let mut enr = enr_with(vec![ir_scan(face1.clone(), Some("adapter:deadbeef0123"))]);
        enr.profiles.push(FaceProfile {
            ir_calib: None,
            ir_calibs: Default::default(),
            name: "P2".into(),
            scans: vec![ir_scan(face2.clone(), Some("adapter:deadbeef0123"))],
        });
        let err = enroll_merge_target(
            &enr,
            &[&face1, &face2],
            LEGACY_RECOGNIZER_SPACE,
            irlume_core::RGB_MATCH_THRESHOLD,
        )
        .unwrap_err();
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
        let m = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &short_probe);
        assert_eq!(m.n_templates, 0);
        assert!(m.centroid.is_none());
        assert_eq!(m.best, f32::NEG_INFINITY);
        // The right width still matches.
        assert_eq!(
            ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &probe).n_templates,
            5
        );
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
            let m = ir_match_in(space, LEGACY_RECOGNIZER_SPACE, false, &enr, &probe);
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
            ir_calibs: Default::default(),
            scans: vec![FaceScan {
                name: "s".into(),
                rgb: vec![0.0; 4],
                ir: Some(v.to_vec()),
                ir_space: Some("raw".into()),
                embed_space: None,
                ir_center_edge_ratio: 0.0,
                ir_brightness: 0.0,
                pitch: 0.0,
            }],
        };
        let mut enr = Enrollment::new("u");
        enr.profiles.push(mk_prof("A", &a));
        enr.profiles.push(mk_prof("B", &b));
        let m = ir_match_in("raw", LEGACY_RECOGNIZER_SPACE, false, &enr, &b);
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
        // A bbox that straddles the frame clamps to the frame.
        assert!((mean_in_bbox(&grey, w, h, &[-9.0, -9.0, 99.0, 99.0]) - 45.0).abs() < 1e-4);
        assert_eq!(mean_in_bbox(&grey, w, h, &[3.0, 1.0, 3.0, 1.0]), 0.0);
        // A frame shorter than w*h (truncated/mismatched capture) must degrade
        // to 0.0, not panic on the out-of-bounds index.
        assert_eq!(mean_in_bbox(&grey[..3], w, h, &[0.0, 0.0, 4.0, 2.0]), 0.0);
    }

    /// A region wholly outside the frame contains no pixels, so every
    /// bbox-sampling helper must measure nothing rather than substitute the
    /// frame's far edge. The old clamp put the near corner at w-1 and the far
    /// one at w, leaving a one-pixel strip of the opposite side of the image
    /// whose mean was returned as the region's (#225). All three helpers had
    /// the same clamp, so all three are pinned here: fixing one and leaving
    /// its siblings is how this survived the first time.
    #[test]
    fn a_region_off_the_frame_measures_nothing_in_every_helper() {
        let (w, h) = (4u32, 2u32);
        let grey = [10u8, 20, 30, 40, 50, 60, 70, 80];
        // Bright far edge, so an accidental one-column sample is loud.
        let rgb: Vec<u8> = (0..(w * h)).flat_map(|i| [(i * 30) as u8; 3]).collect();

        for off in [
            [9.0f32, 0.0, 99.0, 2.0], // wholly right of the frame
            [0.0, 9.0, 4.0, 99.0],    // wholly below it
            [9.0, 9.0, 99.0, 99.0],   // past the corner
            [-99.0, 0.0, -9.0, 2.0],  // wholly left, clamped to zero width
        ] {
            assert_eq!(mean_in_bbox(&grey, w, h, &off), 0.0, "mean_in_bbox {off:?}");
            assert_eq!(luma_in_bbox(&rgb, w, h, &off), 0.0, "luma_in_bbox {off:?}");
            assert_eq!(
                rgb_luma_stats(&rgb, w, h, &off),
                (0.0, 0.0),
                "rgb_luma_stats {off:?}"
            );
        }

        // The on-frame answers are untouched: this changes off-frame boxes
        // only, and a face detection is always at least partly on-frame.
        assert!((mean_in_bbox(&grey, w, h, &[0.0, 0.0, 4.0, 2.0]) - 45.0).abs() < 1e-4);
        assert!((mean_in_bbox(&grey, w, h, &[2.0, 0.0, 4.0, 2.0]) - 55.0).abs() < 1e-4);
    }

    /// `face_frac` is the seating-distance signal the framing guide already
    /// judges by, recorded with the liveness cues so the #174 correlation is
    /// answerable from ordinary debug output. It is a fraction of frame
    /// width, so it must not depend on the frame's pixel dimensions.
    #[test]
    fn bbox_width_frac_is_a_fraction_of_frame_width() {
        // Same face, same relative size, two sensor resolutions.
        assert!((bbox_width_frac(&[100.0, 0.0, 292.0, 200.0], 640) - 0.3).abs() < 1e-6);
        assert!((bbox_width_frac(&[200.0, 0.0, 584.0, 400.0], 1280) - 0.3).abs() < 1e-6);
        // The guide's accepted band, as ends: 12% and 55% of the frame.
        assert!((bbox_width_frac(&[0.0, 0.0, 76.8, 50.0], 640) - 0.12).abs() < 1e-6);
        assert!((bbox_width_frac(&[0.0, 0.0, 352.0, 300.0], 640) - 0.55).abs() < 1e-6);
        // Degenerate inputs report no face rather than a negative or a NaN.
        assert_eq!(bbox_width_frac(&[300.0, 0.0, 100.0, 50.0], 640), 0.0);
        assert_eq!(bbox_width_frac(&[0.0, 0.0, 100.0, 50.0], 0), 0.0);
    }

    /// The clipped fraction is what #221 needs to know whether a real
    /// authentication ever measures its cues on a blown exposure. The ceiling
    /// is supplied by the caller because it is a property of the negotiated
    /// format, not of this arithmetic.
    #[test]
    fn saturated_frac_counts_pixels_at_or_above_the_supplied_ceiling() {
        let (w, h) = (4u32, 2u32);
        // Row 0 at 255, row 1 below it.
        let grey = [255u8, 255, 255, 255, 200, 254, 0, 128];
        let f = |bbox: &[f32; 4], white: u8| saturated_frac_in_bbox(&grey, w, h, bbox, white);
        assert_eq!(f(&[0.0, 0.0, 4.0, 1.0], 255), 1.0);
        assert_eq!(f(&[0.0, 1.0, 4.0, 2.0], 255), 0.0);
        assert_eq!(f(&[0.0, 0.0, 4.0, 2.0], 255), 0.5);
        // A limited-range YUV ceiling counts 254 and 255 alike, which is the
        // whole reason the ceiling is a parameter: at white=235 the second row
        // contributes its 254.
        assert_eq!(f(&[0.0, 1.0, 4.0, 2.0], 235), 0.25);
        // Out-of-frame boxes clamp; a degenerate box reports nothing.
        assert_eq!(f(&[-9.0, -9.0, 99.0, 99.0], 255), 0.5);
        assert_eq!(f(&[3.0, 1.0, 3.0, 1.0], 255), 0.0);
        // A box wholly past the right or bottom edge measures NOTHING, which
        // every bbox-sampling helper has agreed on since #225.
        assert_eq!(f(&[10.0, 0.0, 20.0, 2.0], 255), 0.0);
        assert_eq!(f(&[0.0, 9.0, 4.0, 12.0], 255), 0.0);
        // A truncated frame degrades like mean_in_bbox, never panics.
        assert_eq!(
            saturated_frac_in_bbox(&grey[..3], w, h, &[0.0, 0.0, 4.0, 2.0], 255),
            0.0
        );
    }

    /// Two different absences, one meaning: NOT MEASURED. Recording 0.0 for
    /// either would put "no clipping seen" in the corpus for a capture nobody
    /// could measure, and #221 would then be answered wrongly on exactly the
    /// cameras where clipping is hardest to see.
    #[test]
    fn saturated_frac_of_is_absent_without_a_face_or_a_known_ceiling() {
        let grey = [255u8; 16];
        let bbox = [0.0f32, 0.0, 4.0, 4.0];
        assert_eq!(saturated_frac_of(&grey, 4, 4, None, Some(255)), None);
        assert_eq!(saturated_frac_of(&grey, 4, 4, Some(&bbox), None), None);
        assert_eq!(saturated_frac_of(&grey, 4, 4, None, None), None);
        assert_eq!(
            saturated_frac_of(&grey, 4, 4, Some(&bbox), Some(255)),
            Some(1.0)
        );
    }

    /// Ambient subtraction hides the ceiling it subtracts from, so the exposure
    /// gate must read the raw gate frame that `IrCaptureStats::saturation_frame`
    /// preserves. Measuring the returned pixels instead reports a blown face as
    /// pristine, which is the fail-open the #238 review found: 255 minus an
    /// ambient 1 is 254, and 254 is not at the ceiling.
    #[test]
    fn subtraction_hides_clipping_so_the_gate_reads_the_raw_frame() {
        let bbox = [0.0f32, 0.0, 4.0, 4.0];
        // A face region a quarter of which reached the sensor ceiling.
        let raw: Vec<u8> = [
            255, 255, 255, 255, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        ]
        .into_iter()
        .collect();
        let ambient = vec![1u8; 16];
        let returned = irlume_camera::ir_probe::subtract(&raw, &ambient);

        assert_eq!(
            saturated_frac_of(&returned, 4, 4, Some(&bbox), Some(255)),
            Some(0.0),
            "control: the returned image no longer shows the clipping"
        );
        assert_eq!(
            saturated_frac_of(&raw, 4, 4, Some(&bbox), Some(255)),
            Some(0.25),
            "the raw gate frame is where the clipping is still measurable"
        );
    }

    /// No detection means NO distance signal, and 0.0 is how that is spelled:
    /// a reader correlating cues against face size must be able to drop those
    /// rows rather than treat them as "a face filling nothing".
    #[test]
    fn face_frac_of_reports_zero_when_nothing_was_detected() {
        assert_eq!(face_frac_of(None, 640), 0.0);
        let bbox = [100.0f32, 0.0, 292.0, 200.0];
        assert!((face_frac_of(Some(&bbox), 640) - 0.3).abs() < 1e-6);
    }

    /// The center/edge ratio's GEOMETRY is bbox-relative (the inner box is
    /// half the bbox per side), so the same face filling more of the frame
    /// must read the same ratio. This is what makes #174 a question about
    /// physics and pixel count rather than about the formula: it isolates
    /// the one part that is scale invariant by construction, so a
    /// correlation found on hardware cannot be blamed on the sampling
    /// geometry.
    #[test]
    fn center_edge_ratio_is_invariant_to_apparent_face_size() {
        // One synthetic "face": a bright center square on a dim rim, drawn at
        // two scales in two frames, each filling its bbox identically.
        let render = |side: u32| -> Vec<u8> {
            let mut buf = vec![40u8; (side * side) as usize];
            let q = side / 4;
            for y in q..(side - q) {
                for x in q..(side - q) {
                    buf[(y * side + x) as usize] = 200;
                }
            }
            buf
        };
        let small = render(40);
        let large = render(160);
        let r_small = center_edge_ratio(&small, 40, 40, &[0.0, 0.0, 40.0, 40.0]);
        let r_large = center_edge_ratio(&large, 160, 160, &[0.0, 0.0, 160.0, 160.0]);
        assert!(r_small > 1.0 && r_large > 1.0, "{r_small} {r_large}");
        assert!(
            (r_small - r_large).abs() < 0.05,
            "the ratio must not move with apparent size on identical content: \
             {r_small} vs {r_large}"
        );
        // The pixel count behind it does move, and the guard against a face
        // too small to sample is a hard floor, not a gradual one.
        assert_eq!(
            center_edge_ratio(&small, 40, 40, &[0.0, 0.0, 4.0, 4.0]),
            0.0
        );
    }

    #[test]
    fn center_edge_ratio_rises_with_center_emphasis() {
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

    /// A peak that reached the format's ceiling measured nothing, and must not
    /// be recorded as the strongest possible reading (#222).
    #[test]
    fn a_glint_at_the_ceiling_reads_as_absent_not_as_maximal() {
        // ONE glint, so the peak over both eye windows is the value set here;
        // with two the other eye's 250 would mask what is being tested.
        let (mut grey, lm) = ir_frame_with_glints(true, false);
        grey[20 * 64 + 20] = 255;

        // Full-range GREY8: 255 is the ceiling, so the reading says nothing.
        assert_eq!(eye_glint_of(&grey, 64, 48, Some(&lm), Some(255)), None);
        // One grey level below the ceiling is a real measurement.
        grey[20 * 64 + 20] = 254;
        assert_eq!(
            eye_glint_of(&grey, 64, 48, Some(&lm), Some(255)),
            Some(254.0)
        );

        // Limited-range (235) rails earlier, and `>=` covers 236..=255 as well,
        // matching how the saturation fraction tests its own ceiling.
        grey[20 * 64 + 20] = 235;
        assert_eq!(eye_glint_of(&grey, 64, 48, Some(&lm), Some(235)), None);
        assert_eq!(
            eye_glint_of(&grey, 64, 48, Some(&lm), Some(255)),
            Some(235.0)
        );

        // A format that cannot name its ceiling passes the peak through, which
        // is exactly today's behaviour. #237 settled this direction: refusing on
        // a number nobody produced would deny every non-GREY8 module.
        grey[20 * 64 + 20] = 255;
        assert_eq!(
            eye_glint_of(&grey, 64, 48, Some(&lm), None),
            Some(255.0),
            "no known ceiling means no ceiling test"
        );

        // No IR face is an absence, not a measured dark eye.
        assert_eq!(eye_glint_of(&grey, 64, 48, None, Some(255)), None);
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

        // The window is BOUNDED: a bright pixel away from both eyes must not
        // be picked up. Moved here from a duplicate of this function that
        // irlume-cli carried for its dev probe; the probe now calls this one
        // (#222), and the copy went with it rather than the assertion.
        let (w, h) = (64u32, 48u32);
        let mut plain = vec![0u8; (w * h) as usize];
        let lm: Landmarks5 = [
            (10.0, 10.0),
            (30.0, 10.0),
            (20.0, 20.0),
            (12.0, 28.0),
            (28.0, 28.0),
        ];
        assert_eq!(eye_glint(&plain, w, h, &lm), 0.0);
        plain[(12 * w + 12) as usize] = 200; // inside radius 8 of the left eye
        plain[(44 * w + 60) as usize] = 255; // far from both: must not count
        assert_eq!(
            eye_glint(&plain, w, h, &lm),
            200.0,
            "a bright pixel outside both eye windows must not become the peak"
        );
    }

    #[test]
    fn nan_landmarks_never_read_the_frame_corner_as_an_eye() {
        // Rust's saturating float→int cast turns NaN into 0, so before the
        // finite guards a NaN eye sampled pixel (0,0). With a bright corner
        // (emitter bloom is a realistic stand-in) the probe measured
        // eye_glint=255 and both_eyes_open=TRUE from landmarks that do not
        // exist. All three cues must fail closed instead.
        let (mut grey, _) = ir_frame_with_glints(false, false);
        // A SPIKE over darker neighbors, not a uniform block: the contrast
        // cue is peak minus local mean, so a uniform corner reads 0.0 with or
        // without the guard and the assertion below would not discriminate
        // (the mutant that removes the guard survived exactly that way).
        for y in 0..4u32 {
            for x in 0..4u32 {
                grey[(y * 64 + x) as usize] = 60;
            }
        }
        grey[0] = 255;
        let nan: Landmarks5 = [(f32::NAN, f32::NAN); 5];
        assert_eq!(eye_glint(&grey, 64, 48, &nan), 0.0);
        assert_eq!(eye_glint_contrast(&grey, 64, 48, &nan), 0.0);
        assert!(!both_eyes_open(&grey, 64, 48, &nan, Some(255)));
        // One placeable eye is still not both eyes, and the glint helpers
        // score the whole set 0.0 rather than letting the valid eye vouch
        // for a set whose producer emitted a non-finite point (#293 review:
        // per-eye skipping let a bright valid eye carry the score). The
        // placeable eye sits ON a bright disk so the unguarded value is
        // provably nonzero.
        let (mut bright, lm) = ir_frame_with_glints(true, true);
        for y in 0..4u32 {
            for x in 0..4u32 {
                bright[(y * 64 + x) as usize] = 60;
            }
        }
        bright[0] = 255;
        let one: Landmarks5 = [lm[0], (f32::NAN, 20.0), lm[2], lm[3], lm[4]];
        assert!(!both_eyes_open(&bright, 64, 48, &one, Some(255)));
        assert_eq!(eye_glint(&bright, 64, 48, &one), 0.0);
        assert_eq!(eye_glint_contrast(&bright, 64, 48, &one), 0.0);
    }

    #[test]
    fn both_eyes_open_requires_a_glint_at_each_eye() {
        let (grey, lm) = ir_frame_with_glints(true, true);
        assert!(both_eyes_open(&grey, 64, 48, &lm, Some(255)));
        // One closed lid (no specular point) fails the gate, conservatively.
        let (grey, lm) = ir_frame_with_glints(true, false);
        assert!(!both_eyes_open(&grey, 64, 48, &lm, Some(255)));
        let (grey, lm) = ir_frame_with_glints(false, false);
        assert!(!both_eyes_open(&grey, 64, 48, &lm, Some(255)));
    }

    /// #386, and the reason the suite above never went red: `ir_frame_with_glints`
    /// models a closed eye as NO specular at all. A real closed lid behind a
    /// spectacle lens still returns the emitter, railed. On hardware on
    /// 2026-08-08 that granted 3/3 with the eyes shut, and every frame with
    /// glasses on in the repo's own measurements has the eye peak pinned at 255.
    ///
    /// A railed window is therefore built here explicitly. It clears
    /// EYE_OPEN_PEAK_MIN by construction, so before this fix it read as an open
    /// eye no matter what the eyelid was doing.
    #[test]
    fn a_railed_eye_window_cannot_report_an_open_eye() {
        let (mut grey, lm) = ir_frame_with_glints(false, false);
        // Rail both eye windows, the lens-specular signature.
        for &(ex, ey) in &lm[0..2] {
            let (cx, cy) = (ex as usize, ey as usize);
            for dy in 0..3usize {
                for dx in 0..3usize {
                    grey[(cy + dy - 1) * 64 + (cx + dx - 1)] = 255;
                }
            }
        }
        assert!(
            !both_eyes_open(&grey, 64, 48, &lm, Some(255)),
            "a window at the sensor ceiling establishes nothing about the eyelid"
        );
        // The refusal is the CEILING's doing, not a lower threshold sneaking in:
        // told the format names no ceiling, the same buffer still reads open,
        // which is #237's settled precedent for Grey16/NV12/YUYV.
        assert!(
            both_eyes_open(&grey, 64, 48, &lm, None),
            "with no ceiling to compare against, the peak passes through"
        );
        // And a genuine sub-ceiling corneal glint is untouched: this fix must
        // not deny the users the gate is supposed to admit.
        let (open, lm) = ir_frame_with_glints(true, true);
        assert!(both_eyes_open(&open, 64, 48, &lm, Some(255)));
    }

    /// The other half of #386, which the test above cannot see. Rejecting a
    /// railed peak is worth nothing if the gate is handed the SUBTRACTED frame,
    /// because subtraction moves every railed 255 to 254: under the ceiling and
    /// over `EYE_OPEN_PEAK_MIN`, so both eyes report open again.
    ///
    /// The first assertion states that trap as a fact rather than describing
    /// it, so the second one has something to be different from.
    #[test]
    fn the_eyes_open_gate_measures_the_raw_frame_not_the_subtracted_one() {
        let (mut raw, lm) = ir_frame_with_glints(false, false);
        for &(ex, ey) in &lm[0..2] {
            let (cx, cy) = (ex as usize, ey as usize);
            for dy in 0..3usize {
                for dx in 0..3usize {
                    raw[(cy + dy - 1) * 64 + (cx + dx - 1)] = 255;
                }
            }
        }
        // What ambient subtraction does to a railed sample.
        let returned: Vec<u8> = raw.iter().map(|&p| p.saturating_sub(1)).collect();
        assert!(
            both_eyes_open(&returned, 64, 48, &lm, Some(255)),
            "the subtracted frame alone reads open; this is the regression the \
             selection exists to prevent"
        );
        assert!(
            !eyes_open_from_capture(&returned, Some(&raw), 64, 48, &lm, Some(255)),
            "the ceiling test must run against the preserved raw frame"
        );
        // With nothing preserved, the returned frame IS the raw one, so the
        // fallback must not become a second way to skip the check.
        let (open, lm2) = ir_frame_with_glints(true, true);
        assert!(eyes_open_from_capture(&open, None, 64, 48, &lm2, Some(255)));
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

    /// A truncated IR frame (buffer shorter than w*h, from a driver reporting a
    /// short sizeimage) must degrade both glint cues to 0.0, not panic the root
    /// daemon on an out-of-bounds index. The landmarks sit deep in the frame, so
    /// an unguarded index would run past the short slice.
    #[test]
    fn glint_cues_survive_a_truncated_ir_frame() {
        let (grey, lm) = ir_frame_with_glints(true, true);
        let short = &grey[..grey.len() / 4]; // buffer well under w*h
        assert_eq!(eye_glint(short, 64, 48, &lm), 0.0);
        assert_eq!(eye_glint_contrast(short, 64, 48, &lm), 0.0);
        // The require-eyes-open gate reads the same frame via a different index
        // path; a truncated frame there must fail-closed (eyes read closed), not
        // panic the daemon on an out-of-bounds index.
        assert!(!both_eyes_open(short, 64, 48, &lm, Some(255)));
    }
}

#[cfg(test)]
mod thirdparty_cue_tests {
    use super::{thirdparty_abstains, thirdparty_downgrades};
    use irlume_common::thirdparty::{Stage, CATALOG, MEASURED_GENUINE_CEILING};

    /// The PAD entries only: these invariants are about P(fake) scores, and a
    /// recognition entry's threshold is a cosine in a different unit entirely.
    /// Sweeping the whole catalog here silently asserted PAD semantics onto
    /// the first recognition entry.
    fn pad_entries() -> impl Iterator<Item = &'static irlume_common::thirdparty::ThirdPartyModel> {
        CATALOG.iter().filter(|m| m.stage == Stage::Pad)
    }
    use irlume_liveness::Verdict;

    #[test]
    fn fires_only_on_live_plus_confident_fake() {
        assert!(thirdparty_downgrades(Verdict::Live, Some(0.9), 0.5));
        assert!(thirdparty_downgrades(Verdict::Live, Some(0.5), 0.5)); // at threshold
        assert!(!thirdparty_downgrades(Verdict::Live, Some(0.49), 0.5));
        assert!(!thirdparty_downgrades(Verdict::Live, None, 0.5));
    }

    #[test]
    fn the_shipped_threshold_sits_above_every_score_a_genuine_face_produced() {
        // The 2026-07-17 qualification measured genuine faces at 0.001-0.13 and
        // the vinyl-print attack at 0.998-1.0000. A threshold inside that empty
        // band denies on scores neither class was ever observed at, which is how
        // a live face lost its keyring at 0.702 on 2026-07-27.
        let mut seen = 0;
        for m in pad_entries() {
            seen += 1;
            assert!(
                m.threshold > MEASURED_GENUINE_CEILING,
                "{}: threshold {} is at or below the measured genuine ceiling {}",
                m.name,
                m.threshold,
                MEASURED_GENUINE_CEILING
            );
            assert!(
                m.threshold >= 0.9,
                "{}: threshold {} reaches into the band no attack was measured in",
                m.name,
                m.threshold
            );
        }
        assert!(seen > 0, "no PAD entries swept; the loop proved nothing");
    }

    #[test]
    fn the_threshold_stays_below_the_lowest_score_a_real_attack_produced() {
        // 2026-07-27, same vinyl banner as the qualification, threshold 0.9:
        // 6/6 flagged at 0.941, 0.956, 0.995, 0.999, 0.999, 1.000. The floor is
        // 0.941, well under the 0.998-1.0000 medians the qualification reported,
        // so raising this threshold for a feeling of safety would drop a real
        // detection. The window is 0.702 (highest genuine) to 0.941.
        const MEASURED_ATTACK_FLOOR: f32 = 0.941;
        let mut seen = 0;
        for m in pad_entries() {
            seen += 1;
            assert!(
                m.threshold < MEASURED_ATTACK_FLOOR,
                "{}: threshold {} is at or above the lowest score a real attack \
                 produced ({MEASURED_ATTACK_FLOOR}); that loses a detection",
                m.name,
                m.threshold
            );
        }
        assert!(seen > 0, "no PAD entries swept; the loop proved nothing");
    }

    #[test]
    fn a_score_in_the_unmeasured_band_abstains_instead_of_denying() {
        let thr = 0.9;
        // 0.702 is the real reading that denied a genuine user before this fix.
        assert!(thirdparty_abstains(Some(0.702), thr));
        assert!(!thirdparty_downgrades(Verdict::Live, Some(0.702), thr));
        // Below the genuine ceiling is an ordinary pass, not an abstention.
        assert!(!thirdparty_abstains(Some(0.05), thr));
        // At and above the threshold the cue still denies: the attack species
        // measured 0.998-1.0000, well clear of this line.
        assert!(!thirdparty_abstains(Some(0.9), thr));
        assert!(thirdparty_downgrades(Verdict::Live, Some(0.9), thr));
        assert!(thirdparty_downgrades(Verdict::Live, Some(0.998), thr));
        // No score at all is neither.
        assert!(!thirdparty_abstains(None, thr));
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

/// Engine tests against the REAL shipped models (fetched under `models/` by
/// scripts/fetch-models.sh), with
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
            embed_space: None,
            ir_center_edge_ratio: 1.3,
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
        // The engine loaded the shipped glintr100.onnx, so its embedding space
        // must BE the pinned legacy space: this ties Engine::load's full-digest
        // tag, models/SHA256SUMS, and LEGACY_RECOGNIZER_SPACE together. If this
        // fails after a deliberate recognizer change, mint a NEW space rather
        // than repointing the legacy constant — untagged templates were made by
        // the old model, and the constant exists to say exactly that.
        assert_eq!(
            e.embed_space(),
            irlume_core::storage::LEGACY_RECOGNIZER_SPACE,
            "shipped recognizer no longer matches the pinned legacy space"
        );
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
    fn device_selection_carries_ir_availability_and_honours_forced_off() {
        // #281: the selection, not the load-time probe, decides IR
        // availability. The truth table is the testable decision (this suite
        // keeps IRLUME_FORCE_NO_IR=1 set process-wide, so the positive arm is
        // unreachable through a real engine here):
        assert!(ir_selection_available(true, false));
        assert!(!ir_selection_available(false, false));
        // The #282 review's regression: the operator's forced-convenience
        // override must outrank an existing selected path. The first cut
        // overwrote it — and the first version of THIS test only passed
        // because of that cancellation.
        assert!(!ir_selection_available(true, true));
        assert!(!ir_selection_available(false, true));

        // Through the real engine, under the suite's forced-off env: an
        // existing IR path must STAY unavailable via both entry points, and a
        // nonexistent one reads unavailable either way.
        let _g = env_guard();
        let mut s = shared();
        s.engine.set_devices(NO_RGB, "/dev/null");
        assert!(
            !s.engine.ir_available(),
            "forced-off must survive a runtime switch to an existing IR path"
        );
        assert_eq!(s.engine.tier(), Tier::Convenience);
        s.engine.set_devices(NO_RGB, NO_IR); // restore the shared baseline
        drop(s);
        let e = Engine::load(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &model_path("glintr100.onnx"),
        )
        .expect("engine load")
        .with_devices(NO_RGB, "/dev/null");
        assert!(
            !e.ir_available(),
            "forced-off must survive the builder with an existing IR path"
        );
        // The assignment itself, discriminated: under this suite's forced-off
        // env every computed value is false, so a deleted assignment is
        // invisible to the asserts above (its mutant survived exactly that
        // way). Pre-forcing the field TRUE makes the entry points' write the
        // only thing that can restore the truth.
        let mut e = e;
        e.ir_available = true;
        let e = e.with_devices(NO_RGB, NO_IR);
        assert!(
            !e.ir_available(),
            "with_devices must WRITE the selection's answer, not keep state"
        );
        let mut e = e;
        e.ir_available = true;
        e.set_devices(NO_RGB, NO_IR);
        assert!(
            !e.ir_available(),
            "set_devices must WRITE the selection's answer, not keep state"
        );
    }

    #[test]
    fn refit_profile_calib_fits_skips_and_defers_to_the_adapter() {
        let _g = env_guard();
        let mut s = shared();
        // Healthy paired 512-D scans in the current space: calibration fits.
        let mut prof = FaceProfile {
            name: "p".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: (0..5).map(|i| scan512(i, true, Some("raw"))).collect(),
        };
        s.engine.refit_profile_calib(&mut prof);
        let calib = prof.ir_calib.as_ref().expect("calibration fitted");
        assert_eq!(calib.fitted_pairs, 5);
        // Wrong-dimension IR templates are quarantined: nothing to fit.
        let mut bad = FaceProfile {
            name: "bad".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
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
            ir_calibs: Default::default(),
            scans: (0..5)
                .map(|i| scan512(i, true, Some("adapter:deadbeef0123")))
                .collect(),
        };
        s.engine.refit_profile_calib(&mut foreign);
        assert!(foreign.ir_calib.is_none());
        // Templates from another RECOGNIZER are skipped too: fitting across
        // embedding spaces would produce a calibration describing neither.
        let mut foreign_rec = FaceProfile {
            name: "foreign-rec".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: (0..5)
                .map(|i| FaceScan {
                    embed_space: Some("embed:model-b".into()),
                    ..scan512(i, true, Some("raw"))
                })
                .collect(),
        };
        s.engine.refit_profile_calib(&mut foreign_rec);
        assert!(foreign_rec.ir_calib.is_none());
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
            ir_calibs: Default::default(),
            scans: (0..5).map(|i| scan512(i, true, Some("raw"))).collect(),
        };
        s.engine.refit_profile_calib(&mut fresh);
        assert!(fresh.ir_calib.is_none(), "adapter mode must not fit anew");
        s.engine.ir_adapter = None; // restore the shared baseline
    }

    #[test]
    fn thirdparty_recognizer_policy_threshold_and_ir_shutdown() {
        let _g = env_guard();
        let mut s = shared();
        // Default: the shipped constant, scaled; IR matching on.
        assert_eq!(
            s.engine.rgb_grant_threshold(1),
            irlume_core::RGB_MATCH_THRESHOLD
        );
        assert!(s.engine.ir_matching);
        // An IR-scanned enrollment the choke point can be proven against.
        let mut enr = Enrollment::new("u");
        enr.profiles.push(FaceProfile {
            name: "p".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: (0..3).map(|i| scan512(i, true, Some("raw"))).collect(),
        });
        let probe = unit512(0);
        assert_eq!(
            s.engine.ir_match(&enr, &probe).n_templates,
            3,
            "control: IR matching must work before the policy flips"
        );

        // The third-party policy: measured threshold in, IR matching dead.
        s.engine.rgb_threshold = 0.60;
        s.engine.ir_matching = false;
        assert_eq!(s.engine.rgb_grant_threshold(1), 0.60);
        // Scaling still applies on top of the model's own base.
        assert!(s.engine.rgb_grant_threshold(8) > 0.60);
        // The choke point: no IR template is scored, whoever asks.
        let m = s.engine.ir_match(&enr, &probe);
        assert_eq!(m.n_templates, 0);
        assert_eq!(m.best, f32::NEG_INFINITY);
        assert!(m.centroid.is_none());
        // And no calibration is fitted, so nothing on disk implies dark
        // support that cannot exist for this model.
        let mut prof = FaceProfile {
            name: "p2".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: (0..5).map(|i| scan512(i, true, Some("raw"))).collect(),
        };
        s.engine.refit_profile_calib(&mut prof);
        assert!(prof.ir_calib.is_none());

        // Restore the shared baseline; prove the restore took (a poisoned
        // shared engine would fail every later test for the wrong reason).
        s.engine.rgb_threshold = irlume_core::RGB_MATCH_THRESHOLD;
        s.engine.ir_matching = true;
        assert_eq!(s.engine.ir_match(&enr, &probe).n_templates, 3);
        s.engine.refit_profile_calib(&mut prof);
        assert!(prof.ir_calib.is_some(), "restored engine must fit again");
    }

    #[test]
    fn verified_recognizer_bytes_are_the_loaded_embedding_space() {
        // The weights loader exists so a caller's pin check, the
        // template-space digest, and the ONNX session all come from ONE
        // buffer: the digest must be of exactly the bytes handed in, or a path
        // swap between a caller's checksum and this load could pair new
        // weights with a threshold measured for old ones (#279 review).
        let _g = env_guard();
        let _s = shared(); // ensure ORT is initialized for this process
        let bytes = std::fs::read(model_path("glintr100.onnx")).unwrap();
        let expected = format!("embed:{}", irlume_common::thirdparty::sha256_hex(&bytes));
        let weights = irlume_common::HashedModel::new(bytes);
        let engine = Engine::load_with_recognizer_weights(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &weights,
        )
        .expect("engine from bytes");
        assert_eq!(engine.embed_space(), expected);
    }

    #[test]
    fn with_thirdparty_recognizer_sets_both_halves_of_the_policy() {
        // The builder is the public face of the policy: one call, both
        // effects. Split halves would let a future caller set the threshold
        // and forget the IR shutdown.
        let _g = env_guard();
        let s = shared();
        // Cheap structural check on a rebuilt engine is not possible without
        // loading models again; assert via the builder on a clone of the
        // shared engine's config instead: consume-and-rebuild is what the
        // daemon does, so exercise exactly that shape.
        drop(s);
        let e = Engine::load(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &model_path("glintr100.onnx"),
        )
        .expect("engine load")
        .with_devices(NO_RGB, NO_IR)
        .with_thirdparty_recognizer(0.6, "fixture-rec");
        assert_eq!(e.rgb_grant_threshold(1), 0.6);
        assert!(!e.ir_matching);
        assert_eq!(e.thirdparty_recognizer_name(), Some("fixture-rec"));
    }

    #[test]
    fn a_refit_under_one_recognizer_leaves_another_models_calibration_alone() {
        // #288, the switching scenario end to end through the engine: a
        // profile calibrated under the shipped recognizer, then refitted
        // while a different recognizer is loaded, must keep BOTH. The single
        // slot made the second refit destroy the first, so switching back
        // applied the wrong model's calibration inside ir_match_in.
        let _g = env_guard();
        let mut s = shared();
        let shipped = s.engine.embed_space().to_string();
        let mut prof = FaceProfile {
            name: "p".into(),
            ir_calib: None,
            ir_calibs: Default::default(),
            scans: (0..5).map(|i| scan512(i, true, Some("raw"))).collect(),
        };
        s.engine.refit_profile_calib(&mut prof);
        let shipped_pairs = prof
            .calib_for(&shipped)
            .expect("shipped calibration fitted")
            .fitted_pairs;

        // Now the same profile gains scans from another recognizer, and a
        // refit runs with that recognizer loaded.
        let other = "embed:model-b";
        prof.scans.extend((10..15).map(|i| FaceScan {
            embed_space: Some(other.to_string()),
            ..scan512(i, true, Some("raw"))
        }));
        s.engine.embed_space = other.to_string();
        s.engine.refit_profile_calib(&mut prof);
        s.engine.embed_space = shipped.clone(); // restore the shared baseline

        assert!(
            prof.calib_for(other).is_some(),
            "the loaded recognizer must get its own calibration"
        );
        assert_eq!(
            prof.calib_for(&shipped).map(|c| c.fitted_pairs),
            Some(shipped_pairs),
            "the other recognizer's calibration must survive the refit"
        );
        // Both recognizers must remain fully usable: their own templates
        // score AND their own calibration runs. n_templates alone proves
        // only the space filter, since it is counted before the calibration
        // lookup; the calibrated-centroid protocol running is what shows the
        // keyed calibration actually reached the matcher (#289 review).
        let mut enr = Enrollment::new("u");
        enr.profiles.push(prof);
        let model_b = ir_match_in("raw", other, false, &enr, &unit512(0));
        assert_eq!(
            model_b.n_templates, 5,
            "only model B's templates score under B"
        );
        assert!(
            model_b.centroid.is_some(),
            "model B's keyed calibration must run the calibrated-centroid protocol"
        );
        let shipped_match = ir_match_in("raw", &shipped, false, &enr, &unit512(0));
        assert_eq!(
            shipped_match.n_templates, 5,
            "only the shipped recognizer's templates score after switching back"
        );
        assert!(
            shipped_match.centroid.is_some(),
            "the shipped recognizer's preserved calibration must still apply"
        );
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
            ir_calibs: Default::default(),
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
            ir_calibs: Default::default(),
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
            ir_calibs: Default::default(),
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

        // authenticate() derives the purpose from the service class, fresh per
        // call, via forced_consent_for: polkit-1 is AppConsent, sudo (and None)
        // are plain Verify.
        assert!(forced_consent_for(Some("polkit-1")));
        assert!(!forced_consent_for(Some("sudo")));
        assert!(!forced_consent_for(None));
        assert_eq!(
            AuthenticationPurpose::for_service(Some("polkit-1")),
            AuthenticationPurpose::AppConsent
        );
        assert_eq!(
            AuthenticationPurpose::for_service(Some("sudo")),
            AuthenticationPurpose::Verify
        );
        // Escape hatch: IRLUME_POLKIT_GESTURE=0 turns the forcing off.
        std::env::set_var("IRLUME_POLKIT_GESTURE", "0");
        assert!(!forced_consent_for(Some("polkit-1")));
        assert_eq!(
            AuthenticationPurpose::for_service(Some("polkit-1")),
            AuthenticationPurpose::Verify
        );
        std::env::remove_var("IRLUME_POLKIT_GESTURE");

        // The shared engine runs IR-less (IRLUME_FORCE_NO_IR), where the blink
        // gate cannot run. BOTH a FORCED gate and the per-enrollment opt-in must
        // then withdraw the grant (fail closed to the password).
        let enr = Enrollment::new("irlume-test-consent");
        let granted = || Outcome::grant(0.9, "match");
        let out = s
            .engine
            .challenge_if_required(&enr, AuthenticationPurpose::AppConsent, None, granted())
            .unwrap();
        assert!(!out.granted, "forced gate must fail closed without IR");
        assert!(out.reason.contains("consent gesture"), "{}", out.reason);
        let mut opt_in = Enrollment::new("irlume-test-consent");
        opt_in.require_challenge = true;
        let out = s
            .engine
            .challenge_if_required(&opt_in, AuthenticationPurpose::Verify, None, granted())
            .unwrap();
        assert!(
            out.granted,
            "require_challenge is no longer gating; gesture-based intent supersedes it: {}",
            out.reason
        );

        teardown_sandbox(&dir);
    }

    /// The credential-release gate, purpose by purpose, on an IR-less engine (so
    /// a required gesture always fails and the deny reason names which gate ran).
    ///
    /// The contract: a credential release with the challenge ON demands the
    /// deliberate gesture even for an enrollment that opted into nothing; with the
    /// challenge OFF it falls back to exactly the per-enrollment behaviour, which a
    /// global opt-out must not cancel. Verify is untouched either way.
    #[test]
    fn credential_release_requires_the_gesture_by_default_and_honours_the_opt_out() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("credrelease");

        let plain = Enrollment::new("irlume-test-credrel");
        let mut opted_in = Enrollment::new("irlume-test-credrel");
        opted_in.require_challenge = true;
        let grant = || Outcome::grant(0.9, "match");
        let release = |on: bool| AuthenticationPurpose::CredentialRelease {
            temporal_challenge: on,
        };

        // Challenge ON (the default) + an enrollment that opted into nothing:
        // the deliberate gesture is still required, and fails closed here.
        let out = s
            .engine
            .challenge_if_required(&plain, release(true), None, grant())
            .unwrap();
        assert!(!out.granted, "default-on release must gate: {}", out.reason);
        assert!(
            out.reason.contains("consent gesture"),
            "the gesture gate must be the one that ran: {}",
            out.reason
        );

        // Challenge OFF + no per-enrollment opt-in: today's behaviour, a grant.
        let out = s
            .engine
            .challenge_if_required(&plain, release(false), None, grant())
            .unwrap();
        assert!(out.granted, "opt-out must not add a gate: {}", out.reason);

        // The per-enrollment require_challenge gate is removed. Gesture-based
        // intent (nod/shake) proves both liveness and intent; a print cannot
        // produce a coherent head pose sequence. The require_challenge flag
        // is kept on the struct for backward compat but is no longer checked.
        let out = s
            .engine
            .challenge_if_required(&opted_in, release(false), None, grant())
            .unwrap();
        assert!(
            out.granted,
            "require_challenge is no longer gating; gesture-based intent supersedes it: {}",
            out.reason
        );

        // Verify is unchanged: no opt-in, no gate.
        for purpose in [AuthenticationPurpose::Verify, release(false)] {
            assert!(
                s.engine
                    .challenge_if_required(&plain, purpose, None, grant())
                    .unwrap()
                    .granted,
                "{purpose:?} must not gate a plain enrollment"
            );
        }

        // A DENIED match never reaches any gate (no free gesture prompt for a
        // face that did not match).
        let denied = Outcome::deny_live(OutcomeKind::BelowThreshold, 0.1, "below threshold");
        let out = s
            .engine
            .challenge_if_required(&plain, release(true), None, denied)
            .unwrap();
        assert!(!out.granted);
        assert!(
            out.reason.contains("below threshold"),
            "the deny reason must survive untouched: {}",
            out.reason
        );

        // A gesture seen BEFORE the match satisfies the gate without asking for
        // a second one (issue #101: the watch used to open only after the match,
        // so a user who nodded when the greeter asked was refused). The flag is
        // the only thing that changes here: same enrollment, same purpose, same
        // granted outcome.
        s.engine.gesture_seen_before_match = true;
        let out = s
            .engine
            .challenge_if_required(&plain, release(true), None, grant())
            .unwrap();
        assert!(
            out.granted,
            "a gesture made before the match must satisfy the gate: {}",
            out.reason
        );
        // And it must not persist: cleared, the gate is back to requiring one.
        // (No camera in the sandbox, so the watch fails closed rather than
        // waiting, which is exactly the fail-closed reading of `false`.)
        s.engine.gesture_seen_before_match = false;
        let out = s
            .engine
            .challenge_if_required(&plain, release(true), None, grant())
            .unwrap();
        assert!(
            !out.granted,
            "without a seen gesture the gate must still refuse: {}",
            out.reason
        );

        // demands_gesture is the whole policy surface; pin it.
        assert!(!AuthenticationPurpose::Verify.demands_gesture(None));
        assert!(AuthenticationPurpose::AppConsent.demands_gesture(None));
        assert!(release(true).demands_gesture(None));
        assert!(!release(false).demands_gesture(None));

        teardown_sandbox(&dir);
    }

    /// THE invariant behind a default-on gate: with the challenge required, NO
    /// failure mode may hand back a granted outcome. Every case must be a deny or
    /// an Err, both of which the daemon turns into `Response::Error` and PAM turns
    /// into IGNORE, so the user types their password instead of being locked out.
    ///
    /// Swept across every `consent_gesture` mode and both calibration states,
    /// because those pick different branches inside the gate: a nod needs no
    /// calibration (which is what lets existing enrollments keep working with no
    /// re-enroll), while closure-only without calibration can never be satisfied.
    #[test]
    fn no_credential_release_failure_mode_ever_grants() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("credrelease-safe");
        let release = AuthenticationPurpose::CredentialRelease {
            temporal_challenge: true,
        };

        let mut calibrated = Enrollment::new("irlume-test-safe");
        // A usable open/closed EAR pair, so the closure branch is eligible.
        calibrated.closure_calibration = Some((0.30, 0.10));
        let uncalibrated = Enrollment::new("irlume-test-safe");

        for mode in ["nod", "closure", "either", ""] {
            if mode.is_empty() {
                std::env::remove_var("IRLUME_CONSENT_GESTURE");
            } else {
                std::env::set_var("IRLUME_CONSENT_GESTURE", mode);
            }
            for (label, enr) in [("calibrated", &calibrated), ("uncalibrated", &uncalibrated)] {
                // An Err is as fail-safe as a deny (both become Response::Error, then
                // PAM_IGNORE, then the password prompt), but WHICH error still has to
                // be the one this stage is named for: silently accepting any Err
                // would let the stage pass without exercising its branch at all.
                let assert_no_grant =
                    |engine: &mut Engine, stage: &str, err_must_say: &str| match engine
                        .challenge_if_required(enr, release, None, Outcome::grant(0.95, "match"))
                    {
                        Ok(o) => assert!(
                            !o.granted,
                            "mode={mode} {label} {stage} GRANTED without a gesture: {}",
                            o.reason
                        ),
                        Err(e) => assert!(
                            e.to_string().contains(err_must_say),
                            "mode={mode} {label} {stage} failed for the wrong reason \
                             (wanted {err_must_say:?}): {e}"
                        ),
                    };
                // No IR at all: declined before any camera is touched.
                s.engine.ir_available = false;
                assert_no_grant(&mut s.engine, "no-IR", "camera");
                // IR present, FaceMesh missing: the consent watch cannot classify
                // a frame, so there is no way to observe the gesture.
                s.engine.ir_available = true;
                let mesh = s.engine.mesh.take();
                assert_no_grant(&mut s.engine, "no-mesh", "camera");
                // Mesh loaded but no camera to stream: the watch itself errors out.
                // Assert the mesh really came back, else this repeats the no-mesh
                // case and the stage would prove nothing.
                s.engine.mesh = mesh;
                assert!(
                    s.engine.mesh.is_some(),
                    "the shared engine must carry a FaceMesh for the no-camera stage \
                     to exercise the consent watch rather than the missing-model branch"
                );
                assert_no_grant(&mut s.engine, "no-camera", "no camera found");
            }
        }
        std::env::remove_var("IRLUME_CONSENT_GESTURE");
        s.engine.ir_available = false; // restore the shared baseline
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
            ir_calibs: Default::default(),
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
        let err = s.engine.add_scan("irlume-test-ghost", "P1", 1).unwrap_err();
        assert!(err.to_string().contains("is not enrolled"), "{err}");
        // Known user, unknown profile.
        let mut e = Enrollment::new("irlume-test-add");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
            ir_calibs: Default::default(),
        });
        write_enrollment(&dir, &e);
        let err = s.engine.add_scan("irlume-test-add", "nope", 1).unwrap_err();
        assert!(err.to_string().contains("no face profile 'nope'"), "{err}");
        // Full profile: refused before any capture.
        let mut e = Enrollment::new("irlume-test-full");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: (0..irlume_core::storage::MAX_SCANS_PER_PROFILE)
                .map(|i| scan512(i, false, None))
                .collect(),
            ir_calib: None,
            ir_calibs: Default::default(),
        });
        write_enrollment(&dir, &e);
        let err = s.engine.add_scan("irlume-test-full", "P1", 1).unwrap_err();
        assert!(err.to_string().contains("already has the max"), "{err}");
        // #288: the SAME profile, full of ANOTHER recognizer's scans, is not
        // full for the loaded one. Without per-space counting a profile that
        // had reached the limit under one model could never gain templates
        // for a second, which is the case this feature exists for. It reaches
        // the capture boundary instead of refusing.
        let mut e = Enrollment::new("irlume-test-otherfull");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: (0..irlume_core::storage::MAX_SCANS_PER_PROFILE)
                .map(|i| FaceScan {
                    embed_space: Some("embed:another-model".into()),
                    ..scan512(i, false, None)
                })
                .collect(),
            ir_calib: None,
            ir_calibs: Default::default(),
        });
        write_enrollment(&dir, &e);
        let err = s
            .engine
            .add_scan("irlume-test-otherfull", "P1", 1)
            .unwrap_err();
        assert!(
            err.to_string().contains("no camera found"),
            "a profile full of another recognizer's scans must still accept \
             this one's, got: {err}"
        );
        // Room in the profile: proceeds to the capture boundary.
        let err = s.engine.add_scan("irlume-test-add", "P1", 1).unwrap_err();
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
            .challenge_if_required(&enr_flag(true), AuthenticationPurpose::Verify, None, denied)
            .unwrap();
        assert!(!o.granted);
        // Grant without the opt-in flag: passes through untouched.
        let o = s
            .engine
            .challenge_if_required(
                &enr_flag(false),
                AuthenticationPurpose::Verify,
                None,
                grant(),
            )
            .unwrap();
        assert!(o.granted);
        // The require_challenge flag is no longer checked (gesture-based
        // intent supersedes it). Flag on with no IR or no mesh: grant passes
        // through unchanged.
        assert!(!s.engine.ir_available);
        let o = s
            .engine
            .challenge_if_required(
                &enr_flag(true),
                AuthenticationPurpose::Verify,
                None,
                grant(),
            )
            .unwrap();
        assert!(
            o.granted,
            "require_challenge is no longer gating: {}",
            o.reason
        );
        // Flag on + IR + no mesh: also passes through.
        s.engine.ir_available = true;
        let mesh = s.engine.mesh.take();
        let o = s
            .engine
            .challenge_if_required(
                &enr_flag(true),
                AuthenticationPurpose::Verify,
                None,
                grant(),
            )
            .unwrap();
        assert!(
            o.granted,
            "require_challenge is no longer gating: {}",
            o.reason
        );
        // The require_challenge flag is no longer checked. The passive-liveness
        // capture (run_passive_liveness) still exists for require_eyes_open.
        s.engine.mesh = mesh;
        let o = s
            .engine
            .challenge_if_required(
                &enr_flag(true),
                AuthenticationPurpose::Verify,
                None,
                grant(),
            )
            .unwrap();
        assert!(
            o.granted,
            "require_challenge is no longer gating: {}",
            o.reason
        );
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

    /// The feeder nodes, or a panic (#361). An `#[ignore]`d test that returns
    /// early still prints `ok`, and the CI lane counts passes, so a self-skip
    /// is indistinguishable from a real run.
    fn loopback_pair() -> (String, String) {
        let var = |k: &str| {
            std::env::var(k).unwrap_or_else(|_| {
                panic!(
                    "{k} is unset. This test is #[ignore]d, so running it is a request for the \
                     v4l2loopback harness; it will not silently pass without one."
                )
            })
        };
        (var("IRLUME_TEST_RGB_DEVICE"), var("IRLUME_TEST_IR_DEVICE"))
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
        let (rgb, ir) = loopback_pair();
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
                closure_calibration: None,
                profiles: vec![FaceProfile {
                    ir_calib: None,
                    ir_calibs: Default::default(),
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

    /// An enrolment asked to stop must yield at a capture boundary and leave
    /// nothing behind.
    ///
    /// Run against the loopback feeders, which hold no face, so the enrolment
    /// would otherwise spend its whole retry budget looking for one: that is
    /// precisely the long operation an arriving authentication must not wait
    /// for. The assertions that matter are the typed `Preempted` outcome and an
    /// enrollment store that is still empty afterwards, because a half-written
    /// profile would be worse than the delay this feature removes.
    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_enrolment_stops_when_asked_and_saves_nothing() {
        let (rgb, ir) = loopback_pair();
        let _g = env_guard();
        ort_init();
        let dir = state_sandbox("loopback-preempt");

        let mut e = Engine::load(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &model_path("glintr100.onnx"),
        )
        .expect("engine load")
        .with_devices(&rgb, &ir);
        // Answer "keep going" once so the entry check passes and the camera is
        // opened, then "stop": that lands the yield on the boundary BETWEEN
        // captures, which is the case that has to work. A signal that is true
        // from the start would only prove the cheap entry check.
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&calls);
        e.set_stop_signal(std::sync::Arc::new(move || {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0
        }));

        let err = e
            .enroll_profile("preemptuser", None, 10)
            .expect_err("a stop request must not look like a successful enrolment");
        assert!(
            matches!(err, irlume_common::Error::Preempted(_)),
            "the caller has to tell a yield from a failure, got: {err}"
        );
        assert!(
            err.to_string().contains("retry"),
            "the message should tell the user what to do: {err}"
        );
        assert!(
            irlume_core::storage::load("preemptuser")
                .expect("store readable")
                .is_none(),
            "a stopped enrolment must persist nothing"
        );
        assert!(
            calls.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the yield must come from the in-loop boundary, not only the entry check"
        );

        teardown_sandbox(&dir);
    }

    /// A pose series shaped like the measured #101 boundary: flat until the
    /// last in-loop check point, with the nod completing in the trailing
    /// frames the cadence never evaluates.
    fn boundary_poses() -> Vec<irlume_liveness::PoseSample> {
        [0.5f32; 18]
            .into_iter()
            .chain([0.6, 0.4])
            .enumerate()
            .map(|(idx, pitch)| irlume_liveness::PoseSample {
                idx,
                pitch_frac: Some(pitch),
                yaw_signed: Some(0.0),
                bri: 60.0,
            })
            .collect()
    }

    #[test]
    fn completed_take_catches_a_nod_in_the_trailing_frames() {
        let poses = boundary_poses();
        // The premise first: the prefix the last in-loop check saw must NOT
        // read as a nod, or this test is not about the boundary at all.
        assert_ne!(
            irlume_liveness::detect_nod(&poses[..18]),
            irlume_liveness::HeadGesture::Nod,
            "the 18-pose prefix must be flat"
        );
        // The full take carries the gesture, and the completed-take evaluation
        // must find it even though no in-loop check fired.
        assert!(completed_consent_take_hit(false, true, &poses, &[], None));
        // Removing the completed-take evaluation reduces the decision to
        // hit_in_loop, which is false here: that is the observation that
        // fails if the fix is reverted.
    }

    #[test]
    fn completed_take_respects_the_gesture_inputs() {
        let poses = boundary_poses();
        // With the nod disallowed and no closure calibration, the same series
        // must NOT satisfy the gate: the final evaluation widens coverage of
        // the take, never the set of accepted gestures.
        assert!(!completed_consent_take_hit(false, false, &poses, &[], None));
        // An in-loop hit stands on its own, whatever the series holds.
        assert!(completed_consent_take_hit(true, false, &[], &[], None));
    }

    #[test]
    fn completed_take_stays_quiet_on_a_still_series() {
        // A flat take (today's still windows read pitch_range 0.012-0.029
        // against the 0.075 floor) must not fire through the new path either.
        let poses: Vec<_> = (0..20)
            .map(|idx| irlume_liveness::PoseSample {
                idx,
                pitch_frac: Some(0.5 + (idx % 2) as f32 * 0.01),
                yaw_signed: Some(0.0),
                bri: 60.0,
            })
            .collect();
        assert!(!completed_consent_take_hit(false, true, &poses, &[], None));
    }
}
