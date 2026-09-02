// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Shared authentication orchestration: the one place the security-critical
//! pipeline lives. Both the CLI and the `irlumed` daemon drive this.
//!
//! Flow: capture RGB + IR (firing the IR emitter) → detect → align → embed (RGB)
//! and run the liveness gate on the cross-spectrum signals → on Live, match the
//! embedding against the user's enrolled templates at the fixed threshold.

pub mod capture_plan;

use irlume_common::config::HeadConsentPolicy;
use irlume_liveness::{LivenessGate, Signals, Verdict};
use irlume_vision::model_input::{
    ArcFaceInput, BlazeFaceInput, CanonicalGreyView, CanonicalRgbView, DetectorInput,
    FlirIrPadInput, VitRgbPadInput,
};
use irlume_vision::{align, Adapter, Detection, Embedder, Landmarks5, EMBED_DIM};

pub use irlume_camera::capture_qualification::{
    AttemptOutcome, CaptureQualificationRecord, InconclusiveReason, QualificationMismatch,
    QualificationResolution, QualificationStore, QualificationStoreError, SequentialReason,
};
pub use irlume_camera::lease;
/// Enumerate the Hello camera pairs. Re-exported for the daemon's
/// camera-class `ListCameras` arm: clients must not enumerate for themselves
/// (#187), so this is the only path to a listing.
pub use irlume_camera::{
    camera_rate_diagnostics, list_pairs, privacy_engaged, set_forbid_external_cameras, CameraPair,
};
/// Auto-select the RGB+IR camera pair (built-in or external Hello webcam), plus
/// the stable per-device identity the daemon records alongside a persisted pair
/// so select_pair can survive a udev renumber. Re-exported so the daemon can pick
/// devices without depending on the camera crate directly. See
/// [`irlume_camera::select_pair`].
pub use irlume_camera::{capabilities, device_identity, select_pair, select_rgb};
/// IR-emitter auto-setup (integrated linux-enable-ir-emitter), re-exported for
/// the daemon. See [`irlume_camera::setup_ir_emitter`].
pub use irlume_camera::{
    current_capture_qualification_context, list_ir_controls,
    measure_capture_qualification_with_progress, measure_contention,
    measure_contention_with_progress, no_progress, setup_ir_emitter, store_capture_mode,
    store_capture_mode_if_absent, stored_capture_mode, stored_capture_qualification, CaptureMode,
    CaptureModeOrigin, CaptureQualificationMeasurement, ContentionReport, MeasurementSource,
    PairSample, Progress, StoreIfAbsent,
};

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
    /// Optional MediaPipe FaceMesh: dense landmarks used to refine a BlazeFace
    /// rescue box into alignment points. Loaded iff the model file is present.
    mesh: Option<irlume_vision::FaceMesh>,
    /// Optional BlazeFace short-range RESCUE detector: runs only when YuNet
    /// finds no face (saturated outdoor backgrounds; 2026-07-15 bench: 96.9%
    /// vs YuNet's 76.9% on the sunlight walking bursts). Needs `mesh` to
    /// refine its coarse box into alignment landmarks.
    blaze: Option<Rescue>,
    /// Shipped ViT RGB PAD cue (`liveness_vit.onnx`, ADR-0013, default-on
    /// with the daemon's password-only switch): scores the RGB face chip whenever the
    /// gate verdicted Live and downgrades to Spoof when the rolling median of
    /// the last `VIT_VOTE_N` scores clears `VIT_THRESHOLD`. DENY-ONLY.
    vit_pad: Option<irlume_vision::PadVit>,
    /// Rolling per-request ViT scores for the 5-frame-median vote. Reset at
    /// the start of each authentication (`authenticate_for`), because voting
    /// across requests would mix presentations.
    vit_scores: Vec<f32>,
    /// Shipped IR PAD cue (`flir.onnx`, ADR-0013, default-on with the
    /// daemon's password-only switch): the FLIR classifier at its measured 0.9
    /// threshold, lit-phase IR frames, DENY-ONLY. This is the same weights
    /// and operating point as the opt-in catalog entry; shipping it removes
    /// the enablement step the 2026-07-17 qualification asked operators to run.
    pad_ir: Option<irlume_vision::PadIr>,
    gate: LivenessGate,
    rgb_dev: String,
    ir_dev: String,
    /// Smart-Auto: true when a real RGB+IR Hello camera is present. False = an
    /// RGB-only device → face runs in CONVENIENCE tier (lock-screen unlock only,
    /// RGB-only liveness, never releases credentials / logs in / elevates).
    ir_available: bool,
    /// Typed result of the pre-match head-consent watch for the authentication
    /// currently in flight.
    ///
    /// Set by [`Engine::authenticate_for`] and cleared there when it returns, so
    /// it never outlives one call. It is engine state rather than a parameter
    /// because the grant sites that consult it are spread across the matcher and
    /// threading a verdict through every one of them would obscure them for no
    /// gain. `NoGesture` is the fail-closed default and reset value.
    head_consent_before_match: HeadConsentVerdict,
    /// The facts snapshot of the most recent authentication attempt's
    /// assessment. Set where the assessment binds in `authenticate_once`,
    /// read by the retry loop to write the situation line of a FAILED
    /// attempt (#616 step 2); every attempt refreshes it before any Outcome
    /// exists, so it can never be read stale.
    last_attempt_facts: AttemptFacts,
    /// The classified situation of the most recent FAILED attempt (#616
    /// step 3): stored under the same `!out.granted` guard that journals
    /// the situation line, cleared by a granted final attempt, and exposed
    /// read-only as the label the daemon wires onto `AuthResult` for
    /// pam_irlume's prompt wording. Reporting only: it gates nothing.
    last_attempt_situation: Option<AttemptSituation>,
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
/// BlazeFace on ONNX. The third-party full-range variant was removed with the
/// BYOM lane (ADR-0015); the type stays a newtype rather than collapsing to
/// the bare BlazeRescue so the cascade-stage vocabulary and its one-slot
/// invariant keep their name.
struct Rescue(irlume_vision::BlazeRescue);

impl Rescue {
    fn detect_top(
        &mut self,
        input: &BlazeFaceInput,
    ) -> irlume_common::Result<Option<([f32; 4], f32)>> {
        self.0.detect_top(input)
    }
}

#[cfg(test)]
mod inference_runtime_tests {
    use super::Engine;
    use irlume_vision::inference::{
        DimensionContract, InferenceSession, ModelCompiler, OwnedTensor, SessionContract,
        SessionMetadata, TensorMetadata,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "irlume-inference-runtime-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn model(&self, name: &str, bytes: &[u8]) -> String {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct SessionDrop(Arc<AtomicUsize>);

    impl Drop for SessionDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct RecordingCompiler {
        models: Arc<Mutex<Vec<&'static str>>>,
        dropped: Arc<AtomicUsize>,
        fail_on_call: Option<usize>,
    }

    impl RecordingCompiler {
        fn new() -> Self {
            Self {
                models: Arc::new(Mutex::new(Vec::new())),
                dropped: Arc::new(AtomicUsize::new(0)),
                fail_on_call: None,
            }
        }
    }

    impl ModelCompiler for RecordingCompiler {
        fn compile(
            &mut self,
            _model: &[u8],
            contract: &'static SessionContract,
        ) -> irlume_common::Result<InferenceSession> {
            let call = self.models.lock().unwrap().len() + 1;
            self.models.lock().unwrap().push(contract.model);
            if self.fail_on_call == Some(call) {
                return Err(irlume_common::Error::Hardware(
                    "candidate compile failed".into(),
                ));
            }
            let dimensions = |dimensions: &[DimensionContract]| {
                dimensions
                    .iter()
                    .map(|dimension| match dimension {
                        DimensionContract::Fixed(value) => Some(*value),
                        DimensionContract::FixedOneOf(values) => values.last().copied(),
                        DimensionContract::BatchOneOrDynamic => Some(1),
                    })
                    .collect::<Vec<_>>()
            };
            let metadata = SessionMetadata {
                input: TensorMetadata::f32(
                    contract.input.name,
                    dimensions(contract.input.dimensions),
                ),
                outputs: contract
                    .outputs
                    .iter()
                    .map(|output| TensorMetadata::f32(output.name, dimensions(output.dimensions)))
                    .collect(),
            };
            let dropped = SessionDrop(Arc::clone(&self.dropped));
            InferenceSession::new(contract, metadata, move |_| {
                let _keep_drop_guard = &dropped;
                Ok(contract
                    .outputs
                    .iter()
                    .map(|output| {
                        let shape: Vec<usize> = output
                            .dimensions
                            .iter()
                            .map(|dimension| match dimension {
                                DimensionContract::Fixed(value) => *value,
                                DimensionContract::FixedOneOf(values) => *values.last().unwrap(),
                                DimensionContract::BatchOneOrDynamic => 1,
                            })
                            .collect();
                        OwnedTensor {
                            name: output.name.into(),
                            values: vec![0.0; shape.iter().product()],
                            shape,
                        }
                    })
                    .collect())
            })
        }
    }

    #[test]
    fn inference_runtime_one_compiler_reaches_every_configured_onnx_model() {
        let dir = TestDir::new();
        let det = dir.model("det.onnx", b"det");
        let adapter = dir.model("adapter.onnx", b"adapter");
        let mesh = dir.model("mesh.onnx", b"mesh");
        let blaze = dir.model("blaze.onnx", b"blaze");
        let vit = dir.model("vit.onnx", b"vit");
        let flir = dir.model("flir.onnx", b"flir");
        let recognizer = irlume_common::HashedModel::new(b"recognizer".to_vec());
        let mut runtime = RecordingCompiler::new();

        let engine =
            Engine::load_with_recognizer_weights_and_runtime(&mut runtime, &det, &recognizer)
                .unwrap()
                .with_ir_adapter_with_runtime(&mut runtime, &adapter)
                .unwrap()
                .with_mesh_with_runtime(&mut runtime, &mesh)
                .unwrap()
                .with_blaze_rescue_with_runtime(&mut runtime, &blaze)
                .unwrap()
                .with_vit_pad_with_runtime(&mut runtime, &vit)
                .unwrap()
                .with_pad_ir_with_runtime(&mut runtime, &flir)
                .unwrap();

        assert!(engine.has_ir_adapter());
        assert_eq!(
            engine.ir_space(),
            format!("adapter:{}", &irlume_common::sha256_hex(b"adapter")[..12])
        );
        assert!(engine.has_blaze_rescue());
        assert!(engine.has_vit_pad());
        assert!(engine.has_pad_ir());
        assert_eq!(
            *runtime.models.lock().unwrap(),
            [
                "yunet",
                "auraface",
                "ir-adapter",
                "facemesh",
                "blazeface",
                "vit-pad",
                "flir-pad"
            ]
        );
    }

    #[test]
    fn inference_runtime_absence_and_tflite_never_compile_as_onnx() {
        let dir = TestDir::new();
        let det = dir.model("det.onnx", b"det");
        let tflite = dir.model("mesh.tflite", &[0, 0, 0, 0, b'T', b'F', b'L', b'3']);
        let recognizer = irlume_common::HashedModel::new(b"recognizer".to_vec());
        let mut runtime = RecordingCompiler::new();
        let engine =
            Engine::load_with_recognizer_weights_and_runtime(&mut runtime, &det, &recognizer)
                .unwrap();
        let missing = dir.0.join("absent.onnx").to_string_lossy().into_owned();
        let engine = engine
            .with_ir_adapter_with_runtime(&mut runtime, &missing)
            .unwrap()
            .with_blaze_rescue_with_runtime(&mut runtime, &missing)
            .unwrap()
            .with_vit_pad_with_runtime(&mut runtime, &missing)
            .unwrap()
            .with_pad_ir_with_runtime(&mut runtime, &missing)
            .unwrap();
        assert_eq!(*runtime.models.lock().unwrap(), ["yunet", "auraface"]);

        assert!(engine
            .with_mesh_with_runtime(&mut runtime, &tflite)
            .is_err());
        assert_eq!(*runtime.models.lock().unwrap(), ["yunet", "auraface"]);
    }

    #[test]
    fn inference_runtime_failed_partial_build_drops_every_prior_session() {
        let dir = TestDir::new();
        let det = dir.model("det.onnx", b"det");
        let mesh = dir.model("mesh.onnx", b"mesh");
        let recognizer = irlume_common::HashedModel::new(b"recognizer".to_vec());
        let mut runtime = RecordingCompiler::new();
        runtime.fail_on_call = Some(3);
        let engine =
            Engine::load_with_recognizer_weights_and_runtime(&mut runtime, &det, &recognizer)
                .unwrap();

        assert!(engine.with_mesh_with_runtime(&mut runtime, &mesh).is_err());
        assert_eq!(runtime.dropped.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn inference_runtime_degraded_blaze_failure_keeps_the_same_engine() {
        let dir = TestDir::new();
        let det = dir.model("det.onnx", b"det");
        let blaze = dir.model("blaze.onnx", b"blaze");
        let recognizer = irlume_common::HashedModel::new(b"recognizer".to_vec());
        let mut runtime = RecordingCompiler::new();
        runtime.fail_on_call = Some(3);
        let engine =
            Engine::load_with_recognizer_weights_and_runtime(&mut runtime, &det, &recognizer)
                .unwrap();

        let (engine, error) = engine.with_blaze_rescue_degraded_with_runtime(&mut runtime, &blaze);

        assert!(error.is_some());
        assert!(!engine.has_blaze_rescue());
        assert_eq!(
            *runtime.models.lock().unwrap(),
            ["yunet", "auraface", "blazeface"]
        );
    }
}

fn read_model(path: &str) -> irlume_common::Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| irlume_common::Error::Io(format!("{path}: {error}")))
}

fn model_input_error(error: irlume_vision::model_input::ModelInputError) -> irlume_common::Error {
    irlume_common::Error::Protocol(error.to_string())
}

/// Assurance tier of this engine, derived from the available camera hardware.
pub use irlume_core::biopolicy::Tier;
/// The vision detector, re-exported for the daemon's enrollment preflight
/// closure signature (#613: the preflight measures the detected face region).
pub use irlume_vision::Detector;

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
    /// P(fake) from the SHIPPED IR PAD cue (ADR-0013, `flir.onnx`), when
    /// loaded and an IR face was present. Deny-only: consulted by both the
    /// cross-spectrum verdict (in `assess_full`) and the dark path.
    pub shipped_ir_fake: Option<f32>,
    rgb_pad: PadEvidence,
    ir_pad: PadEvidence,
    /// True when the RGB/IR pair this assessment rests on was admitted only
    /// under the sequential pairing budget (`SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW`,
    /// ADR-0014): the frames were captured as two temporally separated one-shot
    /// bursts, not concurrently. The lit path then defers its RGB-primary grant
    /// to the IR-identity-verified arms (fusion / IR fallback / centroid); see
    /// `rgb_primary_grant_admissible` and ADR-0014.
    pub sequential_pair: bool,
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
    /// A DELIBERATE head-shake decline during the consent watch (pre- or
    /// post-match). Kept distinct from `OtherDeny` so the daemon can report it as
    /// `declined_by_gesture` and pam_irlume can abort a polkit dialog on it, and
    /// only it. Non-retryable: a decline is final, so it stays OUT of
    /// [`presence_retryable`] (the same as `OtherDeny`).
    GestureDeclined,
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

    /// A DELIBERATE head-shake decline: kind [`OutcomeKind::GestureDeclined`], the
    /// class the daemon maps to `declined_by_gesture` and pam_irlume aborts a polkit
    /// dialog on. Built HERE, used by BOTH the pre- and post-match shake sites, so
    /// "a shake is GestureDeclined" is one tested contract, not a class repeated at
    /// two sites where a revert to `OtherDeny` would pass every camera-less test
    /// (pinned by `a_shake_decline_reads_as_a_gesture_decline`). `live`/`score`
    /// carry through from the take (`0.0`/`false` when the shake came before any
    /// match), so the reason is uniform but the evidence is not fabricated.
    fn gesture_declined(live: bool, score: f32) -> Self {
        Self {
            granted: false,
            live,
            score,
            reason: "head shake cancelled the request".into(),
            kind: OutcomeKind::GestureDeclined,
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

/// Enrollment may deliberately use the convenience-tier RGB path after a
/// user-present emitter preflight measured this request's IR stream as dark.
/// Physical IR presence alone must not undo that request-scoped decision.
fn enrollment_ir_enabled(ir_available: bool, force_rgb_only: bool) -> bool {
    ir_available && !force_rgb_only
}

/// One failed authentication attempt's situation, in the stable vocabulary a
/// person reads in `irlume logs` (#616 step 2). Reporting only: derived from
/// facts the attempt already measured, it gates nothing, scores nothing, and
/// moves no bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptSituation {
    NoFace,
    TooFar,
    OffCenter,
    LookingAway,
    IrSource,
    TooDark,
    GlintBelow,
    BelowScore,
    Spoof,
    Declined,
    Other,
}

/// The situation label exactly as it appears in the journal: one stable
/// string each, so `irlume logs` greps by situation.
const fn attempt_situation_label(situation: AttemptSituation) -> &'static str {
    match situation {
        AttemptSituation::NoFace => "no face",
        AttemptSituation::TooFar => "too far",
        AttemptSituation::OffCenter => "off-center",
        AttemptSituation::LookingAway => "looking away",
        AttemptSituation::IrSource => "IR source",
        AttemptSituation::TooDark => "too dark",
        AttemptSituation::GlintBelow => "glint below",
        AttemptSituation::BelowScore => "below score",
        AttemptSituation::Spoof => "spoof",
        AttemptSituation::Declined => "declined",
        AttemptSituation::Other => "other",
    }
}

/// The measured facts one attempt's situation is read from: a Copy snapshot
/// of the [`Assessment`] the attempt produced. The RGB face center is
/// normalized (0..1), exactly as the liveness `FaceBox` carries it.
#[derive(Debug, Clone, Copy, Default)]
struct AttemptFacts {
    rgb_face: Option<(f32, f32)>,
    face_frac: f32,
    yaw_asym: f32,
    rgb_face_brightness: f32,
    glint: Option<f32>,
    ir_bright: f32,
    persistent_ir_source_overwhelms: bool,
}

impl AttemptFacts {
    fn from_assessment(a: &Assessment) -> Self {
        Self {
            rgb_face: a.signals.rgb_face.map(|f| (f.cx, f.cy)),
            face_frac: a.signals.face_frac,
            yaw_asym: a.signals.head_yaw_asym,
            rgb_face_brightness: a.signals.rgb_face_brightness,
            glint: a.signals.ir_eye_glint,
            ir_bright: a.ir_brightness,
            persistent_ir_source_overwhelms: a.signals.persistent_ir_source_overwhelms(),
        }
    }
}

/// Classify one failed attempt. Precedence mirrors the framing guide's
/// severity order, usability situations first, so a genuine user's #617
/// shape (a Spoof verdict on a turned head) reads `looking away` rather
/// than the attack label. Dark-path attempts enter with no RGB face by
/// design and fall through to the IR facts and the outcome kind.
fn auth_attempt_situation(kind: OutcomeKind, f: &AttemptFacts) -> AttemptSituation {
    if kind == OutcomeKind::GestureDeclined {
        return AttemptSituation::Declined;
    }
    // No detection in either spectrum: face_frac is the IR face's share on
    // the pair path and the RGB face's on the RGB-only path, so zero with no
    // RGB face means nothing was seen anywhere.
    if kind == OutcomeKind::NoFace || (f.rgb_face.is_none() && f.face_frac <= 0.0) {
        return AttemptSituation::NoFace;
    }
    if f.face_frac > 0.0 && f.face_frac < MIN_FRAC {
        return AttemptSituation::TooFar;
    }
    if let Some((cx, cy)) = f.rgb_face {
        if (cx - 0.5).abs() > CENTER_TOL || (cy - 0.5).abs() > CENTER_TOL {
            return AttemptSituation::OffCenter;
        }
    }
    if f.yaw_asym > FRAME_YAW_ASYM_MAX {
        return AttemptSituation::LookingAway;
    }
    if f.persistent_ir_source_overwhelms {
        return AttemptSituation::IrSource;
    }
    if f.rgb_face.is_some() && f.rgb_face_brightness < DIM {
        return AttemptSituation::TooDark;
    }
    if f.glint.is_some_and(|g| g < irlume_liveness::GLINT_MIN) {
        return AttemptSituation::GlintBelow;
    }
    if kind == OutcomeKind::BelowThreshold {
        return AttemptSituation::BelowScore;
    }
    if matches!(kind, OutcomeKind::Spoof | OutcomeKind::SpoofNoIrFace) {
        return AttemptSituation::Spoof;
    }
    AttemptSituation::Other
}

/// One journal line per failed attempt (#616 step 2): the situation label,
/// then the measured numbers in a fixed order. Numbers only; no threshold
/// values (those stay in the verdict lines). A glint that railed or was
/// never measured prints `n/a`, the #222 rule: a maximum nobody could
/// measure must not appear as one that was.
fn attempt_situation_line(kind: OutcomeKind, score: f32, f: &AttemptFacts) -> String {
    format!(
        "attempt: {}; face_frac={:.2} yaw={:.2} glint={} ir_bright={:.0} rgb_bright={:.0} \
         score={:.2}",
        attempt_situation_label(auth_attempt_situation(kind, f)),
        f.face_frac,
        f.yaw_asym,
        f.glint
            .map(|g| format!("{g:.2}"))
            .unwrap_or_else(|| "n/a".into()),
        f.ir_bright,
        f.rgb_face_brightness,
        score,
    )
}

/// A dark IR preflight would store an RGB-only enrollment. On a pair that
/// does not authorize concurrent capture, identity requires an IR-verified
/// match (ADR-0014), so such a profile could never grant: refuse it up front
/// instead of storing an enrollment that will be refused at every later
/// attempt (#618). `pair_qualifies_concurrent` is only consulted when the
/// preflight measured dark, so a lit enrollment never pays a store read.
fn dark_ir_rgb_only_enrollment_refusal(
    pair_qualifies_concurrent: impl FnOnce() -> bool,
) -> irlume_common::Result<()> {
    if pair_qualifies_concurrent() {
        return Ok(());
    }
    Err(irlume_common::Error::Protocol(
        "the IR stream measured dark, and this camera pair authenticates by IR: \
         an RGB-only profile could never unlock it. Check the lighting and the \
         emitter (`sudo irlume ir-setup`), then enroll again"
            .into(),
    ))
}

/// Whether the stored qualification authorizes CONCURRENT capture for this
/// pair: the only pair shape an RGB-only enrollment can ever authenticate on
/// (rgb-primary admission requires a non-sequential pair). Absent, unreadable,
/// and context-mismatched records all read "not concurrent": the unmeasured
/// default captures one frame at a time, and so does a stored sequential
/// verdict. No camera is opened; the store is the whole question.
fn pair_qualifies_concurrent(rgb_dev: &str, ir_dev: &str) -> bool {
    let resolved = (|| {
        let context = current_capture_qualification_context(rgb_dev, ir_dev).ok()?;
        let record = QualificationStore::system().load(&context).ok()??;
        Some(matches!(
            record.resolve(&context),
            QualificationResolution::ConcurrentQualified
        ))
    })();
    resolved.unwrap_or(false)
}

/// Mean of the GREY bytes inside a pixel bbox (x1, y1, x2, y2), clamped to
/// the frame. Zero for a degenerate box: an empty region measures nothing
/// and must not read as dark-by-arithmetic. Pure, so the #613 semantics
/// (measure the subject, not the frame) are testable without a camera.
fn grey_mean_in_bbox(data: &[u8], width: u32, height: u32, bbox: &[f32; 4]) -> f32 {
    let (w, h) = (width as usize, height as usize);
    if w == 0 || h == 0 || data.len() < w * h {
        return 0.0;
    }
    let clamp = |v: f32, max: usize| v.clamp(0.0, max as f32) as usize;
    let (x1, y1, x2, y2) = (
        clamp(bbox[0], w),
        clamp(bbox[1], h),
        clamp(bbox[2], w),
        clamp(bbox[3], h),
    );
    let count = (x2.saturating_sub(x1)) * (y2.saturating_sub(y1));
    if count == 0 {
        return 0.0;
    }
    let sum: u64 = (y1..y2)
        .flat_map(|y| (x1..x2).map(move |x| y * w + x))
        .map(|i| data[i] as u64)
        .sum();
    sum as f32 / count as f32
}

/// The enrollment preflight's verdict from the detected face's region mean:
/// lit when the subject is lit, dark only when a PRESENT face is unlit
/// (#613/#618). `None` (no face in the frame) is inconclusive, never dark:
/// an empty frame cannot testify about the emitter, and the dark refusal
/// must not fire on it. Pure over the measured mean.
fn ir_preflight_subject_lit(face_mean: Option<f32>) -> irlume_common::Result<bool> {
    match face_mean {
        Some(mean) => Ok(mean >= irlume_camera::ir_emitter::IR_LIT_MEAN),
        None => Err(irlume_common::Error::Hardware(
            "no face in the IR preflight frame; the emitter check is inconclusive".into(),
        )),
    }
}

/// Apply the KNOWN emitter control, capture one IR frame, and measure the
/// SUBJECT: the mean inside the detected face's region (#613). An emitter
/// lights the person, not the frame: on a camera whose working emitter
/// lights only the face centre, the whole-frame mean reads ~20 while the
/// face reads 137-158, which is what made the preflight call a working
/// camera dark and store dead RGB-only profiles (#618).
///
/// This never searches for an unknown control: capture applies only the
/// env override, persisted conf, or built-in table (#159's rule). A face
/// the emitter does not light is the honest dark verdict; no face at all
/// is inconclusive (`ir_preflight_subject_lit`).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn apply_known_ir_emitter_subject_region(
    device: &str,
    det: &mut irlume_vision::Detector,
) -> irlume_common::Result<bool> {
    let frame = irlume_camera::capture_ir(device)?;
    let view = CanonicalGreyView::try_from_parts(&frame.data, frame.width, frame.height)
        .map_err(model_input_error)?;
    let faces = det.detect(&DetectorInput::from_grey(view))?;
    let face_mean = top_detection(&faces)
        .map(|top| grey_mean_in_bbox(&frame.data, frame.width, frame.height, &top.bbox));
    let verdict = ir_preflight_subject_lit(face_mean)?;
    irlume_common::dlog!(
        "preflight(ir subject): face_mean={:.0} lit={verdict}",
        face_mean.unwrap_or(0.0)
    );
    Ok(verdict)
}

struct EnrollmentCapturePolicy<'a> {
    mode: &'a CaptureModeSelection,
    use_ir: bool,
    diagnostics: &'a dyn irlume_common::diagnostics::DiagnosticSink,
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

/// Shipped ViT RGB PAD deny threshold (ADR-0013). MEASURED operating point
/// across the FLEET, not one camera: the 2026-08-22 qualification set 0.60
/// from the Zenbook window (genuine frames ≤ 0.551, banner floor 0.604), but
/// fleet validation measured the NexiGo banner at presentation-medians
/// 0.55–0.60 — 0.60 misses that camera's banner entirely. At 0.55 with
/// 5-frame-median voting: every login-distance banner presentation on BOTH
/// cameras measured 0.594–0.656 (caught), every genuine presentation on
/// both cameras across desk/dim/close/glasses measured 0.27–0.465 (margin
/// 0.085), and 531 sampled LFW all-genuine presentations: 0 fire (0.50
/// would fire 7.3% — rejected). Do NOT raise toward 0.60 (drops the NexiGo
/// banner) or lower toward 0.50 (crosses the LFW tail and halves the
/// genuine margin). Evidence: docs/research/2026-08-22-vit-live-
/// qualification.md + the fleet run recorded in PR #516.
pub const VIT_PAD_THRESHOLD: f32 = 0.55;

/// ViT PAD vote window: the median of the last N scores decides. Voting is
/// what collapsed the LFW genuine tail (0.29% frame-level ≥ 0.60 → 0/531
/// 5-frame-median presentations), so single-frame firing would trade that
/// measured genuine stability away.
pub const VIT_PAD_VOTE_N: usize = 5;

/// Shipped IR PAD deny threshold (ADR-0013): the FLIR cue's measured
/// operating point. 2026-07-17 qualification + the 2026-07-27 re-measure:
/// highest genuine 0.702, banner attack floor 0.941, so 0.9 is inside the
/// usable window with margin on both sides. Do NOT move without re-running
/// both legs (see docs/pad-results/2026-07-17-third-party-pad-candidates.md
/// addendum).
pub const IR_PAD_THRESHOLD: f32 = 0.9;

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

/// How far apart the RGB and IR frames of ONE decision may be captured, under
/// the CONCURRENT capture schedule.
///
/// The cross-spectrum cues treat the two frames as one scene: the face must sit
/// in the same place in both, and the RGB head pose is used to judge a decision
/// made largely on the IR frame. Nothing else bounds the distance between them,
/// so this does. It is a ceiling on the pathological case, not a tuning knob:
/// under the CONCURRENT schedule the captures OVERLAP (gap zero), so the
/// distance only grows when captures stack up: a hard retry of one side, or
/// the dimming self-heal recapturing RGB after IR finished. Measured worst
/// single capture on the hardware we have is the NexiGo N930W at ~3.6s for a
/// full sequential pair, so 3s of GAP between two concurrent windows means
/// something went wrong rather than slow.
///
/// Exceeding it is never accepted as a pair: stale RGB evidence is discarded.
/// A valid IR face may continue through the separately gated IR-only path;
/// otherwise the capture is [`Verdict::Uncertain`], never Spoof, because stale
/// frames say nothing about the person in front of the camera.
const MAX_CROSS_SPECTRUM_SKEW: std::time::Duration = std::time::Duration::from_secs(3);

/// SecureDark scene gate (ADR-0016): is the RGB frame's own brightness
/// CONCLUSIVE evidence of a lit scene?
///
/// The dark (IR-only) path's legitimacy rests on an ENVIRONMENTAL fact — the
/// room is too dark for RGB identity — not on a presentation-controllable
/// one. "RGB found no face" alone is presentation-controllable: an artifact
/// crafted to reflect 850nm while absorbing visible light (or simply a black
/// visor over the presentation) produces exactly no-RGB-face + IR-face in a
/// fully lit room, routing a lit-room attack onto the path with the least
/// evidence. The gate reuses [`irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS`],
/// the repo's existing measured lit/dark boundary: pitch-dark reads ~17,
/// a dark room ~62 (NexiGo, 2026-07-25), the fault-visible lit arm 117-143;
/// 100.0 sits between with anchors on both sides. At or above it, the scene
/// is lit enough that the absence of an RGB face is SUSPICIOUS rather than
/// environmental, and the dark path refuses: the user still has the RGB path
/// (a face visible to IR in a conclusively lit scene is nearly always
/// visible to RGB) and the password below everything.
///
/// Uncertain (not Spoof): a genuine user walking up to a lit machine also
/// produces this shape transiently, and the grace window's retry lets RGB
/// find them; the refusal is a routing decision, not an attack verdict.
#[must_use]
pub fn scene_conclusively_lit(rgb_frame_mean: f32) -> bool {
    rgb_frame_mean >= irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS
}
/// The same ceiling under the SEQUENTIAL capture schedule, where a machinery
/// gap between the two windows is NORMAL, not pathological: the second
/// stream's one-shot capture pays open/negotiate plus its delivered-rate
/// evidence (startup flush + a 30-delta window) between the two bursts.
///
/// The bound is derived, not chosen: the rate gate guarantees a delivered IR
/// floor, so the machinery gap is bounded by construction at
/// ~open(0.3s) + 40 dequeues at the floor. At the measured fleet floors
/// (14.7-15 fps) that is a ~3.1s gap (ASUS measured 3050ms after the
/// role-aware flush), and a slower camera that still passes its floor
/// (e.g. 14.55 fps at the widened IR tolerance) lands at ~3.05s — the flush
/// and window counts are constants, so the gap cannot exceed ~3.1s while the
/// gate passes. A single hard retry or self-heal recapture REPLACES one
/// window and re-pays one open+fill (~3.1s), and both can occur in one
/// decision, so the pathological stacking case reaches ~6.2s. 8s bounds that
/// with margin while staying under the login grace window (15s) — a pair
/// older than the grace window can never use a decision this stale anyway.
///
/// Security posture (ADR-0014): the alternative to accepting the pair is not
/// a stricter check — the IR-only path GRANTS with no RGB evidence at all.
/// Discarding the pair removes cues (RGB co-location, RGB recognition, the
/// ViT RGB PAD) from an already-granting decision; accepting it only adds
/// them, and both paths still hinge on the same independently gated IR
/// evidence. Stale RGB cannot manufacture a grant; it can only deny (a real
/// user moving between captures), which is the same false-denial cost the
/// retry loop already carries.
const SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW: std::time::Duration = std::time::Duration::from_secs(8);

/// Cost of ONE sequential two-stream attempt: open + negotiate + flush +
/// rate window per stream (~3.1 s each, ADR-0014's derivation), paid serially
/// ≈ 7 s with recovery headroom. Used only to decide whether a sequential
/// fallback can still finish inside the remaining window before it starts
/// re-opening cameras.
const SEQUENTIAL_PAIR_ATTEMPT_COST: std::time::Duration = std::time::Duration::from_secs(7);

#[derive(Debug, Eq, PartialEq)]
enum EligiblePairEvidence<T> {
    Paired(Option<T>),
    IrOnly,
    Reject,
}

fn eligible_pair_evidence<T>(
    skew: std::time::Duration,
    limit: std::time::Duration,
    rgb_evidence: Option<T>,
    has_ir_face: bool,
) -> EligiblePairEvidence<T> {
    if skew <= limit {
        EligiblePairEvidence::Paired(rgb_evidence)
    } else if has_ir_face {
        EligiblePairEvidence::IrOnly
    } else {
        EligiblePairEvidence::Reject
    }
}

/// ADR-0014 security posture: on a pair captured under the sequential
/// schedule the RGB and IR bursts are separated by the capture machinery gap
/// (~3.05 s measured), which is a physical swap window. The lit path's
/// IR-side gates (cross-spectrum co-location, FLIR IR PAD, the per-user IR
/// center/edge floor) pass for ANY live face — they prove presence and
/// liveness, not identity — so an RGB recognition hit must not carry the
/// grant alone across that gap. Such pairs grant only through arms that
/// carry IR identity thresholds (IR fallback, calibrated centroid).
/// Concurrent pairs (skew <= `MAX_CROSS_SPECTRUM_SKEW`) interleave the two
/// spectra and keep the RGB-primary arm.
fn rgb_primary_grant_admissible(score: f32, threshold: f32, sequential_pair: bool) -> bool {
    score >= threshold && !sequential_pair
}

/// Whether a PAIRED assessment's frames were admitted only under the
/// sequential budget: a pair exists AND the frames sit beyond the concurrent
/// ceiling, i.e. they were captured as separated one-shot bursts (ADR-0014).
/// The budget that admitted the pair (`pairing_limit`) is schedule-aware, so
/// a concurrent capture can never pair beyond `MAX_CROSS_SPECTRUM_SKEW`
/// (`eligible_pair_evidence` demotes it to IrOnly first).
fn pair_admitted_sequentially(skew: std::time::Duration, paired: bool) -> bool {
    paired && skew > MAX_CROSS_SPECTRUM_SKEW
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
    // From the shared table, not a local list. The list this replaced was
    // missing `doas`, which is Elevation for the policy, so a doas prompt held
    // the camera for the 15s login window instead of the 5s one (#362).
    match service.and_then(irlume_common::pam_service::classify) {
        Some(kind) if kind.wants_short_grace() => SUDO_GRACE_WINDOW_MS,
        _ => GRACE_WINDOW_MS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadConsentVerdict {
    Approve,
    Decline,
    NoGesture,
}

fn head_consent_from_poses(poses: &[irlume_liveness::PoseSample]) -> HeadConsentVerdict {
    match irlume_liveness::detect_head_gesture(poses) {
        irlume_liveness::HeadGesture::Nod => HeadConsentVerdict::Approve,
        irlume_liveness::HeadGesture::Shake => HeadConsentVerdict::Decline,
        irlume_liveness::HeadGesture::None | irlume_liveness::HeadGesture::NoFace => {
            HeadConsentVerdict::NoGesture
        }
    }
}

fn resolve_head_consent(
    stream: Option<HeadConsentVerdict>,
    completed: impl FnOnce() -> HeadConsentVerdict,
) -> HeadConsentVerdict {
    stream.unwrap_or_else(completed)
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
#[cfg(test)]
fn completed_consent_take_hit(
    hit_in_loop: bool,
    allow_nod: bool,
    poses: &[irlume_liveness::PoseSample],
) -> bool {
    hit_in_loop || (allow_nod && head_consent_from_poses(poses) == HeadConsentVerdict::Approve)
}

/// Resolve a consent watch's verdict from what the stream reported.
///
/// `stream_hit` is `capture_ir_streaming`'s break value: `Some(true)` an accepted
/// nod, `Some(false)` a head-shake decline, `None` the budget ran out with
/// no in-loop verdict. A `Some(_)` outcome is TERMINAL and returned as-is; the
/// decline in particular must never be re-examined, or a completed-take nod
/// reading would overturn it into a grant. `completed_take_hit` is consulted, and
/// evaluated, ONLY for `None`: it is what closes the trailing-poses boundary the
/// in-loop cadence leaves (#101). Kept pure so a test can prove a decline stays a
/// decline; the call site's own coverage cannot reach the camera.
#[cfg(test)]
fn resolve_consent_watch(
    stream_hit: Option<bool>,
    completed_take_hit: impl FnOnce() -> bool,
) -> bool {
    let stream = stream_hit.map(|accepted| {
        if accepted {
            HeadConsentVerdict::Approve
        } else {
            HeadConsentVerdict::Decline
        }
    });
    match resolve_head_consent(stream, || {
        if completed_take_hit() {
            HeadConsentVerdict::Approve
        } else {
            HeadConsentVerdict::NoGesture
        }
    }) {
        HeadConsentVerdict::Approve => true,
        HeadConsentVerdict::Decline | HeadConsentVerdict::NoGesture => false,
    }
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
    /// Prove identity for a session (login, lock screen, sudo). A gesture is
    /// demanded only when the service explicitly opts in.
    Verify,
    /// Approve one application request (a polkit prompt). Conventional PAM
    /// confirmation carries intent; a head gesture is an optional extra gate.
    AppConsent,
    /// Release a stored credential: the TPM-sealed login-keyring password. A spoof
    /// here yields a reusable secret rather than one session, so the same
    /// deliberate gesture as [`Self::AppConsent`] can be REQUIRED, but it is
    /// an opt-in: the default is OFF (#424 relaxed it), because a greeter
    /// cold login and logout release the keyring after the face match and
    /// the gesture is intent, not the anti-print layer.
    ///
    /// `temporal_challenge` carries the live `credential_release_challenge`
    /// setting (default off; an absent key reads as off, see
    /// [`irlume_common::config::credential_release_challenge`], overridable
    /// per service via `service_gesture.credential_release`). The daemon reads
    /// it per request so a toggle needs no restart, and the engine stays free of
    /// policy lookups it cannot test in isolation.
    CredentialRelease { temporal_challenge: bool },
}

impl AuthenticationPurpose {
    /// The purpose a plain [`Engine::authenticate`] runs under: consent-class
    /// services (polkit) get [`Self::AppConsent`], everything else [`Self::Verify`].
    fn for_service(service: Option<&str>) -> Self {
        if matches!(
            service.and_then(irlume_common::pam_service::classify),
            Some(irlume_common::pam_service::ServiceKind::AppConsent)
        ) {
            Self::AppConsent
        } else {
            Self::Verify
        }
    }

    /// Whether the deliberate consent gesture is explicitly required.
    ///
    /// `service` is the PAM service name when available (e.g. `sudo`, `polkit-1`).
    /// It is consulted for per-service overrides in `settings.conf` under
    /// `service_gesture.<service>`. When absent, the per-purpose default is used.
    fn demands_gesture(self, service: Option<&str>) -> bool {
        match self {
            Self::Verify | Self::AppConsent => {
                service.is_some_and(irlume_common::config::service_gesture_required)
            }
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

/// The deferred enrollment load's result, as sent by the loader thread in
/// [`Engine::authenticate_for_with_diagnostics`].
type EnrollmentLoad = irlume_common::Result<Option<irlume_core::storage::Enrollment>>;

/// Wait out a still-running deferred enrollment load on an early exit, so the
/// user-state flock and the TPM are free before this request returns. An
/// immediate retry (decline, then a fallback attempt) would otherwise block
/// on the orphaned loader's locks — the one way this overlap could make a
/// retry SLOWER than the serial load it replaced. The exits that can still be
/// waiting are rare deny/error paths (consent-policy refusal, camera-lease
/// failure); the post-watch exits arrive seconds after the spawn, by which
/// time the load has long finished.
fn finish_loader(loader: &mut Option<std::sync::mpsc::Receiver<EnrollmentLoad>>) {
    if let Some(rx) = loader.take() {
        // The loader always sends or drops its sender (a panic drops it), so
        // this returns as soon as the load — not the whole thread — is done.
        let _ = rx.recv();
    }
}

/// How a deferred enrollment load ended when it did not produce an
/// enrollment the request can use.
#[derive(Debug)]
enum LoaderExit {
    /// The store vanished between the pre-check and the read: the same
    /// "not enrolled" deny as the pre-check.
    NotEnrolled,
    /// The request must fail closed to the password: the load errored, the
    /// deadline expired before it finished, or the loader panicked.
    Fallback(irlume_common::Error),
}

/// Resolve the deferred loader's channel result into the enrollment (or the
/// request-ending fallback). Pure, so every arm of the fail-closed mapping
/// is unit-testable without camera hardware; the join in
/// [`Engine::authenticate_for_with_diagnostics`] is exactly this mapping.
fn resolve_loader(
    recv: Result<EnrollmentLoad, std::sync::mpsc::RecvTimeoutError>,
) -> Result<irlume_core::storage::Enrollment, LoaderExit> {
    match recv {
        Ok(Ok(Some(enr))) => Ok(enr),
        Ok(Ok(None)) => Err(LoaderExit::NotEnrolled),
        Ok(Err(e)) => Err(LoaderExit::Fallback(e)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(LoaderExit::Fallback(irlume_common::Error::Protocol(
                "enrollment load exceeded the authentication deadline; \
                 falling back to password"
                    .into(),
            )))
        }
        // The sender is gone without a result: the loader panicked.
        // Contained by the thread boundary; the request fails closed rather
        // than crashing the daemon over an enrollment read.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(LoaderExit::Fallback(irlume_common::Error::Protocol(
                "enrollment loader failed; falling back to password".into(),
            )))
        }
    }
}

fn blocking_head_consent_policy(
    purpose: AuthenticationPurpose,
    service: Option<&str>,
) -> Option<HeadConsentPolicy> {
    if !purpose.demands_gesture(service) {
        return None;
    }
    match irlume_common::config::head_consent_policy() {
        HeadConsentPolicy::Ready => None,
        policy @ (HeadConsentPolicy::LegacyClosure(_) | HeadConsentPolicy::Misconfigured(_)) => {
            Some(policy)
        }
    }
}

fn legacy_eye_policy(enrollment: &irlume_core::storage::Enrollment) -> Result<(), &'static str> {
    if enrollment.require_eyes_open {
        Err(
            "legacy require-eyes-open is retired; run `irlume profiles eyes-open off`; \
             use your password or fingerprint until it is cleared",
        )
    } else {
        Ok(())
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

/// Was this refusal a DELIBERATE head-shake decline?
///
/// The daemon maps this onto the wire `AuthResult.declined_by_gesture` field, and
/// pam_irlume aborts a polkit dialog on it (and only it), so this is a
/// security-relevant boundary and lives as a tested pure function rather than an
/// inline `matches!` at the wire site. Only [`OutcomeKind::GestureDeclined`]
/// qualifies: a timeout, a no-match, a caught spoof, or any policy denial is NOT a
/// deliberate decline and must never close a dialog. Pinned by
/// `only_a_gesture_decline_is_a_gesture_decline`.
pub fn is_gesture_decline(o: &Outcome) -> bool {
    matches!(o.kind, OutcomeKind::GestureDeclined)
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

fn emit_trace_stage_ms(
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    stage: irlume_common::diagnostics::TraceStage,
    elapsed_ms: u128,
) {
    diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
        stage,
        elapsed_us: u64::try_from(elapsed_ms)
            .unwrap_or(u64::MAX)
            .saturating_mul(1_000),
    });
}

fn emit_trace_match(
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    metric: irlume_common::diagnostics::TraceMetric,
    score: f32,
    threshold: f32,
    matched: bool,
) {
    use irlume_common::diagnostics::{TraceEventKind, TraceMeasurement, TraceVerdict};
    let measurements = TraceMeasurement::new(metric, f64::from(score), Some(f64::from(threshold)))
        .into_iter()
        .collect();
    diagnostics.emit_trace(TraceEventKind::Decision {
        verdict: if matched {
            TraceVerdict::Match
        } else {
            TraceVerdict::NoMatch
        },
        measurements,
    });
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum PadEvidence {
    NotApplicable,
    Unavailable,
    InferenceFailed,
    Score(f32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PadModality {
    Rgb,
    Ir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PadRequirements {
    RgbOnly,
    RgbAndIr,
    IrOnly,
}

fn pad_evidence_refusal(modality: PadModality, evidence: PadEvidence) -> Option<Outcome> {
    let modality = match modality {
        PadModality::Rgb => "RGB",
        PadModality::Ir => "IR",
    };
    let reason = match evidence {
        PadEvidence::Unavailable => {
            format!("{modality} PAD is unavailable; use your password")
        }
        PadEvidence::InferenceFailed => {
            format!("{modality} PAD inference failed; use your password")
        }
        PadEvidence::NotApplicable => {
            format!("{modality} PAD was not evaluated; use your password")
        }
        PadEvidence::Score(_) => return None,
    };
    Some(Outcome::deny(OutcomeKind::OtherDeny, reason))
}

fn pad_policy_refusal(
    requirements: PadRequirements,
    rgb: PadEvidence,
    ir: PadEvidence,
) -> Option<Outcome> {
    match requirements {
        PadRequirements::RgbOnly => pad_evidence_refusal(PadModality::Rgb, rgb),
        PadRequirements::RgbAndIr => pad_evidence_refusal(PadModality::Rgb, rgb)
            .or_else(|| pad_evidence_refusal(PadModality::Ir, ir)),
        PadRequirements::IrOnly => pad_evidence_refusal(PadModality::Ir, ir),
    }
}

/// Deny-only rule for the opt-in third-party PAD cue: fires (downgrades to
/// Spoof) ONLY when the built-in gate already said Live AND the cue's P(fake)
/// clears the threshold. A non-Live verdict is never touched, and an absent
/// score never fires, so the cue cannot rescue an attack or mask a gate
/// rejection; enabling it can only tighten.
pub fn pad_downgrades(verdict: Verdict, p_fake: Option<f32>, threshold: f32) -> bool {
    verdict == Verdict::Live && p_fake.is_some_and(|p| p >= threshold)
}

/// The shipped ViT PAD 5-frame-median vote (ADR-0013). Pure decision core of
/// [`Engine`]'s `vit_pad_votes_deny`: appends `score` to `scores`, then denies
/// only when the last [`VIT_PAD_VOTE_N`] scores have a median at or above
/// [`VIT_PAD_THRESHOLD`]. Fewer than N scores abstain (a presentation denied
/// in <N frames never had its vote), and the window SLIDES: the 6th score
/// drops the 1st, so a sustained attack denies on every full window while a
/// single outlier frame can never carry a denial alone.
pub fn vit_vote_denies(scores: &[f32]) -> bool {
    let skip = scores.len().saturating_sub(VIT_PAD_VOTE_N);
    let window = &scores[skip..];
    if window.len() < VIT_PAD_VOTE_N {
        return false;
    }
    let mut sorted = window.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted[VIT_PAD_VOTE_N / 2] >= VIT_PAD_THRESHOLD
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
/// override, then a context-bound v2 qualification for THIS exact pairing,
/// stream tuple, and USB connection, then the sequential default.
///
/// One resolver for every consumer, because the two halves of the answer must
/// agree: the ASSESS path uses it to order its reads, and the ENROLL path
/// uses it to decide whether both streams may be armed at once. When they
/// disagreed, "sequential" ordered the reads of two streams that were both
/// live anyway, which on a bandwidth-starved camera is indistinguishable
/// from concurrent (#187).
#[derive(Clone, Debug)]
struct CaptureModeSelection {
    sequential: bool,
    source: &'static str,
    runtime_key: Option<String>,
    runtime_contract: Option<irlume_camera::RuntimePairContract>,
    camera_contract: Option<irlume_camera::attempt_contract::CameraAttemptContract>,
    qualification_authority: Option<irlume_camera::StoredCaptureQualificationState>,
    qualification_state: irlume_common::diagnostics::QualificationState,
    qualification_reason: Option<irlume_common::diagnostics::QualificationReason>,
    authoritative_rate_shortfalls: Option<irlume_common::diagnostics::RateShortfallsByArm>,
    latest_attempt_rate_shortfalls: Option<irlume_common::diagnostics::RateShortfallsByArm>,
    operation_demoted: std::cell::Cell<bool>,
}

impl CaptureModeSelection {
    fn is_sequential(&self) -> bool {
        self.sequential || self.operation_demoted.get()
    }

    fn active_source(&self) -> &'static str {
        if self.operation_demoted.get() {
            RUNTIME_CAPTURE_MODE_SOURCE
        } else {
            self.source
        }
    }

    fn demote_operation(&self) {
        self.operation_demoted.set(true);
    }
}

/// Daemon-facing active scheduling status for one exact open camera pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureModeStatus {
    pub mode: CaptureMode,
    pub source: &'static str,
    pub runtime_context: Option<String>,
    pub qualification_state: String,
    pub qualification_reason: Option<String>,
    pub qualification_context: Option<serde_json::Value>,
    pub runtime_degradation: Option<String>,
}

/// Resolve the same exact-open-pair policy authentication and enrollment use.
#[must_use]
pub fn capture_mode_status_from_cameras(
    rgb: &irlume_camera::RgbCamera,
    ir: &irlume_camera::IrCamera,
) -> CaptureModeStatus {
    let selection = capture_mode_selection(rgb, ir);
    let stored = irlume_camera::stored_capture_qualification_state_from_cameras(rgb, ir);
    let (qualification_state, qualification_reason) = match stored {
        Ok(state) => match state.resolution {
            QualificationResolution::ConcurrentQualified => ("qualified_concurrent", None),
            QualificationResolution::SequentialRequired(reason) => (
                "measured_sequential",
                Some(
                    match reason {
                        SequentialReason::ConcurrentUnavailable => "concurrent_unavailable",
                        SequentialReason::DeliveredRateShortfall => "delivered_rate_shortfall",
                        SequentialReason::SignalLoss => "signal_loss",
                        SequentialReason::InvalidProvenance => "invalid_provenance",
                    }
                    .into(),
                ),
            ),
            QualificationResolution::Unqualified(
                irlume_camera::capture_qualification::QualificationMismatch::NoAuthority,
            ) => match state.last_attempt_outcome {
                Some(AttemptOutcome::Inconclusive(reason)) => (
                    "inconclusive",
                    Some(
                        match reason {
                            InconclusiveReason::IncompleteRounds => "incomplete_rounds",
                            InconclusiveReason::DimScene => "dim_scene",
                            InconclusiveReason::ContractDrift => "contract_drift",
                            InconclusiveReason::MissingProvenance => "missing_provenance",
                        }
                        .into(),
                    ),
                ),
                _ => (
                    "unqualified_no_authority",
                    Some("no stored authority".into()),
                ),
            },
            QualificationResolution::Unqualified(
                irlume_camera::capture_qualification::QualificationMismatch::ContextChanged,
            ) => (
                "unqualified_context_changed",
                Some("stored authority does not match the live context".into()),
            ),
        },
        Err(error) => ("unreadable", Some(error.to_string())),
    };
    let qualification_context = selection
        .runtime_contract
        .as_ref()
        .and_then(|contract| serde_json::to_value(contract.context()).ok());
    let runtime_degradation = selection.runtime_key.as_deref().and_then(|key| {
        with_runtime_capture_health(|health| health.degradation(key))
            .map(|reason| reason.as_str().to_owned())
    });
    CaptureModeStatus {
        mode: if selection.is_sequential() {
            CaptureMode::Sequential
        } else {
            CaptureMode::Concurrent
        },
        source: selection.source,
        runtime_context: selection.runtime_key,
        qualification_state: qualification_state.into(),
        qualification_reason,
        qualification_context,
        runtime_degradation,
    }
}

struct AuthenticationCaptureContext<'a> {
    mode: Option<&'a CaptureModeSelection>,
    operation: Option<&'a irlume_camera::lease::CameraOperationSession>,
    held_pair_failed: Option<&'a mut bool>,
    diagnostics: &'a dyn irlume_common::diagnostics::DiagnosticSink,
}

enum CapturePathError {
    ConcurrentPair(irlume_common::Error),
    Other(irlume_common::Error),
}

impl CapturePathError {
    fn into_inner(self) -> irlume_common::Error {
        match self {
            Self::ConcurrentPair(error) | Self::Other(error) => error,
        }
    }
}

impl From<irlume_common::Error> for CapturePathError {
    fn from(error: irlume_common::Error) -> Self {
        Self::Other(error)
    }
}

fn unavailable_capture_mode_selection() -> CaptureModeSelection {
    let (requested_sequential, requested_source) = capture_mode_decision(
        std::env::var("IRLUME_SEQUENTIAL_CAPTURE").ok().as_deref(),
        None,
    );
    let source = if requested_sequential {
        requested_source
    } else {
        RUNTIME_CAPTURE_MODE_SOURCE
    };
    CaptureModeSelection {
        sequential: true,
        source,
        runtime_key: None,
        runtime_contract: None,
        camera_contract: None,
        qualification_authority: None,
        qualification_state: irlume_common::diagnostics::QualificationState::Unreadable,
        qualification_reason: Some(
            irlume_common::diagnostics::QualificationReason::StoreUnreadable,
        ),
        authoritative_rate_shortfalls: None,
        latest_attempt_rate_shortfalls: None,
        operation_demoted: std::cell::Cell::new(false),
    }
}

/// The capture selection for a DELIBERATE RGB-only enrollment: sequential by
/// construction (one camera, one stream), labeled so it can never be misread
/// as "no stored qualification decided this" the way `unavailable_capture_mode_selection`'s
/// `from default` was (#618). This is a choice, not an availability failure.
fn rgb_only_enrollment_capture_mode_selection() -> CaptureModeSelection {
    CaptureModeSelection {
        sequential: true,
        source: RGB_ONLY_ENROLLMENT_CAPTURE_MODE_SOURCE,
        runtime_key: None,
        runtime_contract: None,
        camera_contract: None,
        qualification_authority: None,
        // The share-safe vocabulary has no "IR skipped by request" state; the
        // operation genuinely runs RGB-only, which is what NoIrPair names.
        qualification_state: irlume_common::diagnostics::QualificationState::NoIrPair,
        qualification_reason: None,
        authoritative_rate_shortfalls: None,
        latest_attempt_rate_shortfalls: None,
        operation_demoted: std::cell::Cell::new(false),
    }
}

fn capture_mode_selection(
    rgb_camera: &irlume_camera::RgbCamera,
    ir_camera: &irlume_camera::IrCamera,
) -> CaptureModeSelection {
    capture_mode_selection_with_diagnostics(rgb_camera, ir_camera, &())
}

fn capture_mode_selection_with_diagnostics(
    rgb_camera: &irlume_camera::RgbCamera,
    ir_camera: &irlume_camera::IrCamera,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
) -> CaptureModeSelection {
    let runtime_contract =
        match irlume_camera::runtime_pair_contract_from_cameras(rgb_camera, ir_camera) {
            Ok(contract) => contract,
            Err(error) => {
                irlume_common::dlog!(
                    "live pair contract unavailable ({error}); selecting one-at-a-time capture"
                );
                return unavailable_capture_mode_selection();
            }
        };
    let (
        stored,
        runtime_key,
        qualification_state,
        qualification_reason,
        authoritative_rate_shortfalls,
        latest_attempt_rate_shortfalls,
        qualification_authority,
    ) = match irlume_camera::stored_capture_qualification_state_from_cameras(rgb_camera, ir_camera)
    {
        Ok(state) => {
            diagnostics.emit_share_safe(diagnostic_qualification_event(&state));
            let (qualification_state, qualification_reason) =
                diagnostic_qualification_state(&state);
            let qualification_authority = Some(state.clone());
            let stored = match state.resolution {
                    irlume_camera::capture_qualification::QualificationResolution::ConcurrentQualified => {
                        Some(irlume_camera::CaptureMode::Concurrent)
                    }
                    irlume_camera::capture_qualification::QualificationResolution::SequentialRequired(
                        _,
                    ) => Some(irlume_camera::CaptureMode::Sequential),
                    irlume_camera::capture_qualification::QualificationResolution::Unqualified(
                        _,
                    ) => None,
                };
            (
                stored,
                Some(state.runtime_key),
                qualification_state,
                qualification_reason,
                state.authoritative_rate_shortfalls,
                state.latest_attempt_rate_shortfalls,
                qualification_authority,
            )
        }
        Err(error) => {
            diagnostics.emit_share_safe(
                irlume_common::diagnostics::ShareSafeEventKind::QualificationChanged {
                    state: irlume_common::diagnostics::QualificationState::Unreadable,
                    reason: Some(irlume_common::diagnostics::QualificationReason::StoreUnreadable),
                },
            );
            irlume_common::dlog!(
                "capture qualification unreadable ({error}); selecting one-at-a-time capture"
            );
            (
                None,
                None,
                irlume_common::diagnostics::QualificationState::Unreadable,
                Some(irlume_common::diagnostics::QualificationReason::StoreUnreadable),
                None,
                None,
                None,
            )
        }
    };
    let env = std::env::var("IRLUME_SEQUENTIAL_CAPTURE").ok();
    let selected = capture_mode_decision(env.as_deref(), stored);
    let selected = with_runtime_capture_health(|health| {
        apply_runtime_capture_health(selected, runtime_key.as_deref(), health)
    });
    let schedule = if selected.0 {
        irlume_camera::profile::CaptureSchedule::Sequential
    } else {
        irlume_camera::profile::CaptureSchedule::Concurrent
    };
    let camera_contract = camera_contract_from_runtime(
        &runtime_contract,
        qualification_authority.as_ref(),
        schedule,
    );
    CaptureModeSelection {
        sequential: selected.0,
        source: selected.1,
        runtime_key,
        runtime_contract: Some(runtime_contract),
        camera_contract,
        qualification_authority,
        qualification_state,
        qualification_reason,
        authoritative_rate_shortfalls,
        latest_attempt_rate_shortfalls,
        operation_demoted: std::cell::Cell::new(false),
    }
}

fn camera_contract_from_runtime(
    runtime: &irlume_camera::RuntimePairContract,
    qualification: Option<&irlume_camera::StoredCaptureQualificationState>,
    schedule: irlume_camera::profile::CaptureSchedule,
) -> Option<irlume_camera::attempt_contract::CameraAttemptContract> {
    qualification
        .and_then(|state| {
            irlume_camera::attempt_contract::CameraAttemptContract::from_qualified_runtime(
                runtime.clone(),
                state,
                schedule,
            )
            .ok()
        })
        .or_else(|| {
            irlume_camera::attempt_contract::CameraAttemptContract::from_legacy_unqualified_runtime(
                runtime.clone(),
                schedule,
            )
            .ok()
        })
}

fn ir_fallback_rgb_context(score: f32, threshold: f32, sequential_pair: bool) -> String {
    if sequential_pair && score >= threshold {
        format!("sequential pair required IR verification; rgb {score:.2}>={threshold:.2}")
    } else {
        format!("dim light; rgb {score:.2}<{threshold:.2}")
    }
}

fn attempt_plan_from_camera(
    camera: irlume_camera::attempt_contract::CameraAttemptContract,
    versions: capture_plan::AttemptPlanVersions,
    model_contracts: irlume_vision::model_input::ModelContractSet,
) -> Option<capture_plan::AttemptCapturePlan> {
    Some(capture_plan::AttemptCapturePlan::new(
        camera,
        versions,
        model_contracts,
    ))
}

fn standalone_capture_mode_selection(rgb_dev: &str, ir_dev: &str) -> CaptureModeSelection {
    let operation = match irlume_camera::lease::acquire_camera_operation(
        &[rgb_dev, ir_dev],
        irlume_camera::lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    ) {
        Ok(operation) => operation,
        Err(error) => {
            irlume_common::dlog!(
                "capture qualification operation unavailable ({error}); selecting one-at-a-time capture"
            );
            return unavailable_capture_mode_selection();
        }
    };
    match (operation.open_rgb(rgb_dev), operation.open_ir(ir_dev)) {
        (Ok(rgb), Ok(ir)) => capture_mode_selection(&rgb, &ir),
        _ => unavailable_capture_mode_selection(),
    }
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
            Some(m) => (
                m == irlume_camera::CaptureMode::Sequential,
                STORED_CAPTURE_MODE_SOURCE,
            ),
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
const STORED_CAPTURE_MODE_SOURCE: &str = "qualification-v2";
const RUNTIME_CAPTURE_MODE_SOURCE: &str = "runtime-health";
/// The `mode_source` the deliberate RGB-only enrollment selection carries, so
/// the enroll journal can never read it as the unmeasured default (#618: the
/// `from default` line was read as the stored qualification failing to load).
const RGB_ONLY_ENROLLMENT_CAPTURE_MODE_SOURCE: &str = "rgb-only-enrollment";

/// Evidence that makes this daemon process stop attempting concurrent capture
/// for one exact qualification context. This is deliberately not serialized:
/// a live authentication failure is useful immediate safety evidence, but it
/// is not a controlled A/B qualification and therefore must not rewrite the
/// durable hardware verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeDegradation {
    ConcurrentCaptureFailure,
    PairArmFailure,
    PairRateEstablishmentFailure,
    StreamRecovery,
    MissingRuntimeContract,
    CameraGenerationChanged,
    StreamContractMismatch,
    DeliveredRateShortfall,
    ContinuityLoss,
    ActiveIrMissing,
    ConfirmedSignalLoss,
}

#[derive(Debug, Default)]
struct RuntimeCaptureHealth {
    demoted: std::collections::HashMap<String, RuntimeDegradation>,
}

impl RuntimeCaptureHealth {
    fn trip(&mut self, context_key: &str, reason: RuntimeDegradation) -> bool {
        match self.demoted.entry(context_key.to_owned()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(reason);
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        }
    }

    fn requires_sequential(&self, context_key: &str) -> bool {
        self.demoted.contains_key(context_key)
    }

    fn degradation(&self, context_key: &str) -> Option<RuntimeDegradation> {
        self.demoted.get(context_key).copied()
    }

    fn reset(&mut self, context_key: &str) -> bool {
        self.demoted.remove(context_key).is_some()
    }
}

impl RuntimeDegradation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ConcurrentCaptureFailure => "concurrent_capture_failure",
            Self::PairArmFailure => "pair_arm_failure",
            Self::PairRateEstablishmentFailure => "pair_rate_establishment_failure",
            Self::StreamRecovery => "stream_recovery",
            Self::MissingRuntimeContract => "missing_runtime_contract",
            Self::CameraGenerationChanged => "camera_generation_changed",
            Self::StreamContractMismatch => "stream_contract_mismatch",
            Self::DeliveredRateShortfall => "delivered_rate_shortfall",
            Self::ContinuityLoss => "continuity_loss",
            Self::ActiveIrMissing => "active_ir_missing",
            Self::ConfirmedSignalLoss => "confirmed_signal_loss",
        }
    }
}

/// Apply process-local health after the explicit/stored/default authority
/// decision. An explicit environment override remains authoritative; health
/// only narrows an otherwise-qualified concurrent schedule to the safe one.
fn apply_runtime_capture_health(
    selected: (bool, &'static str),
    context_key: Option<&str>,
    health: &RuntimeCaptureHealth,
) -> (bool, &'static str) {
    if selected.0 || selected.1 == ENV_CAPTURE_MODE_SOURCE {
        return selected;
    }
    match context_key {
        Some(key) if health.requires_sequential(key) => (true, RUNTIME_CAPTURE_MODE_SOURCE),
        _ => selected,
    }
}

static RUNTIME_CAPTURE_HEALTH: std::sync::OnceLock<std::sync::Mutex<RuntimeCaptureHealth>> =
    std::sync::OnceLock::new();

fn with_runtime_capture_health<T>(use_health: impl FnOnce(&RuntimeCaptureHealth) -> T) -> T {
    let health = RUNTIME_CAPTURE_HEALTH
        .get_or_init(|| std::sync::Mutex::new(RuntimeCaptureHealth::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use_health(&health)
}

fn trip_runtime_capture_health(context_key: &str, reason: RuntimeDegradation) {
    let first = {
        let mut health = RUNTIME_CAPTURE_HEALTH
            .get_or_init(|| std::sync::Mutex::new(RuntimeCaptureHealth::default()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        health.trip(context_key, reason)
    };
    if first {
        eprintln!(
            "irlumed: concurrent capture degraded for this exact camera context; using \
             one-at-a-time RGB then IR capture until this daemon restarts or the context changes"
        );
    }
}

/// Clear process-local degradation after a controlled tune publishes fresh
/// durable evidence. This never changes qualification records.
pub fn reset_runtime_capture_health(context_key: &str) {
    let mut health = RUNTIME_CAPTURE_HEALTH
        .get_or_init(|| std::sync::Mutex::new(RuntimeCaptureHealth::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    health.reset(context_key);
}

/// Whether a SUCCESSFUL concurrent capture's provenance evidence carries
/// early warning signs that the next one will fail (#586 proactive
/// degradation). Pure over the three observable warning facts, so the
/// decision is testable without a camera.
///
/// The threshold is deliberately any-single-sign: the #586 testbed showed
/// that once sequence gaps start under concurrent USB isochronous load,
/// they compound (rounds 1-3 clean, then every round fails). Waiting for
/// two or three warning captures means the user eats a failure that could
/// have been avoided. The CURRENT auth completes normally (the frame was
/// usable); the NEXT one goes sequential.
fn successful_capture_shows_degradation_signs(
    rgb_sequence_gap: bool,
    ir_sequence_gap: bool,
    timestamp_discontinuity: bool,
) -> bool {
    rgb_sequence_gap || ir_sequence_gap || timestamp_discontinuity
}

fn concurrent_pair_requires_fallback(
    sequential: bool,
    rgb_failed: bool,
    ir_failed: bool,
    recovered_side: bool,
    invalid_runtime_contract: bool,
) -> bool {
    !sequential && (rgb_failed || ir_failed || recovered_side || invalid_runtime_contract)
}

fn capture_pair_sequentially<R, I>(
    rgb_capture: impl FnOnce() -> irlume_common::Result<R>,
    ir_capture: impl FnOnce() -> irlume_common::Result<I>,
) -> (irlume_common::Result<R>, irlume_common::Result<Option<I>>) {
    let rgb = rgb_capture();
    if rgb.is_err() {
        return (rgb, Ok(None));
    }
    (rgb, ir_capture().map(Some))
}

fn arm_pair_transactionally<R, I, E>(
    rgb_arm: impl FnOnce() -> Result<R, E>,
    ir_arm: impl FnOnce() -> Result<I, E>,
) -> Result<(R, I), E> {
    let rgb = rgb_arm()?;
    match ir_arm() {
        Ok(ir) => Ok((rgb, ir)),
        Err(error) => {
            drop(rgb);
            Err(error)
        }
    }
}

fn pair_rate_failure_is_degradation(selection: &CaptureModeSelection) -> bool {
    !selection.is_sequential()
        && selection.source != ENV_CAPTURE_MODE_SOURCE
        && selection.runtime_key.is_some()
}

fn demote_after_pair_rate_failure(selection: &mut CaptureModeSelection) {
    demote_after_concurrent_setup_failure(
        selection,
        RuntimeDegradation::PairRateEstablishmentFailure,
    );
}

fn demote_after_pair_arm_failure(selection: &mut CaptureModeSelection) {
    demote_after_concurrent_setup_failure(selection, RuntimeDegradation::PairArmFailure);
}

fn demote_after_concurrent_setup_failure(
    selection: &mut CaptureModeSelection,
    reason: RuntimeDegradation,
) {
    if selection.is_sequential() {
        return;
    }
    if pair_rate_failure_is_degradation(selection) {
        if let Some(context_key) = selection.runtime_key.as_deref() {
            trip_runtime_capture_health(context_key, reason);
        }
    }
    selection.sequential = true;
    selection.operation_demoted.set(true);
    selection.source = RUNTIME_CAPTURE_MODE_SOURCE;
}

fn demote_after_concurrent_capture_failure(selection: &mut CaptureModeSelection) {
    demote_after_concurrent_setup_failure(selection, RuntimeDegradation::ConcurrentCaptureFailure);
}

fn runtime_violation_degradation(
    violation: irlume_camera::RuntimePairViolation,
) -> RuntimeDegradation {
    match violation {
        irlume_camera::RuntimePairViolation::CameraGeneration => {
            RuntimeDegradation::CameraGenerationChanged
        }
        irlume_camera::RuntimePairViolation::StreamContract => {
            RuntimeDegradation::StreamContractMismatch
        }
        irlume_camera::RuntimePairViolation::DeliveredRate => {
            RuntimeDegradation::DeliveredRateShortfall
        }
        irlume_camera::RuntimePairViolation::Continuity => RuntimeDegradation::ContinuityLoss,
        irlume_camera::RuntimePairViolation::ActiveIr => RuntimeDegradation::ActiveIrMissing,
    }
}

fn concurrent_pair_degradation(
    violation: Option<irlume_camera::RuntimePairViolation>,
    missing_runtime_contract: bool,
    recovered_side: bool,
) -> RuntimeDegradation {
    violation.map_or_else(
        || {
            if missing_runtime_contract {
                RuntimeDegradation::MissingRuntimeContract
            } else if recovered_side {
                RuntimeDegradation::StreamRecovery
            } else {
                RuntimeDegradation::ConcurrentCaptureFailure
            }
        },
        runtime_violation_degradation,
    )
}

fn diagnostic_runtime_violation(
    degradation: RuntimeDegradation,
) -> irlume_common::diagnostics::RuntimeViolationLabel {
    use irlume_common::diagnostics::RuntimeViolationLabel as Label;
    match degradation {
        RuntimeDegradation::ConcurrentCaptureFailure => Label::ConcurrentCaptureFailure,
        RuntimeDegradation::PairArmFailure => Label::PairArmFailure,
        RuntimeDegradation::PairRateEstablishmentFailure => Label::PairRateEstablishmentFailure,
        RuntimeDegradation::StreamRecovery => Label::StreamRecovery,
        RuntimeDegradation::MissingRuntimeContract => Label::MissingRuntimeContract,
        RuntimeDegradation::CameraGenerationChanged => Label::CameraGenerationChanged,
        RuntimeDegradation::StreamContractMismatch => Label::StreamContractMismatch,
        RuntimeDegradation::DeliveredRateShortfall => Label::DeliveredRateShortfall,
        RuntimeDegradation::ContinuityLoss => Label::ContinuityLoss,
        RuntimeDegradation::ActiveIrMissing => Label::ActiveIrMissing,
        RuntimeDegradation::ConfirmedSignalLoss => Label::ConfirmedSignalLoss,
    }
}

fn emit_capture_schedule(
    selection: &CaptureModeSelection,
    ir_available: bool,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
) {
    use irlume_common::diagnostics::ShareSafeEventKind;
    let (schedule, source) = diagnostic_capture_schedule(selection, ir_available);
    diagnostics.emit_share_safe(ShareSafeEventKind::CaptureScheduleSelected { schedule, source });
}

fn diagnostic_capture_schedule(
    selection: &CaptureModeSelection,
    ir_available: bool,
) -> (
    irlume_common::diagnostics::CaptureSchedule,
    irlume_common::diagnostics::CaptureScheduleSource,
) {
    use irlume_common::diagnostics::{CaptureSchedule, CaptureScheduleSource};
    let schedule = if selection.is_sequential() {
        CaptureSchedule::Sequential
    } else {
        CaptureSchedule::Concurrent
    };
    let source = if !ir_available {
        CaptureScheduleSource::NoIrPair
    } else {
        match selection.active_source() {
            ENV_CAPTURE_MODE_SOURCE => CaptureScheduleSource::EnvironmentOverride,
            STORED_CAPTURE_MODE_SOURCE => CaptureScheduleSource::StoredQualification,
            RUNTIME_CAPTURE_MODE_SOURCE => CaptureScheduleSource::RuntimeHealth,
            _ => CaptureScheduleSource::SequentialDefault,
        }
    };
    (schedule, source)
}

fn diagnostic_capture_status(
    selection: &CaptureModeSelection,
    ir_available: bool,
    runtime_context: Option<irlume_common::diagnostics::DigestToken>,
    qualification_context: Option<irlume_common::diagnostics::DigestToken>,
    runtime_degradation: Option<irlume_common::diagnostics::RuntimeViolationLabel>,
) -> irlume_common::diagnostics::CaptureStatus {
    let (schedule, source) = diagnostic_capture_schedule(selection, ir_available);
    irlume_common::diagnostics::CaptureStatus {
        schedule,
        source,
        runtime_context,
        qualification_state: selection.qualification_state,
        qualification_reason: selection.qualification_reason,
        qualification_context,
        runtime_degradation,
        authoritative_rate_shortfalls: selection.authoritative_rate_shortfalls.clone(),
        latest_attempt_rate_shortfalls: selection.latest_attempt_rate_shortfalls.clone(),
    }
}

fn diagnostic_qualification_event(
    state: &irlume_camera::StoredCaptureQualificationState,
) -> irlume_common::diagnostics::ShareSafeEventKind {
    let (state_label, reason) = diagnostic_qualification_state(state);
    irlume_common::diagnostics::ShareSafeEventKind::QualificationChanged {
        state: state_label,
        reason,
    }
}

fn diagnostic_qualification_state(
    state: &irlume_camera::StoredCaptureQualificationState,
) -> (
    irlume_common::diagnostics::QualificationState,
    Option<irlume_common::diagnostics::QualificationReason>,
) {
    use irlume_camera::capture_qualification::QualificationMismatch;
    use irlume_common::diagnostics::{QualificationReason as Reason, QualificationState as State};
    match state.resolution {
        QualificationResolution::ConcurrentQualified => (State::QualifiedConcurrent, None),
        QualificationResolution::SequentialRequired(reason) => (
            State::MeasuredSequential,
            Some(match reason {
                SequentialReason::ConcurrentUnavailable => Reason::ConcurrentUnavailable,
                SequentialReason::DeliveredRateShortfall => Reason::DeliveredRateShortfall,
                SequentialReason::SignalLoss => Reason::SignalLoss,
                SequentialReason::InvalidProvenance => Reason::InvalidProvenance,
            }),
        ),
        QualificationResolution::Unqualified(QualificationMismatch::ContextChanged) => (
            State::UnqualifiedContextChanged,
            Some(Reason::ContextChanged),
        ),
        QualificationResolution::Unqualified(QualificationMismatch::NoAuthority) => {
            match state.last_attempt_outcome {
                Some(AttemptOutcome::Inconclusive(reason)) => (
                    State::Inconclusive,
                    Some(match reason {
                        InconclusiveReason::IncompleteRounds => Reason::IncompleteRounds,
                        InconclusiveReason::DimScene => Reason::DimScene,
                        InconclusiveReason::ContractDrift => Reason::ContractDrift,
                        InconclusiveReason::MissingProvenance => Reason::MissingProvenance,
                    }),
                ),
                _ => (
                    State::UnqualifiedNoAuthority,
                    Some(Reason::NoStoredAuthority),
                ),
            }
        }
    }
}

fn emit_capture_context(
    selection: &CaptureModeSelection,
    ir_available: bool,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
) {
    use irlume_common::diagnostics::{
        CameraRoleLabel, DigestToken, QualificationState, ShareSafeEventKind,
    };
    emit_capture_schedule(selection, ir_available, diagnostics);
    if let Some(contract) = selection.runtime_contract.as_ref() {
        if let (Ok(cameras), Ok(runtime_context)) = (
            contract.diagnostic_camera_contexts(),
            DigestToken::from_sha256_hex(contract.runtime_key()),
        ) {
            let qualification_context = cameras[0].qualification_token;
            let runtime_degradation = selection.runtime_key.as_deref().and_then(|key| {
                with_runtime_capture_health(|health| health.degradation(key))
                    .map(diagnostic_runtime_violation)
            });
            diagnostics.publish_support_context(
                diagnostic_capture_status(
                    selection,
                    ir_available,
                    Some(runtime_context),
                    qualification_context,
                    runtime_degradation,
                ),
                cameras.into(),
            );
        }
        diagnostics.emit_share_safe(ShareSafeEventKind::LifecycleChanged {
            role: CameraRoleLabel::Rgb,
            generation: contract.rgb_generation(),
        });
        diagnostics.emit_share_safe(ShareSafeEventKind::LifecycleChanged {
            role: CameraRoleLabel::Ir,
            generation: contract.ir_generation(),
        });
    }
    if !ir_available {
        diagnostics.emit_share_safe(ShareSafeEventKind::QualificationChanged {
            state: QualificationState::NoIrPair,
            reason: None,
        });
    }
}

fn publish_rgb_only_support_context(
    camera: irlume_common::diagnostics::SanitizedCameraContext,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
) {
    use irlume_common::diagnostics::{
        CaptureSchedule, CaptureScheduleSource, CaptureStatus, QualificationState,
    };
    diagnostics.publish_support_context(
        CaptureStatus {
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::NoIrPair,
            runtime_context: None,
            qualification_state: QualificationState::NoIrPair,
            qualification_reason: None,
            qualification_context: None,
            runtime_degradation: None,
            authoritative_rate_shortfalls: None,
            latest_attempt_rate_shortfalls: None,
        },
        vec![camera],
    );
}

fn emit_capture_fallback(
    degradation: RuntimeDegradation,
    diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
) {
    diagnostics.emit_share_safe(
        irlume_common::diagnostics::ShareSafeEventKind::CaptureFallback {
            reason: diagnostic_runtime_violation(degradation),
        },
    );
}

struct SupportProbeSink<'a> {
    upstream: &'a dyn irlume_common::diagnostics::DiagnosticSink,
    fallback: std::sync::Mutex<Option<irlume_common::diagnostics::RuntimeViolationLabel>>,
}

impl<'a> SupportProbeSink<'a> {
    fn new(upstream: &'a dyn irlume_common::diagnostics::DiagnosticSink) -> Self {
        Self {
            upstream,
            fallback: std::sync::Mutex::new(None),
        }
    }

    fn fallback(&self) -> Option<irlume_common::diagnostics::RuntimeViolationLabel> {
        *self
            .fallback
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl irlume_common::diagnostics::DiagnosticSink for SupportProbeSink<'_> {
    fn emit_share_safe(&self, kind: irlume_common::diagnostics::ShareSafeEventKind) {
        if let irlume_common::diagnostics::ShareSafeEventKind::CaptureFallback { reason } = &kind {
            let mut fallback = self
                .fallback
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if fallback.is_none() {
                *fallback = Some(*reason);
            }
            drop(fallback);
        }
        self.upstream.emit_share_safe(kind);
    }

    fn emit_trace(&self, kind: irlume_common::diagnostics::TraceEventKind) {
        self.upstream.emit_trace(kind);
    }

    fn publish_support_context(
        &self,
        capture: irlume_common::diagnostics::CaptureStatus,
        cameras: Vec<irlume_common::diagnostics::SanitizedCameraContext>,
    ) {
        self.upstream.publish_support_context(capture, cameras);
    }
}

fn support_probe_result(
    schedule: irlume_common::diagnostics::CaptureSchedule,
    source: irlume_common::diagnostics::CaptureScheduleSource,
    outcome: irlume_common::diagnostics::ProbeOutcome,
    fallback_reason: Option<irlume_common::diagnostics::RuntimeViolationLabel>,
    rgb: irlume_common::diagnostics::ProbeRoleOutcome,
    ir: irlume_common::diagnostics::ProbeRoleOutcome,
) -> irlume_common::diagnostics::SupportProbeResult {
    irlume_common::diagnostics::SupportProbeResult {
        snapshot: irlume_common::diagnostics::SupportSnapshot::bounded(
            0,
            0,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        ),
        schedule,
        source,
        outcome,
        fallback_reason,
        rgb,
        ir,
    }
}

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

#[cfg(test)]
mod capture_mode_decision_tests {
    use super::{
        cameras_for_held_pair, capture_mode_decision, ENV_CAPTURE_MODE_SOURCE,
        STORED_CAPTURE_MODE_SOURCE,
    };
    use irlume_camera::CaptureMode;

    struct DropProbe(std::rc::Rc<std::cell::Cell<bool>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

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
            (true, STORED_CAPTURE_MODE_SOURCE)
        );
        assert_eq!(
            capture_mode_decision(None, Some(CaptureMode::Concurrent)),
            (false, STORED_CAPTURE_MODE_SOURCE)
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
    fn sequential_selection_releases_preflight_camera_handles_immediately() {
        let dropped = std::rc::Rc::new(std::cell::Cell::new(false));
        let cameras = Some(DropProbe(std::rc::Rc::clone(&dropped)));

        let held = cameras_for_held_pair(true, cameras);

        assert!(held.is_none());
        assert!(
            dropped.get(),
            "the one-shot capture must be able to reopen the camera before auth continues"
        );
    }

    #[test]
    fn concurrent_selection_keeps_preflight_camera_handles() {
        let dropped = std::rc::Rc::new(std::cell::Cell::new(false));
        let cameras = Some(DropProbe(std::rc::Rc::clone(&dropped)));

        let held = cameras_for_held_pair(false, cameras);

        assert!(held.is_some());
        assert!(!dropped.get());
        drop(held);
        assert!(dropped.get());
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
            (false, STORED_CAPTURE_MODE_SOURCE)
        );
    }
}

#[cfg(test)]
mod capture_mode_switch_tests {
    use super::*;
    use irlume_camera::CaptureMode;
    use irlume_common::diagnostics::{
        CaptureSchedule, CaptureScheduleSource, DiagnosticSink, QualificationReason,
        QualificationState, RuntimeViolationLabel, ShareSafeEventKind, TraceEventKind, TraceMetric,
        TraceVerdict,
    };
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<ShareSafeEventKind>>);

    impl DiagnosticSink for RecordingSink {
        fn emit_share_safe(&self, kind: ShareSafeEventKind) {
            self.0.lock().unwrap().push(kind);
        }
    }

    impl RecordingSink {
        fn events(&self) -> Vec<ShareSafeEventKind> {
            self.0.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct TraceRecordingSink(Mutex<Vec<TraceEventKind>>);

    impl DiagnosticSink for TraceRecordingSink {
        fn emit_trace(&self, kind: TraceEventKind) {
            self.0.lock().unwrap().push(kind);
        }
    }

    #[test]
    fn runtime_degradation_is_process_local_and_exact_context_scoped() {
        let mut health = RuntimeCaptureHealth::default();
        let qualified = (false, STORED_CAPTURE_MODE_SOURCE);

        assert_eq!(
            apply_runtime_capture_health(qualified, Some("dock-a"), &health),
            qualified
        );

        health.trip("dock-a", RuntimeDegradation::ConcurrentCaptureFailure);

        assert_eq!(
            apply_runtime_capture_health(qualified, Some("dock-a"), &health),
            (true, RUNTIME_CAPTURE_MODE_SOURCE)
        );
        assert_eq!(
            apply_runtime_capture_health(qualified, Some("dock-b"), &health),
            qualified,
            "a failure on one exact USB context must not demote another"
        );
    }

    #[test]
    fn match_trace_uses_the_exact_score_threshold_and_authoritative_verdict() {
        let sink = TraceRecordingSink::default();
        emit_trace_match(&sink, TraceMetric::MatchCosine, 0.61, 0.64, false);
        let events = sink.0.lock().unwrap();
        assert!(matches!(
            &events[..],
            [TraceEventKind::Decision {
                verdict: TraceVerdict::NoMatch,
                measurements,
            }] if measurements.len() == 1
                && measurements[0].metric == TraceMetric::MatchCosine
                && measurements[0].value == 0.61_f32 as f64
                && measurements[0].threshold == Some(0.64_f32 as f64)
        ));
    }

    #[test]
    fn runtime_health_preserves_the_first_concrete_cause() {
        let mut health = RuntimeCaptureHealth::default();
        assert!(health.trip("dock-a", RuntimeDegradation::ActiveIrMissing));
        assert!(!health.trip("dock-a", RuntimeDegradation::ConcurrentCaptureFailure));
        assert_eq!(
            health.degradation("dock-a"),
            Some(RuntimeDegradation::ActiveIrMissing)
        );
    }

    #[test]
    fn successful_tune_reset_only_clears_the_qualified_context() {
        let mut health = RuntimeCaptureHealth::default();
        health.trip("dock-a", RuntimeDegradation::ConcurrentCaptureFailure);
        health.trip("dock-b", RuntimeDegradation::ConfirmedSignalLoss);

        assert!(health.reset("dock-a"));

        assert!(!health.requires_sequential("dock-a"));
        assert!(health.requires_sequential("dock-b"));
    }

    #[test]
    fn runtime_health_never_overrides_an_explicit_operator_mode() {
        let mut health = RuntimeCaptureHealth::default();
        health.trip("dock-a", RuntimeDegradation::ConfirmedSignalLoss);

        assert_eq!(
            apply_runtime_capture_health((false, ENV_CAPTURE_MODE_SOURCE), Some("dock-a"), &health,),
            (false, ENV_CAPTURE_MODE_SOURCE)
        );
    }

    #[test]
    fn schedule_event_uses_the_resolved_operation_snapshot() {
        let sink = RecordingSink::default();
        let selection = CaptureModeSelection {
            sequential: false,
            source: STORED_CAPTURE_MODE_SOURCE,
            runtime_key: Some("dock-a".into()),
            runtime_contract: None,
            camera_contract: None,
            qualification_authority: None,
            qualification_state: QualificationState::QualifiedConcurrent,
            qualification_reason: None,
            authoritative_rate_shortfalls: None,
            latest_attempt_rate_shortfalls: None,
            operation_demoted: std::cell::Cell::new(false),
        };

        emit_capture_schedule(&selection, true, &sink);

        assert_eq!(
            sink.events(),
            vec![ShareSafeEventKind::CaptureScheduleSelected {
                schedule: CaptureSchedule::Concurrent,
                source: CaptureScheduleSource::StoredQualification,
            }]
        );
    }

    #[test]
    fn rate_shortfall_support_context_preserves_authoritative_and_latest_attempt() {
        use irlume_common::diagnostics::{
            CameraRoleLabel, DigestToken, RateShortfallEvidence, RateShortfallsByArm,
            RateShortfallsByRole,
        };

        let evidence = |role, failure_count| RateShortfallEvidence {
            role,
            failure_count,
            delivered_num: 10,
            delivered_den: 1,
            floor_num: 15,
            floor_den: 1,
            tolerance_percent: 98,
            window_count: 30,
            window_span_us: 3_000_000,
        };
        let authoritative = RateShortfallsByArm {
            sequential: Some(RateShortfallsByRole::default()),
            concurrent: Some(RateShortfallsByRole {
                rgb: Some(evidence(CameraRoleLabel::Rgb, 4)),
                ir: None,
            }),
        };
        let latest = RateShortfallsByArm {
            sequential: Some(RateShortfallsByRole::default()),
            concurrent: Some(RateShortfallsByRole {
                rgb: None,
                ir: Some(evidence(CameraRoleLabel::Ir, 1)),
            }),
        };
        let selection = CaptureModeSelection {
            sequential: true,
            source: STORED_CAPTURE_MODE_SOURCE,
            runtime_key: Some("dock-a".into()),
            runtime_contract: None,
            camera_contract: None,
            qualification_authority: None,
            qualification_state: QualificationState::MeasuredSequential,
            qualification_reason: Some(QualificationReason::DeliveredRateShortfall),
            authoritative_rate_shortfalls: Some(authoritative.clone()),
            latest_attempt_rate_shortfalls: Some(latest.clone()),
            operation_demoted: std::cell::Cell::new(false),
        };

        let status = diagnostic_capture_status(
            &selection,
            true,
            Some(DigestToken::from_sha256_hex(&"a".repeat(64)).unwrap()),
            Some(DigestToken::from_sha256_hex(&"b".repeat(64)).unwrap()),
            None,
        );

        assert_eq!(status.authoritative_rate_shortfalls, Some(authoritative));
        assert_eq!(status.latest_attempt_rate_shortfalls, Some(latest));
    }

    #[test]
    fn runtime_violation_event_preserves_the_exact_validator_cause() {
        let sink = RecordingSink::default();

        emit_capture_fallback(RuntimeDegradation::DeliveredRateShortfall, &sink);

        assert_eq!(
            sink.events(),
            vec![ShareSafeEventKind::CaptureFallback {
                reason: RuntimeViolationLabel::DeliveredRateShortfall,
            }]
        );
    }

    #[test]
    fn qualification_mismatch_event_preserves_context_change() {
        let stored = irlume_camera::StoredCaptureQualificationState::unqualified(
            "context",
            irlume_camera::capture_qualification::QualificationMismatch::ContextChanged,
        );

        assert_eq!(
            diagnostic_qualification_event(&stored),
            ShareSafeEventKind::QualificationChanged {
                state: QualificationState::UnqualifiedContextChanged,
                reason: Some(QualificationReason::ContextChanged),
            }
        );
    }

    #[test]
    fn support_probe_preserves_the_first_pair_wide_fallback_cause() {
        let upstream = RecordingSink::default();
        let probe = SupportProbeSink::new(&upstream);

        emit_capture_fallback(RuntimeDegradation::DeliveredRateShortfall, &probe);
        emit_capture_fallback(RuntimeDegradation::ConcurrentCaptureFailure, &probe);

        assert_eq!(
            probe.fallback(),
            Some(RuntimeViolationLabel::DeliveredRateShortfall)
        );
        assert_eq!(upstream.events().len(), 2);
    }

    #[test]
    fn support_probe_forwards_trace_only_events_to_the_daemon_sink() {
        let upstream = TraceRecordingSink::default();
        let probe = SupportProbeSink::new(&upstream);
        let event = TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::Detection,
            elapsed_us: 42,
        };

        probe.emit_trace(event.clone());

        assert_eq!(&*upstream.0.lock().unwrap(), &[event]);
    }

    #[test]
    fn support_probe_result_is_categorical_and_starts_without_history() {
        use irlume_common::diagnostics::{ProbeOutcome, ProbeRoleOutcome};
        let result = support_probe_result(
            CaptureSchedule::Sequential,
            CaptureScheduleSource::RuntimeHealth,
            ProbeOutcome::FallbackCaptured,
            Some(RuntimeViolationLabel::ContinuityLoss),
            ProbeRoleOutcome::Captured,
            ProbeRoleOutcome::Captured,
        );

        assert_eq!(result.outcome, ProbeOutcome::FallbackCaptured);
        assert_eq!(
            result.fallback_reason,
            Some(RuntimeViolationLabel::ContinuityLoss)
        );
        assert!(result.snapshot.events().is_empty());
    }

    #[test]
    fn only_a_one_shot_concurrent_hard_failure_trips_runtime_health() {
        assert!(concurrent_pair_requires_fallback(
            false, true, false, false, false
        ));
        assert!(concurrent_pair_requires_fallback(
            false, false, true, false, false
        ));
        assert!(concurrent_pair_requires_fallback(
            false, false, false, true, false
        ));
        assert!(concurrent_pair_requires_fallback(
            false, false, false, false, true
        ));
        assert!(!concurrent_pair_requires_fallback(
            true, true, true, true, true
        ));
        assert!(!concurrent_pair_requires_fallback(
            false, false, false, false, false
        ));
    }

    /// #586 proactive degradation: a concurrent capture that SUCCEEDED but
    /// carried provenance warning signs should trip runtime degradation so
    /// the NEXT capture goes sequential, not wait for a hard failure.
    #[test]
    fn successful_capture_degradation_signs() {
        use super::successful_capture_shows_degradation_signs;
        // Clean capture: no signs, no proactive degradation.
        assert!(!successful_capture_shows_degradation_signs(
            false, false, false
        ));
        // Any single sign is enough (the #586 evidence: gaps compound).
        assert!(successful_capture_shows_degradation_signs(
            true, false, false
        ));
        assert!(successful_capture_shows_degradation_signs(
            false, true, false
        ));
        assert!(successful_capture_shows_degradation_signs(
            false, false, true
        ));
        // Multiple signs: still just true.
        assert!(successful_capture_shows_degradation_signs(true, true, true));
    }

    #[test]
    fn a_qualified_pair_rate_failure_demotes_but_other_schedules_do_not() {
        let qualified = CaptureModeSelection {
            sequential: false,
            source: STORED_CAPTURE_MODE_SOURCE,
            runtime_key: Some("dock-a".into()),
            runtime_contract: None,
            camera_contract: None,
            qualification_authority: None,
            qualification_state: QualificationState::QualifiedConcurrent,
            qualification_reason: None,
            authoritative_rate_shortfalls: None,
            latest_attempt_rate_shortfalls: None,
            operation_demoted: std::cell::Cell::new(false),
        };
        assert!(pair_rate_failure_is_degradation(&qualified));

        let mut sequential = qualified.clone();
        sequential.sequential = true;
        assert!(!pair_rate_failure_is_degradation(&sequential));

        let mut forced = qualified;
        forced.source = ENV_CAPTURE_MODE_SOURCE;
        forced.runtime_key = None;
        assert!(!pair_rate_failure_is_degradation(&forced));

        demote_after_pair_rate_failure(&mut forced);
        assert!(forced.sequential);
        assert_eq!(forced.source, RUNTIME_CAPTURE_MODE_SOURCE);
    }

    #[test]
    fn pair_arming_is_transactional() {
        struct Held<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Held<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let rgb_dropped = std::cell::Cell::new(false);
        let result = arm_pair_transactionally(
            || Ok::<_, &'static str>(Held(&rgb_dropped)),
            || Err::<Held<'_>, _>("IR arm failed"),
        );
        assert!(result.is_err());
        assert!(rgb_dropped.get(), "a partial RGB arm must be released");

        let ir_called = std::cell::Cell::new(false);
        let result = arm_pair_transactionally(
            || Err::<Held<'_>, _>("RGB arm failed"),
            || {
                ir_called.set(true);
                Ok(Held(&rgb_dropped))
            },
        );
        assert!(result.is_err());
        assert!(!ir_called.get(), "IR must not arm after RGB failed");
    }

    #[test]
    fn concurrent_failure_retry_replaces_both_sides_and_short_circuits_ir() {
        let (rgb, ir) = capture_pair_sequentially(|| Ok("fresh-rgb"), || Ok("fresh-ir"));
        assert_eq!(rgb.unwrap(), "fresh-rgb");
        assert_eq!(ir.unwrap(), Some("fresh-ir"));

        let ir_called = std::cell::Cell::new(false);
        let (rgb, ir) = capture_pair_sequentially(
            || Err::<(), _>(irlume_common::Error::Hardware("rgb failed".into())),
            || {
                ir_called.set(true);
                Ok(())
            },
        );
        assert!(rgb.is_err());
        assert!(ir.unwrap().is_none());
        assert!(
            !ir_called.get(),
            "IR must not fire after the RGB retry failed"
        );
    }

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
                .map(|n| n >= SELF_HEAL_SWITCH_AFTER)
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

    /// A mode the operator forced is never narrowed by runtime learning.
    #[test]
    fn an_operator_forced_mode_is_never_learned_from() {
        // Bind the guard to the one place that produces the string, so a rename
        // breaks this test instead of silently disabling the guard.
        assert_eq!(
            capture_mode_decision(Some("0"), Some(CaptureMode::Concurrent)).1,
            ENV_CAPTURE_MODE_SOURCE
        );
        // And the one mode the switch may act on.
        assert_eq!(
            capture_mode_decision(None, Some(CaptureMode::Concurrent)),
            (false, STORED_CAPTURE_MODE_SOURCE)
        );
    }
}

/// Hand the camera back before anything opens it again.
///
/// Dropping the sessions is the release: an `IrSession` owns the device's
/// buffer queue, and uvcvideo grants stream privileges to one file handle at
/// a time, so a consent watch that opens its own stream while one is alive
/// gets EBUSY from this same process. Named rather than inlined so all seven
/// release sites are one greppable thing, and so the next reader sees that
/// the release is a DROP and not a flag.
fn release_held(
    rgb: &mut Option<irlume_camera::RgbSession<'_>>,
    ir: &mut Option<irlume_camera::IrSession<'_>>,
) {
    *rgb = None;
    *ir = None;
}

/// Keep camera objects only when this operation will arm a held pair.
///
/// This must consume and explicitly drop the preflight opens on the sequential
/// path. A conditional move such as `if sequential { None } else { cameras }`
/// leaves the unselected value alive until the surrounding scope exits. The
/// following one-shot capture then reopens the same nodes while those handles
/// still exist, which is `EBUSY` on single-consumer drivers and v4l2loopback.
fn cameras_for_held_pair<T>(sequential: bool, cameras: Option<T>) -> Option<T> {
    if sequential {
        drop(cameras);
        None
    } else {
        cameras
    }
}

impl Engine {
    fn active_plan_versions(&self) -> Option<capture_plan::AttemptPlanVersions> {
        capture_plan::AttemptPlanVersions::new(
            self.ir_space.clone(),
            CanonicalRgbView::PREPROCESSING_ID,
            CanonicalGreyView::PREPROCESSING_ID,
        )
        .ok()
    }

    fn active_model_contracts(&self) -> irlume_vision::model_input::ModelContractSet {
        irlume_vision::model_input::ModelContractSet::from_initialized_adapters(
            &self.det,
            &self.emb,
            self.vit_pad.as_ref(),
            self.pad_ir.as_ref(),
            self.blaze.as_ref().map(|rescue| &rescue.0),
            self.mesh.as_ref(),
        )
    }

    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn load(det_path: &str, model_path: &str) -> irlume_common::Result<Self> {
        let mut runtime = irlume_vision::inference::CandidateRuntime::ort_cpu()?;
        Self::load_with_runtime(&mut runtime, det_path, model_path)
    }

    /// [`Self::load`], with all required ONNX sessions compiled by one runtime.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn load_with_runtime(
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        det_path: &str,
        model_path: &str,
    ) -> irlume_common::Result<Self> {
        // Identify the recognizer by its weights, not its path: a file swapped
        // in place under the same name is a different embedding space and must
        // not silently score against templates from the old one. Read the file
        // ONCE and hand those bytes to the weights loader below.
        let model_bytes = std::fs::read(model_path)
            .map_err(|e| irlume_common::Error::Io(format!("{model_path}: {e}")))?;
        Self::load_with_recognizer_weights_and_runtime(
            runtime,
            det_path,
            &irlume_common::HashedModel::new(model_bytes),
        )
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
        let mut runtime = irlume_vision::inference::CandidateRuntime::ort_cpu()?;
        Self::load_with_recognizer_weights_and_runtime(&mut runtime, det_path, model)
    }

    /// Build every required ONNX session with one candidate runtime.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn load_with_recognizer_weights_and_runtime(
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        det_path: &str,
        model: &irlume_common::HashedModel,
    ) -> irlume_common::Result<Self> {
        // Full digest: the tag resists an adversarial model, and truncation
        // halves its strength per dropped character.
        let embed_space = format!("embed:{}", model.sha256());
        let det_bytes = read_model(det_path)?;
        Ok(Self {
            det: Detector::load_from_memory_with_runtime(runtime, &det_bytes)?,
            emb: Embedder::load_from_memory_with_runtime(runtime, model.bytes())?,
            ir_adapter: None,
            ir_space: "raw".into(),
            embed_space,
            rgb_threshold: irlume_core::RGB_MATCH_THRESHOLD,
            mesh: None,
            blaze: None,
            vit_pad: None,
            vit_scores: Vec::new(),
            pad_ir: None,
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
            head_consent_before_match: HeadConsentVerdict::NoGesture,
            stop_requested: None,
            last_attempt_facts: AttemptFacts::default(),
            last_attempt_situation: None,
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
    pub fn with_ir_adapter(self, path: &str) -> irlume_common::Result<Self> {
        if !std::path::Path::new(path).exists() {
            return Ok(self);
        }
        let mut runtime = irlume_vision::inference::CandidateRuntime::ort_cpu()?;
        self.with_ir_adapter_with_runtime(&mut runtime, path)
    }

    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_ir_adapter_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            // One read feeds both the digest and the session, so the tag always
            // describes the weights that are running (same reasoning as the
            // recognizer in `load`). The 12-hex prefix is the format existing
            // enrollments carry in `ir_space`; changing it would orphan them.
            let bytes = read_model(path)?;
            let digest = irlume_common::sha256_hex(&bytes);
            self.ir_adapter = Some(Adapter::load_from_memory_with_runtime(runtime, &bytes)?);
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
        self.refit_profile_calib_for_adapter_state(self.ir_adapter.is_some(), prof);
    }

    fn refit_profile_calib_for_adapter_state(
        &self,
        adapter_loaded: bool,
        prof: &mut irlume_core::storage::FaceProfile,
    ) {
        if adapter_loaded {
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
        ir_match_in(
            &self.ir_space,
            &self.embed_space,
            self.ir_adapter.is_some(),
            enr,
            probe,
        )
    }

    /// Load MediaPipe FaceMesh for detection-rescue alignment. Head consent does
    /// not use this model. If the file is absent this is a no-op; the
    /// mesh-dependent rescue path is skipped, so face auth keeps working.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_mesh(self, path: &str) -> irlume_common::Result<Self> {
        if !std::path::Path::new(path).exists() {
            return Ok(self);
        }
        let bytes = read_model(path)?;
        if bytes.len() >= 8 && &bytes[4..8] == b"TFL3" {
            let mut engine = self;
            engine.mesh = Some(irlume_vision::FaceMesh::load_from_memory(&bytes)?);
            return Ok(engine);
        }
        let mut runtime = irlume_vision::inference::CandidateRuntime::ort_cpu()?;
        let mut engine = self;
        engine.mesh = Some(irlume_vision::FaceMesh::load_from_memory_with_runtime(
            &mut runtime,
            &bytes,
        )?);
        Ok(engine)
    }

    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_mesh_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.mesh = Some(irlume_vision::FaceMesh::load_from_memory_with_runtime(
                runtime,
                &read_model(path)?,
            )?);
        }
        Ok(self)
    }

    /// [`Self::with_mesh`], except a LOAD failure leaves the mesh off and
    /// hands the error back beside the engine instead of consuming it, so the
    /// caller can apply its own policy (the daemon degrades outside strict
    /// mode: head consent needs no mesh, and killing the daemon over an optional
    /// rescue model would turn "rescue off" into "face auth dead").
    #[must_use]
    pub fn with_mesh_degraded(self, path: &str) -> (Self, Option<irlume_common::Error>) {
        if !std::path::Path::new(path).exists() {
            return (self, None);
        }
        match irlume_vision::inference::CandidateRuntime::ort_cpu() {
            Ok(mut runtime) => self.with_mesh_degraded_with_runtime(&mut runtime, path),
            Err(error) => (self, Some(error)),
        }
    }

    #[must_use]
    pub fn with_mesh_degraded_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> (Self, Option<irlume_common::Error>) {
        if std::path::Path::new(path).exists() {
            let loaded = read_model(path).and_then(|bytes| {
                irlume_vision::FaceMesh::load_from_memory_with_runtime(runtime, &bytes)
            });
            match loaded {
                Ok(m) => self.mesh = Some(m),
                Err(e) => return (self, Some(e)),
            }
        }
        (self, None)
    }

    /// Load the BlazeFace short-range rescue detector (improves detection on
    /// saturated outdoor frames). No-op if the file is absent.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_blaze_rescue(self, path: &str) -> irlume_common::Result<Self> {
        if !std::path::Path::new(path).exists() {
            return Ok(self);
        }
        let mut runtime = irlume_vision::inference::CandidateRuntime::ort_cpu()?;
        self.with_blaze_rescue_with_runtime(&mut runtime, path)
    }

    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_blaze_rescue_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> irlume_common::Result<Self> {
        // Shipped short-range rescue (ONNX).
        if std::path::Path::new(path).exists() {
            self.blaze = Some(Rescue(
                irlume_vision::BlazeRescue::load_from_memory_with_runtime(
                    runtime,
                    &read_model(path)?,
                )?,
            ));
        }
        Ok(self)
    }

    #[must_use]
    pub fn with_blaze_rescue_degraded_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> (Self, Option<irlume_common::Error>) {
        if std::path::Path::new(path).exists() {
            let loaded = read_model(path).and_then(|bytes| {
                irlume_vision::BlazeRescue::load_from_memory_with_runtime(runtime, &bytes)
            });
            match loaded {
                Ok(blaze) => self.blaze = Some(Rescue(blaze)),
                Err(error) => return (self, Some(error)),
            }
        }
        (self, None)
    }

    pub fn has_blaze_rescue(&self) -> bool {
        self.blaze.is_some()
    }

    /// Load the shipped ViT RGB PAD classifier (`liveness_vit.onnx`,
    /// ADR-0013). No-op if the file is absent; ADR-0019 makes the resulting
    /// unavailable evidence a password-fallback denial without turning model
    /// absence into a daemon startup failure.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_vit_pad(self, path: &str) -> irlume_common::Result<Self> {
        if !std::path::Path::new(path).exists() {
            return Ok(self);
        }
        let mut runtime = irlume_vision::inference::CandidateRuntime::ort_cpu()?;
        self.with_vit_pad_with_runtime(&mut runtime, path)
    }

    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_vit_pad_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.vit_pad = Some(irlume_vision::PadVit::load_from_memory_with_runtime(
                runtime,
                &read_model(path)?,
            )?);
        }
        Ok(self)
    }

    #[must_use]
    pub fn with_vit_pad_degraded(self, path: &str) -> (Self, Option<irlume_common::Error>) {
        if !std::path::Path::new(path).exists() {
            return (self, None);
        }
        match irlume_vision::inference::CandidateRuntime::ort_cpu() {
            Ok(mut runtime) => self.with_vit_pad_degraded_with_runtime(&mut runtime, path),
            Err(error) => (self, Some(error)),
        }
    }

    #[must_use]
    pub fn with_vit_pad_degraded_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> (Self, Option<irlume_common::Error>) {
        if std::path::Path::new(path).exists() {
            let loaded = read_model(path).and_then(|bytes| {
                irlume_vision::PadVit::load_from_memory_with_runtime(runtime, &bytes)
            });
            match loaded {
                Ok(pad) => self.vit_pad = Some(pad),
                Err(e) => return (self, Some(e)),
            }
        }
        (self, None)
    }

    pub fn has_vit_pad(&self) -> bool {
        self.vit_pad.is_some()
    }

    /// Load the shipped IR PAD classifier (`flir.onnx`, ADR-0013): same
    /// weights/threshold as the opt-in catalog entry, default-on. Absent
    /// files retain unavailable evidence and therefore force password fallback
    /// on IR-requiring face paths (ADR-0019).
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_pad_ir(self, path: &str) -> irlume_common::Result<Self> {
        if !std::path::Path::new(path).exists() {
            return Ok(self);
        }
        let mut runtime = irlume_vision::inference::CandidateRuntime::ort_cpu()?;
        self.with_pad_ir_with_runtime(&mut runtime, path)
    }

    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn with_pad_ir_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.pad_ir = Some(irlume_vision::PadIr::load_from_memory_with_runtime(
                runtime,
                &read_model(path)?,
            )?);
        }
        Ok(self)
    }

    #[must_use]
    pub fn with_pad_ir_degraded(self, path: &str) -> (Self, Option<irlume_common::Error>) {
        if !std::path::Path::new(path).exists() {
            return (self, None);
        }
        match irlume_vision::inference::CandidateRuntime::ort_cpu() {
            Ok(mut runtime) => self.with_pad_ir_degraded_with_runtime(&mut runtime, path),
            Err(error) => (self, Some(error)),
        }
    }

    #[must_use]
    pub fn with_pad_ir_degraded_with_runtime(
        mut self,
        runtime: &mut dyn irlume_vision::inference::ModelCompiler,
        path: &str,
    ) -> (Self, Option<irlume_common::Error>) {
        if std::path::Path::new(path).exists() {
            let loaded = read_model(path).and_then(|bytes| {
                irlume_vision::PadIr::load_from_memory_with_runtime(runtime, &bytes)
            });
            match loaded {
                Ok(pad) => self.pad_ir = Some(pad),
                Err(e) => return (self, Some(e)),
            }
        }
        (self, None)
    }

    pub fn has_pad_ir(&self) -> bool {
        self.pad_ir.is_some()
    }

    /// Record one ViT PAD score and answer whether the 5-frame-median vote
    /// DENIES. Median (not mean) per the qualification protocol: it is the
    /// statistic that held genuine at 0/531 presentations on LFW. The ring
    /// keeps the last [`VIT_PAD_VOTE_N`] scores of THIS authentication only
    /// (`authenticate_for` clears it).
    fn vit_pad_votes_deny(&mut self, score: f32) -> bool {
        if !score.is_finite() {
            return false; // inference garbage abstains, deny-only cannot fire on it
        }
        self.vit_scores.push(score);
        vit_vote_denies(&self.vit_scores)
    }

    /// Detection rescue (cascade stage 2): when YuNet returns no face, try
    /// BlazeFace and refine its coarse box into the 5 alignment landmarks
    /// with FaceMesh (BlazeFace has no mouth corners and its eyes measured
    /// 0.087 NME vs YuNet's 0.053; never align from its own keypoints).
    /// Returns a Detection shaped exactly like YuNet's, or None when either
    /// optional model is absent or no face clears the threshold.
    fn rescue_detect(&mut self, view: CanonicalRgbView<'_>, tag: &str) -> Option<Detection> {
        let blaze = self.blaze.as_mut()?;
        let mesh = self.mesh.as_mut()?;
        let (bbox, score) = blaze
            .detect_top(&BlazeFaceInput::new(view))
            .ok()
            .flatten()?;
        // (both rescue variants return the same coarse-box contract; the
        // mesh refine below is what turns either into alignment landmarks)
        let input = mesh.prepare_input(view, bbox).ok()?;
        let lm = mesh.landmarks(&input).ok()?;
        if lm.len() < irlume_vision::MESH_N {
            return None;
        }
        const RESCUE_LEFT_EYE_RING: [usize; 6] = [33, 160, 158, 133, 153, 144];
        const RESCUE_RIGHT_EYE_RING: [usize; 6] = [362, 385, 387, 263, 373, 380];
        let center = |idx: &[usize; 6]| {
            let (mut x, mut y) = (0.0f32, 0.0f32);
            for &i in idx {
                x += lm[i].0;
                y += lm[i].1;
            }
            (x / 6.0, y / 6.0)
        };
        let e1 = center(&RESCUE_LEFT_EYE_RING);
        let e2 = center(&RESCUE_RIGHT_EYE_RING);
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

    fn run_camera_operation<T>(
        operation: &irlume_camera::lease::CameraOperationSession,
        task: impl FnOnce() -> irlume_common::Result<T>,
    ) -> irlume_common::Result<T> {
        operation
            .run(task)
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?
    }

    /// One capture: RGB+IR → liveness verdict + (if a face) its embedding.
    /// Capture + assess, choosing the path from the hardware: full cross-spectrum
    /// (RGB+IR) when an IR camera is present, else RGB-only (convenience).
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn assess(&mut self) -> irlume_common::Result<Assessment> {
        // One-shot entry: no authenticate_for/capture_scans ran to clear the
        // ViT vote ring, so repeated assess() calls must not accumulate a
        // cross-presentation vote (GLM review finding 2).
        self.vit_scores.clear();
        let endpoints: Vec<&str> = if self.ir_available {
            vec![self.rgb_dev.as_str(), self.ir_dev.as_str()]
        } else {
            vec![self.rgb_dev.as_str()]
        };
        let operation = irlume_camera::lease::acquire_camera_operation(
            &endpoints,
            irlume_camera::lease::CameraOperationKind::Authentication,
            std::time::Duration::from_secs(2),
        )
        .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
        operation
            .run(|| {
                if self.ir_available {
                    self.assess_full(&operation)
                } else {
                    self.assess_rgb_only()
                }
            })
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?
    }

    /// Perform one bounded, production-shaped camera capture for a support
    /// report. This publishes no enrollment or qualification state and never
    /// discovers emitter controls; IR session creation uses only the ordinary
    /// already-authorized emitter path.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn support_probe(
        &mut self,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<irlume_common::diagnostics::SupportProbeResult> {
        use irlume_common::diagnostics::{DiagnosticSink as _, ProbeOutcome, ProbeRoleOutcome};

        let probe_sink = SupportProbeSink::new(diagnostics);
        let (rgb_dev, ir_dev) = (self.rgb_dev.clone(), self.ir_dev.clone());
        let endpoints: Vec<&str> = if self.ir_available {
            vec![rgb_dev.as_str(), ir_dev.as_str()]
        } else {
            vec![rgb_dev.as_str()]
        };
        let operation = match irlume_camera::lease::acquire_camera_operation(
            &endpoints,
            irlume_camera::lease::CameraOperationKind::Diagnostics,
            std::time::Duration::from_secs(2),
        ) {
            Ok(operation) => operation,
            Err(_) => {
                let selection = unavailable_capture_mode_selection();
                emit_capture_context(&selection, self.ir_available, &probe_sink);
                probe_sink.emit_share_safe(
                    irlume_common::diagnostics::ShareSafeEventKind::CaptureFallback {
                        reason: irlume_common::diagnostics::RuntimeViolationLabel::PairOpenFailure,
                    },
                );
                let (schedule, source) = diagnostic_capture_schedule(&selection, self.ir_available);
                return Ok(support_probe_result(
                    schedule,
                    source,
                    ProbeOutcome::Unavailable,
                    probe_sink.fallback(),
                    ProbeRoleOutcome::Missing,
                    ProbeRoleOutcome::Missing,
                ));
            }
        };

        if !self.ir_available {
            let selection = unavailable_capture_mode_selection();
            emit_capture_context(&selection, false, &probe_sink);
            let (schedule, source) = diagnostic_capture_schedule(&selection, false);
            if let Ok(rgb) = operation.open_rgb(&rgb_dev) {
                if let Ok(camera) = rgb.diagnostic_camera_context() {
                    probe_sink.emit_trace(
                        irlume_common::diagnostics::TraceEventKind::StreamContract {
                            role: irlume_common::diagnostics::CameraRoleLabel::Rgb,
                            requested: camera.requested.clone(),
                            accepted: camera.accepted.clone(),
                        },
                    );
                    publish_rgb_only_support_context(camera, &probe_sink);
                }
            }
            let captured = Self::run_camera_operation(&operation, || {
                self.assess_rgb_only_with_diagnostics(&probe_sink)
                    .map(|_| ())
            });
            return Ok(support_probe_result(
                schedule,
                source,
                if captured.is_ok() {
                    ProbeOutcome::RgbOnlyCaptured
                } else {
                    ProbeOutcome::Failed
                },
                None,
                if captured.is_ok() {
                    ProbeRoleOutcome::Captured
                } else {
                    ProbeRoleOutcome::Failed
                },
                ProbeRoleOutcome::Missing,
            ));
        }

        let resolved_cams = match (operation.open_rgb(&rgb_dev), operation.open_ir(&ir_dev)) {
            (Ok(rgb), Ok(ir)) => Some((rgb, ir)),
            _ => None,
        };
        let mut selection = resolved_cams
            .as_ref()
            .map_or_else(unavailable_capture_mode_selection, |(rgb, ir)| {
                capture_mode_selection_with_diagnostics(rgb, ir, &probe_sink)
            });
        emit_capture_context(&selection, true, &probe_sink);
        if resolved_cams.is_none() {
            probe_sink.emit_share_safe(
                irlume_common::diagnostics::ShareSafeEventKind::CaptureFallback {
                    reason: irlume_common::diagnostics::RuntimeViolationLabel::PairOpenFailure,
                },
            );
        }
        let (selected_schedule, selected_source) = diagnostic_capture_schedule(&selection, true);
        let sequential = selection.is_sequential();
        let held_cams = cameras_for_held_pair(sequential, resolved_cams);

        if let (Some((rgb, ir)), false) = (&held_cams, sequential) {
            let progress = self.capture_progress();
            match arm_pair_transactionally(
                || rgb.session_with_progress(&progress),
                || ir.session_with_progress(&progress),
            ) {
                Ok((mut rgb_session, mut ir_session)) => {
                    match irlume_camera::establish_pair_rate(&mut rgb_session, &mut ir_session) {
                        Ok(()) => match self.assess_full_with_operation(
                            Some((&mut rgb_session, &mut ir_session)),
                            Some(&selection),
                            &operation,
                            &probe_sink,
                        ) {
                            Ok(_) => {
                                return Ok(support_probe_result(
                                    selected_schedule,
                                    selected_source,
                                    ProbeOutcome::Captured,
                                    probe_sink.fallback(),
                                    ProbeRoleOutcome::Captured,
                                    ProbeRoleOutcome::Captured,
                                ));
                            }
                            Err(CapturePathError::ConcurrentPair(_)) => {
                                drop(rgb_session);
                                drop(ir_session);
                                demote_after_concurrent_capture_failure(&mut selection);
                            }
                            Err(CapturePathError::Other(_)) => {
                                return Ok(support_probe_result(
                                    selected_schedule,
                                    selected_source,
                                    ProbeOutcome::Failed,
                                    probe_sink.fallback(),
                                    ProbeRoleOutcome::Failed,
                                    ProbeRoleOutcome::Failed,
                                ));
                            }
                        },
                        Err(_) => {
                            emit_capture_fallback(
                                RuntimeDegradation::PairRateEstablishmentFailure,
                                &probe_sink,
                            );
                            demote_after_pair_rate_failure(&mut selection);
                        }
                    }
                }
                Err(_) => {
                    emit_capture_fallback(RuntimeDegradation::PairArmFailure, &probe_sink);
                    demote_after_pair_arm_failure(&mut selection);
                }
            }
        }

        drop(held_cams);
        let captured =
            self.assess_full_with_operation(None, Some(&selection), &operation, &probe_sink);
        let fallback_reason = probe_sink.fallback();
        Ok(support_probe_result(
            selected_schedule,
            selected_source,
            if captured.is_ok() {
                if fallback_reason.is_some() {
                    ProbeOutcome::FallbackCaptured
                } else {
                    ProbeOutcome::Captured
                }
            } else {
                ProbeOutcome::Failed
            },
            fallback_reason,
            if captured.is_ok() {
                ProbeRoleOutcome::Captured
            } else {
                ProbeRoleOutcome::Failed
            },
            if captured.is_ok() {
                ProbeRoleOutcome::Captured
            } else {
                ProbeRoleOutcome::Failed
            },
        ))
    }

    /// RGB-only capture + algorithmic (no-IR) liveness, the convenience-tier
    /// path for devices without an IR camera. Anti-spoof here is DETERRENT-grade
    /// (well-lit + frontal + screen/glare heuristic), which is why this tier is
    /// limited to lock-screen unlock and never releases credentials.
    fn assess_rgb_only(&mut self) -> irlume_common::Result<Assessment> {
        self.assess_rgb_only_with_diagnostics(&())
    }

    fn assess_rgb_only_with_diagnostics(
        &mut self,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Assessment> {
        let capture_started = std::time::Instant::now();
        let rgb = irlume_camera::capture_rgb_denoised_with_progress(
            &self.rgb_dev,
            &self.capture_progress(),
        )?;
        if let Some(event) = irlume_camera::diagnostic_manifest_stream_evidence(rgb.manifest()) {
            diagnostics.emit_trace(event);
        }
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::RgbCapture,
            elapsed_us: u64::try_from(capture_started.elapsed().as_micros()).unwrap_or(u64::MAX),
        });
        let rgb_view = CanonicalRgbView::try_from_parts(rgb.pixels(), rgb.width(), rgb.height())
            .map_err(model_input_error)?;
        let detection_started = std::time::Instant::now();
        let rgb_faces = self.det.detect(&DetectorInput::from_rgb(rgb_view))?;
        let rgb_top = top_detection(&rgb_faces).cloned();
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::Detection,
            elapsed_us: u64::try_from(detection_started.elapsed().as_micros()).unwrap_or(u64::MAX),
        });
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::DetectorCount {
            role: irlume_common::diagnostics::CameraRoleLabel::Rgb,
            count: u32::try_from(rgb_faces.len()).unwrap_or(u32::MAX),
        });
        let (rgb_brightness, rgb_specular) = rgb_top
            .as_ref()
            .map(|f| rgb_luma_stats(rgb.pixels(), rgb.width(), rgb.height(), &f.bbox))
            .unwrap_or((0.0, 0.0));
        // 2D-FFT moiré / pixel-grid cue (screen-replay deterrent).
        let rgb_moire = rgb_top
            .as_ref()
            .map(|f| {
                irlume_vision::moire::moire_score(&irlume_vision::moire::face_gray_n(
                    rgb.pixels(),
                    rgb.width(),
                    rgb.height(),
                    &f.bbox,
                ))
            })
            .unwrap_or(0.0);
        let pose = rgb_top
            .as_ref()
            .map(|f| irlume_vision::head_pose(&f.landmarks));
        let signals = Signals {
            rgb_face: rgb_top.as_ref().map(|f| irlume_liveness::FaceBox {
                cx: (f.bbox[0] + f.bbox[2]) / 2.0 / rgb.width() as f32,
                cy: (f.bbox[1] + f.bbox[3]) / 2.0 / rgb.height() as f32,
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
            face_frac: face_frac_of(rgb_top.as_ref().map(|f| &f.bbox), rgb.width()),
            // RGB-only path: no IR frame exists to clip.
            ir_saturated_frac: None,
            ir_persistent_saturated_frac: None,
            ir_ceiling_known: false,
            rgb_face_brightness: rgb_brightness,
            rgb_specular_frac: rgb_specular,
            rgb_moire_score: rgb_moire,
        };
        let liveness_started = std::time::Instant::now();
        let (verdict, _cues, reason) = self.gate.evaluate_rgb_only(&signals);
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::Liveness,
            elapsed_us: u64::try_from(liveness_started.elapsed().as_micros()).unwrap_or(u64::MAX),
        });
        diagnostics.emit_trace(irlume_liveness::diagnostic_trace_decision(
            verdict, &signals,
        ));
        irlume_common::dlog!(
            "liveness(rgb-only): {verdict:?} ({reason}); bright={:.0} specular={:.2} moire={:.0} face_frac={:.3} (recorded for #174, gates nothing)",
            signals.rgb_face_brightness,
            signals.rgb_specular_frac,
            signals.rgb_moire_score,
            signals.face_frac
        );
        // Shipped ViT RGB PAD cue (ADR-0013): on the RGB-ONLY tier this is
        // the one measured defence against the life-size print (the 2026-06-30
        // breach species; IR face-presence does not exist here). Same deny-only
        // 5-median contract as the cross-spectrum path.
        let rgb_pad = match (verdict, rgb_top.as_ref(), self.vit_pad.as_mut()) {
            (Verdict::Live, Some(_), None) => PadEvidence::Unavailable,
            (Verdict::Live, Some(f), Some(pad)) => {
                match pad.p_spoof(&VitRgbPadInput::new(rgb_view, f.bbox)) {
                    Ok(p) if p.is_finite() => PadEvidence::Score(p),
                    Ok(_) => PadEvidence::InferenceFailed,
                    Err(e) => {
                        irlume_common::dlog!("pad-vit: inference failed ({e})");
                        PadEvidence::InferenceFailed
                    }
                }
            }
            _ => PadEvidence::NotApplicable,
        };
        let (verdict, reason) = match rgb_pad {
            PadEvidence::Score(p) => {
                irlume_common::dlog!("pad-vit(rgb-only): p_spoof {p:.3}");
                if self.vit_pad_votes_deny(p) {
                    irlume_common::dlog!(
                        "pad-vit: 5-frame median >= {VIT_PAD_THRESHOLD:.2}; downgrading Live to Spoof"
                    );
                    (
                        Verdict::Spoof,
                        "RGB PAD cue flags a spoof; use your password".into(),
                    )
                } else {
                    (verdict, reason)
                }
            }
            _ => (verdict, reason),
        };
        let embedding = match &rgb_top {
            Some(f) => Some(self.emb.embed_tta(
                &ArcFaceInput::from_rgb(rgb_view, &f.landmarks).map_err(model_input_error)?,
            )?),
            None => None,
        };
        Ok(Assessment {
            verdict,
            reason,
            embedding,
            rgb_frame_mean: irlume_camera::frame_mean(rgb.pixels()),
            ir_embedding: None,
            signals,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            ir_ambient_share: None, // RGB-only path: no IR burst to measure
            shipped_ir_fake: None,  // RGB-only path: no IR frame exists
            rgb_pad,
            ir_pad: PadEvidence::NotApplicable,
            sequential_pair: false, // RGB-only path: no pair exists
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
    fn assess_full(
        &mut self,
        operation: &irlume_camera::lease::CameraOperationSession,
    ) -> irlume_common::Result<Assessment> {
        let rgb = operation.open_rgb(&self.rgb_dev)?;
        let ir = operation.open_ir(&self.ir_dev)?;
        let selection = capture_mode_selection(&rgb, &ir);
        drop(rgb);
        drop(ir);
        self.assess_full_with(None, Some(&selection), operation, &())
            .map_err(CapturePathError::into_inner)
    }

    fn assess_full_with_operation(
        &mut self,
        held: Option<(
            &mut irlume_camera::RgbSession<'_>,
            &mut irlume_camera::IrSession<'_>,
        )>,
        capture_mode: Option<&CaptureModeSelection>,
        operation: &irlume_camera::lease::CameraOperationSession,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> Result<Assessment, CapturePathError> {
        operation
            .run(|| self.assess_full_with(held, capture_mode, operation, diagnostics))
            .map_err(|error| {
                CapturePathError::Other(irlume_common::Error::Hardware(error.to_string()))
            })?
    }

    /// [`Self::assess_full`], optionally reusing already-streaming cameras.
    fn assess_full_with(
        &mut self,
        held: Option<(
            &mut irlume_camera::RgbSession<'_>,
            &mut irlume_camera::IrSession<'_>,
        )>,
        capture_mode: Option<&CaptureModeSelection>,
        operation: &irlume_camera::lease::CameraOperationSession,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> Result<Assessment, CapturePathError> {
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
        // capture-mode probe measured for THIS exact endpoint pair, negotiated
        // stream tuple, controller and link speed (`irlume camera-tune`), then
        // the sequential default. The probe exists because the dimming above
        // is a property of the whole live hardware context, not just a camera
        // model: the NexiGo N930W keeps 56% of its RGB brightness when both of
        // its interfaces stream, the ASUS built-in keeps all of it, and only a
        // measurement on the actual connection can tell which schedule works.
        // The caller supplies one snapshot when sessions are HELD; a one-shot
        // call resolves once before opening either stream. Re-resolving after
        // both streams are live would be a check-to-act window and can collide
        // with cameras that reject a second open (#187, #313).
        let fresh_selection;
        let capture_mode = match capture_mode {
            Some(selection) => selection,
            None => {
                fresh_selection = unavailable_capture_mode_selection();
                &fresh_selection
            }
        };
        let sequential = capture_mode.is_sequential();
        let mut attempt_plan = capture_mode
            .camera_contract
            .clone()
            .zip(self.active_plan_versions())
            .and_then(|(camera, versions)| {
                attempt_plan_from_camera(camera, versions, self.active_model_contracts())
            })
            .ok_or_else(|| {
                irlume_common::Error::Hardware(
                    "immutable attempt capture plan unavailable; refusing capture".into(),
                )
            })?;
        let mut conditioning_selection = attempt_plan.camera().conditioning();
        let mode_source = capture_mode.active_source();
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
            conditioning: irlume_camera::conditioning::ConditioningSelection,
        ) -> (
            irlume_common::Result<(
                irlume_camera::CanonicalRgbEvidence,
                irlume_camera::conditioning::ConditioningRestoration,
            )>,
            bool,
        ) {
            if let Err(error) = rgb_s.ensure_conditioning(conditioning) {
                return (Err(error), false);
            }
            let (capture, recovered) = match rgb_s.denoised() {
                Ok(frame) => (Ok(frame), false),
                Err(e) => {
                    irlume_common::dlog!(
                        "assess: held rgb stream broke ({e}); recovering it in place"
                    );
                    let recovered = rgb_s.recover().and_then(|()| rgb_s.denoised());
                    (recovered, true)
                }
            };
            let restoration = rgb_s.restore_conditioning(conditioning);
            let result = match (capture, restoration) {
                (Ok(frame), Ok(proof)) => Ok((frame, proof)),
                (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            };
            (result, recovered)
        }
        // One IR capture from a HELD session, recovering the stream in place
        // on a mid-stream fault. Mirrors held_rgb_capture; the same EBUSY
        // reasoning applies: a standalone reopen would collide with the held
        // session's own fd on a double-open-rejecting camera.
        fn held_ir_capture(
            ir_s: &mut irlume_camera::IrSession<'_>,
        ) -> (
            irlume_common::Result<irlume_camera::CanonicalIrEvidence>,
            bool,
        ) {
            match ir_s.capture_with_stats() {
                Ok(f) => (Ok(f), false),
                Err(e) => {
                    irlume_common::dlog!(
                        "assess: held ir stream broke ({e}); recovering it in place"
                    );
                    let recovered = ir_s.recover().and_then(|()| ir_s.capture_with_stats());
                    (recovered, true)
                }
            }
        }
        let held_sessions = held.is_some();
        // Every one-shot capture below carries the per-window heartbeat
        // (#336); held sessions already carry theirs from `capture_scans`.
        let progress = self.capture_progress();
        let (mut rgb_res, mut rgb_ms, mut ir_res, mut ir_ms, recovered_side) =
            if let Some((rgb_s, ir_s)) = held {
                if sequential {
                    let t = std::time::Instant::now();
                    let (rgb, rgb_recovered) = held_rgb_capture(rgb_s, conditioning_selection);
                    let rgb_ms = t.elapsed().as_millis();
                    if rgb.is_err() {
                        (rgb, rgb_ms, Ok(None), 0, rgb_recovered)
                    } else {
                        let t = std::time::Instant::now();
                        let (ir, ir_recovered) = held_ir_capture(ir_s);
                        (
                            rgb,
                            rgb_ms,
                            ir.map(Some),
                            t.elapsed().as_millis(),
                            rgb_recovered || ir_recovered,
                        )
                    }
                } else {
                    std::thread::scope(|s| {
                        let ir_thread = s.spawn(move || {
                            let t = std::time::Instant::now();
                            let captured = Self::run_camera_operation(operation, || {
                                let (capture, recovered) = held_ir_capture(ir_s);
                                capture.map(|frame| (frame, recovered))
                            });
                            (captured, t.elapsed().as_millis())
                        });
                        let t = std::time::Instant::now();
                        let (rgb, rgb_recovered) = held_rgb_capture(rgb_s, conditioning_selection);
                        let rgb_ms = t.elapsed().as_millis();
                        let (ir, ir_ms) = ir_thread.join().unwrap_or_else(|_| {
                            (
                                Err(irlume_common::Error::Hardware(
                                    "IR capture thread panicked".into(),
                                )),
                                0,
                            )
                        });
                        let (ir, ir_recovered) = match ir {
                            Ok((frame, recovered)) => (Ok(frame), recovered),
                            Err(error) => (Err(error), false),
                        };
                        (
                            rgb,
                            rgb_ms,
                            ir.map(Some),
                            ir_ms,
                            rgb_recovered || ir_recovered,
                        )
                    })
                }
            } else if sequential {
                let t = std::time::Instant::now();
                let rgb = irlume_camera::capture_rgb_denoised_with_progress_and_conditioning(
                    &self.rgb_dev,
                    &progress,
                    conditioning_selection,
                );
                let rgb_ms = t.elapsed().as_millis();
                // Match the old short-circuit: don't fire the IR emitter after an
                // RGB fault (privacy switch, missing node); the shared retry below
                // surfaces the RGB error.
                if rgb.is_err() {
                    (rgb, rgb_ms, Ok(None), 0, false)
                } else {
                    let t = std::time::Instant::now();
                    let ir =
                        irlume_camera::capture_ir_with_stats_and_progress(&self.ir_dev, &progress);
                    (rgb, rgb_ms, ir.map(Some), t.elapsed().as_millis(), false)
                }
            } else {
                std::thread::scope(|s| {
                    let ir_dev = self.ir_dev.clone();
                    let ir_progress = progress.clone();
                    let ir_thread = s.spawn(move || {
                        let t = std::time::Instant::now();
                        let captured = Self::run_camera_operation(operation, || {
                            irlume_camera::capture_ir_with_stats_and_progress(&ir_dev, &ir_progress)
                        });
                        (captured, t.elapsed().as_millis())
                    });
                    let t = std::time::Instant::now();
                    let rgb = irlume_camera::capture_rgb_denoised_with_progress_and_conditioning(
                        &self.rgb_dev,
                        &progress,
                        conditioning_selection,
                    );
                    let rgb_ms = t.elapsed().as_millis();
                    let (ir, ir_ms) = ir_thread.join().unwrap_or_else(|_| {
                        (
                            Err(irlume_common::Error::Hardware(
                                "IR capture thread panicked".into(),
                            )),
                            0,
                        )
                    });
                    (rgb, rgb_ms, ir.map(Some), ir_ms, false)
                })
            };
        emit_trace_stage_ms(
            diagnostics,
            irlume_common::diagnostics::TraceStage::RgbCapture,
            rgb_ms,
        );
        emit_trace_stage_ms(
            diagnostics,
            irlume_common::diagnostics::TraceStage::IrCapture,
            ir_ms,
        );
        let observed_runtime_violation =
            match (&rgb_res, &ir_res, capture_mode.runtime_contract.as_ref()) {
                (Ok((rgb, _)), Ok(Some(ir)), Some(contract)) => {
                    match contract.diagnostic_canonical_trace_events(rgb, ir) {
                        Ok(events) => {
                            for event in events {
                                diagnostics.emit_trace(event);
                            }
                            None
                        }
                        Err(violation) => Some(violation),
                    }
                }
                _ => None,
            };
        // Sequential capture does not depend on the concurrent license, but a
        // valid pair still contributes exact trace evidence. Only concurrent
        // violations participate in the bounded safety fallback decision.
        let runtime_violation = (!sequential)
            .then_some(observed_runtime_violation)
            .flatten();
        let missing_runtime_contract = !sequential
            && rgb_res.is_ok()
            && matches!(ir_res, Ok(Some(_)))
            && capture_mode.runtime_contract.is_none();
        let pair_requires_fallback = concurrent_pair_requires_fallback(
            sequential,
            rgb_res.is_err(),
            ir_res.is_err(),
            recovered_side,
            runtime_violation.is_some() || missing_runtime_contract,
        );
        if held_sessions && pair_requires_fallback {
            let degradation = concurrent_pair_degradation(
                runtime_violation,
                missing_runtime_contract,
                recovered_side,
            );
            emit_capture_fallback(degradation, diagnostics);
            if let Some(context_key) = capture_mode.runtime_key.as_deref() {
                trip_runtime_capture_health(context_key, degradation);
            }
            return Err(CapturePathError::ConcurrentPair(
                irlume_common::Error::Hardware(format!(
                    "held concurrent pair became unusable (rgb: {}; ir: {}; recovered-side: {recovered_side}; runtime: {}); both results must be discarded",
                    rgb_res
                        .as_ref()
                        .err()
                        .map_or("ok".to_owned(), ToString::to_string),
                    ir_res
                        .as_ref()
                        .err()
                        .map_or("ok".to_owned(), ToString::to_string),
                    runtime_violation.map_or_else(
                        || if missing_runtime_contract { "missing contract".to_owned() } else { "ok".to_owned() },
                        |error| error.to_string(),
                    ),
                )),
            ));
        }
        let mut pair_sequential_retried = false;
        if pair_requires_fallback {
            let degradation = concurrent_pair_degradation(
                runtime_violation,
                missing_runtime_contract,
                recovered_side,
            );
            emit_capture_fallback(degradation, diagnostics);
            if let Some(context_key) = capture_mode.runtime_key.as_deref() {
                trip_runtime_capture_health(context_key, degradation);
            }
            capture_mode.demote_operation();
            attempt_plan = capture_mode
                .runtime_contract
                .as_ref()
                .and_then(|runtime| {
                    camera_contract_from_runtime(
                        runtime,
                        capture_mode.qualification_authority.as_ref(),
                        irlume_camera::profile::CaptureSchedule::Sequential,
                    )
                })
                .zip(self.active_plan_versions())
                .and_then(|(camera, versions)| {
                    attempt_plan_from_camera(camera, versions, self.active_model_contracts())
                })
                .ok_or_else(|| {
                    irlume_common::Error::Hardware(
                        "sequential retry attempt plan unavailable; discarding prior evidence"
                            .into(),
                    )
                })?;
            conditioning_selection = attempt_plan.camera().conditioning();
            irlume_common::dlog!(
                "assess: concurrent pair failed; discarding both frames and retrying RGB then IR"
            );
            let (fresh_rgb, fresh_ir) = capture_pair_sequentially(
                || {
                    let started = std::time::Instant::now();
                    let frame = irlume_camera::capture_rgb_denoised_with_progress_and_conditioning(
                        &self.rgb_dev,
                        &progress,
                        conditioning_selection,
                    )?;
                    Ok((frame, started.elapsed().as_millis()))
                },
                || {
                    let started = std::time::Instant::now();
                    let frame =
                        irlume_camera::capture_ir_with_stats_and_progress(&self.ir_dev, &progress)?;
                    Ok((frame, started.elapsed().as_millis()))
                },
            );
            match fresh_rgb {
                Ok((frame, elapsed)) => {
                    rgb_res = Ok(frame);
                    rgb_ms = elapsed;
                }
                Err(error) => {
                    rgb_res = Err(error);
                    rgb_ms = 0;
                }
            }
            match fresh_ir {
                Ok(Some((fresh_ir, fresh_ir_ms))) => {
                    ir_res = Ok(Some(fresh_ir));
                    ir_ms = fresh_ir_ms;
                }
                Ok(None) => {
                    ir_res = Ok(None);
                    ir_ms = 0;
                }
                Err(error) => {
                    ir_res = Err(error);
                    ir_ms = 0;
                }
            }
            pair_sequential_retried = true;
        }
        if pair_sequential_retried {
            emit_trace_stage_ms(
                diagnostics,
                irlume_common::diagnostics::TraceStage::RgbCapture,
                rgb_ms,
            );
            emit_trace_stage_ms(
                diagnostics,
                irlume_common::diagnostics::TraceStage::IrCapture,
                ir_ms,
            );
        }
        // Proactive degradation (#586): a concurrent capture that SUCCEEDED
        // but carried provenance warning signs (sequence gaps, timestamp
        // discontinuity) is the leading indicator the next one will fail
        // outright. The #586 testbed showed gaps compound under USB
        // isochronous load (rounds 1-3 clean, then every round fails). The
        // current auth completes normally (the frame was usable); the NEXT
        // one goes sequential via runtime degradation. Post-capture check,
        // zero streaming overhead.
        if !sequential && !pair_sequential_retried {
            if let (Ok(rgb), Ok(Some(ir))) = (&rgb_res, &ir_res) {
                let rgb_gap = rgb.0.manifest().rate_evidence().sequence_gap() > 0;
                let ir_gap = ir.manifest().rate_evidence().sequence_gap() > 0;
                let ts_disc = !rgb.0.manifest().is_continuous() || !ir.manifest().is_continuous();
                if successful_capture_shows_degradation_signs(rgb_gap, ir_gap, ts_disc) {
                    if let Some(context_key) = capture_mode.runtime_key.as_deref() {
                        trip_runtime_capture_health(
                            context_key,
                            RuntimeDegradation::ContinuityLoss,
                        );
                    }
                    irlume_common::dlog!(
                        "assess: proactive degradation: concurrent capture succeeded \\
                         but showed warning signs (rgb_gap={rgb_gap}, ir_gap={ir_gap}, \\
                         ts_discontinuity={ts_disc}); subsequent captures go sequential"
                    );
                }
            }
        }
        // Retry a hard-failed side alone: with the other stream stopped, a
        // bandwidth-starved capture succeeds; a genuine fault (privacy
        // switch, missing node) fails again with the same error. Logged so a
        // silent retry can't make the timing lines below lie about a slow login.
        let mut rgb_hard_retried = pair_sequential_retried;
        let (mut rgb, mut conditioning_application) = match rgb_res {
            Ok(pair) => pair,
            // Standalone reopen is only safe when THIS call opened one-shot:
            // with held sessions the device queue belongs to the caller's
            // stream, the in-place recovery above already had its attempt,
            // and a reopen here meets our own handle as EBUSY (#187).
            Err(e) if !held_sessions && !pair_sequential_retried => {
                irlume_common::dlog!(
                    "assess: rgb capture retry ({} capture failed: {e})",
                    if sequential {
                        "sequential"
                    } else {
                        "concurrent"
                    }
                );
                rgb_hard_retried = true;
                irlume_camera::capture_rgb_denoised_with_progress_and_conditioning(
                    &self.rgb_dev,
                    &progress,
                    conditioning_selection,
                )?
            }
            Err(e) => return Err(e.into()),
        };
        // `None` = sequential mode skipped IR after an RGB fault; the RGB `?`
        // above already returned, so reaching here with `None` is unreachable,
        // but capture alone rather than unwrap to stay panic-free.
        let ir = match ir_res {
            Ok(Some(f)) => f,
            Ok(None) => irlume_camera::capture_ir_with_stats_and_progress(&self.ir_dev, &progress)?,
            Err(e) if !held_sessions && !pair_sequential_retried => {
                irlume_common::dlog!("assess: ir capture retry (concurrent failed: {e})");
                irlume_camera::capture_ir_with_stats_and_progress(&self.ir_dev, &progress)?
            }
            Err(e) => return Err(e.into()),
        };
        let plan = &attempt_plan;
        let observed_schedule = if sequential || pair_sequential_retried {
            irlume_camera::profile::CaptureSchedule::Sequential
        } else {
            irlume_camera::profile::CaptureSchedule::Concurrent
        };
        let observed_plan = capture_mode
            .runtime_contract
            .as_ref()
            .and_then(|runtime| {
                camera_contract_from_runtime(
                    runtime,
                    capture_mode.qualification_authority.as_ref(),
                    observed_schedule,
                )
            })
            .zip(self.active_plan_versions())
            .and_then(|(camera, versions)| {
                attempt_plan_from_camera(camera, versions, self.active_model_contracts())
            })
            .ok_or_else(|| {
                irlume_common::Error::Hardware(
                    "observed attempt capture plan unavailable; discarding RGB and IR evidence"
                        .into(),
                )
            })?;
        plan.validate_canonical_pair(&observed_plan, conditioning_application, &rgb, &ir)
            .map_err(|violation| {
                irlume_common::Error::Hardware(format!(
                    "attempt capture plan violation ({violation:?}); discarding RGB and IR evidence"
                ))
            })?;
        let rgb_detection_started = std::time::Instant::now();
        let mut rgb_view =
            CanonicalRgbView::try_from_parts(rgb.pixels(), rgb.width(), rgb.height())
                .map_err(model_input_error)?;
        let mut rgb_faces = self.det.detect(&DetectorInput::from_rgb(rgb_view))?;
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::Detection,
            elapsed_us: u64::try_from(rgb_detection_started.elapsed().as_micros())
                .unwrap_or(u64::MAX),
        });
        let mut rgb_top = top_detection(&rgb_faces).cloned();
        irlume_common::dlog!(
            "assess: rgb {}x{} in {rgb_ms}ms, faces={} top-det={:.2}",
            rgb.width(),
            rgb.height(),
            rgb_faces.len(),
            rgb_top.as_ref().map(|f| f.score).unwrap_or(0.0)
        );
        if rgb_top.is_none() {
            rgb_top = self.rescue_detect(rgb_view, "rgb");
        }
        let ir_stats = ir.stats();
        let ir_view = CanonicalGreyView::try_from_parts(ir.pixels(), ir.width(), ir.height())
            .map_err(model_input_error)?;
        let ir_detection_started = std::time::Instant::now();
        let ir_faces = self.det.detect(&DetectorInput::from_grey(ir_view))?;
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::Detection,
            elapsed_us: u64::try_from(ir_detection_started.elapsed().as_micros())
                .unwrap_or(u64::MAX),
        });
        let mut ir_top = top_detection(&ir_faces).cloned();
        irlume_common::dlog!(
            "assess: ir {}x{} in {ir_ms}ms, faces={} top-det={:.2}",
            ir.width(),
            ir.height(),
            ir_faces.len(),
            ir_top.as_ref().map(|f| f.score).unwrap_or(0.0)
        );
        if ir_top.is_none() {
            // rescue_detect needs the mesh path over RGB-shaped data; the
            // grey view expands here only on the (rare) rescue path.
            let expanded = irlume_camera::grey_to_rgb(ir.pixels());
            let iv = CanonicalRgbView::try_from_parts(&expanded, ir.width(), ir.height())
                .map_err(model_input_error)?;
            ir_top = self.rescue_detect(iv, "ir");
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
            let recaptured = irlume_camera::capture_rgb_denoised_with_progress_and_conditioning(
                &self.rgb_dev,
                &progress,
                conditioning_selection,
            )?;
            rgb = recaptured.0;
            conditioning_application = recaptured.1;
            plan.validate_canonical_pair(
                &observed_plan,
                conditioning_application,
                &rgb,
                &ir,
            )
                .map_err(|violation| {
                    irlume_common::Error::Hardware(format!(
                        "recaptured evidence violates attempt plan ({violation:?}); discarding RGB and IR evidence"
                    ))
                })?;
            rgb_view = CanonicalRgbView::try_from_parts(rgb.pixels(), rgb.width(), rgb.height())
                .map_err(model_input_error)?;
            rgb_faces = self.det.detect(&DetectorInput::from_rgb(rgb_view))?;
            rgb_top = top_detection(&rgb_faces).cloned();
            irlume_common::dlog!(
                "assess: rgb (recaptured) {}x{}, faces={} top-det={:.2}",
                rgb.width(),
                rgb.height(),
                rgb_faces.len(),
                rgb_top.as_ref().map(|f| f.score).unwrap_or(0.0)
            );
        }
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::DetectorCount {
            role: irlume_common::diagnostics::CameraRoleLabel::Rgb,
            count: if rgb_top.is_some() {
                u32::try_from(rgb_faces.len()).unwrap_or(u32::MAX).max(1)
            } else {
                0
            },
        });
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::DetectorCount {
            role: irlume_common::diagnostics::CameraRoleLabel::Ir,
            count: if ir_top.is_some() {
                u32::try_from(ir_faces.len()).unwrap_or(u32::MAX).max(1)
            } else {
                0
            },
        });

        // How far apart in time the two frames are. The cross-spectrum cues
        // (same face co-located in RGB and IR, RGB pose judged against the IR
        // face) only mean something if both frames show the SAME moment, and
        // nothing upstream bounds that: the two captures race on separate
        // threads, either side can retry alone, and the dimming self-heal above
        // recaptures RGB after IR is long finished. Measure it, then refuse a
        // pair too stale to compare.
        let skew = rgb.capture_window().gap_to(ir.capture_window());
        irlume_common::dlog!(
            "assess: rgb/ir capture skew {}ms (rgb span {}ms, ir span {}ms)",
            skew.as_millis(),
            rgb.capture_window()
                .end
                .duration_since(rgb.capture_window().start)
                .as_millis(),
            ir.capture_window()
                .end
                .duration_since(ir.capture_window().start)
                .as_millis()
        );
        // Move the RGB detection into the eligibility decision. The IR-only
        // variant has no field in which stale RGB evidence could survive, so
        // all later signal and embedding code can consume only eligible data.
        // The pairing budget is schedule-aware: concurrent captures overlap,
        // so 3s of gap still means something went wrong there. The sequential
        // budget applies whenever the captures ACTUALLY ran as sequential
        // one-shots — the qualified sequential schedule, or a concurrent
        // attempt that degraded to the sequential retry (`pair_sequential_retried`),
        // which re-pays the same one-shot machinery between the bursts. See
        // [`SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW`] for the derivation and
        // ADR-0014 for the security posture.
        let pairing_limit = if sequential || pair_sequential_retried {
            SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW
        } else {
            MAX_CROSS_SPECTRUM_SKEW
        };
        let eligible_pair = eligible_pair_evidence(skew, pairing_limit, rgb_top, ir_top.is_some());
        let (rgb_top, stale_pair_reason) = match eligible_pair {
            EligiblePairEvidence::Paired(rgb_top) => (rgb_top, None),
            EligiblePairEvidence::IrOnly => {
                // Keep the actual detector count above for capture provenance,
                // but make the stale RGB face structurally unavailable before
                // any liveness signal or embedding is derived. Authentication
                // can then enter only the independently gated IR-only path;
                // identify and enrollment remain RGB-primary and cannot consume
                // this frame.
                let reason = format!(
                    "RGB and IR frames are {}ms apart (limit {}ms); discarded stale RGB and using IR-only authentication",
                    skew.as_millis(),
                    pairing_limit.as_millis()
                );
                irlume_common::dlog!("assess: {reason}");
                (None, Some(reason))
            }
            EligiblePairEvidence::Reject => {
                // Uncertain, not Spoof: a stale pair is a capture-quality
                // problem and says nothing about the person. With no usable IR
                // face there is no independent modality to salvage.
                let measurements = irlume_common::diagnostics::TraceMeasurement::new(
                    irlume_common::diagnostics::TraceMetric::CaptureSkewMilliseconds,
                    skew.as_secs_f64() * 1_000.0,
                    Some(pairing_limit.as_secs_f64() * 1_000.0),
                )
                .into_iter()
                .collect();
                diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::Decision {
                    verdict: irlume_common::diagnostics::TraceVerdict::Uncertain,
                    measurements,
                });
                return Ok(Assessment {
                    verdict: Verdict::Uncertain,
                    rgb_frame_mean: irlume_camera::frame_mean(rgb.pixels()),
                    reason: format!(
                        "RGB and IR frames are {}ms apart (limit {}ms); they may not show the same moment",
                        skew.as_millis(),
                        pairing_limit.as_millis()
                    ),
                    embedding: None,
                    ir_embedding: None,
                    signals: Default::default(),
                    ir_center_edge_ratio: 0.0,
                    ir_brightness: 0.0,
                    ir_ambient_share: None,
                    shipped_ir_fake: None,
                    rgb_pad: PadEvidence::NotApplicable,
                    ir_pad: PadEvidence::NotApplicable,
                    sequential_pair: false, // rejected pair: no pair survives
                });
            }
        };
        if stale_pair_reason.is_some() {
            let measurements = irlume_common::diagnostics::TraceMeasurement::new(
                irlume_common::diagnostics::TraceMetric::CaptureSkewMilliseconds,
                skew.as_secs_f64() * 1_000.0,
                Some(pairing_limit.as_secs_f64() * 1_000.0),
            )
            .into_iter()
            .collect();
            diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::Decision {
                verdict: irlume_common::diagnostics::TraceVerdict::Uncertain,
                measurements,
            });
        }

        let fbox = |f: &Detection, w: u32, h: u32| irlume_liveness::FaceBox {
            cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
            cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
            score: f.score,
        };
        let ir_brightness = ir_top
            .as_ref()
            .map(|f| mean_in_bbox(ir.pixels(), ir.width(), ir.height(), &f.bbox))
            .unwrap_or(0.0);
        let ir_center_edge_ratio = ir_top
            .as_ref()
            .map(|f| center_edge_ratio(ir.pixels(), ir.width(), ir.height(), &f.bbox))
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
            .map(|f| rgb_luma_stats(rgb.pixels(), rgb.width(), rgb.height(), &f.bbox).0)
            .unwrap_or(0.0);
        let signals = Signals {
            rgb_face: rgb_top.as_ref().map(|f| fbox(f, rgb.width(), rgb.height())),
            ir_face: ir_top.as_ref().map(|f| fbox(f, ir.width(), ir.height())),
            ir_face_brightness: ir_brightness,
            ir_center_edge_ratio,
            // Same RAW-frame rule as `ir_saturated_frac` below, for the same
            // reason: the ceiling test has to see the samples that actually
            // railed, and subtraction moves a 255 to 254 (#238 review).
            ir_eye_glint: eye_glint_of(
                ir.saturation_pixels(),
                ir.width(),
                ir.height(),
                ir_top.as_ref().map(|f| &f.landmarks),
                ir_stats.white_level,
            ),
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            ir_ambient: ir_stats.ambient_mean,
            // From the IR frame, because the IR cues are measured there.
            face_frac: face_frac_of(ir_top.as_ref().map(|f| &f.bbox), ir.width()),
            // Measured on the raw gate frame retained by canonical evidence.
            ir_saturated_frac: saturated_frac_of(
                ir.saturation_pixels(),
                ir.width(),
                ir.height(),
                ir_top.as_ref().map(|f| &f.bbox),
                ir_stats.white_level,
            ),
            ir_persistent_saturated_frac: ir_stats.persistent_saturated_frac,
            // Whether the FORMAT could be measured, which is not the same
            // question as whether this capture produced a number: the call
            // above also yields None when no face was found (#358).
            ir_ceiling_known: ir_stats.white_level.is_some(),
            rgb_face_brightness: rgb_brightness,
            rgb_moire_score: 0.0,
            rgb_specular_frac: 0.0,
        };
        let liveness_started = std::time::Instant::now();
        let (verdict, _cues, reason) = match stale_pair_reason {
            Some(reason) => (Verdict::Uncertain, Default::default(), reason),
            None => self.gate.evaluate(&signals),
        };
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
        // Shipped IR PAD cue (ADR-0013, default-on), deny-only on the lit IR
        // frame. Scored even when the gate did not say Live so the dark path
        // can reuse it below.
        let ir_pad = match (ir_top.as_ref(), self.pad_ir.as_mut()) {
            (Some(_), None) => PadEvidence::Unavailable,
            (Some(f), Some(pad)) => match pad.p_fake(&FlirIrPadInput::new(ir_view, f.bbox)) {
                Ok(p) if p.is_finite() => PadEvidence::Score(p),
                Ok(_) => PadEvidence::InferenceFailed,
                Err(e) => {
                    irlume_common::dlog!("pad-ir: inference failed ({e})");
                    PadEvidence::InferenceFailed
                }
            },
            (None, _) => PadEvidence::NotApplicable,
        };
        let shipped_ir_fake = match ir_pad {
            PadEvidence::Score(p) => Some(p),
            _ => None,
        };
        let (verdict, reason) = if pad_downgrades(verdict, shipped_ir_fake, IR_PAD_THRESHOLD) {
            let pf = shipped_ir_fake.unwrap_or(1.0);
            irlume_common::dlog!(
                "pad-ir: p_fake {pf:.3} >= {IR_PAD_THRESHOLD:.2}; downgrading Live to Spoof"
            );
            (
                Verdict::Spoof,
                "IR PAD cue flags a spoof; use your password".into(),
            )
        } else {
            (verdict, reason)
        };
        // Shipped ViT RGB PAD cue (ADR-0013, default-on): score the RGB face
        // only on frames the (already post-IR-PAD) verdict still calls Live —
        // deny-only cues never need to run on frames that already deny, and
        // the 268ms N100 inference is not free (the plan: consent-watch-
        // pipelined, Live frames only).
        let rgb_pad = match (verdict, rgb_top.as_ref(), self.vit_pad.as_mut()) {
            (Verdict::Live, Some(_), None) => PadEvidence::Unavailable,
            (Verdict::Live, Some(f), Some(pad)) => {
                match pad.p_spoof(&VitRgbPadInput::new(rgb_view, f.bbox)) {
                    Ok(p) if p.is_finite() => PadEvidence::Score(p),
                    Ok(_) => PadEvidence::InferenceFailed,
                    Err(e) => {
                        irlume_common::dlog!("pad-vit: inference failed ({e})");
                        PadEvidence::InferenceFailed
                    }
                }
            }
            _ => PadEvidence::NotApplicable,
        };
        let (verdict, reason) = match rgb_pad {
            PadEvidence::Score(p) => {
                irlume_common::dlog!("pad-vit: p_spoof {p:.3}");
                if self.vit_pad_votes_deny(p) {
                    irlume_common::dlog!(
                        "pad-vit: 5-frame median >= {VIT_PAD_THRESHOLD:.2}; downgrading Live to Spoof"
                    );
                    (
                        Verdict::Spoof,
                        "RGB PAD cue flags a spoof; use your password".into(),
                    )
                } else {
                    (verdict, reason)
                }
            }
            _ => (verdict, reason),
        };
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::Liveness,
            elapsed_us: u64::try_from(liveness_started.elapsed().as_micros()).unwrap_or(u64::MAX),
        });
        diagnostics.emit_trace(irlume_liveness::diagnostic_trace_decision(
            verdict, &signals,
        ));

        let embedding = match &rgb_top {
            Some(f) => {
                let input =
                    ArcFaceInput::from_rgb(rgb_view, &f.landmarks).map_err(model_input_error)?;
                Some(self.emb.embed_tta(&input)?) // TTA flip-average (RGB only; cuts FRR)
            }
            None => None,
        };
        // IR-face embedding (for dark operation): align + embed the IR image,
        // then apply the domain-adaptation adapter if loaded.
        let ir_embedding = match &ir_top {
            Some(f) => {
                let input =
                    ArcFaceInput::from_grey(ir_view, &f.landmarks).map_err(model_input_error)?;
                let raw = self.emb.embed(&input)?;
                Some(match &mut self.ir_adapter {
                    Some(a) => a.apply(&raw)?,
                    None => raw.to_vec(),
                })
            }
            None => None,
        };
        Ok(Assessment {
            verdict,
            reason,
            embedding,
            rgb_frame_mean: irlume_camera::frame_mean(rgb.pixels()),
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
            shipped_ir_fake,
            rgb_pad,
            ir_pad,
            // Paired under the schedule-aware budget AND beyond the concurrent
            // ceiling: the bursts ran as separated one-shots (ADR-0014). Such
            // pairs defer the RGB-primary grant (rgb_primary_grant_admissible).
            sequential_pair: pair_admitted_sequentially(skew, rgb_top.is_some()),
        })
    }

    /// Capture a temporal IR sequence and record per-frame HEAD POSE (pitch and
    /// yaw from the DETECTOR's 5-point landmarks) for the head-nod consent
    /// gesture. Needs only the detector, not the FaceMesh, so it works across
    /// head angles and in IR-only light. A frame with no detected face carries
    /// `None` pose.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn capture_pose_samples(
        &mut self,
        samples: usize,
    ) -> irlume_common::Result<Vec<irlume_liveness::PoseSample>> {
        let frames = irlume_camera::capture_ir_sequence(&self.ir_dev, samples, 1)?;
        let mut out = Vec::with_capacity(frames.len());
        for (i, f) in frames.iter().enumerate() {
            let bri = f.data.iter().map(|&p| p as f32).sum::<f32>() / f.data.len().max(1) as f32;
            let view = CanonicalGreyView::try_from_parts(&f.data, f.width, f.height)
                .map_err(model_input_error)?;
            let (mut pitch_frac, mut yaw_signed) = (None, None);
            let faces = self.det.detect(&DetectorInput::from_grey(view))?;
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

    /// Process one decoded IR frame into the head-pose sample used by the
    /// rolling consent watch. This needs only the face detector.
    fn frame_to_head_pose(
        &mut self,
        frame: &irlume_camera::Frame,
        idx: usize,
    ) -> irlume_common::Result<irlume_liveness::PoseSample> {
        let bri =
            frame.data.iter().map(|&p| p as f32).sum::<f32>() / frame.data.len().max(1) as f32;
        let view = CanonicalGreyView::try_from_parts(&frame.data, frame.width, frame.height)
            .map_err(model_input_error)?;
        let (mut pitch_frac, mut yaw_signed) = (None, None);
        let faces = self.det.detect(&DetectorInput::from_grey(view))?;
        if let Some(t) = top_detection(&faces) {
            let pose = irlume_vision::head_pose(&t.landmarks);
            pitch_frac = Some(pose.pitch_frac);
            yaw_signed = Some(pose.yaw_signed);
        }
        Ok(irlume_liveness::PoseSample {
            idx,
            pitch_frac,
            yaw_signed,
            bri,
        })
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
    fn early_consent_watch(&mut self) -> irlume_common::Result<HeadConsentVerdict> {
        if !self.ir_available {
            return Ok(HeadConsentVerdict::NoGesture);
        }
        let verdict = self.head_consent_watch(Self::consent_budget() / 3)?;
        irlume_common::dlog!(
            "consent: pre-match watch {}",
            match verdict {
                HeadConsentVerdict::Approve => "saw approval",
                HeadConsentVerdict::Decline => "saw decline",
                HeadConsentVerdict::NoGesture => {
                    "saw nothing yet; will watch again after the match"
                }
            }
        );
        Ok(verdict)
    }

    /// Rolling head-consent watch: drive a held-open IR stream, process each
    /// frame, and return as soon as a nod or shake is seen. Bounded by
    /// `max_frames`.
    fn head_consent_watch(
        &mut self,
        max_frames: usize,
    ) -> irlume_common::Result<HeadConsentVerdict> {
        // Re-check the accumulated gestures every few frames (not every frame:
        // the detectors need a small window, and running them per frame is waste).
        const CHECK_EVERY: usize = 6;
        let ir_dev = self.ir_dev.clone();
        let mut poses: Vec<irlume_liveness::PoseSample> = Vec::new();
        let mut err: Option<irlume_common::Error> = None;
        let stream_verdict = irlume_camera::capture_ir_streaming(&ir_dev, max_frames, |sf| {
            // Stop the moment the work is no longer wanted: the client that asked
            // for it has gone (its polkit dialog closed, so the daemon's connection
            // thread asked us to stop), or a new authentication needs the camera.
            //
            // Checked HERE, per frame, because this loop is where an authentication
            // spends its seconds: the watch runs for the whole consent budget, and
            // the only other stop checks sit between whole captures on the ENROLMENT
            // path, so nothing was watching during the one phase a user actually
            // waits through. Measured 2026-08-11: cancelling a polkit prompt left
            // the IR emitter lit and this loop streaming for the rest of the budget.
            // A frame boundary is safe: nothing is written mid-stream, and setting
            // `err` makes the whole request end rather than reporting a false
            // "no gesture" that a caller might treat as a real refusal.
            if self.should_stop() {
                err = Some(irlume_common::Error::Preempted(
                    "the request was cancelled before a consent gesture arrived".into(),
                ));
                return std::ops::ControlFlow::Break(HeadConsentVerdict::NoGesture);
            }
            let idx = poses.len();
            match self.frame_to_head_pose(&sf.frame, idx) {
                Ok(pose) => poses.push(pose),
                Err(e) => {
                    err = Some(e);
                    return std::ops::ControlFlow::Break(HeadConsentVerdict::NoGesture);
                }
            }
            if !poses.len().is_multiple_of(CHECK_EVERY) {
                return std::ops::ControlFlow::Continue(());
            }
            let verdict = head_consent_from_poses(&poses);
            match verdict {
                HeadConsentVerdict::Approve | HeadConsentVerdict::Decline => {
                    irlume_common::dlog!(
                        "consent: head classifier returned {verdict:?} at frame {}",
                        poses.len()
                    );
                    return std::ops::ControlFlow::Break(verdict);
                }
                HeadConsentVerdict::NoGesture => {}
            }
            std::ops::ControlFlow::Continue(())
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        // Resolve the take. A stream verdict is terminal. Only a budget-exhausted
        // `None` consults the completed take, to catch a gesture that finished
        // inside the trailing poses the in-loop cadence never checked
        // (measured 2026-08-04, #101: two 20-pose windows at pitch_range
        // 0.077-0.085 against the 0.075 floor, last in-loop check at pose 18; one
        // cost a real trial its release).
        let verdict = resolve_head_consent(stream_verdict, || head_consent_from_poses(&poses));
        if stream_verdict.is_none() && verdict != HeadConsentVerdict::NoGesture {
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
            let (_, ev) = irlume_liveness::detect_head_gesture_with_evidence(&poses);
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
                match verdict {
                    HeadConsentVerdict::Approve => "GESTURE ACCEPTED",
                    HeadConsentVerdict::Decline => "GESTURE DECLINED",
                    HeadConsentVerdict::NoGesture => "no gesture",
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
        Ok(verdict)
    }

    /// Apply the purpose's head-consent gate on top of the match, just before
    /// granting.
    ///
    /// One gate lives here: the DELIBERATE head gesture, required by
    /// [`AuthenticationPurpose::AppConsent`] (polkit), by
    /// elevation services under [`AuthenticationPurpose::Verify`], and by
    /// [`AuthenticationPurpose::CredentialRelease`] when the user has opted in
    /// (it defaults off). A gesture records intent, not liveness; automatic PAD
    /// remains separate.
    ///
    /// Every failure downgrades to a non-grant with an Uncertain-style reason, so
    /// PAM cascades to the typed password; nothing here can lock a user out. When
    /// IR is missing, the gate fails closed to the password rather than hand back
    /// a grant weaker than what was asked for.
    fn challenge_if_required(
        &mut self,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        outcome: Outcome,
    ) -> irlume_common::Result<Outcome> {
        if !outcome.granted {
            return Ok(outcome);
        }
        if let Some(policy) = blocking_head_consent_policy(purpose, service) {
            return Ok(Outcome {
                granted: false,
                live: outcome.live,
                score: outcome.score,
                reason: policy.instruction("approve"),
                kind: OutcomeKind::OtherDeny,
            });
        }
        if purpose.demands_gesture(service) {
            let verdict = self.head_consent_before_match;
            return self.consent_gesture_gate(outcome, verdict);
        }
        // No gesture is demanded here. Releasing the keyring with no nod is the
        // DEFAULT now (a greeter cold login and logout release after the face
        // match; the gesture is intent, not the anti-print layer, so there is
        // nothing to warn about on every release). The consent gesture gate
        // above covers the AppConsent and CredentialRelease paths when their
        // policy asks for it, and the Verify path is gated per service.
        Ok(outcome)
    }

    /// The forced consent gate: require a DELIBERATE head nod before approving a
    /// prompt. FAILS CLOSED (PAM cascades to the password) when no nod is seen.
    fn consent_gesture_gate(
        &mut self,
        outcome: Outcome,
        before_match: HeadConsentVerdict,
    ) -> irlume_common::Result<Outcome> {
        let (live, score) = (outcome.live, outcome.score);
        match before_match {
            HeadConsentVerdict::Approve => {
                irlume_common::dlog!("consent: approval already seen before the match");
                return Ok(outcome);
            }
            HeadConsentVerdict::Decline => {
                irlume_common::dlog!("consent: head shake cancelled the request");
                return Ok(Outcome::gesture_declined(live, score));
            }
            HeadConsentVerdict::NoGesture => {}
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
        match self.head_consent_watch(max_frames)? {
            HeadConsentVerdict::Approve => {
                irlume_common::dlog!("consent: approval seen after the match");
                Ok(outcome)
            }
            HeadConsentVerdict::Decline => {
                irlume_common::dlog!("consent: head shake cancelled the request");
                Ok(Outcome::gesture_declined(live, score))
            }
            HeadConsentVerdict::NoGesture => Ok(deny("keep nodding your head to approve")),
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
        self.authenticate_for_with_diagnostics(
            user,
            service,
            AuthenticationPurpose::for_service(service),
            &(),
        )
    }

    /// [`Self::authenticate`] while publishing bounded, structurally
    /// share-safe capture decisions to the caller-owned operation scope.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn authenticate_with_diagnostics(
        &mut self,
        user: &str,
        service: Option<&str>,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        self.authenticate_for_with_diagnostics(
            user,
            service,
            AuthenticationPurpose::for_service(service),
            diagnostics,
        )
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
    pub fn authenticate_for(
        &mut self,
        user: &str,
        service: Option<&str>,
        purpose: AuthenticationPurpose,
    ) -> irlume_common::Result<Outcome> {
        self.authenticate_for_with_diagnostics(user, service, purpose, &())
    }

    /// [`Self::authenticate_for`] while publishing bounded, structurally
    /// share-safe capture decisions to the caller-owned operation scope.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn authenticate_for_with_diagnostics(
        &mut self,
        user: &str,
        service: Option<&str>,
        purpose: AuthenticationPurpose,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Outcome> {
        self.head_consent_before_match = HeadConsentVerdict::NoGesture;
        // Fresh ViT PAD vote ring per authentication: votes must not mix
        // presentations across requests (ADR-0013 protocol).
        self.vit_scores.clear();
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
        //
        // It leaves the critical path HERE, for the case that has a critical
        // path to leave: an ENCRYPTED store, whose unseal costs 2.7s quiet /
        // 18.97s contended on a discrete TPM. A plaintext store loads with no
        // TPM at all, so it stays synchronous and keeps the historical
        // deny-before-camera precedence for every policy check below (tests
        // and plaintext hosts see identical behavior to before). For an
        // encrypted store the full load runs on a helper thread CONCURRENTLY
        // with the camera lease, stream arming, delivered-rate establishment
        // and the consent watch below (>=5s of camera-bound work in
        // concurrent mode), joined before the first enrollment-dependent
        // decision. The one precedence change: on an encrypted store whose
        // camera path ALSO fails hard, the hardware error now precedes the
        // empty-scans/binding deny lines — both end at the password, so the
        // user-visible outcome is unchanged. A panic inside the loader maps
        // to an error (password fallback), never a daemon crash.
        let load_started = std::time::Instant::now();
        let mut loader = match irlume_core::storage::store_is_encrypted(user)? {
            // No file at all: the instant deny, before anything else wakes.
            None => {
                return Ok(Outcome::deny(
                    OutcomeKind::OtherDeny,
                    format!("'{user}' is not enrolled"),
                ));
            }
            // Plaintext: cheap JSON load, synchronous, old precedence.
            Some(false) => None,
            // Encrypted: the TPM unseal is the expensive part — defer it
            // into the overlap window. A channel, not a JoinHandle: the
            // receiver can wait with a timeout at the join (a wedged unseal
            // must not pin the camera lease past the auth deadline), and a
            // dropped sender reports a loader panic as a disconnect.
            Some(true) => Some({
                let loader_user = user.to_string();
                let (tx, rx) = std::sync::mpsc::channel::<EnrollmentLoad>();
                std::thread::Builder::new()
                    .name("irlume-enrollment-load".into())
                    .spawn(move || {
                        let _ = tx.send(irlume_core::storage::load(&loader_user));
                    })
                    .map_err(|e| irlume_common::Error::Io(e.to_string()))?;
                rx
            }),
        };
        // The synchronous-path enrollment (plaintext stores). The encrypted
        // path resolves `enr` at the join below, after camera setup.
        let loader_was_async = loader.is_some();
        let sync_enr = if loader.is_none() {
            match irlume_core::storage::load(user)? {
                Some(enr) => match self.enrollment_policy_refusal(user, &enr) {
                    Some(outcome) => return Ok(outcome),
                    None => Some(enr),
                },
                None => {
                    return Ok(Outcome::deny(
                        OutcomeKind::OtherDeny,
                        format!("'{user}' is not enrolled"),
                    ));
                }
            }
        } else {
            None
        };
        if let Some(policy) = blocking_head_consent_policy(purpose, service) {
            finish_loader(&mut loader);
            return Ok(Outcome::deny(
                OutcomeKind::OtherDeny,
                policy.instruction("approve"),
            ));
        }
        let (rgb_dev, ir_dev) = (self.rgb_dev.clone(), self.ir_dev.clone());
        let endpoints: Vec<&str> = if self.ir_available {
            vec![rgb_dev.as_str(), ir_dev.as_str()]
        } else {
            vec![rgb_dev.as_str()]
        };
        // One authentication owns its physical camera set from the first
        // consent frame through the final grace-window retry.  Keeping this
        // lease across sequential fallbacks is deliberate: otherwise another
        // operation can interleave between consent and matching.
        let camera_operation = match irlume_camera::lease::acquire_camera_operation(
            &endpoints,
            irlume_camera::lease::CameraOperationKind::Authentication,
            std::time::Duration::from_secs(2),
        ) {
            Ok(op) => op,
            Err(error) => {
                finish_loader(&mut loader);
                return Err(irlume_common::Error::Hardware(error.to_string()));
            }
        };

        // Watch for the consent gesture BEFORE the first capture, so a user who
        // nods when the greeter asks is not ignored for the seconds it takes to
        // capture and match a face. Once per authentication, never per retry: a
        // grace window can hold several attempts and none of them should re-ask
        // for a gesture already given.
        if purpose.demands_gesture(service) {
            let verdict = match Self::run_camera_operation(&camera_operation, || {
                self.early_consent_watch()
            }) {
                Ok(v) => v,
                Err(e) => {
                    finish_loader(&mut loader);
                    return Err(e);
                }
            };
            self.head_consent_before_match = verdict;
            // A head-shake during the pre-match watch is an explicit decline.
            // Close the request now: do not spend the capture and match only to
            // deny after a second post-match watch, and do not let a later cue
            // override the decline.
            if self.head_consent_before_match == HeadConsentVerdict::Decline {
                irlume_common::dlog!("consent: head shake before the match cancelled the request");
                // A pre-match shake never reached matching: no live face, no score.
                self.head_consent_before_match = HeadConsentVerdict::NoGesture;
                finish_loader(&mut loader);
                return Ok(Outcome::gesture_declined(false, 0.0));
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
        // Declared in reverse drop order: the sessions borrow from `held_cams`, so
        // Rust drops the sessions first and the cameras after.
        //
        // The sessions are passed to `authenticate_once` AS THE OWNING OPTIONS,
        // not as borrows of them. That is the whole point: the match path
        // releases the camera before the consent watch opens its own IR stream,
        // and it can only do that by dropping the session itself. Handing down
        // `&mut Option<(&mut RgbSession, &mut IrSession)>` made every release
        // site drop a pair of REFERENCES while these two kept the buffer queue,
        // so the watch's S_FMT and REQBUFS hit EBUSY against this very process:
        // the self-collision #187 diagnosed, reintroduced by #346 and caught by
        // the release audit before it shipped.
        let camera_open_started = std::time::Instant::now();
        let resolved_cams = match (
            camera_operation.open_rgb(&rgb_dev),
            camera_operation.open_ir(&ir_dev),
        ) {
            (Ok(rgb), Ok(ir)) => Some((rgb, ir)),
            _ => None,
        };
        diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
            stage: irlume_common::diagnostics::TraceStage::CameraOpen,
            elapsed_us: u64::try_from(camera_open_started.elapsed().as_micros())
                .unwrap_or(u64::MAX),
        });
        let mut capture_mode = resolved_cams
            .as_ref()
            .map_or_else(unavailable_capture_mode_selection, |(rgb, ir)| {
                capture_mode_selection_with_diagnostics(rgb, ir, diagnostics)
            });
        emit_capture_context(&capture_mode, self.ir_available, diagnostics);
        if resolved_cams.is_none() && self.ir_available {
            diagnostics.emit_share_safe(
                irlume_common::diagnostics::ShareSafeEventKind::CaptureFallback {
                    reason: irlume_common::diagnostics::RuntimeViolationLabel::PairOpenFailure,
                },
            );
        }
        let sequential = capture_mode.is_sequential();
        let held_cams = cameras_for_held_pair(
            sequential || capture_mode.camera_contract.is_none(),
            resolved_cams,
        );
        let mut held_rgb: Option<irlume_camera::RgbSession<'_>> = None;
        let mut held_ir: Option<irlume_camera::IrSession<'_>> = None;
        if let (Some((cam_r, cam_i)), true, Some(camera_contract)) = (
            &held_cams,
            !sequential && self.ir_available,
            capture_mode.camera_contract.as_ref(),
        ) {
            let progress = self.capture_progress();
            let conditioning = camera_contract.conditioning();
            // The camera pair is declared before the sessions so it outlives them.
            let arm_started = std::time::Instant::now();
            let armed = arm_pair_transactionally(
                || cam_r.session_with_selected_conditioning(&progress, conditioning),
                || cam_i.session_with_progress(&progress),
            );
            diagnostics.emit_trace(irlume_common::diagnostics::TraceEventKind::StageTiming {
                stage: irlume_common::diagnostics::TraceStage::StreamArm,
                elapsed_us: u64::try_from(arm_started.elapsed().as_micros()).unwrap_or(u64::MAX),
            });
            match armed {
                Ok((mut rs, mut is)) => {
                    // Establish the delivered-rate windows for the HELD PAIR up
                    // front, draining both streams concurrently. A failure drops
                    // both streams and selects the one-at-a-time path below.
                    let rate_started = std::time::Instant::now();
                    let rate = irlume_camera::establish_pair_rate(&mut rs, &mut is);
                    diagnostics.emit_trace(
                        irlume_common::diagnostics::TraceEventKind::StageTiming {
                            stage: irlume_common::diagnostics::TraceStage::RateEstablishment,
                            elapsed_us: u64::try_from(rate_started.elapsed().as_micros())
                                .unwrap_or(u64::MAX),
                        },
                    );
                    match rate {
                        Ok(()) => {
                            held_rgb = Some(rs);
                            held_ir = Some(is);
                        }
                        Err(error) => {
                            irlume_common::dlog!(
                                "auth: held pair could not establish delivered-rate evidence \
                                 ({error}); dropping both streams and retrying one-at-a-time"
                            );
                            emit_capture_fallback(
                                RuntimeDegradation::PairRateEstablishmentFailure,
                                diagnostics,
                            );
                            demote_after_pair_rate_failure(&mut capture_mode);
                        }
                    }
                }
                Err(error) => {
                    irlume_common::dlog!(
                        "auth: held pair could not arm transactionally ({error}); \
                         retrying one-at-a-time"
                    );
                    emit_capture_fallback(RuntimeDegradation::PairArmFailure, diagnostics);
                    demote_after_pair_arm_failure(&mut capture_mode);
                }
            }
        }
        // Join the enrollment loader. Everything between the spawn and HERE —
        // camera lease, consent watch, stream arming, delivered-rate
        // establishment — is the overlap window the TPM unseal ran inside;
        // on every measured host that window exceeds the unseal (2.7s quiet),
        // so the load costs the auth path nothing. First enrollment-dependent
        // decision happens after this join, before any capture is spent.
        // The wait is bounded by the authentication deadline: a wedged unseal
        // (stuck tpmrm, or a user-state flock held by a wedged sibling) must
        // not pin the camera lease forever — on timeout the auth fails closed
        // to the password and the detached loader releases its locks whenever
        // it finishes. A ready result is returned even at zero remaining
        // time, so a healthy load that already finished is never mistaken
        // for a timeout. The arms live in [`resolve_loader`].
        let enr = match loader.take() {
            Some(rx) => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                match resolve_loader(rx.recv_timeout(remaining)) {
                    Ok(enr) => enr,
                    Err(LoaderExit::NotEnrolled) => {
                        return Ok(Outcome::deny(
                            OutcomeKind::OtherDeny,
                            format!("'{user}' is not enrolled"),
                        ));
                    }
                    Err(LoaderExit::Fallback(e)) => return Err(e),
                }
            }
            None => match sync_enr {
                Some(enr) => enr,
                // Unreachable by construction (the sync path resolves
                // sync_enr or returns early); a deny rather than a panic so
                // a future edit cannot crash the daemon here.
                None => {
                    return Ok(Outcome::deny(
                        OutcomeKind::OtherDeny,
                        format!("'{user}' is not enrolled"),
                    ));
                }
            },
        };
        irlume_common::dlog!(
            "auth: enrollment load took {:?} ({})",
            load_started.elapsed(),
            if loader_was_async {
                "overlapped with camera setup"
            } else {
                "plaintext, synchronous"
            }
        );
        if loader_was_async {
            if let Some(outcome) = self.enrollment_policy_refusal(user, &enr) {
                return Ok(outcome);
            }
        }
        if held_rgb.is_none() || held_ir.is_none() {
            drop(held_rgb);
            drop(held_ir);
            drop(held_cams);
            let mut no_rgb = None;
            let mut no_ir = None;
            let mut costliest_attempt = std::time::Duration::ZERO;
            return self
                .authentication_attempt_loop(
                    &enr,
                    purpose,
                    service,
                    deadline,
                    window,
                    &mut no_rgb,
                    &mut no_ir,
                    &capture_mode,
                    &camera_operation,
                    diagnostics,
                    &mut costliest_attempt,
                )
                .0;
        }
        let mut costliest_attempt = std::time::Duration::ZERO;
        let (first_result, held_pair_failed) = self.authentication_attempt_loop(
            &enr,
            purpose,
            service,
            deadline,
            window,
            &mut held_rgb,
            &mut held_ir,
            &capture_mode,
            &camera_operation,
            diagnostics,
            &mut costliest_attempt,
        );
        if !held_pair_failed {
            return first_result;
        }
        let error = first_result.expect_err("held-pair failure must return an error");
        // The sequential fallback re-opens both cameras: ~3.1 s of machinery
        // per stream, ~7 s for the pair (the loop comment below derives it).
        // Bound its FIRST attempt the same way the loop bounds retries: when
        // the cost of that attempt cannot finish before the deadline, do not
        // start it — the camera is released and the password fallback answers
        // inside the window instead of the lease overrunning mid-capture
        // (ADR-0014). The estimator is the observed costliest attempt raised
        // to that floor: the concurrent loop's own attempts (~1 s) would
        // never bound a ~7 s sequential reopen.
        let fallback_cost = costliest_attempt.max(SEQUENTIAL_PAIR_ATTEMPT_COST);
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining < fallback_cost {
            irlume_common::dlog!(
                "grace: sequential fallback skipped ({}ms left, fallback cost {}ms); settling",
                remaining.as_millis(),
                fallback_cost.as_millis()
            );
            return Err(error);
        }
        drop(held_rgb);
        drop(held_ir);
        drop(held_cams);
        demote_after_concurrent_capture_failure(&mut capture_mode);
        irlume_common::dlog!(
            "auth: {error}; dropped both held streams and camera handles; retrying RGB then IR"
        );
        let mut no_rgb = None;
        let mut no_ir = None;
        // Seed with the first loop's costliest attempt so the fallback's own
        // retry decisions account for what this deadline has already spent.
        self.authentication_attempt_loop(
            &enr,
            purpose,
            service,
            deadline,
            window,
            &mut no_rgb,
            &mut no_ir,
            &capture_mode,
            &camera_operation,
            diagnostics,
            &mut costliest_attempt,
        )
        .0
    }

    /// The stable situation label of the final FAILED authentication
    /// attempt (#616 step 3), for the daemon to carry on `AuthResult`:
    /// `None` when the final attempt granted or nothing ran, so a stale
    /// label can never reach a prompt. Read-only reporting; gates nothing,
    /// scores nothing, moves no bar.
    pub fn last_attempt_situation_label(&self) -> Option<&'static str> {
        self.last_attempt_situation.map(attempt_situation_label)
    }

    #[allow(clippy::too_many_arguments)]
    fn authentication_attempt_loop(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        deadline: std::time::Instant,
        window: u64,
        held_rgb: &mut Option<irlume_camera::RgbSession<'_>>,
        held_ir: &mut Option<irlume_camera::IrSession<'_>>,
        capture_mode: &CaptureModeSelection,
        camera_operation: &irlume_camera::lease::CameraOperationSession,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
        costliest_attempt: &mut std::time::Duration,
    ) -> (irlume_common::Result<Outcome>, bool) {
        let mut attempt = 0_u32;
        // The costliest attempt so far (caller-seeded: the sequential fallback
        // starts with the concurrent loop's observed worst). A retry that
        // cannot FINISH before the deadline would overrun mid-capture —
        // holding the camera past the window for a result that can never be
        // used. The costliest (not latest) attempt is the estimator because a
        // retry can be far slower than the attempt before it: the
        // held-concurrent pair costs ~1s, and its sequential fallback re-opens
        // both cameras at ~7s.
        loop {
            attempt += 1;
            let mut held_pair_failed = false;
            let attempt_started = std::time::Instant::now();
            let attempt_result = Self::run_camera_operation(camera_operation, || {
                self.authenticate_once(
                    enr,
                    purpose,
                    service,
                    held_rgb,
                    held_ir,
                    AuthenticationCaptureContext {
                        mode: Some(capture_mode),
                        operation: Some(camera_operation),
                        held_pair_failed: Some(&mut held_pair_failed),
                        diagnostics,
                    },
                )
            });
            let out = match attempt_result {
                Ok(out) => out,
                Err(error) => {
                    self.head_consent_before_match = HeadConsentVerdict::NoGesture;
                    return (Err(error), held_pair_failed);
                }
            };
            *costliest_attempt = (*costliest_attempt).max(attempt_started.elapsed());
            // One situation line per FAILED attempt (#616 step 2), including
            // attempts the grace window retries: the "why did it fail" a
            // person reads in `irlume logs`, from the facts this attempt
            // measured. A granted attempt says nothing.
            if !out.granted {
                irlume_common::dlog!(
                    "{}",
                    attempt_situation_line(out.kind, out.score, &self.last_attempt_facts)
                );
                // #616 step 3: the wire reads what the journal just said.
                // Same guard, same facts: the prompt situation can never
                // disagree with the journaled one.
                self.last_attempt_situation =
                    Some(auth_attempt_situation(out.kind, &self.last_attempt_facts));
            } else {
                // A granted final attempt clears the label, so a later
                // reader can never prompt off a stale failure.
                self.last_attempt_situation = None;
            }
            let expired = std::time::Instant::now() >= deadline;
            let retry_wont_fit = !expired
                && presence_retryable(&out)
                && deadline.saturating_duration_since(std::time::Instant::now())
                    < *costliest_attempt;
            if retry_wont_fit {
                irlume_common::dlog!(
                    "grace: retry skipped ({}ms left, costliest attempt {}ms); settling",
                    deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .as_millis(),
                    costliest_attempt.as_millis()
                );
            }
            if !presence_retryable(&out) || expired || retry_wont_fit {
                if attempt > 1 {
                    irlume_common::dlog!(
                        "grace: settled after {attempt} attempts ({}ms window)",
                        window
                    );
                }
                self.head_consent_before_match = HeadConsentVerdict::NoGesture;
                return (Ok(out), false);
            }
            irlume_common::dlog!(
                "grace: attempt {attempt} found no usable face ({}); retrying within window",
                out.reason
            );
            self.note_capture_boundary();
        }
    }

    fn authenticate_once(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        purpose: AuthenticationPurpose,
        service: Option<&str>,
        // The OWNING options, so a release site can actually drop the sessions
        // and hand the camera back; see the declaration comment in
        // `authenticate_for`.
        held_rgb: &mut Option<irlume_camera::RgbSession<'_>>,
        held_ir: &mut Option<irlume_camera::IrSession<'_>>,
        capture: AuthenticationCaptureContext<'_>,
    ) -> irlume_common::Result<Outcome> {
        let AuthenticationCaptureContext {
            mode,
            operation,
            held_pair_failed,
            diagnostics,
        } = capture;
        let assessment = if !self.ir_available {
            self.assess_rgb_only_with_diagnostics(diagnostics)
                .map_err(CapturePathError::from)
        } else if let (Some(rs), Some(is), Some(operation)) =
            (held_rgb.as_mut(), held_ir.as_mut(), operation)
        {
            self.assess_full_with(Some((rs, is)), mode, operation, diagnostics)
        } else if let Some(operation) = operation {
            self.assess_full_with(None, mode, operation, diagnostics)
        } else {
            self.assess().map_err(CapturePathError::from)
        };
        let a = match assessment {
            Ok(assessment) => assessment,
            Err(CapturePathError::ConcurrentPair(error)) => {
                if let Some(failed) = held_pair_failed {
                    *failed = true;
                }
                return Err(error);
            }
            Err(error) => return Err(error.into_inner()),
        };
        // The situation line of a failed attempt reads THIS attempt's facts
        // (#616 step 2): snapshot them before any Outcome branch returns.
        self.last_attempt_facts = AttemptFacts::from_assessment(&a);

        // An unreadable frame is reported as unreadable before anything derived
        // from it is consulted. Uncertain is the only verdict this promotes; a
        // Spoof still reaches its own branch below with its own reason.
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
            let requirements = if self.ir_available {
                PadRequirements::RgbAndIr
            } else {
                PadRequirements::RgbOnly
            };
            if let Some(refusal) = pad_policy_refusal(requirements, a.rgb_pad, a.ir_pad) {
                return Ok(refusal);
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
            emit_trace_match(
                diagnostics,
                irlume_common::diagnostics::TraceMetric::MatchCosine,
                score,
                thr,
                score >= thr,
            );
            if rgb_primary_grant_admissible(score, thr, a.sequential_pair) {
                release_held(held_rgb, held_ir);
                return self.challenge_if_required(
                    purpose,
                    service,
                    Outcome::grant(score, format!("match: {who} (rgb)")),
                );
            }
            if a.sequential_pair && score >= thr {
                irlume_common::dlog!(
                    "match(rgb): {score:.3} >= thr {thr:.3} DEFERRED (sequential-schedule pair; \
                     IR-identity arms only, ADR-0014)"
                );
            }
            // Stage-2 lighting-adaptive fusion: RGB recognition missed (poor ambient
            // light or a marginal angle). If we also captured an IR face and the user
            // enrolled IR templates, fuse the two CALIBRATED scores, each weighted by
            // its modality's capture quality; a marginal RGB + marginal IR can jointly
            // grant while FMR stays bounded (an impostor must fool BOTH at once). The
            // cross-spectrum liveness gate + per-user IR floor already passed above.
            // This is the bright→RGB / dark→IR / dim→FUSE story.
            // SEQUENTIAL-SCHEDULE PAIRS DO NOT FUSE (ADR-0014): the fusion
            // floor only requires IR to clear FUSION_MIN_PER_MODALITY_PROB
            // (~0.35 Platt-equivalent cosine) — a presence bar, not an
            // identity bar — and a strong RGB score alone can carry the
            // fused grant. On a temporally split capture that reopens the
            // swap window; such pairs grant only through the IR-fallback and
            // centroid arms below, which carry identity thresholds.
            // With a third-party recognizer the whole IR side is unmeasured
            // (thresholds AND the fusion Platt calibration are shipped-model
            // measurements), so a marginal RGB miss ends here: password.
            if let Some(ir_probe) = a.ir_embedding.as_ref() {
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
                    emit_trace_match(
                        diagnostics,
                        irlume_common::diagnostics::TraceMetric::FusionProbability,
                        f.prob,
                        irlume_core::fusion::FUSION_PROB_THRESHOLD,
                        f.grant,
                    );
                    if f.grant && !a.sequential_pair {
                        let who = if ir_score >= score { ir_who } else { who };
                        release_held(held_rgb, held_ir);
                        return self.challenge_if_required(
                    purpose,
                    service,
                    Outcome::grant(f.prob,
                            format!("match: {who} (rgb+ir fusion p={:.2}; rgb {score:.2}/ir {ir_score:.2})", f.prob)));
                    }
                    if f.grant && a.sequential_pair {
                        irlume_common::dlog!(
                            "fusion p={:.3} DEFERRED (sequential-schedule pair: the fusion \
                             IR floor is a presence bar, not an identity bar; ADR-0014)",
                            f.prob
                        );
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
                    emit_trace_match(
                        diagnostics,
                        irlume_common::diagnostics::TraceMetric::MatchCosine,
                        ir_score,
                        ir_thr,
                        ir_score >= ir_thr,
                    );
                    if ir_score >= ir_thr {
                        release_held(held_rgb, held_ir);
                        let rgb_context = ir_fallback_rgb_context(score, thr, a.sequential_pair);
                        return self.challenge_if_required(
                            purpose,
                            service,
                            Outcome::grant(
                                ir_score,
                                format!("match: {ir_who} (ir-fallback, {rgb_context})"),
                            ),
                        );
                    }
                    // (c) calibrated-centroid fallback (ADR-0004): the mean-
                    // template score carries no best-of-N FAR inflation, so it
                    // uses the base threshold scaled only by profile count.
                    if let Some((cs, cwho)) = &m.centroid {
                        let cthr = irlume_core::scaled_threshold(ir_base, enr.profiles.len())
                            + irlume_core::IR_FALLBACK_MARGIN;
                        irlume_common::dlog!("match(ir-centroid): {cs:.3} vs thr {cthr:.3}");
                        emit_trace_match(
                            diagnostics,
                            irlume_common::diagnostics::TraceMetric::MatchCosine,
                            *cs,
                            cthr,
                            *cs >= cthr,
                        );
                        if *cs >= cthr {
                            release_held(held_rgb, held_ir);
                            let rgb_context =
                                ir_fallback_rgb_context(score, thr, a.sequential_pair);
                            return self.challenge_if_required(
                                purpose,
                                service,
                                Outcome::grant(
                                    *cs,
                                    format!("match: {cwho} (calibrated centroid, {rgb_context})"),
                                ),
                            );
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
                if a.sequential_pair && score >= thr {
                    format!(
                        "rgb {score:.2} matched but the sequentially captured pair \
                         requires an IR-verified match; fusion+ir missed"
                    )
                } else {
                    format!("below threshold (rgb {score:.2}, fusion+ir-fallback miss)")
                },
            ));
        }

        // Dark path: no RGB face, but an IR face -> IR-only liveness + IR
        // recognition (Windows-Hello-style dark operation) across all profiles.
        if let Some(probe) = a.ir_embedding {
            // SecureDark scene gate (ADR-0016): the dark path requires the
            // scene to actually BE dark. In a conclusively lit room the
            // absence of an RGB face is suspicious (an 850nm-reflective /
            // visibly-dark presentation routes itself here on purpose), so
            // the IR-only path refuses and the capture retries — a genuine
            // user walking up gets found by RGB, an artifact gets the
            // password. Uncertain, not Spoof: this is routing, not a
            // verdict.
            if scene_conclusively_lit(a.rgb_frame_mean) {
                irlume_common::dlog!(
                    "securedark: refusing IR-only path in a lit scene (rgb mean {:.0} >= {})",
                    a.rgb_frame_mean,
                    irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS
                );
                return Ok(Outcome::deny(
                    OutcomeKind::Uncertain,
                    "the room is lit but no face is visible to the RGB camera; \
                     dark (IR-only) authentication requires a dark room — add \
                     light so the RGB camera can see you, or use your password",
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
            diagnostics.emit_trace(irlume_liveness::diagnostic_trace_decision(
                verdict, &a.signals,
            ));
            irlume_common::dlog!("liveness(ir-only/dark): {verdict:?} ({reason}); ir_bright={:.0} ir_center_edge_ratio={:.2} glint={} ambient={:.0} ir_pad_p_fake={:?} rgb_frame_mean={:.0}",
                a.signals.ir_face_brightness, a.signals.ir_center_edge_ratio,
                a.signals
                    .ir_eye_glint
                    .map(|g| format!("{g:.2}"))
                    .unwrap_or_else(|| "n/a".into()),
                a.signals.ir_ambient,
                a.shipped_ir_fake,
                a.rgb_frame_mean);
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
            if let Some(refusal) = pad_policy_refusal(PadRequirements::IrOnly, a.rgb_pad, a.ir_pad)
            {
                return Ok(refusal);
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
            // Shipped IR PAD cue (ADR-0013): the dark path's own consult of
            // the same lit-frame score computed in assess_full. Same
            // deny-only contract, same threshold.
            if pad_downgrades(verdict, a.shipped_ir_fake, IR_PAD_THRESHOLD) {
                let pf = a.shipped_ir_fake.unwrap_or(1.0);
                irlume_common::dlog!(
                    "pad-ir: dark path p_fake {pf:.3} >= {IR_PAD_THRESHOLD:.2}; denying"
                );
                return Ok(Outcome::deny(
                    OutcomeKind::Spoof,
                    "dark liveness: IR PAD cue flags a spoof; use your password",
                ));
            }
            let ir_base = if self.ir_adapter.is_some() {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                // SecureDark stage 2 (ADR-0016): the pure-dark grant carries
                // no RGB evidence at all, so its bar is the STRICTER dark
                // constant (0.635: deployment-shaped OR-arm FAR 1.24e-4 on
                // CBSR; live dark-session genuine min 0.884 vs the 0.685
                // effective bar), never looser than the dim-light fallback
                // that at least saw an RGB face.
                irlume_core::IR_DARK_MATCH_THRESHOLD
            };
            let ir_thr = irlume_core::scaled_threshold(ir_base, m.n_templates);
            let (score, who) = (m.best, m.best_who.clone());
            irlume_common::dlog!(
                "match(ir/dark): best {score:.3} vs thr {ir_thr:.3} ({} scans, adapter={}, calib_centroid={:?})",
                m.n_templates,
                self.ir_adapter.is_some(),
                m.centroid.as_ref().map(|(s, _)| *s)
            );
            emit_trace_match(
                diagnostics,
                irlume_common::diagnostics::TraceMetric::MatchCosine,
                score,
                ir_thr,
                score >= ir_thr,
            );
            // Grant on best-of-N at the scaled threshold, or on the
            // calibrated centroid at the base threshold (no best-of-N FAR
            // inflation; the prototype-validated mean-template protocol).
            if score >= ir_thr {
                release_held(held_rgb, held_ir);
                return self.challenge_if_required(
                    purpose,
                    service,
                    Outcome::grant(score, format!("match: {who} (ir/dark)")),
                );
            }
            if let Some((cs, cwho)) = &m.centroid {
                let cthr = irlume_core::scaled_threshold(ir_base, enr.profiles.len());
                irlume_common::dlog!("match(ir/dark centroid): {cs:.3} vs thr {cthr:.3}");
                emit_trace_match(
                    diagnostics,
                    irlume_common::diagnostics::TraceMetric::MatchCosine,
                    *cs,
                    cthr,
                    *cs >= cthr,
                );
                if *cs >= cthr {
                    release_held(held_rgb, held_ir);
                    return self.challenge_if_required(
                        purpose,
                        service,
                        Outcome::grant(
                            *cs,
                            format!("match: {cwho} (ir/dark, calibrated centroid)"),
                        ),
                    );
                }
            }
            release_held(held_rgb, held_ir);
            return self.challenge_if_required(
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
        let view = CanonicalRgbView::try_from_parts(rgb.pixels(), rgb.width(), rgb.height())
            .map_err(model_input_error)?;
        let faces = self.det.detect(&DetectorInput::from_rgb(view))?;
        let Some(f) = top_detection(&faces) else {
            return Ok((
                false,
                "no RGB face detected; face the camera and retry".into(),
            ));
        };
        let input = ArcFaceInput::from_rgb(view, &f.landmarks).map_err(model_input_error)?;
        let emb_first = self.emb.embed(&input)?;
        let emb_second = self.emb.embed(&input)?;
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
        force_rgb_only: bool,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<Vec<CapturedScan>> {
        // Fresh ViT PAD vote ring per enrollment, mirroring the
        // per-authentication reset: the 5-median vote must describe ONE
        // presentation (the enrollment), and a banner presented to enroll is
        // exactly the sustained presentation the vote exists to deny.
        self.vit_scores.clear();
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
        let use_ir = enrollment_ir_enabled(self.ir_available, force_rgb_only);
        let endpoints: Vec<&str> = if use_ir {
            vec![rgb_dev.as_str(), ir_dev.as_str()]
        } else {
            vec![rgb_dev.as_str()]
        };
        let operation = irlume_camera::lease::acquire_camera_operation(
            &endpoints,
            irlume_camera::lease::CameraOperationKind::Enrollment,
            std::time::Duration::from_secs(2),
        )
        .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
        let cams = if use_ir {
            match (operation.open_rgb(&rgb_dev), operation.open_ir(&ir_dev)) {
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
        let mut capture_mode = if use_ir {
            cams.as_ref()
                .map_or_else(unavailable_capture_mode_selection, |(rgb, ir)| {
                    capture_mode_selection_with_diagnostics(rgb, ir, diagnostics)
                })
        } else {
            // Not an availability failure: this request chose RGB-only, and
            // the journal must not read it as the unmeasured default (#618).
            rgb_only_enrollment_capture_mode_selection()
        };
        emit_capture_context(&capture_mode, use_ir, diagnostics);
        if cams.is_none() && use_ir {
            diagnostics.emit_share_safe(
                irlume_common::diagnostics::ShareSafeEventKind::CaptureFallback {
                    reason: irlume_common::diagnostics::RuntimeViolationLabel::PairOpenFailure,
                },
            );
        }
        let sequential = capture_mode.is_sequential();
        let mode_source = capture_mode.source;
        if sequential {
            irlume_common::dlog!(
                "enroll: sequential capture mode (from {mode_source}); not holding \
                 both streams, capturing per-frame"
            );
        } else if let (Some((r, i)), Some(camera_contract)) =
            (&cams, capture_mode.camera_contract.as_ref())
        {
            let progress = self.capture_progress();
            let conditioning = camera_contract.conditioning();
            match arm_pair_transactionally(
                || r.session_with_selected_conditioning(&progress, conditioning),
                || i.session_with_progress(&progress),
            ) {
                Ok((mut rs, mut is)) => {
                    // Establish the delivered-rate windows for the HELD PAIR up
                    // front, draining both streams concurrently so neither starves
                    // the other's buffer queue. A failure drops both streams and
                    // selects the one-at-a-time path below.
                    match irlume_camera::establish_pair_rate(&mut rs, &mut is) {
                        Ok(()) => {
                            let held_result = self.capture_scan_loop(
                                want,
                                pitch_neutral,
                                Some((&mut rs, &mut is)),
                                EnrollmentCapturePolicy {
                                    mode: &capture_mode,
                                    use_ir,
                                    diagnostics,
                                },
                                &operation,
                                observed,
                            );
                            match held_result {
                                Ok(scans) => return Ok(scans),
                                Err(CapturePathError::ConcurrentPair(error)) => {
                                    drop(rs);
                                    drop(is);
                                    demote_after_concurrent_capture_failure(&mut capture_mode);
                                    irlume_common::dlog!(
                                    "enroll: {error}; dropped both held streams and restarting RGB then IR"
                                );
                                }
                                Err(error) => return Err(error.into_inner()),
                            }
                        }
                        Err(error) => {
                            irlume_common::dlog!(
                                "enroll: held pair could not establish delivered-rate evidence \
                             ({error}); dropping both streams and retrying one-at-a-time"
                            );
                            emit_capture_fallback(
                                RuntimeDegradation::PairRateEstablishmentFailure,
                                diagnostics,
                            );
                            demote_after_pair_rate_failure(&mut capture_mode);
                        }
                    }
                }
                Err(error) => {
                    irlume_common::dlog!(
                        "enroll: held pair could not arm transactionally ({error}); \
                         retrying one-at-a-time"
                    );
                    emit_capture_fallback(RuntimeDegradation::PairArmFailure, diagnostics);
                    demote_after_pair_arm_failure(&mut capture_mode);
                }
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
            EnrollmentCapturePolicy {
                mode: &capture_mode,
                use_ir,
                diagnostics,
            },
            &operation,
            observed,
        )
        .map_err(CapturePathError::into_inner)
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
        policy: EnrollmentCapturePolicy<'_>,
        operation: &irlume_camera::lease::CameraOperationSession,
        observed: &mut CaptureShape,
    ) -> Result<Vec<CapturedScan>, CapturePathError> {
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
                return Err(CapturePathError::Other(irlume_common::Error::Preempted(
                    "an authentication needed the camera; nothing was saved, please retry".into(),
                )));
            }
            let a = operation
                .run(|| match &mut sessions {
                    Some((rs, is)) => self.assess_full_with(
                        Some((rs, is)),
                        Some(policy.mode),
                        operation,
                        policy.diagnostics,
                    ),
                    None if policy.use_ir => self.assess_full_with(
                        None,
                        Some(policy.mode),
                        operation,
                        policy.diagnostics,
                    ),
                    None => self
                        .assess_rgb_only_with_diagnostics(policy.diagnostics)
                        .map_err(CapturePathError::from),
                })
                .map_err(|error| {
                    CapturePathError::Other(irlume_common::Error::Hardware(error.to_string()))
                })??;
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
        let view = CanonicalRgbView::try_from_parts(&frame.data, frame.width, frame.height).ok()?;
        // A detector ERROR is not an observation that no face was there, and
        // collapsing the two would let a broken detector read as a refutation.
        // Nothing is confirmed without a detection that actually ran.
        let found = match self.det.detect(&DetectorInput::from_rgb(view)) {
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
        let operation = match irlume_camera::lease::acquire_camera_operation(
            &[rgb_dev.as_str(), ir_dev.as_str()],
            irlume_camera::lease::CameraOperationKind::Authentication,
            std::time::Duration::from_secs(2),
        ) {
            Ok(operation) => operation,
            Err(_) => return false,
        };
        let cams = match (operation.open_rgb(&rgb_dev), operation.open_ir(&ir_dev)) {
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
        // Establish the delivered-rate windows for the held pair before the
        // A/B/A capture, so the serial fill cannot starve one stream and skew
        // the concurrent mean it measures.
        if let Err(error) = irlume_camera::establish_pair_rate(&mut rs, &mut is) {
            irlume_common::dlog!(
                "enroll: A/B/A check could not establish delivered-rate evidence \
                 ({error}); the per-frame fill will retry"
            );
        }
        let (rgb, ir) = std::thread::scope(|scope| {
            let ir_thread = scope.spawn(|| {
                operation
                    .run(|| is.capture_with_stats())
                    .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?
            });
            let rgb = operation
                .run(|| rs.denoised())
                .map_err(|error| irlume_common::Error::Hardware(error.to_string()))
                .and_then(|capture| capture);
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
        let concurrent_mean = irlume_camera::frame_mean(rgb.pixels());
        irlume_common::dlog!(
            "enroll: A/B/A check: held mean {held_mean:.1}, solo mean {solo_mean:.1}, \
             reopened held mean {concurrent_mean:.1}"
        );
        // The reopened held frame must still be pinned to the original held
        // mean, not tracking the solo mean. Same rule the probe uses.
        concurrent_mean < solo_mean * irlume_camera::CONCURRENT_SIGNAL_FLOOR
    }

    /// Stop asking this exact live context to capture concurrently for the rest
    /// of this daemon process once enrollment's solo probe and A/B/A check both
    /// confirm signal loss (#100).
    ///
    /// This must remain process-local. Authentication traffic is not the
    /// controlled qualification experiment and cannot rewrite durable v2
    /// authority; `camera-tune` is the only path that may do that.
    fn maybe_switch_capture_mode_from_enrolment(
        &mut self,
        consecutive_ir_only: usize,
        held_mean: f32,
        solo_mean: f32,
    ) {
        if consecutive_ir_only < SELF_HEAL_SWITCH_AFTER as usize {
            return;
        }
        let selection = standalone_capture_mode_selection(&self.rgb_dev, &self.ir_dev);
        if selection.is_sequential() || selection.source == ENV_CAPTURE_MODE_SOURCE {
            return;
        }
        let Some(context_key) = selection.runtime_key.as_deref() else {
            return;
        };
        if !self.aba_check_confirms(held_mean, solo_mean) {
            return;
        }
        trip_runtime_capture_health(context_key, RuntimeDegradation::ConfirmedSignalLoss);
    }

    /// Enroll `want` scans (capped at MAX_SCANS_PER_PROFILE). If the captured
    /// face already owns a profile, the scans are merged into it (a face can
    /// never own two profiles, so that is always what the user meant, and it
    /// is the 0.2.0 upgrade remedy, fresh scans reviving dark/dim login after
    /// an embedding-space change). A novel face gets a NEW profile; that errors
    /// if the account is already at MAX_PROFILES.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn enroll_profile(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
    ) -> irlume_common::Result<EnrollOutcome> {
        self.enroll_profile_with_capture_policy(user, profile_name, want, |_| true, &())
    }

    /// Run a user-present IR readiness check only after the enrollment's
    /// storage-only refusal gates pass, then keep its answer for every capture
    /// in this request. The closure receives the engine's detector: the
    /// preflight measures the detected FACE's region, not the whole frame
    /// (#613), and detection needs the loaded model.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn enroll_profile_with_ir_preflight(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        ir_preflight: impl FnOnce(&mut irlume_vision::Detector) -> bool,
    ) -> irlume_common::Result<EnrollOutcome> {
        self.enroll_profile_with_capture_policy(user, profile_name, want, ir_preflight, &())
    }

    /// [`Self::enroll_profile_with_ir_preflight`] while publishing bounded,
    /// structurally share-safe capture decisions to the caller-owned scope.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn enroll_profile_with_ir_preflight_and_diagnostics(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        ir_preflight: impl FnOnce(&mut irlume_vision::Detector) -> bool,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> irlume_common::Result<EnrollOutcome> {
        self.enroll_profile_with_capture_policy(user, profile_name, want, ir_preflight, diagnostics)
    }

    fn enroll_profile_with_capture_policy(
        &mut self,
        user: &str,
        profile_name: Option<String>,
        want: usize,
        ir_preflight: impl FnOnce(&mut irlume_vision::Detector) -> bool,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
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
        // A dark IR preflight downgrades to RGB-only convenience capture,
        // which on a non-concurrent pair stores a profile that could never
        // authenticate: refuse it before any camera work (#618). Only the
        // dark case pays the store read; the preflight itself still runs
        // only when an IR pair exists (the && short-circuits).
        let preflight_dark = self.ir_available && !ir_preflight(&mut self.det);
        if preflight_dark {
            dark_ir_rgb_only_enrollment_refusal(|| {
                pair_qualifies_concurrent(&self.rgb_dev, &self.ir_dev)
            })?;
        }
        let force_rgb_only = !self.ir_available || preflight_dark;
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
        let probe_scans = self.capture_scans(
            1,
            enr.pitch_neutral(),
            &mut observed,
            force_rgb_only,
            diagnostics,
        )?;
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
            captured.extend(self.capture_scans(
                goal - 1,
                enr.pitch_neutral(),
                &mut observed,
                force_rgb_only,
                diagnostics,
            )?);
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

    /// The enrollment-dependent policy refusals that gate an authentication
    /// before any capture is spent: retired-eye-policy migration, the
    /// empty-profile refuse, and the anti-swap camera binding. A pure
    /// decision over the loaded enrollment (plus sysfs identities for the
    /// binding); runs synchronously for plaintext stores (before the camera)
    /// and at the loader join for encrypted stores (see
    /// `authenticate_for_with_diagnostics` for the precedence note).
    fn enrollment_policy_refusal(
        &self,
        user: &str,
        enr: &irlume_core::storage::Enrollment,
    ) -> Option<Outcome> {
        if let Err(reason) = legacy_eye_policy(enr) {
            return Some(Outcome::deny(OutcomeKind::OtherDeny, reason));
        }
        if enr.profiles.iter().all(|p| p.scans.is_empty()) {
            return Some(Outcome::deny(
                OutcomeKind::OtherDeny,
                format!("'{user}' has no face scans enrolled"),
            ));
        }
        if let Some(bind) = &enr.camera_binding {
            if let Some(reason) = self.binding_mismatch(bind) {
                return Some(Outcome::deny(OutcomeKind::OtherDeny, reason));
            }
        }
        None
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
        self.add_scan_with_capture_policy(user, profile_name, count, |_| true)
    }

    /// Run a user-present IR readiness check only after the target profile and
    /// remaining room are validated, then keep its answer for this request.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn add_scan_with_ir_preflight(
        &mut self,
        user: &str,
        profile_name: &str,
        count: usize,
        ir_preflight: impl FnOnce(&mut irlume_vision::Detector) -> bool,
    ) -> irlume_common::Result<AddScanOutcome> {
        self.add_scan_with_capture_policy(user, profile_name, count, ir_preflight)
    }

    fn add_scan_with_capture_policy(
        &mut self,
        user: &str,
        profile_name: &str,
        count: usize,
        ir_preflight: impl FnOnce(&mut irlume_vision::Detector) -> bool,
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
        // Same gate as enrollment (#618): a dark preflight on a
        // non-concurrent pair would add RGB-only scans to a profile that
        // authenticates by IR.
        let preflight_dark = self.ir_available && !ir_preflight(&mut self.det);
        if preflight_dark {
            dark_ir_rgb_only_enrollment_refusal(|| {
                pair_qualifies_concurrent(&self.rgb_dev, &self.ir_dev)
            })?;
        }
        let force_rgb_only = !self.ir_available || preflight_dark;
        let want = count.clamp(1, room);
        let mut observed = CaptureShape::default();
        let captured = self.capture_scans(
            want,
            enr.pitch_neutral(),
            &mut observed,
            force_rgb_only,
            &(),
        )?;
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
        // Face width as a fraction of frame width; center tolerance; dim-face
        // luma bound. MIN_FRAC, CENTER_TOL, and DIM are module-level (shared
        // with the attempt situation line, #616 step 2); only the upper
        // bounds stay local to the guide.
        const MAX_FRAC: f32 = 0.55;
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
        let view = CanonicalRgbView::try_from_parts(&rgb.data, rgb.width, rgb.height)
            .map_err(model_input_error)?;
        let faces = self.det.detect(&DetectorInput::from_rgb(view))?;
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
/// Face width as a fraction of frame width below which a face is too far
/// away to be useful. The framing guide's bar (`position_sample`), hoisted
/// module-level so the attempt situation line (#616 step 2) names `too far`
/// by the SAME bar the enrollment guide coaches to.
const MIN_FRAC: f32 = 0.12;
/// Max face-center offset from frame center, fraction of frame size, before
/// the framing guide says `Center your face in the frame`; the situation
/// line's `off-center` uses it unchanged.
const CENTER_TOL: f32 = 0.18;
/// Mean face luma (0-255 BT.601) below which the framing guide says the face
/// is too dim; the situation line's `too dark` uses it unchanged.
const DIM: f32 = 55.0;
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
    /// the process-local capture-mode breaker (#100): three consecutive
    /// IR-only attempts within one held enrolment loop, followed by the solo
    /// probe and A/B/A confirmation of concurrent signal loss.
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
        // top-up loop runs after the probe loop, and the breaker needs the
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
/// The remedy says "in a lit room" on purpose. Retention reads 121%, 122% and
/// 126% at an RGB mean of 17, which is arithmetic on noise rather than a camera
/// gaining signal. `camera-tune` now refuses to store that weak evidence, and
/// the qualifier tells the user how to produce a conclusive measurement.
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
        // separate the two is the A/B/A check used before tripping runtime
        // health; the diagnostic message itself asserts only the observations.
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
/// point highlight near the landmark at typical login distances. `GLINT_MIN`
/// is a reporting/reference threshold for supporting evidence, not an
/// independent gate.
const GLINT_SEARCH_RADIUS_PX: i32 = 8;

/// Peak grey level (0-255) near the eye landmarks of an IR frame: the
/// emitter's specular corneal glint. Supporting liveness cue only (feeds
/// `Signals::ir_eye_glint`); 0.0 when the landmarks fall outside the frame.
pub fn eye_glint(grey: &[u8], w: u32, h: u32, landmarks: &Landmarks5) -> f32 {
    // The in-bounds test below is against the logical w/h, so a frame buffer
    // shorter than w*h would still index past the slice. Same guard as
    // mean_in_bbox: a truncated IR frame degrades to 0.0 instead of panicking
    // the root daemon. This removes supporting glint evidence; it does not fail
    // authentication on its own.
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
/// `Nv12Luma`, `YuyvLuma`), and there the peak passes through unchanged,
/// matching the choice `eye_glint_of` makes. On the authentication path this
/// arm is unreachable: #358's exposure refusal
/// (`exposure_refusal` in irlume-liveness) rejects a format that names no
/// ceiling before any cue below it runs. It stays live for the PAD corpus
/// tool and the dev probe, which feed frames with no negotiation step.
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

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan, LEGACY_RECOGNIZER_SPACE};

    /// Serializes access to process-wide env vars (`IRLUME_GRACE_MS`,
    /// `IRLUME_STATE_DIR`, `IRLUME_METHOD_CONF`, ...) across this binary's
    /// parallel test threads. Engine tests share it via `super::tests`.
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn legacy_eyes_open_true_blocks_without_running_an_eye_detector() {
        let enrollment: Enrollment =
            serde_json::from_str(r#"{"user":"u","profiles":[],"require_eyes_open":true}"#).unwrap();

        let reason = legacy_eye_policy(&enrollment).expect_err("legacy true must block");

        assert!(reason.contains("profiles eyes-open off"), "{reason}");
        assert!(reason.contains("password or fingerprint"), "{reason}");
    }

    /// A head-shake decline is TERMINAL: `resolve_consent_watch` returns the
    /// stream's `Some(false)` verdict without evaluating the completed-take
    /// nod check, so a completed-take nod can never overturn a decline into a
    /// grant. The panicking callbacks prove the completed take is
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
    fn only_a_gesture_decline_is_a_gesture_decline() {
        // The wire boundary: pam_irlume aborts a polkit dialog on `declined_by_gesture`
        // and nothing else, so `is_gesture_decline` must read true for a deliberate
        // shake and false for every other refusal (a timeout, a no-match, a caught
        // spoof, a policy denial). A mutant that matched OtherDeny (the class the
        // shake used before this feature) would abort a dialog on an ordinary denial.
        assert!(is_gesture_decline(&Outcome::deny(
            OutcomeKind::GestureDeclined,
            "head shake cancelled the request"
        )));
        for kind in [
            OutcomeKind::NoFace,
            OutcomeKind::Uncertain,
            OutcomeKind::SpoofNoIrFace,
            OutcomeKind::Spoof,
            OutcomeKind::BelowThreshold,
            OutcomeKind::OtherDeny,
        ] {
            assert!(
                !is_gesture_decline(&Outcome::deny(kind, "x")),
                "{kind:?} must not read as a gesture decline"
            );
        }
        assert!(!is_gesture_decline(&Outcome::grant(0.9, "match")));
    }

    #[test]
    fn a_shake_decline_reads_as_a_gesture_decline() {
        // Pins the shared shake-outcome constructor: BOTH shake sites build their
        // Outcome here, so a revert of this kind to OtherDeny would stop the daemon
        // setting declined_by_gesture and silently kill the feature, yet every other
        // camera-less test would stay green. Also pins the reason and that a
        // pre-match shake carries no live face and no score.
        let pre = Outcome::gesture_declined(false, 0.0);
        assert!(
            is_gesture_decline(&pre),
            "a shake decline is a gesture decline"
        );
        assert_eq!(pre.reason, "head shake cancelled the request");
        assert!(!pre.granted && !pre.live && pre.score == 0.0);
        // The post-match variant carries the take's live/score but is still a decline.
        let post = Outcome::gesture_declined(true, 0.42);
        assert!(is_gesture_decline(&post));
        assert!(!post.granted && post.live && post.score == 0.42);
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
    fn a_stale_pair_with_an_ir_face_discards_rgb_for_ir_only_authentication() {
        assert_eq!(
            eligible_pair_evidence(
                MAX_CROSS_SPECTRUM_SKEW + std::time::Duration::from_millis(1),
                MAX_CROSS_SPECTRUM_SKEW,
                Some(42_u8),
                true,
            ),
            EligiblePairEvidence::IrOnly,
        );
    }

    #[test]
    fn a_pair_at_the_skew_limit_remains_eligible_for_cross_spectrum_authentication() {
        assert_eq!(
            eligible_pair_evidence(
                MAX_CROSS_SPECTRUM_SKEW,
                MAX_CROSS_SPECTRUM_SKEW,
                Some(42_u8),
                true,
            ),
            EligiblePairEvidence::Paired(Some(42_u8)),
        );
    }

    #[test]
    fn the_securedark_scene_gate_separates_the_measured_lighting_landscapes() {
        // The gate reuses CONCLUSIVE_SCENE_BRIGHTNESS, whose own provenance
        // anchors both sides: pitch dark ~17 and a dark room ~62 (NexiGo,
        // 2026-07-25) must pass THROUGH to the dark path; the lit arm
        // (117-143) must refuse. The boundary itself (100.0) is pinned here
        // so a camera-crate change cannot silently move the SecureDark gate.
        assert_eq!(irlume_camera::CONCLUSIVE_SCENE_BRIGHTNESS, 100.0);
        // Dark and pitch-dark rooms take the dark path.
        assert!(!scene_conclusively_lit(17.0));
        assert!(!scene_conclusively_lit(62.0));
        assert!(
            !scene_conclusively_lit(83.0),
            "dim rooms are not conclusively lit"
        );
        // The boundary is inclusive-lit: at exactly 100 the scene is lit.
        assert!(!scene_conclusively_lit(99.9));
        assert!(scene_conclusively_lit(100.0));
        assert!(scene_conclusively_lit(117.0));
        assert!(scene_conclusively_lit(143.0));
        // A failed/empty RGB frame reads 0.0 (frame_mean of nothing): the
        // gate must not turn a sensor fault into a lit-scene refusal — the
        // liveness and match gates behind it decide that case.
        assert!(!scene_conclusively_lit(0.0));
    }

    #[test]
    fn a_stale_pair_without_an_ir_face_remains_a_capture_rejection() {
        assert_eq!(
            eligible_pair_evidence(
                MAX_CROSS_SPECTRUM_SKEW + std::time::Duration::from_millis(1),
                MAX_CROSS_SPECTRUM_SKEW,
                Some(42_u8),
                false,
            ),
            EligiblePairEvidence::Reject,
        );
    }

    #[test]
    fn the_sequential_budget_admits_the_machinery_gap_the_concurrent_budget_rejects() {
        // The measured post-flush machinery gap is ~3.05s: over the
        // concurrent ceiling (whose intent — captures that overlap — it does
        // not describe) and inside the sequential one.
        let machinery_gap = std::time::Duration::from_millis(3_050);
        assert_eq!(
            eligible_pair_evidence(machinery_gap, MAX_CROSS_SPECTRUM_SKEW, Some(42_u8), true),
            EligiblePairEvidence::IrOnly,
            "under the concurrent budget the pair is stale"
        );
        assert_eq!(
            eligible_pair_evidence(
                machinery_gap,
                SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW,
                Some(42_u8),
                true
            ),
            EligiblePairEvidence::Paired(Some(42_u8)),
            "under the sequential budget the machinery gap pairs"
        );
        // The sequential ceiling still discards pathological stacking:
        // measured worst stacking (one retry + one self-heal, ~6.2s) fits;
        // beyond the constant does not.
        assert_eq!(
            eligible_pair_evidence(
                SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW,
                SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW,
                Some(42_u8),
                true
            ),
            EligiblePairEvidence::Paired(Some(42_u8)),
        );
        assert_eq!(
            eligible_pair_evidence(
                SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW + std::time::Duration::from_millis(1),
                SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW,
                Some(42_u8),
                true
            ),
            EligiblePairEvidence::IrOnly,
        );
    }

    #[test]
    fn sequential_schedule_pairs_do_not_grant_on_rgb_alone() {
        // ADR-0014 security posture: the machinery gap between the RGB and IR
        // bursts of a sequential-schedule pair is a physical swap window, and
        // the IR-side gates pass for any live face (presence/liveness, not
        // identity), so a passing RGB score must defer to the IR-identity
        // arms instead of granting alone.
        assert!(
            !rgb_primary_grant_admissible(0.90, 0.60, true),
            "a sequential-schedule pair must not take the RGB-primary grant"
        );
        // Concurrent pairs interleave the two spectra; the arm stands.
        assert!(
            rgb_primary_grant_admissible(0.90, 0.60, false),
            "a concurrent pair keeps the RGB-primary arm"
        );
        // A miss is a miss on either schedule.
        assert!(!rgb_primary_grant_admissible(0.59, 0.60, false));
    }

    #[test]
    fn sequential_pair_stamp_matches_the_schedule_that_admitted_the_pair() {
        // The stamp couples to the pairing budget: the measured machinery gap
        // (3.05 s) pairs only under the sequential budget and stamps; under
        // the concurrent budget the same gap demotes to IrOnly (no pair), so
        // the stamp cannot fire. A held-sequential sub-3s pair
        // (concurrent-equivalent) does not stamp either.
        let machinery_gap = std::time::Duration::from_millis(3_050);
        assert!(pair_admitted_sequentially(machinery_gap, true));
        assert!(!pair_admitted_sequentially(MAX_CROSS_SPECTRUM_SKEW, true));
        assert!(!pair_admitted_sequentially(machinery_gap, false));
        // The pairing side of the coupling: the concurrent budget demotes the
        // same gap to IrOnly, so `paired` can only be true there for
        // sub-ceiling skews.
        assert_eq!(
            eligible_pair_evidence(machinery_gap, MAX_CROSS_SPECTRUM_SKEW, Some(42_u8), true),
            EligiblePairEvidence::IrOnly
        );
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
    /// so the runtime breaker is never reached by summing unrelated events.
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
        // The remedy is qualified on purpose. Retention reads 121-126% at an
        // RGB mean of 17; `camera-tune` refuses that evidence, and "lit room"
        // says how to make the re-measure conclusive.
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
        // SecureDark (ADR-0016): stage 1 ended the old inversion (less
        // evidence, looser threshold) by aligning the pure-dark bar with the
        // dim-light fallback's effective bar; stage 2's live-measured bar
        // (0.635) must stay AT OR ABOVE that fallback bar — the dark path
        // carries strictly less evidence and can never be the looser arm.
        const {
            assert!(IR_DARK_MATCH_THRESHOLD >= IR_MATCH_THRESHOLD + IR_FALLBACK_MARGIN);
            assert!(IR_DARK_MATCH_THRESHOLD > IR_MATCH_THRESHOLD);
        }
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
    /// gate must read the raw gate frame that canonical IR evidence preserves.
    /// Measuring the returned pixels instead reports a blown face as
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
        // eye_glint=255 from landmarks that do not exist. The glint cue must
        // fail closed instead.
        let (mut grey, _) = ir_frame_with_glints(false, false);
        // A SPIKE over darker neighbors, not a uniform block: the contrast
        for y in 0..4u32 {
            for x in 0..4u32 {
                grey[(y * 64 + x) as usize] = 60;
            }
        }
        grey[0] = 255;
        let nan: Landmarks5 = [(f32::NAN, f32::NAN); 5];
        assert_eq!(eye_glint(&grey, 64, 48, &nan), 0.0);
        // One placeable eye is still not enough: the glint helper scores the
        // whole set 0.0 rather than letting the valid eye vouch
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
        assert_eq!(eye_glint(&bright, 64, 48, &one), 0.0);
    }

    /// A truncated IR frame (buffer shorter than w*h, from a driver reporting a
    /// short sizeimage) must degrade the glint cue to 0.0, not panic the root
    /// daemon on an out-of-bounds index. The landmarks sit deep in the frame, so
    /// an unguarded index would run past the short slice.
    #[test]
    fn glint_cues_survive_a_truncated_ir_frame() {
        let (grey, lm) = ir_frame_with_glints(true, true);
        let short = &grey[..grey.len() / 4]; // buffer well under w*h
        assert_eq!(eye_glint(short, 64, 48, &lm), 0.0);
    }
}

#[cfg(test)]
mod pad_cue_tests {
    use super::{
        pad_downgrades, pad_evidence_refusal, pad_policy_refusal, PadEvidence, PadModality,
        PadRequirements,
    };
    use super::{vit_vote_denies, IR_PAD_THRESHOLD, VIT_PAD_VOTE_N};
    use irlume_liveness::Verdict;

    #[test]
    fn applicable_pad_unavailable_is_terminal_password_fallback_not_abstention() {
        let refusal = pad_evidence_refusal(PadModality::Rgb, PadEvidence::Unavailable)
            .expect("required unavailable PAD must refuse face authentication");

        assert_eq!(refusal.kind, super::OutcomeKind::OtherDeny);
        assert!(!super::presence_retryable(&refusal));
        assert!(refusal.reason.contains("RGB PAD is unavailable"));
        assert!(refusal.reason.contains("use your password"));
    }

    #[test]
    fn pad_requirements_follow_the_grant_modalities() {
        assert!(pad_policy_refusal(
            PadRequirements::RgbOnly,
            PadEvidence::Score(0.1),
            PadEvidence::NotApplicable,
        )
        .is_none());
        assert!(pad_policy_refusal(
            PadRequirements::RgbAndIr,
            PadEvidence::Score(0.1),
            PadEvidence::Score(0.1),
        )
        .is_none());
        assert!(pad_policy_refusal(
            PadRequirements::IrOnly,
            PadEvidence::NotApplicable,
            PadEvidence::Score(0.1),
        )
        .is_none());

        let paired_ir_missing = pad_policy_refusal(
            PadRequirements::RgbAndIr,
            PadEvidence::Score(0.1),
            PadEvidence::Unavailable,
        )
        .expect("paired grants require IR PAD");
        assert!(paired_ir_missing.reason.contains("IR PAD is unavailable"));

        assert!(pad_policy_refusal(
            PadRequirements::IrOnly,
            PadEvidence::Unavailable,
            PadEvidence::Score(0.1),
        )
        .is_none());

        let required_but_not_evaluated = pad_policy_refusal(
            PadRequirements::RgbOnly,
            PadEvidence::NotApplicable,
            PadEvidence::NotApplicable,
        )
        .expect("a required modality must produce a PAD score");
        assert!(required_but_not_evaluated
            .reason
            .contains("RGB PAD was not evaluated"));
    }

    #[test]
    fn applicable_pad_inference_failure_is_password_fallback() {
        let refusal = pad_policy_refusal(
            PadRequirements::IrOnly,
            PadEvidence::NotApplicable,
            PadEvidence::InferenceFailed,
        )
        .expect("required failed PAD inference must refuse face authentication");

        assert_eq!(refusal.kind, super::OutcomeKind::OtherDeny);
        assert!(!super::presence_retryable(&refusal));
        assert!(refusal.reason.contains("IR PAD inference failed"));
        assert!(refusal.reason.contains("use your password"));
    }

    #[test]
    fn every_authentication_grant_path_checks_required_pad_first() {
        let source = include_str!("lib.rs");
        let auth = &source[source.find("fn authenticate_once").unwrap()
            ..source.find("/// 1:N identify").unwrap()];
        let dark_start = auth.find("// Dark path:").unwrap();
        let (rgb_path, dark_path) = auth.split_at(dark_start);

        let rgb_check = rgb_path
            .find("pad_policy_refusal(requirements, a.rgb_pad, a.ir_pad)")
            .expect("RGB authentication path must enforce applicable PAD");
        let rgb_grant = rgb_path
            .find("Outcome::grant")
            .expect("RGB authentication path must contain a grant arm");
        assert!(
            rgb_check < rgb_grant,
            "RGB PAD must be checked before grants"
        );

        let dark_check = dark_path
            .find("pad_policy_refusal(PadRequirements::IrOnly, a.rgb_pad, a.ir_pad)")
            .expect("dark authentication path must enforce IR PAD");
        let dark_grant = dark_path
            .find("Outcome::grant")
            .expect("dark authentication path must contain a grant arm");
        assert!(
            dark_check < dark_grant,
            "dark IR PAD must be checked before grants"
        );
    }

    #[test]
    fn authentication_source_has_no_raw_model_input_view_types() {
        let source = include_str!("lib.rs");
        let production = source
            .split_once("#[cfg(test)]\nmod tests")
            .expect("test module boundary")
            .0;
        let raw_types = [
            ["align::", "RgbView"].concat(),
            ["align::", "Grey8View"].concat(),
            ["Frame", "View"].concat(),
        ];
        for raw_type in raw_types {
            assert!(
                !production.contains(&raw_type),
                "authentication production source must construct typed model inputs, not use {raw_type}"
            );
        }
        assert!(production.contains("DetectorInput::from_rgb"));
        assert!(production.contains("DetectorInput::from_grey"));
        assert!(production.contains("ArcFaceInput::"));
        assert!(production.contains("VitRgbPadInput::new"));
        assert!(production.contains("FlirIrPadInput::new"));
    }

    #[test]
    fn fires_only_on_live_plus_confident_fake() {
        assert!(pad_downgrades(Verdict::Live, Some(0.9), 0.5));
        assert!(pad_downgrades(Verdict::Live, Some(0.5), 0.5)); // at threshold
        assert!(!pad_downgrades(Verdict::Live, Some(0.49), 0.5));
        assert!(!pad_downgrades(Verdict::Live, None, 0.5));
    }

    /// The ViT PAD vote (ADR-0013): abstains until N scores, median decides,
    /// the window slides, and the threshold sits in the measured FLEET gap:
    /// genuine presentation-medians topped at 0.465 (dim-marginal, Zenbook)
    /// and every login-distance banner presentation on both fleet cameras
    /// measured 0.594-0.656. These assertions pin BOTH sides: a raised
    /// threshold drops the NexiGo banner (measured at 0.55-0.60 median), a
    /// lowered one crosses the LFW presentation tail (1.3% fire at 0.52,
    /// 7.3% at 0.50).
    #[test]
    fn vit_vote_abstains_until_full_and_the_threshold_pins_the_measured_window() {
        // Worst measured genuine presentation (0.465): never a denial.
        let mut genuine = Vec::new();
        for i in 0..VIT_PAD_VOTE_N {
            genuine.push(0.465);
            assert!(!vit_vote_denies(&genuine), "genuine frame {i} denied");
        }
        // Lowest measured login-distance banner median (0.594): every full
        // window denies.
        let mut banner = Vec::new();
        for i in 0..VIT_PAD_VOTE_N {
            banner.push(0.594);
            assert_eq!(
                vit_vote_denies(&banner),
                i == VIT_PAD_VOTE_N - 1,
                "vote must abstain until the window fills"
            );
        }
        // Sliding window: a 6th score drops the 1st. Four genuine scores
        // followed by sustained attacks deny once the window is attack-majority.
        let mut slide = vec![0.30; VIT_PAD_VOTE_N];
        assert!(!vit_vote_denies(&slide));
        slide.push(0.90);
        assert!(!vit_vote_denies(&slide), "window still holds 4 genuine");
        // After two pushes the window is [0.30,0.30,0.30,0.90,0.90]:
        // median 0.30, still no denial.
        slide.push(0.90);
        assert!(!vit_vote_denies(&slide));
        // Two more: window [0.30,0.90,0.90,0.90,0.90], median 0.90.
        slide.push(0.90);
        slide.push(0.90);
        assert!(vit_vote_denies(&slide), "sustained attack denies");
        // A single outlier among genuine never denies (median robustness).
        let mut outlier = vec![0.40; VIT_PAD_VOTE_N - 1];
        outlier.push(0.99);
        assert!(
            !vit_vote_denies(&outlier),
            "one spoof outlier among genuine must not deny"
        );
    }

    #[test]
    fn vit_threshold_sits_between_the_measured_genuine_max_and_attack_floor() {
        // Behavioral pin (not a const assert): a window of the worst measured
        // genuine presentation median (0.465, fleet, dim-marginal) must never
        // deny, and a window of the lowest measured login-distance banner
        // median (0.594, fleet) must always deny. Moving VIT_PAD_THRESHOLD
        // across either boundary fails this.
        let genuine = vec![0.465; VIT_PAD_VOTE_N];
        assert!(
            !vit_vote_denies(&genuine),
            "threshold crosses the fleet genuine presentation max (0.465): false denials"
        );
        let banner = vec![0.594; VIT_PAD_VOTE_N];
        assert!(
            vit_vote_denies(&banner),
            "threshold crosses the fleet banner presentation min (0.594): dropped detections"
        );
        assert_eq!(
            VIT_PAD_VOTE_N, 5,
            "the vote protocol is part of the measurement"
        );
    }

    #[test]
    fn the_shipped_ir_threshold_sits_in_the_measured_window() {
        // The 2026-07-17 qualification measured genuine faces at 0.001-0.13
        // (offline corpus) with one out-of-distribution genuine reading at
        // 0.702 on 2026-07-27 (the reading that denied a real user when the
        // threshold was 0.5), and the vinyl-print attack at 0.998-1.0000
        // medians with a measured floor of 0.941 (2026-07-27, 6/6 flagged at
        // 0.941-1.000). The 2026-08-23 SecureDark lit-room control (RGB lens
        // occluded, room lit, genuine face via IR) measured 0.799 — the
        // worst genuine excursion on record, an out-of-domain regime (FLIR
        // trained on emitter-dark NIR), disclosed in ADR-0016. The operating
        // window is 0.799-0.941; the threshold must stay inside it. Raising
        // it "to be safer" crosses the attack floor and drops detections;
        // lowering it crosses the genuine excursion and denies real faces.
        const MEASURED_GENUINE_EXCURSION: f32 = 0.799;
        const MEASURED_ATTACK_FLOOR: f32 = 0.941;
        const { assert!(IR_PAD_THRESHOLD > MEASURED_GENUINE_EXCURSION) };
        const { assert!(IR_PAD_THRESHOLD < MEASURED_ATTACK_FLOOR) };
        // Behavioral pin of both sides through the deny-only helper.
        assert!(!pad_downgrades(
            Verdict::Live,
            Some(MEASURED_GENUINE_EXCURSION),
            IR_PAD_THRESHOLD
        ));
        assert!(pad_downgrades(
            Verdict::Live,
            Some(MEASURED_ATTACK_FLOOR),
            IR_PAD_THRESHOLD
        ));
    }

    #[test]
    fn never_touches_a_non_live_verdict() {
        // The deny-only property: a gate rejection or non-response stands even
        // if the cue is confident the presentation is genuine or a spoof; the
        // cue can tighten the gate, never loosen or reshape it.
        for v in [Verdict::Spoof, Verdict::Uncertain] {
            for p in [None, Some(0.0), Some(0.49), Some(0.5), Some(1.0)] {
                assert!(!pad_downgrades(v, p, 0.5));
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
                .with_pad_ir("/nonexistent/pad.onnx")
                .unwrap();
            assert!(
                !e.has_ir_adapter() && !e.has_mesh() && !e.has_blaze_rescue() && !e.has_pad_ir(),
                "absent model files must leave the engine bare"
            );
            // A mesh file that EXISTS but will not load must hand the engine
            // back beside the error, not consume it: the daemon degrades on
            // this (nod still works) where a fatal treatment turned "mesh
            // gates off" into "face auth dead" on hosts whose bundled TFLite
            // runtime does not load.
            let bogus = std::env::temp_dir()
                .join(format!("irlume-bogus-mesh-{}.tflite", std::process::id()));
            std::fs::write(&bogus, b"TFL3 this is not a model").unwrap();
            let (e, err) = e.with_mesh_degraded(&bogus.to_string_lossy());
            assert!(
                err.is_some(),
                "an unloadable mesh must report its error to the caller"
            );
            assert!(!e.has_mesh(), "the engine must come back mesh-less");
            let _ = std::fs::remove_file(&bogus);
            let bogus_pad =
                std::env::temp_dir().join(format!("irlume-bogus-pad-{}.onnx", std::process::id()));
            std::fs::write(&bogus_pad, b"not an ONNX model").unwrap();
            let (e, vit_err) = e.with_vit_pad_degraded(&bogus_pad.to_string_lossy());
            assert!(
                vit_err.is_some(),
                "an unloadable RGB PAD must report its error"
            );
            assert!(
                !e.has_vit_pad(),
                "the engine must come back without RGB PAD"
            );
            let (e, ir_err) = e.with_pad_ir_degraded(&bogus_pad.to_string_lossy());
            assert!(
                ir_err.is_some(),
                "an unloadable IR PAD must report its error"
            );
            assert!(!e.has_pad_ir(), "the engine must come back without IR PAD");
            let _ = std::fs::remove_file(&bogus_pad);
            assert_eq!(e.ir_space(), "raw");
            // Adapter digest naming is covered by the contract-aware recording
            // runtime test. A graph for another model must not masquerade as an
            // adapter now that model ports are validated.
            let blaze = model_path("blaze_face_short_range.onnx");
            let adapter_space = format!(
                "adapter:{}",
                &irlume_common::sha256_hex(&std::fs::read(&blaze).unwrap())[..12]
            );
            let e = e
                .with_mesh(&model_path("face_landmark.onnx"))
                .unwrap()
                .with_blaze_rescue(&blaze)
                .unwrap()
                .with_pad_ir(&model_path("flir.onnx"))
                .unwrap();
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
        assert!(e.has_mesh() && e.has_blaze_rescue() && e.has_pad_ir());
        // Adapter space naming: "adapter:" + first 12 hex of the file's sha256,
        // computed independently here from the same bytes.
        let bytes = std::fs::read(model_path("blaze_face_short_range.onnx")).unwrap();
        let digest = irlume_common::sha256_hex(&bytes);
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
        let before = prof.ir_calib.clone().unwrap();
        s.engine
            .refit_profile_calib_for_adapter_state(true, &mut prof);
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
        s.engine
            .refit_profile_calib_for_adapter_state(true, &mut fresh);
        assert!(fresh.ir_calib.is_none(), "adapter mode must not fit anew");
        s.engine.ir_adapter = None; // restore the shared baseline
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
        let expected = format!("embed:{}", irlume_common::sha256_hex(&bytes));
        let weights = irlume_common::HashedModel::new(bytes);
        let engine = Engine::load_with_recognizer_weights(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &weights,
        )
        .expect("engine from bytes");
        assert_eq!(engine.embed_space(), expected);
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

        // A legacy eyes-open flag is a retired policy, not a reason to run an
        // eye detector. The nonexistent devices prove this denial happens
        // before any camera lease, open, or capture.
        let mut e = Enrollment::new("irlume-test-legacy-eyes-open");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
            ir_calibs: Default::default(),
        });
        let mut legacy = serde_json::to_value(&e).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .insert("require_eyes_open".into(), serde_json::Value::Bool(true));
        std::fs::write(
            dir.join(format!("{}.json", e.user)),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let o = s
            .engine
            .authenticate("irlume-test-legacy-eyes-open", None)
            .expect("legacy eye policy must deny before the missing camera is opened");
        assert!(!o.granted && !o.live);
        assert_eq!(o.kind, OutcomeKind::OtherDeny);
        assert!(o.reason.contains("profiles eyes-open off"), "{}", o.reason);
        assert!(o.reason.contains("password or fingerprint"), "{}", o.reason);

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
    fn legacy_and_malformed_gesture_config_block_gated_auth_before_camera() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("legacy-gesture");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        let mut enrollment = Enrollment::new("irlume-test-legacy-gesture");
        enrollment.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
            ir_calibs: Default::default(),
        });
        write_enrollment(&dir, &enrollment);

        for (configured, expected) in [
            (
                "closure",
                "cannot approve: eye closure is retired; remove consent_gesture from settings.conf or set it to nod",
            ),
            (
                "clousure",
                "cannot approve: consent_gesture is invalid; remove consent_gesture from settings.conf or set it to nod",
            ),
        ] {
            std::fs::write(
                dir.join("settings.conf"),
                format!("service_gesture.sudo=1\nconsent_gesture={configured}\n"),
            )
            .unwrap();
            let out = s
                .engine
                .authenticate("irlume-test-legacy-gesture", Some("sudo"))
                .expect("retired policy must deny before the missing camera is opened");
            assert!(!out.granted, "{configured} granted: {}", out.reason);
            assert_eq!(out.kind, OutcomeKind::OtherDeny, "{configured}");
            assert_eq!(out.reason, expected, "{configured}");
        }

        std::fs::write(
            dir.join("settings.conf"),
            "service_gesture.sudo=1\nconsent_gesture=nod\n",
        )
        .unwrap();
        for (configured, expected) in [
            (
                "closure",
                "cannot approve: eye closure is retired; unset IRLUME_CONSENT_GESTURE or set it to nod",
            ),
            (
                "clousure",
                "cannot approve: consent_gesture is invalid; unset IRLUME_CONSENT_GESTURE or set it to nod",
            ),
        ] {
            std::env::set_var("IRLUME_CONSENT_GESTURE", configured);
            let out = s
                .engine
                .authenticate("irlume-test-legacy-gesture", Some("sudo"))
                .expect("environment policy must deny before the missing camera is opened");
            assert!(!out.granted, "{configured} granted: {}", out.reason);
            assert_eq!(out.kind, OutcomeKind::OtherDeny, "{configured}");
            assert_eq!(out.reason, expected, "{configured}");
        }

        std::env::remove_var("IRLUME_CONSENT_GESTURE");
        std::env::remove_var("IRLUME_CONFIG_DIR");
        teardown_sandbox(&dir);
    }

    #[test]
    fn legacy_gesture_config_does_not_block_non_gated_authentication() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("legacy-non-gated");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::fs::write(dir.join("settings.conf"), "consent_gesture=closure\n").unwrap();

        let out = s
            .engine
            .challenge_if_required(
                AuthenticationPurpose::Verify,
                None,
                Outcome::grant(0.9, "match"),
            )
            .unwrap();
        assert!(
            out.granted,
            "a non-gated verify was blocked: {}",
            out.reason
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        teardown_sandbox(&dir);
    }

    #[test]
    fn legacy_migration_keeps_absent_and_nod_policies_ready() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("legacy-ready");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        for configured in [None, Some("nod")] {
            let consent = configured
                .map(|value| format!("consent_gesture={value}\n"))
                .unwrap_or_default();
            std::fs::write(
                dir.join("settings.conf"),
                format!("service_gesture.polkit-1=1\n{consent}"),
            )
            .unwrap();
            s.engine.head_consent_before_match = HeadConsentVerdict::Approve;
            let out = s
                .engine
                .challenge_if_required(
                    AuthenticationPurpose::AppConsent,
                    Some("polkit-1"),
                    Outcome::grant(0.9, "match"),
                )
                .unwrap();
            assert!(out.granted, "{configured:?} was not ready: {}", out.reason);
        }
        s.engine.head_consent_before_match = HeadConsentVerdict::NoGesture;

        std::env::remove_var("IRLUME_CONFIG_DIR");
        teardown_sandbox(&dir);
    }

    #[test]
    fn polkit_service_classification_is_independent_of_optional_gesture_policy() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("consent");

        // Purpose comes from the service class, not from whether the optional
        // gesture is enabled. Otherwise turning the gesture off changes the
        // operation's meaning instead of only removing an additional gate.
        assert_eq!(
            AuthenticationPurpose::for_service(Some("polkit-1")),
            AuthenticationPurpose::AppConsent
        );
        assert_eq!(
            AuthenticationPurpose::for_service(Some("sudo")),
            AuthenticationPurpose::Verify
        );
        assert_eq!(
            AuthenticationPurpose::for_service(None),
            AuthenticationPurpose::Verify
        );

        // Default off: AppConsent remains the purpose, but the optional gate
        // does not withdraw an otherwise valid match.
        let granted = || Outcome::grant(0.9, "match");
        let out = s
            .engine
            .challenge_if_required(
                AuthenticationPurpose::AppConsent,
                Some("polkit-1"),
                granted(),
            )
            .unwrap();
        assert!(
            out.granted,
            "default-off gesture must not gate: {}",
            out.reason
        );

        // Explicit opt-in keeps the old fail-closed behavior on this IR-less
        // engine, without changing the service's AppConsent classification.
        std::env::set_var("IRLUME_POLKIT_GESTURE", "1");
        assert_eq!(
            AuthenticationPurpose::for_service(Some("polkit-1")),
            AuthenticationPurpose::AppConsent
        );
        let out = s
            .engine
            .challenge_if_required(
                AuthenticationPurpose::AppConsent,
                Some("polkit-1"),
                granted(),
            )
            .unwrap();
        assert!(!out.granted, "explicit gesture must fail closed without IR");
        std::env::remove_var("IRLUME_POLKIT_GESTURE");

        teardown_sandbox(&dir);
    }

    /// The credential-release gate, purpose by purpose, on an IR-less engine (so
    /// a required gesture always fails and the deny reason names which gate ran).
    ///
    /// The contract: a credential release whose `temporal_challenge` is ON demands
    /// the deliberate gesture; with it OFF (the default) the release grants after
    /// the match. Verify is untouched either way. The purpose carries the resolved
    /// setting explicitly, so this pins the arm independent of the config default.
    #[test]
    fn consent_gate_preserves_gesture_decline_and_credential_release_policy() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("credrelease");

        let grant = || Outcome::grant(0.9, "match");
        let release = |on: bool| AuthenticationPurpose::CredentialRelease {
            temporal_challenge: on,
        };

        // temporal_challenge ON: the deliberate gesture is required, and fails
        // closed here (IR-less).
        let out = s
            .engine
            .challenge_if_required(release(true), None, grant())
            .unwrap();
        assert!(!out.granted, "an on release must gate: {}", out.reason);
        assert!(
            out.reason.contains("consent gesture"),
            "the gesture gate must be the one that ran: {}",
            out.reason
        );

        // temporal_challenge OFF (the default): a grant, no gesture.
        let out = s
            .engine
            .challenge_if_required(release(false), None, grant())
            .unwrap();
        assert!(out.granted, "an off release must not gate: {}", out.reason);

        // Verify is unchanged: no service, no gate.
        for purpose in [AuthenticationPurpose::Verify, release(false)] {
            assert!(
                s.engine
                    .challenge_if_required(purpose, None, grant())
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
            .challenge_if_required(release(true), None, denied)
            .unwrap();
        assert!(!out.granted);
        assert!(
            out.reason.contains("below threshold"),
            "the deny reason must survive untouched: {}",
            out.reason
        );

        // A gesture seen BEFORE the match satisfies the gate without asking for
        // a second one (issue #101: the watch used to open only after the match,
        // so a user who nodded when the greeter asked was refused). The verdict
        // is the only thing that changes here: same purpose, same
        // granted outcome.
        s.engine.head_consent_before_match = HeadConsentVerdict::Approve;
        let out = s
            .engine
            .challenge_if_required(release(true), None, grant())
            .unwrap();
        assert!(
            out.granted,
            "a gesture made before the match must satisfy the gate: {}",
            out.reason
        );
        // A typed pre-match decline is terminal and preserves the matched
        // take's evidence rather than opening another watch.
        s.engine.head_consent_before_match = HeadConsentVerdict::Decline;
        let out = s
            .engine
            .challenge_if_required(release(true), None, grant())
            .unwrap();
        assert!(is_gesture_decline(&out));
        assert!(out.live);
        assert!((out.score - 0.9).abs() < f32::EPSILON);

        // And it must not persist: cleared, the gate is back to requiring one.
        // (No camera in the sandbox, so the watch fails closed rather than
        // waiting, which is exactly the fail-closed reading of `NoGesture`.)
        s.engine.head_consent_before_match = HeadConsentVerdict::NoGesture;
        let out = s
            .engine
            .challenge_if_required(release(true), None, grant())
            .unwrap();
        assert!(
            !out.granted,
            "without a seen gesture the gate must still refuse: {}",
            out.reason
        );

        // demands_gesture is the whole policy surface; pin it.
        assert!(!AuthenticationPurpose::Verify.demands_gesture(None));
        assert!(!AuthenticationPurpose::AppConsent.demands_gesture(None));
        assert!(release(true).demands_gesture(None));
        assert!(!release(false).demands_gesture(None));

        teardown_sandbox(&dir);
    }

    /// App consent is a purpose, while its experimental head gesture is an
    /// explicit-only additional gate. The per-service key keeps precedence.
    #[test]
    fn app_consent_honors_the_polkit_service_override() {
        let _g = env_guard();
        let dir =
            std::env::temp_dir().join(format!("irlume-auth-polkitovr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        let ac = AuthenticationPurpose::AppConsent;
        assert!(!ac.demands_gesture(Some("polkit-1")), "default must be off");
        std::fs::write(dir.join("settings.conf"), "service_gesture.polkit-1=0\n").unwrap();
        assert!(
            !ac.demands_gesture(Some("polkit-1")),
            "service_gesture.polkit-1=0 must disable the gesture"
        );
        std::fs::write(dir.join("settings.conf"), "service_gesture.polkit-1=1\n").unwrap();
        assert!(
            ac.demands_gesture(Some("polkit-1")),
            "service_gesture.polkit-1=1 must require the gesture"
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The call-site WIRING of `demands_gesture`, not just the
    /// `service_gesture_default` helper (pattern #75). The `None`-only
    /// assertions elsewhere are satisfied by a mutant that drops the Verify arm
    /// (returns `false`) or the CredentialRelease per-service override branch, so
    /// this pins the two arms through a real service and a real settings.conf.
    #[test]
    fn demands_gesture_wires_verify_and_credential_release() {
        let _g = env_guard();
        let dir = std::env::temp_dir().join(format!("irlume-auth-dgwire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE");

        let verify = AuthenticationPurpose::Verify;
        let release = |on| AuthenticationPurpose::CredentialRelease {
            temporal_challenge: on,
        };

        // Verify arm: elevation and lock services both default OFF; an explicit
        // per-service opt-in is the only way to add the gesture.
        assert!(!verify.demands_gesture(Some("sudo")), "sudo defaults off");
        assert!(!verify.demands_gesture(Some("su-l")), "su-l defaults off");
        assert!(
            !verify.demands_gesture(Some("kde")),
            "a lock screen must default OFF"
        );
        assert!(!verify.demands_gesture(None), "no service demands nothing");
        std::fs::write(dir.join("settings.conf"), "service_gesture.sudo=1\n").unwrap();
        assert!(
            verify.demands_gesture(Some("sudo")),
            "service_gesture.sudo=1 must enable the additional gate"
        );

        // CredentialRelease arm: the per-service credential_release override
        // wins over the temporal_challenge fallback, both directions.
        std::fs::write(
            dir.join("settings.conf"),
            "service_gesture.credential_release=1\n",
        )
        .unwrap();
        assert!(
            release(false).demands_gesture(None),
            "credential_release=1 must win over temporal_challenge=false"
        );
        std::fs::write(
            dir.join("settings.conf"),
            "service_gesture.credential_release=0\n",
        )
        .unwrap();
        assert!(
            !release(true).demands_gesture(None),
            "credential_release=0 must win over temporal_challenge=true"
        );
        // No override: the arm falls back to temporal_challenge.
        let _ = std::fs::remove_file(dir.join("settings.conf"));
        assert!(
            release(true).demands_gesture(None),
            "no override falls back to temporal_challenge=true"
        );
        assert!(
            !release(false).demands_gesture(None),
            "no override falls back to temporal_challenge=false"
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE invariant behind a default-on gate: with the challenge required, NO
    /// failure mode may hand back a granted outcome. Every case must be a deny or
    /// an Err, both of which the daemon turns into `Response::Error` and PAM turns
    /// into IGNORE, so the user types their password instead of being locked out.
    ///
    /// The head-only watch needs neither an enrollment calibration nor FaceMesh.
    #[test]
    fn no_credential_release_failure_mode_ever_grants() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("credrelease-safe");
        let release = AuthenticationPurpose::CredentialRelease {
            temporal_challenge: true,
        };

        let assert_no_grant = |engine: &mut Engine, stage: &str, err_must_say: &str| match engine
            .challenge_if_required(release, None, Outcome::grant(0.95, "match"))
        {
            Ok(o) => assert!(
                !o.granted,
                "{stage} GRANTED without a head gesture: {}",
                o.reason
            ),
            Err(e) => assert!(
                e.to_string().contains(err_must_say),
                "{stage} failed for the wrong reason (wanted {err_must_say:?}): {e}"
            ),
        };
        // No IR at all: declined before any camera is touched.
        s.engine.ir_available = false;
        assert_no_grant(&mut s.engine, "no-IR", "camera");
        // With IR available and FaceMesh absent, the pose-only watch still reaches
        // the camera boundary; the missing camera, not the missing mesh, fails it.
        s.engine.ir_available = true;
        let mesh = s.engine.mesh.take();
        assert_no_grant(&mut s.engine, "no-mesh", "no camera found");
        s.engine.mesh = mesh;
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
        let emitter_touched = std::cell::Cell::new(false);
        let err = s
            .engine
            .enroll_profile_with_ir_preflight(
                "irlume-test-enroll",
                Some("Work Laptop".into()),
                3,
                |_| {
                    emitter_touched.set(true);
                    true
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert!(
            !emitter_touched.get(),
            "a refused duplicate must not run the emitter preflight"
        );
        // A novel name proceeds to the probe capture, which needs the camera.
        let err = s
            .engine
            .enroll_profile("irlume-test-enroll", Some("New Face".into()), 3)
            .unwrap_err();
        assert!(err.to_string().contains("no camera found"), "{err}");
        teardown_sandbox(&dir);
    }

    #[test]
    fn rgb_only_enrollment_policy_suppresses_ir_even_when_hardware_is_present() {
        assert!(enrollment_ir_enabled(true, false));
        assert!(!enrollment_ir_enabled(true, true));
        assert!(!enrollment_ir_enabled(false, false));
    }

    #[test]
    fn dark_ir_refusal_gate_is_decided_by_the_pair_qualification() {
        // A pair without concurrent authorization (sequential verdict, or the
        // unmeasured sequential default) refuses; the only pair shape an
        // RGB-only enrollment can ever grant on does not.
        assert!(dark_ir_rgb_only_enrollment_refusal(|| false).is_err());
        assert!(dark_ir_rgb_only_enrollment_refusal(|| true).is_ok());
    }

    #[test]
    fn rgb_only_enrollment_selection_is_not_misread_as_the_unmeasured_default() {
        // #618: the enroll journal printed `from default` for the deliberate
        // RGB-only enrollment selection, which read as "the stored
        // qualification is not in effect". The selection must name itself.
        let selection = rgb_only_enrollment_capture_mode_selection();
        assert!(selection.is_sequential());
        assert_eq!(selection.source, RGB_ONLY_ENROLLMENT_CAPTURE_MODE_SOURCE);
        assert_ne!(selection.source, "default");
    }

    #[test]
    fn attempt_situation_line_names_every_vocabulary_shape() {
        use super::{attempt_situation_line, AttemptFacts, AttemptSituation, OutcomeKind};
        // The #616 step 2 vocabulary: one stable label per failed-attempt
        // shape, the measured numbers alongside, never a threshold value.
        let frontal = AttemptFacts {
            rgb_face: Some((0.5, 0.5)),
            face_frac: 0.30,
            yaw_asym: 0.10,
            rgb_face_brightness: 120.0,
            glint: Some(250.0),
            ir_bright: 140.0,
            persistent_ir_source_overwhelms: false,
        };
        let line = |kind, score, facts: &AttemptFacts| {
            let text = attempt_situation_line(kind, score, facts);
            assert!(text.starts_with("attempt: "), "stable prefix: {text}");
            text
        };
        assert!(line(OutcomeKind::GestureDeclined, 0.0, &frontal).starts_with("attempt: declined;"));
        assert!(line(
            OutcomeKind::NoFace,
            0.0,
            &AttemptFacts {
                rgb_face: None,
                ..frontal
            }
        )
        .starts_with("attempt: no face;"));
        assert!(line(
            OutcomeKind::Uncertain,
            0.0,
            &AttemptFacts {
                face_frac: 0.08,
                ..frontal
            }
        )
        .starts_with("attempt: too far;"));
        assert!(line(
            OutcomeKind::Uncertain,
            0.0,
            &AttemptFacts {
                rgb_face: Some((0.85, 0.5)),
                ..frontal
            }
        )
        .starts_with("attempt: off-center;"));
        assert!(line(
            OutcomeKind::Spoof,
            0.0,
            &AttemptFacts {
                yaw_asym: 0.52,
                glint: Some(72.0),
                ..frontal
            }
        )
        .starts_with("attempt: looking away;"));
        assert!(line(
            OutcomeKind::Uncertain,
            0.0,
            &AttemptFacts {
                rgb_face_brightness: 30.0,
                ..frontal
            }
        )
        .starts_with("attempt: too dark;"));
        assert!(line(
            OutcomeKind::Uncertain,
            0.0,
            &AttemptFacts {
                glint: Some(72.0),
                ..frontal
            }
        )
        .starts_with("attempt: glint below;"));
        assert!(
            line(OutcomeKind::BelowThreshold, 0.44, &frontal).starts_with("attempt: below score;")
        );
        assert!(line(OutcomeKind::Spoof, 0.0, &frontal).starts_with("attempt: spoof;"));
        assert!(line(OutcomeKind::OtherDeny, 0.0, &frontal).starts_with("attempt: other;"));
        // Every vocabulary label is reachable and the enum stays closed.
        assert_eq!(
            super::attempt_situation_label(AttemptSituation::LookingAway),
            "looking away"
        );
    }

    #[test]
    fn attempt_situation_line_is_numbers_only_and_stable() {
        use super::{attempt_situation_line, AttemptFacts, OutcomeKind};
        // One exact rendering pins the format: fixed field order, n/a for an
        // unmeasured glint (a railed peak measured nothing, #222), and no
        // threshold values anywhere in the line.
        let facts = AttemptFacts {
            rgb_face: None,
            face_frac: 0.0,
            yaw_asym: 0.10,
            rgb_face_brightness: 0.0,
            glint: None,
            ir_bright: 140.0,
            persistent_ir_source_overwhelms: false,
        };
        assert_eq!(
            attempt_situation_line(OutcomeKind::NoFace, 0.0, &facts),
            "attempt: no face; face_frac=0.00 yaw=0.10 glint=n/a ir_bright=140 rgb_bright=0 score=0.00"
        );
    }

    #[test]
    fn attempt_situation_precedence_explains_the_user_before_the_attack_label() {
        use super::{auth_attempt_situation, AttemptFacts, AttemptSituation, OutcomeKind};
        // The #617 lesson lives here too: a live person glancing sideways
        // produced a Spoof verdict; the situation names looking away.
        let turned = AttemptFacts {
            rgb_face: Some((0.5, 0.5)),
            face_frac: 0.30,
            yaw_asym: 0.52,
            rgb_face_brightness: 120.0,
            glint: Some(72.0),
            ir_bright: 140.0,
            persistent_ir_source_overwhelms: false,
        };
        assert_eq!(
            auth_attempt_situation(OutcomeKind::Spoof, &turned),
            AttemptSituation::LookingAway
        );
        // The framing guide's severity order holds: a tiny face that is also
        // off-center names too far first.
        let messy = AttemptFacts {
            face_frac: 0.08,
            rgb_face: Some((0.85, 0.5)),
            ..turned
        };
        assert_eq!(
            auth_attempt_situation(OutcomeKind::Uncertain, &messy),
            AttemptSituation::TooFar
        );
        // A genuine below-threshold miss with clean framing names below score.
        let clean = AttemptFacts {
            yaw_asym: 0.10,
            glint: Some(250.0),
            ..turned
        };
        assert_eq!(
            auth_attempt_situation(OutcomeKind::BelowThreshold, &clean),
            AttemptSituation::BelowScore
        );
        // The dark path enters with no RGB face by design; its failures are
        // not "no face" when the IR side saw one.
        assert_eq!(
            auth_attempt_situation(
                OutcomeKind::BelowThreshold,
                &AttemptFacts {
                    rgb_face: None,
                    face_frac: 0.28,
                    yaw_asym: 0.10,
                    glint: Some(250.0),
                    ..turned
                }
            ),
            AttemptSituation::BelowScore
        );
        // No detection anywhere is no face, whatever the kind claims.
        assert_eq!(
            auth_attempt_situation(
                OutcomeKind::Uncertain,
                &AttemptFacts {
                    rgb_face: None,
                    face_frac: 0.0,
                    glint: None,
                    ir_bright: 0.0,
                    ..turned
                }
            ),
            AttemptSituation::NoFace
        );
    }

    #[test]
    fn attempt_facts_snapshot_the_assessment() {
        use super::AttemptFacts;
        use irlume_liveness::{FaceBox, Signals, Verdict};
        let a = super::Assessment {
            verdict: Verdict::Uncertain,
            reason: "test".into(),
            embedding: None,
            ir_embedding: None,
            signals: Signals {
                rgb_face: Some(FaceBox {
                    cx: 0.25,
                    cy: 0.75,
                    score: 0.9,
                }),
                ir_face: Some(FaceBox {
                    cx: 0.5,
                    cy: 0.5,
                    score: 0.8,
                }),
                ir_face_brightness: 150.0,
                ir_center_edge_ratio: 1.2,
                ir_eye_glint: None,
                head_yaw_asym: 0.42,
                head_pitch_frac: 0.5,
                ir_ambient: 30.0,
                face_frac: 0.22,
                ir_saturated_frac: None,
                ir_persistent_saturated_frac: None,
                ir_ceiling_known: false,
                rgb_face_brightness: 90.0,
                rgb_moire_score: 0.0,
                rgb_specular_frac: 0.0,
            },
            ir_center_edge_ratio: 1.2,
            ir_brightness: 150.0,
            ir_ambient_share: None,
            rgb_frame_mean: 60.0,
            shipped_ir_fake: None,
            rgb_pad: PadEvidence::NotApplicable,
            ir_pad: PadEvidence::NotApplicable,
            sequential_pair: false,
        };
        let facts = AttemptFacts::from_assessment(&a);
        assert_eq!(facts.rgb_face, Some((0.25, 0.75)));
        assert_eq!(facts.face_frac, 0.22);
        assert_eq!(facts.yaw_asym, 0.42);
        assert_eq!(facts.rgb_face_brightness, 90.0);
        assert_eq!(facts.glint, None);
        assert_eq!(facts.ir_bright, 150.0);
        assert!(!facts.persistent_ir_source_overwhelms);
    }

    #[test]
    fn ir_source_situation_requires_persistent_clipping_and_a_failed_cue() {
        use super::{
            auth_attempt_situation, liveness_deny_kind, Assessment, AttemptFacts, AttemptSituation,
            OutcomeKind,
        };
        use irlume_liveness::{FaceBox, LivenessGate, Signals, Verdict};

        let base = Signals {
            rgb_face: Some(FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.9,
            }),
            ir_face: Some(FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.9,
            }),
            ir_face_brightness: 90.0,
            ir_center_edge_ratio: 1.2,
            ir_eye_glint: Some(220.0),
            face_frac: 0.30,
            ir_saturated_frac: Some(0.0),
            ir_ceiling_known: true,
            rgb_face_brightness: 120.0,
            ..Default::default()
        };
        let situation = |signals: Signals, kind: OutcomeKind| {
            let ir_brightness = signals.ir_face_brightness;
            let assessment = Assessment {
                verdict: Verdict::Spoof,
                reason: "failed liveness assessment".into(),
                embedding: None,
                ir_embedding: None,
                signals,
                ir_center_edge_ratio: 0.0,
                ir_brightness,
                ir_ambient_share: None,
                rgb_frame_mean: 0.0,
                shipped_ir_fake: None,
                rgb_pad: PadEvidence::NotApplicable,
                ir_pad: PadEvidence::NotApplicable,
                sequential_pair: false,
            };
            auth_attempt_situation(kind, &AttemptFacts::from_assessment(&assessment))
        };

        for cue in ["dark", "flat"] {
            let mut thinkpad = base.clone();
            thinkpad.ir_persistent_saturated_frac = Some(0.1702);
            match cue {
                "dark" => {
                    thinkpad.ir_face_brightness = 20.0;
                    thinkpad.rgb_face_brightness = 30.0;
                }
                "flat" => thinkpad.ir_center_edge_ratio = 1.0,
                _ => unreachable!(),
            }
            let (verdict, _, reason) = LivenessGate::new().evaluate(&thinkpad);
            assert_eq!(verdict, Verdict::Spoof, "{cue}: {reason}");
            let kind = liveness_deny_kind(verdict, &reason);
            assert_eq!(kind, OutcomeKind::Spoof, "{cue}: {reason}");
            assert_eq!(
                situation(thinkpad.clone(), kind),
                AttemptSituation::IrSource,
                "{cue}: {reason}"
            );

            let mut turned = thinkpad;
            turned.head_yaw_asym = 0.52;
            assert_eq!(
                situation(turned, kind),
                AttemptSituation::LookingAway,
                "framing and orientation must keep precedence"
            );
        }

        for fraction in [Some(0.0031), None] {
            let mut dark = base.clone();
            dark.ir_face_brightness = 20.0;
            dark.ir_persistent_saturated_frac = fraction;
            let (verdict, _, reason) = LivenessGate::new().evaluate(&dark);
            assert_eq!(verdict, Verdict::Spoof, "fraction {fraction:?}: {reason}");
            let kind = liveness_deny_kind(verdict, &reason);
            assert_eq!(
                situation(dark, kind),
                AttemptSituation::Spoof,
                "fraction {fraction:?}: {reason}"
            );
        }

        let mut healthy = base;
        healthy.ir_persistent_saturated_frac = Some(0.1702);
        let (verdict, _, reason) = LivenessGate::new().evaluate(&healthy);
        assert_eq!(verdict, Verdict::Live, "{reason}");
        assert_eq!(
            situation(healthy, OutcomeKind::BelowThreshold),
            AttemptSituation::BelowScore,
            "persistent clipping without a dark or flat cue is not IR source"
        );
        assert_eq!(
            super::attempt_situation_label(AttemptSituation::IrSource),
            "IR source"
        );
    }

    #[test]
    fn ir_source_rewording_does_not_change_the_liveness_deny_kind() {
        use irlume_liveness::{FaceBox, LivenessGate, Signals, Verdict};

        let old = Signals {
            rgb_face: Some(FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.9,
            }),
            ir_face: Some(FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.9,
            }),
            ir_face_brightness: 90.0,
            ir_center_edge_ratio: 1.0,
            ir_eye_glint: Some(220.0),
            ir_saturated_frac: Some(0.0),
            ir_persistent_saturated_frac: Some(0.0031),
            ir_ceiling_known: true,
            ..Default::default()
        };
        let mut reworded = old.clone();
        reworded.ir_persistent_saturated_frac = Some(0.1702);

        let gate = LivenessGate::new();
        let (old_verdict, _, old_reason) = gate.evaluate(&old);
        let (new_verdict, _, new_reason) = gate.evaluate(&reworded);
        assert_eq!(old_verdict, Verdict::Spoof, "{old_reason}");
        assert_eq!(new_verdict, Verdict::Spoof, "{new_reason}");
        assert!(!old_reason.contains("IR-bright source"), "{old_reason}");
        assert!(new_reason.contains("IR-bright source"), "{new_reason}");
        assert_eq!(
            super::liveness_deny_kind(old_verdict, &old_reason),
            super::liveness_deny_kind(new_verdict, &new_reason)
        );
        assert_eq!(
            super::liveness_deny_kind(new_verdict, &new_reason),
            super::OutcomeKind::Spoof
        );
    }

    #[test]
    fn grey_mean_in_bbox_measures_only_the_face_region() {
        use super::grey_mean_in_bbox;
        // A 8x4 grey frame: dark everywhere except a bright face region.
        let (w, h) = (8u32, 4u32);
        let mut data = vec![10u8; (w * h) as usize];
        // Face box: x 2..=5, y 1..=2 (pixels), all at 200.
        for y in 1..=2 {
            for x in 2..=5 {
                data[(y * w + x) as usize] = 200;
            }
        }
        let mean = grey_mean_in_bbox(&data, w, h, &[2.0, 1.0, 6.0, 3.0]);
        assert_eq!(mean, 200.0, "the region mean, not the frame mean");
        // The whole frame including the dark surround reads far lower: that
        // gap is exactly the #613 defect this helper exists to close.
        let whole = grey_mean_in_bbox(&data, w, h, &[0.0, 0.0, w as f32, h as f32]);
        assert!(whole < 60.0, "whole-frame mean stays low: {whole}");
        // Clamping: a box that runs past the frame edge measures exactly the
        // pixels that exist. Hand-computed: x 2..8, y 1..2 holds four bright
        // pixels (200) and two dark ones (10) => (4*200 + 2*10) / 6.
        let clamped = grey_mean_in_bbox(&data, w, h, &[2.0, 1.0, 99.0, 2.0]);
        assert!(
            (clamped - 820.0 / 6.0).abs() < 0.01,
            "hand-computed: {clamped}"
        );
        // A box entirely outside the face reads the surround, never indexes
        // out of bounds.
        assert_eq!(
            grey_mean_in_bbox(&data, w, h, &[6.0, 3.0, 99.0, 99.0]),
            10.0
        );
        // A degenerate box measures nothing and says so with 0.0.
        assert_eq!(grey_mean_in_bbox(&data, w, h, &[3.0, 2.0, 3.0, 2.0]), 0.0);
    }

    #[test]
    fn subject_region_preflight_is_dark_only_for_a_present_unlit_face() {
        use super::ir_preflight_subject_lit;
        // #613's camera: the whole frame reads ~20 while the lit face reads
        // 137-158. Measured at the face, the working camera is clearly lit.
        assert!(matches!(ir_preflight_subject_lit(Some(137.0)), Ok(true)));
        assert!(matches!(ir_preflight_subject_lit(Some(158.0)), Ok(true)));
        // A present face the emitter does not light is the honest dark case
        // (#618's refusal trigger): the sock measurement, face region 0.
        assert!(matches!(ir_preflight_subject_lit(Some(19.0)), Ok(false)));
        assert!(matches!(ir_preflight_subject_lit(Some(0.0)), Ok(false)));
        // No face in the preflight frame is INCONCLUSIVE, never dark: an
        // empty frame cannot testify about the emitter, and a dark refusal
        // must not fire on it.
        let no_face = ir_preflight_subject_lit(None);
        assert!(no_face.is_err(), "no face is inconclusive: {no_face:?}");
        assert!(
            no_face.unwrap_err().to_string().contains("inconclusive"),
            "the error names its meaning"
        );
    }

    #[test]
    fn dark_ir_preflight_refuses_enrollment_that_could_never_authenticate() {
        let _g = env_guard();
        let mut s = shared();
        let dir = state_sandbox("dark-ir-enroll");
        s.engine.ir_available = true;
        // A dark preflight on a pair the empty sandbox store cannot authorize
        // (no concurrent qualification) must refuse up front instead of
        // storing an RGB-only profile: on a sequential pair identity requires
        // an IR-verified match, so that profile would be refused forever.
        let err = s
            .engine
            .enroll_profile_with_ir_preflight("irlume-test-dark", None, 1, |_| false)
            .unwrap_err();
        assert!(err.to_string().contains("authenticates by IR"), "{err}");
        assert!(err.to_string().contains("could never unlock"), "{err}");
        assert!(
            !dir.join("irlume-test-dark.json").exists(),
            "a refused enrollment must not store anything"
        );
        // A lit preflight passes the gate and fails later at the camera for a
        // camera reason: the dark-IR refusal must not fire.
        let err = s
            .engine
            .enroll_profile_with_ir_preflight("irlume-test-dark", None, 1, |_| true)
            .unwrap_err();
        assert!(
            !err.to_string().contains("authenticates by IR"),
            "a lit preflight must not hit the dark-IR refusal: {err}"
        );
        // add-scan shares the same gate.
        let mut e = Enrollment::new("irlume-test-dark2");
        e.profiles.push(FaceProfile {
            name: "P1".into(),
            scans: vec![scan512(1, false, None)],
            ir_calib: None,
            ir_calibs: Default::default(),
        });
        write_enrollment(&dir, &e);
        let err = s
            .engine
            .add_scan_with_ir_preflight("irlume-test-dark2", "P1", 1, |_| false)
            .unwrap_err();
        assert!(err.to_string().contains("authenticates by IR"), "{err}");
        // The convenience tier is untouched: with no IR pair at all the
        // preflight must not even be consulted, and the enrollment proceeds.
        s.engine.ir_available = false; // restore the shared baseline
        let err = s
            .engine
            .enroll_profile_with_ir_preflight("irlume-test-dark", None, 1, |_| {
                panic!("the preflight must not run when no IR pair exists")
            })
            .unwrap_err();
        assert!(!err.to_string().contains("authenticates by IR"), "{err}");
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
        let emitter_touched = std::cell::Cell::new(false);
        let err = s
            .engine
            .add_scan_with_ir_preflight("irlume-test-ghost", "P1", 1, |_| {
                emitter_touched.set(true);
                true
            })
            .unwrap_err();
        assert!(err.to_string().contains("is not enrolled"), "{err}");
        assert!(
            !emitter_touched.get(),
            "an unknown enrollment must be refused before emitter preflight"
        );
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
    fn rescue_detect_declines_faceless_frames_and_missing_models() {
        let _g = env_guard();
        let mut s = shared();
        let (w, h) = (64u32, 64u32);
        let flat = vec![127u8; (w * h * 3) as usize];
        let view = CanonicalRgbView::try_from_parts(&flat, w, h).expect("valid fixture");
        // Both rescue models loaded, but no face in the frame.
        assert!(s.engine.has_blaze_rescue() && s.engine.has_mesh());
        assert!(s.engine.rescue_detect(view, "test").is_none());
        // With BlazeFace missing the cascade stage is simply absent.
        let blaze = s.engine.blaze.take();
        assert!(s.engine.rescue_detect(view, "test").is_none());
        s.engine.blaze = blaze;
        // Same when only the mesh refiner is missing.
        let mesh = s.engine.mesh.take();
        assert!(s.engine.rescue_detect(view, "test").is_none());
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

    /// `release_held` must HAND THE CAMERA BACK, which is the whole reason the
    /// grant paths call it before `challenge_if_required` opens its own IR
    /// stream for the consent watch.
    ///
    /// The bug this pins: `held` used to be `&mut Option<(&mut RgbSession,
    /// &mut IrSession)>`, so every release site dropped a pair of REFERENCES
    /// while the sessions themselves stayed alive in `authenticate_for`. The
    /// watch's `S_FMT` and `REQBUFS` then hit EBUSY against this same process,
    /// the self-collision #187 diagnosed, and a successful match was thrown
    /// away for a password prompt. Introduced by #346, so it never shipped.
    ///
    /// The CONTROL is the point: a second stream must FAIL while the session
    /// is alive, or this test cannot tell a working release from a camera that
    /// was never held in the first place.
    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_release_held_hands_the_camera_back() {
        let (rgb, ir) = loopback_pair();
        let _g = env_guard();
        let operation = irlume_camera::lease::acquire_camera_operation(
            &[rgb.as_str(), ir.as_str()],
            irlume_camera::lease::CameraOperationKind::Capture,
            std::time::Duration::from_secs(2),
        )
        .expect("acquire one RGB+IR operation");
        let cam = operation.open_ir(&ir).expect("open the IR node");
        let rgb_cam = operation.open_rgb(&rgb).expect("open the RGB node");
        let mut held_ir = Some(cam.session().expect("hold an IR session"));
        // BOTH halves must release: the review round noted the test proved
        // only the IR side, and release_held drops two owners.
        let mut held_rgb = Some(rgb_cam.session().expect("hold an RGB session"));

        // Control: with the session alive, a second stream on the same node
        // must be refused. If this passes, the rest proves nothing.
        let busy_ir = cam.session();
        let busy_rgb = rgb_cam.session();
        assert!(
            busy_ir.is_err() && busy_rgb.is_err(),
            "control failed: live IR and RGB sessions must each block a second stream, or this \
             test cannot distinguish a real release from a camera nobody held"
        );

        release_held(&mut held_rgb, &mut held_ir);
        assert!(
            held_ir.is_none() && held_rgb.is_none(),
            "the release must clear BOTH session slots"
        );

        // The observation: the original cameras accept fresh sessions after
        // release_held drops both owners and their per-camera slots reset.
        let mut after = cam.session().expect("open IR session after release");
        let after_capture = after.capture_with_stats();
        assert!(
            after_capture.is_ok(),
            "after release the consent watch must be able to capture from its own \
             stream, got {:?}",
            after_capture.err()
        );
        drop(after);
        // The RGB half too: the original camera's session slot must reopen.
        let mut rgb_after = rgb_cam.session().expect("open RGB session after release");
        assert!(
            rgb_after.frame().is_ok(),
            "after release an RGB session must be able to capture a frame"
        );
    }

    /// Full `authenticate()` through the LIVE capture pipeline, against the
    /// v4l2loopback feeder nodes CI provides: opens both devices, runs the
    /// parallel RGB+IR capture, detection, and the deny mapping. The ffmpeg
    /// test pattern holds no face, so the outcome must be a clean denial,
    /// not an error, with a face-shaped reason. Env-gated like the camera
    /// crate's loopback tests.

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_legacy_unqualified_attempt_contract_is_available() {
        let (rgb, ir) = loopback_pair();
        let _g = env_guard();
        let operation = irlume_camera::lease::acquire_camera_operation(
            &[rgb.as_str(), ir.as_str()],
            irlume_camera::lease::CameraOperationKind::Capture,
            std::time::Duration::from_secs(2),
        )
        .expect("acquire one RGB+IR operation");
        let rgb_camera = operation.open_rgb(&rgb).expect("open the RGB node");
        let ir_camera = operation.open_ir(&ir).expect("open the IR node");
        let runtime = irlume_camera::runtime_pair_contract_from_cameras(&rgb_camera, &ir_camera)
            .expect("bind the loopback runtime pair");

        irlume_camera::attempt_contract::CameraAttemptContract::from_legacy_unqualified_runtime(
            runtime,
            irlume_camera::profile::CaptureSchedule::Sequential,
        )
        .expect("the production loopback tuple must retain the legacy sequential path");
    }

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

    fn still_poses() -> Vec<irlume_liveness::PoseSample> {
        (0..20)
            .map(|idx| irlume_liveness::PoseSample {
                idx,
                pitch_frac: Some(0.5),
                yaw_signed: Some(0.0),
                bri: 60.0,
            })
            .collect()
    }

    fn wide_shake_poses(len: usize) -> Vec<irlume_liveness::PoseSample> {
        (0..len)
            .map(|idx| irlume_liveness::PoseSample {
                idx,
                pitch_frac: Some(0.5),
                yaw_signed: Some(match idx * 7 / len {
                    0 | 4 => -0.9,
                    2 | 6 => 0.9,
                    _ => 0.0,
                }),
                bri: 60.0,
            })
            .collect()
    }

    fn trailing_shake_poses(tail: usize) -> Vec<irlume_liveness::PoseSample> {
        let trailing = [-0.9, 0.0, 0.9, 0.0, -0.9, 0.0, 0.9];
        (0..18 + tail)
            .map(|idx| irlume_liveness::PoseSample {
                idx,
                pitch_frac: Some(0.5),
                yaw_signed: Some(if idx < 18 { 0.0 } else { trailing[idx - 18] }),
                bri: 60.0,
            })
            .collect()
    }

    #[test]
    fn completed_take_reports_nod_and_shake_as_distinct_terminal_verdicts() {
        assert_eq!(
            head_consent_from_poses(&boundary_poses()),
            HeadConsentVerdict::Approve
        );
        assert_eq!(
            head_consent_from_poses(&wide_shake_poses(20)),
            HeadConsentVerdict::Decline
        );
        assert_eq!(
            head_consent_from_poses(&still_poses()),
            HeadConsentVerdict::NoGesture
        );
    }

    #[test]
    fn completed_head_take_catches_a_repeated_trailing_shake() {
        let poses = trailing_shake_poses(7);
        assert_eq!(
            head_consent_from_poses(&poses[..18]),
            HeadConsentVerdict::NoGesture,
            "the last in-loop check must not already contain the shake"
        );
        assert_eq!(
            resolve_head_consent(None, || head_consent_from_poses(&poses)),
            HeadConsentVerdict::Decline,
            "the trailing frames must complete a repeated typed decline"
        );
    }

    #[test]
    fn head_consent_api_is_pose_only() {
        let classify: fn(&[irlume_liveness::PoseSample]) -> HeadConsentVerdict =
            head_consent_from_poses;
        assert_eq!(classify(&boundary_poses()), HeadConsentVerdict::Approve);
    }

    #[test]
    fn stream_verdict_is_terminal_before_completed_take() {
        assert_eq!(
            resolve_head_consent(Some(HeadConsentVerdict::Decline), || panic!("must not run")),
            HeadConsentVerdict::Decline
        );
        assert_eq!(
            resolve_head_consent(Some(HeadConsentVerdict::Approve), || panic!("must not run")),
            HeadConsentVerdict::Approve
        );
    }

    #[test]
    fn completed_take_catches_a_nod_in_the_trailing_frames() {
        let poses = boundary_poses();
        // The premise first: the prefix the last in-loop check saw must NOT
        // read as a nod, or this test is not about the boundary at all.
        assert_ne!(
            irlume_liveness::detect_head_gesture(&poses[..18]),
            irlume_liveness::HeadGesture::Nod,
            "the 18-pose prefix must be flat"
        );
        // The full take carries the gesture, and the completed-take evaluation
        // must find it even though no in-loop check fired.
        assert!(completed_consent_take_hit(false, true, &poses));
        // Removing the completed-take evaluation reduces the decision to
        // hit_in_loop, which is false here: that is the observation that
        // fails if the fix is reverted.
    }

    #[test]
    fn completed_take_respects_the_gesture_inputs() {
        let poses = boundary_poses();
        // With the nod disallowed, the same series
        // must NOT satisfy the gate: the final evaluation widens coverage of
        // the take, never the set of accepted gestures.
        assert!(!completed_consent_take_hit(false, false, &poses));
        // An in-loop hit stands on its own, whatever the series holds.
        assert!(completed_consent_take_hit(true, false, &[]));
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
        assert!(!completed_consent_take_hit(false, true, &poses));
    }

    #[test]
    fn ir_fallback_context_distinguishes_rgb_miss_from_sequential_deferral() {
        assert_eq!(
            ir_fallback_rgb_context(0.58, 0.61, false),
            "dim light; rgb 0.58<0.61",
        );
        assert_eq!(
            ir_fallback_rgb_context(0.76, 0.61, true),
            "sequential pair required IR verification; rgb 0.76>=0.61",
        );
    }

    #[test]
    fn deferred_loader_resolution_fails_closed_on_every_arm() {
        // Every way the deferred enrollment load can end, through a real
        // channel; the join in authenticate_for_with_diagnostics is exactly
        // this mapping, so its fail-closed contract is pinned here without
        // camera hardware.
        // A finished load passes through, even at zero remaining deadline.
        let (tx, rx) = std::sync::mpsc::channel::<EnrollmentLoad>();
        tx.send(Ok(Some(Enrollment::new("u")))).unwrap();
        drop(tx);
        assert!(resolve_loader(rx.recv_timeout(std::time::Duration::ZERO)).is_ok());

        // A store that vanished between the pre-check and the read is the
        // not-enrolled deny, not an error.
        let (tx, rx) = std::sync::mpsc::channel::<EnrollmentLoad>();
        tx.send(Ok(None)).unwrap();
        drop(tx);
        assert!(matches!(
            resolve_loader(rx.recv_timeout(std::time::Duration::ZERO)),
            Err(LoaderExit::NotEnrolled)
        ));

        // A load error is the fallback, propagated verbatim.
        let (tx, rx) = std::sync::mpsc::channel::<EnrollmentLoad>();
        tx.send(Err(irlume_common::Error::Io("unreadable".into())))
            .unwrap();
        drop(tx);
        assert!(matches!(
            resolve_loader(rx.recv_timeout(std::time::Duration::ZERO)),
            Err(LoaderExit::Fallback(irlume_common::Error::Io(_)))
        ));

        // A load that outlives the authentication deadline fails closed.
        let (tx, rx) = std::sync::mpsc::channel::<EnrollmentLoad>();
        let resolved = resolve_loader(rx.recv_timeout(std::time::Duration::from_millis(1)));
        match resolved {
            Err(LoaderExit::Fallback(irlume_common::Error::Protocol(msg))) => {
                assert!(msg.contains("deadline"), "{msg}");
            }
            other => panic!("deadline expiry must fail closed to the password: {other:?}"),
        }
        drop(tx);

        // A sender dropped without a result (the loader panicked) fails
        // closed with its own reason, distinct from the deadline.
        let (tx, rx) = std::sync::mpsc::channel::<EnrollmentLoad>();
        drop(tx);
        match resolve_loader(rx.recv_timeout(std::time::Duration::from_secs(1))) {
            Err(LoaderExit::Fallback(irlume_common::Error::Protocol(msg))) => {
                assert!(msg.contains("loader failed"), "{msg}");
            }
            other => panic!("a panicked loader must fail closed: {other:?}"),
        }
    }
}
