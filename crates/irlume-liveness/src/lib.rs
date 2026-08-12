// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Algorithmic IR presentation-attack detection (PAD): NO trained weights.
//!
//! Why no model: every public anti-spoof dataset is non-commercial, so a trained
//! PAD model is license-tainted. We gate on documented physics instead, which is
//! license-clean and (for the NIR cue) demographically fair.
//!
//! The gate is HARD: any failing cue rejects. The signals are computed upstream
//! (camera + detector); this crate applies the decision thresholds.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Live,
    Spoof,
    Uncertain,
}

/// A detected face reduced to normalized center (0..1) + detector score.
#[derive(Debug, Clone, Copy)]
pub struct FaceBox {
    pub cx: f32,
    pub cy: f32,
    pub score: f32,
}

/// The physical signals the gate decides on (computed from RGB + IR captures).
#[derive(Debug, Clone)]
pub struct Signals {
    /// Top face in the RGB frame, if any.
    pub rgb_face: Option<FaceBox>,
    /// Top face in the IR frame, if any (a screen/print won't reflect 850nm IR
    /// like skin, so it usually yields no IR face).
    pub ir_face: Option<FaceBox>,
    /// Mean brightness (0..255) inside the IR face region; skin reflects the
    /// active emitter strongly; a screen/print does not.
    pub ir_face_brightness: f32,
    /// Center-to-edge IR brightness ratio in the face region. A real 3D face lit
    /// by a near-coaxial emitter is brighter at the center/nose and falls off at
    /// the edges (ratio > 1); a flat photo/screen is more uniform (~1). Anti-flat.
    pub ir_center_edge_ratio: f32,
    /// Peak IR brightness (0..255) at the eyes: the emitter's specular corneal
    /// glint. Supporting cue only (glint alone is not decisive).
    ///
    /// `None` = the reading established nothing, and it is NOT a dark eye. Three
    /// ways to get there: no IR face was found, the RGB-only path ran (no IR
    /// frame at all), or the peak reached the negotiated format's ceiling, where
    /// a clipped sample says the value was AT LEAST that and never what it was.
    ///
    /// The railed case is #222, and it is the common one rather than a corner:
    /// with glasses on the peak pinned at 255 in all 30 frames measured
    /// 2026-08-04, reading the lens specular rather than the cornea, and in
    /// `docs/pad-results/2026-08-04-occluder-gate.jsonl` all 8 records that
    /// recorded a glint are railed at exactly 255, so "glint present" and "the
    /// peak railed" name the same set. A cue recorded that way cannot separate
    /// two populations, which is what re-deriving [`GLINT_MIN`] would need.
    ///
    /// `None` is NOT zero: the same distinction [`Signals::ir_saturated_frac`]
    /// draws, and it exists so a maximum nobody could measure is never recorded
    /// as one that was.
    pub ir_eye_glint: Option<f32>,
    /// Head-orientation yaw asymmetry from the RGB face landmarks (0 frontal,
    /// →1 turned). Defaults to 0 (frontal) when not computed.
    pub head_yaw_asym: f32,
    /// Head-orientation pitch fraction (0.5 frontal; lower = chin down, higher =
    /// chin up). Defaults to 0.5 (frontal) when not computed.
    pub head_pitch_frac: f32,
    /// Mean RGB-face luma (0–255). RGB-only path: the face must be lit enough to
    /// recognize. Unused on the IR path.
    pub rgb_face_brightness: f32,
    /// Fraction (0–1) of near-white pixels in the RGB face region; RGB-only
    /// screen/glare deterrent cue. Unused on the IR path.
    pub rgb_specular_frac: f32,
    /// High-frequency spectral peakiness of the RGB face region (2D-FFT moiré /
    /// pixel-grid cue); RGB-only screen-replay deterrent. Unused on the IR path.
    pub rgb_moire_score: f32,
    /// Ambient IR level (0–255): mean of the darkest (unlit) frame in the IR
    /// capture burst, i.e. the scene's own infrared with the emitter off. 0.0 =
    /// not measured (RGB-only path, older callers); the flood rewording below
    /// then never triggers. See [`IR_AMBIENT_FLOOD`].
    pub ir_ambient: f32,
    /// Whether the negotiated IR format defines where its sensor ceiling is,
    /// i.e. whether [`Self::ir_saturated_frac`] could be measured at all.
    ///
    /// Separate from `ir_saturated_frac` being `None`, which is ambiguous:
    /// `saturated_frac_of` also yields `None` when no face was detected. The
    /// evaluators happen to require an IR face before they reach the exposure
    /// gate, so today the two cannot be confused there, but that is a distant
    /// invariant in another crate and the gate now states its own precondition
    /// rather than inheriting one (#358).
    ///
    /// Defaults to FALSE, the fail-safe direction: a `Signals` nobody filled in
    /// measured no ceiling, and a permissive default here is what let the gate
    /// pass unread frames in the first place.
    pub ir_ceiling_known: bool,
    /// Face width as a fraction of frame width, from the frame the IR cues
    /// were measured in (the RGB frame on the RGB-only path). 0.0 when no
    /// face was found.
    ///
    /// RECORDED, NEVER GATED. The framing guide accepts 0.12 to 0.55, a 4.6x
    /// span, and several cues above are absolute thresholds on quantities
    /// that could move across it. Which ones do is now measured (#174 thread,
    /// 2026-08-04, ASUS FHD IR module, one subject, 40 bona-fide
    /// presentations through this gate at ~30 cm, normal seating, and
    /// ~80 cm): [`ir_face_brightness`] falls 1.8x across that band, the
    /// [`ir_center_edge_ratio`] stays inside 1.39-1.56 with overlap at every
    /// distance, and the glint peak tracks eyewear, not seating. The field
    /// itself is a working 1/d proxy: face_frac times tape-measured distance
    /// came out 9.3, 9.0 and 10.7 at 20, 45 and 67.5 cm (#174 thread).
    ///
    /// No cue is normalised by it, and the measurements are the reason, not
    /// an omission: the module's firmware runs its own auto-exposure with no
    /// v4l2 exposure control exposed, so raw brightness is an AE output
    /// rather than irradiance, and dividing it by face_frac squared tracks
    /// the AE instead of the physics (measured 87 at 67.5 cm where 1/d^2
    /// from the 45 cm baseline predicts 43, #174 thread); for the ratio, the
    /// available one-subject, one-module measurements do not justify a
    /// distance term in the measured band. The field stays recorded so
    /// padcapture corpora and the debug lines can re-answer the question on
    /// other modules and outside 20 to 80 cm, where nothing is measured.
    ///
    /// [`ir_face_brightness`]: Self::ir_face_brightness
    /// [`ir_center_edge_ratio`]: Self::ir_center_edge_ratio
    pub face_frac: f32,
    /// Fraction (0-1) of the IR face region at or above the sensor's ceiling,
    /// or `None` when the reading could not be taken: no IR face, the RGB-only
    /// path, or a negotiated format the camera crate declines to give a ceiling
    /// for (the Y16 family is rescaled per frame, so its 255 is the frame's own
    /// maximum; NV12 and YUYV are declined so that a colour stream placed in
    /// the IR slot is refused rather than judged; resolving their `Default`
    /// quantization needs the colorspace AND the Y'CbCr encoding, and the
    /// pinned v4l crate drops the encoding, so it stays uncomputable; the
    /// refusal is the load-bearing part either way, see
    /// `clipping_white_level` and #385). `None` is NOT zero clipping.
    ///
    /// GATED since #237, at [`IR_SATURATED_FRAC_MAX`]. Saturation compresses
    /// [`ir_center_edge_ratio`] toward 1 the way an ambient pedestal does,
    /// because a clipped centre cannot read brighter than a clipped rim, and it
    /// starves the third-party PAD model of the texture it scores: measured
    /// against a flat vinyl print on one ASUS module, `p_fake` fell 1.000,
    /// 0.998, 0.963, 0.749 at 0.3%, 5.3%, 8.8% and 24.8% clipped, so past
    /// roughly 13% the cue drops below its own 0.90 deny threshold, abstains,
    /// and the print is left facing only cues it already clears (#237).
    /// Clipping weakens the evidence on both sides at once, which is why this
    /// end is refused rather than interpreted.
    ///
    /// [`face_frac`]: Self::face_frac
    /// [`ir_center_edge_ratio`]: Self::ir_center_edge_ratio
    pub ir_saturated_frac: Option<f32>,
}

impl Default for Signals {
    fn default() -> Self {
        Self {
            rgb_face: None,
            ir_face: None,
            ir_face_brightness: 0.0,
            ir_center_edge_ratio: 0.0,
            ir_eye_glint: None,
            head_yaw_asym: 0.0,   // frontal
            head_pitch_frac: 0.5, // frontal
            face_frac: 0.0,
            ir_saturated_frac: None,
            rgb_face_brightness: 0.0,
            rgb_specular_frac: 0.0,
            rgb_moire_score: 0.0,
            ir_ambient: 0.0,
            ir_ceiling_known: false, // not measured
        }
    }
}

/// RGB-only convenience path: the face must be at least this bright to recognize.
pub const RGB_FACE_MIN_BRIGHTNESS: f32 = 60.0;
/// And not blown out (sunlight/overexposure makes recognition unreliable too).
pub const RGB_FACE_MAX_BRIGHTNESS: f32 = 245.0;
/// Above this near-white fraction in the face region, treat it as a screen/glare
/// spoof (deterrent-grade; emissive displays & glossy prints blow out).
pub const RGB_SPECULAR_MAX: f32 = 0.18;
/// Above this high-frequency spectral peakiness, treat the face region as a
/// display (periodic pixel-grid / moiré). DETERRENT-grade and hardware-specific.
/// Calibrated on the Shinetech RGB cam: a real lit face read ~9–13; a high-PPI
/// phone held VERY CLOSE (the best case for moiré) read only ~15–38, and moiré
/// weakens with distance, so at arm's length a replay would overlap real faces
/// entirely. This is NOT a strong PAD; the real mitigation for RGB-only is the
/// convenience-tier policy (lock-screen unlock only, never credential release).
///
/// PER-CAMERA SPREAD IS REAL (cross-distro survey 2026-07-01): a live face reads
/// 9–13 on the Zenbook's Shinetech but 18–27 on a ThinkPad Chicony; the old 18
/// hard-rejected a real user on the latter, and the two cameras' live/replay
/// ranges overlap so no universal threshold exists. 28 clears every observed
/// live face and still catches the top of the close-replay band (~30–38);
/// override per camera with IRLUME_RGB_MOIRE_MAX until enrollment-time
/// per-camera baselining lands.
pub const RGB_MOIRE_MAX: f32 = 28.0;

/// A value an environment override can carry into one of this crate's
/// thresholds: parsed from the variable's text, and printed back when it is
/// refused.
///
/// `is_comparable` is the half of the check [`env_override`] applies at every
/// site, so a new override cannot omit it the way the moiré ceiling did (#345).
/// The other half, the range a particular setting accepts, differs per setting
/// and stays at the call.
trait OverrideValue: std::str::FromStr + std::fmt::Display + Copy {
    /// False for a parsed value that cannot act as a threshold.
    fn is_comparable(&self) -> bool;
}

impl OverrideValue for f32 {
    /// NaN loses every comparison it takes part in, so a threshold holding it
    /// answers "over" and "under" alike with false and the cue reading against
    /// it can never fire. The infinities answer one side for every input, which
    /// is the same failure pointed the other way (#345).
    fn is_comparable(&self) -> bool {
        self.is_finite()
    }
}

impl OverrideValue for usize {
    /// Every `usize` a parse can produce is an ordinary integer; the frame
    /// counts carry their floors in their own range rule.
    fn is_comparable(&self) -> bool {
        true
    }
}

/// The text of `name`, or `None` when nothing was set.
///
/// Bytes that are not UTF-8 come back lossily rather than as `None`: they are
/// still a value somebody set, so they belong on the refusal path and its log
/// line, not on the silent unset path.
fn env_text(name: &str) -> Option<String> {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
}

/// Read `name` from the environment, falling back to `default`.
///
/// A supplied value takes effect only when it parses as `T`, is comparable, and
/// satisfies `accepts`, the range rule of the setting being read. Anything else
/// leaves `default` in place and reports one line naming the variable.
///
/// Every override in this crate goes through here. Before #345 each site
/// hand-rolled the same chain and the moiré ceiling was written without the
/// comparability filter, so `IRLUME_RGB_MOIRE_MAX=nan` reached the comparison
/// in [`LivenessGate::evaluate_rgb_only`] and made it false for every frame:
/// the only RGB anti-screen cue was off, and nothing said so.
fn env_override<T: OverrideValue>(
    name: &'static str,
    default: T,
    accepts: impl Fn(T) -> bool,
) -> T {
    resolve_override(
        std::io::stderr().lock(),
        name,
        env_text(name).as_deref(),
        default,
        accepts,
    )
}

/// [`env_override`] with the variable's text and the report's destination
/// supplied directly (`raw` of `None` means unset).
///
/// Both are parameters so that a test can drive the whole decision, including
/// the line it emits, without touching the process environment or stderr.
/// Mutating the environment of a running process is unsound on Unix whatever
/// lock the mutating threads agree on, because the readers that matter are in
/// libc and in dependencies that took no lock.
fn resolve_override<T: OverrideValue>(
    mut out: impl std::io::Write,
    name: &'static str,
    raw: Option<&str>,
    default: T,
    accepts: impl Fn(T) -> bool,
) -> T {
    let Some(raw) = raw else {
        return default; // unset: the built-in value stands and nothing was refused
    };
    let refused = match raw.trim().parse::<T>() {
        Ok(v) if !v.is_comparable() => "not a finite number",
        Ok(v) if !accepts(v) => "outside the range this setting accepts",
        Ok(v) => return v,
        Err(_) => "not a number",
    };
    if first_refusal(name) {
        // Reported unconditionally rather than through `dlog!`: diagnostic
        // tracing is off unless an administrator turns it on, and the moment
        // this line is worth having is the unlock where nobody yet knows the
        // setting was ignored. Same shape as the IRLUME_IR_EMITTER refusal in
        // irlume-camera.
        //
        // The write error is dropped, and `eprintln!` is not used, because that
        // macro panics when stderr fails (a closed, full, or non-blocking
        // journal stream). Panicking here would destroy the authentication this
        // function exists to hand a safe default to, which is a worse failure
        // than the one #345 fixed.
        let _ = writeln!(
            out,
            "irlume: ignoring {name}={raw:?} ({refused}); using {default}"
        );
    }
    default
}

/// True the first time `name` is refused in this process.
///
/// The moiré ceiling is read on every authentication and the blink thresholds
/// on every capture window, so printing per call would repeat the same line for
/// as long as the bad value stays in the unit file. One line per variable is
/// what makes it findable in the journal.
fn first_refusal(name: &'static str) -> bool {
    static REFUSED: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());
    // A panic under this lock elsewhere must not turn a logging decision into a
    // failed authentication.
    let mut seen = REFUSED.lock().unwrap_or_else(|e| e.into_inner());
    if seen.contains(&name) {
        return false;
    }
    seen.push(name);
    true
}

/// The effective moiré ceiling: `IRLUME_RGB_MOIRE_MAX` env override (per-camera
/// tuning, set on the daemon unit) or the built-in default.
///
/// Positive only. A ceiling of zero or below refuses every face with any
/// measurable peakiness, and the live readings this constant was calibrated
/// against run 9 to 27.
pub fn rgb_moire_max() -> f32 {
    env_override("IRLUME_RGB_MOIRE_MAX", RGB_MOIRE_MAX, |v| v > 0.0)
}

/// Per-cue evidence, surfaced for logging/self-test (never raw image data).
#[derive(Debug, Default, Clone)]
pub struct Cues {
    pub face_in_rgb: bool,
    /// Face present in IR; defeats screen/print attacks (the core cue).
    pub face_in_ir: bool,
    /// RGB and IR face roughly co-located; defeats RGB-deepfake + IR-blocker.
    pub cross_spectrum_aligned: bool,
    /// IR face region is brightly lit by the emitter (skin reflectance).
    pub ir_reflectance_ok: bool,
    /// The IR face region's center is brighter than its edges by at least
    /// [`MIN_CENTER_EDGE_RATIO`]. A lit 3D face produces that falloff and a flat
    /// surface held at the same distance usually does not, so it is evidence
    /// against a flat spoof. It is a brightness ratio, not a depth measurement:
    /// the sensor has no range-finding, and a glossy print with a hot center
    /// passes it (see docs/PAD_SELFTEST.md).
    pub center_edge_ratio_ok: bool,
    /// Corneal glint present (supporting; logged, not decisive).
    ///
    /// FALSE when the peak could not be read at all, not only when it was dim.
    /// [`Cues::glint_readable`] separates those two, because merging them is the
    /// same conflation this field used to carry from the other direction.
    pub glint_present: bool,
    /// The eye peak was IN BAND rather than at the sensor's ceiling (#222).
    ///
    /// Without this, `glint_present: false` would merge "the eye was dim" with
    /// "the reading railed and says nothing", and the corpus would trade one
    /// conflation for another. False also on the early-refusal paths where the
    /// cue is never reached, exactly like `glint_present`.
    pub glint_readable: bool,
    /// Face is frontal enough (≈±15°) to make a decision; Windows-Hello-style
    /// head-orientation gate.
    pub frontal_ok: bool,
    /// The IR face region is readable rather than blown out: at most
    /// [`IR_SATURATED_FRAC_MAX`] of it sits at the sensor ceiling. False means
    /// no cue below it was worth reading (#237).
    ///
    /// Read together with [`Self::ir_exposure_measured`]. This used to be true
    /// when the format could not say where its ceiling was, which recorded
    /// "clean" into the PAD corpus for frames the gate never read, on exactly
    /// the cameras where the question is hardest (#358).
    pub ir_exposure_ok: bool,
    /// Whether the exposure above was actually measured. False means the
    /// negotiated IR format defines no sensor ceiling, so nothing was read and
    /// `ir_exposure_ok` carries no information.
    pub ir_exposure_measured: bool,
}

/// IR face region must be at least this bright (0..255). A lit live face ran ~83
/// mean overall on the Shinetech module; the face region is brighter still. A
/// screen reflects far less 850nm.
///
/// Seating distance moves this cue more than any other (#174, measured
/// 2026-08-04, ASUS FHD IR module, 10 bona-fide presentations per condition):
/// settled readings were 112.0-136.0 at ~30 cm, 104.8-113.5 at normal
/// seating, and 75.1-96.2 at ~80 cm, a 1.8x fall. The weakest genuine
/// reading still clears this floor 2.1x, so the gate holds where users
/// actually sit, but the margin is a function of distance: re-measure the
/// far end before raising this. If a distance-aware form of this gate is
/// ever built, this absolute floor stays as a lower bound underneath it,
/// because a normalisation must never admit at any distance what the floor
/// refuses (#174).
pub const IR_FACE_MIN_BRIGHTNESS: f32 = 35.0;
/// Max normalized center distance between the RGB and IR face.
pub const CROSS_SPECTRUM_TOLERANCE: f32 = 0.30;
/// Minimum detector score to trust a face.
pub const MIN_FACE_SCORE: f32 = 0.6;
/// Center/edge IR brightness ratio above which the face region is treated as
/// having 3D falloff. Calibrated 2026-06-26: a real lit face measured 1.36; a
/// flat matte spoof is ~1.0. The 1.03 floor is lenient to avoid false-rejects
/// across poses, and that leniency is measured: a glossy IR print cleared it in
/// 69 of 70 trials (docs/pad-results/2026-06-30-ir-liveness-selftest.md). Treat
/// it as one weak cue, never as proof of a live face.
///
/// The 2026-08-04 campaign did not show a distance-separated ratio range:
/// across a 2.7x distance change (~30 to ~80 cm), all observed genuine values
/// remained within 1.39-1.56 and the condition ranges overlapped (#174). On
/// one subject and one ASUS module, that supplies no evidence for adding a
/// `face_frac` term in the measured band, but it does not establish that
/// distance has zero effect. Re-measure across subjects and modules before
/// generalising. Eyewear moves it more than seating did: bare-eyed 1.33-1.43
/// against glasses-on 1.44-1.53, disjoint ranges on the same subject at the
/// same distance. What does collapse the ratio is saturation up close, which
/// the exposure gate (#237) refuses before this cue reads it. A retune of the
/// 1.03 floor therefore argues against the flat-print attack range (a vinyl
/// print read 1.12-1.17 on the same cue, #235), not against distance.
pub const MIN_CENTER_EDGE_RATIO: f32 = 1.03;

/// Fraction of the IR face region at the sensor ceiling above which the frame
/// is refused as unreadable rather than judged.
///
/// A blown frame does not measure a face, and every cue that reads it degrades
/// together: the centre/edge ratio compresses toward the floor, and the
/// third-party PAD model's `p_fake` decays out of its deny range and into the
/// abstain band, so a flat print stops being denied by the one cue that
/// reliably denies it (#237). Whether that band was ever exercised with clipped
/// frames during the model's qualification is not recorded either way; what is
/// measured is the decay itself.
///
/// 10% sits between two measured populations on the ASUS module, dark room, one
/// subject: with clip-aware frame selection (#221) every genuine gate frame
/// measured at or below 6.3%, while the print needed roughly 13% before the PAD
/// cue went quiet (`p_fake` 0.963 at 8.8%, 0.749 at 24.8%). The margin either
/// side is under 4 points, so this is a floor set from one camera and one room;
/// widen the corpus before trusting it elsewhere (#101).
///
/// Only measurable where the source format names its ceiling
/// (`clipping_white_level`), which today means the 8-bit greys. A frame whose
/// format names no ceiling is REFUSED rather than judged, because a gate that
/// could not run is not a gate that passed; see [`Signals::ir_ceiling_known`]
/// (#358). This sentence used to say the opposite, and anyone retuning the
/// constant should know the population it is fitted to is GREY8 only.
pub const IR_SATURATED_FRAC_MAX: f32 = 0.10;

/// Ambient IR (see [`Signals::ir_ambient`]) above which the brightness and
/// center/edge cues are physically starved rather than measuring a spoof: the scene's
/// own infrared swamps the emitter, so the strobe adds almost nothing to read
/// shape or skin reflectance from. Measured 2026-07-16 (430-sample field
/// session, ~/irlume-suncal/SESSION-2026-07-16.md): genuine faces clear the ratio
/// reliably below ambient ~120, marginally to ~170, and 0/129 samples passed
/// above ~170 (emitter-over-ambient gap collapsed to 4–9, IR frame 46–82%
/// saturated). The verdict stays Spoof (fail closed); only the REASON changes,
/// from "looks 2D" (which reads as an accusation) to what is actually wrong
/// and what to do about it. The sensor cannot tell WHAT the source is (open
/// sky, sun, and strong lamps look identical in IR), so the message names
/// examples, not a diagnosis.
pub const IR_AMBIENT_FLOOD: f32 = 170.0;

/// The actionable rejection for ambient-flooded IR scenes.
fn flood_reason(ambient: f32) -> String {
    format!(
        "too much IR light behind you (ambient {ambient:.0}: open sky, sun, or bright \
         lamps wash out the emitter); turn away from the light or use your password"
    )
}
/// Eye IR peak above this counts as a corneal glint (supporting cue).
///
/// Supporting-only is load-bearing, not caution (#174, measured 2026-08-04):
/// with glasses on the peak pinned at 255 in all 30 frames, so it reads the
/// lens specular, not the cornea (#222), and bare-eyed genuine frames read
/// 164-247 with 6 of 10 below this value. As a hard gate it would
/// false-reject a bare-eyed user at normal distance more often than not.
/// The cue is an eyewear-state variable before it is anything else; it does
/// not track seating distance.
pub const GLINT_MIN: f32 = 180.0;
/// Head-orientation gate (Windows-Hello-style ±15° frontality), approximated
/// from 2D landmarks. Deliberately PERMISSIVE: rejects only clearly off-angle
/// faces, to avoid false-rejects; a non-frontal face yields `Uncertain` ("face
/// the camera"), never `Spoof`. Also gates enrollment, keeping templates frontal.
/// PITCH is intentionally wide: a top-bezel camera sees the user pitched ~15-17°
/// DOWN when they look at the screen, so a tight pitch gate would reject normal
/// use. Tune per-camera with real pose data; calibrating to the user's enrolled
/// pose is a follow-up.
pub const YAW_ASYM_MAX: f32 = 0.40;
pub const PITCH_FRAC_MIN: f32 = 0.20;
pub const PITCH_FRAC_MAX: f32 = 0.80;

/// The hard liveness gate. Stateless for now (per-user IR calibration is a P2
/// follow-up).
#[derive(Default)]
pub struct LivenessGate;

impl LivenessGate {
    pub fn new() -> Self {
        Self
    }

    /// Decide live / spoof / uncertain from the captured signals. Any hard
    /// failure rejects (no weighted fusion).
    pub fn evaluate(&self, s: &Signals) -> (Verdict, Cues, String) {
        let mut cues = Cues::default();

        let Some(rgb) = s.rgb_face.filter(|f| f.score >= MIN_FACE_SCORE) else {
            return (
                Verdict::Uncertain,
                cues,
                "no face in RGB; present your face".into(),
            );
        };
        cues.face_in_rgb = true;

        // Core anti-screen cue: a real face reflects the IR emitter and is
        // detectable in IR; a phone/print does not.
        let Some(ir) = s.ir_face.filter(|f| f.score >= MIN_FACE_SCORE) else {
            return (
                Verdict::Spoof,
                cues,
                "no face in IR: a real face reflects 850nm; a screen/print does not".into(),
            );
        };
        cues.face_in_ir = true;

        // Cross-spectrum co-location: the same face in both spectra.
        let dist = ((rgb.cx - ir.cx).powi(2) + (rgb.cy - ir.cy).powi(2)).sqrt();
        cues.cross_spectrum_aligned = dist <= CROSS_SPECTRUM_TOLERANCE;
        if !cues.cross_spectrum_aligned {
            return (
                Verdict::Uncertain,
                cues,
                format!("RGB/IR face mismatch (dist {dist:.2}); re-center"),
            );
        }

        // Head-orientation gate (Windows-Hello-style ±15° frontality): a face
        // turned away or tilted yields a poor representation. Quality issue, not
        // a spoof -> Uncertain ("face the camera"). Also rejects off-angle frames
        // at enrollment, keeping templates frontal.
        cues.frontal_ok = s.head_yaw_asym <= YAW_ASYM_MAX
            && (PITCH_FRAC_MIN..=PITCH_FRAC_MAX).contains(&s.head_pitch_frac);
        if !cues.frontal_ok {
            return (
                Verdict::Uncertain,
                cues,
                format!(
                    "not facing the camera (yaw {:.2}, pitch {:.2}); look directly at it",
                    s.head_yaw_asym, s.head_pitch_frac
                ),
            );
        }

        if let Some((verdict, reason)) = exposure_refusal(s, &mut cues) {
            return (verdict, cues, reason);
        }

        // IR skin reflectance: the face region must be brightly lit.
        cues.ir_reflectance_ok = s.ir_face_brightness >= IR_FACE_MIN_BRIGHTNESS;
        if !cues.ir_reflectance_ok {
            let reason = if s.ir_ambient >= IR_AMBIENT_FLOOD {
                flood_reason(s.ir_ambient)
            } else {
                format!(
                    "IR face too dark ({:.0}); not reflecting IR like skin",
                    s.ir_face_brightness
                )
            };
            return (Verdict::Spoof, cues, reason);
        }

        // Anti-flat: a real 3D face shows center-vs-edge IR falloff.
        cues.center_edge_ratio_ok = s.ir_center_edge_ratio >= MIN_CENTER_EDGE_RATIO;
        if !cues.center_edge_ratio_ok {
            let reason = if s.ir_ambient >= IR_AMBIENT_FLOOD {
                flood_reason(s.ir_ambient)
            } else {
                format!(
                    "IR too flat (center/edge {:.2}); looks 2D, not a 3D face",
                    s.ir_center_edge_ratio
                )
            };
            return (Verdict::Spoof, cues, reason);
        }

        // Corneal glint: supporting only; logged, never decisive on its own.
        cues.glint_readable = s.ir_eye_glint.is_some();
        cues.glint_present = s.ir_eye_glint.is_some_and(|g| g >= GLINT_MIN);

        (
            Verdict::Live,
            cues,
            "live: face in RGB+IR, co-located, frontal, IR-reflective, 3D".into(),
        )
    }

    /// RGB-only convenience gate (no IR hardware). DETERRENT-grade anti-spoof:
    /// requires a present, frontal, well-lit face and rejects obvious screen/glare
    /// (blown-out highlights). It CANNOT match IR's defeat of photo/screen replay,
    /// which is exactly why this tier is limited to lock-screen unlock and never
    /// releases credentials / logs in / elevates. The user must have light on
    /// their face for the RGB camera to see them.
    pub fn evaluate_rgb_only(&self, s: &Signals) -> (Verdict, Cues, String) {
        let mut cues = Cues::default();
        let Some(_rgb) = s.rgb_face.filter(|f| f.score >= MIN_FACE_SCORE) else {
            return (
                Verdict::Uncertain,
                cues,
                "no face; present your face to the camera".into(),
            );
        };
        cues.face_in_rgb = true;
        cues.frontal_ok = s.head_yaw_asym <= YAW_ASYM_MAX
            && (PITCH_FRAC_MIN..=PITCH_FRAC_MAX).contains(&s.head_pitch_frac);
        if !cues.frontal_ok {
            return (
                Verdict::Uncertain,
                cues,
                "not facing the camera; look directly at it".into(),
            );
        }
        if s.rgb_face_brightness < RGB_FACE_MIN_BRIGHTNESS {
            return (
                Verdict::Uncertain,
                cues,
                "too dark: add light on your face (RGB-only mode needs a lit face)".into(),
            );
        }
        if s.rgb_face_brightness > RGB_FACE_MAX_BRIGHTNESS {
            return (
                Verdict::Uncertain,
                cues,
                "overexposed; reduce the light/backlight".into(),
            );
        }
        if s.rgb_specular_frac > RGB_SPECULAR_MAX {
            return (
                Verdict::Spoof,
                cues,
                "screen/glare detected (blown-out highlights); RGB-only anti-spoof".into(),
            );
        }
        if s.rgb_moire_score > rgb_moire_max() {
            return (Verdict::Spoof, cues,
                format!("screen pixel-grid/moiré pattern detected (peakiness {:.0}); RGB-only anti-spoof", s.rgb_moire_score));
        }
        (
            Verdict::Live,
            cues,
            format!(
                "live (rgb convenience; bright {:.0} specular {:.2} moire {:.0})",
                s.rgb_face_brightness, s.rgb_specular_frac, s.rgb_moire_score
            ),
        )
    }

    /// Dark-operation gate: IR only (no RGB to cross-check). Used when there's no
    /// visible-light face. Weaker than the full gate (no cross-spectrum anti-
    /// injection) but keeps IR reflectance + center/edge falloff + glint; same
    /// basis Windows Hello uses in the dark.
    pub fn evaluate_ir_only(&self, s: &Signals) -> (Verdict, Cues, String) {
        let mut cues = Cues::default();
        if s.ir_face.filter(|f| f.score >= MIN_FACE_SCORE).is_none() {
            return (Verdict::Uncertain, cues, "no face in IR".into());
        }
        cues.face_in_ir = true;
        if let Some((verdict, reason)) = exposure_refusal(s, &mut cues) {
            return (verdict, cues, reason);
        }
        cues.ir_reflectance_ok = s.ir_face_brightness >= IR_FACE_MIN_BRIGHTNESS;
        if !cues.ir_reflectance_ok {
            let reason = if s.ir_ambient >= IR_AMBIENT_FLOOD {
                flood_reason(s.ir_ambient)
            } else {
                format!("IR face too dark ({:.0})", s.ir_face_brightness)
            };
            return (Verdict::Spoof, cues, reason);
        }
        cues.center_edge_ratio_ok = s.ir_center_edge_ratio >= MIN_CENTER_EDGE_RATIO;
        if !cues.center_edge_ratio_ok {
            let reason = if s.ir_ambient >= IR_AMBIENT_FLOOD {
                flood_reason(s.ir_ambient)
            } else {
                format!("IR too flat (center/edge {:.2})", s.ir_center_edge_ratio)
            };
            return (Verdict::Spoof, cues, reason);
        }
        cues.glint_readable = s.ir_eye_glint.is_some();
        cues.glint_present = s.ir_eye_glint.is_some_and(|g| g >= GLINT_MIN);
        (
            Verdict::Live,
            cues,
            "live (dark/IR-only): IR-reflective, 3D".into(),
        )
    }
}

/// The exposure refusal, shared by every evaluator that can release credentials.
///
/// A blown face region measures nothing: the cues below it degrade together as
/// clipping rises, so judging any one of them is reading noise (#237). Returns
/// the refusal to propagate, or `None` when the frame is readable, and records
/// [`Cues::ir_exposure_ok`] either way.
///
/// This lives in one function because it guards two entry points,
/// [`LivenessGate::evaluate`] and [`LivenessGate::evaluate_ir_only`], and the
/// first version of #237 gated only the first: the dark-room path kept
/// accepting the frames the cross-spectrum path had just started refusing.
/// Adding a third evaluator means calling this, not copying it.
fn exposure_refusal(s: &Signals, cues: &mut Cues) -> Option<(Verdict, String)> {
    // Not measurable at all. This used to read as "clean" and let every cue
    // below run on a frame nobody had checked, which is off on any IR node that
    // negotiates Y16/Y10/Y12/NV12/YUYV rather than 8-bit grey (#358).
    //
    // Refused rather than passed: the cues below degrade together as clipping
    // rises, so running them on an unverified frame is reading noise, and a
    // gate that cannot run is not a gate that passed.
    //
    // Worded so it does NOT say "move back". Moving cannot repair a format that
    // defines no ceiling, and the reason prefix is what keeps this out of the
    // presence-retryable set: retrying would burn the whole grace window every
    // login and then fall back to the password anyway, while advising something
    // that cannot help. See `liveness_deny_kind` in irlume-auth.
    cues.ir_exposure_measured = s.ir_ceiling_known;
    if !s.ir_ceiling_known {
        cues.ir_exposure_ok = false;
        return Some((
            Verdict::Uncertain,
            "IR exposure unmeasurable: this camera's IR format defines no sensor \
             ceiling, so clipping cannot be checked and the liveness cues cannot \
             be trusted. Report the camera so its format can be supported."
                .to_string(),
        ));
    }

    cues.ir_exposure_ok = s
        .ir_saturated_frac
        .is_some_and(|f| f <= IR_SATURATED_FRAC_MAX);
    if cues.ir_exposure_ok {
        return None;
    }
    // Uncertain, not Spoof: the capture failed to measure a face rather than
    // showing a fake one, and moving back fixes it. That classification is also
    // what makes the refusal presence-retryable, so a login's grace window can
    // absorb it while a single-capture probe reports it.
    let clipped = s.ir_saturated_frac.unwrap_or(1.0) * 100.0;
    Some((
        Verdict::Uncertain,
        format!(
            "IR frame blown out ({clipped:.0}% of the face at the sensor ceiling); \
             move back or dim the light"
        ),
    ))
}

// --- Passive blink liveness (opt-in, ADR-0002) ------------------------------
//
// Defeats the demonstrated static IR-reflective print attack (a life-size glossy
// vinyl banner passed the single-frame gate at 98.6% APCER, 2026-06-30): a static
// print cannot blink. Given a per-frame eye-aspect-ratio (EAR) sequence
// (`irlume_vision::eye_ear` over MediaPipe FaceMesh landmarks, in capture order),
// we PASSIVELY look for a natural blink: an EAR dip well below the user's open
// baseline. No prompt, no deliberate action: the user just looks at the camera and
// blinks naturally within the window; the print holds EAR flat and never dips.
//
// Why EAR (and not the earlier IR-glint metric): live-validated 2026-07-01, EAR is
// the clean signal: open eye ≈0.24 (rock-stable), a natural blink dips to ≈0.15,
// while a static vinyl banner sits flat 0.21–0.24 (min ≈0.206, spread ≈0.034, no
// dips). The deliberate-blink glint challenge that preceded this was replaced for
// bad UX (natural blinks too fast for the glint metric; a timed held blink is not
// ergonomic). EAR is scale-invariant (a ratio), so the threshold is relative to the
// user's own open baseline and needs no per-user calibration.

/// An EAR at/below this fraction of the open baseline is a blink outright (the
/// original depth rule, kept: live blinks hit ≈0.64×, banner jitter stays ≥0.75×).
pub const BLINK_EAR_DIP_RATIO: f32 = 0.72;
/// The open baseline (per-class median EAR) must be at least this to trust a
/// plausibly-open eye was seen; guards against the mesh failing / a squint spoof.
/// Lowered 0.15 → 0.12 (2026-07-01): glasses depress the open baseline to
/// 0.13–0.14 on IR, which read NoEyes and cost half the glasses catch rate; the
/// banner sits at 0.20–0.24 so this floor was never its rejector (re-validated
/// against the banner after the change).
pub const BLINK_MIN_OPEN_EAR: f32 = 0.12;
// -- V-shape (velocity) rule, added 2026-07-01 after real-world traces showed
// natural blinks at 15 fps dip only to 0.78–0.85× baseline (mid-closure sampled,
// full closure missed); above the depth cutoff but with a sharp drop-and-recover
// transient a static print's slow jitter does not produce.
/// Samples at/below this ratio are candidates for a blink "run".
pub const BLINK_V_RUN_RATIO: f32 = 0.88;
/// A single-sample run must dip at least this deep (one 66 ms frame at full
/// closure); deeper than the multi-sample floor to resist one-frame mesh noise.
pub const BLINK_V_MIN_SINGLE: f32 = 0.82;
/// A multi-sample run's deepest sample must reach this.
pub const BLINK_V_MIN_MULTI: f32 = 0.85;
/// Runs longer than this many samples are a squint / pose change, not a blink.
pub const BLINK_V_MAX_RUN: usize = 6;
/// The eye must be near-open (≥ this ratio) shortly before AND after the run:
/// the sharp V. Slow drifts (auto-exposure settling, gaze shifts) fail this.
pub const BLINK_V_OPEN_RATIO: f32 = 0.93;
/// How many frames before the run start the near-open pre-sample may be.
pub const BLINK_V_PRE_WIN: usize = 4;
/// How many frames after the run end the near-open recovery may be (~400 ms).
pub const BLINK_V_POST_WIN: usize = 6;
/// A brightness class needs at least this many face samples to be trusted;
/// tiny windows (camera stream died / exposure never settled) read NoEyes.
pub const BLINK_MIN_CLASS_SAMPLES: usize = 8;
/// Consent gesture ([`detect_deliberate_closure`]) closure LOWER bound: the eyes
/// must stay shut for at least this many consecutive face frames. Validated on
/// real captures 2026-07-22: every accepted deliberate hold ran ≥11 face frames,
/// while the one natural blink that reached the reopen test ran 10, so 11 is the
/// clean floor (the face node runs ~7-8 fps after the strobe, so ~11 frames is
/// ~1.5 s, well above the 100-400 ms spontaneous-blink range). Overridable via
/// `IRLUME_CONSENT_CLOSURE_FRAMES`.
pub const CONSENT_CLOSURE_MIN_FRAMES: usize = 11;
/// Consent gesture closure UPPER bound: a run longer than this is a SUSTAINED
/// hold (a held squint, eyes closed, or looking away), not a discrete ~1 s
/// gesture. On the campaign data the deliberate holds ran ≤20 frames while the
/// squints ran 32-38; 25 sits between them. Overridable via
/// `IRLUME_CONSENT_CLOSURE_MAX`.
pub const CONSENT_CLOSURE_MAX_FRAMES: usize = 25;
/// Frames after a closure within which the eyes must reopen for it to count as a
/// discrete gesture (a squint never reopens).
pub const CLOSURE_REOPEN_WINDOW: usize = 4;
/// Openness fraction the eyes must recover to after a closure to count as
/// reopened (0 = shut, 1 = fully open). High, so easing a squint slightly does
/// not read as a reopen.
pub const CLOSURE_REOPEN_FRACTION: f32 = 0.6;
/// Frames the eyes may blip back open mid-hold without ending the closure run
/// (landmark noise tolerance).
pub const CLOSURE_HYSTERESIS_FRAMES: usize = 2;
/// Openness fraction (0 = fully shut, 1 = fully open) at/below which the eye
/// counts as shut for the consent gesture. The blink-taxonomy "complete closure"
/// level is ~0.20-0.25 (PMC11133197); this sits just above it so a genuine full
/// hold clears it while a partial squint does not. Validated on real captures
/// 2026-07-22 (deep threshold ~0.10 for this camera separates a held closure
/// from a squint that hovered near 0.12).
pub const CLOSURE_DEEP_FRACTION: f32 = 0.30;
/// Minimum open-minus-closed EAR gap for a [`ClosureCalibration`] to be trusted;
/// a smaller gap means the open and closed extremes were not cleanly captured.
pub const MIN_CALIBRATION_SEPARATION: f32 = 0.05;
/// The V's pre/post near-open samples must have frame brightness within this
/// factor of the dip's; EAR shifts with exposure, so a dip during auto-exposure
/// slewing (measured live 2026-07-01) must not pass as a blink.
pub const BLINK_V_BRI_BAND: f32 = 0.25;
/// Motion gate: reject a "blink" when the face's median per-frame speed over the
/// window exceeds this fraction of a face-width. A moving print or panning
/// camera jitters the mesh landmarks into fake EAR dips; a real blink is a
/// LOCAL eye change with the head essentially still. Calibrated live on the
/// NexiGo N930W 2026-07-09: genuine still-head blinks read median speed
/// 0.007-0.010, while a moving banner's false-accept reps read 0.045-0.047, a
/// clean gap. 0.02 sits in it with 2x margin on both sides. A genuinely moving
/// user is rejected here and falls back to the password (never a lockout).
///
/// The value is normalized by face width (distance/scale invariant), but not by
/// frame rate or a camera's bbox-jitter floor, so it is per-camera; override
/// with `IRLUME_BLINK_MOTION_MAX` (a float) after re-calibrating on new hardware.
pub const BLINK_MOTION_MAX_MEDIAN: f32 = 0.02;
/// Corneal-contrast gate: a real blink must show the eye's specular glint
/// COLLAPSE under the lid, i.e. open-eye contrast at least this many times the
/// contrast at the closed (lowest-EAR) frame. A diffuse print has no glint to
/// lose, so its ratio sits at ~1.0. This is a RATIO, so it is camera-invariant
/// (sensor gain cancels), unlike an absolute contrast floor. Calibrated live on
/// the NexiGo 2026-07-09: genuine blinks 1.41-2.63, a banner 0.88-1.38 (its
/// high end only under motion, which the motion gate independently rejects).
/// 1.15 clears every flat-print reading with margin below the genuine floor.
/// Second, independent cue (corneal specular, an established liveness signal);
/// override with `IRLUME_BLINK_CONTRAST_DROP`. Strong-ambient-IR FRR (washes out
/// the corneal peak) is still untested; fails safe to the password.
pub const BLINK_CONTRAST_DROP_MIN: f32 = 1.15;
/// The contrast gate is applied only when the face's median motion is at least
/// this (see [`BLINK_MOTION_MAX_MEDIAN`] for the unit). Below it the presentation
/// is near-still, where a print cannot fake an EAR dip, so the EAR blink alone is
/// trustworthy and the corneal cue is skipped. This is what keeps GLASSES usable:
/// a lens IR reflection flattens the contrast ratio to ~1.1 (print-like), so a
/// still glasses wearer (measured motion 0.004-0.008 on the NexiGo) must not be
/// gated on it; validated 10/10 glasses grant once skipped. Override with
/// `IRLUME_BLINK_CONTRAST_MOTION_FLOOR`.
pub const BLINK_CONTRAST_MOTION_FLOOR: f32 = 0.015;

/// One observation from an IR capture sequence: frame index in the sequence, the
/// min-eye EAR when a face was detected in that frame, and the frame's mean
/// brightness. The IR emitter STROBES (alternate frames are emitter-lit vs
/// ambient-only), and ambient-only frames read systematically lower EAR, so the
/// detector baselines each brightness class separately instead of one median.
///
/// `cx`/`cy`/`fsize` carry the detected face's center and width (frame pixels,
/// all 0 when no face); [`face_speeds`] uses them to reject blinks that
/// coincide with whole-face motion (a moving print/camera jitters the mesh
/// landmarks into fake EAR dips), which a real, local blink does not.
#[derive(Clone, Copy, Debug)]
pub struct EarSample {
    pub idx: usize,
    pub ear: Option<f32>,
    pub bri: f32,
    pub cx: f32,
    pub cy: f32,
    pub fsize: f32,
    /// Corneal specular contrast (peak − local-mean at the eye, 0 when no face).
    /// A live open eye spikes high and collapses on closure; a diffuse print
    /// stays flat. The second liveness cue: a real blink shows this DROP.
    pub contrast: f32,
}

/// One observation of HEAD POSE from an IR capture frame, for the head-nod
/// consent gesture. Pose comes from the DETECTOR's 5-point landmarks (not the
/// FaceMesh), so unlike [`EarSample`] it does not depend on eye landmarks and stays
/// reliable across head angle and lighting: a nod reads the same reclined or upright.
/// `pitch_frac`/`yaw_signed` are `None` when no face was detected in the frame.
#[derive(Clone, Copy, Debug)]
pub struct PoseSample {
    pub idx: usize,
    /// Nose vertical position between eye and mouth lines: ~0.5 frontal, LARGER
    /// looking down, SMALLER looking up (see `irlume_vision::HeadPose`). A nod
    /// swings this down-and-back.
    pub pitch_frac: Option<f32>,
    /// Signed horizontal turn: ~0 frontal, sign = nose toward image-left/right. A
    /// shake swings this side-to-side.
    pub yaw_signed: Option<f32>,
    /// Frame mean brightness (IR strobe phase), carried for parity with the
    /// blink pipeline; the pose detector does not currently gate on it.
    pub bri: f32,
}

/// Whether a deliberate head gesture (the consent nod) was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadGesture {
    /// A deliberate NOD (approve).
    Nod,
    /// A deliberate SHAKE (reserved for a future "deny"; detected but distinct).
    Shake,
    /// A face was tracked but no deliberate gesture (still, drift, or noise).
    None,
    /// No face tracked in enough of the window to judge.
    NoFace,
}

/// Deliberate head-nod consent gesture ([`detect_nod`]): minimum pitch RANGE
/// (max-min of `pitch_frac`) over the window. A nod swings the head down and
/// back; a still head barely moves. This is the gate that actually separates the
/// two, which is why it carries the threshold.
///
/// Raised 0.070 → 0.075 on 2026-07-27 after measuring the live consent watch on
/// one user, one camera, 28 watches, with the daemon reporting the numbers
/// behind every verdict:
///
/// | population | n | pitch_range |
/// |---|---|---|
/// | accepted, deliberate continuous nods | 10 | 0.082 - 0.108 |
/// | rejected, sitting still + hand-held printed face | 18 | 0.021 - 0.069 |
///
/// The populations do not overlap, and 0.070 sat on the very edge of the gap.
/// 0.075 is its midpoint: 0.006 above the worst non-gesture and 0.007 below the
/// weakest real nod. An earlier session the same evening, where the numbers were
/// not captured, DID see the gate fire on a still user and on a print, so treat
/// this as widening a measured margin rather than as proof the case is closed.
///
/// The 2026-07-22 campaign recorded genuine nods as low as 0.057, which this
/// threshold rejects. Those were single nods; the instruction has since changed
/// to keep nodding (a single nod released 0 times out of 3), and continuous
/// nodding measured 0.082 at its weakest. The failure direction is also the safe
/// one: a rejected gesture falls back to the typed password, while a false
/// accept releases a credential the user never consented to release.
///
/// Overridable via `IRLUME_NOD_PITCH_MIN`.
pub const NOD_PITCH_MIN: f32 = 0.075;
/// ...and maximum yaw RANGE, so idle LOOKING-AROUND (which swings yaw a lot) and
/// a head SHAKE are not read as a nod. Campaign: nods ranged ≤0.46 in yaw while
/// look-around ranged 0.87-6.95, so 0.6 separates them cleanly.
pub const NOD_YAW_MAX: f32 = 0.6;
/// Minimum pitch oscillation crossings (the pitch signal must cross above AND
/// below its median): 1 = a single deliberate down-up nod. A drift that looks
/// down and HOLDS never crosses back, so it stays 0 and is rejected. Set to 1
/// (from 2) after live testing: requiring two nods pushed the gesture past the
/// capture window and slowed grants; the campaign data shows 1 crossing accepts
/// more genuine nods (19/21 vs 17/21) with still ZERO false accepts on
/// still/look-around (the pitch-range and yaw gates do that work).
///
/// DO NOT RAISE THIS TO FIX A FALSE ACCEPT. Measured 2026-07-27 over 28 live
/// consent watches, crossings does not separate the populations at all, and is
/// if anything inverted:
///
/// | population | crossings observed |
/// |---|---|
/// | accepted, deliberate nods | 1, 1, 1, 2, 2, 2, 2, 3, 3, 3 |
/// | rejected, still + printed face | 0, 0, 1, 1, 1, 1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 5, 7 |
///
/// A still head reached 7 while real nods fired on 1, so requiring 2 would have
/// rejected three genuine nods and still admitted every still take that produced
/// 3 or more. The cause is [`NOD_CROSSING_AMP_FRAC`]: the amplitude bar is a
/// fraction of the take's OWN pitch range, so a nearly-still head gets a tiny
/// bar and sensor noise oscillates across it repeatedly. [`NOD_PITCH_MIN`] is
/// the gate that discriminates; raise that instead.
pub const NOD_MIN_CROSSINGS: usize = 1;
/// A crossing counts only when the pitch moves past this fraction of the take's
/// pitch range from the median, so sensor noise on a near-still head is ignored.
pub const NOD_CROSSING_AMP_FRAC: f32 = 0.25;
/// The window must have at least this many face frames to judge a nod.
pub const NOD_MIN_FACE_FRAMES: usize = 12;

/// Deliberate head-SHAKE consent gesture: minimum yaw RANGE (max-min of
/// `yaw_signed`) over the window. A shake swings the head left and right;
/// a still head barely moves. Measured 2026-08-10 on one subject, two
/// postures (sitting, reclining), 20 samples each:
///
/// | posture | gesture | yaw_range |
/// |---|---|---|
/// | sitting | nod | 0.18-0.37 (median 0.27) |
/// | sitting | shake | 0.53-1.09 (median 0.79) |
/// | reclining | nod | 0.16-0.32 (median 0.22) |
/// | reclining | shake | 0.34-0.63 (median 0.48) |
///
/// 0.45 separates every nod from the majority of shakes; the reclining
/// shakes below 0.45 (3 of 10) are the ones the nod detector also misses
/// (pitch too low). Overridable via `IRLUME_SHAKE_YAW_MIN`.
pub const SHAKE_YAW_MIN: f32 = 0.45;
/// Maximum yaw RANGE for a deliberate shake. Idle looking-around swings yaw
/// much wider (measured 4.1 in the test corpus) than a deliberate shake.
/// Live daemon shakes measured 1.60-2.04 on 2026-08-11; the calibration
/// tool's shorter window reported 0.53-1.09.
///
/// RAISED 2.5 -> 3.5 on 2026-08-11 after a live polkit session: deliberate
/// shakes at a real consent dialog reached yaw 2.81 and 2.99, ABOVE the old
/// ceiling, so they left the band and could not register at all. The window
/// accumulates range as it grows, so the old value made a LONGER or more
/// vigorous shake progressively LESS detectable, the opposite of the intent.
/// 3.5 sits above every shake measured to date (2.99) and below the measured
/// look-around (4.1). The oscillation requirement below is what actually
/// separates a shake from a look-around; this ceiling is the coarse guard.
pub const SHAKE_YAW_MAX: f32 = 3.5;
/// Maximum pitch RANGE during a shake: the head should not nod up/down while
/// shaking. Measured 2026-08-10: sitting shakes ranged 0.044-0.169 in pitch,
/// reclining shakes 0.066-0.133. The sitting nod pitch goes up to 0.156, so
/// 0.18 catches shakes while letting nods through. Overridable via
/// `IRLUME_SHAKE_PITCH_MAX`.
pub const SHAKE_PITCH_MAX: f32 = 0.18;
/// Minimum yaw MEDIAN-CROSSINGS for a shake: the yaw must OSCILLATE, not merely
/// span a range. Measured 2026-08-11 on the ASUS FHD IR module, a STILL face
/// carries yaw_range 0.48-0.61 (above the 0.45 floor) with ZERO yaw crossings,
/// while a deliberate shake shows 6-7; a floor of 2 (one full there-and-back)
/// sits safely between and rejects the still-face drift that range alone read as
/// a Shake. Overridable via `IRLUME_SHAKE_MIN_CROSSINGS`.
pub const SHAKE_MIN_CROSSINGS: usize = 2;

/// Yaw range at which a shake is UNAMBIGUOUS and one crossing is enough.
///
/// The 2-crossing floor above exists to reject a STILL face, whose drift measured
/// 0.42-0.72 yaw. That drift cannot reach 1.5: it is more than double the widest
/// still reading, and 1.5 is itself below every live shake measured (1.58-2.99 at
/// a real polkit dialog on 2026-08-11). Requiring a full there-and-back at that
/// width rejected genuine one-sweep declines: three consecutive live shakes logged
/// yaw 1.58-2.24 with a single crossing and were read as "no gesture", so the user
/// had to shake repeatedly. One crossing IS an oscillation (a sweep that returns
/// through the median); a look-around holds its new heading instead, which is why
/// the crossing count, not the range, is the real discriminator.
pub const SHAKE_WIDE_YAW: f32 = 1.5;

/// Crossings required once the yaw range is [`SHAKE_WIDE_YAW`] or wider.
pub const SHAKE_WIDE_MIN_CROSSINGS: usize = 1;

/// Detect a deliberate head-NOD consent gesture from a pose sequence: the head
/// pitch swings through a range of at least [`NOD_PITCH_MIN`] while the yaw stays
/// within [`NOD_YAW_MAX`] (not a look-around or shake), oscillating up-and-down
/// at least [`NOD_MIN_CROSSINGS`] times (not a single drift). Pose-DEFINED, so
/// unlike the eye-closure gesture it reads the same at any head angle or
/// lighting, which is why it survives a reclined user where EAR collapses.
///
/// `Nod` = the gesture was seen; `None` = a face was tracked but no nod;
/// `NoFace` = too few face frames to judge. `Shake` is not yet detected (returns
/// `None` for a shake) pending its own tuning data.
pub fn detect_nod(samples: &[PoseSample]) -> HeadGesture {
    detect_nod_with_evidence(samples).0
}

/// Why [`detect_nod`] reached its answer, for diagnosis.
///
/// A nod that is not detected leaves no trace otherwise: the caller simply waits
/// out its deadline and denies, which is indistinguishable from a user who never
/// moved. These are the numbers that decide it, so a failure can be read instead
/// of guessed at.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NodEvidence {
    /// Frames that produced a usable pitch reading, against [`NOD_MIN_FACE_FRAMES`].
    pub frames: usize,
    /// Peak-to-peak head pitch, against `pitch_min`.
    pub pitch_range: f32,
    /// The pitch threshold ACTUALLY applied to this window. Carried rather than
    /// left for the reader to look up, because `IRLUME_NOD_PITCH_MIN` overrides
    /// [`NOD_PITCH_MIN`]: a report naming the constant while the run enforced an
    /// override would send the next investigation after the wrong number.
    pub pitch_min: f32,
    /// Peak-to-peak yaw, against [`NOD_YAW_MAX`]: too much means head-shake.
    pub yaw_range: f32,
    /// Median crossings of sufficient amplitude, against [`NOD_MIN_CROSSINGS`].
    pub crossings: usize,
    /// Mean absolute pitch change PER FRAME: |Δpitch| / Δidx over pairs of
    /// usable samples whose recorded frame indices differ by 1 (plain
    /// cadence) or 2 (strobe cadence; the ASUS module lights alternate
    /// frames, so live captures there have every usable pair at gap 2). The
    /// division keeps a strobe pair a rate rather than a double step, so a
    /// gap cannot inflate the metric, and a gap longer than 2 (face lost,
    /// detection loss) contributes nothing.
    ///
    /// RECORDED, NEVER GATING. This is the candidate discriminator #101 left
    /// on the table: measured there once, it separated a still head from a
    /// deliberate nod by 2.3x (still at most 0.0064, nods at least 0.0149)
    /// where the gating `pitch_range` manages 1.44x. Those numbers come
    /// from one user in one session, and the same thread documents this class
    /// of signal drifting across sessions (genuine nods at 0.057 in one
    /// campaign, 0.082 weakest in another). The issue's recorded blocker is
    /// cross-session data; this field rides in the evidence so debug-enabled
    /// consent watches (`IRLUME_LOG=debug`, the same opt-in as every other
    /// diagnostic line) and validated replay captures report it without
    /// anyone remembering IRLUME_DUMP_POSE_SERIES. An ordinary authentication
    /// run computes it and discards it with the rest of the evidence; making
    /// it durable everywhere would need the storage and access-control design
    /// the anti-oracle logging policy exists to force. Turning it into a
    /// threshold is #101's call to make on that data, not this field's.
    pub mean_step: f32,
}

/// [`detect_nod`], plus the measurements behind the verdict.
///
/// This holds the whole decision: [`detect_nod`] is a thin wrapper over it, so
/// the evidence cannot describe one rule while the gate applies another. It is
/// the single place the nod is judged.
///
/// `crossings` is computed even when the range gate has already failed, so a
/// report is never missing the one number that would have explained it; the
/// extra work lands only on the failure path.
pub fn detect_nod_with_evidence(samples: &[PoseSample]) -> (HeadGesture, NodEvidence) {
    let pitch: Vec<f32> = samples.iter().filter_map(|s| s.pitch_frac).collect();
    let yaw: Vec<f32> = samples.iter().filter_map(|s| s.yaw_signed).collect();
    let range = |v: &[f32]| -> f32 {
        let (mut lo, mut hi) = (f32::INFINITY, f32::NEG_INFINITY);
        for &x in v {
            lo = lo.min(x);
            hi = hi.max(x);
        }
        if v.is_empty() {
            0.0
        } else {
            hi - lo
        }
    };
    let pitch_range = range(&pitch);
    // A per-FRAME rate over usable pairs at most one strobe apart, keyed on
    // the recorded frame index, not vector position. Three constraints shaped
    // this, each learned the hard way:
    //
    //   * position-based pairing let a sample dropped upstream turn a
    //     two-frame move into one frame's motion (the review round's finding);
    //   * requiring idx to differ by exactly 1 then zeroed the metric on real
    //     hardware: the ASUS module strobes alternate frames, so a live 75-
    //     frame take had 38 usable samples and ALL 37 usable pairs at gap 2
    //     (measured 2026-08-01, nod and still takes both);
    //   * dividing |Δpitch| by the gap keeps a strobe pair a per-frame rate
    //     instead of a double step, so a gap CANNOT inflate the metric.
    //
    // Gap 1 is plain cadence, gap 2 is strobe cadence (or one dropped frame,
    // indistinguishable and equally honest once normalized); anything longer
    // is a detection loss and contributes nothing, which is the face-lost
    // rule the field documentation promises. On those live takes this reads
    // nod 0.0116 against still 0.0018.
    let usable: Vec<(usize, f32)> = samples
        .iter()
        .filter_map(|s| s.pitch_frac.filter(|p| p.is_finite()).map(|p| (s.idx, p)))
        .collect();
    let (step_sum, step_n) = usable.windows(2).fold((0.0f32, 0usize), |acc, w| {
        // saturating_sub: a disordered or duplicate idx yields gap 0 and is
        // skipped rather than wrapping into a huge divisor.
        let gap = w[1].0.saturating_sub(w[0].0);
        if (1..=2).contains(&gap) {
            (acc.0 + (w[1].1 - w[0].1).abs() / gap as f32, acc.1 + 1)
        } else {
            acc
        }
    });
    let yaw_range = range(&yaw);
    let yaw_crossings = if yaw.is_empty() {
        0
    } else {
        signal_crossings(&yaw, yaw_range, NOD_CROSSING_AMP_FRAC)
    };
    let evidence = NodEvidence {
        frames: pitch.len(),
        pitch_range,
        pitch_min: nod_pitch_min(),
        yaw_range,
        crossings: if pitch.is_empty() {
            0
        } else {
            signal_crossings(&pitch, pitch_range, NOD_CROSSING_AMP_FRAC)
        },
        mean_step: if step_n == 0 {
            0.0
        } else {
            step_sum / step_n as f32
        },
    };
    let verdict = if evidence.frames < NOD_MIN_FACE_FRAMES {
        HeadGesture::NoFace
    } else if evidence.yaw_range >= shake_yaw_min() && evidence.yaw_range <= SHAKE_YAW_MAX {
        // Shake-shaped yaw is a decline or NOTHING, never an approving nod. The
        // shake band [SHAKE_YAW_MIN, SHAKE_YAW_MAX] overlaps the nod band
        // (yaw <= NOD_YAW_MAX) across [0.45, 0.60], so this band is TERMINAL: a
        // shake whose pitch exceeded SHAKE_PITCH_MAX must not fall through to the
        // nod branch and grant (a head-shake "no" with a vertical bob approving
        // sudo, polkit or credential release). A genuine nod sits at yaw
        // 0.16-0.37, well below SHAKE_YAW_MIN, so it never enters this band.
        //
        // A Shake also requires yaw OSCILLATION, not just yaw range: measured
        // 2026-08-11 on the ASUS FHD IR module (gesture_calibrate), a STILL face
        // carries yaw_range 0.48-0.61 with ZERO yaw crossings while a deliberate
        // shake shows 6-7. Range alone read the still face as a Shake and would
        // cancel the consent watch of a user who did nothing; the crossing count
        // separates them cleanly. Non-oscillating drift in the band fails CLOSED
        // to None. SHAKE_YAW_MAX excludes idle looking-around.
        // The crossing floor is TIERED by width. A still face's drift lives at
        // 0.42-0.72 yaw and needs the full there-and-back (2) to be excluded; at
        // SHAKE_WIDE_YAW and above, drift cannot reach the width at all, and
        // demanding 2 there rejected genuine one-sweep declines measured live at
        // yaw 1.58-2.24 with a single crossing.
        let need_crossings = if evidence.yaw_range >= shake_wide_yaw() {
            SHAKE_WIDE_MIN_CROSSINGS
        } else {
            shake_min_crossings()
        };
        if evidence.pitch_range <= shake_pitch_max() && yaw_crossings >= need_crossings {
            HeadGesture::Shake
        } else {
            HeadGesture::None
        }
    } else if evidence.pitch_range >= evidence.pitch_min
        && evidence.yaw_range <= NOD_YAW_MAX
        && evidence.crossings >= NOD_MIN_CROSSINGS
    {
        HeadGesture::Nod
    } else {
        HeadGesture::None
    };
    // When the shake check nearly fires but doesn't, say why. The caller
    // has no other way to know whether a shake was close.
    if verdict == HeadGesture::None
        && evidence.frames >= NOD_MIN_FACE_FRAMES
        && evidence.yaw_range >= shake_yaw_min()
    {
        // Calibration aid: print to stderr so the daemon's journal captures
        // it even without IRLUME_LOG. The format string is deliberately
        // simple so it can't be dead-code eliminated.
        // Names the FIRST unmet condition. The earlier version always printed the
        // crossing floor, so a shake rejected by the yaw CEILING was reported as if
        // it lacked oscillation, and a live session spent its diagnosis on the wrong
        // knob. A diagnostic that points away from the cause is worse than none.
        let need_crossings = if evidence.yaw_range >= shake_wide_yaw() {
            SHAKE_WIDE_MIN_CROSSINGS
        } else {
            shake_min_crossings()
        };
        let why = if evidence.yaw_range > SHAKE_YAW_MAX {
            format!(
                "yaw {:.2} ABOVE max {:.2} (reads as look-around)",
                evidence.yaw_range, SHAKE_YAW_MAX
            )
        } else if evidence.pitch_range > shake_pitch_max() {
            format!(
                "pitch {:.3} above max {:.3} (nodding while shaking)",
                evidence.pitch_range,
                shake_pitch_max()
            )
        } else {
            format!("yaw_crossings {yaw_crossings} below need {need_crossings}")
        };
        let msg = format!(
            "irlumed-shake-check REJECTED: {why} [yaw={:.2} in {:.2}..{:.2}, pitch={:.3} max {:.3}, yaw_crossings={} need {}]",
            evidence.yaw_range,
            shake_yaw_min(),
            SHAKE_YAW_MAX,
            evidence.pitch_range,
            shake_pitch_max(),
            yaw_crossings,
            need_crossings
        );
        eprintln!("{msg}");
    }
    (verdict, evidence)
}

/// Count median crossings of a signal, the rhythmic oscillation of a deliberate
/// head gesture. Each time the signal moves from clearly-above to clearly-below
/// its median (or vice versa, past `amp_frac * range`), one crossing is counted.
///
/// An empty signal has no crossings. Guarded here rather than at every call site
/// because this is public: the median index `len / 2` panics on an empty slice.
pub fn signal_crossings(signal: &[f32], range: f32, amp_frac: f32) -> usize {
    if signal.is_empty() {
        return 0;
    }
    let mut sorted = signal.to_vec();
    sorted.sort_by(f32::total_cmp);
    let median = sorted[sorted.len() / 2];
    let amp = range * amp_frac;
    let (mut crossings, mut sign) = (0usize, 0i8);
    for &s in signal {
        let cur = if s > median + amp {
            1
        } else if s < median - amp {
            -1
        } else {
            0
        };
        if cur != 0 && cur != sign {
            if sign != 0 {
                crossings += 1;
            }
            sign = cur;
        }
    }
    crossings
}

/// Minimum nod pitch range, overridable via `IRLUME_NOD_PITCH_MIN`.
///
/// Positive only: at zero the amplitude test stops discriminating, since every
/// pitch range clears it, and the gesture rests on the crossing count alone.
fn nod_pitch_min() -> f32 {
    env_override("IRLUME_NOD_PITCH_MIN", NOD_PITCH_MIN, |v| v > 0.0)
}

/// Minimum shake yaw range, overridable via `IRLUME_SHAKE_YAW_MIN`.
fn shake_yaw_min() -> f32 {
    env_override("IRLUME_SHAKE_YAW_MIN", SHAKE_YAW_MIN, |v| v > 0.0)
}

/// Maximum shake pitch range, overridable via `IRLUME_SHAKE_PITCH_MAX`.
fn shake_pitch_max() -> f32 {
    env_override("IRLUME_SHAKE_PITCH_MAX", SHAKE_PITCH_MAX, |v| v > 0.0)
}

/// Minimum shake yaw crossings, overridable via `IRLUME_SHAKE_MIN_CROSSINGS`.
fn shake_min_crossings() -> usize {
    std::env::var("IRLUME_SHAKE_MIN_CROSSINGS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SHAKE_MIN_CROSSINGS)
}

/// Yaw width above which one crossing is enough, overridable via
/// `IRLUME_SHAKE_WIDE_YAW`. Guarded like the other yaw overrides: a
/// non-positive value would make EVERY shake-band reading "wide" and drop the
/// still-face protection the 2-crossing floor exists for.
fn shake_wide_yaw() -> f32 {
    env_override("IRLUME_SHAKE_WIDE_YAW", SHAKE_WIDE_YAW, |v| v > 0.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlinkResult {
    /// A natural blink was observed (a clear EAR dip below the open baseline) → live.
    Blinked,
    /// A plausibly-open eye was seen but no blink in the window (a static artefact,
    /// or the user simply didn't blink; caller re-captures / falls back to password).
    NoBlink,
    /// No plausibly-open eye anywhere in the window (mesh failed, or a non-eye/print):
    /// the median EAR never reached the open floor.
    NoEyes,
}

fn median(xs: &mut [f32]) -> Option<f32> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(xs[xs.len() / 2])
}

/// Per-frame face-center speed between consecutive face-detected frames,
/// normalized by face width (so it's distance-invariant): the fraction of a
/// face-width the face travels per frame. A still head during a natural blink
/// reads near 0; a moving print or panning camera reads high. Used both as a
/// diagnostic and by [`detect_blink`]'s motion gate.
///
/// Returns per-sample speed aligned to `samples` (0.0 where either this or the
/// previous face-detected frame is missing), plus the median and max over the
/// frames that have a value.
pub fn face_speeds(samples: &[EarSample]) -> (Vec<f32>, f32, f32) {
    let mut speeds = vec![0.0f32; samples.len()];
    let mut vals: Vec<f32> = Vec::new();
    let mut prev: Option<(usize, f32, f32, f32)> = None; // idx, cx, cy, fsize
    for (i, s) in samples.iter().enumerate() {
        if s.fsize <= 0.0 {
            continue; // no face this frame
        }
        if let Some((pi, pcx, pcy, pfs)) = prev {
            let gap = (s.idx.saturating_sub(pi)).max(1) as f32;
            let scale = ((s.fsize + pfs) * 0.5).max(1.0);
            let d = ((s.cx - pcx).powi(2) + (s.cy - pcy).powi(2)).sqrt();
            let v = d / scale / gap; // face-widths per frame
            speeds[i] = v;
            vals.push(v);
        }
        prev = Some((s.idx, s.cx, s.cy, s.fsize));
    }
    let (mut med, mut mx) = (0.0f32, 0.0f32);
    if !vals.is_empty() {
        for &v in &vals {
            mx = mx.max(v);
        }
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        med = vals[vals.len() / 2];
    }
    (speeds, med, mx)
}

/// Corneal-contrast signature of the window: the open-eye contrast (median
/// specular contrast over the frames where the eye is most open) and the dip
/// contrast (contrast at the lowest-EAR frame). A real eye's corneal glint is
/// bright when open and collapses under the lid on a blink, so open ≫ dip; a
/// diffuse print has no glint to lose, so open ≈ dip. Returns (open, dip);
/// both 0 if no usable face frames. Diagnostic for calibrating the second cue.
#[expect(
    clippy::missing_panics_doc,
    reason = "cannot panic: `faces` is filtered on `ear.is_some_and(..)`, so every \
              `ear.unwrap()` below is on a value already proven to be Some"
)]
pub fn contrast_signature(samples: &[EarSample]) -> (f32, f32) {
    let faces: Vec<&EarSample> = samples
        .iter()
        .filter(|s| s.fsize > 0.0 && s.ear.is_some_and(|e| e.is_finite()))
        .collect();
    if faces.is_empty() {
        return (0.0, 0.0);
    }
    let max_ear = faces
        .iter()
        .map(|s| s.ear.unwrap())
        .fold(f32::NEG_INFINITY, f32::max);
    // Open-eye frames: EAR within 85% of this window's max (clearly not mid-blink).
    let mut open: Vec<f32> = faces
        .iter()
        .filter(|s| s.ear.unwrap() >= 0.85 * max_ear)
        .map(|s| s.contrast)
        .collect();
    let open_c = median(&mut open).unwrap_or(0.0);
    // Dip contrast: at the single lowest-EAR face frame.
    let dip_c = faces
        .iter()
        .min_by(|a, b| a.ear.unwrap().total_cmp(&b.ear.unwrap()))
        .map(|s| s.contrast)
        .unwrap_or(0.0);
    (open_c, dip_c)
}

/// Detect a natural blink PASSIVELY from a raw-frame-rate EAR sequence.
///
/// Steps: (1) split frames into emitter-lit vs ambient-only classes when the
/// strobe is visible (a frame is "lit" if brighter than the midpoint of its
/// neighbours); (2) baseline each class by its own median EAR and convert to
/// ratios; (3) a blink is either a deep dip (≤ `BLINK_EAR_DIP_RATIO`) or a sharp
/// V: a short run of samples ≤ `BLINK_V_RUN_RATIO` that is deep enough for its
/// length and has near-open samples just before and after it. A static print's
/// jitter is neither deep nor a coherent drop-and-recover; slow drifts (AE
/// settling, squints) fail the pre/post near-open check or the run-length cap.
/// Outcome of the blink analysis over a sample window, consumed by
/// [`detect_blink`] and nothing else. The consent gesture that shipped is a
/// HELD CLOSURE, and [`detect_deliberate_closure`] does not come through here:
/// it walks the EAR samples against per-user calibrated thresholds directly.
/// The comment this replaces named a `detect_double_blink` that has never
/// existed, so it described a second consumer as well as a different gesture, so the anti-spoof gates and dip
/// detection live in exactly one place.
enum BlinkScan {
    /// No plausibly-open eye anywhere in the window (mesh failed / print / dark).
    NoEyes,
    /// An anti-spoof gate (motion or corneal-contrast) rejected the window; no
    /// dip may be trusted as a blink.
    Gated,
    /// Trustworthy blink closures in ascending onset order, de-duplicated so one
    /// blink counts once. Empty means eyes were seen but no blink occurred.
    Events(Vec<BlinkEvent>),
}

/// One detected eyelid closure: the frame index where it began and the last
/// frame it was still closed. `end - onset` is the closure duration in frames,
/// which distinguishes a brief spontaneous blink from a deliberately held one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlinkEvent {
    onset: usize,
    end: usize,
}

/// Median head-motion ceiling above which no EAR dip is trusted as a blink,
/// overridable via `IRLUME_BLINK_MOTION_MAX`.
///
/// Positive only: at zero any measured movement at all gates the window, and a
/// head holding still to within the bbox-jitter floor is not something a user
/// can present on purpose.
fn blink_motion_max() -> f32 {
    env_override("IRLUME_BLINK_MOTION_MAX", BLINK_MOTION_MAX_MEDIAN, |v| {
        v > 0.0
    })
}

/// Motion level at or above which the corneal-contrast cue engages,
/// overridable via `IRLUME_BLINK_CONTRAST_MOTION_FLOOR`.
///
/// Zero is accepted here and refused at the other float settings, on purpose:
/// this floor names the motion below which the cue is SKIPPED, so zero is the
/// meaningful setting "apply it to every window", not a disabled threshold.
fn blink_contrast_motion_floor() -> f32 {
    env_override(
        "IRLUME_BLINK_CONTRAST_MOTION_FLOOR",
        BLINK_CONTRAST_MOTION_FLOOR,
        |v| v >= 0.0,
    )
}

/// Minimum ratio of open-eye to closed-eye corneal contrast for a dip to count,
/// overridable via `IRLUME_BLINK_CONTRAST_DROP`.
///
/// Positive only: the value is a required ratio of two measured positives,
/// which can never fall below zero, so a non-positive bar accepts everything.
fn blink_contrast_drop_min() -> f32 {
    env_override("IRLUME_BLINK_CONTRAST_DROP", BLINK_CONTRAST_DROP_MIN, |v| {
        v > 0.0
    })
}

/// Shared blink analysis: strobe classification, per-class open baseline, the
/// motion and corneal-contrast anti-spoof gates, and blink-onset detection
/// (deep EAR dip and sharp-V run). Returns every detected blink onset rather
/// than short-circuiting on the first, so a consumer can count deliberate
/// repeats. [`detect_blink`]'s observable result is unchanged: non-empty
/// `Events` ⇔ the old code returned `Blinked`.
fn blink_scan(samples: &[EarSample]) -> BlinkScan {
    if samples.is_empty() {
        return BlinkScan::NoEyes;
    }
    // Strobe visible? Compare typical adjacent brightness jump to typical level.
    let mut bris: Vec<f32> = samples.iter().map(|s| s.bri).collect();
    let mut deltas: Vec<f32> = samples
        .windows(2)
        .map(|w| (w[0].bri - w[1].bri).abs())
        .collect();
    let med_bri = median(&mut bris).unwrap_or(0.0).max(1.0);
    let strobing = median(&mut deltas).unwrap_or(0.0) > 0.30 * med_bri;
    let lit = |i: usize| -> bool {
        if !strobing {
            return true;
        }
        let prev = if i > 0 {
            samples[i - 1].bri
        } else {
            samples[i + 1].bri
        };
        let next = if i + 1 < samples.len() {
            samples[i + 1].bri
        } else {
            samples[i - 1].bri
        };
        samples[i].bri > (prev + next) / 2.0
    };
    // Per-class open baseline; classes too small or never-open don't count as eyes.
    let mut baseline = [None::<f32>; 2];
    for (class, slot) in baseline.iter_mut().enumerate() {
        let mut ears: Vec<f32> = samples
            .iter()
            .enumerate()
            .filter(|(i, s)| (lit(*i) == (class == 0)) && s.ear.is_some_and(|e| e.is_finite()))
            .map(|(_, s)| s.ear.unwrap())
            .collect();
        if ears.len() >= BLINK_MIN_CLASS_SAMPLES {
            *slot = median(&mut ears).filter(|m| *m >= BLINK_MIN_OPEN_EAR);
        }
    }
    // Merged ratio timeline (frame order, each sample against its class baseline).
    struct Obs {
        idx: usize,
        ratio: f32,
        bri: f32,
        lit: bool,
    }
    let ratios: Vec<Obs> = samples
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let base = baseline[if lit(i) { 0 } else { 1 }]?;
            let e = s.ear.filter(|e| e.is_finite())?;
            Some(Obs {
                idx: s.idx,
                ratio: e / base,
                bri: s.bri,
                lit: lit(i),
            })
        })
        .collect();
    if ratios.is_empty() {
        return BlinkScan::NoEyes;
    }
    // Motion gate: a moving print/camera fakes EAR dips via landmark jitter. If
    // the face was moving through the window (median speed over threshold), we
    // can't trust any dip as a real blink; downgrade to NoBlink (password
    // fallback), never granting on motion. A real blink keeps the head still.
    // The threshold is per-camera-calibrated (NexiGo default); a camera with a
    // different frame rate or bbox-jitter floor can override it via
    // IRLUME_BLINK_MOTION_MAX without a rebuild.
    let motion_max = blink_motion_max();
    let (_, motion_med, _) = face_speeds(samples);
    if motion_med > motion_max {
        return BlinkScan::Gated;
    }
    // Corneal-contrast gate (second, independent cue): a real blink occludes the
    // eye's specular glint under the lid, so open-eye contrast must exceed the
    // closed-frame contrast by a ratio. A diffuse print has no glint to lose
    // (ratio ~1).
    //
    // Applied ONLY above a low-motion floor. A rigid planar print held still
    // cannot produce an EAR dip: its landmarks are fixed, so a still bbox means
    // still eye landmarks (validated: a still banner never dips). Below the
    // floor the EAR blink is therefore trustworthy without the corneal cue,
    // which is also what keeps GLASSES usable (a lens IR reflection flattens the
    // contrast ratio to ~1.1, print-like, so a still glasses wearer must not be
    // gated on it). NOTE the motion metric is bbox-centroid based, so "still"
    // means the face box is still, not that the eye region is provably static:
    // a contrived print that animates only the eye at a fixed bbox would skip
    // this cue, but that merely reverts to the pre-cue baseline in the still
    // band (still gated by the IR-face requirement and recognition), not a
    // regression. The cue does its work in the slow-motion band [floor, gate],
    // where a slowly-moved print could otherwise fake a subtle dip. Skipped too
    // when no contrast was measured (backward-compat).
    let contrast_floor = blink_contrast_motion_floor();
    if motion_med >= contrast_floor {
        let (open_c, dip_c) = contrast_signature(samples);
        if open_c > 0.0 && dip_c > 0.0 {
            let drop_min = blink_contrast_drop_min();
            if open_c / dip_c < drop_min {
                return BlinkScan::Gated;
            }
        }
    }
    // Collect blink events from both detectors (rather than returning on the
    // first), each with the eyelid-closure span so a caller can tell a brief
    // spontaneous blink from a deliberately HELD closure.
    let mut events: Vec<BlinkEvent> = Vec::new();
    // Deep-dip detector: a closure begins on the first frame whose EAR falls to/
    // below the dip ratio and ends when the eye REOPENS (ratio back above the
    // open ratio). `end` tracks the last still-closed frame, so `end - onset` is
    // the closure duration in frame indices. Requiring a genuine reopen (not a
    // bare frame gap) is what separates two blinks from one long closure.
    let mut cur: Option<BlinkEvent> = None;
    for o in &ratios {
        if o.ratio <= BLINK_EAR_DIP_RATIO {
            match &mut cur {
                Some(ev) => ev.end = o.idx,
                None => {
                    cur = Some(BlinkEvent {
                        onset: o.idx,
                        end: o.idx,
                    })
                }
            }
        } else if o.ratio >= BLINK_V_OPEN_RATIO {
            if let Some(ev) = cur.take() {
                events.push(ev);
            }
        }
    }
    if let Some(ev) = cur.take() {
        events.push(ev);
    }
    // Sharp-V scan: maximal same-class runs of near-consecutive samples (frame
    // gap ≤ 3) at/below the run ratio. A blink spanning both classes appears as
    // one run per class, each judged on its own. These are brief by construction
    // (`BLINK_V_MAX_RUN`), so they register as short-closure events.
    let mut start = 0;
    while start < ratios.len() {
        if ratios[start].ratio > BLINK_V_RUN_RATIO {
            start += 1;
            continue;
        }
        let mut end = start;
        while end + 1 < ratios.len()
            && ratios[end + 1].ratio <= BLINK_V_RUN_RATIO
            && ratios[end + 1].lit == ratios[start].lit
            && ratios[end + 1].idx - ratios[end].idx <= 3
        {
            end += 1;
        }
        let run = &ratios[start..=end];
        let len = run.len();
        let deepest = run.iter().map(|o| o.ratio).fold(f32::INFINITY, f32::min);
        let deep_enough = deepest
            <= if len == 1 {
                BLINK_V_MIN_SINGLE
            } else {
                BLINK_V_MIN_MULTI
            };
        if len <= BLINK_V_MAX_RUN && deep_enough {
            let (first_idx, last_idx) = (run[0].idx, run[len - 1].idx);
            let run_bri = run.iter().map(|o| o.bri).sum::<f32>() / len as f32;
            let bri_ok = |b: f32| {
                b >= (1.0 - BLINK_V_BRI_BAND) * run_bri && b <= (1.0 + BLINK_V_BRI_BAND) * run_bri
            };
            let pre = ratios[..start].iter().rev().any(|o| {
                first_idx - o.idx <= BLINK_V_PRE_WIN
                    && o.ratio >= BLINK_V_OPEN_RATIO
                    && bri_ok(o.bri)
            });
            let post = ratios[end + 1..].iter().any(|o| {
                o.idx - last_idx <= BLINK_V_POST_WIN
                    && o.ratio >= BLINK_V_OPEN_RATIO
                    && bri_ok(o.bri)
            });
            if pre && post {
                events.push(BlinkEvent {
                    onset: first_idx,
                    end: last_idx,
                });
            }
        }
        start = end + 1;
    }
    // A blink caught by BOTH detectors (or by overlapping runs) must count once:
    // sort by onset and merge events whose onsets are within 3 frames, keeping
    // the wider closure span.
    events.sort_unstable_by_key(|e| e.onset);
    events.dedup_by(|next, kept| {
        if next.onset.saturating_sub(kept.onset) <= 3 {
            kept.end = kept.end.max(next.end);
            true
        } else {
            false
        }
    });
    BlinkScan::Events(events)
}

/// True when a NATURAL blink was observed (a clear EAR dip below the open
/// baseline) → live. Any single blink of any duration suffices. `NoBlink` = a
/// plausibly-open eye but no blink (a static artefact, or the user didn't blink;
/// the caller re-captures / falls back to password). `NoEyes` = no open eye
/// anywhere (mesh failed, or a non-eye/print): the median EAR never reached the
/// open floor.
pub fn detect_blink(samples: &[EarSample]) -> BlinkResult {
    match blink_scan(samples) {
        BlinkScan::NoEyes => BlinkResult::NoEyes,
        BlinkScan::Gated => BlinkResult::NoBlink,
        BlinkScan::Events(events) if !events.is_empty() => BlinkResult::Blinked,
        BlinkScan::Events(_) => BlinkResult::NoBlink,
    }
}

/// Per-user eye-closure calibration: the enrolled open-eye and closed-eye EAR
/// medians. Set once from an enrollment calibration (a few open frames, then a
/// held closure), NOT from the gesture window itself.
///
/// The consent gesture is measured against an ABSOLUTE, per-user threshold, not
/// a running-median baseline. That is deliberate: a running median is polluted
/// by the very closure being detected (once the eyes are shut for most of the
/// window the median drops to the closed value and the closure vanishes into the
/// "baseline"), a documented failure mode of relative EAR gating. Capturing the
/// open/closed extremes offline and comparing at a fixed midpoint (the
/// Modified-EAR method, PeerJ CS-943 / PMC9044337) avoids it, and validated
/// cleanly on real captures (a deliberate hold reads a 18-35 frame sub-threshold
/// run; spontaneous blinks and squints read ≤5).
///
/// KNOWN COST OF THAT CHOICE, measured 2026-07-27, one user, 20 readings: absolute
/// values move with the LIGHT. The same seated position gave a median open EAR of
/// 0.109 at an ambient of 22-42 and 0.166 at an ambient of 1, a 52% shift, with
/// the closed values rising too. No single calibration spans both sessions:
/// registering the deepest closure (0.0894) and the shallowest reopen (0.0984)
/// requires `(CLOSURE_REOPEN_FRACTION - CLOSURE_DEEP_FRACTION) * gap <= 0.0090`,
/// so `gap <= 0.030`, while [`MIN_CALIBRATION_SEPARATION`] demands 0.05. Each
/// session calibrates fine alone; the pair cannot. A calibration therefore
/// describes one lighting condition, which `calibrate-closure` and `doctor` both
/// now say out loud. [`detect_nod`] is pose-defined and carries none of this,
/// which is why it is the default and the only gesture the prompts name.
#[derive(Debug, Clone, Copy)]
pub struct ClosureCalibration {
    /// Median EAR with the eyes open (the smaller eye, as [`EarSample::ear`]).
    pub ear_open: f32,
    /// Median EAR with the eyes deliberately shut (near 0 on a clean landmark).
    pub ear_closed: f32,
}

impl ClosureCalibration {
    /// The closed threshold below which the eye counts as shut for the gesture.
    /// A DEEP fraction of the way from the user's closed extreme toward open, not
    /// the halfway Modified-EAR point: the blink-taxonomy "complete closure"
    /// level is an openness fraction of ~0.20-0.25 (PMC11133197), and requiring
    /// that depth is what rejects a shallow squint that only partly closes. On
    /// real captures the halfway point let a squint that hovered at ~0.12 count
    /// as shut; the deep fraction (~0.10 for this camera) breaks that run while
    /// still catching a genuine full hold (~0.05).
    pub fn closed_threshold(&self) -> f32 {
        self.ear_closed + CLOSURE_DEEP_FRACTION * (self.ear_open - self.ear_closed)
    }

    /// EAR at/above which the eyes count as REOPENED after a closure, confirming
    /// a discrete gesture rather than a sustained hold. A high openness fraction
    /// ([`CLOSURE_REOPEN_FRACTION`]) of the way back toward the open extreme, so
    /// a partial recovery (a squint easing slightly) does not count as a reopen.
    pub fn reopen_threshold(&self) -> f32 {
        self.ear_closed + CLOSURE_REOPEN_FRACTION * (self.ear_open - self.ear_closed)
    }

    /// True when open and closed are far enough apart to threshold reliably; a
    /// too-small gap means bad landmarks / pose and the calibration should be
    /// re-taken rather than trusted.
    pub fn is_usable(&self) -> bool {
        self.ear_open - self.ear_closed >= MIN_CALIBRATION_SEPARATION
    }
}

/// Median open-eye EAR over a window of samples, for the OPEN half of an
/// enrollment calibration (the user simply looks at the camera). `None` if no
/// eye was ever detected. Uses the median so a stray blink during the open
/// capture does not drag it down.
pub fn calibrate_open_ear(samples: &[EarSample]) -> Option<f32> {
    let mut ears: Vec<f32> = samples
        .iter()
        .filter_map(|s| s.ear)
        .filter(|e| e.is_finite())
        .collect();
    median(&mut ears)
}

/// Detect a DELIBERATE eye-closure consent gesture: a BOUNDED closure that
/// REOPENS. The eyes must go shut (EAR below the per-user
/// [`ClosureCalibration::closed_threshold`]) for a run of
/// [`CONSENT_CLOSURE_MIN_FRAMES`]..=[`CONSENT_CLOSURE_MAX_FRAMES`] face frames
/// (tolerating [`CLOSURE_HYSTERESIS_FRAMES`] dropout frames), then reopen (EAR
/// back up past [`ClosureCalibration::reopen_threshold`]) within
/// [`CLOSURE_REOPEN_WINDOW`] frames.
///
/// The bounds and the reopen are what make this hold up, learned from a hardware
/// capture campaign 2026-07-22: a deliberately HELD SQUINT is physically the
/// same as a held eye-closure (it goes just as deep on EAR), so neither depth
/// nor a duration floor alone can separate them. What separates them is SHAPE: a
/// deliberate gesture is a discrete ~1 s close-and-reopen (bounded run, clear
/// reopen), while a squint / eyes-closed / looking-away is a SUSTAINED hold that
/// runs past the upper bound and never reopens. On the campaign data this
/// rejected all 20 squints, all 20 look-down and every natural blink, while
/// accepting the deliberate holds. A single spontaneous blink (100-400 ms;
/// Bentivoglio 1997) is too SHORT to reach the lower bound.
///
/// `Blinked` = the gesture was seen, `NoBlink` = a face was seen but not the
/// gesture, `NoEyes` = no face frames at all.
pub fn detect_deliberate_closure(samples: &[EarSample], cal: &ClosureCalibration) -> BlinkResult {
    let face_frames: Vec<f32> = samples.iter().filter_map(|s| s.ear).collect();
    if face_frames.is_empty() {
        return BlinkResult::NoEyes;
    }
    let closed = cal.closed_threshold();
    let reopen = cal.reopen_threshold();
    let (min, max) = consent_closure_bounds();
    let hysteresis = CLOSURE_HYSTERESIS_FRAMES;

    // Walk closure runs (consecutive frames below `closed`, tolerating a few
    // dropout frames). A run qualifies when its length is within [min, max] AND
    // the eyes reopen (a frame back above `reopen`) within a short window after
    // it ends. A too-short run is a blink; a too-long run that never reopens is
    // a sustained squint / eyes-closed.
    let n = face_frames.len();
    let mut i = 0;
    while i < n {
        if face_frames[i] >= closed {
            i += 1;
            continue;
        }
        // Extend the run over sub-threshold frames, allowing `hysteresis`
        // consecutive above-threshold blips before it ends.
        let (start, mut end, mut dropouts) = (i, i, 0usize);
        let mut j = i;
        while j < n {
            if face_frames[j] < closed {
                end = j;
                dropouts = 0;
            } else if dropouts < hysteresis {
                dropouts += 1;
            } else {
                break;
            }
            j += 1;
        }
        let length = end - start + 1;
        if length >= min && length <= max {
            let reopened = face_frames
                .iter()
                .skip(end + 1)
                .take(CLOSURE_REOPEN_WINDOW)
                .any(|&e| e >= reopen);
            if reopened {
                return BlinkResult::Blinked;
            }
        }
        i = j.max(end + 1);
    }
    BlinkResult::NoBlink
}

/// The closure length window `[min, max]` for the consent gesture, in
/// consecutive face frames below the per-user closed threshold, overridable via
/// `IRLUME_CONSENT_CLOSURE_FRAMES` and `IRLUME_CONSENT_CLOSURE_MAX` for
/// per-camera-fps tuning.
///
/// The minimum is at least one frame, since a run of zero frames is not a
/// closure to detect. The pair is resolved together, and the returned window is
/// always satisfiable: `max >= min` holds for every combination of settings.
///
/// That invariant needs the built-in maximum to be raised as well as an
/// explicit one refused. `detect_deliberate_closure` accepts a run when
/// `length >= min && length <= max`, so an inverted pair silently accepts no
/// closure of any duration; and a minimum above the built-in maximum inverts
/// the pair without either value being refused, since a refusal rule only sees
/// values that were supplied. `IRLUME_CONSENT_CLOSURE_FRAMES=26` with the
/// maximum unset produced exactly that: a window of `[26, 25]`, consent
/// disabled, no line in the journal (#345 review).
fn consent_closure_bounds() -> (usize, usize) {
    closure_bounds_from(
        std::io::stderr().lock(),
        env_text("IRLUME_CONSENT_CLOSURE_FRAMES").as_deref(),
        env_text("IRLUME_CONSENT_CLOSURE_MAX").as_deref(),
    )
}

/// [`consent_closure_bounds`] with both variables' text supplied directly, so
/// the invariant is testable at every combination without an environment.
fn closure_bounds_from(
    mut out: impl std::io::Write,
    min_raw: Option<&str>,
    max_raw: Option<&str>,
) -> (usize, usize) {
    let min = resolve_override(
        &mut out,
        "IRLUME_CONSENT_CLOSURE_FRAMES",
        min_raw,
        CONSENT_CLOSURE_MIN_FRAMES,
        |v| v >= 1,
    );
    // The minimum is read once and carried into both the fallback and the rule.
    // Re-reading it inside the rule would be a second observation of a setting
    // the first half of this pair has already acted on.
    let max = resolve_override(
        &mut out,
        "IRLUME_CONSENT_CLOSURE_MAX",
        max_raw,
        CONSENT_CLOSURE_MAX_FRAMES.max(min),
        |v| v >= min,
    );
    (min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- environment overrides (#345) ---
    //
    // No test here mutates this process's environment. `set_var` is unsafe on
    // Unix whatever lock the mutating threads agree on, because the readers
    // that matter sit in libc and in dependencies that take no lock. So the
    // decision is driven through its text-in, writer-out seam, and the tests
    // that must cross the real environment boundary re-run this binary in a
    // CHILD whose variables `Command::env` fills in before it starts. Same
    // shape as `irlume-common`'s dbglog test.

    /// The helper's own contract on the text: only a value that parses, is
    /// comparable, and clears the site's range rule wins.
    #[test]
    fn resolve_override_keeps_the_default_for_every_unusable_value() {
        let positive = |v: f32| v > 0.0;
        for raw in [
            "nan", "NaN", "-nan", "inf", "-inf", "infinity", // not comparable
            "-0.5", "-1", "0", // outside a positive-only range
            "twelve", "", "  ", "1,5", "12.5x", "0x10", // not a number
        ] {
            assert_eq!(
                resolve_override(std::io::sink(), "IRLUME_TEST_F32", Some(raw), 7.5, positive),
                7.5,
                "{raw:?} should not have replaced the default"
            );
        }
        // The same shapes on a usize setting, whose parse also rejects a
        // fractional or negative count.
        for raw in ["0", "-1", "2.5", "many", ""] {
            assert_eq!(
                resolve_override(
                    std::io::sink(),
                    "IRLUME_TEST_USIZE",
                    Some(raw),
                    11,
                    |v: usize| { v >= 1 }
                ),
                11,
                "{raw:?} should not have replaced the default"
            );
        }
    }

    #[test]
    fn resolve_override_takes_a_value_that_clears_the_range_rule() {
        let positive = |v: f32| v > 0.0;
        let sunk =
            |raw| resolve_override(std::io::sink(), "IRLUME_TEST_F32", Some(raw), 7.5, positive);
        assert_eq!(sunk("0.5"), 0.5);
        // Whitespace a systemd drop-in leaves behind is trimmed off first.
        assert_eq!(sunk("\t 1e3\n"), 1000.0);
        assert_eq!(
            resolve_override(
                std::io::sink(),
                "IRLUME_TEST_USIZE",
                Some(" 3 "),
                11,
                |v: usize| { v >= 1 }
            ),
            3
        );
    }

    /// The refusal is a diagnostic, so its failure must not become the
    /// authentication's failure: a writer that errors on every byte still
    /// leaves the caller holding the safe default.
    #[test]
    fn a_report_writer_that_fails_still_yields_the_default() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(
            resolve_override(
                Broken,
                "IRLUME_TEST_BROKEN_WRITER",
                Some("nan"),
                28.0,
                |v: f32| { v > 0.0 }
            ),
            28.0
        );
    }

    /// The line itself: one per variable, naming the variable, the value, the
    /// reason, and the value left in force.
    #[test]
    fn a_refusal_writes_one_line_naming_the_variable_and_the_reason() {
        let mut out = Vec::new();
        for _ in 0..3 {
            resolve_override(
                &mut out,
                "IRLUME_TEST_ONE_LINE",
                Some("nan"),
                28.0,
                |v: f32| v > 0.0,
            );
        }
        resolve_override(
            &mut out,
            "IRLUME_TEST_ONE_LINE_OTHER",
            Some("-1"),
            11,
            |v: usize| v >= 1,
        );
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected one line per variable, got {text:?}"
        );
        assert_eq!(
            lines[0],
            r#"irlume: ignoring IRLUME_TEST_ONE_LINE="nan" (not a finite number); using 28"#
        );
        assert_eq!(
            lines[1],
            r#"irlume: ignoring IRLUME_TEST_ONE_LINE_OTHER="-1" (not a number); using 11"#
        );
    }

    /// An unset variable is not a refusal, so it writes nothing at all.
    #[test]
    fn an_unset_variable_writes_nothing() {
        let mut out = Vec::new();
        assert_eq!(
            resolve_override(&mut out, "IRLUME_TEST_UNSET_PROBE", None, 1.5, |v: f32| v
                > 0.0),
            1.5
        );
        assert!(out.is_empty(), "an unset variable reported: {out:?}");
    }

    /// The closure window must be satisfiable at every combination of the two
    /// settings, including the ordering that needs no refusal to go wrong: a
    /// minimum above the BUILT-IN maximum, with the maximum unset.
    #[test]
    fn the_closure_window_is_always_satisfiable() {
        let above_default_max = (CONSENT_CLOSURE_MAX_FRAMES + 5).to_string();
        let below_default_min = (CONSENT_CLOSURE_MIN_FRAMES - 1).to_string();
        // A minimum past the built-in maximum carries the maximum up with it.
        assert_eq!(
            closure_bounds_from(std::io::sink(), Some(&above_default_max), None),
            (
                CONSENT_CLOSURE_MAX_FRAMES + 5,
                CONSENT_CLOSURE_MAX_FRAMES + 5
            )
        );
        // A maximum under the minimum in force is refused, and the built-in
        // pair stands.
        assert_eq!(
            closure_bounds_from(std::io::sink(), None, Some(&below_default_min)),
            (CONSENT_CLOSURE_MIN_FRAMES, CONSENT_CLOSURE_MAX_FRAMES)
        );
        // A usable pair is taken as given.
        assert_eq!(
            closure_bounds_from(std::io::sink(), Some("3"), Some("9")),
            (3, 9)
        );
        // And the invariant over the grid, refused and usable shapes mixed.
        let mins = [
            None,
            Some("1"),
            Some("11"),
            Some("26"),
            Some("40"),
            Some("0"),
            Some("x"),
        ];
        let maxes = [
            None,
            Some("2"),
            Some("25"),
            Some("60"),
            Some("-1"),
            Some("x"),
        ];
        for min_raw in mins {
            for max_raw in maxes {
                let (min, max) = closure_bounds_from(std::io::sink(), min_raw, max_raw);
                assert!(
                    min >= 1 && max >= min,
                    "min {min_raw:?} max {max_raw:?} gave an empty window [{min}, {max}]"
                );
            }
        }
    }

    /// Every setting, with the variable's name, four shapes it must refuse, a
    /// value it must take, and the effective value each yields.
    ///
    /// The refused shapes are per setting rather than one shared list because
    /// the boundary is where a relaxed rule shows: at a positive-only threshold
    /// the discriminating case is `0`, and at the contrast floor, where zero is
    /// a real setting, it is the value just below it.
    struct Setting {
        name: &'static str,
        refused: [&'static str; 4],
        usable: (&'static str, &'static str),
        fallback: String,
    }

    fn settings() -> Vec<Setting> {
        vec![
            Setting {
                name: "IRLUME_RGB_MOIRE_MAX",
                refused: ["nan", "-1", "0", "moire"],
                usable: (" 15.0 ", "15"),
                fallback: RGB_MOIRE_MAX.to_string(),
            },
            Setting {
                name: "IRLUME_NOD_PITCH_MIN",
                refused: ["inf", "-0.05", "0", "a bit"],
                usable: ("0.2", "0.2"),
                fallback: NOD_PITCH_MIN.to_string(),
            },
            Setting {
                name: "IRLUME_BLINK_MOTION_MAX",
                refused: ["nan", "-1", "0", "fast"],
                usable: ("0.005", "0.005"),
                fallback: BLINK_MOTION_MAX_MEDIAN.to_string(),
            },
            Setting {
                // Zero is a SETTING here, not a refusal, so the boundary case
                // is the value immediately below it.
                name: "IRLUME_BLINK_CONTRAST_MOTION_FLOOR",
                refused: ["nan", "-1", "-0.0001", "still"],
                usable: ("0", "0"),
                fallback: BLINK_CONTRAST_MOTION_FLOOR.to_string(),
            },
            Setting {
                name: "IRLUME_BLINK_CONTRAST_DROP",
                refused: ["inf", "-1", "0", "1.15x"],
                usable: ("3", "3"),
                fallback: BLINK_CONTRAST_DROP_MIN.to_string(),
            },
            Setting {
                name: "IRLUME_CONSENT_CLOSURE_FRAMES",
                refused: ["0", "-1", "2.5", "eleven"],
                usable: ("3", "3"),
                fallback: CONSENT_CLOSURE_MIN_FRAMES.to_string(),
            },
            Setting {
                name: "IRLUME_CONSENT_CLOSURE_MAX",
                refused: ["0", "-1", "2.5", "twenty"],
                usable: ("30", "30"),
                fallback: CONSENT_CLOSURE_MAX_FRAMES.to_string(),
            },
        ]
    }

    /// The effective value of one setting, through the accessor the detectors
    /// call. Read in a child process, where the environment is fixed.
    fn effective(name: &str) -> String {
        match name {
            "IRLUME_RGB_MOIRE_MAX" => rgb_moire_max().to_string(),
            "IRLUME_NOD_PITCH_MIN" => nod_pitch_min().to_string(),
            "IRLUME_BLINK_MOTION_MAX" => blink_motion_max().to_string(),
            "IRLUME_BLINK_CONTRAST_MOTION_FLOOR" => blink_contrast_motion_floor().to_string(),
            "IRLUME_BLINK_CONTRAST_DROP" => blink_contrast_drop_min().to_string(),
            "IRLUME_CONSENT_CLOSURE_FRAMES" => consent_closure_bounds().0.to_string(),
            "IRLUME_CONSENT_CLOSURE_MAX" => consent_closure_bounds().1.to_string(),
            other => panic!("no accessor for {other}"),
        }
    }

    fn in_child() -> Option<String> {
        std::env::var("IRLUME_TEST_CASE").ok()
    }

    /// Re-runs `test` in a child process carrying `vars`, and fails with the
    /// child's output if it does not pass.
    ///
    /// The child's environment is built by `Command::env` before the process
    /// exists, so nothing is ever mutated in a running multithreaded program.
    /// Every setting is cleared first: a developer with one exported must not
    /// change what this test measures.
    fn run_in_child(test: &str, case: &str, vars: &[(&str, &str)]) {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([test, "--exact", "--test-threads=1"]);
        for s in settings() {
            cmd.env_remove(s.name);
        }
        cmd.env("IRLUME_TEST_CASE", case);
        for (k, v) in vars {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // "1 passed" as well as the exit status: libtest exits 0 when a filter
        // matches NOTHING, so a renamed test would otherwise turn every case
        // here into a green run of no assertions.
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "child case {case:?} with {vars:?} did not run green:\n{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Each accessor reads ITS variable, applies ITS range rule, and falls back
    /// to ITS default. One child per row, with all seven variables set, since
    /// the settings are independent.
    #[test]
    fn every_threshold_reads_its_own_variable() {
        if let Some(case) = in_child() {
            for s in settings() {
                let want = match case.as_str() {
                    "usable" => s.usable.1.to_string(),
                    _ => s.fallback.clone(),
                };
                assert_eq!(effective(s.name), want, "{} in case {case}", s.name);
            }
            return;
        }
        for shape in 0..4 {
            let vars: Vec<(&str, &str)> = settings()
                .iter()
                .map(|s| (s.name, s.refused[shape]))
                .collect();
            run_in_child(
                "tests::every_threshold_reads_its_own_variable",
                &format!("refused{shape}"),
                &vars,
            );
        }
        let vars: Vec<(&str, &str)> = settings().iter().map(|s| (s.name, s.usable.0)).collect();
        run_in_child(
            "tests::every_threshold_reads_its_own_variable",
            "usable",
            &vars,
        );
    }

    /// #345 at the boundary it was reported at: a refused ceiling must leave
    /// the screen cue firing. A `nan` ceiling loses every comparison, so
    /// `score > ceiling` was false for any score and the RGB-only path's one
    /// anti-screen cue was off.
    #[test]
    fn a_refused_moire_ceiling_leaves_the_screen_cue_armed() {
        let face = |moire: f32| Signals {
            rgb_face: Some(FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: 0.9,
            }),
            rgb_face_brightness: 120.0,
            rgb_specular_frac: 0.02,
            rgb_moire_score: moire,
            ..Default::default()
        };
        if let Some(case) = in_child() {
            // 40 is above the 28 default, inside the close-replay band the
            // constant was calibrated against; 20 is under it.
            let (verdict, _, why) = LivenessGate.evaluate_rgb_only(&face(40.0));
            assert_eq!(verdict, Verdict::Spoof, "case {case}: {why}");
            let want = if case == "usable" {
                Verdict::Spoof // the tightened 15 ceiling catches 20 as well
            } else {
                Verdict::Live
            };
            let (verdict, _, why) = LivenessGate.evaluate_rgb_only(&face(20.0));
            assert_eq!(verdict, want, "case {case}: {why}");
            return;
        }
        // Unset, the cue fires above 28 and not below it.
        assert_eq!(
            LivenessGate.evaluate_rgb_only(&face(40.0)).0,
            Verdict::Spoof
        );
        assert_eq!(LivenessGate.evaluate_rgb_only(&face(20.0)).0, Verdict::Live);
        for raw in ["nan", "inf", "-1", "0", "moire"] {
            run_in_child(
                "tests::a_refused_moire_ceiling_leaves_the_screen_cue_armed",
                raw,
                &[("IRLUME_RGB_MOIRE_MAX", raw)],
            );
        }
        run_in_child(
            "tests::a_refused_moire_ceiling_leaves_the_screen_cue_armed",
            "usable",
            &[("IRLUME_RGB_MOIRE_MAX", "15")],
        );
    }

    /// The blink gates move with their variables, and the contrast floor's zero
    /// is a setting rather than a disabled threshold: it applies the corneal cue
    /// to a window the default skips as too still to need it.
    #[test]
    fn the_blink_gates_move_with_their_variables() {
        let ears = [0.24, 0.24, 0.23, 0.15, 0.16, 0.24, 0.24, 0.23, 0.24];
        // Still face, flat corneal contrast: below the floor the EAR blink is
        // trusted on its own, which is what keeps glasses usable.
        let still = moving_seq(&ears, 0.0, |_| 60.0);
        // Slow band, contrast collapsing with the EAR: a genuine blink.
        let slow = moving_seq(&ears, 1.7, |e| e * 500.0);
        if let Some(case) = in_child() {
            let (fixture, want) = match case.as_str() {
                "floor" => (&still, BlinkResult::NoBlink),
                "motion" => (&slow, BlinkResult::NoBlink),
                "drop" => (&slow, BlinkResult::NoBlink),
                other => panic!("unknown case {other}"),
            };
            assert_eq!(detect_blink(fixture), want, "case {case}");
            return;
        }
        assert_eq!(detect_blink(&still), BlinkResult::Blinked);
        assert_eq!(detect_blink(&slow), BlinkResult::Blinked);
        run_in_child(
            "tests::the_blink_gates_move_with_their_variables",
            "floor",
            &[("IRLUME_BLINK_CONTRAST_MOTION_FLOOR", "0")],
        );
        run_in_child(
            "tests::the_blink_gates_move_with_their_variables",
            "motion",
            &[("IRLUME_BLINK_MOTION_MAX", "0.005")],
        );
        run_in_child(
            "tests::the_blink_gates_move_with_their_variables",
            "drop",
            &[("IRLUME_BLINK_CONTRAST_DROP", "3.0")],
        );
    }

    /// EAR trace with a per-frame horizontal step (in pixels, against a face
    /// size of 100) and a corneal-contrast rule of the caller's choosing.
    fn moving_seq(ears: &[f32], step: f32, contrast: impl Fn(f32) -> f32) -> Vec<EarSample> {
        ears.iter()
            .enumerate()
            .map(|(i, &e)| EarSample {
                idx: i,
                ear: Some(e),
                bri: 60.0,
                cx: 100.0 + i as f32 * step,
                cy: 100.0,
                fsize: 100.0,
                contrast: contrast(e),
            })
            .collect()
    }

    // --- head-nod consent gesture (detect_nod) ---
    fn pose_seq(pitch: &[f32], yaw: &[f32]) -> Vec<PoseSample> {
        pitch
            .iter()
            .zip(yaw)
            .enumerate()
            .map(|(i, (&p, &y))| PoseSample {
                idx: i,
                pitch_frac: Some(p),
                yaw_signed: Some(y),
                bri: 60.0,
            })
            .collect()
    }

    #[test]
    fn deliberate_nod_is_detected() {
        // Pitch swings down-up-down (a 2-nod), yaw flat. Range ~0.12, oscillates.
        let pitch = [
            0.53, 0.55, 0.60, 0.63, 0.58, 0.52, 0.51, 0.55, 0.62, 0.64, 0.57, 0.52, 0.53, 0.56,
        ];
        let yaw = [0.05; 14];
        assert_eq!(detect_nod(&pose_seq(&pitch, &yaw)), HeadGesture::Nod);
    }

    #[test]
    fn still_head_is_not_a_nod() {
        // Near-flat pitch (range ~0.02), the campaign still-take shape.
        let pitch = [
            0.57, 0.568, 0.571, 0.569, 0.57, 0.572, 0.568, 0.57, 0.569, 0.571, 0.57, 0.568, 0.569,
            0.57,
        ];
        let yaw = [0.09; 14];
        assert_eq!(detect_nod(&pose_seq(&pitch, &yaw)), HeadGesture::None);
    }

    #[test]
    fn look_around_is_not_a_nod() {
        // Big yaw swings (idle glancing): excluded by the yaw gate even though
        // pitch also moves.
        let pitch = [
            0.52, 0.58, 0.63, 0.55, 0.60, 0.51, 0.57, 0.62, 0.54, 0.59, 0.53, 0.61, 0.56, 0.58,
        ];
        let yaw = [
            0.1, 1.2, -0.8, 2.0, -1.5, 0.9, -2.1, 1.8, -0.6, 1.1, -1.9, 0.7, -1.3, 1.6,
        ];
        assert_eq!(detect_nod(&pose_seq(&pitch, &yaw)), HeadGesture::None);
    }

    #[test]
    fn single_look_down_drift_is_not_a_nod() {
        // Pitch drifts down and STAYS (looking down to read), never oscillates
        // back up: high range but too few crossings.
        let pitch = [
            0.52, 0.54, 0.57, 0.60, 0.62, 0.63, 0.63, 0.64, 0.63, 0.64, 0.63, 0.64, 0.63, 0.64,
        ];
        let yaw = [0.05; 14];
        assert_eq!(detect_nod(&pose_seq(&pitch, &yaw)), HeadGesture::None);
    }

    #[test]
    fn too_few_face_frames_is_noface() {
        let pitch = [0.5, 0.6, 0.5];
        let yaw = [0.0; 3];
        assert_eq!(detect_nod(&pose_seq(&pitch, &yaw)), HeadGesture::NoFace);
    }

    fn fb(cx: f32, cy: f32) -> FaceBox {
        FaceBox { cx, cy, score: 0.9 }
    }

    fn live_signals() -> Signals {
        Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: Some(fb(0.52, 0.49)),
            ir_face_brightness: 90.0,
            ir_center_edge_ratio: 1.2,
            ir_eye_glint: Some(220.0),
            // A Grey8 camera, which is what the fleet actually runs and what
            // every cue below this is written against. Stated rather than
            // defaulted: the default is FALSE (fail-safe), so a fixture that
            // wants to exercise a cue past the exposure gate has to say so
            // (#358).
            ir_ceiling_known: true,
            // ...and a face that was actually read and found unclipped. Leaving
            // this None while claiming a known ceiling is a state production
            // cannot reach, because a measurable format with a face present
            // always yields a number (#358).
            ir_saturated_frac: Some(0.0),
            ..Default::default() // frontal pose
        }
    }

    /// A blown face region is refused before any cue reads it (#237), on EVERY
    /// evaluator that can release credentials. The signals are otherwise a
    /// textbook live face, so only the clipped fraction can move the verdict.
    ///
    /// Both paths are asserted here because the first version of this change
    /// gated only `evaluate`, and `evaluate_ir_only` (the dark-room path that
    /// authenticates when RGB finds nothing) kept returning Live for exactly
    /// the frames the other path had begun refusing. A test that exercised one
    /// evaluator could not see that.
    #[test]
    fn a_blown_ir_face_is_refused_on_every_credential_releasing_path() {
        let gate = LivenessGate::new();
        for frac in [0.11, 0.25, 0.5, 1.0] {
            let mut s = live_signals();
            s.ir_saturated_frac = Some(frac);
            for (path, (verdict, cues, reason)) in [
                ("cross-spectrum", gate.evaluate(&s)),
                ("ir-only", gate.evaluate_ir_only(&s)),
            ] {
                assert_eq!(
                    verdict,
                    Verdict::Uncertain,
                    "{path} judged a frame {frac} clipped, which measures nothing"
                );
                assert!(!cues.ir_exposure_ok, "{path}");
                assert!(
                    reason.contains("blown out"),
                    "{path}: the reason must name the exposure, not a cue read from it: {reason}"
                );
            }
        }
    }

    /// The refusal is an exposure ceiling, not a new spoof cue: everything at
    /// or under the limit is judged exactly as before.
    ///
    /// The unmeasurable case is deliberately NOT here. This doc used to claim
    /// that a format with no known ceiling "must not deny anyone", which is the
    /// fail-open #358 removed, and the body three lines down now asserts the
    /// opposite. A test whose documentation states the inverse of its own
    /// assertions is worse than an undocumented one.
    #[test]
    fn a_readable_ir_face_is_judged_as_before() {
        let gate = LivenessGate::new();
        // `None` was in this list and asserted Live, which is the fail-open
        // #358 removed: on a camera whose format defines no ceiling the gate
        // was passing frames it had not read. A measurable camera with a face
        // present always yields Some, so the readable cases are the Some ones;
        // the unmeasurable case has its own test below.
        for frac in [Some(0.0), Some(0.063), Some(IR_SATURATED_FRAC_MAX)] {
            let mut live = live_signals();
            live.ir_saturated_frac = frac;
            let mut flat = live_signals();
            flat.ir_saturated_frac = frac;
            flat.ir_center_edge_ratio = 1.0; // flat
            for (path, live_verdict, flat_verdict) in [
                (
                    "cross-spectrum",
                    gate.evaluate(&live).0,
                    gate.evaluate(&flat).0,
                ),
                (
                    "ir-only",
                    gate.evaluate_ir_only(&live).0,
                    gate.evaluate_ir_only(&flat).0,
                ),
            ] {
                assert_eq!(
                    live_verdict,
                    Verdict::Live,
                    "{path}: a live face must stay Live at ir_saturated_frac {frac:?}"
                );
                assert_eq!(
                    flat_verdict,
                    Verdict::Spoof,
                    "{path}: a flat target must still be called a spoof at {frac:?}, not merely refused"
                );
            }
        }
    }

    /// The limited #174 campaign (2026-08-04) did not justify a
    /// distance-normalised gate: observed center/edge ranges overlapped
    /// across ~30 to ~80 cm on one subject and one module, and brightness
    /// is an auto-exposure output no 1/d^2 model can hold against (see
    /// `Signals::face_frac`). This test pins the current contract that
    /// `face_frac` remains observational and cannot change a verdict until
    /// a distance-aware rule is separately derived and reviewed.
    #[test]
    fn face_frac_changes_no_verdict() {
        let gate = LivenessGate::new();
        // Across the framing guide's whole accepted band and past both ends.
        for frac in [0.0, 0.05, 0.12, 0.3, 0.55, 0.9] {
            let mut live = live_signals();
            live.face_frac = frac;
            assert_eq!(
                gate.evaluate(&live).0,
                Verdict::Live,
                "a live face must stay Live at face_frac {frac}"
            );
            // And the same on the spoof side: a flat target does not become
            // live by sitting closer, nor a live face a spoof by sitting back.
            let mut flat = live_signals();
            flat.face_frac = frac;
            flat.ir_center_edge_ratio = 1.0; // flat
            assert_ne!(
                gate.evaluate(&flat).0,
                Verdict::Live,
                "a flat target must not pass at face_frac {frac}"
            );
        }
    }

    /// The cue is still supporting-only. Making it honest must not promote it
    /// into something decisive, on either evaluator.
    #[test]
    fn an_unreadable_glint_changes_no_verdict() {
        let gate = LivenessGate::new();
        for glint in [None, Some(0.0), Some(126.0), Some(255.0)] {
            let mut live = live_signals();
            live.ir_eye_glint = glint;
            assert_eq!(
                gate.evaluate(&live).0,
                Verdict::Live,
                "a live face must stay Live at glint {glint:?}"
            );
        }
    }

    /// A railed eye peak records as ABSENT, and absent is not "present".
    ///
    /// The corpus this cue feeds is what any future re-derivation of
    /// [`GLINT_MIN`] would be fitted to, and you cannot observe two populations
    /// in a variable that is pinned at the sensor's ceiling. In
    /// `docs/pad-results/2026-08-04-occluder-gate.jsonl` all 8 records carrying
    /// a glint are railed at exactly 255, so before this change "glint present"
    /// and "the peak railed" named the same 8 records (#222).
    #[test]
    fn a_railed_glint_records_as_absent_not_as_the_strongest_reading() {
        let gate = LivenessGate::new();
        for signals in [live_signals()] {
            // Three-way separation, which is the whole point: unreadable, read
            // and dim, read and strong. Before this, the first and third were
            // the same value.
            for (glint, want_readable, want_present) in [
                (None, false, false),
                (Some(126.0), true, false), // the highest unpegged reading in that corpus
                (Some(220.0), true, true),
            ] {
                let mut s = signals.clone();
                s.ir_eye_glint = glint;
                let (_, cues, _) = gate.evaluate(&s);
                assert_eq!(cues.glint_readable, want_readable, "readable for {glint:?}");
                assert_eq!(cues.glint_present, want_present, "present for {glint:?}");
            }
        }
        // BOTH evaluators. #237's first version gated one path and left the
        // dark-room path accepting what the other refused.
        let mut dark = live_signals();
        dark.ir_eye_glint = None;
        let (_, cues, _) = gate.evaluate_ir_only(&dark);
        assert!(!cues.glint_present, "an absent glint is not a present one");
        assert!(!cues.glint_readable);
    }

    #[test]
    fn live_face_passes() {
        assert_eq!(
            LivenessGate::new().evaluate(&live_signals()).0,
            Verdict::Live
        );
    }

    #[test]
    fn off_angle_face_is_uncertain() {
        // A real, co-located, IR-lit 3D face that is turned away -> Uncertain
        // (positioning), never Spoof or Live.
        let mut yaw = live_signals();
        yaw.head_yaw_asym = 0.5; // turned
        assert_eq!(LivenessGate::new().evaluate(&yaw).0, Verdict::Uncertain);
        let mut down = live_signals();
        down.head_pitch_frac = 0.15; // chin down
        assert_eq!(LivenessGate::new().evaluate(&down).0, Verdict::Uncertain);
    }

    /// The cross-spectrum co-location cue: RGB and IR faces at far-apart centers
    /// must be refused, because a print or screen can put the two "faces" in
    /// different places. Every other evaluate() test uses aligned centers
    /// (dist ~0.02), so a mutant making cross_spectrum_aligned unconditionally
    /// true survives (pattern #28), letting a mismatched presentation past the
    /// one cue that ties the two spectra to the same physical object.
    #[test]
    fn misaligned_rgb_ir_faces_are_refused() {
        let mut s = live_signals();
        s.rgb_face = Some(fb(0.2, 0.2));
        s.ir_face = Some(fb(0.8, 0.8)); // dist ~0.85, well past CROSS_SPECTRUM_TOLERANCE 0.30
        let (verdict, cues, reason) = LivenessGate::new().evaluate(&s);
        assert!(
            !cues.cross_spectrum_aligned,
            "far-apart faces are not aligned: {reason}"
        );
        assert_ne!(
            verdict,
            Verdict::Live,
            "a cross-spectrum mismatch cannot be Live: {reason}"
        );
        assert!(
            reason.contains("RGB/IR face mismatch"),
            "the mismatch cue must be the one that refuses: {reason}"
        );
    }

    #[test]
    fn flat_ir_is_spoof() {
        let mut s = live_signals();
        s.ir_center_edge_ratio = 1.0; // uniform => flat
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    #[test]
    fn ambient_flood_rewords_but_still_denies() {
        // Flat under flood ambient: still Spoof (fail closed), but the reason
        // says what is wrong (too much IR behind the user) instead of accusing
        // a genuine face of being a photo. Both starved cues get the wording.
        let mut s = live_signals();
        s.ir_center_edge_ratio = 0.85; // outdoor-flat (2026-07-16 field data)
        s.ir_ambient = 190.0;
        let (v, _, reason) = LivenessGate::new().evaluate(&s);
        assert_eq!(v, Verdict::Spoof);
        assert!(reason.contains("too much IR light behind you"), "{reason}");

        let mut s = live_signals();
        s.ir_face_brightness = 20.0; // starved by subtraction/backlight
        s.ir_ambient = 190.0;
        let (v, _, reason) = LivenessGate::new().evaluate(&s);
        assert_eq!(v, Verdict::Spoof);
        assert!(reason.contains("too much IR light behind you"), "{reason}");

        // Same cues indoors (low ambient): the specific accusations remain,
        // and the ir-only/dark path rewords the same way under flood.
        let mut s = live_signals();
        s.ir_center_edge_ratio = 0.85;
        s.ir_ambient = 60.0;
        let (_, _, reason) = LivenessGate::new().evaluate(&s);
        assert!(reason.contains("IR too flat"), "{reason}");

        let mut s = live_signals();
        s.rgb_face = None;
        s.ir_center_edge_ratio = 0.85;
        s.ir_ambient = 200.0;
        let (v, _, reason) = LivenessGate::new().evaluate_ir_only(&s);
        assert_eq!(v, Verdict::Spoof);
        assert!(reason.contains("too much IR light behind you"), "{reason}");
    }

    #[test]
    fn screen_with_no_ir_face_is_spoof() {
        let s = Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: None,
            ir_face_brightness: 5.0,
            ..Default::default()
        };
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    #[test]
    fn dark_ir_face_is_spoof() {
        let s = Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: Some(fb(0.5, 0.5)),
            ir_face_brightness: 12.0,
            // A readable Grey8 frame, so the darkness below is what decides
            // this and not the exposure gate above it (#358).
            ir_ceiling_known: true,
            ir_saturated_frac: Some(0.0),
            ..Default::default()
        };
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    /// A camera whose IR format defines no sensor ceiling is refused, not
    /// passed (#358).
    ///
    /// This was the fail-open: `is_none_or` read "could not measure" as "clean",
    /// so on any IR node negotiating Y16/Y10/Y12/NV12/YUYV the #237 exposure
    /// gate was off entirely and every cue below it ran on a frame nobody had
    /// checked. The signals here are otherwise a textbook live face, so only
    /// the missing ceiling can move the verdict.
    #[test]
    fn an_unmeasurable_ir_format_is_refused_on_every_credential_releasing_path() {
        let gate = LivenessGate::new();
        let mut s = live_signals();
        s.ir_ceiling_known = false;
        s.ir_saturated_frac = None;

        for (path, (verdict, cues, reason)) in [
            ("cross-spectrum", gate.evaluate(&s)),
            ("ir-only", gate.evaluate_ir_only(&s)),
        ] {
            assert_eq!(
                verdict,
                Verdict::Uncertain,
                "{path}: an unread frame is not a passed frame"
            );
            assert!(
                !cues.ir_exposure_measured,
                "{path}: the corpus must record that nothing was measured"
            );
            assert!(
                !cues.ir_exposure_ok,
                "{path}: an unmeasured exposure is not a clean one"
            );
            // The wording carries two jobs: it must not tell the user to move,
            // which cannot help, and its prefix is what keeps the refusal out
            // of the presence-retryable set in irlume-auth.
            assert!(
                reason.starts_with("IR exposure unmeasurable"),
                "{path}: prefix is pinned by irlume-auth's liveness_deny_kind: {reason}"
            );
            assert!(
                !reason.contains("move back"),
                "{path}: moving cannot repair a format with no ceiling: {reason}"
            );
        }
    }

    /// The same signals with a measurable ceiling stay Live, so the refusal
    /// above is attributable to the missing ceiling and nothing else.
    #[test]
    fn a_measurable_ceiling_still_passes_a_live_face() {
        let gate = LivenessGate::new();
        let s = live_signals();
        assert!(s.ir_ceiling_known);
        let (verdict, cues, _) = gate.evaluate(&s);
        assert_eq!(verdict, Verdict::Live);
        assert!(cues.ir_exposure_measured && cues.ir_exposure_ok);
    }

    #[test]
    fn no_subject_is_uncertain() {
        let s = Signals::default();
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Uncertain);
    }

    /// Uniform lighting (no strobe): every frame same brightness, all with a face.
    fn flat(ears: &[f32]) -> Vec<EarSample> {
        ears.iter()
            .enumerate()
            .map(|(i, &e)| EarSample {
                idx: i,
                ear: Some(e),
                bri: 60.0,
                // Still face (constant position) so the motion gate passes.
                cx: 100.0,
                cy: 100.0,
                fsize: 100.0,
                // Contrast tracks EAR (open eye = bright corneal glint, blink =
                // glint occluded), so a real blink shows the contrast drop the
                // gate requires; a flat EAR trace stays flat here too.
                contrast: e * 500.0,
            })
            .collect()
    }

    /// Emitter strobe: even frames lit (bri 60) with `lit` EARs, odd frames
    /// ambient-only (bri 9) with `dark` EARs (None = face not detected).
    fn strobed(lit: &[f32], dark: &[Option<f32>]) -> Vec<EarSample> {
        let mut out = Vec::new();
        for i in 0..lit.len().max(dark.len()) {
            if i < lit.len() {
                out.push(EarSample {
                    idx: 2 * i,
                    ear: Some(lit[i]),
                    bri: 60.0,
                    cx: 100.0,
                    cy: 100.0,
                    fsize: 100.0,
                    contrast: lit[i] * 500.0,
                });
            }
            if i < dark.len() {
                out.push(EarSample {
                    idx: 2 * i + 1,
                    ear: dark[i],
                    bri: 9.0,
                    cx: 100.0,
                    cy: 100.0,
                    fsize: dark[i].map_or(0.0, |_| 100.0),
                    contrast: dark[i].map_or(0.0, |e| e * 500.0),
                });
            }
        }
        out
    }

    // --- deliberate held-closure consent gesture (detect_deliberate_closure) ---
    // The detector compares EAR to a per-user ABSOLUTE closed threshold from an
    // enrollment calibration, so unlike the natural-blink gate it needs no open
    // baseline in the window (a hold that fills the window still registers). Test
    // calibration: open 0.24 / closed 0.05 → threshold 0.145.

    fn cal() -> ClosureCalibration {
        ClosureCalibration {
            ear_open: 0.24,
            ear_closed: 0.05,
        }
    }

    #[test]
    fn deliberate_bounded_closure_that_reopens_is_the_consent_gesture() {
        // The real gesture: open, close ~12 frames (0.05 < deep threshold), then
        // REOPEN. Within [min, max] and reopens → accepted.
        let mut ears = vec![0.24; 4];
        ears.extend([0.05; 12]);
        ears.extend([0.24; 4]);
        let seq = flat(&ears);
        assert_eq!(
            detect_deliberate_closure(&seq, &cal()),
            BlinkResult::Blinked
        );
    }

    #[test]
    fn sustained_hold_without_reopen_is_not_the_gesture() {
        // A held squint / eyes-closed: shut the whole window, never reopens and
        // runs past the upper bound. This is the case that broke a pure
        // depth+duration detector; the reopen + upper bound reject it.
        let mut ears = vec![0.24; 4];
        ears.extend([0.03; 34]); // held to the end: no reopen, > max
        let seq = flat(&ears);
        assert_eq!(
            detect_deliberate_closure(&seq, &cal()),
            BlinkResult::NoBlink
        );
    }

    #[test]
    fn brief_natural_blink_is_not_the_consent_gesture() {
        // A spontaneous blink (~2 frames shut) and an open window: a blink but
        // NOT consent. A passively watching person blinks, so this must not
        // approve.
        let seq = flat(&[0.24, 0.24, 0.24, 0.05, 0.06, 0.24, 0.24, 0.24]);
        assert_eq!(detect_blink(&seq), BlinkResult::Blinked);
        assert_eq!(
            detect_deliberate_closure(&seq, &cal()),
            BlinkResult::NoBlink
        );
    }

    #[test]
    fn wandering_squint_is_not_the_consent_gesture() {
        // The real false-positive shape: a blink then a squint wandering above
        // and below the threshold (0.05..0.13), never a sustained deep run. The
        // absolute-threshold run breaks on the frames above 0.145, so it stays
        // short and is rejected (the relative-baseline detector wrongly read it
        // as one long closure).
        let seq = flat(&[
            0.24, 0.05, 0.09, 0.13, 0.12, 0.11, 0.13, 0.10, 0.12, 0.24, 0.24,
        ]);
        assert_eq!(
            detect_deliberate_closure(&seq, &cal()),
            BlinkResult::NoBlink
        );
    }

    #[test]
    fn open_eyes_are_neither_blink_nor_consent() {
        let seq = flat(&[0.24; 12]);
        assert_eq!(detect_blink(&seq), BlinkResult::NoBlink);
        assert_eq!(
            detect_deliberate_closure(&seq, &cal()),
            BlinkResult::NoBlink
        );
        // No face frames at all → NoEyes.
        assert_eq!(detect_deliberate_closure(&[], &cal()), BlinkResult::NoEyes);
    }

    #[test]
    fn calibration_midpoint_and_usability() {
        let c = ClosureCalibration {
            ear_open: 0.24,
            ear_closed: 0.05,
        };
        // closed + 0.30*(open-closed) = 0.05 + 0.30*0.19 = 0.107.
        assert!((c.closed_threshold() - 0.107).abs() < 1e-6);
        assert!(c.is_usable());
        // Too small a gap = untrustworthy calibration.
        assert!(!ClosureCalibration {
            ear_open: 0.10,
            ear_closed: 0.09
        }
        .is_usable());
    }

    #[test]
    fn consent_closure_frame_threshold_is_env_overridable() {
        // A 4-frame closure is below the default but passes with a lowered bar.
        let seq = flat(&[0.24, 0.24, 0.05, 0.05, 0.05, 0.05, 0.24, 0.24]);
        if in_child().is_some() {
            assert_eq!(
                detect_deliberate_closure(&seq, &cal()),
                BlinkResult::Blinked
            );
            return;
        }
        assert_eq!(
            detect_deliberate_closure(&seq, &cal()),
            BlinkResult::NoBlink
        );
        run_in_child(
            "tests::consent_closure_frame_threshold_is_env_overridable",
            "lowered",
            &[("IRLUME_CONSENT_CLOSURE_FRAMES", "3")],
        );
    }

    #[test]
    fn deep_natural_blink_is_detected() {
        // Night-validation shape: open ≈0.24, blink to ≈0.15 (0.63× → deep rule).
        let seq = flat(&[0.24, 0.24, 0.23, 0.15, 0.16, 0.24, 0.24, 0.23, 0.24]);
        assert_eq!(detect_blink(&seq), BlinkResult::Blinked);
    }

    /// Same deep-dip EAR shape, but the face is translating fast every frame (a
    /// moving print/panning camera): the motion gate rejects it as NoBlink even
    /// though the EAR trace alone looks like a blink. Calibrated on the NexiGo:
    /// genuine still-head median speed ~0.008, moving false-accepts ~0.045.
    #[test]
    fn moving_face_dip_is_gated_out() {
        let ears = [0.24, 0.24, 0.23, 0.15, 0.16, 0.24, 0.24, 0.23, 0.24];
        let seq: Vec<EarSample> = ears
            .iter()
            .enumerate()
            .map(|(i, &e)| EarSample {
                idx: i,
                ear: Some(e),
                bri: 60.0,
                // Face marches ~5% of a face-width per frame (median well above
                // the 0.02 gate); fsize 100 so the normalization matches.
                cx: 100.0 + i as f32 * 5.0,
                cy: 100.0,
                fsize: 100.0,
                contrast: e * 500.0,
            })
            .collect();
        // Sanity: the same EAR shape with a still face still passes.
        assert_eq!(detect_blink(&flat(&ears)), BlinkResult::Blinked);
        assert_eq!(detect_blink(&seq), BlinkResult::NoBlink);
    }

    /// Deep-dip EAR shape with FLAT corneal contrast (a diffuse print has no
    /// glint to lose) and motion in the slow band (above the contrast-gate
    /// floor, below the motion gate): the contrast gate rejects it as NoBlink.
    /// Calibrated on the NexiGo: genuine drop 1.41-2.63, a flat print ~1.0.
    #[test]
    fn flat_contrast_dip_is_gated_out() {
        let ears = [0.24, 0.24, 0.23, 0.15, 0.16, 0.24, 0.24, 0.23, 0.24];
        // Move ~1.7% of a face-width per frame: above the 0.015 contrast floor,
        // below the 0.02 motion gate, so the contrast cue (not motion) decides.
        let moving = |contrast: f32| -> Vec<EarSample> {
            ears.iter()
                .enumerate()
                .map(|(i, &e)| EarSample {
                    idx: i,
                    ear: Some(e),
                    bri: 60.0,
                    cx: 100.0 + i as f32 * 1.7,
                    cy: 100.0,
                    fsize: 100.0,
                    contrast,
                })
                .collect()
        };
        // Flat contrast, in the slow band → contrast gate rejects.
        assert_eq!(detect_blink(&moving(60.0)), BlinkResult::NoBlink);
        // A still glasses-like face with the SAME flat ratio is NOT gated
        // (below the motion floor the EAR blink is trusted): accepted.
        let mut still = moving(60.0);
        for s in &mut still {
            s.cx = 100.0;
        }
        assert_eq!(detect_blink(&still), BlinkResult::Blinked);
        // A GENUINE blink in the same slow band (contrast collapses with the
        // EAR: open ~120, dip ~75, ratio ~1.6) survives the contrast gate.
        let genuine: Vec<EarSample> = ears
            .iter()
            .enumerate()
            .map(|(i, &e)| EarSample {
                idx: i,
                ear: Some(e),
                bri: 60.0,
                cx: 100.0 + i as f32 * 1.7, // motion ~0.017, in [0.015, 0.02]
                cy: 100.0,
                fsize: 100.0,
                contrast: e * 500.0, // real glint collapse tracks the EAR
            })
            .collect();
        assert_eq!(detect_blink(&genuine), BlinkResult::Blinked);
    }

    #[test]
    fn shallow_single_frame_v_is_detected() {
        // Real kitchen trace 2026-07-01 (the old depth rule MISSED this): lit-class
        // blink sampled mid-closure, one frame at 0.173 (0.82× the lit median 0.212),
        // sharp drop from 0.212 and recovery to 0.205. Ambient-class frames read
        // systematically lower (~0.185) and must not drag the baseline down.
        let lit = [
            0.209, 0.224, 0.257, 0.240, 0.236, 0.204, 0.208, 0.212, 0.173, 0.205, 0.226, 0.206,
        ];
        let dark: Vec<Option<f32>> = [
            0.192, 0.191, 0.180, 0.184, 0.189, 0.193, 0.194, 0.189, 0.181, 0.175, 0.184, 0.185,
        ]
        .iter()
        .map(|&e| Some(e))
        .collect();
        assert_eq!(detect_blink(&strobed(&lit, &dark)), BlinkResult::Blinked);
    }

    #[test]
    fn dark_room_two_sample_v_is_detected() {
        // Real dark-living-room trace 2026-07-01: ambient frames have NO face (only
        // the emitter lights you), blink = two lit samples 0.129/0.142 (0.73×/0.81×
        // of the 0.176 lit median) with clean pre/post open samples.
        let lit = [
            0.176, 0.185, 0.176, 0.129, 0.142, 0.174, 0.174, 0.188, 0.180, 0.176,
        ];
        let dark = vec![None; 10];
        assert_eq!(detect_blink(&strobed(&lit, &dark)), BlinkResult::Blinked);
    }

    #[test]
    fn static_banner_flat_ear_is_not_a_blink() {
        // Real banner trace: flat 0.21–0.24, min 0.206 (≈0.91× median): too shallow
        // for a run sample, no V, no deep dip.
        let banner = flat(&[
            0.221, 0.236, 0.227, 0.229, 0.206, 0.232, 0.226, 0.224, 0.223,
        ]);
        assert_eq!(detect_blink(&banner), BlinkResult::NoBlink);
    }

    #[test]
    fn slow_drift_is_not_a_blink() {
        // Slow U-drift (gaze shift / AE settling, ~1s down and back): the bottom
        // sample only reaches 0.87× of median; a lone sample must reach the
        // single-frame depth (0.82×) to count, so no blink.
        let seq = flat(&[
            0.240, 0.236, 0.230, 0.224, 0.216, 0.208, 0.200, 0.193, 0.187, 0.193, 0.200, 0.208,
            0.216, 0.224, 0.230, 0.236,
        ]);
        assert_eq!(detect_blink(&seq), BlinkResult::NoBlink);
    }

    #[test]
    fn long_depression_is_not_a_blink() {
        // Real AE-settle trace (dark room 2026-07-01): EAR depressed for ~7
        // consecutive samples while exposure stabilises, longer than any real
        // blink; the run-length cap rejects it even though it is deep.
        let lit = [
            0.190, 0.168, 0.182, 0.159, 0.155, 0.159, 0.154, 0.158, 0.144, 0.137, 0.164, 0.185,
            0.189, 0.201, 0.200, 0.201, 0.203, 0.205, 0.194, 0.195,
        ];
        let dark = vec![None; 20];
        assert_eq!(detect_blink(&strobed(&lit, &dark)), BlinkResult::NoBlink);
    }

    #[test]
    fn tiny_window_is_no_eyes() {
        // Real closet trace 2026-07-01: the stream froze after 5 face frames whose
        // EAR dipped in sync with auto-exposure slewing (bri 182→57); previously
        // scored Live. Too few samples to trust: NoEyes.
        let mut seq: Vec<EarSample> = [
            (0usize, 0.236f32, 182.4f32),
            (2, 0.226, 202.8),
            (4, 0.177, 145.6),
            (6, 0.181, 126.4),
            (8, 0.217, 57.0),
        ]
        .iter()
        .map(|&(idx, e, b)| EarSample {
            idx,
            ear: Some(e),
            bri: b,
            cx: 100.0,
            cy: 100.0,
            fsize: 100.0,
            contrast: e * 500.0,
        })
        .collect();
        for i in 5..30 {
            seq.push(EarSample {
                idx: 2 * i,
                ear: None,
                bri: 144.0,
                cx: 0.0,
                cy: 0.0,
                fsize: 0.0,
                contrast: 0.0,
            });
        }
        assert_eq!(detect_blink(&seq), BlinkResult::NoEyes);
    }

    #[test]
    fn exposure_slew_dip_is_not_a_blink() {
        // EAR sags while auto-exposure is still slewing (brightness falling 200→90):
        // the dip's only near-open neighbours sit at a very different exposure, so
        // the brightness-band check refuses to treat it as a V.
        let seq: Vec<EarSample> = [
            (0usize, 0.230f32, 210.0f32),
            (1, 0.231, 200.0),
            (2, 0.229, 185.0),
            (3, 0.185, 150.0),
            (4, 0.188, 132.0),
            (5, 0.219, 96.0),
            (6, 0.221, 92.0),
            (7, 0.222, 91.0),
            (8, 0.222, 90.0),
            (9, 0.221, 90.0),
            (10, 0.222, 90.0),
            (11, 0.221, 90.0),
        ]
        .iter()
        .map(|&(idx, e, b)| EarSample {
            idx,
            ear: Some(e),
            bri: b,
            cx: 100.0,
            cy: 100.0,
            fsize: 100.0,
            contrast: e * 500.0,
        })
        .collect();
        assert_eq!(detect_blink(&seq), BlinkResult::NoBlink);
    }

    #[test]
    fn no_plausible_open_eye_reads_no_eyes() {
        // Median below the open floor (mesh failing / non-eye) → NoEyes, not a blink.
        assert_eq!(
            detect_blink(&flat(&[0.05, 0.06, 0.04, 0.05, 0.05])),
            BlinkResult::NoEyes
        );
        assert_eq!(detect_blink(&[]), BlinkResult::NoEyes);
        // Dark closet: frames captured but no face anywhere → NoEyes.
        let none = strobed(&[], &[None; 20]);
        assert_eq!(detect_blink(&none), BlinkResult::NoEyes);
    }
}

#[cfg(test)]
mod nod_evidence_tests {
    use super::*;

    /// `signal_crossings` is public, so an empty slice must return 0 rather than
    /// panic on the median index `len / 2`. The internal callers guard, but the
    /// function cannot rely on that once anyone else can call it.
    #[test]
    fn signal_crossings_on_empty_is_zero_not_a_panic() {
        assert_eq!(signal_crossings(&[], 1.0, NOD_CROSSING_AMP_FRAC), 0);
    }

    fn samples(pitches: &[f32]) -> Vec<PoseSample> {
        pitches
            .iter()
            .enumerate()
            .map(|(i, &p)| PoseSample {
                idx: i,
                pitch_frac: Some(p),
                yaw_signed: Some(0.0),
                bri: 100.0,
            })
            .collect()
    }

    fn poses(pitch: &[f32], yaw: &[f32]) -> Vec<PoseSample> {
        assert_eq!(pitch.len(), yaw.len());
        pitch
            .iter()
            .zip(yaw)
            .enumerate()
            .map(|(i, (&p, &y))| PoseSample {
                idx: i,
                pitch_frac: Some(p),
                yaw_signed: Some(y),
                bri: 100.0,
            })
            .collect()
    }

    /// A head-shake with a little vertical bob must NEVER approve. Its yaw range
    /// (~0.5) sits in the [0.45, 0.60] overlap of the shake and nod bands, and
    /// its pitch range (~0.23) exceeds SHAKE_PITCH_MAX, so before the fix the
    /// shake branch rejected it on pitch and it fell through to the nod branch
    /// and returned Nod, which grants sudo/polkit/credential release. Shake-shaped
    /// yaw now resolves to Shake or None, never Nod.
    #[test]
    fn shake_band_with_vertical_motion_never_becomes_an_approving_nod() {
        // yaw swings -0.25..0.25 (range 0.50, inside [SHAKE_YAW_MIN, NOD_YAW_MAX]).
        let yaw = [
            -0.25, -0.15, 0.00, 0.15, 0.25, 0.15, 0.00, -0.15, -0.25, -0.10, 0.10, 0.25,
        ];
        // pitch oscillates with range 0.23 > SHAKE_PITCH_MAX (0.18), which is what
        // used to satisfy the nod branch's pitch and crossings gates.
        let pitch = [
            0.40, 0.43, 0.48, 0.55, 0.62, 0.58, 0.50, 0.43, 0.39, 0.44, 0.52, 0.61,
        ];
        assert_ne!(
            detect_nod(&poses(&pitch, &yaw)),
            HeadGesture::Nod,
            "motion in the shake yaw band must never resolve to an approving nod"
        );
    }

    /// A still-face yaw DRIFT (range in the shake band but no left-right
    /// oscillation) must NOT read as a Shake. Measured 2026-08-11 on the ASUS FHD
    /// IR module: a still face carried yaw_range ~0.5 with ZERO yaw crossings, and
    /// range alone read it as a Shake, which would cancel the consent watch of a
    /// user who did nothing. The oscillation gate (yaw_crossings >=
    /// SHAKE_MIN_CROSSINGS) is what separates it from a deliberate shake (6-7
    /// crossings), and the band stays terminal so it is never a nod either.
    #[test]
    fn a_still_face_yaw_drift_is_not_a_shake() {
        // yaw mostly constant with two outlier frames: range lands in the shake
        // band but produces 0 median crossings (no oscillation). Pitch flat.
        let mut yaw = vec![0.15f32; 18];
        yaw.push(0.65);
        yaw.push(0.65);
        let pitch = vec![0.5f32; yaw.len()];
        let (verdict, ev) = detect_nod_with_evidence(&poses(&pitch, &yaw));
        assert!(
            ev.yaw_range >= SHAKE_YAW_MIN,
            "premise: the yaw range must land in the shake band, got {}",
            ev.yaw_range
        );
        assert_ne!(
            verdict,
            HeadGesture::Shake,
            "a non-oscillating yaw drift is not a deliberate shake"
        );
        assert_ne!(
            verdict,
            HeadGesture::Nod,
            "shake-band yaw stays terminal, never an approving nod"
        );
    }

    #[test]
    fn a_wide_one_sweep_shake_is_a_decline() {
        // Measured at a live polkit dialog 2026-08-11: deliberate declines logged
        // yaw 1.58-2.24 with a SINGLE median crossing and were rejected as "no
        // gesture", so the user had to shake again and again. At this width a still
        // face cannot reach the range (its drift measured 0.42-0.72), so one
        // crossing is enough. One sweep out and back through the median.
        // One sweep: held left, through centre, held right. The centre samples put
        // the median between the extremes, which is what a real sweep looks like.
        let yaw: Vec<f32> = std::iter::repeat_n(-0.9, 8)
            .chain(std::iter::repeat_n(0.0, 4))
            .chain(std::iter::repeat_n(0.9, 8))
            .collect();
        let pitch = vec![0.5f32; yaw.len()];
        let (verdict, ev) = detect_nod_with_evidence(&poses(&pitch, &yaw));
        assert!(
            ev.yaw_range >= SHAKE_WIDE_YAW,
            "premise: this fixture must be a WIDE shake, got {}",
            ev.yaw_range
        );
        assert_eq!(
            signal_crossings(&yaw, ev.yaw_range, NOD_CROSSING_AMP_FRAC),
            1,
            "premise: one sweep is exactly one crossing"
        );
        assert_eq!(
            verdict,
            HeadGesture::Shake,
            "a wide one-sweep shake must read as a decline (yaw {}, one crossing)",
            ev.yaw_range
        );
    }

    #[test]
    fn a_vigorous_shake_above_the_old_ceiling_is_still_a_decline() {
        // The live session's shakes reached yaw 2.81 and 2.99, above the OLD 2.5
        // ceiling, so they fell out of the band entirely and could never register:
        // shaking harder made the decline LESS likely to be seen. Pinned at 2.99,
        // the widest measured, which must stay inside SHAKE_YAW_MAX.
        let yaw: Vec<f32> = std::iter::repeat_n(-1.495, 8)
            .chain(std::iter::repeat_n(0.0, 4))
            .chain(std::iter::repeat_n(1.495, 8))
            .collect();
        let pitch = vec![0.5f32; yaw.len()];
        let (verdict, ev) = detect_nod_with_evidence(&poses(&pitch, &yaw));
        assert!(
            (ev.yaw_range - 2.99).abs() < 0.01,
            "premise: fixture reproduces the measured 2.99 yaw, got {}",
            ev.yaw_range
        );
        assert!(
            ev.yaw_range <= SHAKE_YAW_MAX,
            "the measured shake must sit inside the ceiling, got {} vs {SHAKE_YAW_MAX}",
            ev.yaw_range
        );
        assert_eq!(
            verdict,
            HeadGesture::Shake,
            "a vigorous shake must still decline"
        );
    }

    #[test]
    fn a_look_around_stays_outside_the_shake_band() {
        // The ceiling's job: idle looking-around measured 4.1 yaw in the test
        // corpus, and must NOT cancel a consent watch. Pins that raising the
        // ceiling to 3.5 kept look-around out (the margin is 2.99 shake -> 3.5
        // ceiling -> 4.1 look-around, so this is the assertion that fails first if
        // the ceiling is raised again).
        let yaw: Vec<f32> = (0..20)
            .map(|i| if i % 2 == 0 { -2.05 } else { 2.05 })
            .collect();
        let pitch = vec![0.5f32; yaw.len()];
        let (verdict, ev) = detect_nod_with_evidence(&poses(&pitch, &yaw));
        assert!(
            ev.yaw_range > SHAKE_YAW_MAX,
            "premise: look-around must exceed the ceiling, got {}",
            ev.yaw_range
        );
        assert_ne!(verdict, HeadGesture::Shake, "look-around is not a decline");
        assert_ne!(verdict, HeadGesture::Nod, "look-around is not an approval");
    }

    #[test]
    fn evidence_agrees_with_the_verdict_and_names_the_shortfall() {
        // Too few frames: the verdict is NoFace and the frame count says why.
        let short = samples(&[0.5; 4]);
        let (v, ev) = detect_nod_with_evidence(&short);
        assert_eq!(v, HeadGesture::NoFace);
        assert_eq!(ev.frames, 4);
        assert!(ev.frames < NOD_MIN_FACE_FRAMES);

        // Enough frames but a motionless head: the pitch range is the shortfall,
        // which is the case a user reports as "I nodded and nothing happened".
        let still = samples(&[0.5; 20]);
        let (v, ev) = detect_nod_with_evidence(&still);
        assert_eq!(v, HeadGesture::None);
        assert_eq!(ev.frames, 20);
        assert!(
            ev.pitch_range < NOD_PITCH_MIN,
            "a still head must show a pitch range under the threshold, got {}",
            ev.pitch_range
        );

        // A real down-up-down nod, the same shape `deliberate_nod_is_detected`
        // uses: the verdict is Nod and the evidence clears every bar.
        let nod = [
            0.53, 0.55, 0.60, 0.63, 0.58, 0.52, 0.51, 0.55, 0.62, 0.64, 0.57, 0.52, 0.53, 0.56,
        ];
        let (v, ev) = detect_nod_with_evidence(&samples(&nod));
        assert_eq!(v, HeadGesture::Nod);
        assert!(ev.pitch_range >= ev.pitch_min);
        assert!(ev.yaw_range <= NOD_YAW_MAX);
        assert!(ev.crossings >= NOD_MIN_CROSSINGS);
    }

    /// `mean_step` is the #101 shadow metric: recorded with the verdict,
    /// never part of it. Pin the arithmetic (|Δpitch| / Δidx over usable
    /// pairs at gap 1 or 2) and the two rules that keep it honest: a strobe
    /// pair is normalized to a per-frame rate rather than inflated, and a
    /// longer gap (face lost) contributes nothing. The measured populations
    /// that motivated it (still ≤0.0064, nods ≥0.0149) are provenance in the
    /// field's docs, deliberately NOT asserted here: one session's numbers
    /// are not a contract.
    #[test]
    fn mean_step_is_recorded_per_adjacent_pair_and_skips_gaps() {
        // Known arithmetic: steps 0.02, 0.03, 0.01 → mean 0.02.
        let (_, ev) = detect_nod_with_evidence(&samples(&[0.50, 0.52, 0.55, 0.54]));
        assert!((ev.mean_step - 0.02).abs() < 1e-6, "got {}", ev.mean_step);

        // A None gap breaks adjacency: the 0.50→0.60 jump spans the gap and
        // must NOT count as one frame's motion. Pairs left: none.
        let gappy = vec![
            PoseSample {
                idx: 0,
                pitch_frac: Some(0.50),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
            PoseSample {
                idx: 1,
                pitch_frac: None,
                yaw_signed: None,
                bri: 0.0,
            },
            PoseSample {
                idx: 2,
                pitch_frac: Some(0.60),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
        ];
        // One missing frame is the strobe shape (the ASUS lights alternate
        // frames; a live 75-frame take had all 37 usable pairs at gap 2), so
        // this pair COUNTS, normalized: (0.60-0.50)/2, a per-frame rate. The
        // division is the load-bearing assertion: unnormalized it would read
        // 0.10 and a gap would inflate the metric.
        let (_, ev) = detect_nod_with_evidence(&gappy);
        assert!(
            (ev.mean_step - 0.05).abs() < 1e-6,
            "a strobe pair is one per-frame rate, got {}",
            ev.mean_step
        );

        // Two samples two frames apart with nothing between them read the
        // same as the strobe case above: gap alone cannot say whether a frame
        // was dark or dropped, and normalization makes both readings honest.
        let sparse = vec![
            PoseSample {
                idx: 10,
                pitch_frac: Some(0.50),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
            PoseSample {
                idx: 12,
                pitch_frac: Some(0.60),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
        ];
        let sparse_step = detect_nod_with_evidence(&sparse).1.mean_step;
        assert!(
            (sparse_step - 0.05).abs() < 1e-6,
            "a gap-2 pair must be normalized, never a full step, got {sparse_step}"
        );

        // A LONGER gap is a detection loss and contributes nothing: the
        // face-lost rule the field documentation promises.
        let lost = vec![
            PoseSample {
                idx: 0,
                pitch_frac: Some(0.50),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
            PoseSample {
                idx: 4,
                pitch_frac: Some(0.60),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
        ];
        assert_eq!(
            detect_nod_with_evidence(&lost).1.mean_step,
            0.0,
            "a face-lost gap must not form a step"
        );

        // A strobed series end to end: gaps of 2 throughout, steps 0.02,
        // 0.03, 0.01 across pairs → per-frame mean 0.02 / 2 = 0.01.
        let strobed: Vec<PoseSample> = [0.50f32, 0.52, 0.55, 0.54]
            .iter()
            .enumerate()
            .map(|(i, &p)| PoseSample {
                idx: i * 2,
                pitch_frac: Some(p),
                yaw_signed: Some(0.0),
                bri: 100.0,
            })
            .collect();
        let strobed_step = detect_nod_with_evidence(&strobed).1.mean_step;
        assert!(
            (strobed_step - 0.01).abs() < 1e-6,
            "a strobed take must read as per-frame rates, got {strobed_step}"
        );

        // And the gap arithmetic must not overflow on a hostile idx.
        let wrap = vec![
            PoseSample {
                idx: usize::MAX,
                pitch_frac: Some(0.50),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
            PoseSample {
                idx: 0,
                pitch_frac: Some(0.60),
                yaw_signed: Some(0.0),
                bri: 100.0,
            },
        ];
        assert_eq!(detect_nod_with_evidence(&wrap).1.mean_step, 0.0);

        // Empty and single-frame windows have no pairs: 0.0, not NaN.
        assert_eq!(detect_nod_with_evidence(&[]).1.mean_step, 0.0);
        assert_eq!(detect_nod_with_evidence(&samples(&[0.5])).1.mean_step, 0.0);

        // Directional sanity on the shapes the gate already models: the nod
        // series moves more per frame than the still series. Relative order
        // only; no absolute floor, that is #101's threshold call to make.
        let nod = [
            0.53, 0.55, 0.60, 0.63, 0.58, 0.52, 0.51, 0.55, 0.62, 0.64, 0.57, 0.52, 0.53, 0.56,
        ];
        let nod_step = detect_nod_with_evidence(&samples(&nod)).1.mean_step;
        let still_step = detect_nod_with_evidence(&samples(&[0.5; 20])).1.mean_step;
        assert!(nod_step > still_step);
    }

    /// The whole value of the evidence is that it describes the gate that
    /// actually ran. `detect_nod` delegating here is what guarantees that, so
    /// walk a spread of inputs and require the two to agree on every one; a
    /// reintroduced second copy of the rules would show up as a mismatch.
    #[test]
    fn detect_nod_reports_exactly_what_the_evidence_judged() {
        let nod = [
            0.53, 0.55, 0.60, 0.63, 0.58, 0.52, 0.51, 0.55, 0.62, 0.64, 0.57, 0.52, 0.53, 0.56,
        ];
        let cases: Vec<Vec<PoseSample>> = vec![
            Vec::new(),
            samples(&[]),
            samples(&[0.5; 4]),
            samples(&[0.5; 20]),
            samples(&[
                0.50, 0.51, 0.50, 0.51, 0.50, 0.51, 0.50, 0.51, 0.50, 0.51, 0.50, 0.51,
            ]),
            samples(&nod),
        ];
        for case in cases {
            let (verdict, _) = detect_nod_with_evidence(&case);
            assert_eq!(
                detect_nod(&case),
                verdict,
                "detect_nod disagreed with the evidence on a {}-frame window",
                case.len()
            );
        }
    }

    /// An empty window must not panic or invent a reading. The peak-to-peak
    /// helper starts from infinities, so a naive `hi - lo` yields NaN here and
    /// every later comparison silently goes false.
    #[test]
    fn an_empty_window_reports_zeroes_rather_than_nan() {
        let (v, ev) = detect_nod_with_evidence(&[]);
        assert_eq!(v, HeadGesture::NoFace);
        assert_eq!(ev.frames, 0);
        assert_eq!(ev.crossings, 0);
        assert!(ev.pitch_range.is_finite() && ev.pitch_range == 0.0);
        assert!(ev.yaw_range.is_finite() && ev.yaw_range == 0.0);
    }

    /// The threshold must keep separating the two populations MEASURED on
    /// hardware 2026-07-27, or the false-accept this was raised to close comes
    /// back. Pinned as data, not as a restatement of the constant: if someone
    /// lowers `NOD_PITCH_MIN` toward the rejected side, this fails and says why.
    #[test]
    fn the_pitch_threshold_still_separates_the_measured_populations() {
        // Deliberate continuous nods, 10 accepted watches.
        const REAL_NODS: &[f32] = &[
            0.082, 0.085, 0.088, 0.089, 0.094, 0.095, 0.096, 0.099, 0.107, 0.108,
        ];
        // Sitting still and holding a printed face, 18 rejected watches.
        const NOT_GESTURES: &[f32] = &[
            0.021, 0.022, 0.023, 0.023, 0.024, 0.024, 0.030, 0.033, 0.035, 0.038, 0.038, 0.042,
            0.044, 0.052, 0.055, 0.055, 0.059, 0.069,
        ];
        let thr = NOD_PITCH_MIN;
        for v in REAL_NODS {
            assert!(
                *v >= thr,
                "a measured real nod at {v} would now be refused by NOD_PITCH_MIN {thr}"
            );
        }
        for v in NOT_GESTURES {
            assert!(
                *v < thr,
                "a measured still/print take at {v} would now be ACCEPTED by NOD_PITCH_MIN {thr}"
            );
        }
        // And it sits inside the gap rather than on either edge, so neither side
        // is one noisy capture away from crossing it.
        let worst_real = REAL_NODS.iter().copied().fold(f32::INFINITY, f32::min);
        let worst_fake = NOT_GESTURES.iter().copied().fold(0.0f32, f32::max);
        assert!(
            thr - worst_fake >= 0.004 && worst_real - thr >= 0.004,
            "threshold {thr} is not centred in the gap {worst_fake}..{worst_real}"
        );
    }

    /// The reported threshold is the one the gate applied, not the constant.
    /// Without this the line reads plausibly while naming a limit no run used.
    #[test]
    fn the_evidence_carries_the_threshold_that_was_applied() {
        let (_, ev) = detect_nod_with_evidence(&samples(&[0.5; 20]));
        // No override is set in this process, so the effective value is the
        // constant; `pitch_min` is read from the same source the gate reads.
        assert_eq!(ev.pitch_min, NOD_PITCH_MIN);
        assert!(ev.pitch_min > 0.0 && ev.pitch_min.is_finite());
    }

    /// The evidence must always JUSTIFY the verdict. This is the property the
    /// whole feature rests on: a denial is reported to the user through these
    /// numbers, so a line that clears every bar while the gate said no would
    /// send the reader hunting for a fault that is not there.
    ///
    /// Randomised because the interesting failures live at combinations no
    /// hand-written case thinks to try, and the generator is checked for
    /// coverage at the end: an earlier version of this test produced ZERO Nod
    /// verdicts in 20,000 windows and passed a deliberately broken gate.
    #[test]
    fn the_evidence_always_justifies_the_verdict() {
        let mut seed: u64 = 0x2026_0727;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((seed >> 33) as f64 / (u32::MAX as f64 / 2.0)) as f32
        };
        let mut checked = 0usize;
        let mut counts = (0usize, 0usize, 0usize);
        for case in 0..20_000 {
            let n = (case % 40) as usize;
            // Yaw must usually stay INSIDE NOD_YAW_MAX, or every window dies at
            // the shake gate and the crossings branch is never reached.
            let yaw_scale = if case % 5 == 0 { 1.4 } else { 0.12 };
            // Amplitude straddles NOD_PITCH_MIN so both sides of that gate occur.
            let amp = match case % 4 {
                0 => 0.0,
                1 => 0.02,
                2 => 0.09,
                _ => 0.30,
            };
            let mut v = Vec::with_capacity(n);
            for i in 0..n {
                // Flat, slow drift, and oscillation at several periods: the
                // last is what actually produces crossings.
                let base = match case % 3 {
                    0 => 0.5 + amp * ((i % 4) as f32 - 1.5) / 1.5,
                    1 => 0.4 + amp * i as f32 / n.max(1) as f32,
                    _ => 0.5 + amp * ((i % 6) as f32 - 2.5) / 2.5,
                };
                v.push(PoseSample {
                    idx: i,
                    pitch_frac: if next() > 0.05 { Some(base) } else { None },
                    yaw_signed: if next() > 0.05 {
                        Some((next() - 0.5) * yaw_scale)
                    } else {
                        None
                    },
                    bri: 100.0,
                });
            }
            let (got, ev) = detect_nod_with_evidence(&v);
            assert_eq!(detect_nod(&v), got, "detect_nod disagreed on case {case}");
            match got {
                HeadGesture::NoFace => assert!(
                    ev.frames < NOD_MIN_FACE_FRAMES,
                    "case {case}: NoFace with {} usable frames",
                    ev.frames
                ),
                HeadGesture::Nod => assert!(
                    ev.frames >= NOD_MIN_FACE_FRAMES
                        && ev.pitch_range >= ev.pitch_min
                        && ev.yaw_range <= NOD_YAW_MAX
                        && ev.crossings >= NOD_MIN_CROSSINGS,
                    "case {case}: granted on evidence that fails a gate: {ev:?}"
                ),
                _ => assert!(
                    ev.frames >= NOD_MIN_FACE_FRAMES
                        && (ev.pitch_range < ev.pitch_min
                            || ev.yaw_range > NOD_YAW_MAX
                            || ev.crossings < NOD_MIN_CROSSINGS),
                    "case {case}: denied but every number clears its bar: {ev:?}"
                ),
            }
            match got {
                HeadGesture::NoFace => counts.0 += 1,
                HeadGesture::Nod => counts.2 += 1,
                _ => counts.1 += 1,
            }
            checked += 1;
        }
        assert_eq!(checked, 20_000);
        // A window that never reaches a verdict proves nothing about it. This
        // test passed a deliberately broken refactor until the generator was
        // fixed, because it produced zero Nod verdicts in 20,000 cases.
        assert!(
            counts.0 > 500 && counts.1 > 500 && counts.2 > 500,
            "coverage too thin to be evidence: NoFace={} None={} Nod={}",
            counts.0,
            counts.1,
            counts.2
        );
    }
}
