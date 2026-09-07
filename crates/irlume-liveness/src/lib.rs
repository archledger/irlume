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
    /// Fraction (0-1) of the whole IR frame saturated in both the selected lit
    /// frame and its adjacent explicit dark frame. `None` means the diagnostic
    /// evidence was unavailable. This can reword an existing denial but cannot
    /// grant or deny by itself.
    pub ir_persistent_saturated_frac: Option<f32>,
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
            ir_persistent_saturated_frac: None,
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
/// Retained threshold overrides may be read more than once per process, so
/// printing per call would repeat the same line for as long as the bad value
/// stays in the unit file. One line per variable is what makes it findable in
/// the journal.
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

/// Persistent whole-frame saturation above this fraction can explain an
/// already-dark or already-flat IR reading. This is a reason selector, not a
/// grant or denial threshold.
pub const IR_PERSISTENT_SATURATED_FRAC_MIN: f32 = 0.10;

impl Signals {
    /// Whether persistent external IR saturation explains an existing dark or
    /// flat denial.
    pub fn persistent_ir_source_overwhelms(&self) -> bool {
        self.ir_persistent_saturated_frac
            .is_some_and(|fraction| fraction > IR_PERSISTENT_SATURATED_FRAC_MIN)
            && (self.ir_face_brightness < IR_FACE_MIN_BRIGHTNESS
                || self.ir_center_edge_ratio < MIN_CENTER_EDGE_RATIO)
    }
}

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

/// The actionable rejection for a dark or flat reading explained by a
/// persistent external IR source.
fn persistent_ir_source_reason() -> String {
    "a persistent IR-bright source overwhelms the camera; reposition away from it or use your password"
        .into()
}

/// The actionable rejection for ambient-flooded IR scenes.
fn flood_reason(ambient: f32) -> String {
    format!(
        "too much IR light behind you (ambient {ambient:.0}: open sky, sun, or bright \
         lamps wash out the emitter); turn away from the light or use your password"
    )
}

/// Whether the corneal glint says the eyes are off the lens while the head
/// stayed inside the permissive frontal gate. The glint stays a REASON
/// SELECTOR only, never decisive (#616 step 1): it reframes a just-flat
/// center/edge reading as the angle artifact it is, the same way ambient
/// flood reframes it. An unreadable glint is no evidence of anything.
fn eyes_off_lens(glint: Option<f32>) -> bool {
    glint.is_some_and(|g| g < GLINT_MIN)
}

/// The actionable rejection for a face whose flat reading is explained by
/// averted eyes rather than by a two-dimensional source.
fn off_axis_reason(ratio: f32, glint: Option<f32>) -> String {
    let glint = glint.unwrap_or_default();
    format!(
        "IR reads flat (center/edge {ratio:.2}) with the eyes off the lens \
         (glint {glint:.0} against the {GLINT_MIN:.0} an on-lens eye returns); \
         look straight at the camera or use your password"
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
            let reason = if s.persistent_ir_source_overwhelms() {
                persistent_ir_source_reason()
            } else if s.ir_ambient >= IR_AMBIENT_FLOOD {
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
            let reason = if s.persistent_ir_source_overwhelms() {
                persistent_ir_source_reason()
            } else if s.ir_ambient >= IR_AMBIENT_FLOOD {
                flood_reason(s.ir_ambient)
            } else if eyes_off_lens(s.ir_eye_glint) {
                off_axis_reason(s.ir_center_edge_ratio, s.ir_eye_glint)
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
            let reason = if s.persistent_ir_source_overwhelms() {
                persistent_ir_source_reason()
            } else if s.ir_ambient >= IR_AMBIENT_FLOOD {
                flood_reason(s.ir_ambient)
            } else {
                format!("IR face too dark ({:.0})", s.ir_face_brightness)
            };
            return (Verdict::Spoof, cues, reason);
        }
        cues.center_edge_ratio_ok = s.ir_center_edge_ratio >= MIN_CENTER_EDGE_RATIO;
        if !cues.center_edge_ratio_ok {
            let reason = if s.persistent_ir_source_overwhelms() {
                persistent_ir_source_reason()
            } else if s.ir_ambient >= IR_AMBIENT_FLOOD {
                flood_reason(s.ir_ambient)
            } else if eyes_off_lens(s.ir_eye_glint) {
                off_axis_reason(s.ir_center_edge_ratio, s.ir_eye_glint)
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

/// Convert one already-computed gate result into the bounded, trace-only
/// measurements owned by this crate. This never includes a reason string or
/// biometric payload; callers emit the returned value only to a privileged
/// diagnostic sink.
#[must_use]
pub fn diagnostic_trace_decision(
    verdict: Verdict,
    signals: &Signals,
) -> irlume_common::diagnostics::TraceEventKind {
    use irlume_common::diagnostics::{TraceEventKind, TraceMeasurement, TraceMetric, TraceVerdict};

    let mut measurements = Vec::with_capacity(11);
    let mut add = |metric, value: f32, threshold: Option<f32>| {
        if let Ok(measurement) =
            TraceMeasurement::new(metric, f64::from(value), threshold.map(f64::from))
        {
            measurements.push(measurement);
        }
    };
    add(
        TraceMetric::RgbBrightness,
        signals.rgb_face_brightness,
        Some(RGB_FACE_MIN_BRIGHTNESS),
    );
    add(
        TraceMetric::IrBrightness,
        signals.ir_face_brightness,
        Some(IR_FACE_MIN_BRIGHTNESS),
    );
    add(
        TraceMetric::IrCenterEdgeRatio,
        signals.ir_center_edge_ratio,
        Some(MIN_CENTER_EDGE_RATIO),
    );
    if let Some(glint) = signals.ir_eye_glint {
        add(TraceMetric::IrEyeGlint, glint, Some(GLINT_MIN));
    }
    add(
        TraceMetric::IrAmbientShare,
        signals.ir_ambient,
        Some(IR_AMBIENT_FLOOD),
    );
    add(
        TraceMetric::HeadYawAsymmetry,
        signals.head_yaw_asym,
        Some(YAW_ASYM_MAX),
    );
    add(
        TraceMetric::HeadPitchFraction,
        signals.head_pitch_frac,
        None,
    );
    add(TraceMetric::FaceFraction, signals.face_frac, None);
    if let Some(saturated) = signals.ir_saturated_frac {
        add(
            TraceMetric::IrSaturatedFraction,
            saturated,
            Some(IR_SATURATED_FRAC_MAX),
        );
    }
    add(
        TraceMetric::RgbSpecularFraction,
        signals.rgb_specular_frac,
        Some(RGB_SPECULAR_MAX),
    );
    add(
        TraceMetric::RgbMoireScore,
        signals.rgb_moire_score,
        Some(rgb_moire_max()),
    );

    TraceEventKind::Decision {
        verdict: match verdict {
            Verdict::Live => TraceVerdict::Live,
            Verdict::Spoof => TraceVerdict::Spoof,
            Verdict::Uncertain => TraceVerdict::Uncertain,
        },
        measurements,
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

    /// Every setting, with the variable's name, four shapes it must refuse, a
    /// value it must take, and the effective value each yields.
    ///
    /// The refused shapes are per setting rather than one shared list because
    /// each accessor owns its parsing and range rule.
    struct Setting {
        name: &'static str,
        refused: [&'static str; 4],
        usable: (&'static str, &'static str),
        fallback: String,
    }

    fn settings() -> Vec<Setting> {
        vec![Setting {
            name: "IRLUME_RGB_MOIRE_MAX",
            refused: ["nan", "-1", "0", "moire"],
            usable: (" 15.0 ", "15"),
            fallback: RGB_MOIRE_MAX.to_string(),
        }]
    }

    /// The effective value of one setting, through the accessor the detectors
    /// call. Read in a child process, where the environment is fixed.
    fn effective(name: &str) -> String {
        match name {
            "IRLUME_RGB_MOIRE_MAX" => rgb_moire_max().to_string(),
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
    /// to ITS default. One child per row, with both variables set, since
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
            ir_persistent_saturated_frac: None,
            ..Default::default() // frontal pose
        }
    }

    #[test]
    fn persistent_ir_source_rewords_existing_denials_on_both_paths() {
        let gate = LivenessGate::new();
        for cue in ["dark", "flat"] {
            let mut s = live_signals();
            s.ir_persistent_saturated_frac = Some(0.1702); // ThinkPad field evidence
            match cue {
                "dark" => s.ir_face_brightness = 20.0,
                "flat" => s.ir_center_edge_ratio = 1.0,
                _ => unreachable!(),
            }

            for (path, (verdict, _, reason)) in [
                ("cross-spectrum", gate.evaluate(&s)),
                ("ir-only", gate.evaluate_ir_only(&s)),
            ] {
                assert_eq!(verdict, Verdict::Spoof, "{path}/{cue}: {reason}");
                assert!(
                    reason.contains("IR-bright source"),
                    "{path}/{cue}: {reason}"
                );
                assert!(reason.contains("reposition"), "{path}/{cue}: {reason}");
                assert!(reason.contains("password"), "{path}/{cue}: {reason}");
                assert!(!reason.contains("ir-setup"), "{path}/{cue}: {reason}");
            }
        }
    }

    #[test]
    fn persistent_ir_source_boundary_rewords_only_above_ten_percent() {
        let gate = LivenessGate::new();
        for (fraction, reworded) in [
            (None, false),
            (Some(0.0031), false), // BRIO field evidence
            (Some(0.10), false),
            (Some(0.1001), true),
        ] {
            for cue in ["dark", "flat"] {
                let mut s = live_signals();
                s.ir_persistent_saturated_frac = fraction;
                match cue {
                    "dark" => s.ir_face_brightness = 20.0,
                    "flat" => s.ir_center_edge_ratio = 1.0,
                    _ => unreachable!(),
                }

                for (path, (verdict, _, reason), old_reason) in [
                    (
                        "cross-spectrum",
                        gate.evaluate(&s),
                        match cue {
                            "dark" => "IR face too dark (20); not reflecting IR like skin",
                            "flat" => "IR too flat (center/edge 1.00); looks 2D, not a 3D face",
                            _ => unreachable!(),
                        },
                    ),
                    (
                        "ir-only",
                        gate.evaluate_ir_only(&s),
                        match cue {
                            "dark" => "IR face too dark (20)",
                            "flat" => "IR too flat (center/edge 1.00)",
                            _ => unreachable!(),
                        },
                    ),
                ] {
                    assert_eq!(verdict, Verdict::Spoof, "{path}/{cue}: {reason}");
                    if reworded {
                        assert_ne!(reason, old_reason, "{path}/{cue} at {fraction:?}");
                        assert!(
                            reason.contains("IR-bright source"),
                            "{path}/{cue} at {fraction:?}: {reason}"
                        );
                    } else {
                        assert_eq!(reason, old_reason, "{path}/{cue} at {fraction:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn persistent_ir_source_evidence_alone_changes_no_verdict() {
        let gate = LivenessGate::new();
        let mut s = live_signals();
        s.ir_persistent_saturated_frac = Some(0.1702);

        assert!(!s.persistent_ir_source_overwhelms());
        for (path, (verdict, _, reason)) in [
            ("cross-spectrum", gate.evaluate(&s)),
            ("ir-only", gate.evaluate_ir_only(&s)),
        ] {
            assert_eq!(verdict, Verdict::Live, "{path}: {reason}");
        }
    }

    /// #616 step 1, the case observed on real hardware in the omarchy thread:
    /// a head inside the permissive frontal gate but eyes off the lens reads
    /// just under the center/edge bar and was called "looks 2D". The glint is
    /// the eyes-on-lens instrument, so a readable glint below the corneal
    /// threshold reframes the flat reading as an angle artifact: the verdict
    /// stays Spoof (fail closed) and the reason names the fixable condition,
    /// exactly the ambient-flood precedent.
    #[test]
    fn flat_with_eyes_off_the_lens_names_looking_not_spoof_shape() {
        let mut s = live_signals();
        s.ir_center_edge_ratio = 1.0; // just under the 1.03 bar
        s.ir_eye_glint = Some(72.0); // readable, eyes off the lens
        let (verdict, _, why) = LivenessGate.evaluate(&s);
        assert_eq!(verdict, Verdict::Spoof, "still denied, fail closed: {why}");
        assert!(
            why.contains("look straight at the camera"),
            "the reason names the fixable condition: {why}"
        );
        assert!(!why.contains("looks 2D"), "not a spoof accusation: {why}");
        // The dark path keeps the same split: both evaluators rule.
        let (verdict, _, why) = LivenessGate.evaluate_ir_only(&s);
        assert_eq!(verdict, Verdict::Spoof, "dark path still denied: {why}");
        assert!(
            why.contains("look straight at the camera"),
            "dark path names the condition too: {why}"
        );
    }

    /// Eyes ON the lens and flat means flat: the spoof wording stands, and so
    /// does an unreadable glint, which is no evidence of anything.
    #[test]
    fn flat_with_eyes_on_or_unreadable_lens_keeps_the_spoof_wording() {
        for glint in [Some(251.0), None] {
            let mut s = live_signals();
            s.ir_center_edge_ratio = 1.0;
            s.ir_eye_glint = glint;
            let (verdict, _, why) = LivenessGate.evaluate(&s);
            assert_eq!(verdict, Verdict::Spoof, "{why}");
            assert!(why.contains("looks 2D"), "no reattribution: {why}");
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
}

#[cfg(test)]
mod trace_tests {
    use super::*;
    #[test]
    fn diagnostic_trace_uses_the_gate_owned_values_and_thresholds() {
        use irlume_common::diagnostics::{TraceEventKind, TraceMetric, TraceVerdict};

        let signals = Signals {
            rgb_face_brightness: 91.0,
            ir_face_brightness: 77.0,
            ir_center_edge_ratio: 1.42,
            ir_eye_glint: Some(203.0),
            ir_ambient: 12.0,
            head_yaw_asym: 0.08,
            head_pitch_frac: 0.52,
            face_frac: 0.31,
            ir_saturated_frac: Some(0.02),
            rgb_specular_frac: 0.03,
            rgb_moire_score: 11.0,
            ..Signals::default()
        };
        let TraceEventKind::Decision {
            verdict,
            measurements,
        } = diagnostic_trace_decision(Verdict::Live, &signals)
        else {
            panic!("liveness tracing must produce a typed decision")
        };
        assert_eq!(verdict, TraceVerdict::Live);
        let ir_brightness = measurements
            .iter()
            .find(|measurement| measurement.metric == TraceMetric::IrBrightness)
            .unwrap();
        assert_eq!(ir_brightness.value, 77.0);
        assert_eq!(
            ir_brightness.threshold,
            Some(f64::from(IR_FACE_MIN_BRIGHTNESS))
        );
        assert!(measurements
            .iter()
            .any(|measurement| measurement.metric == TraceMetric::IrSaturatedFraction));

        assert!(measurements.len() <= 11);
    }
}
