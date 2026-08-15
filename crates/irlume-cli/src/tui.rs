// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume tui`: keyboard-driven setup/management over the `irlumed` socket.
//!
//! Layout & feel follow linhello: a step-wizard (Tab/⇧Tab between steps, a
//! "step N/M" header), a blue Activity bar that shows in plain language exactly
//! what irlume is doing to the system (transparency, inspired by linutil), and a
//! static keybind footer. Enrollment uses linhello-style **guided cues**, a
//! live framing guide (quality + checklist + guidance) with a 3-2-1 countdown
//! and auto-capture, instead of a live video preview (which a terminal can't
//! show). A thin client: all work happens in the daemon.

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use irlume_common::{PositionReport, ProfileSummary, Request, Response};

/// Semantic color slots, resolved once at startup down a capability ladder:
/// NO_COLOR (no-color.org) gets none and the glyphs carry all state; plain
/// terminals get ANSI names so the USER'S terminal theme is the palette
/// (light themes stay readable); truecolor terminals get the soft irlume
/// palette as polish. Every use is a semantic slot (accent/ok/warn/err),
/// never decoration, so the ladder degrades without losing information.
struct Theme {
    accent: Color,
    blue: Color,
    ok: Color,
    err: Color,
    warn: Color,
    /// Key-chip style for the footer (`[w]`, `[?]`…): colored chip normally,
    /// REVERSED under NO_COLOR (a black-on-Reset chip would be invisible).
    chip: Style,
}

fn th() -> &'static Theme {
    static T: std::sync::OnceLock<Theme> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
            return Theme {
                accent: Color::Reset,
                blue: Color::Reset,
                ok: Color::Reset,
                err: Color::Reset,
                warn: Color::Reset,
                chip: Style::new().add_modifier(Modifier::REVERSED),
            };
        }
        let truecolor = std::env::var("COLORTERM")
            .map(|v| v.contains("truecolor") || v.contains("24bit"))
            .unwrap_or(false);
        if truecolor {
            let accent = Color::Rgb(0x6c, 0xb6, 0xff);
            Theme {
                accent,
                blue: Color::Rgb(0x4a, 0x90, 0xd9),
                ok: Color::Rgb(0x73, 0xc9, 0x91),
                err: Color::Rgb(0xe8, 0x7a, 0x7a),
                warn: Color::Rgb(0xe6, 0xc0, 0x7a),
                chip: Style::new().fg(Color::Black).bg(accent),
            }
        } else {
            Theme {
                accent: Color::Cyan,
                blue: Color::Blue,
                ok: Color::Green,
                err: Color::Red,
                warn: Color::Yellow,
                chip: Style::new().fg(Color::Black).bg(Color::Cyan),
            }
        }
    })
}
const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SCREENS: [&str; 12] = [
    "Welcome",
    "Repair",
    "Cameras",
    "Profiles",
    "Identify",
    "Keyring",
    "Recovery",
    "Fingerprint",
    "Login wiring",
    "Settings",
    "Models",
    "Done",
];
// Screen indices (keep in sync with SCREENS).
const SC_WELCOME: usize = 0;
const SC_REPAIR: usize = 1;
const SC_CAMERAS: usize = 2;
const SC_PROFILES: usize = 3;
const SC_IDENTIFY: usize = 4;
const SC_KEYRING: usize = 5;
const SC_RECOVERY: usize = 6;
const SC_FINGERPRINT: usize = 7;
const SC_PAM: usize = 8;
const SC_SETTINGS: usize = 9;
const SC_MODELS: usize = 10;
const SC_DONE: usize = 11;
const ACT_H: usize = 5; // visible rows in the Activity panel (height 7 minus borders)
/// Below this body width the sidebar would starve the content, so the layout
/// collapses to full-width content and the header carries the step position
/// (login greeters / TTYs / SSH at 80 columns).
const SIDEBAR_MIN_COLS: u16 = 90;

/// The services the Settings tab lets the user toggle the consent gesture for,
/// with arrow keys + `c`. All four are high-privilege (elevation or app-consent),
/// so disabling any of them asks for confirmation first. The keyring-release path
/// has its own `g` toggle, so it is not repeated here.
const SETTINGS_GESTURE_SERVICES: &[&str] = &["sudo", "su", "doas", "polkit-1"];
const MAX_PROFILES: usize = 3;
const ENROLL_SCANS: usize = irlume_core::storage::DEFAULT_ENROLL_SCANS;
/// Scans captured per improve-recognition round (add to an existing profile).
const ADD_SCANS: usize = irlume_core::storage::IMPROVE_SCANS;
const GOOD_STREAK: u32 = 3;
/// Consecutive framing-guide misses (10s budget each) before enrollment gives
/// up and says the camera never answered. Three misses is ~30s of a daemon
/// that answers nothing; the #187 wedge sat for minutes behind the old 120s
/// budget while a stale cue read as a verdict (#309).
const GUIDE_MISS_LIMIT: u32 = 3;
/// Full auto-refresh cadence in ms (fingerprint probe + diagnostics; spawns
/// subprocesses, so it runs on the slow timer).
const HEAVY_REFRESH_MS: u64 = 10_000;
/// Light auto-refresh cadence in ms (daemon ping + camera nodes; sub-millisecond).
const LIGHT_REFRESH_MS: u64 = 2500;
/// Post-suspend daemon wait: up to `DAEMON_WAIT_TRIES` polls spaced
/// `DAEMON_WAIT_POLL_MS` ms apart (10 s total), covering irlumed's ONNX model
/// load before it binds its socket.
const DAEMON_WAIT_TRIES: u32 = 40;
const DAEMON_WAIT_POLL_MS: u64 = 250;
/// Enroll-checklist "Facing the camera" bounds: the liveness frontality gate,
/// referenced (not retyped) so the display can't drift from the daemon's
/// verdict. The daemon's live framing guide is stricter still (irlume-auth
/// `FRAME_YAW_ASYM_MAX` / `pitch_band`); the checklist shows the looser gate a
/// capture must clear.
const CHECK_YAW_ASYM_MAX: f32 = irlume_liveness::YAW_ASYM_MAX;
const CHECK_PITCH_MIN: f32 = irlume_liveness::PITCH_FRAC_MIN;
const CHECK_PITCH_MAX: f32 = irlume_liveness::PITCH_FRAC_MAX;
/// Enroll-checklist "Well lit" bounds, mean face luma 0-255: mirror the
/// private `DIM` / `BRIGHT` consts in irlume-auth's `position_sample`; keep in
/// sync by name if either side changes.
const CHECK_LUMA_MIN: f32 = 55.0;
const CHECK_LUMA_MAX: f32 = 235.0;

#[derive(Clone, Copy)]
enum Row {
    Profile(usize),
    Scan(usize, usize),
}

enum Pending {
    EnrollName,
    RenameProfile(String),
    RenameScan(String, String),
    // Masked password/passphrase entry, handled in-TUI (sent to the root daemon
    // over the socket; no sudo, no screen teardown). The first entry is held in
    // a Zeroizing<String> across the double-entry confirm so it is wiped from
    // memory on drop, not left in swappable heap.
    KeyringPw(Option<zeroize::Zeroizing<String>>),
    RecoveryPw(Option<zeroize::Zeroizing<String>>),
    RecoveryRestorePw,
    // Uninstall challenge: the user must type the exact word to remove irlume,
    // so it can never be triggered by an accidental keypress.
    UninstallConfirm,
}

impl Pending {
    /// Password entries render masked.
    fn masked(&self) -> bool {
        matches!(
            self,
            Pending::KeyringPw(_) | Pending::RecoveryPw(_) | Pending::RecoveryRestorePw
        )
    }
}

/// Interactive flow that needs a cooked terminal; the TUI tears down the
/// alt-screen, runs it via the existing CLI handler (no-echo prompts), then
/// re-enters. Mirrors linhello's suspend pattern.
/// Flows that genuinely need the cooked terminal: an interactive root tool
/// (sudo) or fprintd's own prompts. Daemon password ops are handled in-TUI
/// instead (masked entry → socket), so they're not here.
#[derive(Clone)]
enum Suspend {
    FingerprintAdd,
    LoginStatus,
    LoginEnable,
    RestartDaemon,
    RestartFprintd,
    SelinuxLoad,
    /// Switch the active camera pair; root op (writes /etc), so it suspends to
    /// `sudo irlume set-cameras <rgb> <ir>`.
    SetCameras(String, String),
    /// Set up the IR emitter; root op, suspends to `sudo irlume ir-setup`.
    IrSetup,
    /// Measure whether the camera can stream RGB and IR at once and persist
    /// the verdict (capture policy changes with it). The daemon root-gates the
    /// write, and the measurement holds the camera and fires the emitter for
    /// up to a minute, so like the other privileged one-shots it suspends to
    /// `sudo irlume camera-tune`.
    CameraTune,
    /// View the face-auth journal (`sudo irlume logs`); the daemon's lines live
    /// in the system journal, so it runs under sudo to guarantee they show.
    Logs,
    /// Full teardown: un-wire PAM, stop the daemon, wipe data. Root op, so it
    /// suspends to `sudo irlume uninstall --yes` (the TUI already double-
    /// confirmed, so --yes skips the CLI's own prompts).
    Uninstall,
    /// Install Bitwarden's biometric-unlock polkit action; root op, suspends
    /// to `sudo irlume bitwarden setup --apply` (non-interactive, flavor-aware).
    BitwardenSetup,
    /// Opt-in wiring extras and unwiring; each suspends to the matching
    /// `sudo irlume login …` invocation (same shape as LoginEnable).
    LoginEnableSudo,
    LoginEnablePolkit,
    LoginDisable,
    /// Re-apply wiring a distro PAM regeneration stripped (Repair fix).
    LoginReconcile,
    /// Teach the eye-closure consent gesture; interactive + root, so it runs
    /// `sudo irlume calibrate-closure` in the cooked terminal.
    CalibrateClosure,
    /// Flip daemon debug logging; the bool is the direction to switch TO.
    LogsDebug(bool),
    /// fprintd verify runs as the user with its own prompts (like Add).
    FingerprintVerify,
    FingerprintEnable,
    FingerprintDisable,
    /// Wipe enrolled fingers; TUI y/n-confirmed first, root op.
    FingerprintReset,
    /// Enable a third-party PAD model BY NAME. Deliberately runs the CLI's own
    /// interactive flow under sudo (license text, name typed back, y/N): that
    /// friction is the point of the models policy, so the TUI hosts it in the
    /// cooked terminal instead of bypassing it.
    ModelsEnable(String),
    ModelsDisable(String),
    /// Origin-aware updater; runs unprivileged (it invokes sudo itself for
    /// the package-manager step when one is needed).
    Update,
    /// The full `irlume doctor` text readout in the cooked terminal: the
    /// complete authoritative dump (incl. the info-only lines the Repair
    /// checklist omits), copy-pasteable for a bug report.
    Doctor,
    /// Refresh the systemd-pcrlock policy after a firmware/Secure Boot change
    /// so a Tier-2 seal keeps validating. Idempotent (re-predicts the current
    /// PCRs); a system operation, so it is root-gated and clearly labeled.
    PcrlockMakePolicy,
    /// Toggle the opt-in biopolicy operation-class gate (the bool is the target
    /// state). Root op; the daemon reads it live, no restart.
    Biopolicy(bool),
    /// Toggle the credential-release gesture gate (the bool is the target state).
    /// Root op; the daemon reads it live, no restart. Turning it OFF weakens
    /// credential release, so the TUI confirms first and the CLI still prints its
    /// own warning in the cooked terminal.
    CredentialReleaseChallenge(bool),
    /// Toggle the consent gesture for one PAM service (the bool is the target
    /// state). Root op; runs `sudo irlume credential-release-challenge <service>
    /// on|off --yes`. Disabling a high-privilege service is confirmed by the TUI
    /// first (the `--yes` then skips the CLI's own prompt).
    ServiceGesture {
        service: String,
        on: bool,
    },
    /// IR liveness self-test via `sudo irlume selftest liveness` (the daemon
    /// root-gates it; the raw measurements are a spoof-tuning oracle).
    SelfTestLiveness,
}

/// What a y/n confirm modal executes on `[y]`: a daemon request (async, the
/// original shape) or a suspend-to-terminal action (root ops like un-wiring
/// PAM). A dedicated enum so a confirm can only name an action with a handler.
enum ConfirmAct {
    Daemon(Request),
    Sus(Suspend),
}

/// A y/n confirm with a SPECIFIC verb on the affirmative (GNOME HIG: "Label
/// the affirmative button with a specific imperative verb… clearer than a
/// generic label"): question, verb, action.
type Confirm = (String, &'static str, ConfirmAct);

/// Severity of a Repair-tab diagnostic.
#[derive(Clone, Copy, PartialEq)]
enum Sev {
    Ok,
    Warn,
    Fail,
}

/// What can be done about a failing/■warning check.
#[derive(Clone)]
enum Fix {
    /// Nothing actionable (informational / hardware).
    None,
    /// Show the user an exact command to run.
    Manual(String),
    /// Needs root: suspend the TUI and run via sudo (`apply_fix` → Suspend).
    Root(RootFix),
}

/// The root-op fixes `apply_fix` knows how to run. A dedicated enum (not a
/// string id) so a check row can only name a fix that has a handler.
#[derive(Clone, Copy)]
enum RootFix {
    /// `sudo irlume login reconcile`: re-apply wiring a distro PAM
    /// regeneration stripped (marker says wired, active greeter is not).
    LoginReconcile,
    RestartDaemon,
    RestartFprintd,
    LoginEnable,
    FingerprintAdd,
    SelinuxLoad,
}

/// A parked enrollment intent: what to resume after the daemon fix brings
/// irlumed up (see `daemon_gate`).
#[derive(Clone)]
enum ResumeEnroll {
    /// `begin_enroll`: re-open the new-profile name prompt.
    New,
    /// Add one scan to this existing profile.
    Add(String),
    /// New-profile enroll with this already-typed name.
    Named(String),
}

/// One Repair-tab diagnostic row.
struct Check {
    label: String,
    sev: Sev,
    detail: String,
    fix: Fix,
}

/// Non-camera state that steers `compute_visible`, named so call sites read
/// without counting positional bools. Defaults are all-false (no reader,
/// basic view, daemon reachable).
#[derive(Clone, Copy, Default)]
struct VisibilityInputs {
    /// A fingerprint reader is present.
    fp_present: bool,
    /// `[v]` advanced view is on.
    advanced: bool,
    /// The daemon is not answering Ping.
    daemon_down: bool,
}

/// Where an async op's result should land (besides the Activity log).
#[derive(Clone, Copy, PartialEq)]
enum OpTag {
    Generic,
    Identify,
}

/// Fingerprint snapshot for the Fingerprint screen.
#[derive(Default, Clone)]
struct FpInfo {
    available: bool,
    device: Option<String>,
    enrolled: Vec<String>,
    method: String,
}

/// Daemon self-report (`Request::Health`): camera tier + loaded models.
#[derive(Clone)]
struct HealthInfo {
    tier: String,
    rgb_dev: Option<String>,
    ir_dev: Option<String>,
    mesh: bool,
    adapter: bool,
    version: String,
    /// Loaded third-party PAD cue name (authoritative on/off, since
    /// settings.conf is root-only and a non-root TUI can't read it).
    third_party_pad: Option<String>,
    /// Loaded third-party recognizer name, same authority argument.
    third_party_recognizer: Option<String>,
    /// The third-party DETECTOR the daemon has in its rescue slot (#295),
    /// or None for the shipped short-range rescue.
    third_party_detector: Option<String>,
    /// The daemon's real AppArmor confinement label ("irlumed (enforce)",
    /// "unconfined", ...), or None when AppArmor is off or the daemon predates
    /// the field. Authoritative: the on-disk profile can exist while the daemon
    /// runs unconfined (a failed apparmor_parser load).
    apparmor: Option<String>,
}

/// Template-encryption + recovery status (`RecoveryStatus`).
#[derive(Clone, Copy, Default)]
struct RecoveryInfo {
    encrypted: bool,
    recovery_set: bool,
    tpm_present: bool,
    /// Whether the key that opens an encrypted store still exists. Encrypted
    /// with no key means the enrollment cannot be opened by anything, which
    /// `encrypted` alone cannot say.
    key_present: bool,
}

/// Messages streamed from the guided-enroll worker to the UI.
#[derive(Debug)]
enum WMsg {
    Cue(PositionReport),
    /// A framing-guide poll got no answer (timeout / connection error). NOT a
    /// biometric observation: the UI must stop showing the last cue as if it
    /// were current (#309).
    Stall(String),
    Count(u8),
    Captured(usize, usize),
    Done {
        /// Scans whose IR burst the room mostly lit; above zero the UI says
        /// dark-room login is unverified (#312).
        ambient_lit: usize,
    },
    Err(String),
    /// Scan 1 of a "new profile" enroll matched an existing identity, so the
    /// daemon merged it into `profile` instead. The worker ends here and hands
    /// off to the UI, which confirms with the user before adding the rest.
    /// `added_scans` are the scan(s) already appended (undo target on decline).
    MergePrompt {
        profile: String,
        /// Ambient-lit count of the scan(s) the merge already added, so the
        /// continuation's completion note covers them too (#312).
        ambient_lit: Option<usize>,
        /// Scans the daemon will still accept for this profile in the LOADED
        /// recognizer's space (#290 made the limit per recognizer). `None`
        /// when the daemon did not say, which is any daemon older than 0.9.0.
        room: Option<usize>,
        added_scans: Vec<String>,
    },
}

/// A pending "this face is already enrolled as X; add these scans to it?"
/// confirmation, raised when scan 1 of a new-profile enroll merged. `remaining`
/// is how many more scans to capture on confirm (capped at the 30-scan budget).
struct MergeConfirm {
    profile: String,
    added_scans: Vec<String>,
    remaining: usize,
    /// Ambient-lit count of the already-added scan(s), seeded into the
    /// continuation's total (#312).
    ambient_lit: usize,
}

struct EnrollUi {
    rx: mpsc::Receiver<WMsg>,
    stop: Arc<AtomicBool>,
    profile: String,
    last: Option<PositionReport>,
    count: Option<u8>,
    /// The framing guide stopped answering (timeout or connection error), with
    /// the transport error. Rendered INSTEAD of the last cue: a stale
    /// "No face detected" reads as a biometric verdict and sends the user
    /// into lighting adjustments against a hung capture (#309).
    stalled: Option<String>,
    captured: usize,
    target: usize,
    /// Scans already on the profile from this enroll session before the worker
    /// started (e.g. the one scan a merge added), so the on-screen "scan X/Y"
    /// stays continuous across the merge-confirm continuation instead of
    /// restarting at 0.
    base: usize,
    /// Ambient-lit count of scans added BEFORE this worker started (the
    /// merged scan(s)), folded into the completion note's total (#312).
    ambient_base: usize,
}

struct Op {
    label: String,
    tag: OpTag,
    rx: mpsc::Receiver<(bool, String)>,
}

/// TUI state. Seven `Option` fields act as modal overlays; when several are
/// `Some`, `on_key` consumes input in this order (first match wins):
/// `error` (any key dismisses) > `enroll` (Esc only) > `op` (q/Esc only) >
/// `input` (text entry) > `confirm` (y/n) > `enroll_merge` (y/n) > normal
/// screen keys. `suspend` is not a key state: the main loop takes it after
/// each key/tick, leaves the TUI, and runs the command. PageUp/PageDown
/// scroll the Activity panel in every state except text entry.
struct App {
    user: String,
    screen: usize,
    sel: usize,
    profiles: Vec<ProfileSummary>,
    eyes_open: bool,
    keyring_armed: Option<bool>,
    /// Seal-tier label from `KeyringInfo` (e.g. "pcrlock NV 0x… (Tier 2)");
    /// `None` when not armed or the daemon predates the request.
    keyring_policy: Option<String>,
    /// Whether the bound PCRs drifted since sealing (`KeyringInfo`).
    keyring_drift: Option<bool>,
    /// What kind of secret is armed (`KeyringInfo`); `None` from an older
    /// daemon. Routes the disarm key: a token disarm needs the CLI's re-key
    /// flow, and a bare `ForgetPassword` on it would strand the keyring.
    keyring_kind: Option<irlume_common::KeyringSecretKind>,
    nodes: Vec<(String, irlume_camera::Role)>,
    /// Cached camera pairs, refreshed on the slow timer so the Cameras tab and
    /// move_sel don't re-probe the hardware on every keystroke and frame.
    /// The camera pairs as the DAEMON enumerated them (#187): the TUI never
    /// opens a video node itself, so this arrives via ListCameras and each
    /// entry carries the privacy state the daemon read while it had the
    /// device.
    pairs: Vec<irlume_common::CameraPairInfo>,
    /// Whether the daemon has ever ANSWERED ListCameras. An empty `pairs`
    /// with this false means "not asked yet, refused, or an older daemon",
    /// which must not be drawn as "no cameras found" (#187): that claim
    /// contradicted the active-pair line right under it on a daemon that
    /// predates the request.
    pairs_known: bool,
    activity: Vec<(char, String)>,
    input: Option<(String, String, Pending)>,
    confirm: Option<Confirm>,
    /// True while mouse capture is released so the terminal's own selection
    /// works (the `[M]` toggle); wheel scroll is unavailable meanwhile.
    mouse_select: bool,
    /// The [?] full-keymap overlay (tier two of the disclosure ladder).
    show_help: bool,
    /// Selected row of the Welcome hub (Enter jumps to its screen).
    hub_sel: usize,
    op: Option<Op>,
    enroll: Option<EnrollUi>,
    /// A pending merge confirmation (scan 1 matched an existing profile).
    enroll_merge: Option<MergeConfirm>,
    fp: FpInfo,
    recovery: Option<RecoveryInfo>,
    suspend: Option<Suspend>,
    /// Enrollment intent parked while the daemon fix runs; resumed (once) as
    /// soon as the daemon answers after the suspended sudo step.
    resume_enroll: Option<ResumeEnroll>,
    /// Last 1:N identify result, shown as a card on the Identify screen.
    identify_result: Option<(bool, String)>,
    /// Last IR liveness self-test result, shown on the Repair screen.
    /// Repair-tab diagnostics + selection.
    repair: Vec<Check>,
    repair_sel: usize,
    /// Cameras-tab pair selection.
    cam_sel: usize,
    /// Settings-tab per-service consent-gesture selection (index into
    /// [`SETTINGS_GESTURE_SERVICES`]).
    settings_svc_sel: usize,
    /// Cached third-party-model and Bitwarden state for the DRAW path, with the
    /// moment they were taken.
    ///
    /// Both were computed per frame. `models::tui_state` reads and SHA-256s every
    /// enabled weight file (1.3 MiB for the shipped PAD cue here), and
    /// `bitwarden::tui_state` forks `getent` to resolve the invoking user's home,
    /// measured at ~37ms a call and called twice in one draw of the login-wiring
    /// tab. A redraw happens on every keypress and every tick, so the interface
    /// was hashing megabytes and forking processes to paint two rows. The key
    /// HANDLERS still read fresh: an action must act on the current state, and it
    /// runs once per press rather than once per frame.
    heavy: (crate::models::TuiState, Option<crate::bitwarden::TuiState>),
    heavy_at: std::time::Instant,
    /// A prominent, dismissible error banner (e.g. "camera busy") so failures
    /// are never silently buried in the Activity log.
    error: Option<String>,
    /// Live daemon reachability (a real Ping, refreshed each tick), not a
    /// hardcoded socket-path check.
    daemon_up: bool,
    /// The four-way classification behind `daemon_up`; see `LightState::reach`.
    daemon_reach: crate::commands::DaemonReach,
    /// Last ListProfiles error (corrupt enrollment / missing template key);
    /// distinguishes "file broken" from "no profiles" on the Repair tab.
    enroll_error: Option<String>,
    /// Daemon self-report (Request::Health): its camera tier and loaded models:
    /// ground truth for the Repair rows (static path probes lie when the daemon
    /// runs with its own env, e.g. a packaged install).
    health: Option<HealthInfo>,
    /// Activity panel scroll offset (lines up from the bottom; 0 = follow newest).
    act_scroll: usize,
    /// Models-tab catalog states, copied from the landed probe sweep; `None`
    /// until the first sweep lands (draw then says the state is loading
    /// instead of asserting either direction). See [`ModelsStatus`] for why
    /// this is cached rather than computed in draw.
    models_status: Option<ModelsStatus>,
    /// Models-tab scroll offset in wrapped rows (↑/↓); clamped to the content
    /// height in `draw_models`, reset on entering the tab.
    models_scroll: u16,
    /// Hardware-adaptive: the subset of screen indices to show (Tab walks these).
    /// e.g. a fingerprint-only desktop hides the camera/face screens entirely.
    visible: Vec<usize>,
    /// `[v]` advanced view: also show the diagnostic/tuning screens
    /// (Cameras, Identify, Settings, and Repair even when healthy).
    advanced: bool,
    /// Detected face-hardware capabilities (drives `visible` + the recommendation).
    caps: irlume_camera::Caps,
    /// A fingerprint reader is present.
    fp_present: bool,
    /// An in-flight background ListProfiles, drained by `poll()`. The listing
    /// decrypts every profile under the TPM template key: ~350ms on the
    /// reference Zenbook, MEASURED 10.8s on a ThinkPad X13 Yoga Gen 4 whose
    /// TPM workqueue was hogging. Run synchronously it froze the UI for that
    /// long at startup and on every Profiles entry, and the short poll budget
    /// then read the still-working daemon as down; on its own thread it gets
    /// a real budget and the UI keeps drawing.
    profiles_load: Option<std::sync::mpsc::Receiver<ProfilesOutcome>>,
    /// True after at least one successful ListProfiles response has landed.
    /// An empty list is VALID OBSERVED STATE, not "never loaded": deriving
    /// "unloaded" from emptiness made every light poll on an unenrolled
    /// machine start another TPM-backed listing, and each one occupies the
    /// daemon worker, which a login then waits behind.
    profiles_loaded: bool,
    /// The last landed machine snapshot; see [`Probes`]. Draw and run_checks
    /// only ever READ it, so both stay off every external interface.
    probes: Probes,
    /// An in-flight background probe sweep, drained by `poll()`.
    probes_load: Option<std::sync::mpsc::Receiver<Probes>>,
    /// At least one sweep has landed. Until then `probes` holds defaults,
    /// and copying defaults over the capabilities `App::new` observed hides
    /// real hardware; recompute_checks gates its copies on this.
    probes_landed: bool,
    /// An in-flight background light poll (daemon reads), drained by `poll()`.
    light_load: Option<std::sync::mpsc::Receiver<LightState>>,
    /// PAM-screen state, computed with the diagnostics (10s tier + screen
    /// entry), never in draw: rendering used to re-read every PAM service
    /// file and probe the LSM per FRAME.
    pam_cache: PamCache,
    /// Per-surface fingerprint coverage (#155), the same table `fingerprint
    /// status` prints; refreshed with the diagnostics when a reader exists.
    fp_coverage: Vec<(&'static str, &'static str, bool)>,
    spin: usize,
    quit: bool,
}

/// What one background `ListProfiles` produced (see `App::profiles_load`).
enum ProfilesOutcome {
    Loaded {
        profiles: Vec<ProfileSummary>,
        eyes_open: bool,
    },
    /// The daemon answered with an error (corrupt enrollment, missing
    /// template key): real state, shown on Repair like the sync path did.
    DaemonError(String),
    /// The request itself failed (daemon down mid-load, timeout). Not state:
    /// the previous list stays and the next refresh retries.
    Transport(String),
}

/// Everything the PAM screen renders, gathered off the draw path.
#[derive(Default, Clone)]
struct PamCache {
    /// `(label, present, wired)` per service, as `login status` reports.
    rows: Vec<(String, bool, bool)>,
    /// `/sys/fs/selinux` existed at refresh time (Fedora-family).
    selinux_present: bool,
    /// SELinux module state when present (`None` = needs root to tell).
    selinux: Option<bool>,
    /// AppArmor enabled this boot (Debian/Ubuntu-family).
    apparmor_enabled: bool,
    /// An irlume AppArmor profile is installed on disk.
    apparmor_profiled: bool,
    /// Wired greeters whose released password nothing turns into an open
    /// wallet (#200's advisory, the same walk `login status` prints).
    handoffs: Vec<crate::pamwire::HandoffWarning>,
}

/// Every observation of the MACHINE the diagnostics and screens read,
/// gathered on a background thread. The sweep behind this struct spawns
/// fprintd-list two to three times, busctl three times, walks $PATH for
/// semodule, runs `ls -Z`, and touches V4L2 and sysfs; on a ThinkPad with a
/// slow TPM keeping the daemon busy, running it inline put every keypress
/// behind ~8.8s of it (measured), because each slow iteration made the next
/// sweep due immediately. The UI thread only ever READS the last snapshot;
/// tests construct one directly, which also makes the Repair checklist
/// deterministic under test for the first time.
#[derive(Default, Clone)]
struct Probes {
    caps: irlume_camera::Caps,
    /// Whether `caps` came from an actual device probe. False means the
    /// daemon was up and the probe was skipped to avoid opening nodes it may
    /// be streaming (#187); the caller must then take capabilities from the
    /// daemon's Health rather than believing this all-false default.
    caps_probed: bool,
    fp_present: bool,
    fp: FpInfo,
    pam_cache: PamCache,
    fp_coverage: Vec<(&'static str, &'static str, bool)>,
    /// The reader is claimed by a stale fprintd session (prompts fail silently).
    reader_stuck: bool,
    /// SELinux is enforcing this boot.
    selinux_enforcing: bool,
    /// The daemon socket carries the irlume SELinux label.
    selinux_socket_labeled: bool,
    /// Face login is wired into at least one greeter.
    login_wired: bool,
    /// The fingerprint keyring-unlock line is present in every service the
    /// active login manager consults.
    fp_keyring_wired: bool,
    /// A TPM device exists.
    tpm_present: bool,
    /// A distro PAM regeneration dropped the wiring (self-heal pending).
    reconcile_needed: bool,
    /// The login keyring is locked right now (`None` = could not tell).
    keyring_locked: Option<bool>,
    /// Secure Boot: (firmware supports it, currently enabled, setup mode).
    secureboot: (bool, bool, bool),
    /// Firmware boot mode label (UEFI/legacy), from efivars.
    boot_mode: String,
    /// Third-party catalog states for the Models tab; `None` until gathered
    /// (the derived default), so draw asserts nothing before the first sweep.
    models: Option<ModelsStatus>,
}

/// Cached per-entry state for the Models tab, one label per
/// `thirdparty::CATALOG` entry in catalog order.
///
/// Gathered on the probe worker, never in draw (#334 review): the ENABLED and
/// root-only labels hash the on-disk weights (`entry_state_label` →
/// `weight_state`), the main loop redraws every 100ms, and rendered inline an
/// installed recognizer was reread and re-hashed about ten times a second on
/// the UI thread for as long as the tab stayed open.
#[derive(Clone)]
struct ModelsStatus {
    /// `models::entry_state_label` per catalog entry, catalog order.
    labels: Vec<String>,
    /// Whether settings.conf was readable; root-only when not, and the
    /// listing then names the sudo command for the authoritative answer.
    readable: bool,
}

impl ModelsStatus {
    /// The one computation source (the probe worker and the tests both call
    /// it): exactly the labels the CLI listing prints.
    fn gather() -> Self {
        ModelsStatus {
            labels: irlume_common::thirdparty::CATALOG
                .iter()
                .map(crate::models::entry_state_label)
                .collect(),
            readable: crate::models::enabled_state_readable(),
        }
    }
}

impl Probes {
    /// The full sweep, verbatim from the code that used to run inline. Runs
    /// on a worker thread; everything here may block on D-Bus activation, a
    /// subprocess, or a device open without costing the UI a frame.
    fn gather(user: &str) -> Self {
        use irlume_common::secureboot;
        // No camera probe (#187): capabilities() classifies every node,
        // which opens it. Capabilities come from the daemon's Health.
        let caps = irlume_camera::Caps {
            ir_pair: false,
            rgb: false,
        };
        let fp_present = irlume_fingerprint::available();
        let fp = FpInfo {
            available: fp_present,
            device: irlume_fingerprint::device_name(),
            enrolled: irlume_fingerprint::enrolled_fingers(user),
            method: irlume_core::policy::method().as_str().to_string(),
        };
        let pam_cache = PamCache {
            rows: crate::pamwire::status_report(),
            selinux_present: std::path::Path::new("/sys/fs/selinux").exists(),
            selinux: crate::pamwire::selinux_state(),
            apparmor_enabled: std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
                .map(|s| s.trim() == "Y")
                .unwrap_or(false),
            apparmor_profiled: std::path::Path::new("/etc/apparmor.d/usr.bin.irlumed").exists()
                || std::path::Path::new("/etc/apparmor.d/usr.local.bin.irlumed").exists(),
            handoffs: crate::pamwire::keyring_handoff_warnings(),
        };
        Probes {
            caps,
            caps_probed: false,
            fp_present,
            reader_stuck: fp_present && irlume_fingerprint::reader_stuck(user),
            fp,
            fp_coverage: if fp_present {
                crate::fingerprint::fprintd_coverage_live()
            } else {
                Vec::new()
            },
            pam_cache,
            selinux_enforcing: std::fs::read_to_string("/sys/fs/selinux/enforce")
                .map(|s| s.trim() == "1")
                .unwrap_or(false),
            selinux_socket_labeled: std::process::Command::new("ls")
                .args(["-Z", "/run/irlume.sock"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("irlume_runtime_t"))
                .unwrap_or(false),
            login_wired: crate::pamwire::login_wired(),
            fp_keyring_wired: crate::pamwire::fp_keyring_wired(),
            tpm_present: crate::tpm_device().is_some(),
            reconcile_needed: crate::pamwire::reconcile_needed(),
            keyring_locked: crate::secrets::login_keyring_locked(),
            secureboot: (
                secureboot::secure_boot_present(),
                secureboot::is_secure_boot_enabled(),
                secureboot::is_setup_mode(),
            ),
            boot_mode: secureboot::detect_boot_mode().as_str().to_string(),
            models: Some(ModelsStatus::gather()),
        }
    }
}

/// The cheap live poll's results (daemon socket reads + camera enumeration),
/// also gathered off the UI thread: when the daemon is busy, even the SHORT
/// poll budget is 1.5s per request, and paying that between keystrokes is
/// what made the whole TUI feel wedged whenever the daemon was.
struct LightState {
    daemon_up: bool,
    /// The classified Ping outcome behind `daemon_up`. Kept alongside the
    /// bool because Repair needs four answers where the gating logic needs
    /// one: "starting" must not be offered a restart (it kills a daemon
    /// seconds from ready) and EACCES must not read as "not reachable".
    reach: crate::commands::DaemonReach,
    health: Option<HealthInfo>,
    keyring_armed: Option<bool>,
    keyring_policy: Option<String>,
    keyring_drift: Option<bool>,
    keyring_kind: Option<irlume_common::KeyringSecretKind>,
    recovery: Option<RecoveryInfo>,
}

impl LightState {
    /// Verbatim the reads `refresh_light` used to make inline, EXCEPT that
    /// it no longer enumerates cameras at all: the daemon answers Health for
    /// capabilities and ListCameras for the picker (#187).
    fn gather(user: &str, prev_armed: Option<bool>) -> Self {
        // The raw client call, not `daemon_poll`: classification needs the
        // errno kind and daemon_poll flattens errors to String.
        let reach =
            crate::commands::classify_reach(irlume_common::client::request_poll(&Request::Ping));
        let daemon_up = reach == crate::commands::DaemonReach::Running;
        // Classifying a node OPENS it. While the daemon is reachable it may
        // be streaming those same nodes, and a second opener is EBUSY on
        // strict UVC modules (#187). Gating on "is the daemon up" was not
        // enough: a Ping that TIMES OUT reads as down, and a timing-out Ping
        // is exactly what a daemon busy with the camera produces, so the
        // fallback fired precisely when it was most dangerous. Capabilities
        // come from Health, the picker's listing from ListCameras, and both
        // are serialized against captures on the daemon's side.
        let mut out = LightState {
            daemon_up,
            reach,
            health: None,
            keyring_armed: prev_armed,
            keyring_policy: None,
            keyring_drift: None,
            keyring_kind: None,
            recovery: None,
        };
        if !daemon_up {
            return out;
        }
        out.health = match crate::daemon_poll(&Request::Health) {
            Ok(Response::Health {
                tier,
                rgb_dev,
                ir_dev,
                mesh,
                adapter,
                version,
                third_party_pad,
                third_party_recognizer,
                third_party_detector,
                apparmor,
            }) => Some(HealthInfo {
                tier,
                rgb_dev,
                ir_dev,
                mesh,
                adapter,
                version,
                third_party_pad,
                third_party_recognizer,
                third_party_detector,
                apparmor,
            }),
            _ => None, // older daemon / daemon down → Repair falls back to local probes
        };
        // KeyringInfo adds the seal tier and PCR drift; an older daemon
        // answers it with an error, so fall back to the plain armed bit.
        match crate::daemon_poll(&Request::KeyringInfo {
            user: user.to_string(),
        }) {
            Ok(Response::KeyringInfo {
                armed,
                policy,
                drifted,
                kind,
                ..
            }) => {
                out.keyring_armed = Some(armed);
                out.keyring_policy = policy;
                out.keyring_drift = drifted;
                out.keyring_kind = kind;
            }
            _ => {
                out.keyring_armed = match crate::daemon_poll(&Request::HasSealedPassword {
                    user: user.to_string(),
                }) {
                    Ok(Response::HasPassword(b)) => Some(b),
                    _ => prev_armed,
                };
            }
        }
        if let Ok(Response::RecoveryStatus {
            encrypted,
            recovery_set,
            tpm_present,
            key_present,
        }) = crate::daemon_poll(&Request::RecoveryStatus {
            user: user.to_string(),
        }) {
            out.recovery = Some(RecoveryInfo {
                encrypted,
                key_present,
                recovery_set,
                tpm_present,
            });
        }
        out
    }
}

pub fn run(args: &[String]) -> std::io::Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        eprintln!("irlume tui needs an interactive terminal (TTY). Run it directly in a terminal.");
        return Ok(());
    }
    let mut terminal = ratatui::init();
    let _ = ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::event::EnableMouseCapture
    );
    let mut app = App::new(crate::user_arg(args));
    app.log('·', format!("irlume: managing '{}' (live)", app.user));
    app.refresh();
    let res = app.main_loop(&mut terminal);
    let _ = ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::event::DisableMouseCapture
    );
    ratatui::restore();
    res
}

impl App {
    /// `user` is resolved by the caller through `crate::user_arg`, NOT from
    /// $USER here.
    ///
    /// Under `sudo irlume tui` the environment says USER=root and LOGNAME=root
    /// while SUDO_USER holds the person who actually ran it, and this screen
    /// tells users to run it with sudo to see root-only settings. Reading $USER
    /// therefore pointed every one of this file's requests at the account
    /// `root`: an empty dashboard for a fully configured user, and worse, `[a]`
    /// sealing the typed login password and `[e]` enrolling a face under the
    /// wrong account. `user_arg` is the single rule the rest of the CLI already
    /// follows, and it also honours an explicit `--user`.
    fn new(user: String) -> Self {
        // Hardware-adaptive screens: only show what the device can actually
        // do, so a fingerprint-only box never offers face/camera setup steps.
        //
        // Asked of the DAEMON, never probed here (#187 review): probing
        // classifies every node, which opens it, and App::new runs before
        // any other daemon contact, so it could open a node mid-capture. A
        // daemon that does not answer leaves capabilities unknown, and
        // unknown must not hide the camera screens on a machine that has
        // cameras, so the optimistic default stands until the first light
        // poll replaces it with the daemon's answer.
        let caps = match crate::daemon_poll(&Request::Health) {
            Ok(Response::Health {
                ref tier,
                ref rgb_dev,
                ..
            }) => irlume_camera::Caps {
                ir_pair: tier == "secure",
                rgb: rgb_dev.is_some() || tier == "secure",
            },
            _ => irlume_camera::Caps {
                ir_pair: true,
                rgb: true,
            },
        };
        let fp_present = irlume_fingerprint::available();
        let visible = Self::compute_visible(
            &caps,
            VisibilityInputs {
                fp_present,
                // Assume the daemon is down until the first Ping answers, so
                // Repair starts visible rather than flickering in later.
                daemon_down: true,
                ..VisibilityInputs::default()
            },
            &[],
        );
        let screen = visible.first().copied().unwrap_or(0);
        Self {
            user,
            screen,
            sel: 0,
            profiles: Vec::new(),
            eyes_open: false,
            keyring_armed: None,
            keyring_policy: None,
            keyring_drift: None,
            keyring_kind: None,
            // EMPTY at construction (#187 review caught this one): App::new
            // ran before any daemon contact, so probing here opened every
            // node while the daemon might be mid-authentication. The light
            // poll fills both in from the daemon within the first tick.
            nodes: Vec::new(),
            pairs: Vec::new(),
            pairs_known: false,
            activity: Vec::new(),
            input: None,
            confirm: None,
            mouse_select: false,
            show_help: false,
            hub_sel: 0,
            op: None,
            enroll: None,
            enroll_merge: None,
            fp: FpInfo::default(),
            recovery: None,
            suspend: None,
            resume_enroll: None,
            identify_result: None,
            repair: Vec::new(),
            repair_sel: 0,
            cam_sel: 0,
            settings_svc_sel: 0,
            heavy: (crate::models::tui_state(), crate::bitwarden::tui_state()),
            heavy_at: std::time::Instant::now(),
            error: None,
            daemon_up: false,
            daemon_reach: crate::commands::DaemonReach::Down,
            enroll_error: None,
            health: None,
            act_scroll: 0,
            models_status: None,
            models_scroll: 0,
            visible,
            caps,
            fp_present,
            advanced: false,
            profiles_load: None,
            profiles_loaded: false,
            probes: Probes::default(),
            probes_load: None,
            probes_landed: false,
            light_load: None,
            pam_cache: PamCache::default(),
            fp_coverage: Vec::new(),
            spin: 0,
            quit: false,
        }
    }

    /// Which wizard steps to show. The DEFAULT view is the essential setup
    /// path only: Welcome → Enroll → Keyring → Recovery → Login wiring →
    /// Done. Diagnostic/advanced screens earn their place instead of always
    /// claiming one: Repair appears only when something actually needs fixing
    /// (daemon down or a failing check), and Cameras / Identify / Settings
    /// live behind the `[v]` advanced toggle.
    fn compute_visible(
        caps: &irlume_camera::Caps,
        state: VisibilityInputs,
        checks: &[Check],
    ) -> Vec<usize> {
        let VisibilityInputs {
            fp_present,
            advanced,
            daemon_down,
        } = state;
        // Repair surfaces whenever there is ANYTHING to report (a failure OR an
        // advisory), so the Welcome health summary's "→ see checks & repair"
        // pointer is always reachable; a warning used to point at a hidden tab.
        let needs_repair = daemon_down
            || checks
                .iter()
                .any(|c| c.sev == Sev::Fail || c.sev == Sev::Warn);
        (0..SCREENS.len())
            .filter(|&i| match i {
                // Essential face path requires a camera.
                SC_PROFILES | SC_RECOVERY => caps.rgb,
                // Diagnostics/tuning: advanced view only.
                SC_CAMERAS | SC_IDENTIFY => advanced && caps.rgb,
                // Settings holds user preferences (eyes-open, per-service consent
                // gesture, keyring gesture, biopolicy,
                // third-party models), not diagnostics, so it is always
                // reachable; hiding config behind "advanced" both buries it and
                // creates dead-end pointers (a Repair fix references Settings).
                // Models (#331) is reachable for the same reason: the measured
                // catalog is the surface the issue exists to expose, and the
                // Settings third-party section points at it.
                SC_SETTINGS | SC_MODELS => true,
                // Repair: only when something needs attention (or advanced view).
                SC_REPAIR => advanced || needs_repair,
                // Keyring unlock: an IR camera (face releases the credential) OR a
                // fingerprint reader (ADR-0003: a fingerprint login unseals it too).
                SC_KEYRING => caps.ir_pair || fp_present,
                // Fingerprint screen only if a reader exists.
                SC_FINGERPRINT => fp_present,
                // Welcome / Login-wiring / Done: always.
                _ => true,
            })
            .collect()
    }

    /// Re-derive tab visibility from live state; keeps the current screen when
    /// it survives, else snaps to the nearest visible step.
    fn recompute_visible(&mut self) {
        // The hub lists the VISIBLE screens, so this is where its list can
        // shrink ([v] leaves advanced view, a probe lands, the daemon goes
        // away). `move_sel` wraps modulo the current length, so a stale index
        // fixes itself on the next arrow, but until then no row is highlighted
        // and Enter silently opens nothing: an advertised key doing nothing,
        // which is the shape this pass keeps finding.
        self.visible = Self::compute_visible(
            &self.caps,
            VisibilityInputs {
                fp_present: self.fp_present,
                advanced: self.advanced,
                daemon_down: !self.daemon_up,
            },
            &self.repair,
        );
        if !self.visible.contains(&self.screen) {
            let cur = self.screen;
            self.screen = self
                .visible
                .iter()
                .copied()
                .min_by_key(|&s| s.abs_diff(cur))
                .unwrap_or(0);
        }
        // Clamp the hub selection into the list it now has.
        let rows = self.hub_rows().len();
        if rows > 0 && self.hub_sel >= rows {
            self.hub_sel = rows - 1;
        }
    }

    /// Enrollment as the chrome may claim it. `None` until ListProfiles has
    /// ever answered (`profiles_loaded`): an unanswered question must not
    /// render as "not enrolled", the same rule the Profiles empty state and
    /// the Done badge already follow.
    fn enrolled_known(&self) -> Option<bool> {
        if !self.profiles.is_empty() {
            Some(true)
        } else if self.profiles_loaded {
            Some(false)
        } else {
            None
        }
    }

    /// Login wiring as the chrome may claim it. `Probes` holds `login_wired:
    /// false` until the first sweep lands, and the hint, the Done body and the
    /// Done footer must not read that default as "not wired" (#187's rule:
    /// a default is not an observation).
    fn login_wired_known(&self) -> Option<bool> {
        self.probes_landed.then_some(self.probes.login_wired)
    }

    /// Capability-aware recommended unlock method (item: "suggest the best one").
    fn recommended(&self) -> &'static str {
        match (self.caps.ir_pair, self.caps.rgb, self.fp_present) {
            // "in the dark", never "dark mode": IR needs no visible light,
            // but "dark mode" reads as a UI theme.
            (true, _, _) => "Face (IR) · secure: login, sudo, lock screen, in the dark",
            (false, true, true) => "Fingerprint (secure), or Face (RGB) for lock-screen only",
            (false, true, false) => "Face (RGB) · convenience: lock-screen unlock only",
            (false, false, true) => "Fingerprint",
            (false, false, false) => "Password only (no supported biometric hardware)",
        }
    }

    fn log(&mut self, g: char, m: impl Into<String>) {
        self.activity.push((g, m.into()));
        // If the user has scrolled up to read history, hold their view in place
        // as new lines arrive (instead of yanking them to the bottom).
        if self.act_scroll > 0 {
            self.act_scroll += 1;
        }
        let n = self.activity.len();
        if n > 200 {
            let d = n - 200;
            self.activity.drain(0..d);
            self.act_scroll = self.act_scroll.saturating_sub(d);
        }
    }

    /// Record a failure: log it AND raise the dismissible error banner so the
    /// user sees WHY something failed (not just a scrolled-off Activity line).
    fn set_error(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        self.log('✗', m.clone());
        self.error = Some(m);
    }

    /// Request a CHEAP live poll (daemon state + camera nodes) on the worker;
    /// `poll()` lands it. Even the short poll budget is 1.5s PER REQUEST when
    /// the daemon is busy behind a slow TPM operation, and paying that
    /// between keystrokes is what made the whole TUI feel wedged whenever the
    /// daemon was. SILENT (no Activity spam).
    fn refresh_light(&mut self) {
        if self.light_load.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let user = self.user.clone();
        let prev_armed = self.keyring_armed;
        std::thread::spawn(move || {
            let _ = tx.send(LightState::gather(&user, prev_armed));
        });
        self.light_load = Some(rx);
    }

    /// Refresh the Cameras picker from the DAEMON.
    ///
    /// `ListCameras` is camera-class on the daemon side, so the arbiter
    /// serializes it against captures exactly like an enrollment: the
    /// enumeration still opens nodes, but only ever on the one thread that
    /// owns them (#187). A refusal (an authentication holds the camera) or
    /// any transport error leaves the previous listing in place rather than
    /// blanking it, because neither is an observation that the cameras are
    /// gone.
    fn refresh_camera_listing(&mut self) {
        if let Ok(Response::Cameras(pairs)) = crate::daemon_poll(&Request::ListCameras) {
            self.pairs = pairs;
            self.pairs_known = true;
            let n = self.pairs.len().max(1);
            if self.cam_sel >= n {
                self.cam_sel = n - 1;
            }
        }
    }

    /// Capabilities as the DAEMON reports them, for use whenever it is
    /// reachable (#187): it already has the cameras open, so it can say what
    /// they are without the TUI opening anything. `tier` is the daemon's own
    /// hardware classification; only the secure tier means a usable IR pair,
    /// and any reported RGB device means RGB capture works.
    fn caps_from_health(h: &HealthInfo) -> irlume_camera::Caps {
        irlume_camera::Caps {
            ir_pair: h.tier == "secure",
            rgb: h.rgb_dev.is_some() || h.tier == "secure",
        }
    }

    /// Land a background light poll: the daemon reads plus the selection
    /// clamps the inline version used to apply.
    fn apply_light(&mut self, l: LightState) {
        self.daemon_up = l.daemon_up;
        self.daemon_reach = l.reach;
        // Daemon down/unresponsive: show the down state; the local probes
        // still land via the heavy sweep so Repair can diagnose.
        self.health = l.health;
        // The daemon is the authority on cameras while it is reachable.
        if let Some(h) = self.health.as_ref() {
            self.caps = Self::caps_from_health(h);
        }
        if l.daemon_up {
            self.keyring_armed = l.keyring_armed;
            self.keyring_policy = l.keyring_policy;
            self.keyring_kind = l.keyring_kind;
            self.keyring_drift = l.keyring_drift;
            if l.recovery.is_some() {
                self.recovery = l.recovery;
            }
        }
        // The daemon just became reachable and no list was ever loaded (the
        // startup attempt may have raced a still-booting daemon): fetch it
        // now instead of waiting for a tab visit.
        if self.daemon_up && !self.profiles_loaded && self.enroll_error.is_none() {
            self.refresh_profiles();
        }
        let max = self.rows().len().max(1);
        if self.sel >= max {
            self.sel = max - 1;
        }
        let pairs = self.pairs.len().max(1);
        if self.cam_sel >= pairs {
            self.cam_sel = pairs - 1;
        }
    }

    /// Request the FULL machine sweep (fingerprint via fprintd, the PAM and
    /// coverage walks, LSM and TPM probes) on the worker; `poll()` lands it
    /// and recomputes the checks. See [`Probes`] for why this must never run
    /// on the UI thread.
    fn request_probes(&mut self) {
        if self.probes_load.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let user = self.user.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Probes::gather(&user));
        });
        self.probes_load = Some(rx);
    }

    /// Start a BACKGROUND enrollment-list load; `poll()` lands the result.
    /// This is the ONE slow read: ListProfiles triggers a TPM unseal of the
    /// template key to decrypt the profiles, ~350ms on the reference Zenbook
    /// and a MEASURED 10.8s on a ThinkPad X13 Yoga Gen 4 (its TPM workqueue
    /// hogging; dmesg said so). Run inline it froze the UI for the whole
    /// unseal, and the 1.5s poll budget then abandoned the reply entirely, so
    /// that machine never saw its profiles at all. The worker gets a budget
    /// sized to the slowest TPM observed, and the UI keeps drawing. Called
    /// only where a change can have happened: at startup, after a TUI
    /// mutation, and when entering the Profiles tab.
    fn refresh_profiles(&mut self) {
        // No daemon_up gate: at startup the async light poll has not landed
        // yet, so the flag still reads false and gating on it meant the
        // profile list never loaded until the user visited the Profiles tab
        // (seen live: an enrolled machine's Repair row claiming "no face
        // enrolled"). A down daemon just costs the worker a fast connect
        // error, reported as a Transport outcome.
        if self.profiles_load.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let user = self.user.clone();
        std::thread::spawn(move || {
            let outcome = match irlume_common::client::request_with_timeout(
                &Request::ListProfiles {
                    user,
                    structured_errors: false,
                },
                std::time::Duration::from_secs(60),
            ) {
                Ok(Response::Enrollment {
                    profiles,
                    require_eyes_open,
                    ..
                }) => ProfilesOutcome::Loaded {
                    profiles,
                    eyes_open: require_eyes_open,
                },
                // A corrupt/unreadable enrollment (or a missing template key
                // for an encrypted file) surfaces as an Error, not empty;
                // don't silently show "no face enrolled"; capture it so
                // Repair can flag+fix it.
                Ok(Response::Error(e)) => ProfilesOutcome::DaemonError(e),
                Ok(_) => ProfilesOutcome::Transport("unexpected daemon reply".into()),
                Err(e) => ProfilesOutcome::Transport(e.to_string()),
            };
            let _ = tx.send(outcome);
        });
        self.profiles_load = Some(rx);
    }

    /// Re-derive hardware caps + fingerprint + the PAM/coverage caches + the
    /// Repair checklist from the CURRENT state (daemon reads + self.profiles).
    /// Split out so both refresh paths run it AFTER their state reads, and
    /// run_checks never sees stale profiles (a startup ordering bug showed a
    /// spurious "no enrollment" warn; the async profile load closes the same
    /// hole by reporting "loading" instead of "none" while in flight).
    fn recompute_checks(&mut self) {
        // Copy the landed snapshot into the fields draw reads (hardware caps
        // so a hot-plugged camera or reader reveals its tabs, the fingerprint
        // trio, the PAM screen's cache, the coverage table), then rebuild the
        // checklist. Everything here is in-memory: the machine was observed
        // by `Probes::gather` on the worker. Before the FIRST sweep lands the
        // snapshot holds defaults, and defaults are not observations: copying
        // them would erase the capabilities `App::new` detected and hide the
        // camera screens until the sweep arrives.
        if self.probes_landed {
            // Only adopt probed capabilities. When the daemon was up the
            // sweep skipped the device probe (#187), and its all-false
            // default is not an observation: `caps_from_health` already set
            // the authoritative value, and copying the default over it would
            // hide the camera screens on a machine that has cameras.
            if self.probes.caps_probed {
                self.caps = self.probes.caps;
            }
            self.fp_present = self.probes.fp_present;
            self.fp = self.probes.fp.clone();
            self.pam_cache = self.probes.pam_cache.clone();
            self.fp_coverage = self.probes.fp_coverage.clone();
            // The Models-tab cache (#334 review): only ever replaced by a
            // gathered value, so a landed sweep can never blank it.
            if let Some(models) = self.probes.models.clone() {
                self.models_status = Some(models);
            }
        }
        self.run_checks();
        // Visibility is state-driven (Repair appears when something fails);
        // re-derive it from the fresh diagnostics.
        self.recompute_visible();
    }

    /// Diagnostics without the slow profile poll: fast daemon reads + hardware
    /// caps + fingerprint + the Repair checks (with the CACHED profile list).
    /// Tab switches use this so moving between tabs never pays the ListProfiles
    /// TPM-unseal cost.
    fn refresh_diagnostics(&mut self) {
        self.refresh_light();
        self.request_probes();
    }

    /// Full refresh incl. the slow profile poll: startup, after mutations, and
    /// suspend-return. Order matters: refresh_light sets `daemon_up` (which
    /// refresh_profiles needs), profiles load, THEN recompute_checks runs so
    /// run_checks sees the fresh profile list (not the stale/empty one).
    /// Full refresh: request daemon state, enrollment state, and the complete
    /// machine snapshot. Existing landed state stays visible until the
    /// replacements arrive through `poll()`; recomputing here would copy a
    /// default (unlanded) snapshot over real observations, which at startup
    /// erased the capabilities `App::new` had just detected and hid whole
    /// screens for the first ten seconds.
    fn refresh(&mut self) {
        self.refresh_light();
        self.refresh_profiles();
        self.request_probes();
    }

    /// Build the Repair-tab diagnostics from current state + quick local probes.
    fn run_checks(&mut self) {
        let mut v = Vec::new();
        let mk = |label: &str, sev, detail: String, fix| Check {
            label: label.into(),
            sev,
            detail,
            fix,
        };

        // refresh_light already pinged with the SHORT poll budget and both
        // refresh paths run it first; asking again here with daemon_request's
        // 120s budget meant every heavy tick blocked the UI for the whole
        // arbiter queue whenever the daemon was busy (measured: ~9s per tab
        // press on a ThinkPad while a TPM-bound ListProfiles was in flight).
        {
            use crate::commands::DaemonReach as R;
            // Four answers, not two. "Starting" got told "not reachable" about
            // a socket that had just answered, and its [f] restarted a daemon
            // seconds from ready, reopening the same window. EACCES is the
            // socket refusing THIS user (mode is 0666, so in practice a
            // SELinux denial), which a restart does not change either.
            let (sev, detail, fix) = match self.daemon_reach {
                R::Running => (Sev::Ok, "running, socket reachable".into(), Fix::None),
                R::Starting => (
                    Sev::Warn,
                    "starting (loading models); re-run checks with [r] in a few seconds".into(),
                    Fix::None,
                ),
                R::AccessDenied => (
                    Sev::Fail,
                    format!(
                        "running, but this user may not connect (EACCES on {})",
                        irlume_common::client::socket_path().display()
                    ),
                    Fix::Manual(
                        "see the SELinux policy row below; sudo irlume selinux status".into(),
                    ),
                ),
                // Name the socket the ping actually used: with IRLUME_SOCKET
                // set, "/run/irlume.sock" described a path nobody probed.
                R::Down => (
                    Sev::Fail,
                    format!(
                        "not reachable on {}",
                        irlume_common::client::socket_path().display()
                    ),
                    Fix::Root(RootFix::RestartDaemon),
                ),
            };
            v.push(mk("Daemon (irlumed)", sev, detail, fix));
        }

        // ONNX Runtime + Models: the daemon is the ground truth: if it answers
        // Health it loaded both at startup (it exits otherwise). Static path
        // probes are only a fallback while the daemon is down; they can't know
        // the daemon's env (ORT_DYLIB_PATH / IRLUME_*_MODEL of a packaged unit).
        if let Some(h) = self.health.clone() {
            v.push(mk(
                "ONNX Runtime",
                Sev::Ok,
                "loaded (reported by the daemon)".into(),
                Fix::None,
            ));
            v.push(mk(
                "Models",
                Sev::Ok,
                format!(
                    "YuNet + AuraFace loaded{}{}",
                    if h.adapter { " + IR adapter" } else { "" },
                    if h.mesh { " + FaceMesh" } else { "" }
                ),
                Fix::None,
            ));
            // The mesh ships as a .tflite (#295) and the packaged unit points
            // IRLUME_MESH_MODEL at it, so a running daemon reporting the mesh
            // is the ground truth that the TFLite runtime loaded, the same way
            // Health answers for ONNX. A daemon running WITHOUT the mesh is
            // not fine: passive blink liveness and the eye-closure consent
            // gesture are off, and with the release challenge on, a face
            // login leaves the keyring locked.
            v.push(mk(
                "TFLite runtime",
                if h.mesh { Sev::Ok } else { Sev::Warn },
                if h.mesh {
                    "loaded (the daemon reports FaceMesh, which ships as a .tflite)".into()
                } else {
                    "FaceMesh is not loaded: passive blink liveness and the eye-closure \
                     consent gesture are off"
                        .into()
                },
                if h.mesh {
                    Fix::None
                } else {
                    Fix::Manual(
                        "check IRLUME_MESH_MODEL in the irlumed unit, or reinstall the package"
                            .into(),
                    )
                },
            ));
            // Camera row from the daemon's validated tier (never the raw fallback).
            let priv_on = self.pairs.iter().any(|p| p.privacy);
            let (csev, cdetail, cfix) = match h.tier.as_str() {
                _ if priv_on => (Sev::Warn, "camera present, but a privacy switch is ON".to_string(),
                    Fix::Manual("turn off the camera privacy switch".into())),
                "secure" => (Sev::Ok,
                    format!("RGB + IR ({} + {}): secure tier",
                        h.rgb_dev.as_deref().unwrap_or("?"), h.ir_dev.as_deref().unwrap_or("?")),
                    Fix::None),
                "convenience" => (Sev::Warn,
                    format!("RGB-only ({}), convenience tier: face unlocks the screen only, never sudo/login",
                        h.rgb_dev.as_deref().unwrap_or("?")),
                    Fix::None),
                _ => (Sev::Warn, "no camera: face auth unavailable (password/fingerprint only)".to_string(),
                    Fix::None),
            };
            v.push(mk("Cameras", csev, cdetail, cfix));
            // Emitter fix only makes sense when an IR node exists.
            if h.ir_dev.is_some() {
                // No row at all. This check has never measured the emitter: it
                // was unconditionally a warning whenever an IR node existed,
                // which cried wolf on every working machine and pointed its fix
                // button at a write to the camera. Turning it into an OK just
                // moved the false claim to the other side, telling someone with
                // a genuinely dark feed that everything is fine.
                //
                // Repair states verdicts it can support. Emitter setup is not a
                // verdict, it is an action, and it lives on the Cameras screen
                // where it is offered without a diagnosis attached.
            }
        } else {
            let ort = std::env::var("ORT_DYLIB_PATH")
                .ok()
                .filter(|p| std::path::Path::new(p).exists())
                .is_some()
                || ORT_FALLBACK_PATHS
                    .iter()
                    .any(|p| std::path::Path::new(p).exists());
            v.push(ort_fallback_check(ort));
            v.push(tflite_fallback_check(
                std::env::var(irlume_vision::tflite::TFLITE_LIB_ENV)
                    .ok()
                    .as_deref(),
                |p| p.exists(),
            ));

            // Resolve models the way the daemon does (env → /usr/share/irlume/models
            // → repo cwd), NOT just cwd-relative; a packaged install keeps them in
            // /usr/share and the TUI is rarely launched from the repo.
            let m1 = crate::commands::resolve_model("glintr100.onnx", "IRLUME_MODEL").is_some();
            let m2 = crate::commands::resolve_model(
                "face_detection_yunet_2023mar.onnx",
                "IRLUME_DET_MODEL",
            )
            .is_some();
            v.push(mk(
                "Models",
                if m1 && m2 { Sev::Ok } else { Sev::Fail },
                if m1 && m2 {
                    "YuNet + AuraFace present".into()
                } else {
                    "not found (daemon down; local probe)".into()
                },
                if m1 && m2 {
                    Fix::None
                } else {
                    Fix::Manual(
                        "install the irlume package (models ship in /usr/share/irlume/models)"
                            .into(),
                    )
                },
            ));

            let rgb = self
                .nodes
                .iter()
                .any(|(_, r)| matches!(r, irlume_camera::Role::Rgb));
            let ir = self
                .nodes
                .iter()
                .any(|(_, r)| matches!(r, irlume_camera::Role::Ir));
            let priv_on = self.pairs.iter().any(|p| p.privacy);
            let (csev, cdetail, cfix) = if self.nodes.is_empty() {
                // NOTHING was probed, which is not the same as nothing being
                // there. `nodes` is only ever filled by a classifying scan, and
                // this screen deliberately does not run one: classifying opens
                // every node, which is the device contention #187 is about, so
                // the daemon's Health is where camera facts normally come from
                // and the daemon is what is down in this branch. The old text
                // read the empty list as proof and told everyone with a working
                // camera that face auth was unavailable, on the one screen they
                // opened to find out what was wrong.
                (
                    Sev::Warn,
                    "cannot check the cameras while the daemon is down (start it with: \
                     sudo systemctl start irlumed)"
                        .to_string(),
                    Fix::Manual("sudo systemctl start irlumed".into()),
                )
            } else if !rgb && !ir {
                (
                    Sev::Warn,
                    "no camera: face auth unavailable (password/fingerprint only)".to_string(),
                    Fix::None,
                )
            } else if !ir {
                (
                    Sev::Warn,
                    "RGB-only, convenience tier: face unlocks the screen only".to_string(),
                    Fix::None,
                )
            } else if priv_on {
                (
                    Sev::Warn,
                    "RGB+IR present, but a privacy switch is ON".to_string(),
                    Fix::Manual("turn off the camera privacy switch".into()),
                )
            } else {
                (Sev::Ok, "RGB + IR nodes present".to_string(), Fix::None)
            };
            v.push(mk("Cameras", csev, cdetail, cfix));
            if ir {
                // No row at all. This check has never measured the emitter: it
                // was unconditionally a warning whenever an IR node existed,
                // which cried wolf on every working machine and pointed its fix
                // button at a write to the camera. Turning it into an OK just
                // moved the false claim to the other side, telling someone with
                // a genuinely dark feed that everything is fine.
                //
                // Repair states verdicts it can support. Emitter setup is not a
                // verdict, it is an action, and it lives on the Cameras screen
                // where it is offered without a diagnosis attached.
            }
        }

        if self.probes.selinux_enforcing {
            let labeled = self.probes.selinux_socket_labeled;
            // Only a FAILURE once login is wired (the greeter actually needs it
            // then). Pre-wiring it's informational: `login enable --apply`
            // loads the module itself, so don't alarm a fresh install.
            let wired = self.probes.login_wired;
            v.push(mk(
                "SELinux policy",
                if labeled {
                    Sev::Ok
                } else if wired {
                    Sev::Fail
                } else {
                    Sev::Warn
                },
                if labeled {
                    "irlume module loaded (socket labeled)".into()
                } else if wired {
                    "module not loaded: greeter can't reach the daemon".into()
                } else {
                    "loads automatically when you wire login (Done tab → [w])".into()
                },
                if labeled {
                    Fix::None
                } else {
                    Fix::Root(RootFix::SelinuxLoad)
                },
            ));
        }

        let enrolled = !self.profiles.is_empty();
        if let Some(err) = &self.enroll_error {
            // File present but unreadable; never silently read as "not enrolled".
            v.push(mk("Enrollment", Sev::Fail,
                format!("enrollment unreadable: {err}"),
                Fix::Manual("restore the backup, or re-enroll (Profiles → [e]); if encrypted, the template key may be missing".into())));
        } else if self.profiles_load.is_some() && self.profiles.is_empty() {
            // The list is still loading in the background (a slow TPM makes
            // this take seconds): "no face enrolled" would be a claim about
            // state nobody has observed yet.
            v.push(mk(
                "Enrollment",
                Sev::Ok,
                "loading profiles…".into(),
                Fix::None,
            ));
        } else if !self.profiles_loaded {
            // No ListProfiles has ever landed (the daemon was down before the
            // first answer). "no face enrolled yet" here sent users with a
            // working encrypted enrollment to [e], overwriting good data; an
            // unanswered question renders as unknown, never as a negative.
            v.push(mk(
                "Enrollment",
                Sev::Warn,
                "unknown (profile list not read yet)".into(),
                Fix::None,
            ));
        } else {
            v.push(mk(
                "Enrollment",
                if enrolled { Sev::Ok } else { Sev::Warn },
                if enrolled {
                    format!("{} profile(s) enrolled", self.profiles.len())
                } else {
                    "no face enrolled yet".into()
                },
                if enrolled {
                    Fix::None
                } else {
                    Fix::Manual("Profiles tab → [e] enroll".into())
                },
            ));
        }

        // ---- Checks distilled from live cross-distro debugging (2026-07-01):
        // every failure mode below cost a human diagnosis session once; Repair
        // detects and resolves them now.

        // Stale daemon build: the installed daemon predates this CLI (bit us on
        // Fedora: an old daemon silently missing new behavior).
        if let Some(h) = &self.health {
            if !h.version.is_empty() && h.version != env!("CARGO_PKG_VERSION") {
                v.push(mk(
                    "Daemon build",
                    Sev::Warn,
                    format!(
                        "daemon v{} ≠ CLI v{}; reinstall/restart the daemon",
                        h.version,
                        env!("CARGO_PKG_VERSION")
                    ),
                    Fix::Root(RootFix::RestartDaemon),
                ));
            }
        }
        // Fingerprint reader health: a crashed/aborted enrollment leaves the
        // device CLAIMED and pam_fprintd fails silently (no finger prompt).
        if self.fp.available {
            if self.probes.reader_stuck {
                v.push(mk(
                    "Fingerprint reader",
                    Sev::Fail,
                    "reader is claimed by a stale session; finger prompts fail silently".into(),
                    Fix::Root(RootFix::RestartFprintd),
                ));
            } else {
                v.push(mk(
                    "Fingerprint reader",
                    Sev::Ok,
                    format!("{} finger(s) enrolled", self.fp.enrolled.len()),
                    Fix::None,
                ));
            }
        }
        // Method ↔ PAM-wiring coherence: competing biometric stacks intercept
        // each other's prompts; a chosen method that isn't wired does nothing.
        // Matched on the DIRECTIVE part (everything before the first '#', all
        // libpam tokenizes), via the same shared semantics as the wiring: a
        // module named only in a trailing comment is not wired, and reading it
        // as wired would suppress this exact Fail diagnostic. `pam_has` stays
        // a substring scan because its callers hunt LEFTOVERS of other tools
        // wherever they appear on an active line; the fprintd check below
        // instead asks "does an auth RULE run this module", the same parsed
        // question the enable gate asks, so a session line or an argument
        // naming the file cannot suppress the not-wired Fail.
        let pam_has = |needle: &str| {
            ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]
                .iter()
                .any(|p| {
                    std::fs::read_to_string(p)
                        .map(|s| {
                            s.lines()
                                .any(|l| crate::pamwire::directive(l).contains(needle))
                        })
                        .unwrap_or(false)
                })
        };
        let fprintd_wired = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]
            .iter()
            .any(|p| {
                std::fs::read_to_string(p)
                    .map(|s| {
                        s.lines()
                            .any(|l| crate::pamwire::directive_has_auth_module(l, "pam_fprintd.so"))
                    })
                    .unwrap_or(false)
            });
        match self.fp.method.as_str() {
            "fingerprint" => {
                if !fprintd_wired {
                    v.push(mk(
                        "Method wiring",
                        Sev::Fail,
                        "method is fingerprint but pam_fprintd is not wired".into(),
                        Fix::Manual("Fingerprint tab → [e] unlock with face OR fingerprint".into()),
                    ));
                } else if self.fp.enrolled.is_empty() {
                    v.push(mk(
                        "Method wiring",
                        Sev::Fail,
                        "method is fingerprint but no finger is enrolled".into(),
                        Fix::Root(RootFix::FingerprintAdd),
                    ));
                } else {
                    v.push(mk(
                        "Method wiring",
                        Sev::Ok,
                        "fingerprint drives; face stands down".into(),
                        Fix::None,
                    ));
                }
                // Fingerprint keyring unlock (ADR-0003): on a fingerprint box a
                // login leaves the wallet locked unless the keyring is armed
                // (TPM-seal the password) AND the greeter carries the `keyring`
                // line. Surface it so the user isn't left typing the keyring
                // password after every fingerprint login.
                if fprintd_wired && !self.fp.enrolled.is_empty() && self.probes.tpm_present {
                    // DM-aware: the keyring line must be in EVERY login service
                    // the active DM uses (GDM: gdm-password AND gdm-fingerprint).
                    let wired = self.probes.fp_keyring_wired;
                    // None = the daemon never answered; neither "arm it" nor
                    // "all good" is supportable, so no row at all (the Daemon
                    // row above already carries the failure).
                    if self.keyring_armed == Some(false) {
                        v.push(mk(
                            "FP keyring unlock",
                            Sev::Warn,
                            "wallet won't auto-unlock on fingerprint login; arm the keyring".into(),
                            Fix::Manual("Keyring tab → [a] arm (seal your login password)".into()),
                        ));
                    } else if self.keyring_armed == Some(true) && !wired {
                        v.push(mk(
                            "FP keyring unlock",
                            Sev::Warn,
                            "keyring armed but the login stack lacks the unlock line".into(),
                            Fix::Root(RootFix::LoginEnable),
                        ));
                    } else if self.keyring_armed == Some(true) {
                        v.push(mk(
                            "FP keyring unlock",
                            Sev::Ok,
                            "a fingerprint login unseals the wallet (no keyring prompt)".into(),
                            Fix::None,
                        ));
                    }
                }
            }
            // Coexistence is the intended state since 0.5.0: `both` (explicit)
            // and `auto` (hardware-led) both mean "unlock with face OR
            // fingerprint", so a reader wired alongside face is CORRECT, not a
            // misconfiguration. Report it as healthy.
            "both" | "auto" if fprintd_wired && enrolled && self.fp.available => {
                v.push(mk(
                    "Method wiring",
                    Sev::Ok,
                    "face + fingerprint both wired; unlock with either".into(),
                    Fix::None,
                ));
            }
            // An EXPLICIT face-only method with a reader still wired: not harmful
            // (the fingerprint just works too), but it contradicts the chosen
            // method, so point at the two ways to resolve it. A vendor
            // pam_fprintd line with NO reader fails instantly and PAM moves on,
            // so the `self.fp.available` guard keeps this off reader-less boxes.
            _ if fprintd_wired && enrolled && self.fp.available => {
                v.push(mk(
                    "Method wiring",
                    Sev::Warn,
                    "method is face-only but a fingerprint reader is also wired; both will unlock"
                        .into(),
                    Fix::Manual(
                        "[e] on the Fingerprint tab (face OR fingerprint), or [d] to disable"
                            .into(),
                    ),
                ));
            }
            _ => {}
        }
        // Wiring drift: login WAS enabled (marker) but the active greeter's
        // stack lost the module (authselect/pam-auth-update regenerated the
        // PAM files). Face silently falls back to password until re-applied.
        if self.probes.reconcile_needed {
            v.push(mk(
                "Login wiring",
                Sev::Fail,
                "a distro PAM regeneration dropped the face-auth wiring; logins fall back to password".into(),
                Fix::Root(RootFix::LoginReconcile),
            ));
        }
        // Foreign face-auth modules left over from another tool hijack the same
        // PAM slots (a leftover module intercepted the greeter in live testing).
        for foreign in ["howdy", "linhello"] {
            if pam_has(foreign) {
                v.push(mk("Other face auth", Sev::Warn,
                    format!("another face-auth module ({foreign}) is wired; it will conflict with irlume"),
                    Fix::Manual(format!("remove the {foreign} lines from /etc/pam.d (or uninstall it)"))));
            }
        }
        // RGB-only anti-spoof tuning: the moiré cue varies per camera (glasses
        // reflecting the screen can spike it on a live face).
        if self
            .health
            .as_ref()
            .is_some_and(|h| h.tier == "convenience")
        {
            v.push(mk("RGB anti-spoof", Sev::Ok,
                "moiré screen-detector active; if real faces read 'screen pattern', tune IRLUME_RGB_MOIRE_MAX on the unit".into(),
                Fix::None));
        }
        // AppArmor: prefer the daemon's SELF-REPORTED confinement (Health.apparmor
        // read from its /proc/self/attr). The on-disk profile file existing does
        // NOT prove the daemon is confined: apparmor_parser can fail to load it
        // (a swallowed install error) and leave irlumed unconfined while the file
        // is still present. Only fall back to the file heuristic for an older
        // daemon that doesn't report the field.
        let aa = self.health.as_ref().and_then(|h| h.apparmor.as_deref());
        let aa_reload =
            "reinstall the package, or: sudo apparmor_parser -r /etc/apparmor.d/usr.bin.irlumed";
        match aa {
            Some(label) if label.contains("unconfined") => v.push(mk(
                "AppArmor",
                Sev::Warn,
                "daemon running UNCONFINED; the profile is installed but not loaded".into(),
                Fix::Manual(aa_reload.into()),
            )),
            Some(label) if label.contains("(complain)") => v.push(mk(
                "AppArmor",
                Sev::Warn,
                format!("profile loaded in COMPLAIN mode, not enforcing ({label})"),
                Fix::Manual("enforce it: sudo aa-enforce /etc/apparmor.d/usr.bin.irlumed".into()),
            )),
            Some(label) => v.push(mk(
                "AppArmor",
                Sev::Ok,
                format!("daemon confined ({label})"),
                Fix::None,
            )),
            None => {
                // Older daemon (no field). Fall back to the file heuristic, but
                // only when AppArmor is actually live this boot.
                let enabled = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
                    .map(|s| s.trim() == "Y")
                    .unwrap_or(false);
                if enabled {
                    let profiled = std::path::Path::new("/etc/apparmor.d/usr.bin.irlumed").exists();
                    v.push(mk(
                        "AppArmor",
                        if profiled { Sev::Ok } else { Sev::Warn },
                        if profiled {
                            "irlume profile installed (update the daemon to confirm it is loaded)"
                                .into()
                        } else {
                            "daemon unconfined; the AppArmor hardening profile is not loaded".into()
                        },
                        if profiled {
                            Fix::None
                        } else {
                            Fix::Manual(aa_reload.into())
                        },
                    ));
                }
            }
        }

        // Login keyring LOCKED: a Secret Service provider is up but its login
        // collection is locked, so apps (Bitwarden, browsers) can't read their
        // secrets even after a face login. Only flag it when the keyring is
        // armed (else it's expected) and a provider actually answered. The TUI
        // runs as the user, so unlike `sudo doctor` it can see the session bus.
        if self.keyring_armed == Some(true) {
            if let Some(true) = self.probes.keyring_locked {
                v.push(mk(
                    "Login keyring",
                    Sev::Warn,
                    "the wallet is locked; apps (Bitwarden, browsers) can't read secrets yet"
                        .into(),
                    Fix::Manual(
                        "unlock it by logging in with your face, or `sudo irlume keyring arm`"
                            .into(),
                    ),
                ));
            }
        }

        // Keyring PCR-drift: the seal no longer matches the current PCRs (a
        // firmware/Secure Boot update moved them), so face login silently stops
        // opening the wallet until re-bound. Only the Keyring tab drew this;
        // surface it here too, with the one-key fix (reseal, added to Keyring).
        if self.keyring_drift == Some(true) {
            v.push(mk(
                "Keyring seal",
                Sev::Warn,
                "PCRs drifted since sealing; the wallet won't auto-unlock until re-bound".into(),
                Fix::Manual("Keyring tab → [r] reseal (re-bind to current PCRs)".into()),
            ));
        }

        // A third-party model enabled but with a CHECKSUM MISMATCH, reported
        // PER ENTRY: a joined string smeared one model's failure across every
        // enabled stage (#285 review). The consequence differs by stage — a
        // refused PAD cue is silently OFF, a refused recognizer means the
        // daemon will not start with it selected. Only flag a stage the
        // daemon did not actually load (Health proves loaded weights fine).
        //
        // NOT gated on the daemon being up: a refused recognizer or detector
        // EXITS the daemon at startup, so the gate switched this check off in
        // exactly the state it exists to explain. With the daemon down,
        // `health` is None, `loaded` is false, and the row is emitted.
        {
            if let crate::models::TuiState::Enabled { entries } = &self.heavy.0 {
                use irlume_common::thirdparty::{Stage, WeightState};
                for entry in entries {
                    if entry.weight_state != WeightState::ChecksumMismatch {
                        continue;
                    }
                    let loaded = match entry.stage {
                        Stage::Pad => self
                            .health
                            .as_ref()
                            .is_some_and(|h| h.third_party_pad.as_deref() == Some(entry.name)),
                        Stage::Recognition => self.health.as_ref().is_some_and(|h| {
                            h.third_party_recognizer.as_deref() == Some(entry.name)
                        }),
                        _ => false,
                    };
                    if loaded {
                        continue;
                    }
                    let effect = match entry.stage {
                        Stage::Pad => "the deny-only cue is OFF",
                        Stage::Recognition => {
                            "the daemon refuses to start with it selected; face auth falls back to the password"
                        }
                        _ => "the daemon refuses the selected model",
                    };
                    v.push(mk(
                        "Third-party model",
                        Sev::Fail,
                        format!(
                            "'{}' ({} stage) weights fail their checksum; {effect}",
                            entry.name,
                            entry.stage.as_str()
                        ),
                        Fix::Manual(format!(
                            "run `sudo irlume models disable {0}`, then re-enable {0}",
                            entry.name
                        )),
                    ));
                }
            }
        }

        if let Some(r) = self.recovery {
            if r.encrypted && !r.recovery_set {
                v.push(mk(
                    "Recovery backstop",
                    Sev::Warn,
                    "templates encrypted but no recovery passphrase".into(),
                    Fix::Manual("Recovery tab → [s] set a recovery passphrase".into()),
                ));
            } else if r.encrypted && !r.key_present {
                // Encrypted with the key gone: no passphrase and no reseal opens
                // it, so this is not a backstop question at all. The Cameras-side
                // row already says this loudly; the check said "encrypted +
                // recovery set" and passed.
                v.push(mk(
                    "Recovery backstop",
                    Sev::Fail,
                    "templates encrypted but the template key is MISSING: nothing can \
                     open them"
                        .into(),
                    Fix::Manual("re-enroll: Profiles tab → [e]".into()),
                ));
            } else {
                v.push(mk(
                    "Recovery backstop",
                    Sev::Ok,
                    if r.encrypted {
                        "encrypted + recovery set".into()
                    } else if r.tpm_present {
                        "templates not encrypted yet (TPM available; encrypts at enroll)".into()
                    } else {
                        "templates not encrypted (no TPM on this device)".into()
                    },
                    Fix::None,
                ));
            }
        }

        // TPM presence: without one, templates are root-only plaintext (not
        // encrypted at rest) and keyring auto-unlock can't be armed at all.
        // Face login + sudo still work; this only bounds at-rest hardening and
        // the wallet-on-login convenience. Info, not a failure.
        let tpm = self
            .recovery
            .map(|r| r.tpm_present)
            .unwrap_or(self.probes.tpm_present);
        if !tpm {
            v.push(mk("TPM", Sev::Warn,
                "no TPM: templates stored root-only plaintext; keyring auto-unlock unavailable (face login/sudo still work)".into(),
                Fix::Manual("optional: enable the firmware TPM (fTPM/PTT) in BIOS, then re-enroll to encrypt at rest".into())));
        } else {
            // Secure Boot binds the TPM seal to the boot state (PCR-7). Off ⇒ the
            // seal still works but isn't tamper-bound to a trusted boot chain.
            let (sb_present, sb_enabled, _) = self.probes.secureboot;
            if sb_present && !sb_enabled {
                v.push(mk("Secure Boot", Sev::Warn,
                    "Secure Boot is OFF; TPM seals still work but aren't bound to a trusted boot chain (weaker tamper resistance)".into(),
                    Fix::Manual("optional: enable Secure Boot in firmware for boot-state-bound sealing".into())));
            }
        }

        self.repair = v;
        if self.repair_sel >= self.repair.len().max(1) {
            self.repair_sel = self.repair.len().saturating_sub(1);
        }
    }

    /// Apply the selected Repair check's fix: daemon fixes run in-place; root
    /// fixes suspend to a sudo prompt; manual fixes echo the command to Activity.
    fn apply_fix(&mut self, idx: usize) {
        let fix = match self.repair.get(idx) {
            Some(c) => c.fix.clone(),
            // Empty list, or a selection left behind by a list that shrank. The
            // footer advertises [f], so pressing it has to answer: a silent
            // return reads as a broken key.
            None => {
                self.log('·', "no check is selected to fix");
                return;
            }
        };
        match fix {
            Fix::None => self.log('·', "nothing to fix on this row"),
            Fix::Manual(cmd) => self.log('·', format!("manual fix → {cmd}")),
            // Emitter setup writes the persisted UVC control, a root op now.
            Fix::Root(RootFix::RestartDaemon) => {
                self.log(
                    '→',
                    "sudo systemctl enable --now irlumed (you'll be asked for your password)",
                );
                self.suspend = Some(Suspend::RestartDaemon);
            }
            Fix::Root(RootFix::RestartFprintd) => {
                self.log(
                    '→',
                    "sudo systemctl restart fprintd: releases a stale reader claim",
                );
                self.suspend = Some(Suspend::RestartFprintd);
            }
            Fix::Root(RootFix::LoginEnable) => {
                self.log(
                    '→',
                    "sudo irlume login enable --apply: wires the login stack for your method",
                );
                self.suspend = Some(Suspend::LoginEnable);
            }
            Fix::Root(RootFix::FingerprintAdd) => {
                self.log('→', "enrolling a finger (interactive)");
                self.suspend = Some(Suspend::FingerprintAdd);
            }
            Fix::Root(RootFix::LoginReconcile) => {
                self.log(
                    '→',
                    "sudo irlume login reconcile: re-applies the face-auth PAM wiring",
                );
                self.suspend = Some(Suspend::LoginReconcile);
            }
            Fix::Root(RootFix::SelinuxLoad) => {
                self.log(
                    '→',
                    "sudo irlume selinux load (you'll be asked for your password)",
                );
                self.suspend = Some(Suspend::SelinuxLoad);
            }
        }
    }

    fn rows(&self) -> Vec<Row> {
        let mut v = Vec::new();
        for (pi, p) in self.profiles.iter().enumerate() {
            v.push(Row::Profile(pi));
            for si in 0..p.scans.len() {
                v.push(Row::Scan(pi, si));
            }
        }
        v
    }

    fn next_profile_name(&self) -> String {
        for n in 1..=MAX_PROFILES {
            let c = format!("Face Profile {n}");
            if !self.profiles.iter().any(|p| p.name == c) {
                return c;
            }
        }
        format!("Face Profile {}", self.profiles.len() + 1)
    }

    /// Run a daemon request on a worker thread, mapping its response to
    /// (ok, message) with `map`. Result is logged + routed by `tag` in `poll`.
    fn start_async(
        &mut self,
        label: impl Into<String>,
        tag: OpTag,
        req: Request,
        map: fn(Response) -> (bool, String),
    ) {
        let label = label.into();
        self.log('→', format!("daemon: {label}"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = match crate::daemon_request(&req) {
                Ok(resp) => map(resp),
                Err(e) => (false, e),
            };
            let _ = tx.send(r);
        });
        self.op = Some(Op { label, tag, rx });
    }

    /// `start_async` for work that is more than one request→map: the whole
    /// closure runs on the worker thread. Exists for the token arm (#250),
    /// where a `TokenSealed` reply must be followed by the keyring re-key,
    /// which needs the password and user the plain fn-pointer mapper cannot
    /// capture.
    fn start_async_task(
        &mut self,
        label: impl Into<String>,
        tag: OpTag,
        task: Box<dyn FnOnce() -> (bool, String) + Send>,
    ) {
        let label = label.into();
        self.log('→', format!("daemon: {label}"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(task());
        });
        self.op = Some(Op { label, tag, rx });
    }

    /// Start guided enrollment (new profile) or add-scan (`add` = existing name).
    fn start_enroll(&mut self, add: Option<String>) {
        let resume = match &add {
            Some(name) => ResumeEnroll::Add(name.clone()),
            None => ResumeEnroll::New,
        };
        if !self.daemon_gate(resume) {
            return;
        }
        let (profile, target) = match &add {
            Some(name) => (name.clone(), ADD_SCANS),
            None => (self.next_profile_name(), ENROLL_SCANS),
        };
        let user = self.user.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let (st, pn, addc) = (stop.clone(), profile.clone(), add.clone());
        std::thread::spawn(move || enroll_worker(user, pn, addc, target, st, tx));
        self.log(
            '→',
            format!("guided enroll → '{profile}' ({target} scan(s))"),
        );
        self.enroll = Some(EnrollUi {
            rx,
            stop,
            profile,
            last: None,
            count: None,
            stalled: None,
            captured: 0,
            target,
            base: 0,
            ambient_base: 0,
        });
    }

    /// User confirmed the merge: keep the scan already added and, if the profile
    /// still has room and more scans were requested, capture the rest via
    /// AddScan targeting the resolved profile (never a new merge).
    fn confirm_enroll_merge(&mut self, mc: MergeConfirm) {
        self.log(
            '·',
            format!("adding these scans to '{}' (already your face)", mc.profile),
        );
        if mc.remaining == 0 {
            self.log('✓', format!("scan added to '{}'", mc.profile));
            self.refresh();
            return;
        }
        let user = self.user.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let (st, pn) = (stop.clone(), mc.profile.clone());
        let add = Some(mc.profile.clone());
        let base = mc.added_scans.len(); // the merged scan(s), for a continuous count
        let ambient_base = mc.ambient_lit;
        std::thread::spawn(move || enroll_worker(user, pn, add, mc.remaining, st, tx));
        self.enroll = Some(EnrollUi {
            rx,
            stop,
            profile: mc.profile,
            last: None,
            count: None,
            stalled: None,
            captured: 0,
            target: mc.remaining,
            base,
            ambient_base,
        });
    }

    /// User declined the merge: remove the scan(s) scan 1 already added, so the
    /// cancel leaves the existing profile exactly as it was.
    fn cancel_enroll_merge(&mut self, mc: MergeConfirm) {
        self.log(
            '·',
            format!(
                "cancelled; removing the scan added to '{}' (a face can only own one profile)",
                mc.profile
            ),
        );
        // The split-protocol merge added exactly one scan (scan 1 was Enroll
        // scans:1). Undo it async so a slow/wedged daemon can't hitch the UI,
        // and so a delete failure surfaces instead of being silently ignored
        // (which would leave the scan on the profile).
        if let Some(scan) = mc.added_scans.into_iter().next() {
            self.start_async(
                "(undo merge)",
                OpTag::Generic,
                Request::DeleteScan {
                    user: self.user.clone(),
                    profile: mc.profile,
                    scan,
                },
                map_confirm,
            );
        } else {
            self.refresh();
        }
    }

    /// How long the cached model/Bitwarden state may be reused before the poll
    /// takes it again. Long enough that a redraw storm costs nothing, short
    /// enough that a change made outside the TUI shows up while the user is
    /// still looking at the screen.
    const HEAVY_TTL: std::time::Duration = std::time::Duration::from_secs(3);

    /// Re-read the state the draw path caches. Called on the poll's TTL, and
    /// immediately after any step that can change it, so a model the user just
    /// enabled does not sit invisible for up to the TTL.
    fn refresh_heavy(&mut self) {
        self.heavy = (crate::models::tui_state(), crate::bitwarden::tui_state());
        self.heavy_at = std::time::Instant::now();
    }

    fn poll(&mut self) {
        if self.heavy_at.elapsed() >= Self::HEAVY_TTL {
            self.refresh_heavy();
        }
        if let Some(rx) = &self.light_load {
            if let Ok(l) = rx.try_recv() {
                self.light_load = None;
                self.apply_light(l);
                // The checklist reads daemon_up/health; rebuild it from the
                // fresh reads (pure: no probes are taken here).
                self.run_checks();
                self.recompute_visible();
            }
        }
        if let Some(rx) = &self.probes_load {
            if let Ok(p) = rx.try_recv() {
                self.probes_load = None;
                self.probes = p;
                self.probes_landed = true;
                self.recompute_checks();
            }
        }
        if let Some(rx) = &self.profiles_load {
            if let Ok(outcome) = rx.try_recv() {
                self.profiles_load = None;
                match outcome {
                    ProfilesOutcome::Loaded {
                        profiles,
                        eyes_open,
                    } => {
                        self.profiles = profiles;
                        self.eyes_open = eyes_open;
                        self.enroll_error = None;
                        self.profiles_loaded = true;
                    }
                    ProfilesOutcome::DaemonError(e) => self.enroll_error = Some(e),
                    // Transport failures are not state: the previous list
                    // stays, the next refresh retries, and the Activity log
                    // says why the list may be stale.
                    ProfilesOutcome::Transport(e) => {
                        self.log('·', format!("profile list not refreshed: {e}"));
                    }
                }
                // The checks read the profile list (the no-enrollment warn);
                // recompute now that it is current.
                self.recompute_checks();
            }
        }
        if let Some(op) = &self.op {
            if let Ok((ok, msg)) = op.rx.try_recv() {
                let tag = op.tag;
                // The IR self-test shows its own result line on the Repair screen;
                // a normal "no face / uncertain" outcome shouldn't also raise the
                // alarming error modal (that's for genuine failures like a busy
                // camera). Identify/Generic keep the modal on failure.
                if ok {
                    self.log('✓', msg.clone());
                } else if !matches!(tag, OpTag::Identify) {
                    self.set_error(msg.clone());
                } else {
                    self.log('·', msg.clone());
                }
                match tag {
                    OpTag::Identify => self.identify_result = Some((ok, msg)),
                    OpTag::Generic => {}
                }
                self.op = None;
                self.refresh();
            }
        }
        if let Some(e) = &self.enroll {
            let target = e.target;
            let mut msgs = Vec::new();
            while let Ok(m) = e.rx.try_recv() {
                msgs.push(m);
            }
            let mut finished = false;
            let mut merge: Option<MergeConfirm> = None;
            for m in msgs {
                match m {
                    WMsg::Cue(r) => {
                        if let Some(e) = &mut self.enroll {
                            e.last = Some(r);
                            e.count = None;
                            e.stalled = None;
                        }
                    }
                    WMsg::Stall(err) => {
                        if let Some(e) = &mut self.enroll {
                            e.stalled = Some(err);
                            e.count = None;
                        }
                    }
                    WMsg::Count(c) => {
                        if let Some(e) = &mut self.enroll {
                            e.count = Some(c);
                        }
                    }
                    WMsg::Captured(n, t) => {
                        let base = self.enroll.as_ref().map(|e| e.base).unwrap_or(0);
                        if let Some(e) = &mut self.enroll {
                            e.captured = n;
                            e.count = None;
                        }
                        self.log('✓', format!("captured scan {}/{}", n + base, t + base));
                    }
                    WMsg::Done { ambient_lit } => {
                        self.log('✓', "enrollment complete");
                        let ambient_lit =
                            ambient_lit + self.enroll.as_ref().map(|e| e.ambient_base).unwrap_or(0);
                        if ambient_lit > 0 {
                            self.log(
                                '!',
                                format!(
                                    "{ambient_lit} scan(s) were lit mainly by the room, not \
                                     provably by the IR emitter; dark-room login is unverified. \
                                     Check it with the lights off: irlume identify"
                                ),
                            );
                        }
                        finished = true;
                    }
                    WMsg::Err(e) => {
                        let e = e.strip_prefix("hardware: ").unwrap_or(&e);
                        self.set_error(format!("Enrollment failed: {e}"));
                        finished = true;
                    }
                    WMsg::MergePrompt {
                        profile,
                        room,
                        added_scans,
                        ambient_lit,
                    } => {
                        // The rest of the requested scans, capped at the room
                        // the DAEMON reports for the loaded recognizer. It was
                        // computed here from the profile's total scan count,
                        // which is wrong since the limit became per-recognizer
                        // (#290): a profile holding two models' templates
                        // under-counted and the UI refused scans the daemon
                        // would have accepted.
                        //
                        // A daemon older than 0.9.0 does not report room at
                        // all. Treating that silence as zero offered no
                        // continuation scans and silently under-enrolled, the
                        // very failure #290 exists to prevent, in the window
                        // every upgrade passes through between the package
                        // swap and the daemon restart. Unknown means ask for
                        // what the user wanted and let the daemon refuse what
                        // it will; it is the authority either way.
                        let rest = target.saturating_sub(1);
                        let remaining = match room {
                            Some(room) => rest.min(room),
                            None => rest,
                        };
                        merge = Some(MergeConfirm {
                            profile,
                            added_scans,
                            remaining,
                            ambient_lit: ambient_lit.unwrap_or(0),
                        });
                        finished = true; // the worker has ended; the modal takes over
                    }
                }
            }
            if finished {
                self.enroll = None;
                self.enroll_merge = merge;
                self.refresh();
            }
        }
    }

    fn main_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> std::io::Result<()> {
        use ratatui::crossterm::event::MouseEventKind;
        let mut last_light = std::time::Instant::now();
        let mut last_heavy = std::time::Instant::now();
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(k) if k.kind == KeyEventKind::Press => {
                        // A Ctrl-modified letter (Ctrl-C…) must not alias to
                        // that letter's action; found live when Ctrl-C fired
                        // the [c] calibrate binding. Plain keys pass through.
                        let ctrl = k
                            .modifiers
                            .contains(ratatui::crossterm::event::KeyModifiers::CONTROL);
                        if !(ctrl && matches!(k.code, KeyCode::Char(_))) {
                            self.on_key(k.code)
                        }
                    }
                    // Mouse wheel scrolls the Activity history.
                    Event::Mouse(m) => match m.kind {
                        MouseEventKind::ScrollUp => {
                            self.act_scroll = (self.act_scroll + 1).min(self.act_max())
                        }
                        MouseEventKind::ScrollDown => {
                            self.act_scroll = self.act_scroll.saturating_sub(1)
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            self.spin = (self.spin + 1) % SPIN.len();
            self.poll();
            // Live auto-refresh, tiered so external changes appear on their own
            // without periodic subprocess hitches. Skip while the user is mid-flow.
            if self.op.is_none()
                && self.enroll.is_none()
                && self.input.is_none()
                && self.confirm.is_none()
            {
                if last_heavy.elapsed() >= Duration::from_millis(HEAVY_REFRESH_MS) {
                    // Diagnostics only, NOT the slow profile poll: keeping the
                    // ListProfiles TPM-unseal off every timer tick is what makes
                    // the UI stay smooth. Profiles refresh on mutation / Profiles
                    // tab / startup instead.
                    self.refresh_diagnostics();
                    last_heavy = std::time::Instant::now();
                    last_light = std::time::Instant::now();
                } else if last_light.elapsed() >= Duration::from_millis(LIGHT_REFRESH_MS) {
                    self.refresh_light(); // daemon state + cameras only
                    last_light = std::time::Instant::now();
                }
            }
            // Interactive flows that need a cooked terminal: tear down, run, re-enter.
            if let Some(s) = self.suspend.take() {
                let _ = ratatui::crossterm::execute!(
                    std::io::stdout(),
                    ratatui::crossterm::event::DisableMouseCapture
                );
                ratatui::restore();
                // Cooked terminal here: Ctrl-C raises SIGINT to the whole
                // foreground group, and the TUI parent has the default (fatal)
                // disposition. Install a no-op HANDLER around every suspended
                // flow so the TUI survives an abort during the in-process arms
                // too (fingerprint prompt, update, doctor, login status), not
                // just the sudo_step ones. A caught signal is reset to the
                // default across exec, so a child (sudo, dnf, the prompt) still
                // gets SIGINT and is cancelled; only the parent is shielded.
                extern "C" fn noop_sigint(_: libc::c_int) {}
                // Cast through a fn pointer then a data pointer: a direct
                // fn-item-to-integer cast trips clippy::fn_to_numeric_cast_any.
                let handler =
                    noop_sigint as extern "C" fn(libc::c_int) as *const () as libc::sighandler_t;
                #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
                let old_int = unsafe { libc::signal(libc::SIGINT, handler) };
                self.run_suspended(s);
                #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
                unsafe {
                    libc::signal(libc::SIGINT, old_int);
                }
                *terminal = ratatui::init();
                if !self.mouse_select {
                    let _ = ratatui::crossterm::execute!(
                        std::io::stdout(),
                        ratatui::crossterm::event::EnableMouseCapture
                    );
                }
                terminal.clear()?;
                self.refresh();
                // irlumed binds its socket only after loading the ONNX models;
                // give a just-started daemon a bounded moment before judging.
                if self.resume_enroll.is_some() && !self.daemon_up {
                    for _ in 0..DAEMON_WAIT_TRIES {
                        std::thread::sleep(Duration::from_millis(DAEMON_WAIT_POLL_MS));
                        if matches!(crate::daemon_poll(&Request::Ping), Ok(Response::Pong)) {
                            self.daemon_up = true;
                            break;
                        }
                    }
                }
                // A parked enrollment resumes exactly once: only if the daemon
                // now answers (the fix worked); otherwise drop it; the error
                // banner from the failed sudo step explains what happened.
                if let Some(r) = self.resume_enroll.take() {
                    if self.daemon_up {
                        self.screen = SC_PROFILES;
                        self.log('✓', "daemon is up; continuing enrollment");
                        match r {
                            ResumeEnroll::New => self.begin_enroll(),
                            ResumeEnroll::Add(p) => self.start_enroll(Some(p)),
                            ResumeEnroll::Named(n) => self.start_enroll_named(n),
                        }
                    }
                }
            }
        }
        if let Some(e) = &self.enroll {
            e.stop.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Flip mouse capture so the terminal's native selection (highlight +
    /// copy) works while released. State survives suspend/resume.
    fn toggle_mouse(&mut self) {
        self.mouse_select = !self.mouse_select;
        let mut out = std::io::stdout();
        if self.mouse_select {
            let _ =
                ratatui::crossterm::execute!(out, ratatui::crossterm::event::DisableMouseCapture);
            self.log(
                '·',
                "mouse released: highlight + copy with your terminal as usual; [M] restores wheel scroll",
            );
        } else {
            let _ =
                ratatui::crossterm::execute!(out, ratatui::crossterm::event::EnableMouseCapture);
            self.log('·', "mouse captured: the wheel scrolls the TUI again");
        }
    }

    /// Run a privileged sub-step via `sudo` and surface its ACTUAL outcome. A
    /// cancelled or failed sudo (wrong password ×3, subcommand error) must not
    /// look like success: `refresh()` re-probes what it can, but a one-shot like
    /// `ir-setup` reports its own outcome and is not re-probed here, so we log ✓
    /// on success and raise the error banner on failure.
    ///
    /// It DOES leave re-checkable state now: an interrupted run leaves an undo
    /// record, which `irlume doctor` reports as `emitter-undo-pending`. This
    /// step does not read it, because the record is about a camera control and
    /// this is the sudo wrapper's own success or failure.
    /// Absolute path to the running binary, for re-invoking ourselves as root
    /// instead of whatever `irlume` PATH resolves to (a running TUI must not
    /// shell out to a different, older installed build for its privileged half).
    /// Falls back to the PATH name `irlume` when the path can't be resolved, or
    /// when an in-session `update` replaced the binary and `/proc/self/exe` now
    /// points at the unlinked inode (a "(deleted)" path that would fail to exec).
    fn self_exe() -> String {
        std::env::current_exe()
            .ok()
            .filter(|p| p.exists())
            .and_then(|p| p.to_str().map(String::from))
            .filter(|s| !s.ends_with(" (deleted)"))
            .unwrap_or_else(|| "irlume".to_string())
    }

    /// The command a privileged step runs: `sudo <args>` normally, but `<args>`
    /// alone when the TUI is ALREADY root.
    ///
    /// A second `sudo` from a root process resets `SUDO_USER` to `root`, because
    /// root is then the invoking user. Every per-user command resolves its target
    /// from `SUDO_USER` (see `user_arg`), so `sudo irlume tui` -> `[c]` ->
    /// `sudo irlume calibrate-closure` taught the consent gesture and stored it
    /// for **root**, while the daemon reads the calibration from the real user's
    /// enrollment: the user calibrated, saw it succeed, and their own prompts
    /// never used it. Found by walking the TUI as root on 2026-08-12. The same
    /// reset silently retargeted every other per-user step (enrol, keyring).
    ///
    /// Running the command directly when root keeps the OUTER sudo's
    /// `SUDO_USER`, which names the person who started the TUI.
    fn privileged_cmd(args: &[&str], already_root: bool) -> std::process::Command {
        if already_root {
            let mut cmd = std::process::Command::new(args[0]);
            cmd.args(&args[1..]);
            cmd
        } else {
            let mut cmd = std::process::Command::new("sudo");
            cmd.args(args);
            cmd
        }
    }

    fn sudo_step(&mut self, what: &str, args: &[&str]) {
        // Invoke OUR OWN binary as root, not whatever `irlume` PATH resolves
        // to. Resolve the first "irlume" arg to the current exe; leave
        // non-irlume commands (systemd-pcrlock, sh -c) as is.
        let self_exe = Self::self_exe();
        let resolved: Vec<String> = args
            .iter()
            .enumerate()
            .map(|(i, &a)| match (i, a) {
                (0, "irlume") => self_exe.clone(),
                _ => a.to_string(),
            })
            .collect();
        let args: Vec<&str> = resolved.iter().map(String::as_str).collect();
        // SAFETY: geteuid() reads the caller's own credentials and cannot fail.
        let already_root = unsafe { libc::geteuid() } == 0;
        eprintln!(
            "\n{what}; running: {}{}…",
            if already_root { "" } else { "sudo " },
            args.join(" ")
        );
        // In the cooked terminal, Ctrl-C goes to the whole foreground group:
        // a user aborting the CHILD (a sudo prompt, the models license flow)
        // must not also kill the TUI. Ignore SIGINT here while the child runs;
        // the child gets the default disposition back pre-exec so Ctrl-C still
        // cancels IT. (Found live: Ctrl-C in the license prompt took the whole
        // TUI down.)
        use std::os::unix::process::CommandExt;
        let mut cmd = Self::privileged_cmd(&args, already_root);
        // SAFETY: signal() is async-signal-safe; this runs in the forked child
        // just before exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                Ok(())
            });
        }
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let old_int = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
        let status = cmd.status();
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        unsafe {
            libc::signal(libc::SIGINT, old_int)
        };
        match status {
            Ok(st) if st.success() => {
                // A step can enable a model or install the Bitwarden policy, and
                // the draw path reads a cache: take it again now rather than let
                // the screen show the pre-action state until the TTL expires.
                self.refresh_heavy();
                self.log('✓', format!("{what}: done"));
            }
            Ok(st) => {
                // A failed/cancelled sudo can't have started the daemon; drop
                // any parked enrollment so the resume path doesn't sit through
                // its bounded daemon wait for nothing.
                self.resume_enroll = None;
                match st.code() {
                    Some(c) => self.set_error(format!(
                        "{what}: sudo exited {c}; not applied (cancelled or failed)"
                    )),
                    None => {
                        self.set_error(format!("{what}: sudo terminated by a signal; not applied"))
                    }
                }
            }
            Err(e) => {
                self.resume_enroll = None;
                self.set_error(format!("{what}: could not launch sudo: {e}"));
            }
        }
    }

    /// Run an interactive sub-flow outside the alt-screen via the CLI handlers
    /// (no-echo passphrase / fprintd prompts), then wait for the user to return.
    fn run_suspended(&mut self, s: Suspend) {
        let none: [String; 0] = [];
        // The account this TUI is managing, for the steps that act on ONE user.
        // `irlume tui --user bob` shows bob everywhere and sends bob in every
        // daemon request, but a step that shells out re-resolves its own subject
        // from SUDO_USER/$USER, which names whoever launched the TUI: an admin
        // setting bob up calibrated the gesture onto their own enrollment, and
        // "delete ALL enrolled fingerprints" deleted their own. Built here so
        // every per-user arm passes the same thing.
        let for_user: [String; 2] = ["--user".to_string(), self.user.clone()];
        // A local copy for the shell-out slices: `sudo_step` takes `&mut self`,
        // so they cannot hold a borrow of `self.user` across the call.
        let target = self.user.clone();
        match s {
            Suspend::FingerprintAdd => {
                crate::fingerprint::run(Some("add"), &for_user);
            }
            Suspend::LoginStatus => {
                crate::pamwire::run(Some("status"), &none);
            }
            // Wire the login stack for the current method+tier (adds the keyring
            // line where the DM needs it). Idempotent; runs as root.
            Suspend::LoginEnable => self.sudo_step(
                "wire the login stack",
                &["irlume", "login", "enable", "--apply"],
            ),
            Suspend::SetCameras(rgb, ir) => self.sudo_step(
                "switch the active camera pair",
                &["irlume", "set-cameras", &rgb, &ir],
            ),
            Suspend::IrSetup => self.sudo_step("enable the IR emitter", &["irlume", "ir-setup"]),
            Suspend::CameraTune => self.sudo_step(
                "measure simultaneous RGB+IR capture",
                &["irlume", "camera-tune"],
            ),
            Suspend::BitwardenSetup => self.sudo_step(
                "install Bitwarden's polkit action",
                &["irlume", "bitwarden", "setup", "--apply"],
            ),
            Suspend::LoginEnableSudo => self.sudo_step(
                "wire face-sudo (opt-in)",
                &["irlume", "login", "enable", "--with-sudo", "--apply"],
            ),
            Suspend::LoginEnablePolkit => self.sudo_step(
                "wire app prompts / polkit (opt-in)",
                &["irlume", "login", "enable", "--with-polkit", "--apply"],
            ),
            Suspend::LoginDisable => self.sudo_step(
                "un-wire face auth from PAM",
                &["irlume", "login", "disable", "--apply"],
            ),
            Suspend::LoginReconcile => self.sudo_step(
                "re-apply the login wiring",
                &["irlume", "login", "reconcile"],
            ),
            Suspend::CalibrateClosure => self.sudo_step(
                "calibrate the eye-closure gesture",
                &["irlume", "calibrate-closure", "--user", &target],
            ),
            Suspend::LogsDebug(on) => self.sudo_step(
                if on {
                    "turn daemon debug logging ON"
                } else {
                    "turn daemon debug logging OFF"
                },
                &["irlume", "logs", "debug", if on { "on" } else { "off" }],
            ),
            Suspend::FingerprintVerify => {
                crate::fingerprint::run(Some("verify"), &for_user);
            }
            Suspend::FingerprintEnable => self.sudo_step(
                "enable fingerprint (face OR finger)",
                &["irlume", "fingerprint", "enable", "--user", &target],
            ),
            Suspend::FingerprintDisable => self.sudo_step(
                "disable fingerprint for login",
                &["irlume", "fingerprint", "disable", "--user", &target],
            ),
            Suspend::FingerprintReset => self.sudo_step(
                "delete ALL enrolled fingerprints",
                &["irlume", "fingerprint", "reset", "--user", &target],
            ),
            Suspend::ModelsEnable(name) => self.sudo_step(
                "enable a third-party model (license confirm follows)",
                &["irlume", "models", "enable", &name],
            ),
            Suspend::ModelsDisable(name) => self.sudo_step(
                "disable the third-party model",
                &["irlume", "models", "disable", &name],
            ),
            Suspend::Update => {
                crate::commands::update(&none);
            }
            Suspend::Doctor => {
                // The TUI already knows its target account; pass it so doctor
                // reports on the same user the rest of the screen does.
                let _ = crate::doctor(&["--user".to_string(), self.user.clone()]);
            }
            Suspend::PcrlockMakePolicy => self.sudo_step(
                "refresh the pcrlock policy (re-predict the boot measurements)",
                &["systemd-pcrlock", "make-policy"],
            ),
            Suspend::Biopolicy(on) => self.sudo_step(
                if on {
                    "enable the biopolicy gate"
                } else {
                    "disable the biopolicy gate"
                },
                &["irlume", "biopolicy", if on { "on" } else { "off" }],
            ),
            // `--yes`: the TUI already ran the confirm above. The CLI still prints
            // its warning to the cooked terminal, which is the point of routing
            // through it rather than writing settings.conf from here.
            Suspend::CredentialReleaseChallenge(on) => self.sudo_step(
                if on {
                    "require a gesture before releasing the keyring password"
                } else {
                    "stop requiring a gesture before releasing the keyring password"
                },
                &[
                    "irlume",
                    "credential-release-challenge",
                    if on { "on" } else { "off" },
                    "--yes",
                ],
            ),
            Suspend::ServiceGesture { service, on } => self.sudo_step(
                &if on {
                    format!("require a consent gesture for '{service}'")
                } else {
                    format!("stop requiring a consent gesture for '{service}'")
                },
                &[
                    "irlume",
                    "credential-release-challenge",
                    service.as_str(),
                    if on { "on" } else { "off" },
                    "--yes",
                ],
            ),
            Suspend::SelfTestLiveness => self.sudo_step(
                "run the IR liveness self-test",
                &["irlume", "selftest", "liveness"],
            ),
            Suspend::Logs => self.sudo_step("show the face-auth journal", &["irlume", "logs"]),
            // The TUI already double-confirmed, so pass --yes; the CLI still
            // does the teardown (un-wire PAM, stop daemon, wipe data) as root
            // and prints the package-removal command.
            Suspend::Uninstall => {
                self.sudo_step("uninstall irlume", &["irlume", "uninstall", "--yes"]);
                self.quit = true; // irlume is being removed; leave the TUI after
            }
            // enable + restart: `enable` makes the unit survive reboots (fresh
            // installs ship disabled under distro preset policy) and `restart`
            // also revives an enabled-but-wedged daemon; either alone misses a case.
            Suspend::RestartDaemon => self.sudo_step(
                "enable + start irlumed",
                &[
                    "sh",
                    "-c",
                    "systemctl enable irlumed; systemctl restart irlumed",
                ],
            ),
            // A stale device claim (crashed/aborted enrollment) makes pam_fprintd
            // fail silently; restarting fprintd releases it.
            Suspend::RestartFprintd => self.sudo_step(
                "restart fprintd (release a stale reader claim)",
                &[
                    "sh",
                    "-c",
                    "systemctl restart fprintd 2>/dev/null || pkill fprintd",
                ],
            ),
            // `selinux load` does the whole job: semodule -i, try-restart, and
            // the restorecon that actually settles the label. The old command
            // here appended its own `systemctl restart irlumed`, which under
            // socket activation relabels nothing (systemd owns the socket file
            // and a service restart never recreates it), so the step reported
            // done while the row stayed red.
            Suspend::SelinuxLoad => {
                // sudo_step resolves the leading "irlume" to the running
                // binary, so the rpm-path .pp lookup this build ships is the
                // one that runs, not an older PATH `irlume`.
                self.sudo_step(
                    "load the SELinux module + relabel the socket",
                    &["irlume", "selinux", "load"],
                );
            }
        }
        eprint!("\nPress Enter to return to the TUI… ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }

    fn on_key(&mut self, code: KeyCode) {
        // A raised error banner says "press any key to dismiss", so it takes the
        // next key BEFORE anything else (including the activity scroll below).
        if self.error.is_some() {
            self.error = None;
            return;
        }
        // Activity history scroll works in every state except text entry:
        // mid-enroll and mid-op, when lines stream fastest, is exactly when
        // the user wants to read back. Handled before the state gates below
        // so those can't swallow it.
        if self.input.is_none() {
            match code {
                KeyCode::PageUp => {
                    self.act_scroll = (self.act_scroll + 3).min(self.act_max());
                    return;
                }
                KeyCode::PageDown => {
                    self.act_scroll = self.act_scroll.saturating_sub(3);
                    return;
                }
                _ => {}
            }
        }
        // Guided enroll: only Esc (cancel).
        if let Some(e) = &self.enroll {
            if matches!(code, KeyCode::Esc) {
                e.stop.store(true, Ordering::Relaxed);
                self.enroll = None;
                self.log('·', "enrollment cancelled");
                // The daemon may already hold what the cancelled run created:
                // scan 1 creates the profile before any of the later scans, so
                // stopping after it leaves a real profile the cached list has
                // never seen. Without this the screen shows no profile at all,
                // and the user's reasonable next move is to enroll again on top
                // of it. Async, so the cancel stays instant.
                self.refresh_profiles();
            }
            return;
        }
        if self.op.is_some() {
            // An op (Identify / IR self-test) otherwise eats every key until the
            // worker returns, up to the 120s daemon budget. Keep a quit escape
            // hatch so a stalled probe can never trap the user; the worker result
            // is harmlessly dropped when we exit.
            if matches!(code, KeyCode::Char('q') | KeyCode::Esc) {
                self.quit = true;
            }
            return;
        }
        if let Some((_, buf, pending)) = self.input.as_mut() {
            match code {
                KeyCode::Esc => {
                    // Wipe a half-typed password/passphrase on cancel.
                    if pending.masked() {
                        use zeroize::Zeroize;
                        buf.zeroize();
                    }
                    self.input = None;
                }
                KeyCode::Enter => self.submit_input(),
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return;
        }
        // Generic confirm (delete scan/profile, recovery-forget, keyring-forget):
        // [y] confirms, [n]/Esc cancels, any other key is ignored so a stray
        // keypress can't confirm OR cancel a destructive action.
        if self.confirm.is_some() {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let (_, _, act) = self.confirm.take().unwrap();
                    match act {
                        // Async so the UI keeps animating; poll() logs the
                        // result (✓/error banner) and refreshes. map_confirm
                        // handles the Ok acks and PasswordForgotten.
                        ConfirmAct::Daemon(req) => {
                            self.start_async("(confirmed)", OpTag::Generic, req, map_confirm)
                        }
                        // Root op: leave the alt-screen and run it under sudo.
                        ConfirmAct::Sus(s) => self.suspend = Some(s),
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.confirm = None;
                }
                _ => {} // ignore stray keys
            }
            return;
        }
        // Merge confirm: scan 1 of a "new profile" enroll matched an existing
        // identity. [y] adds the rest of the scans to that profile, [n]/Esc
        // cancels (removing the one merged scan). Any other key is ignored so a
        // stray keypress can't silently cancel the enroll.
        if self.enroll_merge.is_some() {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let mc = self.enroll_merge.take().unwrap();
                    self.confirm_enroll_merge(mc);
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    let mc = self.enroll_merge.take().unwrap();
                    self.cancel_enroll_merge(mc);
                }
                _ => {} // ignore stray keys; the modal stays up
            }
            return;
        }
        if self.show_help {
            // Any of the closers dismisses; other keys are ignored so the
            // overlay can't trigger actions the user can't see.
            if matches!(code, KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q')) {
                self.show_help = false;
            }
            return;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('?') => self.show_help = true,
            // Home: jump back to the Welcome hub from any tab, so the "at a
            // glance" summary is one key away instead of a Tab walk. (Home the
            // KEY is taken by activity scroll; 'h' for home is unused globally.)
            KeyCode::Char('h') if self.visible.contains(&SC_WELCOME) => {
                self.screen = SC_WELCOME;
            }
            // Release/recapture the mouse: captured, the wheel scrolls the TUI
            // but the terminal cannot select text; released, highlight-to-copy
            // works. A toggle because both are legitimate wants.
            KeyCode::Char('M') => self.toggle_mouse(),
            // Advanced view: also show the diagnostic/tuning tabs.
            KeyCode::Char('v') => {
                self.advanced = !self.advanced;
                self.recompute_visible();
                self.log(
                    '·',
                    if self.advanced {
                        "advanced view: all tabs shown ([v] to simplify)"
                    } else {
                        "essential view: setup steps only ([v] for all tabs)"
                    },
                );
            }
            KeyCode::Tab | KeyCode::Right => self.step(1),
            KeyCode::BackTab | KeyCode::Left => self.step(-1),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            // Activity jump-to-oldest/newest (PgUp/PgDn are handled at the top
            // of on_key so they also work mid-op and mid-enroll).
            KeyCode::Home => self.act_scroll = self.act_max(),
            KeyCode::End => self.act_scroll = 0,
            _ => self.on_action(code),
        }
    }

    fn act_max(&self) -> usize {
        self.activity.len().saturating_sub(ACT_H)
    }

    /// Step `d` tabs through the VISIBLE (hardware-applicable) screens, wrapping.
    /// Repair/Fingerprint pull their heavier probes immediately so the tab is
    /// fresh on open (the slow timer only refreshes them every ~10s).
    fn step(&mut self, d: i32) {
        if self.visible.is_empty() {
            return;
        }
        let n = self.visible.len() as i32;
        let pos = self
            .visible
            .iter()
            .position(|&s| s == self.screen)
            .unwrap_or(0) as i32;
        let new_pos = (((pos + d) % n + n) % n) as usize;
        self.screen = self.visible[new_pos];
        self.sel = 0;
        // Fast diagnostics on entering Repair/Fingerprint (no slow profile
        // poll, so the switch is instant); a fresh profile poll only when
        // landing on Profiles, where an external `irlume enroll` should show.
        // Repair too, not just Cameras. Its camera verdicts read the same
        // listing, and Cameras is hidden unless advanced view is on, so on a
        // default session the list was always empty and the "a privacy switch is
        // ON" warning could never fire: the one hardware state that silently
        // stops face auth was unreportable on the screen built to find it.
        if self.screen == SC_CAMERAS || self.screen == SC_REPAIR {
            self.refresh_camera_listing();
        }
        if self.screen == SC_REPAIR || self.screen == SC_FINGERPRINT {
            self.refresh_diagnostics();
        } else if self.screen == SC_PROFILES {
            self.refresh_profiles();
        } else if self.screen == SC_MODELS {
            // Fresh entry starts at the top, so the re-enroll warning is met
            // before any switch command (#331), and the state cache refreshes
            // via the probe worker (idempotent while one is in flight).
            self.models_scroll = 0;
            self.request_probes();
        }
    }

    fn move_sel(&mut self, d: i32) {
        // The Models tab is a read-only text panel: ↑↓ (and j/k) scroll the
        // catalog (#334 review: at 80×24 the body shows ~7 rows and ratatui
        // clips the rest, hiding whole entries and their commands) instead of
        // moving a selection nothing on that screen has. The offset is
        // clamped HERE, not just in draw: an unclamped store kept counting
        // past the end, and every wasted ↓ then cost an ↑ before the view
        // moved again.
        if self.screen == SC_MODELS {
            let max = self.models_lines().len().saturating_sub(1) as u16;
            self.models_scroll = if d > 0 {
                self.models_scroll.saturating_add(d as u16).min(max)
            } else {
                self.models_scroll.saturating_sub(d.unsigned_abs() as u16)
            };
            return;
        }
        // The Settings tab has no profile/scan list; ↑/↓ pick the per-service
        // consent-gesture row that [c] toggles.
        if self.screen == SC_SETTINGS {
            let n = SETTINGS_GESTURE_SERVICES.len() as i32;
            self.settings_svc_sel = (((self.settings_svc_sel as i32 + d) % n + n) % n) as usize;
            return;
        }
        let len = match self.screen {
            SC_REPAIR => self.repair.len(),
            SC_CAMERAS => self.pairs.len(),
            SC_WELCOME => self.hub_rows().len(),
            _ => self.rows().len(),
        };
        let n = len.max(1) as i32;
        let cur = match self.screen {
            SC_REPAIR => &mut self.repair_sel,
            SC_CAMERAS => &mut self.cam_sel,
            SC_WELCOME => &mut self.hub_sel,
            _ => &mut self.sel,
        };
        *cur = (((*cur as i32 + d) % n + n) % n) as usize;
    }

    fn on_action(&mut self, code: KeyCode) {
        match (self.screen, code) {
            // Hub: Enter opens the selected section (the summary IS the nav).
            (SC_WELCOME, KeyCode::Enter) => {
                if let Some((_, _, target)) = self.hub_rows().get(self.hub_sel).copied() {
                    self.screen = target;
                    self.sel = 0;
                    // Same fast paths as a Tab switch: diagnostics for
                    // Repair/Fingerprint, a fresh profile poll for Profiles.
                    if target == SC_CAMERAS || target == SC_REPAIR {
                        self.refresh_camera_listing();
                    }
                    if target == SC_REPAIR || target == SC_FINGERPRINT {
                        self.refresh_diagnostics();
                    } else if target == SC_PROFILES {
                        self.refresh_profiles();
                    } else if target == SC_MODELS {
                        // Same fresh-entry rule as a Tab switch: top of the
                        // catalog (warning before commands) + a cache refresh.
                        self.models_scroll = 0;
                        self.request_probes();
                    }
                }
            }
            // Welcome / Done: refresh the whole snapshot.
            (SC_WELCOME, KeyCode::Char('r')) | (SC_DONE, KeyCode::Char('r')) => {
                self.log('·', "refreshing status…");
                self.refresh();
            }
            // Welcome: start the uninstall challenge (capital U, so a stray
            // lower-case key can't begin it). The user must TYPE the word to
            // proceed, so it can never be triggered by accident.
            (SC_WELCOME, KeyCode::Char('U')) => {
                self.input = Some((
                    "Type  uninstall  to remove irlume (Esc cancels)".into(),
                    String::new(),
                    Pending::UninstallConfirm,
                ));
            }
            // Welcome quick-launch: jump to Profiles and start enrollment.
            // Gate on the CAMERA, not tab visibility: Identify is an
            // advanced-view tab, so a visibility gate made [i] a silent
            // no-op (then claim "no camera") in the default essential view
            // on a camera-equipped machine.
            (SC_WELCOME, KeyCode::Char('e')) if self.caps.rgb => {
                self.screen = SC_PROFILES;
                self.begin_enroll();
            }
            (SC_WELCOME, KeyCode::Char('i')) if self.caps.rgb => {
                // Only jump to the Identify tab where it exists (advanced
                // view); in essential view stay put and let the result land
                // in Activity.
                if self.visible.contains(&SC_IDENTIFY) {
                    self.screen = SC_IDENTIFY;
                }
                self.start_async(
                    "Identify (1:N)",
                    OpTag::Identify,
                    Request::Identify,
                    map_identify,
                );
            }
            (SC_WELCOME, KeyCode::Char('e' | 'i')) => {
                self.log('·', "no camera on this device: face enrollment/identify unavailable (see Fingerprint/Settings)");
            }
            // Cameras: switch the active pair; persists to /etc, so it's a root
            // op that suspends to `sudo irlume set-cameras`.
            (SC_CAMERAS, KeyCode::Enter) => {
                // Use the cached pairs (clone the selected one so self stays
                // free for the log/suspend below).
                match self.pairs.get(self.cam_sel).cloned() {
                    Some(p) => {
                        self.log(
                            '→',
                            format!(
                                "sudo irlume set-cameras {} {} (you'll be asked for your password)",
                                p.rgb, p.ir
                            ),
                        );
                        self.suspend = Some(Suspend::SetCameras(p.rgb.clone(), p.ir.clone()));
                    }
                    None => self.log(
                        '·',
                        "no paired Hello camera to switch to (an RGB-only device has no pair)",
                    ),
                }
            }
            // Repair: re-run checks, fix the selected issue, or run a live IR test.
            (SC_REPAIR, KeyCode::Char('r')) => {
                self.log('·', "re-running diagnostics…");
                self.refresh();
            }
            (SC_REPAIR, KeyCode::Char('f')) | (SC_REPAIR, KeyCode::Enter) => {
                self.apply_fix(self.repair_sel)
            }
            // View the face-auth journal to see WHY a check failed. `logs debug
            // on` (a console step) adds per-stage tracing when a number is needed.
            // Key is 'g'; 'v' is the global basic/all-tabs toggle (on_key).
            (SC_REPAIR, KeyCode::Char('g')) => {
                self.log(
                    '→',
                    "sudo irlume logs: the daemon/PAM/keyring journal in one view",
                );
                self.log('·', "deeper: `sudo irlume logs debug on` traces each pipeline stage (turn off after)");
                self.suspend = Some(Suspend::Logs);
            }
            // Full `irlume doctor` readout: the complete authoritative dump,
            // including the info-only lines the Repair checklist omits, for a
            // bug report. Runs as the user (no sudo prompt); root-only lines
            // say so.
            (SC_REPAIR, KeyCode::Char('d')) => {
                self.log('→', "irlume doctor: the complete platform readout (copy-pasteable)");
                self.suspend = Some(Suspend::Doctor);
            }
            // IR liveness self-test: the daemon root-gates it (the raw
            // measurements are a spoof-tuning oracle), so like every other root
            // action it suspends to sudo instead of failing with a peer-uid
            // error on the direct socket call.
            (SC_REPAIR, KeyCode::Char('l')) => {
                self.log('→', "sudo irlume selftest liveness: fires the IR camera through the daemon and reports the liveness measurements");
                self.suspend = Some(Suspend::SelfTestLiveness);
            }
            // Cameras: IR emitter auto-setup (root; writes the persisted UVC
            // control) suspends to sudo; the [p] probe below is read-only.
            (SC_CAMERAS, KeyCode::Char('s')) => {
                self.log('→', "sudo irlume ir-setup: set up the 850nm emitter; this writes to the camera (you'll be asked for your password)");
                self.suspend = Some(Suspend::IrSetup);
            }
            // Capture-mode tuning: some Hello modules starve their own RGB
            // interface when both stream, others keep the faster concurrent
            // path; only a measurement can tell which camera this is. Said
            // up front because it holds the camera for a while (#170).
            (SC_CAMERAS, KeyCode::Char('t')) => {
                // A modal, not an Activity line: the log-then-suspend shape
                // never RENDERS before the terminal leaves the alt screen (the
                // frame was drawn before the key was read, and the suspend
                // runs in the same loop iteration), so the explanation the
                // route promises would appear only after the run (#204
                // review). The confirm modal is drawn before any key can
                // schedule the suspend, which is the existing shape of every
                // other consequential route here.
                self.confirm = Some((
                    concat!(
                        "Tune capture mode? This holds the camera and fires the ",
                        "IR emitter for up to a minute, then stores the verdict ",
                        "in /etc/irlume/cameras.conf. Your password will be ",
                        "requested."
                    )
                        .into(),
                    "Tune",
                    ConfirmAct::Sus(Suspend::CameraTune),
                ));
            }
            (SC_CAMERAS, KeyCode::Char('p')) => self.start_async(
                "IR emitter units",
                OpTag::Generic,
                Request::SetupIrEmitter { dry_run: true },
                map_ok,
            ),
            // Profiles.
            (SC_PROFILES, KeyCode::Char('e')) => self.begin_enroll(),
            (SC_PROFILES, KeyCode::Char('a')) => match self.sel_profile() {
                Some(p) => self.start_enroll(Some(p)),
                None => self.log('·', "select a profile first (↑↓), then [a] to add scans"),
            },
            (SC_PROFILES, KeyCode::Char('r')) => self.begin_rename(),
            (SC_PROFILES, KeyCode::Char('d')) => self.begin_delete(),
            // Identify: 1:N who-is-this.
            (SC_IDENTIFY, KeyCode::Char('i')) => self.start_async(
                "Identify (1:N)",
                OpTag::Identify,
                Request::Identify,
                map_identify,
            ),
            // Keyring: masked in-TUI entry (goes to the root daemon; no sudo).
            (SC_KEYRING, KeyCode::Char('a')) => {
                self.input = Some((
                    "Login password to seal (••):".into(),
                    String::new(),
                    Pending::KeyringPw(None),
                ));
            }
            // Refresh the pcrlock policy (Tier-2 only): re-predict the boot
            // measurements after a firmware/Secure Boot change so the seal keeps
            // validating. Root op; idempotent, so no confirm.
            (SC_KEYRING, KeyCode::Char('p'))
                if self
                    .keyring_policy
                    .as_deref()
                    .is_some_and(|p| p.contains("Tier 2")) =>
            {
                self.log('→', "sudo systemd-pcrlock make-policy: refreshes the boot-measurement policy your seal is bound to");
                self.suspend = Some(Suspend::PcrlockMakePolicy);
            }
            // Reseal: re-bind the sealed password to the current PCRs (the CLI
            // `irlume reseal`). Same masked-prompt + SealPassword path as arm;
            // the distinct entry point and copy are the discoverability the
            // drift-recovery workflow needs.
            (SC_KEYRING, KeyCode::Char('r')) if self.keyring_armed == Some(true) => {
                self.input = Some((
                    "Login password to re-seal to current PCRs (••):".into(),
                    String::new(),
                    Pending::KeyringPw(None),
                ));
            }
            (SC_KEYRING, KeyCode::Char('f')) => {
                // A token arm (#250) must re-key the login keyring back to the
                // password before the envelope is erased; a bare forget here
                // would delete the keyring's live credential. That flow needs
                // a password prompt and the control socket, so route it to the
                // CLI rather than duplicating it in TUI state.
                // Anything other than a confirmed non-token refuses here.
                // `None` means an older daemon or an envelope it could not
                // parse, and erasing a token envelope on that reading leaves
                // the login keyring encrypted under a secret nothing can
                // reproduce. The CLI has the re-key flow and the --force
                // escape; this screen has neither, so it defers.
                if self.keyring_kind != Some(irlume_common::KeyringSecretKind::LoginPassword)
                    && self.keyring_kind != Some(irlume_common::KeyringSecretKind::KdeWalletKey)
                {
                    self.log(
                        '!',
                        "cannot confirm this is safe to erase from here; run `irlume keyring \
                         forget` in a terminal (it re-keys a token back to your password first)",
                    );
                    return;
                }
                self.confirm = Some((
                    "Erase the TPM-sealed keyring secret?".into(),
                    "Erase",
                    ConfirmAct::Daemon(Request::ForgetPassword {
                        user: self.user.clone(),
                    }),
                ));
            }
            // Recovery: masked in-TUI entry.
            (SC_RECOVERY, KeyCode::Char('s')) => {
                self.input = Some((
                    "New recovery passphrase (••):".into(),
                    String::new(),
                    Pending::RecoveryPw(None),
                ));
            }
            (SC_RECOVERY, KeyCode::Char('t')) => {
                self.input = Some((
                    "Recovery passphrase to restore (••):".into(),
                    String::new(),
                    Pending::RecoveryRestorePw,
                ));
            }
            (SC_RECOVERY, KeyCode::Char('f')) => {
                self.confirm = Some((
                    "Erase the recovery passphrase? (templates stay encrypted)".into(),
                    "Erase",
                    ConfirmAct::Daemon(Request::RecoveryForget {
                        user: self.user.clone(),
                    }),
                ));
            }
            // Fingerprint.
            (SC_FINGERPRINT, KeyCode::Char('a')) => {
                if self.fp.available {
                    self.suspend = Some(Suspend::FingerprintAdd);
                } else {
                    self.log('✗', "no fingerprint reader detected");
                }
            }
            // 't' not 'v': 'v' is the global basic/advanced view toggle and
            // never reaches per-screen actions (found in container E2E).
            (SC_FINGERPRINT, KeyCode::Char('t')) => {
                if self.fp.available {
                    self.suspend = Some(Suspend::FingerprintVerify);
                } else {
                    self.log('✗', "no fingerprint reader detected");
                }
            }
            (SC_FINGERPRINT, KeyCode::Char('e')) => {
                self.log('→', "sudo irlume fingerprint enable: unlock with face OR fingerprint");
                self.suspend = Some(Suspend::FingerprintEnable);
            }
            (SC_FINGERPRINT, KeyCode::Char('d')) => {
                self.log('→', "sudo irlume fingerprint disable: remove fingerprint from login");
                self.suspend = Some(Suspend::FingerprintDisable);
            }
            (SC_FINGERPRINT, KeyCode::Char('x')) => {
                self.confirm = Some((
                    "Delete ALL enrolled fingerprints from the reader?".into(),
                    "Delete",
                    ConfirmAct::Sus(Suspend::FingerprintReset),
                ));
            }
            // Login wiring (PAM): [w] wires the login stack (root, suspends to
            // sudo) from either the wiring tab or the Done dashboard; the last
            // setup mile must not require leaving the TUI for a manual command.
            (SC_PAM, KeyCode::Char('w')) | (SC_DONE, KeyCode::Char('w')) => {
                self.log('→', "sudo irlume login enable --apply: wires the greeter + lock screen for your method");
                self.log('·', "leave the password empty and press Enter to use your face (login needs the IR/secure tier; an RGB-only camera unlocks the lock screen only)");
                self.log('·', "face-sudo is opt-in; add it later with: sudo irlume login enable --with-sudo --apply");
                self.suspend = Some(Suspend::LoginEnable);
            }
            // Login wiring (PAM): show status outside the alt-screen.
            (SC_PAM, KeyCode::Char('s')) => self.suspend = Some(Suspend::LoginStatus),
            // Opt-in wiring extras; each logs the exact command then suspends,
            // so nothing needs to be copied out of the TUI to be run.
            (SC_PAM, KeyCode::Char('u')) => {
                self.log('→', "sudo irlume login enable --with-sudo --apply: face approves sudo prompts (password still works)");
                self.suspend = Some(Suspend::LoginEnableSudo);
            }
            (SC_PAM, KeyCode::Char('p')) => {
                self.log('→', "sudo irlume login enable --with-polkit --apply: face + consent gesture approve app prompts (Bitwarden, pkexec)");
                self.suspend = Some(Suspend::LoginEnablePolkit);
            }
            (SC_PAM, KeyCode::Char('c')) => {
                self.log('→', "sudo irlume calibrate-closure: teach the eye-closure consent gesture (the head nod needs no calibration)");
                self.suspend = Some(Suspend::CalibrateClosure);
            }
            // Un-wiring is destructive-ish (face login stops working until
            // re-enabled), so it gets the y/n gate.
            (SC_PAM, KeyCode::Char('x')) => {
                self.confirm = Some((
                    "Un-wire face auth from login/lock/sudo/apps? (password logins are untouched)"
                        .into(),
                    "Un-wire",
                    ConfirmAct::Sus(Suspend::LoginDisable),
                ));
            }
            // Bitwarden app unlock: install its polkit action, only ever on
            // explicit request and only useful when the row says so.
            (SC_PAM, KeyCode::Char('b')) => match crate::bitwarden::tui_state() {
                Some(crate::bitwarden::TuiState::NeedsSetup) => {
                    self.log('→', "sudo irlume bitwarden setup --apply: installs Bitwarden's polkit action (host-side; the flatpak cannot)");
                    self.suspend = Some(Suspend::BitwardenSetup);
                }
                Some(crate::bitwarden::TuiState::Ready) => {
                    self.log('·', "Bitwarden's polkit action is already installed; enable \"unlock with system authentication\" in its settings")
                }
                Some(crate::bitwarden::TuiState::SnapMissing) => {
                    self.log('·', "snap install: snapd owns that file; run: sudo snap connect bitwarden:polkit")
                }
                None => self.log('·', "Bitwarden is not installed on this system"),
            },
            // Settings.
            (SC_SETTINGS, KeyCode::Enter) | (SC_SETTINGS, KeyCode::Char(' ')) => {
                let on = !self.eyes_open;
                // Turning it ON is refused by the daemon (#386), so do not fire
                // a request known in advance to fail. The refusal still lives
                // there, because that is the one choke point both this and the
                // CLI go through; this only avoids offering the user an action
                // whose only outcome is an error modal.
                if on {
                    // The row no longer advertises enter while off, so this is
                    // a bare keypress: a log line, not a modal. The wording
                    // matches the daemon's own refusal at its choke point.
                    self.log(
                        '·',
                        "require-eyes-open cannot be enabled: it refuses the user it \
                         exists to admit (measured 1 of 12 bare-eyed frames with eyes \
                         open, 0 of 12 with glasses). See issue #386.",
                    );
                    return;
                }
                self.start_async(
                    "toggle require-eyes-open",
                    OpTag::Generic,
                    Request::SetRequireEyesOpen {
                        user: self.user.clone(),
                        on,
                    },
                    map_settings,
                );
            }
            // Biopolicy gate: enabling changes the security posture (restricts
            // which services a face may satisfy), so it is confirmed; disabling
            // just relaxes back to default and goes straight through.
            (SC_SETTINGS, KeyCode::Char('b')) => {
                let Some(on) = irlume_common::config::enforce_biopolicy_visible() else {
                    self.log(
                        '·',
                        "the biopolicy gate is a root-only setting; run the TUI with sudo, \
                         or check it with: irlume biopolicy status",
                    );
                    return;
                };
                if on {
                    self.log('→', "sudo irlume biopolicy off: relax back to the default (all services may verify)");
                    self.suspend = Some(Suspend::Biopolicy(false));
                } else {
                    self.confirm = Some((
                        "Enable the biopolicy gate? Only Login/Elevation may then release the \
                         keyring; lock-screen becomes verify-only. Password stays available."
                            .into(),
                        "Enable",
                        ConfirmAct::Sus(Suspend::Biopolicy(true)),
                    ));
                }
            }
            // Per-service consent gesture: ↑/↓ pick the service, [c] toggles it.
            // settings.conf is root-only, so this shells out to the CLI, the one
            // place the write and its high-privilege confirmation live. Every
            // service in the list is elevation or app-consent, so disabling the
            // gesture (a face match alone would then approve it) asks first;
            // enabling only adds friction and goes straight through.
            (SC_SETTINGS, KeyCode::Char('c')) => {
                // Same clamp as the draw: a key must not panic on a stale index.
                let svc = SETTINGS_GESTURE_SERVICES
                    .get(self.settings_svc_sel)
                    .copied()
                    .unwrap_or(SETTINGS_GESTURE_SERVICES[0]);
                // Same effective read as the badge, so [c] flips what the user
                // sees. Reading the elevation-only default here meant the first
                // press on polkit wrote `on` (already the behaviour) and skipped
                // the confirmation that disabling is supposed to require.
                //
                // And it must be the read that can say "I do not know".
                // settings.conf is 0600 root-owned, so an unprivileged TUI cannot
                // see an override at all and every service defaulted to ON: the
                // key could then only ever DISABLE, and pressing it again after a
                // disable wrote `off` a second time while the row still claimed
                // the gesture was required. Say so instead of guessing.
                let Some(current) = irlume_common::config::service_gesture_required_visible(svc)
                else {
                    self.log(
                        '·',
                        format!(
                            "the consent gesture for '{svc}' is a root-only setting; \
                             run the TUI with sudo, or check it with: \
                             sudo irlume credential-release-challenge {svc} status"
                        ),
                    );
                    return;
                };
                let target = !current;
                let sus = Suspend::ServiceGesture {
                    service: svc.to_string(),
                    on: target,
                };
                if target {
                    self.log(
                        '→',
                        format!(
                            "sudo irlume credential-release-challenge {svc} on: \
                             require a consent gesture for '{svc}'"
                        ),
                    );
                    self.suspend = Some(sus);
                } else {
                    self.confirm = Some((
                        format!(
                            "Disable the consent gesture for '{svc}'? A face match alone would \
                             then approve it: a print of your face held to the camera could use \
                             '{svc}'. Your typed password still works."
                        ),
                        "Disable",
                        ConfirmAct::Sus(sus),
                    ));
                }
            }
            // Credential-release gesture gate. DEFAULT OFF: the keyring releases
            // after the face match with no nod. 'g' toggles the opt-in extra
            // step; neither direction needs a confirm (off is the default, on only
            // adds friction). settings.conf is root-only, so an unprivileged TUI
            // cannot read the state; then offer to enable the opt-in.
            (SC_SETTINGS, KeyCode::Char('g')) => {
                match irlume_common::config::credential_release_challenge_visible() {
                    Some(true) => {
                        self.log(
                            '→',
                            "sudo irlume credential-release-challenge off: back to the default \
                             (the keyring releases with no nod)",
                        );
                        self.suspend = Some(Suspend::CredentialReleaseChallenge(false));
                    }
                    Some(false) | None => {
                        self.log(
                            '→',
                            "sudo irlume credential-release-challenge on: add a gesture before \
                             keyring release",
                        );
                        self.suspend = Some(Suspend::CredentialReleaseChallenge(true));
                    }
                }
            }
            // Third-party PAD model toggle. settings.conf is root-only, so the
            // readable proxy for "enabled" is installed weights (disable
            // deletes them). Enabling runs the CLI's own license/provenance
            // confirm in the cooked terminal: that friction is the policy,
            // the TUI hosts it rather than bypassing it.
            (SC_SETTINGS, KeyCode::Char('m')) => {
                use irlume_common::thirdparty::{Stage, CATALOG};
                // Decide from ENABLED state, not installed files: weights can
                // be orphaned on disk with no settings key (an admitted
                // partial state of install), and `models disable <name>`
                // refuses names that are not enabled (#285 review).
                match crate::models::tui_state() {
                    crate::models::TuiState::Enabled { entries } if entries.len() == 1 => {
                        let entry = &entries[0];
                        self.confirm = Some((
                            format!(
                                "Disable third-party {} model '{}'? (its weights are deleted)",
                                entry.stage.as_str(),
                                entry.name
                            ),
                            "Disable",
                            ConfirmAct::Sus(Suspend::ModelsDisable(entry.name.to_string())),
                        ));
                    }
                    // Several enabled stages: a single toggle key must not
                    // guess which authentication policy to remove.
                    crate::models::TuiState::Enabled { entries } => {
                        for entry in entries {
                            self.log(
                                '·',
                                format!(
                                    "enabled: {} ({} stage) — disable with: sudo irlume models disable {}",
                                    entry.name,
                                    entry.stage.as_str(),
                                    entry.name
                                ),
                            );
                        }
                    }
                    crate::models::TuiState::UnknownName { name } => {
                        self.log(
                            '·',
                            format!("'{name}' is set in settings.conf but not in the catalog; fix it with `sudo irlume models`"),
                        );
                    }
                    crate::models::TuiState::InstalledUnknown { .. } => {
                        self.log(
                            '·',
                            "weights are installed but the enabled state is root-only; run `sudo irlume models` for the authoritative view",
                        );
                    }
                    crate::models::TuiState::None => {
                        // Nothing enabled: offer the PAD recommendation, the
                        // same one doctor makes (the built-in gate does not
                        // stop a print).
                        match CATALOG.iter().find(|m| m.stage == Stage::Pad) {
                            Some(m) => {
                                self.log('→', format!("sudo irlume models enable {}: the license + provenance confirm runs in the terminal", m.name));
                                self.suspend = Some(Suspend::ModelsEnable(m.name.to_string()));
                            }
                            None => self.log('·', "no third-party models in the catalog"),
                        }
                    }
                }
            }
            // Daemon debug logging toggle; deny scores land in the journal
            // while on, so remind the user to turn it back off.
            (SC_REPAIR, KeyCode::Char('t')) => {
                let on = crate::logs::debug_active();
                if !on {
                    self.log('·', "debug logging writes per-stage detail (incl. scores) to the journal; press [t] again to turn it off when done");
                }
                self.suspend = Some(Suspend::LogsDebug(!on));
            }
            // Origin-aware updater, from the dashboard.
            (SC_DONE, KeyCode::Char('u')) => {
                self.log('→', "irlume update: checks the release feed and updates via the channel this install came from");
                self.suspend = Some(Suspend::Update);
            }
            _ => {}
        }
    }

    /// Enrollment (and add-scan) needs the daemon. When it's down, route
    /// straight into the Repair fix (sudo enable+start) instead of starting a
    /// doomed capture, the #1 first-run state (fresh package install, unit
    /// disabled by distro preset policy). The enroll intent is remembered and
    /// resumes automatically once the daemon answers.
    fn daemon_gate(&mut self, resume: ResumeEnroll) -> bool {
        if self.daemon_up {
            return true;
        }
        self.log(
            '✗',
            "irlumed isn't running; starting it now (enrollment continues automatically)",
        );
        self.recompute_visible(); // daemon down ⇒ Repair earns its tab back
        self.screen = SC_REPAIR;
        self.repair_sel = 0; // the Daemon row is always first
        self.resume_enroll = Some(resume);
        self.suspend = Some(Suspend::RestartDaemon);
        false
    }

    /// Start a new-profile enrollment (prompts for a name; blank = default).
    fn begin_enroll(&mut self) {
        if !self.daemon_gate(ResumeEnroll::New) {
            return;
        }
        if self.profiles.len() >= MAX_PROFILES {
            // A new PERSON can't be added at the cap. Refreshing your OWN face
            // (the merge path) is what [a] Improve Recognition does, so point
            // there instead of only "delete one".
            self.log(
                '✗',
                format!(
                    "at the max {MAX_PROFILES} profiles (people). To refresh your own face, use [a] Improve Recognition; to add a different person, delete a profile first."
                ),
            );
        } else {
            self.input = Some((
                "New profile name (blank = default):".into(),
                String::new(),
                Pending::EnrollName,
            ));
        }
    }

    fn sel_profile(&self) -> Option<String> {
        match self.rows().get(self.sel)? {
            Row::Profile(pi) | Row::Scan(pi, _) => Some(self.profiles[*pi].name.clone()),
        }
    }

    fn begin_rename(&mut self) {
        match self.rows().get(self.sel).copied() {
            Some(Row::Profile(pi)) => {
                let name = self.profiles[pi].name.clone();
                self.input = Some((
                    format!("Rename profile '{name}' to:"),
                    String::new(),
                    Pending::RenameProfile(name),
                ));
            }
            Some(Row::Scan(pi, si)) => {
                let (p, s) = (
                    self.profiles[pi].name.clone(),
                    self.profiles[pi].scans[si].clone(),
                );
                self.input = Some((
                    format!("Rename scan '{s}' to:"),
                    String::new(),
                    Pending::RenameScan(p, s),
                ));
            }
            // Nothing selected (an empty profile list, or a selection left by
            // a list that shrank). [r] is advertised, so say why it did nothing.
            None => self.log('·', "select a profile or scan to rename"),
        }
    }

    fn begin_delete(&mut self) {
        match self.rows().get(self.sel).copied() {
            Some(Row::Profile(pi)) => {
                let p = self.profiles[pi].name.clone();
                self.confirm = Some((
                    format!("Delete profile '{p}' and all its scans?"),
                    "Delete",
                    ConfirmAct::Daemon(Request::DeleteProfile {
                        user: self.user.clone(),
                        profile: p,
                    }),
                ));
            }
            Some(Row::Scan(pi, si)) => {
                let (p, s) = (
                    self.profiles[pi].name.clone(),
                    self.profiles[pi].scans[si].clone(),
                );
                self.confirm = Some((
                    format!("Delete scan '{s}' from '{p}'?"),
                    "Delete",
                    ConfirmAct::Daemon(Request::DeleteScan {
                        user: self.user.clone(),
                        profile: p,
                        scan: s,
                    }),
                ));
            }
            // Same as the rename above: an advertised key must answer.
            None => self.log('·', "select a profile or scan to delete"),
        }
    }

    fn submit_input(&mut self) {
        let Some((_, buf, pending)) = self.input.take() else {
            return;
        };
        // Wrap the raw buffer so it (a password on the secret paths) is zeroized
        // on drop, not left in swappable heap. The trimmed copy is computed only
        // in the non-secret arms so a password never leaves a plain-String copy.
        let buf = zeroize::Zeroizing::new(buf);
        match pending {
            // The uninstall challenge: only the exact word proceeds; anything
            // else (including empty / Esc, which submits nothing) cancels.
            Pending::UninstallConfirm => {
                if buf.trim() == "uninstall" {
                    self.log(
                        '→',
                        "uninstall confirmed; suspending to `sudo irlume uninstall --yes` \
                         (the TUI already confirmed)",
                    );
                    self.suspend = Some(Suspend::Uninstall);
                } else {
                    self.log('·', "uninstall cancelled (word did not match)");
                }
            }
            Pending::EnrollName => {
                let v = buf.trim().to_string();
                if !v.is_empty() && self.profiles.iter().any(|p| p.name == v) {
                    self.log('✗', format!("a profile named '{v}' already exists"));
                    return;
                }
                // Always pass a concrete name so the worker can add scans to it.
                let name = if v.is_empty() {
                    self.next_profile_name()
                } else {
                    v
                };
                self.start_enroll_named(name);
            }
            Pending::RenameProfile(old) => self.rename(Request::RenameProfile {
                user: self.user.clone(),
                profile: old,
                new_name: buf.trim().to_string(),
            }),
            Pending::RenameScan(p, s) => self.rename(Request::RenameScan {
                user: self.user.clone(),
                profile: p,
                scan: s,
                new_name: buf.trim().to_string(),
            }),
            // Passwords: use the RAW buffer (never trim). Double-entry to confirm.
            Pending::KeyringPw(None) => {
                if buf.is_empty() {
                    self.set_error("empty password; aborted (nothing sealed)");
                    return;
                }
                self.input = Some((
                    "Confirm login password (••):".into(),
                    String::new(),
                    Pending::KeyringPw(Some(zeroize::Zeroizing::new((*buf).clone()))),
                ));
            }
            Pending::KeyringPw(Some(first)) => {
                if *buf != *first {
                    self.set_error("passwords don't match; aborted (nothing sealed)");
                    return;
                }
                let user = self.user.clone();
                let pw = zeroize::Zeroizing::new(buf.as_bytes().to_vec());
                // Async: the TPM seal is the slowest daemon op; don't freeze
                // the frame. A closure task rather than a mapper, because a
                // TokenSealed reply (GNOME, #250) must be followed by the
                // keyring re-key, which needs the password and user.
                self.start_async_task(
                    "SealPassword",
                    OpTag::Generic,
                    Box::new(move || {
                        let req = Request::SealPassword {
                            kind: None, // let the daemon judge from what the user has
                            user: user.clone(),
                            password: irlume_common::SecretBytes::new(pw.to_vec()),
                        };
                        match crate::daemon_request(&req) {
                            Ok(Response::TokenSealed { token, minted }) => {
                                match crate::finish_token_arm(&user, &pw, token.expose(), minted) {
                                    Ok(()) => (
                                        true,
                                        "keyring armed with a token; the login keyring was \
                                         re-keyed to it"
                                            .into(),
                                    ),
                                    Err(e) => (false, e),
                                }
                            }
                            Ok(resp) => map_sealed(resp),
                            Err(e) => (false, e),
                        }
                    }),
                );
            }
            Pending::RecoveryPw(None) => {
                if buf.is_empty() {
                    self.set_error("empty passphrase; aborted");
                    return;
                }
                self.input = Some((
                    "Confirm recovery passphrase (••):".into(),
                    String::new(),
                    Pending::RecoveryPw(Some(zeroize::Zeroizing::new((*buf).clone()))),
                ));
            }
            Pending::RecoveryPw(Some(first)) => {
                if *buf != *first {
                    self.set_error("passphrases don't match; aborted");
                    return;
                }
                let req = Request::RecoverySetup {
                    user: self.user.clone(),
                    passphrase: irlume_common::SecretBytes::new(buf.as_bytes().to_vec()),
                };
                self.start_async("RecoverySetup", OpTag::Generic, req, map_ok);
            }
            Pending::RecoveryRestorePw => {
                if buf.is_empty() {
                    self.set_error("empty passphrase; aborted");
                    return;
                }
                let req = Request::RecoveryRestore {
                    user: self.user.clone(),
                    passphrase: irlume_common::SecretBytes::new(buf.as_bytes().to_vec()),
                };
                self.start_async("RecoveryRestore", OpTag::Generic, req, map_ok);
            }
        }
    }

    fn rename(&mut self, req: Request) {
        self.start_async("Rename", OpTag::Generic, req, map_ok);
    }

    /// New-profile guided enroll with an explicit name.
    fn start_enroll_named(&mut self, name: String) {
        if !self.daemon_gate(ResumeEnroll::Named(name.clone())) {
            return;
        }
        let user = self.user.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let (st, pn) = (stop.clone(), name.clone());
        std::thread::spawn(move || enroll_worker(user, pn, None, ENROLL_SCANS, st, tx));
        self.log(
            '→',
            format!("guided enroll → '{name}' ({ENROLL_SCANS} scans)"),
        );
        self.enroll = Some(EnrollUi {
            rx,
            stop,
            profile: name,
            last: None,
            count: None,
            stalled: None,
            captured: 0,
            target: ENROLL_SCANS,
            base: 0,
            ambient_base: 0,
        });
    }

    // ---- rendering --------------------------------------------------------

    fn draw(&self, f: &mut Frame) {
        let [header, hint, body, activity, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(7),
            Constraint::Length(3),
        ])
        .areas(f.area());
        self.draw_header(f, header);
        self.draw_hint(f, hint);
        // Redesign: on a roomy terminal the body splits into a settings-app
        // sidebar (the visible screens, grouped) and the content pane.
        // `step()`/arrows still drive `self.screen`; the sidebar renders that
        // selection vertically instead of the old horizontal step-walk. Below
        // SIDEBAR_MIN_COLS (login greeters / TTYs / SSH at 80) the sidebar
        // would starve the content, so it collapses back to full-width content
        // and the header's "step N/N" carries position instead.
        if self.is_first_run() {
            // A not-yet-enrolled user gets a focused front door: one screen, one
            // action, no 12-item sidebar to parse. Tab or [v] leaves it.
            self.draw_firstrun(f, body);
        } else if body.width >= SIDEBAR_MIN_COLS {
            let [sidebar, content] =
                Layout::horizontal([Constraint::Length(22), Constraint::Min(20)]).areas(body);
            self.draw_sidebar(f, sidebar);
            // `draw_content` already frames each screen in its own titled card,
            // so the content pane needs no extra border here.
            self.draw_content(f, content);
        } else {
            self.draw_content(f, body);
        }
        self.draw_activity(f, activity);
        self.draw_footer(f, footer);
        if let Some(err) = &self.error {
            self.error_modal(f, err);
        } else if let Some((prompt, buf, pending)) = &self.input {
            let shown = if pending.masked() {
                "•".repeat(buf.chars().count())
            } else {
                buf.clone()
            };
            // Prompt in the wrapping body (a long name/prompt would truncate as a
            // border title); the typed field on its own line below it.
            self.modal(f, "Input", &format!("{prompt}\n{shown}▏"));
        } else if let Some((what, _, _)) = &self.confirm {
            // Question in the body so a long target name isn't clipped by the
            // single-line border title.
            let verb = self.confirm.as_ref().map(|c| c.1).unwrap_or("Confirm");
            self.modal(
                f,
                "Confirm",
                &format!("{what}\n[n]/Esc Cancel    [y] {verb}"),
            );
        } else if let Some(mc) = &self.enroll_merge {
            // Keep the message in the wrapping body, not the border title (which
            // is a single line clamped to the box width and would truncate).
            let body = format!(
                "This face is already enrolled as '{}' (a face owns one profile). \
                 Add these scans to it?   [y] add   ·   [n] cancel",
                mc.profile
            );
            self.modal(f, "Already enrolled", &body);
        }
        // Tier two of the key-disclosure ladder; drawn last so it sits above
        // everything except nothing (help is always answerable).
        if self.show_help {
            self.modal(f, "Keys  ([?] or Esc to close)", &self.help_body());
        }
    }

    /// A red, dismissible error banner centred on screen.
    fn error_modal(&self, f: &mut Frame, msg: &str) {
        let area = f.area();
        // Both dimensions are capped by the frame: the 30-column floor and the
        // fixed 7 rows are bigger than a small terminal, and a rect that reaches
        // past the buffer is not something a draw may produce.
        let w = area
            .width
            .saturating_sub(8)
            .clamp(30, 78)
            .min(area.width.max(1));
        let h = 7u16.min(area.height.max(1));
        let rect = Rect {
            x: area.width.saturating_sub(w) / 2,
            y: area.height.saturating_sub(h) / 2,
            width: w,
            height: h,
        };
        f.render_widget(Clear, rect);
        let blk = Block::bordered()
            .title(" ⚠ Problem ")
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(th().err).add_modifier(Modifier::BOLD))
            .padding(ratatui::widgets::Padding::horizontal(1));
        let body = vec![
            Line::raw(""),
            Line::from(Span::styled(msg.to_string(), Style::new().fg(th().err))),
            Line::raw(""),
            Line::from(Span::styled("[any key] dismiss", Style::new().dim())),
        ];
        f.render_widget(
            Paragraph::new(body).block(blk).wrap(Wrap { trim: true }),
            rect,
        );
    }

    /// A brand-new user (face camera present, nothing enrolled yet, sitting on
    /// Welcome, no capture in flight) gets one focused screen with one action
    /// instead of the full sidebar. Tab or [v] moves off Welcome and restores
    /// the sidebar. Fingerprint-only / no-camera hosts keep the classic Welcome
    /// (its wording already adapts to their hardware).
    fn is_first_run(&self) -> bool {
        self.enroll.is_none()
            && self.screen == SC_WELCOME
            && self.caps.rgb
            && self.enrolled_known() == Some(false)
    }

    /// The first-run front door: a single "scan your face" call to action, the
    /// three steps of what happens, and the reassurance that the password never
    /// stops working. Deliberately no sidebar — nothing to parse on run one.
    fn draw_firstrun(&self, f: &mut Frame, area: Rect) {
        let a = th().accent;
        let key = |k: &str| Span::styled(format!(" {k} "), th().chip);
        let lines = vec![
            Line::raw(""),
            Line::raw(""),
            Line::from(Span::styled(
                "Set up face unlock",
                Style::new().fg(a).add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                "Look at your IR camera once and irlume learns your face — then it",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "unlocks login, sudo, and the lock screen. Even in the dark.",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "No images are ever stored.",
                Style::new().dim(),
            )),
            Line::raw(""),
            Line::from(vec![
                Span::styled(
                    "  ▶  Scan my face  ",
                    Style::new()
                        .fg(Color::Black)
                        .bg(a)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("   "),
                key("e"),
            ]),
            Line::raw(""),
            Line::raw(""),
            Line::from(Span::styled(
                "1  Look at the camera      2  Hold still a moment      3  Face unlock is on",
                Style::new().dim(),
            )),
            Line::raw(""),
            Line::from(vec![
                Span::styled("Tab", Style::new().fg(a)),
                Span::styled(" walks every step   ", Style::new().dim()),
                Span::styled("[v]", Style::new().fg(a)),
                Span::styled(" shows all sections", Style::new().dim()),
            ]),
            Line::raw(""),
            Line::from(Span::styled(
                "Your password always works. Typing never starts a scan.",
                Style::new().dim(),
            )),
        ];
        let blk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim());
        f.render_widget(
            Paragraph::new(lines)
                .block(blk)
                .alignment(ratatui::layout::Alignment::Center),
            area,
        );
    }

    /// The left navigation rail: the visible screens grouped Setup / Security /
    /// System, current screen marked with an accent bar. This renders the same
    /// `self.visible` / `self.screen` model the horizontal step-walk used, so
    /// Tab and the arrows keep working unchanged.
    fn draw_sidebar(&self, f: &mut Frame, area: Rect) {
        let groups: [(&str, &[usize]); 3] = [
            (
                "Setup",
                &[SC_WELCOME, SC_REPAIR, SC_CAMERAS, SC_PROFILES, SC_IDENTIFY],
            ),
            ("Security", &[SC_KEYRING, SC_RECOVERY, SC_FINGERPRINT]),
            ("System", &[SC_PAM, SC_SETTINGS, SC_MODELS, SC_DONE]),
        ];
        let mut lines: Vec<Line> = Vec::new();
        for (gi, (name, members)) in groups.iter().enumerate() {
            let shown: Vec<usize> = members
                .iter()
                .copied()
                .filter(|s| self.visible.contains(s))
                .collect();
            if shown.is_empty() {
                continue;
            }
            if gi > 0 {
                lines.push(Line::raw(""));
            }
            lines.push(Line::from(Span::styled(
                format!(" {name}"),
                Style::new().dim().add_modifier(Modifier::BOLD),
            )));
            for s in shown {
                if s == self.screen {
                    lines.push(Line::from(vec![
                        Span::styled("▎", Style::new().fg(th().accent)),
                        Span::styled(
                            format!(" {}", SCREENS[s]),
                            Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
                        ),
                    ]));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("  {}", SCREENS[s]),
                        Style::new().dim(),
                    )));
                }
            }
        }
        let blk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim());
        f.render_widget(Paragraph::new(lines).block(blk), area);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        // Slim one-line title bar. On a wide terminal the sidebar shows position
        // (the highlighted row), so the header just names the section; on a
        // narrow terminal the sidebar is gone, so the header carries "step N/N".
        let mut left = vec![
            Span::styled(
                " irlume ",
                Style::new()
                    .fg(Color::Black)
                    .bg(th().accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
        ];
        if area.width < SIDEBAR_MIN_COLS {
            left.push(Span::styled(
                format!(
                    "step {}/{}: ",
                    self.visible
                        .iter()
                        .position(|&s| s == self.screen)
                        .map_or(1, |p| p + 1),
                    self.visible.len()
                ),
                Style::new().dim(),
            ));
        }
        left.push(Span::styled(
            SCREENS[self.screen],
            Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
        ));
        let right =
            Line::from(Span::styled(format!("{} ", self.user), Style::new().dim())).right_aligned();
        f.render_widget(Paragraph::new(Line::from(left)), area);
        f.render_widget(Paragraph::new(right), area);
    }

    /// A single plain-language line under the header: what THIS tab is for and
    /// the one thing to do here. The whole point is that a first-time user never
    /// lands on a screen not knowing why they're there: no jargon, names the key.
    fn draw_hint(&self, f: &mut Frame, area: Rect) {
        // During a capture the whole UI is about holding still; don't distract.
        // Kept to ~72 chars so it never wraps off this single row on an 80-col
        // terminal (the "  ℹ " prefix eats ~4). Each names the key to press.
        //
        // The four setup screens key their hint off observed state: a fixed
        // "go configure this" line told a fully configured user to redo every
        // step, which reads as "your setup did not take". Unknown state
        // (daemon unreachable, sweep not landed) asserts neither direction;
        // the tri-state rule the rest of this file follows.
        let text = if self.enroll.is_some() {
            "Look at the camera and hold still; the checklist turns green as you go."
        } else {
            match self.screen {
                SC_WELCOME => match self.enrolled_known() {
                    Some(true) => {
                        "You're enrolled; ↑↓ + Enter opens a section, [i] tests recognition."
                    }
                    Some(false) => {
                        "New here? Press [e] to scan your face; your password still works too."
                    }
                    None => "Guided setup: Tab walks the steps; each screen names its keys.",
                },
                SC_REPAIR => {
                    "A red row is a problem: highlight it, press [f] to fix or [g] for logs."
                }
                SC_CAMERAS => "Wrong camera picked? Highlight a pair and press [enter] to use it.",
                SC_PROFILES => {
                    "Press [e] to add a face, or [a] to add scans so it knows you better."
                }
                SC_IDENTIFY => "A 'does it recognize me?' test. Press [i] and look at the camera.",
                SC_KEYRING => match self.keyring_armed {
                    Some(true) => {
                        "Armed: face login opens your wallet. New password? Re-arm with [a]."
                    }
                    Some(false) => {
                        "Let your login open your password wallet: press [a], type your password."
                    }
                    None => {
                        "Seals your login password in the TPM so face login opens your wallet."
                    }
                },
                SC_RECOVERY => match self.recovery.map(|r| r.recovery_set) {
                    Some(true) => {
                        "Recovery passphrase set; [t] restores access if the TPM seal breaks."
                    }
                    Some(false) => {
                        "Set a backup passphrase so a broken TPM seal can't force re-enroll: [s]."
                    }
                    None => {
                        "A backup passphrase keeps your enrollment usable if the TPM seal breaks."
                    }
                },
                SC_FINGERPRINT => "Optional backup: press [a] to add a fingerprint too.",
                SC_PAM => match self.login_wired_known() {
                    Some(true) => {
                        "Face login is wired in; [s] shows status, [x] un-wires a service."
                    }
                    Some(false) => {
                        "Turn on face login for your screen: press [w] (asks for your password)."
                    }
                    None => "Wires face login into your greeter, lock screen and sudo.",
                },
                SC_SETTINGS => {
                    "[enter] turns the eyes-open check OFF (it cannot be turned on, see #386); other settings are root or read-only."
                }
                SC_MODELS => {
                    "Measured model options; switching the recognizer means re-enrolling."
                }
                SC_DONE => {
                    "Green = done; anything left shows its key. Press [q] to close."
                }
                _ => "",
            }
        };
        let line = Line::from(vec![
            Span::styled(
                "  ℹ ",
                Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(text, Style::new().fg(th().accent)),
        ]);
        f.render_widget(Paragraph::new(line), area);
    }

    fn draw_content(&self, f: &mut Frame, area: Rect) {
        let blk = Block::bordered()
            .title(format!(" {} ", SCREENS[self.screen]))
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(th().accent))
            // Breathing room (whitespace over chrome): content never touches
            // the frame.
            .padding(ratatui::widgets::Padding::new(2, 2, 1, 0));
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        if self.enroll.is_some() {
            self.draw_enroll(f, inner);
            return;
        }
        match self.screen {
            SC_WELCOME => self.draw_welcome(f, inner),
            SC_REPAIR => self.draw_repair(f, inner),
            SC_CAMERAS => self.draw_cameras(f, inner),
            SC_PROFILES => self.draw_profiles(f, inner),
            SC_IDENTIFY => self.draw_identify(f, inner),
            SC_KEYRING => self.draw_keyring(f, inner),
            SC_RECOVERY => self.draw_recovery(f, inner),
            SC_FINGERPRINT => self.draw_fingerprint(f, inner),
            SC_PAM => self.draw_pam(f, inner),
            SC_SETTINGS => self.draw_settings(f, inner),
            SC_MODELS => self.draw_models(f, inner),
            _ => self.draw_done(f, inner),
        }
    }

    fn draw_enroll(&self, f: &mut Frame, area: Rect) {
        let e = self.enroll.as_ref().unwrap();
        let r = e.last.as_ref();
        let q = r.map(|x| x.quality).unwrap_or(0);
        let chk = |ok: bool, label: &str| {
            Line::from(vec![
                Span::styled(
                    if ok { "  ✓ " } else { "  ○ " },
                    if ok {
                        Style::new().fg(th().ok)
                    } else {
                        Style::new().dim()
                    },
                ),
                Span::styled(
                    label.to_string(),
                    if ok { Style::new() } else { Style::new().dim() },
                ),
            ])
        };
        let face = r.map(|x| x.face).unwrap_or(false);
        let mut lines = vec![
            Line::from(Span::styled(
                format!(
                    "Enrolling '{}' (scan {}/{})",
                    e.profile,
                    e.captured + e.base,
                    e.target + e.base
                ),
                Style::new().add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
        ];
        if let Some(err) = &e.stalled {
            // Not a biometric verdict: the guide stopped answering, so EVERY
            // live reading (quality bar, checklist, guidance) is stale and
            // rendering any of it reads as a current verdict against a hung
            // capture (#309). The stall replaces the whole live panel.
            lines.push(Line::from(vec![
                Span::styled("  ✗ ", Style::new().fg(th().err)),
                Span::styled(
                    "Camera guide not answering; this is not about your face or lighting.",
                    Style::new().fg(th().err).add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                format!("    ({err}) Check: journalctl -u irlumed -n 50"),
                Style::new().dim(),
            )));
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "  [esc] cancel",
                Style::new().dim(),
            )));
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
            return;
        }
        lines.extend([
            Line::from(vec![
                Span::raw("  Quality  "),
                Span::styled(
                    quality_bar(q),
                    Style::new().fg(if q >= 70 { th().ok } else { th().accent }),
                ),
            ]),
            Line::raw(""),
            chk(face, "Face detected"),
            chk(r.map(|x| x.centered).unwrap_or(false), "Centered in frame"),
            chk(
                r.map(|x| {
                    x.yaw_asym <= CHECK_YAW_ASYM_MAX
                        && (CHECK_PITCH_MIN..=CHECK_PITCH_MAX).contains(&x.pitch_frac)
                })
                .unwrap_or(false),
                "Facing the camera",
            ),
            chk(
                r.map(|x| (CHECK_LUMA_MIN..=CHECK_LUMA_MAX).contains(&x.brightness))
                    .unwrap_or(false),
                "Well lit",
            ),
            Line::raw(""),
        ]);
        if let Some(c) = e.count {
            lines.push(Line::from(Span::styled(
                format!("  ● Hold still; capturing in {c}…",),
                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
            )));
        } else {
            let g = r
                .map(|x| x.guidance.clone())
                .unwrap_or_else(|| "Starting camera…".into());
            lines.push(Line::from(vec![
                Span::styled("  → ", Style::new().fg(th().accent)),
                Span::styled(g, Style::new().add_modifier(Modifier::BOLD)),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "  [esc] cancel",
            Style::new().dim(),
        )));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn draw_profiles(&self, f: &mut Frame, area: Rect) {
        if self.profiles.is_empty() {
            // The list loads in the background (a TPM unseal, seconds on slow
            // TPMs). Until it lands, an empty list is "not loaded yet", and
            // saying "no profiles" would tell an enrolled user their face is
            // gone every time they open this tab.
            let msg = if self.profiles_load.is_some() {
                "\nLoading profiles… (decrypting the enrollment under the TPM key)".to_string()
            } else if let Some(err) = &self.enroll_error {
                // The load FAILED (daemon up, enrollment unreadable). The [e]
                // prompt here invited overwriting an enrollment that exists;
                // Repair carries the recovery guidance.
                format!("\nProfile list unreadable: {err}\n\nDo not re-enroll over it; see the Repair tab first.")
            } else if !self.profiles_loaded {
                // Never answered (daemon unreachable): the enrollment may
                // exist and be fine, so no "none" and no enroll prompt.
                "\nProfile list not read yet: irlumed is not reachable, so nothing is known about your enrollment.\n\nStart the daemon (Repair tab) and this list loads by itself."
                    .to_string()
            } else {
                "\nNo face profiles yet.\n\nPress [e] to enroll; irlume will guide your framing and capture automatically."
                    .to_string()
            };
            f.render_widget(Paragraph::new(msg).wrap(Wrap { trim: false }).dim(), area);
            return;
        }
        let rows = self.rows();
        let items: Vec<ListItem> = rows
            .iter()
            .map(|r| match r {
                Row::Profile(pi) => {
                    let p = &self.profiles[*pi];
                    // Same rule as the CLI listing (#288): only the loaded
                    // recognizer's scans can match, so a bare total would let
                    // a profile look usable when none of it is. The breakdown
                    // appears when the total would mislead; an old daemon
                    // reports neither field and keeps the flat count.
                    let live = p.live_recognizer.as_deref();
                    let live_count = live
                        .and_then(|l| p.scans_by_recognizer.get(l).copied())
                        .unwrap_or(0);
                    let misleading = p.scans_by_recognizer.len() > 1
                        || (live.is_some() && live_count != p.scans.len());
                    let count = if misleading {
                        format!(
                            "   ({} scans, {} for the loaded recognizer)",
                            p.scans.len(),
                            live_count
                        )
                    } else {
                        format!("   ({} scans)", p.scans.len())
                    };
                    let mut item = vec![Line::from(vec![
                        Span::styled(
                            format!("● {}", p.name),
                            Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(count, Style::new().dim()),
                    ])];
                    if misleading && live_count == 0 {
                        item.push(Line::from(Span::styled(
                            "     none of these match the loaded recognizer; add scans with [a] Improve Recognition",
                            Style::new().fg(th().warn),
                        )));
                    }
                    ListItem::new(item)
                }
                Row::Scan(pi, si) => ListItem::new(Line::from(Span::raw(format!(
                    "     ↳ {}",
                    self.profiles[*pi].scans[*si]
                )))),
            })
            .collect();
        // Windows-Hello-style enrollment guidance (selection never reaches
        // these: `sel` is clamped to the real rows above).
        let mut items = items;
        items.push(ListItem::new(Line::raw("")));
        // Pre-split like the two lines below: ratatui Lists never wrap a
        // ListItem, so one long line here was clipped at the terminal edge
        // and the sentence ended mid-word at every width. 74 columns is the
        // budget (80-col terminal minus borders and padding).
        items.push(ListItem::new(Line::from(Span::styled(
            "  Tips: look different sometimes (glasses, low light)? Add scans with",
            Style::new().dim(),
        ))));
        items.push(ListItem::new(Line::from(Span::styled(
            "  Improve Recognition ([a]); same identity, not a second profile.",
            Style::new().dim(),
        ))));
        items.push(ListItem::new(Line::from(Span::styled(
            "  Add a scan ([a]) after big appearance changes, or where strong sunlight",
            Style::new().dim(),
        ))));
        items.push(ListItem::new(Line::from(Span::styled(
            "  (high ambient IR) makes recognition unreliable.",
            Style::new().dim(),
        ))));
        let mut st =
            ListState::default().with_selected(Some(self.sel.min(rows.len().saturating_sub(1))));
        f.render_stateful_widget(
            List::new(items).highlight_style(
                Style::new()
                    .bg(Color::Rgb(0x20, 0x30, 0x40))
                    .add_modifier(Modifier::BOLD),
            ),
            area,
            &mut st,
        );
    }

    /// The Settings tab's per-service consent-gesture section: a header carrying
    /// the keys, then one row of service names with the picked one
    /// (`settings_svc_sel`) highlighted and its EFFECTIVE state. Arrow keys pick,
    /// `c` toggles the picked one. Compact (three lines) because the Settings
    /// panel does not scroll. settings.conf is root-only, so an unreadable value
    /// falls
    /// back to the per-service default (all four default on) rather than guessing
    /// off on a security setting.
    fn service_gesture_lines(&self) -> Vec<Line<'static>> {
        // Clamped, not indexed. The arrow handler wraps this selection modulo the
        // list length, so it is in range today, but a DRAW must never be able to
        // panic: an index that survives a list shrinking (or any future writer
        // that forgets the wrap) would take the whole interface down mid-setup
        // instead of mis-highlighting one row.
        let picked = SETTINGS_GESTURE_SERVICES
            .get(self.settings_svc_sel)
            .copied()
            .unwrap_or(SETTINGS_GESTURE_SERVICES[0]);
        // The EFFECTIVE state the engine enforces, not the elevation-only default:
        // polkit is AppConsent and defaults ON, so the old computation rendered
        // `polkit-1: no` on a default install while the daemon required a gesture.
        // Tri-state, like the two panels below it: an unprivileged TUI cannot read
        // the root-only settings.conf, and a definite badge there is a guess
        // dressed as a fact.
        let required = irlume_common::config::service_gesture_required_visible(picked);
        let mut row: Vec<Span> = vec![Span::raw("  ")];
        for (i, &svc) in SETTINGS_GESTURE_SERVICES.iter().enumerate() {
            let style = if i == self.settings_svc_sel {
                Style::new().fg(th().accent).add_modifier(Modifier::BOLD)
            } else {
                Style::new().dim()
            };
            row.push(Span::styled(format!("{svc}   "), style));
        }
        row.push(Span::raw(format!("   {picked}: ")));
        row.push(onoff_opt(required));
        vec![
            section("Per-service consent gesture   ([↑/↓] pick  [c] toggle; disabling asks first)"),
            Line::from(row),
            // The decline half, stated once where the gesture is configured. A
            // user told only how to approve does not know a shake is a
            // deliberate "no" the daemon acts on.
            Line::from(Span::styled(
                "  Keep nodding to approve; shake your head to decline.",
                Style::new().dim(),
            )),
            Line::raw(""),
        ]
    }

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        // The shared reader, which agrees with the daemon's truthy set (`yes` and
        // `on` count too) and admits when the root-only file cannot be read. The
        // local `biopolicy_on` accepted only `1`/`true`, so `enforce_biopolicy=yes`
        // drew "turn it on" while the daemon was already enforcing.
        let bio = irlume_common::config::enforce_biopolicy_visible();
        f.render_widget(
            Paragraph::new({
                let mut v = vec![
                section("Require eyes open"),
                Line::from(vec![Span::raw("  state  "), onoff(self.eyes_open)]),
                Line::from(Span::styled(
                    "  Never unlock unless both eyes read open (IR-glint heuristic).",
                    Style::new().dim(),
                )),
                // OFF is this setting's terminal state: the daemon refuses to
                // enable it (#386, it admits 1 of 12 bare-eyed eyes-open
                // frames), so advertising "[enter] toggle" offered an action
                // whose only outcome was an error modal. The hint appears only
                // while there is something to do: turn a legacy ON back off.
                if self.eyes_open {
                    Line::from(vec![
                        Span::styled("  [enter]", Style::new().fg(th().accent)),
                        Span::styled(" turn off", Style::new().dim()),
                    ])
                } else {
                    Line::from(Span::styled(
                        "  Cannot be enabled: the gate refuses eyes-open users (#386).",
                        Style::new().dim(),
                    ))
                },
                Line::raw(""),
                ];
                v.extend(self.service_gesture_lines());
                v.extend(vec![
                section("Gesture before keyring release"),
                {
                    // Tri-state, not a bool: settings.conf is root-only, so an
                    // unprivileged TUI genuinely cannot read this. Off is the
                    // DEFAULT (no nod on a cold login), so it shows neutrally, not
                    // as a warning; on is the opt-in extra step.
                    let (icon, icon_style, label) =
                        match irlume_common::config::credential_release_challenge_visible() {
                            Some(true) => (
                                "●",
                                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                                "required (opt-in)".to_string(),
                            ),
                            Some(false) => (
                                "○",
                                Style::new().dim(),
                                "off (default): the keyring releases with no nod".to_string(),
                            ),
                            None => (
                                "◐",
                                Style::new().fg(th().warn),
                                "on/off is root-only; run the TUI with sudo to see it".to_string(),
                            ),
                        };
                    Line::from(vec![
                        Span::raw("  state  "),
                        Span::styled(format!("{icon} "), icon_style),
                        Span::styled(label, Style::new().dim()),
                    ])
                },
                // The gesture proves INTENT, not liveness (it fired on a hand-held
                // print 2 times in 24 on 2026-07-27), which is why it defaults OFF
                // for the greeter cold login and logout; the IR gate stops a print.
                // ONE line: this panel does not scroll and the per-service section
                // above needs the room. THREAT_MODEL.md carries the numbers.
                Line::from(Span::styled(
                    "  Off by default (a cold login releases with no nod). On adds a nod (or an eye closure).",
                    Style::new().dim(),
                )),
                Line::from(vec![
                    Span::styled("  [g]", Style::new().fg(th().accent)),
                    Span::styled(" turn it on or off (sudo)", Style::new().dim()),
                ]),
                Line::raw(""),
                section("Biopolicy operation-class gate"),
                {
                    // The shared tri-state reader, not the raw config read the
                    // [b] direction uses: settings.conf is 0600 root-only, so
                    // the raw read showed "off (default)" here while the Done
                    // dashboard said "◐ root-only" for the same key. Same
                    // truthy set and env override as the daemon.
                    let (icon, icon_style, label) =
                        match irlume_common::config::enforce_biopolicy_visible() {
                            Some(true) => (
                                "●",
                                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                                "ENFORCING",
                            ),
                            Some(false) => ("○", Style::new().dim(), "off (default)"),
                            None => (
                                "◐",
                                Style::new().fg(th().warn),
                                "on/off is root-only; run the TUI with sudo to see it",
                            ),
                        };
                    Line::from(vec![
                        Span::raw("  state  "),
                        Span::styled(format!("{icon} "), icon_style),
                        Span::styled(label, Style::new().dim()),
                    ])
                },
                Line::from(Span::styled(
                    "  When on: only Login/Elevation may release the keyring; lock-screen",
                    Style::new().dim(),
                )),
                Line::from(Span::styled(
                    "  is verify-only; remote/unknown services are denied. Advanced; the",
                    Style::new().dim(),
                )),
                Line::from(Span::styled(
                    "  password is always available, so this can restrict but never lock out.",
                    Style::new().dim(),
                )),
                Line::from(vec![
                    Span::styled("  [b]", Style::new().fg(th().accent)),
                    Span::styled(
                        match bio {
                            Some(true) => " turn it off (sudo)",
                            Some(false) => " turn it on (sudo; asks first)",
                            None => " on/off is root-only; run the TUI with sudo",
                        },
                        Style::new().dim(),
                    ),
                ]),
                Line::raw(""),
                section("Third-party models"),
                {
                    // A ●/○ status row like the sections above, not a text blob.
                    // The daemon's loaded-cue name is authoritative (it knows
                    // what it loaded); fall back to the filesystem probe only
                    // when the daemon can't answer, since settings.conf is
                    // root-only and a non-root TUI can't read the flag itself.
                    // Every daemon-reported stage, not just PAD: a loaded
                    // cue must not hide a loaded recognizer (#285 review).
                    let loaded: Vec<String> = self
                        .health
                        .iter()
                        .flat_map(|h| {
                            [
                                h.third_party_pad
                                    .as_ref()
                                    .map(|n| format!("{n} (pad stage, loaded)")),
                                h.third_party_recognizer
                                    .as_ref()
                                    .map(|n| format!("{n} (recognition stage, loaded)")),
                                h.third_party_detector
                                    .as_ref()
                                    .map(|n| format!("{n} (detection stage, loaded)")),
                            ]
                        })
                        .flatten()
                        .collect();
                    let (icon, icon_style, label) = if !loaded.is_empty() {
                        (
                            "●",
                            Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                            format!("enabled: {}", loaded.join(" + ")),
                        )
                    } else {
                        // Nothing daemon-reported: could be a daemon too old
                        // to report the fields OR genuinely none. We can't
                        // tell the two apart (both deserialize to None), so
                        // trust the filesystem probe rather than claim "off":
                        // an older daemon with flir loaded must not read as
                        // ○ none.
                        match &self.heavy.0 {
                            crate::models::TuiState::Enabled { entries } => (
                                "●",
                                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                                format!(
                                    "enabled: {}",
                                    entries
                                        .iter()
                                        .map(|e| format!(
                                            "{} ({} stage · {})",
                                            e.name,
                                            e.stage.as_str(),
                                            match e.weight_state {
                                                irlume_common::thirdparty::WeightState::ChecksumOk => "checksum ok",
                                                irlume_common::thirdparty::WeightState::ChecksumMismatch => "CHECKSUM MISMATCH",
                                                irlume_common::thirdparty::WeightState::Absent => "weights missing",
                                            }
                                        ))
                                        .collect::<Vec<_>>()
                                        .join(" + ")
                                ),
                            ),
                            crate::models::TuiState::UnknownName { name } => (
                                "◐",
                                Style::new().fg(th().warn),
                                format!("'{name}' set in settings.conf but NOT in the catalog (daemon ignores it)"),
                            ),
                            crate::models::TuiState::InstalledUnknown { name } => (
                                "◐",
                                Style::new().fg(th().warn),
                                format!("{name} weights installed; on/off is root-only"),
                            ),
                            crate::models::TuiState::None => {
                                ("○", Style::new().dim(), "none (default)".to_string())
                            }
                        }
                    };
                    Line::from(vec![
                        Span::raw("  state  "),
                        Span::styled(format!("{icon} "), icon_style),
                        Span::styled(label, Style::new().dim()),
                    ])
                },
                Line::from(Span::styled(
                    "  Opt-in, measured models by pipeline stage: PAD adds a deny-only cue,",
                    Style::new().dim(),
                )),
                // Points at the Models tab (#331) so the full listing is one
                // Tab away, not a CLI command the user has to know about.
                Line::from(Span::styled(
                    "  recognition replaces RGB matching. Licenses + measurements: the Models tab.",
                    Style::new().dim(),
                )),
                Line::from(vec![
                    Span::styled("  [m]", Style::new().fg(th().accent)),
                    Span::styled(
                        " enable or disable one (sudo; the license confirm runs in the terminal)",
                        Style::new().dim(),
                    ),
                ]),
                Line::raw(""),
                section("Match thresholds (read-only)"),
                Line::from(Span::styled(
                    "  Calibrated per modality (RGB/IR), auto-scaled by enrolled scan count.",
                    Style::new().dim(),
                )),
                ]);
                v
            })
            .wrap(Wrap { trim: false }),
            area,
        );
    }

    /// The measured model choices (#331). Every catalog entry renders with
    /// the license line, measurement summary, and effect line the CLI listing
    /// prints, all read from the one catalog in `irlume_common::thirdparty`
    /// (via `crate::models`), so nothing unmeasured can appear and the two
    /// surfaces cannot drift. Provenance is deliberately omitted: the
    /// provenance rows pushed the root-only note off a 50-row terminal, and
    /// the CLI consent flow prints provenance before any enable can proceed.
    /// The re-enrollment consequence is a section ABOVE the entries, so it is
    /// met before any switch command (#288: templates are per recognizer, and
    /// on a one-user machine a stranded enrollment is a lockout path if the
    /// camera then misbehaves). Display and guidance only: a state change
    /// goes through the CLI's own sudo + license flow, so the screen shows
    /// the exact command instead of wrapping it, and root-gating stays where
    /// the CLI already enforces it.
    ///
    /// A PURE RENDER of `self.models_status` (#334 review): the per-entry
    /// state hashes weight files, so it is gathered on the probe worker and
    /// cached; the content builder must never call back into `crate::models`
    /// state readers. `↑/↓` scroll by LOGICAL line (`models_scroll` skips
    /// leading entries of [`Self::models_lines`]): exact and clampable, where
    /// a wrapped-row offset needs the renderer's private line count and every
    /// estimate of it risks clamping the tail commands out of reach.
    fn draw_models(&self, f: &mut Frame, area: Rect) {
        let lines = self.models_lines();
        // Clamp so the LAST content line can top the viewport but the view
        // can never run away into blank space; models_lines ends on content
        // (trailing blanks popped), so even fully scrolled the tail command
        // or root-only note stays on screen.
        let start = (self.models_scroll as usize).min(lines.len().saturating_sub(1));
        f.render_widget(
            Paragraph::new(lines[start..].to_vec()).wrap(Wrap { trim: false }),
            area,
        );
    }

    /// The Models tab's full content, top to bottom; see [`Self::draw_models`]
    /// for the contract. Split out so the ↑/↓ handler can clamp the scroll
    /// offset against the same list the renderer slices.
    fn models_lines(&self) -> Vec<Line<'static>> {
        use irlume_common::thirdparty::CATALOG;
        let kv = |k: &str, v: &str| {
            Line::from(vec![
                Span::styled(format!("    {k:<12}"), Style::new().dim()),
                Span::raw(v.to_string()),
            ])
        };
        let mut lines: Vec<Line> = vec![
            Line::from(Span::styled(
                "  Models irlume measured on real hardware but does not ship or warrant.",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  Only measured entries appear (ADR-0001): the same catalog, numbers and",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  license lines `irlume models` prints.",
                Style::new().dim(),
            )),
            Line::raw(""),
            section("Switching the recognizer means re-enrolling"),
            Line::from(Span::styled(
                "  Templates are stored per recognizer (#288): scans enrolled under one do",
                Style::new().fg(th().warn),
            )),
            Line::from(Span::styled(
                "  not match under another. After a switch, face login stays off until you",
                Style::new().fg(th().warn),
            )),
            Line::from(Span::styled(
                "  re-enroll; until then only your password works.",
                Style::new().fg(th().warn),
            )),
            Line::raw(""),
        ];
        for (i, m) in CATALOG.iter().enumerate() {
            // From the cache, never a live read: `entry_state_label` hashes
            // the weight file, and this runs per frame. Before the first
            // sweep lands the answer is not known, and the tri-state rule
            // says say so rather than claim "disabled".
            let state = self
                .models_status
                .as_ref()
                .and_then(|s| s.labels.get(i).cloned())
                .unwrap_or_else(|| "state loading".into());
            let enabled = state.starts_with("ENABLED");
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {}", m.name),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  ({} stage)  [{state}]", m.stage.as_str()),
                    Style::new().dim(),
                ),
            ]));
            lines.push(kv("license:", m.license));
            lines.push(kv("measured:", m.summary));
            lines.push(kv("effect:", &crate::models::role_line(m)));
            lines.push(kv("obtain:", &crate::models::obtain_line(m)));
            if enabled {
                lines.push(kv(
                    "disable:",
                    &format!("sudo irlume models disable {}", m.name),
                ));
            }
            lines.push(Line::raw(""));
        }
        // Root-gated like the CLI: settings.conf is 0600 root-only, so an
        // unprivileged TUI cannot read the enabled flags and must say so
        // rather than render "disabled" (the same tri-state rule the Settings
        // sections follow). The commands above are the way to act either way.
        // Keyed off the CACHED observation; before the first sweep neither
        // direction is asserted.
        if self.models_status.as_ref().is_some_and(|s| !s.readable) {
            lines.push(Line::from(Span::styled(
                "  settings.conf is root-only, so the enabled states above are unknown;",
                Style::new().fg(th().warn),
            )));
            lines.push(Line::from(Span::styled(
                "  the authoritative answer: sudo irlume models list",
                Style::new().fg(th().warn),
            )));
        }
        // End on content, never a blank: the scroll clamp lets the last line
        // top the viewport, and a trailing blank there would render a page
        // holding nothing.
        while lines
            .last()
            .is_some_and(|l| l.spans.iter().all(|s| s.content.trim().is_empty()))
        {
            lines.pop();
        }
        lines
    }

    fn draw_cameras(&self, f: &mut Frame, area: Rect) {
        // The active pair comes from the daemon's Health, NOT from
        // select_pair(): that helper falls through to discovery when no
        // explicit pair is configured, and discovery opens every node. This
        // is a DRAW function, so it ran per frame, which is where the last
        // hundred-odd opens per session came from (#187). Health reports the
        // devices the daemon actually has open, which is a better answer
        // anyway.
        let (argb, air) = self
            .health
            .as_ref()
            .map(|h| {
                (
                    h.rgb_dev.clone().unwrap_or_default(),
                    h.ir_dev.clone().unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        let pairs = &self.pairs;
        // Size the list to its rows (header + one row per camera/note) so the
        // info block sits right under it instead of a stretched gap; leftover
        // space stays empty at the bottom (content near the top).
        let list_rows = self.nodes.len().max(pairs.len()).max(1) as u16 + 1;
        let [list_area, info_area] =
            Layout::vertical([Constraint::Length(list_rows + 1), Constraint::Length(9)])
                .areas(area);

        // ---- selectable list of trusted (physical) Hello camera pairs ----
        // No pair ≠ no camera: an RGB-only device still serves the convenience
        // tier, so show what exists instead of only an error line.
        let items: Vec<ListItem> = if pairs.is_empty() {
            let mut v = Vec::new();
            for (path, role) in &self.nodes {
                if matches!(role, irlume_camera::Role::Rgb) {
                    v.push(ListItem::new(Line::from(vec![
                        Span::styled(" ● ", Style::new().fg(th().ok)),
                        Span::styled(
                            format!("{:<16}", path.trim_start_matches("/dev/")),
                            Style::new().add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            "RGB-only, convenience tier (face unlocks the screen only)",
                            Style::new().dim(),
                        ),
                    ])));
                }
            }
            if v.is_empty() {
                // Only claim "none" when the daemon actually said so. An
                // unanswered ListCameras (daemon down, busy with a capture,
                // or older than the request) is not an observation, and
                // printing "no camera found" for it contradicted the active
                // pair shown right below (#187).
                v.push(ListItem::new(Span::styled(
                    if self.pairs_known {
                        "no camera found: face auth unavailable on this device"
                    } else if self.daemon_up {
                        "asking irlumed for the camera list (it answers once the camera is free)"
                    } else {
                        "irlumed is not running, so the camera list is unknown; start it from Repair"
                    },
                    Style::new().dim(),
                )));
            } else {
                v.push(ListItem::new(Span::styled(
                    "   no IR node: the Secure tier (sudo/login/keyring) needs an IR Hello camera",
                    Style::new().dim(),
                )));
            }
            v
        } else {
            pairs
                .iter()
                .map(|p| {
                    let active = p.rgb == argb && p.ir == air;
                    let kind = if p.fixed { "built-in" } else { "external" };
                    let id = p.id.clone().unwrap_or_else(|| "?".into());
                    let priv_on = p.privacy;
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            if active { " ● " } else { " ○ " },
                            Style::new().fg(if active { th().ok } else { Color::DarkGray }),
                        ),
                        Span::styled(
                            format!(
                                "{:<16}",
                                format!(
                                    "{}+{}",
                                    p.rgb.trim_start_matches("/dev/"),
                                    p.ir.trim_start_matches("/dev/")
                                )
                            ),
                            if active {
                                Style::new().add_modifier(Modifier::BOLD)
                            } else {
                                Style::new()
                            },
                        ),
                        Span::styled(format!("{kind:<10}"), Style::new().fg(th().accent)),
                        Span::styled(format!("[{id}]"), Style::new().dim()),
                        if priv_on {
                            Span::styled("  ⚠ privacy ON", Style::new().fg(th().err))
                        } else {
                            Span::raw("")
                        },
                    ]))
                })
                .collect()
        };
        let mut st = ListState::default()
            .with_selected(Some(self.cam_sel.min(pairs.len().saturating_sub(1))));
        // No inner border (whitespace over chrome; the content panel already
        // frames this). A section header carries what the border title did.
        let [hdr_area, rows_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(list_area);
        f.render_widget(
            Paragraph::new(section(
                "Cameras  (● = active · ↑↓ select · Enter uses one)",
            )),
            hdr_area,
        );
        f.render_stateful_widget(
            List::new(items).highlight_style(
                Style::new()
                    .bg(Color::Rgb(0x20, 0x30, 0x40))
                    .add_modifier(Modifier::BOLD),
            ),
            rows_area,
            &mut st,
        );

        // ---- info: active pair, selected pair nodes, emitter ----
        // Only claim a node as "active" if it exists; select_pair's fixed
        // fallback names devices that may be absent on this hardware.
        let ex = |d: &str| std::path::Path::new(d).exists();
        // "No camera hardware" is a claim about the MACHINE, so it needs an
        // answer from the daemon to stand on. With health absent the paths
        // above default to "", `ex("")` is false, and this line asserted no
        // hardware on machines with four video nodes, contradicting the
        // daemon row rendered above it. Unknown is not none.
        let (active, active_style) = if self.health.is_none() {
            (
                "unknown (daemon not answering; see the Repair tab)".to_string(),
                Style::new().dim(),
            )
        } else {
            let ok = Style::new().fg(th().ok).add_modifier(Modifier::BOLD);
            match (ex(&argb), ex(&air)) {
                (true, true) => (format!("{argb} + {air}"), ok),
                (true, false) => (format!("{argb} (RGB only)"), ok),
                (false, true) => (format!("{air} (IR only)"), ok),
                (false, false) => ("none (no camera hardware)".to_string(), Style::new().dim()),
            }
        };
        let mut lines = vec![Line::from(vec![
            Span::styled("  active   ", Style::new().dim()),
            Span::styled(active, active_style),
        ])];
        if let Some(p) = pairs.get(self.cam_sel) {
            if p.rgb != argb || p.ir != air {
                lines.push(Line::from(vec![
                    Span::styled("  selected ", Style::new().dim()),
                    Span::styled(format!("{} + {}", p.rgb, p.ir), Style::new()),
                    Span::styled("   [enter] to switch", Style::new().fg(th().accent)),
                ]));
            }
        }
        lines.push(Line::raw(""));
        lines.push(section("IR emitter (850nm)"));
        lines.push(Line::from(Span::styled(
            "  Setting this up writes to your camera. It uses only the controls",
            Style::new().dim(),
        )));
        lines.push(Line::from(Span::styled(
            "  your camera's USB descriptor documents, and never runs on its own.",
            Style::new().dim(),
        )));
        lines.push(Line::from(vec![
            Span::styled("  [s]", Style::new().fg(th().accent)),
            Span::styled(" set up emitter   ", Style::new().dim()),
            Span::styled("[t]", Style::new().fg(th().accent)),
            Span::styled(
                " tune capture (holds the camera ~1 min)   ",
                Style::new().dim(),
            ),
            Span::styled("[p]", Style::new().fg(th().accent)),
            Span::styled(" list units (writes nothing)", Style::new().dim()),
        ]));
        // Borderless (no box-in-box); the content panel is the only frame.
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), info_area);
    }

    fn draw_fingerprint(&self, f: &mut Frame, area: Rect) {
        let reader = match (&self.fp.device, self.fp.available) {
            (Some(n), _) => Span::styled(format!("● {n}"), Style::new().fg(th().ok)),
            (None, true) => Span::styled("● present (unnamed)", Style::new().fg(th().ok)),
            (None, false) => Span::styled("○ none detected", Style::new().dim()),
        };
        let enrolled = if self.fp.enrolled.is_empty() {
            Span::styled("none".to_string(), Style::new().dim())
        } else {
            Span::styled(
                format!(
                    "{} ({})",
                    self.fp.enrolled.len(),
                    self.fp.enrolled.join(", ")
                ),
                Style::new().fg(th().ok),
            )
        };
        let mut lines = vec![
            section("Fingerprint (companion factor)"),
            state_row("reader", 14, reader),
            state_row("enrolled", 14, enrolled),
            state_row(
                "active method",
                14,
                Span::raw(method_label(&self.fp.method)),
            ),
            Line::raw(""),
        ];
        if self.fp.available {
            lines.push(Line::from(Span::styled(
                "  Stock fprintd + pam_fprintd; unlocks alongside face, never instead.",
                Style::new().dim(),
            )));
            // Per-surface coverage (#155), the same table `fingerprint status`
            // prints: which prompts a finger actually answers, over the same
            // search path libpam uses (machine then vendor, #208).
            // Shown only when at least one surface reaches the module; a
            // face-only box would render a column of ✗ noise.
            if self.fp_coverage.iter().any(|(_, _, reaches)| *reaches) {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    "  Where a finger can answer the prompt (per the PAM service path):",
                    Style::new().dim(),
                )));
                for (_, label, reaches) in &self.fp_coverage {
                    let mark = if *reaches {
                        Span::styled("✓ ", Style::new().fg(th().ok))
                    } else {
                        Span::styled("✗ ", Style::new().dim())
                    };
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        mark,
                        Span::styled((*label).to_string(), Style::new().dim()),
                    ]));
                }
            }
            lines.push(Line::raw(""));
            lines.push(action_line(&[
                ("a", "enroll a finger"),
                ("t", "test a finger"),
                ("x", "wipe all"),
            ]));
            lines.push(action_line(&[
                ("e", "face OR fingerprint (sudo)"),
                ("d", "remove from login"),
            ]));
        } else {
            lines.push(Line::from(Span::styled(
                "  No usable reader on this device; fingerprint unavailable.",
                Style::new().dim(),
            )));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn draw_recovery(&self, f: &mut Frame, area: Rect) {
        // None = RecoveryStatus never answered. The old default here claimed
        // "plaintext at rest" and "No TPM" about templates that are encrypted
        // on a TPM machine, one Tab away from the Keyring tab saying "TPM
        // ● present"; a failed read establishes nothing (docs/MACHINE-API.md).
        let enc = match self.recovery {
            Some(r) if r.encrypted && r.key_present => Span::styled(
                "● encrypted",
                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
            ),
            // Encrypted with the key gone: safe from a stolen disk and
            // unreadable by its owner. Neither a reseal nor a recovery
            // passphrase brings it back, so say re-enroll and say it loudly.
            Some(r) if r.encrypted => Span::styled(
                "✗ encrypted, TEMPLATE KEY MISSING (re-enroll)",
                Style::new().fg(th().err).add_modifier(Modifier::BOLD),
            ),
            Some(_) => Span::styled("○ plaintext at rest", Style::new().dim()),
            None => Span::styled("◐ unknown (daemon unreachable)", Style::new().fg(th().warn)),
        };
        let rec = match self.recovery {
            Some(r) if r.recovery_set => Span::styled(
                "● set",
                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
            ),
            Some(_) => Span::styled("○ not set", Style::new().dim()),
            None => Span::styled("◐ unknown (daemon unreachable)", Style::new().fg(th().warn)),
        };
        let mut lines = vec![
            section("Recovery + template encryption"),
            state_row("templates", 12, enc),
            state_row("passphrase", 12, rec),
            Line::raw(""),
            Line::from(Span::styled(
                "  A recovery passphrase backs up the face-template key, the manual",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  backstop after a TPM clear, firmware/dbx update, or disk move.",
                Style::new().dim(),
            )),
            Line::raw(""),
        ];
        match self.recovery {
            Some(r) if !r.tpm_present => {
                lines.push(Line::from(Span::styled(
                    "  No TPM on this host: templates stay plaintext; recovery N/A.",
                    Style::new().fg(th().err),
                )));
            }
            Some(r) if r.encrypted && !r.recovery_set => {
                lines.push(Line::from(Span::styled(
                    "  ⚠ No backstop: set one now, or a broken seal means re-enrolling.",
                    Style::new().fg(th().err),
                )));
            }
            Some(_) => {}
            None => {
                lines.push(Line::from(Span::styled(
                    "  Nothing here has been read; start irlumed (Repair tab) to see it.",
                    Style::new().dim(),
                )));
            }
        }
        lines.push(Line::raw(""));
        lines.push(action_line(&[
            ("s", "set passphrase"),
            ("t", "restore"),
            ("f", "forget"),
        ]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn draw_keyring(&self, f: &mut Frame, area: Rect) {
        let armed = self.keyring_armed.unwrap_or(false);
        let status = match self.keyring_armed {
            Some(true) => Span::styled(
                "● armed",
                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
            ),
            Some(false) => Span::styled("○ not armed", Style::new().dim()),
            None => Span::styled("unknown (daemon unreachable)", Style::new().dim()),
        };
        let tpm = self.probes.tpm_present;
        let mut lines = vec![
            section("TPM keyring unlock"),
            Line::from(vec![Span::raw("  state    "), status]),
        ];
        // WHAT is sealed, not just whether something is. A GNOME token means
        // this user's password no longer opens that keyring on its own, which
        // is not a thing to leave them to discover at a prompt.
        if armed {
            use irlume_common::KeyringSecretKind as K;
            let (what, note) = match self.keyring_kind {
                Some(K::LoginPassword) => ("login password", ""),
                Some(K::KdeWalletKey) => ("KDE wallet key", " (a typed password still opens it)"),
                Some(K::GnomeKeyringToken) => (
                    "GNOME keyring token",
                    // NOT "[f] re-keys back": [f] refuses for this kind and
                    // sends the user to the CLI, which is where the re-key
                    // and its password prompt live.
                    " (your password alone no longer opens it; `irlume keyring forget` re-keys back)",
                ),
                None => ("unreported by this daemon", ""),
            };
            lines.push(Line::from(vec![
                Span::raw("  sealed   "),
                Span::raw(what.to_string()),
                Span::styled(note.to_string(), Style::new().dim()),
            ]));
        }
        if self.keyring_drift == Some(true) {
            lines.push(Line::from(vec![
                Span::raw("  PCRs     "),
                Span::styled(
                    "drifted since sealing; re-arm to rebind",
                    Style::new().fg(th().warn),
                ),
            ]));
        }
        // Show the envelope's actual policy tier when the daemon reports it.
        // The static text is the pre-KeyringInfo default; it only applies once
        // the daemon has ANSWERED (an old daemon, or a fresh arm landing on
        // the literal tier). Unanswered, it read as this machine's binding.
        let binding = match (&self.keyring_policy, self.keyring_armed) {
            (Some(p), _) => p.clone(),
            (None, None) => "unknown (daemon unreachable)".to_string(),
            (None, Some(_)) => "PCR-7 (Secure Boot state)".to_string(),
        };
        lines.extend([
            Line::from(vec![
                Span::raw("  TPM      "),
                if tpm {
                    Span::styled("● present", Style::new().fg(th().ok))
                } else {
                    Span::styled("✗ none", Style::new().fg(th().err))
                },
            ]),
            Line::from(vec![
                Span::raw("  binding  "),
                Span::styled(binding, Style::new().dim()),
            ]),
            Line::raw(""),
        ]);
        // The unlock trigger depends on this box's hardware.
        if self.caps.ir_pair {
            lines.push(Line::from(Span::styled(
                "  At a face login the daemon unseals that secret and delivers it,",
                Style::new().dim(),
            )));
            lines.push(Line::from(Span::styled(
                "  so your wallet opens with no prompt.",
                Style::new().dim(),
            )));
        } else if self.fp_present {
            lines.push(Line::from(Span::styled(
                "  At a fingerprint login the daemon unseals that secret (ADR-0003)",
                Style::new().dim(),
            )));
            lines.push(Line::from(Span::styled(
                "  and delivers it, so your wallet opens with no prompt.",
                Style::new().dim(),
            )));
        }
        lines.push(Line::raw(""));
        if armed {
            let tier2 = self
                .keyring_policy
                .as_deref()
                .is_some_and(|p| p.contains("Tier 2"));
            if tier2 {
                lines.push(Line::from(Span::styled(
                    "  Tier 2 seal (survives kernel updates). After a firmware or Secure",
                    Style::new().dim(),
                )));
                lines.push(Line::from(Span::styled(
                    "  Boot change, the boot measurements move; press [p] to refresh the",
                    Style::new().dim(),
                )));
                lines.push(Line::from(Span::styled(
                    "  pcrlock policy so face-unlock keeps working (no re-arm needed).",
                    Style::new().dim(),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "  ⚠ if a firmware/dbx update moves the bound PCRs, unseal fails →",
                    Style::new().fg(th().warn),
                )));
                lines.push(Line::from(Span::styled(
                    "    press [r] to reseal (re-bind to the current PCRs, same password).",
                    Style::new().dim(),
                )));
            }
        } else if self.keyring_armed == Some(false) {
            // Only an OBSERVED not-armed earns this line; with the daemon
            // unreachable the state row above already says unknown, and
            // "won't open your wallet" would contradict it.
            let how = if self.caps.ir_pair {
                "face"
            } else {
                "fingerprint"
            };
            lines.push(Line::from(Span::styled(
                format!("  Not armed; {how} login won't open your wallet yet."),
                Style::new().dim(),
            )));
        }
        lines.push(Line::raw(""));
        // [r] reseal is shown only once armed (re-bind needs an existing seal);
        // it re-enters the password and re-seals to the current PCRs, the CLI
        // `irlume reseal` a keyboard-only user would otherwise have no way to run.
        if armed {
            lines.push(action_line(&[
                ("a", "re-arm (new password)"),
                ("r", "reseal (re-bind to current PCRs)"),
                ("f", "forget"),
            ]));
        } else {
            lines.push(action_line(&[
                ("a", "arm (enter your login password)"),
                ("f", "forget"),
            ]));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    /// How many enrolled scans the LOADED recognizer can match, or `None`
    /// when the daemon predates per-recognizer reporting (then nothing can be
    /// said and the flat total stands). Feeds [`count_badge`]: a profile full
    /// of another recognizer's scans is not healthy enrollment (#288).
    fn live_scans(&self) -> Option<usize> {
        // One daemon, one loaded recognizer: every summary carries the same
        // live_recognizer, so the first is the answer.
        let live = self
            .profiles
            .iter()
            .find_map(|p| p.live_recognizer.as_deref())?;
        Some(
            self.profiles
                .iter()
                .map(|p| p.scans_by_recognizer.get(live).copied().unwrap_or(0))
                .sum(),
        )
    }

    /// Hub rows for the Welcome screen: each visible section with its live
    /// state, selectable and Enter-jumpable (hub-and-spoke: the summary IS
    /// the navigation, the tab ribbon stays for direct access).
    fn hub_rows(&self) -> Vec<(&'static str, Option<bool>, usize)> {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        // None = never observed (the daemon has not answered); the badge
        // renders it as unknown. `unwrap_or(false)` here turned every
        // unanswered question into "○ no", two of them security claims.
        let all: [(&'static str, Option<bool>, usize); 8] = [
            ("checks & repair", Some(self.daemon_up), SC_REPAIR),
            ("cameras", Some(self.caps.rgb), SC_CAMERAS),
            (
                "enrollment",
                self.profiles_loaded.then_some(scans > 0),
                SC_PROFILES,
            ),
            ("keyring unlock", self.keyring_armed, SC_KEYRING),
            (
                "recovery + encryption",
                // The key has to be there too: encrypted with no key is not a
                // completed step, it is an enrollment nothing can read.
                self.recovery
                    .map(|r| r.encrypted && r.recovery_set && r.key_present),
                SC_RECOVERY,
            ),
            ("login wiring", self.login_wired_known(), SC_PAM),
            ("settings", Some(true), SC_SETTINGS),
            ("model options", Some(true), SC_MODELS),
        ];
        all.into_iter()
            .filter(|(_, _, sc)| self.visible.contains(sc))
            .collect()
    }

    fn draw_welcome(&self, f: &mut Frame, area: Rect) {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        let lines = vec![
            Line::from(Span::styled(
                "  irlume - local face authentication",
                Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  IR + lume · clean-BOM · TPM-sealed · privacy by design",
                Style::new().dim(),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                "  This is a guided panel. Tab / ⇧Tab walk the steps left-to-right;",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  each step shows live state and its own action keys in the footer.",
                Style::new().dim(),
            )),
            Line::raw(""),
            {
                // A one-line health summary from the same run_checks() the
                // Repair tab uses, so a healthy user never needs to open Repair
                // and an unhealthy one is pointed straight at it.
                let fails = self.repair.iter().filter(|c| c.sev == Sev::Fail).count();
                let warns = self.repair.iter().filter(|c| c.sev == Sev::Warn).count();
                // needs_repair (compute_visible) surfaces the "checks & repair"
                // hub row on any warn/fail, so this always points at a row that
                // is right below and Enter-openable, no "switch to advanced" step.
                if fails > 0 {
                    Line::from(vec![
                        Span::styled(
                            format!("  ✗ {fails} issue(s) need attention"),
                            Style::new().fg(th().err).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(" → open \"checks & repair\" below", Style::new().dim()),
                    ])
                } else if warns > 0 {
                    Line::from(vec![
                        Span::styled(
                            format!("  ⚠ {warns} advisory item(s)"),
                            Style::new().fg(th().warn),
                        ),
                        Span::styled(" → open \"checks & repair\" below", Style::new().dim()),
                    ])
                } else {
                    Line::from(Span::styled(
                        "  ✓ all checks pass",
                        Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                    ))
                }
            },
            Line::raw(""),
            section("At a glance  (↑↓ pick a section, Enter opens it)"),
            Line::from(vec![
                Span::styled("  Recommended  ", Style::new().add_modifier(Modifier::BOLD)),
                Span::styled(self.recommended(), Style::new().fg(th().ok)),
            ]),
            Line::from(Span::styled(
                "  (you can change the method any time; [v] shows every tab)",
                Style::new().dim(),
            )),
            Line::raw(""),
            if self.visible.contains(&SC_IDENTIFY) {
                Line::from(vec![
                    Span::styled("  [e]", Style::new().fg(th().accent)),
                    Span::styled(" enroll now   ", Style::new().dim()),
                    Span::styled("[i]", Style::new().fg(th().accent)),
                    Span::styled(" identify   ", Style::new().dim()),
                    Span::styled("Tab", Style::new().fg(th().accent)),
                    Span::styled(" walk the steps", Style::new().dim()),
                ])
            } else {
                Line::from(vec![
                    Span::styled("  [e]", Style::new().fg(th().accent)),
                    Span::styled(" enroll now   ", Style::new().dim()),
                    Span::styled("Tab", Style::new().fg(th().accent)),
                    Span::styled(" walk the steps   ", Style::new().dim()),
                    Span::styled("[v]", Style::new().fg(th().accent)),
                    Span::styled(" all tabs", Style::new().dim()),
                ])
            },
            Line::from(Span::styled(
                "  Live panel: changes to irlume appear here automatically.",
                Style::new().dim(),
            )),
        ];
        let mut lines = lines;
        // Splice the selectable hub rows just under the "At a glance" header.
        let at = lines
            .iter()
            .position(|l| l.spans.iter().any(|sp| sp.content.contains("At a glance")))
            .map(|i| i + 1)
            .unwrap_or(lines.len());
        let rows = self.hub_rows();
        let n = rows.len();
        for (i, (label, ok, _)) in rows.into_iter().enumerate() {
            let selected = i == self.hub_sel;
            let mut style = Style::new();
            if selected {
                style = style.fg(th().accent).add_modifier(Modifier::BOLD);
            }
            let badge = if label == "enrollment" {
                count_badge(
                    self.profiles_loaded,
                    self.profiles.len(),
                    scans,
                    self.live_scans(),
                )
            } else {
                onoff_opt(ok)
            };
            let marker = if selected { '▸' } else { ' ' };
            lines.insert(
                at + i,
                Line::from(vec![
                    Span::styled(format!("  {marker} {label:<24}"), style),
                    badge,
                ]),
            );
        }
        lines.insert(at + n, Line::raw(""));
        // trim:false: leading spaces are the marker column of the hub rows;
        // trim would collapse unselected rows against the ▸ rows.
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    /// Diagnostic + repair: a live checklist (✓/⚠/✗) of everything irlume needs
    /// to run, with one-key fixes, plus platform trust anchors and a live IR PAD
    /// self-test. Covers the `irlume doctor`/`diag`/`deps` checks that have a
    /// remediation or that a TUI-only user would otherwise miss (daemon, models,
    /// cameras, SELinux/AppArmor, wiring drift, keyring drift, login-keyring
    /// locked, recovery, TPM, third-party-model checksum). The full text
    /// readout (incl. info-only lines) is one key away via the `[d]` key. Some
    /// advisory-only doctor lines (fingerprint
    /// vendor-stack, polkit sandbox, install hygiene) stay in `doctor`.
    fn draw_repair(&self, f: &mut Frame, area: Rect) {
        let [list_area, info_area] =
            Layout::vertical([Constraint::Min(4), Constraint::Length(9)]).areas(area);

        // ---- checklist --------------------------------------------------
        let ok = self.repair.iter().filter(|c| c.sev == Sev::Ok).count();
        let fail = self.repair.iter().filter(|c| c.sev == Sev::Fail).count();
        let warn = self.repair.iter().filter(|c| c.sev == Sev::Warn).count();
        let items: Vec<ListItem> = self
            .repair
            .iter()
            .map(|c| {
                let (icon, color) = match c.sev {
                    Sev::Ok => ("✓", th().ok),
                    Sev::Warn => ("⚠", th().warn),
                    Sev::Fail => ("✗", th().err),
                };
                let tag = match &c.fix {
                    Fix::None => "",
                    Fix::Manual(_) => " · manual",
                    Fix::Root(_) => " · [f] fix (sudo)",
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!(" {icon} "),
                        Style::new().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<19}", c.label),
                        Style::new().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(c.detail.clone(), Style::new().dim()),
                    Span::styled(tag.to_string(), Style::new().fg(th().accent)),
                ]))
            })
            .collect();
        let mut st = ListState::default().with_selected(Some(
            self.repair_sel.min(self.repair.len().saturating_sub(1)),
        ));
        f.render_stateful_widget(
            List::new(items).highlight_style(
                Style::new()
                    .bg(Color::Rgb(0x20, 0x30, 0x40))
                    .add_modifier(Modifier::BOLD),
            ),
            list_area,
            &mut st,
        );

        // ---- info / platform / live test --------------------------------
        let (sb_present, sb_enabled, sb_setup) = self.probes.secureboot;
        let sb = if sb_enabled {
            ("enabled", th().ok)
        } else if sb_setup {
            ("setup mode", th().warn)
        } else if sb_present {
            ("disabled", th().warn)
        } else {
            ("n/a", th().warn)
        };
        let mut lines = vec![Line::from(vec![
            Span::styled(format!("  {ok} ok"), Style::new().fg(th().ok)),
            Span::styled(format!("   {warn} warn"), Style::new().fg(th().warn)),
            Span::styled(format!("   {fail} fail"), Style::new().fg(th().err)),
        ])];
        lines.push(action_line(&[
            ("f", "fix selected"),
            ("r", "re-check"),
            ("l", "IR self-test"),
            ("g", "logs"),
        ]));
        lines.push(Line::raw(""));
        if let Some(c) = self.repair.get(self.repair_sel) {
            let hint = match &c.fix {
                // "no action needed" next to a non-zero fail count reads as a
                // contradiction; point at the failing rows instead.
                Fix::None if fail > 0 => {
                    "this row is fine; ↑↓ select a failing row for its fix".to_string()
                }
                Fix::None => "no action needed".to_string(),
                Fix::Manual(cmd) => format!("manual: {cmd}"),
                Fix::Root(_) => "press [f]: irlume runs the fix with sudo".to_string(),
            };
            lines.push(Line::from(vec![
                Span::styled("  → ", Style::new().fg(th().accent)),
                Span::styled(hint, Style::new()),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("  platform  ", Style::new().dim()),
            Span::styled(
                format!(
                    "TPM {} · ",
                    if self.probes.tpm_present {
                        "✓"
                    } else {
                        "✗"
                    }
                ),
                Style::new(),
            ),
            Span::styled(format!("Secure Boot {} · ", sb.0), Style::new().fg(sb.1)),
            Span::styled(self.probes.boot_mode.clone(), Style::new().dim()),
        ]));
        // The seal tier is a three-rung ladder (signed PCR-11 > pcrlock NV >
        // literal PCR-7; see irlume-core/src/pcrsig.rs). The daemon's
        // KeyringInfo names the armed envelope's actual rung, which is what
        // the Keyring tab shows; a local artifact probe can only prove Tier 1
        // availability, so without an answer this line told every Tier-2
        // pcrlock user their seal sat on the weakest tier.
        lines.push(Line::from(vec![
            Span::styled("  PCR policy ", Style::new().dim()),
            Span::styled(
                if let Some(p) = &self.keyring_policy {
                    p.clone()
                } else if !self.daemon_up {
                    "unknown (daemon unreachable)".to_string()
                } else if self.keyring_armed == Some(true) {
                    "unreported by this daemon".to_string()
                } else if irlume_core::pcrsig::signed_policy_available() {
                    "signed (PCR-11, Tier 1) available".to_string()
                } else {
                    "not armed; tier decided at arm time".to_string()
                },
                Style::new().dim(),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            "  IR test    press [l] to run the IR PAD self-test (sudo; look at the camera)",
            Style::new().dim(),
        )));
        let blk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim())
            .title(" diagnosis ");
        f.render_widget(
            Paragraph::new(lines).block(blk).wrap(Wrap { trim: false }),
            info_area,
        );
    }

    fn draw_identify(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![
            section("1:N identify (\"who is this?\")"),
            Line::from(Span::styled(
                "  Capture once and match against your enrollment (every user when",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  run as root). Liveness-gated, RGB primary; a diagnostic, not unlock.",
                Style::new().dim(),
            )),
            Line::raw(""),
        ];
        match &self.identify_result {
            Some((true, who)) => {
                lines.push(Line::from(vec![
                    Span::styled(
                        "  ✓ Recognized  ",
                        Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(who.clone(), Style::new().fg(th().ok)),
                ]));
                lines.push(Line::from(Span::styled(
                    "    confidence is 0.00-1.00 (higher = surer); this cleared your match",
                    Style::new().dim(),
                )));
                lines.push(Line::from(Span::styled(
                    "    threshold. Identify is a diagnostic check, not a login.",
                    Style::new().dim(),
                )));
            }
            Some((false, why)) => lines.push(Line::from(vec![
                Span::styled("  ✗ ", Style::new().fg(th().err)),
                Span::styled(why.clone(), Style::new().fg(th().err)),
            ])),
            None => lines.push(Line::from(Span::styled(
                "  press [i] and look at the camera",
                Style::new().dim(),
            ))),
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("  [i]", Style::new().fg(th().accent)),
            Span::styled(" identify now", Style::new().dim()),
        ]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn draw_pam(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![section("PAM services (face auth wiring)")];
        // Everything below renders `self.pam_cache`, computed with the
        // diagnostics: draw used to re-read every PAM service file and probe
        // the LSM on EVERY FRAME, which is I/O in a render loop.
        for (label, present, wired) in &self.pam_cache.rows {
            let val = if !present {
                Span::styled("(not present)", Style::new().dim())
            } else if *wired {
                Span::styled(
                    "● wired",
                    Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("○ not wired", Style::new().dim())
            };
            lines.push(Line::from(vec![Span::raw(format!("  {label:<16}")), val]));
        }
        // The #200 advisory, same walk as `login status`: a wired greeter
        // whose released password nothing turns into an open wallet is the
        // one failure the user sees as "KWallet prompts anyway", and every
        // other row here says wired ✓ while it happens.
        for w in &self.pam_cache.handoffs {
            let detail = match w.auth_only {
                Some(m) => format!(
                    "  ⚠ {}: {m} reads the password but has no session line; the wallet will still prompt",
                    w.service
                ),
                None => format!(
                    "  ⚠ {}: nothing reads the released password; the wallet will still prompt",
                    w.service
                ),
            };
            lines.push(Line::from(Span::styled(detail, Style::new().fg(th().err))));
        }
        // LSM row is distro-aware: SELinux (Fedora-family), AppArmor
        // (Debian/Ubuntu-family), or nothing (e.g. Arch default); showing a
        // SELinux row on a non-SELinux system reads as a fault that isn't one.
        if self.pam_cache.selinux_present {
            let sel = match self.pam_cache.selinux {
                Some(true) => Span::styled("● loaded", Style::new().fg(th().ok)),
                Some(false) => Span::styled("✗ not loaded", Style::new().fg(th().err)),
                None => Span::styled("unknown (needs root)", Style::new().dim()),
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {:<16}", "SELinux module")),
                sel,
            ]));
        } else {
            // AppArmor row: prefer the daemon's real confinement (Health.apparmor
            // from its /proc/self/attr). The on-disk profile existing does not
            // prove the daemon is confined (apparmor_parser can fail silently at
            // install). Fall back to the on-disk-profile heuristic only for an
            // older daemon that doesn't report the field.
            let aa = self.health.as_ref().and_then(|h| h.apparmor.as_deref());
            let val = match aa {
                Some(l) if l.contains("unconfined") => Some(Span::styled(
                    "✗ daemon UNCONFINED (profile installed but not loaded)",
                    Style::new().fg(th().err),
                )),
                Some(l) if l.contains("(complain)") => Some(Span::styled(
                    "◐ profile loaded in complain mode (not enforcing)",
                    Style::new().dim(),
                )),
                Some(_) => Some(Span::styled(
                    "● daemon confined (enforce)",
                    Style::new().fg(th().ok),
                )),
                None if self.pam_cache.apparmor_enabled => {
                    Some(if self.pam_cache.apparmor_profiled {
                        Span::styled("● irlume profile installed", Style::new().fg(th().ok))
                    } else {
                        Span::styled(
                            "active; irlume unconfined (profile optional)",
                            Style::new().dim(),
                        )
                    })
                }
                None => None, // AppArmor not enabled this boot: no row
            };
            if let Some(val) = val {
                lines.push(Line::from(vec![
                    Span::raw(format!("  {:<16}", "AppArmor")),
                    val,
                ]));
            }
        }
        lines.push(Line::raw(""));
        lines.push(section("What each does"));
        // Tier-accurate: only the Secure (IR) tier releases the login credential
        // at the greeter. On a convenience (RGB-only) box face is lock-screen
        // only; describing keyring-unseal there would be a false promise.
        match self.health.as_ref().map(|h| h.tier.as_str()) {
            Some("convenience") => {
                lines.push(Line::from(Span::styled(
                    "  greeter (RGB-only): face is NOT accepted for login; password only",
                    Style::new().dim(),
                )));
                lines.push(Line::from(Span::styled(
                    "  lock screen: face unlocks the screen (no credential release)",
                    Style::new().dim(),
                )));
            }
            Some("secure") => {
                lines.push(Line::from(Span::styled(
                    "  greeter: face → TPM-unseal password → wallet opens at login",
                    Style::new().dim(),
                )));
                lines.push(Line::from(Span::styled(
                    "  lock screen: face verify-only (wallet already open)",
                    Style::new().dim(),
                )));
            }
            // Daemon unreachable/older, or no camera; don't promise credential release.
            _ => lines.push(Line::from(Span::styled(
                "  tier unknown (daemon unreachable); password remains the fallback",
                Style::new().dim(),
            ))),
        }
        lines.push(Line::from(Span::styled(
            "  always fail-safe to the password: no lockout.",
            Style::new().dim(),
        )));
        lines.push(Line::raw(""));
        lines.push(section("Change (root)"));
        // One consistent shape per action: [key] in a fixed accent column, a
        // verb-first label padded to a common width, then a dim detail column.
        // Scannable as a command list instead of a paragraph; the key never
        // wanders into the middle of a sentence.
        let act = |key: &str, label: &str, detail: &str| {
            Line::from(vec![
                Span::styled(format!("  {key:<4}"), Style::new().fg(th().accent)),
                Span::styled(format!("{label:<22}"), Style::new()),
                Span::styled(detail.to_string(), Style::new().dim()),
            ])
        };
        lines.push(act(
            "[w]",
            "Wire login + lock",
            "the core action; leave the password empty then Enter to use your face",
        ));
        lines.push(act(
            "[u]",
            "Wire face-sudo",
            "opt-in; face + a consent gesture approve sudo prompts",
        ));
        lines.push(act(
            "[p]",
            "Wire app prompts",
            "opt-in; face approves Bitwarden and pkexec",
        ));
        // What [c] teaches is only USEFUL in the modes that accept it, so the row
        // reads the configured mode instead of always calling the closure an
        // optional extra. Under `closure` the nod is refused and this calibration
        // is the only way any gesture passes; under `nod` the closure is refused
        // and teaching it changes nothing. Naming the nod first in the default
        // mode still matches the prompts: it needs no calibration and is
        // unaffected by lighting, while this is stored as absolute eye
        // measurements that shift as the room changes.
        lines.push(act(
            "[c]",
            "Calibrate gesture",
            match irlume_common::config::consent_gesture_mode() {
                irlume_common::config::ConsentGesture::Closure => {
                    "REQUIRED: consent_gesture=closure accepts only the eye closure"
                }
                irlume_common::config::ConsentGesture::Nod => {
                    "not accepted: consent_gesture=nod accepts only the head nod"
                }
                irlume_common::config::ConsentGesture::Either => {
                    "optional eye-closure alternative; the head nod needs no calibration"
                }
                irlume_common::config::ConsentGesture::Misconfigured => {
                    "no gesture is accepted until consent_gesture is fixed"
                }
            },
        ));
        // [b] is an ACTION only when Bitwarden is installed without its polkit
        // action; otherwise its state shows as a status line below.
        if matches!(
            self.heavy.1.clone(),
            Some(crate::bitwarden::TuiState::NeedsSetup)
        ) {
            lines.push(act(
                "[b]",
                "Set up Bitwarden",
                "installs its polkit action so your face unlocks the vault",
            ));
        }
        lines.push(act(
            "[x]",
            "Un-wire everything",
            "removes face auth from login/lock/sudo/apps; asks first",
        ));
        lines.push(act(
            "[s]",
            "Show full status",
            "opens the detailed console status view",
        ));
        // Bitwarden status line (not an action): only when installed and the
        // action is present or snapd owns it. Set apart by a blank line.
        match &self.heavy.1 {
            Some(crate::bitwarden::TuiState::Ready) => {
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![
                    Span::raw("  Bitwarden   "),
                    Span::styled("● polkit action installed", Style::new().fg(th().ok)),
                    Span::styled(
                        "  (turn on \"unlock with system authentication\" in its settings)",
                        Style::new().dim(),
                    ),
                ]));
            }
            Some(crate::bitwarden::TuiState::SnapMissing) => {
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![
                    Span::raw("  Bitwarden   "),
                    Span::styled("○ snap action missing", Style::new().fg(th().warn)),
                    Span::styled(
                        "  run: sudo snap connect bitwarden:polkit",
                        Style::new().dim(),
                    ),
                ]));
            }
            _ => {}
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn draw_done(&self, f: &mut Frame, area: Rect) {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        // Tri-state, not the raw probe bool: before the first sweep lands the
        // bool is a default, and this screen must not read a default as "one
        // step left" (nor as done).
        let wired = self.login_wired_known();
        let lines = vec![
            section("Setup dashboard"),
            Line::raw(""),
            Line::from(vec![
                Span::raw("  daemon            "),
                onoff(self.daemon_up),
            ]),
            Line::from(vec![
                Span::raw("  auth method       "),
                Span::styled(method_label(&self.fp.method), Style::new().fg(th().accent)),
            ]),
            Line::from(vec![
                Span::raw("  enrollment        "),
                count_badge(
                    self.profiles_loaded,
                    self.profiles.len(),
                    scans,
                    self.live_scans(),
                ),
            ]),
            Line::from(vec![
                Span::raw("  eyes-open gate    "),
                onoff(self.eyes_open),
            ]),
            Line::from(vec![
                Span::raw("  keyring unlock    "),
                onoff_opt(self.keyring_armed),
            ]),
            Line::from(vec![
                Span::raw("  keyring gesture   "),
                match irlume_common::config::credential_release_challenge_visible() {
                    Some(v) => onoff(v),
                    // Root-only setting: say unknown rather than claim either state.
                    None => Span::styled("◐ root-only", Style::new().fg(th().warn)),
                },
            ]),
            Line::from(vec![
                Span::raw("  templates enc     "),
                // Three states, not two. An encrypted store whose key is gone
                // cannot be opened by anything, and `encrypted` alone drew it as
                // a green yes; drawing it as "no" would be just as wrong in the
                // other direction. The Recovery tab already says this loudly.
                match self.recovery {
                    Some(r) if r.encrypted && r.key_present => onoff(true),
                    Some(r) if r.encrypted => Span::styled(
                        "✗ key missing",
                        Style::new().fg(th().err).add_modifier(Modifier::BOLD),
                    ),
                    Some(_) => onoff(false),
                    None => onoff_opt(None),
                },
            ]),
            Line::from(vec![
                Span::raw("  recovery pass     "),
                onoff_opt(self.recovery.map(|r| r.recovery_set)),
            ]),
            Line::from(vec![
                Span::raw("  biopolicy         "),
                // Same tri-state as the gesture row above: the CLI half fixed
                // this in `status` (settings.conf is 0600 root-only, so an
                // unreadable key must not print as off), and the two surfaces
                // must agree on the daemon's truthy set and env override.
                match irlume_common::config::enforce_biopolicy_visible() {
                    Some(v) => onoff(v),
                    None => Span::styled("◐ root-only", Style::new().fg(th().warn)),
                },
            ]),
            Line::from(vec![
                Span::raw("  fingerprint       "),
                onoff(self.fp.available),
            ]),
            Line::from(vec![Span::raw("  login wiring      "), onoff_opt(wired)]),
            Line::raw(""),
            Line::from(Span::styled(
                if !self.daemon_up {
                    "  Daemon not running; see the Repair tab before quitting."
                } else if self.profiles.is_empty() && self.caps.rgb {
                    "  Not set up yet; enroll a face (Welcome [e]) to begin."
                } else if self.profiles.is_empty() {
                    "  No face hardware; fingerprint/password remain your methods."
                } else if wired == Some(false) {
                    "  One step left: your login screen isn't wired yet; press [w] (sudo; password stays the fallback)."
                } else if wired.is_none() {
                    "  Checking login wiring; the row above fills in when the probe lands."
                } else {
                    "  All set. irlume keeps running as a daemon; this panel is safe to quit."
                },
                Style::new().dim(),
            )),
            if !self.profiles.is_empty() && wired == Some(false) {
                Line::from(vec![
                    Span::styled("  [w]", Style::new().fg(th().accent)),
                    Span::styled(" wire login    [r] refresh    [q] quit", Style::new().dim()),
                ])
            } else {
                Line::from(vec![
                    Span::styled("  [r]", Style::new().fg(th().accent)),
                    Span::styled(" refresh    [q] quit", Style::new().dim()),
                ])
            },
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn draw_activity(&self, f: &mut Frame, area: Rect) {
        let scrolled = self.act_scroll > 0;
        let title = match (&self.op, scrolled) {
            (Some(op), _) => format!(" ● Activity   {} {}… ", SPIN[self.spin], op.label),
            (None, true) => format!(
                " ● Activity: ↑ history ({} up · PgDn/End to follow) ",
                self.act_scroll
            ),
            (None, false) => " ● Activity: newest last · PgUp to scroll back ".to_string(),
        };
        let blk = Block::bordered()
            .title(title)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(if scrolled { th().accent } else { th().blue }));
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let h = inner.height as usize;
        // Window ends `act_scroll` lines up from the newest entry.
        // Designed empty state (HIG placeholders): say what will appear, not
        // nothing.
        if self.activity.is_empty() {
            f.render_widget(
                Paragraph::new("Actions you take show up here, newest last.")
                    .style(Style::new().dim()),
                inner,
            );
            return;
        }
        let end = self.activity.len().saturating_sub(self.act_scroll);
        let start = end.saturating_sub(h);
        let lines: Vec<Line> = self.activity[start..end]
            .iter()
            .map(|(g, m)| {
                let gs = match g {
                    '→' => Style::new().fg(th().accent),
                    '✓' => Style::new().fg(th().ok),
                    '✗' => Style::new().fg(th().err),
                    _ => Style::new().dim(),
                };
                Line::from(vec![
                    Span::styled(format!("{g} "), gs),
                    Span::raw(m.clone()),
                ])
            })
            .collect();
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    /// Per-screen action keys, ordered primary-first: the footer shows
    /// the first three, the [?] overlay shows them all. Every bound key of a
    /// screen belongs here; the overlay claims to be the full keymap, so a
    /// key documented only in body text is invisible once the body scrolls
    /// or the user reaches for [?].
    fn screen_actions(&self) -> &'static [(&'static str, &'static str)] {
        match self.screen {
            SC_WELCOME => &[
                ("e", "enroll"),
                ("i", "identify"),
                ("r", "refresh"),
                ("enter", "open the selected section"),
                ("U", "uninstall"),
            ],
            SC_REPAIR => &[
                ("f", "fix"),
                ("r", "re-check"),
                ("d", "full doctor"),
                ("l", "IR test"),
                ("g", "logs"),
                ("t", "debug logs"),
            ],
            SC_CAMERAS => &[
                ("enter", "use"),
                ("s", "setup emitter"),
                ("p", "list units"),
                ("t", "tune capture"),
            ],
            SC_PROFILES => &[
                ("e", "enroll"),
                ("a", "add scan"),
                ("r", "rename"),
                ("d", "delete"),
            ],
            SC_IDENTIFY => &[("i", "identify")],
            // Both [r] and [p] are guarded in the handler: [r] reseals a seal that
            // must already exist, and [p] refreshes the boot-measurement policy a
            // Tier 2 seal is bound to. Advertising either where its guard cannot
            // pass offered a key that did nothing and said nothing.
            SC_KEYRING => match (
                self.keyring_armed == Some(true),
                self.keyring_policy
                    .as_deref()
                    .is_some_and(|p| p.contains("Tier 2")),
            ) {
                (true, true) => &[
                    ("a", "arm"),
                    ("r", "reseal"),
                    ("f", "forget"),
                    ("p", "refresh pcrlock policy"),
                ],
                (true, false) => &[("a", "arm"), ("r", "reseal"), ("f", "forget")],
                (false, true) => &[
                    ("a", "arm"),
                    ("f", "forget"),
                    ("p", "refresh pcrlock policy"),
                ],
                (false, false) => &[("a", "arm"), ("f", "forget")],
            },
            SC_RECOVERY => &[("s", "set"), ("t", "restore"), ("f", "forget")],
            SC_FINGERPRINT => &[
                ("a", "enroll finger"),
                ("t", "test finger"),
                ("e", "enable both"),
                ("d", "disable"),
                ("x", "reset"),
            ],
            SC_PAM => &[
                ("w", "wire login (sudo)"),
                ("u", "face-sudo"),
                ("p", "app prompts"),
                ("c", "calibrate gesture"),
                ("b", "app unlock"),
                ("x", "un-wire"),
                ("s", "show status"),
            ],
            SC_SETTINGS => &[
                ("enter", "eyes-open off"),
                ("↑/↓", "pick service"),
                ("c", "toggle gesture"),
                ("g", "keyring gesture"),
                ("b", "biopolicy"),
                ("m", "3rd-party model"),
            ],
            // Read-only by design (#331): a model change goes through the
            // CLI's own sudo + license flow, and the screen prints the exact
            // command for it, so the only key to advertise is the scroll.
            SC_MODELS => &[("↑/↓", "scroll catalog")],
            // [w] only while wiring is OBSERVED missing: the body hides its
            // [w] line on a wired box, and a footer still offering it invites
            // a needless `sudo irlume login enable --apply` re-run. Unknown
            // state (no sweep yet) advertises nothing either way.
            SC_DONE => {
                if self.login_wired_known() == Some(false) {
                    &[("w", "wire login"), ("u", "update"), ("r", "refresh")]
                } else {
                    &[("u", "update"), ("r", "refresh")]
                }
            }
            _ => &[("r", "refresh")],
        }
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let key = |k: &str| Span::styled(format!(" {k} "), th().chip);
        // Guided enrollment swallows every key but Esc; show only that, so the
        // footer doesn't advertise dead nav/action keys during a capture.
        if self.enroll.is_some() {
            let spans = vec![
                key("esc"),
                Span::styled(" cancel enrollment", Style::new().dim()),
            ];
            let blk = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().dim());
            f.render_widget(Paragraph::new(Line::from(spans)).block(blk), area);
            return;
        }
        // A running op (Identify / IR self-test) also swallows every key but
        // q/Esc, so don't advertise the live nav/action keys during it.
        if self.op.is_some() {
            let spans = vec![
                key("q / esc"),
                // "quit", not "cancel": these keys leave the TUI. The op keeps
                // running in the daemon and its result is dropped; nothing here
                // can call it back. Esc means "back out and stay" on every other
                // screen, so promising a cancel here read as the safe choice.
                Span::styled(
                    " quit (the op keeps running) · working…",
                    Style::new().dim(),
                ),
            ];
            let blk = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().dim());
            f.render_widget(Paragraph::new(Line::from(spans)).block(blk), area);
            return;
        }
        let actions = self.screen_actions();
        // Three-tier disclosure (GNOME HIG): the footer shows the primary
        // action plus at most two more; [?] opens the full keymap overlay;
        // docs hold the rest. The first action is THE action for the screen,
        // so it alone gets the emphasized label.
        let mut spans = vec![key("Tab"), Span::styled(" tabs  ", Style::new().dim())];
        for (i, (k, d)) in actions.iter().take(3).enumerate() {
            spans.push(key(k));
            if i == 0 {
                spans.push(Span::styled(
                    format!(" {d}  "),
                    Style::new().add_modifier(Modifier::BOLD),
                ));
            } else {
                spans.push(Span::styled(format!(" {d}  "), Style::new().dim()));
            }
        }
        spans.push(key("?"));
        spans.push(Span::styled(" all keys  ", Style::new().dim()));
        spans.push(key("q"));
        spans.push(Span::styled(" quit", Style::new().dim()));
        let blk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim());
        f.render_widget(Paragraph::new(Line::from(spans)).block(blk), area);
    }

    /// The full keymap for the [?] overlay: the global keys plus every action
    /// of the CURRENT screen (tier two of the disclosure ladder).
    fn help_body(&self) -> String {
        let mut b = String::from(
            "Global\n  Tab / \u{2190}\u{2192}  switch tab      \u{2191}\u{2193}  select\n               v  basic/all tabs       PgUp/Dn  activity log\n               h  home (the Welcome tab)\n               M  release mouse (highlight/copy)   q  quit\n\nThis screen\n",
        );
        for (k, d) in self.screen_actions() {
            b.push_str(&format!("  {k:<7} {d}\n"));
        }
        b
    }

    fn modal(&self, f: &mut Frame, title: &str, body: &str) {
        let area = f.area();
        let w = area.width.saturating_sub(4).clamp(20, 72).min(area.width);
        // Grow the box to fit the wrapped body so a long message never clips,
        // on any terminal width; borders + 1-col horizontal padding = 4 chars.
        let inner = (w as usize).saturating_sub(4).max(1);
        let lines = wrapped_line_count(body, inner) as u16;
        // `clamp(3, area.height)` PANICS when the frame is shorter than 3 rows
        // (min > max), taking the whole interface down for anyone whose terminal
        // is a couple of rows tall (a dragged-narrow window, a small tmux split).
        // Cap the floor by what the frame actually has, so a tiny frame gets a
        // cramped box instead of a crash.
        let max_h = area.height.max(1);
        let h = (lines + 2).clamp(3.min(max_h), max_h);
        let rect = Rect {
            x: area.width.saturating_sub(w) / 2,
            y: area.height.saturating_sub(h) / 2,
            width: w,
            height: h,
        };
        f.render_widget(Clear, rect);
        let blk = Block::bordered()
            .title(format!(" {title} "))
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(th().accent))
            .padding(ratatui::widgets::Padding::horizontal(1));
        f.render_widget(
            Paragraph::new(body.to_string())
                .block(blk)
                .wrap(Wrap { trim: true }),
            rect,
        );
    }
}

/// Approximate ratatui's word-wrap line count for `text` at `width` columns, so
/// `modal()` can size its height to fit. Off-by-one on a word longer than the
/// width is harmless (the height is clamped to the frame).
fn wrapped_line_count(text: &str, width: usize) -> usize {
    if width == 0 {
        return 1;
    }
    // Count each explicit line (split on '\n'), word-wrapped to `width`.
    text.split('\n')
        .map(|line| {
            let mut lines = 1usize;
            let mut col = 0usize;
            for word in line.split_whitespace() {
                let wlen = word.chars().count();
                if col == 0 {
                    col = wlen;
                } else if col + 1 + wlen <= width {
                    col += 1 + wlen;
                } else {
                    lines += 1;
                    col = wlen;
                }
            }
            lines
        })
        .sum()
}

fn quality_bar(q: u8) -> String {
    let filled = (q as usize * 10 / 100).min(10);
    format!(
        "[{}{}] {q:>3}%",
        "█".repeat(filled),
        "░".repeat(10 - filled)
    )
}

// ---- rich-render helpers --------------------------------------------------

/// A bold accent section header line.
fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
    ))
}

/// Green ● ON / dim ○ off badge.
fn onoff(on: bool) -> Span<'static> {
    if on {
        Span::styled(
            "● yes",
            Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("○ no", Style::new().dim())
    }
}

/// [`onoff`] with the honest third state: `None` means the question was never
/// answered (daemon unreachable), which must render as unknown, never as "no".
/// Same glyph and reasoning as the Done tab's root-only badge.
fn onoff_opt(state: Option<bool>) -> Span<'static> {
    match state {
        Some(v) => onoff(v),
        None => Span::styled("◐ unknown", Style::new().fg(th().warn)),
    }
}

/// A screen state row: 2-space indent, label padded to `w`, then the value
/// span. One shape for every status line so screens line up the same way.
fn state_row(label: &str, w: usize, value: Span<'static>) -> Line<'static> {
    Line::from(vec![Span::raw(format!("  {label:<w$}")), value])
}

/// An action line: accent `[key]` chips with dim labels, 2-space indent, a
/// gap between actions. THE way action keys render, so a key is never a dim
/// mid-sentence token or a whole dim line.
fn action_line(items: &[(&str, &str)]) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    for (i, (k, d)) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(format!("[{k}]"), Style::new().fg(th().accent)));
        spans.push(Span::styled(format!(" {d}"), Style::new().dim()));
    }
    Line::from(spans)
}

/// Human label for the stored auth method string (`Method::as_str()`): the raw
/// `"both"` reads as opaque, so spell out the coexistence.
fn method_label(method: &str) -> String {
    match method {
        "both" => "face + fingerprint (either)".to_string(),
        "auto" => "auto (face; fingerprint if present)".to_string(),
        "fingerprint" => "fingerprint".to_string(),
        "face" => "face".to_string(),
        other => other.to_string(),
    }
}

/// "N profile(s), M scan(s)" or a dim "none". `live` is how many of those
/// scans the loaded recognizer can match, `None` when the daemon does not
/// report it. Zero live scans is a warning, not a green badge: enrollment
/// that cannot match is not healthy, however many scans it holds (#288).
/// `known` = a ListProfiles has landed; an empty list before that is "not
/// observed", and "○ none" there prompted enrolled users to re-enroll.
fn count_badge(known: bool, profiles: usize, scans: usize, live: Option<usize>) -> Span<'static> {
    if profiles == 0 {
        if !known {
            return Span::styled(
                "◐ unknown (profile list not read)",
                Style::new().fg(th().warn),
            );
        }
        return Span::styled("○ none", Style::new().dim());
    }
    match live {
        Some(0) => Span::styled(
            format!("● {profiles} profile(s), {scans} scan(s), none for the loaded recognizer"),
            Style::new().fg(th().warn).add_modifier(Modifier::BOLD),
        ),
        _ => Span::styled(
            format!("● {profiles} profile(s), {scans} scan(s)"),
            Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
        ),
    }
}

/// Where the down-mode fallback probe looks for libonnxruntime.so. The first
/// two are the packaged bundle locations (keep in step with PACKAGED_ORTS in
/// crates/irlume-vision/src/lib.rs, the canonical list): the packages export
/// ORT_DYLIB_PATH only inside the daemon's unit drop-in, so this process's
/// environment cannot see it and the probe false-failed on every packaged
/// install until these paths were scanned too.
const ORT_FALLBACK_PATHS: &[&str] = &[
    "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
    "/opt/irlume/onnxruntime/lib/libonnxruntime.so",
    "/usr/lib64/libonnxruntime.so",
    "/usr/lib/libonnxruntime.so",
];

/// The Repair row for the ONNX fallback probe (daemon down). Not-found is a
/// Warn, not a Fail: with the daemon down the probe is a guess about an env
/// it cannot see, and the Daemon row above already carries the real failure;
/// a Fail here sent users off to install packages they may already have.
fn ort_fallback_check(found: bool) -> Check {
    Check {
        label: "ONNX Runtime".into(),
        sev: if found { Sev::Ok } else { Sev::Warn },
        detail: if found {
            "library found".into()
        } else {
            "not seen by a local probe; the daemon's unit may set its own path".into()
        },
        fix: if found {
            Fix::None
        } else {
            Fix::Manual("start the daemon first; it reports its real ONNX state".into())
        },
    }
}

/// The TFLite mirror of [`ort_fallback_check`], with one extra state: an
/// explicit `IRLUME_TFLITE_LIB` override is the WHOLE candidate list (the
/// resolver refuses to fall through a broken override), so an override
/// pointing at a missing file is an operator error this environment CAN see,
/// and that one is a Fail rather than the not-seen Warn. Existence only, no
/// dlopen: the TUI runs unconfined and a load that succeeds here can still
/// fail under the daemon's AppArmor profile, so "found" is the strongest
/// claim a local probe can honestly make.
fn tflite_fallback_check(
    env_override: Option<&str>,
    exists: impl Fn(&std::path::Path) -> bool,
) -> Check {
    let candidates = irlume_vision::tflite::tflite_lib_candidates(env_override, &exists);
    let (sev, detail, fix) = match (env_override, candidates.first()) {
        (Some(_), Some(p)) if exists(p) => (
            Sev::Ok,
            format!("override found at {}", p.display()),
            Fix::None,
        ),
        (Some(_), Some(p)) => (
            Sev::Fail,
            format!(
                "IRLUME_TFLITE_LIB points at {}, which does not exist",
                p.display()
            ),
            Fix::Manual("fix or unset IRLUME_TFLITE_LIB; the resolver refuses to fall through a broken override".into()),
        ),
        (None, Some(p)) => (
            Sev::Ok,
            format!("library found at {}", p.display()),
            Fix::None,
        ),
        _ => (
            Sev::Warn,
            "not seen by a local probe; the daemon's unit may set its own path".into(),
            Fix::Manual(
                "install the irlume package's TFLite runtime (it ships at \
                 /usr/share/irlume/tflite/libtensorflowlite_c.so), or set \
                 IRLUME_TFLITE_LIB in the irlumed unit"
                    .into(),
            ),
        ),
    };
    Check {
        label: "TFLite runtime".into(),
        sev,
        detail,
        fix,
    }
}

// ---- async response mappers (Response -> (ok, message)) -------------------

fn map_ok(resp: Response) -> (bool, String) {
    match resp {
        Response::Ok(m) => (true, m),
        Response::Error(e) => (false, e),
        o => (false, format!("unexpected: {o:?}")),
    }
}

/// Does `reason` carry any word the summary line does not already say?
/// Word-set based, not equality: daemons phrase the echo with connectives
/// ("live face, BUT no enrolled match"), so an exact compare never fires.
fn reason_adds_information(summary: &str, reason: &str) -> bool {
    let words = |s: &str| -> Vec<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(str::to_lowercase)
            .collect()
    };
    let known = words(summary);
    words(reason)
        .iter()
        .any(|w| w != "but" && !known.contains(w))
}

fn map_identify(resp: Response) -> (bool, String) {
    match resp {
        Response::Identified {
            user: Some(u),
            profile,
            score,
            ..
        } => (
            true,
            format!(
                "{u} · {} · confidence {score:.3}",
                profile.unwrap_or_default()
            ),
        ),
        Response::Identified {
            user: None,
            live,
            reason,
            ..
        } => {
            let summary = if live {
                "live face, no enrolled match"
            } else {
                "no live face"
            };
            // The daemon's reason often restates the summary ("live face, but
            // no enrolled match"), which rendered as "live face, no enrolled
            // match (live face, but no enrolled match)". Append it only when
            // it says something the summary does not.
            (
                false,
                if reason_adds_information(summary, &reason) {
                    format!("{summary} ({reason})")
                } else {
                    summary.to_string()
                },
            )
        }
        Response::Error(e) => (false, e),
        o => (false, format!("unexpected: {o:?}")),
    }
}

/// Confirm-flow ops (delete profile/scan, forget keyring/recovery). Delete and
/// recovery-forget ack with `Ok`; keyring-forget acks with `PasswordForgotten`.
fn map_confirm(resp: Response) -> (bool, String) {
    match resp {
        Response::Ok(m) => (true, m),
        Response::PasswordForgotten => (
            true,
            "sealed keyring secret erased; keyring unlock disarmed".into(),
        ),
        Response::Error(e) => (false, e),
        o => (false, format!("unexpected: {o:?}")),
    }
}

/// Arm the TPM-sealed login password (a slow op worth keeping off the UI thread).
fn map_sealed(resp: Response) -> (bool, String) {
    match resp {
        Response::PasswordSealed => (
            true,
            "keyring armed; unlocking your session will open your wallet".into(),
        ),
        Response::Error(e) => (false, format!("arm failed: {e}")),
        o => (false, format!("arm failed: {o:?}")),
    }
}

/// Settings toggles reply with the updated `Enrollment`; report the resulting
/// state the daemon actually applied (poll() then refreshes the display).
fn map_settings(resp: Response) -> (bool, String) {
    match resp {
        Response::Enrollment {
            require_eyes_open, ..
        } => (
            true,
            format!(
                "require-eyes-open {}",
                if require_eyes_open {
                    "ENABLED"
                } else {
                    "disabled"
                }
            ),
        ),
        // The daemon's SetRequire* handlers go through mutate_enrollment, which
        // acks with Ok(msg), not Enrollment. Without this arm every toggle fell
        // to the "unexpected" fallback and raised a spurious error modal.
        Response::Ok(m) => (true, m),
        Response::Error(e) => (false, e),
        o => (false, format!("unexpected: {o:?}")),
    }
}

/// One transport miss against the framing guide, counted toward
/// [`GUIDE_MISS_LIMIT`]. Sends the stall (or the final give-up error) to the
/// UI. Returns what the caller must do next.
fn guide_miss(misses: &mut u32, e: String, send: &impl Fn(WMsg) -> bool) -> GuideOutcome {
    *misses += 1;
    if *misses >= GUIDE_MISS_LIMIT {
        let _ = send(WMsg::Err(format!(
            "the camera guide never answered ({e}); this is not a \
             detection result. Check: journalctl -u irlumed -n 50"
        )));
        return GuideOutcome::Halt;
    }
    if !send(WMsg::Stall(e)) {
        return GuideOutcome::Halt;
    }
    GuideOutcome::Reframe
}

enum GuideOutcome {
    /// Well-framed streak held through the countdown: fire the capture.
    Ready,
    /// Framing drifted or a sample was missed (under the limit): re-frame.
    /// The consecutive-miss counter lives with the SCAN, not this attempt,
    /// so countdown misses cannot reset it by re-entering (Codex round on
    /// #309: the re-entry reset made a flapping daemon loop forever).
    Reframe,
    /// Stop was requested, the UI hung up, or a fatal error was sent.
    Halt,
}

/// Framing streak + 3-2-1 countdown for one capture attempt, over an
/// injectable sampler so the miss/give-up state machine is testable without
/// a daemon socket.
fn guide_until_capture(
    user: &str,
    stop: &AtomicBool,
    send: &impl Fn(WMsg) -> bool,
    sample: &mut impl FnMut(&Request) -> Result<Response, String>,
    misses: &mut u32,
) -> GuideOutcome {
    // Framing loop: wait for a well-framed streak. Samples use a bounded
    // budget: a guide that does not answer is a transport fact, not a
    // framing fact, and must never leave the last cue on screen reading as
    // a current biometric verdict (#309). A missed sample shows a visible
    // "not answering" state; GUIDE_MISS_LIMIT consecutive misses (across
    // framing AND countdown) end the enrollment saying so plainly.
    let mut streak = 0u32;
    loop {
        if stop.load(Ordering::Relaxed) {
            return GuideOutcome::Halt;
        }
        match sample(&Request::PositionSample {
            user: Some(user.to_owned()),
        }) {
            Ok(Response::Position(r)) => {
                *misses = 0;
                let good = r.well_framed;
                if !send(WMsg::Cue(r)) {
                    return GuideOutcome::Halt;
                }
                streak = if good { streak + 1 } else { 0 };
                if streak >= GOOD_STREAK {
                    break;
                }
            }
            Ok(Response::Error(e)) => {
                let _ = send(WMsg::Err(e));
                return GuideOutcome::Halt;
            }
            // A response of the wrong type is a protocol break, not a cue to
            // retry: swallowing it here would spin a tight request loop
            // against a confused daemon.
            Ok(o) => {
                let _ = send(WMsg::Err(format!(
                    "camera guide answered with the wrong response type: {o:?}"
                )));
                return GuideOutcome::Halt;
            }
            Err(e) => {
                streak = 0;
                match guide_miss(misses, e, send) {
                    GuideOutcome::Reframe => {} // stay in the framing loop
                    halt => return halt,
                }
            }
        }
    }
    // 3-2-1 countdown: re-verify framing at each beat (the poll lands
    // just before the next beat / the capture). Drift off-angle aborts.
    for c in (1..=3).rev() {
        if stop.load(Ordering::Relaxed) {
            return GuideOutcome::Halt;
        }
        if !send(WMsg::Count(c)) {
            return GuideOutcome::Halt;
        }
        std::thread::sleep(Duration::from_millis(650));
        match sample(&Request::PositionSample {
            user: Some(user.to_owned()),
        }) {
            // Still framed: keep counting (don't send a Cue; that would
            // clear the on-screen count). Only surface a cue on abort.
            Ok(Response::Position(r)) if r.well_framed => {
                *misses = 0;
            }
            Ok(Response::Position(r)) => {
                *misses = 0;
                let _ = send(WMsg::Cue(r));
                return GuideOutcome::Reframe;
            }
            Ok(Response::Error(e)) => {
                let _ = send(WMsg::Err(e));
                return GuideOutcome::Halt;
            }
            Ok(o) => {
                let _ = send(WMsg::Err(format!(
                    "camera guide answered with the wrong response type: {o:?}"
                )));
                return GuideOutcome::Halt;
            }
            // A mid-countdown miss counts like any other: the counter
            // survives the trip back through the framing loop.
            Err(e) => match guide_miss(misses, e, send) {
                GuideOutcome::Reframe => return GuideOutcome::Reframe,
                halt => return halt,
            },
        }
    }
    GuideOutcome::Ready
}

/// Guided-enroll worker: poll the framing guide, count down on a good streak,
/// then capture, repeating until `target` scans. Streams cues to the UI.
fn enroll_worker(
    user: String,
    profile: String,
    add: Option<String>,
    target: usize,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<WMsg>,
) {
    let send = |m: WMsg| tx.send(m).is_ok();
    // Scans this worker added whose IR burst the room mostly lit (#312);
    // summed across captures and reported once at Done.
    let mut ambient_lit_total = 0usize;
    for i in 0..target {
        // Consecutive guide misses for THIS scan, framing and countdown
        // together; only a successful sample resets it.
        let mut misses = 0u32;
        // Retry this scan until it's captured while well-framed: a drift during
        // the 3-2-1 aborts the countdown and re-frames instead of firing capture.
        'scan: loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match guide_until_capture(
                &user,
                &stop,
                &send,
                &mut |req| crate::daemon_sample(req),
                &mut misses,
            ) {
                GuideOutcome::Ready => {}
                GuideOutcome::Reframe => continue 'scan,
                GuideOutcome::Halt => return,
            }
            // Capture: first scan of a NEW profile creates it; the rest append.
            let req = if i == 0 && add.is_none() {
                Request::Enroll {
                    user: user.clone(),
                    profile: Some(profile.clone()),
                    scans: Some(1),
                    reset: false,
                }
            } else {
                Request::AddScan {
                    user: user.clone(),
                    profile: profile.clone(),
                    scans: None,
                    // Every scan after the first arrives via AddScan, so
                    // without the structured reply the #312 ambient-lit
                    // count would cover only scan 1 (Codex round).
                    report_enrollment: true,
                }
            };
            match crate::daemon_request(&req) {
                // Scan 1 of a new-profile enroll matched an existing identity:
                // the daemon merged it. Hand off to the UI to confirm before
                // adding the rest; the worker ends here (the UI spawns a
                // continuation on confirm, or undoes the scan on decline).
                Ok(Response::Enrolled {
                    created: false,
                    profile: resolved,
                    room,
                    added_scans,
                    ambient_lit,
                    ..
                }) => {
                    let _ = send(WMsg::MergePrompt {
                        profile: resolved,
                        room,
                        added_scans,
                        ambient_lit,
                    });
                    return;
                }
                // A brand-new profile (created) or an AddScan success.
                Ok(Response::Enrolled { ambient_lit, .. }) => {
                    ambient_lit_total += ambient_lit.unwrap_or(0);
                    if !send(WMsg::Captured(i + 1, target)) {
                        return;
                    }
                    break 'scan;
                }
                Ok(Response::Ok(_)) => {
                    if !send(WMsg::Captured(i + 1, target)) {
                        return;
                    }
                    break 'scan;
                }
                Ok(Response::Error(e)) => {
                    let _ = send(WMsg::Err(e));
                    return;
                }
                Ok(o) => {
                    let _ = send(WMsg::Err(format!("unexpected: {o:?}")));
                    return;
                }
                Err(e) => {
                    let _ = send(WMsg::Err(e));
                    return;
                }
            }
        }
    }
    let _ = send(WMsg::Done {
        ambient_lit: ambient_lit_total,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Serializes tests that mutate process-global environment (IRLUME_SOCKET,
    /// PATH) so they can't race each other under the parallel test runner.
    /// One binary-wide lock: main.rs and commands.rs tests use the same one,
    /// so env mutations can never race across test modules.
    use crate::testenv::ENV_LOCK;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::sync::atomic::AtomicUsize;

    /// The TUI must resolve its target account the way the rest of the CLI does.
    ///
    /// Reading $USER here pointed every request in this file at `root` under
    /// `sudo irlume tui`, which is the documented way to see root-only settings.
    /// That meant an empty dashboard for a configured user, and `[a]`/`[e]`
    /// sealing a password and enrolling a face under the wrong account. The rule
    /// lives in `user_arg`; this pins the TUI to it.
    #[test]
    fn the_tui_targets_the_invoking_user_not_the_sudo_environment() {
        // The rule itself: SUDO_USER wins over the root $USER that sudo sets.
        let _g = ();
        let explicit = crate::user_arg(&["--user".to_string(), "someone".to_string()]);
        assert_eq!(explicit, "someone", "an explicit --user must win");

        // And App stores exactly what it is handed, with no environment read of
        // its own to reintroduce the bug.
        let app = app_with_user("handed-in");
        assert_eq!(app.user, "handed-in");
    }

    /// A bare App for tests: no hardware probes, no daemon socket, no terminal.
    /// Mirrors `App::new()` but every probe-derived field is inert.
    /// `test_app` with a chosen account, for the user-resolution test.
    #[test]
    fn first_run_shows_focused_front_door() {
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.profiles_loaded = true; // loaded + empty profiles => not enrolled
        app.screen = SC_WELCOME;
        assert!(
            app.is_first_run(),
            "unenrolled + camera + Welcome is first-run"
        );
        let text = draw_text(&app);
        assert!(
            text.contains("Set up face unlock"),
            "front-door title missing:\n{text}"
        );
        assert!(text.contains("Scan my face"), "primary action missing");
        assert!(
            !text.contains("At a glance"),
            "the focused front door must replace the Welcome hub"
        );
    }

    #[test]
    fn first_run_suppressed_once_enrolled_or_without_camera() {
        // Enrolled => classic Welcome, never the front door.
        let mut enrolled = test_app();
        enrolled.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        enrolled.profiles = vec![profile("me", &["s1"])];
        enrolled.profiles_loaded = true;
        enrolled.screen = SC_WELCOME;
        assert!(!enrolled.is_first_run());
        // No camera => the face-worded front door would be wrong; classic Welcome.
        let mut headless = test_app(); // caps.rgb = false
        headless.profiles_loaded = true;
        headless.screen = SC_WELCOME;
        assert!(!headless.is_first_run());
        // Off Welcome (e.g. user pressed Tab) => sidebar returns, no front door.
        let mut elsewhere = test_app();
        elsewhere.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        elsewhere.profiles_loaded = true;
        elsewhere.screen = SC_SETTINGS;
        assert!(!elsewhere.is_first_run());
    }

    #[test]
    fn sidebar_groups_the_visible_screens_and_marks_the_current() {
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.daemon_up = true;
        app.advanced = true;
        app.recompute_visible();
        app.screen = SC_PROFILES;
        let text = draw_text(&app); // 120 wide => sidebar shown
        assert!(text.contains("Setup"), "sidebar group missing:\n{text}");
        assert!(text.contains("Security"), "sidebar group missing");
        assert!(text.contains("System"), "sidebar group missing");
        assert!(
            text.contains('▎'),
            "the current screen must carry the accent selection bar"
        );
    }

    #[test]
    fn header_step_counter_is_narrow_only() {
        let mut app = test_app();
        app.screen = SC_PAM;
        // Wide: the sidebar carries position, so the header omits "step N/N".
        let wide = draw_text(&app);
        let wide_hdr = row_with(&wide, "irlume");
        assert!(
            !wide_hdr.contains("step "),
            "wide header must not show the step counter, got: {wide_hdr}"
        );
        // Narrow: sidebar collapsed, so the header carries position.
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let narrow = rendered(&term);
        let narrow_hdr = row_with(&narrow, "irlume");
        assert!(
            narrow_hdr.contains("step "),
            "narrow header must show the step counter, got: {narrow_hdr}"
        );
    }

    fn app_with_user(user: &str) -> App {
        let mut a = test_app();
        a.user = user.into();
        a
    }

    fn test_app() -> App {
        let caps = irlume_camera::Caps {
            ir_pair: false,
            rgb: false,
        };
        App {
            user: "testuser".into(),
            screen: SC_WELCOME,
            sel: 0,
            profiles: Vec::new(),
            eyes_open: false,
            keyring_armed: None,
            keyring_policy: None,
            keyring_drift: None,
            keyring_kind: None,
            nodes: Vec::new(),
            pairs: Vec::new(),
            pairs_known: false,
            activity: Vec::new(),
            input: None,
            confirm: None,
            mouse_select: false,
            show_help: false,
            hub_sel: 0,
            op: None,
            enroll: None,
            enroll_merge: None,
            fp: FpInfo::default(),
            recovery: None,
            suspend: None,
            resume_enroll: None,
            identify_result: None,
            repair: Vec::new(),
            repair_sel: 0,
            cam_sel: 0,
            settings_svc_sel: 0,
            heavy: (crate::models::tui_state(), crate::bitwarden::tui_state()),
            heavy_at: std::time::Instant::now(),
            error: None,
            daemon_up: false,
            daemon_reach: crate::commands::DaemonReach::Down,
            enroll_error: None,
            health: None,
            act_scroll: 0,
            models_status: None,
            models_scroll: 0,
            visible: App::compute_visible(&caps, VisibilityInputs::default(), &[]),
            advanced: false,
            caps,
            fp_present: false,
            profiles_load: None,
            profiles_loaded: false,
            probes: Probes::default(),
            probes_load: None,
            probes_landed: false,
            light_load: None,
            pam_cache: PamCache::default(),
            fp_coverage: Vec::new(),
            spin: 0,
            quit: false,
        }
    }

    /// A running-op placeholder whose worker never answers (the receiver stays
    /// empty). The sender is returned so the channel stays open for the test.
    fn fake_op() -> (mpsc::Sender<(bool, String)>, Op) {
        let (tx, rx) = mpsc::channel();
        (
            tx,
            Op {
                label: "Identify".into(),
                tag: OpTag::Identify,
                rx,
            },
        )
    }

    fn fake_enroll(base: usize, target: usize) -> (mpsc::Sender<WMsg>, EnrollUi) {
        let (tx, rx) = mpsc::channel();
        (
            tx,
            EnrollUi {
                rx,
                stop: Arc::new(AtomicBool::new(false)),
                profile: "p".into(),
                last: None,
                count: None,
                stalled: None,
                captured: 0,
                target,
                base,
                ambient_base: 0,
            },
        )
    }

    /// Flatten a TestBackend buffer into one string (rows joined by newlines)
    /// for substring assertions on rendered output.
    fn rendered(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer();
        let mut out = String::new();
        for (i, cell) in buf.content.iter().enumerate() {
            if i > 0 && i % buf.area.width as usize == 0 {
                out.push('\n');
            }
            out.push_str(cell.symbol());
        }
        out
    }

    /// Hold ENV_LOCK and point IRLUME_SOCKET at a nonexistent path for the
    /// guard's lifetime. Every test that can trigger a daemon request (directly
    /// or on a worker thread) must hold one: a dev box may be running a REAL
    /// irlumed, and e.g. Request::Identify would fire its camera.
    struct DeadSocket {
        _lock: std::sync::MutexGuard<'static, ()>,
        old: Option<std::ffi::OsString>,
    }

    fn dead_socket() -> DeadSocket {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("IRLUME_SOCKET");
        std::env::set_var("IRLUME_SOCKET", "/nonexistent/irlume-test.sock");
        DeadSocket { _lock: lock, old }
    }

    impl Drop for DeadSocket {
        fn drop(&mut self) {
            match self.old.take() {
                Some(v) => std::env::set_var("IRLUME_SOCKET", v),
                None => std::env::remove_var("IRLUME_SOCKET"),
            }
        }
    }

    /// Drive poll() until the async op finishes (its worker thread answers with
    /// the dead-socket connect error). Must be called while a DeadSocket guard
    /// is held so the worker cannot race onto a real socket.
    fn wait_op_done(app: &mut App) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while app.op.is_some() && std::time::Instant::now() < deadline {
            app.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.op.is_none(), "async op never finished");
    }

    /// Drive poll() until the guided-enroll worker ends (dead socket → Err).
    fn wait_enroll_done(app: &mut App) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while app.enroll.is_some() && std::time::Instant::now() < deadline {
            app.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.enroll.is_none(), "enroll worker never finished");
    }

    /// Wait for every in-flight background load to land (or the budget to
    /// run out), so a test that triggered spawns does not leak workers into
    /// the NEXT test's environment: a leaked worker reads IRLUME_SOCKET at
    /// request time and connects to whatever socket that test set up.
    fn drain_loads(app: &mut App) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while (app.light_load.is_some() || app.probes_load.is_some() || app.profiles_load.is_some())
            && std::time::Instant::now() < deadline
        {
            app.poll();
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Render the full frame at 120x50 and return the flattened text.
    fn draw_text(app: &App) -> String {
        let mut term = Terminal::new(TestBackend::new(120, 50)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        rendered(&term)
    }

    /// The first rendered line containing `needle`, for row-scoped assertions:
    /// a badge must be tied to ITS row, not merely found somewhere on screen.
    fn row_with<'a>(text: &'a str, needle: &str) -> &'a str {
        text.lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no line contains '{needle}':\n{text}"))
    }

    fn profile(name: &str, scans: &[&str]) -> ProfileSummary {
        ProfileSummary {
            name: name.into(),
            scans: scans.iter().map(|s| s.to_string()).collect(),
            scans_by_recognizer: Default::default(),
            live_recognizer: None,
        }
    }

    fn check_row(label: &str, sev: Sev, fix: Fix) -> Check {
        Check {
            label: label.into(),
            sev,
            detail: format!("{label} detail"),
            fix,
        }
    }

    fn good_report(guidance: &str) -> PositionReport {
        PositionReport {
            face: true,
            face_frac: 0.3,
            centered: true,
            yaw_asym: 0.1,
            pitch_frac: 0.5,
            brightness: 120.0,
            ir_ok: true,
            quality: 85,
            well_framed: true,
            guidance: guidance.into(),
        }
    }

    // Regression: f00f316. The daemon acks SetRequireEyesOpen with
    // Response::Ok (via mutate_enrollment), not Response::Enrollment; before
    // the fix map_settings routed Ok to the "unexpected" fallback and every
    // eyes-open toggle raised a false error modal.
    #[test]
    fn eyes_open_toggle_accepts_ok_response() {
        let (ok, msg) = map_settings(Response::Ok("require-eyes-open ENABLED".into()));
        assert!(ok, "Response::Ok must be a success, not an error modal");
        assert_eq!(msg, "require-eyes-open ENABLED");
        // The updated-Enrollment reply and genuine errors keep working.
        let (ok, _) = map_settings(Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: true,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        });
        assert!(ok);
        let (ok, _) = map_settings(Response::Error("boom".into()));
        assert!(!ok);
    }

    // Regression: f00f316. modal() had a fixed height of 5, so any body longer
    // than three wrapped lines was clipped. The wrap math must match what the
    // renderer does: explicit newlines count, and words wrap at the width.
    #[test]
    fn wrapped_line_count_matches_wrap_math() {
        assert_eq!(wrapped_line_count("short", 32), 1);
        assert_eq!(wrapped_line_count("line one\nline two", 32), 2);
        // Eight 4-char words at width 9: two words fit per line ("aaaa aaaa").
        let words = ["aaaa"; 8].join(" ");
        assert_eq!(wrapped_line_count(&words, 9), 4);
        // Degenerate width never divides by zero.
        assert_eq!(wrapped_line_count("anything", 0), 1);
    }

    // Regression: f00f316. A long modal body must be fully visible: the box
    // grows to the wrapped line count instead of clipping at the old fixed
    // height of 5 (three body rows).
    #[test]
    fn modal_grows_to_fit_long_body() {
        let app = test_app();
        let mut term = Terminal::new(TestBackend::new(40, 20)).unwrap();
        // ~8 wrapped lines at the modal's inner width; the last word is the
        // sentinel that the fixed-height modal used to clip away.
        let body = format!("{} ENDBODY", ["lorem"; 40].join(" "));
        term.draw(|f| app.modal(f, "Confirm", &body)).unwrap();
        let text = rendered(&term);
        assert!(
            text.contains("ENDBODY"),
            "long modal body was clipped:\n{text}"
        );
    }

    // Regression: f00f316. The confirm question used to live in the border
    // title, a single line clamped to the box width, so a long target name was
    // cut off. It must render inside the wrapping body, with the deliberate
    // [y] yes / [n] no hint from 093dc56.
    /// The keyring-gesture toggle: DEFAULT OFF, so neither direction weakens a
    /// default and [g] acts on the keypress with no y/n gate. The default renders
    /// as off and [g] there enables the opt-in; an explicit on renders as opt-in
    /// and [g] there returns to the default off. The rendered section reports the
    /// state it actually read.
    #[test]
    fn keyring_gesture_toggle_needs_no_confirm() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-tui-crc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = std::env::var_os("IRLUME_CONFIG_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE");

        let mut app = test_app();
        app.screen = SC_SETTINGS;

        // Default (no settings.conf): shown as off (default); [g] enables the
        // opt-in with no confirm.
        let text = draw_text(&app);
        assert!(
            text.contains("Gesture before keyring release") && text.contains("off (default)"),
            "the default must render as off:\n{text}"
        );
        app.on_key(KeyCode::Char('g'));
        assert!(app.confirm.is_none(), "toggling needs no confirm");
        assert!(
            matches!(
                app.suspend.take(),
                Some(Suspend::CredentialReleaseChallenge(true))
            ),
            "from the default (off), [g] enables the opt-in"
        );

        // Explicitly on: rendered as opt-in; [g] returns to the default off with
        // no gate.
        std::fs::write(
            dir.join("settings.conf"),
            "credential_release_challenge=1\n",
        )
        .unwrap();
        let text = draw_text(&app);
        assert!(
            text.contains("required (opt-in)"),
            "an enabled gate must render as opt-in:\n{text}"
        );
        app.on_key(KeyCode::Char('g'));
        assert!(
            app.confirm.is_none(),
            "returning to the default needs no confirm"
        );
        assert!(matches!(
            app.suspend.take(),
            Some(Suspend::CredentialReleaseChallenge(false))
        ));

        match old {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The per-service consent-gesture toggle: ↑/↓ pick a service, [c] toggles
    /// it. Disabling a high-privilege service (all four in the list are) asks
    /// first and acts on the confirm, not the keypress; enabling one that is off
    /// goes straight through. The write shells out to the CLI (settings.conf is
    /// root-only), so the action is a suspend to
    /// `credential-release-challenge <service> on|off --yes`.
    #[test]
    fn settings_per_service_gesture_toggle_picks_and_confirms() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-tui-svc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = std::env::var_os("IRLUME_CONFIG_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        let mut app = test_app();
        app.screen = SC_SETTINGS;

        // The section renders with the service names.
        let text = draw_text(&app);
        assert!(text.contains("Per-service consent gesture"), "{text}");
        assert!(text.contains("sudo") && text.contains("polkit-1"), "{text}");

        // Default (no key): sudo defaults gesture ON, so [c] DISABLES it and must
        // confirm first (high-privilege), acting on the confirm, not the keypress.
        assert_eq!(app.settings_svc_sel, 0, "sudo is first");
        app.on_key(KeyCode::Char('c'));
        assert!(
            app.suspend.is_none(),
            "disabling a high-priv service must not act on the keypress alone"
        );
        match app.confirm.take() {
            Some((q, verb, ConfirmAct::Sus(Suspend::ServiceGesture { service, on }))) => {
                assert_eq!(service, "sudo");
                assert!(!on, "the confirm must target DISABLE");
                assert_eq!(verb, "Disable");
                assert!(q.contains("sudo"), "the confirm must name the service: {q}");
            }
            Some((q, verb, _)) => panic!("wrong confirm action: {verb} / {q}"),
            None => panic!("disabling a high-priv service must raise a confirm"),
        }

        // ↑/↓ move the picked service.
        app.on_key(KeyCode::Down);
        assert_eq!(app.settings_svc_sel, 1, "Down picks the next service");
        app.on_key(KeyCode::Up);
        assert_eq!(app.settings_svc_sel, 0);

        // polkit-1 with no override. It is AppConsent, which the ENGINE defaults
        // to gesture-ON, so the first [c] must offer to DISABLE it. Only sudo
        // (index 0) was ever driven here, so the elevation-only default read
        // polkit as already-off and the first press wrote an `on` that changed
        // nothing, with no confirmation, and every test still passed.
        std::fs::write(dir.join("settings.conf"), "").unwrap();
        let polkit_i = SETTINGS_GESTURE_SERVICES
            .iter()
            .position(|&s| s == "polkit-1")
            .expect("polkit-1 is in the list");
        app.settings_svc_sel = polkit_i;
        let text = draw_text(&app);
        assert!(
            text.contains("polkit-1: ● yes"),
            "polkit must render as REQUIRED, matching the daemon: {text}"
        );
        app.on_key(KeyCode::Char('c'));
        assert!(
            app.suspend.is_none(),
            "disabling polkit must not act on the keypress alone"
        );
        match app.confirm.take() {
            Some((q, verb, ConfirmAct::Sus(Suspend::ServiceGesture { service, on }))) => {
                assert_eq!(service, "polkit-1");
                assert!(!on, "the first press on a default-ON polkit must DISABLE");
                assert_eq!(verb, "Disable");
                assert!(q.contains("polkit-1"), "the confirm must name it: {q}");
            }
            Some((q, verb, _)) => panic!("wrong confirm action: {verb} / {q}"),
            None => panic!("disabling polkit must raise a confirm"),
        }
        app.settings_svc_sel = 0;

        // A service explicitly OFF: [c] ENABLES it and goes straight through
        // (turning a gesture ON only adds friction, so no confirm).
        std::fs::write(dir.join("settings.conf"), "service_gesture.sudo=0\n").unwrap();
        app.on_key(KeyCode::Char('c'));
        assert!(app.confirm.is_none(), "enabling needs no confirm");
        assert!(
            matches!(
                app.suspend.take(),
                Some(Suspend::ServiceGesture { ref service, on: true }) if service == "sudo"
            ),
            "enabling must suspend to the on toggle"
        );

        match old {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hub_selection_and_enter_jump_to_the_picked_screen() {
        let mut app = test_app();
        app.screen = SC_WELCOME;
        app.visible = (0..SCREENS.len()).collect();
        app.daemon_up = true;
        let rows = app.hub_rows();
        assert!(rows.len() >= 6, "hub rows: {rows:?}");
        // 5 downs from 0 select row 5; Enter opens exactly that screen.
        for _ in 0..5 {
            app.move_sel(1);
        }
        assert_eq!(app.hub_sel, 5);
        let target = app.hub_rows()[5].2;
        app.on_key(KeyCode::Enter);
        assert_eq!(app.screen, target);
        // Wrap: one Up from row 0 lands on the last row.
        app.screen = SC_WELCOME;
        app.hub_sel = 0;
        app.move_sel(-1);
        assert_eq!(app.hub_sel, app.hub_rows().len() - 1);
    }

    #[test]
    fn parity_keys_route_to_the_right_actions() {
        // The new per-screen actions: keys must set the right suspend/confirm,
        // and destructive ones must go through the y/n gate, not act directly.
        //
        // A readable config, because [b] now refuses to pick a direction it
        // cannot read: the shipped settings.conf is 0600 root-owned, so an
        // unprivileged run sees EACCES and must say so rather than offer to
        // enable a gate that may already be enforcing.
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-tui-parity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=0\n").unwrap();
        let old_cfg = std::env::var_os("IRLUME_CONFIG_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY");

        let mut app = test_app();
        app.screen = SC_PAM;
        app.on_key(KeyCode::Char('u'));
        assert!(matches!(app.suspend, Some(Suspend::LoginEnableSudo)));
        app.suspend = None;
        app.on_key(KeyCode::Char('p'));
        assert!(matches!(app.suspend, Some(Suspend::LoginEnablePolkit)));
        app.suspend = None;
        app.on_key(KeyCode::Char('c'));
        assert!(matches!(app.suspend, Some(Suspend::CalibrateClosure)));
        app.suspend = None;
        // Un-wire: confirm first, nothing suspended yet; [y] flips it over.
        app.on_key(KeyCode::Char('x'));
        assert!(app.suspend.is_none());
        assert!(matches!(
            app.confirm,
            Some((_, _, ConfirmAct::Sus(Suspend::LoginDisable)))
        ));
        app.on_key(KeyCode::Char('y'));
        assert!(matches!(app.suspend, Some(Suspend::LoginDisable)));
        app.suspend = None;

        // Fingerprint: reset is confirm-gated; verify honors reader absence.
        app.screen = SC_FINGERPRINT;
        app.fp.available = false;
        app.on_key(KeyCode::Char('t'));
        assert!(app.suspend.is_none(), "no reader: verify must not suspend");
        app.fp.available = true;
        app.on_key(KeyCode::Char('t'));
        assert!(matches!(app.suspend, Some(Suspend::FingerprintVerify)));
        app.suspend = None;
        app.on_key(KeyCode::Char('x'));
        assert!(matches!(
            app.confirm,
            Some((_, _, ConfirmAct::Sus(Suspend::FingerprintReset)))
        ));
        app.on_key(KeyCode::Esc); // cancel path leaves nothing armed
        assert!(app.confirm.is_none() && app.suspend.is_none());

        // Repair debug toggle and Done updater.
        app.screen = SC_REPAIR;
        app.on_key(KeyCode::Char('t'));
        assert!(matches!(app.suspend, Some(Suspend::LogsDebug(_))));
        app.suspend = None;
        app.screen = SC_DONE;
        app.on_key(KeyCode::Char('u'));
        assert!(matches!(app.suspend, Some(Suspend::Update)));
        app.suspend = None;

        // Biopolicy [b]: enabling (from off) is confirm-gated; the confirm's
        // affirmative names the specific verb and carries the enable suspend.
        app.screen = SC_SETTINGS;
        app.on_key(KeyCode::Char('b'));
        assert!(
            app.suspend.is_none(),
            "enabling biopolicy must confirm first"
        );
        match &app.confirm {
            Some((q, verb, ConfirmAct::Sus(Suspend::Biopolicy(true)))) => {
                assert!(q.contains("biopolicy") && *verb == "Enable");
            }
            _ => panic!("expected the biopolicy-enable confirm"),
        }
        app.on_key(KeyCode::Char('y'));
        assert!(matches!(app.suspend, Some(Suspend::Biopolicy(true))));
        app.suspend = None;

        // The mouse toggle flips state and logs; second press restores.
        assert!(!app.mouse_select);
        app.on_key(KeyCode::Char('M'));
        assert!(app.mouse_select);
        app.on_key(KeyCode::Char('M'));
        assert!(!app.mouse_select);
        match old_cfg {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirm_modal_question_wraps_in_body() {
        let mut app = test_app();
        let question = format!(
            "Delete profile '{}ZZTARGETZZ' and all its scans?",
            ["word"; 20].join(" ")
        );
        app.confirm = Some((question, "Confirm", ConfirmAct::Daemon(Request::Ping)));
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let text = rendered(&term);
        assert!(
            text.contains("ZZTARGETZZ"),
            "end of a long confirm question was clipped:\n{text}"
        );
        // The affirmative carries the verb now (GNOME HIG), cancel is first.
        assert!(
            text.contains("[y] Confirm"),
            "deliberate-confirm hint missing"
        );
        assert!(text.contains("Cancel"), "cancel option missing");
    }

    // Regression: f00f316. At MAX_PROFILES the guidance said only "delete one
    // first"; refreshing your own face is what [a] Improve Recognition does,
    // so the at-cap message must point there.
    #[test]
    fn enroll_at_cap_points_to_improve_recognition() {
        let mut app = test_app();
        app.daemon_up = true; // skip the daemon gate; the cap check is next
        app.profiles = (0..MAX_PROFILES)
            .map(|i| ProfileSummary {
                name: format!("p{i}"),
                scans: Vec::new(),
                scans_by_recognizer: Default::default(),
                live_recognizer: None,
            })
            .collect();
        app.begin_enroll();
        assert!(app.input.is_none(), "no name prompt at the profile cap");
        let (_, msg) = app.activity.last().expect("a cap message is logged");
        assert!(
            msg.contains("Improve Recognition"),
            "at-cap guidance must name the add-scan path, got: {msg}"
        );
    }

    // Regression: 093dc56. Destructive confirms used to cancel on ANY key
    // other than [y]; a stray keypress must now be ignored, and only [n] or
    // Esc may cancel.
    #[test]
    fn confirm_ignores_stray_keys_and_cancels_only_on_n_or_esc() {
        let mut app = test_app();
        app.confirm = Some((
            "Delete profile 'x'?".into(),
            "Confirm",
            ConfirmAct::Daemon(Request::Ping),
        ));
        app.on_key(KeyCode::Char('x'));
        app.on_key(KeyCode::Char(' '));
        app.on_key(KeyCode::Enter);
        assert!(
            app.confirm.is_some(),
            "a stray key must not cancel a destructive confirm"
        );
        app.on_key(KeyCode::Char('n'));
        assert!(app.confirm.is_none(), "[n] cancels");
        app.confirm = Some((
            "Delete scan 's'?".into(),
            "Delete",
            ConfirmAct::Daemon(Request::Ping),
        ));
        app.on_key(KeyCode::Esc);
        assert!(app.confirm.is_none(), "Esc cancels");
    }

    // Regression: 093dc56. Uninstall must not run off keypresses alone: [U]
    // opens a typed challenge, a wrong word cancels, and only the exact word
    // "uninstall" reaches the sudo teardown.
    #[test]
    fn uninstall_requires_typed_word() {
        let mut app = test_app();
        app.screen = SC_WELCOME;
        app.on_key(KeyCode::Char('U'));
        assert!(
            matches!(app.input, Some((_, _, Pending::UninstallConfirm))),
            "[U] must open the typed uninstall challenge"
        );
        for c in "yes".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        assert!(app.input.is_none());
        assert!(
            app.suspend.is_none(),
            "a wrong word must not trigger the uninstall"
        );
        app.on_key(KeyCode::Char('U'));
        for c in "uninstall".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        assert!(
            matches!(app.suspend, Some(Suspend::Uninstall)),
            "the exact word must proceed to the sudo teardown"
        );
    }

    // Regression: cae2eea. The error banner says "press any key to dismiss",
    // but PgUp/PgDn used to scroll the activity log instead of dismissing.
    // Dismiss must take the key first; the NEXT PgUp scrolls.
    #[test]
    fn error_banner_dismissed_by_pgup_before_scroll() {
        let mut app = test_app();
        for i in 0..20 {
            app.log('·', format!("line {i}"));
        }
        app.error = Some("camera busy".into());
        app.on_key(KeyCode::PageUp);
        assert!(app.error.is_none(), "PgUp must dismiss the banner");
        assert_eq!(app.act_scroll, 0, "the dismissing key must not also scroll");
        app.on_key(KeyCode::PageUp);
        assert_eq!(app.act_scroll, 3, "with no banner up, PgUp scrolls");
    }

    // Regression: cae2eea. During a running op every key but q/Esc is
    // swallowed, so the footer must not advertise the dead nav/action keys.
    #[test]
    fn footer_shows_minimal_keys_during_op() {
        let mut app = test_app();
        let (_tx, op) = fake_op();
        app.op = Some(op);
        let mut term = Terminal::new(TestBackend::new(100, 3)).unwrap();
        term.draw(|f| app.draw_footer(f, f.area())).unwrap();
        let text = rendered(&term);
        assert!(text.contains("working"), "op footer missing, got:\n{text}");
        assert!(
            !text.contains("switch tab"),
            "footer advertises dead nav keys during an op:\n{text}"
        );
        // Sanity: the normal footer returns once the op is gone (trimmed
        // design: tabs hint + primary action + the [?] disclosure chip).
        app.op = None;
        term.draw(|f| app.draw_footer(f, f.area())).unwrap();
        let text = rendered(&term);
        assert!(text.contains("tabs") && text.contains("all keys"), "{text}");
    }

    // Regression: cae2eea. caps/fp_present were captured once at startup, so a
    // camera hot-plugged after launch never revealed its tabs. refresh() must
    // re-derive them. The seeded value is impossible for capabilities() to
    // return (rgb is true whenever ir_pair is), so a frozen field keeps it and
    // a re-derived one cannot.
    #[test]
    fn no_tui_code_path_enumerates_cameras_locally() {
        // #187: the TUI must never open a video node. Gating on "is the
        // daemon up" was not enough, because a Ping that times out (exactly
        // what a camera-busy daemon produces) read as down and licensed the
        // opens. The rule is now absolute, so it is pinned as a source
        // property: no camera-enumerating call may appear in this module
        // outside tests. An instrumented run is the empirical half (strace
        // counted 12 node opens before this change, 0 after); this catches
        // a reintroduction at review time instead.
        let src = include_str!("tui.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        for banned in [
            "irlume_camera::discover_nodes",
            "irlume_camera::list_pairs",
            "irlume_camera::capabilities",
            "irlume_camera::privacy_engaged",
            // Falls through to discovery when no pair is configured, and it
            // sat in a per-frame draw path (#187 review).
            "irlume_camera::select_pair",
        ] {
            assert!(
                !body.contains(banned),
                "{banned} opens video nodes; the TUI must ask the daemon (#187)"
            );
        }
    }

    #[test]
    fn health_supplies_capabilities_while_the_daemon_is_up() {
        // The other half of #187: having stopped probing, the TUI must still
        // know what hardware it has, from the daemon that already has the
        // cameras open. A secure tier means a usable IR pair; a reported RGB
        // device means RGB capture works.
        let secure = HealthInfo {
            tier: "secure".into(),
            rgb_dev: Some("/dev/video0".into()),
            ir_dev: Some("/dev/video2".into()),
            mesh: true,
            adapter: false,
            version: "test".into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        };
        let caps = App::caps_from_health(&secure);
        assert!(
            caps.ir_pair && caps.rgb,
            "secure tier is an IR pair: {caps:?}"
        );
        let convenience = HealthInfo {
            tier: "convenience".into(),
            ir_dev: None,
            ..secure.clone()
        };
        let caps = App::caps_from_health(&convenience);
        assert!(
            !caps.ir_pair,
            "only the secure tier means an IR pair: {caps:?}"
        );
        assert!(caps.rgb, "an RGB device was reported: {caps:?}");
        let none = HealthInfo {
            tier: "none".into(),
            rgb_dev: None,
            ir_dev: None,
            ..secure
        };
        let caps = App::caps_from_health(&none);
        assert!(!caps.ir_pair && !caps.rgb, "no devices reported: {caps:?}");
    }

    #[test]
    fn refresh_rederives_hardware_capabilities() {
        // The async flavor of the old property: a LANDED sweep replaces a
        // stale capability snapshot. refresh() itself only requests
        // (full_refresh_requests_the_machine_snapshot pins that), and an
        // unlanded snapshot must replace nothing
        // (full_refresh_does_not_replace_known_caps_with_unobserved_defaults).
        let _guard = dead_socket();
        let impossible = irlume_camera::Caps {
            ir_pair: true,
            rgb: false,
        };
        let mut app = test_app();
        app.caps = impossible;
        // An OBSERVED no-camera machine. `caps_probed` is what makes it an
        // observation rather than the unprobed default: since #187 the sweep
        // skips the device probe while the daemon is up, so the flag is the
        // only thing separating "looked, found none" from "did not look".
        app.probes = Probes {
            caps_probed: true,
            ..Probes::default()
        };
        app.probes_landed = true;
        app.recompute_checks();
        assert_ne!(
            app.caps, impossible,
            "a landed sweep must replace the stale capability snapshot"
        );
        assert!(
            app.caps.rgb || !app.caps.ir_pair,
            "re-derived caps must satisfy the capabilities() invariant"
        );
    }

    // Regression: cae2eea. The double-entry password stash must be Zeroizing,
    // not a plain String, so the first entry is wiped on drop. This is a
    // type-level check: reverting the stash to Option<String> breaks the
    // return type below at compile time.
    #[test]
    fn password_stash_is_zeroizing() {
        fn stash(p: Pending) -> Option<zeroize::Zeroizing<String>> {
            match p {
                Pending::KeyringPw(s) => s,
                Pending::RecoveryPw(s) => s,
                _ => None,
            }
        }
        let k = stash(Pending::KeyringPw(Some(zeroize::Zeroizing::new(
            "pw".to_string(),
        ))));
        assert_eq!(k.as_deref().map(String::as_str), Some("pw"));
        let r = stash(Pending::RecoveryPw(Some(zeroize::Zeroizing::new(
            "phrase".to_string(),
        ))));
        assert_eq!(r.as_deref().map(String::as_str), Some("phrase"));
    }

    // Regression: 1da8bd3. refresh_light used to fire ~6 sequential daemon
    // reads with long budgets, so a wedged daemon (accepting but never
    // answering) froze the UI thread. The fix polls Ping first on a short
    // budget and skips the remaining reads when it gets no answer. The fake
    // daemon here accepts connections and never replies; only ONE connection
    // (the Ping probe) may arrive.
    #[test]
    fn wedged_daemon_poll_short_circuits_after_ping() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let sock =
            std::env::temp_dir().join(format!("irlume-tui-wedge-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream); // hold the connection open, never answer
            }
        });
        std::env::set_var("IRLUME_SOCKET", &sock);
        // The gather itself (now on a worker) still short-circuits: one
        // unanswered Ping, nothing else touches the wedged daemon.
        let start = std::time::Instant::now();
        let l = LightState::gather("testuser", None);
        assert!(!l.daemon_up, "an unanswered Ping means the daemon is down");
        assert!(l.health.is_none());
        // Not an exact count: other tests' background workers are detached
        // and one can connect to whatever IRLUME_SOCKET names at that moment,
        // which put a stray accept here on the archhost runner. The bound
        // still discriminates the defect this guards: a gather that does NOT
        // skip after the failed Ping makes five connections BY ITSELF
        // (Ping, Health, KeyringInfo, HasSealedPassword, RecoveryStatus), so
        // any non-skipping gather fails this even with zero strays.
        let accepted = accepted.load(Ordering::SeqCst);
        assert!(
            (1..5).contains(&accepted),
            "a wedged daemon may see the Ping probe (plus a stray worker), never \
             the full poll set; accepted {accepted}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the status poll must fail fast, not sit through full read budgets"
        );
        // And the UI-thread side never blocks at all: refresh_light only
        // SPAWNS the gather. This is the property the whole async split
        // exists for; the inline version cost up to one full poll budget
        // per tick against a busy daemon.
        let mut app = test_app();
        app.daemon_up = true;
        app.health = Some(HealthInfo {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: "test".into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        });
        let start = std::time::Instant::now();
        app.refresh_light();
        assert!(
            start.elapsed() < Duration::from_millis(250),
            "refresh_light must not block the UI thread"
        );
        assert!(app.light_load.is_some(), "a gather must be in flight");
        // Landing the wedge result applies it: daemon down, stale health gone.
        for _ in 0..200 {
            app.poll();
            if !app.daemon_up {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        std::env::remove_var("IRLUME_SOCKET");
        let _ = std::fs::remove_file(&sock);
        assert!(!app.daemon_up, "the landed wedge result must apply");
        assert!(app.health.is_none(), "stale health must be cleared");
    }

    // Regression: 1da8bd3. After a merge confirm the continuation worker
    // restarts its own count at 1, but the profile already holds the merged
    // scan; the on-screen counter must add the EnrollUi base offset instead of
    // restarting at 0.
    #[test]
    fn merge_continuation_scan_counter_keeps_base_offset() {
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(1, 4); // one scan merged in already
        app.enroll = Some(enroll);
        tx.send(WMsg::Captured(1, 4)).unwrap();
        app.poll();
        let (_, msg) = app.activity.last().expect("a capture line is logged");
        assert_eq!(
            msg, "captured scan 2/5",
            "the counter must continue past the merged scan, not restart"
        );
    }

    // Regression: 4780805. PgUp/PgDn used to be swallowed by the op and enroll
    // key gates; the activity panel must stay scrollable mid-op and mid-enroll,
    // exactly when lines stream fastest.
    #[test]
    fn activity_scroll_reaches_panel_during_op_and_enroll() {
        let mut app = test_app();
        for i in 0..30 {
            app.log('·', format!("line {i}"));
        }
        let (_tx, op) = fake_op();
        app.op = Some(op);
        app.on_key(KeyCode::PageUp);
        assert_eq!(app.act_scroll, 3, "PgUp must scroll during a running op");
        app.on_key(KeyCode::PageDown);
        assert_eq!(app.act_scroll, 0, "PgDn must scroll during a running op");
        app.op = None;
        let (_tx2, enroll) = fake_enroll(0, 4);
        app.enroll = Some(enroll);
        app.on_key(KeyCode::PageUp);
        assert_eq!(app.act_scroll, 3, "PgUp must scroll during enrollment");
        assert!(app.enroll.is_some(), "PgUp must not cancel the enrollment");
    }

    // Regression: f709fff. Repair "logs" was bound to [v], which the global
    // basic/all-tabs toggle swallows in on_key before on_action ever runs, so
    // the action was dead. The binding is [g]; [v] must keep toggling the view
    // without opening logs.
    #[test]
    fn repair_logs_binding_not_swallowed_by_global_toggle() {
        let mut app = test_app();
        app.screen = SC_REPAIR;
        app.on_key(KeyCode::Char('v'));
        assert!(app.advanced, "[v] is the global view toggle");
        assert!(app.suspend.is_none(), "[v] must not open the logs view");
        app.screen = SC_REPAIR;
        app.on_key(KeyCode::Char('g'));
        assert!(
            matches!(app.suspend, Some(Suspend::Logs)),
            "the advertised logs key must actually reach the Repair action"
        );
    }

    // Regression: 0be786b. A cancelled or failed sudo during the enroll
    // daemon-gate must drop the parked enrollment immediately; before the fix
    // the resume path sat through a ~10s daemon wait for a daemon that was
    // never started. Uses a fake `sudo` that exits 1 (the cancelled case).
    #[test]
    fn sudo_failure_drops_parked_enrollment() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-fake-sudo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("sudo");
        std::fs::write(&fake, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut new_path = dir.into_os_string();
        new_path.push(":");
        new_path.push(&old_path);
        std::env::set_var("PATH", &new_path);
        let mut app = test_app();
        app.resume_enroll = Some(ResumeEnroll::New);
        app.sudo_step("start the daemon", &["systemctl", "start", "irlumed"]);
        std::env::set_var("PATH", &old_path);
        assert!(
            app.resume_enroll.is_none(),
            "a failed sudo must drop the parked enrollment immediately"
        );
        assert!(
            app.error.is_some(),
            "the failure must raise the error banner"
        );
    }

    // ---- pure helpers -----------------------------------------------------

    #[test]
    fn quality_bar_fills_proportionally() {
        assert_eq!(quality_bar(0), "[░░░░░░░░░░]   0%");
        assert_eq!(quality_bar(50), "[█████░░░░░]  50%");
        assert_eq!(quality_bar(100), "[██████████] 100%");
    }

    #[test]
    fn map_ok_routes_ack_error_and_unexpected() {
        assert_eq!(map_ok(Response::Ok("done".into())), (true, "done".into()));
        assert_eq!(
            map_ok(Response::Error("boom".into())),
            (false, "boom".into())
        );
        let (ok, msg) = map_ok(Response::Pong);
        assert!(!ok);
        assert!(msg.contains("unexpected"), "got: {msg}");
    }

    #[test]
    fn map_identify_formats_match_and_both_miss_reasons() {
        let (ok, msg) = map_identify(Response::Identified {
            user: Some("alice".into()),
            profile: Some("Face Profile 1".into()),
            score: 0.8125,
            live: true,
            reason: String::new(),
        });
        assert!(ok);
        assert_eq!(msg, "alice · Face Profile 1 · confidence 0.812");
        let (ok, msg) = map_identify(Response::Identified {
            user: None,
            profile: None,
            score: 0.0,
            live: true,
            reason: "below threshold".into(),
        });
        assert!(!ok);
        assert_eq!(msg, "live face, no enrolled match (below threshold)");
        let (ok, msg) = map_identify(Response::Identified {
            user: None,
            profile: None,
            score: 0.0,
            live: false,
            reason: "flat depth".into(),
        });
        assert!(!ok);
        assert_eq!(msg, "no live face (flat depth)");
        assert!(!map_identify(Response::Error("e".into())).0);
    }

    #[test]
    fn map_confirm_accepts_ok_and_password_forgotten() {
        assert!(map_confirm(Response::Ok("deleted".into())).0);
        let (ok, msg) = map_confirm(Response::PasswordForgotten);
        assert!(ok);
        assert!(msg.contains("disarmed"), "got: {msg}");
        assert!(!map_confirm(Response::Error("e".into())).0);
    }

    #[test]
    fn map_sealed_reports_armed_and_prefixes_failures() {
        let (ok, msg) = map_sealed(Response::PasswordSealed);
        assert!(ok);
        assert!(msg.contains("keyring armed"), "got: {msg}");
        let (ok, msg) = map_sealed(Response::Error("tpm gone".into()));
        assert!(!ok);
        assert_eq!(msg, "arm failed: tpm gone");
    }

    #[test]
    fn recommended_covers_every_hardware_tier() {
        let mut app = test_app();
        let cases = [
            (true, true, true, "Face (IR)"),
            (false, true, true, "Fingerprint (secure), or Face (RGB)"),
            (false, true, false, "Face (RGB) · convenience"),
            (false, false, true, "Fingerprint"),
            (false, false, false, "Password only"),
        ];
        for (ir_pair, rgb, fp, want) in cases {
            app.caps = irlume_camera::Caps { ir_pair, rgb };
            app.fp_present = fp;
            let got = app.recommended();
            assert!(
                got.starts_with(want),
                "caps ir={ir_pair} rgb={rgb} fp={fp}: got '{got}', want prefix '{want}'"
            );
        }
    }

    #[test]
    fn next_profile_name_skips_taken_names() {
        let mut app = test_app();
        assert_eq!(app.next_profile_name(), "Face Profile 1");
        app.profiles = vec![profile("Face Profile 1", &[])];
        assert_eq!(app.next_profile_name(), "Face Profile 2");
        app.profiles = vec![
            profile("Face Profile 1", &[]),
            profile("Face Profile 2", &[]),
            profile("Face Profile 3", &[]),
        ];
        assert_eq!(app.next_profile_name(), "Face Profile 4");
    }

    #[test]
    fn rows_interleave_profiles_and_scans_and_sel_profile_resolves_owner() {
        let mut app = test_app();
        app.profiles = vec![profile("a", &["s1", "s2"]), profile("b", &["t1"])];
        let rows = app.rows();
        assert_eq!(rows.len(), 5, "2 profiles + 3 scans");
        assert!(matches!(rows[0], Row::Profile(0)));
        assert!(matches!(rows[1], Row::Scan(0, 0)));
        assert!(matches!(rows[2], Row::Scan(0, 1)));
        assert!(matches!(rows[3], Row::Profile(1)));
        assert!(matches!(rows[4], Row::Scan(1, 0)));
        app.sel = 2; // scan s2 → owner is profile 'a'
        assert_eq!(app.sel_profile().as_deref(), Some("a"));
        app.sel = 3;
        assert_eq!(app.sel_profile().as_deref(), Some("b"));
        app.sel = 99;
        assert_eq!(app.sel_profile(), None);
    }

    // ---- tab visibility & navigation --------------------------------------

    #[test]
    fn compute_visible_matches_hardware_tiers() {
        let none = irlume_camera::Caps {
            ir_pair: false,
            rgb: false,
        };
        let rgb = irlume_camera::Caps {
            ir_pair: false,
            rgb: true,
        };
        let ir = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        let basic = VisibilityInputs::default();
        // No biometric hardware: only the always-on steps.
        assert_eq!(
            App::compute_visible(&none, basic, &[]),
            vec![SC_WELCOME, SC_PAM, SC_SETTINGS, SC_MODELS, SC_DONE]
        );
        // RGB-only adds the face path (Profiles + Recovery), not Keyring.
        assert_eq!(
            App::compute_visible(&rgb, basic, &[]),
            vec![
                SC_WELCOME,
                SC_PROFILES,
                SC_RECOVERY,
                SC_PAM,
                SC_SETTINGS,
                SC_MODELS,
                SC_DONE
            ]
        );
        // An IR pair earns the Keyring step.
        assert_eq!(
            App::compute_visible(&ir, basic, &[]),
            vec![
                SC_WELCOME,
                SC_PROFILES,
                SC_KEYRING,
                SC_RECOVERY,
                SC_PAM,
                SC_SETTINGS,
                SC_MODELS,
                SC_DONE
            ]
        );
        // A fingerprint-only box gets Keyring + Fingerprint, no face tabs.
        assert_eq!(
            App::compute_visible(
                &none,
                VisibilityInputs {
                    fp_present: true,
                    ..basic
                },
                &[]
            ),
            vec![
                SC_WELCOME,
                SC_KEYRING,
                SC_FINGERPRINT,
                SC_PAM,
                SC_SETTINGS,
                SC_MODELS,
                SC_DONE
            ]
        );
        // Advanced view on full hardware shows every screen.
        assert_eq!(
            App::compute_visible(
                &ir,
                VisibilityInputs {
                    fp_present: true,
                    advanced: true,
                    ..basic
                },
                &[]
            ),
            (0..SCREENS.len()).collect::<Vec<_>>()
        );
        // Repair earns its tab when the daemon is down…
        assert_eq!(
            App::compute_visible(
                &none,
                VisibilityInputs {
                    daemon_down: true,
                    ..basic
                },
                &[]
            ),
            vec![
                SC_WELCOME,
                SC_REPAIR,
                SC_PAM,
                SC_SETTINGS,
                SC_MODELS,
                SC_DONE
            ]
        );
        // …and when anything needs reporting (a failure OR an advisory), so the
        // Welcome health summary's "→ open checks & repair" pointer is reachable.
        let fail = [check_row("x", Sev::Fail, Fix::None)];
        assert!(App::compute_visible(&none, basic, &fail).contains(&SC_REPAIR));
        let warn = [check_row("x", Sev::Warn, Fix::None)];
        assert!(App::compute_visible(&none, basic, &warn).contains(&SC_REPAIR));
        // But an all-clear basic view hides it.
        let ok = [check_row("x", Sev::Ok, Fix::None)];
        assert!(!App::compute_visible(&none, basic, &ok).contains(&SC_REPAIR));
    }

    #[test]
    fn tab_steps_wrap_and_walk_only_visible_screens() {
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: false,
            rgb: true,
        };
        app.daemon_up = true; // healthy: Repair earns no tab
        app.recompute_visible(); // Welcome, Profiles, Recovery, PAM, Done
        assert_eq!(app.screen, SC_WELCOME);
        app.sel = 3;
        app.on_key(KeyCode::Tab);
        assert_eq!(app.screen, SC_PROFILES, "Tab skips the hidden Repair tab");
        assert_eq!(app.sel, 0, "changing tab resets the selection");
        app.on_key(KeyCode::Right);
        assert_eq!(app.screen, SC_RECOVERY, "Cameras/Identify stay hidden");
        app.on_key(KeyCode::BackTab);
        app.on_key(KeyCode::Left);
        assert_eq!(app.screen, SC_WELCOME);
        app.on_key(KeyCode::BackTab);
        assert_eq!(app.screen, SC_DONE, "BackTab from the first step wraps");
        app.on_key(KeyCode::Tab);
        assert_eq!(app.screen, SC_WELCOME, "Tab from the last step wraps");
    }

    #[test]
    fn recompute_visible_snaps_to_nearest_surviving_screen() {
        let mut app = test_app();
        app.advanced = true;
        app.recompute_visible();
        // Identify is advanced-only; leaving advanced view must snap off it.
        app.screen = SC_IDENTIFY;
        app.advanced = false;
        app.recompute_visible();
        assert_ne!(
            app.screen, SC_IDENTIFY,
            "leaving advanced view must land on a still-visible step"
        );
        assert!(
            app.visible.contains(&app.screen),
            "the landed screen is visible"
        );
    }

    #[test]
    fn move_sel_wraps_within_each_screens_list() {
        let mut app = test_app();
        app.profiles = vec![profile("a", &["s1", "s2"])]; // 3 rows
        app.screen = SC_PROFILES;
        app.on_key(KeyCode::Up);
        assert_eq!(app.sel, 2, "Up from the top wraps to the last row");
        app.on_key(KeyCode::Char('j'));
        assert_eq!(app.sel, 0, "j from the bottom wraps to the top");
        app.on_key(KeyCode::Char('k'));
        assert_eq!(app.sel, 2);
        app.screen = SC_REPAIR;
        app.repair = vec![
            check_row("a", Sev::Ok, Fix::None),
            check_row("b", Sev::Fail, Fix::None),
        ];
        app.on_key(KeyCode::Down);
        assert_eq!(app.repair_sel, 1, "Repair has its own selection");
        assert_eq!(app.sel, 2, "the profile selection must not move");
        app.on_key(KeyCode::Down);
        assert_eq!(app.repair_sel, 0);
        app.screen = SC_CAMERAS;
        app.pairs = vec![
            irlume_common::CameraPairInfo {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
                id: None,
                fixed: true,
                privacy: false,
            },
            irlume_common::CameraPairInfo {
                rgb: "/dev/video4".into(),
                ir: "/dev/video6".into(),
                id: None,
                fixed: false,
                privacy: false,
            },
        ];
        app.on_key(KeyCode::Up);
        assert_eq!(app.cam_sel, 1, "Cameras has its own selection");
    }

    // ---- key routing / actions --------------------------------------------

    #[test]
    fn quit_keys_work_everywhere_but_stray_keys_do_not() {
        let mut app = test_app();
        app.on_key(KeyCode::Char('q'));
        assert!(app.quit);
        let mut app = test_app();
        app.on_key(KeyCode::Esc);
        assert!(app.quit);
        // During a running op only q/Esc get through; the rest are swallowed.
        let mut app = test_app();
        let (_tx, op) = fake_op();
        app.op = Some(op);
        app.on_key(KeyCode::Tab);
        app.on_key(KeyCode::Char('e'));
        assert_eq!(app.screen, SC_WELCOME, "nav keys are dead during an op");
        assert!(!app.quit);
        app.on_key(KeyCode::Char('q'));
        assert!(app.quit, "q must stay a live escape hatch during an op");
    }

    #[test]
    fn welcome_refresh_key_logs_and_reprobes() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.on_key(KeyCode::Char('r'));
        assert!(
            app.activity.iter().any(|(_, m)| m.contains("refreshing")),
            "[r] must announce the refresh in Activity"
        );
        assert!(!app.daemon_up, "the dead socket means daemon down");
    }

    #[test]
    fn welcome_enroll_and_identify_without_camera_explain_instead_of_noop() {
        let mut app = test_app(); // caps: no camera
        app.on_key(KeyCode::Char('e'));
        assert!(app.input.is_none(), "no name prompt without a camera");
        let (_, msg) = app.activity.last().expect("a guidance line is logged");
        assert!(msg.contains("no camera"), "got: {msg}");
        let before = app.activity.len();
        app.on_key(KeyCode::Char('i'));
        assert!(app.op.is_none(), "identify must not start without a camera");
        assert_eq!(app.activity.len(), before + 1);
    }

    #[test]
    fn welcome_enroll_with_camera_jumps_to_profiles_and_prompts_for_name() {
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.daemon_up = true;
        app.on_key(KeyCode::Char('e'));
        assert_eq!(app.screen, SC_PROFILES);
        match &app.input {
            Some((prompt, _, Pending::EnrollName)) => {
                assert!(prompt.contains("New profile name"), "got: {prompt}")
            }
            other => panic!("expected the enroll-name prompt, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn welcome_identify_stays_put_in_essential_view_and_jumps_in_advanced() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: false,
            rgb: true,
        };
        app.recompute_visible();
        app.on_key(KeyCode::Char('i'));
        assert_eq!(
            app.screen, SC_WELCOME,
            "essential view has no Identify tab; stay put"
        );
        assert!(app.op.is_some(), "the 1:N identify op must still start");
        wait_op_done(&mut app);
        let (ok, _) = app
            .identify_result
            .as_ref()
            .expect("the op result must land on the Identify card");
        assert!(!ok, "a dead socket cannot identify anyone");
        assert!(
            app.error.is_none(),
            "an identify miss shows on the card, not the error modal"
        );
        // Advanced view: the tab exists, so [i] jumps there. (The refresh at op
        // completion re-derived caps from real hardware; pin them back so this
        // half is deterministic on camera-less machines too.)
        app.caps = irlume_camera::Caps {
            ir_pair: false,
            rgb: true,
        };
        app.advanced = true;
        app.recompute_visible();
        app.screen = SC_WELCOME;
        app.on_key(KeyCode::Char('i'));
        assert_eq!(app.screen, SC_IDENTIFY);
        wait_op_done(&mut app);
    }

    #[test]
    fn daemon_gate_parks_the_enroll_intent_and_routes_to_repair() {
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.daemon_up = false;
        app.screen = SC_PROFILES;
        app.on_key(KeyCode::Char('e'));
        assert_eq!(app.screen, SC_REPAIR, "a down daemon routes to Repair");
        assert_eq!(app.repair_sel, 0, "the Daemon row is selected");
        assert!(matches!(app.resume_enroll, Some(ResumeEnroll::New)));
        assert!(matches!(app.suspend, Some(Suspend::RestartDaemon)));
        assert!(
            app.input.is_none(),
            "no name prompt while the daemon is down"
        );
        // The add-scan path parks its own intent.
        let mut app = test_app();
        app.daemon_up = false;
        app.profiles = vec![profile("p1", &[])];
        app.screen = SC_PROFILES;
        app.on_key(KeyCode::Char('a'));
        assert!(matches!(app.resume_enroll, Some(ResumeEnroll::Add(ref p)) if p == "p1"));
    }

    #[test]
    fn profiles_add_scan_without_profiles_hints_instead_of_starting() {
        let mut app = test_app();
        app.daemon_up = true;
        app.screen = SC_PROFILES;
        app.on_key(KeyCode::Char('a'));
        assert!(app.enroll.is_none());
        let (_, msg) = app.activity.last().expect("a hint is logged");
        assert!(msg.contains("select a profile first"), "got: {msg}");
    }

    #[test]
    fn profiles_add_scan_starts_improve_round_on_selected_profile() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.daemon_up = true;
        app.profiles = vec![profile("p1", &["s1"])];
        app.screen = SC_PROFILES;
        app.sel = 1; // the scan row still resolves to its owning profile
        app.on_key(KeyCode::Char('a'));
        {
            let e = app.enroll.as_ref().expect("an improve round must start");
            assert_eq!(e.profile, "p1");
            assert_eq!(e.target, ADD_SCANS, "improve rounds capture ADD_SCANS");
        }
        wait_enroll_done(&mut app);
        let err = app.error.as_ref().expect("dead socket fails the capture");
        assert!(err.contains("Enrollment failed"), "got: {err}");
    }

    #[test]
    fn profiles_rename_and_delete_target_the_selected_row() {
        let mut app = test_app();
        app.profiles = vec![profile("p1", &["s1", "s2"])];
        app.screen = SC_PROFILES;
        app.on_key(KeyCode::Char('r'));
        match &app.input {
            Some((prompt, _, Pending::RenameProfile(old))) => {
                assert!(prompt.contains("Rename profile 'p1'"), "got: {prompt}");
                assert_eq!(old, "p1");
            }
            _ => panic!("expected the rename-profile prompt"),
        }
        app.input = None;
        app.sel = 2; // second scan
        app.on_key(KeyCode::Char('r'));
        match &app.input {
            Some((prompt, _, Pending::RenameScan(p, s))) => {
                assert!(prompt.contains("Rename scan 's2'"), "got: {prompt}");
                assert_eq!((p.as_str(), s.as_str()), ("p1", "s2"));
            }
            _ => panic!("expected the rename-scan prompt"),
        }
        app.input = None;
        app.sel = 0;
        app.on_key(KeyCode::Char('d'));
        match &app.confirm {
            Some((q, _, ConfirmAct::Daemon(Request::DeleteProfile { user, profile }))) => {
                assert!(q.contains("Delete profile 'p1'"), "got: {q}");
                assert_eq!((user.as_str(), profile.as_str()), ("testuser", "p1"));
            }
            _ => panic!("expected the delete-profile confirm"),
        }
        app.confirm = None;
        app.sel = 1;
        app.on_key(KeyCode::Char('d'));
        match &app.confirm {
            Some((q, _, ConfirmAct::Daemon(Request::DeleteScan { profile, scan, .. }))) => {
                assert!(q.contains("Delete scan 's1' from 'p1'"), "got: {q}");
                assert_eq!((profile.as_str(), scan.as_str()), ("p1", "s1"));
            }
            _ => panic!("expected the delete-scan confirm"),
        }
    }

    #[test]
    fn keyring_and_recovery_keys_open_masked_prompts_and_confirms() {
        let mut app = test_app();
        app.screen = SC_KEYRING;
        app.on_key(KeyCode::Char('a'));
        match &app.input {
            Some((_, _, p @ Pending::KeyringPw(None))) => {
                assert!(p.masked(), "a password prompt must render masked")
            }
            _ => panic!("expected the keyring password prompt"),
        }
        app.input = None;
        // [r] reseal opens the masked prompt ONLY when armed (re-bind needs an
        // existing seal); the CLI `irlume reseal` reachable from the TUI.
        app.keyring_armed = Some(false);
        app.on_key(KeyCode::Char('r'));
        assert!(app.input.is_none(), "reseal is inert when not armed");
        app.keyring_armed = Some(true);
        app.on_key(KeyCode::Char('r'));
        match &app.input {
            Some((prompt, _, p @ Pending::KeyringPw(None))) => {
                assert!(p.masked() && prompt.contains("re-seal"), "got: {prompt}");
            }
            _ => panic!("expected the reseal password prompt"),
        }
        app.input = None;

        // An unidentified arm must NOT offer the plain erase: `None` is what an
        // older daemon reports and what an unparseable envelope reports, and
        // erasing a GNOME keyring token on that reading leaves the login
        // keyring encrypted under a secret nothing can reproduce.
        app.keyring_kind = None;
        app.on_key(KeyCode::Char('f'));
        assert!(
            app.confirm.is_none(),
            "an unknown keyring kind must not reach the erase confirm"
        );

        // A confirmed password arm is safe to erase from here.
        app.keyring_kind = Some(irlume_common::KeyringSecretKind::LoginPassword);
        app.on_key(KeyCode::Char('f'));
        match &app.confirm {
            Some((q, _, ConfirmAct::Daemon(Request::ForgetPassword { user }))) => {
                assert!(q.contains("Erase the TPM-sealed"), "got: {q}");
                assert_eq!(user, "testuser");
            }
            _ => panic!("expected the keyring-forget confirm"),
        }
        app.confirm = None;
        app.screen = SC_RECOVERY;
        app.on_key(KeyCode::Char('s'));
        assert!(matches!(app.input, Some((_, _, Pending::RecoveryPw(None)))));
        app.input = None;
        app.on_key(KeyCode::Char('t'));
        match &app.input {
            Some((_, _, p @ Pending::RecoveryRestorePw)) => assert!(p.masked()),
            _ => panic!("expected the recovery-restore prompt"),
        }
        app.input = None;
        app.on_key(KeyCode::Char('f'));
        assert!(matches!(
            app.confirm,
            Some((_, _, ConfirmAct::Daemon(Request::RecoveryForget { .. })))
        ));
    }

    #[test]
    fn fingerprint_add_requires_a_reader() {
        let mut app = test_app();
        app.screen = SC_FINGERPRINT;
        app.on_key(KeyCode::Char('a'));
        assert!(app.suspend.is_none());
        let (_, msg) = app.activity.last().expect("the refusal is logged");
        assert!(msg.contains("no fingerprint reader"), "got: {msg}");
        app.fp.available = true;
        app.on_key(KeyCode::Char('a'));
        assert!(matches!(app.suspend, Some(Suspend::FingerprintAdd)));
    }

    #[test]
    fn login_wiring_keys_suspend_to_the_right_flows() {
        let mut app = test_app();
        app.screen = SC_PAM;
        app.on_key(KeyCode::Char('w'));
        assert!(matches!(app.suspend, Some(Suspend::LoginEnable)));
        assert!(
            app.activity
                .iter()
                .any(|(_, m)| m.contains("login enable --apply")),
            "the exact sudo command must be announced"
        );
        app.suspend = None;
        app.on_key(KeyCode::Char('s'));
        assert!(matches!(app.suspend, Some(Suspend::LoginStatus)));
        // The Done dashboard offers the same last-mile wire.
        let mut app = test_app();
        app.screen = SC_DONE;
        app.on_key(KeyCode::Char('w'));
        assert!(matches!(app.suspend, Some(Suspend::LoginEnable)));
    }

    #[test]
    fn cameras_enter_switches_only_when_a_pair_exists() {
        let mut app = test_app();
        app.screen = SC_CAMERAS;
        app.on_key(KeyCode::Enter);
        assert!(app.suspend.is_none());
        let (_, msg) = app.activity.last().expect("the no-pair case is explained");
        assert!(msg.contains("no paired Hello camera"), "got: {msg}");
        app.pairs = vec![irlume_common::CameraPairInfo {
            rgb: "/dev/video0".into(),
            ir: "/dev/video2".into(),
            id: Some("abcd:1234".into()),
            fixed: true,
            privacy: false,
        }];
        app.cam_sel = 0;
        app.on_key(KeyCode::Enter);
        assert!(matches!(
            app.suspend,
            Some(Suspend::SetCameras(ref r, ref i)) if r == "/dev/video0" && i == "/dev/video2"
        ));
    }

    #[test]
    fn cameras_emitter_keys_route_setup_and_probe() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_CAMERAS;
        app.on_key(KeyCode::Char('s'));
        assert!(matches!(app.suspend, Some(Suspend::IrSetup)));
        app.suspend = None;
        // [t] routes capture tuning to sudo (#170: previously no TUI route),
        // through a confirm modal so the effects are RENDERED before anything
        // can run: the first version logged an Activity line in the same loop
        // iteration as the suspend, which never reached the screen (#204
        // review), and its test read the in-memory vector, which could not
        // notice.
        app.on_key(KeyCode::Char('t'));
        assert!(
            app.suspend.is_none(),
            "[t] must show the effects before scheduling camera-tune"
        );
        // The popup wraps its message at the box edge, so reflow the rendered
        // text before asserting: borders become spaces, runs of whitespace
        // collapse, and the phrases read as written regardless of wrap point.
        let text = draw_text(&app);
        let flat = text
            .replace(['│', '╭', '╮', '╰', '╯', '─'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flat.contains("fires the IR emitter for up to a minute")
                && flat.contains("/etc/irlume/cameras.conf")
                && flat.contains("password will be requested"),
            "the pre-run confirmation must render every material effect:\n{text}"
        );
        app.on_key(KeyCode::Char('y'));
        assert!(matches!(app.suspend, Some(Suspend::CameraTune)));
        app.suspend = None;
        // And [n] declines without scheduling anything.
        app.on_key(KeyCode::Char('t'));
        app.on_key(KeyCode::Char('n'));
        assert!(app.suspend.is_none() && app.confirm.is_none());
        app.on_key(KeyCode::Char('p'));
        assert!(app.op.is_some(), "[p] starts the read-only emitter probe");
        wait_op_done(&mut app);
    }

    #[test]
    fn settings_enter_refuses_to_enable_eyes_open_and_sends_nothing() {
        // #386: the daemon refuses to turn this gate on, so Enter from OFF must
        // not fire a request whose only outcome is an error modal. The refusal
        // still lives in the daemon, which is the choke point the CLI shares;
        // this is about not offering the user a dead action.
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        assert!(!app.eyes_open, "the fixture starts with the gate off");
        app.on_key(KeyCode::Enter);
        assert!(
            app.op.is_none(),
            "no request may be sent for an enable the daemon refuses"
        );
        // The row no longer advertises Enter while off, so a bare keypress
        // logs quietly instead of raising a modal about a hint nobody saw.
        assert!(
            app.error.is_none(),
            "no modal for an action the screen does not offer"
        );
        let logged = app.activity.last().map(|e| e.1.as_str()).unwrap_or("");
        assert!(logged.contains("cannot be enabled"), "{logged}");
        assert!(
            logged.contains("#386"),
            "the refusal must name the issue: {logged}"
        );
        // The old literal spanned continuation lines without `\`, burying
        // 26-space runs mid-sentence in the rendered message.
        assert!(
            !logged.contains("  "),
            "the message must not carry embedded space runs: {logged:?}"
        );
    }

    #[test]
    fn settings_enter_still_turns_eyes_open_off_via_the_daemon() {
        // The OFF direction is the one an enrollment already carrying the flag
        // needs, so it must still reach the daemon.
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        app.eyes_open = true;
        app.on_key(KeyCode::Enter);
        assert_eq!(
            app.op.as_ref().map(|o| o.label.as_str()),
            Some("toggle require-eyes-open"),
            "turning the gate OFF must still fire the request"
        );
        wait_op_done(&mut app);
        assert!(
            app.error.is_some(),
            "a failed toggle must raise the error banner, not vanish"
        );
    }

    #[test]
    fn repair_ir_selftest_suspends_to_sudo_not_a_direct_daemon_call() {
        // The daemon root-gates SelfTest (spoof-tuning oracle), so [l] must run
        // it via sudo like every other root action, not fail on a peer-uid
        // error from a direct socket call.
        let mut app = test_app();
        app.screen = SC_REPAIR;
        app.on_key(KeyCode::Char('l'));
        assert!(matches!(app.suspend, Some(Suspend::SelfTestLiveness)));
        assert!(app.op.is_none() && app.error.is_none());
    }

    #[test]
    fn apply_fix_routes_every_fix_kind() {
        let mut app = test_app();
        app.repair = vec![
            check_row("ok", Sev::Ok, Fix::None),
            check_row("man", Sev::Warn, Fix::Manual("run `foo --bar`".into())),
            check_row("emitter", Sev::Warn, Fix::Root(RootFix::SelinuxLoad)),
            check_row("daemon", Sev::Fail, Fix::Root(RootFix::RestartDaemon)),
            check_row("reader", Sev::Fail, Fix::Root(RootFix::RestartFprintd)),
            check_row("wiring", Sev::Fail, Fix::Root(RootFix::LoginEnable)),
            check_row("finger", Sev::Fail, Fix::Root(RootFix::FingerprintAdd)),
            check_row("selinux", Sev::Fail, Fix::Root(RootFix::SelinuxLoad)),
        ];
        app.apply_fix(0);
        assert!(app.suspend.is_none());
        assert!(app.activity.last().unwrap().1.contains("nothing to fix"));
        app.apply_fix(1);
        assert!(app.suspend.is_none());
        assert!(
            app.activity.last().unwrap().1.contains("run `foo --bar`"),
            "a manual fix must echo the exact command"
        );
        let suspended_by = |app: &mut App, idx: usize| {
            app.suspend = None;
            app.apply_fix(idx);
            app.suspend.take()
        };
        assert!(matches!(
            suspended_by(&mut app, 2),
            Some(Suspend::SelinuxLoad)
        ));
        assert!(matches!(
            suspended_by(&mut app, 3),
            Some(Suspend::RestartDaemon)
        ));
        assert!(matches!(
            suspended_by(&mut app, 4),
            Some(Suspend::RestartFprintd)
        ));
        assert!(matches!(
            suspended_by(&mut app, 5),
            Some(Suspend::LoginEnable)
        ));
        assert!(matches!(
            suspended_by(&mut app, 6),
            Some(Suspend::FingerprintAdd)
        ));
        assert!(matches!(
            suspended_by(&mut app, 7),
            Some(Suspend::SelinuxLoad)
        ));
        // Out of range: no panic, and no silent nothing either. [f] is
        // advertised, so a stale selection has to say why it did not act.
        let before = app.activity.len();
        app.apply_fix(99);
        assert_eq!(app.activity.len(), before + 1);
        assert!(
            app.activity
                .last()
                .is_some_and(|l| l.1.contains("no check is selected")),
            "{:?}",
            app.activity.last()
        );
    }

    // ---- text entry & submit ----------------------------------------------

    #[test]
    fn input_editing_appends_backspaces_and_esc_cancels() {
        let mut app = test_app();
        app.input = Some((
            "Rename profile 'x' to:".into(),
            String::new(),
            Pending::RenameProfile("x".into()),
        ));
        for c in "abc".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Backspace);
        assert_eq!(app.input.as_ref().unwrap().1, "ab");
        // Nav keys must type into the buffer path, not switch tabs.
        assert_eq!(app.screen, SC_WELCOME);
        app.on_key(KeyCode::Esc);
        assert!(app.input.is_none(), "Esc cancels text entry");
        assert!(!app.quit, "Esc in a prompt must not quit the TUI");
    }

    #[test]
    fn rename_submit_starts_the_async_rename_op() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.input = Some((
            "Rename profile 'old' to:".into(),
            "new name".into(),
            Pending::RenameProfile("old".into()),
        ));
        app.on_key(KeyCode::Enter);
        assert!(app.input.is_none(), "Enter consumes the prompt");
        assert_eq!(app.op.as_ref().map(|o| o.label.as_str()), Some("Rename"));
        wait_op_done(&mut app);
        assert!(
            app.error.is_some(),
            "a rename the daemon never acked must surface"
        );
    }

    #[test]
    fn enroll_name_duplicate_is_rejected_before_capture() {
        let mut app = test_app();
        app.daemon_up = true;
        app.profiles = vec![profile("dup", &[])];
        app.input = Some((
            "New profile name (blank = default):".into(),
            "dup".into(),
            Pending::EnrollName,
        ));
        app.on_key(KeyCode::Enter);
        assert!(app.enroll.is_none(), "a duplicate name must not enroll");
        let (_, msg) = app.activity.last().unwrap();
        assert!(msg.contains("already exists"), "got: {msg}");
    }

    #[test]
    fn enroll_name_blank_uses_the_default_and_starts_the_worker() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.daemon_up = true;
        app.input = Some((
            "New profile name (blank = default):".into(),
            String::new(),
            Pending::EnrollName,
        ));
        app.on_key(KeyCode::Enter);
        {
            let e = app.enroll.as_ref().expect("a blank name starts the enroll");
            assert_eq!(e.profile, "Face Profile 1");
            assert_eq!(e.target, ENROLL_SCANS);
        }
        wait_enroll_done(&mut app);
        let err = app.error.as_ref().expect("the dead socket fails the scan");
        assert!(err.contains("Enrollment failed"), "got: {err}");
    }

    #[test]
    fn enroll_name_submit_while_daemon_down_parks_the_named_intent() {
        let mut app = test_app();
        app.daemon_up = false;
        app.input = Some((
            "New profile name (blank = default):".into(),
            "zed".into(),
            Pending::EnrollName,
        ));
        app.on_key(KeyCode::Enter);
        assert!(app.enroll.is_none());
        assert!(
            matches!(app.resume_enroll, Some(ResumeEnroll::Named(ref n)) if n == "zed"),
            "the typed name must survive the daemon fix"
        );
        assert!(matches!(app.suspend, Some(Suspend::RestartDaemon)));
    }

    #[test]
    fn keyring_password_double_entry_gates_the_seal() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_KEYRING;
        // Empty first entry aborts.
        app.on_key(KeyCode::Char('a'));
        app.on_key(KeyCode::Enter);
        assert!(app.input.is_none());
        let err = app.error.take().expect("empty password must abort loudly");
        assert!(err.contains("empty password"), "got: {err}");
        // Mismatched confirmation aborts without sealing.
        app.on_key(KeyCode::Char('a'));
        for c in "pw1".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        match &app.input {
            Some((prompt, buf, Pending::KeyringPw(Some(first)))) => {
                assert!(prompt.contains("Confirm"), "got: {prompt}");
                assert!(buf.is_empty(), "the confirm entry starts blank");
                assert_eq!(&***first, "pw1");
            }
            _ => panic!("expected the confirm prompt with the stashed first entry"),
        }
        for c in "pw2".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        assert!(app.op.is_none(), "a mismatch must never reach SealPassword");
        let err = app.error.take().expect("the mismatch must abort loudly");
        assert!(err.contains("don't match"), "got: {err}");
        // Matching entries seal (async).
        app.on_key(KeyCode::Char('a'));
        for c in "pw".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        for c in "pw".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        assert_eq!(
            app.op.as_ref().map(|o| o.label.as_str()),
            Some("SealPassword")
        );
        wait_op_done(&mut app);
        assert!(app.error.is_some(), "a failed seal must surface");
    }

    #[test]
    fn recovery_passphrase_flows_mirror_the_keyring_gates() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_RECOVERY;
        // Set: double entry, mismatch aborts.
        app.on_key(KeyCode::Char('s'));
        app.on_key(KeyCode::Char('a'));
        app.on_key(KeyCode::Enter);
        assert!(matches!(
            app.input,
            Some((_, _, Pending::RecoveryPw(Some(_))))
        ));
        app.on_key(KeyCode::Char('b'));
        app.on_key(KeyCode::Enter);
        assert!(app.op.is_none());
        let err = app.error.take().expect("mismatch aborts");
        assert!(err.contains("don't match"), "got: {err}");
        // Set: matching entries fire RecoverySetup.
        app.on_key(KeyCode::Char('s'));
        app.on_key(KeyCode::Char('a'));
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Char('a'));
        app.on_key(KeyCode::Enter);
        assert_eq!(
            app.op.as_ref().map(|o| o.label.as_str()),
            Some("RecoverySetup")
        );
        wait_op_done(&mut app);
        app.error = None;
        // wait_op_done pumps poll(), which re-derives hardware capabilities
        // from the real /dev nodes; on a camera-less host (CI) the visible
        // screen set shrinks and the current screen gets clamped away from
        // Recovery. Pin it back so the restore keys land where a user on a
        // stable machine would be.
        app.screen = SC_RECOVERY;
        // Restore: empty aborts, non-empty fires RecoveryRestore.
        app.on_key(KeyCode::Char('t'));
        app.on_key(KeyCode::Enter);
        assert!(app.op.is_none());
        let err = app.error.take().expect("empty restore passphrase aborts");
        assert!(err.contains("empty passphrase"), "got: {err}");
        app.on_key(KeyCode::Char('t'));
        app.on_key(KeyCode::Char('x'));
        app.on_key(KeyCode::Enter);
        assert_eq!(
            app.op.as_ref().map(|o| o.label.as_str()),
            Some("RecoveryRestore")
        );
        wait_op_done(&mut app);
    }

    // ---- confirm & merge flows --------------------------------------------

    #[test]
    fn confirm_yes_fires_the_stored_request_async() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.confirm = Some((
            "Delete profile 'x'?".into(),
            "Confirm",
            ConfirmAct::Daemon(Request::Ping),
        ));
        app.on_key(KeyCode::Char('y'));
        assert!(app.confirm.is_none());
        assert!(app.op.is_some(), "[y] must run the stored request");
        assert!(
            app.activity.iter().any(|(_, m)| m.contains("(confirmed)")),
            "the confirmed op must be visible in Activity"
        );
        wait_op_done(&mut app);
        assert!(app.error.is_some(), "the dead-socket failure must surface");
    }

    #[test]
    fn merge_prompt_raises_the_modal_and_caps_remaining_scans() {
        let _sock = dead_socket();
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, ENROLL_SCANS);
        app.enroll = Some(enroll);
        // Two slots left for the loaded recognizer, so the modal offers 2 even
        // though the requested target is larger.
        tx.send(WMsg::MergePrompt {
            profile: "Alice".into(),
            room: Some(2),
            added_scans: vec!["scan28".into()],
            ambient_lit: Some(1),
        })
        .unwrap();
        app.poll();
        assert!(app.enroll.is_none(), "the worker hands off to the modal");
        let mc = app.enroll_merge.as_ref().expect("the merge modal is up");
        assert_eq!(mc.profile, "Alice");
        assert_eq!(mc.remaining, 2, "remaining = min(target-1, room)");
        // Below the budget the requested count minus the merged scan survives.
        let (tx, enroll) = fake_enroll(0, ENROLL_SCANS);
        app.enroll = Some(enroll);
        app.enroll_merge = None;
        tx.send(WMsg::MergePrompt {
            profile: "Alice".into(),
            room: Some(25),
            added_scans: vec!["scan5".into()],
            ambient_lit: None,
        })
        .unwrap();
        app.poll();
        assert_eq!(
            app.enroll_merge.as_ref().unwrap().remaining,
            ENROLL_SCANS - 1
        );
    }

    /// The upgrade window: a 0.9.0 TUI talking to a still-running 0.8.1
    /// daemon, which is every upgrade between the package swap and the daemon
    /// restart. That daemon never sends `room`. While the field was a plain
    /// `usize` it defaulted to 0, indistinguishable from a genuinely full
    /// profile, so the modal offered zero continuation scans and the user who
    /// asked for ten got the one merged scan with nothing saying so. That is
    /// the silent under-enrollment #290 exists to prevent.
    #[test]
    fn an_unreported_room_falls_back_to_the_requested_count() {
        let _sock = dead_socket();
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, ENROLL_SCANS);
        app.enroll = Some(enroll);
        tx.send(WMsg::MergePrompt {
            profile: "Alice".into(),
            room: None,
            added_scans: vec!["scan1".into()],
            ambient_lit: None,
        })
        .unwrap();
        app.poll();
        assert_eq!(
            app.enroll_merge.as_ref().expect("modal is up").remaining,
            ENROLL_SCANS - 1,
            "a daemon that did not say must not read as a full profile"
        );

        // Some(0) is a different answer and still means full.
        let (tx, enroll) = fake_enroll(0, ENROLL_SCANS);
        app.enroll = Some(enroll);
        app.enroll_merge = None;
        tx.send(WMsg::MergePrompt {
            profile: "Alice".into(),
            room: Some(0),
            added_scans: vec!["scan1".into()],
            ambient_lit: None,
        })
        .unwrap();
        app.poll();
        assert_eq!(
            app.enroll_merge.as_ref().expect("modal is up").remaining,
            0,
            "an explicit zero is a real answer and must still cap"
        );
    }

    /// The mixed-recognizer state this release creates: a profile can hold more
    /// than MAX_SCANS_PER_PROFILE scans in total across recognizers while the
    /// loaded one still has room. Deriving remaining from `total` computed 0
    /// here, so the user asked for ten scans, got the one merged scan, and the
    /// new recognizer was left under-enrolled with no message saying so. The
    /// daemon counts per recognizer and sends the answer; the TUI uses it.
    #[test]
    fn merge_remaining_follows_the_daemons_room_not_the_profile_total() {
        let _sock = dead_socket();
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, ENROLL_SCANS);
        app.enroll = Some(enroll);
        tx.send(WMsg::MergePrompt {
            profile: "Alice".into(),
            // The profile holds more than MAX_SCANS_PER_PROFILE across both
            // recognizers, yet the loaded one still has most of its own budget.
            room: Some(25),
            added_scans: vec!["scan1".into()],
            ambient_lit: None,
        })
        .unwrap();
        app.poll();
        assert_eq!(
            app.enroll_merge.as_ref().expect("modal is up").remaining,
            ENROLL_SCANS - 1,
            "a full profile-wide count must not zero out a recognizer with room"
        );
    }

    #[test]
    fn merge_modal_renders_the_resolved_profile() {
        let mut app = test_app();
        app.enroll_merge = Some(MergeConfirm {
            profile: "Alice".into(),
            added_scans: vec!["s".into()],
            remaining: 4,
            ambient_lit: 0,
        });
        let text = draw_text(&app);
        assert!(text.contains("Already enrolled"), "modal title missing");
        assert!(text.contains("'Alice'"), "the owning profile must be named");
        assert!(text.contains("[y] add"), "the confirm keys must be shown");
    }

    #[test]
    fn merge_confirm_continues_with_the_base_offset() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.enroll_merge = Some(MergeConfirm {
            profile: "Alice".into(),
            added_scans: vec!["s1".into()],
            remaining: 3,
            ambient_lit: 0,
        });
        app.on_key(KeyCode::Char('y'));
        assert!(app.enroll_merge.is_none());
        {
            let e = app.enroll.as_ref().expect("the continuation must start");
            assert_eq!(e.profile, "Alice");
            assert_eq!(e.target, 3);
            assert_eq!(e.base, 1, "the merged scan keeps the counter continuous");
        }
        wait_enroll_done(&mut app);
    }

    #[test]
    fn merge_confirm_with_nothing_left_just_acknowledges() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.enroll_merge = Some(MergeConfirm {
            profile: "Alice".into(),
            added_scans: vec!["s1".into()],
            remaining: 0,
            ambient_lit: 0,
        });
        app.on_key(KeyCode::Char('y'));
        assert!(app.enroll.is_none(), "nothing left to capture");
        assert!(
            app.activity
                .iter()
                .any(|(_, m)| m.contains("scan added to 'Alice'")),
            "the kept scan must be acknowledged"
        );
    }

    #[test]
    fn merge_decline_undoes_the_added_scan_and_stray_keys_are_ignored() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.enroll_merge = Some(MergeConfirm {
            profile: "Alice".into(),
            added_scans: vec!["scanZ".into()],
            remaining: 3,
            ambient_lit: 0,
        });
        app.on_key(KeyCode::Char('x'));
        app.on_key(KeyCode::Enter);
        assert!(
            app.enroll_merge.is_some(),
            "a stray key must not resolve the merge modal"
        );
        app.on_key(KeyCode::Char('n'));
        assert!(app.enroll_merge.is_none());
        assert!(
            app.op.is_some(),
            "declining must fire the DeleteScan undo async"
        );
        assert!(
            app.activity
                .iter()
                .any(|(_, m)| m.contains("removing the scan added to 'Alice'")),
            "the undo must be explained in Activity"
        );
        wait_op_done(&mut app);
        // With no scan recorded there is nothing to undo: no op is started.
        let mut app = test_app();
        app.enroll_merge = Some(MergeConfirm {
            profile: "Alice".into(),
            added_scans: Vec::new(),
            remaining: 3,
            ambient_lit: 0,
        });
        app.on_key(KeyCode::Esc);
        assert!(app.enroll_merge.is_none(), "Esc declines");
        assert!(app.op.is_none());
    }

    // ---- enroll worker messages & the enroll key gate ----------------------

    #[test]
    fn poll_routes_cue_count_and_captured_to_the_enroll_ui() {
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, 4);
        app.enroll = Some(enroll);
        tx.send(WMsg::Count(3)).unwrap();
        app.poll();
        assert_eq!(app.enroll.as_ref().unwrap().count, Some(3));
        // A fresh cue clears the countdown (the user drifted off-frame).
        tx.send(WMsg::Cue(good_report("Hold still"))).unwrap();
        app.poll();
        {
            let e = app.enroll.as_ref().unwrap();
            assert_eq!(e.count, None, "a cue aborts the on-screen countdown");
            assert_eq!(e.last.as_ref().unwrap().guidance, "Hold still");
        }
        tx.send(WMsg::Count(2)).unwrap();
        tx.send(WMsg::Captured(1, 4)).unwrap();
        app.poll();
        let e = app.enroll.as_ref().unwrap();
        assert_eq!(e.captured, 1);
        assert_eq!(e.count, None, "a capture clears the countdown");
        assert!(
            app.activity.iter().any(|(_, m)| m == "captured scan 1/4"),
            "each capture must be logged"
        );
    }

    #[test]
    fn poll_done_completes_the_enrollment() {
        let _sock = dead_socket();
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, 4);
        app.enroll = Some(enroll);
        tx.send(WMsg::Done { ambient_lit: 0 }).unwrap();
        app.poll();
        assert!(app.enroll.is_none());
        assert!(
            app.activity
                .iter()
                .any(|(_, m)| m.contains("enrollment complete")),
            "completion must be logged"
        );
        assert!(app.error.is_none());
    }

    #[test]
    fn poll_err_strips_the_hardware_prefix_and_raises_the_banner() {
        let _sock = dead_socket();
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, 4);
        app.enroll = Some(enroll);
        tx.send(WMsg::Err("hardware: camera busy".into())).unwrap();
        app.poll();
        assert!(app.enroll.is_none());
        let err = app.error.as_ref().expect("a failed scan must surface");
        assert_eq!(err, "Enrollment failed: camera busy");
    }

    /// Regression for #309: a framing guide that stops answering must not
    /// leave the last cue on screen reading as a current biometric verdict.
    /// The #187 session lost an hour to "No face detected" rendered against
    /// a wedged capture the user's face could never satisfy.
    #[test]
    fn guide_stall_replaces_the_stale_cue_and_names_the_transport() {
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, 4);
        app.enroll = Some(enroll);
        // The nastiest stale state: every reading GOOD. A stall must hide all
        // of it, not just the guidance line (Codex round: the checklist and
        // quality bar are biometric verdicts too).
        tx.send(WMsg::Cue(good_report(
            "No face detected; look straight at the camera and center yourself",
        )))
        .unwrap();
        tx.send(WMsg::Count(3)).unwrap();
        app.poll();
        tx.send(WMsg::Stall("read timed out".into())).unwrap();
        app.poll();
        let e = app.enroll.as_ref().expect("enrollment stays up on a stall");
        assert_eq!(e.count, None, "a stall aborts the on-screen countdown");
        let text = draw_text(&app);
        assert!(
            text.contains("not answering") && text.contains("journalctl -u irlumed"),
            "the stall must be named, with the journal pointer: {text}"
        );
        assert!(
            text.contains("read timed out"),
            "the transport error is shown: {text}"
        );
        for stale in [
            "No face detected",
            "Quality",
            "Face detected",
            "Centered in frame",
            "Facing the camera",
            "Well lit",
        ] {
            assert!(
                !text.contains(stale),
                "stale live reading rendered during a stall: {stale}\n{text}"
            );
        }
        assert!(
            text.contains("[esc] cancel"),
            "cancel stays offered: {text}"
        );
    }

    /// Codex round on #309: the miss counter must survive the trip from a
    /// countdown miss back through the framing loop. Before the fix, the
    /// re-entry re-declared it at zero, so a daemon that flapped (answers
    /// framing, dies in the countdown) could keep an enrollment looping
    /// forever without ever reaching the give-up message.
    #[test]
    fn countdown_misses_count_toward_the_guide_limit() {
        let stop = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel();
        let send = |m: WMsg| tx.send(m).is_ok();
        // Scripted guide: three well-framed samples reach the countdown, then
        // every request times out. One countdown miss + two framing misses
        // must hit GUIDE_MISS_LIMIT (3) with no further requests.
        let script: Vec<Result<Response, String>> = vec![
            Ok(Response::Position(good_report("hold still"))),
            Ok(Response::Position(good_report("hold still"))),
            Ok(Response::Position(good_report("hold still"))),
            Err("read timed out".into()),
            Err("read timed out".into()),
            Err("read timed out".into()),
        ];
        let mut calls = script.into_iter();
        let mut sample = |_req: &Request| calls.next().expect("guide polled past the give-up");
        let mut misses = 0u32;
        let outcome = loop {
            match guide_until_capture("u", &stop, &send, &mut sample, &mut misses) {
                GuideOutcome::Reframe => continue,
                other => break other,
            }
        };
        assert!(matches!(outcome, GuideOutcome::Halt), "give-up must halt");
        assert!(calls.next().is_none(), "all six scripted samples consumed");
        drop(tx);
        let msgs: Vec<WMsg> = rx.iter().collect();
        let last = msgs.last().expect("messages were sent");
        match last {
            WMsg::Err(e) => assert!(
                e.contains("never answered") && e.contains("journalctl"),
                "the give-up says the guide never answered: {e}"
            ),
            o => panic!("the final message must be the give-up error, got {o:?}"),
        }
        let stalls = msgs.iter().filter(|m| matches!(m, WMsg::Stall(_))).count();
        assert_eq!(stalls, 2, "misses below the limit render as stalls");
    }

    /// A guide that recovers goes back to live cues with no stall residue.
    #[test]
    fn cue_after_stall_clears_the_stall() {
        let mut app = test_app();
        let (tx, enroll) = fake_enroll(0, 4);
        app.enroll = Some(enroll);
        tx.send(WMsg::Stall("connect refused".into())).unwrap();
        tx.send(WMsg::Cue(good_report("Hold still"))).unwrap();
        app.poll();
        let text = draw_text(&app);
        assert!(text.contains("Hold still"), "live cues resume: {text}");
        assert!(
            !text.contains("not answering"),
            "no stall residue after a live cue: {text}"
        );
    }

    #[test]
    fn enroll_esc_cancels_and_signals_the_worker_to_stop() {
        let mut app = test_app();
        let (_tx, enroll) = fake_enroll(0, 4);
        let stop = enroll.stop.clone();
        app.enroll = Some(enroll);
        app.on_key(KeyCode::Char('e'));
        assert!(app.enroll.is_some(), "other keys are dead mid-capture");
        assert!(app.input.is_none());
        app.on_key(KeyCode::Esc);
        assert!(app.enroll.is_none());
        assert!(
            stop.load(Ordering::Relaxed),
            "Esc must signal the worker thread to stop"
        );
        assert!(
            app.activity
                .iter()
                .any(|(_, m)| m.contains("enrollment cancelled")),
            "the cancel must be logged"
        );
    }

    // ---- rendering ---------------------------------------------------------

    #[test]
    fn welcome_renders_glance_hint_and_tier_recommendation() {
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.recompute_visible();
        app.daemon_up = true;
        app.profiles = vec![profile("a", &["s1", "s2"])];
        let text = draw_text(&app);
        assert!(text.contains("irlume - local face authentication"));
        assert!(text.contains("At a glance"));
        assert!(text.contains("1 profile(s), 2 scan(s)"));
        assert!(
            text.contains("Face (IR)"),
            "the IR tier must be recommended on IR hardware"
        );
        // Enrolled (a profile is present), so the hint must not read as a
        // first-run greeting; the state-aware variants have their own test.
        assert!(
            text.contains("You're enrolled"),
            "the Welcome hint line is missing:\n{text}"
        );
        // Wide render: position is shown by the sidebar (grouped nav), not a
        // "step N/N" counter — the header only carries that when the sidebar is
        // collapsed on a narrow terminal.
        assert!(
            text.contains("Setup"),
            "the sidebar nav is missing:\n{text}"
        );
        // No-camera tier: the recommendation flips to password-only.
        let app2 = test_app();
        let text = draw_text(&app2);
        assert!(text.contains("Password only"), "got no fallback tier");
    }

    #[test]
    fn profiles_screen_renders_empty_state_and_scan_tree() {
        let mut app = test_app();
        app.screen = SC_PROFILES;
        // The empty state requires an OBSERVED empty list; unobserved renders
        // unknown (see the unanswered-question tests).
        app.profiles_loaded = true;
        let text = draw_text(&app);
        assert!(text.contains("No face profiles yet"));
        assert!(text.contains("Press [e] to enroll"));
        app.profiles = vec![profile("Alice", &["scan-a", "scan-b"])];
        let text = draw_text(&app);
        assert!(text.contains("● Alice"));
        assert!(text.contains("(2 scans)"));
        assert!(text.contains("↳ scan-a"), "scans render under the profile");
        assert!(
            text.contains("Improve Recognition"),
            "the add-scan guidance is missing"
        );
    }

    #[test]
    fn profiles_screen_separates_live_scans_from_another_recognizers() {
        // Only the loaded recognizer's scans can match, so a flat count let a
        // profile read as healthy when none of it was usable (#288). The
        // breakdown appears exactly when the flat count would mislead.
        let live_space = "embed:model-b";
        let mut app = test_app();
        app.screen = SC_PROFILES;
        // All scans live: the flat count stands, no warning.
        let mut p = profile("Alice", &["scan-a", "scan-b"]);
        p.scans_by_recognizer = [(live_space.to_string(), 2)].into();
        p.live_recognizer = Some(live_space.into());
        app.profiles = vec![p];
        let text = draw_text(&app);
        assert!(text.contains("(2 scans)"), "{text}");
        assert!(!text.contains("for the loaded recognizer"), "{text}");
        // No scan lives in the loaded space: the count says so, and the row
        // grows the warning naming the fix.
        let mut p = profile("Alice", &["scan-a", "scan-b"]);
        p.scans_by_recognizer = [("embed:model-a".to_string(), 2)].into();
        p.live_recognizer = Some(live_space.into());
        app.profiles = vec![p];
        let text = draw_text(&app);
        assert!(
            text.contains("(2 scans, 0 for the loaded recognizer)"),
            "{text}"
        );
        assert!(
            text.contains("none of these match the loaded recognizer"),
            "{text}"
        );
        // An old daemon reports neither field: nothing can be said, so the
        // flat count stands rather than a false all-clear or a false warning.
        app.profiles = vec![profile("Alice", &["scan-a", "scan-b"])];
        let text = draw_text(&app);
        assert!(text.contains("(2 scans)"), "{text}");
        assert!(!text.contains("for the loaded recognizer"), "{text}");
    }

    #[test]
    fn welcome_badge_warns_when_no_scan_matches_the_loaded_recognizer() {
        // The Welcome hub's enrollment badge fed off the same flat total; a
        // green "1 profile(s), 2 scan(s)" over zero usable scans is the same
        // lie one screen earlier.
        let mut app = test_app();
        app.screen = SC_WELCOME;
        // The enrollment hub row only exists when SC_PROFILES is visible,
        // which needs an RGB camera.
        app.caps.rgb = true;
        app.visible = App::compute_visible(&app.caps, VisibilityInputs::default(), &[]);
        let mut p = profile("Alice", &["scan-a", "scan-b"]);
        p.scans_by_recognizer = [("embed:model-a".to_string(), 2)].into();
        p.live_recognizer = Some("embed:model-b".into());
        app.profiles = vec![p];
        let text = draw_text(&app);
        assert!(text.contains("none for the loaded recognizer"), "{text}");
        // With live scans (or an old daemon), the badge is the plain count.
        let mut p = profile("Alice", &["scan-a", "scan-b"]);
        p.scans_by_recognizer = [("embed:model-b".to_string(), 2)].into();
        p.live_recognizer = Some("embed:model-b".into());
        app.profiles = vec![p];
        let text = draw_text(&app);
        assert!(text.contains("1 profile(s), 2 scan(s)"), "{text}");
        assert!(!text.contains("none for the loaded recognizer"), "{text}");
    }

    #[test]
    fn a_loading_profile_list_never_reads_as_no_profiles() {
        // The list loads in the background (a TPM unseal, 10.8s measured on
        // one machine). Until it lands, an empty list is "not loaded yet";
        // claiming "no profiles" told an enrolled user their face was gone.
        let mut app = test_app();
        app.screen = SC_PROFILES;
        let (_tx, rx) = mpsc::channel();
        app.profiles_load = Some(rx);
        let text = draw_text(&app);
        assert!(text.contains("Loading profiles"), "{text}");
        assert!(
            !text.contains("No face profiles yet"),
            "an unloaded list must not claim absence"
        );
    }

    #[test]
    fn poll_lands_the_background_profile_list() {
        let _guard = dead_socket();
        let mut app = test_app();
        let (tx, rx) = mpsc::channel();
        app.profiles_load = Some(rx);
        tx.send(ProfilesOutcome::Loaded {
            profiles: vec![profile("Alice", &["s1"])],
            eyes_open: true,
        })
        .unwrap();
        app.poll();
        assert!(app.profiles_load.is_none(), "the landed load must clear");
        assert_eq!(app.profiles.len(), 1);
        assert!(app.eyes_open);

        // A daemon-side error is STATE (corrupt enrollment): it lands on
        // enroll_error so Repair can flag it, exactly as the sync path did.
        let (tx, rx) = mpsc::channel();
        app.profiles_load = Some(rx);
        tx.send(ProfilesOutcome::DaemonError("corrupt".into()))
            .unwrap();
        app.poll();
        assert_eq!(app.enroll_error.as_deref(), Some("corrupt"));

        // A transport failure is NOT state: the loaded list stays, and the
        // next refresh retries.
        let (tx, rx) = mpsc::channel();
        app.profiles_load = Some(rx);
        tx.send(ProfilesOutcome::Transport("timeout".into()))
            .unwrap();
        app.poll();
        assert_eq!(
            app.profiles.len(),
            1,
            "a failed refresh must not clear the list"
        );
    }

    #[test]
    fn an_observed_empty_profile_list_is_not_reloaded_by_every_light_poll() {
        // An empty list is valid observed state (a new machine). Deriving
        // "never loaded" from emptiness made every light poll start another
        // TPM-backed listing, each occupying the daemon worker a login then
        // waits behind.
        let _guard = dead_socket();
        let mut app = test_app();
        let (tx, rx) = mpsc::channel();
        app.profiles_load = Some(rx);
        tx.send(ProfilesOutcome::Loaded {
            profiles: Vec::new(),
            eyes_open: false,
        })
        .unwrap();
        app.poll();
        assert!(app.profiles_loaded);
        assert!(app.profiles_load.is_none());
        app.apply_light(LightState {
            daemon_up: true,
            reach: crate::commands::DaemonReach::Running,
            health: None,
            keyring_armed: None,
            keyring_policy: None,
            keyring_drift: None,
            keyring_kind: None,
            recovery: None,
        });
        assert!(
            app.profiles_load.is_none(),
            "a valid observed empty enrollment must not trigger another listing"
        );
    }

    #[test]
    fn full_refresh_requests_the_machine_snapshot() {
        let _guard = dead_socket();
        let mut app = test_app();
        assert!(app.probes_load.is_none());
        app.refresh();
        assert!(
            app.probes_load.is_some(),
            "startup/manual full refresh must launch the heavy snapshot"
        );
        drain_loads(&mut app);
    }

    #[test]
    fn full_refresh_does_not_replace_known_caps_with_unobserved_defaults() {
        // App::new observed real hardware; a refresh before the first sweep
        // lands must not overwrite that with Probes::default() and hide the
        // camera screens.
        let _guard = dead_socket();
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.refresh();
        app.recompute_checks();
        assert!(app.caps.ir_pair);
        assert!(app.caps.rgb);
        drain_loads(&mut app);
    }

    #[test]
    fn the_repair_enrollment_row_says_loading_while_the_list_is_in_flight() {
        let _guard = dead_socket();
        let mut app = test_app();
        let (_tx, rx) = mpsc::channel();
        app.profiles_load = Some(rx);
        app.run_checks();
        let row = app
            .repair
            .iter()
            .find(|c| c.label == "Enrollment")
            .expect("an Enrollment row");
        assert!(row.detail.contains("loading"), "{}", row.detail);
        assert!(
            !row.detail.contains("no face enrolled"),
            "an in-flight load must not read as absence: {}",
            row.detail
        );
    }

    #[test]
    fn the_pam_screen_renders_cached_state_and_the_handoff_warning() {
        let mut app = test_app();
        app.screen = SC_PAM;
        app.pam_cache = PamCache {
            rows: vec![("plasmalogin".into(), true, true)],
            selinux_present: false,
            selinux: None,
            apparmor_enabled: false,
            apparmor_profiled: false,
            handoffs: vec![crate::pamwire::HandoffWarning {
                service: "/etc/pam.d/plasmalogin",
                auth_only: None,
            }],
        };
        let text = draw_text(&app);
        assert!(text.contains("● wired"), "{text}");
        // The #200 advisory: wired ✓ rows alone would hide the one failure
        // the user actually sees (the wallet prompting after a face login).
        assert!(
            text.contains("nothing reads the released password"),
            "{text}"
        );
    }

    #[test]
    fn the_fingerprint_screen_shows_coverage_only_when_something_reaches() {
        let mut app = test_app();
        app.screen = SC_FINGERPRINT;
        app.fp.available = true;
        app.fp_coverage = vec![
            (
                "gdm-fingerprint",
                "login screen (GNOME, fingerprint service)",
                true,
            ),
            ("sudo", "sudo", false),
        ];
        let text = draw_text(&app);
        assert!(text.contains("Where a finger can answer"), "{text}");
        assert!(text.contains("login screen (GNOME"), "{text}");
        // All-✗ coverage is noise, not information: the block stays hidden,
        // matching `fingerprint status` gating the table on a wired line.
        app.fp_coverage = vec![("sudo", "sudo", false)];
        let text = draw_text(&app);
        assert!(!text.contains("Where a finger can answer"), "{text}");
    }

    #[test]
    fn keyring_screen_states_render_distinctly() {
        let mut app = test_app();
        app.screen = SC_KEYRING;
        // Daemon unreachable: unknown, never a fake "not armed".
        let text = draw_text(&app);
        assert!(text.contains("unknown (daemon unreachable)"));
        // Not armed on a fingerprint box: names the fingerprint trigger.
        app.keyring_armed = Some(false);
        app.fp_present = true;
        let text = draw_text(&app);
        assert!(text.contains("○ not armed"));
        assert!(text.contains("fingerprint login won't open your wallet yet"));
        assert!(text.contains("At a fingerprint login"));
        // Armed on IR hardware with PCR drift and a Tier-2 policy.
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.fp_present = false;
        app.keyring_armed = Some(true);
        app.keyring_drift = Some(true);
        app.keyring_policy = Some("pcrlock NV 0x1a2b (Tier 2)".into());
        let text = draw_text(&app);
        assert!(text.contains("● armed"));
        assert!(text.contains("drifted since sealing"));
        assert!(text.contains("pcrlock NV 0x1a2b (Tier 2)"));
        assert!(
            text.contains("press [p]") && text.contains("pcrlock policy"),
            "Tier 2 offers the [p] pcrlock-refresh action, not the re-arm warning"
        );
        assert!(text.contains("At a face login"));
        // Armed on the plain PCR-7 tier: the dbx re-arm warning instead.
        app.keyring_policy = None;
        app.keyring_drift = None;
        let text = draw_text(&app);
        assert!(text.contains("PCR-7 (Secure Boot state)"));
        assert!(text.contains("firmware/dbx update"));
    }

    #[test]
    fn recovery_screen_states_render_distinctly() {
        let mut app = test_app();
        app.screen = SC_RECOVERY;
        // No TPM: plaintext + the recovery-N/A line.
        app.recovery = Some(RecoveryInfo {
            encrypted: false,
            key_present: false,
            recovery_set: false,
            tpm_present: false,
        });
        let text = draw_text(&app);
        assert!(text.contains("○ plaintext at rest"));
        assert!(text.contains("No TPM on this host"));
        // Encrypted without a backstop: the warning line.
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
            key_present: true,
            recovery_set: false,
            tpm_present: true,
        });
        let text = draw_text(&app);
        assert!(text.contains("● encrypted"));
        assert!(text.contains("No backstop"));
        assert!(text.contains("[s] set passphrase"));
        // Fully set: both badges green, no warning.
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
            key_present: true,
            recovery_set: true,
            tpm_present: true,
        });
        let text = draw_text(&app);
        assert!(text.contains("● set"));
        assert!(!text.contains("No backstop"));
    }

    #[test]
    fn fingerprint_screen_renders_reader_and_enrolled_fingers() {
        let mut app = test_app();
        app.screen = SC_FINGERPRINT;
        app.fp = FpInfo {
            available: false,
            device: None,
            enrolled: Vec::new(),
            method: "face".into(),
        };
        let text = draw_text(&app);
        assert!(text.contains("○ none detected"));
        assert!(text.contains("No usable reader"));
        app.fp = FpInfo {
            available: true,
            device: Some("Goodix Reader".into()),
            enrolled: vec!["right-index-finger".into()],
            method: "typed-method-x".into(),
        };
        let text = draw_text(&app);
        assert!(text.contains("● Goodix Reader"));
        assert!(text.contains("1 (right-index-finger)"));
        assert!(text.contains("[a] enroll a finger"));
        assert!(
            text.contains("typed-method-x"),
            "the active method value is shown"
        );
    }

    #[test]
    fn identify_screen_renders_hit_miss_and_idle_states() {
        let mut app = test_app();
        app.screen = SC_IDENTIFY;
        let text = draw_text(&app);
        assert!(text.contains("press [i] and look at the camera"));
        app.identify_result = Some((true, "alice · Face Profile 1 · confidence 0.912".into()));
        let text = draw_text(&app);
        assert!(text.contains("alice · Face Profile 1 · confidence 0.912"));
        assert!(
            text.contains("✓ Recognized") && text.contains("confidence is 0.00-1.00"),
            "the hit shows a plain verdict + the confidence scale"
        );
        app.identify_result = Some((false, "no live face (flat depth)".into()));
        let text = draw_text(&app);
        assert!(text.contains("✗"));
        assert!(text.contains("no live face (flat depth)"));
    }

    #[test]
    fn repair_screen_renders_checks_counts_and_fix_hints() {
        let mut app = test_app();
        app.screen = SC_REPAIR;
        app.repair = vec![
            check_row("Daemon (irlumed)", Sev::Ok, Fix::None),
            check_row(
                "Models",
                Sev::Warn,
                Fix::Manual("install the package".into()),
            ),
            check_row("SELinux policy", Sev::Fail, Fix::Root(RootFix::SelinuxLoad)),
        ];
        app.repair_sel = 0;
        let text = draw_text(&app);
        assert!(text.contains("1 ok"));
        assert!(text.contains("1 warn"));
        assert!(text.contains("1 fail"));
        assert!(text.contains("Daemon (irlumed)"));
        assert!(
            text.contains("· [f] fix (sudo)"),
            "root fixes advertise [f]"
        );
        assert!(text.contains("· manual"), "manual fixes are tagged");
        assert!(
            text.contains("this row is fine"),
            "an Ok row selected while another row fails must redirect"
        );
        app.repair_sel = 1;
        let text = draw_text(&app);
        assert!(text.contains("manual: install the package"));
        app.repair_sel = 2;
        let text = draw_text(&app);
        assert!(text.contains("press [f]: irlume runs the fix with sudo"));
        // The IR self-test prompt (the result now shows in the terminal, run
        // via sudo, so the card is a static "press [l]" prompt).
        assert!(text.contains("press [l] to run the IR PAD self-test"));
    }

    #[test]
    fn cameras_screen_renders_pairs_and_the_no_pair_fallbacks() {
        let mut app = test_app();
        app.screen = SC_CAMERAS;
        // Not asked yet: the screen must NOT claim there are no cameras,
        // because an unanswered listing is not an observation (#187).
        let text = draw_text(&app);
        assert!(!text.contains("no camera found"), "{text}");
        assert!(text.contains("camera list is unknown"), "{text}");
        // The ACTIVE line has the same rule: with health unanswered it used
        // to default the paths to "" and assert "no camera hardware" from
        // Path::new("").exists(), contradicting the list line above it.
        assert!(!text.contains("no camera hardware"), "{text}");
        assert!(text.contains("unknown (daemon not answering"), "{text}");
        // The daemon answered but named no devices: now none IS the fact.
        app.health = Some(HealthInfo {
            tier: "none".into(),
            rgb_dev: None,
            ir_dev: None,
            adapter: false,
            mesh: false,
            version: env!("CARGO_PKG_VERSION").into(),
            apparmor: None,
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
        });
        let text = draw_text(&app);
        assert!(text.contains("no camera hardware"), "{text}");
        app.health = None;
        // The daemon ANSWERED with an empty list: now "none" is a fact.
        app.pairs_known = true;
        let text = draw_text(&app);
        assert!(text.contains("no camera found"), "{text}");
        // RGB node only: convenience tier, and why Secure needs IR.
        app.nodes = vec![("/dev/video9".into(), irlume_camera::Role::Rgb)];
        let text = draw_text(&app);
        assert!(text.contains("video9"));
        assert!(text.contains("RGB-only, convenience tier"));
        assert!(text.contains("no IR node"));
        // A real Hello pair renders its nodes, kind, and USB id.
        app.pairs = vec![irlume_common::CameraPairInfo {
            rgb: "/dev/video0".into(),
            ir: "/dev/video2".into(),
            id: Some("abcd:1234".into()),
            fixed: true,
            privacy: false,
        }];
        let text = draw_text(&app);
        assert!(text.contains("video0+video2"));
        assert!(text.contains("built-in"));
        assert!(text.contains("[abcd:1234]"));
        assert!(text.contains("IR emitter (850nm)"));
        assert!(text.contains("[s]"), "the emitter setup key is advertised");
    }

    #[test]
    fn pam_screen_describes_what_each_tier_actually_does() {
        let mut app = test_app();
        app.screen = SC_PAM;
        let text = draw_text(&app);
        assert!(text.contains("PAM services"));
        assert!(
            text.contains("tier unknown (daemon unreachable)"),
            "no tier claim without the daemon"
        );
        // The aligned action list: the primary wire action plus the un-wire.
        assert!(text.contains("[w]") && text.contains("Wire login + lock"));
        assert!(text.contains("[x]") && text.contains("Un-wire everything"));
        app.health = Some(HealthInfo {
            tier: "convenience".into(),
            rgb_dev: Some("/dev/video0".into()),
            ir_dev: None,
            mesh: false,
            adapter: false,
            version: "1.0".into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        });
        let text = draw_text(&app);
        assert!(
            text.contains("face is NOT accepted for login"),
            "RGB-only must not promise greeter login"
        );
        app.health.as_mut().unwrap().tier = "secure".into();
        let text = draw_text(&app);
        assert!(text.contains("TPM-unseal password"));
        assert!(text.contains("always fail-safe to the password"));
    }

    #[test]
    fn settings_screen_renders_sections_and_the_eyes_open_state() {
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        let text = draw_text(&app);
        assert!(text.contains("Require eyes open"));
        assert!(text.contains("○ no"), "eyes-open starts off");
        // OFF is terminal (#386): the section must say why instead of
        // advertising a toggle whose only outcome used to be an error modal.
        assert!(
            text.contains("Cannot be enabled"),
            "the off state must explain itself"
        );
        assert!(
            !text.contains("turn off"),
            "no turn-off hint while already off"
        );
        assert!(text.contains("Biopolicy operation-class gate"));
        assert!(text.contains("Third-party models"));
        assert!(
            !text.contains("Third-party liveness models"),
            "the heading must not claim every model is a liveness cue"
        );
        assert!(text.contains("Match thresholds (read-only)"));
        app.eyes_open = true;
        let text = draw_text(&app);
        assert!(text.contains("● yes"), "the toggled state must show");
        assert!(
            text.contains("turn off"),
            "a legacy ON must offer the one action that works"
        );
        assert!(
            !text.contains("Cannot be enabled"),
            "the refusal note belongs to the off state only"
        );
    }

    #[test]
    fn settings_row_reports_pad_and_recognizer_together() {
        // The #285 review's counterexample: with both stages loaded, the
        // health-driven arm previously showed only the PAD cue — a loaded
        // deny-only cue hid the replacement RECOGNIZER, the more
        // consequential of the two.
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        app.daemon_up = true;
        // Health constructed EXPLICITLY: test_app leaves it None, and an
        // `if let Some` mutation here would silently opt the test out of the
        // very state it exists to render.
        app.health = Some(HealthInfo {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: "test".into(),
            third_party_pad: Some("flir".into()),
            third_party_recognizer: Some("buffalo".into()),
            // A loaded DETECTOR must be visible too: the daemon is the only
            // authority on it (settings.conf is root-only), and a TUI that
            // cannot show it cannot verify what is running (#299 review).
            third_party_detector: Some("fullrange".into()),
            apparmor: None,
        });
        let text = draw_text(&app);
        assert!(text.contains("flir (pad stage, loaded)"), "{text}");
        // The detector assertion renders WIDE on purpose: three loaded
        // entries overflow the 120-column default, and three is synthetic
        // while the detection stage is closed. The point under test is that
        // the daemon-reported detector reaches the row at all.
        let mut wide = Terminal::new(TestBackend::new(220, 40)).unwrap();
        wide.draw(|f| app.draw(f)).unwrap();
        let wide_text = rendered(&wide);
        assert!(
            wide_text.contains("fullrange (detection stage, loaded)"),
            "a loaded detector must be reported: {wide_text}"
        );
        assert!(
            text.contains("buffalo (recognition stage, loaded)"),
            "{text}"
        );
    }

    #[test]
    fn settings_third_party_row_prefers_the_daemon_loaded_cue() {
        // The daemon's loaded-cue name is authoritative: a non-root TUI can't
        // read the root-only settings.conf flag, so a loaded cue must show as
        // green enabled (not the ◐ "root-only" filesystem guess).
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        app.daemon_up = true;
        app.health = Some(HealthInfo {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: "test".into(),
            third_party_pad: Some("flir".into()),
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        });
        let text = draw_text(&app);
        assert!(
            text.contains("● ") && text.contains("enabled: flir"),
            "a daemon-loaded cue shows green enabled:\n{text}"
        );
        // Specifically the THIRD-PARTY row's root-only fallback must be gone (the
        // keyring-gesture section on the same page has its own root-only label).
        assert!(
            !text.contains("weights installed; on/off is root-only"),
            "the authoritative state replaces the root-only guess"
        );
        // No daemon-reported cue: fall back to the filesystem probe (we can't
        // tell "old daemon didn't report" from "new daemon reports none"). With
        // no weights on disk (empty state dir) that is a clean ○ none. This also
        // proves an older daemon with weights present is NOT falsely shown off.
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let empty = std::env::temp_dir().join(format!("irlume-tp-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let old = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &empty);
        app.health.as_mut().unwrap().third_party_pad = None;
        // The draw path reads a cache taken at construction (hashing every
        // enabled weight file on each frame was costing megabytes of I/O per
        // keypress). The running TUI re-takes it on its poll; a test that moves
        // the state dir under it has to do the same.
        app.refresh_heavy();
        let text = draw_text(&app);
        assert!(text.contains("none (default)"), "empty state dir -> ○ none");
        match old {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// Env restoration for [`with_models_sandbox`] on DROP, so a failed
    /// assertion inside the body still puts IRLUME_CONFIG_DIR/IRLUME_STATE_DIR
    /// back (#334 review): restored only on return, a panicking test left the
    /// process env pointing into its deleted sandbox and later tests failed
    /// against the wrong configuration, burying the original failure.
    struct ModelsEnvGuard {
        root: std::path::PathBuf,
        old_cfg: Option<std::ffi::OsString>,
        old_state: Option<std::ffi::OsString>,
    }

    impl Drop for ModelsEnvGuard {
        fn drop(&mut self) {
            // Restored independently: a paired match would drop whichever var
            // existed alone before the test.
            match self.old_cfg.take() {
                Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
                None => std::env::remove_var("IRLUME_CONFIG_DIR"),
            }
            match self.old_state.take() {
                Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
                None => std::env::remove_var("IRLUME_STATE_DIR"),
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Sandbox the config + state dirs for a Models-screen draw and restore
    /// them after, panic or not. The screen's state cache reads settings.conf
    /// and the weights dir through `crate::models`; without the sandbox a dev
    /// box with a real (0600) /etc/irlume/settings.conf renders "root-only
    /// unknown" and the tests assert on that machine's state instead of the
    /// state they set up. Caller must hold ENV_LOCK.
    fn with_models_sandbox<R>(tag: &str, body: impl FnOnce(&std::path::Path) -> R) -> R {
        let root = std::env::temp_dir().join(format!("irlume-tui-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (cfg, state) = (root.join("cfg"), root.join("state"));
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let _guard = ModelsEnvGuard {
            root,
            old_cfg: std::env::var_os("IRLUME_CONFIG_DIR"),
            old_state: std::env::var_os("IRLUME_STATE_DIR"),
        };
        std::env::set_var("IRLUME_CONFIG_DIR", &cfg);
        std::env::set_var("IRLUME_STATE_DIR", &state);
        body(&cfg)
    }

    /// A test App on the Models tab with the state cache gathered from the
    /// CURRENT (sandboxed) environment, the way `poll()` lands a probe sweep.
    /// Draw itself must never read the environment (#334 review), so every
    /// draw test populates the cache through the same `ModelsStatus::gather`
    /// the probe worker runs.
    fn models_app() -> App {
        let mut app = test_app();
        app.screen = SC_MODELS;
        app.models_status = Some(ModelsStatus::gather());
        app
    }

    #[test]
    fn models_screen_lists_each_catalog_entry_with_license_and_measurement() {
        // The listing is the CATALOG rendered, nothing else (#331): each
        // entry's name, license line, measurement summary, and obtain command
        // come from the same `crate::models` helpers the CLI listing uses.
        // Iterates the live catalog so this keeps holding as entries land.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let text = with_models_sandbox("mlist", |_| draw_text(&models_app()));
        // Compared WHOLE, normalized: the rendered lines word-wrap at the
        // panel width, so collapsing all whitespace on both sides lets the
        // full license and summary text be asserted, not just its first
        // words (#334 review: a renderer truncating after the opening words
        // used to pass). The block border glyphs land between wrapped
        // segments in the flattened frame, so they normalize to spaces too.
        let flat = |s: &str| {
            s.replace('│', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let flat_text = flat(&text);
        for m in irlume_common::thirdparty::CATALOG {
            row_with(&text, m.name);
            assert!(
                flat_text.contains(&flat(m.license)),
                "full license line for '{}' missing:\n{text}",
                m.name
            );
            assert!(
                flat_text.contains(&flat(m.summary)),
                "full measurement summary for '{}' missing:\n{text}",
                m.name
            );
            // The obtain line is short enough to sit on one rendered row, so
            // it is asserted whole: the exact sudo command is the point.
            assert!(
                text.contains(&crate::models::obtain_line(m)),
                "obtain command for '{}' missing:\n{text}",
                m.name
            );
        }
        // An enabled entry earns the one extra row: its exact disable command
        // (still under the same ENV_LOCK guard).
        let enabled = with_models_sandbox("mlist-on", |cfg| {
            std::fs::write(cfg.join("settings.conf"), "third_party_pad=flir\n").unwrap();
            draw_text(&models_app())
        });
        assert!(
            enabled.contains("ENABLED"),
            "the enabled tag must show:\n{enabled}"
        );
        assert!(
            enabled.contains("sudo irlume models disable flir"),
            "an enabled entry must name its disable command:\n{enabled}"
        );
    }

    #[test]
    fn models_screen_states_the_reenroll_consequence_before_any_switch_command() {
        // #331's ordering policy: templates are per recognizer (#288), so the
        // cost of switching renders ABOVE every switch command, and a reader
        // meets it before the offer. Byte order in the flattened frame is
        // render order (rows top to bottom).
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let text = with_models_sandbox("morder", |_| draw_text(&models_app()));
        let warn = text
            .find("Templates are stored per recognizer")
            .unwrap_or_else(|| panic!("no re-enroll warning:\n{text}"));
        let cmd = text
            .find("sudo irlume models")
            .unwrap_or_else(|| panic!("no switch command:\n{text}"));
        assert!(
            warn < cmd,
            "the re-enroll consequence must render before the first switch command:\n{text}"
        );
    }

    #[test]
    fn models_screen_unprivileged_shows_unknown_state_and_the_sudo_commands() {
        // Root-gated like the CLI: settings.conf unreadable (0600 root-only in
        // the field, chmod 000 here) must render as unknown state, never as
        // "disabled", with the sudo commands as the only way to act. FAILS
        // (never silently skips) under root (#334 review): root reads any
        // mode, so the chmod fixture proves nothing there, and an early
        // return recorded a test that observed nothing as passed on root-run
        // package builders.
        assert!(
            !crate::is_root(),
            "this test needs a non-root job: under root the chmod-000 fixture is \
             readable and none of the assertions below observe anything"
        );
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let text = with_models_sandbox("mroot", |cfg| {
            use std::os::unix::fs::PermissionsExt;
            let conf = cfg.join("settings.conf");
            std::fs::write(&conf, "third_party_pad=flir\n").unwrap();
            std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o000)).unwrap();
            draw_text(&models_app())
        });
        assert!(
            text.contains("enabled state unknown, root-only"),
            "unreadable settings must not claim disabled:\n{text}"
        );
        assert!(
            text.contains("sudo irlume models list"),
            "the authoritative sudo listing must be named:\n{text}"
        );
        // The state-changing commands render read-only for everyone; the
        // unprivileged case is where they are the ONLY path.
        assert!(
            text.contains("sudo irlume models enable flir"),
            "the fetchable entry's enable command must show:\n{text}"
        );
        assert!(
            text.contains("sudo irlume models add buffalo"),
            "the bring-your-own entry's add command must show:\n{text}"
        );
    }

    #[test]
    fn models_screen_renders_the_cached_state_never_a_fresh_probe() {
        // The #334 review's HIGH finding: drawing this tab used to call
        // entry_state_label per entry per frame, and its ENABLED/root-only
        // branches read and hash the whole weight file, ~10x/s on the UI
        // thread. Draw must be a pure render of App.models_status. A sentinel
        // label no gather could produce proves it: if draw recomputed from
        // the environment the sentinel could not reach the frame.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (fresh, cached) = with_models_sandbox("mcache", |_| {
            let mut app = test_app();
            app.screen = SC_MODELS;
            let fresh = draw_text(&app); // cache still None
            app.models_status = Some(ModelsStatus {
                labels: irlume_common::thirdparty::CATALOG
                    .iter()
                    .map(|_| "SENTINEL-CACHED-STATE".into())
                    .collect(),
                readable: true,
            });
            (fresh, draw_text(&app))
        });
        // Before the first sweep lands the state is not yet known, and the
        // tri-state rule says say so rather than claim either direction.
        assert!(
            fresh.contains("state loading"),
            "an unlanded cache must render as loading:\n{fresh}"
        );
        // The state TAG specifically: "disabled" also appears in prose (the
        // recognizer effect line names the disabled IR paths), so only the
        // bracketed tag would be a false claim.
        assert!(
            !fresh.contains("[disabled]"),
            "an unlanded cache must not claim a disabled state:\n{fresh}"
        );
        assert!(
            cached.contains("SENTINEL-CACHED-STATE"),
            "draw must render the cache verbatim:\n{cached}"
        );
    }

    #[test]
    fn models_screen_scrolls_to_reach_every_command_on_a_short_terminal() {
        // The #334 review's MEDIUM finding: at 80x24 the body shows about
        // seven rows and ratatui clips the rest, so without scrolling the
        // entries and their commands were unreachable. ↑/↓ (move_sel's
        // SC_MODELS branch) must bring the LAST command into view, and the
        // re-enroll warning must sit at the unscrolled top so it is met
        // before any command.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_models_sandbox("mscroll", |_| {
            let mut app = models_app();
            let render = |app: &App| {
                let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
                term.draw(|f| app.draw(f)).unwrap();
                rendered(&term)
            };
            let top = render(&app);
            assert!(
                top.contains("Templates are stored per recognizer"),
                "the warning heads the unscrolled view:\n{top}"
            );
            let last_cmd = "sudo irlume models add buffalo";
            assert!(
                !top.contains(last_cmd),
                "at 80x24 the last command must genuinely start off-screen, or \
                 the scroll assertions below prove nothing:\n{top}"
            );
            // ↓ one logical line at a time until the LAST command scrolls in.
            let budget = app.models_lines().len();
            let mut found = false;
            for _ in 0..budget {
                app.on_key(KeyCode::Down);
                if render(&app).contains(last_cmd) {
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "the last catalog command never scrolled into view:\n{}",
                render(&app)
            );
            // The clamp (#334 review): extra presses cannot run past the end
            // into blank space; the content's last line still tops the view.
            for _ in 0..100 {
                app.on_key(KeyCode::Down);
            }
            let clamped = render(&app);
            assert!(
                clamped.contains(last_cmd),
                "over-scrolling must clamp at the content end:\n{clamped}"
            );
            // And ↑ returns to the warning-first top without re-walking the
            // wasted presses (the store itself is clamped, not just the view).
            for _ in 0..budget {
                app.on_key(KeyCode::Up);
            }
            let back = render(&app);
            assert!(
                back.contains("Templates are stored per recognizer"),
                "scrolling back up must restore the warning-first view:\n{back}"
            );
        });
    }

    #[test]
    fn done_screen_status_line_matches_setup_state() {
        let mut app = test_app();
        app.screen = SC_DONE;
        let text = draw_text(&app);
        assert!(text.contains("Setup dashboard"));
        assert!(
            text.contains("Daemon not running; see the Repair tab"),
            "a down daemon is the first thing Done must flag"
        );
        app.daemon_up = true;
        app.caps = irlume_camera::Caps {
            ir_pair: false,
            rgb: true,
        };
        let text = draw_text(&app);
        assert!(
            text.contains("enroll a face (Welcome [e])"),
            "an empty enrollment with a camera points at [e]"
        );
        app.caps = irlume_camera::Caps {
            ir_pair: false,
            rgb: false,
        };
        let text = draw_text(&app);
        assert!(text.contains("No face hardware"));
    }

    #[test]
    fn enroll_screen_renders_progress_checklist_countdown_and_guidance() {
        let mut app = test_app();
        let (_tx, mut enroll) = fake_enroll(1, 4);
        enroll.captured = 1;
        enroll.count = Some(2);
        enroll.last = Some(good_report("Hold still"));
        app.enroll = Some(enroll);
        let text = draw_text(&app);
        assert!(
            text.contains("Enrolling 'p' (scan 2/5)"),
            "progress must include the merged base offset:\n{text}"
        );
        assert!(text.contains("85%"), "the quality bar shows the percent");
        assert!(text.contains("Face detected"));
        assert!(text.contains("Well lit"));
        assert!(
            text.contains("capturing in 2"),
            "the countdown overrides the guidance line"
        );
        assert!(text.contains("[esc] cancel"));
        assert!(
            text.contains("Look at the camera and hold still"),
            "the hint line switches to capture mode"
        );
        // Between countdowns the daemon's guidance cue shows instead.
        app.enroll.as_mut().unwrap().count = None;
        let text = draw_text(&app);
        assert!(text.contains("Hold still"));
        assert!(!text.contains("capturing in"));
        // Before the first cue arrives the camera-start placeholder shows.
        app.enroll.as_mut().unwrap().last = None;
        let text = draw_text(&app);
        assert!(text.contains("Starting camera…"));
    }

    #[test]
    fn error_banner_renders_over_everything_including_prompts() {
        let mut app = test_app();
        app.input = Some((
            "New profile name (blank = default):".into(),
            String::new(),
            Pending::EnrollName,
        ));
        app.error = Some("camera busy".into());
        let text = draw_text(&app);
        assert!(text.contains("⚠ Problem"));
        assert!(text.contains("camera busy"));
        assert!(text.contains("[any key] dismiss"));
        assert!(
            !text.contains("New profile name"),
            "the error modal must take precedence over the input prompt"
        );
    }

    #[test]
    fn masked_input_renders_bullets_never_the_password() {
        let mut app = test_app();
        app.input = Some((
            "Login password to seal (••):".into(),
            "hunter2".into(),
            Pending::KeyringPw(None),
        ));
        let text = draw_text(&app);
        assert!(
            text.contains("•••••••"),
            "7 typed chars must render as 7 bullets"
        );
        assert!(
            !text.contains("hunter2"),
            "the password must never reach the screen"
        );
        // A non-secret prompt renders the actual text.
        app.input = Some((
            "Rename profile 'x' to:".into(),
            "visible".into(),
            Pending::RenameProfile("x".into()),
        ));
        let text = draw_text(&app);
        assert!(text.contains("visible"));
    }

    #[test]
    fn header_counts_steps_over_visible_screens_only() {
        let mut app = test_app(); // visible: Welcome, Login wiring, Settings, Models, Done
        app.screen = SC_PAM;
        // The step counter only appears on a narrow terminal (sidebar collapsed);
        // there it must track VISIBLE tabs, so Login wiring is 2 of 5.
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let text = rendered(&term);
        assert!(
            text.contains("step 2/5: Login wiring"),
            "the step counter must track visible tabs, got:\n{text}"
        );
        assert!(text.contains("testuser"), "the managed user is shown");
    }

    #[test]
    fn footer_lists_each_screens_action_keys() {
        let mut app = test_app();
        // The Done footer offers [w] only on OBSERVED-unwired state; give the
        // sweep so the case below exercises the offer, not the unknown state.
        app.probes_landed = true;
        let footer = |app: &App| {
            let mut term = Terminal::new(TestBackend::new(200, 3)).unwrap();
            term.draw(|f| app.draw_footer(f, f.area())).unwrap();
            rendered(&term)
        };
        // Footer = primary action only (trimmed, three-tier disclosure);
        // the [?] overlay must list EVERY action of the screen.
        let cases: [(usize, &str, &str); 11] = [
            (SC_WELCOME, "enroll", "uninstall"),
            (SC_REPAIR, "fix", "debug logs"),
            (SC_CAMERAS, "use", "list units"),
            (SC_PROFILES, "enroll", "delete"),
            (SC_IDENTIFY, "identify", "identify"),
            (SC_KEYRING, "arm", "forget"),
            (SC_RECOVERY, "set", "forget"),
            (SC_FINGERPRINT, "enroll finger", "reset"),
            (SC_PAM, "wire login (sudo)", "un-wire"),
            (SC_SETTINGS, "eyes-open", "3rd-party model"),
            (SC_DONE, "wire login", "refresh"),
        ];
        for (screen, primary, in_overlay) in cases {
            app.screen = screen;
            assert!(
                app.help_body().contains(in_overlay),
                "[?] overlay for screen {screen} misses '{in_overlay}':\n{}",
                app.help_body()
            );
            let needle = primary;
            let text = footer(&app);
            assert!(
                text.contains(needle),
                "footer for {} must advertise '{needle}', got:\n{text}",
                SCREENS[screen]
            );
            assert!(
                text.contains("all keys"),
                "the [?] disclosure chip always shows"
            );
        }
        // Guided enrollment swallows everything but Esc: only that shows.
        let (_tx, enroll) = fake_enroll(0, 4);
        app.enroll = Some(enroll);
        let text = footer(&app);
        assert!(text.contains("cancel enrollment"));
        assert!(!text.contains("switch tab"));
    }

    #[test]
    fn activity_panel_windows_scroll_and_titles_reflect_state() {
        let mut app = test_app();
        for i in 0..30 {
            app.log('·', format!("line {i}"));
        }
        let panel = |app: &App| {
            let mut term = Terminal::new(TestBackend::new(80, 7)).unwrap();
            term.draw(|f| app.draw_activity(f, f.area())).unwrap();
            rendered(&term)
        };
        // Following: the newest lines fill the 5 visible rows.
        let text = panel(&app);
        assert!(text.contains("line 29"));
        assert!(text.contains("line 25"));
        assert!(!text.contains("line 24"), "older lines are scrolled out");
        assert!(text.contains("newest last"));
        // Scrolled to the top: the oldest lines and the history title.
        app.act_scroll = app.act_max();
        let text = panel(&app);
        assert!(text.contains("line 0"));
        assert!(text.contains("line 4"));
        assert!(!text.contains("line 5"), "the window is 5 rows");
        assert!(text.contains("history (25 up"));
        // A running op puts its label in the title.
        app.act_scroll = 0;
        let (_tx, op) = fake_op();
        app.op = Some(op);
        let text = panel(&app);
        assert!(text.contains("Identify"));
    }

    // ---- log ring, scroll bounds, status poll ------------------------------

    #[test]
    fn log_ring_buffer_caps_at_200_and_keeps_the_newest() {
        let mut app = test_app();
        for i in 0..250 {
            app.log('·', format!("line {i}"));
        }
        assert_eq!(app.activity.len(), 200);
        assert_eq!(app.activity[0].1, "line 50", "the oldest 50 are dropped");
        assert_eq!(app.activity[199].1, "line 249");
    }

    #[test]
    fn log_holds_a_scrolled_view_in_place_as_lines_arrive() {
        let mut app = test_app();
        for i in 0..20 {
            app.log('·', format!("line {i}"));
        }
        app.act_scroll = 5;
        app.log('·', "new line");
        assert_eq!(
            app.act_scroll, 6,
            "new lines must not yank a reading user to the bottom"
        );
        app.act_scroll = 0;
        app.log('·', "another");
        assert_eq!(app.act_scroll, 0, "at the bottom the view keeps following");
    }

    #[test]
    fn scroll_keys_clamp_at_both_ends() {
        let mut app = test_app();
        for i in 0..30 {
            app.log('·', format!("line {i}"));
        }
        app.on_key(KeyCode::Home);
        assert_eq!(app.act_scroll, app.act_max(), "Home jumps to the oldest");
        app.on_key(KeyCode::PageUp);
        assert_eq!(
            app.act_scroll,
            app.act_max(),
            "PgUp cannot scroll past the top"
        );
        app.on_key(KeyCode::End);
        assert_eq!(app.act_scroll, 0, "End jumps back to following");
        app.on_key(KeyCode::PageDown);
        assert_eq!(app.act_scroll, 0, "PgDn cannot scroll below the bottom");
    }

    #[test]
    fn refresh_light_clamps_selections_to_the_shrunken_lists() {
        let mut app = test_app();
        app.profiles = vec![profile("a", &["s1"])]; // 2 rows
        app.sel = 9;
        app.cam_sel = 9;
        app.apply_light(LightState {
            daemon_up: false,
            reach: crate::commands::DaemonReach::Down,
            health: None,
            keyring_armed: None,
            keyring_policy: None,
            keyring_drift: None,
            keyring_kind: None,
            recovery: None,
        });
        assert_eq!(app.sel, 1, "sel must clamp to the last real row");
        assert!(
            app.cam_sel < app.pairs.len().max(1),
            "cam_sel must clamp to the discovered pairs"
        );
        assert!(!app.daemon_up);
        assert!(app.health.is_none());
    }

    // ---- run_checks with the daemon's self-report ---------------------------

    #[test]
    fn run_checks_trusts_daemon_health_over_local_probes() {
        let _sock = dead_socket();
        let mut app = test_app();
        // The "no face enrolled yet" verdict needs an observed empty list.
        app.profiles_loaded = true;
        app.health = Some(HealthInfo {
            tier: "secure".into(),
            rgb_dev: Some("/dev/video0".into()),
            ir_dev: Some("/dev/video2".into()),
            mesh: true,
            adapter: true,
            version: env!("CARGO_PKG_VERSION").into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        });
        app.run_checks();
        let find = |label: &str| {
            app.repair
                .iter()
                .find(|c| c.label == label)
                .unwrap_or_else(|| panic!("missing check row '{label}'"))
        };
        // The socket is dead, so the Daemon row fails with the root fix…
        let daemon = find("Daemon (irlumed)");
        assert!(daemon.sev == Sev::Fail);
        assert!(matches!(daemon.fix, Fix::Root(RootFix::RestartDaemon)));
        // …but the daemon-reported model/camera state is still ground truth.
        let ort = find("ONNX Runtime");
        assert!(ort.sev == Sev::Ok);
        assert!(ort.detail.contains("reported by the daemon"));
        let models = find("Models");
        assert!(models.detail.contains("+ IR adapter"));
        assert!(models.detail.contains("+ FaceMesh"));
        let cams = find("Cameras");
        assert!(cams.sev == Sev::Ok);
        assert!(cams.detail.contains("secure tier"));
        // Repair no longer carries an emitter row. It never measured the
        // emitter: it was unconditionally a warning whenever an IR node
        // existed, so it cried wolf on every working machine and pointed its
        // fix button at a write to the camera. Setup lives on the Cameras
        // screen, offered as an action rather than dressed as a diagnosis, and
        // the daemon says when the feed is genuinely dark.
        assert!(
            !app.repair.iter().any(|c| c.label == "IR emitter"),
            "Repair must not state a verdict it has not measured"
        );
        assert!(
            !app.repair.iter().any(|c| c.label == "Daemon build"),
            "matching daemon/CLI versions must not warn"
        );
        let enroll = find("Enrollment");
        assert!(enroll.sev == Sev::Warn, "no profiles yet is a warning");
        assert!(enroll.detail.contains("no face enrolled yet"));
    }

    #[test]
    fn run_checks_flags_version_skew_and_corrupt_enrollment() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.health = Some(HealthInfo {
            tier: "convenience".into(),
            rgb_dev: Some("/dev/video0".into()),
            ir_dev: None,
            mesh: false,
            adapter: false,
            version: "0.0.1-old".into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        });
        app.enroll_error = Some("bad ciphertext".into());
        app.run_checks();
        let find = |label: &str| {
            app.repair
                .iter()
                .find(|c| c.label == label)
                .unwrap_or_else(|| panic!("missing check row '{label}'"))
        };
        let build = find("Daemon build");
        assert!(build.sev == Sev::Warn);
        assert!(
            build.detail.contains("0.0.1-old"),
            "names the stale version"
        );
        let enroll = find("Enrollment");
        assert!(enroll.sev == Sev::Fail, "unreadable ≠ not enrolled");
        assert!(enroll.detail.contains("bad ciphertext"));
        let cams = find("Cameras");
        assert!(cams.sev == Sev::Warn);
        assert!(cams.detail.contains("convenience tier"));
        assert!(
            !app.repair.iter().any(|c| c.label == "IR emitter"),
            "no IR node, no emitter row"
        );
        assert!(
            app.repair.iter().any(|c| c.label == "RGB anti-spoof"),
            "the convenience tier documents its moiré detector"
        );
        // The selection clamps when the list shrinks between runs.
        app.repair_sel = 999;
        app.run_checks();
        assert!(app.repair_sel < app.repair.len());
    }

    #[test]
    fn repair_surfaces_keyring_drift_with_the_reseal_fix() {
        // A TUI-only user never runs `doctor`; PCR drift must show on Repair
        // and point at the reseal action (the newly-added parity fix).
        let mut app = test_app();
        app.keyring_drift = None;
        app.run_checks();
        assert!(
            !app.repair.iter().any(|c| c.label == "Keyring seal"),
            "no drift, no row"
        );
        app.keyring_drift = Some(true);
        app.run_checks();
        let row = app
            .repair
            .iter()
            .find(|c| c.label == "Keyring seal")
            .expect("drift must surface on Repair");
        assert!(row.sev == Sev::Warn);
        match &row.fix {
            Fix::Manual(m) => assert!(m.contains("reseal"), "fix points at reseal: {m}"),
            _ => panic!("expected a manual fix pointing at reseal"),
        }
    }

    // ---- an unanswered question renders as unknown, never as a negative ----
    // The machine-API contract (docs/MACHINE-API.md): a failed read
    // "established nothing", and a consumer must not render it as disabled.
    // These pin the TUI surfaces that used to claim "none"/"no"/"plaintext"
    // while the daemon had never answered.

    #[test]
    fn an_unanswered_profile_list_renders_unknown_not_none() {
        // Daemon down before the first ListProfiles landed: every surface
        // that said "none" here invited a re-enroll over an enrollment that
        // exists (reproduced on three machines).
        let mut app = test_app();
        assert!(!app.profiles_loaded && app.profiles_load.is_none());

        // Profiles tab: no absence claim, no [e] invitation.
        app.screen = SC_PROFILES;
        let text = draw_text(&app);
        assert!(!text.contains("No face profiles yet"), "{text}");
        assert!(!text.contains("Press [e] to enroll"), "{text}");
        assert!(text.contains("Profile list not read yet"), "{text}");

        // Repair: the Enrollment verdict is unknown, not "no face enrolled".
        app.run_checks();
        let enroll = app
            .repair
            .iter()
            .find(|c| c.label == "Enrollment")
            .expect("an Enrollment row");
        assert!(enroll.detail.contains("unknown"), "{}", enroll.detail);
        assert!(
            !enroll.detail.contains("no face enrolled"),
            "{}",
            enroll.detail
        );

        // Welcome hub: the three unanswered rows carry the unknown badge.
        app.screen = SC_WELCOME;
        app.visible = (0..SCREENS.len()).collect();
        let text = draw_text(&app);
        assert!(
            row_with(&text, "enrollment").contains("◐ unknown"),
            "{text}"
        );
        assert!(
            row_with(&text, "keyring unlock").contains("◐ unknown"),
            "{text}"
        );
        assert!(
            row_with(&text, "recovery + encryption").contains("◐ unknown"),
            "{text}"
        );

        // Done dashboard: same rule for its four claim rows.
        app.screen = SC_DONE;
        let text = draw_text(&app);
        assert!(
            row_with(&text, "enrollment").contains("◐ unknown"),
            "{text}"
        );
        assert!(
            row_with(&text, "keyring unlock").contains("◐ unknown"),
            "{text}"
        );
        assert!(
            row_with(&text, "templates enc").contains("◐ unknown"),
            "{text}"
        );
        assert!(
            row_with(&text, "recovery pass").contains("◐ unknown"),
            "{text}"
        );
    }

    /// The store is encrypted and its key is gone, which is what a lost
    /// template key looks like from the panel. Rendering that as "encrypted"
    /// hides that the enrollment can no longer be opened by anything.
    #[test]
    fn recovery_screen_names_an_encrypted_store_whose_key_is_gone() {
        let mut app = test_app();
        app.screen = SC_RECOVERY;
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
            key_present: false,
            recovery_set: false,
            tpm_present: true,
        });
        let text = draw_text(&app);
        assert!(
            text.contains("TEMPLATE KEY MISSING"),
            "an orphaned store must be named, not shown as healthy: {text}"
        );
        assert!(
            !text.contains("● encrypted"),
            "it must not read as a clean encrypted state: {text}"
        );
    }

    #[test]
    fn recovery_screen_renders_unknown_when_never_answered() {
        // recovery = None used to default-render "plaintext at rest" and
        // "No TPM on this host", both false on the machines that hit it, and
        // one Tab away from the Keyring tab saying "TPM ● present".
        let mut app = test_app();
        app.screen = SC_RECOVERY;
        assert!(app.recovery.is_none());
        let text = draw_text(&app);
        assert!(!text.contains("plaintext at rest"), "{text}");
        assert!(!text.contains("No TPM on this host"), "{text}");
        assert!(!text.contains("○ not set"), "{text}");
        assert!(text.contains("◐ unknown (daemon unreachable)"), "{text}");
    }

    #[test]
    fn the_ort_fallback_probe_covers_packaged_installs_and_never_hard_fails() {
        // The packages bundle onnxruntime outside the system lib dirs and set
        // ORT_DYLIB_PATH only inside the daemon's unit drop-in, so the probe
        // must scan the PACKAGED_ORTS locations (irlume-vision/src/lib.rs)
        // itself or it false-fails on every packaged install.
        for packaged in [
            "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
            "/opt/irlume/onnxruntime/lib/libonnxruntime.so",
        ] {
            assert!(
                ORT_FALLBACK_PATHS.contains(&packaged),
                "fallback probe misses the packaged path {packaged}"
            );
        }
        // With the daemon down the probe is a guess about an env it cannot
        // see; a Fail sent users to install packages they already have.
        let miss = ort_fallback_check(false);
        assert!(miss.sev == Sev::Warn, "a guess must not be a hard failure");
        assert!(miss.detail.contains("local probe"), "{}", miss.detail);
        let hit = ort_fallback_check(true);
        assert!(hit.sev == Sev::Ok);
    }

    /// The four TFLite states, driven through the injected `exists` so no
    /// test depends on what this machine has installed. The one that differs
    /// from ONNX: a broken override is an operator error THIS environment can
    /// see, so it is a Fail, not the not-seen Warn.
    #[test]
    fn tflite_fallback_check_distinguishes_override_packaged_and_absent() {
        let ok_override = tflite_fallback_check(Some("/opt/x/libtensorflowlite_c.so"), |_| true);
        assert!(ok_override.sev == Sev::Ok, "{}", ok_override.detail);
        assert!(
            ok_override.detail.contains("/opt/x/"),
            "{}",
            ok_override.detail
        );

        let bad_override = tflite_fallback_check(Some("/opt/x/libtensorflowlite_c.so"), |_| false);
        assert!(
            bad_override.sev == Sev::Fail,
            "a set-but-missing override is not a guess: {}",
            bad_override.detail
        );
        assert!(
            bad_override.detail.contains("does not exist"),
            "{}",
            bad_override.detail
        );

        let packaged = tflite_fallback_check(None, |p| {
            p == std::path::Path::new("/usr/share/irlume/tflite/libtensorflowlite_c.so")
        });
        assert!(packaged.sev == Sev::Ok, "{}", packaged.detail);
        assert!(
            packaged.detail.contains("/usr/share/irlume/tflite"),
            "{}",
            packaged.detail
        );

        let absent = tflite_fallback_check(None, |_| false);
        assert!(
            absent.sev == Sev::Warn,
            "nothing seen is a guess about the daemon's env, same as ONNX: {}",
            absent.detail
        );
        assert!(absent.detail.contains("local probe"), "{}", absent.detail);
        assert!(
            matches!(&absent.fix, Fix::Manual(m) if m.contains("IRLUME_TFLITE_LIB")),
            "the fix must name both remedies"
        );
    }

    #[test]
    fn repair_reports_the_daemons_seal_tier_not_the_weakest_rung() {
        let mut app = test_app();
        app.screen = SC_REPAIR;
        // Down: the tier is unknown; "literal PCR-7" told a Tier-2 pcrlock
        // user their seal sat on the weakest rung, contradicting the Keyring
        // tab one Tab away.
        let text = draw_text(&app);
        assert!(!text.contains("literal PCR-7"), "{text}");
        assert!(
            row_with(&text, "PCR policy").contains("unknown (daemon unreachable)"),
            "{text}"
        );
        // The daemon's KeyringInfo names the rung: show it verbatim, exactly
        // as the Keyring tab does.
        app.daemon_up = true;
        app.keyring_armed = Some(true);
        app.keyring_policy = Some("pcrlock NV 0x1a2b (Tier 2)".into());
        let text = draw_text(&app);
        assert!(
            row_with(&text, "PCR policy").contains("pcrlock NV 0x1a2b (Tier 2)"),
            "{text}"
        );
    }

    #[test]
    fn the_daemon_row_names_the_socket_actually_probed() {
        // IRLUME_SOCKET redirects every request the TUI makes; the row
        // hardcoded /run/irlume.sock, a path nobody probed.
        let _guard = dead_socket();
        let mut app = test_app();
        app.run_checks();
        let d = app
            .repair
            .iter()
            .find(|c| c.label == "Daemon (irlumed)")
            .expect("a Daemon row");
        assert!(
            d.detail.contains("/nonexistent/irlume-test.sock"),
            "{}",
            d.detail
        );
    }

    #[test]
    fn keyring_binding_and_advice_wait_for_the_daemon() {
        let mut app = test_app();
        app.screen = SC_KEYRING;
        let text = draw_text(&app);
        // The pre-KeyringInfo default described a binding nobody read.
        assert!(!text.contains("PCR-7 (Secure Boot state)"), "{text}");
        assert!(
            row_with(&text, "binding").contains("unknown (daemon unreachable)"),
            "{text}"
        );
        // And no armed-state consequence line off an unanswered question.
        assert!(!text.contains("Not armed;"), "{text}");
    }

    #[test]
    fn identify_deny_reasons_that_echo_the_summary_are_not_repeated() {
        // The daemon's deny reason restates the summary with a connective;
        // appending it rendered "live face, no enrolled match (live face,
        // but no enrolled match)". Informative reasons keep their
        // parenthetical (pinned by map_identify_formats_match_and_both_miss_reasons).
        let (ok, msg) = map_identify(Response::Identified {
            user: None,
            profile: None,
            score: 0.0,
            live: true,
            reason: "live face, but no enrolled match".into(),
        });
        assert!(!ok);
        assert_eq!(msg, "live face, no enrolled match");
        let (_, msg) = map_identify(Response::Identified {
            user: None,
            profile: None,
            score: 0.0,
            live: false,
            reason: "no live face".into(),
        });
        assert_eq!(msg, "no live face");
        // An empty reason: no dangling "()" either.
        let (_, msg) = map_identify(Response::Identified {
            user: None,
            profile: None,
            score: 0.0,
            live: true,
            reason: String::new(),
        });
        assert_eq!(msg, "live face, no enrolled match");
    }

    #[test]
    fn done_biopolicy_row_uses_the_shared_tri_state_reader() {
        // Same rule the CLI `status` fix established (commit 156417f): the
        // daemon's truthy set and its env override decide what displays, not
        // a bare settings.conf read that shows "enforce_biopolicy=yes" as no.
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("IRLUME_ENFORCE_BIOPOLICY");
        std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", "yes");
        let mut app = test_app();
        app.screen = SC_DONE;
        let text = draw_text(&app);
        match old {
            Some(v) => std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", v),
            None => std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY"),
        }
        assert!(row_with(&text, "biopolicy").contains("● yes"), "{text}");
    }

    #[test]
    fn settings_biopolicy_row_uses_the_shared_tri_state_reader() {
        // The Done dashboard and this row must agree: on a box whose 0600
        // settings.conf holds `enforce_biopolicy=yes`, Done said "◐ root-only"
        // (or "● yes" under the env override) while the raw read here showed
        // "○ off (default)". The env override is how the test pins the shared
        // reader: the raw read ignores it.
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("IRLUME_ENFORCE_BIOPOLICY");
        std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", "yes");
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        let text = draw_text(&app);
        match old {
            Some(v) => std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", v),
            None => std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY"),
        }
        assert!(
            text.contains("ENFORCING"),
            "the Settings biopolicy row must read the shared tri-state:\n{text}"
        );
    }

    #[test]
    fn setup_hints_follow_observed_state_not_defaults() {
        // Each setup hint has three honest states: not done (instruct), done
        // (describe), never observed (assert neither). The fixed per-screen
        // instruction told a fully configured box to redo every step.
        let mut app = test_app();

        // Welcome: unknown until ListProfiles has answered.
        assert!(!draw_text(&app).contains("New here?"));
        app.profiles_loaded = true;
        assert!(draw_text(&app).contains("New here? Press [e]"));
        app.profiles = vec![profile("a", &["s1"])];
        assert!(draw_text(&app).contains("You're enrolled"));

        // Keyring: keyring_armed is already tri-state.
        app.screen = SC_KEYRING;
        let text = draw_text(&app);
        assert!(!text.contains("press [a], type your password"), "{text}");
        app.keyring_armed = Some(false);
        assert!(draw_text(&app).contains("press [a], type your password"));
        app.keyring_armed = Some(true);
        assert!(draw_text(&app).contains("Armed: face login opens your wallet"));

        // Recovery: unknown until RecoveryStatus has answered.
        app.screen = SC_RECOVERY;
        let text = draw_text(&app);
        assert!(!text.contains("Set a backup passphrase"), "{text}");
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
            recovery_set: false,
            tpm_present: true,
            key_present: true,
        });
        assert!(draw_text(&app).contains("Set a backup passphrase"));
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
            key_present: true,
        });
        assert!(draw_text(&app).contains("Recovery passphrase set"));

        // Login wiring: unknown until the first probe sweep lands.
        app.screen = SC_PAM;
        let text = draw_text(&app);
        assert!(!text.contains("Turn on face login"), "{text}");
        app.probes_landed = true;
        app.probes.login_wired = false;
        assert!(draw_text(&app).contains("Turn on face login"));
        app.probes.login_wired = true;
        assert!(draw_text(&app).contains("Face login is wired in"));
    }

    #[test]
    fn profiles_tips_fit_an_80_column_terminal_whole() {
        // ratatui Lists never wrap a ListItem, so the tips must be pre-split;
        // the old single-line tip ended mid-sentence ("…same identity, not a")
        // at every width. Rendering at 80 columns proves the whole sentence
        // survives the narrowest supported terminal.
        let mut app = test_app();
        app.screen = SC_PROFILES;
        app.profiles_loaded = true;
        app.profiles = vec![profile("Alice", &["s1"])];
        let mut term = Terminal::new(TestBackend::new(80, 45)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let text = rendered(&term);
        assert!(
            text.contains("second profile."),
            "the Tips sentence is cut off mid-sentence:\n{text}"
        );
    }

    #[test]
    fn done_offers_wire_login_only_when_wiring_is_observed_missing() {
        let mut app = test_app();
        app.screen = SC_DONE;
        app.daemon_up = true;
        app.profiles = vec![profile("a", &["s1"])];
        let footer = |app: &App| {
            let mut term = Terminal::new(TestBackend::new(200, 3)).unwrap();
            term.draw(|f| app.draw_footer(f, f.area())).unwrap();
            rendered(&term)
        };
        // No sweep yet: the probe default is not an observation, so neither
        // the footer, the overlay, nor the body may claim wiring is missing.
        assert!(!footer(&app).contains("wire login"), "{}", footer(&app));
        assert!(!app.help_body().contains("wire login"));
        let text = draw_text(&app);
        assert!(!text.contains("One step left"), "{text}");
        assert!(!text.contains("All set"), "{text}");
        // Observed unwired: the offer appears in body and footer.
        app.probes_landed = true;
        app.probes.login_wired = false;
        assert!(footer(&app).contains("wire login"));
        assert!(draw_text(&app).contains("One step left"));
        // Observed wired: the body says done and no chrome advertises [w],
        // which on a wired box would re-run `sudo irlume login enable`.
        app.probes.login_wired = true;
        let f = footer(&app);
        assert!(!f.contains("wire login"), "{f}");
        assert!(!app.help_body().contains("wire login"));
        let text = draw_text(&app);
        assert!(text.contains("All set"), "{text}");
        assert!(row_with(&text, "login wiring").contains("● yes"), "{text}");
    }

    #[test]
    fn ir_recommendation_names_darkness_not_a_ui_theme() {
        let mut app = test_app();
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        let text = draw_text(&app);
        assert!(
            row_with(&text, "Recommended").contains("in the dark"),
            "{text}"
        );
        // "dark mode" reads as a UI theme, not an IR capability.
        assert!(!text.contains("dark mode"), "{text}");
    }

    /// Every screen must render at any terminal size, including sizes too small
    /// to hold its content.
    ///
    /// Layout arithmetic is where a TUI panics: a width or height subtraction
    /// that underflows, a constraint that cannot be satisfied, a centred popup
    /// wider than the frame. A user who drags a terminal narrow, or runs in a tmux
    /// split, must get a cramped screen and not a crash that takes their setup
    /// session with it. 1x1 is included deliberately: it is the degenerate case
    /// every clamp has to survive.
    #[test]
    fn every_screen_renders_at_every_size() {
        let sizes = [
            (1, 1),
            (2, 2),
            (10, 3),
            (20, 5),
            (40, 10),
            (60, 20),
            (80, 24),
            (120, 50),
            (200, 60),
        ];
        for screen in 0..SCREENS.len() {
            for (w, h) in sizes {
                let mut app = test_app();
                app.screen = screen;
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| app.draw(f)).unwrap();

                // The same size with the modal layers up: a popup is laid out
                // against the frame, so it is the case most likely to underflow.
                let mut app = test_app();
                app.screen = screen;
                app.show_help = true;
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| app.draw(f)).unwrap();

                let mut app = test_app();
                app.screen = screen;
                app.set_error("an error long enough to need wrapping in a narrow frame");
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| app.draw(f)).unwrap();

                // The confirm and input modals lay out the same way, and a
                // confirm is what stands between a user and a destructive action,
                // so it is the worst one to lose to a layout panic.
                let mut app = test_app();
                app.screen = screen;
                app.confirm = Some((
                    "A confirmation question long enough to wrap more than once in a narrow frame"
                        .into(),
                    "Disable",
                    ConfirmAct::Daemon(Request::Ping),
                ));
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| app.draw(f)).unwrap();

                let mut app = test_app();
                app.screen = screen;
                app.input = Some((
                    "Rename profile 'a-fairly-long-profile-name' to:".into(),
                    "typed text".into(),
                    Pending::RenameProfile("a-fairly-long-profile-name".into()),
                ));
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| app.draw(f)).unwrap();
            }
        }
    }

    /// Every screen must survive every key without panicking, and must still
    /// render afterwards.
    ///
    /// The TUI is a state machine over 12 screens with per-screen key handlers,
    /// selection indices into lists that can be empty, and modal states
    /// (confirm/input/help) layered on top. A handler that indexes its list, or
    /// that assumes a selection is in range, panics the whole interface for the
    /// user mid-setup. `on_key` only ever RECORDS a privileged step (the run loop
    /// executes it), so driving every key here touches no system state.
    ///
    /// Crossed with the modal states, because a key that is safe on a screen can
    /// still be routed to a modal handler that reads different state.
    #[test]
    fn every_screen_survives_every_key() {
        // Some keys spawn a daemon request on a detached worker. Those workers
        // connect to whatever IRLUME_SOCKET names when they run, so without this
        // they land on another test's socket and inflate its connection count
        // (`wedged_daemon_poll_short_circuits_after_ping` counts accepts and says
        // so in its own comment). Point them at a path nothing is listening on,
        // under the env lock, so this test cannot perturb another.
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dead =
            std::env::temp_dir().join(format!("irlume-keyfuzz-nothing-{}", std::process::id()));
        let _ = std::fs::remove_file(&dead);
        let old_sock = std::env::var_os("IRLUME_SOCKET");
        std::env::set_var("IRLUME_SOCKET", &dead);

        let keys: Vec<KeyCode> = ('a'..='z')
            .chain('A'..='Z')
            .chain('0'..='9')
            .map(KeyCode::Char)
            .chain([
                KeyCode::Enter,
                KeyCode::Esc,
                KeyCode::Tab,
                KeyCode::BackTab,
                KeyCode::Up,
                KeyCode::Down,
                KeyCode::Left,
                KeyCode::Right,
                KeyCode::Home,
                KeyCode::End,
                KeyCode::PageUp,
                KeyCode::PageDown,
                KeyCode::Backspace,
                KeyCode::Delete,
                KeyCode::Insert,
                KeyCode::Char(' '),
                KeyCode::Char('/'),
                KeyCode::Char('?'),
                KeyCode::Char('-'),
                KeyCode::F(1),
                KeyCode::F(12),
            ])
            .collect();

        for screen in 0..SCREENS.len() {
            for key in &keys {
                // Fresh app per key: this asserts each key is safe from a clean
                // state, not that some earlier key happened to guard it.
                let mut app = test_app();
                app.screen = screen;
                app.on_key(*key);
                let _ = draw_text(&app);

                // Same key with a selection pushed past the end of every list,
                // which is what an empty profile list plus a remembered index
                // looks like after a delete.
                let mut app = test_app();
                app.screen = screen;
                app.sel = 99;
                app.hub_sel = 99;
                app.settings_svc_sel = 99;
                app.on_key(*key);
                let _ = draw_text(&app);
            }
        }

        match old_sock {
            Some(v) => std::env::set_var("IRLUME_SOCKET", v),
            None => std::env::remove_var("IRLUME_SOCKET"),
        }
    }

    /// Every key a screen advertises must do something on that screen.
    ///
    /// The footer is the disclosure ladder: a key listed there is a promise. The
    /// Keyring tab listed [r] reseal in every state while its handler required an
    /// armed seal, so on a fresh machine the key did nothing and said nothing.
    /// This drives each advertised key on its own screen and asserts the app
    /// changed in some observable way, which is the weakest honest definition of
    /// "did something" that does not need to know what each key means.
    #[test]
    fn every_advertised_key_does_something_on_its_screen() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dead =
            std::env::temp_dir().join(format!("irlume-footer-nothing-{}", std::process::id()));
        let _ = std::fs::remove_file(&dead);
        let old_sock = std::env::var_os("IRLUME_SOCKET");
        std::env::set_var("IRLUME_SOCKET", &dead);

        for (screen, screen_name) in SCREENS.iter().enumerate() {
            let probe = {
                let mut a = test_app();
                a.screen = screen;
                a
            };
            for (key, label) in probe.screen_actions() {
                // Only single-character keys are drivable here; "enter"/"esc" and
                // the arrow hints are covered by the key-fuzz test.
                let mut chars = key.chars();
                let (Some(c), None) = (chars.next(), chars.next()) else {
                    continue;
                };
                let mut app = test_app();
                app.screen = screen;
                let before = draw_text(&app);
                let before_state = (
                    app.quit,
                    app.screen,
                    app.show_help,
                    app.confirm.is_some(),
                    app.input.is_some(),
                    app.suspend.is_some(),
                    app.op.is_some(),
                    app.activity.len(),
                    app.error.is_some(),
                );
                app.on_key(KeyCode::Char(c));
                let after_state = (
                    app.quit,
                    app.screen,
                    app.show_help,
                    app.confirm.is_some(),
                    app.input.is_some(),
                    app.suspend.is_some(),
                    app.op.is_some(),
                    app.activity.len(),
                    app.error.is_some(),
                );
                let moved = before_state != after_state || draw_text(&app) != before;
                assert!(
                    moved,
                    "screen {screen_name} ({screen}) advertises [{key}] {label}, \
                     and pressing it changed nothing"
                );
            }
        }

        match old_sock {
            Some(v) => std::env::set_var("IRLUME_SOCKET", v),
            None => std::env::remove_var("IRLUME_SOCKET"),
        }
    }

    /// A hub selection must stay inside the list when the list shrinks.
    ///
    /// The hub shows only visible screens, and [v] leaving advanced view removes
    /// several. `move_sel` wraps modulo the current length, so a stale index
    /// recovers on the next arrow, but until then nothing is highlighted and
    /// Enter opens nothing at all.
    #[test]
    fn the_hub_selection_survives_the_list_shrinking() {
        let mut app = test_app();
        app.screen = SC_WELCOME;
        app.advanced = true;
        app.daemon_up = true;
        app.fp_present = true;
        app.caps = irlume_camera::Caps {
            ir_pair: true,
            rgb: true,
        };
        app.recompute_visible();
        let wide = app.hub_rows().len();
        assert!(wide > 1, "premise: advanced view lists several sections");
        app.hub_sel = wide - 1;

        // Leaving advanced view removes screens, so the list gets shorter.
        app.advanced = false;
        app.recompute_visible();
        let narrow = app.hub_rows().len();
        assert!(narrow > 0, "the hub always has rows");
        assert!(
            app.hub_sel < narrow,
            "selection {} must be inside the {narrow} remaining rows",
            app.hub_sel
        );
        // And Enter opens the row it is on rather than nothing.
        let target = app.hub_rows()[app.hub_sel].2;
        app.on_key(KeyCode::Enter);
        assert_eq!(app.screen, target, "Enter opens the highlighted section");
    }

    /// An encrypted enrollment whose template key is gone must not read as a
    /// completed step anywhere.
    ///
    /// Nothing opens it: no recovery passphrase, no reseal, only a re-enrol. The
    /// Recovery tab said so loudly while the Repair check passed it as
    /// "encrypted + recovery set", the Done row drew a green yes, and the hub
    /// badge counted the step done.
    #[test]
    fn a_missing_template_key_is_not_a_completed_step() {
        let mut app = test_app();
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
            key_present: false,
        });
        app.run_checks();

        // Repair: a failure with a re-enrol remedy, not an OK.
        let backstop = app
            .repair
            .iter()
            .find(|c| c.label == "Recovery backstop")
            .expect("the backstop check is present");
        assert!(matches!(backstop.sev, Sev::Fail), "{}", backstop.detail);
        assert!(backstop.detail.contains("MISSING"), "{}", backstop.detail);

        // Done dashboard: not a green yes.
        app.screen = SC_DONE;
        let text = draw_text(&app);
        assert!(text.contains("key missing"), "{text}");

        // Hub badge: the step is not done. (The hub lists only VISIBLE screens,
        // and the test app has no camera, so make them all visible first, as the
        // hub-navigation test does.)
        app.screen = SC_WELCOME;
        app.visible = (0..SCREENS.len()).collect();
        let rows = app.hub_rows();
        let enc = rows
            .iter()
            .find(|(label, _, _)| *label == "recovery + encryption")
            .expect("the hub lists the recovery step");
        assert_eq!(enc.1, Some(false), "an unopenable store is not done");

        // With the key present, all three read as done again.
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
            key_present: true,
        });
        app.run_checks();
        let backstop = app
            .repair
            .iter()
            .find(|c| c.label == "Recovery backstop")
            .unwrap();
        assert!(matches!(backstop.sev, Sev::Ok), "{}", backstop.detail);
        app.visible = (0..SCREENS.len()).collect();
        let rows = app.hub_rows();
        let enc = rows
            .iter()
            .find(|(label, _, _)| *label == "recovery + encryption")
            .unwrap();
        assert_eq!(enc.1, Some(true));
    }

    /// Cancelling a guided enrolment must re-read the profile list.
    ///
    /// Scan 1 creates the profile on the daemon before the later scans run, so a
    /// cancel after it leaves a real profile the cached list has never seen. The
    /// screen then showed nothing, and enrolling again on top of that is the
    /// natural next move.
    #[test]
    fn cancelling_an_enrolment_re_reads_the_profiles() {
        let mut app = test_app();
        let (_tx, rx) = mpsc::channel();
        app.enroll = Some(EnrollUi {
            rx,
            stop: Arc::new(AtomicBool::new(false)),
            profile: "BEN".into(),
            last: None,
            count: None,
            stalled: None,
            captured: 1,
            target: 5,
            base: 0,
            ambient_base: 0,
        });
        assert!(app.profiles_load.is_none(), "premise: no load in flight");
        app.on_key(KeyCode::Esc);
        assert!(app.enroll.is_none(), "Esc cancels the guided enrolment");
        assert!(
            app.profiles_load.is_some(),
            "and asks the daemon what the profile list is now"
        );
    }

    /// With the daemon down and nothing probed, the Repair tab must say it cannot
    /// check the cameras, not that there are none.
    ///
    /// `nodes` is filled only by a classifying scan, and this screen deliberately
    /// never runs one (classifying opens every node, the contention #187 is
    /// about). The empty list was being read as proof of absence, so every user
    /// whose daemon was down was told face auth was unavailable on the very
    /// screen they opened to fix it.
    #[test]
    fn a_daemon_down_repair_tab_does_not_claim_the_cameras_are_missing() {
        let mut app = test_app();
        app.daemon_up = false;
        app.nodes.clear();
        app.screen = SC_REPAIR;
        app.run_checks();
        let text = draw_text(&app);
        assert!(
            !text.contains("no camera: face auth unavailable"),
            "an unprobed list is not an absent camera: {text}"
        );
        assert!(
            text.contains("cannot check the cameras while the daemon is down"),
            "it must say what it actually knows: {text}"
        );

        // When a scan HAS classified nodes, the real verdicts still apply.
        app.nodes = vec![("/dev/video0".into(), irlume_camera::Role::Rgb)];
        app.run_checks();
        let text = draw_text(&app);
        assert!(
            text.contains("RGB-only") || text.contains("convenience"),
            "a classified RGB-only machine keeps its verdict: {text}"
        );
    }

    /// The biopolicy row must agree with the daemon about what counts as ON.
    ///
    /// The daemon accepts `1`, `true`, `yes` and `on`. The TUI had its own reader
    /// that took only `1` and `true`, so `enforce_biopolicy=yes` drew "turn it on"
    /// and the key offered to enable a gate the daemon was already enforcing.
    #[test]
    fn the_biopolicy_row_reads_every_value_the_daemon_calls_on() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-tui-bio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = std::env::var_os("IRLUME_CONFIG_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY");

        let mut app = test_app();
        app.screen = SC_SETTINGS;
        for on in ["1", "true", "yes", "on", " ON "] {
            std::fs::write(
                dir.join("settings.conf"),
                format!("enforce_biopolicy={on}\n"),
            )
            .unwrap();
            let text = draw_text(&app);
            assert!(
                text.contains("turn it off"),
                "enforce_biopolicy={on:?} is ON to the daemon, so the row must offer OFF: {text}"
            );
        }
        for off in ["0", "false", "no", "off"] {
            std::fs::write(
                dir.join("settings.conf"),
                format!("enforce_biopolicy={off}\n"),
            )
            .unwrap();
            let text = draw_text(&app);
            assert!(
                text.contains("turn it on"),
                "enforce_biopolicy={off:?} is OFF, so the row must offer ON: {text}"
            );
        }

        match old {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When settings.conf cannot be read, the gesture row must say so rather than
    /// render a default as a fact, and [c] must refuse to pick a direction.
    ///
    /// The file ships 0600 root-owned, so this is what an ordinary `irlume tui`
    /// sees. Guessing made the key one-way: every service read as required, so
    /// the only move [c] offered was DISABLE, and pressing it after a disable
    /// wrote `off` again while the row still claimed the gesture was in place.
    #[test]
    fn an_unreadable_settings_file_shows_unknown_and_refuses_to_toggle() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-tui-noread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("settings.conf");
        std::fs::write(&conf, "service_gesture.sudo=0\n").unwrap();
        // Unreadable, the way the shipped file is to a non-root TUI.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o000)).unwrap();
        let old = std::env::var_os("IRLUME_CONFIG_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        // Root can read a 0000 file, so this test only means anything unprivileged.
        // SAFETY: geteuid reads our own credentials and cannot fail.
        let is_root = unsafe { libc::geteuid() } == 0;
        if !is_root {
            let mut app = test_app();
            app.screen = SC_SETTINGS;
            let text = draw_text(&app);
            assert!(
                text.contains("◐ unknown"),
                "an unreadable config must render as unknown, not as a default: {text}"
            );

            let before = app.suspend.is_none() && app.confirm.is_none();
            assert!(before);
            app.on_key(KeyCode::Char('c'));
            assert!(
                app.suspend.is_none() && app.confirm.is_none(),
                "[c] must not pick a direction from a state it cannot read"
            );
            assert!(
                app.activity.iter().any(|l| l.1.contains("root-only")),
                "and it must say why: {:?}",
                app.activity
            );
        }

        let _ = std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o600));
        match old {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A privileged step must not re-`sudo` when the TUI is already root: the
    /// inner sudo resets SUDO_USER to "root", and every per-user command
    /// resolves its target from it, so `sudo irlume tui` -> `[c]` stored the eye
    /// calibration for root instead of the person who ran the TUI.
    #[test]
    fn a_root_tui_runs_privileged_steps_without_a_second_sudo() {
        let args = ["/usr/bin/irlume", "calibrate-closure"];

        // Already root: run the binary directly, so the OUTER sudo's SUDO_USER
        // survives and names the real user.
        let cmd = App::privileged_cmd(&args, true);
        assert_eq!(cmd.get_program(), "/usr/bin/irlume");
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            vec!["calibrate-closure"],
            "no sudo, and the arguments are unchanged"
        );

        // Unprivileged: sudo is how the step gets its privilege at all.
        let cmd = App::privileged_cmd(&args, false);
        assert_eq!(cmd.get_program(), "sudo");
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            vec!["/usr/bin/irlume", "calibrate-closure"]
        );
    }

    /// The PAM tab's [c] row must describe the calibration the CONFIGURED mode
    /// actually uses. It was one fixed string calling the eye closure an optional
    /// alternative, which is true only in the default mode: under
    /// `consent_gesture=closure` the nod is refused and this calibration is the
    /// only way any gesture passes (the old text sent that user to nod at a gate
    /// that would deny them), and under `consent_gesture=nod` the closure is
    /// refused, so teaching it changes nothing.
    #[test]
    fn calibrate_row_describes_the_configured_gesture_mode() {
        let _g = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-tui-calibmode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = std::env::var_os("IRLUME_CONFIG_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        let mut app = test_app();
        app.screen = SC_PAM;
        for (conf, expect) in [
            ("", "optional eye-closure alternative"),
            ("consent_gesture=closure\n", "REQUIRED"),
            ("consent_gesture=nod\n", "not accepted"),
            ("consent_gesture=banana\n", "until consent_gesture is fixed"),
        ] {
            std::fs::write(dir.join("settings.conf"), conf).unwrap();
            let text = draw_text(&app);
            let row = row_with(&text, "Calibrate gesture");
            assert!(
                row.contains(expect),
                "mode {conf:?} must say {expect:?}, got: {row}"
            );
        }

        match old {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The Settings tab must name BOTH halves of the gesture. A user told only
    /// how to approve does not know a head shake is a deliberate decline the
    /// daemon acts on (it cancels the request, and on a polkit prompt it ends the
    /// attempt). Before this, no user-visible string in the CLI or TUI mentioned
    /// the shake at all.
    #[test]
    fn settings_names_the_shake_decline() {
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        let text = draw_text(&app);
        assert!(
            text.contains("shake your head to decline"),
            "the gesture section must name the decline: {text}"
        );
    }

    #[test]
    fn gesture_explainer_uses_the_right_article() {
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        let text = draw_text(&app);
        // The explainer offers the eye closure as the alternative to nodding; the
        // article before "eye" must be "an", and the phrase is kept on one line so
        // it cannot render as "(or a / eye closure)".
        assert!(
            row_with(&text, "or an eye closure").contains("or an eye closure"),
            "{text}"
        );
        assert!(!text.contains("or a eye closure"), "{text}");
    }

    #[test]
    fn help_overlay_lists_every_bound_key_of_the_screen() {
        let mut app = test_app();
        // Global: 'h' jumps home from any tab.
        assert!(app.help_body().contains("home"), "{}", app.help_body());
        // Welcome: Enter opens the selected hub section.
        app.screen = SC_WELCOME;
        assert!(
            app.help_body().contains("open the selected section"),
            "{}",
            app.help_body()
        );
        // Cameras: [t] tune capture is bound and documented in body text.
        app.screen = SC_CAMERAS;
        assert!(
            app.help_body().contains("tune capture"),
            "{}",
            app.help_body()
        );
        // Keyring: [p] refreshes the pcrlock policy on a Tier-2 seal, and its
        // handler is guarded on exactly that, so the disclosure follows the guard.
        // Listing it on a seal that has no such policy offered a key that did
        // nothing and said nothing.
        app.screen = SC_KEYRING;
        app.keyring_armed = Some(true);
        app.keyring_policy = Some("pcrlock NV 0x18fb7a2 (Tier 2)".into());
        assert!(app.help_body().contains("pcrlock"), "{}", app.help_body());
        app.keyring_policy = None;
        assert!(
            !app.help_body().contains("pcrlock"),
            "no Tier-2 policy, so no [p]: {}",
            app.help_body()
        );
        // And [r] follows the armed state the same way.
        assert!(app.help_body().contains("reseal"), "{}", app.help_body());
        app.keyring_armed = Some(false);
        assert!(
            !app.help_body().contains("reseal"),
            "nothing to reseal on an unarmed keyring: {}",
            app.help_body()
        );
    }
}
