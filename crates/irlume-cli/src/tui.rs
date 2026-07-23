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
const SCREENS: [&str; 11] = [
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
const SC_DONE: usize = 10;
const ACT_H: usize = 5; // visible rows in the Activity panel (height 7 minus borders)
const MAX_PROFILES: usize = 3;
const ENROLL_SCANS: usize = irlume_core::storage::DEFAULT_ENROLL_SCANS;
/// Scans captured per improve-recognition round (add to an existing profile).
const ADD_SCANS: usize = irlume_core::storage::IMPROVE_SCANS;
const GOOD_STREAK: u32 = 3;
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
    /// Auto-configure the IR emitter; root op, suspends to `sudo irlume ir-setup`.
    IrSetup,
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
    ModelsDisable,
    /// Origin-aware updater; runs unprivileged (it invokes sudo itself for
    /// the package-manager step when one is needed).
    Update,
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
    IrSetup,
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
    Calibrate,
}

/// Fingerprint snapshot for the Fingerprint screen.
#[derive(Default)]
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
}

/// Template-encryption + recovery status (`RecoveryStatus`).
#[derive(Clone, Copy, Default)]
struct RecoveryInfo {
    encrypted: bool,
    recovery_set: bool,
    tpm_present: bool,
}

/// Messages streamed from the guided-enroll worker to the UI.
enum WMsg {
    Cue(PositionReport),
    Count(u8),
    Captured(usize, usize),
    Done,
    Err(String),
    /// Scan 1 of a "new profile" enroll matched an existing identity, so the
    /// daemon merged it into `profile` instead. The worker ends here and hands
    /// off to the UI, which confirms with the user before adding the rest.
    /// `added_scans` are the scan(s) already appended (undo target on decline).
    MergePrompt {
        profile: String,
        total: usize,
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
}

struct EnrollUi {
    rx: mpsc::Receiver<WMsg>,
    stop: Arc<AtomicBool>,
    profile: String,
    last: Option<PositionReport>,
    count: Option<u8>,
    captured: usize,
    target: usize,
    /// Scans already on the profile from this enroll session before the worker
    /// started (e.g. the one scan a merge added), so the on-screen "scan X/Y"
    /// stays continuous across the merge-confirm continuation instead of
    /// restarting at 0.
    base: usize,
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
    challenge: bool,
    keyring_armed: Option<bool>,
    /// Seal-tier label from `KeyringInfo` (e.g. "pcrlock NV 0x… (Tier 2)");
    /// `None` when not armed or the daemon predates the request.
    keyring_policy: Option<String>,
    /// Whether the bound PCRs drifted since sealing (`KeyringInfo`).
    keyring_drift: Option<bool>,
    nodes: Vec<(String, irlume_camera::Role)>,
    /// Cached camera pairs, refreshed on the slow timer so the Cameras tab and
    /// move_sel don't re-probe the hardware on every keystroke and frame.
    pairs: Vec<irlume_camera::CameraPair>,
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
    selftest_result: Option<(bool, String)>,
    /// Repair-tab diagnostics + selection.
    repair: Vec<Check>,
    repair_sel: usize,
    /// Cameras-tab pair selection.
    cam_sel: usize,
    /// A prominent, dismissible error banner (e.g. "camera busy") so failures
    /// are never silently buried in the Activity log.
    error: Option<String>,
    /// Live daemon reachability (a real Ping, refreshed each tick), not a
    /// hardcoded socket-path check.
    daemon_up: bool,
    /// Last ListProfiles error (corrupt enrollment / missing template key);
    /// distinguishes "file broken" from "no profiles" on the Repair tab.
    enroll_error: Option<String>,
    /// Daemon self-report (Request::Health): its camera tier and loaded models:
    /// ground truth for the Repair rows (static path probes lie when the daemon
    /// runs with its own env, e.g. a packaged install).
    health: Option<HealthInfo>,
    /// Activity panel scroll offset (lines up from the bottom; 0 = follow newest).
    act_scroll: usize,
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
    spin: usize,
    quit: bool,
}

pub fn run() -> std::io::Result<()> {
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
    let mut app = App::new();
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
    fn new() -> Self {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "user".into());
        // Hardware-adaptive screens: only show what the device can actually do, so
        // a fingerprint-only box never offers face/camera setup steps.
        let caps = irlume_camera::capabilities();
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
            challenge: false,
            keyring_armed: None,
            keyring_policy: None,
            keyring_drift: None,
            nodes: irlume_camera::discover_nodes(),
            pairs: irlume_camera::list_pairs(),
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
            selftest_result: None,
            repair: Vec::new(),
            repair_sel: 0,
            cam_sel: 0,
            error: None,
            daemon_up: false,
            enroll_error: None,
            health: None,
            act_scroll: 0,
            visible,
            caps,
            fp_present,
            advanced: false,
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
        let needs_repair = daemon_down || checks.iter().any(|c| c.sev == Sev::Fail);
        (0..SCREENS.len())
            .filter(|&i| match i {
                // Essential face path requires a camera.
                SC_PROFILES | SC_RECOVERY => caps.rgb,
                // Diagnostics/tuning: advanced view only.
                SC_CAMERAS | SC_IDENTIFY => advanced && caps.rgb,
                SC_SETTINGS => advanced,
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
    }

    /// Capability-aware recommended unlock method (item: "suggest the best one").
    fn recommended(&self) -> &'static str {
        match (self.caps.ir_pair, self.caps.rgb, self.fp_present) {
            (true, _, _) => "Face (IR) · secure: login, sudo, lock screen, dark mode",
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

    /// CHEAP live poll (runs on the fast ~2.5s timer): daemon state + camera
    /// nodes only; all sub-millisecond, no subprocess spawns. Keeps the panel
    /// live without periodic UI hitches. SILENT (no Activity spam).
    fn refresh_light(&mut self) {
        // Short-budget poll: if the daemon isn't answering (down, or busy
        // mid-capture and not accepting), fail fast and skip the rest of the
        // reads rather than stalling the UI thread on each one. Next tick retries.
        self.daemon_up = matches!(crate::daemon_poll(&Request::Ping), Ok(Response::Pong));
        if self.daemon_up {
            self.health = match crate::daemon_poll(&Request::Health) {
                Ok(Response::Health {
                    tier,
                    rgb_dev,
                    ir_dev,
                    mesh,
                    adapter,
                    version,
                }) => Some(HealthInfo {
                    tier,
                    rgb_dev,
                    ir_dev,
                    mesh,
                    adapter,
                    version,
                }),
                _ => None, // older daemon / daemon down → Repair falls back to local probes
            };
            match crate::daemon_poll(&Request::ListProfiles {
                user: self.user.clone(),
            }) {
                Ok(Response::Enrollment {
                    profiles,
                    require_eyes_open,
                    require_challenge,
                    ..
                }) => {
                    self.profiles = profiles;
                    self.eyes_open = require_eyes_open;
                    self.challenge = require_challenge;
                    self.enroll_error = None;
                }
                // A corrupt/unreadable enrollment (or a missing template key for an
                // encrypted file) surfaces as an Error, not empty; don't silently
                // show "no face enrolled"; capture it so Repair can flag+fix it.
                Ok(Response::Error(e)) => self.enroll_error = Some(e),
                _ => {}
            }
            // KeyringInfo adds the seal tier and PCR drift; an older daemon
            // answers it with an error, so fall back to the plain armed bit.
            match crate::daemon_poll(&Request::KeyringInfo {
                user: self.user.clone(),
            }) {
                Ok(Response::KeyringInfo {
                    armed,
                    policy,
                    drifted,
                    ..
                }) => {
                    self.keyring_armed = Some(armed);
                    self.keyring_policy = policy;
                    self.keyring_drift = drifted;
                }
                _ => {
                    self.keyring_armed = match crate::daemon_poll(&Request::HasSealedPassword {
                        user: self.user.clone(),
                    }) {
                        Ok(Response::HasPassword(b)) => Some(b),
                        _ => self.keyring_armed,
                    };
                    self.keyring_policy = None;
                    self.keyring_drift = None;
                }
            }
            if let Ok(Response::RecoveryStatus {
                encrypted,
                recovery_set,
                tpm_present,
            }) = crate::daemon_poll(&Request::RecoveryStatus {
                user: self.user.clone(),
            }) {
                self.recovery = Some(RecoveryInfo {
                    encrypted,
                    recovery_set,
                    tpm_present,
                });
            }
        } else {
            // Daemon down/unresponsive: show the down state; local probes below
            // still run so Repair can diagnose.
            self.health = None;
        }
        self.nodes = irlume_camera::discover_nodes();
        self.pairs = irlume_camera::list_pairs();
        let max = self.rows().len().max(1);
        if self.sel >= max {
            self.sel = max - 1;
        }
        let pairs = self.pairs.len().max(1);
        if self.cam_sel >= pairs {
            self.cam_sel = pairs - 1;
        }
    }

    /// FULL refresh = cheap poll + the heavier probes (fingerprint via fprintd,
    /// the Repair diagnostics which spawn `ls -Z` etc.). Runs on the slow timer,
    /// on demand (`[r]`), after an op, and when opening Repair/Fingerprint, but
    /// NOT every fast tick, so fprintd/subprocess calls can't hitch the UI.
    fn refresh(&mut self) {
        self.refresh_light();
        // Re-derive hardware capabilities so a camera or reader hot-plugged
        // after launch reveals its tabs (caps/fp_present drive `visible` and the
        // Welcome gates, and were otherwise frozen at startup).
        self.caps = irlume_camera::capabilities();
        self.fp_present = irlume_fingerprint::available();
        self.fp = FpInfo {
            available: self.fp_present,
            device: irlume_fingerprint::device_name(),
            enrolled: irlume_fingerprint::enrolled_fingers(&self.user),
            method: irlume_core::policy::method().as_str().to_string(),
        };
        self.run_checks();
        // Visibility is state-driven (Repair appears when something fails);
        // re-derive it from the fresh diagnostics.
        self.recompute_visible();
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

        let up = matches!(crate::daemon_request(&Request::Ping), Ok(Response::Pong));
        v.push(mk(
            "Daemon (irlumed)",
            if up { Sev::Ok } else { Sev::Fail },
            if up {
                "running, socket reachable".into()
            } else {
                "not reachable on /run/irlume.sock".into()
            },
            if up {
                Fix::None
            } else {
                Fix::Root(RootFix::RestartDaemon)
            },
        ));

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
            // Camera row from the daemon's validated tier (never the raw fallback).
            let priv_on = self
                .nodes
                .iter()
                .any(|(p, _)| irlume_camera::privacy_engaged(p));
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
                v.push(mk(
                    "IR emitter",
                    Sev::Warn,
                    "if the IR feed is dark, auto-enable the 850nm illuminator".into(),
                    Fix::Root(RootFix::IrSetup),
                ));
            }
        } else {
            let ort = std::env::var("ORT_DYLIB_PATH")
                .ok()
                .filter(|p| std::path::Path::new(p).exists())
                .is_some()
                || ["/usr/lib64/libonnxruntime.so", "/usr/lib/libonnxruntime.so"]
                    .iter()
                    .any(|p| std::path::Path::new(p).exists());
            v.push(mk(
                "ONNX Runtime",
                if ort { Sev::Ok } else { Sev::Fail },
                if ort {
                    "library found".into()
                } else {
                    "libonnxruntime.so not found (daemon down; local probe)".into()
                },
                if ort {
                    Fix::None
                } else {
                    Fix::Manual("install onnxruntime or set ORT_DYLIB_PATH".into())
                },
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
            let priv_on = self
                .nodes
                .iter()
                .any(|(p, _)| irlume_camera::privacy_engaged(p));
            let (csev, cdetail, cfix) = if !rgb && !ir {
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
                v.push(mk(
                    "IR emitter",
                    Sev::Warn,
                    "if the IR feed is dark, auto-enable the 850nm illuminator".into(),
                    Fix::Root(RootFix::IrSetup),
                ));
            }
        }

        if std::fs::read_to_string("/sys/fs/selinux/enforce")
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
        {
            let labeled = std::process::Command::new("ls")
                .args(["-Z", "/run/irlume.sock"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("irlume_runtime_t"))
                .unwrap_or(false);
            // Only a FAILURE once login is wired (the greeter actually needs it
            // then). Pre-wiring it's informational: `login enable --apply`
            // loads the module itself, so don't alarm a fresh install.
            let wired = crate::pamwire::login_wired();
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
        // Blink challenge configured but the FaceMesh model isn't loaded: the
        // challenge silently skips; surface it instead.
        if self.challenge && self.health.as_ref().is_some_and(|h| !h.mesh) {
            v.push(mk(
                "Blink challenge",
                Sev::Fail,
                "require-challenge is ON but FaceMesh isn't loaded; the challenge is skipped"
                    .into(),
                Fix::Manual(
                    "set IRLUME_MESH_MODEL=<models/face_landmark.onnx> in the irlumed unit".into(),
                ),
            ));
        }
        // Fingerprint reader health: a crashed/aborted enrollment leaves the
        // device CLAIMED and pam_fprintd fails silently (no finger prompt).
        if self.fp.available {
            if irlume_fingerprint::reader_stuck(&self.user) {
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
        // Active (non-comment) PAM lines only; a commented-out module is not wired.
        let pam_has = |needle: &str| {
            ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]
                .iter()
                .any(|p| {
                    std::fs::read_to_string(p)
                        .map(|s| {
                            s.lines()
                                .any(|l| !l.trim_start().starts_with('#') && l.contains(needle))
                        })
                        .unwrap_or(false)
                })
        };
        let fprintd_wired = pam_has("pam_fprintd");
        match self.fp.method.as_str() {
            "fingerprint" => {
                if !fprintd_wired {
                    v.push(mk(
                        "Method wiring",
                        Sev::Fail,
                        "method is fingerprint but pam_fprintd is not wired".into(),
                        Fix::Manual("sudo irlume fingerprint enable --user <you>".into()),
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
                if fprintd_wired && !self.fp.enrolled.is_empty() && crate::tpm_device().is_some() {
                    let armed = self.keyring_armed.unwrap_or(false);
                    // DM-aware: the keyring line must be in EVERY login service
                    // the active DM uses (GDM: gdm-password AND gdm-fingerprint).
                    let wired = crate::pamwire::fp_keyring_wired();
                    if !armed {
                        v.push(mk(
                            "FP keyring unlock",
                            Sev::Warn,
                            "wallet won't auto-unlock on fingerprint login; arm the keyring".into(),
                            Fix::Manual("Keyring tab → [a] arm (seal your login password)".into()),
                        ));
                    } else if !wired {
                        v.push(mk(
                            "FP keyring unlock",
                            Sev::Warn,
                            "keyring armed but the login stack lacks the unlock line".into(),
                            Fix::Root(RootFix::LoginEnable),
                        ));
                    } else {
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
        // stack lost the module — authselect/pam-auth-update regenerated the
        // PAM files. Face silently falls back to password until re-applied.
        if crate::pamwire::reconcile_needed() {
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
        // AppArmor (Debian-family) parity with the SELinux check.
        if std::path::Path::new("/sys/kernel/security/apparmor").exists() {
            let profiled = std::path::Path::new("/etc/apparmor.d/usr.local.bin.irlumed").exists();
            v.push(mk(
                "AppArmor",
                if profiled { Sev::Ok } else { Sev::Warn },
                if profiled {
                    "irlume profile installed".into()
                } else {
                    "daemon unconfined; optional hardening profile available".into()
                },
                if profiled {
                    Fix::None
                } else {
                    Fix::Manual(
                        "install packaging/apparmor/usr.local.bin.irlumed (see repo)".into(),
                    )
                },
            ));
        }

        if let Some(r) = self.recovery {
            if r.encrypted && !r.recovery_set {
                v.push(mk(
                    "Recovery backstop",
                    Sev::Warn,
                    "templates encrypted but no recovery passphrase".into(),
                    Fix::Manual("run `irlume recovery setup`".into()),
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
            .unwrap_or_else(|| crate::tpm_device().is_some());
        if !tpm {
            v.push(mk("TPM", Sev::Warn,
                "no TPM: templates stored root-only plaintext; keyring auto-unlock unavailable (face login/sudo still work)".into(),
                Fix::Manual("optional: enable the firmware TPM (fTPM/PTT) in BIOS, then re-enroll to encrypt at rest".into())));
        } else {
            // Secure Boot binds the TPM seal to the boot state (PCR-7). Off ⇒ the
            // seal still works but isn't tamper-bound to a trusted boot chain.
            use irlume_common::secureboot;
            if secureboot::secure_boot_present() && !secureboot::is_secure_boot_enabled() {
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
            None => return,
        };
        match fix {
            Fix::None => self.log('·', "nothing to fix on this row"),
            Fix::Manual(cmd) => self.log('·', format!("manual fix → {cmd}")),
            // Emitter setup writes the persisted UVC control, a root op now.
            Fix::Root(RootFix::IrSetup) => {
                self.log('→', "sudo irlume ir-setup: enable the 850nm emitter (you'll be asked for your password)");
                self.suspend = Some(Suspend::IrSetup);
            }
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
            captured: 0,
            target,
            base: 0,
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
        std::thread::spawn(move || enroll_worker(user, pn, add, mc.remaining, st, tx));
        self.enroll = Some(EnrollUi {
            rx,
            stop,
            profile: mc.profile,
            last: None,
            count: None,
            captured: 0,
            target: mc.remaining,
            base,
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

    fn poll(&mut self) {
        if let Some(op) = &self.op {
            if let Ok((ok, msg)) = op.rx.try_recv() {
                let tag = op.tag;
                // The IR self-test shows its own result line on the Repair screen;
                // a normal "no face / uncertain" outcome shouldn't also raise the
                // alarming error modal (that's for genuine failures like a busy
                // camera). Identify/Generic keep the modal on failure.
                if ok {
                    self.log('✓', msg.clone());
                } else if !matches!(tag, OpTag::Calibrate | OpTag::Identify) {
                    self.set_error(msg.clone());
                } else {
                    self.log('·', msg.clone());
                }
                match tag {
                    OpTag::Identify => self.identify_result = Some((ok, msg)),
                    OpTag::Calibrate => self.selftest_result = Some((ok, msg)),
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
                    WMsg::Done => {
                        self.log('✓', "enrollment complete");
                        finished = true;
                    }
                    WMsg::Err(e) => {
                        let e = e.strip_prefix("hardware: ").unwrap_or(&e);
                        self.set_error(format!("Enrollment failed: {e}"));
                        finished = true;
                    }
                    WMsg::MergePrompt {
                        profile,
                        total,
                        added_scans,
                    } => {
                        // The rest of the requested scans, capped at the profile's
                        // remaining 30-scan budget (scan 1 already merged in).
                        let remaining = target
                            .saturating_sub(1)
                            .min(irlume_core::storage::MAX_SCANS_PER_PROFILE.saturating_sub(total));
                        merge = Some(MergeConfirm {
                            profile,
                            added_scans,
                            remaining,
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
                    self.refresh(); // cheap + fingerprint + diagnostics
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
                self.run_suspended(s);
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
                        if matches!(crate::daemon_request(&Request::Ping), Ok(Response::Pong)) {
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
    /// `ir-setup` leaves no re-checkable state, so we log ✓ on success and raise
    /// the error banner on failure.
    fn sudo_step(&mut self, what: &str, args: &[&str]) {
        eprintln!("\n{what}; running: sudo {}…", args.join(" "));
        // In the cooked terminal, Ctrl-C goes to the whole foreground group:
        // a user aborting the CHILD (a sudo prompt, the models license flow)
        // must not also kill the TUI. Ignore SIGINT here while the child runs;
        // the child gets the default disposition back pre-exec so Ctrl-C still
        // cancels IT. (Found live: Ctrl-C in the license prompt took the whole
        // TUI down.)
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("sudo");
        cmd.args(args);
        // SAFETY: signal() is async-signal-safe; this runs in the forked child
        // just before exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                Ok(())
            });
        }
        let old_int = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
        let status = cmd.status();
        unsafe { libc::signal(libc::SIGINT, old_int) };
        match status {
            Ok(st) if st.success() => self.log('✓', format!("{what}: done")),
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
        match s {
            Suspend::FingerprintAdd => {
                crate::fingerprint::run(Some("add"), &none);
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
                &["irlume", "calibrate-closure"],
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
                crate::fingerprint::run(Some("verify"), &none);
            }
            Suspend::FingerprintEnable => self.sudo_step(
                "enable fingerprint (face OR finger)",
                &["irlume", "fingerprint", "enable"],
            ),
            Suspend::FingerprintDisable => self.sudo_step(
                "disable fingerprint for login",
                &["irlume", "fingerprint", "disable"],
            ),
            Suspend::FingerprintReset => self.sudo_step(
                "delete ALL enrolled fingerprints",
                &["irlume", "fingerprint", "reset"],
            ),
            Suspend::ModelsEnable(name) => self.sudo_step(
                "enable a third-party liveness model (license confirm follows)",
                &["irlume", "models", "enable", &name],
            ),
            Suspend::ModelsDisable => self.sudo_step(
                "disable the third-party model",
                &["irlume", "models", "disable"],
            ),
            Suspend::Update => {
                crate::commands::update(&none);
            }
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
            // Load the policy AND restart the daemon so the socket relabels to
            // irlume_runtime_t; otherwise the existing socket keeps its old label
            // and the check would still fail.
            Suspend::SelinuxLoad => self.sudo_step(
                "load the SELinux module + relabel the socket",
                &[
                    "sh",
                    "-c",
                    "irlume selinux load && systemctl restart irlumed",
                ],
            ),
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
        if self.screen == SC_REPAIR || self.screen == SC_FINGERPRINT {
            self.refresh();
        }
    }

    fn move_sel(&mut self, d: i32) {
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
                    if target == SC_REPAIR || target == SC_FINGERPRINT {
                        self.refresh();
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
            (SC_REPAIR, KeyCode::Char('l')) => self.start_async(
                "SelfTest (IR liveness)",
                OpTag::Calibrate,
                Request::SelfTest {
                    kind: irlume_common::SelfTestKind::Liveness,
                },
                map_selftest,
            ),
            // Cameras: IR emitter auto-setup (root; writes the persisted UVC
            // control) suspends to sudo; the [p] probe below is read-only.
            (SC_CAMERAS, KeyCode::Char('s')) => {
                self.log('→', "sudo irlume ir-setup: enable the 850nm emitter (you'll be asked for your password)");
                self.suspend = Some(Suspend::IrSetup);
            }
            (SC_CAMERAS, KeyCode::Char('p')) => self.start_async(
                "IR emitter probe",
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
            (SC_KEYRING, KeyCode::Char('f')) => {
                self.confirm = Some((
                    "Erase the TPM-sealed login password?".into(),
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
            // Blink challenge is a per-user opt-in gate, togglable exactly like
            // eyes-open; [c] flips it so the anti-spoof stage no longer needs a
            // drop to the shell (`irlume profiles challenge on|off`).
            (SC_SETTINGS, KeyCode::Char('c')) => {
                let on = !self.challenge;
                self.start_async(
                    "toggle require-challenge",
                    OpTag::Generic,
                    Request::SetRequireChallenge {
                        user: self.user.clone(),
                        on,
                    },
                    map_settings,
                );
            }
            // Third-party PAD model toggle. settings.conf is root-only, so the
            // readable proxy for "enabled" is installed weights (disable
            // deletes them). Enabling runs the CLI's own license/provenance
            // confirm in the cooked terminal: that friction is the policy,
            // the TUI hosts it rather than bypassing it.
            (SC_SETTINGS, KeyCode::Char('m')) => {
                use irlume_common::thirdparty::{weight_state, WeightState, CATALOG};
                let installed = CATALOG
                    .iter()
                    .find(|m| matches!(weight_state(m), WeightState::ChecksumOk));
                match installed {
                    Some(m) => {
                        self.confirm = Some((
                            format!(
                                "Disable third-party model '{}'? (its weights are deleted)",
                                m.name
                            ),
                            "Disable",
                            ConfirmAct::Sus(Suspend::ModelsDisable),
                        ));
                    }
                    None => match CATALOG.first() {
                        Some(m) => {
                            self.log('→', format!("sudo irlume models enable {}: the license + provenance confirm runs in the terminal", m.name));
                            self.suspend = Some(Suspend::ModelsEnable(m.name.to_string()));
                        }
                        None => self.log('·', "no third-party models in the catalog"),
                    },
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
            None => {}
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
            None => {}
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
                        "uninstall confirmed; suspending to `sudo irlume uninstall`",
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
                let req = Request::SealPassword {
                    user: self.user.clone(),
                    password: irlume_common::SecretBytes::new(buf.as_bytes().to_vec()),
                };
                // Async: the TPM seal is the slowest daemon op; don't freeze the frame.
                self.start_async("SealPassword", OpTag::Generic, req, map_sealed);
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
            captured: 0,
            target: ENROLL_SCANS,
            base: 0,
        });
    }

    // ---- rendering --------------------------------------------------------

    fn draw(&self, f: &mut Frame) {
        let [header, hint, body, activity, footer] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(7),
            Constraint::Length(3),
        ])
        .areas(f.area());
        self.draw_header(f, header);
        self.draw_hint(f, hint);
        self.draw_content(f, body);
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
        let w = area.width.saturating_sub(8).clamp(30, 78);
        let h = 7u16;
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

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let blk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim());
        let left = Line::from(vec![
            Span::styled(
                " irlume ",
                Style::new()
                    .fg(Color::Black)
                    .bg(th().accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!(
                    "step {}/{}: ",
                    self.visible
                        .iter()
                        .position(|&s| s == self.screen)
                        .map_or(1, |p| p + 1),
                    self.visible.len()
                ),
                Style::new().dim(),
            ),
            Span::styled(
                SCREENS[self.screen],
                Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
            ),
        ]);
        let right =
            Line::from(Span::styled(format!("{} ", self.user), Style::new().dim())).right_aligned();
        f.render_widget(Paragraph::new(left).block(blk.clone()), area);
        f.render_widget(Paragraph::new(right).block(blk), area);
    }

    /// A single plain-language line under the header: what THIS tab is for and
    /// the one thing to do here. The whole point is that a first-time user never
    /// lands on a screen not knowing why they're there: no jargon, names the key.
    fn draw_hint(&self, f: &mut Frame, area: Rect) {
        // During a capture the whole UI is about holding still; don't distract.
        // Kept to ~70 chars so it never wraps off this single row on an 80-col
        // terminal (the "  ℹ " prefix eats ~4). Each names the key to press.
        let text = if self.enroll.is_some() {
            "Look at the camera and hold still; the checklist turns green as you go."
        } else {
            match self.screen {
                SC_WELCOME => {
                    "New here? Press [e] to scan your face; your password still works too."
                }
                SC_REPAIR => {
                    "A red row is a problem: highlight it, press [f] to fix or [g] for logs."
                }
                SC_CAMERAS => "Wrong camera picked? Highlight a pair and press [enter] to use it.",
                SC_PROFILES => {
                    "Press [e] to add a face, or [a] to add scans so it knows you better."
                }
                SC_IDENTIFY => "A 'does it recognize me?' test. Press [i] and look at the camera.",
                SC_KEYRING => {
                    "Let your login open your password wallet: press [a], type your password."
                }
                SC_RECOVERY => "Set a backup passphrase so a broken TPM seal never forces a re-enroll; press [s].",
                SC_FINGERPRINT => "Optional backup: press [a] to add a fingerprint too.",
                SC_PAM => "Turn on face login for your screen: press [w] (asks for your password).",
                SC_SETTINGS => {
                    "[enter] toggles the eyes-open check, [c] the blink challenge; other settings are root or read-only."
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
        ];
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
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_profiles(&self, f: &mut Frame, area: Rect) {
        if self.profiles.is_empty() {
            f.render_widget(Paragraph::new("\nNo face profiles yet.\n\nPress [e] to enroll; irlume will guide your framing and capture automatically.")
                .wrap(Wrap { trim: true }).dim(), area);
            return;
        }
        let rows = self.rows();
        let items: Vec<ListItem> = rows
            .iter()
            .map(|r| match r {
                Row::Profile(pi) => {
                    let p = &self.profiles[*pi];
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!("● {}", p.name),
                            Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(format!("   ({} scans)", p.scans.len()), Style::new().dim()),
                    ]))
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
        items.push(ListItem::new(Line::from(Span::styled(
            "  Tips: look different sometimes (glasses, low light)? Add scans to your profile with Improve Recognition ([a]); same identity, not a second profile.",
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

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let bio = biopolicy_on();
        f.render_widget(
            Paragraph::new(vec![
                section("Require eyes open"),
                Line::from(vec![Span::raw("  state  "), onoff(self.eyes_open)]),
                Line::from(Span::styled(
                    "  Never unlock unless both eyes read open (IR-glint heuristic).",
                    Style::new().dim(),
                )),
                Line::from(vec![
                    Span::styled("  [enter]", Style::new().fg(th().accent)),
                    Span::styled(" toggle", Style::new().dim()),
                ]),
                Line::raw(""),
                section("Biopolicy operation-class gate"),
                Line::from(vec![
                    Span::raw("  state  "),
                    if bio {
                        Span::styled(
                            "● ENFORCING",
                            Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                        )
                    } else {
                        Span::styled("○ off (default)", Style::new().dim())
                    },
                ]),
                Line::from(Span::styled(
                    "  When on: only Login/Elevation may release the keyring; lock-screen",
                    Style::new().dim(),
                )),
                Line::from(Span::styled(
                    "  is verify-only; remote/unknown services are denied.",
                    Style::new().dim(),
                )),
                Line::from(Span::styled(
                    "  Toggle (root): set enforce_biopolicy=1 in /etc/irlume/settings.conf.",
                    Style::new().dim(),
                )),
                Line::raw(""),
                section("Third-party liveness models"),
                Line::from(vec![
                    Span::raw("  state  "),
                    Span::styled(crate::models::doctor_line(), Style::new().dim()),
                ]),
                Line::from(Span::styled(
                    "  Opt-in, measured, deny-only extra anti-spoof cue; fetched from the",
                    Style::new().dim(),
                )),
                Line::from(Span::styled(
                    "  publisher, checksum-pinned, never shipped by irlume.",
                    Style::new().dim(),
                )),
                Line::from(Span::styled(
                    "  [m] enables or disables one (sudo; the license confirm runs in the terminal)",
                    Style::new().dim(),
                )),
                Line::raw(""),
                section("Match thresholds (read-only)"),
                Line::from(Span::styled(
                    "  Calibrated per modality (RGB/IR), auto-scaled by enrolled scan count.",
                    Style::new().dim(),
                )),
            ])
            .wrap(Wrap { trim: true }),
            area,
        );
    }

    fn draw_cameras(&self, f: &mut Frame, area: Rect) {
        let [list_area, info_area] =
            Layout::vertical([Constraint::Min(3), Constraint::Length(8)]).areas(area);
        let (argb, air) = irlume_camera::select_pair(); // currently active pair
        let pairs = &self.pairs;

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
                v.push(ListItem::new(Span::styled(
                    "no camera found: face auth unavailable on this device",
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
                    let priv_on = irlume_camera::privacy_engaged(&p.rgb)
                        || irlume_camera::privacy_engaged(&p.ir);
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
        let blk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim())
            .title(" cameras (● = active · ↑↓ select · enter = use) ");
        let inner = blk.inner(list_area);
        f.render_widget(blk, list_area);
        f.render_stateful_widget(
            List::new(items).highlight_style(
                Style::new()
                    .bg(Color::Rgb(0x20, 0x30, 0x40))
                    .add_modifier(Modifier::BOLD),
            ),
            inner,
            &mut st,
        );

        // ---- info: active pair, selected pair nodes, emitter ----
        // Only claim a node as "active" if it exists; select_pair's fixed
        // fallback names devices that may be absent on this hardware.
        let ex = |d: &str| std::path::Path::new(d).exists();
        let active = match (ex(&argb), ex(&air)) {
            (true, true) => format!("{argb} + {air}"),
            (true, false) => format!("{argb} (RGB only)"),
            _ => "none (no camera hardware)".into(),
        };
        let mut lines = vec![Line::from(vec![
            Span::styled("  active   ", Style::new().dim()),
            Span::styled(
                active,
                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
            ),
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
            "  If the IR feed is dark irlume probes the UVC controls and enables",
            Style::new().dim(),
        )));
        lines.push(Line::from(Span::styled(
            "  the illuminator automatically (no phone-camera step).",
            Style::new().dim(),
        )));
        lines.push(Line::from(vec![
            Span::styled("  [s]", Style::new().fg(th().accent)),
            Span::styled(" auto-setup emitter   ", Style::new().dim()),
            Span::styled("[p]", Style::new().fg(th().accent)),
            Span::styled(" probe XU controls", Style::new().dim()),
        ]));
        let iblk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim());
        f.render_widget(
            Paragraph::new(lines).block(iblk).wrap(Wrap { trim: true }),
            info_area,
        );
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
            Line::raw(""),
            Line::from(vec![
                Span::styled("Reader        ", Style::new().add_modifier(Modifier::BOLD)),
                reader,
            ]),
            Line::from(vec![
                Span::styled("Enrolled      ", Style::new().add_modifier(Modifier::BOLD)),
                enrolled,
            ]),
            Line::from(vec![
                Span::styled("Active method ", Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(method_label(&self.fp.method)),
            ]),
            Line::raw(""),
        ];
        if self.fp.available {
            lines.push(Line::from(Span::styled(
                "Fingerprint is a companion factor via stock fprintd + pam_fprintd.",
                Style::new().dim(),
            )));
            lines.push(Line::from(Span::styled(
                "  [a] enroll a finger · [t] test a finger · [x] wipe all enrolled fingers",
                Style::new().dim(),
            )));
            lines.push(Line::from(Span::styled(
                "  [e] unlock with face OR fingerprint (sudo) · [d] remove fingerprint from login",
                Style::new().dim(),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "No usable reader on this device; fingerprint unavailable.",
                Style::new().dim(),
            )));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_recovery(&self, f: &mut Frame, area: Rect) {
        let r = self.recovery.unwrap_or_default();
        let enc = if r.encrypted {
            Span::styled(
                "● encrypted",
                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("○ plaintext at rest", Style::new().dim())
        };
        let rec = if r.recovery_set {
            Span::styled(
                "● set",
                Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("○ not set", Style::new().dim())
        };
        let mut lines = vec![
            Line::raw(""),
            Line::from(vec![
                Span::styled(
                    "Templates at rest    ",
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                enc,
            ]),
            Line::from(vec![
                Span::styled(
                    "Recovery passphrase  ",
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                rec,
            ]),
            Line::raw(""),
            Line::from(Span::styled(
                "A recovery passphrase backs up the face-template key, the manual",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "backstop after a TPM clear, firmware/dbx update, or disk move.",
                Style::new().dim(),
            )),
            Line::raw(""),
        ];
        if !r.tpm_present {
            lines.push(Line::from(Span::styled(
                "No TPM on this host: templates stay plaintext; recovery N/A.",
                Style::new().fg(th().err),
            )));
        } else if r.encrypted && !r.recovery_set {
            lines.push(Line::from(Span::styled(
                "⚠ No backstop: set one now, or a broken seal means re-enrolling.",
                Style::new().fg(th().err),
            )));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "  [s] set passphrase   [t] restore from passphrase   [f] forget",
            Style::new().dim(),
        )));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
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
        let tpm = crate::tpm_device().is_some();
        let mut lines = vec![
            section("TPM keyring unlock"),
            Line::from(vec![Span::raw("  state    "), status]),
        ];
        if self.keyring_drift == Some(true) {
            lines.push(Line::from(vec![
                Span::raw("  PCRs     "),
                Span::styled(
                    "drifted since sealing; re-arm to rebind",
                    Style::new().fg(th().warn),
                ),
            ]));
        }
        // Show the envelope's actual policy tier when the daemon reports it;
        // the static text is the pre-KeyringInfo default (and what a fresh
        // arm lands on when neither Tier 1 nor Tier 2 exists on this box).
        let binding = self
            .keyring_policy
            .clone()
            .unwrap_or_else(|| "PCR-7 (Secure Boot state)".to_string());
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
                "  At a face login the daemon unseals your password and hands it to",
                Style::new().dim(),
            )));
            lines.push(Line::from(Span::styled(
                "  pam_kwallet/gnome-keyring, so your wallet opens with no prompt.",
                Style::new().dim(),
            )));
        } else if self.fp_present {
            lines.push(Line::from(Span::styled(
                "  At a fingerprint login the daemon unseals your password (ADR-0003)",
                Style::new().dim(),
            )));
            lines.push(Line::from(Span::styled(
                "  and hands it to gnome-keyring, so your wallet opens with no prompt.",
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
                    "  after a firmware/Secure Boot update, re-run `systemd-pcrlock",
                    Style::new().dim(),
                )));
                lines.push(Line::from(Span::styled(
                    "  make-policy` as root; the seal keeps working with no re-arm.",
                    Style::new().dim(),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "  ⚠ if a firmware/dbx update moves the bound PCRs, unseal fails →",
                    Style::new().fg(th().warn),
                )));
                lines.push(Line::from(Span::styled(
                    "    use the Repair tab or `irlume reseal` to re-bind to current PCRs.",
                    Style::new().dim(),
                )));
            }
        } else {
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
        lines.push(Line::from(vec![
            Span::styled("  [a]", Style::new().fg(th().accent)),
            Span::styled(" arm (enter your login password)   ", Style::new().dim()),
            Span::styled("[f]", Style::new().fg(th().accent)),
            Span::styled(" forget", Style::new().dim()),
        ]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    /// Hub rows for the Welcome screen: each visible section with its live
    /// state, selectable and Enter-jumpable (hub-and-spoke: the summary IS
    /// the navigation, the tab ribbon stays for direct access).
    fn hub_rows(&self) -> Vec<(&'static str, bool, usize)> {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        let rec = self.recovery.unwrap_or_default();
        let all: [(&'static str, bool, usize); 7] = [
            ("daemon + checks", self.daemon_up, SC_REPAIR),
            ("cameras", self.caps.rgb, SC_CAMERAS),
            ("enrollment", scans > 0, SC_PROFILES),
            (
                "keyring unlock",
                self.keyring_armed.unwrap_or(false),
                SC_KEYRING,
            ),
            (
                "recovery + encryption",
                rec.encrypted && rec.recovery_set,
                SC_RECOVERY,
            ),
            ("login wiring", crate::pamwire::login_wired(), SC_PAM),
            ("settings", true, SC_SETTINGS),
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
                count_badge(self.profiles.len(), scans)
            } else {
                onoff(ok)
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
    /// self-test. Mirrors `irlume doctor` + `diag` + `deps` and adds remediation.
    fn draw_repair(&self, f: &mut Frame, area: Rect) {
        use irlume_common::secureboot;
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
        let sb = if secureboot::is_secure_boot_enabled() {
            ("enabled", th().ok)
        } else if secureboot::is_setup_mode() {
            ("setup mode", th().warn)
        } else if secureboot::secure_boot_present() {
            ("disabled", th().warn)
        } else {
            ("n/a", th().warn)
        };
        let mut lines = vec![Line::from(vec![
            Span::styled(format!("  {ok} ok"), Style::new().fg(th().ok)),
            Span::styled(format!("   {warn} warn"), Style::new().fg(th().warn)),
            Span::styled(format!("   {fail} fail"), Style::new().fg(th().err)),
            Span::styled(
                "      [f] fix selected   [r] re-check   [l] IR self-test   [g] logs",
                Style::new().dim(),
            ),
        ])];
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
                    if crate::tpm_device().is_some() {
                        "✓"
                    } else {
                        "✗"
                    }
                ),
                Style::new(),
            ),
            Span::styled(format!("Secure Boot {} · ", sb.0), Style::new().fg(sb.1)),
            Span::styled(
                secureboot::detect_boot_mode().as_str().to_string(),
                Style::new().dim(),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  PCR policy ", Style::new().dim()),
            Span::styled(
                if irlume_core::pcrsig::signed_policy_available() {
                    "signed (PCR-11)"
                } else {
                    "literal PCR-7"
                }
                .to_string(),
                Style::new().dim(),
            ),
        ]));
        match &self.selftest_result {
            Some((ok, d)) => lines.push(Line::from(vec![
                Span::styled("  IR test   ", Style::new().dim()),
                Span::styled(
                    d.clone(),
                    Style::new().fg(if *ok { th().ok } else { th().err }),
                ),
            ])),
            None => lines.push(Line::from(Span::styled(
                "  IR test    press [l] to run the IR PAD self-test (look at the camera)",
                Style::new().dim(),
            ))),
        }
        let blk = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().dim())
            .title(" diagnosis ");
        f.render_widget(
            Paragraph::new(lines).block(blk).wrap(Wrap { trim: true }),
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
                lines.push(Line::from(Span::styled(
                    "  ┌─ result ───────────────────────────",
                    Style::new().dim(),
                )));
                lines.push(Line::from(vec![
                    Span::styled("  │ ", Style::new().dim()),
                    Span::styled(
                        who.clone(),
                        Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(Span::styled(
                    "  └────────────────────────────────────",
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
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_pam(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![section("PAM services (face auth wiring)")];
        // Inline per-service status, same data as `irlume login status`.
        for (label, present, wired) in crate::pamwire::status_report() {
            let val = if !present {
                Span::styled("(not present)", Style::new().dim())
            } else if wired {
                Span::styled(
                    "● wired",
                    Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("○ not wired", Style::new().dim())
            };
            lines.push(Line::from(vec![Span::raw(format!("  {label:<16}")), val]));
        }
        // LSM row is distro-aware: SELinux (Fedora-family), AppArmor
        // (Debian/Ubuntu-family), or nothing (e.g. Arch default); showing a
        // SELinux row on a non-SELinux system reads as a fault that isn't one.
        if std::path::Path::new("/sys/fs/selinux").exists() {
            let sel = match crate::pamwire::selinux_state() {
                Some(true) => Span::styled("● loaded", Style::new().fg(th().ok)),
                Some(false) => Span::styled("✗ not loaded", Style::new().fg(th().err)),
                None => Span::styled("unknown (needs root)", Style::new().dim()),
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {:<16}", "SELinux module")),
                sel,
            ]));
        } else if std::path::Path::new("/sys/kernel/security/apparmor").exists() {
            let profiled = std::fs::read_to_string("/proc/self/attr/apparmor/current")
                .map(|s| s.contains("irlume"))
                .unwrap_or(false)
                || std::path::Path::new("/etc/apparmor.d/usr.local.bin.irlumed").exists();
            lines.push(Line::from(vec![
                Span::raw(format!("  {:<16}", "AppArmor")),
                if profiled {
                    Span::styled("● irlume profile installed", Style::new().fg(th().ok))
                } else {
                    Span::styled(
                        "active; irlume unconfined (profile optional)",
                        Style::new().dim(),
                    )
                },
            ]));
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
        lines.push(Line::from(vec![
            Span::styled("  [w]", Style::new().fg(th().accent)),
            Span::styled(
                " wire the login stack now (runs sudo irlume login enable --apply)",
                Style::new(),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            "  empty password + Enter fires face (greeter login = IR/secure tier; RGB-only = lock screen only)",
            Style::new().dim(),
        )));
        lines.push(Line::from(vec![
            Span::styled("  face-sudo ", Style::new()),
            Span::styled("[u]", Style::new().fg(th().accent)),
            Span::styled(
                " wire it (opt-in, not part of [w]; face approves sudo prompts)",
                Style::new().dim(),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  app prompts ", Style::new()),
            Span::styled("[p]", Style::new().fg(th().accent)),
            Span::styled(
                " wire them (opt-in; face approves Bitwarden/pkexec)",
                Style::new().dim(),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            "    an app prompt needs a deliberate NOD to approve (no calibration); or an eye",
            Style::new().dim(),
        )));
        lines.push(Line::from(Span::styled(
            "    closure, taught once with [c].  See docs/APP-INTEGRATION.md",
            Style::new().dim(),
        )));
        // Bitwarden app-unlock row: only rendered when Bitwarden is installed
        // (invisible for everyone else), and never acts on its own — [b] is
        // the user's explicit opt-in.
        match crate::bitwarden::tui_state() {
            None => {}
            Some(crate::bitwarden::TuiState::Ready) => lines.push(Line::from(vec![
                Span::styled("  Bitwarden ", Style::new()),
                Span::styled("● polkit action installed", Style::new().fg(th().ok)),
                Span::styled(
                    "  (enable \"unlock with system authentication\" in its settings)",
                    Style::new().dim(),
                ),
            ])),
            Some(crate::bitwarden::TuiState::SnapMissing) => lines.push(Line::from(vec![
                Span::styled("  Bitwarden ", Style::new()),
                Span::styled("○ snap action missing", Style::new().fg(th().warn)),
                Span::styled(
                    "  fix: sudo snap connect bitwarden:polkit",
                    Style::new().dim(),
                ),
            ])),
            Some(crate::bitwarden::TuiState::NeedsSetup) => lines.push(Line::from(vec![
                Span::styled("  Bitwarden ", Style::new()),
                Span::styled("○ biometric unlock not set up", Style::new().fg(th().warn)),
                Span::styled("  [b]", Style::new().fg(th().accent)),
                Span::styled(" set it up (sudo; optional)", Style::new().dim()),
            ])),
        }
        lines.push(Line::from(vec![
            Span::styled("  disable ", Style::new()),
            Span::styled("[x]", Style::new().fg(th().accent)),
            Span::styled(
                " un-wires face auth everywhere (confirmed first)",
                Style::new().dim(),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  [s]", Style::new().fg(th().accent)),
            Span::styled(" open full status in a console view", Style::new().dim()),
        ]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_done(&self, f: &mut Frame, area: Rect) {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        let rec = self.recovery.unwrap_or_default();
        let wired = crate::pamwire::login_wired();
        let lines = vec![
            Line::from(Span::styled(
                "  Setup dashboard",
                Style::new().fg(th().accent).add_modifier(Modifier::BOLD),
            )),
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
                count_badge(self.profiles.len(), scans),
            ]),
            Line::from(vec![
                Span::raw("  eyes-open gate    "),
                onoff(self.eyes_open),
            ]),
            Line::from(vec![
                Span::raw("  blink challenge   "),
                onoff(self.challenge),
            ]),
            Line::from(vec![
                Span::raw("  keyring unlock    "),
                onoff(self.keyring_armed.unwrap_or(false)),
            ]),
            Line::from(vec![
                Span::raw("  templates enc     "),
                onoff(rec.encrypted),
            ]),
            Line::from(vec![
                Span::raw("  recovery pass     "),
                onoff(rec.recovery_set),
            ]),
            Line::from(vec![
                Span::raw("  biopolicy         "),
                onoff(biopolicy_on()),
            ]),
            Line::from(vec![
                Span::raw("  fingerprint       "),
                onoff(self.fp.available),
            ]),
            Line::from(vec![Span::raw("  login wiring      "), onoff(wired)]),
            Line::raw(""),
            Line::from(Span::styled(
                if !self.daemon_up {
                    "  Daemon not running; see the Repair tab before quitting."
                } else if self.profiles.is_empty() && self.caps.rgb {
                    "  Not set up yet; enroll a face (Welcome [e]) to begin."
                } else if self.profiles.is_empty() {
                    "  No face hardware; fingerprint/password remain your methods."
                } else if !wired {
                    "  One step left: your login screen isn't wired yet; press [w] (sudo; password stays the fallback)."
                } else {
                    "  All set. irlume keeps running as a daemon; this panel is safe to quit."
                },
                Style::new().dim(),
            )),
            if !self.profiles.is_empty() && !wired {
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
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
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
    /// the first three, the [?] overlay shows them all.
    fn screen_actions(&self) -> &'static [(&'static str, &'static str)] {
        match self.screen {
            SC_WELCOME => &[
                ("e", "enroll"),
                ("i", "identify"),
                ("r", "refresh"),
                ("U", "uninstall"),
            ],
            SC_REPAIR => &[
                ("f", "fix"),
                ("r", "re-check"),
                ("l", "IR test"),
                ("g", "logs"),
                ("t", "debug logs"),
            ],
            SC_CAMERAS => &[("enter", "use"), ("s", "setup emitter"), ("p", "probe")],
            SC_PROFILES => &[
                ("e", "enroll"),
                ("a", "add scan"),
                ("r", "rename"),
                ("d", "delete"),
            ],
            SC_IDENTIFY => &[("i", "identify")],
            SC_KEYRING => &[("a", "arm"), ("f", "forget")],
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
                ("enter", "toggle eyes-open"),
                ("c", "toggle blink"),
                ("m", "3rd-party model"),
            ],
            SC_DONE => &[("w", "wire login"), ("u", "update"), ("r", "refresh")],
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
                Span::styled(" cancel · working…", Style::new().dim()),
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
            "Global\n  Tab / \u{2190}\u{2192}  switch tab      \u{2191}\u{2193}  select\n               v  basic/all tabs       PgUp/Dn  activity log\n               M  release mouse (highlight/copy)   q  quit\n\nThis screen\n",
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
        let h = (lines + 2).clamp(3, area.height);
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

/// "N profile(s), M scan(s)" or a dim "none".
fn count_badge(profiles: usize, scans: usize) -> Span<'static> {
    if profiles == 0 {
        Span::styled("○ none", Style::new().dim())
    } else {
        Span::styled(
            format!("● {profiles} profile(s), {scans} scan(s)"),
            Style::new().fg(th().ok).add_modifier(Modifier::BOLD),
        )
    }
}

/// Is opt-in biopolicy enforcement enabled (settings.conf)?
fn biopolicy_on() -> bool {
    irlume_common::config::read_kv("settings.conf", "enforce_biopolicy")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

// ---- async response mappers (Response -> (ok, message)) -------------------

fn map_ok(resp: Response) -> (bool, String) {
    match resp {
        Response::Ok(m) => (true, m),
        Response::Error(e) => (false, e),
        o => (false, format!("unexpected: {o:?}")),
    }
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
            format!("{u} · {} · score {score:.3}", profile.unwrap_or_default()),
        ),
        Response::Identified {
            user: None,
            live,
            reason,
            ..
        } => (
            false,
            if live {
                format!("live face, no enrolled match ({reason})")
            } else {
                format!("no live face ({reason})")
            },
        ),
        Response::Error(e) => (false, e),
        o => (false, format!("unexpected: {o:?}")),
    }
}

fn map_selftest(resp: Response) -> (bool, String) {
    match resp {
        Response::SelfTest { passed, detail } => (passed, detail),
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
            "sealed login password erased; keyring unlock disarmed".into(),
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
    for i in 0..target {
        // Retry this scan until it's captured while well-framed: a drift during
        // the 3-2-1 aborts the countdown and re-frames instead of firing capture.
        'scan: loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            // Framing loop: wait for a well-framed streak.
            let mut streak = 0u32;
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                match crate::daemon_request(&Request::PositionSample {
                    user: Some(user.clone()),
                }) {
                    Ok(Response::Position(r)) => {
                        let good = r.well_framed;
                        if !send(WMsg::Cue(r)) {
                            return;
                        }
                        streak = if good { streak + 1 } else { 0 };
                        if streak >= GOOD_STREAK {
                            break;
                        }
                    }
                    Ok(Response::Error(e)) => {
                        let _ = send(WMsg::Err(e));
                        return;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        let _ = send(WMsg::Err(e));
                        return;
                    }
                }
            }
            // 3-2-1 countdown: re-verify framing at each beat (the poll lands
            // just before the next beat / the capture). Drift off-angle aborts.
            for c in (1..=3).rev() {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                if !send(WMsg::Count(c)) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(650));
                match crate::daemon_request(&Request::PositionSample {
                    user: Some(user.clone()),
                }) {
                    // Still framed: keep counting (don't send a Cue; that would
                    // clear the on-screen count). Only surface a cue on abort.
                    Ok(Response::Position(r)) if r.well_framed => {}
                    Ok(Response::Position(r)) => {
                        let _ = send(WMsg::Cue(r));
                        continue 'scan;
                    }
                    Ok(Response::Error(e)) => {
                        let _ = send(WMsg::Err(e));
                        return;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        let _ = send(WMsg::Err(e));
                        return;
                    }
                }
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
                    total,
                    added_scans,
                    ..
                }) => {
                    let _ = send(WMsg::MergePrompt {
                        profile: resolved,
                        total,
                        added_scans,
                    });
                    return;
                }
                // A brand-new profile (created) or an AddScan success.
                Ok(Response::Enrolled { .. }) | Ok(Response::Ok(_)) => {
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
    let _ = send(WMsg::Done);
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

    /// A bare App for tests: no hardware probes, no daemon socket, no terminal.
    /// Mirrors `App::new()` but every probe-derived field is inert.
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
            challenge: false,
            keyring_armed: None,
            keyring_policy: None,
            keyring_drift: None,
            nodes: Vec::new(),
            pairs: Vec::new(),
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
            selftest_result: None,
            repair: Vec::new(),
            repair_sel: 0,
            cam_sel: 0,
            error: None,
            daemon_up: false,
            enroll_error: None,
            health: None,
            act_scroll: 0,
            visible: App::compute_visible(&caps, VisibilityInputs::default(), &[]),
            advanced: false,
            caps,
            fp_present: false,
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
                captured: 0,
                target,
                base,
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

    /// Render the full frame at 120x50 and return the flattened text.
    fn draw_text(app: &App) -> String {
        let mut term = Terminal::new(TestBackend::new(120, 50)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        rendered(&term)
    }

    fn profile(name: &str, scans: &[&str]) -> ProfileSummary {
        ProfileSummary {
            name: name.into(),
            scans: scans.iter().map(|s| s.to_string()).collect(),
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
            require_challenge: false,
            closure_calibrated: false,
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

        // The mouse toggle flips state and logs; second press restores.
        assert!(!app.mouse_select);
        app.on_key(KeyCode::Char('M'));
        assert!(app.mouse_select);
        app.on_key(KeyCode::Char('M'));
        assert!(!app.mouse_select);
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
    fn refresh_rederives_hardware_capabilities() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRLUME_SOCKET", "/nonexistent/irlume-test.sock");
        let impossible = irlume_camera::Caps {
            ir_pair: true,
            rgb: false,
        };
        let mut app = test_app();
        app.caps = impossible;
        app.refresh();
        std::env::remove_var("IRLUME_SOCKET");
        assert_ne!(
            app.caps, impossible,
            "refresh() left the startup capability snapshot in place"
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
        let mut app = test_app();
        app.daemon_up = true;
        app.health = Some(HealthInfo {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: "test".into(),
        });
        let start = std::time::Instant::now();
        app.refresh_light();
        std::env::remove_var("IRLUME_SOCKET");
        let _ = std::fs::remove_file(&sock);
        assert!(
            !app.daemon_up,
            "an unanswered Ping means the daemon is down"
        );
        assert!(app.health.is_none(), "stale health must be cleared");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "only the Ping probe may touch a wedged daemon; the rest must be skipped"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the status poll must fail fast, not sit through full read budgets"
        );
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
        assert_eq!(msg, "alice · Face Profile 1 · score 0.812");
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
    fn map_selftest_passes_through_verdict() {
        assert_eq!(
            map_selftest(Response::SelfTest {
                passed: true,
                detail: "depth 0.7".into()
            }),
            (true, "depth 0.7".into())
        );
        assert_eq!(
            map_selftest(Response::SelfTest {
                passed: false,
                detail: "too flat".into()
            }),
            (false, "too flat".into())
        );
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
            vec![SC_WELCOME, SC_PAM, SC_DONE]
        );
        // RGB-only adds the face path (Profiles + Recovery), not Keyring.
        assert_eq!(
            App::compute_visible(&rgb, basic, &[]),
            vec![SC_WELCOME, SC_PROFILES, SC_RECOVERY, SC_PAM, SC_DONE]
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
            vec![SC_WELCOME, SC_KEYRING, SC_FINGERPRINT, SC_PAM, SC_DONE]
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
            vec![SC_WELCOME, SC_REPAIR, SC_PAM, SC_DONE]
        );
        // …or when any check fails, but not for a mere warning.
        let fail = [check_row("x", Sev::Fail, Fix::None)];
        assert!(App::compute_visible(&none, basic, &fail).contains(&SC_REPAIR));
        let warn = [check_row("x", Sev::Warn, Fix::None)];
        assert!(!App::compute_visible(&none, basic, &warn).contains(&SC_REPAIR));
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
        app.screen = SC_SETTINGS;
        app.advanced = false;
        app.recompute_visible();
        assert_eq!(
            app.screen, SC_PAM,
            "leaving advanced view must land on the nearest visible step"
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
            irlume_camera::CameraPair {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
                id: None,
                fixed: true,
            },
            irlume_camera::CameraPair {
                rgb: "/dev/video4".into(),
                ir: "/dev/video6".into(),
                id: None,
                fixed: false,
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
        app.pairs = vec![irlume_camera::CameraPair {
            rgb: "/dev/video0".into(),
            ir: "/dev/video2".into(),
            id: Some("abcd:1234".into()),
            fixed: true,
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
        app.on_key(KeyCode::Char('p'));
        assert!(app.op.is_some(), "[p] starts the read-only emitter probe");
        wait_op_done(&mut app);
    }

    #[test]
    fn settings_enter_toggles_eyes_open_via_the_daemon() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        app.on_key(KeyCode::Enter);
        assert_eq!(
            app.op.as_ref().map(|o| o.label.as_str()),
            Some("toggle require-eyes-open")
        );
        wait_op_done(&mut app);
        assert!(
            app.error.is_some(),
            "a failed toggle must raise the error banner, not vanish"
        );
    }

    #[test]
    fn settings_c_toggles_blink_challenge_via_the_daemon() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_SETTINGS;
        app.on_key(KeyCode::Char('c'));
        assert_eq!(
            app.op.as_ref().map(|o| o.label.as_str()),
            Some("toggle require-challenge"),
            "[c] must fire the SetRequireChallenge toggle, not fall through"
        );
        wait_op_done(&mut app);
        assert!(
            app.error.is_some(),
            "a failed toggle must raise the error banner, not vanish"
        );
    }

    #[test]
    fn repair_ir_selftest_lands_on_the_card_without_the_error_modal() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.screen = SC_REPAIR;
        app.on_key(KeyCode::Char('l'));
        assert!(app.op.is_some());
        wait_op_done(&mut app);
        let (ok, _) = app
            .selftest_result
            .as_ref()
            .expect("the self-test verdict must land on the Repair card");
        assert!(!ok);
        assert!(
            app.error.is_none(),
            "a self-test miss is a card result, not an error modal"
        );
    }

    #[test]
    fn apply_fix_routes_every_fix_kind() {
        let mut app = test_app();
        app.repair = vec![
            check_row("ok", Sev::Ok, Fix::None),
            check_row("man", Sev::Warn, Fix::Manual("run `foo --bar`".into())),
            check_row("emitter", Sev::Warn, Fix::Root(RootFix::IrSetup)),
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
        assert!(matches!(suspended_by(&mut app, 2), Some(Suspend::IrSetup)));
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
        // Out of range: a no-op, not a panic.
        let before = app.activity.len();
        app.apply_fix(99);
        assert_eq!(app.activity.len(), before);
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
        // 28 of 30 scans already on the profile: only 2 more fit the budget.
        tx.send(WMsg::MergePrompt {
            profile: "Alice".into(),
            total: 28,
            added_scans: vec!["scan28".into()],
        })
        .unwrap();
        app.poll();
        assert!(app.enroll.is_none(), "the worker hands off to the modal");
        let mc = app.enroll_merge.as_ref().expect("the merge modal is up");
        assert_eq!(mc.profile, "Alice");
        assert_eq!(
            mc.remaining, 2,
            "remaining = min(target-1, 30-scan budget left)"
        );
        // Below the budget the requested count minus the merged scan survives.
        let (tx, enroll) = fake_enroll(0, ENROLL_SCANS);
        app.enroll = Some(enroll);
        app.enroll_merge = None;
        tx.send(WMsg::MergePrompt {
            profile: "Alice".into(),
            total: 5,
            added_scans: vec!["scan5".into()],
        })
        .unwrap();
        app.poll();
        assert_eq!(
            app.enroll_merge.as_ref().unwrap().remaining,
            ENROLL_SCANS - 1
        );
    }

    #[test]
    fn merge_modal_renders_the_resolved_profile() {
        let mut app = test_app();
        app.enroll_merge = Some(MergeConfirm {
            profile: "Alice".into(),
            added_scans: vec!["s".into()],
            remaining: 4,
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
        tx.send(WMsg::Done).unwrap();
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
        assert!(
            text.contains("New here? Press [e]"),
            "the Welcome hint line is missing"
        );
        assert!(text.contains("step 1/"), "the wizard position is missing");
        // No-camera tier: the recommendation flips to password-only.
        let app2 = test_app();
        let text = draw_text(&app2);
        assert!(text.contains("Password only"), "got no fallback tier");
    }

    #[test]
    fn profiles_screen_renders_empty_state_and_scan_tree() {
        let mut app = test_app();
        app.screen = SC_PROFILES;
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
            text.contains("systemd-pcrlock"),
            "Tier 2 gets the make-policy guidance, not the re-arm warning"
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
            recovery_set: false,
            tpm_present: false,
        });
        let text = draw_text(&app);
        assert!(text.contains("○ plaintext at rest"));
        assert!(text.contains("No TPM on this host"));
        // Encrypted without a backstop: the warning line.
        app.recovery = Some(RecoveryInfo {
            encrypted: true,
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
        app.identify_result = Some((true, "alice · Face Profile 1 · score 0.912".into()));
        let text = draw_text(&app);
        assert!(text.contains("alice · Face Profile 1 · score 0.912"));
        assert!(
            text.contains("result"),
            "the hit renders in the result card"
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
        // The IR self-test card: idle prompt, then the verdict.
        assert!(text.contains("press [l] to run the IR PAD self-test"));
        app.selftest_result = Some((true, "PAD pass: depth 0.71".into()));
        let text = draw_text(&app);
        assert!(text.contains("PAD pass: depth 0.71"));
    }

    #[test]
    fn cameras_screen_renders_pairs_and_the_no_pair_fallbacks() {
        let mut app = test_app();
        app.screen = SC_CAMERAS;
        // No camera at all.
        let text = draw_text(&app);
        assert!(text.contains("no camera found"));
        // RGB node only: convenience tier, and why Secure needs IR.
        app.nodes = vec![("/dev/video9".into(), irlume_camera::Role::Rgb)];
        let text = draw_text(&app);
        assert!(text.contains("video9"));
        assert!(text.contains("RGB-only, convenience tier"));
        assert!(text.contains("no IR node"));
        // A real Hello pair renders its nodes, kind, and USB id.
        app.pairs = vec![irlume_camera::CameraPair {
            rgb: "/dev/video0".into(),
            ir: "/dev/video2".into(),
            id: Some("abcd:1234".into()),
            fixed: true,
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
        assert!(text.contains("wire the login stack now"));
        app.health = Some(HealthInfo {
            tier: "convenience".into(),
            rgb_dev: Some("/dev/video0".into()),
            ir_dev: None,
            mesh: false,
            adapter: false,
            version: "1.0".into(),
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
        assert!(text.contains("Biopolicy operation-class gate"));
        assert!(text.contains("Third-party liveness models"));
        assert!(text.contains("Match thresholds (read-only)"));
        app.eyes_open = true;
        let text = draw_text(&app);
        assert!(text.contains("● yes"), "the toggled state must show");
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
        let mut app = test_app(); // visible: Welcome, Login wiring, Done
        app.screen = SC_PAM;
        let text = draw_text(&app);
        assert!(
            text.contains("step 2/3: Login wiring"),
            "the step counter must track visible tabs, got:\n{text}"
        );
        assert!(text.contains("testuser"), "the managed user is shown");
    }

    #[test]
    fn footer_lists_each_screens_action_keys() {
        let app = test_app();
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
            (SC_CAMERAS, "use", "probe"),
            (SC_PROFILES, "enroll", "delete"),
            (SC_IDENTIFY, "identify", "identify"),
            (SC_KEYRING, "arm", "forget"),
            (SC_RECOVERY, "set", "forget"),
            (SC_FINGERPRINT, "enroll finger", "reset"),
            (SC_PAM, "wire login (sudo)", "un-wire"),
            (SC_SETTINGS, "toggle eyes-open", "3rd-party model"),
            (SC_DONE, "wire login", "refresh"),
        ];
        let mut app = app;
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
        let _sock = dead_socket();
        let mut app = test_app();
        app.profiles = vec![profile("a", &["s1"])]; // 2 rows
        app.sel = 9;
        app.cam_sel = 9;
        app.refresh_light();
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
        app.health = Some(HealthInfo {
            tier: "secure".into(),
            rgb_dev: Some("/dev/video0".into()),
            ir_dev: Some("/dev/video2".into()),
            mesh: true,
            adapter: true,
            version: env!("CARGO_PKG_VERSION").into(),
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
        assert!(
            app.repair.iter().any(|c| c.label == "IR emitter"),
            "an IR node earns the emitter fix row"
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
    fn run_checks_flags_version_skew_challenge_gap_and_corrupt_enrollment() {
        let _sock = dead_socket();
        let mut app = test_app();
        app.health = Some(HealthInfo {
            tier: "convenience".into(),
            rgb_dev: Some("/dev/video0".into()),
            ir_dev: None,
            mesh: false,
            adapter: false,
            version: "0.0.1-old".into(),
        });
        app.challenge = true;
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
        let blink = find("Blink challenge");
        assert!(blink.sev == Sev::Fail);
        assert!(blink.detail.contains("challenge is skipped"));
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
}
