//! `irlume tui` — keyboard-driven setup/management over the `irlumed` socket.
//!
//! Layout & feel follow linhello: a step-wizard (Tab/⇧Tab between steps, a
//! "step N/M" header), a blue Activity bar that shows in plain language exactly
//! what irlume is doing to the system (transparency, inspired by linutil), and a
//! static keybind footer. Enrollment uses linhello-style **guided cues** — a
//! live framing guide (quality + checklist + guidance) with a 3-2-1 countdown
//! and auto-capture — instead of a live video preview (which a terminal can't
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

const ACCENT: Color = Color::Rgb(0x6c, 0xb6, 0xff);
const BLUE: Color = Color::Rgb(0x4a, 0x90, 0xd9);
const OK: Color = Color::Rgb(0x73, 0xc9, 0x91);
const ERR: Color = Color::Rgb(0xe8, 0x7a, 0x7a);
const WARN: Color = Color::Rgb(0xe6, 0xc0, 0x7a);
const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SCREENS: [&str; 11] = [
    "Welcome", "Repair", "Cameras", "Profiles", "Identify",
    "Keyring", "Recovery", "Fingerprint", "Login wiring", "Settings", "Done",
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
const ENROLL_SCANS: usize = 3;
const GOOD_STREAK: u32 = 3;

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
    // over the socket — no sudo, no screen teardown). The `Option<String>` holds
    // the first entry while confirming (double-entry catches typos).
    KeyringPw(Option<String>),
    RecoveryPw(Option<String>),
    RecoveryRestorePw,
}

impl Pending {
    /// Password entries render masked.
    fn masked(&self) -> bool {
        matches!(self, Pending::KeyringPw(_) | Pending::RecoveryPw(_) | Pending::RecoveryRestorePw)
    }
}

/// Interactive flow that needs a cooked terminal — the TUI tears down the
/// alt-screen, runs it via the existing CLI handler (no-echo prompts), then
/// re-enters. Mirrors linhello's suspend pattern.
/// Flows that genuinely need the cooked terminal: an interactive root tool
/// (sudo) or fprintd's own prompts. Daemon password ops are handled in-TUI
/// instead (masked entry → socket), so they're not here.
#[derive(Clone, Copy)]
enum Suspend {
    FingerprintAdd,
    LoginStatus,
    RestartDaemon,
    SelinuxLoad,
}

/// Severity of a Repair-tab diagnostic.
#[derive(Clone, Copy, PartialEq)]
enum Sev { Ok, Warn, Fail }

/// What can be done about a failing/■warning check.
#[derive(Clone)]
enum Fix {
    /// Nothing actionable (informational / hardware).
    None,
    /// Show the user an exact command to run.
    Manual(String),
    /// Auto-fixable by the daemon (no root): an id dispatched in `apply_fix`.
    Daemon(&'static str),
    /// Needs root: suspend the TUI and run via sudo (`apply_fix` → Suspend).
    Root(&'static str),
}

/// One Repair-tab diagnostic row.
struct Check {
    label: String,
    sev: Sev,
    detail: String,
    fix: Fix,
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
}

struct EnrollUi {
    rx: mpsc::Receiver<WMsg>,
    stop: Arc<AtomicBool>,
    profile: String,
    last: Option<PositionReport>,
    count: Option<u8>,
    captured: usize,
    target: usize,
}

struct Op {
    label: String,
    tag: OpTag,
    rx: mpsc::Receiver<(bool, String)>,
}

struct App {
    user: String,
    screen: usize,
    sel: usize,
    profiles: Vec<ProfileSummary>,
    eyes_open: bool,
    keyring_armed: Option<bool>,
    nodes: Vec<(String, irlume_camera::Role)>,
    activity: Vec<(char, String)>,
    input: Option<(String, String, Pending)>,
    confirm: Option<(String, Request)>,
    op: Option<Op>,
    enroll: Option<EnrollUi>,
    fp: FpInfo,
    recovery: Option<RecoveryInfo>,
    suspend: Option<Suspend>,
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
    /// Live daemon reachability (a real Ping, refreshed each tick) — not a
    /// hardcoded socket-path check.
    daemon_up: bool,
    /// Activity panel scroll offset (lines up from the bottom; 0 = follow newest).
    act_scroll: usize,
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
    let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::EnableMouseCapture);
    let mut app = App::new();
    app.log('·', format!("irlume — managing '{}' (live)", app.user));
    app.refresh();
    let res = app.main_loop(&mut terminal);
    let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::DisableMouseCapture);
    ratatui::restore();
    res
}

impl App {
    fn new() -> Self {
        let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "user".into());
        Self {
            user, screen: 0, sel: 0, profiles: Vec::new(), eyes_open: false, keyring_armed: None,
            nodes: irlume_camera::discover_nodes(),
            activity: Vec::new(), input: None, confirm: None, op: None,
            enroll: None, fp: FpInfo::default(), recovery: None, suspend: None,
            identify_result: None, selftest_result: None,
            repair: Vec::new(), repair_sel: 0, cam_sel: 0, error: None, daemon_up: false, act_scroll: 0,
            spin: 0, quit: false,
        }
    }

    fn log(&mut self, g: char, m: impl Into<String>) {
        self.activity.push((g, m.into()));
        // If the user has scrolled up to read history, hold their view in place
        // as new lines arrive (instead of yanking them to the bottom).
        if self.act_scroll > 0 { self.act_scroll += 1; }
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

    fn request(&mut self, req: Request, action: &str) -> Option<Response> {
        self.log('→', format!("daemon: {action}"));
        match crate::daemon_request(&req) {
            Ok(Response::Error(e)) => { self.log('✗', e); None }
            Ok(r) => Some(r),
            Err(e) => { self.log('✗', e); None }
        }
    }

    /// CHEAP live poll (runs on the fast ~2.5s timer): daemon state + camera
    /// nodes only — all sub-millisecond, no subprocess spawns. Keeps the panel
    /// live without periodic UI hitches. SILENT (no Activity spam).
    fn refresh_light(&mut self) {
        self.daemon_up = matches!(crate::daemon_request(&Request::Ping), Ok(Response::Pong));
        if let Ok(Response::Enrollment { profiles, require_eyes_open }) =
            crate::daemon_request(&Request::ListProfiles { user: self.user.clone() })
        {
            self.profiles = profiles;
            self.eyes_open = require_eyes_open;
        }
        self.keyring_armed = match crate::daemon_request(&Request::HasSealedPassword { user: self.user.clone() }) {
            Ok(Response::HasPassword(b)) => Some(b),
            _ => self.keyring_armed,
        };
        if let Ok(Response::RecoveryStatus { encrypted, recovery_set, tpm_present }) =
            crate::daemon_request(&Request::RecoveryStatus { user: self.user.clone() })
        { self.recovery = Some(RecoveryInfo { encrypted, recovery_set, tpm_present }); }
        self.nodes = irlume_camera::discover_nodes();
        let max = self.rows().len().max(1);
        if self.sel >= max { self.sel = max - 1; }
        let pairs = irlume_camera::list_pairs().len().max(1);
        if self.cam_sel >= pairs { self.cam_sel = pairs - 1; }
    }

    /// FULL refresh = cheap poll + the heavier probes (fingerprint via fprintd,
    /// the Repair diagnostics which spawn `ls -Z` etc.). Runs on the slow timer,
    /// on demand ([r]), after an op, and when opening Repair/Fingerprint — but
    /// NOT every fast tick, so fprintd/subprocess calls can't hitch the UI.
    fn refresh(&mut self) {
        self.refresh_light();
        self.fp = FpInfo {
            available: irlume_fingerprint::available(),
            device: irlume_fingerprint::device_name(),
            enrolled: irlume_fingerprint::enrolled_fingers(&self.user),
            method: irlume_core::policy::method().as_str().to_string(),
        };
        self.run_checks();
    }

    /// Build the Repair-tab diagnostics from current state + quick local probes.
    fn run_checks(&mut self) {
        let mut v = Vec::new();
        let mk = |label: &str, sev, detail: String, fix| Check { label: label.into(), sev, detail, fix };

        let up = matches!(crate::daemon_request(&Request::Ping), Ok(Response::Pong));
        v.push(mk("Daemon (irlumed)", if up { Sev::Ok } else { Sev::Fail },
            if up { "running, socket reachable".into() } else { "not reachable on /run/irlume.sock".into() },
            if up { Fix::None } else { Fix::Root("restart-daemon") }));

        let ort = std::env::var("ORT_DYLIB_PATH").ok().filter(|p| std::path::Path::new(p).exists()).is_some()
            || ["/usr/lib64/libonnxruntime.so", "/usr/lib/libonnxruntime.so"].iter().any(|p| std::path::Path::new(p).exists());
        v.push(mk("ONNX Runtime", if ort { Sev::Ok } else { Sev::Fail },
            if ort { "library found".into() } else { "libonnxruntime.so not found".into() },
            if ort { Fix::None } else { Fix::Manual("install onnxruntime or set ORT_DYLIB_PATH".into()) }));

        let m1 = std::path::Path::new("models/glintr100.onnx").exists();
        let m2 = std::path::Path::new("models/face_detection_yunet_2023mar.onnx").exists();
        v.push(mk("Models", if m1 && m2 { Sev::Ok } else { Sev::Fail },
            if m1 && m2 { "YuNet + AuraFace present".into() } else { "missing model file(s) in models/".into() },
            if m1 && m2 { Fix::None } else { Fix::Manual("place glintr100.onnx + face_detection_yunet_2023mar.onnx in models/".into()) }));

        let rgb = self.nodes.iter().any(|(_, r)| matches!(r, irlume_camera::Role::Rgb));
        let ir = self.nodes.iter().any(|(_, r)| matches!(r, irlume_camera::Role::Ir));
        let priv_on = self.nodes.iter().any(|(p, _)| irlume_camera::privacy_engaged(p));
        let (csev, cdetail, cfix) = if !(rgb && ir) {
            (Sev::Fail, "need both an RGB and an IR node".to_string(), Fix::Manual("connect the camera / confirm an IR (Hello) module".into()))
        } else if priv_on {
            (Sev::Warn, "RGB+IR present, but a privacy switch is ON".to_string(), Fix::Manual("turn off the camera privacy switch".into()))
        } else {
            (Sev::Ok, "RGB + IR nodes present".to_string(), Fix::None)
        };
        v.push(mk("Cameras", csev, cdetail, cfix));

        v.push(mk("IR emitter", Sev::Warn,
            "if the IR feed is dark, auto-enable the 850nm illuminator".into(), Fix::Daemon("ir-emitter")));

        if std::fs::read_to_string("/sys/fs/selinux/enforce").map(|s| s.trim() == "1").unwrap_or(false) {
            let labeled = std::process::Command::new("ls").args(["-Z", "/run/irlume.sock"]).output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("irlume_runtime_t")).unwrap_or(false);
            v.push(mk("SELinux policy", if labeled { Sev::Ok } else { Sev::Fail },
                if labeled { "irlume module loaded (socket labeled)".into() } else { "module not loaded — greeter can't reach the daemon".into() },
                if labeled { Fix::None } else { Fix::Root("selinux-load") }));
        }

        let enrolled = !self.profiles.is_empty();
        v.push(mk("Enrollment", if enrolled { Sev::Ok } else { Sev::Warn },
            if enrolled { format!("{} profile(s) enrolled", self.profiles.len()) } else { "no face enrolled yet".into() },
            if enrolled { Fix::None } else { Fix::Manual("Profiles tab → [e] enroll".into()) }));

        if let Some(r) = self.recovery {
            if r.encrypted && !r.recovery_set {
                v.push(mk("Recovery backstop", Sev::Warn,
                    "templates encrypted but no recovery passphrase".into(),
                    Fix::Manual("run `irlume recovery setup`".into())));
            } else {
                v.push(mk("Recovery backstop", Sev::Ok,
                    if r.encrypted { "encrypted + recovery set".into() } else { "plaintext (no TPM / not encrypted)".into() },
                    Fix::None));
            }
        }

        self.repair = v;
        if self.repair_sel >= self.repair.len().max(1) { self.repair_sel = self.repair.len().saturating_sub(1); }
    }

    /// Apply the selected Repair check's fix: daemon fixes run in-place; root
    /// fixes suspend to a sudo prompt; manual fixes echo the command to Activity.
    fn apply_fix(&mut self, idx: usize) {
        let fix = match self.repair.get(idx) { Some(c) => c.fix.clone(), None => return };
        match fix {
            Fix::None => self.log('·', "nothing to fix on this row"),
            Fix::Manual(cmd) => self.log('·', format!("manual fix → {cmd}")),
            Fix::Daemon("ir-emitter") => self.start_op("SetupIrEmitter (auto-enable emitter)", Request::SetupIrEmitter { dry_run: false }),
            Fix::Daemon(_) => {}
            Fix::Root("restart-daemon") => { self.log('→', "sudo systemctl restart irlumed (you'll be asked for your password)"); self.suspend = Some(Suspend::RestartDaemon); }
            Fix::Root("selinux-load") => { self.log('→', "sudo irlume selinux load (you'll be asked for your password)"); self.suspend = Some(Suspend::SelinuxLoad); }
            Fix::Root(_) => {}
        }
    }

    fn rows(&self) -> Vec<Row> {
        let mut v = Vec::new();
        for (pi, p) in self.profiles.iter().enumerate() {
            v.push(Row::Profile(pi));
            for si in 0..p.scans.len() { v.push(Row::Scan(pi, si)); }
        }
        v
    }

    fn next_profile_name(&self) -> String {
        for n in 1..=MAX_PROFILES {
            let c = format!("Face Profile {n}");
            if !self.profiles.iter().any(|p| p.name == c) { return c; }
        }
        format!("Face Profile {}", self.profiles.len() + 1)
    }

    fn start_op(&mut self, label: impl Into<String>, req: Request) {
        self.start_async(label, OpTag::Generic, req, map_ok);
    }

    /// Run a daemon request on a worker thread, mapping its response to
    /// (ok, message) with `map`. Result is logged + routed by `tag` in `poll`.
    fn start_async(&mut self, label: impl Into<String>, tag: OpTag, req: Request, map: fn(Response) -> (bool, String)) {
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
        let (profile, target) = match &add {
            Some(name) => (name.clone(), 1),
            None => (self.next_profile_name(), ENROLL_SCANS),
        };
        let user = self.user.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let (st, pn, addc) = (stop.clone(), profile.clone(), add.clone());
        std::thread::spawn(move || enroll_worker(user, pn, addc, target, st, tx));
        self.log('→', format!("guided enroll → '{profile}' ({target} scan(s))"));
        self.enroll = Some(EnrollUi { rx, stop, profile, last: None, count: None, captured: 0, target });
    }

    fn poll(&mut self) {
        if let Some(op) = &self.op {
            if let Ok((ok, msg)) = op.rx.try_recv() {
                let tag = op.tag;
                if ok { self.log('✓', msg.clone()); } else { self.set_error(msg.clone()); }
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
            let mut msgs = Vec::new();
            while let Ok(m) = e.rx.try_recv() { msgs.push(m); }
            let mut finished = false;
            for m in msgs {
                match m {
                    WMsg::Cue(r) => { if let Some(e) = &mut self.enroll { e.last = Some(r); e.count = None; } }
                    WMsg::Count(c) => { if let Some(e) = &mut self.enroll { e.count = Some(c); } }
                    WMsg::Captured(n, t) => {
                        if let Some(e) = &mut self.enroll { e.captured = n; e.count = None; }
                        self.log('✓', format!("captured scan {n}/{t}"));
                    }
                    WMsg::Done => { self.log('✓', "enrollment complete"); finished = true; }
                    WMsg::Err(e) => {
                        let e = e.strip_prefix("hardware: ").unwrap_or(&e);
                        self.set_error(format!("Enrollment failed — {e}"));
                        finished = true;
                    }
                }
            }
            if finished { self.enroll = None; self.refresh(); }
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
                    Event::Key(k) if k.kind == KeyEventKind::Press => self.on_key(k.code),
                    // Mouse wheel scrolls the Activity history.
                    Event::Mouse(m) => match m.kind {
                        MouseEventKind::ScrollUp => self.act_scroll = (self.act_scroll + 1).min(self.act_max()),
                        MouseEventKind::ScrollDown => self.act_scroll = self.act_scroll.saturating_sub(1),
                        _ => {}
                    },
                    _ => {}
                }
            }
            self.spin = (self.spin + 1) % SPIN.len();
            self.poll();
            // Live auto-refresh, tiered so external changes appear on their own
            // without periodic subprocess hitches. Skip while the user is mid-flow.
            if self.op.is_none() && self.enroll.is_none() && self.input.is_none() && self.confirm.is_none() {
                if last_heavy.elapsed() >= Duration::from_millis(10_000) {
                    self.refresh(); // cheap + fingerprint + diagnostics
                    last_heavy = std::time::Instant::now();
                    last_light = std::time::Instant::now();
                } else if last_light.elapsed() >= Duration::from_millis(2500) {
                    self.refresh_light(); // daemon state + cameras only
                    last_light = std::time::Instant::now();
                }
            }
            // Interactive flows that need a cooked terminal: tear down, run, re-enter.
            if let Some(s) = self.suspend.take() {
                let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::DisableMouseCapture);
                ratatui::restore();
                self.run_suspended(s);
                *terminal = ratatui::init();
                let _ = ratatui::crossterm::execute!(std::io::stdout(), ratatui::crossterm::event::EnableMouseCapture);
                terminal.clear()?;
                self.refresh();
            }
        }
        if let Some(e) = &self.enroll { e.stop.store(true, Ordering::Relaxed); }
        Ok(())
    }

    /// Run an interactive sub-flow outside the alt-screen via the CLI handlers
    /// (no-echo passphrase / fprintd prompts), then wait for the user to return.
    fn run_suspended(&mut self, s: Suspend) {
        let none: [String; 0] = [];
        match s {
            Suspend::FingerprintAdd => { crate::fingerprint::run(Some("add"), &none); }
            Suspend::LoginStatus => { crate::pamwire::run(Some("status"), &none); }
            Suspend::RestartDaemon => {
                eprintln!("\nRestarting irlumed (sudo)…");
                let _ = std::process::Command::new("sudo").args(["systemctl", "restart", "irlumed"]).status();
            }
            Suspend::SelinuxLoad => {
                eprintln!("\nLoading the irlume SELinux module (sudo)…");
                let _ = std::process::Command::new("sudo").args(["irlume", "selinux", "load"]).status();
            }
        }
        eprint!("\nPress Enter to return to the TUI… ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }

    fn on_key(&mut self, code: KeyCode) {
        // Guided enroll: only Esc (cancel).
        if let Some(e) = &self.enroll {
            if matches!(code, KeyCode::Esc) {
                e.stop.store(true, Ordering::Relaxed);
                self.enroll = None;
                self.log('·', "enrollment cancelled");
            }
            return;
        }
        // A raised error banner swallows the next key (dismiss it).
        if self.error.is_some() { self.error = None; return; }
        if self.op.is_some() { return; }
        if let Some((_, buf, _)) = self.input.as_mut() {
            match code {
                KeyCode::Esc => self.input = None,
                KeyCode::Enter => self.submit_input(),
                KeyCode::Backspace => { buf.pop(); }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return;
        }
        if let Some((_, req)) = &self.confirm {
            if matches!(code, KeyCode::Char('y') | KeyCode::Char('Y')) {
                let req = req.clone();
                self.confirm = None;
                if let Some(Response::Ok(m)) = self.request(req, "(confirmed)") { self.log('✓', m); }
                self.refresh();
            } else { self.confirm = None; }
            return;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::Right => self.goto((self.screen + 1) % SCREENS.len()),
            KeyCode::BackTab | KeyCode::Left => self.goto((self.screen + SCREENS.len() - 1) % SCREENS.len()),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            // Activity panel history scroll (auto-follows newest when at bottom).
            KeyCode::PageUp => self.act_scroll = (self.act_scroll + 3).min(self.act_max()),
            KeyCode::PageDown => self.act_scroll = self.act_scroll.saturating_sub(3),
            KeyCode::Home => self.act_scroll = self.act_max(),
            KeyCode::End => self.act_scroll = 0,
            _ => self.on_action(code),
        }
    }

    fn act_max(&self) -> usize {
        self.activity.len().saturating_sub(ACT_H)
    }

    /// Switch tabs. Repair/Fingerprint pull their heavier probes immediately so
    /// the tab is fresh on open (the slow timer only refreshes them every ~10s).
    fn goto(&mut self, new: usize) {
        self.screen = new;
        self.sel = 0;
        if new == SC_REPAIR || new == SC_FINGERPRINT {
            self.refresh();
        }
    }

    fn move_sel(&mut self, d: i32) {
        let len = match self.screen {
            SC_REPAIR => self.repair.len(),
            SC_CAMERAS => irlume_camera::list_pairs().len(),
            _ => self.rows().len(),
        };
        let n = len.max(1) as i32;
        let cur = match self.screen {
            SC_REPAIR => &mut self.repair_sel,
            SC_CAMERAS => &mut self.cam_sel,
            _ => &mut self.sel,
        };
        *cur = (((*cur as i32 + d) % n + n) % n) as usize;
    }

    fn on_action(&mut self, code: KeyCode) {
        match (self.screen, code) {
            // Welcome / Done: refresh the whole snapshot.
            (SC_WELCOME, KeyCode::Char('r')) | (SC_DONE, KeyCode::Char('r')) => {
                self.log('·', "refreshing status…");
                self.refresh();
            }
            // Welcome quick-launch: jump to Profiles and start enrollment.
            (SC_WELCOME, KeyCode::Char('e')) => { self.screen = SC_PROFILES; self.begin_enroll(); }
            (SC_WELCOME, KeyCode::Char('i')) => { self.screen = SC_IDENTIFY; self.start_async("Identify (1:N)", OpTag::Identify, Request::Identify, map_identify); }
            // Cameras: switch the active pair (persisted via the daemon).
            (SC_CAMERAS, KeyCode::Enter) => {
                let pairs = irlume_camera::list_pairs();
                if let Some(p) = pairs.get(self.cam_sel) {
                    let (rgb, ir) = (p.rgb.clone(), p.ir.clone());
                    if self.request(Request::SetCameras { rgb: rgb.clone(), ir: ir.clone() }, "SetCameras").is_some() {
                        self.log('✓', format!("active camera → {rgb} + {ir}"));
                    }
                    self.refresh();
                }
            }
            // Repair: re-run checks, fix the selected issue, or run a live IR test.
            (SC_REPAIR, KeyCode::Char('r')) => { self.log('·', "re-running diagnostics…"); self.refresh(); }
            (SC_REPAIR, KeyCode::Char('f')) | (SC_REPAIR, KeyCode::Enter) => self.apply_fix(self.repair_sel),
            (SC_REPAIR, KeyCode::Char('l')) => self.start_async(
                "SelfTest (IR liveness)", OpTag::Calibrate,
                Request::SelfTest { kind: irlume_common::SelfTestKind::Liveness }, map_selftest),
            // Cameras: IR emitter auto-setup / probe.
            (SC_CAMERAS, KeyCode::Char('s')) => self.start_op("SetupIrEmitter (auto-enable emitter)", Request::SetupIrEmitter { dry_run: false }),
            (SC_CAMERAS, KeyCode::Char('p')) => {
                if let Some(Response::Ok(m)) = self.request(Request::SetupIrEmitter { dry_run: true }, "SetupIrEmitter(dry-run)") { self.log('✓', m); }
            }
            // Profiles.
            (SC_PROFILES, KeyCode::Char('e')) => self.begin_enroll(),
            (SC_PROFILES, KeyCode::Char('a')) => { if let Some(p) = self.sel_profile() { self.start_enroll(Some(p)); } }
            (SC_PROFILES, KeyCode::Char('r')) => self.begin_rename(),
            (SC_PROFILES, KeyCode::Char('d')) => self.begin_delete(),
            // Identify: 1:N who-is-this.
            (SC_IDENTIFY, KeyCode::Char('i')) => self.start_async(
                "Identify (1:N)", OpTag::Identify, Request::Identify, map_identify),
            // Keyring — masked in-TUI entry (goes to the root daemon; no sudo).
            (SC_KEYRING, KeyCode::Char('a')) => {
                self.input = Some(("Login password to seal (••):".into(), String::new(), Pending::KeyringPw(None)));
            }
            (SC_KEYRING, KeyCode::Char('f')) => {
                self.confirm = Some(("Erase the TPM-sealed login password?".into(), Request::ForgetPassword { user: self.user.clone() }));
            }
            // Recovery — masked in-TUI entry.
            (SC_RECOVERY, KeyCode::Char('s')) => {
                self.input = Some(("New recovery passphrase (••):".into(), String::new(), Pending::RecoveryPw(None)));
            }
            (SC_RECOVERY, KeyCode::Char('t')) => {
                self.input = Some(("Recovery passphrase to restore (••):".into(), String::new(), Pending::RecoveryRestorePw));
            }
            (SC_RECOVERY, KeyCode::Char('f')) => {
                self.confirm = Some(("Erase the recovery passphrase? (templates stay encrypted)".into(), Request::RecoveryForget { user: self.user.clone() }));
            }
            // Fingerprint.
            (SC_FINGERPRINT, KeyCode::Char('a')) => {
                if self.fp.available { self.suspend = Some(Suspend::FingerprintAdd); }
                else { self.log('✗', "no fingerprint reader detected"); }
            }
            // Login wiring (PAM): show status outside the alt-screen.
            (SC_PAM, KeyCode::Char('s')) => self.suspend = Some(Suspend::LoginStatus),
            // Settings.
            (SC_SETTINGS, KeyCode::Enter) | (SC_SETTINGS, KeyCode::Char(' ')) => {
                let on = !self.eyes_open;
                if self.request(Request::SetRequireEyesOpen { user: self.user.clone(), on }, &format!("SetRequireEyesOpen({on})")).is_some() {
                    self.log('✓', format!("require-eyes-open {}", if on { "ENABLED" } else { "disabled" }));
                }
                self.refresh();
            }
            _ => {}
        }
    }

    /// Start a new-profile enrollment (prompts for a name; blank = default).
    fn begin_enroll(&mut self) {
        if self.profiles.len() >= MAX_PROFILES {
            self.log('✗', format!("at the max {MAX_PROFILES} profiles — delete one first"));
        } else {
            self.input = Some(("New profile name (blank = default):".into(), String::new(), Pending::EnrollName));
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
                self.input = Some((format!("Rename profile '{name}' to:"), String::new(), Pending::RenameProfile(name)));
            }
            Some(Row::Scan(pi, si)) => {
                let (p, s) = (self.profiles[pi].name.clone(), self.profiles[pi].scans[si].clone());
                self.input = Some((format!("Rename scan '{s}' to:"), String::new(), Pending::RenameScan(p, s)));
            }
            None => {}
        }
    }

    fn begin_delete(&mut self) {
        match self.rows().get(self.sel).copied() {
            Some(Row::Profile(pi)) => {
                let p = self.profiles[pi].name.clone();
                self.confirm = Some((format!("Delete profile '{p}' and all its scans?"), Request::DeleteProfile { user: self.user.clone(), profile: p }));
            }
            Some(Row::Scan(pi, si)) => {
                let (p, s) = (self.profiles[pi].name.clone(), self.profiles[pi].scans[si].clone());
                self.confirm = Some((format!("Delete scan '{s}' from '{p}'?"), Request::DeleteScan { user: self.user.clone(), profile: p, scan: s }));
            }
            None => {}
        }
    }

    fn submit_input(&mut self) {
        let Some((_, buf, pending)) = self.input.take() else { return };
        let v = buf.trim().to_string();
        match pending {
            Pending::EnrollName => {
                if !v.is_empty() && self.profiles.iter().any(|p| p.name == v) {
                    self.log('✗', format!("a profile named '{v}' already exists"));
                    return;
                }
                // Always pass a concrete name so the worker can add scans to it.
                let name = if v.is_empty() { self.next_profile_name() } else { v };
                self.start_enroll_named(name);
            }
            Pending::RenameProfile(old) => self.rename(Request::RenameProfile { user: self.user.clone(), profile: old, new_name: v }),
            Pending::RenameScan(p, s) => self.rename(Request::RenameScan { user: self.user.clone(), profile: p, scan: s, new_name: v }),
            // Passwords: use the RAW buffer (never trim). Double-entry to confirm.
            Pending::KeyringPw(None) => {
                if buf.is_empty() { self.set_error("empty password — aborted (nothing sealed)"); return; }
                self.input = Some(("Confirm login password (••):".into(), String::new(), Pending::KeyringPw(Some(buf))));
            }
            Pending::KeyringPw(Some(first)) => {
                if buf != first { self.set_error("passwords don't match — aborted (nothing sealed)"); return; }
                let req = Request::SealPassword { user: self.user.clone(), password: irlume_common::SecretBytes::new(buf.into_bytes()) };
                match self.request(req, "SealPassword") {
                    Some(Response::PasswordSealed) => self.log('✓', "keyring armed — face login will open your wallet"),
                    Some(other) => self.set_error(format!("arm failed: {other:?}")),
                    None => {}
                }
                self.refresh();
            }
            Pending::RecoveryPw(None) => {
                if buf.is_empty() { self.set_error("empty passphrase — aborted"); return; }
                self.input = Some(("Confirm recovery passphrase (••):".into(), String::new(), Pending::RecoveryPw(Some(buf))));
            }
            Pending::RecoveryPw(Some(first)) => {
                if buf != first { self.set_error("passphrases don't match — aborted"); return; }
                let req = Request::RecoverySetup { user: self.user.clone(), passphrase: irlume_common::SecretBytes::new(buf.into_bytes()) };
                match self.request(req, "RecoverySetup") {
                    Some(Response::Ok(m)) => self.log('✓', m),
                    Some(other) => self.set_error(format!("recovery setup failed: {other:?}")),
                    None => {}
                }
                self.refresh();
            }
            Pending::RecoveryRestorePw => {
                if buf.is_empty() { self.set_error("empty passphrase — aborted"); return; }
                let req = Request::RecoveryRestore { user: self.user.clone(), passphrase: irlume_common::SecretBytes::new(buf.into_bytes()) };
                match self.request(req, "RecoveryRestore") {
                    Some(Response::Ok(m)) => self.log('✓', m),
                    Some(other) => self.set_error(format!("recovery restore failed: {other:?}")),
                    None => {}
                }
                self.refresh();
            }
        }
    }

    fn rename(&mut self, req: Request) {
        if let Some(Response::Ok(m)) = self.request(req, "Rename") { self.log('✓', m); }
        self.refresh();
    }

    /// New-profile guided enroll with an explicit name.
    fn start_enroll_named(&mut self, name: String) {
        let user = self.user.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let (st, pn) = (stop.clone(), name.clone());
        std::thread::spawn(move || enroll_worker(user, pn, None, ENROLL_SCANS, st, tx));
        self.log('→', format!("guided enroll → '{name}' ({ENROLL_SCANS} scans)"));
        self.enroll = Some(EnrollUi { rx, stop, profile: name, last: None, count: None, captured: 0, target: ENROLL_SCANS });
    }

    // ---- rendering --------------------------------------------------------

    fn draw(&self, f: &mut Frame) {
        let [header, body, activity, footer] = Layout::vertical([
            Constraint::Length(3), Constraint::Min(6), Constraint::Length(7), Constraint::Length(3),
        ]).areas(f.area());
        self.draw_header(f, header);
        self.draw_content(f, body);
        self.draw_activity(f, activity);
        self.draw_footer(f, footer);
        if let Some(err) = &self.error {
            self.error_modal(f, err);
        } else if let Some((prompt, buf, pending)) = &self.input {
            let shown = if pending.masked() { "•".repeat(buf.chars().count()) } else { buf.clone() };
            self.modal(f, prompt, &format!("{shown}▏"));
        } else if let Some((what, _)) = &self.confirm {
            self.modal(f, what, "[y] confirm    [any other key] cancel");
        }
    }

    /// A red, dismissible error banner centred on screen.
    fn error_modal(&self, f: &mut Frame, msg: &str) {
        let area = f.area();
        let w = area.width.saturating_sub(8).min(78).max(30);
        let h = 7u16;
        let rect = Rect { x: area.width.saturating_sub(w) / 2, y: area.height.saturating_sub(h) / 2, width: w, height: h };
        f.render_widget(Clear, rect);
        let blk = Block::bordered().title(" ⚠ Problem ").border_type(BorderType::Rounded)
            .border_style(Style::new().fg(ERR).add_modifier(Modifier::BOLD))
            .padding(ratatui::widgets::Padding::horizontal(1));
        let body = vec![
            Line::raw(""),
            Line::from(Span::styled(msg.to_string(), Style::new().fg(ERR))),
            Line::raw(""),
            Line::from(Span::styled("[any key] dismiss", Style::new().dim())),
        ];
        f.render_widget(Paragraph::new(body).block(blk).wrap(Wrap { trim: true }), rect);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let blk = Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().dim());
        let left = Line::from(vec![
            Span::styled(" irlume ", Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(format!("step {}/{}: ", self.screen + 1, SCREENS.len()), Style::new().dim()),
            Span::styled(SCREENS[self.screen], Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
        ]);
        let right = Line::from(Span::styled(format!("{} ", self.user), Style::new().dim())).right_aligned();
        f.render_widget(Paragraph::new(left).block(blk.clone()), area);
        f.render_widget(Paragraph::new(right).block(blk), area);
    }

    fn draw_content(&self, f: &mut Frame, area: Rect) {
        let blk = Block::bordered().title(format!(" {} ", SCREENS[self.screen]))
            .border_type(BorderType::Rounded).border_style(Style::new().fg(ACCENT))
            .padding(ratatui::widgets::Padding::horizontal(1));
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        if self.enroll.is_some() { self.draw_enroll(f, inner); return; }
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
        let chk = |ok: bool, label: &str| Line::from(vec![
            Span::styled(if ok { "  ✓ " } else { "  ○ " }, if ok { Style::new().fg(OK) } else { Style::new().dim() }),
            Span::styled(label.to_string(), if ok { Style::new() } else { Style::new().dim() }),
        ]);
        let face = r.map(|x| x.face).unwrap_or(false);
        let mut lines = vec![
            Line::from(Span::styled(format!("Enrolling '{}'  —  scan {}/{}", e.profile, e.captured, e.target), Style::new().add_modifier(Modifier::BOLD))),
            Line::raw(""),
            Line::from(vec![Span::raw("  Quality  "), Span::styled(quality_bar(q), Style::new().fg(if q >= 70 { OK } else { ACCENT }))]),
            Line::raw(""),
            chk(face, "Face detected"),
            chk(r.map(|x| x.centered).unwrap_or(false), "Centered in frame"),
            chk(r.map(|x| x.yaw_asym <= 0.40 && (0.20..=0.80).contains(&x.pitch_frac)).unwrap_or(false), "Facing the camera"),
            chk(r.map(|x| x.brightness >= 55.0 && x.brightness <= 235.0).unwrap_or(false), "Well lit"),
            Line::raw(""),
        ];
        if let Some(c) = e.count {
            lines.push(Line::from(Span::styled(format!("  ● Hold still — capturing in {c}…", ), Style::new().fg(OK).add_modifier(Modifier::BOLD))));
        } else {
            let g = r.map(|x| x.guidance.clone()).unwrap_or_else(|| "Starting camera…".into());
            lines.push(Line::from(vec![Span::styled("  → ", Style::new().fg(ACCENT)), Span::styled(g, Style::new().add_modifier(Modifier::BOLD))]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled("  [esc] cancel", Style::new().dim())));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_profiles(&self, f: &mut Frame, area: Rect) {
        if self.profiles.is_empty() {
            f.render_widget(Paragraph::new("\nNo face profiles yet.\n\nPress [e] to enroll — irlume will guide your framing and capture automatically.")
                .wrap(Wrap { trim: true }).dim(), area);
            return;
        }
        let rows = self.rows();
        let items: Vec<ListItem> = rows.iter().map(|r| match r {
            Row::Profile(pi) => {
                let p = &self.profiles[*pi];
                ListItem::new(Line::from(vec![
                    Span::styled(format!("● {}", p.name), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("   ({} scans)", p.scans.len()), Style::new().dim()),
                ]))
            }
            Row::Scan(pi, si) => ListItem::new(Line::from(Span::raw(format!("     ↳ {}", self.profiles[*pi].scans[*si])))),
        }).collect();
        let mut st = ListState::default().with_selected(Some(self.sel.min(rows.len().saturating_sub(1))));
        f.render_stateful_widget(List::new(items).highlight_style(Style::new().bg(Color::Rgb(0x20, 0x30, 0x40)).add_modifier(Modifier::BOLD)), area, &mut st);
    }

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let bio = biopolicy_on();
        f.render_widget(Paragraph::new(vec![
            section("Require eyes open"),
            Line::from(vec![Span::raw("  state  "), onoff(self.eyes_open)]),
            Line::from(Span::styled("  Never unlock unless both eyes read open (IR-glint heuristic).", Style::new().dim())),
            Line::from(vec![Span::styled("  [enter]", Style::new().fg(ACCENT)), Span::styled(" toggle", Style::new().dim())]),
            Line::raw(""),
            section("Biopolicy operation-class gate"),
            Line::from(vec![Span::raw("  state  "),
                if bio { Span::styled("● ENFORCING", Style::new().fg(OK).add_modifier(Modifier::BOLD)) } else { Span::styled("○ off (default)", Style::new().dim()) }]),
            Line::from(Span::styled("  When on: only Login/Elevation may release the keyring; lock-screen", Style::new().dim())),
            Line::from(Span::styled("  is verify-only; remote/unknown services are denied.", Style::new().dim())),
            Line::from(Span::styled("  Toggle (root): set enforce_biopolicy=1 in /etc/irlume/settings.conf.", Style::new().dim())),
            Line::raw(""),
            section("Match thresholds (read-only)"),
            Line::from(Span::styled("  RGB 0.55 · IR-adapted 0.40 · auto-scaled by enrolled scan count.", Style::new().dim())),
        ]).wrap(Wrap { trim: true }), area);
    }

    fn draw_cameras(&self, f: &mut Frame, area: Rect) {
        let [list_area, info_area] = Layout::vertical([Constraint::Min(3), Constraint::Length(8)]).areas(area);
        let (argb, air) = irlume_camera::select_pair(); // currently active pair
        let pairs = irlume_camera::list_pairs();

        // ---- selectable list of trusted (physical) Hello camera pairs ----
        let items: Vec<ListItem> = if pairs.is_empty() {
            vec![ListItem::new(Span::styled("no RGB+IR camera pair found", Style::new().fg(ERR)))]
        } else {
            pairs.iter().map(|p| {
                let active = p.rgb == argb && p.ir == air;
                let kind = if p.fixed { "built-in" } else { "external" };
                let id = p.id.clone().unwrap_or_else(|| "?".into());
                let priv_on = irlume_camera::privacy_engaged(&p.rgb) || irlume_camera::privacy_engaged(&p.ir);
                ListItem::new(Line::from(vec![
                    Span::styled(if active { " ● " } else { " ○ " }, Style::new().fg(if active { OK } else { Color::DarkGray })),
                    Span::styled(format!("{:<16}", format!("{}+{}", p.rgb.trim_start_matches("/dev/"), p.ir.trim_start_matches("/dev/"))),
                        if active { Style::new().add_modifier(Modifier::BOLD) } else { Style::new() }),
                    Span::styled(format!("{kind:<10}"), Style::new().fg(ACCENT)),
                    Span::styled(format!("[{id}]"), Style::new().dim()),
                    if priv_on { Span::styled("  ⚠ privacy ON", Style::new().fg(ERR)) } else { Span::raw("") },
                ]))
            }).collect()
        };
        let mut st = ListState::default().with_selected(Some(self.cam_sel.min(pairs.len().saturating_sub(1))));
        let blk = Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().dim())
            .title(" cameras (● = active · ↑↓ select · enter = use) ");
        let inner = blk.inner(list_area);
        f.render_widget(blk, list_area);
        f.render_stateful_widget(
            List::new(items).highlight_style(Style::new().bg(Color::Rgb(0x20, 0x30, 0x40)).add_modifier(Modifier::BOLD)),
            inner, &mut st);

        // ---- info: active pair, selected pair nodes, emitter ----
        let mut lines = vec![
            Line::from(vec![Span::styled("  active   ", Style::new().dim()),
                Span::styled(format!("{argb} + {air}"), Style::new().fg(OK).add_modifier(Modifier::BOLD))]),
        ];
        if let Some(p) = pairs.get(self.cam_sel) {
            if p.rgb != argb || p.ir != air {
                lines.push(Line::from(vec![Span::styled("  selected ", Style::new().dim()),
                    Span::styled(format!("{} + {}", p.rgb, p.ir), Style::new()),
                    Span::styled("   [enter] to switch", Style::new().fg(ACCENT))]));
            }
        }
        lines.push(Line::raw(""));
        lines.push(section("IR emitter (850nm)"));
        lines.push(Line::from(Span::styled("  If the IR feed is dark irlume probes the UVC controls and enables", Style::new().dim())));
        lines.push(Line::from(Span::styled("  the illuminator automatically (no phone-camera step).", Style::new().dim())));
        lines.push(Line::from(vec![
            Span::styled("  [s]", Style::new().fg(ACCENT)), Span::styled(" auto-setup emitter   ", Style::new().dim()),
            Span::styled("[p]", Style::new().fg(ACCENT)), Span::styled(" probe XU controls", Style::new().dim()),
        ]));
        let iblk = Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().dim());
        f.render_widget(Paragraph::new(lines).block(iblk).wrap(Wrap { trim: true }), info_area);
    }

    fn draw_fingerprint(&self, f: &mut Frame, area: Rect) {
        let reader = match (&self.fp.device, self.fp.available) {
            (Some(n), _) => Span::styled(format!("● {n}"), Style::new().fg(OK)),
            (None, true) => Span::styled("● present (unnamed)", Style::new().fg(OK)),
            (None, false) => Span::styled("○ none detected", Style::new().dim()),
        };
        let enrolled = if self.fp.enrolled.is_empty() {
            Span::styled("none".to_string(), Style::new().dim())
        } else {
            Span::styled(format!("{} ({})", self.fp.enrolled.len(), self.fp.enrolled.join(", ")), Style::new().fg(OK))
        };
        let mut lines = vec![
            Line::raw(""),
            Line::from(vec![Span::styled("Reader        ", Style::new().add_modifier(Modifier::BOLD)), reader]),
            Line::from(vec![Span::styled("Enrolled      ", Style::new().add_modifier(Modifier::BOLD)), enrolled]),
            Line::from(vec![Span::styled("Active method ", Style::new().add_modifier(Modifier::BOLD)), Span::raw(self.fp.method.clone())]),
            Line::raw(""),
        ];
        if self.fp.available {
            lines.push(Line::from(Span::styled("Fingerprint is a companion factor via stock fprintd + pam_fprintd.", Style::new().dim())));
            lines.push(Line::from(Span::styled("  [a] enroll a finger (interactive).  To make it the unlock method:", Style::new().dim())));
            lines.push(Line::from(Span::styled("  sudo irlume fingerprint enable", Style::new().fg(ACCENT))));
        } else {
            lines.push(Line::from(Span::styled("No usable reader on this device — fingerprint unavailable.", Style::new().dim())));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_recovery(&self, f: &mut Frame, area: Rect) {
        let r = self.recovery.unwrap_or_default();
        let enc = if r.encrypted { Span::styled("● encrypted", Style::new().fg(OK).add_modifier(Modifier::BOLD)) }
                  else { Span::styled("○ plaintext at rest", Style::new().dim()) };
        let rec = if r.recovery_set { Span::styled("● set", Style::new().fg(OK).add_modifier(Modifier::BOLD)) }
                  else { Span::styled("○ not set", Style::new().dim()) };
        let mut lines = vec![
            Line::raw(""),
            Line::from(vec![Span::styled("Templates at rest    ", Style::new().add_modifier(Modifier::BOLD)), enc]),
            Line::from(vec![Span::styled("Recovery passphrase  ", Style::new().add_modifier(Modifier::BOLD)), rec]),
            Line::raw(""),
            Line::from(Span::styled("A recovery passphrase backs up the face-template key — the manual", Style::new().dim())),
            Line::from(Span::styled("backstop after a TPM clear, firmware/dbx update, or disk move.", Style::new().dim())),
            Line::raw(""),
        ];
        if !r.tpm_present {
            lines.push(Line::from(Span::styled("No TPM on this host — templates stay plaintext; recovery N/A.", Style::new().fg(ERR))));
        } else if r.encrypted && !r.recovery_set {
            lines.push(Line::from(Span::styled("⚠ No backstop: set one now, or a broken seal means re-enrolling.", Style::new().fg(ERR))));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled("  [s] set passphrase   [t] restore from passphrase   [f] forget", Style::new().dim())));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_keyring(&self, f: &mut Frame, area: Rect) {
        let armed = self.keyring_armed.unwrap_or(false);
        let status = match self.keyring_armed {
            Some(true) => Span::styled("● armed", Style::new().fg(OK).add_modifier(Modifier::BOLD)),
            Some(false) => Span::styled("○ not armed", Style::new().dim()),
            None => Span::styled("unknown (daemon unreachable)", Style::new().dim()),
        };
        let tpm = crate::tpm_device().is_some();
        let mut lines = vec![
            section("TPM keyring unlock"),
            Line::from(vec![Span::raw("  state    "), status]),
            Line::from(vec![Span::raw("  TPM      "), if tpm { Span::styled("● present", Style::new().fg(OK)) } else { Span::styled("✗ none", Style::new().fg(ERR)) }]),
            Line::from(vec![Span::raw("  binding  "), Span::styled("PCR-7 (Secure Boot state)", Style::new().dim())]),
            Line::raw(""),
            Line::from(Span::styled("  At a face login the daemon unseals your password and hands it to", Style::new().dim())),
            Line::from(Span::styled("  pam_kwallet/gnome-keyring, so your wallet opens with no prompt.", Style::new().dim())),
            Line::raw(""),
        ];
        if armed {
            lines.push(Line::from(Span::styled("  ⚠ if a firmware/dbx update moves PCR-7, unseal fails → use the", Style::new().fg(WARN))));
            lines.push(Line::from(Span::styled("    Repair tab or `irlume reseal` to re-bind to current PCRs.", Style::new().dim())));
        } else {
            lines.push(Line::from(Span::styled("  Not armed — face login won't open your wallet yet.", Style::new().dim())));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("  [a]", Style::new().fg(ACCENT)), Span::styled(" arm (enter your login password)   ", Style::new().dim()),
            Span::styled("[f]", Style::new().fg(ACCENT)), Span::styled(" forget", Style::new().dim()),
        ]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_welcome(&self, f: &mut Frame, area: Rect) {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        let rec = self.recovery.unwrap_or_default();
        let lines = vec![
            Line::from(Span::styled("  irlume — local face authentication", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))),
            Line::from(Span::styled("  IR + lume · clean-BOM · TPM-sealed · privacy by design", Style::new().dim())),
            Line::raw(""),
            Line::from(Span::styled("  This is a guided panel. Tab / ⇧Tab walk the steps left-to-right;", Style::new().dim())),
            Line::from(Span::styled("  each step shows live state and its own action keys in the footer.", Style::new().dim())),
            Line::raw(""),
            section("At a glance"),
            Line::from(vec![Span::raw("  daemon       "), onoff(self.daemon_up)]),
            Line::from(vec![Span::raw("  enrolled     "), count_badge(self.profiles.len(), scans)]),
            Line::from(vec![Span::raw("  keyring      "), onoff(self.keyring_armed.unwrap_or(false))]),
            Line::from(vec![Span::raw("  encrypted    "), onoff(rec.encrypted)]),
            Line::from(vec![Span::raw("  biopolicy    "), onoff(biopolicy_on())]),
            Line::raw(""),
            Line::from(vec![Span::styled("  [e]", Style::new().fg(ACCENT)), Span::styled(" enroll now   ", Style::new().dim()),
                Span::styled("[i]", Style::new().fg(ACCENT)), Span::styled(" identify   ", Style::new().dim()),
                Span::styled("Tab", Style::new().fg(ACCENT)), Span::styled(" walk the steps", Style::new().dim())]),
            Line::from(Span::styled("  Live panel — changes to irlume appear here automatically.", Style::new().dim())),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    /// Diagnostic + repair: a live checklist (✓/⚠/✗) of everything irlume needs
    /// to run, with one-key fixes, plus platform trust anchors and a live IR PAD
    /// self-test. Mirrors `irlume doctor` + `diag` + `deps` and adds remediation.
    fn draw_repair(&self, f: &mut Frame, area: Rect) {
        use irlume_common::secureboot;
        let [list_area, info_area] = Layout::vertical([Constraint::Min(4), Constraint::Length(9)]).areas(area);

        // ---- checklist --------------------------------------------------
        let ok = self.repair.iter().filter(|c| c.sev == Sev::Ok).count();
        let fail = self.repair.iter().filter(|c| c.sev == Sev::Fail).count();
        let warn = self.repair.iter().filter(|c| c.sev == Sev::Warn).count();
        let items: Vec<ListItem> = self.repair.iter().map(|c| {
            let (icon, color) = match c.sev { Sev::Ok => ("✓", OK), Sev::Warn => ("⚠", WARN), Sev::Fail => ("✗", ERR) };
            let tag = match &c.fix { Fix::None => "", Fix::Manual(_) => " · manual", Fix::Daemon(_) => " · [f] auto-fix", Fix::Root(_) => " · [f] fix (sudo)" };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {icon} "), Style::new().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{:<19}", c.label), Style::new().add_modifier(Modifier::BOLD)),
                Span::styled(c.detail.clone(), Style::new().dim()),
                Span::styled(tag.to_string(), Style::new().fg(ACCENT)),
            ]))
        }).collect();
        let mut st = ListState::default().with_selected(Some(self.repair_sel.min(self.repair.len().saturating_sub(1))));
        f.render_stateful_widget(
            List::new(items).highlight_style(Style::new().bg(Color::Rgb(0x20, 0x30, 0x40)).add_modifier(Modifier::BOLD)),
            list_area, &mut st);

        // ---- info / platform / live test --------------------------------
        let sb = if secureboot::is_secure_boot_enabled() { ("enabled", OK) }
                 else if secureboot::is_setup_mode() { ("setup mode", WARN) }
                 else if secureboot::secure_boot_present() { ("disabled", WARN) }
                 else { ("n/a", WARN) };
        let mut lines = vec![Line::from(vec![
            Span::styled(format!("  {ok} ok"), Style::new().fg(OK)),
            Span::styled(format!("   {warn} warn"), Style::new().fg(WARN)),
            Span::styled(format!("   {fail} fail"), Style::new().fg(ERR)),
            Span::styled("      [f] fix selected   [r] re-check   [l] IR self-test", Style::new().dim()),
        ])];
        if let Some(c) = self.repair.get(self.repair_sel) {
            let hint = match &c.fix {
                Fix::None => "no action needed".to_string(),
                Fix::Manual(cmd) => format!("manual: {cmd}"),
                Fix::Daemon(_) => "press [f] — irlume fixes this via the daemon".to_string(),
                Fix::Root(_) => "press [f] — irlume runs the fix with sudo".to_string(),
            };
            lines.push(Line::from(vec![Span::styled("  → ", Style::new().fg(ACCENT)), Span::styled(hint, Style::new())]));
        }
        lines.push(Line::from(vec![
            Span::styled("  platform  ", Style::new().dim()),
            Span::styled(format!("TPM {} · ", if crate::tpm_device().is_some() { "✓" } else { "✗" }), Style::new()),
            Span::styled(format!("Secure Boot {} · ", sb.0), Style::new().fg(sb.1)),
            Span::styled(secureboot::detect_boot_mode().as_str().to_string(), Style::new().dim()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  PCR policy ", Style::new().dim()),
            Span::styled(if irlume_core::pcrsig::signed_policy_available() { "signed (PCR-11)" } else { "literal PCR-7" }.to_string(), Style::new().dim()),
        ]));
        match &self.selftest_result {
            Some((ok, d)) => lines.push(Line::from(vec![
                Span::styled("  IR test   ", Style::new().dim()),
                Span::styled(d.clone(), Style::new().fg(if *ok { OK } else { ERR })),
            ])),
            None => lines.push(Line::from(Span::styled("  IR test    press [l] to run the IR PAD self-test (look at the camera)", Style::new().dim()))),
        }
        let blk = Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().dim())
            .title(" diagnosis ");
        f.render_widget(Paragraph::new(lines).block(blk).wrap(Wrap { trim: true }), info_area);
    }

    fn draw_identify(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![
            section("1:N identify — \"who is this?\""),
            Line::from(Span::styled("  Capture once and match against every enrolled user (no claimed", Style::new().dim())),
            Line::from(Span::styled("  identity). Liveness-gated, RGB primary — a diagnostic, not unlock.", Style::new().dim())),
            Line::raw(""),
        ];
        match &self.identify_result {
            Some((true, who)) => {
                lines.push(Line::from(Span::styled("  ┌─ result ───────────────────────────", Style::new().dim())));
                lines.push(Line::from(vec![Span::styled("  │ ", Style::new().dim()), Span::styled(who.clone(), Style::new().fg(OK).add_modifier(Modifier::BOLD))]));
                lines.push(Line::from(Span::styled("  └────────────────────────────────────", Style::new().dim())));
            }
            Some((false, why)) => lines.push(Line::from(vec![Span::styled("  ✗ ", Style::new().fg(ERR)), Span::styled(why.clone(), Style::new().fg(ERR))])),
            None => lines.push(Line::from(Span::styled("  press [i] and look at the camera", Style::new().dim()))),
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![Span::styled("  [i]", Style::new().fg(ACCENT)), Span::styled(" identify now", Style::new().dim())]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_pam(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![section("PAM services (face auth wiring)")];
        // Inline per-service status — same data as `irlume login status`.
        for (label, present, wired) in crate::pamwire::status_report() {
            let val = if !present { Span::styled("— not present", Style::new().dim()) }
                      else if wired { Span::styled("● wired", Style::new().fg(OK).add_modifier(Modifier::BOLD)) }
                      else { Span::styled("○ not wired", Style::new().dim()) };
            lines.push(Line::from(vec![Span::raw(format!("  {label:<16}")), val]));
        }
        let sel = match crate::pamwire::selinux_state() {
            Some(true) => Span::styled("● loaded", Style::new().fg(OK)),
            Some(false) => Span::styled("✗ not loaded", Style::new().fg(ERR)),
            None => Span::styled("unknown (needs root)", Style::new().dim()),
        };
        lines.push(Line::from(vec![Span::raw(format!("  {:<16}", "SELinux module")), sel]));
        lines.push(Line::raw(""));
        lines.push(section("What each does"));
        lines.push(Line::from(Span::styled("  greeter: face → TPM-unseal password → wallet opens at login", Style::new().dim())));
        lines.push(Line::from(Span::styled("  lock screen: face verify-only (wallet already open)", Style::new().dim())));
        lines.push(Line::from(Span::styled("  always fail-safe to the password — no lockout.", Style::new().dim())));
        lines.push(Line::raw(""));
        lines.push(section("Change (root)"));
        lines.push(Line::from(vec![Span::styled("  enable  ", Style::new()), Span::styled("sudo irlume login enable --apply", Style::new().fg(ACCENT))]));
        lines.push(Line::from(vec![Span::styled("  disable ", Style::new()), Span::styled("sudo irlume login disable --apply", Style::new().dim())]));
        lines.push(Line::from(vec![Span::styled("  [s]", Style::new().fg(ACCENT)), Span::styled(" open full status in a console view", Style::new().dim())]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_done(&self, f: &mut Frame, area: Rect) {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        let rec = self.recovery.unwrap_or_default();
        let lines = vec![
            Line::from(Span::styled("  Setup dashboard", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))),
            Line::raw(""),
            Line::from(vec![Span::raw("  daemon            "), onoff(self.daemon_up)]),
            Line::from(vec![Span::raw("  auth method       "), Span::styled(self.fp.method.clone(), Style::new().fg(ACCENT))]),
            Line::from(vec![Span::raw("  enrollment        "), count_badge(self.profiles.len(), scans)]),
            Line::from(vec![Span::raw("  eyes-open gate    "), onoff(self.eyes_open)]),
            Line::from(vec![Span::raw("  keyring unlock    "), onoff(self.keyring_armed.unwrap_or(false))]),
            Line::from(vec![Span::raw("  templates enc     "), onoff(rec.encrypted)]),
            Line::from(vec![Span::raw("  recovery pass     "), onoff(rec.recovery_set)]),
            Line::from(vec![Span::raw("  biopolicy         "), onoff(biopolicy_on())]),
            Line::from(vec![Span::raw("  fingerprint       "), onoff(self.fp.available)]),
            Line::raw(""),
            Line::from(Span::styled("  All set. irlume keeps running as a daemon; this panel is safe to quit.", Style::new().dim())),
            Line::from(vec![Span::styled("  [r]", Style::new().fg(ACCENT)), Span::styled(" refresh    [q] quit", Style::new().dim())]),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_activity(&self, f: &mut Frame, area: Rect) {
        let scrolled = self.act_scroll > 0;
        let title = match (&self.op, scrolled) {
            (Some(op), _) => format!(" ● Activity   {} {}… ", SPIN[self.spin], op.label),
            (None, true) => format!(" ● Activity — ↑ history ({} up · PgDn/End to follow) ", self.act_scroll),
            (None, false) => " ● Activity — newest last · PgUp to scroll back ".to_string(),
        };
        let blk = Block::bordered().title(title).border_type(BorderType::Rounded)
            .border_style(Style::new().fg(if scrolled { ACCENT } else { BLUE }));
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let h = inner.height as usize;
        // Window ends `act_scroll` lines up from the newest entry.
        let end = self.activity.len().saturating_sub(self.act_scroll);
        let start = end.saturating_sub(h);
        let lines: Vec<Line> = self.activity[start..end].iter().map(|(g, m)| {
            let gs = match g { '→' => Style::new().fg(ACCENT), '✓' => Style::new().fg(OK), '✗' => Style::new().fg(ERR), _ => Style::new().dim() };
            Line::from(vec![Span::styled(format!("{g} "), gs), Span::raw(m.clone())])
        }).collect();
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let actions: &[(&str, &str)] = match self.screen {
            SC_WELCOME => &[("e", "enroll"), ("i", "identify"), ("r", "refresh")],
            SC_REPAIR => &[("f", "fix"), ("r", "re-check"), ("l", "IR test")],
            SC_CAMERAS => &[("enter", "use"), ("s", "setup emitter"), ("p", "probe")],
            SC_PROFILES => &[("e", "enroll"), ("a", "add scan"), ("r", "rename"), ("d", "delete")],
            SC_IDENTIFY => &[("i", "identify")],
            SC_KEYRING => &[("a", "arm"), ("f", "forget")],
            SC_RECOVERY => &[("s", "set"), ("t", "restore"), ("f", "forget")],
            SC_FINGERPRINT => &[("a", "enroll finger")],
            SC_PAM => &[("s", "show status")],
            SC_SETTINGS => &[("enter", "toggle eyes-open")],
            _ => &[("r", "refresh")],
        };
        let key = |k: &str| Span::styled(format!(" {k} "), Style::new().fg(Color::Black).bg(ACCENT));
        let mut spans = vec![
            key("Tab"), Span::styled(" next  ", Style::new().dim()),
            key("↑↓"), Span::styled(" select  ", Style::new().dim()),
            key("PgUp/Dn"), Span::styled(" activity  ", Style::new().dim()),
            key("q"), Span::styled(" quit    ", Style::new().dim()),
        ];
        for (k, d) in actions {
            spans.push(key(k));
            spans.push(Span::styled(format!(" {d}  "), Style::new().dim()));
        }
        let blk = Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().dim());
        f.render_widget(Paragraph::new(Line::from(spans)).block(blk), area);
    }

    fn modal(&self, f: &mut Frame, title: &str, body: &str) {
        let area = f.area();
        let w = area.width.saturating_sub(8).min(72).max(24);
        let rect = Rect { x: area.width.saturating_sub(w) / 2, y: area.height / 2 - 2, width: w, height: 5 };
        f.render_widget(Clear, rect);
        let blk = Block::bordered().title(format!(" {title} ")).border_type(BorderType::Rounded).border_style(Style::new().fg(ACCENT)).padding(ratatui::widgets::Padding::horizontal(1));
        f.render_widget(Paragraph::new(Line::from(body.to_string())).block(blk).wrap(Wrap { trim: true }), rect);
    }
}

fn quality_bar(q: u8) -> String {
    let filled = (q as usize * 10 / 100).min(10);
    format!("[{}{}] {q:>3}%", "█".repeat(filled), "░".repeat(10 - filled))
}

// ---- rich-render helpers --------------------------------------------------

/// A bold accent section header line.
fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(title.to_string(), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)))
}

/// Green ● ON / dim ○ off badge.
fn onoff(on: bool) -> Span<'static> {
    if on { Span::styled("● yes", Style::new().fg(OK).add_modifier(Modifier::BOLD)) }
    else { Span::styled("○ no", Style::new().dim()) }
}

/// "N profile(s), M scan(s)" or a dim "none".
fn count_badge(profiles: usize, scans: usize) -> Span<'static> {
    if profiles == 0 { Span::styled("○ none", Style::new().dim()) }
    else { Span::styled(format!("● {profiles} profile(s), {scans} scan(s)"), Style::new().fg(OK).add_modifier(Modifier::BOLD)) }
}

/// Is opt-in biopolicy enforcement enabled (settings.conf)?
fn biopolicy_on() -> bool {
    irlume_common::config::read_kv("settings.conf", "enforce_biopolicy")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
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
        Response::Identified { user: Some(u), profile, score, .. } =>
            (true, format!("{u} · {} · score {score:.3}", profile.unwrap_or_default())),
        Response::Identified { user: None, live, reason, .. } =>
            (false, if live { format!("live face, no enrolled match ({reason})") } else { format!("no live face ({reason})") }),
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

/// Guided-enroll worker: poll the framing guide, count down on a good streak,
/// then capture — repeating until `target` scans. Streams cues to the UI.
fn enroll_worker(user: String, profile: String, add: Option<String>, target: usize, stop: Arc<AtomicBool>, tx: mpsc::Sender<WMsg>) {
    let send = |m: WMsg| tx.send(m).is_ok();
    for i in 0..target {
        if stop.load(Ordering::Relaxed) { return; }
        // Framing loop: wait for a well-framed streak.
        let mut streak = 0u32;
        loop {
            if stop.load(Ordering::Relaxed) { return; }
            match crate::daemon_request(&Request::PositionSample) {
                Ok(Response::Position(r)) => {
                    let good = r.well_framed;
                    if !send(WMsg::Cue(r)) { return; }
                    streak = if good { streak + 1 } else { 0 };
                    if streak >= GOOD_STREAK { break; }
                }
                Ok(Response::Error(e)) => { let _ = send(WMsg::Err(e)); return; }
                Ok(_) => {}
                Err(e) => { let _ = send(WMsg::Err(e)); return; }
            }
        }
        // 3-2-1 countdown.
        for c in (1..=3).rev() {
            if stop.load(Ordering::Relaxed) { return; }
            if !send(WMsg::Count(c)) { return; }
            std::thread::sleep(Duration::from_millis(650));
        }
        // Capture: first scan of a NEW profile creates it; the rest append.
        let req = if i == 0 && add.is_none() {
            Request::Enroll { user: user.clone(), profile: Some(profile.clone()), scans: Some(1), reset: false }
        } else {
            Request::AddScan { user: user.clone(), profile: profile.clone() }
        };
        match crate::daemon_request(&req) {
            Ok(Response::Ok(_)) => { if !send(WMsg::Captured(i + 1, target)) { return; } }
            Ok(Response::Error(e)) => { let _ = send(WMsg::Err(e)); return; }
            Ok(o) => { let _ = send(WMsg::Err(format!("unexpected: {o:?}"))); return; }
            Err(e) => { let _ = send(WMsg::Err(e)); return; }
        }
    }
    let _ = send(WMsg::Done);
}
