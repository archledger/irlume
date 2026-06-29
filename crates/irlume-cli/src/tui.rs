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
const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SCREENS: [&str; 12] = [
    "Welcome", "Host check", "Cameras", "Profiles", "Calibrate", "Identify",
    "Keyring", "Recovery", "Fingerprint", "Login wiring", "Settings", "Done",
];
// Screen indices (keep in sync with SCREENS).
const SC_WELCOME: usize = 0;
const SC_DOCTOR: usize = 1;
const SC_CAMERAS: usize = 2;
const SC_PROFILES: usize = 3;
const SC_CALIBRATE: usize = 4;
const SC_IDENTIFY: usize = 5;
const SC_KEYRING: usize = 6;
const SC_RECOVERY: usize = 7;
const SC_FINGERPRINT: usize = 8;
const SC_PAM: usize = 9;
const SC_SETTINGS: usize = 10;
const SC_DONE: usize = 11;
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
}

/// Interactive flow that needs a cooked terminal — the TUI tears down the
/// alt-screen, runs it via the existing CLI handler (no-echo prompts), then
/// re-enters. Mirrors linhello's suspend pattern.
#[derive(Clone, Copy)]
enum Suspend {
    FingerprintAdd,
    RecoverySetup,
    RecoveryRestore,
    KeyringArm,
    LoginStatus,
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
    /// Last IR liveness self-test result, shown on the Calibrate screen.
    calibrate_result: Option<(bool, String)>,
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
    let mut app = App::new();
    app.log('·', format!("irlume — managing '{}'", app.user));
    app.refresh();
    let res = app.main_loop(&mut terminal);
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
            identify_result: None, calibrate_result: None,
            spin: 0, quit: false,
        }
    }

    fn log(&mut self, g: char, m: impl Into<String>) {
        self.activity.push((g, m.into()));
        let n = self.activity.len();
        if n > 200 { self.activity.drain(0..n - 200); }
    }

    fn request(&mut self, req: Request, action: &str) -> Option<Response> {
        self.log('→', format!("daemon: {action}"));
        match crate::daemon_request(&req) {
            Ok(Response::Error(e)) => { self.log('✗', e); None }
            Ok(r) => Some(r),
            Err(e) => { self.log('✗', e); None }
        }
    }

    fn refresh(&mut self) {
        if let Some(Response::Enrollment { profiles, require_eyes_open }) =
            self.request(Request::ListProfiles { user: self.user.clone() }, "ListProfiles")
        {
            let (np, ns) = (profiles.len(), profiles.iter().map(|p| p.scans.len()).sum::<usize>());
            self.profiles = profiles;
            self.eyes_open = require_eyes_open;
            self.log('✓', format!("{np} profile(s), {ns} scan(s)"));
        }
        if let Some(Response::HasPassword(b)) =
            self.request(Request::HasSealedPassword { user: self.user.clone() }, "HasSealedPassword")
        { self.keyring_armed = Some(b); }
        if let Some(Response::RecoveryStatus { encrypted, recovery_set, tpm_present }) =
            self.request(Request::RecoveryStatus { user: self.user.clone() }, "RecoveryStatus")
        { self.recovery = Some(RecoveryInfo { encrypted, recovery_set, tpm_present }); }
        self.fp = FpInfo {
            available: irlume_fingerprint::available(),
            device: irlume_fingerprint::device_name(),
            enrolled: irlume_fingerprint::enrolled_fingers(&self.user),
            method: irlume_core::policy::method().as_str().to_string(),
        };
        let max = self.rows().len().max(1);
        if self.sel >= max { self.sel = max - 1; }
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
                self.log(if ok { '✓' } else { '✗' }, msg.clone());
                match tag {
                    OpTag::Identify => self.identify_result = Some((ok, msg)),
                    OpTag::Calibrate => self.calibrate_result = Some((ok, msg)),
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
                    WMsg::Err(e) => { self.log('✗', e); finished = true; }
                }
            }
            if finished { self.enroll = None; self.refresh(); }
        }
    }

    fn main_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> std::io::Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press { self.on_key(k.code); }
                }
            }
            self.spin = (self.spin + 1) % SPIN.len();
            self.poll();
            // Interactive flows that need a cooked terminal: tear down, run, re-enter.
            if let Some(s) = self.suspend.take() {
                ratatui::restore();
                self.run_suspended(s);
                *terminal = ratatui::init();
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
            Suspend::RecoverySetup => { crate::recovery::run(Some("setup"), &none); }
            Suspend::RecoveryRestore => { crate::recovery::run(Some("restore"), &none); }
            Suspend::KeyringArm => { crate::keyring(Some("arm"), &none); }
            Suspend::LoginStatus => { crate::pamwire::run(Some("status"), &none); }
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
            KeyCode::Tab | KeyCode::Right => { self.screen = (self.screen + 1) % SCREENS.len(); self.sel = 0; }
            KeyCode::BackTab | KeyCode::Left => { self.screen = (self.screen + SCREENS.len() - 1) % SCREENS.len(); self.sel = 0; }
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            _ => self.on_action(code),
        }
    }

    fn move_sel(&mut self, d: i32) {
        let n = self.rows().len().max(1) as i32;
        self.sel = (((self.sel as i32 + d) % n + n) % n) as usize;
    }

    fn on_action(&mut self, code: KeyCode) {
        match (self.screen, code) {
            // Welcome / Done / Host check: refresh the whole snapshot.
            (SC_WELCOME, KeyCode::Char('r')) | (SC_DONE, KeyCode::Char('r')) | (SC_DOCTOR, KeyCode::Char('r')) => {
                self.log('·', "refreshing status…");
                self.refresh();
            }
            // Cameras: IR emitter auto-setup / probe.
            (SC_CAMERAS, KeyCode::Char('s')) => self.start_op("SetupIrEmitter (auto-enable emitter)", Request::SetupIrEmitter { dry_run: false }),
            (SC_CAMERAS, KeyCode::Char('p')) => {
                if let Some(Response::Ok(m)) = self.request(Request::SetupIrEmitter { dry_run: true }, "SetupIrEmitter(dry-run)") { self.log('✓', m); }
            }
            // Profiles.
            (SC_PROFILES, KeyCode::Char('e')) => {
                if self.profiles.len() >= MAX_PROFILES {
                    self.log('✗', format!("at the max {MAX_PROFILES} profiles — delete one first"));
                } else {
                    self.input = Some(("New profile name (blank = default):".into(), String::new(), Pending::EnrollName));
                }
            }
            (SC_PROFILES, KeyCode::Char('a')) => { if let Some(p) = self.sel_profile() { self.start_enroll(Some(p)); } }
            (SC_PROFILES, KeyCode::Char('r')) => self.begin_rename(),
            (SC_PROFILES, KeyCode::Char('d')) => self.begin_delete(),
            // Calibrate: run the algorithmic IR liveness/PAD self-test.
            (SC_CALIBRATE, KeyCode::Char('c')) => self.start_async(
                "SelfTest (IR liveness)", OpTag::Calibrate,
                Request::SelfTest { kind: irlume_common::SelfTestKind::Liveness }, map_selftest),
            // Identify: 1:N who-is-this.
            (SC_IDENTIFY, KeyCode::Char('i')) => self.start_async(
                "Identify (1:N)", OpTag::Identify, Request::Identify, map_identify),
            // Keyring.
            (SC_KEYRING, KeyCode::Char('a')) => self.suspend = Some(Suspend::KeyringArm),
            (SC_KEYRING, KeyCode::Char('f')) => {
                self.confirm = Some(("Erase the TPM-sealed login password?".into(), Request::ForgetPassword { user: self.user.clone() }));
            }
            // Recovery.
            (SC_RECOVERY, KeyCode::Char('s')) => self.suspend = Some(Suspend::RecoverySetup),
            (SC_RECOVERY, KeyCode::Char('t')) => self.suspend = Some(Suspend::RecoveryRestore),
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
        if let Some((prompt, buf, _)) = &self.input {
            self.modal(f, prompt, &format!("{buf}▏"));
        } else if let Some((what, _)) = &self.confirm {
            self.modal(f, what, "[y] confirm    [any other key] cancel");
        }
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
            SC_DOCTOR => self.draw_doctor(f, inner),
            SC_CAMERAS => self.draw_cameras(f, inner),
            SC_PROFILES => self.draw_profiles(f, inner),
            SC_CALIBRATE => self.draw_calibrate(f, inner),
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
        let (rgb, ir) = irlume_camera::select_pair();
        let mut lines = vec![
            section("Active pair (auto-selected)"),
            kv("  RGB", Span::styled(rgb.clone(), Style::new().fg(OK).add_modifier(Modifier::BOLD))),
            kv("  IR ", Span::styled(ir.clone(), Style::new().fg(OK).add_modifier(Modifier::BOLD))),
            Line::raw(""),
            section("All video nodes"),
        ];
        if self.nodes.is_empty() {
            lines.push(Line::from(Span::styled("  no camera nodes found under /dev/video*", Style::new().fg(ERR))));
        }
        for (p, role) in &self.nodes {
            let chosen = *p == rgb || *p == ir;
            let mark = if chosen { Span::styled("  ▸ ", Style::new().fg(ACCENT)) } else { Span::raw("    ") };
            let priv_on = if irlume_camera::privacy_engaged(p) { Span::styled("  ⚠ privacy switch ON", Style::new().fg(ERR)) } else { Span::raw("") };
            lines.push(Line::from(vec![
                mark,
                Span::styled(format!("{p:<14}"), if chosen { Style::new().add_modifier(Modifier::BOLD) } else { Style::new().dim() }),
                Span::styled(format!("{role:?}"), Style::new().fg(ACCENT)),
                priv_on,
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(section("IR emitter (850nm)"));
        lines.push(Line::from(Span::styled("  If the IR feed is dark, irlume can probe the UVC extension-unit", Style::new().dim())));
        lines.push(Line::from(Span::styled("  controls and auto-enable the illuminator (no phone-camera step).", Style::new().dim())));
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("  [s]", Style::new().fg(ACCENT)), Span::raw(" auto-setup emitter    "),
            Span::styled("[p]", Style::new().fg(ACCENT)), Span::raw(" probe XU controls (read-only)"),
        ]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
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
        let status = match self.keyring_armed {
            Some(true) => Span::styled("● armed", Style::new().fg(OK).add_modifier(Modifier::BOLD)),
            Some(false) => Span::styled("○ not armed", Style::new().dim()),
            None => Span::styled("unknown", Style::new().dim()),
        };
        f.render_widget(Paragraph::new(vec![
            Line::raw(""),
            Line::from(vec![Span::styled("TPM keyring unlock   ", Style::new().add_modifier(Modifier::BOLD)), status]),
            Line::from(Span::styled("  Face login releases your TPM-sealed password to open KWallet.", Style::new().dim())),
            Line::raw(""),
            Line::from(Span::styled("  [f] forget (disarm).  To arm: `irlume keyring arm` (needs your password).", Style::new().dim())),
        ]).wrap(Wrap { trim: true }), area);
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
            Line::from(vec![Span::raw("  daemon       "), onoff(std::path::Path::new("/run/irlume.sock").exists())]),
            Line::from(vec![Span::raw("  enrolled     "), count_badge(self.profiles.len(), scans)]),
            Line::from(vec![Span::raw("  keyring      "), onoff(self.keyring_armed.unwrap_or(false))]),
            Line::from(vec![Span::raw("  encrypted    "), onoff(rec.encrypted)]),
            Line::from(vec![Span::raw("  biopolicy    "), onoff(biopolicy_on())]),
            Line::raw(""),
            Line::from(Span::styled("  New here? Step to Profiles and press [e] to enroll your face.", Style::new().dim())),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_doctor(&self, f: &mut Frame, area: Rect) {
        use irlume_common::secureboot;
        let model = |m: &str| std::path::Path::new(m).exists();
        let sb = if secureboot::is_secure_boot_enabled() { ("enabled", OK) }
                 else if secureboot::is_setup_mode() { ("SETUP MODE", ERR) }
                 else if secureboot::secure_boot_present() { ("disabled", ERR) }
                 else { ("not UEFI", ERR) };
        let lines = vec![
            section("Trust anchors"),
            Line::from(vec![chk_span(crate::tpm_device().is_some()), Span::raw("TPM 2.0  "),
                Span::styled(crate::tpm_device().unwrap_or("none").to_string(), Style::new().dim())]),
            Line::from(vec![chk_span(sb.1 == OK), Span::raw("Secure Boot  "), Span::styled(sb.0.to_string(), Style::new().fg(sb.1))]),
            Line::from(vec![Span::raw("    boot mode  "), Span::styled(secureboot::detect_boot_mode().as_str().to_string(), Style::new().dim())]),
            Line::from(vec![chk_span(irlume_core::pcrsig::signed_policy_available()), Span::raw("signed PCR policy  "),
                Span::styled(if irlume_core::pcrsig::signed_policy_available() { "PCR-11 signature" } else { "none (literal PCR-7)" }.to_string(), Style::new().dim())]),
            Line::raw(""),
            section("Models / runtime"),
            Line::from(vec![chk_span(model("models/glintr100.onnx")), Span::raw("AuraFace glintr100.onnx")]),
            Line::from(vec![chk_span(model("models/face_detection_yunet_2023mar.onnx")), Span::raw("YuNet detector")]),
            Line::from(vec![chk_span(self.nodes.iter().any(|(_, r)| matches!(r, irlume_camera::Role::Rgb))
                && self.nodes.iter().any(|(_, r)| matches!(r, irlume_camera::Role::Ir))), Span::raw("RGB + IR camera nodes")]),
            Line::raw(""),
            Line::from(Span::styled("  Full report: `irlume doctor` (CLI). [r] re-check.", Style::new().dim())),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_calibrate(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![
            section("Per-user IR liveness"),
            Line::from(Span::styled("  irlume's anti-spoof floor is calibrated automatically from your", Style::new().dim())),
            Line::from(Span::styled("  enrolled IR scans (≈75% of your weakest enrolled IR reading), so", Style::new().dim())),
            Line::from(Span::styled("  re-enrolling re-tunes it to your camera/rig — no manual step.", Style::new().dim())),
            Line::raw(""),
            section("Live check"),
        ];
        match &self.calibrate_result {
            Some((ok, detail)) => lines.push(Line::from(vec![
                if *ok { Span::styled("  ● ", Style::new().fg(OK)) } else { Span::styled("  ● ", Style::new().fg(ERR)) },
                Span::styled(detail.clone(), if *ok { Style::new().fg(OK) } else { Style::new().fg(ERR) }),
            ])),
            None => lines.push(Line::from(Span::styled("  press [c] to run the IR PAD self-test against a live frame", Style::new().dim()))),
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![Span::styled("  [c]", Style::new().fg(ACCENT)), Span::styled(" run IR liveness self-test (look at the camera)", Style::new().dim())]));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
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
        let lines = vec![
            section("PAM login wiring"),
            Line::from(Span::styled("  Face auth plugs into your display-manager greeter and lock screen", Style::new().dim())),
            Line::from(Span::styled("  via pam_irlume — always fail-safe to the password (no lockout).", Style::new().dim())),
            Line::raw(""),
            Line::from(vec![Span::raw("  greeter unlock  "), Span::styled("face → TPM-unseal password → wallet opens", Style::new().dim())]),
            Line::from(vec![Span::raw("  lock screen     "), Span::styled("face verify-only (wallet already open)", Style::new().dim())]),
            Line::from(vec![Span::raw("  sudo            "), Span::styled("face verify (optional)", Style::new().dim())]),
            Line::raw(""),
            section("Apply (root)"),
            Line::from(Span::styled("  Preview:  irlume login enable            (dry-run, no changes)", Style::new().dim())),
            Line::from(Span::styled("  Apply:    sudo irlume login enable --apply", Style::new().fg(ACCENT))),
            Line::from(Span::styled("  Remove:   sudo irlume login disable --apply", Style::new().dim())),
            Line::raw(""),
            Line::from(vec![Span::styled("  [s]", Style::new().fg(ACCENT)), Span::styled(" show current wiring status (opens a console view)", Style::new().dim())]),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_done(&self, f: &mut Frame, area: Rect) {
        let scans: usize = self.profiles.iter().map(|p| p.scans.len()).sum();
        let rec = self.recovery.unwrap_or_default();
        let lines = vec![
            Line::from(Span::styled("  Setup dashboard", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))),
            Line::raw(""),
            Line::from(vec![Span::raw("  daemon            "), onoff(std::path::Path::new("/run/irlume.sock").exists())]),
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
        let title = match &self.op {
            Some(op) => format!(" ● Activity   {} {}… ", SPIN[self.spin], op.label),
            None => " ● Activity — what irlume is doing to your system (newest last) ".to_string(),
        };
        let blk = Block::bordered().title(title).border_type(BorderType::Rounded).border_style(Style::new().fg(BLUE));
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let h = inner.height as usize;
        let start = self.activity.len().saturating_sub(h);
        let lines: Vec<Line> = self.activity[start..].iter().map(|(g, m)| {
            let gs = match g { '→' => Style::new().fg(ACCENT), '✓' => Style::new().fg(OK), '✗' => Style::new().fg(ERR), _ => Style::new().dim() };
            Line::from(vec![Span::styled(format!("{g} "), gs), Span::raw(m.clone())])
        }).collect();
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let actions: &[(&str, &str)] = match self.screen {
            SC_WELCOME => &[("r", "refresh")],
            SC_DOCTOR => &[("r", "re-check")],
            SC_CAMERAS => &[("s", "setup emitter"), ("p", "probe")],
            SC_PROFILES => &[("e", "enroll"), ("a", "add scan"), ("r", "rename"), ("d", "delete")],
            SC_CALIBRATE => &[("c", "IR self-test")],
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
            key("⇧Tab"), Span::styled(" back  ", Style::new().dim()),
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

/// `label  value` line.
fn kv(label: &str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![Span::styled(format!("{label}  "), Style::new()), value])
}

/// Green ● ON / dim ○ off badge.
fn onoff(on: bool) -> Span<'static> {
    if on { Span::styled("● yes", Style::new().fg(OK).add_modifier(Modifier::BOLD)) }
    else { Span::styled("○ no", Style::new().dim()) }
}

/// Leading ✓ / ✗ checklist marker.
fn chk_span(ok: bool) -> Span<'static> {
    if ok { Span::styled("  ✓ ", Style::new().fg(OK)) } else { Span::styled("  ✗ ", Style::new().fg(ERR)) }
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
