//! `irlume tui` — a keyboard-driven configuration UI over the `irlumed` socket.
//!
//! Design goals: clean (GNOME/Apple-calm spacing, rounded panels, one accent
//! colour), navigable (arrow keys + Tab, a static keybind footer), and
//! transparent — every operation irlume performs is shown live in the Activity
//! panel (inspired by ChrisTitusTech/linutil), so the user always sees what's
//! being done to their device. It is a thin client: all work happens in the
//! daemon, exactly as the CLI/PAM module do.

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::sync::mpsc;
use std::time::Duration;

use irlume_common::{ProfileSummary, Request, Response};

const ACCENT: Color = Color::Rgb(0x6c, 0xb6, 0xff);
const OK: Color = Color::Rgb(0x73, 0xc9, 0x91);
const ERR: Color = Color::Rgb(0xe8, 0x7a, 0x7a);
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const SCREENS: [&str; 5] = ["Profiles", "Settings", "IR Camera", "Keyring", "Diagnostics"];

/// A flattened, selectable row on the Profiles screen.
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

struct Op {
    label: String,
    rx: mpsc::Receiver<(bool, String)>,
}

struct App {
    user: String,
    screen: usize,
    menu_focus: bool,
    sel: usize,
    profiles: Vec<ProfileSummary>,
    eyes_open: bool,
    keyring_armed: Option<bool>,
    nodes: Vec<(String, irlume_camera::Role)>,
    activity: Vec<(char, String)>,
    input: Option<(String, String, Pending)>,
    confirm: Option<(String, Request)>,
    op: Option<Op>,
    spin: usize,
    quit: bool,
}

pub fn run() -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new();
    app.log('·', format!("irlume TUI — managing '{}'", app.user));
    app.refresh();
    let res = app.main_loop(&mut terminal);
    ratatui::restore();
    res
}

impl App {
    fn new() -> Self {
        let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "user".into());
        Self {
            user,
            screen: 0,
            menu_focus: true,
            sel: 0,
            profiles: Vec::new(),
            eyes_open: false,
            keyring_armed: None,
            nodes: irlume_camera::discover_nodes(), // probed once, not per-frame
            activity: Vec::new(),
            input: None,
            confirm: None,
            op: None,
            spin: 0,
            quit: false,
        }
    }

    fn log(&mut self, glyph: char, msg: impl Into<String>) {
        self.activity.push((glyph, msg.into()));
        let n = self.activity.len();
        if n > 200 {
            self.activity.drain(0..n - 200);
        }
    }

    /// Synchronous daemon round-trip, logged to Activity (the transparency point).
    fn request(&mut self, req: Request, action: &str) -> Option<Response> {
        self.log('→', format!("daemon: {action}"));
        match crate::daemon_request(&req) {
            Ok(Response::Error(e)) => {
                self.log('✗', e);
                None
            }
            Ok(r) => Some(r),
            Err(e) => {
                self.log('✗', e);
                None
            }
        }
    }

    fn refresh(&mut self) {
        if let Some(Response::Enrollment { profiles, require_eyes_open }) =
            self.request(Request::ListProfiles { user: self.user.clone() }, "ListProfiles")
        {
            let np = profiles.len();
            let ns: usize = profiles.iter().map(|p| p.scans.len()).sum();
            self.profiles = profiles;
            self.eyes_open = require_eyes_open;
            self.log('✓', format!("{np} profile(s), {ns} scan(s)"));
        }
        if let Some(Response::HasPassword(b)) =
            self.request(Request::HasSealedPassword { user: self.user.clone() }, "HasSealedPassword")
        {
            self.keyring_armed = Some(b);
        }
        let max = self.rows().len().max(1);
        if self.sel >= max {
            self.sel = max - 1;
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

    /// Long (camera) op: run in a thread, show a spinner, log the result.
    fn start_op(&mut self, label: impl Into<String>, req: Request) {
        let label = label.into();
        self.log('→', format!("daemon: {label}"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = match crate::daemon_request(&req) {
                Ok(Response::Ok(m)) => (true, m),
                Ok(Response::Error(e)) => (false, e),
                Ok(other) => (false, format!("unexpected: {other:?}")),
                Err(e) => (false, e),
            };
            let _ = tx.send(r);
        });
        self.op = Some(Op { label, rx });
    }

    fn poll_op(&mut self) {
        if let Some(op) = &self.op {
            if let Ok((ok, msg)) = op.rx.try_recv() {
                self.log(if ok { '✓' } else { '✗' }, msg);
                self.op = None;
                self.refresh();
            }
        }
    }

    fn main_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> std::io::Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(120))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        self.on_key(k.code);
                    }
                }
            }
            self.spin = (self.spin + 1) % SPINNER.len();
            self.poll_op();
        }
        Ok(())
    }

    fn on_key(&mut self, code: KeyCode) {
        // Modal layers first.
        if self.op.is_some() {
            return; // busy: ignore input until the op finishes
        }
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
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let req = req.clone();
                    self.confirm = None;
                    if let Some(Response::Ok(m)) = self.request(req, "(confirmed)") {
                        self.log('✓', m);
                    }
                    self.refresh();
                }
                _ => self.confirm = None,
            }
            return;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Tab => self.menu_focus = !self.menu_focus,
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::Left => self.menu_focus = true,
            KeyCode::Right | KeyCode::Enter if self.menu_focus => self.menu_focus = false,
            _ => self.on_action(code),
        }
    }

    fn move_sel(&mut self, d: i32) {
        if self.menu_focus {
            let n = SCREENS.len() as i32;
            self.screen = (((self.screen as i32 + d) % n + n) % n) as usize;
            self.sel = 0;
        } else {
            let n = self.rows().len().max(1) as i32;
            self.sel = (((self.sel as i32 + d) % n + n) % n) as usize;
        }
    }

    fn on_action(&mut self, code: KeyCode) {
        match (self.screen, code) {
            // Profiles
            (0, KeyCode::Char('e')) => {
                self.input = Some(("New profile name (blank = default):".into(), String::new(), Pending::EnrollName));
            }
            (0, KeyCode::Char('a')) => {
                if let Some(p) = self.sel_profile() {
                    self.start_op(format!("AddScan to '{p}'"), Request::AddScan { user: self.user.clone(), profile: p });
                }
            }
            (0, KeyCode::Char('r')) => self.begin_rename(),
            (0, KeyCode::Char('d')) => self.begin_delete(),
            // Settings
            (1, KeyCode::Enter) | (1, KeyCode::Char(' ')) => {
                let on = !self.eyes_open;
                if self.request(Request::SetRequireEyesOpen { user: self.user.clone(), on }, &format!("SetRequireEyesOpen({on})")).is_some() {
                    self.log('✓', format!("require-eyes-open {}", if on { "ENABLED" } else { "disabled" }));
                }
                self.refresh();
            }
            // IR Camera
            (2, KeyCode::Char('s')) => self.start_op("SetupIrEmitter (auto-enable emitter)", Request::SetupIrEmitter { dry_run: false }),
            (2, KeyCode::Char('p')) => {
                if let Some(Response::Ok(m)) = self.request(Request::SetupIrEmitter { dry_run: true }, "SetupIrEmitter(dry-run)") {
                    self.log('✓', m);
                }
            }
            // Keyring
            (3, KeyCode::Char('f')) => {
                self.confirm = Some(("Erase the TPM-sealed login password (disables keyring unlock)?".into(),
                    Request::ForgetPassword { user: self.user.clone() }));
            }
            // Diagnostics
            (4, KeyCode::Char('r')) => {
                if self.request(Request::Ping, "Ping").is_some() {
                    self.log('✓', "daemon reachable (Pong)");
                }
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
                let p = self.profiles[pi].name.clone();
                let s = self.profiles[pi].scans[si].clone();
                self.input = Some((format!("Rename scan '{s}' to:"), String::new(), Pending::RenameScan(p, s)));
            }
            None => {}
        }
    }

    fn begin_delete(&mut self) {
        match self.rows().get(self.sel).copied() {
            Some(Row::Profile(pi)) => {
                let p = self.profiles[pi].name.clone();
                self.confirm = Some((format!("Delete profile '{p}' and all its scans?"),
                    Request::DeleteProfile { user: self.user.clone(), profile: p }));
            }
            Some(Row::Scan(pi, si)) => {
                let p = self.profiles[pi].name.clone();
                let s = self.profiles[pi].scans[si].clone();
                self.confirm = Some((format!("Delete scan '{s}' from '{p}'?"),
                    Request::DeleteScan { user: self.user.clone(), profile: p, scan: s }));
            }
            None => {}
        }
    }

    fn submit_input(&mut self) {
        let Some((_, buf, pending)) = self.input.take() else { return };
        let v = buf.trim().to_string();
        match pending {
            Pending::EnrollName => {
                let name = (!v.is_empty()).then_some(v);
                self.start_op("Enroll new profile (capturing scans)", Request::Enroll { user: self.user.clone(), profile: name });
            }
            Pending::RenameProfile(old) => {
                if !v.is_empty() {
                    if let Some(Response::Ok(m)) = self.request(Request::RenameProfile { user: self.user.clone(), profile: old, new_name: v }, "RenameProfile") {
                        self.log('✓', m);
                    }
                    self.refresh();
                }
            }
            Pending::RenameScan(p, s) => {
                if !v.is_empty() {
                    if let Some(Response::Ok(m)) = self.request(Request::RenameScan { user: self.user.clone(), profile: p, scan: s, new_name: v }, "RenameScan") {
                        self.log('✓', m);
                    }
                    self.refresh();
                }
            }
        }
    }

    // ---- rendering --------------------------------------------------------

    fn draw(&self, f: &mut Frame) {
        let [header, body, activity, footer] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(9),
            Constraint::Length(1),
        ])
        .areas(f.area());

        self.draw_header(f, header);
        let [menu, content] = Layout::horizontal([Constraint::Length(20), Constraint::Min(20)]).areas(body);
        self.draw_menu(f, menu);
        self.draw_content(f, content);
        self.draw_activity(f, activity);
        self.draw_footer(f, footer);

        if let Some((prompt, buf, _)) = &self.input {
            self.draw_modal(f, prompt, &format!("{buf}▏"));
        } else if let Some((what, _)) = &self.confirm {
            self.draw_modal(f, what, "[y] confirm   [any other key] cancel");
        }
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let title = Line::from(vec![
            Span::styled(" irlume ", Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled("face authentication", Style::new().fg(ACCENT)),
        ]);
        let right = Line::from(Span::styled(format!("{} ", self.user), Style::new().dim())).right_aligned();
        let blk = Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().dim());
        f.render_widget(Paragraph::new(title).block(blk.clone()), area);
        f.render_widget(Paragraph::new(right).block(blk), area);
    }

    fn draw_menu(&self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = SCREENS.iter().enumerate().map(|(i, s)| {
            let selected = i == self.screen;
            let marker = if selected { "▸ " } else { "  " };
            let style = if selected { Style::new().fg(ACCENT).add_modifier(Modifier::BOLD) } else { Style::new() };
            ListItem::new(Line::from(vec![Span::styled(marker, style), Span::styled(*s, style)]))
        }).collect();
        let border = if self.menu_focus { Style::new().fg(ACCENT) } else { Style::new().dim() };
        let blk = Block::bordered().title(" Menu ").border_type(BorderType::Rounded).border_style(border);
        f.render_widget(List::new(items).block(blk), area);
    }

    fn draw_content(&self, f: &mut Frame, area: Rect) {
        let border = if self.menu_focus { Style::new().dim() } else { Style::new().fg(ACCENT) };
        let blk = Block::bordered().title(format!(" {} ", SCREENS[self.screen]))
            .border_type(BorderType::Rounded).border_style(border).padding(ratatui::widgets::Padding::horizontal(1));
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        match self.screen {
            0 => self.draw_profiles(f, inner),
            1 => self.draw_settings(f, inner),
            2 => self.draw_ircam(f, inner),
            3 => self.draw_keyring(f, inner),
            _ => self.draw_diag(f, inner),
        }
    }

    fn draw_profiles(&self, f: &mut Frame, area: Rect) {
        if self.profiles.is_empty() {
            f.render_widget(Paragraph::new("\nNo face profiles yet.\n\nPress [e] to enroll your first profile (captures a few scans).")
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
            Row::Scan(pi, si) => ListItem::new(Line::from(Span::styled(
                format!("     ↳ {}", self.profiles[*pi].scans[*si]), Style::new()))),
        }).collect();
        let mut st = ListState::default().with_selected(Some(self.sel.min(rows.len().saturating_sub(1))));
        let hl = if self.menu_focus { Style::new().add_modifier(Modifier::REVERSED).dim() } else { Style::new().bg(Color::Rgb(0x20, 0x30, 0x40)).add_modifier(Modifier::BOLD) };
        f.render_stateful_widget(List::new(items).highlight_style(hl), area, &mut st);
    }

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let dot = if self.eyes_open { Span::styled("● ON ", Style::new().fg(OK).add_modifier(Modifier::BOLD)) } else { Span::styled("○ off", Style::new().dim()) };
        let lines = vec![
            Line::raw(""),
            Line::from(vec![Span::styled("Require eyes open   ", Style::new().add_modifier(Modifier::BOLD)), dot]),
            Line::from(Span::styled("  Never unlock unless both eyes read open (heuristic).", Style::new().dim())),
            Line::from(Span::styled("  Press [enter] to toggle.", Style::new().dim())),
            Line::raw(""),
            Line::from(Span::styled("Thresholds (read-only): RGB 0.55 · IR-adapted 0.40 · scaled by scan count", Style::new().dim())),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_ircam(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![Line::raw("")];
        for (p, role) in &self.nodes {
            lines.push(Line::from(vec![Span::raw(format!("  {p}  ")), Span::styled(format!("{role:?}"), Style::new().fg(ACCENT))]));
        }
        if self.nodes.is_empty() { lines.push(Line::from(Span::styled("  no camera nodes found", Style::new().fg(ERR)))); }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled("If the IR feed is dark, irlume can auto-enable the 850nm emitter:", Style::new().dim())));
        lines.push(Line::from(Span::styled("  [s] auto-setup emitter    [p] probe XU controls (read-only)", Style::new())));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_keyring(&self, f: &mut Frame, area: Rect) {
        let status = match self.keyring_armed {
            Some(true) => Span::styled("● armed", Style::new().fg(OK).add_modifier(Modifier::BOLD)),
            Some(false) => Span::styled("○ not armed", Style::new().dim()),
            None => Span::styled("unknown", Style::new().dim()),
        };
        let lines = vec![
            Line::raw(""),
            Line::from(vec![Span::styled("TPM keyring unlock   ", Style::new().add_modifier(Modifier::BOLD)), status]),
            Line::from(Span::styled("  Face login releases your TPM-sealed password to open KWallet.", Style::new().dim())),
            Line::raw(""),
            Line::from(Span::styled("  [f] forget (disarm).  To arm: run `irlume keyring arm` (needs your password).", Style::new().dim())),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_diag(&self, f: &mut Frame, area: Rect) {
        let socket = std::path::Path::new("/run/irlume.sock").exists();
        let lines = vec![
            Line::raw(""),
            Line::from(vec![Span::raw("  daemon socket  "), if socket { Span::styled("● present", Style::new().fg(OK)) } else { Span::styled("✗ missing", Style::new().fg(ERR)) }]),
            Line::from(vec![Span::raw("  models         "),
                Span::styled(if std::path::Path::new("/home/wisbfime/irlume/models/glintr100.onnx").exists() { "present" } else { "?" }, Style::new().dim())]),
            Line::raw(""),
            Line::from(Span::styled("  [r] ping the daemon", Style::new())),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_activity(&self, f: &mut Frame, area: Rect) {
        let title = if let Some(op) = &self.op {
            Line::from(vec![Span::raw(" Activity  "), Span::styled(format!("{} {} ", SPINNER[self.spin], op.label), Style::new().fg(ACCENT))])
        } else {
            Line::from(" Activity (what irlume is doing) ")
        };
        let blk = Block::bordered().title(title).border_type(BorderType::Rounded).border_style(Style::new().dim());
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let h = inner.height as usize;
        let start = self.activity.len().saturating_sub(h);
        let lines: Vec<Line> = self.activity[start..].iter().map(|(g, m)| {
            let gs = match g { '→' => Style::new().fg(ACCENT), '✓' => Style::new().fg(OK), '✗' => Style::new().fg(ERR), _ => Style::new().dim() };
            Line::from(vec![Span::styled(format!("{g} "), gs), Span::raw(m.clone())])
        }).collect();
        f.render_widget(Paragraph::new(lines), inner);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let keys: &[(&str, &str)] = match self.screen {
            0 => &[("↑↓", "nav"), ("tab", "focus"), ("e", "enroll"), ("a", "add scan"), ("r", "rename"), ("d", "delete"), ("q", "quit")],
            1 => &[("↑↓", "menu"), ("tab", "focus"), ("enter", "toggle"), ("q", "quit")],
            2 => &[("↑↓", "menu"), ("tab", "focus"), ("s", "setup emitter"), ("p", "probe"), ("q", "quit")],
            3 => &[("↑↓", "menu"), ("tab", "focus"), ("f", "forget"), ("q", "quit")],
            _ => &[("↑↓", "menu"), ("tab", "focus"), ("r", "ping"), ("q", "quit")],
        };
        let mut spans = vec![Span::raw(" ")];
        for (k, d) in keys {
            spans.push(Span::styled(format!(" {k} "), Style::new().fg(Color::Black).bg(ACCENT)));
            spans.push(Span::styled(format!(" {d}   "), Style::new().dim()));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_modal(&self, f: &mut Frame, title: &str, body: &str) {
        let area = f.area();
        let w = (area.width.saturating_sub(8)).min(70).max(20);
        let rect = Rect { x: (area.width.saturating_sub(w)) / 2, y: area.height / 2 - 2, width: w, height: 5 };
        f.render_widget(Clear, rect);
        let blk = Block::bordered().title(format!(" {title} ")).border_type(BorderType::Rounded).border_style(Style::new().fg(ACCENT)).padding(ratatui::widgets::Padding::horizontal(1));
        f.render_widget(Paragraph::new(Line::from(body.to_string())).block(blk).wrap(Wrap { trim: true }), rect);
    }
}
