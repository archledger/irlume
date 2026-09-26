// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! irlume-created `/etc/pam.d` overrides of vendor PAM files.
//!
//! A distribution that ships a service only under `/usr/lib/pam.d` leaves no
//! `/etc` file to edit, so irlume writes an `/etc` copy of the vendor file with
//! its own lines added. That copy shadows the vendor file from then on: a
//! vendor update never reaches it, and an administrator may add lines to it.
//! This module holds everything about such a file that needs no filesystem:
//! its two header lines, whether anybody but irlume changed it, whether the
//! vendor file moved on since irlume wrote it, and the one decision every
//! caller takes for it (human enable and disable, reconcile, the machine plan
//! and apply, uninstall).
//!
//! In a file with an administrator's lines, irlume never lets its own writes
//! change what those lines do: a numeric jump in them keeps landing on the
//! same line, and irlume's lines stay on the same side of each of them. A
//! write that cannot keep both is not made.
//!
//! Pure: text in, text out. Nothing here reads a file, asks the daemon or reads
//! a capability, which is what lets reconcile maintain overrides without ever
//! unwiring anything on a capability reading.

use super::grammar::{
    self, content_has_module, directive, head, irlume_rule, is_auth_substack_anchor,
    is_include_auth_layout, is_passwd_substack,
};
use super::stanzas::{inert_line, BACKUP, CREATED_PREFIX, INERT_TAG, KEYRING_TAG};
use super::transform::{
    is_irlume_line, unwire_lines, wire_greeter_impl, wire_lock, wire_polkit_service,
    wire_verify_service,
};
use super::PlannedChange;

/// The second header line of an override irlume writes, followed by a version
/// token (`v1`) and that version's fields.
pub(super) const OVERRIDE_TRACK_PREFIX: &str = "# irlume: override ";

/// Most diff lines a human report prints for one file.
const DIFF_CAP: usize = 40;

/// The first header line. The same text releases that wrote only this line
/// used, so every reader, older binaries included, still recognizes the file
/// by its first bytes.
pub(super) fn created_line(vendor_path: &str) -> String {
    format!("{CREATED_PREFIX}{vendor_path}; delete this file to restore the vendor copy")
}

fn tracking_line(vendor_sha: &str, body_sha: &str) -> String {
    format!("{OVERRIDE_TRACK_PREFIX}v1 vendor-sha256={vendor_sha} body-sha256={body_sha}")
}

fn sha256(text: &str) -> String {
    crate::logintx::sha256_hex(text.as_bytes())
}

/// A tracking line of any version: the prefix, `v`, one or more digits, then a
/// space or the end of the line. Anything else that starts with the prefix is
/// an ordinary comment, so recording a tracking line never replaces one.
fn is_tracking_line(line: &str) -> bool {
    let Some(rest) = line
        .strip_prefix(OVERRIDE_TRACK_PREFIX)
        .and_then(|r| r.strip_prefix('v'))
    else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && (rest.len() == digits || rest.as_bytes()[digits] == b' ')
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The two digests of a `v1` tracking line, or `None` for anything this
/// version cannot read (a newer version, an extra field, bad hex). Fails
/// closed: an unreadable line makes the file legacy, the cautious class.
fn parse_v1(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix(OVERRIDE_TRACK_PREFIX)?;
    let mut parts = rest.split(' ');
    if parts.next()? != "v1" {
        return None;
    }
    let vendor = parts.next()?.strip_prefix("vendor-sha256=")?;
    let body = parts.next()?.strip_prefix("body-sha256=")?;
    if parts.next().is_some() || !is_sha256_hex(vendor) || !is_sha256_hex(body) {
        return None;
    }
    Some((vendor.to_string(), body.to_string()))
}

/// An override split into its header lines and its body.
pub(super) struct Parsed<'a> {
    first: &'a str,
    track_line: Option<&'a str>,
    /// `(vendor, body)` digests from a readable tracking line.
    digests: Option<(String, String)>,
    /// Every line except the two header lines, newline-terminated, without
    /// carriage returns.
    body: String,
    /// The file has a carriage return. Linux-PAM reads it as part of the
    /// line, so a file saved with CRLF endings names modules and stacks that
    /// do not exist and refuses every login. The digests leave it out, so
    /// such a file still reads as unedited; every write irlume makes to it
    /// has LF endings.
    crlf: bool,
}

/// Said when a write replaces CRLF line endings.
const CRLF_FIXED: &str = "its CRLF line endings, which PAM does not read, are now LF";

/// Split an override. `None` when the text is not one (no first header line).
///
/// The tracking line is looked for in the comment block above the first
/// directive rather than on line 2 alone, so a comment an administrator adds
/// under line 1 leaves the file tracked (and edited) instead of legacy.
pub(super) fn parse(content: &str) -> Option<Parsed<'_>> {
    if !content.starts_with(CREATED_PREFIX) {
        return None;
    }
    let lines: Vec<&str> = content.lines().collect();
    let first = *lines.first()?;
    let track_at = lines
        .iter()
        .enumerate()
        .skip(1)
        .take_while(|(_, l)| directive(l).is_empty())
        .find(|(_, l)| is_tracking_line(l))
        .map(|(i, _)| i);
    let body_lines: Vec<&str> = lines
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(i, _)| Some(*i) != track_at)
        .map(|(_, l)| l.trim_end_matches('\r'))
        .collect();
    let body = if body_lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", body_lines.join("\n"))
    };
    let track_line = track_at.map(|i| lines[i]);
    Some(Parsed {
        first,
        track_line,
        digests: track_line.and_then(parse_v1),
        body,
        crlf: content.contains('\r'),
    })
}

/// The text without irlume's lines, line endings normalized.
pub(super) fn base(text: &str) -> String {
    unwire_lines(text).0
}

/// The digest recorded as `body-sha256`: the body without irlume's lines. So
/// irlume rewriting its own lines (a method switch, a stanza migration) never
/// makes an override read as edited, while any other added, removed or changed
/// line does.
pub(super) fn body_digest(body: &str) -> String {
    sha256(&base(body))
}

/// A fresh override: both header lines, then the wired body.
pub(super) fn render(vendor_path: &str, vendor: &str, wired: &str) -> String {
    format!(
        "{}\n{}\n{wired}",
        created_line(vendor_path),
        tracking_line(&sha256(vendor), &body_digest(wired))
    )
}

/// The same header lines over a new body, for a write that keeps the file
/// rather than rebuilding it. The digests keep describing the last generation
/// on purpose: refreshing them here would make an edited file read as
/// unedited, and the next vendor change would then rebuild it.
fn keep_header(p: &Parsed<'_>, body: &str) -> String {
    match p.track_line {
        Some(track) => format!("{}\n{track}\n{body}", p.first),
        None => format!("{}\n{body}", p.first),
    }
}

fn normalize(text: &str) -> String {
    format!("{}\n", text.lines().collect::<Vec<_>>().join("\n"))
}

/// What an override is, compared with the vendor file it was made from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// Tracked, unedited, and the vendor file is the one it was built from.
    U1,
    /// Tracked and unedited; the vendor file changed since.
    U2,
    /// Tracked and unedited; the vendor file is gone.
    U3,
    /// Its lines other than irlume's are exactly the current vendor file's:
    /// a file that predates tracking, or a tracked one edited back to the
    /// vendor copy. Rebuilding it loses nothing.
    L1,
    /// Tracked and edited; the vendor file is the one it was built from.
    E1,
    /// Tracked and edited; the vendor file changed since.
    E2,
    /// Tracked and edited; the vendor file is gone.
    E3,
    /// Predates tracking and differs from the vendor file: the vendor may
    /// have changed, an administrator may have edited it, or both.
    L2,
    /// Predates tracking; the vendor file is gone.
    L3,
}

impl Class {
    /// Whether the file may hold lines an administrator wrote.
    fn edited(self) -> bool {
        !matches!(self, Class::U1 | Class::U2 | Class::U3 | Class::L1)
    }
}

pub(super) fn classify(p: &Parsed<'_>, vendor: Option<&str>) -> Class {
    use Class::*;
    if let Some((vendor_sha, body_sha)) = &p.digests {
        if body_digest(&p.body) == *body_sha {
            return match vendor {
                None => U3,
                Some(v) if sha256(v) == *vendor_sha => U1,
                Some(_) => U2,
            };
        }
    }
    if let Some(v) = vendor {
        if base(&p.body) == base(v) {
            return L1;
        }
    }
    match (&p.digests, vendor) {
        (Some((vendor_sha, _)), Some(v)) if sha256(v) == *vendor_sha => E1,
        (Some(_), Some(_)) => E2,
        (Some(_), None) => E3,
        (None, Some(_)) => L2,
        (None, None) => L3,
    }
}

fn has_irlume_line(text: &str) -> bool {
    text.lines().any(is_irlume_line)
}

/// Whether irlume's lines in `text` are held by inactive lines (see
/// [`neutralize`]) and none of them is live.
fn only_inert_lines(text: &str) -> bool {
    !content_has_module(text)
        && text
            .lines()
            .any(|l| is_irlume_line(l) && l.contains(INERT_TAG))
}

fn norm(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// irlume's lines as a sorted list, so two files compare by WHICH lines irlume
/// has in them and not where. An administrator may have placed an edited
/// file's lines around irlume's deliberately; moving irlume's lines back is a
/// change of its own, made only as a named migration.
fn irlume_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| is_irlume_line(l))
        .map(norm)
        .collect();
    lines.sort();
    lines
}

// ---- irlume's lines by job -------------------------------------------------------

const PHASES: [&str; 4] = ["auth", "account", "password", "session"];

/// The phase of a PAM line, without the `-` that tolerates a missing module,
/// read as libpam reads the type (a bracketed `[auth]` included). `None` for
/// a comment, an `@include` or anything else.
fn phase(line: &str) -> Option<&'static str> {
    head(line).map(|h| h.phase)
}

/// What one of irlume's lines is for, so an old and a new version of it can
/// be paired: its phase and its job. The job is the module argument that
/// names it (`unseal`, `keyring`, `reseal`, or nothing for a verify stanza),
/// `landing` for the permit landing, `keyring-tag` for a gnome-keyring line
/// irlume added. An inactive line holding the place of one of irlume's lines
/// has the kind of the line it replaced.
fn kind(line: &str) -> String {
    let phase = phase(line).unwrap_or("auth");
    let job = if let Some((_, rest)) = line.split_once(INERT_TAG) {
        rest.split_whitespace().next().unwrap_or("").to_string()
    } else if line.contains("# irlume-landing") {
        "landing".to_string()
    } else if line.contains(KEYRING_TAG) {
        "keyring-tag".to_string()
    } else {
        irlume_rule(line)
            .and_then(|r| r.args.first().copied())
            .unwrap_or("")
            .to_string()
    };
    format!("{phase} {job}")
}

/// `body` with every rule loading pam_irlume.so replaced by an inactive line of
/// the same phase and job, in the same place. Every other line stays, irlume's
/// permit landing included. So every numeric jump counts the same lines and
/// lands where it did, and the stack runs as the wired one does when
/// pam_irlume.so returns `PAM_IGNORE`, which it does whenever it cannot help
/// (no daemon, no match, an error): a state the wired stack must already be
/// safe in.
fn neutralize(body: &str) -> String {
    let lines: Vec<String> = body
        .lines()
        .map(|l| {
            if irlume_rule(l).is_some() {
                let k = kind(l);
                let (phase, job) = k.split_once(' ').unwrap_or((k.as_str(), ""));
                inert_line(phase, job)
            } else {
                l.to_string()
            }
        })
        .collect();
    format!("{}\n", lines.join("\n"))
}

/// `body` with irlume's lines updated in their own places: each line of
/// irlume's takes the line `wired` has for the same job (see [`kind`]), an
/// inactive line holding a place included, and a rule loading pam_irlume.so
/// that `wired` has no line for becomes an inactive line in the same place.
/// irlume's other lines (its permit landing, its tagged keyring lines, and
/// inactive lines `wired` does not fill) stay as they are. So every line
/// keeps its position and no jump that counts irlume's lines moves.
///
/// `None` when `wired` has a line of irlume's that `body` has no place for:
/// adding one is a move of its own, which [`arrange`] and [`check_jumps`]
/// decide.
fn fill_slots(body: &str, wired: &str) -> Option<String> {
    let mut wanted: Vec<(String, &str)> = wired
        .lines()
        .filter(|l| is_irlume_line(l))
        .map(|l| (kind(l), l))
        .collect();
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        if !is_irlume_line(line) {
            out.push(line.to_string());
            continue;
        }
        let k = kind(line);
        if let Some(at) = wanted.iter().position(|(w, _)| *w == k) {
            out.push(wanted.remove(at).1.to_string());
        } else if irlume_rule(line).is_some() {
            let (phase, job) = k.split_once(' ').unwrap_or((k.as_str(), ""));
            out.push(inert_line(phase, job));
        } else {
            out.push(line.to_string());
        }
    }
    wanted.is_empty().then(|| format!("{}\n", out.join("\n")))
}

/// Where each numeric jump of irlume's own rules lands, keyed by the rule's
/// kind and the action: what [`fill_slots`] must leave as the recipe has it.
fn own_landings(text: &str) -> Vec<(String, String, Landing)> {
    let mut out = Vec::new();
    for phase_name in PHASES {
        let chain = chain(text, phase_name);
        for (at, line) in chain.iter().enumerate() {
            if irlume_rule(line).is_none() {
                continue;
            }
            for (key, n) in numeric_actions(line) {
                out.push((kind(line), key, landing_of(&chain, at, n)));
            }
        }
    }
    out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    out
}

/// [`fill_slots`] as an alternative to a write [`check_jumps`] refused: the
/// filled file when it moves no jump of the other lines and irlume's own
/// jumps land as they do in `wired`.
fn filled_in_place(body: &str, wired: &str, edited: bool) -> Option<(String, JumpCheck)> {
    let filled = fill_slots(body, wired)?;
    if own_landings(&filled) != own_landings(wired) {
        return None;
    }
    match check_jumps(body, &filled, edited) {
        JumpCheck::Refuse(_) => None,
        check => Some((filled, check)),
    }
}

// ---- numeric jumps -------------------------------------------------------------
//
// A control such as `[success=2 default=ignore]` skips the next two modules of
// its phase. An administrator who writes one into an override counts irlume's
// lines as they stand, so a write that adds, removes or moves irlume's lines
// can make that jump land somewhere else with nothing reported, which changes
// what the administrator's line does.

/// Where a numeric jump lands.
#[derive(Clone, Debug)]
pub(super) enum Landing {
    /// On this line. Two landings are the same when their `key` is: the line
    /// itself, whitespace normalized, or for one of irlume's lines its job
    /// (see [`kind`]), so a new version of irlume's line, or an inactive line
    /// holding its place, is the same landing. `text` is for messages.
    Line { key: String, text: String },
    /// Just past the last module of the phase: the stack ends there.
    End,
    /// Past the end of the stack, which libpam logs as a bad jump and fails.
    PastEnd,
    /// The skipped lines include an `include`, whose expansion irlume cannot
    /// count. Equal only when the same lines are skipped to the same target.
    Across {
        skipped: Vec<String>,
        target: Option<String>,
    },
}

impl PartialEq for Landing {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Landing::Line { key: a, .. }, Landing::Line { key: b, .. }) => a == b,
            (Landing::End, Landing::End) | (Landing::PastEnd, Landing::PastEnd) => true,
            (
                Landing::Across {
                    skipped: a,
                    target: t,
                },
                Landing::Across {
                    skipped: b,
                    target: u,
                },
            ) => a == b && t == u,
            _ => false,
        }
    }
}

impl Eq for Landing {}

impl Landing {
    fn describe(&self, phase: &str) -> String {
        match self {
            Landing::Line { text, .. } => format!("`{text}`"),
            Landing::End => format!("the end of the {phase} stack"),
            Landing::PastEnd => format!("past the end of the {phase} stack, which fails it"),
            Landing::Across { .. } => {
                "a line irlume cannot name, because the jump crosses an include".to_string()
            }
        }
    }
}

/// How a landing identifies a line: see [`Landing::Line`].
fn line_key(line: &str) -> String {
    if is_irlume_line(line) {
        format!("irlume {}", kind(line))
    } else {
        norm(line)
    }
}

/// The lines libpam puts in one phase's chain, one module each (a `substack`
/// counts as one; an `include` expands to lines this file does not show).
fn chain<'a>(text: &'a str, phase_name: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|l| directive(l).starts_with("@include") || phase(l) == Some(phase_name))
        .collect()
}

fn is_include(line: &str) -> bool {
    directive(line).starts_with("@include")
        || head(line).is_some_and(|h| h.control.eq_ignore_ascii_case("include"))
}

/// The numeric actions of a line's control, as `(value, count)` (see
/// [`grammar::numeric_actions`]).
fn numeric_actions(line: &str) -> Vec<(String, usize)> {
    head(line).map_or_else(Vec::new, |h| grammar::numeric_actions(&h))
}

fn landing_of(chain: &[&str], at: usize, n: usize) -> Landing {
    let last = chain.len() - 1;
    if n > last - at {
        return Landing::PastEnd;
    }
    let skipped = &chain[at + 1..=at + n];
    let target = chain.get(at + n + 1).copied();
    if skipped.iter().any(|l| is_include(l)) {
        return Landing::Across {
            skipped: skipped.iter().map(|l| line_key(l)).collect(),
            target: target.map(line_key),
        };
    }
    match target {
        Some(line) => Landing::Line {
            key: line_key(line),
            text: norm(line),
        },
        None => Landing::End,
    }
}

/// One numeric action of a line irlume did not write. Identified by the line's
/// text, which occurrence of that text it is, and the action's value.
struct Jump {
    phase: &'static str,
    line: String,
    ordinal: usize,
    key: String,
    landing: Landing,
    /// The lines it skips (see [`line_key`]).
    skipped: Vec<String>,
}

/// Every numeric action in every phase, of the lines irlume did not write.
fn jumps(text: &str) -> Vec<Jump> {
    let mut out = Vec::new();
    for phase_name in PHASES {
        let chain = chain(text, phase_name);
        let mut seen: Vec<(String, usize)> = Vec::new();
        for (at, line) in chain.iter().enumerate() {
            if is_irlume_line(line) {
                continue;
            }
            let actions = numeric_actions(line);
            if actions.is_empty() {
                continue;
            }
            let text = norm(line);
            let ordinal = match seen.iter_mut().find(|(t, _)| *t == text) {
                Some((_, count)) => {
                    *count += 1;
                    *count
                }
                None => {
                    seen.push((text.clone(), 1));
                    1
                }
            };
            for (key, n) in actions {
                let skipped = chain
                    .iter()
                    .skip(at + 1)
                    .take(n)
                    .map(|l| line_key(l))
                    .collect();
                out.push(Jump {
                    phase: phase_name,
                    line: text.clone(),
                    ordinal,
                    key,
                    landing: landing_of(&chain, at, n),
                    skipped,
                });
            }
        }
    }
    out
}

fn has_numeric_jump(text: &str) -> bool {
    !jumps(text).is_empty()
}

/// A jump irlume did not write that lands somewhere else after a write.
pub(super) struct Shift {
    phase: &'static str,
    line: String,
    now: Landing,
}

fn find_landing(set: &[Jump], j: &Jump) -> Option<Landing> {
    set.iter()
        .find(|o| o.line == j.line && o.ordinal == j.ordinal && o.key == j.key)
        .map(|o| o.landing.clone())
}

/// Every jump in `after` that a line irlume did not write carries and that
/// lands somewhere other than it did in `before`. A jump `before` does not have
/// (a vendor update added it) is compared with the same file without irlume's
/// lines instead: irlume's lines must not change where it lands.
pub(super) fn jump_shifts(before: &str, after: &str) -> Vec<Shift> {
    let old = jumps(before);
    let unwired = jumps(&base(after));
    let mut out: Vec<Shift> = Vec::new();
    for j in jumps(after) {
        let reference = find_landing(&old, &j).or_else(|| find_landing(&unwired, &j));
        if reference.is_some_and(|r| r != j.landing) && !out.iter().any(|s| s.line == j.line) {
            out.push(Shift {
                phase: j.phase,
                line: j.line,
                now: j.landing,
            });
        }
    }
    out
}

/// The jumps taking irlume's lines out of `body` moves (see [`jump_shifts`]),
/// except one that then skips the same lines and lands on the same line as in
/// the vendor copy: irlume's lines had moved that jump, and taking them out
/// gives it back the vendor's own behaviour.
fn strip_shifts(body: &str, stripped: &str, vendor: Option<&str>) -> Vec<Shift> {
    let shifts = jump_shifts(body, stripped);
    let Some(v) = vendor else {
        return shifts;
    };
    let vendor_jumps = jumps(&base(v));
    let stripped_jumps = jumps(stripped);
    let as_vendor_has_it = |j: &&Jump| {
        vendor_jumps.iter().any(|o| {
            o.line == j.line
                && o.ordinal == j.ordinal
                && o.key == j.key
                && o.landing == j.landing
                && o.skipped == j.skipped
        })
    };
    // A shift is reported once per line, so it is dropped only when every
    // jump of that line is as the vendor has it.
    shifts
        .into_iter()
        .filter(|s| {
            !stripped_jumps
                .iter()
                .filter(|j| j.line == s.line)
                .all(|j| as_vendor_has_it(&j))
        })
        .collect()
}

fn shift_reason(shifts: &[Shift]) -> String {
    let first = &shifts[0];
    let more = match shifts.len() {
        1 => String::new(),
        n => format!(" (and {} more)", n - 1),
    };
    format!(
        "the jump in `{}` would then land on {}{more}",
        first.line,
        first.now.describe(first.phase)
    )
}

fn shift_warnings(shifts: &[Shift], why: &str) -> String {
    shifts
        .iter()
        .map(|s| {
            format!(
                "\n    ⚠ `{}` now jumps to {}{why}; check that jump",
                s.line,
                s.now.describe(s.phase)
            )
        })
        .collect()
}

/// What a write would do to the numeric jumps in lines irlume did not write.
enum JumpCheck {
    /// No jump lands anywhere new.
    Clear,
    /// A jump the vendor copy carries moves in a file nobody edited that has
    /// none of irlume's lines now, as it does when irlume first creates the
    /// override. The write goes ahead and says where each lands.
    Warn(String),
    /// A jump moves in a file an administrator may have written it into, or
    /// while irlume's lines are in the file and it may count them. Why, for
    /// the message.
    Refuse(String),
}

/// The jumps a write moves because of irlume's lines: each lands somewhere
/// other than it did in `before` (or is new), and somewhere other than it
/// would with irlume's lines taken out. A vendor file that changed the lines
/// inside its own jump moves that jump without irlume's help, and an
/// arrangement the file already had is not new; neither counts.
fn jumps_moved_by_irlume(before: &str, after: &str) -> Vec<Shift> {
    let old = jumps(before);
    let unwired = jumps(&base(after));
    let mut out: Vec<Shift> = Vec::new();
    for j in jumps(after) {
        let moved_by_irlume = find_landing(&unwired, &j).is_some_and(|bare| bare != j.landing);
        let changed = find_landing(&old, &j).is_none_or(|prior| prior != j.landing);
        if moved_by_irlume && changed && !out.iter().any(|s| s.line == j.line) {
            out.push(Shift {
                phase: j.phase,
                line: j.line,
                now: j.landing,
            });
        }
    }
    out
}

/// `edited`: the file may hold an administrator's lines, and so jumps written
/// by someone who counted what they saw.
fn check_jumps(before: &str, after: &str, edited: bool) -> JumpCheck {
    let shifts = jumps_moved_by_irlume(before, after);
    if shifts.is_empty() {
        JumpCheck::Clear
    } else if edited || has_irlume_line(before) {
        JumpCheck::Refuse(shift_reason(&shifts))
    } else {
        JumpCheck::Warn(shift_warnings(&shifts, " once irlume's lines are in"))
    }
}

// ---- where irlume's lines go in a file it keeps --------------------------------

/// The longest-common-subsequence table of two line lists. PAM files are a
/// few dozen lines, so the quadratic table is fine.
fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<usize>> {
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    lcs
}

/// For each line of `ours`, whether the longest common subsequence with
/// `theirs` that [`line_diff`] reports keeps it.
fn common_lines(ours: &[&str], theirs: &[&str]) -> Vec<bool> {
    let lcs = lcs_table(ours, theirs);
    let (mut i, mut j) = (0, 0);
    let mut out = vec![false; ours.len()];
    while i < ours.len() && j < theirs.len() {
        if ours[i] == theirs[j] {
            out[i] = true;
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// What PAM reads of a line, whitespace normalized: how irlume compares a
/// file's lines with its vendor copy's. A comment added to a vendor line
/// leaves it the vendor's line, and a blank or comment line, which PAM does
/// not read, is empty.
fn pam_key(line: &str) -> String {
    norm(directive(line))
}

/// For each line of `bare` (a file without irlume's lines), whether an
/// administrator may have written it.
///
/// In a file nobody edited (`edited` false) none is. Otherwise it is a line
/// PAM reads that the vendor copy does not have there, matched on what PAM
/// reads by a longest common subsequence. A line whose text the file has more
/// often than the vendor copy is an administrator's copy, and since the match
/// cannot tell which copy is the vendor's, every copy counts as theirs. With
/// no vendor copy to compare with, every line PAM reads may be theirs. A
/// blank or comment line never is: moving past it changes nothing PAM does.
fn own_lines(bare: &str, vendor: Option<&str>, edited: bool) -> Vec<bool> {
    let ours: Vec<String> = bare.lines().map(pam_key).collect();
    if !edited {
        return vec![false; ours.len()];
    }
    let Some(v) = vendor else {
        return ours.iter().map(|k| !k.is_empty()).collect();
    };
    let read: Vec<usize> = (0..ours.len()).filter(|&i| !ours[i].is_empty()).collect();
    let a: Vec<&str> = read.iter().map(|&i| ours[i].as_str()).collect();
    let theirs: Vec<String> = base(v)
        .lines()
        .map(pam_key)
        .filter(|k| !k.is_empty())
        .collect();
    let b: Vec<&str> = theirs.iter().map(String::as_str).collect();
    let count = |set: &[&str], key: &str| set.iter().filter(|k| **k == key).count();
    let common = common_lines(&a, &b);
    let mut own = vec![false; ours.len()];
    for (n, &i) in read.iter().enumerate() {
        own[i] = !common[n] || count(&a, a[n]) > count(&b, a[n]);
    }
    own
}

/// Each of irlume's lines in `text` with its kind and its slot: how many of
/// the administrator's lines (`own`, indexed by the lines irlume did not
/// write) come before it.
fn slots(text: &str, own: &[bool]) -> Vec<(String, usize)> {
    let (mut seen, mut admin) = (0usize, 0usize);
    let mut out = Vec::new();
    for line in text.lines() {
        if is_irlume_line(line) {
            out.push((kind(line), admin));
        } else {
            if own.get(seen).copied().unwrap_or(true) {
                admin += 1;
            }
            seen += 1;
        }
    }
    out
}

/// The first administrator's line `candidate` would move one of irlume's
/// lines past, compared with `body`; both have the same lines irlume did not
/// write. A line of a kind `body` has must keep its slot; a line of a new kind
/// may only go into a slot where irlume already has a line.
fn crossing(body: &str, candidate: &str, bare: &str, own: &[bool]) -> Option<String> {
    let admin_lines: Vec<&str> = bare
        .lines()
        .zip(own)
        .filter(|(_, admin)| **admin)
        .map(|(l, _)| l)
        .collect();
    let before = slots(body, own);
    let held: Vec<usize> = before.iter().map(|(_, s)| *s).collect();
    let mut paired: Vec<(String, usize)> = Vec::new();
    for (k, slot) in slots(candidate, own) {
        let n = match paired.iter_mut().find(|(pk, _)| *pk == k) {
            Some((_, count)) => {
                *count += 1;
                *count - 1
            }
            None => {
                paired.push((k.clone(), 1));
                0
            }
        };
        let old = before
            .iter()
            .filter(|(bk, _)| *bk == k)
            .nth(n)
            .map(|(_, s)| *s);
        let other = match old {
            Some(o) if o == slot => continue,
            Some(o) => o,
            None if held.contains(&slot) => continue,
            None => held
                .iter()
                .copied()
                .min_by_key(|h| h.abs_diff(slot))
                .unwrap_or(slot),
        };
        let crossed = slot.min(other);
        return Some(
            admin_lines
                .get(crossed)
                .map_or_else(String::new, |l| norm(l)),
        );
    }
    None
}

/// `body` with each of irlume's lines replaced by the line of the same kind in
/// `candidate`, in order: the new text in the old places. A line of a kind
/// `candidate` has fewer of (a stray copy, or a job the new settings drop) is
/// removed. `None` when `candidate` has a line with no old place to take.
fn substitute(body: &str, candidate: &str) -> Option<String> {
    let mut want: Vec<(String, &str)> = candidate
        .lines()
        .filter(|l| is_irlume_line(l))
        .map(|l| (kind(l), l))
        .collect();
    let mut out = Vec::new();
    for line in body.lines() {
        if is_irlume_line(line) {
            let k = kind(line);
            if let Some(at) = want.iter().position(|(wk, _)| *wk == k) {
                out.push(want.remove(at).1.to_string());
            }
        } else {
            out.push(line.to_string());
        }
    }
    want.is_empty().then(|| format!("{}\n", out.join("\n")))
}

/// The index of the password line of `bare` (a file without irlume's lines
/// that may hold an administrator's): the line irlume wires next to when none
/// of its lines are in such a file.
///
/// It is the first line that includes or substacks a shared password stack
/// irlume knows by name, else the first auth substack. With a vendor copy it
/// is the first such line that is not an administrator's (`own`). Without one
/// (`vendor_known` false) every line may be an administrator's, so it is the
/// first such line, taken only when no other line of the file has its text.
fn password_line(bare: &str, own: &[bool], vendor_known: bool) -> Option<usize> {
    let lines: Vec<&str> = bare.lines().collect();
    let named = |l: &str| is_include_auth_layout(l) || is_passwd_substack(l, "auth");
    let first = |take: &dyn Fn(usize) -> bool| {
        (0..lines.len())
            .find(|&i| named(lines[i]) && take(i))
            .or_else(|| (0..lines.len()).find(|&i| is_auth_substack_anchor(lines[i]) && take(i)))
    };
    if vendor_known {
        return first(&|i| !own.get(i).copied().unwrap_or(true));
    }
    let k = first(&|_| true)?;
    let key = pam_key(lines[k]);
    (lines.iter().filter(|l| pam_key(l) == key).count() == 1).then_some(k)
}

/// Whether taking irlume's lines out of `body` would leave a file irlume
/// cannot wire again where they are: an edited file (`edited`) whose password
/// line irlume cannot tell (see [`password_line`]). A disable then keeps
/// inactive lines in their places, as it does for a jump that counts them.
fn strip_loses_place(body: &str, vendor: Option<&str>, edited: bool) -> bool {
    let bare = base(body);
    edited && password_line(&bare, &own_lines(&bare, vendor, true), vendor.is_some()).is_none()
}

/// `wire` applied from the file's password line on (see [`password_line`]),
/// in a file with none of irlume's lines that may hold an administrator's:
/// every line above it (a faillock or a group gate, the vendor's or not)
/// stays above irlume's lines, which the recipe puts next to it. `None` when
/// there is no such line, the recipe refuses, or the recipe anchors on
/// another line.
fn anchored(
    bare: &str,
    own: &[bool],
    vendor_known: bool,
    wire: &dyn Fn(&str) -> (String, bool),
) -> Option<String> {
    let lines: Vec<&str> = bare.lines().collect();
    let k = password_line(bare, own, vendor_known)?;
    let (tail, ok) = wire(&format!("{}\n", lines[k..].join("\n")));
    if !ok {
        return None;
    }
    // Every recipe puts one of its lines directly above or below the line it
    // anchors on, and that line is the first of the tail it did not write.
    let t: Vec<&str> = tail.lines().collect();
    let at = t.iter().position(|l| !is_irlume_line(l))?;
    let irlume_at = |j: Option<usize>| j.and_then(|j| t.get(j)).is_some_and(|l| is_irlume_line(l));
    if !irlume_at(at.checked_sub(1)) && !irlume_at(Some(at + 1)) {
        return None;
    }
    Some(if k == 0 {
        tail
    } else {
        format!("{}\n{tail}", lines[..k].join("\n"))
    })
}

/// Why irlume's lines cannot be updated in a file it keeps.
enum Misplaced {
    /// The update would move one of irlume's lines past this line, which an
    /// administrator may have placed around irlume's on purpose.
    Crossing(String),
    /// The file has none of irlume's lines and no password stack irlume can
    /// tell is not an administrator's to wire next to (see [`anchored`]).
    NoPasswordAnchor,
}

/// Where irlume's lines go when it updates them in a file it keeps.
///
/// `wired` is the recipe applied to the file without irlume's lines. In a
/// file nobody edited (`edited` false) every line is the vendor's, so it is
/// used as a rebuild would use it. Otherwise it is used when it keeps each of
/// irlume's lines on the same side of every line an administrator added. The
/// recipe anchors on the first auth line of some shapes (sudo, polkit), which
/// can be an administrator's faillock or group gate above irlume's line; then
/// each new line takes the place of the old one of the same kind instead,
/// which covers a change of irlume's line text such as the polkit stanza
/// migration. A file with none of irlume's lines gets them next to its
/// password stack, below every line above it (see [`anchored`]).
fn arrange(
    body: &str,
    bare: &str,
    wired: String,
    vendor: Option<&str>,
    edited: bool,
    wire: &dyn Fn(&str) -> (String, bool),
) -> Result<String, Misplaced> {
    let own = own_lines(bare, vendor, edited);
    if !has_irlume_line(body) {
        if !edited {
            return Ok(wired);
        }
        return anchored(bare, &own, vendor.is_some(), wire).ok_or(Misplaced::NoPasswordAnchor);
    }
    match crossing(body, &wired, bare, &own) {
        None => Ok(wired),
        Some(line) => substitute(body, &wired).ok_or(Misplaced::Crossing(line)),
    }
}

// ---- the human diff ------------------------------------------------------------

/// A plain line diff: `- ` for a line only in `ours`, `+ ` for one only in
/// `theirs`, unchanged lines left out.
pub(super) fn line_diff(ours: &str, theirs: &str) -> Vec<String> {
    let a: Vec<&str> = ours.lines().collect();
    let b: Vec<&str> = theirs.lines().collect();
    let (n, m) = (a.len(), b.len());
    let lcs = lcs_table(&a, &b);
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < n && j < m {
        if a[i] == b[j] {
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(format!("- {}", a[i]));
            i += 1;
        } else {
            out.push(format!("+ {}", b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|l| format!("- {l}")));
    out.extend(b[j..].iter().map(|l| format!("+ {l}")));
    out
}

fn diff_block(etc: &str, vendor_path: &str, body: &str, vendor: &str) -> String {
    let lines = line_diff(&base(body), &base(vendor));
    let mut out = format!(
        "    lines that differ from {vendor_path} (irlume's own lines not shown; \
         - only in {etc}, + only in {vendor_path}):"
    );
    for line in lines.iter().take(DIFF_CAP) {
        out.push_str("\n    ");
        out.push_str(line);
    }
    if lines.len() > DIFF_CAP {
        out.push_str(&format!("\n    … {} more", lines.len() - DIFF_CAP));
    }
    out
}

/// `stale`: `<etc>.pre-irlume` already holds a different file, which stops
/// `--force` until it is moved away.
fn force_hint(etc: &str, vendor_path: &str, scope_flag: &str, stale: bool) -> String {
    let first = if stale {
        format!("\n      move {etc}{BACKUP} away first: it holds a different file")
    } else {
        String::new()
    };
    format!(
        "\n    to rebuild it from {vendor_path} and keep this file as {etc}{BACKUP}:{first}\
         \n      irlume login enable{scope_flag} --force   (preview)\
         \n      sudo irlume login enable{scope_flag} --apply --force"
    )
}

/// Whether `<etc>.pre-irlume` holds a file other than the current one.
fn stale_backup(i: &Input<'_>) -> bool {
    i.backup.is_some_and(|b| Some(b) != i.current)
}

/// How many lines the vendor copy has that the file lacks, when that is the
/// only way the file differs from it: every line irlume did not write is the
/// vendor's, in the vendor's order. The vendor added lines after irlume wrote
/// the file, or someone deleted them; irlume cannot tell which, so such a
/// file is kept like any other it did not write, and says so.
fn lacks(body: &str, vendor: Option<&str>) -> Option<usize> {
    let diff = line_diff(&base(body), &base(vendor?));
    (!diff.is_empty() && diff.iter().all(|l| l.starts_with("+ "))).then_some(diff.len())
}

fn lines_word(n: usize) -> String {
    match n {
        1 => "1 line".to_string(),
        n => format!("{n} lines"),
    }
}

// ---- the decision --------------------------------------------------------------

/// Everything the decision for one override needs, read by the caller.
pub(super) struct Input<'a> {
    pub(super) etc: &'a str,
    pub(super) vendor_path: &'a str,
    /// The `/etc` file, which must be an override, or `None` when absent.
    pub(super) current: Option<&'a str>,
    /// The vendor file, or `None` when absent. An unreadable one is the
    /// caller's error: it is never treated as removed.
    pub(super) vendor: Option<&'a str>,
    /// `<etc>.pre-irlume`, when there is one.
    pub(super) backup: Option<&'a str>,
    /// Whether this run wants irlume's lines in the file.
    pub(super) enable: bool,
    /// `login enable --force`: rebuild an edited override from the vendor file.
    pub(super) force: bool,
    /// ` --with-sudo` or ` --with-polkit` for the hint, or empty.
    pub(super) scope_flag: &'a str,
    pub(super) wire: &'a dyn Fn(&str) -> (String, bool),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Write {
    Nothing,
    Replace(String),
    Remove,
}

pub(super) struct Decision {
    pub(super) change: PlannedChange,
    pub(super) write: Write,
    /// Copy the current file to `<etc>.pre-irlume` before the write.
    pub(super) keep_copy: bool,
    pub(super) message: String,
    /// The diff and the `--force` hint, for a human run.
    pub(super) detail: Option<String>,
    /// irlume's lines in the file are not the ones this run wanted: updating
    /// or adding them was refused, and the file keeps what it has.
    pub(super) unmet: bool,
    /// The write adds the tracking line to a file and changes no PAM line.
    /// A file that may not be written (immutable, or on a read-only mount)
    /// then loses nothing by being left as it is.
    pub(super) header_only: bool,
}

fn keep(change: PlannedChange, message: String) -> Decision {
    Decision {
        change,
        write: Write::Nothing,
        keep_copy: false,
        message,
        detail: None,
        unmet: false,
        header_only: false,
    }
}

fn replace(change: PlannedChange, content: String, message: String) -> Decision {
    Decision {
        change,
        write: Write::Replace(content),
        keep_copy: false,
        message,
        detail: None,
        unmet: false,
        header_only: false,
    }
}

fn no_anchor(etc: &str) -> Decision {
    keep(
        PlannedChange::NoAnchor,
        format!("· {etc}: no anchor to wire (skipped)"),
    )
}

/// The one decision for an irlume-created override, whoever runs it.
///
/// An override with lines irlume did not write is never rebuilt from the
/// vendor file without `force`; irlume updates only its own lines in it, and
/// only when that changes neither where a jump in the other lines lands nor
/// which side of them its lines are on. One nobody edited follows the vendor
/// file. One whose vendor file is gone is the service's only configuration
/// and is never deleted.
///
/// # Errors
///
/// The current file is not an override (it changed after the caller looked),
/// or `force` would replace a different `<etc>.pre-irlume`.
pub(super) fn decide(i: &Input<'_>) -> Result<Decision, String> {
    use Class::*;
    let etc = i.etc;
    let Some(current) = i.current else {
        return Ok(match (i.enable, i.vendor) {
            (false, _) => keep(PlannedChange::NotWired, format!("· {etc}: not wired")),
            (true, None) => keep(
                PlannedChange::NotInstalled,
                format!("· {etc}: not installed (skipped)"),
            ),
            (true, Some(v)) => {
                let (wired, ok) = (i.wire)(&base(v));
                if !ok {
                    no_anchor(etc)
                } else {
                    let warn = match check_jumps(&base(v), &wired, false) {
                        JumpCheck::Warn(w) => w,
                        _ => String::new(),
                    };
                    replace(
                        PlannedChange::MaterializeOverride,
                        render(i.vendor_path, v, &wired),
                        format!(
                            "✓ {etc}: materialized override from {}{warn}",
                            i.vendor_path
                        ),
                    )
                }
            }
        });
    };
    let Some(p) = parse(current) else {
        return Err(format!(
            "{etc} changed while irlume was reading it; not touched"
        ));
    };
    let class = classify(&p, i.vendor);
    if !i.enable {
        return Ok(remove_or_strip(i, &p, class));
    }
    if i.force && matches!(class, E1 | E2 | L2) {
        return forced(i, current, &p);
    }
    Ok(match class {
        U3 | E3 | L3 => vendor_gone(i, &p, class),
        U1 | U2 | L1 => rebuild(i, current, &p, class),
        E1 | E2 | L2 => rewire_edited(i, &p, class),
    })
}

/// Disable. A file nobody edited is deleted, which restores the vendor copy.
/// Any other is kept: irlume's lines are removed from it, or replaced by
/// inactive lines in the same places when a numeric jump in the other lines
/// counts them and would land somewhere else without them, or when irlume
/// could not tell where to put them back without them (see
/// [`strip_loses_place`]).
fn remove_or_strip(i: &Input<'_>, p: &Parsed<'_>, class: Class) -> Decision {
    let (etc, vendor_path) = (i.etc, i.vendor_path);
    if matches!(class, Class::U1 | Class::U2 | Class::L1) {
        // Vendor text plus irlume's lines: deleting it loses nothing.
        return Decision {
            write: Write::Remove,
            ..keep(
                PlannedChange::RemoveOverride,
                format!("✓ {etc}: removed override (vendor restored)"),
            )
        };
    }
    let (stripped, had) = unwire_lines(&p.body);
    if !had {
        return keep(PlannedChange::NotWired, format!("· {etc}: not wired"));
    }
    let kept_why = match (i.vendor, lacks(&p.body, i.vendor)) {
        (None, _) => {
            format!("{vendor_path} is gone, so this file is the service's only configuration")
        }
        (Some(_), Some(n)) => format!(
            "it lacks {} {vendor_path} has, and irlume cannot tell whether they were removed on \
             purpose; delete it to use {vendor_path}",
            lines_word(n)
        ),
        (Some(_), None) => {
            format!("it has lines irlume did not write; delete it to use {vendor_path}")
        }
    };
    let shifts = strip_shifts(&p.body, &stripped, i.vendor);
    // Why removing irlume's lines would change the file's behaviour or lose
    // their places, and when a later disable can remove them after all.
    let held = if !shifts.is_empty() {
        let why = shift_reason(&shifts).replacen("would then land on", "would land on", 1);
        Some((
            format!("change a jump: without them {why}"),
            format!("without them {why}"),
            "once that jump no longer counts them",
        ))
    } else if strip_loses_place(&p.body, i.vendor, class.edited()) {
        let why = "irlume could not tell where to put them back";
        Some((
            format!("lose their places: {why}"),
            format!("without them {why}"),
            "once the file has a password line irlume can tell apart",
        ))
    } else {
        None
    };
    let (body, message) = match held {
        None => (
            stripped,
            format!("✓ {etc}: removed irlume's lines and kept the file; {kept_why}"),
        ),
        Some((change, without, until)) => {
            // Inactive lines in their places keep every jump where it lands
            // now, and keep the places for the next enable.
            let inert = neutralize(&p.body);
            if inert == normalize(&p.body) {
                return keep(
                    PlannedChange::NotWired,
                    format!(
                        "· {etc}: not wired; inactive lines hold the places of irlume's lines, \
                         because {without}"
                    ),
                );
            }
            (
                inert,
                format!(
                    "✓ {etc}: turned irlume's lines into inactive pam_permit.so lines and kept \
                     the file; {kept_why}\n    removing them instead would {change}; {until}, \
                     `sudo irlume login disable --apply` removes them"
                ),
            )
        }
    };
    Decision {
        detail: i.vendor.map(|v| {
            format!(
                "{}\n    delete {etc} to use {vendor_path}",
                diff_block(etc, vendor_path, &p.body, v)
            )
        }),
        ..replace(PlannedChange::StripInPlace, keep_header(p, &body), message)
    }
}

fn forced(i: &Input<'_>, current: &str, p: &Parsed<'_>) -> Result<Decision, String> {
    let (etc, vendor_path) = (i.etc, i.vendor_path);
    let v = i
        .vendor
        .ok_or_else(|| format!("{etc}: {vendor_path} is gone"))?;
    let (wired, ok) = (i.wire)(&base(v));
    if !ok {
        return Ok(no_anchor(etc));
    }
    if i.backup.is_some_and(|b| b != current) {
        return Err(format!(
            "{etc}: not rebuilt: {etc}{BACKUP} already holds a different file; move it away \
             and run again"
        ));
    }
    Ok(Decision {
        keep_copy: true,
        // The preview shows what the rebuild drops before `--apply`.
        detail: Some(diff_block(etc, vendor_path, &p.body, v)),
        ..replace(
            PlannedChange::MaterializeOverride,
            render(vendor_path, v, &wired),
            format!("✓ {etc}: rebuilt from {vendor_path}; the previous file is at {etc}{BACKUP}"),
        )
    })
}

/// Stands for why an update of irlume's lines was refused, in
/// [`InPlace::refused`].
const WHY: &str = "{why}";

/// U1, U2 and L1: nothing of anybody else's is in the file, so it follows the
/// vendor file.
fn rebuild(i: &Input<'_>, current: &str, p: &Parsed<'_>, class: Class) -> Decision {
    let (etc, vendor_path) = (i.etc, i.vendor_path);
    let Some(v) = i.vendor else {
        return vendor_gone(i, p, class);
    };
    let (wired, ok) = (i.wire)(&base(v));
    let (why, way_out) = if !ok {
        (
            "irlume finds no line to wire in it".to_string(),
            String::new(),
        )
    } else {
        let fresh = render(vendor_path, v, &wired);
        if normalize(current) == fresh && !p.crlf {
            return keep(
                PlannedChange::AlreadyCorrect,
                format!("· {etc}: already correctly wired"),
            );
        }
        let warn = match check_jumps(&p.body, &wired, false) {
            JumpCheck::Refuse(reason) => Err(reason),
            JumpCheck::Warn(w) => Ok(w),
            JumpCheck::Clear => Ok(String::new()),
        };
        match warn {
            Ok(warn) => {
                let same_lines = normalize(&p.body) == wired;
                let mut what = match class {
                    Class::U2 => format!(
                        "rebuilt from {vendor_path}, which changed since irlume created this \
                         override"
                    ),
                    Class::L1 if same_lines && !p.crlf => format!(
                        "recorded {vendor_path} in the override header; no PAM line changed"
                    ),
                    _ if same_lines => CRLF_FIXED.to_string(),
                    _ => format!("updated irlume's lines in the override of {vendor_path}"),
                };
                if p.crlf && !same_lines {
                    what.push_str(&format!("; {CRLF_FIXED}"));
                }
                return Decision {
                    header_only: class == Class::L1 && same_lines && !p.crlf,
                    ..replace(
                        PlannedChange::MaterializeOverride,
                        fresh,
                        format!("✓ {etc}: {what}{warn}"),
                    )
                };
            }
            Err(reason) => (
                reason,
                format!(
                    "; to take {vendor_path} anyway, delete {etc} and run `sudo irlume login \
                     enable{} --apply`, which creates it again with irlume's lines in, and then \
                     check that jump",
                    i.scope_flag
                ),
            ),
        }
    };
    // The vendor file cannot be used as it is. The file still works on the
    // vendor text it was built from, so keep that and touch irlume's lines only.
    let not_rebuilt = match class {
        Class::U2 => format!(
            "not rebuilt from {vendor_path}, which changed since irlume created this override: \
             {why}"
        ),
        _ => format!("not rebuilt from {vendor_path}: {why}"),
    };
    in_place(
        i,
        p,
        InPlace {
            edited: false,
            unchanged: (
                PlannedChange::AlreadyCorrect,
                format!("⚠ {etc}: {not_rebuilt}; the override is left as it is{way_out}"),
            ),
            rewired: format!("✓ {etc}: updated irlume's lines in place; {not_rebuilt}"),
            refused: format!(
                "⚠ {etc}: {not_rebuilt}; it is left as it is, because updating irlume's lines \
                 in place would {WHY}"
            ),
            detail: None,
            refused_detail: None,
        },
    )
}

/// The messages of an in-place update, one per way it can end.
struct InPlace {
    /// Whether the file may hold lines an administrator wrote (see
    /// [`check_jumps`]).
    edited: bool,
    /// irlume's lines are already right: the outcome and its line.
    unchanged: (PlannedChange, String),
    /// irlume's lines are updated.
    rewired: String,
    /// Nothing is written; [`WHY`] marks where the reason goes.
    refused: String,
    /// Shown with every outcome.
    detail: Option<String>,
    /// Shown with a refusal only.
    refused_detail: Option<String>,
}

/// Update irlume's lines in an override and keep every other line, the
/// header included. Refused, with nothing written, when the update would
/// change where a numeric jump in the other lines lands or would move one of
/// irlume's lines past an administrator's line.
fn in_place(i: &Input<'_>, p: &Parsed<'_>, m: InPlace) -> Decision {
    let etc = i.etc;
    let bare = base(&p.body);
    let (wired, ok) = (i.wire)(&bare);
    if !ok {
        return no_anchor(etc);
    }
    let InPlace {
        edited,
        unchanged,
        rewired,
        refused,
        detail,
        refused_detail,
    } = m;
    if irlume_lines(&p.body) == irlume_lines(&wired) {
        if p.crlf {
            // The lines are right but PAM reads none of them. Every line is
            // kept; only the line endings change.
            return Decision {
                detail,
                ..replace(
                    PlannedChange::RewireOverride,
                    keep_header(p, &p.body),
                    format!("✓ {etc}: {CRLF_FIXED}; every line is kept"),
                )
            };
        }
        let (change, message) = unchanged;
        return Decision {
            detail,
            ..keep(change, message)
        };
    }
    let wired_now = has_irlume_line(&p.body);
    let refuse = |why: String| {
        let message = if wired_now {
            refused.replace(WHY, &why)
        } else {
            // Nothing of irlume's to keep: say it is not wired, and what
            // stands in the way.
            let way = if i.vendor.is_some() && edited {
                "adjust that line, or rebuild the file with --force"
            } else {
                "adjust that line"
            };
            format!(
                "⚠ {etc}: not wired: irlume's lines are not in it, and adding them would {why}, \
                 so it is left as it is; {way}"
            )
        };
        Decision {
            detail: detail.clone().or_else(|| refused_detail.clone()),
            unmet: true,
            ..keep(PlannedChange::KeepEditedOverride, message)
        }
    };
    let arranged = match arrange(&p.body, &bare, wired.clone(), i.vendor, edited, i.wire) {
        Ok(text) => text,
        Err(Misplaced::Crossing(line)) => {
            return refuse(format!(
                "move one of them past `{line}`, which irlume did not write"
            ));
        }
        Err(Misplaced::NoPasswordAnchor) => {
            let why = match i.vendor {
                Some(_) => format!(
                    "irlume finds no password line in it that it can tell is {}'s to wire them \
                     next to",
                    i.vendor_path
                ),
                None => format!(
                    "without {} irlume cannot tell which password line to wire them next to",
                    i.vendor_path
                ),
            };
            return Decision {
                detail: refused_detail.clone().or_else(|| detail.clone()),
                ..keep(
                    PlannedChange::NoAnchor,
                    format!(
                        "⚠ {etc}: not wired: irlume's lines are not in it, and {why} (skipped)"
                    ),
                )
            };
        }
    };
    // A write that would move a jump can often be made without moving
    // anything: each of irlume's lines updated in its own place, and an
    // inactive line kept where this configuration no longer wants one (face
    // login turned off where a jump counts the face line, or lines a disable
    // left inactive).
    let (arranged, check, filled) = match check_jumps(&p.body, &arranged, edited) {
        JumpCheck::Refuse(reason) => match filled_in_place(&p.body, &wired, edited) {
            Some((text, check)) => (text, check, true),
            None => return refuse(format!("move a jump: {reason}")),
        },
        check => (arranged, check, false),
    };
    if filled && normalize(&arranged) == normalize(&p.body) && !p.crlf {
        let (change, message) = unchanged;
        return Decision {
            detail,
            ..keep(change, message)
        };
    }
    let mut message = match check {
        JumpCheck::Warn(warn) => format!("{rewired}{warn}"),
        JumpCheck::Clear | JumpCheck::Refuse(_) => rewired,
    };
    if filled && arranged.contains(INERT_TAG) {
        message.push_str(
            "; an inactive line holds the place of each of irlume's lines this configuration \
             does not use, so every jump lands where it did",
        );
    }
    if p.crlf {
        message.push_str(&format!("; {CRLF_FIXED}"));
    }
    Decision {
        detail,
        ..replace(
            PlannedChange::RewireOverride,
            keep_header(p, &arranged),
            message,
        )
    }
}

/// E1, E2 and L2 without `force`: irlume's lines are updated in place and
/// every other line is kept. Never rebuilt from the vendor file.
fn rewire_edited(i: &Input<'_>, p: &Parsed<'_>, class: Class) -> Decision {
    let (etc, vendor_path) = (i.etc, i.vendor_path);
    let hint = i.vendor.map(|v| {
        format!(
            "{}{}",
            diff_block(etc, vendor_path, &p.body, v),
            force_hint(etc, vendor_path, i.scope_flag, stale_backup(i))
        )
    });
    // What the file keeps besides irlume's lines: lines of its own, or only
    // the vendor lines it has, when it lacks some the vendor copy has now.
    let (kept, rewired_kept) = match lacks(&p.body, i.vendor) {
        Some(n) => {
            let lacking = format!(
                "it lacks {} {vendor_path} has, and has no line of its own",
                lines_word(n)
            );
            (
                format!("kept; {lacking}"),
                format!("kept the file; {lacking}"),
            )
        }
        None => (
            "kept, with the lines irlume did not write".to_string(),
            "kept the lines irlume did not write".to_string(),
        ),
    };
    let refusal = match class {
        Class::E2 => format!(
            "not rebuilt from {vendor_path}, which changed since irlume created this override"
        ),
        Class::L2 => format!(
            "it differs from {vendor_path} and predates vendor tracking, so it is not rebuilt"
        ),
        // E1: built from the vendor file as it is now, so there is nothing to
        // rebuild from; only irlume's lines can need work.
        _ => {
            return in_place(
                i,
                p,
                InPlace {
                    edited: true,
                    unchanged: (
                        PlannedChange::AlreadyCorrect,
                        format!("· {etc}: already correctly wired"),
                    ),
                    rewired: format!(
                        "✓ {etc}: updated irlume's lines and kept the lines irlume did not write"
                    ),
                    refused: format!(
                        "⚠ {etc}: kept as it is, because updating irlume's lines would {WHY}; \
                         adjust that line, or rebuild the file with --force"
                    ),
                    detail: None,
                    refused_detail: hint,
                },
            );
        }
    };
    in_place(
        i,
        p,
        InPlace {
            edited: true,
            unchanged: (
                PlannedChange::KeepEditedOverride,
                format!("⚠ {etc}: {kept}; {refusal}"),
            ),
            rewired: format!("⚠ {etc}: updated irlume's lines and {rewired_kept}; {refusal}"),
            refused: format!(
                "⚠ {etc}: kept as it is ({refusal}); irlume's lines were not updated either, \
                 because that would {WHY}"
            ),
            detail: hint,
            refused_detail: None,
        },
    )
}

/// U3, E3 and L3: the vendor file is gone, so this file is what PAM reads for
/// the service. It is wired in place like an administrator's file and never
/// deleted.
fn vendor_gone(i: &Input<'_>, p: &Parsed<'_>, class: Class) -> Decision {
    let etc = i.etc;
    let vendor_path = i.vendor_path;
    let gone = format!("{vendor_path} is gone, so this file is the service's only configuration");
    // Without the vendor copy irlume cannot tell an administrator's lines
    // from the vendor's in a file that may hold some, so it moves none of
    // its lines past any of them. Say how to go on.
    let way_out = if class.edited() {
        format!(
            "; without it irlume cannot tell which lines came from it: put it back and run this \
             again, or move irlume's lines in {etc} by hand"
        )
    } else {
        String::new()
    };
    in_place(
        i,
        p,
        InPlace {
            edited: class.edited(),
            unchanged: (
                PlannedChange::AlreadyCorrect,
                format!("· {etc}: already correctly wired; {gone}"),
            ),
            rewired: format!("✓ {etc}: updated irlume's lines in place; {gone}"),
            refused: format!(
                "⚠ {etc}: kept as it is, because updating irlume's lines would {WHY}; \
                 {gone}{way_out}"
            ),
            detail: None,
            refused_detail: None,
        },
    )
}

// ---- reconcile's maintenance step ---------------------------------------------

/// Which wiring recipe a surface takes. Reconcile infers the recipe's settings
/// from the lines in the file rather than asking the daemon, so maintaining an
/// override never depends on a capability reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Recipe {
    Greeter,
    Lock,
    Verify,
    Polkit,
}

/// The settings a greeter's irlume lines were written with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Settings {
    face: bool,
    keyring: bool,
    ondemand: bool,
}

/// Read the settings back from irlume's lines. `None` when there are none, or
/// when they contradict each other (an `ondemand` and a `facefirst` face line).
fn infer(recipe: Recipe, body: &str) -> Option<Settings> {
    let lines: Vec<Vec<&str>> = body
        .lines()
        .filter_map(irlume_rule)
        .map(|r| r.args)
        .collect();
    if lines.is_empty() {
        return None;
    }
    if recipe != Recipe::Greeter {
        return Some(Settings::default());
    }
    let unseal: Vec<&Vec<&str>> = lines.iter().filter(|t| t.contains(&"unseal")).collect();
    let face = !unseal.is_empty();
    let keyring = lines.iter().any(|t| t.contains(&"keyring"));
    let ondemand = if face {
        let on = unseal.iter().filter(|t| t.contains(&"ondemand")).count();
        let first = unseal.iter().filter(|t| t.contains(&"facefirst")).count();
        if on == unseal.len() && first == 0 {
            true
        } else if first == unseal.len() && on == 0 {
            false
        } else {
            return None;
        }
    } else {
        false
    };
    (face || keyring).then_some(Settings {
        face,
        keyring,
        ondemand,
    })
}

fn wire_with(recipe: Recipe, settings: Settings, content: &str) -> (String, bool) {
    match recipe {
        Recipe::Greeter => {
            wire_greeter_impl(content, settings.face, settings.keyring, settings.ondemand)
        }
        Recipe::Lock => wire_lock(content),
        Recipe::Verify => wire_verify_service(content),
        Recipe::Polkit => wire_polkit_service(content),
    }
}

/// Why reconcile does not rebuild an override nobody edited whose vendor copy
/// changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hold {
    /// irlume's lines do not say which login methods they were written for.
    UnknownSettings,
    /// The new vendor copy has no line irlume can wire next to.
    NoAnchor,
    /// Rebuilt, irlume's lines would serve other login methods than now.
    SettingsChange,
    /// irlume's lines would make a numeric jump in the new vendor copy land
    /// somewhere else.
    Jump,
}

/// What reconcile's maintenance step does to one override.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Maintenance {
    Nothing,
    /// Add the tracking line to a file that matches its vendor copy. Every
    /// other line stays byte for byte.
    Record(String),
    /// Rebuild a file nobody edited from its changed vendor copy, with the
    /// settings its irlume lines have now.
    Refresh(String),
    /// The vendor copy changed but reconcile will not rebuild the file.
    Blocked(Hold),
}

pub(super) fn maintenance(
    recipe: Recipe,
    current: &str,
    vendor_path: &str,
    vendor: Option<&str>,
) -> Maintenance {
    let (Some(p), Some(v)) = (parse(current), vendor) else {
        return Maintenance::Nothing;
    };
    match classify(&p, Some(v)) {
        Class::L1 => Maintenance::Record(format!(
            "{}\n{}\n{}",
            p.first,
            tracking_line(&sha256(v), &body_digest(&p.body)),
            p.body
        )),
        Class::U2 => {
            let Some(settings) = infer(recipe, &p.body) else {
                return Maintenance::Blocked(Hold::UnknownSettings);
            };
            let (wired, ok) = wire_with(recipe, settings, &base(v));
            if !ok {
                return Maintenance::Blocked(Hold::NoAnchor);
            }
            if infer(recipe, &wired) != Some(settings) {
                return Maintenance::Blocked(Hold::SettingsChange);
            }
            if !jumps_moved_by_irlume(&p.body, &wired).is_empty() {
                return Maintenance::Blocked(Hold::Jump);
            }
            Maintenance::Refresh(render(vendor_path, v, &wired))
        }
        _ => Maintenance::Nothing,
    }
}

// ---- doctor and status -----------------------------------------------------------

/// How much an override needs attention. Ordered, so a report takes the worst.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Pass,
    Info,
    Warn,
}

/// One override's state for doctor and `login status`, without its service
/// name or any path, and without quoting a PAM line (a module can be named by
/// path): the caller names the service.
///
/// `siblings` are the package-manager leftovers next to the file (`.rpmnew`
/// and the like), which say where a vendor file that left `/usr/lib/pam.d`
/// went. `stale_backup` is the name of a `.pre-irlume` next to the file that
/// holds a different file, which stops `--force` until it is moved away.
pub(super) fn assess(
    recipe: Recipe,
    current: &str,
    vendor_path: &str,
    vendor: Option<&str>,
    siblings: &[String],
    stale_backup: Option<&str>,
    scope_flag: &str,
) -> (Level, Option<String>) {
    let Some(p) = parse(current) else {
        return (Level::Pass, None);
    };
    let class = classify(&p, vendor);
    let enable_apply = format!("`sudo irlume login enable{scope_flag} --apply`");
    let (mut level, mut note) = match class {
        Class::U1 => (Level::Pass, None),
        Class::L1 => (
            Level::Info,
            Some("matches its vendor copy; the next reconcile records that in its header".into()),
        ),
        Class::U2 => match maintenance(recipe, current, vendor_path, vendor) {
            Maintenance::Refresh(_) => (
                Level::Info,
                Some("its vendor copy changed; the next reconcile rebuilds it".into()),
            ),
            Maintenance::Blocked(hold) => (
                Level::Info,
                Some(match hold {
                    Hold::UnknownSettings | Hold::SettingsChange => format!(
                        "its vendor copy changed, and irlume cannot tell from its lines which \
                         login methods they were written for, so reconcile does not rebuild \
                         it; {enable_apply} rebuilds it for this machine's settings"
                    ),
                    Hold::NoAnchor => "its vendor copy changed, and irlume finds no line to \
                                       wire in the new one, so the file keeps working on the \
                                       old one"
                        .to_string(),
                    Hold::Jump => format!(
                        "its vendor copy changed and gained a numeric jump that irlume's lines \
                         would move, so reconcile does not rebuild it; to take the new vendor \
                         copy anyway, delete the file and run {enable_apply}, then check that \
                         jump"
                    ),
                }),
            ),
            _ => (Level::Pass, None),
        },
        Class::U3 | Class::E3 | Class::L3 => {
            let mut note =
                "its vendor copy is gone, so this file is the service's only configuration"
                    .to_string();
            for name in siblings {
                note.push_str(&format!("; {name} is next to it"));
            }
            (Level::Info, Some(note))
        }
        Class::E2 | Class::L2 => {
            let since = if class == Class::E2 {
                "its vendor copy changed since irlume created it"
            } else {
                "it predates vendor tracking and differs from its vendor copy"
            };
            // A file that lacks only lines its vendor copy has now may
            // equally be one the vendor updated or one somebody cut lines
            // from, so it is kept and reported like any other.
            let what = match lacks(&p.body, vendor) {
                Some(n) => format!(
                    "kept; it lacks {} its vendor copy has and has no line of its own",
                    lines_word(n)
                ),
                None => "kept with lines irlume did not write".to_string(),
            };
            let next = if content_has_module(&p.body) {
                let force = format!(
                    "`sudo irlume login enable{scope_flag} --apply --force` rebuilds it and keeps \
                     the old file as .pre-irlume"
                );
                let force = match stale_backup {
                    Some(name) => {
                        format!("once {name}, which holds a different file, is moved away, {force}")
                    }
                    None => force,
                };
                format!("`irlume login enable{scope_flag}` shows how it differs, and {force}")
            } else {
                "delete it to use its vendor copy".to_string()
            };
            (Level::Warn, Some(format!("{what}; {since}; {next}")))
        }
        Class::E1 => (Level::Pass, None),
    };
    if only_inert_lines(&p.body) {
        let held = "inactive lines hold the places of irlume's lines";
        let inert = if !strip_shifts(&p.body, &base(&p.body), vendor).is_empty() {
            format!("{held}, because a numeric jump in a line irlume did not write counts them")
        } else if strip_loses_place(&p.body, vendor, class.edited()) {
            format!("{held}, because irlume could not tell where to put them back without them")
        } else {
            let removes = if class.edited() || class == Class::U3 {
                "removes them"
            } else {
                "deletes the file, which restores its vendor copy"
            };
            format!(
                "{held}, and nothing needs them any more; `sudo irlume login disable --apply` \
                 {removes}"
            )
        };
        match note.as_mut() {
            Some(text) => {
                text.push_str("; ");
                text.push_str(&inert);
            }
            None => {
                level = Level::Info;
                note = Some(inert);
            }
        }
    } else if class.edited() && !has_irlume_line(&p.body) {
        let absent = "irlume's lines are not in it, and it has lines irlume did not write";
        // A tracked file irlume stripped itself was checked: no jump moved.
        // A file from before tracking was not, whoever took the lines out.
        if matches!(class, Class::L2 | Class::L3) && has_numeric_jump(&p.body) {
            level = Level::Warn;
            note = Some(format!(
                "{absent}; a numeric jump in one of those lines may have counted irlume's lines, \
                 so check where it lands"
            ));
        } else if note.is_none() {
            level = Level::Info;
            note = Some(format!("{absent}; delete it to use its vendor copy"));
        }
    }
    if p.crlf {
        let fix = if content_has_module(&p.body) {
            format!("{enable_apply} rewrites them as LF and keeps every line")
        } else {
            "save it with LF line endings".to_string()
        };
        let crlf = format!(
            "it has CRLF line endings, which PAM does not read, so every login through it fails; \
             {fix}"
        );
        level = Level::Warn;
        note = Some(match note {
            Some(rest) => format!("{crlf}; {rest}"),
            None => crlf,
        });
    }
    (level, note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pamwire::stanzas::{PERMIT_LANDING, POLKIT_VERIFY_STANZA, VERIFY_STANZA};

    type WireFn<'a> = &'a dyn Fn(&str) -> (String, bool);
    /// current, vendor, enable, force, recipe, expected outcome
    type Row<'a> = (
        Option<&'a str>,
        Option<&'a str>,
        bool,
        bool,
        WireFn<'a>,
        PlannedChange,
    );

    const VENDOR: &str = "auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth        substack      password-auth
-auth        optional      pam_gnome_keyring.so
-auth        optional      pam_kwallet5.so
auth        include       postlogin

account     include       password-auth

session     include       password-auth
-session     optional      pam_kwallet5.so auto_start
";

    const ADMIN: &str =
        "auth       [success=2 default=ignore]   pam_fprintd.so max-tries=1 timeout=15   # local";

    fn greeter(content: &str) -> (String, bool) {
        wire_greeter_impl(content, true, true, true)
    }

    fn keyring_only(content: &str) -> (String, bool) {
        wire_greeter_impl(content, false, true, false)
    }

    /// The landing on `text`, as [`landing_of`] builds it.
    fn line(text: &str) -> Landing {
        Landing::Line {
            key: line_key(text),
            text: norm(text),
        }
    }

    fn with_admin_line(text: &str) -> String {
        text.replacen(
            "pam_selinux_permit.so\n",
            &format!("pam_selinux_permit.so\n{ADMIN}\n"),
            1,
        )
    }

    fn vendor_v2() -> String {
        VENDOR.replacen(
            "-auth        optional      pam_kwallet5.so\n",
            "-auth        optional      pam_kwallet5.so\n-auth        optional      pam_oo7.so\n",
            1,
        )
    }

    fn generation(vendor: &str) -> String {
        let (wired, ok) = greeter(&base(vendor));
        assert!(ok);
        render("/usr/lib/pam.d/plasmalogin", vendor, &wired)
    }

    fn legacy(vendor: &str) -> String {
        let (wired, _) = greeter(&base(vendor));
        format!("{}\n{wired}", created_line("/usr/lib/pam.d/plasmalogin"))
    }

    fn input<'a>(
        current: Option<&'a str>,
        vendor: Option<&'a str>,
        enable: bool,
        wire: WireFn<'a>,
    ) -> Input<'a> {
        Input {
            etc: "/etc/pam.d/plasmalogin",
            vendor_path: "/usr/lib/pam.d/plasmalogin",
            current,
            vendor,
            backup: None,
            enable,
            force: false,
            scope_flag: "",
            wire,
        }
    }

    /// How irlume told its own lines apart before it read the module-path
    /// field: the module named anywhere in the directive, plus the tagged
    /// lines. Kept here to compare the digests earlier builds recorded.
    fn is_irlume_line_by_substring(l: &str) -> bool {
        let d = directive(l);
        d.contains("pam_irlume.so")
            || (d.contains("pam_permit.so")
                && (l.contains("# irlume-landing") || l.contains(INERT_TAG)))
            || (d.contains("pam_gnome_keyring.so") && l.contains(KEYRING_TAG))
    }

    fn body_digest_by_substring(body: &str) -> String {
        let kept: Vec<&str> = body
            .lines()
            .filter(|l| !is_irlume_line_by_substring(l))
            .collect();
        sha256(&format!("{}\n", kept.join("\n")))
    }

    /// Every override irlume writes is its vendor copy plus irlume's own
    /// lines, and every one of those loads pam_irlume.so by its module path
    /// or is a tagged line. So the body digest an earlier build recorded with
    /// the substring rule is the one this build computes, and a file nobody
    /// edited still reads as unedited, and still follows its vendor copy,
    /// after the upgrade. Checked over every vendor fixture and recipe.
    #[test]
    fn an_unedited_override_digests_as_it_did_under_the_substring_rule() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pam");
        let mut vendors = vec![VENDOR.to_string(), vendor_v2()];
        for distro in std::fs::read_dir(&root).unwrap() {
            for file in std::fs::read_dir(distro.unwrap().path()).unwrap() {
                vendors.push(std::fs::read_to_string(file.unwrap().path()).unwrap());
            }
        }
        let fp_keyring = |c: &str| super::super::transform::wire_fp_keyring(c, "gdm-fingerprint");
        type OwnedWire = Box<dyn Fn(&str) -> (String, bool)>;
        let mut recipes: Vec<(String, OwnedWire)> = vec![
            ("lock".into(), Box::new(wire_lock)),
            ("verify".into(), Box::new(wire_verify_service)),
            ("polkit".into(), Box::new(wire_polkit_service)),
            ("fingerprint keyring".into(), Box::new(fp_keyring)),
        ];
        for (face, keyring, ondemand) in [
            (true, true, true),
            (true, true, false),
            (true, false, true),
            (true, false, false),
            (false, true, false),
        ] {
            recipes.push((
                format!("greeter face={face} keyring={keyring} ondemand={ondemand}"),
                Box::new(move |c: &str| wire_greeter_impl(c, face, keyring, ondemand)),
            ));
        }
        let vp = "/usr/lib/pam.d/plasmalogin";
        let mut checked = 0;
        for vendor in &vendors {
            for (label, wire) in &recipes {
                let (wired, ok) = wire(&base(vendor));
                if !ok {
                    continue;
                }
                let written = render(vp, vendor, &wired);
                let p = parse(&written).unwrap();
                assert_eq!(
                    body_digest(&p.body),
                    body_digest_by_substring(&p.body),
                    "{label}\n{written}"
                );
                let earlier = format!(
                    "{}\n{}\n{wired}",
                    created_line(vp),
                    tracking_line(&sha256(vendor), &body_digest_by_substring(&wired))
                );
                let p = parse(&earlier).unwrap();
                assert_eq!(classify(&p, Some(vendor)), Class::U1, "{label}\n{earlier}");
                assert_eq!(
                    classify(
                        &p,
                        Some(&format!("{vendor}session optional pam_keyinit.so\n"))
                    ),
                    Class::U2,
                    "{label}: a vendor update still reaches it"
                );
                checked += 1;
            }
        }
        assert!(checked >= 100, "only {checked} files checked");
    }

    #[test]
    fn a_tracked_header_round_trips_and_keeps_the_legacy_first_line() {
        let text = generation(VENDOR);
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some(created_line("/usr/lib/pam.d/plasmalogin").as_str())
        );
        assert!(
            text.starts_with(CREATED_PREFIX),
            "older readers still see it"
        );
        let second = lines.next().unwrap();
        assert!(second.starts_with(OVERRIDE_TRACK_PREFIX), "{second}");
        let p = parse(&text).unwrap();
        let (vendor_sha, body_sha) = p.digests.clone().expect("a v1 line parses");
        assert_eq!(vendor_sha, sha256(VENDOR));
        assert_eq!(body_sha, sha256(&base(VENDOR)));
        assert!(
            !p.body.contains("# irlume: override"),
            "the body excludes it"
        );
        assert_eq!(classify(&p, Some(VENDOR)), Class::U1);
    }

    #[test]
    fn a_second_header_line_irlume_cannot_read_makes_the_override_legacy() {
        let text = generation(VENDOR);
        let second = text.lines().nth(1).unwrap().to_string();
        let hex = "a".repeat(64);
        for unreadable in [
            second.replace(" v1 ", " v2 "),
            second.replacen("vendor-sha256=", "vendor-sha256=zz", 1),
            format!("{second} extra=1"),
            format!("{OVERRIDE_TRACK_PREFIX}v1 body-sha256={hex} vendor-sha256={hex}"),
        ] {
            let changed = text.replace(&second, &unreadable);
            let p = parse(&changed).unwrap();
            assert!(p.digests.is_none(), "{unreadable}");
            assert!(
                !p.body.contains(&unreadable),
                "a versioned line stays a header line"
            );
            // Legacy, and matching its vendor copy, so it is L1, not tracked.
            assert_eq!(classify(&p, Some(VENDOR)), Class::L1, "{unreadable}");
        }
        // A comment that only looks like the prefix is an ordinary line.
        let lookalike = text.replace(&second, "# irlume: override notes from the admin");
        let p = parse(&lookalike).unwrap();
        assert!(p.digests.is_none());
        assert!(
            p.body.contains("notes from the admin"),
            "it stays in the body"
        );
        assert_eq!(classify(&p, Some(VENDOR)), Class::L2);
        // An admin comment above the tracking line leaves it tracked and
        // edited, not legacy.
        let first = created_line("/usr/lib/pam.d/plasmalogin");
        let commented = text.replacen(&first, &format!("{first}\n# my note"), 1);
        let p = parse(&commented).unwrap();
        assert!(p.digests.is_some());
        assert_eq!(classify(&p, Some(VENDOR)), Class::E1);
    }

    #[test]
    fn the_body_digest_leaves_irlume_lines_out() {
        let (face_and_keyring, _) = greeter(&base(VENDOR));
        let (keyring, _) = keyring_only(&base(VENDOR));
        assert_ne!(face_and_keyring, keyring);
        assert_eq!(body_digest(&face_and_keyring), body_digest(&keyring));
        // The polkit stanza migration is irlume's own line changing.
        let old_polkit =
            "auth       sufficient                   pam_irlume.so\nauth include system-auth\n";
        let (new_polkit, _) = wire_polkit_service(&base(old_polkit));
        assert_eq!(body_digest(old_polkit), body_digest(&new_polkit));
        // Any other line added, removed or changed does change it.
        let added = with_admin_line(&face_and_keyring);
        let removed = face_and_keyring.replace("-auth        optional      pam_kwallet5.so\n", "");
        let changed = face_and_keyring.replace("pam_kwallet5.so auto_start", "pam_kwallet5.so");
        for edit in [added, removed, changed] {
            assert_ne!(body_digest(&edit), body_digest(&face_and_keyring));
        }
        // A pam_irlume.so line an administrator typed counts as irlume's: a
        // documented choice, the same one the in-place branch makes.
        let typed = format!("{face_and_keyring}auth optional pam_irlume.so reseal\n");
        assert_eq!(body_digest(&typed), body_digest(&face_and_keyring));
    }

    #[test]
    fn classification_covers_every_edit_and_vendor_state() {
        let v2 = vendor_v2();
        let tracked = generation(VENDOR);
        let edited = with_admin_line(&tracked);
        let old = legacy(VENDOR);
        let old_edited = with_admin_line(&old);
        let cases: [(&str, Option<&str>, Class); 11] = [
            (&tracked, Some(VENDOR), Class::U1),
            (&tracked, Some(&v2), Class::U2),
            (&tracked, None, Class::U3),
            (&edited, Some(VENDOR), Class::E1),
            (&edited, Some(&v2), Class::E2),
            (&edited, None, Class::E3),
            (&old, Some(VENDOR), Class::L1),
            (&old, Some(&v2), Class::L2),
            (&old_edited, Some(VENDOR), Class::L2),
            (&old, None, Class::L3),
            // Edited back to the new vendor copy by hand: loses nothing.
            (
                &format!(
                    "{}\n{}\n{}",
                    created_line("/usr/lib/pam.d/plasmalogin"),
                    tracked.lines().nth(1).unwrap(),
                    greeter(&base(&v2)).0
                ),
                Some(&v2),
                Class::L1,
            ),
        ];
        for (text, vendor, want) in cases {
            let p = parse(text).unwrap();
            assert_eq!(classify(&p, vendor), want, "{text}");
        }
    }

    #[test]
    fn the_decision_table_matches_the_design() {
        use PlannedChange::*;
        let v2 = vendor_v2();
        let tracked = generation(VENDOR);
        let edited = with_admin_line(&tracked);
        let old = legacy(VENDOR);
        let old_edited = with_admin_line(&old);
        let wire: WireFn<'_> = &greeter;
        let other: WireFn<'_> = &|c: &str| wire_greeter_impl(c, true, false, true);
        let rows: Vec<Row<'_>> = vec![
            // no file
            (None, Some(VENDOR), true, false, wire, MaterializeOverride),
            (None, None, true, false, wire, NotInstalled),
            (None, Some(VENDOR), false, false, wire, NotWired),
            // enable without force
            (
                Some(&tracked),
                Some(VENDOR),
                true,
                false,
                wire,
                AlreadyCorrect,
            ),
            (
                Some(&tracked),
                Some(VENDOR),
                true,
                false,
                other,
                MaterializeOverride,
            ),
            (
                Some(&tracked),
                Some(&v2),
                true,
                false,
                wire,
                MaterializeOverride,
            ),
            (Some(&tracked), None, true, false, wire, AlreadyCorrect),
            (Some(&tracked), None, true, false, other, RewireOverride),
            (
                Some(&old),
                Some(VENDOR),
                true,
                false,
                wire,
                MaterializeOverride,
            ),
            (
                Some(&edited),
                Some(VENDOR),
                true,
                false,
                wire,
                AlreadyCorrect,
            ),
            (
                Some(&edited),
                Some(&v2),
                true,
                false,
                wire,
                KeepEditedOverride,
            ),
            (
                Some(&old_edited),
                Some(&v2),
                true,
                false,
                wire,
                KeepEditedOverride,
            ),
            (Some(&old), Some(&v2), true, false, wire, KeepEditedOverride),
            (Some(&edited), None, true, false, wire, AlreadyCorrect),
            // enable with force
            (
                Some(&edited),
                Some(VENDOR),
                true,
                true,
                wire,
                MaterializeOverride,
            ),
            (
                Some(&edited),
                Some(&v2),
                true,
                true,
                wire,
                MaterializeOverride,
            ),
            (
                Some(&old_edited),
                Some(&v2),
                true,
                true,
                wire,
                MaterializeOverride,
            ),
            (Some(&edited), None, true, true, wire, AlreadyCorrect),
            (
                Some(&tracked),
                Some(&v2),
                true,
                true,
                wire,
                MaterializeOverride,
            ),
            // removal
            (
                Some(&tracked),
                Some(VENDOR),
                false,
                false,
                wire,
                RemoveOverride,
            ),
            (
                Some(&tracked),
                Some(&v2),
                false,
                false,
                wire,
                RemoveOverride,
            ),
            (Some(&old), Some(VENDOR), false, false, wire, RemoveOverride),
            (Some(&tracked), None, false, false, wire, StripInPlace),
            (
                Some(&edited),
                Some(VENDOR),
                false,
                false,
                wire,
                StripInPlace,
            ),
            (Some(&edited), Some(&v2), false, false, wire, StripInPlace),
            (
                Some(&old_edited),
                Some(&v2),
                false,
                false,
                wire,
                StripInPlace,
            ),
            (Some(&old), None, false, false, wire, StripInPlace),
        ];
        for (n, (current, vendor, enable, force, wire, want)) in rows.into_iter().enumerate() {
            let mut i = input(current, vendor, enable, wire);
            i.force = force;
            let d = decide(&i).unwrap();
            assert_eq!(d.change, want, "row {n}: {}", d.message);
            assert_eq!(d.change.writes(), d.write != Write::Nothing, "row {n}");
            let edited_file = current.is_some_and(|c| c != tracked.as_str());
            assert_eq!(
                d.keep_copy,
                force && want == MaterializeOverride && edited_file,
                "row {n}"
            );
        }
        // A stripped edited override with nothing of irlume's left is not
        // wired, and disable leaves it alone.
        let stripped = with_admin_line(&keep_header(
            &parse(&tracked).unwrap(),
            &base(&parse(&tracked).unwrap().body),
        ));
        let d = decide(&input(Some(&stripped), Some(VENDOR), false, wire)).unwrap();
        assert_eq!(d.change, NotWired);
    }

    #[test]
    fn force_refuses_to_replace_a_different_backup() {
        let edited = with_admin_line(&generation(VENDOR));
        let wire: WireFn<'_> = &greeter;
        let mut i = input(Some(&edited), Some(VENDOR), true, wire);
        i.force = true;
        i.backup = Some("an older file\n");
        let err = decide(&i).err().expect("a different backup is in the way");
        assert!(err.contains("already holds a different file"), "{err}");
        i.backup = Some(&edited);
        assert!(decide(&i).unwrap().keep_copy, "an identical backup is fine");
    }

    #[test]
    fn line_diff_lists_only_the_lines_that_differ() {
        let ours = "a\nb\nlocal\nc\n";
        let theirs = "a\nb\nc\nnew\n";
        assert_eq!(line_diff(ours, theirs), vec!["- local", "+ new"]);
        assert!(line_diff(ours, ours).is_empty());
        let many: String = (0..60).map(|n| format!("line {n}\n")).collect();
        // 60 lines only here and one only there: 61 diff lines, 40 shown.
        let block = diff_block("/etc/x", "/usr/x", &many, "vendor line\n");
        assert_eq!(
            block.lines().filter(|l| l.starts_with("    - ")).count(),
            DIFF_CAP
        );
        assert!(block.ends_with("… 21 more"), "{block}");
    }

    #[test]
    fn a_jump_that_counts_irlume_lines_is_followed_through_every_write() {
        let wired = greeter(&base(VENDOR)).0;
        let thinkpad = with_admin_line(&wired);
        // The admin's success=2 skips irlume's face line and the password
        // substack and lands on irlume's permit landing.
        let js = jumps(&thinkpad);
        assert_eq!(js.len(), 1);
        assert_eq!(js[0].landing, line(PERMIT_LANDING));
        // Rewiring with the same recipe keeps it there.
        let (same, _) = greeter(&base(&thinkpad));
        assert!(jump_shifts(&thinkpad, &same).is_empty());
        // The keyring-only recipe would move it onto irlume's reseal line.
        let (moved, _) = keyring_only(&base(&thinkpad));
        let shifts = jump_shifts(&thinkpad, &moved);
        assert_eq!(shifts.len(), 1);
        assert!(
            shift_reason(&shifts).contains("pam_irlume.so reseal"),
            "{}",
            shift_reason(&shifts)
        );
        // Stripping moves it onto a wallet line.
        let shifts = jump_shifts(&thinkpad, &base(&thinkpad));
        assert_eq!(shifts[0].now, line("-auth optional pam_kwallet5.so"));
        // A vendor jump added right above the anchor would now skip irlume's
        // face line instead of the password substack.
        let v3 = VENDOR.replacen(
            "auth        substack      password-auth\n",
            "auth       [success=1 default=ignore]   pam_fprintd.so\nauth        substack      password-auth\n",
            1,
        );
        let (rewired, _) = greeter(&base(&v3));
        let shifts = jump_shifts(&wired, &rewired);
        assert_eq!(
            shifts.len(),
            1,
            "irlume's line lands inside the vendor jump"
        );
    }

    #[test]
    fn a_jump_the_vendor_moved_itself_does_not_block_a_rebuild() {
        let vp = "/usr/lib/pam.d/plasmalogin";
        // A vendor jump that skips only the SELinux line, above irlume's lines.
        let v1 = VENDOR.replacen(
            "auth     [success=done",
            "auth       [success=1 default=ignore]   pam_vendor_check.so\nauth     [success=done",
            1,
        );
        // The vendor then puts a line inside its own jump.
        let v2 = v1.replacen(
            "pam_vendor_check.so\n",
            "pam_vendor_check.so\nauth       optional     pam_vendor_note.so\n",
            1,
        );
        let m = maintenance(Recipe::Greeter, &generation(&v1), vp, Some(&v2));
        assert!(matches!(m, Maintenance::Refresh(_)), "{m:?}");
        // The same jump spanning irlume's lines from the start is not new
        // either, so it does not block a rebuild after an unrelated change.
        let spanning = VENDOR.replacen(
            "auth        substack      password-auth\n",
            "auth       [success=1 default=ignore]   pam_fprintd.so\nauth        substack      password-auth\n",
            1,
        );
        let later = format!("{spanning}session     optional      pam_extra.so\n");
        let m = maintenance(Recipe::Greeter, &generation(&spanning), vp, Some(&later));
        assert!(matches!(m, Maintenance::Refresh(_)), "{m:?}");
    }

    #[test]
    fn landings_follow_libpam_counting() {
        let chain = "auth [success=1 default=ignore] pam_a.so\nauth required pam_b.so\n";
        assert_eq!(jumps(chain)[0].landing, Landing::End);
        let past = "auth [success=2 default=ignore] pam_a.so\nauth required pam_b.so\n";
        assert_eq!(jumps(past)[0].landing, Landing::PastEnd);
        let across = "auth [success=1 default=ignore] pam_a.so\nauth include system-auth\nauth required pam_c.so\n";
        assert!(matches!(jumps(across)[0].landing, Landing::Across { .. }));
        // Non-auth lines are not in the chain.
        let mixed = "auth [success=1 default=ignore] pam_a.so\naccount required pam_x.so\nauth required pam_b.so\nauth required pam_c.so\n";
        assert_eq!(jumps(mixed)[0].landing, line("auth required pam_c.so"));
        assert!(!has_numeric_jump(
            "auth [success=done default=bad] pam_a.so\n"
        ));
    }

    #[test]
    fn recipe_inference_reads_each_recipe_back_and_refuses_contradictions() {
        let base_text = base(VENDOR);
        for face in [false, true] {
            for keyring in [false, true] {
                for ondemand in [false, true] {
                    if !face && !keyring {
                        continue;
                    }
                    let (wired, ok) = wire_greeter_impl(&base_text, face, keyring, ondemand);
                    assert!(ok);
                    let got = infer(Recipe::Greeter, &wired).unwrap();
                    assert_eq!((got.face, got.keyring), (face, keyring));
                    if face {
                        assert_eq!(got.ondemand, ondemand);
                    }
                }
            }
        }
        let (wired, _) = greeter(&base_text);
        let contradiction = format!("{wired}auth sufficient pam_irlume.so unseal facefirst\n");
        assert_eq!(infer(Recipe::Greeter, &contradiction), None);
        assert_eq!(
            infer(Recipe::Greeter, &base_text),
            None,
            "nothing of irlume's"
        );
        let (sudo, _) = wire_verify_service("auth include system-auth\n");
        assert!(infer(Recipe::Verify, &sudo).is_some());
    }

    #[test]
    fn maintenance_records_matching_legacy_files_and_refreshes_only_unedited_tracked_ones() {
        let vp = "/usr/lib/pam.d/plasmalogin";
        let v2 = vendor_v2();
        // L1: only the tracking line is added.
        let old = legacy(VENDOR);
        let Maintenance::Record(recorded) = maintenance(Recipe::Greeter, &old, vp, Some(VENDOR))
        else {
            panic!("a matching legacy file is recorded");
        };
        let mut without_track: Vec<&str> = recorded.lines().collect();
        without_track.remove(1);
        assert_eq!(
            format!("{}\n", without_track.join("\n")),
            old,
            "no other line changes"
        );
        assert_eq!(
            classify(&parse(&recorded).unwrap(), Some(VENDOR)),
            Class::U1
        );
        assert_eq!(
            maintenance(Recipe::Greeter, &recorded, vp, Some(VENDOR)),
            Maintenance::Nothing,
            "idempotent"
        );
        // U2: rebuilt with the same settings.
        let keyring_file = {
            let (w, _) = keyring_only(&base(VENDOR));
            render(vp, VENDOR, &w)
        };
        let Maintenance::Refresh(fresh) =
            maintenance(Recipe::Greeter, &keyring_file, vp, Some(&v2))
        else {
            panic!("an unedited file follows its vendor copy");
        };
        assert!(fresh.contains("pam_oo7.so"));
        assert_eq!(
            irlume_lines(&fresh),
            irlume_lines(&keyring_file),
            "the same settings"
        );
        assert_eq!(classify(&parse(&fresh).unwrap(), Some(&v2)), Class::U1);
        assert_eq!(
            maintenance(Recipe::Greeter, &fresh, vp, Some(&v2)),
            Maintenance::Nothing
        );
        // Edited or differing files are never written here.
        for text in [
            with_admin_line(&generation(VENDOR)),
            with_admin_line(&old),
            old.clone(),
        ] {
            let m = maintenance(Recipe::Greeter, &text, vp, Some(&v2));
            assert!(matches!(m, Maintenance::Nothing), "{m:?}");
        }
        // Vendor gone: nothing.
        assert_eq!(
            maintenance(Recipe::Greeter, &old, vp, None),
            Maintenance::Nothing
        );
    }

    #[test]
    fn maintenance_does_not_rebuild_when_a_vendor_jump_would_span_irlume_lines() {
        let vp = "/usr/lib/pam.d/plasmalogin";
        let v3 = VENDOR.replacen(
            "auth        substack      password-auth\n",
            "auth       [success=1 default=ignore]   pam_fprintd.so\nauth        substack      password-auth\n",
            1,
        );
        let m = maintenance(Recipe::Greeter, &generation(VENDOR), vp, Some(&v3));
        assert!(matches!(m, Maintenance::Blocked(Hold::Jump)), "{m:?}");
    }

    /// The maintenance step must be able to run with no capability reading at
    /// all, so reconcile can never unwire anything on one. Checked on the
    /// source: this module reaches neither the daemon nor the capability
    /// cache, and only pure sibling modules.
    #[test]
    fn this_module_reads_no_capability_and_asks_no_daemon() {
        let source = include_str!("overrides.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "caps(",
            "wants(",
            "client::",
            "std::fs",
            "Command::",
            "super::files",
        ] {
            assert!(!code.contains(forbidden), "{forbidden} in overrides.rs");
        }
    }

    #[test]
    fn assessment_names_what_needs_attention() {
        let vp = "/usr/lib/pam.d/plasmalogin";
        let v2 = vendor_v2();
        let tracked = generation(VENDOR);
        let a = |text: &str, vendor: Option<&str>| {
            assess(Recipe::Greeter, text, vp, vendor, &[], None, "")
        };
        assert_eq!(a(&tracked, Some(VENDOR)).0, Level::Pass);
        assert_eq!(
            a(&with_admin_line(&tracked), Some(VENDOR)).0,
            Level::Pass,
            "E1 is fine"
        );
        assert_eq!(a(&with_admin_line(&tracked), Some(&v2)).0, Level::Warn);
        assert_eq!(
            a(&with_admin_line(&legacy(VENDOR)), Some(&v2)).0,
            Level::Warn
        );
        // Only vendor additions missing: irlume cannot tell a vendor update
        // from lines someone cut, so it warns as for any file it keeps.
        let (level, note) = a(&legacy(VENDOR), Some(&v2));
        assert_eq!(level, Level::Warn);
        assert!(note
            .unwrap()
            .contains("it lacks 1 line its vendor copy has"));
        assert_eq!(a(&tracked, Some(&v2)).0, Level::Info);
        let (level, note) = assess(
            Recipe::Greeter,
            &tracked,
            vp,
            None,
            &["plasmalogin.rpmnew".to_string()],
            None,
            "",
        );
        assert_eq!(level, Level::Info);
        assert!(note.unwrap().contains("plasmalogin.rpmnew is next to it"));
        // Without irlume's lines and with a jump that may have counted them:
        // a tracked file irlume stripped itself was checked, and one from
        // before tracking was not.
        let p = parse(&tracked).unwrap();
        let kept = with_admin_line(&keep_header(&p, &base(&p.body)));
        assert_eq!(a(&kept, Some(VENDOR)).0, Level::Info);
        let old = legacy(VENDOR);
        let p = parse(&old).unwrap();
        let kept = with_admin_line(&keep_header(&p, &base(&p.body)));
        let (level, note) = a(&kept, Some(VENDOR));
        assert_eq!(level, Level::Warn);
        assert!(note.unwrap().contains("check where it lands"));
        // The main case names both next steps, commands only.
        let (_, note) = a(&with_admin_line(&tracked), Some(&v2));
        let note = note.unwrap();
        for step in [
            "`irlume login enable` shows how it differs",
            "`sudo irlume login enable --apply --force` rebuilds it and keeps the old file as \
             .pre-irlume",
        ] {
            assert!(note.contains(step), "{note}");
        }
        assert!(!note.contains('/'), "no path: {note}");
        let (_, note) = assess(
            Recipe::Polkit,
            &with_admin_line(&tracked),
            vp,
            Some(&v2),
            &[],
            None,
            " --with-polkit",
        );
        assert!(
            note.unwrap()
                .contains("`sudo irlume login enable --with-polkit --apply --force`"),
            "the opt-in flag is named"
        );
        // Kept after disable with inactive lines in irlume's places.
        let edited = with_admin_line(&tracked);
        let p = parse(&edited).unwrap();
        let held = keep_header(&p, &neutralize(&p.body));
        let (level, note) = a(&held, Some(VENDOR));
        assert_eq!(level, Level::Info);
        assert!(note.unwrap().contains("inactive lines hold"));
        // A blocked rebuild names no PAM line (a module can be named by path).
        let v3 = VENDOR.replacen(
            "auth        substack      password-auth\n",
            "auth       [success=1 default=ignore]   /usr/lib64/security/pam_fprintd.so\n\
             auth        substack      password-auth\n",
            1,
        );
        let (level, note) = a(&tracked, Some(&v3));
        assert_eq!(level, Level::Info);
        let note = note.unwrap();
        assert!(note.contains("delete the file"), "{note}");
        assert!(!note.contains("pam_fprintd"), "{note}");
    }

    /// Inactive lines take the places of irlume's module lines, with the same
    /// phase and job, and the permit landing stays: every jump lands where it
    /// did, and the lines still read as irlume's.
    #[test]
    fn neutralizing_keeps_every_jump_and_the_lines_stay_irlume_lines() {
        let wired = greeter(&base(VENDOR)).0;
        let thinkpad = with_admin_line(&wired);
        let inert = neutralize(&thinkpad);
        assert!(!content_has_module(&inert), "{inert}");
        assert!(only_inert_lines(&inert));
        assert!(inert.contains(PERMIT_LANDING), "the landing stays: {inert}");
        assert_eq!(base(&inert), base(&thinkpad), "nothing else changes");
        assert_eq!(inert.lines().count(), thinkpad.lines().count());
        for (was, now) in thinkpad.lines().zip(inert.lines()) {
            if is_irlume_line(was) {
                assert!(is_irlume_line(now), "{now}");
                assert_eq!(kind(was), kind(now), "{was} / {now}");
            } else {
                assert_eq!(was, now);
            }
        }
        assert!(jump_shifts(&thinkpad, &inert).is_empty());
        assert_eq!(neutralize(&inert), inert, "idempotent");
        // The inactive line cannot change the stack's result.
        assert!(inert.contains(
            "auth       [default=ignore]             pam_permit.so   # irlume-inert unseal"
        ));
        assert!(inert.contains(
            "session    [default=ignore]             pam_permit.so   # irlume-inert reseal"
        ));
    }

    /// An administrator's failure jump that skips irlume's face line lands on
    /// the password stack. Disable keeps inactive lines in irlume's places, so
    /// it still lands there, with the vendor copy present or gone.
    #[test]
    fn disable_keeps_a_failure_jump_landing_on_the_password_stack() {
        let fail_jump =
            "auth       [success=done default=1]   pam_fprintd.so max-tries=1 timeout=15   # local";
        let edited = generation(VENDOR).replacen(
            "pam_selinux_permit.so\n",
            &format!("pam_selinux_permit.so\n{fail_jump}\n"),
            1,
        );
        let default_lands = |text: &str| {
            jumps(text)
                .into_iter()
                .find(|j| j.line == norm(fail_jump) && j.key == "default")
                .map(|j| j.landing)
        };
        let password = line("auth        substack      password-auth");
        assert_eq!(default_lands(&edited), Some(password.clone()));
        for vendor in [Some(VENDOR), None] {
            let wire: WireFn<'_> = &greeter;
            let d = decide(&input(Some(&edited), vendor, false, wire)).unwrap();
            assert_eq!(d.change, PlannedChange::StripInPlace, "{}", d.message);
            let Write::Replace(after) = d.write else {
                panic!("a write");
            };
            assert!(!content_has_module(&after), "{after}");
            assert!(after.contains(fail_jump));
            assert_eq!(
                default_lands(&after),
                Some(password.clone()),
                "{}\n{after}",
                d.message
            );
            assert!(d.message.contains("inactive"), "{}", d.message);
        }
        // Without a jump that counts them, irlume's lines are simply removed.
        let plain = generation(VENDOR).replacen(
            "pam_selinux_permit.so\n",
            "pam_selinux_permit.so\nauth       required     pam_faillock.so preauth\n",
            1,
        );
        let d = decide(&input(Some(&plain), Some(VENDOR), false, &greeter)).unwrap();
        let Write::Replace(after) = d.write else {
            panic!("a write");
        };
        assert!(!has_irlume_line(&after), "{after}");
    }

    /// irlume adds a session line too, so a session jump that counts it is
    /// followed the same way.
    #[test]
    fn a_session_jump_that_counts_irlume_lines_is_followed() {
        let session_jump = "session    [success=1 default=ignore]   pam_succeed_if.so service = x";
        let wired = generation(VENDOR).replacen(
            "session     include       password-auth\n",
            &format!("{session_jump}\nsession     include       password-auth\n"),
            1,
        );
        let p = parse(&wired).unwrap();
        let stripped = base(&p.body);
        let shifts = jump_shifts(&p.body, &stripped);
        assert_eq!(shifts.len(), 1, "{stripped}");
        assert!(shift_reason(&shifts).contains("pam_succeed_if.so"));
        assert!(jump_shifts(&p.body, &neutralize(&p.body)).is_empty());
        let d = decide(&input(Some(&wired), Some(VENDOR), false, &greeter)).unwrap();
        let Write::Replace(after) = d.write else {
            panic!("a write");
        };
        assert!(after.contains("# irlume-inert reseal"), "{after}");
    }

    /// Updating irlume's lines never moves one past an administrator's line.
    /// A text change lands in the old place; a new line goes only where
    /// irlume already has lines; anything else is refused.
    #[test]
    fn irlume_lines_stay_on_their_side_of_every_admin_line() {
        let polkit_vendor =
            "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\n";
        let faillock = "auth       required     pam_faillock.so preauth   # local";
        let body = format!(
            "#%PAM-1.0\n{faillock}\nauth       sufficient                   pam_irlume.so\nauth       include      system-auth\naccount    include      system-auth\n"
        );
        let bare = base(&body);
        let (wired, _) = wire_polkit_service(&bare);
        let own = own_lines(&bare, Some(polkit_vendor), true);
        assert_eq!(
            own,
            vec![false, true, false, false],
            "only faillock is theirs"
        );
        assert_eq!(
            crossing(&body, &wired, &bare, &own).as_deref(),
            Some(norm(faillock).as_str()),
            "the recipe anchors above faillock"
        );
        let arranged = arrange(
            &body,
            &bare,
            wired,
            Some(polkit_vendor),
            true,
            &wire_polkit_service,
        )
        .ok()
        .expect("the stanza migrates in place");
        let pos = |t: &str, n: &str| t.lines().position(|l| l.contains(n)).unwrap();
        assert!(pos(&arranged, "pam_faillock") < pos(&arranged, "pam_irlume"));
        assert!(arranged.contains("abort=die"), "{arranged}");
        // A stray second copy of the old stanza is dropped, not left behind
        // with the old control.
        let doubled = body.replacen(
            "auth       sufficient                   pam_irlume.so\n",
            "auth       sufficient                   pam_irlume.so\nauth       sufficient                   pam_irlume.so\n",
            1,
        );
        let migrated = substitute(&doubled, &wire_polkit_service(&base(&doubled)).0).unwrap();
        assert_eq!(migrated.matches("pam_irlume.so").count(), 1, "{migrated}");
        assert!(pos(&migrated, "pam_faillock") < pos(&migrated, "abort=die"));
        // Different jobs cannot swap places: an include-layout face line and
        // a keyring line are not the same line.
        let debian = "auth    include    common-auth\nsession include    common-session\n";
        let (face, _) = wire_greeter_impl(debian, true, false, true);
        let (keyring, _) = wire_greeter_impl(debian, false, true, true);
        assert!(substitute(&face, &keyring).is_none());
        // With none of irlume's lines left, the stanza goes below a line an
        // administrator put above the vendor's first auth line.
        let stripped = format!("#%PAM-1.0\n{faillock}\nauth       include      system-auth\naccount    include      system-auth\n");
        let own = own_lines(&stripped, Some(polkit_vendor), true);
        let wired = anchored(&stripped, &own, true, &wire_verify_service).unwrap();
        assert!(
            pos(&wired, "pam_faillock") < pos(&wired, "pam_irlume"),
            "{wired}"
        );
        // No auth line of the vendor's left: nothing to anchor on.
        let only_admin = format!("#%PAM-1.0\n{faillock}\n");
        let own = own_lines(&only_admin, Some(polkit_vendor), true);
        assert!(anchored(&only_admin, &own, true, &wire_verify_service).is_none());
    }

    // ---- irlume's lines and an administrator's lines, more shapes ------------------

    const POLKIT_VENDOR: &str = "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n";

    /// sudo as Fedora ships it, as a vendor file only.
    const FEDORA_SUDO: &str = "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    optional     pam_keyinit.so revoke\nsession    include      system-auth\n";

    const FAILLOCK: &str = "auth       required     pam_faillock.so preauth   # local";

    fn written(d: &Decision) -> Option<String> {
        match &d.write {
            Write::Replace(text) => Some(text.clone()),
            _ => None,
        }
    }

    fn position(text: &str, needle: &str) -> usize {
        text.lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not in\n{text}"))
    }

    /// `text` with `line` inserted directly above its first line containing
    /// `needle`.
    fn insert_above(text: &str, needle: &str, line: &str) -> String {
        let at = position(text, needle);
        let mut lines: Vec<&str> = text.lines().collect();
        lines.insert(at, line);
        format!("{}\n", lines.join("\n"))
    }

    fn insert_below(text: &str, needle: &str, line: &str) -> String {
        let at = position(text, needle);
        let mut lines: Vec<&str> = text.lines().collect();
        lines.insert(at + 1, line);
        format!("{}\n", lines.join("\n"))
    }

    fn created(vendor: &str, wire: WireFn<'_>) -> String {
        let (wired, ok) = wire(&base(vendor));
        assert!(ok);
        render("/usr/lib/pam.d/plasmalogin", vendor, &wired)
    }

    fn opensuse_sudo() -> String {
        crate::pamwire::tests::fixture("opensuse", "sudo")
    }

    /// A gate an administrator put above irlume's sudo or polkit line stays
    /// above it when the vendor copy goes away, whether it goes before or
    /// after a disable: the file then comes back byte for byte.
    #[test]
    fn a_gate_above_irlume_stays_above_it_when_the_vendor_copy_is_gone() {
        let suse = opensuse_sudo();
        let cases: [(&str, WireFn<'_>); 3] = [
            (&suse, &wire_verify_service),
            (FEDORA_SUDO, &wire_verify_service),
            (POLKIT_VENDOR, &wire_polkit_service),
        ];
        for (vendor, wire) in cases {
            let edited = insert_above(&created(vendor, wire), "pam_irlume.so", FAILLOCK);
            // The vendor copy goes after the disable, then before it.
            for vendor_at_disable in [Some(vendor), None] {
                let off =
                    written(&run(&edited, vendor_at_disable, false, wire)).expect("disable writes");
                assert!(!content_has_module(&off), "{off}");
                let d = run(&off, None, true, wire);
                let Some(on) = written(&d) else {
                    panic!("not wired again: {}\n{off}", d.message);
                };
                assert!(
                    position(&on, "pam_faillock.so") < position(&on, "pam_irlume.so"),
                    "{}\n{on}",
                    d.message
                );
                assert_eq!(on, edited, "{}", d.message);
            }
        }
    }

    fn run(current: &str, vendor: Option<&str>, enable: bool, wire: WireFn<'_>) -> Decision {
        decide(&input(Some(current), vendor, enable, wire)).unwrap()
    }

    /// A comment an administrator adds to the vendor's password line does not
    /// make it an administrator's line: disable then enable puts irlume's
    /// lines back next to it.
    #[test]
    fn a_comment_on_the_password_line_leaves_it_the_vendors() {
        let greetd = crate::pamwire::tests::fixture("fedora-45", "greetd");
        let face: WireFn<'_> = &|c: &str| wire_greeter_impl(c, true, false, true);
        let suse = opensuse_sudo();
        let cases: [(&str, &str, WireFn<'_>); 3] = [
            (&greetd, "auth       substack    system-auth", face),
            (
                &suse,
                "auth     include        common-auth",
                &wire_verify_service,
            ),
            (
                POLKIT_VENDOR,
                "auth       include      system-auth",
                &wire_polkit_service,
            ),
        ];
        for (vendor, password, wire) in cases {
            let commented = format!("{password}   # reviewed locally");
            let edited = created(vendor, wire).replacen(
                &format!("{password}\n"),
                &format!("{commented}\n"),
                1,
            );
            assert!(edited.contains(&commented));
            let off = written(&run(&edited, Some(vendor), false, wire)).expect("disable writes");
            let d = run(&off, Some(vendor), true, wire);
            assert_eq!(
                written(&d).as_deref(),
                Some(edited.as_str()),
                "{}\n{off}",
                d.message
            );
        }
    }

    /// An administrator's verbatim copy of a vendor line is theirs, whichever
    /// copy a line-by-line match would pair with the vendor's: irlume's line
    /// keeps its side of both copies.
    #[test]
    fn a_copied_vendor_line_above_irlume_stays_above_it() {
        let copy = "auth       include      system-auth";
        // The polkit stanza migration, in a file with the copy above it.
        let old = format!(
            "{}\n#%PAM-1.0\n{copy}\n{VERIFY_STANZA}\n{}",
            created_line("/usr/lib/pam.d/plasmalogin"),
            POLKIT_VENDOR.trim_start_matches("#%PAM-1.0\n")
        );
        let d = run(&old, Some(POLKIT_VENDOR), true, &wire_polkit_service);
        assert_eq!(
            written(&d).as_deref(),
            Some(
                old.replacen(VERIFY_STANZA, POLKIT_VERIFY_STANZA, 1)
                    .as_str()
            ),
            "the new stanza takes the old one's place: {}",
            d.message
        );
        // Disable, then enable, with the vendor copy there or gone: irlume
        // cannot tell which copy is the vendor's, so disable keeps an
        // inactive line in its place and enable puts it back there.
        let edited = insert_above(
            &created(POLKIT_VENDOR, &wire_polkit_service),
            "pam_irlume.so",
            copy,
        );
        for vendor in [Some(POLKIT_VENDOR), None] {
            let d = run(&edited, vendor, false, &wire_polkit_service);
            let off = written(&d).expect("disable writes");
            assert!(!content_has_module(&off), "{off}");
            assert!(off.contains(INERT_TAG), "{}\n{off}", d.message);
            let d = run(&off, vendor, true, &wire_polkit_service);
            assert_eq!(
                written(&d).as_deref(),
                Some(edited.as_str()),
                "{}",
                d.message
            );
            // Stripped by hand instead: enable does not guess.
            let p = parse(&off).unwrap();
            let bare = keep_header(&p, &base(&p.body));
            let d = run(&bare, vendor, true, &wire_polkit_service);
            assert_eq!(d.write, Write::Nothing, "{}", d.message);
            assert!(d.message.starts_with('⚠'), "{}", d.message);
        }
    }

    /// An override nobody edited whose vendor copy is gone can take new
    /// kinds of irlume's lines: every line in it is the vendor's, so irlume's
    /// lines go where a rebuild from that text puts them.
    #[test]
    fn an_unedited_override_whose_vendor_copy_is_gone_can_gain_face() {
        let arch = crate::pamwire::tests::fixture("arch", "sddm");
        for vendor in [VENDOR, arch.as_str()] {
            let tracked = created(vendor, &keyring_only);
            let p = parse(&tracked).unwrap();
            assert_eq!(classify(&p, None), Class::U3);
            let want = keep_header(&p, &greeter(&base(&p.body)).0);
            for force in [false, true] {
                let mut i = input(Some(&tracked), None, true, &greeter);
                i.force = force;
                let d = decide(&i).unwrap();
                assert!(!d.unmet, "{}", d.message);
                assert_eq!(d.change, PlannedChange::RewireOverride, "{}", d.message);
                assert_eq!(written(&d).as_deref(), Some(want.as_str()), "{}", d.message);
            }
            // With a line of an administrator's, irlume cannot tell which
            // lines are the vendor's, and says how to go on.
            let edited = insert_above(&tracked, "pam_irlume.so keyring", "# local");
            let edited = insert_above(&edited, "# local", FAILLOCK);
            let d = run(&edited, None, true, &greeter);
            assert!(d.unmet, "{}", d.message);
            assert!(d.message.contains("put it back"), "{}", d.message);
        }
    }

    /// A legacy override whose only difference from its vendor copy is lines
    /// the vendor added after irlume wrote it reads as such, and doctor warns
    /// about it, as it does for any file irlume will not rebuild.
    #[test]
    fn an_override_that_only_lacks_vendor_lines_says_so() {
        let v2 = vendor_v2();
        let old = legacy(VENDOR);
        let (level, note) = assess(
            Recipe::Greeter,
            &old,
            "/usr/lib/pam.d/plasmalogin",
            Some(&v2),
            &[],
            None,
            "",
        );
        assert_eq!(level, Level::Warn, "{note:?}");
        let note = note.unwrap();
        assert!(note.contains("lacks 1 line"), "{note}");
        let on = run(&old, Some(&v2), true, &greeter);
        assert_eq!(on.change, PlannedChange::KeepEditedOverride);
        assert!(on.message.contains("lacks 1 line"), "{}", on.message);
        assert!(
            !on.message.contains("lines irlume did not write"),
            "{}",
            on.message
        );
        let off = run(&old, Some(&v2), false, &greeter);
        assert_eq!(off.change, PlannedChange::StripInPlace);
        assert!(off.message.contains("lacks 1 line"), "{}", off.message);
        assert!(
            !off.message.contains("lines irlume did not write"),
            "{}",
            off.message
        );
    }

    /// A blank line or a comment has no effect on PAM, so one under the
    /// password stack does not stop irlume adding a line above that stack.
    #[test]
    fn a_blank_or_comment_line_does_not_block_adding_face() {
        let tracked = created(VENDOR, &keyring_only);
        for extra in ["", "# local: wallet below"] {
            let edited = insert_below(&tracked, "substack      password-auth", extra);
            let d = run(&edited, Some(VENDOR), true, &greeter);
            assert!(!d.unmet, "{}", d.message);
            assert_eq!(d.change, PlannedChange::RewireOverride, "{}", d.message);
            let on = written(&d).unwrap();
            assert!(on.contains("pam_irlume.so unseal"), "{on}");
            assert!(on.contains(&format!("\n{extra}\n")), "{on}");
        }
    }

    /// Doctor does not keep warning about a strip irlume checked moved no
    /// jump, and does not claim a jump counts inactive lines once none does.
    #[test]
    fn doctor_notes_follow_what_the_strip_found() {
        let vp = "/usr/lib/pam.d/plasmalogin";
        let tracked = generation(VENDOR);
        let account_jump =
            "account    [success=1 default=ignore]   pam_succeed_if.so uid < 1000 quiet   # local";
        let edited = insert_above(
            &tracked,
            "account     include       password-auth",
            account_jump,
        );
        let d = run(&edited, Some(VENDOR), false, &greeter);
        assert!(
            d.message.contains("removed irlume's lines"),
            "{}",
            d.message
        );
        let off = written(&d).unwrap();
        let (level, note) = assess(Recipe::Greeter, &off, vp, Some(VENDOR), &[], None, "");
        assert_ne!(level, Level::Warn, "{note:?}");
        // Inactive lines whose jump the administrator removed again.
        let gate = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup noface quiet   # local";
        let edited = insert_above(&tracked, "pam_irlume.so unseal", gate);
        let off = written(&run(&edited, Some(VENDOR), false, &greeter)).unwrap();
        assert!(off.contains(INERT_TAG), "{off}");
        let reverted: String = off
            .lines()
            .filter(|l| !l.contains("noface"))
            .map(|l| format!("{l}\n"))
            .collect();
        let (_, note) = assess(Recipe::Greeter, &reverted, vp, Some(VENDOR), &[], None, "");
        let note = note.unwrap_or_default();
        assert!(!note.contains("because a numeric jump"), "{note}");
        assert!(note.contains("nothing needs them any more"), "{note}");
        assert!(note.contains("login disable --apply"), "{note}");
    }

    /// A vendor jump that irlume's lines had moved lands where the vendor
    /// meant once disable takes them out.
    #[test]
    fn disable_returns_a_vendor_jump_irlume_moved_to_the_vendors_landing() {
        let vendor = VENDOR.replacen(
            "auth        substack      password-auth\n",
            "auth       [success=1 default=ignore]   pam_fprintd.so\nauth        substack      password-auth\n",
            1,
        );
        let edited = insert_above(
            &generation(&vendor),
            "include       postlogin",
            "# local note",
        );
        let off = written(&run(&edited, Some(&vendor), false, &greeter)).unwrap();
        let landings =
            |text: &str| -> Vec<Landing> { jumps(text).into_iter().map(|j| j.landing).collect() };
        assert_eq!(landings(&off), landings(&vendor), "{off}");
        assert!(!has_irlume_line(&off), "{off}");
        // With an administrator's line inside that jump, the jump would
        // skip it without irlume's lines, so they stay as inactive lines.
        let inside = insert_above(&edited, "pam_irlume.so unseal", FAILLOCK);
        let off = written(&run(&inside, Some(&vendor), false, &greeter)).unwrap();
        assert!(off.contains(INERT_TAG), "{off}");
    }

    /// PAM does not read a line that ends in a carriage return, so an
    /// override saved with CRLF endings refuses every login. irlume does not
    /// report it as correctly wired, rewrites it with LF endings, and keeps
    /// every line.
    #[test]
    fn an_override_with_crlf_endings_is_not_correctly_wired() {
        let vp = "/usr/lib/pam.d/plasmalogin";
        let tracked = generation(VENDOR);
        for text in [tracked.clone(), with_admin_line(&tracked)] {
            let crlf = text.replace('\n', "\r\n");
            let d = run(&crlf, Some(VENDOR), true, &greeter);
            assert_eq!(written(&d).as_deref(), Some(text.as_str()), "{}", d.message);
            let (level, note) = assess(Recipe::Greeter, &crlf, vp, Some(VENDOR), &[], None, "");
            assert_eq!(level, Level::Warn, "{note:?}");
            assert!(note.unwrap().contains("CRLF"));
        }
    }

    /// A kept file whose irlume lines were taken out by hand says it is not
    /// wired and what stands in the way, not that irlume's lines were left
    /// as they were.
    #[test]
    fn a_kept_file_without_irlume_lines_says_it_is_not_wired() {
        let tracked = generation(VENDOR);
        let p = parse(&tracked).unwrap();
        let stripped = with_admin_line(&keep_header(&p, &base(&p.body)));
        let d = run(&stripped, Some(VENDOR), true, &greeter);
        assert!(d.unmet, "{}", d.message);
        assert_eq!(d.write, Write::Nothing);
        assert!(
            d.message.contains(
                "not wired: irlume's lines are not in it, and adding them would move a jump"
            ),
            "{}",
            d.message
        );
        assert!(!d.message.contains("were not updated"), "{}", d.message);
    }

    /// `--force` stops when `.pre-irlume` holds another file, so every place
    /// that suggests it says to move that file first.
    #[test]
    fn a_different_backup_is_named_where_force_is_suggested() {
        let v2 = vendor_v2();
        let old = with_admin_line(&legacy(VENDOR));
        let name = "plasmalogin.pre-irlume";
        let vp = "/usr/lib/pam.d/plasmalogin";
        let (_, note) = assess(Recipe::Greeter, &old, vp, Some(&v2), &[], Some(name), "");
        let note = note.unwrap();
        assert!(
            note.contains(
                "once plasmalogin.pre-irlume, which holds a different file, is moved away"
            ),
            "{note}"
        );
        let (_, note) = assess(Recipe::Greeter, &old, vp, Some(&v2), &[], None, "");
        assert!(!note.unwrap().contains("moved away"));
        let mut i = input(Some(&old), Some(&v2), true, &greeter);
        i.backup = Some("an older stack\n");
        let detail = decide(&i).unwrap().detail.unwrap();
        assert!(
            detail.contains("move /etc/pam.d/plasmalogin.pre-irlume away first"),
            "{detail}"
        );
        i.backup = Some(&old);
        let detail = decide(&i).unwrap().detail.unwrap();
        assert!(!detail.contains("away first"), "{detail}");
    }

    /// Only recording the tracking line in a legacy file that matches its
    /// vendor copy changes no PAM line; a caller may skip that write when the
    /// file cannot be written.
    #[test]
    fn only_the_record_of_a_matching_legacy_file_is_header_only() {
        let d = run(&legacy(VENDOR), Some(VENDOR), true, &greeter);
        assert_eq!(d.change, PlannedChange::MaterializeOverride);
        assert!(d.header_only, "{}", d.message);
        for (text, vendor) in [
            (generation(VENDOR), vendor_v2()),
            (legacy(VENDOR).replace('\n', "\r\n"), VENDOR.to_string()),
        ] {
            let d = run(&text, Some(&vendor), true, &greeter);
            assert_ne!(d.write, Write::Nothing, "{}", d.message);
            assert!(!d.header_only, "{}", d.message);
        }
        let d = run(&legacy(VENDOR), Some(VENDOR), true, &keyring_only);
        assert!(!d.header_only, "{}", d.message);
    }
}
