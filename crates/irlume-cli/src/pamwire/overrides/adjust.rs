// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `--adjust-jumps`: keep where a numeric jump lands when irlume puts its
//! lines inside it (`login enable`) or takes them out of it
//! (`login disable`), by changing the jump's value.
//!
//! pam.conf(5): in a bracketed control such as `[success=1 default=ignore]`,
//! an action that is a number N jumps over the next N modules in the stack,
//! and N equal to 0 is not allowed. Only lines of the same type count. A
//! `substack` line counts as one module (libpam skips the modules of the
//! substack with it); an `include` line counts as every line of that type in
//! the file it names, which this file does not show. pam.conf(5) calls the
//! jump "equivalent to ok", but libpam's `_pam_dispatch_aux` treats it as
//! `ok` only when it replays a frozen chain (`pam_setcred`,
//! `pam_close_session`): in the auth chain a jump records nothing, so what
//! the stack returns is decided by the lines it lands on and after. That is
//! why irlume's own face jump lands on a `pam_permit.so` line.
//!
//! An administrator who writes `[success=1 default=ignore] pam_fprintd.so`
//! above the password substack counts the lines as they stand, so irlume's
//! face line put between the two makes the jump land on the password step it
//! was written to skip (#875).
//!
//! An adjusted action skips the same lines of the file as before, and
//! irlume's lines among them, and lands on the same line as before. There is
//! one exception, the one #875 asks for: the `success` action of a
//! `pam_fprintd.so` line lands on irlume's `pam_permit.so` landing when an
//! enable adds that line right after the last line the jump skips
//! (`success=1` becomes `success=2`). pam_fprintd.so returns `PAM_SUCCESS`
//! only for a verified fingerprint, the landing records that success, and
//! irlume's keyring and reseal lines after it run, as its keyring line
//! expects after a trusted factor. No other module gets that landing: after
//! one that does not authenticate, such as a `pam_succeed_if.so` group
//! check, it would record a success nothing had earned.
//!
//! A disable that takes out the line a jump landed on, one of irlume's, lands
//! the jump on the first line after it that stays. The stack reached that
//! line from there whenever irlume's module declined, which every wired
//! stack must be safe in, so the jump reaches nothing it could not reach
//! before. A jump of the vendor copy that irlume's lines had moved (the
//! override was made with a warning) is left as the vendor wrote it: taking
//! irlume's lines out gives it back its vendor landing, as a disable without
//! the flag does.
//!
//! Lines are read and counted as the rest of the wiring reads them, which is
//! as libpam reads them (`grammar`): a line with a type and no control, or
//! with a control libpam rejects, is a module of its type's chain, and
//! `[success = 1 default=ignore]` is the same jump as
//! `[success=1 default=ignore]`. A new value is written over the digits
//! libpam reads for that jump, every other byte of the line as it was
//! ([`with_jump_values`]), so `success = 1` becomes `success = 2`.
//!
//! Refused, with the file kept as it is: a file whose other lines do not stay
//! as they are (irlume's own lines already there that an enable would change
//! among them, see [`OWN_LINES`]), a `substack` whose file irlume cannot show
//! libpam loads as one stack (see [`unopened`]), a jump across an include, an
//! include above lines of irlume's the adjustment adds or takes out whose
//! stack has a numeric jump that could land past its end (see
//! [`include_jump`]), a jump past the end of the stack, one that would become
//! 0, a disable that would land a jump on the end of the stack, a control
//! that is not in brackets or names a value it changes in more than one pair,
//! and an adjusted line whose text is not the only one of its kind. A line
//! continued with `\`, a carriage return PAM reads and any other line irlume
//! does not read as libpam does ([`unreadable_line`]) are refused as well,
//! although no caller gets here with one: every enable and disable refuses
//! such a file first. The text this returns is checked again as written (see
//! [`prove`]).

use super::super::grammar::{
    head, include_could_jump_past, include_is_read, rule_names_module, stack_name, unreadable_line,
    with_jump_values,
};
use super::super::stanzas::PERMIT_LANDING;
use super::{
    as_the_vendor_has_them, has_line_continuation, in_chain, is_include, is_irlume_line,
    jump_shifts, jumps_moved_by_irlume, kind, landing_of, line_key, norm, numeric_actions, phase,
    role_of_kind, Landing, PHASES,
};

/// A line whose control an adjustment changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Changed {
    /// The line as it is and as it becomes, trimmed, to compare. A message
    /// shows [`Changed::describe`] instead, never the line's text: a module's
    /// arguments can hold a secret, and reconcile's messages reach the
    /// system journal.
    pub(super) before: String,
    pub(super) after: String,
    /// How a message names the line: its number in the file as it is.
    pub(super) name: String,
    /// Each value whose jump changes, as `(value, from, to)`.
    pub(super) edits: Vec<(String, usize, usize)>,
    /// Each action of the line that lands on a line other than the one it
    /// landed on before, in words; every other action lands on the same
    /// line.
    pub(super) notes: Vec<String>,
}

impl Changed {
    /// The change for a message: the line by its number, and each jump
    /// before and after (`line 5: success=1 becomes success=2`).
    pub(super) fn describe(&self) -> String {
        let edits: Vec<String> = self
            .edits
            .iter()
            .map(|(value, from, to)| format!("`{value}={from}` becomes `{value}={to}`"))
            .collect();
        format!("{}: {}", self.name, edits.join(", "))
    }
}

/// A file with its jumps adjusted.
#[derive(Debug)]
pub(super) struct Adjusted {
    /// The text to write.
    pub(super) text: String,
    /// The lines whose control changed, in file order.
    pub(super) changed: Vec<Changed>,
    /// Each action that keeps its value and lands on a line other than the
    /// one it landed on before, in words, naming its line: a disable took
    /// out the line of irlume's it landed on.
    pub(super) moved: Vec<String>,
}

/// Which way irlume's lines move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Way {
    /// `after` is `before` with lines of irlume's added: an enable.
    Add,
    /// `after` is `before` with lines of irlume's taken out: a disable.
    Remove,
}

/// What libpam reads around the text `before` and `after` hold, which the
/// text itself does not show, and how a message names a line of it.
pub(super) struct Source<'a> {
    /// The file `before` was read from has a carriage return PAM reads (one
    /// outside a comment), which the reading took off (see `Parsed::body` in
    /// the parent). No caller gets here with one: every enable and disable
    /// refuses such a file first (`Parsed::unreadable`).
    pub(super) carriage_return: bool,
    /// Whether libpam loads the file a `substack` line names as one stack
    /// (see [`unopened`]).
    pub(super) opens: &'a dyn Fn(&str) -> bool,
    /// The number, counting from 1, of the line of the file that the line
    /// of `before` at an index is: a message names a line by it, never by
    /// its text.
    pub(super) number: &'a dyn Fn(usize) -> usize,
    /// The vendor copy the file was made from, when there is one. A disable
    /// leaves a jump of it that irlume's lines had moved as the vendor wrote
    /// it, since taking them out gives it back its vendor landing
    /// (`as_the_vendor_has_them` in the parent).
    pub(super) vendor: Option<&'a str>,
}

/// `after`, which is `before` with lines of irlume's added, with each numeric
/// jump those lines land inside raised by their number (see the module
/// documentation). The error says why it cannot be done.
pub(super) fn raise(before: &str, after: &str, source: &Source<'_>) -> Result<Adjusted, String> {
    adjust(before, after, Way::Add, source)
}

/// `after`, which is `before` with lines of irlume's taken out, with each
/// numeric jump that counted them lowered by their number (see the module
/// documentation). The error says why it cannot be done.
pub(super) fn lower(before: &str, after: &str, source: &Source<'_>) -> Result<Adjusted, String> {
    adjust(before, after, Way::Remove, source)
}

/// Why an enable cannot adjust a jump when lines of irlume's already in the
/// file (inactive lines a disable left, or an older version of them) do not
/// stay as they are: the adjustment counts only lines irlume adds or only
/// lines it takes out. The refusal goes on to say whether a disable with the
/// flag takes them out, after which an enable with the flag only adds (see
/// `own_lines_way` in the parent).
pub(super) const OWN_LINES: &str = "irlume's lines already in the file (inactive lines a \
                                    disable left, or an older version of them) would change \
                                    as well, and --adjust-jumps changes a jump only for lines \
                                    irlume adds or only for lines it takes out";

/// Why no jump is adjusted in a file with a carriage return PAM reads.
const CARRIAGE_RETURN: &str = "the file has a carriage return outside a comment, which PAM \
                               reads as part of its line, so irlume cannot count the lines a \
                               jump skips as PAM does";

/// How the lines of `before` and `after` pair up.
struct Pairing {
    /// For each line of `before`, the index of the same line in `after`, or
    /// `None` for a line of irlume's a disable takes out.
    to_after: Vec<Option<usize>>,
    /// For each line of `after`, the index of the same line in `before`, or
    /// `None` for a line of irlume's an enable adds.
    to_before: Vec<Option<usize>>,
    /// For each line of `after`, whether it is a line of irlume's an enable
    /// adds.
    added: Vec<bool>,
}

/// The indices in `more` of the lines of `fewer`, in order, taking the first
/// line that fits each time. `None` when `fewer` is not `more` with lines
/// taken out.
fn first_fit(fewer: &[&str], more: &[&str]) -> Option<Vec<usize>> {
    let mut at = Vec::with_capacity(fewer.len());
    let mut j = 0;
    for line in fewer {
        while *more.get(j)? != *line {
            j += 1;
        }
        at.push(j);
        j += 1;
    }
    Some(at)
}

/// As [`first_fit`], taking the last line that fits each time.
fn last_fit(fewer: &[&str], more: &[&str]) -> Option<Vec<usize>> {
    let mut at = vec![0; fewer.len()];
    let mut j = more.len();
    for (i, line) in fewer.iter().enumerate().rev() {
        loop {
            j = j.checked_sub(1)?;
            if more[j] == *line {
                break;
            }
        }
        at[i] = j;
    }
    Some(at)
}

/// Pair the lines of `before` and `after`. The lines that are in one and not
/// the other must all be irlume's, and there must be only one way to pair
/// them: every other way of fitting the lines lies between the first and the
/// last fit, so when those two agree there is no other. A repeated line that
/// could be the one irlume added or the one already there would otherwise
/// leave where a jump lands to a guess.
fn pair(b: &[&str], a: &[&str], way: Way) -> Result<Pairing, String> {
    let (fewer, more) = match way {
        Way::Add => (b, a),
        Way::Remove => (a, b),
    };
    let Some(at) = first_fit(fewer, more) else {
        // Every other line of the file stays, and only lines of irlume's
        // already in it change: say so, and what to run instead.
        let theirs: Vec<&str> = b.iter().copied().filter(|l| !is_irlume_line(l)).collect();
        let only_irlumes = |at: Vec<usize>| {
            let mut paired = vec![false; a.len()];
            for j in at {
                paired[j] = true;
            }
            a.iter().zip(&paired).all(|(l, p)| *p || is_irlume_line(l))
        };
        if way == Way::Add && first_fit(&theirs, a).is_some_and(only_irlumes) {
            return Err(OWN_LINES.to_string());
        }
        return Err("lines other than irlume's would change as well".to_string());
    };
    if last_fit(fewer, more).as_ref() != Some(&at) {
        return Err(
            "a line irlume adds or takes out repeats one next to it, so irlume cannot tell \
             which one a jump counts"
                .to_string(),
        );
    }
    let mut paired = vec![false; more.len()];
    for &j in &at {
        paired[j] = true;
    }
    if more
        .iter()
        .zip(&paired)
        .any(|(l, p)| !p && !is_irlume_line(l))
    {
        return Err("lines other than irlume's would change as well".to_string());
    }
    Ok(match way {
        Way::Add => {
            let mut to_before = vec![None; a.len()];
            for (i, &j) in at.iter().enumerate() {
                to_before[j] = Some(i);
            }
            Pairing {
                to_after: at.into_iter().map(Some).collect(),
                to_before,
                added: paired.iter().map(|p| !p).collect(),
            }
        }
        Way::Remove => {
            let mut to_after = vec![None; b.len()];
            for (i, &j) in at.iter().enumerate() {
                to_after[j] = Some(i);
            }
            Pairing {
                to_after,
                to_before: at.into_iter().map(Some).collect(),
                added: vec![false; a.len()],
            }
        }
    })
}

/// The indices of the lines in one phase's chain (see `chain` in the parent).
fn chain_at(lines: &[&str], phase_name: &str) -> Vec<usize> {
    (0..lines.len())
        .filter(|&i| in_chain(lines[i], phase_name))
        .collect()
}

/// irlume's `pam_permit.so` landing, the line after the password step its own
/// face jump lands on.
fn is_permit_landing(line: &str) -> bool {
    is_irlume_line(line) && line.contains("# irlume-landing")
}

/// A line whose `success` may land on irlume's permit landing (see the
/// module documentation): pam_fprintd.so, whose success is a verified
/// fingerprint.
fn is_fingerprint(line: &str) -> bool {
    rule_names_module(line, "pam_fprintd.so")
}

/// One numeric action an adjustment changes: `key` on the line at `line` of
/// `after` goes from `from` to `to`.
struct Step {
    phase: &'static str,
    line: usize,
    key: String,
    from: usize,
    to: usize,
    /// The line's place in its chain, in `before` and in `after`.
    before_at: usize,
    after_at: usize,
    /// Whether it lands on the same line as before, rather than on the
    /// permit landing an enable adds or past a line a disable takes out.
    same_line: bool,
}

/// What one of irlume's lines is, for a message (`role_of_kind` in the
/// parent): `pam_permit.so landing`, `auth keyring line`.
fn role(line: &str) -> String {
    role_of_kind(&kind(line))
}

/// How a message names the line at `at` of `before`, the file as it is: by
/// its number in the file, and what it is when it is one of irlume's lines.
/// Never by its text: a module's arguments can hold a secret, and
/// reconcile's messages reach the system journal.
fn name_before(before: &[&str], at: usize, source: &Source<'_>) -> String {
    let number = (source.number)(at);
    if is_irlume_line(before[at]) {
        format!("irlume's {} (line {number})", role(before[at]))
    } else {
        format!("line {number}")
    }
}

/// Why irlume cannot tell that libpam counts the `substack` line `line` as
/// one module of its stack; `None` for any other line and for a substack
/// whose file libpam loads as one stack (`source.opens`). `name` names the
/// line.
///
/// libpam adds a substack line to its stack, then loads the file it names;
/// when it cannot open or load that file, it adds a module that always fails
/// after it, at the same level (`pam_handlers.c`). A jump over such a line
/// skips two modules, so a value irlume computed would land a line further
/// in PAM. An `include` line whose file libpam cannot open becomes one such
/// module in place of the file's lines; no jump across an include is
/// adjusted, so it needs no check here.
fn unopened(line: &str, name: &dyn Fn() -> String, source: &Source<'_>) -> Option<String> {
    let h = head(line)?;
    if !h.control.eq_ignore_ascii_case("substack") {
        return None;
    }
    // libpam turns `\]` in a bracketed name into `]`, which irlume does not:
    // such a name is not looked up. A substack that names no stack is one
    // [`unreadable_line`] names first.
    if stack_name(&h).is_some_and(|stack| !stack.contains('\\') && (source.opens)(stack)) {
        return None;
    }
    Some(format!(
        "PAM counts the substack on {} as two modules, the substack and one that always fails, \
         when it cannot load the stack it names, and irlume cannot read that stack where PAM \
         finds it, or cannot read every line of it as PAM does, so it cannot count the lines a \
         jump skips",
        name()
    ))
}

/// Why a numeric jump in a stack an include puts in its place could count
/// lines of irlume's this adjustment adds or takes out; `None` when none
/// could.
///
/// libpam puts the included stack's lines in the include's place, so a jump
/// among them that lands past them counts the lines after the include, and
/// no value in this file changes it. Read as `jump_could_count_irlume_lines`
/// reads it for a disable ([`include_could_jump_past`]): the stacks through
/// the reader the caller set, a stack that cannot be read counting.
fn include_jump(b: &[&str], a: &[&str], pairing: &Pairing, source: &Source<'_>) -> Option<String> {
    b.iter().enumerate().find_map(|(at, line)| {
        // Whether a line of irlume's of type `kind` that this adjustment adds
        // or takes out comes after the include.
        let later = |kind: &str| {
            let added_after = pairing.to_after[at].is_some_and(|from| {
                (from + 1..a.len()).any(|k| pairing.added[k] && phase(a[k]) == Some(kind))
            });
            let taken_after = (at + 1..b.len())
                .any(|k| pairing.to_after[k].is_none() && phase(b[k]) == Some(kind));
            added_after || taken_after
        };
        (include_could_jump_past(line, later) == Some(true)).then(|| {
            let name = name_before(b, at, source);
            if include_is_read(line) {
                format!(
                    "a numeric jump in the stack the include on {name} puts in its place could \
                     land past that stack's end, onto irlume's lines after it, and irlume \
                     changes no jump in an included stack"
                )
            } else {
                format!(
                    "irlume cannot read the stack the include on {name} names, or one it \
                     includes in turn, where PAM finds it, so it cannot tell whether a numeric \
                     jump there lands past its end, onto irlume's lines after it"
                )
            }
        })
    })
}

/// Why irlume cannot place a line in its stack; not expected, since a line
/// keeps its text and so its phase.
const UNPLACED: &str = "irlume cannot place a line in its stack";

fn adjust(before: &str, after: &str, way: Way, source: &Source<'_>) -> Result<Adjusted, String> {
    if source.carriage_return {
        return Err(CARRIAGE_RETURN.to_string());
    }
    if has_line_continuation(before) || has_line_continuation(after) {
        return Err("a line ends in `\\`, which PAM joins with the next line".to_string());
    }
    // Named by number and why, as the rest of the wiring names such a line.
    if let Some(line) = unreadable_line(before) {
        return Err(format!(
            "irlume does not read line {} as PAM does ({}), so it cannot count the lines a jump \
             skips",
            (source.number)(line.number - 1),
            line.why.describe()
        ));
    }
    if let Some(line) = unreadable_line(after) {
        return Err(format!(
            "irlume would not read a line it writes as PAM does ({})",
            line.why.describe()
        ));
    }
    let b: Vec<&str> = before.lines().collect();
    let a: Vec<&str> = after.lines().collect();
    let name_b = |at: usize| name_before(&b, at, source);
    if let Some(why) = (0..b.len()).find_map(|at| unopened(b[at], &|| name_b(at), source)) {
        return Err(why);
    }
    let pairing = pair(&b, &a, way)?;
    // The lines irlume adds are its own, never a substack; checked all the
    // same, since the count relies on it.
    let added = (0..a.len()).filter(|&at| pairing.added[at]);
    if let Some(why) = added
        .into_iter()
        .find_map(|at| unopened(a[at], &|| "a line irlume adds".to_string(), source))
    {
        return Err(why);
    }
    if let Some(why) = include_jump(&b, &a, &pairing, source) {
        return Err(why);
    }
    // How a message names the line at an index of `after`: as the line of
    // the file it was, or as the line of irlume's the enable adds.
    let name_a = |at: usize| match pairing.to_before[at] {
        Some(from) => name_b(from),
        None => format!("irlume's new {}", role(a[at])),
    };
    // The vendor's own jumps a disable gives back their vendor landings.
    let restored = match way {
        Way::Add => Vec::new(),
        Way::Remove => as_the_vendor_has_them(after, source.vendor),
    };
    let mut steps: Vec<Step> = Vec::new();
    // For each action that lands on another line: its line, the action as
    // it is written now, and where it lands.
    let mut notes: Vec<(usize, String, String)> = Vec::new();
    // Each action of a vendor jump left as the vendor wrote it that lands
    // on another line than before, in words.
    let mut given_back: Vec<String> = Vec::new();
    for phase_name in PHASES {
        let cb = chain_at(&b, phase_name);
        let ca = chain_at(&a, phase_name);
        let place = |line: usize| ca.iter().position(|&x| x == line).ok_or(UNPLACED);
        let end = format!("the end of the {phase_name} stack");
        for (b_at, &bl) in cb.iter().enumerate() {
            // A line taken out takes its jumps with it.
            let Some(al) = pairing.to_after[bl] else {
                continue;
            };
            let actions = numeric_actions(b[bl]);
            if actions.is_empty() {
                continue;
            }
            // The same text, so the same phase: it is in the chain.
            let a_at = place(al)?;
            // Which line of its phase with that text it is, as `jumps` in
            // the parent counts it: without irlume's lines, every such line
            // carries the same jumps.
            let ordinal = ca[..=a_at]
                .iter()
                .filter(|&&x| norm(a[x]) == norm(a[al]))
                .count();
            if restored.contains(&(phase_name, norm(a[al]), ordinal)) {
                // Left as the vendor wrote it: say where an action of it
                // now lands when that is another line than before.
                for (key, n) in &actions {
                    let (t, u) = (b_at + n + 1, a_at + n + 1);
                    if t > cb.len() || u > ca.len() {
                        continue;
                    }
                    let (was, now) = (cb.get(t).copied(), ca.get(u).copied());
                    let same = match (was, now) {
                        (Some(x), Some(y)) => pairing.to_after[x] == Some(y),
                        (None, None) => true,
                        _ => false,
                    };
                    if !same {
                        given_back.push(format!(
                            "`{key}={n}` on {} lands on {} rather than {}, as the vendor copy \
                             has it",
                            name_b(bl),
                            now.map_or_else(|| end.clone(), name_a),
                            was.map_or_else(|| end.clone(), name_b)
                        ));
                    }
                }
                continue;
            }
            for (key, n) in actions {
                let what = || format!("`{key}={n}` on {}", name_b(bl));
                let t = b_at + n + 1;
                if t > cb.len() {
                    // Past the end, which libpam logs as a bad jump and fails
                    // the stack on. Left alone unless irlume's lines change
                    // after it.
                    let touched = match way {
                        Way::Add => ca[a_at + 1..].iter().any(|&x| pairing.added[x]),
                        Way::Remove => cb[b_at + 1..]
                            .iter()
                            .any(|&x| pairing.to_after[x].is_none()),
                    };
                    if touched {
                        return Err(format!(
                            "{} jumps past the end of the {phase_name} stack",
                            what()
                        ));
                    }
                    continue;
                }
                let skipped = &cb[b_at + 1..t];
                let lands_before = cb.get(t).copied();
                // The last skipped line that stays, as a place in `ca`.
                let a_last = match skipped.iter().rev().find_map(|&x| pairing.to_after[x]) {
                    Some(x) => place(x)?,
                    None => a_at,
                };
                // Where the new jump lands, as a place in `ca` (its length
                // for the end of the stack), and whether that is the line it
                // landed on before.
                let (land, same_line) = match way {
                    Way::Add => {
                        // An enable keeps every line, the landing included:
                        // skip irlume's lines up to it.
                        let same = match lands_before {
                            Some(x) => place(pairing.to_after[x].ok_or(UNPLACED)?)?,
                            None => ca.len(),
                        };
                        let permit = a_last + 1;
                        let onto_permit = key == "success"
                            && lands_before.is_some()
                            && is_fingerprint(b[bl])
                            && permit < same
                            && pairing.added[ca[permit]]
                            && is_permit_landing(a[ca[permit]]);
                        if onto_permit {
                            (permit, false)
                        } else {
                            (same, true)
                        }
                    }
                    // A disable lands it on the line after the last line it
                    // skips that stays: the same line, unless irlume's line
                    // it landed on is taken out.
                    Way::Remove => {
                        let land = a_last + 1;
                        let same = match (lands_before, ca.get(land)) {
                            (Some(x), Some(&y)) => pairing.to_after[x] == Some(y),
                            (None, None) => true,
                            _ => false,
                        };
                        (land, same)
                    }
                };
                let to = land - a_at - 1;
                if to == n && same_line {
                    continue;
                }
                if is_irlume_line(b[bl]) {
                    return Err(format!("irlume's own jump on {} would move", name_b(bl)));
                }
                let across = skipped.iter().any(|&x| is_include(b[x]))
                    || ca[a_at + 1..land].iter().any(|&x| is_include(a[x]));
                if across {
                    return Err(format!(
                        "{} crosses an include, whose lines irlume cannot count",
                        what()
                    ));
                }
                if to == 0 {
                    return Err(format!(
                        "{} skips only irlume's lines, and a jump of 0 is not one",
                        what()
                    ));
                }
                let lands_after = ca.get(land).copied();
                if !same_line {
                    // An enable moves only a fingerprint's success, onto the
                    // permit landing (checked above). A disable moves a jump
                    // only off a line of irlume's it takes out, onto a line.
                    let lost = lands_before.is_some_and(|x| pairing.to_after[x].is_none())
                        && lands_after.is_some();
                    let now = lands_after.map_or_else(|| end.clone(), name_a);
                    let was = lands_before.map_or_else(|| end.clone(), name_b);
                    if way == Way::Remove && !lost {
                        return Err(format!("{} would land on {now} rather than {was}", what()));
                    }
                    notes.push((
                        al,
                        format!("`{key}={to}`"),
                        match way {
                            Way::Add => format!(
                                "lands on {now} rather than {was}; that landing records the \
                                 verified fingerprint's success"
                            ),
                            Way::Remove => {
                                format!("lands on {now} rather than on {was}, which is taken out")
                            }
                        },
                    ));
                }
                steps.push(Step {
                    phase: phase_name,
                    line: al,
                    key,
                    from: n,
                    to,
                    before_at: b_at,
                    after_at: a_at,
                    same_line,
                });
            }
        }
    }
    let mut out: Vec<String> = a.iter().map(|l| (*l).to_string()).collect();
    let mut changed: Vec<Changed> = Vec::new();
    let mut moved: Vec<String> = Vec::new();
    let mut lines: Vec<usize> = steps.iter().map(|s| s.line).collect();
    lines.sort_unstable();
    lines.dedup();
    for &line in &lines {
        let name = name_a(line);
        // The jump check below names a line by its text, so a line it may
        // excuse must be the only one with that text, before and after the
        // change.
        if a.iter().filter(|l| norm(l) == norm(a[line])).count() != 1 {
            return Err(format!("{name} reads the same as another line of the file"));
        }
        let edits: Vec<(&str, usize, usize)> = steps
            .iter()
            .filter(|s| s.line == line && s.to != s.from)
            .map(|s| (s.key.as_str(), s.from, s.to))
            .collect();
        let noted = notes.iter().filter(|(l, _, _)| *l == line);
        if edits.is_empty() {
            moved.extend(noted.map(|(_, action, lands)| format!("{action} on {name} {lands}")));
            continue;
        }
        let Some(new) = with_jump_values(a[line], &edits) else {
            return Err(format!(
                "irlume changes a jump only in a control written in brackets that names each \
                 value it changes in one pair, and the control on {name} is not"
            ));
        };
        changed.push(Changed {
            before: a[line].trim().to_string(),
            after: new.trim().to_string(),
            edits: edits
                .iter()
                .map(|&(key, from, to)| (key.to_string(), from, to))
                .collect(),
            notes: noted
                .map(|(_, action, lands)| format!("{action} {lands}"))
                .collect(),
            name,
        });
        out[line] = new;
    }
    for &line in &lines {
        if out.iter().filter(|l| norm(l) == norm(&out[line])).count() != 1 {
            return Err(format!(
                "{} would then read the same as another line of the file",
                name_a(line)
            ));
        }
    }
    moved.extend(given_back);
    let text = format!("{}\n", out.join("\n"));
    prove(before, after, &text, way, &steps, &restored, source)?;
    Ok(Adjusted {
        text,
        changed,
        moved,
    })
}

/// Check the adjusted text as written, against `before` and the `after` it
/// was made from. Every line of it must be read as libpam reads it, as
/// [`adjust`] requires of `before` and `after`.
///
/// The jump check as the rest of this file runs it ([`jumps_moved_by_irlume`]
/// through `check_jumps`) cannot pass on an adjusted line, by design: the
/// line's text is new, so the check does not know it as a jump the file
/// already had, and without irlume's lines its new value lands somewhere
/// else. Instead:
///
/// - each adjusted line carries the value computed for each changed action,
///   and has the same place in its chain as in `after`;
/// - each changed action, counted as written, skips the same lines of the
///   file that are not irlume's as before, and lands on the same line, or on
///   the permit landing for a fingerprint's success in an enable, or past a
///   line of irlume's a disable takes out. Lines are named as they were
///   before any value changed, so an adjusted line another adjusted jump
///   skips or lands on is still that line;
/// - the jump check itself, [`jumps_moved_by_irlume`] for an enable and
///   [`jump_shifts`] for a disable, finds no jump moved on any line not
///   adjusted, other than a jump of the vendor copy the adjustment left as
///   the vendor wrote it (`restored`, found in `after` by
///   `as_the_vendor_has_them`). Such a line keeps its text and its place, and
///   every chain its places, so it skips and lands on the same places as in
///   `after`, where the vendor copy has it, whatever other line changed its
///   value. That check names a line by its text, so it runs against
///   `before` with each adjusted line given its new text: a jump that lands
///   on or skips an adjusted line is then compared by the line's place, as
///   the steps are.
fn prove(
    before: &str,
    after: &str,
    adjusted: &str,
    way: Way,
    steps: &[Step],
    restored: &[(&'static str, String, usize)],
    source: &Source<'_>,
) -> Result<(), String> {
    let b: Vec<&str> = before.lines().collect();
    let a: Vec<&str> = after.lines().collect();
    let w: Vec<&str> = adjusted.lines().collect();
    let broken = |why: &str| Err(format!("the adjusted file does not check out ({why})"));
    if w.len() != a.len() {
        return broken("a line was added or lost");
    }
    if unreadable_line(adjusted).is_some()
        || has_line_continuation(adjusted)
        || w.iter()
            .any(|l| unopened(l, &String::new, source).is_some())
    {
        return broken("a line irlume cannot read as PAM does");
    }
    for s in steps {
        if !numeric_actions(w[s.line]).contains(&(s.key.clone(), s.to)) {
            return broken("a value was not written");
        }
        let ib = chain_at(&b, s.phase);
        let iw = chain_at(&w, s.phase);
        if iw != chain_at(&a, s.phase) || iw.get(s.after_at) != Some(&s.line) {
            return broken("a line left its place");
        }
        let cb: Vec<&str> = ib.iter().map(|&i| b[i]).collect();
        let ca: Vec<&str> = iw.iter().map(|&i| a[i]).collect();
        let theirs = |chain: &[&str], at: usize, n: usize| -> Vec<String> {
            chain
                .iter()
                .skip(at + 1)
                .take(n)
                .filter(|l| !is_irlume_line(l))
                .map(|l| line_key(l))
                .collect()
        };
        if theirs(&cb, s.before_at, s.from) != theirs(&ca, s.after_at, s.to) {
            return broken("a jump skips other lines");
        }
        let was = landing_of(&cb, s.before_at, s.from);
        let now = landing_of(&ca, s.after_at, s.to);
        let fits = if s.same_line {
            was == now
        } else {
            match (way, &was, &now) {
                (Way::Add, Landing::Line { .. }, Landing::Line { key, .. }) => {
                    s.key == "success"
                        && is_fingerprint(w[s.line])
                        && key == &line_key(PERMIT_LANDING)
                }
                (Way::Remove, Landing::Line { key, .. }, Landing::Line { .. }) => {
                    key.starts_with("irlume ")
                }
                _ => false,
            }
        };
        if !fits {
            return broken("a jump lands elsewhere");
        }
    }
    let excused: Vec<String> = steps.iter().map(|s| norm(w[s.line])).collect();
    // `before` with each adjusted line as it is written now, in its place.
    let mut renamed = b.clone();
    for s in steps {
        let Some(&at) = chain_at(&b, s.phase).get(s.before_at) else {
            return broken("a line left its place");
        };
        renamed[at] = w[s.line];
    }
    let renamed = format!("{}\n", renamed.join("\n"));
    // A line left as the vendor wrote it keeps its text, and every chain its
    // places, so it lands by place where it does in `after`.
    let kept_places = PHASES
        .into_iter()
        .all(|phase_name| chain_at(&w, phase_name) == chain_at(&a, phase_name));
    let kept_texts = restored.iter().all(|(phase_name, line, ordinal)| {
        let with_text = |text: &[&str]| -> Vec<usize> {
            chain_at(text, phase_name)
                .into_iter()
                .filter(|&x| norm(text[x]) == *line)
                .collect()
        };
        let at = with_text(&a);
        at.get(ordinal - 1).is_some() && at == with_text(&w)
    });
    if !kept_places || !kept_texts {
        return broken("a line the vendor wrote left its place");
    }
    let shifts = match way {
        Way::Add => jumps_moved_by_irlume(&renamed, adjusted),
        Way::Remove => jump_shifts(&renamed, adjusted),
    };
    let given_back = |s: &super::Shift| restored.contains(&(s.phase, s.line.clone(), s.ordinal));
    if shifts
        .iter()
        .any(|s| !excused.contains(&s.line) && !given_back(s))
    {
        return broken("another jump moves");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::grammar::{with_stack_reader, StackReader};
    use super::super::super::stanzas::{
        GREETER_UNSEAL_COSMIC_JUMP, KEYRING_UNSEAL, PERMIT_LANDING, RESEAL_AUTH, RESEAL_SESSION,
    };
    use super::super::super::tests::{FEDORA_PASSWORD_AUTH, FEDORA_POSTLOGIN, UPSTREAM_FEDORA};
    use super::super::super::transform::{unwire_lines, wire_greeter_impl};
    use super::*;

    /// The stack files these tests' files name: Fedora's password stack and
    /// a fingerprint stack.
    fn opens(name: &str) -> bool {
        matches!(name, "password-auth" | "fingerprint-auth")
    }

    /// The number of the line at `at` of a file with no header lines.
    fn number(at: usize) -> usize {
        at + 1
    }

    /// A file read with no carriage return, whose stack files are [`opens`].
    const READ: Source<'static> = Source {
        carriage_return: false,
        opens: &opens,
        number: &number,
        vendor: None,
    };

    /// The number of the line of `text` that is `line`.
    fn number_of(text: &str, line: &str) -> usize {
        text.lines()
            .position(|l| l == line)
            .unwrap_or_else(|| panic!("`{line}` is not in the file"))
            + 1
    }

    /// The stacks these tests' files include, as Fedora ships them, and
    /// `extra` as given.
    fn stacks(extra: Option<&'static str>) -> StackReader {
        std::rc::Rc::new(move |name: &str| match name {
            "password-auth" => Some(FEDORA_PASSWORD_AUTH.to_string()),
            "postlogin" => Some(FEDORA_POSTLOGIN.to_string()),
            "extra" => extra.map(str::to_string),
            _ => None,
        })
    }

    /// [`super::raise`] with the stacks the caller sets for the file read as
    /// Fedora ships them.
    fn raise(before: &str, after: &str) -> Result<Adjusted, String> {
        with_stack_reader(stacks(None), || super::raise(before, after, &READ))
    }

    /// [`super::lower`], read as [`raise`] reads it.
    fn lower(before: &str, after: &str) -> Result<Adjusted, String> {
        with_stack_reader(stacks(None), || super::lower(before, after, &READ))
    }

    /// The issue's line, as written on the Fedora 44 ThinkPad (#875).
    const ISSUE_JUMP: &str = "auth [success=1 default=ignore] pam_fprintd.so max-tries=1 \
                              timeout=5   # fingerprint at the login screen (local)";

    fn face(content: &str) -> String {
        let (wired, ok) = wire_greeter_impl(content, true, true, true);
        assert!(ok);
        wired
    }

    fn keyring(content: &str) -> String {
        let (wired, ok) = wire_greeter_impl(content, false, true, false);
        assert!(ok);
        wired
    }

    /// `text` with `line` right above its password substack.
    fn above_substack(text: &str, line: &str) -> String {
        let anchor = "auth        substack      password-auth\n";
        assert!(text.contains(anchor), "{text}");
        text.replacen(anchor, &format!("{line}\n{anchor}"), 1)
    }

    fn vendor() -> String {
        unwire_lines(UPSTREAM_FEDORA).0
    }

    /// The file before face login: the keyring-only wiring an RGB camera
    /// gets, with the administrator's fingerprint line above the password
    /// substack. And what the face recipe makes of it.
    fn issue_files(jump: &str) -> (String, String) {
        let before = above_substack(&keyring(&vendor()), jump);
        let after = face(&unwire_lines(&before).0);
        (before, after)
    }

    // ---- an independent reading of where each line sends the stack --------------

    /// What libpam does after one module, per pam.conf(5): go on to the next
    /// line, jump over N lines, or stop (`done`, `die`, `requisite` on a
    /// failure). Read here without the code under test.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Go {
        Next,
        Skip(usize),
        Stop,
    }

    /// The auth lines of `text`, each with what its module's success and its
    /// failure do. A bracketed control's `success` falls back to its
    /// `default`, the last of two same actions wins and blanks around `=` do
    /// not count, as in libpam, and a line with no control goes on to the
    /// next line either way.
    fn auth_lines(text: &str) -> Vec<(String, Go, Go)> {
        text.lines()
            .filter_map(|line| {
                let d = squeeze_equals(line.split('#').next().unwrap_or(""));
                let mut words = d.split_whitespace();
                let kind = words.next()?;
                if kind.trim_start_matches('-').trim_matches(['[', ']']) != "auth" {
                    return None;
                }
                // A type with no control: PAM runs a module that always
                // fails there, and goes on.
                let Some(first) = words.next() else {
                    return Some((line.trim().to_string(), Go::Next, Go::Next));
                };
                let (on_success, on_failure) = if let Some(open) = first.strip_prefix('[') {
                    let mut control = vec![open];
                    let mut last = open;
                    while !last.ends_with(']') {
                        last = words.next()?;
                        control.push(last);
                    }
                    let pairs: Vec<(&str, &str)> = control
                        .iter()
                        .filter_map(|w| w.trim_end_matches(']').split_once('='))
                        .collect();
                    let find = |k: &str| {
                        pairs
                            .iter()
                            .rev()
                            .find(|(key, _)| *key == k)
                            .map(|(_, v)| *v)
                    };
                    let go = |v: Option<&str>| match v {
                        Some("done" | "die") => Go::Stop,
                        Some(v) => v.parse().map_or(Go::Next, Go::Skip),
                        None => Go::Next,
                    };
                    let default = find("default");
                    (go(find("success").or(default)), go(default))
                } else {
                    match first {
                        "sufficient" => (Go::Stop, Go::Next),
                        "requisite" => (Go::Next, Go::Stop),
                        _ => (Go::Next, Go::Next),
                    }
                };
                Some((line.trim().to_string(), on_success, on_failure))
            })
            .collect()
    }

    /// `text` with the blanks before and after each `=` taken out, which PAM
    /// skips in a control: `[success = 1]` reads as `[success=1]`.
    fn squeeze_equals(text: &str) -> String {
        let parts: Vec<&str> = text.split('=').collect();
        let last = parts.len() - 1;
        parts
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let part = if i > 0 { part.trim_start() } else { part };
                if i < last {
                    part.trim_end()
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("=")
    }

    /// Where `go` from the auth line at `at` lands: an index into
    /// [`auth_lines`] (past its end for the end of the stack), or `None` for
    /// a stop.
    fn lands(at: usize, go: Go) -> Option<usize> {
        match go {
            Go::Next => Some(at + 1),
            Go::Skip(n) => Some(at + 1 + n),
            Go::Stop => None,
        }
    }

    /// From the auth line at `at`, the lines that run until the next line
    /// that is not irlume's, with irlume's modules declining (a failure),
    /// the state every wired stack must be safe in; and that line, as an
    /// index into `lines` (`None` for the end of the stack or a stop).
    fn runs_to(lines: &[(String, Go, Go)], mut at: Option<usize>) -> (Vec<String>, Option<usize>) {
        let mut passed = Vec::new();
        while let Some(i) = at {
            let Some((line, _, on_failure)) = lines.get(i) else {
                return (passed, None);
            };
            if !is_irlume_line(line) {
                return (passed, Some(i));
            }
            passed.push(line.clone());
            at = lands(i, *on_failure);
        }
        (passed, None)
    }

    /// For every auth line that is not irlume's, before and after: on success
    /// and on failure, the next line not irlume's that runs is the same one
    /// (the same place among those lines: an adjusted line's own text
    /// changes), and, when irlume's lines are added (`adding`), irlume's
    /// lines that ran before still run. A jump runs irlume's permit landing,
    /// which records a success, on a path it did not run on before only for
    /// a fingerprint's success. Returns, for each such line of `after`, the
    /// line its success lands on first.
    fn assert_every_path_kept(
        before: &str,
        after: &str,
        adding: bool,
    ) -> Vec<(String, Option<String>)> {
        let lb = auth_lines(before);
        let la = auth_lines(after);
        let theirs = |lines: &[(String, Go, Go)]| -> Vec<usize> {
            (0..lines.len())
                .filter(|&i| !is_irlume_line(&lines[i].0))
                .collect()
        };
        let (tb, ta) = (theirs(&lb), theirs(&la));
        assert_eq!(tb.len(), ta.len(), "{before}\n---\n{after}");
        // Which of the lines that are not irlume's `at` is.
        let nth = |set: &[usize], at: Option<usize>| at.map(|k| set.iter().position(|&x| x == k));
        let permit = |ran: &[String]| ran.iter().any(|l| is_permit_landing(l));
        let mut first = Vec::new();
        for (&i, &j) in tb.iter().zip(&ta) {
            for (label, gb, ga) in [("success", lb[i].1, la[j].1), ("failure", lb[i].2, la[j].2)] {
                let (ran_before, reached_before) = runs_to(&lb, lands(i, gb));
                let (ran_after, reached_after) = runs_to(&la, lands(j, ga));
                assert_eq!(
                    nth(&tb, reached_before),
                    nth(&ta, reached_after),
                    "{label} of `{}` reaches another line\n{after}",
                    la[j].0
                );
                for line in ran_before.iter().filter(|_| adding) {
                    assert!(
                        ran_after.contains(line),
                        "{label} of `{}` no longer runs `{line}`\n{after}",
                        la[j].0
                    );
                }
                // A line that goes on to the next line reaches the landing
                // after the password step as irlume wires every stack; a
                // jump reaches it only by being moved there.
                if matches!(ga, Go::Skip(_)) && permit(&ran_after) && !permit(&ran_before) {
                    assert!(
                        label == "success" && is_fingerprint(&la[j].0),
                        "{label} of `{}` now runs irlume's permit landing\n{after}",
                        la[j].0
                    );
                }
            }
            first.push((
                la[j].0.clone(),
                lands(j, la[j].1)
                    .and_then(|k| la.get(k))
                    .map(|l| l.0.clone()),
            ));
        }
        first
    }

    /// Where the success of the line `line` of `after` lands first, from
    /// [`assert_every_path_kept`].
    fn success_of(first: &[(String, Option<String>)], line: &str) -> Option<String> {
        first
            .iter()
            .find(|(l, _)| l == line)
            .unwrap_or_else(|| panic!("`{line}` is not in the file"))
            .1
            .clone()
    }

    // ---- the issue's shape ----------------------------------------------------------

    /// The Fedora 44 plasmalogin of #875: the fingerprint line's `success=1`
    /// skips the password substack and lands on irlume's keyring line. Face
    /// login puts irlume's face line between them; raised to `success=2`, the
    /// jump skips the face line and the substack and lands on irlume's
    /// permit landing, after which the keyring and reseal lines run.
    #[test]
    fn the_issue_jump_is_raised_to_two_and_lands_on_the_permit_line() {
        let (before, after) = issue_files(ISSUE_JUMP);
        assert!(
            !jumps_moved_by_irlume(&before, &after).is_empty(),
            "without the adjustment the jump check refuses the file"
        );
        let adjusted = raise(&before, &after).expect("adjustable");
        let raised = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        assert_eq!(adjusted.changed.len(), 1);
        let changed = &adjusted.changed[0];
        assert_eq!(
            (changed.before.as_str(), changed.after.as_str()),
            (ISSUE_JUMP, raised.as_str())
        );
        // The line is named by its number, never by its text, and so is
        // each line the one action that lands elsewhere lands on.
        assert_eq!(
            changed.describe(),
            format!(
                "line {}: `success=1` becomes `success=2`",
                number_of(&before, ISSUE_JUMP)
            )
        );
        assert_eq!(changed.notes.len(), 1, "{:?}", changed.notes);
        assert_eq!(
            changed.notes[0],
            format!(
                "`success=2` lands on irlume's new pam_permit.so landing rather than irlume's \
                 auth keyring line (line {}); that landing records the verified fingerprint's \
                 success",
                number_of(&before, KEYRING_UNSEAL)
            )
        );
        assert!(adjusted.moved.is_empty());
        assert_eq!(adjusted.text, after.replacen(ISSUE_JUMP, &raised, 1));
        let first = assert_every_path_kept(&before, &adjusted.text, true);
        assert_eq!(
            success_of(&first, &raised).as_deref(),
            Some(PERMIT_LANDING.trim())
        );
        // The keyring and reseal lines follow the landing.
        let lines: Vec<&str> = adjusted.text.lines().collect();
        let at = lines.iter().position(|l| *l == PERMIT_LANDING).unwrap();
        assert_eq!(&lines[at + 1..at + 3], &[KEYRING_UNSEAL, RESEAL_AUTH]);
        assert!(jumps_moved_by_irlume(&before, &adjusted.text)
            .iter()
            .all(|s| s.line == norm(&raised)));
    }

    /// The failure half of the same line: `default=ignore` goes on to the
    /// next line, now irlume's face line, then the password substack, as
    /// without a jump; `default=die` still stops the stack. Either way only
    /// the success value changes.
    #[test]
    fn default_ignore_and_default_die_both_raise_only_the_success_value() {
        for failure in ["ignore", "die"] {
            let jump = format!(
                "auth       [success=1 default={failure}]   pam_fprintd.so max-tries=1 timeout=5"
            );
            let (before, after) = issue_files(&jump);
            let adjusted = raise(&before, &after).expect(failure);
            let raised = jump.replacen("success=1", "success=2", 1);
            assert_eq!(adjusted.changed.len(), 1, "{failure}");
            assert_eq!(adjusted.changed[0].after, raised);
            assert_eq!(adjusted.text, after.replacen(&jump, &raised, 1));
            assert_every_path_kept(&before, &adjusted.text, true);
            let lines = auth_lines(&adjusted.text);
            let fp = lines.iter().position(|l| l.0 == raised).unwrap();
            if failure == "die" {
                assert_eq!(lines[fp].2, Go::Stop);
            } else {
                assert!(lines[fp + 1].0.contains("pam_irlume.so unseal"));
            }
        }
    }

    /// A jump over two lines (a group gate and the password substack) takes
    /// irlume's face line too: `success=3`, landing on the permit line.
    #[test]
    fn a_jump_over_two_lines_is_raised_by_the_one_line_inside_it() {
        let gate = "auth       requisite    pam_succeed_if.so user ingroup fingerprint";
        let jump = "auth       [success=2 default=ignore]   pam_fprintd.so";
        let before = above_substack(&keyring(&vendor()), &format!("{jump}\n{gate}"));
        let after = face(&unwire_lines(&before).0);
        let adjusted = raise(&before, &after).expect("adjustable");
        let raised = jump.replacen("success=2", "success=3", 1);
        assert_eq!(adjusted.changed[0].after, raised);
        let first = assert_every_path_kept(&before, &adjusted.text, true);
        assert_eq!(
            success_of(&first, &raised).as_deref(),
            Some(PERMIT_LANDING.trim())
        );
    }

    /// A jump irlume's lines do not land inside, here one above the SELinux
    /// line, keeps its value and its landing; only the crossing jump changes.
    /// It lands on the line of the fingerprint jump, whose text the raise
    /// and the lower change, and the disable still goes through: each other
    /// jump is compared by the place of the line it lands on, not its text.
    #[test]
    fn a_jump_that_does_not_cross_irlumes_lines_is_left_as_it_is() {
        let top = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup kiosk";
        let (before, _) = issue_files(ISSUE_JUMP);
        let before = format!("{top}\n{before}");
        let after = face(&unwire_lines(&before).0);
        let adjusted = raise(&before, &after).expect("adjustable");
        assert_eq!(adjusted.changed.len(), 1);
        assert_eq!(adjusted.changed[0].before, ISSUE_JUMP);
        assert!(adjusted.text.contains(top));
        let raised = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        let first = assert_every_path_kept(&before, &adjusted.text, true);
        assert_eq!(success_of(&first, top).as_deref(), Some(raised.as_str()));

        let stripped = unwire_lines(&adjusted.text).0;
        let lowered = lower(&adjusted.text, &stripped).expect("lowered");
        assert_eq!(lowered.text, unwire_lines(&before).0);
        assert_eq!(lowered.changed.len(), 1);
        assert_eq!(lowered.changed[0].after, ISSUE_JUMP);
        let first = assert_every_path_kept(&adjusted.text, &lowered.text, false);
        assert_eq!(success_of(&first, top).as_deref(), Some(ISSUE_JUMP));
    }

    /// Nothing in the text a jump lands on is used to find it again: a
    /// gate's success and a gate's failure that land on the fingerprint line
    /// past a line that is not adjusted (`pam_faillock.so preauth`) keep
    /// that landing through a raise and a lower.
    #[test]
    fn a_jump_landing_on_an_adjusted_line_keeps_it_both_ways() {
        let faillock = "auth       required     pam_faillock.so preauth";
        let raised = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        for gate in [
            "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup x",
            "auth       [success=ok default=1]   pam_succeed_if.so user ingroup x",
        ] {
            let (before, after) = issue_files(&format!("{gate}\n{faillock}\n{ISSUE_JUMP}"));
            let adjusted = raise(&before, &after).expect("adjustable");
            let written: Vec<&str> = adjusted.changed.iter().map(|c| c.after.as_str()).collect();
            assert_eq!(written, [raised.as_str()], "{gate}");
            assert_every_path_kept(&before, &adjusted.text, true);
            let stripped = unwire_lines(&adjusted.text).0;
            let lowered = lower(&adjusted.text, &stripped).expect("lowered");
            assert_eq!(lowered.text, unwire_lines(&before).0, "{gate}");
            assert_every_path_kept(&adjusted.text, &lowered.text, false);
        }
    }

    // ---- lines irlume does not read as PAM does ------------------------------------

    /// The issue's files for `jump`, with `lines` right after it: for a line
    /// the recipe does not wire around, since it leaves a file it does not
    /// read as PAM does as it is.
    fn issue_files_with(jump: &str, lines: &str) -> (String, String) {
        let (before, after) = issue_files(jump);
        let put = |t: &str| t.replacen(jump, &format!("{jump}\n{lines}"), 1);
        (put(&before), put(&after))
    }

    /// Lines irlume does not read as PAM does ([`unreadable_line`]): a type
    /// PAM does not know, a typo or a type led by a no-break space, a
    /// vertical tab or a form feed, and a no-break space alone. Every enable
    /// and disable leaves a file with one as it is before it gets here; the
    /// adjustment refuses it too, whether the line sits inside a gate's range
    /// or a failure jump's, both ways, and outside every range as well. The
    /// reason names the line by its number, never by its text.
    #[test]
    fn a_line_irlume_does_not_read_as_pam_does_is_refused() {
        let gate = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup fpusers";
        let fail = "auth       [success=done default=1]   pam_fprintd.so";
        for odd in [
            "auht       optional     pam_foo.so secret=kept",
            "\u{a0}session    optional     pam_foo.so secret=kept",
            "\u{a0}auth       optional     pam_foo.so secret=kept",
            "\u{b}auth       optional     pam_foo.so secret=kept",
            "\u{c}auth       optional     pam_foo.so secret=kept",
            "\u{a0}",
        ] {
            assert!(unreadable_line(odd).is_some(), "{odd:?}");
            for (jump, raised) in [
                (gate, gate.replacen("success=1", "success=3", 1)),
                (fail, fail.replacen("default=1", "default=3", 1)),
            ] {
                let (before, after) = issue_files_with(jump, odd);
                let why = raise(&before, &after).expect_err(odd);
                let named = format!(
                    "irlume does not read line {} as PAM does (",
                    number_of(&before, odd)
                );
                assert!(why.contains(&named), "{odd:?}: {why}");
                assert!(!why.contains("secret=kept"), "{odd:?}: {why}");
                // A disable of the stack a raise would have written.
                let wired = after.replacen(jump, &raised, 1);
                let why = lower(&wired, &unwire_lines(&wired).0).expect_err(odd);
                assert!(why.contains("as PAM does ("), "{odd:?}: {why}");
            }
            // Outside every range: the issue's own jump is refused too.
            let (before, after) = issue_files(ISSUE_JUMP);
            let (before, after) = (format!("{odd}\n{before}"), format!("{odd}\n{after}"));
            let why = raise(&before, &after).expect_err(odd);
            assert!(
                why.contains("irlume does not read line 1 as PAM does ("),
                "{odd:?}: {why}"
            );
        }
    }

    /// Lines PAM installs in the auth chain as modules that always fail: a
    /// type with no control, or with no module. No recipe wires a file with
    /// one (`has_failing_auth_line`), so no enable raises a jump over one.
    /// An administrator can still add one to a file irlume's lines are in,
    /// and a disable then counts it as PAM does: a gate's success and a
    /// failure jump over it and irlume's face line keep landing on the
    /// password substack when lowered, and every line's paths stay as they
    /// were.
    #[test]
    fn a_disable_counts_an_auth_line_that_always_fails_as_pam_does() {
        let gate = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup fpusers";
        let fail = "auth       [success=done default=1]   pam_fprintd.so";
        for odd in [
            "auth",
            "-auth",
            "auth   # a type and no control",
            "auth       optional",
            "auth       [default=ignore]",
            "auth       [] pam_foo.so",
        ] {
            // The recipe wires nothing around it.
            let (keyring_only, _) = issue_files(gate);
            let with_odd = keyring_only.replacen(gate, &format!("{gate}\n{odd}"), 1);
            let (_, wired) = wire_greeter_impl(&unwire_lines(&with_odd).0, true, true, true);
            assert!(!wired, "{odd:?}");
            for (jump, raised) in [
                (gate, gate.replacen("success=1", "success=2", 1)),
                (fail, fail.replacen("default=1", "default=2", 1)),
            ] {
                // irlume's face lines in, and the administrator's jump over
                // the line and the face line onto the password substack.
                let (_, after) = issue_files(jump);
                let wired = after.replacen(jump, &format!("{raised}\n{odd}"), 1);
                let lowered = lower(&wired, &unwire_lines(&wired).0).expect(odd);
                assert_eq!(
                    lowered.text,
                    unwire_lines(&wired).0.replacen(&raised, jump, 1),
                    "{odd:?}"
                );
                assert_eq!(lowered.changed.len(), 1, "{odd:?}");
                assert_every_path_kept(&wired, &lowered.text, false);
            }
        }
    }

    /// A session line with no control is in no auth chain, so a file with
    /// one is wired: a gate's success or a failure jump over the password
    /// substack keeps its landing through a raise and a lower, and every
    /// line's paths stay as they were.
    #[test]
    fn a_session_line_with_no_control_is_counted_in_its_own_chain() {
        let gate = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup fpusers";
        let fail = "auth       [success=done default=1]   pam_fprintd.so";
        for jump in [gate, fail] {
            let (before, after) = issue_files(&format!("{jump}\nsession"));
            let adjusted = raise(&before, &after).expect(jump);
            assert_eq!(adjusted.changed.len(), 1, "{jump}");
            assert_every_path_kept(&before, &adjusted.text, true);
            let lowered = lower(&adjusted.text, &unwire_lines(&adjusted.text).0).expect(jump);
            assert_eq!(lowered.text, unwire_lines(&before).0, "{jump}");
            assert_every_path_kept(&adjusted.text, &lowered.text, false);
        }
    }

    /// A control libpam rejects (a return value it does not know or spells
    /// otherwise, `0`, a sign, `\]`, a bare word) makes every value `bad`: a
    /// line with no jump, which libpam runs as one that always fails. No
    /// recipe wires a file with one (`has_failing_auth_line`), so no enable
    /// raises a jump over one; an administrator can still add one to a file
    /// irlume's lines are in, and a disable then counts it over as any other
    /// line, leaves it as it is and lowers the jump around it.
    #[test]
    fn a_control_pam_rejects_is_a_line_with_no_jump() {
        let raised = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        for odd in [
            "auth [Success=2 default=ignore] pam_succeed_if.so user ingroup x",
            "auth [success=2 foo=bar] pam_succeed_if.so user ingroup x",
            "auth [success=2 default=0] pam_succeed_if.so user ingroup x",
            "auth [success=+2 default=ignore] pam_succeed_if.so user ingroup x",
            "auth [success=2 reset=1] pam_succeed_if.so user ingroup x",
            "auth [success=2 default=ig\\]nore] pam_succeed_if.so user ingroup x",
            "auth bogus pam_succeed_if.so user ingroup x",
        ] {
            assert!(numeric_actions(odd).is_empty(), "{odd}");
            let (before, after) = issue_files(ISSUE_JUMP);
            let with_odd = before.replacen(ISSUE_JUMP, &format!("{ISSUE_JUMP}\n{odd}"), 1);
            let (_, wired) = wire_greeter_impl(&unwire_lines(&with_odd).0, true, true, true);
            assert!(!wired, "{odd}");
            let wired = after.replacen(ISSUE_JUMP, &format!("{raised}\n{odd}"), 1);
            let lowered = lower(&wired, &unwire_lines(&wired).0).expect(odd);
            assert_eq!(
                lowered.text,
                unwire_lines(&wired).0.replacen(&raised, ISSUE_JUMP, 1),
                "{odd}"
            );
            assert!(lowered.text.contains(odd), "{odd}");
        }
    }

    /// A jump libpam reads through blanks around `=` or run into the next
    /// pair is the same jump as the compact spelling: a group check's
    /// `success = 1` over the password substack becomes `success = 3`, its
    /// spelling kept, landing on irlume's keyring line as before, and a
    /// disable gives it back its value.
    #[test]
    fn a_jump_spelled_with_blanks_around_its_equals_sign_is_adjusted_in_its_spelling() {
        for (spelling, raised) in [
            (
                "[success = 1 default=ignore]",
                "[success = 3 default=ignore]",
            ),
            (
                "[success =\t1 default = ignore]",
                "[success =\t3 default = ignore]",
            ),
            (
                "[ success=1 default=ignore ]",
                "[ success=3 default=ignore ]",
            ),
            ("[success=1default=ignore]", "[success=3default=ignore]"),
        ] {
            let gate = format!("auth       {spelling}   pam_succeed_if.so user ingroup fpusers");
            let written = gate.replacen(spelling, raised, 1);
            let (before, after) = issue_files(&gate);
            let adjusted = raise(&before, &after).expect(spelling);
            assert_eq!(adjusted.changed.len(), 1, "{spelling}");
            assert_eq!(adjusted.changed[0].after, written, "{spelling}");
            assert_eq!(
                adjusted.changed[0].describe(),
                format!(
                    "line {}: `success=1` becomes `success=3`",
                    number_of(&before, &gate)
                )
            );
            assert_eq!(
                numeric_actions(&written),
                [("success".to_string(), 3)],
                "{spelling}"
            );
            assert_eq!(adjusted.text, after.replacen(&gate, &written, 1));
            // The independent reading splits the pairs at blanks only.
            if !spelling.contains("1default") {
                let first = assert_every_path_kept(&before, &adjusted.text, true);
                assert_eq!(
                    success_of(&first, &written).as_deref(),
                    Some(KEYRING_UNSEAL.trim())
                );
            }
            let lowered = lower(&adjusted.text, &unwire_lines(&adjusted.text).0).expect(spelling);
            assert_eq!(lowered.text, unwire_lines(&before).0, "{spelling}");
        }
    }

    /// What libpam and irlume read the same way does not stop an adjustment
    /// above the issue's jump: comments and blank lines (a line that is
    /// only spaces and tabs), keywords in any case, a bracketed or `-` type,
    /// controls with every action and a number, leading zeros, and a comment
    /// that holds a control. (An auth line with no control or no module is
    /// one no recipe wires around:
    /// `a_disable_counts_an_auth_line_that_always_fails_as_pam_does`.)
    #[test]
    fn lines_pam_and_irlume_read_alike_do_not_stop_an_adjustment() {
        let raised = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        for line in [
            "",
            " \t ",
            "# a comment",
            "  \t# an indented comment \u{a0}",
            "auth required pam_env.so",
            "-auth optional pam_kwallet5.so",
            "AUTH Sufficient pam_fprintd.so",
            "[auth] [success=1 default=ignore] pam_fprintd.so",
            "[-auth] optional pam_foo.so",
            "auth [success=ok ignore=reset auth_err=1 default=bad] pam_foo.so",
            "auth\t[success=01\tdefault=reset]\tpam_foo.so",
            "auth [success=1 default=ignore] pam_foo.so # [success = 1 note]",
        ] {
            assert!(unreadable_line(line).is_none(), "{line:?}");
            let (before, after) = issue_files(ISSUE_JUMP);
            let (before, after) = (format!("{line}\n{before}"), format!("{line}\n{after}"));
            let adjusted = raise(&before, &after).unwrap_or_else(|e| panic!("{line:?}: {e}"));
            assert!(
                adjusted.changed.iter().any(|c| c.after == raised),
                "{line:?}"
            );
        }
    }

    /// A file with a carriage return PAM reads (outside a comment) is never
    /// adjusted. PAM reads it as part of its line: a line that holds only
    /// one, or blanks and one, is a module that always fails to PAM, and a
    /// jump counts it, while the reading of the file takes it off and irlume
    /// would count a blank line. Refused whether the reading took the
    /// carriage return off (the source says the file had one) or the text
    /// still holds it, inside a gate's range and a failure jump's, both
    /// ways, and at the end of a rule, where PAM reads it as part of the last
    /// argument. No caller gets here with one: every enable and disable
    /// leaves such a file as it is first.
    #[test]
    fn a_file_with_a_carriage_return_is_refused() {
        let gate = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup fpusers";
        let fail = "auth       [success=done default=1]   pam_fprintd.so";
        let had_one = Source {
            carriage_return: true,
            ..READ
        };
        for (jump, raised) in [
            (gate, gate.replacen("success=1", "success=3", 1)),
            (fail, fail.replacen("default=1", "default=3", 1)),
        ] {
            let (before, after) = issue_files(jump);
            let why = super::raise(&before, &after, &had_one).expect_err(jump);
            assert!(why.contains("carriage return"), "{why}");
            let wired = raise(&before, &after).expect(jump).text;
            assert!(wired.contains(&raised), "{wired}");
            let why = super::lower(&wired, &unwire_lines(&wired).0, &had_one).expect_err(jump);
            assert!(why.contains("carriage return"), "{why}");
            for cr in ["\r", "   \r", "\t\r"] {
                let with = |t: &str| t.replacen(jump, &format!("{jump}\n{cr}"), 1);
                let why = raise(&with(&before), &after).expect_err(cr);
                assert!(why.contains("carriage return"), "{cr:?}: {why}");
                let wired = wired.replacen(&raised, &format!("{raised}\n{cr}"), 1);
                let why = lower(&wired, &unwire_lines(&wired).0).expect_err(cr);
                assert!(why.contains("carriage return"), "{cr:?}: {why}");
            }
            let why = raise(&before.replacen(jump, &format!("{jump}\r"), 1), &after)
                .expect_err("at the end of a rule");
            assert!(why.contains("carriage return"), "{why}");
        }
    }

    /// A `substack` whose file PAM cannot load is two modules to PAM, the
    /// substack and one that always fails, and one line to irlume. A raise
    /// over it would land a line further in PAM, on irlume's permit landing
    /// past the password substack. Refused inside a gate's range and a
    /// failure jump's range, both ways, and outside every range too,
    /// whatever its type prefix, brackets or case, with the line named by
    /// its number and not its text. One that names no stack is a line
    /// irlume does not read as PAM does. A substack PAM loads is one module
    /// to both and is adjusted like any other line.
    #[test]
    fn a_substack_pam_cannot_open_is_refused() {
        let gate = "auth       [success=2 default=ignore]   pam_succeed_if.so user ingroup fpusers";
        let fail = "auth       [success=done default=2]   pam_fprintd.so";
        for odd in [
            "auth        substack      fingerprint-missing",
            "auth        substack",
            "auth        substack      # a comment and no file",
            "-auth       substack      fingerprint-missing",
            "auth        [substack]    fingerprint-missing",
            "auth        SUBSTACK      fingerprint-missing",
            "auth        substack      /etc/pam.d/password-auth",
            "auth        substack      [password\\]auth]",
        ] {
            let why_of = |why: &str| {
                if unreadable_line(odd).is_some() {
                    why.contains("without a stack")
                } else {
                    why.contains("two modules") && !why.contains("fingerprint-missing")
                }
            };
            for (jump, raised) in [
                (gate, gate.replacen("success=2", "success=4", 1)),
                (fail, fail.replacen("default=2", "default=4", 1)),
            ] {
                let (before, after) = issue_files_with(jump, odd);
                let why = raise(&before, &after).expect_err(odd);
                assert!(why_of(&why), "{odd}: {why}");
                assert!(
                    why.contains(&format!("line {}", number_of(&before, odd))),
                    "{odd}: {why}"
                );
                let wired = after.replacen(jump, &raised, 1);
                assert!(wired.contains(&raised), "{wired}");
                let why = lower(&wired, &unwire_lines(&wired).0).expect_err(odd);
                assert!(why_of(&why), "{odd}: {why}");
            }
            let (before, after) = issue_files(ISSUE_JUMP);
            let (before, after) = (format!("{odd}\n{before}"), format!("{odd}\n{after}"));
            let why = raise(&before, &after).expect_err(odd);
            assert!(why_of(&why), "{odd}: {why}");
        }
        for (jump, raised) in [
            (gate, gate.replacen("success=2", "success=4", 1)),
            (fail, fail.replacen("default=2", "default=4", 1)),
        ] {
            let known = "auth        substack      fingerprint-auth";
            let (before, after) = issue_files(&format!("{jump}\n{known}"));
            let adjusted = raise(&before, &after).expect(jump);
            assert_eq!(adjusted.changed[0].after, raised);
            assert_every_path_kept(&before, &adjusted.text, true);
            let lowered = lower(&adjusted.text, &unwire_lines(&adjusted.text).0).expect(jump);
            assert_eq!(lowered.text, unwire_lines(&before).0);
        }
    }

    /// A numeric jump in a stack an include puts in its place that lands
    /// past the included lines counts the lines after the include, and no
    /// value in the file changes it: with such an include above lines of
    /// irlume's that an enable adds or a disable takes out, the adjustment
    /// is refused, as it is for an include of a stack irlume cannot read.
    /// An included stack whose jumps land inside it is no obstacle, and
    /// neither is Fedora's `password-auth` above irlume's session line: its
    /// `crond` jump lands right after its last line.
    #[test]
    fn a_jump_an_include_puts_above_irlumes_lines_is_refused() {
        let include = "auth        include       extra";
        let inside = "auth [success=1 default=ignore] pam_x.so\nauth required pam_y.so\n\
                      auth required pam_z.so\n";
        let past = "auth [success=2 default=ignore] pam_x.so\nauth required pam_y.so\n";
        let (before, after) = issue_files(ISSUE_JUMP);
        let top = |t: &str| format!("{include}\n{t}");
        let raise_with = |extra: Option<&'static str>, b: &str, a: &str| {
            with_stack_reader(stacks(extra), || super::raise(b, a, &READ))
        };
        let lower_with = |extra: Option<&'static str>, b: &str, a: &str| {
            with_stack_reader(stacks(extra), || super::lower(b, a, &READ))
        };
        let adjusted = raise_with(Some(inside), &top(&before), &top(&after)).expect("inside");
        let stripped = unwire_lines(&adjusted.text).0;
        lower_with(Some(inside), &adjusted.text, &stripped).expect("inside");
        // A stack whose jump could land past its end, and one irlume cannot
        // read, each named for what it is.
        for (extra, named) in [
            (
                Some(past),
                "a numeric jump in the stack the include on line 1 puts in its place could \
                 land past that stack's end",
            ),
            (
                None,
                "irlume cannot read the stack the include on line 1 names",
            ),
        ] {
            let raised = raise_with(extra, &top(&before), &top(&after)).expect_err("past");
            let lowered = lower_with(extra, &adjusted.text, &stripped).expect_err("past");
            for why in [raised, lowered] {
                assert!(why.starts_with(named), "{why}");
            }
        }
        // Above irlume's session line only, which a disable takes out: a
        // `password-auth` whose session jump could land past its end.
        let session_past = "session [success=1 default=ignore] pam_x.so\n";
        let wired = raise(&before, &after).expect("adjustable").text;
        let stripped = unwire_lines(&wired).0;
        assert!(wired.contains(RESEAL_SESSION), "{wired}");
        lower(&wired, &stripped).expect("Fedora's password-auth");
        let why = with_stack_reader(
            std::rc::Rc::new(move |name: &str| {
                (name == "password-auth").then(|| session_past.to_string())
            }),
            || super::lower(&wired, &stripped, &READ),
        )
        .expect_err("past");
        let include_at = number_of(&wired, "session     include       password-auth");
        assert!(
            why.contains(&format!("the include on line {include_at}")),
            "{why}"
        );
    }

    /// An enable over a file whose lines of irlume's do not all stay, here
    /// the inactive lines a disable without the flag leaves, is refused with
    /// [`OWN_LINES`], which the caller follows with the two commands that get
    /// there: a lower takes irlume's lines out, and a raise from that file
    /// only adds them, `success=1` becoming `success=2` onto the permit
    /// landing as from the issue's file. A change to another line is still
    /// named as one.
    #[test]
    fn irlumes_own_lines_that_would_change_are_named() {
        let (keyring_only, _) = issue_files(ISSUE_JUMP);
        let inert = super::super::neutralize(&keyring_only);
        assert!(inert.contains(super::super::INERT_TAG), "{inert}");
        let after = face(&unwire_lines(&inert).0);
        assert_eq!(raise(&inert, &after).expect_err("own lines"), OWN_LINES);
        let other = after.replacen("pam_nologin.so", "pam_nologin.so debug", 1);
        let why = raise(&inert, &other).expect_err("another line");
        assert!(why.contains("other than irlume's"), "{why}");

        let lowered = lower(&inert, &unwire_lines(&inert).0).expect("lowered");
        assert_eq!(lowered.text, unwire_lines(&keyring_only).0);
        let raised = raise(&lowered.text, &face(&lowered.text)).expect("raised");
        let written = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        assert_eq!(raised.changed[0].after, written);
        let first = assert_every_path_kept(&lowered.text, &raised.text, true);
        assert_eq!(
            success_of(&first, &written).as_deref(),
            Some(PERMIT_LANDING.trim())
        );
    }

    // ---- other modules: the same landing line ---------------------------------------

    /// A jump that is not a fingerprint's success never takes the permit
    /// landing, which would record a success its module did not earn: a
    /// group check over the password substack skips irlume's face line, the
    /// substack and the permit landing, and lands on the line it landed on
    /// before. Once in the issue's keyring-only file (`success=3`, onto
    /// irlume's keyring line), and once in a file with none of irlume's
    /// lines and a fingerprint line of its own after the substack, which the
    /// check still lands on, past every line irlume adds.
    #[test]
    fn a_success_jump_of_another_module_keeps_its_landing_line() {
        let gate = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup fpusers";
        let (before, after) = issue_files(gate);
        let adjusted = raise(&before, &after).expect("adjustable");
        let raised = gate.replacen("success=1", "success=3", 1);
        assert_eq!(adjusted.changed[0].after, raised);
        assert!(
            adjusted.changed[0].notes.is_empty(),
            "{:?}",
            adjusted.changed
        );
        let first = assert_every_path_kept(&before, &adjusted.text, true);
        assert_eq!(
            success_of(&first, &raised).as_deref(),
            Some(KEYRING_UNSEAL.trim())
        );

        let local = "auth       sufficient   pam_fprintd.so   # local";
        let before = vendor().replacen(
            "auth        substack      password-auth\n",
            &format!("{gate}\nauth        substack      password-auth\n{local}\n"),
            1,
        );
        assert!(!before.lines().any(is_irlume_line), "{before}");
        let after = face(&before);
        let adjusted = raise(&before, &after).expect("adjustable");
        let first = assert_every_path_kept(&before, &adjusted.text, true);
        let written = &adjusted.changed[0].after;
        assert_ne!(written, &gate.replacen("success=1", "success=2", 1));
        assert_eq!(success_of(&first, written).as_deref(), Some(local));
    }

    /// A jump that ends right where irlume's face line goes skips the face
    /// line too and lands on the password substack, as it did; the
    /// fingerprint line it skips is raised onto the permit landing.
    #[test]
    fn a_jump_landing_where_irlume_adds_its_face_line_keeps_its_landing_line() {
        let gate = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup nofp";
        let (before, _) = issue_files(ISSUE_JUMP);
        let before = before.replacen(ISSUE_JUMP, &format!("{gate}\n{ISSUE_JUMP}"), 1);
        let after = face(&unwire_lines(&before).0);
        let adjusted = raise(&before, &after).expect("adjustable");
        let gate_raised = gate.replacen("success=1", "success=2", 1);
        let fp_raised = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        let written: Vec<&str> = adjusted.changed.iter().map(|c| c.after.as_str()).collect();
        assert_eq!(written, [gate_raised.as_str(), fp_raised.as_str()]);
        let first = assert_every_path_kept(&before, &adjusted.text, true);
        assert_eq!(
            success_of(&first, &gate_raised).as_deref(),
            Some("auth        substack      password-auth")
        );
        assert_eq!(
            success_of(&first, &fp_raised).as_deref(),
            Some(PERMIT_LANDING.trim())
        );
    }

    /// A failure jump over the password substack lands on the line it landed
    /// on before, irlume's keyring line, never on the permit landing between,
    /// which would turn a failure into a success: `default=1` becomes
    /// `default=3`. A fingerprint's success in the same control still takes
    /// the landing.
    #[test]
    fn a_failure_jump_keeps_its_landing_line_and_never_takes_the_permit_line() {
        for (jump, raised) in [
            (
                "auth       [success=done default=1]   pam_fprintd.so",
                "auth       [success=done default=3]   pam_fprintd.so",
            ),
            (
                "auth       [default=1]   pam_fprintd.so",
                "auth       [default=3]   pam_fprintd.so",
            ),
            (
                "auth       [success=1 default=1]   pam_fprintd.so",
                "auth       [success=2 default=3]   pam_fprintd.so",
            ),
        ] {
            let (before, after) = issue_files(jump);
            let adjusted = raise(&before, &after).expect(jump);
            assert_eq!(adjusted.changed[0].after, raised);
            assert_every_path_kept(&before, &adjusted.text, true);
            let lines = auth_lines(&adjusted.text);
            let at = lines.iter().position(|l| l.0 == raised).unwrap();
            let fails_to = lands(at, lines[at].2).and_then(|k| lines.get(k));
            assert_eq!(
                fails_to.map(|l| l.0.as_str()),
                Some(KEYRING_UNSEAL.trim()),
                "{jump}"
            );
            // And back again.
            let stripped = unwire_lines(&adjusted.text).0;
            let lowered = lower(&adjusted.text, &stripped).expect(jump);
            assert_eq!(lowered.text, unwire_lines(&before).0, "{jump}");
        }
    }

    /// A jump that skips another adjusted jump: each is raised, the skipped
    /// line is still counted as itself although its value changed, and
    /// lowering gives both their values back.
    #[test]
    fn nested_adjusted_jumps_are_raised_and_lowered_together() {
        let outer = "auth       [success=2 default=ignore]   pam_fprintd.so";
        let inner = "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup wheel";
        let (before, after) = issue_files(&format!("{outer}\n{inner}"));
        let adjusted = raise(&before, &after).expect("adjustable");
        let (outer_raised, inner_raised) = (
            outer.replacen("success=2", "success=3", 1),
            inner.replacen("success=1", "success=3", 1),
        );
        let written: Vec<&str> = adjusted.changed.iter().map(|c| c.after.as_str()).collect();
        assert_eq!(written, [outer_raised.as_str(), inner_raised.as_str()]);
        let first = assert_every_path_kept(&before, &adjusted.text, true);
        assert_eq!(
            success_of(&first, &outer_raised).as_deref(),
            Some(PERMIT_LANDING.trim())
        );
        assert_eq!(
            success_of(&first, &inner_raised).as_deref(),
            Some(KEYRING_UNSEAL.trim())
        );
        let stripped = unwire_lines(&adjusted.text).0;
        let lowered = lower(&adjusted.text, &stripped).expect("lowered");
        assert_eq!(lowered.text, unwire_lines(&before).0);
        assert_every_path_kept(&adjusted.text, &lowered.text, false);
    }

    /// A raised line that would read like another line of the file is
    /// refused: the jump check names a line by its text, and could no longer
    /// tell the two apart.
    #[test]
    fn a_raised_line_that_would_repeat_another_is_refused() {
        let jump = "auth       [success=1 default=ignore]   pam_fprintd.so";
        let twin = "auth       [success=2 default=ignore]   pam_fprintd.so";
        let (before, _) = issue_files(jump);
        let anchor = "-auth        optional      pam_kwallet5.so\n";
        assert!(before.contains(anchor), "{before}");
        let before = before.replacen(anchor, &format!("{twin}\n{anchor}"), 1);
        let after = face(&unwire_lines(&before).0);
        let why = raise(&before, &after).expect_err("refused");
        assert_eq!(
            why,
            format!(
                "line {} would then read the same as another line of the file",
                number_of(&before, jump)
            )
        );
    }

    // ---- refusals -------------------------------------------------------------------

    /// A line continued with `\` is never adjusted: PAM reads it and the next
    /// line as one rule.
    #[test]
    fn a_continued_line_is_refused() {
        let (before, after) = issue_files(ISSUE_JUMP);
        let continued = |t: &str| {
            t.replacen(
                "-auth        optional      pam_kwallet.so",
                "-auth        optional      pam_kwallet.so \\",
                1,
            )
        };
        assert!(raise(&continued(&before), &continued(&after))
            .expect_err("continued")
            .contains('\\'));
    }

    /// A jump that lands past the end of the stack, which libpam fails on,
    /// is not made to land somewhere by irlume's lines.
    #[test]
    fn a_jump_past_the_end_of_the_stack_is_refused() {
        let jump = "auth       [success=12 default=ignore]   pam_fprintd.so";
        let (before, after) = issue_files(jump);
        let why = raise(&before, &after).expect_err("past the end");
        assert!(why.contains("past the end"), "{why}");
    }

    /// A jump across an `include` is refused: the include counts as every
    /// line of its phase in the file it names, which irlume does not read.
    #[test]
    fn a_jump_across_an_include_is_refused() {
        let jump = "auth       [success=2 default=ignore]   pam_fprintd.so";
        let (before, after) = issue_files(&format!(
            "{jump}\nauth       include      fingerprint-extra"
        ));
        assert!(after.contains("pam_irlume.so unseal"), "{after}");
        let why = raise(&before, &after).expect_err("across an include");
        assert!(why.contains("include"), "{why}");
    }

    /// A control that is not in brackets is read by libpam as the same
    /// jump, but irlume changes only a bracketed one.
    #[test]
    fn a_control_not_in_brackets_is_refused() {
        let jump = "auth       success=1   pam_fprintd.so";
        let (before, after) = issue_files(jump);
        let why = raise(&before, &after).expect_err("not in brackets");
        assert!(why.contains("in brackets"), "{why}");
    }

    /// Only a control in brackets is changed, and only the digits libpam
    /// reads for the jump: the pairs keep their spelling (blanks around `=`,
    /// a pair run into the next, leading zeros, tabs), and an argument such
    /// as `max-tries=1` and the comment stay as written. libpam reads the
    /// new line with the new value, as the rest of the wiring does.
    #[test]
    fn only_the_value_in_a_bracketed_control_is_rewritten() {
        let raised = ISSUE_JUMP.replacen("success=1", "success=2", 1);
        for (line, edits, expected) in [
            (ISSUE_JUMP, vec![("success", 1, 2)], raised.as_str()),
            (
                "[auth]\t[success=1\tdefault=ignore] pam_fprintd.so max-tries=1",
                vec![("success", 1, 3)],
                "[auth]\t[success=3\tdefault=ignore] pam_fprintd.so max-tries=1",
            ),
            (
                "auth [success = 1 default=ignore] pam_fprintd.so success=1",
                vec![("success", 1, 2)],
                "auth [success = 2 default=ignore] pam_fprintd.so success=1",
            ),
            (
                "auth [ success =\t9 default= 1 ] pam_fprintd.so",
                vec![("default", 1, 3), ("success", 9, 10)],
                "auth [ success =\t10 default= 3 ] pam_fprintd.so",
            ),
            (
                "auth [success=1default=ignore] pam_fprintd.so",
                vec![("success", 1, 2)],
                "auth [success=2default=ignore] pam_fprintd.so",
            ),
            (
                "auth [success=01 default=ignore] pam_fprintd.so",
                vec![("success", 1, 2)],
                "auth [success=2 default=ignore] pam_fprintd.so",
            ),
        ] {
            let written = with_jump_values(line, &edits).unwrap_or_else(|| panic!("{line}"));
            assert_eq!(written, expected, "{line}");
            let mut read = numeric_actions(&written);
            read.sort();
            let mut wanted: Vec<(String, usize)> = edits
                .iter()
                .map(|(value, _, to)| ((*value).to_string(), *to))
                .collect();
            wanted.sort();
            assert_eq!(read, wanted, "{written}");
        }
        for refused in [
            "auth success=1 pam_fprintd.so",
            "auth [success=1 success=1] pam_fprintd.so",
            "auth [default=ignore] pam_fprintd.so success=1",
            "auth [success=1 # default=ignore] pam_fprintd.so",
            "auth [success=ok success=1] pam_fprintd.so",
            "auth [success=2 default=ignore] pam_fprintd.so",
            "auth [Success=1 default=ignore] pam_fprintd.so",
            "auth [] pam_fprintd.so",
            "auth",
        ] {
            assert_eq!(
                with_jump_values(refused, &[("success", 1, 2)]),
                None,
                "{refused}"
            );
        }
        // A value changed twice, and a jump libpam does not read.
        let line = "auth [success=1 default=ignore] pam_fprintd.so";
        assert_eq!(
            with_jump_values(line, &[("success", 1, 2), ("success", 1, 3)]),
            None
        );
        assert_eq!(with_jump_values(line, &[("success", 1, 0)]), None);
        assert_eq!(with_jump_values(line, &[("success", 1, 1 << 31)]), None);
    }

    // ---- disable --------------------------------------------------------------------

    /// Disable lowers the raised jump back, and the file without irlume's
    /// lines is the administrator's file without irlume's lines, byte for
    /// byte, with `success=1` again.
    #[test]
    fn lowering_undoes_raising() {
        let (before, after) = issue_files(ISSUE_JUMP);
        let raised = raise(&before, &after).expect("adjustable");
        let stripped = unwire_lines(&raised.text).0;
        let lowered = lower(&raised.text, &stripped).expect("lowered");
        assert_eq!(lowered.text, unwire_lines(&before).0);
        assert_eq!(lowered.changed.len(), 1);
        let changed = &lowered.changed[0];
        assert_eq!(
            (changed.before.clone(), changed.after.clone()),
            (
                ISSUE_JUMP.replacen("success=1", "success=2", 1),
                ISSUE_JUMP.to_string()
            )
        );
        // It landed on the permit landing, which is taken out; both lines
        // are named by their numbers in the file as it is.
        let fingerprint = number_of(
            &raised.text,
            &ISSUE_JUMP.replacen("success=1", "success=2", 1),
        );
        assert_eq!(
            changed.describe(),
            format!("line {fingerprint}: `success=2` becomes `success=1`")
        );
        assert_eq!(changed.notes.len(), 1, "{:?}", changed.notes);
        assert_eq!(
            changed.notes[0],
            format!(
                "`success=1` lands on line {} rather than on irlume's pam_permit.so landing \
                 (line {}), which is taken out",
                number_of(
                    &raised.text,
                    "-auth        optional      pam_gnome_keyring.so"
                ),
                number_of(&raised.text, PERMIT_LANDING)
            )
        );
        assert_every_path_kept(&raised.text, &lowered.text, false);
        // The keyring-only file itself: its jump lands on irlume's keyring
        // line, and without irlume's lines on the line after them, with no
        // value changed.
        let lowered = lower(&before, &unwire_lines(&before).0).expect("landing only");
        assert!(lowered.changed.is_empty());
        assert_eq!(lowered.moved.len(), 1, "{:?}", lowered.moved);
        assert!(
            lowered.moved[0].starts_with(&format!(
                "`success=1` on line {} lands on line ",
                number_of(&before, ISSUE_JUMP)
            )),
            "{}",
            lowered.moved[0]
        );
        assert_eq!(lowered.text, unwire_lines(&before).0);
    }

    /// A vendor jump that irlume's face line moved when the override was
    /// made (with a warning) lands where the vendor file has it again once a
    /// disable takes irlume's lines out, as a disable without the flag
    /// reads it (`strip_shifts`): the lowering leaves it as the vendor wrote
    /// it and changes only the jump the administrator added, here a #875
    /// fingerprint line over it, the face line and the substack onto irlume's
    /// permit landing. Without the vendor copy the lowering keeps that jump
    /// on the substack instead.
    #[test]
    fn a_vendor_jump_irlumes_lines_had_moved_is_left_as_the_vendor_wrote_it() {
        let vendor_jump = "auth [success=2 default=ignore] pam_x.so";
        let vendor = format!(
            "{vendor_jump}\nauth required pam_a.so\nauth substack password-auth\n\
             auth optional pam_b.so\n"
        );
        let fingerprint = "auth [success=4 default=ignore] pam_fprintd.so";
        let before = format!("{fingerprint}\n{}", face(&vendor));
        let stripped = unwire_lines(&before).0;
        // Where the success of `line` lands in `text`, read independently.
        let lands_on = |line: &str, text: &str| {
            let lines = auth_lines(text);
            let at = lines.iter().position(|l| l.0 == line).unwrap();
            lines
                .get(lands(at, lines[at].1).unwrap())
                .map(|l| l.0.clone())
        };
        assert_eq!(
            lands_on(vendor_jump, &before).as_deref(),
            Some("auth substack password-auth"),
            "{before}"
        );
        let with_vendor = Source {
            vendor: Some(&vendor),
            ..READ
        };
        let lowered = with_stack_reader(stacks(None), || {
            super::lower(&before, &stripped, &with_vendor)
        })
        .expect("lowered");
        let lowered_fingerprint = fingerprint.replacen("success=4", "success=3", 1);
        assert_eq!(
            lowered.text,
            stripped.replacen(fingerprint, &lowered_fingerprint, 1)
        );
        let written: Vec<&str> = lowered.changed.iter().map(|c| c.after.as_str()).collect();
        assert_eq!(written, [lowered_fingerprint.as_str()]);
        assert_eq!(
            lands_on(vendor_jump, &lowered.text).as_deref(),
            lands_on(vendor_jump, &vendor).as_deref()
        );
        // Its landing changes, and the note says so, by line number.
        assert_eq!(
            lowered.moved,
            [format!(
                "`success=2` on line {} lands on line {} rather than line {}, as the vendor \
                 copy has it",
                number_of(&before, vendor_jump),
                number_of(&before, "auth optional pam_b.so"),
                number_of(&before, "auth substack password-auth")
            )]
        );
        // Without the vendor copy it keeps its landing on the substack.
        let lowered = lower(&before, &stripped).expect("lowered");
        let kept = vendor_jump.replacen("success=2", "success=1", 1);
        assert!(lowered.text.contains(&kept), "{}", lowered.text);
    }

    /// Two vendor jumps irlume's face line moved when the override was
    /// made, and a line an administrator then added right after the
    /// password substack. The first lands where the vendor file has it once
    /// irlume's lines are out, and is left as the vendor wrote it although
    /// the second, whose landing the added line changed, is lowered from 2
    /// to 1: the first skips the second by its place, not its text. The note
    /// says where the first lands now.
    #[test]
    fn a_vendor_jump_is_left_as_written_while_the_jump_it_skips_is_lowered() {
        let v = "auth [success=1 default=ignore] pam_v.so";
        let w = "auth [success=2 default=ignore] pam_w.so";
        let substack = "auth substack password-auth";
        let vendor =
            format!("{v}\n{w}\n{substack}\nauth required pam_b.so\nauth required pam_c.so\n");
        let added = "auth optional pam_z.so";
        let before = face(&vendor).replacen(
            &format!("{substack}\n"),
            &format!("{substack}\n{added}\n"),
            1,
        );
        let stripped = unwire_lines(&before).0;
        let with_vendor = Source {
            vendor: Some(&vendor),
            ..READ
        };
        let lowered = with_stack_reader(stacks(None), || {
            super::lower(&before, &stripped, &with_vendor)
        })
        .expect("lowered");
        let lowered_w = w.replacen("success=2", "success=1", 1);
        assert_eq!(lowered.text, stripped.replacen(w, &lowered_w, 1));
        let written: Vec<&str> = lowered.changed.iter().map(|c| c.after.as_str()).collect();
        assert_eq!(written, [lowered_w.as_str()]);
        assert_eq!(
            lowered.moved,
            [format!(
                "`success=1` on line {} lands on line {} rather than irlume's auth unseal \
                 line (line {}), as the vendor copy has it",
                number_of(&before, v),
                number_of(&before, substack),
                number_of(&before, GREETER_UNSEAL_COSMIC_JUMP)
            )]
        );
    }

    /// A vendor jump left as the vendor wrote it may land on a line the
    /// same disable lowers: the vendor's first jump lands on its second
    /// once irlume's keyring line is out, and the second, whose landing an
    /// administrator's line changed, is lowered. The first is compared by
    /// the place it lands on, not that line's new text.
    #[test]
    fn a_vendor_jump_may_land_on_a_lowered_line() {
        let v = "auth [success=1 default=ignore] pam_v.so";
        let w = "auth [success=2 default=ignore] pam_w.so";
        let vendor = format!(
            "{v}\nauth required pam_x.so\n{w}\nauth required pam_b.so\n\
             auth required pam_d.so\nauth required pam_c.so\n"
        );
        let before = format!(
            "{v}\n{KEYRING_UNSEAL}\nauth required pam_x.so\n{w}\n{RESEAL_AUTH}\n\
             auth required pam_b.so\nauth optional pam_z.so\nauth required pam_d.so\n\
             auth required pam_c.so\n"
        );
        let stripped = unwire_lines(&before).0;
        let with_vendor = Source {
            vendor: Some(&vendor),
            ..READ
        };
        let lowered = super::lower(&before, &stripped, &with_vendor).expect("lowered");
        let lowered_w = w.replacen("success=2", "success=1", 1);
        assert_eq!(lowered.text, stripped.replacen(w, &lowered_w, 1));
        assert_eq!(
            lowered.moved,
            [format!(
                "`success=1` on line 1 lands on line {} rather than line {}, as the vendor \
                 copy has it",
                number_of(&before, w),
                number_of(&before, "auth required pam_x.so")
            )]
        );
        let lines = auth_lines(&lowered.text);
        let at = lines.iter().position(|l| l.0 == v).unwrap();
        assert_eq!(lines[lands(at, lines[at].1).unwrap()].0, lowered_w);
    }

    /// A disable that would land a jump on the end of the stack is refused:
    /// the jump landed on a line of irlume's with no auth line after it, and
    /// without irlume's lines it would end the stack there. The reason names
    /// the lines by their numbers.
    #[test]
    fn a_disable_that_would_land_a_jump_on_the_end_of_the_stack_is_refused() {
        let vendor = "auth required pam_env.so\nauth substack password-auth\n";
        let wired = face(vendor);
        let lines: Vec<&str> = wired.lines().collect();
        assert_eq!(
            lines.iter().rev().find(|l| l.starts_with("auth")),
            Some(&RESEAL_AUTH),
            "{wired}"
        );
        // Over the substack, the permit landing and the keyring line onto
        // irlume's reseal line, the last auth line.
        let gate = "auth [success=3 default=ignore] pam_succeed_if.so user ingroup x";
        let substack = "auth substack password-auth";
        let before = wired.replacen(substack, &format!("{gate}\n{substack}"), 1);
        let why = lower(&before, &unwire_lines(&before).0).expect_err("the end of the stack");
        assert_eq!(
            why,
            format!(
                "`success=3` on line {} would land on the end of the auth stack rather than \
                 irlume's auth reseal line (line {})",
                number_of(&before, gate),
                number_of(&before, RESEAL_AUTH)
            )
        );
    }

    /// An include's stack counts only for the types of the lines of irlume's
    /// the adjustment adds or takes out after it, and a Debian `@include`
    /// for every type. An enable adds auth lines only here, so an `account`
    /// or `session` include whose stack jumps past its end, or an `@include`
    /// whose file does so in its session lines only, is no obstacle; an
    /// `@include` whose file does so in its auth lines is refused, and so is
    /// one irlume cannot read. A disable takes irlume's session line out as
    /// well, so there the `session` include and the `@include` are refused.
    #[test]
    fn an_include_counts_only_for_the_types_of_irlumes_lines_after_it() {
        let leaves = |kind: &str| -> &'static str {
            match kind {
                "auth" => "auth [success=2 default=ignore] pam_x.so\nauth required pam_y.so\n",
                "account" => {
                    "account [success=2 default=ignore] pam_x.so\naccount required pam_y.so\n"
                }
                _ => "session [success=2 default=ignore] pam_x.so\nsession required pam_y.so\n",
            }
        };
        let (before, after) = issue_files(ISSUE_JUMP);
        let wired = raise(&before, &after).expect("adjustable").text;
        let stripped = unwire_lines(&wired).0;
        let top = |line: &str, t: &str| format!("{line}\n{t}");
        for (line, stack, on, off) in [
            (
                "account     include       extra",
                leaves("account"),
                true,
                true,
            ),
            (
                "session     include       extra",
                leaves("session"),
                true,
                false,
            ),
            (
                "auth        include       extra",
                leaves("auth"),
                false,
                false,
            ),
            ("@include extra", leaves("session"), true, false),
            ("@include extra", leaves("auth"), false, false),
        ] {
            let with = |t: &str| top(line, t);
            let raised = with_stack_reader(stacks(Some(stack)), || {
                super::raise(&with(&before), &with(&after), &READ)
            });
            assert_eq!(raised.is_ok(), on, "{line} / {stack:?}: {raised:?}");
            let lowered = with_stack_reader(stacks(Some(stack)), || {
                super::lower(&with(&wired), &with(&stripped), &READ)
            });
            assert_eq!(lowered.is_ok(), off, "{line} / {stack:?}: {lowered:?}");
            for why in [raised.err(), lowered.err()].into_iter().flatten() {
                assert!(why.contains("the include on line 1"), "{why}");
            }
        }
        // An `@include` irlume cannot read counts for every type, and the
        // reason says it was not read; one it read says where its jump
        // could land.
        let with = |t: &str| top("@include extra", t);
        let why = with_stack_reader(stacks(None), || {
            super::raise(&with(&before), &with(&after), &READ)
        })
        .expect_err("unread");
        assert!(
            why.starts_with("irlume cannot read the stack the include on line 1 names"),
            "{why}"
        );
        assert!(!why.contains("could land past"), "{why}");
        let why = with_stack_reader(stacks(Some(leaves("auth"))), || {
            super::raise(&with(&before), &with(&after), &READ)
        })
        .expect_err("read");
        assert!(why.contains("could land past that stack's end"), "{why}");
        assert!(!why.contains("cannot read"), "{why}");
    }

    /// A disable cannot lower a failure jump over irlume's face line alone:
    /// it would become a jump of 0.
    #[test]
    fn a_jump_over_only_irlumes_lines_is_not_lowered() {
        let jump = "auth       [success=done default=1]   pam_fprintd.so";
        let current = face(&vendor()).replacen(
            GREETER_UNSEAL_COSMIC_JUMP,
            &format!("{jump}\n{GREETER_UNSEAL_COSMIC_JUMP}"),
            1,
        );
        assert!(current.contains(jump), "{current}");
        let why = lower(&current, &unwire_lines(&current).0).expect_err("jump of 0");
        assert!(why.contains("jump of 0"), "{why}");
    }
}
