// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Reading PAM stack lines: which line is an auth directive, which one is the
//! shared password stack, where the face block should anchor.
//!
//! Pure predicates over a single line (or a slice of them). No I/O and no
//! rewriting, so every distro layout irlume supports can be pinned by a unit
//! test without touching a filesystem. The one stack read beyond the lines
//! given, the one a first auth `include` names, goes through the reader the
//! caller sets ([`with_stack_reader`]).
//!
//! Lines are read the way libpam reads them (linux-pam `libpam/pam_handlers.c`
//! `_pam_parse_conf_file`, `libpam/pam_misc.c` `_pam_tokenize` and
//! `_pam_parse_control`, `libpam_internal/pam_line.c` `_pam_str_trim`), with
//! Debian's `@include` (its patch `031_pam_include`). What irlume cannot read
//! that way, [`unreadable_line`] names, and no write is made to such a file.

use super::stanzas::{KEYRING_CONSUMERS, MODULE};
use std::ops::Range;

/// Whether any line of `c` is a rule that loads pam_irlume.so (see
/// [`irlume_rule`]).
pub(super) fn content_has_module(c: &str) -> bool {
    c.lines().any(|l| irlume_rule(l).is_some())
}

/// A PAM rule line split into its fields the way libpam splits it:
/// `[-]type control module-path module-arguments`, per pam.conf(5).
pub(crate) struct Rule<'a> {
    /// The type, read case-insensitively as libpam reads it and without its
    /// leading `-`: `auth`, `account`, `password` or `session`.
    pub(crate) phase: &'static str,
    /// One word, or the inside of a bracketed group: `success=1
    /// default=ignore` for `[success=1 default=ignore]`.
    pub(crate) control: &'a str,
    /// The module path as written: a bare name or a path.
    pub(crate) module: &'a str,
    pub(crate) args: Vec<&'a str>,
}

/// The four types libpam knows, which it compares case-insensitively.
const TYPES: [&str; 4] = ["auth", "account", "password", "session"];

/// What separates the fields of a PAM line: libpam's `_pam_tokenize` splits
/// on these three and nothing else.
const FIELD_DELIMITERS: [char; 3] = [' ', '\t', '\n'];

/// The next field of a directive, advancing `rest` past it, as libpam's
/// `_pam_tokenize` reads it. A field that opens with `[` runs to the first
/// `]` not written `\]`, spaces included, and comes back without its
/// brackets, as libpam hands it on; the next field starts right after that
/// `]`. One never closed runs to the end of the line. Any field can be
/// bracketed this way, the type and the module path included.
///
/// libpam also turns each `\]` inside the brackets into `]`. The field is
/// returned as written instead, which answers every question asked of it
/// here the same way: a field holding `]` equals no type, control keyword,
/// module file name or argument irlume looks for, and a control holding a
/// `\` or a `]` is one `_pam_parse_control` rejects either way.
fn next_field<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let s = rest.trim_start_matches(FIELD_DELIMITERS);
    if s.is_empty() {
        *rest = s;
        return None;
    }
    if let Some(inner) = s.strip_prefix('[') {
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i < bytes.len() && bytes[i] != b']' {
            if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b']') {
                i += 1;
            }
            i += 1;
        }
        let i = i.min(inner.len());
        *rest = inner.get(i + 1..).unwrap_or("");
        return Some(&inner[..i]);
    }
    let end = s.find(FIELD_DELIMITERS).unwrap_or(s.len());
    let (field, tail) = s.split_at(end);
    *rest = tail;
    Some(field)
}

/// The type field of a directive without the one leading `-` libpam takes
/// off it (after taking off any brackets, so `[-auth]` loses it and `-[auth]`
/// keeps its brackets).
fn type_field<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let kind = next_field(rest)?;
    Some(kind.strip_prefix('-').unwrap_or(kind))
}

/// The type and control of any line libpam reads as part of a stack, an
/// `include` or `substack` line among them: what numeric jumps and the chain
/// of a phase are counted from.
pub(crate) struct Head<'a> {
    /// As in [`Rule::phase`]. A line whose type libpam does not know is in
    /// the auth chain: libpam reads a service file for every type at once and
    /// puts such a line in the auth chain, as one that always fails unless
    /// its control is `include` or `substack` (`_pam_parse_conf_file`: "Illegal
    /// module type", `requested_module_type != PAM_T_ANY ? ... : PAM_T_AUTH`,
    /// `PAM_HT_MUST_FAIL`).
    pub(crate) phase: &'static str,
    /// As in [`Rule::control`]; empty for a line with none, which libpam
    /// installs in its type's chain as one that always fails, every value
    /// `bad` ("no control flag supplied").
    pub(crate) control: &'a str,
    /// Everything after the control.
    rest: &'a str,
    /// The type is one of the four libpam knows.
    known_type: bool,
}

/// The type and control of a line, split as [`rule`] splits them, or `None`
/// for a comment, a blank line or an `@include` line (see
/// [`is_at_include`]). A bracketed type (`[auth]`) is read as libpam reads
/// it, and so is a line with no control or a type libpam does not know: it
/// is in a chain all the same (see [`Head::phase`]).
pub(crate) fn head(line: &str) -> Option<Head<'_>> {
    let mut rest = directive(line);
    let kind = type_field(&mut rest)?;
    if kind.eq_ignore_ascii_case("@include") {
        return None;
    }
    let phase = TYPES.into_iter().find(|p| p.eq_ignore_ascii_case(kind));
    let control = next_field(&mut rest).unwrap_or("");
    Some(Head {
        phase: phase.unwrap_or("auth"),
        control,
        rest,
        known_type: phase.is_some(),
    })
}

/// The first field after the control: the module path of a rule, the stack
/// an `include` or `substack` line names.
fn third_field<'a>(h: &Head<'a>) -> Option<&'a str> {
    let mut rest = h.rest;
    next_field(&mut rest)
}

/// Every field after the control.
fn fields_after_control<'a>(h: &Head<'a>) -> Vec<&'a str> {
    let mut rest = h.rest;
    std::iter::from_fn(|| next_field(&mut rest)).collect()
}

/// Whether this line is a Debian `@include` line: a type field (read as a
/// type is read, case-insensitively and without a leading `-`) of
/// `@include`. Debian's libpam reads the file it names for every type, in
/// place of the line.
pub(crate) fn is_at_include(line: &str) -> bool {
    let mut rest = directive(line);
    type_field(&mut rest).is_some_and(|kind| kind.eq_ignore_ascii_case("@include"))
}

/// The file an `@include` line names, `None` for any other line.
pub(super) fn at_include_target(line: &str) -> Option<&str> {
    let mut rest = directive(line);
    let kind = type_field(&mut rest)?;
    if !kind.eq_ignore_ascii_case("@include") {
        return None;
    }
    next_field(&mut rest)
}

/// Whether this line is an `include` or `substack` line, whose third field
/// names a stack rather than a module. libpam compares the control with its
/// keywords after taking off any brackets, so `[include]` is one too.
pub(crate) fn names_stack(h: &Head<'_>) -> bool {
    h.control.eq_ignore_ascii_case("include") || h.control.eq_ignore_ascii_case("substack")
}

/// The stack an `include` or `substack` line names, its third field as
/// [`next_field`] reads it, or `None` for any other line and for one that
/// names no stack.
pub(crate) fn stack_name<'a>(h: &Head<'a>) -> Option<&'a str> {
    names_stack(h).then(|| third_field(h)).flatten()
}

/// The words libpam reads as a whole control (`strcasecmp` in
/// `_pam_parse_conf_file`); any other control is parsed by
/// `_pam_parse_control` as `value=action` pairs.
const CONTROL_KEYWORDS: [&str; 6] = [
    "required",
    "requisite",
    "sufficient",
    "optional",
    "include",
    "substack",
];

/// libpam's return values, in its order (`_pam_token_returns` in
/// `libpam/pam_tokens.h`), then `default`. `_pam_parse_control` takes the
/// first of them a pair starts with.
const RETURN_VALUES: [&str; 33] = [
    "success",
    "open_err",
    "symbol_err",
    "service_err",
    "system_err",
    "buf_err",
    "perm_denied",
    "auth_err",
    "cred_insufficient",
    "authinfo_unavail",
    "user_unknown",
    "maxtries",
    "new_authtok_reqd",
    "acct_expired",
    "session_err",
    "cred_unavail",
    "cred_expired",
    "cred_err",
    "no_module_data",
    "conv_err",
    "authtok_err",
    "authtok_recover_err",
    "authtok_lock_busy",
    "authtok_disable_aging",
    "try_again",
    "ignore",
    "abort",
    "authtok_expired",
    "module_unknown",
    "bad_item",
    "conv_again",
    "incomplete",
    "default",
];

/// The largest jump libpam reads (`INT_MAX`); a larger one is a parse error.
const MAX_JUMP: u64 = i32::MAX as u64;

/// The blanks `_pam_parse_control` skips, with `isspace`: space, tab,
/// newline, vertical tab, form feed and carriage return.
fn control_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// What libpam does with one return value of a line: one of its actions
/// (`_pam_token_actions`), or a jump over the next `N` lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Ignore,
    Ok,
    Done,
    Bad,
    Die,
    Reset,
    Jump(usize),
}

/// libpam's actions by name, in its order (`_pam_token_actions`).
const ACTION_NAMES: [(&str, Action); 6] = [
    ("ignore", Action::Ignore),
    ("ok", Action::Ok),
    ("done", Action::Done),
    ("bad", Action::Bad),
    ("die", Action::Die),
    ("reset", Action::Reset),
];

/// The `value=action` pairs of a control, in order, as libpam's
/// `_pam_parse_control` reads them: each pair a return value (or `default`)
/// libpam knows, spelled exactly, blanks allowed before and after the `=`,
/// then an action or a jump of 1 to `INT_MAX`; the next pair may follow an
/// action with no blank at all (`success=1default=ignore`). `None` for a
/// control libpam rejects ("pam_parse: expecting ..."), which makes every
/// value `bad`: no jump at all, whatever pairs it read before the error.
fn control_pairs(control: &str) -> Option<Vec<(&'static str, Action)>> {
    Some(
        control_pairs_at(control)?
            .into_iter()
            .map(|(value, action, _)| (value, action))
            .collect(),
    )
}

/// As [`control_pairs`], with where each pair's action is written: the bytes
/// of `control` that hold the action word or the jump's digits.
fn control_pairs_at(control: &str) -> Option<Vec<(&'static str, Action, Range<usize>)>> {
    let b = control.as_bytes();
    let skip = |mut i: usize| {
        while i < b.len() && control_blank(b[i]) {
            i += 1;
        }
        i
    };
    let mut pairs = Vec::new();
    let mut i = 0;
    loop {
        i = skip(i);
        if i == b.len() {
            return Some(pairs);
        }
        let value = RETURN_VALUES
            .into_iter()
            .find(|v| b[i..].starts_with(v.as_bytes()))?;
        i += value.len();
        if i == b.len() {
            return None;
        }
        i = skip(i);
        if b.get(i) != Some(&b'=') {
            return None;
        }
        i = skip(i + 1);
        if i == b.len() {
            return None;
        }
        let start = i;
        if let Some((name, action)) = ACTION_NAMES
            .into_iter()
            .find(|(name, _)| b[i..].starts_with(name.as_bytes()))
        {
            i += name.len();
            pairs.push((value, action, start..i));
            continue;
        }
        if !b[i].is_ascii_digit() {
            return None;
        }
        let mut n: u64 = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            n = n * 10 + u64::from(b[i] - b'0');
            if n > MAX_JUMP {
                return None;
            }
            i += 1;
        }
        if n == 0 {
            return None;
        }
        pairs.push((value, Action::Jump(usize::try_from(n).ok()?), start..i));
    }
}

/// Which pair of `pairs` sets each of the 32 return values in the end, in
/// [`RETURN_VALUES`] order: a later pair for the same value replaces an
/// earlier one, and `default` sets only the values no pair before it set
/// (`_pam_set_default_control`). `None` for a value no pair sets.
fn set_by(pairs: &[(&'static str, Action)]) -> [Option<usize>; 32] {
    let mut set_by: [Option<usize>; 32] = [None; 32];
    for (at, (value, _)) in pairs.iter().enumerate() {
        match RETURN_VALUES[..32].iter().position(|v| v == value) {
            Some(r) => set_by[r] = Some(at),
            None => {
                for slot in set_by.iter_mut().filter(|s| s.is_none()) {
                    *slot = Some(at);
                }
            }
        }
    }
    set_by
}

/// What a line does with each of libpam's 32 return values, in
/// [`RETURN_VALUES`] order, as `_pam_parse_conf_file` sets it up for its
/// control: the four keywords, or the pairs of a bracketed control with
/// `bad` for every value they leave unset, and `bad` for every value of a
/// control libpam rejects. `None` for `include` and `substack`, whose
/// stack's lines run in its place, and for a line with no control.
fn control_actions(control: &str) -> Option<[Action; 32]> {
    let at = |value: &str| RETURN_VALUES.iter().position(|v| *v == value);
    let keyword = |success: Action, ignore: Option<Action>, rest: Action| {
        let mut table = [rest; 32];
        for value in ["success", "new_authtok_reqd"] {
            if let Some(r) = at(value) {
                table[r] = success;
            }
        }
        if let (Some(action), Some(r)) = (ignore, at("ignore")) {
            table[r] = action;
        }
        table
    };
    let word = |k: &str| control.eq_ignore_ascii_case(k);
    if control.is_empty() || word("include") || word("substack") {
        return None;
    }
    if word("required") {
        return Some(keyword(Action::Ok, Some(Action::Ignore), Action::Bad));
    }
    if word("requisite") {
        return Some(keyword(Action::Ok, Some(Action::Ignore), Action::Die));
    }
    if word("optional") {
        return Some(keyword(Action::Ok, None, Action::Ignore));
    }
    if word("sufficient") {
        return Some(keyword(Action::Done, None, Action::Ignore));
    }
    let Some(pairs) = control_pairs(control) else {
        return Some([Action::Bad; 32]);
    };
    let by = set_by(&pairs);
    Some(std::array::from_fn(|r| {
        by[r].map_or(Action::Bad, |at| pairs[at].1)
    }))
}

/// The numeric jumps of a control, as `(value, N)`: every `value=N` pair
/// whose jump libpam keeps, in the order written, `value` being the return
/// value or `default` as written. libpam reads every control that is not one
/// of its keywords as `value=action` pairs, bracketed
/// (`[success=2 default=ignore]`) or not (`success=2`), exactly as
/// [`control_pairs`] reads them: a control it rejects has no jump. A later
/// pair for the same value replaces an earlier one, and `default` sets only
/// the values no pair before it set (`_pam_set_default_control`), so a pair
/// that sets nothing in the end is left out: `[default=1 default=2]` jumps 1
/// on every value.
pub(crate) fn numeric_actions(h: &Head<'_>) -> Vec<(String, usize)> {
    if CONTROL_KEYWORDS
        .iter()
        .any(|k| h.control.eq_ignore_ascii_case(k))
    {
        return Vec::new();
    }
    let Some(pairs) = control_pairs(h.control) else {
        return Vec::new();
    };
    let by = set_by(&pairs);
    pairs
        .iter()
        .enumerate()
        .filter_map(|(at, (value, action))| match action {
            Action::Jump(n) if by.contains(&Some(at)) => Some(((*value).to_string(), *n)),
            _ => None,
        })
        .collect()
}

/// `line` with some of its numeric jumps given new values and every other
/// byte kept: each `(value, from, to)` names a jump [`numeric_actions`]
/// reports for the line as `(value, from)`, and the digits libpam reads for
/// it become `to`'s. Each pair keeps its spelling, blanks around `=` and a
/// jump run into the next pair (`success=1default=ignore`) included, so
/// libpam splits the control into the same pairs and reads each changed
/// jump as `to`. `None` when the control is not written in brackets closed
/// on the line before any comment, names a changed value in more than one
/// pair, or has no such jump in effect, and when a value is changed twice
/// or `to` is not a jump libpam reads (1 to `INT_MAX`).
pub(crate) fn with_jump_values(line: &str, edits: &[(&str, usize, usize)]) -> Option<String> {
    let h = head(line)?;
    if h.control.is_empty() {
        return None;
    }
    // The control is a slice of the line: `head` reads it from `directive`,
    // which slices the line.
    let start = (h.control.as_ptr() as usize).checked_sub(line.as_ptr() as usize)?;
    let end = start + h.control.len();
    let bracketed = line.get(..start).is_some_and(|l| l.ends_with('['))
        && line.get(end..).is_some_and(|l| l.starts_with(']'));
    if !bracketed || line.get(start..end) != Some(h.control) {
        return None;
    }
    let pairs = control_pairs_at(h.control)?;
    let plain: Vec<(&'static str, Action)> = pairs.iter().map(|(v, a, _)| (*v, *a)).collect();
    let by = set_by(&plain);
    let mut spans: Vec<(Range<usize>, usize)> = Vec::with_capacity(edits.len());
    for (e, &(value, from, to)) in edits.iter().enumerate() {
        if edits[..e].iter().any(|o| o.0 == value)
            || to == 0
            || u64::try_from(to).ok().is_none_or(|t| t > MAX_JUMP)
        {
            return None;
        }
        let mut named = pairs
            .iter()
            .enumerate()
            .filter(|(_, (v, _, _))| *v == value);
        let (at, (_, action, span)) = named.next()?;
        if named.next().is_some() || *action != Action::Jump(from) || !by.contains(&Some(at)) {
            return None;
        }
        spans.push((start + span.start..start + span.end, to));
    }
    // From the last span back, so the earlier ones stay where they are.
    spans.sort_by_key(|(span, _)| std::cmp::Reverse(span.start));
    let mut out = line.to_string();
    for (span, to) in spans {
        out.replace_range(span, &to.to_string());
    }
    Some(out)
}

/// The fields of a rule line, or `None` for anything that loads no module: a
/// comment, a blank line, an `@include`, an `include` or `substack` line
/// (their third field names a stack, not a module), a line whose type libpam
/// does not know (it installs a rule that always fails in its place), or one
/// with no control or no module path.
///
/// Only spaces and tabs are skipped before the type, as libpam skips them. A
/// line that starts with any other blank (a vertical tab, a form feed, a
/// no-break space) has a type libpam does not know, so it loads no module.
pub(crate) fn rule(line: &str) -> Option<Rule<'_>> {
    let h = head(line)?;
    if !h.known_type || names_stack(&h) {
        return None;
    }
    let (phase, control, mut rest) = (h.phase, h.control, h.rest);
    let module = next_field(&mut rest)?;
    let mut args = Vec::new();
    while let Some(arg) = next_field(&mut rest) {
        args.push(arg);
    }
    Some(Rule {
        phase,
        control,
        module,
        args,
    })
}

// ---- lines irlume does not read as libpam does ----------------------------------

/// Why irlume does not read a line the way libpam reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unread {
    /// A NUL byte: libpam reads a line only up to it (a C string), and
    /// decides whether a line continues on the bytes past it.
    Nul,
    /// A blank other than a space or a tab. libpam splits fields only at
    /// spaces and tabs, so it reads this blank as part of a field (a type
    /// libpam does not know, when it leads the line), where irlume's line
    /// tests would take it for a separator.
    Blank(char),
    /// A carriage return that ends the line, as in a file saved with CRLF
    /// line endings: libpam reads it as the end of the line's last field (a
    /// module or stack name it then does not find, or an argument), and a
    /// blank CRLF line as a line whose type is a carriage return.
    CrlfEnding,
    /// A type libpam does not know. It puts the line in the auth chain of the
    /// file it reads for a service, but in the chain of the including line's
    /// type when another file includes this one, so which chain it is in
    /// depends on how the file is reached. `names_stack` when its control is
    /// `include` or `substack`, which libpam then follows.
    UnknownType { names_stack: bool },
    /// An `@include` that names no file: Debian's libpam then refuses the
    /// whole service.
    IncludeWithoutFile,
    /// A `substack` line that names no stack: libpam adds the substack and,
    /// finding no stack to read, a line that always fails after it, so it
    /// counts as two lines.
    SubstackWithoutStack,
    /// A module path (or a substack's stack name) from which libpam can take
    /// no module name (`extract_modulename`: nothing left once the directory
    /// and the last `.` are taken off, or `?`). libpam then stops reading the
    /// file and refuses the whole service.
    NoModuleName,
}

impl Unread {
    /// Why, for a message. Quotes nothing from the line.
    pub(crate) fn describe(self) -> String {
        match self {
            Unread::Nul => "it holds a NUL byte, where PAM stops reading the line".to_string(),
            Unread::Blank(c) => format!(
                "it holds {}, which PAM does not take for a blank between fields",
                blank_name(c)
            ),
            Unread::CrlfEnding => {
                "it ends in a carriage return (a CRLF line ending), which PAM reads as part of \
                 the line; save the file with LF line endings"
                    .to_string()
            }
            Unread::UnknownType { names_stack: false } => {
                "PAM does not know its type and runs it as an auth line that always fails"
                    .to_string()
            }
            Unread::UnknownType { names_stack: true } => {
                "PAM does not know its type and reads the stack it names into the auth stack"
                    .to_string()
            }
            Unread::IncludeWithoutFile => {
                "it is an `@include` without a file, which makes PAM refuse the whole service"
                    .to_string()
            }
            Unread::SubstackWithoutStack => {
                "it is a `substack` without a stack, which PAM counts as two lines".to_string()
            }
            Unread::NoModuleName => {
                "PAM takes no module name from it and then refuses the whole service".to_string()
            }
        }
    }
}

fn blank_name(c: char) -> String {
    match c {
        '\u{b}' => "a vertical tab".to_string(),
        '\u{c}' => "a form feed".to_string(),
        '\r' => "a carriage return".to_string(),
        '\u{a0}' => "a no-break space".to_string(),
        c => format!("the blank U+{:04X}", u32::from(c)),
    }
}

/// A line of a file irlume does not read the way libpam reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnreadLine<'a> {
    /// Which line of the text, counting from 1.
    pub(crate) number: usize,
    /// The line without its newline, a carriage return before it kept.
    pub(crate) text: &'a str,
    pub(crate) why: Unread,
}

/// Whether libpam can take a module name from a module path
/// (`extract_modulename` in `pam_handlers.c`): what is left after the last
/// `/` and before the last `.` must be neither empty nor `?`.
fn libpam_names_module(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    let name = file.rfind('.').map_or(file, |dot| &file[..dot]);
    !name.is_empty() && name != "?"
}

/// Why irlume does not read `line` as libpam does, `None` when it does.
fn unread(line: &str) -> Option<Unread> {
    if line.contains('\0') {
        return Some(Unread::Nul);
    }
    let d = directive(line);
    let before_cr = d.trim_end_matches('\r');
    if let Some(c) = before_cr
        .chars()
        .find(|&c| c != ' ' && c != '\t' && c.is_whitespace())
    {
        return Some(Unread::Blank(c));
    }
    if before_cr.len() < d.len() {
        return Some(Unread::CrlfEnding);
    }
    if is_at_include(line) {
        return at_include_target(line)
            .is_none()
            .then_some(Unread::IncludeWithoutFile);
    }
    let h = head(line)?;
    if !h.known_type {
        return Some(Unread::UnknownType {
            names_stack: names_stack(&h),
        });
    }
    let substack = h.control.eq_ignore_ascii_case("substack");
    if substack && third_field(&h).is_none() {
        return Some(Unread::SubstackWithoutStack);
    }
    // An include adds no line of its own. A substack is a line named after
    // its stack, and a rule one named after its module.
    (substack || !names_stack(&h))
        .then(|| third_field(&h))
        .flatten()
        .is_some_and(|path| !libpam_names_module(path))
        .then_some(Unread::NoModuleName)
}

/// The first line of `content` irlume does not read the way libpam reads
/// it, or `None` when it reads every line as libpam does.
///
/// Every other line is read exactly: a line with no control counts in its
/// type's chain, a control is parsed as `_pam_parse_control` parses it, and
/// a type is read case-insensitively, without its `-` and brackets. These
/// are not: a NUL byte, a blank other than a space or a tab in what PAM
/// reads (it is part of a field to PAM), a type PAM does not know (which
/// chain PAM puts the line in depends on whether another file includes this
/// one), an `@include` without a file and a module path PAM takes no module
/// name from (either makes PAM refuse the whole service), and a `substack`
/// without a stack (PAM counts it as two lines).
///
/// Lines are split at each newline alone, so the carriage return of a CRLF
/// ending stays in its line, as it does for libpam, which splits fields at
/// spaces, tabs and newlines only: it reads the carriage return as the end
/// of the line's last field (a module or stack name it then does not find),
/// and a blank CRLF line as a line whose type is a carriage return. Such a
/// line is one irlume does not read as PAM does. One in a comment is not:
/// PAM reads nothing after a `#`.
///
/// `None` for a file with a line continued with `\`: PAM reads the next
/// physical line as part of that one, which [`has_line_continuation`]
/// reports, and every write refuses such a file already.
pub(crate) fn unreadable_line(content: &str) -> Option<UnreadLine<'_>> {
    if has_line_continuation(content) {
        return None;
    }
    content.split('\n').enumerate().find_map(|(at, text)| {
        unread(text).map(|why| UnreadLine {
            number: at + 1,
            text,
            why,
        })
    })
}

/// Whether a line of `content` holds a carriage return in the part PAM
/// reads (before any `#`), as each line of a file saved with CRLF line
/// endings does: PAM reads it as part of that line ([`unreadable_line`]).
pub(crate) fn has_read_carriage_return(content: &str) -> bool {
    carriage_return_line(content).is_some()
}

/// The first line of `content` with a carriage return in what libpam reads,
/// named as [`unreadable_line`] names one, whether or not the file has a
/// continued line (for which [`unreadable_line`] names none).
pub(crate) fn carriage_return_line(content: &str) -> Option<UnreadLine<'_>> {
    content.split('\n').enumerate().find_map(|(i, text)| {
        let read = directive(text);
        let before = read.trim_end_matches('\r');
        let why = if before.contains('\r') {
            Unread::Blank('\r')
        } else if before.len() < read.len() {
            Unread::CrlfEnding
        } else {
            return None;
        };
        Some(UnreadLine {
            number: i + 1,
            text,
            why,
        })
    })
}

/// The file name of a module path: everything after its last `/`, so both
/// `pam_irlume.so` and `/usr/lib64/security/pam_irlume.so` name
/// `pam_irlume.so`.
fn module_file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// True when this line is a rule whose module path names `module` by file
/// name. A module named in an argument (`pam_exec.so /usr/local/libexec/
/// check-pam_irlume.so`), in a comment or as part of a longer file name
/// (`pam_irlume.so.disabled`) does not count: PAM loads none of those.
pub(crate) fn rule_names_module(line: &str, module: &str) -> bool {
    rule(line).is_some_and(|r| module_file_name(r.module) == module)
}

/// The fields of this line when it is a rule that loads pam_irlume.so, which
/// is how irlume tells its own lines apart: by the module path, never by the
/// name appearing somewhere in the line.
pub(super) fn irlume_rule(line: &str) -> Option<Rule<'_>> {
    rule(line).filter(|r| module_file_name(r.module) == MODULE)
}

/// Whether this line is an `auth` rule of pam_irlume.so that authenticates or
/// releases a secret: any but a pure `reseal` line, which only re-seals a
/// typed password and hands a keyring token over. That covers `unseal`,
/// `keyring`, the older `wait` form, a bare verify line, and a line that
/// names `reseal` beside one of those, since the module handles the others
/// first; every one of them can reach the camera or a sealed secret.
pub(super) fn irlume_auth_rule_beyond_reseal(line: &str) -> bool {
    irlume_rule(line).is_some_and(|rule| {
        let credential = rule
            .args
            .iter()
            .any(|arg| matches!(*arg, "unseal" | "keyring" | "wait"));
        rule.phase == "auth" && (credential || !rule.args.contains(&"reseal"))
    })
}

/// Whether this line is a rule that loads pam_irlume.so with `arg` among its
/// arguments (`unseal`, `keyring`, `reseal`), matched whole as the module
/// matches them.
pub(super) fn irlume_rule_has_arg(line: &str, arg: &str) -> bool {
    irlume_rule(line).is_some_and(|r| r.args.contains(&arg))
}

/// The head of a line of type `phase` written with a type libpam knows.
fn typed_head<'a>(line: &'a str, phase: &str) -> Option<Head<'a>> {
    head(line).filter(|h| h.known_type && h.phase == phase)
}

/// The stack an `include` or `substack` line of type `phase` names.
fn stack_named<'a>(line: &'a str, phase: &str) -> Option<&'a str> {
    typed_head(line, phase)
        .filter(names_stack)
        .and_then(|h| third_field(&h))
}

/// An `auth`-phase line whose password path is an `include` a `success=N` jump
/// can't skip: Debian's `@include common-auth`/`login`, Arch's
/// `auth include system-login`/`system-local-login`/`system-auth`, or a bare
/// `auth include common-auth`. These need the `sufficient` (module IGNOREs on
/// cold login) form, NOT the jump form. A `substack` is atomic for jump
/// counting, so it deliberately does not match here and keeps the jump stanza;
/// which is what openSUSE's `auth substack common-auth` relies on.
///
/// Read as libpam reads the line: the type and control case-insensitively,
/// a leading `-` and brackets taken off, and the stack's name as the whole
/// third field. A Debian `@include` counts when the file it names starts
/// with `common-auth` or `login`, so a site's own copy of the password
/// stack (`@include common-auth-local`) takes this layout too: the face line
/// above it, and irlume's keyring and `reseal` lines below it, never above
/// the password step.
pub(super) fn is_include_auth_layout(line: &str) -> bool {
    if let Some(file) = at_include_target(line) {
        return file.starts_with("common-auth") || file.starts_with("login");
    }
    typed_head(line, "auth")
        .filter(|h| h.control.eq_ignore_ascii_case("include"))
        .and_then(|h| third_field(&h))
        .is_some_and(|stack| {
            matches!(
                stack,
                "system-login" | "system-local-login" | "system-auth" | "common-auth"
            )
        })
}

/// `<kind>` is `auth`/`session`; matches the shared password stack that the
/// `success=1` jump skips: Fedora's `password-auth`/`system-auth`, and
/// openSUSE's `common-auth`/`common-session`.
///
/// The stack names are kind-aware so an `auth` line is only tested against
/// auth-phase names. openSUSE's `plasmalogin` routes the password through
/// `auth substack common-auth`, which matched nothing here: wiring then fell
/// back to the first auth line and inserted the jump above `pam_nologin.so`, so
/// a face login skipped the nologin gate and *still* landed on the password
/// stack underneath: face auth that neither honoured nologin nor logged you in.
pub(super) fn is_passwd_substack(line: &str, kind: &str) -> bool {
    let stacks: &[&str] = match kind {
        "auth" => &["password-auth", "system-auth", "common-auth"],
        "session" => &["password-auth", "system-auth", "common-session"],
        _ => &["password-auth", "system-auth"],
    };
    stack_named(line, kind).is_some_and(|stack| stacks.contains(&stack))
}

/// Whether this line is in the auth chain as an auth line: its type, read
/// as libpam reads it, is `auth`.
pub(super) fn is_auth_directive(line: &str) -> bool {
    typed_head(line, "auth").is_some()
}

/// Whether `content` holds an auth line libpam installs or runs as one that
/// always fails: one with a type but no control, with no module path or
/// stack name, or with a control libpam rejects, which makes every return
/// value `bad`. libpam fails the stack there unless a line before it ends
/// the stack, so a `sufficient` face line irlume put above it would let a
/// face match through where the stack lets no one through; irlume wires
/// nothing into such a file. A valid control that is `bad` or `die` for
/// every value, such as `[default=die]` on faillock's `authfail` line, is
/// not one: it is the branch a failed password takes, and a correct one
/// jumps past it.
pub(super) fn has_failing_auth_line(content: &str) -> bool {
    content.lines().any(|l| {
        typed_head(l, "auth").is_some_and(|h| {
            h.control.is_empty() || third_field(&h).is_none() || control_is_rejected(h.control)
        })
    })
}

/// Whether libpam rejects `control` ("pam_parse: expecting ..."): not one
/// of its keywords, `include` or `substack`, and not `value=action` pairs it
/// reads ([`control_pairs`]).
fn control_is_rejected(control: &str) -> bool {
    !CONTROL_KEYWORDS
        .iter()
        .any(|k| control.eq_ignore_ascii_case(k))
        && control_pairs(control).is_none()
}

/// Whether this line's type, read as libpam reads it, is `session`.
pub(super) fn is_session_directive(line: &str) -> bool {
    typed_head(line, "session").is_some()
}

/// Whether this line is a Debian `@include` of the shared session stack: a
/// file whose name starts with `common-session`, which irlume's session
/// `reseal` line follows.
pub(super) fn is_session_include(line: &str) -> bool {
    at_include_target(line).is_some_and(|file| file.starts_with("common-session"))
}

/// An `auth` line whose control keyword is `substack`, whatever the shared stack
/// happens to be NAMED. A substack is atomic for jump counting, so this is a
/// safe jump anchor even when we do not recognize the target.
///
/// This exists because the named list cannot keep up with upstreams. GDM's main
/// branch renamed its shared stack from `password-auth` to
/// `gdm-password-auth-substack` (a file GDM does not ship; distros supply it),
/// which no name in `is_passwd_substack` matches. Without this tier the anchor
/// search falls through to "first auth line", which on GDM's stack is
/// `pam_selinux_permit.so`: the jump would then skip THAT and land above the
/// password substack, which still runs. That is the openSUSE failure exactly,
/// and it would arrive silently with a GDM upgrade.
pub(super) fn is_auth_substack_anchor(line: &str) -> bool {
    typed_head(line, "auth").is_some_and(|h| h.control.eq_ignore_ascii_case("substack"))
}

/// Whether `line` is a password step the verify stanza goes above: an inline
/// include of the auth stack, a shared password substack, any auth substack,
/// or the `pam_unix.so` auth line.
pub(super) fn is_password_step(line: &str) -> bool {
    is_include_auth_layout(line)
        || is_passwd_substack(line, "auth")
        || is_auth_substack_anchor(line)
        || (is_auth_directive(line) && rule_names_module(line, "pam_unix.so"))
}

/// Where the face block anchors, in descending order of confidence: a shared
/// stack we recognize by name, then any `substack` whatever its name, and only
/// then the first `auth` line. The last tier is a guess and is kept last
/// deliberately: it is what produces a jump over an unrelated module.
///
/// The guess is taken only where [`first_auth_line_is_safe`] holds, since
/// irlume's permit landing, keyring and `reseal` lines go right below it:
/// `None` otherwise, so the file is left as it is.
pub(super) fn find_auth_anchor(lines: &[&str]) -> Option<usize> {
    lines
        .iter()
        .position(|l| is_passwd_substack(l, "auth"))
        .or_else(|| lines.iter().position(|l| is_auth_substack_anchor(l)))
        .or_else(|| {
            lines
                .iter()
                .position(|l| is_auth_directive(l))
                .filter(|&at| first_auth_line_is_safe(lines, at))
        })
}

/// Debian's `@include` files that hold no auth line.
const NON_AUTH_INCLUDES: [&str; 4] = [
    "common-account",
    "common-password",
    "common-session",
    "common-session-noninteractive",
];

/// Auth modules that check no password, which irlume's lines may sit above.
/// The keyring modules ([`KEYRING_CONSUMERS`]) count as such lines too.
const NO_PASSWORD_AUTH_MODULES: [&str; 17] = [
    "pam_access.so",
    "pam_deny.so",
    "pam_env.so",
    "pam_faildelay.so",
    "pam_faillock.so",
    "pam_group.so",
    "pam_listfile.so",
    "pam_localuser.so",
    "pam_nologin.so",
    "pam_permit.so",
    "pam_rootok.so",
    "pam_securetty.so",
    "pam_selinux_permit.so",
    "pam_shells.so",
    "pam_succeed_if.so",
    "pam_tally2.so",
    "pam_warn.so",
];

/// Auth modules that check the password they are given and answer with a
/// success or a failure: the password step irlume's lines follow.
const PASSWORD_MODULES: [&str; 3] = ["pam_sss.so", "pam_unix.so", "pam_unix2.so"];

/// How many stacks deep irlume follows an `include` or `@include` it reads
/// ([`included_lines`]). Deeper is read as a stack it cannot tell about.
const INCLUDE_DEPTH: usize = 4;

/// Whether the first auth line, at `at`, is safe to wire next to when no
/// line names the password stack. irlume's face line jumps over it onto a
/// `pam_permit` landing, and its keyring and `reseal` lines follow the
/// landing. irlume's lines are designed to follow the password step and a
/// line whose failure fails the stack, so that line must be:
///
/// - a password step ([`is_password_step_that_fails_the_stack`]); or
/// - an `include` of a stack whose first line is one
///   ([`included_stack_starts_with_the_step`]), read from where libpam finds
///   it ([`with_stack_reader`]). One that cannot be read is no anchor.
///
/// No auth line below it may check a password either
/// ([`quiet_below_anchor`]).
fn first_auth_line_is_safe(lines: &[&str], at: usize) -> bool {
    let decides = head(lines[at]).is_some_and(|h| {
        if names_stack(&h) {
            h.control.eq_ignore_ascii_case("include")
                && third_field(&h).is_some_and(included_stack_starts_with_the_step)
        } else {
            is_password_step_that_fails_the_stack(&h)
        }
    });
    decides && lines[at + 1..].iter().all(|l| quiet_below_anchor(l, 1))
}

/// Whether `l`, a line below the first auth line [`first_auth_line_is_safe`]
/// takes, checks no password: an auth line must be one of
/// [`NO_PASSWORD_AUTH_MODULES`] or a keyring module, with no `include` or
/// `substack`, since the stack it names can check one. A Debian `@include`
/// is expanded in the auth stack too, so the file it names, one of
/// [`NON_AUTH_INCLUDES`], is read where libpam finds it, [`INCLUDE_DEPTH`]
/// files deep at most, and each of its lines must be one too.
fn quiet_below_anchor(l: &str, depth: usize) -> bool {
    if let Some(file) = at_include_target(l) {
        return depth <= INCLUDE_DEPTH
            && NON_AUTH_INCLUDES.contains(&file)
            && read_stack(file).is_some_and(|text| {
                !has_line_continuation(&text)
                    && unreadable_line(&text).is_none()
                    && text.lines().all(|m| quiet_below_anchor(m, depth + 1))
            });
    }
    let Some(h) = head(l) else {
        return true;
    };
    if h.known_type && h.phase != "auth" {
        return true;
    }
    if !h.known_type || names_stack(&h) {
        return false;
    }
    // A line with no module loads none: libpam installs one that always
    // fails in its place.
    third_field(&h).is_none_or(|path| {
        let file = module_file_name(path);
        NO_PASSWORD_AUTH_MODULES.contains(&file) || KEYRING_CONSUMERS.contains(&file)
    })
}

/// Whether `h` is a password step whose failure fails the stack: a rule of
/// one of [`PASSWORD_MODULES`] whose control gives `ok` or `done` for
/// `success`, so a correct password counts, and `bad` or `die` for every
/// other return value but `new_authtok_reqd` and `ignore`, with no numeric
/// jump. An `ignore_` argument (pam_sss's `ignore_unknown_user` and
/// `ignore_authinfo_unavail`) makes the module answer `ignore` in place of a
/// failure, so a line with one is not such a step.
fn is_password_step_that_fails_the_stack(h: &Head<'_>) -> bool {
    let fields = fields_after_control(h);
    let Some((module, args)) = fields.split_first() else {
        return false;
    };
    PASSWORD_MODULES.contains(&module_file_name(module))
        && !args.iter().any(|a| a.starts_with("ignore_"))
        && control_actions(h.control).is_some_and(|table| {
            table
                .iter()
                .zip(RETURN_VALUES)
                .all(|(action, value)| match (action, value) {
                    (Action::Jump(_), _) => false,
                    (action, "success") => matches!(action, Action::Ok | Action::Done),
                    (Action::Bad | Action::Die, _) => true,
                    (_, value) => matches!(value, "new_authtok_reqd" | "ignore"),
                })
        })
}

/// Whether the stack an `include` taken as the first auth line names starts
/// with the password step. libpam puts the stack's lines in the include's
/// place, and irlume's face line jumps over the first of them onto its
/// landing after the include, so a face match stands in for that line
/// alone and every other line of the stack still runs, gates included.
/// That first line must be a password step
/// ([`is_password_step_that_fails_the_stack`]) or the shared password
/// `substack` irlume knows, one line whatever it holds; the others are held
/// to the rule for the lines below the first auth line
/// ([`quiet_below_anchor`]), and none may jump or `reset`. The stack is read
/// as [`included_lines`] reads it; one irlume cannot read is no anchor.
fn included_stack_starts_with_the_step(name: &str) -> bool {
    let Some(lines) = included_lines(name, "auth", 1) else {
        return false;
    };
    let Some((first, rest)) = lines.split_first() else {
        return false;
    };
    let moves = |l: &String| {
        head(l).is_some_and(|h| {
            control_actions(h.control).is_some_and(|table| {
                table
                    .iter()
                    .any(|a| matches!(a, Action::Jump(_) | Action::Reset))
            })
        })
    };
    let step = is_passwd_substack(first, "auth")
        || head(first)
            .is_some_and(|h| !names_stack(&h) && is_password_step_that_fails_the_stack(&h));
    step && !lines.iter().any(moves) && rest.iter().all(|l| quiet_below_anchor(l, 1))
}

/// Whether a numeric jump among the `phase` lines that an `include` of the
/// stack `name` puts in its place could land past them, onto the lines after
/// the include: libpam counts the included lines, not the include, so such
/// a jump counts the lines after it. Also `true` when irlume cannot tell: a
/// stack [`included_lines`] cannot read.
///
/// With `to_end`, a jump that lands on the first line after the include
/// counts too: it lands on whatever line comes next.
fn included_jump_leaves(name: &str, phase: &str, to_end: bool) -> bool {
    included_lines(name, phase, 1).is_none_or(|lines| {
        lines.iter().enumerate().any(|(at, line)| {
            head(line).is_some_and(|h| {
                numeric_actions(&h)
                    .into_iter()
                    .any(|(_, reach)| at + reach + usize::from(to_end) >= lines.len())
            })
        })
    })
}

/// For an `include` or a Debian `@include` line, `Some` of whether a numeric
/// jump among the lines it puts in its place could land past them for a
/// type `later` says one of irlume's lines comes after it in
/// ([`included_jump_leaves`]; with `to_end`, onto the first line after
/// them too): libpam puts the named stack's lines of the include's type in
/// its place, and all of a Debian `@include`'s file, in every type's stack.
/// `Some(true)` for one irlume cannot read, `None` for any other line.
pub(super) fn include_could_jump_past(
    line: &str,
    later: impl Fn(&str) -> bool,
    to_end: bool,
) -> Option<bool> {
    if is_at_include(line) {
        return Some(at_include_target(line).is_none_or(|file| {
            TYPES
                .into_iter()
                .any(|phase| later(phase) && included_jump_leaves(file, phase, to_end))
        }));
    }
    let h = head(line)?;
    if !h.control.eq_ignore_ascii_case("include") {
        return None;
    }
    // PAM counts a line of a type it does not know in the auth stack, as one
    // that always fails.
    Some(
        !h.known_type
            || later(h.phase)
                && third_field(&h).is_none_or(|stack| included_jump_leaves(stack, h.phase, to_end)),
    )
}

/// Whether irlume can read the lines an `include` or a Debian `@include`
/// line puts in its place, the stacks they include in turn among them, as
/// [`include_could_jump_past`] reads them ([`included_lines`]): `false` for
/// one it cannot read, and for any other line.
pub(super) fn include_is_read(line: &str) -> bool {
    if is_at_include(line) {
        return at_include_target(line)
            .is_some_and(|file| included_lines(file, "auth", 1).is_some());
    }
    head(line)
        .filter(|h| h.known_type && h.control.eq_ignore_ascii_case("include"))
        .is_some_and(|h| {
            third_field(&h).is_some_and(|stack| included_lines(stack, h.phase, 1).is_some())
        })
}

/// The `phase` lines libpam puts in the place of an `include` of the stack
/// `name`, in order: the lines of the stacks an `include` or a Debian
/// `@include` in it names in turn, [`INCLUDE_DEPTH`] stacks deep at most,
/// and a `substack` as the one line it is. `None` when irlume cannot tell: a
/// stack that cannot be read ([`with_stack_reader`]), one too deep, a
/// continued line or a line irlume does not read as PAM does
/// ([`unreadable_line`]).
fn included_lines(name: &str, phase: &str, depth: usize) -> Option<Vec<String>> {
    if depth > INCLUDE_DEPTH {
        return None;
    }
    let text = read_stack(name)?;
    if has_line_continuation(&text) || unreadable_line(&text).is_some() {
        return None;
    }
    let mut lines = Vec::new();
    for line in text.lines() {
        if let Some(file) = at_include_target(line) {
            lines.extend(included_lines(file, phase, depth + 1)?);
            continue;
        }
        let Some(h) = typed_head(line, phase) else {
            continue;
        };
        if h.control.eq_ignore_ascii_case("include") {
            lines.extend(included_lines(third_field(&h)?, phase, depth + 1)?);
            continue;
        }
        lines.push(line.to_string());
    }
    Some(lines)
}

/// Reads a stack an `include`, `substack` or `@include` names: its text, or
/// `None` when there is no such stack or it cannot be read.
pub(super) type StackReader = std::rc::Rc<dyn Fn(&str) -> Option<String>>;

thread_local! {
    /// The reader [`with_stack_reader`] sets for the recipe it runs.
    static STACK_READER: std::cell::RefCell<Option<StackReader>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `f` with `reader` as the way the stacks an include names are read,
/// which is how [`first_auth_line_is_safe`] reads the stack a first auth
/// `include` names. The file handling sets it for each file it wires; this
/// module reads no file itself, and outside such a call no stack can be read.
pub(super) fn with_stack_reader<T>(reader: StackReader, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<StackReader>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            STACK_READER.with(|r| *r.borrow_mut() = previous);
        }
    }
    let _restore = Restore(STACK_READER.with(|r| r.replace(Some(reader))));
    f()
}

/// The stack `name` names, read with the reader [`with_stack_reader`] set.
fn read_stack(name: &str) -> Option<String> {
    let reader = STACK_READER.with(|r| r.borrow().clone())?;
    reader(name)
}

/// The auth line that performs the fingerprint check, and therefore the line the
/// keyring unseal must follow.
///
/// Matching a literal `pam_fprintd.so` was not enough: GDM's shipped
/// `gdm-fingerprint.pam` never names the module, delegating instead to
/// `auth substack fingerprint-auth` (renamed `gdm-fingerprint-auth-substack` on
/// GDM's development branch). With only the literal match this returned no
/// anchor, `wire_fp_keyring` became a silent no-op, and the fingerprint keyring
/// unlock never wired on Fedora at all.
///
/// The module is matched on the rule's module path and the stack on the
/// name the line gives it, never on an argument: `pam_exec.so
/// /usr/local/libexec/check-pam_fprintd.so` checks no fingerprint.
pub(super) fn is_fingerprint_auth(line: &str) -> bool {
    let Some(h) = typed_head(line, "auth") else {
        return false;
    };
    if names_stack(&h) {
        return third_field(&h).is_some_and(|stack| stack.contains("fingerprint"));
    }
    rule_names_module(line, "pam_fprintd.so")
}

/// The keyring module on this line, if it is one AND it will actually do
/// something for `service`.
///
/// `pam_gnome_keyring.so` accepts `only_if=<comma,separated,services>`, and for
/// any service outside that list every one of its entry points returns
/// `PAM_SUCCESS` immediately: it reads no token, stashes nothing, unlocks
/// nothing. Matching the module name alone would therefore count a line that is
/// a guaranteed no-op here as a working consumer, and report a hand-off that
/// cannot happen: the exact false reassurance this check exists to prevent.
///
/// The list is matched the way gkr-pam's `evaluate_inlist` matches it: whole
/// comma-separated items, not substrings, so `only_if=gdm` does not satisfy
/// `gdm-fingerprint`. Any single excluding `only_if=` disables the module, since
/// gkr ORs `ARG_IGNORE_SERVICE` in and never clears it. `pam_kwallet5.so` has no
/// equivalent option (`only_if` appears nowhere in kwallet-pam), so this only
/// ever narrows the gnome-keyring case.
///
/// The module is the rule's module path, never an argument: `pam_exec.so
/// /path/pam_gnome_keyring.so` loads only pam_exec.
pub(super) fn consumer_active_for(line: &str, service: &str) -> Option<&'static str> {
    let r = rule(line)?;
    let module = KEYRING_CONSUMERS
        .iter()
        .copied()
        .find(|m| module_file_name(r.module) == *m)?;
    let gated_out = r
        .args
        .iter()
        .filter_map(|w| w.strip_prefix("only_if="))
        .any(|list| !list.split(',').any(|item| item == service));
    (!gated_out).then_some(module)
}

/// The part of a stack line PAM actually tokenizes: everything before the
/// first `#`, leading spaces and tabs trimmed, as libpam's `_pam_str_trim`
/// leaves it. libpam skips only those two there, so a line led by another
/// blank keeps it (and PAM reads it as part of the type).
///
/// Matching the raw line disagrees with libpam, which strips a trailing comment
/// before tokenizing (verified against `pam_exec.so`: a real argument survives,
/// a trailing comment does not). Without this, a module named only inside a
/// comment counts as configured, and because `content_has_module` gates the
/// whole wiring path, a stack whose comment happens to mention `pam_irlume.so`
/// would be treated as already wired and silently left alone.
///
/// A full-line comment yields `""`, so callers need no separate `#` check.
pub(crate) fn directive(line: &str) -> &str {
    let t = line.trim_start_matches([' ', '\t']);
    match t.find('#') {
        Some(i) => &t[..i],
        None => t,
    }
}

/// True when a line of `content` continues on the next one, as libpam's line
/// assembler decides it (`_pam_str_unescnl` and `_pam_str_prepare` in
/// `libpam_internal/pam_line.c`): the physical line, with the spaces, tabs
/// and newline at its end taken off, ends in `\`, and it has no `#` before
/// its first NUL byte (libpam looks for one with `strchr`).
///
/// libpam's line assembler joins such a line with the next one before
/// tokenizing, so a two-physical-line entry is ONE line to PAM. Everything
/// here is line-oriented, and on a continued file the two views disagree.
/// Worse than mis-reading: inserting a stanza directly after a continued
/// anchor would splice our text into the MIDDLE of the logical line PAM
/// evaluates, corrupting the stack on write.
///
/// The semantics are pinned empirically against `pam_exec.so`:
///   * a trailing `\` on a directive continues; the next physical line's
///     text executed as this line's arguments;
///   * spaces and tabs AFTER the backslash do not defuse it (still
///     continues); a carriage return or any other blank there does, since
///     libpam skips only spaces, tabs and the newline back from the end;
///   * a `\` at the end of a COMMENT does not continue; both lines ran.
///
/// No upstream stack irlume pins uses continuations, so the fail-safe answer
/// is to notice and stand down: the wiring transforms refuse the file
/// (staged, never written, the same contract as a missing anchor), and the
/// hand-off advisory stays silent rather than reporting from an analysis
/// that cannot see the file the way PAM does.
pub(crate) fn has_line_continuation(content: &str) -> bool {
    content.split('\n').any(|l| {
        let read = l.split('\0').next().unwrap_or(l);
        l.trim_end_matches([' ', '\t']).ends_with('\\') && !read.contains('#')
    })
}

/// The module-path field of this line, when it is an auth RULE: `type control
/// module-path module-arguments`, per pam.conf(5), with the type read
/// case-insensitively as libpam does and PAM's leading `-` tolerated.
///
/// `include`/`substack` controls carry a target, not a module, and a bracketed
/// control (`[success=1 default=ignore]`) spans tokens until the closing `]`,
/// so the module path is whatever follows the WHOLE control field. Substring
/// scans that skipped this parsing counted a `session` line, a module
/// ARGUMENT naming the file, or `pam_fprintd.so.disabled` as fingerprint
/// authentication, and the `--fingerprint-only` gate then stood face down on
/// a box where no fingerprint rule answers any prompt.
pub(crate) fn auth_module(line: &str) -> Option<&str> {
    rule(line).filter(|r| r.phase == "auth").map(|r| r.module)
}

/// True when this line is an auth rule whose module-path names `module` (by
/// file name, so `/usr/lib64/security/pam_fprintd.so` matches
/// `pam_fprintd.so` and `pam_fprintd.so.disabled` does not).
pub(crate) fn directive_has_auth_module(line: &str, module: &str) -> bool {
    auth_module(line).is_some_and(|path| module_file_name(path) == module)
}
