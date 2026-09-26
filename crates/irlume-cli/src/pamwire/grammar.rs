// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Reading PAM stack lines: which line is an auth directive, which one is the
//! shared password stack, where the face block should anchor.
//!
//! Pure predicates over a single line (or a slice of them). No I/O and no
//! rewriting, so every distro layout irlume supports can be pinned by a unit
//! test without touching a filesystem.

use super::stanzas::{KEYRING_CONSUMERS, MODULE};

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
/// module file name or argument irlume looks for.
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

/// The type and control of any line libpam reads as part of a stack, an
/// `include` or `substack` line among them: what numeric jumps and the chain
/// of a phase are counted from.
pub(crate) struct Head<'a> {
    /// As in [`Rule::phase`].
    pub(crate) phase: &'static str,
    /// As in [`Rule::control`].
    pub(crate) control: &'a str,
    /// Everything after the control.
    rest: &'a str,
}

/// The type and control of a line, split as [`rule`] splits them, or `None`
/// for a comment, a blank line, an `@include` or a line whose type is not one
/// of the four. A bracketed type (`[auth]`) is read as libpam reads it.
pub(crate) fn head(line: &str) -> Option<Head<'_>> {
    let line = line.trim_start_matches([' ', '\t']);
    let mut rest = &line[..line.find('#').unwrap_or(line.len())];
    let kind = next_field(&mut rest)?;
    let bare = kind.strip_prefix('-').unwrap_or(kind);
    let phase = ["auth", "account", "password", "session"]
        .into_iter()
        .find(|p| p.eq_ignore_ascii_case(bare))?;
    let control = next_field(&mut rest)?;
    Some(Head {
        phase,
        control,
        rest,
    })
}

/// Whether this line is an `include` or `substack` line, whose third field
/// names a stack rather than a module. libpam compares the control with its
/// keywords after taking off any brackets, so `[include]` is one too.
pub(crate) fn names_stack(h: &Head<'_>) -> bool {
    h.control.eq_ignore_ascii_case("include") || h.control.eq_ignore_ascii_case("substack")
}

/// The `value=N` jumps of a control, as `(value, N)` with N above zero. libpam
/// reads every control that is not one of its keywords as `value=action`
/// pairs, bracketed (`[success=2 default=ignore]`) or not (`success=2`).
pub(crate) fn numeric_actions(h: &Head<'_>) -> Vec<(String, usize)> {
    const KEYWORDS: [&str; 6] = [
        "required",
        "requisite",
        "sufficient",
        "optional",
        "include",
        "substack",
    ];
    if KEYWORDS.iter().any(|k| h.control.eq_ignore_ascii_case(k)) {
        return Vec::new();
    }
    h.control
        .split(FIELD_DELIMITERS)
        .filter_map(|kv| {
            let (key, value) = kv.split_once('=')?;
            let n: usize = value.parse().ok()?;
            (n > 0).then(|| (key.to_string(), n))
        })
        .collect()
}

/// The fields of a rule line, or `None` for anything that loads no module: a
/// comment, a blank line, an `@include`, an `include` or `substack` line
/// (their third field names a stack, not a module), a line whose type is not
/// one of the four, or one with no module path.
///
/// Only spaces and tabs are skipped before the type, as libpam skips them. A
/// line that starts with any other blank (a vertical tab, a form feed, a
/// no-break space) has a type libpam does not know, so it loads no module:
/// PAM installs a rule that always fails in its place.
pub(crate) fn rule(line: &str) -> Option<Rule<'_>> {
    let h = head(line)?;
    if names_stack(&h) {
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

/// An `auth`-phase line whose password path is an `include` a `success=N` jump
/// can't skip: Debian's `@include common-auth`/`login`, Arch's
/// `auth include system-login`/`system-local-login`/`system-auth`, or a bare
/// `auth include common-auth`. These need the `sufficient` (module IGNOREs on
/// cold login) form, NOT the jump form. A `substack` is atomic for jump
/// counting, so it deliberately does not match here and keeps the jump stanza;
/// which is what openSUSE's `auth substack common-auth` relies on.
pub(super) fn is_include_auth_layout(line: &str) -> bool {
    let t = directive(line);
    if t.starts_with("@include common-auth") || t.starts_with("@include login") {
        return true;
    }
    let toks: Vec<&str> = t.split_whitespace().collect();
    toks.first() == Some(&"auth")
        && toks.get(1) == Some(&"include")
        && matches!(
            toks.get(2),
            Some(&"system-login")
                | Some(&"system-local-login")
                | Some(&"system-auth")
                | Some(&"common-auth")
        )
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
    let d = directive(line);
    let toks: Vec<&str> = d
        .strip_prefix('-')
        .unwrap_or(d)
        .split_whitespace()
        .collect();
    let stacks: &[&str] = match kind {
        "auth" => &["password-auth", "system-auth", "common-auth"],
        "session" => &["password-auth", "system-auth", "common-session"],
        _ => &["password-auth", "system-auth"],
    };
    toks.first() == Some(&kind)
        && toks.iter().any(|w| *w == "substack" || *w == "include")
        && toks.iter().any(|w| stacks.contains(w))
}

pub(super) fn is_auth_directive(line: &str) -> bool {
    let t = directive(line);
    t.strip_prefix('-').unwrap_or(t).split_whitespace().next() == Some("auth")
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
    let d = directive(line);
    let toks: Vec<&str> = d
        .strip_prefix('-')
        .unwrap_or(d)
        .split_whitespace()
        .collect();
    toks.first() == Some(&"auth") && toks.get(1) == Some(&"substack")
}

/// Where the face block anchors, in descending order of confidence: a shared
/// stack we recognize by name, then any `substack` whatever its name, and only
/// then the first `auth` line. The last tier is a guess and is kept last
/// deliberately: it is what produces a jump over an unrelated module.
pub(super) fn find_auth_anchor(lines: &[&str]) -> Option<usize> {
    lines
        .iter()
        .position(|l| is_passwd_substack(l, "auth"))
        .or_else(|| lines.iter().position(|l| is_auth_substack_anchor(l)))
        .or_else(|| lines.iter().position(|l| is_auth_directive(l)))
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
pub(super) fn is_fingerprint_auth(line: &str) -> bool {
    let d = directive(line);
    let toks: Vec<&str> = d
        .strip_prefix('-')
        .unwrap_or(d)
        .split_whitespace()
        .collect();
    if toks.first() != Some(&"auth") {
        return false;
    }
    toks.iter().any(|w| w.contains("pam_fprintd.so"))
        || (toks.iter().any(|w| *w == "substack" || *w == "include")
            && toks.iter().any(|w| w.contains("fingerprint")))
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
pub(super) fn consumer_active_for(line: &str, service: &str) -> Option<&'static str> {
    let t = directive(line);
    let module = KEYRING_CONSUMERS.iter().copied().find(|m| t.contains(m))?;
    let gated_out = t
        .split_whitespace()
        .filter_map(|w| w.strip_prefix("only_if="))
        .any(|list| !list.split(',').any(|item| item == service));
    (!gated_out).then_some(module)
}

/// The part of a stack line PAM actually tokenizes: everything before the first
/// `#`, leading whitespace trimmed.
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
    let t = line.trim_start();
    match t.find('#') {
        Some(i) => &t[..i],
        None => t,
    }
}

/// True when any line's DIRECTIVE part ends in a `\` continuation.
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
///   * whitespace AFTER the backslash does not defuse it (still continues);
///   * a `\` at the end of a COMMENT does not continue; both lines ran.
///
/// Hence the check runs on `directive()` output with trailing space trimmed.
///
/// No upstream stack irlume pins uses continuations, so the fail-safe answer
/// is to notice and stand down: the wiring transforms refuse the file
/// (staged, never written, the same contract as a missing anchor), and the
/// hand-off advisory stays silent rather than reporting from an analysis
/// that cannot see the file the way PAM does.
pub(crate) fn has_line_continuation(content: &str) -> bool {
    content
        .lines()
        .any(|l| directive(l).trim_end().ends_with('\\'))
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
