// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Reading PAM stack lines: which line is an auth directive, which one is the
//! shared password stack, where the face block should anchor.
//!
//! Pure predicates over a single line (or a slice of them). No I/O and no
//! rewriting, so every distro layout irlume supports can be pinned by a unit
//! test without touching a filesystem.

use super::stanzas::{KEYRING_CONSUMERS, MODULE};

pub(super) fn content_has_module(c: &str) -> bool {
    c.lines().any(|l| directive(l).contains(MODULE))
}

/// An `auth`-phase line whose password path is an `include` a `success=N` jump
/// can't skip: Debian's `@include common-auth`/`login`, Arch's
/// `auth include system-login`/`system-local-login`/`system-auth`, or a bare
/// `auth include common-auth`. These need the `sufficient` (module IGNOREs on
/// cold login) form, NOT the jump form. A `substack` is atomic for jump
/// counting, so it deliberately does not match here and keeps the jump stanza —
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
/// stack underneath — face auth that neither honoured nologin nor logged you in.
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
/// `gdm-password-auth-substack` (a file GDM does not ship — distros supply it),
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
/// deliberately — it is what produces a jump over an unrelated module.
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
/// `PAM_SUCCESS` immediately — it reads no token, stashes nothing, unlocks
/// nothing. Matching the module name alone would therefore count a line that is
/// a guaranteed no-op here as a working consumer, and report a hand-off that
/// cannot happen: the exact false reassurance this check exists to prevent.
///
/// The list is matched the way gkr-pam's `evaluate_inlist` matches it — whole
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
/// comment counts as configured — and because `content_has_module` gates the
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
///   * a trailing `\` on a directive continues — the next physical line's
///     text executed as this line's arguments;
///   * whitespace AFTER the backslash does not defuse it (still continues);
///   * a `\` at the end of a COMMENT does not continue — both lines ran.
///
/// Hence the check runs on `directive()` output with trailing space trimmed.
///
/// No upstream stack irlume pins uses continuations, so the fail-safe answer
/// is to notice and stand down: the wiring transforms refuse the file
/// (staged, never written — the same contract as a missing anchor), and the
/// hand-off advisory stays silent rather than reporting from an analysis
/// that cannot see the file the way PAM does.
pub(crate) fn has_line_continuation(content: &str) -> bool {
    content
        .lines()
        .any(|l| directive(l).trim_end().ends_with('\\'))
}
