// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Per-distro abstraction. A minimal port of linhello's platform layer: just
//! the distro-family detection that the fingerprint (and, later, login) wiring
//! needs to pick the right mechanism (authselect vs pam-auth-update vs direct).

/// Distro family, for choosing the PAM-wiring mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroFamily {
    /// Debian/Ubuntu/Mint: `pam-auth-update` + `/usr/share/pam-configs`.
    Debian,
    /// Fedora/RHEL/derivatives: `authselect` custom profiles.
    Fedora,
    /// Arch/Manjaro/EndeavourOS: edit `/etc/pam.d` services directly.
    Arch,
    /// Anything else: direct `/etc/pam.d` edits, best-effort.
    Other,
}

impl DistroFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            DistroFamily::Debian => "Debian-family",
            DistroFamily::Fedora => "Fedora-family",
            DistroFamily::Arch => "Arch-family",
            DistroFamily::Other => "other/unknown",
        }
    }
}

/// Detect the distro family from `/etc/os-release` (`ID` + `ID_LIKE`).
pub fn distro_family() -> DistroFamily {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    distro_family_from(&os)
}

/// Classify raw `os-release` contents. Split out of [`distro_family`] verbatim
/// (test seam: the parse is exercised against fixture strings without touching
/// the host's `/etc/os-release`); behavior unchanged.
fn distro_family_from(os: &str) -> DistroFamily {
    let field = |key: &str| -> String {
        os.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .unwrap_or_default()
    };
    let id = field("ID=");
    let like = field("ID_LIKE=");
    let hay = format!("{id} {like}");
    if ["debian", "ubuntu", "mint", "pop", "raspbian"]
        .iter()
        .any(|d| hay.contains(d))
    {
        DistroFamily::Debian
    } else if ["fedora", "rhel", "centos", "rocky", "alma"]
        .iter()
        .any(|d| hay.contains(d))
    {
        DistroFamily::Fedora
    } else if ["arch", "manjaro", "endeavouros", "garuda"]
        .iter()
        .any(|d| hay.contains(d))
    {
        DistroFamily::Arch
    } else {
        DistroFamily::Other
    }
}

/// Best-effort "does this user already have a live login session", the same
/// heuristic the daemon uses for its warm/cold classification: `/run/user/<uid>`
/// exists. The PAM module uses it to distinguish a COLD login (unlock the login
/// keyring: let the auth stack continue so pam_gnome_keyring runs) from a WARM
/// lock-screen unlock (keyring already open: short-circuit). Lingering user
/// services can also create `/run/user/<uid>`; treating that rare case as "warm"
/// is acceptable (worst case: a cold login that skips the keyring-continue).
pub fn user_has_live_session(user: &str) -> bool {
    // Prefer logind: an ACTIVE, `user`-class session. Unlike a bare
    // `/run/user/<uid>` check, this is NOT fooled by a runtime dir that lingers
    // after logout, which otherwise makes a logout→login look "warm" and skip
    // the cold-login keyring unlock. Fall back to `/run/user/<uid>` if logind is
    // unavailable.
    if let Some(active) = active_graphical_session(user) {
        return active;
    }
    uid_for_name(user)
        .map(|uid| std::path::Path::new(&format!("/run/user/{uid}")).exists())
        .unwrap_or(false)
}

/// `Some(active?)` from logind: does `user` own an active/online `user`-class
/// session right now? `None` if `loginctl` is missing/unparsable (→ caller falls
/// back to the runtime-dir heuristic).
fn active_graphical_session(user: &str) -> Option<bool> {
    let out = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // columns: SESSION  UID  USER  SEAT  [TTY…]
        let mut cols = line.split_whitespace();
        let Some(session) = cols.next() else { continue };
        let _uid = cols.next();
        if cols.next() != Some(user) {
            continue;
        }
        if session_is_active_user(session) {
            return Some(true);
        }
    }
    Some(false)
}

/// A greeter session is `Class=greeter`; a real logged-in session is
/// `Class=user`. A logout closes the user session (gone or `closing`), so only a
/// live lock screen leaves an active/online user-class session.
fn session_is_active_user(session: &str) -> bool {
    let Ok(out) = std::process::Command::new("loginctl")
        .args(["show-session", session, "-p", "Class", "-p", "State"])
        .output()
    else {
        return false;
    };
    let t = String::from_utf8_lossy(&out.stdout);
    let val = |k: &str| {
        t.lines()
            .find_map(|l| l.strip_prefix(k))
            .unwrap_or("")
            .trim()
    };
    val("Class=") == "user" && matches!(val("State="), "active" | "online")
}

/// Resolve a user name to its uid via NSS (`getpwnam_r`). `None` if absent.
fn uid_for_name(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; `buf` is sized and owned here;
    // on success `result` points into `pwd`, from which we copy the uid out.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(pwd.pw_uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distro_family_classifies_real_os_release_shapes() {
        // Shapes lifted from real distro os-release files: bare vs quoted
        // values, ID_LIKE chains, derivative IDs.
        let cases: &[(&str, DistroFamily)] = &[
            // Fedora: bare ID, no ID_LIKE.
            (
                "NAME=\"Fedora Linux\"\nVERSION=\"44 (KDE Plasma)\"\nID=fedora\nVERSION_ID=44\n",
                DistroFamily::Fedora,
            ),
            // RHEL and clones: quoted ID, ID_LIKE chain back to fedora.
            (
                "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\n",
                DistroFamily::Fedora,
            ),
            (
                "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
                DistroFamily::Fedora,
            ),
            (
                "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
                DistroFamily::Fedora,
            ),
            // Debian family: Debian itself, Ubuntu (ID_LIKE=debian), Mint
            // (ID=linuxmint, ID_LIKE chains through ubuntu), Pop, Raspbian.
            (
                "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n",
                DistroFamily::Debian,
            ),
            (
                "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n",
                DistroFamily::Debian,
            ),
            (
                "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n",
                DistroFamily::Debian,
            ),
            ("ID=pop\nID_LIKE=\"ubuntu debian\"\n", DistroFamily::Debian),
            ("ID=raspbian\nID_LIKE=debian\n", DistroFamily::Debian),
            // Arch family.
            (
                "NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n",
                DistroFamily::Arch,
            ),
            ("ID=manjaro\nID_LIKE=arch\n", DistroFamily::Arch),
            ("ID=endeavouros\nID_LIKE=arch\n", DistroFamily::Arch),
            ("ID=garuda\nID_LIKE=arch\n", DistroFamily::Arch),
            // Unmatched distros and degenerate input fall through to Other.
            ("NAME=NixOS\nID=nixos\n", DistroFamily::Other),
            (
                "ID=opensuse-tumbleweed\nID_LIKE=\"opensuse suse\"\n",
                DistroFamily::Other,
            ),
            ("", DistroFamily::Other),
            ("NAME=\"Something\"\nVERSION_ID=1\n", DistroFamily::Other),
        ];
        for (os, want) in cases {
            assert_eq!(distro_family_from(os), *want, "input: {os:?}");
        }
    }

    #[test]
    fn distro_family_field_parsing_details() {
        // Uppercase inside a quoted value is lowercased before matching.
        assert_eq!(distro_family_from("ID=\"Ubuntu\"\n"), DistroFamily::Debian);
        // Surrounding whitespace on the value is trimmed.
        assert_eq!(distro_family_from("ID= fedora \n"), DistroFamily::Fedora);
        // ID_LIKE alone (no ID line) still classifies.
        assert_eq!(
            distro_family_from("NAME=Derived\nID_LIKE=debian\n"),
            DistroFamily::Debian
        );
        // `VERSION_ID=` must not be mistaken for `ID=`: a numeric VERSION_ID
        // with an unmatched ID stays Other.
        assert_eq!(
            distro_family_from("VERSION_ID=12\nID=slackware\n"),
            DistroFamily::Other
        );
        // Debian is checked before Fedora/Arch: a hybrid ID_LIKE mentioning
        // both classifies as Debian (pam-auth-update wiring wins).
        assert_eq!(
            distro_family_from("ID=weird\nID_LIKE=\"debian fedora arch\"\n"),
            DistroFamily::Debian
        );
    }

    #[test]
    fn distro_family_as_str_names_each_family() {
        assert_eq!(DistroFamily::Debian.as_str(), "Debian-family");
        assert_eq!(DistroFamily::Fedora.as_str(), "Fedora-family");
        assert_eq!(DistroFamily::Arch.as_str(), "Arch-family");
        assert_eq!(DistroFamily::Other.as_str(), "other/unknown");
    }

    #[test]
    fn distro_family_reads_the_host_os_release() {
        // On any Linux box /etc/os-release (or its absence) must classify
        // without panicking, and agree with feeding the same bytes through the
        // parse seam.
        let host = distro_family();
        let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        assert_eq!(host, distro_family_from(&os));
    }

    #[test]
    fn uid_for_name_resolves_root_and_rejects_garbage() {
        assert_eq!(uid_for_name("root"), Some(0));
        assert_eq!(uid_for_name("no-such-user-irlume-test"), None);
        // Interior NUL cannot become a C string; must be None, not a panic.
        assert_eq!(uid_for_name("a\0b"), None);
    }

    #[test]
    fn nonexistent_user_never_has_a_live_session() {
        // Deterministic on every box: with logind present the bogus user owns
        // no session (Some(false)); without logind the uid lookup fails and the
        // /run/user fallback cannot fire either.
        assert!(!user_has_live_session("no-such-user-irlume-test"));
    }

    #[test]
    fn unknown_session_id_is_not_an_active_user_session() {
        // `loginctl show-session` on a bogus id prints nothing usable; the
        // parser must fail closed (false), never treat it as active.
        assert!(!session_is_active_user("irlume-test-no-such-session"));
    }
}
