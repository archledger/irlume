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
