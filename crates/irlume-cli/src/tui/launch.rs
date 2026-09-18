// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Launch-time concerns of `irlume tui`: argument parsing for the start
//! page, and the single-instance guard.
//!
//! The guard exists so that launching the TUI repeatedly (from the
//! application menu, or from the System Settings module's buttons) cannot
//! pile up terminals: the first instance holds a kernel `flock` and a
//! handoff listener; later instances hand their start page to it and exit.
//! The channel is navigate-only by construction: the accepted message
//! vocabulary is `goto:<page>` and `focus:`, and nothing else.

use super::{
    SC_CAMERAS, SC_FINGERPRINT, SC_IDENTIFY, SC_KEYRING, SC_PAM, SC_PROFILES, SC_RECOVERY,
    SC_REPAIR, SC_SETTINGS, SC_WELCOME,
};
use std::os::unix::net::UnixListener;

/// CLI page names, mapped to screen indices. The names the System Settings
/// module's launch buttons use (`faces`, `cameras`, `wallet`, `recovery`,
/// `diagnostics`) are the load-bearing subset; the rest complete the
/// registry so every screen is reachable.
pub(crate) fn resolve_page(name: &str) -> Option<usize> {
    match name {
        "overview" => Some(SC_WELCOME),
        "diagnostics" => Some(SC_REPAIR),
        "cameras" => Some(SC_CAMERAS),
        "faces" => Some(SC_PROFILES),
        "identify" => Some(SC_IDENTIFY),
        "wallet" => Some(SC_KEYRING),
        "recovery" => Some(SC_RECOVERY),
        "fingerprint" => Some(SC_FINGERPRINT),
        "login" => Some(SC_PAM),
        "settings" => Some(SC_SETTINGS),
        _ => None,
    }
}

/// Every accepted page name, for usage text and tests.
pub(crate) const PAGE_NAMES: [&str; 10] = [
    "overview",
    "diagnostics",
    "cameras",
    "faces",
    "identify",
    "wallet",
    "recovery",
    "fingerprint",
    "login",
    "settings",
];

/// Parsed launch arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LaunchOptions {
    /// Screen index to start on, from `--page`.
    pub(crate) page: Option<usize>,
    /// `--new`: skip the single-instance guard entirely.
    pub(crate) new_instance: bool,
}

fn usage() -> String {
    format!(
        "usage: irlume tui [--user NAME] [--page PAGE] [--new]\n  pages: {}",
        PAGE_NAMES.join(", ")
    )
}

/// Parses `irlume tui` arguments. `--user` is consumed elsewhere but must
/// be tolerated here so unknown-flag detection does not fire on it.
pub(crate) fn parse_launch(args: &[String]) -> Result<LaunchOptions, String> {
    let mut parsed = LaunchOptions::default();
    let mut idx = 0;
    while idx < args.len() {
        let arg = args[idx].as_str();
        let (flag, inline_value) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (arg, None),
        };
        match flag {
            "--user" => {
                if inline_value.is_some() {
                    idx += 1;
                } else {
                    // Consume the value only when it cannot be a flag: an
                    // option-looking token stays for its own parsing, and a
                    // dangling `--user` is reported by the user-argument
                    // parser itself, not here.
                    match args.get(idx + 1) {
                        Some(value) if !value.starts_with('-') => idx += 2,
                        _ => idx += 1,
                    }
                }
            }
            "--page" => {
                let name = match inline_value {
                    Some(name) => {
                        idx += 1;
                        name
                    }
                    None => match args.get(idx + 1) {
                        Some(name) => {
                            idx += 2;
                            name
                        }
                        None => return Err(usage()),
                    },
                };
                let Some(page) = resolve_page(name) else {
                    return Err(format!("unknown page '{name}'\n{}", usage()));
                };
                parsed.page = Some(page);
            }
            "--new" => {
                parsed.new_instance = true;
                idx += 1;
            }
            _ => return Err(format!("unknown argument '{arg}'\n{}", usage())),
        }
    }
    Ok(parsed)
}

/// The CLI name of a screen index, for handoff messages.
pub(crate) fn page_name(page: usize) -> Option<&'static str> {
    let name = match page {
        SC_WELCOME => "overview",
        SC_REPAIR => "diagnostics",
        SC_CAMERAS => "cameras",
        SC_PROFILES => "faces",
        SC_IDENTIFY => "identify",
        SC_KEYRING => "wallet",
        SC_RECOVERY => "recovery",
        SC_FINGERPRINT => "fingerprint",
        SC_PAM => "login",
        SC_SETTINGS => "settings",
        _ => return None,
    };
    Some(name)
}

/// The one-line handoff message for a start request.
pub(crate) fn handoff_message(page: Option<usize>) -> String {
    match page.and_then(page_name) {
        Some(name) => format!("goto:{name}\n"),
        None => "focus:\n".to_string(),
    }
}

/// What a received handoff message may do: navigate, or nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Navigation {
    Goto(usize),
    Focus,
}

/// Parses a received handoff message. Anything outside the navigate-only
/// vocabulary is rejected (`None`): the channel must never grow abilities.
pub(crate) fn parse_handoff(msg: &str) -> Option<Navigation> {
    let line = msg.strip_suffix('\n')?;
    if line.contains('\n') || line.contains('\0') {
        return None;
    }
    let (verb, arg) = line.split_once(':')?;
    match verb {
        "goto" => resolve_page(arg).map(Navigation::Goto),
        "focus" if arg.is_empty() => Some(Navigation::Focus),
        _ => None,
    }
}

/// Outcome of trying to become the single TUI instance.
#[derive(Debug)]
pub(crate) enum GuardOutcome {
    /// We hold the lock and the handoff listener is bound. Dropping the
    /// returned guard releases both (kernel-owned lifetimes).
    Acquired(Guard),
    /// Another instance holds the lock and accepted the handoff; print the
    /// message and exit successfully without starting a TUI.
    HandedOff(String),
    /// The lock is held but no listener answered: proceed WITHOUT the guard
    /// (never refuse to start over a UX lock).
    ProceedWithoutLock(String),
    /// Guard disabled (`--new`, or no runtime directory).
    Disabled,
}

/// The held lock plus the bound listener.
#[derive(Debug)]
pub(crate) struct Guard {
    // Field order matters: the listener closes first, then the flock file.
    listener: UnixListener,
    _file: std::fs::File,
}

impl Guard {
    pub(crate) fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

/// Filesystem-safe encoding of the TARGET ACCOUNT the TUI manages. The
/// guard is keyed by it, not just the uid: `irlume tui --user bob` while a
/// TUI for alice runs is a separate instance, not a handoff to alice's
/// window.
fn target_key(user: &str) -> String {
    let mut key = String::with_capacity(user.len());
    for ch in user.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            key.push(ch);
        } else {
            key.push('_');
        }
    }
    if key.is_empty() {
        key.push('_');
    }
    key
}

/// The lock file path under the (per-user, 0700) runtime directory, keyed
/// by the target account.
fn guard_paths(runtime_dir: &std::path::Path, user: &str) -> std::path::PathBuf {
    runtime_dir
        .join("irlume")
        .join(format!("tui-{}.lock", target_key(user)))
}

/// The abstract socket name carrying the current uid and the target
/// account, so neither users nor target accounts collide. Abstract names
/// have no permission bits; `peer_is_self` on accept is the access control.
fn abstract_name(user: &str) -> String {
    // SAFETY: getuid cannot fail and touches no memory.
    let uid = unsafe { libc::getuid() };
    format!("irlume-tui-{uid}-{}", target_key(user))
}

fn connect_handoff_listener(user: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    // SAFETY: getuid cannot fail and touches no memory.
    let uid = unsafe { libc::getuid() };
    let _ = uid;
    let addr = SocketAddr::from_abstract_name(abstract_name(user).as_bytes())
        .map_err(std::io::Error::other)?;
    let stream = UnixStream::connect_addr(&addr)?;
    // The listener accepts only same-uid peers; that check lives there.
    // This side only sends.
    Ok(stream)
}

/// Sends the handoff message to the running instance for this same target
/// account, retrying briefly: the holder may be between taking the lock
/// and binding the listener.
fn try_handoff(user: &str, message: &str) -> Result<(), ()> {
    use std::io::Write;
    for attempt in 0..3 {
        if let Ok(mut stream) = connect_handoff_listener(user) {
            if stream.write_all(message.as_bytes()).is_ok() {
                let _ = stream.flush();
                return Ok(());
            }
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(60));
        }
    }
    Err(())
}

/// Tries to become the single TUI instance for `user` (the TARGET ACCOUNT
/// the TUI manages, not just the invoking uid) under
/// `$XDG_RUNTIME_DIR/irlume`.
pub(crate) fn acquire_guard(user: &str, page: Option<usize>, new_instance: bool) -> GuardOutcome {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::DirBuilderExt;
    if new_instance {
        return GuardOutcome::Disabled;
    }
    let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from)
    else {
        return GuardOutcome::Disabled;
    };

    let guard_dir = guard_paths(&runtime_dir, user)
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| runtime_dir.clone());
    let made = std::fs::DirBuilder::new().mode(0o700).create(&guard_dir);
    if let Err(error) = made {
        // An existing directory (created by an earlier run at 0700) is the
        // ordinary case, not a failure.
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return GuardOutcome::ProceedWithoutLock(format!(
                "guard directory unavailable ({error}); starting without the single-instance guard"
            ));
        }
    }

    let lock_path = guard_paths(&runtime_dir, user);
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(error) => {
            return GuardOutcome::ProceedWithoutLock(format!(
                "guard lock unavailable ({error}); starting without the single-instance guard"
            ));
        }
    };
    // The lock file holds no secrets; pin its mode anyway so a permissive
    // umask cannot advertise an irlume-owned writable file.
    let _ = std::fs::set_permissions(
        &lock_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );

    // SAFETY: fd is owned by `file` and outlives the call.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        // Someone else is (or was) the single instance for this target
        // account: hand off to it.
        drop(file);
        let message = handoff_message(page);
        let handed = try_handoff(user, &message);
        let target = page.and_then(page_name).unwrap_or("the running instance");
        return match handed {
            Ok(()) => GuardOutcome::HandedOff(format!(
                "irlume TUI is already running; switching it to {target}"
            )),
            Err(()) => GuardOutcome::ProceedWithoutLock(
                "another irlume TUI holds the lock but did not answer; starting anyway".into(),
            ),
        };
    }

    match bind_listener(user) {
        Ok(listener) => GuardOutcome::Acquired(Guard {
            listener,
            _file: file,
        }),
        Err(error) => GuardOutcome::ProceedWithoutLock(format!(
            "handoff listener unavailable ({error}); starting without the single-instance guard"
        )),
    }
}

fn bind_listener(user: &str) -> std::io::Result<UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;
    let addr = SocketAddr::from_abstract_name(abstract_name(user).as_bytes())
        .map_err(std::io::Error::other)?;
    UnixListener::bind_addr(&addr)
}

/// Whether a connecting peer's credentials match the given user. The
/// abstract namespace has no permission bits; this check on accept is the
/// access control.
pub(crate) fn peer_is_self(uid: libc::uid_t, creds_uid: libc::uid_t) -> bool {
    uid == creds_uid
}

/// Reads a connected peer's uid with `SO_PEERCRED` (the same kernel answer
/// the daemon's socket authorization uses; std's `UCred` fields are not
/// stable) and reports whether it is the current user.
pub(crate) fn stream_peer_is_self(stream: &std::os::unix::net::UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid fd; ucred/len out-params are correctly sized.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return false;
    }
    // SAFETY: takes no arguments, reads only this process's own
    // credentials, and is specified as always succeeding.
    let self_uid = unsafe { libc::getuid() };
    peer_is_self(self_uid, ucred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn parse_launch_defaults_with_no_args() {
        let parsed = parse_launch(&[]).expect("no args parse");
        assert_eq!(
            parsed,
            LaunchOptions {
                page: None,
                new_instance: false
            }
        );
    }

    #[test]
    fn parse_launch_reads_page_in_both_forms() {
        for form in [argv(&["--page", "faces"]), argv(&["--page=faces"])] {
            let parsed = parse_launch(&form).expect("page parses");
            assert_eq!(parsed.page, Some(SC_PROFILES), "{form:?}");
        }
    }

    #[test]
    fn parse_launch_rejects_unknown_page_by_name() {
        let err = parse_launch(&argv(&["--page", "bogus"])).expect_err("unknown page rejected");
        assert!(err.contains("faces"), "usage names valid pages: {err}");
    }

    #[test]
    fn parse_launch_rejects_dangling_page() {
        assert!(parse_launch(&argv(&["--page"])).is_err());
    }

    #[test]
    fn parse_launch_rejects_unknown_flags() {
        assert!(parse_launch(&argv(&["--rounds", "3"])).is_err());
    }

    #[test]
    fn parse_launch_tolerates_user_forms() {
        for form in [argv(&["--user", "carol"]), argv(&["--user=carol"])] {
            assert!(parse_launch(&form).is_ok(), "{form:?}");
        }
    }

    #[test]
    fn parse_launch_never_consumes_an_option_looking_user_value() {
        // `--user --new` must not swallow `--new` as the account name: the
        // flags still parse, and the dangling `--user` is reported by the
        // user-argument parser itself (same as every other subcommand).
        let parsed = parse_launch(&argv(&["--user", "--new"])).expect("flags parse");
        assert!(parsed.new_instance, "{parsed:?}");
        let parsed = parse_launch(&argv(&["--user", "--page=faces"])).expect("flags parse");
        assert_eq!(parsed.page, Some(SC_PROFILES), "{parsed:?}");
    }

    #[test]
    fn parse_launch_accepts_new() {
        let parsed = parse_launch(&argv(&["--new"])).expect("--new parses");
        assert!(parsed.new_instance);
    }

    #[test]
    fn resolve_page_maps_every_name_to_its_screen() {
        let expected = [
            ("overview", SC_WELCOME),
            ("diagnostics", SC_REPAIR),
            ("cameras", SC_CAMERAS),
            ("faces", SC_PROFILES),
            ("identify", SC_IDENTIFY),
            ("wallet", SC_KEYRING),
            ("recovery", SC_RECOVERY),
            ("fingerprint", SC_FINGERPRINT),
            ("login", SC_PAM),
            ("settings", SC_SETTINGS),
        ];
        for (name, screen) in expected {
            assert_eq!(resolve_page(name), Some(screen), "{name}");
        }
        assert_eq!(resolve_page("nope"), None);
        assert_eq!(PAGE_NAMES.len(), 10);
    }

    #[test]
    fn handoff_message_names_the_page_or_focuses() {
        assert_eq!(handoff_message(Some(SC_PROFILES)), "goto:faces\n");
        assert_eq!(handoff_message(None), "focus:\n");
    }

    #[test]
    fn parse_handoff_accepts_only_navigation() {
        assert_eq!(
            parse_handoff("goto:cameras\n"),
            Some(Navigation::Goto(SC_CAMERAS))
        );
        assert_eq!(parse_handoff("focus:\n"), Some(Navigation::Focus));
        assert_eq!(parse_handoff("goto:bogus\n"), None);
        assert_eq!(parse_handoff("goto:\n"), None);
        assert_eq!(parse_handoff("enroll:faces\n"), None);
        assert_eq!(parse_handoff("goto:faces goto:cameras\n"), None);
        assert_eq!(parse_handoff(""), None);
        assert_eq!(parse_handoff("\u{0}goto:faces\n"), None);
    }

    #[test]
    fn peer_credentials_must_match_the_current_user() {
        // SAFETY: getuid cannot fail and touches no memory.
        let self_uid = unsafe { libc::getuid() };
        assert!(peer_is_self(self_uid, self_uid));
        assert!(!peer_is_self(self_uid, self_uid.wrapping_add(1)));
    }

    #[test]
    fn guard_hands_off_to_the_running_instance() {
        let _env = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("irlume-tui-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);

        let first = match acquire_guard("test-user", None, false) {
            GuardOutcome::Acquired(g) => g,
            other => panic!("first acquire must succeed: {other:?}"),
        };

        // A TUI for a DIFFERENT target account is a separate instance: no
        // handoff, its own guard.
        assert!(matches!(
            acquire_guard("other-user", Some(SC_PROFILES), false),
            GuardOutcome::Acquired(_)
        ));

        // The second instance for the SAME account hands its page off.
        match acquire_guard("test-user", Some(SC_PROFILES), false) {
            GuardOutcome::HandedOff(msg) => {
                assert!(msg.contains("faces"), "{msg}");
            }
            other => panic!("second acquire must hand off: {other:?}"),
        }

        // The running instance received exactly the navigate-only message.
        use std::io::{Read, Write};
        let (mut client, _meta) = first.listener().accept().unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        let msg = std::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(msg, "goto:faces\n");
        let _ = client.write_all(b"ok");

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&dir);
        drop(first);
    }

    #[test]
    fn guard_falls_back_when_the_lock_is_held_without_a_listener() {
        use std::os::fd::AsRawFd;
        let _env = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("irlume-tui-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);

        // Hold ONLY the flock (a predecessor that never bound a listener).
        std::fs::create_dir_all(dir.join("irlume")).unwrap();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("irlume").join("tui-test-user.lock"))
            .unwrap();
        assert_eq!(
            // SAFETY: fd is owned by `file` and outlives the call.
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        match acquire_guard("test-user", None, false) {
            GuardOutcome::ProceedWithoutLock(msg) => {
                assert!(!msg.is_empty());
            }
            other => panic!("held lock without listener must fall back: {other:?}"),
        }

        std::env::remove_var("XDG_RUNTIME_DIR");
        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guard_disabled_by_new_or_missing_runtime_dir() {
        let _env = crate::testenv::ENV_LOCK.lock().unwrap();
        // Restore whatever the runner had: removing the variable without
        // restoring leaks "no runtime dir" into every later test.
        let saved = std::env::var_os("XDG_RUNTIME_DIR");
        let dir = std::env::temp_dir().join(format!("irlume-tui-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);

        // --new never touches the filesystem.
        assert!(matches!(
            acquire_guard("test-user", None, true),
            GuardOutcome::Disabled
        ));
        assert!(
            !dir.join("irlume").exists(),
            "--new must not create the guard dir"
        );

        // No runtime directory: guard off, same behavior as before.
        std::env::remove_var("XDG_RUNTIME_DIR");
        assert!(matches!(
            acquire_guard("test-user", None, false),
            GuardOutcome::Disabled
        ));

        match saved {
            Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
