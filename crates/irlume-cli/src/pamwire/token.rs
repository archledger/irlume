// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! What a GNOME keyring token needs from the login stacks.
//!
//! A token arm keys the account's login keyring to a random secret only
//! irlume holds, and one line delivers it: the `reseal` session line in the
//! login screen's PAM stack, which hands the token to gnome-keyring once the
//! session is open. Without that line every login leaves the keyring locked,
//! a typed password included, under a secret the user has never seen, and
//! only `irlume keyring forget` from inside a session gets it back.
//!
//! So an arm that would mint a token refuses where no login would deliver it
//! ([`token_delivery_refusal`]), and a disable that removes the line refuses
//! while a token is armed ([`tokens_a_disable_strands`]).

use super::*;

/// Whether a PAM stack carries irlume's `reseal` session line, active.
pub(super) fn delivers_tokens(content: &str) -> bool {
    content.lines().any(|line| {
        irlume_rule(line)
            .is_some_and(|rule| rule.phase == "session" && rule.args.contains(&"reseal"))
    })
}

/// Why a GNOME keyring token armed for `user` would never reach their keyring
/// at login, followed by what to do, or `None` when the active login screen
/// delivers it. GDM's separate fingerprint service must also deliver: current
/// reader availability or enrollment cannot rule out a later fingerprint login.
/// The arm can ask from the user's own session before anything is sealed.
pub(crate) fn token_delivery_refusal(user: &str) -> Option<String> {
    delivery_refusal_with(
        active_display_manager().as_deref(),
        user,
        read_stack,
        autologin::autologin_source,
    )
}

/// The stack PAM reads for `service`: the `/etc/pam.d` file, else the vendor
/// copy. `None` when neither exists.
fn read_stack(service: &str) -> Result<Option<String>, String> {
    for dir in ["/etc/pam.d", "/usr/lib/pam.d"] {
        let path = Path::new(dir).join(service);
        match read_stack_file(&path) {
            Ok(text) => return Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Ok(None)
}

/// Pin the resolved object without opening a device or waiting for a FIFO,
/// then read only a regular file through that descriptor. Follow distro
/// symlinks, including absolute includes; re-opening the pathname after a
/// metadata check would let a replacement bypass the file-type check.
pub(super) fn read_stack_file(path: &Path) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    let meta = pinned.metadata()?;
    if !meta.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PAM stack is not a regular file",
        ));
    }
    if meta.len() > SESSION_STACK_MAX_BYTES as u64 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PAM stack exceeds 64 KiB",
        ));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
    let opened = file.metadata()?;
    if !opened.is_file() || (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PAM stack identity changed",
        ));
    }
    // Metadata is not a read bound: the file can grow or report length zero.
    let mut bytes = Vec::new();
    file.take(SESSION_STACK_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > SESSION_STACK_MAX_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PAM stack exceeds 64 KiB",
        ));
    }
    String::from_utf8(bytes).map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

/// [`token_delivery_refusal`] with the login manager, the stack reader and the
/// autologin reader passed in.
fn delivery_refusal_with(
    dm: Option<&str>,
    user: &str,
    stack: impl Fn(&str) -> Result<Option<String>, String>,
    autologin: impl Fn(&str, &str) -> Result<Option<PathBuf>, String>,
) -> Option<String> {
    let unreadable = |what: String| {
        Some(format!(
            "irlume could not read {what}, so it cannot tell whether a login would deliver \
             a keyring token. Fix that, then arm again"
        ))
    };
    let Some(dm) = dm else {
        return Some(
            "irlume finds no active login manager here, and a keyring token is delivered \
             only through the login screen irlume wires. Arm once one is active"
                .to_string(),
        );
    };
    let (greeter, fp_greeter) = dm_pam_services(dm);
    if !dm_wirable(dm) {
        return Some(format!(
            "irlume does not wire the {dm} login screen, and a keyring token is delivered \
             only through a login screen irlume wires"
        ));
    }
    let check = |greeter: &str| match stack(greeter) {
        Ok(Some(text)) if session_reaches_reseal(&text, &|name| stack(name).ok().flatten()) => None,
        Ok(_) => Some(format!(
            "the {greeter} login stack has no provably reached irlume reseal session line. \
                 A missing line, a session control that can skip it, or an unreadable or \
                 unsupported included stack can leave the keyring locked. Run \
                 `sudo irlume login enable --apply` and check the session stack before arming"
        )),
        Err(e) => unreadable(e),
    };
    // Both the normal greeter and GDM's separate fingerprint conversation can
    // open the session. An enrolled reader can return without any PAM or
    // enrollment change, so no current fingerprint observation waives this.
    if let Some(why) = check(greeter) {
        return Some(why);
    }
    if let Some(fp) = fp_greeter {
        if let Some(why) = check(fp) {
            return Some(why);
        }
    }
    match autologin(dm, user) {
        Ok(None) => None,
        Ok(Some(path)) => Some(format!(
            "{dm} logs '{user}' in automatically ({}). An automatic login asks for nothing, \
             so irlume releases no token there and the keyring would stay locked. Turn \
             automatic login off, then arm again",
            path.display()
        )),
        Err(e) => unreadable(e),
    }
}

/// Whether the stack at `path` carries irlume's `reseal` line. One that
/// exists and cannot be read counts: it may carry one.
fn stack_delivers(path: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(text) => delivers_tokens(&text),
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// The token holders a run strands that leaves the stacks at `dropping`
/// without irlume's lines: every holder when one of them is on the login
/// path and delivers a token now, none otherwise.
pub(super) fn tokens_stranded_by(dropping: &[&str]) -> Result<Vec<String>, String> {
    tokens_stranded_with(
        removes_delivery(dropping, login_path_stacks().as_deref(), stack_delivers),
        crate::uninstall::root_sealed_token_holders,
    )
}

/// The stacks a login goes through: the active login manager's greeter and
/// its fingerprint service. `None` when no known login manager is active, so
/// every stack counts.
fn login_path_stacks() -> Option<Vec<String>> {
    let dm = active_display_manager()?;
    let (greeter, fingerprint) = dm_pam_services(&dm);
    if greeter == "(unknown)" {
        return None;
    }
    Some(
        std::iter::once(greeter)
            .chain(fingerprint)
            .map(|service| format!("/etc/pam.d/{service}"))
            .collect(),
    )
}

/// Whether leaving the stacks at `dropping` without irlume's lines removes a
/// delivery that matters: one of them delivers a token now and is on the
/// login path (`login_path`, or any when unknown). A stack of a login manager
/// that is not running delivers nothing to anyone.
fn removes_delivery(
    dropping: &[&str],
    login_path: Option<&[String]>,
    delivers: impl Fn(&str) -> bool,
) -> bool {
    dropping.iter().any(|path| {
        login_path.is_none_or(|stacks| stacks.iter().any(|stack| stack == path)) && delivers(path)
    })
}

/// The accounts whose GNOME keyring token a disable would leave with no
/// delivery: every token holder when some login stack carries irlume's
/// `reseal` line, none when no stack does. An envelope store that cannot be
/// read is an error, never "none", as in `irlume uninstall`.
pub(crate) fn tokens_a_disable_strands() -> Result<Vec<String>, String> {
    let all: Vec<&str> = GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .map(|s| s.etc)
        .collect();
    tokens_stranded_by(&all)
}

/// [`tokens_a_disable_strands`] for a rollback: every token holder when a
/// stack it restores carries irlume's `reseal` line now and would not after
/// (its recorded before-state lacks one, or the file did not exist). A stack
/// that exists and cannot be read counts as carrying one.
pub(crate) fn tokens_a_restore_strands<'a>(
    restores: impl IntoIterator<Item = (&'a Path, Option<&'a str>)>,
) -> Result<Vec<String>, String> {
    let login_path = login_path_stacks();
    let loses_one = restores.into_iter().any(|(path, before)| {
        let on_path = login_path
            .as_ref()
            .is_none_or(|stacks| stacks.iter().any(|stack| Path::new(stack) == path));
        let now = match std::fs::read_to_string(path) {
            Ok(text) => delivers_tokens(&text),
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        };
        on_path && now && !before.is_some_and(delivers_tokens)
    });
    tokens_stranded_with(loses_one, crate::uninstall::root_sealed_token_holders)
}

fn tokens_stranded_with(
    removes_delivery: bool,
    holders: impl FnOnce() -> Result<Vec<String>, String>,
) -> Result<Vec<String>, String> {
    if !removes_delivery {
        return Ok(Vec::new());
    }
    holders()
}

/// The lines a refused run prints: whose keyring, and the two ways on.
pub(super) fn stranded_lines(users: &[String]) -> [String; 2] {
    [
        format!(
            "[login] refusing: the login keyring of {} is keyed to an irlume-held token, and \
             this run removes the session line that delivers it. After it, the keyring would \
             stay locked at every login, a typed password included.",
            users.join(", ")
        ),
        "[login] Have each of these users run `irlume keyring forget` in their own session \
         first (it re-keys the keyring back to their password), or re-run with --force to go \
         ahead anyway."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIRED: &str = "auth     substack      password-auth\n\
        session  include       password-auth\n\
        session    optional                     pam_irlume.so reseal\n";

    fn never(_: &str, _: &str) -> Result<Option<PathBuf>, String> {
        Ok(None)
    }

    #[test]
    fn hotplug_or_a_different_reader_cannot_waive_gdm_fingerprint_delivery() {
        // A returning enrolled reader and a connected empty reader can both
        // coexist with a listing that currently reports no usable prints.
        // Neither observation can authorize a permanently token-keyed wallet.
        // The PAM file may be missing, or installed but unwired while the
        // connected reader has no prints and an enrolled one is disconnected.
        for fingerprint_stack in [None, Some("session optional pam_unix.so\n")] {
            let stacks = |name: &str| {
                Ok(match name {
                    "gdm-password" => Some("session optional pam_irlume.so reseal\n".to_string()),
                    "gdm-fingerprint" => fingerprint_stack.map(str::to_string),
                    _ => panic!("unexpected stack {name}"),
                })
            };
            assert!(
                delivery_refusal_with(Some("gdm"), "alice", stacks, never).is_some(),
                "fingerprint stack {fingerprint_stack:?} waived delivery"
            );
        }
    }

    #[test]
    fn exhausted_session_depth_never_calls_the_reader_again() {
        let calls = std::cell::Cell::new(0);
        let read = |_: &str| {
            calls.set(calls.get() + 1);
            Some("session include cycle\n".to_string())
        };
        assert!(!session_reaches_reseal("session include cycle\n", &read));
        assert_eq!(
            calls.get(),
            4,
            "reader invoked beyond the four include levels"
        );
    }

    #[test]
    fn duplicate_includes_and_empty_files_consume_the_read_budget() {
        let calls = std::cell::Cell::new(0);
        let read = |_: &str| {
            calls.set(calls.get() + 1);
            Some(String::new())
        };
        let text = format!(
            "{}session optional pam_irlume.so reseal\n",
            "@include empty\n".repeat(65)
        );
        assert!(!session_reaches_reseal(&text, &read));
        assert_eq!(calls.get(), 64);
        calls.set(0);
        assert!(session_reaches_reseal(
            &text.replacen("@include empty\n", "", 1),
            &read
        ));
        assert_eq!(calls.get(), 64);
    }

    #[test]
    fn exhausted_session_graph_never_calls_the_reader() {
        let text = format!("{}@include unread\n", "\n".repeat(4095));
        assert!(!session_reaches_reseal(&text, &|_| panic!(
            "graph exhausted before read"
        )));
    }

    struct StackFixture(PathBuf);

    impl StackFixture {
        fn new(tag: &str) -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("irlume-token-{tag}-{}-{stamp}", std::process::id()));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for StackFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn file_backed_absolute_include_and_distro_symlink_deliver() {
        let fixture = StackFixture::new("absolute");
        let target = fixture.0.join("system-login");
        std::fs::write(&target, "session optional pam_irlume.so reseal\n").unwrap();
        let link = fixture.0.join("linked-login");
        std::os::unix::fs::symlink("system-login", &link).unwrap();
        for path in [target, link] {
            let root = format!("session include {}\n", path.display());
            let stack = |name: &str| {
                if name == "sddm" {
                    Ok(Some(root.clone()))
                } else {
                    read_stack(name)
                }
            };
            assert_eq!(
                delivery_refusal_with(Some("sddm"), "alice", stack, never),
                None
            );
        }
    }

    #[test]
    fn stack_reader_rejects_oversize_files_before_parsing() {
        let fixture = StackFixture::new("oversize");
        let path = fixture.0.join("stack");
        std::fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert!(read_stack(path.to_str().unwrap()).is_err());
        let text = format!(
            "session include {}\nsession optional pam_irlume.so reseal\n",
            path.display()
        );
        assert!(!session_reaches_reseal(&text, &|name| read_stack(name)
            .ok()
            .flatten()));

        // The exact byte ceiling remains supported; bad UTF-8 does not.
        let mut text = "session optional pam_irlume.so reseal\n#".to_string();
        text.push_str(&"x".repeat(64 * 1024 - text.len()));
        std::fs::write(&path, &text).unwrap();
        assert_eq!(read_stack(path.to_str().unwrap()).unwrap(), Some(text));
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_stack(path.to_str().unwrap()).is_err());
    }

    #[test]
    #[ignore = "child of stack_reader_refuses_special_files_without_waiting"]
    fn stack_reader_special_file_child() {
        let path = std::env::var("IRLUME_TOKEN_SPECIAL_FIXTURE").unwrap();
        assert!(read_stack(&path).is_err(), "accepted special file {path}");
        let text = format!("session include {path}\nsession optional pam_irlume.so reseal\n");
        assert!(!session_reaches_reseal(&text, &|name| read_stack(name)
            .ok()
            .flatten()));
    }

    #[test]
    fn stack_reader_refuses_special_files_without_waiting() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let fixture = StackFixture::new("special");
        let fifo = fixture.0.join("fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let link = fixture.0.join("device-link");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        let mut failures = Vec::new();
        for path in [fifo, link, PathBuf::from("/dev/null"), fixture.0.clone()] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "pamwire::token::tests::stack_reader_special_file_child",
                ])
                .env("IRLUME_TOKEN_SPECIAL_FIXTURE", &path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
                failures.push(format!("{} blocked", path.display()));
            }
            let output = child.wait_with_output().unwrap();
            if !output.status.success()
                || !String::from_utf8_lossy(&output.stdout).contains("1 passed;")
            {
                failures.push(format!(
                    "{}: {}",
                    path.display(),
                    String::from_utf8_lossy(&output.stdout)
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn arm_refuses_a_session_short_circuit_before_reseal() {
        for control in [
            "sufficient",
            "[success=done default=ignore]",
            "[success=1 default=ignore]",
        ] {
            let text =
                format!("session {control} pam_permit.so\nsession optional pam_irlume.so reseal\n");
            let stack = |_: &str| Ok(Some(text.clone()));
            assert!(
                delivery_refusal_with(Some("sddm"), "alice", stack, never).is_some(),
                "{control}"
            );
        }
    }

    #[test]
    fn arm_refuses_an_included_session_short_circuit() {
        let stack = |name: &str| {
            let text = match name {
                "sddm" => "session include common-session\nsession optional pam_irlume.so reseal\n",
                "common-session" => "session sufficient pam_permit.so\n",
                _ => panic!("unexpected stack {name}"),
            };
            Ok(Some(text.to_string()))
        };
        assert!(delivery_refusal_with(Some("sddm"), "alice", stack, never).is_some());
    }

    #[test]
    fn session_delivery_models_includes_substacks_and_jumps() {
        let reseal = "session optional pam_irlume.so reseal\n";
        let nested = |name: &str| match name {
            "safe" => Some("session required pam_unix.so\n".to_string()),
            "done" => Some("session sufficient pam_permit.so\n".to_string()),
            "jump" => Some("session [success=1 default=ignore] pam_permit.so\n".to_string()),
            "token" => Some(reseal.to_string()),
            "nested" => Some("@include token\n".to_string()),
            "cycle" => Some("session include cycle\n".to_string()),
            "malformed" => Some("session optional pam_permit.so\0\n".to_string()),
            _ => None,
        };
        for (prefix, expected) in [
            ("session required pam_unix.so\n", true),
            ("auth sufficient pam_permit.so\n", true),
            ("session include safe\n", true),
            ("@include safe\n", true),
            ("session include done\n", false),
            ("@include done\n", false),
            ("session include jump\n", false),
            ("session substack done\n", true),
            ("session substack jump\n", true),
            (
                "session [success=1 default=ignore] pam_permit.so\nsession substack done\n",
                true,
            ),
            (
                "session [success=1 default=ignore] pam_permit.so\nsession include safe\n",
                true,
            ),
            (
                "session [success=2 default=ignore] pam_permit.so\nsession substack safe\n",
                false,
            ),
            (
                "session [success=done success=ok default=ignore] pam_permit.so\n",
                true,
            ),
            (
                "session [default=done default=ignore] pam_permit.so\n",
                false,
            ),
            (
                "session [default=ignore default=done] pam_permit.so\n",
                true,
            ),
            ("session requisite pam_unix.so\n", false),
            (
                "session [success=reset default=ignore] pam_permit.so\n",
                true,
            ),
            ("session include missing\n", false),
            ("session substack missing\n", false),
            ("@include cycle\n", false),
            ("session include malformed\n", false),
            ("session [success=bogus] pam_permit.so\n", false),
            ("session optional\n", false),
            ("session optional pam_permit.so\\\n", false),
            ("session optional pam_permit.so\r\n", false),
        ] {
            assert_eq!(
                session_reaches_reseal(&format!("{prefix}{reseal}"), &nested),
                expected,
                "{prefix:?}"
            );
        }
        assert!(session_reaches_reseal("session include token\n", &nested));
        assert!(session_reaches_reseal("@include nested\n", &nested));
        assert!(session_reaches_reseal("session substack token\n", &nested));
        assert!(!session_reaches_reseal("session substack done\n", &nested));
        assert!(!session_reaches_reseal(
            "session [success=1 default=ignore] pam_permit.so\nsession substack token\n",
            &nested
        ));
        assert!(session_reaches_reseal(
            &format!("{reseal}session sufficient pam_permit.so\n"),
            &nested
        ));
        assert!(!session_reaches_reseal(
            &format!(
                "{}{reseal}",
                "session optional pam_permit.so\n".repeat(4096)
            ),
            &nested
        ));
        assert!(!session_reaches_reseal(
            "# session optional pam_irlume.so reseal\n",
            &nested
        ));
    }

    #[test]
    fn gdm_fingerprint_delivery_is_required_for_each_account() {
        for user in ["alice", "bob"] {
            let stack = |name: &str| {
                Ok((name == "gdm-password")
                    .then(|| "session optional pam_irlume.so reseal\n".to_string()))
            };
            let refusal = delivery_refusal_with(Some("gdm"), user, stack, never)
                .expect("missing fingerprint delivery");
            assert!(refusal.contains("gdm-fingerprint"), "{refusal}");
        }
    }

    #[test]
    fn fingerprint_delivery_proof_is_required_only_for_the_separate_service() {
        let wired = "session optional pam_irlume.so reseal\n";
        let all = |_: &str| Ok(Some(wired.to_string()));
        assert_eq!(
            delivery_refusal_with(Some("gdm"), "alice", all, never),
            None
        );
        assert_eq!(
            delivery_refusal_with(Some("sddm"), "alice", all, never),
            None
        );
        for bad in [
            None,
            Some("session sufficient pam_permit.so\nsession optional pam_irlume.so reseal\n"),
        ] {
            let stack = |name: &str| match name {
                "gdm-password" => Ok(Some(wired.to_string())),
                "gdm-fingerprint" => Ok(bad.map(str::to_string)),
                _ => panic!("unexpected stack {name}"),
            };
            assert!(delivery_refusal_with(Some("gdm"), "alice", stack, never).is_some());
        }
        let unread = |name: &str| {
            if name == "gdm-password" {
                Ok(Some(wired.to_string()))
            } else {
                Err("gdm-fingerprint unreadable".to_string())
            }
        };
        assert!(delivery_refusal_with(Some("gdm"), "alice", unread, never).is_some());
    }

    #[test]
    fn only_an_active_session_reseal_line_delivers() {
        assert!(delivers_tokens(WIRED));
        assert!(delivers_tokens(&format!(
            "session optional pam_irlume.so reseal\n{RESEAL_SESSION}\n"
        )));
        assert!(!delivers_tokens(
            "auth optional pam_irlume.so reseal\nsession include password-auth\n"
        ));
        assert!(!delivers_tokens("#session optional pam_irlume.so reseal\n"));
        assert!(!delivers_tokens(
            "session [default=ignore] pam_permit.so # irlume-inert reseal\n"
        ));
        assert!(!delivers_tokens("session optional pam_irlume.so\n"));
    }

    #[test]
    fn an_arm_needs_a_delivering_greeter_and_no_autologin() {
        let wired = |name: &str| {
            Ok(Some(if name == "password-auth" {
                "session required pam_unix.so\n".to_string()
            } else {
                WIRED.to_string()
            }))
        };
        assert_eq!(
            delivery_refusal_with(Some("gdm"), "alice", wired, never),
            None
        );

        let refusal = delivery_refusal_with(None, "alice", wired, never).expect("no DM");
        assert!(refusal.contains("no active login manager"), "{refusal}");

        let refusal = delivery_refusal_with(Some("xdm"), "alice", wired, never).expect("unknown");
        assert!(refusal.contains("does not wire the xdm"), "{refusal}");

        // The default guided flow on main: arm before `login enable`.
        let unwired = |_: &str| Ok(Some("session include password-auth\n".to_string()));
        let refusal = delivery_refusal_with(Some("gdm"), "alice", unwired, never).expect("unwired");
        assert!(
            refusal.contains(
                "gdm-password login stack has no provably reached irlume reseal session line"
            ) && refusal.contains("sudo irlume login enable --apply"),
            "{refusal}"
        );
        let absent = |_: &str| Ok(None);
        assert!(delivery_refusal_with(Some("sddm"), "alice", absent, never).is_some());

        let broken = |_: &str| Err("/etc/pam.d/sddm: Permission denied".to_string());
        let refusal = delivery_refusal_with(Some("sddm"), "alice", broken, never).expect("unread");
        assert!(
            refusal.contains("could not read /etc/pam.d/sddm"),
            "{refusal}"
        );

        let automatic = |dm: &str, user: &str| {
            assert_eq!((dm, user), ("gdm", "alice"));
            Ok(Some(PathBuf::from("/etc/gdm/custom.conf")))
        };
        let refusal =
            delivery_refusal_with(Some("gdm"), "alice", wired, automatic).expect("autologin");
        assert!(
            refusal.contains("gdm logs 'alice' in automatically (/etc/gdm/custom.conf)"),
            "{refusal}"
        );
        let unknown = |_: &str, _: &str| Err("/etc/sddm.conf: Permission denied".to_string());
        let refusal =
            delivery_refusal_with(Some("sddm"), "alice", wired, unknown).expect("unknown");
        assert!(
            refusal.contains("could not read /etc/sddm.conf"),
            "{refusal}"
        );
    }

    #[test]
    fn only_a_stack_on_the_login_path_counts() {
        let delivers = |path: &str| path != "/etc/pam.d/quiet";
        let path = ["/etc/pam.d/gdm-password".to_string()];
        // Dropping an inactive login manager's stack strands nothing.
        assert!(!removes_delivery(
            &["/etc/pam.d/sddm"],
            Some(&path),
            delivers
        ));
        assert!(removes_delivery(
            &["/etc/pam.d/sddm", "/etc/pam.d/gdm-password"],
            Some(&path),
            delivers
        ));
        // With no login manager known, every stack counts.
        assert!(removes_delivery(&["/etc/pam.d/sddm"], None, delivers));
        assert!(!removes_delivery(&["/etc/pam.d/quiet"], None, delivers));
    }

    #[test]
    fn a_disable_strands_holders_only_when_a_stack_delivers() {
        let holders = || Ok(vec!["alice".to_string()]);
        assert_eq!(
            tokens_stranded_with(true, holders),
            Ok(vec!["alice".to_string()])
        );
        // Nothing to remove, so the store is not even read.
        let unread = || -> Result<Vec<String>, String> { panic!("store read") };
        assert_eq!(tokens_stranded_with(false, unread), Ok(Vec::new()));
        let broken = || Err("keyring: Permission denied".to_string());
        assert_eq!(
            tokens_stranded_with(true, broken),
            Err("keyring: Permission denied".to_string())
        );
        let [what, how] = stranded_lines(&["alice".to_string(), "bob".to_string()]);
        assert!(what.contains("keyring of alice, bob"), "{what}");
        assert!(
            how.contains("irlume keyring forget") && how.contains("--force"),
            "{how}"
        );
    }
}
