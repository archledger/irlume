// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Unlock a user's GNOME login keyring with their sealed keyring token (#250).
//!
//! On a token-armed account the login keyring is keyed to a random token, not
//! the login password, so after a face or fingerprint login (and after a typed
//! password login, whose password no longer opens it) something must hand the
//! token to `gnome-keyring-daemon`. That channel is the daemon's control
//! socket, `$XDG_RUNTIME_DIR/keyring/control`, with the `UNLOCK` operation:
//! the exact channel and operation `pam_gnome_keyring` itself uses.
//!
//! This exists as a separate program for the same reason `irlume-kwallet-init`
//! does: `pam_irlume` is loaded into sshd, login and every greeter, and it has
//! no privilege dropping. The control socket authenticates the peer's uid
//! (`gkr-pam-client.c` does its own seteuid dance for the same reason), so the
//! connection must be made AS the target user, and becoming the user
//! permanently in a short-lived helper keeps the module's blast radius
//! unchanged.
//!
//! Invoked as `irlume-gkr-unlock <username>` with the token on **stdin**,
//! never in argv, which is world-readable through `/proc`. Exit status 0 means
//! the daemon reported the keyring unlocked; anything else is a refusal or an
//! error, printed to stderr.

use irlume_common::gkr_wire::{self, ControlResult, Op};
use std::ffi::CString;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Ceiling on the token read from stdin. The armed token is 64 bytes of hex;
/// the margin tolerates a future longer format without accepting arbitrary
/// stream lengths from a confused caller.
const MAX_TOKEN_LEN: usize = 256;

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(user) = args.next() else {
        eprintln!("usage: irlume-gkr-unlock <username>  (token on stdin)");
        return std::process::ExitCode::from(2);
    };
    let user = user.to_string_lossy().into_owned();

    match run(&user) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("irlume-gkr-unlock: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(user: &str) -> Result<(), String> {
    // Read the token first, before any privilege change, so a malformed
    // invocation fails without side effects.
    let mut token = Vec::with_capacity(MAX_TOKEN_LEN);
    std::io::stdin()
        .take(MAX_TOKEN_LEN as u64 + 1)
        .read_to_end(&mut token)
        .map_err(|e| format!("reading the token from stdin: {e}"))?;
    if token.is_empty() {
        return Err("empty token on stdin".into());
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(format!("token longer than {MAX_TOKEN_LEN} bytes; refusing"));
    }
    // The keyring credential is a string; a token with a NUL or control bytes
    // is not one this program ever produced, so refuse it rather than let a
    // truncated comparison "succeed" somewhere downstream.
    if token.iter().any(|b| !b.is_ascii_graphic()) {
        return Err("token contains non-printable bytes; refusing".into());
    }

    let pw = lookup_user(user)?;
    let runtime_dir = PathBuf::from(format!("/run/user/{}", pw.uid));
    if !runtime_dir.is_dir() {
        return Err(format!(
            "{} does not exist; the session is not far enough along for a keyring",
            runtime_dir.display()
        ));
    }

    // EVERYTHING below runs as the target user: the daemon compares the
    // connecting peer's uid against its own, and root pathname work inside a
    // user-owned directory is the CVE-2018-10380 shape this codebase refuses
    // to repeat.
    drop_privileges(&pw)?;

    let sock = gkr_wire::control_socket_path(&runtime_dir);
    let mut stream = UnixStream::connect(&sock).map_err(|e| {
        format!(
            "connect {}: {e} (no gnome-keyring-daemon control socket; is \
             gnome-keyring installed and socket-activated?)",
            sock.display()
        )
    })?;
    match gkr_wire::call(&mut stream, Op::Unlock, &[&token])? {
        ControlResult::Ok => Ok(()),
        other => Err(format!("keyring UNLOCK: {}", other.describe())),
    }
}

/// Become the target user, permanently. Same order and same paranoia as
/// `irlume-kwallet-init`: groups and gid before uid, then verify the drop
/// took, because a drop that silently failed would leave the control-socket
/// connection coming from root and everything below running with privilege it
/// must not have.
fn drop_privileges(pw: &User) -> Result<(), String> {
    if unsafe { libc::initgroups(pw.name.as_ptr(), pw.gid) } != 0 {
        return Err(format!("initgroups: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::setgid(pw.gid) } != 0 {
        return Err(format!("setgid: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::setuid(pw.uid) } != 0 {
        return Err(format!("setuid: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::getuid() } != pw.uid
        || unsafe { libc::geteuid() } != pw.uid
        || unsafe { libc::getgid() } != pw.gid
        || unsafe { libc::getegid() } != pw.gid
    {
        return Err("privilege drop did not take effect".into());
    }
    Ok(())
}

struct User {
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: CString,
}

fn lookup_user(user: &str) -> Result<User, String> {
    let cname = CString::new(user).map_err(|_| "username contains a NUL".to_string())?;
    // SAFETY: getpwnam returns a pointer into a static buffer, read before any
    // further libc call that could overwrite it.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return Err(format!("no such user: {user}"));
    }
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    if uid == 0 {
        return Err("refusing to unlock a keyring for uid 0".to_string());
    }
    Ok(User {
        uid,
        gid,
        name: cname,
    })
}
