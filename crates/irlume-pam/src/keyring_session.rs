// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Module-side upgrade guard: an old daemon can ignore `auth_phase`.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const OBSERVATION_BUDGET: Duration = Duration::from_millis(250);
const MAX_ENTRIES: usize = 1024;
const MAX_SESSION_BYTES: u64 = 16 * 1024;

/// Permit the auth request only after establishing that the account has no
/// live local desktop. Unknown state withholds this optional release; it never
/// decides authentication. No NSS runs in the PAM process and no runtime-dir
/// heuristic substitutes for explicit logind graphical-session properties.
pub(super) fn auth_release_allowed(user: &str) -> bool {
    let deadline = Instant::now() + OBSERVATION_BUDGET;
    let Some(getent) = getent_path() else {
        return false;
    };
    let Some(uid) = account_uid(&getent, user, deadline) else {
        return false;
    };
    let root = irlume_common::client::secure_env("IRLUME_LOGIND_DIR")
        .map_or_else(|| PathBuf::from("/run/systemd"), PathBuf::from);
    local_graphical_session(&root.join("sessions"), uid, deadline) == Some(false)
}

fn getent_path() -> Option<PathBuf> {
    if let Some(path) = irlume_common::client::secure_env("IRLUME_GETENT") {
        return Some(PathBuf::from(path));
    }
    // Administrator-owned locations only, including Nix's system profile.
    // Never resolve an executable using a PAM caller's PATH.
    [
        "/usr/bin/getent",
        "/bin/getent",
        "/run/current-system/sw/bin/getent",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

fn account_uid(getent: &Path, user: &str, deadline: Instant) -> Option<u32> {
    // Empty means enumeration to getent; a leading '-' could be an option.
    if user.is_empty() || user.starts_with('-') || Instant::now() >= deadline {
        return None;
    }
    let mut child = Command::new(getent)
        .args(["passwd", user])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Reuse PAM's bounded read/reap, not a detached thread that could outlive
    // dlclose. Cleanup after expiry is itself capped at 200 ms.
    let (status, bytes) = super::read_stdout_bounded(
        &mut child,
        deadline.saturating_duration_since(Instant::now()),
    )?;
    if !status.success() || Instant::now() >= deadline {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let mut lines = text.lines();
    let fields: Vec<_> = lines.next()?.split(':').collect();
    // NSS can canonicalize a name, and getent treats numeric input as a UID.
    // Neither ambiguity proves this PAM account cold. Do not guess a mapping.
    if lines.next().is_some() || fields.len() != 7 || fields[0] != user {
        return None;
    }
    decimal_uid(fields[2])
}

fn decimal_uid(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn local_graphical_session(root: &Path, uid: u32, deadline: Instant) -> Option<bool> {
    let entries = std::fs::read_dir(root).ok()?;
    for (count, entry) in entries.enumerate() {
        if count >= MAX_ENTRIES || Instant::now() >= deadline {
            return None;
        }
        let entry = entry.ok()?;
        let name = entry.file_name();
        // logind's legacy <id>.ref FIFOs and temporary publication files are
        // not session records. Opening a reference FIFO would hang the login.
        if !name.to_str().is_some_and(super::logind_id) {
            continue;
        }
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(entry.path())
        {
            Ok(file) => file,
            // logind removed this session during the scan.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut facts = String::new();
        file.take(MAX_SESSION_BYTES + 1)
            .read_to_string(&mut facts)
            .ok()?;
        if facts.len() as u64 > MAX_SESSION_BYTES || Instant::now() >= deadline {
            return None;
        }
        if graphical_session_of(&facts, uid)? {
            return Some(true);
        }
    }
    (Instant::now() < deadline).then_some(false)
}

fn graphical_session_of(facts: &str, uid: u32) -> Option<bool> {
    let value = |key: &str| {
        let mut values = facts.lines().filter_map(|line| line.strip_prefix(key));
        let first = values.next()?;
        values.next().is_none().then_some(first)
    };
    if decimal_uid(value("UID=")?)? != uid {
        return Some(false);
    }
    let remote = match value("REMOTE=")? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let user = match value("CLASS=")? {
        "user" => true,
        "greeter" | "lock-screen" | "background" | "manager" => false,
        _ => return None,
    };
    let live = match value("STATE=")? {
        "active" | "online" => true,
        "closing" | "opening" => false,
        _ => return None,
    };
    let graphical = match value("TYPE=")? {
        "x11" | "wayland" | "mir" => true,
        "tty" | "unspecified" => false,
        _ => return None,
    };
    Some(!remote && user && live && graphical)
}
