// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Connection-bound password verification. Never occupies the camera worker.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{operation_authorization::Subject, pregate, retry_throttle::recovery::Recovery, Peer};
use irlume_common::{Request, Response};

const HELPER: &str = "/usr/libexec/irlume-password-verify";
const SERVICE: &str = "/etc/pam.d/irlume-retry-reset";
const UNAVAILABLE: &str = "password-only retry recovery is unavailable; use your password for normal login or ask an administrator";
const REFUSED: &str = "password verification failed or was cancelled; retry state unchanged";
const BUDGET: Duration = Duration::from_secs(12);

fn trusted(path: &Path, executable: bool) -> bool {
    // Both the configured path and resolved target must stay inside root-owned,
    // non-writable ancestry (Nix and distribution libexec symlinks are allowed).
    let Ok(resolved) = path.canonicalize() else {
        return false;
    };
    for item in path.ancestors().chain(resolved.ancestors()) {
        let Ok(m) = item.metadata() else {
            return false;
        };
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return false;
        }
    }
    let Ok(m) = resolved.metadata() else {
        return false;
    };
    m.is_file() && m.mode() & 0o6000 == 0 && (!executable || m.mode() & 0o111 != 0)
}

fn available_at(helper: &Path, service: &Path) -> bool {
    if !trusted(helper, true) || !trusted(service, false) {
        return false;
    }
    let Ok(file) = std::fs::File::open(service) else {
        return false;
    };
    let mut bytes = Vec::new();
    if file.take(4097).read_to_end(&mut bytes).is_err() {
        return false;
    }
    if bytes.len() > 4096 {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return false;
    };
    supported_service(text)
}

fn supported_service(text: &str) -> bool {
    let rules: Vec<Vec<&str>> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default())
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|l| !l.is_empty())
        .collect();
    rules
        == [
            vec!["auth", "required", "pam_unix.so", "nodelay"],
            vec!["account", "required", "pam_unix.so"],
        ]
}

fn available() -> bool {
    // Keep NoNewPrivileges and existing confinement. An enforcing AppArmor
    // transition needs separate runtime qualification before self-service use.
    if super::apparmor_confinement().is_some_and(|label| label.contains("(enforce)")) {
        return false;
    }
    available_at(Path::new(HELPER), Path::new(SERVICE))
}

fn verify(user: &str, password: &[u8], active: impl Fn() -> bool) -> Result<(), &'static str> {
    if !available() {
        return Err(UNAVAILABLE);
    }
    run_helper(Path::new(HELPER), user, password, BUDGET, active)
}

fn run_helper(
    helper: &Path,
    user: &str,
    password: &[u8],
    budget: Duration,
    active: impl Fn() -> bool,
) -> Result<(), &'static str> {
    if password.is_empty() || password.len() > 4096 || password.contains(&0) || !active() {
        return Err(REFUSED);
    }
    let mut child = Command::new(helper)
        .arg(user)
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| UNAVAILABLE)?;
    let deadline = Instant::now() + budget;
    // Linux pipes accommodate this bounded payload without waiting for the
    // reader; no unbounded stream is accepted. EOF terminates the secret.
    let written = child
        .stdin
        .take()
        .ok_or(REFUSED)
        .and_then(|mut pipe| pipe.write_all(password).map_err(|_| REFUSED));
    if written.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(REFUSED);
    }
    loop {
        if !active() || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(REFUSED);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() && active() {
                    Ok(())
                } else {
                    Err(REFUSED)
                }
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(REFUSED);
            }
        }
    }
}

pub(super) fn dispatch(req: &Request, peer: &Peer, stream: &UnixStream) -> Response {
    dispatch_using(req, peer, stream, available(), |user, password, active| {
        verify(user, password, active)
    })
}

fn dispatch_using(
    req: &Request,
    peer: &Peer,
    stream: &UnixStream,
    is_available: bool,
    verifier: impl FnOnce(&str, &[u8], &dyn Fn() -> bool) -> Result<(), &'static str>,
) -> Response {
    if let Some(response) = pregate(req, peer) {
        return response;
    }
    let user = match req {
        Request::RetryStatus { user } | Request::RetryReset { user, .. } => user,
        _ => return Response::Error(UNAVAILABLE.into()),
    };
    let gate = match Recovery::for_user(user) {
        Ok(gate) => gate,
        Err(e) => return Response::Error(e.into()),
    };
    if matches!(req, Request::RetryStatus { .. }) {
        return match gate.status() {
            Ok(s) => Response::RetryStatus {
                face_budget: Some(s.face_budget),
                failures: s.failures,
                cooldown_seconds: s.cooldown_seconds,
                recovery_failures: s.recovery_failures,
                recovery_cooldown_seconds: s.recovery_cooldown_seconds,
                recovery_required: s.recovery_required,
                password_reset_available: is_available,
            },
            Err(e) => Response::Error(e.into()),
        };
    }
    let Request::RetryReset { password, .. } = req else {
        unreachable!()
    };
    if peer.uid != 0 && !is_available {
        return Response::Error(UNAVAILABLE.into());
    }
    let _slot = match Slot::acquire() {
        Some(slot) => slot,
        None => {
            return Response::Error("another retry recovery is pending; try again shortly".into())
        }
    };
    let binding = match Subject::capture(peer) {
        Ok(b) => b,
        Err(_) => return Response::Error(REFUSED.into()),
    };
    let deadline = Instant::now() + BUDGET;
    let active =
        || Instant::now() < deadline && connection_active(stream) && binding.validate(peer).is_ok();
    match gate.reset(peer.uid == 0, active, || {
        verifier(user, password.expose(), &active)
    }) {
        Ok(()) => Response::Ok("face retry state reset".into()),
        Err(e) => Response::Error(e.into()),
    }
}

/// Detect a closed write side even when unconsumed input hides EOF from recv.
/// Recovery clients retain the full connection until the reset response.
fn connection_active(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: fd is one initialized pollfd, held exclusively for this call;
    // stream keeps its descriptor alive and a zero timeout cannot block.
    let result = unsafe { libc::poll(&mut fd, 1, 0) };
    result >= 0
        && fd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0
}

static PENDING: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
struct Slot;
impl Slot {
    fn acquire() -> Option<Self> {
        let mut n = PENDING.lock().ok()?;
        if *n >= 8 {
            return None;
        }
        *n += 1;
        Some(Self)
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut n) = PENDING.lock() {
            *n -= 1;
        }
    }
}

#[cfg(test)]
mod tests;
