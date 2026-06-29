//! `irlumed` — the privileged daemon. Owns the camera + models and is the only
//! component that runs the biometric pipeline. Untrusted clients (`pam_irlume`,
//! the CLI) connect over a Unix socket and send line-delimited JSON requests;
//! the daemon authenticates each peer with `SO_PEERCRED` before honoring
//! privileged operations (enroll/delete).
//!
//! Single-threaded by design: the camera is a single shared resource, so
//! requests are served one at a time.

use irlume_common::{Request, Response, SOCKET_PATH};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};

mod users;

fn main() {
    let det = env_or("IRLUME_DET_MODEL", "/etc/irlume/det.onnx");
    let model = env_or("IRLUME_MODEL", "/etc/irlume/face.onnx");
    let adapter = env_or("IRLUME_IR_ADAPTER", "/etc/irlume/ir_adapter.onnx");
    let socket = std::env::var("IRLUME_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());

    eprintln!("irlumed: loading models (det={det}, model={model})…");
    // Auto-select the camera pair: explicit IRLUME_RGB_DEVICE/IR_DEVICE, else a
    // discovered Hello camera (built-in or external Brio/NexiGo), else defaults.
    let (rgb_dev, ir_dev) = irlume_auth::select_pair();
    eprintln!("irlumed: cameras rgb={rgb_dev} ir={ir_dev}");
    let mut engine = match irlume_auth::Engine::load(&det, &model)
        .map(|e| e.with_devices(&rgb_dev, &ir_dev))
        .and_then(|e| e.with_ir_adapter(&adapter))
    {
        Ok(e) => {
            eprintln!("irlumed: IR adapter {}", if e.has_ir_adapter() { "loaded" } else { "absent (raw IR)" });
            e
        }
        Err(e) => {
            eprintln!("irlumed: failed to load models: {e}");
            std::process::exit(1);
        }
    };

    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("irlumed: cannot bind {socket}: {e}");
            std::process::exit(1);
        }
    };
    // SO_PEERCRED is the real trust boundary. Defence-in-depth: if the `irlume`
    // group exists, restrict the socket to `0660 root:irlume` so only group
    // members (greeters, the user) can even connect; otherwise fall back to
    // 0666 so a box without the group set up still works (greeters run as
    // varied uids). Privileged ops are gated by the peer-credential check either way.
    match users::gid_for_group("irlume") {
        Some(gid) => {
            if let Err(e) = users::chown(std::path::Path::new(&socket), Some(0), Some(gid)) {
                eprintln!("irlumed: could not chown socket to root:irlume ({e}); leaving 0666");
                set_mode(&socket, 0o666);
            } else {
                set_mode(&socket, 0o660);
                eprintln!("irlumed: socket restricted to root:irlume (0660)");
            }
        }
        None => set_mode(&socket, 0o666),
    }
    eprintln!("irlumed: listening on {socket}");

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle(stream, &mut engine) {
                    eprintln!("irlumed: connection error: {e}");
                }
            }
            Err(e) => eprintln!("irlumed: accept error: {e}"),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

/// Peer identity from SO_PEERCRED.
struct Peer {
    uid: u32,
    #[allow(dead_code)]
    gid: u32,
    #[allow(dead_code)]
    pid: i32,
}

fn peer_cred(stream: &UnixStream) -> std::io::Result<Peer> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(Peer { uid: ucred.uid, gid: ucred.gid, pid: ucred.pid })
}

/// Only root or the target user themselves may enroll/delete that user's data.
fn authorized_for(peer: &Peer, target_user: &str) -> bool {
    peer.uid == 0 || uid_of(target_user).is_some_and(|u| u == peer.uid)
}

/// Resolve a username to its uid via NSS (covers LDAP/SSSD/systemd-homed, not
/// just `/etc/passwd`).
fn uid_of(user: &str) -> Option<u32> {
    users::uid_for_name(user)
}

fn handle(stream: UnixStream, engine: &mut irlume_auth::Engine) -> std::io::Result<()> {
    let peer = peer_cred(&stream)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => return respond(stream, &Response::Error(format!("bad request: {e}"))),
    };
    let resp = dispatch(req, &peer, engine);
    respond(stream, &resp)
}

fn dispatch(req: Request, peer: &Peer, engine: &mut irlume_auth::Engine) -> Response {
    match req {
        Request::Ping => Response::Pong,
        Request::PositionSample => match engine.position_sample() {
            Ok(r) => Response::Position(r),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::Authenticate { user } => match engine.authenticate(&user) {
            Ok(o) => Response::AuthResult { granted: o.granted, score: o.score, live: o.live, reason: o.reason },
            Err(e) => Response::Error(e.to_string()),
        },
        Request::Enroll { user, profile, scans } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to enroll '{user}'"));
            }
            let want = scans.unwrap_or(irlume_core::storage::DEFAULT_ENROLL_SCANS);
            // Auto-fix a dark/disabled IR emitter so dark-mode scans enroll
            // cleanly — only runs the brute-force if IR is actually dark.
            match irlume_auth::ensure_ir_emitter(engine.ir_device()) {
                Ok(true) => {}
                Ok(false) => eprintln!("irlumed: IR still dark after auto-setup — enrolling RGB (dark unlock unavailable)"),
                Err(e) => eprintln!("irlumed: IR emitter auto-setup skipped: {e}"),
            }
            match engine.enroll_profile(&user, profile, want) {
                Ok((name, n)) => Response::Ok(format!("enrolled '{name}' with {n} scans")),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::SetupIrEmitter { dry_run } => {
            // Hardware fix on the shared camera; non-destructive on failure.
            if dry_run {
                match irlume_auth::list_ir_controls(engine.ir_device()) {
                    Ok(c) if c.is_empty() => Response::Ok("no UVC extension-unit controls found".into()),
                    Ok(c) => Response::Ok(format!(
                        "XU controls: {}",
                        c.iter().map(|(u, s, l)| format!("unit{u}/sel{s}/{l}B")).collect::<Vec<_>>().join(", ")
                    )),
                    Err(e) => Response::Error(e.to_string()),
                }
            } else {
                match irlume_auth::setup_ir_emitter(engine.ir_device()) {
                    Ok(msg) => { eprintln!("irlumed: {msg}"); Response::Ok(msg) }
                    Err(e) => Response::Error(e.to_string()),
                }
            }
        }
        Request::AddScan { user, profile } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            match engine.add_scan(&user, &profile) {
                Ok((scan, total)) => Response::Ok(format!("added '{scan}' to '{profile}' ({total} scans)")),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        // --- keyring unlock (TPM-sealed password) ---------------------------
        Request::SealPassword { user, password } => {
            // Arming the keyring: root or the user themselves. `password`
            // zeroizes on drop, covering every return path.
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to seal password for '{user}'"));
            }
            match irlume_core::keyring::seal_password(&user, password.expose()) {
                Ok(()) => {
                    eprintln!("irlumed: SealPassword: armed keyring unlock for '{user}'");
                    Response::PasswordSealed
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::UnsealPassword { user } => {
            // The sealed LOGIN password is released ONLY to a root peer (the
            // login/lockscreen PAM stack runs as root). A non-root caller never
            // gets it, even with a matching face.
            if peer.uid != 0 {
                return Response::Error(format!("unseal_password requires root (peer uid {})", peer.uid));
            }
            do_unseal_password(&user, engine)
        }
        Request::HasSealedPassword { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to query '{user}'"));
            }
            Response::HasPassword(irlume_core::keyring::has_sealed_password(&user))
        }
        Request::ForgetPassword { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to forget password for '{user}'"));
            }
            match irlume_core::keyring::forget_password(&user) {
                Ok(()) => Response::PasswordForgotten,
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::ResealPassword { user, password } => {
            // Self-heal hook from the login SESSION phase (runs only after auth
            // succeeded, so `password` is verified-correct). Same authz as arming
            // (root or the user), but it can only ever *re-seal an already armed*
            // password against today's PCRs — it never arms a fresh user, so a
            // self-peer cannot use it to plant a sealed password they didn't set.
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to reseal password for '{user}'"));
            }
            match irlume_core::keyring::reseal_password(&user, password.expose()) {
                Ok(outcome) => {
                    use irlume_core::keyring::Reseal;
                    if outcome == Reseal::Resealed {
                        eprintln!(
                            "irlumed: ResealPassword: re-bound '{user}' to current PCRs (self-heal after PCR/password change)"
                        );
                    }
                    Response::PasswordResealed {
                        armed: outcome != Reseal::NotArmed,
                        changed: outcome == Reseal::Resealed,
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        // --- template-key recovery passphrase -------------------------------
        Request::RecoverySetup { user, passphrase } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to set recovery for '{user}'"));
            }
            // If templates are still plaintext (pre-encryption enrollment), mint
            // and seal a template key now by re-saving — encryption takes effect
            // and there's a key for the recovery passphrase to wrap. A no-op when
            // already encrypted or when the user isn't enrolled.
            if !irlume_core::template_key::has_key(&user) {
                if let Ok(Some(enr)) = irlume_core::storage::load(&user) {
                    if let Err(e) = irlume_core::storage::save(&enr) {
                        return Response::Error(format!("could not encrypt existing templates: {e}"));
                    }
                    eprintln!("irlumed: RecoverySetup: encrypted existing templates for '{user}'");
                }
            }
            match irlume_core::template_key::setup_recovery(&user, passphrase.expose()) {
                Ok(()) => {
                    eprintln!("irlumed: RecoverySetup: recovery passphrase set for '{user}'");
                    Response::Ok(format!("recovery passphrase set for '{user}'"))
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::RecoveryRestore { user, passphrase } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to restore recovery for '{user}'"));
            }
            match irlume_core::template_key::restore_from_recovery(&user, passphrase.expose()) {
                Ok(()) => {
                    eprintln!("irlumed: RecoveryRestore: re-sealed '{user}' template key to current PCRs");
                    Response::Ok(format!("template key restored and re-sealed for '{user}'"))
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::RecoveryStatus { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to query '{user}'"));
            }
            Response::RecoveryStatus {
                encrypted: irlume_core::template_key::has_key(&user),
                recovery_set: irlume_core::template_key::has_recovery(&user),
                tpm_present: irlume_core::template_key::tpm_available(),
            }
        }
        Request::RecoveryForget { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to forget recovery for '{user}'"));
            }
            match irlume_core::template_key::forget_recovery(&user) {
                Ok(()) => Response::Ok(format!("recovery passphrase erased for '{user}'")),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::ListProfiles { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to list '{user}'"));
            }
            match irlume_core::storage::load(&user) {
                Ok(Some(enr)) => Response::Enrollment {
                    profiles: enr.profiles.iter().map(|p| irlume_common::ProfileSummary {
                        name: p.name.clone(),
                        scans: p.scans.iter().map(|s| s.name.clone()).collect(),
                    }).collect(),
                    require_eyes_open: enr.require_eyes_open,
                },
                Ok(None) => Response::Enrollment { profiles: vec![], require_eyes_open: false },
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::DeleteProfile { user, profile } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let before = enr.profiles.len();
                enr.profiles.retain(|p| p.name != profile);
                if enr.profiles.len() == before {
                    Err(format!("no face profile '{profile}'"))
                } else {
                    Ok(format!("deleted profile '{profile}'"))
                }
            })
        }
        Request::DeleteScan { user, profile, scan } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let p = enr.profiles.iter_mut().find(|p| p.name == profile).ok_or(format!("no face profile '{profile}'"))?;
                let before = p.scans.len();
                p.scans.retain(|s| s.name != scan);
                if p.scans.len() == before { Err(format!("no scan '{scan}' in '{profile}'")) }
                else if p.scans.is_empty() { Err("a profile must keep at least one scan — delete the profile instead".into()) }
                else { Ok(format!("deleted scan '{scan}' from '{profile}'")) }
            })
        }
        Request::RenameProfile { user, profile, new_name } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                if enr.profiles.iter().any(|p| p.name == new_name) { return Err(format!("'{new_name}' already exists")); }
                let p = enr.profiles.iter_mut().find(|p| p.name == profile).ok_or(format!("no face profile '{profile}'"))?;
                p.name = new_name.clone();
                Ok(format!("renamed profile to '{new_name}'"))
            })
        }
        Request::RenameScan { user, profile, scan, new_name } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let p = enr.profiles.iter_mut().find(|p| p.name == profile).ok_or(format!("no face profile '{profile}'"))?;
                if p.scans.iter().any(|s| s.name == new_name) { return Err(format!("'{new_name}' already exists in '{profile}'")); }
                let s = p.scans.iter_mut().find(|s| s.name == scan).ok_or(format!("no scan '{scan}' in '{profile}'"))?;
                s.name = new_name.clone();
                Ok(format!("renamed scan to '{new_name}'"))
            })
        }
        Request::SetRequireEyesOpen { user, on } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                enr.require_eyes_open = on;
                Ok(format!("require-eyes-open {}", if on { "ENABLED" } else { "disabled" }))
            })
        }
        Request::SelfTest { .. } => Response::Error("unimplemented".into()),
    }
}

/// Load `user`'s enrollment, apply `f`, and save. `f` returns an Ok message or an
/// error string. Used by the storage-only management operations.
fn mutate_enrollment(user: &str, f: impl FnOnce(&mut irlume_core::storage::Enrollment) -> Result<String, String>) -> Response {
    let mut enr = match irlume_core::storage::load(user) {
        Ok(Some(e)) => e,
        Ok(None) => return Response::Error(format!("'{user}' is not enrolled")),
        Err(e) => return Response::Error(e.to_string()),
    };
    match f(&mut enr) {
        Ok(msg) => {
            // If no profiles remain, remove the file entirely.
            let save = if enr.profiles.is_empty() {
                irlume_core::storage::delete(user).map(|_| ())
            } else {
                irlume_core::storage::save(&enr)
            };
            match save {
                Ok(()) => Response::Ok(msg),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Err(e) => Response::Error(e),
    }
}

/// Face-verify `user` and, on a live match, release the TPM-sealed password. The
/// biometric check happens HERE (inside unseal), so a caller cannot get the
/// password without a live face that matches the enrolled templates. We log the
/// decision + cosine score, but never the password or its length.
fn do_unseal_password(user: &str, engine: &mut irlume_auth::Engine) -> Response {
    eprintln!("irlumed: UnsealPassword: attempt for '{user}'");
    if !irlume_core::keyring::has_sealed_password(user) {
        return Response::Error(format!("no sealed password for '{user}' — run `irlume keyring arm`"));
    }
    let outcome = match engine.authenticate(user) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("irlumed: UnsealPassword: capture/auth failed for '{user}': {e}");
            return Response::Error(e.to_string());
        }
    };
    if !outcome.granted {
        eprintln!(
            "irlumed: UnsealPassword: denied for '{user}' (live={}, score {:.4}: {}) -> password",
            outcome.live, outcome.score, outcome.reason
        );
        return Response::Error(format!("face not granted: {}", outcome.reason));
    }
    match irlume_core::keyring::unseal_password(user) {
        Ok(secret) => {
            eprintln!(
                "irlumed: UnsealPassword: OK for '{user}' (score {:.4}), password unsealed",
                outcome.score
            );
            Response::PasswordUnsealed { secret: irlume_common::SecretBytes::new(secret.to_vec()) }
        }
        // Face matched but the TPM could not release the secret (e.g. PCR drift
        // after a Secure Boot config change). This is the line that explains a
        // face login that nonetheless leaves the keyring locked.
        Err(e) => {
            eprintln!(
                "irlumed: UnsealPassword: face matched for '{user}' (score {:.4}) but TPM unseal FAILED: {e}",
                outcome.score
            );
            Response::Error(e.to_string())
        }
    }
}

fn respond(mut stream: UnixStream, resp: &Response) -> std::io::Result<()> {
    let mut json = serde_json::to_vec(resp)?;
    json.push(b'\n');
    stream.write_all(&json)?;
    stream.flush()
}

fn set_mode(path: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_self_authorized_others_denied() {
        let root = Peer { uid: 0, gid: 0, pid: 1 };
        // uid_of relies on /etc/passwd; just exercise the root path deterministically.
        assert!(authorized_for(&root, "nonexistent-user"));
    }
}
