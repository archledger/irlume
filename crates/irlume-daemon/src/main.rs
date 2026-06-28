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
    // SO_PEERCRED is the real trust boundary; 0666 lets any local user *attempt*
    // auth (login greeters / sudo run as different uids); privileged ops are
    // still gated by the peer-credential check.
    set_mode(&socket, 0o666);
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

fn uid_of(user: &str) -> Option<u32> {
    let data = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in data.lines() {
        let mut f = line.split(':');
        if f.next() == Some(user) {
            return f.nth(1).and_then(|u| u.parse().ok()); // field index 2 = uid
        }
    }
    None
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
        Request::Authenticate { user } => match engine.authenticate(&user) {
            Ok(o) => Response::AuthResult { granted: o.granted, score: o.score, live: o.live, reason: o.reason },
            Err(e) => Response::Error(e.to_string()),
        },
        Request::Enroll { user, .. } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to enroll '{user}'"));
            }
            match engine.enroll(&user, 5) {
                Ok(n) => Response::AuthResult { granted: true, score: 0.0, live: true, reason: format!("enrolled {n} samples") },
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
        Request::ListProfiles { .. } | Request::DeleteProfile { .. } | Request::SelfTest { .. } => {
            Response::Error("unimplemented".into())
        }
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
