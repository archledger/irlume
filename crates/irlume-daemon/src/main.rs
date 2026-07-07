//! `irlumed` — the privileged daemon. Owns the camera + models and is the only
//! component that runs the biometric pipeline. Untrusted clients (`pam_irlume`,
//! the CLI) connect over a Unix socket and send line-delimited JSON requests;
//! the daemon authenticates each peer with `SO_PEERCRED` before honoring
//! privileged operations (enroll/delete).
//!
//! Single-threaded by design: the camera is a single shared resource, so
//! requests are served one at a time.

use irlume_common::{Request, Response, SOCKET_PATH};
use std::io::{BufRead, BufReader, Read, Write};
use zeroize::Zeroize;
use std::os::unix::net::{UnixListener, UnixStream};

mod users;

fn main() {
    let det = env_or("IRLUME_DET_MODEL", "/etc/irlume/det.onnx");
    let model = env_or("IRLUME_MODEL", "/etc/irlume/face.onnx");
    let adapter = env_or("IRLUME_IR_ADAPTER", "/etc/irlume/ir_adapter.onnx");
    let mesh = env_or("IRLUME_MESH_MODEL", "/etc/irlume/face_landmark.onnx");
    let socket = std::env::var("IRLUME_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());

    eprintln!("irlumed: loading models (det={det}, model={model})…");
    // Auto-select the camera pair: explicit IRLUME_RGB_DEVICE/IR_DEVICE, else a
    // discovered Hello camera (built-in or external Brio/NexiGo), else defaults.
    let (rgb_dev, ir_dev) = irlume_auth::select_pair();
    // Log what is actually usable, not the raw (possibly fallback) selection —
    // on camera-less or RGB-only hardware the fixed default pair doesn't exist.
    {
        let ok = |d: &str| std::path::Path::new(d).exists();
        match (ok(&rgb_dev), ok(&ir_dev)) {
            (true, true) => eprintln!("irlumed: cameras rgb={rgb_dev} ir={ir_dev} (secure tier)"),
            (true, false) => eprintln!("irlumed: camera rgb={rgb_dev}, no IR node (convenience tier — screen unlock only)"),
            (false, _) => eprintln!("irlumed: no camera found (face auth unavailable; password/fingerprint only)"),
        }
    }
    let mut engine = match irlume_auth::Engine::load(&det, &model)
        .map(|e| e.with_devices(&rgb_dev, &ir_dev))
        .and_then(|e| e.with_ir_adapter(&adapter))
        .and_then(|e| e.with_mesh(&mesh))
    {
        Ok(e) => {
            eprintln!("irlumed: IR adapter {}", if e.has_ir_adapter() { "loaded" } else { "absent (raw IR)" });
            eprintln!("irlumed: FaceMesh (passive liveness) {}", if e.has_mesh() { "loaded" } else { "absent" });
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
    if irlume_common::dbglog::on() {
        eprintln!("irlumed: diagnostic tracing ON (IRLUME_LOG=debug) — per-stage pipeline lines follow; numbers only, never frames/embeddings");
    }

    // Socket watchdog: if our socket file is deleted/replaced out from under us
    // (a stale-runtime cleanup, a botched reinstall), the bound fd keeps working
    // but no client can ever connect again — a silent outage. Detect it and exit
    // so systemd (Restart=on-failure) re-binds a fresh socket. Self-heals what
    // the Repair tab otherwise needs a manual restart for.
    {
        let socket = socket.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
            if !std::path::Path::new(&socket).exists() {
                eprintln!("irlumed: socket {socket} vanished — exiting for a clean re-bind");
                std::process::exit(1);
            }
        });
    }

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

/// Whether opt-in biopolicy operation-class gating is enabled. Off by default;
/// turn on via `IRLUME_ENFORCE_BIOPOLICY=1` or `enforce_biopolicy=1` in
/// `/etc/irlume/settings.conf`. When off, behaviour is unchanged.
fn biopolicy_enforced() -> bool {
    let truthy = |s: &str| matches!(s.trim(), "1" | "true" | "yes" | "on");
    if let Ok(v) = std::env::var("IRLUME_ENFORCE_BIOPOLICY") {
        return truthy(&v);
    }
    irlume_common::config::read_kv("settings.conf", "enforce_biopolicy")
        .map(|v| truthy(&v))
        .unwrap_or(false)
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

/// One request line may not exceed this. A face embedding or sealed password is
/// a few KB of base64; 64 KiB is generous and bounds a slow-loris / memory DoS
/// from a peer that never sends a newline.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

fn handle(stream: UnixStream, engine: &mut irlume_auth::Engine) -> std::io::Result<()> {
    let peer = peer_cred(&stream)?;
    // A read/write deadline stops one wedged peer from blocking the single-
    // threaded daemon (and thus ALL logins) forever.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(15)));
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_REQUEST_BYTES);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        // Don't echo the peer's raw bytes / parser internals back to them.
        Err(_) => {
            line.zeroize();
            return respond(stream, &Response::Error("bad request".into()));
        }
    };
    // The line may hold a plaintext secret (SealPassword/RecoverySetup) — wipe it
    // now that it's parsed into the zeroizing SecretBytes.
    line.zeroize();
    let resp = dispatch(req, &peer, engine);
    respond(stream, &resp)
}

/// A username is interpolated into `<user>.json` paths (enrollment, sealed key,
/// keyring). Reject anything that could traverse or escape the state dir before
/// any path is built — defence-in-depth on top of the NSS `authorized_for` check.
fn valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with(['-', '.'])
        && u.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
}

/// The `user` field of a request, if it carries one (for the traversal guard).
fn request_user(req: &Request) -> Option<&str> {
    use Request::*;
    match req {
        Authenticate { user, .. } | Enroll { user, .. } | ListProfiles { user }
        | DeleteProfile { user, .. } | DeleteScan { user, .. } | RenameProfile { user, .. }
        | RenameScan { user, .. } | AddScan { user, .. } | SetRequireEyesOpen { user, .. }
        | SetRequireChallenge { user, .. } | SealPassword { user, .. } | UnsealPassword { user, .. }
        | UnsealKeyring { user, .. } | HasSealedPassword { user } | ForgetPassword { user }
        | ResealPassword { user, .. } | RecoveryStatus { user } | RecoverySetup { user, .. }
        | RecoveryRestore { user, .. } | RecoveryForget { user } => Some(user.as_str()),
        _ => None,
    }
}

fn dispatch(req: Request, peer: &Peer, engine: &mut irlume_auth::Engine) -> Response {
    if let Some(u) = request_user(&req) {
        if !valid_username(u) {
            return Response::Error("invalid username".into());
        }
    }
    match req {
        Request::Ping => Response::Pong,
        Request::Health => {
            // Live probe (cameras can appear/vanish); report selected nodes only
            // when they actually exist — never the unvalidated fallback pair.
            let caps = irlume_auth::capabilities();
            let (rgb, ir) = irlume_auth::select_pair();
            let rgb_dev = (caps.rgb && std::path::Path::new(&rgb).exists()).then_some(rgb);
            let ir_dev = (caps.ir_pair && std::path::Path::new(&ir).exists()).then_some(ir);
            let tier = if ir_dev.is_some() {
                "secure"
            } else if rgb_dev.is_some() {
                "convenience"
            } else {
                "none"
            };
            Response::Health {
                tier: tier.into(),
                rgb_dev,
                ir_dev,
                mesh: engine.has_mesh(),
                adapter: engine.has_ir_adapter(),
                version: env!("CARGO_PKG_VERSION").into(),
            }
        }
        Request::PositionSample => match engine.position_sample() {
            Ok(r) => Response::Position(r),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::Authenticate { user, service } => {
            // Root (PAM stacks) or the account owner only. Without this gate any
            // local peer could probe Authenticate{other_user} and read the raw
            // similarity score — a hill-climbing oracle toward a match (the
            // threat model promises scores never leak to unprivileged peers).
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to authenticate '{user}'"));
            }
            // Honor the configured unlock method: if the admin chose fingerprint,
            // face must actually stand down (pam_fprintd drives; password is the
            // fallback) — not just be claimed disabled by the CLI message.
            if irlume_core::policy::method().face_disabled() {
                return Response::AuthResult {
                    granted: false,
                    score: 0.0,
                    live: false,
                    reason: "face auth disabled — the configured method is fingerprint".into(),
                };
            }
            // Smart-Auto tier gate: on a CONVENIENCE (RGB-only) device, a face
            // match may ONLY satisfy a screen unlock — never login, elevation, or
            // a remote/unknown service (those keep the password). Always-on for
            // RGB-only hardware (independent of the opt-in biopolicy for IR boxes).
            if engine.tier() == irlume_core::biopolicy::Tier::Convenience {
                use irlume_core::biopolicy::{classify, OperationClass};
                // "Warm" = the user already has a running session (their systemd
                // runtime dir exists) — then an ambiguous greeter service (GDM
                // drives cold login AND the lock screen through gdm-password) is
                // a screen unlock, not a login. Caveat: lingering user services
                // also create /run/user/<uid>; acceptable for the convenience
                // tier where the worst case is unlocking a lock screen.
                let warm = users::uid_for_name(&user)
                    .map(|uid| std::path::Path::new(&format!("/run/user/{uid}")).exists())
                    .unwrap_or(false);
                let class = classify(service.as_deref().unwrap_or(""), warm);
                if class != OperationClass::ScreenUnlock {
                    eprintln!("irlumed: convenience(RGB-only) denies face for '{}' ({class:?}) -> password", service.as_deref().unwrap_or("?"));
                    return Response::AuthResult { granted: false, score: 0.0, live: false,
                        reason: format!("RGB-only convenience: face limited to screen unlock (not {class:?})") };
                }
            }
            // Opt-in biopolicy also gates identity VERIFICATION on IR/Secure
            // hardware (mirrors the credential-release gate) — else a face grant
            // for a Remote/Unknown service would bypass the "face never satisfies
            // remote" invariant. Off by default (behaviour unchanged).
            if biopolicy_enforced() && engine.tier() != irlume_core::biopolicy::Tier::Convenience {
                use irlume_core::biopolicy::{classify, decide, Action, Tier};
                let svc = service.as_deref().unwrap_or("");
                if decide(classify(svc, false), Tier::Secure) == Action::Deny {
                    eprintln!("irlumed: biopolicy denies verify for service '{svc}' -> password");
                    return Response::AuthResult { granted: false, score: 0.0, live: false,
                        reason: format!("biopolicy: face may not satisfy '{svc}'") };
                }
            }
            let convenience = engine.tier() == irlume_core::biopolicy::Tier::Convenience;
            let t = std::time::Instant::now();
            match engine.authenticate(&user) {
                Ok(o) => {
                    if convenience || irlume_common::dbglog::on() {
                        // Denied score + reason measurements quantized/redacted
                        // unless tracing (anti-oracle); grants log exact.
                        let (score, reason) = if o.granted {
                            (format!("{:.3}", o.score), o.reason.clone())
                        } else {
                            (deny_score(o.score), deny_reason(&o.reason))
                        };
                        eprintln!("irlumed: face auth '{user}': granted={} live={} score={score} ({reason})",
                            o.granted, o.live);
                    }
                    irlume_common::dlog!("verify '{user}' total {}ms", t.elapsed().as_millis());
                    Response::AuthResult { granted: o.granted, score: o.score, live: o.live, reason: o.reason }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::Identify => match engine.identify() {
            Ok(o) => Response::Identified { user: o.user, profile: o.profile, score: o.score, live: o.live, reason: o.reason },
            Err(e) => Response::Error(e.to_string()),
        },
        Request::SetCameras { rgb, ir } => {
            // Persists to /etc and repoints the camera the daemon trusts — an
            // attacker who could set this to a v4l2loopback node feeds recorded
            // video into the match path (spoof) or bricks face auth (DoS). Root
            // only (a system-wide /etc setting isn't an arbitrary peer's to make).
            if peer.uid != 0 {
                return Response::Error(format!("set_cameras requires root (peer uid {})", peer.uid));
            }
            engine.set_devices(&rgb, &ir);
            let mut msg = format!("cameras set to rgb={rgb} ir={ir}");
            if let Err(e) = irlume_common::config::write_kv("cameras.conf", "rgb", &rgb)
                .and_then(|_| irlume_common::config::write_kv("cameras.conf", "ir", &ir))
            {
                msg = format!("{msg} (live only — could not persist: {e})");
            }
            eprintln!("irlumed: {msg}");
            Response::Ok(msg)
        }
        Request::Enroll { user, profile, scans, reset } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to enroll '{user}'"));
            }
            if reset {
                // Clean slate: drop the old enrollment (and its stale camera
                // binding) before enrolling fresh.
                if let Err(e) = irlume_core::storage::delete(&user) {
                    return Response::Error(format!("reset failed: {e}"));
                }
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
                // The non-dry path brute-forces UVC control writes on the shared
                // camera — a local peer could thrash the hardware. Root only.
                if peer.uid != 0 {
                    return Response::Error(format!("setup_ir_emitter requires root (peer uid {})", peer.uid));
                }
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
        Request::UnsealPassword { user, service } => {
            // The sealed LOGIN password is released ONLY to a root peer (the
            // login/lockscreen PAM stack runs as root). A non-root caller never
            // gets it, even with a matching face.
            if peer.uid != 0 {
                return Response::Error(format!("unseal_password requires root (peer uid {})", peer.uid));
            }
            // Same method gate as Authenticate: fingerprint-configured means no
            // face-driven credential release either.
            if irlume_core::policy::method().face_disabled() {
                return Response::Error("face auth disabled — the configured method is fingerprint".into());
            }
            // Smart-Auto: an RGB-only (convenience) device NEVER releases the
            // sealed credential — no cold-login / keyring unlock by RGB-only face.
            if engine.tier() == irlume_core::biopolicy::Tier::Convenience {
                eprintln!("irlumed: convenience(RGB-only) refuses credential release for '{user}' -> password");
                return Response::Error("RGB-only convenience: face cannot release the login credential".into());
            }
            // Opt-in biopolicy: when enforcement is enabled, gate credential
            // release by the PAM service's operation class (e.g. refuse a remote
            // / unknown service). Default off → unchanged behaviour.
            if biopolicy_enforced() {
                use irlume_core::biopolicy::{classify, decide, Action, Tier};
                let svc = service.as_deref().unwrap_or("");
                // UnsealPassword is the cold-login path (the lock screen uses
                // verify-only `wait`), so warm=false. irlume's liveness already
                // requires IR for any grant, so a granted match is Secure tier.
                let action = decide(classify(svc, false), Tier::Secure);
                if action != Action::Unseal {
                    eprintln!("irlumed: biopolicy denies unseal for service '{svc}' ({action:?}) -> password");
                    return Response::Error(format!("biopolicy: '{svc}' may not release the credential"));
                }
            }
            do_unseal_password(&user, engine)
        }
        Request::UnsealKeyring { user, service } => {
            // Fingerprint keyring unlock. pam_fprintd has ALREADY authenticated
            // the user in this PAM transaction (pam_irlume `keyring` only runs at
            // the post-auth landing). The daemon can't re-verify a fingerprint —
            // fprintd owns the sensor — so the trust is: root peer + a login /
            // unlock service class. Releases the sealed login password so
            // pam_gnome_keyring can open the wallet, matching Windows Hello's
            // functional model. SECURITY (ADR-0003 / THREAT_MODEL): preserves
            // at-rest protection — a stolen disk still can't unseal (needs the
            // live TPM) — but a live root attacker in a login context can obtain
            // it; root stays the trust boundary. For daemon-verified biometric
            // release resistant to live root, use the face/IR path.
            if peer.uid != 0 {
                return Response::Error(format!("unseal_keyring requires root (peer uid {})", peer.uid));
            }
            if !irlume_core::keyring::has_sealed_password(&user) {
                return Response::Error(format!("no sealed password for '{user}' — run `irlume keyring arm`"));
            }
            // Only a login / greeter / lock-screen context — never sudo,
            // elevation, remote, or unknown. Defence-in-depth: a direct caller
            // can forge the service string (root can call us directly), so this
            // does not stop a root attacker; it does stop the keyring line being
            // (mis)wired into a non-login stack from releasing the credential.
            {
                use irlume_core::biopolicy::{classify, OperationClass};
                let class = classify(service.as_deref().unwrap_or(""), true);
                if !matches!(class, OperationClass::ScreenUnlock | OperationClass::Login) {
                    eprintln!("irlumed: UnsealKeyring refused for service '{}' ({class:?})",
                        service.as_deref().unwrap_or("?"));
                    return Response::Error(format!("keyring unseal not allowed for {class:?}"));
                }
            }
            match irlume_core::keyring::unseal_password(&user) {
                Ok(secret) => {
                    eprintln!("irlumed: UnsealKeyring: OK for '{user}' (fingerprint-authenticated), password unsealed");
                    Response::PasswordUnsealed { secret: irlume_common::SecretBytes::new(secret.to_vec()) }
                }
                Err(e) => {
                    eprintln!("irlumed: UnsealKeyring: TPM unseal FAILED for '{user}': {e}");
                    Response::Error(e.to_string())
                }
            }
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
                    require_challenge: enr.require_challenge,
                },
                Ok(None) => Response::Enrollment { profiles: vec![], require_eyes_open: false, require_challenge: false },
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
        Request::SetRequireChallenge { user, on } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                enr.require_challenge = on;
                Ok(format!("require-challenge {}", if on { "ENABLED" } else { "disabled" }))
            })
        }
        Request::SelfTest { kind } => {
            use irlume_common::SelfTestKind;
            let r = match kind {
                SelfTestKind::Liveness => engine.liveness_selftest(),
                SelfTestKind::AlignmentIdentity => engine.alignment_selftest(),
            };
            match r {
                Ok((passed, detail)) => Response::SelfTest { passed, detail },
                Err(e) => Response::Error(e.to_string()),
            }
        }
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
/// Deny-line score display: exact under IRLUME_LOG=debug tracing, else
/// quantized to one decimal (anti-oracle — see comment at the deny log).
fn deny_score(s: f32) -> String {
    if irlume_common::dbglog::on() { format!("{s:.4}") } else { format!("~{s:.1}") }
}

/// Journal-side deny-reason display. Deny reasons embed measured values
/// ("IR too flat (1.02)", "rgb 0.35") as coaching for a genuine false reject —
/// but in the JOURNAL those same numbers are per-attempt feedback a spoofer
/// could tune against. The exact reason still goes back over IPC to the
/// session's own TUI/CLI; here we strip the numeric payloads unless tracing is
/// on. Digit runs attached to letters ("2D", "3D", "850nm") are prose, kept.
fn deny_reason(r: &str) -> String {
    if irlume_common::dbglog::on() {
        return r.to_string();
    }
    let cs: Vec<char> = r.chars().collect();
    let mut out = String::with_capacity(r.len());
    let mut i = 0;
    while i < cs.len() {
        if cs[i].is_ascii_digit() {
            let start = i;
            while i < cs.len() && (cs[i].is_ascii_digit() || cs[i] == '.') { i += 1; }
            let mut end = i;
            while end > start && cs[end - 1] == '.' { end -= 1; } // sentence period, not a decimal
            let prev_alpha = start > 0 && cs[start - 1].is_ascii_alphabetic();
            let next_alpha = end < cs.len() && cs[end].is_ascii_alphabetic();
            if prev_alpha || next_alpha {
                out.extend(&cs[start..end]);
            } else {
                out.push('…');
            }
            out.extend(&cs[end..i]);
        } else {
            out.push(cs[i]);
            i += 1;
        }
    }
    out
}

fn do_unseal_password(user: &str, engine: &mut irlume_auth::Engine) -> Response {
    eprintln!("irlumed: UnsealPassword: attempt for '{user}'");
    let t = std::time::Instant::now();
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
        // Denied-attempt scores are QUANTIZED to one decimal unless tracing is
        // on: a 4-decimal score after every try is a gradient a journal-reading
        // attacker could climb to tune a spoof. One decimal still separates
        // "borderline" from "not even close" for false-reject diagnosis.
        eprintln!(
            "irlumed: UnsealPassword: denied for '{user}' (live={}, score {}: {}) -> password",
            outcome.live, deny_score(outcome.score), deny_reason(&outcome.reason)
        );
        return Response::Error(format!("face not granted: {}", outcome.reason));
    }
    match irlume_core::keyring::unseal_password(user) {
        Ok(secret) => {
            eprintln!(
                "irlumed: UnsealPassword: OK for '{user}' (score {:.4}), password unsealed",
                outcome.score
            );
            irlume_common::dlog!("unseal '{user}' total {}ms (face + TPM)", t.elapsed().as_millis());
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
    let r = stream.flush();
    // The response may carry an unsealed secret (PasswordUnsealed) — wipe the
    // serialized line, same hygiene as the request path and the client side.
    json.zeroize();
    r
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

    #[test]
    fn deny_reason_strips_measurements_keeps_prose() {
        // (tracing is off in tests — IRLUME_LOG unset)
        assert_eq!(deny_reason("IR too flat (center/edge 1.02) — looks 2D, not a 3D face"),
                   "IR too flat (center/edge …) — looks 2D, not a 3D face");
        assert_eq!(deny_reason("IR face too dark (42)"), "IR face too dark (…)");
        assert_eq!(deny_reason("below threshold (rgb 0.35, fusion+ir-fallback miss)"),
                   "below threshold (rgb …, fusion+ir-fallback miss)");
        // digit runs attached to letters are prose/idents, not measurements
        assert_eq!(deny_reason("a real face reflects 850nm"), "a real face reflects 850nm");
        // trailing sentence period survives a float at end of sentence
        assert_eq!(deny_reason("floor 1.12."), "floor ….");
        // no numbers -> unchanged
        assert_eq!(deny_reason("'ghost' is not enrolled"), "'ghost' is not enrolled");
    }
}
