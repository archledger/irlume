// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlumed`: the privileged daemon. Owns the camera + models and is the only
//! component that runs the biometric pipeline. Untrusted clients (`pam_irlume`,
//! the CLI) connect over a Unix socket and send line-delimited JSON requests;
//! the daemon authenticates each peer with `SO_PEERCRED` before honoring
//! privileged operations (enroll/delete).
//!
//! Single-threaded by design: the camera is a single shared resource, so
//! requests are served one at a time.

use irlume_common::{Request, Response, SOCKET_PATH};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

mod users;

/// Release checksums of the bundled models (models/SHA256SUMS, committed next
/// to the weights and embedded at build time).
const MODEL_MANIFEST: &str = include_str!("../../../models/SHA256SUMS");

/// Hash each configured model file and compare against the release manifest.
/// Matching by digest (not filename) so packaging renames stay irrelevant.
/// Unknown weights WARN by default: operators legitimately deploy self-trained
/// adapters, and refusing to start would turn a model swap into a lockout.
/// `IRLUME_MODELS_STRICT=1` upgrades the warning to a startup refusal.
fn verify_models(paths: &[&str]) {
    let known: std::collections::HashSet<&str> = MODEL_MANIFEST
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    let strict = std::env::var("IRLUME_MODELS_STRICT")
        .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"));
    for path in paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                // Strict must also catch a *deleted* model: silently skipping
                // would let removal (not just tampering) downgrade liveness.
                if strict {
                    eprintln!(
                        "irlumed: IRLUME_MODELS_STRICT: cannot read model {path} ({e}); refusing to start"
                    );
                    std::process::exit(1);
                }
                // Without strict, the loader reports missing/optional models.
                continue;
            }
        };
        let digest = irlume_common::thirdparty::sha256_hex(&bytes);
        if !known.contains(digest.as_str()) {
            eprintln!(
                "irlumed: WARNING: {path} does not match any release model checksum (sha256 {digest})"
            );
            if strict {
                eprintln!(
                    "irlumed: IRLUME_MODELS_STRICT=1: refusing to start with unverified models"
                );
                std::process::exit(1);
            }
            eprintln!(
                "irlumed: continuing with unverified weights (expected for custom or \
                 self-trained models; set IRLUME_MODELS_STRICT=1 to refuse instead)"
            );
        }
    }
}

/// The model files to checksum-verify at startup. det/model/mesh/blaze ship
/// with every package, so a missing one is a broken install
/// (IRLUME_MODELS_STRICT rightly refuses). The IR adapter is optional (none
/// ships since ADR-0004; user supplies their own via IRLUME_IR_ADAPTER), so it
/// is included only when the file actually exists; otherwise strict mode would
/// refuse to start on a normal install that never had an adapter.
fn models_to_verify<'a>(shipped: [&'a str; 4], adapter: &'a str) -> Vec<&'a str> {
    let mut v: Vec<&str> = shipped.to_vec();
    if std::path::Path::new(adapter).exists() {
        v.push(adapter);
    }
    v
}

fn main() {
    let det = env_or("IRLUME_DET_MODEL", "/etc/irlume/det.onnx");
    let model = env_or("IRLUME_MODEL", "/etc/irlume/face.onnx");
    let adapter = env_or("IRLUME_IR_ADAPTER", "/etc/irlume/ir_adapter.onnx");
    let mesh = env_or("IRLUME_MESH_MODEL", "/etc/irlume/face_landmark.onnx");
    let blaze = env_or(
        "IRLUME_BLAZE_MODEL",
        "/etc/irlume/blaze_face_short_range.onnx",
    );
    let socket = std::env::var("IRLUME_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());

    eprintln!("irlumed: loading models (det={det}, model={model})…");
    verify_models(&models_to_verify([&det, &model, &mesh, &blaze], &adapter));
    // Auto-select the camera pair: explicit IRLUME_RGB_DEVICE/IR_DEVICE, else a
    // discovered Hello camera (built-in or external Brio/NexiGo), else defaults.
    let (rgb_dev, ir_dev) = irlume_auth::select_pair();
    // Log what is actually usable, not the raw (possibly fallback) selection;
    // on camera-less or RGB-only hardware the fixed default pair doesn't exist.
    {
        let ok = |d: &str| std::path::Path::new(d).exists();
        match (ok(&rgb_dev), ok(&ir_dev)) {
            (true, true) => eprintln!("irlumed: cameras rgb={rgb_dev} ir={ir_dev} (secure tier)"),
            (true, false) => eprintln!(
                "irlumed: camera rgb={rgb_dev}, no IR node (convenience tier: screen unlock only)"
            ),
            (false, _) => eprintln!(
                "irlumed: no camera found (face auth unavailable; password/fingerprint only)"
            ),
        }
    }
    // Self-heal the IR emitter at startup, not just on enroll. The emitter is a
    // camera hardware state that resets on a USB/power cycle or a daemon
    // restart; if the working control was never persisted, the first auth after
    // a restart gets a dark IR frame and fails (exactly the "worked at enroll,
    // failed at the lock screen" case). ensure_ir_emitter fires the known
    // control (env/conf/table) and, only if IR is still dark, runs auto-setup
    // and persists what it finds to ir_emitter.conf, so every later capture,
    // and every later boot, applies it. No-op on RGB-only hardware; best-effort.
    if std::path::Path::new(&ir_dev).exists() {
        match irlume_auth::ensure_ir_emitter(&ir_dev) {
            Ok(true) => eprintln!("irlumed: IR emitter ready"),
            Ok(false) => eprintln!(
                "irlumed: IR still dark after emitter auto-setup (dark-mode unlock may be unavailable)"
            ),
            Err(e) => eprintln!("irlumed: IR emitter check skipped: {e}"),
        }
    }
    // Opt-in third-party PAD cue (`irlume models`): enabled via settings.conf,
    // weights fetched by the CLI to the state dir. Unlike the shipped models'
    // warn-first verification, a third-party file MUST match its catalog pin:
    // on any mismatch the cue is skipped (the built-in gate alone is the safe
    // default), never trusted. Env override for sandboxes.
    let tp_pad: Option<(String, f32, String)> = std::env::var("IRLUME_THIRDPARTY_PAD")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            irlume_common::config::read_kv("settings.conf", irlume_common::thirdparty::SETTINGS_KEY)
        })
        .and_then(|name| {
            let Some(entry) = irlume_common::thirdparty::by_name(name.trim()) else {
                eprintln!("irlumed: WARNING: third_party_pad='{name}' is not in the catalog; ignoring");
                return None;
            };
            let path = irlume_common::thirdparty::model_path(entry);
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!(
                        "irlumed: WARNING: third-party PAD '{name}' enabled but {} unreadable ({e}); cue disabled (run `sudo irlume models enable {name}` to re-fetch)",
                        path.display()
                    );
                    return None;
                }
            };
            let digest = irlume_common::thirdparty::sha256_hex(&bytes);
            if digest != entry.sha256 {
                eprintln!(
                    "irlumed: WARNING: third-party PAD '{name}' checksum mismatch (sha256 {digest}); cue DISABLED, refusing to load unpinned weights"
                );
                return None;
            }
            Some((
                path.to_string_lossy().into_owned(),
                entry.threshold,
                entry.name.to_string(),
            ))
        });
    let mut engine = match irlume_auth::Engine::load(&det, &model)
        .map(|e| e.with_devices(&rgb_dev, &ir_dev))
        .and_then(|e| e.with_ir_adapter(&adapter))
        .and_then(|e| e.with_mesh(&mesh))
        .and_then(|e| e.with_blaze_rescue(&blaze))
        .and_then(|e| match &tp_pad {
            Some((path, thr, name)) => e.with_thirdparty_pad(path, *thr, name),
            None => Ok(e),
        }) {
        Ok(e) => {
            eprintln!(
                "irlumed: IR adapter {}",
                if e.has_ir_adapter() {
                    "loaded"
                } else {
                    "absent (raw IR)"
                }
            );
            eprintln!(
                "irlumed: FaceMesh (passive liveness) {}",
                if e.has_mesh() { "loaded" } else { "absent" }
            );
            eprintln!(
                "irlumed: BlazeFace rescue detector {}",
                if e.has_blaze_rescue() {
                    "loaded"
                } else {
                    "absent"
                }
            );
            match e.thirdparty_pad_name() {
                Some(n) => eprintln!(
                    "irlumed: third-party PAD cue '{n}' loaded (deny-only; disable with `sudo irlume models disable`)"
                ),
                None => eprintln!("irlumed: third-party PAD cue: none (default)"),
            }
            e
        }
        Err(e) => {
            eprintln!("irlumed: failed to load models: {e}");
            std::process::exit(1);
        }
    };

    // One-time inoculation: stamp legacy (untagged) IR scans with the current
    // embedding space while it is still the space they were captured under.
    // A later adapter swap/removal then degrades to a clear "re-enroll" for
    // dark unlock instead of silently scoring across embedding spaces.
    for user in irlume_core::storage::list_users() {
        if let Ok(Some(mut enr)) = irlume_core::storage::load(&user) {
            let n = enr.retag_untagged_ir(engine.ir_space(), engine.ir_dim());
            if n > 0 {
                match irlume_core::storage::save(&enr) {
                    Ok(()) => eprintln!(
                        "irlumed: tagged {n} legacy IR scan(s) for '{user}' as '{}'",
                        engine.ir_space()
                    ),
                    Err(e) => eprintln!("irlumed: could not retag IR scans for '{user}': {e}"),
                }
            }
            // Upgrade notice: IR scans enrolled under a now-absent adapter (e.g.
            // 0.1.x -> 0.2.0, where the research-only IR adapter was removed) are
            // in a foreign embedding space and cannot match. Bright-light RGB
            // login still works; dark/dim login needs a re-enroll. Surfaced here
            // (journal, and `irlume logs`) because the daemon restarts on upgrade.
            // Only an OUTAGE gets the notice: once the user re-enrolls, the fresh
            // usable scans coexist with the stale ones (whose RGB templates still
            // help), and nagging them to re-run the remedy they already ran is
            // noise on every restart.
            let stale = enr.stale_ir_scans(engine.ir_space());
            if stale > 0 && enr.usable_ir_scans(engine.ir_space()) == 0 {
                eprintln!(
                    "irlumed: NOTE for '{user}': {stale} IR template(s) were enrolled under a \
                     removed IR adapter and no longer match. Bright-light face login still works; \
                     run `irlume enroll` to capture fresh scans into your existing profile and \
                     restore dark/dim login."
                );
            }
        }
    }

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
        eprintln!("irlumed: diagnostic tracing ON (IRLUME_LOG=debug): per-stage pipeline lines follow; numbers only, never frames/embeddings");
    }

    // Socket watchdog: if our socket file is deleted/replaced out from under us
    // (a stale-runtime cleanup, a botched reinstall), the bound fd keeps working
    // but no client can ever connect again: a silent outage. Detect it and exit
    // so systemd (Restart=on-failure) re-binds a fresh socket. Self-heals what
    // the Repair tab otherwise needs a manual restart for.
    {
        let socket = socket.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
            if !std::path::Path::new(&socket).exists() {
                eprintln!("irlumed: socket {socket} vanished; exiting for a clean re-bind");
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

// ---------------------------------------------------------------------------
// Consecutive-failure throttle (NIST SP 800-63B-4 s3.2.3 intent).
//
// After a run of failed face attempts, stop firing the camera on the gesture
// for a short cooldown and let PAM fall straight to the password. Deliberately
// a THROTTLE, not a hard biometric-disable: irlume's password is always the
// fallback and there is no account lockout, so the standard's disable-and-
// offer-another-factor tier would only add friction (the "other factor" that
// re-enables face IS the password the throttled user is already typing). Every
// platform (Face ID, Android, Windows Hello) also uses ~5 fails then falls to a
// non-biometric factor. State is per-user and in-memory only; a daemon restart
// clears it (there is nothing to protect on disk since the password is the
// floor). Tunable/testable via env; 0 strikes disables the throttle.
// ---------------------------------------------------------------------------
#[derive(Default)]
struct FailState {
    strikes: u32,
    cooldown_until: Option<std::time::Instant>,
}

fn rate_state() -> &'static std::sync::Mutex<std::collections::HashMap<String, FailState>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, FailState>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn rate_max_strikes() -> u32 {
    env_or("IRLUME_RATE_LIMIT", "5").parse().unwrap_or(5)
}

fn rate_cooldown() -> std::time::Duration {
    std::time::Duration::from_secs(
        env_or("IRLUME_RATE_COOLDOWN_SECS", "30")
            .parse()
            .unwrap_or(30),
    )
}

/// True when `user` is in a cooldown window: skip the camera and fall to the
/// password. Clears an expired window as a side effect.
fn rate_limited(user: &str) -> bool {
    if rate_max_strikes() == 0 {
        return false;
    }
    let mut map = rate_state().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = map.get_mut(user) {
        if let Some(until) = s.cooldown_until {
            if std::time::Instant::now() < until {
                return true;
            }
            s.cooldown_until = None;
            s.strikes = 0;
        }
    }
    false
}

/// Record a face attempt's outcome. A grant resets the user; a rejected real
/// presentation is a strike, and `rate_max_strikes()` of them starts a cooldown.
/// `faced` is the *strike-worthy* signal: it must be true for a genuine failed
/// presentation, which includes a hard spoof rejection (those return
/// `live=false, score=0`, so an earlier `live || score>0` test never struck on
/// the actual attack it is meant to throttle). Callers pass
/// `!presence_retryable(&outcome)`: false only for the retryable no-face /
/// uncertain-liveness outcomes (nobody in frame, walk-away, transient
/// uncertainty), which must never count against the user.
fn rate_record(user: &str, granted: bool, faced: bool) {
    if rate_max_strikes() == 0 {
        return;
    }
    let mut map = rate_state().lock().unwrap_or_else(|e| e.into_inner());
    let s = map.entry(user.to_string()).or_default();
    if granted {
        s.strikes = 0;
        s.cooldown_until = None;
        return;
    }
    if !faced {
        return;
    }
    s.strikes += 1;
    if s.strikes >= rate_max_strikes() {
        s.cooldown_until = Some(std::time::Instant::now() + rate_cooldown());
        s.strikes = 0;
        eprintln!(
            "irlumed: '{user}' hit {} consecutive face failures; face throttled for {}s (password still works)",
            rate_max_strikes(),
            rate_cooldown().as_secs()
        );
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
    // gid/pid are unread today; kept for future audit logging, since
    // SO_PEERCRED delivers all three fields in the same getsockopt call.
    #[allow(dead_code)]
    gid: u32,
    #[allow(dead_code)]
    pid: i32,
}

fn peer_cred(stream: &UnixStream) -> std::io::Result<Peer> {
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(Peer {
        uid: ucred.uid,
        gid: ucred.gid,
        pid: ucred.pid,
    })
}

/// Only root or the target user themselves may enroll/delete that user's data.
fn authorized_for(peer: &Peer, target_user: &str) -> bool {
    peer.uid == 0 || uid_of(target_user).is_some_and(|u| u == peer.uid)
}

// libxcrypt's one-way hash (glibc moved `crypt` out of libc into libcrypt).
#[link(name = "crypt")]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Verify `password` against `user`'s `/etc/shadow` hash so `keyring arm` can
/// reject a password that is not the current LOGIN password (the cause of the
/// later "-9" wallet-key-derive failure: the face path jumps over pam_unix, so a
/// wrong seal is never caught at auth time, only when ksecretd tries to open the
/// wallet). Returns `Some(true/false)` on a verifiable hash, or `None` when it
/// cannot verify (no `/etc/shadow` access, no such user, or a locked / empty /
/// non-password field), in which case the caller does NOT block, since absence
/// of proof is not proof of a wrong password. Root-only (`/etc/shadow`).
fn password_matches_login(user: &str, password: &[u8]) -> Option<bool> {
    let shadow = std::fs::read_to_string("/etc/shadow").ok()?;
    let stored = verifiable_shadow_hash(&shadow, user)?;
    // An interior NUL can't be a shadow password; treat as unverifiable.
    let key = std::ffi::CString::new(password).ok()?;
    let setting = std::ffi::CString::new(stored.as_str()).ok()?;
    // SAFETY: single-threaded daemon (crypt's static buffer is not shared); the
    // pointers are valid NUL-terminated C strings for the call's duration.
    let out = unsafe { crypt(key.as_ptr(), setting.as_ptr()) };
    if out.is_null() {
        return None; // unsupported hash format on this libcrypt
    }
    let computed = unsafe { std::ffi::CStr::from_ptr(out) };
    Some(computed.to_bytes() == stored.as_bytes())
}

/// The user's VERIFIABLE `/etc/shadow` hash, or `None` when there is nothing to
/// verify against: the user is absent, or the field is empty / locked (`!`,
/// `!!`) / disabled (`*`). Pure (takes the shadow text) so the "don't block on
/// an unverifiable account" rule is unit-tested.
fn verifiable_shadow_hash(shadow: &str, user: &str) -> Option<String> {
    let stored = shadow.lines().find_map(|line| {
        let mut f = line.split(':');
        (f.next()? == user).then(|| f.next().map(str::to_string))?
    })?;
    (!stored.is_empty() && !stored.starts_with('!') && !stored.starts_with('*')).then_some(stored)
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
    match read_request(&stream)? {
        ReadOutcome::Closed => Ok(()),
        ReadOutcome::Bad => respond(stream, &Response::Error("bad request".into())),
        ReadOutcome::Req(req) => {
            let resp = dispatch(req, &peer, engine);
            respond(stream, &resp)
        }
    }
}

/// One parsed request line off the wire (see [`read_request`]).
#[cfg_attr(test, derive(Debug))] // tests unwrap_err() around it; not needed at runtime
enum ReadOutcome {
    /// Peer closed without sending a line.
    Closed,
    /// The line did not parse; the caller answers a generic "bad request"
    /// (never echoing the peer's raw bytes / parser internals back).
    Bad,
    Req(Request),
}

/// Read one request line (bounded by [`MAX_REQUEST_BYTES`]) and parse it.
/// Extracted verbatim from [`handle`] (test seam: exercised over a socketpair
/// without an [`irlume_auth::Engine`]); behavior unchanged.
fn read_request(stream: &UnixStream) -> std::io::Result<ReadOutcome> {
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_REQUEST_BYTES);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(ReadOutcome::Closed);
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(_) => {
            line.zeroize();
            return Ok(ReadOutcome::Bad);
        }
    };
    // The line may hold a plaintext secret (SealPassword/RecoverySetup); wipe it
    // now that it's parsed into the zeroizing SecretBytes.
    line.zeroize();
    Ok(ReadOutcome::Req(req))
}

/// A username is interpolated into `<user>.json` paths (enrollment, sealed key,
/// keyring). Reject anything that could traverse or escape the state dir before
/// any path is built; defence-in-depth on top of the NSS `authorized_for` check.
fn valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with(['-', '.'])
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
}

/// The `user` field of a request, if it carries one (for the traversal guard).
fn request_user(req: &Request) -> Option<&str> {
    use Request::*;
    match req {
        Authenticate { user, .. }
        | Enroll { user, .. }
        | ListProfiles { user }
        | DeleteProfile { user, .. }
        | DeleteScan { user, .. }
        | RenameProfile { user, .. }
        | RenameScan { user, .. }
        | AddScan { user, .. }
        | SetRequireEyesOpen { user, .. }
        | SetRequireChallenge { user, .. }
        | CaptureEarMedian { user }
        | SetClosureCalibration { user, .. }
        | SealPassword { user, .. }
        | UnsealPassword { user, .. }
        | UnsealKeyring { user, .. }
        | HasSealedPassword { user }
        | KeyringInfo { user }
        | ForgetPassword { user }
        | ResealPassword { user, .. }
        | RecoveryStatus { user }
        | RecoverySetup { user, .. }
        | RecoveryRestore { user, .. }
        | RecoveryForget { user } => Some(user.as_str()),
        // Framing guide: the (optional) user only tunes the pitch band, but it's
        // still interpolated into a state path, so validate it like the rest.
        PositionSample { user: Some(u) } => Some(u.as_str()),
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
            // when they actually exist; never the unvalidated fallback pair.
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
                // Authoritative loaded-cue name so a non-root TUI can show the
                // real on/off state (settings.conf is root-only).
                third_party_pad: engine.thirdparty_pad_name().map(String::from),
            }
        }
        // Only tune the band to a user the peer may act for (root, or their own
        // account); else ignore it. Stops a non-root peer forcing a per-poll TPM
        // unseal of another user's (e.g. root's) enrollment via the framing guide.
        Request::PositionSample { user } => {
            match engine.position_sample(user.as_deref().filter(|u| authorized_for(peer, u))) {
                Ok(r) => Response::Position(r),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::Authenticate { user, service } => {
            // Root (PAM stacks) or the account owner only. Without this gate any
            // local peer could probe Authenticate{other_user} and read the raw
            // similarity score, a hill-climbing oracle toward a match (the
            // threat model promises scores never leak to unprivileged peers).
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to authenticate '{user}'"));
            }
            // Honor the configured unlock method: if the admin chose fingerprint,
            // face must actually stand down (pam_fprintd drives; password is the
            // fallback), not just be claimed disabled by the CLI message.
            if irlume_core::policy::method().face_disabled() {
                return Response::AuthResult {
                    granted: false,
                    score: 0.0,
                    live: false,
                    reason: "face auth disabled: the configured method is fingerprint".into(),
                };
            }
            // Smart-Auto tier gate: on a CONVENIENCE (RGB-only) device, a face
            // match may ONLY satisfy a screen unlock; never login, elevation, or
            // a remote/unknown service (those keep the password). Always-on for
            // RGB-only hardware (independent of the opt-in biopolicy for IR boxes).
            if engine.tier() == irlume_core::biopolicy::Tier::Convenience {
                use irlume_core::biopolicy::{classify, OperationClass, SessionState};
                // Warm = the user already has a running session (their systemd
                // runtime dir exists); then an ambiguous greeter service (GDM
                // drives cold login AND the lock screen through gdm-password) is
                // a screen unlock, not a login. Caveat: lingering user services
                // also create /run/user/<uid>; acceptable for the convenience
                // tier where the worst case is unlocking a lock screen.
                let session = users::uid_for_name(&user)
                    .map(|uid| std::path::Path::new(&format!("/run/user/{uid}")).exists())
                    .map(|has_runtime_dir| {
                        if has_runtime_dir {
                            SessionState::Warm
                        } else {
                            SessionState::Cold
                        }
                    })
                    .unwrap_or(SessionState::Cold);
                let class = classify(service.as_deref().unwrap_or(""), session);
                if class != OperationClass::ScreenUnlock {
                    eprintln!("irlumed: convenience(RGB-only) denies face for '{}' ({class:?}) -> password", service.as_deref().unwrap_or("?"));
                    return Response::AuthResult {
                        granted: false,
                        score: 0.0,
                        live: false,
                        reason: format!(
                            "RGB-only convenience: face limited to screen unlock (not {class:?})"
                        ),
                    };
                }
            }
            // Opt-in biopolicy also gates identity VERIFICATION on IR/Secure
            // hardware (mirrors the credential-release gate); else a face grant
            // for a Remote/Unknown service would bypass the "face never satisfies
            // remote" invariant. Off by default (behaviour unchanged).
            if biopolicy_enforced() && engine.tier() != irlume_core::biopolicy::Tier::Convenience {
                use irlume_core::biopolicy::{classify, decide, Action, SessionState, Tier};
                let svc = service.as_deref().unwrap_or("");
                if decide(classify(svc, SessionState::Cold), Tier::Secure) == Action::Deny {
                    eprintln!("irlumed: biopolicy denies verify for service '{svc}' -> password");
                    return Response::AuthResult {
                        granted: false,
                        score: 0.0,
                        live: false,
                        reason: format!("biopolicy: face may not satisfy '{svc}'"),
                    };
                }
            }
            // Too many recent failures: don't fire the camera, fall to password.
            if rate_limited(&user) {
                return Response::AuthResult {
                    granted: false,
                    score: 0.0,
                    live: false,
                    reason: "too many recent face attempts; use your password".into(),
                };
            }
            let convenience = engine.tier() == irlume_core::biopolicy::Tier::Convenience;
            let t = std::time::Instant::now();
            match engine.authenticate(&user, service.as_deref()) {
                Ok(o) => {
                    rate_record(&user, o.granted, !irlume_auth::presence_retryable(&o));
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
                    Response::AuthResult {
                        granted: o.granted,
                        score: o.score,
                        live: o.live,
                        reason: o.reason,
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::Identify => {
            // 1:N identify returns an exact similarity score, so an ungated
            // socket peer could hill-climb it to tune a spoof or enumerate who
            // is enrolled. Root keeps the full cross-user search (admin/test);
            // a non-root peer is scoped to its OWN account; the score then only
            // concerns a face the caller already controls, not other users'.
            let scoped = match identify_scope(peer) {
                IdentifyScope::Full => engine.identify(),
                IdentifyScope::SelfOnly(name) => engine.identify_within(&name),
                IdentifyScope::NoAccount => Ok(irlume_auth::IdentifyOutcome {
                    user: None,
                    profile: None,
                    score: 0.0,
                    live: false,
                    reason: "caller has no local account".into(),
                }),
            };
            match scoped {
                Ok(o) => Response::Identified {
                    user: o.user,
                    profile: o.profile,
                    score: o.score,
                    live: o.live,
                    reason: o.reason,
                },
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::SetCameras { rgb, ir } => {
            // Persists to /etc and repoints the camera the daemon trusts; an
            // attacker who could set this to a v4l2loopback node feeds recorded
            // video into the match path (spoof) or bricks face auth (DoS). Root
            // only (a system-wide /etc setting isn't an arbitrary peer's to make).
            if peer.uid != 0 {
                return Response::Error(format!(
                    "set_cameras requires root (peer uid {})",
                    peer.uid
                ));
            }
            engine.set_devices(&rgb, &ir);
            let mut msg = format!("cameras set to rgb={rgb} ir={ir}");
            if let Err(e) = irlume_common::config::write_kv("cameras.conf", "rgb", &rgb)
                .and_then(|_| irlume_common::config::write_kv("cameras.conf", "ir", &ir))
            {
                msg = format!("{msg} (live only; could not persist: {e})");
            }
            eprintln!("irlumed: {msg}");
            Response::Ok(msg)
        }
        Request::Enroll {
            user,
            profile,
            scans,
            reset,
        } => {
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
            // cleanly; only runs the brute-force if IR is actually dark.
            match irlume_auth::ensure_ir_emitter(engine.ir_device()) {
                Ok(true) => {}
                Ok(false) => eprintln!("irlumed: IR still dark after auto-setup; enrolling RGB (dark unlock unavailable)"),
                Err(e) => eprintln!("irlumed: IR emitter auto-setup skipped: {e}"),
            }
            match engine.enroll_profile(&user, profile, want) {
                Ok(outcome) => enroll_response(outcome),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::SetupIrEmitter { dry_run } => {
            // Hardware fix on the shared camera; non-destructive on failure.
            if dry_run {
                match irlume_auth::list_ir_controls(engine.ir_device()) {
                    Ok(c) if c.is_empty() => {
                        Response::Ok("no UVC extension-unit controls found".into())
                    }
                    Ok(c) => Response::Ok(format!(
                        "XU controls: {}",
                        c.iter()
                            .map(|(u, s, l)| format!("unit{u}/sel{s}/{l}B"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    Err(e) => Response::Error(e.to_string()),
                }
            } else {
                // The non-dry path brute-forces UVC control writes on the shared
                // camera; a local peer could thrash the hardware. Root only.
                if peer.uid != 0 {
                    return Response::Error(format!(
                        "setup_ir_emitter requires root (peer uid {})",
                        peer.uid
                    ));
                }
                match irlume_auth::setup_ir_emitter(engine.ir_device()) {
                    Ok(msg) => {
                        eprintln!("irlumed: {msg}");
                        Response::Ok(msg)
                    }
                    Err(e) => Response::Error(e.to_string()),
                }
            }
        }
        Request::AddScan { user, profile } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            match engine.add_scan(&user, &profile) {
                Ok((scan, total)) => {
                    Response::Ok(format!("added '{scan}' to '{profile}' ({total} scans)"))
                }
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
            // Refuse to seal a password that is not the user's LOGIN password:
            // it would seal cleanly but fail later at wallet key-derive ("-9").
            // Only a POSITIVE mismatch blocks; an unverifiable hash proceeds.
            if password_matches_login(&user, password.expose()) == Some(false) {
                return Response::Error(format!(
                    "that is not '{user}'s current login password; the keyring is unlocked with \
                     the login password, so arming a different one would leave the wallet locked"
                ));
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
                return Response::Error(format!(
                    "unseal_password requires root (peer uid {})",
                    peer.uid
                ));
            }
            // Same method gate as Authenticate: fingerprint-configured means no
            // face-driven credential release either.
            if irlume_core::policy::method().face_disabled() {
                return Response::Error(
                    "face auth disabled: the configured method is fingerprint".into(),
                );
            }
            // ALWAYS-ON: a polkit prompt never releases the sealed credential,
            // independent of the tier and the opt-in biopolicy below. The
            // polkit agent runs its PAM conversation with no user gesture, so a
            // `unseal`-arg line (mis)wired into polkit-1 must not be able to
            // pull the login password out of the TPM; polkit gets verify-only
            // (Authenticate).
            {
                use irlume_core::biopolicy::{classify, OperationClass, SessionState};
                let svc = service.as_deref().unwrap_or("");
                if classify(svc, SessionState::Cold) == OperationClass::AppConsent {
                    eprintln!("irlumed: UnsealPassword refused for polkit service '{svc}' (verify-only class)");
                    return Response::Error(format!(
                        "'{svc}' is verify-only: a polkit prompt never releases the credential"
                    ));
                }
            }
            // Smart-Auto: an RGB-only (convenience) device NEVER releases the
            // sealed credential: no cold-login / keyring unlock by RGB-only face.
            if engine.tier() == irlume_core::biopolicy::Tier::Convenience {
                eprintln!("irlumed: convenience(RGB-only) refuses credential release for '{user}' -> password");
                return Response::Error(
                    "RGB-only convenience: face cannot release the login credential".into(),
                );
            }
            // Opt-in biopolicy: when enforcement is enabled, gate credential
            // release by the PAM service's operation class (e.g. refuse a remote
            // / unknown service). Default off → unchanged behaviour.
            if biopolicy_enforced() {
                use irlume_core::biopolicy::{classify, decide, Action, SessionState, Tier};
                let svc = service.as_deref().unwrap_or("");
                // UnsealPassword is the cold-login path (the lock screen uses
                // verify-only `wait`), so Cold. irlume's liveness already
                // requires IR for any grant, so a granted match is Secure tier.
                let action = decide(classify(svc, SessionState::Cold), Tier::Secure);
                if action != Action::Unseal {
                    eprintln!("irlumed: biopolicy denies unseal for service '{svc}' ({action:?}) -> password");
                    return Response::Error(format!(
                        "biopolicy: '{svc}' may not release the credential"
                    ));
                }
            }
            do_unseal_password(&user, service.as_deref(), engine)
        }
        Request::UnsealKeyring { user, service } => {
            // Fingerprint keyring unlock. pam_fprintd has ALREADY authenticated
            // the user in this PAM transaction (pam_irlume `keyring` only runs at
            // the post-auth landing). The daemon can't re-verify a fingerprint
            // (fprintd owns the sensor), so the trust is: root peer + a login /
            // unlock service class. Releases the sealed login password so
            // pam_gnome_keyring can open the wallet, matching Windows Hello's
            // functional model. SECURITY (ADR-0003 / THREAT_MODEL): preserves
            // at-rest protection (a stolen disk still can't unseal; it needs the
            // live TPM), but a live root attacker in a login context can obtain
            // it; root stays the trust boundary. For daemon-verified biometric
            // release resistant to live root, use the face/IR path.
            if peer.uid != 0 {
                return Response::Error(format!(
                    "unseal_keyring requires root (peer uid {})",
                    peer.uid
                ));
            }
            if !irlume_core::keyring::has_sealed_password(&user) {
                return Response::Error(format!(
                    "no sealed password for '{user}': run `irlume keyring arm`"
                ));
            }
            // Only a login / greeter / lock-screen context; never sudo,
            // elevation, remote, or unknown. Defence-in-depth: a direct caller
            // can forge the service string (root can call us directly), so this
            // does not stop a root attacker; it does stop the keyring line being
            // (mis)wired into a non-login stack from releasing the credential.
            {
                use irlume_core::biopolicy::{classify, OperationClass, SessionState};
                let class = classify(service.as_deref().unwrap_or(""), SessionState::Warm);
                if !matches!(class, OperationClass::ScreenUnlock | OperationClass::Login) {
                    eprintln!(
                        "irlumed: UnsealKeyring refused for service '{}' ({class:?})",
                        service.as_deref().unwrap_or("?")
                    );
                    return Response::Error(format!("keyring unseal not allowed for {class:?}"));
                }
            }
            match irlume_core::keyring::unseal_password(&user) {
                Ok(secret) => {
                    eprintln!("irlumed: UnsealKeyring: OK for '{user}' (fingerprint-authenticated), password unsealed");
                    Response::PasswordUnsealed {
                        secret: irlume_common::SecretBytes::new(secret.to_vec()),
                    }
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
        Request::KeyringInfo { user } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to query '{user}'"));
            }
            let armed = irlume_core::keyring::has_sealed_password(&user);
            let path = irlume_core::keyring::envelope_path(&user);
            match irlume_core::envelope::SealedEnvelope::load(&path) {
                Ok(env) => Response::KeyringInfo {
                    armed,
                    policy: Some(env.policy.describe()),
                    pcrs: env.pcrs.clone(),
                    // None when the envelope carries no PCR snapshot or the
                    // replay failed; the CLI then just omits the drift note.
                    drifted: irlume_core::tpm::diagnose_pcrs(&env)
                        .ok()
                        .filter(|_| !env.pcr_values.is_empty())
                        .map(|d| !d.is_empty()),
                },
                // Not armed, or the envelope is unreadable/corrupt: report the
                // armed bit alone rather than failing the whole query.
                Err(_) => Response::KeyringInfo {
                    armed,
                    policy: None,
                    pcrs: Vec::new(),
                    drifted: None,
                },
            }
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
            // password against today's PCRs; it never arms a fresh user, so a
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
                    } else if outcome == Reseal::Upgraded {
                        eprintln!(
                            "irlumed: ResealPassword: upgraded '{user}' keyring seal to a stronger TPM policy tier (no re-arm needed)"
                        );
                    }
                    Response::PasswordResealed {
                        // Both Resealed (self-heal) and Upgraded (tier climb)
                        // changed the on-disk envelope.
                        armed: outcome != Reseal::NotArmed,
                        changed: outcome == Reseal::Resealed || outcome == Reseal::Upgraded,
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
            // and seal a template key now by re-saving; encryption takes effect
            // and there's a key for the recovery passphrase to wrap. A no-op when
            // already encrypted or when the user isn't enrolled.
            if !irlume_core::template_key::has_key(&user) {
                if let Ok(Some(enr)) = irlume_core::storage::load(&user) {
                    if let Err(e) = irlume_core::storage::save(&enr) {
                        return Response::Error(format!(
                            "could not encrypt existing templates: {e}"
                        ));
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
                    eprintln!(
                        "irlumed: RecoveryRestore: re-sealed '{user}' template key to current PCRs"
                    );
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
                    profiles: enr
                        .profiles
                        .iter()
                        .map(|p| irlume_common::ProfileSummary {
                            name: p.name.clone(),
                            scans: p.scans.iter().map(|s| s.name.clone()).collect(),
                        })
                        .collect(),
                    require_eyes_open: enr.require_eyes_open,
                    require_challenge: enr.require_challenge,
                    closure_calibrated: enr
                        .closure_calibration
                        .map(|(o, c)| {
                            irlume_liveness::ClosureCalibration {
                                ear_open: o,
                                ear_closed: c,
                            }
                            .is_usable()
                        })
                        .unwrap_or(false),
                },
                Ok(None) => Response::Enrollment {
                    profiles: vec![],
                    require_eyes_open: false,
                    require_challenge: false,
                    closure_calibrated: false,
                },
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
        Request::DeleteScan {
            user,
            profile,
            scan,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let p = enr
                    .profiles
                    .iter_mut()
                    .find(|p| p.name == profile)
                    .ok_or(format!("no face profile '{profile}'"))?;
                let before = p.scans.len();
                p.scans.retain(|s| s.name != scan);
                if p.scans.len() == before {
                    Err(format!("no scan '{scan}' in '{profile}'"))
                } else if p.scans.is_empty() {
                    Err("a profile must keep at least one scan; delete the profile instead".into())
                } else {
                    Ok(format!("deleted scan '{scan}' from '{profile}'"))
                }
            })
        }
        Request::RenameProfile {
            user,
            profile,
            new_name,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                if enr.profiles.iter().any(|p| p.name == new_name) {
                    return Err(format!("'{new_name}' already exists"));
                }
                let p = enr
                    .profiles
                    .iter_mut()
                    .find(|p| p.name == profile)
                    .ok_or(format!("no face profile '{profile}'"))?;
                p.name = new_name.clone();
                Ok(format!("renamed profile to '{new_name}'"))
            })
        }
        Request::RenameScan {
            user,
            profile,
            scan,
            new_name,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                let p = enr
                    .profiles
                    .iter_mut()
                    .find(|p| p.name == profile)
                    .ok_or(format!("no face profile '{profile}'"))?;
                if p.scans.iter().any(|s| s.name == new_name) {
                    return Err(format!("'{new_name}' already exists in '{profile}'"));
                }
                let s = p
                    .scans
                    .iter_mut()
                    .find(|s| s.name == scan)
                    .ok_or(format!("no scan '{scan}' in '{profile}'"))?;
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
                Ok(format!(
                    "require-eyes-open {}",
                    if on { "ENABLED" } else { "disabled" }
                ))
            })
        }
        Request::SetRequireChallenge { user, on } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                enr.require_challenge = on;
                Ok(format!(
                    "require-challenge {}",
                    if on { "ENABLED" } else { "disabled" }
                ))
            })
        }
        Request::CaptureEarMedian { user: _ } => {
            // Fires the camera; root-gate like the other camera-bearing requests
            // (on the 0666 socket fallback this is what keeps other uids out).
            if peer.uid != 0 {
                return Response::Error(format!(
                    "capture_ear_median requires root (peer uid {})",
                    peer.uid
                ));
            }
            // ~3s window: enough frames for a stable median of the current eye
            // state (open or closed, whichever the caller is prompting).
            const CAL_FRAMES: usize = 45;
            match engine.capture_ear_samples(CAL_FRAMES) {
                Ok(samples) => Response::EarMedian(irlume_liveness::calibrate_open_ear(&samples)),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::SetClosureCalibration {
            user,
            ear_open,
            ear_closed,
        } => {
            if !authorized_for(peer, &user) {
                return Response::Error(format!("not authorized to modify '{user}'"));
            }
            mutate_enrollment(&user, |enr| {
                enr.closure_calibration = Some((ear_open, ear_closed));
                Ok(format!(
                    "closure calibration stored (open {ear_open:.3}, closed {ear_closed:.3})"
                ))
            })
        }
        Request::SelfTest { kind } => {
            // Fires the camera and returns raw liveness/alignment measurements
            // (IR brightness, depth, glint), which are a spoof-tuning oracle and
            // a way to tie up the single-threaded daemon. Gate to root, like the
            // other camera-bearing requests; on the 0666 socket fallback this is
            // the only thing keeping an arbitrary local uid out.
            if peer.uid != 0 {
                return Response::Error(format!("self_test requires root (peer uid {})", peer.uid));
            }
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

/// How a peer's 1:N Identify is scoped. Root keeps the full cross-user search;
/// any other peer is confined to its own account (or to nothing at all), so
/// the returned similarity score never concerns a face the caller does not
/// already control.
#[derive(Debug, PartialEq, Eq)]
enum IdentifyScope {
    /// Full cross-user search (root only).
    Full,
    /// Scoped to the peer's own username.
    SelfOnly(String),
    /// The peer resolves to no local account; identify matches no one.
    NoAccount,
}

fn identify_scope(peer: &Peer) -> IdentifyScope {
    if peer.uid == 0 {
        return IdentifyScope::Full;
    }
    match users::name_for_uid(peer.uid) {
        Some(name) => IdentifyScope::SelfOnly(name),
        None => IdentifyScope::NoAccount,
    }
}

/// Map an engine enroll outcome onto the wire response. A merge into an
/// existing profile MUST report `created: false`: the TUI's split-capture
/// worker keys off it to stop and confirm, instead of sending the remaining
/// AddScans to a profile that was never created.
fn enroll_response(outcome: irlume_auth::EnrollOutcome) -> Response {
    match outcome {
        irlume_auth::EnrollOutcome::New { name, scans } => Response::Enrolled {
            profile: name,
            created: true,
            added: scans,
            total: scans,
            added_scans: Vec::new(),
        },
        irlume_auth::EnrollOutcome::Merged {
            name,
            added,
            total,
            added_scans,
        } => Response::Enrolled {
            profile: name,
            created: false,
            added,
            total,
            added_scans,
        },
    }
}

/// Load `user`'s enrollment, apply `f`, and save. `f` returns an Ok message or an
/// error string. Used by the storage-only management operations.
fn mutate_enrollment(
    user: &str,
    f: impl FnOnce(&mut irlume_core::storage::Enrollment) -> Result<String, String>,
) -> Response {
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
/// quantized to one decimal (anti-oracle; see comment at the deny log).
fn deny_score(s: f32) -> String {
    if irlume_common::dbglog::on() {
        format!("{s:.4}")
    } else {
        format!("~{s:.1}")
    }
}

/// Prose tokens that legitimately contain digits and must survive redaction:
/// dimension labels and the emitter wavelength. FAIL-CLOSED: the redactor keeps
/// ONLY these exact tokens; every other number (including a future unit-suffixed
/// measurement like `12ms` or `3px`) is stripped by default, so adding a new
/// numeric cue to a deny reason can't silently defeat the redaction.
const REASON_PROSE_KEEP: &[&str] = &["2D", "3D", "850nm"];

/// Journal-side deny-reason display. Deny reasons embed measured values
/// ("IR too flat (1.02)", "rgb 0.35") as coaching for a genuine false reject,
/// but in the JOURNAL those same numbers are per-attempt feedback a spoofer
/// could tune against. The exact reason still goes back over IPC to the
/// session's own TUI/CLI; here we strip every numeric payload unless tracing is
/// on, keeping only the [`REASON_PROSE_KEEP`] tokens.
fn deny_reason(r: &str) -> String {
    if irlume_common::dbglog::on() {
        return r.to_string();
    }
    let cs: Vec<char> = r.chars().collect();
    let mut out = String::with_capacity(r.len());
    let mut i = 0;
    while i < cs.len() {
        if cs[i].is_ascii_digit() {
            // Grab the number, then any glued alpha suffix (a unit or a prose
            // tail like the "D" in "2D") so we can test the whole token.
            let start = i;
            while i < cs.len() && (cs[i].is_ascii_digit() || cs[i] == '.') {
                i += 1;
            }
            let mut num_end = i;
            while num_end > start && cs[num_end - 1] == '.' {
                num_end -= 1;
            } // sentence period, not a decimal
            let mut tok_end = num_end;
            while tok_end < cs.len() && cs[tok_end].is_ascii_alphabetic() {
                tok_end += 1;
            }
            let token: String = cs[start..tok_end].iter().collect();
            // An identifier (digits glued AFTER letters, e.g. "PCR7") is a name,
            // not a measurement; keep it. Otherwise keep only allowlisted prose.
            let is_ident = start > 0 && cs[start - 1].is_ascii_alphabetic();
            if is_ident || REASON_PROSE_KEEP.contains(&token.as_str()) {
                out.extend(&cs[start..tok_end]);
                i = tok_end;
            } else {
                out.push('…');
                out.extend(&cs[num_end..i]); // keep a trailing '.' that was a sentence period
            }
        } else {
            out.push(cs[i]);
            i += 1;
        }
    }
    out
}

fn do_unseal_password(
    user: &str,
    service: Option<&str>,
    engine: &mut irlume_auth::Engine,
) -> Response {
    eprintln!("irlumed: UnsealPassword: attempt for '{user}'");
    let t = std::time::Instant::now();
    if !irlume_core::keyring::has_sealed_password(user) {
        return Response::Error(format!(
            "no sealed password for '{user}': run `irlume keyring arm`"
        ));
    }
    // Same failure throttle as the login/sudo path: after a run of failures,
    // skip the camera and let PAM fall to the password.
    if rate_limited(user) {
        return Response::Error("too many recent face attempts; use your password".into());
    }
    let outcome = match engine.authenticate(user, service) {
        Ok(o) => o,
        Err(e) => {
            // A PCR-drift here is the ENROLLED-TEMPLATE key failing to unseal (it
            // is TPM-sealed to the same PCRs), so the daemon can't decrypt the face
            // to match at all: face auth is locked until the template key is
            // re-bound. `keyring arm` won't fix it (that only re-seals the
            // password); the user must re-enroll or run `irlume recovery restore`.
            let hint = if is_pcr_drift(&e) {
                " -- a firmware/Secure Boot change locked your enrolled face; re-enroll or run `irlume recovery restore`"
            } else {
                ""
            };
            eprintln!("irlumed: UnsealPassword: capture/auth failed for '{user}': {e}{hint}");
            return Response::Error(e.to_string());
        }
    };
    rate_record(
        user,
        outcome.granted,
        !irlume_auth::presence_retryable(&outcome),
    );
    if !outcome.granted {
        // Denied-attempt scores are QUANTIZED to one decimal unless tracing is
        // on: a 4-decimal score after every try is a gradient a journal-reading
        // attacker could climb to tune a spoof. One decimal still separates
        // "borderline" from "not even close" for false-reject diagnosis.
        eprintln!(
            "irlumed: UnsealPassword: denied for '{user}' (live={}, score {}: {}) -> password",
            outcome.live,
            deny_score(outcome.score),
            deny_reason(&outcome.reason)
        );
        return Response::Error(format!("face not granted: {}", outcome.reason));
    }
    match irlume_core::keyring::unseal_password(user) {
        Ok(secret) => {
            eprintln!(
                "irlumed: UnsealPassword: OK for '{user}' (score {:.4}), password unsealed",
                outcome.score
            );
            irlume_common::dlog!(
                "unseal '{user}' total {}ms (face + TPM)",
                t.elapsed().as_millis()
            );
            Response::PasswordUnsealed {
                secret: irlume_common::SecretBytes::new(secret.to_vec()),
            }
        }
        // Face matched but the TPM could not release the secret (e.g. PCR drift
        // after a Secure Boot config change). This is the line that explains a
        // face login that nonetheless leaves the keyring locked.
        Err(e) => {
            // Here the template key unsealed (face matched) but the PASSWORD seal
            // did not. A PCR drift on this path is fixed by re-binding the password
            // with `irlume keyring arm` (the enrolled face still works).
            let hint = if is_pcr_drift(&e) {
                " -- re-run `irlume keyring arm` to re-bind the password to the current PCRs"
            } else {
                ""
            };
            eprintln!(
                "irlumed: UnsealPassword: face matched for '{user}' (score {:.4}) but TPM unseal FAILED: {e}{hint}",
                outcome.score
            );
            Response::Error(e.to_string())
        }
    }
}

/// A PCR-drift unseal failure (Secure Boot / firmware / dbx change moved a bound
/// PCR). [`irlume_core::tpm`] tags these where the error is built, so the
/// daemon can print the right remedy without re-reading the TPM.
fn is_pcr_drift(e: &irlume_common::Error) -> bool {
    irlume_core::tpm::is_pcr_mismatch(e)
}

fn respond(mut stream: UnixStream, resp: &Response) -> std::io::Result<()> {
    let mut json = serde_json::to_vec(resp)?;
    json.push(b'\n');
    stream.write_all(&json)?;
    let r = stream.flush();
    // The response may carry an unsealed secret (PasswordUnsealed); wipe the
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
    fn verifiable_shadow_hash_extracts_and_skips_unverifiable() {
        let shadow = "root:$6$abc$hash:19000:0:99999:7:::\n\
                      alice:$y$j9T$salt$realhash:19000::::::\n\
                      locked:!$6$x$y:19000::::::\n\
                      disabled:*:19000::::::\n\
                      nopw::19000::::::\n";
        // A real hash comes back for verification.
        assert_eq!(
            verifiable_shadow_hash(shadow, "alice").as_deref(),
            Some("$y$j9T$salt$realhash")
        );
        // Locked / disabled / empty / absent all read None → the caller must NOT
        // block the seal (absence of proof is not proof of a wrong password).
        for u in ["locked", "disabled", "nopw", "ghost"] {
            assert_eq!(verifiable_shadow_hash(shadow, u), None, "{u}");
        }
    }

    #[test]
    fn is_pcr_drift_matches_the_real_error_shape() {
        use irlume_common::Error;
        // The exact message tpm::policy_aware_err produces on a PCR move.
        let drift = Error::Policy(
            "a policy check failed (associated with session number 1): PCR mismatch: [7] changed since seal".into(),
        );
        assert!(is_pcr_drift(&drift));
        // A generic policy error (e.g. no signed policy) is NOT a drift.
        assert!(!is_pcr_drift(&Error::Policy(
            "no signed PCR policy matches".into()
        )));
        // A non-policy TPM error (corrupt blob, TPM cleared) is not a drift either.
        assert!(!is_pcr_drift(&Error::Tpm(
            "structure is the wrong size".into()
        )));
    }

    #[test]
    fn root_and_self_authorized_others_denied() {
        let root = Peer {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        // uid_of relies on /etc/passwd; just exercise the root path deterministically.
        assert!(authorized_for(&root, "nonexistent-user"));
    }

    // Regression: d793a27. Request::Identify was an unauthenticated 1:N
    // similarity oracle: any local peer got a cross-user search plus the exact
    // score. Root keeps the full search; a non-root peer is scoped to its own
    // account; a peer with no local account gets no search at all.
    #[test]
    fn identify_scope_confines_non_root_peers_to_their_own_account() {
        let peer = |uid| Peer {
            uid,
            gid: uid,
            pid: 1,
        };
        assert_eq!(identify_scope(&peer(0)), IdentifyScope::Full);
        // The uid running this test resolves to a real account; its scope must
        // be exactly that username, never Full.
        let me = unsafe { libc::geteuid() };
        if me != 0 {
            let name = users::name_for_uid(me).expect("test uid has an account");
            assert_eq!(identify_scope(&peer(me)), IdentifyScope::SelfOnly(name));
        }
        // A uid outside the account database is denied any scope.
        assert_eq!(identify_scope(&peer(0xfffe_fffe)), IdentifyScope::NoAccount);
        // Ground the reverse lookup itself (added by the same fix).
        assert_eq!(users::name_for_uid(0).as_deref(), Some("root"));
    }

    // Regression: 834c71e. IRLUME_MODELS_STRICT=1 refused to start because the
    // daemon still verified the OPTIONAL IR adapter at its default path even
    // though none ships since ADR-0004. A missing adapter must be excluded
    // from verification; a present one is still verified.
    #[test]
    fn missing_optional_adapter_is_not_verified() {
        let shipped = [
            "/etc/irlume/det.onnx",
            "/etc/irlume/face.onnx",
            "/etc/irlume/face_landmark.onnx",
            "/etc/irlume/blaze_face_short_range.onnx",
        ];
        assert_eq!(
            models_to_verify(shipped, "/nonexistent/irlume-test/ir_adapter.onnx"),
            shipped.to_vec(),
            "a missing optional adapter must not reach verify_models"
        );
        // An adapter that actually exists is still checked.
        let dir =
            std::env::temp_dir().join(format!("irlume-daemon-adapter-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let adapter = dir.join("ir_adapter.onnx");
        std::fs::write(&adapter, b"weights").unwrap();
        let ap = adapter.to_string_lossy().into_owned();
        let v = models_to_verify(shipped, &ap);
        assert_eq!(v.len(), 5);
        assert_eq!(v[4], ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Regression: 834c71e (companion guard). Excluding the optional adapter
    // must not soften strict mode for the SHIPPED models: under
    // IRLUME_MODELS_STRICT=1 an unreadable/deleted shipped model still refuses
    // to start. verify_models exits the process, so re-exec this test binary
    // as the child that makes the call.
    #[test]
    fn strict_verify_still_refuses_a_missing_shipped_model() {
        if std::env::var("IRLUME_TEST_VERIFY_CHILD").is_ok() {
            // Child: strict verify of an unreadable model must exit(1) here.
            verify_models(&["/nonexistent/irlume-test/det.onnx"]);
            return; // reaching this line means strict did NOT refuse
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "tests::strict_verify_still_refuses_a_missing_shipped_model",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("IRLUME_TEST_VERIFY_CHILD", "1")
            .env("IRLUME_MODELS_STRICT", "1")
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "strict verify of a missing shipped model must refuse to start"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("refusing to start"), "stderr was: {err}");
    }

    // Regression: 965d64e. The daemon collapsed EnrollOutcome::New and
    // ::Merged into Response::Ok(String), so the TUI could not tell a merge
    // from a new profile and aborted with "no face profile". The engine itself
    // needs camera + models, so the response-construction seam is what a unit
    // test can pin: Merged maps to Enrolled with created:false and the exact
    // appended scan names (the undo handle), New to created:true.
    #[test]
    fn enroll_merge_reports_created_false_with_the_added_scans() {
        let merged = enroll_response(irlume_auth::EnrollOutcome::Merged {
            name: "Face Profile 1".into(),
            added: 1,
            total: 8,
            added_scans: vec!["Face Scan 8".into()],
        });
        match merged {
            Response::Enrolled {
                profile,
                created,
                added,
                total,
                added_scans,
            } => {
                assert_eq!(profile, "Face Profile 1");
                assert!(!created, "a merge must not claim a new profile was created");
                assert_eq!((added, total), (1, 8));
                assert_eq!(added_scans, vec!["Face Scan 8".to_string()]);
            }
            other => panic!("merge must answer Enrolled, got {other:?}"),
        }
        let new = enroll_response(irlume_auth::EnrollOutcome::New {
            name: "Face Profile 2".into(),
            scans: 3,
        });
        match new {
            Response::Enrolled {
                created,
                added,
                total,
                added_scans,
                ..
            } => {
                assert!(created);
                assert_eq!((added, total), (3, 3));
                assert!(added_scans.is_empty());
            }
            other => panic!("new enroll must answer Enrolled, got {other:?}"),
        }
    }

    #[test]
    fn deny_reason_strips_measurements_keeps_prose() {
        // (tracing is off in tests; IRLUME_LOG unset)
        assert_eq!(
            deny_reason("IR too flat (center/edge 1.02); looks 2D, not a 3D face"),
            "IR too flat (center/edge …); looks 2D, not a 3D face"
        );
        assert_eq!(deny_reason("IR face too dark (42)"), "IR face too dark (…)");
        assert_eq!(
            deny_reason("below threshold (rgb 0.35, fusion+ir-fallback miss)"),
            "below threshold (rgb …, fusion+ir-fallback miss)"
        );
        // allowlisted prose (dimension labels, wavelength) survives
        assert_eq!(
            deny_reason("a real face reflects 850nm"),
            "a real face reflects 850nm"
        );
        assert_eq!(deny_reason("looks 2D not 3D"), "looks 2D not 3D");
        // identifiers (digits glued after letters) survive as names
        assert_eq!(deny_reason("PCR7 drift"), "PCR7 drift");
        // FAIL-CLOSED: a future unit-suffixed measurement is still redacted
        assert_eq!(deny_reason("gap 3px wide"), "gap …px wide");
        assert_eq!(deny_reason("took 12ms"), "took …ms");
        assert_eq!(deny_reason("margin 0.5x"), "margin …x");
        // trailing sentence period survives a float at end of sentence
        assert_eq!(deny_reason("floor 1.12."), "floor ….");
        // no numbers -> unchanged
        assert_eq!(
            deny_reason("'ghost' is not enrolled"),
            "'ghost' is not enrolled"
        );
    }

    /// Tests that mutate process env vars serialize here (setenv/getenv are
    /// process-global and the harness runs tests concurrently).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn deny_score_is_quantized_to_one_decimal_without_tracing() {
        // IRLUME_LOG is unset in the test env, so the anti-oracle quantization
        // applies: one decimal, ~-prefixed, never the 4-decimal exact score.
        assert_eq!(deny_score(0.4321), "~0.4");
        assert_eq!(deny_score(0.06), "~0.1"); // rounds, still one decimal
        assert_eq!(deny_score(0.0), "~0.0");
    }

    #[test]
    fn valid_username_rejects_traversal_and_junk() {
        // Accepted: ordinary local, NSS, and samba-machine account shapes.
        for ok in ["alice", "u", "user_1", "web-svc", "a.b-c", "host$", "x1.y2"] {
            assert!(valid_username(ok), "{ok:?} must be accepted");
        }
        // Rejected: empty, oversized, leading '-'/'.', separators, traversal.
        let long = "a".repeat(65);
        for bad in [
            "",
            long.as_str(),
            "-flag",
            ".hidden",
            "..",
            "../root",
            "a/b",
            "a b",
            "tab\tname",
            "new\nline",
            "nul\0byte",
            "café",
            "semi;colon",
        ] {
            assert!(!valid_username(bad), "{bad:?} must be rejected");
        }
        // Boundary: exactly 64 bytes is still legal.
        assert!(valid_username(&"a".repeat(64)));
    }

    #[test]
    fn request_user_extracts_the_user_from_every_user_bearing_variant() {
        use irlume_common::SecretBytes;
        let u = || "carol".to_string();
        let secret = || SecretBytes::new(b"pw".to_vec());
        let carrying: Vec<Request> = vec![
            Request::Authenticate {
                user: u(),
                service: Some("sudo".into()),
            },
            Request::Enroll {
                user: u(),
                profile: None,
                scans: None,
                reset: false,
            },
            Request::ListProfiles { user: u() },
            Request::DeleteProfile {
                user: u(),
                profile: "p".into(),
            },
            Request::DeleteScan {
                user: u(),
                profile: "p".into(),
                scan: "s".into(),
            },
            Request::RenameProfile {
                user: u(),
                profile: "p".into(),
                new_name: "q".into(),
            },
            Request::RenameScan {
                user: u(),
                profile: "p".into(),
                scan: "s".into(),
                new_name: "t".into(),
            },
            Request::AddScan {
                user: u(),
                profile: "p".into(),
            },
            Request::SetRequireEyesOpen {
                user: u(),
                on: true,
            },
            Request::SetRequireChallenge {
                user: u(),
                on: false,
            },
            Request::SealPassword {
                user: u(),
                password: secret(),
            },
            Request::UnsealPassword {
                user: u(),
                service: None,
            },
            Request::UnsealKeyring {
                user: u(),
                service: None,
            },
            Request::HasSealedPassword { user: u() },
            Request::KeyringInfo { user: u() },
            Request::ForgetPassword { user: u() },
            Request::ResealPassword {
                user: u(),
                password: secret(),
            },
            Request::RecoveryStatus { user: u() },
            Request::RecoverySetup {
                user: u(),
                passphrase: secret(),
            },
            Request::RecoveryRestore {
                user: u(),
                passphrase: secret(),
            },
            Request::RecoveryForget { user: u() },
            Request::PositionSample { user: Some(u()) },
        ];
        for req in &carrying {
            assert_eq!(
                request_user(req),
                Some("carol"),
                "variant must expose its user for the traversal guard: {req:?}"
            );
        }
        // Variants with no user field must not invent one.
        let userless: Vec<Request> = vec![
            Request::Ping,
            Request::Health,
            Request::Identify,
            Request::SetCameras {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
            },
            Request::SetupIrEmitter { dry_run: true },
            Request::SelfTest {
                kind: irlume_common::SelfTestKind::Liveness,
            },
            Request::PositionSample { user: None },
        ];
        for req in &userless {
            assert_eq!(request_user(req), None, "no user in {req:?}");
        }
    }

    #[test]
    fn peer_cred_reports_our_own_identity_on_a_socketpair() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = peer_cred(&a).unwrap();
        assert_eq!(peer.uid, unsafe { libc::geteuid() });
        assert_eq!(peer.gid, unsafe { libc::getegid() });
        assert_eq!(peer.pid, std::process::id() as i32);
    }

    #[test]
    fn read_request_parses_one_line_and_rejects_garbage() {
        // A valid newline-terminated request.
        let (ours, theirs) = UnixStream::pair().unwrap();
        (&theirs).write_all(b"\"Ping\"\n").unwrap();
        match read_request(&ours).unwrap() {
            ReadOutcome::Req(Request::Ping) => {}
            _ => panic!("a Ping line must parse to Request::Ping"),
        }
        // Unparsable bytes -> Bad (generic error, never an echo).
        let (ours, theirs) = UnixStream::pair().unwrap();
        (&theirs).write_all(b"{not json}\n").unwrap();
        assert!(matches!(read_request(&ours).unwrap(), ReadOutcome::Bad));
        // Peer closing without a byte -> Closed.
        let (ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        assert!(matches!(read_request(&ours).unwrap(), ReadOutcome::Closed));
    }

    #[test]
    fn read_request_caps_an_oversized_payload_at_max_request_bytes() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // 128 KiB with no newline: a slow-loris / memory-DoS shape. The writer
        // runs on its own thread in case the kernel buffers fill up.
        let writer = std::thread::spawn(move || {
            let payload = vec![b'a'; 2 * MAX_REQUEST_BYTES as usize];
            let _ = (&theirs).write_all(&payload);
            let _ = (&theirs).write_all(b"\n\"Ping\"\n");
        });
        // The reader must stop at the 64 KiB cap and answer Bad; it must not
        // buffer the whole flood or hang waiting for the newline.
        assert!(matches!(read_request(&ours).unwrap(), ReadOutcome::Bad));
        writer.join().unwrap();
    }

    #[test]
    fn read_request_honours_the_read_deadline_against_a_silent_peer() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // Same mechanism handle() arms (shorter here to keep the test quick).
        ours.set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .unwrap();
        let t = std::time::Instant::now();
        let err = read_request(&ours).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "a silent peer must trip the deadline, got {err:?}"
        );
        assert!(t.elapsed() >= std::time::Duration::from_millis(250));
        drop(theirs);
    }

    #[test]
    fn respond_writes_one_newline_terminated_json_line() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        respond(ours, &Response::Pong).unwrap();
        let mut line = String::new();
        BufReader::new(&theirs).read_line(&mut line).unwrap();
        assert!(line.ends_with('\n'));
        assert!(matches!(
            serde_json::from_str::<Response>(line.trim()).unwrap(),
            Response::Pong
        ));
        // A secret-carrying response survives the wire intact (the zeroize of
        // the serialization buffer must not corrupt what was already sent).
        let (ours, theirs) = UnixStream::pair().unwrap();
        respond(
            ours,
            &Response::PasswordUnsealed {
                secret: irlume_common::SecretBytes::new(b"hunter2".to_vec()),
            },
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(&theirs).read_line(&mut line).unwrap();
        match serde_json::from_str::<Response>(line.trim()).unwrap() {
            Response::PasswordUnsealed { secret } => {
                assert_eq!(secret.expose(), b"hunter2")
            }
            other => panic!("expected PasswordUnsealed, got {other:?}"),
        }
    }

    #[test]
    fn rate_throttle_trips_after_the_limit_and_resets_on_grant() {
        let _g = env_lock();
        std::env::set_var("IRLUME_RATE_LIMIT", "3");
        std::env::set_var("IRLUME_RATE_COOLDOWN_SECS", "30");
        // Unique user so the process-global map does not bleed across tests.
        let u = format!("throttle-{}", std::process::id());

        // Below the limit: strikes accumulate, not yet throttled.
        assert!(!rate_limited(&u));
        rate_record(&u, false, true); // strike 1
        rate_record(&u, false, true); // strike 2
        assert!(!rate_limited(&u), "under the limit must not throttle");
        rate_record(&u, false, true); // strike 3 -> cooldown
        assert!(rate_limited(&u), "at the limit the user is throttled");

        // No-face outcomes (nobody in frame) never count: fresh user stays open
        // even after many of them.
        let u2 = format!("noface-{}", std::process::id());
        for _ in 0..10 {
            rate_record(&u2, false, false);
        }
        assert!(!rate_limited(&u2), "absence must not throttle");

        // A grant clears the throttle immediately.
        let u3 = format!("grant-{}", std::process::id());
        rate_record(&u3, false, true);
        rate_record(&u3, false, true);
        rate_record(&u3, false, true);
        assert!(rate_limited(&u3));
        rate_record(&u3, true, true);
        assert!(!rate_limited(&u3), "a grant resets the throttle");

        // Limit of 0 disables the throttle entirely.
        std::env::set_var("IRLUME_RATE_LIMIT", "0");
        let u4 = format!("disabled-{}", std::process::id());
        for _ in 0..20 {
            rate_record(&u4, false, true);
        }
        assert!(
            !rate_limited(&u4),
            "IRLUME_RATE_LIMIT=0 disables the throttle"
        );

        std::env::remove_var("IRLUME_RATE_LIMIT");
        std::env::remove_var("IRLUME_RATE_COOLDOWN_SECS");
    }

    #[test]
    fn env_or_prefers_the_env_var_over_the_default() {
        let _g = env_lock();
        std::env::remove_var("IRLUME_TEST_ENV_OR");
        assert_eq!(
            env_or("IRLUME_TEST_ENV_OR", "/etc/fallback"),
            "/etc/fallback"
        );
        std::env::set_var("IRLUME_TEST_ENV_OR", "/tmp/override");
        assert_eq!(
            env_or("IRLUME_TEST_ENV_OR", "/etc/fallback"),
            "/tmp/override"
        );
        std::env::remove_var("IRLUME_TEST_ENV_OR");
    }

    #[test]
    fn biopolicy_enforced_reads_env_then_settings_conf() {
        let _g = env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-biopol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY");

        // Default: no env, no settings.conf -> off.
        assert!(!biopolicy_enforced());
        // settings.conf truthy value turns it on; a falsy one keeps it off.
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=1\n").unwrap();
        assert!(biopolicy_enforced());
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=0\n").unwrap();
        assert!(!biopolicy_enforced());
        // The env var wins over the file, in both directions.
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=1\n").unwrap();
        std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", "0");
        assert!(!biopolicy_enforced());
        std::fs::write(dir.join("settings.conf"), "enforce_biopolicy=0\n").unwrap();
        for truthy in ["1", "true", "yes", "on", " on "] {
            std::env::set_var("IRLUME_ENFORCE_BIOPOLICY", truthy);
            assert!(biopolicy_enforced(), "{truthy:?} must enable");
        }
        std::env::remove_var("IRLUME_ENFORCE_BIOPOLICY");
        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_models_without_strict_warns_but_continues() {
        // No IRLUME_MODELS_STRICT in the test env: an unknown digest and a
        // missing file must both come back (reaching the next line at all is
        // the contract; strict mode would have exited the process).
        let dir = std::env::temp_dir().join(format!("irlume-vm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let unknown = dir.join("custom_adapter.onnx");
        std::fs::write(&unknown, b"self-trained weights").unwrap();
        verify_models(&[
            unknown.to_str().unwrap(),
            "/nonexistent/irlume-test/missing.onnx",
        ]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Companion to the missing-model child test: strict mode must also refuse
    // a PRESENT model whose digest is not in the release manifest (tampering),
    // and must ACCEPT a shipped model that matches it. verify_models exits the
    // process, so both run as re-exec'd children.
    #[test]
    fn strict_verify_refuses_a_tampered_model_and_accepts_a_shipped_one() {
        if let Ok(path) = std::env::var("IRLUME_TEST_VERIFY_TAMPER_CHILD") {
            verify_models(&[&path]); // must exit(1) before the return
            return;
        }
        if let Ok(path) = std::env::var("IRLUME_TEST_VERIFY_KNOWN_CHILD") {
            verify_models(&[&path]); // digest is in the manifest: must survive
            println!("known-model-accepted");
            std::process::exit(0);
        }
        let exe = std::env::current_exe().unwrap();
        let run = |var: &str, path: &str| {
            std::process::Command::new(&exe)
                .args([
                    "tests::strict_verify_refuses_a_tampered_model_and_accepts_a_shipped_one",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(var, path)
                .env("IRLUME_MODELS_STRICT", "1")
                .output()
                .unwrap()
        };
        // Tampered: on-disk bytes whose sha256 is not in models/SHA256SUMS.
        let dir = std::env::temp_dir().join(format!("irlume-vm-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tampered = dir.join("face.onnx");
        std::fs::write(&tampered, b"swapped weights").unwrap();
        let out = run(
            "IRLUME_TEST_VERIFY_TAMPER_CHILD",
            tampered.to_str().unwrap(),
        );
        assert!(
            !out.status.success(),
            "strict mode must refuse an unmanifested model"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("refusing to start with unverified models"),
            "stderr: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Shipped: a real release model from the repo matches its manifest
        // digest and must start even under strict.
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../models/blaze_face_short_range.onnx");
        if !shipped.exists() {
            eprintln!("skipping known-model half: repo models/ not present");
            return;
        }
        let out = run("IRLUME_TEST_VERIFY_KNOWN_CHILD", shipped.to_str().unwrap());
        assert!(
            out.status.success(),
            "strict mode must accept a manifest-matching model; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("known-model-accepted"));
    }

    #[test]
    fn mutate_enrollment_reports_a_missing_enrollment() {
        let _g = env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-mut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        let resp = mutate_enrollment("ghost", |_| Ok("never runs".into()));
        match resp {
            Response::Error(msg) => assert_eq!(msg, "'ghost' is not enrolled"),
            other => panic!("expected Error, got {other:?}"),
        }
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_mode_applies_the_requested_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("irlume-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("sock-standin");
        std::fs::write(&f, b"").unwrap();
        set_mode(f.to_str().unwrap(), 0o660);
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        // Best-effort on a missing path: must not panic.
        set_mode("/nonexistent/irlume-test/sock", 0o666);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- engine-loaded dispatch arms ------------------------------------
    //
    // These drive dispatch() with a REAL irlume_auth::Engine (the same model
    // files the daemon loads in production) and a constructed Peer. The
    // engine's camera devices are nonexistent paths, so every ungated test
    // below either refuses before any capture or fails the capture cleanly;
    // nothing touches real hardware, /var/lib, or a real TPM. Tests that need
    // fake hardware are env-gated: `loopback_` (v4l2loopback feeder nodes) and
    // `tpm_` (swtpm via IRLUME_TCTI).

    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};
    use std::sync::{MutexGuard, OnceLock};

    const NO_RGB: &str = "/dev/irlume-daemon-test-none-rgb";
    const NO_IR: &str = "/dev/irlume-daemon-test-none-ir";
    /// A uid outside any account database (same sentinel the identify-scope
    /// test uses): authorized_for() is false for every user.
    const NOBODY: u32 = 0xfffe_fffe;

    fn peer(uid: u32) -> Peer {
        Peer {
            uid,
            gid: uid,
            pid: 1,
        }
    }

    fn model_path(name: &str) -> String {
        format!("{}/../../models/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Point `ort` (load-dynamic) at the packaged onnxruntime when the test
    /// env doesn't already provide `ORT_DYLIB_PATH`. Same fallbacks as
    /// irlume-auth's engine tests.
    fn ort_init() {
        if std::env::var_os("ORT_DYLIB_PATH").is_some() {
            return;
        }
        for cand in [
            "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
            "/usr/lib64/libonnxruntime.so",
            "/usr/lib/libonnxruntime.so",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
        ] {
            if std::path::Path::new(cand).exists() {
                std::env::set_var("ORT_DYLIB_PATH", cand);
                return;
            }
        }
    }

    /// Process-wide shared engine, loaded once (glintr100 is big). LOCK ORDER:
    /// every test takes env_lock() FIRST, then engine(); the initializer only
    /// touches env vars no other daemon test reads (IRLUME_FORCE_NO_IR,
    /// ORT_DYLIB_PATH), both left set for the whole process, so every
    /// engine-backed test sees the same deterministic convenience (RGB-only)
    /// hardware probe on any machine.
    fn engine() -> MutexGuard<'static, irlume_auth::Engine> {
        static E: OnceLock<std::sync::Mutex<irlume_auth::Engine>> = OnceLock::new();
        E.get_or_init(|| {
            ort_init();
            std::env::set_var("IRLUME_FORCE_NO_IR", "1");
            std::sync::Mutex::new(
                irlume_auth::Engine::load(
                    &model_path("face_detection_yunet_2023mar.onnx"),
                    &model_path("glintr100.onnx"),
                )
                .expect("engine load")
                .with_devices(NO_RGB, NO_IR),
            )
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    }

    /// Isolated state/config/keyring/template-key/recovery dirs plus a method
    /// conf pointing at a missing file (=> method Auto). Redirects every path
    /// the dispatch arms touch, so no test can read or write this machine's
    /// real /etc/irlume or /var/lib state. Caller must hold env_lock(); the
    /// guard must be declared BEFORE the sandbox so Drop runs under it.
    struct Sandbox {
        dir: std::path::PathBuf,
    }

    fn sandbox(tag: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("irlume-daemon-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_CONFIG_DIR", dir.join("config"));
        std::env::set_var("IRLUME_KEYRING_DIR", dir.join("keyring"));
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("template-keys"));
        std::env::set_var("IRLUME_RECOVERY_DIR", dir.join("recovery"));
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("no-method-conf"));
        Sandbox { dir }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            for var in [
                "IRLUME_STATE_DIR",
                "IRLUME_CONFIG_DIR",
                "IRLUME_KEYRING_DIR",
                "IRLUME_TEMPLATE_KEY_DIR",
                "IRLUME_RECOVERY_DIR",
                "IRLUME_METHOD_CONF",
            ] {
                std::env::remove_var(var);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Write a PLAINTEXT enrollment (what a no-TPM host stores) straight into
    /// the sandbox state dir; never through storage::save, which would seal a
    /// template key against this machine's real TPM.
    fn write_enrollment(dir: &std::path::Path, e: &Enrollment) {
        std::fs::write(
            dir.join(format!("{}.json", e.user)),
            serde_json::to_vec(e).unwrap(),
        )
        .unwrap();
    }

    fn unit512(seed: usize) -> Vec<f32> {
        let mut v: Vec<f32> = (0..512)
            .map(|j| (j as f32 * 0.7).sin() + 0.05 * (seed as f32 * 1.3 + j as f32).sin())
            .collect();
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-9;
        v.iter_mut().for_each(|x| *x /= n);
        v
    }

    fn rgb_scan(name: &str, seed: usize) -> FaceScan {
        FaceScan {
            name: name.into(),
            rgb: unit512(seed),
            ir: None,
            ir_space: None,
            ir_depth: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        }
    }

    /// One-profile plaintext enrollment: "Face Profile 1" with the named scans.
    fn enrollment_with(user: &str, scans: &[&str]) -> Enrollment {
        Enrollment {
            user: user.into(),
            profiles: vec![FaceProfile {
                name: "Face Profile 1".into(),
                ir_calib: None,
                scans: scans
                    .iter()
                    .enumerate()
                    .map(|(i, s)| rgb_scan(s, i + 1))
                    .collect(),
            }],
            require_eyes_open: false,
            require_challenge: false,
            camera_binding: None,
            closure_calibration: None,
        }
    }

    /// Plant a bogus sealed-password envelope file. has_sealed_password() is a
    /// pure existence check, so this drives the armed/unarmed branches without
    /// a TPM; any arm that actually unseals it must then fail on the parse.
    fn plant_fake_envelope(user: &str) {
        let path = irlume_core::keyring::envelope_path(user);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not a sealed envelope").unwrap();
    }

    #[test]
    fn dispatch_rejects_an_invalid_username_before_any_arm() {
        let _g = env_lock();
        let mut e = engine();
        for req in [
            Request::ListProfiles {
                user: "../root".into(),
            },
            Request::Authenticate {
                user: "a/b".into(),
                service: None,
            },
            Request::UnsealPassword {
                user: "-flag".into(),
                service: None,
            },
        ] {
            match dispatch(req, &peer(0), &mut e) {
                Response::Error(msg) => assert_eq!(msg, "invalid username"),
                other => panic!("traversal username must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn ping_answers_pong_through_dispatch() {
        let _g = env_lock();
        let mut e = engine();
        assert!(matches!(
            dispatch(Request::Ping, &peer(NOBODY), &mut e),
            Response::Pong
        ));
    }

    #[test]
    fn health_reports_version_and_never_secure_under_forced_no_ir() {
        let _g = env_lock();
        let mut e = engine();
        match dispatch(Request::Health, &peer(NOBODY), &mut e) {
            Response::Health {
                tier,
                ir_dev,
                mesh,
                adapter,
                version,
                third_party_pad,
                ..
            } => {
                // IRLUME_FORCE_NO_IR=1 (set by the shared engine init) forces
                // ir_pair=false, so no IR node may be reported and the tier can
                // never be "secure", whatever cameras this machine has.
                assert_ne!(tier, "secure");
                assert_eq!(ir_dev, None);
                // The bare shared engine loaded no optional models.
                assert!(!mesh && !adapter);
                // No opt-in PAD cue loaded -> Health reports None (the field
                // the TUI uses for the authoritative on/off state).
                assert_eq!(third_party_pad, None);
                assert_eq!(version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("Health must answer Response::Health, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_requires_root_or_the_account_owner() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-authz");
        let _ = &sb;
        match dispatch(
            Request::Authenticate {
                user: "carol".into(),
                service: None,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to authenticate 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_stands_down_when_the_method_is_fingerprint() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-fp");
        std::fs::write(sb.dir.join("method"), "fingerprint").unwrap();
        std::env::set_var("IRLUME_METHOD_CONF", sb.dir.join("method"));
        match dispatch(
            Request::Authenticate {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::AuthResult {
                granted,
                score,
                live,
                reason,
            } => {
                assert!(!granted && !live);
                assert_eq!(score, 0.0);
                assert_eq!(
                    reason,
                    "face auth disabled: the configured method is fingerprint"
                );
            }
            other => panic!("fingerprint mode must deny via AuthResult, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_on_convenience_tier_is_limited_to_screen_unlock() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-conv");
        let _ = &sb;
        // (service, the OperationClass Debug name the deny reason must carry)
        for (service, class) in [("sshd", "Remote"), ("sudo", "Elevation")] {
            match dispatch(
                Request::Authenticate {
                    user: "carol".into(),
                    service: Some(service.into()),
                },
                &peer(0),
                &mut e,
            ) {
                Response::AuthResult {
                    granted,
                    live,
                    reason,
                    ..
                } => {
                    assert!(!granted && !live, "{service} must not grant");
                    assert_eq!(
                        reason,
                        format!(
                            "RGB-only convenience: face limited to screen unlock (not {class})"
                        )
                    );
                }
                other => panic!("convenience gate must deny {service}, got {other:?}"),
            }
        }
    }

    #[test]
    fn authenticate_refuses_an_unenrolled_user_before_the_camera() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-ghost");
        let _ = &sb;
        // "kde" classifies as ScreenUnlock, so the convenience gate passes and
        // the engine itself answers; an unenrolled user is refused before any
        // capture (the devices don't exist, so reaching the camera would error).
        match dispatch(
            Request::Authenticate {
                user: "irlume-test-ghost".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::AuthResult {
                granted,
                live,
                reason,
                ..
            } => {
                assert!(!granted && !live);
                assert_eq!(reason, "'irlume-test-ghost' is not enrolled");
                // The reason must survive journal redaction unchanged (no
                // numeric payload for a spoofer to tune against).
                assert_eq!(deny_reason(&reason), reason);
            }
            other => panic!("unenrolled user must deny via AuthResult, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_surfaces_a_capture_error_for_an_enrolled_user() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("auth-cam");
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        match dispatch(
            Request::Authenticate {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
    }

    #[test]
    fn identify_answers_a_peer_without_an_account_and_needs_a_camera_for_root() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("identify");
        let _ = &sb;
        // A peer with no local account gets an empty identify, no capture at all.
        match dispatch(Request::Identify, &peer(NOBODY), &mut e) {
            Response::Identified {
                user,
                profile,
                score,
                live,
                reason,
            } => {
                assert_eq!(user, None);
                assert_eq!(profile, None);
                assert_eq!(score, 0.0);
                assert!(!live);
                assert_eq!(reason, "caller has no local account");
            }
            other => panic!("no-account peer must get Identified, got {other:?}"),
        }
        // Root keeps the full 1:N search, which needs the (absent) camera.
        match dispatch(Request::Identify, &peer(0), &mut e) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("root identify without a camera must Error, got {other:?}"),
        }
    }

    #[test]
    fn list_profiles_reports_the_enrollment_and_gates_on_authorization() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("list");
        let mut enr = enrollment_with("carol", &["Face Scan 1", "Face Scan 2"]);
        enr.require_eyes_open = true;
        write_enrollment(&sb.dir, &enr);
        match dispatch(
            Request::ListProfiles {
                user: "carol".into(),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Enrollment {
                profiles,
                require_eyes_open,
                require_challenge,
                ..
            } => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(profiles[0].name, "Face Profile 1");
                assert_eq!(
                    profiles[0].scans,
                    vec!["Face Scan 1".to_string(), "Face Scan 2".to_string()]
                );
                assert!(require_eyes_open);
                assert!(!require_challenge);
            }
            other => panic!("expected Response::Enrollment, got {other:?}"),
        }
        // An unenrolled user lists as empty rather than erroring.
        match dispatch(
            Request::ListProfiles {
                user: "ghost".into(),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Enrollment { profiles, .. } => assert!(profiles.is_empty()),
            other => panic!("unenrolled user must list empty, got {other:?}"),
        }
        // A foreign peer may not even list.
        match dispatch(
            Request::ListProfiles {
                user: "carol".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to list 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
    }

    #[test]
    fn profile_mutations_error_precisely_without_rewriting_state() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("mut-err");
        write_enrollment(
            &sb.dir,
            &enrollment_with("carol", &["Face Scan 1", "Face Scan 2"]),
        );
        let root = peer(0);
        // Every branch here errors BEFORE storage::save, so this runs on any
        // host (TPM or not) without sealing anything.
        let cases: Vec<(Request, &str)> = vec![
            (
                Request::DeleteProfile {
                    user: "carol".into(),
                    profile: "nope".into(),
                },
                "no face profile 'nope'",
            ),
            (
                Request::DeleteScan {
                    user: "carol".into(),
                    profile: "nope".into(),
                    scan: "Face Scan 1".into(),
                },
                "no face profile 'nope'",
            ),
            (
                Request::RenameScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "Face Scan 1".into(),
                    new_name: "Face Scan 2".into(),
                },
                "'Face Scan 2' already exists in 'Face Profile 1'",
            ),
            (
                Request::RenameScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "missing".into(),
                    new_name: "Front".into(),
                },
                "no scan 'missing' in 'Face Profile 1'",
            ),
            (
                Request::DeleteProfile {
                    user: "ghost".into(),
                    profile: "Face Profile 1".into(),
                },
                "'ghost' is not enrolled",
            ),
        ];
        for (req, want) in cases {
            match dispatch(req, &root, &mut e) {
                Response::Error(msg) => assert_eq!(msg, want),
                other => panic!("expected Error({want}), got {other:?}"),
            }
        }
        // Unauthorized peers are refused before the enrollment is even loaded.
        match dispatch(
            Request::DeleteProfile {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to modify 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        // The enrollment file is untouched by all of the above.
        let enr = irlume_core::storage::load("carol").unwrap().unwrap();
        assert_eq!(enr.profiles[0].scans.len(), 2);
    }

    #[test]
    fn delete_scan_never_orphans_a_profile_and_deleting_the_last_profile_erases_the_file() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("del-last");
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        let root = peer(0);
        // A profile must keep at least one scan (the deny path never saves).
        match dispatch(
            Request::DeleteScan {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
                scan: "Face Scan 1".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(
                msg,
                "a profile must keep at least one scan; delete the profile instead"
            ),
            other => panic!("last-scan delete must be refused, got {other:?}"),
        }
        // Deleting the only profile removes the whole enrollment file
        // (storage::delete, not save: safe on a TPM host too).
        match dispatch(
            Request::DeleteProfile {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Ok(msg) => assert_eq!(msg, "deleted profile 'Face Profile 1'"),
            other => panic!("sole-profile delete must succeed, got {other:?}"),
        }
        assert!(
            !sb.dir.join("carol.json").exists(),
            "an enrollment with zero profiles must not linger on disk"
        );
        match dispatch(
            Request::DeleteProfile {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "'carol' is not enrolled"),
            other => panic!("second delete must report unenrolled, got {other:?}"),
        }
    }

    #[test]
    fn mutations_that_rewrite_the_enrollment_roundtrip_through_dispatch() {
        // These arms end in storage::save; on a host with /dev/tpm* that would
        // seal a real template key, so this test only runs on no-TPM hosts
        // (CI runners). Same convention as irlume-core's storage tests.
        if irlume_core::template_key::tpm_available() {
            eprintln!("skipping: TPM present; storage::save would touch real hardware");
            return;
        }
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("mut-save");
        let _ = &sb;
        write_enrollment(
            &sb.dir,
            &enrollment_with("carol", &["Face Scan 1", "Face Scan 2"]),
        );
        let root = peer(0);
        let expect_ok = |resp: Response, want: &str| match resp {
            Response::Ok(msg) => assert_eq!(msg, want),
            other => panic!("expected Ok({want}), got {other:?}"),
        };
        expect_ok(
            dispatch(
                Request::DeleteScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "Face Scan 2".into(),
                },
                &root,
                &mut e,
            ),
            "deleted scan 'Face Scan 2' from 'Face Profile 1'",
        );
        expect_ok(
            dispatch(
                Request::RenameScan {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    scan: "Face Scan 1".into(),
                    new_name: "Front".into(),
                },
                &root,
                &mut e,
            ),
            "renamed scan to 'Front'",
        );
        expect_ok(
            dispatch(
                Request::RenameProfile {
                    user: "carol".into(),
                    profile: "Face Profile 1".into(),
                    new_name: "Work".into(),
                },
                &root,
                &mut e,
            ),
            "renamed profile to 'Work'",
        );
        // Renaming onto an existing name collides (checked before the lookup,
        // so even a self-rename is refused).
        match dispatch(
            Request::RenameProfile {
                user: "carol".into(),
                profile: "Work".into(),
                new_name: "Work".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "'Work' already exists"),
            other => panic!("rename collision must be refused, got {other:?}"),
        }
        expect_ok(
            dispatch(
                Request::SetRequireEyesOpen {
                    user: "carol".into(),
                    on: true,
                },
                &root,
                &mut e,
            ),
            "require-eyes-open ENABLED",
        );
        expect_ok(
            dispatch(
                Request::SetRequireChallenge {
                    user: "carol".into(),
                    on: false,
                },
                &root,
                &mut e,
            ),
            "require-challenge disabled",
        );
        // The saved state reflects every mutation.
        match dispatch(
            Request::ListProfiles {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Enrollment {
                profiles,
                require_eyes_open,
                require_challenge,
                ..
            } => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(profiles[0].name, "Work");
                assert_eq!(profiles[0].scans, vec!["Front".to_string()]);
                assert!(require_eyes_open);
                assert!(!require_challenge);
            }
            other => panic!("expected Response::Enrollment, got {other:?}"),
        }
    }

    #[test]
    fn enroll_validates_authorization_and_duplicate_names_before_capture() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("enroll");
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: None,
                scans: None,
                reset: false,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to enroll 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        // An explicit duplicate profile name fails fast, before the camera
        // would open (the devices don't exist, so getting further would turn
        // this into a hardware error instead).
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: Some("Face Profile 1".into()),
                scans: None,
                reset: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(
                    msg.contains("a face profile named 'Face Profile 1' already exists"),
                    "{msg}"
                );
            }
            other => panic!("duplicate profile name must be refused, got {other:?}"),
        }
        // Past validation, the capture itself fails cleanly on this hardware.
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: Some("Second".into()),
                scans: Some(1),
                reset: false,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
        // reset:true wipes the old enrollment even though the capture then
        // fails: the reset half of the arm ran.
        match dispatch(
            Request::Enroll {
                user: "carol".into(),
                profile: None,
                scans: None,
                reset: true,
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
        assert!(
            !sb.dir.join("carol.json").exists(),
            "Enroll{{reset:true}} must delete the previous enrollment first"
        );
    }

    #[test]
    fn add_scan_refuses_unenrolled_users_and_full_profiles_before_capture() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("addscan");
        match dispatch(
            Request::AddScan {
                user: "ghost".into(),
                profile: "Face Profile 1".into(),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("'ghost' is not enrolled"), "{msg}"),
            other => panic!("unenrolled AddScan must Error, got {other:?}"),
        }
        // A profile at MAX_SCANS_PER_PROFILE is refused before any capture.
        let max = irlume_core::storage::MAX_SCANS_PER_PROFILE;
        let names: Vec<String> = (1..=max).map(|i| format!("Face Scan {i}")).collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        write_enrollment(&sb.dir, &enrollment_with("carol", &name_refs));
        match dispatch(
            Request::AddScan {
                user: "carol".into(),
                profile: "Face Profile 1".into(),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(
                msg.contains(&format!("already has the max {max} scans")),
                "{msg}"
            ),
            other => panic!("full profile must be refused, got {other:?}"),
        }
    }

    #[test]
    fn seal_password_gates_authorization_and_refuses_an_empty_secret() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("seal");
        let _ = &sb;
        match dispatch(
            Request::SealPassword {
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(b"pw".to_vec()),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to seal password for 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        // The empty-password refusal fires before any TPM operation, so this
        // is safe (and deterministic) on every host.
        match dispatch(
            Request::SealPassword {
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(Vec::new()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(msg.contains("refusing to seal an empty password"), "{msg}")
            }
            other => panic!("empty password must be refused, got {other:?}"),
        }
    }

    #[test]
    fn unseal_password_arm_gates_peer_method_and_tier_before_the_face_check() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("unseal-gates");
        // Only a root peer (the PAM stack) may even ask.
        match dispatch(
            Request::UnsealPassword {
                user: "carol".into(),
                service: None,
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("unseal_password requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root unseal must be refused, got {other:?}"),
        }
        // Fingerprint mode refuses credential release outright.
        std::fs::write(sb.dir.join("method"), "fingerprint").unwrap();
        std::env::set_var("IRLUME_METHOD_CONF", sb.dir.join("method"));
        match dispatch(
            Request::UnsealPassword {
                user: "carol".into(),
                service: Some("plasmalogin".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    "face auth disabled: the configured method is fingerprint"
                )
            }
            other => panic!("fingerprint mode must refuse unseal, got {other:?}"),
        }
        std::env::set_var("IRLUME_METHOD_CONF", sb.dir.join("no-method-conf"));
        // The convenience (RGB-only) tier never releases the credential; this
        // fires before the sealed-password lookup and the face check.
        match dispatch(
            Request::UnsealPassword {
                user: "carol".into(),
                service: Some("plasmalogin".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(
                msg,
                "RGB-only convenience: face cannot release the login credential"
            ),
            other => panic!("convenience tier must refuse unseal, got {other:?}"),
        }
        // A polkit service NEVER releases the credential, on any tier, with or
        // without the opt-in biopolicy: the polkit agent starts its PAM
        // conversation with no user gesture, so this fires before every other
        // consideration except root and method.
        for svc in ["polkit-1", "polkit"] {
            match dispatch(
                Request::UnsealPassword {
                    user: "carol".into(),
                    service: Some(svc.into()),
                },
                &peer(0),
                &mut e,
            ) {
                Response::Error(msg) => assert_eq!(
                    msg,
                    format!(
                        "'{svc}' is verify-only: a polkit prompt never releases the credential"
                    )
                ),
                other => panic!("polkit unseal must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn do_unseal_password_requires_an_armed_seal_then_a_granted_face() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("do-unseal");
        // Nothing armed: refused before any capture or TPM traffic.
        match do_unseal_password("carol", None, &mut e) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    "no sealed password for 'carol': run `irlume keyring arm`"
                )
            }
            other => panic!("unarmed unseal must be refused, got {other:?}"),
        }
        // Armed (existence check only) but the user is not enrolled: the face
        // check denies before the camera and the envelope is never opened.
        plant_fake_envelope("carol");
        match do_unseal_password("carol", None, &mut e) {
            Response::Error(msg) => {
                assert_eq!(msg, "face not granted: 'carol' is not enrolled")
            }
            other => panic!("unenrolled unseal must be refused, got {other:?}"),
        }
        // Enrolled: the capture itself fails on this hardware and maps to a
        // clean Error (the non-drift branch: no remedy hint appended).
        write_enrollment(&sb.dir, &enrollment_with("carol", &["Face Scan 1"]));
        match do_unseal_password("carol", None, &mut e) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("missing camera must be an Error, got {other:?}"),
        }
    }

    #[test]
    fn unseal_keyring_gates_peer_service_class_and_envelope_integrity() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("unseal-keyring");
        let _ = &sb;
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("unseal_keyring requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root keyring unseal must be refused, got {other:?}"),
        }
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    "no sealed password for 'carol': run `irlume keyring arm`"
                )
            }
            other => panic!("unarmed keyring unseal must be refused, got {other:?}"),
        }
        plant_fake_envelope("carol");
        // Only a login / lock-screen service class may release; sudo may not.
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("sudo".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "keyring unseal not allowed for Elevation"),
            other => panic!("elevation keyring unseal must be refused, got {other:?}"),
        }
        // A corrupt envelope must surface as an Error, never a secret.
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => assert!(!msg.is_empty()),
            other => panic!("a corrupt envelope must Error, got {other:?}"),
        }
    }

    #[test]
    fn has_sealed_password_and_forget_roundtrip_through_dispatch() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("haspw");
        let _ = &sb;
        let root = peer(0);
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to query 'carol'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(!armed),
            other => panic!("expected HasPassword(false), got {other:?}"),
        }
        plant_fake_envelope("carol");
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(armed),
            other => panic!("expected HasPassword(true), got {other:?}"),
        }
        match dispatch(
            Request::ForgetPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::PasswordForgotten => {}
            other => panic!("expected PasswordForgotten, got {other:?}"),
        }
        assert!(
            !irlume_core::keyring::envelope_path("carol").exists(),
            "ForgetPassword must remove the envelope file"
        );
    }

    #[test]
    fn keyring_info_reports_unarmed_and_unreadable_envelopes() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("krinfo");
        let _ = &sb;
        let root = peer(0);
        match dispatch(
            Request::KeyringInfo {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::KeyringInfo {
                armed,
                policy,
                pcrs,
                drifted,
            } => {
                assert!(!armed);
                assert_eq!(policy, None);
                assert!(pcrs.is_empty());
                assert_eq!(drifted, None);
            }
            other => panic!("expected KeyringInfo, got {other:?}"),
        }
        // Armed but unreadable: report the armed bit alone, don't fail.
        plant_fake_envelope("carol");
        match dispatch(
            Request::KeyringInfo {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::KeyringInfo { armed, policy, .. } => {
                assert!(armed);
                assert_eq!(policy, None);
            }
            other => panic!("expected KeyringInfo, got {other:?}"),
        }
    }

    #[test]
    fn reseal_password_reports_not_armed_and_refuses_an_empty_password() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("reseal");
        let _ = &sb;
        // Not armed short-circuits before any TPM traffic: never auto-arm.
        match dispatch(
            Request::ResealPassword {
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(b"pw".to_vec()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::PasswordResealed { armed, changed } => {
                assert!(!armed && !changed, "reseal must never arm a fresh user");
            }
            other => panic!("expected PasswordResealed, got {other:?}"),
        }
        match dispatch(
            Request::ResealPassword {
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(Vec::new()),
            },
            &peer(0),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(
                    msg.contains("refusing to reseal an empty password"),
                    "{msg}"
                )
            }
            other => panic!("empty reseal must be refused, got {other:?}"),
        }
    }

    #[test]
    fn recovery_arms_report_status_and_error_without_a_template_key() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("recovery");
        let _ = &sb;
        let root = peer(0);
        match dispatch(
            Request::RecoveryStatus {
                user: "ghost".into(),
            },
            &root,
            &mut e,
        ) {
            Response::RecoveryStatus {
                encrypted,
                recovery_set,
                ..
            } => assert!(!encrypted && !recovery_set),
            other => panic!("expected RecoveryStatus, got {other:?}"),
        }
        // No template key exists (and the user isn't enrolled, so none is
        // minted): setup has nothing to wrap.
        match dispatch(
            Request::RecoverySetup {
                user: "ghost".into(),
                passphrase: irlume_common::SecretBytes::new(b"phrase".to_vec()),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => {
                assert!(msg.contains("no template key sealed for 'ghost'"), "{msg}")
            }
            other => panic!("setup without a key must Error, got {other:?}"),
        }
        match dispatch(
            Request::RecoveryRestore {
                user: "ghost".into(),
                passphrase: irlume_common::SecretBytes::new(b"phrase".to_vec()),
            },
            &root,
            &mut e,
        ) {
            Response::Error(msg) => assert!(
                msg.contains("no recovery passphrase set for 'ghost'"),
                "{msg}"
            ),
            other => panic!("restore without an envelope must Error, got {other:?}"),
        }
        match dispatch(
            Request::RecoveryForget {
                user: "ghost".into(),
            },
            &root,
            &mut e,
        ) {
            Response::Ok(msg) => assert_eq!(msg, "recovery passphrase erased for 'ghost'"),
            other => panic!("forget must be idempotent Ok, got {other:?}"),
        }
        match dispatch(
            Request::RecoveryStatus {
                user: "ghost".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert_eq!(msg, "not authorized to query 'ghost'"),
            other => panic!("foreign peer must be refused, got {other:?}"),
        }
    }

    #[test]
    fn set_cameras_requires_root_then_repoints_and_persists() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("setcam");
        let _ = &sb;
        match dispatch(
            Request::SetCameras {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("set_cameras requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root SetCameras must be refused, got {other:?}"),
        }
        let (rgb, ir) = ("/dev/irlume-test-alt-rgb", "/dev/irlume-test-alt-ir");
        match dispatch(
            Request::SetCameras {
                rgb: rgb.into(),
                ir: ir.into(),
            },
            &peer(0),
            &mut e,
        ) {
            // The exact message proves the persist to cameras.conf succeeded
            // (a failed persist appends a "live only" suffix).
            Response::Ok(msg) => assert_eq!(msg, format!("cameras set to rgb={rgb} ir={ir}")),
            other => panic!("root SetCameras must succeed, got {other:?}"),
        }
        assert_eq!(e.rgb_device(), rgb);
        assert_eq!(e.ir_device(), ir);
        assert_eq!(
            irlume_common::config::read_kv("cameras.conf", "rgb").as_deref(),
            Some(rgb)
        );
        assert_eq!(
            irlume_common::config::read_kv("cameras.conf", "ir").as_deref(),
            Some(ir)
        );
        // Restore the shared engine's baseline devices.
        e.set_devices(NO_RGB, NO_IR);
    }

    #[test]
    fn setup_ir_emitter_gates_root_and_surfaces_a_missing_camera() {
        let _g = env_lock();
        let mut e = engine();
        // Dry-run is open to any peer but needs the (absent) IR node.
        match dispatch(
            Request::SetupIrEmitter { dry_run: true },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("dry-run without a camera must Error, got {other:?}"),
        }
        // The write path is root-only.
        match dispatch(
            Request::SetupIrEmitter { dry_run: false },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("setup_ir_emitter requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root setup must be refused, got {other:?}"),
        }
    }

    #[test]
    fn selftest_and_position_sample_surface_the_missing_camera() {
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("selftest");
        let _ = &sb;
        for kind in [
            irlume_common::SelfTestKind::Liveness,
            irlume_common::SelfTestKind::AlignmentIdentity,
        ] {
            match dispatch(Request::SelfTest { kind }, &peer(0), &mut e) {
                Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
                other => panic!("selftest without a camera must Error, got {other:?}"),
            }
            // A non-root peer is refused before the camera ever fires: the
            // self-test returns raw liveness measurements (a spoof oracle).
            match dispatch(Request::SelfTest { kind }, &peer(NOBODY), &mut e) {
                Response::Error(msg) => assert!(
                    msg.contains("requires root"),
                    "non-root selftest must be refused as root-only, got {msg}"
                ),
                other => panic!("non-root selftest must Error, got {other:?}"),
            }
        }
        // A non-root peer asking to tune for another user is silently scoped
        // to the anonymous band; either way the capture needs the camera.
        match dispatch(
            Request::PositionSample {
                user: Some("root".into()),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => assert!(msg.contains("no camera found"), "{msg}"),
            other => panic!("position sample without a camera must Error, got {other:?}"),
        }
    }

    // ---- env-gated: v4l2loopback feeder nodes ---------------------------

    /// Fresh engine wired to the CI loopback nodes; None when the env is
    /// absent. The feeder holds no face, so capture arms end in clean denials.
    fn loopback_engine() -> Option<irlume_auth::Engine> {
        let (Ok(rgb), Ok(ir)) = (
            std::env::var("IRLUME_TEST_RGB_DEVICE"),
            std::env::var("IRLUME_TEST_IR_DEVICE"),
        ) else {
            return None;
        };
        ort_init();
        Some(
            irlume_auth::Engine::load(
                &model_path("face_detection_yunet_2023mar.onnx"),
                &model_path("glintr100.onnx"),
            )
            .expect("engine load")
            .with_devices(&rgb, &ir),
        )
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_authenticate_dispatches_to_a_no_face_denial() {
        let _g = env_lock();
        let Some(mut e) = loopback_engine() else {
            return;
        };
        let sb = sandbox("lb-auth");
        // One-shot capture instead of a grace window: a no-face run finishes
        // in one camera round.
        std::env::set_var("IRLUME_GRACE_MS", "0");
        write_enrollment(&sb.dir, &enrollment_with("lbuser", &["Face Scan 1"]));
        // "kde" is a ScreenUnlock in every tier, so the dispatch gates pass
        // whether or not the runner's loopback nodes register as an IR pair.
        let resp = dispatch(
            Request::Authenticate {
                user: "lbuser".into(),
                service: Some("kde".into()),
            },
            &peer(0),
            &mut e,
        );
        std::env::remove_var("IRLUME_GRACE_MS");
        match resp {
            Response::AuthResult {
                granted,
                live,
                reason,
                ..
            } => {
                assert!(!granted, "no face on the feed must never grant");
                assert!(!live);
                assert!(
                    reason.to_lowercase().contains("face"),
                    "denial should name the missing face, got: {reason}"
                );
            }
            other => panic!("a faceless frame is a denial, not an error: {other:?}"),
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_identify_dispatches_to_a_no_match() {
        let _g = env_lock();
        let Some(mut e) = loopback_engine() else {
            return;
        };
        let sb = sandbox("lb-identify");
        std::env::set_var("IRLUME_GRACE_MS", "0");
        write_enrollment(&sb.dir, &enrollment_with("lbuser", &["Face Scan 1"]));
        // Root keeps the full 1:N search; with no face on the feed it must
        // come back empty, not error and not name anyone.
        let resp = dispatch(Request::Identify, &peer(0), &mut e);
        std::env::remove_var("IRLUME_GRACE_MS");
        match resp {
            Response::Identified {
                user,
                profile,
                live,
                reason,
                ..
            } => {
                assert_eq!(user, None, "no face must identify nobody");
                assert_eq!(profile, None);
                assert!(!live);
                assert!(!reason.is_empty());
            }
            other => panic!("a faceless identify is a no-match, not an error: {other:?}"),
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_enroll_reaches_capture_and_fails_the_no_face_probe_cleanly() {
        let _g = env_lock();
        let Some(mut e) = loopback_engine() else {
            return;
        };
        let sb = sandbox("lb-enroll");
        std::env::set_var("IRLUME_GRACE_MS", "0");
        let resp = dispatch(
            Request::Enroll {
                user: "lbenroll".into(),
                profile: None,
                scans: Some(1),
                reset: false,
            },
            &peer(0),
            &mut e,
        );
        std::env::remove_var("IRLUME_GRACE_MS");
        match resp {
            Response::Error(msg) => assert!(
                msg.contains("check lighting and framing"),
                "a faceless enroll must coach, got: {msg}"
            ),
            other => panic!("a faceless enroll must Error, got {other:?}"),
        }
        assert!(
            !sb.dir.join("lbenroll.json").exists(),
            "a failed enroll must not leave a partial enrollment"
        );
    }

    // ---- env-gated: swtpm ------------------------------------------------

    #[test]
    #[ignore = "needs swtpm via IRLUME_TCTI (CI does this); never runs against a real TPM"]
    fn tpm_seal_and_unseal_keyring_release_the_secret_to_root_only() {
        // Only ever a software TPM: without the explicit TCTI this returns
        // rather than fall back to this machine's /dev/tpmrm0.
        if std::env::var("IRLUME_TCTI").is_err() {
            return;
        }
        let _g = env_lock();
        let mut e = engine();
        let sb = sandbox("tpm-keyring");
        let _ = &sb;
        let root = peer(0);
        let secret = b"hunter2-swtpm".to_vec();
        match dispatch(
            Request::SealPassword {
                user: "carol".into(),
                password: irlume_common::SecretBytes::new(secret.clone()),
            },
            &root,
            &mut e,
        ) {
            Response::PasswordSealed => {}
            other => panic!("sealing against swtpm must succeed, got {other:?}"),
        }
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(armed),
            other => panic!("expected HasPassword(true), got {other:?}"),
        }
        // A real envelope reports its policy.
        match dispatch(
            Request::KeyringInfo {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::KeyringInfo { armed, policy, .. } => {
                assert!(armed);
                assert!(
                    policy.is_some(),
                    "a sealed envelope must describe its policy"
                );
            }
            other => panic!("expected KeyringInfo, got {other:?}"),
        }
        // The sealed login secret is released only to a root peer in a
        // login / lock-screen service class.
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &peer(NOBODY),
            &mut e,
        ) {
            Response::Error(msg) => {
                assert_eq!(
                    msg,
                    format!("unseal_keyring requires root (peer uid {NOBODY})")
                )
            }
            other => panic!("non-root peer must never get the secret, got {other:?}"),
        }
        match dispatch(
            Request::UnsealKeyring {
                user: "carol".into(),
                service: Some("kde".into()),
            },
            &root,
            &mut e,
        ) {
            Response::PasswordUnsealed { secret: got } => assert_eq!(got.expose(), secret),
            other => panic!("root keyring unseal must release the secret, got {other:?}"),
        }
        match dispatch(
            Request::ForgetPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::PasswordForgotten => {}
            other => panic!("expected PasswordForgotten, got {other:?}"),
        }
        match dispatch(
            Request::HasSealedPassword {
                user: "carol".into(),
            },
            &root,
            &mut e,
        ) {
            Response::HasPassword(armed) => assert!(!armed),
            other => panic!("expected HasPassword(false), got {other:?}"),
        }
    }
}
