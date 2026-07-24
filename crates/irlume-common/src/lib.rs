// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Shared types: the daemon<->client IPC protocol, well-known paths, errors.
//!
//! Trust boundary (see docs/ARCHITECTURE.md): the thin `pam_irlume` module and the
//! `irlume` CLI are UNTRUSTED clients. The privileged `irlumed` daemon is the only
//! component that touches the camera, IR emitter, ONNX models, templates and TPM.
//! Clients speak this protocol over a Unix socket; the daemon authenticates them
//! with `SO_PEERCRED` (verify uid/gid of the peer) before honouring privileged
//! requests such as enrollment.

pub mod client;
pub mod config;
pub mod dbglog;
pub mod memlock;
pub mod platform;
pub mod secureboot;
pub mod thirdparty;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unix domain socket the daemon listens on. Root-owned, mode 0660, group-gated.
pub const SOCKET_PATH: &str = "/run/irlume.sock";

/// A byte secret (e.g. the login password) that zeroizes on drop and whose
/// `Debug` is redacted, so it never lingers on the daemon/PAM heap longer than
/// needed nor leaks into a log line. `#[serde(transparent)]` so it ships as a
/// plain byte array over the IPC channel.
#[derive(Clone, Serialize, Default)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

// Manual impl (not derived) so deserialization routes through `new()`: a
// secret received over IPC gets the same memlock treatment as one built
// locally. The derive would construct the inner Vec directly and skip it.
impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(SecretBytes::new(<Vec<u8> as Deserialize>::deserialize(d)?))
    }
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        // Lock the secret's pages against swap / core dumps for its lifetime
        // (defence-in-depth atop the zeroize-on-drop below).
        memlock::lock_slice(&bytes);
        SecretBytes(bytes)
    }
    /// Borrow the raw bytes. Callers must not copy them into a non-zeroizing buffer.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([{} bytes redacted])", self.0.len())
    }
}

/// Per-user enrolled templates + TPM-sealed release secrets.
pub const STATE_DIR: &str = "/var/lib/irlume";

/// The effective state directory, honoring the `IRLUME_STATE_DIR` sandbox
/// override that tests and the model tooling set. Prefer this over the bare
/// `STATE_DIR` constant whenever you resolve a real path, so one override moves
/// every consumer together.
pub fn state_dir() -> std::path::PathBuf {
    std::env::var_os("IRLUME_STATE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(STATE_DIR))
}

/// Create or truncate `path` with mode 0600 and write `bytes`, then fsync.
///
/// Mode-on-open (not write-then-chmod) so a secret-bearing file is never
/// briefly readable under a lax umask. If the file pre-existed at a wider
/// mode, open keeps its permissions, so the mode is re-asserted after the
/// write. `sync_all` makes the bytes durable before any caller renames the
/// file over a live one. Non-unix builds fall back to a plain write.
pub fn write_0600(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)
}

/// Request from an (untrusted) client to the (privileged) daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Attempt to authenticate `user` from a live capture. The default,
    /// unprivileged operation. `service` is the PAM service name (e.g. `sudo`,
    /// `kde-fingerprint`) for tier×operation-class gating; on an RGB-only
    /// (convenience) device only a screen-unlock service is honoured. `None`
    /// from older callers (treated as unrestricted on IR hardware).
    Authenticate {
        user: String,
        #[serde(default)]
        service: Option<String>,
    },
    /// Enrol a (possibly named) profile for `user`. PRIVILEGED: the daemon must
    /// verify via SO_PEERCRED that the caller is root or `user` themselves.
    /// `reset` (default false) wipes the user's existing enrollment first, a
    /// clean re-enroll that also clears a stale camera binding.
    Enroll {
        user: String,
        profile: Option<String>,
        scans: Option<usize>,
        #[serde(default)]
        reset: bool,
    },
    /// 1:N identify ("who is this?"): one live capture matched against every
    /// enrolled user, no claimed identity. Unprivileged (no credential release).
    Identify,
    /// Switch the active RGB+IR camera pair, persisting it (cameras.conf) so it
    /// survives a daemon restart. PRIVILEGED (root or self); writes /etc/irlume.
    SetCameras { rgb: String, ir: String },
    /// Add one scan to an existing profile ("improve recognition"). PRIVILEGED.
    AddScan { user: String, profile: String },
    /// List enrolled profiles + their scans for `user`.
    ListProfiles { user: String },
    /// Delete a whole profile (and its scans). PRIVILEGED, same rule as Enroll.
    DeleteProfile { user: String, profile: String },
    /// Delete one scan from a profile. PRIVILEGED.
    DeleteScan {
        user: String,
        profile: String,
        scan: String,
    },
    /// Rename a profile. PRIVILEGED.
    RenameProfile {
        user: String,
        profile: String,
        new_name: String,
    },
    /// Rename a scan within a profile. PRIVILEGED.
    RenameScan {
        user: String,
        profile: String,
        scan: String,
        new_name: String,
    },
    /// Toggle the per-user "require eyes open to unlock" gate. PRIVILEGED.
    SetRequireEyesOpen { user: String, on: bool },
    /// Toggle the per-user "require blink challenge to unlock" gate (temporal
    /// liveness vs static prints, ADR-0002). PRIVILEGED.
    SetRequireChallenge { user: String, on: bool },
    /// Capture a short IR sequence and return the MEDIAN eye-aspect-ratio over
    /// it: one phase of the deliberate-closure consent calibration. The caller
    /// prompts the user (eyes open, then eyes closed) and sends this once per
    /// phase. Fires the camera; PRIVILEGED.
    CaptureEarMedian { user: String },
    /// Store the per-user eye-closure calibration `(ear_open, ear_closed)` from
    /// the two `CaptureEarMedian` phases into the enrollment. PRIVILEGED.
    SetClosureCalibration {
        user: String,
        ear_open: f32,
        ear_closed: f32,
    },
    /// Auto-configure the IR emitter (integrated linux-enable-ir-emitter): find
    /// and persist the UVC control that lights the 850nm illuminator, using IR
    /// brightness to detect success. `dry_run` only enumerates XU controls.
    SetupIrEmitter { dry_run: bool },
    /// Liveness/alignment self-test (no auth side effects). See PAD self-testing.
    SelfTest { kind: SelfTestKind },
    /// Liveness/health ping.
    Ping,
    /// Daemon self-report: what it actually has loaded and which camera tier it
    /// operates in: ground truth for the Repair tab (a daemon that answers at
    /// all has, by construction, working ONNX Runtime + recognition models).
    Health,
    /// One framing-guide sample (no enrollment, no auth): captures a frame and
    /// returns a [`PositionReport`] of how the user is positioned, for the guided
    /// enrollment cues. Safe to poll repeatedly. `user` is the account being
    /// enrolled: it tunes the pitch band to that user's calibrated neutral (a
    /// read-only lookup) so the guide matches the capture gate. `None` = default band.
    PositionSample { user: Option<String> },

    // --- keyring unlock (TPM-sealed password) -------------------------------
    /// Seal `user`'s login password in the TPM so a later face login can release
    /// it to unlock the GNOME-keyring / KWallet. PRIVILEGED: root or `user`.
    SealPassword { user: String, password: SecretBytes },
    /// Face-verify `user` and, on a live match, release the TPM-sealed password
    /// so the caller can set it as `PAM_AUTHTOK` (login keyring unlock).
    /// PRIVILEGED: root only; the sealed login password is never released to a
    /// non-root peer.
    UnsealPassword {
        user: String,
        /// PAM service name (e.g. `plasmalogin`, `sudo`), for opt-in
        /// biopolicy operation-class gating. `None` from older callers.
        #[serde(default)]
        service: Option<String>,
    },
    /// Release the TPM-sealed password to unlock the login keyring WITHOUT a
    /// face match, for the fingerprint path, where `pam_fprintd` has already
    /// authenticated the user in this PAM transaction (this request only runs at
    /// the post-auth landing). The daemon cannot re-verify a fingerprint
    /// (fprintd owns the sensor), so the gate is: root peer + a login/unlock
    /// service class. Preserves at-rest protection (a stolen disk still can't
    /// unseal); a live root attacker in a login context can obtain it; see
    /// ADR-0003 / THREAT_MODEL. PRIVILEGED: root only.
    UnsealKeyring {
        user: String,
        #[serde(default)]
        service: Option<String>,
    },
    /// Whether `user` has a sealed password armed (for status / CLI / the
    /// delete-erases-it warning). Unprivileged: root or `user`.
    HasSealedPassword { user: String },
    /// Describe `user`'s sealed-password envelope: whether one is armed and,
    /// when it is, the policy tier, bound PCRs, and live PCR drift. The richer
    /// sibling of `HasSealedPassword` for status surfaces (the envelope file
    /// is root-only, so the CLI and TUI ask the daemon instead of reading it).
    /// Callers must fall back to `HasSealedPassword` on an error reply: a
    /// daemon from before this request answers with a parse error.
    /// Unprivileged: root or `user`.
    KeyringInfo { user: String },
    /// Erase `user`'s sealed password (disarms keyring unlock). PRIVILEGED:
    /// root or `user`.
    ForgetPassword { user: String },
    /// Re-seal `user`'s login password against the *current* PCR policy, but
    /// ONLY if a sealed password is already armed (never auto-arms a fresh user)
    /// and only if it actually changed (the PCRs moved, e.g. a dbx/Secure Boot
    /// update, or the user changed their password). Fired from the login
    /// **session** phase, which runs only after authentication SUCCEEDED, so
    /// `password` is always one `pam_unix` accepted (never a typo). PRIVILEGED:
    /// root or `user`.
    ResealPassword { user: String, password: SecretBytes },

    // --- template-key recovery passphrase -----------------------------------
    /// Wrap `user`'s template key under a recovery `passphrase` (the manual
    /// backstop for TPM-clear / dbx / disk-move). Requires an enrolled template
    /// key to exist. PRIVILEGED: root or `user`.
    RecoverySetup {
        user: String,
        passphrase: SecretBytes,
    },
    /// Restore `user`'s template key from the recovery envelope using
    /// `passphrase`, re-sealing it to the current TPM PCRs. PRIVILEGED: root or
    /// `user`.
    RecoveryRestore {
        user: String,
        passphrase: SecretBytes,
    },
    /// Report whether `user` has a sealed template key and/or a recovery
    /// envelope. Unprivileged: root or `user`.
    RecoveryStatus { user: String },
    /// Erase `user`'s recovery envelope (keeps the template key). PRIVILEGED:
    /// root or `user`.
    RecoveryForget { user: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SelfTestKind {
    /// Phase-1 gate: same aligned crop in twice MUST yield cosine ~= 1.0.
    /// Catches the AuraFace alignment/normalization mismatch (the "identical
    /// images score 0.6" trap) before anything else is trusted.
    AlignmentIdentity,
    /// Run the algorithmic IR PAD gate against a captured frame and report cues.
    Liveness,
}

/// A profile and the names of its scans, for `ListProfiles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub name: String,
    pub scans: Vec<String>,
}

/// Framing-guide sample for guided enrollment; no raw image, safe to poll. The
/// gates that set `well_framed` mirror the enroll/auth path, so "well framed"
/// implies a capture will succeed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PositionReport {
    pub face: bool,
    /// Face width / frame width (distance signal).
    pub face_frac: f32,
    pub centered: bool,
    /// Head-orientation proxies (0 frontal yaw; ~0.5 frontal pitch).
    pub yaw_asym: f32,
    pub pitch_frac: f32,
    /// Mean luma (0–255) of the RGB face region (lighting signal).
    pub brightness: f32,
    /// IR companion sees an emitter-lit face (dark-capable / liveness-ready).
    pub ir_ok: bool,
    /// Composite framing quality, 0–100.
    pub quality: u8,
    /// All gates pass; ready to capture.
    pub well_framed: bool,
    /// One plain-language cue for the user ("Move closer", "Hold still", …).
    pub guidance: String,
}

/// Daemon response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Authentication decision plus the evidence behind it.
    AuthResult {
        granted: bool,
        /// Best cosine similarity vs the user's enrolled templates.
        score: f32,
        /// Liveness verdict; auth is granted only if `live` AND score>=threshold.
        live: bool,
        reason: String,
    },
    Profiles(Vec<String>),
    /// Result of a 1:N `Identify`. `user`/`profile` are `None` when no enrolled
    /// face matched (check `live` to tell "no match" from "not a live face").
    Identified {
        user: Option<String>,
        profile: Option<String>,
        score: f32,
        live: bool,
        reason: String,
    },
    /// Structured enrollment listing: profiles (each with its scan names) plus
    /// the per-user require-eyes-open and require-challenge settings.
    Enrollment {
        profiles: Vec<ProfileSummary>,
        require_eyes_open: bool,
        require_challenge: bool,
        /// Whether a usable eye-closure consent calibration is stored (for the
        /// polkit gesture); surfaced so `doctor` can flag wired-but-uncalibrated.
        #[serde(default)]
        closure_calibrated: bool,
    },
    /// Generic success ack for management operations, with a human message.
    Ok(String),
    /// Result of an Enroll capture, carrying the profile the scans actually
    /// landed on. `created` distinguishes a brand-new profile from a merge into
    /// an existing identity (the engine auto-merges a face that already owns a
    /// profile). `added_scans` names the scans this call appended, so a caller
    /// that wants to undo a merge (e.g. the TUI on a declined confirm) can
    /// delete exactly them. See EnrollOutcome.
    Enrolled {
        profile: String,
        created: bool,
        added: usize,
        total: usize,
        added_scans: Vec<String>,
    },
    SelfTest {
        passed: bool,
        detail: String,
    },
    Pong,
    /// Reply to [`Request::Health`]. `rgb_dev`/`ir_dev` are the selected camera
    /// nodes ONLY when they exist right now (never the unvalidated fallback).
    Health {
        /// "secure" (RGB+IR) | "convenience" (RGB-only) | "none" (no camera).
        tier: String,
        rgb_dev: Option<String>,
        ir_dev: Option<String>,
        /// FaceMesh (passive blink liveness) model loaded.
        mesh: bool,
        /// IR domain adapter loaded.
        adapter: bool,
        /// The daemon's crate version; lets the TUI flag a stale installed
        /// build (daemon predating the CLI it's talking to).
        #[serde(default)]
        version: String,
        /// Name of the loaded opt-in third-party PAD cue, if any. The
        /// authoritative enabled-state: settings.conf is root-only, so a
        /// non-root TUI can only see the weights file otherwise. `None` when
        /// no cue is loaded (or an older daemon that predates this field).
        #[serde(default)]
        third_party_pad: Option<String>,
    },
    /// A framing-guide sample (`PositionSample`).
    Position(PositionReport),
    /// Median eye-aspect-ratio over a capture (`CaptureEarMedian`); `None` if no
    /// eye was detected in any frame.
    EarMedian(Option<f32>),
    Error(String),

    // --- keyring unlock responses -------------------------------------------
    /// The password was sealed (`SealPassword`).
    PasswordSealed,
    /// Face matched and the TPM released the password (`UnsealPassword`).
    PasswordUnsealed {
        secret: SecretBytes,
    },
    /// Whether a sealed password exists (`HasSealedPassword`).
    HasPassword(bool),
    /// Envelope detail (`KeyringInfo`). `policy` is `None` and `pcrs` empty
    /// when nothing is armed (or the envelope is unreadable); `drifted` is
    /// `None` when there is nothing to compare or the PCR replay failed.
    KeyringInfo {
        armed: bool,
        #[serde(default)]
        policy: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pcrs: Vec<u32>,
        #[serde(default)]
        drifted: Option<bool>,
    },
    /// The sealed password was erased (`ForgetPassword`).
    PasswordForgotten,
    /// Outcome of a `ResealPassword`. `changed` is true when the envelope was
    /// (re-)written: either the old one no longer unsealed (PCRs moved) or the
    /// password differed. `armed` is false when the user has no sealed password
    /// at all, in which case nothing was done (we never auto-arm).
    PasswordResealed {
        armed: bool,
        changed: bool,
    },

    // --- recovery responses -------------------------------------------------
    /// Status of `user`'s template-key encryption and recovery passphrase
    /// (`RecoveryStatus`): whether templates are encrypted (a sealed key exists)
    /// and whether a recovery passphrase is set.
    RecoveryStatus {
        encrypted: bool,
        recovery_set: bool,
        tpm_present: bool,
    },
}

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("not authorized: {0}")]
    NotAuthorized(String),
    #[error("hardware: {0}")]
    Hardware(String),
    #[error("tpm: {0}")]
    Tpm(String),
    #[error("policy: {0}")]
    Policy(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Test-only: every test that mutates process environment variables
/// (IRLUME_SOCKET, IRLUME_CONFIG_DIR, IRLUME_STATE_DIR, ...) serializes on this
/// one lock; setenv/getenv are process-global, and the test harness runs
/// modules concurrently.
#[cfg(test)]
pub(crate) mod testenv {
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub fn lock() -> MutexGuard<'static, ()> {
        // A panic under the lock (failed assert) must not cascade into every
        // later env test; the env itself is per-test state, not shared data.
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `Locked:` kB of the /proc/self/smaps mapping containing `addr`
    /// (Linux splits a VMA on mlock, so a locked buffer's mapping reports a
    /// nonzero value). `None` when the address isn't found.
    fn locked_kb_of(addr: usize) -> Option<u64> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
        let mut in_range = false;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ') {
                if let Some((s, e)) = range.split_once('-') {
                    if let (Ok(s), Ok(e)) =
                        (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16))
                    {
                        in_range = s <= addr && addr < e;
                        continue;
                    }
                }
            }
            if in_range {
                if let Some(rest) = line.strip_prefix("Locked:") {
                    return rest.trim().trim_end_matches("kB").trim().parse().ok();
                }
            }
        }
        None
    }

    // Regression: e8e59c2. SecretBytes derived Deserialize, constructing the
    // inner Vec directly and skipping new()'s mlock: a secret received over
    // IPC was swappable/dumpable. Deserialization must route through new(),
    // observable as the deserialized buffer's pages being memlocked.
    #[test]
    fn deserialized_secret_bytes_are_memlocked_like_new() {
        // Big enough to own whole pages, so the smaps Locked field is
        // unambiguous; serialized from a plain (unlocked) Vec.
        let payload: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
        let wire = serde_json::to_string(&payload).unwrap();

        // Deserialize FIRST, before anything else in this test locks pages the
        // allocator might hand back.
        let de: SecretBytes = serde_json::from_str(&wire).unwrap();
        assert_eq!(de.expose(), payload.as_slice());
        assert_eq!(de.len(), payload.len());
        assert!(!de.is_empty());
        // Debug stays redacted through the custom impl path.
        assert_eq!(format!("{de:?}"), "SecretBytes([16384 bytes redacted])");

        // Control: can this environment mlock at all? (RLIMIT_MEMLOCK may
        // forbid it; lock_slice is best-effort by design, so then there is
        // nothing observable to assert and the test stands down.)
        let control = SecretBytes::new(vec![0x5a; 16384]);
        let control_mid = control.expose().as_ptr() as usize + 8192;
        match locked_kb_of(control_mid) {
            Some(kb) if kb > 0 => {}
            _ => {
                eprintln!("skipping: environment cannot mlock (RLIMIT_MEMLOCK?)");
                return;
            }
        }
        let de_mid = de.expose().as_ptr() as usize + 8192;
        let locked = locked_kb_of(de_mid).unwrap_or(0);
        assert!(
            locked > 0,
            "a deserialized SecretBytes must be memlocked like a new()-built one"
        );
    }

    #[test]
    fn error_display_prefixes_each_variant() {
        // The PAM module and CLI print these verbatim; the category prefix is
        // what tells a user (and the docs) which subsystem failed.
        let cases: &[(Error, &str)] = &[
            (Error::Io("socket gone".into()), "io: socket gone"),
            (Error::Protocol("bad frame".into()), "protocol: bad frame"),
            (
                Error::NotAuthorized("peer uid 1000".into()),
                "not authorized: peer uid 1000",
            ),
            (Error::Hardware("no camera".into()), "hardware: no camera"),
            (Error::Tpm("unseal failed".into()), "tpm: unseal failed"),
            (
                Error::Policy("PCR mismatch: [7]".into()),
                "policy: PCR mismatch: [7]",
            ),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), *want);
        }
    }

    #[test]
    fn secret_bytes_expose_len_and_redaction_invariants() {
        let sb = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(sb.expose(), &[1, 2, 3]);
        assert_eq!(sb.len(), sb.expose().len());
        assert!(!sb.is_empty());
        // Debug must name only the length, never any content byte.
        assert_eq!(format!("{sb:?}"), "SecretBytes([3 bytes redacted])");

        // A clone exposes the same bytes but its own copy (drop-zeroize of one
        // must not scrub the other).
        let clone = sb.clone();
        assert_eq!(clone.expose(), sb.expose());
        assert_ne!(clone.expose().as_ptr(), sb.expose().as_ptr());

        // Explicit zeroize empties the buffer (Vec zeroize scrubs + clears).
        let mut z = SecretBytes::new(vec![9; 32]);
        z.zeroize();
        assert!(z.is_empty());
        assert_eq!(z.len(), 0);

        // Default is the empty secret.
        let d = SecretBytes::default();
        assert!(d.is_empty());
        assert_eq!(format!("{d:?}"), "SecretBytes([0 bytes redacted])");

        // #[serde(transparent)]: ships as a plain byte array on the wire.
        assert_eq!(
            serde_json::to_string(&SecretBytes::new(vec![7, 8])).unwrap(),
            "[7,8]"
        );
    }

    #[test]
    fn request_wire_compat_defaults_for_older_callers() {
        // An 0.1.x pam_irlume sends Authenticate without `service`; the field
        // must default to None, not fail the parse (login would break).
        let r: Request = serde_json::from_str(r#"{"Authenticate":{"user":"alice"}}"#).unwrap();
        match r {
            Request::Authenticate { user, service } => {
                assert_eq!(user, "alice");
                assert_eq!(service, None);
            }
            other => panic!("expected Authenticate, got {other:?}"),
        }
        // Enroll without `reset` (pre-0.5 callers) defaults to false: an old
        // client must never trigger the wipe-first path.
        let r: Request =
            serde_json::from_str(r#"{"Enroll":{"user":"alice","profile":null,"scans":null}}"#)
                .unwrap();
        match r {
            Request::Enroll { user, reset, .. } => {
                assert_eq!(user, "alice");
                assert!(!reset);
            }
            other => panic!("expected Enroll, got {other:?}"),
        }
        // Response::Health from a daemon predating `version` parses with the
        // empty-string default (the TUI shows "unknown" instead of erroring).
        let r: Response = serde_json::from_str(
            r#"{"Health":{"tier":"secure","rgb_dev":null,"ir_dev":null,"mesh":true,"adapter":false}}"#,
        )
        .unwrap();
        match r {
            Response::Health { version, tier, .. } => {
                assert_eq!(version, "");
                assert_eq!(tier, "secure");
            }
            other => panic!("expected Health, got {other:?}"),
        }
    }

    #[test]
    fn enrolled_response_round_trips() {
        // The daemon serializes Response over the socket and the TUI/CLI
        // deserialize it; the enroll merge fix depends on this variant carrying
        // the resolved profile + the merged scan names intact.
        for r in [
            Response::Enrolled {
                profile: "Face Profile 1".into(),
                created: true,
                added: 3,
                total: 3,
                added_scans: vec![],
            },
            Response::Enrolled {
                profile: "Face Profile 1".into(),
                created: false,
                added: 1,
                total: 8,
                added_scans: vec!["scan8".into()],
            },
        ] {
            let wire = serde_json::to_string(&r).unwrap();
            let back: Response = serde_json::from_str(&wire).unwrap();
            match (r, back) {
                (
                    Response::Enrolled {
                        profile: p1,
                        created: c1,
                        added: a1,
                        total: t1,
                        added_scans: s1,
                    },
                    Response::Enrolled {
                        profile: p2,
                        created: c2,
                        added: a2,
                        total: t2,
                        added_scans: s2,
                    },
                ) => {
                    assert_eq!((p1, c1, a1, t1, s1), (p2, c2, a2, t2, s2));
                }
                _ => panic!("Enrolled did not round-trip to Enrolled"),
            }
        }
    }
}
