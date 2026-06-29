//! Shared types: the daemon<->client IPC protocol, well-known paths, errors.
//!
//! Trust boundary (see docs/ARCHITECTURE.md): the thin `pam_irlume` module and the
//! `irlume` CLI are UNTRUSTED clients. The privileged `irlumed` daemon is the only
//! component that touches the camera, IR emitter, ONNX models, templates and TPM.
//! Clients speak this protocol over a Unix socket; the daemon authenticates them
//! with `SO_PEERCRED` (verify uid/gid of the peer) before honouring privileged
//! requests such as enrollment.

pub mod platform;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unix domain socket the daemon listens on. Root-owned, mode 0660, group-gated.
pub const SOCKET_PATH: &str = "/run/irlume.sock";

/// A byte secret (e.g. the login password) that zeroizes on drop and whose
/// `Debug` is redacted, so it never lingers on the daemon/PAM heap longer than
/// needed nor leaks into a log line. `#[serde(transparent)]` so it ships as a
/// plain byte array over the IPC channel.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
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

/// Where models live at runtime (bundled via `include_bytes!` in `irlume-vision`,
/// this path is only for optional overrides / operator-supplied weights).
pub const MODEL_DIR: &str = "/usr/share/irlume/models";

/// Per-user enrolled templates + TPM-sealed release secrets.
pub const STATE_DIR: &str = "/var/lib/irlume";

/// Request from an (untrusted) client to the (privileged) daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Attempt to authenticate `user` from a live capture. The default,
    /// unprivileged operation.
    Authenticate { user: String },
    /// Enrol a (possibly named) profile for `user`. PRIVILEGED: the daemon must
    /// verify via SO_PEERCRED that the caller is root or `user` themselves.
    Enroll { user: String, profile: Option<String>, scans: Option<usize> },
    /// Add one scan to an existing profile ("improve recognition"). PRIVILEGED.
    AddScan { user: String, profile: String },
    /// List enrolled profiles + their scans for `user`.
    ListProfiles { user: String },
    /// Delete a whole profile (and its scans). PRIVILEGED, same rule as Enroll.
    DeleteProfile { user: String, profile: String },
    /// Delete one scan from a profile. PRIVILEGED.
    DeleteScan { user: String, profile: String, scan: String },
    /// Rename a profile. PRIVILEGED.
    RenameProfile { user: String, profile: String, new_name: String },
    /// Rename a scan within a profile. PRIVILEGED.
    RenameScan { user: String, profile: String, scan: String, new_name: String },
    /// Toggle the per-user "require eyes open to unlock" gate. PRIVILEGED.
    SetRequireEyesOpen { user: String, on: bool },
    /// Auto-configure the IR emitter (integrated linux-enable-ir-emitter): find
    /// and persist the UVC control that lights the 850nm illuminator, using IR
    /// brightness to detect success. `dry_run` only enumerates XU controls.
    SetupIrEmitter { dry_run: bool },
    /// Liveness/alignment self-test (no auth side effects). See PAD self-testing.
    SelfTest { kind: SelfTestKind },
    /// Liveness/health ping.
    Ping,

    // --- keyring unlock (TPM-sealed password) -------------------------------
    /// Seal `user`'s login password in the TPM so a later face login can release
    /// it to unlock the GNOME-keyring / KWallet. PRIVILEGED: root or `user`.
    SealPassword { user: String, password: SecretBytes },
    /// Face-verify `user` and, on a live match, release the TPM-sealed password
    /// so the caller can set it as `PAM_AUTHTOK` (login keyring unlock).
    /// PRIVILEGED: root only — the sealed login password is never released to a
    /// non-root peer.
    UnsealPassword { user: String },
    /// Whether `user` has a sealed password armed (for status / CLI / the
    /// delete-erases-it warning). Unprivileged: root or `user`.
    HasSealedPassword { user: String },
    /// Erase `user`'s sealed password (disarms keyring unlock). PRIVILEGED:
    /// root or `user`.
    ForgetPassword { user: String },
    /// Re-seal `user`'s login password against the *current* PCR policy, but
    /// ONLY if a sealed password is already armed (never auto-arms a fresh user)
    /// and only if it actually changed (the PCRs moved, e.g. a dbx/Secure Boot
    /// update, or the user changed their password). Fired from the login
    /// **session** phase — which runs only after authentication SUCCEEDED — so
    /// `password` is always one `pam_unix` accepted (never a typo). PRIVILEGED:
    /// root or `user`.
    ResealPassword { user: String, password: SecretBytes },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Structured enrollment listing: profiles (each with its scan names) plus
    /// the per-user require-eyes-open setting.
    Enrollment { profiles: Vec<ProfileSummary>, require_eyes_open: bool },
    /// Generic success ack for management operations, with a human message.
    Ok(String),
    SelfTest { passed: bool, detail: String },
    Pong,
    Error(String),

    // --- keyring unlock responses -------------------------------------------
    /// The password was sealed (`SealPassword`).
    PasswordSealed,
    /// Face matched and the TPM released the password (`UnsealPassword`).
    PasswordUnsealed { secret: SecretBytes },
    /// Whether a sealed password exists (`HasSealedPassword`).
    HasPassword(bool),
    /// The sealed password was erased (`ForgetPassword`).
    PasswordForgotten,
    /// Outcome of a `ResealPassword`. `changed` is true when the envelope was
    /// (re-)written: either the old one no longer unsealed (PCRs moved) or the
    /// password differed. `armed` is false when the user has no sealed password
    /// at all, in which case nothing was done (we never auto-arm).
    PasswordResealed { armed: bool, changed: bool },
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
