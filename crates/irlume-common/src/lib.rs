//! Shared types: the daemon<->client IPC protocol, well-known paths, errors.
//!
//! Trust boundary (see docs/ARCHITECTURE.md): the thin `pam_irlume` module and the
//! `irlume` CLI are UNTRUSTED clients. The privileged `irlumed` daemon is the only
//! component that touches the camera, IR emitter, ONNX models, templates and TPM.
//! Clients speak this protocol over a Unix socket; the daemon authenticates them
//! with `SO_PEERCRED` (verify uid/gid of the peer) before honouring privileged
//! requests such as enrollment.

use serde::{Deserialize, Serialize};

/// Unix domain socket the daemon listens on. Root-owned, mode 0660, group-gated.
pub const SOCKET_PATH: &str = "/run/irlume.sock";

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
    Enroll { user: String, profile: Option<String> },
    /// List enrolled profiles for `user`.
    ListProfiles { user: String },
    /// Delete a profile (privileged, same rule as Enroll).
    DeleteProfile { user: String, profile: String },
    /// Liveness/alignment self-test (no auth side effects). See PAD self-testing.
    SelfTest { kind: SelfTestKind },
    /// Liveness/health ping.
    Ping,
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
    SelfTest { passed: bool, detail: String },
    Pong,
    Error(String),
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
}

pub type Result<T> = std::result::Result<T, Error>;
