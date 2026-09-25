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

pub mod artifact;
pub mod client;
pub mod config;
pub mod dbglog;
pub mod diagnostics;
pub mod gkr_wire;
pub mod journal_out;
pub mod live;
pub mod live_camera;
pub mod memlock;
pub mod pam_service;
pub mod platform;
pub mod process;
pub mod secureboot;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unix domain socket the daemon listens on. Root-owned, mode 0666: every local
/// uid may connect, and `SO_PEERCRED` authorizes each request.
pub const SOCKET_PATH: &str = "/run/irlume.sock";

/// A byte secret (e.g. the login password) that zeroizes on drop and whose
/// `Debug` is redacted, so it never lingers on the daemon/PAM heap longer than
/// needed nor leaks into a log line. `#[serde(transparent)]` so it ships as a
/// plain byte array over the IPC channel.
#[derive(Serialize, Default)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

// Manual so every copied allocation receives the same protection as a newly
// constructed or deserialized secret. Deriving Clone copies the Vec directly
// and bypasses new().
impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

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

/// The fixed-size KDE wallet salt carried by authorized callers.
///
/// The wrapper makes the 56-byte wire invariant part of deserialization, so a
/// malformed or mixed-version client is rejected before daemon dispatch. Its
/// debug representation never includes salt bytes.
#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct WalletSalt(SecretBytes);

impl WalletSalt {
    /// Construct a wallet salt only when it has KDE's exact wire length.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() == kwallet_wire::SALT_LEN).then(|| Self(SecretBytes::new(bytes)))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl<'de> Deserialize<'de> for WalletSalt {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let bytes = SecretBytes::deserialize(d)?;
        if bytes.len() != kwallet_wire::SALT_LEN {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"exactly 56 wallet-salt bytes",
            ));
        }
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for WalletSalt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletSalt([{} bytes redacted])", self.0.len())
    }
}

/// Where the irlume packages install onnxruntime: Fedora/Copr first, then the
/// Debian/Ubuntu universal .deb and PPA layout (packaging/README.md records
/// both). Their systemd drop-in hands `ORT_DYLIB_PATH` to the DAEMON only, so
/// anything running as a bare CLI has to probe these paths itself.
///
/// Shared rather than restated: `irlume deps` kept its own shorter list that
/// had neither packaged path, so with the daemon stopped it told users to
/// install onnxruntime on machines where the package had already installed it,
/// at exactly the moment they were debugging a failed login.
pub const PACKAGED_ORT_PATHS: &[&str] = &[
    "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
    "/opt/irlume/onnxruntime/lib/libonnxruntime.so",
];

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
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

/// Hex sha256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A model's weights together with the sha256 of THOSE weights.
///
/// Whoever checks a model against a manifest or a catalog pin, and whoever
/// loads it, both need the digest, and hashing a 260MB recognizer twice per
/// start cost measurable time for nothing (#346). Carrying the pair in one
/// value removes the second pass, and it removes the failure mode that would
/// have come with passing a loose digest alongside loose bytes: the constructor
/// is the only way in and it takes the digest from the buffer it stores, so the
/// two cannot be from different artifacts. The invariant is pinned by
/// `the_digest_always_belongs_to_the_bytes_it_was_built_from` rather than by a
/// doctest: the sanitizer lane builds with an explicit target and no
/// instrumented std, so a doctest there fails to link while a unit test runs
/// in every lane.
pub struct HashedModel {
    bytes: Vec<u8>,
    sha256: String,
}

impl HashedModel {
    /// Hash `bytes` once and keep both halves.
    pub fn new(bytes: Vec<u8>) -> Self {
        let sha256 = sha256_hex(&bytes);
        Self { bytes, sha256 }
    }

    /// Hex sha256 of [`Self::bytes`].
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The weights themselves.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the artifact and transfer its allocation to an owning loader.
    /// The digest is discarded so later mutations cannot leave a stale pair.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Make every directory above `dir` durable, so the names leading to it survive
/// a power loss.
///
/// Shallowest first, because a directory's entry lives in its parent: syncing
/// `/var/lib/irlume` makes `login-transactions` findable, and does nothing for
/// `irlume` itself, whose entry is in `/var/lib`. A record fsynced into a
/// directory whose name did not survive is not a record.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn fsync_ancestors(dir: &std::path::Path) -> std::result::Result<(), String> {
    for parent in ancestor_chain(dir) {
        fsync_dir(&parent)?;
    }
    Ok(())
}

/// The directories to sync above `dir`, shallowest first.
///
/// Separated out because the interesting case cannot be observed from outside:
/// whether an `fsync` happened is not visible in the filesystem afterwards, so
/// the list is what a test can actually assert on.
pub fn ancestor_chain(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut chain: Vec<std::path::PathBuf> = dir
        .ancestors()
        .skip(1) // `dir` itself is synced by the atomic write that fills it
        .map(|p| {
            // A relative path's last ancestor is "", which opens nothing. The
            // directory a relative path is anchored in is the working
            // directory, and that is where the entry actually lives. Filtering
            // the empty one out instead left `IRLUME_STATE_DIR=state` syncing
            // `state` while nothing synced the `state` entry itself.
            if p.as_os_str().is_empty() {
                std::path::PathBuf::from(".")
            } else {
                p.to_path_buf()
            }
        })
        .collect();
    chain.reverse();
    chain
}

/// Make a directory's own contents durable, so entries created in it survive a
/// power loss.
///
/// `fsync(2)` is explicit that syncing a file does not necessarily persist the
/// directory entry naming it; the directory has to be synced too. Opening a
/// directory read-only and syncing that descriptor is the way to do it.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn fsync_dir(dir: &std::path::Path) -> std::result::Result<(), String> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync {}: {e}", dir.display()))
}

/// Set `path`'s permission bits, naming the path when it fails.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn restrict(path: &std::path::Path, mode: u32) -> std::result::Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

/// Remove `path` and make its absence durable.
///
/// The counterpart to [`write_0600_atomic`] for a record whose whole meaning is
/// "there is unfinished business here": an unlink still sitting in the page
/// cache when the machine loses power brings the record back, and a record that
/// comes back is acted on again. Already-gone is success, because the caller's
/// postcondition is that nothing is there.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn remove_durable(path: &std::path::Path) -> std::result::Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("remove {}: {e}", path.display())),
    }
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    fsync_dir(dir)
}

/// Create or truncate `path` with mode 0600 and write `bytes`, then fsync.
///
/// Mode-on-open (not write-then-chmod) so a secret-bearing file is never
/// briefly readable under a lax umask. If the file pre-existed at a wider
/// mode, open keeps its permissions, so the mode is re-asserted after the
/// write. `sync_all` makes the bytes durable before any caller renames the
/// file over a live one. Non-unix builds fall back to a plain write.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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

/// Like [`write_0600`] but ATOMIC: write a unique 0600 temp file in the same
/// directory, fsync it, rename it over `path`, then fsync the directory. A
/// crash, ENOSPC, or kill mid-write leaves the PRE-EXISTING file byte-for-byte
/// intact instead of a truncated/half-written one. Use this for anything a
/// failed rewrite must never corrupt: a TPM-sealed keyring password or template
/// key whose loss would drop face auth to the password until a re-seal or
/// re-enroll. The rename replaces the target in one step, so a reader (the
/// greeter unseal) sees either the whole old file or the whole new one, never a
/// torn write. Temp and target must share a directory so the rename stays within
/// one filesystem (where rename is atomic).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn write_0600_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_mode(path, bytes, 0o600)
}

/// [`write_0600_atomic`] at a caller-chosen mode.
///
/// Exists because not everything that needs the atomic, fsynced write is secret.
/// `ir_emitter.conf` names a camera and a control number; it needed durability,
/// not privacy.
///
/// `mode` is a CEILING, not a guarantee: the kernel applies the process umask to
/// a newly created file, so the result is `mode & !umask`. `irlumed.service`
/// sets `UMask=0027`, which turns a requested 0644 into 0640 — and that is
/// deliberately left alone, because `std::fs::write` behaved identically
/// (`0666 & !umask` is also 0640 there) and forcing the requested bits would
/// WIDEN permissions on machines already running. The 0600 callers are
/// unaffected: a umask can only remove bits, and every ordinary umask removes
/// none of those.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn write_atomic_mode(path: &std::path::Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    match write_atomic_reporting(path, bytes, mode)? {
        AtomicWrite::Durable => Ok(()),
        AtomicWrite::VisibleNotDurable(e) => Err(e),
    }
}

/// [`write_atomic_mode`] that keeps the mode of an EXISTING file and only uses
/// `default_mode` when creating one.
///
/// For rewrite-in-place surfaces whose current mode is the deployed truth: a
/// PAM stack a distro shipped 0600 must not come back 0644 because our edit
/// replaced the file (2026-08-29 audit; `write_pam_edit` used to force 0644).
/// The umask ceiling note of [`write_atomic_mode`] applies, so the replacement
/// can only come out EQUAL OR TIGHTER than the mode being preserved, never
/// wider.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn write_atomic_preserving(
    path: &std::path::Path,
    bytes: &[u8],
    default_mode: u32,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(default_mode);
        write_atomic_mode(path, bytes, mode)
    }
    #[cfg(not(unix))]
    write_atomic_mode(path, bytes, default_mode)
}

/// How far an atomic write got.
///
/// "It returned an error" and "nothing became visible" are not the same thing,
/// and three separate defects on #183 came from treating them as one. The rename
/// publishes the new content immediately and atomically; the fsyncs that make it
/// survive a power loss come afterwards, and a failure there leaves the new
/// content exactly where it was put.
#[derive(Debug)]
pub enum AtomicWrite {
    /// Written, published, and both the file and its directory made durable.
    Durable,
    /// The rename landed, so the new content IS what a reader sees, but a later
    /// fsync failed and it may not survive a power loss. A caller that must know
    /// what is visible now has to treat this as published.
    ///
    /// NOT COVERED BY A TEST. Nothing available here can make a directory fsync
    /// fail; provoking it needs filesystem fault injection, and a mutant that
    /// reverts this arm to `?` propagation survives the suite. The branch rests
    /// on `rename(2)` being atomic and immediate and `fsync(2)` being a separate
    /// step, not on anything observed.
    VisibleNotDurable(std::io::Error),
}

/// [`write_atomic_mode`], reporting whether the content became visible when the
/// durability step failed. `Err` means nothing was published.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn write_atomic_reporting(
    path: &std::path::Path,
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<AtomicWrite> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("irlume");
        // Unique per call: pid plus a process-monotonic counter (no time
        // dependency). create_new below never adopts a stale or planted temp, so
        // the inode is always freshly ours at 0600.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = dir.join(format!(".{name}.tmp.{}.{seq}", std::process::id()));
        // create_new + mode(0o600): the mode is set at CREATION, before the fsync,
        // so sync_all captures the final permissions; no post-fsync metadata
        // change. On the rare stale-temp collision (a crashed prior writer reusing
        // this pid+seq), drop it and retry once.
        let open_tmp = || {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)
        };
        let mut f = match open_tmp() {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&tmp)?;
                open_tmp()?
            }
            other => other?,
        };
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp); // don't leave a stray temp behind
            return Err(e);
        }
        // fsync the directory so the rename (the directory entry that makes the
        // new bytes visible under `path`) is itself durable across a power loss.
        // The rename has ALREADY happened, so a failure here does not un-publish
        // anything: the new content is what a reader sees, it simply might not
        // survive a power loss. Reported as such rather than as a plain error,
        // because a caller that then behaves as though nothing was written is
        // exactly how a half-published file goes unnoticed.
        match std::fs::File::open(dir).and_then(|d| d.sync_all()) {
            Ok(()) => Ok(AtomicWrite::Durable),
            Err(e) => Ok(AtomicWrite::VisibleNotDurable(e)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, bytes)?;
        Ok(AtomicWrite::Durable)
    }
}

/// How a privileged face request claims explicit user intent was collected.
/// The daemon still validates the service class and peer credentials; this is
/// an assertion, not cryptographic proof of physical input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentAttestation {
    /// A root PAM client reports collecting the conventional confirmation.
    PamConversation,
    /// A root PAM client reports that this machine's policy waives the
    /// confirmation (`privileged_face_consent=0`). Never trusted on its own:
    /// the daemon re-reads the same policy before honouring it, so a client
    /// cannot waive a confirmation the machine still requires.
    PolicyWaived,
}

/// Public progress contains counts and a profile label, never biometric scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnrollmentEvent {
    Started,
    Progress { captured: usize, target: usize },
    Merge { profile: String, remaining: usize },
}

/// The sole continuation accepted on an enrollment session's own socket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentDecision {
    pub accept: bool,
}

/// Control an accepted framing connection. Reports are never generated ahead
/// of demand. Finish waits for camera release; disconnect cancels instead.
#[derive(Debug, Serialize, Deserialize)]
pub enum PositionSessionControl {
    Sample,
    Finish,
}

/// Hard protocol bounds for one interactive framing operation.
pub const POSITION_SESSION_SECONDS: u64 = 60;
/// Bounds an untrusted peer independently of the elapsed-time limit.
pub const POSITION_SESSION_MAX_SAMPLES: usize = 256;

/// Request from an untrusted client to the privileged daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Attempt to authenticate `user` from a live capture. The default,
    /// unprivileged operation. `service` is the PAM service name (e.g. `sudo`,
    /// `kde-fingerprint`) for tier×operation-class gating; on an RGB-only
    /// (convenience) device only a screen-unlock service is honoured. `None`
    /// from older callers (treated as unrestricted on IR hardware).
    Authenticate {
        /// Opt in to typed hardware errors. Omitted/false preserves legacy
        /// Error replies; older daemons ignore this additional request field.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        structured_errors: bool,
        user: String,
        #[serde(default)]
        service: Option<String>,
        /// Root PAM's assertion that it collected conventional confirmation.
        /// The daemon rejects it from untrusted peers and irrelevant services.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intent_confirmation: Option<IntentAttestation>,
    },
    /// Enrol a (possibly named) profile for `user`. PRIVILEGED: the daemon must
    /// verify via SO_PEERCRED that the caller is root or `user` themselves.
    /// `reset` (default false) replaces profiles and the camera binding only
    /// after successful capture, preserving the template key and recovery setup.
    Enroll {
        user: String,
        profile: Option<String>,
        scans: Option<usize>,
        #[serde(default)]
        reset: bool,
    },
    /// One authorized guided operation. Only this opt-in request receives
    /// streamed enrollment events and can answer a merge on the same socket.
    EnrollmentSession {
        user: String,
        profile: Option<String>,
        scans: usize,
        improve: bool,
    },
    /// 1:N identify ("who is this?"): one live capture, no claimed identity.
    /// Unprivileged (no credential release), but NOT unscoped: a root peer is
    /// matched against every enrolled user, and a non-root peer only against its
    /// own account. The CLI help has always said so; this wire doc did not, and
    /// it is the contract the machine surface keys off. Root's search spans
    /// accounts and is therefore filed in no account's attempt record; a
    /// client that shows one account's recognition test sends
    /// [`Request::IdentifyFor`] instead.
    Identify,
    /// Switch the active RGB+IR camera pair, persisting it (cameras.conf) so it
    /// survives a daemon restart. ROOT ONLY: it writes a system-wide setting
    /// under /etc/irlume, which is not an arbitrary peer's to change. (This said
    /// "root or self", which never matched the dispatch gate.)
    SetCameras { rgb: String, ir: String },
    /// Apply a camera choice only while its observed device generation exists.
    SetCamerasIfCurrent {
        rgb: String,
        ir: String,
        expected: live_camera::CameraSelection,
    },
    /// Add scans to an existing profile ("improve recognition"). PRIVILEGED.
    /// Add scans to an existing profile, in the recognizer space the daemon
    /// has loaded. Also how a profile gains a second recognizer's templates
    /// without re-enrolling as a new person (#288).
    AddScan {
        user: String,
        profile: String,
        /// How many scans to capture. Absent (an older CLI) means one, the
        /// behaviour this request always had.
        #[serde(default)]
        scans: Option<usize>,
        /// Ask for a full [`Response::Enrolled`] (with the per-recognizer
        /// room and the ambient-lit count, #312) instead of the legacy
        /// `Response::Ok` prose. Absent (an older CLI) keeps the legacy
        /// reply, so nothing already parsing the Ok string breaks.
        #[serde(default)]
        report_enrollment: bool,
    },
    /// Enroll the CURRENT camera pair as a secondary camera group
    /// (ADR-0024 §4): an attended, credential-management-authorized
    /// addition - the new camera never authorizes its own addition. The
    /// captured face must match the named primary profile. PRIVILEGED and
    /// PolicyKit-approved like every enrollment addition.
    AddCameraGroup {
        user: String,
        /// The primary profile the captured scans belong to. `None` uses
        /// the enrollment's only profile; an ambiguous set must name one.
        profile: Option<String>,
        /// Capture target for the new group. Absent (an older CLI) means
        /// DEFAULT_ENROLL_SCANS, the add-camera target (ADR-0024 §3).
        #[serde(default)]
        scans: Option<usize>,
    },
    /// Remove one secondary camera group (ADR-0024 §4.2): its binding,
    /// scans, and derived state go together under the same
    /// credential-management authorization; in-flight authentication on
    /// the group refuses at its grant boundary. PRIVILEGED.
    RemoveCameraGroup {
        user: String,
        /// The immutable group id (as reported when it was enrolled), or
        /// the opaque group id a handle-correlating client was given.
        group: String,
    },
    /// List enrolled profiles + their scans for `user`.
    ListProfiles {
        user: String,
        /// Opt in to [`Response::OperationError`] instead of
        /// [`Response::Error`].
        ///
        /// This exists because the socket has to survive a package upgrade in
        /// both directions: the old daemon keeps running until it restarts, so
        /// a new client can meet an old daemon and vice versa. An unknown
        /// response variant fails to deserialize outright, so the daemon must
        /// never send a typed error to a client that did not ask for one. An
        /// old client omits this field, serde defaults it to false, and the
        /// daemon answers exactly as before. A new client meeting an old daemon
        /// is equally safe: serde ignores the unknown field and the old daemon
        /// replies with the prose `Error` the new client still handles.
        #[serde(default)]
        structured_errors: bool,
        /// The client correlates camera roles by the daemon's pair handles
        /// (ADR-0030 §4) and does not need binding identities: a non-root
        /// peer that sets this receives `vid:pid` binding sides and an
        /// opaque group id in place of the store's identity-derived one
        /// (which [`Request::RemoveCameraGroup`] accepts). A client that
        /// omits it — one that predates handles and matches roles on the
        /// identities itself — keeps receiving exactly what it did, so its
        /// labels do not silently change meaning across the upgrade. Same
        /// compatibility shape as `structured_errors`.
        #[serde(default)]
        handles: bool,
    },
    /// Delete a whole profile (and its scans). PRIVILEGED, same rule as Enroll.
    DeleteProfile { user: String, profile: String },
    /// Delete one scan from a profile. PRIVILEGED.
    DeleteScan {
        user: String,
        profile: String,
        scan: String,
    },
    /// Remove every scan `user` holds in one recognizer's embedding space,
    /// plus the calibrations fitted from them (#288). PRIVILEGED, same rule
    /// as DeleteProfile.
    ///
    /// `models disable` deletes a recognizer's weights and deliberately keeps
    /// its templates, so that re-enabling it later needs no re-enrollment.
    /// This request is the deliberate counterpart for when the operator wants
    /// that biometric material gone. `space` is the embedding-space tag
    /// (`embed:<sha256>` of the recognizer weights); the CLI resolves a
    /// catalog name to it. A profile left with no scans is deleted with them:
    /// an empty profile can never match, and `DeleteScan` upholds the same
    /// never-orphaned rule.
    ForgetRecognizer { user: String, space: String },
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
    /// Retired eyes-open policy. Kept parseable for one release; OFF performs
    /// legacy cleanup and ON returns a retired error. PRIVILEGED.
    SetRequireEyesOpen { user: String, on: bool },
    /// Retired eye-closure calibration capture tombstone. Kept parseable for
    /// one release and returns a retired error. PRIVILEGED.
    CaptureEarMedian { user: String },
    /// Retired eye-closure calibration storage tombstone. Kept parseable for
    /// one release and returns a retired error. PRIVILEGED.
    SetClosureCalibration {
        user: String,
        ear_open: f32,
        ear_closed: f32,
    },
    /// Configure the IR emitter from what the camera's USB descriptor documents: find
    /// and persist the UVC control that lights the 850nm illuminator, using IR
    /// brightness to detect success. `dry_run` only enumerates XU controls.
    SetupIrEmitter { dry_run: bool },
    /// Measure whether this camera can stream RGB and IR at once without losing
    /// signal, and persist context-bound v2 qualification authority so
    /// authentication picks the right mode. Fires the camera. PRIVILEGED.
    TuneCaptureMode {
        #[serde(default)]
        rounds: Option<usize>,
        /// Where the daemon should write the ADR-0023 measurement-record
        /// evidence artifact (JSON array, one record per completed arm).
        /// Root-only command; the file is created with 0600. Evidence only:
        /// writing it changes no capture behavior.
        #[serde(default)]
        emit_record_path: Option<String>,
    },
    /// Resolve the daemon's active capture schedule from the exact camera pair
    /// it owns, including process-local safety degradation. CAMERA-CLASS.
    CaptureModeStatus,
    /// Camera-free sensor policy; a user explicitly requests enrollment preflight.
    FaceSensorStatus { user: Option<String> },
    /// The account's retained face-attempt record (ADR-0030 §5): the latest
    /// attempt of each kind and the last few per camera, non-biometric.
    /// Root or the account itself; answered from the daemon's state
    /// directory without touching the engine or a camera.
    LastAttempts { user: String },
    /// 1:N identify against one account's enrollment only (ADR-0030 §2):
    /// the account-scoped recognition test a client (the TUI's Faces page)
    /// runs for the one account it shows. Root or
    /// the account itself, checked before the request is queued, so no
    /// local user can run recognition against another account, learn its
    /// result or touch its record. Never a grant; answered with
    /// [`Response::Identified`] and filed as an `identify` attempt in that
    /// account's record (for root as well). A daemon that predates it
    /// answers `Error("bad request")`.
    IdentifyFor { user: String },
    /// Camera-free, non-secret machine preferences as observed by the daemon.
    PreferencesStatus,
    /// Liveness/alignment self-test (no auth side effects). See PAD self-testing.
    SelfTest { kind: SelfTestKind },
    /// Enumerate the Hello camera pairs for the picker. CAMERA-CLASS: it
    /// opens every video node to classify it, so it must be serialized
    /// against captures by the arbiter like any other camera work. Clients
    /// must NOT enumerate for themselves; a second opener racing the
    /// daemon's stream is EBUSY on strict UVC modules (#187).
    ListCameras,
    /// Machine-readable delivered-rate diagnostics for the configured camera
    /// pair (issue #462). CAMERA-CLASS: runs the normal gated capture session
    /// per present role and reports the measured evidence; a below-floor stream
    /// is returned as a measured `fail`, never degraded to English.
    CameraDiagnostics,
    /// Read the daemon's bounded, structurally share-safe diagnostic snapshot.
    SupportSnapshot { since_ms: u64 },
    /// Copy current daemon worker metadata and passive camera inventory.
    LiveStatus,
    /// Explicit root-only bounded camera probe for a support report.
    SupportProbe { since_ms: u64 },
    /// Root-only subscription to one bounded daemon-authored diagnostic trace.
    TraceSubscribe {
        duration_ms: u64,
        /// Omission selects legacy trace schema 1. Unsupported explicit
        /// versions are refused by the daemon before subscription.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trace_schema: Option<u32>,
    },
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
    /// A bounded RGB framing session, with the same account-hint rules as
    /// `PositionSample`. After `PositionSessionStarted`, each
    /// `PositionSessionControl::Sample` receives one fresh `Position` report.
    /// Finish receives `PositionSessionEnded` after camera release. Closing
    /// the connection cancels. No enrollment or auth.
    PositionSession { user: Option<String> },

    // --- keyring unlock (TPM-sealed password) -------------------------------
    /// Seal `user`'s login password in the TPM so a later face login can release
    /// it to unlock the GNOME-keyring / KWallet. The daemon refuses a password
    /// with a NUL byte, and one that fails its login-hash check where it can
    /// read the account's hash. Where it cannot (an LDAP or SSSD account, or
    /// the shipped AppArmor profile, which keeps the daemon out of
    /// `/etc/shadow`), it refuses an arm over an armed GNOME keyring token.
    /// Either way it refuses an arm over an envelope it cannot read, one that
    /// would replace an armed token with another kind, detected or requested,
    /// and a requested `GnomeKeyringToken` where oo7 keeps the account's
    /// keyrings (oo7 opens them with the login password). Each refusal
    /// applies to any peer, root included, and changes nothing. Over a token,
    /// `irlume keyring forget` and a fresh arm are the way back; an envelope
    /// it cannot read is left for an irlume that can read it. PRIVILEGED:
    /// root or `user`.
    SealPassword {
        user: String,
        password: SecretBytes,
        /// What to seal, or `None` to let the daemon decide from what the user
        /// actually has. `LoginPassword` seals `password` itself; `KdeWalletKey`
        /// derives the wallet key from it and seals that, leaving the password
        /// out of the envelope entirely.
        ///
        /// `None` is also what an older client sends, and resolving it by
        /// inspection is the right answer for one: a KDE-only machine gets the
        /// wallet key without the client having to know to ask.
        ///
        /// Current clients send `LoginPassword` when `oo7-daemon` provides the
        /// Secret Service in the caller's own session, which the daemon cannot
        /// see, and `None` otherwise. An older daemon seals a requested kind
        /// without checking for an armed token, so before sending
        /// `LoginPassword` such a client asks `KeyringInfo` and stops when a
        /// GNOME keyring token is armed; when it cannot tell, it sends `None`.
        #[serde(default)]
        kind: Option<KeyringSecretKind>,
        /// Account-scoped KDE wallet salt read by the authorized caller. The
        /// daemon never opens the user's wallet path. Absent for non-KDE
        /// operations and older clients; redacted by the [`WalletSalt`] debug implementation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wallet_salt: Option<WalletSalt>,
        /// True only when this caller ran the account-scoped helper. This
        /// distinguishes a proven-absent salt from an older client that omitted
        /// the field; the daemon fails the latter closed.
        #[serde(default, skip_serializing_if = "is_false")]
        wallet_salt_checked: bool,
    },
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
        /// Whether the PAM stack already holds a typed password. For a
        /// `LoginPassword` or `KdeWalletKey` envelope that makes the unseal
        /// pointless (the keyring/wallet opens from the typed password) and the daemon answers
        /// [`Response::KeyringUnlockNotNeeded`] without touching the TPM. For a
        /// `GnomeKeyringToken` envelope the typed password does NOT open the
        /// keyring, so the unseal proceeds regardless. The decision lives in
        /// the daemon because only it can read the envelope's kind. Defaults to
        /// `false`, which preserves the old always-unseal behaviour for a PAM
        /// module from before this field.
        #[serde(default)]
        have_password: bool,
    },
    /// Whether `user` has a sealed password armed (for status / CLI / the
    /// delete-erases-it warning). Unprivileged: root or `user`.
    HasSealedPassword { user: String },
    /// Describe the sealed envelope without reading live PCRs or opening the
    /// TPM. Returns `KeyringInfo` with `drifted: None`. Routine status clients
    /// should use this and fall back to `HasSealedPassword` on old daemons.
    /// Unprivileged: root or `user`.
    KeyringMetadata { user: String },
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
    /// Release `user`'s sealed GNOME keyring token to the caller so `keyring
    /// forget` can re-key the login keyring BACK to the password before the
    /// envelope is erased. Without that re-key, deleting a token envelope
    /// strands the keyring on a secret that no longer exists anywhere.
    /// `password` must open the token's password wrap, made under the login
    /// password the token was armed or last re-sealed with; the daemon checks
    /// it before releasing (the caller proves they could have obtained the
    /// keyring contents anyway). Refused for envelopes of any other kind.
    /// PRIVILEGED: root or `user`.
    ReleaseTokenForDisarm { user: String, password: SecretBytes },
    /// Re-seal `user`'s login password against the *current* PCR policy, but
    /// ONLY if a sealed password is already armed (never auto-arms a fresh user)
    /// and only if it actually changed (the PCRs moved, e.g. a dbx/Secure Boot
    /// update, or the user changed their password). Fired from the login
    /// **session** phase, which runs only after authentication SUCCEEDED. That
    /// does not prove `password` is the one that authenticated, so the daemon
    /// refuses a password with a NUL byte, and one that fails its login-hash
    /// check where it can read the account's hash, and leaves the envelope as
    /// it was. Where it cannot, the session's word is all it has, and the
    /// password re-seals (a token's password wrap moves to it). PRIVILEGED:
    /// root only, the PAM session line being its one sender (older daemons
    /// also accepted `user`).
    ResealPassword {
        user: String,
        password: SecretBytes,
        /// Account-scoped KDE wallet salt, when resealing a KDE envelope.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wallet_salt: Option<WalletSalt>,
        #[serde(default, skip_serializing_if = "is_false")]
        wallet_salt_checked: bool,
    },

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
    /// Inspect this account's face and password-reset retry state; root or self.
    RetryStatus { user: String },
    /// Reset retry state after independent password verification. Root is an
    /// explicit administrator override and may supply an empty password.
    RetryReset { user: String, password: SecretBytes },
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

/// Why a face attempt did not grant, as the daemon decided it (ADR-0030
/// §5): the closed vocabulary the TUI phrases and the attempt record
/// stores. Set where the result is decided — on the engine's outcome, at
/// its error boundary, or by the daemon before the engine — and never
/// inferred from reason prose. Absent on a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeCause {
    /// No usable face in frame.
    NoFace,
    /// The liveness gate refused (uncertain, pending evidence, or a spoof
    /// verdict): a presentation problem, not a recognition one.
    LivenessRefused,
    /// A live face matched no enrolled template above the threshold.
    BelowThreshold,
    /// The camera's hardware privacy shutter is engaged.
    PrivacyShutter,
    /// The camera could not be opened or used (absent, busy, refused by
    /// the hardware layer, or a broken stream).
    CameraUnavailable,
    /// The account is enrolled, but not on the configured camera.
    NotEnrolledOnThisCamera,
    /// The enrollment or its settings cannot serve this attempt: missing,
    /// empty, incompatible with the loaded recognizer, or unreadable.
    SetupUnavailable,
    /// The attempt was cancelled or pre-empted before a decision.
    Cancelled,
    /// The authentication window closed before a decision.
    TimedOut,
    /// Face authentication is not the configured method.
    MethodNotAvailable,
    /// A policy refused the attempt before any capture (service class,
    /// convenience tier, biopolicy, confirmation, authorization).
    Policy,
    /// The daemon's configuration could not be read or is invalid.
    Configuration,
    /// Too many recent attempts, or the retry state is unavailable.
    RetryThrottled,
    /// The daemon was still starting when the request arrived.
    DaemonStarting,
    /// Everything else: a refusal the vocabulary does not name.
    Other,
    /// A cause this build does not know (a newer daemon).
    #[serde(other)]
    Unknown,
}

impl OutcomeCause {
    /// Whether the cause is a verdict about a presented face (no face,
    /// liveness, no match) rather than a reason the attempt did not run
    /// or could not be decided.
    #[must_use]
    pub fn is_face_verdict(self) -> bool {
        matches!(
            self,
            OutcomeCause::NoFace | OutcomeCause::LivenessRefused | OutcomeCause::BelowThreshold
        )
    }

    /// Whether the attempt did not run or could not be decided: a known
    /// cause that is not a face verdict. `Unknown` (a newer daemon's
    /// value) is neither, so a client falls back to the reply's `live`
    /// rendering rather than calling a completed assessment "not run".
    #[must_use]
    pub fn is_operational(self) -> bool {
        !self.is_face_verdict() && self != OutcomeCause::Unknown
    }
}

/// What kind of face attempt a record entry describes (ADR-0030 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptKind {
    /// A verification for a service (login, unlock, elevation, an app).
    Authenticate,
    /// A 1:N recognition test; never a grant.
    Identify,
}

/// The surface an authentication served, from the operation class the
/// daemon resolved with the session state it established itself
/// (ADR-0030 §5); `Other` when it could not be resolved, never guessed
/// from the service name. Absent meaning for an `Identify` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptSurface {
    Login,
    Lock,
    Elevation,
    App,
    Other,
}

/// How an attempt ended: granted, refused by a decision, or failed before
/// one (a camera or daemon fault). The cause says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptResult {
    Granted,
    Refused,
    Failed,
}

/// The camera an attempt used, as a share-safe location (ADR-0030 §5):
/// the model, the USB port it was attached to and the descriptor digest
/// — never a serial or a node path. A unit that carries a serial adds a
/// keyed discriminator (a digest under a per-account secret the record
/// keeps) so a same-model replacement in the same port does not inherit
/// its history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCamera {
    /// `vid:pid`.
    pub model: String,
    /// `<bus>-<port>[.<port>…]` as sysfs names the device; `None` when
    /// the camera is not on a USB bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_chain: Option<String>,
    /// First 16 hex of the descriptor fingerprint, the same token the
    /// diagnostics carry; identical only for byte-identical descriptors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_token: Option<String>,
    /// Keyed per-account unit discriminator when the unit has a serial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// One retained attempt (ADR-0030 §5). No score, threshold, embedding or
/// reason prose: the outcome class, the cause and the two durations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptEntry {
    /// Unix seconds.
    pub at: u64,
    /// The account's completion order: assigned by the daemon's one record
    /// writer and kept in the account's record, so it stays ordered across
    /// daemon restarts and is shared by both kinds (a client compares the
    /// latest `authenticate` and `identify` entries by it, then by `at`).
    /// Zero from an older daemon.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub seq: u64,
    pub kind: AttemptKind,
    pub surface: AttemptSurface,
    pub result: AttemptResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<OutcomeCause>,
    pub elapsed_ms: u64,
    /// The capture stage's duration when the attempt reached a camera.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_ms: Option<u64>,
    /// Absent for an attempt refused before any camera was selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camera: Option<AttemptCamera>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// The attempts retained for one camera location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraAttempts {
    pub camera: AttemptCamera,
    /// Newest first, at most five.
    pub attempts: Vec<AttemptEntry>,
    /// Whether this camera is attached now (ADR-0030 §5), decided by the
    /// daemon when it serves the record: the same port chain and
    /// descriptor token, and for a serial-bearing unit the same keyed
    /// discriminator — so a same-model replacement in the same port
    /// reads `Some(false)` ("replaced unit"). `None` from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    /// The camera's display name (ADR-0029: the node's sysfs name, else the
    /// USB product string) as read at this bucket's most recent attempt that
    /// had one, so a client can name the camera without a listing that
    /// opens devices (ADR-0030 §2). Display only: never part of the bucket's
    /// identity. `None` from an older daemon and for a bucket last written
    /// before names were recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// An account's attempt record (ADR-0030 §5): the latest attempt of each
/// kind, so a recognition test never displaces the last authentication,
/// and the last five attempts per camera over at most eight cameras.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_authenticate: Option<AttemptEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_identify: Option<AttemptEntry>,
    /// Most recently used camera first.
    #[serde(default)]
    pub cameras: Vec<CameraAttempts>,
}

/// Why an operation failed, in terms a caller can act on.
///
/// Kept deliberately small. Each value has to mean the same thing for the life
/// of a contract version, because the public machine API maps these straight to
/// its published error codes, so a new value is cheap to add and a changed
/// meaning is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationErrorCode {
    /// The peer may not act on the target. Covers "that is not your account"
    /// and "this needs root": the daemon does not distinguish them to the
    /// caller, because an unprivileged peer is refused before the store is ever
    /// consulted, so the answer carries no information about which accounts
    /// exist or which are enrolled.
    NotAuthorized,
    /// The request was well-formed but the engine could not carry it out, for
    /// example the enrollment store could not be read.
    OperationFailed,
    /// The camera driver reports contention. Retry once the camera is free.
    CameraBusy,
    /// The authentication budget ended; this is neither biometric evidence nor
    /// a camera fault. Callers must fall back without retrying or recording a
    /// match attempt. Distinct from OperationFailed because the prose says
    /// nothing a client can branch on and the retry decision is the opposite.
    DeadlineExpired,
    /// A code this build does not know. Present so a client compiled against an
    /// older contract can still decode a response from a newer daemon rather
    /// than failing the whole message.
    #[serde(other)]
    Unknown,
}

/// One physical camera exposing an RGB and an IR node, as the daemon sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraPairInfo {
    pub rgb: String,
    pub ir: String,
    /// `idVendor:idProduct`, when readable.
    pub id: Option<String>,
    /// Built-in (`removable=fixed`) rather than an external USB camera.
    pub fixed: bool,
    /// A privacy shutter/switch is engaged on either node of this pair.
    /// Read by the daemon while it enumerates, because reading the control
    /// opens the device and only the daemon may do that (#187).
    #[serde(default)]
    pub privacy: bool,
    /// The camera's own name, for people (ADR-0029): the USB `product`
    /// string, else the RGB node's sysfs name. Display only; nothing
    /// matches on it (ADR-0007). Absent on older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The full binding identity of the pair (`vid:pid[:serial]`), the
    /// value enrollments and camera groups are bound to. Sent to a root
    /// peer only (the serial is device-identifying; ADR-0008 keeps the
    /// ordinary surface at present/absent); absent for other peers, on
    /// older daemons and for nodes without USB descriptors — a client then
    /// matches roles on `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// The descriptor carries a serial: without one, two units of the same
    /// model cannot be told apart (ADR-0024 §6).
    #[serde(default)]
    pub serial_present: bool,
    /// `<bus>-<port>[.<port>…]`, the USB location the pair is attached to
    /// (ADR-0030 §5), so an attempt record maps to a listed camera; absent
    /// off USB and on older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_chain: Option<String>,
    /// First 16 hex of the pair's descriptor fingerprint, the share-safe
    /// token the diagnostics and the attempt record carry (ADR-0030 §5):
    /// with `port_chain` it tells a record's camera from a same-model unit
    /// elsewhere. Absent off USB and on older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_token: Option<String>,
    /// The daemon's opaque handle for this pair (ADR-0030 §4): a keyed
    /// digest of the pair's binding identity under a secret this daemon
    /// instance drew at start, so it names the unit without revealing the
    /// serial and means nothing off the machine or to another daemon
    /// instance. The enrollment reply carries the same handle as
    /// `connected_handle` on the binding it matches, which is how a client
    /// labels roles without ever seeing the identity. Absent on older
    /// daemons and for nodes without USB descriptors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// The primary enrollment's camera binding, by identity (`vid:pid[:serial]`
/// per side), for the client's role labels (ADR-0029). Same shape as a
/// camera group's pair; an unbound side is `None`. The sides carry the
/// full identity for a root peer and `vid:pid` for others (ADR-0030 §4);
/// `connected_handle` is what an ordinary client correlates on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryCameraBinding {
    #[serde(default)]
    pub rgb: Option<String>,
    #[serde(default)]
    pub ir: Option<String>,
    /// The handle of the connected pair whose identity this binding names
    /// (ADR-0030 §4), correlated by the daemon from sysfs; `None` when no
    /// connected pair matches, or from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_handle: Option<String>,
}

/// A profile and the names of its scans, for `ListProfiles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub name: String,
    pub scans: Vec<String>,
    /// Per-recognizer scan counts, keyed by embedding space (#288). A profile
    /// can hold templates from several recognizers at once, and only those
    /// belonging to the loaded one can match, so "how many scans" has no
    /// single answer worth reporting on its own. Empty from a daemon that
    /// predates this field.
    #[serde(default)]
    pub scans_by_recognizer: std::collections::BTreeMap<String, usize>,
    /// The recognizer space the daemon has loaded, so a consumer can say
    /// which of the above are live right now. `None` from an older daemon.
    #[serde(default)]
    pub live_recognizer: Option<String>,
    /// Template compatibility for the daemon's loaded recognizer and IR
    /// pipeline. Absent from older daemons; absence is not zero usable scans.
    /// This is not a camera, liveness or authentication readiness verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ir: Option<ProfileIrSummary>,
    /// When each scan was captured (unix seconds), index for index with
    /// `scans`; `None` for a scan that predates capture dates (ADR-0030 §2).
    /// A parallel list rather than a map because nothing guarantees scan
    /// names are unique in a stored enrollment. Empty when no scan is dated,
    /// and from an older daemon; a client reads a list whose length is not
    /// `scans.len()` as "date not recorded" for every scan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scan_captured_at: Vec<Option<u64>>,
}

/// Aggregate IR scan compatibility for one profile and the loaded recognizer.
/// The four counts partition that recognizer's scans. No templates, scores,
/// camera identifiers or per-scan biometric measurements are exposed.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProfileIrSummary {
    pub compatible_scans: usize,
    pub missing_scans: usize,
    pub unknown_scans: usize,
    pub incompatible_scans: usize,
    /// A stored raw-IR calibration is withheld because this recognizer still
    /// has unknown IR scans in this profile. Adding tagged scans alone does
    /// not clear this restriction; tagged templates can still match raw.
    pub calibration_withheld: bool,
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

/// Camera-free prerequisites; never qualification or login permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrOnlyReadiness {
    /// The daemon cannot establish the prerequisites for an experimental attempt.
    Unavailable,
    ReadyForExperimentalAttempt,
    InvalidPolicy,
    TargetUnavailable,
    BindingUnavailable,
    BindingMismatch,
    ModelsUnavailable,
    PadUnavailable,
    EnrollmentUnavailable,
    IncompatibleEnrollment,
    /// ADR-0028: the configured pair is an enrolled secondary camera group,
    /// but the store is inactive because the primary enrollment changed
    /// since that group was authorized.
    SecondaryInactive,
    /// ADR-0028 Phase 1 daemons: the configured pair resolved to a
    /// secondary group while the route was still gated pending hardware
    /// validation. Current daemons never send it; kept so their status
    /// still decodes.
    SecondaryUnvalidated,
    /// A value this build does not know. Present so a newer daemon's status
    /// never makes an older client reject the whole response (ADR-0028).
    #[serde(other)]
    Unknown,
}

impl IrOnlyReadiness {
    /// The value to put in the long-standing `ir_readiness` wire field: a
    /// vocabulary every released client decodes. The ADR-0028 states travel
    /// there as [`Self::BindingMismatch`], which is what an older daemon would
    /// have reported for the same configuration; the precise state goes in
    /// `ir_readiness_detail`, which older clients ignore.
    #[must_use]
    pub fn wire_compatible(self) -> Self {
        match self {
            Self::SecondaryInactive | Self::SecondaryUnvalidated | Self::Unknown => {
                Self::BindingMismatch
            }
            other => other,
        }
    }
}

/// Which enrollment scope an IR-only readiness or attempt resolved to
/// (ADR-0028). A secondary scope is identified only by its ordinal in the
/// store; group ids derive from device identities and are never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrScope {
    Primary,
    Secondary,
    #[serde(other)]
    Unknown,
}

/// Camera-free explanation of a target refusal. This is diagnostic information,
/// never readiness or authority. Unknown future labels keep generic fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrTargetIssue {
    Unconfigured,
    Unavailable,
    UnsupportedTopology,
    BindingUnavailable,
    Changed,
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod sensor_target_wire_tests;

/// Runtime state of one shipped presentation-attack-detection model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PadModelStatus {
    Loaded,
    Disabled,
    Missing,
    LoadFailed,
}

/// Prospective cumulative face-request budget, independent of password recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaceRetryBudget {
    /// Absent until the first reservation or verified reset creates an epoch.
    pub unsuccessful_requests: Option<u32>,
    pub limit: u32,
    pub reset_required: bool,
}

#[cfg(test)]
mod retry_status_wire_tests {
    use super::*;

    #[derive(Deserialize)]
    enum LegacyResponse {
        RetryStatus {
            failures: u32,
            cooldown_seconds: u64,
            recovery_failures: u32,
            recovery_cooldown_seconds: u64,
            recovery_required: bool,
            password_reset_available: bool,
        },
    }

    #[test]
    fn retry_status_old_and_new_clients_keep_distinct_budget_meanings() {
        let old = serde_json::json!({"RetryStatus": {
            "failures": 2, "cooldown_seconds": 0, "recovery_failures": 3,
            "recovery_cooldown_seconds": 0, "recovery_required": false,
            "password_reset_available": true
        }});
        let decoded: Response = serde_json::from_value(old.clone()).unwrap();
        assert!(matches!(
            decoded,
            Response::RetryStatus {
                face_budget: None,
                ..
            }
        ));
        let mut new = old;
        new["RetryStatus"]["face_budget"] =
            serde_json::json!({"unsuccessful_requests": 50, "limit": 50, "reset_required": true});
        let LegacyResponse::RetryStatus {
            failures,
            cooldown_seconds,
            recovery_failures,
            recovery_cooldown_seconds,
            recovery_required,
            password_reset_available,
        } = serde_json::from_value(new.clone()).unwrap();
        assert_eq!(
            (
                failures,
                cooldown_seconds,
                recovery_failures,
                recovery_cooldown_seconds,
                recovery_required,
                password_reset_available
            ),
            (2, 0, 3, 0, false, true)
        );
        let decoded: Response = serde_json::from_value(new).unwrap();
        assert!(matches!(
            decoded,
            Response::RetryStatus {
                recovery_required: false,
                face_budget: Some(FaceRetryBudget {
                    unsuccessful_requests: Some(50),
                    reset_required: true,
                    ..
                }),
                ..
            }
        ));
    }
}

/// Non-secret preference observations, including daemon environment overrides.
/// These describe policy, not hardware readiness or a successful authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferencesState {
    pub face_sensor_policy: config::FaceSensorPolicyObservation,
    pub privileged_face_consent: Option<bool>,
    pub enforce_biopolicy: Option<bool>,
    pub consent_overridden: bool,
    pub biopolicy_overridden: bool,
    /// The effective external-camera prohibition as the daemon observes
    /// it (ADR-0029 A): the `forbid_external_cameras` setting or the
    /// legacy `IRLUME_CAMERA_REQUIRE_FIXED=1` gate. `Some(true)` means
    /// only built-in cameras may authenticate; `None` when unreadable or
    /// from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbid_external_cameras: Option<bool>,
}

impl PreferencesState {
    /// Observe preferences in this process's configuration and environment.
    #[must_use]
    pub fn observe() -> Self {
        Self {
            face_sensor_policy: config::observe_face_sensor_policy(),
            privileged_face_consent: config::privileged_face_consent_visible(),
            enforce_biopolicy: config::enforce_biopolicy_visible(),
            consent_overridden: std::env::var_os("IRLUME_PRIVILEGED_FACE_CONSENT").is_some(),
            biopolicy_overridden: std::env::var_os("IRLUME_ENFORCE_BIOPOLICY").is_some(),
            // The effective restriction: the setting, or the legacy
            // IRLUME_CAMERA_REQUIRE_FIXED=1 gate the camera crate still
            // honours before authentication.
            forbid_external_cameras: config::forbid_external_cameras_visible().map(|forbid| {
                forbid || std::env::var("IRLUME_CAMERA_REQUIRE_FIXED").is_ok_and(|v| v == "1")
            }),
        }
    }
}

/// One secondary camera group's listing row (ADR-0024 Phase 2): identity,
/// connection/selection/activation state, and per-profile counts with
/// calibration state. Frozen by the worker at summary-publish time; the
/// connection-thread cache path serves it memory-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraGroupSummary {
    /// The group id as this peer may name it: the store's immutable id for
    /// root and for clients that did not ask for handles; for a non-root
    /// client that did, an opaque group handle (the store id is derived
    /// from the camera identity, serial included). Either form is accepted
    /// by [`Request::RemoveCameraGroup`].
    pub id: String,
    /// The bound RGB identity (`vid:pid[:serial]`), if any.
    pub rgb: Option<String>,
    /// The bound IR identity, if any.
    pub ir: Option<String>,
    /// Every bound side's identity is present on this machine (answered
    /// from sysfs; no device is opened).
    pub connected: bool,
    /// The group's complete pair is the pair the engine would use.
    pub selected: bool,
    /// The store's activation binding is stale against the current
    /// primary bytes (ADR-0024 §1.1): the group's data is retained but
    /// cannot authenticate until explicitly re-authorized.
    pub stale: bool,
    pub generation: u64,
    pub profiles: Vec<CameraGroupProfileSummary>,
    /// The handle of the connected pair this group is bound to (ADR-0030
    /// §4), correlated by the daemon; `None` when not connected or from
    /// an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_handle: Option<String>,
}

/// One profile's row within one camera group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraGroupProfileSummary {
    pub profile: String,
    /// Total retained scans of this profile on this group.
    pub scans: usize,
    /// The add-camera capture target (DEFAULT_ENROLL_SCANS) is met.
    pub capture_target_met: bool,
    /// Enough compatible IR pairs exist to ATTEMPT calibration fitting.
    pub calibration_fittable: bool,
    pub compatible_rgb_candidates: usize,
    pub compatible_ir_pairs: usize,
    /// This group carries its own calibration for the live recognizer.
    pub calibrated: bool,
    /// The earliest and latest capture time (unix seconds) among this
    /// profile's scans on this group (ADR-0030 §2). A group's scans are
    /// captured together when the camera is added, so they are all dated or
    /// all not; `None` for scans that predate capture dates and from an
    /// older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_captured_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_captured_at: Option<u64>,
}

/// Daemon response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Reply only to the explicit preferences request; older clients are unchanged.
    PreferencesStatus(PreferencesState),
    /// The account's attempt record (`LastAttempts`).
    LastAttempts(AttemptRecord),
    /// Camera-free policy observation. Readiness is absent for ordinary status.
    FaceSensorStatus {
        policy: config::FaceSensorPolicyObservation,
        /// Always a value every released client decodes
        /// ([`IrOnlyReadiness::wire_compatible`]).
        ir_readiness: Option<IrOnlyReadiness>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ir_target_issue: Option<IrTargetIssue>,
        /// ADR-0028: the precise readiness when `ir_readiness` had to be
        /// widened for older clients; absent on older daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ir_readiness_detail: Option<IrOnlyReadiness>,
        /// ADR-0028: the resolved enrollment scope, when one resolved.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ir_scope: Option<IrScope>,
        /// ADR-0028: the secondary group's 1-based ordinal in the store.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ir_scope_index: Option<usize>,
    },
    /// Retry recovery capability and current per-account state.
    RetryStatus {
        failures: u32,
        cooldown_seconds: u64,
        recovery_failures: u32,
        recovery_cooldown_seconds: u64,
        recovery_required: bool,
        password_reset_available: bool,
        /// Older daemons omit this field; absence never means a zero count.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        face_budget: Option<FaceRetryBudget>,
    },
    /// Progress for an explicitly requested guided enrollment operation.
    EnrollmentSession(EnrollmentEvent),
    /// Authentication decision plus the evidence behind it.
    AuthResult {
        granted: bool,
        /// Best cosine similarity vs the user's enrolled templates.
        score: f32,
        /// Liveness verdict; auth is granted only if `live` AND score>=threshold.
        live: bool,
        reason: String,
        /// True when the refusal came from POLICY rather than from looking at a
        /// face: the configured method is fingerprint, the RGB-only convenience
        /// tier does not allow this service, the opt-in biopolicy gate refuses
        /// it, or the user is rate-limited. Every one of those answers
        /// `granted: false, live: false`, which a reader cannot tell apart from
        /// a spoof verdict, so `auth test` reported them all as "not-live" and a
        /// desktop told the user their face looked fake. `#[serde(default)]` so
        /// an older daemon decodes as false.
        #[serde(default)]
        refused_by_policy: bool,
        /// Reserved compatibility field for an older daemon's explicit cancellation.
        /// Current daemons always emit false; head gestures have been removed.
        /// Readers may honor a legacy true value only as a denial, never a grant.
        #[serde(default)]
        declined_by_gesture: bool,
        /// The final FAILED attempt's situation, in the #616 step 2 stable
        /// vocabulary ("timed out", "no face", "too far", ...), carried so
        /// pam_irlume can word its prompt (#616 step 3). Empty on a grant, on every
        /// pre-camera policy refusal, and from an older daemon
        /// (`#[serde(default)]`); attack-shaped labels are carried too, but
        /// the PAM layer stays silent on them: no threshold value ever
        /// reaches a prompt surface.
        #[serde(default)]
        situation: String,
        /// Why the attempt did not grant, from the closed vocabulary of
        /// [`OutcomeCause`] (ADR-0030 §5), set on every refusal — engine
        /// verdicts and pre-camera refusals alike, which `situation` leaves
        /// empty. Absent on a grant and from an older daemon.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<OutcomeCause>,
    },
    Profiles(Vec<String>),
    /// Answer to [`Request::ListCameras`]: every physical camera exposing an
    /// RGB+IR pair, built-in first.
    Cameras(Vec<CameraPairInfo>),
    /// Active RGB+IR scheduling policy resolved by the daemon.
    CaptureModeStatus {
        mode: String,
        source: String,
        rgb: String,
        ir: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_context: Option<String>,
        #[serde(default)]
        qualification_state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        qualification_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        qualification_context: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_degradation: Option<String>,
    },
    /// Structurally share-safe daemon facts and recent typed events.
    SupportSnapshot(Box<diagnostics::SupportSnapshot>),
    LiveStatus(Box<live::LiveStatusSnapshot>),
    /// Explicit support probe result with its contemporaneous safe snapshot.
    SupportProbe(Box<diagnostics::SupportProbeResult>),
    /// Trace subscription accepted with daemon-applied bounds. Subsequent
    /// newline-delimited records use [`diagnostics::TraceRecord`].
    TraceAccepted {
        limits: diagnostics::TraceLimits,
    },
    /// Result of a 1:N `Identify` or `IdentifyFor`. `user`/`profile` are
    /// `None` when no enrolled face matched (check `live` to tell "no match"
    /// from "not a live face").
    Identified {
        user: Option<String>,
        profile: Option<String>,
        score: f32,
        live: bool,
        reason: String,
        /// Why no match was found, when none was (ADR-0030 §5); absent on
        /// a match and from an older daemon.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<OutcomeCause>,
    },
    /// Structured enrollment listing. The retired eye fields remain required
    /// on the wire and are frozen at false for compatibility.
    Enrollment {
        profiles: Vec<ProfileSummary>,
        require_eyes_open: bool,
        /// Retired eye-closure signal, frozen at false for compatibility.
        #[serde(default)]
        closure_calibrated: bool,
        /// Whether this enrollment has a per-user floor fitted on the IR
        /// center/edge brightness ratio (>=2 scans carry a recorded ratio). False
        /// for enrollments made before the feature; surfaced so `doctor` can nudge
        /// a re-enroll to activate the personalized tightening. The alias keeps a
        /// new client readable by the 0.6.1 daemon, which sent `ir_depth_floored`.
        #[serde(default, alias = "ir_depth_floored")]
        ir_ratio_calibrated: bool,
        /// Secondary camera-group rows (ADR-0024 Phase 2): absent (an
        /// older daemon) and empty (no secondary store) both read as "no
        /// groups"; a store that exists but cannot be summarized is
        /// reported through `camera_store_error`, never as empty.
        #[serde(default)]
        camera_groups: Vec<CameraGroupSummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        camera_store_error: Option<String>,
        /// The primary enrollment's camera binding (ADR-0029): absent on
        /// older daemons and for an enrollment captured before binding.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        primary_camera: Option<PrimaryCameraBinding>,
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
        /// Scans in the profile across EVERY recognizer. Display only: the
        /// scan limit is counted per recognizer (#290), so this is not the
        /// number to compute a remaining budget from. Use `room`.
        total: usize,
        /// How many more scans this profile may take IN THE LOADED
        /// RECOGNIZER'S SPACE, which is what the limit actually governs.
        /// Carried rather than recomputed by the client: deriving it from
        /// `total` under-counts on a multi-model profile and refuses scans
        /// the daemon would accept.
        ///
        /// `None` means the daemon did not say, which is every daemon older
        /// than 0.9.0. That is NOT the same as `Some(0)`, a profile that is
        /// genuinely full, and the difference is load-bearing: a plain
        /// `usize` defaulted to 0, so a 0.9.0 client talking to a
        /// still-running 0.8.1 daemon (the window every upgrade passes
        /// through, between the package swap and the daemon restart) offered
        /// zero continuation scans and silently under-enrolled, which is the
        /// failure #290 exists to prevent. A caller seeing `None` uses its
        /// own requested count and lets the daemon refuse what it will.
        #[serde(default)]
        room: Option<usize>,
        added_scans: Vec<String>,
        /// Of the scans just added, how many had their IR burst at least
        /// half lit by the ROOM rather than provably by the emitter. Above
        /// zero, the enrollment measured a property of the lighting as well
        /// as the user, and dark-room login is unverified until tried
        /// (#312: "enroll at noon, locked out at night" on a camera whose
        /// emitter never fires). `None` means the daemon did not say (any
        /// daemon older than 0.9.1), which callers must not render as 0.
        #[serde(default)]
        ambient_lit: Option<usize>,
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
        /// FaceMesh dense-landmark model loaded for BlazeFace rescue alignment.
        mesh: bool,
        /// IR domain adapter loaded.
        adapter: bool,
        /// RGB PAD model state. `None` means the daemon predates this field.
        #[serde(default)]
        rgb_pad: Option<PadModelStatus>,
        /// IR PAD model state. `None` means the daemon predates this field.
        #[serde(default)]
        ir_pad: Option<PadModelStatus>,
        /// The daemon's crate version; lets the TUI flag a stale installed
        /// build (daemon predating the CLI it's talking to).
        #[serde(default)]
        version: String,
        /// The daemon's OWN AppArmor confinement, read from its /proc/self/attr
        /// at request time: e.g. `irlumed (enforce)`, `irlumed (complain)`, or
        /// `unconfined`. `None` when AppArmor is not enabled on this boot (or an
        /// older daemon that predates this field). Lets the TUI report the real
        /// confinement of the running daemon instead of inferring it from the
        /// on-disk profile file, which stays present even if `apparmor_parser`
        /// failed to load it and the daemon is actually unconfined.
        #[serde(default)]
        apparmor: Option<String>,
    },
    /// A framing-guide sample (`PositionSample`).
    Position(PositionReport),
    /// Framing connection accepted. Errors after acceptance must not cause
    /// a client to silently restart through the one-shot compatibility path.
    PositionSessionStarted,
    /// Framing finished and the camera worker released its operation slot.
    PositionSessionEnded,
    /// Delivered-rate diagnostic report (`CameraDiagnostics`).
    CameraDiagnostics(Box<CameraDiagnosticsReport>),
    /// Retired `CaptureEarMedian` response tombstone. No current request
    /// produces it; retained for one-release wire compatibility.
    EarMedian(Option<f32>),
    Error(String),
    /// A failure the caller can act on, sent ONLY to a request that opted in
    /// (see `ListProfiles::structured_errors` and `Authenticate::structured_errors`).
    ///
    /// `Error(String)` carries prose meant for a human, so the machine API had
    /// to flatten every failure into one opaque code: a request refused for
    /// authorization and a storage failure were indistinguishable, and a
    /// frontend could not tell "you may not do that" from "something broke".
    /// This variant carries the distinction the daemon already knows.
    OperationError {
        code: OperationErrorCode,
        /// Whether an identical request could plausibly succeed later without
        /// the caller changing anything.
        #[serde(default)]
        retryable: bool,
        /// The attempt's cause when the error ended a face attempt
        /// (ADR-0030 §5); absent for other operations and from an older
        /// daemon.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<OutcomeCause>,
    },

    // --- keyring unlock responses -------------------------------------------
    /// The password was sealed (`SealPassword`).
    PasswordSealed,
    /// A GNOME keyring token was sealed (`SealPassword` that resolved to
    /// [`KeyringSecretKind::GnomeKeyringToken`]). Carries the token because
    /// sealing is only half the arm: the caller, which runs in the user's
    /// session and can reach the keyring control socket, must now re-key the
    /// login keyring to it. Released only to the requesting peer, which
    /// `SealPassword` already restricts to root or the user themselves.
    TokenSealed {
        token: SecretBytes,
        /// Whether the token was freshly minted (first arm) or reused from an
        /// existing envelope (re-arm). Governs the caller's failure handling:
        /// a minted envelope may be rolled back with `ForgetPassword` once
        /// the caller has shown the keyring never took the token (a re-key
        /// whose answer was lost may have landed); a reused one may hold the
        /// LIVE keyring credential and must never be deleted on error.
        /// Defaults to `false`, the never-delete reading, so an older caller
        /// cannot inherit the destructive branch.
        #[serde(default)]
        minted: bool,
    },
    /// `UnsealKeyring` with `have_password: true` against a `LoginPassword` or
    /// `KdeWalletKey` envelope: the password already opens it, so nothing was
    /// unsealed and nothing needs releasing.
    KeyringUnlockNotNeeded,
    /// `UnsealPassword` was refused before face authentication because credential
    /// release is unavailable (peer privilege, device tier, or no armed secret).
    /// An identity-only caller may request `Authenticate`, which independently
    /// enforces authorization and policy. This is not a face grant, and must
    /// never represent a failed capture, denial, throttle or secret delivery.
    UnsealUnavailable {
        reason: String,
    },
    /// Face matched and the TPM released the secret (`UnsealPassword` /
    /// `UnsealKeyring`).
    PasswordUnsealed {
        secret: SecretBytes,
        /// What `secret` is. Absent from an older daemon's reply, which only
        /// ever sealed login passwords, so the default is correct for it.
        #[serde(default)]
        kind: KeyringSecretKind,
    },
    /// Whether a sealed password exists (`HasSealedPassword`).
    HasPassword(bool),
    /// Envelope detail (`KeyringInfo` or `KeyringMetadata`). `policy` is `None`
    /// and `pcrs` empty when nothing is armed (or the envelope is unreadable); `drifted` is
    /// `None` for metadata-only requests, when there is nothing to compare,
    /// or when the PCR replay failed.
    KeyringInfo {
        armed: bool,
        #[serde(default)]
        policy: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pcrs: Vec<u32>,
        #[serde(default)]
        drifted: Option<bool>,
        /// What kind of secret is armed. `None` from a daemon predating #250's
        /// GNOME half, or when nothing is armed. `keyring forget` routes on
        /// this: a token disarm must re-key the keyring back to the password
        /// first, a password disarm just deletes the envelope.
        #[serde(default)]
        kind: Option<KeyringSecretKind>,
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
        /// Whether the STORE is encrypted at rest, from its own on-disk shape.
        encrypted: bool,
        recovery_set: bool,
        tpm_present: bool,
        /// Whether the template key that opens an encrypted store still exists.
        /// False with `encrypted` true means the enrollment cannot be opened by
        /// anything, which no other field can express. Defaults to true so a
        /// pre-0.9.0 daemon, which never sends it, does not read as key-missing.
        #[serde(default = "default_true")]
        key_present: bool,
    },
}

/// One logical stream role's delivered-rate measurement, as a plain serializable
/// DTO with no camera-crate dependency. Carried by [`Error::DeliveredRate`] and
/// embedded in [`Response::CameraDiagnostics`] so a caller can act on an
/// under-rate stream without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraStreamRateEvidence {
    /// `"rgb"` or `"ir"`.
    pub role: String,
    /// Requested frame interval, numerator and denominator (reduced).
    pub requested_num: u32,
    pub requested_den: u32,
    /// Accepted (negotiated) frame interval, numerator and denominator (reduced).
    pub accepted_num: u32,
    pub accepted_den: u32,
    /// Exact floor numerator/denominator in frames per second.
    pub floor_num: u32,
    pub floor_den: u32,
    /// Whole-percent tolerance applied to the floor (98).
    pub tolerance_percent: u32,
    /// Number of deltas held in the rolling window.
    pub window_count: u32,
    /// Sum of the held deltas in microseconds.
    pub window_span_us: u64,
    /// Exact delivered rate numerator/denominator in frames per second (reduced).
    pub delivered_num: u64,
    pub delivered_den: u64,
    /// Whether the measured rate clears the exact floor.
    pub meets_floor: bool,
    /// Sequence gap of the latest delivered frame.
    pub sequence_gap: u32,
    /// Cumulative dropped frames reported by sequence continuity.
    pub cumulative_drops: u64,
    /// V4L2 timestamp clock (`"monotonic"`, `"copy"`, `"unknown"`).
    pub clock: String,
    /// V4L2 timestamp source (`"end_of_frame"`, `"start_of_exposure"`).
    pub source: String,
    /// Latest successful timestamp in microseconds.
    pub latest_timestamp_us: i64,
    /// Stream epoch the evidence belongs to.
    pub stream_epoch: u64,
}

/// One role's diagnostic result: whether it is known, its state, and the exact
/// rate evidence when a measurement exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraRoleDiagnostic {
    /// Whether this role is present on the machine at all.
    pub known: bool,
    /// `"measured"` (floor cleared), `"fail"` (under-rate), `"missing"` (no
    /// node), or `"unknown"` (open/transport failure).
    pub state: String,
    /// Exact evidence, present for `measured` and `fail`, absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub evidence: Option<CameraStreamRateEvidence>,
}

/// Whether the IR image node's MS-XU metadata sibling was discoverable during
/// a diagnostics run (#568).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CameraIlluminationNode {
    /// A same-interface sibling above the IR node accepted the UVCM probe.
    Present,
    /// No metadata sibling exists, or none accepted the format.
    Absent,
}

/// MS-XU illumination metadata stream state for one diagnostics run (#568).
///
/// The per-frame counts come from the same bounded gated capture that
/// produced the delivered-rate evidence. `None` means the capture could not
/// run, not that the camera reported nothing: a present node with zero
/// classified frames is the honest "the camera did not say" reading, exactly
/// as the illumination fallback treats a missing per-frame record.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CameraIlluminationState {
    /// Metadata node presence for the IR image node, by UVCM probe.
    pub node: CameraIlluminationNode,
    /// Burst frames the camera's illumination metadata classified (lit or
    /// dark).
    pub frames_classified: Option<usize>,
    /// The subset the camera flagged lit (the illuminator fired).
    pub frames_lit: Option<usize>,
    /// True only when the camera flagged both a lit and a dark frame, so
    /// `frames_lit < frames_classified` is a real emitter-off observation
    /// rather than absent records.
    pub ambient_observed: Option<bool>,
}

/// Complete machine diagnostic report for [`Response::CameraDiagnostics`].
///
/// Deliberately free of device paths, account identity, and template data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraDiagnosticsReport {
    pub rgb: CameraRoleDiagnostic,
    pub ir: CameraRoleDiagnostic,
    /// Same-domain RGB/IR skew in microseconds. `None` means unknown (the two
    /// latest timestamps do not share clock and source, or a role is missing).
    pub skew_us: Option<i64>,
    /// Capture strategy used by the diagnostic (`"burst"`, `"streaming"`, …).
    pub capture_strategy: String,
    /// MS-XU illumination metadata stream state for the IR node. `None` on an
    /// RGB-only pair (there is no IR node to probe). Reports written before
    /// #568 deserialize this as `None`.
    #[serde(default)]
    pub illumination: Option<CameraIlluminationState>,
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
    /// EBUSY from camera I/O, excluding an identified self-only holder bug.
    /// Display preserves the legacy hardware error while the type survives
    /// through the engine to clients that request structured errors.
    #[error("hardware: {0}")]
    CameraBusy(String),
    #[error("tpm: {0}")]
    Tpm(String),
    #[error("policy: {0}")]
    Policy(String),
    /// The camera delivered frames below the exact role floor. Carries the
    /// machine-readable measurement so callers act on the rate, not the prose;
    /// the message is a fixed, stable string and the evidence rides in the payload.
    #[error("delivered rate below floor")]
    DeliveredRate(Box<CameraStreamRateEvidence>),
    /// A long camera operation stopped early because an authentication needed
    /// the camera. Distinct from a failure: nothing went wrong and nothing was
    /// written, so the caller should say "retry", not "it broke".
    #[error("preempted: {0}")]
    Preempted(String),
    /// The authentication budget ended; this is neither biometric evidence nor
    /// a camera fault. Callers must fall back without retrying or recording a match.
    #[error("authentication window expired; use your password")]
    DeadlineExpired,
    /// The camera's hardware privacy shutter refused capture (ADR-0030 §5).
    /// Display keeps the legacy hardware prose so existing readers see what
    /// they did; the type is what the daemon classifies on.
    #[error("hardware: {0}")]
    PrivacyShutter(String),
    /// The camera itself could not be opened or used: absent, refused by
    /// the hardware layer, or a broken stream (ADR-0030 §5). Raised only
    /// by the camera layer; `Hardware` stays the generic variant that
    /// inference and other layers also use, so it never points a person
    /// at a camera that worked. Display keeps the legacy hardware prose.
    #[error("hardware: {0}")]
    CameraUnavailable(String),
    /// The account's enrollment exists but could not be read or decoded
    /// (ADR-0030 §5): no biometric comparison happened. Wraps the storage
    /// error's own text so the prose reply is unchanged.
    #[error("{0}")]
    Enrollment(String),
}

impl Error {
    /// The attempt cause this error decides (ADR-0030 §5), from the typed
    /// variant alone — never from the message. Errors that are not about
    /// the attempt's camera or budget are `Other`.
    #[must_use]
    pub fn cause(&self) -> OutcomeCause {
        match self {
            Error::PrivacyShutter(_) => OutcomeCause::PrivacyShutter,
            Error::CameraUnavailable(_) | Error::CameraBusy(_) | Error::DeliveredRate(_) => {
                OutcomeCause::CameraUnavailable
            }
            Error::Enrollment(_) => OutcomeCause::SetupUnavailable,
            Error::Preempted(_) => OutcomeCause::Cancelled,
            Error::DeadlineExpired => OutcomeCause::TimedOut,
            Error::Policy(_) | Error::NotAuthorized(_) => OutcomeCause::Policy,
            // Generic: a hardware-layer failure that is not the camera's
            // (inference, for one), or storage and transport faults.
            Error::Hardware(_) | Error::Io(_) | Error::Protocol(_) | Error::Tpm(_) => {
                OutcomeCause::Other
            }
        }
    }
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
    /// The observed prohibition is the effective one: the legacy
    /// `IRLUME_CAMERA_REQUIRE_FIXED=1` gate counts, so a client never
    /// presents an external pair as ready when the daemon would refuse it.
    #[test]
    fn observed_external_camera_prohibition_includes_the_legacy_fixed_gate() {
        let _g = super::testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-prefs-fixed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_FORBID_EXTERNAL_CAMERAS");
        std::env::remove_var("IRLUME_CAMERA_REQUIRE_FIXED");

        assert_eq!(
            super::PreferencesState::observe().forbid_external_cameras,
            Some(false)
        );
        // Only the exact legacy value engages the gate, as the camera crate
        // reads it.
        std::env::set_var("IRLUME_CAMERA_REQUIRE_FIXED", "yes");
        assert_eq!(
            super::PreferencesState::observe().forbid_external_cameras,
            Some(false)
        );
        std::env::set_var("IRLUME_CAMERA_REQUIRE_FIXED", "1");
        assert_eq!(
            super::PreferencesState::observe().forbid_external_cameras,
            Some(true)
        );
        // The setting turned off does not lift the legacy gate.
        std::env::set_var("IRLUME_FORBID_EXTERNAL_CAMERAS", "0");
        assert_eq!(
            super::PreferencesState::observe().forbid_external_cameras,
            Some(true)
        );

        std::env::remove_var("IRLUME_CAMERA_REQUIRE_FIXED");
        std::env::remove_var("IRLUME_FORBID_EXTERNAL_CAMERAS");
        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrollment_response_carries_camera_group_rows_optionally() {
        use super::{CameraGroupProfileSummary, CameraGroupSummary, ProfileSummary, Response};
        // An older daemon's reply (no group fields) still parses: empty
        // rows, no store error.
        let legacy = serde_json::json!({"Enrollment": {
            "profiles": [], "require_eyes_open": false,
            "closure_calibrated": false, "ir_ratio_calibrated": false
        }});
        let decoded: Response = serde_json::from_value(legacy).unwrap();
        match &decoded {
            Response::Enrollment {
                camera_groups,
                camera_store_error,
                ..
            } => {
                assert!(camera_groups.is_empty());
                assert!(camera_store_error.is_none());
            }
            other => panic!("expected Enrollment, got {other:?}"),
        }
        // A modern reply carries rows and, separately, a store-level error.
        let row = CameraGroupSummary {
            id: "cam-046d-desk".into(),
            rgb: Some("046d:desk".into()),
            ir: Some("046d:desk".into()),
            connected: true,
            selected: false,
            stale: false,
            generation: 3,
            connected_handle: None,
            profiles: vec![CameraGroupProfileSummary {
                profile: "Face Profile 1".into(),
                scans: 10,
                capture_target_met: true,
                calibration_fittable: true,
                compatible_rgb_candidates: 10,
                compatible_ir_pairs: 10,
                calibrated: true,
                first_captured_at: None,
                last_captured_at: None,
            }],
        };
        let response = Response::Enrollment {
            profiles: vec![ProfileSummary {
                name: "Face Profile 1".into(),
                scans: vec![],
                scans_by_recognizer: Default::default(),
                live_recognizer: None,
                ir: None,
                scan_captured_at: Vec::new(),
            }],
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
            camera_groups: vec![row],
            camera_store_error: None,
            primary_camera: None,
        };
        let encoded = serde_json::to_value(&response).unwrap();
        assert_eq!(
            encoded["Enrollment"]["camera_groups"][0]["id"],
            serde_json::json!("cam-046d-desk")
        );
        assert!(encoded["Enrollment"].get("camera_store_error").is_none());
        let round: Response = serde_json::from_value(encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&round).unwrap(),
            serde_json::to_value(&response).unwrap()
        );
    }

    #[test]
    fn camera_group_requests_round_trip_with_defaulted_fields() {
        use super::Request;
        // An older CLI omits `scans`: it decodes to the default and
        // re-encodes without the field, so both directions stay wire-stable.
        let legacy = serde_json::json!({"AddCameraGroup": {
            "user": "alice", "profile": null
        }});
        let decoded: Request = serde_json::from_value(legacy.clone()).unwrap();
        assert!(matches!(
            &decoded,
            Request::AddCameraGroup {
                user,
                profile: None,
                scans: None
            } if user == "alice"
        ));
        // `#[serde(default)]` deserializes the absent field and serializes
        // it back as an explicit null: the re-encoded form CARRIES
        // "scans": null, which the same reader accepts.
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::json!({"AddCameraGroup": {"user": "alice", "profile": null, "scans": null}})
        );
        let full: Request = serde_json::from_value(serde_json::json!({
            "AddCameraGroup": {"user": "alice", "profile": "Face Profile 1", "scans": 10}
        }))
        .unwrap();
        assert!(matches!(
            full,
            Request::AddCameraGroup {
                scans: Some(10),
                ..
            }
        ));
        let removal: Request = serde_json::from_value(serde_json::json!({
            "RemoveCameraGroup": {"user": "alice", "group": "cam-046d-desk"}
        }))
        .unwrap();
        assert!(matches!(
            &removal,
            Request::RemoveCameraGroup { user, group }
                if user == "alice" && group == "cam-046d-desk"
        ));
        assert_eq!(
            serde_json::to_value(&removal).unwrap(),
            serde_json::json!({"RemoveCameraGroup": {"user": "alice", "group": "cam-046d-desk"}})
        );
    }

    #[test]
    fn operation_error_code_wire_is_kebab_case_and_forward_compatible() {
        let d = serde_json::to_value(super::OperationErrorCode::DeadlineExpired).unwrap();
        assert_eq!(d, serde_json::json!("deadline-expired"));
        let future: super::OperationErrorCode =
            serde_json::from_str("\"some-future-code\"").unwrap();
        assert_eq!(future, super::OperationErrorCode::Unknown);
    }

    #[test]
    fn wallet_salt_wire_is_optional_fixed_length_and_redacted() {
        use super::{kwallet_wire::SALT_LEN, Request, WalletSalt};

        let legacy = serde_json::json!({"SealPassword": {
            "user": "alice", "password": [1, 2, 3], "kind": null
        }});
        let decoded: Request = serde_json::from_value(legacy.clone()).unwrap();
        assert!(matches!(
            decoded,
            Request::SealPassword {
                wallet_salt: None,
                wallet_salt_checked: false,
                ..
            }
        ));
        assert_eq!(serde_json::to_value(&decoded).unwrap(), legacy);

        let salt = WalletSalt::new(vec![0x5a; SALT_LEN]).unwrap();
        assert_eq!(format!("{salt:?}"), "WalletSalt([56 bytes redacted])");
        let request = Request::SealPassword {
            user: "alice".into(),
            password: super::SecretBytes::new(vec![1, 2, 3]),
            kind: Some(super::KeyringSecretKind::KdeWalletKey),
            wallet_salt: Some(salt),
            wallet_salt_checked: true,
        };
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(
            encoded["SealPassword"]["wallet_salt"]
                .as_array()
                .unwrap()
                .len(),
            SALT_LEN
        );
        assert!(serde_json::from_value::<Request>(encoded).is_ok());

        for len in [SALT_LEN - 1, SALT_LEN + 1] {
            let malformed = serde_json::json!({"ResealPassword": {
                "user": "alice", "password": [1], "wallet_salt": vec![0; len]
            }});
            assert!(serde_json::from_value::<Request>(malformed).is_err());
        }
    }

    #[test]
    fn auth_structured_errors_preserves_legacy_wire_and_unknown_codes() {
        use super::{OperationErrorCode, Request, Response};
        let old = serde_json::json!({"Authenticate":{"user":"alice","service":null}});
        let request: Request = serde_json::from_value(old.clone()).unwrap();
        assert!(matches!(
            &request,
            Request::Authenticate {
                structured_errors: false,
                ..
            }
        ));
        assert_eq!(serde_json::to_value(&request).unwrap(), old);
        let opted_in: Request = serde_json::from_value(serde_json::json!({"Authenticate":{
            "user":"alice","service":null,"structured_errors":true
        }}))
        .unwrap();
        assert!(matches!(
            opted_in,
            Request::Authenticate {
                structured_errors: true,
                ..
            }
        ));
        #[derive(serde::Deserialize)]
        enum LegacyRequest {
            Authenticate { user: String },
        }
        let LegacyRequest::Authenticate { user } =
            serde_json::from_value(serde_json::to_value(opted_in).unwrap()).unwrap();
        assert_eq!(user, "alice");
        let busy: Response = serde_json::from_value(
            serde_json::json!({"OperationError":{"code":"camera-busy","retryable":true}}),
        )
        .unwrap();
        assert!(matches!(
            busy,
            Response::OperationError {
                code: OperationErrorCode::CameraBusy,
                retryable: true,
                cause: None,
            }
        ));
        let future: Response = serde_json::from_value(
            serde_json::json!({"OperationError":{"code":"future-code","retryable":false}}),
        )
        .unwrap();
        assert!(matches!(
            future,
            Response::OperationError {
                code: OperationErrorCode::Unknown,
                ..
            }
        ));
    }

    #[test]
    fn profile_ir_metadata_is_optional_in_both_wire_directions() {
        let old = r#"{"name":"P","scans":["s"]}"#;
        let mut p: super::ProfileSummary = serde_json::from_str(old).unwrap();
        assert!(p.ir.is_none());
        assert!(serde_json::to_value(&p).unwrap().get("ir").is_none());
        p.ir = Some(super::ProfileIrSummary::default());
        #[derive(serde::Deserialize)]
        struct OldProfile {
            name: String,
            scans: Vec<String>,
        }
        let old: OldProfile = serde_json::from_value(serde_json::to_value(p).unwrap()).unwrap();
        assert_eq!(old.name, "P");
        assert_eq!(old.scans, ["s"]);
    }

    #[test]
    fn profile_ir_summary_survives_wire_round_trip() {
        let ir = serde_json::json!({"compatible_scans":2,"missing_scans":1,
            "unknown_scans":1,"incompatible_scans":1,"calibration_withheld":true});
        let p: super::ProfileSummary = serde_json::from_value(serde_json::json!({
            "name":"P","scans":["s"],"ir":ir
        }))
        .unwrap();
        assert_eq!(serde_json::to_value(p).unwrap()["ir"], ir);
    }

    /// ADR-0030 §2: capture times are additive on the enrollment reply. An
    /// older daemon's rows decode as undated and an undated row serialises
    /// exactly as before; a dated row still decodes for an older reader.
    #[test]
    fn scan_capture_times_are_optional_in_both_wire_directions() {
        let old = r#"{"name":"P","scans":["s","t"]}"#;
        let mut p: super::ProfileSummary = serde_json::from_str(old).unwrap();
        assert!(p.scan_captured_at.is_empty());
        assert!(serde_json::to_value(&p)
            .unwrap()
            .get("scan_captured_at")
            .is_none());
        p.scan_captured_at = vec![None, Some(1_790_000_000)];
        let wire = serde_json::to_value(&p).unwrap();
        assert_eq!(
            wire["scan_captured_at"],
            serde_json::json!([null, 1_790_000_000u64])
        );
        #[derive(serde::Deserialize)]
        struct OldProfile {
            scans: Vec<String>,
        }
        let old_reader: OldProfile = serde_json::from_value(wire).unwrap();
        assert_eq!(old_reader.scans, ["s", "t"]);

        let old_group = serde_json::json!({"profile":"P","scans":10,
            "capture_target_met":true,"calibration_fittable":true,
            "compatible_rgb_candidates":10,"compatible_ir_pairs":10,"calibrated":false});
        let mut group: super::CameraGroupProfileSummary =
            serde_json::from_value(old_group.clone()).unwrap();
        assert_eq!(group.first_captured_at, None);
        assert_eq!(group.last_captured_at, None);
        assert_eq!(serde_json::to_value(&group).unwrap(), old_group);
        group.first_captured_at = Some(1_790_000_000);
        group.last_captured_at = Some(1_790_000_060);
        let back: super::CameraGroupProfileSummary =
            serde_json::from_value(serde_json::to_value(&group).unwrap()).unwrap();
        assert_eq!(back, group);
    }

    /// ADR-0030 §2: the account-scoped recognition test is its own request
    /// variant, so a daemon that predates it cannot mistake it for the
    /// account-less `Identify`: it fails to parse (answered "bad request").
    #[test]
    fn identify_for_names_its_account_and_is_unknown_to_an_older_daemon() {
        let wire = serde_json::to_string(&super::Request::IdentifyFor {
            user: "alice".into(),
        })
        .unwrap();
        assert_eq!(wire, r#"{"IdentifyFor":{"user":"alice"}}"#);
        assert!(matches!(
            serde_json::from_str::<super::Request>(&wire).unwrap(),
            super::Request::IdentifyFor { user } if user == "alice"
        ));
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        enum OldRequest {
            Identify,
            LastAttempts { user: String },
        }
        assert!(serde_json::from_str::<OldRequest>(&wire).is_err());
        assert!(serde_json::from_str::<OldRequest>(r#""Identify""#).is_ok());
    }

    #[test]
    fn enrollment_session_is_an_explicit_bounded_request() {
        let wire =
            r#"{"EnrollmentSession":{"user":"alice","profile":null,"scans":10,"improve":false}}"#;
        let parsed = serde_json::from_str::<super::Request>(wire);
        assert!(
            parsed.is_ok(),
            "guided enrollment needs its own opt-in request: {parsed:?}"
        );
    }

    /// `AuthResult.situation` (#616 step 3) is `#[serde(default)]` so an
    /// OLDER daemon's reply, which predates the field, still decodes: the
    /// empty string means "no situation to prompt on" and pam stays silent.
    /// Round-trips when set, so the daemon's label reaches pam verbatim.
    #[test]
    fn auth_result_situation_defaults_empty_for_old_daemons() {
        let old = r#"{"AuthResult":{"granted":false,"score":0.25,"live":false,"reason":"no match","refused_by_policy":false,"declined_by_gesture":false}}"#;
        match serde_json::from_str::<Response>(old).expect("old reply decodes") {
            Response::AuthResult { situation, .. } => {
                assert_eq!(situation, "", "an old daemon decodes with no situation");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let new = r#"{"AuthResult":{"granted":false,"score":0.25,"live":false,"reason":"no match","refused_by_policy":false,"declined_by_gesture":false,"situation":"too far"}}"#;
        match serde_json::from_str::<Response>(new).expect("new reply decodes") {
            Response::AuthResult { situation, .. } => {
                assert_eq!(situation, "too far", "the label round-trips verbatim");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The delivered-rate DTO is a plain serializable carrier: snake_case JSON
    /// round-trips every field, and the typed error keeps a stable,
    /// machine-parseable message with the evidence recoverable from the payload
    /// rather than parsed from prose (#462).
    #[test]
    fn delivered_rate_error_carries_machine_readable_evidence() {
        use super::{CameraStreamRateEvidence, Error};

        let evidence = CameraStreamRateEvidence {
            role: "ir".to_string(),
            requested_num: 1,
            requested_den: 15,
            accepted_num: 1,
            accepted_den: 15,
            floor_num: 15,
            floor_den: 1,
            tolerance_percent: 98,
            window_count: 30,
            window_span_us: 2_000_000,
            delivered_num: 15,
            delivered_den: 1,
            meets_floor: true,
            sequence_gap: 0,
            cumulative_drops: 0,
            clock: "monotonic".to_string(),
            source: "end_of_frame".to_string(),
            latest_timestamp_us: 123_456_789,
            stream_epoch: 1,
        };

        // snake_case JSON round-trips every field exactly.
        let json = serde_json::to_string(&evidence).expect("serialize");
        assert!(
            json.contains("\"requested_num\":1"),
            "requested_num: {json}"
        );
        assert!(
            json.contains("\"window_span_us\":2000000"),
            "window_span_us: {json}"
        );
        assert!(
            json.contains("\"delivered_num\":15"),
            "delivered_num: {json}"
        );
        assert!(
            json.contains("\"tolerance_percent\":98"),
            "tolerance_percent: {json}"
        );
        assert!(
            json.contains("\"latest_timestamp_us\":123456789"),
            "latest: {json}"
        );
        assert!(json.contains("\"clock\":\"monotonic\""), "clock: {json}");
        let round: CameraStreamRateEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round, evidence);

        // The error message is a fixed, stable prefix; the evidence is carried
        // in the payload, not logged into the prose.
        let error = Error::DeliveredRate(Box::new(evidence.clone()));
        assert_eq!(error.to_string(), "delivered rate below floor");
        match error {
            Error::DeliveredRate(inner) => assert_eq!(*inner, evidence),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The illumination section added by #568 must serialize under its
    /// documented snake_case names, and a report written before #568 must
    /// keep parsing with the section reading as absent rather than failing.
    #[test]
    fn camera_diagnostics_report_carries_and_survives_without_the_illumination_section() {
        use super::{
            CameraDiagnosticsReport, CameraIlluminationNode, CameraIlluminationState,
            CameraRoleDiagnostic,
        };

        let role = CameraRoleDiagnostic {
            known: true,
            state: "measured".to_string(),
            evidence: None,
        };
        let report = CameraDiagnosticsReport {
            rgb: role.clone(),
            ir: role,
            skew_us: None,
            capture_strategy: "burst".to_string(),
            illumination: Some(CameraIlluminationState {
                node: CameraIlluminationNode::Present,
                frames_classified: Some(12),
                frames_lit: Some(5),
                ambient_observed: Some(true),
            }),
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["illumination"]["node"], "present");
        assert_eq!(json["illumination"]["frames_classified"], 12);
        assert_eq!(json["illumination"]["frames_lit"], 5);
        assert_eq!(json["illumination"]["ambient_observed"], true);

        let legacy = serde_json::json!({
            "rgb": {"known": true, "state": "measured"},
            "ir": {"known": false, "state": "missing"},
            "skew_us": null,
            "capture_strategy": "burst",
        });
        let decoded: CameraDiagnosticsReport =
            serde_json::from_value(legacy).expect("a pre-#568 report keeps parsing");
        assert_eq!(decoded.illumination, None);
    }

    /// The digest a `HashedModel` reports must be the digest of the bytes it
    /// carries, because callers skip their own hashing on the strength of it
    /// (#346). Fails if the constructor ever stores a digest from anywhere
    /// but its own buffer.
    #[test]
    fn the_digest_always_belongs_to_the_bytes_it_was_built_from() {
        for payload in [b"weights".to_vec(), Vec::new(), vec![0u8; 4096]] {
            let m = super::HashedModel::new(payload.clone());
            assert_eq!(m.bytes(), &payload[..]);
            assert_eq!(m.sha256(), super::sha256_hex(&payload));
        }
    }

    #[test]
    fn consuming_hashed_model_preserves_the_original_allocation() {
        let model = super::HashedModel::new(b"owned model weights".to_vec());
        let original = model.bytes().as_ptr();
        let digest = model.sha256().to_owned();
        let bytes = model.into_bytes();
        assert_eq!(
            bytes.as_ptr(),
            original,
            "transfer must not clone the weights"
        );
        assert_eq!(super::sha256_hex(&bytes), digest);
    }
    use std::path::{Path, PathBuf};

    /// The upgrade window: a 0.9.1 client reading an Enrolled reply from a
    /// still-running older daemon. The wire JSON has no `ambient_lit`, and
    /// that must read as `None` ("the daemon did not say"), never as
    /// `Some(0)` ("the daemon measured zero ambient-lit scans") — the same
    /// distinction `room` carries for #290, applied to #312.
    #[test]
    fn enrolled_without_ambient_lit_reads_as_daemon_did_not_say() {
        let full = super::Response::Enrolled {
            profile: "p".into(),
            created: true,
            added: 3,
            total: 3,
            room: Some(22),
            added_scans: vec!["scan1".into()],
            ambient_lit: Some(2),
        };
        let mut v = serde_json::to_value(&full).expect("serialize");
        let obj = v
            .get_mut("Enrolled")
            .and_then(|e| e.as_object_mut())
            .expect("externally tagged Enrolled object");
        obj.remove("ambient_lit").expect("field serializes");
        let old: super::Response = serde_json::from_value(v).expect("older-daemon shape parses");
        let super::Response::Enrolled { ambient_lit, .. } = old else {
            panic!("round-trip changed the variant");
        };
        assert_eq!(ambient_lit, None, "absent must be None, not Some(0)");
    }

    #[test]
    fn auth_result_without_declined_by_gesture_reads_false() {
        // An OLDER daemon never sets declined_by_gesture. The new pam_irlume must
        // decode the absent field as FALSE, never abort a polkit dialog on an
        // ordinary timeout or no-match: #[serde(default)] must stay a false default.
        // Set the source true so a truthy default (or a failed strip) cannot pass by
        // accident. Mirrors enrolled_without_ambient_lit_reads_as_daemon_did_not_say.
        let full = super::Response::AuthResult {
            granted: false,
            score: 0.0,
            live: true,
            reason: "no match".into(),
            declined_by_gesture: true,
            refused_by_policy: false,
            situation: "too far".into(),
            cause: None,
        };
        let mut v = serde_json::to_value(&full).expect("serialize");
        let obj = v
            .get_mut("AuthResult")
            .and_then(|e| e.as_object_mut())
            .expect("externally tagged AuthResult object");
        obj.remove("declined_by_gesture").expect("field serializes");
        let old: super::Response = serde_json::from_value(v).expect("older-daemon shape parses");
        let super::Response::AuthResult {
            declined_by_gesture,
            ..
        } = old
        else {
            panic!("round-trip changed the variant");
        };
        assert!(!declined_by_gesture, "absent must decode false (no abort)");
    }

    #[test]
    fn retired_eye_requests_still_parse_as_tombstones() {
        for wire in [
            r#"{"SetRequireEyesOpen":{"user":"u","on":false}}"#,
            r#"{"CaptureEarMedian":{"user":"u"}}"#,
            r#"{"SetClosureCalibration":{"user":"u","ear_open":0.2,"ear_closed":0.1}}"#,
        ] {
            serde_json::from_str::<Request>(wire).expect("old request remains parseable");
        }
    }

    #[test]
    fn enrollment_response_is_compatible_in_both_reader_directions() {
        #[derive(serde::Deserialize)]
        enum OldResponse {
            Enrollment {
                profiles: Vec<ProfileSummary>,
                require_eyes_open: bool,
                #[serde(default)]
                closure_calibrated: bool,
                #[serde(default)]
                ir_ratio_calibrated: bool,
            },
        }

        let new = Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
            camera_groups: Vec::new(),
            camera_store_error: None,
            primary_camera: None,
        };
        let old: OldResponse = serde_json::from_value(
            serde_json::to_value(new).expect("serialize current enrollment response"),
        )
        .expect("old reader requires require_eyes_open");
        let OldResponse::Enrollment {
            profiles,
            require_eyes_open,
            closure_calibrated,
            ir_ratio_calibrated,
        } = old;
        assert!(profiles.is_empty());
        assert!(!require_eyes_open);
        assert!(!closure_calibrated);
        assert!(!ir_ratio_calibrated);

        let old = r#"{"Enrollment":{"profiles":[],"require_eyes_open":true}}"#;
        let current: Response =
            serde_json::from_str(old).expect("current reader accepts old reply");
        let Response::Enrollment {
            profiles,
            require_eyes_open,
            closure_calibrated,
            ir_ratio_calibrated,
            camera_groups,
            camera_store_error,
            primary_camera,
        } = current
        else {
            panic!("old enrollment reply must remain Enrollment");
        };
        assert!(camera_groups.is_empty());
        assert!(primary_camera.is_none());
        assert!(camera_store_error.is_none());
        assert!(profiles.is_empty());
        assert!(require_eyes_open);
        assert!(!closure_calibrated);
        assert!(!ir_ratio_calibrated);
    }

    /// Every directory whose entry has to survive is in the chain, shallowest
    /// first, including the one a RELATIVE state root is anchored in.
    ///
    /// A directory's name lives in its parent, so syncing `state` does nothing
    /// for the `state` entry itself; for a relative path that entry is in the
    /// working directory. An earlier version dropped the empty last ancestor
    /// instead of reading it as ".", which left exactly that gap. Asserted on
    /// the list because an `fsync` leaves no trace in the filesystem to check.
    #[test]
    fn the_sync_chain_covers_every_directory_whose_entry_must_survive() {
        let abs = super::ancestor_chain(Path::new("/var/lib/irlume/login-transactions"));
        assert_eq!(
            abs,
            vec![
                PathBuf::from("/"),
                PathBuf::from("/var"),
                PathBuf::from("/var/lib"),
                PathBuf::from("/var/lib/irlume"),
            ],
            "shallowest first, and the store itself is left to the atomic write"
        );

        // The case the filter used to lose: nothing anchored `state`.
        let rel = super::ancestor_chain(Path::new("state/login-transactions"));
        assert_eq!(rel, vec![PathBuf::from("."), PathBuf::from("state")]);

        // A store directly under a relative root still names the anchor.
        assert_eq!(
            super::ancestor_chain(Path::new("login-transactions")),
            vec![PathBuf::from(".")]
        );
        // Nothing in a chain may be empty: an empty path opens nothing, so a
        // sync of it is a sync that silently did not happen.
        for dir in ["/a/b", "a/b", "b", "/"] {
            assert!(
                super::ancestor_chain(Path::new(dir))
                    .iter()
                    .all(|p| !p.as_os_str().is_empty()),
                "{dir} produced an empty entry"
            );
        }
    }

    /// A write reports whether it became VISIBLE, separately from whether it
    /// became durable.
    ///
    /// Three defects on #183 came from callers reading "returned an error" as
    /// "nothing is on disk". The rename publishes; the fsyncs come after. The
    /// ordinary path must still report `Durable`, or the distinction is a
    /// distinction nobody can act on.
    #[test]
    fn an_atomic_write_reports_that_it_became_durable() {
        // Per-process, because the ASan lane and the ordinary lane run this same
        // binary at once and a shared fixed name makes them delete each other's
        // scratch directory mid-test.
        let dir =
            std::env::temp_dir().join(format!("irlume-atomic-reporting-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("f");
        match super::write_atomic_reporting(&path, b"hello", 0o600).expect("write") {
            super::AtomicWrite::Durable => {}
            super::AtomicWrite::VisibleNotDurable(e) => {
                panic!("an ordinary write must be durable, got {e}")
            }
        }
        assert_eq!(std::fs::read(&path).expect("read"), b"hello");
        // And a write that cannot be published at all is an error, not a
        // half-success: nothing is visible under the target name.
        let missing = dir.join("no-such-dir").join("f");
        assert!(super::write_atomic_reporting(&missing, b"x", 0o600).is_err());
        assert!(!missing.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A removal that is not durable brings the record back after a power loss,
    /// and a record that comes back is acted on again. Absence is the whole
    /// meaning of a resolved journal, so it gets the same treatment as a write.
    #[test]
    fn removing_a_record_that_is_already_gone_is_success() {
        let dir =
            std::env::temp_dir().join(format!("irlume-remove-durable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("record");
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(super::remove_durable(&path), Ok(()));
        assert!(!path.exists());
        // Idempotent: a caller resuming after a crash must not fail here.
        assert_eq!(super::remove_durable(&path), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- cross-version wire compatibility for typed operation errors --------
    //
    // The package ships client and daemon together, but the old daemon keeps
    // running until it restarts, so both directions happen during an upgrade.
    // These pin the behaviour that makes that safe.

    #[test]
    fn an_old_client_request_defaults_to_prose_errors() {
        // Exactly what a pre-typed-error client puts on the wire: no
        // `structured_errors` key at all. The daemon must read it as false and
        // therefore keep answering with `Error(String)`, which is the only
        // variant that client can decode.
        let wire = r#"{"ListProfiles":{"user":"alice"}}"#;
        let req: Request = serde_json::from_str(wire).expect("old request must still parse");
        match req {
            Request::ListProfiles {
                user,
                structured_errors,
                handles,
            } => {
                assert_eq!(user, "alice");
                assert!(!structured_errors, "absent field must default to opted-out");
                assert!(!handles, "absent field: the client matches on identities");
            }
            other => panic!("expected ListProfiles, got {other:?}"),
        }
    }

    #[test]
    fn an_old_daemon_ignores_the_new_request_field() {
        // The other direction: a new client sends the field to a daemon that
        // predates it. Serde ignores unknown fields, so the old daemon still
        // sees a valid request. Simulated with a struct carrying only the old
        // shape, because the old type no longer exists in this build.
        #[derive(serde::Deserialize)]
        struct OldListProfiles {
            user: String,
        }
        #[derive(serde::Deserialize)]
        enum OldRequest {
            ListProfiles(OldListProfiles),
        }
        let new_wire = serde_json::to_string(&Request::ListProfiles {
            user: "alice".into(),
            structured_errors: true,
            handles: true,
        })
        .unwrap();
        let parsed: OldRequest =
            serde_json::from_str(&new_wire).expect("old daemon must still parse a new request");
        let OldRequest::ListProfiles(p) = parsed;
        assert_eq!(p.user, "alice");
    }

    #[test]
    fn an_unknown_error_code_decodes_instead_of_failing_the_message() {
        // A newer daemon may name a code this build has never heard of. The
        // whole response must still decode, degrading to Unknown, rather than
        // failing to parse and losing the outcome entirely.
        let wire = r#"{"OperationError":{"code":"some-future-code","retryable":true}}"#;
        let resp: Response = serde_json::from_str(wire).expect("must decode");
        match resp {
            Response::OperationError {
                code,
                retryable,
                cause,
            } => {
                assert_eq!(code, OperationErrorCode::Unknown);
                assert!(retryable);
                assert_eq!(cause, None, "absent from an older daemon");
            }
            other => panic!("expected OperationError, got {other:?}"),
        }
    }

    /// ADR-0030 §5: the cause vocabulary is stable on the wire, an
    /// unknown value degrades to `Unknown`, a reply without it (older
    /// daemon) decodes with `None`, and `Error::cause()` classifies on
    /// the typed variant alone.
    #[test]
    fn outcome_cause_is_stable_on_the_wire_and_typed_at_the_error_boundary() {
        assert_eq!(
            serde_json::to_string(&OutcomeCause::NotEnrolledOnThisCamera).unwrap(),
            "\"not-enrolled-on-this-camera\""
        );
        let future: OutcomeCause = serde_json::from_str("\"some-future-cause\"").unwrap();
        assert_eq!(future, OutcomeCause::Unknown);
        let legacy = r#"{"AuthResult":{"granted":false,"score":0.0,"live":false,"reason":"no"}}"#;
        match serde_json::from_str::<Response>(legacy).unwrap() {
            Response::AuthResult { cause, .. } => assert_eq!(cause, None),
            other => panic!("{other:?}"),
        }
        let modern = serde_json::to_value(Response::AuthResult {
            granted: false,
            score: 0.0,
            live: false,
            reason: "no".into(),
            refused_by_policy: true,
            declined_by_gesture: false,
            situation: String::new(),
            cause: Some(OutcomeCause::RetryThrottled),
        })
        .unwrap();
        assert_eq!(modern["AuthResult"]["cause"], "retry-throttled");
        let granted = serde_json::to_value(Response::AuthResult {
            granted: true,
            score: 0.9,
            live: true,
            reason: "match".into(),
            refused_by_policy: false,
            declined_by_gesture: false,
            situation: String::new(),
            cause: None,
        })
        .unwrap();
        assert!(
            granted["AuthResult"].get("cause").is_none(),
            "absent on a grant"
        );

        assert_eq!(
            Error::PrivacyShutter("s".into()).cause(),
            OutcomeCause::PrivacyShutter
        );
        assert_eq!(
            Error::CameraUnavailable("no camera found".into()).cause(),
            OutcomeCause::CameraUnavailable
        );
        // Generic hardware is not the camera's: inference raises it too.
        assert_eq!(Error::Hardware("onnx".into()).cause(), OutcomeCause::Other);
        assert_eq!(
            Error::Enrollment("io: bad store".into()).cause(),
            OutcomeCause::SetupUnavailable
        );
        assert_eq!(
            Error::Enrollment("io: bad store".into()).to_string(),
            "io: bad store"
        );
        assert_eq!(
            Error::CameraBusy("b".into()).cause(),
            OutcomeCause::CameraUnavailable
        );
        assert!(OutcomeCause::NoFace.is_face_verdict());
        assert!(!OutcomeCause::RetryThrottled.is_face_verdict());
        assert!(OutcomeCause::RetryThrottled.is_operational());
        assert!(!OutcomeCause::Unknown.is_operational());
        assert!(!OutcomeCause::NoFace.is_operational());
        assert_eq!(
            Error::Preempted("c".into()).cause(),
            OutcomeCause::Cancelled
        );
        assert_eq!(Error::DeadlineExpired.cause(), OutcomeCause::TimedOut);
        assert_eq!(Error::Policy("p".into()).cause(), OutcomeCause::Policy);
        assert_eq!(Error::Io("i".into()).cause(), OutcomeCause::Other);
        // Display keeps the hardware prose an older reader expects.
        assert_eq!(
            Error::PrivacyShutter("cam: shut".into()).to_string(),
            "hardware: cam: shut"
        );
    }

    #[test]
    fn operation_error_round_trips_and_retryable_defaults_false() {
        for code in [
            OperationErrorCode::NotAuthorized,
            OperationErrorCode::OperationFailed,
        ] {
            let wire = serde_json::to_string(&Response::OperationError {
                code,
                retryable: false,
                cause: None,
            })
            .unwrap();
            match serde_json::from_str::<Response>(&wire).unwrap() {
                Response::OperationError { code: back, .. } => assert_eq!(back, code),
                other => panic!("expected OperationError, got {other:?}"),
            }
        }
        // An older peer that omits `retryable` must not fail to decode.
        let resp: Response =
            serde_json::from_str(r#"{"OperationError":{"code":"not-authorized"}}"#).unwrap();
        match resp {
            Response::OperationError { retryable, .. } => assert!(!retryable),
            other => panic!("expected OperationError, got {other:?}"),
        }
    }

    #[test]
    fn error_codes_serialize_as_the_published_kebab_case_names() {
        // These strings are the public contract's codes; a rename here is a
        // breaking change for every consumer.
        let json = serde_json::to_string(&OperationErrorCode::NotAuthorized).unwrap();
        assert_eq!(json, r#""not-authorized""#);
        let json = serde_json::to_string(&OperationErrorCode::OperationFailed).unwrap();
        assert_eq!(json, r#""operation-failed""#);
    }
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_0600_atomic_replaces_content_at_0600_without_stray_temp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("irlume-atomic-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("seal.json");
        // Fresh write, then an overwrite: the new content fully replaces the old.
        write_0600_atomic(&target, b"OLD-SEAL").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"OLD-SEAL");
        write_0600_atomic(&target, b"NEW-SEAL-longer").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW-SEAL-longer");
        // 0600, and no leftover `.seal.json.tmp.*` beside it.
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "must be 0600");
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(strays.is_empty(), "atomic write left a temp file behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    fn drop_and_verify_ipc_lock_capability() {
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        const CAP_IPC_LOCK_BIT: u32 = 1 << 14;
        let mut header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: header/data use Linux's v3 capability ABI and point to
        // initialized writable storage for the calling process (pid 0).
        let rc = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
        assert_eq!(rc, 0, "capget failed: {}", std::io::Error::last_os_error());
        data[0].effective &= !CAP_IPC_LOCK_BIT;
        data[0].permitted &= !CAP_IPC_LOCK_BIT;
        data[0].inheritable &= !CAP_IPC_LOCK_BIT;
        // SAFETY: the same valid v3 buffers now request only removal of one
        // capability from this process; dropping one's own capability is allowed.
        let rc = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
        assert_eq!(rc, 0, "capset failed: {}", std::io::Error::last_os_error());
        // SAFETY: refresh the initialized data through the same v3 ABI.
        let rc = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
        assert_eq!(rc, 0, "capget failed: {}", std::io::Error::last_os_error());
        assert_eq!(data[0].effective & CAP_IPC_LOCK_BIT, 0);
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

    // Regression: deriving Clone copied the inner Vec directly, bypassing
    // SecretBytes::new() and leaving the copied plaintext swappable/dumpable.
    #[test]
    fn cloned_secret_bytes_are_memlocked_like_new() {
        if let Ok(case) = std::env::var("IRLUME_TEST_SECRET_CLONE_MEMLOCK") {
            drop_and_verify_ipc_lock_capability();
            let (limit, source_must_lock, clone_must_lock) = match case.as_str() {
                "zero" => (0, false, false),
                "constrained" => (384 * 1024, true, false),
                "adequate" => (2 * 1024 * 1024, true, true),
                other => panic!("unknown clone memlock test case: {other}"),
            };
            let rlimit = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            // SAFETY: `rlimit` is fully initialized and this fresh child only
            // lowers its own RLIMIT_MEMLOCK before allocating either secret.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) }, 0);

            // Large, distinct allocations make page ownership and aggregate
            // accounting unambiguous at the three selected limits.
            if case == "adequate" {
                let first = SecretBytes::new(vec![0x61; 256 * 1024]);
                let second = SecretBytes::new(vec![0x62; 256 * 1024]);
                let first_locked =
                    locked_kb_of(first.expose().as_ptr() as usize + 128 * 1024).unwrap_or(0) > 0;
                let second_locked =
                    locked_kb_of(second.expose().as_ptr() as usize + 128 * 1024).unwrap_or(0) > 0;
                if !first_locked || !second_locked {
                    eprintln!("unsupported: two live adequate-budget controls did not lock");
                    println!("clone-memlock-case-{case}-unsupported");
                    return;
                }
                drop((first, second));
            }
            let source = SecretBytes::new(vec![0x31; 256 * 1024]);
            let clone = source.clone();
            assert_eq!(clone.expose(), source.expose());
            assert_ne!(clone.expose().as_ptr(), source.expose().as_ptr());
            let source_locked =
                locked_kb_of(source.expose().as_ptr() as usize + 128 * 1024).unwrap_or(0) > 0;
            let clone_locked =
                locked_kb_of(clone.expose().as_ptr() as usize + 128 * 1024).unwrap_or(0) > 0;
            if case == "zero" && (source_locked || clone_locked) {
                eprintln!("unsupported: zero-budget locks appear effective after capability drop");
                println!("clone-memlock-case-{case}-unsupported");
                return;
            }
            if case == "constrained" && !source_locked {
                eprintln!("unsupported: constrained-budget source control did not lock");
                println!("clone-memlock-case-{case}-unsupported");
                return;
            }
            assert_eq!(source_locked, source_must_lock, "case {case}: source");
            assert_eq!(clone_locked, clone_must_lock, "case {case}: clone");
            println!("clone-memlock-case-{case}-passed");
            return;
        }

        let mut inherited = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `inherited` is initialized storage for getrlimit's output.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut inherited) };
        assert_eq!(rc, 0);
        if inherited.rlim_max < 2 * 1024 * 1024 {
            eprintln!(
                "skipping clone memlock cases: inherited hard limit {} cannot establish the \
                 required 2 MiB adequate-budget control",
                inherited.rlim_max
            );
            return;
        }

        let exe = std::env::current_exe().unwrap();
        for case in ["zero", "constrained", "adequate"] {
            let out = std::process::Command::new(&exe)
                .args([
                    "tests::cloned_secret_bytes_are_memlocked_like_new",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("IRLUME_TEST_SECRET_CLONE_MEMLOCK", case)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "clone memlock case {case} failed; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                [
                    format!("clone-memlock-case-{case}-passed"),
                    format!("clone-memlock-case-{case}-unsupported"),
                ]
                .iter()
                .any(|marker| String::from_utf8_lossy(&out.stdout).contains(marker)),
                "clone memlock case {case} did not run"
            );
        }
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
            Request::Authenticate { user, service, .. } => {
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
    fn health_pad_status_is_typed_and_defaults_unknown_for_old_daemons() {
        let old: Response = serde_json::from_str(
            r#"{"Health":{"tier":"secure","rgb_dev":null,"ir_dev":null,"mesh":true,"adapter":false}}"#,
        )
        .unwrap();
        match old {
            Response::Health {
                rgb_pad, ir_pad, ..
            } => {
                assert_eq!(rgb_pad, None);
                assert_eq!(ir_pad, None);
            }
            other => panic!("expected Health, got {other:?}"),
        }

        let current: Response = serde_json::from_str(
            r#"{"Health":{"tier":"secure","rgb_dev":null,"ir_dev":null,"mesh":true,"adapter":false,"rgb_pad":"loaded","ir_pad":"load-failed"}}"#,
        )
        .unwrap();
        match current {
            Response::Health {
                rgb_pad, ir_pad, ..
            } => {
                assert_eq!(rgb_pad, Some(PadModelStatus::Loaded));
                assert_eq!(ir_pad, Some(PadModelStatus::LoadFailed));
            }
            other => panic!("expected Health, got {other:?}"),
        }
    }

    /// `Authenticate` crosses a live-upgrade boundary in both directions: an
    /// old PAM omits the attestation, while a new PAM can meet an old daemon
    /// whose reader knows only `user` and `service`.
    #[test]
    fn authenticate_intent_attestation_is_compatible_in_both_directions() {
        let old: Request =
            serde_json::from_str(r#"{"Authenticate":{"user":"alice","service":"sudo"}}"#).unwrap();
        assert!(matches!(
            old,
            Request::Authenticate {
                structured_errors: false,
                user,
                service: Some(service),
                intent_confirmation: None,
            } if user == "alice" && service == "sudo"
        ));

        let without_attestation = Request::Authenticate {
            structured_errors: false,
            user: "alice".into(),
            service: Some("kde".into()),
            intent_confirmation: None,
        };
        let value = serde_json::to_value(without_attestation).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"Authenticate":{"user":"alice","service":"kde"}}),
            "None must be omitted so the ordinary wire shape stays unchanged"
        );

        let new = Request::Authenticate {
            structured_errors: false,
            user: "alice".into(),
            service: Some("sudo".into()),
            intent_confirmation: Some(IntentAttestation::PamConversation),
        };
        let wire = serde_json::to_string(&new).unwrap();
        let round_trip: Request = serde_json::from_str(&wire).unwrap();
        assert!(matches!(
            round_trip,
            Request::Authenticate {
                structured_errors: false,
                user,
                service: Some(service),
                intent_confirmation: Some(IntentAttestation::PamConversation),
            } if user == "alice" && service == "sudo"
        ));

        #[derive(serde::Deserialize)]
        struct OldAuthenticate {
            user: String,
            #[serde(default)]
            service: Option<String>,
        }
        #[derive(serde::Deserialize)]
        enum OldRequest {
            Authenticate(OldAuthenticate),
        }

        let parsed: OldRequest = serde_json::from_str(&wire).unwrap();
        let OldRequest::Authenticate(old) = parsed;
        assert_eq!(old.user, "alice");
        assert_eq!(old.service.as_deref(), Some("sudo"));
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
                room: Some(27),
                added_scans: vec![],
                ambient_lit: Some(0),
            },
            Response::Enrolled {
                profile: "Face Profile 1".into(),
                created: false,
                added: 1,
                total: 8,
                room: Some(22),
                added_scans: vec!["scan8".into()],
                ambient_lit: Some(2),
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
                        room: r1,
                        added_scans: s1,
                        ambient_lit: l1,
                    },
                    Response::Enrolled {
                        profile: p2,
                        created: c2,
                        added: a2,
                        total: t2,
                        room: r2,
                        added_scans: s2,
                        ambient_lit: l2,
                    },
                ) => {
                    assert_eq!((p1, c1, a1, t1, r1, s1, l1), (p2, c2, a2, t2, r2, s2, l2));
                }
                _ => panic!("Enrolled did not round-trip to Enrolled"),
            }
        }
    }
}

/// What a released keyring secret actually is, on the wire.
///
/// Mirrors `irlume_core::envelope::SecretKind`. It is declared here rather than
/// shared because irlume-common is the dependency of irlume-core, not the other
/// way round, and the PAM module needs it without the TPM stack.
///
/// The consumer differs by kind: a login password goes into `PAM_AUTHTOK`, a
/// wallet key goes to `ksecretd` through `irlume-kwallet-init`. Sending it on
/// the wire means the PAM module never has to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum KeyringSecretKind {
    /// The user's Unix login password.
    #[default]
    LoginPassword,
    /// The 56-byte key `ksecretd` opens the KDE wallet with.
    KdeWalletKey,
    /// A random token the GNOME login keyring has been re-keyed to (#250). Not
    /// a password: it must never reach `PAM_AUTHTOK`, where `pam_unix` on a
    /// Debian-style stack would consume it as the Unix password and fail the
    /// login. It goes to `gnome-keyring-daemon`'s control socket instead, via
    /// the session helper.
    GnomeKeyringToken,
}

/// Wire constants for the KDE wallet handoff.
///
/// These are shared with software we do not ship (`pam_kwallet5`, `ksecretd`).
/// They live here rather than in `irlume-core` so the tiny handoff helper can
/// use them without pulling in the TPM and inference stacks, and so there is a
/// single definition for both sides to agree on.
pub mod kwallet_wire {
    /// Length of the derived key. `KWALLET_PAM_KEYSIZE` in kwallet-pam's
    /// `pam_kwallet.c`; `PBKDF2_SHA512_KEYSIZE` in kwallet's
    /// `src/runtime/ksecretd/main.cpp`, whose `waitForHash()` reads exactly
    /// this many bytes and no more.
    pub const KEY_LEN: usize = 56;

    /// Length of the salt file. `KWALLET_PAM_SALTSIZE`.
    pub const SALT_LEN: usize = 56;

    /// PBKDF2 iteration count. `KWALLET_PAM_ITERATIONS`.
    pub const ITERATIONS: u32 = 50_000;

    /// Helper exit status meaning the salt path is absent. Every other
    /// nonzero status is a read or policy failure.
    pub const SALT_ABSENT_EXIT: i32 = 3;

    /// Helper exit status meaning `/run/user/<uid>` does not exist yet: the
    /// auth phase of a first login after a cold boot, before logind has
    /// opened the session. The caller may retry once the session is open.
    /// Every other nonzero status is a failure.
    pub const SESSION_NOT_READY_EXIT: i32 = 4;

    /// Basename of the handoff socket inside `XDG_RUNTIME_DIR`.
    ///
    /// Deliberately the same name `pam_kwallet5` uses (`socketPrefix` in
    /// `pam_kwallet.c`), because Plasma's `plasma-kwallet-pam.service` runs
    /// `env | socat STDIN UNIX-CONNECT:$PAM_KWALLET5_LOGIN` and that is how
    /// `ksecretd` gets the session environment it blocks waiting for. Using the
    /// same name and exporting the same variable means Plasma delivers the
    /// environment to our daemon with no change on its side.
    pub const SOCKET_NAME: &str = "kwallet5.socket";

    /// The environment variable Plasma's autostart reads.
    pub const LOGIN_ENV: &str = "PAM_KWALLET5_LOGIN";
}

/// Installed path of the KDE wallet handoff helper.
///
/// Under `libexec` rather than `bin`: it is not a command a user runs, it takes
/// a secret on stdin, and it is only meaningful inside a PAM transaction.
/// `IRLUME_KWALLET_INIT` overrides it for tests and for distributions that
/// place libexec elsewhere.
pub const KWALLET_INIT_PATH: &str = "/usr/libexec/irlume/irlume-kwallet-init";

/// Installed path of the GNOME keyring unlock helper (#250). Same reasoning as
/// [`KWALLET_INIT_PATH`]: takes a secret on stdin, only meaningful inside a PAM
/// transaction, overridable via `IRLUME_GKR_UNLOCK` for tests.
pub const GKR_UNLOCK_PATH: &str = "/usr/libexec/irlume/irlume-gkr-unlock";

#[cfg(test)]
mod live_status_request_tests {
    #[test]
    fn live_status_request_is_a_payload_free_read() {
        let request = serde_json::from_str::<super::Request>(r#""LiveStatus""#);
        assert!(
            request.is_ok(),
            "LiveStatus must be an additive payload-free request"
        );
        assert_eq!(
            serde_json::to_value(request.unwrap()).unwrap(),
            "LiveStatus"
        );
    }

    #[test]
    fn tune_request_carries_the_evidence_path_optionally() {
        // Newer CLI, older field absent: defaults to None (no emission).
        let absent: super::Request =
            serde_json::from_str(r#"{"TuneCaptureMode":{"rounds":6}}"#).expect("absent path");
        match absent {
            super::Request::TuneCaptureMode {
                rounds,
                emit_record_path,
            } => {
                assert_eq!(rounds, Some(6));
                assert_eq!(emit_record_path, None);
            }
            other => panic!("unexpected request: {other:?}"),
        }
        let present: super::Request = serde_json::from_str(
            r#"{"TuneCaptureMode":{"rounds":6,"emit_record_path":"/tmp/evidence.json"}}"#,
        )
        .expect("present path");
        match present {
            super::Request::TuneCaptureMode {
                rounds,
                emit_record_path,
            } => {
                assert_eq!(rounds, Some(6));
                assert_eq!(emit_record_path.as_deref(), Some("/tmp/evidence.json"));
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }
}
