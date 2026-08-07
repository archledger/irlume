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
pub mod gkr_wire;
pub mod memlock;
pub mod platform;
pub mod secureboot;
pub mod thirdparty;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unix domain socket the daemon listens on. Root-owned, mode 0666: every local
/// uid may connect, and `SO_PEERCRED` authorizes each request.
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

/// Make every directory above `dir` durable, so the names leading to it survive
/// a power loss.
///
/// Shallowest first, because a directory's entry lives in its parent: syncing
/// `/var/lib/irlume` makes `login-transactions` findable, and does nothing for
/// `irlume` itself, whose entry is in `/var/lib`. A record fsynced into a
/// directory whose name did not survive is not a record.
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
pub fn fsync_dir(dir: &std::path::Path) -> std::result::Result<(), String> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync {}: {e}", dir.display()))
}

/// Set `path`'s permission bits, naming the path when it fails.
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
pub fn write_atomic_mode(path: &std::path::Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    match write_atomic_reporting(path, bytes, mode)? {
        AtomicWrite::Durable => Ok(()),
        AtomicWrite::VisibleNotDurable(e) => Err(e),
    }
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
    /// 1:N identify ("who is this?"): one live capture, no claimed identity.
    /// Unprivileged (no credential release), but NOT unscoped: a root peer is
    /// matched against every enrolled user, and a non-root peer only against its
    /// own account. The CLI help has always said so; this wire doc did not, and
    /// it is the contract the machine surface keys off.
    Identify,
    /// Switch the active RGB+IR camera pair, persisting it (cameras.conf) so it
    /// survives a daemon restart. ROOT ONLY: it writes a system-wide setting
    /// under /etc/irlume, which is not an arbitrary peer's to change. (This said
    /// "root or self", which never matched the dispatch gate.)
    SetCameras { rgb: String, ir: String },
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
    /// Configure the IR emitter from what the camera's USB descriptor documents: find
    /// and persist the UVC control that lights the 850nm illuminator, using IR
    /// brightness to detect success. `dry_run` only enumerates XU controls.
    SetupIrEmitter { dry_run: bool },
    /// Measure whether this camera can stream RGB and IR at once without losing
    /// signal, and persist the answer (cameras.conf) so authentication picks the
    /// right capture mode. Fires the camera for several seconds. PRIVILEGED.
    TuneCaptureMode {
        #[serde(default)]
        rounds: Option<usize>,
    },
    /// Liveness/alignment self-test (no auth side effects). See PAD self-testing.
    SelfTest { kind: SelfTestKind },
    /// Enumerate the Hello camera pairs for the picker. CAMERA-CLASS: it
    /// opens every video node to classify it, so it must be serialized
    /// against captures by the arbiter like any other camera work. Clients
    /// must NOT enumerate for themselves; a second opener racing the
    /// daemon's stream is EBUSY on strict UVC modules (#187).
    ListCameras,
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
        #[serde(default)]
        kind: Option<KeyringSecretKind>,
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
        /// `LoginPassword` envelope that makes the unseal pointless (the keyring
        /// self-unlocks from the typed password) and the daemon answers
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
    /// `password` must be the user's current login password; the daemon
    /// verifies it before releasing (the caller proves they could have obtained
    /// the keyring contents anyway). Refused for envelopes of any other kind.
    /// PRIVILEGED: root or `user`.
    ReleaseTokenForDisarm { user: String, password: SecretBytes },
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
    /// Answer to [`Request::ListCameras`]: every physical camera exposing an
    /// RGB+IR pair, built-in first.
    Cameras(Vec<CameraPairInfo>),
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
        /// Whether this enrollment has a per-user floor fitted on the IR
        /// center/edge brightness ratio (>=2 scans carry a recorded ratio). False
        /// for enrollments made before the feature; surfaced so `doctor` can nudge
        /// a re-enroll to activate the personalized tightening. The alias keeps a
        /// new client readable by the 0.6.1 daemon, which sent `ir_depth_floored`.
        #[serde(default, alias = "ir_depth_floored")]
        ir_ratio_calibrated: bool,
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
        /// Name of the loaded third-party RECOGNIZER, if any (#276 stage 4).
        /// Same authority argument as the PAD field: this is what the daemon
        /// actually loaded, which a non-root TUI cannot learn from the
        /// root-only settings file. `None` = shipped recognizer (or an older
        /// daemon predating the field).
        #[serde(default)]
        third_party_recognizer: Option<String>,
        /// Name of the loaded third-party DETECTOR occupying the rescue slot,
        /// if any (#295). Same authority argument as the fields above: a
        /// non-root TUI cannot read the root-only settings file, and without
        /// this it cannot tell which detector the daemon is running.
        /// `None` = the shipped short-range rescue (or an older daemon).
        #[serde(default)]
        third_party_detector: Option<String>,
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
    /// Median eye-aspect-ratio over a capture (`CaptureEarMedian`); `None` if no
    /// eye was detected in any frame.
    EarMedian(Option<f32>),
    Error(String),
    /// A failure the caller can act on, sent ONLY to a request that opted in
    /// (see `ListProfiles::structured_errors`).
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
        /// a minted envelope is inert and safe to roll back with
        /// `ForgetPassword`; a reused one may hold the LIVE keyring credential
        /// and must never be deleted on error. Defaults to `false`, the
        /// never-delete reading, so an older caller cannot inherit the
        /// destructive branch.
        #[serde(default)]
        minted: bool,
    },
    /// `UnsealKeyring` with `have_password: true` against a `LoginPassword`
    /// envelope: the typed password already opens the keyring, so nothing was
    /// unsealed and nothing needs releasing.
    KeyringUnlockNotNeeded,
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
    /// A long camera operation stopped early because an authentication needed
    /// the camera. Distinct from a failure: nothing went wrong and nothing was
    /// written, so the caller should say "retry", not "it broke".
    #[error("preempted: {0}")]
    Preempted(String),
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
            } => {
                assert_eq!(user, "alice");
                assert!(!structured_errors, "absent field must default to opted-out");
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
            Response::OperationError { code, retryable } => {
                assert_eq!(code, OperationErrorCode::Unknown);
                assert!(retryable);
            }
            other => panic!("expected OperationError, got {other:?}"),
        }
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
