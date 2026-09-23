// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The per-account face-attempt record (ADR-0030 §5): the latest attempt
//! of each kind and the last five attempts per camera, non-biometric,
//! bounded as a whole, kept root-only under the daemon's state directory
//! like the retry journal.
//!
//! What is stored: the time, the surface, the kind, the outcome class,
//! the cause, the two durations, and the camera as a share-safe location
//! (model, USB port chain, descriptor token, and a keyed discriminator for
//! a unit that carries a serial). What is never stored: a score, a
//! threshold, an embedding, reason prose, a serial or a node path.
//!
//! Bounds (all enforced on every write): five attempts per camera bucket,
//! eight camera buckets per account with the least recently used evicted,
//! and a bucket whose newest attempt is older than ninety days pruned.

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};

use irlume_common::{
    AttemptCamera, AttemptEntry, AttemptKind, AttemptRecord, AttemptResult, AttemptSurface,
    CameraAttempts, OutcomeCause,
};

/// Attempts kept per camera bucket.
pub(crate) const PER_CAMERA: usize = 5;
/// Camera buckets kept per account.
pub(crate) const MAX_CAMERAS: usize = 8;
/// A bucket whose newest attempt is older than this is pruned on write.
pub(crate) const BUCKET_TTL_SECS: u64 = 90 * 24 * 60 * 60;

/// The on-disk shape: the wire record plus the per-account secret that
/// keys the unit discriminator (random, drawn on first write; it lives in
/// the root-only file and nowhere else, so the discriminator means
/// nothing off the machine and reveals nothing about the serial).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Stored {
    /// The account name the record belongs to. The file is keyed by uid,
    /// and a uid can be reused after an account is deleted: a record whose
    /// name is not the requesting account's is that other account's
    /// history and is neither served nor appended to.
    #[serde(default)]
    account: String,
    #[serde(default)]
    unit_key_hex: String,
    /// The next completion sequence for this account: assigned by the one
    /// writer in the order attempts completed (its queue is FIFO), kept in
    /// the file so it stays ordered across daemon restarts, and private to
    /// the account so it says nothing about other accounts' activity.
    #[serde(default = "first_seq")]
    next_seq: u64,
    #[serde(flatten)]
    record: AttemptRecord,
}

fn first_seq() -> u64 {
    1
}

/// What a recording site knows about the attempt it is filing.
#[derive(Debug, Clone)]
pub(crate) struct Filed {
    /// When the attempt completed (unix seconds), taken by the caller
    /// before the write is queued; the writer assigns the order within a
    /// second from the account's own sequence.
    pub at: u64,
    pub kind: AttemptKind,
    pub surface: AttemptSurface,
    pub result: AttemptResult,
    pub cause: Option<OutcomeCause>,
    pub elapsed_ms: u64,
    pub capture_ms: Option<u64>,
    /// The camera the attempt used, as sysfs describes it; `None` when
    /// the attempt was refused before a camera was selected.
    pub camera: Option<irlume_auth::CameraLocation>,
}

/// The outcome class of a wire reply: a grant, a decision against, or a
/// failure before any decision.
pub(crate) fn result_of(granted: bool, decided: bool) -> AttemptResult {
    if granted {
        AttemptResult::Granted
    } else if decided {
        AttemptResult::Refused
    } else {
        AttemptResult::Failed
    }
}

/// The surface an operation class serves (ADR-0030 §5).
pub(crate) fn surface_for(class: irlume_core::biopolicy::OperationClass) -> AttemptSurface {
    use irlume_core::biopolicy::OperationClass as C;
    match class {
        C::Login => AttemptSurface::Login,
        C::ScreenUnlock => AttemptSurface::Lock,
        C::Elevation => AttemptSurface::Elevation,
        C::AppConsent => AttemptSurface::App,
        C::Remote | C::Unknown => AttemptSurface::Other,
    }
}

/// The session state of the requesting login (ADR-0030 §5), bound to the
/// PAM conversation's own process rather than to the account: warm only
/// when the peer runs inside a `user`-class logind session that belongs
/// to the target account — an unlock or an elevation from a live session.
/// A greeter's or TTY's conversation runs in no such session and is cold,
/// whatever other sessions the account has; anything unresolvable is
/// cold, the stricter class.
/// `None` when the state cannot be resolved (the peer's cgroup or the
/// session's facts are unreadable): the record files such an attempt as
/// `Other`; a policy caller that needs a fail-safe default treats `None`
/// as cold. A peer outside any logind session resolves to cold.
pub(crate) fn session_state_for(
    peer_pid: i32,
    target_uid: u32,
) -> Option<irlume_core::biopolicy::SessionState> {
    session_state_from(
        Path::new("/proc"),
        Path::new("/run/systemd/sessions"),
        peer_pid,
        target_uid,
    )
}

fn session_state_from(
    proc_root: &Path,
    sessions_root: &Path,
    peer_pid: i32,
    target_uid: u32,
) -> Option<irlume_core::biopolicy::SessionState> {
    use irlume_core::biopolicy::SessionState;
    let cgroup =
        std::fs::read_to_string(proc_root.join(peer_pid.to_string()).join("cgroup")).ok()?;
    let Some(session) = cgroup
        .split(|c: char| c == '/' || c.is_whitespace())
        .filter_map(|part| part.strip_prefix("session-")?.strip_suffix(".scope"))
        .find(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
    else {
        // Resolved: this conversation runs in no session at all.
        return Some(SessionState::Cold);
    };
    let facts = std::fs::read_to_string(sessions_root.join(session)).ok()?;
    let mut uid = None;
    let mut class = None;
    for line in facts.lines() {
        if let Some(value) = line.strip_prefix("UID=") {
            uid = value.trim().parse::<u32>().ok();
        } else if let Some(value) = line.strip_prefix("CLASS=") {
            class = Some(value.trim().to_owned());
        }
    }
    Some(
        if uid == Some(target_uid) && class.as_deref() == Some("user") {
            SessionState::Warm
        } else {
            SessionState::Cold
        },
    )
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Keyed discriminator for a unit that carries a serial: the first eight
/// bytes of SHA-256 over the per-account key and the serial. Same unit,
/// same account, same value; a different serial or another account's key
/// gives another value, and the serial is not recoverable.
fn unit_discriminator(key: &[u8], serial: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(key);
    h.update(b"irlume-attempt-unit\0");
    h.update(serial.as_bytes());
    h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn camera_of(location: &irlume_auth::CameraLocation, key: &[u8]) -> AttemptCamera {
    AttemptCamera {
        model: location.model.clone(),
        port_chain: location.port_chain.clone(),
        descriptor_token: Some(location.descriptor_token.clone()),
        unit: location
            .serial
            .as_deref()
            .filter(|serial| !serial.trim().is_empty())
            .map(|serial| unit_discriminator(key, serial)),
    }
}

/// Apply one attempt to a record under the ADR-0030 §5 bounds. Pure, so
/// the bounds are testable without a store.
pub(crate) fn apply(record: &mut AttemptRecord, entry: AttemptEntry, now: u64) {
    // A bucket nobody has used for the TTL is gone before the new attempt
    // is filed, so the eviction below counts live cameras only.
    record.cameras.retain(|bucket| {
        bucket
            .attempts
            .first()
            .is_some_and(|newest| now.saturating_sub(newest.at) <= BUCKET_TTL_SECS)
    });
    // Writers run in whatever order their threads get the lock: an entry
    // is placed by its own completion time and never displaces a newer one.
    let latest = match entry.kind {
        AttemptKind::Authenticate => &mut record.latest_authenticate,
        AttemptKind::Identify => &mut record.latest_identify,
    };
    // The writer's sequence is the completion order; wall time only orders
    // entries that predate the sequence (seq 0) and is otherwise display
    // data, so a clock stepped backwards cannot freeze the record.
    let order = |e: &AttemptEntry| (e.seq, e.at);
    if latest
        .as_ref()
        .is_none_or(|current| order(current) <= order(&entry))
    {
        *latest = Some(entry.clone());
    }
    let Some(camera) = entry.camera.clone() else {
        return;
    };
    let bucket = match record
        .cameras
        .iter()
        .position(|bucket| bucket.camera == camera)
    {
        Some(index) => record.cameras.remove(index),
        None => CameraAttempts {
            camera,
            attempts: Vec::new(),
            connected: None,
        },
    };
    let mut bucket = bucket;
    let slot = bucket
        .attempts
        .iter()
        .position(|kept| order(kept) <= order(&entry))
        .unwrap_or(bucket.attempts.len());
    bucket.attempts.insert(slot, entry);
    bucket.attempts.truncate(PER_CAMERA);
    // Most recently used first (by the newest attempt each holds); the
    // least recently used falls off.
    let newest = |bucket: &CameraAttempts| bucket.attempts.first().map_or((0, 0), order);
    // A clock stepped backwards must not bury a newer completion.
    let position = record
        .cameras
        .iter()
        .position(|kept| newest(kept) <= newest(&bucket))
        .unwrap_or(record.cameras.len());
    record.cameras.insert(position, bucket);
    record.cameras.truncate(MAX_CAMERAS);
}

/// Where the records live: `/var/lib/irlume/attempts`, root-only, or the
/// test state directory. Every ancestor is validated (owner, not a
/// symlink, not group/world-writable) and the records directory is
/// pinned by descriptor: all file operations go through it, so a
/// redirected path after validation reaches nothing.
struct Store {
    dir: File,
    owner: u32,
}

#[cfg(not(test))]
fn store() -> io::Result<Store> {
    for path in ["/", "/var"] {
        checked_dir(Path::new(path), 0, false)?;
    }
    let var_lib = checked_dir(Path::new("/var/lib"), 0, false)?;
    // A new directory entry is durable only once its parent is synced;
    // an existing one costs a read path nothing.
    if create_private(Path::new("/var/lib/irlume"))? {
        var_lib.sync_all()?;
    }
    // The parent is validated before its child is followed; an existing
    // directory is accepted only when root owns it and nobody else can
    // write it.
    let parent = checked_dir(Path::new("/var/lib/irlume"), 0, false)?;
    let child = proc_path(&parent, "attempts");
    if create_private(&child)? {
        parent.sync_all()?;
    }
    let dir = checked_dir(&child, 0, true)?;
    Ok(Store { dir, owner: 0 })
}

#[cfg(test)]
fn store() -> io::Result<Store> {
    let parent = PathBuf::from(std::env::var_os("IRLUME_STATE_DIR").ok_or_else(invalid)?);
    // SAFETY: geteuid has no preconditions.
    let owner = unsafe { libc::geteuid() };
    let parent = checked_dir(&parent, owner, false)?;
    let child = proc_path(&parent, "attempts");
    if create_private(&child)? {
        parent.sync_all()?;
    }
    let dir = checked_dir(&child, owner, true)?;
    Ok(Store { dir, owner })
}

/// Create a private directory; `Ok(true)` when this call created it.
fn create_private(path: &Path) -> io::Result<bool> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// A path that resolves through an open directory descriptor, so the
/// directory it names is the one that was validated.
fn proc_path(dir: &File, name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{name}",
        std::os::fd::AsRawFd::as_raw_fd(dir)
    ))
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "attempt record store invalid")
}

/// A directory the store trusts: owned by `owner`, not a symlink, and
/// private when it holds records.
fn checked_dir(path: &Path, owner: u32, private: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    let mode = meta.mode() & 0o7777;
    if meta.uid() != owner
        || !meta.is_dir()
        || if private {
            mode != 0o700
        } else {
            mode & 0o022 != 0
        }
    {
        return Err(invalid());
    }
    Ok(file)
}

impl Store {
    fn path(&self, uid: u32) -> PathBuf {
        proc_path(&self.dir, &format!("{uid}.json"))
    }

    /// The record filed for `uid`, provided it is `user`'s: another
    /// account's record under a reused uid reads as empty and is replaced
    /// by the next write.
    fn read(&self, uid: u32, user: &str) -> io::Result<Stored> {
        let stored = self.read_any(uid)?;
        if !stored.account.is_empty() && stored.account != user {
            return Ok(Stored::default());
        }
        Ok(stored)
    }

    fn read_any(&self, uid: u32) -> io::Result<Stored> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path(uid))
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Stored::default()),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if meta.uid() != self.owner || !meta.is_file() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }

    /// Replace the record atomically: a private temp file in the same
    /// directory, then rename.
    fn write(&self, uid: u32, stored: &Stored) -> io::Result<()> {
        let bytes = serde_json::to_vec(stored).map_err(|_| invalid())?;
        let tmp = proc_path(&self.dir, &format!(".{uid}.json.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, self.path(uid))?;
        self.dir.sync_all()
    }

    fn lock(&self) -> io::Result<File> {
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(proc_path(&self.dir, ".lock"))?;
        // SAFETY: lock owns a live descriptor.
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(lock)
    }
}

fn account_uid(user: &str) -> io::Result<u32> {
    // The name must round-trip: a uid whose current name differs is
    // another account.
    let uid = crate::users::uid_for_name(user).ok_or_else(invalid)?;
    if crate::users::name_for_uid(uid).as_deref() != Some(user) {
        return Err(invalid());
    }
    Ok(uid)
}

/// File an attempt for `user`. Failures are reported to the journal by the
/// caller and never change the reply: the record is history, not policy.
pub(crate) fn record(user: &str, filed: Filed) -> io::Result<()> {
    let uid = account_uid(user)?;
    let store = store()?;
    let _lock = store.lock()?;
    let mut stored = store.read(uid, user)?;
    stored.account = user.to_owned();
    if stored.unit_key_hex.len() != 64 {
        let mut key = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut key)?;
        stored.unit_key_hex = key.iter().map(|b| format!("{b:02x}")).collect();
    }
    let key = key_bytes(&stored.unit_key_hex);
    let now = unix_now();
    // Assigned here, under the lock, in the writer's FIFO order. A fresh
    // record (the derived Default) starts at one.
    let seq = stored.next_seq.max(1);
    stored.next_seq = seq.wrapping_add(1).max(1);
    let entry = AttemptEntry {
        at: filed.at,
        seq,
        kind: filed.kind,
        surface: filed.surface,
        result: filed.result,
        cause: filed.cause,
        elapsed_ms: filed.elapsed_ms,
        capture_ms: filed.capture_ms,
        camera: filed
            .camera
            .as_ref()
            .map(|location| camera_of(location, &key)),
    };
    apply(&mut stored.record, entry, now);
    store.write(uid, &stored)
}

/// Queue capacity for the background writer: attempts complete far
/// slower than this drains; a peer spinning on refusals fills it and its
/// later attempts are dropped (journaled), never queued without bound.
const WRITER_QUEUE: usize = 64;

/// File an attempt from the one background writer: a bounded queue and a
/// single thread, so however fast refusals arrive the daemon holds at
/// most `WRITER_QUEUE` pending records and one writer serialized on the
/// store lock. A full queue drops the record and says so; the record is
/// history and never delays a reply.
pub(crate) fn record_in_background(user: String, filed: Filed) {
    static WRITER: std::sync::OnceLock<std::sync::mpsc::SyncSender<(String, Filed)>> =
        std::sync::OnceLock::new();
    static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sender = WRITER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<(String, Filed)>(WRITER_QUEUE);
        let spawned = std::thread::Builder::new()
            .name("irlume-attempt-record".into())
            .spawn(move || {
                for (user, filed) in rx {
                    if let Err(error) = record(&user, filed) {
                        irlume_common::jout_warn!(
                            "irlumed: attempt record for '{}' not written: {error}",
                            crate::journal_safe(&user)
                        );
                    }
                }
            });
        if let Err(error) = spawned {
            irlume_common::jout_warn!("irlumed: attempt record writer not started: {error}");
        }
        tx
    });
    if sender.try_send((user, filed)).is_err() {
        // Journal the first drop and then every hundredth, not each one.
        let dropped = DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if dropped == 1 || dropped % 100 == 0 {
            irlume_common::jout_warn!(
                "irlumed: attempt record writer queue full; {dropped} records dropped so far"
            );
        }
    }
}

/// The record for `user` (empty when nothing was ever filed), or `None`
/// when the account or the store cannot be read; the daemon answers with
/// an empty record either way. Each camera bucket is annotated with
/// whether that camera is attached now (ADR-0030 §5), decided here where
/// the account's key is: a same-model replacement in the same port does
/// not match a serial-bearing unit's discriminator.
pub(crate) fn load(user: &str) -> Option<AttemptRecord> {
    let uid = account_uid(user).ok()?;
    let stored = store().ok()?.read(uid, user).ok()?;
    let key = key_bytes(&stored.unit_key_hex);
    let mut record = stored.record;
    annotate_connected(
        &mut record,
        &key,
        &irlume_auth::connected_camera_locations(),
    );
    Some(record)
}

fn key_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Mark each bucket as attached or not against the cameras sysfs lists
/// now. Pure over `connected` so it is testable without hardware.
pub(crate) fn annotate_connected(
    record: &mut AttemptRecord,
    key: &[u8],
    connected: &[irlume_auth::CameraLocation],
) {
    for bucket in &mut record.cameras {
        let attached = connected.iter().any(|location| {
            let same_location = location.model == bucket.camera.model
                && location.port_chain == bucket.camera.port_chain
                && Some(location.descriptor_token.as_str())
                    == bucket.camera.descriptor_token.as_deref();
            // A recorded discriminator must be matched by the unit that is
            // there now; a record without one matches on location alone.
            let same_unit = match &bucket.camera.unit {
                Some(unit) => camera_of(location, key).unit.as_deref() == Some(unit.as_str()),
                None => true,
            };
            same_location && same_unit
        });
        bucket.connected = Some(attached);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: u64, kind: AttemptKind, camera: Option<&str>) -> AttemptEntry {
        AttemptEntry {
            at,
            seq: 0,
            kind,
            surface: AttemptSurface::Login,
            result: AttemptResult::Refused,
            cause: Some(OutcomeCause::NoFace),
            elapsed_ms: 100,
            capture_ms: None,
            camera: camera.map(|port| AttemptCamera {
                model: "046d:085e".into(),
                port_chain: Some(port.into()),
                descriptor_token: Some("0123456789abcdef".into()),
                unit: None,
            }),
        }
    }

    #[test]
    fn latest_of_each_kind_is_kept_apart_and_buckets_are_bounded() {
        let mut record = AttemptRecord::default();
        let now = 1_000_000;
        apply(
            &mut record,
            entry(now, AttemptKind::Authenticate, Some("1-2")),
            now,
        );
        apply(
            &mut record,
            entry(now + 1, AttemptKind::Identify, Some("1-2")),
            now + 1,
        );
        assert_eq!(record.latest_authenticate.as_ref().unwrap().at, now);
        assert_eq!(record.latest_identify.as_ref().unwrap().at, now + 1);
        // Six attempts on one camera keep five, newest first.
        for i in 2..8 {
            apply(
                &mut record,
                entry(now + i, AttemptKind::Authenticate, Some("1-2")),
                now + i,
            );
        }
        assert_eq!(record.cameras.len(), 1);
        assert_eq!(record.cameras[0].attempts.len(), PER_CAMERA);
        assert_eq!(record.cameras[0].attempts[0].at, now + 7);
        // A ninth camera evicts the least recently used bucket.
        for i in 0..8u64 {
            let t = now + 100 + i;
            apply(
                &mut record,
                entry(t, AttemptKind::Authenticate, Some(&format!("2-{i}"))),
                t,
            );
        }
        assert_eq!(record.cameras.len(), MAX_CAMERAS);
        assert!(
            record
                .cameras
                .iter()
                .all(|b| b.camera.port_chain.as_deref() != Some("1-2")),
            "the oldest bucket (1-2) was evicted"
        );
        assert_eq!(record.cameras[0].camera.port_chain.as_deref(), Some("2-7"));
        // Reusing a camera moves its bucket to the front without growing.
        apply(
            &mut record,
            entry(now + 200, AttemptKind::Authenticate, Some("2-0")),
            now + 200,
        );
        assert_eq!(record.cameras.len(), MAX_CAMERAS);
        assert_eq!(record.cameras[0].camera.port_chain.as_deref(), Some("2-0"));
        assert_eq!(record.cameras[0].attempts.len(), 2);
        // A camera-less attempt updates the latest line and no bucket.
        apply(
            &mut record,
            entry(now + 300, AttemptKind::Authenticate, None),
            now + 300,
        );
        assert_eq!(record.latest_authenticate.as_ref().unwrap().at, now + 300);
        assert_eq!(record.cameras.len(), MAX_CAMERAS);
        // Ninety days later, buckets nobody used are pruned on the write.
        let later = now + 300 + BUCKET_TTL_SECS + 1;
        apply(
            &mut record,
            entry(later, AttemptKind::Authenticate, Some("3-1")),
            later,
        );
        assert_eq!(record.cameras.len(), 1);
        assert_eq!(record.cameras[0].camera.port_chain.as_deref(), Some("3-1"));
    }

    /// ADR-0030 §5: a bucket is "connected" only for the same location
    /// and, for a serial-bearing unit, the same discriminator: a
    /// replacement in the same port reads as replaced, a move reads as
    /// disconnected.
    #[test]
    fn connected_annotation_tells_replacements_and_moves_apart() {
        let key = [3u8; 32];
        let brio = irlume_auth::CameraLocation {
            model: "046d:085e".into(),
            port_chain: Some("1-2".into()),
            descriptor_token: "0123456789abcdef".into(),
            serial: Some("e179cb54".into()),
        };
        let nexigo = irlume_auth::CameraLocation {
            model: "3443:c803".into(),
            port_chain: Some("1-3".into()),
            descriptor_token: "fedcba9876543210".into(),
            serial: None,
        };
        let mut record = AttemptRecord::default();
        for (i, location) in [&brio, &nexigo].into_iter().enumerate() {
            let mut entry = entry(1000 + i as u64, AttemptKind::Authenticate, None);
            entry.camera = Some(camera_of(location, &key));
            apply(&mut record, entry, 1000 + i as u64);
        }
        annotate_connected(&mut record, &key, &[brio.clone(), nexigo.clone()]);
        assert!(record.cameras.iter().all(|b| b.connected == Some(true)));
        // A same-model BRIO with another serial in the same port: replaced.
        let twin = irlume_auth::CameraLocation {
            serial: Some("e179cb55".into()),
            ..brio.clone()
        };
        annotate_connected(&mut record, &key, &[twin, nexigo.clone()]);
        let by_port = |record: &AttemptRecord, port: &str| {
            record
                .cameras
                .iter()
                .find(|b| b.camera.port_chain.as_deref() == Some(port))
                .unwrap()
                .connected
        };
        assert_eq!(by_port(&record, "1-2"), Some(false), "replaced unit");
        assert_eq!(by_port(&record, "1-3"), Some(true));
        // The NexiGo (serial-less) moved to another port: not this location.
        let moved = irlume_auth::CameraLocation {
            port_chain: Some("2-1".into()),
            ..nexigo.clone()
        };
        annotate_connected(&mut record, &key, &[brio.clone(), moved]);
        assert_eq!(by_port(&record, "1-2"), Some(true));
        assert_eq!(by_port(&record, "1-3"), Some(false));
        // Nothing attached: every bucket says so.
        annotate_connected(&mut record, &key, &[]);
        assert!(record.cameras.iter().all(|b| b.connected == Some(false)));
    }

    /// Writers may run out of order: an entry is placed by its own time
    /// and never displaces a newer one.
    #[test]
    fn out_of_order_writes_keep_completion_order() {
        let mut record = AttemptRecord::default();
        let now = 5_000_000;
        apply(
            &mut record,
            entry(now + 10, AttemptKind::Authenticate, Some("1-2")),
            now + 10,
        );
        apply(
            &mut record,
            entry(now + 5, AttemptKind::Authenticate, Some("1-2")),
            now + 10,
        );
        assert_eq!(record.latest_authenticate.as_ref().unwrap().at, now + 10);
        assert_eq!(record.cameras[0].attempts[0].at, now + 10);
        assert_eq!(record.cameras[0].attempts[1].at, now + 5);
        // An older attempt on another camera does not move that bucket ahead.
        apply(
            &mut record,
            entry(now + 1, AttemptKind::Authenticate, Some("1-3")),
            now + 10,
        );
        assert_eq!(record.cameras[0].camera.port_chain.as_deref(), Some("1-2"));
        assert_eq!(record.cameras[1].camera.port_chain.as_deref(), Some("1-3"));
        // Within one second the sequence decides: the later completion
        // stays latest whichever writer ran first.
        let mut later = entry(now + 20, AttemptKind::Identify, Some("1-2"));
        later.seq = 7;
        let mut earlier = entry(now + 20, AttemptKind::Identify, Some("1-2"));
        earlier.seq = 6;
        apply(&mut record, later, now + 20);
        apply(&mut record, earlier, now + 20);
        assert_eq!(record.latest_identify.as_ref().unwrap().seq, 7);
        assert_eq!(record.cameras[0].attempts[0].seq, 7);
        assert_eq!(record.cameras[0].attempts[1].seq, 6);
    }

    #[test]
    fn unit_discriminator_is_keyed_and_reveals_nothing() {
        let a = unit_discriminator(b"key-a", "200901010001");
        assert_eq!(a, unit_discriminator(b"key-a", "200901010001"));
        assert_ne!(a, unit_discriminator(b"key-b", "200901010001"));
        assert_ne!(a, unit_discriminator(b"key-a", "200901010002"));
        assert!(!a.contains("2009"));
        assert_eq!(a.len(), 16);
        let key = [7u8; 32];
        let with_serial = irlume_auth::CameraLocation {
            model: "046d:085e".into(),
            port_chain: Some("1-2".into()),
            descriptor_token: "0123456789abcdef".into(),
            serial: Some("e179cb54".into()),
        };
        let camera = camera_of(&with_serial, &key);
        assert!(camera.unit.is_some());
        assert!(!serde_json::to_string(&camera).unwrap().contains("e179cb54"));
        let blank = irlume_auth::CameraLocation {
            serial: Some("  ".into()),
            ..with_serial
        };
        assert_eq!(camera_of(&blank, &key).unit, None);
    }

    #[test]
    fn session_state_is_bound_to_the_requesting_login() {
        use irlume_core::biopolicy::SessionState;
        let dir = std::env::temp_dir().join(format!(
            "irlume-session-state-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let proc_root = dir.join("proc");
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(proc_root.join("100")).unwrap();
        std::fs::create_dir_all(proc_root.join("200")).unwrap();
        std::fs::create_dir_all(proc_root.join("300")).unwrap();
        std::fs::create_dir_all(&sessions).unwrap();
        // A lock screen inside the account's own user session.
        std::fs::write(
            proc_root.join("100/cgroup"),
            "0::/user.slice/user-1000.slice/session-2.scope\n",
        )
        .unwrap();
        std::fs::write(
            sessions.join("2"),
            "UID=1000\nUSER=alice\nCLASS=user\nSTATE=active\n",
        )
        .unwrap();
        // A greeter: in a greeter-class session of another uid.
        std::fs::write(
            proc_root.join("200/cgroup"),
            "0::/user.slice/user-980.slice/session-c1.scope\n",
        )
        .unwrap();
        std::fs::write(
            sessions.join("c1"),
            "UID=980\nUSER=gdm\nCLASS=greeter\nSTATE=active\n",
        )
        .unwrap();
        // A service outside any session.
        std::fs::write(
            proc_root.join("300/cgroup"),
            "0::/system.slice/sshd.service\n",
        )
        .unwrap();

        assert_eq!(
            session_state_from(&proc_root, &sessions, 100, 1000),
            Some(SessionState::Warm)
        );
        // The account having a live session elsewhere does not warm a
        // conversation that is not inside it.
        assert_eq!(
            session_state_from(&proc_root, &sessions, 200, 1000),
            Some(SessionState::Cold)
        );
        assert_eq!(
            session_state_from(&proc_root, &sessions, 300, 1000),
            Some(SessionState::Cold)
        );
        // Another account's session never warms this account.
        assert_eq!(
            session_state_from(&proc_root, &sessions, 100, 1001),
            Some(SessionState::Cold)
        );
        // Unresolvable (no such process, or the session's facts gone) is
        // no answer at all: the record files it as other.
        assert_eq!(session_state_from(&proc_root, &sessions, 999, 1000), None);
        std::fs::write(
            proc_root.join("300/cgroup"),
            "0::/user.slice/user-1000.slice/session-9.scope\n",
        )
        .unwrap();
        assert_eq!(session_state_from(&proc_root, &sessions, 300, 1000), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_round_trips_through_the_store_and_stays_private() {
        let _g = crate::tests::env_lock();
        let dir = std::env::temp_dir().join(format!(
            "irlume-attempts-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let me = crate::users::name_for_uid(uid).expect("own name");
        assert_eq!(
            load(&me),
            Some(AttemptRecord::default()),
            "nothing recorded yet: an empty record, not an error"
        );
        record(
            &me,
            Filed {
                at: unix_now(),
                kind: AttemptKind::Authenticate,
                surface: AttemptSurface::Lock,
                result: AttemptResult::Granted,
                cause: None,
                elapsed_ms: 1700,
                capture_ms: Some(1250),
                camera: Some(irlume_auth::CameraLocation {
                    model: "3277:0059".into(),
                    port_chain: Some("3-6".into()),
                    descriptor_token: "0123456789abcdef".into(),
                    serial: Some("200901010001".into()),
                }),
            },
        )
        .expect("record");
        let loaded = load(&me).expect("record present");
        let latest = loaded.latest_authenticate.as_ref().unwrap();
        assert_eq!(latest.result, AttemptResult::Granted);
        assert_eq!(latest.surface, AttemptSurface::Lock);
        assert_eq!(latest.capture_ms, Some(1250));
        let camera = latest.camera.as_ref().unwrap();
        assert_eq!(camera.model, "3277:0059");
        assert!(camera.unit.is_some());
        assert_eq!(loaded.cameras.len(), 1);
        // Root-only on disk, and the serial is nowhere in it.
        let path = dir.join("attempts").join(format!("{uid}.json"));
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("200901010001"), "{raw}");
        assert!(raw.contains("unit_key_hex"));
        // A second write keeps the same key, so the discriminator is stable.
        record(
            &me,
            Filed {
                at: unix_now(),
                kind: AttemptKind::Identify,
                surface: AttemptSurface::Other,
                result: AttemptResult::Refused,
                cause: Some(OutcomeCause::BelowThreshold),
                elapsed_ms: 900,
                capture_ms: None,
                camera: Some(irlume_auth::CameraLocation {
                    model: "3277:0059".into(),
                    port_chain: Some("3-6".into()),
                    descriptor_token: "0123456789abcdef".into(),
                    serial: Some("200901010001".into()),
                }),
            },
        )
        .expect("record");
        let again = load(&me).unwrap();
        assert_eq!(again.cameras.len(), 1, "same unit, same bucket");
        assert_eq!(again.cameras[0].attempts.len(), 2);
        // The sequence lives in the file: ordered across restarts, and
        // counting only this account's attempts.
        assert_eq!(again.cameras[0].attempts[0].seq, 2);
        assert_eq!(again.cameras[0].attempts[1].seq, 1);
        assert_eq!(store().unwrap().read_any(uid).unwrap().next_seq, 3);
        assert_eq!(again.latest_authenticate.as_ref().unwrap().at, latest.at);
        assert!(again.latest_identify.is_some());
        // A record left by a deleted account under this uid is not this
        // account's: it reads empty and the next write replaces it.
        let foreign = Stored {
            account: "someone-else".into(),
            ..Stored::default()
        };
        store().unwrap().write(uid, &foreign).unwrap();
        assert_eq!(load(&me), Some(AttemptRecord::default()));
        record(
            &me,
            Filed {
                at: unix_now(),
                kind: AttemptKind::Authenticate,
                surface: AttemptSurface::Login,
                result: AttemptResult::Refused,
                cause: Some(OutcomeCause::NoFace),
                elapsed_ms: 10,
                capture_ms: None,
                camera: None,
            },
        )
        .unwrap();
        let replaced = store().unwrap().read_any(uid).unwrap();
        assert_eq!(replaced.account, me);
        assert!(
            replaced.record.latest_identify.is_none(),
            "the foreign history is gone"
        );
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
