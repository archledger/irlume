// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Login transactions: a record of what a `login apply` changed, so it can be
//! verified afterwards and put back.
//!
//! # Why a record rather than the backups
//!
//! `pamwire` already keeps a `.pre-irlume` backup per file, and its disable path
//! restores it only when the live file still equals that backup plus irlume's
//! lines, stripping in place otherwise so an admin's later edit is not reverted.
//! That mechanism stays exactly as it is. This module does not replace it and
//! must not become a second opinion about what a PAM file should contain.
//!
//! What it adds is the ability to answer two questions the backups cannot:
//! *did the change I asked for actually land*, and *put back what was there
//! before THIS operation*, for a consumer that ran one specific apply and holds
//! its id.
//!
//! # The safety rule
//!
//! A record stores each file's digest as apply left it. Rollback recomputes
//! that digest and restores only if it still matches. If anything edited the
//! file in between, rollback refuses rather than reverting a change nobody
//! asked it to revert. That is the same principle the disable path already
//! follows, applied to a narrower question.
//!
//! # What is stored
//!
//! The pre-change content of each file irlume wrote. PAM stacks under
//! `/etc/pam.d` are world-readable, so this is not secret material, but the
//! store is kept root-only anyway: it describes exactly how a machine
//! authenticates, and there is no reason for an ordinary process to read it.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where transaction records live, unless `IRLUME_STATE_DIR` overrides the
/// state root (tests and containers do).
fn store_dir() -> PathBuf {
    let root = std::env::var_os("IRLUME_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/irlume"));
    root.join("login-transactions")
}

/// One file as it stood before and after a transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SurfaceRecord {
    /// PAM service name. The stable public identifier.
    pub(crate) id: String,
    /// The `/etc` path. Needed to restore, and deliberately never published in
    /// machine output, which names surfaces by service.
    pub(crate) path: String,
    /// The planned change this surface was recorded for.
    pub(crate) change: String,
    /// The file's content before the change. `None` when it did not exist, so
    /// rollback removes it rather than writing an empty file.
    pub(crate) before: Option<String>,
    /// Digest of the file as apply left it. Rollback requires this to still
    /// match, which is what stops it reverting somebody else's later edit.
    pub(crate) after_sha256: String,
    /// Permission bits before the change.
    ///
    /// Content alone does not restore a file. `write_atomic` copies permissions
    /// from the CURRENT file, which does not exist when apply removed it, so a
    /// recreated PAM stack would otherwise take the root process's umask
    /// default. Absent on records written before this field existed, in which
    /// case the old behaviour is kept rather than guessed at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<u32>,
    /// Owner before the change. Restored alongside `mode` for the same reason:
    /// a stack owned root:some-group and readable by it is not the same file
    /// once it comes back owned root:root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) gid: Option<u32>,
    /// The `.pre-irlume` backup, when apply created or consumed one.
    ///
    /// Wiring creates a backup and unwiring renames it back over the live file,
    /// so both change a second path the record would otherwise never mention.
    /// An undo that does not know about a file cannot undo it, and the leftover
    /// is not inert: a later enable rebuilds from the backup as its origin, so a
    /// stale one silently discards whatever an administrator changed in between.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sidecar: Option<SidecarRecord>,
}

/// A file changed alongside a surface, restored with it and never published.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SidecarRecord {
    pub(crate) path: String,
    /// The backup's digest as apply left it.
    ///
    /// Rollback used to restore the backup with no check at all, so a backup an
    /// administrator or a package replaced afterwards was silently overwritten —
    /// the same defect the surface's own digest exists to prevent, and worse in
    /// one way: a later enable rebuilds the live stack FROM the backup, so a
    /// wrong one propagates into PAM at the next enable.
    ///
    /// Absent on records written before this field existed, in which case the
    /// backup is restored unchecked as it was then; the schema gate is what
    /// stops an older engine reading a newer record and skipping the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) after_sha256: Option<String>,
    /// `None` when it did not exist, so a rollback removes it rather than
    /// leaving one behind for a later enable to trust.
    pub(crate) before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) gid: Option<u32>,
}

/// A file's ownership and permission bits, or `None` when it does not exist.
pub(crate) fn file_metadata(path: &Path) -> Option<(u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    // symlink_metadata, not metadata: a PAM path that is a symlink should be
    // described as itself rather than as whatever it points at.
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some((meta.mode() & 0o7777, meta.uid(), meta.gid()))
}

/// What one `login apply` did.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Transaction {
    pub(crate) id: String,
    /// How far this transaction got.
    ///
    /// A record is written `Prepared` BEFORE the first PAM write and rewritten
    /// `Applied` afterwards. A record left `Prepared` therefore means the writes
    /// may have run partially and nothing confirmed them: its before-states are
    /// still the authority for a rollback, but its after-digests are not, so
    /// rollback must not gate on them. Defaulted for records written by an
    /// engine that predates the field.
    #[serde(default)]
    pub(crate) status: TransactionStatus,
    /// Which record format this is. A GATE, unlike `engine_version`.
    ///
    /// Bumped only when the MEANING of a record changes: a new field a rollback
    /// must act on, or a different interpretation of an existing one. Adding a
    /// purely descriptive field does not need it. A build refuses anything above
    /// what it implements rather than reading the parts it recognises.
    ///
    /// Defaulted for records written before the field existed. Those predate any
    /// meaning change, so treating them as version 1 is accurate rather than
    /// generous.
    #[serde(default = "schema_version_1")]
    pub(crate) schema_version: u32,
    /// `enable` or `disable`.
    pub(crate) action: String,
    /// The plan this was applied from, so a consumer can tie the two together.
    pub(crate) plan_id: String,
    /// Which engine wrote the record. A record written by a different version
    /// is still readable, but the difference is worth surfacing.
    pub(crate) engine_version: String,
    pub(crate) surfaces: Vec<SurfaceRecord>,
}

/// How far a transaction got before the process stopped writing.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TransactionStatus {
    /// Before-states captured and persisted; the writes have not been confirmed.
    /// A record found in this state after the process exited means a crash, a
    /// full disk, or a kill landed mid-apply.
    #[default]
    Prepared,
    /// Every surface was written and its after-state recorded.
    Applied,
    /// A status this build does not know, written by a newer engine.
    ///
    /// Present for the same reason `OperationErrorCode::Unknown` is: without it
    /// serde fails the whole document, and an older engine meeting a newer
    /// record could not read it AT ALL. That matters more here than elsewhere,
    /// because the record is the recovery path: refusing to parse it would take
    /// away the one thing that says how to undo a change.
    ///
    /// Treated as conservatively as `Prepared`: this build cannot know what
    /// guarantees the newer status carries, so a rollback needs the same
    /// explicit acknowledgement.
    #[serde(other)]
    Unknown,
}

/// The record format this build writes and is willing to act on.
/// 2 since the sidecar carries an after-digest a rollback must honour: an engine
/// that ignored it would overwrite a backup somebody replaced, which is the
/// behaviour the field exists to stop.
pub(crate) const SCHEMA_VERSION: u32 = 2;

fn schema_version_1() -> u32 {
    1
}

/// Hex sha256 of a byte slice.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The digest of a file's current content, or `None` when it does not exist.
///
/// An unreadable file that DOES exist is an error rather than `None`: treating
/// "cannot read" as "absent" would let rollback decide a file was never there
/// and delete it.
pub(crate) fn file_sha256(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(sha256_hex(&bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

/// Digest of an absent file, as recorded. A distinct constant rather than an
/// empty string, so "the file was absent" cannot be confused with "nobody
/// recorded a digest".
pub(crate) const ABSENT: &str = "absent";

impl Transaction {
    /// Persist the record, root-readable only, replacing any earlier version of
    /// it atomically and durably.
    ///
    /// Written before the caller reports success. A transaction that changed
    /// files but could not be recorded is worse than one that did not run: the
    /// change is on disk with nothing describing how to undo it, so the write
    /// failing is an error the caller must surface.
    ///
    /// # Why this cannot open the record and truncate it
    ///
    /// A transaction is saved twice: `Prepared` before the first PAM write, then
    /// `Applied` after. The point of that ordering is that the before-states
    /// reach disk while the files are still untouched, so a crash mid-apply
    /// leaves something that says how to get back.
    ///
    /// This used to open the same path with `truncate(true)`. The second save
    /// therefore destroyed the prepared record as its FIRST act, and wrote the
    /// confirmed one into the emptied file. Between those two moments the files
    /// had already changed and the only description of their previous contents
    /// was gone; an ENOSPC, an EIO or a kill in that window left a machine whose
    /// PAM stack had been rewritten with nothing at all to roll back from. The
    /// write-ahead ordering was defeated by the write that was supposed to
    /// confirm it.
    ///
    /// Writing a temp file in the same directory and renaming means the record
    /// is only ever the prepared one or the confirmed one, never neither.
    /// `write_0600_atomic` also `fsync`s the file and its directory before
    /// returning, which the ordering needs and the old code never did: bytes
    /// still in the page cache when the machine loses power are not a record,
    /// and "written before the first PAM write" only means something if it is
    /// durable before the first PAM write. The store directory's own entry is
    /// synced too, on the run that creates it, for the same reason.
    pub(crate) fn save(&self) -> Result<PathBuf, String> {
        let dir = store_dir();
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        restrict(&dir, 0o700)?;
        // Creating the store is itself a directory entry that has to survive a
        // power loss, and `create_dir_all` does not make one durable.
        // `write_0600_atomic` fsyncs the record and the directory holding it,
        // but on a fresh install the entry FOR that directory is still only in
        // its parent's page cache: the record would be fsynced into a directory
        // that does not come back. PAM is rewritten immediately afterwards, so
        // the machine would again be left changed with nothing describing how
        // to undo it — the same defect as the truncate above, one level up.
        //
        // The WHOLE chain, unconditionally, and not just the immediate parent:
        // `create_dir_all` can create several levels, and syncing only the
        // store's parent leaves the parent's own entry in ITS parent unsynced.
        //
        // Unconditional because every way of narrowing it is the same
        // check-then-act split. Skipping the sync when the directory already
        // exists means a second process finds it there, writes its record and
        // rewrites PAM having inherited a guarantee nobody has made yet: the
        // process that created it may not have synced anything yet, or may have
        // died. Probing which ancestors are missing has the identical hole one
        // level up. So it is not narrowed. Syncing a directory with nothing
        // dirty is cheap, this runs twice per `login apply`, and `login apply`
        // is an administrator rewriting a login stack, not a hot path.
        fsync_ancestors(&dir)?;
        let path = dir.join(format!("{}.json", self.id));
        let body = serde_json::to_string(self).map_err(|e| format!("serialize record: {e}"))?;
        // The temp is created 0600 and renamed over the path, so the record is
        // never briefly readable by anyone the umask allows, and it does not
        // inherit the mode of a record an earlier run left behind: the inode is
        // a fresh one every time. Same helper as `envelope.rs` and
        // `template_key.rs`, which store material of the same sensitivity.
        irlume_common::write_0600_atomic(&path, body.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(path)
    }

    /// Read a record back by id.
    ///
    /// The id is used as a filename, so it is checked to be plain hex first: a
    /// consumer-supplied id containing a separator would otherwise reach
    /// outside the store.
    pub(crate) fn load(id: &str) -> Result<Self, LoadFailure> {
        if !is_valid_id(id) {
            return Err(LoadFailure::NotFound);
        }
        let path = store_dir().join(format!("{id}.json"));
        let body = match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(LoadFailure::NotFound)
            }
            // The store is root-only, so an ordinary caller lands here. Saying
            // "not found" would tell them their transaction id was wrong when
            // the truth is that they may not read it.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(LoadFailure::NotAuthorized)
            }
            Err(error) => return Err(LoadFailure::Unreadable(format!("{error}"))),
        };
        let record: Self =
            serde_json::from_str(&body).map_err(|e| LoadFailure::Unreadable(format!("{e}")))?;
        // Before anything reads a field. Deserializing succeeded, which is
        // exactly the trap: serde ignores unknown fields, so a newer record
        // parses cleanly into this older shape and every field this build knows
        // about looks reasonable. What it cannot know is whether they still mean
        // the same thing.
        if record.schema_version > SCHEMA_VERSION {
            return Err(LoadFailure::TooNew {
                found: record.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(record)
    }
}

/// Why a record could not be loaded.
///
/// Separated because they mean different things to a caller: a missing record
/// is a wrong or expired id, while a record that cannot be read is a permission
/// or storage problem the id has nothing to do with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoadFailure {
    NotFound,
    NotAuthorized,
    Unreadable(String),
    /// Written to a schema this build does not implement.
    ///
    /// `engine_version` was recorded but never checked, and serde ignores
    /// unknown fields, so an older engine happily read a newer record whenever
    /// the fields it knew about happened to deserialize — then rolled it back
    /// using its own, older meaning of them. A record is the recovery path for a
    /// machine's login stack; acting on one whose semantics this build cannot
    /// know is worse than refusing and naming the version that can.
    TooNew {
        found: u32,
        supported: u32,
    },
}

/// How far a rollback got, so a stopped one can be finished rather than
/// restarted.
///
/// A rollback restores surfaces one at a time. A write failure, an ENOSPC or a
/// signal after the second of four leaves a stack that is neither the
/// transaction's nor the administrator's, and re-running made it worse rather
/// than better: the surfaces already restored no longer match the recorded
/// after-digest, so the drift check refused the whole record and the operator
/// was left reconstructing the rest out of the JSON by hand.
///
/// Recording what is done, durably, after each surface, turns that into a
/// resume. A surface named here is skipped and not re-checked, because its
/// digest is deliberately no longer the one apply left.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RollbackProgress {
    /// Restores that were BEGUN. Each may or may not have landed.
    ///
    /// This is the half that was missing, and hardware found it: noting a
    /// restore only AFTER it succeeded leaves the window between the write and
    /// the note, and a kill there leaves a surface holding its before-image with
    /// nothing recording it. The re-run then checks it against the after-digest
    /// and refuses. Thirty killed rollbacks in a row were unfinishable for
    /// exactly this reason — write-then-record, the same ordering mistake the
    /// transaction record itself exists to avoid.
    ///
    /// An entry here means "do not trust this file's digest, and just do it
    /// again": restoring writes the recorded before-content, so doing it twice
    /// is the same as doing it once.
    pub(crate) started: Vec<String>,
    /// Restores known to have completed. Skipped entirely on a re-run.
    pub(crate) done: Vec<String>,
}

impl RollbackProgress {
    /// Whether this item's on-disk digest can still be believed.
    ///
    /// Anything begun is untrustworthy whether or not it finished, so both lists
    /// exempt an item from the drift check.
    pub(crate) fn touched(&self, key: &str) -> bool {
        self.started.iter().any(|k| k == key) || self.done.iter().any(|k| k == key)
    }

    pub(crate) fn finished(&self, key: &str) -> bool {
        self.done.iter().any(|k| k == key)
    }
}

pub(crate) fn rollback_progress(id: &str) -> RollbackProgress {
    let Some(path) = progress_path(id) else {
        return RollbackProgress::default();
    };
    // A progress note that cannot be parsed is treated as no progress: redoing a
    // restore is safe, since it writes the same recorded content, while skipping
    // one that never happened is not.
    std::fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<RollbackProgress>(&body).ok())
        .unwrap_or_default()
}

/// Note that a surface is restored, before moving to the next one.
///
/// Atomic and fsynced, for the same reason the record itself is: a note that
/// does not survive the crash it exists to describe is not a note.
pub(crate) fn note_rollback_progress(id: &str, progress: &RollbackProgress) -> Result<(), String> {
    let Some(path) = progress_path(id) else {
        return Err("invalid transaction id".into());
    };
    let body = serde_json::to_string(progress).map_err(|e| format!("serialize progress: {e}"))?;
    irlume_common::write_0600_atomic(&path, body.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// Drop the note once every surface is back.
///
/// Durably, and reported. Discarding the outcome meant a note could survive the
/// success that should have removed it: a power loss after the report resurrects
/// it, and the NEXT rollback trusts it and skips those files without checking
/// them. If an administrator changed a restored stack in between, that rollback
/// would report success having left the change untouched.
pub(crate) fn clear_rollback_progress(id: &str) -> Result<(), String> {
    let Some(path) = progress_path(id) else {
        return Ok(());
    };
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("remove {}: {e}", path.display())),
    }
    fsync_dir(&store_dir())
}

/// How a surface's backup is named in the progress note.
///
/// A surface is two writes: the live file and its `.pre-irlume` backup. Noting
/// the surface only once BOTH were done reproduced the very failure the note
/// exists to fix, one level down: a crash between them left the live file
/// holding its before-image and nothing recording that, so the re-run checked it
/// against the after-digest and refused it as drift.
pub(crate) fn sidecar_progress_id(surface_id: &str) -> String {
    format!("{surface_id}\u{0}sidecar")
}

fn progress_path(id: &str) -> Option<PathBuf> {
    is_valid_id(id).then(|| store_dir().join(format!("{id}.progress")))
}

/// Copy what is on disk NOW, before an unconfirmed rollback overwrites it.
///
/// A `prepared` record has no trustworthy after-digest, so `--accept-unconfirmed`
/// restores its before-images without checking the current state. That is the
/// only way to recover a machine whose apply was interrupted, and it is equally
/// a way to revert a package security update or an administrator's change made
/// after the crash. Nothing captured what it overwrote.
///
/// So it is captured first. This is not a second transaction record and feeds no
/// automatic path: it is files in a directory whose location the command
/// reports, for the person who finds their change gone.
///
/// Confirmed rollbacks do not need it. Their drift check has already established
/// that every file is byte-for-byte what apply left, so there is nothing
/// unrelated to lose.
pub(crate) fn snapshot_before_rollback(record: &Transaction) -> Result<PathBuf, String> {
    let dir = store_dir().join(format!("{}.before-rollback", record.id));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    restrict(&dir, 0o700)?;
    fsync_ancestors(&dir)?;
    for surface in &record.surfaces {
        let paths = [
            Some(surface.path.clone()),
            surface.sidecar.as_ref().map(|s| s.path.clone()),
        ];
        for path in paths.into_iter().flatten() {
            let source = Path::new(&path);
            // Copied under the file's own name, flattened. `sudo` and
            // `sudo.pre-irlume` therefore do not collide, and a name is checked
            // rather than trusted so nothing can point outside this directory.
            let Some(name) = source.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                || name.starts_with('.')
            {
                return Err(format!("{path} has a name irlume will not copy"));
            }
            match std::fs::read(source) {
                Ok(bytes) => {
                    let dest = dir.join(name);
                    // The FIRST capture is the one worth keeping. A resumed
                    // rollback runs this again, and by then the surfaces it
                    // already restored hold their before-image: re-capturing
                    // would overwrite the only copy of the administrator's
                    // change with irlume's own restore. Published by link, which
                    // fails rather than replaces, so the decision is not a
                    // separate check that could be raced.
                    let tmp = dir.join(format!(".{name}.tmp"));
                    irlume_common::write_0600_atomic(&tmp, &bytes)
                        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
                    let linked = std::fs::hard_link(&tmp, &dest);
                    let _ = std::fs::remove_file(&tmp);
                    match linked {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(format!("write {}: {e}", dest.display())),
                    }
                    // The link and the temp's removal are directory changes, and
                    // the rollback that follows destroys what was just copied. A
                    // snapshot that does not survive the power loss it exists for
                    // is not a snapshot.
                    fsync_dir(&dir)?;
                }
                // Absent is a state worth knowing about, but there is nothing to
                // copy and a rollback that recreates the file destroys nothing.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("read {path}: {e}")),
            }
        }
    }
    Ok(dir)
}

/// Whether a transaction id is safe to use as a filename.
///
/// Hex only, and a fixed length. This is the whole defence against a supplied
/// id escaping the store directory, so it rejects rather than sanitises: a
/// `..` or a `/` makes the id invalid, it does not get stripped out.
pub(crate) fn is_valid_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Make every directory above `dir` durable, so the names leading to it survive
/// a power loss.
///
/// Shallowest first, because a directory's entry lives in its parent: syncing
/// `/var/lib/irlume` makes `login-transactions` findable, and does nothing for
/// `irlume` itself, whose entry is in `/var/lib`. A record fsynced into a
/// directory whose name did not survive is not a record.
fn fsync_ancestors(dir: &Path) -> Result<(), String> {
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
fn ancestor_chain(dir: &Path) -> Vec<PathBuf> {
    let mut chain: Vec<PathBuf> = dir
        .ancestors()
        .skip(1) // `dir` itself is synced by the atomic write that fills it
        .map(|p| {
            // A relative path's last ancestor is "", which opens nothing. The
            // directory a relative path is anchored in is the working
            // directory, and that is where the entry actually lives. Filtering
            // the empty one out instead left `IRLUME_STATE_DIR=state` syncing
            // `state` while nothing synced the `state` entry itself.
            if p.as_os_str().is_empty() {
                PathBuf::from(".")
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
fn fsync_dir(dir: &Path) -> Result<(), String> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync {}: {e}", dir.display()))
}

fn restrict(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

/// Why a surface could not be rolled back.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RollbackRefusal {
    /// The file no longer matches what apply left, so restoring the recorded
    /// content would revert an edit this transaction did not make.
    ChangedSinceApply,
    /// The file could not be read to check.
    Unreadable(String),
}

/// Whether this surface is still exactly as apply left it.
///
/// The check rollback is gated on. Kept separate from the restore itself so it
/// can be run on its own by `verify`, and so both answer from one rule.
pub(crate) fn unchanged_since_apply(record: &SurfaceRecord) -> Result<(), RollbackRefusal> {
    unchanged_since_apply_excluding(record, &RollbackProgress::default())
}

/// The same question, minus the halves a stopped rollback already put back.
///
/// A surface is two writes, so it is two entries in the progress note. Either
/// one already restored holds its BEFORE content and therefore no longer matches
/// the after-digest; checking it would refuse the record and leave the other half
/// unfinishable.
pub(crate) fn unchanged_since_apply_excluding(
    record: &SurfaceRecord,
    done: &RollbackProgress,
) -> Result<(), RollbackRefusal> {
    if !done.touched(&record.id) {
        let current = match file_sha256(Path::new(&record.path)) {
            Ok(value) => value,
            Err(error) => return Err(RollbackRefusal::Unreadable(error)),
        };
        let current = current.unwrap_or_else(|| ABSENT.to_string());
        if current != record.after_sha256 {
            return Err(RollbackRefusal::ChangedSinceApply);
        }
    }
    if done.touched(&sidecar_progress_id(&record.id)) {
        return Ok(());
    }
    // The backup counts as part of the surface. Rollback restores it too, so
    // leaving it out of the check meant a backup an administrator or a package
    // replaced afterwards was silently overwritten — and a later `login enable`
    // rebuilds the LIVE stack from the backup, so a wrong one reaches PAM at the
    // next enable rather than sitting inert.
    //
    // Asked here rather than in the restore loop so it refuses BEFORE anything
    // is written: a rollback that stops halfway through is the thing the blanket
    // precheck exists to prevent.
    if let Some(sidecar) = &record.sidecar {
        if let Some(expected) = &sidecar.after_sha256 {
            let now = match file_sha256(Path::new(&sidecar.path)) {
                Ok(value) => value.unwrap_or_else(|| ABSENT.to_string()),
                Err(error) => return Err(RollbackRefusal::Unreadable(error)),
            };
            if &now != expected {
                return Err(RollbackRefusal::ChangedSinceApply);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises tests that set IRLUME_STATE_DIR. Cargo runs tests on threads
    /// and the variable is process-global, so two of these racing made one read
    /// the other's store.
    ///
    /// This is `crate::testenv::ENV_LOCK`, the one every other env-mutating test
    /// in this crate holds, and it has to be: a second mutex guarding the same
    /// variable serialises a test against its own module and against nothing
    /// else. These tests used a private one, so `logintx` and `pamwire` could
    /// both be inside their own lock, holding different values of
    /// IRLUME_STATE_DIR, at the same moment. It passed here and failed in CI,
    /// which is what a lock that guards the wrong scope looks like.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Holds the env lock AND puts `IRLUME_STATE_DIR` back to whatever it was.
    ///
    /// These tests used to end with `remove_var`, which is not a restore: a
    /// suite started with `IRLUME_STATE_DIR` pointing at a sandbox came out of
    /// them with it unset, and a later test would then resolve the store to the
    /// real `/var/lib/irlume`. The lock stops tests overlapping; it does not
    /// stop one handing the next a different world than it found. Restoring in
    /// `Drop` also covers the panicking test, which is when it matters most.
    struct StateDirGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<std::ffi::OsString>,
        root: PathBuf,
    }

    impl StateDirGuard {
        fn new(tag: &str) -> Self {
            let lock = env_lock();
            let previous = std::env::var_os("IRLUME_STATE_DIR");
            let root = temp_state(tag);
            // SAFETY: the env lock is held for this guard's whole lifetime, so
            // no other test in this process reads or writes the variable here.
            unsafe { std::env::set_var("IRLUME_STATE_DIR", &root) };
            Self {
                _lock: lock,
                previous,
                root,
            }
        }
    }

    impl Drop for StateDirGuard {
        fn drop(&mut self) {
            // SAFETY: as above; the lock is released after this runs.
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var("IRLUME_STATE_DIR", value),
                    None => std::env::remove_var("IRLUME_STATE_DIR"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn temp_state(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("irlume-logintx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp state dir");
        root
    }

    fn record(path: &Path, before: Option<&str>, after_sha: &str) -> SurfaceRecord {
        SurfaceRecord {
            id: "plasmalogin".into(),
            path: path.display().to_string(),
            change: "wire".into(),
            before: before.map(str::to_string),
            after_sha256: after_sha.into(),
            mode: None,
            uid: None,
            gid: None,
            sidecar: None,
        }
    }

    #[test]
    fn an_id_that_is_not_plain_hex_is_refused_rather_than_cleaned() {
        // The id becomes a filename, so this is the whole defence against one
        // reaching outside the store. Rejecting beats sanitising: a stripped
        // separator leaves a plausible-looking id that addresses a different file.
        assert!(is_valid_id("0123456789abcdef0123456789abcdef"));
        for bad in [
            "../../etc/passwd",
            "0123456789abcdef0123456789abcde/",
            "0123456789abcdef0123456789abcdeZ",
            "short",
            "",
            "0123456789abcdef0123456789abcdef0",
        ] {
            assert!(!is_valid_id(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_record_survives_a_round_trip() {
        let _env = StateDirGuard::new("roundtrip");
        let tx = Transaction {
            id: "0123456789abcdef0123456789abcdef".into(),
            schema_version: SCHEMA_VERSION,
            status: TransactionStatus::Applied,
            action: "enable".into(),
            plan_id: "aaaabbbbccccddddaaaabbbbccccdddd".into(),
            engine_version: "0.0.0".into(),
            surfaces: vec![record(
                Path::new("/etc/pam.d/plasmalogin"),
                Some("old\n"),
                "deadbeef",
            )],
        };
        let path = tx.save().expect("save");
        assert!(path.exists());
        assert_eq!(Transaction::load(&tx.id).expect("load"), tx);
    }

    /// Confirming a transaction must never be able to destroy the record that
    /// says how to undo it.
    ///
    /// A transaction is saved twice: `Prepared` before the first PAM write, then
    /// `Applied` after. `save` used to open the same path with `truncate(true)`,
    /// so the second save emptied the prepared record as its first act and then
    /// wrote the confirmed one into it. In that window the PAM files had already
    /// changed and nothing on disk described their previous contents, so an
    /// ENOSPC, an EIO or a kill left a rewritten machine with nothing to roll
    /// back from. The write that was meant to confirm the write-ahead ordering
    /// was the write that defeated it.
    ///
    /// Asserted on the INODE, because that is what distinguishes the two
    /// mechanisms rather than describing them. Truncating in place keeps the
    /// inode and passes through a moment where the file is empty; replacing by
    /// rename gives a new inode and never does. A test that only checked the
    /// final contents would pass either way.
    /// A stopped rollback can be finished, and an unconfirmed one keeps a copy
    /// of what it is about to overwrite.
    #[test]
    fn a_rollback_records_its_progress_and_snapshots_what_it_overwrites() {
        let _env = StateDirGuard::new("resume");
        let live = store_dir().parent().unwrap().join("etc");
        std::fs::create_dir_all(&live).unwrap();
        let greeter = live.join("kde");
        let sidecar = live.join("kde.pre-irlume");
        std::fs::write(&greeter, "what an administrator put here later\n").unwrap();
        std::fs::write(&sidecar, "the backup as it stands\n").unwrap();

        let id = "ab".repeat(16);
        let mut tx = Transaction {
            id: id.clone(),
            schema_version: SCHEMA_VERSION,
            status: TransactionStatus::Prepared,
            action: "enable".into(),
            plan_id: "1".repeat(32),
            engine_version: "0.0.0".into(),
            surfaces: vec![record(&greeter, Some("the original\n"), "deadbeef")],
        };
        tx.surfaces[0].sidecar = Some(SidecarRecord {
            path: sidecar.display().to_string(),
            after_sha256: None,
            before: None,
            mode: None,
            uid: None,
            gid: None,
        });

        // The snapshot holds what is on disk NOW, which is precisely what an
        // unconfirmed rollback would overwrite without checking.
        let dir = snapshot_before_rollback(&tx).expect("snapshot");
        assert_eq!(
            std::fs::read_to_string(dir.join("kde")).unwrap(),
            "what an administrator put here later\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("kde.pre-irlume")).unwrap(),
            "the backup as it stands\n",
            "the sidecar is overwritten too, so it is copied too"
        );

        // A surface that does not exist is not an error: recreating it destroys
        // nothing.
        std::fs::remove_file(&greeter).unwrap();
        assert!(snapshot_before_rollback(&tx).is_ok());

        // Progress: nothing, then BEGUN, then done, then cleared.
        assert_eq!(rollback_progress(&id), RollbackProgress::default());
        let begun = RollbackProgress {
            started: vec!["kde".to_string()],
            done: Vec::new(),
        };
        note_rollback_progress(&id, &begun).expect("note");
        // Begun is already enough to stop trusting the file: the write may have
        // landed before the process died. That is the whole point — a restore
        // writes the recorded content, so repeating it is safe, while checking
        // its digest is not.
        assert!(rollback_progress(&id).touched("kde"));
        assert!(!rollback_progress(&id).finished("kde"));
        let done = RollbackProgress {
            started: vec!["kde".to_string()],
            done: vec!["kde".to_string()],
        };
        note_rollback_progress(&id, &done).expect("note");
        assert!(rollback_progress(&id).finished("kde"));
        clear_rollback_progress(&id).expect("clear");
        assert_eq!(rollback_progress(&id), RollbackProgress::default());

        // An unreadable note means "no progress", never "all done": redoing a
        // restore writes the same recorded content, while skipping one that
        // never happened leaves a half-rolled-back stack.
        note_rollback_progress(&id, &done).expect("note");
        std::fs::write(store_dir().join(format!("{id}.progress")), "{ not a list").unwrap();
        assert_eq!(rollback_progress(&id), RollbackProgress::default());

        // An id that is not plain hex never becomes a path.
        assert!(note_rollback_progress("../../etc/passwd", &RollbackProgress::default()).is_err());
        assert_eq!(
            rollback_progress("../../etc/passwd"),
            RollbackProgress::default()
        );
        clear_rollback_progress(&id).expect("clear");

        // A surface is TWO writes, so it is two entries. Noting it only once
        // both landed left a crash between them unresumable at a finer
        // granularity: the live file held its before-image and nothing said so,
        // and the re-run refused it as drift.
        let surface = &tx.surfaces[0];
        let started = |ids: &[&str]| RollbackProgress {
            started: ids.iter().map(|s| (*s).to_string()).collect(),
            done: Vec::new(),
        };
        assert!(
            unchanged_since_apply_excluding(surface, &RollbackProgress::default()).is_err(),
            "the live file is not what apply left, so unaided this refuses"
        );
        assert_eq!(
            unchanged_since_apply_excluding(surface, &started(&[&surface.id])),
            Ok(()),
            "a restore merely BEGUN already exempts the file from the digest check"
        );

        // The halves are independent, and each excuses only itself. With a
        // DRIFTED backup recorded, noting the live half must not also excuse the
        // backup: one progress entry standing for both is how a stopped rollback
        // skipped a write it never made.
        let mut with_backup = surface.clone();
        with_backup.sidecar = Some(SidecarRecord {
            path: sidecar.display().to_string(),
            after_sha256: Some("a digest the backup does not have".into()),
            before: None,
            mode: None,
            uid: None,
            gid: None,
        });
        assert_eq!(
            unchanged_since_apply_excluding(&with_backup, &started(&[&with_backup.id])),
            Err(RollbackRefusal::ChangedSinceApply),
            "noting the live half excused the backup as well"
        );
        assert_eq!(
            unchanged_since_apply_excluding(
                &with_backup,
                &started(&[&with_backup.id, &sidecar_progress_id(&with_backup.id)])
            ),
            Ok(()),
            "with both halves noted there is nothing left to check"
        );
        // And noting the backup does not excuse the live file.
        assert!(unchanged_since_apply_excluding(
            &with_backup,
            &started(&[&sidecar_progress_id(&with_backup.id)])
        )
        .is_err());
    }

    /// A resumed unconfirmed rollback must not overwrite its own rescue copies.
    ///
    /// Every unconfirmed run snapshots before it looks at the progress note, so
    /// a second run re-captures surfaces the first already restored — which by
    /// then hold irlume's own before-image. That would replace the only saved
    /// copy of the administrator's change with the thing that overwrote it.
    #[test]
    fn a_resumed_snapshot_keeps_the_first_capture() {
        let _env = StateDirGuard::new("resnap");
        let live = store_dir().parent().unwrap().join("etc");
        std::fs::create_dir_all(&live).unwrap();
        let greeter = live.join("kde");
        std::fs::write(&greeter, "the administrator's change\n").unwrap();

        let tx = Transaction {
            id: "cd".repeat(16),
            schema_version: SCHEMA_VERSION,
            status: TransactionStatus::Prepared,
            action: "enable".into(),
            plan_id: "1".repeat(32),
            engine_version: "0.0.0".into(),
            surfaces: vec![record(&greeter, Some("the original\n"), "deadbeef")],
        };

        let dir = snapshot_before_rollback(&tx).expect("first snapshot");
        // The rollback restored it; a resumed run snapshots again.
        std::fs::write(&greeter, "the original\n").unwrap();
        snapshot_before_rollback(&tx).expect("second snapshot");

        assert_eq!(
            std::fs::read_to_string(dir.join("kde")).unwrap(),
            "the administrator's change\n",
            "the resume overwrote the only copy of what the rollback replaced"
        );
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "left scratch: {strays:?}");
    }

    /// A record from a schema this build does not implement is refused, not
    /// half-read.
    ///
    /// `engine_version` was recorded and never checked, and serde ignores
    /// unknown fields, so a newer record parsed cleanly into the older shape and
    /// every field this build knew about looked reasonable. What it could not
    /// know is whether they still MEAN the same thing, and a record is the
    /// recovery path for a machine's login stack.
    #[test]
    fn a_record_from_a_newer_schema_is_refused_rather_than_partly_understood() {
        let _env = StateDirGuard::new("schema");
        let dir = store_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let id = "0".repeat(32);
        let write = |body: &str| std::fs::write(dir.join(format!("{id}.json")), body).unwrap();

        // A newer engine's record: fields this build knows, plus one it does
        // not, plus a schema it does not implement.
        write(&format!(
            r#"{{"id":"{id}","schema_version":{},"status":"applied","action":"enable",
                "plan_id":"{}","engine_version":"9.9.9","surfaces":[],
                "something_this_build_ignores":{{"restore_me_too":"/etc/pam.d/x"}}}}"#,
            SCHEMA_VERSION + 1,
            "1".repeat(32)
        ));
        assert_eq!(
            Transaction::load(&id),
            Err(LoadFailure::TooNew {
                found: SCHEMA_VERSION + 1,
                supported: SCHEMA_VERSION
            }),
            "a newer record must not be acted on by an older engine"
        );

        // The same record at a schema this build implements is fine, unknown
        // field and all: ignoring a descriptive addition is the point of not
        // bumping the version for one.
        write(&format!(
            r#"{{"id":"{id}","schema_version":{SCHEMA_VERSION},"status":"applied","action":"enable",
                "plan_id":"{}","engine_version":"9.9.9","surfaces":[],
                "something_this_build_ignores":true}}"#,
            "1".repeat(32)
        ));
        assert_eq!(
            Transaction::load(&id).map(|r| r.schema_version),
            Ok(SCHEMA_VERSION)
        );

        // A record written before the field existed predates any meaning
        // change, so it reads as version 1 rather than being refused.
        write(&format!(
            r#"{{"id":"{id}","status":"applied","action":"enable",
                "plan_id":"{}","engine_version":"0.7.0","surfaces":[]}}"#,
            "1".repeat(32)
        ));
        assert_eq!(Transaction::load(&id).map(|r| r.schema_version), Ok(1));
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
        let abs = ancestor_chain(Path::new("/var/lib/irlume/login-transactions"));
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
        let rel = ancestor_chain(Path::new("state/login-transactions"));
        assert_eq!(rel, vec![PathBuf::from("."), PathBuf::from("state")]);

        // A store directly under a relative root still names the anchor.
        assert_eq!(
            ancestor_chain(Path::new("login-transactions")),
            vec![PathBuf::from(".")]
        );
        // Nothing in a chain may be empty: an empty path opens nothing, so a
        // sync of it is a sync that silently did not happen.
        for dir in ["/a/b", "a/b", "b", "/"] {
            assert!(
                ancestor_chain(Path::new(dir))
                    .iter()
                    .all(|p| !p.as_os_str().is_empty()),
                "{dir} produced an empty entry"
            );
        }
    }

    #[test]
    fn confirming_a_transaction_replaces_its_record_instead_of_emptying_it() {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let _env = StateDirGuard::new("atomic");

        let mut tx = Transaction {
            id: "abcdef0123456789abcdef0123456789".into(),
            schema_version: SCHEMA_VERSION,
            status: TransactionStatus::Prepared,
            action: "enable".into(),
            plan_id: "1".repeat(32),
            engine_version: "0.0.0".into(),
            surfaces: vec![record(
                Path::new("/etc/pam.d/plasmalogin"),
                Some("the only copy of what was there before\n"),
                "deadbeef",
            )],
        };
        let path = tx.save().expect("save prepared");
        let prepared_inode = std::fs::metadata(&path).expect("stat").ino();

        // The second save, the one that happens after PAM has been rewritten.
        tx.status = TransactionStatus::Applied;
        tx.save().expect("save applied");
        let applied_inode = std::fs::metadata(&path).expect("stat").ino();

        assert_ne!(
            prepared_inode, applied_inode,
            "the record was rewritten in place, so confirming it passes through a \
             moment where the before-states are gone"
        );
        assert_eq!(
            Transaction::load(&tx.id).expect("load").status,
            TransactionStatus::Applied
        );
        // The replacement is a fresh inode, so it must carry the mode itself
        // rather than inheriting the previous record's.
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the replacement must not widen the record");

        // A temp left behind in the store would be a second, stale description
        // of how the machine authenticates.
        let strays: Vec<_> = std::fs::read_dir(store_dir())
            .expect("read store")
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|n| n != "abcdef0123456789abcdef0123456789.json")
            .collect();
        assert!(strays.is_empty(), "stray files in the store: {strays:?}");
    }

    #[test]
    fn the_store_is_not_readable_by_other_accounts() {
        use std::os::unix::fs::PermissionsExt;
        let _env = StateDirGuard::new("perms");
        let tx = Transaction {
            id: "ffffffffffffffffffffffffffffffff".into(),
            schema_version: SCHEMA_VERSION,
            status: TransactionStatus::Applied,
            action: "disable".into(),
            plan_id: "0".repeat(32),
            engine_version: "0.0.0".into(),
            surfaces: vec![],
        };
        let path = tx.save().expect("save");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a record describes how a machine authenticates"
        );
        let dir_mode = std::fs::metadata(path.parent().expect("parent"))
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn rollback_is_refused_once_the_file_has_moved_on() {
        let root = temp_state("changed");
        let target = root.join("plasmalogin");
        std::fs::write(&target, "as apply left it\n").expect("write");
        let after = sha256_hex(b"as apply left it\n");
        let rec = record(&target, Some("original\n"), &after);

        // Untouched since apply: restoring is safe.
        assert_eq!(unchanged_since_apply(&rec), Ok(()));

        // Somebody else edited it. Restoring the recorded content now would
        // revert a change this transaction never made.
        std::fs::write(&target, "an admin added a line\n").expect("write");
        assert_eq!(
            unchanged_since_apply(&rec),
            Err(RollbackRefusal::ChangedSinceApply)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_apply_created_is_recognised_when_it_is_still_absent() {
        // `disable` can remove a file. Its recorded after-state is ABSENT, and
        // an absent file must compare equal to that rather than read as drift.
        let root = temp_state("absent");
        let target = root.join("never-existed");
        let rec = record(&target, Some("was here\n"), ABSENT);
        assert_eq!(unchanged_since_apply(&rec), Ok(()));

        std::fs::write(&target, "something put it back\n").expect("write");
        assert_eq!(
            unchanged_since_apply(&rec),
            Err(RollbackRefusal::ChangedSinceApply)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unreadable_file_is_an_error_not_an_absent_one() {
        // Treating "cannot read" as "absent" would let rollback conclude a file
        // was never there and delete it.
        let root = temp_state("unreadable");
        let dir = root.join("a-directory-where-a-file-is-expected");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let rec = record(&dir, None, "deadbeef");
        assert!(matches!(
            unchanged_since_apply(&rec),
            Err(RollbackRefusal::Unreadable(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }
}
