// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A record of the ONE capture write a stream makes, so a later irlume can
//! tell its own crash leftover from another writer's value.
//!
//! # The question this answers
//!
//! `StreamMode` restores the emitter control when a stream ends. When a new
//! stream finds the control already holding the value it wants, that fact
//! alone cannot separate two cases (#188):
//!
//!   * another tool set this value, so it is not irlume's to undo;
//!   * irlume set it and was killed before it could undo it.
//!
//! Claiming it always undoes another program's change; never claiming it makes
//! one `SIGKILL` leave the mode applied forever, because every later session
//! reads the leftover as somebody else's. This record is the missing fact: it
//! is written immediately before the `SET_CUR` and removed once the guard
//! resolves, so a value found already in place is irlume's own leftover
//! exactly when a record for this camera, this control and these bytes exists.
//!
//! # Durability, deliberately weaker than the discovery journal's
//!
//! What this must survive is PROCESS death: a `SIGKILL`, the watchdog, a panic.
//! The page cache survives all of those, so a plain write and rename is
//! enough for the next process to read the record, and nothing here calls
//! `fsync`. The #183 journal fsyncs because a discovery record must survive a
//! POWER CUT; this record sits on the authentication path, once per unlock,
//! and a power cut that loses it loses an in-flight stream's bookkeeping on a
//! control that a physical power cycle was measured to reset anyway (pt190:
//! a replugged camera returns at its `GET_DEF`). Conflating the two
//! requirements is what kept this record out of #184 for two review rounds.
//!
//! # Liveness
//!
//! The file doubles as its own liveness signal: the writer holds a
//! non-blocking `flock` on it for as long as the guard is armed, and the lock
//! dies with the process while the file does not. A claim that cannot take
//! the lock is looking at a LIVE stream's record — a second process, or this
//! process's own previous guard during a frozen-stream restart — and refuses.
//! No pid or boot id is stored: #183 removed those from the journal because a
//! recorded pid strands a record when its long-lived writer outlives the
//! stream, and a kernel-released lock cannot go stale.

use crate::emitter_journal::{filing_key, fingerprint, from_hex, identity_authorizes, to_hex};
use crate::uvc_descriptor::CameraIdentity;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The record format this build writes and is willing to act on.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// How many times a leftover may be claimed before irlume stops trying.
///
/// A claim ends in a firmware write at stream end, and a control whose
/// `GET_CUR` never reflects that write would otherwise be "claimed" again at
/// every stream open, forever — the unbounded rewrite loop the #183 journal
/// bounds with the same constant, on the same reasoning.
pub(crate) const MAX_RESTORE_ATTEMPTS: u32 = 3;

/// Trace a stream-record event onto the stream `set_cur` traces writes to.
///
/// Same switch as the journal's, for the same reason: the claims this module
/// makes are ORDERINGS — record on disk before the `SET_CUR`, resolved only
/// after the restore — and on hardware the only way to observe them is to put
/// the events into the same transcript as the writes, in order. An strace of
/// `write(2)` then shows both interleaved (pt190).
fn trace(event: &str) {
    if std::env::var_os("IRLUME_LOG_EMITTER_WRITES").is_some() {
        eprintln!("irlume: stream-record {event}");
    }
}

/// One stream's applied emitter mode, on disk from just before the `SET_CUR`
/// until the guard resolves.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct StreamWrite {
    /// A GATE, required with no serde default, for the reason the journal's
    /// is: serde ignores unknown fields, so any future record would otherwise
    /// deserialize into a plausible-looking older shape and authorise a write
    /// this build cannot reason about.
    pub(crate) schema_version: u32,
    /// Which build wrote the record. Descriptive, not a gate.
    pub(crate) engine_version: String,
    /// Hex sha256 of the camera's USB descriptor blob: the model.
    pub(crate) descriptor_sha256: String,
    /// `vid:pid`, human-readable, checked against the digest's camera.
    pub(crate) usb_id: String,
    pub(crate) interface_number: u8,
    pub(crate) unit: u8,
    pub(crate) selector: u8,
    /// Hex of the payload the stream applied. A claim requires the control to
    /// be holding exactly this, or the leftover it describes is already gone.
    pub(crate) applied: String,
    /// Hex of what the write displaced: the value a claimed restore puts back.
    pub(crate) displaced: String,
    /// How many times a claim has armed a restore for this record. Counted at
    /// claim time, before the write it authorises, like the journal's.
    #[serde(default)]
    pub(crate) restore_attempts: u32,
    /// The USB serial, when the camera published one at write time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) serial: Option<String>,
    /// The sysfs path of the USB device: the port, which with the digest and
    /// serial is the same three-part identity the journal files under.
    pub(crate) usb_devpath: String,
}

/// Where stream records live. Separate from the discovery journal's store:
/// the two have different lifetimes, different durability, and a shared
/// directory would invite a shared reader.
fn store_dir() -> PathBuf {
    irlume_common::state_dir().join("ir-emitter-stream")
}

/// This camera's record path. One file per camera: a stream applies one
/// control, and a second stream on the same camera replaces rather than
/// accumulates.
///
/// Filed under the journal's [`filing_key`], which includes the serial. A
/// serial that reads at write time and not at claim time (or the reverse)
/// makes the claim MISS; that fails toward not restoring, which is the
/// pre-#188 status quo for a leftover, and the identity check would refuse
/// such a claim anyway. No scan fallback, deliberately: a stream record is
/// bookkeeping for the machine's own camera, not undo data for exploratory
/// bytes, and the cost of a miss is bounded where the journal's was not.
fn record_path(id: &CameraIdentity) -> PathBuf {
    store_dir().join(format!("{}.json", filing_key(id)))
}

/// A live record: the file on disk plus the `flock` that marks its writer as
/// alive. Held by the stream guard while armed.
///
/// Dropping this WITHOUT [`resolve`](StreamRecord::resolve) keeps the file and
/// releases the lock, which is exactly the crash shape on purpose: a restore
/// that failed leaves the leftover real, so the record must stay claimable.
#[derive(Debug)]
pub(crate) struct StreamRecord {
    path: PathBuf,
    file: std::fs::File,
}

impl StreamRecord {
    /// Remove the record: the change it describes is no longer outstanding,
    /// either because the restore landed or because the control was found no
    /// longer holding irlume's value.
    ///
    /// Only the inode this handle locked is removed. The path may already
    /// hold a NEWER record — a replacement guard renames its own over this
    /// one — and removing by name alone would delete bookkeeping that is not
    /// ours. A writer renaming over between the check and the unlink loses
    /// its file's name; the window is a few instructions wide, needs a second
    /// irlume on the same camera in it, and costs that writer a claimable
    /// leftover rather than a wrong write, so it is accepted rather than
    /// closed.
    pub(crate) fn resolve(self) {
        use std::os::unix::fs::MetadataExt as _;
        let Ok(ours) = self.file.metadata() else {
            return;
        };
        match std::fs::metadata(&self.path) {
            Ok(m) if (m.dev(), m.ino()) == (ours.dev(), ours.ino()) => {
                let _ = std::fs::remove_file(&self.path);
                trace("resolved");
            }
            _ => trace("resolved (already replaced, left in place)"),
        }
    }
}

/// Serialize, write to a fresh temp file, lock it, and rename it into place.
///
/// The lock is taken on the temp fd BEFORE the rename, so from the first
/// instant the record is visible its writer already reads as alive; there is
/// no window in which a concurrent claim could adopt a record whose owner is
/// running. `flock` follows the open file description across the rename.
///
/// No fsync anywhere, see the module doc: process death is the requirement,
/// and the page cache meets it.
fn publish(path: &Path, record: &StreamWrite) -> Result<StreamRecord, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::io::AsRawFd as _;

    let dir = store_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    irlume_common::restrict(&dir, 0o700)?;
    let body = serde_json::to_string(record).map_err(|e| format!("serialize: {e}"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("stream");
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.tmp.{}.{seq}", std::process::id()));
    let open_tmp = || {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
    };
    let mut file = match open_tmp() {
        // A crashed prior writer with this pid and seq left its temp behind;
        // it is nobody's record (never renamed), so replace it.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)
                .map_err(|e| format!("clear stale {}: {e}", tmp.display()))?;
            open_tmp().map_err(|e| format!("create {}: {e}", tmp.display()))?
        }
        other => other.map_err(|e| format!("create {}: {e}", tmp.display()))?,
    };
    if let Err(e) = file.write_all(body.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {}: {e}", tmp.display()));
    }
    // SAFETY: the fd is owned by `file`, which the returned guard keeps open.
    // A fresh 0600 temp file nobody else can have opened: the non-blocking
    // lock cannot fail with WouldBlock, and any failure is reported.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("lock {}: {e}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("publish {}: {e}", path.display()));
    }
    Ok(StreamRecord {
        path: path.to_path_buf(),
        file,
    })
}

/// Put the record for this stream's write on disk, locked, BEFORE the write.
///
/// Best-effort at the caller: a store that cannot be written costs crash
/// bookkeeping, not the authentication — see `write_if_different` for why
/// that direction was chosen.
pub(crate) fn save(
    id: &CameraIdentity,
    unit: u8,
    selector: u8,
    applied: &[u8],
    displaced: &[u8],
) -> Result<StreamRecord, String> {
    let record = StreamWrite {
        schema_version: SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        descriptor_sha256: fingerprint(id),
        usb_id: id.usb_id(),
        interface_number: id.interface_number,
        unit,
        selector,
        applied: to_hex(applied),
        displaced: to_hex(displaced),
        restore_attempts: 0,
        serial: id.serial.clone(),
        usb_devpath: id.usb_devpath.clone(),
    };
    let handle = publish(&record_path(id), &record)?;
    trace(&format!(
        "saved unit{unit}/sel{selector} applied={} displaced={}",
        record.applied, record.displaced
    ));
    Ok(handle)
}

/// Why a record does not hand this stream a restore.
///
/// Separated because they call for different noise: most are the ordinary
/// business of a machine where something else also touches the control, and
/// two mean the store holds something wrong enough to say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaimRefusal {
    /// Not written about the camera in front of us, to the standard required
    /// to write to it. Includes a recorded serial the attached camera cannot
    /// currently reproduce, which fails CLOSED exactly as the journal does.
    DifferentCamera,
    /// A build with a different record format wrote this. Report, never act.
    UnsupportedSchema { found: u32 },
    /// The record's own fields disagree with each other or will not parse.
    Malformed(String),
    /// The record names a different control than this stream is applying.
    /// The leftover may still be real, but it is not THIS write's business:
    /// claiming it here would arm a restore for a control nobody validated
    /// this pass.
    DifferentControl { unit: u8, selector: u8 },
    /// The control is not holding what the record says was applied, so the
    /// leftover it describes is already gone — somebody moved the control
    /// after the crash. There is nothing of irlume's to undo.
    Superseded,
    /// Claimed and restored [`MAX_RESTORE_ATTEMPTS`] times without the
    /// control ever reading back different. Writing again is the loop the
    /// counter exists to stop.
    OutOfAttempts { attempts: u32 },
}

/// Whether this record hands the stream that found `current` already in place
/// a restore value. Pure, so every gate that ends in a firmware write is
/// testable without a camera (#183's rule).
///
/// The caller has already validated that (unit, selector) names a control
/// this camera's descriptor publishes — every apply path checks that before
/// reading the control — so equality with the record's coordinates carries
/// that gate over to the claim without a second descriptor walk.
pub(crate) fn record_claims(
    record: &StreamWrite,
    id: &CameraIdentity,
    unit: u8,
    selector: u8,
    current: &[u8],
) -> Result<Vec<u8>, ClaimRefusal> {
    if record.schema_version != SCHEMA_VERSION {
        return Err(ClaimRefusal::UnsupportedSchema {
            found: record.schema_version,
        });
    }
    if !identity_authorizes(
        &record.descriptor_sha256,
        &record.usb_devpath,
        record.serial.as_deref(),
        id,
    ) {
        return Err(ClaimRefusal::DifferentCamera);
    }
    // The digest already pins the descriptors; these two come from the same
    // sysfs read, so a disagreement means the record was assembled from two
    // cameras or edited. Same check, same reasoning as the journal's.
    if record.usb_id != id.usb_id() || record.interface_number != id.interface_number {
        return Err(ClaimRefusal::Malformed(format!(
            "record says {} interface {}, camera is {} interface {}",
            record.usb_id,
            record.interface_number,
            id.usb_id(),
            id.interface_number
        )));
    }
    if (record.unit, record.selector) != (unit, selector) {
        return Err(ClaimRefusal::DifferentControl {
            unit: record.unit,
            selector: record.selector,
        });
    }
    let applied =
        from_hex(&record.applied).map_err(|e| ClaimRefusal::Malformed(format!("applied: {e}")))?;
    let displaced = from_hex(&record.displaced)
        .map_err(|e| ClaimRefusal::Malformed(format!("displaced: {e}")))?;
    if displaced.len() != applied.len() {
        return Err(ClaimRefusal::Malformed(format!(
            "{} displaced bytes recorded for a control whose applied value is {} long",
            displaced.len(),
            applied.len()
        )));
    }
    if applied == displaced {
        // A write that displaced nothing is a write the tail never makes, so
        // this record did not come from it.
        return Err(ClaimRefusal::Malformed(
            "applied and displaced are identical".to_string(),
        ));
    }
    if applied != current {
        return Err(ClaimRefusal::Superseded);
    }
    if record.restore_attempts >= MAX_RESTORE_ATTEMPTS {
        return Err(ClaimRefusal::OutOfAttempts {
            attempts: record.restore_attempts,
        });
    }
    Ok(displaced)
}

/// Try to claim a control found already holding the wanted value as irlume's
/// own crash leftover.
///
/// `None` is the ordinary answer and means "not irlume's to undo": no record,
/// a record whose writer is still alive (its lock is held), or a record the
/// pure gate refuses. `Some` arms the caller's guard with the displaced value
/// and hands over the still-locked record, with the attempt already counted
/// on disk — counted BEFORE the write it authorises, so a crash between claim
/// and restore cannot uncount it.
pub(crate) fn claim(
    id: &CameraIdentity,
    unit: u8,
    selector: u8,
    current: &[u8],
) -> Option<(Vec<u8>, StreamRecord)> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::io::AsRawFd as _;

    let path = record_path(id);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            // Not absence: a store that cannot be read may be hiding a real
            // leftover, and silence here would wear the "somebody else's
            // value" answer without the evidence for it.
            eprintln!(
                "irlume: cannot read the stream record {}: {e}; treating the control's value \
                 as another writer's",
                path.display()
            );
            return None;
        }
    };
    // A held lock is a live writer: this stream's own predecessor during a
    // frozen-stream restart, or another process mid-capture. Either way the
    // value in the control is a RUNNING stream's business. Silent, because
    // the restart path lands here at every reopen on a camera whose control
    // survives a stream close.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    // The lock arrived after the open; make sure the name still means this
    // inode. A record replaced in between belongs to whoever replaced it.
    let (Ok(ours), Ok(named)) = (file.metadata(), std::fs::metadata(&path)) else {
        return None;
    };
    if (ours.dev(), ours.ino()) != (named.dev(), named.ino()) {
        return None;
    }
    let body = match std::io::read_to_string(&file) {
        Ok(body) => body,
        Err(e) => {
            eprintln!(
                "irlume: cannot read the stream record {}: {e}",
                path.display()
            );
            return None;
        }
    };
    let record: StreamWrite = match serde_json::from_str(&body) {
        Ok(record) => record,
        Err(e) => {
            eprintln!(
                "irlume: stream record {} does not parse ({e}); a leftover may be \
                 unresolved and this build cannot claim it",
                path.display()
            );
            return None;
        }
    };
    let displaced = match record_claims(&record, id, unit, selector, current) {
        Ok(displaced) => displaced,
        // Ordinary refusals, quiet: a machine where something else also sets
        // the control lands here at every stream open.
        Err(ClaimRefusal::DifferentCamera)
        | Err(ClaimRefusal::DifferentControl { .. })
        | Err(ClaimRefusal::Superseded) => return None,
        Err(ClaimRefusal::UnsupportedSchema { found }) => {
            eprintln!(
                "irlume: stream record {} has schema {found}, this build reads {SCHEMA_VERSION}; \
                 a leftover may be unresolved and this build cannot claim it",
                path.display()
            );
            return None;
        }
        Err(ClaimRefusal::Malformed(why)) => {
            eprintln!(
                "irlume: stream record {} is malformed ({why}); not acting on it",
                path.display()
            );
            return None;
        }
        Err(ClaimRefusal::OutOfAttempts { attempts }) => {
            eprintln!(
                "irlume: unit{unit}/sel{selector} was restored {attempts} times and still \
                 reads as irlume's leftover; leaving it and its record alone"
            );
            return None;
        }
    };
    // Count the attempt before the write it authorises. The rewrite replaces
    // the inode, so the lock moves to the new file with the returned handle;
    // a claim that cannot count durably-enough does not arm.
    let counted = StreamWrite {
        restore_attempts: record.restore_attempts + 1,
        ..record
    };
    match publish(&path, &counted) {
        Ok(handle) => {
            trace(&format!(
                "claimed unit{unit}/sel{selector} displaced={} attempt={}",
                counted.displaced, counted.restore_attempts
            ));
            Some((displaced, handle))
        }
        Err(why) => {
            eprintln!(
                "irlume: cannot count a claim on {} ({why}); not restoring",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_with(descriptors: Vec<u8>) -> CameraIdentity {
        CameraIdentity {
            descriptors,
            interface_number: 0,
            vid: 0x3443,
            pid: 0xc803,
            serial: None,
            usb_devpath: "/devices/pci0000:00/usb1/1-2/1-2.1".to_string(),
        }
    }

    fn identity() -> CameraIdentity {
        identity_with(vec![0x0a, 0x24, 0x03, 0x0e])
    }

    fn record_for(id: &CameraIdentity) -> StreamWrite {
        StreamWrite {
            schema_version: SCHEMA_VERSION,
            engine_version: "test".into(),
            descriptor_sha256: fingerprint(id),
            usb_id: id.usb_id(),
            interface_number: id.interface_number,
            unit: 4,
            selector: 6,
            applied: "010302".into(),
            displaced: "010301".into(),
            restore_attempts: 0,
            serial: None,
            usb_devpath: id.usb_devpath.clone(),
        }
    }

    #[test]
    fn a_matching_record_hands_over_the_displaced_value() {
        let id = identity();
        assert_eq!(
            record_claims(&record_for(&id), &id, 4, 6, &[1, 3, 2]),
            Ok(vec![1, 3, 1]),
            "camera, control and bytes all match: this is irlume's leftover"
        );
    }

    #[test]
    fn a_record_for_another_camera_is_refused() {
        let id = identity();
        let other = identity_with(vec![0xff]);
        assert_eq!(
            record_claims(&record_for(&other), &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::DifferentCamera)
        );
        let mut moved = record_for(&id);
        moved.usb_devpath = "/devices/pci0000:00/usb1/1-3/1-3.1".to_string();
        assert_eq!(
            record_claims(&moved, &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::DifferentCamera),
            "a devpath names a port; a record from another port is not this camera's"
        );
    }

    #[test]
    fn a_recorded_serial_the_camera_cannot_reproduce_fails_closed() {
        let id = identity();
        let mut with_serial = record_for(&id);
        with_serial.serial = Some("200901010001".to_string());
        assert_eq!(
            record_claims(&with_serial, &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::DifferentCamera),
            "the record was written with a discriminator this camera cannot currently show"
        );
    }

    #[test]
    fn schema_and_malformed_records_never_authorize() {
        let id = identity();
        let mut newer = record_for(&id);
        newer.schema_version = 2;
        assert_eq!(
            record_claims(&newer, &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::UnsupportedSchema { found: 2 })
        );
        let mut zero = record_for(&id);
        zero.schema_version = 0;
        assert!(
            matches!(
                record_claims(&zero, &id, 4, 6, &[1, 3, 2]),
                Err(ClaimRefusal::UnsupportedSchema { found: 0 })
            ),
            "equality, not an upper bound: schema 0 is not a schema this build wrote"
        );
        let mut badhex = record_for(&id);
        badhex.displaced = "01030".into();
        assert!(matches!(
            record_claims(&badhex, &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::Malformed(_))
        ));
        let mut wrong_usb = record_for(&id);
        wrong_usb.usb_id = "ffff:0000".into();
        assert!(matches!(
            record_claims(&wrong_usb, &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::Malformed(_))
        ));
        let mut same = record_for(&id);
        same.displaced = same.applied.clone();
        assert!(
            matches!(
                record_claims(&same, &id, 4, 6, &[1, 3, 2]),
                Err(ClaimRefusal::Malformed(_))
            ),
            "the tail never writes a value over itself, so this record is not the tail's"
        );
    }

    #[test]
    fn another_control_or_moved_bytes_are_not_this_streams_business() {
        let id = identity();
        assert_eq!(
            record_claims(&record_for(&id), &id, 14, 6, &[1, 3, 2]),
            Err(ClaimRefusal::DifferentControl {
                unit: 4,
                selector: 6
            })
        );
        assert_eq!(
            record_claims(&record_for(&id), &id, 4, 6, &[9, 9, 9]),
            Err(ClaimRefusal::Superseded),
            "the control is not holding what was applied, so the leftover is already gone"
        );
    }

    #[test]
    fn the_attempt_limit_refuses_the_fourth_claim() {
        let id = identity();
        let mut spent = record_for(&id);
        spent.restore_attempts = MAX_RESTORE_ATTEMPTS;
        assert_eq!(
            record_claims(&spent, &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::OutOfAttempts {
                attempts: MAX_RESTORE_ATTEMPTS
            })
        );
    }
}
