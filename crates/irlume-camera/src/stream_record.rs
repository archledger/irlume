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
//! goes on disk immediately before the `SET_CUR` and is removed once the guard
//! resolves, so a value found already in place is irlume's own leftover
//! exactly when a CONFIRMED record for this camera, this control and these
//! bytes exists.
//!
//! # Two phases, because the record precedes the write
//!
//! A record written before the `SET_CUR` describes a write that may never
//! happen: a kill in the gap leaves the file with no hardware effect behind
//! it. If that file could authorise a claim, a value some other program set
//! LATER, matching the bytes irlume once intended, would be "restored" over —
//! a firmware write on the strength of nothing (review of this PR, round 1).
//! So the record is published as `prepared`, and rewritten as `applied` only
//! after the camera accepts the write. Claims require `applied`. A crash
//! between the write and the confirmation leaves an unclaimable leftover,
//! which is the pre-#188 status quo and the safe direction.
//!
//! # One writer at a time, on a lock that never moves
//!
//! Every mutation of the record happens holding a per-camera LOCK FILE that is
//! created once and never renamed or removed. The lock cannot ride the record
//! itself: `flock` binds to the open file description, and replacing the
//! pathname by rename leaves the old lock attached to a nameless inode while
//! a second writer locks a fresh one — two live "exclusive" locks, no
//! exclusion (same review round). The stable inode gives the lock one
//! identity for everyone. It is held for the guard's whole lifetime, released
//! by any death, so it is also the liveness signal: a claim that cannot take
//! it is looking at a live stream's record and refuses. No pid or boot id is
//! stored; #183 removed those from the journal after one stranded a record.
//!
//! The lock serialises IRLUME's writers only. A non-cooperating process can
//! still move the control between irlume's `GET_CUR` and `SET_CUR`; UVC has
//! no compare-and-swap, so that window cannot be closed from here.
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
/// makes are ORDERINGS — record on disk before the `SET_CUR`, confirmed after
/// it, resolved only after the restore — and on hardware the only way to
/// observe them is to put the events into the same transcript as the writes,
/// in order. An strace of `write(2)` then shows both interleaved (pt190).
fn trace(event: &str) {
    if std::env::var_os("IRLUME_LOG_EMITTER_WRITES").is_some() {
        eprintln!("irlume: stream-record {event}");
    }
}

/// How far the write this record covers actually got.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WriteState {
    /// Published before the `SET_CUR`. The write may never have happened, so
    /// this state authorises NOTHING; it exists so a crash after the write
    /// cannot be unrecorded, not so a crash before it can forge ownership.
    Prepared,
    /// The camera accepted the `SET_CUR`. Only this state makes a leftover
    /// irlume's to undo.
    Applied,
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
    /// Whether the write this record covers is known to have reached the
    /// camera. REQUIRED, no default: a record that cannot say is a record
    /// that must not authorise.
    pub(crate) state: WriteState,
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

/// This camera's lock path: the stable inode every writer and claimer locks.
///
/// Beside the record, one per camera, created on first use and never renamed
/// or removed — removing a lock file hands the next opener a different inode
/// and two "exclusive" locks. The store directory is root-only, so the lock
/// is too.
fn lock_path(id: &CameraIdentity) -> PathBuf {
    store_dir().join(format!("{}.lock", filing_key(id)))
}

/// The per-camera stream lock, held from before the control is read until the
/// guard resolves.
///
/// Released by ANY process death, which makes it the liveness signal for the
/// record beside it. Excludes irlume's own writers only; see the module doc.
#[derive(Debug)]
pub(crate) struct StreamLock {
    /// Held, never read: the open file description IS the lock, released
    /// when this drops however the process ends.
    _file: std::fs::File,
}

/// Why the stream lock was not acquired. The two answers demand OPPOSITE
/// responses, and collapsing them was review round 4's finding: a busy lock
/// is a LIVE irlume writer whose restore bookkeeping a second, unrecorded
/// write would silently invalidate, so the write must be refused; an
/// unavailable store is machine trouble with nobody contesting the camera,
/// where refusing would turn a full disk into dark IR at every login.
#[derive(Debug)]
pub(crate) enum AcquireError {
    /// Another live irlume guard holds this camera's lock.
    Busy,
    /// The lock could not be created, opened or taken for a reason other
    /// than contention.
    Unavailable(String),
}

/// Take this camera's stream lock, or say why not.
///
/// `Busy` means another live irlume guard owns this camera right now —
/// another process mid-capture, or this process's own previous guard
/// (`flock` excludes per open file description, so a second open in the same
/// process is refused too).
pub(crate) fn acquire(id: &CameraIdentity) -> Result<StreamLock, AcquireError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::io::AsRawFd as _;

    let dir = store_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| AcquireError::Unavailable(format!("create {}: {e}", dir.display())))?;
    irlume_common::restrict(&dir, 0o700).map_err(AcquireError::Unavailable)?;
    let path = lock_path(id);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|e| AcquireError::Unavailable(format!("open {}: {e}", path.display())))?;
    // SAFETY: the fd is owned by `file`, which the returned guard keeps open.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::EWOULDBLOCK) => Err(AcquireError::Busy),
            _ => Err(AcquireError::Unavailable(format!(
                "lock {}: {e}",
                path.display()
            ))),
        };
    }
    Ok(StreamLock { _file: file })
}

/// A live record: the file on disk, its parsed contents, and the stream lock
/// that marks its writer as alive. Held by the stream guard while armed.
///
/// Dropping this WITHOUT [`resolve`](StreamRecord::resolve) keeps the file and
/// releases the lock, which is exactly the crash shape on purpose: a restore
/// that failed leaves the leftover real, so the record must stay claimable.
#[derive(Debug)]
pub(crate) struct StreamRecord {
    path: PathBuf,
    record: StreamWrite,
    /// Whether this handle came from [`claim`] rather than [`save`]. A
    /// claimed restore spends one counted attempt — persisted inside
    /// [`retire`](Self::retire)'s pre-write publication, not at claim time,
    /// so a bookkeeping failure that prevents the restore from even being
    /// attempted spends nothing (review round 11).
    claimed: bool,
    _lock: StreamLock,
}

impl StreamRecord {
    /// Rewrite the record as `applied`, after the camera accepted the write.
    ///
    /// Also how a record whose RESTORE failed is put back into force: the
    /// leftover is real again, so the record must be claimable again. On
    /// failure the record stays `prepared` on disk: reported, unclaimable,
    /// and the safe direction.
    pub(crate) fn mark_applied(mut self) -> Result<Self, Box<(Self, String)>> {
        self.record.state = WriteState::Applied;
        if let Err(why) = publish(&self.path, &self.record) {
            // The handle comes BACK on failure. Consuming it here dropped the
            // stream lock while the hardware write it covered was still live,
            // and a second irlume could then interleave exactly the way the
            // busy-refusal exists to prevent (review round 5). Boxed for the
            // cold path only.
            self.record.state = WriteState::Prepared;
            return Err(Box::new((self, why)));
        }
        trace("confirmed applied");
        Ok(self)
    }

    /// Rewrite the record as `prepared`, BEFORE the effect it covers is
    /// undone, so it can no longer authorise a restore.
    ///
    /// The unlink in [`resolve`](Self::resolve) can fail — a store gone
    /// read-only is exactly the kind of machine trouble that arrives between
    /// a write and its cleanup — and an `applied` record surviving its own
    /// resolution would later authorise a firmware write over whatever
    /// unrelated value happened to match it (review round 2). Demoting first
    /// means the worst a failed cleanup leaves is inert litter.
    pub(crate) fn retire(mut self) -> Result<Self, Box<(Self, String)>> {
        // Already non-authoritative: a failed post-write confirmation left the
        // record `prepared` in memory and on disk, and rewriting it buys
        // nothing — while a store still broken from that failure would turn
        // the rewrite into a refusal that blocks the RESTORE of a change
        // whose record never authorised anything (review round 10).
        if self.record.state == WriteState::Prepared {
            trace("retired");
            return Ok(self);
        }
        let previous_attempts = self.record.restore_attempts;
        self.record.state = WriteState::Prepared;
        if self.claimed {
            // The claimed attempt is counted HERE, in the same durable step
            // that precedes the restoring write, and not at claim time: a
            // retirement that fails makes no camera request, and spending the
            // budget on bookkeeping failures could exhaust it with zero
            // restores ever attempted (review round 11). Plain add: a claim
            // only arms below MAX_RESTORE_ATTEMPTS, far from overflow.
            self.record.restore_attempts += 1;
        }
        if let Err(why) = publish(&self.path, &self.record) {
            self.record.state = WriteState::Applied;
            self.record.restore_attempts = previous_attempts;
            return Err(Box::new((self, why)));
        }
        trace("retired");
        Ok(self)
    }

    /// Remove a record that [`retire`](Self::retire) has already made
    /// non-authoritative.
    ///
    /// A plain unlink is enough: every writer of this path holds the stable
    /// lock, this handle holds it now, so the record at the name is this
    /// handle's own. A failure is the caller's to report, and costs litter
    /// rather than authority: the record on disk is `prepared`, and a later
    /// write replaces it.
    pub(crate) fn resolve(self) -> Result<(), String> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                trace("resolved");
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                trace("resolved");
                Ok(())
            }
            Err(e) => Err(format!("remove {}: {e}", self.path.display())),
        }
    }
}

/// Serialize and publish a record: temp file, write, rename. The caller holds
/// the stream lock; nothing here locks.
///
/// No fsync anywhere, see the module doc: process death is the requirement,
/// and the page cache meets it.
fn publish(path: &Path, record: &StreamWrite) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

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
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("publish {}: {e}", path.display()));
    }
    Ok(())
}

/// Why a record was not saved. Both failures return the caller's lock: the
/// exclusion must outlive the bookkeeping trouble, or a second irlume takes
/// the camera mid-stream (review round 5).
#[derive(Debug)]
pub(crate) enum SaveError {
    /// An `applied` record for a change that may still be LIVE sits at this
    /// camera's path, and publishing would rename over the only recovery
    /// data it has (review round 5). Same control with the record's applied
    /// bytes still in the control, or a DIFFERENT control whose state this
    /// write cannot see: either way, nothing is written and nothing is
    /// destroyed.
    /// The lock is NOT returned here: the caller refuses the write, so there
    /// is no change for the exclusion to outlive, and releasing it lets the
    /// control's own next capture claim the outstanding record.
    Outstanding { unit: u8, selector: u8 },
    /// The existing record cannot be REASONED ABOUT — an unsupported schema,
    /// an unparseable body — or is `prepared` for a change this write cannot
    /// prove absent. Not authorising a claim does not license destroying it:
    /// a `prepared` record's write may have SUCCEEDED (a crash between the
    /// `SET_CUR` and the confirmation), and its displaced value is then the
    /// only route back (review round 7). The caller refuses the write; the
    /// lock is dropped, nothing is written, nothing is destroyed.
    Protected { why: String },
    /// The store could not take the record for a reason other than the two
    /// above: an unreadable existing file, an unwritable directory, a failed
    /// rename. The caller proceeds unrecorded, still holding the lock.
    Unavailable { lock: StreamLock, why: String },
}

/// Put the `prepared` record for this stream's write on disk, BEFORE the
/// write, under the lock the caller acquired.
///
/// `displaced` is what the target control holds right now, which doubles as
/// the liveness probe for an existing SAME-control record: an applied record
/// whose bytes are still in the control describes irlume's own live leftover,
/// and renaming over it would destroy the only route back. A record for a
/// DIFFERENT control cannot be probed from here at all, so it is never
/// replaced. The ONLY record replaced is one demonstrably superseded on this
/// same control: its applied bytes are no longer what the control holds. A
/// `prepared` record authorises no claim, and is still protected wherever
/// its write may have landed — see the gate below and review rounds 7 and 11.
pub(crate) fn save(
    lock: StreamLock,
    id: &CameraIdentity,
    unit: u8,
    selector: u8,
    applied: &[u8],
    displaced: &[u8],
) -> Result<StreamRecord, SaveError> {
    let path = record_path(id);
    // What already sits at this camera's path decides whether writing is
    // allowed at all. The ONLY record that may be replaced is one that is
    // demonstrably superseded: same schema, same control, and its applied
    // bytes no longer in the control. Everything else is protected —
    // including `prepared` records, whose write may have succeeded before a
    // crash stopped the confirmation, and schemas this build cannot read
    // (review round 7: "authorises nothing" never meant "may be destroyed").
    match std::fs::read_to_string(&path) {
        Ok(body) => match serde_json::from_str::<StreamWrite>(&body) {
            Ok(existing) => {
                if existing.schema_version != SCHEMA_VERSION {
                    drop(lock);
                    return Err(SaveError::Protected {
                        why: format!(
                            "existing record {} uses schema {} and this build reads \
                             {SCHEMA_VERSION}; not writing over recovery data this build \
                             cannot interpret",
                            path.display(),
                            existing.schema_version
                        ),
                    });
                }
                let superseded = (existing.unit, existing.selector) == (unit, selector)
                    && from_hex(&existing.applied)
                        .map(|bytes| bytes != displaced)
                        .unwrap_or(false);
                if !superseded {
                    drop(lock);
                    return Err(SaveError::Outstanding {
                        unit: existing.unit,
                        selector: existing.selector,
                    });
                }
            }
            Err(e) => {
                // A file that will not parse could be hiding anything,
                // including an applied record. Nothing is written over it.
                drop(lock);
                return Err(SaveError::Protected {
                    why: format!(
                        "existing record {} does not parse ({e}); not writing over it",
                        path.display()
                    ),
                });
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(SaveError::Unavailable {
                lock,
                why: format!("read {}: {e}", path.display()),
            });
        }
    }
    let record = StreamWrite {
        schema_version: SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        descriptor_sha256: fingerprint(id),
        usb_id: id.usb_id(),
        interface_number: id.interface_number,
        unit,
        selector,
        state: WriteState::Prepared,
        applied: to_hex(applied),
        displaced: to_hex(displaced),
        restore_attempts: 0,
        serial: id.serial.clone(),
        usb_devpath: id.usb_devpath.clone(),
    };
    if let Err(why) = publish(&path, &record) {
        return Err(SaveError::Unavailable { lock, why });
    }
    trace(&format!(
        "saved unit{unit}/sel{selector} applied={} displaced={} state=prepared",
        record.applied, record.displaced
    ));
    Ok(StreamRecord {
        path,
        record,
        claimed: false,
        _lock: lock,
    })
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
    /// The record was published before its write and never confirmed after
    /// it, so the write may not have happened at all. A value matching it can
    /// be another program's deliberate choice, and restoring over that would
    /// be a firmware write on the strength of nothing.
    NotConfirmed,
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
    // Before anything else about the camera: a record whose write was never
    // confirmed authorises nothing, whoever it matches.
    if record.state != WriteState::Applied {
        return Err(ClaimRefusal::NotConfirmed);
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
/// own crash leftover. The caller holds the stream lock, which is consumed:
/// into the returned record on success, dropped on refusal.
///
/// `None` is the ordinary answer and means "not irlume's to undo": no record,
/// or a record the pure gate refuses. `Some` arms the caller's guard with the
/// displaced value and hands over the record. The attempt it spends is
/// persisted by `retire`, in the durable step immediately before the write it
/// authorises — not here, where a later bookkeeping failure could leave it
/// spent with no restore ever attempted (review round 11).
pub(crate) fn claim(
    lock: StreamLock,
    id: &CameraIdentity,
    unit: u8,
    selector: u8,
    current: &[u8],
) -> Option<(Vec<u8>, StreamRecord)> {
    let path = record_path(id);
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
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
        // the control lands here at every stream open, and an unconfirmed
        // record is precisely a value that may be somebody else's choice.
        Err(ClaimRefusal::DifferentCamera)
        | Err(ClaimRefusal::DifferentControl { .. })
        | Err(ClaimRefusal::NotConfirmed)
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
    trace(&format!(
        "claimed unit{unit}/sel{selector} displaced={} attempt={}",
        record.displaced,
        record.restore_attempts + 1
    ));
    Some((
        displaced,
        StreamRecord {
            path,
            record,
            claimed: true,
            _lock: lock,
        },
    ))
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
            state: WriteState::Applied,
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

    /// The finding from review round 1: a record published before a write
    /// that never happened must not authorise a restore, however well it
    /// matches. The value it matches may be another program's later choice.
    #[test]
    fn a_prepared_record_never_authorizes_a_claim() {
        let id = identity();
        let mut unconfirmed = record_for(&id);
        unconfirmed.state = WriteState::Prepared;
        assert_eq!(
            record_claims(&unconfirmed, &id, 4, 6, &[1, 3, 2]),
            Err(ClaimRefusal::NotConfirmed),
            "an unconfirmed write may never have reached the camera"
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

    /// A retirement that fails spends nothing (review round 11): the
    /// increment rolls back with the state, and only the successful
    /// pre-write publication carries it to disk.
    #[test]
    fn a_failed_retirement_spends_no_attempt() {
        let _guard = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-sr-rollback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = crate::testenv::EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let id = identity();
        let lock = acquire(&id).expect("the lock is free");
        drop(
            save(lock, &id, 4, 6, &[1, 3, 2], &[1, 3, 1])
                .expect("seed")
                .mark_applied()
                .expect("confirm"),
        );
        let lock = acquire(&id).expect("free again");
        let (_, record) = claim(lock, &id, 4, 6, &[1, 3, 2]).expect("claimable");
        // Break the retirement: the record's own path becomes a directory,
        // so the publishing rename fails while everything else works.
        let store = dir.join("ir-emitter-stream");
        let path = std::fs::read_dir(&store)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .expect("the record file");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let record = match record.retire() {
            Ok(_) => panic!("the broken store must fail the retirement"),
            Err(e) => e.0,
        };
        // Repair, and retire for real: exactly ONE attempt lands, in the
        // successful publication.
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        record
            .retire()
            .expect("the repaired store retires")
            .resolve()
            .expect("resolve");
        // Nothing left: resolve removed the record, and the one attempt it
        // carried went with it — the failed try left no counter behind.
        let survivors = std::fs::read_dir(&store)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .count();
        assert_eq!(survivors, 0, "the retired record resolved cleanly");
        let _ = std::fs::remove_dir_all(&dir);
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
