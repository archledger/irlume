// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A durable record of an exploratory write to camera firmware, so a run that
//! dies between the write and the restore leaves something that says how to put
//! the control back.
//!
//! # The gap this closes
//!
//! `ir_emitter::try_documented_control` reads a control with `GET_CUR`, writes
//! a different value with `SET_CUR`, measures, and writes the original back. The
//! original lived only in a stack `Vec<u8>` for the seconds in between, and two
//! camera measurements sit in that window. A `SIGKILL`, a watchdog, a panic in
//! the decoder or a power loss there left the control changed with no undo data
//! anywhere: not in `ir_emitter.conf`, which stores coordinates and deliberately
//! no payload, and not anywhere else.
//!
//! On the cameras this was measured against a control that is set stays set: one
//! write on a NexiGo N930W held across 120 frames and a stream close. So the
//! damage does not clear itself.
//!
//! # Ordering
//!
//! The record is written and fsynced BEFORE the first `SET_CUR`, and removed
//! only after the control has been read back and found to hold the original
//! again. Both halves matter. Recording after the write leaves the same gap one
//! level down, and removing the record on the strength of a `SET_CUR` that
//! returned success assumes the write landed, which is the assumption that put
//! the camera in this state to begin with.
//!
//! A record that outlives a completed restore is harmless: recovery re-reads the
//! control, finds it already holding the original, and writes nothing.
//!
//! # What this does not prove
//!
//! The record is bound to the camera's USB descriptor blob, which two units of
//! the same model share byte for byte. Swapping one for an identical one between
//! the interrupted run and the recovery would let the recorded bytes be written
//! to the second camera. They are that model's own bytes, read from that model's
//! own control moments earlier, so the exposure is small, but it is not zero and
//! a serial number would not close it either: not every camera publishes one.

use crate::uvc_descriptor::CameraIdentity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The record format this build writes and is willing to act on.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// How many times recovery may write the original back before it stops trying.
///
/// Recovery runs on a path that executes at every capture, and it confirms a
/// restore by reading the control back. A control whose `GET_CUR` does not
/// report what was just written to it would therefore never satisfy the check,
/// and irlume would write to camera firmware on every authentication forever.
/// That is a worse failure than the one being recovered from, so the attempts
/// are counted, durably, and the record is left for a human once they run out.
pub(crate) const MAX_RESTORE_ATTEMPTS: u32 = 3;

/// One control left changed by a run that has not finished putting it back.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingWrite {
    /// Which record format this is. A GATE: a build refuses a record from a
    /// newer schema rather than reading the fields it happens to recognise,
    /// because serde ignores unknown fields and every field here would still
    /// deserialize into a plausible-looking older shape.
    ///
    /// REQUIRED, with no serde default. A default invented schema 1 whenever the
    /// field was absent, which handed the gate its own answer: a record with no
    /// version at all deserialized into a schema-1 record and could authorise a
    /// firmware write. An absent version is precisely "this build cannot know
    /// what this record means", so the parse fails, `load` reports it, and
    /// nothing is acted on. The default existed for records written before the
    /// field, and this feature has never shipped, so there are none.
    pub(crate) schema_version: u32,
    /// Which build wrote the record. Descriptive, not a gate.
    pub(crate) engine_version: String,
    /// Hex sha256 of the camera's USB descriptor blob, and this record's
    /// filename.
    ///
    /// The descriptor is what `override_is_published` and `control_is_documented`
    /// already reason about, so binding the record to it means a record can only
    /// authorise a write to a camera that publishes the same units and
    /// selectors it was written against.
    pub(crate) descriptor_sha256: String,
    /// `vid:pid`, so the file says which camera it is about without hashing
    /// anything. Checked as well as the digest: a record whose two identities
    /// disagree describes no camera that exists.
    pub(crate) usb_id: String,
    pub(crate) interface_number: u8,
    pub(crate) unit: u8,
    pub(crate) selector: u8,
    /// `GET_LEN` for this control when the original was read.
    ///
    /// A restore that writes a different number of bytes than the control holds
    /// is not a restore. Re-checked at recovery rather than trusted, because the
    /// length is a property of the attached camera and this record may have been
    /// written against a different one.
    pub(crate) len: usize,
    /// Hex of what `GET_CUR` answered before the first `SET_CUR`.
    pub(crate) original: String,
    /// Hex of the value the interrupted run was about to write.
    ///
    /// Not needed to restore. It is here so recovery can tell an operator
    /// whether the control is still holding irlume's exploratory value or has
    /// since been moved by something else, which is the difference between "this
    /// is our mess" and "something else is also writing to this control".
    pub(crate) attempted: String,
    /// How many times recovery has written the original back.
    ///
    /// Counted BEFORE each write and made durable before the ioctl. Counting
    /// after would leave the same write-then-record gap the record exists to
    /// close: a kill during the restore would not increment, and the next boot
    /// would try again from zero, forever.
    #[serde(default)]
    pub(crate) restore_attempts: u32,
    /// The boot the record was written in, and the process that wrote it.
    ///
    /// A record is open for the whole of a discovery run, and the capture path
    /// recovers records at every stream open. Without this, a capture running
    /// beside a live `ir-setup` would read that run's open record and restore
    /// the control out from under it, mid-measurement.
    ///
    /// The pair is only ever used to answer "is the writer still running", and
    /// it fails in the safe direction: a reused pid in the same boot makes
    /// recovery wait, and the next boot has a different `boot_id` and acts
    /// unconditionally. Waiting a boot is recoverable; writing to firmware
    /// underneath a live run is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pid: Option<u32>,
    /// The USB serial the camera published, when it published one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) serial: Option<String>,
    /// The sysfs path of the USB device the change was made to.
    ///
    /// The only field that distinguishes two identical units attached at the
    /// same time. Without it the key was the descriptor blob, which two units of
    /// one model share byte for byte: a capture on the second camera would load
    /// the first camera's record, write the first camera's bytes into the
    /// second, and then delete the record on a successful read-back, leaving the
    /// camera that was actually changed with no undo data at all. Reported by
    /// review on #183.
    ///
    /// Empty on records written before this field existed. Those cannot be
    /// confirmed to belong to the camera in front of us, so they are reported
    /// rather than acted on.
    #[serde(default)]
    pub(crate) usb_devpath: String,
}

/// This boot's identifier, or `None` where the kernel does not publish one.
///
/// `None` means the owner check cannot be made, and recovery then acts rather
/// than waiting: a record that is never recovered is the failure this module
/// exists to prevent, and the alternative risk needs a second irlume writing to
/// the same camera at the same moment.
pub(crate) fn current_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Whether the process that opened this record is still running in this boot.
pub(crate) fn owner_still_running(record: &PendingWrite) -> bool {
    let (Some(recorded_boot), Some(pid)) = (record.boot_id.as_deref(), record.pid) else {
        return false;
    };
    if current_boot_id().as_deref() != Some(recorded_boot) {
        return false;
    }
    // `/proc/<pid>` rather than `kill(pid, 0)`: the latter cannot tell a live
    // process owned by somebody else from a dead one without inspecting errno,
    // and this runs as root where that distinction disappears anyway.
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

impl PendingWrite {
    /// The original bytes, or an error naming what is wrong with the record.
    pub(crate) fn original_bytes(&self) -> Result<Vec<u8>, String> {
        from_hex(&self.original).map_err(|e| format!("original: {e}"))
    }
}

/// What the store holds right now, for a report that has no camera open.
///
/// Deliberately does not open a camera or write anything: `doctor` runs on a
/// machine whose camera may be detached, may be in use, and whose operator may
/// have set `IRLUME_IR_EMITTER=off` precisely because they do not want irlume
/// touching it. It counts files and says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingSummary {
    /// The store has no records: nothing was left changed.
    None,
    /// This many cameras have an outstanding change, with the coordinates of
    /// each so an operator can match them against `lsusb`.
    Pending(Vec<String>),
    /// The store could not be listed. Not the same as empty: it is root-only, so
    /// an ordinary `doctor` run lands here, and reporting that as "nothing
    /// pending" would be a clean bill of health nobody checked.
    Unreadable(String),
}

/// Summarise the store without touching any camera.
pub fn pending_summary() -> PendingSummary {
    let dir = store_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return PendingSummary::None,
        Err(e) => return PendingSummary::Unreadable(format!("{}: {e}", dir.display())),
    };
    let mut pending = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => return PendingSummary::Unreadable(format!("{}: {e}", dir.display())),
        };
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        // A record that will not parse is still a record: something is pending
        // and this build cannot read it, which an operator needs told.
        pending.push(match std::fs::read_to_string(&path) {
            Ok(body) => match serde_json::from_str::<PendingWrite>(&body) {
                Ok(record) => format!(
                    "{} unit {} selector {} (original {})",
                    record.usb_id, record.unit, record.selector, record.original
                ),
                Err(e) => format!("{} (unparseable: {e})", path.display()),
            },
            Err(e) => format!("{} (unreadable: {e})", path.display()),
        });
    }
    if pending.is_empty() {
        PendingSummary::None
    } else {
        pending.sort();
        PendingSummary::Pending(pending)
    }
}

/// Trace a journal event onto the same stream `set_cur` traces writes to.
///
/// The ordering claims this module makes — record before the first write,
/// attempt counted before the restore, record dropped only after the read-back —
/// are sequences of side effects, and a test that inspects the filesystem
/// afterwards cannot see any of them: the record's whole job is to be gone by
/// the end. Interleaving these lines with the `SET_CUR` lines makes the order an
/// observation rather than a reading of the control flow.
///
/// `IRLUME_LOG_EMITTER_WRITES` is the same switch, deliberately: someone
/// debugging what irlume sent their camera wants the undo record in the same
/// transcript, in order.
pub(crate) fn trace(event: &str) {
    if std::env::var_os("IRLUME_LOG_EMITTER_WRITES").is_some() {
        eprintln!("irlume: journal {event}");
    }
}

/// Only referenced by a mutation-test variant that reinstates the serde default
/// this type deliberately does not have. Never used in production.
#[cfg(test)]
#[allow(dead_code)]
fn schema_version_one() -> u32 {
    1
}

/// Where journal records live. One file per camera, under the state root.
///
/// A directory rather than a single file because a machine can have more than
/// one IR camera, and an unresolved record for a camera that is not currently
/// attached must survive a run against a different one. A single file would let
/// the second camera's discovery erase the first camera's undo data, which is
/// the exact loss this module exists to prevent.
pub(crate) fn store_dir() -> PathBuf {
    irlume_common::state_dir().join("ir-emitter-journal")
}

/// This camera's record path.
///
/// The filename is the descriptor digest, which `sha256_hex` guarantees is
/// lowercase hex of a fixed length, so no caller-supplied text ever reaches a
/// path component.
pub(crate) fn record_path(descriptor_sha256: &str) -> PathBuf {
    store_dir().join(format!("{descriptor_sha256}.json"))
}

/// The digest of the camera's PUBLISHED DESCRIPTION: model, not unit.
///
/// Two units of one model produce the same value, by construction. That is what
/// makes it the right key for "is this record about a camera like the one in
/// front of me" and the wrong key for "is this record about THIS camera", which
/// is [`filing_key`].
pub(crate) fn fingerprint(id: &CameraIdentity) -> String {
    irlume_common::sha256_hex(&id.descriptors)
}

/// The name a record for this exact camera is filed under.
///
/// Binds the model description to the port and, where the device publishes one,
/// the serial. The descriptor blob alone collided across identical units, so one
/// camera's setup silently replaced another's undo record.
///
/// The parts are length-prefixed rather than concatenated, so a serial ending in
/// what looks like a path cannot produce the same key as a different pairing.
pub(crate) fn filing_key(id: &CameraIdentity) -> String {
    key_of(&fingerprint(id), id.serial.as_deref(), &id.usb_devpath)
}

/// The one place a filing key is built, so a record is always written where a
/// lookup for the same camera will go looking. Two constructions of this would
/// be two chances to file a record somewhere it is never found again, which is
/// the same as not having written it.
fn key_of(descriptor_sha256: &str, serial: Option<&str>, usb_devpath: &str) -> String {
    let serial = serial.unwrap_or("");
    irlume_common::sha256_hex(
        format!(
            "descriptors:{descriptor_sha256}|serial:{}:{serial}|devpath:{}:{usb_devpath}",
            serial.len(),
            usb_devpath.len(),
        )
        .as_bytes(),
    )
}

impl PendingWrite {
    /// Where this record belongs, derived from the record's own fields.
    pub(crate) fn filing_key(&self) -> String {
        key_of(
            &self.descriptor_sha256,
            self.serial.as_deref(),
            &self.usb_devpath,
        )
    }
}

/// Whether this record was written about the camera in front of us, to the
/// standard required to WRITE to that camera.
///
/// This answers the authorisation question, not the "can I find it" question.
/// The two pull in opposite directions and both matter:
///
///   * A record must stay FINDABLE when the serial read fails, or a transient
///     failure hides the only description of an outstanding change. `load`
///     handles that by scanning, so the record is still reported and `doctor`
///     still warns.
///   * A record must not AUTHORISE a firmware write on evidence weaker than the
///     evidence it was written with. A record carrying a serial, matched
///     against a camera whose serial could not be read, is exactly that: the
///     device path names a port, and the kernel is explicit that it is the
///     device's key "at that point in time", not a persistent identity. An
///     identical unit swapped into the same port between the record and the
///     recovery would satisfy descriptor and path alike.
///
/// So a missing current serial fails CLOSED. The record is found, reported and
/// left alone; when the serial reads again it is acted on.
pub(crate) fn describes_this_camera(record: &PendingWrite, id: &CameraIdentity) -> bool {
    identity_authorizes(
        &record.descriptor_sha256,
        &record.usb_devpath,
        record.serial.as_deref(),
        id,
    )
}

/// The authorisation rule itself, over a recorded identity's three parts.
///
/// One construction, shared with the per-stream leftover record (#188), so
/// "which camera may a record act on" cannot drift between the two stores. The
/// rule is [`describes_this_camera`]'s: descriptor digest and device path must
/// match outright, and a recorded serial the attached camera cannot currently
/// reproduce refuses — failing OPEN there would let an identical unit in the
/// same port receive the first camera's bytes.
pub(crate) fn identity_authorizes(
    descriptor_sha256: &str,
    usb_devpath: &str,
    serial: Option<&str>,
    id: &CameraIdentity,
) -> bool {
    if descriptor_sha256 != fingerprint(id) {
        return false;
    }
    if usb_devpath.is_empty() || usb_devpath != id.usb_devpath {
        return false;
    }
    match (serial, id.serial.as_deref()) {
        (Some(recorded), Some(attached)) => recorded == attached,
        // The record was written with a discriminator this observation cannot
        // reproduce. Throwing that away and writing anyway is the one direction
        // that cannot be taken back.
        (Some(_), None) => false,
        // Nothing to compare: the record was written for a camera that
        // published no serial, which is the ordinary case on the module this
        // was developed against.
        (None, _) => true,
    }
}

/// Why a record cannot be acted on against the camera in front of us.
///
/// Separated rather than collapsed to a bool because they call for different
/// responses: a record for another camera is normal on a machine with two of
/// them and must be left alone, while a record whose unit is no longer published
/// means the record and the camera disagree about what exists and nobody should
/// write anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mismatch {
    /// Written for a different camera. Leave it where it is.
    DifferentCamera,
    /// Written to a schema this build does not implement, in either direction.
    UnsupportedSchema { found: u32, supported: u32 },
    /// The record's own two identities disagree, or a field will not parse.
    Malformed(String),
    /// The camera no longer publishes the unit or advertises the selector the
    /// record names.
    ControlNotPublished,
    /// Recovery has already written the original back this many times without
    /// the control reading back as restored.
    OutOfAttempts { attempts: u32 },
    /// The run that opened this record is still going. Its control is supposed
    /// to be changed right now.
    OwnerStillRunning { pid: u32 },
}

/// Whether this record describes the camera in front of us, and may be acted on.
///
/// Pure, so the decision can be tested without a camera. Every check that gates
/// a firmware write lives here rather than in the ioctl wrapper.
pub(crate) fn record_applies(record: &PendingWrite, id: &CameraIdentity) -> Result<(), Mismatch> {
    // Equality, not an upper bound. `> SCHEMA_VERSION` let schema 0 through, and
    // there is no schema 0: a corrupted or hand-repaired record carrying one
    // would have passed every remaining check and authorised a firmware write.
    // A record this build cannot read is a record this build must not act on,
    // whichever side of the version it falls.
    if record.schema_version != SCHEMA_VERSION {
        return Err(Mismatch::UnsupportedSchema {
            found: record.schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    if record.descriptor_sha256 != fingerprint(id) {
        return Err(Mismatch::DifferentCamera);
    }
    // The digest already pins the descriptors, and these fields come from the
    // same sysfs read, so a disagreement means the record was assembled from two
    // different cameras or edited by hand. Either way it is not a description of
    // anything, and it must not authorise a write.
    if record.usb_id != id.usb_id() || record.interface_number != id.interface_number {
        return Err(Mismatch::Malformed(format!(
            "record says {} interface {}, camera is {} interface {}",
            record.usb_id,
            record.interface_number,
            id.usb_id(),
            id.interface_number
        )));
    }
    let original = record.original_bytes().map_err(Mismatch::Malformed)?;
    if original.len() != record.len {
        return Err(Mismatch::Malformed(format!(
            "record holds {} original bytes for a control it says is {} long",
            original.len(),
            record.len
        )));
    }
    // The same descriptor gate every other write in this crate passes. A record
    // cannot be a way around it.
    match id.microsoft_xu() {
        Some(ms) if ms.unit_id == record.unit && ms.advertises(record.selector) => {}
        _ => return Err(Mismatch::ControlNotPublished),
    }
    if record.restore_attempts >= MAX_RESTORE_ATTEMPTS {
        return Err(Mismatch::OutOfAttempts {
            attempts: record.restore_attempts,
        });
    }
    // Last, so a record that is malformed or names a control this camera does
    // not publish is reported as that rather than as somebody else's business.
    if owner_still_running(record) {
        return Err(Mismatch::OwnerStillRunning {
            pid: record.pid.unwrap_or_default(),
        });
    }
    Ok(())
}

/// What the control reports right now, gathered before deciding anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlNow {
    /// `GET_LEN` as the attached camera reports it.
    pub(crate) len: usize,
    /// Whether `GET_INFO` still permits a write.
    pub(crate) writable: bool,
    /// `GET_CUR`.
    pub(crate) current: Vec<u8>,
}

/// What recovery should do about a control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Restore {
    /// The control already holds the original. Resolve the record, write
    /// nothing. This is the expected outcome of a kill that landed after the
    /// restore but before the record was removed.
    AlreadyRestored,
    /// Write these bytes back.
    Write(Vec<u8>),
    /// Touch nothing, and say why.
    Refuse(String),
}

/// Decide from the record and what the control reports, without touching it.
///
/// Pure for the same reason `record_applies` is: this is the decision, and a
/// decision that only exists inside a sequence of ioctls cannot be tested
/// anywhere but on hardware.
pub(crate) fn restore_decision(record: &PendingWrite, now: &ControlNow) -> Restore {
    let original = match record.original_bytes() {
        Ok(bytes) => bytes,
        Err(why) => return Restore::Refuse(why),
    };
    // The control's length is the attached camera's answer, not the record's.
    // A record written against a control of a different width would otherwise
    // send a short or long payload to firmware.
    if now.len != record.len {
        return Restore::Refuse(format!(
            "the control is {} bytes now and was {} when the value was recorded, \
             so the recorded bytes are not this control's value",
            now.len, record.len
        ));
    }
    if now.current == original {
        return Restore::AlreadyRestored;
    }
    // The control must be holding THIS run's exploratory value, or there is no
    // basis for writing anything.
    //
    // `attempted` was recorded from the start and, until review pointed it out,
    // never read: any value other than the original was taken as proof that
    // irlume's write was still live. The per-camera lock excludes other irlume
    // processes and nothing else, so a vendor tool, a driver action or an
    // operator could have set this control between the interruption and now, and
    // recovery would have silently overwritten a state it did not create. A
    // record cannot authorise undoing somebody else's change.
    let attempted = match from_hex(&record.attempted) {
        Ok(bytes) => bytes,
        Err(why) => return Restore::Refuse(format!("attempted: {why}")),
    };
    if now.current != attempted {
        return Restore::Refuse(format!(
            "the control holds {:02x?}, which is neither the value this run wrote \
             ({attempted:02x?}) nor the one it recorded ({original:02x?}), so something \
             else has changed it since",
            now.current
        ));
    }
    if !now.writable {
        return Restore::Refuse(
            "the camera reports it does not accept a write to this control right now".into(),
        );
    }
    Restore::Write(original)
}

/// Held for the whole of a recovery pass or a discovery run, so no other
/// process can act on the same camera's record in between.
#[derive(Debug)]
pub(crate) struct CameraLock {
    _file: std::fs::File,
}

/// The lock path, for tests in sibling modules that must hold the same lock the
/// daemon does rather than rebuild its name.
#[cfg(test)]
pub(crate) fn lock_path_for_test(id: &CameraIdentity) -> PathBuf {
    lock_path(id)
}

/// One camera at one physical address, for the purpose of EXCLUDING a second
/// writer. Deliberately not [`filing_key`].
///
/// The serial is excluded because `identity_from_fd` maps every failure to read
/// the sysfs `serial` file to absence. A key that changes when a read
/// transiently fails is fine for a filename — the lookup falls back to scanning
/// the store — but it is fatal for a lock: two processes opening the same camera
/// with different serial-read outcomes would take DIFFERENT lock files, both
/// `flock` calls would succeed, and both would go on to drive the same control.
/// `flock` excludes on the open file description, so two names are two locks.
///
/// The descriptor pins the model and the device path pins which attached unit of
/// that model this is. Neither can quietly become unavailable the way the serial
/// can.
fn synchronization_key(id: &CameraIdentity) -> String {
    irlume_common::sha256_hex(
        format!(
            "descriptors:{}|devpath:{}:{}",
            fingerprint(id),
            id.usb_devpath.len(),
            id.usb_devpath
        )
        .as_bytes(),
    )
}

/// Where a camera's lock file lives.
///
/// `/run/lock`, not beside the records, for the same reason `pamwire` puts its
/// lock there: a lock's lifetime is a boot, not the machine's. Under the store it
/// would create `/var/lib/irlume/ir-emitter-journal/` on every machine that ever
/// opens a camera, including the overwhelming majority that never run `ir-setup`
/// and have nothing to record, and leave a lock file behind for each camera
/// forever. `IRLUME_EMITTER_LOCK_DIR` moves it for tests and containers.
fn lock_path(id: &CameraIdentity) -> PathBuf {
    std::env::var_os("IRLUME_EMITTER_LOCK_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock"))
        .join(format!("irlume-emitter-{}.lock", synchronization_key(id)))
}

/// Take this camera's lock, or report that somebody else holds it.
///
/// Reading a record and acting on it is a check and an act with a long window
/// between: `GET_LEN`, `GET_INFO`, `GET_CUR`, the attempt counter, `SET_CUR`,
/// the read-back, and only then the removal. Nothing re-read the record at the
/// end, so a second process that resolved that record, started its own setup and
/// saved a NEW record at the same name would have it deleted by the first
/// process finishing — and its exploratory value would then be live with no undo
/// data at all. That is the loss this whole module exists to prevent, arriving
/// through the module itself.
///
/// The pid and boot id in a record narrow the window; they do not close it. They
/// describe the record that happened to be loaded before the window opened.
/// `flock` is kernel-enforced, covers the whole operation, and is released
/// however the process exits, so a killed irlume strands nothing.
///
/// NON-BLOCKING on purpose. This is taken on the capture path, which runs at
/// every stream open during authentication; waiting behind a discovery run that
/// takes tens of seconds would stall a login. A camera whose lock is held is a
/// camera somebody else is already looking after.
pub(crate) fn lock_camera(id: &CameraIdentity) -> Result<Option<CameraLock>, String> {
    use std::os::unix::io::AsRawFd as _;
    let path = lock_path(id);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    // /dev/video* is root:video 0660, so the lock guarding that capability
    // matches rather than being root-only. Without this a non-root caller in
    // the video group (the nightly CI runner, ir-setup, camera-tune) can open
    // the camera but not the lock, and ir-setup declines to drive the emitter
    // with "passwordless sudo is required" even though the caller already owns
    // the device it is trying to configure.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = file
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .permissions();
        // Fix the mode only when it is wrong AND this process can: fchmod on
        // a root-owned file from a non-root caller is EPERM no matter what
        // mode is requested, and failing the LOCK on it disabled the emitter
        // for exactly the caller #392 exists to serve (the lock already
        // exists as root:video 0660 after the daemon's first run, the video
        // group member opens it through the group bit, and then the
        // unconditional chmod errored). A wrong mode that cannot be fixed is
        // reported by whoever cannot OPEN the file, with a better message
        // than EPERM here.
        if perms.mode() & 0o777 != 0o660 {
            perms.set_mode(0o660);
            if let Err(e) = file.set_permissions(perms) {
                irlume_common::dlog!(
                    "emitter lock {}: mode left as-is ({e}); a non-owner cannot chmod",
                    path.display()
                );
            }
        }
    }
    // Set the group to video so the lock is reachable by the same group that
    // already owns /dev/video*. The caller is root (the daemon), so fchown
    // succeeds. If the group does not exist on this system the mode alone is
    // still an improvement: the lock was 0640 root:root and is now 0660, so a
    // non-root caller whose primary group is video can open it.
    //
    // SAFETY: getgrnam_r reads /etc/group (or the nsswitch equivalent). The
    // C string is a literal null-terminated byte string.
    unsafe {
        let mut grp: libc::group = std::mem::zeroed();
        let mut buf = vec![0u8; 2048];
        let mut result: *mut libc::group = std::ptr::null_mut();
        let name = b"video\0";
        if libc::getgrnam_r(
            name.as_ptr().cast(),
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        ) == 0
            && !result.is_null()
        {
            let _ = libc::fchown(file.as_raw_fd(), u32::MAX, grp.gr_gid);
        }
    }
    // SAFETY: `fd` is owned by `file`, which outlives the call and the guard.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        return match err.kind() {
            std::io::ErrorKind::WouldBlock => Ok(None),
            _ => Err(format!("lock {}: {err}", path.display())),
        };
    }
    Ok(Some(CameraLock { _file: file }))
}

/// What the store has to say about the camera in front of us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Situation {
    /// Nothing about this camera or anything like it.
    Nothing,
    /// A record written about THIS camera: same model, same port, and the same
    /// serial where both sides publish one.
    ///
    /// Carries the path it was actually found at, because that is what has to be
    /// removed when it is resolved. `SameModelElsewhere` needs no path: it is
    /// reported and never cleared.
    Mine {
        path: PathBuf,
        record: Box<PendingWrite>,
    },
    /// A record about a camera of the SAME MODEL at a different port, or one
    /// written before records carried a port at all.
    ///
    /// Kept apart from `Mine` because the bytes in it were read from a control
    /// on some other unit, or on this one at a time we cannot confirm. Writing
    /// them here would be guessing, and clearing the record afterwards would
    /// destroy the only description of a change that is still outstanding
    /// somewhere. Reported, never acted on.
    SameModelElsewhere(Box<PendingWrite>),
}

/// Classify the store against this camera.
///
/// The exact record is tried first, by name, so the ordinary case costs one
/// failed open. Only when that misses is the directory scanned, which is what
/// finds a same-model record filed under a different port.
///
/// An unreadable record that exists is an error rather than "no record":
/// treating a permission or IO failure as absence would silently drop the one
/// description of how to undo a firmware write.
pub(crate) fn load(id: &CameraIdentity) -> Result<Situation, String> {
    // The filename is a fast path, never the authority. Two things make it
    // unreliable on its own, and both were found by review:
    //
    //   * It is derived from the serial, and `identity_from_fd` maps EVERY
    //     failure to read the sysfs `serial` file to `None`. One transient read
    //     failure changes the key, the exact lookup misses, and a record that
    //     describes this camera perfectly well by descriptor and device path
    //     would have been dismissed as another camera's — leaving the camera
    //     changed and its emitter disabled, which is the opposite of the point.
    //   * A record could be sitting under this name without describing this
    //     camera at all.
    //
    // So a MISS falls through and the scan below decides. A hit is still checked,
    // but a hit that fails the check is an error, not a fall-through: the name is
    // built from the very fields being compared, so contents that disagree at
    // this path mean the file was damaged, and continuing to the scan let it drop
    // out as "nothing pending" while a firmware change was still outstanding.
    let path = record_path(&filing_key(id));
    match std::fs::read_to_string(&path) {
        Ok(body) => {
            let record: PendingWrite = serde_json::from_str(&body)
                .map_err(|e| format!("parse {}: {e}", path.display()))?;
            if !describes_this_camera(&record, id) {
                // Filed under THIS camera's key, yet its contents say otherwise.
                // The key is built from the fingerprint, serial and device path,
                // so a record that legitimately belongs to another camera lands
                // under another name; arriving here means the file was damaged
                // or edited. Falling through was fail-open: the scan drops it on
                // the same mismatch, `load` answers `Nothing`, and the capture
                // path takes that as licence to write to the camera while an
                // unresolved change may still be outstanding. An existing record
                // is never absence, which is the rule the unparseable and
                // unreadable cases already follow.
                return Err(format!(
                    "{} is filed under this camera's exact journal key but its contents \
                     describe a different camera; refusing to treat the store as empty",
                    path.display()
                ));
            }
            return Ok(Situation::Mine {
                path,
                record: Box::new(record),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    }

    // EVERY same-model record is examined, not the first one `read_dir` happens
    // to hand back. Directory order is unspecified, so stopping at the first
    // match could report another camera's record while this camera's own record
    // sat further down the list.
    let model = fingerprint(id);
    let mut elsewhere = None;
    for (found_at, record) in all_records()? {
        if record.descriptor_sha256 != model {
            continue;
        }
        if describes_this_camera(&record, id) {
            // The path it was FOUND at, not one derived from it: a record is not
            // necessarily filed under the name its own fields produce.
            return Ok(Situation::Mine {
                path: found_at,
                record: Box::new(record),
            });
        }
        if elsewhere.is_none() {
            elsewhere = Some(record);
        }
    }
    Ok(match elsewhere {
        Some(record) => Situation::SameModelElsewhere(Box::new(record)),
        None => Situation::Nothing,
    })
}

/// Every parseable record in the store.
///
/// A record that will not parse is an error rather than a skip: something is
/// pending, this build cannot read it, and continuing as though the store were
/// empty is how an outstanding firmware change gets reported as clean.
fn all_records() -> Result<Vec<(PathBuf, PendingWrite)>, String> {
    let dir = store_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("list {}: {e}", dir.display())),
    };
    let mut records = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("list {}: {e}", dir.display()))?
            .path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let body =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let record =
            serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
        records.push((path, record));
    }
    Ok(records)
}

/// Write a record and make it durable before the caller touches the camera.
///
/// The directory chain above the store is fsynced too, unconditionally. On a
/// fresh install the store's own entry is still only in its parent's page cache,
/// so a record fsynced into it would be fsynced into a directory that does not
/// come back, and the firmware write happens seconds later. Every way of
/// narrowing that (skip it when the directory already exists, sync only the
/// levels that were missing) is a check-then-act on shared state: a second
/// process finds the directory present and inherits a guarantee nobody has made.
/// `ir-setup` is a person running a command, not a hot path.
/// DURABLE, or this is an error. The initial record's durability IS the
/// authorization for the first firmware write, so "the rename landed but the
/// directory fsync failed" must not open discovery: the entry can still be lost,
/// and losing it after the camera has been written recreates the whole defect
/// this module exists to prevent. Only the attempt COUNTER may treat a visible
/// record as good enough, because there the question is whether a later reader
/// sees the higher number, not whether the machine may be cut.
///
/// The visible record is deliberately left where it is. No camera write has
/// happened, so a later run finds the control already holding `original` and
/// drops the record without touching anything.
pub(crate) fn save(record: &PendingWrite) -> Result<PathBuf, String> {
    let (path, durability) = save_at(&record_path(&record.filing_key()), record)?;
    require_durable(path, durability)
}

/// The decision itself, separated from the write that produces it.
///
/// Nothing available here can make a directory `fsync` fail, so a test that goes
/// through `save` cannot reach the rejecting arm and a mutant deleting it
/// survives. `AtomicWrite` is a value, so the decision made ABOUT that value can
/// be exercised directly even when the condition producing it cannot be staged.
fn require_durable(
    path: PathBuf,
    durability: irlume_common::AtomicWrite,
) -> Result<PathBuf, String> {
    match durability {
        irlume_common::AtomicWrite::Durable => Ok(path),
        irlume_common::AtomicWrite::VisibleNotDurable(e) => Err(format!(
            "write {}: the undo record became visible but could not be made durable: {e}",
            path.display()
        )),
    }
}

/// Write a record to a PARTICULAR path.
///
/// Recovery uses this to rewrite a record it found by scanning. `save` derives
/// the name from the contents, and a scanned record need not be filed under the
/// name its contents produce, so counting an attempt through `save` wrote the
/// incremented record to a second file and left the first one behind — two
/// records for one operation, and the clear afterwards removed only one.
pub(crate) fn save_at(
    path: &std::path::Path,
    record: &PendingWrite,
) -> Result<(PathBuf, irlume_common::AtomicWrite), String> {
    let dir = store_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    irlume_common::restrict(&dir, 0o700)?;
    irlume_common::fsync_ancestors(&dir)?;
    let path = path.to_path_buf();
    let body = serde_json::to_string(record).map_err(|e| format!("serialize record: {e}"))?;
    // The reporting variant, because an error after the rename does NOT mean the
    // record is absent. A caller that treats "save failed" as "nothing is on
    // disk" spends an attempt it never made, or leaves a record it thinks it
    // never wrote — both have happened here.
    let durability = irlume_common::write_atomic_reporting(&path, body.as_bytes(), 0o600)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    // After the fsyncs, and it says which outcome it got rather than asserting
    // one: the ordering depends on the record being DURABLE before the firmware
    // write, so a transcript that cannot distinguish "durable" from "published,
    // might not survive a power cut" cannot establish the thing it is read for.
    trace(&format!(
        "saved unit{}/sel{} original={} attempts={} ({})",
        record.unit,
        record.selector,
        record.original,
        record.restore_attempts,
        match &durability {
            irlume_common::AtomicWrite::Durable => "durable",
            irlume_common::AtomicWrite::VisibleNotDurable(_) => "visible, not durable",
        }
    ));
    Ok((path, durability))
}

/// Remove a record whose control is confirmed back where it was found.
///
/// Takes the PATH the record was read from or written to, never a path derived
/// from its contents. Deriving it looked equivalent and was not: a record found
/// by scanning the store is not necessarily filed under the name its own fields
/// produce — one written by a build with a different key derivation, or planted
/// by hand, or left behind by a rename that failed after publication. Removing
/// the derived name then deletes nothing, and the record warns forever while
/// looking resolved to the code that "cleared" it.
pub(crate) fn clear(path: &std::path::Path) -> Result<(), String> {
    irlume_common::remove_durable(path)?;
    trace("cleared");
    Ok(())
}

/// Lowercase hex, the encoding the record stores control bytes in.
///
/// Hex rather than serde's byte array so the file stays readable by a person
/// recovering a camera by hand, which is the situation the record is for.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Strict inverse of [`to_hex`].
///
/// Every failure is an error, never a shorter payload. A lenient decode that
/// skipped unparseable pairs would turn a corrupted record into a different,
/// well-formed write to camera firmware, which is the same defect that made
/// `parse_control` drop bad fields out of an override.
pub(crate) fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!(
            "{} hex digits is not a whole number of bytes",
            text.len()
        ));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let text = std::str::from_utf8(pair).map_err(|_| "not ascii hex".to_string())?;
        // `from_str_radix` accepts a leading `+` and unicode digits; the explicit
        // ascii check keeps the accepted set to exactly what `to_hex` emits.
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("'{text}' is not two hex digits"));
        }
        out.push(u8::from_str_radix(text, 16).map_err(|e| format!("'{text}': {e}"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testenv::{env_lock, EnvGuard};

    /// #392's own caller: the lock already exists as root:video 0660 from the
    /// daemon's first run, and a non-root video-group member opens it through
    /// the group bit. The unconditional `fchmod` then answered EPERM (a
    /// non-owner cannot chmod, whatever mode it asks for), `lock_camera`
    /// failed, and the emitter went dark for exactly the caller the change
    /// was written for. The lock must succeed on a pre-existing lock this
    /// process can open but cannot chmod.
    ///
    /// Ignored because the scenario needs a file owned by ANOTHER uid, which
    /// a test cannot create; scripts/ orchestration (or a by-hand sudo) sets
    /// IRLUME_EMITTER_LOCK_DIR and pre-creates the file as root. The test
    /// PANICS rather than self-skips when the setup is absent: running an
    /// ignored test is a request for the harness (#361).
    #[test]
    #[ignore = "needs a root-owned pre-created lock; set IRLUME_EMITTER_LOCK_DIR and pre-create the lock file as root:<caller-group> 0660"]
    fn lock_succeeds_on_a_preexisting_lock_this_process_cannot_chmod() {
        use std::os::unix::fs::MetadataExt as _;
        let _env = env_lock();
        let dir = std::env::var_os("IRLUME_EMITTER_LOCK_DIR")
            .expect("IRLUME_EMITTER_LOCK_DIR is unset; this test is a request for the harness");
        let id = identity();
        let path = std::path::PathBuf::from(&dir)
            .join(format!("irlume-emitter-{}.lock", synchronization_key(&id)));
        let meta = std::fs::metadata(&path).expect("the harness pre-creates the lock file");
        // SAFETY: geteuid reads this process's own credentials and cannot fail.
        let me = unsafe { libc::geteuid() };
        assert_ne!(
            meta.uid(),
            me,
            "the pre-created lock must belong to another uid or this test proves nothing"
        );
        let lock = lock_camera(&id).expect("a lock this process can open must be takeable");
        assert!(lock.is_some(), "nobody else holds it in this harness");
    }

    /// A camera identity backed by the real ASUS descriptor bytes, so these
    /// exercise the same parsing path production uses.
    fn identity() -> CameraIdentity {
        CameraIdentity {
            descriptors: include_bytes!("../tests/fixtures/asus-3277-0059.descriptors").to_vec(),
            interface_number: 2,
            vid: 0x3277,
            pid: 0x0059,
            // The real values this module was developed against. The serial is
            // deliberately the batch-looking one the ASUS module actually
            // reports, so nothing here can quietly assume a serial is unique.
            serial: Some("200901010001".into()),
            usb_devpath: "/devices/pci0000:00/0000:00:14.0/usb3/3-5".into(),
        }
    }

    /// The same MODEL at a different port: byte-identical descriptors, the same
    /// serial, a different physical address. This is the pair the descriptor
    /// digest could not tell apart.
    fn identical_unit_elsewhere() -> CameraIdentity {
        CameraIdentity {
            usb_devpath: "/devices/pci0000:00/0000:00:14.0/usb3/3-2".into(),
            ..identity()
        }
    }

    /// The Microsoft unit and a selector the fixture really advertises, so a
    /// record built here would pass the descriptor gate for the right reason.
    fn published_control(id: &CameraIdentity) -> (u8, u8) {
        let ms = id.microsoft_xu().expect("fixture publishes a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises one of the two emitter selectors");
        (ms.unit_id, selector)
    }

    fn record_for(id: &CameraIdentity) -> PendingWrite {
        let (unit, selector) = published_control(id);
        PendingWrite {
            schema_version: SCHEMA_VERSION,
            engine_version: "test".into(),
            descriptor_sha256: fingerprint(id),
            usb_id: id.usb_id(),
            interface_number: id.interface_number,
            unit,
            selector,
            len: 3,
            original: to_hex(&[1, 3, 1]),
            attempted: to_hex(&[1, 3, 2]),
            restore_attempts: 0,
            boot_id: None,
            pid: None,
            serial: id.serial.clone(),
            usb_devpath: id.usb_devpath.clone(),
        }
    }

    #[test]
    fn hex_round_trips_and_refuses_anything_it_did_not_write() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(from_hex("000fff"), Ok(vec![0x00, 0x0f, 0xff]));
        assert_eq!(from_hex(""), Ok(vec![]));

        // A truncated record must not decode to a shorter payload that would
        // then be written to firmware.
        assert!(from_hex("01020").is_err(), "odd length");
        assert!(from_hex("01zz").is_err(), "not hex");
        assert!(from_hex("01 2").is_err(), "spaces are not hex");
        // `from_str_radix` accepts these; the record format does not.
        assert!(from_hex("+1").is_err(), "leading sign");
    }

    #[test]
    fn a_record_survives_a_round_trip_through_the_store() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let id = identity();
        let record = record_for(&id);
        let path = save(&record).expect("save");
        assert!(path.starts_with(&dir), "record lands under the state root");
        match load(&id).expect("load") {
            Situation::Mine {
                path: found,
                record: got,
            } => {
                assert_eq!(*got, record);
                assert_eq!(
                    found, path,
                    "the path it was found at is the path it was saved to"
                );
            }
            other => panic!("expected this camera's own record: {other:?}"),
        }

        clear(&path).expect("clear");
        assert_eq!(load(&id), Ok(Situation::Nothing));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record sitting at THIS camera's exact key whose contents disagree is an
    /// error, never "nothing pending".
    ///
    /// The key is built from the fingerprint, serial and device path, so a
    /// record that genuinely belongs to another camera is filed under another
    /// name. Contents that disagree HERE mean the file was damaged or edited.
    /// The old code fell through to the scan, which drops it on the same
    /// mismatch, so `load` answered `Nothing` and the capture path read that as
    /// licence to write to the camera while an undo record was still outstanding
    /// — fail-open, in the one module whose entire job is to fail closed.
    #[test]
    fn a_damaged_record_at_this_cameras_exact_key_is_not_treated_as_absent() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-damaged-exact");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let id = identity();
        let mut record = record_for(&id);
        let path = save(&record).expect("save");

        // Still valid JSON, still at the name this camera computes, but one
        // identity field no longer matches the camera in front of us.
        record.descriptor_sha256 = "0".repeat(64);
        std::fs::write(&path, serde_json::to_string(&record).expect("serialize"))
            .expect("damage the record");

        let why = load(&id)
            .expect_err("a record at the exact key that disagrees must not read as an empty store");
        assert!(
            why.contains("exact journal key"),
            "the error must say where the record was found, got: {why}"
        );
        // And it is still there: refusing must not destroy the only description
        // of a change that may still be outstanding.
        assert!(
            path.exists(),
            "the record must be left for a person to look at"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_store_is_not_readable_by_other_accounts() {
        use std::os::unix::fs::PermissionsExt as _;
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-perms");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let id = identity();
        let path = save(&record_for(&id)).expect("save");
        let mode =
            |p: &std::path::Path| std::fs::metadata(p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "record");
        assert_eq!(mode(&store_dir()), 0o700, "store directory");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A machine with two IR cameras must not lose one camera's undo data
    /// because the other one was set up afterwards.
    #[test]
    fn a_record_for_one_camera_survives_a_record_for_another() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-two-cameras");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let first = identity();
        let mut second = identity();
        // A different descriptor blob is a different camera, which is the whole
        // basis of the filing.
        second.descriptors.push(0x00);

        save(&record_for(&first)).expect("save first");
        save(&record_for(&second)).expect("save second");

        assert!(matches!(
            load(&first).expect("load first"),
            Situation::Mine { .. }
        ));
        assert!(matches!(
            load(&second).expect("load second"),
            Situation::Mine { .. }
        ));
        assert_ne!(
            record_path(&filing_key(&first)),
            record_path(&filing_key(&second))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two units of one model publish byte-identical descriptors, so the model
    /// digest cannot tell them apart. Filing by it meant a capture on the second
    /// camera loaded the first camera's record, and a successful read-back then
    /// DELETED it, leaving the camera that was actually changed with no undo
    /// data. Setup on the second camera also replaced the first camera's record
    /// outright, since the atomic write deliberately replaces its destination.
    #[test]
    fn two_identical_cameras_do_not_share_one_record() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-identical-units");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let first = identity();
        let second = identical_unit_elsewhere();

        // The premise: these really are indistinguishable by everything except
        // the port. Without this the rest of the test proves nothing.
        assert_eq!(
            fingerprint(&first),
            fingerprint(&second),
            "the fixture must be two units of ONE model"
        );
        assert_eq!(first.serial, second.serial, "and the same serial");
        assert_ne!(first.usb_devpath, second.usb_devpath);

        assert_ne!(
            filing_key(&first),
            filing_key(&second),
            "so they must not be filed under the same name"
        );

        let record = record_for(&first);
        save(&record).expect("save the first camera's record");

        // The capture on the second camera: it must not be handed the first
        // camera's bytes, and it must not delete the record either.
        match load(&second).expect("load for the second camera") {
            Situation::SameModelElsewhere(found) => {
                assert_eq!(found.usb_devpath, first.usb_devpath)
            }
            other => panic!("the second camera must not own this record: {other:?}"),
        }
        assert!(
            !describes_this_camera(&record, &second),
            "the record does not describe the second camera"
        );
        assert!(describes_this_camera(&record, &first));

        // And setting up the second camera leaves the first camera's record
        // where it was, rather than replacing it.
        save(&record_for(&second)).expect("save the second camera's record");
        assert_eq!(
            load(&first).expect("the first record survived"),
            Situation::Mine {
                path: record_path(&record.filing_key()),
                record: Box::new(record)
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record filed under a name its own contents do not produce is still
    /// cleared, because the path it was FOUND at is what gets removed.
    ///
    /// Deriving the path from the record looked equivalent to remembering it and
    /// was not. A record can sit under a name its fields do not reproduce: one
    /// written by a build with a different key derivation, one placed by hand, or
    /// one left by a rename that failed after publication. Removing the derived
    /// name deletes nothing, and the record then warns forever while the code
    /// that "cleared" it believes it is gone.
    #[test]
    fn a_misfiled_record_is_still_removed_when_it_is_resolved() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-misfiled");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let id = identity();
        let record = record_for(&id);
        // Deliberately NOT the name its own fields produce.
        std::fs::create_dir_all(store_dir()).expect("store");
        let wrong = store_dir()
            .join("0000000000000000000000000000000000000000000000000000000000000000.json");
        std::fs::write(&wrong, serde_json::to_string(&record).expect("serialize")).expect("plant");
        assert_ne!(
            wrong,
            record_path(&record.filing_key()),
            "the premise: it is filed under a name its contents do not produce"
        );

        // The scan finds it and reports where it really is.
        let found_at = match load(&id).expect("load") {
            Situation::Mine { path, .. } => path,
            other => panic!("expected this camera's record: {other:?}"),
        };
        assert_eq!(
            found_at, wrong,
            "the path reported must be the path on disk"
        );

        clear(&found_at).expect("clear");
        assert!(
            !wrong.exists(),
            "the file that was read must be the file removed"
        );
        assert_eq!(load(&id).expect("load"), Situation::Nothing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record with no schema version at all authorises nothing.
    ///
    /// A serde default invented schema 1 whenever the field was missing, which
    /// handed the gate its own answer. An absent version means this build cannot
    /// know what the record means, so the parse must fail and the record must be
    /// reported rather than acted on.
    #[test]
    fn a_record_with_no_schema_version_is_refused_rather_than_assumed() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-no-schema");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let id = identity();
        let mut fields: serde_json::Value =
            serde_json::to_value(record_for(&id)).expect("serialize");
        fields
            .as_object_mut()
            .expect("object")
            .remove("schema_version");
        std::fs::create_dir_all(store_dir()).expect("store");
        std::fs::write(
            record_path(&filing_key(&id)),
            serde_json::to_string(&fields).expect("reserialize"),
        )
        .expect("plant");

        // Not silently read as schema 1: the load fails, which the caller turns
        // into an unresolved outcome rather than an authorisation.
        assert!(
            load(&id).is_err(),
            "a record with no version must not deserialize into one"
        );
        // And it is still visible to an operator rather than vanishing.
        match pending_summary() {
            PendingSummary::Pending(entries) => assert_eq!(entries.len(), 1),
            other => panic!("the record must still be reported: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE CONSEQUENCE OF TWO IDENTICAL CAMERAS: one camera's pending record
    /// darkens the other one too.
    ///
    /// Two units of one model publish the same descriptors and, on the module
    /// this was developed against, no serial at all. So when the second camera
    /// looks for its own record and finds none, the scan turns up the first
    /// camera's, and nothing can prove it is not about this camera. It is
    /// reported as `SameModelElsewhere`, which stops the emitter here as well.
    ///
    /// That is the conservative answer and it is deliberate — the alternative is
    /// writing one camera's recorded bytes into another — but the cost is real
    /// and wider than the camera that was actually changed, so it is pinned by a
    /// test rather than left as a surprise.
    #[test]
    fn an_identical_cameras_pending_record_also_stops_this_one() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-identical-blocks");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let first = identity();
        let second = identical_unit_elsewhere();
        // Only the FIRST has an outstanding change.
        save(&record_for(&first)).expect("save the first unit's record");

        match load(&second).expect("load for the second unit") {
            Situation::SameModelElsewhere(found) => {
                assert_eq!(found.usb_devpath, first.usb_devpath)
            }
            other => panic!("expected the other unit's record to be visible: {other:?}"),
        }
        // A different MODEL is unaffected: its descriptors differ, so the record
        // is plainly not about it and its emitter keeps working.
        let mut other_model = identity();
        other_model
            .descriptors
            .extend_from_slice(b"a different model entirely");
        assert_eq!(
            load(&other_model).expect("load for a different model"),
            Situation::Nothing,
            "only cameras indistinguishable from the recorded one are held back"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record written before records carried a port cannot be confirmed to
    /// belong to anything, so it is reported rather than acted on.
    #[test]
    fn a_record_with_no_recorded_port_is_never_acted_on() {
        let id = identity();
        let mut legacy = record_for(&id);
        legacy.usb_devpath = String::new();
        assert!(
            !describes_this_camera(&legacy, &id),
            "an empty port matches nothing, including a camera whose path is also unknown"
        );
    }

    /// The serial narrows a match but never settles one, and it is only compared
    /// when both sides have it: a record from a build that did not store one
    /// must not read as a different unit.
    /// All four serial combinations, because the asymmetric ones are where the
    /// safe answer differs and where two review rounds pulled opposite ways.
    #[test]
    fn a_missing_serial_never_authorises_a_write() {
        let id = identity(); // publishes 200901010001
        let no_serial_camera = CameraIdentity {
            serial: None,
            ..identity()
        };

        // both present and equal -> confirmed
        assert!(describes_this_camera(&record_for(&id), &id));

        // both present and different -> two cameras
        let mut different = record_for(&id);
        different.serial = Some("some-other-unit".into());
        assert!(
            !describes_this_camera(&different, &id),
            "two serials that disagree are two cameras"
        );

        // record has none -> nothing to compare, and the module this was built
        // against publishes none at all
        let mut recorded_without = record_for(&id);
        recorded_without.serial = None;
        assert!(describes_this_camera(&recorded_without, &id));
        assert!(describes_this_camera(&recorded_without, &no_serial_camera));

        // record HAS one and this observation does not -> evidence the record
        // was written with cannot be reproduced, so it authorises nothing. The
        // device path names a port, not a unit: an identical camera swapped into
        // that port satisfies descriptor and path alike.
        assert!(
            !describes_this_camera(&record_for(&id), &no_serial_camera),
            "a missing current serial must fail closed"
        );
    }

    /// The lock excludes a second PROCESS.
    ///
    /// Asserted against one, because `flock` is per open file description: two
    /// calls in the same process each open the file and each succeed, so a test
    /// that took the lock twice here would pass no matter what the code did. The
    /// external `flock -n` is the only thing that answers the question the lock
    /// exists to answer.
    #[test]
    fn the_camera_lock_excludes_another_process() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-camera-lock");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);
        let id = identity();
        let path = lock_path(&id);

        let held = lock_camera(&id).expect("take the lock").expect("not busy");

        // `flock -n` exits 1 when the lock is held; the shell is a separate
        // process, which is the whole point.
        let refused = std::process::Command::new("flock")
            .args(["-n", path.to_str().expect("path"), "-c", "true"])
            .status()
            .expect("run flock");
        assert!(
            !refused.success(),
            "a second process must not get the lock while it is held"
        );

        drop(held);
        let granted = std::process::Command::new("flock")
            .args(["-n", path.to_str().expect("path"), "-c", "true"])
            .status()
            .expect("run flock");
        assert!(
            granted.success(),
            "and must get it once released, or the previous assertion could pass \
             for any reason at all"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record must still be found when the serial's AVAILABILITY changes.
    ///
    /// `identity_from_fd` maps every failure to read the sysfs `serial` file to
    /// `None`, and the filename is derived from it. One transient read failure
    /// therefore changes the key the lookup uses. The record still describes
    /// this camera by descriptor and device path, and dismissing it as another
    /// camera's would leave the camera changed with its emitter disabled — the
    /// exact opposite of what the record is for.
    #[test]
    fn a_record_is_found_when_the_serial_becomes_unreadable() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-serial-flip");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);

        let with_serial = identity();
        let record = record_for(&with_serial);
        save(&record).expect("save with a serial");

        // Same camera, same port, same descriptors; the serial simply did not
        // read this time.
        let no_serial = CameraIdentity {
            serial: None,
            ..identity()
        };
        assert_ne!(
            filing_key(&with_serial),
            filing_key(&no_serial),
            "the premise: the key really does change"
        );
        // FOUND, but not acted on. Round 7 established that a transient serial
        // failure must not hide the record; round 12 established that it must
        // not authorise a write either, because the device path names a port
        // and an identical unit could have been swapped into it. Both hold:
        // the record is reported, and left alone until the serial reads again.
        assert_eq!(
            load(&no_serial).expect("load"),
            Situation::SameModelElsewhere(Box::new(record.clone())),
            "the record must still be found, and must not authorise a write"
        );
        assert!(
            !describes_this_camera(&record, &no_serial),
            "a serial the record has and this observation lacks is missing evidence"
        );

        // And the reverse: written without one, read with one.
        let _ = std::fs::remove_dir_all(&dir);
        let mut no_serial_record = record_for(&no_serial);
        no_serial_record.serial = None;
        save(&no_serial_record).expect("save without a serial");
        assert_eq!(
            load(&with_serial).expect("load"),
            Situation::Mine {
                path: record_path(&no_serial_record.filing_key()),
                record: Box::new(no_serial_record)
            },
            "a record with no serial still describes a camera that has one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With several same-model records in the store, this camera's own must be
    /// found wherever the directory listing happens to put it.
    ///
    /// MY record is deliberately MISFILED, so the exact-path fast path misses
    /// and the SCAN is what has to find it. Without that this never reached the
    /// loop at all: the fast path answered, and a mutant that stopped the scan
    /// at the first same-model record survived under a test named for
    /// directory order.
    ///
    /// The foreign record is given a name this directory really does hand back
    /// first, discovered by asking rather than assumed, so the ordering the test
    /// is named for is the ordering it runs against.
    #[test]
    fn this_cameras_record_is_found_whatever_the_directory_order() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-scan-order");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        std::fs::create_dir_all(store_dir()).expect("store");

        let mine = identity();
        let my_record = record_for(&mine);
        let misfiled = store_dir().join(format!("{}.json", "f".repeat(64)));
        std::fs::write(
            &misfiled,
            serde_json::to_string(&my_record).expect("serialize"),
        )
        .expect("plant mine misfiled");

        let other = record_for(&identical_unit_elsewhere());
        let first_entry = || {
            std::fs::read_dir(store_dir())
                .expect("read store")
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .next()
                .expect("an entry")
        };
        let mut foreign = None;
        for n in 0..64u32 {
            let candidate = store_dir().join(format!("{n:064x}.json"));
            std::fs::write(
                &candidate,
                serde_json::to_string(&other).expect("serialize"),
            )
            .expect("plant foreign");
            if first_entry() == candidate {
                foreign = Some(candidate);
                break;
            }
            std::fs::remove_file(&candidate).expect("try another name");
        }
        assert!(
            foreign.is_some(),
            "no name came back before mine in 64 tries, so the ordering this \
             test is named for was never established"
        );

        assert_eq!(
            load(&mine).expect("load"),
            Situation::Mine {
                path: misfiled,
                record: Box::new(my_record)
            },
            "stopping at the first same-model record would report the wrong one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// There is no schema 0, so a record claiming one describes nothing this
    /// build knows how to act on.
    #[test]
    fn a_record_from_a_schema_this_build_does_not_implement_is_refused() {
        let id = identity();
        for version in [0, SCHEMA_VERSION + 1] {
            let mut record = record_for(&id);
            record.schema_version = version;
            assert_eq!(
                record_applies(&record, &id),
                Err(Mismatch::UnsupportedSchema {
                    found: version,
                    supported: SCHEMA_VERSION,
                }),
                "schema {version} must not authorise a firmware write"
            );
        }
    }

    /// One physical camera must always resolve to ONE lock, whether or not its
    /// serial happened to read this time.
    ///
    /// The filing key deliberately includes the serial and the lookup tolerates
    /// it changing by scanning the store. A lock cannot do that: two names are
    /// two locks, so two processes whose serial reads disagreed would each take
    /// their own and both would proceed to drive the same control. Asserted
    /// against a SECOND PROCESS, because `flock` is per open file description
    /// and two calls inside this one would both succeed regardless.
    #[test]
    fn serial_availability_does_not_change_the_camera_lock() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join("irlume-journal-lock-key");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _env = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);

        let with_serial = identity();
        let without_serial = CameraIdentity {
            serial: None,
            ..identity()
        };
        // The premise: the FILING key really does differ between these two, so
        // an equal lock path is a property of the lock key and not a
        // coincidence.
        assert_ne!(filing_key(&with_serial), filing_key(&without_serial));
        assert_eq!(
            lock_path(&with_serial),
            lock_path(&without_serial),
            "one camera, one lock"
        );

        let held = lock_camera(&with_serial)
            .expect("take the lock")
            .expect("not busy");
        let path = lock_path(&without_serial);
        let ready = dir.join("holder-ready");
        let mut holder = std::process::Command::new("flock")
            .args([
                "-n",
                path.to_str().expect("path"),
                "-c",
                &format!("touch {}", ready.display()),
            ])
            .status()
            .expect("run flock");
        assert!(
            !holder.success(),
            "a second process must not get the lock for the same camera just \
             because its serial read came back empty"
        );
        assert!(!ready.exists(), "the holder should never have run");

        drop(held);
        holder = std::process::Command::new("flock")
            .args(["-n", path.to_str().expect("path"), "-c", "true"])
            .status()
            .expect("run flock");
        assert!(
            holder.success(),
            "and must get it once released, or the assertion above could pass \
             for any reason at all"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_for_another_camera_is_left_alone() {
        let id = identity();
        let mut record = record_for(&id);
        record.descriptor_sha256 = "0".repeat(64);
        assert_eq!(record_applies(&record, &id), Err(Mismatch::DifferentCamera));
    }

    /// serde ignores unknown fields, so a newer record deserializes cleanly into
    /// this older shape and every field looks reasonable. What this build cannot
    /// know is whether they still mean the same thing, and the record authorises
    /// a write to firmware.
    #[test]
    fn a_record_from_a_newer_schema_is_refused_rather_than_partly_understood() {
        let id = identity();
        let mut record = record_for(&id);
        record.schema_version = SCHEMA_VERSION + 1;
        assert_eq!(
            record_applies(&record, &id),
            Err(Mismatch::UnsupportedSchema {
                found: SCHEMA_VERSION + 1,
                supported: SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn a_record_whose_two_identities_disagree_authorises_nothing() {
        let id = identity();
        let mut record = record_for(&id);
        record.usb_id = "dead:beef".into();
        assert!(matches!(
            record_applies(&record, &id),
            Err(Mismatch::Malformed(_))
        ));

        let mut record = record_for(&id);
        record.interface_number = id.interface_number.wrapping_add(1);
        assert!(matches!(
            record_applies(&record, &id),
            Err(Mismatch::Malformed(_))
        ));
    }

    #[test]
    fn a_record_naming_a_control_the_camera_does_not_publish_is_refused() {
        let id = identity();
        let (unit, _) = published_control(&id);

        let mut wrong_unit = record_for(&id);
        wrong_unit.unit = unit.wrapping_add(1);
        assert_eq!(
            record_applies(&wrong_unit, &id),
            Err(Mismatch::ControlNotPublished)
        );

        // Microsoft's Focus selector: a real selector number, and one discovery
        // could never have written. Without the check a hand-edited record would
        // put SET_CUR traffic onto it.
        let mut wrong_selector = record_for(&id);
        wrong_selector.selector = 0x01;
        assert_eq!(
            record_applies(&wrong_selector, &id),
            Err(Mismatch::ControlNotPublished)
        );
    }

    #[test]
    fn a_record_whose_original_does_not_match_its_own_length_is_refused() {
        let id = identity();
        let mut record = record_for(&id);
        record.len = 4; // original is three bytes
        assert!(matches!(
            record_applies(&record, &id),
            Err(Mismatch::Malformed(_))
        ));

        let mut record = record_for(&id);
        record.original = "not hex".into();
        assert!(matches!(
            record_applies(&record, &id),
            Err(Mismatch::Malformed(_))
        ));
    }

    /// Without this the restore runs at every capture forever on a control whose
    /// GET_CUR does not report what was written to it, which is a worse outcome
    /// than the one being recovered from.
    #[test]
    fn recovery_stops_writing_after_the_attempt_budget() {
        let id = identity();
        let mut record = record_for(&id);

        record.restore_attempts = MAX_RESTORE_ATTEMPTS - 1;
        assert_eq!(record_applies(&record, &id), Ok(()), "one attempt left");

        record.restore_attempts = MAX_RESTORE_ATTEMPTS;
        assert_eq!(
            record_applies(&record, &id),
            Err(Mismatch::OutOfAttempts {
                attempts: MAX_RESTORE_ATTEMPTS
            })
        );
    }

    /// A capture running beside a live `ir-setup` must leave that run's control
    /// alone. Its record is open precisely because the control is supposed to be
    /// changed at that moment.
    #[test]
    fn a_record_whose_writer_is_still_running_is_left_alone() {
        let id = identity();
        let mut record = record_for(&id);
        record.boot_id = current_boot_id();
        record.pid = Some(std::process::id());
        assert!(
            record.boot_id.is_some(),
            "this kernel must publish a boot id for the check to mean anything"
        );
        assert_eq!(
            record_applies(&record, &id),
            Err(Mismatch::OwnerStillRunning {
                pid: std::process::id()
            })
        );

        // pid 0 is never a live process, so the same record with a dead owner is
        // recoverable. Without this the test would pass on a build where the
        // owner check always said "still running".
        record.pid = Some(0);
        assert_eq!(record_applies(&record, &id), Ok(()));
    }

    /// The owner check is scoped to one boot. A record surviving a reboot names
    /// a pid that means nothing, and the pid space is small enough that some
    /// live process will eventually wear that number.
    #[test]
    fn a_record_from_an_earlier_boot_is_recovered_whatever_pid_it_names() {
        let id = identity();
        let mut record = record_for(&id);
        record.boot_id = Some("00000000-0000-0000-0000-000000000000".into());
        record.pid = Some(std::process::id());
        assert_ne!(
            current_boot_id().as_deref(),
            Some("00000000-0000-0000-0000-000000000000"),
            "the nil uuid must not be this boot, or the test proves nothing"
        );
        assert_eq!(record_applies(&record, &id), Ok(()));
    }

    #[test]
    fn a_control_already_holding_the_original_is_resolved_without_a_write() {
        let id = identity();
        let record = record_for(&id);
        let now = ControlNow {
            len: 3,
            writable: true,
            current: vec![1, 3, 1],
        };
        assert_eq!(restore_decision(&record, &now), Restore::AlreadyRestored);
    }

    #[test]
    fn a_control_still_holding_the_exploratory_value_is_written_back() {
        let id = identity();
        let record = record_for(&id);
        let now = ControlNow {
            len: 3,
            writable: true,
            current: vec![1, 3, 2],
        };
        assert_eq!(
            restore_decision(&record, &now),
            Restore::Write(vec![1, 3, 1])
        );
    }

    /// A control something ELSE moved is left alone.
    ///
    /// The lock excludes other irlume processes and nothing else. A vendor tool
    /// or an operator can change this control between the interruption and the
    /// recovery, and "not the original" was being read as "still holding our
    /// write". `attempted` was recorded from the first commit precisely to tell
    /// those apart, and until review pointed it out nothing read it.
    #[test]
    fn a_control_a_third_party_moved_is_not_overwritten() {
        let id = identity();
        let record = record_for(&id); // original 010301, attempted 010302
        let now = ControlNow {
            len: 3,
            writable: true,
            current: vec![1, 3, 3], // neither
        };
        match restore_decision(&record, &now) {
            Restore::Refuse(why) => {
                // The operator needs all three values to work out what happened.
                assert!(why.contains("[01, 03, 03]"), "{why}");
                assert!(why.contains("[01, 03, 02]"), "{why}");
                assert!(why.contains("[01, 03, 01]"), "{why}");
            }
            other => panic!("a third party's value must not be overwritten: {other:?}"),
        }

        // And the guard must not swallow the case it exists FOR: the control
        // still holding this run's write is restored.
        assert_eq!(
            restore_decision(
                &record,
                &ControlNow {
                    len: 3,
                    writable: true,
                    current: vec![1, 3, 2],
                }
            ),
            Restore::Write(vec![1, 3, 1])
        );
    }

    /// The length is the attached camera's answer, not the record's. Trusting
    /// the record would send a payload of the wrong width to firmware.
    #[test]
    fn a_control_of_a_different_width_is_refused_before_anything_is_written() {
        let id = identity();
        let record = record_for(&id);
        let now = ControlNow {
            len: 4,
            writable: true,
            current: vec![1, 3, 2, 0],
        };
        // The REASON, not merely that it refused. Once the "something else moved
        // this control" check existed, a build with no width check at all still
        // refused this input, because a 4-byte current value does not equal a
        // 3-byte recorded one either. Asserting on the outcome alone stopped
        // discriminating and the mutant survived.
        match restore_decision(&record, &now) {
            Restore::Refuse(why) => assert!(
                why.contains("4 bytes now") && why.contains("3 when"),
                "the refusal must be about the control's WIDTH: {why}"
            ),
            other => panic!("a control of a different width must be refused: {other:?}"),
        }
    }

    /// Checked AFTER the already-restored case: a camera that refuses writes but
    /// is already holding the original needs its record cleared, not a refusal
    /// that leaves it pending forever.
    #[test]
    fn a_control_the_camera_will_not_accept_a_write_to_is_refused() {
        let id = identity();
        let record = record_for(&id);
        assert!(matches!(
            restore_decision(
                &record,
                &ControlNow {
                    len: 3,
                    writable: false,
                    current: vec![1, 3, 2],
                }
            ),
            Restore::Refuse(_)
        ));
        assert_eq!(
            restore_decision(
                &record,
                &ControlNow {
                    len: 3,
                    writable: false,
                    current: vec![1, 3, 1],
                }
            ),
            Restore::AlreadyRestored,
            "nothing to write, so writability does not matter"
        );
    }

    /// The initial undo record's DURABILITY is what authorizes the first
    /// firmware write, so a record that is merely visible must be an error.
    ///
    /// This is the regression for a fix that went too far: the attempt counter
    /// genuinely may treat a published-but-not-durable record as counted, and
    /// relaxing that at the shared helper handed the same licence to `save`,
    /// where it means "write the camera even though the record can still be
    /// lost" — the exact defect this module exists to prevent.
    #[test]
    fn a_record_that_is_visible_but_not_durable_does_not_authorize_a_write() {
        let path = std::path::PathBuf::from("/var/lib/irlume/ir-emitter-journal/x.json");
        assert_eq!(
            super::require_durable(path.clone(), irlume_common::AtomicWrite::Durable),
            Ok(path.clone()),
            "an ordinary durable write is the normal path and must still pass"
        );
        let why = super::require_durable(
            path,
            irlume_common::AtomicWrite::VisibleNotDurable(std::io::Error::other("disk went away")),
        )
        .expect_err("a record that may not survive a power cut must NOT open discovery");
        // The operator has to be able to tell this apart from an ordinary write
        // failure: the file IS there, and that is the surprising part.
        assert!(
            why.contains("visible") && why.contains("durable"),
            "the refusal must say the record is visible but not durable, got: {why}"
        );
        assert!(
            why.contains("disk went away"),
            "the underlying error must survive into the message, got: {why}"
        );
    }
}
