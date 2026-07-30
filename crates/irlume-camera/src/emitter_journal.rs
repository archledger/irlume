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
    #[serde(default = "schema_version_1")]
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

fn schema_version_1() -> u32 {
    1
}

impl PendingWrite {
    /// The original bytes, or an error naming what is wrong with the record.
    pub(crate) fn original_bytes(&self) -> Result<Vec<u8>, String> {
        from_hex(&self.original).map_err(|e| format!("original: {e}"))
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

/// The digest a record for this camera is filed under.
pub(crate) fn fingerprint(id: &CameraIdentity) -> String {
    irlume_common::sha256_hex(&id.descriptors)
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
    /// Written to a schema this build does not implement.
    SchemaTooNew { found: u32, supported: u32 },
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
    if record.schema_version > SCHEMA_VERSION {
        return Err(Mismatch::SchemaTooNew {
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
    if !now.writable {
        return Restore::Refuse(
            "the camera reports it does not accept a write to this control right now".into(),
        );
    }
    Restore::Write(original)
}

/// Read this camera's record, if there is one.
///
/// An unreadable record that exists is an error rather than "no record":
/// treating a permission or IO failure as absence would silently drop the one
/// description of how to undo a firmware write.
pub(crate) fn load(id: &CameraIdentity) -> Result<Option<PendingWrite>, String> {
    let path = record_path(&fingerprint(id));
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    serde_json::from_str(&body)
        .map(Some)
        .map_err(|e| format!("parse {}: {e}", path.display()))
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
pub(crate) fn save(record: &PendingWrite) -> Result<PathBuf, String> {
    let dir = store_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    irlume_common::restrict(&dir, 0o700)?;
    irlume_common::fsync_ancestors(&dir)?;
    let path = record_path(&record.descriptor_sha256);
    let body = serde_json::to_string(record).map_err(|e| format!("serialize record: {e}"))?;
    irlume_common::write_0600_atomic(&path, body.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    // After the fsync, so a line here means the record is durable — which is the
    // property the ordering depends on, not merely that a write was issued.
    trace(&format!(
        "saved unit{}/sel{} original={} attempts={}",
        record.unit, record.selector, record.original, record.restore_attempts
    ));
    Ok(path)
}

/// Remove a record whose control is confirmed back where it was found.
pub(crate) fn clear(descriptor_sha256: &str) -> Result<(), String> {
    irlume_common::remove_durable(&record_path(descriptor_sha256))?;
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

    /// A camera identity backed by the real ASUS descriptor bytes, so these
    /// exercise the same parsing path production uses.
    fn identity() -> CameraIdentity {
        CameraIdentity {
            descriptors: include_bytes!("../tests/fixtures/asus-3277-0059.descriptors").to_vec(),
            interface_number: 2,
            vid: 0x3277,
            pid: 0x0059,
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
        assert_eq!(load(&id), Ok(Some(record)));

        clear(&fingerprint(&id)).expect("clear");
        assert_eq!(load(&id), Ok(None));
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

        assert!(load(&first).expect("load first").is_some());
        assert!(load(&second).expect("load second").is_some());
        assert_ne!(
            record_path(&fingerprint(&first)),
            record_path(&fingerprint(&second))
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
            Err(Mismatch::SchemaTooNew {
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
        assert!(matches!(
            restore_decision(&record, &now),
            Restore::Refuse(_)
        ));
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
}
