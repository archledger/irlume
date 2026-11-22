// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The on-disk copy of ADR-0021 rate-evidence completions, so the first
//! session after a daemon start can try the continuity probe when the same
//! stream completed a full window within the staleness bound (ADR-0021,
//! amendment 2026-11-22).
//!
//! One small file per stream identity under `state_dir()/rate-evidence/`
//! holds the record schema and the completion's unix time in milliseconds,
//! nothing else: no secret, no biometric data, no device path and no
//! serial, since the file name is a digest of the identity.
//!
//! A record only decides whether a probe is tried. The probe on the current
//! session and the per-frame sliding judgment after it remain the evidence
//! that admits the session, so a forged, stale or corrupt record can cost a
//! probe attempt and nothing else. With that in mind a record is read only
//! as far as it can be trusted: a regular file, owned by the effective
//! user, with no access for group or other, within the size bound, in the
//! known schema, with a completion neither in the future nor past the
//! staleness bound. Anything else reads as no record at all.

use super::rate_amortization::{Identity, MAX_STALENESS};
use serde::{Deserialize, Serialize};
use std::fs::Metadata;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Record shape understood by this build. Any other schema is no record.
const SCHEMA: u32 = 1;
/// Largest accepted record. A real one is about 50 bytes.
const MAX_RECORD_BYTES: u64 = 1024;
/// Records kept at once. A machine has a few cameras; when a new record
/// would exceed this, the oldest completions are removed.
const MAX_RECORDS: usize = 32;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    completed_unix_ms: u64,
}

/// The records of one state directory.
#[derive(Clone, Debug)]
pub(crate) struct Store {
    dir: PathBuf,
}

impl Store {
    /// The production store under the state directory.
    #[must_use]
    pub(crate) fn system() -> Self {
        Self {
            dir: irlume_common::state_dir().join("rate-evidence"),
        }
    }

    /// How long ago the stream's last full window completed, when a record
    /// says so within the staleness bound at `now`. `None` when there is no
    /// record or none that can be trusted.
    pub(crate) fn load(&self, identity: &Identity, now: SystemTime) -> Option<Duration> {
        let path = self.path(identity);
        let record = read(&path)?;
        let completed =
            std::time::UNIX_EPOCH.checked_add(Duration::from_millis(record.completed_unix_ms))?;
        // A completion later than now is not evidence of anything, however
        // the file came to say so.
        match now.duration_since(completed) {
            Ok(age) if age <= MAX_STALENESS => Some(age),
            // Past the bound or in the future: no record, and one file
            // fewer to read next time. A removal that fails changes nothing.
            _ => {
                let _ = std::fs::remove_file(path);
                None
            }
        }
    }

    /// Record that `identity`'s full window completed at `at`, replacing any
    /// earlier record for it in one step.
    pub(crate) fn record(&self, identity: &Identity, at: SystemTime) -> std::io::Result<()> {
        let existed = self.dir.exists();
        std::fs::create_dir_all(&self.dir)?;
        irlume_common::restrict(&self.dir, 0o700).map_err(std::io::Error::other)?;
        if !existed {
            irlume_common::fsync_ancestors(&self.dir).map_err(std::io::Error::other)?;
        }
        let completed_unix_ms = u64::try_from(
            at.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let mut body = serde_json::to_vec(&Record {
            schema: SCHEMA,
            completed_unix_ms,
        })?;
        body.push(b'\n');
        // 0600 at creation: the temporary file and the published one belong
        // to the effective user alone, and the rename publishes in one step.
        irlume_common::write_atomic_reporting(&self.path(identity), &body, 0o600).map(|_| ())?;
        // A failed tidy-up leaves a published record behind, never less.
        self.prune();
        Ok(())
    }

    /// Remove the record of `identity`. An absent record is already removed.
    pub(crate) fn remove(&self, identity: &Identity) -> std::io::Result<()> {
        match std::fs::remove_file(self.path(identity)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// Keep at most [`MAX_RECORDS`] completions: a file that is not a sound
    /// record goes first, then the oldest completion.
    fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut sound: Vec<(u64, PathBuf)> = Vec::new();
        let mut doomed: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            // An atomic write's temporary file never ends in `.json`.
            let is_record = entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".json"));
            if !is_record {
                continue;
            }
            match read(&path) {
                Some(record) => sound.push((record.completed_unix_ms, path)),
                None => doomed.push(path),
            }
        }
        sound.sort_by_key(|(completed, _)| *completed);
        let excess = sound.len().saturating_sub(MAX_RECORDS);
        doomed.extend(sound.into_iter().take(excess).map(|(_, path)| path));
        for path in doomed {
            let _ = std::fs::remove_file(path);
        }
    }

    fn path(&self, identity: &Identity) -> PathBuf {
        self.dir.join(format!("{}.json", identity.hex()))
    }

    /// The record file of `identity`, for the tests that inspect it.
    #[cfg(test)]
    pub(crate) fn record_path(&self, identity: &Identity) -> PathBuf {
        self.path(identity)
    }

    /// A store in `dir`, for the tests.
    #[cfg(test)]
    pub(crate) fn at(dir: PathBuf) -> Self {
        Self { dir }
    }
}

/// The user this process runs as, whose records alone it reads.
fn euid() -> u32 {
    // SAFETY: geteuid reads this process's own credentials and cannot fail.
    unsafe { libc::geteuid() }
}

/// Whether `metadata` describes a file this process, running as `euid`, may
/// read a record from: a regular file of that user's with no access for
/// group or other, within the size bound.
fn trusted(metadata: &Metadata, euid: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.is_file()
        && metadata.uid() == euid
        && metadata.mode() & 0o077 == 0
        && metadata.len() <= MAX_RECORD_BYTES
}

/// The record at `path`, when it is one this process can trust.
fn read(path: &Path) -> Option<Record> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // No following of a planted link, no descriptor leak past this read,
    // and no blocking on anything but a regular file.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !trusted(&metadata, euid()) {
        return None;
    }
    let mut body = Vec::new();
    file.take(MAX_RECORD_BYTES.saturating_add(1))
        .read_to_end(&mut body)
        .ok()?;
    let record: Record = serde_json::from_slice(&body).ok()?;
    (record.schema == SCHEMA).then_some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata_of(body: &[u8], mode: u32) -> Metadata {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "irlume-rate-evidence-trust-{:08x}",
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("record");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        metadata
    }

    #[test]
    fn a_record_is_trusted_only_for_its_owner_with_no_other_access_and_in_bounds() {
        let euid = euid();
        let sound = metadata_of(b"{\"schema\":1,\"completed_unix_ms\":1}\n", 0o600);
        assert!(trusted(&sound, euid));
        // Not for another user, however the file is shaped.
        assert!(!trusted(&sound, euid.wrapping_add(1)));
        // Any access for group or other.
        for mode in [0o640_u32, 0o604, 0o660, 0o606, 0o666, 0o644, 0o664] {
            let loose = metadata_of(b"{}", mode);
            assert!(!trusted(&loose, euid), "mode {mode:o}");
        }
        // Tighter is still the owner's alone.
        for mode in [0o400_u32, 0o200, 0o000] {
            let tight = metadata_of(b"{}", mode);
            assert!(trusted(&tight, euid), "mode {mode:o}");
        }
        // Larger than any record.
        let oversized = metadata_of(&vec![b' '; MAX_RECORD_BYTES as usize + 1], 0o600);
        assert!(!trusted(&oversized, euid));
        let at_bound = metadata_of(&vec![b' '; MAX_RECORD_BYTES as usize], 0o600);
        assert!(trusted(&at_bound, euid));
        // Not a regular file: a directory in a record's place is 0700 and
        // this user's own, and is still no record.
        let dir = std::env::temp_dir().join(format!(
            "irlume-rate-evidence-trust-dir-{:08x}",
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!trusted(&std::fs::metadata(&dir).unwrap(), euid));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
