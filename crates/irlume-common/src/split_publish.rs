// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! The single-commit split publication protocol (ADR-0032 §4.1.3-§4.1.5).
//!
//! `cameras.conf` is the single atomic commit point that names an
//! already-durable, immutable generation under `split-pairs/`. Writers hold
//! `lock_exclusive` on `cameras.conf`; readers take no lock and read each file
//! once, so a reader always sees one whole publication. Generation cleanup
//! runs only in the writer, at publication time, where the predecessor is
//! known from the `cameras.conf` read in step 1; the sweep at daemon start
//! removes writer temporaries and unreferenced generations numbered above the
//! referenced one, which cannot be the predecessor.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::config::{self, SplitConfObservation};
use crate::split_key::SplitPairKey;
use crate::split_schema::{self, AuthorizationRecord, GenerationObservation, SchemaError};

/// Directory (under the config root) holding immutable generations and
/// writer temporaries.
pub const GENERATION_DIR: &str = "split-pairs";

/// One successful publication (ADR-0032 §4.1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The generation number committed to `cameras.conf`.
    pub generation: u64,
    /// `sha256:` plus 64 lowercase hex digits over the generation's bytes.
    pub digest: String,
}

/// Why a publication was refused.
#[derive(Debug)]
pub enum PublishError {
    /// An I/O step failed.
    Io(std::io::Error),
    /// `cameras.conf` could not be read.
    Unreadable,
    /// `cameras.conf` is malformed (including malformed split keys).
    MalformedConfig,
    /// The records violate the generation schema.
    Schema(SchemaError),
    /// Every `u64` generation number is spent; none may be reused.
    GenerationExhausted,
}

/// What one lock-free read established (ADR-0032 §4.1.2 states).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitReadState {
    /// No generation is referenced.
    Absent,
    /// A needed file could not be read.
    Unreadable,
    /// A referenced state is malformed or a selection does not resolve.
    Malformed,
    /// A valid reference names invalid or missing generation contents.
    MalformedGeneration {
        /// Referenced generation retained for root diagnostics.
        generation: u64,
    },
    /// The generation is valid, but its configured selection does not resolve.
    UnresolvedSelection {
        /// Referenced generation retained for root diagnostics.
        generation: u64,
        /// Number of verified records in that generation.
        record_count: usize,
    },
    /// The referenced generation's bytes do not match `split_digest`.
    DigestMismatch {
        /// Parsed reference whose bytes failed verification.
        generation: u64,
    },
    /// The publication is coherent; `selected` is the resolved selection.
    Valid {
        /// The referenced generation number.
        generation: u64,
        /// The ordered authorization records.
        records: Vec<AuthorizationRecord>,
        /// The resolved selected pair, if any.
        selected: Option<SplitPairKey>,
    },
}

/// Strict camera selection and split verification from one publication.
///
/// A missing generation permits one new configuration observation. In that
/// case both accessors describe the final observation, never an old ordinary
/// pin combined with a new split generation. This is not live camera proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CameraSelectionSnapshot {
    observation: config::CameraConfObservation,
    split: SplitReadState,
}

impl CameraSelectionSnapshot {
    /// The final strict mode, ordinary pin and split reference observation.
    #[must_use]
    pub fn observation(&self) -> &config::CameraConfObservation {
        &self.observation
    }

    /// Verification of the split reference in [`Self::observation`].
    #[must_use]
    pub fn split(&self) -> &SplitReadState {
        &self.split
    }
}

fn generation_dir() -> PathBuf {
    config::config_path(GENERATION_DIR)
}

/// Create the generation directory root-only (ADR-0032 §4.1.2: mode 0700).
/// The mode is set at creation; `create_dir_all` on an existing directory
/// leaves its mode alone, which is the deployed truth.
fn create_generation_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

fn generation_name(n: u64) -> String {
    format!("{n}.conf")
}

/// A canonical generation name is `<N>.conf` with `N` a decimal `u64` >= 1
/// without leading zeros. Anything else in the directory is not a generation.
fn parse_generation_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".conf")?;
    if stem.is_empty()
        || !stem.bytes().all(|b| b.is_ascii_digit())
        || (stem.len() > 1 && stem.starts_with('0'))
    {
        return None;
    }
    let n: u64 = stem.parse().ok()?;
    (n >= 1).then_some(n)
}

/// Writer temporaries from `write_0600_atomic`: `.{name}.tmp.{pid}.{seq}`
/// where `{name}` is a canonical generation name. Only that exact shape is
/// swept, so a foreign file is never deleted (ADR-0032 §4.1.3).
fn is_writer_temp(name: &str) -> bool {
    let Some(stripped) = name.strip_prefix('.') else {
        return false;
    };
    let Some((target, tail)) = stripped.split_once(".tmp.") else {
        return false;
    };
    if parse_generation_name(target).is_none() {
        return false;
    }
    tail.split_once('.').is_some_and(|(pid, seq)| {
        !pid.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && !seq.is_empty()
            && seq.bytes().all(|b| b.is_ascii_digit())
    })
}

fn digest_value(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `sha256:` plus the lowercase hex digest of `bytes`.
fn digest_key(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_value(bytes))
}

fn split_keys_in(obs: &config::CameraConfObservation) -> Option<(u64, String, Option<String>)> {
    match &obs.split {
        SplitConfObservation::Reference {
            generation,
            digest,
            pair,
        } => Some((*generation, digest.clone(), pair.clone())),
        _ => None,
    }
}

fn list_generations(dir: &Path) -> Vec<(u64, PathBuf)> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Some(n) = parse_generation_name(name) {
                    out.push((n, entry.path()));
                }
            }
        }
    }
    out.sort();
    out
}

/// Delete writer temporaries only. Generations are the retention's job.
fn sweep_temps(dir: &Path) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(is_writer_temp) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// Delete writer temporaries and unreferenced generations numbered above the
/// referenced one. The referenced generation and everything below it is left
/// for publication-time retention (the predecessor is only known there).
fn sweep_dir(dir: &Path, referenced: Option<u64>) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_writer_temp(&name) {
            let _ = std::fs::remove_file(entry.path());
        } else if let Some(n) = parse_generation_name(&name) {
            if referenced.is_some_and(|r| n > r) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok(())
}

/// Delete every generation file except `keep` (ADR-0032 §4.1.5). Failures are
/// harmless and retried at the next publication.
fn retain_only(dir: &Path, keep: &[u64]) {
    for (n, path) in list_generations(dir) {
        if !keep.contains(&n) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The daemon-start sweep: writer temporaries and unreferenced generations
/// above the reference, under the writer lock.
///
/// # Errors
/// When the lock cannot be taken or the directory cannot be read.
pub fn sweep_split_artifacts() -> std::io::Result<()> {
    let _guard = config::lock_exclusive(config::CAMERAS_CONF)?;
    let referenced = split_keys_in(&config::observe_camera_conf()).map(|(g, _, _)| g);
    sweep_dir(&generation_dir(), referenced)
}

/// Publish one coherent generation + selection state (ADR-0032 §4.1.3).
///
/// # Errors
/// [`PublishError`] when `cameras.conf` is unreadable or malformed, the
/// records violate the schema, or an I/O step fails.
pub fn publish_split(
    records: &[AuthorizationRecord],
    selected: Option<&SplitPairKey>,
) -> Result<Published, PublishError> {
    let _guard = config::lock_exclusive(config::CAMERAS_CONF).map_err(PublishError::Io)?;
    let obs = config::observe_camera_conf();
    if matches!(
        obs.selection,
        config::CameraSelectionObservation::Unreadable { .. }
    ) {
        return Err(PublishError::Unreadable);
    }
    if matches!(
        obs.selection,
        config::CameraSelectionObservation::Malformed { .. }
    ) || obs.split == SplitConfObservation::Malformed
    {
        return Err(PublishError::MalformedConfig);
    }
    // The predecessor is what the cameras.conf read in this step referenced:
    // only here is it known (ADR-0032 §4.1.5).
    let predecessor = split_keys_in(&obs).map(|(generation, _, _)| generation);
    let dir = generation_dir();
    create_generation_dir(&dir).map_err(PublishError::Io)?;
    // A crashed writer's temporaries go now, under the lock (§4.1.5).
    // Generation files are NOT swept here: `N` must see every number on disk
    // so a crashed generation's number is never reused, and publication-time
    // retention below collects it.
    sweep_temps(&dir).map_err(PublishError::Io)?;

    // The selection must resolve inside the records being published
    // (ADR-0032 §4: selection never references a pair the generation does
    // not hold). Refuse before any file is touched.
    if let Some(key) = selected {
        if !records.iter().any(|r| record_matches(r, key)) {
            return Err(PublishError::Schema(SchemaError::InvalidField));
        }
    }
    if records.is_empty() {
        // Removal of the last record drops the split keys entirely; the just
        // de-referenced generation counts as the predecessor and is kept.
        config::publish_kv_changes(
            config::CAMERAS_CONF,
            &[],
            &["split_generation", "split_digest", "split_pair"],
        )
        .map_err(PublishError::Io)?;
        retain_only(&dir, &predecessor.into_iter().collect::<Vec<_>>());
        return Ok(Published {
            generation: predecessor.unwrap_or_default(),
            digest: String::new(),
        });
    }

    let highest = list_generations(&dir).into_iter().map(|(n, _)| n).max();
    let n = highest
        .into_iter()
        .chain(predecessor)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(PublishError::GenerationExhausted)?;
    let text = split_schema::serialize_generation(records).map_err(PublishError::Schema)?;
    let bytes = text.as_bytes();
    crate::write_0600_atomic(&dir.join(generation_name(n)), bytes).map_err(PublishError::Io)?;
    let digest = digest_key(bytes);
    let n_text = n.to_string();
    let pair_text = match selected {
        Some(key) => Some(
            key.format_canonical()
                .map_err(|_| PublishError::Schema(SchemaError::InvalidField))?,
        ),
        None => None,
    };
    let mut set: Vec<(&str, &str)> = vec![("split_generation", &n_text), ("split_digest", &digest)];
    if let Some(text) = &pair_text {
        set.push(("split_pair", text));
    }
    let remove: &[&str] = if pair_text.is_none() {
        &["split_pair"]
    } else {
        &[]
    };
    config::publish_kv_changes(config::CAMERAS_CONF, &set, remove).map_err(PublishError::Io)?;
    let mut keep = vec![n];
    if let Some(p) = predecessor {
        if p != n {
            keep.push(p);
        }
    }
    retain_only(&dir, &keep);
    Ok(Published {
        generation: n,
        digest,
    })
}

fn record_matches(record: &AuthorizationRecord, key: &SplitPairKey) -> bool {
    let side = |f: &split_schema::SideFields, k: &crate::split_key::SplitUnitKey| {
        f.identity == k.identity
            && f.controller == k.controller
            && f.domain == k.domain
            && f.ports == k.ports
    };
    side(&record.rgb, &key.rgb) && side(&record.ir, &key.ir)
}

/// Read the current publication without locks (ADR-0032 §4.1.3 reader).
#[must_use]
pub fn read_split() -> SplitReadState {
    read_camera_selection().split
}

/// Read ordinary selection and split authorization as one coherent snapshot.
///
/// Only a missing referenced generation permits one configuration re-read.
/// An unchanged missing reference refuses; a moved reference is read once
/// more. Invalid final selection cannot be repaired by a valid generation.
#[must_use]
pub fn read_camera_selection() -> CameraSelectionSnapshot {
    read_camera_selection_with(config::observe_camera_conf, |generation| {
        std::fs::read(generation_dir().join(generation_name(generation)))
    })
}

fn read_camera_selection_with(
    mut observe: impl FnMut() -> config::CameraConfObservation,
    mut read: impl FnMut(u64) -> std::io::Result<Vec<u8>>,
) -> CameraSelectionSnapshot {
    let mut observation = observe();
    let split = match read_observation(&observation, &mut read) {
        Ok(state) => state,
        Err(generation) => {
            let final_observation = observe();
            // A mode/pin-only change does not make the missing immutable file
            // appear. Retain the final config, but do not read that file twice.
            let unchanged =
                generation_reference(&observation) == generation_reference(&final_observation);
            observation = final_observation;
            if unchanged {
                if matches!(
                    observation.selection,
                    config::CameraSelectionObservation::Malformed { .. }
                ) && !matches!(
                    observation.split,
                    SplitConfObservation::MalformedSelection { .. }
                ) {
                    SplitReadState::Malformed
                } else {
                    SplitReadState::MalformedGeneration { generation }
                }
            } else {
                read_observation(&observation, &mut read)
                    .unwrap_or_else(|generation| SplitReadState::MalformedGeneration { generation })
            }
        }
    };
    CameraSelectionSnapshot { observation, split }
}

// Reader retry identity includes an invalid pair's independently validated
// reference. The writer helper above deliberately accepts only valid config.
fn generation_reference(obs: &config::CameraConfObservation) -> Option<(u64, &str)> {
    match &obs.split {
        SplitConfObservation::Reference {
            generation, digest, ..
        }
        | SplitConfObservation::MalformedSelection { generation, digest } => {
            Some((*generation, digest))
        }
        SplitConfObservation::None | SplitConfObservation::Malformed => None,
    }
}

fn read_observation(
    obs: &config::CameraConfObservation,
    read: &mut impl FnMut(u64) -> std::io::Result<Vec<u8>>,
) -> Result<SplitReadState, u64> {
    if matches!(
        obs.selection,
        config::CameraSelectionObservation::Unreadable { .. }
    ) {
        return Ok(SplitReadState::Unreadable);
    }
    // Malformed pair text retains generation diagnostics, but a malformed
    // ordinary selection must not become Valid merely because its split
    // reference and generation are well formed.
    if matches!(
        obs.selection,
        config::CameraSelectionObservation::Malformed { .. }
    ) && !matches!(obs.split, SplitConfObservation::MalformedSelection { .. })
    {
        return Ok(SplitReadState::Malformed);
    }
    match &obs.split {
        SplitConfObservation::None => Ok(SplitReadState::Absent),
        SplitConfObservation::Malformed => Ok(SplitReadState::Malformed),
        SplitConfObservation::MalformedSelection { generation, digest } => {
            Ok(match read_generation(*generation, digest, None, read) {
                Ok(SplitReadState::Valid { records, .. }) => SplitReadState::UnresolvedSelection {
                    generation: *generation,
                    record_count: records.len(),
                },
                Ok(other) => other,
                Err(generation) => SplitReadState::MalformedGeneration { generation },
            })
        }
        SplitConfObservation::Reference {
            generation,
            digest,
            pair,
        } => read_generation(*generation, digest, pair.as_deref(), read),
    }
}

fn read_generation(
    generation: u64,
    digest: &str,
    pair: Option<&str>,
    read: &mut impl FnMut(u64) -> std::io::Result<Vec<u8>>,
) -> Result<SplitReadState, u64> {
    Ok(match read(generation) {
        Ok(bytes) => {
            if digest.strip_prefix("sha256:") != Some(digest_value(&bytes).as_str()) {
                return Ok(SplitReadState::DigestMismatch { generation });
            }
            // The generation is text under the same rules as cameras.conf:
            // invalid UTF-8 is Malformed, never normalized into records.
            let Ok(text) = std::str::from_utf8(&bytes) else {
                return Ok(SplitReadState::MalformedGeneration { generation });
            };
            match split_schema::parse_generation(text) {
                GenerationObservation::Malformed { .. } => {
                    SplitReadState::MalformedGeneration { generation }
                }
                GenerationObservation::Valid { records } => match pair {
                    None => SplitReadState::Valid {
                        generation,
                        records,
                        selected: None,
                    },
                    Some(text) => match SplitPairKey::parse_canonical(text) {
                        Ok(key) if records.iter().any(|r| record_matches(r, &key)) => {
                            SplitReadState::Valid {
                                generation,
                                records,
                                selected: Some(key),
                            }
                        }
                        _ => SplitReadState::UnresolvedSelection {
                            generation,
                            record_count: records.len(),
                        },
                    },
                },
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(generation),
        Err(_) => SplitReadState::Unreadable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split_schema::SideFields;
    use crate::testenv;

    fn side(identity: &str, path: &str, ports: &[u8]) -> SideFields {
        SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain: crate::split_key::SplitDomain::Usb2,
            ports: ports.to_vec(),
        }
    }

    fn record(rgb_id: &str, ir_id: &str) -> AuthorizationRecord {
        AuthorizationRecord {
            rgb: side(rgb_id, "/dev/video0", &[8]),
            ir: side(ir_id, "/dev/video1", &[5]),
        }
    }

    fn pair_key(rgb_id: &str, ir_id: &str) -> SplitPairKey {
        SplitPairKey {
            rgb: crate::split_key::SplitUnitKey {
                identity: rgb_id.into(),
                controller: "0000:00:14.0".into(),
                domain: crate::split_key::SplitDomain::Usb2,
                ports: vec![8],
            },
            ir: crate::split_key::SplitUnitKey {
                identity: ir_id.into(),
                controller: "0000:00:14.0".into(),
                domain: crate::split_key::SplitDomain::Usb2,
                ports: vec![5],
            },
        }
    }

    /// One isolated config dir per call, serialized by the crate env lock.
    struct Env {
        _g: std::sync::MutexGuard<'static, ()>,
        dir: PathBuf,
    }

    fn env() -> Env {
        let g = testenv::lock();
        let dir = std::env::temp_dir().join(format!(
            "irlume-split-publish-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        Env { _g: g, dir }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            std::env::remove_var("IRLUME_CONFIG_DIR");
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn generation_file(dir: &Path, n: u64, records: &[AuthorizationRecord]) -> String {
        let text = split_schema::serialize_generation(records).unwrap();
        std::fs::create_dir_all(dir.join(GENERATION_DIR)).unwrap();
        std::fs::write(dir.join(GENERATION_DIR).join(generation_name(n)), &text).unwrap();
        text
    }

    #[test]
    fn a_publication_lands_whole() {
        let env = env();
        let published = publish_split(&[record("a:1", "b:2")], Some(&pair_key("a:1", "b:2")))
            .expect("publication");
        assert_eq!(published.generation, 1);
        assert!(published.digest.starts_with("sha256:"));
        match read_split() {
            SplitReadState::Valid {
                generation,
                records,
                selected,
            } => {
                assert_eq!(generation, 1);
                assert_eq!(records.len(), 1);
                assert_eq!(selected, Some(pair_key("a:1", "b:2")));
            }
            other => panic!("expected Valid, got {other:?}"),
        }
        assert_eq!(
            config::read_camera_pin().rgb.as_deref(),
            None,
            "the ordinary pin must be untouched"
        );
        drop(env);
    }

    #[test]
    fn n_is_never_reused_after_a_crash_between_write_and_publish() {
        let env = env();
        // Crashed writer: referenced 3, unreferenced orphan 4 on disk.
        let referenced = generation_file(&env.dir, 3, &[record("a:1", "b:2")]);
        generation_file(&env.dir, 4, &[record("c:3", "d:4")]);
        let digest = digest_key(referenced.as_bytes());
        config::write_kvs(
            config::CAMERAS_CONF,
            &[("split_generation", "3"), ("split_digest", &digest)],
        )
        .unwrap();
        let published = publish_split(&[record("e:5", "f:6")], None).expect("publication");
        assert_eq!(published.generation, 5, "4 must not be reused");
        let names: Vec<u64> = list_generations(&env.dir.join(GENERATION_DIR))
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            names,
            vec![3, 5],
            "orphan 4 is collected, 3 is the predecessor"
        );
        drop(env);
    }

    #[test]
    fn a_crash_before_rename_leaves_a_temp_that_the_sweep_and_next_write_remove() {
        let env = env();
        std::fs::create_dir_all(env.dir.join(GENERATION_DIR)).unwrap();
        let temp = env.dir.join(GENERATION_DIR).join(".9.conf.tmp.1234.0");
        std::fs::write(&temp, b"partial").unwrap();
        sweep_split_artifacts().expect("sweep");
        assert!(!temp.exists(), "the sweep removes writer temporaries");
        std::fs::write(&temp, b"partial").unwrap();
        publish_split(&[record("a:1", "b:2")], None).expect("publication");
        assert!(!temp.exists(), "the next write removes writer temporaries");
        drop(env);
    }

    #[test]
    fn retention_keeps_the_referenced_and_the_predecessor_only() {
        let env = env();
        for _ in 0..3 {
            publish_split(&[record("a:1", "b:2")], None).expect("publication");
        }
        let names: Vec<u64> = list_generations(&env.dir.join(GENERATION_DIR))
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec![2, 3]);
        drop(env);
    }

    #[test]
    fn the_first_publication_has_no_predecessor() {
        let env = env();
        publish_split(&[record("a:1", "b:2")], None).expect("publication");
        assert_eq!(list_generations(&env.dir.join(GENERATION_DIR)).len(), 1);
        drop(env);
    }

    #[test]
    fn removing_the_selected_pair_keeps_the_collection() {
        let env = env();
        publish_split(
            &[record("a:1", "b:2"), record("c:3", "d:4")],
            Some(&pair_key("a:1", "b:2")),
        )
        .expect("publication");
        let published = publish_split(&[record("c:3", "d:4")], None).expect("publication");
        match read_split() {
            SplitReadState::Valid {
                generation,
                records,
                selected,
            } => {
                assert_eq!(generation, published.generation);
                assert_eq!(records.len(), 1);
                assert_eq!(selected, None, "only the selection is dropped");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
        drop(env);
    }

    #[test]
    fn removing_the_last_record_drops_all_split_keys() {
        let env = env();
        publish_split(&[record("a:1", "b:2")], Some(&pair_key("a:1", "b:2"))).expect("publication");
        publish_split(&[], None).expect("removal");
        assert_eq!(read_split(), SplitReadState::Absent);
        drop(env);
    }

    #[test]
    fn a_reader_sees_whole_old_or_whole_new() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let env = env();
        publish_split(&[record("a:1", "b:2")], None).expect("first");
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match read_split() {
                        SplitReadState::Valid {
                            generation,
                            records,
                            ..
                        } => {
                            assert_eq!(records.len(), 1);
                            assert!(generation >= 1);
                        }
                        other => panic!("reader saw a mix: {other:?}"),
                    }
                }
            })
        };
        for i in 0..20 {
            publish_split(&[record("a:1", &format!("b:{i}"))], None).expect("publish");
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();
        drop(env);
    }

    #[test]
    fn digest_mismatch_refuses() {
        let env = env();
        let published = publish_split(&[record("a:1", "b:2")], None).expect("publication");
        let path = env
            .dir
            .join(GENERATION_DIR)
            .join(generation_name(published.generation));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(b'\n');
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_split(),
            SplitReadState::DigestMismatch {
                generation: published.generation
            }
        );
        drop(env);
    }

    #[test]
    fn a_missing_generation_refuses_after_one_retry() {
        let env = env();
        let published = publish_split(&[record("a:1", "b:2")], None).expect("publication");
        std::fs::remove_file(
            env.dir
                .join(GENERATION_DIR)
                .join(generation_name(published.generation)),
        )
        .unwrap();
        assert_eq!(
            read_split(),
            SplitReadState::MalformedGeneration {
                generation: published.generation
            }
        );
        drop(env);
    }

    #[test]
    fn a_retry_refuses_a_moved_generation_with_malformed_ordinary_selection() {
        let env = env();
        let records = [record("c:3", "d:4")];
        let text = generation_file(&env.dir, 2, &records);
        std::fs::write(
            config::config_path(config::CAMERAS_CONF),
            format!(
                "mode=pinned\nsplit_generation=2\nsplit_digest={}\n",
                digest_key(text.as_bytes())
            ),
        )
        .unwrap();
        // The original reader observed generation 1 before publication moved.
        // Its missing file forces the actual retry against the new config.
        let initial = config::parse_camera_conf(&format!(
            "split_generation=1\nsplit_digest={}\n",
            digest_key(b"old generation")
        ));
        let mut first = Some(initial);
        let snapshot = read_camera_selection_with(
            || first.take().unwrap_or_else(config::observe_camera_conf),
            |generation| std::fs::read(generation_dir().join(generation_name(generation))),
        );
        assert_eq!(
            snapshot.split(),
            &SplitReadState::Malformed,
            "a valid generation cannot repair a malformed final selection"
        );
        assert!(matches!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Malformed {
                problem: config::CameraConfProblem::PinnedWithoutPair,
                ..
            }
        ));
    }

    fn reference_observation(generation: u64, ordinary: &str) -> config::CameraConfObservation {
        config::parse_camera_conf(&format!(
            "{ordinary}\nsplit_generation={generation}\nsplit_digest={}\n",
            digest_key(b"removed generation")
        ))
    }

    #[test]
    fn snapshot_retry_retains_final_ordinary_pin_and_selected_split() {
        let env = env();
        let text = generation_file(&env.dir, 2, &[record("c:3", "d:4")]);
        config::write_camera_pin("/dev/new-rgb", "/dev/new-ir", "new-rgb", "new-ir").unwrap();
        config::write_kvs(
            config::CAMERAS_CONF,
            &[
                ("mode", "pinned"),
                ("split_generation", "2"),
                ("split_digest", &digest_key(text.as_bytes())),
                (
                    "split_pair",
                    &pair_key("c:3", "d:4").format_canonical().unwrap(),
                ),
            ],
        )
        .unwrap();
        let mut first = Some(reference_observation(
            1,
            "rgb=/dev/old-rgb\nir=/dev/old-ir\nmode=pinned",
        ));
        let mut observations = 0;
        let mut reads = Vec::new();
        let snapshot = read_camera_selection_with(
            || {
                observations += 1;
                first.take().unwrap_or_else(config::observe_camera_conf)
            },
            |generation| {
                reads.push(generation);
                std::fs::read(generation_dir().join(generation_name(generation)))
            },
        );
        assert_eq!(observations, 2);
        assert_eq!(reads, vec![1, 2]);
        assert_eq!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Pinned {
                pair: config::PinnedPair {
                    rgb: "/dev/new-rgb".into(),
                    ir: "/dev/new-ir".into(),
                    rgb_id: Some("new-rgb".into()),
                    ir_id: Some("new-ir".into()),
                },
                explicit: true,
            }
        );
        match snapshot.split() {
            SplitReadState::Valid {
                generation,
                records,
                selected,
            } => {
                assert_eq!(*generation, 2);
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].rgb.identity, "c:3");
                assert_eq!(records[0].ir.identity, "d:4");
                assert_eq!(selected.as_ref(), Some(&pair_key("c:3", "d:4")));
            }
            other => panic!("expected coherent generation 2, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_retry_retains_automatic_mode_instead_of_old_pin() {
        let env = env();
        let text = generation_file(&env.dir, 2, &[record("c:3", "d:4")]);
        config::write_kvs(
            config::CAMERAS_CONF,
            &[
                ("mode", "automatic"),
                ("rgb", "/dev/retained-rgb"),
                ("ir", "/dev/retained-ir"),
                ("split_generation", "2"),
                ("split_digest", &digest_key(text.as_bytes())),
            ],
        )
        .unwrap();
        let mut first = Some(reference_observation(
            1,
            "rgb=/dev/old-rgb\nir=/dev/old-ir\nmode=pinned",
        ));
        let snapshot = read_camera_selection_with(
            || first.take().unwrap_or_else(config::observe_camera_conf),
            |generation| std::fs::read(generation_dir().join(generation_name(generation))),
        );
        assert_eq!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Automatic {
                retained: Some(config::PinnedPair {
                    rgb: "/dev/retained-rgb".into(),
                    ir: "/dev/retained-ir".into(),
                    rgb_id: None,
                    ir_id: None,
                }),
            }
        );
        assert!(matches!(
            snapshot.split(),
            SplitReadState::Valid {
                generation: 2,
                selected: None,
                ..
            }
        ));
    }

    #[test]
    fn snapshot_retry_is_bounded_when_second_generation_is_also_missing() {
        let _env = env();
        let mut observations = 0;
        let mut reads = Vec::new();
        let snapshot = read_camera_selection_with(
            || {
                observations += 1;
                reference_observation(observations, "mode=automatic")
            },
            |generation| {
                reads.push(generation);
                std::fs::read(generation_dir().join(generation_name(generation)))
            },
        );
        assert_eq!(observations, 2, "there is no third publication observation");
        assert_eq!(reads, vec![1, 2]);
        assert_eq!(
            snapshot.split(),
            &SplitReadState::MalformedGeneration { generation: 2 }
        );
        assert!(matches!(
            snapshot.observation().split,
            SplitConfObservation::Reference { generation: 2, .. }
        ));
    }

    #[test]
    fn snapshot_missing_unchanged_generation_does_not_read_twice() {
        let _env = env();
        let mut observations = 0;
        let mut reads = Vec::new();
        let snapshot = read_camera_selection_with(
            || {
                observations += 1;
                reference_observation(
                    1,
                    if observations == 1 {
                        "mode=automatic"
                    } else {
                        "rgb=/dev/new-rgb\nir=/dev/new-ir\nmode=pinned"
                    },
                )
            },
            |generation| {
                reads.push(generation);
                std::fs::read(generation_dir().join(generation_name(generation)))
            },
        );
        assert_eq!(observations, 2);
        assert_eq!(reads, vec![1]);
        assert_eq!(
            snapshot.split(),
            &SplitReadState::MalformedGeneration { generation: 1 }
        );
        assert!(matches!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Pinned { explicit: true, .. }
        ));
    }

    #[test]
    fn snapshot_unchanged_missing_reference_with_malformed_pair_is_not_read_twice() {
        let _env = env();
        let digest = digest_key(b"removed generation");
        std::fs::write(
            config::config_path(config::CAMERAS_CONF),
            format!("split_generation=1\nsplit_digest={digest}\nsplit_pair=invalid\n"),
        )
        .unwrap();
        let mut first = Some(reference_observation(1, "mode=automatic"));
        let mut observations = 0;
        let mut reads = Vec::new();
        let snapshot = read_camera_selection_with(
            || {
                observations += 1;
                first.take().unwrap_or_else(config::observe_camera_conf)
            },
            |generation| {
                reads.push(generation);
                std::fs::read(generation_dir().join(generation_name(generation)))
            },
        );
        assert_eq!(observations, 2);
        assert_eq!(
            reads,
            vec![1],
            "an unchanged missing reference is read once"
        );
        assert_eq!(
            snapshot.split(),
            &SplitReadState::MalformedGeneration { generation: 1 }
        );
        assert_eq!(
            snapshot.observation().split,
            SplitConfObservation::MalformedSelection {
                generation: 1,
                digest
            }
        );
        assert!(matches!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Malformed { .. }
        ));
    }

    #[test]
    fn snapshot_retry_retains_unreadable_final_config() {
        let _env = env();
        std::fs::create_dir(config::config_path(config::CAMERAS_CONF)).unwrap();
        let mut first = Some(reference_observation(1, "mode=automatic"));
        let mut reads = Vec::new();
        let snapshot = read_camera_selection_with(
            || first.take().unwrap_or_else(config::observe_camera_conf),
            |generation| {
                reads.push(generation);
                std::fs::read(generation_dir().join(generation_name(generation)))
            },
        );
        assert_eq!(reads, vec![1]);
        assert_eq!(snapshot.split(), &SplitReadState::Unreadable);
        assert!(matches!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Unreadable { .. }
        ));
    }

    #[test]
    fn snapshot_retry_to_fresh_clears_both_choices() {
        let _env = env();
        let mut first = Some(reference_observation(1, "rgb=/dev/old-rgb\nir=/dev/old-ir"));
        let mut reads = Vec::new();
        let snapshot = read_camera_selection_with(
            || first.take().unwrap_or_else(config::observe_camera_conf),
            |generation| {
                reads.push(generation);
                std::fs::read(generation_dir().join(generation_name(generation)))
            },
        );
        assert_eq!(reads, vec![1]);
        assert_eq!(snapshot.split(), &SplitReadState::Absent);
        assert_eq!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Fresh
        );
        assert_eq!(snapshot.observation().split, SplitConfObservation::None);
    }

    #[test]
    fn snapshot_preserves_ordinary_absent_and_unselected_authorization_controls() {
        let _env = env();
        config::write_camera_pin("/dev/ordinary-rgb", "/dev/ordinary-ir", "rid", "iid").unwrap();
        let ordinary = read_camera_selection();
        assert_eq!(ordinary.split(), &SplitReadState::Absent);
        publish_split(&[record("c:3", "d:4")], None).unwrap();
        let authorized = read_camera_selection();
        assert_eq!(
            authorized.observation().selection,
            ordinary.observation().selection
        );
        assert!(matches!(
            authorized.split(),
            SplitReadState::Valid { selected: None, .. }
        ));
    }

    #[test]
    fn malformed_ordinary_selection_without_split_keys_refuses() {
        let _env = env();
        std::fs::write(config::config_path(config::CAMERAS_CONF), "mode=pinned\n").unwrap();
        let snapshot = read_camera_selection();
        assert_eq!(snapshot.split(), &SplitReadState::Malformed);
        assert!(matches!(
            snapshot.observation().selection,
            config::CameraSelectionObservation::Malformed { .. }
        ));
    }

    #[test]
    fn a_reader_retries_when_the_reference_moved() {
        let env = env();
        let published = publish_split(&[record("a:1", "b:2")], None).expect("publication");
        // Another writer publishes generation 2 and our 1 is gone before we
        // read it: the reader must pick up the new reference exactly once.
        generation_file(&env.dir, 2, &[record("c:3", "d:4")]);
        let text = split_schema::serialize_generation(&[record("c:3", "d:4")]).unwrap();
        config::write_kvs(
            config::CAMERAS_CONF,
            &[
                ("split_generation", "2"),
                ("split_digest", &digest_key(text.as_bytes())),
            ],
        )
        .unwrap();
        std::fs::remove_file(
            env.dir
                .join(GENERATION_DIR)
                .join(generation_name(published.generation)),
        )
        .unwrap();
        match read_split() {
            SplitReadState::Valid {
                generation,
                records,
                ..
            } => {
                assert_eq!(generation, 2);
                assert_eq!(records[0].rgb.identity, "c:3");
            }
            other => panic!("expected Valid after retry, got {other:?}"),
        }
        drop(env);
    }

    #[test]
    fn a_malformed_generation_refuses() {
        let env = env();
        std::fs::create_dir_all(env.dir.join(GENERATION_DIR)).unwrap();
        let body = "version=2\n";
        std::fs::write(env.dir.join(GENERATION_DIR).join(generation_name(1)), body).unwrap();
        config::write_kvs(
            config::CAMERAS_CONF,
            &[
                ("split_generation", "1"),
                ("split_digest", &digest_key(body.as_bytes())),
            ],
        )
        .unwrap();
        assert_eq!(
            read_split(),
            SplitReadState::MalformedGeneration { generation: 1 }
        );
        drop(env);
    }

    #[test]
    fn the_writer_refuses_an_unresolved_selection() {
        let env = env();
        assert!(matches!(
            publish_split(&[record("a:1", "b:2")], Some(&pair_key("x:9", "y:8"))),
            Err(PublishError::Schema(_))
        ));
        assert_eq!(
            read_split(),
            SplitReadState::Absent,
            "nothing was published"
        );
        drop(env);
    }

    #[test]
    fn an_unresolved_pair_refuses_with_no_fallback() {
        let env = env();
        // A hand-built state that names a pair the generation does not hold:
        // the reader must refuse, never fall back to the ordinary pin.
        let text = generation_file(&env.dir, 1, &[record("a:1", "b:2")]);
        config::publish_kv_changes(
            config::CAMERAS_CONF,
            &[
                ("split_generation", "1"),
                ("split_digest", &digest_key(text.as_bytes())),
                (
                    "split_pair",
                    &pair_key("x:9", "y:8").format_canonical().unwrap(),
                ),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            read_split(),
            SplitReadState::UnresolvedSelection {
                generation: 1,
                record_count: 1
            }
        );
        drop(env);
    }

    #[test]
    fn a_referenced_generation_without_a_pair_is_valid_and_selects_nothing() {
        let env = env();
        publish_split(&[record("a:1", "b:2")], None).expect("publication");
        match read_split() {
            SplitReadState::Valid { selected, .. } => assert_eq!(selected, None),
            other => panic!("expected Valid, got {other:?}"),
        }
        drop(env);
    }

    #[test]
    fn absent_leaves_ordinary_pin_behavior() {
        let env = env();
        config::write_camera_pin("/dev/video0", "/dev/video2", "rid", "iid").unwrap();
        assert_eq!(read_split(), SplitReadState::Absent);
        assert_eq!(
            config::read_camera_pin().rgb.as_deref(),
            Some("/dev/video0"),
            "the ordinary pin keeps its meaning"
        );
        drop(env);
    }

    #[test]
    fn a_published_store_does_not_change_ordinary_selection() {
        let env = env();
        config::write_camera_pin("/dev/video0", "/dev/video2", "rid", "iid").unwrap();
        publish_split(&[record("a:1", "b:2")], Some(&pair_key("a:1", "b:2"))).expect("publication");
        let obs = config::observe_camera_conf();
        assert!(
            matches!(
                obs.selection,
                config::CameraSelectionObservation::Pinned { .. }
            ),
            "ordinary selection must be untouched by a split publication"
        );
        assert_eq!(
            config::read_camera_pin().rgb.as_deref(),
            Some("/dev/video0")
        );
        match read_split() {
            SplitReadState::Valid {
                selected: Some(_), ..
            } => {}
            other => panic!("expected Valid with a selection, got {other:?}"),
        }
        // No caller in this slice hands split candidates to enrollment or
        // authentication: the store is inert for the engine (ADR-0032 §7).
        drop(env);
    }

    #[test]
    fn a_foreign_file_is_never_swept() {
        let env = env();
        std::fs::create_dir_all(env.dir.join(GENERATION_DIR)).unwrap();
        let foreign = env.dir.join(GENERATION_DIR).join(".notes.tmp.1.0");
        let real_temp = env.dir.join(GENERATION_DIR).join(".9.conf.tmp.1.0");
        std::fs::write(&foreign, b"foreign").unwrap();
        std::fs::write(&real_temp, b"temp").unwrap();
        sweep_split_artifacts().expect("sweep");
        assert!(foreign.exists(), "a foreign file must never be deleted");
        assert!(!real_temp.exists(), "a real writer temporary is swept");
        drop(env);
    }

    #[test]
    fn invalid_utf8_in_a_generation_is_malformed() {
        let env = env();
        std::fs::create_dir_all(env.dir.join(GENERATION_DIR)).unwrap();
        let body: &[u8] = b"\xff\xfeversion=1\n";
        std::fs::write(env.dir.join(GENERATION_DIR).join(generation_name(1)), body).unwrap();
        config::publish_kv_changes(
            config::CAMERAS_CONF,
            &[
                ("split_generation", "1"),
                ("split_digest", &digest_key(body)),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            read_split(),
            SplitReadState::MalformedGeneration { generation: 1 }
        );
        drop(env);
    }

    #[test]
    fn removal_drops_the_key_lines_entirely() {
        let env = env();
        publish_split(&[record("a:1", "b:2")], Some(&pair_key("a:1", "b:2"))).expect("publication");
        publish_split(&[], None).expect("removal");
        let text = std::fs::read_to_string(config::config_path(config::CAMERAS_CONF)).unwrap();
        assert!(
            !text.contains("split_"),
            "removal must drop the key lines, got {text:?}"
        );
        drop(env);
    }

    #[test]
    fn the_writer_refuses_a_malformed_config() {
        let env = env();
        config::write_kvs(
            config::CAMERAS_CONF,
            &[("rgb", "/dev/a"), ("rgb", "/dev/b")],
        )
        .unwrap();
        let published = publish_split(&[record("a:1", "b:2")], None);
        assert!(matches!(published, Err(PublishError::MalformedConfig)));
        drop(env);
    }

    #[test]
    fn a_schema_error_propagates_without_publishing() {
        let env = env();
        let mut bad = record("a:1", "b:2");
        bad.rgb.ports = (1..=7).collect();
        assert!(matches!(
            publish_split(&[bad], None),
            Err(PublishError::Schema(_))
        ));
        assert_eq!(read_split(), SplitReadState::Absent);
        drop(env);
    }

    #[test]
    fn the_generation_directory_is_created_root_only() {
        let env = env();
        publish_split(&[record("a:1", "b:2")], None).expect("publication");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(env.dir.join(GENERATION_DIR))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "generation dir must be 0700, got {mode:o}");
        }
        drop(env);
    }

    #[test]
    fn crash_after_publish_leaves_extra_generations_that_the_next_write_collects() {
        let env = env();
        // A writer that crashed after step 4 but before retention: the
        // reference landed and older generations linger (ADR-0032 §4.1.3
        // crash table).
        generation_file(&env.dir, 1, &[record("a:1", "b:2")]);
        generation_file(&env.dir, 2, &[record("c:3", "d:4")]);
        let text = generation_file(&env.dir, 3, &[record("e:5", "f:6")]);
        config::write_kvs(
            config::CAMERAS_CONF,
            &[
                ("split_generation", "3"),
                ("split_digest", &digest_key(text.as_bytes())),
            ],
        )
        .unwrap();
        let published = publish_split(&[record("g:7", "h:8")], None).expect("publication");
        assert_eq!(published.generation, 4);
        let names: Vec<u64> = list_generations(&env.dir.join(GENERATION_DIR))
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec![3, 4], "1 and 2 are collected later, i.e. now");
        drop(env);
    }

    #[test]
    fn the_start_sweep_deletes_only_temps_and_orphans_above_the_reference() {
        let env = env();
        let referenced = generation_file(&env.dir, 3, &[record("a:1", "b:2")]);
        generation_file(&env.dir, 1, &[record("old:1", "old:2")]);
        generation_file(&env.dir, 5, &[record("x:1", "y:2")]);
        std::fs::write(env.dir.join(GENERATION_DIR).join(".8.conf.tmp.1.0"), b"t").unwrap();
        config::write_kvs(
            config::CAMERAS_CONF,
            &[
                ("split_generation", "3"),
                ("split_digest", &digest_key(referenced.as_bytes())),
            ],
        )
        .unwrap();
        sweep_split_artifacts().expect("sweep");
        let names: Vec<u64> = list_generations(&env.dir.join(GENERATION_DIR))
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            names,
            vec![1, 3],
            "5 is an orphan above the reference, 1 may be the predecessor"
        );
        drop(env);
    }
}
