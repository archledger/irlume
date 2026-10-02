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
    /// The referenced generation's bytes do not match `split_digest`.
    DigestMismatch,
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

/// Writer temporaries from `write_0600_atomic`: `.{name}.tmp.{pid}.{seq}`.
/// Only that exact shape is swept, so a foreign file is never deleted
/// (ADR-0032 §4.1.3).
fn is_writer_temp(name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix('.')
        .and_then(|n| n.split_once(".tmp.").map(|(_, tail)| tail))
    else {
        return false;
    };
    rest.split_once('.').is_some_and(|(pid, seq)| {
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

    if records.is_empty() {
        // Removal of the last record drops the split keys entirely; the just
        // de-referenced generation counts as the predecessor and is kept.
        config::write_kvs(
            config::CAMERAS_CONF,
            &[
                ("split_generation", ""),
                ("split_digest", ""),
                ("split_pair", ""),
            ],
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
    let pair_text = selected
        .map(SplitPairKey::format_canonical)
        .unwrap_or_default();
    config::write_kvs(
        config::CAMERAS_CONF,
        &[
            ("split_generation", &n_text),
            ("split_digest", &digest),
            ("split_pair", &pair_text),
        ],
    )
    .map_err(PublishError::Io)?;
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
    let obs = config::observe_camera_conf();
    if matches!(
        obs.selection,
        config::CameraSelectionObservation::Unreadable { .. }
    ) {
        return SplitReadState::Unreadable;
    }
    match &obs.split {
        SplitConfObservation::None => SplitReadState::Absent,
        SplitConfObservation::Malformed => SplitReadState::Malformed,
        SplitConfObservation::Reference {
            generation,
            digest,
            pair,
        } => read_generation(*generation, digest, pair.as_deref(), true),
    }
}

fn read_generation(
    generation: u64,
    digest: &str,
    pair: Option<&str>,
    allow_retry: bool,
) -> SplitReadState {
    match std::fs::read(generation_dir().join(generation_name(generation))) {
        Ok(bytes) => {
            if digest.strip_prefix("sha256:") != Some(digest_value(&bytes).as_str()) {
                return SplitReadState::DigestMismatch;
            }
            match split_schema::parse_generation(&String::from_utf8_lossy(&bytes)) {
                GenerationObservation::Malformed { .. } => SplitReadState::Malformed,
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
                        _ => SplitReadState::Malformed,
                    },
                },
            }
        }
        // The file is missing: re-read cameras.conf once and retry only if
        // the reference moved (a concurrent publication), else refuse.
        Err(e) if e.kind() == ErrorKind::NotFound && allow_retry => {
            let moved = split_keys_in(&config::observe_camera_conf());
            match moved {
                Some((g2, d2, p2)) if g2 != generation || d2 != digest => {
                    read_generation(g2, &d2, p2.as_deref(), false)
                }
                _ => SplitReadState::Malformed,
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => SplitReadState::Malformed,
        Err(_) => SplitReadState::Unreadable,
    }
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
            &[
                ("split_generation", "3"),
                ("split_digest", &digest),
                ("split_pair", ""),
            ],
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
        assert_eq!(read_split(), SplitReadState::DigestMismatch);
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
        assert_eq!(read_split(), SplitReadState::Malformed);
        drop(env);
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
                ("split_pair", ""),
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
                ("split_pair", ""),
            ],
        )
        .unwrap();
        assert_eq!(read_split(), SplitReadState::Malformed);
        drop(env);
    }

    #[test]
    fn an_unresolved_pair_refuses_with_no_fallback() {
        let env = env();
        let published = publish_split(&[record("a:1", "b:2")], Some(&pair_key("x:9", "y:8")))
            .expect("publication writes the reference");
        assert!(published.digest.starts_with("sha256:"));
        assert_eq!(read_split(), SplitReadState::Malformed);
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
                ("split_pair", ""),
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
                ("split_pair", ""),
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
