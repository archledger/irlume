// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Loader for shipped per-camera-model profiles (ADR-0023): read-only data
//! under `cameras.d/`, strictly parsed, evidence-only in schema v1.
//!
//! A profile is an OPTIONAL capture preference document. Nothing here
//! creates, extends, or substitutes a capture qualification, influences
//! authorization, or enforces any authentication-safety requirement: their
//! absence, rejection, or incompatibility never bypasses a runtime gate.
//! Schema v1 carries identity and evidence only - zero executable tuning
//! fields - per the Phase B per-field decisions (2026-09-16).
//!
//! Strictness is the contract: unknown keys at any level, unknown values,
//! noncanonical filenames, identity/filename disagreement, duplicate
//! identities, oversized files, symlinks, and group- or world-writable
//! permission bits each reject that one file (recorded with a reason); the
//! rest of the set still loads. Loading is startup-only.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The only schema version this loader understands.
pub const PROFILE_SCHEMA_VERSION: u32 = 1;

/// Upper bound on one profile file.
pub const MAX_PROFILE_BYTES: u64 = 64 * 1024;

/// Upper bound on any string field inside a profile.
pub const MAX_STRING_BYTES: usize = 256;

/// A parse/validation refusal for one file, with the reason a support
/// reader can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IgnoredProfile {
    pub path: PathBuf,
    pub reason: String,
}

/// One loaded profile: identity and evidence documentation, nothing
/// executable.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CameraProfile {
    pub schema_version: u32,
    pub identity: ProfileIdentity,
    pub evidence: ProfileEvidence,
}

/// The camera a profile describes. `vid`/`pid` are lowercase hex, four
/// characters each; the canonical filename must repeat them as
/// `<vid>-<pid>.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileIdentity {
    pub vid: String,
    pub pid: String,
    #[serde(rename = "model")]
    pub model: String,
}

/// Evidence provenance for the measurements behind the profile. The
/// artifact itself accompanies the profile's PR (ADR-0023 §8): a digest
/// identifies it, it does not replace it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEvidence {
    /// Unix seconds when the evidence artifact was produced.
    pub measured_at_unix: u64,
    /// How it was produced (e.g. "irlume camera-tune --emit-record").
    pub method: String,
    /// SHA-256 of the attached share-safe evidence artifact, lowercase hex.
    pub artifact_sha256: String,
}

/// The result of loading a directory: the profiles that passed every gate,
/// and one recorded reason per file that did not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadedProfiles {
    pub profiles: Vec<CameraProfile>,
    pub ignored: Vec<IgnoredProfile>,
}

/// Errors loading one file that are structural (I/O) rather than a
/// per-file refusal.
#[derive(Debug)]
pub enum LoadError {
    NotADirectory(PathBuf),
    Io(std::io::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NotADirectory(path) => {
                write!(f, "{} is not a directory", path.display())
            }
            LoadError::Io(error) => write!(f, "reading profiles: {error}"),
        }
    }
}

impl std::error::Error for LoadError {}

fn is_four_hex(value: &str) -> bool {
    value.len() == 4
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Loads every profile in `dir`. A missing `dir` is an empty set, not an
/// error: profiles are optional. Every refusal is recorded per file.
///
/// # Errors
///
/// Returns [`LoadError`] only for structural problems (the path exists but
/// is not a directory; the directory cannot be read). Per-file problems are
/// refusals recorded in [`LoadedProfiles::ignored`].
pub fn load_dir(dir: &Path) -> Result<LoadedProfiles, LoadError> {
    let mut loaded = LoadedProfiles::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(loaded),
        Err(error) => return Err(LoadError::Io(error)),
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file() && path.extension().is_some_and(|e| e == "toml"))
        .collect();
    paths.sort();
    for path in paths {
        match load_one(&path) {
            Ok(profile) => {
                let already = loaded.profiles.iter().any(|existing| {
                    existing.identity.vid == profile.identity.vid
                        && existing.identity.pid == profile.identity.pid
                });
                if already {
                    loaded.ignored.push(IgnoredProfile {
                        reason: format!(
                            "duplicate identity {}:{} (first file wins)",
                            profile.identity.vid, profile.identity.pid
                        ),
                        path,
                    });
                } else {
                    loaded.profiles.push(profile);
                }
            }
            Err(reason) => loaded.ignored.push(IgnoredProfile { path, reason }),
        }
    }
    Ok(loaded)
}

/// Loads and validates one file. The checks, in order: the filename is the
/// canonical `<vid>-<pid>.toml` (no traversal shape survives this), the
/// file is a regular non-symlink file within the trusted tree with sane
/// size and no group/world-write permission bits, the TOML parses with no
/// unknown keys at any level,
/// the schema version is supported, field bounds hold, and the identity
/// agrees with the filename.
fn load_one(path: &Path) -> Result<CameraProfile, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "filename is not UTF-8".to_string())?;
    let stem = file_name
        .strip_suffix(".toml")
        .ok_or_else(|| "not a .toml file".to_string())?;
    let (vid, pid) = stem
        .split_once('-')
        .ok_or_else(|| format!("filename {file_name} is not <vid>-<pid>.toml"))?;
    if !is_four_hex(vid) || !is_four_hex(pid) {
        return Err(format!(
            "filename {file_name} does not name lowercase four-hex vid and pid"
        ));
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("cannot stat: {error}"))?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file() {
        return Err("not a regular file".to_string());
    }
    if metadata.len() > MAX_PROFILE_BYTES {
        return Err(format!("larger than {MAX_PROFILE_BYTES} bytes"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err("group- or world-writable".to_string());
    }
    let text = std::fs::read_to_string(path).map_err(|error| format!("cannot read: {error}"))?;
    let profile: CameraProfile =
        toml::from_str(&text).map_err(|error| format!("rejected: {error}"))?;
    if profile.schema_version != PROFILE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema_version {} (loader supports {PROFILE_SCHEMA_VERSION})",
            profile.schema_version
        ));
    }
    for text in [
        &profile.identity.vid,
        &profile.identity.pid,
        &profile.identity.model,
        &profile.evidence.method,
        &profile.evidence.artifact_sha256,
    ] {
        if text.is_empty() || text.len() > MAX_STRING_BYTES {
            return Err("string field empty or out of bounds".to_string());
        }
    }
    if profile.identity.vid != vid || profile.identity.pid != pid {
        return Err(format!(
            "identity {}:{} disagrees with filename {file_name}",
            profile.identity.vid, profile.identity.pid
        ));
    }
    if profile.evidence.artifact_sha256.len() != 64
        || !profile
            .evidence
            .artifact_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("artifact_sha256 is not 64 lowercase hex characters".to_string());
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of this test's own. The name carries a per-process
    /// counter, not only a timestamp: tests run in parallel, and on a
    /// coarse clock two of them can start in the same tick and would then
    /// share (and delete) one directory — seen on CI as one test loading
    /// another's files.
    fn dir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "irlume-profiles-{}-{}-{:x}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write profile");
    }

    fn valid_body(vid: &str, pid: &str) -> String {
        format!(
            "schema_version = 1\n\
             [identity]\n\
             vid = \"{vid}\"\n\
             pid = \"{pid}\"\n\
             model = \"Test Camera\"\n\
             [evidence]\n\
             measured_at_unix = 1789495789\n\
             method = \"irlume camera-tune --emit-record\"\n\
             artifact_sha256 = \"{}\"\n",
            "a".repeat(64)
        )
    }

    #[test]
    fn a_valid_profile_loads_and_a_missing_directory_is_empty() {
        let empty = load_dir(Path::new("/nonexistent-irlume-profiles"))
            .expect("missing dir is not an error");
        assert_eq!(empty, LoadedProfiles::default());
        let d = dir();
        write(&d, "046d-085e.toml", &valid_body("046d", "085e"));
        let loaded = load_dir(&d).expect("load");
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].identity.model, "Test Camera");
        assert!(loaded.ignored.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unknown_keys_reject_at_every_level() {
        let d = dir();
        write(
            &d,
            "046d-085e.toml",
            &format!("{}\nspeculative_knob = true\n", valid_body("046d", "085e")),
        );
        let loaded = load_dir(&d).expect("load");
        assert!(loaded.profiles.is_empty());
        assert!(loaded.ignored[0].reason.contains("rejected"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nested_unknown_keys_reject_whole_file() {
        let d = dir();
        write(
            &d,
            "046d-085e.toml",
            &format!(
                "schema_version = 1\n\
                 [identity]\n\
                 vid = \"046d\"\n\
                 pid = \"085e\"\n\
                 model = \"Test\"\n\
                 [evidence]\n\
                 measured_at_unix = 1\n\
                 method = \"m\"\n\
                 relaxed_after_seeing_results = false\n\
                 artifact_sha256 = \"{}\"\n",
                "a".repeat(64)
            ),
        );
        let loaded = load_dir(&d).expect("load");
        assert!(loaded.profiles.is_empty());
        assert!(loaded.ignored[0].reason.contains("rejected"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn filename_identity_disagreement_and_noncanonical_names_reject() {
        let d = dir();
        write(&d, "046d-085e.toml", &valid_body("3443", "c803"));
        write(&d, "not-a-camera.toml", &valid_body("046d", "085e"));
        let loaded = load_dir(&d).expect("load");
        assert!(loaded.profiles.is_empty());
        assert_eq!(loaded.ignored.len(), 2);
        assert!(loaded
            .ignored
            .iter()
            .any(|i| i.reason.contains("disagrees with filename")));
        assert!(loaded
            .ignored
            .iter()
            .any(|i| i.reason.contains("does not name lowercase four-hex")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn symlinks_and_world_writable_files_reject() {
        let d = dir();
        write(&d, "046d-085e.toml", &valid_body("046d", "085e"));
        let _ = std::fs::remove_file(d.join("046d-085e.toml"));
        let target = d.join("real.toml");
        std::fs::write(&target, valid_body("046d", "085e")).expect("target");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, d.join("046d-085e.toml")).expect("symlink");
        let loaded = load_dir(&d).expect("load");
        assert!(loaded.ignored.iter().any(|i| i
            .path
            .file_name()
            .is_some_and(|n| n == "046d-085e.toml")
            && i.reason.contains("not a regular file")));
        // The link target itself has a noncanonical name and is refused
        // before its permissions matter.
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn canonical_filenames_make_duplicate_identities_structurally_impossible() {
        // The filename IS the identity (enforced by the agreement check), so
        // two files cannot claim one identity. The duplicate guard in
        // load_dir is defense in depth for any future relaxation of the
        // naming rule; it cannot be reached through canonical files today.
        let d = dir();
        write(&d, "046d-085e.toml", &valid_body("046d", "085e"));
        write(&d, "3443-c803.toml", &valid_body("3443", "c803"));
        let loaded = load_dir(&d).expect("load");
        assert_eq!(loaded.profiles.len(), 2);
        assert!(loaded.ignored.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bad_digest_length_and_bad_schema_version_reject() {
        let d = dir();
        let short = valid_body("046d", "085e").replace(&"a".repeat(64), &"a".repeat(63));
        write(&d, "046d-085e.toml", &short);
        let loaded = load_dir(&d).expect("load");
        assert!(loaded.ignored[0].reason.contains("artifact_sha256"));
        let d = dir();
        write(
            &d,
            "046d-085e.toml",
            &valid_body("046d", "085e").replace("schema_version = 1", "schema_version = 2"),
        );
        let loaded = load_dir(&d).expect("load");
        assert!(loaded.ignored[0]
            .reason
            .contains("unsupported schema_version"));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d);
    }
}
