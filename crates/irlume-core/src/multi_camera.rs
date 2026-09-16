//! Multi-camera secondary store (ADR-0024 Phase 1): the separate, versioned
//! home for secondary camera groups, never read by pre-multi-camera
//! binaries.
//!
//! Boundary contract (ADR-0024 §1): the legacy enrollment file remains the
//! PRIMARY group's complete store; everything here lives beside it, outside
//! legacy discovery. Secondary activation is bound to a cryptographic digest
//! of the exact primary-file bytes it was authorized against (§1.1): any
//! primary change - including a semantically equivalent legacy rewrite -
//! makes secondary groups INACTIVE until an explicit authorized transaction
//! republishes the binding. Because activation is snapshot-bound, profile
//! associations inside this store may use the primary's profile names: a
//! rename changes the primary bytes, which deactivates the store before the
//! stale association could ever be used.
//!
//! Parsing is whole-store (§1.2): an unsupported version or any invalid
//! supported-version record rejects the ENTIRE store; nothing is partially
//! accepted, and a rejected store is never treated as an empty file a later
//! add may silently overwrite. One inherited leniency is stated honestly:
//! [`FaceScan`]'s serde contract is fixed by the legacy format and does not
//! reject unknown fields, so scan-level unknown fields are ignored exactly
//! as legacy readers ignore them; all SECONDARY-structural strictness
//! (versions, ids, references, duplicates, bounds) is enforced here.
//!
//! Nothing in this module authorizes authentication: Phase 1 exposes
//! validated data and the activation predicate only.

use crate::storage::FaceScan;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The secondary store's location for `user`: a `cameras/` subdirectory of
/// the state dir, deliberately outside the legacy enrollment namespace
/// (`{state_dir}/{user}.json` exact-name lookups, ADR-0024 §1). Legacy
/// readers never enumerate this subdirectory, so they can neither discover
/// nor open the store. Writers create the directory before publication.
#[must_use]
pub fn secondary_store_path(user: &str) -> PathBuf {
    irlume_common::state_dir()
        .join("cameras")
        .join(format!("{user}.json"))
}

/// The primary enrollment's on-disk path for `user` - the exact file whose
/// bytes the secondary store's activation digest is taken over. Exposed so
/// the coordinator's pin and grant boundary read the same authoritative
/// snapshot the legacy loader resolves.
#[must_use]
pub fn primary_enrollment_path(user: &str) -> PathBuf {
    irlume_common::state_dir().join(format!("{user}.json"))
}

/// The only secondary-store format version this code reads and writes.
pub const SECONDARY_STORE_VERSION: u32 = 1;

/// Account-wide bounds (ADR-0024 §3: fixed and tested in Phase 1).
pub const MAX_GROUPS: usize = 8;
pub const MAX_SCANS_PER_PROFILE_GROUP: usize = 30;
pub const MAX_TOTAL_SCANS: usize = 64;
/// Generous byte ceiling for the serialized store (embeddings dominate).
pub const MAX_STORE_BYTES: usize = 8 * 1024 * 1024;
/// Bound on identifier and identity strings.
pub const MAX_ID_BYTES: usize = 256;
/// Recognizer spaces with a fitted calibration per (group, profile). Real
/// accounts carry one or two recognizers; the bound exists so a hostile
/// store cannot balloon structure beyond the byte ceiling's control of
/// template data.
pub const MAX_CALIB_SPACES_PER_PROFILE_GROUP: usize = 4;

/// Why a secondary store is unusable. The kinds are distinct diagnostics
/// (ADR-0024 §1.2): a support reader must be able to tell absent from
/// incompatible from corrupt from structurally invalid without the
/// templates being exposed.
#[derive(Debug, PartialEq, Eq)]
pub enum SecondaryStoreError {
    /// The path exists but this code cannot parse it at all.
    Corrupt(String),
    /// It parsed, but its format version is not supported.
    IncompatibleVersion(u32),
    /// It parsed and the version matches, but a structural rule failed.
    Invalid(String),
    /// Reading failed for an I/O reason.
    Io(String),
}

impl std::fmt::Display for SecondaryStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecondaryStoreError::Corrupt(detail) => write!(f, "corrupt secondary store: {detail}"),
            SecondaryStoreError::IncompatibleVersion(v) => {
                write!(f, "unsupported secondary store version {v}")
            }
            SecondaryStoreError::Invalid(detail) => write!(f, "invalid secondary store: {detail}"),
            SecondaryStoreError::Io(detail) => write!(f, "cannot read secondary store: {detail}"),
        }
    }
}

impl std::error::Error for SecondaryStoreError {}

/// An immutable camera-group identifier. Opaque, assigned once at group
/// creation, never a list position or display name (ADR-0024 §2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct CameraGroupId(String);

impl CameraGroupId {
    /// Accepts a nonempty bounded identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SecondaryStoreError::Invalid`] when empty or oversized.
    pub fn new(value: String) -> Result<Self, SecondaryStoreError> {
        if value.is_empty() || value.len() > MAX_ID_BYTES {
            return Err(SecondaryStoreError::Invalid(
                "group id empty or out of bounds".into(),
            ));
        }
        Ok(Self(value))
    }

    /// The identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CameraGroupId {
    type Error = SecondaryStoreError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// The complete role-labelled pair a group authorizes (ADR-0024 §2):
/// each side is a `device_identity` string; at least one side must be
/// bound, and membership checks compare the COMPLETE pair (a hybrid of two
/// groups' endpoints never matches).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPair {
    #[serde(default)]
    pub rgb: Option<String>,
    #[serde(default)]
    pub ir: Option<String>,
}

impl GroupPair {
    /// Whether the live pair matches this group's complete pair under the
    /// existing binding semantics: a bound side must match exactly; an
    /// unbound side is not checked (the legacy rule, restated). Missing
    /// identities are never wildcards FOR A BOUND SIDE: they fail.
    #[must_use]
    pub fn matches(&self, live_rgb: Option<&str>, live_ir: Option<&str>) -> bool {
        if let Some(want) = &self.rgb {
            if live_rgb != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = &self.ir {
            if live_ir != Some(want.as_str()) {
                return false;
            }
        }
        true
    }
}

/// One profile's scans captured on one secondary group. The profile
/// reference is the primary store's profile name, made safe by the
/// snapshot binding: any primary change deactivates this store before a
/// stale association could authorize anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryProfileScans {
    pub profile: String,
    pub scans: Vec<FaceScan>,
    /// This group's OWN per-recognizer IR calibrations, fitted from this
    /// group's scan pairs at add-camera time (ADR-0024 §3: a group borrows
    /// no primary calibration). Keyed like `FaceProfile::ir_calibs`; NOT
    /// mirrored into any legacy slot - legacy readers never open this
    /// store. Defaulted so Phase 1 fixtures (no field) still parse.
    #[serde(default)]
    pub ir_calibs: std::collections::BTreeMap<String, crate::calib::IrCalibration>,
}

/// One secondary camera group: immutable id, complete pair, and the
/// per-profile scan sets captured on that pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryGroup {
    pub id: CameraGroupId,
    pub pair: GroupPair,
    pub profiles: Vec<SecondaryProfileScans>,
}

/// The secondary store: owner, generation, the primary-snapshot binding,
/// and the groups. Strictly parsed and validated as a whole.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryStore {
    pub format_version: u32,
    /// The OS account this store belongs to.
    pub owner: String,
    /// Monotonic mutation counter; bumped by every authorized write.
    pub generation: u64,
    /// SHA-256 (lowercase hex) of the exact primary-file bytes this
    /// authorization was captured against.
    pub primary_snapshot_sha256: String,
    pub groups: Vec<SecondaryGroup>,
}

/// The activation verdict for a loaded store against the current primary
/// bytes (ADR-0024 §1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activation {
    /// The digest matches: the store's groups may participate.
    Active,
    /// The primary changed (or is missing/unreadable): groups are INACTIVE,
    /// their data preserved for diagnosis and explicit recovery.
    InactivePrimaryChanged,
}

impl SecondaryStore {
    /// Validates every structural rule. Called by [`load_secondary`] and by
    /// every future writer; the store is only usable when this passes.
    ///
    /// # Errors
    ///
    /// Returns the first violated rule as [`SecondaryStoreError::Invalid`].
    pub fn validate(&self) -> Result<(), SecondaryStoreError> {
        if self.format_version != SECONDARY_STORE_VERSION {
            return Err(SecondaryStoreError::IncompatibleVersion(
                self.format_version,
            ));
        }
        if self.owner.is_empty() || self.owner.len() > MAX_ID_BYTES {
            return Err(SecondaryStoreError::Invalid("owner out of bounds".into()));
        }
        if self.primary_snapshot_sha256.len() != 64
            || !self
                .primary_snapshot_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SecondaryStoreError::Invalid(
                "primary_snapshot_sha256 is not 64 lowercase hex characters".into(),
            ));
        }
        if self.groups.len() > MAX_GROUPS {
            return Err(SecondaryStoreError::Invalid(format!(
                "more than {MAX_GROUPS} groups"
            )));
        }
        let mut total_scans = 0usize;
        for group in &self.groups {
            if group.pair.rgb.is_none() && group.pair.ir.is_none() {
                return Err(SecondaryStoreError::Invalid(format!(
                    "group {} binds neither side",
                    group.id.as_str()
                )));
            }
            for identity in [&group.pair.rgb, &group.pair.ir].into_iter().flatten() {
                if identity.is_empty() || identity.len() > MAX_ID_BYTES {
                    return Err(SecondaryStoreError::Invalid(
                        "pair identity out of bounds".into(),
                    ));
                }
            }
            if group.profiles.is_empty() {
                return Err(SecondaryStoreError::Invalid(format!(
                    "group {} has no profile scans",
                    group.id.as_str()
                )));
            }
            let mut profile_refs = std::collections::BTreeSet::new();
            for scans in &group.profiles {
                if scans.profile.is_empty() || scans.profile.len() > MAX_ID_BYTES {
                    return Err(SecondaryStoreError::Invalid(
                        "profile reference out of bounds".into(),
                    ));
                }
                if scans.scans.is_empty() || scans.scans.len() > MAX_SCANS_PER_PROFILE_GROUP {
                    return Err(SecondaryStoreError::Invalid(format!(
                        "group {} profile {} has an invalid scan count",
                        group.id.as_str(),
                        scans.profile
                    )));
                }
                if scans.ir_calibs.len() > MAX_CALIB_SPACES_PER_PROFILE_GROUP {
                    return Err(SecondaryStoreError::Invalid(format!(
                        "group {} profile {} exceeds {} calibration spaces",
                        group.id.as_str(),
                        scans.profile,
                        MAX_CALIB_SPACES_PER_PROFILE_GROUP
                    )));
                }
                // The profile reference names the primary store's profile;
                // duplicates would alias in every scoped consumer.
                if !profile_refs.insert(scans.profile.as_str()) {
                    return Err(SecondaryStoreError::Invalid(format!(
                        "group {} repeats profile {}",
                        group.id.as_str(),
                        scans.profile
                    )));
                }
                total_scans += scans.scans.len();
            }
        }
        if total_scans > MAX_TOTAL_SCANS {
            return Err(SecondaryStoreError::Invalid(format!(
                "more than {MAX_TOTAL_SCANS} total scans"
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for group in &self.groups {
            if !seen.insert(group.id.as_str()) {
                return Err(SecondaryStoreError::Invalid(format!(
                    "duplicate group id {}",
                    group.id.as_str()
                )));
            }
        }
        Ok(())
    }

    /// The activation verdict against the CURRENT primary bytes
    /// (ADR-0024 §1.1/§4.2). A missing or unreadable primary is a change:
    /// inactive, never an error path that could fall back to guessing.
    #[must_use]
    pub fn activation_against(&self, primary_result: Option<&[u8]>) -> Activation {
        let Some(bytes) = primary_result else {
            return Activation::InactivePrimaryChanged;
        };
        let digest = irlume_common::sha256_hex(bytes);
        if digest == self.primary_snapshot_sha256 {
            Activation::Active
        } else {
            Activation::InactivePrimaryChanged
        }
    }

    /// Resolves the group whose COMPLETE pair matches the live pair, if
    /// any. Ambiguity is impossible by construction (duplicate ids are
    /// rejected), and a hybrid of two groups' endpoints never matches.
    #[must_use]
    pub fn group_for_pair(
        &self,
        live_rgb: Option<&str>,
        live_ir: Option<&str>,
    ) -> Option<&SecondaryGroup> {
        self.groups
            .iter()
            .find(|group| group.pair.matches(live_rgb, live_ir))
    }
}

/// Loads the secondary store. A missing file is `Ok(None)` (no secondary
/// enrollment). Any other failure rejects the WHOLE store (§1.2); callers
/// must not treat an error as empty.
///
/// # Errors
///
/// Returns [`SecondaryStoreError`] with the diagnostic kind; never a
/// partial store.
pub fn load_secondary(path: &Path) -> Result<Option<SecondaryStore>, SecondaryStoreError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SecondaryStoreError::Io(error.to_string())),
    };
    if bytes.len() > MAX_STORE_BYTES {
        return Err(SecondaryStoreError::Invalid(format!(
            "store larger than {MAX_STORE_BYTES} bytes"
        )));
    }
    let version: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| SecondaryStoreError::Corrupt(error.to_string()))?;
    let declared = version
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| SecondaryStoreError::Corrupt("no format_version".into()))?;
    if declared != u64::from(SECONDARY_STORE_VERSION) {
        return Err(SecondaryStoreError::IncompatibleVersion(
            u32::try_from(declared).unwrap_or(u32::MAX),
        ));
    }
    let store: SecondaryStore = serde_json::from_slice(&bytes)
        .map_err(|error| SecondaryStoreError::Corrupt(error.to_string()))?;
    store.validate()?;
    Ok(Some(store))
}

/// Durably saves the secondary store: write to a sibling temporary, fsync
/// the FILE, rename over the target, then fsync the DIRECTORY (a file's
/// fsync does not guarantee its directory entry; ADR-0024 §4.1's
/// durability note). The store is validated before writing; invalid data
/// is never persisted.
///
/// # Errors
///
/// Returns [`SecondaryStoreError::Io`] when any step fails, or
/// [`SecondaryStoreError::Invalid`] when the store fails validation.
pub fn save_secondary(path: &Path, store: &SecondaryStore) -> Result<(), SecondaryStoreError> {
    store.validate()?;
    let bytes =
        serde_json::to_vec(store).map_err(|error| SecondaryStoreError::Io(error.to_string()))?;
    if bytes.len() > MAX_STORE_BYTES {
        return Err(SecondaryStoreError::Invalid(
            "serialized store exceeds the size bound".into(),
        ));
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // Writers create the store's directory before publication (the fixed
    // location sits in a `cameras/` subdirectory legacy code never made).
    std::fs::create_dir_all(dir).map_err(|error| SecondaryStoreError::Io(error.to_string()))?;
    let temp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "secondary".into()),
        std::process::id()
    ));
    use std::io::Write;
    let write_all = |temp: &Path| -> std::io::Result<()> {
        let mut file = std::fs::File::create(temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    };
    write_all(&temp).map_err(|error| SecondaryStoreError::Io(error.to_string()))?;
    std::fs::rename(&temp, path).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        SecondaryStoreError::Io(error.to_string())
    })?;
    let dir_file =
        std::fs::File::open(dir).map_err(|error| SecondaryStoreError::Io(error.to_string()))?;
    dir_file
        .sync_all()
        .map_err(|error| SecondaryStoreError::Io(error.to_string()))?;
    Ok(())
}

pub mod authz;
pub mod commit;
pub mod coordinator;
pub mod views;

#[cfg(test)]
mod tests {
    use super::*;

    fn scan() -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.0; 8],
            ir: None,
            ir_space: None,
            embed_space: None,
            ir_center_edge_ratio: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        }
    }

    fn store() -> SecondaryStore {
        SecondaryStore {
            format_version: SECONDARY_STORE_VERSION,
            owner: "alice".into(),
            generation: 1,
            primary_snapshot_sha256: "a".repeat(64),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("g1".into()).unwrap(),
                pair: GroupPair {
                    rgb: Some("046d:085e:e179cb54".into()),
                    ir: Some("046d:085e:e179cb54".into()),
                },
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "main".into(),
                    scans: vec![scan(); 10],
                }],
            }],
        }
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "irlume-secondary-{}-{}.json",
            tag,
            std::process::id()
        ))
    }

    #[test]
    fn a_valid_store_round_trips_and_a_missing_file_is_none() {
        let path = temp_path("valid");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(load_secondary(&path), Ok(None)));
        let original = store();
        save_secondary(&path, &original).expect("save");
        let loaded = load_secondary(&path).expect("load").expect("present");
        // FaceScan carries no PartialEq (legacy type); equality by
        // deterministic serialization.
        assert_eq!(
            serde_json::to_vec(&loaded).unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn activation_follows_the_primary_bytes_exactly() {
        let s = store();
        let primary = b"primary-bytes-v1";
        let digest = irlume_common::sha256_hex(primary);
        let s = SecondaryStore {
            primary_snapshot_sha256: digest,
            ..s
        };
        assert_eq!(s.activation_against(Some(primary)), Activation::Active);
        assert_eq!(
            s.activation_against(Some(b"primary-bytes-v2")),
            Activation::InactivePrimaryChanged
        );
        assert_eq!(
            s.activation_against(None),
            Activation::InactivePrimaryChanged
        );
    }

    #[test]
    fn whole_store_rejection_unsupported_version_corrupt_and_invalid() {
        let path = temp_path("reject");
        // Unsupported version.
        let bytes = serde_json::to_vec(&SecondaryStore {
            format_version: 2,
            ..store()
        })
        .unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            load_secondary(&path),
            Err(SecondaryStoreError::IncompatibleVersion(2))
        ));
        // Corrupt.
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            load_secondary(&path),
            Err(SecondaryStoreError::Corrupt(_))
        ));
        // Structurally invalid: duplicate group ids.
        let mut duplicated = store();
        let clone = duplicated.groups[0].clone();
        duplicated.groups.push(clone);
        std::fs::write(&path, serde_json::to_vec(&duplicated).unwrap()).unwrap();
        assert!(matches!(
            load_secondary(&path),
            Err(SecondaryStoreError::Invalid(detail)) if detail.contains("duplicate group id")
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn complete_pairs_match_but_hybrids_never_do() {
        let s = store();
        let group = s
            .group_for_pair(Some("046d:085e:e179cb54"), Some("046d:085e:e179cb54"))
            .expect("exact pair matches");
        assert_eq!(group.id.as_str(), "g1");
        // A hybrid of two groups' endpoints: RGB matches, IR from elsewhere.
        assert!(s
            .group_for_pair(Some("046d:085e:e179cb54"), Some("3443:c803"))
            .is_none());
        // A bound side is not a wildcard.
        assert!(s.group_for_pair(None, Some("046d:085e:e179cb54")).is_none());
    }

    #[test]
    fn secondary_store_path_sits_outside_the_legacy_enrollment_namespace() {
        let _guard = crate::testenv::ENV_LOCK.lock().expect("env lock");
        let dir = std::env::temp_dir().join(format!("irlume-sec-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        let path = secondary_store_path("alice");
        assert_eq!(path, dir.join("cameras").join("alice.json"));
        // Non-discovery: a planted secondary store must not make the user
        // enrolled through the legacy per-user loader (ADR-0024 §1).
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        save_secondary(&path, &store()).expect("save");
        assert!(
            matches!(crate::storage::load("alice"), Ok(None)),
            "legacy load must never discover the secondary store"
        );
        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_group_calibrations_round_trip_and_phase1_fixtures_still_load() {
        let calib = crate::calib::IrCalibration {
            m: vec![vec![1.0, 0.0], vec![0.0, 1.0]],
            n_rows: vec![vec![0.0; 2], vec![0.0; 2]],
            lambda: 0.5,
            fitted_pairs: 3,
        };
        let mut with_calib = store();
        with_calib.groups[0].profiles[0]
            .ir_calibs
            .insert("embed:test".into(), calib.clone());
        let path = temp_path("calib");
        let _ = std::fs::remove_file(&path);
        save_secondary(&path, &with_calib).expect("save");
        let loaded = load_secondary(&path).expect("load").expect("present");
        assert_eq!(
            serde_json::to_vec(&loaded.groups[0].profiles[0].ir_calibs.get("embed:test")).unwrap(),
            serde_json::to_vec(&Some(&calib)).unwrap()
        );
        // A Phase 1 fixture (no ir_calibs field) parses with empty calibs:
        // the field is defaulted, never required.
        let phase1 = r#"{"format_version":1,"owner":"alice","generation":1,
            "primary_snapshot_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "groups":[{"id":"g1","pair":{"rgb":"046d:085e:e179cb54","ir":"046d:085e:e179cb54"},
            "profiles":[{"profile":"main","scans":[{"name":"s","rgb":[0.0]}]}]}]}"#;
        std::fs::write(&path, phase1).expect("write fixture");
        let legacy = load_secondary(&path).expect("parse").expect("present");
        assert!(legacy.groups[0].profiles[0].ir_calibs.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn calib_spaces_per_profile_group_are_bounded() {
        let mut crowded = store();
        let scans = &mut crowded.groups[0].profiles[0];
        for n in 0..=MAX_CALIB_SPACES_PER_PROFILE_GROUP {
            scans.ir_calibs.insert(
                format!("embed:{n}"),
                crate::calib::IrCalibration {
                    m: vec![vec![1.0]],
                    n_rows: vec![vec![0.0]],
                    lambda: 0.5,
                    fitted_pairs: 1,
                },
            );
        }
        assert!(crowded.validate().is_err());
    }

    #[test]
    fn duplicate_profile_references_within_a_group_are_invalid() {
        let mut doubled = store();
        let first = doubled.groups[0].profiles[0].clone();
        doubled.groups[0].profiles.push(first);
        assert!(doubled.validate().is_err());
    }

    #[test]
    fn bounds_are_enforced_and_invalid_stores_never_persist() {
        let mut many = store();
        many.groups = (0..MAX_GROUPS + 1)
            .map(|n| SecondaryGroup {
                id: CameraGroupId::new(format!("g{n}")).unwrap(),
                pair: GroupPair {
                    rgb: Some(format!("vid{n}")),
                    ir: None,
                },
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "main".into(),
                    scans: vec![scan()],
                }],
            })
            .collect();
        assert!(many.validate().is_err());
        let path = temp_path("bounds");
        let _ = std::fs::remove_file(&path);
        assert!(save_secondary(&path, &many).is_err());
        assert!(matches!(load_secondary(&path), Ok(None)));
        let _ = std::fs::remove_file(&path);
    }
}
