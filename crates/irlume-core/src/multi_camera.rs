// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

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

use crate::{crypto, storage::FaceScan};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Builds the listing rows for every group in `store` (ADR-0024 Phase 2
/// status surface): identity, connected/selected/stale state, and
/// per-profile counts with calibration state.
///
/// - `connected`: every BOUND side's identity appears in `present`
///   (callers enumerate present identities from sysfs without opening
///   devices).
/// - `selected`: the group's complete pair matches `live` (the pair the
///   engine would use).
/// - `stale`: the store-wide activation binding does not match the
///   CURRENT primary bytes (`primary` is `None` when the primary is
///   unreadable - that is a change, §1.1).
#[must_use]
pub fn group_summaries(
    store: &SecondaryStore,
    primary: Option<&[u8]>,
    live: &GroupPair,
    present: &[String],
    embed_space: &str,
    ir_space: &str,
    ir_dim: usize,
) -> Vec<irlume_common::CameraGroupSummary> {
    let stale = !matches!(store.activation_against(primary), Activation::Active);
    store
        .groups
        .iter()
        .map(|group| {
            let connected = [&group.pair.rgb, &group.pair.ir]
                .into_iter()
                .flatten()
                .all(|identity| present.iter().any(|p| p == identity));
            irlume_common::CameraGroupSummary {
                id: group.id.as_str().to_owned(),
                rgb: group.pair.rgb.clone(),
                ir: group.pair.ir.clone(),
                connected,
                selected: group.pair.matches(live.rgb.as_deref(), live.ir.as_deref()),
                stale,
                generation: store.generation,
                profiles: group
                    .profiles
                    .iter()
                    .map(|scans| {
                        let view = crate::multi_camera::views::ScopedProfileView {
                            profile: scans.profile.clone(),
                            scans: scans.scans.clone(),
                            ir_calibs: scans.ir_calibs.clone(),
                        };
                        let readiness = view.readiness(embed_space, ir_space, ir_dim);
                        irlume_common::CameraGroupProfileSummary {
                            profile: scans.profile.clone(),
                            scans: readiness.scan_count,
                            capture_target_met: readiness.capture_target_met,
                            calibration_fittable: readiness.calibration_fittable,
                            compatible_rgb_candidates: readiness.compatible_rgb_candidates,
                            compatible_ir_pairs: readiness.compatible_ir_pairs,
                            calibrated: scans.ir_calibs.contains_key(embed_space),
                        }
                    })
                    .collect(),
            }
        })
        .collect()
}

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
/// bytes the secondary store's activation digest is taken over. Delegates
/// to the loader's own resolution so the two can never drift apart.
#[must_use]
pub fn primary_enrollment_path(user: &str) -> PathBuf {
    crate::storage::profile_path(user)
}

/// Derives a group id from the pair's device identities: stable for the
/// same pair, unique within `existing` by suffixing. Assigned once at
/// group creation and immutable afterwards; never a display name or list
/// position (ADR-0024 §2). Sanitized and bounded so the result always
/// satisfies [`CameraGroupId::new`].
///
/// # Panics
///
/// Panics only if the sanitized candidate exceeded the id bound, which the
/// truncation above makes impossible (a proven invariant, not a recoverable
/// condition).
#[must_use]
pub fn derive_group_id(
    existing: &SecondaryStore,
    rgb: Option<&str>,
    ir: Option<&str>,
) -> CameraGroupId {
    let source = rgb.or(ir).unwrap_or("camera");
    let mut stem: String = source
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    // Leave room for the prefix and any uniqueness suffix within the id bound.
    stem.truncate(MAX_ID_BYTES.saturating_sub(16));
    let stem = stem.trim_matches('-');
    let stem = if stem.is_empty() { "camera" } else { stem };
    let mut candidate = format!("cam-{stem}");
    let mut suffix = 2;
    while existing
        .groups
        .iter()
        .any(|group| group.id.as_str() == candidate)
    {
        candidate = format!("cam-{stem}-{suffix}");
        suffix += 1;
    }
    CameraGroupId::new(candidate).expect("sanitized bounded id")
}

/// The only secondary-store format version this code reads and writes.
pub const SECONDARY_STORE_VERSION: u32 = 1;

/// Envelope format for a key-encrypted secondary store (ADR-0024 s1.2): the
/// `enc` field decrypts (AES-256-GCM under the account template key) to the
/// exact version-1 store JSON, and `key_id` records the key identity
/// (sha256 of the key material, matching the primary envelope's convention).
pub const SECONDARY_ENC_ENVELOPE_VERSION: u64 = 2;

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
    load_secondary_resolved(path, production_key_for)
}

/// [`load_secondary`] with an explicit key: `Some` decrypts an envelope (or
/// reads a legacy plaintext store unchanged); `None` reads legacy plaintext
/// and FAILS CLOSED on an encrypted store (the key-holder must not be
/// bypassed).
///
/// # Errors
///
/// Same contract as [`load_secondary`]; an encrypted store plus a missing or
/// wrong key is [`SecondaryStoreError::Corrupt`]/[`SecondaryStoreError::Invalid`]
/// naming the key.
pub fn load_secondary_resolved(
    path: &Path,
    key_for: impl Fn(&str) -> Result<Option<Zeroizing<Vec<u8>>>, SecondaryStoreError>,
) -> Result<Option<SecondaryStore>, SecondaryStoreError> {
    // The key is only requested for an ENCRYPTED store: a missing file and a
    // legacy plaintext store never touch the TPM, so pre-encryption stores
    // keep loading on hosts where the account key is locked.
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
    if declared == SECONDARY_ENC_ENVELOPE_VERSION {
        let user = store_user(path)?;
        let key = key_for(&user)?;
        return load_secondary_with_key(path, key.as_deref().map(|v| &**v));
    }
    load_secondary_with_key(path, None)
}

/// The production key resolver: the account template key, only when a TPM is
/// present (degraded no-TPM hosts run the legacy plaintext store, matching
/// the primary store's documented behavior there).
/// # Errors
///
/// Returns [`SecondaryStoreError::Invalid`] when no TPM is present or the
/// account template key cannot be unsealed.
/// The production key resolver: the account template key when a TPM is
/// present; `Ok(None)` on a no-TPM host, which writes the documented
/// root-only plaintext legacy format - exactly how the primary store
/// behaves there. On a TPM host an unseal failure is an error (fail
/// closed; never a silent plaintext downgrade).
///
/// # Errors
///
/// Returns [`SecondaryStoreError::Invalid`] when the TPM is present but the
/// account template key cannot be unsealed.
pub fn production_key_for(user: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecondaryStoreError> {
    if !crate::template_key::tpm_available() {
        return Ok(None);
    }
    crate::template_key::ensure_key_unlocked(user)
        .map(Some)
        .map_err(|error| {
            SecondaryStoreError::Invalid(format!(
                "the account template key is unavailable: {error}"
            ))
        })
}

/// The account name a secondary store belongs to: the fixed layout is
/// `cameras/<user>.json`, so the file stem is the account.
fn store_user(path: &Path) -> Result<String, SecondaryStoreError> {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| SecondaryStoreError::Invalid("secondary store path has no file stem".into()))
}

/// [`load_secondary`] with an explicit key: `Some` decrypts an envelope (or
/// reads a legacy plaintext store unchanged); `None` reads legacy plaintext
/// and FAILS CLOSED on an encrypted store (the key-holder must not be
/// bypassed).
///
/// # Errors
///
/// Same contract as [`load_secondary`]; an encrypted store plus a missing or
/// wrong key is [`SecondaryStoreError::Corrupt`]/[`SecondaryStoreError::Invalid`]
/// naming the key.
/// [`load_secondary`] with the request's key source (ADR-0025): the key is
/// requested only for an encrypted store, borrowed, never copied.
///
/// # Errors
///
/// Same contract as [`load_secondary`].
pub fn load_secondary_with_source(
    path: &Path,
    keys: &mut dyn crate::template_key::TemplateKeySource,
) -> Result<Option<SecondaryStore>, SecondaryStoreError> {
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
    if declared != SECONDARY_ENC_ENVELOPE_VERSION {
        return parse_store_bytes(&bytes, None).map(Some);
    }
    let user = store_user(path)?;
    let key = keys.template_key(&user).map_err(|error| {
        SecondaryStoreError::Invalid(format!("the account template key is unavailable: {error}"))
    })?;
    parse_store_bytes(&bytes, key).map(Some)
}

/// [`load_secondary`] with an explicit borrowed key: `Some` decrypts an
/// envelope (or reads a legacy plaintext store unchanged); `None` reads
/// legacy plaintext and fails closed on an encrypted store.
///
/// # Errors
///
/// Same contract as [`load_secondary`].
pub fn load_secondary_with_key(
    path: &Path,
    key: Option<&[u8]>,
) -> Result<Option<SecondaryStore>, SecondaryStoreError> {
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
    parse_store_bytes(&bytes, key).map(Some)
}

/// Parses persisted store bytes: legacy plaintext v1, or the encrypted v2
/// envelope decrypted under `key` (`None` + encrypted = fail closed).
fn parse_store_bytes(
    bytes: &[u8],
    key: Option<&[u8]>,
) -> Result<SecondaryStore, SecondaryStoreError> {
    let version: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| SecondaryStoreError::Corrupt(error.to_string()))?;
    let declared = version
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| SecondaryStoreError::Corrupt("no format_version".into()))?;
    let store_bytes = match declared {
        v if v == u64::from(SECONDARY_STORE_VERSION) => bytes.to_vec(),
        v if v == SECONDARY_ENC_ENVELOPE_VERSION => {
            let key = key.ok_or_else(|| {
                SecondaryStoreError::Invalid(
                    "the secondary store is encrypted and its template key is unavailable".into(),
                )
            })?;
            // The envelope's key_id binds the ciphertext to this account's
            // key; a mismatch means the store was sealed by a different key
            // (wrong account, rotated key, or tampering) and must not be
            // silently opened with this one.
            let claimed = version
                .get("key_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    SecondaryStoreError::Corrupt("encrypted store has no key_id".into())
                })?;
            if claimed != irlume_common::sha256_hex(key) {
                return Err(SecondaryStoreError::Corrupt(
                    "the store was encrypted with a different template key".into(),
                ));
            }
            let enc = version
                .get("enc")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    SecondaryStoreError::Corrupt("encrypted store has no enc field".into())
                })?;
            use base64::Engine as _;
            let blob = base64::engine::general_purpose::STANDARD
                .decode(enc)
                .map_err(|error| {
                    SecondaryStoreError::Corrupt(format!("enc is not base64: {error}"))
                })?;
            crypto::decrypt(key, &blob)
                .map_err(|error| {
                    SecondaryStoreError::Corrupt(format!("store failed to decrypt: {error}"))
                })?
                .to_vec()
        }
        other => {
            return Err(SecondaryStoreError::IncompatibleVersion(
                u32::try_from(other).unwrap_or(u32::MAX),
            ));
        }
    };
    let store: SecondaryStore = serde_json::from_slice(&store_bytes)
        .map_err(|error| SecondaryStoreError::Corrupt(error.to_string()))?;
    store.validate()?;
    Ok(store)
}

/// [`save_secondary`] with a key resolver (production passes
/// [`production_key_for`]; tests inject fakes).
/// # Errors
///
/// Returns [`SecondaryStoreError`] when the resolver fails or any durable
/// write step fails.
pub fn save_secondary_resolved(
    path: &Path,
    store: &SecondaryStore,
    key_for: impl Fn(&str) -> Result<Option<Zeroizing<Vec<u8>>>, SecondaryStoreError>,
) -> Result<(), SecondaryStoreError> {
    let key = key_for(&store_user(path)?)?;
    save_secondary_with_key(path, store, key.as_ref().map(|v| v.as_slice()))
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
    save_secondary_resolved(path, store, production_key_for)
}

/// [`save_secondary`] with an explicit key: `Some` writes the encrypted
/// envelope (owner-only mode, ADR-0024 s1.2 confidentiality); `None` writes
/// the legacy plaintext format (no-TPM degraded hosts, documented).
///
/// # Errors
///
/// Returns [`SecondaryStoreError`] when validation, encryption or any
/// durable step fails; invalid data is never persisted.
pub(crate) fn save_secondary_with_key(
    path: &Path,
    store: &SecondaryStore,
    key: Option<&[u8]>,
) -> Result<(), SecondaryStoreError> {
    store.validate()?;
    let json =
        serde_json::to_vec(store).map_err(|error| SecondaryStoreError::Io(error.to_string()))?;
    let bytes = match key {
        Some(key) => {
            let blob = crate::crypto::encrypt(key, &json)
                .map_err(|error| SecondaryStoreError::Io(error.to_string()))?;
            use base64::Engine as _;
            let envelope = serde_json::json!({
                "format_version": SECONDARY_ENC_ENVELOPE_VERSION,
                "key_id": irlume_common::sha256_hex(key),
                "enc": base64::engine::general_purpose::STANDARD.encode(&blob),
            });
            serde_json::to_vec(&envelope)
                .map_err(|error| SecondaryStoreError::Io(error.to_string()))?
        }
        None => json,
    };
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
        // Owner-only regardless of umask (ADR-0024 s1.2 permission clause).
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp)?;
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

    // ---- Secondary-store encryption (ADR-0024 s1.2) --------------------
    //
    // A synthetic key stands in for the account template key: the store
    // never invents key material, it encrypts with what it is given.

    fn test_key() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![7u8; 32])
    }

    #[test]
    fn a_keyed_save_writes_an_encrypted_envelope_not_plaintext() {
        let path = temp_path("enc-envelope");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), Some(&test_key())).expect("save");
        let bytes = std::fs::read(&path).expect("read");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("envelope parses");
        assert_eq!(
            doc["format_version"].as_u64(),
            Some(SECONDARY_ENC_ENVELOPE_VERSION),
            "envelope format_version"
        );
        assert!(doc["enc"].is_string(), "ciphertext present");
        assert!(doc["key_id"].is_string(), "key id present");
        // The plaintext field names of the version-1 store must not leak.
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("primary_snapshot_sha256"));
        assert!(!raw.contains("profiles"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_keyed_save_round_trips_through_the_same_key() {
        let path = temp_path("enc-roundtrip");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), Some(&test_key())).expect("save");
        let loaded = load_secondary_with_key(&path, Some(&test_key()))
            .expect("load")
            .expect("present");
        assert_eq!(
            serde_json::to_vec(&loaded).unwrap(),
            serde_json::to_vec(&store()).unwrap()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_encrypted_store_without_the_key_fails_closed() {
        let path = temp_path("enc-nokey");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), Some(&test_key())).expect("save");
        let error = load_secondary_with_key(&path, None).expect_err("must fail closed");
        assert!(
            error.to_string().to_lowercase().contains("key"),
            "the refusal must name the key: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_wrong_key_fails_closed() {
        let path = temp_path("enc-wrongkey");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), Some(&test_key())).expect("save");
        let other = Zeroizing::new(vec![9u8; 32]);
        let error = load_secondary_with_key(&path, Some(&other)).expect_err("must fail");
        // The key_id check rejects a different key before decryption is
        // even attempted, naming the binding rather than a generic
        // decryption failure.
        assert!(
            error
                .to_string()
                .to_lowercase()
                .contains("different template key"),
            "wrong key reports the binding: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let path = temp_path("enc-tamper");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), Some(&test_key())).expect("save");
        // Flip a byte INSIDE the ciphertext blob: the envelope's JSON tail is
        // not the secret, and corrupting it would test JSON parsing instead.
        use base64::Engine as _;
        let bytes = std::fs::read(&path).expect("read");
        let mut doc: serde_json::Value = serde_json::from_slice(&bytes).expect("envelope parses");
        let enc = doc["enc"].as_str().expect("enc is a string");
        let mut blob = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .expect("enc is base64");
        let last = blob.len() - 1; // the GCM tag's final byte
        blob[last] ^= 0x01;
        doc["enc"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&blob));
        let bytes = serde_json::to_vec(&doc).expect("re-encode");
        std::fs::write(&path, &bytes).expect("rewrite");
        let error = load_secondary_with_key(&path, Some(&test_key())).expect_err("must fail");
        assert!(
            error.to_string().to_lowercase().contains("decrypt"),
            "tampering reports a decryption failure: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_keyless_save_stays_legacy_plaintext_for_no_tpm_hosts() {
        let path = temp_path("legacy-write");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), None).expect("save");
        let bytes = std::fs::read(&path).expect("read");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("plaintext parses");
        assert_eq!(
            doc["format_version"].as_u64(),
            Some(u64::from(SECONDARY_STORE_VERSION)),
            "legacy format stays version 1"
        );
        let loaded = load_secondary_with_key(&path, None)
            .expect("load")
            .expect("present");
        assert_eq!(
            serde_json::to_vec(&loaded).unwrap(),
            serde_json::to_vec(&store()).unwrap()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_legacy_plaintext_store_still_loads_when_a_key_is_offered() {
        // Migration readability: pre-encryption stores (0.13.0 era) keep
        // loading unchanged; the upgrade happens on the next write.
        let path = temp_path("legacy-read");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), None).expect("legacy save");
        let loaded = load_secondary_with_key(&path, Some(&test_key()))
            .expect("load")
            .expect("present");
        assert_eq!(loaded.owner, "alice");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_envelope_records_the_key_id_and_the_layout_stays_nonce_first() {
        let path = temp_path("enc-layout");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), Some(&test_key())).expect("save");
        let bytes = std::fs::read(&path).expect("read");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("envelope parses");
        use base64::Engine as _;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(doc["enc"].as_str().expect("enc is a string"))
            .expect("enc is base64");
        assert!(blob.len() > 12 + 16, "nonce + ciphertext + tag");
        let plain = crate::crypto::decrypt(&test_key(), &blob).expect("decrypts");
        let inner: serde_json::Value = serde_json::from_slice(&plain).expect("inner store JSON");
        assert_eq!(inner["format_version"].as_u64(), Some(1), "inner is v1");
        assert_eq!(
            doc["key_id"].as_str(),
            Some(irlume_common::sha256_hex(&test_key()).as_str()),
            "key_id binds the key identity"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keyed_saves_pin_the_file_owner_only_mode() {
        let path = temp_path("enc-mode");
        let _ = std::fs::remove_file(&path);
        save_secondary_with_key(&path, &store(), Some(&test_key())).expect("save");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the store must be owner-only");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_valid_store_round_trips_and_a_missing_file_is_none() {
        let path = temp_path("valid");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(load_secondary(&path), Ok(None)));
        let original = store();
        // Legacy plaintext write: this test pins the version-1 format that
        // no-TPM hosts (and pre-encryption stores) use.
        save_secondary_with_key(&path, &original, None).expect("save");
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
        // Unsupported version (2 is the encrypted-envelope version now).
        let bytes = serde_json::to_vec(&SecondaryStore {
            format_version: 99,
            ..store()
        })
        .unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            load_secondary(&path),
            Err(SecondaryStoreError::IncompatibleVersion(99))
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
        save_secondary_with_key(&path, &with_calib, None).expect("save");
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
    fn group_ids_derive_stably_and_unique_within_a_store() {
        let base = store();
        let first = derive_group_id(&base, Some("046d:085e:e179cb54"), None);
        assert_eq!(first.as_str(), "cam-046d-085e-e179cb54");
        // Same pair, same id (stable); IR is used when RGB is absent.
        assert_eq!(
            derive_group_id(&base, Some("046d:085e:e179cb54"), Some("x")).as_str(),
            "cam-046d-085e-e179cb54"
        );
        assert_eq!(
            derive_group_id(&base, None, Some("3443:c803")).as_str(),
            "cam-3443-c803"
        );
        // A store already holding the id gets a numbered suffix; the next
        // collision continues the sequence.
        let mut occupied = base.clone();
        occupied.groups[0].id = derive_group_id(&occupied, Some("046d:085e"), None);
        assert_eq!(
            derive_group_id(&occupied, Some("046d:085e"), None).as_str(),
            "cam-046d-085e-2"
        );
        // Hostile-long identities stay within the id bound.
        let long = "x".repeat(400);
        let bounded = derive_group_id(&base, Some(&long), None);
        assert!(bounded.as_str().len() <= MAX_ID_BYTES);
        assert!(CameraGroupId::new(bounded.as_str().to_owned()).is_ok());
    }

    #[test]
    fn group_summaries_report_connection_selection_activation_and_counts() {
        let mut store = store();
        store.groups[0].pair = GroupPair {
            rgb: Some("046d:desk".into()),
            ir: Some("046d:desk".into()),
        };
        // Ten scans with IR pairs + a calibration for the live recognizer.
        let mut scans = Vec::new();
        for n in 0..crate::storage::DEFAULT_ENROLL_SCANS {
            let mut s = scan();
            s.name = format!("s{n}");
            s.ir = Some(vec![0.25; 4]);
            s.ir_space = Some("adapter:live".into());
            s.embed_space = Some("embed:live".into());
            scans.push(s);
        }
        store.groups[0].profiles[0] = SecondaryProfileScans {
            ir_calibs: std::iter::once((
                "embed:live".to_owned(),
                crate::calib::IrCalibration {
                    m: vec![vec![1.0]],
                    n_rows: vec![vec![0.0]],
                    lambda: 0.5,
                    fitted_pairs: 3,
                },
            ))
            .collect(),
            profile: "main".into(),
            scans,
        };
        let primary = b"primary-bytes";
        store.primary_snapshot_sha256 = irlume_common::sha256_hex(primary);

        let live = GroupPair {
            rgb: Some("046d:desk".into()),
            ir: Some("046d:desk".into()),
        };
        let present = vec!["046d:desk".to_owned(), "3443:c803".to_owned()];

        let rows = group_summaries(
            &store,
            Some(primary),
            &live,
            &present,
            "embed:live",
            "adapter:live",
            4,
        );
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.id, "g1");
        assert!(row.connected, "both bound sides are present");
        assert!(row.selected, "the live pair is this group");
        assert!(!row.stale, "the digest matches the primary bytes");
        assert_eq!(row.generation, 1);
        let profile = &row.profiles[0];
        assert_eq!(profile.scans, crate::storage::DEFAULT_ENROLL_SCANS);
        assert!(profile.capture_target_met);
        assert!(profile.calibration_fittable);
        assert_eq!(profile.compatible_rgb_candidates, 10);
        assert_eq!(profile.compatible_ir_pairs, 10);
        assert!(profile.calibrated, "the group has its own live-space calib");

        // The same store against a DIFFERENT live pair, one side unplugged,
        // and a rewritten primary: disconnected, unselected, stale.
        let other_live = GroupPair {
            rgb: Some("046d:lap".into()),
            ir: Some("046d:lap".into()),
        };
        let rows = group_summaries(
            &store,
            Some(b"rewritten-primary"),
            &other_live,
            &present,
            "embed:live",
            "adapter:live",
            4,
        );
        let row = &rows[0];
        assert!(row.connected, "presence is about the group's own sides");
        assert!(!row.selected);
        assert!(row.stale, "a rewritten primary stale-marks every group");

        // A group whose bound side is ABSENT from the machine: not connected.
        let absent_present: Vec<String> = vec![];
        let rows = group_summaries(
            &store,
            Some(primary),
            &other_live,
            &absent_present,
            "embed:live",
            "adapter:live",
            4,
        );
        assert!(!rows[0].connected);
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
        // The rejection must be the VALIDATION failure, not key resolution:
        // pin it through the explicit-key write.
        assert!(save_secondary_with_key(&path, &many, None).is_err());
        assert!(matches!(load_secondary(&path), Ok(None)));
        let _ = std::fs::remove_file(&path);
    }
}
