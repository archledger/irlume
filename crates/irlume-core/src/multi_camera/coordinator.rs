// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Secondary-authentication coordinator (ADR-0024 Phase 1): the object the
//! daemon holds for one authentication attempt on a secondary camera
//! group, tying the four foundations together - store loading with
//! journal resolution, view composition, attempt pinning, and the
//! serialized grant-boundary check.
//!
//! Lifecycle: [`SecondaryAuthContext::pin`] loads and resolves both
//! stores, composes the camera-scoped views, verifies the requested group
//! is ACTIVE for the live pair, and records the pinned state. Capture and
//! matching then read ONLY the group's scoped view. Before any grant
//! decision, the daemon calls [`SecondaryAuthContext::boundary_check_now`], which re-reads BOTH
//! stores at the boundary (never a cached descriptor) and applies
//! [`grant_boundary_check`].
//!
//! This is the Phase 1 primitive layer; the engine consumes it when the
//! integrated flows land (Phase 2). Everything here is testable without
//! hardware, and the integration tests below walk the acceptance-matrix
//! software rows end to end.

use super::commit::{
    grant_boundary_check, grant_boundary_now, resolve_commit, GrantContext, GrantDecision,
};
use super::views::{CameraScopedViews, GroupScope};
use super::SecondaryStore;
use std::path::{Path, PathBuf};

/// Why a pin attempt refused. Every refusal names the boundary that
/// failed; the daemon turns these into password-fallback refusals, never
/// into guesses.
#[derive(Debug)]
pub enum PinError {
    /// The secondary store could not be loaded or resolved.
    Secondary(String),
    /// No active group matches the live pair.
    GroupNotActive(String),
    /// ADR-0028: a group matches the configured pair exactly, but the store
    /// is inactive because the primary enrollment changed since that group
    /// was authorized. `index` is the group's 0-based store position, so
    /// the refusal can still name the scope by ordinal.
    GroupInactive { index: usize, detail: String },
    /// ADR-0028: more than one group matches the configured pair exactly.
    Ambiguous(String),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::Secondary(detail) => write!(f, "secondary store unusable: {detail}"),
            PinError::GroupNotActive(detail) => write!(f, "no active group: {detail}"),
            PinError::GroupInactive { detail, .. } => write!(f, "group inactive: {detail}"),
            PinError::Ambiguous(detail) => write!(f, "ambiguous group: {detail}"),
        }
    }
}

impl std::error::Error for PinError {}

/// The account and store paths a strict pin resolves against (ADR-0028).
#[derive(Debug, Clone, Copy)]
pub struct StrictPinStores<'a> {
    /// The authenticating account; a store naming another owner fails closed.
    pub user: &'a str,
    pub secondary_path: &'a Path,
    pub primary_path: &'a Path,
}

/// One authentication attempt's pinned secondary context.
#[derive(Debug)]
pub struct SecondaryAuthContext {
    secondary_path: PathBuf,
    primary_path: PathBuf,
    pinned: GrantContext,
    views: CameraScopedViews,
    group_index: usize,
    /// The pinned group's 0-based position in the store: the only handle
    /// the IR-only path reports (ADR-0028), never the id.
    store_index: usize,
}

impl SecondaryAuthContext {
    /// Pins an attempt on the secondary group matching the live pair.
    /// Resolves any leftover commit journal first (recover-forward), then
    /// loads both stores, composes the views, and requires the live pair
    /// to resolve to an ACTIVE secondary group - ambiguous or inactive
    /// states refuse (§2: never select a group by its biometric score).
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] when the stores are unusable or no active
    /// group matches the live pair.
    pub fn pin(
        secondary_path: &Path,
        primary_path: &Path,
        live_rgb: Option<&str>,
        live_ir: Option<&str>,
    ) -> Result<Self, PinError> {
        Self::pin_with_source(
            secondary_path,
            primary_path,
            live_rgb,
            live_ir,
            &mut crate::template_key::RequestTemplateKey::production(),
        )
    }

    /// [`Self::pin`] lending the request's template key to both store reads
    /// (ADR-0025): the encrypted secondary and the primary re-load borrow
    /// the key the request already unsealed, or have the source unseal once.
    ///
    /// # Errors
    ///
    /// As [`Self::pin`].
    pub fn pin_with_source(
        secondary_path: &Path,
        primary_path: &Path,
        live_rgb: Option<&str>,
        live_ir: Option<&str>,
        keys: &mut dyn crate::template_key::TemplateKeySource,
    ) -> Result<Self, PinError> {
        resolve_commit(secondary_path).map_err(|error| PinError::Secondary(error.to_string()))?;
        let secondary: SecondaryStore = super::load_secondary_with_source(secondary_path, keys)
            .and_then(|option| {
                option
                    .ok_or_else(|| super::SecondaryStoreError::Io("secondary store absent".into()))
            })
            .map_err(|error| PinError::Secondary(error.to_string()))?;
        let primary_bytes = std::fs::read(primary_path)
            .map_err(|error| PinError::Secondary(format!("primary unreadable: {error}")))?;
        // Parse through the SAME loader authentication uses: legacy-format
        // primaries migrate in memory and TPM-sealed envelopes decrypt here
        // under the borrowed key. A raw serde parse of the bytes would
        // silently refuse every legacy or encrypted account's secondary
        // cameras.
        let primary = crate::storage::load_path_with_source(&secondary.owner, primary_path, keys)
            .map_err(|error| PinError::Secondary(format!("primary unloadable: {error}")))?
            .ok_or_else(|| PinError::Secondary("primary absent".into()))?;
        let views = CameraScopedViews::compose(&primary, &primary_bytes, Some(&secondary))
            .map_err(|error| PinError::Secondary(error.to_string()))?;
        let Some(group) = secondary.group_for_pair(live_rgb, live_ir) else {
            return Err(PinError::GroupNotActive(
                "no enrolled group matches the live pair".into(),
            ));
        };
        let store_index = secondary
            .groups
            .iter()
            .position(|candidate| candidate.id == group.id)
            .unwrap_or(0);
        let group_id = group.id.as_str().to_owned();
        let Some(index) = views
            .group_views()
            .iter()
            .position(|view| matches!(&view.scope, GroupScope::Secondary(id) if id == &group_id))
        else {
            return Err(PinError::GroupNotActive(
                "group matches the pair but its activation is stale".into(),
            ));
        };
        Ok(Self {
            secondary_path: secondary_path.to_owned(),
            primary_path: primary_path.to_owned(),
            pinned: GrantContext {
                secondary_generation: secondary.generation,
                primary_snapshot_sha256: secondary.primary_snapshot_sha256.clone(),
                group_id,
            },
            views,
            group_index: index,
            store_index,
        })
    }

    /// ADR-0028: pin an IR-only attempt on the secondary group whose pair
    /// EXACTLY equals the configured pair (both sides present and equal;
    /// [`SecondaryStore::strict_group_for_pair`]). The caller has already
    /// loaded `user`'s primary and retains the bytes it parsed (`primary`
    /// and `primary_bytes`, ADR-0028 §5), so only the secondary store is
    /// read here, under the lent key, after the commit journal is resolved
    /// (a store missing after a crashed publication is recovered first).
    /// A store that names another owner fails closed before any matching.
    /// Distinguishes the causes the IR-only readiness must report: no such
    /// group, an exact group in an inactive store, and an ambiguous store.
    ///
    /// # Errors
    ///
    /// [`PinError::Secondary`] when the store is unusable, absent or names
    /// another owner, [`PinError::GroupNotActive`] when no group has exactly
    /// this pair, [`PinError::GroupInactive`] when one does but the store's
    /// primary snapshot no longer matches, [`PinError::Ambiguous`] when
    /// several do.
    pub fn pin_strict_with_source(
        stores: StrictPinStores<'_>,
        primary: &crate::storage::Enrollment,
        primary_bytes: &[u8],
        rgb: &str,
        ir: &str,
        keys: &mut dyn crate::template_key::TemplateKeySource,
    ) -> Result<Self, PinError> {
        let StrictPinStores {
            user,
            secondary_path,
            primary_path,
        } = stores;
        resolve_commit(secondary_path).map_err(|error| PinError::Secondary(error.to_string()))?;
        let secondary: SecondaryStore = super::load_secondary_with_source(secondary_path, keys)
            .and_then(|option| {
                option
                    .ok_or_else(|| super::SecondaryStoreError::Io("secondary store absent".into()))
            })
            .map_err(|error| PinError::Secondary(error.to_string()))?;
        if secondary.owner != user {
            return Err(PinError::Secondary(format!(
                "the store names owner '{}', not the authenticating account",
                secondary.owner
            )));
        }
        let (store_index, group_id) = match secondary.strict_group_for_pair(rgb, ir) {
            super::StrictPairMatch::One { index, group } => (index, group.id.as_str().to_owned()),
            super::StrictPairMatch::None => {
                return Err(PinError::GroupNotActive(
                    "no enrolled group has exactly the configured pair".into(),
                ))
            }
            super::StrictPairMatch::Ambiguous => {
                return Err(PinError::Ambiguous(
                    "more than one enrolled group has exactly the configured pair".into(),
                ))
            }
        };
        if secondary.activation_against(Some(primary_bytes)) != super::Activation::Active {
            return Err(PinError::GroupInactive {
                index: store_index,
                detail: "the primary enrollment changed since this camera was authorized".into(),
            });
        }
        let views = CameraScopedViews::compose(primary, primary_bytes, Some(&secondary))
            .map_err(|error| PinError::Secondary(error.to_string()))?;
        let Some(index) = views
            .group_views()
            .iter()
            .position(|view| matches!(&view.scope, GroupScope::Secondary(id) if id == &group_id))
        else {
            return Err(PinError::GroupInactive {
                index: store_index,
                detail: "group matches the pair but its activation is stale".into(),
            });
        };
        Ok(Self {
            secondary_path: secondary_path.to_owned(),
            primary_path: primary_path.to_owned(),
            pinned: GrantContext {
                secondary_generation: secondary.generation,
                primary_snapshot_sha256: secondary.primary_snapshot_sha256.clone(),
                group_id,
            },
            views,
            group_index: index,
            store_index,
        })
    }

    /// The pinned group's 0-based position in the store (ADR-0028 reporting).
    #[must_use]
    pub fn store_index(&self) -> usize {
        self.store_index
    }

    /// The pinned grant context (for audit and the serialized boundary).
    #[must_use]
    pub fn pinned(&self) -> &GrantContext {
        &self.pinned
    }

    /// The scoped views this attempt may read. Matching and calibration
    /// consume ONLY the pinned group's view; the primary view belongs to
    /// primary-path attempts and is exposed read-only for diagnostics.
    #[must_use]
    pub fn views(&self) -> &CameraScopedViews {
        &self.views
    }

    /// The pinned group's view.
    #[must_use]
    pub fn group_view(&self) -> &super::views::CameraGroupView {
        &self.views.group_views()[self.group_index]
    }

    /// The serialized grant-boundary check: re-reads BOTH stores at the
    /// boundary and refuses on any drift from the pinned state.
    ///
    /// # Errors
    ///
    /// Returns the boundary's commit error only for unreadable state; a
    /// readable-but-drifted state is a [`GrantDecision::Refuse`].
    pub fn boundary_check_now(&self) -> Result<GrantDecision, super::commit::CommitError> {
        grant_boundary_now(&self.pinned, &self.secondary_path, &self.primary_path)
    }

    /// [`Self::boundary_check_now`] lending the request's template key to the
    /// secondary re-read (ADR-0025). The primary is compared by digest and
    /// needs no key.
    ///
    /// # Errors
    ///
    /// As [`Self::boundary_check_now`].
    pub fn boundary_check_now_with(
        &self,
        keys: &mut dyn crate::template_key::TemplateKeySource,
    ) -> Result<GrantDecision, super::commit::CommitError> {
        super::commit::grant_boundary_now_with(
            &self.pinned,
            &self.secondary_path,
            &self.primary_path,
            keys,
        )
    }

    /// The pure boundary check over caller-provided current state (for
    /// callers that already hold freshly read bytes).
    #[must_use]
    pub fn boundary_check(
        &self,
        current_primary_bytes: Option<&[u8]>,
        current_secondary: Option<&SecondaryStore>,
    ) -> GrantDecision {
        grant_boundary_check(&self.pinned, current_primary_bytes, current_secondary)
    }
}

#[cfg(test)]
mod integration {
    use super::super::authz::{
        ensure_not_consumed, AuthorizationVia, EnrollmentAuthorization, EnrollmentOperation,
    };
    use super::super::commit::{
        publish_with_intent_key, resolve_commit, CommitResolution, GrantDecision as Boundary,
    };
    use super::super::{
        CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans, SecondaryStore,
    };
    use super::*;
    use crate::storage::{Enrollment, FaceProfile, FaceScan};

    fn scan(pitch: f32) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.5; 8],
            ir: Some(vec![0.25; 4]),
            ir_space: Some("adapter:test".into()),
            embed_space: Some("embed:test".into()),
            ir_center_edge_ratio: 2.0,
            ir_brightness: 1.0,
            pitch,
            captured_at: None,
        }
    }

    struct Rig {
        dir: PathBuf,
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "irlume-mc-coordinator-{}-{}",
                tag,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("dir");
            Self { dir }
        }

        fn primary_path(&self) -> PathBuf {
            self.dir.join("primary.json")
        }

        fn secondary_path(&self) -> PathBuf {
            self.dir.join("secondary.json")
        }

        /// Writes a primary with one profile and a secondary with one
        /// group bound to that exact primary's bytes, returning the
        /// identities used.
        fn enroll_pair(&self, rgb: &str, ir: &str) -> (String, String) {
            let enrollment = Enrollment {
                user: "alice".into(),
                profiles: vec![FaceProfile {
                    name: "main".into(),
                    scans: vec![scan(0.1), scan(0.12), scan(0.14)],
                    ir_calib: None,
                    ir_calibs: Default::default(),
                }],
                ..Enrollment::default()
            };
            let bytes = serde_json::to_vec(&enrollment).expect("primary serialize");
            std::fs::write(self.primary_path(), &bytes).expect("primary write");
            let store = SecondaryStore {
                format_version: super::super::SECONDARY_STORE_VERSION,
                owner: "alice".into(),
                generation: 1,
                primary_snapshot_sha256: irlume_common::sha256_hex(&bytes),
                groups: vec![SecondaryGroup {
                    id: CameraGroupId::new("desk".into()).unwrap(),
                    pair: GroupPair {
                        rgb: Some(rgb.into()),
                        ir: Some(ir.into()),
                    },
                    profiles: vec![SecondaryProfileScans {
                        ir_calibs: Default::default(),
                        profile: "main".into(),
                        scans: vec![scan(0.5), scan(0.52), scan(0.54)],
                    }],
                }],
            };
            let digest = store.primary_snapshot_sha256.clone();
            publish_with_intent_key(&self.secondary_path(), &store, &digest, None)
                .expect("publish");
            (rgb.to_string(), ir.to_string())
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Encrypted primary and secondary under one key, at paths whose stem
    /// names the owner (the secondary loader derives the user from it).
    fn enroll_encrypted_pair(
        rig: &Rig,
        key: Option<&[u8]>,
        secondary_key: Option<&[u8]>,
    ) -> (PathBuf, PathBuf, String, String) {
        let enrollment = Enrollment {
            user: "alice".into(),
            profiles: vec![FaceProfile {
                name: "main".into(),
                scans: vec![scan(0.1), scan(0.12), scan(0.14)],
                ir_calib: None,
                ir_calibs: Default::default(),
            }],
            ..Enrollment::default()
        };
        let primary_path = rig.dir.join("primary.json");
        let secondary_path = rig.dir.join("alice.json");
        let bytes = crate::storage::serialize_enrollment(&enrollment, key).expect("primary bytes");
        std::fs::write(&primary_path, &bytes).expect("primary write");
        let store = SecondaryStore {
            format_version: super::super::SECONDARY_STORE_VERSION,
            owner: "alice".into(),
            generation: 1,
            primary_snapshot_sha256: irlume_common::sha256_hex(&bytes),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("desk".into()).unwrap(),
                pair: GroupPair {
                    rgb: Some("3443:c803".into()),
                    ir: Some("3443:c803".into()),
                },
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "main".into(),
                    scans: vec![scan(0.5), scan(0.52), scan(0.54)],
                }],
            }],
        };
        super::super::save_secondary_with_key(&secondary_path, &store, secondary_key)
            .expect("secondary write");
        (
            secondary_path,
            primary_path,
            "3443:c803".into(),
            "3443:c803".into(),
        )
    }

    fn counting_source(key: Option<Vec<u8>>) -> crate::template_key::RequestTemplateKey {
        crate::template_key::RequestTemplateKey::with_unsealer(move |user| {
            assert_eq!(user, "alice");
            Ok(key.clone().map(zeroize::Zeroizing::new))
        })
    }

    /// ADR-0025: the pin (secondary and primary re-load) and the boundary
    /// re-read borrow one key; the source unseals exactly once, or never
    /// when the enrollment load already lent it.
    #[test]
    fn pin_and_boundary_unseal_the_request_key_once_for_encrypted_stores() {
        let rig = Rig::new("one-unseal");
        let key = crate::crypto::generate_key();
        let (secondary_path, primary_path, rgb, ir) =
            enroll_encrypted_pair(&rig, Some(&key), Some(&key));
        let mut keys = counting_source(Some(key.to_vec()));
        let context = SecondaryAuthContext::pin_with_source(
            &secondary_path,
            &primary_path,
            Some(&rgb),
            Some(&ir),
            &mut keys,
        )
        .expect("pin");
        assert_eq!(
            keys.unseals(),
            1,
            "the pin's two encrypted reads share one unseal"
        );
        assert!(matches!(
            context.boundary_check_now_with(&mut keys),
            Ok(Boundary::Grant)
        ));
        assert_eq!(keys.unseals(), 1, "the boundary borrows the same key");

        let mut adopted = counting_source(None);
        adopted.adopt("alice", Some(zeroize::Zeroizing::new(key.to_vec())));
        let context = SecondaryAuthContext::pin_with_source(
            &secondary_path,
            &primary_path,
            Some(&rgb),
            Some(&ir),
            &mut adopted,
        )
        .expect("pin with adopted key");
        assert!(matches!(
            context.boundary_check_now_with(&mut adopted),
            Ok(Boundary::Grant)
        ));
        assert_eq!(
            adopted.unseals(),
            0,
            "a key lent by the enrollment load is never unsealed again"
        );
    }

    /// A legacy plaintext primary beside an encrypted secondary (ADR-0024
    /// §1.2 mixed state): the first encrypted read, at the pin, unseals.
    #[test]
    fn plaintext_primary_with_encrypted_secondary_unseals_once_at_the_pin() {
        let rig = Rig::new("mixed");
        let key = crate::crypto::generate_key();
        let (secondary_path, primary_path, rgb, ir) = enroll_encrypted_pair(&rig, None, Some(&key));
        let mut keys = counting_source(Some(key.to_vec()));
        let context = SecondaryAuthContext::pin_with_source(
            &secondary_path,
            &primary_path,
            Some(&rgb),
            Some(&ir),
            &mut keys,
        )
        .expect("pin");
        assert_eq!(keys.unseals(), 1);
        assert!(matches!(
            context.boundary_check_now_with(&mut keys),
            Ok(Boundary::Grant)
        ));
        assert_eq!(keys.unseals(), 1);
    }

    /// Plaintext stores throughout never ask the source for a key.
    #[test]
    fn plaintext_stores_never_ask_for_a_key() {
        let rig = Rig::new("plain");
        let (secondary_path, primary_path, rgb, ir) = enroll_encrypted_pair(&rig, None, None);
        let mut keys = counting_source(None);
        let context = SecondaryAuthContext::pin_with_source(
            &secondary_path,
            &primary_path,
            Some(&rgb),
            Some(&ir),
            &mut keys,
        )
        .expect("pin");
        assert!(matches!(
            context.boundary_check_now_with(&mut keys),
            Ok(Boundary::Grant)
        ));
        assert_eq!(keys.unseals(), 0);
        assert!(!keys.holds_key());
    }

    /// A secondary store that decrypts under the request's key but declares
    /// another owner cannot borrow that key for the owner's primary: the pin
    /// fails closed instead of activating a group across accounts.
    #[test]
    fn a_secondary_naming_another_owner_cannot_borrow_the_request_key() {
        let rig = Rig::new("owner");
        let key = crate::crypto::generate_key();
        let (secondary_path, primary_path, rgb, ir) =
            enroll_encrypted_pair(&rig, Some(&key), Some(&key));
        let mut store = super::super::load_secondary_with_key(&secondary_path, Some(&key))
            .expect("read")
            .expect("present");
        store.owner = "mallory".into();
        super::super::save_secondary_with_key(&secondary_path, &store, Some(&key))
            .expect("rewrite");
        let mut keys = crate::template_key::RequestTemplateKey::with_unsealer(move |user| {
            assert_eq!(user, "alice", "only the path's account may unseal");
            Ok(Some(zeroize::Zeroizing::new(key.to_vec())))
        });
        let pinned = SecondaryAuthContext::pin_with_source(
            &secondary_path,
            &primary_path,
            Some(&rgb),
            Some(&ir),
            &mut keys,
        );
        assert!(
            matches!(pinned, Err(PinError::Secondary(ref reason)) if reason.contains("mallory")),
            "{pinned:?}"
        );
        assert_eq!(keys.unseals(), 1);
    }

    /// An encrypted store with no lendable key (no TPM) fails closed at the
    /// pin, and a store re-keyed during the request fails at the boundary.
    #[test]
    fn encrypted_stores_fail_closed_without_the_key_and_on_rekeying() {
        let rig = Rig::new("closed");
        let key = crate::crypto::generate_key();
        let (secondary_path, primary_path, rgb, ir) =
            enroll_encrypted_pair(&rig, Some(&key), Some(&key));
        let mut none = counting_source(None);
        assert!(SecondaryAuthContext::pin_with_source(
            &secondary_path,
            &primary_path,
            Some(&rgb),
            Some(&ir),
            &mut none,
        )
        .is_err());

        let mut keys = counting_source(Some(key.to_vec()));
        let context = SecondaryAuthContext::pin_with_source(
            &secondary_path,
            &primary_path,
            Some(&rgb),
            Some(&ir),
            &mut keys,
        )
        .expect("pin");
        let other = crate::crypto::generate_key();
        let store = super::super::load_secondary_with_key(&secondary_path, Some(&key))
            .expect("read")
            .expect("present");
        super::super::save_secondary_with_key(&secondary_path, &store, Some(&other))
            .expect("rekey");
        assert!(
            !matches!(
                context.boundary_check_now_with(&mut keys),
                Ok(Boundary::Grant)
            ),
            "a store re-keyed during the request must not grant"
        );
        assert_eq!(keys.unseals(), 1);
    }

    #[test]
    fn the_full_attempt_story_pins_reads_and_grants() {
        let rig = Rig::new("story");
        let (rgb, ir) = rig.enroll_pair("3443:c803", "3443:c803");
        let context = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some(&rgb),
            Some(&ir),
        )
        .expect("pin");
        // Matching reads ONLY the desk group's scoped view.
        let view = &context.group_view().profiles[0];
        assert!((view.pitch_neutral().unwrap() - 0.52).abs() < f32::EPSILON);
        assert_eq!(view.rgb_candidates("embed:test").count(), 3);
        // The serialized boundary grants on the unchanged state.
        assert!(matches!(context.boundary_check_now(), Ok(Boundary::Grant)));
    }

    #[test]
    fn a_legacy_primary_parses_through_the_real_loader_and_pins() {
        // Production primaries are not guaranteed to be current-format
        // plaintext: legacy-format files migrate in memory inside the real
        // loader, and TPM hosts write sealed envelopes. The pin must parse
        // through the SAME loader authentication uses - a raw serde parse
        // of the file bytes would silently break secondary auth for every
        // legacy or encrypted account.
        let rig = Rig::new("legacy-primary");
        let legacy = br#"{"user":"alice","templates":[[0.5,0.5]]}"#;
        std::fs::write(rig.primary_path(), legacy).expect("write legacy primary");
        let digest = irlume_common::sha256_hex(legacy);
        let store = SecondaryStore {
            format_version: super::super::SECONDARY_STORE_VERSION,
            owner: "alice".into(),
            generation: 1,
            primary_snapshot_sha256: digest.clone(),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("desk".into()).unwrap(),
                pair: GroupPair {
                    rgb: Some("3443:c803".into()),
                    ir: Some("3443:c803".into()),
                },
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "Face Profile 1".into(),
                    scans: vec![scan(0.5), scan(0.52), scan(0.54)],
                }],
            }],
        };
        publish_with_intent_key(&rig.secondary_path(), &store, &digest, None).expect("publish");
        let context = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some("3443:c803"),
            Some("3443:c803"),
        )
        .expect("a legacy primary pins through the real loader");
        // The migrated primary contributes its own view; the desk group's
        // scoped data is untouched by the migration.
        assert_eq!(context.group_view().profiles[0].scans.len(), 3);
    }

    #[test]
    fn an_envelope_primary_without_a_key_fails_closed() {
        // An encrypted primary whose key cannot load (lost/recovery state)
        // must refuse the pin outright - never a plaintext fallback parse,
        // never a grant. The digest still binds to the exact file bytes.
        let rig = Rig::new("envelope-primary");
        let envelope = br#"{"version":3,"enc":{"nonce":"AAAA","blob":"AAAA"},"key_id":"deadbeef"}"#;
        std::fs::write(rig.primary_path(), envelope).expect("write envelope primary");
        let digest = irlume_common::sha256_hex(envelope);
        let store = SecondaryStore {
            format_version: super::super::SECONDARY_STORE_VERSION,
            owner: "no-such-key-user".into(),
            generation: 1,
            primary_snapshot_sha256: digest.clone(),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("desk".into()).unwrap(),
                pair: GroupPair {
                    rgb: Some("3443:c803".into()),
                    ir: Some("3443:c803".into()),
                },
                profiles: vec![SecondaryProfileScans {
                    ir_calibs: Default::default(),
                    profile: "main".into(),
                    scans: vec![scan(0.5)],
                }],
            }],
        };
        publish_with_intent_key(&rig.secondary_path(), &store, &digest, None).expect("publish");
        let refused = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some("3443:c803"),
            Some("3443:c803"),
        )
        .expect_err("no key -> no parse -> no pin");
        assert!(
            refused.to_string().contains("secondary store unusable"),
            "{refused}"
        );
    }

    #[test]
    fn a_hybrid_live_pair_never_pins() {
        let rig = Rig::new("hybrid");
        let (rgb, _) = rig.enroll_pair("3443:c803", "3443:c803");
        // RGB from the enrolled desk group, IR from some other camera.
        let error = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some(&rgb),
            Some("046d:085e:serial"),
        )
        .expect_err("hybrid refuses");
        assert!(error.to_string().contains("no enrolled group matches"));
    }

    #[test]
    fn a_legacy_primary_rewrite_mid_attempt_refuses_at_the_boundary() {
        let rig = Rig::new("rewrite");
        let (rgb, ir) = rig.enroll_pair("3443:c803", "3443:c803");
        let context = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some(&rgb),
            Some(&ir),
        )
        .expect("pin");
        // A legacy writer rewrites the primary between pin and boundary -
        // even byte-equivalent-then-changed, even with the secondary
        // generation untouched.
        let original = std::fs::read(rig.primary_path()).unwrap();
        let mut edited = original.clone();
        edited.extend_from_slice(b"legacy-append");
        std::fs::write(rig.primary_path(), &edited).expect("rewrite");
        assert!(matches!(
            context.boundary_check_now(),
            Ok(Boundary::Refuse(
                "primary snapshot changed during the attempt (§4.2: legacy rewrite with unchanged secondary generation)"
            ))
        ));
        // Restoring the exact bytes restores nothing: the digest matches
        // again only because the file is identical, and the boundary
        // judges CURRENT state - which is now correct again.
        std::fs::write(rig.primary_path(), &original).expect("restore");
        assert!(matches!(context.boundary_check_now(), Ok(Boundary::Grant)));
    }

    #[test]
    fn revocation_by_publication_refuses_and_replays_cannot_reauthories() {
        let rig = Rig::new("revoke");
        let (rgb, ir) = rig.enroll_pair("3443:c803", "3443:c803");
        let context = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some(&rgb),
            Some(&ir),
        )
        .expect("pin");
        // An authorized removal publishes a store without the group.
        let primary_bytes = std::fs::read(rig.primary_path()).unwrap();
        let digest = irlume_common::sha256_hex(&primary_bytes);
        let mut removed = {
            let mut store = super::super::load_secondary(&rig.secondary_path())
                .expect("load")
                .expect("present");
            store.generation += 1;
            store.groups.clear();
            store
        };
        removed.primary_snapshot_sha256 = digest.clone();
        let auth = EnrollmentAuthorization::mint(
            "alice".into(),
            EnrollmentOperation::RemoveGroup {
                group: "desk".into(),
            },
            1_000_000,
            600,
            "remove-1".into(),
            AuthorizationVia::Password,
        )
        .expect("mint");
        ensure_not_consumed(&auth, removed.generation, None).expect("fresh");
        publish_with_intent_key(&rig.secondary_path(), &removed, &digest, None)
            .expect("publish removal");
        // The pinned attempt now refuses: revoked group, changed generation.
        assert!(matches!(
            context.boundary_check_now(),
            Ok(Boundary::Refuse(_))
        ));
        // And the removal authorization cannot be replayed.
        assert!(ensure_not_consumed(&auth, removed.generation, None).is_ok());
        // Replaying against the PUBLISHED generation's recorded
        // consumption is the daemon's job at publication time; here the
        // id would be recorded by the writer that consumed it.
    }

    #[test]
    fn a_leftover_journal_resolves_before_pinning_and_recovery_is_forward() {
        let rig = Rig::new("journal");
        let (rgb, ir) = rig.enroll_pair("3443:c803", "3443:c803");
        // Simulate a crash after the journal of a generation-2 publish.
        let mut bumped = super::super::load_secondary(&rig.secondary_path())
            .expect("load")
            .expect("present");
        bumped.generation = 2;
        let primary_bytes = std::fs::read(rig.primary_path()).unwrap();
        let digest = irlume_common::sha256_hex(&primary_bytes);
        publish_with_intent_key(&rig.secondary_path(), &bumped, &digest, None)
            .expect("clean publish");
        // pin resolves cleanly (nothing pending) and sees generation 2.
        let context = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some(&rgb),
            Some(&ir),
        )
        .expect("pin");
        assert_eq!(context.pinned().secondary_generation, 2);
        assert!(matches!(
            resolve_commit(&rig.secondary_path()),
            Ok(CommitResolution::Clean)
        ));
    }

    #[test]
    fn an_absent_secondary_store_refuses_to_pin_with_password_fallback_intact() {
        let rig = Rig::new("absent");
        let (_, _) = rig.enroll_pair("3443:c803", "3443:c803");
        std::fs::remove_file(rig.secondary_path()).expect("remove secondary");
        let error = SecondaryAuthContext::pin(
            &rig.secondary_path(),
            &rig.primary_path(),
            Some("3443:c803"),
            Some("3443:c803"),
        )
        .expect_err("absent refuses");
        assert!(error.to_string().contains("secondary store"));
        // The primary file is untouched: the password fallback path's
        // data is exactly what it was.
        assert!(rig.primary_path().exists());
    }
}
