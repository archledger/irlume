//! Camera-scoped enrollment views (ADR-0024 Phase 1, §3): validated
//! per-(profile, camera group) candidate sets and derived state, so no
//! scoring or calibration consumer ever handles unfiltered enrollment data.
//!
//! Composition is the only way authentication-relevant code obtains
//! candidates: [`CameraScopedViews::compose`] takes the primary enrollment WITH its exact
//! bytes and an optional secondary store, checks the activation binding,
//! and returns one view per camera group. An INACTIVE secondary store
//! contributes NOTHING while the primary's own view remains valid
//! (§1.2: the independently valid primary stays usable).
//!
//! The scoped derived-state functions mirror the existing pooled
//! implementations exactly - same arithmetic, narrowed inputs - so scoping
//! is a pure restriction and cannot change behavior for the primary
//! group's existing single-camera results.

use super::{Activation, SecondaryStore};
use crate::storage::{Enrollment, FaceScan};
use serde::{Deserialize, Serialize};

/// The camera scope a view is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum GroupScope {
    /// The legacy primary store in its entirety: one validated camera
    /// scope by construction (ADR-0024 §2).
    Primary,
    /// One secondary group, identified by its immutable id.
    Secondary(String),
}

/// One profile's candidate scans on one camera group, plus the scoped
/// derived state computed ONLY from those scans.
#[derive(Clone, Debug)]
pub struct ScopedProfileView {
    pub profile: String,
    pub scans: Vec<FaceScan>,
}

impl ScopedProfileView {
    /// Pitch neutral from THIS group's scans only (same median arithmetic
    /// as the pooled `Enrollment::pitch_neutral`: pitches > 0.0, at least
    /// two, upper-middle median).
    #[must_use]
    pub fn pitch_neutral(&self) -> Option<f32> {
        let mut v: Vec<f32> = self
            .scans
            .iter()
            .map(|s| s.pitch)
            .filter(|&p| p > 0.0)
            .collect();
        if v.len() < 2 {
            return None;
        }
        v.sort_by(f32::total_cmp);
        Some(v[v.len() / 2])
    }

    /// Personalized IR ratio floor from THIS group's applicable scans only
    /// (same 75%-of-minimum arithmetic as the pooled
    /// `Enrollment::ir_center_edge_ratio_floor`: scans with IR and a
    /// positive ratio, at least two).
    #[must_use]
    pub fn ir_ratio_floor(&self) -> Option<f32> {
        let ratios: Vec<f32> = self
            .scans
            .iter()
            .filter(|s| s.ir.is_some() && s.ir_center_edge_ratio > 0.0)
            .map(|s| s.ir_center_edge_ratio)
            .collect();
        if ratios.len() < 2 {
            return None;
        }
        let min = ratios.iter().copied().fold(f32::INFINITY, f32::min);
        Some(min * 0.75)
    }

    /// Scans whose RGB embedding is usable by a recognizer in `space`
    /// (the existing selection rule, narrowed to this group).
    pub fn rgb_candidates<'a>(&'a self, space: &'a str) -> impl Iterator<Item = &'a FaceScan> {
        self.scans.iter().filter(move |scan| {
            scan.embed_space
                .as_deref()
                .unwrap_or(crate::storage::LEGACY_RECOGNIZER_SPACE)
                == space
        })
    }

    /// Scans with a compatible IR embedding in (`space`, `dim`), the
    /// existing selection rule narrowed to this group.
    pub fn ir_candidates<'a>(
        &'a self,
        space: &'a str,
        dim: usize,
    ) -> impl Iterator<Item = &'a FaceScan> {
        self.scans.iter().filter(move |scan| {
            scan.ir_space.as_deref() == Some(space)
                && scan.ir.as_ref().is_some_and(|ir| ir.len() == dim)
        })
    }

    /// Readiness predicates, kept DISTINCT (ADR-0024 §3): the capture
    /// target, the calibration-fit minimum, and authentication readiness
    /// answer different questions and are never derived from one another.
    /// The RGB and IR pipelines are named separately: the recognizer's
    /// embedding space and the IR adapter space are different spaces.
    #[must_use]
    pub fn readiness(&self, embed_space: &str, ir_space: &str, ir_dim: usize) -> GroupReadiness {
        let rgb = self.rgb_candidates(embed_space).count();
        let ir_pairs = self.ir_candidates(ir_space, ir_dim).count();
        GroupReadiness {
            scan_count: self.scans.len(),
            capture_target_met: self.scans.len() >= crate::storage::DEFAULT_ENROLL_SCANS,
            calibration_fittable: ir_pairs >= crate::calib::MIN_FIT_PAIRS,
            compatible_rgb_candidates: rgb,
            compatible_ir_pairs: ir_pairs,
        }
    }
}

/// Readiness facts for one (profile, group, pipeline). Fields are raw
/// observations; POLICY on top of them belongs to the existing modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupReadiness {
    /// Total retained scans in this profile-group.
    pub scan_count: usize,
    /// Whether the add-camera capture target (DEFAULT_ENROLL_SCANS) was met.
    pub capture_target_met: bool,
    /// Whether enough compatible IR pairs exist to ATTEMPT calibration
    /// fitting (MIN_FIT_PAIRS). Distinct from authentication eligibility.
    pub calibration_fittable: bool,
    /// RGB candidates in the recognizer space.
    pub compatible_rgb_candidates: usize,
    /// IR pairs compatible with (space, dim).
    pub compatible_ir_pairs: usize,
}

/// One camera group's complete view: its scope, per-profile views, and the
/// activation context that produced them.
#[derive(Clone, Debug)]
pub struct CameraGroupView {
    pub scope: GroupScope,
    pub profiles: Vec<ScopedProfileView>,
}

/// Why composition refused to produce views. Composition never guesses
/// (§1.2): an invalid secondary store is reported, and the caller decides
/// whether to proceed with primary-only views.
#[derive(Debug, PartialEq, Eq)]
pub enum ComposeError {
    /// The secondary store failed validation or loading; the diagnostic
    /// kind travels with it.
    SecondaryStore(String),
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComposeError::SecondaryStore(detail) => {
                write!(f, "secondary store unusable: {detail}")
            }
        }
    }
}

impl std::error::Error for ComposeError {}

/// The composed, camera-scoped view of one account's enrollment.
///
/// Authentication-relevant consumers use [`Self::group_views`] and never
/// the raw stores; that is the structural guarantee ADR-0024 §3 requires
/// ("diagnostic accessors that expose unfiltered data are not available as
/// authentication inputs").
#[derive(Clone, Debug)]
pub struct CameraScopedViews {
    groups: Vec<CameraGroupView>,
    secondary_active: bool,
}

impl CameraScopedViews {
    /// Composes the views. The primary's exact bytes are REQUIRED: the
    /// activation check compares the digest of the bytes actually read, not
    /// a digest stored elsewhere.
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::SecondaryStore`] when the secondary store
    /// fails its own validation (the caller may compose again without it).
    pub fn compose(
        primary: &Enrollment,
        primary_bytes: &[u8],
        secondary: Option<&SecondaryStore>,
    ) -> Result<Self, ComposeError> {
        if let Some(store) = secondary {
            store
                .validate()
                .map_err(|error| ComposeError::SecondaryStore(error.to_string()))?;
        }
        let mut groups = vec![CameraGroupView {
            scope: GroupScope::Primary,
            profiles: primary
                .profiles
                .iter()
                .map(|profile| ScopedProfileView {
                    profile: profile.name.clone(),
                    scans: profile.scans.clone(),
                })
                .collect(),
        }];
        let mut secondary_active = false;
        if let Some(store) = secondary {
            if matches!(
                store.activation_against(Some(primary_bytes)),
                Activation::Active
            ) {
                secondary_active = true;
                for group in &store.groups {
                    groups.push(CameraGroupView {
                        scope: GroupScope::Secondary(group.id.as_str().to_owned()),
                        profiles: group
                            .profiles
                            .iter()
                            .map(|scans| ScopedProfileView {
                                profile: scans.profile.clone(),
                                scans: scans.scans.clone(),
                            })
                            .collect(),
                    });
                }
            }
        }
        Ok(Self {
            groups,
            secondary_active,
        })
    }

    /// All group views, primary first.
    #[must_use]
    pub fn group_views(&self) -> &[CameraGroupView] {
        &self.groups
    }

    /// Whether any secondary data contributed views (activation held).
    #[must_use]
    pub fn secondary_active(&self) -> bool {
        self.secondary_active
    }

    /// The view for one secondary group id, if it is active.
    #[must_use]
    pub fn secondary_view(&self, id: &str) -> Option<&CameraGroupView> {
        self.groups.iter().find(|group| match &group.scope {
            GroupScope::Secondary(scope_id) => scope_id == id,
            GroupScope::Primary => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_camera::{CameraGroupId, GroupPair, SecondaryGroup, SecondaryProfileScans};
    use crate::storage::{Enrollment, FaceProfile, FaceScan};

    fn scan(pitch: f32, ratio: f32, with_ir: bool) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.5; 8],
            ir: with_ir.then(|| vec![0.25; 4]),
            ir_space: with_ir.then(|| "adapter:test".into()),
            embed_space: Some("embed:test".into()),
            ir_center_edge_ratio: ratio,
            ir_brightness: 1.0,
            pitch,
        }
    }

    fn primary() -> (Enrollment, Vec<u8>) {
        let enrollment = Enrollment {
            user: "alice".into(),
            profiles: vec![FaceProfile {
                name: "main".into(),
                scans: vec![
                    scan(0.10, 2.0, true),
                    scan(0.12, 2.2, true),
                    scan(0.14, 2.4, true),
                ],
                ir_calib: None,
                ir_calibs: Default::default(),
            }],
            ..Enrollment::default()
        };
        let bytes = serde_json::to_vec(&enrollment).expect("serialize primary");
        (enrollment, bytes)
    }

    fn secondary_for(primary_bytes: &[u8]) -> SecondaryStore {
        SecondaryStore {
            format_version: crate::multi_camera::SECONDARY_STORE_VERSION,
            owner: "alice".into(),
            generation: 1,
            primary_snapshot_sha256: irlume_common::sha256_hex(primary_bytes),
            groups: vec![SecondaryGroup {
                id: CameraGroupId::new("desk".into()).unwrap(),
                pair: GroupPair {
                    rgb: Some("3443:c803".into()),
                    ir: Some("3443:c803".into()),
                },
                profiles: vec![SecondaryProfileScans {
                    profile: "main".into(),
                    scans: vec![
                        scan(0.50, 1.2, true),
                        scan(0.52, 1.3, true),
                        scan(0.54, 1.4, true),
                    ],
                }],
            }],
        }
    }

    #[test]
    fn primary_view_is_alone_without_a_secondary_store() {
        let (enrollment, bytes) = primary();
        let views = CameraScopedViews::compose(&enrollment, &bytes, None).expect("compose");
        assert!(!views.secondary_active());
        assert_eq!(views.group_views().len(), 1);
        assert_eq!(views.group_views()[0].scope, GroupScope::Primary);
        let view = &views.group_views()[0].profiles[0];
        assert_eq!(view.scans.len(), 3);
        assert!((view.pitch_neutral().unwrap() - 0.12).abs() < f32::EPSILON);
        assert!((view.ir_ratio_floor().unwrap() - 1.5).abs() < f32::EPSILON);
    }

    #[test]
    fn an_active_secondary_contributes_only_its_own_group() {
        let (enrollment, bytes) = primary();
        let secondary = secondary_for(&bytes);
        let views =
            CameraScopedViews::compose(&enrollment, &bytes, Some(&secondary)).expect("compose");
        assert!(views.secondary_active());
        assert_eq!(views.group_views().len(), 2);
        let desk = views.secondary_view("desk").expect("desk view");
        let view = &desk.profiles[0];
        // Scoped derived state comes ONLY from the desk scans: pitch ~0.52
        // (not the primary's 0.12) and the ratio floor from the desk's
        // ratios (1.2 * 0.75 = 0.9, not the primary's 1.5).
        assert!((view.pitch_neutral().unwrap() - 0.52).abs() < f32::EPSILON);
        assert!((view.ir_ratio_floor().unwrap() - 0.9).abs() < f32::EPSILON);
        // Foreign-group data cannot influence the primary's view.
        let primary_view = &views.group_views()[0].profiles[0];
        assert!((primary_view.pitch_neutral().unwrap() - 0.12).abs() < f32::EPSILON);
        assert!((primary_view.ir_ratio_floor().unwrap() - 1.5).abs() < f32::EPSILON);
    }

    #[test]
    fn a_changed_primary_deactivates_secondary_data_but_keeps_the_primary() {
        let (enrollment, bytes) = primary();
        let secondary = secondary_for(&bytes);
        let changed = b"different-primary-bytes";
        let views =
            CameraScopedViews::compose(&enrollment, changed, Some(&secondary)).expect("compose");
        assert!(!views.secondary_active());
        assert_eq!(views.group_views().len(), 1);
        assert!(views.secondary_view("desk").is_none());
        // The independently valid primary remains usable (§1.2).
        assert_eq!(views.group_views()[0].profiles[0].scans.len(), 3);
    }

    #[test]
    fn candidate_selection_scopes_by_group_and_pipeline() {
        let (enrollment, bytes) = primary();
        let secondary = secondary_for(&bytes);
        let views =
            CameraScopedViews::compose(&enrollment, &bytes, Some(&secondary)).expect("compose");
        let desk = views.secondary_view("desk").expect("desk view");
        let view = &desk.profiles[0];
        assert_eq!(view.rgb_candidates("embed:test").count(), 3);
        assert_eq!(view.rgb_candidates("embed:other").count(), 0);
        assert_eq!(view.ir_candidates("adapter:test", 4).count(), 3);
        assert_eq!(view.ir_candidates("adapter:test", 8).count(), 0);
        assert_eq!(view.ir_candidates("raw", 4).count(), 0);
        // The primary's candidates are its own three scans only.
        let primary_view = &views.group_views()[0].profiles[0];
        assert_eq!(primary_view.rgb_candidates("embed:test").count(), 3);
    }

    #[test]
    fn readiness_predicates_stay_distinct() {
        let (enrollment, bytes) = primary();
        let views = CameraScopedViews::compose(&enrollment, &bytes, None).expect("compose");
        let view = &views.group_views()[0].profiles[0];
        let readiness = view.readiness("embed:test", "adapter:test", 4);
        // Three scans: below the ten-scan capture target, but enough IR
        // pairs to ATTEMPT fitting - the predicates are distinct facts.
        assert_eq!(readiness.scan_count, 3);
        assert!(!readiness.capture_target_met);
        assert!(readiness.calibration_fittable);
        assert_eq!(readiness.compatible_rgb_candidates, 3);
        assert_eq!(readiness.compatible_ir_pairs, 3);
    }

    #[test]
    fn an_invalid_secondary_store_refuses_composition_with_a_diagnostic() {
        let (enrollment, bytes) = primary();
        let mut secondary = secondary_for(&bytes);
        secondary.groups.push(secondary.groups[0].clone());
        let error = CameraScopedViews::compose(&enrollment, &bytes, Some(&secondary))
            .expect_err("duplicate ids refuse");
        assert!(error.to_string().contains("duplicate group id"));
    }
}
