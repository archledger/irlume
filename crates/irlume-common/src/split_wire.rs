// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Share-safe split-management wire types (ADR-0032 §4, §6).
//!
//! Split-pair role and location information is exposed only through these
//! opt-in request and reply types; the closed `CameraCandidate` contract is
//! unchanged. Non-root peers receive share-safe projections only: display
//! controller labels, root-domain labels and relative ports. Raw controller
//! paths, binding identities, serials, node paths and the complete internal
//! binding key stay root-only.

use serde::{Deserialize, Serialize};

/// Opt-in listing limit, including JSON framing. A 64 KiB generation can
/// expand through JSON escaping and canonical keys; leave room for candidates.
/// Other requests retain the client's ordinary 64 KiB reply limit.
pub const MAX_SPLIT_RESPONSE_BYTES: u64 = 1024 * 1024;

/// The displayed guard for one side of a split mutation (ADR-0032 §4): the
/// instance id, generation and selected endpoint from the displayed inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitSideGuard {
    /// The inventory instance id for this side.
    pub instance_id: String,
    /// This side's generation within its instance.
    pub generation: u64,
    /// The selected endpoint path for this side.
    pub endpoint: String,
}

/// The complete mutation guard: expected supervisor, publication revision and
/// both displayed sides in role order (RGB then IR).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitMutationGuard {
    /// The expected supervisor id from the displayed publication.
    pub supervisor_id: String,
    /// The expected publication revision.
    pub revision: u64,
    /// The RGB side's displayed guard.
    pub rgb: SplitSideGuard,
    /// The IR side's displayed guard.
    pub ir: SplitSideGuard,
}

/// Share-safe projection of one authorization side (ADR-0032 §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitSideProjection {
    /// Display controller label (never the raw controller path).
    pub controller_label: String,
    /// Root-domain label (`usb2`, `superspeed`).
    pub domain_label: String,
    /// Relative port chain.
    pub ports: Vec<u8>,
}

/// Root-only facts for one authorization side (ADR-0032 §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitSideFacts {
    /// Binding identity `vid:pid[:serial]`.
    pub identity: String,
    /// Selected node path.
    pub path: String,
    /// Controller identity (PCI address).
    pub controller: String,
    /// Root-hub protocol domain (`usb2`, `superspeed`).
    pub domain: String,
    /// Relative port chain.
    pub ports: Vec<u8>,
}

/// One side of a record as the reply carries it: projections for everyone,
/// full facts only for root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitRecordSide {
    /// Non-root view.
    ShareSafe(SplitSideProjection),
    /// Root view.
    Root(SplitSideFacts),
}

/// One authorization record as a reply carries it (RGB then IR).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRecordView {
    /// Canonical pair key, present only for root. Older replies omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The RGB side.
    pub rgb: SplitRecordSide,
    /// The IR side.
    pub ir: SplitRecordSide,
}

/// The selection as a reply carries it: the canonical key text is root-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitSelectionView {
    /// Non-root view: whether the selection resolves, nothing else.
    ShareSafe {
        /// Whether the selected pair resolves in the generation.
        resolves: bool,
    },
    /// Root view.
    Root {
        /// The selected pair's canonical key text.
        key: String,
        /// Whether the selected pair resolves in the generation.
        resolves: bool,
    },
}

/// Store-level state for status and listings (ADR-0032 §4.1.2, §4.1.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitStoreState {
    /// No generation is referenced.
    Absent,
    /// A needed file could not be read.
    Unreadable,
    /// A referenced state is malformed or a selection does not resolve.
    Malformed,
    /// The referenced generation's bytes do not match the digest.
    DigestMismatch,
    /// The publication is coherent.
    Valid,
}

/// The opt-in listing reply (ADR-0032 §6): the publication, the records and
/// the selection, at the caller's privilege level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitPublicationView {
    /// The publication's supervisor id.
    pub supervisor_id: String,
    /// The publication revision.
    pub revision: u64,
    /// The store state.
    pub store_state: SplitStoreState,
    /// The authorization records, in overlap-resolution order.
    pub records: Vec<SplitRecordView>,
    /// The selection, when one is recorded.
    pub selected: Option<SplitSelectionView>,
    /// Current classified sides, independent of saved authorizations. Absent
    /// from older replies; an empty list grants no mutation authority.
    #[serde(default)]
    pub candidates: Vec<SplitCandidateView>,
}

/// One side available for a guarded add or selection. Root gets the literal
/// endpoint and facts; an ordinary peer gets a daemon-keyed endpoint token
/// and share-safe projections. Tokens are display-only, not authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitCandidateView {
    /// Displayed instance, generation and endpoint guard.
    pub guard: SplitSideGuard,
    /// Classification from this publication, never supplied by the client.
    pub role: SplitCandidateRole,
    /// Facts at the caller's privilege level.
    pub facts: SplitRecordSide,
}

/// Roles eligible for a split-pair side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitCandidateRole {
    /// Color endpoint.
    Rgb,
    /// Infrared endpoint.
    Ir,
}

impl SplitSideGuard {
    /// Validate a bounded per-side guard before accepting it from the wire.
    ///
    /// # Errors
    /// Returns a static reason for malformed identity or endpoint text.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::live_camera::valid_id(&self.instance_id) {
            return Err("invalid split guard instance id");
        }
        if self.endpoint.is_empty() {
            return Err("empty split guard endpoint");
        }
        Ok(())
    }
}

impl SplitMutationGuard {
    /// Validate the bounded mutation guard.
    ///
    /// # Errors
    /// Returns a static reason for malformed supervisor or side metadata.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::live_camera::valid_id(&self.supervisor_id) {
            return Err("invalid split guard supervisor id");
        }
        self.rgb.validate()?;
        self.ir.validate()
    }
}

/// Verify a mutation guard against the current inventory publication
/// (ADR-0032 §4): the expected supervisor and revision, and both displayed
/// sides in role order, each naming its own distinct candidate with the
/// recorded instance id, generation and endpoint.
///
/// Role classification itself is the daemon's publication fact; this check
/// proves the guard names two distinct physical groups from the displayed
/// snapshot and nothing else.
///
/// # Errors
/// A static reason when the publication is not current, the supervisor or
/// revision is stale, a side is missing from the publication, or both sides
/// name the same candidate.
pub fn verify_split_guard(
    guard: &SplitMutationGuard,
    snapshot: &crate::live_camera::CameraInventorySnapshot,
) -> Result<(), &'static str> {
    use crate::live_camera::CameraInventoryState;
    guard.validate()?;
    if snapshot.validate().is_err()
        || snapshot.state != CameraInventoryState::Current
        || snapshot.supervisor_id.as_deref() != Some(guard.supervisor_id.as_str())
        || snapshot.revision != guard.revision
    {
        return Err("split guard does not match the current publication");
    }
    let side_candidate = |side: &SplitSideGuard| {
        snapshot.candidates.iter().position(|c| {
            c.instance_id == side.instance_id
                && c.generation == side.generation
                && c.endpoint_paths.iter().any(|p| p == &side.endpoint)
        })
    };
    let (Some(rgb), Some(ir)) = (side_candidate(&guard.rgb), side_candidate(&guard.ir)) else {
        return Err("split guard side is not in the publication");
    };
    if rgb == ir {
        return Err("split guard sides must name two distinct candidates");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPER: &str = "0123456789abcdef0123456789abcdef";
    const RGB_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IR_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn guard() -> SplitMutationGuard {
        SplitMutationGuard {
            supervisor_id: SUPER.into(),
            revision: 7,
            rgb: SplitSideGuard {
                instance_id: RGB_ID.into(),
                generation: 1,
                endpoint: "/dev/video0".into(),
            },
            ir: SplitSideGuard {
                instance_id: IR_ID.into(),
                generation: 2,
                endpoint: "/dev/video1".into(),
            },
        }
    }

    #[test]
    fn guards_validate_and_bound() {
        assert_eq!(guard().validate(), Ok(()));
        let mut bad = guard();
        bad.supervisor_id = "0".repeat(32);
        assert!(bad.validate().is_err());
        let mut bad = guard();
        bad.rgb.instance_id = "0".repeat(32);
        assert!(bad.validate().is_err());
        let mut bad = guard();
        bad.ir.endpoint = String::new();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn requests_round_trip_through_json() {
        let request = super::super::Request::AddSplitAuthorization {
            guard: Box::new(guard()),
            rgb: Box::new(SplitSideFacts {
                identity: "a:1".into(),
                path: "/dev/video0".into(),
                controller: "0000:00:14.0".into(),
                domain: "usb2".into(),
                ports: vec![8],
            }),
            ir: Box::new(SplitSideFacts {
                identity: "b:2".into(),
                path: "/dev/video1".into(),
                controller: "0000:00:14.0".into(),
                domain: "usb2".into(),
                ports: vec![5],
            }),
        };
        let text = serde_json::to_string(&request).unwrap();
        let back: super::super::Request = serde_json::from_str(&text).unwrap();
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            text,
            "requests must round-trip"
        );
    }

    #[test]
    fn an_unknown_variant_fails_to_parse() {
        // The older-daemon behavior every split request relies on: an unknown
        // variant is a visible decode failure, never a silent success.
        assert!(serde_json::from_str::<super::super::Request>(r#"{"SplitNonsense":{}}"#).is_err());
    }

    #[test]
    fn projection_views_carry_no_raw_facts() {
        let side = SplitRecordSide::ShareSafe(SplitSideProjection {
            controller_label: "0000:00:14.0".into(),
            domain_label: "usb2".into(),
            ports: vec![8],
        });
        let text = serde_json::to_string(&side).unwrap();
        for forbidden in ["identity", "path", "controller\"", "serial"] {
            assert!(
                !text.contains(forbidden),
                "share-safe view leaked {forbidden}: {text}"
            );
        }
        let selected = SplitSelectionView::ShareSafe { resolves: true };
        let text = serde_json::to_string(&selected).unwrap();
        assert!(
            !text.contains("split1;"),
            "share-safe selection leaked the key"
        );
    }

    fn snapshot() -> crate::live_camera::CameraInventorySnapshot {
        crate::live_camera::CameraInventorySnapshot {
            state: crate::live_camera::CameraInventoryState::Current,
            supervisor_id: Some(SUPER.into()),
            revision: 7,
            observed_ago_ms: Some(100),
            reason: None,
            candidates: vec![
                crate::live_camera::CameraCandidate {
                    instance_id: RGB_ID.into(),
                    generation: 1,
                    endpoint_paths: vec!["/dev/video0".into(), "/dev/video2".into()],
                },
                crate::live_camera::CameraCandidate {
                    instance_id: IR_ID.into(),
                    generation: 2,
                    endpoint_paths: vec!["/dev/video1".into(), "/dev/video3".into()],
                },
            ],
        }
    }

    #[test]
    fn a_valid_guard_matches_the_current_publication() {
        assert_eq!(verify_split_guard(&guard(), &snapshot()), Ok(()));
    }

    #[test]
    fn a_stale_revision_or_wrong_supervisor_refuses() {
        let mut stale = snapshot();
        stale.revision = 8;
        assert!(verify_split_guard(&guard(), &stale).is_err());
        let mut wrong = snapshot();
        wrong.supervisor_id = Some("f".repeat(32));
        assert!(verify_split_guard(&guard(), &wrong).is_err());
        let mut refreshing = snapshot();
        refreshing.state = crate::live_camera::CameraInventoryState::Refreshing;
        assert!(verify_split_guard(&guard(), &refreshing).is_err());
    }

    #[test]
    fn a_guard_side_missing_from_the_publication_refuses() {
        let mut missing = guard();
        missing.ir.endpoint = "/dev/video9".into();
        assert!(verify_split_guard(&missing, &snapshot()).is_err());
        let mut missing = guard();
        missing.rgb.generation = 9;
        assert!(verify_split_guard(&missing, &snapshot()).is_err());
    }

    #[test]
    fn both_sides_must_name_distinct_candidates() {
        let mut same = guard();
        same.ir.instance_id = same.rgb.instance_id.clone();
        same.ir.endpoint = "/dev/video2".into();
        assert!(verify_split_guard(&same, &snapshot()).is_err());
    }

    #[test]
    fn store_states_round_trip() {
        let view = SplitPublicationView {
            candidates: Vec::new(),
            supervisor_id: SUPER.into(),
            revision: 7,
            store_state: SplitStoreState::Valid,
            records: vec![SplitRecordView {
                key: None,
                rgb: SplitRecordSide::Root(SplitSideFacts {
                    identity: "a:1".into(),
                    path: "/dev/video0".into(),
                    controller: "0000:00:14.0".into(),
                    domain: "usb2".into(),
                    ports: vec![8],
                }),
                ir: SplitRecordSide::Root(SplitSideFacts {
                    identity: "b:2".into(),
                    path: "/dev/video1".into(),
                    controller: "0000:00:14.0".into(),
                    domain: "usb2".into(),
                    ports: vec![5],
                }),
            }],
            selected: Some(SplitSelectionView::Root {
                key: "split1;a:1|0000:00:14.0|usb2|8;b:2|0000:00:14.0|usb2|5".into(),
                resolves: true,
            }),
        };
        let text = serde_json::to_string(&view).unwrap();
        let back: SplitPublicationView = serde_json::from_str(&text).unwrap();
        assert_eq!(back, view);
    }
}
