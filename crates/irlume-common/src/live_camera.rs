// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Copied UVC connection inventory, not camera qualification or physical activity.

use serde::{Deserialize, Serialize};

/// Maximum number of candidates in a live status reply. Overflow is unavailable,
/// never an apparently complete truncated inventory.
pub const MAX_CAMERA_CANDIDATES: usize = 32;
/// Maximum endpoint count per physical group.
pub const MAX_CAMERA_ENDPOINTS: usize = 16;
/// Linux video node names need no arbitrary filesystem path in this interface.
pub const MAX_CAMERA_ENDPOINT_BYTES: usize = 96;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraInventoryState {
    #[default]
    Uninitialized,
    Current,
    Refreshing,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraInventoryReason {
    Monitor,
    Snapshot,
    Inventory,
    Bounds,
    WorkerStopped,
}

/// One connected UVC physical group. Endpoints may include metadata nodes;
/// their RGB/IR roles, usability and privacy state are deliberately unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CandidateWire")]
pub struct CameraCandidate {
    pub instance_id: String,
    pub generation: u64,
    pub endpoint_paths: Vec<String>,
}

/// A publication revision has meaning only with its supervisor ID. An unchanged
/// poll does not advance it. `observed_ago_ms` ages the last complete passive
/// census, not a video probe or proof of current streaming/idle state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SnapshotWire")]
pub struct CameraInventorySnapshot {
    pub state: CameraInventoryState,
    pub supervisor_id: Option<String>,
    pub revision: u64,
    pub observed_ago_ms: Option<u64>,
    pub reason: Option<CameraInventoryReason>,
    pub candidates: Vec<CameraCandidate>,
}

/// A user's selected connection identity carried through confirmation and any
/// administrator prompt. It conveys no role, capability or authorization proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SelectionWire")]
pub struct CameraSelection {
    pub supervisor_id: String,
    pub candidate: CameraCandidate,
}

impl CameraSelection {
    /// Validate a bounded selection guard before accepting it from the wire.
    ///
    /// # Errors
    /// Returns a static reason for malformed supervisor or candidate metadata.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_id(&self.supervisor_id) {
            return Err("invalid camera supervisor identity");
        }
        self.candidate.validate()
    }

    /// Require the same still-connected candidate before a camera switch. This
    /// only matches a copied snapshot; the caller owns the mutation boundary.
    #[must_use]
    pub fn matches(&self, snapshot: &CameraInventorySnapshot, rgb: &str, ir: &str) -> bool {
        self.validate().is_ok()
            && snapshot.validate().is_ok()
            && snapshot.state == CameraInventoryState::Current
            && snapshot.supervisor_id.as_deref() == Some(self.supervisor_id.as_str())
            && snapshot.candidates.contains(&self.candidate)
            && rgb != ir
            && self.candidate.endpoint_paths.iter().any(|p| p == rgb)
            && self.candidate.endpoint_paths.iter().any(|p| p == ir)
    }
}

impl CameraInventorySnapshot {
    /// Validate the closed, bounded display contract without accessing hardware.
    ///
    /// # Errors
    /// Returns a static reason for malformed identity, bounds or state metadata.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.candidates.len() > MAX_CAMERA_CANDIDATES {
            return Err("too many camera candidates");
        }
        if self
            .supervisor_id
            .as_deref()
            .is_some_and(|id| !valid_id(id))
        {
            return Err("invalid camera supervisor identity");
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut endpoints = std::collections::BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !ids.insert(&candidate.instance_id)
                || candidate
                    .endpoint_paths
                    .iter()
                    .any(|p| !endpoints.insert(p))
            {
                return Err("duplicate camera identity or endpoint");
            }
        }
        match self.state {
            CameraInventoryState::Uninitialized => {
                if self.supervisor_id.is_some()
                    || self.revision != 0
                    || self.observed_ago_ms.is_some()
                    || self.reason.is_some()
                    || !self.candidates.is_empty()
                {
                    return Err("invalid uninitialized camera inventory");
                }
            }
            CameraInventoryState::Current | CameraInventoryState::Refreshing => {
                if self.supervisor_id.is_none()
                    || self.revision == 0
                    || self.reason.is_some()
                    || (self.state == CameraInventoryState::Current
                        && self.observed_ago_ms.is_none())
                {
                    return Err("invalid published camera inventory");
                }
            }
            CameraInventoryState::Unavailable => {
                if self.reason.is_none() || !self.candidates.is_empty() {
                    return Err("invalid unavailable camera inventory");
                }
            }
        }
        Ok(())
    }
}

impl CameraCandidate {
    /// Validate the bounded connection key and literal endpoint names.
    ///
    /// # Errors
    /// Returns a static reason for invalid identity, generation or endpoints.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_id(&self.instance_id) || self.generation == 0 {
            return Err("invalid camera candidate identity");
        }
        if self.endpoint_paths.is_empty() || self.endpoint_paths.len() > MAX_CAMERA_ENDPOINTS {
            return Err("invalid camera endpoint count");
        }
        let mut paths = std::collections::BTreeSet::new();
        for path in &self.endpoint_paths {
            let Some(name) = path.strip_prefix("/dev/") else {
                return Err("invalid camera endpoint");
            };
            if name.is_empty()
                || path.len() > MAX_CAMERA_ENDPOINT_BYTES
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                || name == "."
                || name == ".."
                || !paths.insert(path)
            {
                return Err("invalid camera endpoint");
            }
        }
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && id.bytes().any(|b| b != b'0')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateWire {
    instance_id: String,
    generation: u64,
    #[serde(deserialize_with = "bounded_vec::<_, _, MAX_CAMERA_ENDPOINTS>")]
    endpoint_paths: Vec<String>,
}

impl TryFrom<CandidateWire> for CameraCandidate {
    type Error = &'static str;
    fn try_from(w: CandidateWire) -> Result<Self, Self::Error> {
        let value = Self {
            instance_id: w.instance_id,
            generation: w.generation,
            endpoint_paths: w.endpoint_paths,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    state: CameraInventoryState,
    supervisor_id: Option<String>,
    revision: u64,
    observed_ago_ms: Option<u64>,
    reason: Option<CameraInventoryReason>,
    #[serde(deserialize_with = "bounded_vec::<_, _, MAX_CAMERA_CANDIDATES>")]
    candidates: Vec<CameraCandidate>,
}

impl TryFrom<SnapshotWire> for CameraInventorySnapshot {
    type Error = &'static str;
    fn try_from(w: SnapshotWire) -> Result<Self, Self::Error> {
        let value = Self {
            state: w.state,
            supervisor_id: w.supervisor_id,
            revision: w.revision,
            observed_ago_ms: w.observed_ago_ms,
            reason: w.reason,
            candidates: w.candidates,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionWire {
    supervisor_id: String,
    candidate: CameraCandidate,
}

impl TryFrom<SelectionWire> for CameraSelection {
    type Error = &'static str;
    fn try_from(w: SelectionWire) -> Result<Self, Self::Error> {
        let value = Self {
            supervisor_id: w.supervisor_id,
            candidate: w.candidate,
        };
        value.validate()?;
        Ok(value)
    }
}

fn bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const MAX: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> serde::de::Visitor<'de> for Bounded<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX} entries")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element()? {
                if values.len() == MAX {
                    return Err(serde::de::Error::custom("camera inventory bound exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, MAX>(std::marker::PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn current() -> CameraInventorySnapshot {
        CameraInventorySnapshot {
            state: CameraInventoryState::Current,
            supervisor_id: Some("11111111111111111111111111111111".into()),
            revision: 1,
            observed_ago_ms: Some(0),
            reason: None,
            candidates: vec![],
        }
    }
    fn candidate() -> CameraCandidate {
        CameraCandidate {
            instance_id: "22222222222222222222222222222222".into(),
            generation: 1,
            endpoint_paths: vec!["/dev/video0".into()],
        }
    }
    #[test]
    fn live_camera_current_empty_is_distinct_from_uninitialized_and_unavailable() {
        for value in [
            CameraInventorySnapshot::default(),
            current(),
            CameraInventorySnapshot {
                state: CameraInventoryState::Unavailable,
                reason: Some(CameraInventoryReason::Monitor),
                ..Default::default()
            },
        ] {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(
                serde_json::from_str::<CameraInventorySnapshot>(&json).unwrap(),
                value
            );
        }
        let mut invalid = current();
        invalid.observed_ago_ms = None;
        assert!(serde_json::from_value::<CameraInventorySnapshot>(
            serde_json::to_value(invalid).unwrap()
        )
        .is_err());
    }
    #[test]
    fn live_camera_wire_rejects_unknown_fields_duplicates_and_unbounded_candidates() {
        let mut value = current();
        value.candidates = vec![candidate()];
        assert!(value.validate().is_ok());
        let mut wire = serde_json::to_value(&value).unwrap();
        wire["streaming"] = true.into();
        assert!(serde_json::from_value::<CameraInventorySnapshot>(wire).is_err());
        value.candidates.push(candidate());
        assert!(value.validate().is_err());
        value.candidates = vec![candidate(); MAX_CAMERA_CANDIDATES + 1];
        assert!(serde_json::from_value::<CameraInventorySnapshot>(
            serde_json::to_value(value).unwrap()
        )
        .is_err());
    }
    #[test]
    fn live_camera_wire_rejects_unsafe_names_zero_generation_and_invented_roles() {
        for endpoint in [
            "/dev/../shadow",
            "/dev/video0\u{1b}[2J",
            "/tmp/video0",
            "/dev/..",
        ] {
            let mut c = candidate();
            c.endpoint_paths = vec![endpoint.into()];
            assert!(c.validate().is_err());
        }
        let mut c = candidate();
        c.generation = 0;
        assert!(c.validate().is_err());
        c = candidate();
        c.instance_id = "0".repeat(32);
        assert!(c.validate().is_err());
        let mut wire = serde_json::to_value(candidate()).unwrap();
        wire["role"] = "rgb".into();
        assert!(serde_json::from_value::<CameraCandidate>(wire).is_err());
    }

    #[test]
    fn live_camera_maximum_payload_leaves_room_in_the_64kib_response_envelope() {
        let mut snapshot = current();
        for n in 1..=MAX_CAMERA_CANDIDATES {
            snapshot.candidates.push(CameraCandidate {
                instance_id: format!("{n:032x}"),
                generation: u64::MAX,
                endpoint_paths: (0..MAX_CAMERA_ENDPOINTS)
                    .map(|endpoint| {
                        let start = format!("/dev/camera{n}_{endpoint}_");
                        format!(
                            "{start}{}",
                            "v".repeat(MAX_CAMERA_ENDPOINT_BYTES - start.len())
                        )
                    })
                    .collect(),
            });
        }
        let json = serde_json::to_vec(&snapshot).unwrap();
        assert!(snapshot.validate().is_ok());
        assert!(
            json.len() < 60 * 1024,
            "must leave room for LiveStatus fields"
        );
        assert_eq!(
            serde_json::from_slice::<CameraInventorySnapshot>(&json).unwrap(),
            snapshot
        );
        snapshot.candidates.push(candidate());
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn live_camera_selection_requires_current_exact_continuity_and_both_endpoints() {
        let mut snapshot = current();
        let mut selected = candidate();
        selected.endpoint_paths.push("/dev/video2".into());
        snapshot.candidates.push(selected.clone());
        let guard = CameraSelection {
            supervisor_id: snapshot.supervisor_id.clone().unwrap(),
            candidate: selected,
        };
        assert!(guard.matches(&snapshot, "/dev/video0", "/dev/video2"));
        assert!(!guard.matches(&snapshot, "/dev/video0", "/dev/video0"));
        assert!(!guard.matches(&snapshot, "/dev/video0", "/dev/video9"));
        for state in [
            CameraInventoryState::Refreshing,
            CameraInventoryState::Unavailable,
            CameraInventoryState::Uninitialized,
        ] {
            let mut changed = snapshot.clone();
            changed.state = state;
            assert!(!guard.matches(&changed, "/dev/video0", "/dev/video2"));
        }
        let mut changed = snapshot.clone();
        changed.candidates.clear();
        assert!(!guard.matches(&changed, "/dev/video0", "/dev/video2"));
        changed = snapshot.clone();
        changed.candidates[0].generation += 1;
        assert!(!guard.matches(&changed, "/dev/video0", "/dev/video2"));
        changed = snapshot.clone();
        changed.candidates[0].instance_id = "3".repeat(32);
        assert!(!guard.matches(&changed, "/dev/video0", "/dev/video2"));
        changed = snapshot.clone();
        changed.supervisor_id = Some("4".repeat(32));
        assert!(!guard.matches(&changed, "/dev/video0", "/dev/video2"));
        let json = serde_json::to_value(&guard).unwrap();
        assert_eq!(
            serde_json::from_value::<CameraSelection>(json.clone()).unwrap(),
            guard
        );
        let mut invalid = json;
        invalid["supervisor_id"] = "fake".into();
        assert!(serde_json::from_value::<CameraSelection>(invalid).is_err());
    }
}
