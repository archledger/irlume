// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Durable account bindings. Ordinary objects keep their historical shape;
//! split bindings are canonical strings that pre-split struct readers reject.

use crate::split_key::SplitPairKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A stored binding, including the historical partial ordinary binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairBinding {
    /// Ordinary identity binding, with the historical optional-side semantics.
    Ordinary {
        rgb: Option<String>,
        ir: Option<String>,
    },
    /// Complete role-labelled identities and locations of two physical units.
    Split(SplitPairKey),
}

/// One complete credential key. Declaration order is ordinary before split;
/// split ordering delegates to the common typed RGB-then-IR comparator.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompletePairKey {
    /// Both ordinary identities, RGB first.
    Ordinary { rgb: String, ir: String },
    /// Both split unit keys, RGB first.
    Split(SplitPairKey),
}

/// A binding is malformed or exceeds the existing credential field bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingError(pub &'static str);

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for BindingError {}

fn bounded(text: &str) -> bool {
    !text.is_empty() && text.len() <= 256
}

impl Default for PairBinding {
    fn default() -> Self {
        Self::Ordinary {
            rgb: None,
            ir: None,
        }
    }
}

impl PairBinding {
    /// Checks canonical split components and their credential field bounds.
    /// Ordinary bindings retain their historical primary representation;
    /// stricter secondary-store limits apply at that store's boundary.
    ///
    /// # Errors
    /// Returns [`BindingError`] for invalid or oversized split components.
    pub fn validate(&self) -> Result<(), BindingError> {
        if let Self::Split(key) = self {
            key.format_canonical()
                .map_err(|_| BindingError("invalid split key"))?;
            for unit in [&key.rgb, &key.ir] {
                if !bounded(&unit.identity) || !bounded(&unit.controller) || unit.ports.len() > 6 {
                    return Err(BindingError("split binding component out of bounds"));
                }
            }
        }
        Ok(())
    }

    /// The complete key, if this binding is valid and has both sides.
    #[must_use]
    pub fn complete_key(&self) -> Option<CompletePairKey> {
        self.validate().ok()?;
        match self {
            Self::Ordinary {
                rgb: Some(rgb),
                ir: Some(ir),
            } if !rgb.is_empty() && !ir.is_empty() => Some(CompletePairKey::Ordinary {
                rgb: rgb.clone(),
                ir: ir.clone(),
            }),
            Self::Split(key) => Some(CompletePairKey::Split(key.clone())),
            Self::Ordinary { .. } => None,
        }
    }

    /// Legacy ordinary matching. Identity-only input never admits split.
    #[must_use]
    pub fn matches(&self, live_rgb: Option<&str>, live_ir: Option<&str>) -> bool {
        match self {
            Self::Ordinary { rgb, ir } => {
                self.validate().is_ok()
                    && rgb.as_deref().is_none_or(|want| live_rgb == Some(want))
                    && ir.as_deref().is_none_or(|want| live_ir == Some(want))
            }
            Self::Split(_) => false,
        }
    }

    /// Matches a live binding without projecting away its class or locations.
    /// Ordinary bound sides retain their historical optional-side matching;
    /// split bindings require valid, equal whole role-labelled keys.
    #[must_use]
    pub fn matches_binding(&self, live: &Self) -> bool {
        match (self, live) {
            (Self::Ordinary { .. }, Self::Ordinary { rgb, ir }) => {
                self.matches(rgb.as_deref(), ir.as_deref())
            }
            (Self::Split(want), Self::Split(now)) => {
                self.validate().is_ok() && live.validate().is_ok() && want == now
            }
            (Self::Ordinary { .. }, Self::Split(_)) | (Self::Split(_), Self::Ordinary { .. }) => {
                false
            }
        }
    }

    /// Class-aware matching. Only ordinary bindings retain partial semantics.
    #[must_use]
    pub fn matches_key(&self, live: &CompletePairKey) -> bool {
        if live.validate().is_err() {
            return false;
        }
        match live {
            CompletePairKey::Ordinary { rgb, ir } => self.matches(Some(rgb), Some(ir)),
            CompletePairKey::Split(key) => {
                matches!(self, Self::Split(want) if self.validate().is_ok() && want == key)
            }
        }
    }

    /// RGB identity for display. This does not authorize a pair.
    #[must_use]
    pub fn rgb_identity(&self) -> Option<&str> {
        match self {
            Self::Ordinary { rgb, .. } => rgb.as_deref(),
            Self::Split(key) => Some(&key.rgb.identity),
        }
    }

    /// IR identity for display. This does not authorize a pair.
    #[must_use]
    pub fn ir_identity(&self) -> Option<&str> {
        match self {
            Self::Ordinary { ir, .. } => ir.as_deref(),
            Self::Split(key) => Some(&key.ir.identity),
        }
    }
}

impl CompletePairKey {
    /// Checks completeness and the split class's canonical component bounds.
    ///
    /// # Errors
    /// Returns [`BindingError`] for invalid or oversized components.
    pub fn validate(&self) -> Result<(), BindingError> {
        match self {
            Self::Ordinary { rgb, ir } if rgb.is_empty() || ir.is_empty() => {
                Err(BindingError("binding is not complete"))
            }
            Self::Ordinary { .. } => Ok(()),
            Self::Split(key) => PairBinding::Split(key.clone()).validate(),
        }
    }
}

impl From<CompletePairKey> for PairBinding {
    fn from(key: CompletePairKey) -> Self {
        match key {
            CompletePairKey::Ordinary { rgb, ir } => Self::Ordinary {
                rgb: Some(rgb),
                ir: Some(ir),
            },
            CompletePairKey::Split(key) => Self::Split(key),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrdinaryValue {
    #[serde(default)]
    rgb: Option<String>,
    #[serde(default)]
    ir: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BindingValue {
    Ordinary(OrdinaryValue),
    Split(String),
}

impl Serialize for PairBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        match self {
            Self::Ordinary { rgb, ir } => {
                use serde::ser::SerializeStruct;
                let mut value = serializer.serialize_struct("CameraBinding", 2)?;
                value.serialize_field("rgb", rgb)?;
                value.serialize_field("ir", ir)?;
                value.end()
            }
            Self::Split(key) => serializer
                .serialize_str(&key.format_canonical().map_err(serde::ser::Error::custom)?),
        }
    }
}

impl<'de> Deserialize<'de> for PairBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let binding = match BindingValue::deserialize(deserializer)? {
            BindingValue::Ordinary(value) => Self::Ordinary {
                rgb: value.rgb,
                ir: value.ir,
            },
            BindingValue::Split(text) => {
                Self::Split(SplitPairKey::parse_canonical(&text).map_err(serde::de::Error::custom)?)
            }
        };
        binding.validate().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

impl Serialize for CompletePairKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        PairBinding::from(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CompletePairKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        PairBinding::deserialize(deserializer)?
            .complete_key()
            .ok_or_else(|| serde::de::Error::custom("binding is not complete"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPLIT: &str = "split1;5986:2113:rgb|0000:00:14.0|usb2|8;5986:1141:ir|0000:00:14.0|usb2|5";

    #[test]
    fn binding_matching_preserves_optional_ordinary_sides() {
        let rgb_only = PairBinding::Ordinary {
            rgb: Some("rgb".into()),
            ir: None,
        };
        let ir_only = PairBinding::Ordinary {
            rgb: None,
            ir: Some("ir".into()),
        };
        let complete = PairBinding::Ordinary {
            rgb: Some("rgb".into()),
            ir: Some("ir".into()),
        };
        assert!(rgb_only.matches_binding(&rgb_only));
        assert!(rgb_only.matches_binding(&complete));
        assert!(ir_only.matches_binding(&complete));
        assert!(!complete.matches_binding(&rgb_only));
        assert!(!rgb_only.matches_binding(&ir_only));
        assert!(PairBinding::default().matches_binding(&rgb_only));
        for identity in [String::new(), "x".repeat(257)] {
            let legacy = PairBinding::Ordinary {
                rgb: Some(identity),
                ir: None,
            };
            assert!(legacy.matches_binding(&legacy));
        }
    }

    #[test]
    fn binding_matching_never_crosses_classes_even_with_identical_ids() {
        let split = PairBinding::Split(SplitPairKey::parse_canonical(SPLIT).unwrap());
        let ordinary = PairBinding::Ordinary {
            rgb: Some("5986:2113:rgb".into()),
            ir: Some("5986:1141:ir".into()),
        };
        assert!(!split.matches_binding(&ordinary));
        assert!(!ordinary.matches_binding(&split));
        assert!(!PairBinding::default().matches_binding(&split));
    }

    #[test]
    fn split_binding_matching_requires_valid_role_labelled_whole_keys() {
        let key = SplitPairKey::parse_canonical(SPLIT).unwrap();
        let binding = PairBinding::Split(key.clone());
        assert!(binding.matches_binding(&PairBinding::Split(key.clone())));
        for rgb in [true, false] {
            for drift in 0..4 {
                let mut moved = key.clone();
                let side = if rgb { &mut moved.rgb } else { &mut moved.ir };
                match drift {
                    0 => side.identity.push_str("-other"),
                    1 => side.controller = "0000:00:15.0".into(),
                    2 => side.domain = crate::split_key::SplitDomain::SuperSpeed,
                    _ => side.ports = vec![9],
                }
                let moved = PairBinding::Split(moved);
                assert!(!binding.matches_binding(&moved));
                assert!(!moved.matches_binding(&binding));
            }
            for invalid in 0..5 {
                let mut malformed = key.clone();
                let side = if rgb {
                    &mut malformed.rgb
                } else {
                    &mut malformed.ir
                };
                match invalid {
                    0 => side.identity.clear(),
                    1 => side.controller = "x".repeat(257),
                    2 => side.ports.clear(),
                    3 => side.ports = vec![0],
                    _ => side.ports = vec![1; 7],
                }
                let malformed = PairBinding::Split(malformed);
                assert!(!malformed.matches_binding(&malformed));
                assert!(!binding.matches_binding(&malformed));
                assert!(!malformed.matches_binding(&binding));
            }
        }
        let swapped = PairBinding::Split(SplitPairKey {
            rgb: key.ir,
            ir: key.rgb,
        });
        assert!(!binding.matches_binding(&swapped));
    }

    // Frozen legacy primary binding. Its optional strings had no codec limit.
    #[derive(Debug, Serialize, Deserialize)]
    struct FrozenOrdinaryBinding {
        #[serde(default)]
        rgb: Option<String>,
        #[serde(default)]
        ir: Option<String>,
    }

    #[test]
    fn ordinary_primary_empty_identity_keeps_legacy_round_trip() {
        for input in [r#"{"rgb":"","ir":null}"#, r#"{"rgb":null,"ir":""}"#] {
            let frozen: FrozenOrdinaryBinding = serde_json::from_str(input).unwrap();
            let binding: PairBinding = serde_json::from_str(input)
                .expect("legacy primary empty strings must remain readable");
            assert_eq!(
                serde_json::to_vec(&binding).unwrap(),
                serde_json::to_vec(&frozen).unwrap()
            );
            assert!(
                binding.complete_key().is_none(),
                "empty identity never completes an ordinary pair"
            );
        }
    }

    #[test]
    fn ordinary_primary_long_identity_keeps_legacy_round_trip() {
        for identity in ["a".repeat(257), "é".repeat(129)] {
            let frozen = FrozenOrdinaryBinding {
                rgb: Some(identity.clone()),
                ir: Some("046d:085e:fixture".into()),
            };
            let bytes = serde_json::to_vec(&frozen).unwrap();
            let binding: PairBinding = serde_json::from_slice(&bytes)
                .expect("legacy primary identity limits belong to the store, not this codec");
            assert_eq!(serde_json::to_vec(&binding).unwrap(), bytes);
            let live = CompletePairKey::Ordinary {
                rgb: identity,
                ir: "046d:085e:fixture".into(),
            };
            assert_eq!(binding.complete_key(), Some(live.clone()));
            assert!(binding.matches_key(&live));
        }
    }

    #[test]
    fn ordinary_partial_bindings_keep_partial_matching_without_complete_keys() {
        let missing: PairBinding = serde_json::from_str("{}").unwrap();
        assert!(missing.matches(None, None));
        assert!(missing.complete_key().is_none());
        let partial: PairBinding = serde_json::from_str(r#"{"rgb":"rgb"}"#).unwrap();
        assert!(partial.matches(Some("rgb"), None));
        assert!(!partial.matches(Some("other"), Some("ir")));
        assert!(partial.complete_key().is_none());
        for key in [
            CompletePairKey::Ordinary {
                rgb: String::new(),
                ir: "ir".into(),
            },
            CompletePairKey::Ordinary {
                rgb: "rgb".into(),
                ir: String::new(),
            },
        ] {
            assert!(key.validate().is_err());
            assert!(!missing.matches_key(&key));
            assert!(serde_json::to_vec(&key).is_err());
            let ordinary = PairBinding::from(key);
            let bytes = serde_json::to_vec(&ordinary).unwrap();
            assert!(serde_json::from_slice::<CompletePairKey>(&bytes).is_err());
        }
    }

    #[test]
    fn canonical_split_strings_are_rejected_by_frozen_ordinary_readers() {
        let bytes = serde_json::to_vec(SPLIT).unwrap();
        assert!(serde_json::from_slice::<FrozenOrdinaryBinding>(&bytes).is_err());
        let binding: PairBinding = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(binding, PairBinding::Split(_)));
        assert_eq!(serde_json::to_vec(&binding).unwrap(), bytes);
        for input in [r#"{"split_key":"future"}"#, r#"{"rgb":"rgb","class":1}"#] {
            assert!(serde_json::from_str::<PairBinding>(input).is_err());
        }
    }

    #[test]
    fn identity_only_input_never_matches_a_split_binding() {
        let binding = PairBinding::Split(SplitPairKey::parse_canonical(SPLIT).unwrap());
        assert!(!binding.matches(Some("5986:2113:rgb"), Some("5986:1141:ir")));
        assert!(!binding.matches_key(&CompletePairKey::Ordinary {
            rgb: "5986:2113:rgb".into(),
            ir: "5986:1141:ir".into(),
        }));
        let key = SplitPairKey::parse_canonical(SPLIT).unwrap();
        assert!(binding.matches_key(&CompletePairKey::Split(key.clone())));
        let mut moved = key;
        moved.ir.controller = "0000:00:15.0".into();
        assert!(!binding.matches_key(&CompletePairKey::Split(moved)));
    }

    #[test]
    fn split_component_limits_remain_explicit() {
        for rgb in [true, false] {
            for invalid in 0..4 {
                let mut key = SplitPairKey::parse_canonical(SPLIT).unwrap();
                let side = if rgb { &mut key.rgb } else { &mut key.ir };
                match invalid {
                    0 => side.identity = "a".repeat(257),
                    1 => side.controller = "a".repeat(257),
                    2 => side.ports = vec![0],
                    _ => side.ports = vec![1; 7],
                }
                let binding = PairBinding::Split(key);
                assert!(binding.validate().is_err());
                assert!(binding.complete_key().is_none());
                assert!(serde_json::to_vec(&binding).is_err());
            }
        }
    }
}
