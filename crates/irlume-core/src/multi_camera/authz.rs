// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Enrollment authorization primitives (ADR-0024 Phase 1, §4): the
//! credential-management token that alone may expand (or shrink) an
//! account's camera-group set.
//!
//! Fresh, scoped, and one-shot:
//!
//! - FRESH: minted with an explicit wall-clock time and a bounded validity
//!   window; an expired authorization refuses.
//! - SCOPED: bound to one account and one EXACT operation - the precise
//!   group id and complete pair for an addition - so an authorization for
//!   one camera never authorizes another.
//! - ONE-SHOT: consumption is the generation bump of a successful
//!   publication; the authorization id is embedded in the published store
//!   and its journal, and an id already recorded at the current generation
//!   refuses to publish again (replay refusal).
//!
//! The structural rule "the new camera never authorizes its own addition"
//! (§4) is enforced by the type: [`AuthorizationVia`] has NO face-granted
//! variant. A successful authentication produces grant decisions, and no
//! grant-decision type converts into [`EnrollmentAuthorization`]; the only
//! constructors are the daemon's explicit `mint` with a password
//! verification or an elevated peer. There is no path from "the camera
//! recognized me" to "add this camera".

use super::GroupPair;
use irlume_common::split_key::SplitPairKey;
use serde::{Deserialize, Serialize};

/// How the credential-management authorization was presented. Exactly two
/// variants exist by design: a fresh password verification by the target
/// account, or an elevated peer the daemon judges sufficient. Face
/// authentication is deliberately absent (§4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum AuthorizationVia {
    /// The target account verified its password with the daemon.
    Password,
    /// An elevated local peer (uid) the daemon judged sufficient for
    /// modifying the account's biometric enrollment.
    ElevatedPeer { uid: u32 },
}

/// The exact operation an authorizes. Matching is EXACT: an authorization
/// for one group or pair never validates another (§4: scoped to the
/// account, profile, exact group, and operation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum EnrollmentOperation {
    AddGroup {
        group: String,
        #[serde(flatten)]
        pair: GroupPairRef,
    },
    /// A whole role-labelled split key. Its string shape cannot be read as
    /// the ordinary operation by pre-split readers.
    AddSplitGroup {
        group: String,
        #[serde(with = "split_pair_serde")]
        pair: SplitPairKey,
    },
    RemoveGroup {
        group: String,
    },
}

impl EnrollmentOperation {
    /// Builds the explicit addition for this binding's class. Ordinary
    /// partial bindings retain the existing operation and flattened encoding.
    /// [`EnrollmentAuthorization::mint`] validates the resulting operation.
    #[must_use]
    pub fn add_group(group: String, pair: &GroupPair) -> Self {
        match pair {
            GroupPair::Ordinary { rgb, ir } => Self::AddGroup {
                group,
                pair: GroupPairRef {
                    rgb: rgb.clone(),
                    ir: ir.clone(),
                },
            },
            GroupPair::Split(pair) => Self::AddSplitGroup {
                group,
                pair: pair.clone(),
            },
        }
    }
}

// The common binding codec owns canonical text and component validation.
// This adapter only restricts the allowed class at the operation boundary.
mod split_pair_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        pair: &SplitPairKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        GroupPair::Split(pair.clone()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SplitPairKey, D::Error> {
        match GroupPair::deserialize(deserializer)? {
            GroupPair::Split(pair) => Ok(pair),
            GroupPair::Ordinary { .. } => Err(serde::de::Error::custom(
                "split addition requires a split key string",
            )),
        }
    }
}

/// The ordinary pair an addition authorizes, mirrored in the historical
/// serde-friendly shape. This type never carries split authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPairRef {
    #[serde(default)]
    pub rgb: Option<String>,
    #[serde(default)]
    pub ir: Option<String>,
}

impl GroupPairRef {
    /// Converts to the store's pair type for comparison.
    #[must_use]
    pub fn to_pair(&self) -> GroupPair {
        GroupPair::Ordinary {
            rgb: self.rgb.clone(),
            ir: self.ir.clone(),
        }
    }
}

/// Upper bound on the freshness window. "Fresh" means fresh; a day is the
/// generous ceiling and callers may mint shorter.
pub const MAX_AUTHORIZATION_WINDOW_SECS: u64 = 24 * 60 * 60;

/// The credential-management authorization token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentAuthorization {
    pub account: String,
    pub operation: EnrollmentOperation,
    /// Unix seconds when the daemon minted it.
    pub granted_at_unix: u64,
    /// Validity window in seconds from `granted_at_unix`.
    pub valid_for_secs: u64,
    /// Opaque unique id (bounded), embedded in the published store and
    /// journal; one-shot consumption keys on it.
    pub authorization_id: String,
    pub via: AuthorizationVia,
}

/// Why an authorization refused.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    WrongAccount,
    WrongOperation,
    Expired,
    Malformed(&'static str),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationError::WrongAccount => write!(f, "authorization names another account"),
            AuthorizationError::WrongOperation => {
                write!(f, "authorization names another operation, group, or pair")
            }
            AuthorizationError::Expired => write!(f, "authorization window elapsed"),
            AuthorizationError::Malformed(detail) => write!(f, "malformed authorization: {detail}"),
        }
    }
}

impl std::error::Error for AuthorizationError {}

impl EnrollmentAuthorization {
    /// Mints a fresh, scoped authorization. The ONLY public constructor:
    /// the daemon calls it after a password verification or an elevated
    /// peer check. No authentication-path type converts into this.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError::Malformed`] for empty or oversized
    /// fields, an over-long validity window, or an invalid split key.
    pub fn mint(
        account: String,
        operation: EnrollmentOperation,
        granted_at_unix: u64,
        valid_for_secs: u64,
        authorization_id: String,
        via: AuthorizationVia,
    ) -> Result<Self, AuthorizationError> {
        let bounded = |text: &str| !text.is_empty() && text.len() <= 256;
        if !bounded(&account) {
            return Err(AuthorizationError::Malformed("account out of bounds"));
        }
        if !bounded(&authorization_id) {
            return Err(AuthorizationError::Malformed("id out of bounds"));
        }
        if valid_for_secs == 0 || valid_for_secs > MAX_AUTHORIZATION_WINDOW_SECS {
            return Err(AuthorizationError::Malformed(
                "validity window out of bounds",
            ));
        }
        if let EnrollmentOperation::AddGroup { group, pair } = &operation {
            if !bounded(group) {
                return Err(AuthorizationError::Malformed("group id out of bounds"));
            }
            if pair.rgb.is_none() && pair.ir.is_none() {
                return Err(AuthorizationError::Malformed(
                    "addition authorizes an empty pair",
                ));
            }
        }
        if let EnrollmentOperation::AddSplitGroup { group, pair } = &operation {
            if !bounded(group) {
                return Err(AuthorizationError::Malformed("group id out of bounds"));
            }
            GroupPair::Split(pair.clone())
                .validate()
                .map_err(|_| AuthorizationError::Malformed("invalid split key"))?;
        }
        if let EnrollmentOperation::RemoveGroup { group } = &operation {
            if !bounded(group) {
                return Err(AuthorizationError::Malformed("group id out of bounds"));
            }
        }
        Ok(Self {
            account,
            operation,
            granted_at_unix,
            valid_for_secs,
            authorization_id,
            via,
        })
    }

    /// Validates this authorization for the named account and EXACT
    /// operation at `now_unix`. Freshness is the window; scope is exact
    /// equality of the operation (group id and complete pair included).
    ///
    /// # Errors
    ///
    /// Returns the first failed boundary as [`AuthorizationError`].
    pub fn validate_for(
        &self,
        account: &str,
        operation: &EnrollmentOperation,
        now_unix: u64,
    ) -> Result<(), AuthorizationError> {
        if self.account != account {
            return Err(AuthorizationError::WrongAccount);
        }
        if &self.operation != operation {
            return Err(AuthorizationError::WrongOperation);
        }
        if now_unix.saturating_sub(self.granted_at_unix) > self.valid_for_secs {
            return Err(AuthorizationError::Expired);
        }
        Ok(())
    }

    /// The id embedded at publication for one-shot consumption.
    #[must_use]
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
}

/// One-shot consumption check: whether this authorization id may publish
/// over a store whose current last-authorization is known. A replayed id
/// at the same or newer generation refuses (§4.1: a conflicting mutation
/// never silently overwrites newer state; consumption IS the generation
/// bump).
///
/// # Errors
///
/// Returns [`AuthorizationError::Malformed`] when the id was already
/// consumed.
pub fn ensure_not_consumed(
    authorization: &EnrollmentAuthorization,
    current_generation: u64,
    last_consumed_id: Option<&str>,
) -> Result<(), AuthorizationError> {
    if last_consumed_id == Some(authorization.authorization_id()) {
        return Err(AuthorizationError::Malformed(
            "authorization already consumed by a prior publication",
        ));
    }
    let _ = current_generation;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_common::split_key::{SplitDomain, SplitPairKey};

    const SPLIT: &str = "split1;5986:2113:rgb|0000:00:14.0|usb2|8;5986:1141:ir|0000:00:14.0|usb2|5";

    // Frozen pre-split operation and pair shapes, independent of the new types.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    enum FrozenOperation {
        AddGroup {
            group: String,
            #[serde(flatten)]
            pair: FrozenPair,
        },
        RemoveGroup {
            group: String,
        },
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FrozenPair {
        #[serde(default)]
        rgb: Option<String>,
        #[serde(default)]
        ir: Option<String>,
    }

    fn split_pair() -> GroupPair {
        GroupPair::Split(SplitPairKey::parse_canonical(SPLIT).unwrap())
    }

    #[test]
    fn ordinary_add_group_keeps_golden_encoding_and_partial_scope() {
        for (pair, golden) in [
            (
                GroupPair::Ordinary {
                    rgb: Some("rgb".into()),
                    ir: Some("ir".into()),
                },
                r#"{"add-group":{"group":"desk","rgb":"rgb","ir":"ir"}}"#,
            ),
            (
                GroupPair::Ordinary {
                    rgb: None,
                    ir: Some("ir".into()),
                },
                r#"{"add-group":{"group":"desk","rgb":null,"ir":"ir"}}"#,
            ),
        ] {
            let operation = EnrollmentOperation::add_group("desk".into(), &pair);
            assert_eq!(serde_json::to_string(&operation).unwrap(), golden);
            let frozen: FrozenOperation = serde_json::from_str(golden).unwrap();
            assert_eq!(serde_json::to_string(&frozen).unwrap(), golden);
            assert_eq!(
                serde_json::from_str::<EnrollmentOperation>(golden).unwrap(),
                operation
            );
            let EnrollmentOperation::AddGroup {
                pair: reference, ..
            } = &operation
            else {
                panic!("ordinary additions keep the old variant");
            };
            assert_eq!(reference.to_pair(), pair);
            minted(operation.clone())
                .validate_for("alice", &operation, 1_000_300)
                .unwrap();
        }
        let partial: EnrollmentOperation =
            serde_json::from_str(r#"{"add-group":{"group":"desk","ir":"ir"}}"#).unwrap();
        assert_eq!(
            partial,
            EnrollmentOperation::add_group(
                "desk".into(),
                &GroupPair::Ordinary {
                    rgb: None,
                    ir: Some("ir".into())
                }
            )
        );
    }

    #[test]
    fn split_add_group_is_a_canonical_string_and_frozen_enum_refuses_it() {
        let operation = EnrollmentOperation::add_group("desk".into(), &split_pair());
        let golden = format!(r#"{{"add-split-group":{{"group":"desk","pair":"{SPLIT}"}}}}"#);
        assert_eq!(serde_json::to_string(&operation).unwrap(), golden);
        assert_eq!(
            serde_json::from_str::<EnrollmentOperation>(&golden).unwrap(),
            operation
        );
        assert!(serde_json::from_str::<FrozenOperation>(&golden).is_err());
        let auth = minted(operation.clone());
        let bytes = serde_json::to_vec(&auth).unwrap();
        assert_eq!(
            serde_json::from_slice::<EnrollmentAuthorization>(&bytes).unwrap(),
            auth
        );
        auth.validate_for("alice", &operation, 1_000_300).unwrap();
    }

    #[test]
    fn split_add_group_refuses_unknown_wrong_class_and_malformed_values() {
        for value in [
            serde_json::json!({"rgb": "rgb", "ir": "ir"}),
            serde_json::json!({"split_key": SPLIT}),
            serde_json::json!(SPLIT.replacen("split1;", "split2;", 1)),
            serde_json::json!(SPLIT.replacen("|8;", "|08;", 1)),
            serde_json::json!(SPLIT.replacen("|usb2|", "|ss|", 1)),
            serde_json::Value::Null,
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "add-split-group": {"group": "desk", "pair": value}
            }))
            .unwrap();
            assert!(serde_json::from_slice::<EnrollmentOperation>(&bytes).is_err());
        }
        for value in [
            serde_json::json!({"future-add": {"group": "desk", "pair": SPLIT}}),
            serde_json::json!({"add-split-group": {"group": "desk", "pair": SPLIT, "future": true}}),
            serde_json::json!({"add-group": {"group": "desk", "pair": SPLIT}}),
        ] {
            assert!(serde_json::from_value::<EnrollmentOperation>(value).is_err());
        }
    }

    #[test]
    fn split_authorization_checks_whole_roles_locations_and_class() {
        let pair = split_pair();
        let operation = EnrollmentOperation::add_group("desk".into(), &pair);
        let auth = minted(operation.clone());
        let GroupPair::Split(key) = pair else {
            unreachable!()
        };
        let mut swapped = key.clone();
        std::mem::swap(&mut swapped.rgb, &mut swapped.ir);
        let mut wrong_pairs = vec![
            GroupPair::Split(swapped),
            GroupPair::Ordinary {
                rgb: Some(key.rgb.identity.clone()),
                ir: Some(key.ir.identity.clone()),
            },
        ];
        for rgb in [true, false] {
            for change in 0..4 {
                let mut wrong = key.clone();
                let side = if rgb { &mut wrong.rgb } else { &mut wrong.ir };
                match change {
                    0 => side.identity = "other".into(),
                    1 => side.controller = "0000:00:15.0".into(),
                    2 => side.domain = SplitDomain::SuperSpeed,
                    _ => side.ports.push(1),
                }
                wrong_pairs.push(GroupPair::Split(wrong));
            }
        }
        for wrong in wrong_pairs {
            assert_eq!(
                auth.validate_for(
                    "alice",
                    &EnrollmentOperation::add_group("desk".into(), &wrong),
                    1_000_300
                ),
                Err(AuthorizationError::WrongOperation)
            );
        }
        assert_eq!(
            auth.validate_for("bob", &operation, 1_000_300),
            Err(AuthorizationError::WrongAccount)
        );
        assert_eq!(
            auth.validate_for(
                "alice",
                &EnrollmentOperation::add_group("other".into(), &split_pair()),
                1_000_300
            ),
            Err(AuthorizationError::WrongOperation)
        );
        assert_eq!(
            auth.validate_for("alice", &operation, 1_000_601),
            Err(AuthorizationError::Expired)
        );
        assert!(ensure_not_consumed(&auth, 2, Some("auth-1")).is_err());
    }

    #[test]
    fn split_authorization_mint_validates_the_typed_key() {
        for rgb in [true, false] {
            for invalid in 0..5 {
                let mut key = SplitPairKey::parse_canonical(SPLIT).unwrap();
                let side = if rgb { &mut key.rgb } else { &mut key.ir };
                match invalid {
                    0 => side.identity.clear(),
                    1 => side.controller = "a".repeat(257),
                    2 => side.ports.clear(),
                    3 => side.ports = vec![0],
                    _ => side.ports = vec![1; 7],
                }
                let operation = EnrollmentOperation::AddSplitGroup {
                    group: "desk".into(),
                    pair: key,
                };
                assert!(matches!(
                    EnrollmentAuthorization::mint(
                        "alice".into(),
                        operation,
                        1,
                        60,
                        "x".into(),
                        AuthorizationVia::Password
                    ),
                    Err(AuthorizationError::Malformed(_))
                ));
            }
        }
        assert!(EnrollmentAuthorization::mint(
            "alice".into(),
            EnrollmentOperation::add_group(String::new(), &split_pair()),
            1,
            60,
            "x".into(),
            AuthorizationVia::Password,
        )
        .is_err());
    }

    fn add_desk() -> EnrollmentOperation {
        EnrollmentOperation::AddGroup {
            group: "desk".into(),
            pair: GroupPairRef {
                rgb: Some("3443:c803".into()),
                ir: Some("3443:c803".into()),
            },
        }
    }

    fn minted(operation: EnrollmentOperation) -> EnrollmentAuthorization {
        EnrollmentAuthorization::mint(
            "alice".into(),
            operation,
            1_000_000,
            600,
            "auth-1".into(),
            AuthorizationVia::Password,
        )
        .expect("mint")
    }

    #[test]
    fn exact_scope_validates_and_every_drift_refuses() {
        let auth = minted(add_desk());
        auth.validate_for("alice", &add_desk(), 1_000_300)
            .expect("valid");
        assert_eq!(
            auth.validate_for("bob", &add_desk(), 1_000_300),
            Err(AuthorizationError::WrongAccount)
        );
        // A different group, or the same group with a different pair, is a
        // different operation.
        let other_group = EnrollmentOperation::AddGroup {
            group: "lobby".into(),
            pair: GroupPairRef {
                rgb: Some("3443:c803".into()),
                ir: Some("3443:c803".into()),
            },
        };
        let hybrid_pair = EnrollmentOperation::AddGroup {
            group: "desk".into(),
            pair: GroupPairRef {
                rgb: Some("046d:085e".into()),
                ir: Some("3443:c803".into()),
            },
        };
        assert_eq!(
            auth.validate_for("alice", &other_group, 1_000_300),
            Err(AuthorizationError::WrongOperation)
        );
        assert_eq!(
            auth.validate_for("alice", &hybrid_pair, 1_000_300),
            Err(AuthorizationError::WrongOperation)
        );
        assert_eq!(
            auth.validate_for(
                "alice",
                &EnrollmentOperation::RemoveGroup {
                    group: "desk".into()
                },
                1_000_300
            ),
            Err(AuthorizationError::WrongOperation)
        );
    }

    #[test]
    fn freshness_is_a_bounded_window() {
        let auth = minted(add_desk());
        auth.validate_for("alice", &add_desk(), 1_000_599)
            .expect("inside");
        assert_eq!(
            auth.validate_for("alice", &add_desk(), 1_000_601),
            Err(AuthorizationError::Expired)
        );
        // An over-long window cannot even be minted.
        assert_eq!(
            EnrollmentAuthorization::mint(
                "alice".into(),
                add_desk(),
                1,
                MAX_AUTHORIZATION_WINDOW_SECS + 1,
                "x".into(),
                AuthorizationVia::Password,
            ),
            Err(AuthorizationError::Malformed(
                "validity window out of bounds"
            ))
        );
    }

    #[test]
    fn one_shot_consumption_refuses_replays() {
        let auth = minted(add_desk());
        ensure_not_consumed(&auth, 5, None).expect("first use");
        ensure_not_consumed(&auth, 5, Some("other-id")).expect("different id");
        assert_eq!(
            ensure_not_consumed(&auth, 6, Some("auth-1")),
            Err(AuthorizationError::Malformed(
                "authorization already consumed by a prior publication"
            ))
        );
    }

    #[test]
    fn there_is_no_face_granted_authorization_variant() {
        // The structural rule (§4: the new camera never authorizes its own
        // addition) is the absence of a variant: every construction of
        // AuthorizationVia in this codebase must be one of exactly these
        // two arms, which this exhaustive match pins at compile time.
        let via = AuthorizationVia::Password;
        let what = match via {
            AuthorizationVia::Password => "password",
            AuthorizationVia::ElevatedPeer { uid: _ } => "elevated peer",
        };
        assert_eq!(what, "password");
        // And minting still requires an explicit via: an empty pair or
        // empty account refuses, so no incidental construction slips in.
        assert!(EnrollmentAuthorization::mint(
            String::new(),
            add_desk(),
            1,
            60,
            "x".into(),
            AuthorizationVia::ElevatedPeer { uid: 0 },
        )
        .is_err());
    }
}
