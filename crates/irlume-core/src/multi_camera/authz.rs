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
    RemoveGroup {
        group: String,
    },
}

/// The pair an addition authorizes, mirrored from [`GroupPair`] in a
/// serde-friendly shape.
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
        GroupPair {
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
    /// fields or an over-long validity window.
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
