// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Camera selection order (ADR-0029 §1 and §3): which connected camera pair
//! a request uses when camera selection is automatic, and which pair a
//! first enrollment uses, as pure functions over plain facts.
//!
//! Nothing here opens, lists or reads a device or a file. The caller hands
//! in the connected pairs by identity (from the passive inventory), the
//! account's enrolled pairs, whether each enrolled pair can serve the
//! requested mode, and the external-camera policy. A camera's name is not
//! an input, so it cannot influence a choice (ADR-0029 §9).
//!
//! [`select_for_account`] ranks only the account's enrolled pairs:
//!
//! 1. the primary binding, when both of its sides are bound and a connected
//!    pair carries exactly those identities;
//! 2. then the active secondary groups whose complete pair is connected, in
//!    the canonical order of their identities (RGB, then IR), never store
//!    order, so removing and re-adding a group cannot change which of two
//!    connected cameras is chosen;
//! 3. groups holding one exact pair are ambiguous and skipped, and so is an
//!    enrolled pair that two connected cameras carry (units of one model
//!    without a serial cannot be told apart, ADR-0024 §6);
//! 4. eligibility for the requested mode is part of the ranking: an
//!    ineligible primary beside an eligible group selects the group;
//! 5. when nothing usable is connected the request is refused, and the
//!    refusal names why. A pair the account is not enrolled on is never
//!    chosen.
//!
//! An account whose primary binding is missing or one-sided (enrolled
//! before bindings existed, or on a camera without an IR node) is not
//! refused: when no complete group is chosen, automatic selection does not
//! apply and the caller keeps the standing pair, as before automatic
//! selection existed.
//!
//! [`rank_enrollment_candidates`] orders the connected pairs a first
//! enrollment may use: the `IRLUME_CAMERA_PIN` allowlist, then built-in
//! cameras, then the identities, never a `/dev/videoN` number.

use super::{Activation, GroupPair, SecondaryStore};
use crate::storage::CameraBinding;

/// One connected camera pair, by identity, as the caller's camera-free
/// inventory reports it. It has no name: a name is shown, never compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidatePair<K> {
    /// The caller's handle for this pair, handed back with a choice. The
    /// enrollment ranking also orders two pairs with the same identities by
    /// it, so it should stay the same while the camera stays plugged in (its
    /// USB port chain, say) and never be a `/dev/videoN` path, which udev
    /// renumbers.
    pub key: K,
    /// The RGB node's device identity, `vid:pid[:serial]` in lowercase.
    pub rgb_identity: String,
    /// The IR node's device identity, in the same form.
    pub ir_identity: String,
    /// The camera reads `removable=fixed` (built in). Anything else, an
    /// unknown `removable` included, counts as external, as the open-time
    /// check counts it.
    pub fixed: bool,
}

/// The camera pairs one account is enrolled on, by identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountCameras {
    /// The primary enrollment's binding; `None` for an enrollment written
    /// before bindings existed.
    pub primary: Option<GroupPair>,
    /// The secondary store's activation matches the current primary bytes
    /// (ADR-0024 §1.1). While it does not, no group is a candidate.
    pub secondary_active: bool,
    /// The account has a secondary store that authorizes no group because
    /// it could not be loaded or names another owner. `groups` is then
    /// empty, and a refusal says so rather than that no enrolled camera is
    /// connected.
    pub secondary_unreadable: bool,
    /// Every secondary group's pair, in store order. A group is named by
    /// its 0-based position here.
    pub groups: Vec<GroupPair>,
}

/// What the caller learned of an account's secondary store.
#[derive(Clone, Copy, Debug)]
pub enum SecondaryFacts<'a> {
    /// The account has no secondary store.
    Absent,
    /// The store could not be loaded (unreadable, corrupt, of another
    /// version or over a limit); the caller reports the load error.
    Unreadable,
    /// The loaded store, with its activation against the current primary
    /// bytes.
    Loaded(&'a SecondaryStore, Activation),
}

impl AccountCameras {
    /// The facts for `user` from its loaded stores: the primary
    /// enrollment's `camera_binding`, and what the caller learned of the
    /// secondary store. A store that could not be loaded authorizes no
    /// group (ADR-0024 §1.2). A store that names another owner authorizes
    /// no group either, as
    /// [`SecondaryAuthContext::pin_strict_with_source`](super::coordinator::SecondaryAuthContext::pin_strict_with_source)
    /// refuses it. Both set [`AccountCameras::secondary_unreadable`].
    #[must_use]
    pub fn from_stores(
        user: &str,
        binding: Option<&CameraBinding>,
        secondary: SecondaryFacts<'_>,
    ) -> Self {
        let (secondary_active, secondary_unreadable, groups) = match secondary {
            SecondaryFacts::Absent => (false, false, Vec::new()),
            SecondaryFacts::Loaded(store, activation) if store.owner == user => (
                activation == Activation::Active,
                false,
                store
                    .groups
                    .iter()
                    .map(|group| group.pair.clone())
                    .collect(),
            ),
            SecondaryFacts::Unreadable | SecondaryFacts::Loaded(..) => (false, true, Vec::new()),
        };
        Self {
            primary: binding.map(|binding| GroupPair {
                rgb: binding.rgb.clone(),
                ir: binding.ir.clone(),
            }),
            secondary_active,
            secondary_unreadable,
            groups,
        }
    }
}

/// Which of the account's enrolled pairs a candidate is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateScope {
    /// The primary enrollment.
    Primary,
    /// The secondary group at this 0-based position in
    /// [`AccountCameras::groups`]: an ordinal, the only handle ever reported
    /// for a group (ADR-0028 §3), never its id.
    Secondary { index: usize },
}

/// Why a connected enrolled pair was not chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Two or more groups hold this exact pair; store order never picks one
    /// of them (ADR-0029 §1, item 3).
    AmbiguousGroups,
    /// The group's store is inactive: the primary enrollment changed since
    /// it was authorized (ADR-0024 §1.1).
    SecondaryInactive,
    /// Every connected pair carrying these identities is external, and
    /// external cameras are forbidden (ADR-0029 §6).
    ExternalForbidden,
    /// Two or more connected pairs carry these identities, so the enrolled
    /// unit cannot be told apart from another of its model (ADR-0024 §6).
    Indistinguishable,
    /// The enrollment cannot serve the requested mode (ADR-0029 §1,
    /// item 4).
    NotEligible,
}

/// A connected enrolled pair that was passed over, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub scope: CandidateScope,
    pub reason: SkipReason,
}

/// The pair a request uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection<K> {
    /// The chosen connected pair's key.
    pub key: K,
    /// The enrolled pair it is.
    pub scope: CandidateScope,
    /// Connected enrolled pairs that were passed over, in rank order (see
    /// [`SelectionOutcome`]).
    pub skipped: Vec<Skipped>,
}

/// Why a request is refused before any camera opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCause {
    /// None of the account's complete enrolled pairs is connected
    /// (ADR-0029 §1, item 5: "no enrolled camera is connected").
    NoEnrolledCameraConnected,
    /// No enrolled pair is connected and the secondary store authorizes no
    /// group ([`AccountCameras::secondary_unreadable`]), so an added camera
    /// may be connected but cannot be used.
    SecondaryUnreadable,
    /// The best-ranked connected enrolled pair was skipped for this reason,
    /// and nothing after it was usable.
    Skipped(SkipReason),
}

/// The result of [`select_for_account`].
///
/// Every variant lists the connected enrolled pairs that were passed over,
/// in rank order: each one skipped for a reason that does not depend on the
/// requested mode (ambiguous, inactive, external, indistinguishable), and
/// each one ranked above the choice that `eligible` turned down. An
/// enrolled pair that is not connected is not listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionOutcome<K> {
    /// Open this pair for the attempt.
    Selected(Selection<K>),
    /// Automatic selection does not apply to this account: its primary
    /// binding is missing or one-sided and no complete group was chosen.
    /// The caller keeps the standing pair, as before automatic selection
    /// existed; the owner can pin the camera or re-enroll to use automatic.
    NotApplicable { skipped: Vec<Skipped> },
    /// Refuse to the password before any camera opens.
    Refused {
        cause: RefusalCause,
        skipped: Vec<Skipped>,
    },
}

/// Chooses the connected pair a request for one account uses when camera
/// selection is automatic (ADR-0029 §1).
///
/// The account's complete enrolled pairs are ranked: the primary first,
/// then the groups in canonical identity order. An enrolled pair is usable
/// when exactly one allowed connected pair carries both of its identities
/// (compared exactly, as [`SecondaryStore::strict_group_for_pair`] does),
/// a group's store is active and no other group holds the same pair, and
/// `eligible` accepts its scope. The first usable pair is chosen.
///
/// `eligible` answers whether a scope's enrollment can serve the requested
/// mode (for IR-only: compatible IR templates for the live recognizer). It
/// is asked in rank order, at most once per scope, only for a scope that is
/// otherwise usable, and not again once a pair is chosen.
///
/// `forbid_external` is the external-camera prohibition: when set, a
/// connected pair that is not built in can never be chosen and is left
/// out before units with the same identities are counted. An enrolled
/// pair that only such pairs carry is reported as
/// [`SkipReason::ExternalForbidden`], unless its group is ambiguous or
/// inactive, which is reported instead.
#[must_use]
pub fn select_for_account<K: Clone>(
    connected: &[CandidatePair<K>],
    account: &AccountCameras,
    mut eligible: impl FnMut(CandidateScope) -> bool,
    forbid_external: bool,
) -> SelectionOutcome<K> {
    let primary = account.primary.as_ref().and_then(complete_pair);
    let mut groups: Vec<(usize, (&str, &str))> = account
        .groups
        .iter()
        .enumerate()
        .filter_map(|(index, pair)| complete_pair(pair).map(|pair| (index, pair)))
        .collect();
    // Canonical order: the pair identities, never the store position. The
    // position only orders groups that hold one exact pair, which are all
    // skipped, so it never decides a choice.
    groups.sort_by(|(a_index, a_pair), (b_index, b_pair)| {
        a_pair.cmp(b_pair).then(a_index.cmp(b_index))
    });
    let ranked = primary
        .map(|pair| (CandidateScope::Primary, pair))
        .into_iter()
        .chain(
            groups
                .iter()
                .map(|&(index, pair)| (CandidateScope::Secondary { index }, pair)),
        );

    let mut chosen: Option<(K, CandidateScope)> = None;
    let mut skipped = Vec::new();
    for (scope, (rgb, ir)) in ranked {
        let carrying: Vec<&CandidatePair<K>> = connected
            .iter()
            .filter(|pair| pair.rgb_identity == rgb && pair.ir_identity == ir)
            .collect();
        if carrying.is_empty() {
            continue;
        }
        let secondary = matches!(scope, CandidateScope::Secondary { .. });
        let allowed: Vec<&CandidatePair<K>> = carrying
            .into_iter()
            .filter(|pair| pair.fixed || !forbid_external)
            .collect();
        let reason = if secondary
            && groups
                .iter()
                .filter(|(_, other)| *other == (rgb, ir))
                .count()
                > 1
        {
            Some(SkipReason::AmbiguousGroups)
        } else if secondary && !account.secondary_active {
            Some(SkipReason::SecondaryInactive)
        } else {
            match allowed.as_slice() {
                [] => Some(SkipReason::ExternalForbidden),
                [pair] if chosen.is_none() => {
                    if eligible(scope) {
                        chosen = Some((pair.key.clone(), scope));
                        None
                    } else {
                        Some(SkipReason::NotEligible)
                    }
                }
                [_] => None,
                _ => Some(SkipReason::Indistinguishable),
            }
        };
        if let Some(reason) = reason {
            skipped.push(Skipped { scope, reason });
        }
    }
    match (chosen, primary) {
        (Some((key, scope)), _) => SelectionOutcome::Selected(Selection {
            key,
            scope,
            skipped,
        }),
        (None, None) => SelectionOutcome::NotApplicable { skipped },
        (None, Some(_)) => SelectionOutcome::Refused {
            cause: match skipped.first() {
                Some(first) => RefusalCause::Skipped(first.reason),
                None if account.secondary_unreadable => RefusalCause::SecondaryUnreadable,
                None => RefusalCause::NoEnrolledCameraConnected,
            },
            skipped,
        },
    }
}

/// Where an enrollment candidate ranks (ADR-0029 §3: the existing
/// discovery ranking). Ordered from lowest to highest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateRank {
    /// Neither on the allowlist nor built in.
    Other,
    /// Built in (`removable=fixed`).
    BuiltIn,
    /// The `vid:pid` of both identities is on the `IRLUME_CAMERA_PIN`
    /// allowlist.
    Allowlisted,
}

/// One connected pair a first enrollment may use, in ranked order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentCandidate<K> {
    pub key: K,
    pub rank: CandidateRank,
    /// Another candidate carries the same identities: a unit of the same
    /// model without a serial, which a binding cannot tell apart from this
    /// one (ADR-0024 §6).
    pub shares_identity: bool,
}

/// Orders the connected pairs a first enrollment may use, best first
/// (ADR-0029 §3): pairs whose `vid:pid` is on `allowlist` on both sides,
/// then built-in pairs, then the rest; within a rank by RGB identity, then
/// IR identity, then key. The input order never matters, and no node path
/// is an input. With `forbid_external` set, pairs that are not built in are
/// left out.
///
/// `allowlist` holds the `vid:pid` entries of `IRLUME_CAMERA_PIN`, ideally
/// as irlume-camera's allowlist parser returns them (the list
/// `verify_pinned` enforces); surrounding whitespace and case are ignored.
/// Empty means no allowlist.
#[must_use]
pub fn rank_enrollment_candidates<K: Clone + Ord>(
    connected: &[CandidatePair<K>],
    allowlist: &[String],
    forbid_external: bool,
) -> Vec<EnrollmentCandidate<K>> {
    let allowed: Vec<&CandidatePair<K>> = connected
        .iter()
        .filter(|pair| pair.fixed || !forbid_external)
        .collect();
    let listed = |identity: &str| {
        let wanted = vid_pid(identity);
        allowlist
            .iter()
            .any(|entry| entry.trim().eq_ignore_ascii_case(wanted))
    };
    let mut ranked: Vec<(&CandidatePair<K>, CandidateRank)> = allowed
        .iter()
        .map(|&pair| {
            let rank = if listed(&pair.rgb_identity) && listed(&pair.ir_identity) {
                CandidateRank::Allowlisted
            } else if pair.fixed {
                CandidateRank::BuiltIn
            } else {
                CandidateRank::Other
            };
            (pair, rank)
        })
        .collect();
    ranked.sort_by(|(a, a_rank), (b, b_rank)| {
        b_rank
            .cmp(a_rank)
            .then_with(|| a.rgb_identity.cmp(&b.rgb_identity))
            .then_with(|| a.ir_identity.cmp(&b.ir_identity))
            .then_with(|| a.key.cmp(&b.key))
    });
    ranked
        .iter()
        .map(|&(pair, rank)| EnrollmentCandidate {
            key: pair.key.clone(),
            rank,
            shares_identity: allowed
                .iter()
                .filter(|other| {
                    other.rgb_identity == pair.rgb_identity && other.ir_identity == pair.ir_identity
                })
                .count()
                > 1,
        })
        .collect()
}

/// Both sides of `pair`, when both are bound. An empty identity counts as
/// unbound: no connected camera can carry it.
fn complete_pair(pair: &GroupPair) -> Option<(&str, &str)> {
    match (pair.rgb.as_deref(), pair.ir.as_deref()) {
        (Some(rgb), Some(ir)) if !rgb.is_empty() && !ir.is_empty() => Some((rgb, ir)),
        _ => None,
    }
}

/// The `vid:pid` an identity starts with: everything before its second
/// colon, or the whole identity when it has no serial.
fn vid_pid(identity: &str) -> &str {
    identity
        .match_indices(':')
        .nth(1)
        .map_or(identity, |(end, _)| &identity[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// The account's primary camera: external, with a serial.
    const PRIMARY: &str = "046d:085e:0a01";
    /// Two added cameras; `ADDED_A` sorts before `ADDED_B`.
    const ADDED_A: &str = "1bcf:28c4:0b02";
    const ADDED_B: &str = "2b7e:c80a:0c03";
    /// A built-in camera, enrolled only where a test adds it as a group.
    const BUILT_IN: &str = "3277:0059";

    type Outcome = SelectionOutcome<&'static str>;

    fn pair(identity: &str) -> GroupPair {
        GroupPair {
            rgb: Some(identity.into()),
            ir: Some(identity.into()),
        }
    }

    fn cam(key: &'static str, identity: &str, fixed: bool) -> CandidatePair<&'static str> {
        CandidatePair {
            key,
            rgb_identity: identity.into(),
            ir_identity: identity.into(),
            fixed,
        }
    }

    fn enrolled(primary: Option<GroupPair>, groups: &[GroupPair]) -> AccountCameras {
        AccountCameras {
            primary,
            secondary_active: true,
            secondary_unreadable: false,
            groups: groups.to_vec(),
        }
    }

    fn every(_: CandidateScope) -> bool {
        true
    }

    fn select(connected: &[CandidatePair<&'static str>], account: &AccountCameras) -> Outcome {
        select_for_account(connected, account, every, false)
    }

    fn chosen(outcome: &Outcome) -> Option<(&'static str, CandidateScope)> {
        match outcome {
            SelectionOutcome::Selected(selection) => Some((selection.key, selection.scope)),
            _ => None,
        }
    }

    fn skip(scope: CandidateScope, reason: SkipReason) -> Skipped {
        Skipped { scope, reason }
    }

    const SECONDARY_0: CandidateScope = CandidateScope::Secondary { index: 0 };
    const SECONDARY_1: CandidateScope = CandidateScope::Secondary { index: 1 };
    const SECONDARY_2: CandidateScope = CandidateScope::Secondary { index: 2 };

    #[test]
    fn a_connected_eligible_complete_primary_is_chosen_first() {
        // The primary wins even over a built-in added camera: being built
        // in ranks enrollment candidates, never an account's own pairs.
        let account = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)]);
        let connected = [cam("added", ADDED_A, true), cam("primary", PRIMARY, false)];
        let outcome = select(&connected, &account);
        assert_eq!(
            outcome,
            SelectionOutcome::Selected(Selection {
                key: "primary",
                scope: CandidateScope::Primary,
                skipped: vec![],
            })
        );
    }

    #[test]
    fn an_incomplete_primary_binding_keeps_the_standing_pair_and_is_never_refused() {
        let incomplete = [
            None,
            Some(GroupPair {
                rgb: Some(BUILT_IN.into()),
                ir: None,
            }),
            Some(GroupPair {
                rgb: None,
                ir: Some(PRIMARY.into()),
            }),
            Some(GroupPair {
                rgb: None,
                ir: None,
            }),
            Some(GroupPair {
                rgb: Some(PRIMARY.into()),
                ir: Some(String::new()),
            }),
            Some(GroupPair {
                rgb: Some(String::new()),
                ir: Some(PRIMARY.into()),
            }),
        ];
        let connected = [cam("primary", PRIMARY, false), cam("lid", BUILT_IN, true)];
        for primary in incomplete {
            let label = format!("{primary:?}");
            // No group: automatic selection does not apply whatever is
            // connected; a bound side is never matched on its own.
            let alone = enrolled(primary.clone(), &[]);
            assert_eq!(
                select(&connected, &alone),
                SelectionOutcome::NotApplicable { skipped: vec![] },
                "{label}"
            );
            assert_eq!(
                select(&[], &alone),
                SelectionOutcome::NotApplicable { skipped: vec![] },
                "{label}"
            );
            // A complete group that is connected and eligible is chosen.
            let with_group = enrolled(primary.clone(), &[pair(ADDED_A)]);
            let mut docked = connected.to_vec();
            docked.push(cam("added", ADDED_A, false));
            assert_eq!(
                chosen(&select(&docked, &with_group)),
                Some(("added", SECONDARY_0)),
                "{label}"
            );
            // A group that cannot be used leaves the account on the
            // standing pair, reported, never refused.
            let refuse_all = select_for_account(&docked, &with_group, |_| false, false);
            assert_eq!(
                refuse_all,
                SelectionOutcome::NotApplicable {
                    skipped: vec![skip(SECONDARY_0, SkipReason::NotEligible)],
                },
                "{label}"
            );
            let inactive = AccountCameras {
                secondary_active: false,
                ..with_group.clone()
            };
            assert_eq!(
                select(&docked, &inactive),
                SelectionOutcome::NotApplicable {
                    skipped: vec![skip(SECONDARY_0, SkipReason::SecondaryInactive)],
                },
                "{label}"
            );
        }
    }

    #[test]
    fn a_disconnected_primary_falls_to_a_connected_eligible_group() {
        let account = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)]);
        let connected = [cam("lid", BUILT_IN, true), cam("added", ADDED_A, false)];
        assert_eq!(
            select(&connected, &account),
            SelectionOutcome::Selected(Selection {
                key: "added",
                scope: SECONDARY_0,
                skipped: vec![],
            })
        );
    }

    #[test]
    fn an_ineligible_primary_beside_an_eligible_group_selects_the_group() {
        let account = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)]);
        let connected = [cam("primary", PRIMARY, false), cam("added", ADDED_A, false)];
        let only_groups = |scope| scope != CandidateScope::Primary;
        assert_eq!(
            select_for_account(&connected, &account, only_groups, false),
            SelectionOutcome::Selected(Selection {
                key: "added",
                scope: SECONDARY_0,
                skipped: vec![skip(CandidateScope::Primary, SkipReason::NotEligible)],
            })
        );
        // A group on the primary's own pair (the add-camera path refuses to
        // create one, but a store may hold it) is reached only when the
        // primary cannot serve the mode.
        let same_pair = enrolled(Some(pair(PRIMARY)), &[pair(PRIMARY)]);
        let connected = [cam("primary", PRIMARY, false)];
        assert_eq!(
            chosen(&select(&connected, &same_pair)),
            Some(("primary", CandidateScope::Primary))
        );
        assert_eq!(
            chosen(&select_for_account(
                &connected,
                &same_pair,
                only_groups,
                false
            )),
            Some(("primary", SECONDARY_0))
        );
        // The primary is never ambiguous: two groups on its pair are
        // skipped, and the primary is still chosen.
        let two_on_primary = enrolled(Some(pair(PRIMARY)), &[pair(PRIMARY), pair(PRIMARY)]);
        assert_eq!(
            select(&connected, &two_on_primary),
            SelectionOutcome::Selected(Selection {
                key: "primary",
                scope: CandidateScope::Primary,
                skipped: vec![
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_1, SkipReason::AmbiguousGroups),
                ],
            })
        );
    }

    #[test]
    fn two_connected_groups_choose_the_lower_pair_identity_in_any_store_order() {
        let connected = [cam("b", ADDED_B, false), cam("a", ADDED_A, false)];
        let written = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_B), pair(ADDED_A)]);
        assert_eq!(
            chosen(&select(&connected, &written)),
            Some(("a", SECONDARY_1))
        );
        // The store rewritten in the other order (a group removed and added
        // back): the same camera, now at position 0.
        let rewritten = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A), pair(ADDED_B)]);
        assert_eq!(
            chosen(&select(&connected, &rewritten)),
            Some(("a", SECONDARY_0))
        );
    }

    #[test]
    fn the_canonical_order_compares_rgb_then_ir() {
        let split = |rgb: &str, ir: &str| GroupPair {
            rgb: Some(rgb.into()),
            ir: Some(ir.into()),
        };
        let wire = |key, rgb: &str, ir: &str| CandidatePair {
            key,
            rgb_identity: rgb.into(),
            ir_identity: ir.into(),
            fixed: false,
        };
        let groups = [
            split(ADDED_B, ADDED_A),
            split(ADDED_A, ADDED_B),
            split(ADDED_A, ADDED_A),
        ];
        let connected = [
            wire("ba", ADDED_B, ADDED_A),
            wire("ab", ADDED_A, ADDED_B),
            wire("aa", ADDED_A, ADDED_A),
        ];
        let account = enrolled(None, &groups);
        assert_eq!(
            chosen(&select(&connected, &account)),
            Some(("aa", SECONDARY_2))
        );
        let without_aa = select_for_account(&connected, &account, |s| s != SECONDARY_2, false);
        assert_eq!(chosen(&without_aa), Some(("ab", SECONDARY_1)));
    }

    #[test]
    fn groups_sharing_one_pair_are_skipped_and_reported() {
        let groups = [pair(ADDED_A), pair(ADDED_B), pair(ADDED_A)];
        let both = [cam("a", ADDED_A, false), cam("b", ADDED_B, false)];
        let account = enrolled(Some(pair(PRIMARY)), &groups);
        assert_eq!(
            select(&both, &account),
            SelectionOutcome::Selected(Selection {
                key: "b",
                scope: SECONDARY_1,
                skipped: vec![
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_2, SkipReason::AmbiguousGroups),
                ],
            })
        );
        // Alone, the ambiguous pair is never resolved by store order.
        assert_eq!(
            select(&[cam("a", ADDED_A, false)], &account),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::AmbiguousGroups),
                skipped: vec![
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_2, SkipReason::AmbiguousGroups),
                ],
            }
        );
        // A chosen primary does not hide the ambiguity from the report.
        let docked = [cam("a", ADDED_A, false), cam("primary", PRIMARY, false)];
        assert_eq!(
            select(&docked, &account),
            SelectionOutcome::Selected(Selection {
                key: "primary",
                scope: CandidateScope::Primary,
                skipped: vec![
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_2, SkipReason::AmbiguousGroups),
                ],
            })
        );
    }

    #[test]
    fn an_inactive_store_offers_no_group() {
        let inactive = AccountCameras {
            secondary_active: false,
            ..enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)])
        };
        let connected = [cam("added", ADDED_A, false)];
        assert_eq!(
            select(&connected, &inactive),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::SecondaryInactive),
                skipped: vec![skip(SECONDARY_0, SkipReason::SecondaryInactive)],
            }
        );
        // The primary is unaffected by the store's state, and the inactive
        // group below it is still reported.
        let connected = [cam("added", ADDED_A, false), cam("primary", PRIMARY, false)];
        assert_eq!(
            select(&connected, &inactive),
            SelectionOutcome::Selected(Selection {
                key: "primary",
                scope: CandidateScope::Primary,
                skipped: vec![skip(SECONDARY_0, SkipReason::SecondaryInactive)],
            })
        );
    }

    #[test]
    fn an_unreadable_store_is_the_cause_instead_of_no_enrolled_camera() {
        let binding = CameraBinding {
            rgb: Some(PRIMARY.into()),
            ir: Some(PRIMARY.into()),
        };
        let account =
            AccountCameras::from_stores("alice", Some(&binding), SecondaryFacts::Unreadable);
        // An added camera may be plugged in; the store cannot say which.
        let refused = SelectionOutcome::Refused {
            cause: RefusalCause::SecondaryUnreadable,
            skipped: vec![],
        };
        assert_eq!(select(&[cam("added", ADDED_A, false)], &account), refused);
        assert_eq!(select(&[], &account), refused);
        // A connected primary is still chosen.
        assert_eq!(
            select(&[cam("primary", PRIMARY, false)], &account),
            SelectionOutcome::Selected(Selection {
                key: "primary",
                scope: CandidateScope::Primary,
                skipped: vec![],
            })
        );
        // An incomplete primary keeps the standing pair, as before.
        let legacy = AccountCameras::from_stores("alice", None, SecondaryFacts::Unreadable);
        assert_eq!(
            select(&[cam("added", ADDED_A, false)], &legacy),
            SelectionOutcome::NotApplicable { skipped: vec![] }
        );
    }

    #[test]
    fn nothing_usable_connected_refuses_and_names_the_cause() {
        let account = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)]);
        // Nothing enrolled is connected.
        assert_eq!(
            select(&[cam("lid", BUILT_IN, true)], &account),
            SelectionOutcome::Refused {
                cause: RefusalCause::NoEnrolledCameraConnected,
                skipped: vec![],
            }
        );
        assert_eq!(
            select(&[], &account),
            SelectionOutcome::Refused {
                cause: RefusalCause::NoEnrolledCameraConnected,
                skipped: vec![],
            }
        );
        // Connected but not eligible for the mode.
        let connected = [cam("primary", PRIMARY, false), cam("added", ADDED_A, false)];
        assert_eq!(
            select_for_account(&connected, &account, |_| false, false),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::NotEligible),
                skipped: vec![
                    skip(CandidateScope::Primary, SkipReason::NotEligible),
                    skip(SECONDARY_0, SkipReason::NotEligible),
                ],
            }
        );
    }

    #[test]
    fn the_refusal_names_the_best_ranked_skip() {
        // The primary is connected but cannot serve the mode; the groups
        // are ambiguous. The primary ranks first, so its reason is the
        // cause, and the ambiguity is still reported.
        let account = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A), pair(ADDED_A)]);
        let connected = [cam("a", ADDED_A, false), cam("primary", PRIMARY, false)];
        assert_eq!(
            select_for_account(&connected, &account, |_| false, false),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::NotEligible),
                skipped: vec![
                    skip(CandidateScope::Primary, SkipReason::NotEligible),
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_1, SkipReason::AmbiguousGroups),
                ],
            }
        );
        // With the primary unplugged, the ambiguity is the cause.
        assert_eq!(
            select_for_account(&connected[..1], &account, |_| false, false),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::AmbiguousGroups),
                skipped: vec![
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_1, SkipReason::AmbiguousGroups),
                ],
            }
        );
    }

    #[test]
    fn reason_precedence_is_ambiguity_then_activity_then_external() {
        // Ambiguity is judged before activity, as the strict pin does, and
        // both before the external filter, whatever the carriers are.
        let groups = [pair(ADDED_A), pair(ADDED_A), pair(ADDED_B)];
        let inactive = AccountCameras {
            secondary_active: false,
            ..enrolled(Some(pair(PRIMARY)), &groups)
        };
        let connected = [cam("a", ADDED_A, false), cam("b", ADDED_B, false)];
        assert_eq!(
            select_for_account(&connected, &inactive, every, true),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::AmbiguousGroups),
                skipped: vec![
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_1, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_2, SkipReason::SecondaryInactive),
                ],
            }
        );
    }

    #[test]
    fn an_unenrolled_pair_alone_is_never_chosen() {
        let lid = [cam("lid", BUILT_IN, true)];
        let complete = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)]);
        assert_eq!(
            select(&lid, &complete),
            SelectionOutcome::Refused {
                cause: RefusalCause::NoEnrolledCameraConnected,
                skipped: vec![],
            }
        );
        let legacy = enrolled(None, &[pair(ADDED_A)]);
        assert_eq!(
            select(&lid, &legacy),
            SelectionOutcome::NotApplicable { skipped: vec![] }
        );
    }

    #[test]
    fn a_hybrid_of_two_enrolled_pairs_is_never_chosen() {
        let account = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)]);
        let hybrid = [CandidatePair {
            key: "hybrid",
            rgb_identity: PRIMARY.into(),
            ir_identity: ADDED_A.into(),
            fixed: false,
        }];
        assert_eq!(
            select(&hybrid, &account),
            SelectionOutcome::Refused {
                cause: RefusalCause::NoEnrolledCameraConnected,
                skipped: vec![],
            }
        );
    }

    #[test]
    fn a_one_sided_group_is_never_a_candidate() {
        let one_sided = GroupPair {
            rgb: None,
            ir: Some(ADDED_A.into()),
        };
        let account = enrolled(Some(pair(PRIMARY)), &[one_sided.clone()]);
        assert_eq!(
            select(&[cam("added", ADDED_A, false)], &account),
            SelectionOutcome::Refused {
                cause: RefusalCause::NoEnrolledCameraConnected,
                skipped: vec![],
            }
        );
        // Nor does it make a complete group on the same camera ambiguous.
        let beside = enrolled(Some(pair(PRIMARY)), &[one_sided, pair(ADDED_A)]);
        assert_eq!(
            select(&[cam("added", ADDED_A, false)], &beside),
            SelectionOutcome::Selected(Selection {
                key: "added",
                scope: SECONDARY_1,
                skipped: vec![],
            })
        );
    }

    #[test]
    fn cameras_that_cannot_be_told_apart_are_skipped() {
        let account = enrolled(Some(pair(PRIMARY)), &[pair(ADDED_A)]);
        // Two units carry the primary's identity: neither is opened; the
        // group is chosen instead.
        let twins = [
            cam("left", PRIMARY, false),
            cam("right", PRIMARY, false),
            cam("added", ADDED_A, false),
        ];
        assert_eq!(
            select(&twins, &account),
            SelectionOutcome::Selected(Selection {
                key: "added",
                scope: SECONDARY_0,
                skipped: vec![skip(CandidateScope::Primary, SkipReason::Indistinguishable)],
            })
        );
        assert_eq!(
            select(&twins[..2], &account),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::Indistinguishable),
                skipped: vec![skip(CandidateScope::Primary, SkipReason::Indistinguishable)],
            }
        );
        // Twins of a camera the account is not enrolled on change nothing.
        let others = [
            cam("lid", BUILT_IN, true),
            cam("lid-2", BUILT_IN, true),
            cam("primary", PRIMARY, false),
        ];
        assert_eq!(
            chosen(&select(&others, &account)),
            Some(("primary", CandidateScope::Primary))
        );
    }

    #[test]
    fn forbidding_external_cameras_filters_candidates_first() {
        let account = enrolled(Some(pair(PRIMARY)), &[pair(BUILT_IN)]);
        let connected = [cam("primary", PRIMARY, false), cam("lid", BUILT_IN, true)];
        assert_eq!(
            chosen(&select_for_account(&connected, &account, every, false)),
            Some(("primary", CandidateScope::Primary))
        );
        assert_eq!(
            select_for_account(&connected, &account, every, true),
            SelectionOutcome::Selected(Selection {
                key: "lid",
                scope: SECONDARY_0,
                skipped: vec![skip(CandidateScope::Primary, SkipReason::ExternalForbidden)],
            })
        );
        assert_eq!(
            select_for_account(&connected[..1], &account, every, true),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::ExternalForbidden),
                skipped: vec![skip(CandidateScope::Primary, SkipReason::ExternalForbidden)],
            }
        );
        // Filtering comes before the twin check: an external unit that
        // would be refused at open does not make a built-in one ambiguous.
        let mixed = [cam("dock", BUILT_IN, false), cam("lid", BUILT_IN, true)];
        assert_eq!(
            chosen(&select_for_account(&mixed, &account, every, true)),
            Some(("lid", SECONDARY_0))
        );
        assert_eq!(
            select_for_account(&mixed, &account, every, false),
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::Indistinguishable),
                skipped: vec![skip(SECONDARY_0, SkipReason::Indistinguishable)],
            }
        );
        // Pairs ranked below the choice are still reported when forbidden or
        // carried by twins.
        let below = enrolled(
            Some(pair(PRIMARY)),
            &[pair(BUILT_IN), pair(ADDED_B), pair(ADDED_A)],
        );
        let connected = [
            cam("a", ADDED_A, true),
            cam("b", ADDED_B, false),
            cam("lid", BUILT_IN, true),
            cam("lid-2", BUILT_IN, true),
        ];
        assert_eq!(
            select_for_account(&connected, &below, every, true),
            SelectionOutcome::Selected(Selection {
                key: "a",
                scope: SECONDARY_2,
                skipped: vec![
                    skip(SECONDARY_1, SkipReason::ExternalForbidden),
                    skip(SECONDARY_0, SkipReason::Indistinguishable),
                ],
            })
        );
    }

    #[test]
    fn eligibility_is_asked_lazily_in_rank_order() {
        let groups = [pair(ADDED_B), pair(ADDED_A), pair(BUILT_IN)];
        let account = enrolled(Some(pair(PRIMARY)), &groups);
        let connected = [
            cam("b", ADDED_B, false),
            cam("a", ADDED_A, false),
            cam("primary", PRIMARY, false),
        ];
        let asked = RefCell::new(Vec::new());
        let outcome = select_for_account(
            &connected,
            &account,
            |scope| {
                asked.borrow_mut().push(scope);
                scope == SECONDARY_0
            },
            false,
        );
        // The primary, then ADDED_A (index 1) before ADDED_B (index 0);
        // BUILT_IN is not connected and is never asked about.
        assert_eq!(
            asked.into_inner(),
            vec![CandidateScope::Primary, SECONDARY_1, SECONDARY_0]
        );
        assert_eq!(chosen(&outcome), Some(("b", SECONDARY_0)));
        // Once a pair is chosen, nothing below it is asked about.
        let asked = RefCell::new(Vec::new());
        let _ = select_for_account(
            &connected,
            &account,
            |scope| {
                asked.borrow_mut().push(scope);
                true
            },
            false,
        );
        assert_eq!(asked.into_inner(), vec![CandidateScope::Primary]);
    }

    #[test]
    fn eligibility_is_never_asked_about_a_skipped_pair() {
        let groups = [pair(ADDED_A), pair(ADDED_A), pair(ADDED_B), pair(BUILT_IN)];
        let account = enrolled(Some(pair(PRIMARY)), &groups);
        let connected = [
            cam("left", PRIMARY, false),
            cam("right", PRIMARY, false),
            cam("a", ADDED_A, true),
            cam("b", ADDED_B, false),
            cam("lid", BUILT_IN, true),
        ];
        let asked = RefCell::new(Vec::new());
        let record = |scope: CandidateScope| {
            asked.borrow_mut().push(scope);
            true
        };
        // Forbidden, ambiguous: only the built-in group is asked about.
        assert_eq!(
            select_for_account(&connected, &account, record, true),
            SelectionOutcome::Selected(Selection {
                key: "lid",
                scope: CandidateScope::Secondary { index: 3 },
                skipped: vec![
                    skip(CandidateScope::Primary, SkipReason::ExternalForbidden),
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_1, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_2, SkipReason::ExternalForbidden),
                ],
            })
        );
        assert_eq!(
            asked.replace(Vec::new()),
            vec![CandidateScope::Secondary { index: 3 }]
        );
        // Twins, ambiguous, inactive: nothing is asked about.
        let inactive = AccountCameras {
            secondary_active: false,
            ..account
        };
        let outcome = select_for_account(&connected, &inactive, record, false);
        assert_eq!(
            outcome,
            SelectionOutcome::Refused {
                cause: RefusalCause::Skipped(SkipReason::Indistinguishable),
                skipped: vec![
                    skip(CandidateScope::Primary, SkipReason::Indistinguishable),
                    skip(SECONDARY_0, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_1, SkipReason::AmbiguousGroups),
                    skip(SECONDARY_2, SkipReason::SecondaryInactive),
                    skip(
                        CandidateScope::Secondary { index: 3 },
                        SkipReason::SecondaryInactive
                    ),
                ],
            }
        );
        assert_eq!(asked.into_inner(), vec![]);
    }

    /// Every ordering of `items` (Heap's algorithm).
    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        fn heap<T: Clone>(k: usize, items: &mut [T], out: &mut Vec<Vec<T>>) {
            if k <= 1 {
                out.push(items.to_vec());
                return;
            }
            heap(k - 1, items, out);
            for i in 0..k - 1 {
                if k % 2 == 0 {
                    items.swap(i, k - 1);
                } else {
                    items.swap(0, k - 1);
                }
                heap(k - 1, items, out);
            }
        }
        let mut items = items.to_vec();
        let mut out = Vec::new();
        heap(items.len(), &mut items, &mut out);
        out
    }

    /// An outcome with every group position replaced by its pair, so two
    /// runs over differently ordered stores compare equal when they chose
    /// the same camera for the same enrolled pair.
    #[derive(Debug, PartialEq)]
    enum Normalized {
        Selected(
            &'static str,
            Option<GroupPair>,
            Vec<(Option<GroupPair>, SkipReason)>,
        ),
        NotApplicable(Vec<(Option<GroupPair>, SkipReason)>),
        Refused(RefusalCause, Vec<(Option<GroupPair>, SkipReason)>),
    }

    fn normalize(outcome: Outcome, groups: &[GroupPair]) -> Normalized {
        let scope_pair = |scope: CandidateScope| match scope {
            CandidateScope::Primary => None,
            CandidateScope::Secondary { index } => Some(groups[index].clone()),
        };
        let list = |skipped: Vec<Skipped>| {
            skipped
                .into_iter()
                .map(|s| (scope_pair(s.scope), s.reason))
                .collect()
        };
        match outcome {
            SelectionOutcome::Selected(s) => {
                Normalized::Selected(s.key, scope_pair(s.scope), list(s.skipped))
            }
            SelectionOutcome::NotApplicable { skipped } => Normalized::NotApplicable(list(skipped)),
            SelectionOutcome::Refused { cause, skipped } => {
                Normalized::Refused(cause, list(skipped))
            }
        }
    }

    #[test]
    fn store_and_connection_order_never_change_the_outcome() {
        // ADDED_B is held by two groups (ambiguous); ADDED_A and BUILT_IN by
        // one each. "a2" is a second unit carrying ADDED_A's identity.
        let store = [pair(ADDED_B), pair(ADDED_A), pair(BUILT_IN), pair(ADDED_B)];
        let orders = permutations(&store);
        assert_eq!(orders.len(), 24);
        let universe = [
            cam("p", PRIMARY, false),
            cam("a", ADDED_A, false),
            cam("a2", ADDED_A, false),
            cam("b", ADDED_B, false),
            cam("lid", BUILT_IN, true),
            cam("u", "0bda:5634", true),
        ];
        let identities = [PRIMARY, ADDED_A, ADDED_B, BUILT_IN];
        let mut selected = 0;
        for primary in [Some(pair(PRIMARY)), None] {
            for secondary_active in [true, false] {
                for forbid_external in [false, true] {
                    for connected_mask in 0u32..(1 << universe.len()) {
                        let connected: Vec<_> = universe
                            .iter()
                            .enumerate()
                            .filter(|(bit, _)| connected_mask & (1 << bit) != 0)
                            .map(|(_, pair)| pair.clone())
                            .collect();
                        for eligible_mask in 0u32..(1 << identities.len()) {
                            let eligible_pair = |pair: &GroupPair| {
                                identities.iter().enumerate().any(|(bit, identity)| {
                                    eligible_mask & (1 << bit) != 0
                                        && pair.rgb.as_deref() == Some(*identity)
                                })
                            };
                            let run = |groups: &[GroupPair], connected: &[CandidatePair<&'static str>]| {
                                let facts = AccountCameras {
                                    primary: primary.clone(),
                                    secondary_active,
                                    secondary_unreadable: false,
                                    groups: groups.to_vec(),
                                };
                                let outcome = select_for_account(
                                    connected,
                                    &facts,
                                    |scope| match scope {
                                        CandidateScope::Primary => eligible_pair(&pair(PRIMARY)),
                                        CandidateScope::Secondary { index } => {
                                            eligible_pair(&groups[index])
                                        }
                                    },
                                    forbid_external,
                                );
                                normalize(outcome, groups)
                            };
                            let baseline = run(&store, &connected);
                            if let Normalized::Selected(key, _, _) = &baseline {
                                selected += 1;
                                assert_ne!(*key, "u", "an unenrolled pair was chosen");
                            }
                            if matches!(baseline, Normalized::NotApplicable(_)) {
                                assert!(
                                    primary.is_none(),
                                    "only an incomplete primary is not applicable"
                                );
                            }
                            for order in &orders {
                                assert_eq!(
                                    run(order, &connected),
                                    baseline,
                                    "store {order:?}, connected {connected_mask:#b}, \
                                     eligible {eligible_mask:#b}"
                                );
                            }
                            let mut reversed = connected.clone();
                            reversed.reverse();
                            assert_eq!(run(&store, &reversed), baseline);
                        }
                    }
                }
            }
        }
        assert!(selected > 0);
    }

    #[test]
    fn from_stores_reads_the_binding_and_the_activation() {
        let binding = CameraBinding {
            rgb: Some(PRIMARY.into()),
            ir: None,
        };
        let group = |id: &str, identity: &str| super::super::SecondaryGroup {
            id: super::super::CameraGroupId::new(id.into()).expect("group id"),
            pair: pair(identity),
            profiles: Vec::new(),
        };
        let store = SecondaryStore {
            format_version: super::super::SECONDARY_STORE_VERSION,
            owner: "alice".into(),
            generation: 1,
            primary_snapshot_sha256: "a".repeat(64),
            groups: vec![group("g2", ADDED_B), group("g1", ADDED_A)],
        };
        assert_eq!(
            AccountCameras::from_stores(
                "alice",
                Some(&binding),
                SecondaryFacts::Loaded(&store, Activation::Active)
            ),
            AccountCameras {
                primary: Some(GroupPair {
                    rgb: Some(PRIMARY.into()),
                    ir: None,
                }),
                secondary_active: true,
                secondary_unreadable: false,
                groups: vec![pair(ADDED_B), pair(ADDED_A)],
            }
        );
        let inactive = AccountCameras::from_stores(
            "alice",
            None,
            SecondaryFacts::Loaded(&store, Activation::InactivePrimaryChanged),
        );
        assert_eq!(inactive.primary, None);
        assert!(!inactive.secondary_active);
        assert!(!inactive.secondary_unreadable);
        assert_eq!(inactive.groups.len(), 2, "kept, so they can be reported");
        assert_eq!(
            AccountCameras::from_stores("alice", None, SecondaryFacts::Absent),
            AccountCameras::default()
        );
        // A store that could not be loaded, or that names another owner,
        // authorizes no group, as the strict pin refuses it.
        let unusable = AccountCameras {
            secondary_unreadable: true,
            ..AccountCameras::default()
        };
        assert_eq!(
            AccountCameras::from_stores("alice", None, SecondaryFacts::Unreadable),
            unusable
        );
        let mallory = SecondaryStore {
            owner: "mallory".into(),
            ..store
        };
        assert_eq!(
            AccountCameras::from_stores(
                "alice",
                None,
                SecondaryFacts::Loaded(&mallory, Activation::Active)
            ),
            unusable
        );
    }

    #[test]
    fn enrollment_candidates_rank_allowlist_then_built_in_then_identity() {
        let pairs = [
            cam("ext-z", "fff0:0001", false),
            cam("ext-a", "0001:0001:9", false),
            cam("lid", BUILT_IN, true),
            cam("brio", PRIMARY, false),
        ];
        let allowlist = vec!["046D:085E".to_owned()];
        let expected = vec![
            ("brio", CandidateRank::Allowlisted),
            ("lid", CandidateRank::BuiltIn),
            ("ext-a", CandidateRank::Other),
            ("ext-z", CandidateRank::Other),
        ];
        for order in permutations(&pairs) {
            let ranked: Vec<_> = rank_enrollment_candidates(&order, &allowlist, false)
                .into_iter()
                .map(|c| (c.key, c.rank))
                .collect();
            assert_eq!(ranked, expected, "input {order:?}");
        }
        // No allowlist: built in first, then the identity order.
        let ranked: Vec<_> = rank_enrollment_candidates(&pairs, &[], false)
            .into_iter()
            .map(|c| c.key)
            .collect();
        assert_eq!(ranked, vec!["lid", "ext-a", "brio", "ext-z"]);
    }

    #[test]
    fn the_allowlist_needs_both_sides() {
        let split = CandidatePair {
            key: "split",
            rgb_identity: PRIMARY.into(),
            ir_identity: ADDED_A.into(),
            fixed: false,
        };
        let allowlist = vec!["046d:085e".to_owned()];
        assert_eq!(
            rank_enrollment_candidates(&[split.clone()], &allowlist, false)[0].rank,
            CandidateRank::Other
        );
        let both = vec!["046d:085e".to_owned(), "1bcf:28c4".to_owned()];
        assert_eq!(
            rank_enrollment_candidates(&[split], &both, false)[0].rank,
            CandidateRank::Allowlisted
        );
        // The serial is not part of the match, even when it holds a colon.
        let colon = cam("colon", "046d:085e:ab:cd", false);
        assert_eq!(
            rank_enrollment_candidates(&[colon], &allowlist, false)[0].rank,
            CandidateRank::Allowlisted
        );
        // An identity without a serial is its own `vid:pid`.
        assert_eq!(
            rank_enrollment_candidates(
                &[cam("ext", "0bda:5634", false)],
                &["0bda:5634".to_owned()],
                false
            )[0]
            .rank,
            CandidateRank::Allowlisted
        );
    }

    #[test]
    fn allowlist_entries_are_matched_without_surrounding_whitespace() {
        // `IRLUME_CAMERA_PIN="3277:0059, 046D:085E "` split on commas.
        let raw = vec!["3277:0059".to_owned(), " 046D:085E ".to_owned()];
        let brio = cam("brio", PRIMARY, false);
        let lid = cam("lid", "0bda:5634", true);
        let ranked: Vec<_> = rank_enrollment_candidates(&[lid, brio], &raw, false)
            .into_iter()
            .map(|c| (c.key, c.rank))
            .collect();
        assert_eq!(
            ranked,
            vec![
                ("brio", CandidateRank::Allowlisted),
                ("lid", CandidateRank::BuiltIn),
            ]
        );
    }

    #[test]
    fn forbidding_external_cameras_leaves_them_out_of_enrollment() {
        let pairs = [cam("brio", PRIMARY, false), cam("lid", BUILT_IN, true)];
        let allowlist = vec!["046d:085e".to_owned()];
        let keys = |forbid| -> Vec<&str> {
            rank_enrollment_candidates(&pairs, &allowlist, forbid)
                .into_iter()
                .map(|c| c.key)
                .collect()
        };
        assert_eq!(keys(false), vec!["brio", "lid"]);
        assert_eq!(keys(true), vec!["lid"]);
        // An external unit left out by the policy does not make the
        // built-in one a twin.
        let ranked = rank_enrollment_candidates(
            &[cam("dock", BUILT_IN, false), cam("lid", BUILT_IN, true)],
            &[],
            true,
        );
        assert_eq!(ranked.len(), 1);
        assert!(!ranked[0].shares_identity);
    }

    #[test]
    fn enrollment_candidates_compare_rgb_then_ir_identity() {
        let wire = |key, rgb: &str, ir: &str| CandidatePair {
            key,
            rgb_identity: rgb.into(),
            ir_identity: ir.into(),
            fixed: false,
        };
        let pairs = [
            wire("k0", ADDED_A, BUILT_IN),
            wire("k1", ADDED_A, ADDED_B),
            wire("k2", ADDED_B, ADDED_A),
        ];
        for order in permutations(&pairs) {
            let ranked: Vec<_> = rank_enrollment_candidates(&order, &[], false)
                .into_iter()
                .map(|c| (c.key, c.shares_identity))
                .collect();
            assert_eq!(
                ranked,
                vec![("k1", false), ("k0", false), ("k2", false)],
                "input {order:?}"
            );
        }
    }

    #[test]
    fn enrollment_twins_are_flagged_and_ordered_by_key() {
        let pairs = [
            cam("port-2", BUILT_IN, false),
            cam("brio", PRIMARY, false),
            cam("port-1", BUILT_IN, false),
        ];
        for order in permutations(&pairs) {
            let ranked: Vec<_> = rank_enrollment_candidates(&order, &[], false)
                .into_iter()
                .map(|c| (c.key, c.shares_identity))
                .collect();
            assert_eq!(
                ranked,
                vec![("brio", false), ("port-1", true), ("port-2", true)],
                "input {order:?}"
            );
        }
    }
}
