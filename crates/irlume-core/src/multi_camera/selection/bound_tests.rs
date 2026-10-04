// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Hand-built complete-key selection cases. No device, store or environment IO.

use super::tests::permutations;
use super::*;
use irlume_common::binding_key::CompletePairKey;
use irlume_common::split_key::{SplitDomain, SplitPairKey, SplitUnitKey};

type Outcome = SelectionOutcome<&'static str>;

fn ordinary(rgb: &str, ir: &str) -> CompletePairKey {
    CompletePairKey::Ordinary {
        rgb: rgb.into(),
        ir: ir.into(),
    }
}

fn split() -> SplitPairKey {
    SplitPairKey {
        rgb: SplitUnitKey {
            identity: "5986:2113:rgb".into(),
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::Usb2,
            ports: vec![8],
        },
        ir: SplitUnitKey {
            identity: "5986:1141:ir".into(),
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::Usb2,
            ports: vec![5],
        },
    }
}

fn cam(
    key: &'static str,
    pair: CompletePairKey,
    rgb_fixed: bool,
    ir_fixed: bool,
) -> BoundCandidatePair<&'static str> {
    BoundCandidatePair {
        key,
        pair,
        rgb_fixed,
        ir_fixed,
    }
}

fn account(primary: Option<CompletePairKey>, groups: &[CompletePairKey]) -> AccountCameras {
    AccountCameras {
        primary: primary.map(GroupPair::from),
        secondary_active: true,
        secondary_unreadable: false,
        groups: groups.iter().cloned().map(GroupPair::from).collect(),
    }
}

fn select(connected: &[BoundCandidatePair<&'static str>], account: &AccountCameras) -> Outcome {
    select_bound_for_account(connected, account, |_| true, false)
}

fn skip(scope: CandidateScope, reason: SkipReason) -> Skipped {
    Skipped { scope, reason }
}

fn secondary(index: usize) -> CandidateScope {
    CandidateScope::Secondary { index }
}

fn selected(key: &'static str, scope: CandidateScope, skipped: Vec<Skipped>) -> Outcome {
    SelectionOutcome::Selected(Selection {
        key,
        scope,
        skipped,
    })
}

fn refused(cause: RefusalCause, skipped: Vec<Skipped>) -> Outcome {
    SelectionOutcome::Refused { cause, skipped }
}

/// `low` precedes `high` by a hand-chosen field difference, not a comparator
/// used to derive the expectation. Exercise both store and input orders.
fn assert_precedes(low: SplitPairKey, high: SplitPairKey) {
    let low = CompletePairKey::Split(low);
    let high = CompletePairKey::Split(high);
    let connected = [
        cam("high", high.clone(), true, true),
        cam("low", low.clone(), true, true),
    ];
    for groups in permutations(&[high.clone(), low.clone()]) {
        let low_index = groups.iter().position(|key| key == &low).unwrap();
        let high_index = 1 - low_index;
        let account = account(Some(ordinary("absent", "absent")), &groups);
        for connected in permutations(&connected) {
            let mut asked = Vec::new();
            let outcome = select_bound_for_account(
                &connected,
                &account,
                |scope| {
                    asked.push(scope);
                    true
                },
                false,
            );
            assert_eq!(outcome, selected("low", secondary(low_index), vec![]));
            assert_eq!(asked, vec![secondary(low_index)]);
            let mut asked = Vec::new();
            let outcome = select_bound_for_account(
                &connected,
                &account,
                |scope| {
                    asked.push(scope);
                    scope == secondary(high_index)
                },
                false,
            );
            assert_eq!(
                outcome,
                selected(
                    "high",
                    secondary(high_index),
                    vec![skip(secondary(low_index), SkipReason::NotEligible)],
                )
            );
            assert_eq!(asked, vec![secondary(low_index), secondary(high_index)]);
        }
    }
}

#[test]
fn split_primary_precedes_ordinary_secondary_with_an_opaque_handle() {
    // The selector needs neither Ord nor Eq on the caller's handle.
    #[derive(Clone, Debug)]
    struct Handle(u8);

    let split = CompletePairKey::Split(split());
    let ordinary = ordinary("0001:0001:rgb", "0001:0001:ir");
    let account = account(Some(split.clone()), std::slice::from_ref(&ordinary));
    let connected = [
        BoundCandidatePair {
            key: Handle(1),
            pair: ordinary,
            rgb_fixed: true,
            ir_fixed: true,
        },
        BoundCandidatePair {
            key: Handle(2),
            pair: split,
            rgb_fixed: false,
            ir_fixed: false,
        },
    ];
    for connected in permutations(&connected) {
        let mut asked = Vec::new();
        let outcome = select_bound_for_account(
            &connected,
            &account,
            |scope| {
                asked.push(scope);
                true
            },
            false,
        );
        let SelectionOutcome::Selected(chosen) = outcome else {
            panic!("the enrolled split primary must be selected");
        };
        assert_eq!(chosen.key.0, 2);
        assert_eq!(chosen.scope, CandidateScope::Primary);
        assert!(chosen.skipped.is_empty());
        assert_eq!(asked, vec![CandidateScope::Primary]);
    }
}

#[test]
fn ordinary_secondary_precedes_split_even_with_a_larger_identity() {
    let mut split = split();
    split.rgb.identity = "0001:0001:rgb".into();
    let split = CompletePairKey::Split(split);
    let ordinary = ordinary("ffff:ffff:rgb", "ffff:ffff:ir");
    let connected = [
        cam("split", split.clone(), true, true),
        cam("ordinary", ordinary.clone(), true, true),
    ];
    for groups in permutations(&[split, ordinary.clone()]) {
        let ordinary_index = groups.iter().position(|key| key == &ordinary).unwrap();
        let account = account(Some(ordinary_key_absent()), &groups);
        for connected in permutations(&connected) {
            assert_eq!(
                select(&connected, &account),
                selected("ordinary", secondary(ordinary_index), vec![])
            );
            assert_eq!(
                select_bound_for_account(
                    &connected,
                    &account,
                    |scope| scope != secondary(ordinary_index),
                    false,
                ),
                selected(
                    "split",
                    secondary(1 - ordinary_index),
                    vec![skip(secondary(ordinary_index), SkipReason::NotEligible)],
                )
            );
        }
    }
}

#[test]
fn ordinary_adapter_never_projects_a_split_binding_to_matching_identities() {
    let split = split();
    let connected = [CandidatePair {
        key: "ordinary",
        rgb_identity: split.rgb.identity.clone(),
        ir_identity: split.ir.identity.clone(),
        fixed: true,
    }];
    let account = account(Some(CompletePairKey::Split(split)), &[]);
    let mut asked = Vec::new();
    assert_eq!(
        select_for_account(
            &connected,
            &account,
            |scope| {
                asked.push(scope);
                true
            },
            false,
        ),
        refused(RefusalCause::NoEnrolledCameraConnected, vec![])
    );
    assert!(asked.is_empty());
}

#[test]
fn ordinary_adapter_clones_only_the_chosen_opaque_handle() {
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Debug)]
    struct Handle {
        id: u8,
        clones: Rc<Cell<usize>>,
    }

    impl Clone for Handle {
        fn clone(&self) -> Self {
            self.clones.set(self.clones.get() + 1);
            Self {
                id: self.id,
                clones: Rc::clone(&self.clones),
            }
        }
    }

    let primary_clones = Rc::new(Cell::new(0));
    let secondary_clones = Rc::new(Cell::new(0));
    let connected = [
        CandidatePair {
            key: Handle {
                id: 0,
                clones: Rc::clone(&secondary_clones),
            },
            rgb_identity: "secondary".into(),
            ir_identity: "secondary".into(),
            fixed: true,
        },
        CandidatePair {
            key: Handle {
                id: 1,
                clones: Rc::clone(&primary_clones),
            },
            rgb_identity: "primary".into(),
            ir_identity: "primary".into(),
            fixed: true,
        },
    ];
    let account = account(
        Some(ordinary("primary", "primary")),
        &[ordinary("secondary", "secondary")],
    );
    let outcome = select_for_account(&connected, &account, |_| true, false);
    let SelectionOutcome::Selected(chosen) = outcome else {
        panic!("the ordinary primary is usable");
    };
    assert_eq!(chosen.key.id, 1);
    assert_eq!(primary_clones.get(), 1);
    assert_eq!(secondary_clones.get(), 0);
}

fn ordinary_key_absent() -> CompletePairKey {
    ordinary("046d:085e:absent", "046d:085e:absent")
}

#[test]
fn split_secondary_ports_compare_eight_before_ten_on_either_side() {
    for rgb in [true, false] {
        for prefix in [vec![], vec![2]] {
            let mut low = split();
            let mut high = low.clone();
            let low_side = if rgb { &mut low.rgb } else { &mut low.ir };
            let high_side = if rgb { &mut high.rgb } else { &mut high.ir };
            low_side.ports = prefix.clone();
            low_side.ports.push(8);
            high_side.ports = prefix;
            high_side.ports.push(10);
            assert_precedes(low, high);
        }
    }
}

#[test]
fn split_secondary_port_prefix_precedes_the_longer_chain_on_either_side() {
    for rgb in [true, false] {
        let low = split();
        let mut high = low.clone();
        if rgb {
            high.rgb.ports.push(1);
        } else {
            high.ir.ports.push(1);
        }
        assert_precedes(low, high);
    }
}

#[test]
fn split_secondary_domain_table_order_precedes_port_order_on_either_side() {
    for rgb in [true, false] {
        let mut low = split();
        let mut high = low.clone();
        let low_side = if rgb { &mut low.rgb } else { &mut low.ir };
        let high_side = if rgb { &mut high.rgb } else { &mut high.ir };
        low_side.domain = SplitDomain::SuperSpeed;
        low_side.ports = vec![10];
        high_side.domain = SplitDomain::Usb2;
        high_side.ports = vec![8];
        assert_precedes(low, high);
    }
}

#[test]
fn split_secondary_controller_order_precedes_domain_order_on_either_side() {
    for rgb in [true, false] {
        let mut low = split();
        let mut high = low.clone();
        let low_side = if rgb { &mut low.rgb } else { &mut low.ir };
        let high_side = if rgb { &mut high.rgb } else { &mut high.ir };
        low_side.controller = "0000:00:14.0".into();
        low_side.domain = SplitDomain::Usb2;
        high_side.controller = "0000:00:15.0".into();
        high_side.domain = SplitDomain::SuperSpeed;
        assert_precedes(low, high);
    }
}

#[test]
fn split_secondary_identity_order_and_complete_rgb_key_precede_ir_fields() {
    for rgb in [true, false] {
        let mut low = split();
        let mut high = low.clone();
        let low_side = if rgb { &mut low.rgb } else { &mut low.ir };
        let high_side = if rgb { &mut high.rgb } else { &mut high.ir };
        low_side.identity = "0001:0001:a".into();
        low_side.controller = "0000:00:15.0".into();
        high_side.identity = "0001:0001:b".into();
        high_side.controller = "0000:00:14.0".into();
        assert_precedes(low, high);
    }
    // A later RGB field still precedes the IR identity, even when its text
    // would sort last. Comparing both identities before locations is wrong.
    let mut low = split();
    let mut high = low.clone();
    low.ir.identity = "ffff:ffff:ir".into();
    high.rgb.ports = vec![10];
    high.ir.identity = "0001:0001:ir".into();
    assert_precedes(low, high);
}

#[test]
fn split_secondary_raw_identity_order_is_not_percent_encoded_text_order() {
    for rgb in [true, false] {
        let mut low = split();
        let mut high = low.clone();
        let low_side = if rgb { &mut low.rgb } else { &mut low.ir };
        let high_side = if rgb { &mut high.rgb } else { &mut high.ir };
        low_side.identity = "5986:2113:z".into();
        high_side.identity = "5986:2113:é".into();
        // Raw UTF-8 z precedes é; the canonical %C3%A9 text precedes z.
        assert_precedes(low, high);
    }
}

#[test]
fn mixed_store_and_input_permutations_preserve_choice_and_lower_ranked_reports() {
    let ordinary = ordinary("ffff:ffff:rgb", "ffff:ffff:ir");
    let duplicate = CompletePairKey::Split(split());
    let mut twin = split();
    twin.rgb.ports = vec![10];
    let twin = CompletePairKey::Split(twin);
    let groups = [
        duplicate.clone(),
        twin.clone(),
        ordinary.clone(),
        duplicate.clone(),
    ];
    let connected = [
        cam("duplicate", duplicate.clone(), true, true),
        cam("right", twin.clone(), true, true),
        cam("ordinary", ordinary.clone(), true, true),
        cam("left", twin.clone(), true, true),
    ];
    for groups in permutations(&groups) {
        let ordinary_index = groups.iter().position(|key| key == &ordinary).unwrap();
        let account = account(Some(ordinary_key_absent()), &groups);
        for connected in permutations(&connected) {
            let mut asked = Vec::new();
            let outcome = select_bound_for_account(
                &connected,
                &account,
                |scope| {
                    asked.push(scope);
                    true
                },
                false,
            );
            let SelectionOutcome::Selected(chosen) = outcome else {
                panic!("the ordinary secondary is usable");
            };
            assert_eq!(chosen.key, "ordinary");
            assert_eq!(chosen.scope, secondary(ordinary_index));
            assert_eq!(asked, vec![secondary(ordinary_index)]);
            let reported: Vec<_> = chosen
                .skipped
                .iter()
                .map(|skipped| {
                    let CandidateScope::Secondary { index } = skipped.scope else {
                        panic!("the absent primary is not reported");
                    };
                    (groups[index].clone(), skipped.reason)
                })
                .collect();
            assert_eq!(
                reported,
                vec![
                    (duplicate.clone(), SkipReason::AmbiguousGroups),
                    (duplicate.clone(), SkipReason::AmbiguousGroups),
                    (twin.clone(), SkipReason::Indistinguishable),
                ]
            );
        }
    }
}

#[test]
fn complete_matching_refuses_class_role_hybrid_and_either_side_location_mismatches() {
    let wanted = split();
    let mut other = wanted.clone();
    other.rgb.identity = "5986:2113:other-rgb".into();
    other.ir.identity = "5986:1141:other-ir".into();
    other.rgb.ports = vec![10];
    other.ir.ports = vec![9];
    let account = account(
        Some(CompletePairKey::Split(wanted.clone())),
        &[CompletePairKey::Split(other.clone())],
    );
    let mut mismatches = vec![ordinary(&wanted.rgb.identity, &wanted.ir.identity)];
    mismatches.push(CompletePairKey::Split(SplitPairKey {
        rgb: wanted.ir.clone(),
        ir: wanted.rgb.clone(),
    }));
    for rgb in [true, false] {
        for field in 0..4 {
            let mut mismatch = wanted.clone();
            let side = if rgb {
                &mut mismatch.rgb
            } else {
                &mut mismatch.ir
            };
            match field {
                0 => side.identity = "5986:0001:replacement".into(),
                1 => side.controller = "0000:00:15.0".into(),
                2 => side.domain = SplitDomain::SuperSpeed,
                _ => side.ports.push(1),
            }
            mismatches.push(CompletePairKey::Split(mismatch));
        }
    }
    mismatches.extend([
        CompletePairKey::Split(SplitPairKey {
            rgb: wanted.rgb.clone(),
            ir: other.ir.clone(),
        }),
        CompletePairKey::Split(SplitPairKey {
            rgb: other.rgb.clone(),
            ir: wanted.ir.clone(),
        }),
    ]);
    for pair in mismatches {
        let mut asked = Vec::new();
        let outcome = select_bound_for_account(
            &[cam("mismatch", pair.clone(), true, true)],
            &account,
            |scope| {
                asked.push(scope);
                true
            },
            false,
        );
        assert_eq!(
            outcome,
            refused(RefusalCause::NoEnrolledCameraConnected, vec![]),
            "{pair:?}"
        );
        assert!(asked.is_empty());
    }
    let ordinary_account = account_from_ordinary_sides(&wanted);
    assert_eq!(
        select(
            &[cam("split", CompletePairKey::Split(wanted), true, true)],
            &ordinary_account,
        ),
        refused(RefusalCause::NoEnrolledCameraConnected, vec![])
    );
}

#[test]
fn same_identities_in_distinct_classes_or_locations_do_not_create_ambiguity() {
    let split = split();
    let ordinary = ordinary(&split.rgb.identity, &split.ir.identity);
    let mut moved = split.clone();
    moved.ir.ports.push(1);
    let split = CompletePairKey::Split(split);
    let moved = CompletePairKey::Split(moved);
    let account = account(
        Some(ordinary_key_absent()),
        &[moved.clone(), split.clone(), ordinary.clone()],
    );
    let connected = [
        cam("moved", moved, true, true),
        cam("split", split, true, true),
        cam("ordinary", ordinary, true, true),
    ];
    for connected in permutations(&connected) {
        assert_eq!(
            select(&connected, &account),
            selected("ordinary", secondary(2), vec![])
        );
        assert_eq!(
            select_bound_for_account(&connected, &account, |scope| scope != secondary(2), false),
            selected(
                "split",
                secondary(1),
                vec![skip(secondary(2), SkipReason::NotEligible)],
            )
        );
    }
}

fn account_from_ordinary_sides(split: &SplitPairKey) -> AccountCameras {
    account(Some(ordinary(&split.rgb.identity, &split.ir.identity)), &[])
}

fn malformed_split_keys() -> Vec<CompletePairKey> {
    let mut keys = Vec::new();
    for rgb in [true, false] {
        for invalid in 0..8 {
            let mut key = split();
            let side = if rgb { &mut key.rgb } else { &mut key.ir };
            match invalid {
                0 => side.identity.clear(),
                1 => side.controller.clear(),
                2 => side.ports.clear(),
                3 => side.ports = vec![8, 0],
                4 => side.ports = vec![1; 7],
                5 => side.identity = "a".repeat(257),
                6 => side.controller = "a".repeat(257),
                _ => side.identity = "é".repeat(129),
            }
            keys.push(CompletePairKey::Split(key));
        }
    }
    keys
}

#[test]
fn invalid_split_primary_is_refused_before_legacy_fallback_or_secondary_selection() {
    let ordinary = ordinary("046d:085e:rgb", "046d:085e:ir");
    for invalid in malformed_split_keys() {
        let account = account(Some(invalid.clone()), std::slice::from_ref(&ordinary));
        let connected = [
            cam("invalid", invalid.clone(), true, true),
            cam("ordinary", ordinary.clone(), true, true),
        ];
        let mut asked = Vec::new();
        let outcome = select_bound_for_account(
            &connected,
            &account,
            |scope| {
                asked.push(scope);
                true
            },
            false,
        );
        assert_eq!(
            outcome,
            refused(RefusalCause::InvalidBinding, vec![]),
            "{invalid:?}"
        );
        assert!(asked.is_empty());
        assert_eq!(
            select(&[], &account),
            refused(RefusalCause::InvalidBinding, vec![])
        );
        assert_eq!(
            select_for_account::<&str>(&[], &account, |_| true, false),
            refused(RefusalCause::InvalidBinding, vec![])
        );
    }
}

#[test]
fn malformed_candidates_and_groups_never_select_or_make_a_valid_group_ambiguous() {
    let valid = CompletePairKey::Split(split());
    let mut malformed = malformed_split_keys();
    malformed.extend([ordinary("", "ir"), ordinary("rgb", "")]);
    for invalid in malformed {
        let mut account = account(Some(ordinary_key_absent()), std::slice::from_ref(&invalid));
        let connected = [cam("invalid", invalid.clone(), true, true)];
        let mut asked = Vec::new();
        let outcome = select_bound_for_account(
            &connected,
            &account,
            |scope| {
                asked.push(scope);
                true
            },
            false,
        );
        assert_eq!(
            outcome,
            refused(RefusalCause::NoEnrolledCameraConnected, vec![])
        );
        assert!(asked.is_empty());
        account.groups.push(valid.clone().into());
        let connected = [
            connected[0].clone(),
            cam("valid", valid.clone(), true, true),
        ];
        assert_eq!(
            select(&connected, &account),
            selected("valid", secondary(1), vec![])
        );
    }
}

#[test]
fn valid_split_field_boundaries_remain_selectable() {
    let mut split = split();
    for (side, identity) in [
        (&mut split.rgb, "5986:2113:"),
        (&mut split.ir, "5986:1141:"),
    ] {
        side.identity = format!("{identity}{}", "é".repeat(123));
        side.controller = "a".repeat(256);
        side.ports = vec![1, 8, 10, 128, 254, 255];
    }
    let key = CompletePairKey::Split(split);
    let account = account(Some(key.clone()), &[]);
    assert_eq!(
        select(&[cam("boundary", key, true, true)], &account),
        selected("boundary", CandidateScope::Primary, vec![])
    );
}

#[test]
fn duplicate_split_keys_are_ambiguous_but_primary_skip_keeps_refusal_precedence() {
    let split = CompletePairKey::Split(split());
    let connected = [cam("split", split.clone(), true, true)];
    let account = account(Some(split.clone()), &[split.clone(), split.clone()]);
    assert_eq!(
        select(&connected, &account),
        selected(
            "split",
            CandidateScope::Primary,
            vec![
                skip(secondary(0), SkipReason::AmbiguousGroups),
                skip(secondary(1), SkipReason::AmbiguousGroups),
            ],
        )
    );
    let mut asked = Vec::new();
    assert_eq!(
        select_bound_for_account(
            &connected,
            &account,
            |scope| {
                asked.push(scope);
                false
            },
            false,
        ),
        refused(
            RefusalCause::Skipped(SkipReason::NotEligible),
            vec![
                skip(CandidateScope::Primary, SkipReason::NotEligible),
                skip(secondary(0), SkipReason::AmbiguousGroups),
                skip(secondary(1), SkipReason::AmbiguousGroups),
            ],
        )
    );
    assert_eq!(asked, vec![CandidateScope::Primary]);
    let disconnected_primary = AccountCameras {
        primary: Some(ordinary_key_absent().into()),
        ..account
    };
    assert_eq!(
        select(&connected, &disconnected_primary),
        refused(
            RefusalCause::Skipped(SkipReason::AmbiguousGroups),
            vec![
                skip(secondary(0), SkipReason::AmbiguousGroups),
                skip(secondary(1), SkipReason::AmbiguousGroups),
            ],
        )
    );
}

#[test]
fn connected_split_twins_are_indistinguishable_even_with_equal_opaque_handles() {
    let split = CompletePairKey::Split(split());
    let account = account(Some(split.clone()), &[]);
    for second_handle in ["left", "right"] {
        let connected = [
            cam("left", split.clone(), true, true),
            cam(second_handle, split.clone(), true, true),
        ];
        for connected in permutations(&connected) {
            let mut asked = Vec::new();
            let outcome = select_bound_for_account(
                &connected,
                &account,
                |scope| {
                    asked.push(scope);
                    true
                },
                false,
            );
            assert_eq!(
                outcome,
                refused(
                    RefusalCause::Skipped(SkipReason::Indistinguishable),
                    vec![skip(CandidateScope::Primary, SkipReason::Indistinguishable)],
                )
            );
            assert!(asked.is_empty());
        }
    }
}

#[test]
fn external_policy_requires_both_fixed_sides_in_both_classes() {
    for pair in [CompletePairKey::Split(split()), ordinary_key_absent()] {
        let account = account(Some(pair.clone()), &[]);
        for (rgb_fixed, ir_fixed) in [(false, true), (true, false), (false, false), (true, true)] {
            let connected = [cam("pair", pair.clone(), rgb_fixed, ir_fixed)];
            assert_eq!(
                select(&connected, &account),
                selected("pair", CandidateScope::Primary, vec![])
            );
            let mut asked = Vec::new();
            let outcome = select_bound_for_account(
                &connected,
                &account,
                |scope| {
                    asked.push(scope);
                    true
                },
                true,
            );
            if rgb_fixed && ir_fixed {
                assert_eq!(outcome, selected("pair", CandidateScope::Primary, vec![]));
                assert_eq!(asked, vec![CandidateScope::Primary]);
            } else {
                assert_eq!(
                    outcome,
                    refused(
                        RefusalCause::Skipped(SkipReason::ExternalForbidden),
                        vec![skip(CandidateScope::Primary, SkipReason::ExternalForbidden)],
                    )
                );
                assert!(asked.is_empty());
            }
        }
    }
}

#[test]
fn either_side_external_twin_is_filtered_before_indistinguishability() {
    let split = CompletePairKey::Split(split());
    let account = account(Some(split.clone()), &[]);
    let connected = [
        cam("ir-external", split.clone(), true, false),
        cam("fixed", split.clone(), true, true),
        cam("rgb-external", split, false, true),
    ];
    for connected in permutations(&connected) {
        assert_eq!(
            select_bound_for_account(&connected, &account, |_| true, true),
            selected("fixed", CandidateScope::Primary, vec![])
        );
        assert_eq!(
            select(&connected, &account),
            refused(
                RefusalCause::Skipped(SkipReason::Indistinguishable),
                vec![skip(CandidateScope::Primary, SkipReason::Indistinguishable)],
            )
        );
    }
}

#[test]
fn split_skip_precedence_and_reports_below_a_choice_match_ordinary_policy() {
    let duplicate = CompletePairKey::Split(split());
    let mut external = split();
    external.rgb.ports = vec![10];
    let external = CompletePairKey::Split(external);
    let primary = ordinary_key_absent();
    let mut account = account(
        Some(primary.clone()),
        &[duplicate.clone(), external.clone(), duplicate.clone()],
    );
    let connected = [
        cam("primary", primary, true, true),
        cam("duplicate", duplicate, false, true),
        cam("external", external, true, false),
    ];
    for (active, last_reason) in [
        (false, SkipReason::SecondaryInactive),
        (true, SkipReason::ExternalForbidden),
    ] {
        account.secondary_active = active;
        let mut asked = Vec::new();
        assert_eq!(
            select_bound_for_account(
                &connected,
                &account,
                |scope| {
                    asked.push(scope);
                    true
                },
                true,
            ),
            selected(
                "primary",
                CandidateScope::Primary,
                vec![
                    skip(secondary(0), SkipReason::AmbiguousGroups),
                    skip(secondary(2), SkipReason::AmbiguousGroups),
                    skip(secondary(1), last_reason),
                ],
            )
        );
        assert_eq!(asked, vec![CandidateScope::Primary]);
    }
}

#[test]
fn ineligible_split_primary_falls_to_ordinary_once_and_never_checks_lower_eligibility() {
    let primary = CompletePairKey::Split(split());
    let mut later = split();
    later.rgb.ports = vec![10];
    let later = CompletePairKey::Split(later);
    let ordinary = ordinary_key_absent();
    let account = account(Some(primary.clone()), &[later.clone(), ordinary.clone()]);
    let connected = [
        cam("later", later, true, true),
        cam("ordinary", ordinary, true, true),
        cam("primary", primary, true, true),
    ];
    let mut asked = Vec::new();
    let outcome = select_bound_for_account(
        &connected,
        &account,
        |scope| {
            asked.push(scope);
            scope != CandidateScope::Primary
        },
        false,
    );
    assert_eq!(
        outcome,
        selected(
            "ordinary",
            secondary(1),
            vec![skip(CandidateScope::Primary, SkipReason::NotEligible)],
        )
    );
    assert_eq!(asked, vec![CandidateScope::Primary, secondary(1)]);
}

#[test]
fn complete_split_primary_uses_unreadable_refusal_without_legacy_fallback() {
    let account = AccountCameras {
        secondary_unreadable: true,
        ..account(Some(CompletePairKey::Split(split())), &[])
    };
    assert_eq!(
        select(&[], &account),
        refused(RefusalCause::SecondaryUnreadable, vec![])
    );
}

#[test]
fn legacy_fallback_never_selects_an_unbound_split_pair_but_complete_groups_can_rank() {
    let split = CompletePairKey::Split(split());
    let connected = [cam("split", split.clone(), true, true)];
    for primary in [
        None,
        Some(GroupPair::Ordinary {
            rgb: Some("rgb".into()),
            ir: None,
        }),
        Some(GroupPair::Ordinary {
            rgb: None,
            ir: Some("ir".into()),
        }),
        Some(GroupPair::Ordinary {
            rgb: Some(String::new()),
            ir: Some("ir".into()),
        }),
    ] {
        let mut account = AccountCameras {
            primary,
            secondary_active: true,
            ..AccountCameras::default()
        };
        let mut asked = Vec::new();
        assert_eq!(
            select_bound_for_account(
                &connected,
                &account,
                |scope| {
                    asked.push(scope);
                    true
                },
                false,
            ),
            SelectionOutcome::NotApplicable { skipped: vec![] }
        );
        assert!(asked.is_empty());
        // This is an enrolled complete secondary, not a standing-pair fallback.
        account.groups.push(split.clone().into());
        assert_eq!(
            select(&connected, &account),
            selected("split", secondary(0), vec![])
        );
        assert_eq!(
            select_bound_for_account(&connected, &account, |_| false, false),
            SelectionOutcome::NotApplicable {
                skipped: vec![skip(secondary(0), SkipReason::NotEligible)],
            }
        );
        account.secondary_active = false;
        assert_eq!(
            select(&connected, &account),
            SelectionOutcome::NotApplicable {
                skipped: vec![skip(secondary(0), SkipReason::SecondaryInactive)],
            }
        );
    }
}
