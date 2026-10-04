// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Account-scoped selection from one primary and secondary read snapshot.

use crate::{legacy_eye_policy, Outcome, OutcomeCause, OutcomeKind};
use irlume_core::{
    multi_camera::{
        self,
        coordinator::{SecondaryAuthContext, StrictPinStores},
        selection::{
            AccountCameras, BoundCandidatePair, CandidateScope, SecondaryFacts, SelectionOutcome,
        },
        views::CameraScopedViews,
    },
    storage::PrimarySnapshot,
    template_key::TemplateKeySource,
};

#[derive(Clone)]
enum Handle {
    Ordinary(usize),
    Split(usize),
}

pub(super) enum AccountChoice {
    Legacy(PrimarySnapshot),
    Selected {
        enrollment: irlume_core::storage::Enrollment,
        pair: irlume_camera::ConnectedPair,
        scope: crate::ir_assessment::IrOnlyScope,
    },
}

pub(super) fn select_account(
    user: &str,
    primary: PrimarySnapshot,
    view: &irlume_camera::ResolvedConnectedPairs,
    eligible: impl Fn(&irlume_core::storage::Enrollment) -> bool,
    keys: &mut dyn TemplateKeySource,
    read_only: bool,
) -> Result<AccountChoice, Outcome> {
    if let Err(reason) = legacy_eye_policy(&primary.enrollment) {
        return Err(Outcome::deny(OutcomeKind::SetupUnavailable, reason));
    }
    // Preserve the closed primary credential boundary until split activation.
    if matches!(
        primary.enrollment.camera_binding,
        Some(irlume_core::storage::CameraBinding::Split(_))
    ) {
        return Err(closed_split());
    }
    let secondary_path = multi_camera::secondary_store_path(user);
    let secondary = if read_only {
        // A readiness query cannot recover-forward a pending journal.
        if multi_camera::commit::intent_path_for(&secondary_path).exists() {
            Err(())
        } else {
            multi_camera::load_secondary_with_source(&secondary_path, keys).map_err(|_| ())
        }
    } else {
        multi_camera::commit::resolve_commit(&secondary_path)
            .map_err(|_| ())
            .and_then(|_| {
                multi_camera::load_secondary_with_source(&secondary_path, keys).map_err(|_| ())
            })
    };
    let facts = match &secondary {
        Ok(Some(store)) => {
            SecondaryFacts::Loaded(store, store.activation_against(Some(&primary.bytes)))
        }
        Ok(None) => SecondaryFacts::Absent,
        Err(()) => SecondaryFacts::Unreadable,
    };
    let account =
        AccountCameras::from_stores(user, primary.enrollment.camera_binding.as_ref(), facts);
    let loaded = secondary
        .as_ref()
        .ok()
        .and_then(|store| store.as_ref())
        .filter(|store| store.owner == user);
    let views = CameraScopedViews::compose(&primary.enrollment, &primary.bytes, loaded).ok();
    let mut candidates = Vec::new();
    for (index, pair) in view.ordinary.pairs.iter().enumerate() {
        candidates.push(BoundCandidatePair {
            key: Handle::Ordinary(index),
            pair: irlume_common::binding_key::CompletePairKey::Ordinary {
                rgb: pair.identity.clone(),
                ir: pair.identity.clone(),
            },
            rgb_fixed: pair.fixed,
            ir_fixed: pair.fixed,
        });
    }
    for (index, pair) in view.split_pairs.iter().enumerate() {
        if let Ok(key) = pair.pair_key() {
            candidates.push(BoundCandidatePair {
                key: Handle::Split(index),
                pair: irlume_common::binding_key::CompletePairKey::Split(key),
                rgb_fixed: pair.rgb.fixed,
                ir_fixed: pair.ir.fixed,
            });
        }
    }
    let selection = multi_camera::selection::select_bound_for_account(
        &candidates,
        &account,
        |scope| match scope {
            CandidateScope::Primary => eligible(&primary.enrollment),
            CandidateScope::Secondary { index } => loaded
                .and_then(|store| store.groups.get(index))
                .and_then(|group| {
                    views
                        .as_ref()
                        .and_then(|views| views.secondary_view(group.id.as_str()))
                })
                .is_some_and(|view| eligible(&view.matching_enrollment(user))),
        },
        irlume_common::PreferencesState::observe()
            .forbid_external_cameras
            .unwrap_or(true),
    );
    let selected = match selection {
        SelectionOutcome::NotApplicable { .. } => return Ok(AccountChoice::Legacy(primary)),
        SelectionOutcome::Refused { cause, .. } => {
            return Err(Outcome::deny_because(
                OutcomeKind::SetupUnavailable,
                OutcomeCause::NotEnrolledOnThisCamera,
                format!("no eligible enrolled camera is connected ({cause:?}); use your password"),
            ))
        }
        SelectionOutcome::Selected(selected) => selected,
    };
    let pair = match selected.key {
        Handle::Ordinary(index) => view.ordinary.pairs[index].clone(),
        Handle::Split(index) => {
            let _ = &view.split_pairs[index];
            return Err(closed_split());
        }
    };
    let scope = match selected.scope {
        CandidateScope::Primary => crate::ir_assessment::IrOnlyScope::Primary {
            path: multi_camera::primary_enrollment_path(user),
            digest: irlume_common::sha256_hex(&primary.bytes),
        },
        CandidateScope::Secondary { index } => {
            let store =
                loaded.ok_or_else(|| unavailable("selected secondary snapshot is unavailable"))?;
            let group = store
                .groups
                .get(index)
                .ok_or_else(|| unavailable("selected group snapshot changed"))?;
            let key = group
                .pair
                .complete_key()
                .ok_or_else(|| unavailable("selected binding is incomplete"))?;
            let primary_path = multi_camera::primary_enrollment_path(user);
            let context = SecondaryAuthContext::pin_key_from_loaded(
                StrictPinStores {
                    user,
                    secondary_path: &secondary_path,
                    primary_path: &primary_path,
                },
                &primary.enrollment,
                &primary.bytes,
                &key,
                store,
            )
            .map_err(|_| unavailable("selected secondary snapshot cannot pin"))?;
            if context.store_index() != index
                || context.pinned().secondary_generation != store.generation
            {
                return Err(unavailable("selected secondary ordinal/generation changed"));
            }
            crate::ir_assessment::IrOnlyScope::Secondary(Box::new(context))
        }
    };
    if !read_only {
        if let Some(refusal) = scope.boundary_refusal(keys) {
            return Err(refusal);
        }
    }
    let enrollment = match &scope {
        crate::ir_assessment::IrOnlyScope::Primary { .. } => primary.enrollment,
        crate::ir_assessment::IrOnlyScope::Secondary(context) => {
            context.group_view().matching_enrollment(user)
        }
    };
    Ok(AccountChoice::Selected {
        enrollment,
        pair,
        scope,
    })
}

fn unavailable(reason: &str) -> Outcome {
    Outcome::deny(OutcomeKind::SetupUnavailable, reason)
}
fn closed_split() -> Outcome {
    Outcome::deny_because(
        OutcomeKind::OtherDeny,
        OutcomeCause::NotEnrolledOnThisCamera,
        "split enrollment and authentication are not enabled",
    )
}
