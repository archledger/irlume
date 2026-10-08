// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Account-scoped selection from one primary and secondary read snapshot.

use crate::request_preparation::{PreparedSelection, SplitChoice, SplitTrustEntry};
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

/// A class-aware account choice (ADR-0032 Step 5, plan C4). `Split` exists
/// only while the camera activation predicate admits Authentication, which
/// production never does; `ConnectedPair` stays one physical camera.
pub(super) enum ClassifiedChoice {
    Legacy(PrimarySnapshot),
    Ordinary {
        enrollment: irlume_core::storage::Enrollment,
        pair: irlume_camera::ConnectedPair,
        scope: crate::ir_assessment::IrOnlyScope,
    },
    Split {
        enrollment: irlume_core::storage::Enrollment,
        split: Box<SplitChoice>,
        scope: crate::ir_assessment::IrOnlyScope,
    },
}

/// How split candidates take part in one ranking.
enum SplitRouting<'a> {
    /// The closed boundary: a split primary binding refuses before any
    /// secondary load, and a ranked split candidate refuses without rerank.
    Closed,
    /// Authentication is admitted: a ranked split candidate becomes a choice
    /// built from the retained snapshot. A pending pin ranks only its key.
    Admitted {
        selection: &'a PreparedSelection,
        pin: Option<&'a irlume_common::split_key::SplitPairKey>,
    },
}

impl SplitRouting<'_> {
    fn pin(&self) -> Option<&irlume_common::split_key::SplitPairKey> {
        match self {
            Self::Closed => None,
            Self::Admitted { pin, .. } => *pin,
        }
    }
}

/// The class-aware account choice over one prepared request (plan C4, C7).
///
/// While the camera activation predicate does not admit Authentication, a
/// split candidate keeps the closed refusal, before any secondary load,
/// and so does a request that does not route accounts: a proven ordinary
/// override or an operation-scoped enrollment choice never routes a split.
/// Once admitted, a ranked split candidate becomes a [`SplitChoice`] built
/// only from the request's retained snapshot, and a pending pin ranks only
/// its own key: an unenrolled or absent pin denies, with no legacy or
/// standing fallback. Nothing is reranked after a refusal.
pub(super) fn select_account_classified(
    user: &str,
    primary: PrimarySnapshot,
    selection: &PreparedSelection,
    eligible: impl Fn(&irlume_core::storage::Enrollment) -> bool,
    keys: &mut dyn TemplateKeySource,
    read_only: bool,
) -> Result<ClassifiedChoice, Outcome> {
    let pin = selection.pending_pin();
    let routing = if !selection.routes_accounts() {
        SplitRouting::Closed
    } else if SplitTrustEntry::Authentication.admitted() {
        SplitRouting::Admitted { selection, pin }
    } else if pin.is_some() {
        // A pin outlived its admission: nothing routes.
        return Err(closed_split());
    } else {
        SplitRouting::Closed
    };
    classify(
        user,
        primary,
        selection.view(),
        &routing,
        eligible,
        keys,
        read_only,
    )
}

fn classify(
    user: &str,
    primary: PrimarySnapshot,
    view: &irlume_camera::ResolvedConnectedPairs,
    routing: &SplitRouting<'_>,
    eligible: impl Fn(&irlume_core::storage::Enrollment) -> bool,
    keys: &mut dyn TemplateKeySource,
    read_only: bool,
) -> Result<ClassifiedChoice, Outcome> {
    if let Err(reason) = legacy_eye_policy(&primary.enrollment) {
        return Err(Outcome::deny(OutcomeKind::SetupUnavailable, reason));
    }
    // Preserve the closed primary credential boundary. A split credential is
    // never ordinary input, and this request reached the ordinary path, so the
    // refusal names that limitation rather than the activation predicate, which
    // is not what is being refused here.
    if matches!(routing, SplitRouting::Closed)
        && matches!(
            primary.enrollment.camera_binding,
            Some(irlume_core::storage::CameraBinding::Split(_))
        )
    {
        return Err(ordinary_path_refuses_split());
    }
    let pin = routing.pin();
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
    // A pinned split ranks only its own key: no ordinary candidate.
    let ordinary = if pin.is_some() {
        &[][..]
    } else {
        view.ordinary.pairs.as_slice()
    };
    for (index, pair) in ordinary.iter().enumerate() {
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
            if pin.is_some_and(|pin| *pin != key) {
                continue;
            }
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
        // A pinned split has no legacy or standing fallback.
        SelectionOutcome::NotApplicable { .. } if pin.is_some() => {
            return Err(Outcome::deny_because(
                OutcomeKind::SetupUnavailable,
                OutcomeCause::NotEnrolledOnThisCamera,
                "the selected split camera pair is not enrolled for this account; use your password",
            ))
        }
        SelectionOutcome::NotApplicable { .. } => return Ok(ClassifiedChoice::Legacy(primary)),
        SelectionOutcome::Refused { cause, .. } => {
            return Err(Outcome::deny_because(
                OutcomeKind::SetupUnavailable,
                OutcomeCause::NotEnrolledOnThisCamera,
                format!("no eligible enrolled camera is connected ({cause:?}); use your password"),
            ))
        }
        SelectionOutcome::Selected(selected) => selected,
    };
    let chosen = match selected.key {
        Handle::Ordinary(index) => Chosen::Ordinary(ordinary[index].clone()),
        Handle::Split(index) => match routing {
            SplitRouting::Closed => {
                let _ = &view.split_pairs[index];
                return Err(closed_split());
            }
            SplitRouting::Admitted { selection, .. } => Chosen::Split(Box::new(
                selection.split_choice(index).map_err(unavailable)?,
            )),
        },
    };
    let mut bound = None;
    let scope = match selected.scope {
        CandidateScope::Primary => {
            if matches!(chosen, Chosen::Split(_)) {
                bound = primary
                    .enrollment
                    .camera_binding
                    .as_ref()
                    .and_then(irlume_core::storage::CameraBinding::complete_key);
            }
            crate::ir_assessment::IrOnlyScope::Primary {
                path: multi_camera::primary_enrollment_path(user),
                digest: irlume_common::sha256_hex(&primary.bytes),
            }
        }
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
            bound = Some(key);
            crate::ir_assessment::IrOnlyScope::Secondary(Box::new(context))
        }
    };
    // The ranker matched the exact complete key; refuse any disagreement
    // between the split choice and the binding it routes to.
    if let Chosen::Split(split) = &chosen {
        if bound.as_ref()
            != Some(&irlume_common::binding_key::CompletePairKey::Split(
                split.key().clone(),
            ))
        {
            return Err(unavailable("selected split binding changed"));
        }
    }
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
    Ok(match chosen {
        Chosen::Ordinary(pair) => ClassifiedChoice::Ordinary {
            enrollment,
            pair,
            scope,
        },
        Chosen::Split(split) => ClassifiedChoice::Split {
            enrollment,
            split,
            scope,
        },
    })
}

enum Chosen {
    Ordinary(irlume_camera::ConnectedPair),
    Split(Box<SplitChoice>),
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

/// An ordinary request against a split-bound account: the ordinary path never
/// opens a split camera pair. Kept separate from [`closed_split`], which is the
/// genuine closed-predicate refusal for a split-specific request whose
/// admission was withdrawn.
fn ordinary_path_refuses_split() -> Outcome {
    Outcome::deny_because(
        OutcomeKind::OtherDeny,
        OutcomeCause::NotEnrolledOnThisCamera,
        crate::request_preparation::ORDINARY_PATH_SPLIT_REFUSAL,
    )
}
