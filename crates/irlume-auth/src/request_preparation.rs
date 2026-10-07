// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Coherent request selection and the closed split activation boundary.

use crate::Engine;
use irlume_common::{
    config::CameraSelectionObservation,
    split_publish::{CameraSelectionSnapshot, SplitReadState},
    Error,
};
use std::ops::{Deref, DerefMut};

enum PreparedPair {
    Ordinary(irlume_camera::ConnectedPair),
    Split(Box<PreparedSplit>),
}

/// The split trust entry a retained split selection was prepared for.
///
/// A split selection is usable for trust work only while the running Engine
/// entry has declared this same entry and the camera activation predicate
/// admits its operation kind. Production keeps that predicate closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SplitTrustEntry {
    /// Primary enrollment, reset or secondary add-group on a split pair.
    Enrollment,
    /// Account-routed authentication on a split pair.
    Authentication,
}

impl SplitTrustEntry {
    /// The one camera operation kind this entry may lease.
    pub(crate) const fn kind(self) -> irlume_camera::lease::CameraOperationKind {
        match self {
            Self::Enrollment => irlume_camera::lease::CameraOperationKind::Enrollment,
            Self::Authentication => irlume_camera::lease::CameraOperationKind::Authentication,
        }
    }

    /// The camera activation predicate for this entry's kind, read now.
    pub(crate) fn admitted(self) -> bool {
        irlume_camera::lease::split_trust_admitted(self.kind())
    }
}

/// Which preparation observes the camera selection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectionRoute {
    /// Every request: a saved selected split keeps the closed refusal.
    Generic,
    /// The account-routed authentication call: while the activation
    /// predicate admits Authentication, a saved selected split is retained
    /// as a pending pin that only this call may route.
    Authentication,
}

/// One class-aware split account choice (ADR-0032 Step 5, plan D7).
///
/// Built only from the request's retained snapshot: the resolved pair
/// exactly as the passive view listed it, its durable key, its lease
/// request and the publication the retained snapshot referenced. Nothing
/// is reread to build it, and it authorizes nothing until
/// `Engine::select_account_split_camera` installs it.
pub(super) struct SplitChoice {
    pair: irlume_camera::SplitPair,
    key: irlume_common::split_key::SplitPairKey,
    expected: irlume_camera::lease::SplitLeaseRequest,
    authorization: irlume_common::split_publish::Published,
}

impl SplitChoice {
    /// The resolved pair, as the retained view listed it.
    #[cfg(test)]
    pub(super) fn pair(&self) -> &irlume_camera::SplitPair {
        &self.pair
    }

    /// The pair's durable role-labelled key.
    pub(super) fn key(&self) -> &irlume_common::split_key::SplitPairKey {
        &self.key
    }

    /// The two incarnations a split Authentication lease must hold.
    #[cfg(test)]
    pub(super) fn lease_request(&self) -> &irlume_camera::lease::SplitLeaseRequest {
        &self.expected
    }
}

struct PreparedSplit {
    pair: irlume_camera::SplitPair,
    key: irlume_common::split_key::SplitPairKey,
    expected: irlume_camera::lease::SplitLeaseRequest,
    displayed: irlume_common::split_wire::SplitMutationGuard,
    authorization: irlume_common::split_publish::Published,
    entry: SplitTrustEntry,
}

pub(crate) struct PreparedSelection {
    snapshot: CameraSelectionSnapshot,
    view: irlume_camera::ResolvedConnectedPairs,
    pair: Option<PreparedPair>,
    rgb: String,
    ir: String,
    ir_available: bool,
    automatic: bool,
    retain_standing: bool,
    /// Any call in this request offered a split install, accepted or
    /// refused: account routing then never routes or leases an ordinary or
    /// standing pair for it (plan D8: no fallback, no rerank).
    split_routing_attempted: bool,
    enrollment_choice: bool,
    active_entry: Option<SplitTrustEntry>,
    /// A saved selected split awaiting account routing. Only the
    /// authentication call's preparation retains one; that call alone
    /// declares the Authentication entry over it, for its own duration.
    pin: Option<irlume_common::split_key::SplitPairKey>,
}

impl PreparedSelection {
    /// The request observed automatic ranking: no ordinary override and a
    /// Fresh or Automatic selection. This raw observation can be true under
    /// a pending pin, because split keys never change the selection: a
    /// split-keys-only cameras.conf with a saved selected split reads Fresh.
    /// It never sees the pin, so routing that may run in an authentication
    /// scope uses [`Self::routes_accounts`] and [`Self::pending_pin`], and an
    /// ordinary-only consumer of this answer must not run inside a pending
    /// pin scope. Production never retains a pin.
    pub(super) fn automatic(&self) -> bool {
        self.automatic
    }
    /// Classified account routing applies: an automatic selection, or a
    /// pending pinned split that only classified routing may install.
    pub(super) fn routes_accounts(&self) -> bool {
        self.automatic || self.pin.is_some()
    }
    /// The saved selected split this authentication request routes to,
    /// until account routing installs it.
    pub(super) fn pending_pin(&self) -> Option<&irlume_common::split_key::SplitPairKey> {
        self.pin.as_ref()
    }
    pub(super) fn enrollment_choice(&self) -> bool {
        self.enrollment_choice
    }
    pub(super) fn has_account_candidates(&self) -> bool {
        self.view.ordinary.state == irlume_common::live_camera::CameraInventoryState::Current
            && (!self.view.ordinary.pairs.is_empty() || !self.view.split_pairs.is_empty())
    }
    pub(super) fn view(&self) -> &irlume_camera::ResolvedConnectedPairs {
        &self.view
    }
    pub(super) fn expected_lease(&self) -> Option<irlume_camera::lease::OrdinaryLeaseRequest> {
        let Some(PreparedPair::Ordinary(pair)) = &self.pair else {
            return None;
        };
        Some(irlume_camera::lease::OrdinaryLeaseRequest {
            supervisor_id: self.view.ordinary.supervisor_id.clone()?,
            pair: pair.clone(),
        })
    }
    fn select_ordinary(&mut self, pair: irlume_camera::ConnectedPair, available: bool) {
        self.rgb = pair.rgb.clone();
        self.ir = pair.ir.clone();
        self.ir_available = available;
        self.pair = Some(PreparedPair::Ordinary(pair));
        self.retain_standing = true;
        // A declared split entry never outlives the split it was declared on.
        self.active_entry = None;
    }
    pub(super) fn matches_devices(&self, rgb: &str, ir: &str, ir_available: bool) -> bool {
        self.rgb == rgb && self.ir == ir && self.ir_available == ir_available
    }

    pub(super) fn ordinary_is_current(&self) -> bool {
        let Some(PreparedPair::Ordinary(expected)) = &self.pair else {
            // Standing legacy ordinary selection has no new passive proof.
            // Its existing lease, physical pin and binding checks still apply.
            return true;
        };
        self.pair_is_current(expected)
    }

    pub(super) fn pair_is_current(&self, expected: &irlume_camera::ConnectedPair) -> bool {
        let current = irlume_camera::connected_pairs_with_split(&[]).ordinary;
        current.state == irlume_common::live_camera::CameraInventoryState::Current
            && current.supervisor_id == self.view.ordinary.supervisor_id
            && current
                .pairs
                .iter()
                .filter(|pair| *pair == expected)
                .count()
                == 1
    }

    fn validate_devices(&self, engine: &Engine) -> irlume_common::Result<()> {
        if !self.matches_devices(&engine.rgb_dev, &engine.ir_dev, engine.ir_available) {
            return Err(Error::Policy(
                "camera endpoints or availability changed during prepared request".into(),
            ));
        }
        if !self.ordinary_is_current() {
            return Err(Error::Policy(
                "prepared ordinary camera pair is no longer Current".into(),
            ));
        }
        Ok(())
    }

    fn split(&self) -> Option<&PreparedSplit> {
        match &self.pair {
            Some(PreparedPair::Split(split)) => Some(split),
            _ => None,
        }
    }

    /// The running Engine entry declared this split's own entry and the
    /// activation predicate admits its kind at this moment.
    fn split_entry_active(&self, split: &PreparedSplit) -> bool {
        self.active_entry == Some(split.entry) && split.entry.admitted()
    }

    /// A retained split that no declared, admitted entry may use right now.
    /// A pending pin is usable only while the authentication call that
    /// holds it has declared the Authentication entry and the predicate
    /// still admits Authentication.
    fn split_closed(&self) -> bool {
        if self.pin.is_some() {
            return !(self.active_entry == Some(SplitTrustEntry::Authentication)
                && SplitTrustEntry::Authentication.admitted());
        }
        self.split()
            .is_some_and(|split| !self.split_entry_active(split))
    }

    /// A retained split, installed or still pending, never takes an
    /// ordinary, legacy, single-side or Diagnostics path, and neither does a
    /// request whose offered split install refused before installing.
    fn retains_split(&self) -> bool {
        self.split().is_some() || self.pin.is_some() || self.split_routing_attempted
    }

    /// A pending pin or a routed Authentication split. Its entry admits
    /// only the authentication call that routes it, never a nested entry.
    fn authentication_routed(&self) -> bool {
        self.pin.is_some()
            || self
                .split()
                .is_some_and(|split| split.entry == SplitTrustEntry::Authentication)
    }

    /// The pending pin resolves to exactly one authorized Current pair.
    fn pin_connected(&self) -> bool {
        let Some(pin) = &self.pin else {
            return false;
        };
        self.view.ordinary.state == irlume_common::live_camera::CameraInventoryState::Current
            && self
                .view
                .split_pairs
                .iter()
                .filter(|pair| pair.pair_key().is_ok_and(|key| key == *pin))
                .count()
                == 1
    }

    /// The split choice for `view.split_pairs[index]`, from retained data
    /// only: the pair, its key, its lease request and the publication the
    /// retained snapshot referenced. A pending pin admits only its own key.
    pub(super) fn split_choice(&self, index: usize) -> Result<SplitChoice, &'static str> {
        let pair = self
            .view
            .split_pairs
            .get(index)
            .ok_or("selected split pair is not in the retained snapshot")?;
        let key = pair
            .pair_key()
            .map_err(|_| "selected split pair has no complete key")?;
        if self.pin.as_ref().is_some_and(|pin| *pin != key) {
            return Err("selected split pair is not the pinned pair");
        }
        let irlume_common::config::SplitConfObservation::Reference {
            generation, digest, ..
        } = &self.snapshot.observation().split
        else {
            return Err("split authorization has no retained publication");
        };
        let authorization = irlume_common::split_publish::Published {
            generation: *generation,
            digest: digest.clone(),
        };
        if verified_split_records(&self.snapshot, &authorization).is_err() {
            return Err("split authorization has no verified retained publication");
        }
        Ok(SplitChoice {
            expected: pair.lease_request(),
            pair: pair.clone(),
            key,
            authorization,
        })
    }

    /// Whether this request may install `choice`: a pin still declared and
    /// admitted or an unrouted automatic selection (never an ordinary
    /// override or an enrollment choice), the pin's own key, a pair the
    /// retained view lists exactly once, and the retained publication. All
    /// checks are pure.
    ///
    /// Account routing runs at most once per request (plan D8: no fallback,
    /// no rerank). A request is routed once it holds an installed split, or
    /// once any call in it routed an ordinary pair, accepted or refused at
    /// that pair's validation. A standing ordinary pair the request only
    /// retained is not a route. The other direction is
    /// [`Self::retains_split`]: once a split install was offered, no
    /// ordinary pair routes. The same split may install again once its
    /// pure refusal clears; that is a retry, not a rerank.
    fn admits_split_choice(&self, choice: &SplitChoice) -> irlume_common::Result<()> {
        // A pin whose call ended, or whose admission ended, stays closed.
        if self.split_closed() {
            return Err(split_activation_refusal());
        }
        // Only an ordinary account route sets `retain_standing`
        // (`select_ordinary`); a split install clears it with its own pair.
        if !self.routes_accounts() || self.split().is_some() || self.retain_standing {
            return Err(Error::Policy(
                "split account routing needs an unrouted automatic or pinned request".into(),
            ));
        }
        if self.pin.as_ref().is_some_and(|pin| *pin != choice.key) {
            return Err(Error::Policy(
                "split account choice is not the pinned pair".into(),
            ));
        }
        if self
            .view
            .split_pairs
            .iter()
            .filter(|pair| **pair == choice.pair)
            .count()
            != 1
            || choice.pair.lease_request() != choice.expected
            || choice.pair.pair_key().ok().as_ref() != Some(&choice.key)
        {
            return Err(Error::Policy(
                "split account choice is not from this request's retained snapshot".into(),
            ));
        }
        verified_split_records(&self.snapshot, &choice.authorization).map(|_| ())
    }

    /// Install a routed split for the Authentication entry (plan C5, D8).
    fn install_split(&mut self, choice: SplitChoice) {
        let SplitChoice {
            pair,
            key,
            expected,
            authorization,
        } = choice;
        self.rgb = pair.rgb.path.clone();
        self.ir = pair.ir.path.clone();
        self.ir_available = true;
        // Account routing has no daemon-displayed guard. It is synthesized
        // from the lease request, so split_guard_matches is tautological for
        // a routed split; the passive re-resolution below is the real check.
        let displayed = displayed_guard(&expected);
        self.pair = Some(PreparedPair::Split(Box::new(PreparedSplit {
            pair,
            key,
            expected,
            displayed,
            authorization,
            entry: SplitTrustEntry::Authentication,
        })));
        self.pin = None;
        // No standing split choice: the scope restores the standing devices.
        self.retain_standing = false;
        self.active_entry = Some(SplitTrustEntry::Authentication);
    }

    /// Lock-free machine authority over a retained split (plan D10): a fresh
    /// coherent read must still reference the retained publication and
    /// verify the same ordered records and selection, and both sides must
    /// still be allowed. It takes no configuration lock and creates no lock
    /// file.
    fn split_config_authority(&self, split: &PreparedSplit) -> irlume_common::Result<()> {
        let current = irlume_common::split_publish::read_camera_selection();
        verified_split_records(&current, &split.authorization)?;
        if current.split() != self.snapshot.split() {
            return Err(Error::Policy(
                "split authorization changed during the prepared operation".into(),
            ));
        }
        split_external_policy(&split.pair)
    }

    /// The passive check of a routed Authentication split, without the
    /// cameras.conf writer lock that only publication needs: the retained
    /// guard, a passive canonical re-resolution of the retained records,
    /// then lock-free machine authority. Lease continuity after acquisition
    /// stays with the split capture branch.
    fn validate_split_authentication(&self, split: &PreparedSplit) -> irlume_common::Result<()> {
        if !split_guard_matches(&split.displayed, &split.pair) {
            return Err(Error::Policy(
                "split proof does not retain the original displayed guard".into(),
            ));
        }
        let SplitReadState::Valid { records, .. } = self.snapshot.split() else {
            return Err(Error::Policy(
                "split publication has no verified records".into(),
            ));
        };
        let current = irlume_camera::connected_pairs_with_split(records);
        if current
            .split_pairs
            .iter()
            .filter(|pair| **pair == split.pair)
            .count()
            != 1
        {
            return Err(Error::Policy(
                "prepared split camera pair is no longer Current".into(),
            ));
        }
        self.split_config_authority(split)
    }

    /// A pending pin stays valid only while a fresh lock-free read keeps the
    /// same coherent split state, selection included.
    fn validate_pin(&self) -> irlume_common::Result<()> {
        let current = irlume_common::split_publish::read_camera_selection();
        if matches!(
            current.observation().selection,
            CameraSelectionObservation::Malformed { .. }
                | CameraSelectionObservation::Unreadable { .. }
        ) || current.split() != self.snapshot.split()
        {
            return Err(Error::Policy(
                "split authorization changed during the prepared operation".into(),
            ));
        }
        Ok(())
    }

    /// The only acquisition a retained split selection makes: one split trust
    /// lease over both original sides, RGB then IR, of the declared entry's
    /// own kind. Every other request refuses here in AUTH, before the camera
    /// boundary records a lease attempt, and never falls back to an ordinary,
    /// legacy or single-side lease. Diagnostics is refused too, so neither a
    /// probe nor a capture-mode or qualification read gets a split half.
    fn acquire_split_operation(
        &self,
        endpoints: &[&str],
        kind: irlume_camera::lease::CameraOperationKind,
        timeout: std::time::Duration,
    ) -> Result<irlume_camera::lease::CameraOperationSession, irlume_camera::lease::CameraLeaseError>
    {
        let Some(split) = self.split() else {
            return Err(irlume_camera::lease::CameraLeaseError::SplitActivationDisabled);
        };
        if !self.split_entry_active(split) || kind != split.entry.kind() {
            return Err(irlume_camera::lease::CameraLeaseError::SplitActivationDisabled);
        }
        let both = [
            split.expected.rgb.endpoint.as_str(),
            split.expected.ir.endpoint.as_str(),
        ];
        if endpoints != both.as_slice() {
            return Err(irlume_camera::lease::CameraLeaseError::InvalidEndpoint(
                "a split camera operation leases both original sides, RGB then IR".into(),
            ));
        }
        irlume_camera::lease::acquire_split_camera_operation(&split.expected, kind, timeout)
    }

    fn validate_passive(&self, engine: &Engine) -> irlume_common::Result<()> {
        self.validate_devices(engine)?;
        if self.pin.is_some() {
            self.validate_pin()?;
        }
        match self.split() {
            // Authentication never publishes: no cameras.conf lock (D10).
            Some(split) if split.entry == SplitTrustEntry::Authentication => {
                self.validate_split_authentication(split)?;
            }
            // Enrollment keeps its locked canonical resolution.
            Some(_) => self.with_split_publication(|| Ok(()))?,
            None => {}
        }
        Ok(())
    }

    fn with_split_publication<R>(
        &self,
        publish: impl FnOnce() -> irlume_common::Result<R>,
    ) -> irlume_common::Result<R> {
        let split = self
            .split()
            .ok_or_else(|| Error::Policy("split publication has no retained proof".into()))?;
        if !split_guard_matches(&split.displayed, &split.pair) {
            return Err(Error::Policy(
                "split proof does not retain the original displayed guard".into(),
            ));
        }
        let SplitReadState::Valid { records, .. } = self.snapshot.split() else {
            return Err(Error::Policy(
                "split publication has no verified records".into(),
            ));
        };
        irlume_camera::with_selected_split_camera_publication(&split.expected, records, || {
            let _config = irlume_common::config::lock_exclusive("cameras.conf")
                .map_err(|error| Error::Io(error.to_string()))?;
            let current = irlume_common::split_publish::read_camera_selection();
            verified_split_records(&current, &split.authorization)?;
            // The same immutable ordered collection must authorize the canonical
            // resolver that just admitted both original incarnations.
            if current.split() != self.snapshot.split() {
                return Err(Error::Policy(
                    "split authorization changed during the prepared operation".into(),
                ));
            }
            split_external_policy(&split.pair)?;
            // No authority recheck after the first write or recover-forward intent.
            publish()
        })
        .map_err(crate::lease_unavailable)?
    }

    pub(super) fn binding(&self) -> Option<irlume_core::multi_camera::GroupPair> {
        if let Some(split) = self.split() {
            return Some(irlume_core::multi_camera::GroupPair::Split(
                split.key.clone(),
            ));
        }
        if !matches!(
            self.snapshot.split(),
            SplitReadState::Absent | SplitReadState::Valid { .. }
        ) || self.view.ordinary.state
            != irlume_common::live_camera::CameraInventoryState::Current
        {
            return None;
        }
        match &self.pair {
            Some(PreparedPair::Ordinary(pair)) => {
                Some(irlume_core::multi_camera::GroupPair::Ordinary {
                    rgb: Some(pair.identity.clone()),
                    ir: Some(pair.identity.clone()),
                })
            }
            _ => None,
        }
    }

    pub(super) fn observe(rgb: &str, ir: &str, ir_available: bool) -> irlume_common::Result<Self> {
        Self::observe_choice(rgb, ir, ir_available, None, SelectionRoute::Generic)
    }

    fn observe_choice(
        rgb: &str,
        ir: &str,
        ir_available: bool,
        choice: Option<&irlume_common::live_camera::EnrollmentCameraChoice>,
        route: SelectionRoute,
    ) -> irlume_common::Result<Self> {
        let snapshot = irlume_common::split_publish::read_camera_selection();
        if matches!(
            snapshot.observation().selection,
            CameraSelectionObservation::Malformed { .. }
                | CameraSelectionObservation::Unreadable { .. }
        ) {
            return Err(Error::Policy(
                "camera selection is invalid or unreadable; use your password".into(),
            ));
        }
        let (records, selected) = match snapshot.split() {
            SplitReadState::Absent => (&[][..], None),
            SplitReadState::Valid {
                records, selected, ..
            } => (records.as_slice(), selected.as_ref()),
            SplitReadState::Unreadable
            | SplitReadState::Malformed
            | SplitReadState::MalformedGeneration { .. }
            | SplitReadState::UnresolvedSelection { .. }
            | SplitReadState::DigestMismatch { .. } => {
                return Err(Error::Policy(
                    "split camera selection cannot be verified; use your password".into(),
                ));
            }
        };
        let view = if let Some(choice) = choice {
            irlume_camera::enrollment_connected_pairs(choice, records)
                .map_err(|reason| Error::Policy(reason.into()))?
        } else {
            irlume_camera::connected_pairs_with_split(records)
        };
        let env = choice
            .map(|choice| (choice.rgb.clone(), choice.ir.clone()))
            .or_else(ordinary_environment_pair);
        let automatic = env.is_none()
            && matches!(
                snapshot.observation().selection,
                CameraSelectionObservation::Fresh | CameraSelectionObservation::Automatic { .. }
            );
        let pin = authentication_pin(route, selected, env.is_some(), choice.is_some());
        let (rgb, ir) = if pin.is_some() {
            // Retained for account routing only: no ordinary pair, no
            // standing fallback. Routing ranks only this key (plan C7).
            (rgb.to_owned(), ir.to_owned())
        } else if selected.is_some() || choice.is_some() {
            let (rgb, ir) = env.ok_or_else(|| {
                Error::Policy(
                    irlume_camera::lease::CameraLeaseError::SplitActivationDisabled.to_string(),
                )
            })?;
            let proven = ordinary_pair(&view, &rgb, &ir).ok_or_else(|| {
                Error::Policy(
                    "ordinary camera override is not a unique Current ordinary pair".into(),
                )
            })?;
            if irlume_common::PreferencesState::observe()
                .forbid_external_cameras
                .unwrap_or(true)
                && !proven.fixed
            {
                return Err(Error::Policy(
                    "ordinary camera override is external and forbidden".into(),
                ));
            }
            (rgb, ir)
        } else {
            // Preserve the standing ordinary selection chosen by the daemon or
            // direct caller. Automatic account ranking is a later preparation
            // stage; authorization records alone do not choose a split pair.
            (rgb.to_owned(), ir.to_owned())
        };
        let ordinary = if pin.is_some() {
            None
        } else {
            ordinary_pair(&view, &rgb, &ir).cloned()
        };
        Ok(Self {
            snapshot,
            view,
            pair: ordinary.map(PreparedPair::Ordinary),
            rgb,
            ir,
            ir_available,
            automatic,
            retain_standing: false,
            split_routing_attempted: false,
            enrollment_choice: choice.is_some(),
            // Retaining a pin declares nothing: only the authentication call
            // declares its entry, for its own scope.
            active_entry: None,
            pin,
        })
    }
}

/// The pending pin of an authentication preparation: a saved selected split
/// with no ordinary override and no enrollment choice, while the activation
/// predicate admits Authentication. Every other case keeps the closed path.
fn authentication_pin(
    route: SelectionRoute,
    selected: Option<&irlume_common::split_key::SplitPairKey>,
    ordinary_override: bool,
    enrollment_choice: bool,
) -> Option<irlume_common::split_key::SplitPairKey> {
    if route != SelectionRoute::Authentication || ordinary_override || enrollment_choice {
        return None;
    }
    selected
        .filter(|_| SplitTrustEntry::Authentication.admitted())
        .cloned()
}

/// The guard a daemon would have displayed for `expected`.
fn displayed_guard(
    expected: &irlume_camera::lease::SplitLeaseRequest,
) -> irlume_common::split_wire::SplitMutationGuard {
    let side =
        |side: &irlume_camera::SplitSideExpectation| irlume_common::split_wire::SplitSideGuard {
            instance_id: side.instance_id.clone(),
            generation: side.generation,
            endpoint: side.endpoint.clone(),
        };
    irlume_common::split_wire::SplitMutationGuard {
        supervisor_id: expected.supervisor_id.clone(),
        revision: expected.revision,
        rgb: side(&expected.rgb),
        ir: side(&expected.ir),
    }
}

fn verified_split_records<'a>(
    snapshot: &'a CameraSelectionSnapshot,
    authorization: &irlume_common::split_publish::Published,
) -> irlume_common::Result<&'a [irlume_common::split_schema::AuthorizationRecord]> {
    if matches!(
        snapshot.observation().selection,
        CameraSelectionObservation::Malformed { .. }
            | CameraSelectionObservation::Unreadable { .. }
    ) {
        return Err(Error::Policy(
            "camera selection is invalid or unreadable; use your password".into(),
        ));
    }
    match (snapshot.split(), &snapshot.observation().split) {
        (
            SplitReadState::Valid {
                generation,
                records,
                ..
            },
            irlume_common::config::SplitConfObservation::Reference {
                generation: referenced,
                digest,
                ..
            },
        ) if *generation != 0
            && *generation == authorization.generation
            && generation == referenced
            && digest == &authorization.digest =>
        {
            Ok(records)
        }
        _ => Err(Error::Policy(
            "split authorization is absent, invalid or changed; select it again".into(),
        )),
    }
}

fn split_guard_matches(
    guard: &irlume_common::split_wire::SplitMutationGuard,
    pair: &irlume_camera::SplitPair,
) -> bool {
    let expected = pair.lease_request();
    let same_side = |guard: &irlume_common::split_wire::SplitSideGuard,
                     side: &irlume_camera::SplitSideExpectation| {
        guard.instance_id == side.instance_id
            && guard.generation == side.generation
            && guard.endpoint == side.endpoint
    };
    guard.supervisor_id == expected.supervisor_id
        && guard.revision == expected.revision
        && same_side(&guard.rgb, &expected.rgb)
        && same_side(&guard.ir, &expected.ir)
}

fn split_external_policy(pair: &irlume_camera::SplitPair) -> irlume_common::Result<()> {
    let forbid = irlume_common::PreferencesState::observe()
        .forbid_external_cameras
        .unwrap_or(true)
        || std::env::var("IRLUME_CAMERA_REQUIRE_FIXED").is_ok_and(|value| value == "1");
    if forbid && (!pair.rgb.fixed || !pair.ir.fixed) {
        return Err(Error::Policy(
            "split camera choice has an external side and is forbidden".into(),
        ));
    }
    Ok(())
}

fn split_activation_refusal() -> Error {
    Error::Policy(irlume_camera::lease::CameraLeaseError::SplitActivationDisabled.to_string())
}

pub(crate) fn ordinary_environment_pair() -> Option<(String, String)> {
    let rgb = std::env::var("IRLUME_RGB_DEVICE").ok()?;
    let ir = std::env::var("IRLUME_IR_DEVICE").ok()?;
    (!rgb.trim().is_empty() && !ir.trim().is_empty()).then_some((rgb, ir))
}

fn ordinary_pair<'a>(
    view: &'a irlume_camera::ResolvedConnectedPairs,
    rgb: &str,
    ir: &str,
) -> Option<&'a irlume_camera::ConnectedPair> {
    if view.ordinary.state != irlume_common::live_camera::CameraInventoryState::Current {
        return None;
    }
    let canonical = |path: &str| {
        std::fs::canonicalize(path)
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
            .unwrap_or_else(|| path.into())
    };
    let (rgb, ir) = (canonical(rgb), canonical(ir));
    let mut matches = view
        .ordinary
        .pairs
        .iter()
        .filter(|pair| pair.rgb == rgb && pair.ir == ir);
    let pair = matches.next()?;
    matches.next().is_none().then_some(pair)
}

/// Retains one coherent selection across a daemon probe and nested Engine entry.
/// The outer scope restores devices and clears selection on every exit.
/// A nested scope ends the Authentication entry of the call it ran.
pub struct CameraRequestScope<'a> {
    engine: &'a mut Engine,
    previous: Option<(String, String, bool)>,
}

impl Deref for CameraRequestScope<'_> {
    type Target = Engine;
    fn deref(&self) -> &Engine {
        self.engine
    }
}
impl DerefMut for CameraRequestScope<'_> {
    fn deref_mut(&mut self) -> &mut Engine {
        self.engine
    }
}
impl Drop for CameraRequestScope<'_> {
    fn drop(&mut self) {
        if self.previous.is_none() {
            // A nested scope is one call inside the outer request, and an
            // Authentication entry never outlives it: the one it took over
            // from the outer pin, or the one account routing declared while
            // it ran, pinned or automatic. The outer pin or routed split then
            // stays closed for every later use, a second call included. No
            // nested scope opens over any other Authentication entry, and a
            // declared Enrollment entry belongs to the outer split entry.
            if let Some(selection) = self.engine.camera_selection.as_mut() {
                if selection.active_entry == Some(SplitTrustEntry::Authentication) {
                    selection.active_entry = None;
                }
            }
        }
        if let Some((rgb, ir, available)) = self.previous.take() {
            let keep = self
                .engine
                .camera_selection
                .as_ref()
                .is_some_and(|selection| {
                    selection.retain_standing
                        && selection.matches_devices(
                            &self.engine.rgb_dev,
                            &self.engine.ir_dev,
                            self.engine.ir_available,
                        )
                });
            self.engine.camera_selection = None;
            self.engine.primary_attempt = None;
            self.engine.secondary_attempt = None;
            if !keep {
                self.engine.rgb_dev = rgb;
                self.engine.ir_dev = ir;
                self.engine.ir_available = available;
            }
        }
    }
}

impl Engine {
    /// Prepare a whole operation-scoped split choice without enabling capture.
    ///
    /// # Errors
    /// Refuses unverified machine authorization or unavailable live split proof.
    pub fn prepare_split_enrollment_camera(
        &mut self,
        expected: &irlume_common::split_wire::SplitMutationGuard,
        authorization: &irlume_common::split_publish::Published,
    ) -> irlume_common::Result<CameraRequestScope<'_>> {
        expected
            .validate()
            .map_err(|reason| Error::Policy(reason.into()))?;
        if self.camera_selection.is_some() {
            return Err(Error::Policy(
                "enrollment choice cannot replace a prepared request".into(),
            ));
        }
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let records = verified_split_records(&snapshot, authorization)?;
        let view = irlume_camera::connected_pairs_with_split(records);
        let mut matches = view
            .split_pairs
            .iter()
            .filter(|pair| split_guard_matches(expected, pair));
        let pair = matches.next().cloned().ok_or_else(|| {
            Error::Policy("split choice is not a unique authorized Current pair".into())
        })?;
        if matches.next().is_some() {
            return Err(Error::Policy("split choice is ambiguous".into()));
        }
        split_external_policy(&pair)?;
        let key = pair
            .pair_key()
            .map_err(|reason| Error::Policy(reason.to_string()))?;
        let prepared = PreparedSelection {
            rgb: pair.rgb.path.clone(),
            ir: pair.ir.path.clone(),
            ir_available: !irlume_camera::ir_forced_off(),
            pair: Some(PreparedPair::Split(Box::new(PreparedSplit {
                expected: pair.lease_request(),
                pair,
                key,
                displayed: expected.clone(),
                authorization: authorization.clone(),
                entry: SplitTrustEntry::Enrollment,
            }))),
            snapshot,
            view,
            automatic: false,
            retain_standing: false,
            split_routing_attempted: false,
            enrollment_choice: true,
            active_entry: None,
            pin: None,
        };
        // Canonical resolution repeats under CURRENT inventory, then config.
        // It admits passive preparation only, never a trust-operation lease.
        prepared.with_split_publication(|| Ok(()))?;
        let previous = (self.rgb_dev.clone(), self.ir_dev.clone(), self.ir_available);
        self.rgb_dev = prepared.rgb.clone();
        self.ir_dev = prepared.ir.clone();
        self.ir_available = prepared.ir_available;
        self.camera_selection = Some(prepared);
        Ok(CameraRequestScope {
            engine: self,
            previous: Some(previous),
        })
    }

    /// The whole retained operation binding, not an identity-only projection.
    ///
    /// # Errors
    /// Refuses stale or missing operation proof.
    pub fn prepared_enrollment_binding(
        &self,
    ) -> irlume_common::Result<irlume_core::multi_camera::GroupPair> {
        self.validate_passive_camera_request()?;
        self.camera_selection
            .as_ref()
            .and_then(PreparedSelection::binding)
            .ok_or_else(|| Error::Policy("operation camera has no complete proof".into()))
    }

    /// Refuse split trust operations while their activation gate is closed.
    ///
    /// A retained split passes only when it was prepared for enrollment and
    /// the camera activation predicate admits Enrollment, which production
    /// never does. Passing this gate is not a trust use: capture, leases and
    /// nested entries still need the declared Engine split entry.
    ///
    /// # Errors
    /// Refuses closed split enrollment activation, then any passive
    /// selection drift.
    pub fn validate_enrollment_camera_activation(&self) -> irlume_common::Result<()> {
        if self.camera_selection.as_ref().is_some_and(|selection| {
            selection.pin.is_some()
                || selection.split().is_some_and(|split| {
                    split.entry != SplitTrustEntry::Enrollment || !split.entry.admitted()
                })
        }) {
            return Err(split_activation_refusal());
        }
        self.validate_passive_camera_request()
    }

    /// Declare the running Engine split trust entry on the retained split.
    ///
    /// Only the dedicated Engine split entries call this, and they call
    /// [`Self::leave_split_trust`] when they finish. Dropping the outer
    /// request scope also clears the declaration with the whole selection.
    ///
    /// # Errors
    /// Refuses without a retained split prepared for the same entry, while
    /// the activation predicate is closed for its kind, on a second
    /// declaration, without IR (no RGB-only or convenience split trust) or
    /// when the retained proof no longer validates. The Authentication
    /// entry always refuses here: only the authentication call that routes
    /// a split declares it, once, and it is never re-entered.
    pub(crate) fn enter_split_trust(
        &mut self,
        entry: SplitTrustEntry,
    ) -> irlume_common::Result<()> {
        if entry == SplitTrustEntry::Authentication {
            return Err(split_activation_refusal());
        }
        let selection = self
            .camera_selection
            .as_mut()
            .ok_or_else(split_activation_refusal)?;
        if !selection
            .split()
            .is_some_and(|split| split.entry == entry && entry.admitted())
        {
            return Err(split_activation_refusal());
        }
        if selection.active_entry.is_some() {
            return Err(Error::Policy(
                "a split camera trust entry is already running in this request".into(),
            ));
        }
        if !selection.ir_available {
            return Err(Error::Policy(
                "split camera trust needs both sides and IR is unavailable or forced off".into(),
            ));
        }
        selection.active_entry = Some(entry);
        if let Err(error) = self.validate_camera_request() {
            self.leave_split_trust();
            return Err(error);
        }
        Ok(())
    }

    /// Close the running split trust entry. The retained scope stays, and
    /// every split use refuses again until an entry is declared.
    pub(crate) fn leave_split_trust(&mut self) {
        if let Some(selection) = self.camera_selection.as_mut() {
            selection.active_entry = None;
        }
    }

    /// Check operation-scoped primary compatibility before daemon camera work.
    /// The enrollment entry repeats this check against its own loaded store.
    ///
    /// # Errors
    /// Refuses unreadable enrollment, stale selection or a non-reset operation
    /// whose existing binding or scans lack the same complete primary binding.
    /// An empty, unbound enrollment may start on the chosen pair.
    pub fn validate_enrollment_camera_primary(
        &self,
        user: &str,
        replace: bool,
    ) -> irlume_common::Result<()> {
        self.validate_passive_camera_request()?;
        if replace
            || !self
                .camera_selection
                .as_ref()
                .is_some_and(PreparedSelection::enrollment_choice)
        {
            return Ok(());
        }
        let enrollment = irlume_core::storage::load_unmoved(user)?
            .unwrap_or_else(|| irlume_core::storage::Enrollment::new(user));
        self.validate_operation_primary(&enrollment, replace)
    }

    pub(super) fn validate_operation_primary(
        &self,
        enrollment: &irlume_core::storage::Enrollment,
        replace: bool,
    ) -> irlume_common::Result<()> {
        if !replace
            && self
                .camera_selection
                .as_ref()
                .is_some_and(PreparedSelection::enrollment_choice)
            && (enrollment.camera_binding.is_some()
                || enrollment
                    .profiles
                    .iter()
                    .any(|profile| !profile.scans.is_empty()))
            && enrollment
                .camera_binding
                .as_ref()
                .and_then(|binding| binding.complete_key())
                != self.current_binding().complete_key()
        {
            return Err(Error::Policy("this enrollment belongs to another or unbound camera; use --add-camera or explicitly --reset".into()));
        }
        Ok(())
    }

    /// Prepare a guarded ordinary choice for this enrollment operation only.
    ///
    /// # Errors
    /// Refuses invalid configuration, stale/wrong-role/split choices, forbidden
    /// external cameras or an attempt to replace a nested request's choice.
    pub fn prepare_enrollment_camera(
        &mut self,
        choice: &irlume_common::live_camera::EnrollmentCameraChoice,
    ) -> irlume_common::Result<CameraRequestScope<'_>> {
        choice
            .validate()
            .map_err(|reason| Error::Policy(reason.into()))?;
        if self.camera_selection.is_some() {
            return Err(Error::Policy(
                "enrollment choice cannot replace a prepared request".into(),
            ));
        }
        let mut prepared = PreparedSelection::observe_choice(
            &self.rgb_dev,
            &self.ir_dev,
            self.ir_available,
            Some(choice),
            SelectionRoute::Generic,
        )?;
        let previous = (self.rgb_dev.clone(), self.ir_dev.clone(), self.ir_available);
        self.set_devices(&prepared.rgb, &prepared.ir);
        // A resolved Current pair supplies both classified sides. As with
        // account selection, a racy path-existence check must not demote it.
        // The operator's forced-convenience override still wins.
        prepared.ir_available = !irlume_camera::ir_forced_off();
        self.ir_available = prepared.ir_available;
        prepared.automatic = false;
        self.camera_selection = Some(prepared);
        Ok(CameraRequestScope {
            engine: self,
            previous: Some(previous),
        })
    }

    /// The retained ordinary runtime proof, for enrollment preflight/probe work.
    #[must_use]
    pub fn prepared_camera_lease(&self) -> Option<irlume_camera::lease::OrdinaryLeaseRequest> {
        self.camera_selection
            .as_ref()
            .and_then(PreparedSelection::expected_lease)
    }

    /// Commit only under the retained camera proof, after caller-owned preparation.
    /// The callback must be persistence-only and its receipt is never revalidated.
    pub(super) fn with_prepared_camera_publication<R>(
        &self,
        publish: impl FnOnce() -> irlume_common::Result<R>,
    ) -> irlume_common::Result<R> {
        if let Some(selection) = self
            .camera_selection
            .as_ref()
            .filter(|selection| selection.retains_split())
        {
            if !selection.matches_devices(&self.rgb_dev, &self.ir_dev, self.ir_available) {
                return Err(Error::Policy(
                    "camera endpoints or availability changed during prepared request".into(),
                ));
            }
            // Only an enrollment split publishes; a routed or pending
            // authentication split never does.
            if !selection
                .split()
                .is_some_and(|split| split.entry == SplitTrustEntry::Enrollment)
            {
                return Err(Error::Policy(
                    "split publication has no retained enrollment proof".into(),
                ));
            }
            return selection.with_split_publication(publish);
        }
        match self.prepared_camera_lease() {
            Some(expected) => irlume_camera::with_selected_camera_publication(&expected, publish)
                .map_err(crate::lease_unavailable)?,
            None if self
                .camera_selection
                .as_ref()
                .is_some_and(PreparedSelection::enrollment_choice) =>
            {
                Err(Error::Policy(
                    "operation camera publication has no retained proof".into(),
                ))
            }
            None => publish(),
        }
    }
    /// Late machine authority over a routed Authentication split (plan C6,
    /// D10): None unless one is installed. It refuses when the declared,
    /// admitted entry is gone, or when a fresh lock-free read no longer
    /// verifies the retained publication, records and selection, or either
    /// side is now forbidden as external. It takes no configuration lock and
    /// creates no lock file; lease continuity stays with the capture branch.
    pub(super) fn split_grant_authority_refusal(&self) -> Option<crate::Outcome> {
        let selection = self.camera_selection.as_ref()?;
        let split = selection
            .split()
            .filter(|split| split.entry == SplitTrustEntry::Authentication)?;
        let authority = if selection.split_entry_active(split) {
            selection.split_config_authority(split)
        } else {
            Err(split_activation_refusal())
        };
        authority.err().map(|_| {
            crate::Outcome::deny_because(
                crate::OutcomeKind::OtherDeny,
                irlume_common::OutcomeCause::SetupUnavailable,
                "split camera authorization changed during the request; use your password",
            )
        })
    }

    pub(super) fn pre_open_account_refusal(&self) -> Option<crate::Outcome> {
        if let Some(refusal) = self.split_grant_authority_refusal() {
            return Some(refusal);
        }
        if let Some(scope) = &self.primary_attempt {
            if let Some(refusal) = scope.boundary_refusal(&mut *self.request_key()) {
                return Some(refusal);
            }
        }
        let context = self.secondary_attempt.as_ref()?;
        match context.boundary_check_now_with(&mut *self.request_key()) {
            Ok(irlume_core::multi_camera::commit::GrantDecision::Grant) => None,
            Ok(irlume_core::multi_camera::commit::GrantDecision::Refuse(clause)) => {
                Some(crate::Outcome::deny_because(
                    crate::OutcomeKind::OtherDeny,
                    irlume_common::OutcomeCause::SetupUnavailable,
                    format!("secondary camera preparation refused at the boundary: {clause}"),
                ))
            }
            Err(error) => Some(crate::Outcome::deny(
                crate::OutcomeKind::SetupUnavailable,
                format!("secondary camera preparation unreadable: {error}"),
            )),
        }
    }
    /// Advisory routing fact used only to defer standing-tier policy. The
    /// charged Engine path revalidates authoritative configuration and choice.
    #[must_use]
    pub fn may_select_account_camera(&self) -> bool {
        if std::env::var("IRLUME_FORCE_NO_IR").is_ok_and(|value| value == "1") {
            return false;
        }
        if let Some(selection) = &self.camera_selection {
            // A pending pin routes only to its own key.
            if selection.pending_pin().is_some() {
                return selection.pin_connected();
            }
            return selection.automatic() && selection.has_account_candidates();
        }
        if ordinary_environment_pair().is_some() {
            return false;
        }
        let snapshot = irlume_common::split_publish::read_camera_selection();
        if !matches!(
            snapshot.observation().selection,
            CameraSelectionObservation::Fresh | CameraSelectionObservation::Automatic { .. }
        ) {
            return false;
        }
        let records = match snapshot.split() {
            SplitReadState::Absent => &[][..],
            SplitReadState::Valid { records, .. } => records.as_slice(),
            _ => return false,
        };
        let view = irlume_camera::connected_pairs_with_split(records);
        view.ordinary.state == irlume_common::live_camera::CameraInventoryState::Current
            && (!view.ordinary.pairs.is_empty() || !view.split_pairs.is_empty())
    }

    pub(super) fn select_account_camera(
        &mut self,
        pair: irlume_camera::ConnectedPair,
    ) -> irlume_common::Result<()> {
        // A retained split, pending, routed or offered and refused at or
        // before its install, never yields to an ordinary pair (plan D8: no
        // fallback, no rerank).
        if self
            .camera_selection
            .as_ref()
            .is_some_and(PreparedSelection::retains_split)
        {
            return Err(split_activation_refusal());
        }
        let available = !std::env::var("IRLUME_FORCE_NO_IR").is_ok_and(|value| value == "1");
        self.rgb_dev = pair.rgb.clone();
        self.ir_dev = pair.ir.clone();
        self.ir_available = available;
        self.camera_selection
            .as_mut()
            .ok_or_else(|| Error::Policy("account selection has no request scope".into()))?
            .select_ordinary(pair, available);
        self.validate_camera_request()
    }

    /// Install a class-aware split account choice for the Authentication
    /// entry (plan C5, D8). Refuses without IR (no RGB-only or convenience
    /// split authentication), for a forbidden external side, or for a choice
    /// that is not this request's retained, unrouted, automatic or pinned
    /// split. Routing runs at most once per request: after an installed
    /// split, or after an ordinary pair any call in this request routed,
    /// accepted or refused, the install refuses and leaves the request's
    /// devices as they were. Any offer, refused or not, also closes the
    /// request to every ordinary route and lease. Otherwise both split
    /// paths become the request's devices, the retained split is installed
    /// with no standing choice, the Authentication entry is declared until
    /// the running authentication call's scope drops (a nested scope ends
    /// it; a top-level one clears the whole selection), and the request is
    /// validated without a configuration lock. A failed validation closes the entry and leaves
    /// the refused split installed and closed, so no ordinary pair, second
    /// route or re-entry follows.
    pub(super) fn select_account_split_camera(
        &mut self,
        choice: SplitChoice,
    ) -> irlume_common::Result<()> {
        // Marked before any check: a refused offer must not fall back.
        if let Some(selection) = self.camera_selection.as_mut() {
            selection.split_routing_attempted = true;
        }
        if irlume_camera::ir_forced_off() {
            return Err(Error::Policy(
                "split camera authentication needs both sides and IR is forced off".into(),
            ));
        }
        split_external_policy(&choice.pair)?;
        self.camera_selection
            .as_ref()
            .ok_or_else(|| Error::Policy("account selection has no request scope".into()))?
            .admits_split_choice(&choice)?;
        self.rgb_dev = choice.pair.rgb.path.clone();
        self.ir_dev = choice.pair.ir.path.clone();
        self.ir_available = true;
        if let Some(selection) = self.camera_selection.as_mut() {
            selection.install_split(choice);
        }
        if let Err(error) = self.validate_camera_request() {
            self.leave_split_trust();
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn acquire_account_camera(
        &self,
        endpoints: &[&str],
        kind: irlume_camera::lease::CameraOperationKind,
        timeout: std::time::Duration,
    ) -> Result<irlume_camera::lease::CameraOperationSession, irlume_camera::lease::CameraLeaseError>
    {
        // A retained split, installed or pending, never reaches either
        // ordinary acquisition below.
        if let Some(selection) = self
            .camera_selection
            .as_ref()
            .filter(|selection| selection.retains_split())
        {
            return selection.acquire_split_operation(endpoints, kind, timeout);
        }
        match self
            .camera_selection
            .as_ref()
            .and_then(|selection| selection.expected_lease())
        {
            Some(expected) => irlume_camera::lease::acquire_selected_camera_operation(
                &expected, endpoints, kind, timeout,
            ),
            None => irlume_camera::lease::acquire_camera_operation(endpoints, kind, timeout),
        }
    }
    /// The gate before every probe, preflight, capture, lease and publication.
    /// A retained split passes only for its declared, admitted Engine entry;
    /// every other caller, including public ordinary entries, keeps the closed
    /// refusal. Non-split selections are validated exactly as before.
    pub(crate) fn validate_camera_request(&self) -> irlume_common::Result<()> {
        if self
            .camera_selection
            .as_ref()
            .is_some_and(PreparedSelection::split_closed)
        {
            return Err(split_activation_refusal());
        }
        self.validate_passive_camera_request()
    }

    fn validate_passive_camera_request(&self) -> irlume_common::Result<()> {
        if let Some(selection) = &self.camera_selection {
            return selection.validate_passive(self);
        }
        PreparedSelection::observe(&self.rgb_dev, &self.ir_dev, self.ir_available).map(|_| ())
    }

    /// Validate camera selection before probe, preflight, capture or publication.
    /// Nested entries reuse the outer request's coherent configuration observation.
    /// A nested entry inside a retained Enrollment split passes only while
    /// the outer Engine split entry is declared and admitted. Inside a
    /// pending pin or a routed Authentication split it always refuses: that
    /// entry belongs to the authentication call alone.
    ///
    /// # Errors
    /// Refuses invalid configuration, closed split activation, an unproven
    /// ordinary override or retained device/inventory drift. This is not a
    /// camera lease or an account authorization.
    pub fn prepare_camera_request(&mut self) -> irlume_common::Result<CameraRequestScope<'_>> {
        if let Some(selection) = &self.camera_selection {
            // No nested generic entry runs on a pending pin's standing
            // devices or on a routed split's halves (plan D3, D8).
            if selection.authentication_routed() {
                return Err(split_activation_refusal());
            }
            self.validate_camera_request()?;
            selection.validate_devices(self)?;
            return Ok(CameraRequestScope {
                engine: self,
                previous: None,
            });
        }
        self.prepare_observed(SelectionRoute::Generic)
    }

    /// Prepare the scope of one account-routed authentication call.
    ///
    /// This is [`Self::prepare_camera_request`] with two differences, both
    /// reachable only while the camera activation predicate admits
    /// Authentication, which production never does:
    ///
    /// - With no outer request, a saved selected split pair is retained as a
    ///   pending pin instead of being refused, and the Authentication entry
    ///   is declared for the returned scope, which is this call.
    /// - Inside an outer request holding a pending pin, this nested call
    ///   validates the pin under the outer declaration and takes that
    ///   declaration over.
    ///
    /// Account routing then ranks only the pinned key, or ranks automatically,
    /// and installs a split for one split Authentication lease, declaring the
    /// entry if no pin did. The entry ends with the call: a nested scope ends
    /// it when it drops, pinned or automatic, and nothing reopens it, so the
    /// outer request keeps the routed split or pin closed and a second call
    /// refuses. Every nested generic entry, ordinary lease, publication,
    /// qualification or enrollment use refuses with the closed text
    /// throughout. An authentication call never nests inside a split
    /// enrollment scope or after a split was routed.
    ///
    /// # Errors
    /// As [`Self::prepare_camera_request`], plus the closed refusal for a
    /// nested call over an installed split or an ended entry.
    pub fn prepare_authentication_camera_request(
        &mut self,
    ) -> irlume_common::Result<CameraRequestScope<'_>> {
        let Some(selection) = &self.camera_selection else {
            let scope = self.prepare_observed(SelectionRoute::Authentication)?;
            if let Some(selection) = scope
                .engine
                .camera_selection
                .as_mut()
                .filter(|selection| selection.pin.is_some())
            {
                // This call retained the pin and declares its own entry.
                selection.active_entry = Some(SplitTrustEntry::Authentication);
            }
            return Ok(scope);
        };
        // An authentication call never nests over an installed split: a
        // split enrollment scope, or a split another call already routed.
        if selection.split().is_some() {
            return Err(split_activation_refusal());
        }
        // An outer pin must still be declared and admitted, unchanged and on
        // the same devices; otherwise this refuses with the closed text.
        // Without a pin this is the generic nested validation.
        self.validate_camera_request()?;
        selection.validate_devices(self)?;
        Ok(CameraRequestScope {
            engine: self,
            previous: None,
        })
    }

    fn prepare_observed(
        &mut self,
        route: SelectionRoute,
    ) -> irlume_common::Result<CameraRequestScope<'_>> {
        let mut prepared = PreparedSelection::observe_choice(
            &self.rgb_dev,
            &self.ir_dev,
            self.ir_available,
            None,
            route,
        )?;
        let previous = (self.rgb_dev.clone(), self.ir_dev.clone(), self.ir_available);
        if self.rgb_dev != prepared.rgb || self.ir_dev != prepared.ir {
            self.set_devices(&prepared.rgb, &prepared.ir);
        }
        prepared.ir_available = self.ir_available;
        self.camera_selection = Some(prepared);
        Ok(CameraRequestScope {
            engine: self,
            previous: Some(previous),
        })
    }

    /// Read fd-derived qualification using the retained ordinary incarnation.
    ///
    /// # Errors
    /// Refuses changed request facts, stale/uncovered cameras or unreadable
    /// qualification. A legacy unprepared caller retains its existing lookup.
    /// A retained split always refuses: it has no stored qualification, its
    /// schedule is sequential, and it never gets a Diagnostics half.
    pub fn capture_qualification_for_request(
        &self,
    ) -> irlume_common::Result<irlume_camera::capture_qualification::QualificationResolution> {
        self.validate_camera_request()?;
        if self
            .camera_selection
            .as_ref()
            .is_some_and(PreparedSelection::retains_split)
        {
            return Err(Error::Policy(
                "a split camera pair has no stored capture qualification".into(),
            ));
        }
        if self.prepared_camera_lease().is_none() {
            return irlume_camera::stored_capture_qualification(&self.rgb_dev, &self.ir_dev);
        }
        let operation = self
            .acquire_account_camera(
                &[&self.rgb_dev, &self.ir_dev],
                irlume_camera::lease::CameraOperationKind::Diagnostics,
                std::time::Duration::from_secs(2),
            )
            .map_err(crate::lease_unavailable)?;
        let state = irlume_camera::stored_capture_qualification_state_in_operation(
            &self.rgb_dev,
            &self.ir_dev,
            &operation,
        )?;
        operation
            .lease()
            .validate()
            .map_err(crate::lease_unavailable)?;
        Ok(state.resolution)
    }
}
