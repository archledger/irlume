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

struct PreparedSplit {
    pair: irlume_camera::SplitPair,
    key: irlume_common::split_key::SplitPairKey,
    expected: irlume_camera::lease::SplitLeaseRequest,
    displayed: irlume_common::split_wire::SplitMutationGuard,
    authorization: irlume_common::split_publish::Published,
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
    enrollment_choice: bool,
}

impl PreparedSelection {
    pub(super) fn automatic(&self) -> bool {
        self.automatic
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

    fn validate_passive(&self, engine: &Engine) -> irlume_common::Result<()> {
        self.validate_devices(engine)?;
        if self.split().is_some() {
            self.with_split_publication(|| Ok(()))?;
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
        Self::observe_choice(rgb, ir, ir_available, None)
    }

    fn observe_choice(
        rgb: &str,
        ir: &str,
        ir_available: bool,
        choice: Option<&irlume_common::live_camera::EnrollmentCameraChoice>,
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
        let (rgb, ir) = if selected.is_some() || choice.is_some() {
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
        let ordinary = ordinary_pair(&view, &rgb, &ir).cloned();
        Ok(Self {
            snapshot,
            view,
            pair: ordinary.map(PreparedPair::Ordinary),
            rgb,
            ir,
            ir_available,
            automatic,
            retain_standing: false,
            enrollment_choice: choice.is_some(),
        })
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

fn ordinary_environment_pair() -> Option<(String, String)> {
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
            }))),
            snapshot,
            view,
            automatic: false,
            retain_standing: false,
            enrollment_choice: true,
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
    /// # Errors
    /// Refuses closed split enrollment activation.
    pub fn validate_enrollment_camera_activation(&self) -> irlume_common::Result<()> {
        if self
            .camera_selection
            .as_ref()
            .is_some_and(|selection| selection.split().is_some())
        {
            return Err(split_activation_refusal());
        }
        self.validate_passive_camera_request()
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
            .filter(|selection| selection.split().is_some())
        {
            if !selection.matches_devices(&self.rgb_dev, &self.ir_dev, self.ir_available) {
                return Err(Error::Policy(
                    "camera endpoints or availability changed during prepared request".into(),
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
    pub(super) fn pre_open_account_refusal(&self) -> Option<crate::Outcome> {
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

    pub(super) fn acquire_account_camera(
        &self,
        endpoints: &[&str],
        kind: irlume_camera::lease::CameraOperationKind,
        timeout: std::time::Duration,
    ) -> Result<irlume_camera::lease::CameraOperationSession, irlume_camera::lease::CameraLeaseError>
    {
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
    pub(crate) fn validate_camera_request(&self) -> irlume_common::Result<()> {
        self.validate_enrollment_camera_activation()
    }

    fn validate_passive_camera_request(&self) -> irlume_common::Result<()> {
        if let Some(selection) = &self.camera_selection {
            return selection.validate_passive(self);
        }
        PreparedSelection::observe(&self.rgb_dev, &self.ir_dev, self.ir_available).map(|_| ())
    }

    /// Validate camera selection before probe, preflight, capture or publication.
    /// Nested entries reuse the outer request's coherent configuration observation.
    ///
    /// # Errors
    /// Refuses invalid configuration, closed split activation, an unproven
    /// ordinary override or retained device/inventory drift. This is not a
    /// camera lease or an account authorization.
    pub fn prepare_camera_request(&mut self) -> irlume_common::Result<CameraRequestScope<'_>> {
        if let Some(selection) = &self.camera_selection {
            self.validate_enrollment_camera_activation()?;
            selection.validate_devices(self)?;
            return Ok(CameraRequestScope {
                engine: self,
                previous: None,
            });
        }
        let mut prepared =
            PreparedSelection::observe(&self.rgb_dev, &self.ir_dev, self.ir_available)?;
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
    pub fn capture_qualification_for_request(
        &self,
    ) -> irlume_common::Result<irlume_camera::capture_qualification::QualificationResolution> {
        self.validate_camera_request()?;
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
