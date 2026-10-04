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

pub(crate) struct PreparedSelection {
    snapshot: CameraSelectionSnapshot,
    view: irlume_camera::ResolvedConnectedPairs,
    ordinary: Option<irlume_camera::ConnectedPair>,
    rgb: String,
    ir: String,
    ir_available: bool,
}

impl PreparedSelection {
    pub(super) fn matches_devices(&self, rgb: &str, ir: &str, ir_available: bool) -> bool {
        self.rgb == rgb && self.ir == ir && self.ir_available == ir_available
    }

    pub(super) fn ordinary_is_current(&self) -> bool {
        let Some(expected) = &self.ordinary else {
            // Standing legacy ordinary selection has no new passive proof.
            // Its existing lease, physical pin and binding checks still apply.
            return true;
        };
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

    pub(super) fn binding(&self) -> Option<irlume_core::multi_camera::GroupPair> {
        if !matches!(
            self.snapshot.split(),
            SplitReadState::Absent | SplitReadState::Valid { .. }
        ) || self.view.ordinary.state
            != irlume_common::live_camera::CameraInventoryState::Current
        {
            return None;
        }
        self.ordinary
            .as_ref()
            .map(|pair| irlume_core::multi_camera::GroupPair::Ordinary {
                rgb: Some(pair.identity.clone()),
                ir: Some(pair.identity.clone()),
            })
    }

    fn observe(rgb: &str, ir: &str, ir_available: bool) -> irlume_common::Result<Self> {
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
        let view = irlume_camera::connected_pairs_with_split(records);
        let env = ordinary_environment_pair();
        let (rgb, ir) = if selected.is_some() {
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
            ordinary,
            rgb,
            ir,
            ir_available,
        })
    }
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
            self.engine.camera_selection = None;
            self.engine.rgb_dev = rgb;
            self.engine.ir_dev = ir;
            self.engine.ir_available = available;
        }
    }
}

impl Engine {
    pub(crate) fn validate_camera_request(&self) -> irlume_common::Result<()> {
        if let Some(selection) = &self.camera_selection {
            return selection.validate_devices(self);
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
}
