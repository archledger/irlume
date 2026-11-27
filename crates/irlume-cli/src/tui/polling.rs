// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Completion handling for the Live, Apps and Cameras workers.

use super::{receive_finished, App, Source, Worker};
use std::time::Instant;

impl App {
    pub(super) fn poll_live_apps_and_cameras(&mut self, now: Instant) {
        if let Some(result) = receive_finished(&self.live_load) {
            self.live_load = None;
            if self.freshness.cycle_mut(Worker::Live).finish(now) {
                match result {
                    Ok(Ok(snapshot)) => self.apply_live_snapshot(snapshot, now),
                    _ => {
                        self.freshness
                            .observation_mut(Source::Live)
                            .record(false, now);
                        self.clear_source(Source::Live);
                    }
                }
            }
        }
        if let Some(result) = receive_finished(&self.heavy_load) {
            self.heavy_load = None;
            self.heavy_at = now;
            if self.freshness.cycle_mut(Worker::Apps).finish(now) {
                let success = matches!(&result, Ok(Ok(_)));
                self.freshness
                    .observation_mut(Source::Apps)
                    .record(success, now);
                match result {
                    Ok(Ok(state)) => {
                        self.heavy = state;
                        self.heavy_known = true;
                    }
                    Err(()) => {
                        self.clear_source(Source::Apps);
                        self.log('!', "app status refresh ended without a result; current app state is unavailable. Refresh to retry.");
                    }
                    Ok(Err(_)) => self.clear_source(Source::Apps),
                }
            }
        }
        if let Some(result) = receive_finished(&self.camera_load) {
            self.camera_load = None;
            if self.freshness.cycle_mut(Worker::Cameras).finish(now) {
                let pairs = result
                    .as_ref()
                    .ok()
                    .and_then(|listing| listing.pairs.as_ref());
                self.freshness
                    .observation_mut(Source::Cameras)
                    .record(pairs.is_some(), now);
                self.freshness
                    .observation_mut(Source::CameraPrivacy)
                    .record(pairs.is_some(), now);
                if let Some(pairs) = pairs {
                    let selected = self.selected_camera_choice.take().or_else(|| {
                        (self.pairs_known || !self.pairs.is_empty()).then(|| {
                            self.pairs
                                .get(self.cam_sel)
                                .and_then(|pair| self.camera_choice(&pair.rgb, &pair.ir))
                        })
                    });
                    self.pairs = pairs
                        .iter()
                        .filter(|pair| self.camera_choice(&pair.rgb, &pair.ir).is_some())
                        .cloned()
                        .collect();
                    self.pairs_known = true;
                    self.cam_sel = match selected {
                        None => 0,
                        Some(Some(choice)) if self.camera_choice_current(&choice) => self
                            .pairs
                            .iter()
                            .position(|pair| pair.rgb == choice.rgb && pair.ir == choice.ir)
                            .unwrap_or(self.pairs.len()),
                        Some(_) => self.pairs.len(),
                    };
                } else {
                    self.clear_source(Source::Cameras);
                    if result.is_err() {
                        self.log('!', "camera refresh ended without a result; current camera classification is unavailable. Refresh to retry.");
                    }
                }
                self.run_checks();
                self.recompute_visible();
            }
        }
    }
}
