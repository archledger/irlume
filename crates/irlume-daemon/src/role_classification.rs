// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Background role classification of the passive camera inventory
//! (ADR-0029 §1).
//!
//! Account routing, split pairs and the split listing read each camera's
//! RGB/IR role from the roles recorded when discovery last classified its
//! capture nodes, for the camera's current connection generation. The
//! passive coordinator never opens a node, and a udev change starts a new
//! generation, so after a daemon start or a replug nothing recorded a
//! camera's roles until a client sent the classifying `ListCameras` (the
//! TUI's Cameras page): authentication refused with
//! `NoEnrolledCameraConnected` until then (#887).
//!
//! ADR-0029 §1 classifies each node's role when the device appears, on the
//! camera worker, and this does that. While the Current publication lists a
//! camera as unclassified, the capture nodes of the cameras due a try, and no
//! others, are classified as discovery does: each is opened for its
//! capabilities and formats under a diagnostics lease, with no stream started
//! and no emitter fired. The scan is the worker's background camera work: the
//! arbiter refuses it while an authentication is pending, and an
//! authentication arriving during it stops it before the next node. The
//! publication is read in memory every [`POLL`]; nothing is opened while every
//! camera has its roles. Authentication itself stays camera-free until its
//! capture.

use irlume_auth::ConnectedPairs;
use irlume_common::live_camera::CameraInventoryState;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How often the in-memory publication is read; no device is touched.
pub(crate) const POLL: Duration = Duration::from_secs(2);

/// The wait before each further try at one camera generation that stayed
/// unclassified (a node busy past its lease wait, an open that failed).
/// After the last, that generation is left alone until it changes.
const RETRY_AFTER: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
];

/// Tries at one camera generation, the first included.
pub(crate) const MAX_TRIES: usize = RETRY_AFTER.len() + 1;

/// The least time between two scans for one camera, by how many scans its
/// current run has made. A camera that answered a scan with a udev change
/// would come back as a new, unclassified generation each time; this keeps
/// such a camera from being opened every few seconds. Other cameras keep
/// their own runs, so one appearing meanwhile is still classified at once.
const SCAN_GAP: [Duration; 5] = [
    POLL,
    Duration::from_secs(10),
    Duration::from_secs(60),
    Duration::from_secs(300),
    Duration::from_secs(600),
];

/// A scan this long after a camera's previous one starts a new run for it.
const RUN_ENDS_AFTER: Duration = Duration::from_secs(900);

/// The scans in a run after which the classifier says it is spacing them.
const THROTTLE_NOTICE_AT: usize = 3;

/// One camera's connection generation, as the publication names it.
pub(crate) type CameraKey = (String, u64);

/// The tries made at each camera generation that is still unclassified, and
/// each camera's current run of scans.
#[derive(Debug, Default)]
pub(crate) struct RoleClassifier {
    tries: BTreeMap<CameraKey, (usize, Instant)>,
    /// Per camera instance: its last scan, and the scans in its run.
    runs: BTreeMap<String, (Instant, usize)>,
}

impl RoleClassifier {
    /// The unclassified cameras due a try at `now`. A camera no longer
    /// listed as unclassified (classified, removed, or a new generation) is
    /// forgotten. A publication other than Current asks for nothing: its
    /// view is incomplete, and a scan would not record roles into it.
    pub(crate) fn due(&mut self, view: &ConnectedPairs, now: Instant) -> Vec<CameraKey> {
        if view.state != CameraInventoryState::Current {
            return Vec::new();
        }
        let listed: Vec<CameraKey> = view
            .unclassified
            .iter()
            .map(|camera| (camera.instance_id.clone(), camera.generation))
            .collect();
        self.tries.retain(|key, _| listed.contains(key));
        self.runs
            .retain(|_, (last, _)| now.saturating_duration_since(*last) < RUN_ENDS_AFTER);
        listed
            .into_iter()
            .filter(|key| match self.runs.get(&key.0) {
                Some((last, scans)) => {
                    now.saturating_duration_since(*last)
                        >= SCAN_GAP[(*scans).min(SCAN_GAP.len()) - 1]
                }
                None => true,
            })
            .filter(|key| match self.tries.get(key) {
                None => true,
                Some((made, last)) => RETRY_AFTER
                    .get(made - 1)
                    .is_some_and(|wait| now.saturating_duration_since(*last) >= *wait),
            })
            .collect()
    }

    /// Record that a scan for `keys` ran at `now`; returns the most scans
    /// any of their cameras' runs has now made.
    pub(crate) fn scanned(&mut self, keys: &[CameraKey], now: Instant) -> usize {
        let mut most = 0;
        for (instance, _) in keys {
            let scans = match self.runs.get(instance) {
                Some((last, scans)) if now.saturating_duration_since(*last) < RUN_ENDS_AFTER => {
                    scans + 1
                }
                _ => 1,
            };
            self.runs.insert(instance.clone(), (now, scans));
            most = most.max(scans);
        }
        most
    }

    /// Record a try at `keys` at `now`; returns the cameras whose last try
    /// this was.
    pub(crate) fn tried(&mut self, keys: &[CameraKey], now: Instant) -> Vec<CameraKey> {
        let mut exhausted = Vec::new();
        for key in keys {
            let entry = self.tries.entry(key.clone()).or_insert((0, now));
            entry.0 += 1;
            entry.1 = now;
            if entry.0 == MAX_TRIES {
                exhausted.push(key.clone());
            }
        }
        exhausted
    }
}

/// One poll at `now`: when a camera is due a try and `permitted` (read only
/// then) allows it, `scan` classifies the capture nodes of exactly the due
/// cameras; it answers whether the scan ran to the end. A scan refused or
/// stopped for an authentication is not a try. Returns the cameras tried.
pub(crate) fn tick(
    classifier: &mut RoleClassifier,
    permitted: &dyn Fn() -> bool,
    scan: &dyn Fn(Vec<String>) -> bool,
    now: Instant,
) -> Vec<CameraKey> {
    let view = irlume_auth::connected_pairs();
    let due = classifier.due(&view, now);
    if due.is_empty() || !permitted() {
        return Vec::new();
    }
    let endpoints: Vec<String> = view
        .unclassified
        .iter()
        .filter(|camera| due.contains(&(camera.instance_id.clone(), camera.generation)))
        .flat_map(|camera| camera.endpoints.iter().cloned())
        .collect();
    if !scan(endpoints) {
        return Vec::new();
    }
    irlume_common::jout_info!(
        "irlumed: classified the capture nodes of {} connected camera(s) \
         that had no roles yet (ADR-0029 §1)",
        due.len()
    );
    if classifier.scanned(&due, now) == THROTTLE_NOTICE_AT {
        irlume_common::jout_notice!(
            "irlumed: cameras keep coming back unclassified after a scan (a udev \
             change each time?); scans are now spaced up to {} s apart",
            SCAN_GAP[SCAN_GAP.len() - 1].as_secs()
        );
    }
    for (instance, _) in classifier.tried(&due, now) {
        irlume_common::jout_warn!(
            "irlumed: camera {} is still unclassified after {MAX_TRIES} tries; \
             face authentication cannot route to it until it is replugged \
             or the TUI's Cameras page lists it",
            crate::journal_safe(&instance)
        );
    }
    due
}

/// Classify `endpoints` as the camera worker's background work, and wait for
/// it: true when the scan ran to the end; false when the arbiter refused it
/// (an authentication pending), an authentication stopped it, or the worker
/// shut down without running it.
pub(crate) fn scan_on_worker<T: Send + 'static>(
    arbiter: &crate::arbiter::Arbiter<T>,
    endpoints: Vec<String>,
) -> bool {
    let (done, finished) = std::sync::mpsc::channel();
    let task: crate::arbiter::BackgroundTask = Box::new(move |token| {
        irlume_auth::classify_endpoints(&endpoints, &|| token.stop_requested());
        let _ = done.send(!token.stop_requested());
    });
    match arbiter.submit_background(task) {
        Ok(()) => finished.recv().unwrap_or(false),
        Err(_) => false,
    }
}

/// Start the classifier thread, which hands its scans to `arbiter`'s camera
/// worker. `permitted` is read only when a camera is due a try: the face
/// sensor policy decides, as for background requalification, so the IR-only
/// policy's "no discovery" stays true.
pub(crate) fn spawn<T: Send + 'static>(
    arbiter: std::sync::Arc<crate::arbiter::Arbiter<T>>,
    permitted: impl Fn() -> bool + Send + 'static,
) {
    let spawned = std::thread::Builder::new()
        .name("irlume-camera-roles".into())
        .spawn(move || {
            let mut classifier = RoleClassifier::default();
            let scan = |endpoints| scan_on_worker(&arbiter, endpoints);
            loop {
                std::thread::sleep(POLL);
                tick(&mut classifier, &permitted, &scan, Instant::now());
            }
        });
    if let Err(error) = spawned {
        irlume_common::jout_warn!(
            "irlumed: camera role classification did not start ({error}); \
             cameras are classified when the TUI's Cameras page lists them"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_camera::test_support::{Call, Camera, Endpoint, Guard};
    use irlume_camera::UnclassifiedCamera;

    /// One RGB+IR USB camera, published with no role recorded.
    fn unclassified_camera() -> Guard {
        let endpoint = |path: &str, format| Endpoint {
            path: path.into(),
            formats: vec![format],
        };
        Guard::install_unclassified(&[Camera {
            topology: "/devices/role-classification/cam".into(),
            identity: "1234:00aa:roles".into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![4],
            endpoints: vec![
                endpoint("/dev/irlume-roles-rgb", *b"YUYV"),
                endpoint("/dev/irlume-roles-ir", *b"GREY"),
            ],
        }])
        .unwrap()
    }

    /// The worker task's scan, run on the test thread the fixture lives on.
    fn scan_here(endpoints: Vec<String>) -> bool {
        irlume_auth::classify_endpoints(&endpoints, &|| false);
        true
    }

    #[test]
    fn a_tick_classifies_an_unclassified_camera_into_a_pair() {
        // #887: after a daemon start the camera was listed but unclassified,
        // so account routing found no enrolled camera until a client listed
        // the cameras. One tick records its roles and it pairs.
        let guard = unclassified_camera();
        let before = irlume_auth::connected_pairs();
        assert!(before.pairs.is_empty());
        assert_eq!(before.unclassified.len(), 1);
        let mut classifier = RoleClassifier::default();
        let now = Instant::now();
        assert_eq!(tick(&mut classifier, &|| true, &scan_here, now).len(), 1);
        let after = irlume_auth::connected_pairs();
        assert!(after.unclassified.is_empty(), "{after:?}");
        assert_eq!(after.pairs.len(), 1);
        assert_eq!(after.pairs[0].rgb, "/dev/irlume-roles-rgb");
        assert_eq!(after.pairs[0].ir, "/dev/irlume-roles-ir");
        // Classified: the next ticks scan nothing more. The fixture opens no
        // device; the one boundary call is a scan of that camera's nodes.
        assert!(tick(&mut classifier, &|| true, &scan_here, now + RETRY_AFTER[3]).is_empty());
        assert_eq!(
            guard.calls(),
            [Call::ScanEndpoints(vec![
                "/dev/irlume-roles-ir".into(),
                "/dev/irlume-roles-rgb".into(),
            ])]
        );
    }

    #[test]
    fn a_refused_or_stopped_scan_is_not_a_try() {
        // An authentication pending (refused) or arriving (stopped): the
        // camera is due again on the next poll, its tries untouched.
        let guard = unclassified_camera();
        let mut classifier = RoleClassifier::default();
        let now = Instant::now();
        assert!(tick(&mut classifier, &|| true, &|_| false, now).is_empty());
        assert!(guard.calls().is_empty());
        assert_eq!(
            tick(&mut classifier, &|| true, &scan_here, now + POLL).len(),
            1
        );
        assert!(irlume_auth::connected_pairs().unclassified.is_empty());
    }

    #[test]
    fn only_the_due_cameras_nodes_are_scanned() {
        // A camera held back by its backoff is not opened on another
        // camera's schedule.
        let endpoint = |path: &str, format| Endpoint {
            path: path.into(),
            formats: vec![format],
        };
        let camera = |topology: &str, identity: &str, port: u8, rgb: &str, ir: &str| Camera {
            topology: topology.into(),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![port],
            endpoints: vec![endpoint(rgb, *b"YUYV"), endpoint(ir, *b"GREY")],
        };
        let guard = Guard::install_unclassified(&[
            camera(
                "/devices/role-classification/a",
                "1234:00ac:a",
                6,
                "/dev/irlume-a-rgb",
                "/dev/irlume-a-ir",
            ),
            camera(
                "/devices/role-classification/b",
                "1234:00ad:b",
                7,
                "/dev/irlume-b-rgb",
                "/dev/irlume-b-ir",
            ),
        ])
        .unwrap();
        let view = irlume_auth::connected_pairs();
        let a = view
            .unclassified
            .iter()
            .find(|camera| camera.endpoints.contains(&"/dev/irlume-a-rgb".to_owned()))
            .unwrap();
        let now = Instant::now();
        // `a` was tried a poll ago and is backing off; `b` is new.
        let mut classifier = RoleClassifier::default();
        classifier.tried(&[(a.instance_id.clone(), a.generation)], now);
        assert_eq!(
            tick(&mut classifier, &|| true, &scan_here, now + POLL).len(),
            1
        );
        assert_eq!(
            guard.calls(),
            [Call::ScanEndpoints(vec![
                "/dev/irlume-b-ir".into(),
                "/dev/irlume-b-rgb".into(),
            ])]
        );
    }

    #[test]
    fn the_scan_runs_on_the_worker_and_waits_for_it() {
        // Refused while an authentication is pending; otherwise run by
        // whoever takes the worker's work, and answered once it ran.
        let arbiter = std::sync::Arc::new(crate::arbiter::Arbiter::<()>::new());
        arbiter.submit(crate::arbiter::Class::Auth, 0, ()).unwrap();
        assert!(!scan_on_worker(&arbiter, vec!["/dev/irlume-none".into()]));
        let Some(crate::arbiter::Work::Job(job)) = arbiter.take_work() else {
            panic!("the authentication was not taken first");
        };
        arbiter.finish(job.class, job.uid);
        let worker = {
            let arbiter = std::sync::Arc::clone(&arbiter);
            std::thread::spawn(move || match arbiter.take_work() {
                Some(crate::arbiter::Work::Background(task)) => {
                    task(&arbiter.cancel_token());
                    true
                }
                _ => false,
            })
        };
        // No camera is published on this thread's supervisor for the path,
        // so the worker's scan touches nothing and runs to the end.
        assert!(scan_on_worker(&arbiter, vec!["/dev/irlume-none".into()]));
        assert!(worker.join().unwrap());
    }

    #[test]
    fn a_tick_the_policy_forbids_scans_nothing() {
        // The IR-only policy disables discovery, as for requalification.
        let guard = unclassified_camera();
        let mut classifier = RoleClassifier::default();
        assert!(tick(&mut classifier, &|| false, &scan_here, Instant::now()).is_empty());
        assert!(guard.calls().is_empty());
        assert_eq!(irlume_auth::connected_pairs().unclassified.len(), 1);
    }

    #[test]
    fn a_classified_inventory_never_asks_the_policy_or_scans() {
        let endpoint = |path: &str, format| Endpoint {
            path: path.into(),
            formats: vec![format],
        };
        let guard = Guard::install(&[Camera {
            topology: "/devices/role-classification/known".into(),
            identity: "1234:00ab:known".into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![5],
            endpoints: vec![
                endpoint("/dev/irlume-known-rgb", *b"YUYV"),
                endpoint("/dev/irlume-known-ir", *b"GREY"),
            ],
        }])
        .unwrap();
        let mut classifier = RoleClassifier::default();
        let asked = std::cell::Cell::new(false);
        let permitted = || {
            asked.set(true);
            true
        };
        assert!(tick(&mut classifier, &permitted, &scan_here, Instant::now()).is_empty());
        assert!(!asked.get());
        assert!(guard.calls().is_empty());
    }

    fn view(state: CameraInventoryState, unclassified: &[(&str, u64)]) -> ConnectedPairs {
        ConnectedPairs {
            state,
            unclassified: unclassified
                .iter()
                .map(|(instance, generation)| UnclassifiedCamera {
                    instance_id: (*instance).to_owned(),
                    generation: *generation,
                    endpoints: vec!["/dev/video0".into()],
                })
                .collect(),
            ..ConnectedPairs::default()
        }
    }

    fn key(instance: &str, generation: u64) -> CameraKey {
        (instance.to_owned(), generation)
    }

    #[test]
    fn nothing_is_due_while_every_camera_has_its_roles() {
        let mut classifier = RoleClassifier::default();
        assert!(classifier
            .due(&view(CameraInventoryState::Current, &[]), Instant::now())
            .is_empty());
    }

    #[test]
    fn an_incomplete_publication_asks_for_nothing() {
        let now = Instant::now();
        for state in [
            CameraInventoryState::Uninitialized,
            CameraInventoryState::Refreshing,
            CameraInventoryState::Unavailable,
        ] {
            let mut classifier = RoleClassifier::default();
            assert!(
                classifier.due(&view(state, &[("a", 1)]), now).is_empty(),
                "{state:?}"
            );
        }
    }

    #[test]
    fn an_unclassified_camera_is_due_at_once_then_backs_off() {
        // A daemon start or a replug: classified on the next poll, not when
        // a client happens to list the cameras.
        let mut classifier = RoleClassifier::default();
        let start = Instant::now();
        let listed = view(CameraInventoryState::Current, &[("a", 1)]);
        assert_eq!(classifier.due(&listed, start), [key("a", 1)]);
        assert!(classifier.tried(&[key("a", 1)], start).is_empty());
        assert!(classifier.due(&listed, start + POLL).is_empty());
        assert_eq!(
            classifier.due(&listed, start + RETRY_AFTER[0]),
            [key("a", 1)]
        );
    }

    #[test]
    fn a_generation_that_stays_unclassified_stops_after_max_tries() {
        let mut classifier = RoleClassifier::default();
        let listed = view(CameraInventoryState::Current, &[("a", 1)]);
        let mut now = Instant::now();
        let mut exhausted = Vec::new();
        for _ in 0..MAX_TRIES {
            let due = classifier.due(&listed, now);
            assert_eq!(due, [key("a", 1)]);
            exhausted = classifier.tried(&due, now);
            now += Duration::from_secs(3600);
        }
        assert_eq!(exhausted, [key("a", 1)]);
        assert!(classifier.due(&listed, now).is_empty());
        // A replug is a new generation, due at once.
        let replugged = view(CameraInventoryState::Current, &[("a", 2)]);
        assert_eq!(classifier.due(&replugged, now), [key("a", 2)]);
    }

    #[test]
    fn a_camera_that_returns_unclassified_after_each_scan_is_scanned_ever_less_often() {
        // A camera answering each open with a udev change is a new
        // generation every time; the gap between scans grows to the cap.
        let mut classifier = RoleClassifier::default();
        let start = Instant::now();
        let mut now = start;
        let mut scans = Vec::new();
        for generation in 1..=200u64 {
            let listed = view(CameraInventoryState::Current, &[("a", generation)]);
            // Poll until it is due again, at most an hour on.
            let deadline = now + Duration::from_secs(3600);
            while classifier.due(&listed, now).is_empty() {
                assert!(
                    now < deadline,
                    "never due again after {} scans",
                    scans.len()
                );
                now += POLL;
            }
            classifier.scanned(&[key("a", generation)], now);
            classifier.tried(&[key("a", generation)], now);
            scans.push(now);
            if now.duration_since(start) > Duration::from_secs(4 * 3600) {
                break;
            }
        }
        let gaps: Vec<Duration> = scans.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.windows(2).all(|w| w[1] >= w[0]), "{gaps:?}");
        assert!(gaps
            .iter()
            .all(|gap| *gap <= SCAN_GAP[SCAN_GAP.len() - 1] + POLL));
        assert!(*gaps.last().unwrap() >= SCAN_GAP[SCAN_GAP.len() - 1]);
        // Four hours of a misbehaving camera open it a few dozen times, not
        // once every poll.
        assert!(scans.len() < 40, "{} scans", scans.len());
    }

    #[test]
    fn a_throttled_camera_never_delays_another_and_a_quiet_period_ends_its_run() {
        let mut classifier = RoleClassifier::default();
        let mut now = Instant::now();
        // Camera `a` has come back unclassified enough to be spaced out.
        for generation in 1..=SCAN_GAP.len() as u64 {
            classifier.scanned(&[key("a", generation)], now);
            now += POLL;
        }
        let a_again = view(CameraInventoryState::Current, &[("a", 99)]);
        assert!(classifier.due(&a_again, now).is_empty());
        // A different camera plugged in meanwhile is due at once.
        let both = view(CameraInventoryState::Current, &[("a", 99), ("b", 1)]);
        assert_eq!(classifier.due(&both, now), [key("b", 1)]);
        assert_eq!(classifier.scanned(&[key("b", 1)], now), 1);
        // After a quiet quarter hour, `a` starts a fresh run.
        let later = now + RUN_ENDS_AFTER;
        assert_eq!(classifier.due(&a_again, later), [key("a", 99)]);
        assert_eq!(classifier.scanned(&[key("a", 99)], later), 1);
    }

    #[test]
    fn a_classified_camera_is_forgotten_and_others_keep_their_tries() {
        let mut classifier = RoleClassifier::default();
        let now = Instant::now();
        let both = view(CameraInventoryState::Current, &[("a", 1), ("b", 1)]);
        let due = classifier.due(&both, now);
        assert_eq!(due, [key("a", 1), key("b", 1)]);
        classifier.tried(&due, now);
        // `a` got its roles; `b` waits out its backoff.
        let only_b = view(CameraInventoryState::Current, &[("b", 1)]);
        assert!(classifier.due(&only_b, now + POLL).is_empty());
        assert_eq!(classifier.tries.len(), 1);
        assert_eq!(classifier.due(&only_b, now + RETRY_AFTER[0]), [key("b", 1)]);
    }
}
