// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Non-granting synthetic inventory and lease/open recorder for request tests.
//! No device is opened. Backend opens always return an error.

use super::*;
use std::{marker::PhantomData, rc::Rc};

/// One endpoint's offered formats; roles use the production format classifier.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub path: String,
    pub formats: Vec<[u8; 4]>,
}

/// Synthetic USB facts, distinct from hardware qualification or negotiation.
#[derive(Clone, Debug)]
pub struct Camera {
    pub topology: String,
    pub identity: String,
    pub fixed: bool,
    pub controller: String,
    pub domain: irlume_common::split_key::SplitDomain,
    pub ports: Vec<u8>,
    pub endpoints: Vec<Endpoint>,
}

/// Calls at the actual camera boundary, including refused lease attempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Lease {
        endpoints: Vec<String>,
        kind: CameraOperationKind,
    },
    OpenRgb(String),
    OpenIr(String),
    Scan,
}

struct Recorder(Arc<Mutex<Vec<Call>>>, BTreeMap<String, String>);

impl Recorder {
    fn record(&self, call: Call) {
        self.0.lock().expect("fixture recorder poisoned").push(call);
    }
}

impl CameraBackend for Recorder {
    fn fixture_identity(&self, endpoint: &str) -> Option<String> {
        self.1.get(endpoint).cloned()
    }
    fn lease_requested(&self, endpoints: &[&str], kind: CameraOperationKind) {
        self.record(Call::Lease {
            endpoints: endpoints
                .iter()
                .map(|endpoint| (*endpoint).to_owned())
                .collect(),
            kind,
        });
    }
    fn scan_nodes(&self) -> NodeScan {
        self.record(Call::Scan);
        NodeScan::default()
    }
    fn discovery_scan(&self) -> NodeScan {
        self.scan_nodes()
    }
    fn pairing_scan(&self) -> (NodeScan, Vec<CameraPair>) {
        (self.scan_nodes(), Vec::new())
    }
    fn open_rgb(&self, device: &str, _lease: CameraLease) -> irlume_common::Result<RgbCamera> {
        self.record(Call::OpenRgb(device.into()));
        Err(irlume_common::Error::Hardware(
            "fixture RGB open refused".into(),
        ))
    }
    fn open_ir(&self, device: &str, _lease: CameraLease) -> irlume_common::Result<IrCamera> {
        self.record(Call::OpenIr(device.into()));
        Err(irlume_common::Error::Hardware(
            "fixture IR open refused".into(),
        ))
    }
}

/// Restores the installing thread's supervisor on drop. Cannot move threads.
pub struct Guard {
    previous: Option<Arc<CameraSupervisor>>,
    calls: Arc<Mutex<Vec<Call>>>,
    _thread: PhantomData<Rc<()>>,
}

impl Guard {
    /// Publish classified synthetic facts on this thread without discovery I/O.
    ///
    /// # Errors
    /// Refuses invalid physical identities or inventory reconciliation.
    pub fn install(cameras: &[Camera]) -> irlume_common::Result<Self> {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let identities = cameras
            .iter()
            .flat_map(|camera| {
                camera
                    .endpoints
                    .iter()
                    .map(|endpoint| (endpoint.path.clone(), camera.identity.to_lowercase()))
            })
            .collect();
        let supervisor = Arc::new(CameraSupervisor::new(Recorder(calls.clone(), identities)));
        let observations = cameras
            .iter()
            .map(|camera| {
                Ok(CameraObservation::with_lifecycle_evidence_and_endpoints(
                    crate::contracts::BackendKind::UvcV4l2,
                    crate::contracts::PhysicalCameraId::new(&camera.topology, None)
                        .map_err(|error| irlume_common::Error::Protocol(error.to_string()))?,
                    crate::contracts::CameraCapabilities::default(),
                    vec!["synthetic-format-fixture".into()],
                    camera
                        .endpoints
                        .iter()
                        .map(|endpoint| endpoint.path.clone())
                        .collect(),
                )
                .with_usb_device(Some(
                    crate::inventory::UsbDeviceFacts::new(camera.identity.clone(), camera.fixed)
                        .with_location(Some(crate::UsbLocation {
                            controller: camera.controller.clone(),
                            domain: match camera.domain {
                                irlume_common::split_key::SplitDomain::Usb2 => {
                                    crate::RootHubDomain::Usb2
                                }
                                irlume_common::split_key::SplitDomain::SuperSpeed => {
                                    crate::RootHubDomain::SuperSpeed
                                }
                            },
                            ports: camera.ports.clone(),
                        })),
                )))
            })
            .collect::<irlume_common::Result<Vec<_>>>()?;
        supervisor
            .reconcile_inventory(observations)
            .map_err(|error| {
                irlume_common::Error::Protocol(format!("fixture inventory refused: {error:?}"))
            })?;
        let generations = supervisor.endpoint_generations();
        supervisor.record_roles(
            &generations,
            cameras.iter().flat_map(|camera| {
                camera.endpoints.iter().map(|endpoint| {
                    (
                        endpoint.path.as_str(),
                        crate::role_from_formats(&endpoint.formats),
                    )
                })
            }),
        );
        let previous = TEST_SUPERVISOR.with(|slot| slot.borrow_mut().replace(supervisor));
        Ok(Self {
            previous,
            calls,
            _thread: PhantomData,
        })
    }

    /// Recorded boundary calls; a backend open never succeeds.
    ///
    /// # Panics
    /// Panics if a preceding test poisoned the recorder mutex.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .expect("fixture recorder poisoned")
            .clone()
    }

    /// Observe real lease ownership/wait registration from a coordinating thread.
    /// The observer cannot acquire, redirect or open a camera.
    ///
    /// # Panics
    /// Panics if this guard is not installed or a test poisoned lease state.
    pub fn lease_counts_observer(&self) -> impl Fn() -> (usize, usize) + Send + Sync + 'static {
        let leases = TEST_SUPERVISOR.with(|slot| {
            Arc::clone(
                &slot
                    .borrow()
                    .as_ref()
                    .expect("installed fixture supervisor")
                    .leases,
            )
        });
        move || leases.counts_for_test()
    }

    /// Invalidate only this synthetic publication from a coordinating thread.
    /// This callback cannot refresh facts, acquire a lease or open a camera.
    ///
    /// # Panics
    /// Panics if no fixture is installed or the fixture inventory was poisoned.
    pub fn invalidation_observer(&self) -> impl Fn() + Send + Sync + 'static {
        let inventory = TEST_SUPERVISOR.with(|slot| {
            Arc::clone(
                &slot
                    .borrow()
                    .as_ref()
                    .expect("installed fixture supervisor")
                    .inventory,
            )
        });
        move || {
            inventory
                .lock()
                .expect("fixture inventory poisoned")
                .invalidate_all()
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = TEST_SUPERVISOR.try_with(|slot| *slot.borrow_mut() = previous);
    }
}

/// Exercise the native GREY decoder on a fixed synthetic 2x2 payload.
/// This is format-domain evidence, never a negotiated stream or biometric frame.
#[must_use]
pub fn grey_fixture() -> Vec<u8> {
    crate::decode_ir(&[0, 64, 128, 255], crate::IrPixel::Grey8, 2, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication_fixture() -> Guard {
        Guard::install(&[Camera {
            topology: "/devices/fixture/publication".into(),
            identity: "1234:0001:publication".into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![8],
            endpoints: vec![
                Endpoint {
                    path: "/dev/publication-rgb".into(),
                    formats: vec![*b"YUYV"],
                },
                Endpoint {
                    path: "/dev/publication-ir".into(),
                    formats: vec![*b"GREY"],
                },
            ],
        }])
        .unwrap()
    }

    fn publication_expectation() -> crate::lease::OrdinaryLeaseRequest {
        let view = crate::connected_pairs();
        crate::lease::OrdinaryLeaseRequest {
            supervisor_id: view.supervisor_id.unwrap(),
            pair: view.pairs[0].clone(),
        }
    }

    #[test]
    fn selected_publication_refuses_changed_facts_without_invoking_the_publisher() {
        let guard = publication_fixture();
        let expected = publication_expectation();
        assert_eq!(
            crate::with_selected_camera_publication(&expected, || 7).unwrap(),
            7
        );
        let mut wrong = Vec::new();
        let mut changed = expected.clone();
        changed.supervisor_id = "99999999999999999999999999999999".into();
        wrong.push(changed);
        let mut changed = expected.clone();
        changed.pair.generation += 1;
        wrong.push(changed);
        let mut changed = expected.clone();
        std::mem::swap(&mut changed.pair.rgb, &mut changed.pair.ir);
        wrong.push(changed);
        let mut changed = expected.clone();
        changed.pair.identity = "1234:0001:other".into();
        wrong.push(changed);
        let calls = std::cell::Cell::new(0);
        for changed in wrong {
            assert!(matches!(
                crate::with_selected_camera_publication(&changed, || calls.set(calls.get() + 1)),
                Err(CameraLeaseError::Stale)
            ));
        }
        guard.invalidation_observer()();
        assert!(matches!(
            crate::with_selected_camera_publication(&expected, || calls.set(calls.get() + 1)),
            Err(CameraLeaseError::Stale)
        ));
        assert_eq!(calls.get(), 0);
        assert!(
            guard.calls().is_empty(),
            "publication must neither acquire nor open a camera"
        );
    }

    #[test]
    fn selected_publication_excludes_inventory_writers_and_preserves_visible_receipt() {
        let guard = publication_fixture();
        let expected = publication_expectation();
        let inventory =
            TEST_SUPERVISOR.with(|slot| slot.borrow().as_ref().unwrap().inventory.clone());
        let receipt = crate::with_selected_camera_publication(&expected, || {
            std::thread::scope(|threads| {
                assert!(threads
                    .spawn(|| matches!(
                        inventory.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ))
                    .join()
                    .unwrap());
            });
            irlume_common::AtomicWrite::VisibleNotDurable(std::io::Error::other(
                "publication receipt",
            ))
        })
        .unwrap();
        assert!(
            matches!(receipt, irlume_common::AtomicWrite::VisibleNotDurable(ref error) if error.to_string() == "publication receipt")
        );
        assert!(inventory.try_lock().is_ok());
        assert!(guard.calls().is_empty());
    }

    #[test]
    fn ordinary_fixture_reaches_real_lease_and_recorded_open_without_a_device() {
        let guard = Guard::install(&[Camera {
            topology: "/devices/fixture/ordinary".into(),
            identity: "1234:0001:ordinary".into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: irlume_common::split_key::SplitDomain::Usb2,
            ports: vec![8],
            endpoints: vec![
                Endpoint {
                    path: "/dev/fixture-rgb".into(),
                    formats: vec![*b"YUYV"],
                },
                Endpoint {
                    path: "/dev/fixture-ir".into(),
                    formats: vec![*b"GREY"],
                },
            ],
        }])
        .unwrap();
        assert_eq!(grey_fixture(), [0, 64, 128, 255]);
        let pairs = crate::connected_pairs();
        assert_eq!(pairs.state, CameraInventoryState::Current);
        assert_eq!(pairs.pairs.len(), 1);
        assert_eq!(
            crate::device_identity("/dev/fixture-rgb").as_deref(),
            Some("1234:0001:ordinary")
        );
        assert_eq!(
            crate::camera_inventory_snapshot().state,
            CameraInventoryState::Current
        );
        let operation = crate::lease::acquire_camera_operation(
            &["/dev/fixture-rgb", "/dev/fixture-ir"],
            CameraOperationKind::Authentication,
            std::time::Duration::ZERO,
        )
        .unwrap();
        assert!(operation.open_rgb("/dev/fixture-rgb").is_err());
        assert_eq!(
            guard.calls(),
            vec![
                Call::Lease {
                    endpoints: vec!["/dev/fixture-rgb".into(), "/dev/fixture-ir".into()],
                    kind: CameraOperationKind::Authentication,
                },
                Call::OpenRgb("/dev/fixture-rgb".into())
            ]
        );
    }
}
