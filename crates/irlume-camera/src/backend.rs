// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Crate-private capture-backend ownership and operation routing.

use irlume_common::live_camera::{
    CameraInventoryReason, CameraInventorySnapshot, CameraInventoryState,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use crate::connected::ConnectedPairs;
use crate::contracts::CameraDescriptor;
use crate::inventory::{
    CameraInventory, CameraInventoryError, CameraInventoryEvent, CameraObservation,
    EndpointGeneration,
};
use crate::lease::{
    CameraLease, CameraLeaseError, CameraOperationKind, CameraOperationSession, LeaseAuthority,
};
use crate::{CameraPair, IrCamera, NodeScan, RgbCamera, Role};

/// One capture implementation owned by the process camera supervisor.
trait CameraBackend: Send + Sync + 'static {
    fn scan_nodes(&self) -> NodeScan;
    /// The scan discovery runs, without the holder lookup of `scan_nodes`.
    /// Discovery callers receive only its `classified` bucket.
    fn discovery_scan(&self) -> NodeScan;
    /// The same scan and the pairs made from its `classified` bucket.
    /// Pairing callers receive only the pairs.
    fn pairing_scan(&self) -> (NodeScan, Vec<CameraPair>);
    fn open_rgb(&self, device: &str, lease: CameraLease) -> irlume_common::Result<RgbCamera>;
    fn open_ir(&self, device: &str, lease: CameraLease) -> irlume_common::Result<IrCamera>;

    #[cfg(test)]
    fn has_exact_production_uvc_delegates(&self) -> bool {
        false
    }
}

/// Process component that owns camera backend instances and routes operations.
///
/// Inventory mutation is isolated from capture routing. Leases and hotplug event
/// subscription remain later slices and therefore cannot alter behavior here.
/// Scan, discovery and pairing answers it routes are also kept against the
/// inventory generation they ran under, for the camera-free pairing view
/// (ADR-0029 §1).
pub(crate) struct CameraSupervisor {
    backend: Arc<dyn CameraBackend>,
    inventory: Arc<Mutex<CameraInventory>>,
    leases: Arc<LeaseAuthority>,
}

impl CameraSupervisor {
    fn new(backend: impl CameraBackend) -> Self {
        Self::from_arc(Arc::new(backend))
    }

    fn from_arc(backend: Arc<dyn CameraBackend>) -> Self {
        Self {
            backend,
            inventory: Arc::new(Mutex::new(CameraInventory::new())),
            leases: Arc::new(LeaseAuthority::default()),
        }
    }

    fn inventory_snapshot(&self) -> CameraInventorySnapshot {
        match self.inventory.lock() {
            Ok(inventory) => inventory.snapshot(),
            Err(_) => CameraInventorySnapshot {
                state: CameraInventoryState::Unavailable,
                reason: Some(CameraInventoryReason::Inventory),
                ..Default::default()
            },
        }
    }

    pub(crate) fn mark_inventory_unavailable(
        &self,
        reason: CameraInventoryReason,
    ) -> Result<(), CameraInventoryError> {
        self.inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?
            .mark_unavailable(reason);
        Ok(())
    }

    pub(crate) fn retire_inventory_unavailable(
        &self,
        reason: CameraInventoryReason,
    ) -> Result<(), CameraInventoryError> {
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?;
        inventory.retire_unavailable(reason);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn reconcile_inventory(
        &self,
        observations: Vec<CameraObservation>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
        self.inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?
            .reconcile(observations)
    }

    pub(crate) fn reconcile_inventory_guarded<F>(
        &self,
        observations: Vec<CameraObservation>,
        quiet: F,
    ) -> Result<(Vec<CameraInventoryEvent>, bool), CameraInventoryError>
    where
        F: FnMut() -> bool,
    {
        self.inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?
            .reconcile_guarded(observations, quiet)
    }

    pub(crate) fn invalidate_inventory(&self) -> Result<(), CameraInventoryError> {
        self.inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?
            .invalidate_all();
        Ok(())
    }

    pub(crate) fn invalidate_inventory_topologies(
        &self,
        topologies: &std::collections::BTreeSet<String>,
    ) -> Result<(), CameraInventoryError> {
        self.inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?
            .invalidate_topologies(topologies);
        Ok(())
    }

    pub(crate) fn retire_inventory_topologies(
        &self,
        topologies: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
        Ok(self
            .inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?
            .retire_topologies(topologies))
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "later frame and session slices validate descriptors"
        )
    )]
    pub(crate) fn validate_descriptor(
        &self,
        descriptor: &CameraDescriptor,
    ) -> Result<(), CameraInventoryError> {
        self.inventory
            .lock()
            .map_err(|_| CameraInventoryError::Poisoned)?
            .validate(descriptor)
    }

    pub(crate) fn acquire_operation(
        &self,
        endpoint_paths: &[&str],
        operation: CameraOperationKind,
        deadline: Instant,
    ) -> Result<CameraOperationSession, CameraLeaseError> {
        let reference = self
            .inventory
            .lock()
            .map_err(|_| CameraLeaseError::Poisoned)?
            .reference_for_endpoints(endpoint_paths)
            .map_err(|error| match error {
                CameraInventoryError::UnknownCamera => CameraLeaseError::UnknownEndpoint,
                _ => CameraLeaseError::Stale,
            })?;
        let lease = CameraLease::acquire(
            &self.leases,
            self.inventory.clone(),
            vec![reference],
            operation,
            deadline,
        )?;
        Ok(CameraOperationSession::new(lease))
    }

    fn scan_nodes(&self) -> NodeScan {
        let before = self.endpoint_generations();
        let scan = self.backend.scan_nodes();
        self.record_scan(&before, &scan);
        scan
    }

    fn discover_nodes(&self) -> Vec<(String, Role)> {
        let before = self.endpoint_generations();
        let scan = self.backend.discovery_scan();
        self.record_scan(&before, &scan);
        scan.classified
    }

    fn list_pairs(&self) -> Vec<CameraPair> {
        let before = self.endpoint_generations();
        let (scan, pairs) = self.backend.pairing_scan();
        self.record_scan(&before, &scan);
        pairs
    }

    /// The published endpoints' generations, copied under the inventory lock
    /// and released before any backend call: classification takes leases,
    /// which lock the inventory themselves.
    fn endpoint_generations(&self) -> BTreeMap<String, EndpointGeneration> {
        self.inventory
            .lock()
            .map(|inventory| inventory.endpoint_generations())
            .unwrap_or_default()
    }

    /// Keep every answer a scan that already ran gave: its RGB and IR nodes,
    /// and as `Role::Other` the nodes that answered as neither (a metadata
    /// node among them). A metadata node the media graph did not place is
    /// not among a camera's metadata endpoints, so it needs that recorded
    /// answer before the camera can pair. Unreadable and MC-centric nodes
    /// gave no role.
    fn record_scan(&self, before: &BTreeMap<String, EndpointGeneration>, scan: &NodeScan) {
        self.record_roles(
            before,
            scan.classified
                .iter()
                .map(|(path, role)| (path.as_str(), *role))
                .chain(scan.other.iter().map(|path| (path.as_str(), Role::Other))),
        );
    }

    /// Keep what a discovery that already ran answered, bound to the
    /// generation it ran under (ADR-0029 §1). Never opens, never changes the
    /// answer; a poisoned inventory records nothing.
    fn record_roles<'a>(
        &self,
        before: &BTreeMap<String, EndpointGeneration>,
        classified: impl IntoIterator<Item = (&'a str, Role)>,
    ) {
        if before.is_empty() {
            return;
        }
        if let Ok(mut inventory) = self.inventory.lock() {
            inventory.record_roles(before, classified);
        }
    }

    fn connected_pairs(&self) -> ConnectedPairs {
        match self.inventory.lock() {
            Ok(inventory) => inventory.connected_pairs(),
            Err(_) => ConnectedPairs {
                state: CameraInventoryState::Unavailable,
                reason: Some(CameraInventoryReason::Inventory),
                ..Default::default()
            },
        }
    }

    fn open_rgb(&self, device: &str, lease: CameraLease) -> irlume_common::Result<RgbCamera> {
        self.backend.open_rgb(device, lease)
    }

    fn open_ir(&self, device: &str, lease: CameraLease) -> irlume_common::Result<IrCamera> {
        self.backend.open_ir(device, lease)
    }
}

/// Existing direct V4L2 backend for video-node-centric UVC cameras.
///
/// This delegates to the pre-existing direct functions without changing their
/// probing, pairing, negotiation, privacy, or emitter behavior.
type ScanNodes = fn() -> NodeScan;
type DiscoveryScan = fn() -> NodeScan;
type PairingScan = fn() -> (NodeScan, Vec<CameraPair>);
type OpenRgb = fn(&str, CameraLease) -> irlume_common::Result<RgbCamera>;
type OpenIr = fn(&str, CameraLease) -> irlume_common::Result<IrCamera>;

fn production_scan_nodes() -> NodeScan {
    crate::uvc_scan(true)
}

fn production_discovery_scan() -> NodeScan {
    crate::uvc_scan(false)
}

fn production_pairing_scan() -> (NodeScan, Vec<CameraPair>) {
    crate::uvc_pairing_scan()
}

fn production_open_rgb(device: &str, lease: CameraLease) -> irlume_common::Result<RgbCamera> {
    RgbCamera::open_uvc(device, lease)
}

fn production_open_ir(device: &str, lease: CameraLease) -> irlume_common::Result<IrCamera> {
    IrCamera::open_uvc(device, lease)
}

#[derive(Clone, Copy)]
struct UvcV4l2Backend {
    scan_nodes: ScanNodes,
    discovery_scan: DiscoveryScan,
    pairing_scan: PairingScan,
    open_rgb: OpenRgb,
    open_ir: OpenIr,
}

impl Default for UvcV4l2Backend {
    fn default() -> Self {
        Self {
            scan_nodes: production_scan_nodes,
            discovery_scan: production_discovery_scan,
            pairing_scan: production_pairing_scan,
            open_rgb: production_open_rgb,
            open_ir: production_open_ir,
        }
    }
}

impl CameraBackend for UvcV4l2Backend {
    fn scan_nodes(&self) -> NodeScan {
        (self.scan_nodes)()
    }

    fn discovery_scan(&self) -> NodeScan {
        (self.discovery_scan)()
    }

    fn pairing_scan(&self) -> (NodeScan, Vec<CameraPair>) {
        (self.pairing_scan)()
    }

    fn open_rgb(&self, device: &str, lease: CameraLease) -> irlume_common::Result<RgbCamera> {
        (self.open_rgb)(device, lease)
    }

    fn open_ir(&self, device: &str, lease: CameraLease) -> irlume_common::Result<IrCamera> {
        (self.open_ir)(device, lease)
    }

    #[cfg(test)]
    fn has_exact_production_uvc_delegates(&self) -> bool {
        std::ptr::fn_addr_eq(self.scan_nodes, production_scan_nodes as ScanNodes)
            && std::ptr::fn_addr_eq(
                self.discovery_scan,
                production_discovery_scan as DiscoveryScan,
            )
            && std::ptr::fn_addr_eq(self.pairing_scan, production_pairing_scan as PairingScan)
            && std::ptr::fn_addr_eq(self.open_rgb, production_open_rgb as OpenRgb)
            && std::ptr::fn_addr_eq(self.open_ir, production_open_ir as OpenIr)
    }
}

static DEFAULT_CAMERA_SUPERVISOR: OnceLock<Arc<CameraSupervisor>> = OnceLock::new();

fn snapshot_from_slot(slot: &OnceLock<Arc<CameraSupervisor>>) -> CameraInventorySnapshot {
    slot.get()
        .map_or_else(CameraInventorySnapshot::default, |supervisor| {
            supervisor.inventory_snapshot()
        })
}

pub(crate) fn camera_inventory_snapshot() -> CameraInventorySnapshot {
    snapshot_from_slot(&DEFAULT_CAMERA_SUPERVISOR)
}

fn connected_pairs_from_slot(slot: &OnceLock<Arc<CameraSupervisor>>) -> ConnectedPairs {
    slot.get()
        .map_or_else(ConnectedPairs::default, |supervisor| {
            supervisor.connected_pairs()
        })
}

/// Read the pairing view without initializing the supervisor.
pub(crate) fn connected_pairs() -> ConnectedPairs {
    #[cfg(test)]
    if let Some(supervisor) = TEST_SUPERVISOR.with(|slot| slot.borrow().clone()) {
        return supervisor.connected_pairs();
    }
    connected_pairs_from_slot(&DEFAULT_CAMERA_SUPERVISOR)
}

pub(crate) fn default_camera_supervisor() -> &'static CameraSupervisor {
    DEFAULT_CAMERA_SUPERVISOR
        .get_or_init(|| {
            let supervisor = Arc::new(CameraSupervisor::new(UvcV4l2Backend::default()));
            if let Err(error) = crate::lifecycle::spawn(Arc::downgrade(&supervisor)) {
                eprintln!("irlume: camera lifecycle monitor unavailable: {error}");
            }
            supervisor
        })
        .as_ref()
}

#[cfg(test)]
thread_local! {
    static TEST_SUPERVISOR: std::cell::RefCell<Option<Arc<CameraSupervisor>>> =
        const { std::cell::RefCell::new(None) };
}

/// Route one compatibility operation through the process supervisor.
pub(crate) fn with_camera_supervisor<T>(operation: impl FnOnce(&CameraSupervisor) -> T) -> T {
    #[cfg(test)]
    if let Some(supervisor) = TEST_SUPERVISOR.with(|slot| slot.borrow().clone()) {
        return operation(&supervisor);
    }

    operation(default_camera_supervisor())
}

pub(crate) fn scan_nodes() -> NodeScan {
    with_camera_supervisor(CameraSupervisor::scan_nodes)
}

pub(crate) fn discover_nodes() -> Vec<(String, Role)> {
    with_camera_supervisor(CameraSupervisor::discover_nodes)
}

pub(crate) fn list_pairs() -> Vec<CameraPair> {
    with_camera_supervisor(CameraSupervisor::list_pairs)
}

pub(crate) fn open_rgb(device: &str, lease: CameraLease) -> irlume_common::Result<RgbCamera> {
    with_camera_supervisor(|supervisor| supervisor.open_rgb(device, lease))
}

pub(crate) fn open_ir(device: &str, lease: CameraLease) -> irlume_common::Result<IrCamera> {
    with_camera_supervisor(|supervisor| supervisor.open_ir(device, lease))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::contracts::CameraInstanceId;
    use crate::inventory::fixtures::ObservationFixture;
    use crate::{FailedAt, McCentric, Unreadable};

    struct TestBackendGuard(Option<Arc<CameraSupervisor>>);

    impl Drop for TestBackendGuard {
        fn drop(&mut self) {
            let previous = self.0.take();
            TEST_SUPERVISOR.with(|slot| *slot.borrow_mut() = previous);
        }
    }

    fn install_test_supervisor(supervisor: Arc<CameraSupervisor>) -> TestBackendGuard {
        let previous = TEST_SUPERVISOR.with(|slot| slot.borrow_mut().replace(supervisor));
        TestBackendGuard(previous)
    }

    fn seed_test_endpoints(supervisor: &CameraSupervisor, endpoints: &[&str]) {
        supervisor
            .reconcile_inventory(vec![
                CameraObservation::with_lifecycle_evidence_and_endpoints(
                    crate::contracts::BackendKind::UvcV4l2,
                    crate::contracts::PhysicalCameraId::new("/devices/test/camera", None).unwrap(),
                    crate::contracts::CameraCapabilities::default(),
                    vec!["test-evidence".into()],
                    endpoints.iter().map(|path| (*path).to_owned()).collect(),
                ),
            ])
            .unwrap();
    }

    pub(crate) fn with_test_camera_operation<R>(
        endpoint: &str,
        work: impl FnOnce(&CameraOperationSession) -> R,
    ) -> R {
        let supervisor = Arc::new(CameraSupervisor::new(RecordingBackend::new(Arc::new(
            Mutex::new(Vec::new()),
        ))));
        seed_test_endpoints(&supervisor, &[endpoint]);
        let _installed = install_test_supervisor(supervisor.clone());
        let operation = supervisor
            .acquire_operation(
                &[endpoint],
                CameraOperationKind::Authentication,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap();
        work(&operation)
    }

    type ClassificationHook = Box<dyn FnOnce() + Send>;

    #[derive(Clone)]
    struct RecordingBackend {
        calls: Arc<Mutex<Vec<String>>>,
        /// The report and discovery scans' classified answer; `None` keeps
        /// the spy nodes.
        nodes: Option<Vec<(String, Role)>>,
        /// Every scan's nodes that answered as neither RGB nor IR.
        other: Vec<String>,
        /// Pairing's answer; `None` keeps the spy pair.
        pairs: Option<Vec<CameraPair>>,
        /// Runs once inside the next scan, discovery or pairing call, after
        /// the supervisor's first inventory read and before its second.
        during_classification: Arc<Mutex<Option<ClassificationHook>>>,
    }

    impl RecordingBackend {
        fn new(calls: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                calls,
                nodes: None,
                other: Vec::new(),
                pairs: None,
                during_classification: Arc::default(),
            }
        }

        fn discovering(mut self, nodes: &[(&str, Role)]) -> Self {
            self.nodes = Some(owned(nodes));
            self
        }

        fn answering_other(mut self, other: &[&str]) -> Self {
            self.other = other.iter().map(|path| (*path).to_owned()).collect();
            self
        }

        fn pairing(mut self, pairs: Vec<CameraPair>) -> Self {
            self.pairs = Some(pairs);
            self
        }

        /// Arm the hook for the next scan, discovery or pairing call.
        fn on_next_classification(&self, hook: impl FnOnce() + Send + 'static) {
            *self
                .during_classification
                .lock()
                .expect("hook lock poisoned") = Some(Box::new(hook));
        }

        fn run_hook(&self) {
            let hook = self
                .during_classification
                .lock()
                .expect("hook lock poisoned")
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }

        fn record(&self, call: impl Into<String>) {
            self.calls
                .lock()
                .expect("recording lock poisoned")
                .push(call.into());
        }
    }

    fn owned(nodes: &[(&str, Role)]) -> Vec<(String, Role)> {
        nodes
            .iter()
            .map(|(path, role)| ((*path).to_owned(), *role))
            .collect()
    }

    /// A pairing answer; the spy's pairing scan classifies only its `rgb`
    /// and `ir`.
    fn spy_pair(rgb: &str, ir: &str) -> CameraPair {
        CameraPair {
            rgb: rgb.into(),
            ir: ir.into(),
            id: None,
            fixed: false,
            name: None,
            identity: None,
            serial_present: false,
            port_chain: None,
            descriptor_token: None,
        }
    }

    #[test]
    fn live_inventory_getter_does_not_initialize_or_call_backend() {
        let slot = OnceLock::new();
        assert_eq!(
            snapshot_from_slot(&slot),
            CameraInventorySnapshot::default()
        );
        assert!(
            slot.get().is_none(),
            "reading status must not initialize a supervisor"
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        let supervisor = Arc::new(CameraSupervisor::new(RecordingBackend::new(calls.clone())));
        seed_test_endpoints(&supervisor, &["/dev/video0"]);
        assert!(slot.set(supervisor).is_ok());
        let snapshot = snapshot_from_slot(&slot);
        assert_eq!(snapshot.state, CameraInventoryState::Current);
        assert_eq!(snapshot.candidates[0].endpoint_paths, ["/dev/video0"]);
        assert!(
            calls.lock().unwrap().is_empty(),
            "status called a discovery/open delegate"
        );
    }

    #[test]
    fn live_inventory_poisoned_mutex_is_unavailable_not_a_recovered_old_snapshot() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let supervisor = Arc::new(CameraSupervisor::new(RecordingBackend::new(calls)));
        seed_test_endpoints(&supervisor, &["/dev/video0"]);
        let poison = supervisor.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison.inventory.lock().unwrap();
            panic!("synthetic poison");
        })
        .join();
        let snapshot = supervisor.inventory_snapshot();
        assert_eq!(snapshot.state, CameraInventoryState::Unavailable);
        assert_eq!(snapshot.reason, Some(CameraInventoryReason::Inventory));
        assert!(snapshot.candidates.is_empty());
    }

    #[test]
    fn live_inventory_snapshot_does_not_acquire_or_extend_an_operation_permit() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let supervisor = CameraSupervisor::new(RecordingBackend::new(calls));
        seed_test_endpoints(&supervisor, &["/dev/video0"]);
        let operation = supervisor
            .acquire_operation(&["/dev/video0"], CameraOperationKind::Setup, Instant::now())
            .unwrap();
        let snapshot = supervisor.inventory_snapshot();
        drop(operation);
        let next = supervisor.acquire_operation(
            &["/dev/video0"],
            CameraOperationKind::Diagnostics,
            Instant::now(),
        );
        assert!(
            next.is_ok(),
            "retaining the snapshot must not retain the permit"
        );
        assert_eq!(snapshot.state, CameraInventoryState::Current);
    }

    impl CameraBackend for RecordingBackend {
        fn scan_nodes(&self) -> NodeScan {
            self.record("scan_nodes");
            self.run_hook();
            NodeScan {
                classified: self
                    .nodes
                    .clone()
                    .unwrap_or_else(|| vec![("/dev/spy-scan".into(), Role::Rgb)]),
                other: self.other.clone(),
                ..NodeScan::default()
            }
        }

        fn discovery_scan(&self) -> NodeScan {
            self.record("discovery_scan");
            self.run_hook();
            NodeScan {
                classified: self.nodes.clone().unwrap_or_else(|| {
                    vec![
                        ("/dev/spy-ir".into(), Role::Ir),
                        ("/dev/spy-rgb".into(), Role::Rgb),
                    ]
                }),
                other: self.other.clone(),
                ..NodeScan::default()
            }
        }

        fn pairing_scan(&self) -> (NodeScan, Vec<CameraPair>) {
            self.record("pairing_scan");
            self.run_hook();
            let pairs = self.pairs.clone().unwrap_or_else(|| {
                vec![CameraPair {
                    rgb: "/dev/spy-rgb".into(),
                    ir: "/dev/spy-ir".into(),
                    id: Some("1234:5678".into()),
                    fixed: true,
                    name: Some("Spy Camera".into()),
                    identity: Some("1234:5678".into()),
                    serial_present: false,
                    port_chain: None,
                    descriptor_token: None,
                }]
            });
            let scan = NodeScan {
                classified: pairs
                    .iter()
                    .flat_map(|pair| [(pair.rgb.clone(), Role::Rgb), (pair.ir.clone(), Role::Ir)])
                    .collect(),
                other: self.other.clone(),
                ..NodeScan::default()
            };
            (scan, pairs)
        }

        fn open_rgb(&self, device: &str, _: CameraLease) -> irlume_common::Result<RgbCamera> {
            self.record(format!("open_rgb:{device}"));
            Err(irlume_common::Error::Hardware("spy RGB refusal".into()))
        }

        fn open_ir(&self, device: &str, _: CameraLease) -> irlume_common::Result<IrCamera> {
            self.record(format!("open_ir:{device}"));
            Err(irlume_common::Error::Hardware("spy IR refusal".into()))
        }
    }

    fn fixture_scan_nodes() -> NodeScan {
        NodeScan {
            other: Vec::new(),
            classified: vec![
                ("/dev/fixture-rgb".into(), Role::Rgb),
                ("/dev/fixture-ir".into(), Role::Ir),
            ],
            unreadable: vec![Unreadable {
                path: "/dev/fixture-busy".into(),
                at: FailedAt::Open,
                errno: Some(libc::EBUSY),
                holder: Some("fixture-holder".into()),
            }],
            mc_centric: vec![(
                "/dev/fixture-mc".into(),
                McCentric {
                    driver: "fixture-driver".into(),
                    io_mc: true,
                    mplane_only: true,
                },
            )],
            listing_error: Some("fixture listing warning".into()),
        }
    }

    fn fixture_discovery_scan() -> NodeScan {
        NodeScan {
            classified: vec![
                ("/dev/fixture-ir".into(), Role::Ir),
                ("/dev/fixture-rgb".into(), Role::Rgb),
            ],
            other: vec!["/dev/fixture-meta".into()],
            ..NodeScan::default()
        }
    }

    fn fixture_pairing_scan() -> (NodeScan, Vec<CameraPair>) {
        let scan = NodeScan {
            classified: vec![
                ("/dev/fixed-rgb".into(), Role::Rgb),
                ("/dev/fixed-ir".into(), Role::Ir),
                ("/dev/usb-rgb".into(), Role::Rgb),
                ("/dev/usb-ir".into(), Role::Ir),
            ],
            other: vec!["/dev/fixture-meta".into()],
            ..NodeScan::default()
        };
        let pairs = vec![
            CameraPair {
                rgb: "/dev/fixed-rgb".into(),
                ir: "/dev/fixed-ir".into(),
                id: Some("1111:2222".into()),
                fixed: true,
                name: Some("Fixture Built-in".into()),
                identity: Some("1111:2222:fx1".into()),
                serial_present: true,
                port_chain: None,
                descriptor_token: None,
            },
            CameraPair {
                rgb: "/dev/usb-rgb".into(),
                ir: "/dev/usb-ir".into(),
                id: None,
                fixed: false,
                name: None,
                identity: None,
                serial_present: false,
                port_chain: None,
                descriptor_token: None,
            },
        ];
        (scan, pairs)
    }

    fn fixture_open_rgb(_: &str, _: CameraLease) -> irlume_common::Result<RgbCamera> {
        Err(irlume_common::Error::Hardware("fixture RGB".into()))
    }

    fn fixture_open_ir(_: &str, _: CameraLease) -> irlume_common::Result<IrCamera> {
        Err(irlume_common::Error::Hardware("fixture IR".into()))
    }

    #[test]
    fn public_camera_entrypoints_route_through_one_supervisor_backend() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let supervisor = Arc::new(CameraSupervisor::from_arc(Arc::new(RecordingBackend::new(
            Arc::clone(&calls),
        ))));
        seed_test_endpoints(&supervisor, &["/dev/spy-rgb", "/dev/spy-ir"]);
        let _guard = install_test_supervisor(Arc::clone(&supervisor));
        with_camera_supervisor(|routed| assert!(std::ptr::eq(routed, supervisor.as_ref())));

        assert_eq!(crate::scan_nodes().classified[0].0, "/dev/spy-scan");
        assert_eq!(
            crate::discover_nodes(),
            vec![
                ("/dev/spy-ir".into(), Role::Ir),
                ("/dev/spy-rgb".into(), Role::Rgb),
            ]
        );
        let pairs = crate::list_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].rgb, "/dev/spy-rgb");
        assert_eq!(pairs[0].ir, "/dev/spy-ir");
        assert_eq!(pairs[0].id.as_deref(), Some("1234:5678"));
        assert!(pairs[0].fixed);
        assert!(RgbCamera::open("/dev/spy-rgb")
            .err()
            .expect("spy RGB open must refuse")
            .to_string()
            .contains("spy RGB refusal"));
        assert!(IrCamera::open("/dev/spy-ir")
            .err()
            .expect("spy IR open must refuse")
            .to_string()
            .contains("spy IR refusal"));

        assert_eq!(
            *calls.lock().expect("recording lock poisoned"),
            [
                "scan_nodes",
                "discovery_scan",
                "pairing_scan",
                "open_rgb:/dev/spy-rgb",
                "open_ir:/dev/spy-ir",
            ]
        );
    }

    #[test]
    fn uvc_adapter_preserves_complete_results_and_order() {
        let backend = UvcV4l2Backend {
            scan_nodes: fixture_scan_nodes,
            discovery_scan: fixture_discovery_scan,
            pairing_scan: fixture_pairing_scan,
            open_rgb: fixture_open_rgb,
            open_ir: fixture_open_ir,
        };

        let scan = backend.scan_nodes();
        assert_eq!(
            scan.classified,
            vec![
                ("/dev/fixture-rgb".into(), Role::Rgb),
                ("/dev/fixture-ir".into(), Role::Ir),
            ]
        );
        assert_eq!(scan.unreadable.len(), 1);
        assert_eq!(scan.unreadable[0].path, "/dev/fixture-busy");
        assert_eq!(scan.unreadable[0].at, FailedAt::Open);
        assert_eq!(scan.unreadable[0].errno, Some(libc::EBUSY));
        assert_eq!(scan.unreadable[0].holder.as_deref(), Some("fixture-holder"));
        assert_eq!(
            scan.mc_centric,
            vec![(
                "/dev/fixture-mc".into(),
                McCentric {
                    driver: "fixture-driver".into(),
                    io_mc: true,
                    mplane_only: true,
                },
            )]
        );
        assert_eq!(
            scan.listing_error.as_deref(),
            Some("fixture listing warning")
        );
        let discovery = backend.discovery_scan();
        assert_eq!(discovery.classified, fixture_discovery_scan().classified);
        assert_eq!(discovery.other, ["/dev/fixture-meta"]);

        let (pairing, pairs) = backend.pairing_scan();
        assert_eq!(pairing.classified, fixture_pairing_scan().0.classified);
        assert_eq!(pairing.other, ["/dev/fixture-meta"]);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].rgb, "/dev/fixed-rgb");
        assert_eq!(pairs[0].ir, "/dev/fixed-ir");
        assert_eq!(pairs[0].id.as_deref(), Some("1111:2222"));
        assert!(pairs[0].fixed);
        assert_eq!(pairs[1].rgb, "/dev/usb-rgb");
        assert_eq!(pairs[1].ir, "/dev/usb-ir");
        assert_eq!(pairs[1].id, None);
        assert!(!pairs[1].fixed);
    }

    #[test]
    fn known_invalidated_endpoint_cannot_take_the_discovery_bypass() {
        let supervisor = Arc::new(CameraSupervisor::new(UvcV4l2Backend::default()));
        seed_test_endpoints(&supervisor, &["/dev/video-test"]);
        supervisor.invalidate_inventory().unwrap();
        let _guard = install_test_supervisor(supervisor);
        assert!(matches!(
            crate::lease::permit_for_discovery(
                "/dev/video-test",
                std::time::Duration::from_millis(5)
            ),
            Err(CameraLeaseError::Stale)
        ));
    }

    #[test]
    fn supervisor_owns_and_validates_one_inventory_instance() {
        let backend = Arc::new(RecordingBackend::new(Arc::new(Mutex::new(Vec::new()))));
        let supervisor = CameraSupervisor::from_arc(backend);
        let observation = CameraObservation::new(
            crate::contracts::BackendKind::UvcV4l2,
            crate::contracts::PhysicalCameraId::new("/devices/pci/camera", None).unwrap(),
            crate::contracts::CameraCapabilities::new(
                vec![crate::contracts::StreamRole::Rgb],
                Default::default(),
                Vec::new(),
            )
            .unwrap(),
        );

        let added = supervisor.reconcile_inventory(vec![observation]).unwrap();
        assert_eq!(added.len(), 1);
        assert!(CameraInstanceId::new(added[0].descriptor().camera_instance_id().as_str()).is_ok());
        assert!(supervisor
            .validate_descriptor(added[0].descriptor())
            .is_ok());
    }

    #[test]
    fn supervisor_inventory_poison_fails_closed() {
        let backend = Arc::new(RecordingBackend::new(Arc::new(Mutex::new(Vec::new()))));
        let supervisor = CameraSupervisor::from_arc(backend);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = supervisor.inventory.lock().unwrap();
            panic!("poison inventory fixture");
        }));

        assert_eq!(
            supervisor.reconcile_inventory(Vec::new()),
            Err(CameraInventoryError::Poisoned)
        );
    }

    #[test]
    fn default_supervisor_is_process_wide_and_uses_exact_uvc_delegates() {
        assert!(std::ptr::eq(
            default_camera_supervisor(),
            default_camera_supervisor()
        ));
        assert!(default_camera_supervisor()
            .backend
            .has_exact_production_uvc_delegates());
    }

    const BRIO_AT: &str = "/devices/pci0000:00/0000:00:14.0/usb3/3-1";
    const BRIO_ANSWER: [(&str, Role); 2] = [("/dev/video0", Role::Rgb), ("/dev/video2", Role::Ir)];

    fn brio() -> ObservationFixture {
        ObservationFixture::usb(BRIO_AT, "046d:085e")
            .serial("ABC123")
            .four_node(0)
    }

    /// A spy supervisor over `backend`, whose inventory holds `observations`.
    /// `backend` stays with the caller, sharing the hook slot, so a test can
    /// arm a hook that reaches the supervisor's inventory.
    fn spy_supervisor(
        backend: &RecordingBackend,
        observations: Vec<CameraObservation>,
    ) -> Arc<CameraSupervisor> {
        let supervisor = Arc::new(CameraSupervisor::new(backend.clone()));
        supervisor.reconcile_inventory(observations).unwrap();
        supervisor
    }

    fn recorded_role_count(supervisor: &CameraSupervisor) -> usize {
        supervisor.inventory.lock().unwrap().recorded_role_count()
    }

    #[test]
    fn discovery_records_roles_that_connected_pairs_reads_without_a_backend_call() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let answer = [
            ("/dev/video0", Role::Rgb),
            ("/dev/video2", Role::Ir),
            ("/dev/video4", Role::Rgb),
            ("/dev/video6", Role::Ir),
        ];
        let backend = RecordingBackend::new(calls.clone()).discovering(&answer);
        let supervisor = spy_supervisor(
            &backend,
            vec![
                brio().build(),
                ObservationFixture::usb("/devices/pci0000:00/0000:00:14.0/usb3/3-2", "1111:2222")
                    .serial("DEF456")
                    .fixed()
                    .four_node(4)
                    .build(),
            ],
        );
        let _installed = install_test_supervisor(supervisor.clone());

        assert_eq!(crate::discover_nodes(), owned(&answer));
        let view = crate::connected_pairs();
        assert_eq!(view.state, CameraInventoryState::Current);
        assert!(view.unclassified.is_empty());
        let pairs: Vec<_> = view
            .pairs
            .iter()
            .map(|pair| {
                (
                    pair.rgb.as_str(),
                    pair.ir.as_str(),
                    pair.identity.as_str(),
                    pair.fixed,
                )
            })
            .collect();
        // Topology order, never the fixed-first order of the pair listing.
        assert_eq!(
            pairs,
            [
                ("/dev/video0", "/dev/video2", "046d:085e:abc123", false),
                ("/dev/video4", "/dev/video6", "1111:2222:def456", true),
            ]
        );
        for _ in 0..3 {
            assert_eq!(crate::connected_pairs(), view);
        }
        assert_eq!(
            *calls.lock().unwrap(),
            ["discovery_scan"],
            "reading the view called a discovery or open delegate"
        );
        assert!(
            supervisor
                .acquire_operation(
                    &["/dev/video0"],
                    CameraOperationKind::Authentication,
                    Instant::now(),
                )
                .is_ok(),
            "reading the view must not hold a permit"
        );
    }

    #[test]
    fn pairing_records_the_roles_of_the_pairs_it_returns() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend =
            RecordingBackend::new(calls).pairing(vec![spy_pair("/dev/video0", "/dev/video2")]);
        let supervisor = spy_supervisor(&backend, vec![brio().build()]);
        let _installed = install_test_supervisor(supervisor);

        let pairs = crate::list_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].rgb, "/dev/video0");
        assert_eq!(pairs[0].ir, "/dev/video2");
        // Startup lists again in the same generation (capabilities, then
        // selection); the same answer keeps the roles.
        crate::list_pairs();
        let view = crate::connected_pairs();
        assert_eq!(view.pairs.len(), 1);
        assert_eq!(view.pairs[0].rgb, "/dev/video0");
        assert_eq!(view.pairs[0].ir, "/dev/video2");
        assert_eq!(view.pairs[0].identity, "046d:085e:abc123");
    }

    #[test]
    fn a_classification_that_raced_a_generation_change_is_not_recorded() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls).discovering(&BRIO_ANSWER);
        let supervisor = spy_supervisor(&backend, vec![brio().build()]);
        let inventory = supervisor.inventory.clone();
        // The test fails if the supervisor held the inventory lock across
        // the backend call.
        backend.on_next_classification(move || {
            inventory
                .try_lock()
                .expect("the supervisor held the inventory lock across discovery")
                .reconcile(vec![brio().evidence("changed").build()])
                .unwrap();
        });
        let _installed = install_test_supervisor(supervisor);

        assert_eq!(crate::discover_nodes(), owned(&BRIO_ANSWER));
        let view = crate::connected_pairs();
        assert!(view.pairs.is_empty());
        assert_eq!(view.unclassified.len(), 1);
        assert_eq!(view.unclassified[0].generation, 2);
        assert_eq!(
            view.unclassified[0].endpoints,
            ["/dev/video0", "/dev/video2"]
        );

        // The discard is per generation: the next discovery records.
        crate::discover_nodes();
        let view = crate::connected_pairs();
        assert_eq!(view.pairs.len(), 1);
        assert_eq!(view.pairs[0].generation, 2);
        assert!(view.unclassified.is_empty());
    }

    #[test]
    fn a_classification_that_raced_an_invalidation_is_not_recorded() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls).discovering(&BRIO_ANSWER);
        let supervisor = spy_supervisor(&backend, vec![brio().build()]);
        let inventory = supervisor.inventory.clone();
        backend.on_next_classification(move || {
            inventory
                .try_lock()
                .expect("the supervisor held the inventory lock across discovery")
                .invalidate_all();
        });
        let _installed = install_test_supervisor(supervisor.clone());

        assert_eq!(crate::discover_nodes(), owned(&BRIO_ANSWER));
        let view = crate::connected_pairs();
        assert_eq!(view.state, CameraInventoryState::Refreshing);
        assert!(view.pairs.is_empty());
        assert!(view.unclassified.is_empty());
        assert_eq!(recorded_role_count(&supervisor), 0);

        supervisor
            .reconcile_inventory(vec![brio().build()])
            .unwrap();
        let view = crate::connected_pairs();
        assert!(view.pairs.is_empty());
        assert_eq!(view.unclassified.len(), 1);
        assert_eq!(view.unclassified[0].generation, 2);
        assert_eq!(
            view.unclassified[0].endpoints,
            ["/dev/video0", "/dev/video2"]
        );
    }

    #[test]
    fn a_pairing_that_raced_a_generation_change_is_not_recorded() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend =
            RecordingBackend::new(calls).pairing(vec![spy_pair("/dev/video0", "/dev/video2")]);
        let supervisor = spy_supervisor(&backend, vec![brio().build()]);
        let inventory = supervisor.inventory.clone();
        // The test fails if the supervisor held the inventory lock across
        // the backend call.
        backend.on_next_classification(move || {
            inventory
                .try_lock()
                .expect("the supervisor held the inventory lock across pairing")
                .reconcile(vec![brio().evidence("changed").build()])
                .unwrap();
        });
        let _installed = install_test_supervisor(supervisor.clone());

        let pairs = crate::list_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].rgb, "/dev/video0");
        assert_eq!(pairs[0].ir, "/dev/video2");
        assert_eq!(recorded_role_count(&supervisor), 0);
        let view = crate::connected_pairs();
        assert!(view.pairs.is_empty());
        assert_eq!(view.unclassified.len(), 1);
        assert_eq!(view.unclassified[0].generation, 2);
        assert_eq!(
            view.unclassified[0].endpoints,
            ["/dev/video0", "/dev/video2"]
        );

        // The discard is per generation: the next pairing records.
        crate::list_pairs();
        let view = crate::connected_pairs();
        assert_eq!(view.pairs.len(), 1);
        assert_eq!(view.pairs[0].generation, 2);
        assert!(view.unclassified.is_empty());
    }

    #[test]
    fn an_ir_node_absent_from_the_passive_inventory_is_not_a_candidate() {
        let camera = || {
            ObservationFixture::usb(BRIO_AT, "046d:085e")
                .serial("ABC123")
                .capture("/dev/video0")
                .metadata("/dev/video1")
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        // Sysfs saw an IR node the passive inventory does not hold.
        let backend =
            RecordingBackend::new(calls).pairing(vec![spy_pair("/dev/video0", "/dev/video2")]);
        let supervisor = spy_supervisor(&backend, vec![camera().build()]);
        let _installed = install_test_supervisor(supervisor.clone());

        crate::list_pairs();
        let view = crate::connected_pairs();
        assert!(view.pairs.is_empty());
        assert!(
            view.unclassified.is_empty(),
            "an RGB-only camera is not a pair"
        );
        assert_eq!(recorded_role_count(&supervisor), 1);

        supervisor
            .reconcile_inventory(vec![camera().capture("/dev/video2").build()])
            .unwrap();
        let view = crate::connected_pairs();
        assert!(view.pairs.is_empty());
        assert_eq!(view.unclassified.len(), 1);
        assert_eq!(view.unclassified[0].generation, 2);
        assert_eq!(
            view.unclassified[0].endpoints,
            ["/dev/video0", "/dev/video2"]
        );

        crate::list_pairs();
        let view = crate::connected_pairs();
        assert_eq!(view.pairs.len(), 1);
        assert_eq!(view.pairs[0].ir, "/dev/video2");
    }

    const BRIO_METADATA: [&str; 2] = ["/dev/video1", "/dev/video3"];

    /// The BRIO on a host whose media graph placed neither metadata node
    /// (no /dev/media*): all four nodes are capture candidates.
    fn brio_with_unplaced_metadata() -> ObservationFixture {
        ObservationFixture::usb(BRIO_AT, "046d:085e")
            .serial("ABC123")
            .capture("/dev/video0")
            .capture("/dev/video1")
            .capture("/dev/video2")
            .capture("/dev/video3")
    }

    fn assert_brio_pair(view: &ConnectedPairs) {
        assert!(view.unclassified.is_empty());
        let [pair] = view.pairs.as_slice() else {
            panic!("the BRIO is one pair: {:?}", view.pairs);
        };
        assert_eq!(
            (pair.rgb.as_str(), pair.ir.as_str()),
            ("/dev/video0", "/dev/video2")
        );
        assert_eq!(pair.identity, "046d:085e:abc123");
    }

    #[test]
    fn discovery_pairs_a_camera_whose_metadata_nodes_the_media_graph_did_not_place() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls.clone())
            .discovering(&BRIO_ANSWER)
            .answering_other(&BRIO_METADATA);
        let supervisor = spy_supervisor(&backend, vec![brio_with_unplaced_metadata().build()]);
        let _installed = install_test_supervisor(supervisor);

        let view = crate::connected_pairs();
        assert!(view.pairs.is_empty());
        assert_eq!(
            view.unclassified[0].endpoints,
            ["/dev/video0", "/dev/video1", "/dev/video2", "/dev/video3"]
        );

        // Callers still receive the classified nodes and nothing else.
        assert_eq!(crate::discover_nodes(), owned(&BRIO_ANSWER));
        assert_brio_pair(&crate::connected_pairs());
        assert_eq!(
            *calls.lock().unwrap(),
            ["discovery_scan"],
            "recording the metadata nodes called another delegate"
        );
    }

    #[test]
    fn the_report_scan_pairs_a_camera_whose_metadata_nodes_the_media_graph_did_not_place() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls.clone())
            .discovering(&BRIO_ANSWER)
            .answering_other(&BRIO_METADATA);
        let supervisor = spy_supervisor(&backend, vec![brio_with_unplaced_metadata().build()]);
        let _installed = install_test_supervisor(supervisor);

        let scan = crate::scan_nodes();
        assert_eq!(scan.classified, owned(&BRIO_ANSWER));
        assert_eq!(scan.other, BRIO_METADATA);
        assert_brio_pair(&crate::connected_pairs());
        assert_eq!(
            *calls.lock().unwrap(),
            ["scan_nodes"],
            "recording the report scan called another delegate"
        );
    }

    #[test]
    fn pairing_pairs_a_camera_whose_metadata_nodes_the_media_graph_did_not_place() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls.clone())
            .pairing(vec![spy_pair("/dev/video0", "/dev/video2")])
            .answering_other(&BRIO_METADATA);
        let supervisor = spy_supervisor(&backend, vec![brio_with_unplaced_metadata().build()]);
        let _installed = install_test_supervisor(supervisor);

        // Callers still receive the pairs and nothing else.
        let pairs = crate::list_pairs();
        let [pair] = pairs.as_slice() else {
            panic!("pairing answered one pair: {} pairs", pairs.len());
        };
        assert_eq!(
            (pair.rgb.as_str(), pair.ir.as_str()),
            ("/dev/video0", "/dev/video2")
        );
        assert_brio_pair(&crate::connected_pairs());
        assert_eq!(
            *calls.lock().unwrap(),
            ["pairing_scan"],
            "recording the metadata nodes called another delegate"
        );
    }

    #[test]
    fn a_report_scan_that_raced_a_generation_change_is_not_recorded() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls)
            .discovering(&BRIO_ANSWER)
            .answering_other(&BRIO_METADATA);
        let supervisor = spy_supervisor(&backend, vec![brio_with_unplaced_metadata().build()]);
        let inventory = supervisor.inventory.clone();
        backend.on_next_classification(move || {
            inventory
                .try_lock()
                .expect("the supervisor held the inventory lock across the scan")
                .reconcile(vec![brio_with_unplaced_metadata()
                    .evidence("changed")
                    .build()])
                .unwrap();
        });
        let _installed = install_test_supervisor(supervisor.clone());

        let scan = crate::scan_nodes();
        assert_eq!(scan.classified, owned(&BRIO_ANSWER));
        assert_eq!(scan.other, BRIO_METADATA);
        assert_eq!(recorded_role_count(&supervisor), 0);
        let view = crate::connected_pairs();
        assert!(view.pairs.is_empty());
        assert_eq!(view.unclassified[0].generation, 2);

        crate::scan_nodes();
        assert_brio_pair(&crate::connected_pairs());
    }

    #[test]
    fn two_serialless_units_of_one_model_are_two_pairs_told_apart_by_topology() {
        let unit = |port: &str, first| {
            ObservationFixture::usb(
                &format!("/devices/pci0000:00/0000:00:14.0/usb1/{port}"),
                "3277:0059",
            )
            .four_node(first)
            .build()
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls.clone()).discovering(&[
            ("/dev/video0", Role::Rgb),
            ("/dev/video2", Role::Ir),
            ("/dev/video4", Role::Rgb),
            ("/dev/video6", Role::Ir),
        ]);
        // Port 1-1 holds the higher nodes and comes second in the census:
        // the view follows topology order even where it disagrees with the
        // census order and with node numbering.
        let supervisor = spy_supervisor(&backend, vec![unit("1-2", 0), unit("1-1", 4)]);
        let _installed = install_test_supervisor(supervisor);

        crate::discover_nodes();
        let view = crate::connected_pairs();
        assert!(view.unclassified.is_empty());
        let [first, second] = view.pairs.as_slice() else {
            panic!("two connected units are two pairs: {:?}", view.pairs);
        };
        assert_eq!(first.identity, "3277:0059");
        assert_eq!(second.identity, "3277:0059");
        assert!(!first.serial_present);
        assert!(!second.serial_present);
        assert_ne!(first.instance_id, second.instance_id);
        assert_eq!(first.port_chain.as_deref(), Some("1-1"));
        assert_eq!(second.port_chain.as_deref(), Some("1-2"));
        assert_eq!(
            (first.rgb.as_str(), first.ir.as_str()),
            ("/dev/video4", "/dev/video6")
        );
        assert_eq!(
            (second.rgb.as_str(), second.ir.as_str()),
            ("/dev/video0", "/dev/video2")
        );
        assert_eq!(*calls.lock().unwrap(), ["discovery_scan"]);
    }

    #[test]
    fn connected_pairs_never_initializes_the_default_supervisor() {
        let slot = OnceLock::new();
        assert_eq!(connected_pairs_from_slot(&slot), ConnectedPairs::default());
        assert!(
            slot.get().is_none(),
            "reading the pairing view must not initialize a supervisor"
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls.clone()).discovering(&BRIO_ANSWER);
        let supervisor = spy_supervisor(&backend, vec![brio().build()]);
        supervisor.discover_nodes();
        calls.lock().unwrap().clear();
        assert!(slot.set(supervisor).is_ok());

        let view = connected_pairs_from_slot(&slot);
        assert_eq!(view.pairs.len(), 1);
        assert!(
            calls.lock().unwrap().is_empty(),
            "the pairing view called a discovery or open delegate"
        );
    }

    #[test]
    fn a_poisoned_inventory_reports_unavailable_pairs_and_discovery_still_answers() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls).discovering(&BRIO_ANSWER);
        let supervisor = spy_supervisor(&backend, vec![brio().build()]);
        let poison = supervisor.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison.inventory.lock().unwrap();
            panic!("synthetic poison");
        })
        .join();
        let _installed = install_test_supervisor(supervisor);

        assert_eq!(crate::discover_nodes(), owned(&BRIO_ANSWER));
        assert_eq!(
            crate::connected_pairs(),
            ConnectedPairs {
                state: CameraInventoryState::Unavailable,
                reason: Some(CameraInventoryReason::Inventory),
                ..Default::default()
            }
        );
    }

    #[test]
    fn an_inventory_poisoned_during_discovery_records_nothing_and_discovery_still_answers() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls).discovering(&BRIO_ANSWER);
        let supervisor = spy_supervisor(&backend, vec![brio().build()]);
        let inventory = supervisor.inventory.clone();
        backend.on_next_classification(move || {
            let _ = std::thread::spawn(move || {
                let _guard = inventory
                    .try_lock()
                    .expect("the supervisor held the inventory lock across discovery");
                panic!("synthetic poison");
            })
            .join();
        });
        let _installed = install_test_supervisor(supervisor.clone());

        assert_eq!(crate::discover_nodes(), owned(&BRIO_ANSWER));
        assert_eq!(
            crate::connected_pairs(),
            ConnectedPairs {
                state: CameraInventoryState::Unavailable,
                reason: Some(CameraInventoryReason::Inventory),
                ..Default::default()
            }
        );
        let Err(poisoned) = supervisor.inventory.lock() else {
            panic!("the classification poisoned the inventory");
        };
        assert_eq!(poisoned.into_inner().recorded_role_count(), 0);
    }

    #[test]
    fn an_inventory_poisoned_during_the_report_scan_records_nothing_and_the_scan_still_answers() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend::new(calls)
            .discovering(&BRIO_ANSWER)
            .answering_other(&BRIO_METADATA);
        let supervisor = spy_supervisor(&backend, vec![brio_with_unplaced_metadata().build()]);
        let inventory = supervisor.inventory.clone();
        backend.on_next_classification(move || {
            let _ = std::thread::spawn(move || {
                let _guard = inventory
                    .try_lock()
                    .expect("the supervisor held the inventory lock across the scan");
                panic!("synthetic poison");
            })
            .join();
        });
        let _installed = install_test_supervisor(supervisor.clone());

        let scan = crate::scan_nodes();
        assert_eq!(scan.classified, owned(&BRIO_ANSWER));
        assert_eq!(scan.other, BRIO_METADATA);
        let Err(poisoned) = supervisor.inventory.lock() else {
            panic!("the scan poisoned the inventory");
        };
        assert_eq!(poisoned.into_inner().recorded_role_count(), 0);
    }
}
