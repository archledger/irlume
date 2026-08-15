// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Persistent udev lifecycle invalidation for the supervisor inventory.
//!
//! Udev messages are deliberately treated only as hints. Every published state
//! comes from a complete sysfs/udev snapshot taken after the monitor is already
//! listening. Neither enumeration nor monitoring opens a video node.

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::VecDeque;
use std::fmt;
use std::os::fd::AsRawFd as _;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::Weak;
use std::time::Duration;

use crate::backend::CameraSupervisor;
use crate::contracts::{BackendKind, CameraCapabilities, PhysicalCameraId};
use crate::inventory::{CameraInventoryError, CameraInventoryEvent, CameraObservation};

const MAX_QUIET_SNAPSHOT_ATTEMPTS: usize = 4;
const COALESCE_QUIET: Duration = Duration::from_millis(50);
const MONITOR_WAIT: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceEventKind {
    DirtyUvc,
    ContinuityLost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceEventHint {
    kind: DeviceEventKind,
    devpath: String,
}

impl DeviceEventHint {
    #[cfg(test)]
    fn new(kind: DeviceEventKind, devpath: impl Into<String>) -> Self {
        Self {
            kind,
            devpath: devpath.into(),
        }
    }

    fn from_udev(kind: DeviceEventKind, devpath: impl Into<String>) -> Self {
        Self {
            kind,
            devpath: devpath.into(),
        }
    }

    fn kind(&self) -> DeviceEventKind {
        self.kind
    }

    fn devpath(&self) -> &str {
        &self.devpath
    }

    fn requires_retirement(&self) -> bool {
        self.kind == DeviceEventKind::ContinuityLost
    }
}

fn consume_hints(hints: &[DeviceEventHint]) {
    for hint in hints {
        let _ = (hint.kind(), hint.devpath());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleError {
    Monitor(String),
    Snapshot(String),
    UnstableSnapshot,
    Inventory(CameraInventoryError),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Monitor(message) => write!(f, "udev monitor failed: {message}"),
            Self::Snapshot(message) => write!(f, "camera snapshot failed: {message}"),
            Self::UnstableSnapshot => f.write_str("camera snapshot never became quiet"),
            Self::Inventory(error) => write!(f, "camera inventory failed: {error:?}"),
        }
    }
}

trait DeviceEventSource {
    fn poll(&mut self, timeout: Duration) -> Result<Vec<DeviceEventHint>, LifecycleError>;
}

trait SnapshotSource {
    fn snapshot(&mut self) -> Result<Vec<CameraObservation>, LifecycleError>;
}

trait InventorySink {
    fn invalidate_all(&self) -> Result<(), CameraInventoryError>;

    fn reconcile(
        &self,
        observations: Vec<CameraObservation>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError>;
}

impl InventorySink for CameraSupervisor {
    fn invalidate_all(&self) -> Result<(), CameraInventoryError> {
        self.invalidate_inventory()
    }

    fn reconcile(
        &self,
        observations: Vec<CameraObservation>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
        self.reconcile_inventory(observations)
    }
}

struct LifecycleCoordinator<S, E> {
    snapshots: S,
    events: E,
}

impl<S: SnapshotSource, E: DeviceEventSource> LifecycleCoordinator<S, E> {
    fn new(snapshots: S, events: E) -> Self {
        Self { snapshots, events }
    }

    fn initialize(
        &mut self,
        inventory: &impl InventorySink,
    ) -> Result<Vec<CameraInventoryEvent>, LifecycleError> {
        self.publish_quiet_snapshot(inventory, Vec::new())
    }

    fn process_next(
        &mut self,
        inventory: &impl InventorySink,
        wait: Duration,
    ) -> Result<Vec<CameraInventoryEvent>, LifecycleError> {
        let first = match self.events.poll(wait) {
            Ok(events) => events,
            Err(error) => return Err(fail_closed(inventory, error)),
        };
        if first.is_empty() {
            return Ok(Vec::new());
        }
        consume_hints(&first);
        let mut pending = self.prepare_rescan(inventory, &first)?;

        // A message only invalidates the old view. Drain the burst, then rebuild
        // from one authoritative snapshot; event payloads never mutate inventory.
        loop {
            match self.events.poll(COALESCE_QUIET) {
                Ok(events) if events.is_empty() => break,
                Ok(events) => {
                    consume_hints(&events);
                    pending.extend(self.prepare_rescan(inventory, &events)?);
                }
                Err(error) => return Err(fail_closed(inventory, error)),
            }
        }
        self.publish_quiet_snapshot(inventory, pending)
    }

    fn publish_quiet_snapshot(
        &mut self,
        inventory: &impl InventorySink,
        mut pending: Vec<CameraInventoryEvent>,
    ) -> Result<Vec<CameraInventoryEvent>, LifecycleError> {
        for _ in 0..MAX_QUIET_SNAPSHOT_ATTEMPTS {
            let observations = match self.snapshots.snapshot() {
                Ok(observations) => observations,
                Err(error) => return Err(fail_closed(inventory, error)),
            };
            match self.events.poll(Duration::ZERO) {
                Ok(events) if events.is_empty() => {
                    let mut published = inventory
                        .reconcile(observations)
                        .map_err(LifecycleError::Inventory)?;
                    pending.append(&mut published);
                    return Ok(pending);
                }
                Ok(events) => {
                    consume_hints(&events);
                    pending.extend(self.prepare_rescan(inventory, &events)?);
                    continue;
                }
                Err(error) => return Err(fail_closed(inventory, error)),
            }
        }
        Err(fail_closed(inventory, LifecycleError::UnstableSnapshot))
    }

    fn prepare_rescan(
        &self,
        inventory: &impl InventorySink,
        hints: &[DeviceEventHint],
    ) -> Result<Vec<CameraInventoryEvent>, LifecycleError> {
        inventory
            .invalidate_all()
            .map_err(LifecycleError::Inventory)?;
        if hints.iter().any(DeviceEventHint::requires_retirement) {
            return inventory
                .reconcile(Vec::new())
                .map_err(LifecycleError::Inventory);
        }
        Ok(Vec::new())
    }
}

fn fail_closed(inventory: &impl InventorySink, error: LifecycleError) -> LifecycleError {
    match inventory.reconcile(Vec::new()) {
        Ok(_) => error,
        Err(inventory_error) => LifecycleError::Inventory(inventory_error),
    }
}

struct UdevEventSource {
    socket: udev::MonitorSocket,
}

impl UdevEventSource {
    fn new() -> Result<Self, LifecycleError> {
        // Do not filter to video4linux: USB parent/interface bind, unbind and
        // reset events are continuity evidence even when no child event exists.
        let socket = udev::MonitorBuilder::new()
            .and_then(udev::MonitorBuilder::listen)
            .map_err(|error| LifecycleError::Monitor(error.to_string()))?;
        Ok(Self { socket })
    }
}

impl DeviceEventSource for UdevEventSource {
    fn poll(&mut self, timeout: Duration) -> Result<Vec<DeviceEventHint>, LifecycleError> {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for the duration
        // of the call; poll does not retain it.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready < 0 {
            return Err(LifecycleError::Monitor(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        ensure_monitor_healthy(descriptor.revents)?;
        if ready == 0 || descriptor.revents & libc::POLLIN == 0 {
            return Ok(Vec::new());
        }

        let mut hints = Vec::new();
        for event in self.socket.iter() {
            let subsystem = event.subsystem().and_then(std::ffi::OsStr::to_str);
            let is_uvc_usb = subsystem == Some("usb")
                && (event.driver().and_then(std::ffi::OsStr::to_str) == Some("uvcvideo")
                    || event
                        .property_value("ID_USB_DRIVER")
                        .and_then(std::ffi::OsStr::to_str)
                        == Some("uvcvideo")
                    || event
                        .property_value("ID_USB_INTERFACES")
                        .and_then(std::ffi::OsStr::to_str)
                        .is_some_and(|interfaces| interfaces.contains(":0e")));
            if subsystem != Some("video4linux") && !is_uvc_usb {
                continue;
            }
            let kind = match event.event_type() {
                udev::EventType::Change => DeviceEventKind::DirtyUvc,
                _ => DeviceEventKind::ContinuityLost,
            };
            hints.push(DeviceEventHint::from_udev(
                kind,
                event.devpath().to_string_lossy(),
            ));
        }
        ensure_receive_drained(std::io::Error::last_os_error().raw_os_error())?;
        Ok(hints)
    }
}

fn ensure_monitor_healthy(revents: libc::c_short) -> Result<(), LifecycleError> {
    if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(LifecycleError::Monitor("udev monitor socket lost".into()));
    }
    Ok(())
}

fn ensure_receive_drained(errno: Option<i32>) -> Result<(), LifecycleError> {
    if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
        return Ok(());
    }
    if errno == Some(libc::ENOBUFS) {
        return Err(LifecycleError::Monitor(
            "udev monitor receive buffer overflow".into(),
        ));
    }
    match errno {
        Some(errno) => Err(LifecycleError::Monitor(format!(
            "udev monitor receive failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ))),
        None => Err(LifecycleError::Monitor(
            "udev monitor receive failed without errno".into(),
        )),
    }
}

#[derive(Default)]
struct UdevSnapshotSource;

#[derive(Debug)]
struct UdevNodeRecord {
    usb_devpath: String,
    serial: Option<String>,
    node_devpath: String,
    devnode: Option<String>,
    interface_number: Option<String>,
    v4l_capabilities: Option<String>,
}

impl SnapshotSource for UdevSnapshotSource {
    fn snapshot(&mut self) -> Result<Vec<CameraObservation>, LifecycleError> {
        let mut enumerator =
            udev::Enumerator::new().map_err(|error| LifecycleError::Snapshot(error.to_string()))?;
        enumerator
            .match_subsystem("video4linux")
            .and_then(|()| enumerator.match_is_initialized())
            .map_err(|error| LifecycleError::Snapshot(error.to_string()))?;
        let devices = enumerator
            .scan_devices()
            .map_err(|error| LifecycleError::Snapshot(error.to_string()))?;

        let mut records = Vec::new();
        for device in devices {
            if device.property_value("ID_USB_DRIVER") != Some(std::ffi::OsStr::new("uvcvideo")) {
                continue;
            }
            let usb = device
                .parent_with_subsystem_devtype("usb", "usb_device")
                .map_err(|error| LifecycleError::Snapshot(error.to_string()))?
                .ok_or_else(|| {
                    LifecycleError::Snapshot(format!(
                        "{} has uvcvideo but no USB-device parent",
                        device.devpath().to_string_lossy()
                    ))
                })?;
            records.push(UdevNodeRecord {
                usb_devpath: usb.devpath().to_string_lossy().into_owned(),
                serial: usb
                    .attribute_value("serial")
                    .map(|value| value.to_string_lossy().trim().to_owned())
                    .filter(|value| !value.is_empty()),
                node_devpath: device.devpath().to_string_lossy().into_owned(),
                devnode: device
                    .devnode()
                    .map(|path| path.to_string_lossy().into_owned()),
                interface_number: device
                    .property_value("ID_USB_INTERFACE_NUM")
                    .map(|value| value.to_string_lossy().into_owned()),
                v4l_capabilities: device
                    .property_value("ID_V4L_CAPABILITIES")
                    .map(|value| value.to_string_lossy().into_owned()),
            });
        }
        observations_from_records(records)
    }
}

fn observations_from_records(
    records: Vec<UdevNodeRecord>,
) -> Result<Vec<CameraObservation>, LifecycleError> {
    let mut groups: BTreeMap<String, (Option<String>, Vec<String>)> = BTreeMap::new();
    for record in records {
        let evidence = format!(
            "{}|{}|{}|{}",
            record.node_devpath,
            record.devnode.as_deref().unwrap_or(""),
            record.interface_number.as_deref().unwrap_or(""),
            record.v4l_capabilities.as_deref().unwrap_or("")
        );
        let group = groups
            .entry(record.usb_devpath.clone())
            .or_insert_with(|| (record.serial.clone(), Vec::new()));
        if group.0 != record.serial {
            return Err(LifecycleError::Snapshot(format!(
                "conflicting serial evidence for {}",
                record.usb_devpath
            )));
        }
        group.1.push(evidence);
    }

    groups
        .into_iter()
        .map(|(topology_path, (serial, evidence))| {
            let physical_id = PhysicalCameraId::new(topology_path, serial)
                .map_err(|error| LifecycleError::Snapshot(error.to_string()))?;
            Ok(CameraObservation::with_lifecycle_evidence(
                BackendKind::UvcV4l2,
                physical_id,
                CameraCapabilities::default(),
                evidence,
            ))
        })
        .collect()
}

fn bind_monitor_before_snapshot<S: SnapshotSource, E: DeviceEventSource>(
    bind: impl FnOnce() -> Result<E, LifecycleError>,
    snapshots: impl FnOnce() -> S,
) -> Result<LifecycleCoordinator<S, E>, LifecycleError> {
    let events = bind()?;
    Ok(LifecycleCoordinator::new(snapshots(), events))
}

/// Start the production monitor before the first authoritative scan. The thread
/// owns the monitor socket for the supervisor lifetime; dropping the process is
/// the only normal shutdown path for this process-scoped inventory.
pub(crate) fn spawn(supervisor: Weak<CameraSupervisor>) -> Result<(), LifecycleError> {
    let mut coordinator =
        bind_monitor_before_snapshot(UdevEventSource::new, || UdevSnapshotSource)?;
    std::thread::Builder::new()
        .name("irlume-camera-udev".into())
        .spawn(move || {
            let Some(supervisor) = supervisor.upgrade() else {
                return;
            };
            if let Err(error) = coordinator.initialize(supervisor.as_ref()) {
                eprintln!("irlume: camera lifecycle monitor stopped: {error}");
                return;
            }
            loop {
                if let Err(error) = coordinator.process_next(supervisor.as_ref(), MONITOR_WAIT) {
                    eprintln!("irlume: camera lifecycle monitor stopped: {error}");
                    return;
                }
            }
        })
        .map_err(|error| LifecycleError::Monitor(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{CameraGeneration, StreamRole};
    use crate::inventory::CameraInventory;

    struct TestInventory(Mutex<CameraInventory>);

    impl TestInventory {
        fn new() -> Self {
            Self(Mutex::new(CameraInventory::new()))
        }

        fn validate(
            &self,
            descriptor: &crate::contracts::CameraDescriptor,
        ) -> Result<(), CameraInventoryError> {
            self.0.lock().unwrap().validate(descriptor)
        }
    }

    impl InventorySink for TestInventory {
        fn invalidate_all(&self) -> Result<(), CameraInventoryError> {
            self.0.lock().unwrap().invalidate_all();
            Ok(())
        }

        fn reconcile(
            &self,
            observations: Vec<CameraObservation>,
        ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
            self.0.lock().unwrap().reconcile(observations)
        }
    }

    struct FakeSnapshots(VecDeque<Result<Vec<CameraObservation>, LifecycleError>>);

    impl SnapshotSource for FakeSnapshots {
        fn snapshot(&mut self) -> Result<Vec<CameraObservation>, LifecycleError> {
            self.0.pop_front().expect("snapshot fixture exhausted")
        }
    }

    struct FakeEvents(VecDeque<Result<Vec<DeviceEventHint>, LifecycleError>>);

    impl DeviceEventSource for FakeEvents {
        fn poll(&mut self, _: Duration) -> Result<Vec<DeviceEventHint>, LifecycleError> {
            self.0.pop_front().unwrap_or_else(|| Ok(Vec::new()))
        }
    }

    fn observation(evidence: &str) -> CameraObservation {
        CameraObservation::with_lifecycle_evidence(
            BackendKind::UvcV4l2,
            PhysicalCameraId::new("/devices/pci/usb1/camera", None).unwrap(),
            CameraCapabilities::new(vec![StreamRole::Rgb], Default::default(), Vec::new()).unwrap(),
            vec![evidence.into()],
        )
    }

    fn hint(kind: DeviceEventKind) -> DeviceEventHint {
        DeviceEventHint::new(kind, "/devices/pci/usb1/video4linux/video0")
    }

    #[test]
    fn monitor_is_bound_before_initial_snapshot() {
        struct RecordingSnapshot(std::sync::Arc<Mutex<Vec<&'static str>>>);
        impl SnapshotSource for RecordingSnapshot {
            fn snapshot(&mut self) -> Result<Vec<CameraObservation>, LifecycleError> {
                self.0.lock().unwrap().push("scan");
                Ok(Vec::new())
            }
        }

        let order = std::sync::Arc::new(Mutex::new(Vec::new()));
        let bind_order = order.clone();
        let snapshot_order = order.clone();
        let mut coordinator = bind_monitor_before_snapshot(
            move || {
                bind_order.lock().unwrap().push("bind");
                Ok(FakeEvents(VecDeque::from([Ok(Vec::new())])))
            },
            move || {
                snapshot_order.lock().unwrap().push("snapshot-source");
                RecordingSnapshot(snapshot_order)
            },
        )
        .unwrap();
        coordinator.initialize(&TestInventory::new()).unwrap();
        assert_eq!(*order.lock().unwrap(), ["bind", "snapshot-source", "scan"]);
    }

    #[test]
    fn event_hints_are_invalidation_only() {
        let hint = hint(DeviceEventKind::DirtyUvc);
        assert_eq!(hint.kind(), DeviceEventKind::DirtyUvc);
        assert!(hint.devpath().ends_with("/video0"));
    }

    #[test]
    fn startup_discards_a_scan_if_an_event_arrived_during_it() {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([
                Ok(vec![observation("stale")]),
                Ok(vec![observation("quiet")]),
            ])),
            FakeEvents(VecDeque::from([
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(Vec::new()),
            ])),
        );

        let events = coordinator.initialize(&inventory).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_added());
        assert_eq!(
            events[0].descriptor().generation(),
            CameraGeneration::INITIAL
        );
    }

    #[test]
    fn remove_add_burst_retires_before_publishing_fresh_instance() {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([
                Ok(vec![observation("video0")]),
                Ok(vec![observation("video2")]),
            ])),
            FakeEvents(VecDeque::from([
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::ContinuityLost)]),
                Ok(vec![hint(DeviceEventKind::ContinuityLost)]),
                Ok(Vec::new()),
                Ok(Vec::new()),
            ])),
        );
        let initial = coordinator.initialize(&inventory).unwrap();
        let old = initial[0].descriptor().clone();

        let changed = coordinator
            .process_next(&inventory, Duration::ZERO)
            .unwrap();
        assert_eq!(changed.len(), 2);
        assert!(changed[0].is_removed());
        assert!(changed[1].is_added());
        assert_eq!(
            changed[1].descriptor().generation(),
            CameraGeneration::INITIAL
        );
        assert_ne!(
            changed[1].descriptor().camera_instance_id(),
            old.camera_instance_id()
        );
        assert_eq!(
            inventory.validate(&old),
            Err(CameraInventoryError::ForeignInstance)
        );
    }

    #[test]
    fn old_token_is_unusable_before_soft_rescan_starts() {
        struct CheckingSnapshots<'a> {
            inventory: &'a TestInventory,
            old: Option<crate::contracts::CameraDescriptor>,
            calls: usize,
        }

        impl SnapshotSource for CheckingSnapshots<'_> {
            fn snapshot(&mut self) -> Result<Vec<CameraObservation>, LifecycleError> {
                self.calls += 1;
                if self.calls == 2 {
                    assert_eq!(
                        self.inventory.validate(self.old.as_ref().unwrap()),
                        Err(CameraInventoryError::ContinuityLost)
                    );
                    return Ok(vec![observation("video2")]);
                }
                Ok(vec![observation("video0")])
            }
        }

        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            CheckingSnapshots {
                inventory: &inventory,
                old: None,
                calls: 0,
            },
            FakeEvents(VecDeque::from([
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(Vec::new()),
                Ok(Vec::new()),
            ])),
        );
        let old = coordinator.initialize(&inventory).unwrap()[0]
            .descriptor()
            .clone();
        coordinator.snapshots.old = Some(old);
        coordinator
            .process_next(&inventory, Duration::ZERO)
            .unwrap();
    }

    #[test]
    fn change_burst_coalesces_into_one_generation_change() {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([
                Ok(vec![observation("video0")]),
                Ok(vec![observation("video2")]),
            ])),
            FakeEvents(VecDeque::from([
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(Vec::new()),
                Ok(Vec::new()),
            ])),
        );
        let old = coordinator.initialize(&inventory).unwrap()[0]
            .descriptor()
            .clone();

        let changed = coordinator
            .process_next(&inventory, Duration::ZERO)
            .unwrap();
        assert_eq!(changed.len(), 1);
        assert!(changed[0].is_changed());
        assert_eq!(
            changed[0].descriptor().generation(),
            CameraGeneration::new(2).unwrap()
        );
        assert_eq!(
            inventory.validate(&old),
            Err(CameraInventoryError::StaleGeneration)
        );
    }

    #[test]
    fn event_source_disconnect_retires_every_published_descriptor() {
        assert_monitor_failure_retires("disconnected");
    }

    #[test]
    fn monitor_overflow_retires_every_published_descriptor() {
        assert_monitor_failure_retires("overflow");
    }

    fn assert_monitor_failure_retires(message: &str) {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([Ok(vec![observation("video0")])])),
            FakeEvents(VecDeque::from([
                Ok(Vec::new()),
                Err(LifecycleError::Monitor(message.into())),
            ])),
        );
        let old = coordinator.initialize(&inventory).unwrap()[0]
            .descriptor()
            .clone();

        assert_eq!(
            coordinator.process_next(&inventory, Duration::ZERO),
            Err(LifecycleError::Monitor(message.into()))
        );
        assert_eq!(inventory.validate(&old), Err(CameraInventoryError::Removed));
    }

    #[test]
    fn scan_failure_retires_every_published_descriptor() {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([
                Ok(vec![observation("video0")]),
                Err(LifecycleError::Snapshot("sysfs race".into())),
            ])),
            FakeEvents(VecDeque::from([
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(Vec::new()),
            ])),
        );
        let old = coordinator.initialize(&inventory).unwrap()[0]
            .descriptor()
            .clone();

        assert_eq!(
            coordinator.process_next(&inventory, Duration::ZERO),
            Err(LifecycleError::Snapshot("sysfs race".into()))
        );
        assert_eq!(inventory.validate(&old), Err(CameraInventoryError::Removed));
    }

    #[test]
    fn an_unstable_startup_snapshot_is_bounded_and_fail_closed() {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from_iter(
                (0..MAX_QUIET_SNAPSHOT_ATTEMPTS).map(|_| Ok(vec![observation("moving")])),
            )),
            FakeEvents(VecDeque::from_iter(
                (0..MAX_QUIET_SNAPSHOT_ATTEMPTS).map(|_| Ok(vec![hint(DeviceEventKind::DirtyUvc)])),
            )),
        );

        assert_eq!(
            coordinator.initialize(&inventory),
            Err(LifecycleError::UnstableSnapshot)
        );
    }

    #[test]
    fn netlink_error_flags_are_monitor_loss() {
        assert_eq!(ensure_monitor_healthy(libc::POLLIN), Ok(()));
        for flag in [libc::POLLERR, libc::POLLHUP, libc::POLLNVAL] {
            assert_eq!(
                ensure_monitor_healthy(flag),
                Err(LifecycleError::Monitor("udev monitor socket lost".into()))
            );
        }
    }

    #[test]
    fn receive_tail_distinguishes_drained_overflow_and_other_failures() {
        assert_eq!(ensure_receive_drained(Some(libc::EAGAIN)), Ok(()));
        assert_eq!(
            ensure_receive_drained(Some(libc::ENOBUFS)),
            Err(LifecycleError::Monitor(
                "udev monitor receive buffer overflow".into()
            ))
        );
        assert!(matches!(
            ensure_receive_drained(Some(libc::EIO)),
            Err(LifecycleError::Monitor(message))
                if message.starts_with("udev monitor receive failed:")
        ));
        assert_eq!(
            ensure_receive_drained(None),
            Err(LifecycleError::Monitor(
                "udev monitor receive failed without errno".into()
            ))
        );
    }

    #[test]
    #[ignore = "requires an operator-controlled UVC interface unbind/rebind"]
    fn production_monitor_observes_live_uvc_continuity_loss_and_recovery() {
        use std::io::Write;

        let inventory = TestInventory::new();
        let mut coordinator =
            bind_monitor_before_snapshot(UdevEventSource::new, || UdevSnapshotSource).unwrap();
        let initial = coordinator.initialize(&inventory).unwrap();
        let original = initial
            .iter()
            .find(|event| event.descriptor().physical_id().serial() == Some("200901010001"))
            .expect("Shinetech camera is present")
            .descriptor()
            .clone();

        println!("IRLUME_UDEV_READY");
        std::io::stdout().flush().unwrap();
        let lost_deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let remaining = lost_deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for old instance retirement"
            );
            let events = coordinator.process_next(&inventory, remaining).unwrap();
            if events.iter().any(|event| {
                matches!(event, CameraInventoryEvent::Removed(descriptor)
                    if descriptor.camera_instance_id() == original.camera_instance_id())
            }) {
                break;
            }
        }
        println!("IRLUME_UDEV_LOST");
        std::io::stdout().flush().unwrap();

        let recovered_deadline = std::time::Instant::now() + Duration::from_secs(20);
        let replacement = loop {
            let remaining = recovered_deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for replacement instance"
            );
            let events = coordinator.process_next(&inventory, remaining).unwrap();
            if let Some(descriptor) = events.iter().rev().find_map(|event| match event {
                CameraInventoryEvent::Added(descriptor)
                    if descriptor.physical_id().serial() == Some("200901010001") =>
                {
                    Some(descriptor.clone())
                }
                _ => None,
            }) {
                break descriptor;
            }
        };
        assert_ne!(
            replacement.camera_instance_id(),
            original.camera_instance_id()
        );
        println!("IRLUME_UDEV_RECOVERED");
    }

    #[test]
    #[ignore = "requires a real initialized UVC camera in udev"]
    fn production_snapshot_matches_shinetech_four_node_topology_without_capture() {
        let observations = UdevSnapshotSource.snapshot().unwrap();
        let camera = observations
            .iter()
            .find(|observation| observation.physical_id().serial() == Some("200901010001"))
            .expect("Shinetech 3277:0059 camera is present");
        assert!(camera.physical_id().topology_path().ends_with("/usb3/3-5"));
        assert_eq!(camera.lifecycle_evidence().len(), 4);
        assert!(camera
            .lifecycle_evidence()
            .iter()
            .any(|evidence| evidence.contains("video0") && evidence.ends_with(":capture:")));
        assert!(camera
            .lifecycle_evidence()
            .iter()
            .any(|evidence| evidence.contains("video3") && evidence.ends_with("|:")));
    }

    #[test]
    fn udev_records_group_one_physical_camera_and_normalize_order() {
        let records = vec![
            UdevNodeRecord {
                usb_devpath: "/devices/pci/usb1/camera".into(),
                serial: Some("serial".into()),
                node_devpath: "/devices/pci/usb1/camera/1.2/video2".into(),
                devnode: Some("/dev/video2".into()),
                interface_number: Some("02".into()),
                v4l_capabilities: Some(":capture:".into()),
            },
            UdevNodeRecord {
                usb_devpath: "/devices/pci/usb1/camera".into(),
                serial: Some("serial".into()),
                node_devpath: "/devices/pci/usb1/camera/1.0/video0".into(),
                devnode: Some("/dev/video0".into()),
                interface_number: Some("00".into()),
                v4l_capabilities: Some(":capture:".into()),
            },
        ];
        let observations = observations_from_records(records).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].physical_id().topology_path(),
            "/devices/pci/usb1/camera"
        );
        assert_eq!(observations[0].physical_id().serial(), Some("serial"));
    }
}
