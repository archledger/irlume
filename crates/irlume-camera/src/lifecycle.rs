// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Persistent udev lifecycle invalidation for the supervisor inventory.
//!
//! Udev messages are deliberately treated only as hints. Every published state
//! comes from a complete sysfs/media snapshot taken after the monitor is already
//! listening. Neither enumeration nor monitoring opens a video node.

#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::Weak;
use std::time::Duration;

use crate::backend::CameraSupervisor;
use crate::contracts::{BackendKind, CameraCapabilities, PhysicalCameraId};
use crate::inventory::{CameraInventoryError, CameraInventoryEvent, CameraObservation};

const MAX_QUIET_SNAPSHOT_ATTEMPTS: usize = 4;
const MAX_COALESCE_POLLS: usize = 16;
const MAX_EVENTS_PER_POLL: usize = 4096;
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
    affected_topologies: BTreeSet<String>,
}

impl DeviceEventHint {
    #[cfg(test)]
    fn new(kind: DeviceEventKind, devpath: impl Into<String>) -> Self {
        Self {
            kind,
            devpath: devpath.into(),
            affected_topologies: BTreeSet::new(),
        }
    }

    fn from_udev(
        kind: DeviceEventKind,
        devpath: impl Into<String>,
        tracked_topologies: &BTreeSet<String>,
    ) -> Self {
        let devpath = devpath.into();
        let affected_topologies = tracked_topologies
            .iter()
            .filter(|topology| {
                devpath == topology.as_str()
                    || devpath.starts_with(&format!("{topology}/"))
                    || topology.starts_with(&format!("{devpath}/"))
            })
            .cloned()
            .collect();
        Self {
            kind,
            devpath,
            affected_topologies,
        }
    }

    #[cfg(test)]
    fn with_affected_topology(mut self, topology: impl Into<String>) -> Self {
        self.affected_topologies.insert(topology.into());
        self
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

    fn affected_topologies(&self) -> &BTreeSet<String> {
        &self.affected_topologies
    }
}

fn consume_hints(hints: &[DeviceEventHint]) {
    for hint in hints {
        let _ = (hint.kind(), hint.devpath(), hint.affected_topologies());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleError {
    Monitor(String),
    Snapshot(String),
    UnstableSnapshot,
    EventStorm,
    Inventory(CameraInventoryError),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Monitor(message) => write!(f, "udev monitor failed: {message}"),
            Self::Snapshot(message) => write!(f, "camera snapshot failed: {message}"),
            Self::UnstableSnapshot => f.write_str("camera snapshot never became quiet"),
            Self::EventStorm => f.write_str("camera lifecycle event storm exceeded bounds"),
            Self::Inventory(error) => write!(f, "camera inventory failed: {error:?}"),
        }
    }
}

trait DeviceEventSource {
    fn poll(&mut self, timeout: Duration) -> Result<Vec<DeviceEventHint>, LifecycleError>;

    fn add_tracked_topologies(&mut self, _topologies: &[String]) {}

    fn commit_tracked_topologies(&mut self, _topologies: &[String]) {}
}

trait SnapshotSource {
    fn snapshot(&mut self) -> Result<Vec<CameraObservation>, LifecycleError>;
}

trait InventorySink {
    fn invalidate_all(&self) -> Result<(), CameraInventoryError>;

    fn invalidate_topologies(
        &self,
        topologies: &BTreeSet<String>,
    ) -> Result<(), CameraInventoryError>;

    fn retire_topologies(
        &self,
        topologies: &BTreeSet<String>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError>;

    fn reconcile(
        &self,
        observations: Vec<CameraObservation>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError>;

    fn reconcile_guarded<F>(
        &self,
        observations: Vec<CameraObservation>,
        quiet: F,
    ) -> Result<(Vec<CameraInventoryEvent>, bool), CameraInventoryError>
    where
        F: FnMut() -> bool;
}

impl InventorySink for CameraSupervisor {
    fn invalidate_all(&self) -> Result<(), CameraInventoryError> {
        self.invalidate_inventory()
    }

    fn invalidate_topologies(
        &self,
        topologies: &BTreeSet<String>,
    ) -> Result<(), CameraInventoryError> {
        self.invalidate_inventory_topologies(topologies)
    }

    fn retire_topologies(
        &self,
        topologies: &BTreeSet<String>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
        self.retire_inventory_topologies(topologies)
    }

    fn reconcile(
        &self,
        observations: Vec<CameraObservation>,
    ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
        self.reconcile_inventory(observations)
    }

    fn reconcile_guarded<F>(
        &self,
        observations: Vec<CameraObservation>,
        quiet: F,
    ) -> Result<(Vec<CameraInventoryEvent>, bool), CameraInventoryError>
    where
        F: FnMut() -> bool,
    {
        self.reconcile_inventory_guarded(observations, quiet)
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
        let mut quiet = false;
        for _ in 0..MAX_COALESCE_POLLS {
            match self.events.poll(COALESCE_QUIET) {
                Ok(events) if events.is_empty() => {
                    quiet = true;
                    break;
                }
                Ok(events) => {
                    consume_hints(&events);
                    pending.extend(self.prepare_rescan(inventory, &events)?);
                }
                Err(error) => return Err(fail_closed(inventory, error)),
            }
        }
        if !quiet {
            return Err(fail_closed(inventory, LifecycleError::EventStorm));
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
            let topologies: Vec<String> = observations
                .iter()
                .map(|observation| observation.physical_id().topology_path().to_owned())
                .collect();
            self.events.add_tracked_topologies(&topologies);
            match self.events.poll(COALESCE_QUIET) {
                Ok(events) if events.is_empty() => {
                    let mut boundary_events = Vec::new();
                    let mut boundary_error = None;
                    let (mut published, committed) = inventory
                        .reconcile_guarded(observations, || {
                            match self.events.poll(Duration::ZERO) {
                                Ok(events) if events.is_empty() => true,
                                Ok(events) => {
                                    boundary_events.extend(events);
                                    false
                                }
                                Err(error) => {
                                    boundary_error = Some(error);
                                    false
                                }
                            }
                        })
                        .map_err(LifecycleError::Inventory)?;
                    if let Some(error) = boundary_error {
                        return Err(fail_closed(inventory, error));
                    }
                    if !committed {
                        consume_hints(&boundary_events);
                        pending.extend(self.prepare_rescan(inventory, &boundary_events)?);
                        continue;
                    }
                    self.events.commit_tracked_topologies(&topologies);
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
        let affected: BTreeSet<String> = hints
            .iter()
            .flat_map(|hint| hint.affected_topologies().iter().cloned())
            .collect();
        inventory
            .invalidate_topologies(&affected)
            .map_err(LifecycleError::Inventory)?;
        let retired: BTreeSet<String> = hints
            .iter()
            .filter(|hint| hint.requires_retirement())
            .flat_map(|hint| hint.affected_topologies().iter().cloned())
            .collect();
        inventory
            .retire_topologies(&retired)
            .map_err(LifecycleError::Inventory)
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
    tracked_topologies: BTreeSet<String>,
}

impl UdevEventSource {
    fn new() -> Result<Self, LifecycleError> {
        // Do not filter to video4linux: USB parent/interface bind, unbind and
        // reset events are continuity evidence even when no child event exists.
        // SEQNUM is deliberately not used as loss evidence: it is global across
        // namespace-targeted uevents and assigned before kernel broadcast order.
        // Observable socket loss (ENOBUFS/errors/hangup) is the fail-closed signal.
        let socket = udev::MonitorBuilder::new_kernel()
            .and_then(udev::MonitorBuilder::listen)
            .map_err(|error| LifecycleError::Monitor(error.to_string()))?;
        Ok(Self {
            socket,
            tracked_topologies: BTreeSet::new(),
        })
    }
}

fn classify_kernel_event(
    subsystem: Option<&str>,
    interface: Option<&str>,
    modalias: Option<&str>,
    devtype: Option<&str>,
    tracked_usb_parent: bool,
    event_type: udev::EventType,
) -> Option<DeviceEventKind> {
    if subsystem == Some("video4linux") {
        return Some(if event_type == udev::EventType::Change {
            DeviceEventKind::DirtyUvc
        } else {
            DeviceEventKind::ContinuityLost
        });
    }
    if subsystem != Some("usb") {
        return None;
    }
    let uvc_interface = interface.is_some_and(|value| {
        value.starts_with("14/") || value.to_ascii_lowercase().starts_with("0e/")
    }) || modalias
        .is_some_and(|value| value.to_ascii_lowercase().contains("ic0e"));
    let usb_parent = devtype == Some("usb_device") && tracked_usb_parent;
    if !uvc_interface && !usb_parent {
        return None;
    }
    Some(DeviceEventKind::ContinuityLost)
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
        let mut received = 0;
        let mut events = self.socket.iter();
        while let Some(event) = next_monitor_event(&mut events)? {
            received += 1;
            if received > MAX_EVENTS_PER_POLL {
                return Err(LifecycleError::EventStorm);
            }
            let devpath = event.devpath().to_string_lossy();
            let tracked_usb_parent = self.tracked_topologies.contains(devpath.as_ref());
            let text = |name| event.property_value(name).and_then(std::ffi::OsStr::to_str);
            let Some(kind) = classify_kernel_event(
                event.subsystem().and_then(std::ffi::OsStr::to_str),
                text("INTERFACE"),
                text("MODALIAS"),
                text("DEVTYPE"),
                tracked_usb_parent,
                event.event_type(),
            ) else {
                continue;
            };
            hints.push(DeviceEventHint::from_udev(
                kind,
                event.devpath().to_string_lossy(),
                &self.tracked_topologies,
            ));
        }
        Ok(hints)
    }

    fn add_tracked_topologies(&mut self, topologies: &[String]) {
        self.tracked_topologies.extend(topologies.iter().cloned());
    }

    fn commit_tracked_topologies(&mut self, topologies: &[String]) {
        self.tracked_topologies = topologies.iter().cloned().collect();
    }
}

fn set_errno(errno: i32) {
    // SAFETY: Linux exposes one thread-local errno cell per calling thread.
    unsafe { *libc::__errno_location() = errno };
}

fn next_monitor_event<I: Iterator>(iterator: &mut I) -> Result<Option<I::Item>, LifecycleError> {
    set_errno(0);
    match iterator.next() {
        Some(event) => Ok(Some(event)),
        None => {
            let errno = std::io::Error::last_os_error().raw_os_error();
            ensure_receive_drained(errno)?;
            Ok(None)
        }
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

struct SysfsSnapshotSource {
    root: PathBuf,
}

impl Default for SysfsSnapshotSource {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/sys/class/video4linux"),
        }
    }
}

#[derive(Debug)]
struct UdevNodeRecord {
    usb_devpath: String,
    serial: Option<String>,
    node_devpath: String,
    devnode: String,
    interface_number: Option<String>,
    capture_node: Option<bool>,
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[derive(Default)]
struct UdevCameraGroup {
    serial: Option<String>,
    evidence: Vec<String>,
    endpoints: Vec<String>,
}

fn devpath(path: &Path) -> String {
    match path.strip_prefix("/sys") {
        Ok(relative) => format!("/{}", relative.to_string_lossy()),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

fn usb_device_parent(interface: &Path) -> Option<&Path> {
    interface
        .ancestors()
        .find(|path| path.join("idVendor").is_file() && path.join("idProduct").is_file())
}

impl SnapshotSource for SysfsSnapshotSource {
    fn snapshot(&mut self) -> Result<Vec<CameraObservation>, LifecycleError> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(LifecycleError::Snapshot(error.to_string())),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| LifecycleError::Snapshot(error.to_string()))?;
            let name = entry.file_name();
            let devnode = PathBuf::from("/dev").join(&name);
            let devnode_text = devnode.to_string_lossy().into_owned();
            let interface = match std::fs::canonicalize(entry.path().join("device")) {
                Ok(interface) => interface,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(LifecycleError::Snapshot(error.to_string())),
            };
            let driver = std::fs::canonicalize(interface.join("driver")).ok();
            let is_uvc = driver.as_deref().and_then(Path::file_name)
                == Some(std::ffi::OsStr::new("uvcvideo"));
            if !is_uvc {
                if crate::virtual_camera_allowed(&devnode_text) {
                    let virtual_devpath =
                        format!("/devices/virtual/video4linux/{}", name.to_string_lossy());
                    records.push(UdevNodeRecord {
                        usb_devpath: "/devices/virtual/video4linux/irlume-test-camera".to_string(),
                        serial: None,
                        node_devpath: virtual_devpath,
                        interface_number: None,
                        capture_node: crate::media_graph::node_is_capture(&devnode_text),
                        devnode: devnode_text,
                    });
                }
                continue;
            }
            let usb = usb_device_parent(&interface).ok_or_else(|| {
                LifecycleError::Snapshot(format!(
                    "{} has uvcvideo but no USB-device parent",
                    interface.display()
                ))
            })?;
            records.push(UdevNodeRecord {
                usb_devpath: devpath(usb),
                serial: read_trimmed(usb.join("serial")),
                node_devpath: devpath(&interface),
                interface_number: read_trimmed(interface.join("bInterfaceNumber")),
                capture_node: crate::media_graph::node_is_capture(&devnode_text),
                devnode: devnode_text,
            });
        }
        observations_from_records(records)
    }
}

fn observations_from_records(
    records: Vec<UdevNodeRecord>,
) -> Result<Vec<CameraObservation>, LifecycleError> {
    let mut groups: BTreeMap<String, UdevCameraGroup> = BTreeMap::new();
    for record in records {
        let endpoint = record.devnode.clone();
        let evidence = format!(
            "{}|{}|{}|{}",
            record.node_devpath,
            record.devnode,
            record.interface_number.as_deref().unwrap_or(""),
            match record.capture_node {
                Some(true) => "capture",
                Some(false) => "metadata",
                None => "unknown",
            }
        );
        let group = groups
            .entry(record.usb_devpath.clone())
            .or_insert_with(|| UdevCameraGroup {
                serial: record.serial.clone(),
                ..UdevCameraGroup::default()
            });
        if group.serial != record.serial {
            return Err(LifecycleError::Snapshot(format!(
                "conflicting serial evidence for {}",
                record.usb_devpath
            )));
        }
        group.evidence.push(evidence);
        group.endpoints.push(endpoint);
    }

    groups
        .into_iter()
        .map(|(topology_path, group)| {
            let physical_id = PhysicalCameraId::new(topology_path, group.serial)
                .map_err(|error| LifecycleError::Snapshot(error.to_string()))?;
            Ok(CameraObservation::with_lifecycle_evidence_and_endpoints(
                BackendKind::UvcV4l2,
                physical_id,
                CameraCapabilities::default(),
                group.evidence,
                group.endpoints,
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

struct WorkerExitGuard<'a, I: InventorySink>(&'a I);

impl<'a, I: InventorySink> WorkerExitGuard<'a, I> {
    fn new(inventory: &'a I) -> Self {
        Self(inventory)
    }
}

impl<I: InventorySink> Drop for WorkerExitGuard<'_, I> {
    fn drop(&mut self) {
        let _ = self.0.invalidate_all();
    }
}

/// Start the production monitor before the first authoritative scan. The thread
/// owns the monitor socket for the supervisor lifetime; dropping the process is
/// the only normal shutdown path for this process-scoped inventory.
pub(crate) fn spawn(supervisor: Weak<CameraSupervisor>) -> Result<(), LifecycleError> {
    let mut coordinator =
        bind_monitor_before_snapshot(UdevEventSource::new, SysfsSnapshotSource::default)?;
    let Some(supervisor) = supervisor.upgrade() else {
        return Ok(());
    };
    coordinator.initialize(supervisor.as_ref())?;
    let worker_supervisor = supervisor.clone();
    let spawned = std::thread::Builder::new()
        .name("irlume-camera-udev".into())
        .spawn(move || {
            let _exit_guard = WorkerExitGuard::new(worker_supervisor.as_ref());
            loop {
                if let Err(error) =
                    coordinator.process_next(worker_supervisor.as_ref(), MONITOR_WAIT)
                {
                    eprintln!("irlume: camera lifecycle monitor stopped: {error}");
                    return;
                }
            }
        });
    finish_spawn(supervisor.as_ref(), spawned)
}

fn finish_spawn<I: InventorySink>(
    inventory: &I,
    spawned: std::io::Result<std::thread::JoinHandle<()>>,
) -> Result<(), LifecycleError> {
    match spawned {
        Ok(_) => Ok(()),
        Err(error) => {
            inventory
                .invalidate_all()
                .map_err(LifecycleError::Inventory)?;
            Err(LifecycleError::Monitor(error.to_string()))
        }
    }
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

        fn invalidate_topologies(
            &self,
            topologies: &BTreeSet<String>,
        ) -> Result<(), CameraInventoryError> {
            self.0.lock().unwrap().invalidate_topologies(topologies);
            Ok(())
        }

        fn retire_topologies(
            &self,
            topologies: &BTreeSet<String>,
        ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
            Ok(self.0.lock().unwrap().retire_topologies(topologies))
        }

        fn reconcile(
            &self,
            observations: Vec<CameraObservation>,
        ) -> Result<Vec<CameraInventoryEvent>, CameraInventoryError> {
            self.0.lock().unwrap().reconcile(observations)
        }

        fn reconcile_guarded<F>(
            &self,
            observations: Vec<CameraObservation>,
            quiet: F,
        ) -> Result<(Vec<CameraInventoryEvent>, bool), CameraInventoryError>
        where
            F: FnMut() -> bool,
        {
            self.0
                .lock()
                .unwrap()
                .reconcile_guarded(observations, quiet)
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
        observation_at("/devices/pci/usb1/camera", evidence)
    }

    fn observation_at(topology: &str, evidence: &str) -> CameraObservation {
        CameraObservation::with_lifecycle_evidence(
            BackendKind::UvcV4l2,
            PhysicalCameraId::new(topology, None).unwrap(),
            CameraCapabilities::new(vec![StreamRole::Rgb], Default::default(), Vec::new()).unwrap(),
            vec![evidence.into()],
        )
    }

    fn hint(kind: DeviceEventKind) -> DeviceEventHint {
        DeviceEventHint::new(kind, "/devices/pci/usb1/camera/video4linux/video0")
            .with_affected_topology("/devices/pci/usb1/camera")
    }

    #[test]
    fn iterator_null_preserves_real_receive_error() {
        let result = next_monitor_event(&mut std::iter::from_fn(|| {
            set_errno(libc::ENOBUFS);
            None::<()>
        }));
        assert!(matches!(
            result,
            Err(LifecycleError::Monitor(message)) if message.contains("overflow")
        ));
    }

    #[test]
    fn usb_uvc_change_and_property_sparse_remove_retire_continuity() {
        let change = classify_kernel_event(
            Some("usb"),
            Some("14/1/0"),
            None,
            Some("usb_interface"),
            false,
            udev::EventType::Change,
        );
        assert_eq!(change, Some(DeviceEventKind::ContinuityLost));

        let remove = classify_kernel_event(
            Some("usb"),
            None,
            Some("usb:v3277p0059d0001dcEFdsc02dp01ic0Eisc01ip00in00"),
            Some("usb_interface"),
            false,
            udev::EventType::Remove,
        );
        assert_eq!(remove, Some(DeviceEventKind::ContinuityLost));
        assert_eq!(
            classify_kernel_event(
                Some("video4linux"),
                None,
                None,
                None,
                false,
                udev::EventType::Change,
            ),
            Some(DeviceEventKind::DirtyUvc)
        );
        assert_eq!(
            classify_kernel_event(
                Some("usb"),
                None,
                None,
                Some("usb_device"),
                false,
                udev::EventType::Remove,
            ),
            None
        );
        assert_eq!(
            classify_kernel_event(
                Some("usb"),
                None,
                None,
                Some("usb_device"),
                true,
                udev::EventType::Remove,
            ),
            Some(DeviceEventKind::ContinuityLost)
        );
    }

    #[test]
    fn commit_boundary_event_discards_provisional_snapshot_before_unlock() {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([
                Ok(vec![observation("provisional")]),
                Ok(vec![observation("committed")]),
            ])),
            FakeEvents(VecDeque::from([
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::ContinuityLost)]),
                Ok(Vec::new()),
                Ok(Vec::new()),
            ])),
        );
        coordinator.initialize(&inventory).unwrap();
        assert!(
            coordinator.snapshots.0.is_empty(),
            "event at the guarded post-commit drain must force a fresh snapshot"
        );
    }

    #[test]
    fn sustained_event_storm_is_bounded_and_fail_closed() {
        let inventory = TestInventory::new();
        let descriptor = inventory
            .reconcile(vec![observation("published")])
            .unwrap()
            .remove(0)
            .descriptor()
            .clone();
        let mut polls = VecDeque::from([Ok(vec![hint(DeviceEventKind::DirtyUvc)])]);
        polls.extend((0..MAX_COALESCE_POLLS).map(|_| Ok(vec![hint(DeviceEventKind::DirtyUvc)])));
        let mut coordinator =
            LifecycleCoordinator::new(FakeSnapshots(VecDeque::new()), FakeEvents(polls));
        assert_eq!(
            coordinator.process_next(&inventory, Duration::ZERO),
            Err(LifecycleError::EventStorm)
        );
        assert!(inventory.validate(&descriptor).is_err());
    }

    #[test]
    fn boundary_event_preserves_unaffected_camera_identity_and_events() {
        let inventory = TestInventory::new();
        let camera_a = "/devices/pci/usb1/camera-a";
        let camera_b = "/devices/pci/usb2/camera-b";
        let seeded = inventory
            .reconcile(vec![
                observation_at(camera_a, "a-old"),
                observation_at(camera_b, "b-stable"),
            ])
            .unwrap();
        let old_a = seeded
            .iter()
            .find(|event| event.topology_path() == camera_a)
            .unwrap()
            .descriptor()
            .clone();
        let old_b = seeded
            .iter()
            .find(|event| event.topology_path() == camera_b)
            .unwrap()
            .descriptor()
            .clone();
        let dirty_a = DeviceEventHint::new(
            DeviceEventKind::DirtyUvc,
            format!("{camera_a}/video4linux/video0"),
        )
        .with_affected_topology(camera_a);
        let loss_a = DeviceEventHint::new(
            DeviceEventKind::ContinuityLost,
            format!("{camera_a}/camera-a:1.0"),
        )
        .with_affected_topology(camera_a);
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([
                Ok(vec![
                    observation_at(camera_a, "a-old"),
                    observation_at(camera_b, "b-stable"),
                ]),
                Ok(vec![
                    observation_at(camera_a, "a-new"),
                    observation_at(camera_b, "b-stable"),
                ]),
            ])),
            FakeEvents(VecDeque::from([
                Ok(vec![dirty_a]),
                Ok(Vec::new()),
                Ok(Vec::new()),
                Ok(vec![loss_a]),
                Ok(Vec::new()),
                Ok(Vec::new()),
            ])),
        );
        let events = coordinator
            .process_next(&inventory, Duration::ZERO)
            .unwrap();
        assert!(inventory.validate(&old_a).is_err());
        assert_eq!(inventory.validate(&old_b), Ok(()));
        assert!(events.iter().all(|event| event.topology_path() == camera_a));
        assert_eq!(events.iter().filter(|event| event.is_removed()).count(), 1);
        assert_eq!(events.iter().filter(|event| event.is_added()).count(), 1);
    }

    #[test]
    fn one_camera_continuity_loss_does_not_retire_another_camera() {
        let inventory = TestInventory::new();
        let camera_a = "/devices/pci/usb1/camera-a";
        let camera_b = "/devices/pci/usb2/camera-b";
        let seeded = inventory
            .reconcile(vec![
                observation_at(camera_a, "a-old"),
                observation_at(camera_b, "b-stable"),
            ])
            .unwrap();
        let old_a = seeded
            .iter()
            .find(|event| event.topology_path() == camera_a)
            .unwrap()
            .descriptor()
            .clone();
        let old_b = seeded
            .iter()
            .find(|event| event.topology_path() == camera_b)
            .unwrap()
            .descriptor()
            .clone();
        let loss_a = DeviceEventHint::new(
            DeviceEventKind::ContinuityLost,
            format!("{camera_a}/camera-a:1.0"),
        )
        .with_affected_topology(camera_a);
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([Ok(vec![
                observation_at(camera_a, "a-new"),
                observation_at(camera_b, "b-stable"),
            ])])),
            FakeEvents(VecDeque::from([
                Ok(vec![loss_a]),
                Ok(Vec::new()),
                Ok(Vec::new()),
                Ok(Vec::new()),
            ])),
        );
        coordinator
            .process_next(&inventory, Duration::ZERO)
            .unwrap();
        assert!(inventory.validate(&old_a).is_err());
        assert_eq!(inventory.validate(&old_b), Ok(()));
    }

    #[test]
    fn empty_startup_inventory_can_discover_a_later_hotplug() {
        let inventory = TestInventory::new();
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([
                Ok(Vec::new()),
                Ok(vec![observation("hotplugged")]),
            ])),
            FakeEvents(VecDeque::from([
                Ok(Vec::new()),
                Ok(Vec::new()),
                Ok(vec![DeviceEventHint::new(
                    DeviceEventKind::DirtyUvc,
                    "/devices/pci/usb1/camera/video4linux/video0",
                )]),
                Ok(Vec::new()),
                Ok(Vec::new()),
                Ok(Vec::new()),
            ])),
        );
        assert!(coordinator.initialize(&inventory).unwrap().is_empty());
        let events = coordinator
            .process_next(&inventory, Duration::ZERO)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_added());
    }

    #[test]
    fn missing_video4linux_class_is_an_authoritative_empty_snapshot() {
        let root =
            std::env::temp_dir().join(format!("irlume-missing-video4linux-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut source = SysfsSnapshotSource { root };
        assert_eq!(source.snapshot(), Ok(Vec::new()));
    }

    #[test]
    fn vanished_video_class_entry_does_not_abort_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "irlume-vanished-video4linux-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("video10")).unwrap();
        let mut source = SysfsSnapshotSource { root: root.clone() };
        assert_eq!(source.snapshot(), Ok(Vec::new()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn exact_allowlisted_virtual_camera_is_present_in_test_inventory() {
        use std::os::unix::fs::symlink;

        let _guard = crate::testenv::env_lock();
        let root =
            std::env::temp_dir().join(format!("irlume-virtual-video4linux-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rgb = root.join("devices/virtual/video4linux/video8");
        let ir = root.join("devices/virtual/video4linux/video9");
        let excluded = root.join("devices/virtual/video4linux/video10");
        let driver = root.join("drivers/v4l2loopback");
        std::fs::create_dir_all(root.join("class/video4linux/video8")).unwrap();
        std::fs::create_dir_all(root.join("class/video4linux/video9")).unwrap();
        std::fs::create_dir_all(root.join("class/video4linux/video10")).unwrap();
        std::fs::create_dir_all(&rgb).unwrap();
        std::fs::create_dir_all(&ir).unwrap();
        std::fs::create_dir_all(&excluded).unwrap();
        std::fs::create_dir_all(&driver).unwrap();
        symlink(&rgb, root.join("class/video4linux/video8/device")).unwrap();
        symlink(&ir, root.join("class/video4linux/video9/device")).unwrap();
        symlink(&excluded, root.join("class/video4linux/video10/device")).unwrap();
        symlink(&driver, rgb.join("driver")).unwrap();
        symlink(&driver, ir.join("driver")).unwrap();
        symlink(&driver, excluded.join("driver")).unwrap();
        let _allow = crate::testenv::EnvGuard::set(
            "IRLUME_TEST_ALLOW_VIRTUAL_CAMERA",
            "/dev/video8,/dev/video9",
        );

        let mut source = SysfsSnapshotSource {
            root: root.join("class/video4linux"),
        };
        let observations = source.snapshot().unwrap();
        assert_eq!(observations.len(), 1);
        let evidence = observations[0].lifecycle_evidence();
        assert!(evidence.iter().any(|item| item.contains("/dev/video8")));
        assert!(evidence.iter().any(|item| item.contains("/dev/video9")));
        assert!(!evidence.iter().any(|item| item.contains("/dev/video10")));

        let mut inventory = CameraInventory::new();
        inventory.reconcile(observations).unwrap();
        assert!(inventory
            .reference_for_endpoints(&["/dev/video8", "/dev/video9"])
            .is_ok());
        assert!(matches!(
            inventory.reference_for_endpoints(&["/dev/video10"]),
            Err(CameraInventoryError::UnknownCamera)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn thread_spawn_failure_invalidates_published_inventory() {
        let inventory = TestInventory::new();
        let descriptor = inventory
            .reconcile(vec![observation("published")])
            .unwrap()
            .into_iter()
            .find_map(|event| match event {
                CameraInventoryEvent::Added(descriptor) => Some(descriptor),
                _ => None,
            })
            .unwrap();
        let spawned: std::io::Result<std::thread::JoinHandle<()>> =
            Err(std::io::Error::other("synthetic spawn failure"));

        assert!(matches!(
            finish_spawn(&inventory, spawned),
            Err(LifecycleError::Monitor(_))
        ));
        assert!(matches!(
            inventory.validate(&descriptor),
            Err(CameraInventoryError::ContinuityLost)
        ));
    }

    #[test]
    fn worker_exit_guard_retires_published_inventory() {
        let inventory = TestInventory::new();
        let descriptor = inventory
            .reconcile(vec![observation("published")])
            .unwrap()
            .remove(0)
            .descriptor()
            .clone();
        {
            let _guard = WorkerExitGuard::new(&inventory);
        }
        assert!(inventory.validate(&descriptor).is_err());
    }

    #[test]
    fn snapshot_requires_a_real_quiet_interval_before_publish() {
        struct RecordingEvents(std::sync::Arc<Mutex<Vec<Duration>>>);
        impl DeviceEventSource for RecordingEvents {
            fn poll(&mut self, timeout: Duration) -> Result<Vec<DeviceEventHint>, LifecycleError> {
                self.0.lock().unwrap().push(timeout);
                Ok(Vec::new())
            }
        }
        let waits = std::sync::Arc::new(Mutex::new(Vec::new()));
        let mut coordinator = LifecycleCoordinator::new(
            FakeSnapshots(VecDeque::from([Ok(vec![observation("quiet")])])),
            RecordingEvents(waits.clone()),
        );
        coordinator.initialize(&TestInventory::new()).unwrap();
        assert_eq!(*waits.lock().unwrap(), [COALESCE_QUIET, Duration::ZERO]);
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
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::ContinuityLost)]),
                Ok(vec![hint(DeviceEventKind::ContinuityLost)]),
                Ok(Vec::new()),
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
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(Vec::new()),
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
                Ok(Vec::new()),
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(vec![hint(DeviceEventKind::DirtyUvc)]),
                Ok(Vec::new()),
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
            bind_monitor_before_snapshot(UdevEventSource::new, SysfsSnapshotSource::default)
                .unwrap();
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
        let observations = SysfsSnapshotSource::default().snapshot().unwrap();
        let camera = observations
            .iter()
            .find(|observation| observation.physical_id().serial() == Some("200901010001"))
            .expect("Shinetech 3277:0059 camera is present");
        assert!(camera.physical_id().topology_path().ends_with("/usb3/3-5"));
        assert_eq!(camera.lifecycle_evidence().len(), 4);
        assert!(camera
            .lifecycle_evidence()
            .iter()
            .any(|evidence| evidence.contains("/dev/video0") && evidence.ends_with("|capture")));
        assert!(camera
            .lifecycle_evidence()
            .iter()
            .any(|evidence| evidence.contains("/dev/video3") && evidence.ends_with("|metadata")));
    }

    #[test]
    fn udev_records_group_one_physical_camera_and_normalize_order() {
        let records = vec![
            UdevNodeRecord {
                usb_devpath: "/devices/pci/usb1/camera".into(),
                serial: Some("serial".into()),
                node_devpath: "/devices/pci/usb1/camera/1.2/video2".into(),
                devnode: "/dev/video2".into(),
                interface_number: Some("02".into()),
                capture_node: Some(true),
            },
            UdevNodeRecord {
                usb_devpath: "/devices/pci/usb1/camera".into(),
                serial: Some("serial".into()),
                node_devpath: "/devices/pci/usb1/camera/1.0/video0".into(),
                devnode: "/dev/video0".into(),
                interface_number: Some("00".into()),
                capture_node: Some(true),
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
