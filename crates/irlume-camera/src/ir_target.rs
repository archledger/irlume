// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Configured, sysfs-validated target for experimental IR-only capture.
//!
//! Resolution reads configuration and sysfs only. It never opens a video node,
//! probes formats, or discovers a replacement endpoint.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceNumber(u32, u32);

#[derive(Debug)]
struct ResolvedEndpoint {
    path: PathBuf,
    device: DeviceNumber,
}

trait DeviceAccess {
    fn resolve_endpoint(&self, path: &str) -> Result<ResolvedEndpoint, IrTargetError>;
    fn endpoint_for_node(&self, node: &str) -> String;
}

struct HostDevices;

impl DeviceAccess for HostDevices {
    fn resolve_endpoint(&self, path: &str) -> Result<ResolvedEndpoint, IrTargetError> {
        let resolved = std::fs::canonicalize(path).map_err(|_| {
            IrTargetError::InvalidEndpoint(format!("configured endpoint {path} is missing"))
        })?;
        let metadata = std::fs::metadata(&resolved).map_err(|_| {
            IrTargetError::InvalidEndpoint(format!("configured endpoint {path} is unreadable"))
        })?;
        if !metadata.file_type().is_char_device() {
            return Err(IrTargetError::InvalidEndpoint(format!(
                "configured endpoint {path} is not a character device"
            )));
        }
        let rdev = metadata.rdev();
        Ok(ResolvedEndpoint {
            path: resolved,
            device: DeviceNumber(libc::major(rdev), libc::minor(rdev)),
        })
    }

    fn endpoint_for_node(&self, node: &str) -> String {
        format!("/dev/{node}")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrCaptureTarget {
    rgb_endpoint: String,
    endpoint: String,
    metadata_endpoint: Option<String>,
    identity: String,
    interface: PathBuf,
    image_name: String,
    image_device: DeviceNumber,
    metadata_device: Option<DeviceNumber>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrTargetError {
    Unconfigured,
    InvalidEndpoint(String),
    BindingUnavailable(String),
    UnsupportedTopology(String),
    Changed,
}

impl std::fmt::Display for IrTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconfigured => f.write_str("an explicit RGB and IR camera pair is required"),
            Self::InvalidEndpoint(reason) => write!(f, "invalid configured IR target: {reason}"),
            Self::BindingUnavailable(reason) => {
                write!(f, "IR target identity unavailable: {reason}")
            }
            Self::UnsupportedTopology(reason) => {
                write!(f, "unsupported IR target topology: {reason}")
            }
            Self::Changed => f.write_str("configured IR target changed after validation"),
        }
    }
}

impl std::error::Error for IrTargetError {}

impl IrCaptureTarget {
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub fn metadata_endpoint(&self) -> Option<&str> {
        self.metadata_endpoint.as_deref()
    }

    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    #[must_use]
    pub fn lease_endpoints(&self) -> Vec<&str> {
        let mut endpoints = vec![self.endpoint.as_str()];
        if let Some(metadata) = self.metadata_endpoint.as_deref() {
            endpoints.push(metadata);
        }
        endpoints
    }

    /// Re-read the exact configured endpoints and sysfs evidence. A changed
    /// node, interface, identity, index, name, or sibling set is refused.
    ///
    /// # Errors
    /// Returns the concrete configuration, identity, topology, or change refusal.
    pub fn validate(&self) -> Result<(), IrTargetError> {
        self.validate_in(Path::new("/sys/class/video4linux"))
    }

    /// Revalidate the target before routing its image open through an existing
    /// operation lease. The operation must cover [`Self::lease_endpoints`].
    ///
    /// # Errors
    /// Returns a target-validation, lease-continuity, or camera-open error.
    pub fn open(
        &self,
        operation: &crate::lease::CameraOperationSession,
    ) -> irlume_common::Result<crate::IrCamera> {
        self.open_with(|| self.validate(), |endpoint| operation.open_ir(endpoint))
    }

    /// Capture once through this exact configured target and operation lease.
    ///
    /// The target is revalidated before open and again before its adaptive-startup
    /// session. The full delivered-rate window remains mandatory; explicit
    /// metadata absence never falls back to discovery.
    ///
    /// # Errors
    /// Returns cancellation, deadline, target, lease, camera, metadata, emitter,
    /// privacy, delivered-rate, or capture errors.
    pub fn capture_with_stats_and_control(
        &self,
        operation: &crate::lease::CameraOperationSession,
        control: &crate::CaptureControl,
    ) -> irlume_common::Result<(crate::Frame, crate::IrCaptureStats)> {
        // Nested capture diagnostics must reuse this lease rather than wait
        // for the camera already owned here. Keep teardown in the same scope.
        operation
            .run(|| {
                control.check()?;
                let camera = {
                    let _timing = control.stage(crate::capture_timing::Stage::Open);
                    self.open(operation)?
                };
                let mut session = camera.session_for_target_with_control(self, control)?;
                let result = {
                    let _timing = control.stage(crate::capture_timing::Stage::Frames);
                    session.capture_with_stats()
                };
                finish_capture(control, session, result)
            })
            .map_err(|error| irlume_common::Error::Hardware(error.to_string()))?
    }

    fn open_with<T>(
        &self,
        validate: impl FnOnce() -> Result<(), IrTargetError>,
        open_ir: impl FnOnce(&str) -> irlume_common::Result<T>,
    ) -> irlume_common::Result<T> {
        validate().map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
        open_ir(&self.endpoint)
    }

    pub(super) fn session_with<T>(
        &self,
        opened_endpoint: &str,
        validate: impl FnOnce() -> Result<(), IrTargetError>,
        start: impl FnOnce(
            crate::IrSessionStartup,
            crate::ir_metadata::MetadataSelection<'_>,
        ) -> irlume_common::Result<T>,
    ) -> irlume_common::Result<T> {
        if opened_endpoint != self.endpoint() {
            return Err(irlume_common::Error::Hardware(
                "opened IR camera does not match validated target".into(),
            ));
        }
        validate().map_err(|error| irlume_common::Error::Hardware(error.to_string()))?;
        start(crate::IrSessionStartup::Adaptive, self.metadata_selection())
    }

    pub(crate) fn validate_in(&self, sysfs: &Path) -> Result<(), IrTargetError> {
        let observed = resolve_configured_pair_with(
            Some((self.rgb_endpoint.clone(), self.endpoint.clone())),
            sysfs,
            &HostDevices,
        )?;
        if observed == *self {
            Ok(())
        } else {
            Err(IrTargetError::Changed)
        }
    }

    pub(crate) fn metadata_selection(&self) -> crate::ir_metadata::MetadataSelection<'_> {
        self.metadata_endpoint.as_deref().map_or(
            crate::ir_metadata::MetadataSelection::Absent,
            crate::ir_metadata::MetadataSelection::Exact,
        )
    }
}

fn finish_capture<R, S>(
    control: &crate::CaptureControl,
    session: S,
    result: irlume_common::Result<R>,
) -> irlume_common::Result<R> {
    {
        let _timing = control.stage(crate::capture_timing::Stage::SessionRelease);
        drop(session);
    }
    control.check()?;
    result
}

/// Resolve the configured pair without device I/O or fallback discovery.
///
/// # Errors
/// Returns a configuration, identity, or supported-topology refusal.
pub fn configured_ir_target() -> Result<IrCaptureTarget, IrTargetError> {
    resolve_configured_pair_with(
        crate::configured_pair_no_probe(),
        Path::new("/sys/class/video4linux"),
        &HostDevices,
    )
}

#[derive(Debug)]
struct NodeEvidence {
    endpoint: String,
    interface: PathBuf,
    index: u32,
    name: String,
    device: DeviceNumber,
}

fn node_name(endpoint: &str) -> Result<&str, IrTargetError> {
    Path::new(endpoint)
        .file_name()
        .and_then(|v| v.to_str())
        .filter(|v| {
            v.starts_with("video") && v[5..].chars().all(|c| c.is_ascii_digit()) && v.len() > 5
        })
        .ok_or_else(|| {
            IrTargetError::InvalidEndpoint(format!("{endpoint} is not a video node path"))
        })
}

fn sysfs_device(class: &Path, endpoint: &str) -> Result<DeviceNumber, IrTargetError> {
    let raw = std::fs::read_to_string(class.join("dev")).map_err(|_| {
        IrTargetError::UnsupportedTopology(format!("{endpoint} has no readable sysfs dev number"))
    })?;
    let (major, minor) = raw.trim().split_once(':').ok_or_else(|| {
        IrTargetError::UnsupportedTopology(format!("{endpoint} has an invalid sysfs dev number"))
    })?;
    let parse = |value: &str| value.parse::<u32>().ok();
    match (parse(major), parse(minor)) {
        (Some(major), Some(minor)) => Ok(DeviceNumber(major, minor)),
        _ => Err(IrTargetError::UnsupportedTopology(format!(
            "{endpoint} has an invalid sysfs dev number"
        ))),
    }
}

fn evidence(resolved: ResolvedEndpoint, sysfs: &Path) -> Result<NodeEvidence, IrTargetError> {
    let endpoint = resolved.path.to_string_lossy().into_owned();
    let node = node_name(&endpoint)?;
    let class = sysfs.join(node);
    let interface = std::fs::canonicalize(class.join("device")).map_err(|_| {
        IrTargetError::InvalidEndpoint(format!("{endpoint} has no readable sysfs interface"))
    })?;
    let index = std::fs::read_to_string(class.join("index"))
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| {
            IrTargetError::UnsupportedTopology(format!("{endpoint} has no unambiguous sysfs index"))
        })?;
    let name = std::fs::read_to_string(class.join("name"))
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            IrTargetError::UnsupportedTopology(format!("{endpoint} has no readable sysfs name"))
        })?;
    let advertised = sysfs_device(&class, &endpoint)?;
    if advertised != resolved.device {
        return Err(IrTargetError::InvalidEndpoint(format!(
            "{endpoint} device number does not match its sysfs entry"
        )));
    }
    Ok(NodeEvidence {
        endpoint,
        interface,
        index,
        name,
        device: resolved.device,
    })
}

fn identity(interface: &Path) -> Result<String, IrTargetError> {
    let mut cursor = Some(interface);
    while let Some(path) = cursor {
        if path.join("idVendor").is_file() {
            let read = |name: &str| {
                std::fs::read_to_string(path.join(name))
                    .ok()
                    .map(|v| v.trim().to_owned())
                    .filter(|v| !v.is_empty())
            };
            let vendor = read("idVendor").ok_or_else(|| {
                IrTargetError::BindingUnavailable("USB vendor is unreadable".into())
            })?;
            let product = read("idProduct").ok_or_else(|| {
                IrTargetError::BindingUnavailable("USB product is unreadable".into())
            })?;
            let mut value = format!("{vendor}:{product}");
            if let Some(serial) = read("serial") {
                value.push(':');
                value.push_str(&serial);
            }
            return Ok(value.to_lowercase());
        }
        cursor = path.parent();
    }
    Err(IrTargetError::BindingUnavailable(
        "no USB identity in the IR interface ancestry".into(),
    ))
}

fn siblings(
    interface: &Path,
    sysfs: &Path,
    devices: &impl DeviceAccess,
) -> Result<Vec<NodeEvidence>, IrTargetError> {
    let entries = std::fs::read_dir(sysfs).map_err(|_| {
        IrTargetError::UnsupportedTopology("video4linux sysfs is unreadable".into())
    })?;
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| {
            IrTargetError::UnsupportedTopology("video4linux membership is unreadable".into())
        })?;
        let candidate_interface = match std::fs::canonicalize(entry.path().join("device")) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if candidate_interface != interface {
            continue;
        }
        let node = entry
            .file_name()
            .into_string()
            .map_err(|_| IrTargetError::UnsupportedTopology("non-Unicode video node".into()))?;
        let endpoint = devices.endpoint_for_node(&node);
        found.push(evidence(devices.resolve_endpoint(&endpoint)?, sysfs)?);
    }
    found.sort_by(|a, b| {
        a.index
            .cmp(&b.index)
            .then_with(|| a.endpoint.cmp(&b.endpoint))
    });
    Ok(found)
}

fn resolve_configured_pair_with(
    pair: Option<(String, String)>,
    sysfs: &Path,
    devices: &impl DeviceAccess,
) -> Result<IrCaptureTarget, IrTargetError> {
    let (rgb_endpoint, endpoint) = pair.ok_or(IrTargetError::Unconfigured)?;
    let rgb_resolved = devices.resolve_endpoint(&rgb_endpoint)?;
    let ir_resolved = devices.resolve_endpoint(&endpoint)?;
    if rgb_resolved.path == ir_resolved.path || rgb_resolved.device == ir_resolved.device {
        return Err(IrTargetError::InvalidEndpoint(
            "RGB and IR resolve to the same endpoint".into(),
        ));
    }
    let rgb = evidence(rgb_resolved, sysfs)?;
    let ir = evidence(ir_resolved, sysfs)?;
    if rgb.interface == ir.interface {
        return Err(IrTargetError::UnsupportedTopology(
            "configured RGB shares the IR interface".into(),
        ));
    }
    if ir.index != 0 {
        return Err(IrTargetError::UnsupportedTopology(
            "selected IR image node is not sysfs index 0".into(),
        ));
    }
    let members = siblings(&ir.interface, sysfs, devices)?;
    if members.first().is_none_or(|node| {
        node.endpoint != ir.endpoint || node.device != ir.device || node.index != 0
    }) {
        return Err(IrTargetError::UnsupportedTopology(
            "selected IR image is not the sole index-0 interface member".into(),
        ));
    }
    let metadata_endpoint = match members.as_slice() {
        [_image] => None,
        [image, metadata] if metadata.index == 1 && metadata.name == image.name => {
            Some(metadata.endpoint.clone())
        }
        _ => return Err(IrTargetError::UnsupportedTopology("IR interface must contain one image node and at most its same-name index-1 metadata companion".into())),
    };
    Ok(IrCaptureTarget {
        rgb_endpoint: rgb.endpoint,
        endpoint: ir.endpoint,
        metadata_endpoint,
        identity: identity(&ir.interface)?,
        interface: ir.interface,
        image_name: ir.name,
        image_device: ir.device,
        metadata_device: members.get(1).map(|node| node.device),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    struct Fixture {
        root: PathBuf,
        sysfs: PathBuf,
        dev: PathBuf,
    }
    impl Fixture {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("irlume-ir-target-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let sysfs = root.join("sys/class/video4linux");
            let dev = root.join("dev");
            std::fs::create_dir_all(&sysfs).unwrap();
            std::fs::create_dir_all(&dev).unwrap();
            Self { root, sysfs, dev }
        }
        fn interface(&self, name: &str, vendor: Option<&str>) -> PathBuf {
            let usb = self.root.join("sys/devices/pci0000:00/usb1/1-1");
            std::fs::create_dir_all(&usb).unwrap();
            if let Some(v) = vendor {
                std::fs::write(usb.join("idVendor"), v).unwrap();
                std::fs::write(usb.join("idProduct"), "1234\n").unwrap();
                std::fs::write(usb.join("serial"), "fixture\n").unwrap();
            }
            let i = usb.join(name);
            std::fs::create_dir_all(&i).unwrap();
            i
        }
        fn node(&self, node: &str, interface: &Path, index: &str, name: &str) -> String {
            let class = self.sysfs.join(node);
            std::fs::create_dir_all(&class).unwrap();
            symlink(interface, class.join("device")).unwrap();
            std::fs::write(class.join("index"), index).unwrap();
            std::fs::write(class.join("name"), name).unwrap();
            std::fs::write(
                class.join("dev"),
                format!("81:{}\n", node.trim_start_matches("video")),
            )
            .unwrap();
            let backing = self.root.join("nodes").join(node);
            std::fs::create_dir_all(backing.parent().unwrap()).unwrap();
            std::fs::write(&backing, b"").unwrap();
            let dev = self.dev.join(node);
            symlink(backing, &dev).unwrap();
            dev.to_string_lossy().into_owned()
        }

        fn resolve(
            &self,
            pair: Option<(String, String)>,
        ) -> Result<IrCaptureTarget, IrTargetError> {
            resolve_configured_pair_with(pair, &self.sysfs, self)
        }
    }
    impl DeviceAccess for Fixture {
        fn resolve_endpoint(&self, path: &str) -> Result<ResolvedEndpoint, IrTargetError> {
            let resolved = std::fs::canonicalize(path).map_err(|_| {
                IrTargetError::InvalidEndpoint(format!("fixture endpoint {path} is missing"))
            })?;
            let node = node_name(resolved.to_str().unwrap())?;
            let minor = node.trim_start_matches("video").parse().unwrap();
            Ok(ResolvedEndpoint {
                path: resolved,
                device: DeviceNumber(81, minor),
            })
        }

        fn endpoint_for_node(&self, node: &str) -> String {
            self.dev.join(node).to_string_lossy().into_owned()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn isolated_ir_interface_resolves_exact_optional_metadata() {
        let f = Fixture::new("ok");
        let rgb_if = f.interface("1-1:1.0", None);
        let ir_if = f.interface("1-1:1.2", Some("046d\n"));
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
        let meta = f.node("video3", &ir_if, "1\n", "IR Camera\n");
        let t = f.resolve(Some((rgb, ir.clone()))).unwrap();
        let canonical_ir = std::fs::canonicalize(&ir).unwrap();
        let canonical_meta = std::fs::canonicalize(&meta).unwrap();
        assert_eq!(t.endpoint(), canonical_ir.to_str().unwrap());
        assert_eq!(t.metadata_endpoint(), canonical_meta.to_str());
        assert_eq!(t.identity(), "046d:1234:fixture");
        assert_eq!(
            t.lease_endpoints(),
            vec![
                canonical_ir.to_str().unwrap(),
                canonical_meta.to_str().unwrap()
            ]
        );
        assert_eq!(
            resolve_configured_pair_with(
                Some((t.rgb_endpoint.clone(), t.endpoint.clone())),
                &f.sysfs,
                &f
            )
            .unwrap(),
            t
        );
    }
    #[test]
    fn metadata_absence_is_explicit_and_does_not_discover() {
        let f = Fixture::new("absent");
        let rgb_if = f.interface("1-1:1.0", None);
        let ir_if = f.interface("1-1:1.2", Some("046d\n"));
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
        let t = f.resolve(Some((rgb, ir))).unwrap();
        assert_eq!(t.metadata_endpoint(), None);
        assert_eq!(t.lease_endpoints().len(), 1);
    }
    #[test]
    fn unsafe_or_ambiguous_topologies_fail_closed() {
        assert_eq!(
            resolve_configured_pair_with(None, Path::new("/missing"), &Fixture::new("unused")),
            Err(IrTargetError::Unconfigured)
        );
        let f = Fixture::new("bad");
        let rgb_if = f.interface("1-1:1.0", None);
        let ir_if = f.interface("1-1:1.2", Some("046d\n"));
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
        assert!(matches!(
            f.resolve(Some((ir.clone(), ir.clone()))),
            Err(IrTargetError::InvalidEndpoint(_))
        ));
        let _ = f.node("video4", &ir_if, "2\n", "IR Camera\n");
        assert!(matches!(
            f.resolve(Some((rgb, ir))),
            Err(IrTargetError::UnsupportedTopology(_))
        ));
    }
    #[test]
    fn revalidation_detects_renumbering_and_replacement() {
        let f = Fixture::new("changed");
        let rgb_if = f.interface("1-1:1.0", None);
        let ir_if = f.interface("1-1:1.2", Some("046d\n"));
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
        let t = f.resolve(Some((rgb, ir))).unwrap();
        std::fs::write(f.sysfs.join("video2/index"), "1\n").unwrap();
        assert!(matches!(
            resolve_configured_pair_with(
                Some((t.rgb_endpoint.clone(), t.endpoint.clone())),
                &f.sysfs,
                &f
            ),
            Err(IrTargetError::Changed) | Err(IrTargetError::UnsupportedTopology(_))
        ));
    }

    #[test]
    fn binding_and_interface_ambiguity_are_never_guessed() {
        let f = Fixture::new("binding");
        let no_id = f.root.join("sys/devices/pci0000:00/usb2/2-1/2-1:1.2");
        std::fs::create_dir_all(&no_id).unwrap();
        let rgb_if = f.interface("1-1:1.0", None);
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &no_id, "0\n", "IR Camera\n");
        assert!(matches!(
            f.resolve(Some((rgb, ir))),
            Err(IrTargetError::BindingUnavailable(_))
        ));

        let f = Fixture::new("shared");
        let interface = f.interface("1-1:1.0", Some("046d\n"));
        let rgb = f.node("video0", &interface, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &interface, "0\n", "IR Camera\n");
        assert!(matches!(
            f.resolve(Some((rgb, ir))),
            Err(IrTargetError::UnsupportedTopology(_))
        ));
    }

    #[test]
    fn metadata_must_be_the_same_name_index_one_companion() {
        for (tag, index, name) in [
            ("wrong-index", "2\n", "IR Camera\n"),
            ("wrong-name", "1\n", "Other Camera\n"),
        ] {
            let f = Fixture::new(tag);
            let rgb_if = f.interface("1-1:1.0", None);
            let ir_if = f.interface("1-1:1.2", Some("046d\n"));
            let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
            let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
            let _metadata = f.node("video3", &ir_if, index, name);
            assert!(matches!(
                f.resolve(Some((rgb, ir))),
                Err(IrTargetError::UnsupportedTopology(_))
            ));
        }
    }

    #[test]
    fn canonical_aliases_bind_to_the_sysfs_device_number() {
        let f = Fixture::new("alias");
        let rgb_if = f.interface("1-1:1.0", None);
        let ir_if = f.interface("1-1:1.2", Some("046d\n"));
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
        let aliases = f.dev.join("by-id");
        std::fs::create_dir_all(&aliases).unwrap();
        let alias = aliases.join("configured-ir");
        symlink(&ir, &alias).unwrap();
        let target = f
            .resolve(Some((rgb, alias.to_string_lossy().into_owned())))
            .unwrap();
        assert_eq!(
            target.endpoint(),
            std::fs::canonicalize(ir).unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn path_and_sysfs_device_number_must_correspond() {
        let f = Fixture::new("rdev");
        let rgb_if = f.interface("1-1:1.0", None);
        let ir_if = f.interface("1-1:1.2", Some("046d\n"));
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
        std::fs::write(f.sysfs.join("video2/dev"), "81:99\n").unwrap();
        assert!(matches!(
            f.resolve(Some((rgb, ir))),
            Err(IrTargetError::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn validated_open_routes_only_the_canonical_ir_endpoint() {
        let f = Fixture::new("open-recorder");
        let rgb_if = f.interface("1-1:1.0", None);
        let ir_if = f.interface("1-1:1.2", Some("046d\n"));
        let rgb = f.node("video0", &rgb_if, "0\n", "RGB Camera\n");
        let ir = f.node("video2", &ir_if, "0\n", "IR Camera\n");
        let target = f.resolve(Some((rgb, ir))).unwrap();
        let opens = std::cell::RefCell::new(Vec::new());
        target
            .open_with(
                || {
                    resolve_configured_pair_with(
                        Some((target.rgb_endpoint.clone(), target.endpoint.clone())),
                        &f.sysfs,
                        &f,
                    )
                    .map(|_| ())
                },
                |endpoint| {
                    opens.borrow_mut().push(endpoint.to_owned());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(opens.into_inner(), [target.endpoint()]);
    }

    #[test]
    fn target_session_uses_the_full_rate_window_without_an_unconditional_flush() {
        let target = unopened_target();
        let mut stream =
            crate::tests::rate_fill_fixture(crate::contracts::StreamRole::Ir, 100, 66_667);
        target
            .session_with(
                target.endpoint(),
                || Ok(()),
                |startup, metadata| {
                    assert!(matches!(
                        metadata,
                        crate::ir_metadata::MetadataSelection::Absent
                    ));
                    startup.warm_up(target.endpoint(), &mut stream, &crate::no_progress())?;
                    startup
                        .fill(&mut stream)
                        .map_err(|error| crate::map_io(target.endpoint(), error))
                },
            )
            .unwrap();
        assert_eq!(stream.observations, 31, "reuse the validated warmup seed");
        let (_, _, _, _, evidence) = stream.next().unwrap();
        assert_eq!(evidence.window_count(), 30);
        assert!(evidence.meets_floor());
    }

    #[test]
    fn target_session_keeps_exact_metadata_and_refuses_a_slow_stream() {
        let mut target = unopened_target();
        target.metadata_endpoint = Some("/fixture/metadata".into());
        let mut stream =
            crate::tests::rate_fill_fixture(crate::contracts::StreamRole::Ir, 100, 200_000);
        target
            .session_with(
                target.endpoint(),
                || Ok(()),
                |startup, metadata| {
                    assert!(matches!(
                        metadata,
                        crate::ir_metadata::MetadataSelection::Exact("/fixture/metadata")
                    ));
                    startup.warm_up(target.endpoint(), &mut stream, &crate::no_progress())?;
                    startup
                        .fill(&mut stream)
                        .map_err(|error| crate::map_io(target.endpoint(), error))
                },
            )
            .unwrap();
        assert_eq!(
            stream.observations, 42,
            "slow startup retains the bounded extra work"
        );
        assert!(matches!(
            stream.next(),
            Err(crate::DeliveryError::BelowFloor(_))
        ));
    }

    #[test]
    fn target_session_refuses_a_mismatched_camera_before_validation_or_startup() {
        let target = unopened_target();
        let result: irlume_common::Result<()> = target.session_with(
            "/fixture/another-camera",
            || panic!("mismatched camera must be refused before validation"),
            |_, _| panic!("mismatched camera must never start a session"),
        );
        assert!(matches!(result, Err(irlume_common::Error::Hardware(_))));
    }

    #[test]
    fn target_session_revalidates_before_startup() {
        let target = unopened_target();
        let result: irlume_common::Result<()> = target.session_with(
            target.endpoint(),
            || Err(IrTargetError::Changed),
            |_, _| panic!("changed target must never start a session"),
        );
        assert!(matches!(result, Err(irlume_common::Error::Hardware(_))));
    }

    #[test]
    fn target_capture_releases_before_the_final_control_check() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        struct CancelOnDrop(Arc<AtomicBool>);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let cancelled = Arc::new(AtomicBool::new(false));
        let observed = cancelled.clone();
        let control = crate::CaptureControl::new(
            crate::no_progress(),
            Arc::new(move || observed.load(Ordering::SeqCst)),
        );
        let result = finish_capture::<(), _>(
            &control,
            CancelOnDrop(cancelled.clone()),
            Err(irlume_common::Error::Hardware("capture failed".into())),
        );
        assert!(cancelled.load(Ordering::SeqCst));
        assert!(matches!(result, Err(irlume_common::Error::Preempted(_))));
    }

    const MISSING_IR: &str = "/definitely-missing-irlume-context-fixture/ir";

    fn unopened_target() -> IrCaptureTarget {
        IrCaptureTarget {
            rgb_endpoint: "/definitely-missing-irlume-context-fixture/rgb".into(),
            endpoint: MISSING_IR.into(),
            metadata_endpoint: None,
            identity: "fixture".into(),
            interface: PathBuf::from("/definitely-missing-irlume-context-fixture/sysfs"),
            image_name: "fixture IR".into(),
            image_device: DeviceNumber(81, 2),
            metadata_device: None,
        }
    }

    #[test]
    fn privacy_lookup_without_active_scope_waits_for_its_own_lease() {
        crate::backend::tests::with_test_camera_operation(MISSING_IR, |_| {
            assert!(crate::lease::active_permit(MISSING_IR).unwrap().is_none());
            let started = std::time::Instant::now();
            assert!(!crate::privacy_engaged(MISSING_IR));
            let elapsed = started.elapsed();
            eprintln!("unscoped privacy lookup elapsed: {elapsed:?}");
            assert!(elapsed >= std::time::Duration::from_secs(2));
        });
    }

    #[test]
    fn target_capture_keeps_its_lease_active_for_nested_privacy_lookup() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        crate::backend::tests::with_test_camera_operation(MISSING_IR, |operation| {
            let reused = Arc::new(AtomicBool::new(false));
            let observed = reused.clone();
            // Exercise the real helper before any V4L2 open. The existing
            // cancellation callback observes the same scope used by capture.
            let control = crate::CaptureControl::new(
                crate::no_progress(),
                Arc::new(move || {
                    let started = std::time::Instant::now();
                    assert!(!crate::privacy_engaged(MISSING_IR));
                    eprintln!(
                        "target-scoped privacy lookup elapsed: {:?}",
                        started.elapsed()
                    );
                    observed.store(
                        crate::lease::permit_for_endpoint(
                            MISSING_IR,
                            crate::lease::CameraOperationKind::Diagnostics,
                            std::time::Duration::ZERO,
                        )
                        .is_ok_and(|lease| {
                            lease.operation() == crate::lease::CameraOperationKind::Authentication
                        }),
                        Ordering::SeqCst,
                    );
                    true
                }),
            );
            let result = unopened_target().capture_with_stats_and_control(operation, &control);
            assert!(matches!(result, Err(irlume_common::Error::Preempted(_))));
            assert!(
                reused.load(Ordering::SeqCst),
                "nested lookup lost the held operation"
            );
            assert!(crate::lease::active_permit(MISSING_IR).unwrap().is_none());
            operation.lease().validate().unwrap();
        });
    }

    #[test]
    fn target_capture_retains_context_during_unwind_and_clears_it_afterward() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct ObserveDrop(Arc<AtomicBool>);
        impl Drop for ObserveDrop {
            fn drop(&mut self) {
                self.0.store(
                    crate::lease::active_permit(MISSING_IR).unwrap().is_some(),
                    Ordering::SeqCst,
                );
            }
        }
        crate::backend::tests::with_test_camera_operation(MISSING_IR, |operation| {
            let active_during_drop = Arc::new(AtomicBool::new(false));
            let observed = active_during_drop.clone();
            let control = crate::CaptureControl::new(
                crate::no_progress(),
                Arc::new(move || {
                    let _drop = ObserveDrop(observed.clone());
                    panic!("synthetic capture callback unwind");
                }),
            );
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                unopened_target().capture_with_stats_and_control(operation, &control)
            }));
            assert!(result.is_err());
            assert!(active_during_drop.load(Ordering::SeqCst));
            assert!(crate::lease::active_permit(MISSING_IR).unwrap().is_none());
            operation.lease().validate().unwrap();
        });
    }

    #[cfg(feature = "capture-timing")]
    #[test]
    fn target_capture_cleanup_uses_the_existing_release_timing_scope() {
        let timings = crate::CaptureTimings::default();
        let control = crate::CaptureControl::with_progress(crate::no_progress())
            .with_capture_timings(Some(timings.clone()));
        finish_capture(&control, (), Ok(())).unwrap();
        let snapshot = timings.snapshot();
        assert!(snapshot["session_release"].is_some());
        assert!(snapshot["open"].is_none());
        assert!(snapshot["frames"].is_none());
    }
}
