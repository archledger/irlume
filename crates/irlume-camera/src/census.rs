//! The camera census (#575): every video-adjacent device on the machine,
//! classified once, each classification printing the evidence it keyed on.
//!
//! The census answers the support question that keeps needing hours to
//! resolve: is the camera broken, is it a class irlume cannot use, or is it
//! configuration? Doctor prose answered it piecewise; this is the one
//! surface that answers it whole, in a shape a script can read and a
//! reporter can paste.
//!
//! Diagnostics only: nothing here feeds capture decisions, and no probe here
//! writes to any device.

use crate::Role;
use std::path::Path;

/// Drivers and classes that manufacture video nodes without manufacturing
/// cameras. A node backed by one of these is working software pretending to
/// be hardware, and must never read as a broken camera. `virtual-device` is
/// the census's name for a node with no hardware bus at all (its sysfs
/// device path resolves under `/sys/devices/virtual/`, which is how
/// v4l2loopback registers).
const DUMMY_DRIVERS: [&str; 3] = ["v4l2loopback", "vivid", "virtual-device"];

/// One census row: one video-adjacent node, or one machine-level fact (a
/// MIPI pipeline, an unbound USB camera). The class and verdict flatten
/// into the row (`"class":"uvc_rgb"` beside its `"paired":true`), so a
/// consumer reads one flat object per device.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CensusEntry {
    /// The `/dev/videoN` node this row describes; `None` for machine-level
    /// rows (MIPI generation, unbound USB device).
    pub node: Option<String>,
    #[serde(flatten)]
    pub class: CensusClass,
    #[serde(flatten)]
    pub verdict: CensusVerdict,
    /// The hardware privacy shutter is engaged on this node: nothing is
    /// wrong, the shutter needs opening. `None` when the probe could not
    /// read the control.
    pub privacy_engaged: Option<bool>,
    /// Every fact the classification keyed on (driver, USB identity, format
    /// fourccs, bus, pairing), as printed evidence. Never empty: a bare
    /// verdict is exactly what the census exists to replace.
    pub evidence: Vec<String>,
}

/// The census taxonomy: the classes from the #575 table.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "class")]
pub enum CensusClass {
    /// A UVC colour camera. `paired` says whether a pairing IR sensor makes
    /// this the RGB half of a face-auth pair.
    UvcRgb { paired: bool },
    /// A UVC greyscale sensor. `paired` says whether an RGB partner exists.
    UvcIr { paired: bool },
    /// An IR-classified node advertising only the unbranded Y8/Y800 shape
    /// (`UVC_QUIRK_FORCE_Y8` territory).
    Y8Ir,
    /// A node that answered and advertises no capture format at all: the
    /// metadata interface of a streaming node, not a camera.
    MetadataOnly,
    /// A node manufactured by a loopback/test driver: not hardware.
    DummyNode,
    /// A node that exists but could not be read (errno evidence attached).
    UnreadableNode,
    /// A node whose format list is not camera evidence (`V4L2_CAP_IO_MC`).
    McCentric,
    /// Machine-level: an Intel IPU3/IPU6/IPU7 MIPI pipeline is present.
    MipiIpu { generation: &'static str },
    /// Machine-level: a verified vendor MIPI camera bridge (#574 table).
    MipiVendorBridge { usb_id: String },
    /// Machine-level: a USB device or interface with camera class code
    /// `0x0e` and no driver bound to it.
    UsbCameraWithoutDriver { usb_id: String },
}

/// What irlume can do with the thing the row describes. The payload is the
/// printed explanation; it names the supported path where the class is
/// unsupported, and the next step where the thing is broken.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict", content = "note")]
pub enum CensusVerdict {
    /// Usable by irlume; the note names the tier (`null` when the tier needs
    /// no qualifier, the same explicit-null style `skew_us` uses).
    Supported(Option<&'static str>),
    /// Usable, with limits the note states.
    SupportedWithLimits(&'static str),
    /// Real, working, and not a camera. Nothing to fix.
    Informational(&'static str),
    /// Not hardware at all.
    NotHardware(&'static str),
    /// A camera class irlume cannot use; the note names the supported path.
    Unsupported(&'static str),
    /// Present but not working, or not readable; the note is the next step.
    Broken(&'static str),
}

/// The facts one answering node's classification is decided from. Gathered
/// by the walkers; the decision itself is [`node_entry_from_facts`], pure.
#[derive(Clone, Debug)]
pub(crate) struct NodeFacts {
    pub node: String,
    pub role: crate::Role,
    /// The node's advertised capture formats. `None` means the formats were
    /// NOT probed (open or lease refused), which is a different statement
    /// from an empty advertisement and must never print as one.
    pub fourccs: Option<Vec<[u8; 4]>>,
    pub driver: String,
    pub on_usb: bool,
    /// `vid:pid` when the node sits on USB and the identity was readable.
    pub usb_id: Option<String>,
    /// The kernel's `removable` answer: `Some(true)` external,
    /// `Some(false)` internal, `None` unknown.
    pub removable: Option<bool>,
    /// The hardware privacy shutter control read.
    pub privacy: Option<bool>,
    /// Whether a pairing exists that includes this node.
    pub paired: bool,
}

/// Classify one answering node from gathered facts. Pure, and the part worth
/// testing: the table's every row is a rule here.
pub(crate) fn node_entry_from_facts(facts: &NodeFacts) -> CensusEntry {
    let fourcc_list = || match &facts.fourccs {
        None => "not probed (the node could not be opened to list its formats)".to_string(),
        Some(list) => {
            let names: Vec<String> = list
                .iter()
                .map(|f| String::from_utf8_lossy(f).trim_end().to_string())
                .collect();
            if names.is_empty() {
                "no capture format advertised".to_string()
            } else {
                names.join("/")
            }
        }
    };
    let mut evidence = vec![
        match (facts.driver.as_str(), facts.on_usb) {
            (driver, true) => format!("driver {driver} on USB"),
            (driver, false) => format!("driver {driver}, not USB"),
        },
        facts.removable.map_or_else(
            || "removable: unknown".to_string(),
            |r| {
                if r {
                    "external".to_string()
                } else {
                    "internal".to_string()
                }
            },
        ),
        format!("formats {}", fourcc_list()),
    ];
    if let Some(id) = &facts.usb_id {
        evidence.insert(1, format!("USB {id}"));
    }

    let y8_only = |fourccs: &Option<Vec<[u8; 4]>>| match fourccs {
        None => false,
        Some(list) => {
            let grey = list.iter().any(|f| f == b"GREY");
            let y8 = list.iter().any(|f| f == b"Y8  " || f == b"Y800");
            y8 && !grey
        }
    };

    // doctor's tested-path honesty, carried as evidence: anything but
    // uvcvideo-on-USB is a first-fact-for-a-bug-report, not a verdict change.
    if !DUMMY_DRIVERS.contains(&facts.driver.as_str()) && facts.driver != "uvcvideo" {
        evidence.push("not the uvcvideo-on-USB case irlume is built for".to_string());
    }

    // An RGB node whose formats contain nothing irlume can decode detects
    // fine and then fails at capture; doctor warned, the census carries it
    // as the verdict. Must match the capture path's DECODABLE_RGB (YUYV,
    // NV12): listing RGB3/BGR3 here would pass the census then fail at
    // capture, the exact bug that warning existed to prevent.
    // Judging decodability needs formats that were actually probed: an
    // unprobed list neither clears nor convicts.
    let undecodable_rgb = matches!(&facts.fourccs, Some(list)
        if facts.role == Role::Rgb
            && !list.is_empty()
            && !list.iter().any(|f| f == b"YUYV" || f == b"NV12"));

    let (class, verdict) = if DUMMY_DRIVERS.contains(&facts.driver.as_str()) {
        (
            CensusClass::DummyNode,
            CensusVerdict::NotHardware(
                "created by software; it can never be the machine's face camera",
            ),
        )
    } else {
        match facts.role {
            Role::Other => (
                CensusClass::MetadataOnly,
                CensusVerdict::Informational(
                    "nothing to fix; this row exists so a metadata interface never reads \
                     as a missing or broken camera",
                ),
            ),
            Role::Ir if facts.paired => (
                CensusClass::UvcIr { paired: true },
                CensusVerdict::Supported(Some("secure IR tier")),
            ),
            Role::Ir if y8_only(&facts.fourccs) => (
                CensusClass::Y8Ir,
                CensusVerdict::SupportedWithLimits(
                    "supported with limits: unbranded Y8 IR advertisement shape; usable, \
                     but report it so the class stays known",
                ),
            ),
            Role::Ir => (
                CensusClass::UvcIr { paired: false },
                CensusVerdict::SupportedWithLimits(
                    "supported with limits: standalone IR sensor with no RGB pair, \
                     so no paired face authentication",
                ),
            ),
            Role::Rgb if undecodable_rgb => (
                CensusClass::UvcRgb { paired: facts.paired },
                CensusVerdict::SupportedWithLimits(
                    "detects but fails at capture: offers no uncompressed format irlume can decode (needs YUYV or NV12)",
                ),
            ),
            Role::Rgb if facts.paired => (CensusClass::UvcRgb { paired: true }, CensusVerdict::Supported(None)),
            Role::Rgb => (
                CensusClass::UvcRgb { paired: false },
                CensusVerdict::Supported(Some("RGB-only convenience tier")),
            ),
        }
    };
    if let Role::Ir = facts.role {
        evidence.push(if facts.paired {
            "paired: this sensor completes a face-auth pair".to_string()
        } else {
            "paired: no RGB partner found for this sensor".to_string()
        });
    }
    CensusEntry {
        node: Some(facts.node.clone()),
        class,
        verdict,
        privacy_engaged: facts.privacy,
        evidence,
    }
}

/// Run the census over this machine: every `/dev/videoN` node, plus the
/// machine-level facts (MIPI pipelines, unbound USB camera-class devices).
#[must_use]
pub fn census() -> Vec<CensusEntry> {
    census_from(&crate::scan_nodes())
}

/// [`census`] over a scan the caller already holds, so `doctor` classifies
/// every node exactly once: its capability check and the census rows come
/// from the same answers.
#[must_use]
pub fn census_from(scan: &crate::NodeScan) -> Vec<CensusEntry> {
    let pairs = crate::pairs_from(&scan.classified);
    let mut entries = node_entries(scan, &pairs);
    // Numeric node order across every bucket, double digits included: the
    // scan's buckets (classified, other, mc_centric, unreadable) are book
    // structure, not an order a person reading a census wants.
    entries.sort_by_key(|entry| {
        entry
            .node
            .as_deref()
            .map(crate::ir_metadata::node_number)
            .unwrap_or(u32::MAX)
    });
    entries.extend(machine_entries());
    entries
}

/// Per-node rows from one scan and the pair list. The facts walk (driver,
/// USB identity, formats, privacy) runs here; the verdict mapping is
/// [`node_entry_from_facts`].
fn node_entries(scan: &crate::NodeScan, pairs: &[crate::CameraPair]) -> Vec<CensusEntry> {
    let mut paired: std::collections::HashSet<String> = std::collections::HashSet::new();
    for pair in pairs {
        paired.insert(pair.rgb.clone());
        paired.insert(pair.ir.clone());
    }
    let mut out = Vec::new();
    for (path, role) in &scan.classified {
        out.push(node_entry_from_facts(&facts_for(path, *role, &paired)));
    }
    for path in &scan.other {
        let mut facts = facts_for(path, crate::Role::Other, &paired);
        facts.paired = false;
        out.push(node_entry_from_facts(&facts));
    }
    for (path, mc) in &scan.mc_centric {
        out.push(mc_centric_entry(path, mc));
    }
    for unreadable in &scan.unreadable {
        out.push(unreadable_entry(unreadable));
    }
    out
}

/// Gather one node's classification facts from the live device and sysfs.
/// Hardware-only surface: the mapping from facts to a row is pure above.
fn facts_for(
    path: &str,
    role: crate::Role,
    paired: &std::collections::HashSet<String>,
) -> NodeFacts {
    let (driver, on_usb) = crate::node_backend(path).unwrap_or_else(|error| {
        // node_backend resolves the PHYSICAL device, which virtual nodes
        // (v4l2loopback, vivid) do not have; their driver name still exists
        // as the /sys/class/video4linux/<node>/driver symlink, and it is the
        // one fact the dummy classification keys on.
        let node_name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| std::path::Path::new("/sys/class/video4linux").join(n));
        // A driver symlink on the class entry names the driver directly.
        let driver_link = node_name
            .as_deref()
            .map(|dir| std::fs::read_link(dir.join("driver")))
            .and_then(|link| link.ok())
            .and_then(|link| {
                link.file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_string)
            });
        if let Some(driver) = driver_link {
            return (driver, false);
        }
        // No driver link: a device with no hardware bus at all is virtual by
        // structure (v4l2loopback registers under /sys/devices/virtual/),
        // which is the dummy classification's evidence, not an error.
        let virtual_by_path = node_name
            .as_deref()
            .and_then(|dir| std::fs::canonicalize(dir).ok())
            .is_some_and(|resolved| resolved.starts_with("/sys/devices/virtual/"));
        if virtual_by_path {
            return ("virtual-device".into(), false);
        }
        (format!("unknown driver ({error})"), false)
    });
    let usb_id = crate::physical_device_id(path).and_then(|dir| crate::read_vidpid(&dir));
    let fourccs = crate::node_capture_formats_probed(path);
    NodeFacts {
        node: path.to_string(),
        role,
        fourccs,
        driver,
        on_usb,
        usb_id,
        removable: match crate::node_removable_class(path) {
            "fixed" => Some(false),
            "removable" => Some(true),
            _ => None,
        },
        privacy: Some(crate::privacy_engaged(path)),
        paired: paired.contains(path),
    }
}

/// Machine-level rows: MIPI pipelines and unbound USB camera-class devices.
fn machine_entries() -> Vec<CensusEntry> {
    let mut out = Vec::new();
    if let Some(generation) = crate::intel_ipu_present() {
        out.push(mipi_ipu_entry(generation));
    }
    if let Some(usb_id) = crate::vendor_mipi_bridge_present() {
        out.push(vendor_bridge_entry(&usb_id));
    }
    for (usb_id, name) in unbound_camera_class() {
        out.push(unbound_camera_entry(&usb_id, &name));
    }
    out
}

/// USB camera-class devices with no driver bound, as `(vid:pid, sysfs name)`.
#[must_use]
pub fn unbound_camera_class() -> Vec<(String, String)> {
    unbound_camera_class_in(Path::new("/sys/bus/usb/devices"))
}

/// [`unbound_camera_class`] with the sysfs devices root passed in, so a
/// fixture tree can exercise the whole walk.
///
/// A camera-class device or interface with no driver bound is the kernel's
/// side of "my camera does not show up": the hardware enumerated, the class
/// code says camera (`0x0e`, USB video class at either level), and nothing
/// claimed it. That is a driver or firmware problem, never an irlume one,
/// and the census says so instead of letting it read as absent hardware.
fn unbound_camera_class_in(devices_root: &Path) -> Vec<(String, String)> {
    const CAMERA_CLASS: &str = "0e";
    let Ok(devices) = std::fs::read_dir(devices_root) else {
        return Vec::new();
    };
    let names: Vec<String> = devices
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    // Deterministic across machines: read_dir order is filesystem order.
    let mut names = names;
    names.sort();
    let mut out = Vec::new();
    for name in &names {
        // Interface entries (`2-1:1.0`) are visited as part of their device.
        if !name
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == '.')
        {
            continue;
        }
        let dir = devices_root.join(name);
        let read = |file: &str| {
            std::fs::read_to_string(dir.join(file))
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        };
        let (vendor, product) = (read("idVendor"), read("idProduct"));
        let id = |vendor: &str, product: &str| {
            (!vendor.is_empty() && !product.is_empty()).then(|| format!("{vendor}:{product}"))
        };
        // The device-level class first: some cameras set it and carry no
        // class per interface.
        let device_class = read("bDeviceClass");
        let device_bound = dir.join("driver").exists();
        if device_class == CAMERA_CLASS && !device_bound {
            if let Some(usb_id) = id(&vendor, &product) {
                out.push((usb_id, name.clone()));
                continue;
            }
        }
        // Then per interface: class 0x0e with nothing bound to the
        // interface. A bound sibling interface (the UVC video control one)
        // means the camera is claimed and working.
        let prefix = format!("{name}:");
        for iface in names.iter().filter(|n| n.starts_with(&prefix)) {
            let iface_dir = devices_root.join(iface);
            let Ok(class) = std::fs::read_to_string(iface_dir.join("bInterfaceClass")) else {
                continue;
            };
            if class.trim().eq_ignore_ascii_case(CAMERA_CLASS) && !iface_dir.join("driver").exists()
            {
                if let Some(usb_id) = id(&vendor, &product) {
                    out.push((usb_id, name.clone()));
                }
                break;
            }
        }
    }
    out
}

fn mipi_ipu_entry(generation: &'static str) -> CensusEntry {
    CensusEntry {
        node: None,
        class: CensusClass::MipiIpu { generation },
        verdict: CensusVerdict::Unsupported(
            "MIPI camera pipeline irlume cannot use: the sensor emits raw Bayer behind an \
             ISP Linux drives through libcamera, and its IR sensor is not exposed at all. \
             An external USB IR camera is the supported path on this machine",
        ),
        privacy_engaged: None,
        evidence: vec![format!(
            "Intel {generation} pipeline detected (PCI driver or module present)"
        )],
    }
}

fn vendor_bridge_entry(usb_id: &str) -> CensusEntry {
    CensusEntry {
        node: None,
        class: CensusClass::MipiVendorBridge {
            usb_id: usb_id.to_string(),
        },
        verdict: CensusVerdict::Unsupported(
            "MIPI sensor behind a verified vendor bridge: uvcvideo binds nothing, so irlume \
             cannot use it. An external USB IR camera is the supported path on this machine",
        ),
        privacy_engaged: None,
        evidence: vec![format!("verified bridge USB {usb_id} (the #574 table)")],
    }
}

fn unbound_camera_entry(usb_id: &str, name: &str) -> CensusEntry {
    CensusEntry {
        node: None,
        class: CensusClass::UsbCameraWithoutDriver {
            usb_id: usb_id.to_string(),
        },
        verdict: CensusVerdict::Broken(
            "USB camera-class hardware enumerated with no driver bound: a kernel or firmware \
             problem, not irlume. Check `dmesg | grep -iE \"uvc|usb\"` and that the uvcvideo \
             module is loaded",
        ),
        privacy_engaged: None,
        evidence: vec![
            format!("USB {usb_id} carries camera class 0x0e with nothing bound"),
            format!("sysfs {name}"),
        ],
    }
}

fn mc_centric_entry(path: &str, mc: &crate::McCentric) -> CensusEntry {
    CensusEntry {
        node: Some(path.to_string()),
        class: CensusClass::McCentric,
        verdict: CensusVerdict::Unsupported(
            "media-controller-centric node whose format list is not camera evidence: irlume \
             refuses to classify it rather than guess (#425)",
        ),
        privacy_engaged: None,
        evidence: vec![mc.cause()],
    }
}

fn unreadable_entry(unreadable: &crate::Unreadable) -> CensusEntry {
    CensusEntry {
        node: Some(unreadable.path.clone()),
        class: CensusClass::UnreadableNode,
        verdict: CensusVerdict::Broken(
            "the node exists but could not be read; fix access or free the holder, then re-run",
        ),
        privacy_engaged: None,
        evidence: vec![unreadable.cause()],
    }
}

/// The one-line human rendering shared by `doctor` and `camera census`:
/// every row prints its class, its verdict, and the evidence it keyed on,
/// because a bare verdict is what the census exists to replace.
#[must_use]
pub fn render_line(entry: &CensusEntry) -> String {
    let mut line = String::new();
    if let Some(node) = &entry.node {
        line.push_str(node);
        line.push_str(": ");
    }
    line.push_str(&render_class(&entry.class));
    line.push_str(", ");
    line.push_str(&render_verdict(&entry.verdict));
    if entry.privacy_engaged == Some(true) {
        line.push_str(" | privacy shutter engaged: nothing wrong, open the shutter");
    }
    if !entry.evidence.is_empty() {
        line.push_str("; ");
        line.push_str(&entry.evidence.join(" | "));
    }
    line
}

fn render_class(class: &CensusClass) -> String {
    match class {
        CensusClass::UvcRgb { paired } => format!(
            "UVC RGB camera ({})",
            if *paired { "paired" } else { "unpaired" }
        ),
        CensusClass::UvcIr { paired } => format!(
            "UVC IR sensor ({})",
            if *paired { "paired" } else { "unpaired" }
        ),
        CensusClass::Y8Ir => "unbranded Y8 IR sensor".into(),
        CensusClass::MetadataOnly => "metadata-only node (not a camera)".into(),
        CensusClass::DummyNode => "dummy node (not hardware)".into(),
        CensusClass::UnreadableNode => "unreadable node".into(),
        CensusClass::McCentric => "media-controller node (format list not camera evidence)".into(),
        CensusClass::MipiIpu { generation } => format!("Intel {generation} MIPI camera pipeline"),
        CensusClass::MipiVendorBridge { usb_id } => {
            format!("vendor MIPI camera bridge (USB {usb_id})")
        }
        CensusClass::UsbCameraWithoutDriver { usb_id } => {
            format!("USB camera-class device with no driver (USB {usb_id})")
        }
    }
}

fn render_verdict(verdict: &CensusVerdict) -> String {
    match verdict {
        CensusVerdict::Supported(None) => "supported".into(),
        CensusVerdict::Supported(Some(tier)) => format!("supported ({tier})"),
        CensusVerdict::SupportedWithLimits(note)
        | CensusVerdict::Informational(note)
        | CensusVerdict::NotHardware(note)
        | CensusVerdict::Unsupported(note)
        | CensusVerdict::Broken(note) => (*note).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(node: &str, role: Role, fourccs: &[&[u8; 4]]) -> NodeFacts {
        NodeFacts {
            node: node.into(),
            role,
            fourccs: Some(fourccs.iter().map(|f| **f).collect()),
            driver: "uvcvideo".into(),
            on_usb: true,
            usb_id: Some("046d:085e".into()),
            removable: Some(false),
            privacy: Some(false),
            paired: true,
        }
    }

    #[test]
    fn a_paired_ir_node_is_supported_secure_tier_with_full_evidence() {
        let entry = node_entry_from_facts(&facts("/dev/video2", Role::Ir, &[b"GREY"]));
        assert_eq!(
            entry.class,
            CensusClass::UvcIr { paired: true },
            "a paired IR sensor is the secure-tier half of a face-auth pair"
        );
        assert_eq!(entry.node.as_deref(), Some("/dev/video2"));
        assert_eq!(
            entry.verdict,
            CensusVerdict::Supported(Some("secure IR tier"))
        );
        let evidence = entry.evidence.join(" | ");
        for needle in ["uvcvideo", "USB", "046d:085e", "GREY", "internal"] {
            assert!(
                evidence.contains(needle),
                "evidence must name {needle}: {evidence}"
            );
        }
        assert_eq!(entry.privacy_engaged, Some(false));
    }

    #[test]
    fn an_unpaired_ir_node_is_supported_with_limits_and_says_why() {
        let mut f = facts("/dev/video4", Role::Ir, &[b"GREY"]);
        f.paired = false;
        let entry = node_entry_from_facts(&f);
        assert_eq!(entry.class, CensusClass::UvcIr { paired: false });
        assert!(matches!(
            entry.verdict,
            CensusVerdict::SupportedWithLimits(_)
        ));
    }

    #[test]
    fn a_y8_only_ir_node_is_its_own_class_not_plain_standalone() {
        let mut f = facts("/dev/video2", Role::Ir, &[b"Y8  ", b"Y800"]);
        f.paired = false;
        let entry = node_entry_from_facts(&f);
        assert_eq!(entry.class, CensusClass::Y8Ir);
        assert!(matches!(
            entry.verdict,
            CensusVerdict::SupportedWithLimits(_)
        ));
        let evidence = entry.evidence.join(" | ");
        assert!(
            evidence.contains("Y8") && evidence.contains("Y800"),
            "the Y8 shape must be printed as the evidence: {evidence}"
        );
    }

    #[test]
    fn a_paired_rgb_node_is_supported_and_an_unpaired_one_names_the_tier() {
        let paired = node_entry_from_facts(&facts("/dev/video0", Role::Rgb, &[b"YUYV", b"MJPG"]));
        assert_eq!(paired.class, CensusClass::UvcRgb { paired: true });
        assert_eq!(paired.verdict, CensusVerdict::Supported(None));

        let mut f = facts("/dev/video0", Role::Rgb, &[b"YUYV", b"MJPG"]);
        f.paired = false;
        let unpaired = node_entry_from_facts(&f);
        assert_eq!(unpaired.class, CensusClass::UvcRgb { paired: false });
        assert_eq!(
            unpaired.verdict,
            CensusVerdict::Supported(Some("RGB-only convenience tier"))
        );
    }

    #[test]
    fn a_dummy_driver_node_is_not_hardware_and_says_so() {
        for driver in ["v4l2loopback", "vivid", "virtual-device"] {
            let mut f = facts("/dev/video9", Role::Rgb, &[b"YUYV"]);
            f.driver = driver.into();
            f.on_usb = false;
            f.usb_id = None;
            f.paired = false;
            let entry = node_entry_from_facts(&f);
            assert_eq!(entry.class, CensusClass::DummyNode, "driver {driver}");
            assert!(matches!(entry.verdict, CensusVerdict::NotHardware(_)));
            assert!(
                entry.evidence.join(" | ").contains(driver),
                "the driver/class name is the whole evidence for this class"
            );
        }
    }

    #[test]
    fn a_node_with_no_capture_formats_is_informational_metadata_not_a_camera() {
        let mut f = facts("/dev/video1", Role::Other, &[]);
        f.fourccs = Some(Vec::new());
        f.paired = false;
        let entry = node_entry_from_facts(&f);
        assert_eq!(entry.class, CensusClass::MetadataOnly);
        assert!(matches!(entry.verdict, CensusVerdict::Informational(_)));
        let evidence = entry.evidence.join(" | ");
        assert!(
            evidence.contains("no capture format"),
            "the absence itself is the evidence: {evidence}"
        );
    }

    #[test]
    fn privacy_engaged_is_carried_as_its_own_flag_not_a_class_change() {
        let mut f = facts("/dev/video0", Role::Rgb, &[b"YUYV"]);
        f.privacy = Some(true);
        let entry = node_entry_from_facts(&f);
        assert_eq!(entry.class, CensusClass::UvcRgb { paired: true });
        assert_eq!(entry.privacy_engaged, Some(true));
    }

    #[test]
    fn an_external_node_prints_external() {
        let mut f = facts("/dev/video0", Role::Rgb, &[b"YUYV"]);
        f.removable = Some(true);
        let entry = node_entry_from_facts(&f);
        assert!(
            entry.evidence.join(" | ").contains("external"),
            "the removable attribute is printed so the classification is verifiable"
        );
    }

    /// #575's "no driver bind" class: a USB device or interface with camera
    /// class code 0x0e and nothing bound to it. Fixture tree shaped like
    /// /sys/bus/usb/devices.
    #[test]
    fn usb_camera_class_devices_without_a_driver_are_listed_with_identity() {
        let root = std::env::temp_dir().join(format!("irlume-census-usb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // Device 2-1: camera class at the DEVICE level, no driver bound.
        let unbound = root.join("2-1");
        std::fs::create_dir_all(&unbound).unwrap();
        std::fs::write(unbound.join("bDeviceClass"), "0e").unwrap();
        std::fs::write(unbound.join("idVendor"), "05a3").unwrap();
        std::fs::write(unbound.join("idProduct"), "9331").unwrap();
        // Device 3-2: class 00 at device level, camera-class INTERFACE bound
        // to uvcvideo (a normal working camera; must NOT be listed).
        // Interface entries are SIBLINGS of the device entry in sysfs.
        let bound = root.join("3-2");
        std::fs::create_dir_all(&bound).unwrap();
        std::fs::create_dir_all(root.join("3-2:1.0")).unwrap();
        std::fs::write(bound.join("bDeviceClass"), "00").unwrap();
        std::fs::write(bound.join("idVendor"), "046d").unwrap();
        std::fs::write(bound.join("idProduct"), "085e").unwrap();
        std::fs::write(root.join("3-2:1.0/bInterfaceClass"), "0e").unwrap();
        std::fs::create_dir(root.join("3-2:1.0/driver")).unwrap();
        // Device 4-1: camera-class interface with NO driver (must be listed).
        let iface_unbound = root.join("4-1");
        std::fs::create_dir_all(&iface_unbound).unwrap();
        std::fs::create_dir_all(root.join("4-1:1.0")).unwrap();
        std::fs::write(iface_unbound.join("bDeviceClass"), "00").unwrap();
        std::fs::write(iface_unbound.join("idVendor"), "06cb").unwrap();
        std::fs::write(iface_unbound.join("idProduct"), "0701").unwrap();
        std::fs::write(root.join("4-1:1.0/bInterfaceClass"), "0e").unwrap();
        // Device 5-1: a hub (class 09), unbound: not a camera, not listed.
        let hub = root.join("5-1");
        std::fs::create_dir_all(&hub).unwrap();
        std::fs::write(hub.join("bDeviceClass"), "09").unwrap();
        std::fs::write(hub.join("idVendor"), "1d6b").unwrap();
        std::fs::write(hub.join("idProduct"), "0002").unwrap();

        let found = unbound_camera_class_in(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            found,
            vec![
                ("05a3:9331".to_string(), "2-1".to_string()),
                ("06cb:0701".to_string(), "4-1".to_string()),
            ],
            "exactly the unbound camera-class devices, with identity, in walk order"
        );
    }

    #[test]
    fn machine_level_rows_carry_class_verdict_and_evidence() {
        let ipu = mipi_ipu_entry("IPU6");
        assert_eq!(ipu.class, CensusClass::MipiIpu { generation: "IPU6" });
        assert!(matches!(ipu.verdict, CensusVerdict::Unsupported(_)));
        assert!(
            ipu.evidence.join(" | ").contains("IPU6"),
            "the generation is the evidence: {:?}",
            ipu.evidence
        );

        let bridge = vendor_bridge_entry("06cb:0701");
        assert_eq!(
            bridge.class,
            CensusClass::MipiVendorBridge {
                usb_id: "06cb:0701".into()
            }
        );
        assert!(matches!(bridge.verdict, CensusVerdict::Unsupported(_)));
        assert!(bridge.evidence.join(" | ").contains("06cb:0701"));

        let unbound = unbound_camera_entry("05a3:9331", "2-1");
        assert_eq!(
            unbound.class,
            CensusClass::UsbCameraWithoutDriver {
                usb_id: "05a3:9331".into()
            }
        );
        assert!(matches!(unbound.verdict, CensusVerdict::Broken(_)));
        let evidence = unbound.evidence.join(" | ");
        assert!(
            evidence.contains("05a3:9331") && evidence.contains("2-1"),
            "identity and sysfs location are the evidence: {evidence}"
        );
    }

    #[test]
    fn unreadable_and_mc_centric_rows_state_cause_and_action() {
        let unreadable = crate::Unreadable {
            path: "/dev/video4".into(),
            at: crate::FailedAt::Open,
            errno: Some(libc::EACCES),
            holder: None,
        };
        let entry = unreadable_entry(&unreadable);
        assert_eq!(entry.node.as_deref(), Some("/dev/video4"));
        assert_eq!(entry.class, CensusClass::UnreadableNode);
        assert!(matches!(entry.verdict, CensusVerdict::Broken(_)));
        assert!(
            entry.evidence.join(" | ").contains("could not be opened"),
            "the cause is evidence: {:?}",
            entry.evidence
        );

        let mc_scan = crate::NodeScan::default();
        assert!(
            mc_scan.other.is_empty(),
            "the new other bucket starts empty"
        );
    }

    #[test]
    fn render_line_prints_class_verdict_and_evidence_together() {
        let entry = node_entry_from_facts(&facts("/dev/video2", Role::Ir, &[b"GREY"]));
        let line = render_line(&entry);
        assert!(
            line.starts_with("/dev/video2: UVC IR sensor (paired), supported (secure IR tier); "),
            "class and verdict lead, node first: {line}"
        );
        assert!(
            line.contains("driver uvcvideo on USB") && line.contains("formats GREY"),
            "the evidence is in the line, not behind it: {line}"
        );

        let mut engaged = facts("/dev/video0", Role::Rgb, &[b"YUYV"]);
        engaged.privacy = Some(true);
        let line = render_line(&node_entry_from_facts(&engaged));
        assert!(
            line.contains("privacy shutter engaged: nothing wrong, open the shutter"),
            "the shutter row the #575 table demands: {line}"
        );

        let machine = mipi_ipu_entry("IPU6");
        let line = render_line(&machine);
        assert!(
            line.starts_with("Intel IPU6 MIPI camera pipeline, "),
            "machine rows have no node prefix: {line}"
        );
    }

    #[test]
    fn a_non_uvcvideo_backend_is_flagged_in_the_evidence() {
        let mut f = facts("/dev/video0", Role::Rgb, &[b"YUYV"]);
        f.driver = "bttv".into();
        f.on_usb = false;
        f.usb_id = None;
        let entry = node_entry_from_facts(&f);
        assert!(
            entry
                .evidence
                .join(" | ")
                .contains("not the uvcvideo-on-USB case irlume is built for"),
            "the tested-path honesty doctor printed survives into the census: {:?}",
            entry.evidence
        );
    }

    #[test]
    fn an_rgb_node_without_decodable_formats_is_supported_with_limits() {
        let entry = node_entry_from_facts(&facts("/dev/video0", Role::Rgb, &[b"MJPG"]));
        assert_eq!(
            entry.verdict,
            CensusVerdict::SupportedWithLimits(
                "detects but fails at capture: offers no uncompressed format irlume can decode (needs YUYV or NV12)"
            )
        );
        assert!(
            entry.evidence.join(" | ").contains("MJPG"),
            "the offered formats are the evidence"
        );
    }

    #[test]
    fn an_unprobed_formats_list_never_prints_as_an_empty_advertisement() {
        let mut f = facts("/dev/video8", Role::Rgb, &[b"YUYV"]);
        f.fourccs = None;
        f.paired = false;
        let entry = node_entry_from_facts(&f);
        let evidence = entry.evidence.join(" | ");
        assert!(
            evidence.contains("not probed"),
            "a refused probe is a different statement from an empty advertisement: {evidence}"
        );
        assert!(
            !evidence.contains("no capture format advertised"),
            "the unprobed case must not borrow the empty-advertisement wording: {evidence}"
        );
        assert_eq!(
            entry.verdict,
            CensusVerdict::Supported(Some("RGB-only convenience tier")),
            "an unprobed list neither clears nor convicts decodability"
        );
    }

    #[test]
    fn node_rows_render_in_numeric_order_across_buckets() {
        let scan = crate::NodeScan {
            other: vec!["/dev/video1".into()],
            classified: vec![
                ("/dev/video10".into(), Role::Rgb),
                ("/dev/video2".into(), Role::Ir),
            ],
            unreadable: Vec::new(),
            mc_centric: Vec::new(),
            listing_error: None,
        };
        let nodes: Vec<String> = census_from(&scan)
            .into_iter()
            .filter_map(|entry| entry.node)
            .collect();
        assert_eq!(
            nodes,
            vec!["/dev/video1", "/dev/video2", "/dev/video10"],
            "numeric order, double digits after single, buckets interleaved"
        );
    }

    #[test]
    fn census_from_covers_every_bucket_of_a_scan_exactly_once() {
        let scan = crate::NodeScan {
            other: vec!["/dev/fixture-meta".into()],
            classified: vec![
                ("/dev/fixture-rgb".into(), Role::Rgb),
                ("/dev/fixture-ir".into(), Role::Ir),
            ],
            unreadable: vec![crate::Unreadable {
                path: "/dev/fixture-busy".into(),
                at: crate::FailedAt::Open,
                errno: Some(libc::EBUSY),
                holder: Some("ffmpeg".into()),
            }],
            mc_centric: Vec::new(),
            listing_error: None,
        };
        let mut nodes: Vec<String> = census_from(&scan)
            .into_iter()
            .filter_map(|entry| entry.node)
            .collect();
        nodes.sort();
        assert_eq!(
            nodes,
            vec![
                "/dev/fixture-busy".to_string(),
                "/dev/fixture-ir".to_string(),
                "/dev/fixture-meta".to_string(),
                "/dev/fixture-rgb".to_string(),
            ],
            "one row per node, every bucket, nothing dropped"
        );
    }
}
