// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! GPU identity under closed admission (ADR-0033 sections 2 to 4).
//!
//! The GPU is an eligible accelerator through the same validated OpenVINO
//! C API provider the NPU uses: one explicit device, never `MULTI`,
//! `HETERO` or `AUTO`, and a system that exposes more than one GPU refuses
//! GPU placement until a reviewed rule selects one. Nothing here loads the
//! provider in production: [`discover`] refuses before `dlopen` exactly as
//! the NPU path does, and the admitted entries are test-only, reserved for
//! the hardware evidence a certification starts from.
//!
//! The [`Identity`] here is the complete ADR-0033 section 3 observation:
//! the plugin's own PCI report bound to exactly one DRM render node and to
//! the firmware node at the same PCI address, the loader family the plugin
//! resolved, and every mapped native library hashed through one open file
//! whose inode is kept. One plugin metric is deliberately absent: reading
//! `GPU_DRIVER_VERSION` through the C API kills the process on both
//! shipped 2026.2.1 builds measured for this module (the root-owned
//! archive on minihost and the Fedora RPM on the UX5406S; a bare device
//! index as the device name crashes the same way), so driver identity
//! comes from the hashed mapped-library inventory, which ADR-0033 section
//! 3 already makes a different identity on any driver or compute-runtime
//! rebuild.

use super::runtime::{self, RuntimeSelection};
pub use crate::gpu::{settings_conf_value, switch_allows, Setting};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// How every model is compiled for the GPU (ADR-0033 section 2, amended
/// 2026-10-21). The precision is named explicitly because OpenVINO GPUs
/// accept several inference precisions and the precision changes the
/// drift a certification judges; the certified configuration is `f32`.
/// The GPU plugin's own default is `f16`, which measured outside the
/// ADR-0022 section 7 drift budget on both measured identities, while
/// `f32` reproduced the CPU reference within 1e-6. An explicit precision
/// hint also makes the plugin's execution mode irrelevant: OpenVINO only
/// derives the precision from `EXECUTION_MODE_HINT` when no precision was
/// set. An implementation claiming conformance compiles with exactly this.
pub const COMPILE_CONFIGURATION: &str =
    "batch=1;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=f32";

/// The loaded GPU firmware builds, where the kernel exposes them (ADR-0033
/// section 3): the GuC and HuC versions of the graphics microcontrollers,
/// read from debugfs the same way ADR-0033's NPU premise reads the NPU
/// firmware. Unreadable firmware makes the identity unreadable, and GPU
/// placement refuses; a non-root reader records exactly that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Firmware {
    /// Both builds, as reported by the loaded driver.
    Loaded { guc: String, huc: String },
    /// The controller reports are malformed, incomplete or conflicting.
    Malformed(String),
    /// debugfs is absent or unreadable to this process.
    Unreadable,
}

/// Read the GuC and HuC firmware builds from
/// `/sys/kernel/debug/dri/<N>/gt*/uc/{guc,huc}_info` (i915) or
/// `tile*/gt*/uc/{guc,huc}_info` (xe). Each dri node also
/// appears as a bus-address symlink, so entries are deduplicated by their
/// canonical path; a single graphics node is required, mirroring the
/// single-GPU rule: more than one node's firmware is ambiguous and refuses.
pub fn firmware(debugfs: &Path) -> Firmware {
    match observe_firmware(debugfs) {
        Ok(observation) => observation.into_firmware(),
        Err(error) => error.into(),
    }
}

#[derive(Debug)]
enum FirmwareError {
    Unreadable,
    Malformed(String),
}

impl From<FirmwareError> for Firmware {
    fn from(error: FirmwareError) -> Self {
        match error {
            FirmwareError::Unreadable => Self::Unreadable,
            FirmwareError::Malformed(why) => Self::Malformed(why),
        }
    }
}

struct FirmwareObservation {
    guc: String,
    huc: String,
    #[cfg(test)]
    pci_slots: BTreeSet<String>,
}

impl FirmwareObservation {
    fn into_firmware(self) -> Firmware {
        Firmware::Loaded {
            guc: self.guc,
            huc: self.huc,
        }
    }
}

/// Collect a debugfs directory. Volatile entries (DRM `client-*`
/// directories appear and vanish while a desktop uses the GPU) must not
/// turn a live system's firmware walk unreadable: an entry that disappears
/// mid-walk is skipped, every other error refuses.
fn directory_entries(path: &Path) -> Result<Vec<PathBuf>, FirmwareError> {
    let entries = std::fs::read_dir(path).map_err(|_| FirmwareError::Unreadable)?;
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => paths.push(entry.path()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(FirmwareError::Unreadable),
        }
    }
    paths.sort();
    Ok(paths)
}

fn numbered(path: &Path, prefix: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(prefix))
        .is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Walk actual i915 GTs and xe tiles/GTs. Every visited directory and entry
/// must be readable; absence of a uc directory is distinct from an IO error.
fn uc_directories(node: &Path) -> Result<Vec<PathBuf>, FirmwareError> {
    let mut gts = Vec::new();
    for entry in directory_entries(node)? {
        if numbered(&entry, "gt") {
            gts.push(entry);
        } else if numbered(&entry, "tile") {
            for gt in directory_entries(&entry)? {
                if numbered(&gt, "gt") {
                    gts.push(gt);
                }
            }
        }
    }
    let mut ucs = Vec::new();
    for gt in gts {
        for entry in directory_entries(&gt)? {
            if entry.file_name().is_some_and(|name| name == "uc") {
                directory_entries(&entry)?;
                ucs.push(entry);
            }
        }
    }
    Ok(ucs)
}

fn pci_slot(name: &str) -> bool {
    let parts: Vec<&str> = name.split([':', '.']).collect();
    parts.len() == 4
        && parts.iter().zip([4, 2, 2, 1]).all(|(part, length)| {
            part.len() == length && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && matches!(parts[3], "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7")
}

fn observe_firmware(debugfs: &Path) -> Result<FirmwareObservation, FirmwareError> {
    let mut nodes: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    for card in directory_entries(&debugfs.join("dri"))? {
        let Some(name) = card.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        // The DRM root also contains global files (bridges) and volatile
        // client-* directories. Only numeric minors and PCI device entries
        // name graphics nodes; failures on those still refuse the observation.
        if !(pci_slot(name) || !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())) {
            continue;
        }
        let Ok(canonical) = card.canonicalize() else {
            // A volatile client or vanished alias mid-walk.
            if card
                .symlink_metadata()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
                continue;
            }
            return Err(FirmwareError::Unreadable);
        };
        let slots = nodes.entry(canonical).or_default();
        if let Some(name) = card.file_name().and_then(|name| name.to_str()) {
            if pci_slot(name) {
                slots.insert(name.to_owned());
            }
        }
    }
    let mut per_node = Vec::new();
    #[allow(unused_variables, reason = "only the test identity reads the slots")]
    for (node, pci_slots) in nodes {
        let ucs = uc_directories(&node)?;
        if ucs.is_empty() {
            continue;
        }
        let mut gucs = BTreeSet::new();
        let mut hucs = BTreeSet::new();
        for uc in ucs {
            let guc = read_uc_version(&uc.join("guc_info"), "GuC")?;
            let huc = read_uc_version(&uc.join("huc_info"), "HuC")?;
            match (guc, huc) {
                (UcVersion::Loaded(guc), UcVersion::Loaded(huc)) => {
                    gucs.insert(guc);
                    hucs.insert(huc);
                }
                // Normal xe GTs may have no HuC, but ALL loaded GuCs must
                // agree with the complete pair's GuC, not disappear.
                (UcVersion::Loaded(guc), UcVersion::NotLoaded) => {
                    gucs.insert(guc);
                }
                (UcVersion::NotLoaded, UcVersion::Loaded(_)) => {
                    return Err(FirmwareError::Malformed("HuC loaded without a GuC".into()));
                }
                (UcVersion::NotLoaded, UcVersion::NotLoaded) => {}
            }
        }
        if gucs.is_empty() || hucs.is_empty() {
            return Err(FirmwareError::Malformed(
                "no graphics firmware pair with a loaded HuC".into(),
            ));
        }
        if gucs.len() != 1 || hucs.len() != 1 {
            return Err(FirmwareError::Malformed(
                "conflicting firmware builds across tiles or GTs".into(),
            ));
        }
        per_node.push(FirmwareObservation {
            guc: gucs.into_iter().next().ok_or(FirmwareError::Unreadable)?,
            huc: hucs.into_iter().next().ok_or(FirmwareError::Unreadable)?,
            #[cfg(test)]
            pci_slots,
        });
    }
    match per_node.len() {
        0 => Err(FirmwareError::Unreadable),
        1 => per_node.pop().ok_or(FirmwareError::Unreadable),
        _ => Err(FirmwareError::Malformed(
            "more than one graphics firmware node".into(),
        )),
    }
}

enum UcVersion {
    Loaded(String),
    NotLoaded,
}

fn read_uc_version(path: &Path, controller: &str) -> Result<UcVersion, FirmwareError> {
    let text = std::fs::read_to_string(path).map_err(|_| FirmwareError::Unreadable)?;
    let malformed = || FirmwareError::Malformed(format!("malformed {controller} firmware report"));
    if controller == "HuC" && matches!(text.trim(), "HuC disabled" | "HuC not supported") {
        // i915's intel_huc_load_status returns these before dumping the fw.
        return Ok(UcVersion::NotLoaded);
    }
    if !text
        .trim_start()
        .starts_with(&format!("{controller} firmware: "))
    {
        return Err(malformed());
    }
    let mut status = None;
    let mut found = None;
    let mut wanted = None;
    let mut compatibility = None;
    let mut i915 = false;
    let mut xe = false;
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("status: ") {
            if status.replace(value).is_some() {
                return Err(malformed());
            }
        } else if let Some(value) = line.strip_prefix("version: ") {
            // Linux v6.18 intel_uc_fw_dump: the wanted version can precede
            // the found one ON THE SAME LINE. It is never the loaded build.
            i915 = true;
            let value = if let Some(value) = value.strip_prefix("wanted ") {
                let (want, value) = value.split_once(", found ").ok_or_else(malformed)?;
                if !valid_version(want, 3) || wanted.replace(want).is_some() {
                    return Err(malformed());
                }
                value
            } else {
                value.strip_prefix("found ").ok_or_else(malformed)?
            };
            if !valid_version(value, 3) || found.replace(value).is_some() {
                return Err(malformed());
            }
        } else if let Some(value) = line.strip_prefix("found release version ") {
            // xe_uc_fw_print also prints a separate compatibility version;
            // only the release version names the firmware build.
            xe = true;
            if !valid_version(value, 4) || found.replace(value).is_some() {
                return Err(malformed());
            }
        } else if let Some(value) = line.strip_prefix("found compatibility version ") {
            xe = true;
            if !valid_version(value, 4) || compatibility.replace(value).is_some() {
                return Err(malformed());
            }
        } else if let Some(value) = line
            .strip_prefix("wanted release version ")
            .or_else(|| line.strip_prefix("wanted compatibility version "))
        {
            xe = true;
            if !valid_version(value, 4) || wanted.replace(value).is_some() {
                return Err(malformed());
            }
        } else if line.starts_with("status:")
            || line.starts_with("version:")
            || line.starts_with("found ")
            || line.starts_with("wanted ")
        {
            return Err(malformed());
        }
    }
    if i915 == xe || (xe && wanted.is_none()) {
        return Err(malformed());
    }
    match (status, found) {
        // A found version alone is a parsed blob, not proof it was loaded.
        // xe_uc_fw_is_loaded includes TRANSFERRED, RUNNING and PRELOADED;
        // i915 has the first two. Zero major versions are not loaded builds.
        (Some("TRANSFERRED" | "RUNNING" | "PRELOADED"), Some(version))
            if version
                .split('.')
                .next()
                .and_then(|major| major.parse::<u32>().ok())
                .is_some_and(|major| major != 0) =>
        {
            Ok(UcVersion::Loaded(version.to_owned()))
        }
        // A readable disabled/unsupported xe controller with its valid
        // wanted line and no found version is a known no-load report.
        (Some("N/A" | "DISABLED"), None) if xe && compatibility.is_none() => {
            Ok(UcVersion::NotLoaded)
        }
        _ => Err(malformed()),
    }
}

fn valid_version(version: &str, max_parts: usize) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    (3..=max_parts).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
}

/// The canonical `domain:bus:device.function` spelling Linux uses for PCI
/// addresses in sysfs (`0000:00:02.0`), built from one decimal/`0x` hex
/// component group. Parsing never invents digits: each component must be a
/// plain non-negative number within its width.
#[cfg(test)]
pub(crate) fn canonical_pci(
    domain: &str,
    bus: &str,
    device: &str,
    function: &str,
) -> Option<String> {
    // The plugin prints domain, bus and function as decimal and the
    // device with a `0x` prefix (`{domain: %u bus: %u device: 0x%x
    // function: %u}`), so an unprefixed component is decimal and only a
    // `0x` prefix selects hexadecimal; each component must fit its width.
    let number = |text: &str, text_width: usize, max: u32| {
        let (digits, radix) = if let Some(digits) = text.strip_prefix("0x") {
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            (digits, 16)
        } else {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            (text, 10)
        };
        u32::from_str_radix(digits, radix).ok().and_then(|value| {
            (value < (1 << (4 * text_width)) as u32 && value <= max)
                .then(|| format!("{value:0text_width$X}"))
        })
    };
    Some(format!(
        "{}:{}:{}.{}",
        number(domain, 4, u32::MAX)?,
        number(bus, 2, u32::MAX)?,
        number(device, 2, u32::MAX)?,
        // A PCI function is 3 bits: 0 through 7, as the bus-alias check
        // of the firmware walk already requires.
        number(function, 1, 7)?
    ))
    .map(|address| address.to_ascii_lowercase())
}

/// Parse the GPU plugin's `DEVICE_PCI_INFO` report, printed by OpenVINO
/// 2026.2.1 as `{domain: 0 bus: 0 device: 0x2 function: 0}`, into the
/// canonical sysfs PCI address of the device the plugin selected. Every
/// label must appear in order with a plain value; nothing is guessed.
#[cfg(test)]
pub(crate) fn plugin_pci(info: &str) -> Option<String> {
    let body = info.trim().strip_prefix('{')?.strip_suffix('}')?;
    let mut tokens = body.split_whitespace();
    let mut component = |label: &str| -> Option<String> {
        if tokens.next()? != label {
            return None;
        }
        tokens.next().map(str::to_owned)
    };
    let domain = component("domain:")?;
    let bus = component("bus:")?;
    let device = component("device:")?;
    let function = component("function:")?;
    // A report with trailing or repeated components is not the plugin's
    // format; it refuses instead of being reduced to a canonical address.
    if tokens.next().is_some() {
        return None;
    }
    canonical_pci(&domain, &bus, &device, &function)
}

/// The vendor id embedded in the GPU plugin's `DEVICE_ARCHITECTURE` report
/// (`GPU: vendor=0x8086 arch=v12.4.0`), normalized to `0x`-prefixed
/// lower-case hex.
#[cfg(test)]
pub(crate) fn architecture_vendor(architecture: &str) -> Option<String> {
    let vendor = architecture
        .split_whitespace()
        .find(|field| field.starts_with("vendor="))?
        .strip_prefix("vendor=")?;
    if vendor.len() == 6 && vendor.starts_with("0x") {
        Some(vendor.to_ascii_lowercase())
    } else {
        None
    }
}

/// One DRM render node bound to its PCI device through sysfs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderNode {
    /// The device basename (`renderD128`).
    pub name: String,
    /// Its canonical PCI address (`0000:00:02.0`).
    pub pci: String,
    /// The `vendor` sysfs attribute (`0x8086`).
    pub vendor: String,
    /// The `device` sysfs attribute (`0x46d1`).
    pub device: String,
}

/// Bind the plugin-selected PCI address to exactly one DRM render node:
/// the node whose `device` symlink resolves to that address. The node's
/// vendor must equal the plugin's `DEVICE_ARCHITECTURE` vendor and its
/// device id the plugin's `GPU_DEVICE_ID`, so a stale or foreign sysfs
/// entry can never stand in for the device the plugin reported. Any
/// ambiguity or disagreement refuses (ADR-0033 section 3).
///
/// # Errors
///
/// When the DRM class directory, a render node's PCI symlink or its vendor
/// and device attributes are unreadable or malformed, when no render node
/// carries the plugin's address, or when more than one does.
#[cfg(test)]
pub(crate) fn render_node(
    sysfs_drm: &Path,
    pci: &str,
    vendor: &str,
    device_id: &str,
) -> Result<RenderNode, String> {
    let mut bound = Vec::new();
    for entry in std::fs::read_dir(sysfs_drm).map_err(|error| format!("drm: {error}"))? {
        let entry = entry.map_err(|error| format!("drm: {error}"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with("renderD")
            || !name["renderD".len()..].bytes().all(|b| b.is_ascii_digit())
        {
            continue;
        }
        let address = entry
            .path()
            .join("device")
            .canonicalize()
            .map_err(|error| format!("{}: {error}", entry.path().display()))?
            .file_name()
            .and_then(|address| address.to_str())
            .ok_or_else(|| format!("{} has no PCI address", entry.path().display()))?
            .to_owned();
        if address != pci {
            continue;
        }
        let read = |file| {
            let text = std::fs::read_to_string(entry.path().join("device").join(file))
                .map_err(|error| format!("{} {file}: {error}", entry.path().display()))?;
            let id = text.trim().to_ascii_lowercase();
            (id.len() == 6 && id.starts_with("0x"))
                .then_some(id)
                .ok_or_else(|| format!("{} {file} is malformed", entry.path().display()))
        };
        bound.push(RenderNode {
            name,
            pci: address,
            vendor: read("vendor")?,
            device: read("device")?,
        });
    }
    match bound.as_slice() {
        [node] if node.vendor == vendor && node.device == device_id => Ok(node.clone()),
        [node] => Err(format!(
            "the render node {} reports {}:{}, the plugin {vendor}:{device_id}",
            node.name, node.vendor, node.device
        )),
        [] => Err(format!("no render node at {pci}")),
        _ => Err(format!("more than one render node at {pci}")),
    }
}

/// The loader family the GPU plugin resolved, from the libraries the
/// enumeration mapped: a Level Zero plugin dlopens `libze_loader.so.1`
/// (OpenVINO `zero_loader`), an OpenCL plugin links `libOpenCL.so.1`. The
/// plugin exposes no backend property at 2026.2.1, and the loader decides
/// which driver stack runs in this process, so both families present at
/// once is an unresolvable identity, not a preference.
///
/// # Errors
///
/// When neither loader family is mapped, or both are, or the mapped loader
/// path cannot be found again for the manifest.
#[cfg(test)]
pub(crate) fn loader_stack(maps: &str) -> Result<(&'static str, String), String> {
    let mut mapped: Vec<&str> = Vec::new();
    for line in maps.lines() {
        let Some(mapping) = super::maps::mapping(line) else {
            continue;
        };
        // Only an executable mapping proves the loader ran here; a
        // non-executable remap of the same file is not the plugin's stack.
        if !mapping.executable {
            continue;
        }
        let name = Path::new(mapping.path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.starts_with("libze_loader.so.") {
            if !mapped.contains(&"level-zero") {
                mapped.push("level-zero");
            }
        } else if name.starts_with("libOpenCL.so") && !mapped.contains(&"opencl") {
            mapped.push("opencl");
        }
    }
    let path = |prefix: &str| {
        maps.lines().find_map(|line| {
            let mapping = super::maps::mapping(line)?;
            Path::new(mapping.path)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
                .then(|| mapping.path.to_owned())
        })
    };
    match mapped.as_slice() {
        ["level-zero"] => Ok((
            "level-zero",
            path("libze_loader.so.").ok_or("no libze_loader.so mapped")?,
        )),
        ["opencl"] => Ok((
            "opencl",
            path("libOpenCL.so").ok_or("no libOpenCL.so mapped")?,
        )),
        [] => Err("neither a Level Zero nor an OpenCL loader is mapped".into()),
        _ => Err("both a Level Zero and an OpenCL loader are mapped".into()),
    }
}

/// Every native library the GPU enumeration mapped, hashed through one
/// open file whose inode is kept, under the ADR-0022 section 4 discipline
/// ADR-0033 section 3 extends to the GPU stack. The scope is the whole
/// file-backed executable inventory: the plugin resolves arbitrary ICD and
/// driver libraries by name (a Mesa Rusticl ICD mapped beside the Intel
/// driver ran enumeration code in the measured processes), so guessing a
/// narrower name closure would under-bind the identity. The C API, the
/// core, the GPU plugin, exactly one loader family and the IR and ONNX
/// frontends beside the core, which compiling loads, must all be there.
///
/// # Errors
///
/// When a required member is missing, a library cannot be opened or read,
/// or a mapped library is not the file that was hashed.
#[cfg(test)]
pub(crate) fn gpu_libraries(
    maps_file: &Path,
    executable: &Path,
) -> Result<(String, Vec<super::HashedLibrary>, &'static str), String> {
    // First snapshot: the paths to hash and the loader family.
    let maps = std::fs::read_to_string(maps_file).map_err(|error| format!("maps: {error}"))?;
    let loader = loader_stack(&maps)?;
    let mut paths: Vec<PathBuf> = maps
        .lines()
        .filter_map(super::maps::mapping)
        .filter(|mapping| super::InventoryScope::Execution.includes(mapping))
        .map(|mapping| PathBuf::from(mapping.path))
        .collect();
    let named = |prefix: &str| {
        paths
            .iter()
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
            })
            .cloned()
    };
    for required in ["libopenvino_c.so.", "libopenvino.so."] {
        named(required).ok_or_else(|| format!("no {required} mapped"))?;
    }
    named("libopenvino_intel_gpu_plugin.so").ok_or_else(|| "no GPU plugin mapped".to_owned())?;
    let core = named("libopenvino.so.").ok_or_else(|| "no OpenVINO core mapped".to_owned())?;
    let version = core
        .file_name()
        .and_then(|name| {
            name.to_string_lossy()
                .strip_prefix("libopenvino.so.")
                .map(str::to_owned)
        })
        .ok_or_else(|| "unversioned OpenVINO core".to_owned())?;
    for frontend in [
        "libopenvino_ir_frontend.so.",
        "libopenvino_onnx_frontend.so.",
    ] {
        paths.push(core.with_file_name(format!("{frontend}{version}")));
    }
    paths.sort();
    paths.dedup();
    let mut lines = String::new();
    let mut hashed = Vec::with_capacity(paths.len());
    for path in &paths {
        // Hashed through one open file, whose inode is kept.
        use std::os::unix::fs::MetadataExt;
        let failed = |error: std::io::Error| format!("{}: {error}", path.display());
        let mut file = std::fs::File::open(path).map_err(failed)?;
        let metadata = file.metadata().map_err(failed)?;
        let mut bytes = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut bytes).map_err(failed)?;
        lines.push_str(&format!(
            "{} {}\n",
            path.display(),
            irlume_common::sha256_hex(&bytes)
        ));
        hashed.push(super::HashedLibrary {
            path: path.clone(),
            inode: metadata.ino(),
        });
    }
    // The process executable stays in the verified inventory (its mapping
    // and inode are checked) but out of the manifest, exactly as the NPU
    // execution inventory excludes it: a digest compiled into the binary
    // must not change with every rebuild of that binary.
    if !hashed.iter().any(|library| library.path == executable) {
        return Err("the process executable is absent from the mapped inventory".into());
    }
    let lines = lines
        .lines()
        .filter(|line| {
            line.rsplit_once(' ')
                .is_some_and(|(path, _)| Path::new(path) != executable)
        })
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let (loader_family, _) = loader;
    // Hashing a large stack takes time a runtime's background thread can
    // use to map more code, so the inventory is verified against a FRESH
    // snapshot taken after the hashing: anything mapped by then must be
    // one of the hashed files, or the identity refuses.
    let fresh =
        std::fs::read_to_string(maps_file).map_err(|error| format!("maps (re-read): {error}"))?;
    super::verify_mappings(&fresh, &hashed, super::InventoryScope::Execution).map_err(|why| {
        format!("the {loader_family} stack changed under the GPU identity: {why}")
    })?;
    Ok((lines, hashed, loader_family))
}

/// The complete GPU platform identity (ADR-0033 section 3): the plugin's
/// own device report bound to exactly one DRM render node and to the
/// firmware node at the same PCI address, the plugin and runtime builds,
/// the loader family, the fixed compile configuration, and the SHA-256
/// manifest of every native library the enumeration mapped.
///
/// `GPU_DRIVER_VERSION` is deliberately not a field: reading it through
/// the C API killed every measured 2026.2.1 process (root-owned archive
/// and Fedora RPM alike), and a driver or compute-runtime rebuild is
/// already a different identity through the library manifest. No digest
/// here places a model: loading admission stays closed and `CERTIFIED`
/// stays empty until the ADR-0033 section 5 gates pass on this identity.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The selected OpenVINO C API alias.
    pub selected_library: String,
    /// Its validated canonical endpoint.
    pub canonical_library: String,
    /// The runtime build parts, as reported by openvino-rs 0.11.0.
    pub runtime_version: String,
    /// The OpenVINO runtime build string.
    pub runtime_build: String,
    /// The GPU plugin's build string (`Core::versions("GPU")`).
    pub gpu_plugin: String,
    /// `FULL_DEVICE_NAME` of the one GPU.
    pub full_name: String,
    /// The device's capability line (FP32/FP16/INT8/BIN/...).
    pub capabilities: String,
    /// `DEVICE_ARCHITECTURE` (`GPU: vendor=0x8086 arch=v12.4.0`).
    pub architecture: String,
    /// `GPU_EXECUTION_UNITS_COUNT`.
    pub execution_units: String,
    /// `GPU_DEVICE_TOTAL_MEM_SIZE`, bytes.
    pub total_memory: String,
    /// `GPU_DEVICE_ID`, the PCI device id the plugin reported (`0x46d1`).
    pub device_id: String,
    /// `DEVICE_PCI_INFO` parsed to the canonical sysfs address.
    pub device_pci: String,
    /// The verified render node the plugin's device is bound to.
    pub render_node: RenderNode,
    /// The GPU firmware builds of that same node, or why they are
    /// unavailable.
    pub firmware: Firmware,
    /// The loader family the plugin resolved (`opencl` or `level-zero`).
    pub loader: String,
    /// [`COMPILE_CONFIGURATION`].
    pub configuration: String,
    /// `path sha256` of every mapped native library, one line each,
    /// sorted: a rebuilt library that keeps its version string is still a
    /// different identity.
    pub libraries: String,
}

impl Identity {
    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        [
            self.selected_library.as_str(),
            self.canonical_library.as_str(),
            self.runtime_version.as_str(),
            self.runtime_build.as_str(),
            self.gpu_plugin.as_str(),
            self.full_name.as_str(),
            self.capabilities.as_str(),
            self.architecture.as_str(),
            self.execution_units.as_str(),
            self.total_memory.as_str(),
            self.device_id.as_str(),
            self.device_pci.as_str(),
            self.render_node.name.as_str(),
            self.render_node.pci.as_str(),
            self.render_node.vendor.as_str(),
            self.render_node.device.as_str(),
        ]
        .into_iter()
        .map(std::borrow::Cow::Borrowed)
        .chain([
            std::borrow::Cow::Borrowed(self.loader.as_str()),
            std::borrow::Cow::Borrowed(self.configuration.as_str()),
            std::borrow::Cow::Borrowed(self.libraries.as_str()),
            // The firmware observation joins the digest through its
            // rendered form so every variant is bound.
            std::borrow::Cow::Owned(match &self.firmware {
                Firmware::Loaded { guc, huc } => format!("loaded guc={guc} huc={huc}"),
                Firmware::Malformed(why) => format!("malformed {why}"),
                Firmware::Unreadable => "unreadable".to_owned(),
            }),
        ])
        .collect()
    }

    /// SHA-256 over the fields, each prefixed by its byte length, so no
    /// two different identities share a digest by moving text between
    /// adjacent fields, mirroring the NPU identity. Names future GPU cache
    /// directories; certification keys stay empty until the ADR-0033
    /// section 5 gates pass.
    pub fn digest(&self) -> String {
        let mut encoded = Vec::new();
        for field in self.fields() {
            encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
            encoded.extend_from_slice(field.as_bytes());
        }
        irlume_common::sha256_hex(&encoded)
    }
}

/// What GPU discovery reports. Production never reaches the runtime:
/// [`Discovery::NotAdmitted`] is the closed-loading answer until a reviewed
/// GPU conformance profile exists (ADR-0033 section 4).
#[derive(Debug)]
pub enum Discovery {
    /// Loading admission is closed; nothing was loaded or enumerated.
    NotAdmitted,
    /// The provider could not be resolved or loaded, with the reason.
    Unavailable(String),
    /// More than one GPU is exposed; placement refuses until a reviewed
    /// rule selects one (ADR-0033 section 2).
    MultipleGpus(Vec<String>),
    /// No GPU is exposed by this system.
    Absent,
    /// The one GPU and its complete identity.
    Found(Box<Identity>),
}

/// Discover the GPU through the validated provider path. Production entry:
/// refuses before `dlopen` exactly like the NPU's [`super::Context`] - the
/// same closed gate, because no reviewed profile covers the GPU's driver
/// and compute-runtime inventory yet (ADR-0033 section 4).
pub fn discover(_selection: &RuntimeSelection) -> Discovery {
    if runtime::admit_loading().is_err() {
        return Discovery::NotAdmitted;
    }
    unreachable!("the GPU loading profile stays closed until reviewed")
}

/// Where the admitted test-only GPU entries read platform facts. Defaults
/// point at the real kernel trees; tests inject fixtures.
#[cfg(test)]
pub(crate) struct Sources<'a> {
    pub debugfs: &'a Path,
    pub sysfs_drm: &'a Path,
    pub maps: &'a Path,
}

#[cfg(test)]
impl Default for Sources<'static> {
    fn default() -> Self {
        Self {
            debugfs: Path::new("/sys/kernel/debug"),
            sysfs_drm: Path::new("/sys/class/drm"),
            maps: Path::new("/proc/self/maps"),
        }
    }
}

/// Read the complete identity of the one `device` the enumeration selected
/// (`GPU.0`). Every property read goes through the strings the C API
/// returns at 2026.2.1; the PCI binding then resolves through sysfs and
/// debugfs, and the mapped-library manifest through `maps`. Test-only,
/// like the admitted discovery that reaches it.
#[cfg(test)]
fn identity(
    core: &openvino::Core,
    library: &runtime::ResolvedLibrary,
    sources: &Sources<'_>,
    // The one enumerated device (`GPU.N`), never a hard-coded index. The
    // mapped-library manifest is snapshotted here, at the end, after every
    // property and version call above: if any of them maps another
    // executable library, it joins the manifest instead of escaping it.
    // The caller fixes the moment (after enumeration for discovery, after
    // the compile warm-up for the platform) by when it calls this.
    enumerated: &str,
) -> Result<(Identity, Vec<super::HashedLibrary>), String> {
    let device = openvino::DeviceType::Other(enumerated.to_owned().into());
    let property = |key: &str| {
        core.get_property(
            &device,
            &openvino::PropertyKey::Other(key.to_owned().into()),
        )
        .map_err(|error| format!("{key}: {error}"))
    };
    let full_name = property("FULL_DEVICE_NAME")?;
    let capabilities = property("OPTIMIZATION_CAPABILITIES")?;
    let architecture = property("DEVICE_ARCHITECTURE")?;
    let execution_units = property("GPU_EXECUTION_UNITS_COUNT")?;
    let total_memory = property("GPU_DEVICE_TOTAL_MEM_SIZE")?;
    let device_id = property("GPU_DEVICE_ID")?.to_ascii_lowercase();
    let device_pci = plugin_pci(&property("DEVICE_PCI_INFO")?)
        .ok_or_else(|| "DEVICE_PCI_INFO is malformed".to_owned())?;
    let gpu_plugin = core
        .versions("GPU")
        .map_err(|error| format!("GPU plugin version: {error}"))?
        .into_iter()
        .map(|(_, version)| version.build_number)
        .next()
        .ok_or_else(|| "no GPU plugin version".to_owned())?;
    let vendor = architecture_vendor(&architecture)
        .ok_or_else(|| "no vendor in DEVICE_ARCHITECTURE".to_owned())?;
    let render = render_node(sources.sysfs_drm, &device_pci, &vendor, &device_id)
        .map_err(|why| format!("render node: {why}"))?;
    // A firmware build that cannot be read makes the identity unusable
    // (ADR-0033 section 3): the discovery answer is the refusal, never a
    // Found identity carrying an Unreadable or Malformed observation. A
    // non-root reader gets exactly that reason.
    let firmware = match observe_firmware(sources.debugfs) {
        Ok(observation) => {
            if !observation.pci_slots.contains(&render.pci) {
                return Err(format!(
                    "the firmware node's PCI {:?} is not the render node {}",
                    observation.pci_slots.iter().collect::<Vec<_>>(),
                    render.pci
                ));
            }
            observation.into_firmware()
        }
        Err(FirmwareError::Unreadable) => {
            return Err("firmware: debugfs is unreadable (run as root)".into());
        }
        Err(FirmwareError::Malformed(why)) => {
            return Err(format!("firmware: malformed report: {why}"));
        }
    };
    let executable =
        std::fs::read_link("/proc/self/exe").map_err(|error| format!("exe: {error}"))?;
    let (libraries, hashed, loader) = gpu_libraries(sources.maps, &executable)?;
    let loader = loader.to_owned();
    Ok((
        Identity {
            selected_library: library.selected.to_string_lossy().into_owned(),
            canonical_library: library.canonical.to_string_lossy().into_owned(),
            runtime_version: openvino::version().parts().collect::<Vec<_>>().join("."),
            runtime_build: openvino::version().build_number,
            gpu_plugin,
            full_name,
            capabilities,
            architecture,
            execution_units,
            total_memory,
            device_id,
            device_pci,
            render_node: render,
            firmware,
            loader,
            configuration: COMPILE_CONFIGURATION.to_owned(),
            libraries,
        },
        hashed,
    ))
}

/// The admitted test-only entry for the hardware evidence harness
/// (`gpu_hw_*`): [`discover`] without the closed admission gate, so the
/// ignored measurements can collect what a certification starts from.
/// Production paths never call this; a cfg(test) entry is not a setting
/// that turns the refusal into an opt-in bypass.
#[cfg(test)]
pub(crate) fn discover_admitted(selection: &RuntimeSelection) -> Discovery {
    discover_admitted_with(selection, &Sources::default())
}

#[cfg(test)]
pub(crate) fn discover_admitted_with(
    selection: &RuntimeSelection,
    sources: &Sources<'_>,
) -> Discovery {
    // Discovery reports the same identity the compile platform keys on:
    // it opens the warmed platform, whose inventory covers everything a
    // compile maps, so one host yields one digest whichever entry the
    // harness used. A separate enumeration-time manifest would silently
    // under-name the stack on hosts whose compiles map more libraries.
    match GpuPlatform::open_admitted(selection, sources) {
        Ok(platform) => Discovery::Found(Box::new(platform.identity().clone())),
        Err(OpenError::Absent) => Discovery::Absent,
        Err(OpenError::Multiple(devices)) => Discovery::MultipleGpus(devices),
        Err(OpenError::Failed(why)) => Discovery::Unavailable(why),
    }
}

/// The actual enumeration-to-discovery path, injectable before any device
/// property read. Shared parsing must enforce the single-GPU rule here.
#[cfg(test)]
pub(crate) fn discover_enumerated_gpu(
    indices: &str,
    read_identity: impl FnOnce(&str) -> Discovery,
) -> Discovery {
    let devices = crate::gpu::parse_device_indices(indices);
    match devices.as_slice() {
        [] => Discovery::Absent,
        [device] => read_identity(device),
        _ => Discovery::MultipleGpus(devices),
    }
}

/// Firmware and PCI observation from one walk, for the groundwork
/// regression fixtures. Test-only; sysfs/debugfs roots are injectable.
#[cfg(test)]
pub(crate) fn firmware_with_pci(debugfs: &Path, sysfs_pci: &Path) -> (Firmware, Option<String>) {
    match observe_firmware(debugfs) {
        Ok(observation) => {
            let pci = if observation.pci_slots.len() == 1 {
                observation.pci_slots.iter().next().and_then(|slot| {
                    let base = sysfs_pci.join(slot);
                    let read_id = |name| {
                        let text = std::fs::read_to_string(base.join(name)).ok()?;
                        let id = text.trim();
                        let hex = id.strip_prefix("0x")?;
                        (hex.len() == 4 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
                            .then(|| id.to_owned())
                    };
                    Some(format!(
                        "{slot} {}:{}",
                        read_id("vendor")?,
                        read_id("device")?
                    ))
                })
            } else {
                None
            };
            (observation.into_firmware(), pci)
        }
        Err(error) => (error.into(), None),
    }
}

/// An opened GPU platform for the hardware evidence harness: the validated
/// provider, the complete [`Identity`] assembled after a compile warm-up
/// so its manifest covers the whole compile-path stack, and the fixed
/// compile configuration applied and read back (ADR-0033 section 2).
/// Test-only, like the admitted discovery it builds on; production
/// loading admission stays closed.
#[cfg(test)]
pub(crate) struct GpuPlatform {
    core: openvino::Core,
    identity: Identity,
    libraries: Vec<super::HashedLibrary>,
    maps: PathBuf,
    /// The explicit device every model compiles on (`GPU.0`).
    pub device: String,
}

/// A minimal valid ONNX model (a float[1] through an Identity node, 79
/// bytes) that warms the compile path up before the library inventory is
/// taken: compiling loads driver libraries the enumeration alone does not
/// (udev on the measured hosts), and the identity must name everything a
/// later compile of a real model runs, so no compile can map bytes the
/// manifest does not cover.
#[cfg(test)]
const WARM_UP_ONNX: &[u8] = &[
    0x08, 0x08, 0x12, 0x06, 0x69, 0x72, 0x6c, 0x75, 0x6d, 0x65, 0x3a, 0x3d, 0x0a, 0x13, 0x0a, 0x01,
    0x78, 0x12, 0x01, 0x79, 0x1a, 0x01, 0x6e, 0x22, 0x08, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
    0x79, 0x12, 0x04, 0x77, 0x61, 0x72, 0x6d, 0x5a, 0x0f, 0x0a, 0x01, 0x78, 0x12, 0x0a, 0x0a, 0x08,
    0x08, 0x01, 0x12, 0x04, 0x0a, 0x02, 0x08, 0x01, 0x62, 0x0f, 0x0a, 0x01, 0x79, 0x12, 0x0a, 0x0a,
    0x08, 0x08, 0x01, 0x12, 0x04, 0x0a, 0x02, 0x08, 0x01, 0x42, 0x04, 0x0a, 0x00, 0x10, 0x0d,
];

/// The inference precision of [`COMPILE_CONFIGURATION`].
#[cfg(test)]
const INFERENCE_PRECISION: &str = "f32";

/// The performance hint of [`COMPILE_CONFIGURATION`].
#[cfg(test)]
const PERFORMANCE_HINT: &str = "LATENCY";

/// Private evidence-harness proposal, not an upstream API or placement setting.
#[cfg(test)]
pub(crate) enum CacheMode<'a> {
    Disabled,
    /// Caller-owned existing directory, retained for the whole compile.
    Directory(&'a Path),
}

/// The automatic OpenVINO model-cache outcome a strict compile must observe.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheProvenance {
    Bypass,
    Miss,
    Hit,
}

/// Recognizer readbacks only; no claim about driver caches or global coldness.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CacheObservation {
    pub core_cache_dir: String,
    pub compiled_cache_dir: String,
    pub loaded_from_cache: bool,
}

#[cfg(test)]
type CacheCompileResult = (Box<dyn super::Infer>, String, Option<CacheObservation>);

#[cfg(test)]
fn cache_path(mode: CacheMode<'_>, expected: CacheProvenance) -> Result<&Path, String> {
    match (mode, expected) {
        (CacheMode::Disabled, CacheProvenance::Bypass) => Ok(Path::new("")),
        (CacheMode::Directory(path), CacheProvenance::Miss | CacheProvenance::Hit) => {
            let text = path
                .to_str()
                .ok_or_else(|| "the cache path is not UTF-8".to_owned())?;
            if text.contains('\0') || !path.is_absolute() || !path.is_dir() {
                return Err(
                    "the cache path must be an existing absolute directory without NUL".into(),
                );
            }
            Ok(path)
        }
        _ => Err("the cache mode does not match the expected provenance".into()),
    }
}

// Both compile entries use this gate. None never runs an observer, so legacy
// compilation acquires no provenance getters or their refusal paths.
#[cfg(test)]
fn cache_observation_gate<T>(
    expected: Option<CacheProvenance>,
    observe: impl FnOnce(CacheProvenance) -> Result<T, String>,
) -> Result<Option<T>, String> {
    expected.map(observe).transpose()
}

#[cfg(test)]
fn require_cache_property(key: &str, read: &str, expected: &str) -> Result<(), String> {
    if read != expected {
        return Err(format!("{key} reads {read:?}, not {expected:?}"));
    }
    Ok(())
}

#[cfg(test)]
fn parse_loaded_from_cache(read: &str) -> Result<bool, String> {
    match read {
        "YES" => Ok(true),
        "NO" => Ok(false),
        _ => Err(format!(
            "LOADED_FROM_CACHE is not exactly YES or NO: {read:?}"
        )),
    }
}

#[cfg(test)]
fn read_cache_observation(
    requested: &str,
    expected: CacheProvenance,
    core_cache_dir: String,
    mut get: impl FnMut(&'static str) -> Result<String, String>,
) -> Result<CacheObservation, String> {
    if requested.is_empty() != (expected == CacheProvenance::Bypass) {
        return Err("the cache directory does not match the expected provenance".into());
    }
    require_cache_property("Core CACHE_DIR", &core_cache_dir, requested)?;
    let mut read = |key| get(key).map_err(|error| format!("{key} readback: {error}"));
    let compiled_cache_dir = read("CACHE_DIR")?;
    require_cache_property("compiled CACHE_DIR", &compiled_cache_dir, requested)?;
    // GPU 2026.2.1 implements this getter but omits it from SUPPORTED_PROPERTIES.
    let loaded_from_cache = parse_loaded_from_cache(&read("LOADED_FROM_CACHE")?)?;
    if loaded_from_cache != (expected == CacheProvenance::Hit) {
        return Err(format!("LOADED_FROM_CACHE does not establish {expected:?}"));
    }
    for (key, value) in [
        ("PERFORMANCE_HINT", PERFORMANCE_HINT),
        ("INFERENCE_PRECISION_HINT", INFERENCE_PRECISION),
    ] {
        require_cache_property(key, &read(key)?, value)?;
    }
    Ok(CacheObservation {
        core_cache_dir,
        compiled_cache_dir,
        loaded_from_cache,
    })
}

#[cfg(test)]
fn validate_gpu_assignment(device: &str, assignment: &str) -> Result<String, String> {
    let assigned = assignment.trim();
    if assigned != device && assigned != "GPU" {
        return Err(format!("OpenVINO assigned {assigned:?}, not {device}"));
    }
    Ok(assigned.to_owned())
}

/// Why opening the GPU platform refused: typed so discovery reports the
/// enumeration answers instead of parsing error prose.
#[cfg(test)]
pub(crate) enum OpenError {
    /// No GPU is exposed.
    Absent,
    /// More than one GPU is exposed; placement refuses until a reviewed
    /// rule selects one (ADR-0033 section 2).
    Multiple(Vec<String>),
    /// Anything else, with the reason.
    Failed(String),
}

#[cfg(test)]
impl std::fmt::Debug for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => f.write_str("no GPU is exposed"),
            Self::Multiple(devices) => write!(f, "more than one GPU: {devices:?}"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

#[cfg(test)]
impl GpuPlatform {
    /// Open the platform through the validated provider and apply
    /// [`COMPILE_CONFIGURATION`], reading both properties back so a
    /// fallback cannot pass for the certified configuration.
    pub(crate) fn open_admitted(
        selection: &RuntimeSelection,
        sources: &Sources<'_>,
    ) -> Result<Self, OpenError> {
        let failed = |why: String| OpenError::Failed(why);
        let library = runtime::resolve_library(
            selection,
            super::OPENVINO_LIBRARY_DIRS,
            &runtime::Trust::default(),
        )
        .map_err(|error| failed(format!("provider: {error}")))?;
        openvino_sys::library::load_from(&library.canonical)
            .map_err(|error| failed(format!("load: {error}")))?;
        let mut core = openvino::Core::new().map_err(|error| failed(format!("core: {error}")))?;
        // The single-GPU rule gates the platform too: a system exposing
        // more than one GPU refuses placement (ADR-0033 section 2), and
        // every property, compile and warm-up below names the one
        // enumerated device, never a hard-coded index.
        let gpu = openvino::DeviceType::Other("GPU".into());
        let indices = core
            .get_property(&gpu, &openvino::PropertyKey::AvailableDevices)
            .map_err(|error| failed(format!("enumerate: {error}")))?;
        let enumerated = crate::gpu::parse_device_indices(&indices);
        let device_name = match enumerated.as_slice() {
            [] => return Err(OpenError::Absent),
            [one] => one.clone(),
            _ => return Err(OpenError::Multiple(enumerated)),
        };
        let device = openvino::DeviceType::Other(device_name.clone().into());
        let mut set = |key: openvino::RwPropertyKey, value: &str| -> Result<(), OpenError> {
            core.set_property(&device, &key, value)
                .map_err(|error| failed(format!("{value}: {error}")))
        };
        set(
            openvino::RwPropertyKey::HintPerformanceMode,
            PERFORMANCE_HINT,
        )?;
        set(
            openvino::RwPropertyKey::HintInferencePrecision,
            INFERENCE_PRECISION,
        )?;
        for (key, expected) in [
            (
                openvino::PropertyKey::Other("PERFORMANCE_HINT".into()),
                PERFORMANCE_HINT,
            ),
            (
                openvino::PropertyKey::Other("INFERENCE_PRECISION_HINT".into()),
                INFERENCE_PRECISION,
            ),
        ] {
            let read = core
                .get_property(&device, &key)
                .map_err(|error| failed(format!("{} read back: {error}", key.as_ref())))?;
            if read != expected {
                return Err(failed(format!(
                    "{} reads {read:?}, not {expected}",
                    key.as_ref()
                )));
            }
        }
        // Warm the compile path up with the embedded model before the
        // identity's inventory is taken: compiling loads driver libraries
        // the enumeration alone does not (udev on the measured hosts), and
        // the identity must name everything its own execution runs.
        let warm_scratch =
            tempfile::tempdir().map_err(|error| failed(format!("warm-up dir: {error}")))?;
        {
            use openvino::{DeviceType, RwPropertyKey};
            // The fixture's input is already a static float[1].
            let warm = core
                .read_model_from_buffer(WARM_UP_ONNX, None)
                .map_err(|error| failed(format!("warm-up read: {error}")))?;
            let device = DeviceType::Other(device_name.clone().into());
            core.set_property(
                &device,
                &RwPropertyKey::CacheDir,
                warm_scratch
                    .path()
                    .to_str()
                    .ok_or_else(|| failed("the warm-up cache path is not UTF-8".into()))?,
            )
            .map_err(|error| failed(format!("warm-up CACHE_DIR: {error}")))?;
            let compiled = core
                .compile_model(&warm, device)
                .map_err(|error| failed(format!("warm-up compile: {error}")))?;
            let assigned = compiled
                .get_property(&openvino::PropertyKey::Other("EXECUTION_DEVICES".into()))
                .map_err(|error| failed(format!("warm-up EXECUTION_DEVICES: {error}")))?;
            if assigned.trim() != "GPU" && assigned.trim() != device_name {
                return Err(failed(format!("the warm-up compiled on {assigned:?}")));
            }
        }
        // The identity is assembled here, after the warm-up, and it
        // snapshots its own manifest at the end of its reads, so its
        // inventory covers the full compile-path stack; the hashed set it
        // returns is the platform's verification inventory.
        let (identity, libraries) =
            identity(&core, &library, sources, &device_name).map_err(failed)?;
        Ok(Self {
            core,
            identity,
            libraries,
            maps: sources.maps.to_path_buf(),
            device: device_name,
        })
    }

    /// The complete identity of the opened platform.
    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Every mapped library is still the file the identity hashed, by
    /// inode (ADR-0022 section 4 discipline): the check whose failure
    /// retires an NPU model, available to the GPU harness after any
    /// compile or inference.
    pub(crate) fn still_loaded_as_hashed(&self) -> Result<(), String> {
        let maps = std::fs::read_to_string(&self.maps).map_err(|error| format!("maps: {error}"))?;
        super::verify_mappings(&maps, &self.libraries, super::InventoryScope::Execution)
            .map_err(|why| format!("the mapped GPU stack changed: {why}"))
    }

    /// Compile `model` on the explicit device under
    /// [`COMPILE_CONFIGURATION`], with the batch fixed to 1 and the blobs
    /// cached in `cache_dir`, and require OpenVINO to name that device as
    /// the execution device. Re-reads the memory map afterwards so a
    /// library swapped in during the compile is a refusal, not a silent
    /// identity change (the compile-time arm of retirement).
    pub(crate) fn compile(
        &mut self,
        cache_dir: &Path,
        model: &[u8],
    ) -> Result<(Box<dyn super::Infer>, String), String> {
        self.compile_inner(cache_dir, model, None)
            .map(|(model, assignment, _)| (model, assignment))
    }

    /// Strict recognizer model-cache evidence after the separate identity
    /// warm-up. Disabled resets CACHE_DIR to empty; it does not flush drivers.
    ///
    /// # Errors
    /// Refuses invalid mode/path, any compile/identity error, failed readback,
    /// or cache/configuration readbacks that do not establish `expected`.
    pub(crate) fn compile_with_cache_observation(
        &mut self,
        cache: CacheMode<'_>,
        expected: CacheProvenance,
        model: &[u8],
    ) -> Result<(Box<dyn super::Infer>, String, CacheObservation), String> {
        let path = cache_path(cache, expected)?;
        let (model, assignment, observation) = self.compile_inner(path, model, Some(expected))?;
        let observation = observation.ok_or_else(|| "cache observation missing".to_owned())?;
        Ok((model, assignment, observation))
    }

    fn compile_inner(
        &mut self,
        cache_dir: &Path,
        model: &[u8],
        expected: Option<CacheProvenance>,
    ) -> Result<CacheCompileResult, String> {
        use openvino::{DeviceType, PartialShape, PropertyKey, RwPropertyKey};
        let failed = |what: &str, error: &dyn std::fmt::Display| format!("{what}: {error}");
        let mut read = self
            .core
            .read_model_from_buffer(model, None)
            .map_err(|error| failed("read", &error))?;
        let inputs = read
            .get_inputs_len()
            .map_err(|error| failed("inputs", &error))?;
        if inputs != 1 {
            return Err(format!("the model has {inputs} inputs"));
        }
        let partial = read
            .get_input_by_index(0)
            .and_then(|input| input.get_partial_shape())
            .map_err(|error| failed("input shape", &error))?;
        if partial.get_rank().is_dynamic() {
            return Err("the input rank is dynamic".into());
        }
        let dimensions = partial
            .get_dimensions()
            .iter()
            .map(|dimension| (!dimension.is_dynamic()).then(|| dimension.get_min()))
            .collect::<Vec<_>>();
        let input_shape =
            super::fixed_batch_shape(&dimensions).map_err(|reason| reason.to_string())?;
        if partial.is_dynamic() {
            let fixed = PartialShape::new_static(input_shape.len() as i64, &input_shape)
                .map_err(|error| failed("fixed shape", &error))?;
            read.reshape_single_input(&fixed)
                .map_err(|error| failed("reshape", &error))?;
        }
        let blobs = cache_dir
            .to_str()
            .ok_or_else(|| "the cache path is not UTF-8".to_owned())?;
        let device = DeviceType::Other(self.device.clone().into());
        self.core
            .set_property(&device, &RwPropertyKey::CacheDir, blobs)
            .map_err(|error| failed("CACHE_DIR", &error))?;
        let core_cache_dir = cache_observation_gate(expected, |_| {
            let read = self
                .core
                .get_property(&device, &PropertyKey::from(RwPropertyKey::CacheDir))
                .map_err(|error| failed("Core CACHE_DIR", &error))?;
            require_cache_property("Core CACHE_DIR", &read, blobs)?;
            Ok(read)
        })?;
        let mut compiled = self
            .core
            .compile_model(&read, device)
            .map_err(|error| failed("compile", &error))?;
        let assignment = validate_gpu_assignment(
            &self.device,
            &compiled
                .get_property(&PropertyKey::Other("EXECUTION_DEVICES".into()))
                .map_err(|error| failed("EXECUTION_DEVICES", &error))?,
        )?;
        let observation = cache_observation_gate(expected, |expected| {
            let core_dir =
                core_cache_dir.ok_or_else(|| "Core cache observation missing".to_owned())?;
            read_cache_observation(blobs, expected, core_dir, |key| {
                compiled
                    .get_property(&PropertyKey::Other(key.into()))
                    .map(|value| value.into_owned())
                    .map_err(|error| error.to_string())
            })
        })?;
        let request = compiled
            .create_infer_request()
            .map_err(|error| failed("infer request", &error))?;
        self.still_loaded_as_hashed()?;
        let model = GpuModel {
            _compiled: compiled,
            request,
            input_shape,
        };
        Ok((Box::new(model), assignment, observation))
    }
}

/// A GPU-compiled model: one `f32` input in, its first `f32` output back,
/// mirroring the NPU model so the harness treats both alike.
#[cfg(test)]
struct GpuModel {
    // Owns the compiled model the request runs; dropped after it.
    _compiled: openvino::CompiledModel,
    request: openvino::InferRequest,
    input_shape: Vec<i64>,
}

#[cfg(test)]
impl super::Infer for GpuModel {
    fn infer(&mut self, input: &[f32]) -> Result<Vec<f32>, String> {
        use openvino::{ElementType, Shape, Tensor};
        let failed = |what: &str, error: &dyn std::fmt::Display| format!("{what}: {error}");
        let shape = Shape::new(&self.input_shape).map_err(|error| failed("shape", &error))?;
        let mut tensor = Tensor::new(ElementType::F32, &shape)
            .map_err(|error| failed("input tensor", &error))?;
        let target = tensor
            .get_data_mut::<f32>()
            .map_err(|error| failed("input data", &error))?;
        if target.len() != input.len() {
            return Err(format!(
                "input has {} values, the compiled model takes {}",
                input.len(),
                target.len()
            ));
        }
        target.copy_from_slice(input);
        self.request
            .set_input_tensor(&tensor)
            .map_err(|error| failed("set input", &error))?;
        self.request
            .infer()
            .map_err(|error| failed("infer", &error))?;
        // The C API hands back a new wrapper the caller frees, so dropping
        // it is right; `Tensor::set_shape`, which aliases its pointer, is
        // never called.
        let output = self
            .request
            .get_output_tensor_by_index(0)
            .map_err(|error| failed("output", &error))?;
        if output
            .get_element_type()
            .map_err(|error| failed("output type", &error))?
            != ElementType::F32
        {
            return Err("the output is not f32".into());
        }
        Ok(output
            .get_data::<f32>()
            .map_err(|error| failed("output data", &error))?
            .to_vec())
    }
}

#[cfg(test)]
#[path = "gpu_cache_tests.rs"]
mod gpu_cache_tests;
