// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! GPU device groundwork under closed admission (ADR-0033 sections 2 to 4
//! and 8).
//!
//! The GPU is an eligible accelerator through the same validated OpenVINO
//! C API provider the NPU uses: one explicit device, never `MULTI`,
//! `HETERO` or `AUTO`, and a system that exposes more than one GPU refuses
//! GPU placement until a reviewed rule selects one. Nothing here loads the
//! provider in production: [`discover`] refuses before `dlopen` exactly as
//! the NPU path does, and the admitted entry is test-only, reserved for
//! the hardware evidence a certification starts from.

use super::runtime::{self, RuntimeSelection};
pub use crate::gpu::{settings_conf_value, switch_allows, Setting};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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

fn directory_entries(path: &Path) -> Result<Vec<PathBuf>, FirmwareError> {
    let entries = std::fs::read_dir(path).map_err(|_| FirmwareError::Unreadable)?;
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FirmwareError::Unreadable)?;
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
        let canonical = card.canonicalize().map_err(|_| FirmwareError::Unreadable)?;
        let slots = nodes.entry(canonical).or_default();
        if let Some(name) = card.file_name().and_then(|name| name.to_str()) {
            if pci_slot(name) {
                slots.insert(name.to_owned());
            }
        }
    }
    let mut per_node = Vec::new();
    for (node, _pci_slots) in nodes {
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
            pci_slots: _pci_slots,
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

/// INCOMPLETE GPU identity groundwork (ADR-0033 section 3), never a
/// certification key. It observes the provider/runtime, plugin-reported
/// name/capabilities and a unique debugfs firmware node. The plugin's mapping
/// to that node or a selected render node has NOT been established.
///
/// Missing: GPU plugin version, verified render-node/PCI binding, driver and
/// Level Zero/OpenCL stack, compile configuration and every mapped native
/// library's SHA-256 under the ADR-0022 inode discipline. No digest, loading
/// admission or certification may be derived from this partial observation.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The selected OpenVINO C API alias.
    pub selected_library: String,
    /// Its validated canonical endpoint.
    pub canonical_library: String,
    /// The runtime build parts, as reported by openvino-rs 0.11.0.
    pub runtime_version: String,
    /// `FULL_DEVICE_NAME` of the one GPU.
    pub full_name: String,
    /// The device's capability line (FP32/FP16/INT8/BIN/...).
    pub capabilities: String,
    /// PCI slot and vendor:device of the SAME uniquely observed firmware
    /// node, if its bus alias resolves through sysfs. This is not proof of
    /// the GPU plugin's selected render node; absence/ambiguity is `None`.
    pub firmware_node_pci: Option<String>,
    /// The GPU firmware builds, or why they are unavailable.
    pub firmware: Firmware,
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
    /// The one GPU and its incomplete identity observations.
    Found(Identity),
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

/// The admitted test-only entry for the hardware evidence harness
/// (`gpu_hw_*`): [`discover`] without the closed admission gate, so the
/// ignored measurements can collect what a certification starts from.
/// Production paths never call this; a cfg(test) entry is not a setting
/// that turns the refusal into an opt-in bypass.
#[cfg(test)]
pub(crate) fn discover_admitted(selection: &RuntimeSelection) -> Discovery {
    let library = match runtime::resolve_library(
        selection,
        super::OPENVINO_LIBRARY_DIRS,
        &runtime::Trust::default(),
    ) {
        Ok(library) => library,
        Err(error) => return Discovery::Unavailable(format!("provider: {error}")),
    };
    if let Err(error) = openvino_sys::library::load_from(&library.canonical) {
        return Discovery::Unavailable(format!("load: {error}"));
    }
    let Ok(core) = openvino::Core::new() else {
        return Discovery::Unavailable("core".into());
    };
    let gpu = openvino::DeviceType::Other("GPU".into());
    // The GPU plugin answers AVAILABLE_DEVICES with its device indices
    // ("0", "1", ...); "GPU" is an alias for GPU.0 and the order beyond it
    // is driver-dependent, so the count alone decides (ADR-0033 section 2).
    let indices = match core.get_property(&gpu, &openvino::PropertyKey::AvailableDevices) {
        Ok(indices) => indices,
        Err(error) => return Discovery::Unavailable(format!("enumerate: {error}")),
    };
    discover_enumerated_gpu(&indices, |device| {
        let gpu = openvino::DeviceType::Other(device.into());
        let full_name = match core.get_property(&gpu, &openvino::PropertyKey::DeviceFullName) {
            Ok(name) => name,
            Err(error) => return Discovery::Unavailable(format!("full name: {error}")),
        };
        let capabilities = match core.get_property(&gpu, &openvino::PropertyKey::DeviceCapabilities)
        {
            Ok(caps) => caps,
            Err(error) => return Discovery::Unavailable(format!("capabilities: {error}")),
        };
        let (firmware, firmware_node_pci) = firmware_with_pci(
            Path::new("/sys/kernel/debug"),
            Path::new("/sys/bus/pci/devices"),
        );
        Discovery::Found(Identity {
            selected_library: library.selected.to_string_lossy().into_owned(),
            canonical_library: library.canonical.to_string_lossy().into_owned(),
            runtime_version: openvino::version().parts().collect::<Vec<_>>().join("."),
            full_name,
            capabilities,
            firmware_node_pci,
            firmware,
        })
    })
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

/// Firmware and PCI observation from one walk: no first-bus-entry guess and
/// no claim that the runtime maps to this debugfs node. Test-only, like the
/// admitted discovery that consumes it; sysfs/debugfs roots are injectable.
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
