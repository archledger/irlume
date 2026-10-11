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
use std::path::Path;

/// What the `gpu` key of a `settings.conf` file holds (ADR-0033 section 8;
/// the same shapes as the NPU switch).
#[derive(Clone, Copy, Debug)]
pub enum Setting<'a> {
    /// No `settings.conf`, or no `gpu` key in it.
    Absent,
    /// The key's raw value.
    Value(&'a [u8]),
    /// `settings.conf` exists but cannot be read.
    Unreadable,
}

/// The `gpu` key of a `settings.conf` file's bytes: absent when no line
/// names it; otherwise any line switching it off wins, else the first
/// value, matching the NPU switch's read.
pub fn settings_conf_value(bytes: &[u8]) -> Setting<'_> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Setting::Unreadable;
    };
    let values: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| key.trim() == "gpu")
        .map(|(_, value)| value.trim())
        .collect();
    let off = values
        .iter()
        .find(|value| !switch_allows(None, Setting::Value(value.as_bytes())));
    match off.or(values.first()) {
        Some(value) => Setting::Value(value.as_bytes()),
        None => Setting::Absent,
    }
}

/// The `IRLUME_GPU` / `gpu` kill switch (ADR-0033 section 8): `true` leaves
/// admission and certification to decide, `false` keeps the recognizer off
/// the GPU. An absent source or a recognized on value allows; an off value,
/// an empty, malformed or non-UTF-8 value and an unreadable settings file
/// all disable it; either source disabling wins.
pub fn switch_allows(env: Option<&std::ffi::OsStr>, setting: Setting<'_>) -> bool {
    use std::os::unix::ffi::OsStrExt;
    fn on(raw: &[u8]) -> bool {
        std::str::from_utf8(raw).is_ok_and(|text| {
            matches!(
                text.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
    }
    let env_allows = env.is_none_or(|value| on(value.as_bytes()));
    let setting_allows = match setting {
        Setting::Absent => true,
        Setting::Value(raw) => on(raw),
        Setting::Unreadable => false,
    };
    env_allows && setting_allows
}

/// The loaded GPU firmware builds, where the kernel exposes them (ADR-0033
/// section 3): the GuC and HuC versions of the graphics microcontrollers,
/// read from debugfs the same way ADR-0033's NPU premise reads the NPU
/// firmware. Unreadable firmware makes the identity unreadable, and GPU
/// placement refuses; a non-root reader records exactly that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Firmware {
    /// Both builds, as reported by the loaded driver.
    Loaded { guc: String, huc: String },
    /// The files exist but carry no parseable version.
    Malformed(String),
    /// debugfs is absent or unreadable to this process.
    Unreadable,
}

/// Read the GuC and HuC firmware builds from
/// `/sys/kernel/debug/dri/<N>/gt*/uc/{guc,huc}_info`. Each dri node also
/// appears as a bus-address symlink, so entries are deduplicated by their
/// canonical path; a single graphics node is required, mirroring the
/// single-GPU rule: more than one node's firmware is ambiguous and refuses.
pub fn firmware(debugfs: &Path) -> Firmware {
    let mut nodes: Vec<std::path::PathBuf> = Vec::new();
    let Ok(entries) = std::fs::read_dir(debugfs.join("dri")) else {
        return Firmware::Unreadable;
    };
    for card in entries.flatten() {
        let Ok(canonical) = card.path().canonicalize() else {
            continue;
        };
        if !nodes.contains(&canonical) {
            nodes.push(canonical);
        }
    }
    // One firmware pair per graphics node: i915 exposes it at gt0/uc, the
    // xe driver (Lunar Lake and newer) once per tile at tile*/gt*/uc, so
    // the pairs of one node must agree and become its single answer.
    let mut per_node: Vec<(String, String)> = Vec::new();
    for node in nodes {
        let mut gucs: Vec<String> = Vec::new();
        let mut hucs: Vec<String> = Vec::new();
        for gt in ["gt0", "tile0/gt0", "tile0/gt1"] {
            let uc = node.join(gt).join("uc");
            let (Some(guc), Some(huc)) = (
                read_uc_version(&uc.join("guc_info")),
                read_uc_version(&uc.join("huc_info")),
            ) else {
                continue;
            };
            gucs.push(guc);
            hucs.push(huc);
        }
        let unique_gucs: std::collections::BTreeSet<&str> =
            gucs.iter().map(String::as_str).collect();
        let unique_hucs: std::collections::BTreeSet<&str> =
            hucs.iter().map(String::as_str).collect();
        if unique_gucs.len() != 1 || unique_hucs.len() != 1 {
            // No readable pair: a dri node without graphics microcontrollers
            // (a render-only or non-i915 node) has no uc directory.
            if gucs.is_empty() {
                continue;
            }
            // One node reporting conflicting builds across its tiles is
            // malformed, not loaded.
            return Firmware::Malformed("conflicting firmware builds across tiles".into());
        }
        per_node.push((gucs[0].clone(), hucs[0].clone()));
    }
    match per_node.as_slice() {
        // Exactly one graphics node: the single-GPU answer.
        [(guc, huc)] => Firmware::Loaded {
            guc: guc.clone(),
            huc: huc.clone(),
        },
        // More than one graphics node is ambiguous for a single-GPU
        // placement decision, mirroring the single-GPU rule.
        [_first, _second, ..] => Firmware::Malformed("more than one graphics firmware node".into()),
        [] => Firmware::Unreadable,
    }
}

/// Parse the LOADED build out of a `guc_info`/`huc_info` file. Only a line
/// that contains `found` counts: i915 writes `version: found X.Y[.Z]`, the
/// xe driver writes `found release version X.Y[.Z]` beside a `wanted`
/// line, and a microcontroller that did not load has a `wanted` line and
/// no `found` one. The first version-shaped token on the found line is the
/// answer, wherever on the line it sits.
fn read_uc_version(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let found_line = text
        .lines()
        .find(|line| line.contains("found") && line.contains("version"))?;
    let mut version = String::new();
    let mut in_version = false;
    for character in found_line.chars() {
        let digit_or_dot = character.is_ascii_digit() || character == '.';
        if digit_or_dot {
            in_version = true;
            version.push(character);
        } else if in_version {
            break;
        }
    }
    let trimmed = version.trim_matches('.');
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// The GPU identity a certification names (ADR-0033 section 3): the
/// selected provider endpoint, the device's full name and capabilities as
/// the runtime reports them, and the loaded GPU firmware.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The selected OpenVINO C API alias.
    pub selected_library: String,
    /// Its validated canonical endpoint.
    pub canonical_library: String,
    /// `FULL_DEVICE_NAME` of the one GPU.
    pub full_name: String,
    /// The device's capability line (FP32/FP16/INT8/BIN/...).
    pub capabilities: String,
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
    /// The one GPU and its identity.
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
    let devices: Vec<String> = indices
        .split(',')
        .map(str::trim)
        .filter(|index| !index.is_empty())
        .map(|index| format!("GPU.{index}"))
        .collect();
    match devices.as_slice() {
        [] => return Discovery::Absent,
        [_] => {}
        _ => return Discovery::MultipleGpus(devices),
    }
    let full_name = match core.get_property(&gpu, &openvino::PropertyKey::DeviceFullName) {
        Ok(name) => name,
        Err(error) => return Discovery::Unavailable(format!("full name: {error}")),
    };
    let capabilities = match core.get_property(&gpu, &openvino::PropertyKey::DeviceCapabilities) {
        Ok(caps) => caps,
        Err(error) => return Discovery::Unavailable(format!("capabilities: {error}")),
    };
    Discovery::Found(Identity {
        selected_library: library.selected.to_string_lossy().into_owned(),
        canonical_library: library.canonical.to_string_lossy().into_owned(),
        full_name,
        capabilities,
        firmware: firmware(Path::new("/sys/kernel/debug")),
    })
}
