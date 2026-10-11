// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! GPU policy parsing in every build (ADR-0033 section 8).
//!
//! A switch can disable placement but cannot admit native loading or certify
//! a model. Default builds also need this policy to report the CPU reason.

/// What the `gpu` key of a `settings.conf` file holds.
#[derive(Clone, Copy, Debug)]
pub enum Setting<'a> {
    /// No file or no GPU key.
    Absent,
    /// The single key's raw value, including an invalid empty assignment.
    Value(&'a [u8]),
    /// More than one attempted assignment to the GPU key.
    Duplicate,
    /// The file cannot be read or decoded as UTF-8.
    Unreadable,
}

/// Read the GPU switch without treating malformed assignments as absence.
/// Comments and unrelated keys are ignored; duplicate keys disable placement.
pub fn settings_conf_value(bytes: &[u8]) -> Setting<'_> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Setting::Unreadable;
    };
    let mut value = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next();
        if key != Some("gpu") {
            continue;
        }
        let raw = match line.split_once('=') {
            Some((key, raw)) if key.trim() == "gpu" => raw.trim().as_bytes(),
            _ => b"",
        };
        if value.replace(raw).is_some() {
            return Setting::Duplicate;
        }
    }
    value.map_or(Setting::Absent, Setting::Value)
}

/// Whether neither source disables GPU use. Either disabling source wins;
/// empty, malformed, non-UTF-8, duplicate or unreadable sources disable use.
/// `true` still requires loading admission and model certification.
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
        Setting::Duplicate | Setting::Unreadable => false,
    };
    env_allows && setting_allows
}

/// Parse OpenVINO's whitespace-separated GPU indices. Comma separators are
/// also accepted. The discovery path checks the resulting device count.
pub fn parse_device_indices(indices: &str) -> Vec<String> {
    indices
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|index| !index.is_empty())
        .map(|index| format!("GPU.{index}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn gpu_switch_refuses_duplicate_and_malformed_assignments_in_every_build() {
        for text in [
            "gpu=on\ngpu=on",
            "gpu=off\ngpu=off",
            "gpu=on\ngpu: off",
            "gpu",
            "gpu: off",
            "gpu off",
            "gpu=",
            "gpu=maybe",
        ] {
            assert!(
                !switch_allows(None, settings_conf_value(text.as_bytes())),
                "{text:?}"
            );
            assert!(
                !switch_allows(Some(OsStr::new("on")), settings_conf_value(text.as_bytes())),
                "{text:?}"
            );
        }
        assert!(matches!(
            settings_conf_value(b"gpu=on\ngpu=on"),
            Setting::Duplicate
        ));
        for text in ["", "# gpu off", "gpu_extra=off", "npu=off", "gpu= ON "] {
            assert!(
                switch_allows(None, settings_conf_value(text.as_bytes())),
                "{text:?}"
            );
        }
    }

    #[test]
    fn gpu_switch_refuses_either_invalid_source_in_every_build() {
        assert!(!switch_allows(None, settings_conf_value(b"gpu=on\n\xff")));
        assert!(!switch_allows(None, Setting::Unreadable));
        for raw in [b"off".as_slice(), b"", b"unknown", b"\xff"] {
            assert!(!switch_allows(
                Some(OsStr::from_bytes(raw)),
                Setting::Value(b"on")
            ));
        }
        assert!(!switch_allows(
            Some(OsStr::new("on")),
            Setting::Value(b"off")
        ));
        assert!(switch_allows(Some(OsStr::new(" ON ")), Setting::Absent));
    }

    #[test]
    fn gpu_device_indices_parse_whitespace_and_commas() {
        assert_eq!(parse_device_indices("0"), ["GPU.0"]);
        assert_eq!(
            parse_device_indices(" 0, 1\t2\n3\r4 "),
            ["GPU.0", "GPU.1", "GPU.2", "GPU.3", "GPU.4"]
        );
        assert!(parse_device_indices(" , \t\n").is_empty());
    }
}
