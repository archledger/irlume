// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Read-only observations for the retained-model test, not kernel attestation.

#![cfg(test)]

use super::gpu_reliability_clock_tests::SleepOffsetBounds;
use super::gpu_reliability_witness_tests::{parse_runtime_ms, DeviceBinding, RuntimeSample};
use crate::npu::{gpu::RenderNode, Bound};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    canonical_device: String,
    pci: String,
    vendor: String,
    device: String,
    driver: String,
    boot_id: String,
}

impl Binding {
    fn view(&self) -> DeviceBinding<'_> {
        DeviceBinding {
            canonical_device: &self.canonical_device,
            pci: &self.pci,
            vendor: &self.vendor,
            device: &self.device,
            driver: &self.driver,
            boot_id: &self.boot_id,
        }
    }
}

/// Own both actual endpoint observations until the pure witness consumes them.
#[derive(Debug)]
pub(super) struct Observation {
    bindings: [Binding; 2],
    control: [String; 2],
    status: [String; 2],
    read_window: [Duration; 2],
    active_ms: u64,
    suspended_ms: u64,
}

impl Observation {
    pub(super) fn view(&self) -> RuntimeSample<'_> {
        RuntimeSample {
            binding: self.bindings.each_ref().map(|binding| Some(binding.view())),
            control: self.control.each_ref().map(|value| Some(value.as_str())),
            status: self.status.each_ref().map(|value| Some(value.as_str())),
            read_window: self.read_window,
            active_ms: Some(self.active_ms),
            suspended_ms: Some(self.suspended_ms),
        }
    }
}

pub(super) struct Reader {
    device_link: PathBuf,
    boot_file: PathBuf,
    binding: Binding,
    origin: Instant,
}

fn text(path: &Path, read: &mut impl FnMut(&Path) -> io::Result<String>) -> Result<String, String> {
    read(path)
        .map(|s| s.trim().to_owned())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "unrepresentable sysfs path".to_owned())
}

fn binding(
    device_link: &Path,
    boot_file: &Path,
    read: &mut impl FnMut(&Path) -> io::Result<String>,
) -> Result<Binding, String> {
    let canonical = device_link
        .canonicalize()
        .map_err(|e| format!("device binding: {e}"))?;
    let pci = canonical
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("missing PCI basename")?
        .to_owned();
    let driver = canonical
        .join("driver")
        .canonicalize()
        .map_err(|e| format!("driver binding: {e}"))?;
    if !driver.is_dir() {
        return Err("driver binding is not a directory".into());
    }
    let vendor = text(&canonical.join("vendor"), read)?.to_ascii_lowercase();
    let device = text(&canonical.join("device"), read)?.to_ascii_lowercase();
    for id in [&vendor, &device] {
        if id.len() != 6 || !id.starts_with("0x") || !id[2..].bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err("malformed PCI identifier".into());
        }
    }
    let boot_id = text(boot_file, read)?;
    let parts: Vec<_> = boot_id.split('-').collect();
    if parts.len() != 5
        || !parts.iter().zip([8, 4, 4, 4, 12]).all(|(part, length)| {
            part.len() == length
                && part
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
        })
    {
        return Err("malformed boot identifier".into());
    }
    Ok(Binding {
        canonical_device: path_text(&canonical)?,
        pci,
        vendor,
        device,
        driver: path_text(&driver)?,
        boot_id,
    })
}

impl Reader {
    /// Bind the already-discovered identity, with injectable roots for fixtures.
    /// The hardware controller must pass /sys/class/drm and the kernel boot ID.
    ///
    /// # Errors
    /// Refuses path-like render names, unavailable/malformed metadata, identity
    /// disagreement, and inconsistent startup bindings. No discovery or PM write.
    pub(super) fn new(drm: &Path, boot_file: &Path, node: &RenderNode) -> Result<Self, String> {
        let suffix = node
            .name
            .strip_prefix("renderD")
            .ok_or("invalid render name")?;
        if suffix.is_empty() || !suffix.bytes().all(|v| v.is_ascii_digit()) {
            return Err("invalid render name".into());
        }
        let device_link = drm.join(&node.name).join("device");
        let mut read = |path: &Path| std::fs::read_to_string(path);
        let expected = binding(&device_link, boot_file, &mut read)?;
        if expected.pci != node.pci
            || expected.vendor != node.vendor
            || expected.device != node.device
        {
            return Err("sysfs disagrees with the GPU identity".into());
        }
        if binding(&device_link, boot_file, &mut read)? != expected {
            return Err("startup device binding changed".into());
        }
        Ok(Self {
            device_link,
            boot_file: boot_file.to_owned(),
            binding: expected,
            origin: Instant::now(),
        })
    }

    pub(super) fn expected(&self) -> DeviceBinding<'_> {
        self.binding.view()
    }

    /// # Errors
    /// Refuses unreadable/malformed counters, binding changes or reversed time.
    /// Mixed or transitional status/control remains visible to the pure witness.
    pub(super) fn sample(&self) -> Result<Observation, String> {
        self.capture_with(
            || self.origin.elapsed(),
            |path| std::fs::read_to_string(path),
        )
    }

    fn capture_with(
        &self,
        mut now: impl FnMut() -> Duration,
        mut read: impl FnMut(&Path) -> io::Result<String>,
    ) -> Result<Observation, String> {
        let start = now();
        let before = binding(&self.device_link, &self.boot_file, &mut read)?;
        if before != self.binding {
            return Err("device binding changed before counters".into());
        }
        let power = Path::new(&self.binding.canonical_device).join("power");
        let control_before = text(&power.join("control"), &mut read)?;
        let status_before = text(&power.join("runtime_status"), &mut read)?;
        let active_ms = parse_runtime_ms(&text(&power.join("runtime_active_time"), &mut read)?)
            .ok_or("invalid active counter")?;
        let suspended_ms =
            parse_runtime_ms(&text(&power.join("runtime_suspended_time"), &mut read)?)
                .ok_or("invalid suspended counter")?;
        let status_after = text(&power.join("runtime_status"), &mut read)?;
        let control_after = text(&power.join("control"), &mut read)?;
        let after = binding(&self.device_link, &self.boot_file, &mut read)?;
        let end = now();
        if after != self.binding {
            return Err("device binding changed after counters".into());
        }
        if end < start {
            return Err("reversed observation bracket".into());
        }
        Ok(Observation {
            bindings: [before, after],
            control: [control_before, control_after],
            status: [status_before, status_after],
            read_window: [start, end],
            active_ms,
            suspended_ms,
        })
    }
}

pub(super) fn sleep_bounds() -> Option<SleepOffsetBounds> {
    sleep_bounds_with(crate::npu::suspended)
}

fn sleep_bounds_with(mut read: impl FnMut(Bound) -> Option<Duration>) -> Option<SleepOffsetBounds> {
    let lower = read(Bound::AtMost)?;
    let upper = read(Bound::AtLeast)?;
    SleepOffsetBounds::new(lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npu::gpu::RenderNode;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    struct Fixture {
        _root: tempfile::TempDir,
        drm: PathBuf,
        device: PathBuf,
        boot: PathBuf,
        node: RenderNode,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let drm = root.path().join("class/drm");
            let device = root.path().join("devices/pci0000:00/0000:00:02.0");
            let driver = root.path().join("drivers/xe");
            let boot = root.path().join("boot_id");
            for directory in [
                drm.join("renderD128/power"),
                device.join("power"),
                driver.clone(),
            ] {
                std::fs::create_dir_all(directory).unwrap();
            }
            symlink(&device, drm.join("renderD128/device")).unwrap();
            symlink(&driver, device.join("driver")).unwrap();
            for (name, value) in [
                ("vendor", "0x8086\n"),
                ("device", "0x64a0\n"),
                ("power/control", "auto\n"),
                ("power/runtime_status", "suspended\n"),
                ("power/runtime_active_time", "100\n"),
                ("power/runtime_suspended_time", "200\n"),
            ] {
                std::fs::write(device.join(name), value).unwrap();
            }
            std::fs::write(
                drm.join("renderD128/power/runtime_suspended_time"),
                "9999\n",
            )
            .unwrap();
            std::fs::write(&boot, "01234567-89ab-cdef-0123-456789abcdef\n").unwrap();
            Self {
                _root: root,
                drm,
                device,
                boot,
                node: RenderNode {
                    name: "renderD128".into(),
                    pci: "0000:00:02.0".into(),
                    vendor: "0x8086".into(),
                    device: "0x64a0".into(),
                },
            }
        }
    }

    #[test]
    fn reader_uses_the_identitys_canonical_pci_power_directory() {
        let fixture = Fixture::new();
        let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
        let observation = reader.sample().unwrap();
        let sample = observation.view();
        assert_eq!(sample.active_ms, Some(100));
        assert_eq!(sample.suspended_ms, Some(200));
        assert_eq!(sample.control, [Some("auto"); 2]);
        assert_eq!(sample.status, [Some("suspended"); 2]);
        assert_eq!(sample.binding, [Some(reader.expected()); 2]);
        assert_eq!(
            reader.expected().canonical_device,
            fixture.device.to_str().unwrap()
        );
        assert!(sample.read_window[0] <= sample.read_window[1]);
    }

    #[test]
    fn live_clock_reader_returns_ordered_bounds_without_asserting_sleep() {
        assert!(sleep_bounds().is_some());
    }

    #[test]
    fn regular_file_cannot_stand_in_for_the_bound_driver_directory() {
        let fixture = Fixture::new();
        let replacement = fixture._root.path().join("not-a-driver");
        std::fs::write(&replacement, "xe").unwrap();
        std::fs::remove_file(fixture.device.join("driver")).unwrap();
        symlink(replacement, fixture.device.join("driver")).unwrap();
        assert!(Reader::new(&fixture.drm, &fixture.boot, &fixture.node).is_err());
    }

    #[test]
    fn capture_reads_real_endpoints_inside_one_outer_bracket() {
        use std::cell::RefCell;
        let fixture = Fixture::new();
        let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
        let trace = RefCell::new(Vec::new());
        let mut times = [Duration::from_secs(2), Duration::from_secs(3)].into_iter();
        let observation = reader
            .capture_with(
                || {
                    trace.borrow_mut().push("clock".to_owned());
                    times.next().unwrap()
                },
                |path| {
                    trace
                        .borrow_mut()
                        .push(path.file_name().unwrap().to_str().unwrap().to_owned());
                    let value = std::fs::read_to_string(path);
                    if path.ends_with("runtime_suspended_time") {
                        std::fs::write(fixture.device.join("power/control"), "on\n").unwrap();
                        std::fs::write(fixture.device.join("power/runtime_status"), "active\n")
                            .unwrap();
                    }
                    value
                },
            )
            .unwrap();
        assert_eq!(
            trace.into_inner(),
            [
                "clock",
                "vendor",
                "device",
                "boot_id",
                "control",
                "runtime_status",
                "runtime_active_time",
                "runtime_suspended_time",
                "runtime_status",
                "control",
                "vendor",
                "device",
                "boot_id",
                "clock"
            ]
        );
        assert_eq!(observation.view().control, [Some("auto"), Some("on")]);
        assert_eq!(
            observation.view().status,
            [Some("suspended"), Some("active")]
        );
        assert_eq!(
            observation.view().read_window,
            [Duration::from_secs(2), Duration::from_secs(3)]
        );
    }

    fn change_binding(fixture: &Fixture, field: usize) {
        match field {
            0 => std::fs::write(fixture.device.join("vendor"), "0x1234\n").unwrap(),
            1 => std::fs::write(fixture.device.join("device"), "0x5678\n").unwrap(),
            2 => std::fs::write(&fixture.boot, "01234567-89ab-cdef-0123-456789abcdee\n").unwrap(),
            3 => {
                let other = fixture._root.path().join("other-drivers/xe");
                std::fs::create_dir_all(&other).unwrap();
                std::fs::remove_file(fixture.device.join("driver")).unwrap();
                symlink(other, fixture.device.join("driver")).unwrap();
            }
            4 => {
                let other = fixture._root.path().join("other-devices/0000:00:02.0");
                std::fs::create_dir_all(&other).unwrap();
                for name in ["vendor", "device"] {
                    std::fs::copy(fixture.device.join(name), other.join(name)).unwrap();
                }
                symlink(
                    fixture.device.join("driver").canonicalize().unwrap(),
                    other.join("driver"),
                )
                .unwrap();
                std::fs::remove_file(fixture.drm.join("renderD128/device")).unwrap();
                symlink(other, fixture.drm.join("renderD128/device")).unwrap();
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn rebinding_each_component_before_or_during_capture_refuses() {
        for field in 0..5 {
            for during in [false, true] {
                let fixture = Fixture::new();
                let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
                if !during {
                    change_binding(&fixture, field);
                }
                let error = reader
                    .capture_with(
                        || Duration::ZERO,
                        |path| {
                            let value = std::fs::read_to_string(path);
                            if during && path.ends_with("runtime_suspended_time") {
                                change_binding(&fixture, field);
                            }
                            value
                        },
                    )
                    .unwrap_err();
                assert_eq!(
                    error,
                    if during {
                        "device binding changed after counters"
                    } else {
                        "device binding changed before counters"
                    },
                    "field {field}"
                );
            }
        }
    }

    #[test]
    fn missing_read_at_any_endpoint_is_not_a_fabricated_observation() {
        for missing in 0..12 {
            let fixture = Fixture::new();
            let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
            let mut calls = 0;
            let result = reader.capture_with(
                || Duration::ZERO,
                |path| {
                    let fail = calls == missing;
                    calls += 1;
                    if fail {
                        Err(io::Error::new(io::ErrorKind::PermissionDenied, "fixture"))
                    } else {
                        std::fs::read_to_string(path)
                    }
                },
            );
            assert!(result.is_err(), "read {missing}");
            assert_eq!(calls, missing + 1);
        }
    }

    #[test]
    fn malformed_or_missing_counters_are_not_zero() {
        for name in ["runtime_active_time", "runtime_suspended_time"] {
            for value in [
                "",
                "+1",
                "-1",
                "1.0",
                "0x2",
                "18446744073710",
                "18446744073709551616",
            ] {
                let fixture = Fixture::new();
                let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
                std::fs::write(fixture.device.join("power").join(name), value).unwrap();
                assert!(reader.sample().is_err(), "{name} {value}");
            }
        }
    }

    #[test]
    fn unchanged_bad_posture_is_preserved_for_witness_refusal() {
        let fixture = Fixture::new();
        let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
        for status in [
            "suspending",
            "resuming",
            "error",
            "unsupported",
            "",
            "SUSPENDED",
        ] {
            std::fs::write(fixture.device.join("power/runtime_status"), status).unwrap();
            std::fs::write(fixture.device.join("power/control"), "on").unwrap();
            let sample = reader.sample().unwrap();
            assert_eq!(sample.view().status, [Some(status); 2]);
            assert_eq!(sample.view().control, [Some("on"); 2]);
        }
    }

    #[test]
    fn identity_disagreement_and_path_like_render_names_refuse_at_bind() {
        let fixture = Fixture::new();
        for field in 0..3 {
            let mut node = fixture.node.clone();
            match field {
                0 => node.pci = "0000:00:03.0".into(),
                1 => node.vendor = "0x1234".into(),
                2 => node.device = "0x5678".into(),
                _ => unreachable!(),
            }
            assert!(Reader::new(&fixture.drm, &fixture.boot, &node).is_err());
        }
        for name in [
            "",
            "renderD",
            "renderD/128",
            "renderD../128",
            "/renderD128",
            "card0",
        ] {
            let mut node = fixture.node.clone();
            node.name = name.into();
            assert!(Reader::new(&fixture.drm, &fixture.boot, &node).is_err());
        }
    }

    #[test]
    fn malformed_pci_and_boot_identifiers_refuse_at_bind() {
        for (file, values) in [
            ("vendor", vec!["", "8086", "0xgggg", "0x80860"]),
            ("device", vec!["", "64a0", "0xgggg", "0x64a00"]),
            (
                "boot_id",
                vec![
                    "",
                    "old-boot",
                    "01234567-89ab-cdef-0123-456789abcde",
                    "01234567-89ab-cdef-0123-456789abcdeg",
                ],
            ),
        ] {
            for value in values {
                let fixture = Fixture::new();
                let path = if file == "boot_id" {
                    fixture.boot.clone()
                } else {
                    fixture.device.join(file)
                };
                std::fs::write(path, value).unwrap();
                assert!(Reader::new(&fixture.drm, &fixture.boot, &fixture.node).is_err());
            }
        }
    }

    #[test]
    fn reversed_capture_clock_is_rejected() {
        let fixture = Fixture::new();
        let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
        let mut times = [Duration::from_secs(2), Duration::from_secs(1)].into_iter();
        assert_eq!(
            reader
                .capture_with(|| times.next().unwrap(), |p| std::fs::read_to_string(p))
                .unwrap_err(),
            "reversed observation bracket"
        );
    }

    #[test]
    fn owned_observations_feed_the_existing_witness_without_rebaselining() {
        use super::super::gpu_reliability_witness_tests::{
            validate_runtime_witness, CounterGrowth,
        };
        let fixture = Fixture::new();
        let reader = Reader::new(&fixture.drm, &fixture.boot, &fixture.node).unwrap();
        let observations: [Observation; 4] = std::array::from_fn(|i| {
            for (name, value) in [
                (
                    "runtime_status",
                    if i == 0 || i == 3 {
                        "active".to_owned()
                    } else {
                        "suspended".to_owned()
                    },
                ),
                ("runtime_active_time", [100, 105, 105, 110][i].to_string()),
                (
                    "runtime_suspended_time",
                    [1000, 1005, 1010, 1015][i].to_string(),
                ),
            ] {
                std::fs::write(fixture.device.join("power").join(name), value).unwrap();
            }
            let mut times = [
                Duration::from_millis(i as u64 * 10),
                Duration::from_millis(i as u64 * 10 + 1),
            ]
            .into_iter();
            reader
                .capture_with(|| times.next().unwrap(), |p| std::fs::read_to_string(p))
                .unwrap()
        });
        let views = observations.each_ref().map(Observation::view);
        let clock = SleepOffsetBounds::new(Duration::from_secs(20), Duration::from_secs(20));
        assert_eq!(
            validate_runtime_witness(reader.expected(), &views, clock, clock),
            Ok(CounterGrowth {
                lower_ms: 4,
                upper_ms: 6
            })
        );
        assert_eq!(views[0].status, [Some("active"); 2]);
        assert_eq!(views[1].status, [Some("suspended"); 2]);
        assert_eq!(views[0].suspended_ms, Some(1000));
    }

    #[test]
    fn sleep_reader_uses_lower_then_upper_and_propagates_missing_or_reversed_bounds() {
        use super::super::gpu_reliability_clock_tests::proves_system_sleep;
        let mut calls = Vec::new();
        let bounds = sleep_bounds_with(|bound| {
            calls.push(bound);
            Some(match bound {
                Bound::AtMost => Duration::from_millis(20),
                Bound::AtLeast => Duration::from_millis(21),
            })
        });
        assert_eq!(calls.len(), 2);
        assert!(matches!(calls[0], Bound::AtMost));
        assert!(matches!(calls[1], Bound::AtLeast));
        let later = SleepOffsetBounds::new(Duration::from_millis(23), Duration::from_millis(24));
        assert!(proves_system_sleep(bounds, later));
        for pair in [
            [None, Some(Duration::ZERO)],
            [Some(Duration::ZERO), None],
            [
                Some(Duration::from_millis(2)),
                Some(Duration::from_millis(1)),
            ],
        ] {
            let mut reads = pair.into_iter();
            assert!(sleep_bounds_with(|_| reads.next().unwrap()).is_none());
        }
    }
}
