// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Diagnostic object-lifetime comparison, never retained-model qualification.

#![cfg(test)]

use super::gpu_reliability_clock_tests::excludes_material_system_sleep;
use super::gpu_reliability_reader_tests::{sleep_bounds, Observation, Reader};
use crate::npu::gpu;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

fn settings(name: &str, seconds: &str) -> Result<(String, Duration), String> {
    let digits = name
        .strip_prefix("renderD")
        .ok_or("explicit render node required")?;
    if digits.is_empty() || !digits.bytes().all(|v| v.is_ascii_digit()) {
        return Err("invalid render node name".into());
    }
    if seconds.is_empty() || !seconds.bytes().all(|v| v.is_ascii_digit()) {
        return Err("explicit integer duration required".into());
    }
    let seconds = seconds
        .parse::<u64>()
        .ok()
        .filter(|v| (1..=120).contains(v))
        .ok_or("duration must be 1 through 120 seconds")?;
    Ok((name.to_owned(), Duration::from_secs(seconds)))
}

fn lifetime_mode(value: &str) -> Result<bool, &'static str> {
    match value {
        "baseline" => Ok(false),
        "lifetime" => Ok(true),
        _ => Err("explicit baseline or lifetime mode required"),
    }
}

fn device_handles() -> Result<Vec<String>, String> {
    let mut handles = Vec::new();
    for fd in std::fs::read_dir("/proc/self/fd").map_err(|e| e.to_string())? {
        let fd = fd.map_err(|e| e.to_string())?;
        match std::fs::read_link(fd.path()) {
            Ok(path) if path.starts_with("/dev/dri") || path.starts_with("/dev/accel") => {
                handles.push(path.to_string_lossy().into_owned());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    handles.sort();
    Ok(handles)
}

fn observe_stage(
    reader: &mut Reader,
    output: &Path,
    name: &str,
    duration: Duration,
) -> Result<(), String> {
    let handles_before = device_handles()?;
    let clock_start = sleep_bounds();
    let start = Instant::now();
    let deadline = start + duration;
    let mut observations = Vec::<Observation>::new();
    let mut error = None;
    // Keep the console quiet throughout the window: rendering a per-sample
    // progress stream would itself add desktop GPU activity to this comparison.
    loop {
        match reader.sample() {
            Ok(sample) => {
                let auto = sample.view().control == [Some("auto"); 2];
                observations.push(sample);
                if !auto {
                    error = Some("control changed away from AUTO".to_owned());
                    break;
                }
            }
            Err(why) => {
                error = Some(why);
                break;
            }
        }
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        std::thread::sleep(left.min(Duration::from_millis(200)));
    }
    let clock_end = sleep_bounds();
    let elapsed = start.elapsed();
    let sleep_excluded = excludes_material_system_sleep(clock_start, clock_end);
    if !sleep_excluded && error.is_none() {
        error = Some("material system sleep not excluded".into());
    }
    let samples: Vec<_> = observations
        .iter()
        .map(|sample| {
            let view = sample.view();
            serde_json::json!({"control": view.control, "status": view.status,
            "monotonic_start_ns": view.read_window[0].as_nanos(),
            "monotonic_end_ns": view.read_window[1].as_nanos(),
            "active_ms": view.active_ms, "suspended_ms": view.suspended_ms})
        })
        .collect();
    let suspended = observations
        .iter()
        .filter(|s| s.view().status == [Some("suspended"); 2])
        .count();
    let delta = observations
        .first()
        .zip(observations.last())
        .and_then(|(first, last)| {
            let a = first.view();
            let b = last.view();
            Some([
                b.active_ms?.checked_sub(a.active_ms?)?,
                b.suspended_ms?.checked_sub(a.suspended_ms?)?,
            ])
        });
    let binding = reader.expected();
    let report = serde_json::json!({"diagnostic_only": true, "qualification": false,
        "stage": name, "pid": std::process::id(), "requested_seconds": duration.as_secs(),
        "elapsed_ns": elapsed.as_nanos(), "sample_count": observations.len(),
        "stable_suspended_samples": suspended, "active_suspended_delta_ms": delta,
        "sleep_start": format!("{clock_start:?}"), "sleep_end": format!("{clock_end:?}"),
        "system_sleep_excluded": sleep_excluded, "error": error,
        "own_device_handles_before": handles_before, "own_device_handles_after": device_handles()?,
        "binding": {"canonical_device": binding.canonical_device, "pci": binding.pci,
            "vendor": binding.vendor, "device": binding.device, "driver": binding.driver, "boot_id": binding.boot_id},
        "binding_verified_for_recorded_samples": true, "samples": samples});
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output.join(format!("{name}.json")))
        .map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(file, &report).map_err(|e| e.to_string())?;
    println!("GPU_PM_DIAGNOSTIC stage={name} samples={} stable_suspended={suspended} delta_ms={delta:?} system_sleep_excluded={sleep_excluded} error={error:?} qualification=false", observations.len());
    if let Some(error) = error {
        return Err(error);
    }
    Ok(())
}

fn diagnostic_node(name: &str) -> gpu::RenderNode {
    let device = Path::new("/sys/class/drm")
        .join(name)
        .join("device")
        .canonicalize()
        .unwrap();
    gpu::RenderNode {
        name: name.to_owned(),
        pci: device.file_name().unwrap().to_str().unwrap().to_owned(),
        vendor: std::fs::read_to_string(device.join("vendor"))
            .unwrap()
            .trim()
            .to_ascii_lowercase(),
        device: std::fs::read_to_string(device.join("device"))
            .unwrap()
            .trim()
            .to_ascii_lowercase(),
    }
}

/// Compare application object lifetimes. Dropping a request here deliberately
/// disqualifies this experiment from the retained-request qualification protocol.
#[test]
#[ignore = "hardware: explicit PM diagnostic settings, private output directory and current reference; no system sleep or PM writes"]
fn gpu_pm_hw_lifetime_diagnostic() {
    use super::gpu_groundwork_tests::{
        hw_cpu_cascade, hw_selection, recognizer_bytes, report_hw_identity,
    };
    use super::gpu_reliability_hardware_tests::read_reference;
    let (name, duration) = settings(
        &std::env::var("IRLUME_GPU_PM_RENDER_NODE").unwrap(),
        &std::env::var("IRLUME_GPU_PM_IDLE_SECONDS").unwrap(),
    )
    .unwrap();
    let lifetime = lifetime_mode(&std::env::var("IRLUME_GPU_PM_MODE").unwrap()).unwrap();
    let output =
        std::env::var_os("IRLUME_GPU_PM_OUTPUT_DIR").expect("explicit private output directory");
    let output = Path::new(&output);
    let metadata = std::fs::symlink_metadata(output).unwrap();
    // SAFETY: geteuid takes no arguments and queries this process's effective UID.
    let uid = unsafe { libc::geteuid() };
    assert!(output.is_absolute() && metadata.is_dir() && metadata.uid() == uid);
    assert_eq!(
        metadata.permissions().mode() & 0o077,
        0,
        "private output required"
    );
    assert!(
        std::fs::read_dir(output).unwrap().next().is_none(),
        "preserve earlier receipts"
    );
    let reference_path = std::env::var_os("IRLUME_GPU_RELIABILITY_REFERENCE").unwrap();
    let reference = read_reference(Path::new(&reference_path), None).unwrap();
    let bytes = recognizer_bytes();
    let (mut cpu, _cascade) = hw_cpu_cascade();
    assert_eq!(cpu.cpu_reference_digest().unwrap(), reference.cpu_reference);
    let node = diagnostic_node(&name);
    let mut reader = Reader::new(
        Path::new("/sys/class/drm"),
        Path::new("/proc/sys/kernel/random/boot_id"),
        &node,
    )
    .unwrap();
    assert!(
        device_handles().unwrap().is_empty(),
        "CPU baseline must have no owned accelerator handles"
    );
    observe_stage(&mut reader, output, "a_cpu_only", duration).unwrap();
    if !lifetime {
        assert_eq!(cpu.cpu_reference_digest().unwrap(), reference.cpu_reference);
        println!("GPU_PM_BASELINE_COMPLETE provider_opened=false counted_endurance_calls=0 qualification=false");
        return;
    }

    let mut platform =
        gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default()).unwrap();
    report_hw_identity("PM lifetime diagnostic", platform.identity());
    assert_eq!(
        platform.identity().render_node,
        node,
        "bind the pre-open observations to the selected GPU"
    );
    assert_eq!(platform.identity().digest(), reference.identity);
    observe_stage(&mut reader, output, "b_platform_only", duration).unwrap();
    platform.still_loaded_as_hashed().unwrap();

    let (mut model, assignment, _cache) = platform
        .compile_with_cache_observation(
            gpu::CacheMode::Disabled,
            gpu::CacheProvenance::Bypass,
            &bytes,
        )
        .unwrap();
    assert_eq!(assignment, "GPU.0");
    let mut originals = Vec::new();
    for k in 0..4 {
        let input = super::super::npu_reference::chip(k);
        let result = model.infer(&input).unwrap();
        assert_eq!(result.len(), crate::EMBED_DIM);
        assert!(result.iter().all(|v| v.is_finite()));
        let raw: Vec<_> = result.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(irlume_common::sha256_hex(&raw), reference.gpu_bits[k]);
        originals.push((
            input,
            result.into_iter().map(f32::to_bits).collect::<Vec<_>>(),
        ));
    }
    observe_stage(&mut reader, output, "c_retained_request", duration).unwrap();
    for (input, bits) in &originals {
        let result = model.infer(input).unwrap();
        assert_eq!(result.len(), bits.len());
        assert!(result
            .iter()
            .zip(bits)
            .all(|(v, b)| v.is_finite() && v.to_bits() == *b));
    }
    platform.still_loaded_as_hashed().unwrap();
    drop(model);
    observe_stage(&mut reader, output, "d_request_dropped", duration).unwrap();
    platform.still_loaded_as_hashed().unwrap();
    drop(platform);
    // Core destruction is not shared-library unloading. Global runtime state can
    // survive this phase; a separate parent must also observe AFTER process exit.
    observe_stage(
        &mut reader,
        output,
        "e_platform_dropped_libraries_retained",
        duration,
    )
    .unwrap();
    assert_eq!(cpu.cpu_reference_digest().unwrap(), reference.cpu_reference);
    println!("GPU_PM_DIAGNOSTIC_COMPLETE recognizer_compiles=1 reference_calls=8 counted_endurance_calls=0 qualification=false");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn diagnostic_requires_explicit_bounded_duration_and_safe_render_name() {
        assert_eq!(
            settings("renderD128", "60"),
            Ok(("renderD128".into(), Duration::from_secs(60)))
        );
        for seconds in [
            "",
            "0",
            "121",
            "+1",
            " 60",
            "1.5",
            "-1",
            "18446744073709551616",
        ] {
            assert!(settings("renderD128", seconds).is_err(), "{seconds:?}");
        }
        for name in [
            "",
            "renderD",
            "card0",
            "/renderD128",
            "renderD../128",
            "renderD١",
        ] {
            assert!(settings(name, "60").is_err(), "{name:?}");
        }
        assert_eq!(lifetime_mode("baseline"), Ok(false));
        assert_eq!(lifetime_mode("lifetime"), Ok(true));
        for mode in ["", "auto", "BASELINE", "lifetime "] {
            assert!(lifetime_mode(mode).is_err());
        }
    }

    #[test]
    fn pm_diagnostic_is_explicit_and_outside_the_ordinary_gpu_sweep() {
        let control = "onnx::gpu_tests::gpu_pm_diagnostic_tests::gpu_pm_hw_lifetime_diagnostic";
        let list = |args: &[&str]| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(args)
                .env_remove("IRLUME_GPU_PM_MODE")
                .env_remove("IRLUME_GPU_PM_OUTPUT_DIR")
                .env_remove("IRLUME_GPU_PM_RENDER_NODE")
                .env_remove("IRLUME_GPU_PM_IDLE_SECONDS")
                .env_remove("IRLUME_GPU_RELIABILITY_REFERENCE")
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            list(&["--list", "--ignored", "--exact", control]),
            [control]
        );
        let ordinary = list(&["--list", "--ignored", "gpu_hw_"]);
        assert_eq!(ordinary.len(), 5);
        assert!(!ordinary.iter().any(|v| v == control));
        assert!(
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/NPU.md"))
                .contains(control)
        );
    }
}
