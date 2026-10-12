// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Synthetic cache-contract checks. No OpenVINO Core, models or GPU is opened.

use super::*;

fn observation(
    requested: &str,
    expected: CacheProvenance,
    core_dir: &str,
    compiled_dir: &str,
    loaded: &str,
    performance: &str,
    precision: &str,
) -> Result<CacheObservation, String> {
    read_cache_observation(requested, expected, core_dir.to_owned(), |key| {
        Ok(match key {
            "CACHE_DIR" => compiled_dir,
            "LOADED_FROM_CACHE" => loaded,
            "PERFORMANCE_HINT" => performance,
            "INFERENCE_PRECISION_HINT" => precision,
            other => panic!("unexpected property {other}"),
        }
        .to_owned())
    })
}

#[test]
fn gpu_cache_flag_accepts_exact_yes_and_no_only() {
    assert_eq!(parse_loaded_from_cache("YES"), Ok(true));
    assert_eq!(parse_loaded_from_cache("NO"), Ok(false));
    for invalid in [
        "", "yes", "no", "Yes", "No", "true", "false", "TRUE", "FALSE", "1", "0", " YES", "NO ",
        "YES\n", "\tNO", "YES NO", "NO YES", "YES,NO", "xYES", "NOx", "YES\0",
    ] {
        assert!(parse_loaded_from_cache(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn gpu_cache_valid_bypass_miss_and_hit_keep_owned_readbacks() {
    for (dir, expected, loaded) in [
        ("", CacheProvenance::Bypass, "NO"),
        ("/owned/cache", CacheProvenance::Miss, "NO"),
        ("/owned/cache", CacheProvenance::Hit, "YES"),
    ] {
        assert_eq!(
            observation(dir, expected, dir, dir, loaded, "LATENCY", "f16"),
            Ok(CacheObservation {
                core_cache_dir: dir.into(),
                compiled_cache_dir: dir.into(),
                loaded_from_cache: loaded == "YES",
            })
        );
    }
}

#[test]
fn gpu_cache_bypass_refuses_import_or_nonempty_directory() {
    for (core, compiled, loaded) in [
        ("", "", "YES"),
        ("/identity/warmup", "", "NO"),
        ("", "/identity/warmup", "NO"),
        (".", ".", "NO"),
    ] {
        assert!(observation(
            "",
            CacheProvenance::Bypass,
            core,
            compiled,
            loaded,
            "LATENCY",
            "f16"
        )
        .is_err());
    }
}

#[test]
fn gpu_cache_directory_requires_both_exact_readbacks() {
    for (core, compiled) in [
        ("", "/owned/cache"),
        ("/other", "/owned/cache"),
        ("/owned/cache", ""),
        ("/owned/cache", "/other"),
        ("/owned/cache", "/owned/cache/"),
    ] {
        assert!(observation(
            "/owned/cache",
            CacheProvenance::Miss,
            core,
            compiled,
            "NO",
            "LATENCY",
            "f16"
        )
        .is_err());
    }
}

#[test]
fn gpu_cache_required_hit_refuses_no_and_first_miss_refuses_yes() {
    for (expected, flag) in [(CacheProvenance::Hit, "NO"), (CacheProvenance::Miss, "YES")] {
        assert!(observation(
            "/owned/cache",
            expected,
            "/owned/cache",
            "/owned/cache",
            flag,
            "LATENCY",
            "f16"
        )
        .is_err());
    }
}

#[test]
fn gpu_cache_unknown_getter_flag_never_counts_as_no() {
    for flag in ["", "no", "false", "0", "NO ", "NO YES"] {
        assert!(observation("", CacheProvenance::Bypass, "", "", flag, "LATENCY", "f16").is_err());
    }
}

#[test]
fn gpu_cache_every_compiled_getter_error_refuses() {
    for failed_key in [
        "CACHE_DIR",
        "LOADED_FROM_CACHE",
        "PERFORMANCE_HINT",
        "INFERENCE_PRECISION_HINT",
    ] {
        let result = read_cache_observation("", CacheProvenance::Bypass, String::new(), |key| {
            if key == failed_key {
                return Err("getter unavailable".into());
            }
            Ok(match key {
                "CACHE_DIR" => "",
                "LOADED_FROM_CACHE" => "NO",
                "PERFORMANCE_HINT" => "LATENCY",
                "INFERENCE_PRECISION_HINT" => "f16",
                other => panic!("unexpected property {other}"),
            }
            .into())
        });
        let error = result.unwrap_err();
        assert!(error.contains(failed_key), "{error}");
        assert!(error.contains("getter unavailable"), "{error}");
    }
}

#[test]
fn gpu_cache_core_getter_error_and_mismatch_refuse() {
    let result: Result<Option<String>, String> =
        cache_observation_gate(Some(CacheProvenance::Bypass), |_| {
            Err("Core getter failed".into())
        });
    assert_eq!(result, Err("Core getter failed".into()));
    assert!(require_cache_property("Core CACHE_DIR", "/warmup", "").is_err());
    assert!(require_cache_property("Core CACHE_DIR", "", "/owned/cache").is_err());
    assert!(require_cache_property("Core CACHE_DIR", "", "").is_ok());
}

#[test]
fn gpu_cache_compiled_fixed_configuration_must_match_exactly() {
    for (performance, precision) in [
        ("THROUGHPUT", "f16"),
        ("latency", "f16"),
        ("LATENCY ", "f16"),
        ("LATENCY", "f32"),
        ("LATENCY", "F16"),
        ("LATENCY", "f16 "),
    ] {
        assert!(observation(
            "",
            CacheProvenance::Bypass,
            "",
            "",
            "NO",
            performance,
            precision
        )
        .is_err());
    }
}

#[test]
fn gpu_cache_wrong_provenance_mode_refuses() {
    for (dir, expected) in [
        ("", CacheProvenance::Miss),
        ("", CacheProvenance::Hit),
        ("/owned/cache", CacheProvenance::Bypass),
    ] {
        assert!(observation(dir, expected, dir, dir, "NO", "LATENCY", "f16").is_err());
    }
}

#[test]
fn gpu_cache_observed_path_requires_explicit_existing_utf8_directory() {
    use std::os::unix::ffi::OsStringExt;
    let owned = tempfile::tempdir().unwrap();
    assert_eq!(
        cache_path(CacheMode::Disabled, CacheProvenance::Bypass).unwrap(),
        Path::new("")
    );
    for expected in [CacheProvenance::Miss, CacheProvenance::Hit] {
        assert_eq!(
            cache_path(CacheMode::Directory(owned.path()), expected).unwrap(),
            owned.path()
        );
        assert!(cache_path(CacheMode::Disabled, expected).is_err());
    }
    assert!(cache_path(CacheMode::Directory(owned.path()), CacheProvenance::Bypass).is_err());
    let file = owned.path().join("cache.bin");
    std::fs::write(&file, b"synthetic").unwrap();
    let non_utf8 = owned.path().join(std::ffi::OsString::from_vec(vec![0xff]));
    std::fs::create_dir(&non_utf8).unwrap();
    for path in [
        Path::new(""),
        Path::new("."),
        Path::new("relative"),
        Path::new("/nul\0"),
        file.as_path(),
        owned.path().join("missing").as_path(),
        non_utf8.as_path(),
    ] {
        assert!(
            cache_path(CacheMode::Directory(path), CacheProvenance::Miss).is_err(),
            "{path:?}"
        );
    }
}

#[test]
fn gpu_cache_assignment_keeps_exact_legacy_device_acceptance() {
    for valid in ["GPU", "GPU.0", " \nGPU.0\t"] {
        assert_eq!(
            validate_gpu_assignment("GPU.0", valid).unwrap(),
            valid.trim()
        );
    }
    for invalid in [
        "",
        "CPU",
        "GPU.1",
        "AUTO",
        "HETERO:GPU,CPU",
        "MULTI:GPU",
        "GPU GPU.0",
    ] {
        assert!(
            validate_gpu_assignment("GPU.0", invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn gpu_cache_compile_keeps_real_fixed_batch_refusals() {
    let shape = super::super::fixed_batch_shape;
    assert_eq!(
        shape(&[None, Some(3), Some(112), Some(112)]).unwrap(),
        vec![1, 3, 112, 112]
    );
    for invalid in [
        vec![],
        vec![Some(2)],
        vec![Some(1), None],
        vec![Some(1), Some(0)],
    ] {
        assert!(shape(&invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn gpu_cache_legacy_signature_and_real_common_gate_do_not_observe() {
    type LegacyCompile = fn(
        &mut GpuPlatform,
        &Path,
        &[u8],
    ) -> Result<(Box<dyn super::super::Infer>, String), String>;
    let _: LegacyCompile = GpuPlatform::compile;
    let result: Result<Option<CacheObservation>, String> = cache_observation_gate(None, |_| {
        panic!("legacy compile must never invoke a cache observer")
    });
    assert_eq!(result, Ok(None));
    let mut observed = 0;
    let result = cache_observation_gate(Some(CacheProvenance::Hit), |expected| {
        observed += 1;
        Ok::<_, String>(expected)
    });
    assert_eq!(result, Ok(Some(CacheProvenance::Hit)));
    assert_eq!(observed, 1);
}

#[test]
fn gpu_cache_observed_entry_has_separate_test_only_signature() {
    type ObservedCompile =
        fn(
            &mut GpuPlatform,
            CacheMode<'_>,
            CacheProvenance,
            &[u8],
        ) -> Result<(Box<dyn super::super::Infer>, String, CacheObservation), String>;
    let _: ObservedCompile = GpuPlatform::compile_with_cache_observation;
}
