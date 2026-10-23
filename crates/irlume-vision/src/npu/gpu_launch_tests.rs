// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{validate, CheckedGpuLaunchInputs, GpuLaunchInputError, NeoCachePolicy, POLICY_ID};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

type Entry<'a> = (&'a OsStr, &'a OsStr);

fn entry<'a>(name: &'a [u8], value: &'a [u8]) -> Entry<'a> {
    (OsStr::from_bytes(name), OsStr::from_bytes(value))
}

fn cache_off() -> Entry<'static> {
    entry(b"NEO_CACHE_PERSISTENT", b"0")
}

fn check(entries: &[Entry<'_>]) -> Result<CheckedGpuLaunchInputs, GpuLaunchInputError> {
    validate(OsStr::new(POLICY_ID), entries)
}

fn assert_checked(checked: CheckedGpuLaunchInputs) {
    assert_eq!(checked.policy_id(), POLICY_ID);
    assert_eq!(checked.neo_cache_policy(), NeoCachePolicy::Disabled);
}

fn assert_error(entries: &[Entry<'_>], expected: GpuLaunchInputError) {
    assert_eq!(check(entries), Err(expected));
}

fn assert_permutations(entries: &mut [Entry<'_>], expected: Option<GpuLaunchInputError>) {
    fn visit(entries: &mut [Entry<'_>], start: usize, expected: Option<GpuLaunchInputError>) {
        if start == entries.len() {
            match expected {
                Some(error) => assert_error(entries, error),
                None => assert_checked(check(entries).unwrap()),
            }
            return;
        }
        for index in start..entries.len() {
            entries.swap(start, index);
            visit(entries, start + 1, expected);
            entries.swap(start, index);
        }
    }
    visit(entries, 0, expected);
}

#[test]
fn minimal_candidate_declares_cache_off_without_authorizing_loading() {
    assert_checked(check(&[cache_off()]).unwrap());
    assert_eq!(
        crate::npu::runtime::admit_loading(),
        Err(crate::npu::CpuReason::LoadingNotAdmitted)
    );
    assert!(matches!(
        crate::npu::gpu::discover(&crate::npu::RuntimeSelection::Automatic),
        crate::npu::gpu::Discovery::NotAdmitted
    ));
    assert!(std::hint::black_box(crate::npu::CERTIFIED).is_empty());
    assert!(std::hint::black_box(crate::npu::gpu::certification::CERTIFIED).is_empty());
}

#[test]
fn optional_locales_accept_only_c_in_every_entry_order() {
    for locale in [b"LANG".as_slice(), b"LC_ALL"] {
        assert_permutations(&mut [cache_off(), entry(locale, b"C")], None);
    }
    assert_permutations(
        &mut [cache_off(), entry(b"LANG", b"C"), entry(b"LC_ALL", b"C")],
        None,
    );
}

#[test]
fn missing_cache_intent_is_not_inferred_from_optional_locales() {
    assert_error(&[], GpuLaunchInputError::MissingCacheIntent);
    for mut entries in [
        vec![entry(b"LANG", b"C")],
        vec![entry(b"LC_ALL", b"C")],
        vec![entry(b"LANG", b"C"), entry(b"LC_ALL", b"C")],
    ] {
        assert_permutations(&mut entries, Some(GpuLaunchInputError::MissingCacheIntent));
    }
}

#[test]
fn cache_value_requires_exact_ascii_zero_without_normalization() {
    for value in [
        b"".as_slice(),
        b"1",
        b"false",
        b"true",
        b"off",
        b"00",
        b" 0",
        b"0 ",
        b"0\n",
        b"\t0",
        b"0\0",
        b"\xff",
        b"\xc3\xa9",
    ] {
        assert_error(
            &[entry(b"NEO_CACHE_PERSISTENT", value)],
            GpuLaunchInputError::InvalidValue,
        );
    }
}

#[test]
fn each_optional_locale_rejects_nonexact_values() {
    for name in [b"LANG".as_slice(), b"LC_ALL"] {
        for value in [
            b"".as_slice(),
            b"c",
            b"C.UTF-8",
            b"POSIX",
            b"0",
            b" C",
            b"C ",
            b"C\n",
            b"C\0",
            b"\xff",
            b"\xc3\xa9",
        ] {
            assert_permutations(
                &mut [cache_off(), entry(name, value)],
                Some(GpuLaunchInputError::InvalidValue),
            );
        }
    }
}

#[test]
fn every_other_name_is_unsupported_even_with_an_empty_value() {
    for name in [
        "PATH",
        "HOME",
        "XDG_CACHE_HOME",
        "NEO_CACHE_DIR",
        "NEO_CACHE_MAX_SIZE",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_AUDIT",
        "GLIBC_TUNABLES",
        "ORT_DYLIB_PATH",
        "IRLUME_TFLITE_LIB",
        "OPENVINO_LIB_PATHS",
        "OPENCL_VENDOR_PATH",
        "OPENCL_LAYERS",
        "OPENCL_LAYER_PATH",
        "OCL_ICD_VENDORS",
        "OCL_ICD_FILENAMES",
        "OCL_ICD_ASSUME_ICD_EXTENSION",
        "ZE_ENABLE_ALT_DRIVERS",
        "ZE_AFFINITY_MASK",
        "ZES_ENABLE_SYSMAN",
        "LANGUAGE",
        "LC_CTYPE",
        "NEO_CACHE_PERSISTENT_EXTRA",
        "UNREVIEWED",
        "_",
    ] {
        for value in [b"".as_slice(), b"0", b"C", b"untrusted-value"] {
            assert_permutations(
                &mut [cache_off(), entry(name.as_bytes(), value)],
                Some(GpuLaunchInputError::UnsupportedName),
            );
        }
    }
}

#[test]
fn names_follow_the_exact_ascii_grammar() {
    for name in [
        b"".as_slice(),
        b"lang",
        b"Neo_CACHE_PERSISTENT",
        b"1NAME",
        b"NA-ME",
        b"N=ME",
        b" LANG",
        b"LANG ",
        b"A\tB",
        b"A\nB",
        b"A\0B",
        b"\xff",
        b"\xc3\xa9",
        b"A\x7f",
    ] {
        assert_permutations(
            &mut [cache_off(), entry(name, b"C")],
            Some(GpuLaunchInputError::MalformedName),
        );
    }
    for byte in 0_u8..=127 {
        let first = [byte];
        let expected = if byte.is_ascii_uppercase() || byte == b'_' {
            GpuLaunchInputError::UnsupportedName
        } else {
            GpuLaunchInputError::MalformedName
        };
        assert_error(&[cache_off(), entry(&first, b"")], expected);
        let following = [b'A', byte];
        let expected = if byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_' {
            GpuLaunchInputError::UnsupportedName
        } else {
            GpuLaunchInputError::MalformedName
        };
        assert_error(&[cache_off(), entry(&following, b"")], expected);
    }
}

#[test]
fn duplicate_names_refuse_equal_and_different_values() {
    for (name, allowed) in [
        (b"NEO_CACHE_PERSISTENT".as_slice(), b"0".as_slice()),
        (b"LANG", b"C"),
        (b"LC_ALL", b"C"),
        (b"UNSUPPORTED", b""),
    ] {
        for second in [allowed, b"different"] {
            assert_permutations(
                &mut [entry(name, allowed), entry(name, second)],
                Some(GpuLaunchInputError::DuplicateName),
            );
        }
    }
}

#[test]
fn bounds_are_raw_bytes_and_include_the_exact_limits() {
    let name_at_limit = [b'A'; 64];
    let name_over_limit = [b'A'; 65];
    assert_error(
        &[entry(&name_at_limit, b"")],
        GpuLaunchInputError::UnsupportedName,
    );
    assert_error(&[entry(&name_over_limit, b"")], GpuLaunchInputError::Bounds);
    let value_at_limit = [b'0'; 4096];
    let value_over_limit = [b'0'; 4097];
    assert_error(
        &[entry(b"NEO_CACHE_PERSISTENT", &value_at_limit)],
        GpuLaunchInputError::InvalidValue,
    );
    assert_error(
        &[entry(b"NEO_CACHE_PERSISTENT", &value_over_limit)],
        GpuLaunchInputError::Bounds,
    );
    let multibyte = "\u{00e9}".repeat(2049);
    assert_error(
        &[entry(b"LANG", multibyte.as_bytes())],
        GpuLaunchInputError::Bounds,
    );
    let names: Vec<OsString> = (0..17).map(|index| format!("KEY_{index}").into()).collect();
    let entries: Vec<Entry<'_>> = names
        .iter()
        .map(|name| (name.as_os_str(), OsStr::new("")))
        .collect();
    assert_error(&entries[..16], GpuLaunchInputError::UnsupportedName);
    assert_error(&entries, GpuLaunchInputError::Bounds);
}

#[test]
fn unknown_policy_wins_over_every_environment_error() {
    let long_value = [b'X'; 4097];
    let cases = [
        vec![cache_off()],
        vec![],
        vec![entry(b"bad", &long_value); 17],
        vec![entry(b"NEO_CACHE_PERSISTENT", &long_value)],
        vec![entry(b"bad", b"")],
        vec![entry(b"LANG", b"C"), entry(b"LANG", b"C")],
        vec![entry(b"PATH", b"")],
        vec![entry(b"LC_ALL", b"wrong")],
    ];
    for policy in [
        b"".as_slice(),
        b"gpu-candidate-inputs-v2",
        b"GPU-CANDIDATE-INPUTS-V1",
        b" gpu-candidate-inputs-v1",
        b"gpu-candidate-inputs-v1 ",
        b"gpu-candidate-inputs-v1\0",
        b"\xff",
    ] {
        for entries in &cases {
            assert_eq!(
                validate(OsStr::from_bytes(policy), entries),
                Err(GpuLaunchInputError::UnknownPolicy),
            );
        }
    }
}

#[test]
fn error_precedence_is_independent_of_entry_permutation() {
    // This order is the policy oracle, independent of the validator's logic.
    let long_value = [b'X'; 4097];
    let cases = [
        (
            GpuLaunchInputError::Bounds,
            vec![entry(b"NEO_CACHE_PERSISTENT", &long_value)],
        ),
        (GpuLaunchInputError::MalformedName, vec![entry(b"bad", b"")]),
        (
            GpuLaunchInputError::DuplicateName,
            vec![entry(b"LANG", b"C"), entry(b"LANG", b"C")],
        ),
        (
            GpuLaunchInputError::UnsupportedName,
            vec![entry(b"PATH", b"")],
        ),
        (
            GpuLaunchInputError::InvalidValue,
            vec![entry(b"LC_ALL", b"wrong")],
        ),
        (GpuLaunchInputError::MissingCacheIntent, vec![]),
    ];
    for (index, (expected, first)) in cases.iter().enumerate() {
        assert_permutations(&mut first.clone(), Some(*expected));
        for (_, second) in &cases[index + 1..] {
            let mut entries = first.clone();
            entries.extend_from_slice(second);
            assert_permutations(&mut entries, Some(*expected));
        }
    }
}

#[test]
fn errors_are_fixed_categories_without_raw_name_or_value_payloads() {
    fn detached<T: Copy + 'static>(value: T) -> T {
        value
    }
    let name = OsString::from("PRIVATE_INPUT_NAME");
    let value = OsString::from("PRIVATE_INPUT_VALUE");
    let error = detached(check(&[(name.as_os_str(), value.as_os_str())]).unwrap_err());
    drop(name);
    drop(value);
    assert_eq!(error, GpuLaunchInputError::UnsupportedName);
    assert_eq!(format!("{error:?}"), "UnsupportedName");
    // Exhaustive unit patterns prevent a raw payload from being added unnoticed.
    for (error, text) in [
        (GpuLaunchInputError::UnknownPolicy, "UnknownPolicy"),
        (GpuLaunchInputError::Bounds, "Bounds"),
        (GpuLaunchInputError::MalformedName, "MalformedName"),
        (GpuLaunchInputError::DuplicateName, "DuplicateName"),
        (GpuLaunchInputError::UnsupportedName, "UnsupportedName"),
        (GpuLaunchInputError::InvalidValue, "InvalidValue"),
        (
            GpuLaunchInputError::MissingCacheIntent,
            "MissingCacheIntent",
        ),
    ] {
        let unit_only = match error {
            GpuLaunchInputError::UnknownPolicy => "UnknownPolicy",
            GpuLaunchInputError::Bounds => "Bounds",
            GpuLaunchInputError::MalformedName => "MalformedName",
            GpuLaunchInputError::DuplicateName => "DuplicateName",
            GpuLaunchInputError::UnsupportedName => "UnsupportedName",
            GpuLaunchInputError::InvalidValue => "InvalidValue",
            GpuLaunchInputError::MissingCacheIntent => "MissingCacheIntent",
        };
        assert_eq!(unit_only, text);
        assert_eq!(format!("{error:?}"), text);
    }
}

#[test]
fn borrowed_inputs_are_unchanged_and_checked_output_retains_no_input_lifetime() {
    fn detached<T: Copy + 'static>(value: T) -> T {
        value
    }
    let checked = {
        let policy = OsString::from(POLICY_ID);
        let name = OsString::from("NEO_CACHE_PERSISTENT");
        let value = OsString::from("0");
        let entries = [(name.as_os_str(), value.as_os_str())];
        let checked = detached(validate(policy.as_os_str(), &entries).unwrap());
        assert_eq!(
            entries,
            [(OsStr::new("NEO_CACHE_PERSISTENT"), OsStr::new("0"))],
        );
        assert_eq!(policy, OsStr::new(POLICY_ID));
        checked
    };
    assert_checked(checked);
    assert!(!format!("{checked:?}").contains("NEO_CACHE_PERSISTENT"));
}

#[test]
fn candidate_checker_has_no_ambient_or_native_operations() {
    // Supplemental source boundary: behavioral tests above pass only borrowed
    // values. This check is not proof of a future launcher's confinement.
    let implementation = include_str!("gpu_launch.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    for forbidden in [
        "std::env",
        "std::fs",
        "std::process",
        "env::",
        "fs::",
        "process::",
        "openvino::",
        "openvino_sys::",
        "libloading",
        "libc::",
        "unsafe ",
        "extern ",
        "runtime::",
        "std::thread",
        "std::net",
        "include!(",
        "to_string_lossy",
        "to_os_string",
        "OsString",
        ".to_owned(",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "unexpected operation: {forbidden}",
        );
    }
}
