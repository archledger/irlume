// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;

const ESCAPE: &str = "IRLUME_TEST_ALLOW_UNCERTIFIED_EP";
const REFUSAL: &str = "evidence reference refuses IRLUME_TEST_ALLOW_UNCERTIFIED_EP";
const CHILD: &str = "IRLUME_TEST_REFERENCE_CHILD";

#[test]
fn escape_presence_precedes_ort_work() {
    let test = "onnx::reference_isolation_tests::escape_presence_precedes_ort_work";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        if std::env::var_os("IRLUME_TEST_REFERENCE_CACHED").is_some() {
            ORT_VERDICT.set(Ok(())).unwrap();
        }
        let error = ensure_ort_resolvable().unwrap_err().to_string();
        assert!(error.contains(REFUSAL), "{error}");
        let error = runtime_resolution().1.unwrap_err();
        assert!(error.contains(REFUSAL), "{error}");
        let error = Embedder::load_from_memory(&[]).err().unwrap().to_string();
        assert!(error.contains(REFUSAL), "{error}");
        return;
    }
    for value in [
        OsString::from(""),
        OsString::from("0"),
        OsString::from("1"),
        OsString::from("  "),
        OsString::from("false"),
        OsString::from_vec(vec![0xff]),
    ] {
        for cached in [false, true] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", test, "--nocapture"])
                .env(CHILD, test)
                .env(ESCAPE, &value)
                .env_remove("IRLUME_TEST_REFERENCE_CACHED")
                .env("ORT_DYLIB_PATH", "/irlume-test/no-native-runtime.so");
            if cached {
                command.env("IRLUME_TEST_REFERENCE_CACHED", "1");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "child failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
    }
}

#[test]
fn pinned_native_reference_executes_only_on_default_cpu() {
    const TEST: &str =
        "onnx::reference_isolation_tests::pinned_native_reference_executes_only_on_default_cpu";
    if std::env::var(CHILD).as_deref() != Ok(TEST) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, TEST)
            .env_remove(ESCAPE)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "native CPU child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    ensure_ort_resolvable().expect("the pinned CPU runtime is a required test prerequisite");
    assert_eq!(onnx_runtime_version().as_deref(), Some("1.28.1"));
    let environment = ort::environment::Environment::current().unwrap();
    let cpus: Vec<_> = environment
        .devices()
        .filter(|device| {
            device.ep().is_ok_and(|name| name == "CPUExecutionProvider")
                && device.ep_vendor().is_ok_and(|name| name == "Microsoft")
                && matches!(device.hardware_device().ty(), ort::memory::DeviceType::CPU)
        })
        .collect();
    assert_eq!(cpus.len(), 1, "one exact default CPU device is required");
    eprintln!("reference device: CPUExecutionProvider / Microsoft / CPU");

    // Synthetic ONNX IR8/opset13 graph: one float32[1] input X, constant
    // B=[1], and Add(X, B) -> Y. No image, biometric input or model weights.
    const ADD: &[u8] = &[
        8, 8, 58, 80, 10, 14, 10, 1, 88, 10, 1, 66, 18, 1, 89, 34, 3, 65, 100, 100, 18, 13, 114,
        101, 102, 101, 114, 101, 110, 99, 101, 45, 97, 100, 100, 42, 13, 8, 1, 16, 1, 34, 4, 0, 0,
        128, 63, 66, 1, 66, 90, 15, 10, 1, 88, 18, 10, 10, 8, 8, 1, 18, 4, 10, 2, 8, 1, 98, 15, 10,
        1, 89, 18, 10, 10, 8, 8, 1, 18, 4, 10, 2, 8, 1, 66, 2, 16, 13,
    ];
    let directory = tempfile::tempdir().unwrap();
    let mut session = session_options(&SMALL_POOL)
        .unwrap()
        .with_profiling(directory.path().join("cpu-reference"))
        .unwrap()
        .commit_from_memory(ADD)
        .unwrap();
    let input = Tensor::from_array(([1usize], vec![2.0f32])).unwrap();
    {
        let outputs = session.run(ort::inputs![input]).unwrap();
        assert_eq!(outputs[0].try_extract_tensor::<f32>().unwrap().1, &[3.0]);
    }
    let profile = session.end_profiling().unwrap();
    let events: serde_json::Value =
        serde_json::from_slice(&std::fs::read(profile).unwrap()).unwrap();
    let mut kernels = 0;
    for event in events.as_array().unwrap() {
        if event["cat"] == "Node"
            && event["name"]
                .as_str()
                .is_some_and(|name| name.ends_with("_kernel_time"))
        {
            assert_eq!(event["args"]["provider"], "CPUExecutionProvider");
            kernels += 1;
        }
    }
    assert!(kernels > 0, "the profile must record an executed CPU node");
}
