// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;

#[test]
fn escape_presence_precedes_tflite_work() {
    const TEST: &str = "tflite::reference_isolation_tests::escape_presence_precedes_tflite_work";
    const CHILD: &str = "IRLUME_TEST_REFERENCE_CHILD";
    const REFUSAL: &str = "evidence reference refuses IRLUME_TEST_ALLOW_UNCERTIFIED_EP";
    if std::env::var(CHILD).as_deref() == Ok(TEST) {
        if let Some(path) = std::env::var_os("IRLUME_TEST_REFERENCE_TFLITE_FIXTURE") {
            // Seed a successful cache without changing this child's escape
            // environment or creating an interpreter. The production getter
            // must refuse even though the native handle is already cached.
            let library = Library::from_path(Path::new(&path)).unwrap();
            assert!(LIB.set(library).is_ok());
        }
        let error = tflite_runtime().err().unwrap().to_string();
        assert!(error.contains(REFUSAL), "{error}");
        let model = irlume_common::HashedModel::new(Vec::new());
        let pin = model.sha256().to_owned();
        let error = TfliteSession::from_pinned_model_with_runtime(model, &pin, 1, || {
            panic!("an injected runtime must not bypass reference isolation")
        })
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains(REFUSAL), "{error}");
        let error = TfliteSession::from_pinned_bytes(&[], &pin, 1)
            .err()
            .unwrap()
            .to_string();
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
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, TEST)
                .env("IRLUME_TEST_ALLOW_UNCERTIFIED_EP", &value)
                .env("IRLUME_TFLITE_LIB", "/irlume-test/no-native-runtime.so")
                .env_remove("IRLUME_TEST_REFERENCE_TFLITE_FIXTURE");
            if cached {
                command.env(
                    "IRLUME_TEST_REFERENCE_TFLITE_FIXTURE",
                    std::env::var_os(TFLITE_LIB_ENV)
                        .expect("the pinned LiteRT runtime is a required cache-test fixture"),
                );
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
