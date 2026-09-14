// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Observe the bytes actually passed to the C API, not Model::data's source view.

use super::{Library, TfliteSession, TFLITE_LIB_ENV};
use std::ffi::CStr;
use std::path::Path;

fn counter(library: &Library, name: &CStr) -> usize {
    // SAFETY: The task-owned C shim defines each named zero-argument getter
    // with uintptr_t/size_t return type. The Library keeps that shim mapped.
    unsafe {
        let getter = library
            .as_sys()
            .library()
            .get::<unsafe extern "C" fn() -> usize>(name.to_bytes_with_nul())
            .expect("test shim exports the requested counter");
        getter()
    }
}

fn real_runtime_buffer_check(model_env: &str, expected_pin: &str) {
    let runtime = std::env::var(TFLITE_LIB_ENV).expect("explicit packaged runtime is required");
    let runtime = Path::new(&runtime).canonicalize().expect("runtime path");
    let model_path = std::env::var(model_env).expect("explicit pinned model is required");
    let model = irlume_common::HashedModel::new(std::fs::read(model_path).expect("pinned model"));
    assert_eq!(
        model.sha256(),
        expected_pin,
        "test must use the approved artifact"
    );
    super::model_buffer::require_inline_buffers(model.bytes()).expect("approved model is inline");
    let original_pointer = model.bytes().as_ptr() as usize;
    let original_length = model.bytes().len();

    let temporary = tempfile::tempdir().expect("test-only shim directory");
    let source = temporary.path().join("buffer_spy.c");
    let shim = temporary.path().join("buffer_spy.so");
    std::fs::write(
        &source,
        include_str!("../../tests/fixtures/tflite_buffer_spy.c"),
    )
    .expect("write test shim");
    let runtime_string = runtime.to_str().expect("test runtime path is UTF-8");
    let define = format!(
        "-DIRLUME_REAL_TFLITE={}",
        serde_json::to_string(runtime_string).expect("escape C path literal")
    );
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = std::process::Command::new(compiler)
        .args([
            "-shared", "-fPIC", "-std=c11", "-Wall", "-Wextra", "-Werror",
        ])
        .arg(define)
        .arg(&source)
        // dlsym on the shim also resolves required symbols from this dependency.
        // Only ModelCreate and the two deletion calls are intercepted.
        .arg("-Wl,--no-as-needed")
        .arg(&runtime)
        .arg(format!(
            "-Wl,-rpath,{}",
            runtime.parent().expect("absolute library parent").display()
        ))
        .args(["-ldl", "-o"])
        .arg(&shim)
        .output()
        .expect("C compiler is required by this hardware test");
    assert!(
        output.status.success(),
        "test shim compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Production sessions borrow a process-lifetime library. This isolated test
    // retains one shim handle until process exit to exercise that same lifetime.
    let library = Box::leak(Box::new(
        Library::from_path(&shim).expect("real-runtime shim"),
    ));
    let mut session =
        TfliteSession::from_pinned_model_with_runtime(model, expected_pin, 2, || Ok(library))
            .expect("approved model through production admission and interpreter creation");
    assert_eq!(counter(library, c"irlume_test_model_creations"), 1);
    assert!(
        counter(library, c"irlume_test_model_pointer") == original_pointer,
        "C API must receive the exact SHA-verified allocation, not a rewritten buffer"
    );
    assert_eq!(
        counter(library, c"irlume_test_model_length"),
        original_length
    );

    let shape = session.input_shape().expect("Float32 input contract");
    let output = session
        .run_f32(&vec![0.0; shape.iter().product()])
        .expect("real runtime inference");
    assert!(!output.is_empty());
    assert!(output
        .iter()
        .all(|(_, values)| values.iter().all(|v| v.is_finite())));
    assert!(
        session.run_f32(&[0.0; 7]).is_err(),
        "wrong input length is refused"
    );
    assert_eq!(counter(library, c"irlume_test_model_deleted"), 0);
    drop(session);
    let interpreter_deleted = counter(library, c"irlume_test_interpreter_deleted");
    let model_deleted = counter(library, c"irlume_test_model_deleted");
    assert!(
        interpreter_deleted > 0 && model_deleted > interpreter_deleted,
        "interpreter deletion must finish before its backing model is deleted"
    );
}

#[test]
#[ignore = "requires packaged TFLite, pinned mesh, and a C compiler"]
fn pinned_mesh_reaches_c_api_without_rewriting() {
    real_runtime_buffer_check(
        "IRLUME_TFLITE_MESH_TEST_MODEL",
        crate::onnx::LANDMARKER_MESH_TFLITE_SHA256,
    );
}

#[test]
#[ignore = "requires packaged TFLite, pinned full-range model, and a C compiler"]
fn pinned_full_range_reaches_c_api_without_rewriting() {
    real_runtime_buffer_check(
        "IRLUME_TFLITE_TEST_MODEL",
        crate::blaze_full::FULL_RANGE_BLAZE_SHA256,
    );
}
