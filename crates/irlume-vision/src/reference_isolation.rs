// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Build and environment checks for the non-shippable CPU reference (ADR-0022).

/// Refuse every spelling of the ordinary-build EP escape, even an empty value.
///
/// # Errors
/// Returns the fixed refusal when the variable is present, including non-UTF8.
pub(crate) fn require_clean_environment() -> Result<(), &'static str> {
    if std::env::var_os("IRLUME_TEST_ALLOW_UNCERTIFIED_EP").is_some() {
        Err("evidence reference refuses IRLUME_TEST_ALLOW_UNCERTIFIED_EP")
    } else {
        Ok(())
    }
}

#[cfg(not(feature = "onnx"))]
compile_error!("irlume evidence reference refused: requires onnx and its LiteRT reference");

#[cfg(any(
    feature = "cuda",
    feature = "openvino",
    feature = "coreml",
    feature = "tensorrt"
))]
compile_error!("irlume evidence reference refused: ORT execution-provider feature");

// Cargo features are local to each package. A caller can enable ort/cuda
// directly or through another dependency without setting our cuda feature.
// Observe ort's actual public exports, not a second copy of its feature flags.
#[cfg(feature = "onnx")]
mod ort_features {
    #![forbid(ambiguous_glob_imports)]

    mod absent {
        pub use core::convert::Infallible as CoreML;
        pub use core::convert::Infallible as OpenVINO;
        pub use core::convert::Infallible as TensorRT;
        pub use core::convert::Infallible as CUDA;
    }

    // Both imports must remain globs: an explicit import or a local item
    // would shadow the other name instead of refusing the build.
    // Pinned ort 2.0.0-rc.13 gates these exports individually in src/ep/mod.rs:
    // https://github.com/pykeio/ort/blob/002f41a8e175eac7f6695ff361d2e51a50874c48/src/ep/mod.rs
    use absent::*;
    use ort::ep::*;

    // CPU is always exported. Any forbidden export makes its name ambiguous,
    // including features unified by a downstream normal dependency.
    const _: Option<(CPU, CUDA, TensorRT, OpenVINO, CoreML)> = None;
}
