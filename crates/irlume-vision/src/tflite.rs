// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Native TFLite/LiteRT runtime plumbing (#295): run Google's `.tflite`
//! artifacts unconverted, byte-for-byte as published and sha256-pinned.
//!
//! Shape mirrors the ort integration: the C library is dlopen'd at runtime
//! from an explicit, auditable path (env override, then the packaged
//! locations), and ABSENCE IS AN ANSWER, not a failure: a caller gets a
//! typed error naming what was tried, and the stage that wanted the model
//! refuses gracefully while everything else keeps working. The crate's own
//! `discovery::discover()` is deliberately NOT used: it falls back to bare
//! soname loads that let the dynamic linker pick up whatever
//! `libtensorflow-lite.so` happens to be on the search path, and a root
//! daemon loads code only from paths it chose.
//!
//! The security boundary is unchanged from the ONNX side: TensorFlow's own
//! threat model treats an untrusted model as untrusted code, so nothing
//! here loads a model that was not pinned by sha256 first, and
//! [`TfliteSession::from_pinned_bytes`] takes the VERIFIED BYTES themselves
//! so the checked buffer and the loaded buffer can never diverge (the same
//! one-buffer rule as `Engine::load_with_recognizer_bytes`).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use edgefirst_tflite::{Delegate, Interpreter, Library, Model};

/// Explicit runtime override for the TFLite C library path.
pub const TFLITE_LIB_ENV: &str = "IRLUME_TFLITE_LIB";

/// Packaged/system locations probed in order when the env override is
/// absent. First the bundled copy (every packaging lane installs it here,
/// like the bundled onnxruntime), then the distro-conventional locations.
pub const PACKAGED_TFLITE_LIBS: &[&str] = &[
    "/usr/share/irlume/tflite/libtensorflowlite_c.so",
    "/usr/lib64/libtensorflowlite_c.so",
    "/usr/lib/libtensorflowlite_c.so",
    "/usr/lib/x86_64-linux-gnu/libtensorflowlite_c.so",
];

/// Why the TFLite runtime is not available, with everything a `doctor`
/// surface needs to say so usefully.
#[derive(Debug, thiserror::Error)]
pub enum TfliteUnavailable {
    /// The explicit override was set but did not load. Named separately
    /// because the fix ("your IRLUME_TFLITE_LIB points at a bad library")
    /// differs from "install the runtime".
    #[error("IRLUME_TFLITE_LIB={path}: {source}")]
    OverrideFailed {
        path: String,
        source: edgefirst_tflite::Error,
    },
    /// No override, and no candidate path held a loadable library.
    #[error("no TFLite runtime: none of {tried:?} loaded (install the irlume tflite runtime package, or set IRLUME_TFLITE_LIB)")]
    NotFound { tried: Vec<PathBuf> },
}

/// The candidate paths the resolver will try, in order, as a VALUE: the
/// decision is a pure function of the override and which files exist, so
/// the policy is testable without ever dlopen-ing anything (and a candidate
/// list is what `doctor` prints when nothing loads).
pub fn tflite_lib_candidates(
    env_override: Option<&str>,
    exists: impl Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    // An explicit override is the WHOLE list: falling through a broken
    // override to a packaged copy would mask the operator's mistake and run
    // a library they did not choose.
    if let Some(p) = env_override.filter(|p| !p.trim().is_empty()) {
        return vec![PathBuf::from(p)];
    }
    PACKAGED_TFLITE_LIBS
        .iter()
        .map(PathBuf::from)
        .filter(|p| exists(p))
        .collect()
}

/// The process-wide runtime handle, loaded once on first success.
///
/// Only SUCCESS is cached: a failed resolution re-runs on the next call, so
/// installing the runtime (or fixing the override) works without a daemon
/// restart of whatever probing surface asked first. dlopen attempts on a
/// handful of explicit paths are cheap.
pub fn tflite_runtime() -> Result<&'static Library, TfliteUnavailable> {
    static LIB: OnceLock<Library> = OnceLock::new();
    if let Some(lib) = LIB.get() {
        return Ok(lib);
    }
    let env = std::env::var(TFLITE_LIB_ENV).ok();
    if let Some(path) = env.as_deref().filter(|p| !p.trim().is_empty()) {
        let lib = Library::from_path(path).map_err(|source| TfliteUnavailable::OverrideFailed {
            path: path.into(),
            source,
        })?;
        return Ok(LIB.get_or_init(|| lib));
    }
    let tried = tflite_lib_candidates(None, |p| p.exists());
    for p in &tried {
        if let Ok(lib) = Library::from_path(p) {
            return Ok(LIB.get_or_init(|| lib));
        }
    }
    Err(TfliteUnavailable::NotFound {
        tried: if tried.is_empty() {
            PACKAGED_TFLITE_LIBS.iter().map(PathBuf::from).collect()
        } else {
            tried
        },
    })
}

/// One loaded, allocation-ready `.tflite` model with a single input tensor.
///
/// Deliberately smoke-level for #295 stage 1: enough to load pinned bytes,
/// push one f32 tensor through, and read every output. The full-range
/// BlazeFace decoder (stage 2) builds on this rather than widening it.
///
/// FIELD ORDER IS LOAD-BEARING. The TFLite C contract
/// (`TfLiteModelCreate` docs) requires the model buffer to stay alive and
/// unmodified for the lifetime of every interpreter created from it, but
/// the crate's `InterpreterBuilder::build(&model)` returns an interpreter
/// that does NOT hold the model (an upstream soundness gap this wrapper
/// papers over). Owning both, interpreter first, gives the interpreter's
/// Drop the model it still references; reordering these fields is a
/// use-after-free.
pub struct TfliteSession {
    interp: Interpreter<'static>,
    _model: Model<'static>,
}

impl TfliteSession {
    /// Build a session from model BYTES the caller has already verified
    /// against a pin. Takes bytes, not a path, so the digest that was
    /// checked and the model that runs are the same buffer.
    ///
    /// `threads` caps CPU threads for the interpreter; XNNPACK is applied
    /// explicitly (the C API does not auto-apply it), so inference speed
    /// does not depend on how the shared library was built.
    pub fn from_pinned_bytes(bytes: &[u8], threads: i32) -> irlume_common::Result<Self> {
        let lib = tflite_runtime().map_err(err)?;
        let model = Model::from_bytes(lib, bytes.to_vec()).map_err(err)?;
        let xnnpack = Delegate::xnnpack(lib, threads).map_err(err)?;
        let mut interp = Interpreter::builder(lib)
            .map_err(err)?
            .num_threads(threads)
            .delegate(xnnpack)
            .build(&model)
            .map_err(err)?;
        interp.allocate_tensors().map_err(err)?;
        Ok(Self {
            interp,
            _model: model,
        })
    }

    /// Shape of the single input tensor.
    pub fn input_shape(&self) -> irlume_common::Result<Vec<usize>> {
        let inputs = self.interp.inputs().map_err(err)?;
        let t = inputs
            .first()
            .ok_or_else(|| err_str("model has no input tensor"))?;
        t.shape().map_err(err)
    }

    /// Run one f32 input tensor through the model and return every output
    /// as `(shape, data)`. The input length must match the input shape's
    /// element count; refusing here beats a silent partial write.
    pub fn run_f32(&mut self, input: &[f32]) -> irlume_common::Result<Vec<(Vec<usize>, Vec<f32>)>> {
        {
            let mut inputs = self.interp.inputs_mut().map_err(err)?;
            let t = inputs
                .first_mut()
                .ok_or_else(|| err_str("model has no input tensor"))?;
            let want = t.volume().map_err(err)?;
            if want != input.len() {
                return Err(err_str(format!(
                    "input length {} does not match model input {want}",
                    input.len()
                )));
            }
            t.copy_from_slice(input).map_err(err)?;
        }
        self.interp.invoke().map_err(err)?;
        let outputs = self.interp.outputs().map_err(err)?;
        let mut out = Vec::with_capacity(outputs.len());
        for t in &outputs {
            out.push((
                t.shape().map_err(err)?,
                t.as_slice::<f32>().map_err(err)?.to_vec(),
            ));
        }
        Ok(out)
    }
}

fn err(e: impl std::fmt::Display) -> irlume_common::Error {
    irlume_common::Error::Hardware(format!("tflite: {e}"))
}

fn err_str(s: impl Into<String>) -> irlume_common::Error {
    irlume_common::Error::Hardware(format!("tflite: {}", s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_is_the_whole_candidate_list_even_when_it_does_not_exist() {
        // Falling through a broken override to a packaged copy would run a
        // library the operator did not choose; the override must win alone.
        let c = tflite_lib_candidates(Some("/nonexistent/lib.so"), |_| true);
        assert_eq!(c, vec![PathBuf::from("/nonexistent/lib.so")]);
        // Empty/whitespace override reads as unset (the ort resolver's rule:
        // ORT_DYLIB_PATH="" is unset, and this resolver matches it).
        let c = tflite_lib_candidates(Some("  "), |p| p == Path::new(PACKAGED_TFLITE_LIBS[1]));
        assert_eq!(c, vec![PathBuf::from(PACKAGED_TFLITE_LIBS[1])]);
    }

    /// End-to-end smoke over the REAL runtime and the REAL pinned artifact:
    /// full-range BlazeFace bytes verified against the #295 pin, loaded,
    /// invoked on a zero tensor, output shapes asserted. Self-skips (loudly)
    /// when the library or model is absent, which is every CI runner; the
    /// container/local validation lanes run it via
    /// `IRLUME_TFLITE_LIB=<libtensorflowlite_c.so>` and
    /// `IRLUME_TFLITE_TEST_MODEL=<blaze_face_full_range.tflite>`.
    #[test]
    fn pinned_full_range_blaze_runs_end_to_end() {
        const FULL_RANGE_SHA256: &str =
            "3698b18f063835bc609069ef052228fbe86d9c9a6dc8dcb7c7c2d69aed2b181b";
        let Ok(model_path) = std::env::var("IRLUME_TFLITE_TEST_MODEL") else {
            eprintln!("skipping: IRLUME_TFLITE_TEST_MODEL not set");
            return;
        };
        if std::env::var(TFLITE_LIB_ENV).is_err() {
            eprintln!("skipping: {TFLITE_LIB_ENV} not set");
            return;
        }
        let bytes = std::fs::read(&model_path).expect("read test model");
        // The pin IS the flow under test: bytes are verified, then the SAME
        // buffer is loaded.
        assert_eq!(
            irlume_common::thirdparty::sha256_hex(&bytes),
            FULL_RANGE_SHA256,
            "{model_path}: not the pinned full-range artifact"
        );
        let mut s = TfliteSession::from_pinned_bytes(&bytes, 2).expect("session");
        let shape = s.input_shape().expect("input shape");
        assert_eq!(shape, vec![1, 192, 192, 3], "measured contract (#295)");
        let out = s.run_f32(&vec![0.0f32; 192 * 192 * 3]).expect("invoke");
        let mut shapes: Vec<Vec<usize>> = out.iter().map(|(s, _)| s.clone()).collect();
        shapes.sort();
        assert_eq!(
            shapes,
            vec![vec![1, 2304, 1], vec![1, 2304, 16]],
            "regressor + logit tensors per the measured contract"
        );
        // A wrong-length input is refused before any write.
        assert!(s.run_f32(&[0.0f32; 7]).is_err());
    }

    #[test]
    fn without_an_override_only_existing_packaged_paths_are_candidates() {
        let c = tflite_lib_candidates(None, |p| p == Path::new(PACKAGED_TFLITE_LIBS[0]));
        assert_eq!(c, vec![PathBuf::from(PACKAGED_TFLITE_LIBS[0])]);
        let none = tflite_lib_candidates(None, |_| false);
        assert!(none.is_empty(), "no file, no candidate: {none:?}");
    }
}
