// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The ML pipeline: detect -> align -> embed. CPU-first ONNX via `ort`.
//!
//! Commercially-clean, GPL-3.0-compatible bill of materials (all permissive):
//!   * Detection:   YuNet  (MIT)      `face_detection_yunet_2023mar.onnx`
//!     bbox + 5 landmarks; ~1.6 ms @320x320 on a laptop CPU.
//!   * Recognition: AuraFace (Apache) `glintr100.onnx`, ResNet100/ArcFace,
//!     512-D embedding, 112x112 input, standard 5-point alignment.
//!
//! The weights ship inside the distro packages (installed to
//! /usr/share/irlume/models and loaded from disk at daemon start; a git clone
//! fetches them from the models-v1 release via scripts/fetch-models.sh). Do NOT swap
//! in InsightFace buffalo_l/antelopev2 or YuNet's bundled SCRFD: their weights
//! are non-commercial, which CONFLICTS with GPL's downstream-commercial freedom.

pub mod align;
#[cfg(feature = "tflite")]
pub mod blaze_full;
pub mod detect;
pub mod light;
pub mod moire;
#[cfg(feature = "tflite")]
pub mod tflite;

/// 5 facial landmarks (left eye, right eye, nose, left mouth, right mouth),
/// in pixel coordinates of the source frame. Output by the detector.
pub type Landmarks5 = [(f32, f32); 5];

/// A detected face.
#[derive(Clone)]
pub struct Detection {
    pub bbox: [f32; 4], // x1, y1, x2, y2
    pub score: f32,
    pub landmarks: Landmarks5,
}

/// A detection every consumer can do arithmetic on: finite box, score, and
/// keypoints. Model output is untrusted numerics, and Rust's saturating
/// float→int cast turns a NaN coordinate into pixel (0,0), so a NaN eye
/// landmark makes the glint cues sample the frame corner as if it were an eye
/// (measured: `examples/landmark_failure_probe.rs`, where it read a corner
/// hotspot as an open eye). Dropped at the source, because guarding every
/// consumer is the pattern that misses one.
pub fn detection_is_finite(d: &Detection) -> bool {
    d.bbox.iter().all(|v| v.is_finite())
        && d.score.is_finite()
        && d.landmarks
            .iter()
            .all(|&(x, y)| x.is_finite() && y.is_finite())
}

/// Approximate head orientation from the 5 landmarks, with no 3D model: a 2D
/// heuristic for a frontality gate (Windows Hello uses a ±15° head-orientation
/// step). It rejects clearly off-angle presentations; it is *not* degree-
/// calibrated. `yaw_asym` and `pitch_frac` are scale-invariant (ratios).
#[derive(Debug, Clone, Copy)]
pub struct HeadPose {
    /// Horizontal nose asymmetry between the eyes: `|d(nose,left_eye) -
    /// d(nose,right_eye)| / (sum)`. ~0 frontal, →1 turned left/right.
    pub yaw_asym: f32,
    /// SIGNED horizontal turn, for directional enrollment guidance. Computed in
    /// pure image space (nose x vs the eye-midpoint x, normalized by half the
    /// inter-eye span), so it's independent of which landmark index is labelled
    /// "left". Negative = the nose sits toward image-LEFT; positive = image-RIGHT.
    /// On a non-mirrored camera frame (irlume never flips the capture), nose-
    /// toward-image-left means the person is looking to THEIR OWN right. ~0 frontal.
    pub yaw_signed: f32,
    /// Nose's vertical position between the eye line and mouth line. ~0.5
    /// frontal. Verified against a live camera: SMALLER when looking UP (the
    /// nose tip swings up toward the eye line), LARGER when looking DOWN (the
    /// nose tip drops toward the mouth), the opposite of the naive reading.
    pub pitch_frac: f32,
}

/// Estimate [`HeadPose`] from landmarks `[left_eye, right_eye, nose, left_mouth,
/// right_mouth]`. Defaults to frontal (0.0 / 0.5) on degenerate geometry.
pub fn head_pose(lm: &Landmarks5) -> HeadPose {
    let (le, re, nose, lmth, rmth) = (lm[0], lm[1], lm[2], lm[3], lm[4]);
    let (dl, dr) = ((nose.0 - le.0).abs(), (re.0 - nose.0).abs());
    let yaw_asym = if dl + dr > 1e-3 {
        (dl - dr).abs() / (dl + dr)
    } else {
        0.0
    };
    // Signed yaw straight from image x, label-agnostic (uses the eye midpoint,
    // not "which eye is left"). Half the inter-eye span makes it ~unit-scaled.
    let eye_mid_x = (le.0 + re.0) / 2.0;
    let half_span = ((re.0 - le.0).abs() / 2.0).max(1e-3);
    let yaw_signed = (nose.0 - eye_mid_x) / half_span;
    let eye_y = (le.1 + re.1) / 2.0;
    let span = (lmth.1 + rmth.1) / 2.0 - eye_y;
    let pitch_frac = if span.abs() > 1e-3 {
        (nose.1 - eye_y) / span
    } else {
        0.5
    };
    HeadPose {
        yaw_asym,
        yaw_signed,
        pitch_frac,
    }
}

#[cfg(test)]
mod detection_finite_tests {
    use super::*;

    #[test]
    fn one_non_finite_field_anywhere_disqualifies_a_detection() {
        let good = Detection {
            bbox: [10.0, 10.0, 60.0, 70.0],
            score: 0.9,
            landmarks: [
                (20.0, 30.0),
                (50.0, 30.0),
                (35.0, 45.0),
                (25.0, 60.0),
                (45.0, 60.0),
            ],
        };
        assert!(detection_is_finite(&good));
        let mut bad_box = good.clone();
        bad_box.bbox[2] = f32::NAN;
        assert!(!detection_is_finite(&bad_box));
        let mut bad_score = good.clone();
        bad_score.score = f32::INFINITY;
        assert!(!detection_is_finite(&bad_score));
        // The case that motivated the guard: finite box and score, one NaN
        // eye. Downstream this samples pixel (0,0) as the eye.
        let mut bad_eye = good.clone();
        bad_eye.landmarks[1] = (f32::NAN, 30.0);
        assert!(!detection_is_finite(&bad_eye));
    }
}

#[cfg(test)]
mod head_pose_tests {
    use super::*;

    #[test]
    fn frontal_face_is_centered() {
        // ARCFACE reference geometry: nose centered between eyes, mid eye-mouth.
        let lm: Landmarks5 = [
            (20.0, 24.0),
            (44.0, 24.0),
            (32.0, 36.0),
            (24.0, 48.0),
            (40.0, 48.0),
        ];
        let p = head_pose(&lm);
        assert!(p.yaw_asym < 0.05, "yaw {}", p.yaw_asym);
        assert!((p.pitch_frac - 0.5).abs() < 0.05, "pitch {}", p.pitch_frac);
    }

    #[test]
    fn turned_head_raises_yaw_asym() {
        // Nose shifted toward the left eye (head turned) -> high asymmetry.
        let lm: Landmarks5 = [
            (20.0, 24.0),
            (44.0, 24.0),
            (25.0, 36.0),
            (24.0, 48.0),
            (40.0, 48.0),
        ];
        assert!(
            head_pose(&lm).yaw_asym > 0.35,
            "{}",
            head_pose(&lm).yaw_asym
        );
    }

    #[test]
    fn yaw_signed_tracks_nose_side() {
        // Eye midpoint x = 32. Nose toward image-LEFT (x=25 < 32) -> negative.
        let left: Landmarks5 = [
            (20.0, 24.0),
            (44.0, 24.0),
            (25.0, 36.0),
            (24.0, 48.0),
            (40.0, 48.0),
        ];
        assert!(
            head_pose(&left).yaw_signed < -0.3,
            "{}",
            head_pose(&left).yaw_signed
        );
        // Nose toward image-RIGHT (x=39 > 32) -> positive.
        let right: Landmarks5 = [
            (20.0, 24.0),
            (44.0, 24.0),
            (39.0, 36.0),
            (24.0, 48.0),
            (40.0, 48.0),
        ];
        assert!(
            head_pose(&right).yaw_signed > 0.3,
            "{}",
            head_pose(&right).yaw_signed
        );
        // Frontal (nose centered) -> ~0.
        let mid: Landmarks5 = [
            (20.0, 24.0),
            (44.0, 24.0),
            (32.0, 36.0),
            (24.0, 48.0),
            (40.0, 48.0),
        ];
        assert!(
            head_pose(&mid).yaw_signed.abs() < 0.05,
            "{}",
            head_pose(&mid).yaw_signed
        );
    }

    #[test]
    fn nose_toward_eyeline_lowers_pitch_frac() {
        // Nose risen toward the eye line = looking UP -> small pitch fraction.
        // (Live-verified: looking DOWN instead drives the nose toward the mouth
        // and raises pitch_frac; this geometry is the looking-UP case.)
        let lm: Landmarks5 = [
            (20.0, 24.0),
            (44.0, 24.0),
            (32.0, 28.0),
            (24.0, 48.0),
            (40.0, 48.0),
        ];
        assert!(
            head_pose(&lm).pitch_frac < 0.30,
            "{}",
            head_pose(&lm).pitch_frac
        );
    }
}

/// L2-normalized face embedding. 512 dims for AuraFace.
pub const EMBED_DIM: usize = 512;
pub type Embedding = [f32; EMBED_DIM];

#[cfg(feature = "onnx")]
mod onnx {
    use super::{Detection, Embedding, EMBED_DIM};
    use crate::align;
    use ort::session::{builder::GraphOptimizationLevel, Session};
    use ort::value::Tensor;

    fn err<E: std::fmt::Display>(e: E) -> irlume_common::Error {
        irlume_common::Error::Hardware(format!("onnx: {e}"))
    }

    /// Where the irlume packages install onnxruntime: Fedora/Copr first,
    /// then the Debian/Ubuntu universal .deb and PPA layout (their systemd
    /// override hands the path to the daemon only, so a bare CLI run needs
    /// this list; packaging/README.md records both).
    const PACKAGED_ORTS: &[&str] = irlume_common::PACKAGED_ORT_PATHS;

    /// The candidate the resolver would load, pure over its inputs so the
    /// selection is testable without touching the process environment: an
    /// explicit non-empty `ORT_DYLIB_PATH` wins, else the first packaged copy
    /// present. `None` means "ask the system loader". An EMPTY variable reads
    /// as unset, matching pinned ort's own treatment of it (#269 review).
    fn configured_ort(
        explicit: Option<&std::ffi::OsStr>,
        is_file: impl Fn(&std::path::Path) -> bool,
    ) -> Option<std::path::PathBuf> {
        if let Some(value) = explicit.filter(|value| !value.is_empty()) {
            return Some(value.into());
        }
        PACKAGED_ORTS
            .iter()
            .map(std::path::PathBuf::from)
            .find(|path| is_file(path))
    }

    /// Prove `name` (a path or a bare soname) is a loadable ONNX Runtime that
    /// provides the API level pinned ort will demand, with the loader's own
    /// words when it is not. On success, returns the runtime's version string.
    ///
    /// This CANNOT be delegated to `ort::init_from`: measured on 2026-08-04,
    /// a load failure inside ort parks the process in a futex exactly like
    /// the lazy path does (straced with `ORT_DYLIB_PATH=/etc/hostname`: the
    /// file opens, dlopen rejects it, then FUTEX_WAIT forever, no output), so
    /// the probe has to establish loadability first with its own dlopen. On
    /// success the handle is KEPT for the life of the process, deliberately:
    /// `ort` then reopens the same name (dlopen reference counting makes that
    /// cheap), the probed object and the used object cannot diverge, and
    /// unloading is what LeakSanitizer rightly complains about, since dlclose
    /// on a C++ runtime orphans the allocations its static initializers made
    /// (measured in CI: 80 bytes in 2 allocations from libonnxruntime's init
    /// under dlopen).
    ///
    /// The API-level floor is checked here for the same reason: handed a
    /// runtime below the floor, `ort::init_from` does not return. Measured on
    /// 2026-08-06 against onnxruntime 1.20.1 (#187): the calling thread
    /// parked in `futex_do_wait` with no output and no CPU, so the daemon
    /// answered every client "still starting" indefinitely while systemd
    /// showed it healthy. `GetApi` documents null as "this version is
    /// unsupported", so null IS the version answer, not a call failure.
    fn probe_runtime(name: &std::ffi::CStr) -> Result<String, String> {
        // SAFETY: dlopen/dlerror/dlsym/dlclose with valid NUL-terminated
        // strings; the handle is non-null when dlsym runs, retained on
        // success, and closed on the failures past it. The two OrtApiBase
        // calls go through `ort_sys`'s own declarations, so the signatures
        // match the ABI ort itself uses, and every returned pointer is
        // null-checked before it is read.
        unsafe {
            let handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if handle.is_null() {
                let why = libc::dlerror();
                let why = if why.is_null() {
                    "dlopen failed with no message".to_string()
                } else {
                    std::ffi::CStr::from_ptr(why).to_string_lossy().into_owned()
                };
                return Err(why);
            }
            let sym = libc::dlsym(handle, c"OrtGetApiBase".as_ptr());
            if sym.is_null() {
                // Where dlclose is right: a foreign library that will not be
                // used again. A future test exercising this path under
                // LeakSanitizer will see that library's own initializer
                // allocations; that is this close, not a defect in the probe.
                libc::dlclose(handle);
                return Err(
                    "the library loads but exports no OrtGetApiBase; it is not an \
                     ONNX Runtime"
                        .to_string(),
                );
            }
            let get_base: unsafe extern "system" fn() -> *const ort::sys::OrtApiBase =
                std::mem::transmute(sym);
            let base = get_base();
            if base.is_null() {
                libc::dlclose(handle);
                return Err(
                    "OrtGetApiBase returned null; the library is not a usable ONNX Runtime"
                        .to_string(),
                );
            }
            // Copied to an owned String while the library is still mapped:
            // the pointer aims into the library's own data.
            let version_ptr = ((*base).GetVersionString)();
            let version = if version_ptr.is_null() {
                "(unknown version)".to_string()
            } else {
                std::ffi::CStr::from_ptr(version_ptr)
                    .to_string_lossy()
                    .into_owned()
            };
            if ((*base).GetApi)(ort::MINOR_VERSION).is_null() {
                libc::dlclose(handle);
                return Err(format!(
                    "this is ONNX Runtime {version}, which does not provide API level {api} \
                     (first shipped in ONNX Runtime 1.{api}); irlume needs 1.{api} or newer",
                    api = ort::MINOR_VERSION
                ));
            }
            Ok(version)
        }
    }

    /// Probe, then hand the SAME name to pinned ort, which retains the handle
    /// in its own global. The probe has already established everything ort's
    /// own init would park on: the library loads, it is an ONNX Runtime, and
    /// it provides the pinned API level (ort re-checks that floor, but only
    /// ever against a runtime the probe passed). Measured 2026-08-06, #187:
    /// before the probe checked the floor, a below-floor runtime made this
    /// call park forever instead of returning.
    fn load_ort(path: &std::path::Path) -> Result<String, String> {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| format!("{} contains a NUL byte", path.display()))?;
        let version = probe_runtime(&name)
            .map_err(|why| format!("cannot load ONNX Runtime from {}: {why}", path.display()))?;
        ort::init_from(path).map(|_| version).map_err(|e| {
            format!(
                "cannot initialize ONNX Runtime from {}: {e}",
                path.display()
            )
        })
    }

    /// Settle the onnxruntime library BEFORE ort's lazy default path can park
    /// on it.
    ///
    /// `load-dynamic`'s failure mode for an unresolvable library is not an
    /// error: the loader walks its paths and the process parks forever in a
    /// futex with no output (straced on 2026-08-04, #266; sudo scrubbing
    /// `ORT_DYLIB_PATH` is the easy trigger, and the CLI's model commands hit
    /// it where the daemon's unit file does not). Loading explicitly through
    /// [`load_ort`] turns every failure into an error naming the fix. The
    /// environment is never written: mutating it here would be unsound once
    /// any other thread exists, and this crate's constructors are public API
    /// with no single-threaded guarantee.
    fn ensure_ort_resolvable() -> irlume_common::Result<()> {
        use std::sync::OnceLock;
        static VERDICT: OnceLock<Result<(), String>> = OnceLock::new();
        VERDICT
            .get_or_init(|| {
                let explicit = std::env::var_os("ORT_DYLIB_PATH");
                if let Some(path) = configured_ort(explicit.as_deref(), |p| p.is_file()) {
                    // An explicit path that is not a file gets the actionable
                    // message rather than a load error about a missing file.
                    if !path.is_file() {
                        return Err(format!(
                            "ORT_DYLIB_PATH points at {} which does not exist; the \
                             irlume packages install it at {} (Fedora) or {} \
                             (Debian/Ubuntu); sudo drops the variable, pass it with \
                             `sudo env ORT_DYLIB_PATH=...`",
                            path.display(),
                            PACKAGED_ORTS[0],
                            PACKAGED_ORTS[1]
                        ));
                    }
                    return load_ort(&path).map(|version| {
                        irlume_common::dlog!(
                            "onnxruntime {version} loaded from {}",
                            path.display()
                        );
                    });
                }
                // No explicit path, no packaged copy: ask the system loader,
                // through ort so acceptance and retention still apply.
                load_ort(std::path::Path::new("libonnxruntime.so"))
                    .map(|version| {
                        irlume_common::dlog!("onnxruntime {version} loaded via the system loader");
                    })
                    .map_err(|system_error| {
                        format!(
                            "libonnxruntime.so was not loadable (no ORT_DYLIB_PATH, nothing \
                             at {} or {}, and the system loader failed: {system_error}); \
                             install the irlume package's onnxruntime or set ORT_DYLIB_PATH",
                            PACKAGED_ORTS[0], PACKAGED_ORTS[1]
                        )
                    })
            })
            .clone()
            .map_err(irlume_common::Error::Hardware)
    }

    /// What the onnxruntime resolver would use in this process, for `irlume
    /// doctor`: the candidate (an explicit or packaged path, or the system
    /// loader when `None`) plus the probe's verdict on it, `Ok` carrying the
    /// runtime's own version string.
    ///
    /// A dlopen probe, not a full `ort` init: doctor must be able to report a
    /// broken runtime and move on, and `ort`'s global init is the code whose
    /// failure mode is a silent park (#187). dlopen of a runtime already
    /// loaded by this process is a reference-count bump, so calling this
    /// after models loaded costs nothing new.
    pub fn runtime_resolution() -> (Option<std::path::PathBuf>, Result<String, String>) {
        let explicit = std::env::var_os("ORT_DYLIB_PATH");
        let candidate = configured_ort(explicit.as_deref(), |p| p.is_file());
        let name = candidate
            .as_deref()
            .unwrap_or(std::path::Path::new("libonnxruntime.so"));
        let verdict = match std::ffi::CString::new(name.as_os_str().as_encoded_bytes()) {
            Ok(name) => probe_runtime(&name),
            Err(_) => Err(format!("{} contains a NUL byte", name.display())),
        };
        (candidate, verdict)
    }

    fn build(model: &[u8]) -> irlume_common::Result<Session> {
        ensure_ort_resolvable()?;
        #[allow(unused_mut)]
        let mut b = Session::builder().map_err(err)?;
        // Register a hardware execution provider if compiled in (cf. howrs).
        // These fall back to CPU if the EP can't initialize at runtime.
        #[cfg(feature = "cuda")]
        {
            b = b
                .with_execution_providers([
                    ort::execution_providers::CUDAExecutionProvider::default().build(),
                ])
                .map_err(err)?;
        }
        #[cfg(feature = "openvino")]
        {
            b = b
                .with_execution_providers([
                    ort::execution_providers::OpenVINOExecutionProvider::default().build(),
                ])
                .map_err(err)?;
        }
        b.with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(err)?
            .commit_from_memory(model)
            .map_err(err)
    }

    /// AuraFace embedder (ONNX). Loaded once in the daemon.
    pub struct Embedder {
        session: Session,
    }

    impl Embedder {
        pub fn load_from_memory(model: &[u8]) -> irlume_common::Result<Self> {
            Ok(Self {
                session: build(model)?,
            })
        }

        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Self::load_from_memory(&bytes)
        }

        /// Embed an already-aligned 112x112 RGB chip -> L2-normalized 512-D vector.
        ///
        /// Preprocessing MUST match AuraFace/InsightFace exactly or genuine pairs
        /// collapse (the "identical images score 0.6" trap): channel order per
        /// [`align::INPUT_IS_RGB`], (px-127.5)/128.0, NCHW; output L2-normalized.
        pub fn embed(&mut self, chip_rgb: &[u8]) -> irlume_common::Result<Embedding> {
            Ok(self.embed_with_norm(chip_rgb)?.0)
        }

        /// Test-time augmentation: embed the chip + its horizontal mirror, average,
        /// renormalize. Benchmarked on LFW to cut RGB false-rejects (~27% relative
        /// at thr 0.50; FRR@0.55 13.6%→9.5%) with FAR unchanged (≤1e-4). RGB PATH
        /// ONLY: on NIR it over-smooths the low-texture embedding (no EER gain,
        /// slightly worse at low FAR), so the IR path keeps plain `embed`.
        pub fn embed_tta(&mut self, chip_rgb: &[u8]) -> irlume_common::Result<Embedding> {
            let a = self.embed(chip_rgb)?;
            let b = self.embed(&crate::align::flip_h(chip_rgb))?;
            let mut out = [0.0f32; EMBED_DIM];
            for k in 0..EMBED_DIM {
                out[k] = a[k] + b[k];
            }
            l2_normalize(&mut out);
            Ok(out)
        }

        /// Embed AND return the PRE-normalization L2 norm of the raw feature: an
        /// AdaFace/MagFace-style quality proxy (clearer faces tend to produce
        /// larger feature norms; degraded/low-light faces smaller). The returned
        /// embedding is still L2-normalized; the norm is the quality signal for
        /// fusion weighting / low-quality gating. (AuraFace is ArcFace-trained, not
        /// AdaFace, so the norm↔quality correlation must be validated empirically.)
        pub fn embed_with_norm(
            &mut self,
            chip_rgb: &[u8],
        ) -> irlume_common::Result<(Embedding, f32)> {
            let data = align::preprocess_arcface(chip_rgb);
            let n = align::OUT_SIZE as i64;
            let tensor = Tensor::from_array(([1i64, 3, n, n], data)).map_err(err)?;
            // Positional input (single-input model); avoids needing the input name.
            let outputs = self.session.run(ort::inputs![tensor]).map_err(err)?;
            let (_shape, raw) = outputs[0].try_extract_tensor::<f32>().map_err(err)?;
            if raw.len() != EMBED_DIM {
                return Err(err(format!("expected {EMBED_DIM}-D, got {}", raw.len())));
            }
            let mut out = [0.0f32; EMBED_DIM];
            out.copy_from_slice(raw);
            let norm = out.iter().map(|x| x * x).sum::<f32>().sqrt();
            l2_normalize(&mut out);
            Ok((out, norm))
        }
    }

    /// Optional IR embedding adapter (512→512) applied to AuraFace IR embeddings
    /// in the dark path; output is L2-normalized. NONE ships by default since
    /// ADR-0004 (the former CBSR+Oulu-trained adapter carried research-only
    /// training data and worsened unseen identities); the default IR path is raw
    /// AuraFace + per-enrollment calibration. This loads only when a user supplies
    /// their own adapter via `--adapter` / `IRLUME_IR_ADAPTER`, and a residual
    /// form (out = x + k·A(x)) is the expected shape.
    pub struct Adapter {
        session: Session,
    }

    impl Adapter {
        pub fn load_from_memory(model: &[u8]) -> irlume_common::Result<Self> {
            Ok(Self {
                session: build(model)?,
            })
        }

        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Self::load_from_memory(&bytes)
        }

        /// Adapt one IR embedding -> adapted vector (already L2-normalized).
        pub fn apply(&mut self, emb: &[f32]) -> irlume_common::Result<Vec<f32>> {
            let tensor =
                Tensor::from_array(([1i64, emb.len() as i64], emb.to_vec())).map_err(err)?;
            let outputs = self.session.run(ort::inputs![tensor]).map_err(err)?;
            let (_shape, raw) = outputs[0].try_extract_tensor::<f32>().map_err(err)?;
            Ok(raw.to_vec())
        }
    }

    fn l2_normalize(v: &mut [f32]) {
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-12 {
            for x in v.iter_mut() {
                *x /= norm;
            }
        }
    }

    /// MediaPipe FaceMesh (`face_landmark.onnx`, Apache-2.0): dense facial
    /// landmarks. Used for passive blink liveness (eye-aspect-ratio, ADR-0002)
    /// and to refine a BlazeFace rescue box into 5 alignment points, never
    /// recognition. The shipped model is the 478-point (468 + iris)
    /// FaceLandmarker mesh at NHWC `[1,256,256,3]` (unlike the NCHW recognizer);
    /// the loader reads the input side from the model and accepts either
    /// generation (468 legacy or 478), returning landmarks in the input space
    /// plus a face-probability flag. RGB-trained; IR-grey performance is
    /// validated empirically (that's the open question the diagnostic answers).
    pub struct FaceMesh {
        session: Session,
        /// Square input side, read from the model: 192 for the legacy
        /// face_landmark, 256 for the face_landmarker-generation mesh.
        input: u32,
    }

    /// Legacy FaceMesh square input side (fallback when the model does not
    /// declare static input dims).
    pub const MESH_INPUT: u32 = 192;
    /// Number of dense landmarks in the legacy topology. The newer mesh emits
    /// 478 (the same 468 plus 10 iris points); both are accepted and the
    /// shared indices (EAR rings, nose, mouth corners) are identical.
    pub const MESH_N: usize = 468;
    /// Landmark count of the face_landmarker-generation mesh.
    pub const MESH_N_IRIS: usize = 478;

    impl FaceMesh {
        pub fn load_from_memory(model: &[u8]) -> irlume_common::Result<Self> {
            let session = build(model)?;
            // NHWC [1, side, side, 3]: take the declared H when static.
            let input = session
                .inputs()
                .first()
                .and_then(|i| match i.dtype() {
                    ort::value::ValueType::Tensor { shape, .. } => {
                        shape.get(1).copied().filter(|&d| d > 0)
                    }
                    _ => None,
                })
                .map(|d| d as u32)
                .unwrap_or(MESH_INPUT);
            Ok(Self { session, input })
        }
        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Self::load_from_memory(&bytes)
        }

        /// Run FaceMesh on the face at `bbox` (frame pixel coords) with `margin`
        /// (fraction of the box size added on each side; MediaPipe uses ~0.25).
        /// Returns the 468 landmarks as `(x, y)` in ORIGINAL FRAME pixel coords.
        /// The crop is square and centered so aspect ratio is preserved.
        ///
        /// Errors when the box is not a meaningful face region
        /// ([`mesh_box_valid`]) or the model's output fails the geometric
        /// plausibility check ([`mesh_output_plausible`]). A refusal must
        /// reach the cues as ABSENT landmarks, never abort a capture window:
        /// the EAR pipelines consume it through [`mesh_min_ear`], and the
        /// alignment refine through `.ok()`. A new caller that `?`s this
        /// error re-creates the #293 defect (one refused frame costing the
        /// whole consent watch).
        pub fn landmarks(
            &mut self,
            frame: &align::RgbView,
            bbox: &[f32; 4],
            margin: f32,
        ) -> irlume_common::Result<Vec<(f32, f32)>> {
            mesh_box_valid(bbox, frame.width, frame.height)
                .map_err(|why| err(format!("mesh refused detector box {bbox:?}: {why}")))?;
            // Square crop centered on the box, expanded by `margin` on each side.
            let (cx, cy) = ((bbox[0] + bbox[2]) * 0.5, (bbox[1] + bbox[3]) * 0.5);
            let half = 0.5 * (bbox[2] - bbox[0]).max(bbox[3] - bbox[1]) * (1.0 + 2.0 * margin);
            let (x0, y0) = (cx - half, cy - half);
            let side = 2.0 * half;
            let n = self.input as usize;
            // NHWC, normalized to [0,1] (MediaPipe face_landmark expects [0,1]; flip
            // to (px/127.5−1) if landmarks come out garbage; the first thing to try).
            let mut data = vec![0.0f32; n * n * 3];
            for oy in 0..n {
                for ox in 0..n {
                    let sx = x0 + (ox as f32 + 0.5) / n as f32 * side;
                    let sy = y0 + (oy as f32 + 0.5) / n as f32 * side;
                    let p = frame.sample_bilinear(sx, sy);
                    let i = (oy * n + ox) * 3;
                    data[i] = p[0] / 255.0;
                    data[i + 1] = p[1] / 255.0;
                    data[i + 2] = p[2] / 255.0;
                }
            }
            let s = self.input as i64;
            let tensor = Tensor::from_array(([1i64, s, s, 3], data)).map_err(err)?;
            let outputs = self.session.run(ort::inputs![tensor]).map_err(err)?;
            // Find the landmark tensor by length (order-agnostic): 468x3
            // legacy or 478x3 iris-generation.
            let mut lm_raw: Option<Vec<f32>> = None;
            for i in 0..outputs.len() {
                let (_shape, raw) = outputs[i].try_extract_tensor::<f32>().map_err(err)?;
                if raw.len() == MESH_N * 3 || raw.len() == MESH_N_IRIS * 3 {
                    lm_raw = Some(raw.to_vec());
                }
            }
            let raw =
                lm_raw.ok_or_else(|| err(format!("no {MESH_N}/{MESH_N_IRIS}-landmark output")))?;
            map_checked_mesh_output(&raw, self.input as f32, x0, y0, side)
                .map_err(|why| err(format!("mesh output refused: {why}")))
        }
    }

    /// Map raw mesh output (x,y,z triples in the model's input space) into
    /// frame coordinates, refusing output that fails
    /// [`mesh_output_plausible`]. One function on purpose: the mapping is the
    /// only way `landmarks()` gets its result, so the plausibility check
    /// cannot be skipped without losing the coordinates themselves (the
    /// pattern where a validation bolted on beside the data path quietly
    /// stops being called).
    pub fn map_checked_mesh_output(
        raw: &[f32],
        input: f32,
        x0: f32,
        y0: f32,
        side: f32,
    ) -> Result<Vec<(f32, f32)>, String> {
        let count = raw.len() / 3;
        // Map input-space (0..side) coords back to the frame crop.
        let mut out = Vec::with_capacity(count);
        for k in 0..count {
            let lx = raw[3 * k] / input * side + x0;
            let ly = raw[3 * k + 1] / input * side + y0;
            out.push((lx, ly));
        }
        mesh_output_plausible(&out, x0, y0, side)?;
        Ok(out)
    }

    /// The smaller of the two eye-aspect-ratios from a mesh run, or `None`
    /// when the mesh refuses the detector box or its own output.
    ///
    /// `None` is a MISSING OBSERVATION, the per-frame fail-closed answer for
    /// the EAR pipelines (`EarSample.ear = None`): the bounded capture window
    /// continues and the stream consumers deny on absent eyes. The callers
    /// used to propagate a mesh error with `?`, which was dormant while the
    /// mesh could only fail on runtime errors; the validity refusals made it
    /// live, so one refused frame aborted an entire consent watch instead of
    /// costing one observation (#293 review). Returning `Option` here removes
    /// the operator: a caller cannot re-introduce the abort without
    /// reimplementing the mesh call.
    pub fn mesh_min_ear(
        mesh: &mut FaceMesh,
        frame: &align::RgbView,
        bbox: &[f32; 4],
    ) -> Option<f32> {
        let lm = mesh.landmarks(frame, bbox, 0.25).ok()?;
        Some(eye_ear(&lm, &EAR_LEFT).min(eye_ear(&lm, &EAR_RIGHT)))
    }

    /// Is `bbox` a face region the mesh can meaningfully run on?
    ///
    /// These are validity bounds (is the request geometrically a region at
    /// all), not tuned thresholds. Measured in
    /// `examples/landmark_failure_probe.rs` before this gate existed: a
    /// zero-area box returned 478 identical "landmarks", a NaN box returned
    /// 478 NaN points, an inverted box placed every point outside its own
    /// crop, and an off-frame box returned a full mesh of pure edge-clamp
    /// smear; every one came back `Ok`. Each is a broken or hostile DETECTOR,
    /// the stage #276 wants to open to third-party models, and the mesh
    /// output built on one feeds the liveness cues as confident numbers.
    pub fn mesh_box_valid(bbox: &[f32; 4], frame_w: u32, frame_h: u32) -> Result<(), String> {
        if !bbox.iter().all(|v| v.is_finite()) {
            return Err("non-finite coordinates".into());
        }
        let (w, h) = (bbox[2] - bbox[0], bbox[3] - bbox[1]);
        if w <= 0.0 || h <= 0.0 {
            return Err("not a positive-area region".into());
        }
        if bbox[2] <= 0.0
            || bbox[3] <= 0.0
            || bbox[0] >= frame_w as f32
            || bbox[1] >= frame_h as f32
        {
            return Err("no overlap with the frame".into());
        }
        // A face reported larger than the frame that contains it is a broken
        // detector, not a face. 4x leaves room for a face partly out of frame
        // plus the crop margins.
        if w * h > 4.0 * frame_w as f32 * frame_h as f32 {
            return Err("area exceeds 4x the frame".into());
        }
        Ok(())
    }

    /// Does the mesh's mapped output describe a face-shaped point set?
    ///
    /// The mesh emits coordinates in its own input space, which the caller
    /// maps into the sampled square (`x0..x0+side`), so a healthy model
    /// CANNOT leave that square: out-of-crop points mean the model is not
    /// honoring its own input contract (a broken conversion, or a swapped-in
    /// model with a different output convention). The 25% slop absorbs
    /// benign overshoot at the crop border without admitting a set that
    /// mostly lives elsewhere. Non-finite output is a broken op in a
    /// converted model, and a collapsed extent is a stuck output head; both
    /// were observed as `Ok` before this gate (see the probe example).
    pub fn mesh_output_plausible(
        lm: &[(f32, f32)],
        x0: f32,
        y0: f32,
        side: f32,
    ) -> Result<(), String> {
        if !lm.iter().all(|&(x, y)| x.is_finite() && y.is_finite()) {
            return Err("non-finite landmarks".into());
        }
        let slop = side * 0.25;
        let inside = lm
            .iter()
            .filter(|&&(x, y)| {
                (x0 - slop..=x0 + side + slop).contains(&x)
                    && (y0 - slop..=y0 + side + slop).contains(&y)
            })
            .count();
        if inside * 2 < lm.len() {
            return Err(format!(
                "only {inside}/{} landmarks inside the sampled crop",
                lm.len()
            ));
        }
        // Collapse is judged on the CENTRAL 80% span, not the extrema: with
        // min/max, one stray point vouches for 477 stuck ones, and "a stuck
        // output head plus one corrupt value" is a realistic combination of
        // the pathologies this gate exists for (#293 review). Requiring the
        // bulk of the points to spread keeps a single outlier from carrying
        // the check. The 2px floor is unchanged: validity, not a tuned
        // threshold, and far below any genuine face (the shipped mesh spans
        // >100px on a face-sized crop).
        let central_span = |mut v: Vec<f32>| -> f32 {
            v.sort_by(f32::total_cmp);
            let lo = v.len() / 10;
            let hi = v.len().saturating_sub(1 + lo);
            if hi <= lo {
                return 0.0;
            }
            v[hi] - v[lo]
        };
        let xs: Vec<f32> = lm.iter().map(|&(x, _)| x).collect();
        let ys: Vec<f32> = lm.iter().map(|&(_, y)| y).collect();
        if central_span(xs) < 2.0 || central_span(ys) < 2.0 {
            return Err("landmarks collapsed to a point".into());
        }
        Ok(())
    }

    /// 6-point eye-aspect-ratio landmark indices (MediaPipe 468 topology): the two
    /// horizontal corners + two upper + two lower lid points, per eye.
    pub const EAR_LEFT: [usize; 6] = [33, 160, 158, 133, 153, 144];
    pub const EAR_RIGHT: [usize; 6] = [362, 385, 387, 263, 373, 380];

    /// Eye-aspect-ratio for one eye from its 6 landmarks: `(|p2−p6| + |p3−p5|) /
    /// (2·|p1−p4|)`. Scale-invariant (a ratio): ~0.3 open, →0 closed. This is the
    /// clean blink signal: collapses on closure, unlike the noisy IR-glint metric.
    pub fn eye_ear(lm: &[(f32, f32)], idx: &[usize; 6]) -> f32 {
        let d = |a: (f32, f32), b: (f32, f32)| ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt();
        let p = |k: usize| lm[idx[k]];
        let horiz = d(p(0), p(3));
        if horiz < 1e-6 {
            return 0.0;
        }
        (d(p(1), p(5)) + d(p(2), p(4))) / (2.0 * horiz)
    }

    /// YuNet detector (ONNX). Loaded once in the daemon.
    pub struct Detector {
        #[allow(dead_code)]
        session: Session,
    }

    impl Detector {
        pub fn load_from_memory(model: &[u8]) -> irlume_common::Result<Self> {
            Ok(Self {
                session: build(model)?,
            })
        }
        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Self::load_from_memory(&bytes)
        }

        /// Detect faces in an RGB frame. Letterboxes to YuNet's square input,
        /// runs the net, groups outputs by tensor shape (cls/obj=1ch, bbox=4ch,
        /// kps=10ch) per stride, decodes, NMS, and maps coords back to the frame.
        pub fn detect(&mut self, frame: &align::RgbView) -> irlume_common::Result<Vec<Detection>> {
            use crate::detect::{
                decode_stride, letterbox_scale, nms, unletterbox, INPUT_SIZE, NMS_IOU,
                SCORE_THRESHOLD, STRIDES,
            };
            let scale = letterbox_scale(frame.width, frame.height);
            let input = letterbox_bgr(frame, scale, INPUT_SIZE);
            let n = INPUT_SIZE as i64;
            let tensor = Tensor::from_array(([1i64, 3, n, n], input)).map_err(err)?;
            let outputs = self.session.run(ort::inputs![tensor]).map_err(err)?;

            // Group every output tensor by (channels, stride) using its shape.
            let mut by: std::collections::HashMap<(usize, usize), Vec<Vec<f32>>> =
                std::collections::HashMap::new();
            for i in 0..outputs.len() {
                let (shape, raw) = outputs[i].try_extract_tensor::<f32>().map_err(err)?;
                let dims: Vec<usize> = shape.iter().map(|&d| d as usize).collect();
                let ch = *dims.last().unwrap_or(&1);
                let count = raw.len().checked_div(ch).unwrap_or(0);
                let stride = STRIDES.iter().copied().find(|&s| {
                    let f = INPUT_SIZE / s;
                    f * f == count
                });
                if let Some(stride) = stride {
                    by.entry((ch, stride)).or_default().push(raw.to_vec());
                }
            }

            let mut dets = Vec::new();
            for &stride in &STRIDES {
                let feat_w = INPUT_SIZE / stride;
                let ones = by.get(&(1, stride));
                let (Some(ones), Some(bbox), Some(kps)) =
                    (ones, by.get(&(4, stride)), by.get(&(10, stride)))
                else {
                    continue;
                };
                if ones.len() < 2 {
                    continue;
                }
                // score = sqrt(cls·obj); the two 1-channel tensors are symmetric.
                dets.extend(decode_stride(
                    &ones[0],
                    &ones[1],
                    &bbox[0],
                    &kps[0],
                    stride,
                    feat_w,
                    SCORE_THRESHOLD,
                ));
            }
            let mut dets = nms(dets, NMS_IOU);
            for d in &mut dets {
                unletterbox(d, scale);
            }
            // A NaN score already fails the threshold comparison, but a NaN
            // COORDINATE with a finite score survives decode and NMS, and one
            // NaN landmark is enough to point a downstream cue at pixel (0,0)
            // (see `detection_is_finite`).
            dets.retain(crate::detection_is_finite);
            Ok(dets)
        }
    }

    /// BlazeFace short-range (Apache-2.0, Google MediaPipe): RESCUE detector
    /// for frames YuNet loses. Benchmarked 2026-07-15 on the sunlight field
    /// bursts: 96.9% detection on saturated outdoor-walking frames where
    /// YuNet manages 76.9%, but only 40% on shaded faces where YuNet holds
    /// 99%, and its eye keypoints are coarser (NME 0.087 vs 0.053). It
    /// therefore NEVER replaces YuNet: it runs only when YuNet returns no
    /// face, and its box must be refined by FaceMesh before alignment.
    ///
    /// Contract (decode parity-tested against the official MediaPipe
    /// runtime: 0.94 mean IoU, eyes within ~5px): input 128x128x3 RGB NHWC
    /// in `[-1,1]` from a zero-padded square letterbox; outputs 896 SSD
    /// anchors x 16 regressors (cx,cy,w,h + 6 keypoints, all /128 relative
    /// to anchor centers) + 896 logits (sigmoid, clipped +/-100). Anchors:
    /// 16x16 cells x2 (stride 8) then 8x8 x6 (stride 16), sizes 1.0.
    pub struct BlazeRescue {
        session: Session,
        anchors: Vec<(f32, f32)>,
    }

    /// BlazeFace square input side.
    pub const BLAZE_INPUT: usize = 128;
    /// Rescue-path detection threshold (same operating point as the bench).
    pub const BLAZE_SCORE_THRESHOLD: f32 = 0.5;

    fn blaze_anchors() -> Vec<(f32, f32)> {
        let mut a = Vec::with_capacity(896);
        for (cells, per_cell) in [(16usize, 2usize), (8, 6)] {
            for r in 0..cells {
                for c in 0..cells {
                    for _ in 0..per_cell {
                        a.push((
                            (c as f32 + 0.5) / cells as f32,
                            (r as f32 + 0.5) / cells as f32,
                        ));
                    }
                }
            }
        }
        a
    }

    impl BlazeRescue {
        pub fn load_from_memory(model: &[u8]) -> irlume_common::Result<Self> {
            Ok(Self {
                session: build(model)?,
                anchors: blaze_anchors(),
            })
        }
        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Self::load_from_memory(&bytes)
        }

        /// Top-scoring face, or `None` below threshold. Returns the bbox in
        /// frame pixels (x1,y1,x2,y2) and the score. No keypoints: they are
        /// too coarse for alignment; refine with [`FaceMesh::landmarks`].
        pub fn detect_top(
            &mut self,
            frame: &align::RgbView,
        ) -> irlume_common::Result<Option<([f32; 4], f32)>> {
            let side = frame.width.max(frame.height) as f32;
            let n = BLAZE_INPUT;
            let mut data = vec![0.0f32; n * n * 3];
            for oy in 0..n {
                for ox in 0..n {
                    let sx = (ox as f32 + 0.5) / n as f32 * side;
                    let sy = (oy as f32 + 0.5) / n as f32 * side;
                    // Zero-pad outside the frame (letterbox), matching the
                    // parity reference exactly.
                    if sx >= frame.width as f32 || sy >= frame.height as f32 {
                        continue;
                    }
                    let p = frame.sample_bilinear(sx, sy);
                    let i = (oy * n + ox) * 3;
                    data[i] = (p[0] - 127.5) / 127.5;
                    data[i + 1] = (p[1] - 127.5) / 127.5;
                    data[i + 2] = (p[2] - 127.5) / 127.5;
                }
            }
            let s = n as i64;
            let tensor = Tensor::from_array(([1i64, s, s, 3], data)).map_err(err)?;
            let outputs = self.session.run(ort::inputs![tensor]).map_err(err)?;
            // Identify the two heads by length (order-agnostic).
            let (mut reg, mut cls): (Option<Vec<f32>>, Option<Vec<f32>>) = (None, None);
            for i in 0..outputs.len() {
                let (_shape, raw) = outputs[i].try_extract_tensor::<f32>().map_err(err)?;
                match raw.len() {
                    l if l == 896 * 16 => reg = Some(raw.to_vec()),
                    896 => cls = Some(raw.to_vec()),
                    _ => {}
                }
            }
            let (Some(reg), Some(cls)) = (reg, cls) else {
                return Err(err("blaze: unexpected output tensors"));
            };
            let (mut best_i, mut best_s) = (0usize, f32::NEG_INFINITY);
            for (i, &logit) in cls.iter().enumerate() {
                let sc = 1.0 / (1.0 + (-logit.clamp(-100.0, 100.0)).exp());
                if sc > best_s {
                    best_s = sc;
                    best_i = i;
                }
            }
            if best_s < BLAZE_SCORE_THRESHOLD {
                return Ok(None);
            }
            let r = &reg[best_i * 16..best_i * 16 + 16];
            let (ax, ay) = self.anchors[best_i];
            let scale = BLAZE_INPUT as f32;
            let (cx, cy) = (ax + r[0] / scale, ay + r[1] / scale);
            let (bw, bh) = (r[2] / scale, r[3] / scale);
            let bbox = [
                (cx - bw / 2.0) * side,
                (cy - bh / 2.0) * side,
                (cx + bw / 2.0) * side,
                (cy + bh / 2.0) * side,
            ];
            // A NaN regressor with a finite logit decodes into a NaN box that
            // the mesh refine step would then sample. Same rule as the YuNet
            // path's `detection_is_finite` retain: no face beats a non-face.
            if !bbox.iter().all(|v| v.is_finite()) {
                return Ok(None);
            }
            Ok(Some((bbox, best_s)))
        }
    }

    /// Resize+letterbox an RGB frame into a BGR, raw 0–255, NCHW input tensor for
    /// YuNet (top-left aligned; remainder zero-padded).
    fn letterbox_bgr(frame: &align::RgbView, scale: f32, size: usize) -> Vec<f32> {
        let mut t = vec![0.0f32; 3 * size * size];
        let plane = size * size;
        let (sw, sh) = (
            (frame.width as f32 * scale) as usize,
            (frame.height as f32 * scale) as usize,
        );
        for y in 0..sh.min(size) {
            for x in 0..sw.min(size) {
                let p = frame.sample_bilinear(x as f32 / scale, y as f32 / scale);
                let o = y * size + x;
                t[o] = p[2]; // B
                t[plane + o] = p[1]; // G
                t[2 * plane + o] = p[0]; // R
            }
        }
        t
    }

    /// Third-party PAD classifier (opt-in; see `irlume_common::thirdparty`).
    /// Built for the DAMO FLIR IR liveness model: 112x112x3, (px-127.5)/128,
    /// NCHW, two output LOGITS where softmax index 0 is P(fake). Preprocessing
    /// replicates ModelScope's `FaceLivenessIrPipeline.align_face_padding`
    /// exactly (validated against 1,175 field frames + the live sessions in
    /// docs/pad-results/2026-07-17-third-party-pad-candidates.md): expand the
    /// detection bbox by 16/112 per side, clamp to the frame, square the crop
    /// about its center, fill out-of-crop with 127 gray, resize to 128, take
    /// the center 112.
    pub struct PadIr {
        session: Session,
    }

    impl PadIr {
        pub fn load_from_memory(model: &[u8]) -> irlume_common::Result<Self> {
            Ok(Self {
                session: build(model)?,
            })
        }
        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Self::load_from_memory(&bytes)
        }

        /// P(fake) for the face at `bbox` (frame pixel coords, `[x1,y1,x2,y2]`).
        pub fn p_fake(
            &mut self,
            frame: &align::RgbView,
            bbox: &[f32; 4],
        ) -> irlume_common::Result<f32> {
            const PAD: i64 = 16;
            let (fw, fh) = (frame.width as i64, frame.height as i64);
            let mut b = [
                bbox[0] as i64,
                bbox[1] as i64,
                bbox[2] as i64,
                bbox[3] as i64,
            ];
            let px = (b[2] - b[0] + 1) * PAD / 112;
            let py = (b[3] - b[1] + 1) * PAD / 112;
            b = [
                (b[0] - px).max(0),
                (b[1] - py).max(0),
                (b[2] + px).min(fw - 1),
                (b[3] + py).min(fh - 1),
            ];
            let (ph, pw) = (b[3] - b[1] + 1, b[2] - b[0] + 1);
            let dst_size = if pw > ph {
                let off = (pw - ph) / 2;
                b[1] = (b[1] - off).max(0);
                b[3] = (b[1] + pw - 1).min(fh - 1);
                pw
            } else {
                let off = (ph - pw) / 2;
                b[0] = (b[0] - off).max(0);
                b[2] = (b[0] + ph - 1).min(fw - 1);
                ph
            } as f32;
            // Crop offsets center the (possibly clamped) region in the square.
            let xo = (dst_size as i64 - (b[2] - b[0] + 1)) / 2;
            let yo = (dst_size as i64 - (b[3] - b[1] + 1)) / 2;
            // Sample the 112 center of the virtual 128 square directly:
            // dst pixel (ox,oy) in 0..112 maps to square coord via the cv2
            // INTER_LINEAR convention, offset by the 8px center-crop margin.
            let scale = dst_size / 128.0;
            let mut t = vec![0.0f32; 3 * 112 * 112];
            let plane = 112 * 112;
            for oy in 0..112usize {
                for ox in 0..112usize {
                    let sqx = ((ox + 8) as f32 + 0.5) * scale - 0.5;
                    let sqy = ((oy + 8) as f32 + 0.5) * scale - 0.5;
                    // Square coords -> frame coords (127 gray outside the crop).
                    let fx = sqx - xo as f32 + b[0] as f32;
                    let fy = sqy - yo as f32 + b[1] as f32;
                    let p = if fx < b[0] as f32 - 0.5
                        || fy < b[1] as f32 - 0.5
                        || fx > b[2] as f32 + 0.5
                        || fy > b[3] as f32 + 0.5
                    {
                        [127.0, 127.0, 127.0]
                    } else {
                        frame.sample_bilinear(fx, fy)
                    };
                    let o = oy * 112 + ox;
                    // Grayscale IR: channels are equal, order irrelevant.
                    t[o] = (p[0] - 127.5) * 0.007_812_5;
                    t[plane + o] = (p[1] - 127.5) * 0.007_812_5;
                    t[2 * plane + o] = (p[2] - 127.5) * 0.007_812_5;
                }
            }
            let tensor = Tensor::from_array(([1i64, 3, 112, 112], t)).map_err(err)?;
            let outputs = self.session.run(ort::inputs![tensor]).map_err(err)?;
            let (_shape, raw) = outputs[0].try_extract_tensor::<f32>().map_err(err)?;
            if raw.len() < 2 {
                return Err(err("PAD model: expected 2 output logits"));
            }
            let (a, b2) = (raw[0], raw[1]);
            let m = a.max(b2);
            let (ea, eb) = ((a - m).exp(), (b2 - m).exp());
            Ok(ea / (ea + eb)) // softmax index 0 = P(fake)
        }
    }

    /// Phase-1 gate: embed the SAME aligned chip twice; cosine MUST be ~= 1.0.
    /// Validates that the ONNX path is deterministic and the preprocessing is
    /// wired correctly before any matching logic is trusted. Returns (passed,
    /// detail). A synthetic chip is sufficient; this checks the pipeline, not
    /// recognition accuracy (that needs real faces, a later step).
    pub fn selftest_alignment_identity(embedder: &mut Embedder) -> (bool, String) {
        let n = (align::OUT_SIZE * align::OUT_SIZE) as usize;
        let mut chip = vec![0u8; n * 3];
        for (i, px) in chip.iter_mut().enumerate() {
            *px = ((i * 37 + 11) % 256) as u8; // deterministic pseudo-texture
        }
        let a = match embedder.embed(&chip) {
            Ok(e) => e,
            Err(e) => return (false, format!("embed failed: {e}")),
        };
        let b = match embedder.embed(&chip) {
            Ok(e) => e,
            Err(e) => return (false, format!("embed failed: {e}")),
        };
        let cos = align::cosine(&a, &b);
        let passed = (cos - 1.0).abs() < 1e-4;
        (
            passed,
            format!("cosine(same chip, twice) = {cos:.6} (want ~1.0)"),
        )
    }

    #[cfg(test)]
    mod landmark_sanity_tests {
        use super::*;

        #[test]
        fn mesh_box_valid_refuses_each_pathology_by_its_own_reason() {
            // Asserting the REASON, not just rejection: a later guard refusing
            // the same input for a different reason must not silently take
            // over a case (the #183 lesson).
            let ok = [100.0, 80.0, 220.0, 240.0];
            assert_eq!(mesh_box_valid(&ok, 400, 300), Ok(()));
            // A face partly out of frame, box bigger than the frame: legal.
            assert_eq!(
                mesh_box_valid(&[-50.0, -50.0, 420.0, 330.0], 400, 300),
                Ok(())
            );
            let reason = |b: &[f32; 4]| mesh_box_valid(b, 400, 300).unwrap_err();
            assert_eq!(reason(&[f32::NAN; 4]), "non-finite coordinates");
            assert_eq!(
                reason(&[100.0, 80.0, f32::INFINITY, 240.0]),
                "non-finite coordinates"
            );
            assert_eq!(
                reason(&[160.0, 160.0, 160.0, 160.0]),
                "not a positive-area region"
            );
            assert_eq!(
                reason(&[220.0, 240.0, 100.0, 80.0]),
                "not a positive-area region"
            );
            assert_eq!(
                reason(&[-900.0, -900.0, -700.0, -700.0]),
                "no overlap with the frame"
            );
            assert_eq!(
                reason(&[500.0, 100.0, 600.0, 200.0]),
                "no overlap with the frame"
            );
            assert_eq!(reason(&[-1e6, -1e6, 1e6, 1e6]), "area exceeds 4x the frame");
        }

        #[test]
        fn mesh_output_plausible_separates_face_shapes_from_garbage() {
            // A face-ish spread inside the (0,0)+200 crop.
            let face: Vec<(f32, f32)> = (0..468)
                .map(|i| (40.0 + (i % 24) as f32 * 5.0, 30.0 + (i / 24) as f32 * 7.0))
                .collect();
            assert_eq!(mesh_output_plausible(&face, 0.0, 0.0, 200.0), Ok(()));
            let reason =
                |lm: &[(f32, f32)]| mesh_output_plausible(lm, 0.0, 0.0, 200.0).unwrap_err();
            let mut one_nan = face.clone();
            one_nan[7] = (f32::NAN, 50.0);
            assert_eq!(reason(&one_nan), "non-finite landmarks");
            assert_eq!(
                reason(&vec![(100.0, 100.0); 468]),
                "landmarks collapsed to a point"
            );
            // One stray point must not vouch for 467 stuck ones: extrema-based
            // extent accepted exactly this (#293 review), which is a stuck
            // output head plus one corrupt value, and lets a model supply
            // arbitrary values at the few indices the cues read.
            let mut one_outlier = vec![(100.0, 100.0); 468];
            one_outlier[0] = (103.0, 103.0);
            assert_eq!(reason(&one_outlier), "landmarks collapsed to a point");
            // Most points far outside the sampled square: the model is not
            // honoring its own input space.
            let outside: Vec<(f32, f32)> = (0..468)
                .map(|i| (900.0 + (i % 24) as f32 * 5.0, 800.0 + (i / 24) as f32 * 7.0))
                .collect();
            assert!(reason(&outside).contains("inside the sampled crop"));
            // Benign border overshoot within the 25% slop is NOT refused: a
            // tilted chin can land just past the crop edge.
            let mut overshoot = face.clone();
            for p in overshoot.iter_mut().take(60) {
                p.1 = 240.0; // past side=200, inside the 50px slop
            }
            assert_eq!(mesh_output_plausible(&overshoot, 0.0, 0.0, 200.0), Ok(()));
        }

        #[test]
        fn raw_mesh_output_maps_or_refuses_as_one_operation() {
            // 468 triples spread over the model's own input space map to a
            // face-shaped set inside the crop.
            let mut raw = Vec::with_capacity(468 * 3);
            for i in 0..468 {
                raw.extend([
                    40.0 + (i % 24) as f32 * 5.0,
                    30.0 + (i / 24) as f32 * 7.0,
                    0.0,
                ]);
            }
            let out = map_checked_mesh_output(&raw, 192.0, 10.0, 20.0, 300.0).expect("maps");
            assert_eq!(out.len(), 468);
            // First point: 40/192*300+10, 30/192*300+20.
            assert!((out[0].0 - 72.5).abs() < 1e-3 && (out[0].1 - 66.875).abs() < 1e-3);
            // A NaN raw value is refused by the same call that maps, so the
            // check cannot be skipped without losing the mapping.
            raw[9] = f32::NAN;
            assert_eq!(
                map_checked_mesh_output(&raw, 192.0, 10.0, 20.0, 300.0),
                Err("non-finite landmarks".into())
            );
            // A model ignoring its input space (values far beyond `input`)
            // lands outside the crop and is refused.
            let wild: Vec<f32> = (0..468 * 3).map(|_| 1e5f32).collect();
            assert!(map_checked_mesh_output(&wild, 192.0, 10.0, 20.0, 300.0)
                .unwrap_err()
                .contains("inside the sampled crop"));
        }
    }

    #[cfg(test)]
    mod resolver_tests {
        use super::*;
        use std::ffi::OsStr;
        use std::path::{Path, PathBuf};

        #[test]
        fn an_empty_environment_variable_reads_as_unset() {
            // Pinned ort treats ORT_DYLIB_PATH="" as unset; treating it as an
            // explicit path would error on a configuration ort itself accepts.
            assert_eq!(configured_ort(Some(OsStr::new("")), |_| false), None);
        }

        #[test]
        fn an_explicit_path_wins_even_over_a_present_package() {
            assert_eq!(
                configured_ort(Some(OsStr::new("/custom/libonnxruntime.so")), |_| true),
                Some(PathBuf::from("/custom/libonnxruntime.so"))
            );
        }

        #[test]
        fn each_package_layout_is_found() {
            // Fedora/Copr and the Debian/Ubuntu /opt layout (#269 review: the
            // first version knew only Fedora's path, so a bare CLI run on a
            // .deb install errored with the library installed).
            for packaged in PACKAGED_ORTS {
                assert_eq!(
                    configured_ort(None, |p| p == Path::new(packaged)),
                    Some(PathBuf::from(*packaged))
                );
            }
        }

        #[test]
        fn nothing_found_defers_to_the_system_loader() {
            assert_eq!(configured_ort(None, |_| false), None);
        }

        // The version-floor refusal itself (a runtime that loads, is an ONNX
        // Runtime, and answers null for API level 24) needs a pre-1.24
        // libonnxruntime, which CI does not have; it was validated against
        // onnxruntime 1.20.1 in a container (#187), where the unpatched
        // probe let the process park forever and this one returns the
        // version-naming error. The two refusal classes below are the ones a
        // stock Linux runner can produce deterministically.

        #[test]
        fn an_unloadable_path_reports_the_loaders_words() {
            let err = probe_runtime(c"/nonexistent/libonnxruntime.so").unwrap_err();
            assert!(
                err.contains("cannot open shared object file"),
                "expected the loader's own message, got: {err}"
            );
        }

        #[test]
        fn a_library_without_ortgetapibase_is_not_an_onnx_runtime() {
            // libc is loadable on every supported platform and exports no
            // OrtGetApiBase, so it exercises the loads-but-is-not-ort branch.
            let err = probe_runtime(c"libc.so.6").unwrap_err();
            assert!(
                err.contains("exports no OrtGetApiBase"),
                "expected the not-an-ONNX-Runtime refusal, got: {err}"
            );
        }
    }
}

#[cfg(feature = "onnx")]
pub use onnx::{
    eye_ear, mesh_box_valid, mesh_min_ear, mesh_output_plausible, runtime_resolution,
    selftest_alignment_identity, Adapter, BlazeRescue, Detector, Embedder, FaceMesh, PadIr,
    BLAZE_SCORE_THRESHOLD, EAR_LEFT, EAR_RIGHT, MESH_INPUT, MESH_N, MESH_N_IRIS,
};

/// Model-backed pipeline tests: run the REAL shipped ONNX models (fetched to
/// `models/` at the repo root by scripts/fetch-models.sh) on synthetic frames, asserting output
/// dimensions, value ranges, and determinism. Session creation is expensive, so
/// each model is built once per test binary and shared behind a `OnceLock`.
#[cfg(all(test, feature = "onnx"))]
mod model_tests {
    use super::*;
    use crate::align;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn model_path(name: &str) -> String {
        format!("{}/../../models/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Point `ort` (load-dynamic) at the packaged onnxruntime when the test env
    /// doesn't already provide `ORT_DYLIB_PATH`.
    fn ort_init() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            if std::env::var_os("ORT_DYLIB_PATH").is_some() {
                return;
            }
            for cand in [
                "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
                "/usr/lib64/libonnxruntime.so",
                "/usr/lib/libonnxruntime.so",
                "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
            ] {
                if std::path::Path::new(cand).exists() {
                    std::env::set_var("ORT_DYLIB_PATH", cand);
                    return;
                }
            }
        });
    }

    fn embedder() -> MutexGuard<'static, Embedder> {
        static S: OnceLock<Mutex<Embedder>> = OnceLock::new();
        S.get_or_init(|| {
            ort_init();
            Mutex::new(Embedder::load_from_file(&model_path("glintr100.onnx")).expect("embedder"))
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    }

    fn detector() -> MutexGuard<'static, Detector> {
        static S: OnceLock<Mutex<Detector>> = OnceLock::new();
        S.get_or_init(|| {
            ort_init();
            Mutex::new(
                Detector::load_from_file(&model_path("face_detection_yunet_2023mar.onnx"))
                    .expect("detector"),
            )
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    }

    fn facemesh() -> MutexGuard<'static, FaceMesh> {
        static S: OnceLock<Mutex<FaceMesh>> = OnceLock::new();
        S.get_or_init(|| {
            ort_init();
            Mutex::new(FaceMesh::load_from_file(&model_path("face_landmark.onnx")).expect("mesh"))
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    }

    fn blaze() -> MutexGuard<'static, BlazeRescue> {
        static S: OnceLock<Mutex<BlazeRescue>> = OnceLock::new();
        S.get_or_init(|| {
            ort_init();
            Mutex::new(
                BlazeRescue::load_from_file(&model_path("blaze_face_short_range.onnx"))
                    .expect("blaze"),
            )
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    }

    /// Deterministic pseudo-textured 112x112 chip (the embedder's input shape).
    fn chip(seed: usize) -> Vec<u8> {
        let n = (align::OUT_SIZE * align::OUT_SIZE) as usize * 3;
        (0..n)
            .map(|i| ((i * 37 + seed * 101 + 11) % 256) as u8)
            .collect()
    }

    /// Deterministic gradient frame of arbitrary size.
    fn gradient_frame(w: u32, h: u32) -> Vec<u8> {
        let mut data = vec![0u8; (w * h * 3) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 3) as usize;
                data[i] = (x * 255 / w.max(1)) as u8;
                data[i + 1] = (y * 255 / h.max(1)) as u8;
                data[i + 2] = ((x + y) % 256) as u8;
            }
        }
        data
    }

    fn l2(v: &[f32]) -> f32 {
        v.iter().map(|x| x * x).sum::<f32>().sqrt()
    }

    #[test]
    fn embed_is_512d_unit_norm_and_deterministic() {
        let mut e = embedder();
        let c = chip(1);
        let a = e.embed(&c).expect("embed");
        let b = e.embed(&c).expect("embed again");
        // Contract: 512-D (by type), L2-normalized, bitwise-stable inference.
        assert!((l2(&a) - 1.0).abs() < 1e-4, "norm {}", l2(&a));
        assert!(
            align::cosine(&a, &b) > 0.9999,
            "non-deterministic embedding"
        );
        // A different input must land somewhere else on the hypersphere.
        let other = e.embed(&chip(2)).expect("embed other");
        assert!(
            align::cosine(&a, &other) < 0.999,
            "distinct chips collapsed to one embedding: {}",
            align::cosine(&a, &other)
        );
    }

    #[test]
    fn embed_with_norm_returns_positive_quality_norm() {
        let mut e = embedder();
        let (emb, norm) = e.embed_with_norm(&chip(3)).expect("embed_with_norm");
        assert!(
            norm > 0.0,
            "pre-normalization norm must be positive: {norm}"
        );
        assert!((l2(&emb) - 1.0).abs() < 1e-4);
        // The returned embedding is the plain embed() of the same chip.
        let plain = e.embed(&chip(3)).expect("embed");
        assert!(align::cosine(&emb, &plain) > 0.9999);
    }

    #[test]
    fn embed_tta_is_normalized_deterministic_and_near_plain() {
        let mut e = embedder();
        let c = chip(4);
        let t1 = e.embed_tta(&c).expect("tta");
        let t2 = e.embed_tta(&c).expect("tta again");
        assert!((l2(&t1) - 1.0).abs() < 1e-4);
        assert!(align::cosine(&t1, &t2) > 0.9999);
        // The flip-average stays close to the un-augmented embedding (it is an
        // average containing it), but is not bit-identical.
        let plain = e.embed(&c).expect("embed");
        let cos = align::cosine(&t1, &plain);
        assert!(cos > 0.5, "tta drifted implausibly far: {cos}");
    }

    #[test]
    fn alignment_identity_selftest_passes_on_the_real_model() {
        let mut e = embedder();
        let (passed, detail) = selftest_alignment_identity(&mut e);
        assert!(passed, "{detail}");
    }

    #[test]
    fn detector_finds_no_face_in_synthetic_frames_and_is_deterministic() {
        let mut d = detector();
        let (w, h) = (640u32, 480u32);
        let grad = gradient_frame(w, h);
        let view = align::RgbView {
            data: &grad,
            width: w,
            height: h,
        };
        let dets = d.detect(&view).expect("detect");
        assert!(
            dets.is_empty(),
            "a faceless gradient must yield no detections, got {}",
            dets.len()
        );
        // Full pipeline determinism (letterbox -> session -> decode -> NMS).
        assert_eq!(d.detect(&view).expect("detect again").len(), 0);
        // Flat mid-grey behaves the same.
        let flat = vec![128u8; (w * h * 3) as usize];
        let view = align::RgbView {
            data: &flat,
            width: w,
            height: h,
        };
        assert!(d.detect(&view).expect("detect flat").is_empty());
    }

    #[test]
    fn facemesh_emits_full_point_set_in_crop_space() {
        let mut m = facemesh();
        let (w, h) = (256u32, 256u32);
        let frame = gradient_frame(w, h);
        let view = align::RgbView {
            data: &frame,
            width: w,
            height: h,
        };
        let bbox = [64.0, 64.0, 192.0, 192.0];
        let lm = m.landmarks(&view, &bbox, 0.25).expect("landmarks");
        // Either mesh generation is acceptable; the EAR/mouth indices used by
        // the blink gate exist in both.
        assert!(
            lm.len() == MESH_N || lm.len() == MESH_N_IRIS,
            "unexpected landmark count {}",
            lm.len()
        );
        // Points come back mapped to the frame-space crop: finite, and within
        // the expanded crop square plus slack (the model may overshoot a bit on
        // a faceless input, but not by orders of magnitude).
        for &(x, y) in &lm {
            assert!(x.is_finite() && y.is_finite());
            assert!((-256.0..512.0).contains(&x), "x out of range: {x}");
            assert!((-256.0..512.0).contains(&y), "y out of range: {y}");
        }
        // Determinism: same crop, same points.
        let again = m.landmarks(&view, &bbox, 0.25).expect("landmarks again");
        assert_eq!(lm, again);
        // Headroom over the collapse gate's 2px central-span floor: even on a
        // faceless gradient the real mesh spreads its central 80% far above
        // it, so the validity bound cannot cost a genuine capture.
        let mut xs: Vec<f32> = lm.iter().map(|&(x, _)| x).collect();
        xs.sort_by(f32::total_cmp);
        let span = xs[xs.len() - 1 - xs.len() / 10] - xs[xs.len() / 10];
        assert!(span > 20.0, "central x-span {span} too close to the floor");
    }

    #[test]
    fn a_refused_box_is_a_missing_ear_observation_not_an_error() {
        // The EAR pipelines consume mesh refusals through `mesh_min_ear`,
        // which has no error to propagate: one refused frame is one missing
        // observation, never a lost capture window (#293 review found the
        // old `?` callers turning the new refusals into authentication-stack
        // errors).
        let mut m = facemesh();
        let (w, h) = (256u32, 256u32);
        let frame = gradient_frame(w, h);
        let view = align::RgbView {
            data: &frame,
            width: w,
            height: h,
        };
        assert_eq!(mesh_min_ear(&mut m, &view, &[f32::NAN; 4]), None);
        assert_eq!(
            mesh_min_ear(&mut m, &view, &[-900.0, -900.0, -700.0, -700.0]),
            None
        );
        // A nominal box still measures: Some, and finite.
        let ear = mesh_min_ear(&mut m, &view, &[64.0, 64.0, 192.0, 192.0]);
        assert!(matches!(ear, Some(e) if e.is_finite()), "{ear:?}");
    }

    #[test]
    fn facemesh_refuses_garbage_detector_boxes_through_the_real_model() {
        // The pure gates have their own unit tests; this pins the BOX-gate
        // WIRING, so a refactor that drops that call from `landmarks()`
        // fails here even though the gate functions still pass alone. (The
        // OUTPUT gate's wiring is not pinned by a model test: the real mesh
        // never emits implausible output. It is structural instead: the
        // check lives inside `map_checked_mesh_output`, the only mapping
        // implementation, so skipping it means reimplementing the mapping.)
        let mut m = facemesh();
        let (w, h) = (256u32, 256u32);
        let frame = gradient_frame(w, h);
        let view = align::RgbView {
            data: &frame,
            width: w,
            height: h,
        };
        for bbox in [
            [f32::NAN; 4],
            [128.0, 128.0, 128.0, 128.0],
            [-900.0, -900.0, -700.0, -700.0],
        ] {
            let e = m
                .landmarks(&view, &bbox, 0.25)
                .expect_err("garbage box must be refused");
            assert!(
                e.to_string().contains("mesh refused detector box"),
                "wrong refusal for {bbox:?}: {e}"
            );
        }
    }

    #[test]
    fn blaze_rescue_is_deterministic_and_unconfident_on_synthetic_frames() {
        let mut b = blaze();
        let (w, h) = (640u32, 400u32);
        let frame = gradient_frame(w, h);
        let view = align::RgbView {
            data: &frame,
            width: w,
            height: h,
        };
        let r1 = b.detect_top(&view).expect("blaze");
        let r2 = b.detect_top(&view).expect("blaze again");
        // Determinism of the full decode (letterbox, sigmoid, anchor mapping).
        match (&r1, &r2) {
            (None, None) => {}
            (Some((bb1, s1)), Some((bb2, s2))) => {
                assert_eq!(bb1, bb2);
                assert_eq!(s1, s2);
            }
            _ => panic!("blaze non-deterministic on identical input"),
        }
        // A faceless gradient must not produce a confident face.
        assert!(
            r1.is_none(),
            "blaze hallucinated a face on a gradient: {r1:?}"
        );
        // Flat grey likewise.
        let flat = vec![127u8; (w * h * 3) as usize];
        let view = align::RgbView {
            data: &flat,
            width: w,
            height: h,
        };
        assert!(b.detect_top(&view).expect("blaze flat").is_none());
    }
}

#[cfg(all(test, feature = "onnx"))]
mod ear_tests {
    use super::{eye_ear, EAR_LEFT};

    /// EAR = (|p2−p6| + |p3−p5|) / (2·|p1−p4|). Build a 468-point array with only
    /// the left-eye indices set to a known shape and check the ratio.
    fn lm_with(idx: &[usize; 6], pts: [(f32, f32); 6]) -> Vec<(f32, f32)> {
        let mut lm = vec![(0.0, 0.0); 468];
        for (k, &i) in idx.iter().enumerate() {
            lm[i] = pts[k];
        }
        lm
    }

    #[test]
    fn open_eye_has_normal_ear() {
        // corners 10 apart; lids ±2 => EAR = (4+4)/(2*10) = 0.4.
        let lm = lm_with(
            &EAR_LEFT,
            [
                (0.0, 0.0),
                (3.0, -2.0),
                (7.0, -2.0),
                (10.0, 0.0),
                (7.0, 2.0),
                (3.0, 2.0),
            ],
        );
        assert!((eye_ear(&lm, &EAR_LEFT) - 0.4).abs() < 1e-5);
    }

    #[test]
    fn closed_eye_ear_near_zero() {
        // lids collapse onto the horizontal line => vertical distances 0 => EAR 0.
        let lm = lm_with(
            &EAR_LEFT,
            [
                (0.0, 0.0),
                (3.0, 0.0),
                (7.0, 0.0),
                (10.0, 0.0),
                (7.0, 0.0),
                (3.0, 0.0),
            ],
        );
        assert!(eye_ear(&lm, &EAR_LEFT) < 1e-5);
    }

    #[test]
    fn degenerate_horizontal_is_safe() {
        // Coincident corners (no width) must not divide by zero.
        let lm = lm_with(&EAR_LEFT, [(5.0, 0.0); 6]);
        assert_eq!(eye_ear(&lm, &EAR_LEFT), 0.0);
    }
}
