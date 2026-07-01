//! The ML pipeline: detect -> align -> embed. CPU-first ONNX via `ort`.
//!
//! Commercially-clean, GPL-3.0-compatible bill of materials (all permissive):
//!   * Detection  — YuNet  (MIT)      `face_detection_yunet_2023mar.onnx`
//!                  bbox + 5 landmarks; ~1.6 ms @320x320 on a laptop CPU.
//!   * Recognition— AuraFace (Apache) `glintr100.onnx`, ResNet100/ArcFace,
//!                  512-D embedding, 112x112 input, standard 5-point alignment.
//!
//! These bundle directly (`include_bytes!`) — no fetch-models step. Do NOT swap
//! in InsightFace buffalo_l/antelopev2 or YuNet's bundled SCRFD: their weights
//! are non-commercial, which CONFLICTS with GPL's downstream-commercial freedom.

pub mod align;
pub mod detect;
pub mod light;
pub mod moire;

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

/// Approximate head orientation from the 5 landmarks, with no 3D model — a 2D
/// heuristic for a frontality gate (Windows Hello uses a ±15° head-orientation
/// step). It rejects clearly off-angle presentations; it is *not* degree-
/// calibrated. `yaw_asym` and `pitch_frac` are scale-invariant (ratios).
#[derive(Debug, Clone, Copy)]
pub struct HeadPose {
    /// Horizontal nose asymmetry between the eyes: `|d(nose,left_eye) -
    /// d(nose,right_eye)| / (sum)`. ~0 frontal, →1 turned left/right.
    pub yaw_asym: f32,
    /// Nose's vertical position between the eye line and mouth line. ~0.5
    /// frontal; smaller looking down, larger looking up.
    pub pitch_frac: f32,
}

/// Estimate [`HeadPose`] from landmarks `[left_eye, right_eye, nose, left_mouth,
/// right_mouth]`. Defaults to frontal (0.0 / 0.5) on degenerate geometry.
pub fn head_pose(lm: &Landmarks5) -> HeadPose {
    let (le, re, nose, lmth, rmth) = (lm[0], lm[1], lm[2], lm[3], lm[4]);
    let (dl, dr) = ((nose.0 - le.0).abs(), (re.0 - nose.0).abs());
    let yaw_asym = if dl + dr > 1e-3 { (dl - dr).abs() / (dl + dr) } else { 0.0 };
    let eye_y = (le.1 + re.1) / 2.0;
    let span = (lmth.1 + rmth.1) / 2.0 - eye_y;
    let pitch_frac = if span.abs() > 1e-3 { (nose.1 - eye_y) / span } else { 0.5 };
    HeadPose { yaw_asym, pitch_frac }
}

#[cfg(test)]
mod head_pose_tests {
    use super::*;

    #[test]
    fn frontal_face_is_centered() {
        // ARCFACE reference geometry: nose centered between eyes, mid eye-mouth.
        let lm: Landmarks5 = [(20.0, 24.0), (44.0, 24.0), (32.0, 36.0), (24.0, 48.0), (40.0, 48.0)];
        let p = head_pose(&lm);
        assert!(p.yaw_asym < 0.05, "yaw {}", p.yaw_asym);
        assert!((p.pitch_frac - 0.5).abs() < 0.05, "pitch {}", p.pitch_frac);
    }

    #[test]
    fn turned_head_raises_yaw_asym() {
        // Nose shifted toward the left eye (head turned) -> high asymmetry.
        let lm: Landmarks5 = [(20.0, 24.0), (44.0, 24.0), (25.0, 36.0), (24.0, 48.0), (40.0, 48.0)];
        assert!(head_pose(&lm).yaw_asym > 0.35, "{}", head_pose(&lm).yaw_asym);
    }

    #[test]
    fn chin_down_lowers_pitch_frac() {
        // Nose near the eye line (looking down) -> small pitch fraction.
        let lm: Landmarks5 = [(20.0, 24.0), (44.0, 24.0), (32.0, 28.0), (24.0, 48.0), (40.0, 48.0)];
        assert!(head_pose(&lm).pitch_frac < 0.30, "{}", head_pose(&lm).pitch_frac);
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

    fn build(model: &[u8]) -> irlume_common::Result<Session> {
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
            Ok(Self { session: build(model)? })
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
        /// ONLY — on NIR it over-smooths the low-texture embedding (no EER gain,
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

        /// Embed AND return the PRE-normalization L2 norm of the raw feature — an
        /// AdaFace/MagFace-style quality proxy (clearer faces tend to produce
        /// larger feature norms; degraded/low-light faces smaller). The returned
        /// embedding is still L2-normalized; the norm is the quality signal for
        /// fusion weighting / low-quality gating. (AuraFace is ArcFace-trained, not
        /// AdaFace, so the norm↔quality correlation must be validated empirically.)
        pub fn embed_with_norm(&mut self, chip_rgb: &[u8]) -> irlume_common::Result<(Embedding, f32)> {
            let data = align::preprocess_arcface(chip_rgb);
            let n = align::OUT_SIZE as i64;
            let tensor = Tensor::from_array(([1i64, 3, n, n], data)).map_err(err)?;
            // Positional input (single-input model) — avoids needing the input name.
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

    /// IR embedding adapter (512→512) — the v3 residZero CLIP-adapter (out = x +
    /// 0.6·A(x), A zero-init) trained on NIR faces (CBSR+Oulu COMBINED, multi-sensor)
    /// that tightens IR genuine/impostor separation and generalizes across NIR
    /// cameras. Real-ASUS-validated vs the prior v1 (512→256) adapter: no regression
    /// and better on hard conditions (backlight/dark/motion), FRR@FAR1e-3 halved.
    /// Applied to AuraFace IR embeddings in the dark path. Output is L2-normalized.
    pub struct Adapter {
        session: Session,
    }

    impl Adapter {
        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Ok(Self { session: build(&bytes)? })
        }

        /// Adapt one IR embedding -> adapted vector (already L2-normalized).
        pub fn apply(&mut self, emb: &[f32]) -> irlume_common::Result<Vec<f32>> {
            let tensor = Tensor::from_array(([1i64, emb.len() as i64], emb.to_vec())).map_err(err)?;
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

    /// YuNet detector (ONNX). Loaded once in the daemon.
    pub struct Detector {
        #[allow(dead_code)]
        session: Session,
    }

    impl Detector {
        pub fn load_from_memory(model: &[u8]) -> irlume_common::Result<Self> {
            Ok(Self { session: build(model)? })
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
                let count = if ch == 0 { 0 } else { raw.len() / ch };
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
            Ok(dets)
        }
    }

    /// Resize+letterbox an RGB frame into a BGR, raw 0–255, NCHW input tensor for
    /// YuNet (top-left aligned; remainder zero-padded).
    fn letterbox_bgr(frame: &align::RgbView, scale: f32, size: usize) -> Vec<f32> {
        let mut t = vec![0.0f32; 3 * size * size];
        let plane = size * size;
        let (sw, sh) =
            ((frame.width as f32 * scale) as usize, (frame.height as f32 * scale) as usize);
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

    /// Phase-1 gate: embed the SAME aligned chip twice; cosine MUST be ~= 1.0.
    /// Validates that the ONNX path is deterministic and the preprocessing is
    /// wired correctly before any matching logic is trusted. Returns (passed,
    /// detail). A synthetic chip is sufficient — this checks the pipeline, not
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
        (passed, format!("cosine(same chip, twice) = {cos:.6} (want ~1.0)"))
    }
}

#[cfg(feature = "onnx")]
pub use onnx::{selftest_alignment_identity, Adapter, Detector, Embedder};
