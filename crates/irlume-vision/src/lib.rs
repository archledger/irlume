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
//! carries them via Git LFS, so there is no fetch-models step). Do NOT swap
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
        pub fn load_from_file(path: &str) -> irlume_common::Result<Self> {
            let bytes = std::fs::read(path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            Ok(Self {
                session: build(&bytes)?,
            })
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
        pub fn landmarks(
            &mut self,
            frame: &align::RgbView,
            bbox: &[f32; 4],
            margin: f32,
        ) -> irlume_common::Result<Vec<(f32, f32)>> {
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
            let count = raw.len() / 3;
            // Map input-space (0..side) coords back to the frame crop.
            let mut out = Vec::with_capacity(count);
            for k in 0..count {
                let lx = raw[3 * k] / self.input as f32 * side + x0;
                let ly = raw[3 * k + 1] / self.input as f32 * side + y0;
                out.push((lx, ly));
            }
            Ok(out)
        }
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
    /// in [-1,1] from a zero-padded square letterbox; outputs 896 SSD
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
            Ok(Some((
                [
                    (cx - bw / 2.0) * side,
                    (cy - bh / 2.0) * side,
                    (cx + bw / 2.0) * side,
                    (cy + bh / 2.0) * side,
                ],
                best_s,
            )))
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

        /// P(fake) for the face at `bbox` (frame pixel coords, [x1,y1,x2,y2]).
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
}

#[cfg(feature = "onnx")]
pub use onnx::{
    eye_ear, selftest_alignment_identity, Adapter, BlazeRescue, Detector, Embedder, FaceMesh,
    PadIr, BLAZE_SCORE_THRESHOLD, EAR_LEFT, EAR_RIGHT, MESH_INPUT, MESH_N, MESH_N_IRIS,
};

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
