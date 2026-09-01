// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Full-range BlazeFace on the native TFLite runtime (#295 stage 2).
//!
//! The candidate the #294 live bench measured at 100% detection on every
//! segment of the two-camera corpus through the official runtime, including
//! the far-IR frames the short-range rescue misses at 0%. Runs Google's
//! published artifact byte-for-byte (no conversion), pinned by sha256.
//!
//! Contract, measured from the flatbuffer and MediaPipe's own graph config
//! rather than the model card (whose stated input size is wrong): input
//! `[1,192,192,3]` f32 in `[-1,1]`; outputs `[1,2304,16]` anchor-relative
//! regressors (4 box values + 6 keypoints x 2) and `[1,2304,1]` logits.
//! Decode per `face_detection_full_range.pbtxt`: one layer at stride 4 (a
//! 48x48 grid, one anchor per cell), x/y/w/h scales all 192, and
//! MediaPipe's operating floor 0.6. The preprocessing (square zero-pad
//! letterbox, center-of-pixel sampling, `[-1,1]`) matches the short-range
//! rescue exactly, whose decode was parity-tested against the official
//! runtime at 0.94 IoU; the same parity bar applies to this decoder before
//! any catalog entry cites it.

use crate::model_input::{FullRangeBlazeFaceInput, ModelInputContractId};
use crate::tflite::TfliteSession;

/// Pin of `blaze_face_full_range.tflite` from the versioned
/// `.../blaze_face_full_range/float16/1/` URL (#295). Apache-2.0 weights,
/// consented first-party training data per the model card (read 2026-08-05).
pub const FULL_RANGE_BLAZE_SHA256: &str =
    "3698b18f063835bc609069ef052228fbe86d9c9a6dc8dcb7c7c2d69aed2b181b";

/// Square input side (measured from the flatbuffer; the card says 160x192
/// and is wrong).
pub const FULL_RANGE_INPUT: usize = 192;

/// 48x48 grid at stride 4, one anchor per cell.
const FULL_RANGE_CELLS: usize = 48;
const FULL_RANGE_ANCHORS: usize = FULL_RANGE_CELLS * FULL_RANGE_CELLS;

/// MediaPipe's own `min_score_thresh` for this model. The OPERATING
/// threshold for any catalog entry is measured through irlume's pipeline in
/// stage 3; this constant exists so the decoder's default is the
/// publisher's, not a guess.
pub const FULL_RANGE_SCORE_THRESHOLD: f32 = 0.6;

/// Anchor centers in normalized coordinates, row-major, matching the
/// SSD anchor generation for `num_layers 1, strides [4]` with one anchor
/// per cell (`interpolated_scale_aspect_ratio 0.0`).
fn full_range_anchors() -> Vec<(f32, f32)> {
    let mut a = Vec::with_capacity(FULL_RANGE_ANCHORS);
    for r in 0..FULL_RANGE_CELLS {
        for c in 0..FULL_RANGE_CELLS {
            a.push((
                (c as f32 + 0.5) / FULL_RANGE_CELLS as f32,
                (r as f32 + 0.5) / FULL_RANGE_CELLS as f32,
            ));
        }
    }
    a
}

/// Decode the best detection from raw model output, in NORMALIZED square
/// coordinates: `Some((bbox, score))` with bbox `[x1,y1,x2,y2]` in `[0,1]`
/// of the letterboxed square, or `None` when nothing clears `floor`.
///
/// Pure so the whole decision is testable with synthetic tensors: anchor
/// mapping, the sigmoid clip, the floor, and the non-finite refusal (a NaN
/// regressor with a confident logit must be a non-detection, the same rule
/// the short-range path enforces).
pub fn decode_full_range_best(
    reg: &[f32],
    cls: &[f32],
    anchors: &[(f32, f32)],
    floor: f32,
) -> Option<([f32; 4], f32)> {
    let scale = FULL_RANGE_INPUT as f32;
    let mut best: Option<([f32; 4], f32)> = None;
    for (i, &logit) in cls.iter().enumerate() {
        let score = 1.0 / (1.0 + (-logit.clamp(-100.0, 100.0)).exp());
        // `NaN < floor` is FALSE, so a NaN logit sails through a plain floor
        // comparison and can leave the function returning a NaN score as a
        // "detection" (#298 review). Non-finite scores are refused like
        // non-finite boxes.
        if !score.is_finite() || score < floor || best.is_some_and(|(_, s)| score <= s) {
            continue;
        }
        let r = reg.get(i * 16..i * 16 + 16)?;
        let (ax, ay) = *anchors.get(i)?;
        let (cx, cy) = (ax + r[0] / scale, ay + r[1] / scale);
        let (w, h) = (r[2] / scale, r[3] / scale);
        let bbox = [cx - w / 2.0, cy - h / 2.0, cx + w / 2.0, cy + h / 2.0];
        if !bbox.iter().all(|v| v.is_finite()) {
            continue;
        }
        best = Some((bbox, score));
    }
    best
}

/// Full-range BlazeFace detector backed by the native TFLite runtime.
pub struct FullRangeBlaze {
    session: TfliteSession,
    anchors: Vec<(f32, f32)>,
}

impl FullRangeBlaze {
    /// Load from model bytes; the pin is enforced by the session
    /// constructor, and the tensor contract is verified here so a wrong
    /// (but correctly pinned) artifact fails at load, not at decode.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn from_pinned_bytes(bytes: &[u8]) -> irlume_common::Result<Self> {
        let session = TfliteSession::from_pinned_bytes(bytes, FULL_RANGE_BLAZE_SHA256, 2)?;
        let shape = session.input_shape()?;
        if shape != [1, FULL_RANGE_INPUT, FULL_RANGE_INPUT, 3] {
            return Err(irlume_common::Error::Hardware(format!(
                "full-range blaze: unexpected input shape {shape:?}"
            )));
        }
        Ok(Self {
            session,
            anchors: full_range_anchors(),
        })
    }

    /// Best face in `input`, as `(bbox in frame pixels, score)`, or `None`.
    ///
    /// Preprocessing matches the short-range rescue: square zero-pad
    /// letterbox to the larger frame side, center-of-pixel bilinear
    /// sampling, `[-1,1]` normalization.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn detect_top(
        &mut self,
        input: &FullRangeBlazeFaceInput,
    ) -> irlume_common::Result<Option<([f32; 4], f32)>> {
        self.detect_top_at(input, FULL_RANGE_SCORE_THRESHOLD)
    }

    /// [`Self::detect_top`] at an explicit floor. Exists for MEASUREMENT:
    /// setting an operating threshold needs the sub-floor score
    /// distribution (what an empty room scores), which the default floor
    /// hides by design.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn detect_top_at(
        &mut self,
        input: &FullRangeBlazeFaceInput,
        floor: f32,
    ) -> irlume_common::Result<Option<([f32; 4], f32)>> {
        input
            .require(ModelInputContractId::BlazeFaceFullRangeLetterbox192V1)
            .map_err(irlume_common::Error::from)?;
        let side = input.frame_side();
        let outputs = self.session.run_f32(input.tensor())?;
        // Identify the two heads by element count, order-agnostic, same as
        // the short-range path.
        let (mut reg, mut cls): (Option<&[f32]>, Option<&[f32]>) = (None, None);
        for (shape, values) in &outputs {
            let len: usize = shape.iter().product();
            if len == FULL_RANGE_ANCHORS * 16 {
                reg = Some(values);
            } else if len == FULL_RANGE_ANCHORS {
                cls = Some(values);
            }
        }
        let (Some(reg), Some(cls)) = (reg, cls) else {
            return Err(irlume_common::Error::Hardware(
                "full-range blaze: unexpected output tensors".into(),
            ));
        };
        Ok(decode_full_range_best(reg, cls, &self.anchors, floor)
            .map(|(b, s)| ([b[0] * side, b[1] * side, b[2] * side, b[3] * side], s)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_are_the_48_grid_one_per_cell() {
        let a = full_range_anchors();
        assert_eq!(a.len(), 2304);
        let eps = 1e-6;
        assert!((a[0].0 - 0.5 / 48.0).abs() < eps && (a[0].1 - 0.5 / 48.0).abs() < eps);
        assert!((a[2303].0 - 47.5 / 48.0).abs() < eps && (a[2303].1 - 47.5 / 48.0).abs() < eps);
        // Row-major: the second anchor advances in x, not y.
        assert!((a[1].0 - 1.5 / 48.0).abs() < eps && (a[1].1 - 0.5 / 48.0).abs() < eps);
        assert!(a
            .iter()
            .all(|&(x, y)| (0.0..1.0).contains(&x) && (0.0..1.0).contains(&y)));
    }

    #[test]
    fn decode_places_a_confident_detection_at_its_anchor() {
        let mut cls = vec![-100.0f32; 2304];
        let mut reg = vec![0.0f32; 2304 * 16];
        // Anchor (row 10, col 20): center (20.5/48, 10.5/48). Offsets +9.6px
        // and a 48x38.4px box in input space.
        let i = 10 * 48 + 20;
        cls[i] = 2.0; // sigmoid = 0.881
        reg[i * 16] = 9.6;
        reg[i * 16 + 1] = -9.6;
        reg[i * 16 + 2] = 48.0;
        reg[i * 16 + 3] = 38.4;
        let (bbox, score) =
            decode_full_range_best(&reg, &cls, &full_range_anchors(), 0.6).expect("detects");
        assert!((score - 0.8808).abs() < 1e-3, "{score}");
        let (cx, cy) = (20.5 / 48.0 + 0.05, 10.5 / 48.0 - 0.05);
        assert!((bbox[0] - (cx - 0.125)).abs() < 1e-5, "{bbox:?}");
        assert!((bbox[1] - (cy - 0.1)).abs() < 1e-5, "{bbox:?}");
        assert!((bbox[2] - (cx + 0.125)).abs() < 1e-5, "{bbox:?}");
        assert!((bbox[3] - (cy + 0.1)).abs() < 1e-5, "{bbox:?}");
    }

    #[test]
    fn decode_refuses_the_floor_nan_and_prefers_the_higher_score() {
        let anchors = full_range_anchors();
        // Nothing above the floor: no detection.
        let cls = vec![-1.0f32; 2304]; // sigmoid 0.269 < 0.6
        let reg = vec![0.0f32; 2304 * 16];
        assert!(decode_full_range_best(&reg, &cls, &anchors, 0.6).is_none());
        // A NaN regressor with the BEST logit must not become the answer,
        // and must not shadow a finite runner-up (the short-range rule).
        let mut cls = vec![-100.0f32; 2304];
        let mut reg = vec![0.0f32; 2304 * 16];
        cls[7] = 5.0;
        reg[7 * 16] = f32::NAN;
        cls[9] = 2.0;
        reg[9 * 16 + 2] = 24.0;
        reg[9 * 16 + 3] = 24.0;
        let (bbox, score) =
            decode_full_range_best(&reg, &cls, &anchors, 0.6).expect("finite runner-up wins");
        assert!((score - 0.8808).abs() < 1e-3, "{score}");
        assert!(bbox.iter().all(|v| v.is_finite()));
        // A NaN LOGIT alone must be no detection at all, and must not mask
        // a finite runner-up (NaN survives the clamp and the sigmoid).
        let mut cls = vec![-100.0f32; 2304];
        cls[5] = f32::NAN;
        let reg = vec![0.0f32; 2304 * 16];
        assert!(decode_full_range_best(&reg, &cls, &anchors, 0.6).is_none());
        let mut cls = vec![-100.0f32; 2304];
        cls[5] = f32::NAN;
        cls[9] = 2.0;
        let mut reg = vec![0.0f32; 2304 * 16];
        reg[9 * 16 + 2] = 24.0;
        reg[9 * 16 + 3] = 24.0;
        let (_, score) =
            decode_full_range_best(&reg, &cls, &anchors, 0.6).expect("finite candidate wins");
        assert!(score.is_finite());
        // The sigmoid clip keeps an extreme logit from overflowing.
        let mut cls = vec![-100.0f32; 2304];
        cls[3] = 1e30;
        let mut reg = vec![0.0f32; 2304 * 16];
        reg[3 * 16 + 2] = 10.0;
        reg[3 * 16 + 3] = 10.0;
        let (_, score) = decode_full_range_best(&reg, &cls, &anchors, 0.6).expect("clipped");
        assert!((score - 1.0).abs() < 1e-6);
    }
}
