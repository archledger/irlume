//! YuNet face-detection decode: anchor-free, strides 8/16/32.
//!
//! The pure decode (priors, score, bbox/landmark recovery, NMS) lives here and
//! is unit-tested without the model. `Detector::detect` (in the `onnx` module)
//! runs the session and feeds these. YuNet input is letterboxed BGR, raw 0–255,
//! NCHW; outputs per stride are cls(1) · obj(1) → score, bbox(4), kps(10).
//!
//! NOTE: validate the exact output layout against a real `face_detection_yunet`
//! model with `Detector::describe_io()` — but because score = √(cls·obj) is
//! symmetric and we group outputs by tensor shape, cls/obj order is irrelevant
//! and naming differences don't matter.

use crate::{Detection, Landmarks5};

pub const STRIDES: [usize; 3] = [8, 16, 32];
pub const INPUT_SIZE: usize = 640; // square letterbox; the 2023mar model's fixed input
pub const SCORE_THRESHOLD: f32 = 0.6;
pub const NMS_IOU: f32 = 0.3;

#[inline]
fn iou(a: &[f32; 4], b: &[f32; 4]) -> f32 {
    let x1 = a[0].max(b[0]);
    let y1 = a[1].max(b[1]);
    let x2 = a[2].min(b[2]);
    let y2 = a[3].min(b[3]);
    let inter = (x2 - x1).max(0.0) * (y2 - y1).max(0.0);
    let area_a = (a[2] - a[0]).max(0.0) * (a[3] - a[1]).max(0.0);
    let area_b = (b[2] - b[0]).max(0.0) * (b[3] - b[1]).max(0.0);
    let union = area_a + area_b - inter;
    if union <= 0.0 {
        0.0
    } else {
        inter / union
    }
}

/// Greedy non-maximum suppression; keeps highest-score boxes, drops overlaps.
pub fn nms(mut dets: Vec<Detection>, iou_thresh: f32) -> Vec<Detection> {
    dets.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut keep: Vec<Detection> = Vec::new();
    'outer: for d in dets {
        for k in &keep {
            if iou(&d.bbox, &k.bbox) > iou_thresh {
                continue 'outer;
            }
        }
        keep.push(d);
    }
    keep
}

/// Decode one stride's raw outputs into detections (in letterboxed-input coords).
///
/// `cls`/`obj` are length N (= feat_w·feat_h), `bbox` is N·4, `kps` is N·10.
/// Position idx maps to grid (row = idx/feat_w, col = idx%feat_w).
pub fn decode_stride(
    cls: &[f32],
    obj: &[f32],
    bbox: &[f32],
    kps: &[f32],
    stride: usize,
    feat_w: usize,
    score_thresh: f32,
) -> Vec<Detection> {
    let s = stride as f32;
    let mut out = Vec::new();
    for idx in 0..cls.len() {
        let score = (cls[idx].clamp(0.0, 1.0) * obj[idx].clamp(0.0, 1.0)).sqrt();
        if score < score_thresh {
            continue;
        }
        let (r, c) = ((idx / feat_w) as f32, (idx % feat_w) as f32);
        let cx = (c + bbox[idx * 4]) * s;
        let cy = (r + bbox[idx * 4 + 1]) * s;
        let w = bbox[idx * 4 + 2].exp() * s;
        let h = bbox[idx * 4 + 3].exp() * s;
        let (x1, y1) = (cx - w / 2.0, cy - h / 2.0);
        let mut lm: Landmarks5 = [(0.0, 0.0); 5];
        for (k, slot) in lm.iter_mut().enumerate() {
            *slot = (
                (c + kps[idx * 10 + 2 * k]) * s,
                (r + kps[idx * 10 + 2 * k + 1]) * s,
            );
        }
        out.push(Detection {
            bbox: [x1, y1, x1 + w, y1 + h],
            score,
            landmarks: lm,
        });
    }
    out
}

/// Letterbox scale to map a `w`×`h` frame into the square `INPUT_SIZE` input.
/// Pads at the bottom/right (offset 0,0), so back-mapping is a plain divide.
#[inline]
pub fn letterbox_scale(w: u32, h: u32) -> f32 {
    (INPUT_SIZE as f32 / w as f32).min(INPUT_SIZE as f32 / h as f32)
}

/// Map a detection from letterboxed-input coords back to original-frame coords.
pub fn unletterbox(det: &mut Detection, scale: f32) {
    let inv = 1.0 / scale;
    for v in det.bbox.iter_mut() {
        *v *= inv;
    }
    for p in det.landmarks.iter_mut() {
        p.0 *= inv;
        p.1 *= inv;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(b: [f32; 4], s: f32) -> Detection {
        Detection {
            bbox: b,
            score: s,
            landmarks: [(0.0, 0.0); 5],
        }
    }

    #[test]
    fn iou_basic() {
        let a = [0.0, 0.0, 2.0, 2.0];
        let b = [1.0, 1.0, 3.0, 3.0];
        assert!((iou(&a, &b) - (1.0 / 7.0)).abs() < 1e-5); // inter 1, union 7
        assert_eq!(iou(&a, &[10.0, 10.0, 11.0, 11.0]), 0.0);
    }

    #[test]
    fn nms_suppresses_overlap_keeps_distinct() {
        let dets = vec![
            det([0.0, 0.0, 2.0, 2.0], 0.9),
            det([0.1, 0.1, 2.1, 2.1], 0.8), // overlaps the first -> dropped
            det([10.0, 10.0, 12.0, 12.0], 0.7), // distinct -> kept
        ];
        let keep = nms(dets, 0.3);
        assert_eq!(keep.len(), 2);
        assert!((keep[0].score - 0.9).abs() < 1e-6);
    }

    #[test]
    fn decode_one_cell() {
        // Single 1x1 feature map at stride 8; all deltas 0.
        // center = (col+0)*8 = 0 ; w = exp(0)*8 = 8 ; x1 = 0 - 4 = -4.
        let cls = [1.0f32];
        let obj = [1.0f32];
        let bbox = [0.0f32, 0.0, 0.0, 0.0];
        let kps = [0.0f32; 10];
        let d = decode_stride(&cls, &obj, &bbox, &kps, 8, 1, 0.5);
        assert_eq!(d.len(), 1);
        assert!((d[0].bbox[0] - (-4.0)).abs() < 1e-4);
        assert!((d[0].bbox[2] - 4.0).abs() < 1e-4);
        assert!((d[0].score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn decode_respects_threshold() {
        let cls = [0.5f32, 0.9];
        let obj = [0.5f32, 0.9];
        let bbox = [0.0; 8];
        let kps = [0.0; 20];
        // scores: sqrt(.25)=.5 and sqrt(.81)=.9 ; threshold .6 keeps only the 2nd
        let d = decode_stride(&cls, &obj, &bbox, &kps, 8, 2, 0.6);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn unletterbox_roundtrip() {
        let scale = letterbox_scale(1280, 960); // 640/1280 = 0.5
        assert!((scale - 0.5).abs() < 1e-6);
        let mut d = det([10.0, 20.0, 30.0, 40.0], 0.9);
        d.landmarks[0] = (15.0, 25.0);
        unletterbox(&mut d, scale);
        assert!((d.bbox[0] - 20.0).abs() < 1e-4); // 10 / 0.5
        assert!((d.landmarks[0].0 - 30.0).abs() < 1e-4);
    }
}
