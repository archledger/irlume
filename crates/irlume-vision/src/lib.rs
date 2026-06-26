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

/// 5 facial landmarks (left eye, right eye, nose, left mouth, right mouth),
/// in pixel coordinates of the source frame. Output by the detector.
pub type Landmarks5 = [(f32, f32); 5];

/// A detected face.
pub struct Detection {
    pub bbox: [f32; 4], // x1, y1, x2, y2
    pub score: f32,
    pub landmarks: Landmarks5,
}

/// L2-normalized face embedding. 512 dims for AuraFace.
pub const EMBED_DIM: usize = 512;
pub type Embedding = [f32; EMBED_DIM];

/// YuNet detector (ONNX). Loaded once in the daemon.
pub struct Detector { /* TODO: ort::Session */ }

impl Detector {
    pub fn load() -> irlume_common::Result<Self> {
        // TODO: load bundled YuNet ONNX via ort; GraphOpt Level3; cache session.
        todo!()
    }
    pub fn detect(&self, _frame: &irlume_camera::Frame) -> irlume_common::Result<Vec<Detection>> {
        todo!()
    }
}

/// AuraFace embedder (ONNX). Loaded once in the daemon.
pub struct Embedder { /* TODO: ort::Session */ }

impl Embedder {
    pub fn load() -> irlume_common::Result<Self> {
        todo!()
    }

    /// Embed an already-aligned 112x112 chip.
    ///
    /// PREPROCESSING MUST MATCH AuraFace/InsightFace exactly or genuine pairs
    /// collapse (the "identical images score 0.6" symptom): BGR channel order,
    /// (px-127.5)/128.0 normalization, NCHW, then L2-normalize the output.
    pub fn embed(&self, _chip112: &[u8]) -> irlume_common::Result<Embedding> {
        todo!()
    }
}
