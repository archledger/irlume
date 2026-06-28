//! Shared authentication orchestration — the one place the security-critical
//! pipeline lives. Both the CLI and the `irlumed` daemon drive this.
//!
//! Flow: capture RGB + IR (firing the IR emitter) → detect → align → embed (RGB)
//! and run the liveness gate on the cross-spectrum signals → on Live, match the
//! embedding against the user's enrolled templates at the fixed threshold.

use irlume_liveness::{LivenessGate, Signals, Verdict};
use irlume_vision::{align, Adapter, Detection, Detector, Embedder, Landmarks5, EMBED_DIM};

/// Auto-select the RGB+IR camera pair (built-in or external Hello webcam).
/// Re-exported so the daemon can pick devices without depending on the camera
/// crate directly. See [`irlume_camera::select_pair`].
pub use irlume_camera::select_pair;

/// Loaded models + camera device selection. Build once, reuse per request.
pub struct Engine {
    det: Detector,
    emb: Embedder,
    /// Optional IR domain-adaptation MLP (applied to IR embeddings in the dark).
    ir_adapter: Option<Adapter>,
    gate: LivenessGate,
    rgb_dev: String,
    ir_dev: String,
}

/// What one capture+assessment produced.
pub struct Assessment {
    pub verdict: Verdict,
    pub reason: String,
    /// RGB-face embedding (visible light) — the primary identity.
    pub embedding: Option<[f32; EMBED_DIM]>,
    /// IR-face embedding (for dark operation), if a face was found in IR —
    /// adapter-transformed (256-D) when the IR adapter is loaded, else raw 512-D.
    pub ir_embedding: Option<Vec<f32>>,
    pub signals: Signals,
    pub ir_depth: f32,
    pub ir_brightness: f32,
}

/// The authentication decision for a user.
pub struct Outcome {
    pub granted: bool,
    pub live: bool,
    pub score: f32,
    pub reason: String,
}

impl Engine {
    pub fn load(det_path: &str, model_path: &str) -> irlume_common::Result<Self> {
        Ok(Self {
            det: Detector::load_from_file(det_path)?,
            emb: Embedder::load_from_file(model_path)?,
            ir_adapter: None,
            gate: LivenessGate::new(),
            rgb_dev: irlume_camera::DEFAULT_RGB_DEVICE.into(),
            ir_dev: irlume_camera::DEFAULT_IR_DEVICE.into(),
        })
    }

    pub fn with_devices(mut self, rgb: &str, ir: &str) -> Self {
        self.rgb_dev = rgb.into();
        self.ir_dev = ir.into();
        self
    }

    /// Load the IR domain-adaptation adapter (improves dark recognition). If the
    /// file is absent this is a no-op (raw IR embeddings are used).
    pub fn with_ir_adapter(mut self, path: &str) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.ir_adapter = Some(Adapter::load_from_file(path)?);
        }
        Ok(self)
    }

    pub fn has_ir_adapter(&self) -> bool {
        self.ir_adapter.is_some()
    }

    /// One capture: RGB+IR → liveness verdict + (if a face) its embedding.
    pub fn assess(&mut self) -> irlume_common::Result<Assessment> {
        let rgb = irlume_camera::capture_rgb(&self.rgb_dev)?;
        let rgb_view = align::RgbView { data: &rgb.data, width: rgb.width, height: rgb.height };
        let rgb_faces = self.det.detect(&rgb_view)?;
        let rgb_top = rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)).cloned();

        let ir = irlume_camera::capture_ir(&self.ir_dev)?;
        let ir_grey_rgb = irlume_camera::grey_to_rgb(&ir.data);
        let ir_view = align::RgbView { data: &ir_grey_rgb, width: ir.width, height: ir.height };
        let ir_faces = self.det.detect(&ir_view)?;
        let ir_top = ir_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)).cloned();

        let fbox = |f: &Detection, w: u32, h: u32| irlume_liveness::FaceBox {
            cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
            cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
            score: f.score,
        };
        let ir_brightness = ir_top.as_ref().map(|f| mean_in_bbox(&ir.data, ir.width, ir.height, &f.bbox)).unwrap_or(0.0);
        let ir_depth = ir_top.as_ref().map(|f| center_edge_ratio(&ir.data, ir.width, ir.height, &f.bbox)).unwrap_or(0.0);
        // Head orientation from the RGB face landmarks (Windows-Hello-style
        // frontality gate). Defaults to frontal when there's no RGB face.
        let pose = rgb_top.as_ref().map(|f| irlume_vision::head_pose(&f.landmarks));
        let signals = Signals {
            rgb_face: rgb_top.as_ref().map(|f| fbox(f, rgb.width, rgb.height)),
            ir_face: ir_top.as_ref().map(|f| fbox(f, ir.width, ir.height)),
            ir_face_brightness: ir_brightness,
            ir_center_edge_ratio: ir_depth,
            ir_eye_glint: ir_top.as_ref().map(|f| eye_glint(&ir.data, ir.width, ir.height, &f.landmarks)).unwrap_or(0.0),
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
        };
        let (verdict, _cues, reason) = self.gate.evaluate(&signals);

        let embedding = match &rgb_top {
            Some(f) => {
                let chip = align::align_to_arcface(&rgb_view, &f.landmarks)?;
                Some(self.emb.embed(&chip)?)
            }
            None => None,
        };
        // IR-face embedding (for dark operation): align + embed the IR image,
        // then apply the domain-adaptation adapter if loaded.
        let ir_embedding = match &ir_top {
            Some(f) => {
                let chip = align::align_to_arcface(&ir_view, &f.landmarks)?;
                let raw = self.emb.embed(&chip)?;
                Some(match &mut self.ir_adapter {
                    Some(a) => a.apply(&raw)?,
                    None => raw.to_vec(),
                })
            }
            None => None,
        };
        Ok(Assessment { verdict, reason, embedding, ir_embedding, signals, ir_depth, ir_brightness })
    }

    /// Authenticate `user`: liveness gate FIRST (a spoof never reaches matching),
    /// then cosine match against enrolled templates at the fixed threshold.
    pub fn authenticate(&mut self, user: &str) -> irlume_common::Result<Outcome> {
        let Some(profile) = irlume_core::storage::load(user)? else {
            return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("'{user}' is not enrolled") });
        };
        let a = self.assess()?;
        let thr = irlume_core::RGB_MATCH_THRESHOLD;
        let best = |probe: &[f32], templates: &[Vec<f32>]| {
            templates.iter().map(|t| align::cosine(probe, t)).fold(f32::NEG_INFINITY, f32::max)
        };

        // Primary path: a visible-light (RGB) face -> full cross-spectrum gate +
        // RGB recognition.
        if let Some(probe) = a.embedding {
            if a.verdict != Verdict::Live {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("liveness {:?}: {}", a.verdict, a.reason) });
            }
            let score = best(&probe, &profile.templates);
            let granted = score >= thr;
            return Ok(Outcome { granted, live: true, score, reason: if granted { "match (rgb)".into() } else { "below threshold".into() } });
        }

        // Dark path: no RGB face, but an IR face -> IR-only liveness + IR
        // recognition (Windows-Hello-style dark operation).
        if let Some(probe) = a.ir_embedding {
            if profile.ir_templates.is_empty() {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason: "dark, but no IR enrollment — re-enroll to enable dark unlock".into() });
            }
            let (verdict, _cues, reason) = self.gate.evaluate_ir_only(&a.signals);
            if verdict != Verdict::Live {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("dark liveness {verdict:?}: {reason}") });
            }
            // IR mode threshold — adapted space if the adapter is loaded.
            let ir_thr = if self.ir_adapter.is_some() {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                irlume_core::IR_MATCH_THRESHOLD
            };
            let score = best(&probe, &profile.ir_templates);
            let granted = score >= ir_thr;
            return Ok(Outcome { granted, live: true, score, reason: if granted { "match (ir/dark)".into() } else { "below threshold (ir)".into() } });
        }

        Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("no face: {}", a.reason) })
    }

    /// Capture `want` LIVE samples and store them as `user`'s enrollment. Frames
    /// failing the liveness gate are rejected (no enrolling from a photo).
    pub fn enroll(&mut self, user: &str, want: usize) -> irlume_common::Result<usize> {
        let mut templates = Vec::new();
        let mut ir_templates = Vec::new();
        let (mut depths, mut brights) = (Vec::new(), Vec::new());
        for _ in 0..(want * 3) {
            if templates.len() >= want {
                break;
            }
            let a = self.assess()?;
            // Enroll on a Live (well-lit) capture so both RGB and IR templates
            // are clean; capture the IR template alongside for dark operation.
            if a.verdict == Verdict::Live {
                if let Some(e) = a.embedding {
                    templates.push(e.to_vec());
                    depths.push(a.ir_depth);
                    brights.push(a.ir_brightness);
                    if let Some(ir) = a.ir_embedding {
                        ir_templates.push(ir.to_vec());
                    }
                }
            }
        }
        if templates.len() < want {
            return Err(irlume_common::Error::Protocol(format!(
                "only {} live samples (need {want}) — check lighting and framing",
                templates.len()
            )));
        }
        let n = templates.len();
        irlume_core::storage::save(&irlume_core::storage::Profile {
            user: user.into(),
            templates,
            ir_templates,
            ir_depth_samples: depths,
            ir_brightness_samples: brights,
        })?;
        Ok(n)
    }
}

fn mean_in_bbox(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    let x1 = (bbox[0].max(0.0) as u32).min(w.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(h.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut sum, mut n) = (0u64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            sum += grey[(y * w + x) as usize] as u64;
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        sum as f32 / n as f32
    }
}

fn center_edge_ratio(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    let (bw, bh) = (bbox[2] - bbox[0], bbox[3] - bbox[1]);
    if bw <= 4.0 || bh <= 4.0 {
        return 0.0;
    }
    let inner = [bbox[0] + bw * 0.25, bbox[1] + bh * 0.25, bbox[2] - bw * 0.25, bbox[3] - bh * 0.25];
    let center = mean_in_bbox(grey, w, h, &inner);
    let whole = mean_in_bbox(grey, w, h, bbox);
    let edge = (whole - center * 0.25) / 0.75;
    if edge <= 1.0 {
        0.0
    } else {
        center / edge
    }
}

fn eye_glint(grey: &[u8], w: u32, h: u32, landmarks: &Landmarks5) -> f32 {
    let mut peak = 0u8;
    for &(ex, ey) in &landmarks[0..2] {
        let r = 8i32;
        for dy in -r..=r {
            for dx in -r..=r {
                let x = ex as i32 + dx;
                let y = ey as i32 + dy;
                if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                    peak = peak.max(grey[(y as u32 * w + x as u32) as usize]);
                }
            }
        }
    }
    peak as f32
}
