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
/// IR-emitter auto-setup (integrated linux-enable-ir-emitter), re-exported for
/// the daemon. See [`irlume_camera::setup_ir_emitter`].
pub use irlume_camera::{ensure_ir_emitter, list_ir_controls, setup_ir_emitter};

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
    /// Both eyes read open (IR corneal-glint heuristic). Used only when a profile
    /// opts into the require-eyes-open gate. `false` if eyes couldn't be verified.
    pub eyes_open: bool,
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

    /// The selected IR camera device path (for emitter auto-setup).
    pub fn ir_device(&self) -> &str {
        &self.ir_dev
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
        // Eyes-open (IR corneal-glint heuristic), for the opt-in require-eyes-open
        // gate. Needs an IR face (the emitter lights the cornea); conservative:
        // false when it can't be verified.
        let eyes_open = ir_top
            .as_ref()
            .map(|f| both_eyes_open(&ir.data, ir.width, ir.height, &f.landmarks))
            .unwrap_or(false);
        Ok(Assessment { verdict, reason, embedding, ir_embedding, signals, ir_depth, ir_brightness, eyes_open })
    }

    /// Authenticate `user`: liveness gate FIRST (a spoof never reaches matching),
    /// then 1:N cosine match against every scan in every enrolled face profile
    /// (any enrolled face unlocks). Threshold scales with the total scan count.
    pub fn authenticate(&mut self, user: &str) -> irlume_common::Result<Outcome> {
        let Some(enr) = irlume_core::storage::load(user)? else {
            return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("'{user}' is not enrolled") });
        };
        if enr.profiles.iter().all(|p| p.scans.is_empty()) {
            return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("'{user}' has no face scans enrolled") });
        }
        let a = self.assess()?;

        // Opt-in hard gate: never unlock unless both eyes read open.
        if enr.require_eyes_open && !a.eyes_open {
            return Ok(Outcome { granted: false, live: false, score: 0.0, reason: "eyes not detected open (require-eyes-open is on)".into() });
        }

        // best match over a labeled set of templates -> (score, profile name).
        let best = |probe: &[f32], scans: &[(&str, &str, &[f32])]| -> (f32, String) {
            scans
                .iter()
                .map(|(prof, _scan, t)| (align::cosine(probe, t), prof.to_string()))
                .fold((f32::NEG_INFINITY, String::new()), |acc, x| if x.0 > acc.0 { x } else { acc })
        };

        // Primary path: a visible-light (RGB) face -> full cross-spectrum gate +
        // RGB recognition across all profiles' scans.
        if let Some(probe) = a.embedding {
            if a.verdict != Verdict::Live {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("liveness {:?}: {}", a.verdict, a.reason) });
            }
            let scans = enr.rgb_scans();
            let thr = irlume_core::scaled_threshold(irlume_core::RGB_MATCH_THRESHOLD, scans.len());
            let (score, who) = best(&probe, &scans);
            let granted = score >= thr;
            return Ok(Outcome { granted, live: true, score, reason: if granted { format!("match: {who} (rgb)") } else { "below threshold".into() } });
        }

        // Dark path: no RGB face, but an IR face -> IR-only liveness + IR
        // recognition (Windows-Hello-style dark operation) across all profiles.
        if let Some(probe) = a.ir_embedding {
            let scans = enr.ir_scans();
            if scans.is_empty() {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason: "dark, but no IR scans enrolled — re-enroll to enable dark unlock".into() });
            }
            let (verdict, _cues, reason) = self.gate.evaluate_ir_only(&a.signals);
            if verdict != Verdict::Live {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("dark liveness {verdict:?}: {reason}") });
            }
            let ir_base = if self.ir_adapter.is_some() {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                irlume_core::IR_MATCH_THRESHOLD
            };
            let ir_thr = irlume_core::scaled_threshold(ir_base, scans.len());
            let (score, who) = best(&probe, &scans);
            let granted = score >= ir_thr;
            return Ok(Outcome { granted, live: true, score, reason: if granted { format!("match: {who} (ir/dark)") } else { "below threshold (ir)".into() } });
        }

        Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("no face: {}", a.reason) })
    }

    /// Capture `want` LIVE, frontal scans (best-effort, with a retry budget).
    /// Each Live capture yields one (rgb, ir, depth, brightness). No enrolling
    /// from a photo — the liveness gate rejects spoofs.
    fn capture_scans(&mut self, want: usize) -> irlume_common::Result<Vec<(Vec<f32>, Option<Vec<f32>>, f32, f32)>> {
        let mut out = Vec::new();
        for _ in 0..(want * 4) {
            if out.len() >= want {
                break;
            }
            let a = self.assess()?;
            if a.verdict == Verdict::Live {
                if let Some(e) = a.embedding {
                    out.push((e.to_vec(), a.ir_embedding.clone(), a.ir_depth, a.ir_brightness));
                }
            }
        }
        Ok(out)
    }

    /// Enroll a NEW face profile with `want` scans (capped at MAX_SCANS_PER_PROFILE).
    /// Errors if the account already has MAX_PROFILES. Returns (profile name, scans).
    pub fn enroll_profile(&mut self, user: &str, profile_name: Option<String>, want: usize) -> irlume_common::Result<(String, usize)> {
        use irlume_core::storage::{self, Enrollment, FaceProfile, FaceScan, MAX_PROFILES, MAX_SCANS_PER_PROFILE};
        let mut enr = storage::load(user)?.unwrap_or_else(|| Enrollment::new(user));
        if enr.profiles.len() >= MAX_PROFILES {
            return Err(irlume_common::Error::Protocol(format!("at the max of {MAX_PROFILES} face profiles — delete one first")));
        }
        let want = want.clamp(1, MAX_SCANS_PER_PROFILE);
        let name = profile_name.unwrap_or_else(|| enr.next_profile_name());
        if enr.profiles.iter().any(|p| p.name == name) {
            return Err(irlume_common::Error::Protocol(format!("a face profile named '{name}' already exists")));
        }
        let captured = self.capture_scans(want)?;
        if captured.len() < want {
            return Err(irlume_common::Error::Protocol(format!(
                "only {} live scans (need {want}) — check lighting and framing", captured.len()
            )));
        }
        // Anti-mixing: a new profile must be a face not already enrolled elsewhere.
        for (rgb, ..) in &captured {
            if let Some((other, score)) = colliding_profile(&enr, rgb, None) {
                let cnt = enr.profiles.iter().find(|p| p.name == other).map_or(0, |p| p.scans.len());
                let hint = if cnt < MAX_SCANS_PER_PROFILE {
                    format!("add scans to '{other}' (it has {cnt}/{MAX_SCANS_PER_PROFILE}) instead of a new profile")
                } else {
                    format!("'{other}' is already at the max {MAX_SCANS_PER_PROFILE} scans")
                };
                return Err(irlume_common::Error::Protocol(format!(
                    "this face is already enrolled as '{other}' (match {score:.2}) — {hint}"
                )));
            }
        }
        let mut prof = FaceProfile { name: name.clone(), scans: Vec::new() };
        for (rgb, ir, d, b) in captured {
            let sname = prof.next_scan_name();
            prof.scans.push(FaceScan { name: sname, rgb, ir, ir_depth: d, ir_brightness: b });
        }
        let n = prof.scans.len();
        enr.profiles.push(prof);
        storage::save(&enr)?;
        Ok((name, n))
    }

    /// Add one scan to an existing profile ("improve recognition"). Errors if the
    /// profile is missing or already at MAX_SCANS_PER_PROFILE.
    pub fn add_scan(&mut self, user: &str, profile_name: &str) -> irlume_common::Result<(String, usize)> {
        use irlume_core::storage::{self, FaceScan, MAX_SCANS_PER_PROFILE};
        let mut enr = storage::load(user)?.ok_or_else(|| irlume_common::Error::Protocol(format!("'{user}' is not enrolled")))?;
        let idx = enr.profiles.iter().position(|p| p.name == profile_name)
            .ok_or_else(|| irlume_common::Error::Protocol(format!("no face profile '{profile_name}'")))?;
        if enr.profiles[idx].scans.len() >= MAX_SCANS_PER_PROFILE {
            return Err(irlume_common::Error::Protocol(format!("'{profile_name}' already has the max {MAX_SCANS_PER_PROFILE} scans")));
        }
        let (rgb, ir, d, b) = self.capture_scans(1)?.into_iter().next()
            .ok_or_else(|| irlume_common::Error::Protocol("no live scan captured — check lighting and framing".into()))?;
        // Anti-mixing: reject a scan whose face belongs to a different profile.
        if let Some((other, score)) = colliding_profile(&enr, &rgb, Some(profile_name)) {
            let cnt = enr.profiles.iter().find(|p| p.name == other).map_or(0, |p| p.scans.len());
            let hint = if cnt < MAX_SCANS_PER_PROFILE {
                format!("if you want this face, add the scan to '{other}' (it has {cnt}/{MAX_SCANS_PER_PROFILE})")
            } else {
                format!("'{other}' is already at the max {MAX_SCANS_PER_PROFILE} scans")
            };
            return Err(irlume_common::Error::Protocol(format!(
                "the scanned face belongs to '{other}' (match {score:.2}), not '{profile_name}' — {hint}. \
                 Scans of different faces can't be mixed in one profile."
            )));
        }
        let sname = enr.profiles[idx].next_scan_name();
        enr.profiles[idx].scans.push(FaceScan { name: sname.clone(), rgb, ir, ir_depth: d, ir_brightness: b });
        let total = enr.profiles[idx].scans.len();
        storage::save(&enr)?;
        Ok((sname, total))
    }

}

/// Best-matching OTHER profile for `probe` (excluding `exclude`), if it reaches
/// the identity threshold — i.e. this face already belongs to a different
/// profile. Stops the same person's scans being split across profiles (which
/// would corrupt recognition and the 1:N unlock model).
fn colliding_profile(
    enr: &irlume_core::storage::Enrollment,
    probe: &[f32],
    exclude: Option<&str>,
) -> Option<(String, f32)> {
    let mut best: Option<(String, f32)> = None;
    for p in &enr.profiles {
        if Some(p.name.as_str()) == exclude {
            continue;
        }
        for s in &p.scans {
            let c = align::cosine(probe, &s.rgb);
            if c >= irlume_core::RGB_MATCH_THRESHOLD && best.as_ref().map_or(true, |b| c > b.1) {
                best = Some((p.name.clone(), c));
            }
        }
    }
    best
}

/// Per-eye open check (IR corneal-glint heuristic): an open eye reflects the
/// 850nm emitter as a bright specular point near the eye landmark; a closed
/// eyelid does not. Conservative — requires the glint, so an unverifiable eye
/// reads closed (auth falls back to password). Heuristic; used only when a
/// profile opts into the require-eyes-open gate.
const EYE_OPEN_PEAK_MIN: f32 = 200.0;

fn both_eyes_open(grey: &[u8], w: u32, h: u32, lm: &irlume_vision::Landmarks5) -> bool {
    let iod = ((lm[1].0 - lm[0].0).powi(2) + (lm[1].1 - lm[0].1).powi(2)).sqrt();
    let r = (iod * 0.20).max(2.0) as i32;
    eye_open_at(grey, w, h, lm[0], r) && eye_open_at(grey, w, h, lm[1], r)
}

fn eye_open_at(grey: &[u8], w: u32, h: u32, (ex, ey): (f32, f32), r: i32) -> bool {
    let (cx, cy) = (ex as i32, ey as i32);
    let mut peak = 0u8;
    for dy in -r..=r {
        for dx in -r..=r {
            let (x, y) = (cx + dx, cy + dy);
            if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                peak = peak.max(grey[(y as u32 * w + x as u32) as usize]);
            }
        }
    }
    peak as f32 >= EYE_OPEN_PEAK_MIN
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

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};

    fn scan(v: Vec<f32>) -> FaceScan {
        FaceScan { name: "s".into(), rgb: v, ir: None, ir_depth: 0.0, ir_brightness: 0.0 }
    }

    #[test]
    fn collision_blocks_same_face_in_another_profile() {
        let face1 = vec![1.0, 0.0, 0.0];
        let face2 = vec![0.0, 1.0, 0.0];
        let enr = Enrollment {
            user: "u".into(),
            require_eyes_open: false,
            profiles: vec![
                FaceProfile { name: "Face Profile 1".into(), scans: vec![scan(face1.clone())] },
                FaceProfile { name: "Face Profile 2".into(), scans: vec![scan(face2.clone())] },
            ],
        };
        // Adding face1 under Face Profile 2 -> flagged as belonging to Profile 1.
        assert_eq!(
            colliding_profile(&enr, &face1, Some("Face Profile 2")).map(|(n, _)| n),
            Some("Face Profile 1".to_string())
        );
        // A novel face collides with nothing.
        assert!(colliding_profile(&enr, &[0.0, 0.0, 1.0], None).is_none());
        // Same face into its OWN profile (excluded) is fine — that's improving it.
        assert!(colliding_profile(&enr, &face1, Some("Face Profile 1")).is_none());
    }
}
