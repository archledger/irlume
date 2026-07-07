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
pub use irlume_camera::{capabilities, select_pair};
/// IR-emitter auto-setup (integrated linux-enable-ir-emitter), re-exported for
/// the daemon. See [`irlume_camera::setup_ir_emitter`].
pub use irlume_camera::{ensure_ir_emitter, list_ir_controls, setup_ir_emitter};

/// Loaded models + camera device selection. Build once, reuse per request.
pub struct Engine {
    det: Detector,
    emb: Embedder,
    /// Optional IR domain-adaptation MLP (applied to IR embeddings in the dark).
    ir_adapter: Option<Adapter>,
    /// Optional MediaPipe FaceMesh — dense landmarks for the passive EAR blink
    /// liveness (ADR-0002). Loaded iff the model file is present; `None` disables
    /// the opt-in passive-liveness gate (it can't run without landmarks).
    mesh: Option<irlume_vision::FaceMesh>,
    gate: LivenessGate,
    rgb_dev: String,
    ir_dev: String,
    /// Smart-Auto: true when a real RGB+IR Hello camera is present. False = an
    /// RGB-only device → face runs in CONVENIENCE tier (lock-screen unlock only,
    /// RGB-only liveness, never releases credentials / logs in / elevates).
    ir_available: bool,
}

/// Assurance tier of this engine, derived from the available camera hardware.
pub use irlume_core::biopolicy::Tier;

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

/// The result of a 1:N identification ("who is this?"). `user`/`profile` are set
/// only on a live, above-threshold match against some enrolled face.
pub struct IdentifyOutcome {
    pub user: Option<String>,
    pub profile: Option<String>,
    pub score: f32,
    pub live: bool,
    pub reason: String,
}

impl Engine {
    pub fn load(det_path: &str, model_path: &str) -> irlume_common::Result<Self> {
        Ok(Self {
            det: Detector::load_from_file(det_path)?,
            emb: Embedder::load_from_file(model_path)?,
            ir_adapter: None,
            mesh: None,
            gate: LivenessGate::new(),
            rgb_dev: irlume_camera::DEFAULT_RGB_DEVICE.into(),
            ir_dev: irlume_camera::DEFAULT_IR_DEVICE.into(),
            ir_available: irlume_camera::capabilities().ir_pair,
        })
    }

    /// Assurance tier from the hardware: `Secure` with a real RGB+IR camera,
    /// `Convenience` on an RGB-only device.
    pub fn tier(&self) -> Tier {
        if self.ir_available { Tier::Secure } else { Tier::Convenience }
    }

    /// Whether a real IR+RGB Hello camera is present (full face auth available).
    pub fn ir_available(&self) -> bool {
        self.ir_available
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

    /// The selected RGB camera device path.
    pub fn rgb_device(&self) -> &str {
        &self.rgb_dev
    }

    /// Switch the active camera pair at runtime (TUI camera picker). The next
    /// capture uses the new devices.
    pub fn set_devices(&mut self, rgb: &str, ir: &str) {
        self.rgb_dev = rgb.into();
        self.ir_dev = ir.into();
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

    /// Load MediaPipe FaceMesh for the passive EAR blink liveness (ADR-0002). If
    /// the file is absent this is a no-op — the opt-in passive gate then can't run
    /// and is skipped (logged), so face auth keeps working.
    pub fn with_mesh(mut self, path: &str) -> irlume_common::Result<Self> {
        if std::path::Path::new(path).exists() {
            self.mesh = Some(irlume_vision::FaceMesh::load_from_file(path)?);
        }
        Ok(self)
    }

    pub fn has_mesh(&self) -> bool {
        self.mesh.is_some()
    }

    /// One capture: RGB+IR → liveness verdict + (if a face) its embedding.
    /// Capture + assess, choosing the path from the hardware: full cross-spectrum
    /// (RGB+IR) when an IR camera is present, else RGB-only (convenience).
    pub fn assess(&mut self) -> irlume_common::Result<Assessment> {
        if self.ir_available { self.assess_full() } else { self.assess_rgb_only() }
    }

    /// RGB-only capture + algorithmic (no-IR) liveness — the convenience-tier
    /// path for devices without an IR camera. Anti-spoof here is DETERRENT-grade
    /// (well-lit + frontal + screen/glare heuristic), which is why this tier is
    /// limited to lock-screen unlock and never releases credentials.
    fn assess_rgb_only(&mut self) -> irlume_common::Result<Assessment> {
        let rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev)?;
        let rgb_view = align::RgbView { data: &rgb.data, width: rgb.width, height: rgb.height };
        let rgb_faces = self.det.detect(&rgb_view)?;
        let rgb_top = rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)).cloned();
        let (rgb_brightness, rgb_specular) = rgb_top
            .as_ref()
            .map(|f| rgb_luma_stats(&rgb.data, rgb.width, rgb.height, &f.bbox))
            .unwrap_or((0.0, 0.0));
        // 2D-FFT moiré / pixel-grid cue (screen-replay deterrent).
        let rgb_moire = rgb_top
            .as_ref()
            .map(|f| irlume_vision::moire::moire_score(
                &irlume_vision::moire::face_gray_n(&rgb.data, rgb.width, rgb.height, &f.bbox)))
            .unwrap_or(0.0);
        let pose = rgb_top.as_ref().map(|f| irlume_vision::head_pose(&f.landmarks));
        let signals = Signals {
            rgb_face: rgb_top.as_ref().map(|f| irlume_liveness::FaceBox {
                cx: (f.bbox[0] + f.bbox[2]) / 2.0 / rgb.width as f32,
                cy: (f.bbox[1] + f.bbox[3]) / 2.0 / rgb.height as f32,
                score: f.score,
            }),
            ir_face: None,
            ir_face_brightness: 0.0,
            ir_center_edge_ratio: 0.0,
            ir_eye_glint: 0.0,
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            rgb_face_brightness: rgb_brightness,
            rgb_specular_frac: rgb_specular,
            rgb_moire_score: rgb_moire,
        };
        let (verdict, _cues, reason) = self.gate.evaluate_rgb_only(&signals);
        irlume_common::dlog!("liveness(rgb-only): {verdict:?} ({reason}); bright={:.0} specular={:.2} moire={:.0}",
            signals.rgb_face_brightness, signals.rgb_specular_frac, signals.rgb_moire_score);
        let embedding = match &rgb_top {
            Some(f) => Some(self.emb.embed_tta(&align::align_to_arcface(&rgb_view, &f.landmarks)?)?),
            None => None,
        };
        Ok(Assessment { verdict, reason, embedding, ir_embedding: None, signals, ir_depth: 0.0, ir_brightness: 0.0, eyes_open: false })
    }

    fn assess_full(&mut self) -> irlume_common::Result<Assessment> {
        // Median-denoise the RGB frame so a single blurry/over-exposed frame
        // can't false-reject a genuine user (IR is already brightest-of-burst).
        let t = std::time::Instant::now();
        let rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev)?;
        let rgb_ms = t.elapsed().as_millis();
        let rgb_view = align::RgbView { data: &rgb.data, width: rgb.width, height: rgb.height };
        let rgb_faces = self.det.detect(&rgb_view)?;
        let rgb_top = rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)).cloned();
        irlume_common::dlog!("assess: rgb {}x{} in {rgb_ms}ms, faces={} top-det={:.2}",
            rgb.width, rgb.height, rgb_faces.len(), rgb_top.as_ref().map(|f| f.score).unwrap_or(0.0));

        let t = std::time::Instant::now();
        let ir = irlume_camera::capture_ir(&self.ir_dev)?;
        let ir_ms = t.elapsed().as_millis();
        let ir_grey_rgb = irlume_camera::grey_to_rgb(&ir.data);
        let ir_view = align::RgbView { data: &ir_grey_rgb, width: ir.width, height: ir.height };
        let ir_faces = self.det.detect(&ir_view)?;
        let ir_top = ir_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)).cloned();
        irlume_common::dlog!("assess: ir {}x{} in {ir_ms}ms, faces={} top-det={:.2}",
            ir.width, ir.height, ir_faces.len(), ir_top.as_ref().map(|f| f.score).unwrap_or(0.0));

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
            rgb_face_brightness: 0.0, // IR path doesn't use the RGB-PAD cues
            rgb_moire_score: 0.0,
            rgb_specular_frac: 0.0,
        };
        let (verdict, _cues, reason) = self.gate.evaluate(&signals);
        // Log the cue values on PASS too — a near-miss on a genuine user is
        // invisible in the outcome line but obvious here.
        irlume_common::dlog!(
            "liveness(cross-spectrum): {verdict:?} ({reason}); ir_bright={:.0} ir_depth={:.2} glint={:.2} yaw_asym={:.2} pitch={:.2}",
            signals.ir_face_brightness, signals.ir_center_edge_ratio, signals.ir_eye_glint,
            signals.head_yaw_asym, signals.head_pitch_frac);

        let embedding = match &rgb_top {
            Some(f) => {
                let chip = align::align_to_arcface(&rgb_view, &f.landmarks)?;
                Some(self.emb.embed_tta(&chip)?) // TTA flip-average (RGB only; cuts FRR)
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

    /// Passive blink liveness (opt-in, ADR-0002): capture a short IR sequence and
    /// look for a NATURAL blink via EAR — no prompt, no deliberate action. Per frame
    /// we run FaceMesh (from the detected face crop) and take the smaller eye's EAR;
    /// [`irlume_liveness::detect_blink`] then finds a dip below the open baseline. A
    /// static print holds EAR flat and never dips. Live-validated 2026-07-01: genuine
    /// natural blink → Blinked, static vinyl banner → NoBlink.
    fn run_passive_liveness(&mut self) -> irlume_common::Result<irlume_liveness::BlinkResult> {
        // Raw frame rate (~15 fps, no de-strobe burst): the detector separates
        // emitter-lit from ambient-only frames itself, and a ~150 ms natural blink
        // spans only 2–3 raw frames — halving the rate loses it (measured 2026-07-01).
        const SAMPLES: usize = 75; // ~5s window
        const BURST: usize = 1;
        let Some(mesh) = self.mesh.as_mut() else {
            // No landmark model: can't run the passive gate. Signal NoEyes so the
            // caller can decide (challenge_if_required skips when mesh is absent).
            return Ok(irlume_liveness::BlinkResult::NoEyes);
        };
        let frames = irlume_camera::capture_ir_sequence(&self.ir_dev, SAMPLES, BURST)?;
        // Per-frame EAR (smaller eye). Frames with no detected face carry ear=None
        // (a missed detection must not masquerade as a blink) but keep their
        // brightness so the detector can classify the emitter strobe.
        let mut samples = Vec::with_capacity(frames.len());
        for (i, f) in frames.iter().enumerate() {
            let bri = f.data.iter().map(|&p| p as f32).sum::<f32>() / f.data.len().max(1) as f32;
            let grey_rgb = irlume_camera::grey_to_rgb(&f.data);
            let view = align::RgbView { data: &grey_rgb, width: f.width, height: f.height };
            let mut ear = None;
            if let Some(t) = self.det.detect(&view)?.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
                let lm = mesh.landmarks(&view, &t.bbox, 0.25)?;
                let l = irlume_vision::eye_ear(&lm, &irlume_vision::EAR_LEFT);
                let r = irlume_vision::eye_ear(&lm, &irlume_vision::EAR_RIGHT);
                ear = Some(l.min(r));
            }
            samples.push(irlume_liveness::EarSample { idx: i, ear, bri });
        }
        Ok(irlume_liveness::detect_blink(&samples))
    }

    /// If the user opted into passive liveness and we're about to grant, require a
    /// natural blink before releasing anything. Failure downgrades to a non-grant
    /// with an Uncertain-style reason (PAM cascades to the password fallback — never
    /// a lockout). No-op unless the outcome is a grant, the flag is on, IR is
    /// available, and the FaceMesh model is loaded (else the gate can't run — we log
    /// and skip rather than lock the user out of an undeployed model).
    fn challenge_if_required(
        &mut self,
        enr: &irlume_core::storage::Enrollment,
        outcome: Outcome,
    ) -> irlume_common::Result<Outcome> {
        if !outcome.granted || !enr.require_challenge || !self.ir_available {
            return Ok(outcome);
        }
        if self.mesh.is_none() {
            eprintln!("irlumed: passive liveness (require-challenge) is on but face_landmark.onnx is not loaded — skipping (set IRLUME_MESH_MODEL)");
            return Ok(outcome);
        }
        use irlume_liveness::BlinkResult;
        Ok(match self.run_passive_liveness()? {
            BlinkResult::Blinked => outcome,
            BlinkResult::NoBlink => Outcome {
                granted: false, live: true, score: outcome.score,
                reason: "passive liveness: no natural blink in the window — look at the camera a moment longer".into(),
            },
            BlinkResult::NoEyes => Outcome {
                granted: false, live: false, score: outcome.score,
                reason: "passive liveness: no live eyes (looks like a print/no face)".into(),
            },
        })
    }

    /// Authenticate `user`: liveness gate FIRST (a spoof never reaches matching),
    /// then 1:N cosine match against every scan in every enrolled face profile
    /// (any enrolled face unlocks). Threshold scales with the total scan count.
    pub fn authenticate(&mut self, user: &str) -> irlume_common::Result<Outcome> {
        // Fingerprint mode: face is disabled so pam_fprintd drives — never engage
        // the camera, decline so the PAM stack cascades to fingerprint/password.
        if irlume_core::policy::method().face_disabled() {
            return Ok(Outcome { granted: false, live: false, score: 0.0, reason: "face disabled (fingerprint mode)".into() });
        }
        let Some(enr) = irlume_core::storage::load(user)? else {
            return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("'{user}' is not enrolled") });
        };
        if enr.profiles.iter().all(|p| p.scans.is_empty()) {
            return Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("'{user}' has no face scans enrolled") });
        }
        // Anti-swap: refuse if the live camera no longer matches the one this
        // user enrolled on (only enforced once an enrollment carries a binding).
        if let Some(bind) = &enr.camera_binding {
            if let Some(reason) = self.binding_mismatch(bind) {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason });
            }
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
            // Per-user IR-liveness DEPTH floor (anti-screen/photo, calibrated to
            // this user's enrolled 3D face structure): the live frame must clear the
            // enrolled depth floor. Depth only — a per-user IR *brightness* floor was
            // removed because IR face brightness is ambient-dependent (emitter-only
            // ~40 in the dark vs ~140 lit) and a lit-enrollment floor false-rejected
            // genuine dim/night logins as "screen/photo". The global gate above
            // (`evaluate`) already enforces an ambient-robust IR brightness floor.
            // Only meaningful when IR was actually captured (skip on RGB-only).
            if let Some(depth_floor) = enr.ir_calibration().filter(|_| self.ir_available) {
                irlume_common::dlog!("gate(per-user depth floor): live {:.2} vs floor {:.2}", a.ir_depth, depth_floor);
                if a.ir_depth < depth_floor {
                    return Ok(Outcome {
                        granted: false, live: false, score: 0.0,
                        reason: format!(
                            "IR depth {:.2} below your calibrated floor {:.2} — looks 2D (screen/photo)",
                            a.ir_depth, depth_floor
                        ),
                    });
                }
            }
            let scans = enr.rgb_scans();
            let thr = irlume_core::scaled_threshold(irlume_core::RGB_MATCH_THRESHOLD, scans.len());
            let (score, who) = best(&probe, &scans);
            irlume_common::dlog!("match(rgb): best {score:.3} vs thr {thr:.3} ({} scans, best profile '{who}')", scans.len());
            if score >= thr {
                return self.challenge_if_required(&enr, Outcome { granted: true, live: true, score, reason: format!("match: {who} (rgb)") });
            }
            // Stage-2 lighting-adaptive fusion: RGB recognition missed (poor ambient
            // light or a marginal angle). If we also captured an IR face and the user
            // enrolled IR templates, fuse the two CALIBRATED scores, each weighted by
            // its modality's capture quality — a marginal RGB + marginal IR can jointly
            // grant while FMR stays bounded (an impostor must fool BOTH at once). The
            // cross-spectrum liveness gate + per-user IR floor already passed above.
            // This is the bright→RGB / dark→IR / dim→FUSE story.
            if let Some(ir_probe) = &a.ir_embedding {
                let ir_scans = enr.ir_scans();
                if !ir_scans.is_empty() {
                    let (ir_score, ir_who) = best(ir_probe, &ir_scans);
                    // (a) calibrated quality-weighted fusion — the dim/mixed-light path.
                    let f = irlume_core::fusion::fuse(
                        irlume_core::fusion::rgb_genuine_prob(score),
                        irlume_core::fusion::rgb_quality_weight(a.signals.rgb_face_brightness),
                        irlume_core::fusion::ir_genuine_prob(ir_score),
                        irlume_core::fusion::ir_quality_weight(true, a.ir_brightness),
                    );
                    irlume_common::dlog!("match(fusion): p={:.3} grant={} (rgb {score:.3} bright {:.0} / ir {ir_score:.3} bright {:.0})",
                        f.prob, f.grant, a.signals.rgb_face_brightness, a.ir_brightness);
                    if f.grant {
                        let who = if ir_score >= score { ir_who } else { who };
                        return self.challenge_if_required(&enr, Outcome { granted: true, live: true, score: f.prob,
                            reason: format!("match: {who} (rgb+ir fusion p={:.2}; rgb {score:.2}/ir {ir_score:.2})", f.prob) });
                    }
                    // (b) pure IR fallback — still valid when IR alone is clearly strong
                    // (e.g. IR-only enrollment, or RGB template absent). Stricter than the
                    // dark path (+IR_FALLBACK_MARGIN) for the second-modality risk.
                    let ir_base = if self.ir_adapter.is_some() {
                        irlume_core::IR_ADAPTED_MATCH_THRESHOLD
                    } else {
                        irlume_core::IR_MATCH_THRESHOLD
                    };
                    let ir_thr = irlume_core::scaled_threshold(ir_base, ir_scans.len()) + irlume_core::IR_FALLBACK_MARGIN;
                    irlume_common::dlog!("match(ir-fallback): {ir_score:.3} vs thr {ir_thr:.3} (adapter={})", self.ir_adapter.is_some());
                    if ir_score >= ir_thr {
                        return self.challenge_if_required(&enr, Outcome { granted: true, live: true, score: ir_score,
                            reason: format!("match: {ir_who} (ir-fallback, dim light; rgb {score:.2}<{thr:.2})") });
                    }
                }
            }
            // The reason keeps the exact score: it reaches only the session's
            // own TUI/CLI (coaching a genuine false reject); the daemon redacts
            // measurements before this line touches the journal (anti-oracle).
            return Ok(Outcome { granted: false, live: true, score, reason: format!("below threshold (rgb {score:.2}, fusion+ir-fallback miss)") });
        }

        // Dark path: no RGB face, but an IR face -> IR-only liveness + IR
        // recognition (Windows-Hello-style dark operation) across all profiles.
        if let Some(probe) = a.ir_embedding {
            let scans = enr.ir_scans();
            if scans.is_empty() {
                return Ok(Outcome { granted: false, live: false, score: 0.0, reason: "dark, but no IR scans enrolled — re-enroll to enable dark unlock".into() });
            }
            let (verdict, _cues, reason) = self.gate.evaluate_ir_only(&a.signals);
            irlume_common::dlog!("liveness(ir-only/dark): {verdict:?} ({reason}); ir_bright={:.0} ir_depth={:.2} glint={:.2}",
                a.signals.ir_face_brightness, a.signals.ir_center_edge_ratio, a.signals.ir_eye_glint);
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
            irlume_common::dlog!("match(ir/dark): best {score:.3} vs thr {ir_thr:.3} ({} scans, adapter={})", scans.len(), self.ir_adapter.is_some());
            let granted = score >= ir_thr;
            return self.challenge_if_required(&enr, Outcome { granted, live: true, score, reason: if granted { format!("match: {who} (ir/dark)") } else { "below threshold (ir)".into() } });
        }

        Ok(Outcome { granted: false, live: false, score: 0.0, reason: format!("no face: {}", a.reason) })
    }

    /// 1:N identify ("who is this?"): one live capture, matched against every
    /// enrolled user's RGB profiles (no claimed identity). Liveness-gated like
    /// auth; reports the best above-threshold (user, profile, score). RGB primary
    /// path only — a diagnostic, not a dark-mode unlock.
    /// 1:N identify across every enrolled user. Full cross-user search — an
    /// admin/testing capability; the daemon restricts a non-root caller to
    /// [`identify_within`] so the returned score can't become a hill-climbing
    /// oracle against other users' templates.
    pub fn identify(&mut self) -> irlume_common::Result<IdentifyOutcome> {
        self.identify_impl(None)
    }

    /// Identify scoped to a single enrolled user ("is this `user`?"). Same
    /// liveness gate and RGB match as [`identify`], but the search set is just
    /// this one account — what a non-root peer is allowed to ask about itself.
    pub fn identify_within(&mut self, user: &str) -> irlume_common::Result<IdentifyOutcome> {
        self.identify_impl(Some(user))
    }

    fn identify_impl(&mut self, restrict: Option<&str>) -> irlume_common::Result<IdentifyOutcome> {
        if irlume_core::policy::method().face_disabled() {
            return Ok(IdentifyOutcome { user: None, profile: None, score: 0.0, live: false, reason: "face disabled (fingerprint mode)".into() });
        }
        let a = self.assess()?;
        let Some(probe) = a.embedding else {
            return Ok(IdentifyOutcome { user: None, profile: None, score: 0.0, live: false, reason: format!("no RGB face: {}", a.reason) });
        };
        if a.verdict != Verdict::Live {
            return Ok(IdentifyOutcome { user: None, profile: None, score: 0.0, live: false, reason: format!("liveness {:?}: {}", a.verdict, a.reason) });
        }
        let mut best: Option<(f32, String, String)> = None; // (score, user, profile)
        let candidates: Vec<String> = match restrict {
            Some(u) => vec![u.to_string()],
            None => irlume_core::storage::list_users(),
        };
        for user in candidates {
            let Some(enr) = irlume_core::storage::load(&user)? else { continue };
            let scans = enr.rgb_scans();
            if scans.is_empty() {
                continue;
            }
            let thr = irlume_core::scaled_threshold(irlume_core::RGB_MATCH_THRESHOLD, scans.len());
            let (score, who) = scans
                .iter()
                .map(|(prof, _scan, t)| (align::cosine(&probe, t), prof.to_string()))
                .fold((f32::NEG_INFINITY, String::new()), |acc, x| if x.0 > acc.0 { x } else { acc });
            if score >= thr && best.as_ref().map_or(true, |b| score > b.0) {
                best = Some((score, user.clone(), who));
            }
        }
        match best {
            Some((score, user, profile)) => Ok(IdentifyOutcome {
                user: Some(user), profile: Some(profile), score, live: true,
                reason: "match".into(),
            }),
            None => Ok(IdentifyOutcome { user: None, profile: None, score: 0.0, live: true, reason: "live face, but no enrolled match".into() }),
        }
    }

    /// IR liveness self-test: capture and run the algorithmic PAD gate, reporting
    /// the verdict plus the cues behind it. Backs the TUI Calibrate screen and
    /// `Request::SelfTest { Liveness }`.
    pub fn liveness_selftest(&mut self) -> irlume_common::Result<(bool, String)> {
        let a = self.assess()?;
        let s = &a.signals;
        let live = a.verdict == Verdict::Live;
        let detail = if live {
            format!(
                "Live — RGB face {}, IR face {} · IR brightness {:.0}, depth {:.2}, glint {:.0}",
                if s.rgb_face.is_some() { "✓" } else { "✗" },
                if s.ir_face.is_some() { "✓" } else { "✗" },
                a.ir_brightness, a.ir_depth, s.ir_eye_glint,
            )
        } else {
            format!("{:?} — {}", a.verdict, a.reason)
        };
        Ok((live, detail))
    }

    /// Alignment-determinism self-test: embed the same aligned chip twice; the
    /// cosine MUST be ~1.0. Catches the AuraFace alignment/normalization trap
    /// (the "identical images score 0.6" failure). `Request::SelfTest { AlignmentIdentity }`.
    pub fn alignment_selftest(&mut self) -> irlume_common::Result<(bool, String)> {
        let rgb = irlume_camera::capture_rgb_denoised(&self.rgb_dev)?;
        let view = align::RgbView { data: &rgb.data, width: rgb.width, height: rgb.height };
        let faces = self.det.detect(&view)?;
        let Some(f) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            return Ok((false, "no RGB face detected — face the camera and retry".into()));
        };
        let chip = align::align_to_arcface(&view, &f.landmarks)?;
        let a = self.emb.embed(&chip)?;
        let b = self.emb.embed(&chip)?;
        let cos = align::cosine(&a, &b);
        Ok((cos > 0.999, format!("alignment determinism cosine {cos:.6} (want ≈ 1.000000)")))
    }

    /// Capture `want` LIVE, frontal scans (best-effort, with a retry budget).
    /// Each Live capture yields one (rgb, ir, depth, brightness). No enrolling
    /// from a photo — the liveness gate rejects spoofs.
    fn capture_scans(&mut self, want: usize) -> irlume_common::Result<Vec<(Vec<f32>, Option<Vec<f32>>, f32, f32)>> {
        let mut out = Vec::new();
        // Budget bumped (was ×4) to absorb the added frontality gate — a frame
        // grabbed the instant the user drifts off-angle is now rejected, not saved.
        for _ in 0..(want * 6) {
            if out.len() >= want {
                break;
            }
            let a = self.assess()?;
            // Authoritative capture gate: LIVE *and* squarely frontal. The guided
            // TUI only decides when to START the 3-2-1; this is what actually
            // decides whether the frame is kept, so a turned/tilted (but live)
            // face can't be saved as a bad template even if the user moved during
            // the countdown. Same bounds the enrollment guide coaches to.
            if a.verdict == Verdict::Live && frontal_signals(&a.signals) {
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
        if enr.camera_binding.is_none() {
            enr.camera_binding = Some(self.current_binding());
        }
        storage::save(&enr)?;
        Ok((name, n))
    }

    /// Snapshot the identity of the cameras this engine is bound to, for
    /// anti-swap verification at auth.
    fn current_binding(&self) -> irlume_core::storage::CameraBinding {
        irlume_core::storage::CameraBinding {
            rgb: irlume_camera::device_identity(&self.rgb_dev),
            ir: irlume_camera::device_identity(&self.ir_dev),
        }
    }

    /// If the live cameras no longer match the enrolled binding, return a reason
    /// to refuse (anti-swap). A bound device that now reads differently — or an
    /// enrolled IR camera that's gone — fails; an unbound side is not checked.
    fn binding_mismatch(&self, bind: &irlume_core::storage::CameraBinding) -> Option<String> {
        if let Some(want) = &bind.rgb {
            if irlume_camera::device_identity(&self.rgb_dev).as_ref() != Some(want) {
                return Some("camera changed since enrollment (RGB device identity differs) — re-enroll on this camera".into());
            }
        }
        if let Some(want) = &bind.ir {
            if irlume_camera::device_identity(&self.ir_dev).as_ref() != Some(want) {
                return Some("IR camera changed or absent since enrollment — re-enroll on this camera".into());
            }
        }
        None
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
        if enr.camera_binding.is_none() {
            enr.camera_binding = Some(self.current_binding());
        }
        let total = enr.profiles[idx].scans.len();
        storage::save(&enr)?;
        Ok((sname, total))
    }

    /// One framing-guide sample for guided enrollment: capture, detect, and
    /// report how the user is positioned (no enrollment, no auth). The gates
    /// mirror the enroll/auth path so `well_framed` implies a capture will take.
    pub fn position_sample(&mut self) -> irlume_common::Result<irlume_common::PositionReport> {
        use irlume_common::PositionReport;
        const MIN_FRAC: f32 = 0.12;
        const MAX_FRAC: f32 = 0.55;
        const CENTER_TOL: f32 = 0.18;
        const DIM: f32 = 55.0;
        const BRIGHT: f32 = 235.0;

        let rgb = irlume_camera::capture_rgb(&self.rgb_dev)?;
        let view = align::RgbView { data: &rgb.data, width: rgb.width, height: rgb.height };
        let top = self.det.detect(&view)?.into_iter().max_by(|a, b| a.score.total_cmp(&b.score));
        // NB: the framing guide is RGB-only so it stays fast enough to poll (the
        // IR burst would make each sample multi-second). IR readiness is checked
        // at the actual capture, not in the guide.
        let ir_ok = false;
        let (fw, fh) = (rgb.width as f32, rgb.height as f32);
        let Some(f) = top else {
            return Ok(PositionReport {
                ir_ok,
                guidance: "No face detected — look straight at the camera and center yourself".into(),
                ..Default::default()
            });
        };
        let [x1, y1, x2, y2] = f.bbox;
        let face_frac = (x2 - x1).max(0.0) / fw;
        let centered = ((x1 + x2) / 2.0 - fw / 2.0).abs() <= CENTER_TOL * fw
            && ((y1 + y2) / 2.0 - fh / 2.0).abs() <= CENTER_TOL * fh;
        let pose = irlume_vision::head_pose(&f.landmarks);
        let brightness = luma_in_bbox(&rgb.data, rgb.width, rgb.height, &f.bbox);

        let mut q = 100i32;
        let mut guidance = "Hold still — looking good".to_string();
        let mut well = true;
        let frontal = pose.yaw_asym <= FRAME_YAW_ASYM_MAX
            && (FRAME_PITCH_MIN..=FRAME_PITCH_MAX).contains(&pose.pitch_frac);
        // Live pose numbers for calibrating the framing bounds to a given camera
        // (`IRLUME_LOG=debug`): a below-eye-level laptop cam biases pitch high.
        irlume_common::dlog!("framing: yaw_asym={:.2} yaw_signed={:.2} pitch={:.2} face_frac={:.2} bright={:.0}",
            pose.yaw_asym, pose.yaw_signed, pose.pitch_frac, face_frac, brightness);
        if face_frac < MIN_FRAC {
            guidance = "Move closer".into(); well = false; q -= 45;
        } else if face_frac > MAX_FRAC {
            guidance = "Move back a little".into(); well = false; q -= 30;
        } else if !centered {
            guidance = "Center your face in the frame".into(); well = false; q -= 30;
        } else if !frontal {
            guidance = frontality_hint(&pose); well = false; q -= 30;
        } else if brightness < DIM {
            guidance = "Too dark — add light or face a window".into(); well = false; q -= 30;
        } else if brightness > BRIGHT {
            guidance = "Too bright — reduce glare/backlight".into(); well = false; q -= 20;
        }
        Ok(PositionReport {
            face: true, face_frac, centered, yaw_asym: pose.yaw_asym, pitch_frac: pose.pitch_frac,
            brightness, ir_ok, quality: q.clamp(0, 100) as u8, well_framed: well, guidance,
        })
    }
}

/// Framing-guide frontality bounds — deliberately STRICTER than the liveness
/// anti-spoof gate (yaw 0.40 / pitch 0.20–0.80). The wide liveness pitch band
/// meant a normal chin tilt never left "frontal", so "lift/lower your chin"
/// almost never fired — and by the time a tilt was steep enough to trip the
/// liveness band, the detector had already lost the face ("no face detected").
/// A tighter band makes the up/down cue fire at a MODERATE, still-detectable
/// tilt. Low pitch = looking up, high pitch = looking down (live-verified). A
/// below-eye-level laptop camera looks UP at the face, biasing neutral toward
/// the LOW (looking-up) end, so the floor isn't set aggressively high. These are
/// tighter than the first pass (was yaw 0.40 / pitch 0.33–0.70) to coach a more
/// squarely-frontal capture; still wide enough that a level face isn't nagged.
/// Tune from the `IRLUME_LOG=debug` "framing:" trace (median = a level face).
const FRAME_YAW_ASYM_MAX: f32 = 0.34;
const FRAME_PITCH_MIN: f32 = 0.37;
const FRAME_PITCH_MAX: f32 = 0.66;

/// True when a head pose is squarely-frontal enough to enroll — the capture-time
/// gate (in [`Engine::capture_scans`]) and the guide's `well_framed` share these
/// bounds, so what the guide coaches to is exactly what gets saved.
fn frontal_signals(s: &Signals) -> bool {
    s.head_yaw_asym <= FRAME_YAW_ASYM_MAX
        && (FRAME_PITCH_MIN..=FRAME_PITCH_MAX).contains(&s.head_pitch_frac)
}

/// Turn a non-frontal head pose into a directional enrollment instruction, told
/// in the USER's own frame. On irlume's non-mirrored capture, nose-toward-image-
/// left (`yaw_signed < 0`) means the person is looking to THEIR right, so we ask
/// them to turn left. For pitch (live-verified): a LOW `pitch_frac` means the
/// nose has risen toward the eye line = looking UP → ask them to lower the chin;
/// a HIGH `pitch_frac` means looking DOWN → ask them to lift the chin. When both
/// axes are off the more-severe one wins, so the user is corrected on one thing
/// at a time instead of being bounced around.
fn frontality_hint(pose: &irlume_vision::HeadPose) -> String {
    let mid = (FRAME_PITCH_MIN + FRAME_PITCH_MAX) / 2.0;
    let yaw_off = pose.yaw_asym > FRAME_YAW_ASYM_MAX;
    let pitch_off = pose.pitch_frac < FRAME_PITCH_MIN || pose.pitch_frac > FRAME_PITCH_MAX;
    let yaw_sev = pose.yaw_asym / FRAME_YAW_ASYM_MAX;
    let pitch_sev = (pose.pitch_frac - mid).abs() / ((FRAME_PITCH_MAX - FRAME_PITCH_MIN) / 2.0);
    if yaw_off && (!pitch_off || yaw_sev >= pitch_sev) {
        // Nose toward image-left → looking to their right → turn left, and vice versa.
        if pose.yaw_signed < 0.0 { "Turn your head left to face the camera".into() }
        else { "Turn your head right to face the camera".into() }
    } else if pose.pitch_frac < FRAME_PITCH_MIN {
        // Low pitch = nose toward eye line = looking up → bring the chin down.
        "Lower your chin — look down a little".into()
    } else if pose.pitch_frac > FRAME_PITCH_MAX {
        // High pitch = nose toward mouth = looking down → bring the chin up.
        "Lift your chin — look up a little".into()
    } else {
        "Look straight at the camera".into()
    }
}

/// Mean BT.601 luma (0–255) of the RGB8 face region.
fn luma_in_bbox(rgb: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    let x1 = (bbox[0].max(0.0) as u32).min(w.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(h.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut sum, mut n) = (0f64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            let i = ((y * w + x) * 3) as usize;
            if i + 2 < rgb.len() {
                sum += 0.299 * rgb[i] as f64 + 0.587 * rgb[i + 1] as f64 + 0.114 * rgb[i + 2] as f64;
                n += 1;
            }
        }
    }
    if n == 0 { 0.0 } else { (sum / n as f64) as f32 }
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

/// Mean luma (0–255) and the fraction of near-white ("hot") pixels inside `bbox`
/// of an RGB image. The hot fraction is a basic RGB-PAD cue: emissive screens
/// and glossy prints blow out highlights, so an unusually high fraction is a
/// (deterrent-grade) screen/glare signal.
fn rgb_luma_stats(rgb: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> (f32, f32) {
    let x1 = (bbox[0].max(0.0) as u32).min(w.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(h.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut sum, mut n, mut hot) = (0u64, 0u64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            let i = ((y * w + x) * 3) as usize;
            if i + 2 < rgb.len() {
                let luma = (rgb[i] as u32 * 299 + rgb[i + 1] as u32 * 587 + rgb[i + 2] as u32 * 114) / 1000;
                sum += luma as u64;
                if luma >= 250 { hot += 1; }
                n += 1;
            }
        }
    }
    if n == 0 { (0.0, 0.0) } else { (sum as f32 / n as f32, hot as f32 / n as f32) }
}

pub fn mean_in_bbox(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
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

pub fn center_edge_ratio(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
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

pub fn eye_glint(grey: &[u8], w: u32, h: u32, landmarks: &Landmarks5) -> f32 {
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

/// Specular contrast at the eyes = peak − local-mean brightness, max over both
/// eyes. A live OPEN eye makes a sharp corneal specular spike (high contrast); a
/// CLOSED lid — or a printed/vinyl "eye" — is diffuse (low). This is the basis of
/// the ADR-0002 blink challenge and has far better SNR than raw peak glint: a
/// closed lid still reflects 850nm, so peak alone barely drops, but the specular
/// spike (hence contrast) collapses. Live-validated 2026-06-30: genuine open-eye
/// contrast ≈120, a static vinyl banner ≈70 (flat).
pub fn eye_glint_contrast(grey: &[u8], w: u32, h: u32, landmarks: &Landmarks5) -> f32 {
    let iod = ((landmarks[1].0 - landmarks[0].0).powi(2) + (landmarks[1].1 - landmarks[0].1).powi(2)).sqrt();
    let r = (iod * 0.20).max(2.0) as i32;
    let at = |(ex, ey): (f32, f32)| -> f32 {
        let (cx, cy) = (ex as i32, ey as i32);
        let (mut peak, mut sum, mut cnt) = (0u8, 0u64, 0u64);
        for dy in -r..=r {
            for dx in -r..=r {
                let (x, y) = (cx + dx, cy + dy);
                if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                    let v = grey[(y as u32 * w + x as u32) as usize];
                    peak = peak.max(v);
                    sum += v as u64;
                    cnt += 1;
                }
            }
        }
        if cnt == 0 { 0.0 } else { peak as f32 - sum as f32 / cnt as f32 }
    };
    at(landmarks[0]).max(at(landmarks[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_core::storage::{Enrollment, FaceProfile, FaceScan};

    fn scan(v: Vec<f32>) -> FaceScan {
        FaceScan { name: "s".into(), rgb: v, ir: None, ir_depth: 0.0, ir_brightness: 0.0 }
    }

    #[test]
    fn frontal_signals_gates_capture() {
        let s = |yaw: f32, pitch: f32| Signals { head_yaw_asym: yaw, head_pitch_frac: pitch, ..Default::default() };
        assert!(frontal_signals(&s(0.0, 0.50)), "square-on should pass");
        assert!(frontal_signals(&s(0.30, 0.55)), "small turn within bounds passes");
        assert!(!frontal_signals(&s(0.45, 0.50)), "clearly turned is rejected");
        assert!(!frontal_signals(&s(0.0, 0.20)), "looking up is rejected");
        assert!(!frontal_signals(&s(0.0, 0.75)), "looking down is rejected");
    }

    #[test]
    fn frontality_hint_is_directional() {
        use irlume_vision::HeadPose;
        // Turned so the nose sits image-left (yaw_signed<0) → they're looking to
        // their right → we tell them to turn LEFT (non-mirrored capture).
        let p = HeadPose { yaw_asym: 0.6, yaw_signed: -0.6, pitch_frac: 0.5 };
        assert_eq!(frontality_hint(&p), "Turn your head left to face the camera");
        // Nose image-right → looking to their left → turn RIGHT.
        let p = HeadPose { yaw_asym: 0.6, yaw_signed: 0.6, pitch_frac: 0.5 };
        assert_eq!(frontality_hint(&p), "Turn your head right to face the camera");
        // Looking UP (low pitch = nose toward eye line) → lower chin.
        let p = HeadPose { yaw_asym: 0.0, yaw_signed: 0.0, pitch_frac: 0.10 };
        assert!(frontality_hint(&p).starts_with("Lower your chin"));
        // Looking DOWN (high pitch = nose toward mouth) → lift chin.
        let p = HeadPose { yaw_asym: 0.0, yaw_signed: 0.0, pitch_frac: 0.90 };
        assert!(frontality_hint(&p).starts_with("Lift your chin"));
        // Both off: the more-severe axis wins (here yaw is 2x its limit, pitch
        // barely over) → yaw guidance, not pitch.
        let p = HeadPose { yaw_asym: 0.80, yaw_signed: 0.80, pitch_frac: 0.82 };
        assert_eq!(frontality_hint(&p), "Turn your head right to face the camera");
    }

    #[test]
    fn collision_blocks_same_face_in_another_profile() {
        let face1 = vec![1.0, 0.0, 0.0];
        let face2 = vec![0.0, 1.0, 0.0];
        let enr = Enrollment {
            user: "u".into(),
            require_eyes_open: false,
            require_challenge: false,
            camera_binding: None,
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
