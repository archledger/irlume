// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Fixed, synthetic inputs through the unchanged engine decision boundary.
//! The golden preserves outcomes and trace order for a later refactor; it is
//! not a biometric corpus.

use super::*;
use irlume_common::diagnostics::{DiagnosticSink, TraceEventKind};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct TraceSink(Mutex<Vec<TraceEventKind>>);

impl DiagnosticSink for TraceSink {
    fn emit_trace(&self, event: TraceEventKind) {
        self.0.lock().unwrap().push(event);
    }
}

struct MoireOverride(Option<std::ffi::OsString>);

impl MoireOverride {
    fn clear() -> Self {
        let previous = std::env::var_os("IRLUME_RGB_MOIRE_MAX");
        std::env::remove_var("IRLUME_RGB_MOIRE_MAX");
        Self(previous)
    }
}

impl Drop for MoireOverride {
    fn drop(&mut self) {
        match &self.0 {
            Some(value) => std::env::set_var("IRLUME_RGB_MOIRE_MAX", value),
            None => std::env::remove_var("IRLUME_RGB_MOIRE_MAX"),
        }
    }
}

#[test]
fn moire_override_is_restored_on_return_and_unwind() {
    use std::os::unix::ffi::OsStringExt;

    let _guard = env_guard();
    let _original = MoireOverride::clear();
    for value in ["15".into(), std::ffi::OsString::from_vec(vec![0xff])] {
        std::env::set_var("IRLUME_RGB_MOIRE_MAX", &value);
        {
            let _cleared = MoireOverride::clear();
            assert!(std::env::var_os("IRLUME_RGB_MOIRE_MAX").is_none());
        }
        assert_eq!(
            std::env::var_os("IRLUME_RGB_MOIRE_MAX"),
            Some(value.clone())
        );
        let result = std::panic::catch_unwind(|| {
            let _cleared = MoireOverride::clear();
            panic!("exercise unwind restoration");
        });
        assert!(result.is_err());
        assert_eq!(std::env::var_os("IRLUME_RGB_MOIRE_MAX"), Some(value));
    }
}

struct IrAvailable<'a> {
    engine: &'a mut Engine,
    previous: bool,
}

impl<'a> IrAvailable<'a> {
    fn new(engine: &'a mut Engine) -> Self {
        let previous = std::mem::replace(&mut engine.ir_available, true);
        Self { engine, previous }
    }
}

impl Drop for IrAvailable<'_> {
    fn drop(&mut self) {
        self.engine.ir_available = self.previous;
    }
}

fn probe(cosine: f32) -> [f32; EMBED_DIM] {
    let mut probe = [0.0; EMBED_DIM];
    probe[0] = cosine;
    probe[1] = (1.0 - cosine * cosine).sqrt();
    probe
}

fn fixture(
    engine: &Engine,
    profiles: usize,
    scans: usize,
    calibrated: bool,
) -> (Enrollment, Assessment) {
    let (mut enrollment, mut a) = pad_matching_fixture(0.1, false);
    let mut profile = enrollment.profiles.pop().unwrap();
    let mut scan = profile.scans.pop().unwrap();
    scan.embed_space = Some(engine.embed_space().into());
    scan.ir_space = Some(engine.ir_space().into());
    scan.ir = Some(scan.rgb.clone());
    profile.scans = vec![scan; scans];
    if calibrated {
        // A valid identity map exercises calibration and centroid composition
        // without fitting a model or reading any recorded enrollment.
        profile.set_calib_for(
            engine.embed_space(),
            Some(irlume_core::calib::IrCalibration {
                m: vec![vec![0.0; 3]; EMBED_DIM],
                n_rows: vec![vec![0.0; EMBED_DIM]; 3],
                lambda: irlume_core::calib::RIDGE_LAMBDA as f32,
                fitted_pairs: 3,
            }),
        );
    }
    enrollment.profiles = (0..profiles)
        .map(|i| {
            let mut p = profile.clone();
            p.name = format!("profile-{i}");
            p
        })
        .collect();
    let face = Some(irlume_liveness::FaceBox {
        cx: 0.5,
        cy: 0.5,
        score: 0.99,
    });
    a.signals.rgb_face = face;
    a.signals.ir_face = face;
    a.signals.ir_face_brightness = 100.0;
    a.signals.ir_center_edge_ratio = 1.5;
    a.signals.ir_ceiling_known = true;
    a.signals.ir_saturated_frac = Some(0.0);
    a.ir_center_edge_ratio = 1.5;
    a.ir_brightness = 100.0;
    a.ir_embedding = Some(probe(1.0).to_vec());
    a.ir_pad = PadEvidence::Score(0.1);
    (enrollment, a)
}

fn record(engine: &mut Engine, name: &str, enrollment: &Enrollment, a: Assessment) -> String {
    let sink = TraceSink::default();
    let Outcome {
        granted,
        live,
        score,
        reason,
        kind,
        cause,
    } = engine
        .authenticate_qualified_assessment(
            enrollment,
            AuthenticationPurpose::Verify,
            Some("login"),
            a,
            &sink,
        )
        .unwrap();
    let events = sink.0.into_inner().unwrap();
    serde_json::to_string(&serde_json::json!({
        "case": name,
        "granted": granted,
        "live": live,
        "score_bits": format!("{:08x}", score.to_bits()),
        "reason": reason,
        "kind": format!("{kind:?}"),
        "cause": cause,
        "trace": events,
    }))
    .unwrap()
}

fn digest(lines: &[String]) -> String {
    let mut hash = Sha256::new();
    for line in lines {
        hash.update((line.len() as u64).to_le_bytes());
        hash.update(line.as_bytes());
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn lit_cases(engine: &mut Engine) -> Vec<String> {
    let mut records = Vec::new();
    for profiles in [1, 2, 3] {
        for scans in [1, 5, 10] {
            for calibrated in [false, true] {
                let (enrollment, _) = fixture(engine, profiles, scans, calibrated);
                let rgb_threshold = engine.rgb_grant_threshold(profiles * scans);
                let ir_threshold = irlume_core::scaled_threshold(
                    irlume_core::IR_MATCH_THRESHOLD,
                    profiles * scans,
                ) + irlume_core::IR_FALLBACK_MARGIN;
                for posture in 0..3 {
                    for (rgb_bright, ir_bright) in
                        [(60.0, 35.0), (60.0, 110.0), (130.0, 35.0), (130.0, 110.0)]
                    {
                        for rgb in [
                            0.2,
                            rgb_threshold.next_down(),
                            rgb_threshold,
                            rgb_threshold.next_up(),
                        ] {
                            for ir in [
                                0.2,
                                ir_threshold.next_down(),
                                ir_threshold,
                                ir_threshold.next_up(),
                                0.9,
                            ] {
                                let (_, mut a) = fixture(engine, 1, 1, false);
                                a.embedding = Some(probe(rgb));
                                a.ir_embedding = Some(probe(ir).to_vec());
                                a.sequential_pair = posture == 1;
                                a.split_pair = posture == 2;
                                a.signals.rgb_face_brightness = rgb_bright;
                                a.ir_brightness = ir_bright;
                                assert_eq!(
                                    align::cosine(
                                        &probe(rgb),
                                        &enrollment.profiles[0].scans[0].rgb
                                    )
                                    .to_bits(),
                                    rgb.to_bits()
                                );
                                if !calibrated {
                                    assert_eq!(
                                        engine.ir_match(&enrollment, &probe(ir)).best.to_bits(),
                                        ir.to_bits()
                                    );
                                }
                                let name = format!(
                                    "lit/{profiles}/{scans}/{calibrated}/{posture}/{rgb_bright}/{ir_bright}/{:08x}/{:08x}",
                                    rgb.to_bits(), ir.to_bits()
                                );
                                records.push(record(engine, &name, &enrollment, a));
                            }
                        }
                    }
                }
            }
        }
    }
    records
}

fn dark_cases(engine: &mut Engine) -> Vec<String> {
    let mut records = Vec::new();
    for profiles in [1, 2, 3] {
        for scans in [1, 5, 10] {
            for calibrated in [false, true] {
                let (enrollment, _) = fixture(engine, profiles, scans, calibrated);
                let thresholds =
                    ir_assessment::IdentityThresholds::new(profiles * scans, profiles, false);
                for ir in [
                    0.2,
                    thresholds.best.next_down(),
                    thresholds.best,
                    thresholds.best.next_up(),
                    0.95,
                ] {
                    let (_, mut a) = fixture(engine, 1, 1, false);
                    a.embedding = None;
                    a.signals.rgb_face = None;
                    a.rgb_frame_mean = 0.0;
                    a.verdict = Verdict::Uncertain;
                    a.ir_embedding = Some(probe(ir).to_vec());
                    let name = format!("dark/{profiles}/{scans}/{calibrated}/{:08x}", ir.to_bits());
                    records.push(record(engine, &name, &enrollment, a));
                }
            }
        }
    }
    for enrolled_but_incompatible in [false, true] {
        let (mut enrollment, mut a) = fixture(engine, 1, 1, false);
        a.embedding = None;
        a.signals.rgb_face = None;
        a.rgb_frame_mean = 0.0;
        if enrolled_but_incompatible {
            enrollment.profiles[0].scans[0].ir_space = Some("old-space".into());
        } else {
            enrollment.profiles[0].scans[0].ir = None;
        }
        assert_eq!(engine.ir_match(&enrollment, &probe(1.0)).n_templates, 0);
        let name = format!("dark/no-compatible/{enrolled_but_incompatible}");
        records.push(record(engine, &name, &enrollment, a));
    }
    for dark in [false, true] {
        let (mut enrollment, mut a) = fixture(engine, 1, 10, true);
        for (i, scan) in enrollment.profiles[0].scans.iter_mut().enumerate() {
            let mut ir = probe(0.4);
            if i % 2 == 0 {
                ir[1] = -ir[1];
            }
            scan.ir = Some(ir.to_vec());
        }
        a.embedding = (!dark).then(|| probe(0.2));
        a.rgb_frame_mean = if dark { 0.0 } else { 120.0 };
        a.signals.rgb_face = if dark { None } else { a.signals.rgb_face };
        let matched = engine.ir_match(&enrollment, &probe(1.0));
        assert!(matched.best < 0.5);
        assert!(matched.centroid.unwrap().0 > 0.9);
        records.push(record(
            engine,
            &format!("centroid-only/{dark}"),
            &enrollment,
            a,
        ));
    }
    records
}

fn gate_and_selection_cases(engine: &mut Engine) -> Vec<String> {
    let mut records = Vec::new();
    for dark in [false, true] {
        for failure in [
            "spoof",
            "uncertain",
            "pending-pad",
            "failed-pad",
            "ratio-floor",
        ] {
            let (mut enrollment, mut a) = fixture(engine, 1, 5, false);
            if dark {
                a.embedding = None;
                a.signals.rgb_face = None;
                a.rgb_frame_mean = 0.0;
            }
            match failure {
                "spoof" => {
                    a.verdict = Verdict::Spoof;
                    if dark {
                        a.signals.ir_center_edge_ratio = 0.5;
                    }
                }
                "uncertain" => {
                    a.verdict = Verdict::Uncertain;
                    a.ir_embedding = None;
                }
                "pending-pad" => a.ir_pad = PadEvidence::Pending,
                "failed-pad" => a.ir_pad = PadEvidence::InferenceFailed,
                "ratio-floor" => {
                    for scan in &mut enrollment.profiles[0].scans {
                        scan.ir_center_edge_ratio = 2.0;
                    }
                    a.ir_center_edge_ratio = 1.0;
                }
                _ => unreachable!(),
            }
            let line = record(engine, &format!("gate/{dark}/{failure}"), &enrollment, a);
            let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(parsed["granted"], false, "{line}");
            records.push(line);
        }
    }
    for rgb in [0.2, 0.9] {
        for posture in 0..3 {
            let (enrollment, mut a) = fixture(engine, 1, 1, false);
            a.embedding = Some(probe(rgb));
            a.ir_embedding = None;
            a.sequential_pair = posture == 1;
            a.split_pair = posture == 2;
            records.push(record(
                engine,
                &format!("no-ir/{rgb}/{posture}"),
                &enrollment,
                a,
            ));
        }
    }
    for exclusion in ["recognizer", "ir-space", "dimension", "untagged"] {
        let (mut enrollment, mut a) = fixture(engine, 2, 1, false);
        let decoy = &mut enrollment.profiles[0].scans[0];
        match exclusion {
            "recognizer" => decoy.embed_space = Some("unrelated-model".into()),
            "ir-space" => decoy.ir_space = Some("unrelated-pipeline".into()),
            "dimension" => decoy.ir = Some(vec![1.0; 3]),
            "untagged" => decoy.ir_space = None,
            _ => unreachable!(),
        }
        enrollment.profiles[1].scans[0].ir = Some(probe(0.0).to_vec());
        a.sequential_pair = true;
        let matched = engine.ir_match(&enrollment, a.ir_embedding.as_ref().unwrap());
        assert_eq!(matched.n_templates, 1, "{exclusion}");
        assert_eq!(matched.best.to_bits(), 0.0f32.to_bits());
        records.push(record(
            engine,
            &format!("excluded/{exclusion}"),
            &enrollment,
            a,
        ));
    }
    let (enrollment, mut a) = fixture(engine, 1, 1, false);
    a.embedding = None;
    a.signals.rgb_face = None;
    records.push(record(engine, "dark-in-lit-room", &enrollment, a));
    let (enrollment, mut a) = fixture(engine, 1, 1, false);
    a.embedding = None;
    a.ir_embedding = None;
    records.push(record(engine, "no-face", &enrollment, a));
    records
}

fn brightness_and_winner_cases(engine: &mut Engine) -> Vec<String> {
    let mut records = Vec::new();
    // Pin both ramp knees and their neighbors independently of future helpers.
    let neighbors = |a: f32, b: f32| [a.next_down(), a, a.next_up(), b.next_down(), b, b.next_up()];
    for rgb_bright in neighbors(60.0, 130.0) {
        for ir_bright in neighbors(35.0, 110.0) {
            for ir in [0.4, 0.5, 0.6] {
                let (mut enrollment, mut a) = fixture(engine, 2, 1, false);
                enrollment.profiles[0].scans[0].rgb = probe(0.4).to_vec();
                enrollment.profiles[1].scans[0].rgb = probe(0.5).to_vec();
                enrollment.profiles[0].scans[0].ir = Some(probe(ir).to_vec());
                enrollment.profiles[1].scans[0].ir = Some(probe(0.1).to_vec());
                a.signals.rgb_face_brightness = rgb_bright;
                a.ir_brightness = ir_bright;
                let name = format!(
                    "winner/{:08x}/{:08x}/{:08x}",
                    rgb_bright.to_bits(),
                    ir_bright.to_bits(),
                    ir.to_bits()
                );
                let line = record(engine, &name, &enrollment, a);
                // RGB and IR have different winners. Equality selects IR.
                let who = if ir >= 0.5 { "profile-0" } else { "profile-1" };
                assert!(
                    line.contains(&format!("match: {who} (rgb+ir fusion")),
                    "{line}"
                );
                records.push(line);
            }
        }
    }
    for ir_only in [false, true] {
        let (enrollment, mut a) = fixture(engine, 3, 1, false);
        a.sequential_pair = ir_only;
        let line = record(
            engine,
            &format!("equal-profile-tie/{ir_only}"),
            &enrollment,
            a,
        );
        assert!(line.contains("match: profile-0 ("), "{line}");
        records.push(line);
    }
    records
}

fn centroid_boundary_cases(engine: &mut Engine) -> Vec<String> {
    let mut records = Vec::new();
    for profiles in [1, 2, 3] {
        for dark in [false, true] {
            let base = if dark {
                irlume_core::IR_DARK_MATCH_THRESHOLD
            } else {
                irlume_core::IR_MATCH_THRESHOLD
            };
            let threshold = irlume_core::scaled_threshold(base, profiles)
                + if dark {
                    0.0
                } else {
                    irlume_core::IR_FALLBACK_MARGIN
                };
            for cosine in [threshold.next_down(), threshold, threshold.next_up()] {
                let (mut enrollment, mut a) = fixture(engine, profiles, 10, true);
                for profile in &mut enrollment.profiles {
                    for (i, scan) in profile.scans.iter_mut().enumerate() {
                        let mut ir = [0.0; EMBED_DIM];
                        ir[0] = 0.25;
                        ir[3] = (1.0f32 - 0.25 * 0.25).sqrt() * if i % 2 == 0 { -1.0 } else { 1.0 };
                        scan.ir = Some(ir.to_vec());
                    }
                }
                // Keep normalization from moving the requested first coordinate:
                // a third component fills the rounding gap below unit length.
                let mut p = probe(cosine);
                let x = f64::from(p[0]);
                while x * x + f64::from(p[1]).powi(2) > 1.0 {
                    p[1] = p[1].next_down();
                }
                p[2] = (1.0 - x * x - f64::from(p[1]).powi(2)).sqrt() as f32;
                a.ir_embedding = Some(p.to_vec());
                a.embedding = (!dark).then(|| probe(0.2));
                a.rgb_frame_mean = if dark { 0.0 } else { 120.0 };
                a.signals.rgb_face = if dark { None } else { a.signals.rgb_face };
                let matched = engine.ir_match(&enrollment, &p);
                assert!(matched.best < 0.3);
                assert_eq!(matched.centroid.unwrap().0.to_bits(), cosine.to_bits());
                let name = format!(
                    "centroid-boundary/{profiles}/{dark}/{:08x}",
                    cosine.to_bits()
                );
                let line = record(engine, &name, &enrollment, a);
                let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(parsed["granted"], cosine >= threshold, "{line}");
                records.push(line);
            }
        }
    }
    records
}

fn high_count_and_precedence_cases(engine: &mut Engine) -> Vec<String> {
    let mut records = Vec::new();
    // The main Cartesian grid uses 1/5/10 per profile. Keep the earlier
    // plan's 30-per-profile (90 total) synthetic shape as a focused arm.
    for calibrated in [false, true] {
        let (enrollment, _) = fixture(engine, 3, 30, calibrated);
        let threshold = engine.rgb_grant_threshold(90);
        for posture in 0..3 {
            for rgb in [threshold.next_down(), threshold, threshold.next_up()] {
                for ir in [0.2, 0.9] {
                    let (_, mut a) = fixture(engine, 1, 1, false);
                    a.embedding = Some(probe(rgb));
                    a.ir_embedding = Some(probe(ir).to_vec());
                    a.sequential_pair = posture == 1;
                    a.split_pair = posture == 2;
                    let name = format!("count90/{calibrated}/{posture}/{:08x}/{ir}", rgb.to_bits());
                    records.push(record(engine, &name, &enrollment, a));
                }
            }
        }
        let threshold = ir_assessment::IdentityThresholds::new(90, 3, false).best;
        for ir in [threshold.next_down(), threshold, threshold.next_up()] {
            let (_, mut a) = fixture(engine, 1, 1, false);
            a.embedding = None;
            a.rgb_frame_mean = 0.0;
            a.signals.rgb_face = None;
            a.ir_embedding = Some(probe(ir).to_vec());
            let name = format!("count90/dark/{calibrated}/{:08x}", ir.to_bits());
            records.push(record(engine, &name, &enrollment, a));
        }
    }
    for conflict in 0..4 {
        let (mut enrollment, mut a) = fixture(engine, 1, 5, false);
        a.embedding = None;
        a.rgb_frame_mean = 0.0;
        a.signals.rgb_face = None;
        a.shipped_ir_fake = Some(0.99);
        if conflict == 1 {
            a.signals.ir_center_edge_ratio = 0.5;
            a.ir_pad = PadEvidence::Pending;
        }
        if conflict >= 2 {
            for scan in &mut enrollment.profiles[0].scans {
                scan.ir_center_edge_ratio = 2.0;
            }
            a.ir_center_edge_ratio = 1.0;
        }
        if conflict == 3 {
            a.ir_pad = PadEvidence::Score(0.99);
        }
        let line = record(
            engine,
            &format!("dark-precedence/{conflict}"),
            &enrollment,
            a,
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["granted"], false, "{line}");
        records.push(line);
    }
    records
}

#[test]
fn authentication_outcomes_match_the_recorded_characterization() {
    let _guard = env_guard();
    // The trace emits this threshold even when the RGB moire gate is unused.
    let _moire = MoireOverride::clear();
    let mut shared = shared();
    let scope = IrAvailable::new(&mut shared.engine);
    assert!(
        !scope.engine.has_ir_adapter(),
        "this reference covers raw IR"
    );
    let mut lines = lit_cases(scope.engine);
    lines.extend(dark_cases(scope.engine));
    lines.extend(gate_and_selection_cases(scope.engine));
    lines.extend(brightness_and_winner_cases(scope.engine));
    lines.extend(centroid_boundary_cases(scope.engine));
    lines.extend(high_count_and_precedence_cases(scope.engine));
    assert_eq!(
        lines.len(),
        4610,
        "the characterization matrix must not shrink"
    );
    for arm in [
        "(rgb)",
        "rgb+ir fusion",
        "ir-fallback,",
        "(calibrated centroid,",
        "ir/dark, calibrated centroid)",
        "(ir/dark)",
    ] {
        assert!(lines.iter().any(|line| line.contains(arm)), "missing {arm}");
    }
    let mut actual = format!("identity-characterization-v1\ncases {}\n", lines.len());
    for (i, chunk) in lines.chunks(64).enumerate() {
        actual.push_str(&format!("chunk {i} {}\n", digest(chunk)));
    }
    actual.push_str(&format!("total {}\n", digest(&lines)));
    let expected = include_str!("identity_characterization.golden");
    let expected_lines: Vec<_> = expected.lines().collect();
    let differing = actual
        .lines()
        .enumerate()
        .find_map(|(i, line)| (Some(line) != expected_lines.get(i).copied()).then_some(i));
    let start = differing.unwrap_or(2).saturating_sub(2) * 64;
    let end = (start + 64).min(lines.len());
    let diagnostic = &lines[start.min(end)..end];
    assert_eq!(
        actual,
        expected,
        "first differing chunk records:\n{}",
        diagnostic.join("\n")
    );
}
