// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume padcapture` / `irlume padreport`: the ISO/IEC 30107-3 presentation-
//! attack-detection (PAD) self-test harness.
//!
//! `padcapture` runs the REAL liveness gate (`irlume_liveness::LivenessGate`, the
//! same code the daemon authenticates with) over operator-labeled presentations,
//! bona-fide live faces and attack instruments (printed photos, screen replays,
//! cutouts), and appends one record per presentation to a JSONL log. `padreport`
//! aggregates that log into the standard PAD metrics (APCER per PAI species,
//! worst-case; BPCER; non-response; ACER) with exact confidence intervals via
//! [`irlume_core::pad`].
//!
//! Scope: the harness measures the **credential-releasing IR gate**: the full
//! RGB+IR path (`--path full`, default) and the dark IR-only path
//! (`--path ir-only`). The RGB-only convenience tier is deterrent-grade, is limited
//! to lock-screen unlock and never releases credentials, and is deliberately
//! excluded from the PAD claim (see docs/PAD_SELFTEST.md).

use irlume_core::pad as metrics;
use irlume_liveness::{FaceBox, LivenessGate, Signals, Verdict};
use std::io::Write;

/// Which gate path to exercise.
#[derive(Clone, Copy, PartialEq)]
enum Path {
    Full,
    IrOnly,
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Live => "Live",
        Verdict::Spoof => "Spoof",
        Verdict::Uncertain => "Uncertain",
    }
}

/// The hard cue a `Spoof` verdict failed on, replicating the gate's short-circuit
/// order so the report can attribute each caught attack to the cue that stopped it.
fn caught_cue(path: Path, s: &Signals) -> Option<&'static str> {
    let ir_present = s
        .ir_face
        .map(|f| f.score >= irlume_liveness::MIN_FACE_SCORE)
        .unwrap_or(false);
    match path {
        Path::Full => {
            if !ir_present {
                Some("face_in_ir")
            } else if s.ir_face_brightness < irlume_liveness::IR_FACE_MIN_BRIGHTNESS {
                Some("ir_reflectance")
            } else if s.ir_center_edge_ratio < irlume_liveness::DEPTH_MIN_RATIO {
                Some("depth")
            } else {
                None
            }
        }
        Path::IrOnly => {
            if s.ir_face_brightness < irlume_liveness::IR_FACE_MIN_BRIGHTNESS {
                Some("ir_reflectance")
            } else if s.ir_center_edge_ratio < irlume_liveness::DEPTH_MIN_RATIO {
                Some("depth")
            } else {
                None
            }
        }
    }
}

/// Capture RGB+IR once, build the exact `Signals` the auth path uses, and run the
/// chosen gate path. Mirrors `liveness_probe` so the self-test measures the real gate.
fn capture_once(
    det: &mut irlume_vision::Detector,
    rgb_dev: &str,
    ir_dev: &str,
    path: Path,
) -> irlume_common::Result<(Verdict, irlume_liveness::Cues, String, Signals)> {
    let to_fbox = |f: &irlume_vision::Detection, w: u32, h: u32| FaceBox {
        cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
        cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
        score: f.score,
    };

    // RGB (only needed for the full path's cross-spectrum + pose cues).
    let (rgb_face, head_yaw_asym, head_pitch_frac) = if path == Path::Full {
        let rgb = irlume_camera::capture_rgb(rgb_dev)?;
        let rv = irlume_vision::align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        };
        let faces = det.detect(&rv)?;
        let top = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));
        let pose = top.map(|f| irlume_vision::head_pose(&f.landmarks));
        (
            top.map(|f| to_fbox(f, rgb.width, rgb.height)),
            pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            pose.map(|p| p.pitch_frac).unwrap_or(0.5),
        )
    } else {
        (None, 0.0, 0.5)
    };

    // IR (brightest-of-burst, matches the auth path).
    let ir = irlume_camera::capture_ir(ir_dev)?;
    let ir_rgb = irlume_camera::grey_to_rgb(&ir.data);
    let iv = irlume_vision::align::RgbView {
        data: &ir_rgb,
        width: ir.width,
        height: ir.height,
    };
    let ir_top = det
        .detect(&iv)?
        .into_iter()
        .max_by(|a, b| a.score.total_cmp(&b.score));

    let ir_face_brightness = ir_top
        .as_ref()
        .map(|f| crate::mean_in_bbox(&ir.data, ir.width, ir.height, &f.bbox))
        .unwrap_or(0.0);
    let ir_center_edge_ratio = ir_top
        .as_ref()
        .map(|f| crate::center_edge_ratio(&ir.data, ir.width, ir.height, &f.bbox))
        .unwrap_or(0.0);
    let ir_eye_glint = ir_top
        .as_ref()
        .map(|f| crate::eye_glint(&ir.data, ir.width, ir.height, &f.landmarks))
        .unwrap_or(0.0);

    let signals = Signals {
        rgb_face,
        ir_face: ir_top.as_ref().map(|f| to_fbox(f, ir.width, ir.height)),
        ir_face_brightness,
        ir_center_edge_ratio,
        ir_eye_glint,
        head_yaw_asym,
        head_pitch_frac,
        ..Default::default()
    };
    let gate = LivenessGate::new();
    let (verdict, cues, reason) = match path {
        Path::Full => gate.evaluate(&signals),
        Path::IrOnly => gate.evaluate_ir_only(&signals),
    };
    Ok((verdict, cues, reason, signals))
}

/// `irlume padcapture --species NAME --kind attack|bonafide --det <yunet.onnx>
///   --out pad.jsonl [--path full|ir-only] [--n 10] [--rgb ..] [--ir ..] [--no-prompt]`
pub(crate) fn padcapture(args: &[String]) -> std::process::ExitCode {
    let (Some(species), Some(kind), Some(det_path), Some(out)) = (
        crate::flag(args, "--species"),
        crate::flag(args, "--kind"),
        crate::flag(args, "--det"),
        crate::flag(args, "--out"),
    ) else {
        eprintln!("usage: irlume padcapture --species <name> --kind attack|bonafide --det <yunet.onnx> --out <pad.jsonl> [--path full|ir-only] [--n 10] [--rgb /dev/video0] [--ir /dev/video2] [--no-prompt]");
        eprintln!("  attack species e.g.: print_matte, print_glossy, phone_replay, tablet_replay, laptop_replay, cutout");
        return std::process::ExitCode::from(2);
    };
    if kind != "attack" && kind != "bonafide" {
        eprintln!("padcapture: --kind must be 'attack' or 'bonafide'");
        return std::process::ExitCode::from(2);
    }
    let path = match crate::flag(args, "--path").unwrap_or("full") {
        "full" => Path::Full,
        "ir-only" => Path::IrOnly,
        other => {
            eprintln!("padcapture: --path must be 'full' or 'ir-only' (got '{other}')");
            return std::process::ExitCode::from(2);
        }
    };
    let rgb_dev = crate::flag(args, "--rgb").unwrap_or(irlume_camera::DEFAULT_RGB_DEVICE);
    let ir_dev = crate::flag(args, "--ir").unwrap_or(irlume_camera::DEFAULT_IR_DEVICE);
    let n: usize = crate::flag(args, "--n")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let prompt = !args.iter().any(|a| a == "--no-prompt");
    let path_str = if path == Path::Full {
        "full"
    } else {
        "ir-only"
    };

    let run = || -> irlume_common::Result<usize> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        // Append: a PAD run builds up across many species into one log.
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .map_err(|e| irlume_common::Error::Io(e.to_string()))?;

        println!("[padcapture] species={species} kind={kind} path={path_str} n={n} -> {out}");
        if kind == "attack" {
            println!("[padcapture] SECURITY SELF-TEST: present the '{species}' attack instrument to the camera.");
            println!("             A HARD gate should reject every one (verdict Spoof/Uncertain).");
        } else {
            println!("[padcapture] present the LIVE enrolled user's face (bona-fide baseline).");
        }
        if !prompt {
            println!(
                "[padcapture] --no-prompt: capturing {n} frames back-to-back (no per-frame pause)."
            );
        }

        let mut accepted_attacks = 0usize;
        let mut written = 0usize;
        for idx in 0..n {
            if prompt {
                print!(
                    "  [{}/{n}] set up the presentation, then press Enter (or 'q' to stop)… ",
                    idx + 1
                );
                std::io::stdout().flush().ok();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).ok();
                if line.trim().eq_ignore_ascii_case("q") {
                    break;
                }
            }
            let (verdict, cues, reason, s) = capture_once(&mut det, rgb_dev, ir_dev, path)?;
            let caught = if verdict == Verdict::Spoof {
                caught_cue(path, &s)
            } else {
                None
            };

            let mut rec = serde_json::Map::new();
            rec.insert("species".into(), species.into());
            rec.insert("kind".into(), kind.into());
            rec.insert("path".into(), path_str.into());
            rec.insert("idx".into(), idx.into());
            rec.insert("verdict".into(), verdict_str(verdict).into());
            rec.insert("reason".into(), reason.clone().into());
            rec.insert(
                "caught".into(),
                serde_json::to_value(caught.map(|c| vec![c]).unwrap_or_default()).unwrap(),
            );
            rec.insert("rgb_present".into(), s.rgb_face.is_some().into());
            rec.insert("ir_present".into(), s.ir_face.is_some().into());
            rec.insert(
                "rgb_score".into(),
                crate::json_f32(s.rgb_face.map(|f| f.score).unwrap_or(0.0)),
            );
            rec.insert(
                "ir_score".into(),
                crate::json_f32(s.ir_face.map(|f| f.score).unwrap_or(0.0)),
            );
            rec.insert(
                "ir_brightness".into(),
                crate::json_f32(s.ir_face_brightness),
            );
            rec.insert("ir_depth".into(), crate::json_f32(s.ir_center_edge_ratio));
            rec.insert("ir_glint".into(), crate::json_f32(s.ir_eye_glint));
            let cross = match (s.rgb_face, s.ir_face) {
                (Some(r), Some(i)) => ((r.cx - i.cx).powi(2) + (r.cy - i.cy).powi(2)).sqrt(),
                _ => f32::NAN,
            };
            rec.insert("cross_dist".into(), crate::json_f32(cross));
            rec.insert("yaw_asym".into(), crate::json_f32(s.head_yaw_asym));
            rec.insert("pitch_frac".into(), crate::json_f32(s.head_pitch_frac));
            let cues_json = serde_json::json!({
                "face_in_rgb": cues.face_in_rgb,
                "face_in_ir": cues.face_in_ir,
                "cross_spectrum_aligned": cues.cross_spectrum_aligned,
                "ir_reflectance_ok": cues.ir_reflectance_ok,
                "depth_ok": cues.depth_ok,
                "glint_present": cues.glint_present,
                "frontal_ok": cues.frontal_ok,
            });
            rec.insert("cues".into(), cues_json);

            writeln!(f, "{}", serde_json::Value::Object(rec))
                .map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            written += 1;

            // Live-progress feedback. For an attack, an accepted verdict is a BREACH.
            let flag = if kind == "attack" && verdict == Verdict::Live {
                accepted_attacks += 1;
                " ‼ ACCEPTED (breach!)"
            } else if kind == "bonafide" && verdict != Verdict::Live {
                " ✗ rejected a real user"
            } else {
                ""
            };
            println!(
                "      -> {} | ir {} bri {:>5.1} depth {:>5.2} glint {:>3.0} | {}{}",
                verdict_str(verdict),
                if s.ir_face.is_some() { "✓" } else { "·" },
                s.ir_face_brightness,
                s.ir_center_edge_ratio,
                s.ir_eye_glint,
                reason,
                flag,
            );
        }
        if kind == "attack" && accepted_attacks > 0 {
            println!("[padcapture] ⚠ {accepted_attacks}/{written} attack presentations were ACCEPTED; investigate before trusting this build.");
        }
        Ok(written)
    };
    match run() {
        Ok(w) => {
            println!("[padcapture] appended {w} presentations to {out}");
            println!(
                "[padcapture] run `irlume padreport --in {out}` when all species are captured."
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("padcapture error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume padreport --in pad.jsonl [--md report.md]`
pub(crate) fn padreport(args: &[String]) -> std::process::ExitCode {
    let Some(input) = crate::flag(args, "--in") else {
        eprintln!("usage: irlume padreport --in <pad.jsonl> [--md <report.md>]");
        return std::process::ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(input) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("padreport: cannot read {input}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut trials: Vec<metrics::Trial> = Vec::new();
    let mut path_seen = std::collections::BTreeSet::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("padreport: skipping malformed line {}: {e}", lineno + 1);
                continue;
            }
        };
        let species = v
            .get("species")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let label = match v.get("kind").and_then(|x| x.as_str()) {
            Some("attack") => metrics::Label::Attack,
            Some("bonafide") => metrics::Label::BonaFide,
            _ => {
                eprintln!(
                    "padreport: skipping line {} (missing/invalid kind)",
                    lineno + 1
                );
                continue;
            }
        };
        let outcome = match v.get("verdict").and_then(|x| x.as_str()) {
            Some("Live") => metrics::Outcome::Accepted,
            Some("Spoof") => metrics::Outcome::Rejected,
            Some("Uncertain") => metrics::Outcome::NonResponse,
            _ => {
                eprintln!(
                    "padreport: skipping line {} (missing/invalid verdict)",
                    lineno + 1
                );
                continue;
            }
        };
        let caught = v
            .get("caught")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(p) = v.get("path").and_then(|x| x.as_str()) {
            path_seen.insert(p.to_string());
        }
        trials.push(metrics::Trial {
            species,
            label,
            outcome,
            caught,
        });
    }

    if trials.is_empty() {
        eprintln!("padreport: no usable records in {input}");
        return std::process::ExitCode::FAILURE;
    }

    let report = metrics::analyze(&trials);
    let paths: Vec<String> = path_seen.into_iter().collect();
    let text_out = render_human(&report, input, &paths);
    print!("{text_out}");

    if let Some(md_path) = crate::flag(args, "--md") {
        let md = render_markdown(&report, input, &paths);
        match std::fs::write(md_path, md) {
            Ok(()) => println!("\n[padreport] wrote markdown report to {md_path}"),
            Err(e) => eprintln!("padreport: cannot write {md_path}: {e}"),
        }
    }
    std::process::ExitCode::SUCCESS
}

fn pct(x: f64) -> String {
    if x.is_nan() {
        "  n/a".into()
    } else {
        format!("{:>5.1}%", x * 100.0)
    }
}

fn render_human(r: &metrics::PadReport, input: &str, paths: &[String]) -> String {
    let mut o = String::new();
    o.push_str(&format!("\nISO/IEC 30107-3 PAD self-test: {input}\n"));
    o.push_str(&format!(
        "gate path(s): {}   attack presentations: {}   bona-fide: {}\n\n",
        if paths.is_empty() {
            "unknown".into()
        } else {
            paths.join(", ")
        },
        r.n_attacks,
        r.n_bonafide
    ));

    o.push_str("Per-PAI-species APCER (attacks classified as bona fide; lower is better)\n");
    o.push_str("  species              n   APCER   95% CI            non-resp   caught-by\n");
    for s in &r.species {
        let cues = if s.cue_hits.is_empty() {
            "-".to_string()
        } else {
            s.cue_hits
                .iter()
                .map(|(c, n)| format!("{c}:{n}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        o.push_str(&format!(
            "  {:<18} {:>3}   {}   [{}, {}]   {}   {}\n",
            s.species,
            s.n_attacks,
            pct(s.apcer.p),
            pct(s.apcer.lo),
            pct(s.apcer.hi),
            pct(s.nonresponse.p),
            cues,
        ));
    }

    o.push('\n');
    match &r.worst_apcer {
        Some((sp, ap)) => o.push_str(&format!(
            "WORST-CASE APCER: {} @ {}   <- the ISO headline (max across species)\n",
            sp,
            pct(*ap)
        )),
        None => o.push_str("WORST-CASE APCER: n/a (no attack presentations)\n"),
    }
    o.push_str(&format!(
        "BPCER (live users wrongly rejected): {}   [{}, {}]   (n={})\n",
        pct(r.bpcer.p),
        pct(r.bpcer.lo),
        pct(r.bpcer.hi),
        r.bpcer.den
    ));
    o.push_str(&format!(
        "bona-fide non-response (re-present): {}   (n={})\n",
        pct(r.bonafide_nonresponse.p),
        r.bonafide_nonresponse.den
    ));
    match r.acer {
        Some(a) => o.push_str(&format!(
            "ACER = (worst APCER + BPCER)/2 = {}   (legacy iBeta headline)\n",
            pct(a)
        )),
        None => o.push_str("ACER: n/a\n"),
    }

    // Honest reading of the numbers.
    o.push_str("\nReading this: a 0% point estimate does NOT prove 0%; read the upper CI\n");
    o.push_str("bound. Small n gives wide intervals; capture more presentations to tighten.\n");
    if r.n_bonafide == 0 {
        o.push_str("NOTE: no bona-fide presentations captured; BPCER is undefined. Capture a\n");
        o.push_str(
            "      bona-fide baseline (--kind bonafide) so false-reject rate is measured.\n",
        );
    }
    o
}

fn render_markdown(r: &metrics::PadReport, input: &str, paths: &[String]) -> String {
    let mut o = String::new();
    o.push_str("## IR liveness PAD self-test results\n\n");
    o.push_str(&format!(
        "_Source: `{}` · gate path(s): {} · {} attack / {} bona-fide presentations._\n\n",
        input,
        if paths.is_empty() {
            "unknown".into()
        } else {
            paths.join(", ")
        },
        r.n_attacks,
        r.n_bonafide
    ));
    o.push_str("| PAI species | n | APCER | 95% CI | non-resp | caught-by |\n");
    o.push_str("|---|---:|---:|---|---:|---|\n");
    for s in &r.species {
        let cues = if s.cue_hits.is_empty() {
            "–".to_string()
        } else {
            s.cue_hits
                .iter()
                .map(|(c, n)| format!("{c}:{n}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        o.push_str(&format!(
            "| {} | {} | {} | [{}, {}] | {} | {} |\n",
            s.species,
            s.n_attacks,
            pct(s.apcer.p).trim(),
            pct(s.apcer.lo).trim(),
            pct(s.apcer.hi).trim(),
            pct(s.nonresponse.p).trim(),
            cues,
        ));
    }
    o.push('\n');
    let worst = match &r.worst_apcer {
        Some((sp, ap)) => format!("**{} @ {}**", sp, pct(*ap).trim()),
        None => "n/a".into(),
    };
    o.push_str(&format!("- **Worst-case APCER:** {worst}\n"));
    o.push_str(&format!(
        "- **BPCER:** {} (95% CI [{}, {}], n={})\n",
        pct(r.bpcer.p).trim(),
        pct(r.bpcer.lo).trim(),
        pct(r.bpcer.hi).trim(),
        r.bpcer.den
    ));
    if let Some(a) = r.acer {
        o.push_str(&format!("- **ACER:** {} (legacy)\n", pct(a).trim()));
    }
    o.push_str("\n> Self-administered per ISO/IEC 30107-3 methodology; not a lab-accredited\n");
    o.push_str("> evaluation. See `docs/PAD_SELFTEST.md` for protocol, PAI species, and limits.\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_liveness::{DEPTH_MIN_RATIO, IR_FACE_MIN_BRIGHTNESS, MIN_FACE_SCORE};

    /// Signals that pass every cue the attribution helper looks at.
    fn passing_signals() -> Signals {
        Signals {
            ir_face: Some(FaceBox {
                cx: 0.5,
                cy: 0.5,
                score: MIN_FACE_SCORE + 0.2,
            }),
            ir_face_brightness: IR_FACE_MIN_BRIGHTNESS + 20.0,
            ir_center_edge_ratio: DEPTH_MIN_RATIO + 0.2,
            ..Default::default()
        }
    }

    #[test]
    fn verdict_str_names_every_verdict() {
        assert_eq!(verdict_str(Verdict::Live), "Live");
        assert_eq!(verdict_str(Verdict::Spoof), "Spoof");
        assert_eq!(verdict_str(Verdict::Uncertain), "Uncertain");
    }

    // caught_cue replicates the gate's short-circuit order; if the gate's cue
    // order changes, this attribution must change with it.
    #[test]
    fn caught_cue_full_path_attributes_in_gate_order() {
        let mut s = passing_signals();
        assert_eq!(caught_cue(Path::Full, &s), None);

        s.ir_center_edge_ratio = DEPTH_MIN_RATIO - 0.1;
        assert_eq!(caught_cue(Path::Full, &s), Some("depth"));

        // Reflectance failure outranks the depth failure.
        s.ir_face_brightness = IR_FACE_MIN_BRIGHTNESS - 1.0;
        assert_eq!(caught_cue(Path::Full, &s), Some("ir_reflectance"));

        // Presence outranks everything: no IR face, or one below MIN_FACE_SCORE.
        let mut weak = passing_signals();
        weak.ir_face.as_mut().unwrap().score = MIN_FACE_SCORE - 0.1;
        assert_eq!(caught_cue(Path::Full, &weak), Some("face_in_ir"));
        let mut absent = passing_signals();
        absent.ir_face = None;
        assert_eq!(caught_cue(Path::Full, &absent), Some("face_in_ir"));
    }

    #[test]
    fn caught_cue_ir_only_path_skips_the_presence_cue() {
        // The IR-only gate assumes presence (it just matched the face); its
        // first hard cue is reflectance, even with no ir_face in the signals.
        let mut s = passing_signals();
        s.ir_face = None;
        s.ir_face_brightness = IR_FACE_MIN_BRIGHTNESS - 1.0;
        assert_eq!(caught_cue(Path::IrOnly, &s), Some("ir_reflectance"));

        let mut s = passing_signals();
        s.ir_center_edge_ratio = DEPTH_MIN_RATIO - 0.1;
        assert_eq!(caught_cue(Path::IrOnly, &s), Some("depth"));
        assert_eq!(caught_cue(Path::IrOnly, &passing_signals()), None);
    }

    #[test]
    fn pct_formats_rates_and_maps_nan_to_na() {
        assert_eq!(pct(f64::NAN), "  n/a");
        assert_eq!(pct(0.0), "  0.0%");
        assert_eq!(pct(0.25), " 25.0%");
        assert_eq!(pct(1.0), "100.0%");
    }

    fn attack(species: &str, outcome: metrics::Outcome, caught: &[&str]) -> metrics::Trial {
        metrics::Trial {
            species: species.into(),
            label: metrics::Label::Attack,
            outcome,
            caught: caught.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn bonafide(outcome: metrics::Outcome) -> metrics::Trial {
        metrics::Trial {
            species: "bonafide".into(),
            label: metrics::Label::BonaFide,
            outcome,
            caught: Vec::new(),
        }
    }

    #[test]
    fn renderers_carry_the_iso_numbers_and_cue_attribution() {
        use metrics::Outcome::{Accepted, Rejected};
        let trials = vec![
            attack("print_glossy", Rejected, &["depth"]),
            attack("print_glossy", Rejected, &["depth"]),
            attack("print_glossy", Accepted, &[]),
            bonafide(Accepted),
            bonafide(Accepted),
            bonafide(Accepted),
            bonafide(Rejected),
        ];
        let r = metrics::analyze(&trials);

        let h = render_human(&r, "pad.jsonl", &["full".to_string()]);
        assert!(h.contains("gate path(s): full"), "{h}");
        assert!(h.contains("attack presentations: 3"), "{h}");
        assert!(h.contains("bona-fide: 4"), "{h}");
        assert!(h.contains("print_glossy"), "{h}");
        assert!(h.contains("33.3%"), "APCER 1 accepted of 3: {h}");
        assert!(h.contains("depth:2"), "cue attribution: {h}");
        assert!(h.contains("WORST-CASE APCER: print_glossy"), "{h}");
        assert!(h.contains("25.0%"), "BPCER 1 of 4: {h}");
        assert!(h.contains("29.2%"), "ACER = (33.3 + 25.0)/2: {h}");
        assert!(
            h.contains("upper CI"),
            "the report must warn against reading 0% literally: {h}"
        );

        let m = render_markdown(&r, "pad.jsonl", &["full".to_string()]);
        assert!(m.contains("| print_glossy | 3 | 33.3% |"), "{m}");
        assert!(
            m.contains("**Worst-case APCER:** **print_glossy @ 33.3%**"),
            "{m}"
        );
        assert!(m.contains("**BPCER:** 25.0%"), "{m}");
        assert!(m.contains("not a lab-accredited"), "{m}");
    }

    #[test]
    fn render_human_flags_a_missing_bonafide_baseline() {
        let trials = vec![attack("cutout", metrics::Outcome::Rejected, &["depth"])];
        let r = metrics::analyze(&trials);
        let h = render_human(&r, "pad.jsonl", &[]);
        assert!(h.contains("gate path(s): unknown"), "{h}");
        assert!(h.contains("no bona-fide presentations captured"), "{h}");
        assert!(h.contains("n/a"), "BPCER with n=0 renders n/a: {h}");
    }
}
