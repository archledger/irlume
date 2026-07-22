// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume blinkcap` (dev tool, `IRLUME_DEV=1`): capture and replay labeled
//! blink/closure sequences to tune the deliberate-consent gesture offline.
//!
//! The deliberate held-closure gate ([`irlume_liveness::detect_deliberate_closure`])
//! has a provisional frame threshold and no on-hardware validation of its
//! strobe / auto-exposure-settle robustness. Tuning it by re-capturing on every
//! change wastes a live face each time; instead this records the exact
//! [`irlume_liveness::EarSample`] sequence the live gate sees, tagged with the
//! gesture performed, so the detectors can be swept against a fixed dataset.
//!
//!   capture: `IRLUME_DEV=1 irlume blinkcap capture --label held-closure \
//!            --det <yunet.onnx> --model <glintr100.onnx> --mesh <face_landmark.onnx> \
//!            --out data/held-01.jsonl [--ir /dev/video2] [--n 75]`
//!
//!   replay:  `IRLUME_DEV=1 irlume blinkcap replay data/`   (a file or a directory)
//!
//! Labels are free text; the replay summary groups by them. The suggested set
//! for the consent-gesture campaign: `held-closure` (genuine deliberate closes),
//! `natural-blink` (passive spontaneous blinks, must NOT pass), `ae-settle`
//! (look while the room light changes, the exposure-slew false-closure risk),
//! and `spoof` (a photo/print, must NOT pass).

use crate::{engine, flag};
use irlume_liveness::{
    detect_blink, detect_deliberate_closure, BlinkResult, ClosureCalibration, EarSample,
};
use std::path::Path;
use std::process::ExitCode;

/// Derive a [`ClosureCalibration`] from a pool of samples: open = the 75th
/// percentile EAR (eyes-open dominates the open/blink takes), closed = the 10th
/// percentile (the deep closures and blinks). Used for offline replay when no
/// enrollment calibration is stored; the real gate uses the per-user enrollment
/// values. `None` if too few face frames to estimate.
fn derive_calibration(pool: &[f32]) -> Option<ClosureCalibration> {
    let mut v: Vec<f32> = pool.iter().copied().filter(|e| e.is_finite()).collect();
    if v.len() < 8 {
        return None;
    }
    v.sort_by(f32::total_cmp);
    let pct = |p: f32| v[(((v.len() - 1) as f32) * p).round() as usize];
    Some(ClosureCalibration {
        ear_open: pct(0.75),
        ear_closed: pct(0.10),
    })
}

/// One recorded frame: the serializable mirror of [`EarSample`] (the liveness
/// crate stays serde-free; conversion lives here).
#[derive(serde::Serialize, serde::Deserialize)]
struct RecordedSample {
    idx: usize,
    ear: Option<f32>,
    bri: f32,
    cx: f32,
    cy: f32,
    fsize: f32,
    contrast: f32,
}

impl From<&EarSample> for RecordedSample {
    fn from(s: &EarSample) -> Self {
        RecordedSample {
            idx: s.idx,
            ear: s.ear,
            bri: s.bri,
            cx: s.cx,
            cy: s.cy,
            fsize: s.fsize,
            contrast: s.contrast,
        }
    }
}

impl From<&RecordedSample> for EarSample {
    fn from(s: &RecordedSample) -> Self {
        EarSample {
            idx: s.idx,
            ear: s.ear,
            bri: s.bri,
            cx: s.cx,
            cy: s.cy,
            fsize: s.fsize,
            contrast: s.contrast,
        }
    }
}

pub fn run(args: &[String]) -> ExitCode {
    // args[0] is "blinkcap"; the sub-subcommand is args[1].
    match args.get(1).map(String::as_str) {
        Some("capture") => capture(args),
        Some("replay") => replay(args),
        _ => {
            eprintln!(
                "usage: irlume blinkcap <capture|replay>\n  \
                 capture --label L --det <y.onnx> --model <g.onnx> --mesh <fl.onnx> --out F.jsonl [--ir DEV] [--n 75]\n  \
                 replay <file.jsonl | dir>   (runs the detectors + sweeps the closure threshold)"
            );
            ExitCode::from(2)
        }
    }
}

fn capture(args: &[String]) -> ExitCode {
    let (Some(label), Some(det), Some(model), Some(out)) = (
        flag(args, "--label"),
        flag(args, "--det"),
        flag(args, "--model"),
        flag(args, "--out"),
    ) else {
        eprintln!("usage: irlume blinkcap capture --label L --det <y.onnx> --model <g.onnx> --mesh <fl.onnx> --out F.jsonl [--ir DEV] [--n 75]");
        return ExitCode::from(2);
    };
    let n: usize = flag(args, "--n").and_then(|s| s.parse().ok()).unwrap_or(75);

    let run = || -> irlume_common::Result<()> {
        let mut eng = engine(det, model, args)?;
        if !eng.has_mesh() {
            return Err(irlume_common::Error::Hardware(
                "FaceMesh not loaded: pass --mesh <face_landmark.onnx> (the EAR gate needs it)"
                    .into(),
            ));
        }
        println!("[blinkcap] label='{label}' n={n} -> {out}");
        // Countdown so the take has a defined start: the operator can perform a
        // timed gesture (look, hold ~1s, open) instead of guessing when capture
        // began. The camera warm-up inside capture adds ~1s before real frames.
        use std::io::Write as _;
        print!("[blinkcap] get ready");
        let _ = std::io::stdout().flush();
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_millis(700));
            print!(" .");
            let _ = std::io::stdout().flush();
        }
        println!(" GO  (capturing ~{}s)", n / 15);
        let samples = eng.capture_ear_samples(n)?;
        write_jsonl(out, label, &samples)?;
        // Immediate feedback: face count + blink verdict. The consent verdict
        // needs a per-user calibration (open + closed EAR) that a single gesture
        // take cannot supply, so it comes from `blinkcap replay` on the dataset.
        println!(
            "[blinkcap] captured {} frames, {} with a face; detect_blink={:?}",
            samples.len(),
            samples.iter().filter(|s| s.ear.is_some()).count(),
            detect_blink(&samples),
        );
        println!("[blinkcap] saved. Run `blinkcap replay <dir>` for the consent-gate verdict.");
        Ok(())
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[blinkcap] {e}");
            ExitCode::FAILURE
        }
    }
}

fn write_jsonl(out: &str, label: &str, samples: &[EarSample]) -> irlume_common::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(out).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    let header = serde_json::json!({
        "blinkcap": true,
        "label": label,
        "frames": samples.len(),
        "host": std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default().trim().to_string(),
    });
    writeln!(f, "{header}").map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    for s in samples {
        let rec = RecordedSample::from(s);
        writeln!(f, "{}", serde_json::to_string(&rec).unwrap())
            .map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    }
    Ok(())
}

/// A loaded recording: its label and the samples the detectors consume.
struct Recording {
    file: String,
    label: String,
    samples: Vec<EarSample>,
}

fn load_recording(path: &Path) -> Option<Recording> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let header: serde_json::Value = serde_json::from_str(lines.next()?).ok()?;
    if header.get("blinkcap").and_then(|v| v.as_bool()) != Some(true) {
        return None; // not one of ours
    }
    let label = header
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("unlabeled")
        .to_string();
    let samples = lines
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<RecordedSample>(l).ok())
        .map(|r| EarSample::from(&r))
        .collect();
    Some(Recording {
        file: path.file_name()?.to_string_lossy().into_owned(),
        label,
        samples,
    })
}

fn replay(args: &[String]) -> ExitCode {
    // args = ["blinkcap", "replay", <target>].
    let Some(target) = args.get(2) else {
        eprintln!("usage: irlume blinkcap replay <file.jsonl | dir>");
        return ExitCode::from(2);
    };
    let path = Path::new(target);
    let mut files: Vec<std::path::PathBuf> = if path.is_dir() {
        let mut v: Vec<_> = std::fs::read_dir(path)
            .map(|rd| {
                rd.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    } else {
        vec![path.to_path_buf()]
    };
    files.sort();
    let recordings: Vec<Recording> = files.iter().filter_map(|p| load_recording(p)).collect();
    if recordings.is_empty() {
        eprintln!("[blinkcap] no blinkcap recordings found at {target}");
        return ExitCode::FAILURE;
    }

    // Derive one calibration from the WHOLE dataset (the real gate uses per-user
    // enrollment values; here the pooled open/closed percentiles stand in). The
    // consent detector needs an absolute threshold, not a per-take median which
    // a held closure would pollute.
    let pool: Vec<f32> = recordings
        .iter()
        .flat_map(|r| r.samples.iter().filter_map(|s| s.ear))
        .collect();
    let Some(cal) = derive_calibration(&pool) else {
        eprintln!("[blinkcap] too few face frames to derive a calibration");
        return ExitCode::FAILURE;
    };
    println!(
        "== calibration (pooled): open EAR {:.3}, closed EAR {:.3}, closed threshold {:.3}{} ==",
        cal.ear_open,
        cal.ear_closed,
        cal.closed_threshold(),
        if cal.is_usable() {
            ""
        } else {
            "  ⚠ open/closed gap too small"
        }
    );

    // Per-recording verdicts at the current (default/env) threshold.
    println!(
        "== per-recording (closure threshold = {} frames) ==",
        closure_default()
    );
    for r in &recordings {
        let s = &r.samples;
        println!(
            "  {:<28} label={:<14} frames={:<3} blink={:?} consent={:?} maxclosure={}",
            r.file,
            r.label,
            s.len(),
            detect_blink(s),
            detect_deliberate_closure(s, &cal),
            max_closure_frames(s, &cal),
        );
    }

    // Threshold sweep: for each candidate closure-frame count, how many of each
    // label the consent gate ACCEPTS. The goal is a threshold that accepts
    // `held-closure` and rejects everything else.
    let labels: Vec<String> = {
        let mut ls: Vec<String> = recordings.iter().map(|r| r.label.clone()).collect();
        ls.sort();
        ls.dedup();
        ls
    };
    println!("\n== consent-gate acceptance by closure threshold (accepted / total per label) ==");
    print!("  frames");
    for l in &labels {
        print!("  {l:>14}");
    }
    println!();
    for thr in 3..=20 {
        std::env::set_var("IRLUME_CONSENT_CLOSURE_FRAMES", thr.to_string());
        print!("  {thr:>6}");
        for l in &labels {
            let group: Vec<&Recording> = recordings.iter().filter(|r| &r.label == l).collect();
            let acc = group
                .iter()
                .filter(|r| detect_deliberate_closure(&r.samples, &cal) == BlinkResult::Blinked)
                .count();
            print!("  {:>14}", format!("{}/{}", acc, group.len()));
        }
        println!();
    }
    std::env::remove_var("IRLUME_CONSENT_CLOSURE_FRAMES");
    println!(
        "\n  Pick the smallest threshold that accepts every 'held-closure' and rejects\n  \
         every 'natural-blink' / 'ae-settle' / 'spoof'. Set it as CONSENT_CLOSURE_MIN_FRAMES."
    );
    ExitCode::SUCCESS
}

/// Longest sustained sub-threshold closure run in a recording (frames), the raw
/// signal the consent gate thresholds. Found by sweeping the run-length bar with
/// the given calibration until the detector stops accepting.
fn max_closure_frames(samples: &[EarSample], cal: &ClosureCalibration) -> usize {
    let mut best = 0;
    for thr in 1..=samples.len().max(1) {
        std::env::set_var("IRLUME_CONSENT_CLOSURE_FRAMES", thr.to_string());
        if detect_deliberate_closure(samples, cal) == BlinkResult::Blinked {
            best = thr;
        } else {
            break;
        }
    }
    std::env::remove_var("IRLUME_CONSENT_CLOSURE_FRAMES");
    best
}

fn closure_default() -> usize {
    std::env::var("IRLUME_CONSENT_CLOSURE_FRAMES")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(irlume_liveness::CONSENT_CLOSURE_MIN_FRAMES)
}
