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
use irlume_liveness::{detect_blink, detect_deliberate_closure, BlinkResult, EarSample};
use std::path::Path;
use std::process::ExitCode;

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
        println!(
            "[blinkcap] perform the gesture NOW; capturing ~{}s...",
            n / 15
        );
        let samples = eng.capture_ear_samples(n)?;
        write_jsonl(out, label, &samples)?;
        // Live verdicts so the operator can confirm the take before saving more.
        println!(
            "[blinkcap] captured {} frames, {} with a face; detect_blink={:?} detect_deliberate_closure={:?}",
            samples.len(),
            samples.iter().filter(|s| s.ear.is_some()).count(),
            detect_blink(&samples),
            detect_deliberate_closure(&samples),
        );
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
            detect_deliberate_closure(s),
            max_closure_frames(s),
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
                .filter(|r| detect_deliberate_closure(&r.samples) == BlinkResult::Blinked)
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

/// Longest sustained eyelid closure in a recording, in frame indices: the raw
/// signal the consent threshold is compared against. Mirrors the deep-dip
/// closure span in `blink_scan` but reported here for dataset inspection.
fn max_closure_frames(samples: &[EarSample]) -> usize {
    // Reuse the detector by sweeping: the largest threshold that still accepts
    // is the max closure length. Bounded by the sample count.
    let mut best = 0;
    for thr in 1..=samples.len() {
        std::env::set_var("IRLUME_CONSENT_CLOSURE_FRAMES", thr.to_string());
        if detect_deliberate_closure(samples) == BlinkResult::Blinked {
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
