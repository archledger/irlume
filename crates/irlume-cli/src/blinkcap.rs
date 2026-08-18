// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume blinkcap` (dev tool, `IRLUME_DEV=1`): capture and replay labeled
//! blink/closure sequences to tune the deliberate-consent gesture offline.
//!
//! The deliberate held-closure gate ([`irlume_liveness::detect_deliberate_closure`])
//! has a provisional frame threshold and no on-hardware validation of its
//! strobe / auto-exposure-settle behavior. Tuning it by re-capturing on every
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
//!   selector shadow:
//!   `IRLUME_DEV=1 irlume blinkcap select --profiles profiles.json \
//!      --attempts attempts/ --prefix-frames 6`
//!
//! The selector manifest names repeated open/closed blinkcap recordings for
//! each condition. Paths are relative to the manifest unless absolute:
//!
//! ```json
//! {"profiles":[{"name":"desk-glasses",
//!   "open":["open-1.jsonl","open-2.jsonl"],
//!   "closed":["closed-1.jsonl","closed-2.jsonl"]}]}
//! ```
//!
//! Selector output is evidence only. It never reaches the daemon, enrollment,
//! or authorization outcome, and the prefix length is deliberately explicit
//! because no production value has been qualified.
//!
//! Labels are free text; the replay summary groups by them. The suggested set
//! for the consent-gesture campaign: `held-closure` (genuine deliberate closes),
//! `natural-blink` (passive spontaneous blinks, must NOT pass), `ae-settle`
//! (look while the room light changes, the exposure-slew false-closure risk),
//! and `spoof` (a photo/print, must NOT pass).

use crate::{engine, flag};
use irlume_liveness::{
    detect_blink, detect_deliberate_closure, select_closure_profile, BlinkResult,
    ClosureCalibration, ClosureProfileRange, ClosureProfileSelection, EarSample,
};
use std::path::{Path, PathBuf};
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
        Some("select") => selector(args),
        _ => {
            eprintln!(
                "usage: irlume blinkcap <capture|replay|select>\n  \
                 capture --label L --det <y.onnx> --model <g.onnx> --mesh <fl.onnx> --out F.jsonl [--ir DEV] [--n 75]\n  \
                 replay <file.jsonl | dir>   (runs the detectors + sweeps the closure threshold)\n  \
                 select --profiles P.json --attempts <file.jsonl | dir> --prefix-frames N"
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
    // `--pose` records HEAD POSE (pitch/yaw) for the head-nod gesture instead of
    // EAR; needs only the detector, not the FaceMesh.
    let pose_mode = args.iter().any(|a| a == "--pose");

    let run = || -> irlume_common::Result<()> {
        let mut eng = engine(det, model, args)?;
        if !pose_mode && !eng.has_mesh() {
            return Err(irlume_common::Error::Hardware(
                "FaceMesh not loaded: pass --mesh <face_landmark.onnx> (the EAR gate needs it)"
                    .into(),
            ));
        }
        println!(
            "[blinkcap] label='{label}' n={n}{} -> {out}",
            if pose_mode { " (pose)" } else { "" }
        );
        // Countdown so the take has a defined start: the operator performs a
        // timed gesture instead of guessing when capture began. The camera
        // warm-up inside capture adds ~1s before real frames.
        use std::io::Write as _;
        print!("[blinkcap] get ready");
        let _ = std::io::stdout().flush();
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_millis(700));
            print!(" .");
            let _ = std::io::stdout().flush();
        }
        println!(" GO  (capturing ~{}s)", n / 15);
        if pose_mode {
            let samples = eng.capture_pose_samples(n)?;
            write_pose_jsonl(out, label, &samples)?;
            println!(
                "[blinkcap] captured {} frames, {} with a face (pose).",
                samples.len(),
                samples.iter().filter(|s| s.pitch_frac.is_some()).count(),
            );
        } else {
            let samples = eng.capture_ear_samples(n)?;
            write_jsonl(out, label, &samples)?;
            println!(
                "[blinkcap] captured {} frames, {} with a face; detect_blink={:?}",
                samples.len(),
                samples.iter().filter(|s| s.ear.is_some()).count(),
                detect_blink(&samples),
            );
        }
        println!("[blinkcap] saved.");
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

/// Serializable mirror of a head-pose sample (liveness crate stays serde-free).
#[derive(serde::Serialize, serde::Deserialize)]
struct RecordedPose {
    idx: usize,
    pitch_frac: Option<f32>,
    yaw_signed: Option<f32>,
    bri: f32,
}

/// Install a finished capture at `out` through a `.tmp` file in the same
/// directory, synced before the rename. Writing the destination directly
/// left a crash window where a valid header sat over a truncated body, and
/// replay refuses such a file loudly; a capture killed mid-write must leave
/// either the previous file or nothing. The `.tmp` suffix also keeps a
/// leftover out of replay's `.jsonl` scan.
fn install_capture(out: &str, contents: &str) -> irlume_common::Result<()> {
    use std::io::Write;
    let io = |e: std::io::Error| irlume_common::Error::Io(e.to_string());
    let tmp = format!("{out}.tmp");
    let mut f = std::fs::File::create(&tmp).map_err(io)?;
    f.write_all(contents.as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)?;
    std::fs::rename(&tmp, out).map_err(io)?;
    Ok(())
}

fn write_pose_jsonl(
    out: &str,
    label: &str,
    samples: &[irlume_liveness::PoseSample],
) -> irlume_common::Result<()> {
    use std::fmt::Write;
    let header = serde_json::json!({ "posecap": true, "label": label, "frames": samples.len() });
    let mut contents = format!("{header}\n");
    for s in samples {
        let rec = RecordedPose {
            idx: s.idx,
            pitch_frac: s.pitch_frac,
            yaw_signed: s.yaw_signed,
            bri: s.bri,
        };
        let _ = writeln!(contents, "{}", serde_json::to_string(&rec).unwrap());
    }
    install_capture(out, &contents)
}

fn write_jsonl(out: &str, label: &str, samples: &[EarSample]) -> irlume_common::Result<()> {
    use std::fmt::Write;
    let header = serde_json::json!({
        "blinkcap": true,
        "label": label,
        "frames": samples.len(),
        "host": std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default().trim().to_string(),
    });
    let mut contents = format!("{header}\n");
    for s in samples {
        let rec = RecordedSample::from(s);
        let _ = writeln!(contents, "{}", serde_json::to_string(&rec).unwrap());
    }
    install_capture(out, &contents)
}

/// A loaded recording: its label and the samples the detectors consume.
struct Recording {
    file: String,
    label: String,
    samples: Vec<EarSample>,
}

const SELECTOR_MANIFEST_MAX_BYTES: u64 = 64 * 1024;
const SELECTOR_RECORDING_MAX_BYTES: u64 = 8 * 1024 * 1024;
const SELECTOR_MAX_PROFILES: usize = 16;
const SELECTOR_MAX_RECORDINGS_PER_PHASE: usize = 64;
const SELECTOR_MAX_ATTEMPTS: usize = 512;
const SELECTOR_MAX_LABEL_BYTES: usize = 256;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorManifest {
    profiles: Vec<SelectorProfileSpec>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorProfileSpec {
    name: String,
    open: Vec<String>,
    closed: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorRecordingHeader {
    blinkcap: bool,
    label: String,
    frames: usize,
    #[serde(default, rename = "host")]
    _host: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorRecordedSample {
    idx: usize,
    ear: serde_json::Value,
    bri: f32,
    cx: f32,
    cy: f32,
    fsize: f32,
    contrast: f32,
}

fn read_bounded(path: &Path, max: u64, kind: &str) -> Result<String, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{}: {kind} must be a regular file", path.display()));
    }
    let mut text = String::new();
    file.take(max + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if text.len() as u64 > max {
        return Err(format!(
            "{}: {kind} exceeds the {max}-byte limit",
            path.display()
        ));
    }
    Ok(text)
}

fn load_recording_strict(path: &Path) -> Result<Recording, String> {
    let text = read_bounded(path, SELECTOR_RECORDING_MAX_BYTES, "blink recording")?;
    let mut lines = text.lines();
    let header: SelectorRecordingHeader = serde_json::from_str(
        lines
            .next()
            .ok_or_else(|| format!("{}: empty recording", path.display()))?,
    )
    .map_err(|error| format!("{}: invalid blinkcap header: {error}", path.display()))?;
    if !header.blinkcap {
        return Err(format!("{}: not a blinkcap recording", path.display()));
    }
    if header.label.is_empty() || header.label.len() > SELECTOR_MAX_LABEL_BYTES {
        return Err(format!(
            "{}: label must be 1..={SELECTOR_MAX_LABEL_BYTES} bytes",
            path.display()
        ));
    }
    let mut samples = Vec::new();
    for (line_index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: SelectorRecordedSample = serde_json::from_str(line).map_err(|error| {
            format!(
                "{}:{}: invalid blink record: {error}",
                path.display(),
                line_index + 2
            )
        })?;
        let expected_index = samples.len();
        if record.idx != expected_index {
            return Err(format!(
                "{}:{}: expected frame index {expected_index}, got {}",
                path.display(),
                line_index + 2,
                record.idx
            ));
        }
        let ear = match &record.ear {
            serde_json::Value::Null => None,
            serde_json::Value::Number(number) => number.as_f64().map(|value| value as f32),
            _ => None,
        };
        if !record.ear.is_null() && ear.is_none() {
            return Err(format!(
                "{}:{}: EAR must be a number or null",
                path.display(),
                line_index + 2
            ));
        }
        let sample = EarSample {
            idx: record.idx,
            ear,
            bri: record.bri,
            cx: record.cx,
            cy: record.cy,
            fsize: record.fsize,
            contrast: record.contrast,
        };
        if [
            sample.bri,
            sample.cx,
            sample.cy,
            sample.fsize,
            sample.contrast,
        ]
        .into_iter()
        .any(|value| !value.is_finite())
        {
            return Err(format!(
                "{}:{}: sample fields must be finite",
                path.display(),
                line_index + 2
            ));
        }
        if sample.ear.is_some_and(|ear| !ear.is_finite() || ear < 0.0) {
            return Err(format!(
                "{}:{}: EAR must be finite and non-negative",
                path.display(),
                line_index + 2
            ));
        }
        samples.push(sample);
    }
    if samples.len() != header.frames {
        return Err(format!(
            "{}: header declares {} frames but {} were read",
            path.display(),
            header.frames,
            samples.len()
        ));
    }
    Ok(Recording {
        file: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        label: header.label,
        samples,
    })
}

fn median(values: &mut [f32]) -> f32 {
    values.sort_by(f32::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn recording_median(path: &Path) -> Result<f32, String> {
    let recording = load_recording_strict(path)?;
    let mut ears: Vec<f32> = recording
        .samples
        .iter()
        .filter_map(|sample| sample.ear)
        .collect();
    if ears.is_empty() {
        return Err(format!(
            "{}: recording contains no EAR samples",
            path.display()
        ));
    }
    Ok(median(&mut ears))
}

fn resolve_recording(manifest_path: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

fn phase_medians(manifest_path: &Path, files: &[String]) -> Result<Vec<f32>, String> {
    files
        .iter()
        .map(|file| recording_median(&resolve_recording(manifest_path, file)))
        .collect()
}

fn load_selector_profiles(
    manifest_path: &Path,
) -> Result<Vec<(String, ClosureProfileRange, ClosureCalibration)>, String> {
    let text = read_bounded(
        manifest_path,
        SELECTOR_MANIFEST_MAX_BYTES,
        "selector manifest",
    )?;
    let manifest: SelectorManifest = serde_json::from_str(&text).map_err(|error| {
        format!(
            "{}: invalid selector manifest: {error}",
            manifest_path.display()
        )
    })?;
    if !(1..=SELECTOR_MAX_PROFILES).contains(&manifest.profiles.len()) {
        return Err(format!(
            "selector manifest needs 1..={SELECTOR_MAX_PROFILES} profiles"
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for spec in &manifest.profiles {
        if spec.name.is_empty() || spec.name.len() > 64 || spec.name.trim() != spec.name {
            return Err("profile names must be 1..=64 characters without outer whitespace".into());
        }
        if !names.insert(spec.name.clone()) {
            return Err(format!("duplicate profile name '{}'", spec.name));
        }
        for (phase, files) in [("open", &spec.open), ("closed", &spec.closed)] {
            if !(2..=SELECTOR_MAX_RECORDINGS_PER_PHASE).contains(&files.len()) {
                return Err(format!(
                    "profile '{}' {phase} phase needs 2..={SELECTOR_MAX_RECORDINGS_PER_PHASE} recordings",
                    spec.name
                ));
            }
            if files.iter().any(|file| file.trim().is_empty()) {
                return Err(format!("profile '{}' has an empty {phase} path", spec.name));
            }
        }
    }

    for spec in &manifest.profiles {
        let mut paths = std::collections::BTreeSet::new();
        for file in spec.open.iter().chain(&spec.closed) {
            let path = resolve_recording(manifest_path, file);
            let canonical = std::fs::canonicalize(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if !paths.insert(canonical) {
                return Err(format!(
                    "profile '{}' requires distinct recording files",
                    spec.name
                ));
            }
        }
    }

    let mut profiles = Vec::with_capacity(manifest.profiles.len());
    for spec in manifest.profiles {
        let mut open = phase_medians(manifest_path, &spec.open)?;
        let mut closed = phase_medians(manifest_path, &spec.closed)?;
        open.sort_by(f32::total_cmp);
        closed.sort_by(f32::total_cmp);
        let range = ClosureProfileRange {
            open_min: open[0],
            open_max: open[open.len() - 1],
            closed_min: closed[0],
            closed_max: closed[closed.len() - 1],
        };
        let calibration = ClosureCalibration {
            ear_open: median(&mut open),
            ear_closed: median(&mut closed),
        };
        if !range.is_valid() || !calibration.is_usable() {
            return Err(format!(
                "profile '{}': open and closed evidence is not cleanly separated",
                spec.name
            ));
        }
        profiles.push((spec.name, range, calibration));
    }
    Ok(profiles)
}

fn selector_attempt_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = if path.is_dir() {
        std::fs::read_dir(path)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("{}: {error}", path.display()))?
            .into_iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "jsonl")
            })
            .collect()
    } else {
        vec![path.to_path_buf()]
    };
    files.sort();
    if files.is_empty() || files.len() > SELECTOR_MAX_ATTEMPTS {
        return Err(format!(
            "{}: expected 1..={SELECTOR_MAX_ATTEMPTS} JSONL attempts",
            path.display()
        ));
    }
    Ok(files)
}

fn split_selector_prefix(
    samples: &[EarSample],
    required: usize,
) -> Option<(Vec<f32>, &[EarSample])> {
    let mut prefix = Vec::with_capacity(required);
    for (index, sample) in samples.iter().enumerate() {
        if let Some(ear) = sample.ear {
            prefix.push(ear);
            if prefix.len() == required {
                return Some((prefix, &samples[index + 1..]));
            }
        }
    }
    None
}

fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn evaluate_selector(
    attempts: &Path,
    prefix_frames: usize,
    profiles: &[(String, ClosureProfileRange, ClosureCalibration)],
) -> Result<(), String> {
    let ranges: Vec<ClosureProfileRange> = profiles.iter().map(|(_, range, _)| *range).collect();
    let rows = selector_attempt_files(attempts)?
        .iter()
        .map(|path| -> Result<String, String> {
            let recording = load_recording_strict(path)?;
            let file = escaped(&recording.file);
            let label = escaped(&recording.label);
            let Some((prefix, remaining)) =
                split_selector_prefix(&recording.samples, prefix_frames)
            else {
                let observed = recording
                    .samples
                    .iter()
                    .filter(|sample| sample.ear.is_some())
                    .count();
                return Ok(format!(
                    "{file} label={label} prefix={observed} remaining=0 selector=out-of-range shadow-consent=not-run"
                ));
            };
            let row = match select_closure_profile(&prefix, &ranges) {
                ClosureProfileSelection::Unique(index) => {
                    let profile = escaped(&profiles[index].0);
                    let verdict = detect_deliberate_closure(remaining, &profiles[index].2);
                    format!(
                        "{file} label={label} prefix={} remaining={} selector=unique:{profile} shadow-consent={verdict:?}",
                        prefix.len(),
                        remaining.len()
                    )
                }
                ClosureProfileSelection::Ambiguous => format!(
                    "{file} label={label} prefix={} remaining={} selector=ambiguous shadow-consent=not-run",
                    prefix.len(),
                    remaining.len()
                ),
                ClosureProfileSelection::OutOfRange => format!(
                    "{file} label={label} prefix={} remaining={} selector=out-of-range shadow-consent=not-run",
                    prefix.len(),
                    remaining.len()
                ),
            };
            Ok(row)
        })
        .collect::<Result<Vec<_>, _>>()?;
    println!("== closure profile selector (SHADOW ONLY; never authorizes) ==");
    for row in rows {
        println!("  {row}");
    }
    Ok(())
}

fn selector(args: &[String]) -> ExitCode {
    let (Some(manifest), Some(attempts), Some(prefix)) = (
        flag(args, "--profiles"),
        flag(args, "--attempts"),
        flag(args, "--prefix-frames"),
    ) else {
        eprintln!(
            "usage: irlume blinkcap select --profiles P.json --attempts <file.jsonl | dir> --prefix-frames N"
        );
        return ExitCode::from(2);
    };
    let prefix = match prefix.parse::<usize>() {
        Ok(value) if (1..=120).contains(&value) => value,
        _ => {
            eprintln!("[blinkcap] --prefix-frames requires a number from 1 to 120");
            return ExitCode::from(2);
        }
    };
    match load_selector_profiles(Path::new(manifest))
        .and_then(|profiles| evaluate_selector(Path::new(attempts), prefix, &profiles))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[blinkcap] {error}");
            ExitCode::FAILURE
        }
    }
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

/// Run the head-nod detector over `path` (one pose recording, or every pose
/// recording under a directory) and tally acceptance per label.
///
/// `Ok(true)` means at least one pose recording replayed; `Ok(false)` means
/// none of the files were pose recordings, which is not an error because
/// blink recordings share the same directories and extension. A file whose
/// header DECLARES it a pose recording and whose body then cannot be read in
/// full is an `Err`, never a skip: a truncated capture replayed anyway reads
/// as `mean_step 0.0` and sits in the per-label minimum exactly like a still
/// head, and the cross-session corpus this output feeds (#101) cannot tell
/// "observed no motion" from "failed to read the observation".
fn replay_pose(path: &Path) -> Result<bool, String> {
    use irlume_liveness::{HeadGesture, PoseSample};
    use std::collections::BTreeMap;
    let files: Vec<std::path::PathBuf> = if path.is_dir() {
        let mut v: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        v.sort();
        v
    } else {
        vec![path.to_path_buf()]
    };
    let mut tally: BTreeMap<String, (usize, usize, f32, f32)> = BTreeMap::new();
    let mut any = false;
    for path in files {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut lines = text.lines();
        let Some(header) = lines
            .next()
            .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        else {
            continue; // no parseable header: not a recording of any kind
        };
        if header.get("posecap").and_then(|v| v.as_bool()) != Some(true) {
            continue; // not a pose recording
        }
        any = true;
        let label = header
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("unlabeled")
            .to_string();
        // Strict from here down. Every posecap header ever written carries
        // "frames" (the field predates this check), so a mismatch or an
        // unparseable record is a damaged file, and damage is reported, not
        // measured.
        let expected = header
            .get("frames")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| {
                format!(
                    "{}: posecap header has no valid 'frames' count",
                    path.display()
                )
            })?;
        let mut samples: Vec<PoseSample> = Vec::new();
        for (i, line) in lines.enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let r: RecordedPose = serde_json::from_str(line)
                .map_err(|e| format!("{}:{}: invalid pose record: {e}", path.display(), i + 2))?;
            samples.push(PoseSample {
                idx: r.idx,
                pitch_frac: r.pitch_frac,
                yaw_signed: r.yaw_signed,
                bri: r.bri,
            });
        }
        if samples.len() != expected {
            return Err(format!(
                "{}: header declares {expected} frames but {} were read; refusing to \
                 measure a partial capture",
                path.display(),
                samples.len()
            ));
        }
        let e = tally
            .entry(label)
            .or_insert((0usize, 0usize, f32::INFINITY, f32::NEG_INFINITY));
        e.1 += 1;
        // Verdict and evidence from the same call, so the replayed corpus
        // accumulates the #101 shadow metric alongside the accept rate: the
        // per-label mean_step spread is exactly the cross-session data that
        // issue is blocked on, and old recordings are sessions too.
        let (verdict, ev) = irlume_liveness::detect_nod_with_evidence(&samples);
        if verdict == HeadGesture::Nod {
            e.0 += 1;
        }
        e.2 = e.2.min(ev.mean_step);
        e.3 = e.3.max(ev.mean_step);
    }
    if any {
        println!("== head-nod acceptance (detect_nod) by label ==");
        for (label, (acc, total, lo, hi)) in &tally {
            println!("  {label:<16} {acc}/{total}   mean_step {lo:.4}..{hi:.4} (#101, not gating)");
        }
        println!("\n  A nod should be accepted; still / look-around / reclined-still should not.");
    }
    Ok(any)
}

fn replay(args: &[String]) -> ExitCode {
    // args = ["blinkcap", "replay", <target>].
    let Some(target) = args.get(2) else {
        eprintln!("usage: irlume blinkcap replay <file.jsonl | dir>");
        return ExitCode::from(2);
    };
    let path = Path::new(target);
    // Pose (head-nod) recordings replay through their own detector; a single
    // .jsonl argument can be either kind, so the pose pass sees files too. A
    // damaged pose recording fails the whole replay rather than shrinking the
    // corpus silently.
    let pose_found = match replay_pose(path) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("[blinkcap] {e}");
            return ExitCode::FAILURE;
        }
    };
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
        // A pose-only corpus is a successful replay: its summary printed
        // above, and there was never a blink recording to miss.
        if pose_found {
            return ExitCode::SUCCESS;
        }
        eprintln!("[blinkcap] no blinkcap or posecap recordings found at {target}");
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
