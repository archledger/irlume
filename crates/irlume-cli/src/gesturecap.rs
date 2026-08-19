// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume gesturecap` (developer tool): capture and replay labeled head-pose
//! sequences against the shipped head-gesture detector.
//!
//! Capture still requires both detector and recognizer paths because the
//! established [`irlume_auth::Engine`] constructor loads them together. The
//! recognizer bytes are not used to derive pose; [`irlume_auth::Engine::capture_pose_samples`]
//! uses the detector's five landmarks.
//!
//! ```text
//! IRLUME_DEV=1 irlume gesturecap capture --label nod \
//!   --det <yunet.onnx> --model <recognizer.onnx> --out nod.jsonl [--ir DEV] [--n 75]
//! IRLUME_DEV=1 irlume gesturecap replay <file.jsonl | dir>
//! ```

use crate::{devices_from_flags, flag};
use irlume_liveness::PoseSample;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const RECORDING_MAX_BYTES: u64 = 8 * 1024 * 1024;
const RECORDING_MAX_FRAMES: usize = 65_536;
const MAX_RECORDINGS: usize = 512;
const MAX_LABEL_BYTES: usize = 256;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedPose {
    idx: usize,
    pitch_frac: serde_json::Value,
    yaw_signed: serde_json::Value,
    bri: f32,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordingHeader {
    posecap: bool,
    label: String,
    frames: usize,
}

struct Recording {
    file: String,
    label: String,
    samples: Vec<PoseSample>,
}

pub fn run(args: &[String]) -> ExitCode {
    match args.get(1).map(String::as_str) {
        Some("capture") => capture(args),
        Some("replay") => replay(args),
        _ => {
            eprintln!(
                "usage: irlume gesturecap <capture|replay>\n  \
                 capture --label L --det <y.onnx> --model <g.onnx> --out F.jsonl [--rgb DEV] [--ir DEV] [--n 75]\n  \
                 replay <file.jsonl | dir>"
            );
            ExitCode::from(2)
        }
    }
}

fn capture(args: &[String]) -> ExitCode {
    let (Some(label), Some(detector), Some(recognizer), Some(output)) = (
        flag(args, "--label"),
        flag(args, "--det"),
        flag(args, "--model"),
        flag(args, "--out"),
    ) else {
        eprintln!(
            "usage: irlume gesturecap capture --label L --det <y.onnx> --model <g.onnx> \
             --out F.jsonl [--rgb DEV] [--ir DEV] [--n 75]"
        );
        return ExitCode::from(2);
    };
    if label.is_empty() || label.len() > MAX_LABEL_BYTES {
        eprintln!("[gesturecap] label must be 1..={MAX_LABEL_BYTES} bytes");
        return ExitCode::from(2);
    }
    let count = match flag(args, "--n") {
        None => 75,
        Some(raw) => match raw.parse::<usize>() {
            Ok(value) if (1..=RECORDING_MAX_FRAMES).contains(&value) => value,
            _ => {
                eprintln!("[gesturecap] --n must be a number from 1 to {RECORDING_MAX_FRAMES}");
                return ExitCode::from(2);
            }
        },
    };

    let result = || -> irlume_common::Result<()> {
        let mut engine = irlume_auth::Engine::load(detector, recognizer)?;
        if let Some((rgb, ir)) = devices_from_flags(
            flag(args, "--rgb"),
            flag(args, "--ir"),
            // deliberate camera probe: capture is about to open this pair.
            irlume_camera::select_pair,
        ) {
            engine = engine.with_devices(&rgb, &ir);
        }
        println!("[gesturecap] label='{label}' n={count} -> {output}");
        countdown(count);
        let samples = engine.capture_pose_samples(count)?;
        write_pose_jsonl(output, label, &samples)?;
        println!(
            "[gesturecap] captured {} frames, {} with a face.",
            samples.len(),
            samples
                .iter()
                .filter(|sample| sample.pitch_frac.is_some())
                .count()
        );
        report_recordings(&[Recording {
            file: Path::new(output)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            label: label.to_string(),
            samples,
        }]);
        println!("[gesturecap] saved.");
        Ok(())
    }();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[gesturecap] {error}");
            ExitCode::FAILURE
        }
    }
}

fn countdown(count: usize) {
    use std::io::Write as _;

    print!("[gesturecap] get ready");
    let _ = std::io::stdout().flush();
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(700));
        print!(" .");
        let _ = std::io::stdout().flush();
    }
    println!(" GO  (capturing ~{}s)", count / 15);
}

fn write_pose_jsonl(
    output: &str,
    label: &str,
    samples: &[PoseSample],
) -> irlume_common::Result<()> {
    let header = serde_json::json!({
        "posecap": true,
        "label": label,
        "frames": samples.len(),
    });
    let mut contents = format!("{header}\n");
    for sample in samples {
        let record = serde_json::json!({
            "idx": sample.idx,
            "pitch_frac": sample.pitch_frac,
            "yaw_signed": sample.yaw_signed,
            "bri": sample.bri,
        });
        let line = serde_json::to_string(&record)
            .map_err(|error| irlume_common::Error::Protocol(error.to_string()))?;
        contents.push_str(&line);
        contents.push('\n');
    }
    install_capture(output, contents.as_bytes())
}

fn install_capture(output: &str, contents: &[u8]) -> irlume_common::Result<()> {
    use std::io::Write as _;

    let io = |error: std::io::Error| irlume_common::Error::Io(error.to_string());
    let temporary = format!("{output}.tmp");
    let mut file = std::fs::File::create(&temporary).map_err(io)?;
    file.write_all(contents).map_err(io)?;
    file.sync_all().map_err(io)?;
    std::fs::rename(&temporary, output).map_err(io)?;
    Ok(())
}

fn replay(args: &[String]) -> ExitCode {
    let Some(target) = args.get(2) else {
        eprintln!("usage: irlume gesturecap replay <file.jsonl | dir>");
        return ExitCode::from(2);
    };
    match load_recordings(Path::new(target)) {
        Ok(recordings) => {
            report_recordings(&recordings);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[gesturecap] {error}");
            ExitCode::FAILURE
        }
    }
}

fn recording_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_file() {
        Ok(vec![path.to_path_buf()])
    } else if metadata.file_type().is_dir() {
        let entries = std::fs::read_dir(path)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| format!("{}: {error}", path.display()))
            });
        collect_recording_candidates(path, entries)
    } else {
        Err(format!(
            "{}: recording must be a regular file",
            path.display()
        ))
    }
}

fn collect_recording_candidates(
    directory: &Path,
    entries: impl Iterator<Item = Result<PathBuf, String>>,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry
            .extension()
            .is_none_or(|extension| extension != "jsonl")
        {
            continue;
        }
        if files.len() == MAX_RECORDINGS {
            return Err(format!(
                "{}: expected 1..={MAX_RECORDINGS} JSONL recordings",
                directory.display()
            ));
        }
        files.push(entry);
    }
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "{}: expected 1..={MAX_RECORDINGS} JSONL recordings",
            directory.display()
        ));
    }
    Ok(files)
}

fn load_recordings(path: &Path) -> Result<Vec<Recording>, String> {
    recording_files(path)?
        .iter()
        .map(|file| load_recording(file))
        .collect()
}

fn read_bounded(path: &Path) -> Result<String, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{}: recording must be a regular file",
            path.display()
        ));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?
        .file_type()
        .is_file()
    {
        return Err(format!(
            "{}: recording must be a regular file",
            path.display()
        ));
    }
    let mut text = String::new();
    file.take(RECORDING_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if text.len() as u64 > RECORDING_MAX_BYTES {
        return Err(format!(
            "{}: recording exceeds the {RECORDING_MAX_BYTES}-byte limit",
            path.display()
        ));
    }
    Ok(text)
}

fn load_recording(path: &Path) -> Result<Recording, String> {
    let text = read_bounded(path)?;
    let mut lines = text.lines();
    let header: RecordingHeader = serde_json::from_str(
        lines
            .next()
            .ok_or_else(|| format!("{}: empty recording", path.display()))?,
    )
    .map_err(|error| format!("{}: invalid posecap header: {error}", path.display()))?;
    if !header.posecap {
        return Err(format!("{}: not a posecap recording", path.display()));
    }
    if header.label.is_empty() || header.label.len() > MAX_LABEL_BYTES {
        return Err(format!(
            "{}: label must be 1..={MAX_LABEL_BYTES} bytes",
            path.display()
        ));
    }
    if header.frames > RECORDING_MAX_FRAMES {
        return Err(format!(
            "{}: frames must be 0..={RECORDING_MAX_FRAMES}",
            path.display()
        ));
    }

    let mut samples = Vec::new();
    for (line_index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if samples.len() == header.frames {
            return Err(format!(
                "{}:{}: contains more records than declared {} frames",
                path.display(),
                line_index + 2,
                header.frames
            ));
        }
        let record: RecordedPose = serde_json::from_str(line).map_err(|error| {
            format!(
                "{}:{}: invalid pose record: {error}",
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
        let pitch_frac = parse_nullable_float(&record.pitch_frac, path, line_index, "pitch_frac")?;
        let yaw_signed = parse_nullable_float(&record.yaw_signed, path, line_index, "yaw_signed")?;
        if record.bri.is_finite() {
            samples.push(PoseSample {
                idx: record.idx,
                pitch_frac,
                yaw_signed,
                bri: record.bri,
            });
        } else {
            return Err(format!(
                "{}:{}: pose fields must be finite or null",
                path.display(),
                line_index + 2
            ));
        }
    }
    if samples.len() != header.frames {
        return Err(format!(
            "{}: header declares {} frames but {} were read; refusing to measure a partial capture",
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

fn parse_nullable_float(
    value: &serde_json::Value,
    path: &Path,
    line_index: usize,
    field: &str,
) -> Result<Option<f32>, String> {
    let parsed = match value {
        serde_json::Value::Null => None,
        serde_json::Value::Number(number) => number.as_f64().map(|number| number as f32),
        _ => None,
    };
    if value.is_null() || parsed.is_some_and(f32::is_finite) {
        Ok(parsed)
    } else {
        Err(format!(
            "{}:{}: {field} must be a finite number or null",
            path.display(),
            line_index + 2
        ))
    }
}

fn report_recordings(recordings: &[Recording]) {
    println!(
        "file,label,frames,pitch_range,yaw_range,pitch_crossings,yaw_crossings,mean_step,verdict"
    );
    for recording in recordings {
        let (verdict, evidence) =
            irlume_liveness::detect_head_gesture_with_evidence(&recording.samples);
        let yaw: Vec<f32> = recording
            .samples
            .iter()
            .filter_map(|sample| sample.yaw_signed)
            .collect();
        let yaw_crossings = irlume_liveness::signal_crossings(
            &yaw,
            evidence.yaw_range,
            irlume_liveness::NOD_CROSSING_AMP_FRAC,
        );
        println!(
            "{},{},{},{:.3},{:.2},{},{},{:.4},{verdict:?}",
            csv_cell(&recording.file),
            csv_cell(&recording.label),
            evidence.frames,
            evidence.pitch_range,
            evidence.yaw_range,
            evidence.crossings,
            yaw_crossings,
            evidence.mean_step,
        );
    }
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn gesturecap_directory_limit_stops_before_reading_later_entries() {
        let yielded = Cell::new(0usize);
        let entries = (0..=MAX_RECORDINGS + 1).map(|index| {
            yielded.set(yielded.get() + 1);
            if index > MAX_RECORDINGS {
                Err("walked past the recording limit".to_string())
            } else {
                Ok(PathBuf::from(format!("{index:03}.jsonl")))
            }
        });

        let error = collect_recording_candidates(Path::new("corpus"), entries).unwrap_err();

        assert!(
            error.contains("expected 1..=512 JSONL recordings"),
            "{error}"
        );
        assert_eq!(yielded.get(), MAX_RECORDINGS + 1);
    }
}
