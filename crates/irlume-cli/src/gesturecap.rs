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
//! IRLUME_DEV=1 irlume gesturecap identity [--expected-camera-identity-digest SHA256]
//! IRLUME_DEV=1 irlume gesturecap attempt --expected-camera-identity-digest SHA256 \
//!   --expected-gesture LABEL --det <yunet.onnx> --model <recognizer.onnx> [--n 75]
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
        Some("identity") => identity(args),
        Some("attempt") => attempt(args),
        _ => {
            eprintln!(
                "usage: irlume gesturecap <capture|replay|identity|attempt>\n  \
                 capture --label L --det <y.onnx> --model <g.onnx> --out F.jsonl [--rgb DEV] [--ir DEV] [--n 75]\n  \
                 replay <file.jsonl | dir>\n  \
                 identity [--expected-camera-identity-digest SHA256]\n  \
                 attempt --expected-camera-identity-digest SHA256 --expected-gesture LABEL --det <y.onnx> --model <g.onnx> [--n 75]"
            );
            ExitCode::from(2)
        }
    }
}

fn camera_node_sysfs_path(device: &str) -> Result<String, String> {
    let node = device
        .strip_prefix("/dev/")
        .filter(|node| !node.is_empty() && !node.contains('/'))
        .ok_or_else(|| format!("invalid configured camera node: {device}"))?;
    std::fs::canonicalize(format!("/sys/class/video4linux/{node}/device"))
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| format!("cannot resolve configured camera {device}: {error}"))
}

fn camera_pair_identity_digest(
    rgb_node: &str,
    rgb_identity: &str,
    rgb_sysfs: &str,
    ir_node: &str,
    ir_identity: &str,
    ir_sysfs: &str,
) -> String {
    let material = format!(
        "irlume-camera-pair-v1\0{rgb_node}\0{rgb_identity}\0{rgb_sysfs}\0{ir_node}\0{ir_identity}\0{ir_sysfs}\0"
    );
    irlume_common::thirdparty::sha256_hex(material.as_bytes())
}

fn selected_camera_pair_identity() -> Result<(String, String, String), String> {
    let (rgb, ir) = irlume_camera::configured_pair_no_probe()
        .or_else(irlume_camera::select_pair)
        .ok_or_else(|| {
            "no RGB+IR camera pair is available for hardware qualification".to_string()
        })?;
    camera_pair_identity(&rgb, &ir).map(|digest| (rgb, ir, digest))
}

fn camera_pair_identity(rgb: &str, ir: &str) -> Result<String, String> {
    let rgb_identity = irlume_camera::device_identity(rgb)
        .ok_or_else(|| format!("cannot resolve configured RGB camera identity for {rgb}"))?;
    let ir_identity = irlume_camera::device_identity(ir)
        .ok_or_else(|| format!("cannot resolve configured IR camera identity for {ir}"))?;
    let rgb_sysfs = camera_node_sysfs_path(rgb)?;
    let ir_sysfs = camera_node_sysfs_path(ir)?;
    Ok(camera_pair_identity_digest(
        rgb,
        &rgb_identity,
        &rgb_sysfs,
        ir,
        &ir_identity,
        &ir_sysfs,
    ))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identity(args: &[String]) -> ExitCode {
    let result = || -> Result<String, String> {
        let (_, _, digest) = selected_camera_pair_identity()?;
        if let Some(expected) = flag(args, "--expected-camera-identity-digest") {
            if !valid_digest(expected) {
                return Err("expected camera identity digest must be lowercase SHA-256".into());
            }
            if expected != digest {
                return Err(
                    "configured camera identity digest does not match the frozen expectation"
                        .into(),
                );
            }
        }
        Ok(digest)
    }();
    match result {
        Ok(digest) => {
            println!("{}", serde_json::json!({"camera_identity_digest": digest}));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[gesturecap] {error}");
            ExitCode::FAILURE
        }
    }
}

fn classify_production_gesture_window(
    samples: &[PoseSample],
) -> (
    irlume_liveness::HeadGesture,
    irlume_liveness::NodEvidence,
    usize,
) {
    const CHECK_EVERY: usize = 6;
    for end in (CHECK_EVERY..=samples.len()).step_by(CHECK_EVERY) {
        let (verdict, evidence) =
            irlume_liveness::detect_head_gesture_with_evidence(&samples[..end]);
        if matches!(
            verdict,
            irlume_liveness::HeadGesture::Nod | irlume_liveness::HeadGesture::Shake
        ) {
            return (verdict, evidence, end);
        }
    }
    let (verdict, evidence) = irlume_liveness::detect_head_gesture_with_evidence(samples);
    (verdict, evidence, samples.len())
}

fn attempt(args: &[String]) -> ExitCode {
    let (Some(expected_digest), Some(expected_gesture), Some(detector), Some(recognizer)) = (
        flag(args, "--expected-camera-identity-digest"),
        flag(args, "--expected-gesture"),
        flag(args, "--det"),
        flag(args, "--model"),
    ) else {
        eprintln!(
            "usage: irlume gesturecap attempt --expected-camera-identity-digest SHA256 \
             --expected-gesture LABEL --det <y.onnx> --model <g.onnx> [--n 75]"
        );
        return ExitCode::from(2);
    };
    if !valid_digest(expected_digest) {
        eprintln!("[gesturecap] expected camera identity digest must be lowercase SHA-256");
        return ExitCode::from(2);
    }
    if !matches!(
        expected_gesture,
        "nod" | "shake" | "still" | "look-around" | "look-down-and-hold"
    ) {
        eprintln!("[gesturecap] unsupported hardware-matrix gesture label");
        return ExitCode::from(2);
    }
    let count = match flag(args, "--n").unwrap_or("75").parse::<usize>() {
        Ok(value) if (1..=300).contains(&value) => value,
        _ => {
            eprintln!("[gesturecap] --n must be a number from 1 to 300");
            return ExitCode::from(2);
        }
    };

    let result = || -> irlume_common::Result<serde_json::Value> {
        let (rgb, ir, before) =
            selected_camera_pair_identity().map_err(irlume_common::Error::Hardware)?;
        if before != expected_digest {
            return Err(irlume_common::Error::Hardware(
                "configured camera identity digest does not match the frozen expectation".into(),
            ));
        }
        let mut engine_args = args.to_vec();
        engine_args.extend(["--rgb".into(), rgb.clone(), "--ir".into(), ir.clone()]);
        let mut engine = crate::engine(detector, recognizer, &engine_args)?;
        let samples = engine.capture_pose_samples(count)?;
        let after = camera_pair_identity(&rgb, &ir).map_err(irlume_common::Error::Hardware)?;
        if after != before {
            return Err(irlume_common::Error::Hardware(
                "configured camera identity changed during the attempt".into(),
            ));
        }
        let (verdict, evidence, window_frames) = classify_production_gesture_window(&samples);
        let yaw: Vec<f32> = samples[..window_frames]
            .iter()
            .filter_map(|sample| sample.yaw_signed)
            .collect();
        let yaw_crossings = irlume_liveness::signal_crossings(
            &yaw,
            evidence.yaw_range,
            irlume_liveness::NOD_CROSSING_AMP_FRAC,
        );
        let typed_outcome = match verdict {
            irlume_liveness::HeadGesture::Nod => "approved",
            irlume_liveness::HeadGesture::Shake => "declined",
            irlume_liveness::HeadGesture::None | irlume_liveness::HeadGesture::NoFace => {
                "no-gesture"
            }
        };
        Ok(serde_json::json!({
            "typed_outcome": typed_outcome,
            "detector_evidence": {
                "frames": window_frames,
                "face_frames": evidence.frames,
                "pitch_range": evidence.pitch_range,
                "yaw_range": evidence.yaw_range,
                "pitch_crossings": evidence.crossings,
                "yaw_crossings": yaw_crossings,
                "mean_step": evidence.mean_step,
            }
        }))
    }();
    match result {
        Ok(document) => {
            println!("{document}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[gesturecap] {error}");
            ExitCode::FAILURE
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
    fn camera_pair_digest_has_a_frozen_role_ordered_encoding() {
        let digest = camera_pair_identity_digest(
            "/dev/video0",
            "abcd:1234:serial",
            "/sys/devices/rgb",
            "/dev/video2",
            "abcd:1234:serial",
            "/sys/devices/ir",
        );

        assert_eq!(
            digest,
            "5561b6e7da27ba01fbb50e92e1fe7a39f80f28490ac6dc0b213be641932bdab6"
        );
        assert_ne!(
            digest,
            camera_pair_identity_digest(
                "/dev/video2",
                "abcd:1234:serial",
                "/sys/devices/ir",
                "/dev/video0",
                "abcd:1234:serial",
                "/sys/devices/rgb",
            )
        );
    }

    #[test]
    fn hardware_attempt_keeps_a_terminal_rolling_nod_despite_later_yaw_noise() {
        let mut samples: Vec<PoseSample> = [
            0.50, 0.50, 0.50, 0.50, 0.60, 0.40, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50,
        ]
        .into_iter()
        .enumerate()
        .map(|(idx, pitch_frac)| PoseSample {
            idx,
            pitch_frac: Some(pitch_frac),
            yaw_signed: Some(0.0),
            bri: 80.0,
        })
        .collect();
        samples.extend((12..18).map(|idx| PoseSample {
            idx,
            pitch_frac: Some(0.50),
            yaw_signed: Some(if idx == 17 { 3.0 } else { 0.0 }),
            bri: 80.0,
        }));
        assert_eq!(
            irlume_liveness::detect_head_gesture(&samples),
            irlume_liveness::HeadGesture::None,
            "the fixture must reproduce the full-take regression"
        );

        let (verdict, _, frames) = classify_production_gesture_window(&samples);

        assert_eq!(verdict, irlume_liveness::HeadGesture::Nod);
        assert_eq!(frames, 12);
    }

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
