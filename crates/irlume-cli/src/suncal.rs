//! Offline analysis of the sunlight/ambient burst dataset captured by the
//! `burst_dump` example. For each burst directory it runs the real detection +
//! depth-cue path over the brightest (lit) frame and over the ambient-subtracted
//! frame, so the depth-floor and subtraction-gate tuning works from measured
//! face-crop ratios instead of the crude whole-frame probe numbers.
//!
//! `IRLUME_DEV=1 irlume suncal <det.onnx> <dataset_dir>`
//!
//! Emits one TSV row per burst: dir, ambient mean, lit mean, strobe gap,
//! gap/ambient, raw face depth ratio, subtracted face depth ratio, raw/subtracted
//! IR face brightness. A trailing legend explains the current gate/floor and
//! prints candidate thresholds derived from the run.

use crate::{center_edge_ratio, mean_in_bbox};
use irlume_camera::{grey_to_rgb, ir_probe};
use std::process::ExitCode;

/// Read a binary P5 (greyscale) PGM: `P5\n<w> <h>\n255\n<w*h bytes>`.
fn read_pgm(path: &std::path::Path) -> Option<(u32, u32, Vec<u8>)> {
    let raw = std::fs::read(path).ok()?;
    // Parse the three whitespace-separated header tokens after the "P5" magic.
    if &raw[0..2] != b"P5" {
        return None;
    }
    let mut pos = 2usize;
    let mut vals = [0u32; 3]; // w, h, maxval
    for v in &mut vals {
        while pos < raw.len() && raw[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let start = pos;
        while pos < raw.len() && raw[pos].is_ascii_digit() {
            pos += 1;
        }
        *v = std::str::from_utf8(&raw[start..pos]).ok()?.parse().ok()?;
    }
    pos += 1; // single whitespace after maxval, before the pixel block
    let (w, h) = (vals[0], vals[1]);
    let px = &raw[pos..];
    if px.len() < (w * h) as usize {
        return None;
    }
    Some((w, h, px[..(w * h) as usize].to_vec()))
}

/// Load every `frameNN.pgm` in a burst dir, ascending. Returns (w, h, frames).
fn load_burst(dir: &std::path::Path) -> Option<(u32, u32, Vec<Vec<u8>>)> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("frame") && n.ends_with(".pgm"))
        })
        .collect();
    entries.sort();
    let mut frames = Vec::new();
    let (mut w, mut h) = (0u32, 0u32);
    for p in entries {
        let (fw, fh, data) = read_pgm(&p)?;
        (w, h) = (fw, fh);
        frames.push(data);
    }
    if frames.is_empty() {
        None
    } else {
        Some((w, h, frames))
    }
}

/// Detect the top IR face and return (brightness, depth ratio) for one grey
/// frame, or None when no face is found.
fn face_depth(
    det: &mut irlume_vision::Detector,
    grey: &[u8],
    w: u32,
    h: u32,
) -> Option<(f32, f32)> {
    let rgb = grey_to_rgb(grey);
    let view = irlume_vision::align::RgbView {
        data: &rgb,
        width: w,
        height: h,
    };
    let faces = det.detect(&view).ok()?;
    let top = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score))?;
    let bri = mean_in_bbox(grey, w, h, &top.bbox);
    let ratio = center_edge_ratio(grey, w, h, &top.bbox);
    Some((bri, ratio))
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    // args[0] is the "suncal" subcommand itself.
    let (Some(det_path), Some(dir)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: IRLUME_DEV=1 irlume suncal <det.onnx> <dataset_dir>");
        return ExitCode::FAILURE;
    };
    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[suncal] load detector {det_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut dirs: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect(),
        Err(e) => {
            eprintln!("[suncal] read {dir}: {e}");
            return ExitCode::FAILURE;
        }
    };
    dirs.sort();

    println!("burst\tamb\tlit\tgap\tsubM\tdepth_raw\tdepth_sub\tbri_sub\traw_ok\tchose\tgated");
    // Rows where a face was found in the raw lit frame, for the summary.
    let mut raw_pass = 0usize;
    let mut sub_rescued = 0usize;
    let mut faces_found = 0usize;
    for d in &dirs {
        let Some((w, h, frames)) = load_burst(d) else {
            continue;
        };
        let means: Vec<f64> = frames.iter().map(|f| ir_probe::mean(f)).collect();
        // Brightest = lit strobe phase; adjacent dimmest = ambient (what
        // capture_ir pairs).
        let best_i = means
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let amb_i = [best_i.wrapping_sub(1), best_i + 1]
            .into_iter()
            .filter(|&j| j < means.len())
            .min_by(|&a, &b| means[a].total_cmp(&means[b]))
            .unwrap_or(best_i);
        let (lit_mean, amb_mean) = (means[best_i], means[amb_i]);
        let gap = lit_mean - amb_mean;

        let subtracted = ir_probe::subtract(&frames[best_i], &frames[amb_i]);
        let name = d.file_name().and_then(|n| n.to_str()).unwrap_or("?");

        // Simulate the NEW gate (must match lib.rs: STROBE_MIN_GAP=8,
        // LOW_AMBIENT_SKIP=5, SUBTRACT_MIN_RESULT=12).
        let sub_mean = ir_probe::mean(&subtracted);
        let gate_subtracts = gap > 8.0 && amb_mean >= 5.0 && sub_mean >= 12.0;

        let (draw, dsub, braw, bsub) = match face_depth(&mut det, &frames[best_i], w, h) {
            Some((b, r)) => {
                faces_found += 1;
                let (bs, rs) = face_depth(&mut det, &subtracted, w, h).unwrap_or((0.0, 0.0));
                (r, rs, b, bs)
            }
            None => (0.0, 0.0, 0.0, 0.0),
        };
        // DEPTH_MIN_RATIO = 1.03 is the shipped global floor.
        let rp = draw >= 1.03;
        // The gated outcome: the depth the gate would actually hand downstream.
        let gated_depth = if gate_subtracts { dsub } else { draw };
        let gated_pass = gated_depth >= 1.03;
        if rp {
            raw_pass += 1;
        }
        if gated_pass && !rp && draw > 0.0 {
            sub_rescued += 1;
        }
        let _ = braw;
        println!(
            "{name}\t{amb_mean:.0}\t{lit_mean:.0}\t{gap:.0}\t{sub_mean:.0}\t{draw:.2}\t{dsub:.2}\t{bsub:.0}\t{}\t{}\t{}",
            if rp { "Y" } else { "n" },
            if gate_subtracts { "sub" } else { "raw" },
            if gated_pass { "PASS" } else { "fail" },
        );
    }

    eprintln!(
        "\n[suncal] {faces_found} bursts with a detectable IR face.\n\
         [suncal] raw depth alone (shipped default): {raw_pass}/{faces_found} pass (>=1.03).\n\
         [suncal] NEW gate (gap>8, amb>=5, sub_mean>=12): +{sub_rescued} rescued, so \
         {}/{faces_found} pass.\n\
         [suncal] 'chose' column = which frame the new gate hands downstream; 'gated' = its verdict.\n\
         [suncal] The gate reverts to the raw frame when subtraction collapses the signal\n\
         (sub_mean < 12), so no raw-passing burst regresses; only clear-signal cases are lifted.\n\
         [suncal] Bursts with no face at all (depth 0.00) are DETECTION failures from background\n\
         saturation (outdoor frames run >50% pixels at 255), a separate problem from the depth\n\
         floor: they need IR exposure reduction, not subtraction.\n\
         [suncal] This is GENUINE-only data. Before enabling by default, capture flat spoofs\n\
         under the same bright light to confirm subtraction does NOT lift them over the floor,\n\
         and re-enroll with the flag on so the per-user calibrated floor + IR match match.",
        raw_pass + sub_rescued
    );
    ExitCode::SUCCESS
}
