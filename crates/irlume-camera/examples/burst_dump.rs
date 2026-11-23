// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Dump a raw IR strobe burst to disk as PGM frames plus a means index, so
//! ambient-subtraction and center/edge-cue tuning can be done offline against real
//! captured conditions (e.g. direct sunlight) long after the light is gone.
//!
//! Usage: cargo run --release -p irlume-camera --example burst_dump -- <out_dir> [ir_dev] [frames]
//!
//! A delivered-rate refusal exits 3 and reports the rejected rate window on
//! stderr. It leaves the burst failed; the nightly does not retry it.

use irlume_camera::ir_probe;
use irlume_common::{CameraStreamRateEvidence, Error};
use std::io::{self, Write};
use std::process::ExitCode;

const RATE_REFUSED_EXIT: u8 = 3;

fn main() -> ExitCode {
    let mut a = std::env::args().skip(1);
    let out = a
        .next()
        .expect("usage: burst_dump <out_dir> [ir_dev] [frames]");
    let dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(36);

    std::fs::create_dir_all(&out).expect("create out dir");
    let frames = match ir_probe::capture_raw_burst_timed(&dev, n) {
        Ok(frames) => frames,
        Err(Error::DeliveredRate(evidence)) => {
            // A broken stderr still leaves the refused burst failed.
            let _ = write_rate_refusal(io::stderr().lock(), &evidence);
            return ExitCode::from(RATE_REFUSED_EXIT);
        }
        Err(error) => panic!("capture: {error:?}"),
    };
    // means.txt columns: index, frame mean, ms since first dequeue. The third
    // column is capture-time-only data (real delivered fps, strobe cadence);
    // everything else about a frame can be recomputed offline from the PGM.
    let mut index = std::fs::File::create(format!("{out}/means.txt")).expect("index");
    for (i, (f, ms)) in frames.iter().enumerate() {
        let mean = ir_probe::mean(&f.data);
        writeln!(index, "{i:02} {mean:.1} {ms:.1}").unwrap();
        let mut pgm = std::fs::File::create(format!("{out}/frame{i:02}.pgm")).expect("frame file");
        write!(pgm, "P5\n{} {}\n255\n", f.width, f.height).unwrap();
        pgm.write_all(&f.data).unwrap();
    }
    let span_ms = frames.last().map(|(_, ms)| *ms).unwrap_or(0.0);
    let fps = if span_ms > 0.0 {
        (frames.len().saturating_sub(1)) as f64 / (span_ms / 1000.0)
    } else {
        0.0
    };
    println!(
        "{}: wrote {} frames ({}x{}) in {:.0} ms ({:.1} fps delivered)",
        out,
        frames.len(),
        frames[0].0.width,
        frames[0].0.height,
        span_ms,
        fps
    );
    ExitCode::SUCCESS
}

fn write_rate_refusal(mut out: impl Write, evidence: &CameraStreamRateEvidence) -> io::Result<()> {
    writeln!(
        out,
        "irlume: burst rate refused: role={} requested={}/{} accepted={}/{} \
         floor={}/{} tolerance_percent={} window_count={} window_span_us={} \
         delivered={}/{} meets_floor={} sequence_gap={} cumulative_drops={} \
         clock={} source={}",
        evidence.role,
        evidence.requested_num,
        evidence.requested_den,
        evidence.accepted_num,
        evidence.accepted_den,
        evidence.floor_num,
        evidence.floor_den,
        evidence.tolerance_percent,
        evidence.window_count,
        evidence.window_span_us,
        evidence.delivered_num,
        evidence.delivered_den,
        evidence.meets_floor,
        evidence.sequence_gap,
        evidence.cumulative_drops,
        evidence.clock,
        evidence.source,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_refusal_reports_the_judged_window_without_a_capture_timestamp() {
        let evidence = CameraStreamRateEvidence {
            role: "ir".into(),
            requested_num: 1,
            requested_den: 30,
            accepted_num: 1,
            accepted_den: 30,
            floor_num: 15,
            floor_den: 1,
            tolerance_percent: 97,
            window_count: 30,
            window_span_us: 2_088_113,
            delivered_num: 30_000_000,
            delivered_den: 2_088_113,
            meets_floor: false,
            sequence_gap: 0,
            cumulative_drops: 0,
            clock: "monotonic".into(),
            source: "end_of_frame".into(),
            latest_timestamp_us: 987_654_321,
            stream_epoch: 42,
        };
        let mut output = Vec::new();

        write_rate_refusal(&mut output, &evidence).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "irlume: burst rate refused: role=ir requested=1/30 accepted=1/30 \
             floor=15/1 tolerance_percent=97 window_count=30 window_span_us=2088113 \
             delivered=30000000/2088113 meets_floor=false sequence_gap=0 \
             cumulative_drops=0 clock=monotonic source=end_of_frame\n"
        );
    }
}
