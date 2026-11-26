// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Dump a raw IR strobe burst to disk as PGM frames plus a means index, so
//! ambient-subtraction and center/edge-cue tuning can be done offline against real
//! captured conditions (e.g. direct sunlight) long after the light is gone.
//!
//! Usage: cargo run --release -p irlume-camera --example burst_dump -- <out_dir> [ir_dev] [frames]
//!
//! The stream starts the way the product's fixed IR session starts. When the
//! first rate window of the session misses its floor on the measured camera,
//! the capture makes the product's one startup recheck and this program
//! reports both windows on stderr. A delivered-rate refusal exits 3 and
//! reports the rejected rate window. It leaves the burst failed; the nightly
//! does not retry it.

use irlume_camera::frame_provenance::DeliveredRateEvidence;
use irlume_camera::ir_probe::{self, RefusedStartupWindow};
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
    let mut rechecked = false;
    let frames = match ir_probe::capture_raw_burst_with_startup(&dev, n, |window| {
        rechecked = true;
        // Reported as soon as it is known: the window after it may miss too.
        let _ = write_window(io::stderr().lock(), "first window refused", &window.into());
    }) {
        Ok(frames) => frames,
        Err(Error::DeliveredRate(evidence)) => {
            // A broken stderr still leaves the refused burst failed.
            let _ = write_rate_refusal(io::stderr().lock(), &evidence);
            return ExitCode::from(RATE_REFUSED_EXIT);
        }
        Err(error) => panic!("capture: {error:?}"),
    };
    if rechecked {
        if let Some((frame, _)) = frames.first() {
            // The first delivered frame carries the window that passed.
            let _ = write_window(
                io::stderr().lock(),
                "rate accepted after one startup recheck",
                &frame.provenance().rate_evidence().into(),
            );
        }
    }
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

/// The numbers of one judged rate window, as the two startup lines report
/// them. No timestamps.
#[derive(Clone, Copy)]
struct WindowLine {
    requested: (u32, u32),
    accepted: (u32, u32),
    floor: (u32, u32),
    tolerance_percent: u32,
    window_count: u32,
    window_span_us: u64,
    delivered: (u64, u64),
    max_inter_frame_gap_us: u64,
    meets_floor: bool,
}

impl From<RefusedStartupWindow> for WindowLine {
    fn from(window: RefusedStartupWindow) -> Self {
        Self {
            requested: window.requested,
            accepted: window.accepted,
            floor: window.floor,
            tolerance_percent: window.tolerance_percent,
            window_count: window.window_count,
            window_span_us: window.window_span_us,
            delivered: window.delivered,
            max_inter_frame_gap_us: window.max_inter_frame_gap_us,
            meets_floor: false,
        }
    }
}

impl From<DeliveredRateEvidence> for WindowLine {
    fn from(evidence: DeliveredRateEvidence) -> Self {
        Self {
            requested: evidence.requested(),
            accepted: evidence.accepted(),
            floor: evidence.floor(),
            tolerance_percent: evidence.tolerance_percent(),
            window_count: evidence.window_count(),
            window_span_us: evidence.window_span_us(),
            delivered: evidence.delivered(),
            max_inter_frame_gap_us: evidence.max_inter_frame_gap_us(),
            meets_floor: evidence.meets_floor(),
        }
    }
}

fn write_window(mut out: impl Write, label: &str, window: &WindowLine) -> io::Result<()> {
    writeln!(
        out,
        "irlume: burst {label}: requested={}/{} accepted={}/{} floor={}/{} \
         tolerance_percent={} window_count={} window_span_us={} delivered={}/{} \
         max_inter_frame_gap_us={} meets_floor={}",
        window.requested.0,
        window.requested.1,
        window.accepted.0,
        window.accepted.1,
        window.floor.0,
        window.floor.1,
        window.tolerance_percent,
        window.window_count,
        window.window_span_us,
        window.delivered.0,
        window.delivered.1,
        window.max_inter_frame_gap_us,
        window.meets_floor,
    )
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

    #[test]
    fn the_refused_first_window_is_reported_as_numbers_only() {
        let window = RefusedStartupWindow {
            requested: (1, 30),
            accepted: (1, 30),
            window_count: 30,
            window_span_us: 2_104_076,
            delivered: (7_500_000, 526_019),
            max_inter_frame_gap_us: 95_945,
            floor: (15, 1),
            tolerance_percent: 97,
        };
        let mut output = Vec::new();

        write_window(&mut output, "first window refused", &window.into()).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "irlume: burst first window refused: requested=1/30 accepted=1/30 \
             floor=15/1 tolerance_percent=97 window_count=30 window_span_us=2104076 \
             delivered=7500000/526019 max_inter_frame_gap_us=95945 meets_floor=false\n"
        );
    }

    #[test]
    fn both_startup_lines_report_the_same_fields() {
        let first = WindowLine {
            requested: (1, 30),
            accepted: (1, 30),
            floor: (15, 1),
            tolerance_percent: 97,
            window_count: 30,
            window_span_us: 2_104_076,
            delivered: (7_500_000, 526_019),
            max_inter_frame_gap_us: 95_945,
            meets_floor: false,
        };
        let accepted = WindowLine {
            window_span_us: 2_028_086,
            delivered: (15_000_000, 1_014_043),
            max_inter_frame_gap_us: 71_998,
            meets_floor: true,
            ..first
        };
        let mut output = Vec::new();

        write_window(&mut output, "first window refused", &first).unwrap();
        write_window(
            &mut output,
            "rate accepted after one startup recheck",
            &accepted,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "irlume: burst first window refused: requested=1/30 accepted=1/30 \
             floor=15/1 tolerance_percent=97 window_count=30 window_span_us=2104076 \
             delivered=7500000/526019 max_inter_frame_gap_us=95945 meets_floor=false\n\
             irlume: burst rate accepted after one startup recheck: requested=1/30 \
             accepted=1/30 floor=15/1 tolerance_percent=97 window_count=30 \
             window_span_us=2028086 delivered=15000000/1014043 \
             max_inter_frame_gap_us=71998 meets_floor=true\n"
        );
    }
}
