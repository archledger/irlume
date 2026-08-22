// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Profile a camera node's STREAMON startup transient, the thing the rate
//! gate's RATE_STARTUP_FLUSH (30 discarded dequeues) exists to skip.
//!
//! Streams N raw validated dequeues with NO rate gating and prints, per
//! attempt: index, validity, driver sequence, driver timestamp, and dequeue
//! offset. Then simulates the production fill for a sweep of flush sizes:
//! "discard K dequeues, then measure a 30-delta window of successful
//! dequeue timestamps — does it meet the spectrum's floor?" The smallest K
//! that passes on real hardware is the evidence a shorter flush needs.
//!
//! Usage: cargo run --release -p irlume-camera --example startup_transient \
//!   -- <rgb|ir> [device] [frames]

use irlume_camera::startup_probe;
use irlume_camera::Spectrum;

fn main() {
    let mut a = std::env::args().skip(1);
    let spectrum = match a.next().as_deref() {
        Some("rgb") => Spectrum::Rgb,
        Some("ir") => Spectrum::Ir,
        other => panic!("usage: startup_transient <rgb|ir> [device] [frames], got {other:?}"),
    };
    let device = a.next().unwrap_or_else(|| match spectrum {
        Spectrum::Rgb => "/dev/video0".into(),
        Spectrum::Ir => "/dev/video2".into(),
    });
    let frames: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(96);

    let run = startup_probe::by_spectrum(spectrum, &device, frames)
        .unwrap_or_else(|e| panic!("{device}: {e}"));

    println!("# spectrum={spectrum:?} device={device} frames={frames}");
    println!("# index valid seq ts_us dequeue_us delta_us");
    let mut last_ts: Option<i64> = None;
    for f in &run {
        let delta_us = match (last_ts, f.ts()) {
            (Some(l), Some(t)) => format!("{}", t - l),
            _ => "-".to_string(),
        };
        if let Some(t) = f.ts() {
            last_ts = Some(t);
        }
        println!(
            "{} {} {} {} {} {}",
            f.index,
            f.valid,
            f.sequence_raw
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            f.timestamp_micros
                .map(|t| t.to_string())
                .unwrap_or_else(|| "-".into()),
            f.dequeue_us,
            delta_us,
        );
    }

    // Where does the sequence settle? The last gap between CONSECUTIVE valid
    // driver sequence numbers is the transient's end by the continuity
    // definition the qualification uses.
    let mut last_seq: Option<u32> = None;
    let mut last_gap_index = None;
    for f in &run {
        if let (true, Some(seq)) = (f.valid, f.sequence_raw) {
            if let Some(expected) = last_seq.map(|s| s.wrapping_add(1)) {
                if seq != expected {
                    last_gap_index = Some(f.index);
                }
            }
            last_seq = Some(seq);
        }
    }
    println!(
        "# last sequence gap at index {:?}",
        last_gap_index.unwrap_or(0)
    );

    // Simulate the production fill for flush sizes 0..=30: skip K dequeue
    // ATTEMPTS (valid or not, exactly as next_discarded counts attempts),
    // then seed on the next successful timestamp and collect 30 positive
    // deltas; report span, delivered fps, and floor verdict.
    let (floor_num, floor_den): (u32, u32) = match spectrum {
        Spectrum::Ir => (15, 1),
        Spectrum::Rgb => (15, 2),
    };
    println!("# flush attempts -> window span_us delivered fps meets_floor(98%)");
    for flush in 0..=30_usize {
        let mut deltas: Vec<i64> = Vec::with_capacity(30);
        let mut seed: Option<i64> = None;
        for f in run.iter().skip(flush) {
            let Some(ts) = f.ts() else { continue };
            match seed {
                None => seed = Some(ts),
                Some(last) => {
                    if ts > last {
                        deltas.push(ts - last);
                        seed = Some(ts);
                        if deltas.len() == 30 {
                            break;
                        }
                    } else {
                        // A non-increasing timestamp fails the window closed
                        // in production; record it as a broken fill.
                        seed = Some(ts);
                        deltas.push(0);
                        if deltas.len() == 30 {
                            break;
                        }
                    }
                }
            }
        }
        if deltas.len() < 30 {
            println!(
                "{flush} -> insufficient frames ({} deltas in {} attempts)",
                deltas.len(),
                run.len() - flush
            );
            continue;
        }
        let span: i64 = deltas.iter().sum();
        let fps = 30.0 * 1_000_000.0 / span.max(1) as f64;
        // Exact integer floor check mirroring RateWindow::meets_floor:
        // count * 1e6 * floor_den * 100 >= span * floor_num * 98.
        let lhs = 30_u128 * 1_000_000 * u128::from(floor_den) * 100;
        let rhs = span as u128 * u128::from(floor_num) * 98;
        println!("{flush} -> {span} {fps:.3} {}", lhs >= rhs);
    }
}
