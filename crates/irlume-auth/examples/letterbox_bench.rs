// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Grayscale expansion and optional full production detector comparison.
//! No copied preprocessing loops. See docs/research/benchmark-harness.md.

#[path = "benchmark_support/identity.rs"]
mod identity;
#[path = "benchmark_support/sampling.rs"]
mod sampling;

use irlume_vision::align::{FrameView, Grey8View, RgbView};
use std::hint::black_box;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::Path;

const HELP: &str = "Usage: letterbox_bench [width height [det.onnx [samples [warmup]]]]\nDefaults: 640 400, 200 samples, 5 warmup; dimensions and samples must be positive.\nWithout det.onnx, measures only grey_to_rgb expansion.\nWith det.onnx, compares full production detection: expansion + RGB vs native Grey8View.\nSynthetic costs only; no camera or end-to-end login measurement.";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if args.len() == 1 || args.len() > 5 {
        return Err(HELP.into());
    }
    let w = args
        .first()
        .map_or(Ok(640), |s| s.parse::<NonZeroU32>().map(u32::from))?;
    let h = args
        .get(1)
        .map_or(Ok(400), |s| s.parse::<NonZeroU32>().map(u32::from))?;
    let samples = args
        .get(3)
        .map_or(Ok(200), |s| s.parse::<NonZeroUsize>().map(usize::from))?;
    let warmup = args.get(4).map_or(Ok(5), |s| s.parse::<usize>())?;
    let pixels = (w as usize)
        .checked_mul(h as usize)
        .ok_or("frame dimensions overflow")?;
    let mut grey = Vec::new();
    grey.try_reserve_exact(pixels)?;
    grey.extend((0..pixels).map(|i| ((i % 251) * 37 % 251) as u8));
    let native = FrameView::Grey(Grey8View {
        data: &grey,
        width: w,
        height: h,
    });
    identity::header("synthetic expansion / independent full detector calls; not login latency");
    println!("input=deterministic-grey-pattern-v1 dimensions={w}x{h}");
    let name = "grey_to_rgb expansion only";
    sampling::measure(
        name,
        warmup,
        samples,
        || Ok::<_, std::convert::Infallible>(irlume_camera::grey_to_rgb(black_box(&grey))),
        |_, _| {},
    )?
    .print(name, warmup, samples);

    if let Some(path) = args.get(2) {
        let mut detector =
            identity::construct("detector", || irlume_vision::Detector::load_from_file(path))?;
        identity::file("detector", Path::new(path))?;
        identity::runtimes()?;
        let name = "full detect expansion + RGB";
        sampling::measure(
            name,
            warmup,
            samples,
            || {
                let expanded = irlume_camera::grey_to_rgb(black_box(&grey));
                detector.detect(&RgbView {
                    data: &expanded,
                    width: w,
                    height: h,
                })
            },
            |_, _| {},
        )?
        .print(name, warmup, samples);
        let name = "full detect native Grey8View";
        sampling::measure(
            name,
            warmup,
            samples,
            || detector.detect_any(black_box(&native)),
            |_, _| {},
        )?
        .print(name, warmup, samples);
    } else {
        println!("detector=not-requested; no letterbox or inference timing collected");
    }
    Ok(())
}
