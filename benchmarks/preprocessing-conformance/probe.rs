// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Generated includes contain only the exact pure functions under investigation.
include!("pure.rs");

use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 && args.len() != 8 {
        return Err("usage: probe <yuyv|nv12|pad> width height [x1 y1 x2 y2]".into());
    }
    let width: u32 = args[2].parse()?;
    let height: u32 = args[3].parse()?;
    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return Err("probe dimensions must be in 1..=4096".into());
    }
    let pixels = width as usize * height as usize;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((pixels * 3 + 1) as u64)
        .read_to_end(&mut bytes)?;
    let output = match args[1].as_str() {
        "yuyv" | "nv12" => {
            let expected = if args[1] == "yuyv" {
                pixels * 2
            } else {
                pixels * 3 / 2
            };
            if args.len() != 4 || width % 2 != 0 || height % 2 != 0 || bytes.len() != expected {
                return Err("probe expects tightly packed even-dimension YUV".into());
            }
            if args[1] == "yuyv" {
                yuyv_to_rgb(&bytes, width, height)
            } else {
                nv12_to_rgb(&bytes, width, height)
            }
        }
        "pad" => {
            if args.len() != 8 || bytes.len() != pixels * 3 {
                return Err("probe expects a packed RGB frame and four bbox coordinates".into());
            }
            let mut bbox = [0.0_f32; 4];
            for (value, text) in bbox.iter_mut().zip(&args[4..]) {
                *value = text.parse()?;
            }
            if !bbox.iter().all(|v| v.is_finite()) || bbox[2] <= bbox[0] || bbox[3] <= bbox[1] {
                return Err("probe expects a finite positive-area bbox".into());
            }
            let view = align::RgbView {
                data: &bytes,
                width,
                height,
            };
            pad_vit_input(&view, &bbox, 224)
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect()
        }
        _ => return Err("unknown probe mode".into()),
    };
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}
