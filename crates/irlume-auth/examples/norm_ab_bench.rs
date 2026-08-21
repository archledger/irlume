// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A/B bench for the embedder input normalizer divisor: production uses
//! `(px - 127.5) / 128.0`; the InsightFace reference for graphs WITHOUT
//! baked Sub/Mul nodes (which glintr100.onnx is — first nodes are raw
//! Conv/PRelu) computes `(px - 127.5) / 127.5`. This measures whether the
//! difference moves genuine-pair cosines materially against the production
//! match threshold, so the constant is changed (with migration impact
//! assessed) or the divergence is documented as measured-and-accepted.
//!
//! Walks a directory of per-scene frame directories (the suncal layout:
//! `<root>/<scene>/*.pgm|*.ppm`), detects + aligns + embeds every frame
//! under BOTH divisors, and reports within-scene (genuine) and cross-scene
//! (same person, different conditions) cosine distributions.
//!
//! Usage: cargo run --release -p irlume-auth --example norm_ab_bench -- \
//!   <det.onnx> <embed.onnx> <frames-root> [max_per_scene]

use irlume_vision::align::RgbView;
use irlume_vision::{align, Detector, Embedder};
use std::path::{Path, PathBuf};

const EMBED_DIM: usize = 512;

/// One frame embedded under both divisors.
type DualEmbedding = ([f32; EMBED_DIM], [f32; EMBED_DIM]);

fn preprocess_div(chip_rgb: &[u8], div: f32) -> Vec<f32> {
    let n = (align::OUT_SIZE * align::OUT_SIZE) as usize;
    let mut t = vec![0.0f32; 3 * n];
    for plane in 0..3 {
        let base = plane * n;
        for px in 0..n {
            t[base + px] = (chip_rgb[px * 3 + plane] as f32 - 127.5) / div;
        }
    }
    t
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>()
}

fn stats(v: &[f32]) -> (f32, f32, f32) {
    if v.is_empty() {
        return (f32::NAN, f32::NAN, f32::NAN);
    }
    let mut s = v.to_vec();
    s.sort_by(f32::total_cmp);
    let mean = v.iter().sum::<f32>() / v.len() as f32;
    let var = v.iter().map(|x| (x - mean) * (x - mean)).sum::<f32>() / v.len() as f32;
    (mean, var.sqrt(), s[s.len() / 2])
}

fn load_frame(path: &Path) -> Option<(Vec<u8>, u32, u32)> {
    let data = std::fs::read(path).ok()?;
    match path.extension().and_then(|e| e.to_str()) {
        Some("pgm") => load_pnm(&data, "P5").map(|(v, w, h)| (grey_to_rgb(v), w, h)),
        Some("ppm") => load_pnm(&data, "P6"),
        _ => None,
    }
}

/// Minimal PNM (P5/P6) reader: header tokens with `#` comments, maxval < 256.
fn load_pnm(data: &[u8], magic: &str) -> Option<(Vec<u8>, u32, u32)> {
    let mut pos = 0usize;
    let mut token = |data: &[u8]| -> Option<String> {
        loop {
            while pos < data.len() && data[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos < data.len() && data[pos] == b'#' {
                while pos < data.len() && data[pos] != b'\n' {
                    pos += 1;
                }
                continue;
            }
            let start = pos;
            while pos < data.len() && !data[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos > start {
                break Some(String::from_utf8_lossy(&data[start..pos]).into_owned());
            }
            return None;
        }
    };
    if token(data)? != magic {
        return None;
    }
    let w: u32 = token(data)?.parse().ok()?;
    let h: u32 = token(data)?.parse().ok()?;
    let _maxval: u32 = token(data)?.parse().ok()?;
    pos += 1; // single whitespace byte after maxval
    let bpp = if magic == "P6" { 3 } else { 1 };
    let need = (w as usize) * (h as usize) * bpp;
    if data.len() < pos + need {
        return None;
    }
    Some((data[pos..pos + need].to_vec(), w, h))
}

fn grey_to_rgb(g: Vec<u8>) -> Vec<u8> {
    let mut rgb = Vec::with_capacity(g.len() * 3);
    for p in g {
        rgb.extend_from_slice(&[p, p, p]);
    }
    rgb
}

fn main() {
    let mut args = std::env::args().skip(1);
    let det_path = args.next().expect("det.onnx path");
    let emb_path = args.next().expect("embedder onnx path");
    let root = PathBuf::from(args.next().expect("frames root"));
    let max_per_scene: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(40);

    let mut det = Detector::load_from_file(&det_path).expect("detector");
    let mut emb = Embedder::load_from_file(&emb_path).expect("embedder");

    // scene -> [(embedding /128, embedding /127.5)]
    let mut scenes: Vec<(String, Vec<DualEmbedding>)> = Vec::new();

    let mut scene_dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("read root")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    scene_dirs.sort();

    for scene_dir in &scene_dirs {
        let scene = scene_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let mut frames: Vec<PathBuf> = match std::fs::read_dir(scene_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|e| e.to_str()),
                        Some("pgm") | Some("ppm")
                    )
                })
                .collect(),
            Err(_) => continue,
        };
        if frames.is_empty() {
            continue;
        }
        frames.sort();
        frames.truncate(max_per_scene);
        let mut embs = Vec::new();
        for f in &frames {
            let Some((rgb, w, h)) = load_frame(f) else {
                continue;
            };
            let view = RgbView {
                data: &rgb,
                width: w,
                height: h,
            };
            let dets = match det.detect(&view) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let Some(top) = dets.iter().max_by(|a, b| {
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }) else {
                continue;
            };
            let Ok(chip) = align::align_to_arcface(&view, &top.landmarks) else {
                continue;
            };
            // Match the production IR path: plain embed, no TTA.
            let t128 = align::preprocess_arcface(&chip);
            let t1275 = preprocess_div(&chip, 127.5);
            let e128 = emb.embed_preprocessed(&t128).expect("embed /128");
            let e1275 = emb.embed_preprocessed(&t1275).expect("embed /127.5");
            embs.push((e128, e1275));
        }
        if embs.len() >= 2 {
            println!(
                "[scene] {scene}: {} frames embedded (of {})",
                embs.len(),
                frames.len()
            );
            scenes.push((scene, embs));
        }
    }

    let mut gen128 = Vec::new();
    let mut gen1275 = Vec::new();
    let mut delta = Vec::new();
    for (_s, embs) in &scenes {
        for i in 0..embs.len() {
            for j in (i + 1)..embs.len() {
                let c128 = cosine(&embs[i].0, &embs[j].0);
                let c1275 = cosine(&embs[i].1, &embs[j].1);
                gen128.push(c128);
                gen1275.push(c1275);
                delta.push(c1275 - c128);
            }
        }
    }
    // Cross-scene pairs (same person, different capture conditions).
    let mut cross128 = Vec::new();
    let mut cross1275 = Vec::new();
    for a in 0..scenes.len() {
        for b in (a + 1)..scenes.len() {
            for i in 0..scenes[a].1.len().min(5) {
                for j in 0..scenes[b].1.len().min(5) {
                    cross128.push(cosine(&scenes[a].1[i].0, &scenes[b].1[j].0));
                    cross1275.push(cosine(&scenes[a].1[i].1, &scenes[b].1[j].1));
                }
            }
        }
    }

    let (m128, s128, med128) = stats(&gen128);
    let (m1275, s1275, med1275) = stats(&gen1275);
    let (md, sd, _medd) = stats(&delta);
    println!("\n== within-scene (genuine) pairs: {}", gen128.len());
    println!("  /128.0 : mean {m128:.4}  sd {s128:.4}  median {med128:.4}");
    println!("  /127.5 : mean {m1275:.4}  sd {s1275:.4}  median {med1275:.4}");
    println!("  delta(/127.5 - /128.0): mean {md:.5}  sd {sd:.5}");
    let (cm128, cs128, _) = stats(&cross128);
    let (cm1275, cs1275, _) = stats(&cross1275);
    println!("\n== cross-scene pairs: {}", cross128.len());
    println!("  /128.0 : mean {cm128:.4}  sd {cs128:.4}");
    println!("  /127.5 : mean {cm1275:.4}  sd {cs1275:.4}");
    println!(
        "\nproduction IR threshold reference: ~0.602; genuine-mean shift: {:+.5}",
        md
    );
}
