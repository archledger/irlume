// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Black-box tests of the IMAGE-DATASET benchmark/dev tools in `irlume`:
//! `irbench`, `eval`, `normprobe`, `enrolldev`. These tools take directories
//! (or a single file) of images rather than a live camera, so their offline
//! paths run in CI without hardware.
//!
//! Two tiers of tests live here:
//!
//!  * USAGE / EARLY-EXIT tests run everywhere. They exercise the arg-parse
//!    error arms and the "no images" / "load-failed-before-model" arms that
//!    return before any ONNX model is loaded, so they need neither the model
//!    files nor onnxruntime. They still set `IRLUME_DEV=1` (these are gated
//!    developer commands) but touch no camera, network, TPM, or root.
//!
//!  * `bench_*` tests are `#[ignore]`d and drive the real embedding pipeline
//!    against SYNTHETIC solid-colour images in which detection finds no face.
//!    They need `models/{face_detection_yunet_2023mar.onnx,glintr100.onnx}`
//!    plus a `libonnxruntime.so`. Each early-returns (skips) if those are
//!    absent, so `cargo test --ignored` is safe on a bare machine. Run them
//!    with `cargo test -p irlume-cli --test cli_bench -- --ignored`.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_irlume");

/// Per-test temp tree, deleted on drop.
struct Tmp {
    root: PathBuf,
}

impl Tmp {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("irlume-cli-bench-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Tmp { root }
    }

    fn dir(&self, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Write a minimal valid uncompressed 24-bit BMP of a single solid colour.
/// Solid colour guarantees the face detector finds nothing, which is exactly
/// the "no detectable face" path these tests cover. Hand-rolled so the test
/// needs no image-encoding dependency.
fn write_bmp(path: &Path, w: u32, h: u32, rgb: [u8; 3]) {
    let row = (w * 3) as usize;
    let pad = (4 - row % 4) % 4;
    let pixdata = (row + pad) * h as usize;
    let filesize = 54 + pixdata;
    let mut buf: Vec<u8> = Vec::with_capacity(filesize);
    // BITMAPFILEHEADER (14 bytes).
    buf.extend_from_slice(b"BM");
    buf.extend_from_slice(&(filesize as u32).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    buf.extend_from_slice(&54u32.to_le_bytes()); // pixel-data offset
                                                 // BITMAPINFOHEADER (40 bytes).
    buf.extend_from_slice(&40u32.to_le_bytes());
    buf.extend_from_slice(&(w as i32).to_le_bytes());
    buf.extend_from_slice(&(h as i32).to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // planes
    buf.extend_from_slice(&24u16.to_le_bytes()); // bpp
    buf.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB (no compression)
    buf.extend_from_slice(&(pixdata as u32).to_le_bytes());
    buf.extend_from_slice(&2835i32.to_le_bytes()); // x px/m
    buf.extend_from_slice(&2835i32.to_le_bytes()); // y px/m
    buf.extend_from_slice(&0u32.to_le_bytes()); // palette colours
    buf.extend_from_slice(&0u32.to_le_bytes()); // important colours
    let [r, g, b] = rgb;
    for _y in 0..h {
        for _x in 0..w {
            buf.push(b);
            buf.push(g);
            buf.push(r);
        }
        buf.resize(buf.len() + pad, 0);
    }
    std::fs::write(path, &buf).unwrap();
}

/// A dataset with two "persons" (prefix before '-') and a face-free colour per
/// file: person1-a, person1-b, person2-a, person2-b. Enough structure for the
/// prefix and LFW keying to build multiple identities to pair.
fn synth_dataset(dir: &Path) {
    write_bmp(&dir.join("person1-a.bmp"), 128, 128, [40, 40, 40]);
    write_bmp(&dir.join("person1-b.bmp"), 128, 128, [80, 80, 80]);
    write_bmp(&dir.join("person2-a.bmp"), 128, 128, [120, 120, 120]);
    write_bmp(&dir.join("person2-b.bmp"), 128, 128, [160, 160, 160]);
}

/// Locate the model files (`../../models` from the crate manifest) and an
/// onnxruntime dylib. Returns `None` (test should skip) if anything is missing.
fn models_and_ort() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let models = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models");
    let det = models.join("face_detection_yunet_2023mar.onnx");
    let emb = models.join("glintr100.onnx");
    if !det.exists() || !emb.exists() {
        return None;
    }
    let ort = if let Some(p) = std::env::var_os("ORT_DYLIB_PATH") {
        let p = PathBuf::from(p);
        p.exists().then_some(p)?
    } else {
        [
            "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
            "/usr/lib64/libonnxruntime.so",
            "/usr/lib/libonnxruntime.so",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())?
    };
    Some((det, emb, ort))
}

/// Base command: dev tools enabled, isolated state dir, no daemon/camera reach.
fn cmd(tmp: &Tmp) -> Command {
    let mut c = Command::new(BIN);
    c.env("IRLUME_DEV", "1")
        .env("IRLUME_STATE_DIR", tmp.dir("state"))
        .env("IRLUME_CONFIG_DIR", tmp.dir("cfg"))
        .env("IRLUME_SOCKET", tmp.path("no-daemon.sock"))
        .env_remove("IRLUME_MODEL")
        .env_remove("IRLUME_DET_MODEL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// Spawn, draining stdout/stderr on threads, and enforce a 90s watchdog. A
/// timeout kills the child and fails the test naming the command.
fn run(mut cmd: Command, label: &str) -> (i32, String, String) {
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {label}: {e}"));
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = so.read_to_string(&mut s);
        s
    });
    let t_err = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = se.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(-1),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("timeout (>90s) waiting for `{label}`");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("wait {label}: {e}"),
        }
    };
    let out = t_out.join().unwrap_or_default();
    let err = t_err.join().unwrap_or_default();
    (code, out, err)
}

// ------------------------------------------------------------- usage / gate
// These run everywhere: no models, no onnxruntime, no hardware.

#[test]
fn dev_gate_blocks_irbench_without_irlume_dev() {
    let tmp = Tmp::new("gate");
    let mut c = cmd(&tmp);
    c.env_remove("IRLUME_DEV").arg("irbench");
    let (code, _out, err) = run(c, "irbench(no-dev)");
    assert_eq!(code, 2, "dev gate should exit 2; stderr={err}");
    assert!(
        err.contains("developer/benchmark tool") && err.contains("Set IRLUME_DEV=1"),
        "stderr={err}"
    );
}

#[test]
fn irbench_missing_dir_prints_usage() {
    let tmp = Tmp::new("irb-usage");
    let mut c = cmd(&tmp);
    c.args(["irbench", "--det", "d.onnx", "--model", "m.onnx"]);
    let (code, _out, err) = run(c, "irbench(no --dir)");
    assert_eq!(code, 2, "stderr={err}");
    assert!(err.contains("usage: irlume irbench --dir"), "stderr={err}");
}

#[test]
fn irbench_empty_dir_reports_no_images_before_loading_models() {
    // The "no jpg/png/bmp images" arm returns before any model is loaded, so
    // this exercises the real walk path with no ONNX dependency.
    let tmp = Tmp::new("irb-empty");
    let empty = tmp.dir("empty");
    let mut c = cmd(&tmp);
    c.args([
        "irbench",
        "--dir",
        empty.to_str().unwrap(),
        "--det",
        "d.onnx",
        "--model",
        "m.onnx",
    ]);
    let (code, _out, err) = run(c, "irbench(empty dir)");
    assert_eq!(code, 1, "stderr={err}");
    assert!(err.contains("no jpg/png/bmp images under"), "stderr={err}");
}

#[test]
fn irbench_impostor_only_needs_at_least_two_images() {
    // farbench's <2-images guard also returns before model load.
    let tmp = Tmp::new("far-one");
    let dir = tmp.dir("one");
    write_bmp(&dir.join("solo-a.bmp"), 64, 64, [10, 10, 10]);
    let mut c = cmd(&tmp);
    c.args([
        "irbench",
        "--impostor-only",
        "--dir",
        dir.to_str().unwrap(),
        "--det",
        "d.onnx",
        "--model",
        "m.onnx",
    ]);
    let (code, _out, err) = run(c, "irbench(impostor 1 img)");
    assert_eq!(code, 1, "stderr={err}");
    assert!(err.contains("need >=2 images under"), "stderr={err}");
}

#[test]
fn eval_missing_args_prints_usage() {
    let tmp = Tmp::new("eval-usage");
    let mut c = cmd(&tmp);
    c.args(["eval", "--det", "d.onnx", "--model", "m.onnx"]); // no --image
    let (code, _out, err) = run(c, "eval(no --image)");
    assert_eq!(code, 2, "stderr={err}");
    assert!(err.contains("usage: irlume eval --image"), "stderr={err}");
}

#[test]
fn eval_missing_image_file_fails_before_model_load() {
    // image::open runs before the detector/embedder are loaded.
    let tmp = Tmp::new("eval-missing");
    let missing = tmp.path("does-not-exist.png");
    let mut c = cmd(&tmp);
    c.args([
        "eval",
        "--image",
        missing.to_str().unwrap(),
        "--det",
        "d.onnx",
        "--model",
        "m.onnx",
    ]);
    let (code, _out, err) = run(c, "eval(missing image)");
    assert_eq!(code, 1, "stderr={err}");
    assert!(err.contains("image load failed"), "stderr={err}");
}

#[test]
fn normprobe_missing_dir_prints_usage() {
    let tmp = Tmp::new("norm-usage");
    let mut c = cmd(&tmp);
    c.arg("normprobe"); // no --dir
    let (code, _out, err) = run(c, "normprobe(no --dir)");
    assert_eq!(code, 2, "stderr={err}");
    assert!(
        err.contains("usage: irlume normprobe --dir"),
        "stderr={err}"
    );
}

#[test]
fn enrolldev_missing_model_flags_prints_usage() {
    let tmp = Tmp::new("enrolldev-usage");
    let mut c = cmd(&tmp);
    c.args(["enrolldev", "--user", "alice"]); // no --det/--model
    let (code, _out, err) = run(c, "enrolldev(no --det/--model)");
    assert_eq!(code, 2, "stderr={err}");
    assert!(
        err.contains("usage: irlume enrolldev --user"),
        "stderr={err}"
    );
}

// -------------------------------------------------- real pipeline (gated)
// Need models + onnxruntime; skip cleanly when absent.

#[test]
#[ignore = "needs ONNX models + onnxruntime; CI provides them"]
fn bench_irbench_synthetic_no_face_yields_not_enough_data() {
    let Some((det, emb, ort)) = models_and_ort() else {
        eprintln!("SKIP bench_irbench: models or onnxruntime not found");
        return;
    };
    let tmp = Tmp::new("bench-irb");
    let dir = tmp.dir("imgs");
    synth_dataset(&dir);
    let mut c = cmd(&tmp);
    c.env("ORT_DYLIB_PATH", &ort).args([
        "irbench",
        "--dir",
        dir.to_str().unwrap(),
        "--det",
        det.to_str().unwrap(),
        "--model",
        emb.to_str().unwrap(),
    ]);
    let (code, out, err) = run(c, "irbench(synthetic)");
    // Two persons walked, zero faces embedded, so no genuine/impostor pairs.
    assert!(out.contains("[irbench]"), "out={out} err={err}");
    assert!(out.contains("embedded 0 faces"), "out={out}");
    assert_eq!(code, 1, "out={out} err={err}");
    assert!(err.contains("not enough data"), "err={err}");
}

#[test]
#[ignore = "needs ONNX models + onnxruntime; CI provides them"]
fn bench_irbench_lfw_keying_synthetic() {
    let Some((det, emb, ort)) = models_and_ort() else {
        eprintln!("SKIP bench_irbench_lfw: models or onnxruntime not found");
        return;
    };
    let tmp = Tmp::new("bench-lfw");
    let dir = tmp.dir("imgs");
    // LFW convention: <person>_<index>. Keying strips the trailing _<digits>.
    write_bmp(&dir.join("Ada_Lovelace_0001.bmp"), 128, 128, [30, 30, 30]);
    write_bmp(&dir.join("Ada_Lovelace_0002.bmp"), 128, 128, [70, 70, 70]);
    write_bmp(&dir.join("Alan_Turing_0001.bmp"), 128, 128, [110, 110, 110]);
    let mut c = cmd(&tmp);
    c.env("ORT_DYLIB_PATH", &ort).args([
        "irbench",
        "--lfw",
        "--dir",
        dir.to_str().unwrap(),
        "--det",
        det.to_str().unwrap(),
        "--model",
        emb.to_str().unwrap(),
    ]);
    let (code, out, err) = run(c, "irbench(--lfw synthetic)");
    // "2 persons" proves the LFW key collapsed Ada_Lovelace_{0001,0002}.
    assert!(out.contains("2 persons"), "out={out} err={err}");
    assert_eq!(code, 1, "out={out} err={err}");
    assert!(err.contains("not enough data"), "err={err}");
}

#[test]
#[ignore = "needs ONNX models + onnxruntime; CI provides them"]
fn bench_farbench_synthetic_too_few_embeddings() {
    let Some((det, emb, ort)) = models_and_ort() else {
        eprintln!("SKIP bench_farbench: models or onnxruntime not found");
        return;
    };
    let tmp = Tmp::new("bench-far");
    let dir = tmp.dir("imgs");
    synth_dataset(&dir);
    let mut c = cmd(&tmp);
    c.env("ORT_DYLIB_PATH", &ort).args([
        "irbench",
        "--impostor-only",
        "--dir",
        dir.to_str().unwrap(),
        "--det",
        det.to_str().unwrap(),
        "--model",
        emb.to_str().unwrap(),
    ]);
    let (code, out, err) = run(c, "farbench(synthetic)");
    assert!(out.contains("[farbench]"), "out={out} err={err}");
    assert!(out.contains("embedded 0 faces"), "out={out}");
    assert_eq!(code, 1, "out={out} err={err}");
    assert!(
        err.contains("too few embeddings for pairwise stats"),
        "err={err}"
    );
}

#[test]
#[ignore = "needs ONNX models + onnxruntime; CI provides them"]
fn bench_eval_synthetic_reports_no_pairs() {
    let Some((det, emb, ort)) = models_and_ort() else {
        eprintln!("SKIP bench_eval: models or onnxruntime not found");
        return;
    };
    let tmp = Tmp::new("bench-eval");
    let img = tmp.path("group.bmp");
    write_bmp(&img, 128, 128, [90, 90, 90]);
    let mut c = cmd(&tmp);
    c.env("ORT_DYLIB_PATH", &ort).args([
        "eval",
        "--image",
        img.to_str().unwrap(),
        "--det",
        det.to_str().unwrap(),
        "--model",
        emb.to_str().unwrap(),
    ]);
    let (code, out, err) = run(c, "eval(synthetic)");
    // A face-free image runs the detect+embed path but yields <2 faces.
    assert_eq!(code, 0, "out={out} err={err}");
    assert!(out.contains("faces; embedding each"), "out={out}");
}

#[test]
#[ignore = "needs ONNX models + onnxruntime; CI provides them"]
fn bench_normprobe_synthetic_no_faces() {
    let Some((det, emb, ort)) = models_and_ort() else {
        eprintln!("SKIP bench_normprobe: models or onnxruntime not found");
        return;
    };
    let tmp = Tmp::new("bench-norm");
    let dir = tmp.dir("imgs");
    synth_dataset(&dir);
    let mut c = cmd(&tmp);
    c.env("ORT_DYLIB_PATH", &ort).args([
        "normprobe",
        "--dir",
        dir.to_str().unwrap(),
        "--det",
        det.to_str().unwrap(),
        "--model",
        emb.to_str().unwrap(),
    ]);
    let (code, out, err) = run(c, "normprobe(synthetic)");
    assert_eq!(code, 1, "out={out} err={err}");
    assert!(err.contains("[normprobe] no faces"), "err={err}");
}
