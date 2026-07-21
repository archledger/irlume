// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Black-box tests of the IRLUME_DEV camera/benchmark subcommands (`capture`,
//! `liveness`, `meshprobe`, `calcapture`, `padcapture`, `genuine`, `suncal`)
//! against the v4l2loopback virtual-camera harness CI provides.
//!
//! The feeder nodes carry ffmpeg test patterns (YUYV 640x480 RGB, GREY 640x400
//! IR) with NO face in frame, so every test asserts the tools' documented
//! no-face behavior: the running path past argument parsing, through the real
//! capture + detection pipeline, to the exact output strings and exit codes.
//!
//! Gating follows the camera crate's convention: `loopback_`-prefixed names,
//! `#[ignore]`, and an early return when the env is absent. CI runs them with
//! `-- --ignored loopback_ --test-threads=1` and sets:
//!   IRLUME_TEST_RGB_DEVICE / IRLUME_TEST_IR_DEVICE  (the feeder nodes)
//! The spawned binary additionally needs IRLUME_TEST_ALLOW_VIRTUAL_CAMERA
//! naming those exact paths (loopback nodes have no physical bus, so
//! `verify_pinned` would refuse them); each test sets it itself.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_irlume");

/// Hard ceiling per spawned process: a hung camera read must fail the test,
/// never wedge CI.
const WATCHDOG_SECS: u64 = 60;

fn model(name: &str) -> String {
    format!("{}/../../models/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// The feeder nodes, or None (skip) when the harness is not up.
fn loopback_pair() -> Option<(String, String)> {
    Some((
        std::env::var("IRLUME_TEST_RGB_DEVICE").ok()?,
        std::env::var("IRLUME_TEST_IR_DEVICE").ok()?,
    ))
}

/// `ORT_DYLIB_PATH` for the child: the parent's value when set (CI exports
/// one), else the packaged/system locations irlume-auth's ort_init probes.
fn ort_dylib() -> Option<String> {
    if let Ok(p) = std::env::var("ORT_DYLIB_PATH") {
        return Some(p);
    }
    [
        "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
        "/usr/lib64/libonnxruntime.so",
        "/usr/lib/libonnxruntime.so",
        "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists())
    .map(String::from)
}

/// Per-test temp tree (state/config/keyring/work); deleted on drop.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("irlume-cli-cap-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["cfg", "state", "keyring", "work"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Sandbox { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// A Command for the irlume binary with IRLUME_DEV=1, the virtual-camera
    /// escape for exactly the two feeder nodes, and every writable path inside
    /// the sandbox. cwd is a scratch dir so any stray output file lands there.
    fn dev_cmd(&self, args: &[&str], rgb: &str, ir: &str) -> Command {
        let mut c = Command::new(BIN);
        c.args(args)
            .env("IRLUME_DEV", "1")
            .env("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA", format!("{rgb},{ir}"))
            .env("IRLUME_SOCKET", self.root.join("no-daemon.sock"))
            .env("IRLUME_CONFIG_DIR", self.root.join("cfg"))
            .env("IRLUME_STATE_DIR", self.root.join("state"))
            .env("IRLUME_KEYRING_DIR", self.root.join("keyring"))
            .env_remove("IRLUME_MODEL")
            .env_remove("IRLUME_DET_MODEL")
            .env_remove("IRLUME_CAMERA_PIN")
            .current_dir(self.root.join("work"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(ort) = ort_dylib() {
            c.env("ORT_DYLIB_PATH", ort);
        }
        c
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Run under the watchdog and collect (exit code, stdout, stderr). A process
/// still alive at the deadline is SIGKILLed and the test fails with a message
/// naming the command, so a hung capture can never wedge CI.
fn run_timeboxed(what: &str, cmd: &mut Command) -> (i32, String, String) {
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    let pid = child.id() as i32;
    let done = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let (done, timed_out) = (done.clone(), timed_out.clone());
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(WATCHDOG_SECS);
            while Instant::now() < deadline {
                if done.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            if !done.load(Ordering::SeqCst) {
                timed_out.store(true, Ordering::SeqCst);
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        })
    };
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait {what}: {e}"));
    done.store(true, Ordering::SeqCst);
    watchdog.join().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !timed_out.load(Ordering::SeqCst),
        "`irlume {what}` exceeded the {WATCHDOG_SECS}s watchdog and was killed.\n\
         stdout so far:\n{stdout}\nstderr so far:\n{stderr}"
    );
    let code = out.status.code().unwrap_or_else(|| {
        panic!("`irlume {what}` exited by signal.\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, stdout, stderr)
}

// -------------------------------------------------------------------- capture

#[test]
#[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
fn loopback_capture_runs_detection_and_reports_no_face() {
    let Some((rgb, ir)) = loopback_pair() else {
        return;
    };
    let sb = Sandbox::new("capture");
    let det = model("face_detection_yunet_2023mar.onnx");
    let rec = model("glintr100.onnx");
    let (code, out, err) = run_timeboxed(
        "capture",
        &mut sb.dev_cmd(
            &["capture", "--det", &det, "--model", &rec, "--device", &rgb],
            &rgb,
            &ir,
        ),
    );
    assert_eq!(
        code, 0,
        "no face is a clean outcome, not an error\n{out}\n{err}"
    );
    assert!(
        out.contains(&format!("640x480 RGB frame from {rgb}")),
        "must capture a live frame from the loopback node: {out}"
    );
    assert!(out.contains("[detect]"), "detection stage must run: {out}");
    assert!(
        out.contains("no face in frame; sit in view and re-run."),
        "the test pattern holds no face: {out}"
    );
    assert!(
        !out.contains("[embed]"),
        "without a face the embed stage must never run: {out}"
    );
    // The exact-path escape is deliberately loud: verify_pinned logs each use.
    assert!(
        err.contains("accepted without a physical-device pin"),
        "the virtual-camera escape must warn on stderr: {err}"
    );
}

// ------------------------------------------------------------------- liveness

#[test]
#[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
fn loopback_liveness_probe_gates_a_faceless_feed_as_not_live() {
    let Some((rgb, ir)) = loopback_pair() else {
        return;
    };
    let sb = Sandbox::new("liveness");
    let det = model("face_detection_yunet_2023mar.onnx");
    let (code, out, err) = run_timeboxed(
        "liveness",
        &mut sb.dev_cmd(
            &["liveness", "--det", &det, "--rgb", &rgb, "--ir", &ir],
            &rgb,
            &ir,
        ),
    );
    assert_eq!(code, 0, "a no-face probe completes cleanly\n{out}\n{err}");
    assert!(
        out.contains("[RGB] 640x480"),
        "RGB stage must report the loopback geometry: {out}"
    );
    assert!(
        out.contains("[IR ] 640x400"),
        "IR stage must report the loopback geometry: {out}"
    );
    assert!(
        out.contains("brightness mean"),
        "IR stats line must print: {out}"
    );
    // The gate's first hard cue is face presence; a faceless feed must fail it
    // and the verdict line names the missing face.
    assert!(
        out.contains("[GATE]") && out.contains("no face in"),
        "verdict must be the no-face refusal: {out}"
    );
    assert!(
        !out.contains("[GATE] Live"),
        "a faceless feed must never gate Live: {out}"
    );
}

// ------------------------------------------------------------------ meshprobe

#[test]
#[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
fn loopback_meshprobe_reports_spoof_when_no_eyes_are_found() {
    let Some((rgb, ir)) = loopback_pair() else {
        return;
    };
    let sb = Sandbox::new("meshprobe");
    let det = model("face_detection_yunet_2023mar.onnx");
    let mesh = model("face_landmark.onnx");
    let (code, out, err) = run_timeboxed(
        "meshprobe",
        &mut sb.dev_cmd(
            &[
                "meshprobe",
                "--det",
                &det,
                "--mesh",
                &mesh,
                "--ir",
                &ir,
                "--n",
                "2",
                "--burst",
                "1",
                "--reps",
                "1",
            ],
            &rgb,
            &ir,
        ),
    );
    assert_eq!(code, 0, "a faceless run completes cleanly\n{out}\n{err}");
    // No face in any IR frame means zero EAR samples; detect_blink maps that
    // to NoEyes, which meshprobe prints as the Spoof verdict.
    assert!(
        out.contains("[rep  1/1]"),
        "the single rep must report: {out}"
    );
    assert!(
        out.contains("(n=0)"),
        "no EAR samples on a faceless feed: {out}"
    );
    assert!(
        out.contains("-> Spoof"),
        "NoEyes maps to the Spoof verdict: {out}"
    );
    assert!(
        !out.contains("[meshprobe] appended"),
        "without --species/--kind/--out nothing is recorded: {out}"
    );
}

// ----------------------------------------------------------------- calcapture

#[test]
#[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
fn loopback_calcapture_writes_header_and_faceless_samples() {
    let Some((rgb, ir)) = loopback_pair() else {
        return;
    };
    let sb = Sandbox::new("calcapture");
    let det = model("face_detection_yunet_2023mar.onnx");
    let rec = model("glintr100.onnx");
    let out_path = sb.path("work/cal.jsonl");
    let out_str = out_path.to_str().unwrap().to_string();
    let (code, out, err) = run_timeboxed(
        "calcapture",
        &mut sb.dev_cmd(
            &[
                "calcapture",
                "--user",
                "u",
                "--det",
                &det,
                "--model",
                &rec,
                "--out",
                &out_str,
                "--rgb",
                &rgb,
                "--ir",
                &ir,
                "--n",
                "2",
            ],
            &rgb,
            &ir,
        ),
    );
    assert_eq!(code, 0, "\n{out}\n{err}");
    assert!(
        out.contains("[calcapture] user=u tag=untagged n=2"),
        "run parameters echo: {out}"
    );
    assert!(
        out.contains("rgb_templates=0 ir_templates=0 adapter=no"),
        "sandboxed state dir has no enrollment: {out}"
    );
    assert!(
        err.contains("cosines from pairwise only"),
        "unenrolled user is a note, not a failure: {err}"
    );
    assert!(
        out.contains(&format!("wrote 2 samples to {out_str}")),
        "every requested sample is written even with no face: {out}"
    );

    let text = std::fs::read_to_string(&out_path).expect("cal.jsonl written");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "1 session header + 2 samples, got:\n{text}");
    let hdr: serde_json::Value = serde_json::from_str(lines[0]).expect("header parses");
    assert_eq!(hdr["session"], serde_json::json!(true));
    assert_eq!(hdr["user"], serde_json::json!("u"));
    assert_eq!(hdr["n"], serde_json::json!(2));
    for (i, l) in lines[1..].iter().enumerate() {
        let rec: serde_json::Value = serde_json::from_str(l).expect("sample parses");
        assert_eq!(rec["idx"], serde_json::json!(i));
        assert_eq!(
            rec["rgb_present"],
            serde_json::json!(false),
            "test pattern holds no RGB face: {l}"
        );
        assert_eq!(
            rec["ir_present"],
            serde_json::json!(false),
            "test pattern holds no IR face: {l}"
        );
        assert!(
            rec.get("rgb_emb").is_none() && rec.get("ir_emb_raw").is_none(),
            "no face means no embeddings in the record: {l}"
        );
    }
}

// ----------------------------------------------------------------- padcapture

#[test]
#[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
fn loopback_padcapture_ir_only_records_faceless_attack_presentations() {
    let Some((rgb, ir)) = loopback_pair() else {
        return;
    };
    let sb = Sandbox::new("padcapture");
    let det = model("face_detection_yunet_2023mar.onnx");
    let out_path = sb.path("work/pad.jsonl");
    let out_str = out_path.to_str().unwrap().to_string();
    let (code, out, err) = run_timeboxed(
        "padcapture",
        &mut sb.dev_cmd(
            &[
                "padcapture",
                "--species",
                "test",
                "--kind",
                "attack",
                "--det",
                &det,
                "--out",
                &out_str,
                "--path",
                "ir-only",
                "--n",
                "2",
                "--rgb",
                &rgb,
                "--ir",
                &ir,
                "--no-prompt",
            ],
            &rgb,
            &ir,
        ),
    );
    assert_eq!(code, 0, "\n{out}\n{err}");
    assert!(
        out.contains("species=test kind=attack path=ir-only n=2"),
        "run parameters echo: {out}"
    );
    assert!(
        out.contains("--no-prompt: capturing 2 frames back-to-back"),
        "prompt suppression must be announced: {out}"
    );
    assert!(
        out.contains(&format!("appended 2 presentations to {out_str}")),
        "both presentations recorded: {out}"
    );
    assert!(
        !out.contains("ACCEPTED"),
        "a faceless attack presentation must never be accepted as Live: {out}"
    );

    let text = std::fs::read_to_string(&out_path).expect("pad.jsonl written");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "one record per presentation:\n{text}");
    for (i, l) in lines.iter().enumerate() {
        let rec: serde_json::Value = serde_json::from_str(l).expect("record parses");
        assert_eq!(rec["species"], serde_json::json!("test"));
        assert_eq!(rec["kind"], serde_json::json!("attack"));
        assert_eq!(rec["path"], serde_json::json!("ir-only"));
        assert_eq!(rec["idx"], serde_json::json!(i));
        assert_eq!(
            rec["ir_present"],
            serde_json::json!(false),
            "no IR face on the pattern: {l}"
        );
        // evaluate_ir_only's first hard cue: no IR face is a non-response.
        assert_eq!(
            rec["verdict"],
            serde_json::json!("Uncertain"),
            "a faceless ir-only presentation is Uncertain, never Live: {l}"
        );
    }
}

// -------------------------------------------------------------------- genuine

#[test]
#[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
fn loopback_genuine_declines_stats_without_two_face_frames() {
    let Some((rgb, ir)) = loopback_pair() else {
        return;
    };
    let sb = Sandbox::new("genuine");
    let det = model("face_detection_yunet_2023mar.onnx");
    let rec = model("glintr100.onnx");
    let (code, out, err) = run_timeboxed(
        "genuine",
        &mut sb.dev_cmd(
            &["genuine", "--det", &det, "--model", &rec, "--device", &rgb],
            &rgb,
            &ir,
        ),
    );
    assert_eq!(code, 0, "no face is a clean outcome\n{out}\n{err}");
    assert!(
        out.contains("capturing 5 frames"),
        "the fixed 5-frame loop announces itself: {out}"
    );
    for k in 1..=5 {
        assert!(
            out.contains(&format!("frame {k}: no face")),
            "every frame of the pattern is faceless: {out}"
        );
    }
    assert!(
        out.contains("need >=2 frames with a face"),
        "with <2 face frames the cosine stats must be declined: {out}"
    );
    assert!(
        !out.contains("pairs:"),
        "no pairwise stats may print without faces: {out}"
    );
}

// --------------------------------------------------------------------- suncal

/// Binary P5 PGM bytes for a flat grey frame.
fn pgm(w: u32, h: u32, fill: u8) -> Vec<u8> {
    let mut v = format!("P5\n{w} {h}\n255\n").into_bytes();
    v.extend(vec![fill; (w * h) as usize]);
    v
}

/// `suncal` is the offline half of the sunlight-capture toolchain: it replays
/// recorded IR bursts through the real detector + depth cue. No camera nodes
/// are opened, but it needs the YuNet model and the ONNX runtime, which only
/// the loopback CI lane guarantees, so it gates on the same env.
#[test]
#[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
fn loopback_suncal_analyzes_a_faceless_burst_dataset() {
    let Some((rgb, ir)) = loopback_pair() else {
        return;
    };
    let sb = Sandbox::new("suncal");
    let det = model("face_detection_yunet_2023mar.onnx");
    // One burst: dim ambient frames around a bright lit frame, all flat grey.
    // gap = 200 - 5 = 195 (> 8), ambient 5 (>= 5), subtracted mean 195 (>= 12):
    // the gate chooses the subtracted frame, and no face is detectable.
    let burst = sb.path("work/dataset/b0");
    std::fs::create_dir_all(&burst).unwrap();
    std::fs::write(burst.join("frame00.pgm"), pgm(640, 400, 5)).unwrap();
    std::fs::write(burst.join("frame01.pgm"), pgm(640, 400, 200)).unwrap();
    std::fs::write(burst.join("frame02.pgm"), pgm(640, 400, 5)).unwrap();
    let dataset = sb.path("work/dataset");
    let dataset_str = dataset.to_str().unwrap().to_string();

    let (code, out, err) = run_timeboxed(
        "suncal",
        &mut sb.dev_cmd(&["suncal", &det, &dataset_str], &rgb, &ir),
    );
    assert_eq!(code, 0, "\n{out}\n{err}");
    assert!(
        out.starts_with("burst\tamb\tlit\tgap"),
        "TSV header first: {out}"
    );
    let row = out
        .lines()
        .find(|l| l.starts_with("b0\t"))
        .unwrap_or_else(|| panic!("burst b0 must produce a row: {out}"));
    let cols: Vec<&str> = row.split('\t').collect();
    assert_eq!(cols[1], "5", "ambient mean column: {row}");
    assert_eq!(cols[2], "200", "lit mean column: {row}");
    assert_eq!(cols[3], "195", "strobe gap column: {row}");
    assert_eq!(cols[5], "0.00", "no face means raw depth 0.00: {row}");
    assert_eq!(cols[8], "n", "raw depth cannot pass without a face: {row}");
    assert_eq!(
        cols[9], "sub",
        "this burst clears the subtraction gate: {row}"
    );
    assert_eq!(
        cols[10], "fail",
        "gated verdict fails without a face: {row}"
    );
    assert!(
        err.contains("0 bursts with a detectable IR face"),
        "summary counts detection failures honestly: {err}"
    );
}
