// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! One live engine authentication trial, with construction measured separately.
//! This opens cameras and may access enrollment/TPM state. See --help and
//! docs/research/benchmark-harness.md. Engine timing excludes daemon/PAM/wallet.

#[path = "benchmark_support/identity.rs"]
mod identity;
#[path = "benchmark_support/sampling.rs"]
mod sampling;

use irlume_auth::AuthenticationPurpose;
use irlume_common::diagnostics::{DiagnosticSink, TraceEventKind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

const HELP: &str = "Usage: auth_timing <user> <det.onnx> <model.onnx> [rgb] [ir] [--service NAME|none] [--purpose auto|verify|credential-release|app-consent]\nDefaults: /dev/video0 /dev/video2, service=sudo, purpose=auto (production service classification).\nRuns ONE LIVE Engine authentication: cameras/enrollment/TPM may be accessed.\nAuxiliary models use IRLUME_IR_ADAPTER, IRLUME_MESH_MODEL, IRLUME_BLAZE_MODEL, IRLUME_VIT_PAD_MODEL, IRLUME_PAD_IR_MODEL; otherwise look beside det.onnx.\nExplicit missing auxiliary paths are errors; absent implicit files are reported.\nUse IRLUME_LOG=debug to observe the engine's grouped-capture marker.\nEngine authentication excludes daemon/PAM/wallet work; construction is separate, not cold-login latency.";

struct Options {
    user: String,
    det: String,
    model: String,
    rgb: String,
    ir: String,
    service: Option<String>,
    purpose: AuthenticationPurpose,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut service = Some("sudo".to_owned());
        let mut purpose = "auto";
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--service" => {
                    let value = args.next().ok_or("--service requires a value")?;
                    service = (value != "none").then(|| value.clone());
                }
                "--purpose" => purpose = args.next().ok_or("--purpose requires a value")?,
                value if value.starts_with('-') => return Err(format!("unknown option: {value}")),
                _ => positional.push(arg.clone()),
            }
        }
        if !(3..=5).contains(&positional.len()) {
            return Err(HELP.into());
        }
        let purpose = match purpose {
            "auto" => AuthenticationPurpose::for_service(service.as_deref()),
            "verify" => AuthenticationPurpose::Verify,
            "credential-release" => AuthenticationPurpose::CredentialRelease,
            "app-consent" => AuthenticationPurpose::AppConsent,
            _ => return Err(format!("unknown purpose: {purpose}")),
        };
        Ok(Self {
            user: positional[0].clone(),
            det: positional[1].clone(),
            model: positional[2].clone(),
            rgb: positional
                .get(3)
                .cloned()
                .unwrap_or_else(|| "/dev/video0".into()),
            ir: positional
                .get(4)
                .cloned()
                .unwrap_or_else(|| "/dev/video2".into()),
            service,
            purpose,
        })
    }
}

#[derive(Default)]
struct StageSink {
    stages: Mutex<Vec<(TraceEventKind, Instant)>>,
}

impl DiagnosticSink for StageSink {
    fn emit_trace(&self, kind: TraceEventKind) {
        if matches!(kind, TraceEventKind::StageTiming { .. }) {
            self.stages
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((kind, Instant::now()));
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let options = Options::parse(&args)?;
    identity::header("one live Engine authentication; excludes daemon ingress/queue, PAM, wallet and process startup");
    println!(
        "service={:?} purpose={:?} rgb={} ir={}",
        options.service, options.purpose, options.rgb, options.ir
    );
    println!("grouped_execution=unobserved-by-this-sink; service or sequential scheduling alone does not prove eligibility; see debug grouped-capture marker");
    let parent = Path::new(&options.det).parent().unwrap_or(Path::new("."));
    let mut auxiliary = Vec::new();
    for (key, filename) in [
        ("IRLUME_IR_ADAPTER", "ir_adapter.onnx"),
        ("IRLUME_MESH_MODEL", "face_landmarks_detector.tflite"),
        ("IRLUME_BLAZE_MODEL", "blaze_face_short_range.onnx"),
        ("IRLUME_VIT_PAD_MODEL", "liveness_vit.onnx"),
        ("IRLUME_PAD_IR_MODEL", "flir.onnx"),
    ] {
        let explicit = std::env::var_os(key);
        let path = explicit
            .clone()
            .map_or_else(|| parent.join(filename), PathBuf::from);
        if path.is_file() {
            auxiliary.push((key, path));
        } else if explicit.is_some() {
            return Err(format!(
                "{key}: explicit model path is not a file: {}",
                path.display()
            )
            .into());
        } else {
            println!("auxiliary {key}: absent ({})", path.display());
        }
    }
    let mut engine = identity::construct(
        "engine_with_auxiliary_models",
        || -> Result<_, Box<dyn std::error::Error>> {
            let mut engine = irlume_auth::Engine::load(&options.det, &options.model)?
                .with_devices(&options.rgb, &options.ir)
                .with_ir_adapter_required(std::env::var_os("IRLUME_IR_ADAPTER").is_some());
            for (key, path) in &auxiliary {
                let path = path.to_str().ok_or("model path must be UTF-8")?;
                engine = match *key {
                    "IRLUME_IR_ADAPTER" => engine.with_ir_adapter(path)?,
                    "IRLUME_MESH_MODEL" => engine.with_mesh(path)?,
                    "IRLUME_BLAZE_MODEL" => engine.with_blaze_rescue(path)?,
                    "IRLUME_VIT_PAD_MODEL" => engine.with_vit_pad(path)?,
                    "IRLUME_PAD_IR_MODEL" => engine.with_pad_ir(path)?,
                    _ => unreachable!("fixed auxiliary model list"),
                };
            }
            Ok(engine)
        },
    )?;
    identity::file("detector", Path::new(&options.det))?;
    identity::file("recognizer", Path::new(&options.model))?;
    for (key, path) in &auxiliary {
        identity::file(key, path)?;
    }
    identity::runtimes()?;
    println!(
        "loaded: adapter={} mesh={} blaze={} rgb_pad={} ir_pad={}",
        engine.has_ir_adapter(),
        engine.has_mesh(),
        engine.has_blaze_rescue(),
        engine.has_vit_pad(),
        engine.has_pad_ir()
    );
    let sink = StageSink::default();
    let start = Instant::now();
    sampling::measure(
        "authenticate_for",
        0,
        1,
        || {
            engine.authenticate_for_with_diagnostics(
                &options.user,
                options.service.as_deref(),
                options.purpose,
                &sink,
            )
        },
        |_, outcome| {
            println!(
                "outcome: kind={:?} granted={} live={} reason={}",
                outcome.kind, outcome.granted, outcome.live, outcome.reason
            )
        },
    )?
    .print(
        "authenticate_for (single outcome; no distribution claim)",
        0,
        1,
    );
    println!("stages can overlap/nest; do not sum them or compare Liveness across capture modes as equivalent work");
    for (kind, at) in sink.stages.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if let TraceEventKind::StageTiming { stage, elapsed_us } = kind {
            println!(
                "  +{:.3}s stage {stage:?}: {:.3} ms",
                at.duration_since(start).as_secs_f64(),
                *elapsed_us as f64 / 1000.0
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(extra: &[&str]) -> Result<Options, String> {
        let args: Vec<_> = ["user", "det.onnx", "model.onnx"]
            .into_iter()
            .chain(extra.iter().copied())
            .map(str::to_owned)
            .collect();
        Options::parse(&args)
    }
    #[test]
    fn selected_service_uses_production_purpose_classification() {
        let options = parse(&["--service", "polkit-1"]).unwrap();
        assert_eq!(options.purpose, AuthenticationPurpose::AppConsent);
        assert_eq!(parse(&[]).unwrap().purpose, AuthenticationPurpose::Verify);
    }
    #[test]
    fn explicit_credential_purpose_is_preserved_for_local_unlock() {
        let options = parse(&["--service", "login", "--purpose", "credential-release"]).unwrap();
        assert_eq!(options.service.as_deref(), Some("login"));
        assert_eq!(options.purpose, AuthenticationPurpose::CredentialRelease);
        assert!(parse(&["--service", "none"]).unwrap().service.is_none());
    }
    #[test]
    fn malformed_options_refuse_before_loading_or_authentication() {
        assert!(parse(&["--purpose", "grant"]).is_err());
        assert!(parse(&["--service"]).is_err());
        assert!(parse(&["--surprise"]).is_err());
        assert!(Options::parse(&[]).is_err());
    }
}
