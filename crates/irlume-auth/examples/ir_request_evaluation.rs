// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Root-only, non-granting production IR request measurement.
mod support;
use irlume_auth::ir_request_evaluation::{Phase, RefusalCause, Report};
use std::{
    io::{Read as _, Write as _},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const HELP: &str = "Non-granting IR verification-request measurement. Never grants access or releases credentials.\nUsage: ir_request_evaluation (--preflight|--evaluate) USER DETECTOR RECOGNIZER FLIR --service SERVICE [--adapter PATH] [--cancel-on-stdin]\nUses the configured production window and explicit ordinary camera pair.\nPreflight never opens cameras. Evaluation requires freshly attended supervisor readiness.\nA byte, EOF or read error on cancellation stdin cancels the request.\n";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    phase: Phase,
    user: String,
    detector: String,
    recognizer: String,
    pad: String,
    service: String,
    adapter: Option<String>,
    cancel_on_stdin: bool,
}

fn parse(args: &[String]) -> Option<Options> {
    if !(7..=10).contains(&args.len()) || args.iter().any(|s| s.is_empty() || s.len() > 4096) {
        return None;
    }
    let phase = match args[0].as_str() {
        "--preflight" => Phase::Preflight,
        "--evaluate" => Phase::Evaluation,
        _ => return None,
    };
    let user = &args[1];
    if user.len() > 256
        || !user
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return None;
    }
    if !args[2..5].iter().all(|p| Path::new(p).is_absolute()) {
        return None;
    }
    let mut service = None;
    let mut adapter = None;
    let mut cancel_on_stdin = false;
    let mut rest = args[5..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--service" if service.is_none() => {
                let name = rest.next()?;
                use irlume_common::pam_service::{classify, ServiceKind};
                if !matches!(
                    classify(name),
                    Some(ServiceKind::Greeter | ServiceKind::ScreenUnlock)
                ) {
                    return None;
                }
                service = Some(name.clone());
            }
            "--adapter" if adapter.is_none() => {
                let path = rest.next()?;
                if !Path::new(path).is_absolute() {
                    return None;
                }
                adapter = Some(path.clone());
            }
            "--cancel-on-stdin" if !cancel_on_stdin => cancel_on_stdin = true,
            _ => return None,
        }
    }
    Some(Options {
        phase,
        user: user.clone(),
        detector: args[2].clone(),
        recognizer: args[3].clone(),
        pad: args[4].clone(),
        service: service?,
        adapter,
        cancel_on_stdin,
    })
}

fn run(options: &Options) -> Report {
    let refused = |cause| Report::refused(options.phase, cause);
    if !support::root() {
        return refused(RefusalCause::RootRequired);
    }
    if irlume_common::dbglog::on()
        || std::env::var_os("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA").is_some()
        || !support::disable_process_dumps()
        || !support::quiet_dependencies()
    {
        return refused(RefusalCause::InvalidRequest);
    }
    std::panic::set_hook(Box::new(|_| {}));
    let cancelled = Arc::new(AtomicBool::new(false));
    if options.cancel_on_stdin {
        let signal = cancelled.clone();
        if std::thread::Builder::new()
            .name("ir-request-cancel".into())
            .spawn(move || {
                let _ = std::io::stdin().read(&mut [0u8; 1]);
                signal.store(true, Ordering::Release);
            })
            .is_err()
        {
            return refused(RefusalCause::InvalidRequest);
        }
    }
    let load = || -> Result<irlume_auth::Engine, RefusalCause> {
        let check = || {
            if cancelled.load(Ordering::Acquire) {
                Err(RefusalCause::Cancelled)
            } else {
                Ok(())
            }
        };
        check()?;
        if !irlume_common::platform::user_exists(&options.user) {
            return Err(RefusalCause::StateUnavailable);
        }
        for path in [&options.detector, &options.recognizer, &options.pad]
            .into_iter()
            .chain(options.adapter.iter())
        {
            if !Path::new(path).is_file() {
                return Err(RefusalCause::ModelsUnavailable);
            }
        }
        let (rgb, ir) =
            irlume_camera::configured_pair_no_probe().ok_or(RefusalCause::CameraUnavailable)?;
        let mut engine = irlume_auth::Engine::load(&options.detector, &options.recognizer)
            .map_err(|_| RefusalCause::ModelsUnavailable)?
            .with_devices(&rgb, &ir);
        check()?;
        engine = engine
            .with_pad_ir(&options.pad)
            .map_err(|_| RefusalCause::ModelsUnavailable)?;
        check()?;
        if let Some(path) = &options.adapter {
            engine = engine
                .with_ir_adapter(path)
                .map_err(|_| RefusalCause::ModelsUnavailable)?
                .with_ir_adapter_required(true);
        }
        check()?;
        Ok(engine)
    };
    let initialization = std::time::Instant::now();
    let mut engine = match load() {
        Ok(engine) => engine,
        Err(cause) => return refused(cause).with_initialization_time(initialization.elapsed()),
    };
    let initialization_elapsed = initialization.elapsed();
    engine.set_request_cancel_signal(Arc::new(move || cancelled.load(Ordering::Acquire)));
    engine
        .evaluate_ir_request(&options.user, &options.service, options.phase)
        .with_initialization_time(initialization_elapsed)
}

fn main() {
    // The cap bounds argument collection as well as parsing.
    // args() panics on non-UTF-8 and can print the private argument to stderr.
    let args: Option<Vec<String>> = std::env::args_os()
        .skip(1)
        .take(11)
        .map(|arg| arg.into_string().ok())
        .collect();
    if args.as_deref().is_some_and(|args| args == ["--help"]) {
        print!("{HELP}");
        return;
    }
    let options = args.as_deref().and_then(parse);
    let valid = options.is_some();
    let report = options
        .as_ref()
        .map(run)
        .unwrap_or_else(|| Report::refused(Phase::Evaluation, RefusalCause::InvalidRequest));
    let mut bytes = report.to_json().to_string().into_bytes();
    bytes.push(b'\n');
    if bytes.len() > 16 * 1024 || std::io::stdout().lock().write_all(&bytes).is_err() {
        std::process::exit(1);
    }
    if !valid || !support::root() {
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        [
            "--evaluate",
            "synthetic",
            "/det",
            "/emb",
            "/pad",
            "--service",
            "kde",
        ]
        .map(str::to_owned)
        .to_vec()
    }
    #[test]
    fn request_parser_requires_explicit_action_models_and_supported_service() {
        let base = args();
        assert!(parse(&base).is_some());
        for (i, value) in [
            (0, "--authenticate"),
            (1, "../user"),
            (2, "relative"),
            (5, "--budget-ms"),
            (6, "sudo"),
            (6, "sshd"),
            (6, "unknown"),
        ] {
            let mut bad = base.clone();
            bad[i] = value.into();
            assert!(parse(&bad).is_none(), "{i}/{value}");
        }
        assert!(parse(&base[..6]).is_none());
        for extra in [
            vec!["--service", "kde"],
            vec!["--cancel-on-stdin", "--cancel-on-stdin"],
            vec!["--adapter", "relative"],
            vec!["--unknown"],
        ] {
            let mut bad = base.clone();
            bad.extend(extra.into_iter().map(str::to_owned));
            assert!(parse(&bad).is_none());
        }
    }
    #[test]
    fn request_parser_accepts_preflight_adapter_and_cancellation() {
        let mut input = args();
        input[0] = "--preflight".into();
        input.extend(["--adapter", "/adapter", "--cancel-on-stdin"].map(str::to_owned));
        let options = parse(&input).unwrap();
        assert_eq!(options.phase, Phase::Preflight);
        assert!(options.cancel_on_stdin);
        assert_eq!(options.adapter.as_deref(), Some("/adapter"));
    }
}
