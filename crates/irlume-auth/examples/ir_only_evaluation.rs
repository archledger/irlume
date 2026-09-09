// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Root-only, non-granting, one-presentation IR developer diagnostic.
use irlume_auth::ir_only_evaluation::{valid_budget, Category, Report};
use std::{
    io::Read,
    os::fd::AsRawFd,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const HELP: &str = "Non-granting IR-only developer evaluation. Never authenticates or releases credentials.\nUsage: ir_only_evaluation (--evaluate|--preflight) USER DETECTOR RECOGNIZER FLIR --budget-ms 100..30000 [--adapter PATH] [--cancel-on-stdin]\nModel paths must be absolute. Reads the configured camera pair without discovery.\n--preflight loads models/enrollment but never opens cameras. --evaluate needs an attended start cue.\nWith --cancel-on-stdin, any byte, EOF or read error requests cooperative cancellation.\nThe budget covers capture/inference, not model loading or template-key unseal.\n";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    preflight: bool,
    user: String,
    detector: String,
    recognizer: String,
    pad: String,
    budget_ms: u64,
    adapter: Option<String>,
    cancel_on_stdin: bool,
}

fn parse(args: &[String]) -> Option<Options> {
    if args.len() < 7 || args.len() > 10 || args.iter().any(|s| s.is_empty() || s.len() > 4096) {
        return None;
    }
    let preflight = match args[0].as_str() {
        "--preflight" => true,
        "--evaluate" => false,
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
    if !args[2..5].iter().all(|path| Path::new(path).is_absolute()) {
        return None;
    }
    let mut budget = None;
    let mut adapter = None;
    let mut cancel_on_stdin = false;
    let mut rest = args[5..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--budget-ms" if budget.is_none() => budget = Some(rest.next()?.parse::<u64>().ok()?),
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
    let budget_ms = budget?;
    if !valid_budget(Duration::from_millis(budget_ms)) {
        return None;
    }
    Some(Options {
        preflight,
        user: user.clone(),
        detector: args[2].clone(),
        recognizer: args[3].clone(),
        pad: args[4].clone(),
        budget_ms,
        adapter,
        cancel_on_stdin,
    })
}

fn root() -> bool {
    // SAFETY: getuid/geteuid take no pointers and have no failure convention.
    unsafe { libc::getuid() == 0 && libc::geteuid() == 0 }
}

fn disable_process_dumps() -> bool {
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limits points to the initialized platform rlimit ABI type.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } != 0 {
        return false;
    }
    // SAFETY: PR_SET_DUMPABLE takes a boolean scalar and no pointer arguments.
    unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) == 0
    }
}

fn quiet_dependencies() -> bool {
    let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") else {
        return false;
    };
    // SAFETY: null owns a valid descriptor and STDERR_FILENO is the process's
    // standard error slot. Called before spawning the stdin/model worker threads.
    unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) >= 0 }
}

fn run(options: &Options) -> Report {
    if !root() {
        return Report::new(Category::RootRequired);
    }
    // The reused libraries can emit diagnostic measurements. Refuse debug mode
    // and suppress all dependency stderr before model loading or biometric reads.
    if irlume_common::dbglog::on()
        || std::env::var_os("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA").is_some()
        || !disable_process_dumps()
        || !quiet_dependencies()
    {
        return Report::new(Category::InvalidRequest);
    }
    std::panic::set_hook(Box::new(|_| {}));
    let cancelled = Arc::new(AtomicBool::new(false));
    if options.cancel_on_stdin {
        let signal = Arc::clone(&cancelled);
        if std::thread::Builder::new()
            .name("ir-evaluation-cancel".into())
            .spawn(move || {
                let _ = std::io::stdin().read(&mut [0u8; 1]);
                signal.store(true, Ordering::Release);
            })
            .is_err()
        {
            return Report::new(Category::InvalidRequest);
        }
    }
    let control = irlume_camera::CaptureControl::new(
        irlume_camera::no_progress(),
        Arc::new(move || cancelled.load(Ordering::Acquire)),
    );
    let load = || -> Result<_, Category> {
        control.check().map_err(|_| Category::Cancelled)?;
        let (rgb, ir) =
            irlume_camera::configured_pair_no_probe().ok_or(Category::CameraUnavailable)?;
        if !irlume_common::platform::user_exists(&options.user) {
            return Err(Category::EnrollmentUnavailable);
        }
        for path in [&options.detector, &options.recognizer, &options.pad]
            .into_iter()
            .chain(options.adapter.iter())
        {
            if !Path::new(path).is_file() {
                return Err(Category::ModelsUnavailable);
            }
        }
        let mut engine = irlume_auth::Engine::load(&options.detector, &options.recognizer)
            .map_err(|_| Category::ModelsUnavailable)?
            .with_devices(&rgb, &ir);
        control.check().map_err(|_| Category::Cancelled)?;
        engine = engine
            .with_pad_ir(&options.pad)
            .map_err(|_| Category::ModelsUnavailable)?;
        if let Some(path) = &options.adapter {
            engine = engine
                .with_ir_adapter(path)
                .map_err(|_| Category::ModelsUnavailable)?;
        }
        control.check().map_err(|_| Category::Cancelled)?;
        // Existing protected enrollment loader, read-only. An encrypted store
        // may unseal its template encryption key; no login credential API.
        let enrollment = irlume_core::storage::load_read_only(&options.user)
            .map_err(|_| Category::EnrollmentUnavailable)?
            .ok_or(Category::EnrollmentUnavailable)?;
        if enrollment.user != options.user {
            return Err(Category::EnrollmentUnavailable);
        }
        control.check().map_err(|_| Category::Cancelled)?;
        Ok((engine, enrollment))
    };
    match load() {
        Err(category) => Report::new(category),
        Ok((mut engine, enrollment)) if !options.preflight => engine.evaluate_ir_only(
            &enrollment,
            &control,
            Duration::from_millis(options.budget_ms),
        ),
        Ok((engine, enrollment)) => {
            let start = Instant::now();
            let category = engine.ir_only_evaluation_preflight(&enrollment);
            let mut report = Report::new(if control.check().is_err() {
                Category::Cancelled
            } else {
                category
            });
            report.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            report
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        print!("{HELP}");
        return;
    }
    let Some(options) = parse(&args) else {
        println!("{}", Report::new(Category::InvalidRequest).to_json());
        std::process::exit(2);
    };
    let report = run(&options);
    println!("{}", report.to_json());
    // Status 0 means a diagnostic completed, including refusals. Never login.
    if report.category == Category::RootRequired {
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        [
            "--evaluate",
            "someone",
            "/det",
            "/emb",
            "/pad",
            "--budget-ms",
            "5000",
        ]
        .map(str::to_owned)
        .to_vec()
    }
    #[test]
    fn ir_only_evaluation_arguments_require_explicit_bounded_action() {
        let base = args();
        assert!(parse(&base).is_some());
        for (index, value) in [
            (0, "--authenticate"),
            (1, "../private"),
            (2, "relative"),
            (6, "0"),
            (6, "99"),
            (6, "30001"),
            (6, "NaN"),
            (6, "18446744073709551616"),
        ] {
            let mut input = base.clone();
            input[index] = value.into();
            assert!(parse(&input).is_none(), "accepted invalid argument {index}");
        }
        assert!(parse(&base[..5]).is_none());
    }
    #[test]
    fn ir_only_evaluation_arguments_accept_preflight_and_cancel_but_reject_duplicates() {
        let mut input = args();
        input[0] = "--preflight".into();
        input.extend(["--adapter", "/adapter", "--cancel-on-stdin"].map(str::to_owned));
        let parsed = parse(&input).expect("preflight arguments");
        assert!(parsed.preflight && parsed.cancel_on_stdin);
        assert_eq!(parsed.adapter.as_deref(), Some("/adapter"));
        input.push("--cancel-on-stdin".into());
        assert!(parse(&input).is_none());
        let mut input = args();
        input.extend(["--budget-ms", "5000"].map(str::to_owned));
        assert!(parse(&input).is_none());
    }
    #[test]
    fn ir_only_evaluation_disables_crash_dump_persistence_in_child() {
        const CHILD: &str = "IRLUME_EVALUATION_DUMP_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(disable_process_dumps());
            // SAFETY: GET_DUMPABLE reads the current process flag without pointers.
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            let mut limits = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: limits is writable storage of the expected ABI type.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) },
                0
            );
            assert_eq!((limits.rlim_cur, limits.rlim_max), (0, 0));
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::ir_only_evaluation_disables_crash_dump_persistence_in_child",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
