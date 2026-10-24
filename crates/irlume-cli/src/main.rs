// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume`: operator CLI. A thin, unprivileged client of `irlumed` (same socket
//! protocol as the PAM module). Enrollment requests are authorized by the daemon
//! via SO_PEERCRED, not by this binary.
//!
//! Run `irlume help` for the user-facing subcommands, or `irlume tui` for the
//! guided setup. Developer/benchmark tools are gated behind `IRLUME_DEV=1`.
//! A selection of the main subcommands:
//!   irlume tui                                   guided setup + live dashboard
//!   irlume enroll [--user U] [--name NAME] [--scans N]  register a face profile
//!   irlume identify                              1:N "who is this?"
//!   irlume doctor                                check cameras/IR/TPM/models
//!   irlume keyring <arm|status|forget>           TPM-sealed keyring/wallet unlock
//!   irlume recovery <status|setup|restore|forget> template-key recovery passphrase
//!   irlume fingerprint <status|add|verify|reset|enable|disable> fprintd companion (face OR fingerprint)
//!   irlume login <status|enable|disable|reconcile> wire face auth into PAM (+--with-polkit for apps)
//!   irlume logs [-f] [debug on|off]              face-auth journal view + tracing switch

// BEGIN HARDWARE EVIDENCE BOUNDARY
#[cfg(irlume_hw_evidence)]
compile_error!("irlume evidence build refused: irlume-cli/direct");
const HARDWARE_EVIDENCE_BUILD: bool = cfg!(irlume_hw_evidence)
    || irlume_auth::HARDWARE_EVIDENCE_BUILD
    || irlume_camera::HARDWARE_EVIDENCE_BUILD
    || irlume_common::HARDWARE_EVIDENCE_BUILD
    || irlume_core::HARDWARE_EVIDENCE_BUILD
    || irlume_fingerprint::HARDWARE_EVIDENCE_BUILD
    || irlume_liveness::HARDWARE_EVIDENCE_BUILD
    || irlume_vision::HARDWARE_EVIDENCE_BUILD;
const _: () = assert!(
    !HARDWARE_EVIDENCE_BUILD,
    "irlume evidence build refused: irlume-cli/dependency"
);
// END HARDWARE EVIDENCE BOUNDARY

mod bitwarden;
mod commands;
mod consent;
mod doctor_report;
mod endorsement_check;
mod fingerprint;
mod gkr_session;
mod logintx;
mod logs;
mod machine;
mod models;
mod nixos;
mod os_release;
mod pad;
mod pamwire;
mod preferences;
mod profile_ir;
mod recovery;
mod retry;
mod seal_storage;
mod secrets;
#[cfg(test)]
mod selection_provenance_tests;
mod sensor_policy;
mod split;
mod strays;
mod suncal;
mod support_report;
mod trace;
mod tui;
mod uninstall;
mod upgrade_notice;

pub(crate) fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    // BOTH standard spellings. `--name=value` used to be invisible here, and the
    // silence was the danger: `profiles delete --user=alice` parsed as no --user
    // at all, so the fallback named the INVOKING user and the command deleted
    // their enrollment instead of alice's. Every guard that asks "was --user
    // given" reads `flag_present`, which knows the same two spellings.
    for (i, a) in args.iter().enumerate() {
        if a == name {
            return args.get(i + 1).map(String::as_str);
        }
        // `--username=x` must NOT satisfy `--user`: the '=' has to come directly
        // after the flag name.
        if let Some(rest) = a.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
            return Some(rest);
        }
    }
    None
}

/// Was `name` given at all, in either spelling (`--name v` or `--name=v`)?
///
/// Separate from [`flag`] because a dangling flag has no value but is still
/// PRESENT, and that difference is what the `--user` guards act on.
pub(crate) fn flag_present(args: &[String], name: &str) -> bool {
    args.iter()
        .any(|a| a == name || a.strip_prefix(name).is_some_and(|r| r.starts_with('=')))
}

/// Developer / benchmark / research subcommands: hidden from `help` and gated
/// behind `IRLUME_DEV=1`. They open the camera directly (bypassing the daemon,
/// so they EBUSY-conflict on a running install) and some, like `calcapture`,
/// write RAW face embeddings to a plaintext file; not for end users.
const DEV_CMDS: &[&str] = &[
    "capture",
    "eval",
    "irbench",
    "genuine",
    "calcapture",
    "normprobe",
    "liveness",
    "selftest",
    "padcapture",
    "padreport",
    "verify",
    "enrolldev",
    "suncal",
];

fn main() -> std::process::ExitCode {
    irlume_common::build_mode::refuse_evidence_startup(HARDWARE_EVIDENCE_BUILD);
    // Rust ignores SIGPIPE by default, turning a closed stdout (`irlume … | head`,
    // `| less` then quit, `| grep -q`) into a "failed printing to stdout: Broken
    // pipe" panic + exit 101. Restore the Unix default so we exit quietly like any
    // other CLI when a downstream reader goes away.
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--internal-token-delivery-lock-v1") {
        return if args.len() == 1 {
            pamwire::token_lock_helper()
        } else {
            std::process::ExitCode::FAILURE
        };
    }
    // A TYPED `--user` that names nobody is a typo, and every per-user command
    // answers a typo with the same empty state a real but unenrolled user
    // produces ("none enrolled", "not armed"), so the operator cannot tell which
    // they are looking at.
    //
    // A NOTE, deliberately, not a refusal. Refusing would contradict the machine
    // API's own rule that a consumer calls the command and reads the daemon's
    // error rather than pre-checking existence, and it would preempt the tested
    // `--user requires a username` guard when the value is itself a flag
    // (`--user --json`). The daemon keeps accepting unresolvable names for its
    // own reason: PAM authenticates as root and must survive an NSS outage. So
    // this only supplies the fact the operator is otherwise missing, on stderr,
    // where it cannot disturb a consumer parsing stdout.
    if let Some(named) = flag(&args, "--user").filter(|s| !s.is_empty()) {
        if !irlume_common::platform::user_exists(named) {
            eprintln!(
                "irlume: note: no user '{named}' on this system, so its per-user state reads as empty"
            );
        }
    }
    // Gate the developer tools unless IRLUME_DEV is set. Exception:
    // `selftest liveness` goes THROUGH the daemon (no direct camera open), so
    // it's a normal diagnostic the TUI's [l] uses, not a dev tool.
    let daemon_selftest = args.first().map(String::as_str) == Some("selftest")
        && args.get(1).map(String::as_str) == Some("liveness");
    if let Some(cmd) = args.first().map(String::as_str) {
        if DEV_CMDS.contains(&cmd) && !daemon_selftest && std::env::var_os("IRLUME_DEV").is_none() {
            eprintln!(
                "[irlume] '{cmd}' is a developer/benchmark tool (opens the camera directly, \
                       not for normal use). Set IRLUME_DEV=1 to enable it."
            );
            return std::process::ExitCode::from(2);
        }
    }
    // `--help` ANYWHERE means help, not "run the command and also I asked for
    // help". Matching it only in position 0 meant `irlume detect --help` printed
    // readiness, `irlume enroll --help` fired a capture, `irlume keyring arm
    // --help` prompted for the login password, and `irlume uninstall --help`
    // opened the uninstall confirmation. Asking a program what it does should
    // never be the thing that does it.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        if args.first().map(String::as_str) == Some("split") {
            return split::help();
        }
        return commands::help();
    }
    match (
        args.first().map(String::as_str),
        args.get(1).map(String::as_str),
    ) {
        (Some("selftest"), Some("align")) => selftest_align(&args),
        (Some("selftest"), Some("liveness")) => selftest_liveness(),
        (Some("capture"), _) => capture(&args),
        (Some("eval"), _) => eval(&args),
        (Some("irbench"), _) => irbench(&args),
        (Some("genuine"), _) => genuine(&args),
        (Some("calcapture"), _) => calcapture(&args),
        (Some("padcapture"), _) => pad::padcapture(&args),
        (Some("padreport"), _) => pad::padreport(&args),
        (Some("suncal"), _) => suncal::run(&args),
        (Some("liveness"), _) => liveness_probe(&args),
        (Some("enroll"), _) => enroll(&args),
        // Matched on PRESENCE of the subcommand, not on its position. Binding it
        // to args[1] meant a flag before it displaced it: `profiles --contract 9
        // list --json` fell through to the human handler and answered a machine
        // caller with prose on stderr and exit 2, while `doctor`/`status`/
        // `version` accepted the same flag anywhere. The contract documents no
        // ordering rule, so all five now behave the same way.
        (Some("profiles"), _)
            if args.iter().any(|a| a == "list") && args.iter().any(|a| a == "--json") =>
        {
            machine::profiles_list(&args)
        }
        (Some("profiles"), _) => profiles(profiles_sub(&args), &args),
        (Some("verify"), _) => verify(&args),
        (Some("enrolldev"), _) => enrolldev(&args),
        (Some("keyring"), _) => keyring(keyring_sub(&args), &args),
        (Some("recovery"), _) => recovery::run(recovery_sub(&args), &args),
        (Some("retry"), _) => retry::run(recovery_sub(&args), &args),
        (Some("bitwarden"), sub) => bitwarden::run(sub, &args),
        (Some("fingerprint"), _) => fingerprint::run(fingerprint_sub(&args), &args),
        (Some("login"), _)
            if args.iter().any(|a| a == "status") && args.iter().any(|a| a == "--json") =>
        {
            machine::login_status(&args)
        }
        // `login plan` exists only as a machine command: it is the read-only
        // phase of a login transaction, and the human equivalent is the dry run
        // `login enable` already prints.
        (Some("login"), _) if args.iter().any(|a| a == "plan") => machine::login_plan(&args),
        // The mutating half of a login transaction. Machine-only, like `plan`:
        // the human equivalent is `login enable --apply`.
        (Some("login"), _) if args.iter().any(|a| a == "apply") => machine::login_apply(&args),
        (Some("login"), _) if args.iter().any(|a| a == "verify") => machine::login_verify(&args),
        (Some("login"), _) if args.iter().any(|a| a == "rollback") => {
            machine::login_rollback(&args)
        }
        // `auth test` exists only as a machine command, so it routes here
        // whatever flags follow and answers a bad invocation with a JSON
        // usage-error rather than prose. Bare `auth` still falls through to the
        // help, which is the useful answer to a typo.
        (Some("auth"), Some("consent")) => consent::run(&args[2..]),
        (Some("auth"), Some("sensor")) => sensor_policy::run(&args[2..]),
        (Some("auth"), _) if args.iter().any(|a| a == "test") => machine::auth_test(&args),
        (Some("login"), sub) => pamwire::run(sub, &args),
        (Some("logs"), sub) => logs::run(sub, &args),
        // The machine capability survives the lane's removal (ADR-0015):
        // contract 1 keeps `models list --json` with every stage closed.
        // Presence-matched like `profiles list --json`: a contract flag
        // before the subcommand must not displace it.
        (Some("models"), _)
            if args.iter().any(|a| a == "list") && args.iter().any(|a| a == "--json") =>
        {
            machine::models_list(&args)
        }
        // Removed with the third-party/BYOM lane (ADR-0015): one clear line
        // for scripts and muscle memory, not silence.
        (Some("models"), _) => models::removed_notice(),
        (Some("biopolicy"), sub) => commands::biopolicy(sub, &args),
        (Some("ir-setup"), _) => ir_setup(&args),
        (Some("camera-tune"), _) => camera_tune(&args),
        (Some("camera-mode"), _) => camera_mode(&args),
        (Some("split"), _) => split::run(&args),
        (Some("set-cameras"), _) => set_cameras(&args),
        (Some("update"), _) => commands::update(&args),
        (Some("uninstall"), _) => uninstall::run(&args),
        (Some("doctor"), _) if args.iter().any(|arg| arg == "--json") => machine::doctor(&args),
        (Some("support-report"), _) if args.iter().any(|arg| arg == "--json") => {
            machine::support_report(&args)
        }
        (Some("camera"), Some("diagnostics")) if args.iter().any(|arg| arg == "--json") => {
            machine::camera_diagnostics(&args)
        }
        (Some("camera"), Some("census")) if args.iter().any(|arg| arg == "--json") => {
            machine::camera_census(&args)
        }
        (Some("camera"), Some("census")) => camera_census(&args),
        (Some("status"), _) if args.iter().any(|arg| arg == "--json") => machine::status(&args),
        (Some("version"), _) if args.iter().any(|arg| arg == "--json") => machine::version(&args),
        (Some("version"), _) | (Some("--version"), _) | (Some("-V"), _) => {
            println!("irlume {}", env!("CARGO_PKG_VERSION"));
            std::process::ExitCode::SUCCESS
        }
        (Some("doctor"), _) => doctor(&args),
        (Some("support-report"), _) => support_report::run(&args),
        (Some("trace"), _) => trace::run(&args),
        (Some("normprobe"), _) => normprobe(&args),
        (Some("status"), _) => commands::status(&args),
        (Some("detect"), _) => commands::detect(&args),
        (Some("identify"), _) => commands::identify(&args),
        (Some("diag"), _) => commands::diag(&args),
        (Some("deps"), _) => commands::deps(&args),
        (Some("reseal"), _) => commands::reseal(&args),
        (Some("selinux"), sub) => commands::selinux(sub, &args),
        (Some("setup"), _) => commands::setup(&args),
        (Some("help" | "--help" | "-h"), _) => commands::help(),
        (Some("tui"), _) => match tui::run(&args) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            // Usage errors print their own text (with the page list) and
            // use the CLI-wide exit code 2, not the generic TUI failure.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                std::process::ExitCode::from(2)
            }
            Err(e) => {
                eprintln!("tui: {e}");
                std::process::ExitCode::FAILURE
            }
        },
        (Some(cmd), _) => {
            eprintln!("irlume: unknown command '{cmd}'; run `irlume help`");
            std::process::ExitCode::from(2)
        }
        (None, _) => commands::help(),
    }
}

/// Parse `--scans N` for a command that captures biometrics. A state-changing
/// biometric command must not silently substitute a different operation: an
/// unparseable or zero count is a usage error, not "capture the default". This
/// lives in one place because `enroll` was written without the check that
/// `profiles add-scan` documents, so `enroll --scans abc` fired a real capture
/// at the default count. `Ok(None)` means the flag was absent.
fn scans_flag(args: &[String], tool: &str) -> Result<Option<usize>, std::process::ExitCode> {
    match flag(args, "--scans") {
        // PRESENT with nothing after it is an omission, not an absence. `flag`
        // answers None for both, so `enroll --scans` fired a real capture at the
        // default count while the user had asked for a number and lost it.
        None if flag_present(args, "--scans") => {
            eprintln!("[{tool}] --scans requires a count");
            Err(std::process::ExitCode::from(2))
        }
        None => Ok(None),
        Some(raw) => match raw.parse::<usize>() {
            Ok(n) if n > 0 => Ok(Some(n)),
            _ => {
                eprintln!("[{tool}] --scans must be a positive integer");
                Err(std::process::ExitCode::from(2))
            }
        },
    }
}

/// `irlume enroll --user U [--name "..."]`: enroll a NEW face profile (captures
/// the default number of scans) via the daemon, which owns the camera. Default
/// profile name is "Face Profile N".
fn enroll(args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let user = user_arg(args);
    let name = flag(args, "--name").map(String::from);
    let scans = match scans_flag(args, "enroll") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let choice = match enrollment_camera_choice_flag(args) {
        Ok(choice) => choice,
        Err(code) => return code,
    };
    let split_choice = match enrollment_split_camera_choice_flag(args) {
        Ok(choice) => choice,
        Err(code) => return code,
    };
    if choice.is_some() && split_choice.is_some() {
        eprintln!("[enroll] --camera-choice and --split-camera-choice cannot be combined");
        return std::process::ExitCode::from(2);
    }
    let reset = args.iter().any(|a| a == "--reset");
    let add_camera = args.iter().any(|a| a == "--add-camera");
    if add_camera {
        return enroll_add_camera(&user, name, scans, choice, split_choice);
    }
    if !is_root() {
        eprintln!("[enroll] approve the system authentication dialog before capture; each additional scan request needs approval");
    }
    if reset {
        eprintln!("[enroll] --reset: replacing '{user}'s enrollment after successful capture (preserves the template key and recovery setup)");
    }
    eprintln!(
        "[enroll] '{user}': capturing a new face profile; stay in frame, look at the camera…"
    );
    // The daemon probes an unmeasured ordinary camera pair before the first
    // scan (#340), and that probe holds the line above for up to a minute with
    // no output; without this notice the wait reads as a hang. A split pair
    // gets no probe or emitter preflight (ADR-0032).
    if split_choice.is_some() {
        eprintln!(
            "[enroll] capturing RGB then IR on the chosen split pair (no capture-mode \
             measurement)"
        );
    } else {
        eprintln!(
            "[enroll] if this camera pair has no measured capture mode yet, irlume measures \
             it first (one time, up to a minute; the IR emitter fires)"
        );
    }
    let request = if let Some(pair) = split_choice {
        Request::EnrollSplitOn {
            user: user.clone(),
            profile: name,
            scans,
            reset,
            pair,
        }
    } else {
        match choice {
            Some(pair) => Request::EnrollOn {
                user: user.clone(),
                profile: name,
                scans,
                reset,
                pair,
            },
            None => Request::Enroll {
                user: user.clone(),
                profile: name,
                scans,
                reset,
            },
        }
    };
    match daemon_request(&request) {
        Ok(Response::Enrolled {
            profile,
            created,
            added,
            total,
            ambient_lit,
            ..
        }) => {
            if let Some(n) = ambient_lit.filter(|&n| n > 0) {
                println!(
                    "[enroll] {n} scan(s) were lit mainly by the room, not provably by the \
                     IR emitter; dark-room login is unverified. Check it with the lights \
                     off: irlume identify"
                );
            }
            if created {
                println!("[enroll] enrolled '{profile}' with {total} scans");
            } else {
                println!(
                    "[enroll] this face is already enrolled as '{profile}'; added {added} scans \
                     to it ({total} total). A face can only own one profile; to strengthen \
                     recognition use `irlume profiles add-scan --profile '{profile}'`."
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("enroll failed: {}", enrollment_choice_error(&e, &request));
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("enroll: unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("enroll: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn enrollment_camera_choice_flag(
    args: &[String],
) -> Result<Option<Box<irlume_common::live_camera::EnrollmentCameraChoice>>, std::process::ExitCode>
{
    let count = args
        .iter()
        .filter(|arg| arg.as_str() == "--camera-choice" || arg.starts_with("--camera-choice="))
        .count();
    if count == 0 {
        return Ok(None);
    }
    let parse = || {
        if count != 1 {
            return Err("--camera-choice may be given only once".to_owned());
        }
        let text = flag(args, "--camera-choice")
            .ok_or_else(|| "--camera-choice needs a JSON choice".to_owned())?;
        serde_json::from_str::<irlume_common::live_camera::EnrollmentCameraChoice>(text)
            .map(Box::new)
            .map_err(|error| format!("invalid --camera-choice: {error}"))
    };
    match parse() {
        Ok(choice) => Ok(Some(choice)),
        Err(reason) => {
            eprintln!("[enroll] {reason}");
            Err(std::process::ExitCode::from(2))
        }
    }
}

/// The refusal text for the enrollment `request` that was sent. An older
/// daemon answers a choice request it cannot decode with `bad request`: that
/// means an upgrade, and the client never retries another operation.
fn enrollment_choice_error(error: &str, request: &irlume_common::Request) -> String {
    use irlume_common::Request;
    if error != "bad request" {
        return error.into();
    }
    match request {
        Request::EnrollSplitOn { .. } | Request::AddSplitCameraGroupOn { .. } => {
            "split enrollment needs a newer irlumed; restart it after the upgrade (no fallback attempted)".into()
        }
        Request::EnrollOn { .. } | Request::AddCameraGroupOn { .. } => {
            "operation-scoped camera choice needs a newer irlumed; restart it after the upgrade (no fallback attempted)".into()
        }
        _ => error.into(),
    }
}

/// `--split-camera-choice JSON`: a split enrollment choice built from
/// `irlume split list` (side guards plus the opaque authorization proof).
/// Malformed choices are usage errors before any request; decoding also
/// validates the choice.
fn enrollment_split_camera_choice_flag(
    args: &[String],
) -> Result<
    Option<Box<irlume_common::split_wire::SplitEnrollmentCameraChoice>>,
    std::process::ExitCode,
> {
    let count = args
        .iter()
        .filter(|arg| {
            arg.as_str() == "--split-camera-choice" || arg.starts_with("--split-camera-choice=")
        })
        .count();
    if count == 0 {
        return Ok(None);
    }
    let parse = || {
        if count != 1 {
            return Err("--split-camera-choice may be given only once".to_owned());
        }
        // An empty value or a following flag is a missing choice, as in `split`.
        let text = flag(args, "--split-camera-choice")
            .filter(|text| !text.is_empty() && !text.starts_with("--"))
            .ok_or_else(|| "--split-camera-choice needs a JSON choice".to_owned())?;
        // A fixed reason for an unparseable choice, as `split add` gives, with
        // the JSON position when the decoder has one.
        serde_json::from_str(text).map_err(|error: serde_json::Error| {
            let reason = "invalid --split-camera-choice: not a valid split choice";
            match (error.line(), error.column()) {
                (0, _) => reason.to_owned(),
                (line, column) => format!("{reason} (JSON line {line}, column {column})"),
            }
        })
    };
    match parse() {
        Ok(choice) => Ok(Some(choice)),
        Err(reason) => {
            eprintln!("[enroll] {reason}");
            Err(std::process::ExitCode::from(2))
        }
    }
}

/// `irlume enroll --add-camera [--name P] [--camera-choice JSON |
/// --split-camera-choice JSON]`: enroll the CURRENT camera pair, or the pair
/// a choice flag names for this operation only, as a secondary camera group
/// (ADR-0024 §4). Attended capture on that pair; the daemon derives the
/// group from the pair's USB identities and authorizes the addition through
/// the system authentication dialog - the new camera never authorizes its
/// own addition. An unmeasured ordinary pair is measured first; a split pair
/// (ADR-0032) never is.
fn enroll_add_camera(
    user: &str,
    profile: Option<String>,
    scans: Option<usize>,
    choice: Option<Box<irlume_common::live_camera::EnrollmentCameraChoice>>,
    split_choice: Option<Box<irlume_common::split_wire::SplitEnrollmentCameraChoice>>,
) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let target = if choice.is_some() || split_choice.is_some() {
        "the chosen pair"
    } else {
        "the CURRENT camera pair"
    };
    if !is_root() {
        eprintln!("[add-camera] approve the system authentication dialog before capture");
    }
    eprintln!(
        "[add-camera] '{user}': capturing this face on {target}; stay in \
         frame, look at the camera…"
    );
    if split_choice.is_some() {
        eprintln!(
            "[add-camera] capturing RGB then IR on the chosen split pair (no capture-mode \
             measurement)"
        );
    } else {
        eprintln!(
            "[add-camera] an unmeasured pair is measured first (one time, up to a minute; \
             the IR emitter fires)"
        );
    }
    let request = if let Some(pair) = split_choice {
        Request::AddSplitCameraGroupOn {
            user: user.to_owned(),
            profile,
            scans,
            pair,
        }
    } else {
        match choice {
            Some(pair) => Request::AddCameraGroupOn {
                user: user.to_owned(),
                profile,
                scans,
                pair,
            },
            None => Request::AddCameraGroup {
                user: user.to_owned(),
                profile,
                scans,
            },
        }
    };
    match daemon_request(&request) {
        Ok(Response::Ok(message)) => {
            println!("[add-camera] {message}");
            println!(
                "[add-camera] manage groups with `irlume profiles` (listing shows every \
                 enrolled camera)"
            );
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!(
                "add-camera failed: {}",
                enrollment_choice_error(&e, &request)
            );
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("add-camera: unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("add-camera: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Camera-group rows for the profiles listing (ADR-0024 Phase 2): one line
/// per secondary group with its state flags, then per-profile counts. A
/// store that exists but cannot be summarized is reported, never silent.
fn print_camera_groups(groups: &[irlume_common::CameraGroupSummary], store_error: Option<&str>) {
    if let Some(error) = store_error {
        println!("[profiles] camera groups unavailable: {error}");
        return;
    }
    if groups.is_empty() {
        return;
    }
    println!("[profiles] enrolled cameras:");
    for group in groups {
        let mut state = Vec::new();
        if group.selected {
            state.push("selected");
        }
        if group.connected {
            state.push("connected");
        } else {
            state.push("disconnected");
        }
        if group.stale {
            state.push("STALE (primary changed; re-add the camera)");
        }
        println!("  {} [{}]", group.id, state.join(", "));
        for row in &group.profiles {
            let calib = if row.calibrated {
                "calibrated"
            } else if row.calibration_fittable {
                "uncalibrated"
            } else {
                "no IR calibration"
            };
            let target = if row.capture_target_met {
                String::new()
            } else {
                format!(
                    " (below the {}-scan target)",
                    irlume_core::storage::DEFAULT_ENROLL_SCANS
                )
            };
            println!(
                "      {} · {} scans{target} · {calib}",
                row.profile, row.scans
            );
        }
    }
}

/// Wrap a value so a shell reads it as ONE argument, whatever it contains.
///
/// Profile names are user text: the rename path accepts any string, root can
/// list another user's profiles, and this crate prints commands for a person
/// to copy. A name carrying a quote would otherwise close the quoting and
/// append its own command to something an administrator runs. Single quotes
/// are closed, escaped, and reopened, the only sequence a POSIX shell accepts
/// inside single quotes.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// The flags the profiles family reads as `--flag value` pairs. Kept beside
/// the scanner that steps over them, and pinned against the parsers by a
/// source-scan test, so a new valued flag cannot silently desync the scan.
const PROFILES_VALUED: [&str; 6] = [
    "--user",
    "--profile",
    "--scans",
    "--name",
    "--scan",
    "--group",
];

/// Scan an argument list for its subcommand: the first token that is neither
/// a flag nor the value of a `--flag value` pair, starting after the command
/// word. `--flag=value` spellings carry their own value and need no step.
///
/// This is the shared core behind the flags-first grammar the usage lines
/// document (`irlume <command> [--user U] <subcommand>`, #637 for profiles,
/// the same rule since extended to every per-user subcommand command); the
/// dispatcher used to bind each subcommand to position 1, so a leading flag
/// displaced it and a well-formed command answered usage.
fn subcommand_after_valued<'a>(args: &'a [String], valued: &[&str]) -> Option<&'a str> {
    subcommand_index_after_valued(args, valued).map(|(sub, _)| sub)
}

/// The scanner's index form: forget-model reads a POSITIONAL after the
/// subcommand, so it needs where the subcommand landed, not just what it is.
fn subcommand_index_after_valued<'a>(
    args: &'a [String],
    valued: &[&str],
) -> Option<(&'a str, usize)> {
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if !a.starts_with('-') {
            return Some((a, i));
        }
        if valued.contains(&a) {
            i += 1;
        }
        i += 1;
    }
    None
}

/// The `profiles` subcommand, wherever it sits among the flags.
///
/// The usage line documents `irlume profiles [--user U] <subcommand>`, and the
/// machine path above already matches on presence rather than position for the
/// same reason. Reading `args[1]` made a leading flag the subcommand, so the
/// documented order answered usage on a well-formed command: `profiles --user
/// tester list` looked for a subcommand named `--user`.
fn profiles_sub(args: &[String]) -> Option<&str> {
    subcommand_after_valued(args, &PROFILES_VALUED)
}

/// The same flags-first grammar for the other per-user subcommand commands;
/// each takes exactly the global `--user` as its only valued flag.
fn keyring_sub(args: &[String]) -> Option<&str> {
    subcommand_after_valued(args, &["--user"])
}

fn recovery_sub(args: &[String]) -> Option<&str> {
    subcommand_after_valued(args, &["--user"])
}

fn fingerprint_sub(args: &[String]) -> Option<&str> {
    subcommand_after_valued(args, &["--user"])
}

/// The first bare token after the subcommand (forget-model's model name): the
/// one positional in the profiles family, which used to be read at a fixed
/// index that a leading flag displaces.
fn positional_after_subcommand(args: &[String]) -> Option<&str> {
    let (_, sub_at) = subcommand_index_after_valued(args, &PROFILES_VALUED)?;
    args[sub_at + 1..]
        .iter()
        .map(String::as_str)
        .find(|a| !a.starts_with('-'))
}

/// `irlume profiles [list|add-scan|rename|delete|eyes-open] ...`: manage the up-
/// to-3 face profiles and their scans via the daemon.
fn profiles(sub: Option<&str>, args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    // A supplied `--user` must carry a real username. `user_arg` falls back
    // to SUDO_USER/$USER when the flag is ABSENT, which is right for the bare
    // commands, but a dangling `--user` inheriting that fallback would point
    // a destructive subcommand (forget-model, delete) at the invoking user's
    // own enrollment. Checked here, not in `user_arg`: the fallback semantics
    // of an absent flag belong to every caller, this omission does not.
    if flag_present(args, "--user")
        && !matches!(flag(args, "--user"), Some(u) if !u.is_empty() && !u.starts_with("--"))
    {
        eprintln!("[profiles] --user requires a username");
        return std::process::ExitCode::from(2);
    }
    let user = user_arg(args);
    let quoted_user = shell_single_quote(&user);
    let req = match sub {
        None | Some("list") => Request::ListProfiles {
            user,
            structured_errors: false,
            handles: false,
        },
        Some("add-scan") => match flag(args, "--profile") {
            Some(p) => {
                let scans = match scans_flag(args, "profiles") {
                    Ok(s) => s,
                    Err(code) => return code,
                };
                if !is_root() {
                    eprintln!("[profiles] approve the system authentication dialog before capture");
                }
                match scans {
                    Some(n) if n > 1 => eprintln!(
                        "[profiles] adding {n} scans to '{p}'; stay in frame, vary your pose slightly…"
                    ),
                    _ => eprintln!("[profiles] adding a scan to '{p}'; stay in frame…"),
                }
                eprintln!(
                    "[profiles] scans are recorded for the recognizer the daemon has loaded; \
                     this is also how a profile gains templates for a second model without \
                     re-enrolling as a new person."
                );
                Request::AddScan {
                    user,
                    profile: p.into(),
                    scans,
                    // Structured reply so the ambient-lit count reaches the
                    // completion note (#312); an older daemon ignores the
                    // flag and answers the legacy Ok prose, handled below.
                    report_enrollment: true,
                }
            }
            None => return usage_profiles(),
        },
        Some("forget-model") => {
            // Positional: `irlume profiles [flags] forget-model <model>`.
            // Read AFTER the scanned subcommand, not at a fixed index: the
            // flags-first grammar puts the flag values where args[2] used to
            // be. A flag must not be read as the model name when the
            // positional is missing.
            match positional_after_subcommand(args) {
                Some(name) => match crate::models::recognizer_space_for(name) {
                    Ok(space) => Request::ForgetRecognizer { user, space },
                    Err(e) => {
                        eprintln!("[profiles] {e}");
                        return std::process::ExitCode::from(2);
                    }
                },
                None => return usage_profiles(),
            }
        }
        Some("remove-camera") => {
            // `irlume profiles remove-camera --group <id>`: revoke one
            // secondary camera group (ADR-0024 §4.2). A dangling --group
            // must not fall through to usage after the grammar scan.
            if args.iter().any(|a| a == "--group") && flag(args, "--group").is_none() {
                eprintln!("[profiles] --group requires a camera group id (see `irlume profiles`)");
                return std::process::ExitCode::from(2);
            }
            match flag(args, "--group") {
                Some(group) => {
                    println!("[profiles] Removing an enrolled camera requires OS approval for a non-root user.");
                    Request::RemoveCameraGroup {
                        user,
                        group: group.into(),
                    }
                }
                None => return usage_profiles(),
            }
        }
        Some("delete") => {
            // A `--scan` with no value must not widen the deletion from one
            // scan to the whole profile. `flag` cannot tell "absent" from
            // "present with nothing after it", and the arms below read absence
            // as "the user meant the profile", so `profiles delete --profile P
            // --scan` put `DeleteProfile` on the wire from a command whose
            // visible intent was a single scan. Same shape as the dangling
            // `--user` this file resolves above.
            if args.iter().any(|a| a == "--scan") && flag(args, "--scan").is_none() {
                eprintln!("[profiles] --scan requires a scan name");
                return std::process::ExitCode::from(2);
            }
            match (flag(args, "--profile"), flag(args, "--scan")) {
                (Some(p), Some(s)) => Request::DeleteScan {
                    user,
                    profile: p.into(),
                    scan: s.into(),
                },
                (Some(p), None) => Request::DeleteProfile {
                    user,
                    profile: p.into(),
                },
                _ => return usage_profiles(),
            }
        }
        Some("rename") => match (
            flag(args, "--profile"),
            flag(args, "--scan"),
            flag(args, "--name"),
        ) {
            (Some(p), Some(s), Some(n)) => Request::RenameScan {
                user,
                profile: p.into(),
                scan: s.into(),
                new_name: n.into(),
            },
            (Some(p), None, Some(n)) => Request::RenameProfile {
                user,
                profile: p.into(),
                new_name: n.into(),
            },
            _ => return usage_profiles(),
        },
        Some("eyes-open") => match toggle_value(args, "eyes-open") {
            Some(false) => Request::SetRequireEyesOpen { user, on: false },
            Some(true) => {
                eprintln!(
                    "[profiles] eyes-open can only be turned off; this legacy gate cannot be enabled"
                );
                return std::process::ExitCode::from(2);
            }
            None => return usage_profiles(),
        },
        _ => return usage_profiles(),
    };
    if matches!(
        req,
        Request::DeleteProfile { .. } | Request::ForgetRecognizer { .. }
    ) {
        println!("[profiles] Removing a profile or a recognizer's face data requires OS approval for a non-root user.");
        println!("[profiles] If no profiles remain, the added cameras' scans, the template key and the recovery passphrase are also erased.");
    }
    match daemon_request(&req) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            camera_groups,
            camera_store_error,
            ..
        }) => {
            if require_eyes_open {
                println!(
                    "[profiles] legacy policy blocks authentication; run: sudo irlume profiles eyes-open off --user {quoted_user}"
                );
            }
            if profiles.is_empty() {
                println!("[profiles] none enrolled");
            } else {
                for p in &profiles {
                    println!("  {} ({} scans)", p.name, p.scans.len());
                    // Per-recognizer breakdown when a profile holds more than
                    // one model's templates, or when the loaded recognizer is
                    // not the one those templates belong to. Only the loaded
                    // recognizer's scans can match, so a bare total would let
                    // a profile look usable when none of it is (#288).
                    let live = p.live_recognizer.as_deref();
                    let live_count = live
                        .and_then(|l| p.scans_by_recognizer.get(l).copied())
                        .unwrap_or(0);
                    let show_breakdown = p.scans_by_recognizer.len() > 1
                        || (live.is_some() && live_count != p.scans.len());
                    if show_breakdown {
                        for (space, count) in &p.scans_by_recognizer {
                            let marker = if live == Some(space.as_str()) {
                                "live"
                            } else {
                                "not loaded"
                            };
                            println!("      {count} scans · recognizer {space} ({marker})");
                        }
                        if live_count == 0 {
                            println!(
                                "      none of these match the loaded recognizer; add scans \
                                 with `irlume profiles add-scan --profile {} --user {quoted_user}`",
                                shell_single_quote(&p.name)
                            );
                        }
                    }
                    for line in profile_ir::lines(p) {
                        println!("      {line}");
                    }
                    if profile_ir::needs_capture(p) {
                        println!("      Add IR scans with an IR camera: irlume profiles add-scan --profile {} --user {quoted_user}", shell_single_quote(&p.name));
                    }
                    for s in &p.scans {
                        println!("      - {s}");
                    }
                }
            }
            print_camera_groups(&camera_groups, camera_store_error.as_deref());
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Enrolled {
            added,
            total,
            added_scans,
            ambient_lit,
            ..
        }) => {
            println!(
                "[profiles] added {added} scan(s) ({total} for the loaded recognizer): {}",
                added_scans.join(", ")
            );
            if let Some(n) = ambient_lit.filter(|&n| n > 0) {
                println!(
                    "[profiles] {n} scan(s) were lit mainly by the room, not provably by \
                     the IR emitter; dark-room login is unverified. Check it with the \
                     lights off: irlume identify"
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Ok(msg)) => {
            println!("[profiles] {msg}");
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[profiles] {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[profiles] unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[profiles] {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume ir-setup [--dry-run]`: enable the IR emitter via the daemon, using
/// only controls the camera's USB descriptor documents. `--dry-run` lists the
/// camera's extension units and sends it nothing.
/// `irlume set-cameras <rgb> <ir>`: persist the active RGB+IR pair. Root only
/// (the daemon writes /etc/irlume/cameras.conf); the TUI camera picker runs this
/// via sudo, and headless setups call it directly.
fn set_cameras(args: &[String]) -> std::process::ExitCode {
    let request = match set_cameras_request(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{reason}\nusage: irlume set-cameras <rgb-node> <ir-node> [--expected-camera JSON]   (root)");
            return std::process::ExitCode::from(2);
        }
    };
    // A guarded request is never retried as the legacy unguarded operation.
    // Older daemons must refuse rather than silently ignore camera continuity.
    report_ok_response("set-cameras", daemon_request(&request))
}

fn set_cameras_request(args: &[String]) -> Result<irlume_common::Request, &'static str> {
    use irlume_common::Request;
    let (Some(rgb), Some(ir)) = (args.get(1), args.get(2)) else {
        return Err("both camera paths are required");
    };
    match args.len() {
        3 => Ok(Request::SetCameras {
            rgb: rgb.clone(),
            ir: ir.clone(),
        }),
        5 if args[3] == "--expected-camera" => {
            let expected =
                serde_json::from_str::<irlume_common::live_camera::CameraSelection>(&args[4])
                    .map_err(|_| {
                        "invalid expected camera identity; select the camera again in the TUI"
                    })?;
            Ok(Request::SetCamerasIfCurrent {
                rgb: rgb.clone(),
                ir: ir.clone(),
                expected,
            })
        }
        _ => Err("unexpected or incomplete camera-selection arguments"),
    }
}

/// Report the daemon's answer to a request whose success case is
/// `Response::Ok(msg)`: the message on stdout tagged `[tag]`, everything else
/// on stderr with a FAILURE exit code.
fn report_ok_response(
    tag: &str,
    res: Result<irlume_common::Response, String>,
) -> std::process::ExitCode {
    use irlume_common::Response;
    match res {
        Ok(Response::Ok(msg)) => {
            println!("[{tag}] {msg}");
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[{tag}] {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[{tag}] unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[{tag}] {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn ir_setup(args: &[String]) -> std::process::ExitCode {
    use irlume_common::Request;
    let dry = args.iter().any(|a| a == "--dry-run");
    if !dry {
        eprintln!(
            "[ir-setup] this writes to your camera. It uses only the controls your camera's USB\n\
             descriptor documents, and the values it reports for them. A few seconds…"
        );
    }
    report_ok_response(
        "ir-setup",
        daemon_request(&Request::SetupIrEmitter { dry_run: dry }),
    )
}

/// `irlume camera-tune`: measure whether this camera can stream RGB and IR at
/// once without losing signal, and persist the answer. Some Hello modules starve
/// their own RGB interface when both stream (measured: the NexiGo HelloCam N930W
/// keeps 56% of its RGB brightness), which dims the frame recognition runs on;
/// others are unaffected and should keep the faster concurrent path. Only a
/// measurement on the camera in front of the user can tell the two apart.
/// One human-readable drift line per compared arm+role between a reference
/// measurement artifact and a fresh one (ADR-0023 `--verify-record`).
/// Rates are exact rationals in the records; the report renders them as fps
/// for humans while every comparison stays qualitative (faster/slower/same
/// by cross-multiplication, never float equality).
fn measurement_drift_report(
    reference: &[irlume_camera::measurement::MeasurementRecord],
    fresh: &[irlume_camera::measurement::MeasurementRecord],
) -> Vec<String> {
    let fps = |r: irlume_camera::measurement::RateRational| {
        r.deltas as f64 * 1_000_000.0 / r.span_us as f64
    };
    let mut lines = Vec::new();
    for reference_record in reference {
        let arm = &reference_record.method;
        let Some(fresh_record) = fresh.iter().find(|r| r.method == *arm) else {
            lines.push(format!("{arm}: no fresh {arm} arm ran; cannot compare"));
            continue;
        };
        for (role, reference_evidence) in &reference_record.rates {
            let Some((_, fresh_evidence)) = fresh_record.rates.iter().find(|(r, _)| r == role)
            else {
                lines.push(format!("{arm} {role:?}: no fresh rounds; cannot compare"));
                continue;
            };
            let direction = if fresh_evidence.rate_p50.lt(&reference_evidence.rate_p50) {
                "slower"
            } else if reference_evidence.rate_p50.lt(&fresh_evidence.rate_p50) {
                "faster"
            } else {
                "same"
            };
            lines.push(format!(
                "{arm} {role:?}: p50 {:.1} -> {:.1} fps ({direction}); max gap {} -> {} us; rounds {} -> {}; accepted {} -> {}",
                fps(reference_evidence.rate_p50),
                fps(fresh_evidence.rate_p50),
                reference_evidence.max_inter_frame_gap_us.unwrap_or(0),
                fresh_evidence.max_inter_frame_gap_us.unwrap_or(0),
                reference_evidence.rounds_completed,
                fresh_evidence.rounds_completed,
                reference_record.acceptance.accepted,
                fresh_record.acceptance.accepted,
            ));
        }
    }
    for fresh_record in fresh {
        if !reference.iter().any(|r| r.method == fresh_record.method) {
            lines.push(format!(
                "{}: fresh arm with no reference counterpart",
                fresh_record.method
            ));
        }
    }
    lines
}

fn camera_tune(args: &[String]) -> std::process::ExitCode {
    use irlume_common::Request;
    // Same rule as `enroll --scans`: this command fires the IR emitter for up to
    // a minute, so an unparseable count is a usage error rather than a silent
    // substitution of the default round count.
    let mut rounds = match flag(args, "--rounds") {
        None if flag_present(args, "--rounds") => {
            eprintln!("[camera-tune] --rounds requires a positive integer");
            return std::process::ExitCode::from(2);
        }
        None => None,
        Some(raw) => match raw.parse::<usize>() {
            Ok(n) if n > 0 => Some(n),
            _ => {
                eprintln!("[camera-tune] --rounds must be a positive integer");
                return std::process::ExitCode::from(2);
            }
        },
    };
    // ADR-0023 verification: re-measure and compare against a reference
    // artifact. Runs the same tune with a temporary evidence artifact, then
    // prints per-arm drift. Reference rounds win so both runs judge the
    // same workload.
    let verify_record_path = match flag(args, "--verify-record") {
        None if flag_present(args, "--verify-record") => {
            eprintln!("[camera-tune] --verify-record requires a file path");
            return std::process::ExitCode::from(2);
        }
        None => None,
        Some(raw) if raw.trim().is_empty() => {
            eprintln!("[camera-tune] --verify-record requires a file path");
            return std::process::ExitCode::from(2);
        }
        Some(raw) => Some(raw.to_string()),
    };
    if let Some(reference_path) = &verify_record_path {
        if let Ok(text) = std::fs::read_to_string(reference_path) {
            if let Ok(records) =
                serde_json::from_str::<Vec<irlume_camera::measurement::MeasurementRecord>>(&text)
            {
                if let Some((_, first)) = records.iter().find_map(|r| {
                    r.rates.first().map(|(role, evidence)| {
                        let _ = role;
                        (r, evidence)
                    })
                }) {
                    rounds = Some(first.rounds_completed.max(1) as usize);
                }
            }
        }
    }
    // ADR-0023 evidence emission: asks the daemon to write the completed
    // arms' measurement records as a JSON artifact. An unparseable or
    // missing path is a usage error, same discipline as --rounds.
    let emit_record_path = match flag(args, "--emit-record") {
        None if flag_present(args, "--emit-record") => {
            eprintln!("[camera-tune] --emit-record requires a file path");
            return std::process::ExitCode::from(2);
        }
        None => None,
        Some(raw) if raw.trim().is_empty() => {
            eprintln!("[camera-tune] --emit-record requires a file path");
            return std::process::ExitCode::from(2);
        }
        Some(raw) => Some(raw.to_string()),
    };
    eprintln!(
        "[camera-tune] measuring this camera under load; it fires the IR emitter \
         for up to a minute…"
    );
    let fresh_path = verify_record_path.as_ref().map(|_| {
        std::env::temp_dir().join(format!("irlume-verify-record-{}.json", std::process::id()))
    });
    let result = report_ok_response(
        "camera-tune",
        daemon_request(&Request::TuneCaptureMode {
            rounds,
            emit_record_path: fresh_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .or(emit_record_path),
        }),
    );
    if let Some(path) = flag(args, "--emit-record") {
        eprintln!(
            "[camera-tune] {path} is MEASUREMENT EVIDENCE, not a camera profile; \
             attach it to the PR that contributes this camera's tuning"
        );
    }
    if let (Some(reference_path), Some(fresh)) = (verify_record_path.as_ref(), fresh_path.as_ref())
    {
        let reference_text = match std::fs::read_to_string(reference_path) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("[camera-tune] cannot read {reference_path}: {error}");
                return result;
            }
        };
        let fresh_text = match std::fs::read_to_string(fresh) {
            Ok(text) => text,
            Err(error) => {
                eprintln!(
                    "[camera-tune] no fresh artifact at {}: {error}",
                    fresh.display()
                );
                return result;
            }
        };
        let _ = std::fs::remove_file(fresh);
        match (
            serde_json::from_str::<Vec<irlume_camera::measurement::MeasurementRecord>>(
                &reference_text,
            ),
            serde_json::from_str::<Vec<irlume_camera::measurement::MeasurementRecord>>(&fresh_text),
        ) {
            (Ok(reference), Ok(fresh_records)) => {
                eprintln!("[camera-tune] drift vs {reference_path}:");
                for line in measurement_drift_report(&reference, &fresh_records) {
                    eprintln!("[camera-tune]   {line}");
                }
            }
            (Err(error), _) | (_, Err(error)) => {
                eprintln!("[camera-tune] artifact parse failed: {error}");
            }
        }
    }
    result
}

/// `irlume camera census`: every video-adjacent device on the machine,
/// classified once, each line printing the evidence its classification
/// keyed on (#575). The one-shot answer to "broken, an unusable class, or
/// configuration"; `--json` is the machine-readable twin.
fn camera_census(_args: &[String]) -> std::process::ExitCode {
    let scan = irlume_camera::scan_nodes();
    if let Some(why) = &scan.listing_error {
        eprintln!("[camera-census] ⚠ {why}; whether this machine has camera nodes is unknown");
    }
    for entry in irlume_camera::census::census_from(&scan) {
        println!("{}", irlume_camera::census::render_line(&entry));
    }
    println!("{}", sensor_policy::PAIRED_SUPPORT_NOTE);
    std::process::ExitCode::SUCCESS
}

/// `irlume camera-mode`: report which capture strategy the pair irlume would
/// select uses, and where that verdict came from (a measurement, an auto-switch,
/// or the unmeasured default). Unlike `doctor`, this opens the camera to
/// auto-select the pair, so it answers on an install that never ran `set-cameras`.
fn camera_mode(_args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    match daemon_request(&Request::CaptureModeStatus) {
        Ok(Response::CaptureModeStatus {
            mode,
            source,
            rgb,
            ir,
            runtime_context,
            qualification_state,
            qualification_reason,
            qualification_context,
            runtime_degradation,
        }) => {
            println!(
                "camera pair: rgb={rgb} ir={}",
                ir.as_deref().unwrap_or("unavailable")
            );
            println!("capture mode: {mode} (daemon source: {source})");
            println!("qualification: {qualification_state}");
            if let Some(reason) = qualification_reason {
                println!("qualification reason: {reason}");
            }
            if let Some(reason) = runtime_degradation {
                println!("runtime degradation: {reason}");
            }
            if let Some(context) = runtime_context {
                println!("runtime context: {context}");
            }
            if let Some(context) = qualification_context {
                println!("exact qualification context: {context}");
            }
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(error)) | Err(error) => {
            eprintln!("[camera-mode] {error}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[camera-mode] unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn usage_profiles() -> std::process::ExitCode {
    eprintln!(
        "usage: irlume profiles [--user U] <subcommand>\n  \
        (no sub) | list                         list profiles + scans + cameras\n  \
        add-scan --profile P [--scans N]         add scans to P (improve recognition, or\n  \
                                                add templates for a second model)\n  \
        remove-camera --group ID                remove an enrolled camera group\n  \
                                                (add one with: irlume enroll --add-camera)\n  \
        rename --profile P [--scan S] --name N  rename a profile or a scan\n  \
        delete --profile P [--scan S]           delete a profile or a scan\n  \
        forget-model <model>                    remove one recognizer's scans from every\n  \
                                                profile (shipped | embed:<sha256>)\n  \
        eyes-open off                           one-release migration: clear the retired gate\n  \
        \x20                                       (it cannot be turned on; see issue #386)"
    );
    std::process::ExitCode::from(2)
}

/// `irlume verify --user U`: full auth via the engine: liveness gate then match
/// (RGB recognition in light, IR recognition in the dark).
fn verify(args: &[String]) -> std::process::ExitCode {
    let (Some(det), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume verify --user U --det <yunet.onnx> --model <glintr100.onnx> [--rgb ..] [--ir ..]");
        return std::process::ExitCode::from(2);
    };
    let user = user_arg(args);
    match engine(det, model, args).and_then(|mut e| e.authenticate(&user, None)) {
        Ok(o) => {
            println!(
                "[verify] live={} score {:.3} -> {} ({})",
                o.live,
                o.score,
                if o.granted {
                    "GRANT \u{2705}"
                } else {
                    "DENY \u{274c}"
                },
                o.reason
            );
            if o.granted {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("verify error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Why a CHANGE on the gnome-keyring control socket did not succeed, split by
/// what that proves about the login keyring.
#[derive(Debug)]
enum RekeyError {
    /// gnome-keyring answered DENIED and did not change the keyring: the
    /// current secret was wrong, or the daemon is one `pam_gnome_keyring`
    /// started with `--login` that nothing has initialized yet, which refuses
    /// every request.
    Denied(String),
    /// The keyring did not change: the request was never sent (no session
    /// runtime directory, nothing listening on the control socket, or a
    /// gnome-keyring running as another uid, which ignores the request) or
    /// gnome-keyring answered FAILED.
    Unchanged(String),
    /// The request may have reached gnome-keyring and no usable answer came
    /// back: a failed write or read, a malformed answer or an unknown code.
    /// gnome-keyring applies a CHANGE before it writes the answer
    /// (`control_process` in gkd-control-server.c), so the keyring may have
    /// changed.
    Unconfirmed(String),
}

impl std::fmt::Display for RekeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RekeyError::Denied(e) | RekeyError::Unchanged(e) | RekeyError::Unconfirmed(e) => {
                f.write_str(e)
            }
        }
    }
}

/// This process's effective uid, the one gnome-keyring compares against its
/// own before it reads a control request. A test poses as another uid
/// through `tests::POSE_AS_UID` on its own thread.
fn control_client_uid() -> libc::uid_t {
    #[cfg(test)]
    if let Some(uid) = tests::POSE_AS_UID.with(std::cell::Cell::get) {
        return uid;
    }
    // SAFETY: takes no arguments, reads only this process's own credentials,
    // and is specified as always succeeding.
    unsafe { libc::geteuid() }
}

/// One CHANGE against the caller's own gnome-keyring control socket.
/// gnome-keyring serves only its own uid, so this works only for the invoking
/// user's own keyring, in their own session. Against a gnome-keyring of
/// another uid it sends nothing and fails as unchanged, so arming another
/// user's token rolls back rather than half-arming.
fn rekey_login_keyring(current: &[u8], new: &[u8]) -> Result<(), RekeyError> {
    use irlume_common::gkr_wire::{self, ControlResult, Op};
    let rt = std::env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        RekeyError::Unchanged("no XDG_RUNTIME_DIR; run this inside the user's own session".into())
    })?;
    let sock = gkr_wire::control_socket_path(std::path::Path::new(&rt));
    let mut stream = std::os::unix::net::UnixStream::connect(&sock).map_err(|e| {
        RekeyError::Unchanged(format!(
            "connect {}: {e} (is gnome-keyring-daemon running in this session?)",
            sock.display()
        ))
    })?;
    // gnome-keyring closes a connection from another uid after the
    // credentials byte, applying nothing and answering nothing
    // (`control_input` in gkd-control-server.c). Check before sending, so
    // that case is a known no-op and the secrets stay in this process.
    let me = control_client_uid();
    match gkr_session::peer_credentials(&stream).map(|peer| peer.uid) {
        Ok(owner) if owner == me => {}
        Ok(owner) => {
            return Err(RekeyError::Unchanged(format!(
                "gnome-keyring on {} runs as uid {owner} and ignores requests from uid {me}",
                sock.display()
            )))
        }
        Err(e) => {
            return Err(RekeyError::Unchanged(format!(
                "read the peer credentials of {}: {e}",
                sock.display()
            )))
        }
    }
    match gkr_wire::call(&mut stream, Op::Change, &[current, new]) {
        Ok(ControlResult::Ok) => Ok(()),
        // DENIED: gnome-keyring did not change the keyring (a wrong current
        // secret, the change failed, or nothing has initialized a `--login`
        // daemon yet). FAILED: it could not read the request
        // (`control_change_login` in gkd-control-server.c).
        Ok(ControlResult::Denied) => Err(RekeyError::Denied(format!(
            "keyring re-key: {}",
            ControlResult::Denied.describe()
        ))),
        Ok(ControlResult::Failed) => Err(RekeyError::Unchanged(format!(
            "keyring re-key: {}",
            ControlResult::Failed.describe()
        ))),
        // A code gnome-keyring never sends for a CHANGE.
        Ok(other) => Err(RekeyError::Unconfirmed(format!(
            "keyring re-key: {}",
            other.describe()
        ))),
        // A failed write or read, or a malformed answer.
        Err(e) => Err(RekeyError::Unconfirmed(e)),
    }
}

/// Prove `secret` is the login keyring's current credential: a CHANGE from it
/// to itself succeeds only then, changes nothing, and needs no prompt. The one
/// exception is a gnome-keyring with no login keyring, where it creates one
/// keyed to `secret` (`change_or_create_login` in gkd-login.c); irlumed
/// refuses a token arm for an account without one. This is the post-re-key
/// verification, so "armed" is never claimed on the strength of a re-key reply
/// alone.
fn verify_keyring_credential(secret: &[u8]) -> Result<(), RekeyError> {
    rekey_login_keyring(secret, secret)
}

/// How `keyring forget` put the login keyring back on the password.
#[derive(Debug, PartialEq, Eq)]
enum RekeyedBack {
    /// The keyring was keyed to the token and is now keyed to the password.
    Rekeyed,
    /// The change back was refused or unanswered, but the keyring opens with
    /// the password: the token is not its credential.
    AlreadyPassword,
}

/// Re-key the login keyring from `token` back to `password`, and prove the
/// password is its credential. When the change back is refused or goes
/// unanswered, the keyring may never have taken the token (an arm whose
/// re-key did not land keeps the token, see [`finish_token_arm`]); a password
/// that opens the keyring then still clears the way to erase the envelope.
fn rekey_back(token: &[u8], password: &[u8]) -> Result<RekeyedBack, RekeyError> {
    match rekey_login_keyring(token, password) {
        Ok(()) => verify_keyring_credential(password).map(|()| RekeyedBack::Rekeyed),
        Err(refused) => verify_keyring_credential(password)
            .map(|()| RekeyedBack::AlreadyPassword)
            .map_err(|_| refused),
    }
}

/// [`rekey_back`] for `keyring forget`, which may run before anything in the
/// session has initialized a gnome-keyring the login screen started with
/// `--login` (Fedora 43 and 44 start it that way). Such a daemon answers
/// DENIED to every CHANGE. When the change back is DENIED, `initialize` checks
/// for exactly that daemon and, unless another Secret Service provider runs
/// the session, has the user bus start `org.gnome.keyring` once, as a GNOME
/// session's first keyring client does; the change back is then tried once
/// more. Denied CHANGEs before initialization change and record nothing.
fn rekey_back_initializing(
    token: &[u8],
    password: &[u8],
    initialize: impl FnOnce() -> gkr_session::Initialized,
) -> Result<RekeyedBack, RekeyError> {
    use gkr_session::Initialized;
    let first = rekey_back(token, password);
    let Err(RekeyError::Denied(refused)) = first else {
        return first;
    };
    match initialize() {
        Initialized::Now => {
            println!(
                "[keyring] gnome-keyring here was started by the login screen and not \
                 initialized yet; started it through the session bus, as a GNOME session \
                 does, and trying again."
            );
            rekey_back(token, password)
        }
        Initialized::NotNeeded => Err(RekeyError::Denied(refused)),
        // Here the DENIED says nothing about the secret: this daemon refuses
        // every request until something initializes it.
        Initialized::OtherProvider => Err(RekeyError::Denied(
            "keyring re-key: refused, because gnome-keyring here was started by the login \
             screen and nothing has initialized it, and another Secret Service provider runs \
             this session, so irlume leaves gnome-keyring alone. Run `irlume keyring forget` \
             from a GNOME session"
                .to_string(),
        )),
        Initialized::Failed(why) => Err(RekeyError::Denied(format!(
            "keyring re-key: refused, because gnome-keyring here was started by the login \
             screen and nothing has initialized it, and irlume could not initialize it \
             through the session bus: {why}"
        ))),
    }
}

/// Second half of a GNOME token arm, shared by `keyring arm`, the setup wizard
/// and the TUI: re-key the login keyring from `password` to `token` and verify
/// the token is now the live credential. On a RE-arm the keyring is usually
/// keyed to the token already, so a denied re-key followed by a passing
/// verification is success, not failure.
///
/// `minted` is the daemon's word on whether this token is fresh. irlumed mints
/// one only for an account with a login keyring, and of the CHANGEs sent here
/// only the re-key from `password` can key that keyring to a new secret. So a
/// fresh token's envelope is rolled back with `ForgetPassword` when the
/// keyring provably never took the token: gnome-keyring refused the re-key or
/// never received it, or the keyring still opens with `password`. Any other
/// failure keeps the envelope, because a re-key whose answer was lost may have
/// landed, and the envelope then holds the only copy of the keyring's
/// credential. A reused token may BE the live keyring credential and is never
/// deleted here. Returns a human-readable error; success needs no message
/// beyond the caller's own.
///
/// A session whose gnome-keyring the login screen started and nothing
/// initialized gets no re-key at all (see [`gkr_session`]): that daemon
/// refuses every CHANGE, and a token armed there is never delivered at login.
/// Every arm path refuses such a session before sealing; this check covers a
/// session that changed since.
pub(crate) fn finish_token_arm(
    user: &str,
    password: &[u8],
    token: &[u8],
    minted: bool,
) -> Result<(), String> {
    finish_token_arm_in(user, password, token, minted, gkr_session::session_refusal)
}

/// [`finish_token_arm`] with the session check passed in, so tests can
/// answer it without a real session.
fn finish_token_arm_in(
    user: &str,
    password: &[u8],
    token: &[u8],
    minted: bool,
    session_refusal: impl FnOnce() -> Option<String>,
) -> Result<(), String> {
    if let Some(why) = session_refusal() {
        // Nothing was sent to gnome-keyring, so the keyring never took the
        // token and a fresh one has nothing to protect.
        if !minted {
            return Err(format!(
                "not armed: {why}. The envelope was left in place, since it holds the token \
                 armed earlier; nothing was sent to gnome-keyring."
            ));
        }
        return Err(format!("not armed: {why}. {}.", erase_unused_token(user)));
    }
    let rekey = rekey_login_keyring(password, token);
    // The keyring may already be keyed to this exact token (idempotent
    // re-arm, or a re-key whose answer was lost); verification decides.
    let checked = verify_keyring_credential(token);
    let rekey_confirmed = rekey.is_ok();
    let rekey_unchanged = matches!(rekey, Err(RekeyError::Denied(_) | RekeyError::Unchanged(_)));
    let e = match (rekey, checked) {
        (_, Ok(())) => return Ok(()),
        // Report the re-key's own error; after a confirmed re-key, the
        // verification's.
        (Err(e), Err(_)) | (Ok(()), Err(e)) => e,
    };
    if !minted {
        return Err(format!(
            "keyring re-key failed: {e}. The envelope was left in place (it holds the \
             keyring's live token); retry as '{user}' inside their own graphical session."
        ));
    }
    // A CHANGE from the password to itself succeeds only while the keyring
    // still opens with it. After a confirmed re-key it cannot, so skip it.
    let token_unused =
        rekey_unchanged || (!rekey_confirmed && verify_keyring_credential(password).is_ok());
    if !token_unused {
        return Err(format!(
            "keyring re-key not verified: {e}. The sealed token was kept, since the login \
             keyring may be keyed to it now and the envelope holds its only copy. Run \
             `irlume keyring arm` again as '{user}' inside their own graphical session to \
             finish the re-key with this token. Where irlumed refuses that re-arm, \
             `irlume keyring forget` re-keys the keyring back to the password first."
        ));
    }
    let cleanup = erase_unused_token(user);
    Err(format!(
        "keyring re-key failed: {e}. {cleanup}. Run the arm as '{user}' inside \
         their own graphical session."
    ))
}

/// Roll back a freshly minted token the login keyring never took, and say
/// how that went.
fn erase_unused_token(user: &str) -> String {
    match daemon_request(&irlume_common::Request::ForgetPassword {
        user: user.to_string(),
    }) {
        Ok(irlume_common::Response::PasswordForgotten) => {
            "rolled back: the sealed token was erased; nothing changed".to_string()
        }
        other => format!(
            "WARNING: could not erase the unused token envelope ({other:?}); run \
             `irlume keyring forget` to clean up. The keyring itself is unchanged"
        ),
    }
}

/// Read a typed secret without echo, mirroring the arm prompt's terminal/pipe
/// split. Every no-echo prompt in this binary reads through here: the login
/// password (`keyring arm`, `reseal`, `setup`) and the recovery passphrase.
///
/// The secret is wrapped in `Zeroizing` at the point it is first held, the same
/// as the TUI's `Pending::KeyringPw`, so the buffer is overwritten on drop
/// instead of being freed with the password still in it. That bounds how long
/// the plaintext lives; it cannot undo a page that was already swapped out, and
/// nothing here excludes it from a core dump.
///
/// Callers must keep it inside the wrapper. `.clone()` is safe (a cloned
/// `Zeroizing` wipes itself too), but anything that leaves the wrapper does
/// not: `to_string()`, `as_str().to_owned()`, or `format!` all produce a plain
/// `String` that nothing wipes.
fn read_password(prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        rpassword::prompt_password(prompt)
            .map(zeroize::Zeroizing::new)
            .map_err(|e| format!("could not read password: {e}"))
    } else {
        use std::io::BufRead;
        let mut line = zeroize::Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("could not read password: {e}"))?;
        // Truncate in place: building the trimmed value with `to_string()` would
        // leave the untrimmed original in a buffer nothing wipes.
        let keep = line.trim_end_matches(['\n', '\r']).len();
        line.truncate(keep);
        Ok(line)
    }
}

/// Under a GNOME keyring token, on a release whose next upgrade does not
/// carry the token over, the step to take before upgrading. Shared by every
/// token-arm path: `keyring arm`, the setup wizard and the TUI's message.
pub(crate) fn print_token_upgrade_notice(user: &str) {
    if let Some(notice) = upgrade_notice::host_token_upgrade_notice() {
        println!("[keyring] \u{26a0} {}", notice.advice(user));
    }
}

/// After an arm: what protects the sealed secrets at rest, as a warning where
/// no dm-crypt layer is found under irlumed's keyring or template-key
/// directory or under `/`, `/usr` or `/etc`, or the storage cannot be
/// established, and as information where it is encrypted but a sealed
/// secret's policy may be one another operating system reproduces
/// (`seal_storage`). Reads the envelope's policy with `KeyringMetadata`
/// (`KeyringInfo` from an older daemon), the template key with
/// `RecoveryStatus` and, when something is sealed, the storage with
/// `SealedStorage` (the CLI's own probe for a daemon that answers "bad
/// request" or cannot be reached). Every flow that seals a keyring secret
/// shows it: `keyring arm`, `irlume setup`, `keyring reseal` and the TUI's
/// Password Wallet.
pub(crate) fn print_seal_storage_note(user: &str) {
    if let Some(advice) = seal_storage_advice(user) {
        println!("{}", seal_storage::arm_note(&advice));
    }
}

/// The guidance [`print_seal_storage_note`] prints, for a flow that shows it
/// its own way.
pub(crate) fn seal_storage_advice(user: &str) -> Option<seal_storage::SealAdvice> {
    // The arm just sealed a keyring secret: a daemon that does not describe
    // it still has one, under a policy it did not name.
    let keyring = match seal_storage::keyring_seal_for(user, daemon_request) {
        seal_storage::KeyringSeal::Unknown => seal_storage::KeyringSeal::Armed {
            policy: None,
            pcrs: Vec::new(),
        },
        keyring => keyring,
    };
    let sealed = seal_storage::Sealed {
        keyring,
        template_key: seal_storage::template_key_sealed(&daemon_request(
            &irlume_common::Request::RecoveryStatus {
                user: user.to_string(),
            },
        )),
        pcrlock_seals: irlume_core::tpm::pcrlock_for_sealing().is_some(),
    };
    seal_storage::state_dir_guidance(&sealed)
}

/// `irlume keyring <arm|status|forget>`: manage the TPM-sealed login password
/// that lets a face login unlock the GNOME-keyring / KWallet. Talks to `irlumed`
/// over the socket (the daemon owns the TPM + the root-only sealed store).
pub(crate) fn keyring(sub: Option<&str>, args: &[String]) -> std::process::ExitCode {
    let user = user_arg(args);
    match sub {
        Some("arm") => {
            // Before the password prompt: on NixOS an account that has or
            // would get a kind other than the login password is refused
            // without asking for anything.
            let seal = match crate::nixos::seal_kind(&user) {
                Ok(seal) => seal,
                Err(refusal) => {
                    eprintln!("[keyring] {refusal}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let what = match seal {
                crate::nixos::SealKind::DaemonDecides => {
                    "Depending on the wallet you run, what gets sealed is the password \
                     itself, the key your KDE wallet is already opened with, or a fresh \
                     random token this re-keys your GNOME keyring to. Nothing is stored in \
                     plaintext either way."
                }
                crate::nixos::SealKind::LoginPassword => {
                    "On NixOS what gets sealed is the password itself; it is not stored in \
                     plaintext."
                }
            };
            println!(
                "[keyring] Arming face-driven keyring unlock for '{user}'.\n\
                 Enter this user's LOGIN password. {what}"
            );
            // No-echo prompt on a real terminal; fall back to a plain stdin line
            // when piped (scripts / tests), where /dev/tty isn't available.
            // Every branch keeps the login password inside `Zeroizing` for its
            // whole life, matching the TUI's `Pending::KeyringPw`: this is the
            // user's real login password, and a plain `String` copy of it would
            // sit in swappable heap until the process exits.
            let pw = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                let first = match read_password("Login password: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[keyring] {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                // Confirm to catch typos: a mistyped seal silently fails to
                // unlock the wallet at the next face login (key mismatch).
                let confirm = match read_password("Confirm login password: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[keyring] {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                if first != confirm {
                    eprintln!("[keyring] passwords do not match; aborted (nothing sealed).");
                    return std::process::ExitCode::from(2);
                }
                first
            } else {
                match read_password("Login password: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[keyring] {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            };
            if pw.is_empty() {
                eprintln!("[keyring] empty password; aborted");
                return std::process::ExitCode::from(2);
            }
            let (kind, wallet_salt) = match seal.request_fields(&user) {
                Ok(fields) => fields,
                Err(e) => {
                    eprintln!("[keyring] arm failed: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            // On NixOS the module's rules decide (a login password).
            // Elsewhere the daemon judges from what the user has, unless oo7
            // runs this session's Secret Service (it takes the login
            // password); an armed GNOME keyring token stops the arm there
            // before anything is sent.
            let kind = match kind {
                Some(kind) => Ok(Some(kind)),
                None => crate::secrets::arm_kind_hint(&user, wallet_salt.as_ref()),
            };
            // Where the daemon judges, it may mint a GNOME keyring token, so
            // a session that could never deliver one stops the arm before
            // sealing, and nothing armed is replaced. A requested login
            // password mints no token and skips this check.
            if matches!(kind, Ok(None)) {
                if let Some(why) = gkr_session::token_arm_refusal(&user, wallet_salt.as_ref()) {
                    eprintln!("[keyring] not armed: {why}. Nothing was changed.");
                    return std::process::ExitCode::FAILURE;
                }
            }
            let reply = kind.and_then(|kind| {
                daemon_request(&irlume_common::Request::SealPassword {
                    kind,
                    user: user.clone(),
                    password: irlume_common::SecretBytes::new(pw.as_bytes().to_vec()),
                    wallet_salt,
                    wallet_salt_checked: true,
                })
            });
            match reply {
                Ok(irlume_common::Response::PasswordSealed) => {
                    println!("[keyring] \u{2705} armed. After a face login, your wallet will unlock automatically.");
                    println!("[keyring] NOTE: if you change your login password, re-run `irlume keyring arm`.");
                    print_seal_storage_note(&user);
                    std::process::ExitCode::SUCCESS
                }
                // GNOME token arm (#250): the daemon minted and sealed a token;
                // the login keyring must now be re-keyed to it, which only this
                // process can do (the control socket is in this session). A
                // failure rolls a fresh token's envelope back only where the
                // keyring provably never took the token, and otherwise keeps
                // it (`finish_token_arm`).
                Ok(irlume_common::Response::TokenSealed { token, minted }) => {
                    match finish_token_arm(&user, pw.as_bytes(), token.expose(), minted) {
                        Ok(()) => {
                            println!(
                                "[keyring] \u{2705} armed with a keyring token. Your login keyring \
                                 is now keyed to a random secret that irlume releases on every \
                                 login (face, fingerprint, or typed password)."
                            );
                            println!(
                                "[keyring] Your password alone no longer opens the keyring \
                                 directly; `irlume keyring forget` re-keys it back."
                            );
                            print_token_upgrade_notice(&user);
                            print_seal_storage_note(&user);
                            std::process::ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("[keyring] {e}");
                            std::process::ExitCode::FAILURE
                        }
                    }
                }
                Ok(irlume_common::Response::Error(e)) => {
                    eprintln!("[keyring] arm failed: {e}");
                    std::process::ExitCode::FAILURE
                }
                Ok(other) => {
                    eprintln!("[keyring] unexpected response: {other:?}");
                    std::process::ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("[keyring] arm failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some("status") => {
            // Ask for the detail first. WHAT is armed now changes what the
            // user can expect from their own password: a GNOME token means
            // their password no longer opens that keyring, which is not
            // something to leave them to discover.
            match daemon_request(&irlume_common::Request::KeyringInfo { user: user.clone() }) {
                Ok(irlume_common::Response::KeyringInfo {
                    armed: true, kind, ..
                }) => {
                    use irlume_common::KeyringSecretKind as K;
                    match kind {
                        Some(K::LoginPassword) => println!(
                            "[keyring] '{user}': ARMED \u{2705} (login password). A face or \
                             fingerprint login releases it so your wallet unlocks."
                        ),
                        Some(K::KdeWalletKey) => println!(
                            "[keyring] '{user}': ARMED \u{2705} (KDE wallet key). The sealed \
                             secret is the key ksecretd opens the wallet with, not your \
                             password; a typed password still opens it too."
                        ),
                        Some(K::GnomeKeyringToken) => {
                            println!(
                                "[keyring] '{user}': ARMED \u{2705} (GNOME keyring token). Your \
                                 login keyring is keyed to a random secret irlume releases on \
                                 every login."
                            );
                            println!(
                                "[keyring] Your password alone no longer opens that keyring; \
                                 `irlume keyring forget` re-keys it back."
                            );
                            print_token_upgrade_notice(&user);
                        }
                        // An older daemon does not report the kind.
                        None => println!(
                            "[keyring] '{user}': ARMED \u{2705} (this irlumed does not report \
                             what kind)"
                        ),
                    }
                    std::process::ExitCode::SUCCESS
                }
                Ok(irlume_common::Response::KeyringInfo { armed: false, .. }) => {
                    println!("[keyring] '{user}': keyring unlock is not armed");
                    std::process::ExitCode::SUCCESS
                }
                // A daemon predating KeyringInfo answers with an error; the
                // armed bit is still worth reporting.
                Ok(irlume_common::Response::HasPassword(armed)) => {
                    println!(
                        "[keyring] '{user}': keyring unlock is {}",
                        if armed { "ARMED \u{2705}" } else { "not armed" }
                    );
                    std::process::ExitCode::SUCCESS
                }
                Ok(irlume_common::Response::Error(e)) => {
                    eprintln!("[keyring] status failed: {e}");
                    std::process::ExitCode::FAILURE
                }
                Ok(other) => {
                    eprintln!("[keyring] unexpected response: {other:?}");
                    std::process::ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("[keyring] status failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some("forget") => {
            // A token disarm must re-key the login keyring BACK to the
            // password before the envelope goes away: deleting a token
            // envelope first would strand the keyring on a secret that no
            // longer exists anywhere. `--force` skips the re-key for the case
            // where the keyring is already gone (deleted profile, reinstalled
            // distro) and the stale envelope is all that is left.
            let force = args.iter().any(|a| a == "--force");
            // Three outcomes, not two. "Armed with something we could not
            // identify" must not collapse into "not a token": a daemon from
            // before #250 answers `kind: None`, an unreadable envelope answers
            // an error, and deleting a token envelope on either reading leaves
            // the login keyring encrypted under a secret nothing can
            // reproduce. Unknown therefore refuses and names `--force`.
            let (token_armed, unknown) =
                match daemon_request(&irlume_common::Request::KeyringInfo { user: user.clone() }) {
                    Ok(irlume_common::Response::KeyringInfo { armed: false, .. }) => (false, false),
                    Ok(irlume_common::Response::KeyringInfo { kind: Some(k), .. }) => (
                        k == irlume_common::KeyringSecretKind::GnomeKeyringToken,
                        false,
                    ),
                    // Armed, and the daemon could not say what with: an older
                    // daemon, or an envelope it failed to parse. This is the
                    // dangerous reading, so refuse.
                    Ok(irlume_common::Response::KeyringInfo { kind: None, .. }) => (false, true),
                    // A failed inspection is not permission to erase: a transient
                    // failure can be followed by a successful destructive request.
                    Ok(irlume_common::Response::Error(error)) | Err(error) => {
                        eprintln!("[keyring] forget failed: {error} (sealed secret inspection)");
                        (false, true)
                    }
                    _ => {
                        eprintln!(
                            "[keyring] unexpected response while inspecting the sealed secret"
                        );
                        (false, true)
                    }
                };
            if unknown && !force {
                eprintln!(
                    "[keyring] cannot tell what '{user}' has armed, so refusing to erase it: \
                     if it is a GNOME keyring token, deleting it leaves the login keyring \
                     encrypted under a secret nothing can reproduce."
                );
                eprintln!(
                    "[keyring] Update irlumed (an older one does not report the kind), or \
                     pass --force if you are certain the keyring no longer matters."
                );
                return std::process::ExitCode::FAILURE;
            }
            if token_armed && !force {
                println!(
                    "[keyring] '{user}' is armed with a keyring token; re-keying the login \
                     keyring back to your password first."
                );
                let pw = match read_password("Login password: ") {
                    Ok(p) if !p.is_empty() => p,
                    Ok(_) => {
                        eprintln!("[keyring] empty password; aborted (nothing changed).");
                        return std::process::ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("[keyring] {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                let token = match daemon_request(&irlume_common::Request::ReleaseTokenForDisarm {
                    user: user.clone(),
                    password: irlume_common::SecretBytes::new(pw.as_bytes().to_vec()),
                }) {
                    Ok(irlume_common::Response::PasswordUnsealed { secret, .. }) => secret,
                    Ok(irlume_common::Response::Error(e)) => {
                        eprintln!("[keyring] {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                    other => {
                        eprintln!("[keyring] unexpected response: {other:?}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                let initialize = || {
                    gkr_session::Live::from_env().map_or(
                        gkr_session::Initialized::NotNeeded,
                        |session| {
                            gkr_session::initialize_for_forget(&session, control_client_uid())
                        },
                    )
                };
                match rekey_back_initializing(token.expose(), pw.as_bytes(), initialize) {
                    Ok(RekeyedBack::Rekeyed) => {
                        println!("[keyring] login keyring re-keyed back to your password.");
                    }
                    Ok(RekeyedBack::AlreadyPassword) => {
                        println!(
                            "[keyring] the login keyring already opens with your password; \
                             the token it never took is erased."
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[keyring] could not re-key the keyring back ({e}); the sealed \
                             token is UNTOUCHED so nothing is lost. Fix the session (run as \
                             '{user}' with gnome-keyring running) and retry, or `--force` to \
                             delete the envelope anyway."
                        );
                        return std::process::ExitCode::FAILURE;
                    }
                }
            } else if token_armed && force {
                eprintln!(
                    "[keyring] WARNING: --force on a token arm deletes the only copy of the \
                     keyring token. If the login keyring still exists and is keyed to it, \
                     its contents become unreachable."
                );
            }
            match daemon_request(&irlume_common::Request::ForgetPassword { user: user.clone() }) {
                Ok(irlume_common::Response::PasswordForgotten) => {
                    println!("[keyring] '{user}': sealed secret erased; keyring unlock disarmed.");
                    std::process::ExitCode::SUCCESS
                }
                Ok(irlume_common::Response::Error(e)) => {
                    eprintln!("[keyring] forget failed: {e}");
                    std::process::ExitCode::FAILURE
                }
                Ok(other) => {
                    eprintln!("[keyring] unexpected response: {other:?}");
                    std::process::ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("[keyring] forget failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!(
                "usage: irlume keyring <arm|status|forget> [--user U]\n\n\
                 \x20 arm      seal a secret so a login opens your wallet; what is\n\
                 \x20          sealed depends on the wallet you run\n\
                 \x20 status   whether a secret is armed, and which kind\n\
                 \x20 forget   erase it. A GNOME keyring token is re-keyed back to\n\
                 \x20          your password first, which needs that password;\n\
                 \x20          --force skips the re-key and leaves such a keyring\n\
                 \x20          unreachable"
            );
            std::process::ExitCode::from(2)
        }
    }
}

/// Round-trip one request to `irlumed` over the Unix socket and return its reply.
pub(crate) fn daemon_request(
    req: &irlume_common::Request,
) -> Result<irlume_common::Response, String> {
    // Trust changes allow OS approval, queue admission and the worker budget.
    // Other operations keep their existing timeout, including authentication.
    let seconds = if matches!(
        req,
        irlume_common::Request::Enroll { .. }
            | irlume_common::Request::EnrollOn { .. }
            | irlume_common::Request::EnrollSplitOn { .. }
            | irlume_common::Request::AddScan { .. }
            | irlume_common::Request::AddCameraGroup { .. }
            | irlume_common::Request::AddCameraGroupOn { .. }
            | irlume_common::Request::AddSplitCameraGroupOn { .. }
            | irlume_common::Request::RemoveCameraGroup { .. }
            | irlume_common::Request::RecoverySetup { .. }
            | irlume_common::Request::RecoveryForget { .. }
            | irlume_common::Request::DeleteProfile { .. }
            | irlume_common::Request::ForgetRecognizer { .. }
    ) {
        380
    } else {
        120
    };
    irlume_common::client::request_with_timeout(req, std::time::Duration::from_secs(seconds))
        .map_err(|e| {
            // The connect-failure message already names irlumed and the exact
            // fix (client.rs); only append the hint where it adds information.
            let m = e.to_string();
            if m.contains("irlumed") {
                m
            } else {
                format!("{m} (is irlumed running?)")
            }
        })
}

/// A short-budget status poll (TUI periodic refresh): a busy/wedged daemon fails
/// fast instead of stalling the UI for the full connect/read budget.
pub(crate) fn daemon_poll(req: &irlume_common::Request) -> Result<irlume_common::Response, String> {
    irlume_common::client::request_poll(req).map_err(|e| e.to_string())
}

/// Budget for one framing-guide sample (a single RGB capture + detect). Long
/// enough for a slow first capture, far below `daemon_request`'s 120s capture
/// budget: against a wedged daemon the guide must FAIL and say so, not sit
/// for minutes rendering a stale cue as if it were current (#309).
pub(crate) fn daemon_sample(
    req: &irlume_common::Request,
) -> Result<irlume_common::Response, String> {
    irlume_common::client::request_with_timeout(req, std::time::Duration::from_secs(10))
        .map_err(|e| e.to_string())
}

/// The `on`/`off` word for `profiles eyes-open`, read as the argument AFTER the
/// subcommand rather than found anywhere in argv.
///
/// Scanning the whole command line meant a flag VALUE could be mistaken for the
/// setting: `irlume profiles eyes-open --user on` turned the feature on for an
/// account named `on`, and `--user off` turned it off for one named `off`. The
/// value is positional, so it is read positionally.
fn toggle_value(args: &[String], sub: &str) -> Option<bool> {
    let idx = args.iter().position(|a| a == sub)?;
    let value = match args.get(idx + 1).map(String::as_str) {
        Some("on") => Some(true),
        Some("off") => Some(false),
        _ => None,
    };
    // A contradictory second word stays a usage error rather than first-wins.
    // The previous whole-argv scan caught `eyes-open on off` that way, and
    // reading positionally has to keep it while no longer mistaking a
    // `--user on` VALUE for the setting.
    let contradicted = matches!(args.get(idx + 2).map(String::as_str), Some("on" | "off"));
    match value {
        Some(v) if !contradicted => Some(v),
        _ => {
            eprintln!("usage: irlume profiles {sub} off [--user U] (one-release migration only)");
            None
        }
    }
}

pub(crate) fn user_arg(args: &[String]) -> String {
    // A `--user` with nothing after it is a usage error, never a request to
    // operate on whoever is invoking.
    //
    // `flag` answers None both for "absent" and for "present with no value", so
    // a trailing `--user` fell through to the SUDO_USER default and silently
    // retargeted the command at the person typing it. On the destructive verbs
    // that is total, unconfirmed data loss: `sudo irlume enroll --reset --user`
    // put `{"Enroll":{"user":"<you>","reset":true}}` on the wire, and the
    // daemon's reset then deleted the enrollment, the template key, and the recovery
    // envelope together. `recovery forget --user` and `keyring forget --user`
    // did the same.
    //
    // The guard existed, but only inside `profiles`, so it covered one of the
    // four. It belongs here, where all 24 callers share it: this is a resolver,
    // and the one thing a resolver must not do is quietly resolve to the wrong
    // subject. Exiting rather than returning an error keeps every caller's
    // signature, and there is no sensible way to continue.
    if flag_present(args, "--user") && flag(args, "--user").is_none() {
        // A DANGLING flag only. An empty value (`--user ""`, and now `--user=`)
        // keeps its documented meaning, which
        // `user_arg_falls_back_to_env_user_when_flag_is_empty_or_absent` pins:
        // it falls back like an absent flag. The subcommands that must not
        // tolerate that, `profiles` above all, carry their own stricter guard.
        eprintln!("irlume: --user requires a username");
        std::process::exit(2);
    }
    flag(args, "--user")
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            // Under `sudo irlume …` (which status/diag themselves recommend
            // for envelope detail) $USER is root, but the person almost
            // always means their own profile: prefer the invoking user.
            std::env::var("SUDO_USER")
                .ok()
                // SAFETY: geteuid takes no arguments, reads only this process's own
                // effective uid, and is specified as always succeeding.
                .filter(|s| !s.is_empty() && unsafe { libc::geteuid() } == 0)
                .or_else(|| std::env::var("USER").ok())
                .unwrap_or_else(|| "user".into())
        })
}

/// Effective UID 0: the command can write /etc and manage the daemon.
/// This process's view of the camera hardware, asked of the DAEMON first and
/// cached for the process.
///
/// Every caller used to call `irlume_camera::capabilities()`, which
/// classifies each `/dev/video*` node by OPENING it. Reached from the TUI's
/// refresh paths (through `pamwire::wants`, among others) that ran hundreds
/// of times per session, each one a second opener racing whatever the daemon
/// was streaming: EBUSY on strict UVC modules, which is #187. The daemon
/// already knows what its cameras are and answers from memory, so ask it.
///
/// The local probe survives only as the daemon-silent fallback, and the
/// `OnceLock` bounds it to a single probe per process instead of one per
/// call. Long-running surfaces that must notice a camera being plugged in
/// (the TUI) refresh from Health on their own poll rather than from here.
pub(crate) fn caps() -> irlume_camera::Caps {
    caps_reading().caps
}

/// Whether [`caps`] is an OBSERVATION or a fallback guess.
///
/// The two are not interchangeable and one caller must not confuse them:
/// `pamwire` UNWIRES a surface whose capability reads false, so a guessed
/// `false` removes face authentication from every greeter. See
/// [`CapsReading`].
pub(crate) fn caps_established() -> bool {
    caps_reading().established
}

/// A capability answer and whether anything actually established it.
///
/// The third state is the one that matters. A daemon that ANSWERS gives an
/// observation; a daemon PROVEN absent licenses the one permitted probe,
/// which also observes. Everything else (a timeout, EACCES, a daemon busy
/// mid-capture) establishes nothing, and on a packaged install that is the
/// ORDINARY shape of a dead daemon rather than an exotic one: socket
/// activation keeps `/run/irlume.sock` present from sockets.target onward,
/// so a failed daemon answers with a timeout and never ECONNREFUSED.
///
/// Collapsing that into `{ir_pair: false, rgb: false}` made "could not ask"
/// indistinguishable from "this machine has no camera", which is the same
/// absence-versus-failure-to-observe collapse `control_read_failure_means_
/// absent` and `NodeScan::listing_error` exist to prevent elsewhere.
#[derive(Clone, Copy)]
pub(crate) struct CapsReading {
    pub(crate) caps: irlume_camera::Caps,
    /// False when the fields above are a fallback guess. A caller that acts
    /// DESTRUCTIVELY on a false capability must refuse instead.
    pub(crate) established: bool,
}

fn caps_reading() -> CapsReading {
    static CAPS: std::sync::OnceLock<CapsReading> = std::sync::OnceLock::new();
    *CAPS.get_or_init(|| {
        match irlume_common::client::request_poll(&irlume_common::Request::Health) {
            Ok(irlume_common::Response::Health { tier, rgb_dev, .. }) => CapsReading {
                caps: irlume_camera::Caps {
                    ir_pair: tier == "secure",
                    rgb: rgb_dev.is_some() || tier == "secure",
                },
                established: true,
            },
            // Enumerating opens every node, so it needs POSITIVE evidence that no
            // daemon holds them. Only a failure that proves nobody is listening is
            // that evidence; a timeout is what a daemon busy mid-capture looks
            // like, which is the worst moment to probe.
            Err(e) if daemon_proven_absent(&e) => CapsReading {
                caps: irlume_camera::capabilities(), // the one permitted probe
                established: true,
            },
            // Ambiguous: answer from the configured pair's mere existence,
            // which never opens anything. The rule is ASYMMETRIC on purpose:
            // existence of both paths may establish a POSITIVE reading (a
            // positive only ever WIRES, and wiring is non-destructive since
            // the password stays the fallback even if a path turned into the
            // wrong node), but a missing path must not establish a NEGATIVE
            // one. Path-absence during a timeout is what a suspended,
            // renumbered, or unplugged camera looks like on a machine that
            // HAS one, and an established-false reading is precisely what
            // authorizes the unwire this type exists to prevent. The first
            // cut set established=true here unconditionally, which covered
            // the no-config machine and left the configured one, the common
            // upgrade case, unprotected (found in the PR review).
            _ => match irlume_camera::configured_pair_no_probe() {
                Some((rgb, ir)) => {
                    let caps = irlume_camera::Caps {
                        ir_pair: std::path::Path::new(&ir).exists(),
                        rgb: std::path::Path::new(&rgb).exists(),
                    };
                    CapsReading {
                        established: caps.ir_pair && caps.rgb,
                        caps,
                    }
                }
                None => CapsReading {
                    caps: irlume_camera::Caps {
                        ir_pair: false,
                        rgb: false,
                    },
                    established: false,
                },
            },
        }
    })
}

/// These two accessors call `request_poll` directly rather than `daemon_poll`,
/// because `daemon_poll` flattens `io::Error` into a String for its callers'
/// messages and the error KIND is exactly what decides whether probing the
/// cameras is safe here.
fn daemon_proven_absent(e: &std::io::Error) -> bool {
    irlume_common::client::proves_daemon_absent(e)
}

/// The RGB and IR node paths in use, asked of the DAEMON first and cached for
/// the process.
///
/// The sibling of [`caps`], and for the same reason: `select_pair` classifies
/// nodes by OPENING them, so calling it while the daemon streams is a second
/// opener racing it, which is EBUSY on strict UVC modules (#187). #300 fixed
/// the TUI; `status`, `status --json`, and `setup` were still enumerating,
/// measured with strace as four opens of /dev/video0..3 each with the daemon
/// running. `setup` was the worst: it probed in preflight and enrolled seconds
/// later on the nodes it had just touched.
///
/// The local probe survives only as the daemon-silent fallback, where nothing
/// else holds the cameras and it is the only source of an answer.
pub(crate) fn camera_pair() -> (String, String) {
    static PAIR: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    PAIR.get_or_init(|| {
        match irlume_common::client::request_poll(&irlume_common::Request::Health) {
            Ok(irlume_common::Response::Health {
                rgb_dev, ir_dev, ..
            }) => (
                rgb_dev.unwrap_or_else(|| "none".into()),
                ir_dev.unwrap_or_else(|| "none".into()),
            ),
            // Same rule as `caps`: probe only on proven absence. `None` means
            // no discoverable pair, reported as "none" rather than a guess.
            Err(e) if daemon_proven_absent(&e) => {
                // the one permitted probe
                irlume_camera::select_pair().unwrap_or_else(|| ("none".into(), "none".into()))
            }
            _ => irlume_camera::configured_pair_no_probe()
                .unwrap_or_else(|| ("unknown".into(), "unknown".into())),
        }
    })
    .clone()
}

pub(crate) fn is_root() -> bool {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::geteuid() == 0
    }
}

/// Build an Engine: optional --rgb/--ir device overrides, and load an IR
/// adapter from --adapter PATH if one is supplied (none ships by default since
/// ADR-0004; the default IR path is raw AuraFace + per-enrollment calibration).
/// `irlume enrolldev --user U --det <yunet.onnx> --model <glintr100.onnx>
///   [--name N] [--scans K] [--adapter P] [--rgb ..] [--ir ..]`
///
/// Direct-mode enrollment (no daemon), the enroll-side companion to `verify`:
/// drives `Engine::enroll_profile` against the current `IRLUME_STATE_DIR`, so
/// matching-path changes (e.g. the ADR-0004 per-enrollment calibration) can
/// be exercised end-to-end in an isolated state dir without touching the
/// installed daemon or production enrollments. `--adapter /nonexistent`
/// forces the raw-IR pipeline, which is where the calibration activates.
fn enrolldev(args: &[String]) -> std::process::ExitCode {
    let (Some(det), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume enrolldev --user U --det <yunet.onnx> --model <glintr100.onnx> [--name N] [--scans K] [--adapter P] [--rgb ..] [--ir ..]");
        return std::process::ExitCode::from(2);
    };
    let user = user_arg(args);
    let name = flag(args, "--name").map(String::from);
    let want = flag(args, "--scans")
        .and_then(|s| s.parse().ok())
        .unwrap_or(irlume_core::storage::DEFAULT_ENROLL_SCANS);
    eprintln!("[enrolldev] '{user}': {want} scans into IRLUME_STATE_DIR; stay in frame…");
    match engine(det, model, args).and_then(|mut e| e.enroll_profile(&user, name, want)) {
        Ok(irlume_auth::EnrollOutcome::New {
            name,
            scans,
            ambient_lit,
        }) => {
            println!("[enrolldev] enrolled '{name}' ({scans} scans)");
            if ambient_lit > 0 {
                println!(
                    "[enrolldev] {ambient_lit} of {scans} scans were lit mainly by the room, \
                     not provably by the IR emitter; dark-room login is unverified. Check it: \
                     turn the lights off and run `irlume identify` (#312)"
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Ok(irlume_auth::EnrollOutcome::Merged {
            name,
            added,
            total,
            ambient_lit,
            ..
        }) => {
            println!("[enrolldev] merged into '{name}' (+{added} scans, {total} total)");
            if ambient_lit > 0 {
                println!(
                    "[enrolldev] {ambient_lit} of {added} added scans were lit mainly by the \
                     room, not provably by the IR emitter; dark-room login is unverified. \
                     Check it: turn the lights off and run `irlume identify` (#312)"
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("enrolldev error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Build the direct-mode Engine for the dev tools (`verify`, `enrolldev`,
/// benchmarks): no daemon involved. Prints one `[engine] …` line to stderr for
/// each optional model it loads (adapter / mesh / BlazeFace), so a benchmark
/// log records which stack produced the numbers. `--mesh` and `--blaze`
/// default to `models/…` paths relative to the CURRENT DIRECTORY, i.e. a repo
/// checkout; pass explicit paths when running from anywhere else.
/// Which camera nodes the dev-tool engine should open, from the optional
/// `--rgb`/`--ir` flags. `None` = no override (the engine's own defaults).
///
/// Either flag ALONE overrides its half; the partner comes from `selected`
/// (in production [`irlume_camera::select_pair`]: the persisted pair with
/// identity resolution, then discovery), because a lone flag used to be
/// SILENTLY IGNORED: `gesturecap capture --ir /dev/video6` captured against
/// the built-in default node and failed with "no camera found", saying
/// nothing about the dropped flag (#209). `selected` runs only when needed,
/// since it can probe devices.
pub(crate) fn devices_from_flags(
    rgb: Option<&str>,
    ir: Option<&str>,
    selected: impl FnOnce() -> Option<(String, String)>,
) -> Option<(String, String)> {
    match (rgb, ir) {
        (None, None) => None,
        (Some(r), Some(i)) => Some((r.to_string(), i.to_string())),
        (r, i) => {
            // One flag alone needs its partner from the selection; with no
            // discoverable pair there is nothing to guess (no `/dev/videoN`
            // folklore), so the half-pair is refused rather than invented.
            let (sel_r, sel_i) = selected()?;
            Some((
                r.map(str::to_string).unwrap_or(sel_r),
                i.map(str::to_string).unwrap_or(sel_i),
            ))
        }
    }
}

pub(crate) fn engine(
    det: &str,
    model: &str,
    args: &[String],
) -> irlume_common::Result<irlume_auth::Engine> {
    let e = irlume_auth::Engine::load(det, model)?;
    let e = match devices_from_flags(flag(args, "--rgb"), flag(args, "--ir"), || {
        // deliberate camera probe: this engine is about to OPEN the node it
        // resolves, so resolving it is the first step of using it.
        irlume_camera::select_pair()
    }) {
        Some((r, i)) => e.with_devices(&r, &i),
        None => e,
    };
    let adapter = flag(args, "--adapter").unwrap_or("");
    let e = e.with_ir_adapter(adapter)?;
    if e.has_ir_adapter() {
        eprintln!("[engine] IR adapter loaded ({adapter}); dark mode uses adapted recognition");
    }
    let mesh = flag(args, "--mesh").unwrap_or("models/face_landmarks_detector.tflite");
    let e = e.with_mesh(mesh)?;
    if e.has_mesh() {
        eprintln!("[engine] FaceMesh loaded ({mesh}); BlazeFace rescue alignment available");
    }
    let blaze = flag(args, "--blaze").unwrap_or("models/blaze_face_short_range.onnx");
    let e = e.with_blaze_rescue(blaze)?;
    if e.has_blaze_rescue() {
        eprintln!("[engine] BlazeFace rescue loaded ({blaze}); detection cascade active");
    }
    Ok(e)
}

// Brightness/center-edge cue helpers live in irlume-auth (the daemon-side pipeline
// owns them); re-exported so the dev tools here and in pad.rs measure with the
// exact same code the gate uses.
pub(crate) use irlume_auth::{center_edge_ratio, mean_in_bbox};

/// `irlume irbench --dir <nir_images> --det .. --model ..`: the real IR
/// recognition benchmark: embed real NIR faces (YuNet detect → align → AuraFace),
/// group by person (filename prefix), and report genuine vs impostor cosine
/// distributions + EER + FAR/FRR. Answers "does AuraFace-on-IR discriminate?".
fn irbench(args: &[String]) -> std::process::ExitCode {
    let (Some(dir), Some(det_path), Some(model)) = (
        flag(args, "--dir"),
        flag(args, "--det"),
        flag(args, "--model"),
    ) else {
        eprintln!("usage: irlume irbench --dir <imgdir> --det <yunet.onnx> --model <glintr100.onnx> [--max-persons N] [--lfw] [--impostor-only [--max-images N]]");
        return std::process::ExitCode::from(2);
    };
    let max_persons: usize = flag(args, "--max-persons")
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);

    // Impostor-only / FALSE-ACCEPT mode: a directory of distinct-identity images
    // (e.g. SFHQ synthetic faces; every file is a different person), so every
    // pair is an impostor pair. Measures FAR only (no genuine pairs / FRR).
    if args.iter().any(|a| a == "--impostor-only") {
        // `--lfw` is an identity-GROUPING rule, and this mode has no grouping:
        // it assumes every file is a different person and pairs all of them.
        // Accepting both silently counted same-person pairs as impostor pairs,
        // which inflates the reported FAR on any set with repeated identities.
        // Refuse rather than return a number that does not mean what it says.
        if args.iter().any(|a| a == "--lfw") {
            eprintln!(
                "[irbench] --impostor-only and --lfw are incompatible: --impostor-only \
                 assumes every image is a DIFFERENT person and pairs all of them, so on a \
                 set with several images per identity (which is what --lfw describes) the \
                 same-person pairs would be counted as impostor pairs and the reported FAR \
                 would be an upper bound, not an impostor rate. Drop one of the two flags."
            );
            return std::process::ExitCode::from(2);
        }
        return farbench(dir, det_path, model, args);
    }

    // Collect images (recursive, jpg/png/bmp) grouped by person identity.
    // Default key = prefix before first '-' (CBSR convention). With --lfw the key
    // is the filename stem minus a trailing _<digits> image index, i.e. the LFW
    // convention `AJ_Cook_0001.jpg` -> person `AJ_Cook`.
    let lfw = args.iter().any(|a| a == "--lfw");
    let mut all: Vec<std::path::PathBuf> = Vec::new();
    collect_images(std::path::Path::new(dir), &mut all);
    if all.is_empty() {
        eprintln!("no jpg/png/bmp images under {dir}");
        return std::process::ExitCode::FAILURE;
    }
    all.sort(); // deterministic
    let mut by_person: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> =
        Default::default();
    for p in all {
        let Some(name) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let person = if lfw {
            match name.rsplit_once('_') {
                Some((head, idx)) if !idx.is_empty() && idx.bytes().all(|b| b.is_ascii_digit()) => {
                    head.to_string()
                }
                _ => name.to_string(),
            }
        } else {
            name.split('-').next().unwrap_or(name).to_string()
        };
        by_person.entry(person).or_default().push(p);
    }
    let persons: Vec<_> = by_person.into_iter().take(max_persons).collect();
    println!(
        "[irbench] {} persons, {} images; embedding (YuNet→align→AuraFace)…",
        persons.len(),
        persons.iter().map(|(_, v)| v.len()).sum::<usize>()
    );

    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("det load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("emb load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Experiment knob: --tta = test-time augmentation (embed chip + its mirror,
    // average, renormalize). Standard ArcFace inference trick; no retraining.
    let tta = args.iter().any(|a| a == "--tta");
    // Low-light experiment knobs (applied to the aligned chip BEFORE embedding):
    //   --darken F        simulate a dim capture (scale pixels by F<1)
    //   --lightnorm MODE  illumination normalization: gamma|he|clahe (recover dim probe)
    let darken: Option<f32> = flag(args, "--darken").and_then(|s| s.parse().ok());
    let lightnorm: Option<String> = flag(args, "--lightnorm").map(|s| s.to_string());
    // (person_index, embedding)
    let mut embs: Vec<(usize, [f32; irlume_vision::EMBED_DIM])> = Vec::new();
    let mut nodet = 0usize;
    for (pi, (_person, files)) in persons.iter().enumerate() {
        for f in files {
            let Ok(img) = image::open(f) else { continue };
            let rgb = img.to_rgb8();
            let (w, h) = rgb.dimensions();
            let data = rgb.into_raw();
            let view = irlume_vision::align::RgbView {
                data: &data,
                width: w,
                height: h,
            };
            let Ok(faces) = det.detect(&view) else {
                continue;
            };
            let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
                nodet += 1;
                continue;
            };
            if let Ok(mut chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) {
                if let Some(f) = darken {
                    irlume_vision::light::darken(&mut chip, f);
                }
                match lightnorm.as_deref() {
                    Some("gamma") => irlume_vision::light::gamma(&mut chip, 2.2),
                    Some("he") => irlume_vision::light::equalize(&mut chip),
                    Some("clahe") => irlume_vision::light::clahe(
                        &mut chip,
                        irlume_vision::align::OUT_SIZE as usize,
                        8,
                        3.0,
                    ),
                    _ => {}
                }
                if tta {
                    if let (Ok(a), Ok(b)) = (
                        emb.embed(&chip),
                        emb.embed(&irlume_vision::align::flip_h(&chip)),
                    ) {
                        let mut v = [0f32; irlume_vision::EMBED_DIM];
                        let mut norm = 0f32;
                        for k in 0..irlume_vision::EMBED_DIM {
                            v[k] = a[k] + b[k];
                            norm += v[k] * v[k];
                        }
                        let norm = norm.sqrt().max(1e-12);
                        for vk in v.iter_mut() {
                            *vk /= norm;
                        }
                        embs.push((pi, v));
                    }
                } else if let Ok(e) = emb.embed(&chip) {
                    embs.push((pi, e));
                }
            }
        }
    }
    println!(
        "[irbench] embedded {} faces ({} images had no detectable face){}",
        embs.len(),
        nodet,
        if tta { " [TTA flip-avg]" } else { "" }
    );

    // Optional: dump (person_index, 512-D embedding) per line for offline training.
    if let Some(out) = flag(args, "--export") {
        use std::io::Write;
        match std::fs::File::create(out) {
            Ok(mut f) => {
                for (pi, e) in &embs {
                    let mut line = pi.to_string();
                    for v in e.iter() {
                        line.push(' ');
                        line.push_str(&format!("{v:.6}"));
                    }
                    let _ = writeln!(f, "{line}");
                }
                println!("[irbench] exported {} embeddings -> {out}", embs.len());
            }
            Err(e) => eprintln!("export failed: {e}"),
        }
    }

    // Genuine = same person, impostor = different person.
    let mut genuine = Vec::new();
    let mut impostor = Vec::new();
    for i in 0..embs.len() {
        for j in (i + 1)..embs.len() {
            let c = irlume_vision::align::cosine(&embs[i].1, &embs[j].1);
            if embs[i].0 == embs[j].0 {
                genuine.push(c)
            } else {
                impostor.push(c)
            }
        }
    }
    if genuine.is_empty() || impostor.is_empty() {
        eprintln!("not enough data");
        return std::process::ExitCode::FAILURE;
    }
    genuine.sort_by(f32::total_cmp);
    impostor.sort_by(f32::total_cmp);
    let pct = |v: &[f32], p: f32| v[((p * (v.len() - 1) as f32) as usize).min(v.len() - 1)];
    let mean = |v: &[f32]| v.iter().sum::<f32>() / v.len() as f32;
    println!(
        "[genuine ] n={:6}  min {:.3}  mean {:.3}  median {:.3}",
        genuine.len(),
        genuine[0],
        mean(&genuine),
        pct(&genuine, 0.5)
    );
    println!(
        "[impostor] n={:6}  mean {:.3}  p99 {:.3}  p99.9 {:.3}  max {:.3}",
        impostor.len(),
        mean(&impostor),
        pct(&impostor, 0.99),
        pct(&impostor, 0.999),
        impostor[impostor.len() - 1]
    );

    // FAR/FRR sweep + EER + the threshold meeting FAR=1e-4.
    let far = |t: f32| impostor.iter().filter(|&&c| c >= t).count() as f64 / impostor.len() as f64;
    let frr = |t: f32| genuine.iter().filter(|&&c| c < t).count() as f64 / genuine.len() as f64;
    for t in [0.40f32, 0.45, 0.50, 0.55, 0.60] {
        println!("  thr {t:.2}: FAR {:.5}  FRR {:.4}", far(t), frr(t));
    }
    // EER: scan thresholds for |FAR-FRR| min.
    let mut eer = (1.0f64, 0.0f32);
    let mut t = 0.0;
    while t < 1.0 {
        let (a, r) = (far(t), frr(t));
        if (a - r).abs() < eer.0 {
            eer = ((a - r).abs(), t);
        }
        t += 0.005;
    }
    let et = eer.1;
    println!(
        "[EER] ~{:.3} at threshold {et:.3}",
        (far(et) + frr(et)) / 2.0
    );
    // threshold achieving FAR<=1e-4, and its FRR
    let mut t14 = 1.0f32;
    let mut s = 0.30;
    while s <= 0.95 {
        if far(s) <= 1e-4 {
            t14 = s;
            break;
        }
        s += 0.005;
    }
    println!(
        "[FAR≤1e-4] threshold {t14:.3} -> FRR {:.4} (reject rate for genuine at NIST-grade FAR)",
        frr(t14)
    );
    std::process::ExitCode::SUCCESS
}

/// Large-scale RGB FALSE-ACCEPT benchmark (the visible-light sibling of the IR
/// `irbench`). Every image under `--dir` is treated as a distinct identity (true
/// for SFHQ synthetic faces), so every pair is an impostor pair. Embeds each face
/// through the real auth pipeline (YuNet → align → AuraFace) and reports the
/// impostor cosine tail + FAR at the auth thresholds + the threshold achieving
/// NIST-grade FAR ≤ 1e-4. Histogram-based, so it scales to millions of pairs
/// without storing them. FAR only; genuine/FRR come from live captures, not here.
fn farbench(dir: &str, det_path: &str, model: &str, args: &[String]) -> std::process::ExitCode {
    let max_images: usize = flag(args, "--max-images")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_images(std::path::Path::new(dir), &mut files);
    files.sort(); // deterministic sample
    files.truncate(max_images);
    if files.len() < 2 {
        eprintln!(
            "[farbench] need >=2 images under {dir} (found {})",
            files.len()
        );
        return std::process::ExitCode::FAILURE;
    }
    println!(
        "[farbench] {} images; embedding (YuNet→align→AuraFace)…",
        files.len()
    );

    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("det load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("emb load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut embs: Vec<[f32; irlume_vision::EMBED_DIM]> = Vec::with_capacity(files.len());
    let mut nodet = 0usize;
    for (i, f) in files.iter().enumerate() {
        if i > 0 && i % 1000 == 0 {
            println!(
                "[farbench]   {}/{} embedded ({} no-face)…",
                embs.len(),
                i,
                nodet
            );
        }
        let Ok(img) = image::open(f) else { continue };
        let rgb = img.to_rgb8();
        let (w, h) = rgb.dimensions();
        let data = rgb.into_raw();
        let view = irlume_vision::align::RgbView {
            data: &data,
            width: w,
            height: h,
        };
        let Ok(faces) = det.detect(&view) else {
            continue;
        };
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            nodet += 1;
            continue;
        };
        if let Ok(chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) {
            if let Ok(e) = emb.embed(&chip) {
                embs.push(e);
            }
        }
    }
    println!(
        "[farbench] embedded {} faces ({} images had no detectable face)",
        embs.len(),
        nodet
    );
    if embs.len() < 2 {
        eprintln!("[farbench] too few embeddings for pairwise stats");
        return std::process::ExitCode::FAILURE;
    }

    // Optional: dump the raw 512-D embeddings (one per line) for offline analysis
    // (e.g. apply a debiasing adapter and recompute FAR per demographic group).
    if let Some(out) = flag(args, "--export") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::File::create(out) {
            for e in &embs {
                let line: Vec<String> = e.iter().map(|v| format!("{v:.6}")).collect();
                let _ = writeln!(f, "{}", line.join(" "));
            }
            println!("[farbench] exported {} embeddings -> {out}", embs.len());
        } else {
            eprintln!("[farbench] export failed to create {out}");
        }
    }

    // All-pairs impostor cosines into a histogram over [-1, 1] (bin width 0.001).
    const BINS: usize = 2000;
    let mut hist = vec![0u64; BINS];
    let mut total: u64 = 0;
    let mut sum_c: f64 = 0.0;
    for i in 0..embs.len() {
        for j in (i + 1)..embs.len() {
            let c = irlume_vision::align::cosine(&embs[i], &embs[j]);
            let b = (((c + 1.0) * 0.5 * BINS as f32) as usize).min(BINS - 1);
            hist[b] += 1;
            total += 1;
            sum_c += c as f64;
        }
    }

    // suffix[k] = #pairs in bins >= k, i.e. cos >= -1 + 2k/BINS → FAR numerator.
    let mut suffix = vec![0u64; BINS + 1];
    for k in (0..BINS).rev() {
        suffix[k] = suffix[k + 1] + hist[k];
    }
    let far_at = |t: f32| -> f64 {
        let k = (((t + 1.0) * 0.5 * BINS as f32).ceil() as i64).clamp(0, BINS as i64) as usize;
        suffix[k] as f64 / total as f64
    };
    let pct = |p: f64| -> f32 {
        let target = (p * total as f64) as u64;
        let mut cum = 0u64;
        for (k, &h) in hist.iter().enumerate() {
            cum += h;
            if cum >= target {
                return -1.0 + 2.0 * k as f32 / BINS as f32;
            }
        }
        1.0
    };
    let max_imp = (0..BINS)
        .rev()
        .find(|&k| hist[k] > 0)
        .map(|k| -1.0 + 2.0 * (k as f32 + 1.0) / BINS as f32)
        .unwrap_or(1.0);

    println!(
        "[impostor] pairs={total}  mean {:.3}  p99 {:.3}  p99.9 {:.3}  p99.99 {:.3}  max {:.3}",
        sum_c / total as f64,
        pct(0.99),
        pct(0.999),
        pct(0.9999),
        max_imp
    );
    println!("[FAR sweep]");
    for t in [0.40f32, 0.45, 0.50, 0.55, 0.60] {
        println!(
            "  thr {t:.2}: FAR {:.6}  (1 in {:.0})",
            far_at(t),
            if far_at(t) > 0.0 {
                1.0 / far_at(t)
            } else {
                f64::INFINITY
            }
        );
    }
    let mut t14 = 1.0f32;
    let mut s = 0.30f32;
    while s <= 0.95 {
        if far_at(s) <= 1e-4 {
            t14 = s;
            break;
        }
        s += 0.005;
    }
    println!(
        "[FAR≤1e-4] threshold {t14:.3}  (RGB auth threshold 0.50 → FAR {:.6})",
        far_at(0.50)
    );
    std::process::ExitCode::SUCCESS
}

/// Darken a 112x112x3 RGB chip (simulate low light): pixel *= factor.
fn darken_chip(chip: &[u8], factor: f32) -> Vec<u8> {
    chip.iter()
        .map(|&p| (p as f32 * factor).round().clamp(0.0, 255.0) as u8)
        .collect()
}

/// 3x3 box-blur a 112x112x3 RGB chip (simulate motion/focus blur).
fn blur_chip(chip: &[u8]) -> Vec<u8> {
    let n = 112i32;
    let mut out = chip.to_vec();
    for y in 0..n {
        for x in 0..n {
            for c in 0..3 {
                let (mut sum, mut cnt) = (0u32, 0u32);
                for dy in -1..=1 {
                    for dx in -1..=1 {
                        let (yy, xx) = (y + dy, x + dx);
                        if yy >= 0 && yy < n && xx >= 0 && xx < n {
                            sum += chip[((yy * n + xx) * 3 + c) as usize] as u32;
                            cnt += 1;
                        }
                    }
                }
                out[((y * n + x) * 3 + c) as usize] = (sum / cnt) as u8;
            }
        }
    }
    out
}

/// `irlume normprobe --dir <imgs> --det <yunet> --model <glintr100> [--max N]`
/// Experiment: validate the AdaFace/MagFace feature-norm-as-quality signal on
/// AuraFace. For each face, embed the full chip and degraded (darkened, blurred)
/// versions, comparing the PRE-normalization feature norm. If degraded < full
/// consistently, the norm is a usable quality signal for irlume's fusion.
fn normprobe(args: &[String]) -> std::process::ExitCode {
    let dir = flag(args, "--dir").unwrap_or("");
    let det_path = flag(args, "--det").unwrap_or("models/face_detection_yunet_2023mar.onnx");
    let model = flag(args, "--model").unwrap_or("models/glintr100.onnx");
    let max = flag(args, "--max")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(40);
    if dir.is_empty() {
        eprintln!("usage: irlume normprobe --dir <imgs> [--det Y] [--model G] [--max N]");
        return std::process::ExitCode::from(2);
    }
    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("det load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("emb load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut files = Vec::new();
    collect_images(std::path::Path::new(dir), &mut files);
    files.truncate(max);
    let (mut sf, mut sd, mut sb, mut n) = (0f64, 0f64, 0f64, 0u32);
    let (mut dark_lower, mut blur_lower) = (0u32, 0u32);
    for f in &files {
        let Ok(img) = image::open(f) else { continue };
        let rgb = img.to_rgb8();
        let (w, h) = rgb.dimensions();
        let data = rgb.into_raw();
        let view = irlume_vision::align::RgbView {
            data: &data,
            width: w,
            height: h,
        };
        let Ok(faces) = det.detect(&view) else {
            continue;
        };
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            continue;
        };
        let Ok(chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) else {
            continue;
        };
        let (Ok((_, nf)), Ok((_, nd)), Ok((_, nb))) = (
            emb.embed_with_norm(&chip),
            emb.embed_with_norm(&darken_chip(&chip, 0.35)),
            emb.embed_with_norm(&blur_chip(&chip)),
        ) else {
            continue;
        };
        sf += nf as f64;
        sd += nd as f64;
        sb += nb as f64;
        n += 1;
        if nd < nf {
            dark_lower += 1;
        }
        if nb < nf {
            blur_lower += 1;
        }
    }
    if n == 0 {
        eprintln!("[normprobe] no faces");
        return std::process::ExitCode::FAILURE;
    }
    let (nf, nd, nb) = (sf / n as f64, sd / n as f64, sb / n as f64);
    println!("[normprobe] {n} faces, mean feature norm:");
    println!("  full   {nf:.2}");
    println!(
        "  dark   {nd:.2}  ({:+.1}%, lower in {}/{n} = {:.0}%)",
        (nd - nf) / nf * 100.0,
        dark_lower,
        dark_lower as f32 / n as f32 * 100.0
    );
    println!(
        "  blur   {nb:.2}  ({:+.1}%, lower in {}/{n} = {:.0}%)",
        (nb - nf) / nf * 100.0,
        blur_lower,
        blur_lower as f32 / n as f32 * 100.0
    );
    let verdict = if nd < nf * 0.97 && nb < nf * 0.97 && dark_lower as f32 / n as f32 > 0.8 {
        "✓ feature norm TRACKS quality on AuraFace; usable as a quality signal"
    } else {
        "✗ weak/no correlation; feature norm NOT a reliable quality signal here"
    };
    println!("[normprobe] {verdict}");
    std::process::ExitCode::SUCCESS
}

/// Recursively collect jpg/jpeg/png/bmp files under `dir`.
fn collect_images(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_images(&p, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| {
                matches!(
                    x.to_ascii_lowercase().as_str(),
                    "jpg" | "jpeg" | "png" | "bmp"
                )
            })
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

/// P2 probe: capture RGB + IR and report what the IR stream gives us: mean/min/
/// max brightness (is the emitter illuminating?), and whether YuNet finds a face
/// in each spectrum (the basis for the cross-spectrum liveness cue). Diagnostic,
/// not yet a gate.
fn liveness_probe(args: &[String]) -> std::process::ExitCode {
    let rgb_dev = flag(args, "--rgb").unwrap_or(irlume_camera::DEFAULT_RGB_DEVICE);
    let ir_dev = flag(args, "--ir").unwrap_or(irlume_camera::DEFAULT_IR_DEVICE);
    let Some(det_path) = flag(args, "--det") else {
        eprintln!(
            "usage: irlume liveness --det <yunet.onnx> [--rgb /dev/video0] [--ir /dev/video2]"
        );
        return std::process::ExitCode::from(2);
    };
    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        // RGB
        let rgb = irlume_camera::capture_rgb(rgb_dev)?;
        let rgb_view = irlume_vision::align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        };
        let rgb_faces = det.detect(&rgb_view)?;
        let rgb_top = rgb_faces.iter().map(|f| f.score).fold(0.0f32, f32::max);
        println!(
            "[RGB] {}x{}  faces {}  top score {:.3}",
            rgb.width,
            rgb.height,
            rgb_faces.len(),
            rgb_top
        );
        // IR. Taken with stats rather than bare, because the exposure gate
        // needs the negotiated format's ceiling and `capture_ir` is literally
        // `capture_ir_with_stats(..)?.0`, so the burst already happened and the
        // plain call was only throwing the answer away (#358 review).
        let (ir, ir_stats) = irlume_camera::capture_ir_with_stats(ir_dev)?;
        let (mn, mx, sum) = ir.data.iter().fold((255u8, 0u8, 0u64), |(mn, mx, s), &p| {
            (mn.min(p), mx.max(p), s + p as u64)
        });
        let mean = sum as f64 / ir.data.len() as f64;
        println!(
            "[IR ] {}x{}  brightness mean {:.1} min {} max {}",
            ir.width, ir.height, mean, mn, mx
        );
        let ir_rgb = irlume_camera::grey_to_rgb(&ir.data);
        let ir_view = irlume_vision::align::RgbView {
            data: &ir_rgb,
            width: ir.width,
            height: ir.height,
        };
        let ir_faces = det.detect(&ir_view)?;
        let ir_top_face = ir_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));
        println!(
            "[IR ] faces {}  top score {:.3}",
            ir_faces.len(),
            ir_top_face.map_or(0.0, |f| f.score)
        );

        // Build signals for the gate.
        let to_fbox = |f: &irlume_vision::Detection, w: u32, h: u32| irlume_liveness::FaceBox {
            cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
            cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
            score: f.score,
        };
        let ir_face_brightness = ir_top_face
            .map(|f| mean_in_bbox(&ir.data, ir.width, ir.height, &f.bbox))
            .unwrap_or(0.0);
        let ir_center_edge_ratio = ir_top_face
            .map(|f| center_edge_ratio(&ir.data, ir.width, ir.height, &f.bbox))
            .unwrap_or(0.0);
        // Ceiling-aware, the same call `padcapture` makes. The comment here used
        // to say no white level was known, which was true while this probe
        // captured without burst stats; it takes them now (#358), so the ceiling
        // is in scope and there is no reason left to read the peak raw.
        //
        // Measured 2026-08-08 on the ASUS FHD IR module: with glasses on, ten
        // consecutive probes read the eye-window peak at exactly 255, the
        // format's ceiling. Read raw, every one of those reported as the
        // STRONGEST POSSIBLE glint, which is the conflation #222 removed from
        // the auth path and the corpus. The tool a developer opens to diagnose a
        // glint problem was the one place still giving the old answer.
        let ir_eye_glint = irlume_auth::eye_glint_of(
            ir_stats.saturation_frame.as_deref().unwrap_or(&ir.data),
            ir.width,
            ir.height,
            ir_top_face.map(|f| &f.landmarks),
            ir_stats.white_level,
        );
        let rgb_top = rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));
        let pose = rgb_top.map(|f| irlume_vision::head_pose(&f.landmarks));
        let signals = irlume_liveness::Signals {
            rgb_face: rgb_top.map(|f| to_fbox(f, rgb.width, rgb.height)),
            ir_face: ir_top_face.map(|f| to_fbox(f, ir.width, ir.height)),
            ir_face_brightness,
            ir_center_edge_ratio,
            ir_eye_glint,
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            ir_ambient: 0.0, // dev gate probe: single frame, no burst stats
            face_frac: ir_top_face
                .map(|f| irlume_auth::bbox_width_frac(&f.bbox, ir.width))
                .unwrap_or(0.0),
            // Measured the same way the auth path and `padcapture` measure it,
            // off the same burst stats, so this probe judges the frame instead
            // of refusing it.
            //
            // Hardcoding `None`/`false` here was wrong twice over: the ceiling
            // is a property of the negotiated format, not of the burst, and the
            // burst existed anyway. It made `evaluate` return at the exposure
            // gate before `ir_reflectance_ok`, `center_edge_ratio_ok` and
            // `glint_present` were ever assigned, so the cue line printed three
            // constants and the probe told the operator that a GREY camera
            // whose ceiling is 255 defines no ceiling (#358 review).
            //
            // Raw frame, not the subtracted one: ambient subtraction moves a
            // railed 255 to 254 and hides the clipping this measures.
            ir_saturated_frac: irlume_auth::saturated_frac_of(
                ir_stats.saturation_frame.as_deref().unwrap_or(&ir.data),
                ir.width,
                ir.height,
                ir_top_face.map(|f| &f.bbox),
                ir_stats.white_level,
            ),
            ir_persistent_saturated_frac: ir_stats.persistent_saturated_frac,
            ir_ceiling_known: ir_stats.white_level.is_some(),
            rgb_face_brightness: 0.0,
            rgb_specular_frac: 0.0,
            rgb_moire_score: 0.0,
        };
        let (verdict, cues, reason) = irlume_liveness::LivenessGate::new().evaluate(&signals);
        println!("[gate] IR face brightness {ir_face_brightness:.0}  center/edge {ir_center_edge_ratio:.2}  eye-glint {}  face_frac {:.3}  clipped {}",
            signals
                .ir_eye_glint
                .map(|g| format!("{g:.0}"))
                .unwrap_or_else(|| "n/a".into()),
            signals.face_frac,
            signals
                .ir_saturated_frac
                .map(|f| format!("{:.1}%", f * 100.0))
                .unwrap_or_else(|| "n/a".into()));
        println!(
            "[gate] cues: rgb={} ir={} aligned={} ir_reflective={} center_edge={} glint={} glint_readable={}",
            cues.face_in_rgb,
            cues.face_in_ir,
            cues.cross_spectrum_aligned,
            cues.ir_reflectance_ok,
            cues.center_edge_ratio_ok,
            cues.glint_present,
            cues.glint_readable
        );
        println!("[GATE] {verdict:?}: {reason}");
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("liveness probe error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Capture several frames of the (one) live person, embed each, and report the
/// GENUINE cosine distribution. Compared to the impostor ceiling (~0.42 from
/// `eval`), this shows the separation and lets us set the operating threshold.
fn genuine(args: &[String]) -> std::process::ExitCode {
    let device = flag(args, "--device").unwrap_or("/dev/video0");
    let (Some(det_path), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume genuine --det <yunet.onnx> --model <glintr100.onnx>");
        return std::process::ExitCode::from(2);
    };
    const FRAMES: usize = 5;
    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let mut embs = Vec::new();
        println!("[genuine] stay in frame; capturing {FRAMES} frames…");
        for k in 0..FRAMES {
            let f = irlume_camera::capture_rgb(device)?;
            let view = irlume_vision::align::RgbView {
                data: &f.data,
                width: f.width,
                height: f.height,
            };
            let faces = det.detect(&view)?;
            match faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
                Some(top) => {
                    let chip = irlume_vision::align::align_to_arcface(&view, &top.landmarks)?;
                    embs.push(emb.embed(&chip)?);
                    println!("  frame {}: face score {:.3}", k + 1, top.score);
                }
                None => println!("  frame {}: no face", k + 1),
            }
        }
        if embs.len() < 2 {
            println!("[genuine] need >=2 frames with a face; re-run staying in view.");
            return Ok(());
        }
        let mut scores = Vec::new();
        for i in 0..embs.len() {
            for j in (i + 1)..embs.len() {
                scores.push(irlume_vision::align::cosine(&embs[i], &embs[j]));
            }
        }
        scores.sort_by(f32::total_cmp);
        let mean = scores.iter().sum::<f32>() / scores.len() as f32;
        println!(
            "[genuine] {} pairs: min {:.3}  mean {:.3}  max {:.3}",
            scores.len(),
            scores[0],
            mean,
            scores[scores.len() - 1]
        );
        let impostor_max = 0.423;
        println!("  impostor max (from eval): {impostor_max:.3}");
        if scores[0] > impostor_max {
            let mid = (scores[0] + impostor_max) / 2.0;
            println!(
                "  ✓ SEPARABLE: genuine min {:.3} > impostor max {:.3}; midpoint threshold ≈ {:.3}",
                scores[0], impostor_max, mid
            );
        } else {
            println!("  ⚠ overlap: genuine min {:.3} ≤ impostor max; needs better alignment/lighting or more varied scans (e.g. glasses, angles) on the profile",
                scores[0]);
        }
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("genuine error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume calcapture --user U --det <yunet> --model <glintr100> [--adapter <ir>]
///   [--rgb /dev/video0] [--ir /dev/video2] [--n 40] [--tag bright] --out cal.jsonl`
///
/// REAL-ASUS calibration/validation capture: direct camera access (run with the
/// daemon stopped to avoid EBUSY). Grabs N live RGB+IR samples of the enrolled
/// user and, per sample, records the genuine cosine vs the user's own templates
/// (RGB TTA-512 space; IR in the deployed v1-adapter space) plus face brightness
/// and the RAW 512-D RGB and IR embeddings. The dump feeds two offline jobs:
///   #3 Platt recalibration: real genuine RGB/IR cosine+brightness distribution
///      (the academic-fit consts in fusion.rs are a prior; this is ground truth);
///   #4 adapter-v3 validation: raw IR embeddings re-scored through v1 vs the
///      banked residZero+ASnorm adapter, with academic impostors, before deploy.
/// Capture across lighting with `--tag bright` now and `--tag dim` at sunset.
fn calcapture(args: &[String]) -> std::process::ExitCode {
    let user = user_arg(args);
    let (Some(det_path), Some(model), Some(out)) = (
        flag(args, "--det"),
        flag(args, "--model"),
        flag(args, "--out"),
    ) else {
        eprintln!("usage: irlume calcapture --user U --det <yunet.onnx> --model <glintr100.onnx> --out <cal.jsonl> [--adapter <ir.onnx>] [--rgb /dev/video0] [--ir /dev/video2] [--n 40] [--tag bright]");
        return std::process::ExitCode::from(2);
    };
    let rgb_dev = flag(args, "--rgb").unwrap_or("/dev/video0");
    let ir_dev = flag(args, "--ir").unwrap_or("/dev/video2");
    let n: usize = flag(args, "--n").and_then(|s| s.parse().ok()).unwrap_or(40);
    let tag = flag(args, "--tag").unwrap_or("untagged").to_string();

    // mean luma (RGB, BT.601) / mean grey (IR) inside a detector bbox, clamped.
    let mean_bbox = |data: &[u8], w: u32, h: u32, ch: usize, bbox: &[f32; 4]| -> f32 {
        let (x1, y1) = (bbox[0].max(0.0) as u32, bbox[1].max(0.0) as u32);
        let (x2, y2) = ((bbox[2] as u32).min(w), (bbox[3] as u32).min(h));
        if x2 <= x1 || y2 <= y1 {
            return 0.0;
        }
        let (mut sum, mut cnt) = (0.0f64, 0u64);
        for y in y1..y2 {
            for x in x1..x2 {
                let i = ((y * w + x) as usize) * ch;
                let v = if ch == 3 {
                    0.299 * data[i] as f32 + 0.587 * data[i + 1] as f32 + 0.114 * data[i + 2] as f32
                } else {
                    data[i] as f32
                };
                sum += v as f64;
                cnt += 1;
            }
        }
        if cnt == 0 {
            0.0
        } else {
            (sum / cnt as f64) as f32
        }
    };

    // Luma at (x, y) for 3-channel RGB or 1-channel grey data.
    let luma = |data: &[u8], w: u32, ch: usize, x: u32, y: u32| -> f32 {
        let i = ((y * w + x) as usize) * ch;
        if ch == 3 {
            0.299 * data[i] as f32 + 0.587 * data[i + 1] as f32 + 0.114 * data[i + 2] as f32
        } else {
            data[i] as f32
        }
    };

    // Fraction of pixels at/above 250 (near clipping) across the whole frame:
    // the saturated-background signature that blinds detection outdoors.
    let sat_pct = |data: &[u8], w: u32, h: u32, ch: usize| -> f32 {
        let (mut sat, mut cnt) = (0u64, 0u64);
        for y in 0..h {
            for x in 0..w {
                if luma(data, w, ch, x, y) >= 250.0 {
                    sat += 1;
                }
                cnt += 1;
            }
        }
        if cnt == 0 {
            0.0
        } else {
            sat as f32 / cnt as f32
        }
    };

    // Sharpness: variance of the 3x3 Laplacian inside the face bbox (the
    // standard blur/focus measure; low = defocused or motion-smeared sample).
    let laplacian_var_bbox = |data: &[u8], w: u32, h: u32, ch: usize, bbox: &[f32; 4]| -> f32 {
        let (x1, y1) = (bbox[0].max(1.0) as u32, bbox[1].max(1.0) as u32);
        let (x2, y2) = (
            (bbox[2] as u32).min(w.saturating_sub(1)),
            (bbox[3] as u32).min(h.saturating_sub(1)),
        );
        if x2 <= x1 || y2 <= y1 {
            return 0.0;
        }
        let (mut sum, mut sum2, mut cnt) = (0.0f64, 0.0f64, 0u64);
        for y in y1..y2 {
            for x in x1..x2 {
                let lap = 4.0 * luma(data, w, ch, x, y)
                    - luma(data, w, ch, x - 1, y)
                    - luma(data, w, ch, x + 1, y)
                    - luma(data, w, ch, x, y - 1)
                    - luma(data, w, ch, x, y + 1);
                sum += lap as f64;
                sum2 += (lap * lap) as f64;
                cnt += 1;
            }
        }
        if cnt == 0 {
            0.0
        } else {
            let mean = sum / cnt as f64;
            (sum2 / cnt as f64 - mean * mean) as f32
        }
    };

    // Face contrast: p90 - p10 luma spread inside the bbox. A dim-but-usable
    // face keeps its spread; a flat backlit face (the "IR face too dark"
    // failure axis) loses it, which mean brightness alone cannot show.
    let contrast_bbox = |data: &[u8], w: u32, h: u32, ch: usize, bbox: &[f32; 4]| -> f32 {
        let (x1, y1) = (bbox[0].max(0.0) as u32, bbox[1].max(0.0) as u32);
        let (x2, y2) = ((bbox[2] as u32).min(w), (bbox[3] as u32).min(h));
        if x2 <= x1 || y2 <= y1 {
            return 0.0;
        }
        let mut v: Vec<f32> = (y1..y2)
            .flat_map(|y| (x1..x2).map(move |x| (x, y)))
            .map(|(x, y)| luma(data, w, ch, x, y))
            .collect();
        v.sort_by(f32::total_cmp);
        v[(v.len() - 1) * 9 / 10] - v[(v.len() - 1) / 10]
    };

    // 5-point landmarks flattened to [x0,y0,...,x4,y4] + inter-ocular pixel
    // distance (the distance-to-camera proxy; landmarks 0,1 are the eyes).
    let lm_flat = |lm: &irlume_vision::Landmarks5| -> Vec<f32> {
        lm.iter().flat_map(|&(x, y)| [x, y]).collect()
    };
    let iod_px = |lm: &irlume_vision::Landmarks5| -> f32 {
        ((lm[1].0 - lm[0].0).powi(2) + (lm[1].1 - lm[0].1).powi(2)).sqrt()
    };

    let run = || -> irlume_common::Result<usize> {
        // Enrolled templates are encrypted at rest (TPM-sealed key, root-only), so a
        // user-space run can't decrypt them. That's fine: we always dump the raw
        // embeddings and derive genuine cosines pairwise among the captures offline.
        // When templates ARE available (run as root, daemon stopped) we additionally
        // record the true probe-vs-enrolled cosine.
        let enr = match irlume_core::storage::load(&user) {
            Ok(Some(e)) => Some(e),
            Ok(None) => {
                eprintln!("[calcapture] note: '{user}' not enrolled; cosines from pairwise only");
                None
            }
            Err(e) => {
                eprintln!(
                    "[calcapture] note: templates unavailable ({e}); cosines from pairwise only"
                );
                None
            }
        };
        let rgb_scans = enr.as_ref().map(|e| e.rgb_scans()).unwrap_or_default();
        let ir_scans = enr.as_ref().map(|e| e.ir_scans()).unwrap_or_default();
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let mut adapter = match flag(args, "--adapter") {
            Some(p) => Some(irlume_vision::Adapter::load_from_file(p)?),
            None => None,
        };
        let best = |probe: &[f32], scans: &[(&str, &str, &[f32])]| -> f32 {
            scans
                .iter()
                .map(|(_, _, t)| irlume_vision::align::cosine(probe, t))
                .fold(f32::NEG_INFINITY, f32::max)
        };
        let mut f =
            std::fs::File::create(out).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
        use std::io::Write;
        println!("[calcapture] user={user} tag={tag} n={n} -> {out}");
        println!(
            "[calcapture] rgb_templates={} ir_templates={} adapter={}",
            rgb_scans.len(),
            ir_scans.len(),
            if adapter.is_some() { "yes" } else { "no" }
        );
        println!("[calcapture] sit naturally in frame; vary pose slightly between samples.");

        // Session header (first line): hardware + model provenance, so the
        // dataset self-documents which sensor and which recognizer produced
        // the embeddings. Loaders that want samples skip records without
        // embedding fields. sha256 prefixes match the space-tagging scheme.
        let file_sha12 = |p: &str| -> serde_json::Value {
            match std::fs::read(p) {
                Ok(b) => {
                    let d = irlume_common::sha256_hex(&b);
                    d[..12].to_string().into()
                }
                Err(_) => serde_json::Value::Null,
            }
        };
        let epoch = || -> f64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        };
        let mut hdr = serde_json::Map::new();
        hdr.insert("session".into(), true.into());
        hdr.insert("user".into(), user.clone().into());
        hdr.insert("tag".into(), tag.clone().into());
        hdr.insert("n".into(), n.into());
        hdr.insert(
            "host".into(),
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
                .into(),
        );
        hdr.insert(
            "rgb_camera".into(),
            irlume_camera::device_identity(rgb_dev)
                .unwrap_or_else(|| rgb_dev.to_string())
                .into(),
        );
        hdr.insert(
            "ir_camera".into(),
            irlume_camera::device_identity(ir_dev)
                .unwrap_or_else(|| ir_dev.to_string())
                .into(),
        );
        hdr.insert(
            "irlume_version".into(),
            env!("CARGO_PKG_VERSION").to_string().into(),
        );
        hdr.insert("det_sha256".into(), file_sha12(det_path));
        hdr.insert("model_sha256".into(), file_sha12(model));
        hdr.insert(
            "adapter_sha256".into(),
            flag(args, "--adapter")
                .map(file_sha12)
                .unwrap_or(serde_json::Value::Null),
        );
        hdr.insert("ts_unix".into(), epoch().into());
        writeln!(f, "{}", serde_json::Value::Object(hdr))
            .map_err(|e| irlume_common::Error::Io(e.to_string()))?;

        let mut written = 0usize;
        let t0 = std::time::Instant::now();
        for idx in 0..n {
            // RGB (median-denoised, matches the auth path) + IR (brightest-of-burst).
            let rgbf = irlume_camera::capture_rgb_denoised(rgb_dev)?;
            let rv = irlume_vision::align::RgbView {
                data: &rgbf.data,
                width: rgbf.width,
                height: rgbf.height,
            };
            let rgb_top = det
                .detect(&rv)?
                .into_iter()
                .max_by(|a, b| a.score.total_cmp(&b.score));

            let (irf, ir_stats) = irlume_camera::capture_ir_with_stats(ir_dev)?;
            let ir_rgb = irlume_camera::grey_to_rgb(&irf.data);
            let iv = irlume_vision::align::RgbView {
                data: &ir_rgb,
                width: irf.width,
                height: irf.height,
            };
            let ir_top = det
                .detect(&iv)?
                .into_iter()
                .max_by(|a, b| a.score.total_cmp(&b.score));

            let mut rec = serde_json::Map::new();
            rec.insert("idx".into(), idx.into());
            rec.insert("tag".into(), tag.clone().into());
            // Wall clock since the first sample: real capture cadence (the
            // per-sample rate is camera-I/O-bound and varies with USB load).
            rec.insert(
                "elapsed_ms".into(),
                json_f32(t0.elapsed().as_secs_f32() * 1000.0),
            );
            // Whole-frame saturation: fraction of pixels at/above 250. High
            // values are the outdoor failure signature (saturated background
            // blinding the detector), worth stratifying training data by.
            rec.insert(
                "rgb_sat_pct".into(),
                json_f32(sat_pct(&rgbf.data, rgbf.width, rgbf.height, 3)),
            );
            rec.insert(
                "ir_sat_pct".into(),
                json_f32(sat_pct(&irf.data, irf.width, irf.height, 1)),
            );
            // Capture resolution per modality: the driver may deliver a
            // different mode than requested, and detection/sharpness numbers
            // only compare across samples of the same resolution.
            rec.insert("rgb_res".into(), vec![rgbf.width, rgbf.height].into());
            rec.insert("ir_res".into(), vec![irf.width, irf.height].into());
            rec.insert("ts_unix".into(), epoch().into());
            // Per-capture ambient IR from the burst's darkest (emitter-off)
            // frame, and the strobe gap: the ambient-relative gate's inputs,
            // only observable at capture time.
            rec.insert("ir_ambient".into(), json_f32(ir_stats.ambient_mean));
            rec.insert(
                "ir_strobe_gap".into(),
                json_f32(ir_stats.lit_mean - ir_stats.ambient_mean),
            );

            let (mut rgb_cos, mut rgb_bri) = (f32::NAN, 0.0f32);
            if let Some(t) = &rgb_top {
                let chip = irlume_vision::align::align_to_arcface(&rv, &t.landmarks)?;
                let e = emb.embed_tta(&chip)?; // RGB path = TTA flip-average
                rgb_bri = mean_bbox(&rgbf.data, rgbf.width, rgbf.height, 3, &t.bbox);
                if !rgb_scans.is_empty() {
                    rgb_cos = best(&e, &rgb_scans);
                }
                rec.insert("rgb_face_score".into(), json_f32(t.score));
                rec.insert("rgb_cos".into(), json_f32(rgb_cos));
                rec.insert("rgb_brightness".into(), json_f32(rgb_bri));
                rec.insert(
                    "rgb_sharpness".into(),
                    json_f32(laplacian_var_bbox(
                        &rgbf.data,
                        rgbf.width,
                        rgbf.height,
                        3,
                        &t.bbox,
                    )),
                );
                rec.insert(
                    "rgb_contrast".into(),
                    json_f32(contrast_bbox(
                        &rgbf.data,
                        rgbf.width,
                        rgbf.height,
                        3,
                        &t.bbox,
                    )),
                );
                rec.insert(
                    "rgb_bbox".into(),
                    serde_json::to_value(t.bbox.to_vec()).unwrap(),
                );
                rec.insert(
                    "rgb_landmarks".into(),
                    serde_json::to_value(lm_flat(&t.landmarks)).unwrap(),
                );
                rec.insert("rgb_iod_px".into(), json_f32(iod_px(&t.landmarks)));
                rec.insert("rgb_emb".into(), serde_json::to_value(e.to_vec()).unwrap());
            }
            rec.insert("rgb_present".into(), rgb_top.is_some().into());

            let (mut ir_cos, mut ir_bri, mut ir_center_edge_ratio) = (f32::NAN, 0.0f32, 0.0f32);
            // `Option`, because a railed peak is not a dim eye. See the swap below.
            let mut ir_glint: Option<f32> = None;
            if let Some(t) = &ir_top {
                let chip = irlume_vision::align::align_to_arcface(&iv, &t.landmarks)?;
                let raw = emb.embed(&chip)?; // IR = plain embed (no TTA), RAW 512-D
                ir_bri = mean_bbox(&irf.data, irf.width, irf.height, 1, &t.bbox);
                // Ambient-INDEPENDENT liveness cues (the center/edge-floor candidates):
                // center/edge IR ratio (3D face structure) and corneal glint peak.
                ir_center_edge_ratio =
                    irlume_auth::center_edge_ratio(&irf.data, irf.width, irf.height, &t.bbox);
                // `eye_glint_of` on the RAW frame with the negotiated ceiling, the
                // same pair the daemon and `pad.rs` already pass. `eye_glint`
                // returns the window maximum, and a maximum that reached the
                // ceiling says the true value was at least that and never what
                // it was: with glasses on, the repo's own measurements pin this
                // peak at 255 in all 30 frames, where it reads the lens
                // specular rather than the cornea (#222).
                //
                // Raw and not `irf.data`, because ambient subtraction moves a
                // railed 255 to 254 and a subtracted frame stops reading as
                // railed, which would silently disable the refusal (#238 review).
                ir_glint = irlume_auth::eye_glint_of(
                    ir_stats.saturation_frame.as_deref().unwrap_or(&irf.data),
                    irf.width,
                    irf.height,
                    Some(&t.landmarks),
                    ir_stats.white_level,
                );
                if let Some(a) = adapter.as_mut() {
                    let adapted = a.apply(&raw)?;
                    if !ir_scans.is_empty() {
                        ir_cos = best(&adapted, &ir_scans);
                    }
                }
                rec.insert("ir_face_score".into(), json_f32(t.score));
                rec.insert("ir_cos_v1".into(), json_f32(ir_cos));
                rec.insert("ir_brightness".into(), json_f32(ir_bri));
                rec.insert(
                    "ir_sharpness".into(),
                    json_f32(laplacian_var_bbox(
                        &irf.data, irf.width, irf.height, 1, &t.bbox,
                    )),
                );
                rec.insert(
                    "ir_contrast".into(),
                    json_f32(contrast_bbox(&irf.data, irf.width, irf.height, 1, &t.bbox)),
                );
                rec.insert(
                    "ir_bbox".into(),
                    serde_json::to_value(t.bbox.to_vec()).unwrap(),
                );
                rec.insert(
                    "ir_landmarks".into(),
                    serde_json::to_value(lm_flat(&t.landmarks)).unwrap(),
                );
                rec.insert("ir_iod_px".into(), json_f32(iod_px(&t.landmarks)));
                rec.insert(
                    "ir_center_edge_ratio".into(),
                    json_f32(ir_center_edge_ratio),
                );
                // `null` is unambiguous here in a way it is not elsewhere: this
                // key is written only inside the `if let Some(t) = &ir_top`
                // branch, so a missing IR face leaves it ABSENT with
                // `ir_present: false` beside it. Written, `null` can only mean
                // the peak reached the ceiling (#222).
                rec.insert(
                    "ir_glint".into(),
                    ir_glint.map_or(serde_json::Value::Null, json_f32),
                );
                rec.insert(
                    "ir_emb_raw".into(),
                    serde_json::to_value(raw.to_vec()).unwrap(),
                );
            }
            rec.insert("ir_present".into(), ir_top.is_some().into());

            writeln!(f, "{}", serde_json::Value::Object(rec))
                .map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            written += 1;
            println!(
                "  [{:>2}/{n}] rgb {} bri {:>5.1} | ir {} bri {:>5.1} c/e {:>5.2} glint {:>6}",
                idx + 1,
                if rgb_top.is_some() { "✓" } else { "·" },
                rgb_bri,
                if ir_top.is_some() { "✓" } else { "·" },
                ir_bri,
                ir_center_edge_ratio,
                format_ir_glint(ir_top.is_some(), ir_glint)
            );
        }
        Ok(written)
    };
    match run() {
        Ok(w) => {
            println!("[calcapture] wrote {w} samples to {out}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("calcapture error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// JSON number from an f32, mapping non-finite to JSON null (so `NaN` for an
/// absent cosine round-trips cleanly instead of breaking the encoder).
/// The console trace's glint field, as a value a test can observe.
///
/// Three states, and the first two used to be one. `ir_glint` starts `None` and
/// stays `None` when no IR face was detected, so mapping `None` straight to
/// "railed" told a reader the peak reached the ceiling on frames where no eye
/// was ever sampled.
///
/// Returned as a plain string with a WIDTH and no precision. `{:>3.0}` was the
/// old numeric spec, and precision on a non-numeric argument is a maximum
/// output width rather than a decimal count, so `.0` truncated every value to
/// nothing and printed an empty field for readings and refusals alike (#398
/// review).
fn format_ir_glint(ir_present: bool, glint: Option<f32>) -> String {
    match (ir_present, glint) {
        (false, _) => "n/a".to_string(),
        (true, None) => "railed".to_string(),
        (true, Some(g)) => format!("{g:.1}"),
    }
}

fn json_f32(x: f32) -> serde_json::Value {
    serde_json::Number::from_f64(x as f64)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null)
}

/// Embed every detected face in an image and report the pairwise-cosine
/// distribution. In a group photo every pair is a different person, so this is
/// the IMPOSTOR distribution: it validates AuraFace discriminates (impostors
/// should score low) and sets the threshold floor (must sit above impostor max).
fn eval(args: &[String]) -> std::process::ExitCode {
    let (Some(img), Some(det_path), Some(model)) = (
        flag(args, "--image"),
        flag(args, "--det"),
        flag(args, "--model"),
    ) else {
        eprintln!(
            "usage: irlume eval --image <group.jpg> --det <yunet.onnx> --model <glintr100.onnx>"
        );
        return std::process::ExitCode::from(2);
    };
    let rgb = match image::open(img) {
        Ok(i) => i.to_rgb8(),
        Err(e) => {
            eprintln!("image load failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let (w, h) = rgb.dimensions();
    let data = rgb.into_raw();
    let view = irlume_vision::align::RgbView {
        data: &data,
        width: w,
        height: h,
    };

    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let grey = args.iter().any(|a| a == "--grey");
        let faces = det.detect(&view)?;
        println!(
            "[eval] {} faces; embedding each{}…",
            faces.len(),
            if grey { " (GREYSCALE / IR-proxy)" } else { "" }
        );
        let mut embs = Vec::new();
        for f in &faces {
            let mut chip = irlume_vision::align::align_to_arcface(&view, &f.landmarks)?;
            if grey {
                // Simulate the IR modality: drop colour, keep luminance (BT.601),
                // replicate to 3 channels. Isolates AuraFace's colour-removal loss.
                for px in chip.chunks_exact_mut(3) {
                    let y =
                        (0.299 * px[0] as f32 + 0.587 * px[1] as f32 + 0.114 * px[2] as f32) as u8;
                    px[0] = y;
                    px[1] = y;
                    px[2] = y;
                }
            }
            embs.push(emb.embed(&chip)?);
        }
        // All pairwise cosines = impostor scores (distinct people).
        let mut scores = Vec::new();
        for i in 0..embs.len() {
            for j in (i + 1)..embs.len() {
                scores.push(irlume_vision::align::cosine(&embs[i], &embs[j]));
            }
        }
        if scores.is_empty() {
            println!("[eval] need >=2 faces for pairwise stats.");
            return Ok(());
        }
        scores.sort_by(f32::total_cmp);
        let n = scores.len();
        let mean = scores.iter().sum::<f32>() / n as f32;
        let pct = |p: f32| scores[((p * (n - 1) as f32).round() as usize).min(n - 1)];
        println!("[eval] impostor pairs: {n}");
        println!(
            "  min {:.3}  mean {:.3}  p95 {:.3}  p99 {:.3}  max {:.3}",
            scores[0],
            mean,
            pct(0.95),
            pct(0.99),
            scores[n - 1]
        );
        println!(
            "  => threshold floor (above impostor max): {:.3}",
            scores[n - 1] + 0.02
        );
        println!("  (genuine pairs of the same person across 2 captures set the ceiling; run two `capture` sessions to measure.)");
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eval error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// TPM character device the kernel exposes, if any (resource-managed preferred).
pub(crate) fn tpm_device() -> Option<&'static str> {
    ["/dev/tpmrm0", "/dev/tpm0"]
        .into_iter()
        .find(|d| std::path::Path::new(d).exists())
}

/// What irlumed reported about its TPM ([`irlume_common::Request::TpmReadiness`]), each part
/// read or the reason it was not.
struct TpmReport {
    identity: Result<irlume_common::tpm_readiness::TpmIdentity, String>,
    pcr_bank: Result<irlume_common::tpm_readiness::PcrBankReadiness, String>,
    storage_key: Result<irlume_common::tpm_readiness::StorageKeyCheck, String>,
    lockout: Result<irlume_common::tpm_readiness::TpmLockout, String>,
    da_exempt_key: Result<irlume_common::tpm_readiness::DaExemptKey, String>,
    storage_keys: Result<Vec<irlume_common::tpm_readiness::StorageKeyEntry>, String>,
}

/// Ask irlumed for its TPM readiness. Every way of getting no report (an
/// older daemon, an absent one, a refusal, an unreadable reply) leaves each
/// part unread with the reason, and nothing here opens the TPM.
fn tpm_readiness(
    ask: impl FnOnce(&irlume_common::Request) -> std::io::Result<irlume_common::Response>,
) -> TpmReport {
    use irlume_common::Response;
    let reason = match ask(&irlume_common::Request::TpmReadiness) {
        Ok(Response::TpmReadiness {
            identity,
            pcr_bank,
            storage_key,
            lockout,
            da_exempt_key,
            storage_keys,
        }) => {
            return TpmReport {
                identity,
                pcr_bank,
                storage_key,
                lockout,
                da_exempt_key,
                storage_keys,
            }
        }
        Ok(Response::Error(error)) if error == "bad request" => {
            "this irlumed predates the TPM readiness report".to_owned()
        }
        Ok(Response::Error(error)) => format!("irlumed: {error}"),
        Err(error) if irlume_common::client::proves_daemon_absent(&error) => {
            "irlumed is not running".to_owned()
        }
        Err(error) => format!("irlumed's reply could not be read: {error}"),
        Ok(_) => "irlumed returned an unexpected reply".to_owned(),
    };
    TpmReport {
        identity: Err(reason.clone()),
        pcr_bank: Err(reason.clone()),
        storage_key: Err(reason.clone()),
        lockout: Err(reason.clone()),
        da_exempt_key: Err(reason.clone()),
        storage_keys: Err(reason),
    }
}

/// The `tpm-firmware` check: the TPM's maker and firmware version, any
/// published advisory for that version, and whether irlume's storage key
/// carries the ROCA fingerprint, which a later firmware update does not
/// remove.
fn tpm_firmware_check(
    identity: &Result<irlume_core::tpm::TpmIdentity, String>,
    storage_key: &Result<irlume_core::tpm::StorageKeyCheck, String>,
) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    use irlume_core::tpm::{DerivedKey, FirmwareAdvisory, StorageKeyCheck};
    let describe = |id: &irlume_core::tpm::TpmIdentity| {
        let (major, minor) = id.firmware;
        let vendor = if id.vendor.is_empty() || id.vendor == id.manufacturer {
            String::new()
        } else {
            format!(" {}", id.vendor)
        };
        format!("{}{vendor}, firmware {major}.{minor}", id.manufacturer)
    };
    // A weak storage key is reported even when the TPM's identity was not read.
    if let Ok(StorageKeyCheck::RocaFingerprint { handle, derived }) = storage_key {
        let what = identity
            .as_ref()
            .map_or_else(|_| String::new(), |id| format!("{}: ", describe(id)));
        let evict = format!(
            "from the persistent handle irlumed read it at, {handle:#010x}, on the TPM \
             irlumed uses (pass its IRLUME_TCTI with `-T` if it sets one), for example \
             `sudo tpm2_evictcontrol -C o -c {handle:#010x}`, so the next seal derives a \
             new one. Face login then needs `irlume recovery restore` or a \
             re-enrollment, and the keyring secret reseals at the next password login. \
             Do not clear the whole TPM for this: that also drops every other key \
             sealed in it, such as a disk's"
        );
        let detail = match derived {
            Some(DerivedKey::Same) => format!(
                "{what}irlume's storage key carries the ROCA fingerprint \
                 (CVE-2017-15361). It was generated by a vulnerable Infineon library and \
                 stays weak whatever the firmware is now. Update the TPM firmware with the \
                 machine vendor's tool, then evict only irlume's key {evict}"
            ),
            // The key irlume derived before a firmware update fixed the key
            // generation no longer matches: that is the key to evict.
            Some(DerivedKey::Unaffected) => format!(
                "{what}irlume's storage key carries the ROCA fingerprint \
                 (CVE-2017-15361), but the TPM now derives a key without it from irlume's \
                 template, as it does once a firmware update has fixed its key generation, \
                 so this key most likely dates from before that update; it stays weak. \
                 Unless another tool placed it there and still uses it (`tpm2_readpublic \
                 -c {handle:#010x}` shows it), evict it {evict}"
            ),
            // irlume seals under it, but did not (or could not show it did)
            // derive it: no eviction command for a key another tool may use.
            Some(DerivedKey::Other) | None => {
                let why = if derived.is_some() {
                    "it is not the key irlume's template derives there: another tool may \
                     have placed it"
                } else {
                    "irlume could not derive its own key to compare, so another tool may \
                     have placed it"
                };
                format!(
                    "{what}the storage key at irlume's persistent handle {handle:#010x} \
                     carries the ROCA fingerprint (CVE-2017-15361), and irlume seals under \
                     it, but {why}. Update the TPM firmware with the machine vendor's \
                     tool, and find what else uses that key before removing it \
                     (`tpm2_readpublic -c {handle:#010x}`, on the TPM irlumed uses: pass \
                     its IRLUME_TCTI with `-T` if it sets one). Do not clear the whole TPM \
                     for this: that also drops every other key sealed in it, such as a \
                     disk's"
                )
            }
        };
        return (State::Warn, detail);
    }
    let id = match identity {
        Ok(id) => id,
        Err(e) => return (State::Unknown, format!("TPM not read: {e}")),
    };
    let what = describe(id);
    // On an Infineon part the firmware version alone does not show whether a
    // key generated before an update is still in use.
    if let (None, "IFX", Err(e)) = (id.advisory(), id.manufacturer.as_str(), storage_key) {
        return (
            State::Unknown,
            format!(
                "{what}: firmware past the ROCA range, but irlume's storage key could not \
                 be checked ({e}), and a key generated before an update stays weak"
            ),
        );
    }
    match id.advisory() {
        Some(FirmwareAdvisory::Roca) => (
            State::Warn,
            format!(
                "{what}: listed for CVE-2017-15361 (ROCA): it generates weak RSA keys, and \
                 irlume's storage key is one; update the TPM firmware with the machine \
                 vendor's tool and follow its guidance on regenerating keys"
            ),
        ),
        Some(FirmwareAdvisory::TpmFail) => (
            State::Info,
            format!(
                "{what}: listed for CVE-2019-16863 (TPM-FAIL, ECDSA signing), which irlume \
                 does not use; the machine vendor's TPM firmware update fixes it"
            ),
        ),
        None => (State::Info, what),
    }
}

/// The `tpm-pcr-bank` check: whether the SHA-256 bank can carry a literal seal
/// over the policy PCRs.
fn pcr_bank_check(
    bank: &Result<irlume_core::tpm::PcrBankReadiness, String>,
) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    use irlume_core::tpm::PcrBankReadiness;
    match bank {
        Ok(PcrBankReadiness::Ready(pcrs)) => {
            (State::Pass, format!("SHA-256 values for PCRs {pcrs:?}"))
        }
        Ok(PcrBankReadiness::Missing(pcrs)) => (
            State::Fail,
            format!(
                "no SHA-256 value for PCRs {pcrs:?}: the SHA-256 PCR bank is not active, so \
                 sealing refuses; activate it in the firmware setup's TPM options"
            ),
        ),
        Ok(PcrBankReadiness::Unextended(pcrs)) => (
            State::Warn,
            format!(
                "PCRs {pcrs:?} are still zero in the SHA-256 bank: the firmware measures \
                 nothing there, so a seal to them binds no boot state"
            ),
        ),
        Err(e) => (State::Unknown, format!("PCRs not read: {e}")),
    }
}

/// The `tpm-lockout` check (ADR-0034 §4): the TPM's dictionary-attack state.
/// Its counter is shared by the whole TPM, so a lockout another TPM user
/// caused (wrong disk unlock PINs, a Windows Hello PIN on dual boot) blocks
/// every key that is not DA-exempt. A pass or info reading counts in neither
/// doctor's closing summary nor the `doctor --check` exit code, so every
/// reading that needs action is a warning.
fn tpm_lockout_check(
    lockout: &Result<irlume_core::tpm::TpmLockout, String>,
    da_exempt_key: &Result<irlume_common::tpm_readiness::DaExemptKey, String>,
) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    let refused = da_exempt_key
        .as_ref()
        .ok()
        .and_then(|key| key.refused.as_ref());
    let lockout = match (lockout, refused) {
        (Ok(lockout), _) => lockout,
        // The refusal is read from irlumed's record, not the TPM, so it stays
        // actionable when the lockout properties could not be read.
        (Err(e), Some(refused)) => {
            return (
                State::Warn,
                format!(
                    "lockout state not read ({e}), {}",
                    refusal_warning(refused, da_exempt_key)
                ),
            )
        }
        (Err(e), None) => return (State::Unknown, format!("lockout state not read: {e}")),
    };
    let counts = format!(
        "{} of {} failures, recovery interval {} s",
        lockout.failed_tries, lockout.max_tries, lockout.recovery_time
    );
    if lockout.in_lockout {
        let effect = if lockout.storage_key_no_da {
            "irlume's storage key is DA-exempt, so irlume is not affected, but disk \
             unlock PINs and other TPM PIN users on this machine are"
                .to_owned()
        } else if let Some(named) = original_key_envelopes(da_exempt_key, true) {
            format!(
                "these irlume envelopes are still on its original storage key, which the \
                 lockout blocks (ADR-0034 §3), so what each protects uses the password until \
                 it ends: {named}. Envelopes on irlume's DA-exempt storage key are not \
                 affected"
            )
        } else {
            "not every irlume envelope is on its DA-exempt storage key yet (ADR-0034 §3), \
             so face login with an encrypted enrollment (one a TPM-sealed template key \
             protects) and the release of sealed keyring secrets whose envelopes are still \
             on the original key use the password until it ends"
                .to_owned()
        };
        // The TPM keeps no "time left" value: a lockout ends one recovery
        // interval of powered-on time after the last failure, and a power
        // interruption can restart that wait (TPM 2.0 Library Part 1, 16.8.2;
        // a TPM may keep the elapsed time across a shutdown).
        let wait = format!(
            "It ends within {} s of powered-on time without another failure, and a power \
             cycle can restart that wait, so keep the machine running",
            lockout.recovery_time
        );
        // After a wrong lockout authorization the TPM refuses another try for
        // the lockout recovery time, or until a restart when that is 0
        // (Part 1, 16.8.2 and 16.8.5), and no property shows that state.
        let retry = if lockout.lockout_recovery == 0 {
            "a wrong value blocks another try until the next restart".to_owned()
        } else {
            format!(
                "a wrong value blocks another try for {} s",
                lockout.lockout_recovery
            )
        };
        // tpm2-tools picks its TPM from `-T`, then TPM2TOOLS_TCTI, then its
        // own defaults, so the command names the TPM irlumed reported on.
        const ON_IRLUMES_TPM: &str =
            "on the TPM irlumed uses (pass its IRLUME_TCTI with `-T` if it sets one)";
        let clear = if lockout.lockout_auth_set {
            format!(
                "an administrator who knows the lockout authorization can end it at once \
                 with `tpm2_dictionarylockout --clear-lockout --auth=file:-` {ON_IRLUMES_TPM}, \
                 which reads the value from standard input and keeps it off the process \
                 list; {retry}. If another operating system set that authorization, it \
                 holds the value"
            )
        } else {
            format!(
                "no lockout authorization value is set, so `tpm2_dictionarylockout \
                 --clear-lockout` {ON_IRLUMES_TPM} ends it at once"
            )
        };
        return (
            State::Warn,
            format!(
                "the TPM is in dictionary-attack lockout ({counts}): {effect}. {wait}. Or \
                 {clear}. Clearing the TPM also ends it but destroys every key sealed to \
                 it, irlume's included"
            ),
        );
    }
    if let Some(refused) = refused {
        return (
            State::Warn,
            format!(
                "not in lockout ({counts}), {}",
                refusal_warning(refused, da_exempt_key)
            ),
        );
    }
    // A current irlumed that could not report the key's state (an envelope
    // store or a recorded handle it could not read) leaves the reading
    // unknown. An older irlumed, which has no such report, changes nothing.
    if let Err(e) = da_exempt_key {
        if e != irlume_common::tpm_readiness::DA_EXEMPT_KEY_NOT_REPORTED {
            return (
                State::Unknown,
                format!(
                    "not in lockout ({counts}), but irlumed could not report irlume's DA-exempt \
                     storage key: {}",
                    irlume_common::single_line(e, 300)
                ),
            );
        }
    }
    if !lockout.lockout_auth_set {
        return (
            State::Info,
            format!(
                "not in lockout ({counts}); no lockout authorization value is set, so any \
                 process that can open the TPM can reset the lockout or change its \
                 parameters. This describes the machine, not irlume, which does not rely \
                 on the lockout"
            ),
        );
    }
    (
        State::Pass,
        format!("not in lockout ({counts}); a lockout authorization value is set"),
    )
}

/// The warning for a refused persist of irlume's DA-exempt storage key,
/// naming the envelopes that stay on the original key when irlumed listed
/// them.
fn refusal_warning(
    refused: &irlume_common::tpm_readiness::KeyRefusal,
    da_exempt_key: &Result<irlume_common::tpm_readiness::DaExemptKey, String>,
) -> String {
    let staying = match original_key_envelopes(da_exempt_key, false) {
        Some(named) => format!(
            "These envelopes stay on irlume's original key, which the next TPM lockout \
             would block: {named}"
        ),
        None => "irlume's envelopes stay on its original key, which the next TPM lockout \
                 would block"
            .to_owned(),
    };
    format!(
        "but irlumed could not persist irlume's DA-exempt storage key (ADR-0034 §3): {}. \
         {staying}. irlumed tries again {}",
        refusal_text(refused),
        refused.reason.when_retried()
    )
}

/// At most this many envelopes are named in a doctor line; irlumed sends at
/// most `tpm_readiness::MAX_NAMED_ENVELOPES`, and an older or altered one
/// may send more.
const MAX_ENVELOPES_SHOWN: usize = 12;

/// The envelopes irlumed listed as still under irlume's original storage key
/// (ADR-0034 §4), by account and kind, with what a TPM lockout blocks for each
/// when `with_effect`, and how many more there are. `None` when irlumed sent
/// no list (it predates it, or could not report) or the list is empty. Account
/// names come from irlumed's state directory: they are cleaned again here, as
/// for a refusal's detail.
fn original_key_envelopes(
    da_exempt_key: &Result<irlume_common::tpm_readiness::DaExemptKey, String>,
    with_effect: bool,
) -> Option<String> {
    use irlume_common::tpm_readiness::EnvelopeKind;
    let list = da_exempt_key.as_ref().ok()?.on_original_key.as_ref()?;
    let total = usize::try_from(list.total)
        .unwrap_or(usize::MAX)
        .max(list.named.len());
    if total == 0 {
        return None;
    }
    let mut parts: Vec<String> = list
        .named
        .iter()
        .take(MAX_ENVELOPES_SHOWN)
        .map(|envelope| {
            let user = irlume_common::single_line(&envelope.user, 64);
            let (what, effect) = match envelope.kind {
                EnvelopeKind::TemplateKey => ("template key", Some("face login")),
                EnvelopeKind::KeyringSecret => (
                    "keyring secret",
                    Some("credential release after a face or fingerprint login"),
                ),
                EnvelopeKind::Unknown => ("envelope", None),
            };
            match effect.filter(|_| with_effect) {
                Some(effect) => format!("{user}'s {what} ({effect})"),
                None => format!("{user}'s {what}"),
            }
        })
        .collect();
    let rest = total - parts.len();
    if parts.is_empty() {
        parts.push(format!(
            "{rest} envelope{} under names irlumed does not show",
            if rest == 1 { "" } else { "s" }
        ));
    } else if rest > 0 {
        parts.push(format!("and {rest} more"));
    }
    Some(parts.join("; "))
}

/// irlume's original storage key and its retirement at irlumed's start
/// (ADR-0034, Phase 3 amendment), from irlumed's root-only report. A key
/// waiting to be retired is named with its handle and TPM name and what it
/// waits for. A key today's derivation does not give is offered the manual
/// command, with its warning, once no envelope is under it; a failed
/// retirement is not, since a derivation that errors says nothing about whose
/// key it is.
fn tpm_storage_keys_check(
    da_exempt_key: &Result<irlume_common::tpm_readiness::DaExemptKey, String>,
) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    use irlume_common::tpm_readiness::{OriginalKey, RetirementWait, DA_EXEMPT_KEY_NOT_REPORTED};
    let key = match da_exempt_key {
        Ok(key) => key,
        Err(e) if e == DA_EXEMPT_KEY_NOT_REPORTED => {
            return (
                State::Unknown,
                "this irlumed predates the storage key report".to_owned(),
            )
        }
        Err(e) => {
            return (
                State::Unknown,
                format!(
                    "irlumed could not report irlume's storage keys: {}",
                    irlume_common::single_line(e, 300)
                ),
            )
        }
    };
    let Some(original) = &key.original_key else {
        return (
            State::Unknown,
            "this irlumed predates the report of the original storage key's retirement".to_owned(),
        );
    };
    let (handle, name, wait) = match original {
        OriginalKey::NotRecorded => {
            return (
                State::Info,
                "irlumed has recorded no original storage key: none was persisted at its \
                 handle, or no start that derives no other key has checked it yet"
                    .to_owned(),
            )
        }
        OriginalKey::Retired { handle } => {
            return (
                State::Pass,
                format!(
                    "irlume's original storage key is no longer persisted at {handle:#010x} \
                     (retired at irlumed's start, or evicted by hand)"
                ),
            )
        }
        OriginalKey::Unknown => {
            return (
                State::Unknown,
                "irlumed reported a state of the original storage key this build does not \
                 know"
                    .to_owned(),
            )
        }
        OriginalKey::Waiting { handle, name, wait } => (handle, name, wait),
    };
    // irlumed sends hex; an older or altered daemon's text is cleaned again.
    let name: String = name
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(160)
        .collect();
    let key = if name.is_empty() {
        format!("irlume's original storage key at {handle:#010x}")
    } else {
        format!("irlume's original storage key at {handle:#010x} (TPM name {name})")
    };
    const ON_IRLUMES_TPM: &str =
        "on the TPM irlumed uses (pass its IRLUME_TCTI with `-T` if it sets one)";
    match wait {
        RetirementWait::Envelopes => {
            let named = original_key_envelopes(da_exempt_key, false).unwrap_or_else(|| {
                "an envelope irlumed cannot read, which counts as one".to_owned()
            });
            (
                State::Info,
                format!(
                    "{key} still has envelopes under it ({named}); they move onto the DA-exempt \
                     storage key at their move points, and irlumed retires the key once none \
                     has been under it since a start in an earlier boot"
                ),
            )
        }
        RetirementWait::UnsettledMoves { envelopes, total } => (
            State::Info,
            format!(
                "{key} has no envelope under it, but a move off it in this boot is not yet \
                 shown durable ({}); irlumed's first start in a later boot counts again",
                envelope_names(envelopes, *total)
            ),
        ),
        RetirementWait::Count => (
            State::Info,
            format!(
                "{key} has no envelope under it; irlumed's next start counts them, and a \
                 start in a later boot retires it"
            ),
        ),
        RetirementWait::LaterBoot => (
            State::Info,
            format!(
                "{key} has had no envelope under it since a start in this boot; irlumed \
                 retires it at its first start in a later boot"
            ),
        ),
        RetirementWait::NextStart => (
            State::Info,
            format!(
                "{key} has had no envelope under it since a start in an earlier boot; \
                 irlumed retires it at its next start"
            ),
        ),
        RetirementWait::DaExemptKey => (
            State::Warn,
            format!(
                "{key} waits for irlume's DA-exempt storage key, which is not at its \
                 recorded handle or which irlume cannot seal under; irlumed retires the \
                 original key only beside it (see tpm-lockout for a refused persist)"
            ),
        ),
        RetirementWait::Failed {
            detail,
            in_this_boot,
        } => {
            let when = if *in_this_boot {
                "at its first start in a later boot"
            } else {
                "at its next start"
            };
            (
                State::Warn,
                format!(
                    "the last retirement of {key} failed ({}); irlumed tries again {when}. \
                     Only a derivation shows the key is irlume's, so evict nothing by hand \
                     for this",
                    irlume_common::single_line(detail, 300)
                ),
            )
        }
        // The census counts an envelope irlumed cannot read, which the list
        // does not name: either one keeps the manual command back.
        RetirementWait::NotReproduced { in_use } => {
            match (*in_use, original_key_envelopes(da_exempt_key, false)) {
                (true, named) | (false, named @ Some(_)) => {
                    let named = named.unwrap_or_else(|| {
                        "an envelope irlumed cannot read, which counts as one".to_owned()
                    });
                    (
                        State::Info,
                        format!(
                            "{key} is not the key today's derivation of irlume's template gives, \
                         so irlume never evicts it; envelopes are still under it ({named}) and \
                         move onto the DA-exempt storage key first"
                        ),
                    )
                }
                (false, None) => (
                    State::Warn,
                    format!(
                        "{key} is not the key today's derivation of irlume's template gives, so \
                     irlume never evicts it, and no envelope is under it. Find what else uses \
                     it first (`tpm2_readpublic -c {handle:#010x}`, {ON_IRLUMES_TPM}); if \
                     nothing does, evict it by hand with `sudo tpm2_evictcontrol -C o -c \
                     {handle:#010x}` {ON_IRLUMES_TPM}. Do not clear the whole TPM for this: \
                     that also drops every other key sealed in it, such as a disk's"
                    ),
                ),
            }
        }
        RetirementWait::Unchecked => (
            State::Info,
            format!(
                "{key} is not the key irlumed recorded there; irlumed's next start that \
                 derives no other key checks it"
            ),
        ),
        RetirementWait::HandleChanged { configured } => {
            let now = configured.map_or_else(
                || "a value irlumed refuses".to_owned(),
                |configured| format!("{configured:#010x}"),
            );
            (
                State::Info,
                format!(
                    "{key} was recorded at that handle, but irlumed's IRLUME_SRK_HANDLE now \
                     names {now}; irlumed retires the original key only at the handle \
                     IRLUME_SRK_HANDLE names, so it leaves this one. Set IRLUME_SRK_HANDLE \
                     back to {handle:#010x} for irlumed to retire it there"
                ),
            )
        }
        RetirementWait::Unknown => (
            State::Unknown,
            format!("{key} waits for something this build does not know"),
        ),
    }
}

/// `envelopes` by account and kind, as doctor names them: at most
/// [`MAX_ENVELOPES_SHOWN`], each account name cleaned again, with how many
/// of `total` are not shown.
fn envelope_names(
    envelopes: &[irlume_common::tpm_readiness::OriginalKeyEnvelope],
    total: u32,
) -> String {
    use irlume_common::tpm_readiness::EnvelopeKind;
    let total = usize::try_from(total)
        .unwrap_or(usize::MAX)
        .max(envelopes.len());
    if envelopes.is_empty() {
        return format!(
            "{total} envelope{} under names irlumed does not show",
            if total == 1 { "" } else { "s" }
        );
    }
    let mut parts: Vec<String> = envelopes
        .iter()
        .take(MAX_ENVELOPES_SHOWN)
        .map(|envelope| {
            let what = match envelope.kind {
                EnvelopeKind::TemplateKey => "template key",
                EnvelopeKind::KeyringSecret => "keyring secret",
                EnvelopeKind::Unknown => "envelope",
            };
            format!(
                "{}'s {what}",
                irlume_common::single_line(&envelope.user, 64)
            )
        })
        .collect();
    let rest = total - parts.len();
    if rest > 0 {
        parts.push(format!("and {rest} more"));
    }
    parts.join("; ")
}

/// The `tpm-firmware` check over every storage key irlume knows of
/// (ADR-0034, Phase 3 amendment, #1073 item 2): [`tpm_firmware_check`] for
/// the TPM and the original key, which an older irlumed's reply also carries,
/// then what irlumed's per-key report says of the DA-exempt key and the keys
/// it superseded ([`storage_key_notes`]), the worst state of them all.
fn tpm_firmware_report(
    identity: &Result<irlume_core::tpm::TpmIdentity, String>,
    storage_key: &Result<irlume_core::tpm::StorageKeyCheck, String>,
    storage_keys: &Result<Vec<irlume_common::tpm_readiness::StorageKeyEntry>, String>,
    da_exempt_key: &Result<irlume_common::tpm_readiness::DaExemptKey, String>,
) -> (crate::doctor_report::State, String) {
    let (state, detail) = tpm_firmware_check(identity, storage_key);
    let notes = storage_key_notes(storage_key, storage_keys, da_exempt_key);
    if notes.is_empty() {
        return (state, detail);
    }
    let worst = notes
        .iter()
        .fold(state, |worst, (state, _)| worse_state(worst, *state));
    let mut text = detail.trim_end_matches('.').to_owned();
    for (_, note) in notes {
        text.push_str(". ");
        text.push_str(note.trim_end_matches('.'));
    }
    (worst, text)
}

/// The more serious of two doctor states: fail, warn, unknown, info, pass.
fn worse_state(
    a: crate::doctor_report::State,
    b: crate::doctor_report::State,
) -> crate::doctor_report::State {
    use crate::doctor_report::State;
    let rank = |state: State| match state {
        State::Fail => 4,
        State::Warn => 3,
        State::Unknown => 2,
        State::Info => 1,
        State::Pass => 0,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// What irlumed's per-key report says of irlume's DA-exempt storage key and
/// the keys it superseded: a weak DA-exempt key with why it is not replaced
/// yet (the firmware still generates affected keys, or the replacement was
/// refused) or that irlumed's next start replaces it; and each superseded
/// key still persisted, with the envelopes that still name it, or, once none
/// has named it since a start in an earlier boot, the manual command with
/// its warning, since irlume never evicts a key no derivation gives; a weak
/// original key the record names at a handle `IRLUME_SRK_HANDLE` no longer
/// names; a weak key in a role a newer irlumed added, with no command; and
/// `unknown` when a current irlumed could not make the report. Nothing from an irlumed that
/// predates the report. What irlumed sent is cleaned again.
fn storage_key_notes(
    storage_key: &Result<irlume_core::tpm::StorageKeyCheck, String>,
    storage_keys: &Result<Vec<irlume_common::tpm_readiness::StorageKeyEntry>, String>,
    da_exempt_key: &Result<irlume_common::tpm_readiness::DaExemptKey, String>,
) -> Vec<(crate::doctor_report::State, String)> {
    use crate::doctor_report::State;
    use irlume_common::tpm_readiness::{
        DerivedKey, StorageKeyCheck, StorageKeyRole, STORAGE_KEYS_NOT_REPORTED,
    };
    let entries = match storage_keys {
        Ok(entries) => entries,
        // An older irlumed reports the original key alone, as before.
        Err(e) if e == STORAGE_KEYS_NOT_REPORTED => return Vec::new(),
        // A current one that could not check the others must not read as
        // clean for them.
        Err(e) => {
            return vec![(
                State::Unknown,
                format!(
                    "irlumed could not check irlume's DA-exempt and superseded storage keys: {}",
                    irlume_common::single_line(e, 300)
                ),
            )]
        }
    };
    let key = da_exempt_key.as_ref().ok();
    const ON_IRLUMES_TPM: &str =
        "on the TPM irlumed uses (pass its IRLUME_TCTI with `-T` if it sets one)";
    let mut notes = Vec::new();
    for entry in entries {
        let handle = entry.handle;
        let name: String = entry
            .name
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(160)
            .collect();
        let named = |entry: &irlume_common::tpm_readiness::StorageKeyEntry| {
            entry
                .envelopes
                .as_ref()
                .filter(|envelopes| envelopes.total > 0)
                .map(|envelopes| envelope_names(&envelopes.named, envelopes.total))
        };
        let weak = matches!(entry.check, StorageKeyCheck::RocaFingerprint { .. });
        match entry.role {
            StorageKeyRole::DaExempt if weak => {
                let derived = match entry.check {
                    StorageKeyCheck::RocaFingerprint { derived, .. } => derived,
                    _ => None,
                };
                let what = format!(
                    "irlume's DA-exempt storage key at {handle:#010x} carries the ROCA \
                     fingerprint (CVE-2017-15361)"
                );
                let refused = key.and_then(|key| key.replacement_refused.as_ref());
                let firmware_weak =
                    key.is_some_and(|key| key.derivation_weak) || derived == Some(DerivedKey::Same);
                let note = if let Some(refused) = refused {
                    format!(
                        "{what}, and irlumed could not persist its replacement: {}. The weak \
                         key stays in use, and irlumed tries again {}",
                        refusal_text(refused),
                        refused.reason.when_retried()
                    )
                } else if let Err(e) = da_exempt_key {
                    format!(
                        "{what}; whether irlumed's start replaces it is unknown, since irlumed \
                         could not report its replacement state ({})",
                        irlume_common::single_line(e, 300)
                    )
                } else if key.is_some_and(|key| !key.any_envelope) {
                    // irlumed's start checks the key only while an envelope
                    // is stored, so it promises nothing before one is.
                    let then = if firmware_weak {
                        "once the TPM firmware is updated with the machine vendor's tool, since \
                         today's derivation of its template is weak too"
                    } else {
                        "onto a clean key when today's derivation of its template gives one"
                    };
                    format!(
                        "{what}. No envelope is stored yet, so irlumed's start leaves it and new \
                         seals go under it; the first start after one is made (`sudo systemctl \
                         restart irlumed` after enrolling) replaces it by moving its envelopes, \
                         {then}"
                    )
                } else if firmware_weak {
                    format!(
                        "{what}, and so does the key today's derivation of its template gives: \
                         update the TPM firmware with the machine vendor's tool. irlumed then \
                         replaces the key at its next start by moving its envelopes onto a \
                         clean one, with no recovery or re-enrollment"
                    )
                } else if derived == Some(DerivedKey::Unaffected) {
                    format!(
                        "{what}, but today's derivation of its template gives a clean key, \
                         so irlumed replaces it at its next start by moving its envelopes"
                    )
                } else {
                    format!(
                        "{what}. irlumed's next start derives its template again and replaces \
                         it by moving its envelopes when that gives a clean key; when it is \
                         weak too, update the TPM firmware with the machine vendor's tool"
                    )
                };
                notes.push((State::Warn, note));
            }
            StorageKeyRole::Superseded if entry.check != StorageKeyCheck::Absent => {
                let what = if weak {
                    format!(
                        "the weak key at {handle:#010x} (TPM name {name}), which irlume's \
                         DA-exempt storage key replaced, carries the ROCA fingerprint \
                         (CVE-2017-15361)"
                    )
                } else {
                    format!(
                        "the key at {handle:#010x} (TPM name {name}), which irlume's \
                         DA-exempt storage key superseded, is still persisted"
                    )
                };
                let state = if weak { State::Warn } else { State::Info };
                let note = match named(entry) {
                    Some(named) => format!(
                        "{what}; envelopes still name it ({named}) and move onto the DA-exempt \
                         key at their move points (a template key at irlumed's next start, a \
                         keyring secret at the next password login)"
                    ),
                    None if entry.unused_across_boots => format!(
                        "{what}; no envelope has named it since a start in an earlier boot, \
                         and irlume never evicts a key no derivation gives. Find what else \
                         uses it first (`tpm2_readpublic -c {handle:#010x}`, {ON_IRLUMES_TPM}); \
                         if nothing does, evict it by hand with `sudo tpm2_evictcontrol -C o \
                         -c {handle:#010x}` {ON_IRLUMES_TPM}. Do not clear the whole TPM for \
                         this: that also drops every other key sealed in it, such as a disk's"
                    ),
                    None => format!(
                        "{what}; no envelope names it now, and once a start in a later boot \
                         finds the same, doctor names the manual command"
                    ),
                };
                notes.push((state, note));
            }
            // The original key at a handle IRLUME_SRK_HANDLE no longer names;
            // the one at the configured handle is the original-key reading.
            StorageKeyRole::Original
                if weak
                    && !matches!(
                        storage_key,
                        Ok(StorageKeyCheck::RocaFingerprint { handle: checked, .. })
                            if *checked == handle
                    ) =>
            {
                notes.push((
                    State::Warn,
                    format!(
                        "irlume's original storage key recorded at {handle:#010x} (TPM name \
                         {name}), a handle irlumed's IRLUME_SRK_HANDLE no longer names, carries \
                         the ROCA fingerprint (CVE-2017-15361). irlumed uses the original key \
                         only at the handle IRLUME_SRK_HANDLE names: the `tpm-storage-keys` \
                         check says what setting it back involves"
                    ),
                ));
            }
            // A role a newer irlumed added: what to do about it is that
            // release's to say, but a weak key must not read as clean.
            StorageKeyRole::Unknown if weak => notes.push((
                State::Warn,
                format!(
                    "irlumed reports a storage key at {handle:#010x} (TPM name {name}), in a \
                     role this irlume does not know, that carries the ROCA fingerprint \
                     (CVE-2017-15361); update irlume to see what irlumed does about it"
                ),
            )),
            _ => {}
        }
    }
    notes
}

/// Why irlume's DA-exempt storage key could not be persisted, in words, with
/// the TPM's own as one bounded line: irlumed cleans it, and an older or
/// altered daemon's text is cleaned again here.
fn refusal_text(refused: &irlume_common::tpm_readiness::KeyRefusal) -> String {
    use irlume_common::tpm_readiness::RefusalReason;
    let reason = match refused.reason {
        RefusalReason::NoSpace => "the TPM has no room for another persistent object",
        RefusalReason::NoFreeHandle => "no owner persistent handle is free",
        RefusalReason::OwnerAuthorization => {
            "an owner authorization is set, and irlume derives and persists its keys with \
             an empty one"
        }
        RefusalReason::HandleOverride => {
            "IRLUME_SRK_HANDLE does not name an owner persistent handle"
        }
        RefusalReason::Other | RefusalReason::Unknown => "the TPM refused it",
    };
    format!(
        "{reason} ({})",
        irlume_common::single_line(&refused.detail, 300)
    )
}

/// The `secure-boot-certificates` check: where this machine stands in
/// Microsoft's 2026 Secure Boot certificate rollover, which moves PCR 7.
fn certificate_rollover_check(
    rollover: &irlume_common::secureboot::CertificateRollover,
) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    use irlume_common::secureboot::CertificateRollover;
    match rollover {
        CertificateRollover::Updated => (
            State::Pass,
            "Microsoft's 2023 Secure Boot certificates are enrolled".to_owned(),
        ),
        CertificateRollover::Pending(missing) => {
            let names: Vec<String> = missing
                .iter()
                .map(|(database, name)| format!("{name} ({database})"))
                .collect();
            (
                State::Warn,
                format!(
                    "still to be enrolled: {}. Microsoft's 2011 Secure Boot certificates \
                     expire in 2026, and the update (`fwupdmgr update` with fwupd 2.0.8 or \
                     later, or the firmware vendor's) changes PCR 7. A seal bound to PCR 7 \
                     then stops opening: face login falls back to the password until \
                     `irlume recovery restore` or a re-enrollment, and the keyring secret \
                     reseals at the next password login. Set a recovery passphrase first \
                     (`irlume recovery setup`)",
                    names.join(", ")
                ),
            )
        }
        CertificateRollover::NotMicrosoft => (
            State::Info,
            "Secure Boot uses its own keys, which Microsoft's 2026 rollover does not change"
                .to_owned(),
        ),
        CertificateRollover::NoKeys => (
            State::Info,
            "no Secure Boot keys are enrolled (setup mode), so there is nothing to roll over"
                .to_owned(),
        ),
        CertificateRollover::NotUefi => (
            State::Info,
            "not a UEFI boot: no Secure Boot databases".to_owned(),
        ),
        CertificateRollover::Unreadable => (
            State::Unknown,
            "the Secure Boot KEK and db could not be read, or are absent outside setup mode"
                .to_owned(),
        ),
    }
}

/// The firmware event log as `doctor` could read it, for `pcr7-binding`.
enum EventLogRead {
    /// The log, with PCR 7's SHA-256 value or why that could not be read.
    Bytes(Vec<u8>, Result<[u8; 32], String>),
    Absent,
    /// securityfs is not mounted, so a missing log says nothing.
    NoSecurityfs,
    NotRoot,
    Unreadable(String),
}

fn read_event_log() -> EventLogRead {
    use irlume_common::event_log::{
        pcr_value, securityfs_shown, EVENT_LOG, PCR7_SHA256, SECURITYFS,
    };
    match std::fs::read(EVENT_LOG) {
        Ok(bytes) => {
            let value = std::fs::read_to_string(PCR7_SHA256)
                .map_err(|e| format!("{PCR7_SHA256}: {e}"))
                .and_then(|text| {
                    pcr_value(&text).ok_or_else(|| format!("{PCR7_SHA256} holds no SHA-256 value"))
                });
            EventLogRead::Bytes(bytes, value)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if securityfs_shown(std::path::Path::new(SECURITYFS)) {
                EventLogRead::Absent
            } else {
                EventLogRead::NoSecurityfs
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => EventLogRead::NotRoot,
        Err(e) => EventLogRead::Unreadable(e.to_string()),
    }
}

/// Firmware-written text from the event log (a UEFI variable name) as
/// visible ASCII on one bounded line: anything else shows as `?`.
fn firmware_text(text: &str) -> String {
    const MAX: usize = 32;
    let mut out: String = text
        .chars()
        .take(MAX)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if text.chars().count() > MAX {
        out.push_str("...");
    }
    out
}

/// The `pcr7-binding` check: what PCR 7 bound in this boot, from the
/// firmware's event log once it accounts for PCR 7's value, judged against
/// the PCR 7 measurements Microsoft's BitLocker guidance lists.
fn pcr7_binding_check(read: &EventLogRead) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    use irlume_common::event_log::Untrusted;
    let (bytes, value) = match read {
        EventLogRead::Bytes(bytes, value) => (bytes, value),
        EventLogRead::Absent => {
            return (
                State::Info,
                "no firmware event log: the kernel exposes none for this TPM".to_owned(),
            )
        }
        EventLogRead::NoSecurityfs => {
            return (
                State::Unknown,
                "securityfs is not mounted at /sys/kernel/security (a container or a \
                 chroot), so the firmware event log could not be looked for"
                    .to_owned(),
            )
        }
        EventLogRead::NotRoot => {
            return (
                State::Unknown,
                "the firmware event log is readable by root only (`sudo irlume doctor`)".to_owned(),
            )
        }
        EventLogRead::Unreadable(e) => {
            return (
                State::Unknown,
                format!("the firmware event log could not be read: {e}"),
            )
        }
    };
    let value = match value {
        Ok(value) => value,
        Err(e) => {
            return (
                State::Unknown,
                format!(
                    "PCR 7's value, which the firmware event log must account for, could not \
                     be read: {e}"
                ),
            )
        }
    };
    let why = match irlume_common::event_log::verified_pcr7(bytes, value) {
        Ok(pcr7) => return pcr7_binding_verdict(&pcr7),
        Err(Untrusted::NotCryptoAgile) => "the firmware event log is not in the crypto-agile \
                                           format, or its Spec ID header is not one that \
                                           format allows"
            .to_owned(),
        Err(Untrusted::Incomplete) => "the firmware event log ends in an event that does not \
                                       parse (one that runs past the end, or does not carry \
                                       one digest for each algorithm the log declares), so \
                                       the events after it are unread"
            .to_owned(),
        Err(Untrusted::NoSha256) => "a PCR 7 event in the firmware event log carries no \
                                     SHA-256 digest, so the log cannot be checked against \
                                     PCR 7"
            .to_owned(),
        Err(Untrusted::Replay) => "the firmware event log does not account for the value \
                                   PCR 7 holds: replaying its SHA-256 digests gives another \
                                   value, so PCR 7 was extended with something the log does \
                                   not show"
            .to_owned(),
        Err(Untrusted::Payload(count)) => format!(
            "{count} PCR 7 event(s) in the firmware event log do not hash to their recorded \
             digest, so the log does not show what PCR 7 was extended with"
        ),
        Err(Untrusted::Malformed(count)) => format!(
            "{count} PCR 7 event(s) in the firmware event log do not have the form their type \
             requires (UEFI variable data for a configuration or authority event, a 4-byte \
             0 or all ones for a separator that records no error, 0 or 1 for SecureBoot), so \
             the log does not show what PCR 7 was extended with"
        ),
    };
    (State::Unknown, why)
}

/// The 2023 certificate that takes over signing from a 2011 Microsoft CA that
/// signs boot loaders (Microsoft's 2026 certificate rollover).
fn signing_ca_successor(name: &str) -> Option<&'static str> {
    match name {
        "Microsoft Corporation UEFI CA 2011" => Some("Microsoft UEFI CA 2023"),
        "Microsoft Windows Production PCA 2011" => Some("Windows UEFI CA 2023"),
        _ => None,
    }
}

/// The `pcr7-binding` verdict from what PCR 7 recorded, in a log already
/// shown to account for PCR 7's value.
fn pcr7_binding_verdict(
    pcr7: &irlume_common::event_log::Pcr7<'_>,
) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    const AFTER: &str = "Turn it back on in the firmware setup. That changes PCR 7, so set a \
                         recovery passphrase first (`irlume recovery setup`)";
    use irlume_common::event_log::SECURE_BOOT_CONFIGURATION;
    if pcr7.separator_errors > 0 {
        return (
            State::Warn,
            "the firmware recorded a measurement error in PCR 7 (a separator measured as 1, \
             not 0), so what it measured there may be incomplete and PCR 7 may not show \
             what booted"
                .to_owned(),
        );
    }
    if pcr7.actions.iter().any(|a| a == "UEFI Debug Mode") {
        return (
            State::Warn,
            "the firmware recorded UEFI debug mode in PCR 7. Debug mode can bypass \
                 Secure Boot, so PCR 7 does not show what booted, and BitLocker will not \
                 bind to it then. Turn debug mode off in the firmware setup. That changes \
                 PCR 7, so set a recovery passphrase first (`irlume recovery setup`)"
                .to_owned(),
        );
    }
    if pcr7.actions.iter().any(|a| a == "DMA Protection Disabled") {
        return (
            State::Warn,
            format!(
                "the firmware recorded in PCR 7 that pre-boot DMA protection is off: a \
                 device on a DMA-capable port can change memory before the system starts, \
                 which PCR 7 does not show. {AFTER}"
            ),
        );
    }
    if pcr7.secure_boot == Some(false) {
        return (
            State::Warn,
            "Secure Boot was measured as off (or its SecureBoot variable as absent), so \
             PCR 7 binds no signature check and a seal bound to it does not depend on \
             what boots"
                .to_owned(),
        );
    }
    // Microsoft's BitLocker guidance: SecureBoot, PK, KEK, db and dbx under
    // their UEFI GUIDs, in this order with nothing in between, then an
    // optional separator, then the authorities.
    let in_order = pcr7.configuration.len() >= SECURE_BOOT_CONFIGURATION.len()
        && pcr7
            .configuration
            .iter()
            .zip(SECURE_BOOT_CONFIGURATION)
            .all(|(setting, (name, guid))| setting.name == name && setting.guid == guid);
    if !in_order {
        let measured = if pcr7.configuration.is_empty() {
            "nothing".to_owned()
        } else {
            let mut names: Vec<String> = pcr7
                .configuration
                .iter()
                .take(8)
                .map(|setting| {
                    let name = firmware_text(&setting.name);
                    let known = SECURE_BOOT_CONFIGURATION
                        .iter()
                        .find(|(n, _)| *n == setting.name);
                    match known {
                        Some((_, guid)) if *guid != setting.guid => {
                            format!("{name} (under another vendor GUID)")
                        }
                        _ => name,
                    }
                })
                .collect();
            if pcr7.configuration.len() > 8 {
                names.push("...".to_owned());
            }
            names.join(", ")
        };
        return (
            State::Warn,
            format!(
                "the firmware measured the Secure Boot configuration into PCR 7 as \
                 {measured}, not SecureBoot, PK, KEK, db and dbx in that order, so PCR 7 \
                 may not bind the Secure Boot policy (BitLocker does not bind to PCR 7 over \
                 such a log)"
            ),
        );
    }
    if pcr7.leading_configuration < SECURE_BOOT_CONFIGURATION.len() {
        return (
            State::Warn,
            "the firmware measured other events into PCR 7 before or between SecureBoot, \
             PK, KEK, db and dbx, so PCR 7 may not bind the Secure Boot policy as \
             measured (BitLocker does not bind to PCR 7 over such a log)"
                .to_owned(),
        );
    }
    let empty: Vec<&str> = pcr7.configuration[..3]
        .iter()
        .filter(|setting| !setting.data)
        .map(|setting| setting.name.as_str())
        .collect();
    if !empty.is_empty() {
        return (
            State::Warn,
            format!(
                "the firmware measured {} into PCR 7 with no data, so PCR 7 does not bind \
                 who may change the Secure Boot databases (BitLocker counts that as \
                 missing)",
                empty.join(" and ")
            ),
        );
    }
    if pcr7.authorities.iter().any(|a| a.disables_validation()) {
        return (
            State::Warn,
            "shim measured MokSBState into PCR 7: its validation is disabled \
             (`mokutil --disable-validation`), so it loads images without checking them \
             and PCR 7 binds no boot chain past shim. `sudo mokutil --enable-validation` \
             turns it back on. That changes PCR 7, so set a recovery passphrase first \
             (`irlume recovery setup`)"
                .to_owned(),
        );
    }
    if !pcr7.authorities.iter().any(|a| a.verifies_images()) {
        let detail = if pcr7.authorities.is_empty() {
            "no authority was measured into PCR 7: nothing verified what booted, so a \
             seal bound to PCR 7 binds no boot chain"
                .to_owned()
        } else {
            let names: Vec<String> = pcr7
                .authorities
                .iter()
                .take(8)
                .map(|a| format!("`{}`", firmware_text(&a.variable)))
                .collect();
            format!(
                "PCR 7 records no authority that verified an image, only policy ({}): \
                 nothing verified what booted, so a seal bound to PCR 7 binds no boot chain",
                names.join(", ")
            )
        };
        return (State::Warn, detail);
    }
    if pcr7.extraneous > 0 {
        return (
            State::Warn,
            format!(
                "the firmware measured {} image or driver load(s) into PCR 7, which \
                 Microsoft's guidance calls extraneous there: PCR 7 then changes whenever \
                 those binaries do, and BitLocker does not bind to it over such a log",
                pcr7.extraneous
            ),
        );
    }
    if pcr7.other > 0 {
        let kinds: Vec<String> = pcr7
            .other_kinds
            .iter()
            .map(|kind| format!("{kind:#010x}"))
            .collect();
        return (
            State::Unknown,
            format!(
                "PCR 7 also holds {} event(s) of a type doctor does not read ({}), so what \
                 PCR 7 binds is not fully known",
                pcr7.other,
                kinds.join(", ")
            ),
        );
    }
    // Firmware decides how many authorities there are: name at most eight.
    const MAX_NAMES: usize = 8;
    let mut names: Vec<String> = Vec::new();
    let mut unnamed = 0usize;
    let mut successors: Vec<&str> = Vec::new();
    for authority in &pcr7.authorities {
        let name = match authority.variable.as_str() {
            "db" if authority.verifies_images() => {
                let microsoft = irlume_common::event_log::authority_certificate(authority)
                    .and_then(irlume_common::secureboot::microsoft_certificate);
                // A boot loader signed by the 2011 CA's 2023 replacement is
                // measured with that certificate instead, which moves PCR 7.
                if let Some(successor) = microsoft.and_then(signing_ca_successor) {
                    if !successors.contains(&successor) {
                        successors.push(successor);
                    }
                }
                microsoft.map_or_else(
                    || "a db entry that is not Microsoft's".to_owned(),
                    |name| format!("{name} (db)"),
                )
            }
            "MokListRT" if authority.verifies_images() => {
                "an entry of shim's MokList (its vendor's or an enrolled MOK)".to_owned()
            }
            "vendor_db" if authority.verifies_images() => {
                "an entry of shim's built-in vendor database".to_owned()
            }
            "Shim" if authority.verifies_images() => "shim's built-in certificate".to_owned(),
            "SbatLevel" if authority.guid == irlume_common::event_log::SHIM_LOCK => {
                "shim's SBAT revocation level".to_owned()
            }
            other => format!("an authority from `{}`", firmware_text(other)),
        };
        if names.contains(&name) {
            continue;
        }
        if names.len() < MAX_NAMES {
            names.push(name);
        } else {
            unnamed += 1;
        }
    }
    if unnamed > 0 {
        names.push(format!("{unnamed} more"));
    }
    let mut detail = format!(
        "PCR 7 binds Secure Boot on, its databases and the authorities that verified this \
         boot: {}",
        names.join("; ")
    );
    if !successors.is_empty() {
        detail.push_str(&format!(
            ". A boot loader signed by {} instead, as distributions ship after the 2011 \
             CAs' expiry, changes PCR 7: a seal bound to it then needs `irlume recovery \
             restore` or a re-enrollment, so keep a recovery passphrase set \
             (`irlume recovery setup`)",
            successors.join(" or ")
        ));
    }
    (State::Pass, detail)
}

/// The `shim-validation` check: whether shim verifies what it loads. shim
/// measures into PCR 7 the certificate that verified each image; with its
/// validation disabled it measures none, so PCR 7 binds no boot chain.
fn shim_validation_check(
    validation: irlume_common::secureboot::ShimValidation,
) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    use irlume_common::secureboot::ShimValidation;
    match validation {
        ShimValidation::Enforcing => (
            State::Pass,
            "shim verifies the boot loader and kernel it loads".to_owned(),
        ),
        ShimValidation::Disabled => (
            State::Warn,
            "shim's Secure Boot validation is disabled (`mokutil --disable-validation`): \
             shim loads images without checking their signatures, so PCR 7 records that \
             setting but no boot chain, and a seal bound to PCR 7 does not depend on what \
             boots. Turn it back on with `sudo mokutil --enable-validation`, confirmed in \
             MokManager at the next boot. That changes PCR 7, so set a recovery passphrase \
             first (`irlume recovery setup`): face login then needs `irlume recovery \
             restore` or a re-enrollment, and the keyring secret reseals at the next \
             password login"
                .to_owned(),
        ),
        ShimValidation::SecureBootOff => (
            State::Info,
            "Secure Boot is not enforcing, so shim verifies nothing either way (see \
             secure-boot)"
                .to_owned(),
        ),
        ShimValidation::NotShim => (State::Info, "this boot did not go through shim".to_owned()),
        ShimValidation::NotUefi => (State::Info, "not a UEFI boot".to_owned()),
        ShimValidation::Unreadable => (
            State::Unknown,
            "the SecureBoot variable could not be read from efivarfs".to_owned(),
        ),
    }
}

/// What `doctor` observed about the active camera pair's capture mode. Kept as
/// a value so the wording is decided by a pure function and tested, separately
/// from the root check and config reads that produce it.
enum CaptureModeReport {
    /// The daemon could not resolve an exact v2 status.
    Unreadable(String),
    /// A verdict was measured for this pair and stored.
    Measured(irlume_camera::CaptureMode, Option<String>),
    /// The pair is pinned but no verdict was ever measured for it.
    Unmeasured,
    /// This host has no IR endpoint, so RGB+IR qualification does not apply.
    NoIrPair,
    /// A controlled attempt ran but could not publish authority.
    Inconclusive(String),
    /// `IRLUME_SEQUENTIAL_CAPTURE` is set in THIS process's environment and
    /// decides alone, whatever is stored.
    Overridden(bool),
    /// A qualified concurrent context failed live in this daemon generation.
    RuntimeDegraded(String),
}

/// The `doctor` line and machine state for a capture-mode observation.
///
/// Pure, so the wording of each case is tested without a camera or a config
/// file. Every case is `Info` or `Unknown`, never `Warn`/`Fail`: a capture mode
/// is a strategy, not a fault, and even the slower sequential mode is a correct
/// choice for a camera that dims under concurrent capture. The point of
/// reporting it at all is that the adaptation is otherwise silent (#100): a
/// camera quietly parked in sequential mode forever teaches nobody that it has
/// that fault, and a bug in irlume's own capture path would then look like
/// normal behaviour.
fn capture_mode_report_line(report: &CaptureModeReport) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    use irlume_camera::CaptureMode;
    match report {
        CaptureModeReport::Unreadable(why) => (
            State::Unknown,
            format!(
                "the daemon could not resolve v2 capture status ({why}); authentication stays \
                 on the safe sequential fallback"
            ),
        ),
        CaptureModeReport::Overridden(sequential) => (
            State::Info,
            format!(
                "{}, forced by IRLUME_SEQUENTIAL_CAPTURE in the daemon environment, which \
                 outranks durable qualification authority",
                if *sequential {
                    "sequential"
                } else {
                    "concurrent"
                }
            ),
        ),
        CaptureModeReport::Measured(CaptureMode::Sequential, reason) => (
            State::Info,
            // The measured range, not one end of it. 700ms is the ASUS figure,
            // and the ASUS keeps 102% of its brightness under concurrent
            // capture, so it is measured CONCURRENT and never reaches this
            // line. The population that gets a sequential verdict is the
            // NexiGo-shaped one, measured at 1.3s (#100 review).
            format!(
                "sequential, measured for this camera pair (RGB then IR, one after the other: \
             0.7s to 1.3s more per capture on the modules measured for #340, and the \
             reliable choice on a camera that dims when both sensors stream at once); reason: {}",
                reason.as_deref().unwrap_or("unspecified")
            ),
        ),
        CaptureModeReport::Measured(CaptureMode::Concurrent, _) => (
            State::Info,
            "concurrent, measured for this camera pair (RGB and IR captured together, the \
             faster path)"
                .to_string(),
        ),
        CaptureModeReport::Unmeasured => (
            State::Info,
            "not measured for this camera pair; using the safe sequential default. \
             Run `sudo irlume camera-tune` to measure whether this camera can capture RGB \
             and IR concurrently"
                .to_string(),
        ),
        CaptureModeReport::NoIrPair => (
            State::Info,
            "RGB-only capture: no IR endpoint is available, so RGB+IR capture-mode \
             qualification does not apply on this host"
                .to_string(),
        ),
        CaptureModeReport::Inconclusive(reason) => (
            State::Info,
            format!(
                "the last RGB+IR capture-mode measurement was inconclusive ({reason}); using \
                 the safe sequential default. Run `sudo irlume camera-tune` under stable, lit \
                 conditions to measure again"
            ),
        ),
        CaptureModeReport::RuntimeDegraded(reason) => (
            State::Info,
            format!(
                "sequential for this daemon generation after a live concurrent-pair failure \
             ({reason}); \
             both streams and camera handles were dropped before the sequential retry. Run \
             `sudo irlume camera-tune` to publish fresh controlled evidence"
            ),
        ),
    }
}

fn capture_mode_report_from_status(
    mode: &str,
    source: &str,
    qualification_state: &str,
    qualification_reason: Option<String>,
    runtime_degradation: Option<String>,
) -> CaptureModeReport {
    let parsed = irlume_camera::CaptureMode::parse(mode);
    match (source, qualification_state, parsed) {
        ("IRLUME_SEQUENTIAL_CAPTURE", _, Some(mode)) => {
            CaptureModeReport::Overridden(mode == irlume_camera::CaptureMode::Sequential)
        }
        ("runtime-health", _, _) => CaptureModeReport::RuntimeDegraded(
            runtime_degradation.unwrap_or_else(|| "unspecified".into()),
        ),
        (_, "qualified_concurrent" | "measured_sequential", Some(mode)) => {
            CaptureModeReport::Measured(mode, qualification_reason)
        }
        (_, "unqualified_no_authority", _) => CaptureModeReport::Unmeasured,
        (_, "no_ir_pair", _) => CaptureModeReport::NoIrPair,
        (_, "inconclusive", _) => CaptureModeReport::Inconclusive(
            qualification_reason.unwrap_or_else(|| "unspecified".into()),
        ),
        (_, "unqualified_context_changed" | "unreadable", _) => CaptureModeReport::Unreadable(
            qualification_reason.unwrap_or_else(|| qualification_state.into()),
        ),
        _ => CaptureModeReport::Unreadable("invalid daemon response".into()),
    }
}

/// Doctor's capture-mode block: which capture strategy the active camera pair
/// uses, and whether that was measured or is the unmeasured default.
///
/// Asks the daemon to resolve policy from the exact pair it owns, serialized as
/// camera-class work. This includes process-local runtime degradation and the
/// daemon's environment, neither of which a CLI-side config read can observe.
/// The wording of every case is [`capture_mode_report_line`].
fn report_capture_mode(report: &mut crate::doctor_report::Report) {
    use irlume_common::{Request, Response};
    let observed = match daemon_request(&Request::CaptureModeStatus) {
        Ok(Response::CaptureModeStatus {
            mode,
            source,
            qualification_state,
            qualification_reason,
            runtime_degradation,
            ..
        }) => capture_mode_report_from_status(
            &mode,
            &source,
            &qualification_state,
            qualification_reason,
            runtime_degradation,
        ),
        Ok(Response::Error(error)) | Err(error) => CaptureModeReport::Unreadable(error),
        Ok(other) => CaptureModeReport::Unreadable(format!("unexpected response {other:?}")),
    };
    let (state, detail) = capture_mode_report_line(&observed);
    report.check_detail("capture-mode", state, detail.clone());
    dout!(report, "[doctor] capture mode: {detail}");
}

/// Preflight diagnostics ("preparing"): discover + classify cameras, flag the
/// privacy switch, and confirm models + ONNX Runtime are present.
/// Certify that the polkit agent helper (polkit 126+ socket-activated,
/// device-sandboxed unit) can still reach the irlume daemon socket. irlume is
/// structurally immune to the sandbox that broke Howdy (it opens no camera in
/// the PAM process, only `/run/irlume.sock`), UNLESS a unit override hides the
/// socket path with a filesystem restriction. Best-effort, informative.
fn report_polkit_sandbox(report: &mut crate::doctor_report::Report) {
    use crate::doctor_report::State;
    // No socket-activated helper unit → pre-126 setuid helper (runs unconfined);
    // nothing to certify.
    let unit = std::process::Command::new("systemctl")
        .args(["cat", "polkit-agent-helper@.service"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    let Some(unit) = unit else {
        // No socket-activated helper: nothing to certify, and silence would make
        // the check vanish from the machine report entirely.
        report.check("polkit-helper-sandbox", State::Info);
        return;
    };
    // If the socket-activated helper is inactive, polkit uses the setuid helper,
    // which runs UNCONFINED: no sandbox applies, so the socket is reachable.
    let socket_active = std::process::Command::new("systemctl")
        .args(["is-active", "polkit-agent-helper.socket"])
        .output()
        .map(|o| o.stdout.starts_with(b"active"))
        .unwrap_or(false);
    // Directives that HIDE /run (and thus /run/irlume.sock) from the sandboxed
    // helper. Note what is NOT here: PrivateDevices/DeviceAllow (they gate
    // devices, not an AF_UNIX socket) and ProtectSystem=strict (it makes /run
    // READ-ONLY, but connect() to a socket does not write the file, so the
    // socket stays reachable). Only chroot/hide directives actually block it.
    let hides_run = socket_active
        && unit.lines().any(|l| {
            let t = l.trim();
            (t.starts_with("RootDirectory=") && !t.ends_with('='))
                || (t.starts_with("InaccessiblePaths=") && t.contains("/run"))
                || (t.starts_with("TemporaryFileSystem=") && t.contains("/run"))
        });
    if hides_run {
        dout!(report,
            "[doctor] ⚠ polkit helper sandbox may hide /run/irlume.sock; polkit face prompts\n     \
             would fall back to the password. Add a drop-in exposing only the socket:\n     \
             /etc/systemd/system/polkit-agent-helper@.service.d/irlume.conf with\n     \
             [Service] then a BindReadOnlyPaths=/run/irlume.sock line."
        );
        report.check("polkit-helper-sandbox", State::Warn);
    } else {
        dout!(
            report,
            "[doctor] polkit helper sandbox: OK ✓ (irlume uses the daemon socket, not the \
             camera, so the device sandbox that breaks Howdy does not apply)"
        );
        report.check("polkit-helper-sandbox", State::Pass);
    }
}

/// `--check` turns the report into a scriptable verdict; see `Summary`.
fn doctor_wants_check(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--check")
}

fn doctor(args: &[String]) -> std::process::ExitCode {
    let wants_check = doctor_wants_check(args);
    let mut report = crate::doctor_report::Report::new(crate::doctor_report::Mode::Human);
    let run = doctor_run(&mut report, args);
    let summary = report.summary();
    if summary.warnings + summary.failures > 0 {
        dout!(
            report,
            "[doctor] summary: {} warning(s), {} failure(s). Scripts: `irlume doctor --check` exits 1 on warnings, 2 on failures.",
            summary.warnings,
            summary.failures
        );
    }
    if wants_check {
        std::process::ExitCode::from(summary.check_exit_code())
    } else {
        run
    }
}

/// Whether an unreadable scan entry is a deliberately hardened no-records
/// YUYV IR node: the open was refused on permissions, the USB identity is in
/// the table the packaged rule ships, and the node's own state reads
/// hardened. Pure over the gathered facts so the rule is testable without a
/// camera (Codex #1109 round 5).
fn hardened_ir_node_present(
    errno: Option<i32>,
    usb: Option<(u16, u16)>,
    access: irlume_camera::node_access::NodeAccess,
) -> bool {
    matches!(errno, Some(libc::EACCES) | Some(libc::EPERM))
        && usb.is_some_and(|id| irlume_camera::uvc_descriptor::NO_RECORDS_YUYV_IR.contains(&id))
        && access == irlume_camera::node_access::NodeAccess::Hardened
}

/// The `camera-nodes` verdict: a classified IR node passes, as does a
/// deliberately hardened one (the daemon opens it as root); nothing readable
/// at all fails; some cameras but no IR warns.
fn camera_nodes_state(
    has_ir: bool,
    nothing_classified: bool,
    hardened_ir_present: bool,
) -> crate::doctor_report::State {
    use crate::doctor_report::State;
    if has_ir || hardened_ir_present {
        State::Pass
    } else if nothing_classified {
        State::Fail
    } else {
        State::Warn
    }
}

/// One scanned node's facts for `ir_node_access_rows`: its role where the
/// scan classified it (`None` for the unreadable bucket), its USB identity
/// where sysfs answered, its measured access state and its path.
type NodeAccessFact = (
    Option<irlume_camera::Role>,
    Option<(u16, u16)>,
    irlume_camera::node_access::NodeAccess,
    String,
);

/// The `ir-node-access` rows: one per in-class device, over its candidate
/// nodes' measured states (#1069). Candidates are the scan's classified IR
/// nodes (`Some(Role::Ir)`) and its unreadable nodes (`None`), with their USB
/// identities where sysfs answered; anything else never reaches a row. A
/// device with several candidate nodes (its capture and metadata nodes share
/// the rule) gets one row over their worst state. Pure so the wording is
/// testable without a camera.
fn ir_node_access_rows(entries: Vec<NodeAccessFact>) -> Vec<(crate::doctor_report::State, String)> {
    use crate::doctor_report::State;
    use irlume_camera::node_access::NodeAccess;
    let mut devices: std::collections::BTreeMap<(u16, u16), Vec<(String, NodeAccess)>> =
        std::collections::BTreeMap::new();
    for (role, usb, access, path) in entries {
        if !matches!(role, None | Some(irlume_camera::Role::Ir)) {
            continue;
        }
        let Some(id) = usb else { continue };
        if !irlume_camera::uvc_descriptor::NO_RECORDS_YUYV_IR.contains(&id) {
            continue;
        }
        devices.entry(id).or_default().push((path, access));
    }
    let mut rows = Vec::new();
    for (id, nodes) in devices {
        let paths = nodes
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let worst = nodes
            .iter()
            .map(|(_, access)| access)
            .max_by_key(|access| match access {
                NodeAccess::Hardened => 0,
                NodeAccess::Unreadable => 1,
                NodeAccess::Shared(_) => 2,
            })
            .expect("a device row has at least one node");
        let id_text = format!("{:04x}:{:04x}", id.0, id.1);
        let (state, detail) = match worst {
            NodeAccess::Hardened => (
                State::Pass,
                format!(
                    "{id_text} ({paths}): closed to everyone but root; the burst proof \
                     stands without the experimental opt-in"
                ),
            ),
            NodeAccess::Shared(why) => (
                State::Warn,
                format!(
                    "{id_text} ({paths}): {why}, so a non-root program can reach the \
                     emitter control within a burst; the burst proof stays inside the \
                     experimental split opt-in until the packaged udev rule applies (it \
                     closes the node at the camera's next plug or boot) or an \
                     administrator closes it"
                ),
            ),
            NodeAccess::Unreadable => (
                State::Unknown,
                format!("{id_text} ({paths}): the node's access state could not be read"),
            ),
        };
        rows.push((state, detail));
    }
    rows
}

/// The worst of the per-device row states: a shared device outranks an
/// unreadable one, which outranks a hardened one.
fn ir_node_access_worst(
    rows: &[(crate::doctor_report::State, String)],
) -> crate::doctor_report::State {
    use crate::doctor_report::State;
    if rows.iter().any(|(state, _)| *state == State::Warn) {
        State::Warn
    } else if rows.iter().any(|(state, _)| *state == State::Unknown) {
        State::Unknown
    } else {
        State::Pass
    }
}

/// The negotiated streams against the Windows Hello minimums (#223).
///
/// A line, not a gate: an under-spec stream still authenticates, but a smaller
/// face means fewer pixels behind the centre/edge ratio while a lower rate
/// means fewer usable frames per burst. Saying so is what the user can act on;
/// refusing would break cameras that work fine.
///
/// Both check ids are ALWAYS emitted, whatever this machine has: the machine
/// API's contract is that a check never disappears because it had nothing to
/// say, so an absent node reports Info rather than vanishing. Split from
/// `doctor_run` so a test can drive it against chosen paths; the camera nodes
/// come from `select_pair` at the call site.
fn stream_minimum_checks(report: &mut crate::doctor_report::Report, rgb_node: &str, ir_node: &str) {
    use crate::doctor_report::State;
    let checks: [(
        &str,
        &str,
        irlume_camera::Role,
        &str,
        &irlume_camera::StreamMinimum,
    ); 2] = [
        (
            "ir-stream-hello-minimum",
            "IR",
            irlume_camera::Role::Ir,
            ir_node,
            &irlume_camera::HELLO_IR_MIN,
        ),
        (
            "rgb-stream-hello-minimum",
            "RGB",
            irlume_camera::Role::Rgb,
            rgb_node,
            &irlume_camera::HELLO_RGB_MIN,
        ),
    ];
    for (id, label, role, node, min) in checks {
        if !std::path::Path::new(node).exists() {
            dout!(report, "[doctor] {label} stream: no selected node");
            report.check_detail(id, State::Info, "no selected node");
            continue;
        }
        let floor = format!("{}x{}@{}fps", min.width, min.height, min.fps);
        match irlume_camera::negotiated_stream(node, role) {
            Ok(spec) => {
                // Two decimals, because the floor itself is fractional
                // (7.5fps) and a 14.9 rounded to 15 would print a value that
                // contradicts the verdict beside it.
                let rate = match spec.fps {
                    Some(fps) => format!("@{fps:.2}fps"),
                    None => String::new(),
                };
                let shown = format!("{}x{}{rate} {}", spec.width, spec.height, spec.fourcc);
                match spec.meets(min) {
                    Some(true) => {
                        dout!(
                            report,
                            "[doctor] {label} stream: {shown} ✓ (Windows Hello minimum {floor})"
                        );
                        report.check_detail(id, State::Pass, &shown);
                    }
                    Some(false) => {
                        dout!(
                            report,
                            "[doctor] {label} stream: {shown} ⚠ below the published Windows \
                             Hello minimum {floor}; captures work, but expect weaker liveness \
                             margins on this module"
                        );
                        report.check_detail(id, State::Warn, &shown);
                    }
                    None => {
                        dout!(
                            report,
                            "[doctor] {label} stream: {shown}; dimensions meet the Windows \
                             Hello minimum {floor}, the driver reports no frame rate"
                        );
                        report.check_detail(id, State::Info, &shown);
                    }
                }
            }
            // Could not negotiate is "could not look" (the camera may be
            // mid-capture by the daemon), never silence and never a warn.
            Err(e) => {
                dout!(report, "[doctor] {label} stream: not readable now ({e})");
                report.check_detail(id, State::Unknown, e.to_string());
            }
        }
    }
}

fn selected_stream_minimum_checks(
    report: &mut crate::doctor_report::Report,
    pair: Option<(String, String)>,
) {
    let (rgb_node, ir_node) = pair.unwrap_or_default();
    stream_minimum_checks(report, &rgb_node, &ir_node);
}

/// One pass over the machine. Prints the human report or stays silent and
/// records, depending on `report`.
/// `args` carries `--user`, which doctor reports on in eight per-user lines.
/// Resolving with an empty slice ignored the flag silently, while
/// `docs/COMMANDS.md` documents `--user U` as a global convention.
/// Count the VALID failure records in `faillock --user` output. The tally
/// format is `When Type Source Valid` rows; a header-only output is zero.
/// Pure so the parsing is unit-testable against the live incident's shape.
fn count_faillock_records(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let t = l.trim_end();
            // A record row ends in the Valid column; the header ends in
            // "Valid" itself and the tally title line ends in ':'.
            t.ends_with(" V") || t.ends_with("\tV")
        })
        .count()
}

/// Report the pam_faillock tally for `user` when doctor can read it (root and
/// the binary present). Clean emits a quiet pass; any recorded failure warns
/// with the remedy, because above the deny threshold every password - the
/// right one included - is refused for the unlock window and the lock screen
/// shows only a generic failure.
fn report_faillock_state(report: &mut crate::doctor_report::Report, user: &str) {
    use crate::doctor_report::State;
    if !is_root() {
        return;
    }
    let output = match std::process::Command::new("faillock")
        .args(["--user", user])
        .output()
    {
        Ok(o) if o.status.success() => o,
        // Absent binary (no pam_faillock on this box) or a refused read:
        // nothing this check can say.
        _ => return,
    };
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let failures = count_faillock_records(&text);
    if failures == 0 {
        dout!(
            report,
            "[doctor] pam_faillock ({user}): no recorded failures"
        );
        report.check("pam-faillock", State::Pass);
        return;
    }
    dout!(
        report,
        "  ⠿ pam_faillock ({user}): {failures} recent failed login(s) recorded. Above the \
         deny threshold EVERY password, the correct one included, is refused until the \
         unlock window passes - the lock screen shows that as a plain failure. Clear it: \
         faillock --user {user} --reset"
    );
    report.check("pam-faillock", State::Warn);
}

/// Whether the armed keyring secret survives the next upgrade of this
/// release. Only a release listed in `upgrade_notice` asks the daemon; every
/// other host reports `info`. There, a GNOME keyring token warns with the
/// step, any other answer passes, and a daemon that does not answer the
/// metadata query or does not report the kind leaves the check `unknown`.
/// The query is `KeyringMetadata`, which reads the envelope only: the live
/// PCR diagnosis behind `KeyringInfo` waits on the daemon's TPM queue, and
/// this check needs only `armed` and `kind`.
fn report_keyring_os_upgrade(report: &mut crate::doctor_report::Report, user: &str) {
    use crate::doctor_report::State;
    const ID: &str = "keyring-os-upgrade";
    let notice = match upgrade_notice::host_token_upgrade_notice_checked() {
        Ok(Some(notice)) => notice,
        // A release that was read and is not listed: nothing to check.
        Ok(None) => {
            report.check(ID, State::Info);
            return;
        }
        // No os-release could be read: the check could not run.
        Err(_) => {
            report.check(ID, State::Unknown);
            return;
        }
    };
    let answer = daemon_request(&irlume_common::Request::KeyringMetadata {
        user: user.to_string(),
    });
    match upgrade_notice::token_armed(&answer) {
        Some(true) => {
            let advice = notice.advice(user);
            dout!(
                report,
                "[doctor] \u{26a0} {user} has a GNOME keyring token armed on {}.\n     {advice}",
                notice.release
            );
            report.check_detail(ID, State::Warn, advice);
        }
        Some(false) => report.check(ID, State::Pass),
        None => report.check(ID, State::Unknown),
    }
}

/// Doctor's line for an enrolled account whose active login manager is not
/// wired. On NixOS `irlume login enable` refuses, so it names the module.
fn unwired_login_line(user: &str, nixos: bool) -> String {
    if nixos {
        format!(
            "[doctor] ⚠ {user} is enrolled but no login manager is wired for face auth.\n     \
             On NixOS the system configuration owns the PAM stacks: list the display\n     \
             manager's PAM service under `services.irlume.pam.services` and rebuild\n     \
             (docs/NIXOS.md)."
        )
    } else {
        format!(
            "[doctor] ⚠ {user} is enrolled but no login manager is wired for face auth.\n     \
             A system update (authselect / pam-auth-update) may have regenerated the\n     \
             PAM stacks. The irlume-reconcile.path unit re-applies this automatically\n     \
             once login was enabled; if it persists, re-wire with:\n     \
             sudo irlume login enable --apply"
        )
    }
}

/// Doctor's line when the enrolled account's login screen is one irlume keeps
/// face off (a LightDM serving remote login screens), in place of
/// [`unwired_login_line`]: no regeneration stripped it, and re-running
/// `login enable` leaves it as it is.
fn face_kept_off_login_line(user: &str, dm: &str) -> String {
    format!(
        "[doctor] ⚠ {user} is enrolled, but {dm}'s login screen has no face line: irlume\n     \
         keeps face off it while it serves remote login screens (the {dm} note below\n     \
         says why and how to turn that off). `irlume login enable` does not change that."
    )
}

/// Doctor's line when polkit app prompts are not wired. On NixOS `irlume
/// login enable` refuses, so it points to docs/NIXOS.md instead.
fn polkit_unwired_line(bitwarden_action: bool, nixos: bool) -> &'static str {
    match (bitwarden_action, nixos) {
        (true, false) => {
            "[doctor] polkit app prompts: NOT wired, but Bitwarden's polkit action is installed.\n     \
             Its biometric unlock will fall back to the password prompt. Enable with:\n     \
             sudo irlume login enable --with-polkit --apply"
        }
        (true, true) => {
            "[doctor] polkit app prompts: NOT wired, but Bitwarden's polkit action is installed.\n     \
             Its biometric unlock will fall back to the password prompt. On NixOS the\n     \
             system configuration owns the PAM stacks (docs/NIXOS.md)."
        }
        (false, false) => {
            "[doctor] polkit app prompts: not wired (opt-in: sudo irlume login enable \
             --with-polkit --apply)"
        }
        (false, true) => {
            "[doctor] polkit app prompts: not wired (on NixOS the system configuration owns \
             the PAM stacks; docs/NIXOS.md)"
        }
    }
}

/// The `recognizer-selection` row when the daemon reported its placement
/// (#1053): `info` naming the governing `recognizer_device` word and what it
/// still leaves to admission and certification, or `unknown` when the daemon
/// reported no selection or one this build does not know. Pure so the
/// wording is testable without a daemon.
fn recognizer_selection_row(selection: Option<&str>) -> (crate::doctor_report::State, String) {
    use crate::doctor_report::State;
    match selection {
        Some("auto") => (
            State::Info,
            "auto; only a certified device can take the recognizer off CPU".to_owned(),
        ),
        Some("cpu") => (
            State::Info,
            "cpu; every probe stays on the CPU reference".to_owned(),
        ),
        Some("npu") => (
            State::Info,
            "npu; admission and certification still decide".to_owned(),
        ),
        Some("gpu") => (
            State::Info,
            "gpu; no build admits GPU placement yet".to_owned(),
        ),
        Some(other) => (
            State::Unknown,
            format!("the daemon reported an unrecognized selection ({other})"),
        ),
        None => (
            State::Unknown,
            "the daemon did not report a device selection".to_owned(),
        ),
    }
}

/// Extend the existing selection row without changing its severity. All new
/// text comes from closed enums; a rejected raw setting is never displayed.
fn recognizer_selection_report(
    selection: Option<&str>,
    provenance: Option<&irlume_common::recognizer_selection::RecognizerSelectionProvenance>,
) -> (crate::doctor_report::State, String) {
    use irlume_common::recognizer_selection::{
        RecognizerSelectionIssue as Issue, RecognizerSelectionSource as Source,
    };
    let (state, line) = recognizer_selection_row(selection);
    let Some(provenance) = provenance else {
        return (state, format!("{line}; source not reported"));
    };
    let source = match provenance.source {
        Source::Default => "default",
        Source::Settings => "settings",
        Source::Environment => "environment",
        Source::Unknown => "unknown",
    };
    let issue = match provenance.issue {
        Issue::None => "none",
        Issue::InvalidValue => "invalid value",
        Issue::DuplicateKey => "duplicate key",
        Issue::UnreadableSettings => "unreadable settings",
        Issue::Unknown => "unknown",
    };
    (state, format!("{line}; source: {source}; issue: {issue}"))
}

fn doctor_run(
    report: &mut crate::doctor_report::Report,
    args: &[String],
) -> std::process::ExitCode {
    use crate::doctor_report::State;
    use irlume_common::secureboot;
    // --- platform / trust anchors ------------------------------------------
    dout!(
        report,
        "[doctor] platform: {}",
        irlume_common::platform::distro_family().as_str()
    );
    report.check_detail(
        "platform",
        State::Info,
        irlume_common::platform::distro_family().as_str(),
    );
    let origin = commands::install_origin();
    let origin_detail = commands::origin_detail(&origin);
    dout!(report, "[doctor] install origin: {origin_detail}");
    report.check_detail("install-origin", State::Info, origin_detail);
    // `irlume logs debug on` persists across reboots, and while it is on the
    // journal gets exact scores and liveness measurements.
    match logs::debug_state() {
        Some(true) => {
            dout!(
                report,
                "[doctor] \u{26a0} debug tracing is on: {}",
                logs::DEBUG_ACTIVE_DETAIL
            );
            report.check_detail("debug-tracing", State::Warn, logs::DEBUG_ACTIVE_DETAIL);
        }
        Some(false) => report.check("debug-tracing", State::Pass),
        None => {
            dout!(
                report,
                "[doctor] debug tracing: unknown: {}",
                logs::DEBUG_UNKNOWN_DETAIL
            );
            report.check_detail("debug-tracing", State::Unknown, logs::DEBUG_UNKNOWN_DETAIL);
        }
    }
    match tpm_device() {
        Some(d) => {
            dout!(report, "[doctor] TPM 2.0: {d} ✓");
            report.check("tpm", State::Pass);
        }
        None => {
            dout!(
                report,
                "[doctor] TPM 2.0: none (/dev/tpmrm0 absent) ✗; required for sealing"
            );
            report.check("tpm", State::Fail);
        }
    }
    // What irlumed reads about its TPM: the CLI never opens it (irlumed alone
    // owns the TPM), and the daemon reads with its own TPM and PCR settings.
    let tpm = tpm_readiness(irlume_common::client::request);
    for (id, (state, detail)) in [
        (
            "tpm-firmware",
            tpm_firmware_report(
                &tpm.identity,
                &tpm.storage_key,
                &tpm.storage_keys,
                &tpm.da_exempt_key,
            ),
        ),
        ("tpm-pcr-bank", pcr_bank_check(&tpm.pcr_bank)),
        (
            "tpm-lockout",
            tpm_lockout_check(&tpm.lockout, &tpm.da_exempt_key),
        ),
        (
            "tpm-storage-keys",
            tpm_storage_keys_check(&tpm.da_exempt_key),
        ),
        // ADR-0036: irlumed's root-only TpmEndorsement request, with a
        // budget of its own, since deriving an EK can take seconds.
        (
            "tpm-endorsement",
            endorsement_check::check(
                &endorsement_check::from_irlumed(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            ),
        ),
        (
            "secure-boot-certificates",
            certificate_rollover_check(&secureboot::certificate_rollover()),
        ),
        (
            "shim-validation",
            shim_validation_check(secureboot::shim_validation()),
        ),
        ("pcr7-binding", pcr7_binding_check(&read_event_log())),
    ] {
        let mark = match state {
            State::Pass => " ✓",
            State::Warn => " ⚠",
            State::Fail => " ✗",
            State::Unknown | State::Info => "",
        };
        dout!(report, "[doctor] {id}: {detail}{mark}");
        report.check_detail(id, state, detail);
    }
    if !secureboot::secure_boot_present() {
        dout!(report, "[doctor] Secure Boot: unknown (not a UEFI boot?)");
        report.check("secure-boot", State::Unknown);
    } else if secureboot::is_secure_boot_enabled() {
        dout!(report, "[doctor] Secure Boot: enabled ✓");
        report.check("secure-boot", State::Pass);
    } else if secureboot::is_setup_mode() {
        dout!(report,
            "[doctor] Secure Boot: SETUP MODE ⚠ (keys not enrolled); PCR-7 binding is NOT enforcing"
        );
        report.check_detail("secure-boot", State::Warn, "setup mode: keys not enrolled");
    } else {
        dout!(
            report,
            "[doctor] Secure Boot: disabled ⚠ (TPM PCR-7 binding is weak; enable for trust)"
        );
        report.check_detail("secure-boot", State::Warn, "disabled");
    }
    dout!(
        report,
        "[doctor] boot mode: {}",
        secureboot::detect_boot_mode().as_str()
    );
    report.check_detail(
        "boot-mode",
        State::Info,
        secureboot::detect_boot_mode().as_str(),
    );
    // A control an interrupted `ir-setup` left changed on a camera. The capture
    // path puts it back on its own, but not when the operator has set
    // IRLUME_IR_EMITTER=off, and not while the camera is detached — which are
    // exactly the situations someone runs `doctor` in.
    match irlume_camera::emitter_journal::pending_summary() {
        irlume_camera::emitter_journal::PendingSummary::None => {
            report.check("emitter-undo-pending", State::Pass);
        }
        irlume_camera::emitter_journal::PendingSummary::Pending(entries) => {
            dout!(
                report,
                "[doctor] IR emitter: {} camera control(s) left changed by an interrupted \
                 setup ⚠ — {}. Reconnect the camera and authenticate, or run \
                 `sudo irlume ir-setup`, to put them back. If irlume has reported that \
                 its attempts ran out, shut the machine down fully and boot again: a \
                 reboot does not cut the camera's power, and a full power-off is what \
                 clears a stuck control on the hardware measured so far",
                entries.len(),
                entries.join("; ")
            );
            report.check_detail("emitter-undo-pending", State::Warn, entries.join("; "));
        }
        irlume_camera::emitter_journal::PendingSummary::Unreadable(why) => {
            // Root-only by design, so an ordinary run lands here. Unknown, not
            // Pass: nobody checked.
            report.check_detail("emitter-undo-pending", State::Unknown, why);
        }
    }
    // The stream store is the OTHER emitter ledger: per-stream writes whose
    // restore did not finish. A spent applied record here refuses every new
    // stream write, silently before #429, so a machine in that state had an
    // emitter that never lit and no surface saying why.
    match irlume_camera::stream_record::pending_summary() {
        irlume_camera::emitter_journal::PendingSummary::None => {
            report.check("emitter-stream-pending", State::Pass);
        }
        irlume_camera::emitter_journal::PendingSummary::Pending(entries) => {
            // The advice splits by record state, because the recovery paths
            // differ in kind (Codex round on #429): an APPLIED record is
            // claimed and restored by a later authentication, while a
            // PREPARED or unparseable one is never claimed (irlume cannot
            // prove its write reached the camera) and only an administrator
            // removing the named file resolves it.
            dout!(
                report,
                "[doctor] IR emitter: {} stream control record(s) still pending ⚠ — {}. \
                 A record marked 'applied' is put back by authenticating while the \
                 control still holds irlume's value; if its restore attempts ran out, \
                 shut the machine down fully (not a reboot) or unplug an external \
                 camera first. A record marked 'write may not have reached the camera' \
                 is never restored automatically, but stops blocking on its own once \
                 the control no longer holds its bytes: shut down fully, then \
                 authenticate once. A record that will not parse is the one case that \
                 needs an administrator to remove the named file",
                entries.len(),
                entries.join("; ")
            );
            report.check_detail("emitter-stream-pending", State::Warn, entries.join("; "));
        }
        irlume_camera::emitter_journal::PendingSummary::Unreadable(why) => {
            // Root-only by design, same as the journal store above.
            report.check_detail("emitter-stream-pending", State::Unknown, why);
        }
    }
    // Which capture strategy this camera pair runs, and whether it was measured
    // or is the unmeasured default (#100): silent adaptation hides regressions,
    // so name it.
    report_capture_mode(report);
    report.check(
        "signed-pcr-policy",
        if irlume_core::pcrsig::signed_policy_available() {
            State::Pass
        } else {
            State::Info
        },
    );
    dout!(
        report,
        "[doctor] signed PCR policy: {}",
        if irlume_core::pcrsig::signed_policy_available() {
            "systemd PCR-11 signature present; not used for new seals (it binds only what the booted OS measures)"
        } else {
            "none (no Tier 1 on this boot chain)"
        }
    );
    // An invalid policy or one covering no firmware-measured PCR is passed
    // over for sealing. An index from pcrlock_provisioned alone does not
    // establish which condition made pcrlock_for_sealing reject the policy.
    let pcrlock = (
        irlume_core::tpm::pcrlock_provisioned(),
        irlume_core::tpm::pcrlock_for_sealing(),
    );
    report.check(
        "pcrlock",
        if pcrlock.1.is_some() {
            State::Pass
        } else {
            State::Info
        },
    );
    dout!(
        report,
        "[doctor] pcrlock: {}",
        match pcrlock {
            (Some(nv), Some(_)) => format!(
                "provisioned, NV 0x{nv:x}; an arm binds to it if it unseals on this boot (Tier 2)"
            ),
            (Some(nv), None) => format!(
                "NV 0x{nv:x} reported, not eligible for new seals (invalid policy or no \
                 firmware-measured PCR (0 to 7)); seals use the configured literal PCR policy"
            ),
            (None, _) =>
                "not provisioned: seals use the literal PCR-7 policy + recovery passphrase \
                     (re-arm/restore after firmware updates); `systemd-pcrlock make-policy` \
                     enables Tier 2"
                    .to_string(),
        }
    );

    // --- cameras -----------------------------------------------------------
    dout!(
        report,
        "[doctor] camera nodes (classified by pixel format):"
    );
    let scan = irlume_camera::scan_nodes();
    let nodes = scan.classified.clone();
    // Capability, not identity: a consumer is told an IR node was classified,
    // never which device it is. The human report below still names them, since
    // a person debugging their own machine needs the path.
    // The verdict is unchanged by #227: a node irlume cannot read is still a
    // node it cannot use, so "nodes present, none readable" fails exactly as
    // "no nodes" does. What changed is that the lines below now say which.
    // One deliberate exception (#1069, Codex round 5): a no-records YUYV IR
    // node hardened by the packaged udev rule is unreadable to this seat-user
    // scan BECAUSE hardening succeeded; the daemon opens it as root, so it
    // counts as the machine's IR capability when its own state proves the
    // hardening (refused on permissions, in the USB identity table, and
    // reading hardened).
    let hardened_ir_present = scan.unreadable.iter().any(|u| {
        hardened_ir_node_present(
            u.errno,
            irlume_camera::uvc_descriptor::usb_ids(&u.path).ok(),
            irlume_camera::node_access::node_access(std::path::Path::new(&u.path)),
        )
    });
    report.check(
        "camera-nodes",
        camera_nodes_state(
            nodes.iter().any(|(_, r)| *r == irlume_camera::Role::Ir),
            nodes.is_empty(),
            hardened_ir_present,
        ),
    );
    // "Could not look" is not "nothing there". Reporting a /dev that would not
    // list as a machine with no cameras is the same mistake at one level up.
    if let Some(why) = &scan.listing_error {
        dout!(
            report,
            "  ⚠ {why}; whether this machine has camera nodes is unknown"
        );
    } else if nodes.is_empty()
        && scan.unreadable.is_empty()
        && scan.mc_centric.is_empty()
        && scan.other.is_empty()
    {
        dout!(report, "  (no /dev/video* nodes on this machine)");
    }
    // #575: the census renders every video-adjacent node and every
    // machine-level camera fact, each line carrying the evidence its
    // classification keyed on. The pieces this replaces (the per-node loop,
    // the IPU/bridge fallbacks, the grouped unreadable and MC-centric
    // lines) each told one part of the story; the census is the whole
    // answer to "broken, unusable class, or configuration", and it comes
    // from the same single scan the capability check above read, so doctor
    // classifies each node exactly once.
    for entry in irlume_camera::census::census_from(&scan) {
        dout!(report, "  {}", irlume_camera::census::render_line(&entry));
    }
    dout!(report, "[doctor] {}", sensor_policy::PAIRED_SUPPORT_NOTE);
    dout!(
        report,
        "[doctor] experimental split pairs: {}",
        split::experimental_status_line()
    );

    // --- IR node access for the no-records YUYV class (#1069) --------------
    // A descriptor-attested YUYV IR camera without per-frame illumination
    // records proves active IR from the burst's own alternation, and that
    // proof is complete only while no non-root program can open the node
    // (ADR-0031, amendment 2026-10-17). Report the device's real access
    // state: a node still carrying the seat ACL keeps the proof inside the
    // experimental opt-in. A successfully hardened node is one this scan
    // cannot open as the seat user, so it lands in `unreadable`, not
    // `classified`: both buckets are searched (Codex #1109 round 1). The
    // class membership is keyed on the USB identity table the packaged udev
    // rule ships, so this row names exactly the cameras it covers.
    {
        let mut entries: Vec<NodeAccessFact> = Vec::new();
        for (path, role) in &scan.classified {
            entries.push((
                Some(*role),
                irlume_camera::uvc_descriptor::usb_ids(path).ok(),
                irlume_camera::node_access::node_access(std::path::Path::new(path)),
                path.clone(),
            ));
        }
        for unreadable in &scan.unreadable {
            entries.push((
                None,
                irlume_camera::uvc_descriptor::usb_ids(&unreadable.path).ok(),
                irlume_camera::node_access::node_access(std::path::Path::new(&unreadable.path)),
                unreadable.path.clone(),
            ));
        }
        let rows = ir_node_access_rows(entries);
        for (_, detail) in &rows {
            dout!(report, "[doctor] IR node access: {detail}");
        }
        let (state, detail) = if rows.is_empty() {
            (
                State::Info,
                "no descriptor-attested YUYV IR camera without per-frame illumination \
                 records on this machine"
                    .to_string(),
            )
        } else {
            (
                ir_node_access_worst(&rows),
                rows.iter()
                    .map(|(_, detail)| detail.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        };
        report.check_detail("ir-node-access", state, detail);
    }

    // --- stream vs the Windows Hello minimums (#223) -----------------------
    {
        // deliberate camera probe: doctor's job is to inspect the hardware,
        // and negotiating a stream format needs the node open. Foreground and
        // occasional, not a refresh loop, so it is not the #187 shape.
        selected_stream_minimum_checks(report, irlume_camera::select_pair());
    }

    // --- models / runtime --------------------------------------------------
    dout!(report, "[doctor] models:");
    if commands::daemon_models_loaded() == Some(true) {
        dout!(report, "  loaded by the daemon ✓");
        report.check("models", State::Pass);
    } else {
        report.check(
            "models",
            if commands::REQUIRED_MODELS
                .iter()
                .all(|(f, env)| commands::resolve_model(f, env).is_some())
            {
                State::Pass
            } else {
                State::Fail
            },
        );
        for (f, env) in commands::REQUIRED_MODELS {
            match commands::resolve_model(f, env) {
                Some(p) => dout!(report, "  {f}: present ✓ ({})", p.display()),
                None => {
                    dout!(
                        report,
                        "  {f}: not found; install the irlume package (or run from the repo)"
                    )
                }
            }
        }
    }
    let ort = std::env::var("ORT_DYLIB_PATH").unwrap_or_default();
    report.check("ort-dylib-path", State::Info);
    dout!(
        report,
        "[doctor] ORT_DYLIB_PATH: {}",
        if ort.is_empty() {
            "(unset)".into()
        } else {
            ort
        }
    );
    // Which ONNX Runtime this shell would actually load, and whether it is
    // usable. The resolver prefers a packaged copy over the system library,
    // so a stale file at a packaged path silently outranks a healthy system
    // install; naming the resolved candidate and its version here is what
    // makes that visible (#187: a below-floor leftover from a previous
    // distro's package hung the daemon, and nothing reported which library
    // had been chosen).
    {
        let (candidate, verdict) = irlume_vision::runtime_resolution();
        let source = match &candidate {
            Some(path) => path.display().to_string(),
            None => "system libonnxruntime.so".to_string(),
        };
        match verdict {
            Ok(version) => {
                let detail = format!("{source} ({version})");
                report.check_detail("onnxruntime", State::Pass, &detail);
                dout!(report, "[doctor] ONNX Runtime: {detail} ✓");
            }
            Err(why) => {
                report.check_detail("onnxruntime", State::Fail, format!("{source}: {why}"));
                dout!(
                    report,
                    "[doctor] ONNX Runtime: {source} UNUSABLE ✗ ({why}). The daemon \
                     cannot load models from this; if a packaged path above is a \
                     leftover from a previous install, remove it"
                );
            }
        }
    }
    // The TFLite runtime the mesh runs on, probed the same way the ONNX row
    // is: a real load in this shell, naming what resolved. The mesh has been
    // a .tflite since #295 and a packaged daemon refuses to start without
    // the runtime, yet no surface reported it (found by the 2026-08-12
    // release audit through the Repair tab's same gap). The caveat both
    // rows share: this shell is unconfined, so a load that succeeds here
    // can still fail under the daemon's AppArmor profile.
    {
        use irlume_vision::tflite::{tflite_lib_candidates, tflite_runtime, TfliteUnavailable};
        match tflite_runtime() {
            Ok(_) => {
                let path = tflite_lib_candidates(
                    std::env::var(irlume_vision::tflite::TFLITE_LIB_ENV)
                        .ok()
                        .as_deref(),
                    |p| p.exists(),
                )
                .first()
                .map_or_else(|| "resolved".to_string(), |p| p.display().to_string());
                report.check_detail("tflite-runtime", State::Pass, &path);
                dout!(report, "[doctor] TFLite runtime: {path} ✓");
            }
            // A visible override error is an operator mistake THIS shell can
            // see: Fail. A plain not-found is a guess about the daemon's env
            // (the unit may set IRLUME_TFLITE_LIB), so Warn, matching the
            // ONNX fallback row's reasoning.
            Err(
                e @ (TfliteUnavailable::OverrideInvalid { .. }
                | TfliteUnavailable::OverrideFailed { .. }),
            ) => {
                report.check_detail("tflite-runtime", State::Fail, e.to_string());
                dout!(
                    report,
                    "[doctor] TFLite runtime: UNUSABLE ✗ ({e}); fix or unset \
                     IRLUME_TFLITE_LIB (the resolver refuses to fall through a \
                     broken override)"
                );
            }
            Err(e @ TfliteUnavailable::NotFound { .. }) => {
                report.check_detail("tflite-runtime", State::Warn, e.to_string());
                dout!(
                    report,
                    "[doctor] TFLite runtime: not loadable from this shell ⚠ ({e}). \
                     The mesh is a .tflite, so a daemon without it does not start; \
                     install the irlume package's runtime \
                     (/usr/share/irlume/tflite/libtensorflowlite_c.so) or set \
                     IRLUME_TFLITE_LIB in the irlumed unit"
                );
            }
        }
    }
    // --- pipeline stages (#276) -----------------------------------------
    // Each stage's model CANDIDATE from this process's search order. A
    // candidate, not a claim about the daemon: the service unit (or a
    // drop-in) sets the daemon's own environment, which this shell cannot
    // observe.
    dout!(
        report,
        "[doctor] pipeline stages (candidate per this shell's search order):"
    );
    for s in models::stage_statuses() {
        let Some(file) = s.file else { continue };
        let id = match s.stage {
            "detection" => "stage-detection-model",
            "landmarks" => "stage-landmarks-model",
            "recognition" => "stage-recognition-model",
            other => unreachable!("file-backed stage without a check id: {other}"),
        };
        let (state, line) = match &s.resolved {
            Some(c) if c.readable => (
                State::Pass,
                format!("{file} — {} ({})", c.origin, c.path.display()),
            ),
            // Present but not readable as a regular file: the daemon's
            // fs::read of this same candidate would fail, so this is at
            // least as bad as absent and must not report Pass.
            Some(c) => (
                if s.required { State::Fail } else { State::Warn },
                format!(
                    "{file} — {} ({}) exists but is NOT readable as a model file; \
                     the daemon's load of it would fail",
                    c.origin,
                    c.path.display()
                ),
            ),
            None if s.required => (
                State::Fail,
                format!("{file} — NOT FOUND; the daemon cannot start without it"),
            ),
            None => (
                State::Warn,
                format!("{file} — not found; detection-rescue alignment is disabled"),
            ),
        };
        dout!(report, "  {}: {line}", s.stage);
        report.check_detail(id, state, line);
    }
    // --- recognizer placement (ADR-0022 §13) --------------------------------
    // Where the daemon's recognizer computes authentication probes, as the
    // daemon reports it. Without its answer this is unknown, not CPU.
    match irlume_common::client::request_poll(&irlume_common::Request::Health) {
        Ok(irlume_common::Response::Health {
            recognizer: Some(placement),
            ..
        }) => {
            // `accelerator` is precise; the legacy `device` reads "cpu" for
            // a GPU placement so released clients keep working.
            let line = match (placement.accelerator.as_deref(), &placement.reason) {
                (Some("gpu"), _) => "GPU".to_owned(),
                (_, None) => "NPU".to_owned(),
                (_, Some(reason)) => format!("CPU: {reason}"),
            };
            dout!(report, "[doctor] recognizer: {line}");
            report.check_detail("recognizer-device", State::Info, line);
            let (selection_state, selection_line) = recognizer_selection_report(
                placement.selection.as_deref(),
                placement.selection_provenance.as_ref(),
            );
            dout!(report, "[doctor] recognizer selection: {selection_line}");
            report.check_detail("recognizer-selection", selection_state, selection_line);
            let (runtime_state, runtime_line) = match placement.runtime_available {
                Some(true) => (
                    State::Info,
                    "available to this engine; provider-neutral discovery succeeded",
                ),
                Some(false) => (
                    State::Info,
                    "unavailable to this engine; see the recognizer reason",
                ),
                None => (
                    State::Unknown,
                    "runtime discovery was not attempted or reported",
                ),
            };
            dout!(report, "[doctor] NPU runtime: {runtime_line}");
            report.check_detail("npu-runtime", runtime_state, runtime_line);
            let (qualification_state, qualification_line) = match placement.qualified {
                Some(true) => (State::Info, "qualified for this engine's NPU placement"),
                Some(false) => (
                    State::Info,
                    "not qualified for current placement; CPU reference active",
                ),
                None => (State::Unknown, "no model qualification was reported"),
            };
            dout!(report, "[doctor] NPU qualification: {qualification_line}");
            report.check_detail("npu-qualification", qualification_state, qualification_line);
            let platform = placement
                .platform
                .unwrap_or_else(|| "no NPU platform identity was read".to_owned());
            dout!(report, "[doctor] NPU platform: {platform}");
            report.check_detail("npu-platform", State::Info, platform);
            // The GPU rows (ADR-0033 phase 3), from optional fields an older
            // daemon never sends: absent reads as unknown, never as false.
            let (gpu_runtime_state, gpu_runtime_line) = match placement.gpu_runtime_available {
                Some(true) => (
                    State::Info,
                    "available to this engine; GPU discovery succeeded",
                ),
                Some(false) => (
                    State::Info,
                    "unavailable to this engine; see the recognizer reason",
                ),
                None => (
                    State::Unknown,
                    "GPU discovery was not attempted or reported",
                ),
            };
            dout!(report, "[doctor] GPU runtime: {gpu_runtime_line}");
            report.check_detail("gpu-runtime", gpu_runtime_state, gpu_runtime_line);
            let (gpu_qualification_state, gpu_qualification_line) = match placement.gpu_qualified {
                Some(true) => (State::Info, "qualified for this engine's GPU placement"),
                Some(false) => (
                    State::Info,
                    "not qualified for current placement; CPU reference active",
                ),
                None => (State::Unknown, "no GPU qualification was reported"),
            };
            dout!(
                report,
                "[doctor] GPU qualification: {gpu_qualification_line}"
            );
            report.check_detail(
                "gpu-qualification",
                gpu_qualification_state,
                gpu_qualification_line,
            );
            let gpu_platform = placement
                .gpu_platform
                .unwrap_or_else(|| "no GPU platform identity was read".to_owned());
            dout!(report, "[doctor] GPU platform: {gpu_platform}");
            report.check_detail("gpu-platform", State::Info, gpu_platform);
        }
        Ok(irlume_common::Response::Health { .. }) => {
            report.check_detail(
                "recognizer-device",
                State::Unknown,
                "the daemon predates this report",
            );
            report.check("recognizer-selection", State::Unknown);
            report.check("npu-platform", State::Unknown);
            report.check("npu-runtime", State::Unknown);
            report.check("npu-qualification", State::Unknown);
            report.check("gpu-platform", State::Unknown);
            report.check("gpu-runtime", State::Unknown);
            report.check("gpu-qualification", State::Unknown);
        }
        _ => {
            report.check_detail(
                "recognizer-device",
                State::Unknown,
                "the daemon did not answer",
            );
            report.check("recognizer-selection", State::Unknown);
            report.check("npu-platform", State::Unknown);
            report.check("npu-runtime", State::Unknown);
            report.check("npu-qualification", State::Unknown);
            report.check("gpu-platform", State::Unknown);
            report.check("gpu-runtime", State::Unknown);
            report.check("gpu-qualification", State::Unknown);
        }
    }
    // --- companion factors / data-at-rest ----------------------------------
    let fp_names = irlume_fingerprint::device_names();
    let fp = match fp_names.len() {
        0 if irlume_fingerprint::available() => "present ✓".into(),
        0 => "none".into(),
        _ => format!(
            "{} ✓ (manage with `irlume fingerprint`)",
            fp_names.join(" + ")
        ),
    };
    dout!(report, "[doctor] fingerprint reader: {fp}");
    // The same predicate the text line above uses, and the machine `status`
    // field beside it. `device_name()` answers "fprintd could NAME a device",
    // which is a narrower thing than "a reader was found": a present reader that
    // fprintd will not name printed "present ✓" in the text and "not found" in
    // the check on the same screen, and the machine field agreed with neither.
    report.check(
        "fingerprint-reader",
        if irlume_fingerprint::available() {
            State::Pass
        } else {
            State::Info
        },
    );
    if irlume_fingerprint::fprintd_present() {
        // Vendor stack behind the fprint bus name: open-fprintd/python-validity
        // answer the same D-Bus name with different failure modes (stale PPAs,
        // resume crashes, missing RegisterDevice); name it so bug reports and
        // remedies point at the right daemon.
        if let Some(unit) = irlume_fingerprint::bus_owner_unit() {
            if unit != "fprintd.service" {
                dout!(
                    report,
                    "  ⚠ the fprint bus name is owned by '{unit}', not fprintd.service: a \
                     vendor driver stack is answering; its failure modes differ from stock \
                     fprintd"
                );
            }
        }
        // Stale device claim: pam_fprintd then fails silently and the finger
        // prompt never appears. The dominant post-suspend fingerprint failure.
        let user = user_arg(args);
        if irlume_fingerprint::reader_stuck(&user) {
            dout!(
                report,
                "  ⚠ the reader is held by a stale fprintd claim (finger prompts will not \
                 appear; common after suspend/resume); fix: sudo systemctl restart fprintd"
            );
        }
        // The same search path libpam uses, so a vendor-only stack is not
        // missed by a warning whose whole job is noticing one (#208).
        let pam_path = fingerprint::PamSearchPath::live();
        if fingerprint::faillock_cohabits(&pam_path) {
            dout!(
                report,
                "  ⚠ pam_faillock and pam_fprintd share a PAM stack: a touch-sensor misread \
                 can burn every fingerprint retry in seconds, and each one counts toward the \
                 account lockout. If you get locked out: faillock --user <you> --reset"
            );
        }
        if fingerprint::fprintd_in_sudo(&pam_path) && fingerprint::sshd_present() {
            dout!(
                report,
                "  ⚠ pam_fprintd is reachable from the sudo stack and an SSH server is \
                 enabled: `sudo` inside an SSH session will stall for the fingerprint \
                 timeout (up to 30s) waiting on the local reader. Consider scoping \
                 fingerprint to login/lock services only."
            );
        }
    }

    // Template encryption + recovery come from the daemon (root-only store).
    let user = user_arg(args);
    // pam_faillock tally for this account (root-only read; the check is
    // silently omitted for non-root and absent binaries). A tripped lock
    // refuses even CORRECT passwords for the unlock window, and the lock
    // screen surfaces that as a generic failure - after failed face rounds
    // pushed the user to the password, a mistype or two can escalate into
    // what looks like a broken password (live incident, 2026-09-17).
    report_faillock_state(report, &user);
    let recovery = daemon_request(&irlume_common::Request::RecoveryStatus { user: user.clone() });
    match recovery {
        Ok(irlume_common::Response::RecoveryStatus {
            encrypted,
            recovery_set,
            key_present,
            ..
        }) => {
            dout!(
                report,
                "[doctor] templates ({user}): {} · recovery passphrase {}",
                match (encrypted, key_present) {
                    (true, true) => "ENCRYPTED ✓",
                    (true, false) => "ENCRYPTED but the TEMPLATE KEY IS MISSING (unreadable)",
                    (false, _) => "plaintext at rest",
                },
                if recovery_set {
                    "SET ✓"
                } else if encrypted && !key_present {
                    "not set; no backup available"
                } else {
                    "not set (run `irlume recovery setup`)"
                },
            );
            if encrypted && !key_present {
                dout!(
                    report,
                    "[doctor] {}",
                    crate::recovery::missing_key_advice(recovery_set)
                );
            }
            report.check_detail(
                "templates",
                if encrypted && !key_present {
                    State::Fail
                } else if encrypted {
                    State::Pass
                } else {
                    State::Warn
                },
                if encrypted && !key_present {
                    crate::recovery::missing_key_advice(recovery_set)
                } else {
                    "template key observation complete"
                },
            );
            report.check(
                "recovery-passphrase",
                if recovery_set {
                    State::Pass
                } else {
                    State::Warn
                },
            );
        }
        _ => {
            dout!(report, "[doctor] templates ({user}): unknown (daemon not reachable; run `irlume recovery status`)");
            // Unknown, not failing: the store is root-only, so an unreachable
            // daemon means we did not look, which is different from looking and
            // finding plaintext.
            report.check("templates", State::Unknown);
            report.check("recovery-passphrase", State::Unknown);
        }
    }
    // What protects the sealed secrets at rest: the keyring secret (with its
    // policy) and the template key, against the storage irlumed reports with
    // `SealedStorage` for its keyring and template-key directories and `/`,
    // `/usr` and `/etc` (the CLI's own probe for an older or unreachable
    // daemon). A TPM seal binds the boot chain, not the root filesystem, so
    // this applies whatever tier a new seal would get (`seal_storage`). The
    // template key's policy is not reported; whether seals use a pcrlock
    // policy here tells which it can be.
    let sealed = seal_storage::Sealed {
        keyring: seal_storage::keyring_seal_for(&user, daemon_request),
        template_key: seal_storage::template_key_sealed(&recovery),
        pcrlock_seals: pcrlock.1.is_some(),
    };
    let (state, detail) = seal_storage::state_dir_check(&user, &sealed);
    dout!(
        report,
        "[doctor] {}sealed storage ({user}): {detail}",
        if state == State::Warn {
            "\u{26a0} "
        } else {
            ""
        }
    );
    report.check_detail("sealed-storage", state, detail);

    // --- polkit app prompts ------------------------------------------------
    // Apps like Bitwarden implement "biometric unlock" on Linux as a polkit
    // prompt; wiring pam_irlume into polkit-1 is what lets a face satisfy it.
    // Bitwarden's polkit action file doubles as the tell that the user expects
    // biometric unlock to work (its flatpak/snap can't install it themselves).
    // Counts both the filename Bitwarden's own setup writes AND the one snapd
    // installs for a snap; keying on only the former made doctor tell snap users
    // to run `bitwarden setup`, which then refuses (snapd owns that file).
    let bitwarden_action = bitwarden::action_present();
    // Reserved v1 check id; the retired feature has no runtime/configuration path.
    report.check("credential-release-challenge", State::Info);
    report.check(
        "polkit-app-prompts",
        match crate::pamwire::polkit_wired() {
            Some(true) => State::Pass,
            Some(false) => State::Info,
            None => State::Unknown,
        },
    );
    match crate::pamwire::polkit_wired() {
        Some(true) => dout!(
            report,
            "{}",
            "[doctor] polkit app prompts: wired ✓ (keyboard confirmation required)"
        ),
        Some(false) => dout!(
            report,
            "{}",
            polkit_unwired_line(bitwarden_action, crate::nixos::host_is_nixos())
        ),
        None => {}
    }
    // polkit 126+ moved the agent helper into a sandboxed, socket-activated
    // systemd unit (PrivateDevices etc.) that BROKE Howdy's polkit face path,
    // because Howdy opens the camera inside the PAM process. irlume's PAM module
    // opens no device: it only connects the AF_UNIX daemon socket, which the
    // device sandbox does not block. Certify that here so a future sandbox
    // tightening that hid /run/irlume.sock would be visible.
    if crate::pamwire::polkit_wired() == Some(true) {
        report_polkit_sandbox(report);
        // The inverse of the wired-check above: face auth answers polkit, but
        // Bitwarden is installed without its polkit action, so its biometric
        // unlock silently falls back to the password. One command fixes it.
        if !bitwarden_action && bitwarden::app_detected() {
            dout!(
                report,
                "[doctor] Bitwarden is installed but its polkit action is not; its biometric \
                 unlock\n     falls back to the password. Fix: sudo irlume bitwarden setup --apply"
            );
        }
    } else {
        // The helper sandbox only matters once polkit prompts are wired, but the
        // check still has to report: an id missing from the machine document
        // means "this engine does not run that check", so staying silent here
        // would tell a consumer the check does not exist rather than that it did
        // not apply. Same rule that put `keyring-secrets` on Unknown.
        report.check("polkit-helper-sandbox", State::Info);
    }
    // The login keyring an app like Bitwarden reads from: report whether a
    // Secret Service provider is up and the collection is unlocked. Self-gates
    // on a session bus, so it stays silent under `sudo irlume doctor`.
    crate::secrets::report_keyring_status(report);
    report_keyring_os_upgrade(report, &user);

    // --- wiring drift ------------------------------------------------------
    // If the user is enrolled but no greeter is wired, a distro tool most
    // likely regenerated the PAM stacks (authselect apply on Fedora,
    // pam-auth-update on Debian) and dropped irlume's lines. Face still falls
    // back to the password, so this is not a lockout, but face login silently
    // stopped working. Surface it with the one-command fix.
    let (enrolled, ir_ratio_calibrated, camera_groups, camera_store_error) =
        match daemon_request(&irlume_common::Request::ListProfiles {
            user: user.clone(),
            structured_errors: false,
            handles: false,
        }) {
            Ok(irlume_common::Response::Enrollment {
                ref profiles,
                ir_ratio_calibrated,
                ref camera_groups,
                ref camera_store_error,
                ..
            }) => (
                !profiles.is_empty(),
                ir_ratio_calibrated,
                camera_groups.clone(),
                camera_store_error.clone(),
            ),
            _ => (false, false, Vec::new(), None),
        };
    // Secondary camera groups (ADR-0024): a store that cannot be summarized
    // or a stale/disconnected group is a Warn, never a silent absence.
    if let Some(error) = &camera_store_error {
        dout!(report, "[doctor] camera groups unusable: {error}");
        report.check("camera-groups", State::Warn);
    } else if !camera_groups.is_empty() {
        for group in &camera_groups {
            let mut problems = Vec::new();
            if group.stale {
                problems.push("stale (primary changed; re-add the camera)");
            }
            if !group.connected {
                problems.push("disconnected");
            }
            if problems.is_empty() {
                dout!(report, "[doctor] camera group {} is healthy", group.id);
            } else {
                dout!(
                    report,
                    "[doctor] camera group {}: {}",
                    group.id,
                    problems.join(", ")
                );
            }
        }
        let unhealthy = camera_groups.iter().any(|g| g.stale || !g.connected);
        report.check(
            "camera-groups",
            if unhealthy { State::Warn } else { State::Pass },
        );
    }
    // An IR enrollment made before the per-user center/edge floor existed carries
    // no recorded ratio, so the personalized anti-print check never engages (new
    // IR enrollments fit it automatically). Nudge a re-enroll to activate it.
    // Secure/IR hardware only, and only when actually enrolled.
    report.check(
        "ir-calibration",
        if !enrolled || !crate::caps().ir_pair {
            // Not applicable on this machine or for this account; reported so a
            // consumer sees the check ran rather than silently vanishing.
            State::Info
        } else if ir_ratio_calibrated {
            State::Pass
        } else {
            State::Warn
        },
    );
    if enrolled && !ir_ratio_calibrated && crate::caps().ir_pair {
        dout!(
            report,
            "[doctor] {user}'s face enrollment predates the per-user IR center/edge floor\n     \
             (an anti-print check that new IR enrollments fit automatically).\n     \
             Re-enroll to activate it: the TUI Profiles tab, or `sudo irlume enroll`."
        );
    }
    // The greeter the ACTIVE display manager consults, not any-of. `login_wired`
    // is true when ANY greeter, the lock screen, or the fingerprint-keyring
    // service carries the line, and this file's own sibling documents where that
    // misleads: a distro update that strips the active greeter while a stale
    // inactive greeter file keeps the line leaves it true and the real login
    // broken. Doctor exists to catch exactly that, and was passing it.
    // Read from the greeter's authentication mode, as `login status` reads
    // it: a greeter left with only irlume's reseal lines (a LightDM serving
    // remote login screens) authenticates nothing, though reconcile counts
    // it as intact.
    let login_ok = crate::pamwire::active_login_wired_by_mode();
    report.check(
        "login-wiring",
        if login_ok {
            State::Pass
        } else if enrolled {
            State::Warn
        } else {
            State::Info
        },
    );
    // A login screen irlume deliberately leaves unwired (a LightDM serving
    // XDMCP or VNC login screens to remote users); the display-manager check
    // below reports it.
    let unwired = crate::pamwire::active_dm_face_blocked();
    if enrolled && !login_ok {
        let nixos = crate::nixos::host_is_nixos();
        let line = match &unwired {
            Some((dm, _)) if !nixos => face_kept_off_login_line(&user, dm),
            _ => unwired_login_line(&user, nixos),
        };
        dout!(report, "{line}");
    }
    // irlume's own /etc copies of vendor PAM files: whether each is in step
    // with its vendor copy. Emitted on every run; `pass` covers a machine with
    // none. The detail names services only, never paths.
    let override_reports = crate::pamwire::override_reports();
    let worst = override_reports
        .iter()
        .map(|r| r.level)
        .max()
        .unwrap_or(crate::pamwire::OverrideLevel::Pass);
    for r in &override_reports {
        dout!(
            report,
            "[doctor] {} login override {}: {}",
            if r.level == crate::pamwire::OverrideLevel::Warn {
                "⚠"
            } else {
                "·"
            },
            r.service,
            r.note
        );
    }
    // Joined with a separator no note contains, so a reader can split the
    // detail back into one note per service.
    let override_detail = override_reports
        .iter()
        .map(|r| format!("{}: {}", r.service, r.note))
        .collect::<Vec<_>>()
        .join(" | ");
    let override_state = match worst {
        crate::pamwire::OverrideLevel::Warn => State::Warn,
        crate::pamwire::OverrideLevel::Info => State::Info,
        crate::pamwire::OverrideLevel::Pass => State::Pass,
    };
    if override_detail.is_empty() {
        report.check("login-overrides", override_state);
    } else {
        report.check_detail("login-overrides", override_state, override_detail);
    }
    // A brand-new or renamed display manager irlume has no PAM mapping for:
    // `login enable` can't target it, so face login there quietly stays on the
    // password no matter how the reconcile self-heal runs. `active_display_manager`
    // still resolves the symlink, so name the DM and point at the tracker; adding
    // one line to dm_pam_services is all support takes.
    // The machine answer carries the instruction-display limitation too, as
    // DETAIL rather than a new id or a changed state: the check means "irlume can
    // wire this display manager", which stays true when the greeter cannot show a
    // PAM message. Without it a desktop integration reading `doctor --json` would
    // see `pass` while the human output shows a warning, and this file's own rule
    // is that the two must not disagree.
    // A login screen irlume deliberately leaves unwired (`unwired` above) is
    // one it cannot target either, so the same check warns and says why.
    match (crate::pamwire::active_dm_recognized(), &unwired) {
        (Some((dm, true)), Some((_, why))) => report.check_detail(
            "display-manager",
            State::Warn,
            format!("{dm}; irlume keeps face and fingerprint off it: {why}"),
        ),
        (Some((dm, true)), None)
            if crate::pamwire::active_dm_hides_pam_instructions().is_some() =>
        {
            report.check_detail(
                "display-manager",
                State::Pass,
                format!("{dm}; does not display PAM instructions to the user"),
            )
        }
        (Some((_, true)), None) => report.check("display-manager", State::Pass),
        (Some((_, false)), _) => report.check("display-manager", State::Warn),
        (None, _) => report.check("display-manager", State::Info),
    }
    if let Some((dm, why)) = &unwired {
        // Said from the stack itself: where the reseal lines could not be
        // placed, irlume took all its lines out, the hand-off too.
        let handoff = if crate::pamwire::active_greeter_hands_tokens_over() {
            "a GNOME keyring token is still handed over"
        } else {
            "irlume's lines are all out of that stack, so a GNOME keyring token armed for \
             an account is not handed over there"
        };
        dout!(
            report,
            "[doctor] ⚠ {why}.\n     irlume keeps face and fingerprint off {dm}'s login screen while \
             that is so; your\n     password works, and {handoff}. To use face\n     there, turn \
             that server off in LightDM's configuration and restart LightDM (it\n     keeps the \
             configuration it started with); the reconcile unit then puts the face\n     lines \
             back, or run `sudo irlume login enable --apply`."
        );
    }
    if let Some((dm, false)) = crate::pamwire::active_dm_recognized() {
        dout!(
            report,
            "[doctor] ⚠ irlume has no PAM wiring recipe for the active display manager\n     \
             '{dm}', so face login cannot be wired for it (your password still works).\n     \
             This is usually a display manager that is new, or was renamed by an update.\n     \
             Please report it at https://github.com/archledger/irlume/issues so we can\n     \
             add it."
        );
    }
    // authselect / pam-auth-update awareness: on hosts where a distro tool owns
    // the PAM stacks, confirm the self-heal watcher is in place so the user
    // knows a future `authselect apply` / `pam-auth-update` won't silently kill
    // face login (the reconcile.path re-applies it). Only meaningful once wired.
    if crate::pamwire::login_wired() {
        report_pam_regeneration_guard(report);
    } else {
        // Nothing is wired, so there is no wiring for a regeneration to strip.
        // Reported rather than skipped, for the same reason as the polkit
        // sandbox above: a vanished id is read as an absent check.
        report.check("pam-regeneration-guard", State::Info);
    }
    // Leftover backups next to the managed binaries, and hand-installed builds
    // overlaying the packaged ones (silent when clean).
    strays::report(report, &origin);

    std::process::ExitCode::SUCCESS
}

/// Whether a PAM-regenerating distro tool manages this host's stacks, as a
/// human label: authselect (Fedora/RHEL) or pam-auth-update (Debian/Ubuntu).
/// `None` on a host where PAM files are hand-managed, so the guard advisory
/// stays quiet (nothing periodically rewrites the stack there).
fn pam_regenerator() -> Option<&'static str> {
    // authselect only "manages" a host when a profile is selected; `current`
    // exits non-zero on a host that opted out (e.g. custom /etc/pam.d).
    let authselect_active = std::process::Command::new("authselect")
        .arg("current")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if authselect_active {
        return Some("authselect");
    }
    if std::path::Path::new("/usr/sbin/pam-auth-update").exists() {
        return Some("pam-auth-update");
    }
    None
}

/// Confirm the reconcile.path self-heal is armed on hosts whose PAM stacks a
/// distro tool regenerates. Prints a green line when protected, or a warning
/// (with the fix) when the tool is present but the watcher is not active.
fn report_pam_regeneration_guard(report: &mut crate::doctor_report::Report) {
    use crate::doctor_report::State;
    let Some(tool) = pam_regenerator() else {
        // No distro tool owns the PAM stacks here, so there is nothing to guard
        // against. Recorded rather than skipped so the check never silently
        // disappears from the machine report.
        report.check("pam-regeneration-guard", State::Info);
        return;
    };
    let watcher_active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "irlume-reconcile.path"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    report.check(
        "pam-regeneration-guard",
        if watcher_active {
            State::Pass
        } else {
            State::Warn
        },
    );
    if watcher_active {
        dout!(
            report,
            "[doctor] PAM regeneration guard: OK ✓ ({tool} manages this host; \
             irlume-reconcile.path will re-apply face-auth wiring if it gets stripped)"
        );
    } else {
        dout!(report,
            "[doctor] ⚠ {tool} manages this host's PAM stacks, but the irlume-reconcile.path\n     \
             self-heal watcher is not active; a future regeneration could silently drop\n     \
             face login. Enable it: sudo systemctl enable --now irlume-reconcile.path"
        );
    }
}

/// Full live pipeline on one camera frame: capture RGB → YuNet detect → align
/// the top face → AuraFace embed. Prints what each stage produced. Needs both
/// model files + `libonnxruntime.so` (ORT_DYLIB_PATH) and camera access.
fn capture(args: &[String]) -> std::process::ExitCode {
    let device = flag(args, "--device").unwrap_or("/dev/video0");
    let (Some(det_path), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume capture --det <yunet.onnx> --model <glintr100.onnx> [--device /dev/videoN]");
        return std::process::ExitCode::from(2);
    };

    // Source: a still image (--image, for validating the decode) or the camera.
    let (data, width, height) = if let Some(path) = flag(args, "--image") {
        match image::open(path) {
            Ok(img) => {
                let rgb = img.to_rgb8();
                let (w, h) = rgb.dimensions();
                println!("[capture] {w}x{h} from image {path}");
                (rgb.into_raw(), w, h)
            }
            Err(e) => {
                eprintln!("image load failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        match irlume_camera::capture_rgb(device) {
            Ok(f) => {
                println!("[capture] {}x{} RGB frame from {device}", f.width, f.height);
                (f.data, f.width, f.height)
            }
            Err(e) => {
                eprintln!("capture failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    };
    let view = irlume_vision::align::RgbView {
        data: &data,
        width,
        height,
    };

    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let faces = det.detect(&view)?;
        println!("[detect] {} face(s)", faces.len());
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            println!("  no face in frame; sit in view and re-run.");
            return Ok(());
        };
        println!(
            "[detect] top: score {:.3}, bbox [{:.0},{:.0},{:.0},{:.0}]",
            top.score, top.bbox[0], top.bbox[1], top.bbox[2], top.bbox[3]
        );
        let chip = irlume_vision::align::align_to_arcface(&view, &top.landmarks)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let e = emb.embed(&chip)?;
        let norm = e.iter().map(|x| x * x).sum::<f32>().sqrt();
        println!(
            "[embed]  512-D, L2 norm {norm:.4}, head [{:.3}, {:.3}, {:.3}, {:.3}]",
            e[0], e[1], e[2], e[3]
        );
        println!("[ok] full pipeline ran: capture → detect → align → embed.");
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pipeline error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Serializes unit tests that mutate process-global environment variables
/// (PATH, USER, IRLUME_CONFIG_DIR, IRLUME_STATE_DIR, ...): the same pattern as
/// `tui::tests::ENV_LOCK` (which guards IRLUME_SOCKET), shared here so the
/// env-mutating tests in main.rs, commands.rs, and models.rs never race.
#[cfg(test)]
pub(crate) mod testenv {
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}

/// Phase-1 make-or-break: load the recognition model and embed the same chip
/// twice: cosine MUST be ~1.0. Proves the ONNX path is deterministic and the
/// preprocessing is wired before any matching is trusted. Needs the AuraFace
/// model file and `libonnxruntime.so` available at runtime.
/// `irlume selftest liveness`: run the daemon's IR liveness self-test (fires
/// the camera through the running daemon, so no camera contention). The daemon
/// root-gates it (the raw measurements are a spoof-tuning oracle), so this must
/// run as root; the TUI reaches it via `sudo irlume selftest liveness`.
fn selftest_liveness() -> std::process::ExitCode {
    use irlume_common::{Request, Response, SelfTestKind};
    match daemon_request(&Request::SelfTest {
        kind: SelfTestKind::Liveness,
    }) {
        Ok(Response::SelfTest { passed, detail }) => {
            println!("[selftest liveness] {detail}");
            if passed {
                println!("[selftest liveness] PASS");
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Ok(Response::Error(e)) => {
            eprintln!("[selftest liveness] {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(o) => {
            eprintln!("[selftest liveness] unexpected: {o:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[selftest liveness] {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn selftest_align(args: &[String]) -> std::process::ExitCode {
    let model = match flag(args, "--model") {
        Some(p) => p,
        None => {
            eprintln!("usage: irlume selftest align --model <glintr100.onnx>");
            return std::process::ExitCode::from(2);
        }
    };
    match irlume_vision::Embedder::load_from_file(model) {
        Ok(mut emb) => {
            let (passed, detail) = irlume_vision::selftest_alignment_identity(&mut emb);
            println!("[selftest align] {detail}");
            if passed {
                println!("[selftest align] PASS: ONNX embed path is deterministic.");
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("[selftest align] FAIL: check preprocessing / channel order.");
                std::process::ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("[selftest align] could not load model: {e}");
            eprintln!("  (need the .onnx file and libonnxruntime.so on the system)");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {

    /// #1069: the rows name exactly the cameras the packaged udev rule
    /// covers; a hardened node the seat user's scan cannot open arrives as an
    /// unreadable entry and must still get its row (Codex #1109 round 1).
    #[test]
    fn ir_node_access_rows_cover_classified_and_unreadable_nodes() {
        use crate::doctor_report::State;
        use irlume_camera::node_access::NodeAccess;
        let t480 = Some((0x5986, 0x1141));
        // One device, both its nodes unreadable to the seat user: one row,
        // pass, naming both nodes.
        let rows = ir_node_access_rows(vec![
            (None, t480, NodeAccess::Hardened, "/dev/video0".into()),
            (None, t480, NodeAccess::Hardened, "/dev/video1".into()),
        ]);
        let [(state, detail)] = rows.as_slice() else {
            panic!("one device gets one row, got {rows:?}")
        };
        assert_eq!(*state, State::Pass);
        assert!(
            detail.contains("5986:1141")
                && detail.contains("/dev/video0")
                && detail.contains("/dev/video1"),
            "{detail}"
        );
        // An RGB node of even an in-class device, a records-capable IR camera
        // (the ASUS) and a node whose USB identity was not read never row.
        assert!(ir_node_access_rows(vec![
            (
                Some(irlume_camera::Role::Rgb),
                t480,
                NodeAccess::Hardened,
                "/dev/video0".into()
            ),
            (
                Some(irlume_camera::Role::Ir),
                Some((0x3277, 0x0059)),
                NodeAccess::Shared("the seat tag is set".into()),
                "/dev/video2".into()
            ),
            (
                Some(irlume_camera::Role::Ir),
                None,
                NodeAccess::Shared("the seat tag is set".into()),
                "/dev/video3".into()
            ),
        ])
        .is_empty());
        // One shared node of the pair makes the device warn with the remedy.
        let rows = ir_node_access_rows(vec![
            (None, t480, NodeAccess::Hardened, "/dev/video0".into()),
            (
                None,
                t480,
                NodeAccess::Shared("owned by uid 1000".into()),
                "/dev/video1".into(),
            ),
        ]);
        assert_eq!(rows[0].0, State::Warn);
        assert!(
            rows[0].1.contains("owned by uid 1000")
                && rows[0].1.contains("experimental split opt-in")
                && !rows[0].1.contains('\n'),
            "{}",
            rows[0].1
        );
        // Unreadable outranks hardened but never shared.
        let rows = ir_node_access_rows(vec![(
            None,
            t480,
            NodeAccess::Unreadable,
            "/dev/video0".into(),
        )]);
        assert_eq!(rows[0].0, State::Unknown);
        assert!(rows[0].1.contains("/dev/video0"), "{}", rows[0].1);
    }

    /// #1069: a shared node outranks an unreadable one, which outranks a
    /// hardened one, so the one machine-level check reads the worst node.
    #[test]
    fn ir_node_access_worst_orders_warn_unknown_pass() {
        use crate::doctor_report::State;
        let row = |state| (state, String::new());
        assert_eq!(ir_node_access_worst(&[row(State::Pass)]), State::Pass);
        assert_eq!(
            ir_node_access_worst(&[row(State::Pass), row(State::Unknown)]),
            State::Unknown
        );
        assert_eq!(
            ir_node_access_worst(&[row(State::Unknown), row(State::Warn)]),
            State::Warn
        );
        assert_eq!(
            ir_node_access_worst(&[row(State::Warn), row(State::Pass)]),
            State::Warn
        );
    }

    /// Codex #1109 round 5: on a host where the packaged rule hardened the
    /// no-records YUYV IR node, the seat user's scan cannot open it, and that
    /// success must not fail the camera-nodes capability check.
    #[test]
    fn camera_nodes_count_a_deliberately_hardened_ir_node() {
        use crate::doctor_report::State;
        use irlume_camera::node_access::NodeAccess;
        // The hardened in-class unreadable node counts as IR capability.
        assert!(hardened_ir_node_present(
            Some(libc::EACCES),
            Some((0x5986, 0x1141)),
            NodeAccess::Hardened
        ));
        assert!(hardened_ir_node_present(
            Some(libc::EPERM),
            Some((0x5986, 0x1141)),
            NodeAccess::Hardened
        ));
        // A busy node is not hardening evidence, and neither are an off-table
        // identity, an identity sysfs could not read, or a node still shared.
        assert!(!hardened_ir_node_present(
            Some(libc::EBUSY),
            Some((0x5986, 0x1141)),
            NodeAccess::Hardened
        ));
        assert!(!hardened_ir_node_present(
            Some(libc::EACCES),
            Some((0x3277, 0x0059)),
            NodeAccess::Hardened
        ));
        assert!(!hardened_ir_node_present(
            Some(libc::EACCES),
            Some((0x5986, 0x1141)),
            NodeAccess::Shared("the seat tag is set".into())
        ));
        assert!(!hardened_ir_node_present(
            Some(libc::EACCES),
            None,
            NodeAccess::Hardened
        ));
        // The verdict mapping, including a hardened-only host passing.
        assert_eq!(camera_nodes_state(true, false, false), State::Pass);
        assert_eq!(camera_nodes_state(false, true, true), State::Pass);
        assert_eq!(camera_nodes_state(false, false, true), State::Pass);
        assert_eq!(camera_nodes_state(false, true, false), State::Fail);
        assert_eq!(camera_nodes_state(false, false, false), State::Warn);
    }

    #[test]
    fn faillock_record_counting_matches_the_tally_format() {
        // Header only: a clean account answers with just the title + header.
        assert_eq!(
            count_faillock_records("archledger:\nWhen                Type  Source     Valid\n"),
            0
        );
        // The live 2026-09-17 incident's shape: three valid records.
        let incident = "archledger:\nWhen                Type  Source                                           Valid\n\
            2026-09-17 15:10:17 TTY   /dev/tty4                                            V\n\
            2026-09-17 15:10:40 TTY   /dev/tty4                                            V\n\
            2026-09-17 15:11:07 TTY   /dev/tty4                                            V\n";
        assert_eq!(count_faillock_records(incident), 3);
        // Only VALID records count; an invalidated row is not a lock.
        let mixed = "u:\nWhen Type Source Valid\n2026-09-17 15:10:17 TTY /dev/tty4 V\n2026-09-17 15:10:40 TTY /dev/tty4 R\n";
        assert_eq!(count_faillock_records(mixed), 1);
        assert_eq!(count_faillock_records(""), 0);
    }

    #[test]
    fn tpm_firmware_wording_names_the_advisory_and_its_reach() {
        use crate::doctor_report::State;
        use irlume_core::tpm::{DerivedKey, StorageKeyCheck, TpmIdentity};
        let clean = Ok(StorageKeyCheck::Clean);
        let id = |manufacturer: &str, firmware| {
            Ok(TpmIdentity {
                manufacturer: manufacturer.into(),
                vendor: "LNL".into(),
                firmware,
            })
        };
        let (state, detail) = tpm_firmware_check(&id("INTC", (700, 20)), &clean);
        assert_eq!(
            (state, detail.as_str()),
            (State::Info, "INTC LNL, firmware 700.20")
        );
        let (state, detail) = tpm_firmware_check(&id("IFX", (7, 61)), &clean);
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("CVE-2017-15361") && detail.contains("storage key"),
            "{detail}"
        );
        let (state, detail) = tpm_firmware_check(&id("STM", (73, 8)), &clean);
        assert_eq!(state, State::Info, "TPM-FAIL is not on irlume's path");
        assert!(
            detail.contains("CVE-2019-16863") && detail.contains("does not use"),
            "{detail}"
        );
        // A key generated before a firmware update stays weak after it.
        let weak = |handle| {
            Ok(StorageKeyCheck::RocaFingerprint {
                handle,
                derived: Some(DerivedKey::Same),
            })
        };
        let (state, detail) = tpm_firmware_check(&id("IFX", (7, 85)), &weak(0x8101_0002));
        assert_eq!(state, State::Warn);
        assert!(
            detail.starts_with("IFX LNL, firmware 7.85: ")
                && detail.contains("ROCA fingerprint")
                && detail.contains("whatever the firmware"),
            "{detail}"
        );
        for needle in [
            "evict only irlume's key",
            "`sudo tpm2_evictcontrol -C o -c 0x81010002`",
            "IRLUME_TCTI",
            "Do not clear the whole TPM",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
        // The advice names the handle irlumed read the key at, and the
        // warning stands when the TPM's identity could not be read.
        let (state, detail) = tpm_firmware_check(&Err("busy".into()), &weak(0x8100_0005));
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.starts_with("irlume's storage key carries the ROCA fingerprint")
                && detail.contains("`sudo tpm2_evictcontrol -C o -c 0x81000005`")
                && !detail.contains("0x81010002"),
            "{detail}"
        );
        // After a firmware update fixed the key generation, irlume's own key
        // is no longer the one the TPM derives: it is still the one to evict.
        let updated = Ok(StorageKeyCheck::RocaFingerprint {
            handle: 0x8101_0002,
            derived: Some(DerivedKey::Unaffected),
        });
        let (state, detail) = tpm_firmware_check(&id("IFX", (7, 85)), &updated);
        assert_eq!(state, State::Warn, "{detail}");
        for needle in [
            "ROCA fingerprint",
            "firmware update has fixed its key generation",
            "`tpm2_readpublic -c 0x81010002`",
            "`sudo tpm2_evictcontrol -C o -c 0x81010002`",
            "IRLUME_TCTI",
            "Do not clear the whole TPM",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
        // A key with irlume's template that irlume did not derive, on
        // firmware that still generates affected keys, gets no eviction
        // command: another tool may rely on it.
        for derived in [Some(DerivedKey::Other), None] {
            let planted = Ok(StorageKeyCheck::RocaFingerprint {
                handle: 0x8101_0002,
                derived,
            });
            let (state, detail) = tpm_firmware_check(&id("IFX", (7, 85)), &planted);
            assert_eq!(state, State::Warn, "{detail}");
            assert!(
                detail.contains("ROCA fingerprint")
                    && detail.contains("another tool may have placed it")
                    && detail.contains("`tpm2_readpublic -c 0x81010002`")
                    && detail.contains("IRLUME_TCTI with `-T`")
                    && detail.contains("Do not clear the whole TPM")
                    && !detail.contains("tpm2_evictcontrol"),
                "{derived:?}: {detail}"
            );
        }
        // A daemon from before the field answers without it.
        let old: StorageKeyCheck =
            serde_json::from_str(r#"{"RocaFingerprint":{"handle":2164326402}}"#).unwrap();
        assert_eq!(
            old,
            StorageKeyCheck::RocaFingerprint {
                handle: 0x8101_0002,
                derived: None
            }
        );
        let (state, detail) = tpm_firmware_check(&id("IFX", (7, 85)), &Ok(StorageKeyCheck::Absent));
        assert_eq!(state, State::Info, "{detail}");
        // A fixed Infineon whose key could not be checked is not shown as fine.
        let (state, detail) =
            tpm_firmware_check(&id("IFX", (7, 85)), &Err("ReadPublic failed".into()));
        assert_eq!(state, State::Unknown, "{detail}");
        assert!(detail.contains("ReadPublic failed"), "{detail}");
        // Elsewhere the key's state does not change the verdict.
        let (state, _) = tpm_firmware_check(&id("INTC", (700, 20)), &Err("busy".into()));
        assert_eq!(state, State::Info);
        let (state, detail) = tpm_firmware_check(
            &Err("irlumed: TPM readiness requires root (peer uid 1000)".into()),
            &Err(String::new()),
        );
        assert_eq!(state, State::Unknown);
        assert!(detail.contains("requires root"), "{detail}");
    }

    /// No reply ever leads the CLI to the TPM: each way of getting none is
    /// unknown with its reason, and a report passes through unchanged.
    #[test]
    fn tpm_readiness_comes_only_from_irlumed() {
        use irlume_common::tpm_readiness::{PcrBankReadiness, StorageKeyCheck};
        use irlume_common::{Request, Response};
        let reason = |reply: std::io::Result<Response>| {
            let report = tpm_readiness(|request| {
                assert!(matches!(request, Request::TpmReadiness));
                reply
            });
            assert_eq!(
                report.identity.as_ref().err(),
                report.pcr_bank.as_ref().err()
            );
            report.identity.unwrap_err()
        };
        assert!(reason(Ok(Response::Error("bad request".into()))).contains("predates"));
        assert!(reason(Err(std::io::ErrorKind::NotFound.into())).contains("not running"));
        assert!(reason(Err(std::io::ErrorKind::TimedOut.into())).contains("could not be read"));
        assert!(reason(Ok(Response::Error(
            "TPM readiness requires root (peer uid 1000)".into()
        )))
        .contains("requires root"));
        assert!(reason(Ok(Response::Pong)).contains("unexpected"));
        let lockout = irlume_common::tpm_readiness::TpmLockout::from_properties(
            0x4, 1, 32, 7200, 86400, false,
        );
        let report = tpm_readiness(|_| {
            Ok(Response::TpmReadiness {
                identity: Err("busy".into()),
                pcr_bank: Ok(PcrBankReadiness::Ready(vec![7])),
                storage_key: Ok(StorageKeyCheck::Clean),
                lockout: Ok(lockout),
                da_exempt_key: Ok(irlume_common::tpm_readiness::DaExemptKey {
                    handle: Some(0x8101_0003),
                    ..Default::default()
                }),
                storage_keys: Ok(Vec::new()),
            })
        });
        assert_eq!(report.pcr_bank, Ok(PcrBankReadiness::Ready(vec![7])));
        assert_eq!(report.storage_key, Ok(StorageKeyCheck::Clean));
        assert_eq!(report.lockout, Ok(lockout));
        assert_eq!(report.identity.unwrap_err(), "busy");
        let unreachable = tpm_readiness(|_| Err(std::io::ErrorKind::NotFound.into()));
        assert!(unreachable.lockout.unwrap_err().contains("not running"));
        assert!(unreachable
            .da_exempt_key
            .unwrap_err()
            .contains("not running"));
    }

    /// ADR-0034 §4: a lockout is a warning whichever key irlume seals under,
    /// worded for whether it blocks irlume; no lockout authorization is info;
    /// otherwise pass; a lockout state not read is unknown.
    #[test]
    fn tpm_lockout_warns_in_lockout_and_says_whom_it_blocks() {
        use crate::doctor_report::State;
        use irlume_core::tpm::TpmLockout;
        let persisted = Ok(irlume_common::tpm_readiness::DaExemptKey::default());
        let state = |permanent, failed, no_da| {
            tpm_lockout_check(
                &Ok(TpmLockout::from_properties(
                    permanent, failed, 32, 7200, 86400, no_da,
                )),
                &persisted,
            )
        };
        let (reading, detail) = state(0x204, 32, false);
        assert_eq!(reading, State::Warn);
        assert!(detail.contains("use the password"), "{detail}");
        assert!(detail.contains("encrypted enrollment"), "{detail}");
        assert!(detail.contains("--auth=file:-"), "{detail}");
        assert!(detail.contains("IRLUME_TCTI with `-T`"), "{detail}");
        assert!(detail.contains("within 7200 s"), "{detail}");
        assert!(detail.contains("another try for 86400 s"), "{detail}");
        assert!(detail.contains("keep the machine running"), "{detail}");
        assert!(detail.contains("destroys every key"), "{detail}");
        let (_, detail) = tpm_lockout_check(
            &Ok(TpmLockout::from_properties(0x204, 32, 32, 7200, 0, false)),
            &persisted,
        );
        assert!(detail.contains("until the next restart"), "{detail}");
        let (reading, detail) = state(0x204, 32, true);
        assert_eq!(reading, State::Warn);
        assert!(detail.contains("irlume is not affected"), "{detail}");
        let (reading, detail) = state(0x200, 32, false);
        assert_eq!(reading, State::Warn);
        assert!(detail.contains("no lockout authorization"), "{detail}");
        assert!(detail.contains("IRLUME_TCTI with `-T`"), "{detail}");
        assert!(!detail.contains("--auth"), "{detail}");
        let (reading, detail) = state(0x0, 3, false);
        assert_eq!(reading, State::Info);
        assert!(detail.contains("any process"), "{detail}");
        let (reading, detail) = state(0x4, 3, false);
        assert_eq!(reading, State::Pass);
        assert!(detail.contains("3 of 32 failures"), "{detail}");
        let (reading, detail) =
            tpm_lockout_check(&Err("irlumed is not running".into()), &persisted);
        assert_eq!(reading, State::Unknown);
        assert!(detail.contains("not running"), "{detail}");
    }

    /// ADR-0034 §4 and #1083: not in lockout, a refused persist of the
    /// DA-exempt key is a warning that names the refusal and when irlumed
    /// tries again; in lockout the lockout warning comes first; an older
    /// daemon's missing part changes nothing.
    #[test]
    fn tpm_lockout_warns_when_the_da_exempt_key_could_not_be_persisted() {
        use crate::doctor_report::State;
        use irlume_common::tpm_readiness::{DaExemptKey, KeyRefusal, RefusalReason};
        use irlume_core::tpm::TpmLockout;
        let refused = |reason| {
            Ok(DaExemptKey {
                refused: Some(KeyRefusal {
                    reason,
                    detail: "the TPM's words".into(),
                }),
                ..Default::default()
            })
        };
        let calm = Ok(TpmLockout::from_properties(0x4, 0, 32, 7200, 86400, false));
        let (reading, detail) = tpm_lockout_check(&calm, &refused(RefusalReason::NoSpace));
        assert_eq!(reading, State::Warn);
        assert!(detail.contains("no room"), "{detail}");
        assert!(detail.contains("the TPM's words"), "{detail}");
        assert!(detail.contains("next TPM lockout"), "{detail}");
        assert!(
            detail.contains("next start once the TPM reports room"),
            "{detail}"
        );
        let (_, detail) = tpm_lockout_check(&calm, &refused(RefusalReason::OwnerAuthorization));
        assert!(detail.contains("owner authorization is set"), "{detail}");
        assert!(detail.contains("later boot"), "{detail}");
        assert!(!detail.contains("reports room"), "{detail}");
        let (_, detail) = tpm_lockout_check(&calm, &refused(RefusalReason::HandleOverride));
        assert!(
            detail.contains("next start once IRLUME_SRK_HANDLE is unset"),
            "{detail}"
        );
        let (_, detail) = tpm_lockout_check(&calm, &refused(RefusalReason::Unknown));
        assert!(detail.contains("refused it"), "{detail}");
        let locked = Ok(TpmLockout::from_properties(
            0x204, 32, 32, 7200, 86400, false,
        ));
        let (reading, detail) = tpm_lockout_check(&locked, &refused(RefusalReason::NoSpace));
        assert_eq!(reading, State::Warn);
        assert!(detail.contains("dictionary-attack lockout"), "{detail}");
        let older = Err(irlume_common::tpm_readiness::DA_EXEMPT_KEY_NOT_REPORTED.to_owned());
        let (reading, _) = tpm_lockout_check(&calm, &older);
        assert_eq!(reading, State::Pass, "an older irlumed changes nothing");
        let failed = Err("/var/lib/irlume/keyring: permission denied".to_owned());
        let (reading, detail) = tpm_lockout_check(&calm, &failed);
        assert_eq!(
            reading,
            State::Unknown,
            "a current irlumed's failure is surfaced"
        );
        assert!(detail.contains("could not report"), "{detail}");
        assert!(detail.contains("permission denied"), "{detail}");
        let (_, detail) = tpm_lockout_check(&calm, &refused(RefusalReason::Unknown));
        assert!(detail.contains("does not know the reason"), "{detail}");
        assert!(!detail.contains("later boot"), "{detail}");
        let unread: Result<TpmLockout, String> = Err("the TPM did not answer".into());
        let (reading, detail) = tpm_lockout_check(&unread, &refused(RefusalReason::NoSpace));
        assert_eq!(reading, State::Warn, "a recorded refusal stays actionable");
        assert!(detail.contains("lockout state not read"), "{detail}");
        assert!(detail.contains("no room"), "{detail}");
        let (reading, _) = tpm_lockout_check(&unread, &Ok(DaExemptKey::default()));
        assert_eq!(reading, State::Unknown);
        let hostile = Ok(DaExemptKey {
            refused: Some(KeyRefusal {
                reason: RefusalReason::Other,
                detail: "\u{1b}]0;title\u{7}\nnext line".into(),
            }),
            ..Default::default()
        });
        let (_, detail) = tpm_lockout_check(&calm, &hostile);
        assert!(!detail.chars().any(char::is_control), "{detail:?}");
    }

    /// ADR-0034, Phase 3 amendment (#1073 item 2): doctor's `tpm-firmware`
    /// reads irlumed's per-key report. A weak DA-exempt key says why it is
    /// not replaced yet (the firmware, a refused replacement) or that the
    /// next start replaces it; a superseded key still persisted names the
    /// envelopes still under it, and only once none has named it since a
    /// start in an earlier boot is the manual command offered. A reply
    /// without the list reads as before, and the original key's part stands.
    #[test]
    fn tpm_firmware_reports_every_weak_storage_key_by_role() {
        use crate::doctor_report::State;
        use irlume_common::tpm_readiness::{
            DaExemptKey, DerivedKey, EnvelopeKind, KeyRefusal, OriginalKeyEnvelope,
            OriginalKeyEnvelopes, RefusalReason, StorageKeyCheck, StorageKeyEntry, StorageKeyRole,
            STORAGE_KEYS_NOT_REPORTED,
        };
        let id = |manufacturer: &str, firmware: (u16, u16)| {
            Ok(irlume_core::tpm::TpmIdentity {
                manufacturer: manufacturer.into(),
                vendor: String::new(),
                firmware,
            })
        };
        let identity = id("INTC", (700, 20));
        let clean = Ok(StorageKeyCheck::Clean);
        let weak = |handle, derived| StorageKeyCheck::RocaFingerprint { handle, derived };
        let entry = |role, handle: u32, check, total: u32, unused_across_boots| StorageKeyEntry {
            role,
            handle,
            name: "000b11".into(),
            check,
            envelopes: Some(OriginalKeyEnvelopes {
                named: (0..total.min(1))
                    .map(|_| OriginalKeyEnvelope {
                        user: "alice".into(),
                        kind: EnvelopeKind::TemplateKey,
                    })
                    .collect(),
                total,
            }),
            unused_across_boots,
        };
        let key = |derivation_weak, replacement_refused| {
            Ok(DaExemptKey {
                handle: Some(0x8101_0003),
                derivation_weak,
                replacement_refused,
                any_envelope: true,
                ..Default::default()
            })
        };
        let report = |entries: Vec<StorageKeyEntry>, da_exempt_key| {
            tpm_firmware_report(&identity, &clean, &Ok(entries), &da_exempt_key)
        };

        // Nothing weak: the original key's reading stands as it was.
        let (state, detail) = report(
            vec![entry(
                StorageKeyRole::DaExempt,
                0x8101_0003,
                StorageKeyCheck::Clean,
                0,
                false,
            )],
            key(false, None),
        );
        assert_eq!(
            (state, detail.clone()),
            tpm_firmware_check(&identity, &clean)
        );
        let older = tpm_firmware_report(
            &identity,
            &clean,
            &Err(STORAGE_KEYS_NOT_REPORTED.into()),
            &key(false, None),
        );
        assert_eq!(older, tpm_firmware_check(&identity, &clean));
        // A current irlumed that could not check them does not read as clean.
        let (state, detail) = tpm_firmware_report(
            &identity,
            &clean,
            &Err("the keyring store could not be read\nforged".into()),
            &key(false, None),
        );
        assert_eq!(state, State::Unknown);
        assert!(
            detail.contains("could not check") && !detail.contains('\n'),
            "{detail}"
        );

        let da_exempt = |derived| {
            entry(
                StorageKeyRole::DaExempt,
                0x8101_0003,
                weak(0x8101_0003, derived),
                1,
                false,
            )
        };
        let (state, detail) = report(vec![da_exempt(Some(DerivedKey::Same))], key(true, None));
        assert_eq!(state, State::Warn);
        assert!(detail.contains("update the TPM firmware"), "{detail}");
        let (_, detail) = report(
            vec![da_exempt(Some(DerivedKey::Unaffected))],
            key(false, None),
        );
        assert!(detail.contains("replaces it at its next start"), "{detail}");
        let (state, detail) = report(vec![da_exempt(None)], key(false, None));
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("next start derives its template again"),
            "{detail}"
        );
        // Without the DA-exempt part of the reply, nothing says whether a
        // start replaces it: no promise either way.
        let (state, detail) = report(vec![da_exempt(None)], Err("the record lock".into()));
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("is unknown")
                && detail.contains("the record lock")
                && !detail.contains("next start"),
            "{detail}"
        );
        // A weak original key the record names at another handle is
        // reported; the one at the configured handle is the original-key
        // reading, not repeated.
        let original_at = |handle| {
            entry(
                StorageKeyRole::Original,
                handle,
                weak(handle, None),
                0,
                false,
            )
        };
        let (state, detail) = report(vec![original_at(0x8101_0002)], key(false, None));
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("0x81010002") && detail.contains("no longer names"),
            "{detail}"
        );
        let weak_here = Ok(StorageKeyCheck::RocaFingerprint {
            handle: 0x8101_0002,
            derived: None,
        });
        let (_, detail) = tpm_firmware_report(
            &identity,
            &weak_here,
            &Ok(vec![original_at(0x8101_0002)]),
            &key(false, None),
        );
        assert!(!detail.contains("no longer names"), "{detail}");
        // With no envelope stored, irlumed's start leaves the key: no
        // promise of a replacement at the next start.
        let empty = |derivation_weak| {
            Ok(DaExemptKey {
                handle: Some(0x8101_0003),
                derivation_weak,
                ..Default::default()
            })
        };
        for derivation_weak in [false, true] {
            let (state, detail) = report(vec![da_exempt(None)], empty(derivation_weak));
            assert_eq!(state, State::Warn);
            assert!(
                detail.contains("No envelope is stored yet")
                    && !detail.contains("replaces it at its next start")
                    && detail.contains("update") == derivation_weak,
                "{detail}"
            );
        }
        let refused = KeyRefusal {
            reason: RefusalReason::NoSpace,
            detail: "insufficient space\nforged".into(),
        };
        let (state, detail) = report(
            vec![da_exempt(Some(DerivedKey::Unaffected))],
            key(false, Some(refused)),
        );
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("could not persist its replacement"),
            "{detail}"
        );
        assert!(!detail.contains('\n'), "{detail}");

        let superseded = |total, across| {
            entry(
                StorageKeyRole::Superseded,
                0x8101_0004,
                weak(0x8101_0004, None),
                total,
                across,
            )
        };
        // A role a newer irlumed added: a weak key warns, with no command.
        let unknown = |check| entry(StorageKeyRole::Unknown, 0x8101_0006, check, 0, true);
        let (state, detail) = report(vec![unknown(weak(0x8101_0006, None))], key(false, None));
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("role this irlume does not know") && !detail.contains("evictcontrol"),
            "{detail}"
        );
        let (state, detail) = report(vec![unknown(StorageKeyCheck::Clean)], key(false, None));
        assert_eq!(
            (state, detail),
            tpm_firmware_check(&identity, &clean),
            "a clean key in an unknown role adds nothing"
        );
        const EVICT: &str = "sudo tpm2_evictcontrol -C o -c 0x81010004";
        let (state, detail) = report(vec![superseded(1, false)], key(false, None));
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("alice's template key") && !detail.contains(EVICT),
            "{detail}"
        );
        let (_, detail) = report(vec![superseded(0, false)], key(false, None));
        assert!(detail.contains("once a start in a later boot") && !detail.contains(EVICT));
        let (state, detail) = report(vec![superseded(0, true)], key(false, None));
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains(EVICT) && detail.contains("tpm2_readpublic -c 0x81010004"),
            "{detail}"
        );
        // A superseded key that is gone, and a clean one still persisted.
        let (_, detail) = report(
            vec![entry(
                StorageKeyRole::Superseded,
                0x8101_0004,
                StorageKeyCheck::Absent,
                0,
                true,
            )],
            key(false, None),
        );
        assert_eq!(detail, tpm_firmware_check(&identity, &clean).1);
        let (state, _) = report(
            vec![entry(
                StorageKeyRole::Superseded,
                0x8101_0004,
                StorageKeyCheck::Clean,
                1,
                false,
            )],
            key(false, None),
        );
        assert_eq!(state, State::Info);
        // A weak original key keeps its warning, with the others after it.
        let roca = Ok(weak(0x8101_0002, Some(DerivedKey::Same)));
        let (state, detail) = tpm_firmware_report(
            &identity,
            &roca,
            &Ok(vec![superseded(1, false)]),
            &key(false, None),
        );
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("0x81010002") && detail.contains("0x81010004"),
            "{detail}"
        );
    }

    /// ADR-0034, Phase 3 amendment: doctor's `tpm-storage-keys` names a key
    /// waiting to be retired with its handle, its TPM name and what it waits
    /// for. A key today's derivation does not give gets the manual command
    /// and its warning only once no envelope is under it; a failed
    /// retirement never gets it. A daemon that predates the report, or
    /// whose report could not be read, leaves it unknown, and what the
    /// record supplied is cleaned again.
    #[test]
    fn tpm_storage_keys_says_what_the_original_keys_retirement_waits_for() {
        use crate::doctor_report::State;
        use irlume_common::tpm_readiness::{
            DaExemptKey, EnvelopeKind, OriginalKey, OriginalKeyEnvelope, OriginalKeyEnvelopes,
            RetirementWait, DA_EXEMPT_KEY_NOT_REPORTED,
        };
        let report = |original_key: Option<OriginalKey>, envelopes: Vec<OriginalKeyEnvelope>| {
            let total = u32::try_from(envelopes.len()).unwrap();
            Ok(DaExemptKey {
                original_key,
                on_original_key: Some(OriginalKeyEnvelopes {
                    named: envelopes,
                    total,
                }),
                ..Default::default()
            })
        };
        let waiting = |wait| {
            Some(OriginalKey::Waiting {
                handle: 0x8101_0002,
                name: "000bab".into(),
                wait,
            })
        };
        let alice = OriginalKeyEnvelope {
            user: "alice".into(),
            kind: EnvelopeKind::TemplateKey,
        };
        let check = |key| tpm_storage_keys_check(&key);
        const EVICT: &str = "tpm2_evictcontrol";

        let (state, detail) = check(Err(DA_EXEMPT_KEY_NOT_REPORTED.to_owned()));
        assert_eq!(state, State::Unknown, "{detail}");
        let (state, detail) = check(report(None, vec![]));
        assert_eq!(
            state,
            State::Unknown,
            "an irlumed without the report: {detail}"
        );
        let (state, detail) = check(Err("the store could not be read".into()));
        assert!(
            state == State::Unknown && detail.contains("could not report"),
            "{detail}"
        );
        let (state, _) = check(report(Some(OriginalKey::NotRecorded), vec![]));
        assert_eq!(state, State::Info);
        let (state, detail) = check(report(
            Some(OriginalKey::Retired {
                handle: 0x8101_0002,
            }),
            vec![],
        ));
        assert!(
            state == State::Pass && detail.contains("0x81010002"),
            "{detail}"
        );

        for (wait, envelopes, want, words) in [
            (
                RetirementWait::Envelopes,
                vec![alice.clone()],
                State::Info,
                "alice's template key",
            ),
            (
                RetirementWait::Count,
                vec![],
                State::Info,
                "next start counts",
            ),
            (
                RetirementWait::LaterBoot,
                vec![],
                State::Info,
                "first start in a later boot",
            ),
            (
                RetirementWait::NextStart,
                vec![],
                State::Info,
                "retires it at its next start",
            ),
            (
                RetirementWait::DaExemptKey,
                vec![],
                State::Warn,
                "DA-exempt storage key",
            ),
            (RetirementWait::Unchecked, vec![], State::Info, "checks it"),
            (
                RetirementWait::HandleChanged {
                    configured: Some(0x8101_0010),
                },
                vec![],
                State::Info,
                "Set IRLUME_SRK_HANDLE back to 0x81010002",
            ),
            (
                RetirementWait::HandleChanged { configured: None },
                vec![],
                State::Info,
                "a value irlumed refuses",
            ),
            (
                RetirementWait::NotReproduced { in_use: true },
                vec![alice.clone()],
                State::Info,
                "envelopes are still under it",
            ),
            (
                RetirementWait::NotReproduced { in_use: false },
                vec![alice.clone()],
                State::Info,
                "alice's template key",
            ),
            (
                RetirementWait::NotReproduced { in_use: true },
                vec![],
                State::Info,
                "an envelope irlumed cannot read",
            ),
        ] {
            let (state, detail) = check(report(waiting(wait.clone()), envelopes));
            assert_eq!(state, want, "{wait:?}: {detail}");
            assert!(detail.contains(words), "{wait:?}: {detail}");
            assert!(
                detail.contains("0x81010002") && detail.contains("000bab"),
                "{detail}"
            );
            assert!(
                !detail.contains(EVICT),
                "{wait:?} offers no eviction: {detail}"
            );
        }
        let (state, detail) = check(report(
            waiting(RetirementWait::UnsettledMoves {
                envelopes: vec![OriginalKeyEnvelope {
                    user: "bob\u{1b}[2J".into(),
                    kind: EnvelopeKind::KeyringSecret,
                }],
                total: 1,
            }),
            vec![],
        ));
        assert_eq!(state, State::Info);
        assert!(detail.contains("keyring secret") && !detail.chars().any(char::is_control));
        // More moves than irlumed names: the total stands.
        let many: Vec<OriginalKeyEnvelope> = (0..32)
            .map(|n| OriginalKeyEnvelope {
                user: format!("user{n:02}"),
                kind: EnvelopeKind::KeyringSecret,
            })
            .collect();
        let (_, detail) = check(report(
            waiting(RetirementWait::UnsettledMoves {
                envelopes: many,
                total: 40,
            }),
            vec![],
        ));
        assert!(detail.contains("and 28 more"), "{detail}");
        let (_, detail) = check(report(
            waiting(RetirementWait::UnsettledMoves {
                envelopes: vec![],
                total: 3,
            }),
            vec![],
        ));
        assert!(detail.contains("3 envelopes under names"), "{detail}");

        let (state, detail) = check(report(
            waiting(RetirementWait::NotReproduced { in_use: false }),
            vec![],
        ));
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("`sudo tpm2_evictcontrol -C o -c 0x81010002`")
                && detail.contains("tpm2_readpublic -c 0x81010002")
                && detail.contains("Do not clear the whole TPM"),
            "the manual path, with its warning: {detail}"
        );
        for in_this_boot in [true, false] {
            let (state, detail) = check(report(
                waiting(RetirementWait::Failed {
                    detail: "TPM_RC_BAD_AUTH\nforged".into(),
                    in_this_boot,
                }),
                vec![],
            ));
            assert_eq!(state, State::Warn);
            assert!(detail.contains("TPM_RC_BAD_AUTH") && !detail.contains('\n'));
            assert!(
                !detail.contains(EVICT),
                "a failed proof offers no eviction: {detail}"
            );
            let when = if in_this_boot {
                "first start in a later boot"
            } else {
                "at its next start"
            };
            assert!(detail.contains(when), "{detail}");
        }
        let (_, detail) = check(report(
            Some(OriginalKey::Waiting {
                handle: 0x8101_0002,
                name: "\u{1b}]0;title\u{7}zz".into(),
                wait: RetirementWait::Count,
            }),
            vec![],
        ));
        assert!(!detail.chars().any(char::is_control), "{detail:?}");
        assert!(!detail.contains("title"), "only hex is shown: {detail}");
        let (state, _) = check(report(Some(OriginalKey::Unknown), vec![]));
        assert_eq!(state, State::Unknown);
        let (state, _) = check(report(waiting(RetirementWait::Unknown), vec![]));
        assert_eq!(state, State::Unknown);
    }

    /// ADR-0034 §4: in lockout, doctor names each account and envelope kind
    /// still on the original key and what the lockout blocks for it, and the
    /// refused-persist warning names what stays there. Names are cleaned,
    /// capped and counted; an empty or missing list keeps the general
    /// wording.
    #[test]
    fn tpm_lockout_names_the_envelopes_still_on_the_original_key() {
        use crate::doctor_report::State;
        use irlume_common::tpm_readiness::{
            DaExemptKey, EnvelopeKind, KeyRefusal, OriginalKeyEnvelope, OriginalKeyEnvelopes,
            RefusalReason,
        };
        use irlume_core::tpm::TpmLockout;
        let envelope = |user: &str, kind| OriginalKeyEnvelope {
            user: user.into(),
            kind,
        };
        let listed = |named: Vec<OriginalKeyEnvelope>, total, refused| {
            Ok(DaExemptKey {
                refused,
                on_original_key: Some(OriginalKeyEnvelopes { named, total }),
                ..Default::default()
            })
        };
        let locked = Ok(TpmLockout::from_properties(
            0x204, 32, 32, 7200, 86400, false,
        ));
        let two = listed(
            vec![
                envelope("alice", EnvelopeKind::TemplateKey),
                envelope("bob", EnvelopeKind::KeyringSecret),
            ],
            2,
            None,
        );
        let (reading, detail) = tpm_lockout_check(&locked, &two);
        assert_eq!(reading, State::Warn);
        assert!(
            detail.contains(
                "alice's template key (face login); bob's keyring secret (credential release \
                 after a face or fingerprint login)"
            ),
            "{detail}"
        );
        assert!(
            detail.contains("DA-exempt storage key are not affected"),
            "{detail}"
        );
        assert!(!detail.contains("not every irlume envelope"), "{detail}");

        let hostile = listed(
            vec![envelope("eve\u{1b}[2J\nx", EnvelopeKind::Unknown)],
            40,
            None,
        );
        let (_, detail) = tpm_lockout_check(&locked, &hostile);
        assert!(!detail.chars().any(char::is_control), "{detail:?}");
        assert!(detail.contains("'s envelope; and 39 more"), "{detail}");
        let unnamed = listed(Vec::new(), 3, None);
        let (_, detail) = tpm_lockout_check(&locked, &unnamed);
        assert!(
            detail.contains("3 envelopes under names irlumed does not show"),
            "{detail}"
        );
        let many = listed(
            (0..20)
                .map(|n| envelope(&format!("user{n:02}"), EnvelopeKind::TemplateKey))
                .collect(),
            20,
            None,
        );
        let (_, detail) = tpm_lockout_check(&locked, &many);
        assert!(detail.contains("user11's template key"), "{detail}");
        assert!(!detail.contains("user12"), "{detail}");
        assert!(detail.contains("and 8 more"), "{detail}");
        for general in [listed(Vec::new(), 0, None), Ok(DaExemptKey::default())] {
            let (_, detail) = tpm_lockout_check(&locked, &general);
            assert!(detail.contains("not every irlume envelope"), "{detail}");
        }

        let calm = Ok(TpmLockout::from_properties(0x4, 0, 32, 7200, 86400, false));
        let refused = listed(
            vec![envelope("alice", EnvelopeKind::TemplateKey)],
            1,
            Some(KeyRefusal {
                reason: RefusalReason::NoSpace,
                detail: "the TPM's words".into(),
            }),
        );
        let (reading, detail) = tpm_lockout_check(&calm, &refused);
        assert_eq!(reading, State::Warn);
        assert!(
            detail.contains("next TPM lockout would block: alice's template key."),
            "{detail}"
        );
        assert!(!detail.contains("(face login)"), "{detail}");
    }

    #[test]
    fn pcr_bank_wording_fails_only_when_sealing_would_refuse() {
        use crate::doctor_report::State;
        use irlume_core::tpm::PcrBankReadiness;
        assert_eq!(
            pcr_bank_check(&Ok(PcrBankReadiness::Ready(vec![7]))).0,
            State::Pass
        );
        let (state, detail) = pcr_bank_check(&Ok(PcrBankReadiness::Missing(vec![7])));
        assert_eq!(state, State::Fail);
        assert!(detail.contains("sealing refuses"), "{detail}");
        assert_eq!(
            pcr_bank_check(&Ok(PcrBankReadiness::Unextended(vec![0, 7]))).0,
            State::Warn
        );
        assert_eq!(
            pcr_bank_check(&Err("no TPM device".into())).0,
            State::Unknown
        );
    }

    #[test]
    fn pcr7_binding_names_what_weakens_or_anchors_pcr_7() {
        use crate::doctor_report::State;
        use irlume_common::event_log::{
            Authority, Pcr7, Setting, EFI_IMAGE_SECURITY_DATABASE, SECURE_BOOT_CONFIGURATION,
            SHIM_LOCK,
        };
        let not_microsoft =
            b"\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77certificate";
        let shim = || Pcr7 {
            secure_boot: Some(true),
            configuration: SECURE_BOOT_CONFIGURATION
                .map(|(name, guid)| Setting {
                    guid,
                    name: name.to_owned(),
                    data: true,
                })
                .to_vec(),
            leading_configuration: 5,
            authorities: vec![
                Authority {
                    guid: EFI_IMAGE_SECURITY_DATABASE,
                    variable: "db".into(),
                    data: not_microsoft,
                },
                Authority {
                    guid: SHIM_LOCK,
                    variable: "SbatLevel".into(),
                    data: b"sbat,1",
                },
                Authority {
                    guid: SHIM_LOCK,
                    variable: "MokListRT".into(),
                    data: &[0x77; 40],
                },
            ],
            actions: vec![],
            separator_errors: 0,
            extraneous: 0,
            other: 0,
            other_kinds: vec![],
            unverified: 0,
            malformed: 0,
        };
        let (state, detail) = pcr7_binding_verdict(&shim());
        assert_eq!(state, State::Pass, "{detail}");
        for needle in [
            "a db entry that is not Microsoft's",
            "shim's SBAT revocation level",
            "shim's MokList",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
        assert!(!detail.contains("changes PCR 7"), "{detail}");

        for (action, needle) in [
            ("UEFI Debug Mode", "debug mode"),
            ("DMA Protection Disabled", "DMA protection is off"),
        ] {
            let mut weakened = shim();
            weakened.actions.push(action.into());
            let (state, detail) = pcr7_binding_verdict(&weakened);
            assert_eq!(state, State::Warn, "{action}");
            assert!(detail.contains(needle) && detail.contains("`irlume recovery setup`"));
        }
        // A separator the firmware recorded as a measurement error.
        let mut error = shim();
        error.separator_errors = 1;
        let (state, detail) = pcr7_binding_verdict(&error);
        assert_eq!(state, State::Warn);
        assert!(detail.contains("measurement error in PCR 7"), "{detail}");
        // An image or driver load in PCR 7 is extraneous there.
        let mut loaded = shim();
        loaded.extraneous = 2;
        let (state, detail) = pcr7_binding_verdict(&loaded);
        assert_eq!(state, State::Warn);
        assert!(
            detail.contains("2 image or driver load(s) into PCR 7"),
            "{detail}"
        );
        // An event of a type doctor does not read leaves PCR 7 unknown.
        let mut spdm = shim();
        spdm.other = 3;
        spdm.other_kinds = vec![0x8000_00e3, 0x8000_00e4];
        let (state, detail) = pcr7_binding_verdict(&spdm);
        assert_eq!(state, State::Unknown);
        assert!(
            detail.contains("3 event(s) of a type doctor does not read (0x800000e3, 0x800000e4)"),
            "{detail}"
        );
        let mut off = shim();
        off.secure_boot = Some(false);
        off.configuration[0].data = false;
        let (state, detail) = pcr7_binding_verdict(&off);
        assert_eq!(state, State::Warn);
        assert!(detail.contains("measured as off"), "{detail}");
        let mut unverified = shim();
        unverified.authorities.clear();
        let (state, detail) = pcr7_binding_verdict(&unverified);
        assert_eq!(state, State::Warn);
        assert!(detail.contains("binds no boot chain"), "{detail}");
        // shim's SBAT level is policy: it verified no image.
        let mut sbat_only = shim();
        sbat_only.authorities.retain(|a| a.variable == "SbatLevel");
        let (state, detail) = pcr7_binding_verdict(&sbat_only);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.contains("no authority that verified an image, only policy (`SbatLevel`)"),
            "{detail}"
        );
        // shim with its validation disabled measures MokSBState: the db entry
        // that verified shim does not cover what shim loads then.
        let mut disabled = shim();
        disabled.authorities.push(Authority {
            guid: SHIM_LOCK,
            variable: "MokSBState".into(),
            data: &[1],
        });
        let (state, detail) = pcr7_binding_verdict(&disabled);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.contains("validation is disabled")
                && detail.contains("`sudo mokutil --enable-validation`"),
            "{detail}"
        );
        // An image authority without its signature data verified nothing.
        let mut hollow = shim();
        hollow.authorities.retain(|a| a.variable == "db");
        hollow.authorities[0].data = &[0x77; 16];
        assert_eq!(pcr7_binding_verdict(&hollow).0, State::Warn);
        // Firmware decides how many authorities there are; at most eight are
        // named, the rest counted.
        let mut many = shim();
        let names: Vec<String> = (0..20).map(|i| format!("Vendor{i}")).collect();
        for name in &names {
            many.authorities.push(Authority {
                guid: SHIM_LOCK,
                variable: name.clone(),
                data: &[1],
            });
        }
        let (state, detail) = pcr7_binding_verdict(&many);
        assert_eq!(state, State::Pass, "{detail}");
        assert!(
            detail.contains("`Vendor4`")
                && !detail.contains("`Vendor5`")
                && detail.contains("; 15 more"),
            "{detail}"
        );
        // A db authority under another GUID is not the signature database.
        let mut stray = shim();
        stray.authorities.retain(|a| a.variable == "db");
        stray.authorities[0].guid = SHIM_LOCK;
        assert_eq!(pcr7_binding_verdict(&stray).0, State::Warn);

        // Microsoft's order: SecureBoot, PK, KEK, db, dbx under their GUIDs,
        // nothing in between, with PK and KEK holding data.
        let mut no_kek = shim();
        no_kek.configuration.remove(2);
        let (state, detail) = pcr7_binding_verdict(&no_kek);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.contains("as SecureBoot, PK, db, dbx, not SecureBoot, PK, KEK, db and dbx"),
            "{detail}"
        );
        let mut none = shim();
        none.configuration.clear();
        none.secure_boot = None;
        let (state, detail) = pcr7_binding_verdict(&none);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(detail.contains("as nothing,"), "{detail}");
        let mut swapped = shim();
        swapped.configuration.swap(3, 4);
        assert_eq!(pcr7_binding_verdict(&swapped).0, State::Warn);
        let mut vendor = shim();
        vendor.configuration[1].guid = SHIM_LOCK;
        let (state, detail) = pcr7_binding_verdict(&vendor);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.contains("PK (under another vendor GUID)"),
            "{detail}"
        );
        let mut interleaved = shim();
        interleaved.leading_configuration = 3;
        let (state, detail) = pcr7_binding_verdict(&interleaved);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.contains("other events into PCR 7 before or between"),
            "{detail}"
        );
        let mut extra = shim();
        extra.configuration.push(Setting {
            guid: EFI_IMAGE_SECURITY_DATABASE,
            name: "dbt".to_owned(),
            data: true,
        });
        extra.leading_configuration = 6;
        assert_eq!(
            pcr7_binding_verdict(&extra).0,
            State::Pass,
            "more variables after dbx"
        );
        let mut empty = shim();
        empty.configuration[1].data = false;
        empty.configuration[2].data = false;
        let (state, detail) = pcr7_binding_verdict(&empty);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.contains("measured PK and KEK into PCR 7 with no data"),
            "{detail}"
        );
        let mut blank = shim();
        blank.secure_boot = None;
        blank.configuration[0].data = false;
        let (state, detail) = pcr7_binding_verdict(&blank);
        assert_eq!(state, State::Warn, "{detail}");
        assert!(
            detail.contains("measured SecureBoot into PCR 7 with no data"),
            "{detail}"
        );

        // Firmware-written names reach the output as visible ASCII only.
        let mut odd = shim();
        odd.authorities[2].variable = "Mok\u{1b}[2J\nList\u{202e}".into();
        let (state, detail) = pcr7_binding_verdict(&odd);
        assert_eq!(state, State::Pass);
        assert!(
            detail.contains("an authority from `Mok?[2J?List?`"),
            "{detail}"
        );
        let mut forged = shim();
        forged.configuration[2].name = "K\u{7}EK".into();
        let (_, detail) = pcr7_binding_verdict(&forged);
        assert!(detail.contains("PK, K?EK, db"), "{detail}");
        assert_eq!(
            firmware_text(&"x".repeat(40)),
            format!("{}...", "x".repeat(32))
        );

        assert_eq!(
            signing_ca_successor("Microsoft Corporation UEFI CA 2011"),
            Some("Microsoft UEFI CA 2023")
        );
        assert_eq!(
            signing_ca_successor("Microsoft Windows Production PCA 2011"),
            Some("Windows UEFI CA 2023")
        );
        assert_eq!(signing_ca_successor("Microsoft UEFI CA 2023"), None);

        assert_eq!(pcr7_binding_check(&EventLogRead::Absent).0, State::Info);
        for read in [
            EventLogRead::NoSecurityfs,
            EventLogRead::NotRoot,
            EventLogRead::Unreadable("EIO".into()),
            EventLogRead::Bytes(vec![0; 64], Err("no pcr-sha256".into())),
        ] {
            assert_eq!(pcr7_binding_check(&read).0, State::Unknown);
        }
        let (state, detail) = pcr7_binding_check(&EventLogRead::Bytes(vec![0; 64], Ok([0; 32])));
        assert_eq!(state, State::Unknown);
        assert!(detail.contains("crypto-agile"), "{detail}");
    }

    #[test]
    fn shim_validation_wording_warns_only_when_shim_verifies_nothing() {
        use crate::doctor_report::State;
        use irlume_common::secureboot::ShimValidation;
        assert_eq!(
            shim_validation_check(ShimValidation::Enforcing).0,
            State::Pass
        );
        let (state, detail) = shim_validation_check(ShimValidation::Disabled);
        assert_eq!(state, State::Warn);
        for needle in [
            "PCR 7",
            "no boot chain",
            "`sudo mokutil --enable-validation`",
            "MokManager",
            "`irlume recovery setup`",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
        for info in [
            ShimValidation::SecureBootOff,
            ShimValidation::NotShim,
            ShimValidation::NotUefi,
        ] {
            assert_eq!(shim_validation_check(info).0, State::Info, "{info:?}");
        }
        assert_eq!(
            shim_validation_check(ShimValidation::Unreadable).0,
            State::Unknown
        );
    }

    #[test]
    fn certificate_rollover_wording_warns_before_pcr_7_moves() {
        use crate::doctor_report::State;
        use irlume_common::secureboot::CertificateRollover;
        assert_eq!(
            certificate_rollover_check(&CertificateRollover::Updated).0,
            State::Pass
        );
        let (state, detail) = certificate_rollover_check(&CertificateRollover::Pending(vec![
            ("KEK", "Microsoft Corporation KEK 2K CA 2023"),
            ("db", "Microsoft UEFI CA 2023"),
        ]));
        assert_eq!(state, State::Warn);
        for needle in [
            "Microsoft Corporation KEK 2K CA 2023 (KEK), Microsoft UEFI CA 2023 (db)",
            "PCR 7",
            "irlume recovery restore",
            "irlume recovery setup",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
        for info in [
            CertificateRollover::NotMicrosoft,
            CertificateRollover::NoKeys,
            CertificateRollover::NotUefi,
        ] {
            assert_eq!(certificate_rollover_check(&info).0, State::Info, "{info:?}");
        }
        assert_eq!(
            certificate_rollover_check(&CertificateRollover::Unreadable).0,
            State::Unknown
        );
    }

    #[test]
    fn doctor_check_flag_is_an_expact_match_not_a_prefix() {
        assert!(doctor_wants_check(&["--check".to_string()]));
        assert!(doctor_wants_check(&[
            "doctor".to_string(),
            "--check".to_string()
        ]));
        assert!(!doctor_wants_check(&[]));
        assert!(!doctor_wants_check(&["--checkout".to_string()]));
        assert!(!doctor_wants_check(&["--check=1".to_string()]));
    }

    /// Doctor's unwired-login and polkit lines name `irlume login enable`
    /// everywhere but NixOS, where that command refuses; there they name the
    /// module and docs/NIXOS.md instead.
    #[test]
    fn doctor_wiring_remedies_name_the_module_on_nixos() {
        let login = unwired_login_line("alice", false);
        assert!(
            login.contains("sudo irlume login enable --apply"),
            "{login}"
        );
        let login = unwired_login_line("alice", true);
        assert!(
            login.contains("alice is enrolled")
                && login.contains("services.irlume.pam.services")
                && login.contains("docs/NIXOS.md"),
            "{login}"
        );
        assert!(!login.contains("irlume login enable"), "{login}");
        for bitwarden_action in [false, true] {
            let polkit = polkit_unwired_line(bitwarden_action, false);
            assert!(
                polkit.contains("sudo irlume login enable --with-polkit --apply"),
                "{polkit}"
            );
            let polkit = polkit_unwired_line(bitwarden_action, true);
            assert!(
                polkit.contains("docs/NIXOS.md") && !polkit.contains("irlume login enable"),
                "{polkit}"
            );
            assert_eq!(polkit.contains("Bitwarden"), bitwarden_action, "{polkit}");
        }
    }

    use super::*;

    /// On a login screen irlume keeps face off (a LightDM serving remote
    /// login screens, #859), doctor's unwired-login line names that login
    /// manager and does not send the user to re-run `login enable`, which
    /// leaves that stack as it is.
    #[test]
    fn doctor_names_a_login_screen_face_is_kept_off() {
        let line = face_kept_off_login_line("alice", "lightdm");
        assert!(
            line.contains("alice is enrolled")
                && line.contains("lightdm's login screen has no face line")
                && line.contains("remote login screens"),
            "{line}"
        );
        assert!(!line.contains("sudo irlume login enable --apply"), "{line}");
        assert!(!line.contains('\u{2014}'), "{line}");
    }

    /// #1053: each selection word contract 1 knows is an `info` row naming
    /// it. A placement reported without a selection (a daemon that predates
    /// the report) is `unknown`, and so is a word this build does not know.
    #[test]
    fn doctor_recognizer_selection_row_names_the_governing_selection() {
        use crate::doctor_report::State;
        for word in ["auto", "cpu", "npu", "gpu"] {
            let (state, line) = recognizer_selection_row(Some(word));
            assert_eq!(state, State::Info, "{word}");
            assert!(line.starts_with(&format!("{word}; ")), "{line}");
        }
        assert_eq!(
            recognizer_selection_row(None),
            (
                State::Unknown,
                "the daemon did not report a device selection".to_owned()
            )
        );
        let (state, line) = recognizer_selection_row(Some("tpu"));
        assert_eq!(state, State::Unknown);
        assert!(line.contains("(tpu)"), "{line}");
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn set_cameras_preserves_legacy_request_and_carries_guard_without_fallback() {
        let plain = argv(&["set-cameras", "/dev/video40", "/dev/video42"]);
        assert!(
            matches!(set_cameras_request(&plain), Ok(irlume_common::Request::SetCameras { rgb, ir })
            if rgb == "/dev/video40" && ir == "/dev/video42")
        );
        let guard = serde_json::json!({
            "supervisor_id":"11111111111111111111111111111111",
            "candidate":{"instance_id":"22222222222222222222222222222222",
                "generation":7, "endpoint_paths":["/dev/video40","/dev/video42"]}
        })
        .to_string();
        let mut guarded = plain;
        guarded.extend(["--expected-camera".into(), guard]);
        let request = set_cameras_request(&guarded).unwrap();
        assert!(
            matches!(request, irlume_common::Request::SetCamerasIfCurrent { ref rgb, ref ir, ref expected }
            if rgb == "/dev/video40" && ir == "/dev/video42" && expected.candidate.generation == 7)
        );
        let encoded = serde_json::to_value(&request).unwrap();
        assert!(encoded.get("SetCamerasIfCurrent").is_some());
        assert!(encoded.get("SetCameras").is_none());
    }

    #[test]
    fn set_cameras_refuses_missing_malformed_or_unknown_guard_arguments() {
        for args in [
            argv(&["set-cameras"]),
            argv(&[
                "set-cameras",
                "/dev/video40",
                "/dev/video42",
                "--expected-camera",
            ]),
            argv(&[
                "set-cameras",
                "/dev/video40",
                "/dev/video42",
                "--expected-camera",
                "{}",
            ]),
            argv(&[
                "set-cameras",
                "/dev/video40",
                "/dev/video42",
                "--unknown",
                "{}",
            ]),
            argv(&["set-cameras", "/dev/video40", "/dev/video42", "unexpected"]),
        ] {
            assert!(set_cameras_request(&args).is_err());
        }
    }

    // ---- the shared flags-first subcommand scanner ----

    /// One scanner serves every `<command> [--user U] <subcommand>` command,
    /// so its whole behavior is pinned here once: the valued-flag step-over
    /// (both spellings), the fallback to None, and tolerance of unknown
    /// boolean flags.
    #[test]
    fn subcommand_after_valued_scans_past_flags_and_their_values() {
        let profiles = &["--user", "--profile", "--scans", "--name", "--scan"];
        let args = argv(&["profiles", "--user", "list", "add-scan"]);
        assert_eq!(subcommand_after_valued(&args, profiles), Some("add-scan"));
        // The `--flag=value` spelling carries its own value.
        let args = argv(&["profiles", "--user=tester", "list"]);
        assert_eq!(subcommand_after_valued(&args, profiles), Some("list"));
        // Subcommand first: unchanged.
        let args = argv(&["profiles", "list"]);
        assert_eq!(subcommand_after_valued(&args, profiles), Some("list"));
        // No subcommand at all: the last token was a valued flag's payload.
        let args = argv(&["profiles", "--user", "tester"]);
        assert_eq!(subcommand_after_valued(&args, profiles), None);
        // An unknown boolean flag does not swallow the subcommand.
        let args = argv(&["profiles", "--verbose", "list"]);
        assert_eq!(subcommand_after_valued(&args, profiles), Some("list"));
        // The per-user commands share only --user.
        let args = argv(&["keyring", "--user", "tester", "status"]);
        assert_eq!(subcommand_after_valued(&args, &["--user"]), Some("status"));
    }

    /// Drift tripwire: every valued flag the profiles family READS must be in
    /// the scanner's VALUED list, or a flags-first caller's value would be
    /// mistaken for the subcommand. Source-scanned the daemon-pin way: the
    /// `flag(args, "--x")` reads name exactly what a value can follow.
    #[test]
    fn the_scanner_knows_every_valued_flag_profiles_reads() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
        )
        .expect("read own source");
        let start = src.find("fn profiles(sub:").expect("profiles exists");
        let end = src[start..]
            .find("\nfn ")
            .map(|o| start + o)
            .expect("another fn follows profiles");
        let region = &src[start..end];
        let mut read: Vec<&str> = Vec::new();
        // Only the `flag(args, "--x")` call sites: a value can follow exactly
        // those, and unrelated string literals (usage prose, startswith
        // comparisons) must not pollute the list.
        let needle = "flag(args, \"";
        let mut at = 0;
        while let Some(hit) = region[at..].find(needle) {
            let hit_at = at + hit;
            // A word boundary before `flag`: `scans_flag(args, "profiles")`
            // passes a MESSAGE TAG, not a flag name, and must not match.
            let boundary = match region[..hit_at].chars().next_back() {
                Some(c) => !(c.is_ascii_alphanumeric() || c == '_'),
                None => true,
            };
            let from = hit_at + needle.len();
            let to = region[from..]
                .find('"')
                .map(|o| from + o)
                .expect("closed quote");
            if boundary {
                read.push(&region[from..to]);
            }
            at = to;
        }
        // --user reaches profiles through user_arg/flag ABOVE the region, so
        // it is asserted directly alongside everything the region reads.
        read.push("--user");
        read.sort_unstable();
        read.dedup();
        let valued = PROFILES_VALUED.to_vec();
        for flag in read {
            assert!(
                valued.contains(&flag),
                "{flag} is read as a valued flag by profiles but the scanner does not \
                 step over it; a flags-first caller's value would become the subcommand"
            );
        }
    }

    #[test]
    fn the_login_password_reader_hands_back_a_wiping_string() {
        // Heap hygiene is invisible at runtime: nothing a test can observe
        // distinguishes a wiped allocation from a freed one. The type is what
        // carries the wipe, so the type is what gets pinned. This stops
        // compiling if `read_password` returns to a plain `String`, which is
        // the state the TUI's `Pending::KeyringPw` was already out of.
        fn accepts_only_a_wiping_reader(_: fn(&str) -> Result<zeroize::Zeroizing<String>, String>) {
        }
        accepts_only_a_wiping_reader(read_password);
    }

    #[test]
    fn every_login_password_prompt_hands_back_a_wiping_string() {
        // Same pin, one level up (#348). `read_password` returning `Zeroizing`
        // bought nothing on the paths most users actually take, because the
        // setup wizard and `reseal` read through `prompt_login_password`, which
        // kept its own plain `String`. Pinning the reader alone did not stop
        // that, so the prompt that wraps it is pinned too.
        fn accepts_only_a_wiping_prompt(_: fn() -> Option<zeroize::Zeroizing<String>>) {}
        accepts_only_a_wiping_prompt(commands::prompt_login_password);
    }

    #[test]
    fn stream_minimum_checks_emit_both_ids_even_with_no_nodes() {
        // The machine API's completeness contract: a check never disappears
        // because it had nothing to say. A machine with no camera at all must
        // still carry both stream ids, as Info, or a consumer cannot tell an
        // older engine from a camera-less machine.
        let mut report = crate::doctor_report::Report::new(crate::doctor_report::Mode::Collect);
        stream_minimum_checks(
            &mut report,
            "/dev/irlume-test-no-such-rgb",
            "/dev/irlume-test-no-such-ir",
        );
        let checks = report.into_checks();
        for id in ["ir-stream-hello-minimum", "rgb-stream-hello-minimum"] {
            assert_eq!(
                checks.iter().filter(|c| c.id == id).count(),
                1,
                "{id} must appear exactly once"
            );
        }
    }

    #[test]
    fn selected_stream_minimum_checks_emit_both_ids_when_selection_finds_no_pair() {
        let mut report = crate::doctor_report::Report::new(crate::doctor_report::Mode::Collect);
        selected_stream_minimum_checks(&mut report, None);

        let checks = report.into_checks();
        for id in ["ir-stream-hello-minimum", "rgb-stream-hello-minimum"] {
            assert_eq!(
                checks.iter().filter(|check| check.id == id).count(),
                1,
                "{id} must remain present when no camera pair is selected"
            );
        }
    }

    #[test]
    fn devices_from_flags_honors_either_flag_alone() {
        let sel = || Some(("/dev/sel-rgb".to_string(), "/dev/sel-ir".to_string()));
        // No flags: no override, and the selection must not even run.
        assert_eq!(
            devices_from_flags(None, None, || unreachable!("no probe without flags")),
            None
        );
        // Both flags: taken verbatim, selection not consulted.
        assert_eq!(
            devices_from_flags(Some("/dev/r"), Some("/dev/i"), || unreachable!()),
            Some(("/dev/r".into(), "/dev/i".into()))
        );
        // --ir alone: the half the operator named is honored, the partner
        // comes from the selection. This is the case that was silently
        // dropped: the flag vanished and capture ran on the default node.
        assert_eq!(
            devices_from_flags(None, Some("/dev/video6"), sel),
            Some(("/dev/sel-rgb".into(), "/dev/video6".into()))
        );
        // --rgb alone, symmetric.
        assert_eq!(
            devices_from_flags(Some("/dev/video4"), None, sel),
            Some(("/dev/video4".into(), "/dev/sel-ir".into()))
        );
    }

    #[test]
    fn shell_single_quote_keeps_a_hostile_profile_name_in_one_argument() {
        // Profile names are user text, root can list another user's profiles,
        // and this crate prints commands for a person to copy. A name
        // carrying a quote would otherwise close the quoting and append its
        // own command to something an administrator runs (#291 review).
        let name = "Face'; touch /tmp/irlume-command-injection; #";
        let quoted = shell_single_quote(name);
        assert_eq!(
            quoted,
            "'Face'\"'\"'; touch /tmp/irlume-command-injection; #'"
        );
        // The escaped form is what a shell actually parses back as one
        // argument: confirmed by asking a shell, not by reading the string.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s' {quoted}"))
            .output()
            .expect("sh");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            name,
            "the shell must see exactly the original name, as one argument"
        );
        // Ordinary names are unchanged apart from the wrapping quotes.
        assert_eq!(shell_single_quote("Face Profile 1"), "'Face Profile 1'");
    }

    #[test]
    fn flag_returns_the_value_following_the_name() {
        let a = argv(&["--user", "alice", "--scans", "5"]);
        assert_eq!(flag(&a, "--user"), Some("alice"));
        assert_eq!(flag(&a, "--scans"), Some("5"));
        assert_eq!(flag(&a, "--name"), None);
    }

    #[test]
    fn flag_with_the_name_in_last_position_has_no_value() {
        let a = argv(&["enroll", "--reset"]);
        assert_eq!(flag(&a, "--reset"), None);
    }

    /// A value-taking flag given with no value is an omission, not an absence.
    ///
    /// `enroll --scans` fired a real camera capture at the DEFAULT count while
    /// the operator had asked for a number and lost it to the shell or a typo.
    /// The same shape reaches `camera-tune --rounds`, which runs the IR emitter.
    #[test]
    fn a_value_flag_with_no_value_is_a_usage_error_not_the_default() {
        let argv = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();

        // Absent: the caller's default applies.
        assert!(matches!(scans_flag(&argv(&["enroll"]), "enroll"), Ok(None)));
        // Given properly: that count.
        assert!(matches!(
            scans_flag(&argv(&["enroll", "--scans", "7"]), "enroll"),
            Ok(Some(7))
        ));
        assert!(matches!(
            scans_flag(&argv(&["enroll", "--scans=7"]), "enroll"),
            Ok(Some(7))
        ));
        // Dangling, in both spellings: refused, never the default.
        assert!(scans_flag(&argv(&["enroll", "--scans"]), "enroll").is_err());
        assert!(scans_flag(&argv(&["enroll", "--scans="]), "enroll").is_err());
        // Unparseable or zero stays a usage error, as before.
        assert!(scans_flag(&argv(&["enroll", "--scans", "abc"]), "enroll").is_err());
        assert!(scans_flag(&argv(&["enroll", "--scans", "0"]), "enroll").is_err());
    }

    /// `--name=value` is as standard a spelling as `--name value`, and it used to
    /// parse as ABSENT. That silence is what made it dangerous: `--user=alice`
    /// left the flag looking unset, so the fallback named the invoking user and a
    /// destructive per-user command acted on the wrong enrollment without a word.
    #[test]
    fn flag_reads_the_equals_spelling_and_only_for_an_exact_name() {
        let argv = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();

        assert_eq!(flag(&argv(&["--user=alice"]), "--user"), Some("alice"));
        assert_eq!(flag(&argv(&["--user", "alice"]), "--user"), Some("alice"));
        // A value that itself contains '=' survives intact.
        assert_eq!(flag(&argv(&["--user=a=b"]), "--user"), Some("a=b"));
        // Empty after the '=' is a value that is present and empty, which the
        // caller's guard turns into a usage error rather than a silent fallback.
        assert_eq!(flag(&argv(&["--user="]), "--user"), Some(""));
        // A longer flag that merely STARTS with the name must not satisfy it.
        assert_eq!(flag(&argv(&["--username=alice"]), "--user"), None);
        assert_eq!(flag(&argv(&["--users=alice"]), "--user"), None);
        // Whichever spelling comes first wins, as with the repeated-flag rule.
        assert_eq!(
            flag(&argv(&["--user=first", "--user", "second"]), "--user"),
            Some("first")
        );

        // `flag_present` answers the question the guards ask: given at all?
        assert!(flag_present(&argv(&["--user=alice"]), "--user"));
        assert!(flag_present(&argv(&["--user="]), "--user"));
        assert!(flag_present(&argv(&["--user"]), "--user"));
        assert!(!flag_present(&argv(&["--username=alice"]), "--user"));
        assert!(!flag_present(&argv(&["list"]), "--user"));
    }

    #[test]
    fn flag_takes_the_first_occurrence() {
        let a = argv(&["--user", "a", "--user", "b"]);
        assert_eq!(flag(&a, "--user"), Some("a"));
    }

    /// Every capture-mode case reports a fact, never a fault: a mode is a
    /// strategy, so the state is Info (or Unknown when a non-root run cannot read
    /// the root-only verdict), never Warn or Fail. Each line must name the mode
    /// or the reason it is not known, because a support report is where this is
    /// read, and it points an unmeasured pair at `camera-tune`, the command that
    /// measures it (#100).
    #[test]
    fn capture_mode_report_names_the_mode_and_never_warns() {
        use crate::doctor_report::State;
        use irlume_camera::CaptureMode;

        for (obs, want) in [
            (
                CaptureModeReport::Measured(CaptureMode::Sequential, None),
                "sequential",
            ),
            (
                CaptureModeReport::Measured(CaptureMode::Concurrent, None),
                "concurrent",
            ),
        ] {
            let (state, line) = capture_mode_report_line(&obs);
            assert!(
                matches!(state, State::Info),
                "a measured mode is a fact, not a fault"
            );
            assert!(line.contains(want), "the line names the mode ({want})");
            assert!(line.contains("measured"), "and that it was measured");
        }

        let (state, line) = capture_mode_report_line(&CaptureModeReport::Unmeasured);
        assert!(matches!(state, State::Info));
        assert!(
            line.contains("default"),
            "an unmeasured pair is on the default"
        );
        assert!(
            line.contains("camera-tune"),
            "and is pointed at the command that measures it"
        );

        let (state, line) = capture_mode_report_line(&CaptureModeReport::NoIrPair);
        assert!(matches!(state, State::Info));
        assert!(line.contains("RGB-only"), "{line}");
        assert!(line.contains("does not apply"), "{line}");
        assert!(!line.contains("camera-tune"), "{line}");

        let (state, line) =
            capture_mode_report_line(&CaptureModeReport::Inconclusive("dim_scene".into()));
        assert!(matches!(state, State::Info));
        assert!(line.contains("inconclusive"), "{line}");
        assert!(line.contains("dim_scene"), "{line}");

        // A daemon failure is unknown, never guessed from legacy config.
        let (state, line) =
            capture_mode_report_line(&CaptureModeReport::Unreadable("permission denied".into()));
        assert!(
            matches!(state, State::Unknown),
            "could-not-read must not be reported as an observation: {line}"
        );
        assert!(line.contains("safe sequential"), "{line}");

        // The env override decides alone, in both directions, ahead of anything
        // stored, and the status comes from the daemon environment.
        for (seq, want) in [(true, "sequential"), (false, "concurrent")] {
            let (state, line) = capture_mode_report_line(&CaptureModeReport::Overridden(seq));
            assert!(matches!(state, State::Info));
            assert!(line.starts_with(want), "{line}");
            assert!(line.contains("IRLUME_SEQUENTIAL_CAPTURE"), "{line}");
            assert!(
                line.contains("daemon environment"),
                "must report the daemon's active environment: {line}"
            );
        }

        // The sequential line quotes the range that was measured, not the
        // ASUS end of it. The ASUS keeps 102% under concurrent capture, so it
        // is measured concurrent and never reaches this line at all.
        let (_, seq_line) =
            capture_mode_report_line(&CaptureModeReport::Measured(CaptureMode::Sequential, None));
        assert!(
            !seq_line.contains("700ms"),
            "700ms is the figure for a camera that never gets this verdict: {seq_line}"
        );
        assert!(seq_line.contains("1.3s"), "{seq_line}");

        let (state, line) = capture_mode_report_line(&CaptureModeReport::RuntimeDegraded(
            "concurrent_capture_failure".into(),
        ));
        assert!(matches!(state, State::Info));
        assert!(line.contains("daemon generation"), "{line}");
        assert!(line.contains("both streams"), "{line}");
        assert!(line.contains("camera-tune"), "{line}");
    }

    #[test]
    fn daemon_capture_mode_states_map_without_collapsing_no_ir_or_inconclusive() {
        assert!(matches!(
            capture_mode_report_from_status(
                "sequential",
                "no-ir-pair",
                "no_ir_pair",
                Some("no IR".into()),
                None,
            ),
            CaptureModeReport::NoIrPair
        ));
        assert!(matches!(
            capture_mode_report_from_status(
                "sequential",
                "default",
                "inconclusive",
                Some("dim_scene".into()),
                None,
            ),
            CaptureModeReport::Inconclusive(reason) if reason == "dim_scene"
        ));
        assert!(matches!(
            capture_mode_report_from_status(
                "sequential",
                "default",
                "unqualified_no_authority",
                Some("no authority".into()),
                None,
            ),
            CaptureModeReport::Unmeasured
        ));
    }

    /// The on/off word is positional. Scanning argv for it meant a flag value
    /// could be mistaken for the setting, so `--user on` configured an account
    /// named `on` instead of reporting a usage error.
    #[test]
    fn a_toggle_reads_its_value_positionally_not_from_anywhere_in_argv() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            toggle_value(&argv(&["eyes-open", "on"]), "eyes-open"),
            Some(true)
        );
        assert_eq!(
            toggle_value(
                &argv(&["eyes-open", "off", "--user", "someone"]),
                "eyes-open"
            ),
            Some(false)
        );
        // The bug: a username that happens to be `on` or `off`.
        assert_eq!(
            toggle_value(&argv(&["eyes-open", "--user", "on"]), "eyes-open"),
            None,
            "a --user VALUE must never be read as the setting"
        );
        assert_eq!(
            toggle_value(&argv(&["eyes-open", "--user", "off"]), "eyes-open"),
            None
        );
        // Contradictory input stays a usage error rather than first-wins.
        assert_eq!(
            toggle_value(&argv(&["eyes-open", "on", "off"]), "eyes-open"),
            None
        );
        assert_eq!(
            toggle_value(&argv(&["eyes-open", "off", "on"]), "eyes-open"),
            None
        );
        // Missing value, and a value that is neither word.
        assert_eq!(toggle_value(&argv(&["eyes-open"]), "eyes-open"), None);
        assert_eq!(
            toggle_value(&argv(&["eyes-open", "yes"]), "eyes-open"),
            None
        );
    }

    #[test]
    fn user_arg_prefers_the_explicit_flag() {
        assert_eq!(user_arg(&argv(&["--user", "carol"])), "carol");
    }

    #[test]
    fn user_arg_falls_back_to_env_user_when_flag_is_empty_or_absent() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        if unsafe { libc::geteuid() } == 0 {
            return; // the SUDO_USER preference only applies to root; not this run
        }
        let old_user = std::env::var_os("USER");
        let old_sudo = std::env::var_os("SUDO_USER");
        std::env::set_var("USER", "envuser");
        // A non-root process must ignore SUDO_USER (the root-only preference).
        std::env::set_var("SUDO_USER", "someoneelse");
        assert_eq!(user_arg(&argv(&["--user", ""])), "envuser");
        assert_eq!(user_arg(&[]), "envuser");
        match old_user {
            Some(v) => std::env::set_var("USER", v),
            None => std::env::remove_var("USER"),
        }
        match old_sudo {
            Some(v) => std::env::set_var("SUDO_USER", v),
            None => std::env::remove_var("SUDO_USER"),
        }
    }

    #[test]
    fn json_f32_maps_non_finite_to_null() {
        assert_eq!(json_f32(1.5), serde_json::json!(1.5));
        assert_eq!(json_f32(0.0), serde_json::json!(0.0));
        assert_eq!(json_f32(f32::NAN), serde_json::Value::Null);
        assert_eq!(json_f32(f32::INFINITY), serde_json::Value::Null);
    }

    /// The three states must stay distinguishable in the trace. Two of them
    /// were one: `ir_glint` is `None` both when no IR face was found and when
    /// the peak railed, so a bare `map_or` reported "railed" on frames that
    /// sampled no eye at all.
    ///
    /// The emptiness assertions are the other half. The field carried the
    /// numeric spec `{:>3.0}`, and precision on a non-numeric argument is a
    /// maximum width, so every value printed blank. Anything this function
    /// returns has to survive being formatted as a string (#398 review).
    #[test]
    fn the_glint_trace_field_separates_absent_railed_and_measured() {
        assert_eq!(format_ir_glint(false, None), "n/a");
        assert_eq!(format_ir_glint(true, None), "railed");
        assert_eq!(format_ir_glint(true, Some(126.0)), "126.0");
        // A face detected but no glint recorded is NOT the same as no face.
        assert_ne!(format_ir_glint(false, None), format_ir_glint(true, None));
        for s in [
            format_ir_glint(false, None),
            format_ir_glint(true, None),
            format_ir_glint(true, Some(126.0)),
        ] {
            assert!(!s.is_empty(), "the trace field must not render empty");
            assert!(!format!("{s:>6}").trim().is_empty());
        }
    }

    #[test]
    fn darken_chip_scales_rounds_and_clamps() {
        assert_eq!(darken_chip(&[0, 100, 200, 255], 0.5), vec![0, 50, 100, 128]);
        assert_eq!(darken_chip(&[200], 2.0), vec![255], "must clamp at 255");
    }

    #[test]
    fn blur_chip_keeps_uniform_images_and_spreads_a_point() {
        let n = 112usize;
        let uniform = vec![7u8; n * n * 3];
        assert_eq!(blur_chip(&uniform), uniform);

        // A single bright pixel becomes the 3x3 box average around it.
        let mut chip = vec![0u8; n * n * 3];
        chip[(5 * n + 5) * 3] = 90;
        let out = blur_chip(&chip);
        assert_eq!(out[(5 * n + 5) * 3], 10, "interior: 90 / 9 neighbours");
        assert_eq!(out[(4 * n + 4) * 3], 10, "diagonal neighbour sees it too");

        // At the corner only 4 pixels are in the window.
        let mut chip = vec![0u8; n * n * 3];
        chip[0] = 80;
        assert_eq!(blur_chip(&chip)[0], 20, "corner: 80 / 4 neighbours");
    }

    #[test]
    fn collect_images_recurses_and_filters_extensions() {
        let dir = std::env::temp_dir().join(format!("irlume-collect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for f in [
            "a.jpg",
            "b.PNG",
            "c.txt",
            "noext",
            "sub/d.bmp",
            "sub/e.jpeg",
        ] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        let mut out = Vec::new();
        collect_images(&dir, &mut out);
        let mut names: Vec<String> = out
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["a.jpg", "b.PNG", "d.bmp", "e.jpeg"]);
        let _ = std::fs::remove_dir_all(&dir);

        // A missing directory yields nothing rather than an error.
        let mut out = Vec::new();
        collect_images(std::path::Path::new("/nonexistent/irlume-imgs"), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn drift_report_names_direction_gaps_and_missing_arms() {
        use irlume_camera::measurement as m;
        let round = |deltas: u32, span: u64, gap: u64, meets: bool| m::RateRound {
            deltas,
            timestamp_span_us: span,
            wall_clock_us: None,
            max_inter_frame_gap_us: Some(gap),
            continuity_errors: 0,
            meets_floor: meets,
        };
        let evidence = |rates: &[(u32, u64)]| {
            let rounds: Vec<m::RateRound> = rates
                .iter()
                .map(|&(d, s)| round(d, s, 72_000, true))
                .collect();
            m::RateEvidence::from_rounds(&rounds, 0).expect("valid")
        };
        let record =
            |method: &str, rates: Vec<(m::MeasuredRole, m::RateEvidence)>| m::MeasurementRecord {
                schema_version: m::MEASUREMENT_SCHEMA_VERSION,
                policy: m::AcceptancePolicy {
                    policy_version: 1,
                    min_completed_rounds: 2,
                    max_failed_rounds: 0,
                    max_inter_frame_gap_us: None,
                    require_all_rounds_meet_floor: true,
                },
                tool_revision: "test".into(),
                measured_at_unix: 1,
                method: method.into(),
                stages: Vec::new(),
                rates,
                arm_failed_rounds: 0,
                acceptance: m::Acceptance {
                    accepted: true,
                    failures: Vec::new(),
                },
            };
        let reference = vec![record(
            "sequential",
            vec![
                (
                    m::MeasuredRole::Rgb,
                    evidence(&[(11, 690_000), (11, 690_000)]),
                ),
                (
                    m::MeasuredRole::Ir,
                    evidence(&[(15, 504_000), (15, 504_000)]),
                ),
            ],
        )];
        let fresh = vec![record(
            "sequential",
            vec![
                (
                    m::MeasuredRole::Rgb,
                    evidence(&[(11, 800_000), (11, 800_000)]),
                ),
                (
                    m::MeasuredRole::Ir,
                    evidence(&[(15, 504_000), (15, 504_000)]),
                ),
            ],
        )];
        let lines = measurement_drift_report(&reference, &fresh);
        assert!(lines
            .iter()
            .any(|l| l.contains("Rgb") && l.contains("slower")));
        assert!(lines.iter().any(|l| l.contains("Ir") && l.contains("same")));
        // A reference arm missing from the fresh run is named, not silently
        // skipped.
        let fresh_empty: Vec<m::MeasurementRecord> = Vec::new();
        let lines = measurement_drift_report(&reference, &fresh_empty);
        assert!(lines
            .iter()
            .any(|l| l.contains("no fresh sequential arm ran")));
    }

    /// What the fake gnome-keyring does with one control connection.
    #[derive(Clone, Copy, Debug)]
    enum Control {
        /// Apply the CHANGE and answer it, as gnome-keyring does.
        Answer,
        /// Apply the CHANGE, then close without answering. gnome-keyring
        /// changes the keyring before it writes the answer
        /// (`control_process` in gkd-control-server.c), so an answer can be
        /// lost after the change happened.
        ApplyThenDrop,
        /// Close without reading or applying anything.
        DropUnread,
        /// Read the credentials byte, then close without applying or
        /// answering, as gnome-keyring does for a client whose uid is not
        /// its own (`control_input` in gkd-control-server.c).
        ForeignUid,
        /// Read the request and answer DENIED without applying it, as a
        /// daemon `pam_gnome_keyring` started with `--login` does until
        /// something initializes it (`gkd-control-server.c`, `gkd-login.c`).
        Uninitialized,
    }

    thread_local! {
        /// The uid `control_client_uid` reports on this thread, so a test can
        /// pose as a user other than the one the fake gnome-keyring runs as.
        pub(super) static POSE_AS_UID: std::cell::Cell<Option<libc::uid_t>> =
            const { std::cell::Cell::new(None) };
    }

    /// The outcome of one `finish_token_arm` against the two fakes.
    struct ArmRun {
        result: Result<(), String>,
        /// The accounts named by each `ForgetPassword` irlumed received.
        forgets: Vec<String>,
        /// The login keyring's credential afterwards.
        keyring: zeroize::Zeroizing<Vec<u8>>,
        /// Control connections on which the fake gnome-keyring received at
        /// least the credentials byte (a `DropUnread` one reads nothing, so
        /// it never counts).
        requests: usize,
    }

    /// `keyring forget` erases the token when the keyring opens with the
    /// password, whether it re-keys back or never took the token, and keeps
    /// it otherwise.
    #[test]
    fn forget_rekeys_back_or_finds_the_password_already_current() {
        let back = |keyring: &[u8], script: &[Control]| {
            let outcome = std::cell::Cell::new(None);
            let run = against(keyring, script, || {
                outcome.set(Some(rekey_back(ARM_TOKEN, ARM_PASSWORD)));
                Ok(())
            });
            (outcome.take().unwrap(), run)
        };
        // Keyed to the token: re-keyed back and verified.
        let (outcome, run) = back(ARM_TOKEN, &[Control::Answer, Control::Answer]);
        assert!(matches!(outcome, Ok(RekeyedBack::Rekeyed)), "{outcome:?}");
        assert_eq!(*run.keyring, ARM_PASSWORD);
        // The arm's re-key never landed: the change back is refused, but the
        // password opens the keyring.
        for first in [Control::Answer, Control::ApplyThenDrop] {
            let (outcome, run) = back(ARM_PASSWORD, &[first, Control::Answer]);
            assert!(
                matches!(outcome, Ok(RekeyedBack::AlreadyPassword)),
                "{first:?}: {outcome:?}"
            );
            assert_eq!(*run.keyring, ARM_PASSWORD);
        }
        // Keyed to something else: the token is kept.
        let (outcome, run) = back(b"another-secret", &[Control::Answer, Control::Answer]);
        assert!(outcome.is_err(), "{outcome:?}");
        assert_eq!(*run.keyring, b"another-secret");
        // No gnome-keyring: nothing can be checked, so the token is kept.
        let (outcome, _) = back(ARM_PASSWORD, &[]);
        assert!(outcome.is_err(), "{outcome:?}");
    }

    const ARM_PASSWORD: &[u8] = b"login-password";
    const ARM_TOKEN: &[u8] = b"fresh-random-token";

    /// Serve one control connection: parse the CHANGE, apply it to
    /// `secret` when the current secret matches, and answer or not. Returns
    /// whether the client sent anything.
    fn serve_control(
        mut stream: std::os::unix::net::UnixStream,
        fate: Control,
        secret: &std::sync::Mutex<zeroize::Zeroizing<Vec<u8>>>,
    ) -> bool {
        use std::io::{Read, Write};
        if matches!(fate, Control::DropUnread) {
            return false;
        }
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut credentials = [0u8; 1];
        if matches!(fate, Control::ForeignUid) {
            return matches!(stream.read(&mut credentials), Ok(1));
        }
        stream.read_exact(&mut credentials).unwrap();
        let mut total = [0u8; 4];
        stream.read_exact(&mut total).unwrap();
        let mut packet = zeroize::Zeroizing::new(vec![0u8; u32::from_be_bytes(total) as usize - 4]);
        stream.read_exact(&mut packet).unwrap();
        let word = |at: usize| u32::from_be_bytes(packet[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(word(0), 2, "the arm sends only CHANGE");
        let current_len = word(4);
        let current = zeroize::Zeroizing::new(packet[8..8 + current_len].to_vec());
        let new_len = word(8 + current_len);
        let new =
            zeroize::Zeroizing::new(packet[12 + current_len..12 + current_len + new_len].to_vec());
        let code: u32 = {
            let mut keyring = secret.lock().unwrap();
            if matches!(fate, Control::Uninitialized) {
                1 // DENIED, whatever the secret
            } else if *keyring == current {
                *keyring = new;
                0 // OK
            } else {
                1 // DENIED
            }
        };
        if matches!(fate, Control::Answer | Control::Uninitialized) {
            let mut reply = 8u32.to_be_bytes().to_vec();
            reply.extend_from_slice(&code.to_be_bytes());
            stream.write_all(&reply).unwrap();
        }
        true
    }

    /// Run `finish_token_arm` against a fake gnome-keyring whose login
    /// keyring is keyed to `keyring`, and a fake irlumed. Each control
    /// connection follows the next `script` entry; once the script runs out
    /// the control socket is gone, as when gnome-keyring exits. An empty
    /// script means no gnome-keyring in the session.
    fn arm_against(keyring: &[u8], script: &[Control], minted: bool) -> ArmRun {
        against(keyring, script, || {
            finish_token_arm_in("testuser", ARM_PASSWORD, ARM_TOKEN, minted, || None)
        })
    }

    /// Run `action` against a fake gnome-keyring whose login keyring is keyed
    /// to `keyring`, and a fake irlumed; see [`arm_against`].
    fn against(
        keyring: &[u8],
        script: &[Control],
        action: impl FnOnce() -> Result<(), String>,
    ) -> ArmRun {
        use std::io::{BufRead, Write};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        static RUN: AtomicUsize = AtomicUsize::new(0);
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "irlume-token-arm-{}-{}",
            std::process::id(),
            RUN.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("keyring")).unwrap();
        let stop = Arc::new(AtomicBool::new(false));

        let secret = Arc::new(Mutex::new(zeroize::Zeroizing::new(keyring.to_vec())));
        let keyring_thread = (!script.is_empty()).then(|| {
            let control = irlume_common::gkr_wire::control_socket_path(&dir);
            let listener = std::os::unix::net::UnixListener::bind(&control).unwrap();
            listener.set_nonblocking(true).unwrap();
            let (secret, stop, script) = (secret.clone(), stop.clone(), script.to_vec());
            std::thread::spawn(move || {
                let mut fates = script.into_iter();
                let mut requests = 0;
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let fate = fates.next().unwrap();
                            let last = fates.len() == 0;
                            if last {
                                // Gone before this connection closes, so the
                                // next connect already fails.
                                std::fs::remove_file(&control).unwrap();
                            }
                            requests += usize::from(serve_control(stream, fate, &secret));
                            if last {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(e) => panic!("fake gnome-keyring accept: {e}"),
                    }
                }
                requests
            })
        });

        // irlumed: records every ForgetPassword. Other requests, such as a
        // detached TUI worker from another test reading IRLUME_SOCKET, get an
        // error and are not counted.
        let forgets = Arc::new(Mutex::new(Vec::new()));
        let daemon_sock = dir.join("irlumed.sock");
        let listener = std::os::unix::net::UnixListener::bind(&daemon_sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let daemon_thread = {
            let (forgets, stop) = (forgets.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                                .unwrap();
                            let mut line = String::new();
                            if std::io::BufReader::new(&stream)
                                .read_line(&mut line)
                                .is_err()
                            {
                                continue;
                            }
                            let reply = match serde_json::from_str::<irlume_common::Request>(&line)
                            {
                                Ok(irlume_common::Request::ForgetPassword { user }) => {
                                    forgets.lock().unwrap().push(user);
                                    irlume_common::Response::PasswordForgotten
                                }
                                _ => irlume_common::Response::Error("not in this test".into()),
                            };
                            let _ = writeln!(stream, "{}", serde_json::to_string(&reply).unwrap());
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(e) => panic!("fake irlumed accept: {e}"),
                    }
                }
            })
        };

        let saved_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let saved_socket = std::env::var_os("IRLUME_SOCKET");
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("IRLUME_SOCKET", &daemon_sock);
        let result = action();
        stop.store(true, Ordering::SeqCst);
        let requests = keyring_thread.map_or(0, |t| t.join().unwrap());
        daemon_thread.join().unwrap();
        for (name, saved) in [
            ("XDG_RUNTIME_DIR", saved_runtime),
            ("IRLUME_SOCKET", saved_socket),
        ] {
            match saved {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        let forgets = forgets.lock().unwrap().clone();
        let keyring = secret.lock().unwrap().clone();
        ArmRun {
            result,
            forgets,
            keyring,
            requests,
        }
    }

    /// gnome-keyring re-keys the login keyring to the fresh token, the
    /// answer is lost and gnome-keyring then exits. The token is now the
    /// only secret that opens the keyring, so its envelope must stay.
    #[test]
    fn a_minted_token_is_kept_when_the_rekey_answer_is_lost() {
        let run = arm_against(ARM_PASSWORD, &[Control::ApplyThenDrop], true);
        assert_eq!(*run.keyring, ARM_TOKEN, "the re-key reached the keyring");
        let err = run.result.expect_err("an unconfirmed re-key is not an arm");
        assert!(
            run.forgets.is_empty(),
            "no ForgetPassword while the keyring may be keyed to the token: {err}"
        );
        assert!(err.contains("kept"), "{err}");
        assert!(!err.contains("rolled back"), "{err}");
        // A host whose irlumed refuses the re-arm still has a way out.
        assert!(err.contains("`irlume keyring forget`"), "{err}");
    }

    /// Every answer is lost while gnome-keyring keeps running: the re-key,
    /// the token check and the password check all go unanswered.
    #[test]
    fn a_minted_token_is_kept_when_every_keyring_answer_is_lost() {
        let run = arm_against(ARM_PASSWORD, &[Control::ApplyThenDrop; 3], true);
        assert_eq!(*run.keyring, ARM_TOKEN, "the re-key reached the keyring");
        let err = run.result.expect_err("an unconfirmed re-key is not an arm");
        assert!(run.forgets.is_empty(), "{err}");
        assert!(err.contains("kept"), "{err}");
    }

    /// gnome-keyring confirms the re-key and only the check after it is
    /// lost: the keyring is keyed to the token.
    #[test]
    fn a_minted_token_is_kept_when_only_the_check_answer_is_lost() {
        let run = arm_against(
            ARM_PASSWORD,
            &[Control::Answer, Control::ApplyThenDrop],
            true,
        );
        assert_eq!(*run.keyring, ARM_TOKEN);
        let err = run.result.expect_err("an unverified token is not an arm");
        assert!(run.forgets.is_empty(), "{err}");
        assert!(err.contains("kept"), "{err}");
    }

    /// Rollback still happens where the keyring provably never took the
    /// token, so a failed first arm does not leave a token envelope behind.
    #[test]
    fn a_minted_token_is_rolled_back_when_the_keyring_never_took_it() {
        for (case, keyring, script) in [
            ("no gnome-keyring in the session", ARM_PASSWORD, &[][..]),
            (
                "gnome-keyring refuses the password",
                b"another-password".as_slice(),
                &[Control::Answer; 3][..],
            ),
            (
                "the re-key is lost unread and the password still opens the keyring",
                ARM_PASSWORD,
                &[Control::DropUnread, Control::Answer, Control::Answer][..],
            ),
            (
                "gnome-keyring refuses the re-key and the check's answer is lost",
                b"another-password".as_slice(),
                &[Control::Answer, Control::ApplyThenDrop][..],
            ),
        ] {
            let run = arm_against(keyring, script, true);
            assert_eq!(*run.keyring, keyring, "{case}: the keyring is unchanged");
            let err = run.result.expect_err(case);
            assert_eq!(run.forgets, ["testuser"], "{case}: {err}");
            assert!(err.contains("rolled back"), "{case}: {err}");
        }
    }

    /// gnome-keyring serves only its own uid: from any other it reads the
    /// credentials byte and closes without applying or answering, as when
    /// root runs the arm with the user's `XDG_RUNTIME_DIR`. Nothing is sent
    /// to it, and the token it never took is rolled back.
    #[test]
    fn a_minted_token_is_rolled_back_when_gnome_keyring_runs_as_another_uid() {
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        let keyring_uid = unsafe { libc::geteuid() };
        POSE_AS_UID.with(|uid| uid.set(Some(keyring_uid.wrapping_add(1))));
        let run = arm_against(ARM_PASSWORD, &[Control::ForeignUid; 3], true);
        POSE_AS_UID.with(|uid| uid.set(None));
        assert_eq!(*run.keyring, ARM_PASSWORD, "the keyring is unchanged");
        let err = run.result.expect_err("another uid's keyring is not armed");
        assert_eq!(run.forgets, ["testuser"], "{err}");
        assert_eq!(run.requests, 0, "nothing is sent to it: {err}");
        assert!(err.contains("rolled back"), "{err}");
        assert!(err.contains(&format!("runs as uid {keyring_uid}")), "{err}");
    }

    /// A reused token may be the live credential: no failure deletes it.
    #[test]
    fn a_reused_token_is_never_rolled_back() {
        for script in [&[][..], &[Control::ApplyThenDrop; 3][..]] {
            let run = arm_against(ARM_PASSWORD, script, false);
            let err = run.result.expect_err("an unconfirmed re-key is not an arm");
            assert!(run.forgets.is_empty(), "{script:?}: {err}");
        }
    }

    #[test]
    fn a_confirmed_rekey_arms_the_token() {
        let run = arm_against(ARM_PASSWORD, &[Control::Answer; 2], true);
        assert_eq!(run.result, Ok(()));
        assert_eq!(*run.keyring, ARM_TOKEN);
        assert!(run.forgets.is_empty());
    }

    /// Run `rekey_back_initializing` against a fake gnome-keyring, with
    /// `initialize` standing in for the session bus. Returns the outcome,
    /// the run and how often `initialize` was asked.
    fn forget_against(
        keyring: &[u8],
        script: &[Control],
        initialize: gkr_session::Initialized,
    ) -> (Result<RekeyedBack, RekeyError>, ArmRun, usize) {
        let outcome = std::cell::Cell::new(None);
        let asked = std::cell::Cell::new(0);
        let initialize = std::cell::Cell::new(Some(initialize));
        let run = against(keyring, script, || {
            outcome.set(Some(rekey_back_initializing(
                ARM_TOKEN,
                ARM_PASSWORD,
                || {
                    asked.set(asked.get() + 1);
                    initialize.take().unwrap()
                },
            )));
            Ok(())
        });
        (outcome.take().unwrap(), run, asked.get())
    }

    /// Right after login on Fedora 43 or 44, gnome-keyring is a `--login`
    /// daemon nothing has initialized, which refuses every CHANGE. `forget`
    /// has the bus start it once and the change back then goes through,
    /// whether the keyring was keyed to the token or never took it.
    #[test]
    fn forget_initializes_a_login_started_gnome_keyring_once_and_retries() {
        use gkr_session::Initialized;
        let waiting = [
            Control::Uninitialized,
            Control::Uninitialized,
            Control::Answer,
            Control::Answer,
        ];
        let (outcome, run, asked) = forget_against(ARM_TOKEN, &waiting, Initialized::Now);
        assert!(matches!(outcome, Ok(RekeyedBack::Rekeyed)), "{outcome:?}");
        assert_eq!(*run.keyring, ARM_PASSWORD);
        assert_eq!((asked, run.requests), (1, 4));

        let (outcome, run, asked) = forget_against(ARM_PASSWORD, &waiting, Initialized::Now);
        assert!(
            matches!(outcome, Ok(RekeyedBack::AlreadyPassword)),
            "{outcome:?}"
        );
        assert_eq!(*run.keyring, ARM_PASSWORD);
        assert_eq!(asked, 1);

        // Initialized, and keyed to something else after all: one start
        // only, and the token is kept.
        let (outcome, run, asked) = forget_against(b"another-secret", &waiting, Initialized::Now);
        assert!(matches!(outcome, Err(RekeyError::Denied(_))), "{outcome:?}");
        assert_eq!(*run.keyring, b"another-secret");
        assert_eq!((asked, run.requests), (1, 4));
    }

    /// Without that daemon to initialize, or beside another Secret Service
    /// provider, `forget` sends nothing more and keeps the token; only a
    /// DENIED change back asks at all.
    #[test]
    fn forget_retries_only_after_an_initialization_and_only_on_denied() {
        use gkr_session::Initialized;
        let refused = [Control::Uninitialized, Control::Uninitialized];
        for (case, initialize, says) in [
            (
                "not a login-started daemon",
                Initialized::NotNeeded,
                "denied",
            ),
            (
                "another provider",
                Initialized::OtherProvider,
                "another Secret Service provider runs this session",
            ),
            (
                "the start did not help",
                Initialized::Failed("fixture failure".into()),
                "fixture failure",
            ),
        ] {
            let (outcome, run, asked) = forget_against(ARM_TOKEN, &refused, initialize);
            let Err(RekeyError::Denied(e)) = &outcome else {
                panic!("{case}: {outcome:?}");
            };
            assert!(e.contains(says), "{case}: {e}");
            // A daemon waiting for initialization refuses whatever the
            // secret, so only the plain refusal may blame the secret.
            assert_eq!(
                e.contains("wrong secret"),
                matches!(case, "not a login-started daemon"),
                "{case}: {e}"
            );
            assert_eq!(*run.keyring, ARM_TOKEN, "{case}: the token is kept");
            assert_eq!((asked, run.requests), (1, 2), "{case}");
        }
        // No gnome-keyring at all, and a change back that goes through: no
        // bus is asked.
        let (outcome, _, asked) = forget_against(ARM_TOKEN, &[], Initialized::Now);
        assert!(
            matches!(outcome, Err(RekeyError::Unchanged(_))),
            "{outcome:?}"
        );
        assert_eq!(asked, 0);
        let (outcome, _, asked) =
            forget_against(ARM_TOKEN, &[Control::Answer; 2], Initialized::Now);
        assert!(matches!(outcome, Ok(RekeyedBack::Rekeyed)), "{outcome:?}");
        assert_eq!(asked, 0);
    }

    /// A token arm from a session whose gnome-keyring the login screen
    /// started and nothing initialized sends gnome-keyring nothing. A fresh
    /// token is rolled back and an earlier one kept.
    #[test]
    fn a_token_arm_in_a_session_without_an_initialized_gnome_keyring_sends_nothing() {
        let refusal = || Some(gkr_session::NOT_A_GNOME_SESSION.to_string());
        let run = against(ARM_PASSWORD, &[Control::Answer; 2], || {
            finish_token_arm_in("testuser", ARM_PASSWORD, ARM_TOKEN, true, refusal)
        });
        let err = run.result.expect_err("not armed");
        assert!(err.contains("not a GNOME session"), "{err}");
        assert!(err.contains("rolled back"), "{err}");
        assert_eq!(run.forgets, ["testuser"], "{err}");
        assert_eq!(run.requests, 0, "nothing is sent: {err}");
        assert_eq!(*run.keyring, ARM_PASSWORD, "{err}");

        let run = against(ARM_PASSWORD, &[Control::Answer; 2], || {
            finish_token_arm_in("testuser", ARM_PASSWORD, ARM_TOKEN, false, refusal)
        });
        let err = run.result.expect_err("not armed");
        assert!(err.contains("left in place"), "{err}");
        assert!(run.forgets.is_empty(), "{err}");
        assert_eq!(run.requests, 0, "{err}");
    }
}
