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

mod bitwarden;
mod commands;
mod doctor_report;
mod fingerprint;
mod gesturecap;
mod logintx;
mod logs;
mod machine;
mod models;
mod pad;
mod pamwire;
mod recovery;
mod secrets;
mod strays;
mod suncal;
mod support_report;
mod trace;
mod tui;
mod uninstall;

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
    "gesturecap",
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
    // Rust ignores SIGPIPE by default, turning a closed stdout (`irlume … | head`,
    // `| less` then quit, `| grep -q`) into a "failed printing to stdout: Broken
    // pipe" panic + exit 101. Restore the Unix default so we exit quietly like any
    // other CLI when a downstream reader goes away.
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
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
        (Some("gesturecap"), _) => gesturecap::run(&args),
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
        (Some("credential-release-challenge"), sub) => {
            commands::credential_release_challenge(sub, &args)
        }
        (Some("ir-setup"), _) => ir_setup(&args),
        (Some("camera-tune"), _) => camera_tune(&args),
        (Some("camera-mode"), _) => camera_mode(&args),
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
    let reset = args.iter().any(|a| a == "--reset");
    if reset {
        eprintln!("[enroll] --reset: wiping '{user}'s existing enrollment first (clears any stale camera binding)");
    }
    eprintln!(
        "[enroll] '{user}': capturing a new face profile; stay in frame, look at the camera…"
    );
    // The daemon probes an unmeasured camera pair before the first scan
    // (#340), and that probe holds the line above for up to a minute with no
    // output; without this notice the wait reads as a hang.
    eprintln!(
        "[enroll] if this camera pair has no measured capture mode yet, irlume measures \
         it first (one time, up to a minute; the IR emitter fires)"
    );
    match daemon_request(&Request::Enroll {
        user: user.clone(),
        profile: name,
        scans,
        reset,
    }) {
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
            eprintln!("enroll failed: {e}");
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
const PROFILES_VALUED: [&str; 5] = ["--user", "--profile", "--scans", "--name", "--scan"];

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
        },
        Some("add-scan") => match flag(args, "--profile") {
            Some(p) => {
                let scans = match scans_flag(args, "profiles") {
                    Ok(s) => s,
                    Err(code) => return code,
                };
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
    match daemon_request(&req) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
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
                                 with `irlume profiles add-scan --profile {}`",
                                shell_single_quote(&p.name)
                            );
                        }
                    }
                    for s in &p.scans {
                        println!("      - {s}");
                    }
                }
            }
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
    use irlume_common::Request;
    let (Some(rgb), Some(ir)) = (args.get(1), args.get(2)) else {
        eprintln!(
            "usage: irlume set-cameras <rgb-node> <ir-node>   (root; e.g. /dev/video0 /dev/video2)"
        );
        return std::process::ExitCode::from(2);
    };
    report_ok_response(
        "set-cameras",
        daemon_request(&Request::SetCameras {
            rgb: rgb.clone(),
            ir: ir.clone(),
        }),
    )
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
fn camera_tune(args: &[String]) -> std::process::ExitCode {
    use irlume_common::Request;
    // Same rule as `enroll --scans`: this command fires the IR emitter for up to
    // a minute, so an unparseable count is a usage error rather than a silent
    // substitution of the default round count.
    let rounds = match flag(args, "--rounds") {
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
    eprintln!(
        "[camera-tune] measuring this camera under load; it fires the IR emitter \
         for up to a minute…"
    );
    report_ok_response(
        "camera-tune",
        daemon_request(&Request::TuneCaptureMode { rounds }),
    )
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
        (no sub) | list                         list profiles + scans\n  \
        add-scan --profile P [--scans N]         add scans to P (improve recognition, or\n  \
                                                add templates for a second model)\n  \
        rename --profile P [--scan S] --name N  rename a profile or a scan\n  \
        delete --profile P [--scan S]           delete a profile or a scan\n  \
        forget-model <model>                    remove one recognizer's scans from every\n  \
                                                profile (shipped | a catalog name | embed:<sha256>)\n  \
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

/// One CHANGE against the caller's own gnome-keyring control socket. The
/// control socket authenticates the peer's uid, so this only works for the
/// invoking user's own keyring, in their own session; arming another user's
/// token therefore fails here (and rolls back) rather than half-arming.
fn rekey_login_keyring(current: &[u8], new: &[u8]) -> Result<(), String> {
    use irlume_common::gkr_wire::{self, ControlResult, Op};
    let rt = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or("no XDG_RUNTIME_DIR; run this inside the user's own session")?;
    let sock = gkr_wire::control_socket_path(std::path::Path::new(&rt));
    let mut stream = std::os::unix::net::UnixStream::connect(&sock).map_err(|e| {
        format!(
            "connect {}: {e} (is gnome-keyring-daemon running in this session?)",
            sock.display()
        )
    })?;
    match gkr_wire::call(&mut stream, Op::Change, &[current, new])? {
        ControlResult::Ok => Ok(()),
        other => Err(format!("keyring re-key: {}", other.describe())),
    }
}

/// Prove `secret` is the login keyring's current credential: a CHANGE from it
/// to itself succeeds only then, changes nothing, and needs no prompt. This is
/// the post-re-key verification, so "armed" is never claimed on the strength
/// of a re-key reply alone.
fn verify_keyring_credential(secret: &[u8]) -> Result<(), String> {
    rekey_login_keyring(secret, secret)
}

/// Second half of a GNOME token arm, shared by `keyring arm`, the setup wizard
/// and the TUI: re-key the login keyring from `password` to `token` and verify
/// the token is now the live credential. On a RE-arm the keyring is usually
/// keyed to the token already, so a denied re-key followed by a passing
/// verification is success, not failure.
///
/// `minted` is the daemon's word on whether this token is fresh: only then is
/// the envelope inert and safe to roll back with `ForgetPassword` on failure.
/// A reused token may BE the live keyring credential, and deleting its
/// envelope on an error path would strand the keyring; that branch only
/// reports. Returns a human-readable error; success needs no message beyond
/// the caller's own.
pub(crate) fn finish_token_arm(
    user: &str,
    password: &[u8],
    token: &[u8],
    minted: bool,
) -> Result<(), String> {
    let keyed = match rekey_login_keyring(password, token) {
        Ok(()) => verify_keyring_credential(token),
        // The keyring may already be keyed to this exact token (idempotent
        // re-arm); verification decides. Keep the original error if not.
        Err(rekey_err) => verify_keyring_credential(token).map_err(|_| rekey_err),
    };
    match keyed {
        Ok(()) => Ok(()),
        Err(e) if minted => {
            let cleanup = match daemon_request(&irlume_common::Request::ForgetPassword {
                user: user.to_string(),
            }) {
                Ok(irlume_common::Response::PasswordForgotten) => {
                    "rolled back: the sealed token was erased; nothing changed".to_string()
                }
                other => format!(
                    "WARNING: could not erase the unused token envelope ({other:?}); run \
                     `irlume keyring forget` to clean up. The keyring itself is unchanged"
                ),
            };
            Err(format!(
                "keyring re-key failed: {e}. {cleanup}. Run the arm as '{user}' inside \
                 their own graphical session."
            ))
        }
        Err(e) => Err(format!(
            "keyring re-key failed: {e}. The envelope was left in place (it holds the \
             keyring's live token); retry as '{user}' inside their own graphical session."
        )),
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

/// `irlume keyring <arm|status|forget>`: manage the TPM-sealed login password
/// that lets a face login unlock the GNOME-keyring / KWallet. Talks to `irlumed`
/// over the socket (the daemon owns the TPM + the root-only sealed store).
pub(crate) fn keyring(sub: Option<&str>, args: &[String]) -> std::process::ExitCode {
    let user = user_arg(args);
    match sub {
        Some("arm") => {
            println!(
                "[keyring] Arming face-driven keyring unlock for '{user}'.\n\
                 Enter this user's LOGIN password. Depending on the wallet you run, what \
                 gets sealed is the password itself, the key your KDE wallet is already \
                 opened with, or a fresh random token this re-keys your GNOME keyring to. \
                 Nothing is stored in plaintext either way."
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
            let req = irlume_common::Request::SealPassword {
                kind: None, // let the daemon judge from what the user has
                user: user.clone(),
                password: irlume_common::SecretBytes::new(pw.as_bytes().to_vec()),
            };
            match daemon_request(&req) {
                Ok(irlume_common::Response::PasswordSealed) => {
                    println!("[keyring] \u{2705} armed. After a face login, your wallet will unlock automatically.");
                    println!("[keyring] NOTE: if you change your login password, re-run `irlume keyring arm`.");
                    std::process::ExitCode::SUCCESS
                }
                // GNOME token arm (#250): the daemon minted and sealed a token;
                // the login keyring must now be re-keyed to it, which only this
                // process can do (the control socket is in this session). Until
                // the re-key lands, the envelope is inert and the keyring still
                // opens with the password, so a failure here rolls the envelope
                // back and leaves everything exactly as before the command.
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
                    // No usable answer at all (daemon down, refused, older
                    // protocol). Not "armed with something unknown": fall
                    // through and let the erase attempt below report the real
                    // failure, rather than blaming an envelope nobody saw.
                    _ => (false, false),
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
                if let Err(e) = rekey_login_keyring(token.expose(), pw.as_bytes())
                    .and_then(|()| verify_keyring_credential(pw.as_bytes()))
                {
                    eprintln!(
                        "[keyring] could not re-key the keyring back ({e}); the sealed token \
                         is UNTOUCHED so nothing is lost. Fix the session (run as '{user}' \
                         with gnome-keyring running) and retry, or `--force` to delete the \
                         envelope anyway."
                    );
                    return std::process::ExitCode::FAILURE;
                }
                println!("[keyring] login keyring re-keyed back to your password.");
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
    // Shared client: bounded connect timeout + zeroized wire buffers. The 120s
    // read budget covers slow operations (guided enroll capture loops).
    irlume_common::client::request_with_timeout(req, std::time::Duration::from_secs(120)).map_err(
        |e| {
            // The connect-failure message already names irlumed and the exact
            // fix (client.rs); only append the hint where it adds information.
            let m = e.to_string();
            if m.contains("irlumed") {
                m
            } else {
                format!("{m} (is irlumed running?)")
            }
        },
    )
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
    // daemon's reset deletes the enrollment, the template key, and the recovery
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
        // needs the negotiated format's ceiling. The plain capture call uses
        // the same burst but intentionally discards those statistics (#358 review).
        let ir = irlume_camera::capture_ir_with_stats(ir_dev)?;
        let ir_stats = ir.stats();
        let (mn, mx, sum) = ir
            .pixels()
            .iter()
            .fold((255u8, 0u8, 0u64), |(mn, mx, s), &p| {
                (mn.min(p), mx.max(p), s + p as u64)
            });
        let mean = sum as f64 / ir.pixels().len() as f64;
        println!(
            "[IR ] {}x{}  brightness mean {:.1} min {} max {}",
            ir.width(),
            ir.height(),
            mean,
            mn,
            mx
        );
        let ir_rgb = irlume_camera::grey_to_rgb(ir.pixels());
        let ir_view = irlume_vision::align::RgbView {
            data: &ir_rgb,
            width: ir.width(),
            height: ir.height(),
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
            .map(|f| mean_in_bbox(ir.pixels(), ir.width(), ir.height(), &f.bbox))
            .unwrap_or(0.0);
        let ir_center_edge_ratio = ir_top_face
            .map(|f| center_edge_ratio(ir.pixels(), ir.width(), ir.height(), &f.bbox))
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
            ir.saturation_pixels(),
            ir.width(),
            ir.height(),
            ir_top_face.map(|f| &f.landmarks),
            ir_stats.white_level,
        );
        let rgb_top = rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));
        let pose = rgb_top.map(|f| irlume_vision::head_pose(&f.landmarks));
        let signals = irlume_liveness::Signals {
            rgb_face: rgb_top.map(|f| to_fbox(f, rgb.width, rgb.height)),
            ir_face: ir_top_face.map(|f| to_fbox(f, ir.width(), ir.height())),
            ir_face_brightness,
            ir_center_edge_ratio,
            ir_eye_glint,
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
            ir_ambient: 0.0, // dev gate probe: single frame, no burst stats
            face_frac: ir_top_face
                .map(|f| irlume_auth::bbox_width_frac(&f.bbox, ir.width()))
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
                ir.saturation_pixels(),
                ir.width(),
                ir.height(),
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
                data: rgbf.pixels(),
                width: rgbf.width(),
                height: rgbf.height(),
            };
            let rgb_top = det
                .detect(&rv)?
                .into_iter()
                .max_by(|a, b| a.score.total_cmp(&b.score));

            let irf = irlume_camera::capture_ir_with_stats(ir_dev)?;
            let ir_stats = irf.stats();
            let ir_rgb = irlume_camera::grey_to_rgb(irf.pixels());
            let iv = irlume_vision::align::RgbView {
                data: &ir_rgb,
                width: irf.width(),
                height: irf.height(),
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
                json_f32(sat_pct(rgbf.pixels(), rgbf.width(), rgbf.height(), 3)),
            );
            rec.insert(
                "ir_sat_pct".into(),
                json_f32(sat_pct(irf.pixels(), irf.width(), irf.height(), 1)),
            );
            // Capture resolution per modality: the driver may deliver a
            // different mode than requested, and detection/sharpness numbers
            // only compare across samples of the same resolution.
            rec.insert("rgb_res".into(), vec![rgbf.width(), rgbf.height()].into());
            rec.insert("ir_res".into(), vec![irf.width(), irf.height()].into());
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
                rgb_bri = mean_bbox(rgbf.pixels(), rgbf.width(), rgbf.height(), 3, &t.bbox);
                if !rgb_scans.is_empty() {
                    rgb_cos = best(&e, &rgb_scans);
                }
                rec.insert("rgb_face_score".into(), json_f32(t.score));
                rec.insert("rgb_cos".into(), json_f32(rgb_cos));
                rec.insert("rgb_brightness".into(), json_f32(rgb_bri));
                rec.insert(
                    "rgb_sharpness".into(),
                    json_f32(laplacian_var_bbox(
                        rgbf.pixels(),
                        rgbf.width(),
                        rgbf.height(),
                        3,
                        &t.bbox,
                    )),
                );
                rec.insert(
                    "rgb_contrast".into(),
                    json_f32(contrast_bbox(
                        rgbf.pixels(),
                        rgbf.width(),
                        rgbf.height(),
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
                ir_bri = mean_bbox(irf.pixels(), irf.width(), irf.height(), 1, &t.bbox);
                // Ambient-INDEPENDENT liveness cues (the center/edge-floor candidates):
                // center/edge IR ratio (3D face structure) and corneal glint peak.
                ir_center_edge_ratio = irlume_auth::center_edge_ratio(
                    irf.pixels(),
                    irf.width(),
                    irf.height(),
                    &t.bbox,
                );
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
                    irf.saturation_pixels(),
                    irf.width(),
                    irf.height(),
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
                        irf.pixels(),
                        irf.width(),
                        irf.height(),
                        1,
                        &t.bbox,
                    )),
                );
                rec.insert(
                    "ir_contrast".into(),
                    json_f32(contrast_bbox(
                        irf.pixels(),
                        irf.width(),
                        irf.height(),
                        1,
                        &t.bbox,
                    )),
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

/// Doctor's credential-release block: is the temporal gesture required before the
/// TPM-sealed keyring password is released, and can that gesture actually run here?
///
/// Kept separate from the polkit block because the failure MEANING differs. A
/// polkit prompt with the optional gesture enabled falls back to its password
/// dialog when that gesture cannot run; a credential release failure leaves the
/// keyring locked after an otherwise successful face login, which reads as "face
/// login is broken" unless doctor names it.
///
/// Silent when the user has no sealed password: nothing is released, so there is no
/// gate to explain.
fn report_credential_release(
    report: &mut crate::doctor_report::Report,
    user: &str,
    policy: irlume_common::config::HeadConsentPolicy,
) {
    use crate::doctor_report::State;
    // Recorded from the same visibility the block below prints from, so the
    // machine answer cannot disagree with the human one.
    report.check(
        "credential-release-challenge",
        match irlume_common::config::credential_release_gesture_required_visible() {
            // Off is the DEFAULT (the keyring releases with no nod); on is an
            // opt-in extra. Neither is a problem, so neither warns.
            Some(_) => State::Pass,
            None => State::Unknown,
        },
    );
    let armed = matches!(
        daemon_request(&irlume_common::Request::HasSealedPassword {
            user: user.to_string()
        }),
        Ok(irlume_common::Response::HasPassword(true))
    );
    if !armed {
        return;
    }
    // The EFFECTIVE rule: the per-service `service_gesture.credential_release`
    // override first, then the global gate, exactly as the daemon reads it.
    // Reading only the global key told a user with the per-service key set
    // that the gate was off, and asserted a gate the daemon does not apply
    // when the per-service key disables it over a global on.
    match irlume_common::config::credential_release_gesture_required_visible() {
        // The opt-in gate is on: fall through and check it can actually run.
        Some(true) => {}
        Some(false) => {
            dout!(
                report,
                "[doctor] credential-release challenge: off; the keyring releases \
                 after the face match with no nod. Enable the extra step with: sudo \
                 irlume credential-release-challenge credential_release on (the \
                 per-service key, which outranks the global gate in either state)"
            );
            return;
        }
        None => {
            dout!(
                report,
                "[doctor] credential-release challenge: root-only setting; re-run \
                 `sudo irlume doctor` to read it"
            );
            return;
        }
    }
    if matches!(
        policy,
        irlume_common::config::HeadConsentPolicy::LegacyClosure(_)
            | irlume_common::config::HeadConsentPolicy::Misconfigured(_)
    ) {
        dout!(
            report,
            "[doctor] credential-release challenge: required, but {}; the daemon \
             refuses the release and your keyring falls back to the typed password",
            policy.instruction("release your keyring password")
        );
        return;
    }
    // The gate is on. Running the head gesture needs the mesh model because every
    // consent frame goes through FaceMesh.
    let mesh = matches!(
        daemon_request(&irlume_common::Request::Health),
        Ok(irlume_common::Response::Health { mesh: true, .. })
    );
    if !mesh {
        dout!(
            report,
            "[doctor] ⚠ credential-release challenge is required but cannot run: FaceMesh \
             is not loaded\n     \
             (face_landmarks_detector.tflite). Face login still works; your keyring will fall back to \
             the typed\n     password. Fix: set IRLUME_MESH_MODEL in the irlumed unit, or \
             reinstall the package."
        );
        return;
    }
    dout!(
        report,
        "[doctor] credential-release challenge: required ✓ (keep nodding your head to \
         release your keyring password; shake your head to decline)"
    );
    // The gate is on AND working; the remaining failure is that the user may never
    // be TOLD. pam_irlume sends the instruction, but a login manager that drops
    // PAM_TEXT_INFO turns a required gesture into a silent one, which reads as
    // "face login worked but my keyring asked for a password anyway". Saying it
    // here moves the discovery from the login screen, where the greeter can show
    // nothing, to a command the user runs while set up and unhurried.
    if let Some(dm) = crate::pamwire::active_dm_hides_pam_instructions() {
        dout!(
            report,
            "[doctor] ⚠ your login manager ({dm}) does not display the head-gesture \
             instruction.\n     \
             It is still REQUIRED at the login screen after a reboot or logout: keep \
             nodding your head\n     \
             while your face is being read. Nothing on screen will ask you to. Without \
             it your\n     \
             login still succeeds and only the keyring falls back to the typed password."
        );
    }
}

fn polkit_doctor_message(
    gesture: Option<bool>,
    policy: irlume_common::config::HeadConsentPolicy,
) -> String {
    match gesture {
        Some(false) => "[doctor] polkit app prompts: wired ✓ (keyboard confirmation required; additional head gesture: off)".into(),
        Some(true)
            if matches!(
                policy,
                irlume_common::config::HeadConsentPolicy::LegacyClosure(_)
                    | irlume_common::config::HeadConsentPolicy::Misconfigured(_)
            ) => format!(
                "[doctor] polkit app prompts: wired ✓; keyboard confirmation remains required; additional gesture blocked: {}",
                policy.instruction("approve")
            ),
        Some(true) => "[doctor] polkit app prompts: wired ✓ (type yes, then KEEP NODDING to approve Bitwarden unlock, pkexec, …; shake your head to decline)".into(),
        None => "[doctor] polkit app prompts: wired ✓ (keyboard confirmation required; additional gesture state is root-only—re-run doctor with sudo)".into(),
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

fn doctor(args: &[String]) -> std::process::ExitCode {
    let mut report = crate::doctor_report::Report::new(crate::doctor_report::Mode::Human);
    doctor_run(&mut report, args)
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
    dout!(report, "[doctor] install origin: {}", origin.describe());
    report.check_detail("install-origin", State::Info, origin.describe());
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
            "systemd PCR-11 signature present ✓; kernel updates won't need re-seal"
        } else {
            "none (no Tier 1 on this boot chain)"
        }
    );
    report.check(
        "pcrlock",
        if irlume_core::tpm::pcrlock_provisioned().is_some() {
            State::Pass
        } else {
            State::Info
        },
    );
    dout!(
        report,
        "[doctor] pcrlock: {}",
        match irlume_core::tpm::pcrlock_provisioned() {
            Some(nv) => format!(
                "provisioned, NV 0x{nv:x}; an arm binds to it if it unseals on this boot (Tier 2)"
            ),
            None => "not provisioned: seals use the literal PCR-7 policy + recovery passphrase \
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
    report.check(
        "camera-nodes",
        if nodes.iter().any(|(_, r)| *r == irlume_camera::Role::Ir) {
            State::Pass
        } else if nodes.is_empty() {
            State::Fail
        } else {
            State::Warn
        },
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
                format!(
                    "{file} — not found; head gestures and detection-rescue alignment are disabled"
                ),
            ),
        };
        dout!(report, "  {}: {line}", s.stage);
        report.check_detail(id, state, line);
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
    match daemon_request(&irlume_common::Request::RecoveryStatus { user: user.clone() }) {
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
                } else {
                    "not set (run `irlume recovery setup`)"
                },
            );
            report.check(
                "templates",
                if encrypted { State::Pass } else { State::Warn },
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

    // --- polkit app prompts ------------------------------------------------
    // Apps like Bitwarden implement "biometric unlock" on Linux as a polkit
    // prompt; wiring pam_irlume into polkit-1 is what lets a face satisfy it.
    // Bitwarden's polkit action file doubles as the tell that the user expects
    // biometric unlock to work (its flatpak/snap can't install it themselves).
    // Counts both the filename Bitwarden's own setup writes AND the one snapd
    // installs for a snap; keying on only the former made doctor tell snap users
    // to run `bitwarden setup`, which then refuses (snapd owns that file).
    let bitwarden_action = bitwarden::action_present();
    // Same policy the engine gates on and the PAM module instructs from, so
    // doctor can never report a head gesture the daemon would refuse.
    let head_policy = irlume_common::config::head_consent_policy();
    //
    // Reported as a human line and not as a new check id on purpose. The
    // machine-API registry conformance test asserts BOTH directions (every id
    // emitted has a row, and every row is emitted), so a conditionally-emitted
    // id fails on every healthy machine. Giving it an always-emitted id is a
    // public contract addition and belongs in its own change, not in a review
    // fix.
    if matches!(
        head_policy,
        irlume_common::config::HeadConsentPolicy::LegacyClosure(_)
            | irlume_common::config::HeadConsentPolicy::Misconfigured(_)
    ) {
        dout!(
            report,
            "[doctor] head gesture: BLOCKED. {}. The daemon refuses gesture-gated \
             requests until the configuration is migrated; password fallback remains.",
            head_policy.instruction("approve")
        );
    }
    // --- credential release (the keyring password) --------------------------
    // Reported before the polkit block because it shares the gesture-readiness
    // facts above: this is the same head gate, applied to the one operation
    // where a spoof yields a REUSABLE secret instead of one session.
    report_credential_release(report, &user, head_policy);

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
            polkit_doctor_message(
                irlume_common::config::service_gesture_required_visible("polkit-1"),
                head_policy,
            )
        ),
        Some(false) if bitwarden_action => dout!(report,
            "[doctor] polkit app prompts: NOT wired, but Bitwarden's polkit action is installed.\n     \
             Its biometric unlock will fall back to the password prompt. Enable with:\n     \
             sudo irlume login enable --with-polkit --apply"
        ),
        Some(false) => dout!(report,
            "[doctor] polkit app prompts: not wired (opt-in: sudo irlume login enable \
             --with-polkit --apply)"
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

    // --- wiring drift ------------------------------------------------------
    // If the user is enrolled but no greeter is wired, a distro tool most
    // likely regenerated the PAM stacks (authselect apply on Fedora,
    // pam-auth-update on Debian) and dropped irlume's lines. Face still falls
    // back to the password, so this is not a lockout, but face login silently
    // stopped working. Surface it with the one-command fix.
    let (enrolled, ir_ratio_calibrated) =
        match daemon_request(&irlume_common::Request::ListProfiles {
            user: user.clone(),
            structured_errors: false,
        }) {
            Ok(irlume_common::Response::Enrollment {
                ref profiles,
                ir_ratio_calibrated,
                ..
            }) => (!profiles.is_empty(), ir_ratio_calibrated),
            _ => (false, false),
        };
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
    let login_ok = crate::pamwire::active_login_wired();
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
    if enrolled && !login_ok {
        dout!(
            report,
            "[doctor] ⚠ {user} is enrolled but no login manager is wired for face auth.\n     \
             A system update (authselect / pam-auth-update) may have regenerated the\n     \
             PAM stacks. The irlume-reconcile.path unit re-applies this automatically\n     \
             once login was enabled; if it persists, re-wire with:\n     \
             sudo irlume login enable --apply"
        );
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
    match crate::pamwire::active_dm_recognized() {
        Some((dm, true)) if crate::pamwire::active_dm_hides_pam_instructions().is_some() => report
            .check_detail(
                "display-manager",
                State::Pass,
                format!("{dm}; does not display PAM instructions to the user"),
            ),
        Some((_, true)) => report.check("display-manager", State::Pass),
        Some((_, false)) => report.check("display-manager", State::Warn),
        None => report.check("display-manager", State::Info),
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
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
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
    fn doctor_polkit_copy_keeps_keyboard_confirmation_primary() {
        use irlume_common::config::{HeadConsentPolicy, HeadConsentSource};

        let off = polkit_doctor_message(Some(false), HeadConsentPolicy::Ready);
        assert!(off.contains("keyboard confirmation required"), "{off}");
        assert!(off.contains("additional head gesture: off"), "{off}");
        assert!(!off.contains("face alone approves"), "{off}");

        let on = polkit_doctor_message(Some(true), HeadConsentPolicy::Ready);
        assert!(on.contains("type yes, then KEEP NODDING"), "{on}");
        assert!(on.contains("shake your head to decline"), "{on}");

        let blocked = polkit_doctor_message(
            Some(true),
            HeadConsentPolicy::LegacyClosure(HeadConsentSource::Settings),
        );
        assert!(blocked.contains("additional gesture blocked"), "{blocked}");
        assert!(
            blocked.contains("keyboard confirmation remains required"),
            "{blocked}"
        );

        let unknown = polkit_doctor_message(None, HeadConsentPolicy::Ready);
        assert!(
            unknown.contains("keyboard confirmation required"),
            "{unknown}"
        );
        assert!(
            unknown.contains("additional gesture state is root-only"),
            "{unknown}"
        );
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
}
