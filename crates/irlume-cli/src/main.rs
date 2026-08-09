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
//!   irlume calibrate-closure [--rounds N]        teach the eye-closure consent gesture
//!   irlume calibrate-closure --measure-only      labelled EAR readings, nothing stored
//!   irlume fingerprint <status|add|verify|reset|enable|disable> fprintd companion (face OR fingerprint)
//!   irlume login <status|enable|disable|reconcile> wire face auth into PAM (+--with-polkit for apps)
//!   irlume logs [-f] [debug on|off]              face-auth journal view + tracing switch

mod bitwarden;
mod blinkcap;
mod commands;
mod doctor_report;
mod fingerprint;
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
mod tui;
mod uninstall;

pub(crate) fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
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
    "blinkcap",
    "normprobe",
    "liveness",
    "meshprobe",
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
        (Some("blinkcap"), _) => blinkcap::run(&args),
        (Some("padcapture"), _) => pad::padcapture(&args),
        (Some("padreport"), _) => pad::padreport(&args),
        (Some("suncal"), _) => suncal::run(&args),
        (Some("liveness"), _) => liveness_probe(&args),
        (Some("meshprobe"), _) => meshprobe(&args),
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
        (Some("profiles"), sub) => profiles(sub, &args),
        (Some("verify"), _) => verify(&args),
        (Some("enrolldev"), _) => enrolldev(&args),
        (Some("keyring"), sub) => keyring(sub, &args),
        (Some("recovery"), sub) => recovery::run(sub, &args),
        (Some("bitwarden"), sub) => bitwarden::run(sub, &args),
        (Some("fingerprint"), sub) => fingerprint::run(sub, &args),
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
        // Presence-matched like `profiles list --json`: a contract flag before
        // the subcommand must not displace it into the human handler.
        (Some("models"), _)
            if args.iter().any(|a| a == "list") && args.iter().any(|a| a == "--json") =>
        {
            machine::models_list(&args)
        }
        // Refuse rather than ignore: `models --json` reached the human renderer
        // and printed prose, so a script that asked for JSON silently got
        // something it could not parse. The capability is `models list --json`.
        (Some("models"), _) if args.iter().any(|a| a == "--json") => {
            eprintln!(
                "[models] --json is available on `models list`; try: irlume models list --json"
            );
            std::process::ExitCode::from(2)
        }
        (Some("models"), sub) => models::run(sub, &args),
        (Some("biopolicy"), sub) => commands::biopolicy(sub, &args),
        (Some("credential-release-challenge"), sub) => {
            commands::credential_release_challenge(sub, &args)
        }
        (Some("calibrate-closure"), _) => calibrate_closure(&args),
        (Some("ir-setup"), _) => ir_setup(&args),
        (Some("camera-tune"), _) => camera_tune(&args),
        (Some("set-cameras"), _) => set_cameras(&args),
        (Some("update"), _) => commands::update(&args),
        (Some("uninstall"), _) => uninstall::run(&args),
        (Some("doctor"), _) if args.iter().any(|arg| arg == "--json") => machine::doctor(&args),
        (Some("status"), _) if args.iter().any(|arg| arg == "--json") => machine::status(&args),
        (Some("version"), _) if args.iter().any(|arg| arg == "--json") => machine::version(&args),
        (Some("version"), _) | (Some("--version"), _) | (Some("-V"), _) => {
            println!("irlume {}", env!("CARGO_PKG_VERSION"));
            std::process::ExitCode::SUCCESS
        }
        (Some("doctor"), _) => doctor(&args),
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
                offer_blink_challenge(&user);
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

/// After a fresh enrollment on IR hardware, make the opt-in anti-spoof blink
/// challenge an informed choice rather than a hidden flag. It stays OFF by
/// default (every mainstream face authenticator, Windows Hello / Face ID /
/// Android, ships passive PAD, not an active challenge; the default IR gate is
/// the passive analogue). This offers the extra print/replay defense to those
/// who want it, being honest about the latency and glasses cost.
fn offer_blink_challenge(user: &str) {
    use std::io::{BufRead, IsTerminal, Write};
    // Only meaningful on IR-capable (Secure-tier) hardware.
    if !crate::caps().ir_pair {
        return;
    }
    let tip =
        "Tip: the opt-in anti-spoof blink challenge blocks printed/screen-replay spoofs.\n      \
               Enable it any time with: irlume profiles challenge on";
    if !std::io::stdin().is_terminal() {
        println!("{tip}");
        return;
    }
    print!(
        "\nEnable the anti-spoof blink challenge now? It blocks printed-photo and\n\
         screen-replay spoofs, but adds a few seconds per login and can be finicky\n\
         with glasses. The default IR gate already blocks screens and matte prints.\n\
         Enable blink challenge? [y/N] "
    );
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        println!("{tip}");
        return;
    }
    if matches!(line.trim(), "y" | "Y" | "yes" | "Yes") {
        match daemon_request(&irlume_common::Request::SetRequireChallenge {
            user: user.to_string(),
            on: true,
        }) {
            Ok(irlume_common::Response::Enrollment { .. }) | Ok(irlume_common::Response::Ok(_)) => {
                println!("[enroll] anti-spoof blink challenge enabled. Disable with `irlume profiles challenge off`.")
            }
            _ => println!("[enroll] could not enable the challenge now; run `irlume profiles challenge on` later."),
        }
    } else {
        println!("[enroll] keeping the default (fast) IR gate. {tip}");
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
    if args.iter().any(|a| a == "--user")
        && !matches!(flag(args, "--user"), Some(u) if !u.is_empty() && !u.starts_with("--"))
    {
        eprintln!("[profiles] --user requires a username");
        return std::process::ExitCode::from(2);
    }
    let user = user_arg(args);
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
            // Positional: `irlume profiles forget-model <model>` (args[0] is
            // "profiles", args[1] the subcommand). A flag must not be read as
            // the model name when the positional is missing.
            match args
                .get(2)
                .map(String::as_str)
                .filter(|a| !a.starts_with("--"))
            {
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
            Some(on) => Request::SetRequireEyesOpen { user, on },
            None => return std::process::ExitCode::from(2),
        },
        Some("challenge") => match toggle_value(args, "challenge") {
            Some(on) => Request::SetRequireChallenge { user, on },
            None => return std::process::ExitCode::from(2),
        },
        _ => return usage_profiles(),
    };
    match daemon_request(&req) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            require_challenge,
            ..
        }) => {
            if profiles.is_empty() {
                println!("[profiles] none enrolled");
            } else {
                println!(
                    "[profiles] require-eyes-open: {}  ·  require-challenge (blink): {}",
                    if require_eyes_open { "ON" } else { "off" },
                    if require_challenge { "ON" } else { "off" }
                );
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

/// Ask before discarding an existing calibration. Defaults to NO, including on
/// a read error: the safe answer is the one that keeps working settings.
fn confirm_replace() -> bool {
    use std::io::Write;
    print!("    replace it? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let s = line.trim();
    s.eq_ignore_ascii_case("y") || s.eq_ignore_ascii_case("yes")
}

/// Ask whether to keep the reading just shown; Enter means yes. Defaults to
/// keeping on any read error, so a closed stdin cannot spin the capture loop.
fn keep_reading() -> bool {
    use std::io::Write;
    print!("    keep this reading? [Y/n] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return true;
    }
    match line.trim() {
        "" => true,
        s => s.eq_ignore_ascii_case("y") || s.eq_ignore_ascii_case("yes"),
    }
}

/// How many of the captured readings the resulting calibration would actually
/// accept, as `(closures, reopens)`.
///
/// The gate is applied exactly as [`irlume_liveness::detect_deliberate_closure`]
/// applies it, so the count cannot flatter a calibration the engine would then
/// refuse: a closure must read strictly UNDER `closed_threshold`, and a reopen
/// at or OVER `reopen_threshold`.
fn rounds_that_would_register(
    opens: &[f32],
    closeds: &[f32],
    cal: &irlume_liveness::ClosureCalibration,
) -> (usize, usize) {
    let (closed_thr, reopen_thr) = (cal.closed_threshold(), cal.reopen_threshold());
    (
        closeds.iter().filter(|c| **c < closed_thr).count(),
        opens.iter().filter(|o| **o >= reopen_thr).count(),
    )
}

/// The `--pose` label for measure-only runs, refusing a swallowed value:
/// `flag()` blindly returns the next argument, so `--pose --rounds 5` would
/// label research data '--rounds' and a trailing `--pose` would silently read
/// as unlabeled; both mislabel the measurement they exist to identify (#267
/// review). `Err` means the flag was given without a usable label.
fn measure_pose_label(args: &[String]) -> Result<&str, ()> {
    match args.iter().position(|a| a == "--pose") {
        None => Ok("unlabeled"),
        Some(i) => match args.get(i + 1).map(String::as_str) {
            Some(v) if !v.starts_with('-') => Ok(v),
            _ => Err(()),
        },
    }
}

/// Median of a non-empty slice. Takes `&mut` because selecting the middle
/// element needs an ordering, and EAR readings are floats (`total_cmp`, so a
/// stray NaN sorts to one end rather than corrupting the comparison).
fn median_ear(values: &mut [f32]) -> f32 {
    values.sort_by(|a, b| a.total_cmp(b));
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// How many rounds `calibrate-closure` captures unless `--rounds N` says
/// otherwise. One reading of each phase is a coin toss: measured on real
/// hardware, one user, one seated position, five consecutive closed captures
/// spanned 0.0424 to 0.0894. Calibrating from whichever single value happened to
/// land leaves a threshold that may sit almost on top of the user's own
/// closures. Three rounds and a median cost about a minute and remove that.
const CALIBRATION_ROUNDS_DEFAULT: usize = 3;

/// The guidance shown before `calibrate-closure` captures. It names the two
/// conditions the stored eye shape is tied to: the light in the room, and
/// whether the user is wearing glasses.
///
/// Glasses get their own line because the measurement makes them the sharper
/// trap (#173, 2026-08-04, ASUS FHD IR module). A lens lifts the CLOSED-eye EAR
/// about sixfold (median 0.018 bare-eyed to 0.113 with glasses) while the open
/// extreme barely moves, so the shift eats the bottom of the range rather than
/// offsetting it. A calibration taken bare-eyed then places its closed threshold
/// (0.088 there) below every glasses-on closure (0.107-0.130), and the consent
/// gesture silently never fires: 0 of 5 genuine closures registered. The
/// glasses-on calibration classified both states, so a user who sometimes wears
/// glasses should calibrate with them on. This is the interim guidance the
/// measurement called for; holding more than one calibration per user is the
/// full fix and is still open.
///
/// # The direction this loosens, taken deliberately
///
/// This advice is a tradeoff, not a free win, and the cost lands on the user
/// who calibrates with glasses and then authenticates without them.
/// `closed_threshold` is `ear_closed + CLOSURE_DEEP_FRACTION * gap`, so the
/// glasses-on pair (0.271 / 0.113) puts it at 0.160, while the bare-eyed pair
/// (0.253 / 0.018) puts it at 0.088. Measured against the BARE-EYED range,
/// 0.160 sits at openness fraction 0.61: about twice the 0.30 that
/// [`irlume_liveness::CLOSURE_DEEP_FRACTION`] was validated at, whose own doc
/// says the point of that number is to separate a held closure from a squint.
///
/// The same #173 session recorded an intermediate state that lands in the gap.
/// The operator's excluded run, watching the terminal instead of the camera,
/// read 0.07 to 0.16 "because looking down closes the measured eye shape".
/// Every value in that band is under the glasses-on 0.160; only 0.07 to 0.088
/// is under the bare-eyed 0.088. So a glance down at the keyboard held for the
/// 11 to 25 face frames `detect_deliberate_closure` wants, followed by looking
/// back up (bare-eyed open 0.246-0.254 clears the 0.208 reopen bar), can form a
/// qualifying run under the glasses-on calibration and mostly cannot under the
/// bare-eyed one. That path has no motion, glint, brightness or head-pose test.
///
/// It is still the right default, because the alternative is measured at 0 of 5
/// genuine closures registering, which stops the gesture firing at all for a
/// glasses wearer; that failure is fail-closed to the password, this one
/// loosens a consent gate. The issue's own analysis compared only the two
/// extremes and did not look at intermediate states, which is why this is
/// written down here rather than left implied.
fn closure_calibration_intro(rounds: usize) -> String {
    format!(
        "[calibrate] this teaches irlume your open/closed eye shape for the polkit\n            \
         'close your eyes to approve' gesture. {rounds} round(s), two phases each.\n            \
         Sit the way you actually sit, in the light you actually use: what is stored\n            \
         describes this position and this lighting.\n            \
         If you sometimes wear glasses, wear them for this. A lens lifts your\n            \
         closed-eye reading toward your open one, so a calibration taken without\n            \
         glasses can stop registering a real closure once you put them on;\n            \
         calibrating with them on covers both.\n"
    )
}

/// The note shown after a calibration is stored, at the one moment the user
/// still has the camera up and can redo it. Names the same two conditions the
/// stored eye shape depends on as [`closure_calibration_intro`]: the room light
/// and glasses. The head nod reassurance stays, so a user this gate keeps
/// missing knows the other gesture needs none of this.
fn closure_calibration_stored_note() -> &'static str {
    "[calibrate] this reading is tied to the conditions you are in now. Eye shape is\n            \
     stored as absolute values and they shift as the room changes, so a calibration\n            \
     taken in daylight can stop registering after dark: re-run this in the light you\n            \
     actually use. For the same reason, if you wear glasses sometimes, calibrate with\n            \
     them on. The head nod needs no calibration and is not affected."
}

/// `irlume calibrate-closure [--rounds N]`: teach irlume the user's open and
/// closed eye shape (EAR) for the deliberate-closure consent gesture used by
/// polkit prompts ("close your eyes for a second to approve").
///
/// Captures both phases [`CALIBRATION_ROUNDS_DEFAULT`] times and stores the
/// median of each, then checks the thresholds that result back against every
/// individual reading and says how many would have registered. A calibration
/// that would reject the user's own captures is the failure this reports, and
/// it is invisible from a single pair of numbers.
///
/// Each phase waits for Enter on a terminal, because a capture fired on a
/// countdown while the user is still settling produces a reading that has to be
/// thrown away. With no terminal (a script, a test) the waits and the keep/retry
/// prompt are skipped and every reading is kept, so it stays automatable.
///
/// REPLACING an existing calibration asks first, and with no terminal refuses
/// unless `--force`. Without that, running this command with stdin closed
/// silently overwrites a good calibration with whatever the camera happened to
/// see, and the previous values are gone: they live only inside the encrypted
/// enrollment, so there is nothing to roll back to. That is not hypothetical; it
/// is how this guard came to exist.
///
/// Needs root (fires the camera through the daemon's privileged path); the
/// daemon must be running.
fn calibrate_closure(args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    use std::io::{IsTerminal, Write};
    let user = user_arg(args);
    if !is_root() {
        eprintln!("[calibrate] needs root (fires the camera): sudo irlume calibrate-closure");
        return std::process::ExitCode::FAILURE;
    }
    let rounds = match flag(args, "--rounds") {
        None => CALIBRATION_ROUNDS_DEFAULT,
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=10).contains(&n) => n,
            _ => {
                eprintln!("[calibrate] --rounds takes a number from 1 to 10 (got {v:?})");
                // Usage error, not a runtime failure; the refusal itself was
                // already right, only the code disagreed with every sibling.
                return std::process::ExitCode::from(2);
            }
        },
    };
    // --measure-only: capture and print EAR medians without storing anything.
    // The #173 measurement mode: the stored calibration stays untouched, so a
    // second state (glasses on, different seat, different light) can be
    // measured side by side against the one the user actually authenticates
    // with. `--pose` names what the operator is holding; it is recorded in the
    // output only, since the daemon cannot know what the face is doing.
    if args.iter().any(|a| a == "--measure-only") {
        let Ok(pose) = measure_pose_label(args) else {
            eprintln!("[calibrate] --pose requires a label (e.g. --pose glasses-on-open)");
            return std::process::ExitCode::from(2);
        };
        println!(
            "[calibrate] measure-only: {rounds} capture(s), pose '{pose}', nothing stored.\n\
             [calibrate] hold the pose now; each capture starts after a 3s pause."
        );
        let mut vals: Vec<f32> = Vec::new();
        for i in 1..=rounds {
            std::thread::sleep(std::time::Duration::from_secs(3));
            match daemon_request(&Request::CaptureEarMedian { user: user.clone() }) {
                Ok(Response::EarMedian(Some(v))) => {
                    println!("    round {i}: EAR = {v:.4}");
                    vals.push(v);
                }
                Ok(Response::EarMedian(None)) => {
                    println!("    round {i}: no eye detected (face the camera)");
                }
                Ok(Response::Error(e)) => println!("    round {i}: {e}"),
                Ok(other) => println!("    round {i}: unexpected response: {other:?}"),
                Err(e) => println!("    round {i}: {e}"),
            }
        }
        if vals.is_empty() {
            eprintln!("[calibrate] no reading succeeded; nothing to report");
            return std::process::ExitCode::FAILURE;
        }
        // The SAME median the calibration path stores (median_ear averages the
        // two middles of an even sample); a failed round makes the count even,
        // and an upper-middle pick there is not a median (#267 review).
        let median = median_ear(&mut vals);
        println!(
            "[calibrate] pose '{pose}': median EAR {median:.4} over {} reading(s) (range {:.4} to {:.4})",
            vals.len(),
            vals[0],
            vals[vals.len() - 1]
        );
        return std::process::ExitCode::SUCCESS;
    }
    let interactive = std::io::stdin().is_terminal();
    // Ask BEFORE spending the user's time on captures, not after.
    let already_calibrated = matches!(
        daemon_request(&Request::ListProfiles {
            user: user.clone(),
            structured_errors: false,
        }),
        Ok(Response::Enrollment {
            closure_calibrated: true,
            ..
        })
    );
    if already_calibrated && !args.iter().any(|a| a == "--force") {
        if !interactive {
            eprintln!(
                "[calibrate] '{user}' already has a closure calibration, and replacing it here \
                 would\n            \
                 discard it with nothing to restore from. Re-run on a terminal, or pass \
                 --force."
            );
            return std::process::ExitCode::FAILURE;
        }
        println!("[calibrate] '{user}' already has a closure calibration.");
        println!(
            "[calibrate] replacing it discards the old values; they are not recoverable.\n            \
             Do this in the light you actually use, or answer n to keep what you have."
        );
        if !confirm_replace() {
            println!("[calibrate] keeping the existing calibration; nothing changed.");
            return std::process::ExitCode::SUCCESS;
        }
    }
    println!("[calibrate] eye-closure consent calibration for '{user}'.");
    println!("{}", closure_calibration_intro(rounds));

    // Capture one phase, returning the median EAR or a printed error.
    let capture_phase = |label: &str| -> Result<f32, String> {
        print!("    {label}\n    hold still, capturing in 3");
        let _ = std::io::stdout().flush();
        for n in [2, 1] {
            std::thread::sleep(std::time::Duration::from_millis(800));
            print!(" {n}");
            let _ = std::io::stdout().flush();
        }
        println!(" GO");
        match daemon_request(&Request::CaptureEarMedian { user: user.clone() }) {
            Ok(Response::EarMedian(Some(v))) => Ok(v),
            Ok(Response::EarMedian(None)) => {
                Err("no eye detected in the capture; face the camera and retry".into())
            }
            Ok(Response::Error(e)) => Err(e),
            Ok(other) => Err(format!("unexpected response: {other:?}")),
            Err(e) => Err(e),
        }
    };

    // One phase, repeated until the user keeps a reading. A rejected reading is
    // re-taken rather than averaged in: the person in front of the camera knows
    // whether they actually held the pose, and no statistic recovers a capture
    // taken while they were still moving.
    let one_phase = |name: &str, instruction: &str| -> Result<f32, String> {
        loop {
            if interactive {
                print!("    {instruction}\n    Press Enter when you are ready… ");
                let _ = std::io::stdout().flush();
                let mut line = String::new();
                if std::io::stdin().read_line(&mut line).is_err() {
                    return Err("could not read from the terminal".into());
                }
            }
            match capture_phase(instruction) {
                Ok(v) => {
                    println!("    {name} EAR = {v:.4}");
                    if !interactive || keep_reading() {
                        return Ok(v);
                    }
                }
                Err(e) => {
                    if !interactive {
                        return Err(e);
                    }
                    println!("    {e}");
                }
            }
        }
    };

    let (mut opens, mut closeds) = (Vec::new(), Vec::new());
    for r in 1..=rounds {
        if rounds > 1 {
            println!("--- round {r}/{rounds} ---");
        }
        let o = match one_phase(
            "open",
            "Look at the camera with your eyes OPEN and hold still.",
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[calibrate] {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let c = match one_phase(
            "closed",
            "CLOSE your eyes firmly and HOLD them shut through the countdown.",
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[calibrate] {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        println!(
            "    round {r}: open {o:.4} | closed {c:.4} | gap {:.4}\n",
            o - c
        );
        opens.push(o);
        closeds.push(c);
    }

    let ear_open = median_ear(&mut opens.clone());
    let ear_closed = median_ear(&mut closeds.clone());
    if rounds > 1 {
        println!(
            "[calibrate] median of {rounds} rounds: open {ear_open:.4} closed {ear_closed:.4}"
        );
    }

    if ear_open - ear_closed < irlume_liveness::MIN_CALIBRATION_SEPARATION {
        eprintln!(
            "[calibrate] open ({ear_open:.3}) and closed ({ear_closed:.3}) EAR are too close to \
             tell apart. Make sure you fully open then fully close your eyes, and retry."
        );
        return std::process::ExitCode::FAILURE;
    }

    // Check the thresholds this calibration produces back against every reading
    // that produced it. A median can be perfectly sound while the spread around
    // it is wide enough that some of the user's own closures would not register,
    // which is the difference between a gesture that works and one that works
    // most of the time. Reported, not fatal: it is still the best pair available
    // from these captures, and the user is the one who decides whether to redo it.
    let cal = irlume_liveness::ClosureCalibration {
        ear_open,
        ear_closed,
    };
    let (closed_thr, reopen_thr) = (cal.closed_threshold(), cal.reopen_threshold());
    let (closures_ok, reopens_ok) = rounds_that_would_register(&opens, &closeds, &cal);
    if closures_ok < rounds || reopens_ok < rounds {
        println!(
            "[calibrate] ⚠ with this calibration, {closures_ok}/{rounds} of your closures and \
             {reopens_ok}/{rounds} of your\n            \
             reopens would register (closed must read under {closed_thr:.4}, reopen at or \
             over\n            {reopen_thr:.4}). Your readings varied more than the gate \
             allows, so the gesture\n            \
             will sometimes miss. Re-running in steadier light, holding each pose until \
             GO,\n            usually tightens it. The head nod needs no calibration at all."
        );
    } else if rounds > 1 {
        println!(
            "[calibrate] ✓ all {rounds} rounds would register with this calibration \
             (closed under {closed_thr:.4}, reopen over {reopen_thr:.4})."
        );
    }
    match daemon_request(&Request::SetClosureCalibration {
        user: user.clone(),
        ear_open,
        ear_closed,
    }) {
        Ok(Response::Ok(msg)) => {
            println!("[calibrate] ✓ {msg}");
            println!("[calibrate] the polkit consent gesture is now calibrated for '{user}'.");
            // Said HERE, where the user still has the camera up and can redo it,
            // rather than only in doctor. What was just stored describes the eye
            // shape under the light in the room, and behind whatever eyewear the
            // user had on, right now.
            println!("{}", closure_calibration_stored_note());
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[calibrate] {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[calibrate] unexpected response: {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[calibrate] {e}");
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
        eyes-open <on|off>                      require eyes open to unlock\n  \
        challenge <on|off>                      opt-in passive blink liveness"
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

/// The `on`/`off` word for `profiles eyes-open|challenge`, read as the argument
/// AFTER the subcommand rather than found anywhere in argv.
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
            eprintln!("usage: irlume profiles {sub} <on|off> [--user U]");
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
    if args.iter().any(|a| a == "--user") && flag(args, "--user").is_none() {
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
    static CAPS: std::sync::OnceLock<irlume_camera::Caps> = std::sync::OnceLock::new();
    *CAPS.get_or_init(|| {
        match irlume_common::client::request_poll(&irlume_common::Request::Health) {
            Ok(irlume_common::Response::Health { tier, rgb_dev, .. }) => irlume_camera::Caps {
                ir_pair: tier == "secure",
                rgb: rgb_dev.is_some() || tier == "secure",
            },
            // Enumerating opens every node, so it needs POSITIVE evidence that no
            // daemon holds them. Only a failure that proves nobody is listening is
            // that evidence; a timeout is what a daemon busy mid-capture looks
            // like, which is the worst moment to probe.
            Err(e) if daemon_proven_absent(&e) => irlume_camera::capabilities(), // the one permitted probe
            // Ambiguous: answer from the configured pair's mere existence, which
            // never opens anything, and assume the shipped shape when there is no
            // configuration to read.
            _ => match irlume_camera::configured_pair_no_probe() {
                Some((rgb, ir)) => irlume_camera::Caps {
                    ir_pair: std::path::Path::new(&ir).exists(),
                    rgb: std::path::Path::new(&rgb).exists(),
                },
                None => irlume_camera::Caps {
                    ir_pair: false,
                    rgb: false,
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
            // Same rule as `caps`: probe only on proven absence.
            Err(e) if daemon_proven_absent(&e) => irlume_camera::select_pair(), // the one permitted probe
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
/// SILENTLY IGNORED: `blinkcap capture --ir /dev/video6` captured against
/// the built-in default node and failed with "no camera found", saying
/// nothing about the dropped flag (#209). `selected` runs only when needed,
/// since it can probe devices.
pub(crate) fn devices_from_flags(
    rgb: Option<&str>,
    ir: Option<&str>,
    selected: impl FnOnce() -> (String, String),
) -> Option<(String, String)> {
    match (rgb, ir) {
        (None, None) => None,
        (Some(r), Some(i)) => Some((r.to_string(), i.to_string())),
        (r, i) => {
            let (sel_r, sel_i) = selected();
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
        eprintln!("[engine] FaceMesh loaded ({mesh}); passive EAR liveness available");
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

/// Peak IR brightness near the eye landmarks (corneal glint, supporting cue).
fn eye_glint(grey: &[u8], w: u32, h: u32, landmarks: &irlume_vision::Landmarks5) -> f32 {
    let mut peak = 0u8;
    for &(ex, ey) in &landmarks[0..2] {
        let r = 8i32;
        for dy in -r..=r {
            for dx in -r..=r {
                let x = ex as i32 + dx;
                let y = ey as i32 + dy;
                if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                    peak = peak.max(grey[(y as u32 * w + x as u32) as usize]);
                }
            }
        }
    }
    peak as f32
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
        // IR
        let ir = irlume_camera::capture_ir(ir_dev)?;
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
        let ir_eye_glint = ir_top_face
            .map(|f| eye_glint(&ir.data, ir.width, ir.height, &f.landmarks))
            .unwrap_or(0.0);
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
            // Dev gate probe: a single frame with no burst stats, so the
            // negotiated format's ceiling is not available here and the
            // reading is honestly absent rather than guessed at 255.
            ir_saturated_frac: None,
            rgb_face_brightness: 0.0,
            rgb_specular_frac: 0.0,
            rgb_moire_score: 0.0,
        };
        let (verdict, cues, reason) = irlume_liveness::LivenessGate::new().evaluate(&signals);
        println!("[gate] IR face brightness {ir_face_brightness:.0}  center/edge {ir_center_edge_ratio:.2}  eye-glint {ir_eye_glint:.0}  face_frac {:.3}  clipped {}", signals.face_frac,
            signals
                .ir_saturated_frac
                .map(|f| format!("{:.1}%", f * 100.0))
                .unwrap_or_else(|| "n/a".into()));
        println!(
            "[gate] cues: rgb={} ir={} aligned={} ir_reflective={} center_edge={} glint={}",
            cues.face_in_rgb,
            cues.face_in_ir,
            cues.cross_spectrum_aligned,
            cues.ir_reflectance_ok,
            cues.center_edge_ratio_ok,
            cues.glint_present
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

/// `irlume meshprobe --det <yunet> --mesh <face_landmark.onnx> [--rgb ..] [--ir ..] [--n 30] [--burst 2]`
/// Diagnostic for the ADR-0002 passive-EAR liveness (MediaPipe FaceMesh). First a
/// single RGB frame as a sanity check (does the mesh give a sane open-eye EAR ~0.3
/// at all?), then an IR sequence to see whether EAR survives the RGB→IR domain gap
/// and whether a natural blink shows. Blink naturally a couple times during the IR
/// capture.
fn meshprobe(args: &[String]) -> std::process::ExitCode {
    let ir_dev = flag(args, "--ir").unwrap_or(irlume_camera::DEFAULT_IR_DEVICE);
    let (Some(det_path), Some(mesh_path)) = (flag(args, "--det"), flag(args, "--mesh")) else {
        eprintln!("usage: irlume meshprobe --det <yunet.onnx> --mesh <face_landmark.onnx> [--ir ..] [--n 40] [--burst 2] [--reps 1]");
        eprintln!("  to record a PAD-style validation run: --species NAME --kind bonafide|attack --out ear.jsonl");
        return std::process::ExitCode::from(2);
    };
    let n: usize = flag(args, "--n").and_then(|s| s.parse().ok()).unwrap_or(75);
    let burst: usize = flag(args, "--burst")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let reps: usize = flag(args, "--reps")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let trace_on = args.iter().any(|a| a == "--trace");
    // Optional recording (reuses the padreport JSONL format: Blinked→Live,
    // NoBlink→Uncertain/non-response, NoEyes→Spoof).
    let record = match (
        flag(args, "--species"),
        flag(args, "--kind"),
        flag(args, "--out"),
    ) {
        (Some(s), Some(k), Some(o)) => Some((s.to_string(), k.to_string(), o.to_string())),
        _ => None,
    };
    let run = || -> irlume_common::Result<usize> {
        use std::io::Write;
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut mesh = irlume_vision::FaceMesh::load_from_file(mesh_path)?;
        let mut out_file = match &record {
            Some((_, _, o)) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(o)
                    .map_err(|e| irlume_common::Error::Io(e.to_string()))?,
            ),
            None => None,
        };
        let mut written = 0usize;
        for rep in 0..reps {
            let frames = irlume_camera::capture_ir_sequence(ir_dev, n, burst)?;
            let mut ears: Vec<f32> = Vec::new();
            // Per-frame corneal-specular CONTRAST (the candidate 2nd cue): peak eye
            // contrast over the window. Banner ≤70, no-glasses live ~120; the open
            // question is where glasses-genuine lands (does it clear the floor?).
            let mut contrast_max = 0.0f32;
            // Full EarSample stream (index + EAR-if-face + frame brightness): the
            // brightness column doubles as an emitter duty-cycle probe in dark rooms.
            let mut samples: Vec<irlume_liveness::EarSample> = Vec::new();
            for (i, f) in frames.iter().enumerate() {
                let bri =
                    f.data.iter().map(|&p| p as f32).sum::<f32>() / f.data.len().max(1) as f32;
                let ir_rgb = irlume_camera::grey_to_rgb(&f.data);
                let iv = irlume_vision::align::RgbView {
                    data: &ir_rgb,
                    width: f.width,
                    height: f.height,
                };
                let mut ear_i = None;
                let (mut cx, mut cy, mut fsize, mut contrast) = (0.0, 0.0, 0.0, 0.0);
                if let Some(t) = det
                    .detect(&iv)?
                    .into_iter()
                    .max_by(|a, b| a.score.total_cmp(&b.score))
                {
                    let lm = mesh.landmarks(&iv, &t.bbox, 0.25)?;
                    let ear = irlume_vision::eye_ear(&lm, &irlume_vision::EAR_LEFT)
                        .min(irlume_vision::eye_ear(&lm, &irlume_vision::EAR_RIGHT));
                    ears.push(ear);
                    ear_i = Some(ear);
                    contrast =
                        irlume_auth::eye_glint_contrast(&f.data, f.width, f.height, &t.landmarks);
                    contrast_max = contrast_max.max(contrast);
                    cx = (t.bbox[0] + t.bbox[2]) * 0.5;
                    cy = (t.bbox[1] + t.bbox[3]) * 0.5;
                    fsize = (t.bbox[2] - t.bbox[0]).max(0.0);
                }
                samples.push(irlume_liveness::EarSample {
                    idx: i,
                    ear: ear_i,
                    bri,
                    cx,
                    cy,
                    fsize,
                    contrast,
                });
            }
            if trace_on {
                for s in &samples {
                    match s.ear {
                        Some(e) => {
                            println!("    trace {:>3}  ear {e:.3}  bri {:>5.1}", s.idx, s.bri)
                        }
                        None => println!(
                            "    trace {:>3}  ear   -    bri {:>5.1}  (no face)",
                            s.idx, s.bri
                        ),
                    }
                }
            }
            let verdict = irlume_liveness::detect_blink(&samples);
            let (vs, live) = match verdict {
                irlume_liveness::BlinkResult::Blinked => ("Live", true),
                irlume_liveness::BlinkResult::NoBlink => ("Uncertain", false),
                irlume_liveness::BlinkResult::NoEyes => ("Spoof", false),
            };
            let (mut mn, mut mx) = (1.0f32, 0.0f32);
            for &e in &ears {
                mn = mn.min(e);
                mx = mx.max(e);
            }
            let flag_note = match (&record, live) {
                (Some((_, k, _)), true) if k == "attack" => " ‼ ACCEPTED (breach!)",
                (Some((_, k, _)), false) if k == "bonafide" => " ✗ live user not confirmed",
                _ => "",
            };
            let (_, mot_med, _) = irlume_liveness::face_speeds(&samples);
            let (open_c, dip_c) = irlume_liveness::contrast_signature(&samples);
            let drop = if dip_c > 0.0 { open_c / dip_c } else { 0.0 };
            println!("  [rep {:>2}/{reps}] EAR open {mx:.3} min {mn:.3}  contrast open {open_c:>4.0} dip {dip_c:>4.0} drop {drop:.2}  motion med {mot_med:.3}  (n={}) -> {vs}{flag_note}", rep + 1, ears.len());
            if let (Some(f), Some((sp, kind, _))) = (out_file.as_mut(), &record) {
                let rec = serde_json::json!({
                    "species": sp, "kind": kind, "path": "ear", "idx": rep,
                    "verdict": vs, "reason": format!("passive EAR ({verdict:?})"),
                    "ear_open": json_f32(mx), "ear_min": json_f32(mn), "ear_samples": ears.len(),
                    "contrast_max": json_f32(contrast_max),
                    "caught": Vec::<String>::new(),
                });
                writeln!(f, "{rec}").map_err(|e| irlume_common::Error::Io(e.to_string()))?;
                written += 1;
            }
        }
        Ok(written)
    };
    match run() {
        Ok(w) => {
            if let Some((_, _, o)) = &record {
                println!("[meshprobe] appended {w} presentations to {o}; run `irlume padreport --in {o}`");
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("meshprobe error: {e}");
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
                    let d = irlume_common::thirdparty::sha256_hex(&b);
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

            let (mut ir_cos, mut ir_bri, mut ir_center_edge_ratio, mut ir_glint) =
                (f32::NAN, 0.0f32, 0.0f32, 0.0f32);
            if let Some(t) = &ir_top {
                let chip = irlume_vision::align::align_to_arcface(&iv, &t.landmarks)?;
                let raw = emb.embed(&chip)?; // IR = plain embed (no TTA), RAW 512-D
                ir_bri = mean_bbox(&irf.data, irf.width, irf.height, 1, &t.bbox);
                // Ambient-INDEPENDENT liveness cues (the center/edge-floor candidates):
                // center/edge IR ratio (3D face structure) and corneal glint peak.
                ir_center_edge_ratio =
                    irlume_auth::center_edge_ratio(&irf.data, irf.width, irf.height, &t.bbox);
                ir_glint = irlume_auth::eye_glint(&irf.data, irf.width, irf.height, &t.landmarks);
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
                    "ir_eyes_open".into(),
                    irlume_auth::both_eyes_open(&irf.data, irf.width, irf.height, &t.landmarks)
                        .into(),
                );
                rec.insert(
                    "ir_center_edge_ratio".into(),
                    json_f32(ir_center_edge_ratio),
                );
                rec.insert("ir_glint".into(), json_f32(ir_glint));
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
                "  [{:>2}/{n}] rgb {} bri {:>5.1} | ir {} bri {:>5.1} c/e {:>5.2} glint {:>3.0}",
                idx + 1,
                if rgb_top.is_some() { "✓" } else { "·" },
                rgb_bri,
                if ir_top.is_some() { "✓" } else { "·" },
                ir_bri,
                ir_center_edge_ratio,
                ir_glint
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
/// polkit prompt that cannot run the gesture falls back to a password dialog the
/// user is already looking at; a credential release that cannot run it leaves the
/// keyring locked after an otherwise successful face login, which reads as "face
/// login is broken" unless doctor names it.
///
/// Silent when the user has no sealed password: nothing is released, so there is no
/// gate to explain.
fn report_credential_release(
    report: &mut crate::doctor_report::Report,
    user: &str,
    gesture_is_closure: bool,
    closure_calibrated: bool,
) {
    use crate::doctor_report::State;
    // Recorded from the same visibility the block below prints from, so the
    // machine answer cannot disagree with the human one.
    report.check(
        "credential-release-challenge",
        match irlume_common::config::credential_release_challenge_visible() {
            Some(true) => State::Pass,
            Some(false) => State::Warn,
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
    match irlume_common::config::credential_release_challenge_visible() {
        Some(true) => {}
        Some(false) => {
            dout!(
                report,
                "[doctor] ⚠ credential-release challenge: DISABLED\n     \
                 {risk}.\n     \
                 Re-enable: sudo irlume credential-release-challenge on",
                risk = commands::CREDENTIAL_RELEASE_RISK
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
    // The gate is on. Whether it can RUN needs the mesh model (every consent frame
    // goes through FaceMesh) and, in closure-only mode, this user's EAR calibration.
    // A nod needs no calibration, which is why the default mode leaves existing
    // enrollments working with no re-enroll.
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
    if gesture_is_closure && !closure_calibrated {
        dout!(
            report,
            "[doctor] ⚠ credential-release challenge is required but consent_gesture=closure \
             is NOT\n     calibrated for '{user}': your keyring will fall back to the typed \
             password.\n     Fix: sudo irlume calibrate-closure, or unset consent_gesture in \
             settings.conf to\n     use the no-calibration head nod."
        );
        return;
    }
    dout!(
        report,
        "[doctor] credential-release challenge: required ✓ ({} to release your keyring \
         password)",
        if gesture_is_closure {
            "close your eyes ~1s then open"
        } else if closure_calibrated {
            "keep nodding, or close your eyes ~1s then open"
        } else {
            "keep nodding your head"
        }
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
            "[doctor] ⚠ your login manager ({dm}) does not display the gesture \
             instruction.\n     \
             It is still REQUIRED at the login screen after a reboot or logout: {}\n     \
             while your face is being read. Nothing on screen will ask you to. Without \
             it your\n     \
             login still succeeds and only the keyring falls back to the typed password.",
            if gesture_is_closure {
                "close your eyes ~1s then open"
            } else {
                "keep nodding your head"
            }
        );
    }
    // Only for users who actually have a closure calibration: it is stored as
    // absolute EAR values, and those move with the light. Measured on one user's
    // hardware the same seated position gave a median open EAR of 0.109 at an
    // ambient of 22-42 and 0.166 at an ambient of 1, a 52% shift. No single
    // calibration covers both: registering that session's deepest closure and
    // its shallowest reopen needs a gap of 0.030, and the code requires 0.05.
    //
    // Nothing here can fix that, so doctor says it. Being told once beats
    // discovering it as a keyring prompt that only happens after dark, and the
    // nod is right there needing no calibration at all.
    if closure_calibrated || gesture_is_closure {
        dout!(
            report,
            "[doctor] note: your eye-closure calibration is tied to the LIGHT you \
             calibrated in.\n     \
             Eye shape is stored as absolute values, and they shift as the room \
             changes, so a\n     \
             calibration taken in daylight can stop registering after dark. \
             Re-run `sudo irlume\n     \
             calibrate-closure` in the light you actually use{}",
            if gesture_is_closure {
                ". consent_gesture=closure means there\n     \
                 is no fallback gesture; unset it in settings.conf to also accept the head \
                 nod,\n     which is pose-defined and needs no calibration."
            } else {
                ", or just use the head nod, which is\n     \
                 pose-defined and unaffected by lighting."
            }
        );
    }
}

/// What `doctor` observed about the active camera pair's capture mode. Kept as
/// a value so the wording is decided by a pure function and tested, separately
/// from the root check and config reads that produce it.
enum CaptureModeReport {
    /// The verdict lives in root-only `cameras.conf` and this run cannot read it.
    RootRequired,
    /// `cameras.conf` exists but could not be read, so nothing was established.
    ///
    /// Kept apart from [`Self::NoPinnedPair`] because `read_kv` collapses
    /// "absent" and "unreadable" into `None`, and its own doc says a caller
    /// that REPORTS the state rather than falling back on a default must use
    /// `observe_kv`. This is that caller: gating on euid alone made a root run
    /// on an unreadable file (EACCES from a copy placed without `restorecon`)
    /// report a guess as an observation, at `info` (#100 review).
    Unreadable(String),
    /// No pair is persisted, so there is nothing to look a verdict up by; irlume
    /// auto-selects a pair at capture and the mode follows from that.
    NoPinnedPair,
    /// A verdict was measured for this pair and stored.
    Measured(irlume_camera::CaptureMode),
    /// The pair is pinned but no verdict was ever measured for it.
    Unmeasured,
    /// `IRLUME_SEQUENTIAL_CAPTURE` is set in THIS process's environment and
    /// decides alone, whatever is stored.
    Overridden(bool),
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
        CaptureModeReport::RootRequired => (
            State::Unknown,
            "root-only setting (reads /etc/irlume/cameras.conf); re-run `sudo irlume doctor` \
             to read it"
                .to_string(),
        ),
        CaptureModeReport::Unreadable(why) => (
            State::Unknown,
            format!(
                "/etc/irlume/cameras.conf could not be read ({why}), so the capture mode is \
                 unknown; this is NOT the same as no mode being set"
            ),
        ),
        // Says what it does and does not know. The old wording implied no
        // verdict exists, and on an auto-discovered install that is wrong: the
        // pin (`rgb=`/`ir=`) is written only by `set-cameras` and the TUI, while
        // the verdict is keyed by device identity and written by `camera-tune`
        // and the enrolment probe. So a machine that never pinned a pair can
        // still have a measured verdict in that file, in force, unreported
        // (#100 review). Resolving which one applies needs the device pair, and
        // finding that without a pin means opening cameras, which doctor must
        // not do.
        CaptureModeReport::NoPinnedPair => (
            State::Info,
            "no pinned camera pair, so the stored verdict cannot be looked up here; irlume \
             auto-selects a pair at capture and any mode measured for that pair still \
             applies. Run `sudo irlume set-cameras` to pin one, or `sudo irlume camera-tune` \
             to measure and report the mode"
                .to_string(),
        ),
        CaptureModeReport::Overridden(sequential) => (
            State::Info,
            format!(
                "{}, forced by IRLUME_SEQUENTIAL_CAPTURE in this process's environment, which \
                 outranks any stored verdict. Note this reads THIS shell, not the daemon's \
                 unit environment: a value set only in the irlumed unit decides captures and \
                 is not visible here",
                if *sequential {
                    "sequential"
                } else {
                    "concurrent"
                }
            ),
        ),
        CaptureModeReport::Measured(CaptureMode::Sequential) => (
            State::Info,
            // The measured range, not one end of it. 700ms is the ASUS figure,
            // and the ASUS keeps 102% of its brightness under concurrent
            // capture, so it is measured CONCURRENT and never reaches this
            // line. The population that gets a sequential verdict is the
            // NexiGo-shaped one, measured at 1.3s (#100 review).
            "sequential, measured for this camera pair (RGB then IR, one after the other: \
             0.7s to 1.3s more per capture on the modules measured for #340, and the \
             reliable choice on a camera that dims when both sensors stream at once)"
                .to_string(),
        ),
        CaptureModeReport::Measured(CaptureMode::Concurrent) => (
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
    }
}

/// Doctor's capture-mode block: which capture strategy the active camera pair
/// uses, and whether that was measured or is the unmeasured default.
///
/// Reads the pinned pair without opening the camera ([`irlume_camera::configured_pair_no_probe`]),
/// then the stored verdict; both live in root-only `cameras.conf`, so an
/// unprivileged run reports `Unknown` and says to re-run under sudo, the same
/// shape as the credential-release block. The wording of every case is
/// [`capture_mode_report_line`], which is where the tests are.
fn report_capture_mode(report: &mut crate::doctor_report::Report) {
    // The override decides alone, in BOTH directions, before anything stored is
    // consulted: that is `capture_mode_decision`'s first arm. Reporting a
    // stored verdict as the mode in force while this is set states the opposite
    // of what happens (#100 review). Read from this process, and the line says
    // so, because a value set only in the daemon's unit environment is not
    // visible from here.
    let observed = if let Ok(v) = std::env::var("IRLUME_SEQUENTIAL_CAPTURE") {
        CaptureModeReport::Overridden(v.trim() == "1")
    } else if !is_root() {
        CaptureModeReport::RootRequired
    } else {
        // `observe_kv`, not `read_kv`: the difference between "no pin" and
        // "could not read the file" is exactly what this block reports.
        match irlume_common::config::observe_kv("cameras.conf", "rgb") {
            irlume_common::config::KvObservation::Unknown(e) => {
                CaptureModeReport::Unreadable(e.to_string())
            }
            _ => match irlume_camera::configured_pair_no_probe() {
                None => CaptureModeReport::NoPinnedPair,
                Some((rgb, ir)) => match irlume_camera::stored_capture_mode(&rgb, &ir) {
                    Some(mode) => CaptureModeReport::Measured(mode),
                    None => CaptureModeReport::Unmeasured,
                },
            },
        }
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
                 `sudo irlume ir-setup`, to put them back",
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
    } else if nodes.is_empty() && scan.unreadable.is_empty() {
        dout!(report, "  (no /dev/video* nodes on this machine)");
    }
    if nodes.is_empty() {
        if let Some(gen) = irlume_camera::intel_ipu_present() {
            dout!(report,
                "  ⚠ this laptop has an Intel {gen} MIPI camera, which irlume cannot use:\n     \
                 - its capture nodes emit raw Bayer, not a directly-openable YUYV/GREY stream;\n     \
                 - the IR (Windows Hello) sensor is not exposed on Linux at all, so IR face\n       \
                 auth and IR liveness are unavailable on this hardware.\n     \
                 RGB-only webcam use is possible via a libcamera software-ISP + v4l2loopback\n     \
                 bridge, but irlume needs the IR sensor; an external USB IR camera is the\n     \
                 supported path on {gen} machines."
            );
        }
    }
    for (path, role) in &nodes {
        let priv_on = if irlume_camera::privacy_engaged(path) {
            "  ⚠ PRIVACY SWITCH ON"
        } else {
            ""
        };
        // Name the backend on every node: uvcvideo-on-USB is the case irlume
        // is built and tested for, and anything else is the first fact a bug
        // report needs (an IPU/MIPI node classifies by format just as well and
        // then behaves nothing alike; #187 had to establish this by hand).
        let backend = match irlume_camera::node_backend(path) {
            Ok((drv, true)) if drv == "uvcvideo" => format!(" ({drv}, USB)"),
            Ok((drv, on_usb)) => {
                let bus = if on_usb { "USB" } else { "not USB" };
                format!(" ({drv}, {bus})  ⚠ not the uvcvideo-on-USB case irlume is built for")
            }
            // A failed observation says so; rendering it as the old bare line
            // would make "could not tell" look like "nothing to tell" on the
            // one surface whose whole job is telling (#195 review).
            Err(e) => format!(" (backend unknown: {e})  ⚠ could not identify camera backend"),
        };
        dout!(report, "  {path}: {role:?}{backend}{priv_on}");
        // An RGB node the capture path can't decode (MJPEG-only) classifies as
        // usable but would fail at capture; warn here instead.
        if *role == irlume_camera::Role::Rgb {
            // Must match the capture path's DECODABLE_RGB (YUYV, NV12); listing
            // RGB3/BGR3 here would pass doctor then fail at capture.
            let fmts = irlume_camera::rgb_node_formats(path);
            let decodable = fmts.iter().any(|f| f == b"YUYV" || f == b"NV12");
            if !fmts.is_empty() && !decodable {
                let list: Vec<String> = fmts
                    .iter()
                    .map(|f| {
                        std::str::from_utf8(f)
                            .unwrap_or("????")
                            .trim_end()
                            .to_string()
                    })
                    .collect();
                dout!(
                    report,
                    "     ⚠ offers only [{}]; irlume needs an uncompressed format\n       \
                     (YUYV or NV12). This camera will detect but fail at capture.",
                    list.join(", ")
                );
            }
        }
    }
    // A node irlume could not read is named with its errno, never omitted.
    // Dropping these is what let a permission problem read as absent hardware
    // and sent the reader after a driver bug they did not have (#227).
    // Nodes are grouped by cause: one missing 'video' group membership denies
    // every node on the machine, and that is one fact, not eleven.
    let mut by_cause: std::collections::BTreeMap<String, Vec<&str>> = Default::default();
    for u in &scan.unreadable {
        by_cause.entry(u.cause()).or_default().push(&u.path);
    }
    for (cause, paths) in &by_cause {
        dout!(report, "  ⚠ {}: {cause}", paths.join(", "));
    }

    // --- stream vs the Windows Hello minimums (#223) -----------------------
    {
        // deliberate camera probe: doctor's job is to inspect the hardware,
        // and negotiating a stream format needs the node open. Foreground and
        // occasional, not a refresh loop, so it is not the #187 shape.
        let (rgb_node, ir_node) = irlume_camera::select_pair();
        stream_minimum_checks(report, &rgb_node, &ir_node);
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
    // --- pipeline stages (#276) -----------------------------------------
    // Each stage's model CANDIDATE from this process's search order. A
    // candidate, not a claim about the daemon: the service unit (or a
    // drop-in) sets the daemon's own environment, which this shell cannot
    // observe. The PAD stage is the third-party line below; its built-in
    // gate is code.
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
                format!("{file} — not found; mesh-dependent gates (passive blink liveness, consent gesture) are disabled"),
            ),
        };
        dout!(report, "  {}: {line}", s.stage);
        report.check_detail(id, state, line);
    }
    // Derived from the catalog, never spelled out: this line said "the pad stage
    // only today" through the release that opened recognition, so doctor denied a
    // feature the same binary shipped.
    {
        let open: Vec<&str> = irlume_common::thirdparty::Stage::ALL
            .iter()
            .filter(|st| st.open())
            .map(|st| st.as_str())
            .collect();
        dout!(
            report,
            "  (third-party models accepted for: {}; #276. `irlume models` lists them)",
            if open.is_empty() {
                "no stage".to_string()
            } else {
                open.join(", ")
            }
        );
    }
    dout!(
        report,
        "[doctor] third-party PAD model: {}",
        models::doctor_line()
    );
    report.check_detail("third-party-pad-model", State::Info, models::doctor_line());

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
    report.check(
        "fingerprint-reader",
        if irlume_fingerprint::device_name().is_some() {
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
    // The consent gesture is a head NOD by default (no calibration). Only the
    // opt-in closure gesture needs a per-user calibration; wired-but-uncalibrated
    // then silently falls to the password on every polkit prompt.
    // Same parse the engine gates on and the PAM module instructs from, so doctor
    // can never report a gesture the daemon would refuse.
    let gesture_is_closure = irlume_common::config::consent_gesture_mode()
        == irlume_common::config::ConsentGesture::Closure;
    let closure_calibrated = matches!(
        daemon_request(&irlume_common::Request::ListProfiles {
            user: user.clone(),
            structured_errors: false,
        }),
        Ok(irlume_common::Response::Enrollment {
            closure_calibrated: true,
            ..
        })
    );
    // --- credential release (the keyring password) --------------------------
    // Reported before the polkit block because it shares the gesture-readiness
    // facts above: this is the same nod/closure gate, applied to the one operation
    // where a spoof yields a REUSABLE secret instead of one session.
    report_credential_release(report, &user, gesture_is_closure, closure_calibrated);

    report.check(
        "polkit-app-prompts",
        match crate::pamwire::polkit_wired() {
            Some(true) => State::Pass,
            Some(false) => State::Info,
            None => State::Unknown,
        },
    );
    match crate::pamwire::polkit_wired() {
        // "KEEP nodding", matching the prompt the user will actually see: a
        // single nod released 0 times out of 3 on hardware, because the detector
        // needs a run of frames showing the motion.
        Some(true) if !gesture_is_closure => dout!(report,
            "[doctor] polkit app prompts: wired ✓ (KEEP NODDING to approve Bitwarden unlock,\n     \
             pkexec, …; no calibration needed{})",
            if closure_calibrated {
                "; closing your eyes ~1s also works"
            } else {
                ", or run calibrate-closure to also allow the eye-closure gesture"
            }
        ),
        Some(true) if closure_calibrated => dout!(report,
            "[doctor] polkit app prompts: wired ✓ and calibrated ✓ (close your eyes ~1s to \
             approve; consent_gesture=closure)"
        ),
        Some(true) => dout!(report,
            "[doctor] polkit app prompts: wired ✓ but consent_gesture=closure and NOT calibrated;\n     \
             prompts fall back to the password. Calibrate (sudo irlume calibrate-closure) or unset\n     \
             consent_gesture in settings.conf to use the no-calibration head nod."
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
    report.check(
        "login-wiring",
        if crate::pamwire::login_wired() {
            State::Pass
        } else if enrolled {
            State::Warn
        } else {
            State::Info
        },
    );
    if enrolled && !crate::pamwire::login_wired() {
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
    fn measure_pose_label_refuses_swallowed_and_missing_values() {
        // No flag at all: the honest default.
        assert_eq!(
            measure_pose_label(&argv(&["--measure-only"])),
            Ok("unlabeled")
        );
        // A proper label passes through.
        assert_eq!(
            measure_pose_label(&argv(&["--measure-only", "--pose", "glasses-on-open"])),
            Ok("glasses-on-open")
        );
        // `--pose --rounds 5` must not label the data '--rounds'.
        assert_eq!(
            measure_pose_label(&argv(&["--pose", "--rounds", "5"])),
            Err(())
        );
        // A trailing `--pose` asked for a label and gave none.
        assert_eq!(
            measure_pose_label(&argv(&["--measure-only", "--pose"])),
            Err(())
        );
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
    fn devices_from_flags_honors_either_flag_alone() {
        let sel = || ("/dev/sel-rgb".to_string(), "/dev/sel-ir".to_string());
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

    #[test]
    fn flag_takes_the_first_occurrence() {
        let a = argv(&["--user", "a", "--user", "b"]);
        assert_eq!(flag(&a, "--user"), Some("a"));
    }

    #[test]
    fn median_ear_picks_the_middle_regardless_of_capture_order() {
        // Odd count: the true middle, not the mean, so one bad capture in a
        // round cannot drag the stored value the way an average would.
        assert_eq!(median_ear(&mut [0.10, 0.30, 0.20]), 0.20);
        // Even count: mean of the two middles.
        assert_eq!(median_ear(&mut [0.10, 0.20, 0.30, 0.40]), 0.25);
        assert_eq!(median_ear(&mut [0.17]), 0.17);
        // The outlier that motivated the median: four tight readings and one
        // shallow closure. The mean would be 0.0511, the median stays at 0.0450.
        let mut real = [0.0424, 0.0450, 0.0661, 0.0727, 0.0894];
        assert_eq!(median_ear(&mut real), 0.0661);
    }

    /// The self-check must agree with the engine's own gate, or it would tell the
    /// user a calibration is fine while the daemon refuses their closures.
    #[test]
    fn the_self_check_counts_rounds_the_engine_would_accept() {
        use irlume_liveness::ClosureCalibration;
        // Tonight's measured session: open median 0.1658, closed median 0.0661.
        let opens = [0.1635, 0.1652, 0.1658, 0.1861, 0.1868];
        let closeds = [0.0424, 0.0450, 0.0661, 0.0727, 0.0894];
        let cal = ClosureCalibration {
            ear_open: 0.1658,
            ear_closed: 0.0661,
        };
        let (c_ok, o_ok) = rounds_that_would_register(&opens, &closeds, &cal);
        // Calibrated from its own session, every round registers: the median
        // puts closed_threshold at 0.0960, above even the shallowest closure.
        assert_eq!(o_ok, 5, "every reopen clears {}", cal.reopen_threshold());
        assert_eq!(c_ok, 5, "closed_threshold {}", cal.closed_threshold());

        // The calibration actually stored on that machine, taken in different
        // light, applied to the same evening readings: the 0.0894 closure now
        // sits above a 0.0739 threshold and would not register. This is the
        // shortfall the warning exists to surface, and it is invisible from the
        // stored pair alone.
        let stored = ClosureCalibration {
            ear_open: 0.1090,
            ear_closed: 0.0588,
        };
        let (c2, o2) = rounds_that_would_register(&opens, &closeds, &stored);
        assert_eq!((c2, o2), (4, 5));

        // And the degenerate case: no readings cannot report false confidence.
        assert_eq!(rounds_that_would_register(&[], &[], &cal), (0, 0));
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

        let (state, line) = capture_mode_report_line(&CaptureModeReport::RootRequired);
        assert!(matches!(state, State::Unknown), "a can't-read is Unknown");
        assert!(line.contains("sudo"), "and tells the user how to read it");

        for (obs, want) in [
            (
                CaptureModeReport::Measured(CaptureMode::Sequential),
                "sequential",
            ),
            (
                CaptureModeReport::Measured(CaptureMode::Concurrent),
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

        let (state, line) = capture_mode_report_line(&CaptureModeReport::NoPinnedPair);
        assert!(matches!(state, State::Info));
        assert!(
            line.contains("auto-select"),
            "no pin means auto-selection at capture"
        );
        // ...and it must not imply no verdict exists. The pin and the verdict
        // live on different keys written by different commands, so an
        // auto-discovered install can have a measured mode in force with no pin
        // at all (#100 review).
        assert!(
            line.contains("still applies"),
            "must not read as 'no mode is set': {line}"
        );

        // An unreadable config is not an absent one. `read_kv` collapses them
        // and its own doc says a reporting caller must not.
        let (state, line) =
            capture_mode_report_line(&CaptureModeReport::Unreadable("permission denied".into()));
        assert!(
            matches!(state, State::Unknown),
            "could-not-read must not be reported as an observation: {line}"
        );
        assert!(line.contains("NOT the same"), "{line}");

        // The env override decides alone, in both directions, ahead of anything
        // stored, and the line must say it read this process rather than the
        // daemon's unit environment.
        for (seq, want) in [(true, "sequential"), (false, "concurrent")] {
            let (state, line) = capture_mode_report_line(&CaptureModeReport::Overridden(seq));
            assert!(matches!(state, State::Info));
            assert!(line.starts_with(want), "{line}");
            assert!(line.contains("IRLUME_SEQUENTIAL_CAPTURE"), "{line}");
            assert!(
                line.contains("unit environment"),
                "must disclose that it cannot see the daemon's environment: {line}"
            );
        }

        // The sequential line quotes the range that was measured, not the
        // ASUS end of it. The ASUS keeps 102% under concurrent capture, so it
        // is measured concurrent and never reaches this line at all.
        let (_, seq_line) =
            capture_mode_report_line(&CaptureModeReport::Measured(CaptureMode::Sequential));
        assert!(
            !seq_line.contains("700ms"),
            "700ms is the figure for a camera that never gets this verdict: {seq_line}"
        );
        assert!(seq_line.contains("1.3s"), "{seq_line}");
    }

    /// The stored eye shape is tied to two conditions, room light and glasses,
    /// and the user reads this guidance once. If it names only the light, a user
    /// who calibrates bare-eyed is not warned that putting glasses on can strand
    /// their closures (#173: measured 0 of 5 glasses-on closures registering
    /// against a bare-eyed calibration). Both the pre-capture guidance and the
    /// post-store note must name both conditions, and neither may drop the round
    /// count or the "the nod needs none of this" reassurance.
    #[test]
    fn closure_calibration_guidance_names_light_and_glasses() {
        let intro = closure_calibration_intro(3);
        assert!(intro.contains("3 round(s)"), "intro states the round count");
        assert!(
            intro.to_ascii_lowercase().contains("glasses"),
            "intro must tell a glasses wearer to calibrate with them on"
        );
        assert!(
            intro.contains("light you actually use"),
            "intro must keep the room-light guidance"
        );

        let note = closure_calibration_stored_note();
        assert!(
            note.to_ascii_lowercase().contains("glasses"),
            "stored note must name glasses too"
        );
        assert!(
            note.contains("light you"),
            "stored note must keep the room-light guidance"
        );
        assert!(
            note.contains("nod"),
            "stored note must keep the reassurance that the nod path is unaffected"
        );
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
            toggle_value(&argv(&["challenge", "--user", "off"]), "challenge"),
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
        assert_eq!(toggle_value(&argv(&["challenge"]), "challenge"), None);
        assert_eq!(
            toggle_value(&argv(&["challenge", "yes"]), "challenge"),
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
    fn eye_glint_takes_the_peak_near_the_eye_landmarks_only() {
        let (w, h) = (64u32, 64u32);
        let mut grey = vec![0u8; (w * h) as usize];
        let landmarks: irlume_vision::Landmarks5 = [
            (10.0, 10.0), // left eye
            (30.0, 10.0), // right eye
            (20.0, 20.0),
            (12.0, 28.0),
            (28.0, 28.0),
        ];
        assert_eq!(eye_glint(&grey, w, h, &landmarks), 0.0);
        grey[(12 * w + 12) as usize] = 200; // within radius 8 of the left eye
        grey[(60 * w + 60) as usize] = 255; // far from both eyes: must not count
        assert_eq!(eye_glint(&grey, w, h, &landmarks), 200.0);
    }
}
