// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume logs`: one journal view for diagnosing auth problems, and the
//! switch for the daemon's diagnostic tracing.
//!
//!   irlume logs                    irlume-related journal lines, this boot
//!   irlume logs -f | --follow      live view (watch while you test a login)
//!   irlume logs --since "10m ago"  older window (passed to journalctl)
//!   irlume logs debug              show whether daemon tracing is on
//!   sudo irlume logs debug on|off  toggle IRLUME_LOG=debug via a systemd
//!                                  drop-in + daemon restart
//!
//! The view greps the SYSTEM journal for the whole face-auth story in one
//! stream: `irlumed` daemon lines (attempts, scores, gate reasons, [debug]
//! pipeline traces), PAM audit records naming `pam_irlume` (what the greeter
//! actually granted), and the keyring modules (`pam_kwallet*`,
//! `pam_gnome_keyring`) that a face login is supposed to feed.

use crate::is_root;
use std::path::Path;
use std::process::{Command, ExitCode};

const DROPIN_DIR: &str = "/etc/systemd/system/irlumed.service.d";
const DROPIN: &str = "/etc/systemd/system/irlumed.service.d/50-irlume-debug.conf";
const PATTERN: &str = "irlume|pam_kwallet|pam_gnome_keyring";

pub fn run(sub: Option<&str>, args: &[String]) -> ExitCode {
    match sub {
        Some("debug") => debug(args.get(2).map(String::as_str)),
        _ => view(&args[1..]),
    }
}

/// Build the full journalctl argv (program + args) from the view options, or an
/// error message for a bad option. Extracted verbatim from `view` so the argv
/// assembly (the whole point of the option parse) is unit-testable without
/// execing journalctl; `view` just runs what this returns. Zero behavior change.
fn build_view_argv(opts: &[String]) -> Result<Vec<String>, String> {
    let mut argv = vec![
        "journalctl".to_string(),
        "--no-pager".to_string(),
        "-g".to_string(),
        PATTERN.to_string(),
    ];
    let mut follow = false;
    let mut since = false;
    let mut it = opts.iter().map(String::as_str);
    while let Some(o) = it.next() {
        match o {
            "-f" | "--follow" => follow = true,
            "--since" => match it.next() {
                Some(v) => {
                    since = true;
                    argv.push("--since".to_string());
                    argv.push(v.to_string());
                }
                None => {
                    return Err(
                        "[logs] --since needs a value, e.g. --since \"10 min ago\"".to_string()
                    );
                }
            },
            other => {
                return Err(format!(
                    "[logs] unknown option '{other}' (usage: irlume logs [-f] [--since T] [debug on|off])"
                ));
            }
        }
    }
    if follow {
        argv.push("-f".to_string());
    } else if !since {
        argv.push("-b".to_string());
    } // default: this boot
    Ok(argv)
}

fn view(opts: &[String]) -> ExitCode {
    let argv = match build_view_argv(opts) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if !is_root() {
        eprintln!("[logs] note: without root (or the systemd-journal group) the system journal may be hidden; re-run with sudo if this looks empty");
    }
    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("[logs] could not run journalctl: {e}");
            ExitCode::FAILURE
        }
    }
}

fn debug(action: Option<&str>) -> ExitCode {
    match action {
        None | Some("status") => {
            let on = Path::new(DROPIN).exists();
            println!(
                "[logs] daemon diagnostic tracing: {}",
                if on { "ON (drop-in present)" } else { "off" }
            );
            println!(
                "[logs] toggle: sudo irlume logs debug {}",
                if on { "off" } else { "on" }
            );
            ExitCode::SUCCESS
        }
        Some("on") => {
            if !is_root() {
                eprintln!("[logs] needs root: sudo irlume logs debug on");
                return ExitCode::FAILURE;
            }
            if let Err(e) = std::fs::create_dir_all(DROPIN_DIR).and_then(|()| std::fs::write(DROPIN,
                "# irlume: created by `irlume logs debug on`; remove with `irlume logs debug off`\n[Service]\nEnvironment=IRLUME_LOG=debug\n"))
            {
                eprintln!("[logs] could not write {DROPIN}: {e}");
                return ExitCode::FAILURE;
            }
            restart_daemon();
            println!("[logs] tracing ON: the daemon now logs per-stage pipeline lines (capture/detect/liveness cues/match scores; numbers only, never frames or embeddings).");
            println!("[logs] ⚠ while on, DENIED attempts log their score vs threshold: feedback a journal-reader could use to tune a spoof. Diagnose, then turn it off:");
            println!("[logs] watch live with:  irlume logs -f    ·   turn off with:  sudo irlume logs debug off");
            ExitCode::SUCCESS
        }
        Some("off") => {
            if !is_root() {
                eprintln!("[logs] needs root: sudo irlume logs debug off");
                return ExitCode::FAILURE;
            }
            match std::fs::remove_file(DROPIN) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!("[logs] tracing already off");
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("[logs] could not remove {DROPIN}: {e}");
                    return ExitCode::FAILURE;
                }
            }
            let _ = std::fs::remove_dir(DROPIN_DIR); // only if now empty
            restart_daemon();
            println!("[logs] tracing off");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("[logs] unknown: 'debug {other}' (use: debug [on|off])");
            ExitCode::FAILURE
        }
    }
}

fn restart_daemon() {
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = Command::new("systemctl")
        .args(["try-restart", "irlumed.service"])
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_view_greps_the_pattern_this_boot() {
        // No options → the fixed grep argv plus `-b` (this boot).
        assert_eq!(
            build_view_argv(&[]).unwrap(),
            vec!["journalctl", "--no-pager", "-g", PATTERN, "-b"]
        );
    }

    #[test]
    fn follow_replaces_the_boot_filter_with_f() {
        // -f / --follow both set follow, which suppresses -b and appends -f.
        for flag in ["-f", "--follow"] {
            let argv = build_view_argv(&opts(&[flag])).unwrap();
            assert_eq!(argv.last().unwrap(), "-f");
            assert!(!argv.contains(&"-b".to_string()));
        }
    }

    #[test]
    fn since_passes_its_value_through_and_drops_the_boot_filter() {
        let argv = build_view_argv(&opts(&["--since", "10 min ago"])).unwrap();
        // --since <value> present, in order, and no default -b when a window is given.
        let pos = argv.iter().position(|a| a == "--since").unwrap();
        assert_eq!(argv[pos + 1], "10 min ago");
        assert!(!argv.contains(&"-b".to_string()));
        assert!(!argv.contains(&"-f".to_string()));
    }

    #[test]
    fn since_without_a_value_is_an_error() {
        let err = build_view_argv(&opts(&["--since"])).unwrap_err();
        assert!(err.contains("--since needs a value"), "{err}");
    }

    #[test]
    fn an_unknown_option_names_itself_in_the_error() {
        let err = build_view_argv(&opts(&["--bogus"])).unwrap_err();
        assert!(err.contains("unknown option '--bogus'"), "{err}");
    }

    #[test]
    fn follow_and_since_compose() {
        // Both given: --since value present AND -f appended, still no -b.
        let argv = build_view_argv(&opts(&["--since", "1h", "-f"])).unwrap();
        assert!(argv.windows(2).any(|w| w == ["--since", "1h"]));
        assert_eq!(argv.last().unwrap(), "-f");
        assert!(!argv.contains(&"-b".to_string()));
    }
}
