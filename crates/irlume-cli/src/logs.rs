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

/// Whether the debug-logging drop-in is active (the TUI's toggle reads this
/// to know which way `logs debug` should flip).
pub(crate) fn debug_active() -> bool {
    Path::new(DROPIN).exists()
}

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
/// Normalize a `--since` value into a form journalctl accepts (#561).
///
/// `2 min`, `5m`, `90s`, `2min`, `1h` (the shapes people type because the
/// CLI's own usage hint suggests `10 min ago`) become `<n> <unit> ago`, with
/// the one-letter abbreviations expanded to units systemd documents. Anything
/// else passes through byte-for-byte: values that already parse (`... ago`,
/// negative offsets, absolute timestamps, `yesterday`) must not be rewritten,
/// and multi-term or malformed input stays journalctl's to judge, with the
/// failure hint behind it. Pure, so the table is unit-testable.
fn normalize_since(value: &str) -> String {
    let trimmed = value.trim();
    // Exactly one number, optional space, one alpha unit: the bare relative
    // shape. A leading minus is already a systemd offset; leave it alone.
    if trimmed.starts_with('-') || trimmed.is_empty() {
        return value.to_string();
    }
    let (number, unit) = match trimmed.find(char::is_alphabetic) {
        Some(at) => {
            let n = trimmed[..at].trim();
            if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) {
                (n, &trimmed[at..])
            } else {
                return value.to_string();
            }
        }
        None => return value.to_string(),
    };
    let unit = match unit.trim() {
        "s" | "sec" => "sec".to_string(),
        "m" => "min".to_string(),
        "h" => "hr".to_string(),
        other => other.to_string(),
    };
    if unit.chars().all(|c| c.is_ascii_alphabetic()) && !unit.is_empty() {
        format!("{number} {unit} ago")
    } else {
        value.to_string()
    }
}

/// What `view` prints when journalctl itself rejects the `--since` value
/// anyway: the accepted syntax and the exact retry command, so the user never
/// sees journalctl's bare parse error alone. Pure, so the wording is pinned.
fn since_hint(rejected: &str) -> String {
    format!(
        "[logs] journalctl rejected --since '{rejected}'. Accepted: an absolute timestamp \
         (2026-08-27 12:00:00), \"<N> sec|min|hr|day|week[s] ago\", or a negative offset \
         like \"-90s\". Retry: irlume logs --since \"10 min ago\""
    )
}

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
                    // #561: bare relative forms are normalized here, once, on
                    // the only path into journalctl.
                    argv.push(normalize_since(v));
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
            // A bad option is a usage error (2), not a runtime failure (1);
            // every other command in the CLI answers 2 here and a wrapper that
            // branches on the code was told the journal read had failed.
            return ExitCode::from(2);
        }
    };
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if !is_root() {
        eprintln!("[logs] note: without root (or the systemd-journal group) the system journal may be hidden; re-run with sudo if this looks empty");
    }
    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => {
            // #561: journalctl's own error ("Failed to parse timestamp: ...")
            // names neither the accepted forms nor the retry; add both. Only
            // meaningful when a --since value was in play.
            if let Some(hint) = failure_hint(&argv) {
                eprintln!("{hint}");
            }
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[logs] could not run journalctl: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The hint `view` prints when journalctl rejected the `--since` value, or
/// `None` when no window was given (the failure is then journalctl's own
/// story to tell). Pure, so the gating is unit-testable.
fn failure_hint(argv: &[String]) -> Option<String> {
    let pos = argv.iter().position(|a| a == "--since")?;
    Some(since_hint(&argv[pos + 1]))
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
            restart_daemon_and_wait();
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
            restart_daemon_and_wait();
            println!("[logs] tracing off");
            ExitCode::SUCCESS
        }
        Some(other) => {
            // 2, not 1: this is a usage error, the convention the rest of the CLI
            // follows (and that `logs`'s own option handler a few lines above
            // already returns). FAILURE here told a script the command had run
            // and failed, when it had not run at all.
            eprintln!("[logs] unknown: 'debug {other}' (use: debug [on|off])");
            ExitCode::from(2)
        }
    }
}

/// What `logs debug on|off` prints BEFORE the daemon restarts (#562): the
/// restart was silent, so anyone mid-testing got a surprise stop/start and a
/// request fired right after the command could race the model load.
fn restart_notice() -> &'static str {
    "[logs] restarting irlumed to apply the tracing change (takes a few seconds; \
     wait for 'serving on /run/irlume.sock')"
}

/// Testable core of [`wait_for_serving`]: poll `probe` until it first answers
/// true (serving) or `deadline` passes. Pure polling policy, no clock of its
/// own beyond `Instant::now`, so a test drives it with an already-passed
/// deadline for the timeout arm.
fn wait_for_serving_with(mut probe: impl FnMut() -> bool, deadline: std::time::Instant) -> bool {
    loop {
        if probe() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Wait until the daemon answers Ping as Running again (a restart spends a
/// few seconds loading models first; 21s measured on one host, so the budget
/// is generous). Returns whether serving was confirmed.
fn wait_for_serving() -> bool {
    wait_for_serving_with(
        || {
            crate::commands::classify_reach(irlume_common::client::request_poll(
                &irlume_common::Request::Ping,
            )) == crate::commands::DaemonReach::Running
        },
        std::time::Instant::now() + std::time::Duration::from_secs(45),
    )
}

/// Announce the restart, apply it, and hold the command until the daemon is
/// serving again so scripted flows cannot race the model load (#562).
fn restart_daemon_and_wait() {
    println!("{}", restart_notice());
    restart_daemon();
    if wait_for_serving() {
        println!("[logs] daemon serving again");
    } else {
        eprintln!(
            "[logs] tracing set, but the daemon did not confirm serving within 45s; \
             check: systemctl status irlumed"
        );
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
        // Both given: an already-valid --since value passes through untouched
        // AND -f is appended, still no -b.
        let argv = build_view_argv(&opts(&["--since", "10 min ago", "-f"])).unwrap();
        assert!(argv.windows(2).any(|w| w == ["--since", "10 min ago"]));
        assert_eq!(argv.last().unwrap(), "-f");
        assert!(!argv.contains(&"-b".to_string()));
    }

    // ---- #561: normalize the common relative --since forms ----

    /// Bare relative forms a user actually types become the systemd-accepted
    /// "<n> <unit> ago" shape; abbreviations expand to units journalctl
    /// documents.
    #[test]
    fn since_normalizes_bare_relative_forms() {
        assert_eq!(normalize_since("2 min"), "2 min ago");
        assert_eq!(normalize_since("5m"), "5 min ago");
        assert_eq!(normalize_since("90s"), "90 sec ago");
        assert_eq!(normalize_since("2min"), "2 min ago");
        assert_eq!(normalize_since("1h"), "1 hr ago");
        assert_eq!(normalize_since("3 hours"), "3 hours ago");
        assert_eq!(normalize_since("2 days"), "2 days ago");
        assert_eq!(normalize_since("  10  min  "), "10 min ago");
    }

    /// Anything journalctl already accepts passes through byte-for-byte:
    /// "... ago" forms, negative offsets, absolute timestamps, and words like
    /// yesterday; also multi-term values and garbage, which stay journalctl's
    /// to judge (with our failure hint behind them).
    #[test]
    fn since_passes_through_already_valid_forms() {
        for untouched in [
            "10 min ago",
            "-90s",
            "-2min",
            "2026-08-27 12:00",
            "yesterday",
            "now",
            "2 min 30 sec",
            "in 5 minutes",
            "",
        ] {
            assert_eq!(
                normalize_since(untouched),
                untouched,
                "value: {untouched:?}"
            );
        }
    }

    #[test]
    fn build_view_argv_feeds_the_normalized_value_to_journalctl() {
        let argv = build_view_argv(&opts(&["--since", "5m"])).unwrap();
        assert!(argv.windows(2).any(|w| w == ["--since", "5 min ago"]));
    }

    /// The failure hint exists exactly when a --since window was given, and
    /// it names the value journalctl actually saw (the normalized one).
    #[test]
    fn the_failure_hint_gates_on_a_since_window_and_names_its_value() {
        let with_since = ["journalctl", "--no-pager", "--since", "5 min ago"]
            .map(String::from)
            .to_vec();
        let hint = failure_hint(&with_since).expect("a window was given");
        assert!(hint.contains("'5 min ago'"), "names the value: {hint}");
        let without_since = [
            "journalctl".to_string(),
            "--no-pager".to_string(),
            "-b".to_string(),
        ];
        assert!(
            failure_hint(&without_since).is_none(),
            "no window, no hint: the failure is journalctl's own story"
        );
    }

    /// When journalctl still rejects the value, the hint names the accepted
    /// syntax and carries the exact retry command (#561 acceptance).
    #[test]
    fn the_failure_hint_names_accepted_syntax_and_the_retry_command() {
        let hint = since_hint("nonsense value");
        assert!(
            hint.contains("Accepted"),
            "must say what is accepted: {hint}"
        );
        assert!(
            hint.contains("irlume logs --since"),
            "must carry the exact retry command: {hint}"
        );
        let with_value = since_hint("2 fortnights");
        assert!(
            with_value.contains("'2 fortnights'"),
            "must name the rejected value: {with_value}"
        );
    }

    // ---- #562: the restart is announced before it happens ----

    /// The notice names the restart, the wait, and the serving line that ends
    /// it, so the restart is never a surprise mid-test.
    #[test]
    fn the_restart_notice_names_what_and_how_long() {
        let notice = restart_notice();
        assert!(notice.contains("restarting irlumed"), "{notice}");
        assert!(
            notice.contains("serving on /run/irlume.sock"),
            "the wait's end condition is named: {notice}"
        );
    }

    /// The serving wait stops on the probe's first serving answer...
    #[test]
    fn wait_for_serving_returns_once_the_probe_answers() {
        let mut calls = 0;
        let served = wait_for_serving_with(
            || {
                calls += 1;
                true
            },
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        assert!(served);
        assert_eq!(calls, 1, "the first serving answer stops the wait");
    }

    /// ...and gives up at the deadline when nothing ever answers.
    #[test]
    fn wait_for_serving_times_out_when_nothing_answers() {
        let gave_up = wait_for_serving_with(|| false, std::time::Instant::now());
        assert!(!gave_up);
    }

    /// The acceptance IS the order: the notice prints before the restart
    /// fires, and both toggle paths go through the announcing wrapper. Pinned
    /// against the source (the daemon's startup-glue idiom) because the order
    /// lives in glue no behavioral test can drive without systemd.
    #[test]
    fn the_notice_precedes_the_restart_and_both_toggles_use_it() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/logs.rs"),
        )
        .expect("read own source");
        let production = &src[..src.find("\nmod tests").expect("tests module exists")];
        let flat = production.split_whitespace().collect::<Vec<_>>().join(" ");
        let region_start = flat
            .find("fn restart_daemon_and_wait()")
            .expect("wrapper exists");
        let region = &flat[region_start..];
        let notice_at = region
            .find("println!(\"{}\", restart_notice());")
            .expect("notice printed");
        let restart_at = region.find("restart_daemon();").expect("restart called");
        assert!(
            notice_at < restart_at,
            "the notice must print before the restart fires"
        );
        assert_eq!(
            flat.matches("restart_daemon_and_wait();").count(),
            2,
            "exactly the two toggle paths (on and off) use the announcing wrapper"
        );
    }
}
