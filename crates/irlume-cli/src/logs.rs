//! `irlume logs` — one journal view for diagnosing auth problems, and the
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

fn view(opts: &[String]) -> ExitCode {
    let mut cmd = Command::new("journalctl");
    cmd.args(["--no-pager", "-g", PATTERN]);
    let mut follow = false;
    let mut since = false;
    let mut it = opts.iter().map(String::as_str);
    while let Some(o) = it.next() {
        match o {
            "-f" | "--follow" => follow = true,
            "--since" => match it.next() {
                Some(v) => {
                    since = true;
                    cmd.args(["--since", v]);
                }
                None => {
                    eprintln!("[logs] --since needs a value, e.g. --since \"10 min ago\"");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("[logs] unknown option '{other}' (usage: irlume logs [-f] [--since T] [debug on|off])");
                return ExitCode::FAILURE;
            }
        }
    }
    if follow {
        cmd.arg("-f");
    } else if !since {
        cmd.arg("-b");
    } // default: this boot
    if !is_root() {
        eprintln!("[logs] note: without root (or the systemd-journal group) the system journal may be hidden — re-run with sudo if this looks empty");
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
                "# irlume: created by `irlume logs debug on` — remove with `irlume logs debug off`\n[Service]\nEnvironment=IRLUME_LOG=debug\n"))
            {
                eprintln!("[logs] could not write {DROPIN}: {e}");
                return ExitCode::FAILURE;
            }
            restart_daemon();
            println!("[logs] tracing ON — the daemon now logs per-stage pipeline lines (capture/detect/liveness cues/match scores; numbers only, never frames or embeddings).");
            println!("[logs] ⚠ while on, DENIED attempts log their score vs threshold — feedback a journal-reader could use to tune a spoof. Diagnose, then turn it off:");
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

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
