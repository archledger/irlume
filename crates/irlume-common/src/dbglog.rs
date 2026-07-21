// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Opt-in diagnostic tracing, shared by the daemon and CLI.
//!
//! `IRLUME_LOG=debug` turns on per-stage pipeline traces (capture timings,
//! detection results, every liveness cue with its threshold verdict, match
//! scores vs thresholds) so a failed (or suspiciously slow) auth can be
//! diagnosed from the journal alone. Traces carry NUMBERS ONLY: never frames,
//! embeddings, or secrets. Off by default; toggle on a running system with
//! `sudo irlume logs debug on` (writes a systemd drop-in and restarts irlumed).

use std::sync::OnceLock;

/// True when diagnostic tracing is enabled for this process.
pub fn on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("IRLUME_LOG").is_ok_and(|v| matches!(v.as_str(), "debug" | "trace" | "1"))
    })
}

/// `dlog!("capture rgb {}ms", ms)`: one stderr line, only under IRLUME_LOG.
/// stderr is journald for the daemon and the terminal for CLI tools.
#[macro_export]
macro_rules! dlog {
    ($($t:tt)*) => {
        if $crate::dbglog::on() { eprintln!("irlume[debug]: {}", format_args!($($t)*)); }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // on() caches its answer in a OnceLock for the process lifetime, so each
    // IRLUME_LOG value gets its own re-exec'd child process; asserting in-process
    // would only ever see whatever value froze first.
    #[test]
    fn irlume_log_values_toggle_tracing_per_process() {
        if let Ok(expect) = std::env::var("IRLUME_TEST_DBGLOG_EXPECT") {
            assert_eq!(
                on(),
                expect == "1",
                "IRLUME_LOG={:?}",
                std::env::var("IRLUME_LOG")
            );
            // The answer is frozen after first use, whatever the env does next.
            std::env::set_var("IRLUME_LOG", "debug");
            assert_eq!(on(), expect == "1");
            // The macro must compile and run in both states without output
            // side effects we could crash on.
            crate::dlog!("probe {}", 42);
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let run = |log: Option<&str>, expect: &str| {
            let mut cmd = std::process::Command::new(&exe);
            cmd.args([
                "dbglog::tests::irlume_log_values_toggle_tracing_per_process",
                "--exact",
                "--test-threads=1",
            ])
            .env("IRLUME_TEST_DBGLOG_EXPECT", expect)
            .env_remove("IRLUME_LOG");
            if let Some(v) = log {
                cmd.env("IRLUME_LOG", v);
            }
            let out = cmd.output().unwrap();
            assert!(
                out.status.success(),
                "IRLUME_LOG={log:?} expect={expect}: {}",
                String::from_utf8_lossy(&out.stdout)
            );
        };
        // The three documented enabling values.
        for v in ["debug", "trace", "1"] {
            run(Some(v), "1");
        }
        // Unset, and set to something unrecognized: off.
        run(None, "0");
        run(Some("verbose"), "0");
        run(Some(""), "0");
    }
}
