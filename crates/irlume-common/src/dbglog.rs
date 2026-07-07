//! Opt-in diagnostic tracing, shared by the daemon and CLI.
//!
//! `IRLUME_LOG=debug` turns on per-stage pipeline traces (capture timings,
//! detection results, every liveness cue with its threshold verdict, match
//! scores vs thresholds) so a failed — or suspiciously slow — auth can be
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

/// `dlog!("capture rgb {}ms", ms)` — one stderr line, only under IRLUME_LOG.
/// stderr is journald for the daemon and the terminal for CLI tools.
#[macro_export]
macro_rules! dlog {
    ($($t:tt)*) => {
        if $crate::dbglog::on() { eprintln!("irlume[debug]: {}", format_args!($($t)*)); }
    };
}
