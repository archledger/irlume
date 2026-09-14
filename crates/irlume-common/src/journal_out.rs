// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Leveled journal output, shared by the daemon and CLI.
//!
//! Every daemon line historically went to stderr as one unprioritized
//! journal entry, so `journalctl -p err` could not find a real failure and
//! warnings were only recognizable by their text. This module gives each
//! line a syslog priority using the documented `<N>` stream-prefix protocol
//! journald parses on service output, verified empirically on systemd 261:
//! a leading `<3>` sets PRIORITY=3 and is stripped from MESSAGE.
//!
//! The prefix is only written when stderr is the journal stream systemd
//! connected for us (`JOURNAL_STREAM=<dev>:<ino>` matches `fstat` of fd 2,
//! the contract systemd documents for exactly this detection). In a
//! terminal or a container without journald the message stays byte-identical
//! to the historical output.
//!
//! One call is one journal line: messages never contain inner newlines, and
//! the prefix and text are written in a single `write_all` so concurrent
//! emitters cannot interleave a priority prefix with another line.

use std::fmt;
use std::io::Write as _;
use std::sync::OnceLock;

pub enum Level {
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl Level {
    /// The syslog priority number the journal prefix carries.
    pub fn syslog_number(self) -> u8 {
        match self {
            Level::Error => 3,
            Level::Warning => 4,
            Level::Notice => 5,
            Level::Info => 6,
            Level::Debug => 7,
        }
    }
}

/// Format one line for the given journal mode. Journal mode prepends the
/// `<N>` priority prefix; terminal mode returns the message unchanged.
/// Both append exactly one trailing newline, and an inner newline can never
/// split the result into a second unprefixed journal line.
pub fn format_line(level: Level, journal_mode: bool, message: &str) -> String {
    let mut out = String::with_capacity(message.len() + 5);
    if journal_mode {
        out.push_str(&format!("<{}>", level.syslog_number()));
    }
    out.push_str(message);
    if out.contains('\n') {
        out = out.replace('\n', " ");
    }
    out.push('\n');
    out
}

/// Pure form of the `JOURNAL_STREAM` comparison: `env` is the raw
/// `<dev>:<ino>` value (when present) and `dev`/`ino` are the `fstat`
/// fields of the stream we would write to.
pub fn journal_stream_matches(env: Option<&str>, dev: u64, ino: u64) -> bool {
    let Some(env) = env else { return false };
    let Some((env_dev, env_ino)) = env.split_once(':') else {
        return false;
    };
    if env_dev.is_empty() || env_ino.is_empty() {
        return false;
    }
    match (env_dev.parse::<u64>(), env_ino.parse::<u64>()) {
        (Ok(d), Ok(i)) => d == dev && i == ino,
        _ => false,
    }
}

pub fn stderr_is_journal() -> bool {
    static IS_JOURNAL: OnceLock<bool> = OnceLock::new();
    *IS_JOURNAL.get_or_init(|| {
        let env = std::env::var("JOURNAL_STREAM").ok();
        let meta = std::fs::metadata("/proc/self/fd/2");
        let (dev, ino) = match meta {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                (m.dev(), m.ino())
            }
            Err(_) => return false,
        };
        journal_stream_matches(env.as_deref(), dev, ino)
    })
}

/// Emit one leveled line to stderr, journal-prefixed when applicable.
pub fn line(level: Level, args: fmt::Arguments<'_>) {
    let out = format_line(level, stderr_is_journal(), &args.to_string());
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(out.as_bytes());
}

#[macro_export]
macro_rules! jout_err {
    ($($arg:tt)*) => {
        $crate::journal_out::line($crate::journal_out::Level::Error, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! jout_warn {
    ($($arg:tt)*) => {
        $crate::journal_out::line($crate::journal_out::Level::Warning, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! jout_notice {
    ($($arg:tt)*) => {
        $crate::journal_out::line($crate::journal_out::Level::Notice, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! jout_info {
    ($($arg:tt)*) => {
        $crate::journal_out::line($crate::journal_out::Level::Info, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! jout_debug {
    ($($arg:tt)*) => {
        $crate::journal_out::line($crate::journal_out::Level::Debug, format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_numbers_match_syslog_priorities() {
        assert_eq!(Level::Error.syslog_number(), 3);
        assert_eq!(Level::Warning.syslog_number(), 4);
        assert_eq!(Level::Notice.syslog_number(), 5);
        assert_eq!(Level::Info.syslog_number(), 6);
        assert_eq!(Level::Debug.syslog_number(), 7);
    }

    #[test]
    fn journal_mode_prepends_prefix_and_one_newline() {
        let out = format_line(Level::Error, true, "irlumed: cannot bind: boom");
        assert_eq!(out, "<3>irlumed: cannot bind: boom\n");
    }

    #[test]
    fn terminal_mode_is_byte_identical_to_legacy_output() {
        let out = format_line(Level::Warning, false, "irlumed: WARNING: socket mode");
        assert_eq!(out, "irlumed: WARNING: socket mode\n");
    }

    #[test]
    fn every_level_gets_its_own_prefix_number() {
        let cases = [
            (Level::Error, "<3>"),
            (Level::Warning, "<4>"),
            (Level::Notice, "<5>"),
            (Level::Info, "<6>"),
            (Level::Debug, "<7>"),
        ];
        for (level, prefix) in cases {
            assert!(format_line(level, true, "x").starts_with(prefix));
        }
    }

    #[test]
    fn inner_newlines_cannot_split_a_line() {
        let out = format_line(Level::Error, true, "two\nlines");
        assert_eq!(out, "<3>two lines\n");
    }

    #[test]
    fn journal_stream_env_must_match_both_stat_fields() {
        assert!(journal_stream_matches(Some("10:2089833"), 10, 2_089_833));
        assert!(!journal_stream_matches(Some("10:2089833"), 10, 9));
        assert!(!journal_stream_matches(Some("10:2089833"), 11, 2_089_833));
    }

    #[test]
    fn missing_or_malformed_journal_stream_env_means_terminal() {
        assert!(!journal_stream_matches(None, 10, 2_089_833));
        assert!(!journal_stream_matches(Some(""), 10, 2_089_833));
        assert!(!journal_stream_matches(Some("garbage"), 10, 2_089_833));
        assert!(!journal_stream_matches(Some("10"), 10, 2_089_833));
        assert!(!journal_stream_matches(Some("10:20:30"), 10, 20));
    }

    #[test]
    fn large_device_and_inode_values_parse() {
        assert!(journal_stream_matches(
            Some("18446744073709551615:42"),
            u64::MAX,
            42
        ));
        assert!(!journal_stream_matches(
            Some("18446744073709551616:42"),
            0,
            42
        ));
    }
}
