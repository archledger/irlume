// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Structured results for `doctor`, so one pass produces both the human report
//! and the machine one.
//!
//! `doctor` is instrumented rather than restructured: every existing `println!`
//! stays exactly where it was and is recorded alongside. That is deliberate. A
//! rewrite could have produced tidier code and a differently-worded report, and
//! the report is something people paste into bug threads. Recording next to the
//! print also means the two outputs cannot drift, because there is only one pass
//! over the machine's state. Where a detail would name the account doctor
//! checked or give a camera device path, the machine report reads "this
//! account", the camera's USB identity or `<camera node>` instead
//! (`Report::account`, `ir_node_access_rows` in main.rs and
//! `Report::check_detail`); the human lines keep the name and the paths.

use serde::Serialize;

/// What `doctor` is producing on this run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Print the human report.
    Human,
    /// Print nothing; collect results for the machine document.
    Collect,
}

/// The outcome of one check.
///
/// `Unknown` is not a synonym for `Fail`: it means the check could not be
/// carried out, usually because the daemon was unreachable, and a consumer
/// should say so rather than report a problem the machine may not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Pass,
    Warn,
    Fail,
    Unknown,
    /// Neither good nor bad: a fact worth reporting, such as which platform
    /// family this is.
    Info,
}

#[derive(Serialize)]
pub struct Check {
    /// Stable identifier. PUBLIC API from the moment it ships: a consumer keys
    /// its own logic and its own translations off this string, so an id is
    /// never renamed and never reused for a different meaning. Adding one is
    /// cheap; changing what one means is not.
    pub id: &'static str,
    pub state: State,
    /// Human-readable elaboration, English, not stable and not for matching.
    /// Present so a support report can show something useful; a consumer that
    /// branches on this text has reintroduced the problem this API removes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Collects check results during a `doctor` run.
pub struct Report {
    mode: Mode,
    checks: Vec<Check>,
}

impl Report {
    pub fn new(mode: Mode) -> Self {
        Report {
            mode,
            checks: Vec::new(),
        }
    }

    pub fn human(&self) -> bool {
        self.mode == Mode::Human
    }

    /// Record one check. Call this next to the line that reports it, so the two
    /// cannot disagree.
    pub fn check(&mut self, id: &'static str, state: State) {
        self.checks.push(Check {
            id,
            state,
            detail: None,
        });
    }

    /// Record one check with elaboration. The detail is machine output
    /// (`doctor --json`), which names no camera device path: each path in it
    /// that starts with `/dev/video` or `/dev/v4l/` reads `<camera node>`
    /// (`without_camera_nodes`). The human report prints its own lines
    /// through `dout!` and keeps the paths.
    pub fn check_detail(&mut self, id: &'static str, state: State, detail: impl Into<String>) {
        self.checks.push(Check {
            id,
            state,
            detail: Some(without_camera_nodes(&detail.into())),
        });
    }

    /// How a detail names the account doctor reports on. The human report
    /// gives its name, since `--user` can make it an account other than the
    /// caller's; `doctor --json` reads "this account" for it
    /// (docs/MACHINE-API.md, "Security and privacy").
    pub fn account<'a>(&self, user: &'a str) -> &'a str {
        if self.human() {
            user
        } else {
            THIS_ACCOUNT
        }
    }

    pub fn into_checks(self) -> Vec<Check> {
        self.checks
    }

    /// How the run ended: warnings and failures, the two states a script or a
    /// human closing thought should act on. Pass, Info and Unknown are not
    /// counted; they are facts, not findings.
    pub fn summary(&self) -> Summary {
        let mut summary = Summary::default();
        for check in &self.checks {
            match check.state {
                State::Warn => summary.warnings += 1,
                State::Fail => summary.failures += 1,
                State::Pass | State::Info | State::Unknown => {}
            }
        }
        summary
    }
}

/// The closing count of a doctor run.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct Summary {
    pub warnings: usize,
    pub failures: usize,
}

impl Summary {
    /// Scriptable verdict for `doctor --check`: 0 clean, 1 warnings only,
    /// 2 any failure. Failure outranks warning so a script that only checks
    /// for nonzero still behaves correctly.
    pub fn check_exit_code(self) -> u8 {
        if self.failures > 0 {
            2
        } else if self.warnings > 0 {
            1
        } else {
            0
        }
    }
}

/// How `doctor --json` names the account it reports on ([`Report::account`]).
const THIS_ACCOUNT: &str = "this account";

/// What a camera device path reads as in a check's `detail`.
const CAMERA_NODE: &str = "<camera node>";

/// `text` with every camera device path replaced by [`CAMERA_NODE`]
/// (docs/MACHINE-API.md, "Security and privacy"): a path that starts with
/// `/dev/video` (a node such as `/dev/video2`, or a link such as
/// `/dev/video-ir`) or `/dev/v4l/` (a by-id or by-path link), up to the next
/// ASCII whitespace, backtick, quote, comma, semicolon, `)`, `]`, `}` or `>`,
/// keeping a `:` or `.` that ends it. Only ASCII whitespace ends a path,
/// since a by-id name keeps any non-ASCII text of the camera's USB strings.
/// A configured path that only contains `/dev/video` or `/dev/v4l/`
/// (`/home/u/dev/video-tools/...`) is rewritten too: the replacement errs
/// toward hiding.
fn without_camera_nodes(text: &str) -> String {
    const NODE: &str = "/dev/video";
    const LINK: &str = "/dev/v4l/";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let (at, prefix) = match (rest.find(NODE), rest.find(LINK)) {
            (None, None) => break,
            (Some(node), None) => (node, NODE),
            (None, Some(link)) => (link, LINK),
            (Some(node), Some(link)) => {
                if node < link {
                    (node, NODE)
                } else {
                    (link, LINK)
                }
            }
        };
        out.push_str(&rest[..at]);
        out.push_str(CAMERA_NODE);
        let path = &rest[at..];
        // Every position below is an ASCII one: `find` returns the start of
        // an ASCII needle or of an ASCII delimiter, and the trailing `:` or
        // `.` is a single byte. Neither needle holds a delimiter, so each
        // pass moves past a whole needle.
        let mut end = path
            .find(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, '`' | '\'' | '"' | ',' | ';' | ')' | ']' | '}' | '>')
            })
            .unwrap_or(path.len());
        // A by-path name holds `:` and `.` inside it
        // (`pci-0000:00:14.0-usb-0:8:1.0-video-index0`), so only a trailing
        // one is punctuation of the sentence.
        while end > prefix.len() && matches!(path.as_bytes()[end - 1], b':' | b'.') {
            end -= 1;
        }
        rest = &path[end..];
    }
    out.push_str(rest);
    out
}

/// Print a `doctor` line, unless this run is collecting for the machine report.
#[macro_export]
macro_rules! dout {
    ($report:expr, $($arg:tt)*) => {
        if $report.human() {
            println!($($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_counts_warnings_and_failures_but_not_info_or_pass() {
        let mut r = Report::new(Mode::Human);
        r.check("a", State::Pass);
        r.check("b", State::Info);
        r.check("c", State::Warn);
        r.check_detail("d", State::Fail, "boom");
        let s = r.summary();
        assert_eq!(s.warnings, 1);
        assert_eq!(s.failures, 1);
    }

    #[test]
    fn a_detail_names_no_camera_node() {
        let mut r = Report::new(Mode::Collect);
        r.check_detail(
            "a",
            State::Unknown,
            "/dev/video2: camera busy; `sudo fuser -v /dev/video2` will name it; \
             /dev/video10 and /dev/video* too",
        );
        r.check_detail("b", State::Pass, "5986:1141: closed to everyone but root");
        r.check_detail(
            "c",
            State::Unknown,
            "/dev/v4l/by-path/pci-0000:00:14.0-usb-0:8:1.0-video-index0: camera busy; \
             `sudo fuser -v /dev/v4l/by-id/usb-Acme_Cam_0001-video-index0` names the holder.",
        );
        r.check_detail(
            "d",
            State::Unknown,
            "could not resolve v2 capture status (/dev/v4l/by-id/usb-Acme-video-index0, \
             /dev/video4); authentication stays sequential",
        );
        r.check_detail(
            "e",
            State::Unknown,
            "/dev/v4l/by-id/usb-Acme\u{3000}Cam_SN42-video-index0: camera busy",
        );
        r.check_detail(
            "f",
            State::Unknown,
            "/dev/video-ir: camera busy; the pin [/dev/video2] is kept",
        );
        let checks = r.into_checks();
        assert_eq!(
            checks[0].detail.as_deref(),
            Some(
                "<camera node>: camera busy; `sudo fuser -v <camera node>` will name it; \
                 <camera node> and <camera node> too"
            )
        );
        assert_eq!(
            checks[1].detail.as_deref(),
            Some("5986:1141: closed to everyone but root")
        );
        assert_eq!(
            checks[2].detail.as_deref(),
            Some("<camera node>: camera busy; `sudo fuser -v <camera node>` names the holder.")
        );
        assert_eq!(
            checks[3].detail.as_deref(),
            Some(
                "could not resolve v2 capture status (<camera node>, <camera node>); \
                 authentication stays sequential"
            )
        );
        assert_eq!(
            checks[4].detail.as_deref(),
            Some("<camera node>: camera busy")
        );
        assert_eq!(
            checks[5].detail.as_deref(),
            Some("<camera node>: camera busy; the pin [<camera node>] is kept")
        );
    }

    #[test]
    fn only_the_human_report_names_the_account() {
        assert_eq!(Report::new(Mode::Human).account("alice"), "alice");
        assert_eq!(Report::new(Mode::Collect).account("alice"), "this account");
    }

    #[test]
    fn check_exit_codes_separate_clean_warning_and_failure() {
        assert_eq!(Summary::default().check_exit_code(), 0);
        assert_eq!(
            Summary {
                warnings: 2,
                failures: 0
            }
            .check_exit_code(),
            1
        );
        assert_eq!(
            Summary {
                warnings: 0,
                failures: 1
            }
            .check_exit_code(),
            2
        );
        assert_eq!(
            Summary {
                warnings: 3,
                failures: 2
            }
            .check_exit_code(),
            2
        );
    }
}
