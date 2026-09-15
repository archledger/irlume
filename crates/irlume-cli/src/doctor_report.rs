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
//! over the machine's state.

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
#[derive(Clone, Copy, Serialize)]
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

    /// Record one check with elaboration.
    pub fn check_detail(&mut self, id: &'static str, state: State, detail: impl Into<String>) {
        self.checks.push(Check {
            id,
            state,
            detail: Some(detail.into()),
        });
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
