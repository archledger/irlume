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
