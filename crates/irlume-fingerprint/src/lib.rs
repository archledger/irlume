//! Fingerprint modality, backed by **fprintd** (the standard Linux fingerprint
//! service). irlume does not talk to the sensor directly; it drives fprintd,
//! which owns libfprint and the device. Verification is performed by
//! `pam_fprintd` in the PAM stack (wired by `irlume fingerprint enable`), so
//! irlume never claims the device and coexists with the desktop greeter's native
//! fingerprint prompt.
//!
//! No async D-Bus stack: we use fprintd's shipped tooling with **absolute paths**
//! (so `$PATH` can't be hijacked for an auth-critical helper):
//!   * `busctl tree net.reactivated.Fprint`            - is a reader present?
//!   * `busctl get-property … Device/0 name`           - friendly device name
//!   * `fprintd-list <user>` / `fprintd-enroll`        - enrolled fingers / enroll
//!
//! Ported from linhello (archledger/linhello, the predecessor project).

use std::path::PathBuf;
use std::process::Command;

const FPRINT_BUS: &str = "net.reactivated.Fprint";
const DEVICE0: &str = "/net/reactivated/Fprint/Device/0";

/// Resolve a tool to an absolute path under the standard system dirs, or `None`.
/// Absolute paths only; never trust `$PATH` for an auth-critical helper.
fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/local/bin"]
        .iter()
        .map(|d| PathBuf::from(d).join(name))
        .find(|p| p.exists())
}

fn busctl() -> Option<PathBuf> {
    tool("busctl")
}

/// True when fprintd's user tooling is installed (so we can enroll/list).
pub fn fprintd_present() -> bool {
    tool("fprintd-verify").is_some() && tool("fprintd-list").is_some()
}

/// True when a fingerprint reader is registered with fprintd right now.
pub fn reader_present() -> bool {
    let Some(busctl) = busctl() else { return false };
    match Command::new(busctl)
        .args(["--system", "tree", FPRINT_BUS])
        .output()
    {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).contains("/net/reactivated/Fprint/Device/")
        }
        _ => false,
    }
}

/// Friendly device name (e.g. "Synaptics Sensors"), if a reader is present.
pub fn device_name() -> Option<String> {
    let busctl = busctl()?;
    let out = Command::new(busctl)
        .args([
            "--system",
            "get-property",
            FPRINT_BUS,
            DEVICE0,
            "net.reactivated.Fprint.Device",
            "name",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // Output looks like: `s "Synaptics Sensors"`
    let s = String::from_utf8_lossy(&out.stdout);
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}

/// Usable for auth at all: tooling installed AND a reader present. (Per-user
/// enrollment is checked via [`has_enrollment`].)
pub fn available() -> bool {
    fprintd_present() && reader_present()
}

/// List the fingers `user` has enrolled with fprintd (empty when none/unavailable).
pub fn enrolled_fingers(user: &str) -> Vec<String> {
    let Some(list) = tool("fprintd-list") else {
        return Vec::new();
    };
    let Ok(out) = Command::new(list).arg(user).output() else {
        return Vec::new();
    };
    parse_enrolled_lines(&String::from_utf8_lossy(&out.stdout))
}

/// True when the reader is CLAIMED by a stale fprintd session (a crashed or
/// aborted enrollment holds the device open; `pam_fprintd` then fails silently
/// and the finger prompt never appears; observed live 2026-07-01). Detection:
/// `fprintd-list` must claim the device, and a stuck claim surfaces as
/// "already open" / "failed to claim" in its output. The cure is restarting
/// fprintd, which releases the claim.
pub fn reader_stuck(user: &str) -> bool {
    let Some(list) = tool("fprintd-list") else {
        return false;
    };
    let Ok(out) = Command::new(list).arg(user).output() else {
        return false;
    };
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    all.contains("already open") || all.contains("failed to claim")
}

/// Parse the ` - #N: <finger>` enrolled lines from `fprintd-list`, de-duplicated
/// (fprintd may list the same reader under Device/0 and Device/1).
fn parse_enrolled_lines(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in text.lines() {
        let l = l.trim();
        if let Some(slot) = l
            .strip_prefix('-')
            .map(str::trim)
            .filter(|r| r.starts_with('#'))
            .and_then(|r| r.split(':').nth(1))
            .map(|name| name.trim().to_string())
        {
            if !out.contains(&slot) {
                out.push(slot);
            }
        }
    }
    out
}

/// True when `user` has at least one enrolled finger.
pub fn has_enrollment(user: &str) -> bool {
    !enrolled_fingers(user).is_empty()
}

/// The ten fprintd finger slots, in offer order.
pub const FINGERS: [&str; 10] = [
    "right-index-finger",
    "left-index-finger",
    "right-thumb",
    "left-thumb",
    "right-middle-finger",
    "left-middle-finger",
    "right-ring-finger",
    "left-ring-finger",
    "right-little-finger",
    "left-little-finger",
];

/// The first finger slot `user` has NOT enrolled, or `None` when all ten are taken.
pub fn free_finger(user: &str) -> Option<&'static str> {
    first_free(&enrolled_fingers(user))
}

fn first_free(taken: &[String]) -> Option<&'static str> {
    FINGERS
        .iter()
        .copied()
        .find(|f| !taken.iter().any(|t| t == f))
}

/// Outcome of an enrollment attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    Enrolled,
    /// fprintd refused: this finger is already enrolled (`enroll-duplicate`).
    Duplicate,
    Failed(String),
}

/// Run `fprintd-enroll -f <finger>` for `user`, streaming progress lines live so
/// the user sees each "place / lift finger" step, while capturing them to
/// classify the result.
pub fn enroll_finger(user: &str, finger: &str) -> EnrollOutcome {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let Some(enroll) = tool("fprintd-enroll") else {
        return EnrollOutcome::Failed("fprintd-enroll not installed".into());
    };
    let mut child = match Command::new(enroll)
        .args(["-f", finger, user])
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return EnrollOutcome::Failed(format!("spawn fprintd-enroll: {e}")),
    };
    let mut captured = String::new();
    if let Some(out) = child.stdout.take() {
        for line in BufReader::new(out).lines().map_while(std::io::Result::ok) {
            println!("{line}"); // live feedback
            captured.push_str(&line);
            captured.push('\n');
        }
    }
    let ok = child.wait().map(|s| s.success()).unwrap_or(false);
    if captured.contains("enroll-duplicate") {
        EnrollOutcome::Duplicate
    } else if ok {
        EnrollOutcome::Enrolled
    } else {
        EnrollOutcome::Failed("enrollment did not complete".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolled_line_parser() {
        let sample = "Fingerprints for user x on Synaptics (press):\n - #0: right-index-finger\n - #1: left-index-finger\n";
        assert_eq!(
            parse_enrolled_lines(sample),
            vec!["right-index-finger", "left-index-finger"]
        );
        assert!(parse_enrolled_lines("User x has no fingers enrolled for Synaptics.").is_empty());
    }

    #[test]
    fn enrolled_dedups_across_duplicate_device_sections() {
        let sample = "Using device /net/reactivated/Fprint/Device/1\n - #0: left-index-finger\n - #1: right-index-finger\n\
            Using device /net/reactivated/Fprint/Device/0\n - #0: left-index-finger\n - #1: right-index-finger\n";
        assert_eq!(
            parse_enrolled_lines(sample),
            vec!["left-index-finger", "right-index-finger"]
        );
    }

    #[test]
    fn first_free_picks_next_unused_slot() {
        assert_eq!(first_free(&[]), Some("right-index-finger"));
        assert_eq!(
            first_free(&["right-index-finger".to_string()]),
            Some("left-index-finger")
        );
        let all: Vec<String> = FINGERS.iter().map(|s| s.to_string()).collect();
        assert_eq!(first_free(&all), None);
    }
}
