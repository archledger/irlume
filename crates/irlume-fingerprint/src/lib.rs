// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

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
use std::time::Duration;

const FPRINT_BUS: &str = "net.reactivated.Fprint";
const DEVICE0: &str = "/net/reactivated/Fprint/Device/0";

/// Ceiling for one enrollment run. Synaptics-class sensors need 8-12 placements
/// at a few seconds each; a driver that stops consuming finger events otherwise
/// hangs the caller forever (libfprint#795 is exactly that).
const ENROLL_DEADLINE: Duration = Duration::from_secs(120);
/// Ceiling for one verify run (fprintd-verify allows up to 3 placements).
const VERIFY_DEADLINE: Duration = Duration::from_secs(60);

/// Test-only tool-directory override, so the enroll/verify/delete wrappers can
/// run end to end against fake fprintd scripts. `cfg(test)` compiles only into
/// this crate's own test binary: production builds (and every downstream crate)
/// keep the absolute-paths-only resolution with no override surface.
#[cfg(test)]
static TOOL_DIR_OVERRIDE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Resolve a tool to an absolute path under the standard system dirs, or `None`.
/// Absolute paths only; never trust `$PATH` for an auth-critical helper.
fn tool(name: &str) -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = TOOL_DIR_OVERRIDE.lock().unwrap().clone() {
        let p = dir.join(name);
        return p.exists().then_some(p);
    }
    ["/usr/bin", "/bin", "/usr/local/bin"]
        .iter()
        .map(|d| PathBuf::from(d).join(name))
        .find(|p| p.exists())
}

/// Command builder for the fprintd/busctl helpers. `LC_ALL=C` pins the output
/// to the untranslated strings this module parses; fprintd's CLI tools are
/// gettext-localized, so on a non-English locale every phrase match below would
/// silently stop working without it.
fn helper(path: PathBuf) -> Command {
    let mut c = Command::new(path);
    c.env("LC_ALL", "C").env("LANG", "C");
    c
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
    !device_paths().is_empty()
}

/// The D-Bus object paths of every registered reader (`.../Device/N`).
fn device_paths() -> Vec<String> {
    let Some(busctl) = busctl() else {
        return Vec::new();
    };
    let Ok(out) = helper(busctl)
        .args(["--system", "tree", FPRINT_BUS])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let mut paths: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(i) = line.find("/net/reactivated/Fprint/Device/") {
            let p = line[i..].trim().to_string();
            if p != "/net/reactivated/Fprint/Device" && !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    paths
}

/// Friendly name of the reader at `path` (e.g. "Synaptics Sensors").
fn device_name_at(path: &str) -> Option<String> {
    let busctl = busctl()?;
    let out = helper(busctl)
        .args([
            "--system",
            "get-property",
            FPRINT_BUS,
            path,
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

/// Friendly device name of the first reader, if one is present.
pub fn device_name() -> Option<String> {
    // Prefer the enumerated paths; fall back to the fixed Device/0 the old code
    // used, for daemons that answer get-property but not tree introspection.
    device_paths()
        .first()
        .and_then(|p| device_name_at(p))
        .or_else(|| device_name_at(DEVICE0))
}

/// Friendly names of ALL registered readers (multi-reader docks exist; naming
/// only Device/0 mislabels the second sensor).
pub fn device_names() -> Vec<String> {
    device_paths()
        .iter()
        .filter_map(|p| device_name_at(p))
        .collect()
}

/// The systemd unit owning the fprintd bus name right now, or `None` when the
/// name has no owner (service not running). Anything other than
/// `fprintd.service` means a vendor driver stack (open-fprintd/python-validity)
/// is answering, with its own failure modes; worth surfacing in diagnostics.
pub fn bus_owner_unit() -> Option<String> {
    let busctl = busctl()?;
    let out = helper(busctl)
        .args(["--system", "status", FPRINT_BUS])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Unit=").map(|u| u.trim().to_string()))
}

/// Usable for auth at all: tooling installed AND a reader present. (Per-user
/// enrollment is checked via [`has_enrollment`].)
pub fn available() -> bool {
    fprintd_present() && reader_present()
}

/// What `fprintd-list` actually said, beyond "a list of fingers". `fprintd-list`
/// exits 0 even with no reader ("No devices available"), and a claim or polkit
/// failure otherwise reads as "no fingers enrolled" — the wrong advice follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListOutcome {
    Fingers(Vec<String>),
    /// fprintd answered but has no reader ("No devices available").
    NoDevice,
    /// The listing itself failed (stale claim, polkit refusal, daemon error).
    Error(String),
}

/// List the fingers `user` has enrolled with fprintd, distinguishing "none
/// enrolled" from "the listing failed".
pub fn list_fingers(user: &str) -> ListOutcome {
    let Some(list) = tool("fprintd-list") else {
        return ListOutcome::Error("fprintd-list not installed".into());
    };
    let out = match helper(list).arg(user).output() {
        Ok(o) => o,
        Err(e) => return ListOutcome::Error(format!("could not run fprintd-list: {e}")),
    };
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    classify_list(out.status.success(), &stdout, &stderr)
}

fn classify_list(exit_ok: bool, stdout: &str, stderr: &str) -> ListOutcome {
    let all = format!("{stdout}{stderr}");
    if all.contains("No devices available") {
        return ListOutcome::NoDevice;
    }
    if claim_error(&all) {
        return ListOutcome::Error(
            "the reader is claimed by another/stale fprintd session; \
             fix: sudo systemctl restart fprintd"
                .into(),
        );
    }
    if all.contains("PermissionDenied") || all.contains("Not Authorized") {
        return ListOutcome::Error(
            "fprintd refused the listing (polkit); run from a desktop session or with sudo".into(),
        );
    }
    if !exit_ok {
        let last = stderr.lines().last().unwrap_or("unknown error").trim();
        return ListOutcome::Error(format!("fprintd-list failed: {last}"));
    }
    ListOutcome::Fingers(parse_enrolled_lines(stdout))
}

/// List the fingers `user` has enrolled with fprintd (empty when none/unavailable).
pub fn enrolled_fingers(user: &str) -> Vec<String> {
    match list_fingers(user) {
        ListOutcome::Fingers(v) => v,
        _ => Vec::new(),
    }
}

/// A claim-shaped failure, in any of the forms fprintd emits: the untranslated
/// phrases (`LC_ALL=C`) and the D-Bus error names, which are never translated.
fn claim_error(text: &str) -> bool {
    text.contains("already open")
        || text.contains("failed to claim")
        || text.contains("Device was already claimed")
        || text.contains("Error.AlreadyInUse")
        || text.contains("Error.ClaimDevice")
}

/// True when the reader is CLAIMED by a stale fprintd session (a crashed or
/// aborted enrollment holds the device open; `pam_fprintd` then fails silently
/// and the finger prompt never appears; observed live 2026-07-01). The cure is
/// restarting fprintd, which releases the claim. This is also the field's
/// single biggest post-suspend failure (fprintd#192/#216: the device stays
/// claimed across suspend/resume until the daemon restarts).
pub fn reader_stuck(user: &str) -> bool {
    let Some(list) = tool("fprintd-list") else {
        return false;
    };
    let Ok(out) = helper(list).arg(user).output() else {
        return false;
    };
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    claim_error(&all)
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

/// Result of a streamed child run: combined output, and the exit status
/// (`None` = deadline hit, child killed).
struct StreamedRun {
    output: String,
    status: Option<std::process::ExitStatus>,
}

/// Spawn `cmd`, stream its stdout/stderr live (stdout to ours, stderr to ours)
/// while capturing both, and enforce `deadline`: a child that stops making
/// progress is killed instead of hanging the caller forever (libfprint#795 is
/// an enroll that never returns; a stale claim can block the same way).
fn run_streamed(mut cmd: Command, deadline: Duration) -> Result<StreamedRun, String> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::{Arc, Mutex};

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    let captured = Arc::new(Mutex::new(String::new()));
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        let cap = Arc::clone(&captured);
        readers.push(std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(std::io::Result::ok) {
                println!("{line}"); // live feedback for the placement prompts
                let mut c = cap.lock().unwrap();
                c.push_str(&line);
                c.push('\n');
            }
        }));
    }
    if let Some(err) = child.stderr.take() {
        let cap = Arc::clone(&captured);
        readers.push(std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(std::io::Result::ok) {
                eprintln!("{line}");
                let mut c = cap.lock().unwrap();
                c.push_str(&line);
                c.push('\n');
            }
        }));
    }
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if started.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("wait: {e}")),
        }
    };
    for r in readers {
        let _ = r.join();
    }
    let output = captured.lock().unwrap().clone();
    Ok(StreamedRun { output, status })
}

/// Run `fprintd-enroll -f <finger>` for `user`, streaming progress lines live so
/// the user sees each "place / lift finger" step, while capturing stdout AND
/// stderr to classify the result (the D-Bus errors land on stderr; dropping it
/// turned every distinct failure into "enrollment did not complete").
pub fn enroll_finger(user: &str, finger: &str) -> EnrollOutcome {
    let Some(enroll) = tool("fprintd-enroll") else {
        return EnrollOutcome::Failed("fprintd-enroll not installed".into());
    };
    let mut cmd = helper(enroll);
    cmd.args(["-f", finger, user]);
    let run = match run_streamed(cmd, ENROLL_DEADLINE) {
        Ok(r) => r,
        Err(e) => return EnrollOutcome::Failed(format!("fprintd-enroll: {e}")),
    };
    classify_enroll(&run)
}

/// Map an enroll run to an outcome with an actionable message per failure
/// class. Status vocabulary and error names verified against fprintd 1.94
/// (`Enroll result: %s`, `EnrollStart failed: %s`, `net.reactivated.Fprint.Error.*`).
fn classify_enroll(run: &StreamedRun) -> EnrollOutcome {
    let out = &run.output;
    if out.contains("enroll-duplicate") {
        return EnrollOutcome::Duplicate;
    }
    match run.status {
        None => EnrollOutcome::Failed(format!(
            "no completion from the reader within {}s; the sensor or its claim may be \
             wedged — try: sudo systemctl restart fprintd, then re-run",
            ENROLL_DEADLINE.as_secs()
        )),
        Some(s) if s.success() => EnrollOutcome::Enrolled,
        Some(_) if claim_error(out) => EnrollOutcome::Failed(
            "the reader is claimed by another session (a greeter prompt, GNOME Settings, \
             or a stale claim); close it or run: sudo systemctl restart fprintd"
                .into(),
        ),
        Some(_) if out.contains("enroll-data-full") => EnrollOutcome::Failed(
            "the reader's print storage is full; clear this user's prints \
             (irlume fingerprint reset) and retry"
                .into(),
        ),
        Some(_) if out.contains("enroll-disconnected") => EnrollOutcome::Failed(
            "the reader disconnected mid-enrollment (USB reset or driver fault); re-run, \
             and if it repeats: sudo systemctl restart fprintd"
                .into(),
        ),
        Some(_) if out.contains("PermissionDenied") || out.contains("Not Authorized") => {
            EnrollOutcome::Failed(
                "fprintd refused (polkit); run from a desktop session with a polkit agent, \
                 or with sudo"
                    .into(),
            )
        }
        Some(_) if out.contains("No devices available") || out.contains("NoSuchDevice") => {
            EnrollOutcome::Failed("no fingerprint reader is available to fprintd".into())
        }
        Some(_) => {
            let last = out
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("unknown error")
                .trim();
            EnrollOutcome::Failed(format!("enrollment did not complete: {last}"))
        }
    }
}

/// Outcome of a one-shot verification round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Match,
    NoMatch,
    Error(String),
}

/// Run one interactive `fprintd-verify` round for `user` (up to fprintd's three
/// placements). Used right after enrollment: "enroll succeeds, verify never
/// matches" is a top field complaint (libfprint#401), and catching it here
/// beats discovering it at the greeter.
pub fn verify_once(user: &str) -> VerifyOutcome {
    let Some(verify) = tool("fprintd-verify") else {
        return VerifyOutcome::Error("fprintd-verify not installed".into());
    };
    let mut cmd = helper(verify);
    cmd.arg(user);
    let run = match run_streamed(cmd, VERIFY_DEADLINE) {
        Ok(r) => r,
        Err(e) => return VerifyOutcome::Error(format!("fprintd-verify: {e}")),
    };
    if run.output.contains("verify-match") {
        return VerifyOutcome::Match;
    }
    match run.status {
        None => VerifyOutcome::Error(format!(
            "no verify result within {}s; try: sudo systemctl restart fprintd",
            VERIFY_DEADLINE.as_secs()
        )),
        Some(_) if run.output.contains("verify-no-match") => VerifyOutcome::NoMatch,
        Some(_) if claim_error(&run.output) => VerifyOutcome::Error(
            "the reader is claimed by another session; close it or run: \
             sudo systemctl restart fprintd"
                .into(),
        ),
        Some(s) if s.success() => VerifyOutcome::Match,
        Some(_) => {
            let last = run
                .output
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("unknown error")
                .trim()
                .to_string();
            VerifyOutcome::Error(last)
        }
    }
}

/// Delete ALL of `user`'s enrolled prints (`fprintd-delete <user>`): the remedy
/// for chip/host template desync, where the sensor's on-chip storage holds
/// prints the host database no longer matches (dual-boot Windows enrollment,
/// OS reinstall, BIOS "clear fingerprints" — libfprint#301, fprintd#126).
pub fn delete_all(user: &str) -> Result<(), String> {
    let Some(del) = tool("fprintd-delete") else {
        return Err("fprintd-delete not installed".into());
    };
    let out = helper(del)
        .arg(user)
        .output()
        .map_err(|e| format!("could not run fprintd-delete: {e}"))?;
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() && !all.contains("PrintsNotDeleted") {
        Ok(())
    } else if all.contains("PermissionDenied") || all.contains("Not Authorized") {
        Err("fprintd refused (polkit); re-run with sudo".into())
    } else {
        let last = all
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("unknown error")
            .trim()
            .to_string();
        Err(last)
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

    fn status_from(code: i32) -> Option<std::process::ExitStatus> {
        use std::os::unix::process::ExitStatusExt;
        // from_raw takes a wait(2) status word: exit code lives in the high byte.
        Some(std::process::ExitStatus::from_raw(code << 8))
    }

    #[test]
    fn claim_errors_match_phrases_and_dbus_names() {
        for s in [
            "failed to claim device: GDBus.Error:net.reactivated.Fprint.Error.AlreadyInUse: x",
            "Device was already claimed",
            "device already open",
            "GDBus.Error:net.reactivated.Fprint.Error.ClaimDevice: could not claim",
        ] {
            assert!(claim_error(s), "should classify as claim error: {s}");
        }
        assert!(!claim_error("Enroll result: enroll-completed"));
    }

    #[test]
    fn list_classification_separates_empty_from_broken() {
        // fprintd-list exits 0 with "No devices available" on a readerless box;
        // that must never read as "no fingers enrolled".
        assert_eq!(
            classify_list(true, "No devices available\n", ""),
            ListOutcome::NoDevice
        );
        assert!(matches!(
            classify_list(
                true,
                "",
                "failed to claim device: net.reactivated.Fprint.Error.AlreadyInUse"
            ),
            ListOutcome::Error(_)
        ));
        assert!(matches!(
            classify_list(false, "", "Not Authorized"),
            ListOutcome::Error(_)
        ));
        assert_eq!(
            classify_list(true, "User x has no fingers enrolled for Synaptics.", ""),
            ListOutcome::Fingers(vec![])
        );
        assert_eq!(
            classify_list(true, " - #0: right-index-finger\n", ""),
            ListOutcome::Fingers(vec!["right-index-finger".into()])
        );
    }

    #[test]
    fn enroll_classification_covers_the_field_failure_classes() {
        let run = |output: &str, status| StreamedRun {
            output: output.into(),
            status,
        };
        // Duplicate wins regardless of exit code.
        assert_eq!(
            classify_enroll(&run("Enroll result: enroll-duplicate", status_from(1))),
            EnrollOutcome::Duplicate
        );
        assert_eq!(
            classify_enroll(&run("Enroll result: enroll-completed", status_from(0))),
            EnrollOutcome::Enrolled
        );
        // Deadline hit → wedged-sensor message naming the fprintd restart.
        let EnrollOutcome::Failed(msg) =
            classify_enroll(&run("Enrolling right-index-finger", None))
        else {
            panic!("timeout must be a failure")
        };
        assert!(msg.contains("systemctl restart fprintd"), "{msg}");
        // Distinct messages per class, not one generic string.
        for (out, needle) in [
            ("EnrollStart failed: Error.AlreadyInUse", "claimed"),
            ("Enroll result: enroll-data-full", "storage is full"),
            ("Enroll result: enroll-disconnected", "disconnected"),
            ("Not Authorized", "polkit"),
            ("No devices available", "no fingerprint reader"),
        ] {
            let EnrollOutcome::Failed(msg) = classify_enroll(&run(out, status_from(1))) else {
                panic!("must fail: {out}")
            };
            assert!(msg.contains(needle), "{out} → {msg}");
        }
    }

    #[test]
    fn run_streamed_kills_a_child_that_outlives_the_deadline() {
        let mut cmd = Command::new("/usr/bin/sleep");
        cmd.arg("30");
        let t0 = std::time::Instant::now();
        let run = run_streamed(cmd, Duration::from_millis(300)).unwrap();
        assert!(run.status.is_none(), "deadline must report as timed out");
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "must not wait for the child"
        );
    }

    #[test]
    fn run_streamed_captures_stdout_and_stderr() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo out-line; echo err-line >&2"]);
        let run = run_streamed(cmd, Duration::from_secs(10)).unwrap();
        assert!(run.status.is_some_and(|s| s.success()));
        assert!(run.output.contains("out-line"));
        assert!(run.output.contains("err-line"));
    }

    /// Serializes the fake-tool tests (the override is process-global) and
    /// installs executable fake fprintd/busctl scripts in a temp dir.
    struct FakeTools {
        dir: std::path::PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }
    static FAKE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    impl FakeTools {
        fn new(tag: &str) -> Self {
            let guard = FAKE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let dir =
                std::env::temp_dir().join(format!("irlume-fpfake-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            *TOOL_DIR_OVERRIDE.lock().unwrap() = Some(dir.clone());
            Self { dir, _guard: guard }
        }
        fn script(&self, name: &str, body: &str) {
            use std::os::unix::fs::PermissionsExt;
            let p = self.dir.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    impl Drop for FakeTools {
        fn drop(&mut self) {
            *TOOL_DIR_OVERRIDE.lock().unwrap() = None;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn enroll_runs_end_to_end_against_fake_fprintd() {
        let ft = FakeTools::new("enroll");
        // Success: placement prompts stream through, completed status wins.
        ft.script(
            "fprintd-enroll",
            "echo Enrolling right-index-finger\necho 'Enroll result: enroll-completed'",
        );
        assert_eq!(
            enroll_finger("tester", "right-index-finger"),
            EnrollOutcome::Enrolled
        );
        // Duplicate print reported by the sensor.
        ft.script(
            "fprintd-enroll",
            "echo 'Enroll result: enroll-duplicate'\nexit 1",
        );
        assert_eq!(
            enroll_finger("tester", "right-index-finger"),
            EnrollOutcome::Duplicate
        );
        // Claim conflict lands on stderr and maps to the actionable message.
        ft.script(
            "fprintd-enroll",
            "echo 'EnrollStart failed: GDBus.Error:net.reactivated.Fprint.Error.AlreadyInUse: busy' >&2\nexit 1",
        );
        let EnrollOutcome::Failed(msg) = enroll_finger("tester", "right-index-finger") else {
            panic!("claim conflict must fail")
        };
        assert!(msg.contains("claimed"), "{msg}");
        // Missing tool entirely.
        let _ = std::fs::remove_file(ft.dir.join("fprintd-enroll"));
        assert!(matches!(
            enroll_finger("tester", "x"),
            EnrollOutcome::Failed(_)
        ));
    }

    #[test]
    fn verify_and_delete_run_end_to_end_against_fakes() {
        let ft = FakeTools::new("verify");
        ft.script(
            "fprintd-verify",
            "echo 'Verify result: verify-match (done)'",
        );
        assert_eq!(verify_once("tester"), VerifyOutcome::Match);
        ft.script(
            "fprintd-verify",
            "echo 'Verify result: verify-no-match'\nexit 1",
        );
        assert_eq!(verify_once("tester"), VerifyOutcome::NoMatch);
        ft.script(
            "fprintd-verify",
            "echo 'failed to claim device: busy' >&2\nexit 1",
        );
        assert!(matches!(verify_once("tester"), VerifyOutcome::Error(_)));

        ft.script("fprintd-delete", "echo 'Fingerprints deleted'");
        assert!(delete_all("tester").is_ok());
        ft.script("fprintd-delete", "echo 'Not Authorized' >&2\nexit 1");
        let err = delete_all("tester").unwrap_err();
        assert!(err.contains("polkit"), "{err}");
    }

    #[test]
    fn listing_and_discovery_run_end_to_end_against_fakes() {
        let ft = FakeTools::new("list");
        ft.script(
            "fprintd-list",
            "echo 'Fingerprints for user tester:'\necho ' - #0: right-index-finger'",
        );
        assert_eq!(
            list_fingers("tester"),
            ListOutcome::Fingers(vec!["right-index-finger".into()])
        );
        assert!(has_enrollment("tester"));
        assert_eq!(free_finger("tester"), Some("left-index-finger"));
        ft.script("fprintd-list", "echo 'No devices available'");
        assert_eq!(list_fingers("tester"), ListOutcome::NoDevice);
        ft.script(
            "fprintd-list",
            "echo 'failed to claim device: Error.AlreadyInUse' >&2",
        );
        assert!(reader_stuck("tester"));

        // busctl fakes: device tree, per-device name, bus owner unit.
        ft.script(
            "busctl",
            r#"case "$*" in
  *tree*) echo '  /net/reactivated/Fprint/Device/0'; echo '  /net/reactivated/Fprint/Device/1';;
  *get-property*) echo 's "Fake Sensors"';;
  *status*) echo 'PID=42'; echo 'Unit=fprintd.service';;
esac"#,
        );
        assert!(reader_present());
        assert_eq!(device_name().as_deref(), Some("Fake Sensors"));
        assert_eq!(device_names().len(), 2);
        assert_eq!(bus_owner_unit().as_deref(), Some("fprintd.service"));

        // fprintd tooling presence check through the same seam.
        ft.script("fprintd-verify", "exit 0");
        assert!(fprintd_present());
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
