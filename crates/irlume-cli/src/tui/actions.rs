// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Guided access to less frequent CLI tasks. Argument vectors go straight to
//! the running executable, never through a shell. CLI validation and daemon
//! authorization remain authoritative.

#[derive(Clone, Copy)]
pub(super) struct Field {
    pub label: &'static str,
    pub flag: Option<&'static str>,
    pub optional: bool,
}

pub(super) struct Action {
    pub label: &'static str,
    pub description: &'static str,
    pub args: &'static [&'static str],
    pub root: bool,
    pub per_user: bool,
    pub fields: &'static [Field],
}

#[derive(Clone)]
pub(super) struct Invocation {
    pub action: &'static Action,
    pub values: Vec<String>,
}

impl Invocation {
    pub fn args(&self, user: &str) -> Vec<String> {
        let mut args: Vec<String> = self.action.args.iter().map(|v| (*v).into()).collect();
        for (field, value) in self.action.fields.iter().zip(&self.values) {
            if value.is_empty() && field.optional {
                continue;
            }
            if let Some(flag) = field.flag {
                args.push(flag.into());
            }
            args.push(value.clone());
        }
        if self.action.per_user {
            args.extend(["--user".into(), user.into()]);
        }
        args
    }
}

impl Field {
    pub fn validate(&self, value: &str) -> Result<(), &'static str> {
        if value.is_empty() {
            return if self.optional {
                Ok(())
            } else {
                Err("Enter a value or press Esc to cancel.")
            };
        }
        // Fields are values, not additional options. In particular a profile
        // named --reset must not turn ordinary enrollment into replacement.
        if value.starts_with('-') || value.chars().any(char::is_control) || value.len() > 1024 {
            return Err(
                "Use a value without control characters or a leading '-'; paths can start with ./.",
            );
        }
        if matches!(self.flag, Some("--scans" | "--rounds"))
            && !value.parse::<usize>().is_ok_and(|n| n > 0)
        {
            return Err("Enter a positive whole number.");
        }
        Ok(())
    }
}

const NAME: Field = Field {
    label: "Profile name (blank uses the CLI default)",
    flag: Some("--name"),
    optional: true,
};
const SCANS: Field = Field {
    label: "Number of scans (blank uses the CLI default)",
    flag: Some("--scans"),
    optional: true,
};
const PROFILE: Field = Field {
    label: "Existing profile name",
    flag: Some("--profile"),
    optional: false,
};
const OUTPUT: Field = Field {
    label: "Output file (blank uses the CLI default)",
    flag: Some("--output"),
    optional: true,
};
const SINCE: Field = Field {
    label: "History window, e.g. 10m (blank uses 10m)",
    flag: Some("--since"),
    optional: true,
};
const TRANSACTION: Field = Field {
    label: "Login transaction ID",
    flag: Some("--transaction-id"),
    optional: false,
};

pub(super) const FINGERPRINT_ONLY: Action = Action { label: "Enable fingerprint-only login", description: "Changes system login to fingerprint with password fallback, disabling face authentication. Existing CLI checks must pass.", args: &["fingerprint", "enable", "--fingerprint-only"], root: true, per_user: true, fields: &[] };
pub(super) const SELINUX_STATUS: Action = Action {
    label: "Show SELinux status",
    description: "Shows the installed policy and labeling status; no change.",
    args: &["selinux", "status"],
    root: false,
    per_user: false,
    fields: &[],
};
pub(super) const SENSOR_PREFLIGHT: Action = Action { label: "Check IR-only readiness", description: "Checks this account's IR-only prerequisites without opening the camera or attempting authentication.", args: &["auth", "sensor", "preflight"], root: false, per_user: true, fields: &[] };
pub(super) const WALLET_FORGET: Action = Action { label: "Forget wallet secret safely", description: "For a token-based wallet, asks for your password privately and rekeys the wallet before forgetting its sealed secret.", args: &["keyring", "forget"], root: false, per_user: true, fields: &[] };
pub(super) const WALLET_RESEAL: Action = Action { label: "Reseal wallet secret", description: "Uses the existing seal type to choose the safe recovery path after boot measurements change; may ask for your password privately.", args: &["reseal"], root: false, per_user: true, fields: &[] };

pub(super) static ACTIONS: &[Action] = &[
    Action { label: "Test authentication for this account", description: "Engages the camera. Verifies this account without releasing a password; Shows whether this account was recognized. This does not test a system approval dialog.", args: &["auth", "test", "--events=jsonl"], root: false, per_user: true, fields: &[] },
    Action { label: "Enroll with a chosen scan count", description: "Captures a face profile. Approve the OS authorization prompt when asked.", args: &["enroll"], root: false, per_user: true, fields: &[NAME, SCANS] },
    Action { label: "Replace face enrollment", description: "Captures a replacement, then replaces existing profiles and camera binding only after success. Keeps the template key and recovery setup. Requires OS authorization.", args: &["enroll", "--reset"], root: false, per_user: true, fields: &[NAME, SCANS] },
    Action { label: "Add a chosen number of scans", description: "Captures additional scans for an existing profile. Requires OS authorization.", args: &["profiles", "add-scan"], root: false, per_user: true, fields: &[PROFILE, SCANS] },
    Action { label: "Remove scans for a recognizer", description: "Requires OS approval. Deletes that recognizer's scans and calibrations across this account. Empty profiles are deleted; removing the last profile also erases recovery. This cannot be undone.", args: &["profiles", "forget-model"], root: false, per_user: true, fields: &[Field { label: "Recognizer tag: shipped or embed:<sha256> (see profile listing)", flag: None, optional: false }] },
    Action { label: "Clear legacy eyes-open blocker", description: "Clears the retired eyes-open requirement on this account. It cannot be enabled again.", args: &["profiles", "eyes-open", "off"], root: false, per_user: true, fields: &[] },
    Action { label: "List profiles and recognizer tags", description: "Shows profiles and scans for the selected account, including recognizer ownership.", args: &["profiles", "list"], root: false, per_user: true, fields: &[] },
    Action { label: "List all camera devices", description: "Read-only camera census, including unsupported devices and classification evidence.", args: &["camera", "census"], root: false, per_user: false, fields: &[] },
    Action { label: "Show full capture qualification", description: "Shows the daemon's active schedule, qualification reason and exact camera context.", args: &["camera-mode"], root: false, per_user: false, fields: &[] },
    Action { label: "Capture camera diagnostics to terminal", description: "Opens the camera and captures gated samples to measure delivered-rate and stream evidence, then displays the report as JSON.", args: &["camera", "diagnostics", "--json"], root: false, per_user: false, fields: &[] },
    Action { label: "Tune capture with a chosen round count", description: "Engages RGB and IR cameras and stores qualification for the exact device context. Requires administrator access.", args: &["camera-tune"], root: true, per_user: false, fields: &[Field { label: "Measurement rounds (blank uses the CLI default)", flag: Some("--rounds"), optional: true }] },
    Action { label: "Record a diagnostic trace", description: "Requires administrator access. Records sensitive diagnostic measurements for a bounded duration, with no frames, embeddings or credentials. Review before sharing.", args: &["trace", "record"], root: true, per_user: false, fields: &[Field { label: "Duration, e.g. 60s (blank uses 60s; maximum 5m)", flag: Some("--duration"), optional: true }, OUTPUT] },
    Action { label: "Explain a recorded trace", description: "Validates a trace file and displays its timeline. Sensitive diagnostic measurements may appear. No camera capture.", args: &["trace", "explain"], root: false, per_user: false, fields: &[Field { label: "Trace file (.jsonl)", flag: None, optional: false }, OUTPUT] },
    Action { label: "Create a support report with options", description: "Read-only report from share-safe facts. No camera capture. Output must end in .txt; existing files are preserved.", args: &["support-report"], root: false, per_user: false, fields: &[OUTPUT, SINCE] },
    Action { label: "Create a support report with camera probe", description: "Engages the camera for one bounded probe. Requires administrator access. Review the report before sharing.", args: &["support-report", "--probe"], root: true, per_user: false, fields: &[OUTPUT, SINCE] },
    Action { label: "Follow authentication logs", description: "Shows live system logs until Ctrl-C. Debug logs may contain sensitive measurements. Returns to the TUI afterward.", args: &["logs", "-f"], root: true, per_user: false, fields: &[Field { label: "Since, e.g. 10 min ago (blank uses the CLI default)", flag: Some("--since"), optional: true }] },
    FINGERPRINT_ONLY,
    Action { label: "Reconcile login wiring", description: "Reapplies saved system login wiring after distribution PAM regeneration. Requires administrator access.", args: &["login", "reconcile"], root: true, per_user: false, fields: &[] },
    Action { label: "Preview login wiring", description: "Read-only preview of the default login integration, without applying it.", args: &["login", "enable"], root: true, per_user: false, fields: &[] },
    Action { label: "Verify a login transaction", description: "Checks whether a recorded login transaction still matches the system. Displays a JSON report.", args: &["login", "verify", "--json"], root: true, per_user: false, fields: &[TRANSACTION] },
    Action { label: "Roll back a login transaction", description: "Restores the recorded login configuration using the CLI's transaction checks. Requires administrator access. Displays a JSON report.", args: &["login", "rollback", "--apply", "--json"], root: true, per_user: false, fields: &[TRANSACTION] },
    Action { label: "Show runtime dependencies", description: "Checks installed runtime libraries and model files.", args: &["deps"], root: false, per_user: false, fields: &[] },
    Action { label: "Show installed model inventory", description: "Shows the machine-readable shipped model inventory. Third-party model loading is retired.", args: &["models", "list", "--json"], root: false, per_user: false, fields: &[] },
    Action { label: "Check for updates", description: "Checks the installation channel and available version without installing an update. Uses the network.", args: &["update", "--check"], root: false, per_user: false, fields: &[] },
    Action { label: "Show version", description: "Shows the version of the executable running this TUI.", args: &["version"], root: false, per_user: false, fields: &[] },
    Action { label: "Uninstall while keeping enrollment data", description: "Removes system integration while preserving enrollment data. The CLI asks its own uninstall confirmations in the terminal. Requires administrator access.", args: &["uninstall", "--keep-data"], root: true, per_user: false, fields: &[] },
    Action { label: "Show log history", description: "Shows system authentication logs for a chosen time window. Debug logs may include sensitive measurements.", args: &["logs"], root: true, per_user: false, fields: &[Field { label: "Since, e.g. 10 min ago (blank uses the CLI default)", flag: Some("--since"), optional: true }] },
    Action { label: "Connect login, sudo and app prompts", description: "Applies login wiring with both optional sudo and polkit integration. Requires administrator access; retains password fallback.", args: &["login", "enable", "--with-sudo", "--with-polkit", "--apply"], root: true, per_user: false, fields: &[] },
    Action { label: "Preview a login transaction", description: "Produces a machine-readable plan ID without applying a change.", args: &["login", "plan", "--json"], root: true, per_user: false, fields: &[Field { label: "Action: enable or disable", flag: Some("--action"), optional: false }] },
    Action { label: "Apply a prepared login transaction", description: "Applies a previously reviewed plan with the CLI's freshness and rollback checks. Requires administrator access.", args: &["login", "apply", "--json"], root: true, per_user: false, fields: &[Field { label: "Action: enable or disable", flag: Some("--action"), optional: false }, Field { label: "Plan ID from login plan", flag: Some("--plan-id"), optional: false }] },
    SELINUX_STATUS,
    Action { label: "Show recovery status", description: "Shows this account's template encryption and recovery state. Available even when a camera is disconnected.", args: &["recovery", "status"], root: false, per_user: true, fields: &[] },
    Action { label: "Set a recovery passphrase", description: "Asks for the passphrase privately in the terminal and creates a recovery wrap for this account.", args: &["recovery", "setup"], root: false, per_user: true, fields: &[] },
    Action { label: "Restore the enrollment key", description: "Asks for the recovery passphrase privately in the terminal and restores this account's template key.", args: &["recovery", "restore"], root: false, per_user: true, fields: &[] },
    Action { label: "Forget recovery setup", description: "Deletes this account's recovery wrap. Stored face profiles are retained. This removes the recovery route.", args: &["recovery", "forget"], root: false, per_user: true, fields: &[] },
    Action { label: "Rename a profile or scan", description: "Renames the selected account's profile, or the named scan within it. No camera required.", args: &["profiles", "rename"], root: false, per_user: true, fields: &[PROFILE, Field { label: "Scan name (blank renames the whole profile)", flag: Some("--scan"), optional: true }, Field { label: "New name", flag: Some("--name"), optional: false }] },
    Action { label: "Delete a profile or scan", description: "Permanently deletes the specified profile or scan for this account. A blank scan field means the WHOLE profile and all its scans.", args: &["profiles", "delete"], root: false, per_user: true, fields: &[PROFILE, Field { label: "Scan name (blank deletes the WHOLE profile)", flag: Some("--scan"), optional: true }] },
    Action { label: "Forget wallet secret without rekeying", description: "Force-forgets the sealed wallet secret. For a token-based keyring this skips rekeying and may leave the wallet inaccessible. Use ordinary Forget Wallet when possible.", args: &["keyring", "forget", "--force"], root: false, per_user: true, fields: &[] },

    SENSOR_PREFLIGHT,
    WALLET_FORGET,
    WALLET_RESEAL,
    Action { label: "Face sensor policy status", description: "Show the sensor policy observed by the daemon. Does not open cameras.", args: &["auth", "sensor", "status"], root: false, per_user: false, fields: &[] },
    Action { label: "Privileged face confirmation status", description: "Show whether configured privileged services require confirmation and whether an environment override applies.", args: &["auth", "consent", "status"], root: false, per_user: false, fields: &[] },
    Action { label: "Face retry status", description: "Inspect the selected account's face retry budget and cooldown. Does not authenticate or reset state.", args: &["retry", "status"], root: false, per_user: true, fields: &[] },
    Action { label: "Reset face retries with password", description: "Verifies the selected account's current local login password privately. An administrator running this TUI as root performs an administrator reset.", args: &["retry", "reset"], root: false, per_user: true, fields: &[] },
    Action { label: "Administrator reset of face retries", description: "Requires administrator approval. Resets the selected account's retry state, including when password-verified recovery requires administrator repair. Does not change enrollment or the login password.", args: &["retry", "reset"], root: true, per_user: true, fields: &[] },

];

pub(super) fn matching(query: &str) -> Vec<&'static Action> {
    let words: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
    ACTIONS
        .iter()
        .filter(|a| {
            let text = format!("{} {}", a.label, a.args.join(" ")).to_lowercase();
            words.iter().all(|w| text.contains(w))
        })
        .collect()
}

/// Summarize the current CLI's terminal event. Keep its session lock, request
/// validation and single-capture semantics; never display arbitrary error prose.
pub(super) fn auth_test_feedback(
    output: std::io::Result<std::process::Output>,
) -> Result<bool, &'static str> {
    let output = output.map_err(|_| "Could not start the authentication test.")?;
    let last = std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|text| text.lines().last());
    let event: serde_json::Value = last
        .and_then(|line| serde_json::from_str(line).ok())
        .ok_or("Authentication test returned an unreadable result.")?;
    if event["command"] != "auth.test" {
        return Err("Authentication test returned an unexpected result.");
    }
    if output.status.success() && event["terminal"] == true && event["event"] == "result" {
        return event["data"]["granted"]
            .as_bool()
            .ok_or("Authentication test returned an incomplete result.");
    }
    if !output.status.success() && (event["terminal"] == true || event["ok"] == false) {
        return Err(match event["error"]["code"].as_str() {
            Some("camera-busy") => crate::machine::CAMERA_BUSY_MESSAGE,
            Some("session-busy") => {
                "Another Irlume operation is running. Wait for it to finish, then retry."
            }
            Some("daemon-unavailable") => {
                "Could not reach Irlume. Check the daemon status and retry."
            }
            _ => "Authentication test failed. Check Irlume diagnostics for details.",
        });
    }
    Err("Authentication test ended without a final result.")
}

#[cfg(test)]
mod auth_feedback_tests {
    use super::auth_test_feedback;
    use std::os::unix::process::ExitStatusExt;
    #[test]
    fn camera_diagnostics_action_discloses_capture_before_confirmation() {
        let action = super::matching("camera diagnostics")
            .into_iter()
            .find(|action| action.args == ["camera", "diagnostics", "--json"])
            .unwrap();
        assert!(!action.description.contains("does not start a capture"));
        assert!(action.description.contains("captures"));
        assert!(action.description.contains("camera"));
    }

    fn output(code: i32, value: serde_json::Value) -> std::io::Result<std::process::Output> {
        Ok(std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: format!("{value}\n").into_bytes(),
            stderr: Vec::new(),
        })
    }

    #[test]
    fn camera_busy_feedback_is_actionable_without_rendering_daemon_prose() {
        let event = |code| {
            serde_json::json!({"command":"auth.test","terminal":true,"event":"error", "error":{
                "code":code,"retryable":true,"message":"private fixture"
            }})
        };
        let message = auth_test_feedback(output(1, event("camera-busy"))).unwrap_err();
        assert!(message.contains("Close any app"));
        assert!(message.contains("retry"));
        let generic = auth_test_feedback(output(1, event("operation-failed"))).unwrap_err();
        assert!(!generic.contains("private fixture"));
        assert!(!generic.contains("Close any app"));
        let session = serde_json::json!({"command":"auth.test","ok":false,"error":{"code":"session-busy","retryable":true}});
        assert!(auth_test_feedback(output(2, session))
            .unwrap_err()
            .contains("Another Irlume operation"));
        assert!(auth_test_feedback(output(1, event("daemon-unavailable")))
            .unwrap_err()
            .contains("daemon status"));
    }

    #[test]
    fn auth_feedback_distinguishes_denial_and_grant_and_requires_completion() {
        for granted in [true, false] {
            let event = serde_json::json!({"command":"auth.test","terminal":true,"event":"result","data":{
                "granted":granted,"live":true,"reason":"private fixture","refusal":null
            }});
            assert_eq!(auth_test_feedback(output(0, event.clone())), Ok(granted));
            assert!(auth_test_feedback(output(1, event)).is_err());
        }
        assert!(auth_test_feedback(output(
            0,
            serde_json::json!({"command":"auth.test","event":"capturing","terminal":false})
        ))
        .is_err());
        assert!(auth_test_feedback(output(
            0,
            serde_json::json!({"command":"auth.test","terminal":true,"event":"result","data":{}})
        ))
        .is_err());
    }
}
