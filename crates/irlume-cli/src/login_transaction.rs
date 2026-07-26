// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Versioned machine contract for narrowly-scoped Plasma login wiring.
//!
//! The public caller supplies only a fixed scope and opaque lineage IDs. PAM
//! paths are resolved from an internal allowlist, every plan is bound to the
//! observed file state, and rollback restores only bytes written by the same
//! transaction.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use irlume_common::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CONTRACT_VERSION: u32 = 1;
const ABSENT_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone)]
struct Paths {
    pam_etc: PathBuf,
    pam_vendor: PathBuf,
    transactions: PathBuf,
    display_manager: String,
}

impl Paths {
    fn production() -> Result<Self, &'static str> {
        let display_manager =
            crate::pamwire::active_display_manager().ok_or("display-manager-unavailable")?;
        Ok(Self {
            pam_etc: PathBuf::from("/etc/pam.d"),
            pam_vendor: PathBuf::from("/usr/lib/pam.d"),
            transactions: PathBuf::from(irlume_common::STATE_DIR).join("login-transactions"),
            display_manager,
        })
    }
}

#[derive(Clone)]
struct Facts {
    healthy: bool,
    enrolled: bool,
    tier: String,
    selinux_ready: bool,
}

impl Facts {
    fn production() -> Self {
        let (healthy, tier) = match crate::daemon_request(&Request::Health) {
            Ok(Response::Health { tier, .. }) if tier != "none" => (true, tier),
            _ => (false, "none".into()),
        };
        let selinux_ready = if matches!(
            irlume_common::platform::distro_family(),
            irlume_common::platform::DistroFamily::Fedora
        ) {
            crate::pamwire::selinux_state() == Some(true)
        } else {
            true
        };
        Self {
            healthy,
            enrolled: !irlume_core::storage::list_users().is_empty(),
            tier,
            selinux_ready,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    Enable,
    Disable,
}

#[derive(Clone)]
struct Target {
    name: String,
    etc: PathBuf,
    vendor: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileImage {
    present: bool,
    sha256: String,
    mode: u32,
    bytes_base64: String,
}

impl FileImage {
    fn absent() -> Self {
        Self {
            present: false,
            sha256: ABSENT_DIGEST.into(),
            mode: 0,
            bytes_base64: String::new(),
        }
    }

    fn from_path(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::absent());
        }
        let bytes = std::fs::read(path).map_err(|error| format!("read failed: {error}"))?;
        let mode = std::fs::metadata(path)
            .map_err(|error| format!("metadata failed: {error}"))?
            .permissions()
            .mode()
            & 0o777;
        Ok(Self::from_bytes(bytes, mode))
    }

    fn from_bytes(bytes: Vec<u8>, mode: u32) -> Self {
        Self {
            present: true,
            sha256: digest(&bytes),
            mode,
            bytes_base64: STANDARD.encode(bytes),
        }
    }

    fn bytes(&self) -> Result<Vec<u8>, String> {
        if !self.present {
            return Ok(Vec::new());
        }
        STANDARD
            .decode(&self.bytes_base64)
            .map_err(|_| "transaction journal is corrupt".into())
    }
}

#[derive(Clone)]
struct PlannedTarget {
    target: Target,
    action: &'static str,
    before: FileImage,
    after: FileImage,
}

#[derive(Clone)]
struct Plan {
    operation: Operation,
    scope: String,
    plan_id: String,
    display_manager: String,
    desired: String,
    security_tier: String,
    preconditions: Vec<Value>,
    password_fallback: bool,
    targets: Vec<PlannedTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TransactionState {
    Pending,
    Applied,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalTarget {
    name: String,
    before: FileImage,
    after: FileImage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Journal {
    version: u32,
    transaction_id: String,
    plan_id: String,
    operation: Operation,
    scope: String,
    display_manager: String,
    desired: String,
    state: TransactionState,
    targets: Vec<JournalTarget>,
}

#[derive(Default)]
struct Flags {
    scope: Option<String>,
    plan_id: Option<String>,
    transaction_id: Option<String>,
    apply: bool,
    json: bool,
}

pub fn run(action: Option<&str>, args: &[String]) -> ExitCode {
    let command = match action {
        Some("enable") | Some("disable") if args.iter().any(|arg| arg == "--apply") => {
            "login.apply"
        }
        Some("enable") | Some("disable") => "login.plan",
        Some("verify") => "login.verify",
        Some("rollback") => "login.rollback",
        Some("status") | None => "login.status",
        _ => "login",
    };
    let flags = match parse_flags(args) {
        Ok(flags) => flags,
        Err(()) => return failure(command, "usage-error", false, json!({}), ExitCode::from(2)),
    };
    let paths = match Paths::production() {
        Ok(paths) => paths,
        Err(code) => return failure(command, code, false, json!({}), ExitCode::FAILURE),
    };
    match action {
        Some("enable") => {
            let Some(scope) = flags.scope.as_deref() else {
                return failure(command, "usage-error", false, json!({}), ExitCode::from(2));
            };
            if !matches!(scope, "lock-screen" | "login-screen") {
                return failure(command, "usage-error", false, json!({}), ExitCode::from(2));
            }
            if flags.apply {
                let Some(plan_id) = flags.plan_id.as_deref() else {
                    return failure(command, "usage-error", false, json!({}), ExitCode::from(2));
                };
                apply(
                    &paths,
                    &Facts::production(),
                    Operation::Enable,
                    scope,
                    plan_id,
                    false,
                )
            } else if flags.plan_id.is_none() {
                plan_response(&paths, &Facts::production(), Operation::Enable, scope)
            } else {
                failure(command, "usage-error", false, json!({}), ExitCode::from(2))
            }
        }
        Some("disable") if flags.scope.is_none() => {
            if flags.apply {
                let Some(plan_id) = flags.plan_id.as_deref() else {
                    return failure(command, "usage-error", false, json!({}), ExitCode::from(2));
                };
                apply(
                    &paths,
                    &Facts::production(),
                    Operation::Disable,
                    "disable",
                    plan_id,
                    false,
                )
            } else if flags.plan_id.is_none() {
                plan_response(&paths, &Facts::production(), Operation::Disable, "disable")
            } else {
                failure(command, "usage-error", false, json!({}), ExitCode::from(2))
            }
        }
        Some("verify") if !flags.apply && flags.plan_id.is_none() && flags.scope.is_none() => {
            let Some(transaction_id) = flags.transaction_id.as_deref() else {
                return failure(command, "usage-error", false, json!({}), ExitCode::from(2));
            };
            verify(&paths, &Facts::production(), transaction_id)
        }
        Some("rollback") if flags.apply && flags.plan_id.is_none() && flags.scope.is_none() => {
            let Some(transaction_id) = flags.transaction_id.as_deref() else {
                return failure(command, "usage-error", false, json!({}), ExitCode::from(2));
            };
            rollback(&paths, transaction_id)
        }
        Some("status") | None
            if !flags.apply
                && flags.plan_id.is_none()
                && flags.transaction_id.is_none()
                && flags.scope.is_none() =>
        {
            status(&paths)
        }
        _ => failure(command, "usage-error", false, json!({}), ExitCode::from(2)),
    }
}

fn parse_flags(args: &[String]) -> Result<Flags, ()> {
    let mut flags = Flags::default();
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !flags.json => flags.json = true,
            "--apply" if !flags.apply => flags.apply = true,
            "--scope" if flags.scope.is_none() => {
                flags.scope = Some(args.get(index + 1).ok_or(())?.clone());
                index += 1;
            }
            "--plan-id" if flags.plan_id.is_none() => {
                flags.plan_id = Some(args.get(index + 1).ok_or(())?.clone());
                index += 1;
            }
            "--transaction-id" if flags.transaction_id.is_none() => {
                flags.transaction_id = Some(args.get(index + 1).ok_or(())?.clone());
                index += 1;
            }
            _ => return Err(()),
        }
        index += 1;
    }
    flags.json.then_some(flags).ok_or(())
}

fn plan_response(paths: &Paths, facts: &Facts, operation: Operation, scope: &str) -> ExitCode {
    match build_plan(paths, facts, operation, scope) {
        Ok(plan) => success("login.plan", plan_json(&plan)),
        Err(code) => failure("login.plan", code, false, json!({}), ExitCode::FAILURE),
    }
}

fn build_plan(
    paths: &Paths,
    facts: &Facts,
    operation: Operation,
    scope: &str,
) -> Result<Plan, &'static str> {
    if !matches!(paths.display_manager.as_str(), "plasmalogin" | "sddm") {
        return Err("unsupported-display-manager");
    }
    let targets = target_set(paths, operation, scope)?;
    let mut planned = Vec::with_capacity(targets.len());
    for target in targets {
        let before = FileImage::from_path(&target.etc).map_err(|_| "pam-read-failed")?;
        let after = desired_image(&target, operation).map_err(|_| "unsupported-pam-layout")?;
        let action = match (operation, before.present, after.present) {
            (Operation::Enable, false, true) => "create-local-override",
            (Operation::Enable, true, true) => "update-local-stack",
            (Operation::Disable, true, false) => "remove-local-override",
            (Operation::Disable, _, _) => "restore-local-stack",
            _ => "update-local-stack",
        };
        planned.push(PlannedTarget {
            target,
            action,
            before,
            after,
        });
    }
    let password_fallback = planned.iter().all(|target| {
        effective_after_bytes(target).is_ok_and(|bytes| has_password_fallback(&bytes))
    });
    let preconditions = vec![
        check("engine.healthy", facts.healthy),
        check(
            "profile.enrolled",
            operation == Operation::Disable || facts.enrolled,
        ),
        check("selinux.ready", facts.selinux_ready),
        check("login.password-fallback", password_fallback),
    ];
    let desired = if operation == Operation::Enable {
        "enabled"
    } else {
        "disabled"
    };
    let mut plan = Plan {
        operation,
        scope: scope.into(),
        plan_id: String::new(),
        display_manager: paths.display_manager.clone(),
        desired: desired.into(),
        security_tier: facts.tier.clone(),
        preconditions,
        password_fallback,
        targets: planned,
    };
    plan.plan_id = plan_id(&plan);
    Ok(plan)
}

fn target_set(
    paths: &Paths,
    operation: Operation,
    scope: &str,
) -> Result<Vec<Target>, &'static str> {
    let login = || Target {
        name: format!("pam-service:{}", paths.display_manager),
        etc: paths.pam_etc.join(&paths.display_manager),
        vendor: paths.pam_vendor.join(&paths.display_manager),
    };
    let lock = || Target {
        name: "pam-service:kde".into(),
        etc: paths.pam_etc.join("kde"),
        vendor: paths.pam_vendor.join("kde"),
    };
    match (operation, scope) {
        (Operation::Enable, "lock-screen") => Ok(vec![lock()]),
        (Operation::Enable, "login-screen") => Ok(vec![login()]),
        (Operation::Disable, "disable") => Ok(vec![login(), lock()]),
        _ => Err("usage-error"),
    }
}

fn desired_image(target: &Target, operation: Operation) -> Result<FileImage, String> {
    let before = FileImage::from_path(&target.etc)?;
    if operation == Operation::Disable {
        if !before.present {
            return Ok(FileImage::absent());
        }
        let bytes = before.bytes()?;
        let text = String::from_utf8(bytes).map_err(|_| "PAM file is not UTF-8")?;
        if text.starts_with(crate::pamwire::CREATED_PREFIX) {
            return Ok(FileImage::absent());
        }
        let (clean, _) = crate::pamwire::unwire_lines(&text);
        return Ok(FileImage::from_bytes(clean.into_bytes(), before.mode));
    }

    let (base, from_vendor) = if before.present {
        (before.clone(), false)
    } else {
        (FileImage::from_path(&target.vendor)?, true)
    };
    if !base.present {
        return Err("PAM service is not installed".into());
    }
    let text = String::from_utf8(base.bytes()?).map_err(|_| "PAM file is not UTF-8")?;
    let (wired, changed) = if target.name == "pam-service:kde" {
        crate::pamwire::wire_lock(&text)
    } else {
        crate::pamwire::wire_greeter_impl(&text, true, false, true)
    };
    if !changed && !text.contains("pam_irlume.so") {
        return Err("PAM layout has no safe authentication anchor".into());
    }
    let body = if from_vendor {
        format!(
            "{}{}; delete this file to restore the vendor copy\n{}",
            crate::pamwire::CREATED_PREFIX,
            target.vendor.display(),
            wired
        )
    } else {
        wired
    };
    Ok(FileImage::from_bytes(body.into_bytes(), base.mode))
}

fn effective_after_bytes(target: &PlannedTarget) -> Result<Vec<u8>, String> {
    if target.after.present {
        target.after.bytes()
    } else {
        FileImage::from_path(&target.target.vendor)?.bytes()
    }
}

fn has_password_fallback(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    text.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with('#') {
            return false;
        }
        line.contains("pam_unix.so")
            || line.starts_with("@include common-auth")
            || line.starts_with("@include login")
            || (line.starts_with("auth")
                && (line.contains("password-auth")
                    || line.contains("system-auth")
                    || line.contains("system-login")
                    || line.contains("system-local-login")))
    })
}

fn check(id: &'static str, passed: bool) -> Value {
    json!({"id": id, "state": if passed { "pass" } else { "fail" }})
}

fn plan_id(plan: &Plan) -> String {
    let targets: Vec<_> = plan
        .targets
        .iter()
        .map(|target| {
            json!({
                "target": target.target.name,
                "before": target.before.sha256,
                "before_present": target.before.present,
                "before_mode": target.before.mode,
                "after": target.after.sha256,
                "after_present": target.after.present,
                "after_mode": target.after.mode
            })
        })
        .collect();
    let binding = json!({
        "operation": plan.operation,
        "scope": plan.scope,
        "display_manager": plan.display_manager,
        "security_tier": plan.security_tier,
        "password_fallback": plan.password_fallback,
        "targets": targets
    });
    format!(
        "plan-{}",
        digest(&serde_json::to_vec(&binding).expect("plan binding serializes"))
    )
}

fn plan_json(plan: &Plan) -> Value {
    json!({
        "operation": match plan.operation { Operation::Enable => "enable", Operation::Disable => "disable" },
        "plan_id": plan.plan_id,
        "apply": false,
        "mutated": false,
        "display_manager": {
            "id": plan.display_manager,
            "supported": true
        },
        "security_tier": plan.security_tier,
        "requested_scopes": if plan.operation == Operation::Enable {
            vec![plan.scope.clone()]
        } else {
            Vec::<String>::new()
        },
        "preconditions": plan.preconditions,
        "changes": plan.targets.iter().map(|target| json!({
            "target": target.target.name,
            "action": target.action,
            "before_sha256": target.before.sha256,
            "after_sha256": target.after.sha256
        })).collect::<Vec<_>>(),
        "password_fallback": {
            "preserved": plan.password_fallback
        }
    })
}

fn apply(
    paths: &Paths,
    facts: &Facts,
    operation: Operation,
    scope: &str,
    supplied_plan_id: &str,
    inject_verify_failure: bool,
) -> ExitCode {
    if unsafe { libc::geteuid() } != 0 && !cfg!(test) {
        return failure(
            "login.apply",
            "not-authorized",
            false,
            json!({}),
            ExitCode::FAILURE,
        );
    }
    if !valid_plan_id(supplied_plan_id) {
        return failure(
            "login.apply",
            "invalid-plan-id",
            false,
            json!({}),
            ExitCode::from(2),
        );
    }
    let plan = match build_plan(paths, facts, operation, scope) {
        Ok(plan) => plan,
        Err(code) => return failure("login.apply", code, false, json!({}), ExitCode::FAILURE),
    };
    if plan.plan_id != supplied_plan_id {
        return failure(
            "login.apply",
            "plan-state-drift",
            false,
            json!({"plan_id": supplied_plan_id}),
            ExitCode::FAILURE,
        );
    }
    if plan
        .preconditions
        .iter()
        .any(|check| check["state"] != "pass")
        || (scope == "login-screen" && facts.tier != "secure")
    {
        return failure(
            "login.apply",
            if scope == "login-screen" && facts.tier != "secure" {
                "secure-tier-required"
            } else {
                "precondition-failed"
            },
            false,
            json!({"plan_id": plan.plan_id}),
            ExitCode::FAILURE,
        );
    }

    let transaction_id = format!("transaction-{:032x}", rand::random::<u128>());
    let mut journal = Journal {
        version: 1,
        transaction_id: transaction_id.clone(),
        plan_id: plan.plan_id.clone(),
        operation,
        scope: scope.into(),
        display_manager: paths.display_manager.clone(),
        desired: plan.desired.clone(),
        state: TransactionState::Pending,
        targets: plan
            .targets
            .iter()
            .map(|target| JournalTarget {
                name: target.target.name.clone(),
                before: target.before.clone(),
                after: target.after.clone(),
            })
            .collect(),
    };
    if save_journal(paths, &journal).is_err() {
        return failure(
            "login.apply",
            "transaction-journal-failed",
            false,
            json!({"plan_id": plan.plan_id}),
            ExitCode::FAILURE,
        );
    }

    let mut applied = Vec::new();
    for target in &plan.targets {
        if let Err(_error) = apply_image(&target.target.etc, &target.after) {
            let rollback = rollback_journal(paths, &mut journal);
            return apply_failure(&plan, &transaction_id, "apply-failed", &rollback);
        }
        applied.push(json!({"target": target.target.name, "result": "applied"}));
    }
    journal.state = TransactionState::Applied;
    if save_journal(paths, &journal).is_err() {
        let rollback = rollback_journal(paths, &mut journal);
        return apply_failure(
            &plan,
            &transaction_id,
            "transaction-journal-failed",
            &rollback,
        );
    }

    let post_apply_facts = if cfg!(test) {
        facts.clone()
    } else {
        Facts::production()
    };
    let verified = !inject_verify_failure
        && targets_match(paths, &journal)
        && plan.password_fallback
        && post_apply_facts.healthy
        && post_apply_facts.selinux_ready;
    if !verified {
        let rollback = rollback_journal(paths, &mut journal);
        let data = json!({
            "plan_id": plan.plan_id,
            "transaction_id": transaction_id,
            "state": "verification-failed",
            "mutated": false,
            "verification": {
                "state": "failed",
                "failed_check": if inject_verify_failure {
                    "login.password-fallback"
                } else {
                    "pam.targets-match-plan"
                }
            },
            "rollback": rollback
        });
        return failure(
            "login.apply",
            "post-apply-verification-failed",
            false,
            data,
            ExitCode::FAILURE,
        );
    }

    success(
        "login.apply",
        json!({
            "plan_id": plan.plan_id,
            "transaction_id": transaction_id,
            "state": "applied",
            "mutated": true,
            "operations": applied
        }),
    )
}

fn apply_failure(plan: &Plan, transaction_id: &str, code: &str, rollback: &Value) -> ExitCode {
    failure(
        "login.apply",
        code,
        false,
        json!({
            "plan_id": plan.plan_id,
            "transaction_id": transaction_id,
            "state": "apply-failed",
            "mutated": false,
            "rollback": rollback
        }),
        ExitCode::FAILURE,
    )
}

fn verify(paths: &Paths, facts: &Facts, transaction_id: &str) -> ExitCode {
    if !valid_transaction_id(transaction_id) {
        return failure(
            "login.verify",
            "invalid-transaction-id",
            false,
            json!({}),
            ExitCode::from(2),
        );
    }
    let journal = match load_journal(paths, transaction_id) {
        Ok(journal) => journal,
        Err(code) => return failure("login.verify", code, false, json!({}), ExitCode::FAILURE),
    };
    let pam_match = journal.state == TransactionState::Applied && targets_match(paths, &journal);
    let fallback = journal.targets.iter().all(|target| {
        effective_journal_bytes(paths, &journal, target)
            .is_ok_and(|bytes| has_password_fallback(&bytes))
    });
    let checks = vec![
        check("daemon.reachable", facts.healthy),
        check(
            "display-manager.matches-plan",
            paths.display_manager == journal.display_manager,
        ),
        check("pam.targets-match-plan", pam_match),
        check("selinux.ready", facts.selinux_ready),
        check("login.password-fallback", fallback),
    ];
    let passed = facts.healthy
        && paths.display_manager == journal.display_manager
        && pam_match
        && facts.selinux_ready
        && fallback;
    let data = json!({
        "transaction_id": transaction_id,
        "state": if passed { "verified" } else { "failed" },
        "desired": journal.desired,
        "actual": if pam_match { journal.desired.clone() } else { "drifted".into() },
        "checks": checks
    });
    if passed {
        success("login.verify", data)
    } else {
        failure(
            "login.verify",
            "post-apply-verification-failed",
            false,
            data,
            ExitCode::FAILURE,
        )
    }
}

fn rollback(paths: &Paths, transaction_id: &str) -> ExitCode {
    if unsafe { libc::geteuid() } != 0 && !cfg!(test) {
        return failure(
            "login.rollback",
            "not-authorized",
            false,
            json!({}),
            ExitCode::FAILURE,
        );
    }
    if !valid_transaction_id(transaction_id) {
        return failure(
            "login.rollback",
            "invalid-transaction-id",
            false,
            json!({}),
            ExitCode::from(2),
        );
    }
    let mut journal = match load_journal(paths, transaction_id) {
        Ok(journal) => journal,
        Err(code) => return failure("login.rollback", code, false, json!({}), ExitCode::FAILURE),
    };
    let result = rollback_journal(paths, &mut journal);
    if result["restored"] == true {
        success("login.rollback", result)
    } else {
        failure(
            "login.rollback",
            "rollback-failed",
            false,
            result,
            ExitCode::FAILURE,
        )
    }
}

fn rollback_journal(paths: &Paths, journal: &mut Journal) -> Value {
    let mut operations = Vec::new();
    let mut restored = true;
    for target in journal.targets.iter().rev() {
        let Some(spec) = target_from_name(paths, &journal.display_manager, &target.name) else {
            restored = false;
            continue;
        };
        let current = match FileImage::from_path(&spec.etc) {
            Ok(current) => current,
            Err(_) => {
                restored = false;
                operations.push(json!({"target": target.name, "result": "failed"}));
                continue;
            }
        };
        if current != target.before && current != target.after {
            restored = false;
            operations.push(json!({"target": target.name, "result": "failed"}));
            continue;
        }
        if current != target.before && apply_image(&spec.etc, &target.before).is_err() {
            restored = false;
            operations.push(json!({"target": target.name, "result": "failed"}));
            continue;
        }
        operations.push(json!({"target": target.name, "result": "restored"}));
    }
    operations.reverse();
    if restored {
        journal.state = TransactionState::RolledBack;
        if save_journal(paths, journal).is_err() {
            restored = false;
        }
    }
    json!({
        "transaction_id": journal.transaction_id,
        "state": if restored { "rolled-back" } else { "failed" },
        "restored": restored,
        "operations": operations
    })
}

fn status(paths: &Paths) -> ExitCode {
    if !matches!(paths.display_manager.as_str(), "plasmalogin" | "sddm") {
        return failure(
            "login.status",
            "unsupported-display-manager",
            false,
            json!({}),
            ExitCode::FAILURE,
        );
    }
    let login = target_from_name(
        paths,
        &paths.display_manager,
        &format!("pam-service:{}", paths.display_manager),
    )
    .expect("supported login target");
    let lock =
        target_from_name(paths, &paths.display_manager, "pam-service:kde").expect("lock target");
    let login_enabled = target_enabled(&login);
    let lock_enabled = target_enabled(&lock);
    let (actual, drift) = match (login_enabled, lock_enabled) {
        (true, true) => ("enabled", false),
        (false, false) => ("disabled", false),
        _ => ("mixed", true),
    };
    let fallback = [login, lock].iter().all(|target| {
        effective_current_bytes(target).is_ok_and(|bytes| has_password_fallback(&bytes))
    });
    success(
        "login.status",
        json!({
            "display_manager": {
                "id": paths.display_manager,
                "supported": true
            },
            "desired": actual,
            "actual": actual,
            "drift": drift,
            "password_fallback": {
                "present": fallback,
                "verified": fallback
            },
            "targets": [
                {"id": "lock-screen", "state": if lock_enabled { "enabled" } else { "disabled" }},
                {"id": "login-screen", "state": if login_enabled { "enabled" } else { "disabled" }}
            ]
        }),
    )
}

fn target_enabled(target: &Target) -> bool {
    std::fs::read_to_string(&target.etc).is_ok_and(|content| {
        content.lines().any(|line| {
            let line = line.trim_start();
            !line.starts_with('#') && line.contains("pam_irlume.so")
        })
    })
}

fn effective_current_bytes(target: &Target) -> Result<Vec<u8>, String> {
    let current = FileImage::from_path(&target.etc)?;
    if current.present {
        current.bytes()
    } else {
        FileImage::from_path(&target.vendor)?.bytes()
    }
}

fn target_from_name(paths: &Paths, display_manager: &str, name: &str) -> Option<Target> {
    if name == "pam-service:kde" {
        return Some(Target {
            name: name.into(),
            etc: paths.pam_etc.join("kde"),
            vendor: paths.pam_vendor.join("kde"),
        });
    }
    if matches!(display_manager, "plasmalogin" | "sddm")
        && name == format!("pam-service:{display_manager}")
    {
        return Some(Target {
            name: name.into(),
            etc: paths.pam_etc.join(display_manager),
            vendor: paths.pam_vendor.join(display_manager),
        });
    }
    None
}

fn targets_match(paths: &Paths, journal: &Journal) -> bool {
    journal.targets.iter().all(|target| {
        target_from_name(paths, &journal.display_manager, &target.name)
            .and_then(|spec| FileImage::from_path(&spec.etc).ok())
            .is_some_and(|current| current == target.after)
    })
}

fn effective_journal_bytes(
    paths: &Paths,
    journal: &Journal,
    target: &JournalTarget,
) -> Result<Vec<u8>, String> {
    if target.after.present {
        target.after.bytes()
    } else {
        let spec = target_from_name(paths, &journal.display_manager, &target.name)
            .ok_or_else(|| "unsafe journal target".to_string())?;
        FileImage::from_path(&spec.vendor)?.bytes()
    }
}

fn apply_image(path: &Path, image: &FileImage) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "target has no parent".to_string())?;
    if !image.present {
        if path.exists() {
            std::fs::remove_file(path).map_err(|error| format!("remove failed: {error}"))?;
            sync_directory(parent)?;
        }
        return Ok(());
    }
    let bytes = image.bytes()?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "invalid target name".to_string())?;
    let temporary = parent.join(format!(
        ".{name}.irlume-transaction-{:016x}",
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(image.mode)
            .open(&temporary)
            .map_err(|error| format!("create temporary failed: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write failed: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync failed: {error}"))?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(image.mode))
            .map_err(|error| format!("permissions failed: {error}"))?;
        std::fs::rename(&temporary, path).map_err(|error| format!("rename failed: {error}"))?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("directory sync failed: {error}"))
}

fn journal_path(paths: &Paths, transaction_id: &str) -> PathBuf {
    paths.transactions.join(format!("{transaction_id}.json"))
}

fn save_journal(paths: &Paths, journal: &Journal) -> Result<(), String> {
    std::fs::create_dir_all(&paths.transactions)
        .map_err(|error| format!("create journal directory failed: {error}"))?;
    std::fs::set_permissions(&paths.transactions, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("journal directory permissions failed: {error}"))?;
    let bytes = serde_json::to_vec(journal).map_err(|error| error.to_string())?;
    irlume_common::write_0600_atomic(&journal_path(paths, &journal.transaction_id), &bytes)
        .map_err(|error| format!("write journal failed: {error}"))
}

fn load_journal(paths: &Paths, transaction_id: &str) -> Result<Journal, &'static str> {
    let bytes =
        std::fs::read(journal_path(paths, transaction_id)).map_err(|_| "transaction-not-found")?;
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|_| "transaction-journal-corrupt")?;
    if journal.version != 1
        || journal.transaction_id != transaction_id
        || !matches!(journal.display_manager.as_str(), "plasmalogin" | "sddm")
        || journal.targets.is_empty()
        || journal.targets.len() > 2
        || journal
            .targets
            .iter()
            .any(|target| target_from_name(paths, &journal.display_manager, &target.name).is_none())
    {
        return Err("transaction-journal-corrupt");
    }
    Ok(journal)
}

fn valid_plan_id(value: &str) -> bool {
    value.strip_prefix("plan-").is_some_and(|suffix| {
        suffix.len() == 64 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn valid_transaction_id(value: &str) -> bool {
    value.strip_prefix("transaction-").is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn digest(bytes: &[u8]) -> String {
    let value = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        std::fmt::Write::write_fmt(&mut encoded, format_args!("{byte:02x}"))
            .expect("writing to a String cannot fail");
    }
    encoded
}

fn success(command: &'static str, data: Value) -> ExitCode {
    emit(command, true, data, None, ExitCode::SUCCESS)
}

fn failure(
    command: &'static str,
    code: &str,
    retryable: bool,
    data: Value,
    exit: ExitCode,
) -> ExitCode {
    emit(
        command,
        false,
        data,
        Some(json!({"code": code, "retryable": retryable})),
        exit,
    )
}

fn emit(
    command: &'static str,
    ok: bool,
    data: Value,
    error: Option<Value>,
    exit: ExitCode,
) -> ExitCode {
    let mut document = json!({
        "contract_version": CONTRACT_VERSION,
        "engine_version": env!("CARGO_PKG_VERSION"),
        "command": command,
        "ok": ok,
        "data": data
    });
    if let Some(error) = error {
        document
            .as_object_mut()
            .expect("machine document is an object")
            .insert("error".into(), error);
    }
    println!(
        "{}",
        serde_json::to_string(&document).expect("machine document serializes")
    );
    exit
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAM_STOCK: &str =
        "#%PAM-1.0\nauth substack password-auth\naccount required pam_unix.so\n";

    struct Sandbox {
        root: PathBuf,
        paths: Paths,
    }

    impl Sandbox {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "irlume-login-transaction-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            let pam_etc = root.join("etc");
            let pam_vendor = root.join("vendor");
            std::fs::create_dir_all(&pam_etc).unwrap();
            std::fs::create_dir_all(&pam_vendor).unwrap();
            std::fs::write(pam_vendor.join("plasmalogin"), PAM_STOCK).unwrap();
            std::fs::write(pam_vendor.join("kde"), PAM_STOCK).unwrap();
            Self {
                paths: Paths {
                    pam_etc,
                    pam_vendor,
                    transactions: root.join("transactions"),
                    display_manager: "plasmalogin".into(),
                },
                root,
            }
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn facts() -> Facts {
        Facts {
            healthy: true,
            enrolled: true,
            tier: "secure".into(),
            selinux_ready: true,
        }
    }

    #[test]
    fn plan_is_read_only_bounded_and_bound_to_observed_state() {
        let sandbox = Sandbox::new("plan");
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "login-screen").unwrap();
        assert!(valid_plan_id(&plan.plan_id));
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].target.name, "pam-service:plasmalogin");
        assert!(!sandbox.paths.pam_etc.join("plasmalogin").exists());
        assert!(!sandbox.paths.transactions.exists());

        std::fs::write(
            sandbox.paths.pam_etc.join("plasmalogin"),
            format!("{PAM_STOCK}# admin change\n"),
        )
        .unwrap();
        let changed =
            build_plan(&sandbox.paths, &facts(), Operation::Enable, "login-screen").unwrap();
        assert_ne!(plan.plan_id, changed.plan_id);
    }

    #[test]
    fn plan_document_matches_the_public_consumer_contract() {
        let sandbox = Sandbox::new("plan-document");
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "login-screen").unwrap();
        let document = plan_json(&plan);
        assert_eq!(document["operation"], "enable");
        assert_eq!(document["plan_id"], plan.plan_id);
        assert_eq!(document["apply"], false);
        assert_eq!(document["mutated"], false);
        assert_eq!(document["display_manager"]["id"], "plasmalogin");
        assert_eq!(document["display_manager"]["supported"], true);
        assert_eq!(document["security_tier"], "secure");
        assert_eq!(document["requested_scopes"], json!(["login-screen"]));
        assert_eq!(document["changes"].as_array().unwrap().len(), 1);
        assert_eq!(document["changes"][0]["target"], "pam-service:plasmalogin");
        assert_eq!(document["password_fallback"]["preserved"], true);
        for required in [
            "engine.healthy",
            "profile.enrolled",
            "login.password-fallback",
        ] {
            assert!(document["preconditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check["id"] == required && check["state"] == "pass"));
        }
    }

    #[test]
    fn disable_plan_is_limited_to_login_and_lock_targets() {
        let sandbox = Sandbox::new("disable-plan");
        let mut no_profile = facts();
        no_profile.enrolled = false;
        let plan = build_plan(&sandbox.paths, &no_profile, Operation::Disable, "disable").unwrap();
        let targets: Vec<_> = plan
            .targets
            .iter()
            .map(|target| target.target.name.as_str())
            .collect();
        assert_eq!(targets, vec!["pam-service:plasmalogin", "pam-service:kde"]);
        assert!(plan
            .preconditions
            .iter()
            .all(|precondition| precondition["state"] == "pass"));
    }

    #[test]
    fn missing_password_fallback_fails_the_plan_precondition() {
        let sandbox = Sandbox::new("fallback");
        std::fs::write(
            sandbox.paths.pam_vendor.join("kde"),
            "#%PAM-1.0\nauth required pam_deny.so\n",
        )
        .unwrap();
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "lock-screen").unwrap();
        assert!(!plan.password_fallback);
        assert!(plan
            .preconditions
            .iter()
            .any(
                |precondition| precondition["id"] == "login.password-fallback"
                    && precondition["state"] == "fail"
            ));
    }

    #[test]
    fn apply_verify_and_idempotent_rollback_preserve_lineage() {
        let sandbox = Sandbox::new("lifecycle");
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "login-screen").unwrap();
        assert_eq!(
            apply(
                &sandbox.paths,
                &facts(),
                Operation::Enable,
                "login-screen",
                &plan.plan_id,
                false,
            ),
            ExitCode::SUCCESS
        );
        let wired = std::fs::read_to_string(sandbox.paths.pam_etc.join("plasmalogin")).unwrap();
        assert!(wired.contains("pam_irlume.so"));
        assert!(has_password_fallback(wired.as_bytes()));

        let transaction_id = std::fs::read_dir(&sandbox.paths.transactions)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            std::fs::metadata(&sandbox.paths.transactions)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(journal_path(&sandbox.paths, &transaction_id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            verify(&sandbox.paths, &facts(), &transaction_id),
            ExitCode::SUCCESS
        );
        assert_eq!(rollback(&sandbox.paths, &transaction_id), ExitCode::SUCCESS);
        assert!(!sandbox.paths.pam_etc.join("plasmalogin").exists());
        assert_eq!(rollback(&sandbox.paths, &transaction_id), ExitCode::SUCCESS);
    }

    #[test]
    fn state_drift_rejects_apply_without_writing() {
        let sandbox = Sandbox::new("drift");
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "lock-screen").unwrap();
        let path = sandbox.paths.pam_etc.join("kde");
        std::fs::write(&path, format!("{PAM_STOCK}# foreign\n")).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_ne!(
            apply(
                &sandbox.paths,
                &facts(),
                Operation::Enable,
                "lock-screen",
                &plan.plan_id,
                false,
            ),
            ExitCode::SUCCESS
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!sandbox.paths.transactions.exists());
    }

    #[test]
    fn failed_post_apply_verification_rolls_back_automatically() {
        let sandbox = Sandbox::new("auto-rollback");
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "lock-screen").unwrap();
        assert_ne!(
            apply(
                &sandbox.paths,
                &facts(),
                Operation::Enable,
                "lock-screen",
                &plan.plan_id,
                true,
            ),
            ExitCode::SUCCESS
        );
        assert!(!sandbox.paths.pam_etc.join("kde").exists());
        let journal_path = std::fs::read_dir(&sandbox.paths.transactions)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let journal: Journal =
            serde_json::from_slice(&std::fs::read(journal_path).unwrap()).unwrap();
        assert_eq!(journal.state, TransactionState::RolledBack);
    }

    #[test]
    fn rollback_refuses_to_overwrite_an_unrelated_post_apply_edit() {
        let sandbox = Sandbox::new("foreign-edit");
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "lock-screen").unwrap();
        assert_eq!(
            apply(
                &sandbox.paths,
                &facts(),
                Operation::Enable,
                "lock-screen",
                &plan.plan_id,
                false,
            ),
            ExitCode::SUCCESS
        );
        let transaction_id = std::fs::read_dir(&sandbox.paths.transactions)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let target = sandbox.paths.pam_etc.join("kde");
        let mut edited = std::fs::read_to_string(&target).unwrap();
        edited.push_str("# unrelated admin edit\n");
        std::fs::write(&target, &edited).unwrap();

        assert_ne!(rollback(&sandbox.paths, &transaction_id), ExitCode::SUCCESS);
        assert_eq!(std::fs::read_to_string(target).unwrap(), edited);
    }

    #[test]
    fn display_manager_drift_does_not_block_tty_rollback() {
        let mut sandbox = Sandbox::new("dm-drift");
        let plan = build_plan(&sandbox.paths, &facts(), Operation::Enable, "login-screen").unwrap();
        assert_eq!(
            apply(
                &sandbox.paths,
                &facts(),
                Operation::Enable,
                "login-screen",
                &plan.plan_id,
                false,
            ),
            ExitCode::SUCCESS
        );
        let transaction_id = std::fs::read_dir(&sandbox.paths.transactions)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        sandbox.paths.display_manager = "sddm".into();

        assert_ne!(
            verify(&sandbox.paths, &facts(), &transaction_id),
            ExitCode::SUCCESS
        );
        assert_eq!(rollback(&sandbox.paths, &transaction_id), ExitCode::SUCCESS);
        assert!(!sandbox.paths.pam_etc.join("plasmalogin").exists());
    }

    #[test]
    fn only_reviewed_display_managers_and_opaque_ids_are_accepted() {
        let mut sandbox = Sandbox::new("allowlist");
        sandbox.paths.display_manager = "gdm".into();
        assert!(matches!(
            build_plan(&sandbox.paths, &facts(), Operation::Enable, "login-screen"),
            Err("unsupported-display-manager")
        ));
        assert!(valid_plan_id(&format!("plan-{}", "a".repeat(64))));
        assert!(!valid_plan_id("plan-../etc/shadow"));
        assert!(valid_transaction_id(&format!(
            "transaction-{}",
            "f".repeat(32)
        )));
        assert!(!valid_transaction_id("transaction-/tmp/x"));
    }

    #[test]
    fn machine_argument_parser_rejects_unknown_and_duplicate_flags() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        assert!(parse_flags(&args(&[
            "login",
            "enable",
            "--scope",
            "lock-screen",
            "--json"
        ]))
        .is_ok());
        assert!(parse_flags(&args(&[
            "login",
            "enable",
            "--scope",
            "lock-screen",
            "--json",
            "--json"
        ]))
        .is_err());
        assert!(parse_flags(&args(&[
            "login",
            "enable",
            "--scope",
            "lock-screen",
            "--json",
            "--path",
            "/etc/pam.d/evil"
        ]))
        .is_err());
    }
}
