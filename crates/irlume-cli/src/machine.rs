// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Public, versioned machine output for desktop integrations.
//!
//! Keep this module deliberately narrower than the daemon's private wire
//! protocol. A capability is advertised only after its public command, output
//! shape, and compatibility rules are covered here and in `docs/MACHINE-API.md`.

use irlume_common::{OperationErrorCode, ProfileSummary, Request, Response};
use serde::Serialize;
use serde_json::{json, Value};
use std::process::ExitCode;

/// Lowest contract this build can speak.
pub const CONTRACT_MIN: u32 = 1;
/// Highest contract this build can speak. Bumping this is a deliberate act: it
/// means a second set of semantics now exists and both must be served.
pub const CONTRACT_MAX: u32 = 1;

/// What a caller gets when it does not say which contract it implements.
///
/// This is pinned to the FIRST contract and must never track `CONTRACT_MAX`.
/// A consumer written against contract 1 that omits the flag has to keep
/// receiving contract 1 on an engine that has since learned contract 2, or the
/// engine would silently change the meaning of a response under a program that
/// never asked for it. "Newest" is the one thing a default must not mean here.
pub const CONTRACT_DEFAULT: u32 = 1;

const CAPABILITIES: &[&str] = &[
    "version-json",
    "profiles-list-json",
    "status-json",
    "doctor-json",
    "login-status-json",
    "auth-test-events",
    "login-plan-json",
    "login-transactions",
    "models-list-json",
];

/// The contract the caller asked for, or the failure to report.
///
/// Parsed before anything else happens, so an unsupported request is refused
/// before the daemon is contacted and before any command with side effects can
/// begin. There are no mutating machine commands yet; this exists so that when
/// one arrives it cannot be reached without an agreed contract.
enum Contract {
    Agreed(u32),
    Malformed,
    Unsupported,
}

/// Read `--contract N` out of an argument list.
///
/// Deliberately tolerant of absence and intolerant of everything else: a
/// repeated flag, a missing value, a non-numeric value and an out-of-range
/// version are all refusals rather than guesses.
fn negotiate(args: &[String]) -> Contract {
    let mut requested: Option<u32> = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--contract" {
            if requested.is_some() {
                return Contract::Malformed;
            }
            let Some(raw) = args.get(index + 1) else {
                return Contract::Malformed;
            };
            let Ok(version) = raw.parse::<u32>() else {
                return Contract::Malformed;
            };
            requested = Some(version);
            index += 2;
            continue;
        }
        index += 1;
    }
    match requested {
        None => Contract::Agreed(CONTRACT_DEFAULT),
        Some(v) if (CONTRACT_MIN..=CONTRACT_MAX).contains(&v) => Contract::Agreed(v),
        Some(_) => Contract::Unsupported,
    }
}

/// Strip `--contract N` so each command's own validator sees only its flags.
fn without_contract(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--contract" {
            index += 2;
            continue;
        }
        out.push(args[index].clone());
        index += 1;
    }
    out
}

#[derive(Serialize)]
struct Document {
    contract_version: u32,
    engine_version: &'static str,
    command: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<MachineError>,
}

#[derive(Serialize)]
struct MachineError {
    code: &'static str,
    retryable: bool,
}

fn success(command: &'static str, data: Value, contract: u32) -> Document {
    Document {
        // Echo the contract actually in force, so a consumer can assert the
        // engine agreed to the one it implements rather than inferring it.
        contract_version: contract,
        engine_version: env!("CARGO_PKG_VERSION"),
        command,
        ok: true,
        data: Some(data),
        error: None,
    }
}

fn failure(command: &'static str, code: &'static str, retryable: bool, contract: u32) -> Document {
    Document {
        contract_version: contract,
        engine_version: env!("CARGO_PKG_VERSION"),
        command,
        ok: false,
        data: None,
        error: Some(MachineError { code, retryable }),
    }
}

/// Map a daemon outcome to a published error code. The mapping is total: an
/// `Unknown` code from a newer daemon degrades to the generic failure rather
/// than inventing a meaning for it.
fn error_code(code: OperationErrorCode) -> &'static str {
    match code {
        OperationErrorCode::NotAuthorized => "not-authorized",
        OperationErrorCode::OperationFailed | OperationErrorCode::Unknown => "operation-failed",
    }
}

/// One line of an NDJSON event stream.
///
/// The envelope deliberately repeats `contract_version`, `engine_version` and
/// `command` on every line rather than sending a header once. A consumer that
/// reconnects, tails, or drops a line still knows what it is reading, and a
/// line is meaningful on its own in a log.
#[derive(Serialize)]
struct Event {
    contract_version: u32,
    engine_version: &'static str,
    command: &'static str,
    /// Stable for the whole stream: ties every line to one invocation.
    operation_id: String,
    /// Which exclusive session produced this stream. Distinct from
    /// `operation_id` so a future resumable operation can keep the session
    /// while starting a new operation within it.
    session_id: String,
    /// From zero, incrementing by one, no gaps. A consumer detects a lost line
    /// by arithmetic rather than by guessing.
    sequence: u64,
    event: &'static str,
    /// True on exactly one line, always the last. This is the guarantee that
    /// lets a consumer stop reading without a timeout.
    terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<MachineError>,
}

/// Emits an NDJSON event stream, owning the sequence and the terminal rule.
///
/// The invariants a consumer is promised cannot be maintained by callers
/// remembering to maintain them, so they live here: the sequence is private and
/// only ever incremented, and finishing consumes the stream so a second
/// terminal line is not expressible.
struct EventStream {
    command: &'static str,
    contract: u32,
    operation_id: String,
    session_id: String,
    sequence: u64,
}

impl EventStream {
    fn new(command: &'static str, contract: u32, session_id: String) -> Self {
        Self {
            command,
            contract,
            operation_id: random_id(),
            session_id,
            sequence: 0,
        }
    }

    fn line(
        &mut self,
        event: &'static str,
        terminal: bool,
        data: Option<Value>,
        error: Option<MachineError>,
    ) {
        let line = Event {
            contract_version: self.contract,
            engine_version: env!("CARGO_PKG_VERSION"),
            command: self.command,
            operation_id: self.operation_id.clone(),
            session_id: self.session_id.clone(),
            sequence: self.sequence,
            event,
            terminal,
            data,
            error,
        };
        self.sequence += 1;
        match serde_json::to_string(&line) {
            // Flush per line: a consumer reads this incrementally, and a block
            // buffer would deliver "started" and "result" together, defeating
            // the point of streaming.
            Ok(text) => {
                use std::io::Write;
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{text}");
                let _ = out.flush();
            }
            Err(error) => eprintln!("irlume machine event serialization failed: {error}"),
        }
    }

    /// A non-terminal progress line.
    fn progress(&mut self, event: &'static str, data: Value) {
        self.line(event, false, Some(data), None);
    }

    /// The single terminal line. Consumes the stream, so no line can follow it.
    fn finish(mut self, event: &'static str, data: Value, exit: ExitCode) -> ExitCode {
        self.line(event, true, Some(data), None);
        exit
    }

    /// The single terminal line, as a failure.
    fn fail(mut self, code: &'static str, retryable: bool) -> ExitCode {
        self.line("error", true, None, Some(MachineError { code, retryable }));
        ExitCode::FAILURE
    }
}

/// A 128-bit random identifier, hex encoded.
///
/// Random rather than sequential: an identifier a consumer may log or display
/// should not encode how many operations this machine has run.
fn random_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn emit(document: &Document, exit: ExitCode) -> ExitCode {
    // Serialization only contains compile-time strings and serde_json values,
    // so failure would be a programming error. Keep stdout machine-only even
    // in that case and report the detail on stderr.
    match serde_json::to_string(document) {
        Ok(line) => {
            println!("{line}");
            exit
        }
        Err(error) => {
            eprintln!("irlume machine output serialization failed: {error}");
            ExitCode::FAILURE
        }
    }
}

pub fn version(args: &[String]) -> ExitCode {
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure("version", "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure("version", "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    if without_contract(args) != ["version", "--json"] {
        return emit(
            &failure("version", "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    emit(
        &success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                // The range this build can speak. A consumer should pick a
                // version inside it and pass `--contract`, rather than reading
                // `contract_version` off a response and hoping.
                "contract_versions": { "min": CONTRACT_MIN, "max": CONTRACT_MAX },
                "limits": {
                    // Read the engine's own constant rather than repeating the
                    // number. A consumer displays this as the enrollment limit,
                    // so a literal here would silently start lying the day the
                    // store's limit changes.
                    "max_profiles": irlume_core::storage::MAX_PROFILES
                }
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

/// `irlume status --json`: the readiness summary a desktop integration needs,
/// as values rather than prose.
///
/// Deliberately narrower than the human `status`. It omits camera device paths
/// and the account name: a consumer needs to know whether an IR camera is
/// usable, not which node it is, and it already knows which account it asked
/// about. Everything here is derived from the same sources the human command
/// reads, so the two cannot disagree about the machine's state, only about how
/// it is worded.
pub fn status(args: &[String]) -> ExitCode {
    const COMMAND: &str = "status";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    if !valid_status_args(args) {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    let user = crate::user_arg(args);

    // Reachability is reported, not fatal: a consumer wants to render "the
    // daemon is not answering" rather than receive an error with no detail, and
    // the fields that do not need the daemon are still worth having.
    let daemon = match crate::commands::daemon_reach() {
        crate::commands::DaemonReach::Running => "running",
        crate::commands::DaemonReach::AccessDenied => "access-denied",
        crate::commands::DaemonReach::Down => "unreachable",
    };

    let method = irlume_core::policy::method();
    let enrollment = match crate::daemon_request(&Request::ListProfiles {
        user: user.clone(),
        structured_errors: true,
    }) {
        Ok(Response::Enrollment { profiles, .. }) => {
            let scans: usize = profiles.iter().map(|p| p.scans.len()).sum();
            json!({ "known": true, "profiles": profiles.len(), "scans": scans })
        }
        // Unknown is not zero. A consumer must be able to tell "this account has
        // no face enrolled" from "we could not find out".
        _ => json!({ "known": false }),
    };

    let keyring = match crate::daemon_request(&Request::KeyringInfo { user: user.clone() }) {
        Ok(Response::KeyringInfo { armed, policy, .. }) => {
            json!({ "known": true, "armed": armed, "policy": policy })
        }
        _ => json!({ "known": false }),
    };

    let (templates, recovery) = match crate::daemon_request(&Request::RecoveryStatus { user }) {
        Ok(Response::RecoveryStatus {
            encrypted,
            recovery_set,
            key_present,
            ..
        }) => (
            // `templates` stays the documented STRING with its two values, so a
            // contract 1 consumer is unaffected. The orphaned case rides along
            // on `recovery.key_present`, an ADDED field, which contract 1
            // permits; a new enum value in `templates` would not be.
            json!(if encrypted { "encrypted" } else { "plaintext" }),
            json!({
                "known": true,
                "passphrase_set": recovery_set,
                "key_present": key_present,
            }),
        ),
        _ => (json!("unknown"), json!({ "known": false })),
    };

    // Camera capability, not camera identity: whether each spectrum resolved to
    // a device that is actually THERE, never which one.
    //
    // Emptiness is not the test. `select_pair` falls back to the compiled
    // default node names when discovery finds nothing, so the strings are never
    // empty and this reported `{"rgb":true,"ir":true}` on a machine with no
    // camera at all: in a container, on a desktop without one, or before the
    // nodes appear at boot. A consumer reading that offers face setup, or shows
    // Secure-tier hardware, that does not exist. The daemon's own Health reply
    // has always paired the capability probe with an existence check; this now
    // agrees with it.
    let caps = crate::caps();
    let (rgb, ir) = crate::camera_pair();
    let camera = json!({
        "rgb": caps.rgb && std::path::Path::new(&rgb).exists(),
        "ir": caps.ir_pair && std::path::Path::new(&ir).exists(),
    });

    emit(
        &success(
            COMMAND,
            json!({
                "daemon": daemon,
                "auth_method": format!("{method:?}").to_lowercase(),
                "face_disabled": method.face_disabled(),
                "enrollment": enrollment,
                "templates": templates,
                "keyring": keyring,
                "recovery": recovery,
                "camera": camera,
                // "Whether a fingerprint reader was found", as the schema puts
                // it: fprintd present AND a reader present, the same predicate
                // doctor's line and its `fingerprint-reader` check use. Naming
                // the device is a narrower question and disagreed with both.
                "fingerprint": irlume_fingerprint::available(),
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

fn valid_status_args(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("status") {
        return false;
    }
    let mut saw_json = false;
    let mut saw_user = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
            }
            "--user" if !saw_user => {
                saw_user = true;
                let Some(user) = args.get(index + 1) else {
                    return false;
                };
                if user.is_empty() || user.starts_with('-') {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    saw_json
}

/// `irlume doctor --json`: every readiness check as an identified result.
///
/// The array is complete. A consumer may assume that a check it knows about and
/// does not find here was not run by this engine version, rather than that it
/// passed silently, which is why this shipped all at once instead of check by
/// check.
pub fn doctor(args: &[String]) -> ExitCode {
    const COMMAND: &str = "doctor";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = without_contract(args);
    if args != ["doctor", "--json"] {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    let mut report = crate::doctor_report::Report::new(crate::doctor_report::Mode::Collect);
    // Same pass the human report makes, printing nothing.
    // The machine path is deliberately strict about argv, so it passes none:
    // `--user` is not part of contract 1.
    let _ = crate::doctor_run(&mut report, &[]);
    let checks = report.into_checks();
    emit(
        &success(COMMAND, json!({ "checks": checks }), contract),
        ExitCode::SUCCESS,
    )
}

/// `irlume login status --json`: which PAM surfaces carry face auth.
///
/// Reads the same PAM files the human report reads, in the same pass, so the
/// two cannot disagree about what is wired. It publishes PAM SERVICE NAMES
/// rather than `/etc/pam.d` paths, for the same reason `status --json` reports
/// camera capability rather than camera nodes: a consumer needs to know which
/// surface is wired, not where the file lives.
pub fn login_status(args: &[String]) -> ExitCode {
    const COMMAND: &str = "login.status";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    if without_contract(args) != ["login", "status", "--json"] {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }

    let manager = crate::pamwire::login_manager_fact();
    // Unknown is not "none". A host with no `display-manager.service` may be
    // headless or may run a greeter that registers none; either way the engine
    // did not find out, and a consumer must not render that as "no login
    // manager is installed".
    let login_manager = match &manager.name {
        Some(name) => json!({
            "known": true,
            "name": name,
            "recognized": manager.recognized,
            "services": manager.services,
        }),
        None => json!({ "known": false }),
    };

    let surfaces: Vec<Value> = crate::pamwire::surface_facts()
        .iter()
        .map(|s| {
            let mut entry = json!({
                "id": s.id,
                "role": s.role,
                "present": s.present,
                "wired": s.wired,
            });
            // Absent rather than null when not wired: there is no mode to
            // report, and an explicit null invites a consumer to render one.
            if let Some(mode) = s.mode {
                entry["mode"] = json!(mode);
            }
            entry
        })
        .collect();

    let selinux_module = match crate::pamwire::selinux_state() {
        Some(true) => "loaded",
        Some(false) => "not-loaded",
        // The policy store needs root to read, so an ordinary caller gets
        // `unknown` here. It is not a synonym for "not loaded".
        None => "unknown",
    };

    emit(
        &success(
            COMMAND,
            json!({
                "login_manager": login_manager,
                "surfaces": surfaces,
                "selinux_module": selinux_module,
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

/// `irlume login plan --json`: what `login enable` or `login disable` would
/// change, without changing anything.
///
/// The plan phase of a login transaction. It runs the identical decision the
/// apply path runs, with writing switched off, so a plan cannot describe an
/// outcome the apply would not produce. Reading PAM files needs no privilege;
/// `requires_root` says that applying does.
///
/// `plan_id` is a digest of the intended action and the state the plan was
/// computed against. It exists so that a later apply can refuse a plan that no
/// longer matches the machine, rather than silently doing something the
/// consumer never displayed. Apply is not implemented yet, so nothing consumes
/// the id; publishing it now means the identifier a consumer stores today is
/// the one apply will check tomorrow.
pub fn login_plan(args: &[String]) -> ExitCode {
    const COMMAND: &str = "login.plan";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    let Some(action) = valid_login_plan_args(args) else {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    };
    let enable = action == "enable";
    // Sudo and polkit are opt-in on the human command and stay opt-in here, so
    // a plan a panel shows never quietly includes surfaces the user did not ask
    // for. Both default off.
    let planned = crate::pamwire::plan(enable, false, false);
    let changes: Vec<Value> = planned
        .iter()
        .map(|surface| {
            json!({
                "surface": surface.id,
                "role": surface.role,
                "change": surface.change.id(),
                "writes": surface.change.writes(),
            })
        })
        .collect();
    let writes = planned.iter().filter(|s| s.change.writes()).count();
    emit(
        &success(
            COMMAND,
            json!({
                "plan_id": plan_id(action, &planned),
                "action": action,
                "changes": changes,
                // Counted here rather than left to the consumer, so "nothing to
                // do" is a fact the engine states instead of one a panel infers
                // from change names it may not recognise.
                "writes": writes,
                "requires_root": writes > 0,
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

/// A digest of the action and the exact per-surface outcomes it was computed
/// against.
///
/// Deliberately covers the outcomes rather than a timestamp or a counter: two
/// plans over an unchanged machine share an id, and any change to what would
/// happen produces a different one. That is the property an apply needs to
/// decide whether the plan it was handed still describes this machine.
fn plan_id(action: &str, planned: &[crate::pamwire::PlannedSurface]) -> String {
    let mut material = String::from(action);
    for surface in planned {
        material.push('\n');
        material.push_str(surface.id);
        material.push(' ');
        material.push_str(surface.change.id());
        material.push(' ');
        // The observed state, not just the intended outcome. Without this an
        // admin could rewrite a stack, leave the anchor intact so the outcome
        // stays `wire`, and an apply carrying the old id would overwrite a stack
        // the consumer never saw.
        material.push_str(&surface.state);
    }
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(material.as_bytes());
    // Half the digest. This identifies a plan for a consumer to hand back; it
    // is not a security boundary, and apply re-derives the plan from the
    // machine rather than trusting anything the id encodes.
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

fn valid_login_plan_args(args: &[String]) -> Option<&'static str> {
    if args.first().map(String::as_str) != Some("login")
        || args.get(1).map(String::as_str) != Some("plan")
    {
        return None;
    }
    let mut action: Option<&'static str> = None;
    let mut saw_json = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
            }
            "--action" if action.is_none() => {
                action = match args.get(index + 1).map(String::as_str) {
                    Some("enable") => Some("enable"),
                    Some("disable") => Some("disable"),
                    _ => return None,
                };
                index += 2;
            }
            _ => return None,
        }
    }
    // Both required: a plan with no stated action would have to guess whether
    // the consumer meant to turn login on or off.
    if saw_json {
        action
    } else {
        None
    }
}

/// Root, or the reason to refuse.
///
/// Checked in the command rather than left to the write failing with EACCES:
/// a mutating command that gets partway before losing permission leaves a PAM
/// stack half-changed, and `not-authorized` up front is a better answer than a
/// partial apply.
fn require_root(command: &'static str, contract: u32) -> Option<ExitCode> {
    // SAFETY: geteuid cannot fail and touches no memory.
    if unsafe { libc::geteuid() } == 0 {
        return None;
    }
    Some(emit(
        &failure(command, "not-authorized", false, contract),
        ExitCode::FAILURE,
    ))
}

/// Emit a document with extra top-level fields merged in.
///
/// Used where a FAILURE still carries something the caller needs, such as the
/// transaction id of a partial apply. Contract 1 permits fields to be added, so
/// this stays inside the contract; putting the value on stderr would not,
/// because machine mode promises stderr is empty.
fn emit_with_extra(document: &Document, extra: Value, exit: ExitCode) -> ExitCode {
    let mut value = match serde_json::to_value(document) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("irlume machine output serialization failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let (Some(object), Some(fields)) = (value.as_object_mut(), extra.as_object()) {
        for (key, field) in fields {
            object.insert(key.clone(), field.clone());
        }
    }
    match serde_json::to_string(&value) {
        Ok(line) => {
            println!("{line}");
            exit
        }
        Err(error) => {
            eprintln!("irlume machine output serialization failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Report why a transaction record could not be loaded, without flattening the
/// reasons into one code. A caller told "not found" for a permission problem
/// would go looking for a wrong transaction id.
fn emit_load_failure(
    command: &'static str,
    reason: crate::logintx::LoadFailure,
    contract: u32,
) -> ExitCode {
    let code = match reason {
        crate::logintx::LoadFailure::NotFound => "not-found",
        crate::logintx::LoadFailure::NotAuthorized => "not-authorized",
        crate::logintx::LoadFailure::Unreadable(_) => "operation-failed",
        // Distinct from operation-failed: retrying will never help, and the
        // action a consumer should take is to run the newer irlume, not to
        // report a storage problem.
        crate::logintx::LoadFailure::TooNew { .. } => "unsupported-record",
    };
    emit(&failure(command, code, false, contract), ExitCode::FAILURE)
}

/// Each surface's state, and how many are not as apply left them.
///
/// Split out so it can be driven by a test with a record pointing at temporary
/// files: the command around it needs root and a real PAM tree, but this is the
/// part that decides the answer.
fn verify_surfaces(record: &crate::logintx::Transaction) -> (Vec<Value>, usize) {
    let surfaces: Vec<Value> = record
        .surfaces
        .iter()
        .map(|surface| {
            let state = match crate::logintx::unchanged_since_apply(surface) {
                Ok(()) => "as-applied",
                Err(crate::logintx::RollbackRefusal::ChangedSinceApply) => "changed-since-apply",
                Err(crate::logintx::RollbackRefusal::Unreadable(_)) => "unreadable",
            };
            json!({ "surface": surface.id, "state": state })
        })
        .collect();
    let drifted = surfaces
        .iter()
        .filter(|entry| entry["state"] != "as-applied")
        .count();
    (surfaces, drifted)
}

/// Restore every surface of a transaction, or report what it would restore.
///
/// Shared by the confirmed and the unconfirmed path so the restore itself has
/// one implementation. `unconfirmed` only changes what is reported: the writes
/// are identical, and the decision about whether restoring is safe was already
/// made by the caller.
fn rollback_restore(
    command: &'static str,
    record: &crate::logintx::Transaction,
    will_apply: bool,
    contract: u32,
    unconfirmed: bool,
) -> ExitCode {
    if !will_apply {
        return emit(
            &success(
                command,
                json!({
                    "transaction_id": record.id,
                    "action": record.action,
                    "unconfirmed": unconfirmed,
                    "would_restore": record.surfaces.iter().map(|s| json!(s.id)).collect::<Vec<_>>(),
                    "applied": false,
                }),
                contract,
            ),
            ExitCode::SUCCESS,
        );
    }
    // Refuse the whole record if it names anything irlume does not manage,
    // BEFORE restoring any of it. Checked here rather than at load so a record
    // can still be read and reported by verify; it is writing that is gated.
    if let Some(stray) = record
        .surfaces
        .iter()
        .find(|s| !crate::pamwire::is_managed_path(&s.path))
    {
        irlume_common::dlog!(
            "{command}: refusing, record names an unmanaged path: {}",
            stray.path
        );
        return emit(
            &failure(command, "unmanaged-path", false, contract),
            ExitCode::FAILURE,
        );
    }
    // An unconfirmed rollback writes over whatever is there without checking,
    // because its after-digests were never confirmed. That is how a machine
    // whose apply was interrupted gets recovered, and equally how a package
    // update or an administrator's later edit gets reverted. Copy it first, and
    // say where: nothing else captures what this is about to overwrite.
    let snapshot = if unconfirmed {
        match crate::logintx::snapshot_before_rollback(record) {
            Ok(dir) => Some(dir.display().to_string()),
            Err(message) => {
                irlume_common::dlog!("{command}: cannot snapshot before restoring: {message}");
                return emit(
                    &failure(command, "operation-failed", true, contract),
                    ExitCode::FAILURE,
                );
            }
        }
    } else {
        None
    };
    // What a previous run of this rollback already put back. Those surfaces are
    // skipped: they hold their before-content now, so re-restoring is pointless
    // and re-checking them against the after-digest would refuse the whole
    // record — which is what made a stopped rollback unfinishable.
    let mut progress = crate::logintx::rollback_progress(&record.id);
    // Marking a restore BEGUN before doing it, and finished after, is the same
    // write-ahead ordering the transaction record itself uses. Noting only
    // completions left the window between the write and the note: a kill there
    // leaves a surface holding its before-image with nothing recording it, and
    // the re-run refuses it as drift. Thirty killed rollbacks in a row were
    // unfinishable that way on real hardware.
    let begin = |progress: &mut crate::logintx::RollbackProgress, key: &str| {
        if !progress.started.iter().any(|k| k == key) {
            progress.started.push(key.to_string());
        }
        crate::logintx::note_rollback_progress(&record.id, progress)
    };
    for surface in &record.surfaces {
        let sidecar_key = crate::logintx::sidecar_progress_id(&surface.id);
        let live_done = progress.finished(&surface.id);
        let sidecar_done = progress.finished(&sidecar_key);
        if live_done && sidecar_done {
            continue;
        }
        // Re-check THIS surface immediately before restoring it. The blanket
        // check above happens before any write, which is what stops a rollback
        // half-completing, but it leaves a window: by the time the loop reaches
        // the last surface, the earlier ones have been written and time has
        // passed. Checking again here narrows the window to a single
        // check-and-write. Skipped for an unconfirmed record, whose digests were
        // never confirmed and so cannot gate anything.
        if !unconfirmed {
            if let Err(reason) = crate::logintx::unchanged_since_apply_excluding(surface, &progress)
            {
                irlume_common::dlog!(
                    "{command}: {} moved while the rollback was running: {reason:?}",
                    surface.id
                );
                return emit_with_extra(
                    &failure(command, "changed-since-apply", false, contract),
                    json!({
                        "transaction_id": record.id,
                        "restored": progress.done,
                        "stopped_at": surface.id,
                        // Where the pre-rollback copies are, so a caller that
                        // stopped partway can still find what was overwritten.
                        "snapshot": snapshot,
                    }),
                    ExitCode::FAILURE,
                );
            }
        }
        // Mode and ownership are restored with the content. All three come
        // from the same record, so a partial record restores what it has rather
        // than inventing values.
        let metadata = match (surface.mode, surface.uid, surface.gid) {
            (Some(mode), Some(uid), Some(gid)) => Some((mode, uid, gid)),
            _ => None,
        };
        let live = if live_done {
            Ok(())
        } else {
            // Announced before it happens. Restoring writes the recorded
            // before-content, so doing it twice is the same as doing it once,
            // which is what makes an interrupted one safe to repeat.
            begin(&mut progress, &surface.id).and_then(|()| {
                crate::pamwire::restore_surface(
                    std::path::Path::new(&surface.path),
                    surface.before.as_deref(),
                    metadata,
                )
            })
        };
        match live {
            Ok(()) => {
                // Noted BEFORE the backup is touched. Recording the two together
                // is what left a stop between them unresumable: the live file
                // held its before-image and nothing said so, so the re-run
                // checked it against the after-digest and refused it as drift.
                if !live_done {
                    progress.done.push(surface.id.clone());
                    if let Err(message) =
                        crate::logintx::note_rollback_progress(&record.id, &progress)
                    {
                        irlume_common::dlog!("{command}: cannot record progress: {message}");
                        return emit_with_extra(
                            &failure(command, "operation-failed", false, contract),
                            json!({
                                "transaction_id": record.id,
                                "restored": progress.done,
                                "stopped_at": surface.id,
                                "snapshot": snapshot,
                            }),
                            ExitCode::FAILURE,
                        );
                    }
                }
                // The backup is put back with its surface. Leaving a stale one
                // behind is not inert: a later enable rebuilds from it as the
                // origin, so it would silently discard an administrator's edits.
                if let Some(sidecar) = &surface
                    .sidecar
                    .as_ref()
                    .filter(|_| !sidecar_done)
                    .filter(|s| crate::pamwire::is_managed_path(&s.path))
                {
                    let sidecar_metadata = match (sidecar.mode, sidecar.uid, sidecar.gid) {
                        (Some(mode), Some(uid), Some(gid)) => Some((mode, uid, gid)),
                        _ => None,
                    };
                    if let Err(message) = crate::pamwire::restore_surface(
                        std::path::Path::new(&sidecar.path),
                        sidecar.before.as_deref(),
                        sidecar_metadata,
                    ) {
                        irlume_common::dlog!("{command}: {} backup failed: {message}", surface.id);
                        return emit_with_extra(
                            &failure(command, "operation-failed", false, contract),
                            json!({
                                "transaction_id": record.id,
                                "restored": progress.done,
                                "stopped_at": surface.id,
                            }),
                            ExitCode::FAILURE,
                        );
                    }
                }
                // The sidecar half, noted on its own. Durably, before moving
                // to the next surface: a note written after the whole loop would
                // describe only the runs that did not need it.
                progress.done.push(sidecar_key.clone());
                if let Err(message) = crate::logintx::note_rollback_progress(&record.id, &progress)
                {
                    irlume_common::dlog!("{command}: cannot record progress: {message}");
                    return emit_with_extra(
                        &failure(command, "operation-failed", false, contract),
                        json!({
                            "transaction_id": record.id,
                            "restored": progress.done,
                            "stopped_at": surface.id,
                            "snapshot": snapshot,
                        }),
                        ExitCode::FAILURE,
                    );
                }
            }
            Err(message) => {
                irlume_common::dlog!("{command}: {} failed: {message}", surface.id);
                // What was already restored travels in the document, because
                // machine mode promises an empty stderr and a caller stopped
                // partway needs to know exactly how far it got.
                return emit_with_extra(
                    &failure(command, "operation-failed", false, contract),
                    json!({
                        "transaction_id": record.id,
                        "restored": progress.done,
                        "stopped_at": surface.id,
                        // Where the pre-rollback copies are, so a caller that
                        // stopped partway can still find what was overwritten.
                        "snapshot": snapshot,
                    }),
                    ExitCode::FAILURE,
                );
            }
        }
    }
    // Every surface is back, so the resume note has nothing left to describe.
    // The snapshot stays: it is for a person, not for the next run.
    //
    // A note that outlives the success it describes is not harmless: the next
    // rollback trusts it and skips those files unchecked, so failing to clear it
    // is reported rather than swallowed.
    if let Err(message) = crate::logintx::clear_rollback_progress(&record.id) {
        irlume_common::dlog!(
            "{command}: restored everything but could not clear progress: {message}"
        );
        return emit_with_extra(
            &failure(command, "operation-failed", true, contract),
            json!({
                "transaction_id": record.id,
                "restored": progress.done,
                "applied": true,
                "snapshot": snapshot,
            }),
            ExitCode::FAILURE,
        );
    }
    emit(
        &success(
            command,
            json!({
                "transaction_id": record.id,
                "action": record.action,
                "unconfirmed": unconfirmed,
                "restored": progress.done,
                "applied": true,
                "snapshot": snapshot,
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

/// What blocks a rollback, kept apart by reason.
///
/// A file that CHANGED and one that cannot be READ are different problems: a
/// consumer told "changed-since-apply" goes looking for an edit, when the truth
/// may be a permission or storage fault the transaction had nothing to do with.
/// Both still stop the rollback, since neither is safe to restore over.
#[derive(Default)]
pub(crate) struct RollbackBlockers<'a> {
    pub(crate) changed: Vec<&'a str>,
    pub(crate) unreadable: Vec<&'a str>,
}

impl RollbackBlockers<'_> {
    pub(crate) fn any(&self) -> bool {
        !self.changed.is_empty() || !self.unreadable.is_empty()
    }
}

fn rollback_blockers(record: &crate::logintx::Transaction) -> RollbackBlockers<'_> {
    rollback_blockers_excluding(record, &crate::logintx::rollback_progress(&record.id))
}

/// The blanket precheck, minus the surfaces a stopped run already put back.
///
/// A restored surface holds its BEFORE content, so it no longer matches the
/// recorded after-digest and reads as drift. Checking it anyway refused the
/// whole record, which is precisely what made a stopped rollback unfinishable:
/// the operator was told their stack had been edited when what had happened is
/// that irlume itself restored part of it.
fn rollback_blockers_excluding<'a>(
    record: &'a crate::logintx::Transaction,
    done: &crate::logintx::RollbackProgress,
) -> RollbackBlockers<'a> {
    let mut blockers = RollbackBlockers::default();
    for surface in &record.surfaces {
        match crate::logintx::unchanged_since_apply_excluding(surface, done) {
            Ok(()) => {}
            Err(crate::logintx::RollbackRefusal::ChangedSinceApply) => {
                blockers.changed.push(surface.id.as_str());
            }
            Err(crate::logintx::RollbackRefusal::Unreadable(_)) => {
                blockers.unreadable.push(surface.id.as_str());
            }
        }
    }
    blockers
}

/// `irlume login apply --action X --plan-id ID --json`: carry out a plan.
///
/// The plan is re-derived from the machine and its id recomputed. A `plan_id`
/// that no longer matches is refused as `plan-stale`, because the consumer
/// displayed one set of changes and the machine now calls for another; applying
/// anyway would change something nobody was shown. The id is never trusted as
/// input, only compared.
pub fn login_apply(args: &[String]) -> ExitCode {
    const COMMAND: &str = "login.apply";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    let Some((action, supplied_plan)) = valid_login_apply_args(args) else {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    };
    if let Some(refusal) = require_root(COMMAND, contract) {
        return refusal;
    }
    // Taken BEFORE the plan is revalidated and held past the confirming record,
    // so the whole transaction is one unit. Acquiring it later would leave the
    // staleness check comparing against a stack another irlume process is
    // partway through rewriting, and the record would then describe a state that
    // never existed on disk.
    let _lock = match crate::pamwire::lock_pam() {
        Ok(lock) => lock,
        Err(message) => {
            irlume_common::dlog!("login.apply: refusing, cannot serialise: {message}");
            return emit(
                &failure(COMMAND, "operation-failed", true, contract),
                ExitCode::FAILURE,
            );
        }
    };
    let enable = action == "enable";
    let planned = crate::pamwire::plan(enable, false, false);
    let current_plan = plan_id(action, &planned);
    if current_plan != supplied_plan {
        return emit(
            &failure(COMMAND, "plan-stale", false, contract),
            ExitCode::FAILURE,
        );
    }

    // WRITE-AHEAD. The before-states are captured and persisted BEFORE the first
    // PAM write, because the alternative has no safe ordering: writing the files
    // first leaves a crash, a kill or a full disk able to strand a changed login
    // stack with nothing describing how to undo it. A record left `prepared`
    // says exactly that happened, and its before-states are still the authority
    // for a rollback.
    //
    // Failing to record is therefore a refusal, not a warning: nothing has been
    // touched yet, so refusing costs the caller a retry rather than a login.
    let transaction_id = random_id();
    let to_records = |surfaces: &[crate::pamwire::AppliedSurface]| {
        surfaces
            .iter()
            .map(|surface| crate::logintx::SurfaceRecord {
                id: surface.id.to_string(),
                path: surface.path.clone(),
                change: surface.change.id().to_string(),
                before: surface.before.clone(),
                after_sha256: surface.after_sha256.clone(),
                mode: surface.before_metadata.map(|(mode, _, _)| mode),
                uid: surface.before_metadata.map(|(_, uid, _)| uid),
                gid: surface.before_metadata.map(|(_, _, gid)| gid),
                // Recorded only when there was a backup to speak of, so a
                // surface irlume never wired carries no sidecar at all.
                sidecar: (surface.sidecar_existed || surface.sidecar_before.is_some()).then(|| {
                    crate::logintx::SidecarRecord {
                        path: format!("{}{}", surface.path, crate::pamwire::BACKUP),
                        after_sha256: surface.sidecar_after_sha256.clone(),
                        before: surface.sidecar_before.clone(),
                        mode: surface.sidecar_metadata.map(|(mode, _, _)| mode),
                        uid: surface.sidecar_metadata.map(|(_, uid, _)| uid),
                        gid: surface.sidecar_metadata.map(|(_, _, gid)| gid),
                    }
                }),
            })
            .collect::<Vec<_>>()
    };
    let mut record = crate::logintx::Transaction {
        id: transaction_id,
        schema_version: crate::logintx::SCHEMA_VERSION,
        status: crate::logintx::TransactionStatus::Prepared,
        action: action.to_string(),
        plan_id: current_plan,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        surfaces: to_records(&crate::pamwire::prepare(enable, false, false)),
    };
    if let Err(message) = record.save() {
        irlume_common::dlog!("login.apply: refusing, cannot record beforehand: {message}");
        return emit(
            &failure(COMMAND, "operation-failed", true, contract),
            ExitCode::FAILURE,
        );
    }

    // The plan is handed to apply so each surface can be re-checked against the
    // state it was planned against, immediately before that surface is written.
    let applied = crate::pamwire::apply(enable, false, false, &planned);
    record.surfaces = to_records(&applied);
    record.status = crate::logintx::TransactionStatus::Applied;
    // Rewriting this can fail, and by now the files HAVE changed. The prepared
    // record is already on disk with the before-states, so a rollback remains
    // possible; what is lost is the confirmed after-state, which is why the
    // status matters and why this is still reported as a failure.
    if let Err(message) = record.save() {
        irlume_common::dlog!("login.apply: applied, but confirming the record failed: {message}");
        return emit_with_extra(
            &failure(COMMAND, "operation-failed", false, contract),
            json!({ "transaction_id": record.id, "status": "prepared" }),
            ExitCode::FAILURE,
        );
    }

    let failed: Vec<&crate::pamwire::AppliedSurface> =
        applied.iter().filter(|s| s.error.is_some()).collect();
    // Keep the self-heal marker in step with what was just written, exactly as
    // the human path does. Without this the machine API unwires the files and
    // leaves the marker saying "wired", so `irlume-reconcile.path` fires on the
    // change it just made, re-wires every greeter, and the transaction that
    // asked for the disable is drifted and no longer rollbackable — irlume
    // fighting its own writes.
    //
    // Found on a machine where login was genuinely wired and the path unit
    // active. Neither the container suite nor a bed with nothing wired can show
    // it: there is no reconcile unit in one and nothing to re-wire in the other.
    //
    // The scopes match what `apply` planned: this command wires the greeter and
    // lock screen, and never sudo or polkit, which are their own opt-in.
    if failed.is_empty() {
        // Only the scopes this command is responsible for. `login apply` wires
        // the greeter and the lock screen and never touches sudo or polkit, so
        // it must not overwrite their flags: a machine `enable` on a host where
        // someone had opted into face-polkit would otherwise record
        // with_polkit=false and reconcile would quietly stop maintaining it.
        //
        // On disable the marker goes entirely, because a disable unwires every
        // surface including those two.
        let (with_sudo, with_polkit, _) = crate::pamwire::read_wired_marker().unwrap_or_default();
        // `with_lock` records whether the lock screen IS wired, not whether this
        // was an enable. Passing `enable` claimed one on every host, including
        // those that wire no lock screen at all, and reconcile then reads a
        // surface that was never ours as a regression to repair.
        crate::pamwire::write_wired_marker(
            enable,
            with_sudo,
            with_polkit,
            enable && crate::pamwire::lock_wired(),
        );
    }
    let changes: Vec<Value> = applied
        .iter()
        .map(|surface| {
            json!({
                "surface": surface.id,
                "role": surface.role,
                "change": surface.change.id(),
                "applied": surface.error.is_none(),
            })
        })
        .collect();
    let data = json!({
        "transaction_id": record.id,
        "plan_id": record.plan_id,
        "action": action,
        "changes": changes,
        "applied": applied.len() - failed.len(),
        "failed": failed.len(),
    });
    if failed.is_empty() {
        emit(&success(COMMAND, data, contract), ExitCode::SUCCESS)
    } else {
        // A partial apply is a failure that still has a transaction id, because
        // the surfaces that DID change are recorded and can be rolled back.
        //
        // The id travels IN THE DOCUMENT, not on stderr. Machine mode promises
        // stdout carries the answer and stderr is empty, and the conformance
        // suite enforces that, so a hint printed there would break a caller that
        // trusts the envelope. Contract 1 permits fields to be added, which is
        // what makes carrying it here possible without a contract bump.
        irlume_common::dlog!(
            "login.apply: {} surface(s) failed; transaction {} can be rolled back",
            failed.len(),
            record.id
        );
        emit_with_extra(
            &failure(COMMAND, "operation-failed", false, contract),
            json!({ "transaction_id": record.id, "failed": failed.len() }),
            ExitCode::FAILURE,
        )
    }
}

/// `irlume login verify --transaction-id ID --json`: is the machine still as
/// that transaction left it?
///
/// Read-only, and deliberately usable without root: a desktop asking "did my
/// change stick" should not need privilege to find out. Reading a record does,
/// though, since the store is root-only, so an unprivileged caller gets
/// `not-authorized` from the load rather than a wrong answer.
pub fn login_verify(args: &[String]) -> ExitCode {
    const COMMAND: &str = "login.verify";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    let Some(id) = valid_transaction_args(args, "verify", false) else {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    };
    let record = match crate::logintx::Transaction::load(&id) {
        Ok(record) => record,
        Err(reason) => return emit_load_failure(COMMAND, reason, contract),
    };
    // Unknown is a status a newer engine wrote. This build cannot know what it
    // guarantees, so it is treated as cautiously as an unconfirmed one.
    let unconfirmed = !matches!(record.status, crate::logintx::TransactionStatus::Applied);
    let (surfaces, drifted) = verify_surfaces(&record);
    // A rollback that stopped partway left the surfaces it restored holding
    // their BEFORE content, which reads as drift here. Counting those would tell
    // an operator a rollback is unavailable when re-running it is exactly what
    // finishes the job, so they are excluded from the availability answer and
    // named instead.
    let restored = crate::logintx::rollback_progress(&record.id);
    let blocking = rollback_blockers_excluding(&record, &restored);
    emit(
        &success(
            COMMAND,
            json!({
                "transaction_id": record.id,
                "action": record.action,
                "plan_id": record.plan_id,
                // `prepared` means the writes were never confirmed: the process
                // stopped between persisting the before-states and recording the
                // result. The before-states are still usable, the after-digests
                // are not, so drift is not meaningful for such a record.
                // Reported as it is, not folded into "prepared": a consumer
                // meeting `unknown` is looking at a record from a newer engine,
                // which is a different thing to diagnose than an interrupted one.
                "status": match record.status {
                    crate::logintx::TransactionStatus::Applied => "applied",
                    crate::logintx::TransactionStatus::Prepared => "prepared",
                    crate::logintx::TransactionStatus::Unknown => "unknown",
                },
                "surfaces": surfaces,
                "drifted": drifted,
                // Whether a rollback would be accepted right now. Stated by the
                // engine so a consumer does not have to infer it from per-surface
                // states it may not recognise.
                // An unconfirmed record can still be rolled back, but only on
                // request: see login rollback --accept-unconfirmed.
                "rollback_available": !unconfirmed && !blocking.any(),
                // Present only when a previous rollback stopped partway. A
                // consumer seeing it knows the drift below is irlume's own
                // work, not somebody's edit.
                "already_restored": restored,
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

/// `irlume login rollback --transaction-id ID --apply --json`: put back what a
/// transaction changed.
///
/// Refuses unless every surface is still exactly as apply left it. Restoring a
/// file something else has edited since would revert a change this transaction
/// never made, so drift stops the whole rollback rather than skipping the
/// drifted surface: a half-rolled-back login stack is its own hazard.
///
/// Without `--apply` it reports what it would restore and touches nothing.
pub fn login_rollback(args: &[String]) -> ExitCode {
    const COMMAND: &str = "login.rollback";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    let Some(id) = valid_transaction_args(args, "rollback", true) else {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    };
    let will_apply = args.iter().any(|a| a == "--apply");
    // Restoring an unconfirmed record gives up the protection against reverting
    // somebody else's later edit, so it has to be asked for by name.
    let accept_unconfirmed = args.iter().any(|a| a == "--accept-unconfirmed");
    // Held across the precheck and every restore, for the same reason apply
    // holds it: the per-surface drift check and the write it authorises are two
    // moments, and another irlume process writing between them is exactly what
    // the check cannot see. A dry run writes nothing and does not take it.
    let _lock = if will_apply {
        if let Some(refusal) = require_root(COMMAND, contract) {
            return refusal;
        }
        match crate::pamwire::lock_pam() {
            Ok(lock) => Some(lock),
            Err(message) => {
                irlume_common::dlog!("login.rollback: refusing, cannot serialise: {message}");
                return emit(
                    &failure(COMMAND, "operation-failed", true, contract),
                    ExitCode::FAILURE,
                );
            }
        }
    } else {
        None
    };
    let record = match crate::logintx::Transaction::load(&id) {
        Ok(record) => record,
        Err(reason) => return emit_load_failure(COMMAND, reason, contract),
    };
    // Every surface is checked BEFORE any is written. A rollback that restored
    // three files and then met a fourth it must refuse would leave the stack in
    // a state neither the transaction nor the admin chose.
    // A `prepared` record never confirmed its writes, so its after-digests
    // cannot gate anything: every existing file would read as drift and rollback
    // would refuse exactly when recovery is most needed. Its before-states are
    // still the authority, so a restore IS possible, but it gives up the
    // protection against reverting somebody else's later edit. That trade is the
    // operator's to make, not something to do silently.
    if !matches!(record.status, crate::logintx::TransactionStatus::Applied) {
        if !accept_unconfirmed {
            irlume_common::dlog!(
                "login.rollback: {} is unconfirmed; needs --accept-unconfirmed",
                record.id
            );
            return emit(
                &failure(COMMAND, "unconfirmed-transaction", false, contract),
                ExitCode::FAILURE,
            );
        }
        return rollback_restore(COMMAND, &record, will_apply, contract, true);
    }
    let blockers = rollback_blockers(&record);
    if blockers.any() {
        irlume_common::dlog!(
            "login.rollback: refused; changed {:?}, unreadable {:?}",
            blockers.changed,
            blockers.unreadable
        );
        // A surface that cannot be READ is its own failure, not drift. Calling
        // it drift would send a consumer hunting for an edit nobody made.
        let code = if blockers.changed.is_empty() {
            "operation-failed"
        } else {
            "changed-since-apply"
        };
        return emit(&failure(COMMAND, code, false, contract), ExitCode::FAILURE);
    }
    rollback_restore(COMMAND, &record, will_apply, contract, false)
}

fn valid_login_apply_args(args: &[String]) -> Option<(&'static str, String)> {
    if args.first().map(String::as_str) != Some("login")
        || args.get(1).map(String::as_str) != Some("apply")
    {
        return None;
    }
    let (mut action, mut plan, mut saw_json) = (None, None, false);
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
            }
            "--action" if action.is_none() => {
                action = match args.get(index + 1).map(String::as_str) {
                    Some("enable") => Some("enable"),
                    Some("disable") => Some("disable"),
                    _ => return None,
                };
                index += 2;
            }
            "--plan-id" if plan.is_none() => {
                let value = args.get(index + 1)?;
                if !crate::logintx::is_valid_id(value) {
                    return None;
                }
                plan = Some(value.clone());
                index += 2;
            }
            _ => return None,
        }
    }
    // The plan id is required. Applying without one would mean acting on
    // changes the consumer never saw.
    match (saw_json, action, plan) {
        (true, Some(action), Some(plan)) => Some((action, plan)),
        _ => None,
    }
}

fn valid_transaction_args(args: &[String], sub: &str, allow_apply: bool) -> Option<String> {
    if args.first().map(String::as_str) != Some("login")
        || args.get(1).map(String::as_str) != Some(sub)
    {
        return None;
    }
    let (mut id, mut saw_json, mut saw_apply) = (None, false, false);
    let mut saw_unconfirmed = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
            }
            "--apply" if allow_apply && !saw_apply => {
                saw_apply = true;
                index += 1;
            }
            // Only meaningful where a restore can happen, so it is refused on
            // verify rather than accepted and ignored.
            "--accept-unconfirmed" if allow_apply && !saw_unconfirmed => {
                saw_unconfirmed = true;
                index += 1;
            }
            "--transaction-id" if id.is_none() => {
                let value = args.get(index + 1)?;
                if !crate::logintx::is_valid_id(value) {
                    return None;
                }
                id = Some(value.clone());
                index += 2;
            }
            _ => return None,
        }
    }
    if saw_json {
        id
    } else {
        None
    }
}

/// An exclusive per-user session, held for as long as the guard lives.
///
/// The contract promises one session per user. That is enforced with an
/// advisory lock on a file in the caller's own runtime directory rather than a
/// recorded process id: a lock is released by the kernel when the holder exits
/// for any reason, including a crash or a kill, so a panel that dies mid-capture
/// cannot leave a user unable to start another session.
struct SessionGuard {
    id: String,
    // Held for its Drop, which closes the descriptor and releases the lock.
    _file: std::fs::File,
}

/// Why a session could not be taken.
///
/// Distinguished because they mean opposite things to a caller: another session
/// will finish, so retrying is right, while a runtime directory that cannot be
/// written will not fix itself and retrying is a spin. Reporting both as
/// `session-busy` told a consumer to keep trying against a permission error.
enum SessionRefusal {
    /// Another session for this user holds the lock.
    Busy,
    /// The lock itself could not be created or opened.
    Unavailable,
}

impl SessionGuard {
    fn acquire() -> std::result::Result<Self, SessionRefusal> {
        use std::os::unix::io::AsRawFd;
        let dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            // Falling back to a uid-qualified path keeps the lock per-user on a
            // system without a runtime directory, rather than making it global.
            .unwrap_or_else(|| {
                // SAFETY: getuid cannot fail and touches no memory.
                std::path::PathBuf::from(format!("/tmp/irlume-{}", unsafe { libc::getuid() }))
            });
        let _ = std::fs::create_dir_all(&dir);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("machine-session.lock"))
            .map_err(|_| SessionRefusal::Unavailable)?;
        // SAFETY: fd is owned by `file` and outlives the call.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if locked != 0 {
            // EWOULDBLOCK is the lock being held, which is the ordinary case
            // and the only retryable one. Anything else is the lock mechanism
            // failing, and telling a consumer to retry that would spin.
            let errno = std::io::Error::last_os_error().raw_os_error();
            return Err(if errno == Some(libc::EWOULDBLOCK) {
                SessionRefusal::Busy
            } else {
                SessionRefusal::Unavailable
            });
        }
        Ok(Self {
            id: random_id(),
            _file: file,
        })
    }
}

/// `irlume auth test --events=jsonl`: does the claimed user's live face match
/// their own enrolment?
///
/// Verification against one claimed account, never identification. It answers
/// with a verdict and releases nothing: the daemon's `Authenticate` returns a
/// decision, while credential release is a separate privileged path this command
/// does not touch. It also cannot alter a profile or a threshold, because it
/// sends no request that could.
///
/// The match score is deliberately NOT reported. A caller that can see a
/// continuous score can hill-climb against it, tuning a presentation until it
/// crosses the threshold, which turns a diagnostic into an oracle. `granted`
/// and `live` are the two facts a settings panel needs, and the reason is a
/// stable code derived from them rather than daemon prose.
pub fn auth_test(args: &[String]) -> ExitCode {
    const COMMAND: &str = "auth.test";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    if !valid_auth_test_args(args) {
        // A usage error is reported as a single document, not as a stream. The
        // stream has not started, and a consumer that mis-invoked the command
        // gets the same shape every other refusal uses.
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    let user = crate::user_arg(args);

    // Both of these happen BEFORE the stream begins, and the contract is explicit
    // about that boundary: a refusal before the stream is a single document with
    // exit 2, while exit 1 means the stream started and then failed. Returning 1
    // here told a consumer a capture had begun and died when nothing had run, and
    // `session-busy` is precisely the case a caller retries on.
    let session = match SessionGuard::acquire() {
        Ok(session) => session,
        Err(SessionRefusal::Busy) => {
            return emit(
                &failure(COMMAND, "session-busy", true, contract),
                ExitCode::from(2),
            )
        }
        Err(SessionRefusal::Unavailable) => {
            return emit(
                &failure(COMMAND, "operation-failed", false, contract),
                ExitCode::from(2),
            )
        }
    };
    let mut stream = EventStream::new(COMMAND, contract, session.id.clone());
    // The account is not echoed back. Machine output does not carry usernames,
    // and the caller supplied it, so repeating it would add a name to a stream
    // a desktop may log without adding anything the caller does not know.
    stream.progress("started", json!({ "operation": "auth-test" }));
    stream.progress("capturing", json!({}));

    match crate::daemon_request(&Request::Authenticate {
        user,
        // No PAM service: this is a diagnostic, not an authentication for a
        // surface, so it must not inherit any surface's tier allowances.
        service: None,
    }) {
        Ok(Response::AuthResult { granted, live, .. }) => stream.finish(
            "result",
            json!({
                "granted": granted,
                "live": live,
                "reason": auth_reason(granted, live),
            }),
            // A refusal is a successful test that answered "no". The command
            // failing and the face not matching are different things, and a
            // consumer must be able to tell them apart.
            ExitCode::SUCCESS,
        ),
        Ok(Response::OperationError { code, retryable }) => {
            stream.fail(error_code(code), retryable)
        }
        // Daemon prose is not inspected; see `profiles_list`.
        Ok(Response::Error(_)) => stream.fail("operation-failed", false),
        Ok(_) => stream.fail("protocol-error", false),
        Err(_) => stream.fail("daemon-unavailable", true),
    }
}

/// A stable reason code for an authentication verdict.
///
/// Derived from the two booleans the daemon already returns, never from its
/// prose. That keeps a reworded daemon message from becoming a breaking API
/// change, which is the same rule the single-document commands follow.
fn auth_reason(granted: bool, live: bool) -> &'static str {
    match (granted, live) {
        (true, _) => "granted",
        (false, false) => "not-live",
        (false, true) => "no-match",
    }
}

fn valid_auth_test_args(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("auth")
        || args.get(1).map(String::as_str) != Some("test")
    {
        return false;
    }
    let mut saw_events = false;
    let mut saw_user = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--events=jsonl" if !saw_events => {
                saw_events = true;
                index += 1;
            }
            // Preview is a separate capability that this build does not
            // advertise. Refusing it is the honest answer; accepting and
            // ignoring it would let a consumer believe frames were suppressed
            // by policy when they were never implemented.
            arg if arg.starts_with("--preview") => return false,
            "--user" if !saw_user => {
                saw_user = true;
                let Some(user) = args.get(index + 1) else {
                    return false;
                };
                if user.is_empty() || user.starts_with('-') {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    saw_events
}

pub fn profiles_list(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.list";
    // Negotiate first: an unsupported contract is refused before the daemon is
    // contacted at all.
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    if !valid_profiles_list_args(args) {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    let user = crate::user_arg(args);
    // Ask for typed failures. An older daemon ignores the field and answers
    // with prose, which the `Response::Error` arm below still maps.
    match crate::daemon_request(&Request::ListProfiles {
        user,
        structured_errors: true,
    }) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            ..
        }) => emit(
            &success(
                COMMAND,
                profiles_data(profiles, require_eyes_open),
                contract,
            ),
            ExitCode::SUCCESS,
        ),
        Ok(Response::OperationError { code, retryable }) => emit(
            &failure(COMMAND, error_code(code), retryable, contract),
            ExitCode::FAILURE,
        ),
        // An older daemon predates the typed variant and answers with prose.
        // Its text is deliberately not inspected: matching on daemon wording
        // would make a message change a breaking API change.
        Ok(Response::Error(_)) => emit(
            &failure(COMMAND, "operation-failed", false, contract),
            ExitCode::FAILURE,
        ),
        Ok(_) => emit(
            &failure(COMMAND, "protocol-error", false, contract),
            ExitCode::FAILURE,
        ),
        Err(_) => emit(
            &failure(COMMAND, "daemon-unavailable", true, contract),
            ExitCode::FAILURE,
        ),
    }
}

fn valid_profiles_list_args(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("profiles")
        || args.get(1).map(String::as_str) != Some("list")
    {
        return false;
    }
    let mut saw_json = false;
    let mut saw_user = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
            }
            "--user" if !saw_user => {
                saw_user = true;
                let Some(user) = args.get(index + 1) else {
                    return false;
                };
                if user.is_empty() || user.starts_with('-') {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    saw_json
}

/// `irlume models list --json`: per-pipeline-stage model report (#276).
///
/// Each stage's model CANDIDATE — the file this process's search order lands
/// on, with its origin and whether it opened as a regular file — plus whether
/// the stage is open to third-party models, and for the open PAD stage the
/// catalog with each entry's tier (fetched by irlume vs user-supplied) and
/// weight state. Needs no daemon, so it still answers when the daemon will
/// not start. It deliberately does not say "active": the daemon's service
/// unit (or an administrator's drop-in) sets its own environment, which this
/// process cannot observe, so an authoritative loaded-model report can only
/// ever come from the daemon itself.
pub fn models_list(args: &[String]) -> ExitCode {
    const COMMAND: &str = "models.list";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    if without_contract(args) != ["models", "list", "--json"] {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    emit(
        &success(COMMAND, models_list_data(), contract),
        ExitCode::SUCCESS,
    )
}

fn models_list_data() -> Value {
    let stages = crate::models::stage_statuses()
        .into_iter()
        .map(|s| {
            let candidate = match (s.file, &s.resolved) {
                (None, _) => json!({ "origin": "built-in" }),
                (Some(file), Some(c)) => json!({
                    "file": file,
                    "observed": true,
                    "readable": c.readable,
                    "origin": c.origin,
                    "path": c.path.display().to_string(),
                }),
                (Some(file), None) => json!({
                    "file": file,
                    "observed": false,
                }),
            };
            let mut stage = json!({
                "stage": s.stage,
                "open": s.open,
                "required": s.required,
                "candidate": candidate,
            });
            if s.open {
                stage["third_party"] = third_party_data(s.stage_kind);
            }
            stage
        })
        .collect::<Vec<_>>();
    json!({ "stages": stages })
}

/// The third-party tier of the one open stage: what is enabled, and the
/// catalog with weight states.
///
/// `enabled.known` is honest about observability, like `login_manager.known`,
/// and it is keyed on WHAT THE READ ESTABLISHED, not on who asked. A missing
/// file or key is genuine observed absence (the config directory is world-
/// readable), so `known: true, name: null` — from any caller. A read that
/// FAILED (EACCES on the root-only file for an unprivileged caller, a wrong
/// SELinux label even for root) established nothing, so `known: false`; a
/// consumer must not render that as "disabled".
fn third_party_data(stage: irlume_common::thirdparty::Stage) -> Value {
    use irlume_common::config::KvObservation;
    use irlume_common::thirdparty::{self, WeightState};
    // THIS stage's key and THIS stage's catalog entries: with two stages
    // open, the pad object naming a recognizer (or listing its entries)
    // would make "what is enabled where" unanswerable from the payload.
    let enabled = match irlume_common::config::observe_kv(
        "settings.conf",
        thirdparty::settings_key_for(stage),
    ) {
        KvObservation::Value(name) => json!({ "known": true, "name": name }),
        KvObservation::Absent => json!({ "known": true, "name": null }),
        KvObservation::Unknown(_) => json!({ "known": false }),
    };
    let catalog = thirdparty::CATALOG
        .iter()
        .filter(|m| m.stage == stage)
        .map(|m| {
            json!({
                "name": m.name,
                "stage": m.stage.as_str(),
                "tier": if m.url.is_some() { "fetched" } else { "user-supplied" },
                "weights": match thirdparty::weight_state(m) {
                    WeightState::ChecksumOk => "checksum-ok",
                    WeightState::ChecksumMismatch => "checksum-mismatch",
                    WeightState::Absent => "absent",
                },
            })
        })
        .collect::<Vec<_>>();
    json!({ "enabled": enabled, "catalog": catalog })
}

fn profiles_data(profiles: Vec<ProfileSummary>, require_eyes_open: bool) -> Value {
    // The current enrollment store identifies profiles and scans by their
    // names. Do not falsely present those names as opaque stable IDs. A later
    // contract capability can add mutation-safe IDs after the store owns them.
    let profiles = profiles
        .into_iter()
        .map(|profile| {
            // Per-recognizer counts, and which recognizer is loaded, so a
            // consumer can say which templates are live right now (#288).
            // A profile can hold several recognizers' templates, and only
            // the loaded one's can match; "scans" alone cannot say that.
            //
            // A daemon older than 0.9.0 never sends the counts, and they arrive
            // as an empty map. Rendering that as `"recognizers": []` next to ten
            // scans claims no recognizer can match this profile, which is the
            // "unknown is not zero" mistake this file's own contract forbids and
            // would invite a consumer to prompt for re-enrollment. A 0.9.0
            // daemon always populates the map for a profile that has scans
            // (untagged ones count under the legacy space), so empty-with-scans
            // means only that nobody told us: omit the key instead.
            let live = profile.live_recognizer.clone();
            let recognizers = (!profile.scans_by_recognizer.is_empty() || profile.scans.is_empty())
                .then(|| {
                    profile
                        .scans_by_recognizer
                        .iter()
                        .map(|(space, count)| {
                            json!({
                                "space": space,
                                "scans": count,
                                "live": live.as_deref() == Some(space.as_str()),
                            })
                        })
                        .collect::<Vec<_>>()
                });
            let mut obj = json!({
                "display_name": profile.name,
                "scans": profile.scans.into_iter().map(|name| {
                    json!({ "display_name": name })
                }).collect::<Vec<_>>(),
            });
            if let Some(recognizers) = recognizers {
                obj["recognizers"] = json!(recognizers);
            }
            obj
        })
        .collect::<Vec<_>>();
    json!({
        "profiles": profiles,
        "require_eyes_open": require_eyes_open
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_contract_flag_always_means_the_first_contract() {
        // The load-bearing rule. A consumer written against contract 1 that
        // omits the flag must keep getting contract 1 after the engine learns
        // contract 2, so this must never be expressed as "the newest".
        assert_eq!(CONTRACT_DEFAULT, 1);
        assert_eq!(CONTRACT_DEFAULT, CONTRACT_MIN);
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match negotiate(&args(&["version", "--json"])) {
            Contract::Agreed(v) => assert_eq!(v, CONTRACT_DEFAULT),
            _ => panic!("an absent flag must agree, not refuse"),
        }
    }

    #[test]
    fn a_supported_contract_is_agreed_and_an_unsupported_one_is_refused() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for v in CONTRACT_MIN..=CONTRACT_MAX {
            match negotiate(&args(&["version", "--contract", &v.to_string(), "--json"])) {
                Contract::Agreed(got) => assert_eq!(got, v),
                _ => panic!("contract {v} is in range and must be agreed"),
            }
        }
        // Above the range: a consumer built for a contract this engine does not
        // implement must be told so, not served contract 1 semantics silently.
        assert!(matches!(
            negotiate(&args(&["version", "--contract", "2", "--json"])),
            Contract::Unsupported
        ));
        // Zero is not a contract.
        assert!(matches!(
            negotiate(&args(&["version", "--contract", "0", "--json"])),
            Contract::Unsupported
        ));
    }

    #[test]
    fn a_malformed_contract_flag_is_refused_rather_than_guessed() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for bad in [
            vec!["version", "--contract"],                  // no value
            vec!["version", "--contract", "one", "--json"], // not a number
            vec!["version", "--contract", "-1", "--json"],  // not unsigned
            vec!["version", "--contract", "1", "--contract", "1", "--json"], // repeated
        ] {
            assert!(
                matches!(negotiate(&args(&bad)), Contract::Malformed),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn stripping_the_flag_leaves_the_command_its_own_arguments() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            without_contract(&args(&["profiles", "list", "--contract", "1", "--json"])),
            args(&["profiles", "list", "--json"])
        );
        // A command that never saw the flag is untouched.
        assert_eq!(
            without_contract(&args(&["profiles", "list", "--json"])),
            args(&["profiles", "list", "--json"])
        );
    }

    #[test]
    fn version_freezes_the_public_envelope_and_capabilities() {
        let document = serde_json::to_value(success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                "limits": { "max_profiles": 3 }
            }),
            CONTRACT_DEFAULT,
        ))
        .unwrap();

        assert_eq!(document["contract_version"], 1);
        assert_eq!(document["command"], "version");
        assert_eq!(document["ok"], true);
        // Spelled out rather than compared against CAPABILITIES, so adding a
        // capability has to be done here too. That is the point: a capability
        // is a public promise and lands with its documentation, schema and
        // fixtures, never as a side effect of an implementation.
        assert_eq!(
            document["data"]["capabilities"],
            json!([
                "version-json",
                "profiles-list-json",
                "status-json",
                "doctor-json",
                "login-status-json",
                "auth-test-events",
                "login-plan-json",
                "login-transactions",
                "models-list-json"
            ])
        );
        assert!(document.get("error").is_none());
    }

    /// A daemon older than 0.9.0 does not send per-recognizer counts, so they
    /// deserialize to an empty map. Emitting `"recognizers": []` beside ten
    /// scans asserts that no recognizer can match this profile, which is false
    /// and would invite a consumer to prompt for re-enrollment. This is the
    /// upgrade window: a 0.9.0 CLI against a running 0.8.1 daemon, which is
    /// exactly what a user sees between `dnf upgrade` and the daemon restart.
    #[test]
    fn an_old_daemons_missing_recognizer_counts_are_absent_not_empty() {
        let data = profiles_data(
            vec![ProfileSummary {
                name: "BEN".into(),
                scans: vec!["s1".into(), "s2".into()],
                scans_by_recognizer: Default::default(),
                live_recognizer: None,
            }],
            false,
        );
        let profile = &data["profiles"][0];
        assert_eq!(profile["scans"].as_array().unwrap().len(), 2);
        assert!(
            profile.get("recognizers").is_none(),
            "unknown counts must be ABSENT, not an empty array: {profile}"
        );

        // A profile that genuinely has no scans is not the unknown case, and
        // an empty list there is the honest answer.
        let empty = profiles_data(
            vec![ProfileSummary {
                name: "Fresh".into(),
                scans: vec![],
                scans_by_recognizer: Default::default(),
                live_recognizer: None,
            }],
            false,
        );
        assert_eq!(
            empty["profiles"][0]["recognizers"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn profiles_report_each_recognizer_and_mark_only_the_loaded_one_live() {
        // #288: a profile can hold several recognizers' templates and only
        // the loaded one's can match, so a consumer needs to know WHICH.
        // Marking every recognizer live would tell it the opposite.
        use irlume_common::ProfileSummary;
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("embed:model-a".to_string(), 7usize);
        counts.insert("embed:model-b".to_string(), 3usize);
        let data = profiles_data(
            vec![ProfileSummary {
                name: "P".into(),
                scans: vec!["s1".into()],
                scans_by_recognizer: counts,
                live_recognizer: Some("embed:model-b".into()),
            }],
            false,
        );
        let recs = data["profiles"][0]["recognizers"].as_array().unwrap();
        assert_eq!(recs.len(), 2);
        let by_space = |space: &str| {
            recs.iter()
                .find(|r| r["space"] == space)
                .unwrap_or_else(|| panic!("missing {space}"))
        };
        assert_eq!(by_space("embed:model-a")["scans"], 7);
        assert_eq!(
            by_space("embed:model-a")["live"],
            false,
            "a recognizer that is not loaded must not read as live"
        );
        assert_eq!(by_space("embed:model-b")["scans"], 3);
        assert_eq!(by_space("embed:model-b")["live"], true);
        // Exactly one entry may be live.
        assert_eq!(
            recs.iter().filter(|r| r["live"] == true).count(),
            1,
            "only the loaded recognizer is live"
        );

        // An older daemon reports neither field. Decoded from WIRE JSON that
        // omits them, not from a struct literal supplying them: a literal
        // would keep passing if the serde defaults were ever removed, which
        // is exactly the compatibility this half claims to guard (#291
        // review).
        let old_wire: ProfileSummary = serde_json::from_str(r#"{"name":"P","scans":["s1"]}"#)
            .expect("an older daemon's summary must still decode");
        assert!(old_wire.scans_by_recognizer.is_empty());
        assert!(old_wire.live_recognizer.is_none());
        let data = profiles_data(vec![old_wire], false);
        // This used to assert an empty ARRAY. It now asserts the key is absent:
        // an empty array beside a populated `scans` list says "no recognizer has
        // templates in this profile", which is a definite claim the CLI cannot
        // support and which would send a consumer to re-enroll a working
        // profile. Absent means unknown, which is what an older daemon leaves us
        // with. The wire-decode half of this test is unchanged and is the point:
        // decoding from real JSON rather than a struct literal is what keeps it
        // honest if the serde defaults are ever removed (#291 review).
        assert!(data["profiles"][0].get("recognizers").is_none());
    }

    #[test]
    fn models_list_reports_every_stage_and_only_open_stages_carry_third_party() {
        // Sandboxed state dir so the weight states are this test's, not the
        // machine's. The config dir is NOT sandboxed here; `enabled.known`
        // honesty under an unreadable config is asserted separately below.
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let state = std::env::temp_dir().join(format!("irlume-mls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        let old_state = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &state);

        let data = models_list_data();

        match old_state {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&state);

        let stages = data["stages"].as_array().expect("stages array");
        let names: Vec<&str> = stages
            .iter()
            .map(|s| s["stage"].as_str().expect("stage name"))
            .collect();
        assert_eq!(names, ["detection", "landmarks", "recognition", "pad"]);
        for s in stages {
            let open = s["open"].as_bool().expect("open flag");
            // third_party appears exactly on open stages: a consumer keys the
            // tier UI off its presence, so a closed stage carrying one (or an
            // open stage missing one) is a contract break, not a nicety.
            assert_eq!(
                s.get("third_party").is_some(),
                open,
                "stage {}: third_party must accompany open exactly",
                s["stage"]
            );
            match s["stage"].as_str().unwrap() {
                "detection" | "recognition" => assert_eq!(s["required"], true),
                "landmarks" | "pad" => assert_eq!(s["required"], false),
                other => panic!("unexpected stage {other}"),
            }
        }
        let pad = &stages[3];
        assert_eq!(pad["candidate"]["origin"], "built-in");
        // Sandboxed empty state dir: no weights anywhere.
        for entry in pad["third_party"]["catalog"].as_array().unwrap() {
            assert_eq!(entry["weights"], "absent");
            assert!(matches!(
                entry["tier"].as_str().unwrap(),
                "fetched" | "user-supplied"
            ));
        }
        // Each open stage's third_party lists ONLY its own entries: pad's
        // object naming a recognizer would make "what is enabled where"
        // unanswerable from the payload.
        let names = |st: &serde_json::Value| {
            st["third_party"]["catalog"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["stage"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert!(names(pad).iter().all(|s| s == "pad"));
        let recognition = &stages[2];
        let rec_names = names(recognition);
        assert!(!rec_names.is_empty() && rec_names.iter().all(|s| s == "recognition"));
    }

    #[test]
    fn models_list_enabled_state_is_honest_about_observability() {
        // `enabled.known` is keyed on what the READ established, not on who
        // asked: a missing file is observed absence (known:true, name:null), a
        // readable key names the model, and a read that FAILS establishes
        // nothing (known:false, which a consumer must not render as
        // "disabled"). The failure case is produced deterministically by
        // pointing the config dir at a regular file, so opening
        // `<file>/settings.conf` fails with ENOTDIR for root and non-root
        // alike — the review's counterexample was a root-side SELinux denial
        // being reported as authoritative absence.
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("irlume-mle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&root);
        let cfg = root.join("cfg");
        std::fs::create_dir_all(&cfg).unwrap();
        let old_cfg = std::env::var_os("IRLUME_CONFIG_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &cfg);

        // No settings.conf at all: observed absence.
        let absent = third_party_data(irlume_common::thirdparty::Stage::Pad);
        // A readable enabled key — and the OTHER stage's key alongside it, so
        // the per-stage read is proven to consult its own key, not the pad one.
        std::fs::write(
            cfg.join("settings.conf"),
            "third_party_pad=flir\nthird_party_recognizer=buffalo\n",
        )
        .unwrap();
        let named = third_party_data(irlume_common::thirdparty::Stage::Pad);
        let named_rec = third_party_data(irlume_common::thirdparty::Stage::Recognition);
        // A failing read: the config dir is a regular file.
        let notdir = root.join("not-a-dir");
        std::fs::write(&notdir, b"not a directory").unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &notdir);
        let unreadable = third_party_data(irlume_common::thirdparty::Stage::Pad);

        match old_cfg {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(absent["enabled"], json!({"known": true, "name": null}));
        assert_eq!(named["enabled"], json!({"known": true, "name": "flir"}));
        assert_eq!(
            named_rec["enabled"],
            json!({"known": true, "name": "buffalo"}),
            "the recognition stage must read its own key"
        );
        assert_eq!(
            unreadable["enabled"],
            json!({"known": false}),
            "a failed read must never be reported as observed absence"
        );
    }

    /// Collect the events a closure emits, by capturing what the stream would
    /// serialize. The emitter writes to stdout, so these exercise the envelope
    /// and the sequencing rules against the same `Event` the command sends.
    fn event_value(
        stream: &EventStream,
        sequence: u64,
        event: &'static str,
        terminal: bool,
    ) -> Value {
        serde_json::to_value(Event {
            contract_version: stream.contract,
            engine_version: env!("CARGO_PKG_VERSION"),
            command: stream.command,
            operation_id: stream.operation_id.clone(),
            session_id: stream.session_id.clone(),
            sequence,
            event,
            terminal,
            data: Some(json!({})),
            error: None,
        })
        .unwrap()
    }

    #[test]
    fn an_event_carries_the_whole_envelope_on_every_line() {
        // A consumer that drops a line, tails the stream, or reads it out of a
        // log must still know what it is looking at, so nothing is sent once as
        // a header.
        let stream = EventStream::new("auth.test", 1, "session".into());
        let value = event_value(&stream, 0, "started", false);
        for field in [
            "contract_version",
            "engine_version",
            "command",
            "operation_id",
            "session_id",
            "sequence",
            "event",
            "terminal",
        ] {
            assert!(value.get(field).is_some(), "event is missing {field}");
        }
        assert_eq!(value["contract_version"], 1);
        assert_eq!(value["command"], "auth.test");
    }

    #[test]
    fn the_sequence_starts_at_zero_and_never_repeats() {
        let mut stream = EventStream::new("auth.test", 1, "session".into());
        assert_eq!(stream.sequence, 0);
        stream.sequence += 1;
        stream.sequence += 1;
        // Gapless and monotonic is what lets a consumer detect a lost line by
        // arithmetic instead of by timeout.
        assert_eq!(stream.sequence, 2);
    }

    #[test]
    fn one_operation_id_ties_the_whole_stream_together() {
        let stream = EventStream::new("auth.test", 1, "session".into());
        let first = event_value(&stream, 0, "started", false);
        let last = event_value(&stream, 2, "result", true);
        assert_eq!(first["operation_id"], last["operation_id"]);
        assert_eq!(first["session_id"], last["session_id"]);
        assert_ne!(first["sequence"], last["sequence"]);
    }

    #[test]
    fn two_streams_do_not_share_an_operation_id() {
        let a = EventStream::new("auth.test", 1, "s".into());
        let b = EventStream::new("auth.test", 1, "s".into());
        assert_ne!(a.operation_id, b.operation_id);
        assert_eq!(a.operation_id.len(), 32, "128 bits, hex encoded");
    }

    #[test]
    fn the_verdict_reason_is_derived_from_the_booleans_not_from_prose() {
        // Daemon wording may change freely; these codes may not.
        assert_eq!(auth_reason(true, true), "granted");
        assert_eq!(auth_reason(true, false), "granted");
        assert_eq!(auth_reason(false, false), "not-live");
        assert_eq!(auth_reason(false, true), "no-match");
    }

    /// A record whose surfaces point at files a test controls, so the verify
    /// and rollback decisions can be exercised without root or a PAM tree.
    fn record_over(files: &[(&str, &std::path::Path, &str)]) -> crate::logintx::Transaction {
        crate::logintx::Transaction {
            id: "0123456789abcdef0123456789abcdef".into(),
            schema_version: crate::logintx::SCHEMA_VERSION,
            status: crate::logintx::TransactionStatus::Applied,
            action: "disable".into(),
            plan_id: "f".repeat(32),
            engine_version: "0.0.0".into(),
            surfaces: files
                .iter()
                .map(|(id, path, after)| crate::logintx::SurfaceRecord {
                    id: (*id).to_string(),
                    path: path.display().to_string(),
                    change: "wire".into(),
                    before: Some("before\n".into()),
                    after_sha256: (*after).to_string(),
                    mode: None,
                    uid: None,
                    gid: None,
                    sidecar: None,
                })
                .collect(),
        }
    }

    #[test]
    fn verify_reports_each_surface_and_counts_the_drift() {
        let dir = std::env::temp_dir().join(format!("irlume-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let steady = dir.join("steady");
        let moved = dir.join("moved");
        std::fs::write(&steady, "as applied\n").expect("write");
        std::fs::write(&moved, "somebody edited this\n").expect("write");

        let record = record_over(&[
            (
                "kde",
                steady.as_path(),
                &crate::logintx::sha256_hex(b"as applied\n"),
            ),
            (
                "sudo",
                moved.as_path(),
                &crate::logintx::sha256_hex(b"as applied\n"),
            ),
        ]);
        let (surfaces, drifted) = verify_surfaces(&record);
        assert_eq!(surfaces.len(), 2);
        assert_eq!(surfaces[0]["surface"], "kde");
        assert_eq!(surfaces[0]["state"], "as-applied");
        assert_eq!(surfaces[1]["state"], "changed-since-apply");
        assert_eq!(drifted, 1);

        // Rollback is gated on the same rule, and names what blocks it.
        let blockers = rollback_blockers(&record);
        assert_eq!(blockers.changed, vec!["sudo"]);
        assert!(blockers.unreadable.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rollback_is_allowed_only_when_nothing_drifted() {
        let dir = std::env::temp_dir().join(format!("irlume-rollback-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("kde");
        std::fs::write(&file, "as applied\n").expect("write");
        let record = record_over(&[(
            "kde",
            file.as_path(),
            &crate::logintx::sha256_hex(b"as applied\n"),
        )]);
        assert!(!rollback_blockers(&record).any(), "clean stack rolls back");

        std::fs::write(&file, "changed\n").expect("write");
        let blockers = rollback_blockers(&record);
        assert_eq!(blockers.changed, vec!["kde"]);
        assert!(
            blockers.unreadable.is_empty(),
            "an edit is not a read fault"
        );

        // An unreadable surface blocks a rollback too, but as its OWN reason:
        // it is not evidence the file changed, and reporting it as drift would
        // send a consumer hunting for an edit nobody made.
        std::fs::remove_file(&file).expect("rm");
        std::fs::create_dir(&file).expect("mkdir in its place");
        let blockers = rollback_blockers(&record);
        assert!(blockers.any(), "unreadable still stops the rollback");
        assert_eq!(blockers.unreadable, vec!["kde"]);
        assert!(blockers.changed.is_empty(), "unreadable is not drift");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn login_apply_requires_an_action_and_a_plan_id() {
        let a = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        let good = a(&[
            "login",
            "apply",
            "--action",
            "enable",
            "--plan-id",
            "0123456789abcdef0123456789abcdef",
            "--json",
        ]);
        assert_eq!(
            valid_login_apply_args(&good),
            Some(("enable", "0123456789abcdef0123456789abcdef".to_string()))
        );
        for bad in [
            // No plan id: applying without one means acting on changes the
            // consumer never saw.
            vec!["login", "apply", "--action", "enable", "--json"],
            vec![
                "login",
                "apply",
                "--plan-id",
                "0123456789abcdef0123456789abcdef",
                "--json",
            ],
            // A plan id that is not a hex identifier.
            vec![
                "login",
                "apply",
                "--action",
                "enable",
                "--plan-id",
                "../etc",
                "--json",
            ],
            vec![
                "login",
                "apply",
                "--action",
                "enable",
                "--plan-id",
                "short",
                "--json",
            ],
            // Unknown action, missing --json, repeats, junk.
            vec![
                "login",
                "apply",
                "--action",
                "wat",
                "--plan-id",
                "0123456789abcdef0123456789abcdef",
                "--json",
            ],
            vec![
                "login",
                "apply",
                "--action",
                "enable",
                "--plan-id",
                "0123456789abcdef0123456789abcdef",
            ],
            vec![
                "login",
                "apply",
                "--action",
                "enable",
                "--action",
                "disable",
                "--plan-id",
                "0123456789abcdef0123456789abcdef",
                "--json",
            ],
            vec![
                "login",
                "apply",
                "--action",
                "enable",
                "--plan-id",
                "0123456789abcdef0123456789abcdef",
                "--json",
                "--wat",
            ],
            vec![
                "login",
                "plan",
                "--action",
                "enable",
                "--plan-id",
                "0123456789abcdef0123456789abcdef",
                "--json",
            ],
        ] {
            assert_eq!(valid_login_apply_args(&a(&bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn a_transaction_id_shaped_like_a_path_is_refused() {
        let a = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            valid_transaction_args(
                &a(&["login", "verify", "--transaction-id", id, "--json"]),
                "verify",
                false
            ),
            Some(id.to_string())
        );
        // --apply is accepted only where it means something.
        assert_eq!(
            valid_transaction_args(
                &a(&[
                    "login",
                    "rollback",
                    "--transaction-id",
                    id,
                    "--apply",
                    "--json"
                ]),
                "rollback",
                true
            ),
            Some(id.to_string())
        );
        assert_eq!(
            valid_transaction_args(
                &a(&[
                    "login",
                    "verify",
                    "--transaction-id",
                    id,
                    "--apply",
                    "--json"
                ]),
                "verify",
                false
            ),
            None,
            "verify writes nothing, so --apply is meaningless there"
        );
        for bad in [
            vec![
                "login",
                "verify",
                "--transaction-id",
                "../../etc/passwd",
                "--json",
            ],
            vec![
                "login",
                "verify",
                "--transaction-id",
                "../../etc/shadow",
                "--json",
            ],
            vec!["login", "verify", "--json"],
            vec!["login", "verify", "--transaction-id", id],
            vec![
                "login",
                "verify",
                "--transaction-id",
                id,
                "--transaction-id",
                id,
                "--json",
            ],
            vec!["login", "apply", "--transaction-id", id, "--json"],
        ] {
            assert_eq!(
                valid_transaction_args(&a(&bad), "verify", false),
                None,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn login_plan_requires_both_json_and_a_known_action() {
        let a = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        assert_eq!(
            valid_login_plan_args(&a(&["login", "plan", "--action", "enable", "--json"])),
            Some("enable")
        );
        assert_eq!(
            valid_login_plan_args(&a(&["login", "plan", "--json", "--action", "disable"])),
            Some("disable")
        );
        // An action is mandatory: guessing whether the consumer meant on or off
        // is the one thing a plan must never do.
        assert_eq!(
            valid_login_plan_args(&a(&["login", "plan", "--json"])),
            None
        );
        assert_eq!(
            valid_login_plan_args(&a(&["login", "plan", "--action", "enable"])),
            None
        );
        for bad in [
            vec!["login", "plan", "--action", "wat", "--json"],
            vec!["login", "plan", "--action", "--json"],
            vec!["login", "plan", "--action", "enable", "--json", "--json"],
            vec![
                "login", "plan", "--action", "enable", "--action", "disable", "--json",
            ],
            vec!["login", "plan", "--action", "enable", "--json", "--wat"],
        ] {
            assert_eq!(valid_login_plan_args(&a(&bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn a_plan_id_changes_when_the_file_changes_but_the_outcome_does_not() {
        use crate::pamwire::{PlannedChange, PlannedSurface};
        // Codex found this on #178: the id hashed the outcome LABEL only. An
        // admin can rewrite a stack and leave a valid anchor in place, so the
        // outcome stays `wire` while the file is entirely different. An apply
        // carrying the old id would then overwrite a stack the consumer was
        // never shown, which is the exact thing plan-stale exists to prevent.
        let with_state = |state: &str| {
            vec![PlannedSurface {
                id: "plasmalogin",
                role: "login-screen",
                change: PlannedChange::Wire,
                state: state.to_string(),
            }]
        };
        let before = plan_id("enable", &with_state("aaaa"));
        let after = plan_id("enable", &with_state("bbbb"));
        assert_ne!(
            before, after,
            "the same outcome over different file content must not share a plan id"
        );
        // And the id is still stable when genuinely nothing moved.
        assert_eq!(before, plan_id("enable", &with_state("aaaa")));
        // An unreadable surface is its own state, not folded into absent.
        assert_ne!(
            plan_id("enable", &with_state("unreadable")),
            plan_id("enable", &with_state(crate::logintx::ABSENT))
        );
    }

    #[test]
    fn a_plan_id_covers_the_action_and_the_outcomes() {
        use crate::pamwire::{PlannedChange, PlannedSurface};
        let surfaces = |change| {
            vec![PlannedSurface {
                id: "plasmalogin",
                role: "login-screen",
                change,
                state: "same-state".into(),
            }]
        };
        let base = plan_id("enable", &surfaces(PlannedChange::Wire));
        // Same machine, same intent: the same id, so a consumer can tell that
        // nothing moved between showing a plan and acting on it.
        assert_eq!(base, plan_id("enable", &surfaces(PlannedChange::Wire)));
        // A different intent over identical state is a different plan.
        assert_ne!(base, plan_id("disable", &surfaces(PlannedChange::Wire)));
        // The same intent over changed state is a different plan. This is the
        // property that lets a later apply refuse a stale one.
        assert_ne!(
            base,
            plan_id("enable", &surfaces(PlannedChange::AlreadyCorrect))
        );
        assert_eq!(base.len(), 32);
    }

    #[test]
    fn a_change_that_writes_is_named_as_one() {
        use crate::pamwire::PlannedChange;
        // requires_root is derived from these, so a new outcome landing on the
        // wrong side would tell a panel it needs no privilege when it does.
        for change in [
            PlannedChange::MaterializeOverride,
            PlannedChange::Wire,
            PlannedChange::RemoveOverride,
            PlannedChange::RestoreBackup,
            PlannedChange::StripInPlace,
        ] {
            assert!(change.writes(), "{change:?} writes to disk");
        }
        for change in [
            PlannedChange::AlreadyCorrect,
            PlannedChange::NotInstalled,
            PlannedChange::NoAnchor,
            PlannedChange::NotWired,
        ] {
            assert!(!change.writes(), "{change:?} does not write");
        }
    }

    #[test]
    fn every_planned_change_has_a_distinct_stable_id() {
        use crate::pamwire::PlannedChange;
        let all = [
            PlannedChange::MaterializeOverride,
            PlannedChange::Wire,
            PlannedChange::RemoveOverride,
            PlannedChange::RestoreBackup,
            PlannedChange::StripInPlace,
            PlannedChange::AlreadyCorrect,
            PlannedChange::NotInstalled,
            PlannedChange::NoAnchor,
            PlannedChange::NotWired,
        ];
        let ids: std::collections::BTreeSet<&str> = all.iter().map(|c| c.id()).collect();
        assert_eq!(ids.len(), all.len(), "two outcomes share a published id");
        for id in ids {
            assert!(!id.is_empty() && id.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
        }
    }

    #[test]
    fn auth_test_requires_the_events_flag() {
        assert!(!valid_auth_test_args(&["auth".into(), "test".into()]));
        assert!(valid_auth_test_args(&[
            "auth".into(),
            "test".into(),
            "--events=jsonl".into()
        ]));
    }

    #[test]
    fn auth_test_refuses_preview_rather_than_ignoring_it() {
        // Accepting and dropping the flag would let a consumer believe frames
        // were withheld by policy when the capability simply does not exist.
        for flag in ["--preview=ir-jpeg", "--preview", "--preview=anything"] {
            assert!(
                !valid_auth_test_args(&[
                    "auth".into(),
                    "test".into(),
                    "--events=jsonl".into(),
                    flag.into()
                ]),
                "{flag} must be refused"
            );
        }
    }

    #[test]
    fn auth_test_rejects_repeats_and_unknown_flags() {
        let cases: [&[&str]; 4] = [
            &["auth", "test", "--events=jsonl", "--events=jsonl"],
            &["auth", "test", "--events=jsonl", "--user"],
            &["auth", "test", "--events=jsonl", "--user", "-bad"],
            &["auth", "test", "--events=jsonl", "--wat"],
        ];
        for case in cases {
            let args: Vec<String> = case.iter().map(|s| (*s).to_string()).collect();
            assert!(!valid_auth_test_args(&args), "{case:?} must be refused");
        }
        let ok: Vec<String> = ["auth", "test", "--events=jsonl", "--user", "someone"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(valid_auth_test_args(&ok));
    }

    #[test]
    fn profile_listing_does_not_claim_unimplemented_opaque_ids() {
        let data = profiles_data(
            vec![ProfileSummary {
                name: "Face Profile 1".into(),
                scans: vec!["Scan 1".into()],
                scans_by_recognizer: Default::default(),
                live_recognizer: None,
            }],
            true,
        );

        assert_eq!(data["profiles"][0]["display_name"], "Face Profile 1");
        assert_eq!(data["profiles"][0]["scans"][0]["display_name"], "Scan 1");
        assert!(data["profiles"][0].get("profile_id").is_none());
        assert!(data["profiles"][0]["scans"][0].get("scan_id").is_none());
        assert_eq!(data["require_eyes_open"], true);
    }

    #[test]
    fn errors_have_stable_codes_without_daemon_prose() {
        let document = serde_json::to_value(failure(
            "profiles.list",
            "daemon-unavailable",
            true,
            CONTRACT_DEFAULT,
        ))
        .unwrap();

        assert_eq!(document["ok"], false);
        assert_eq!(document["error"]["code"], "daemon-unavailable");
        assert_eq!(document["error"]["retryable"], true);
        assert!(document.get("data").is_none());
    }

    #[test]
    fn profiles_list_rejects_unknown_missing_and_duplicate_flags() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        assert!(valid_profiles_list_args(&args(&[
            "profiles", "list", "--json"
        ])));
        assert!(valid_profiles_list_args(&args(&[
            "profiles", "list", "--user", "alice", "--json"
        ])));
        assert!(!valid_profiles_list_args(&args(&["profiles", "list"])));
        assert!(!valid_profiles_list_args(&args(&[
            "profiles",
            "list",
            "--json",
            "--verbose"
        ])));
        assert!(!valid_profiles_list_args(&args(&[
            "profiles", "list", "--json", "--json"
        ])));
        assert!(!valid_profiles_list_args(&args(&[
            "profiles", "list", "--json", "--user"
        ])));
    }
}
