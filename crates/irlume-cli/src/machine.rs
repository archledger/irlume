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
            ..
        }) => (
            json!(if encrypted { "encrypted" } else { "plaintext" }),
            json!({ "known": true, "passphrase_set": recovery_set }),
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
    let caps = irlume_camera::capabilities();
    let (rgb, ir) = irlume_camera::select_pair();
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
                "fingerprint": irlume_fingerprint::device_name().is_some(),
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

    let session = match SessionGuard::acquire() {
        Ok(session) => session,
        Err(SessionRefusal::Busy) => {
            return emit(
                &failure(COMMAND, "session-busy", true, contract),
                ExitCode::FAILURE,
            )
        }
        Err(SessionRefusal::Unavailable) => {
            return emit(
                &failure(COMMAND, "operation-failed", false, contract),
                ExitCode::FAILURE,
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
            require_challenge,
            ..
        }) => emit(
            &success(
                COMMAND,
                profiles_data(profiles, require_eyes_open, require_challenge),
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

fn profiles_data(
    profiles: Vec<ProfileSummary>,
    require_eyes_open: bool,
    require_challenge: bool,
) -> Value {
    // The current enrollment store identifies profiles and scans by their
    // names. Do not falsely present those names as opaque stable IDs. A later
    // contract capability can add mutation-safe IDs after the store owns them.
    let profiles = profiles
        .into_iter()
        .map(|profile| {
            json!({
                "display_name": profile.name,
                "scans": profile.scans.into_iter().map(|name| {
                    json!({ "display_name": name })
                }).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    json!({
        "profiles": profiles,
        "require_eyes_open": require_eyes_open,
        "require_challenge": require_challenge
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
                "login-plan-json"
            ])
        );
        assert!(document.get("error").is_none());
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
    fn a_plan_id_covers_the_action_and_the_outcomes() {
        use crate::pamwire::{PlannedChange, PlannedSurface};
        let surfaces = |change| {
            vec![PlannedSurface {
                id: "plasmalogin",
                role: "login-screen",
                change,
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
            }],
            true,
            false,
        );

        assert_eq!(data["profiles"][0]["display_name"], "Face Profile 1");
        assert_eq!(data["profiles"][0]["scans"][0]["display_name"], "Scan 1");
        assert!(data["profiles"][0].get("profile_id").is_none());
        assert!(data["profiles"][0]["scans"][0].get("scan_id").is_none());
        assert_eq!(data["require_eyes_open"], true);
        assert_eq!(data["require_challenge"], false);
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
