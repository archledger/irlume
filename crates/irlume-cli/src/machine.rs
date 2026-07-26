// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Public, versioned machine output for desktop integrations.
//!
//! Keep this module deliberately narrower than the daemon's private wire
//! protocol. A capability is advertised only after its public command, output
//! shape, and compatibility rules are covered here and in `docs/MACHINE-API.md`.

use irlume_common::{OperationErrorCode, ProfileMutationKind, ProfileSummary, Request, Response};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

pub const CONTRACT_VERSION: u32 = 1;

const CAPABILITIES: &[&str] = &[
    "version-json",
    "profiles-json",
    "profile-mutations-json",
    "events-jsonl",
    "position-report",
    "preview-ir-jpeg",
];

static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_cancel(_: libc::c_int) {
    CANCEL_REQUESTED.store(true, Ordering::SeqCst);
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

fn success(command: &'static str, data: Value) -> Document {
    Document {
        contract_version: CONTRACT_VERSION,
        engine_version: env!("CARGO_PKG_VERSION"),
        command,
        ok: true,
        data: Some(data),
        error: None,
    }
}

fn failure(command: &'static str, code: &'static str, retryable: bool) -> Document {
    Document {
        contract_version: CONTRACT_VERSION,
        engine_version: env!("CARGO_PKG_VERSION"),
        command,
        ok: false,
        data: None,
        error: Some(MachineError { code, retryable }),
    }
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

fn operation_id(prefix: &str) -> String {
    format!("{prefix}-{:032x}", rand::random::<u128>())
}

fn install_cancellation_handler() {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    unsafe {
        let handler = request_cancel as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

struct EventStream {
    command: &'static str,
    operation_id: String,
    session_id: String,
    sequence: u64,
}

impl EventStream {
    fn new(command: &'static str) -> Self {
        Self {
            command,
            operation_id: operation_id("operation"),
            session_id: operation_id("session"),
            sequence: 0,
        }
    }

    fn value(
        &self,
        event: &str,
        terminal: bool,
        data: Option<Value>,
        error: Option<Value>,
    ) -> Value {
        let mut value = json!({
            "contract_version": CONTRACT_VERSION,
            "engine_version": env!("CARGO_PKG_VERSION"),
            "command": self.command,
            "operation_id": self.operation_id,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "event": event,
            "terminal": terminal
        });
        let object = value.as_object_mut().expect("event is an object");
        if let Some(data) = data {
            object.insert("data".into(), data);
        }
        if let Some(error) = error {
            object.insert("error".into(), error);
        }
        value
    }

    fn emit(&mut self, event: &str, terminal: bool, data: Option<Value>, error: Option<Value>) {
        let value = self.value(event, terminal, data, error);
        self.sequence += 1;
        println!(
            "{}",
            serde_json::to_string(&value).expect("serialize event")
        );
        let _ = std::io::stdout().flush();
    }

    fn failed(&mut self, code: &'static str, retryable: bool) -> ExitCode {
        self.emit(
            "failed",
            true,
            None,
            Some(json!({"code": code, "retryable": retryable})),
        );
        ExitCode::FAILURE
    }

    fn cancelled(&mut self) -> ExitCode {
        self.emit(
            "cancelled",
            true,
            None,
            Some(json!({"code": "user-cancelled", "retryable": true})),
        );
        ExitCode::from(130)
    }
}

pub fn version(args: &[String]) -> ExitCode {
    if args != ["version", "--json"] {
        return emit(&failure("version", "usage-error", false), ExitCode::from(2));
    }
    emit(
        &success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                "limits": {
                    "max_profiles": 3,
                    "max_scans_per_profile": 20
                }
            }),
        ),
        ExitCode::SUCCESS,
    )
}

pub fn enroll_events(args: &[String]) -> ExitCode {
    const COMMAND: &str = "enroll";
    if !valid_event_args(args, "enroll", false) {
        return event_usage(COMMAND);
    }
    install_cancellation_handler();
    let mut stream = EventStream::new(COMMAND);
    stream.emit("started", false, None, None);
    if CANCEL_REQUESTED.load(Ordering::SeqCst) {
        return stream.cancelled();
    }
    let user = crate::user_arg(args);
    if let Err((code, retryable)) =
        emit_preview_countdown(&mut stream, &user, preview_requested(args))
    {
        return if CANCEL_REQUESTED.load(Ordering::SeqCst) {
            stream.cancelled()
        } else {
            stream.failed(code, retryable)
        };
    }
    stream.emit("stage", false, Some(json!({"stage": "capturing"})), None);
    let response = cancellable_request(&Request::Enroll {
        user: user.clone(),
        profile: None,
        scans: None,
        reset: false,
    });
    if CANCEL_REQUESTED.load(Ordering::SeqCst) && response.is_err() {
        return stream.cancelled();
    }
    match response {
        Ok(Response::Enrolled {
            profile_id,
            created,
            added,
            total,
            added_scan_ids,
            ..
        }) if irlume_core::storage::valid_profile_id(&profile_id)
            && added_scan_ids
                .iter()
                .all(|id| irlume_core::storage::valid_scan_id(id)) =>
        {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                if rollback_enrollment(&user, &profile_id, created, &added_scan_ids) {
                    return stream.cancelled();
                }
                return stream.failed("rollback-failed", false);
            }
            stream.emit(
                "completed",
                true,
                Some(json!({
                    "profile_id": profile_id,
                    "created": created,
                    "added_scans": added,
                    "total_scans": total
                })),
                None,
            );
            ExitCode::SUCCESS
        }
        Ok(Response::OperationError { code, retryable }) => {
            stream.failed(operation_error_code(code), retryable)
        }
        Ok(Response::Error(_)) => stream.failed("precondition-failed", false),
        Ok(_) => stream.failed("protocol-error", false),
        Err(error) => request_failed(&mut stream, error),
    }
}

pub fn auth_test_events(args: &[String]) -> ExitCode {
    const COMMAND: &str = "auth.test";
    if !valid_event_args(args, "auth", false) || args.get(1).map(String::as_str) != Some("test") {
        return event_usage(COMMAND);
    }
    install_cancellation_handler();
    let mut stream = EventStream::new(COMMAND);
    stream.emit("started", false, None, None);
    let user = crate::user_arg(args);
    if let Err((code, retryable)) =
        emit_preview_countdown(&mut stream, &user, preview_requested(args))
    {
        return if CANCEL_REQUESTED.load(Ordering::SeqCst) {
            stream.cancelled()
        } else {
            stream.failed(code, retryable)
        };
    }
    stream.emit("stage", false, Some(json!({"stage": "matching"})), None);
    let response = cancellable_request(&Request::Authenticate {
        user,
        service: None,
    });
    if CANCEL_REQUESTED.load(Ordering::SeqCst) {
        return stream.cancelled();
    }
    match response {
        Ok(Response::AuthResult {
            granted,
            score,
            live,
            ..
        }) => {
            stream.emit(
                "completed",
                true,
                Some(json!({
                    "matched": granted,
                    "liveness": if live { "live" } else { "not-live" },
                    "score": score,
                    "credential_released": false,
                    "profile_modified": false
                })),
                None,
            );
            ExitCode::SUCCESS
        }
        Ok(Response::OperationError { code, retryable }) => {
            stream.failed(operation_error_code(code), retryable)
        }
        Ok(Response::Error(_)) => stream.failed("precondition-failed", false),
        Ok(_) => stream.failed("protocol-error", false),
        Err(error) => request_failed(&mut stream, error),
    }
}

pub fn profiles_add_scan_events(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.add-scan";
    if !valid_event_args(args, "profiles", true)
        || args.get(1).map(String::as_str) != Some("add-scan")
    {
        return event_usage(COMMAND);
    }
    let Some(profile_id) = crate::flag(args, "--profile-id").map(String::from) else {
        return event_usage(COMMAND);
    };
    if !irlume_core::storage::valid_profile_id(&profile_id) {
        return event_usage(COMMAND);
    }
    install_cancellation_handler();
    let mut stream = EventStream::new(COMMAND);
    stream.emit("started", false, None, None);
    let user = crate::user_arg(args);
    if let Err((code, retryable)) =
        emit_preview_countdown(&mut stream, &user, preview_requested(args))
    {
        return if CANCEL_REQUESTED.load(Ordering::SeqCst) {
            stream.cancelled()
        } else {
            stream.failed(code, retryable)
        };
    }
    stream.emit("stage", false, Some(json!({"stage": "capturing"})), None);
    let response = cancellable_request(&Request::AddScanById {
        user: user.clone(),
        profile_id: profile_id.clone(),
    });
    if CANCEL_REQUESTED.load(Ordering::SeqCst) && response.is_err() {
        return stream.cancelled();
    }
    match response {
        Ok(Response::ProfileMutation {
            operation: ProfileMutationKind::AddScan,
            profile_id: returned_profile_id,
            scan_id: Some(scan_id),
            total_scans: Some(total),
            ..
        }) if returned_profile_id == profile_id
            && irlume_core::storage::valid_scan_id(&scan_id) =>
        {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                let rolled_back = matches!(
                    crate::daemon_request(&Request::DeleteScanById {
                        user,
                        profile_id: profile_id.clone(),
                        scan_id,
                    }),
                    Ok(Response::ProfileMutation {
                        operation: ProfileMutationKind::DeleteScan,
                        ..
                    })
                );
                return if rolled_back {
                    stream.cancelled()
                } else {
                    stream.failed("rollback-failed", false)
                };
            }
            stream.emit(
                "completed",
                true,
                Some(json!({
                    "profile_id": profile_id,
                    "added_scans": 1,
                    "total_scans": total,
                    "mutated_other_profiles": false
                })),
                None,
            );
            ExitCode::SUCCESS
        }
        Ok(Response::OperationError { code, retryable }) => {
            stream.failed(operation_error_code(code), retryable)
        }
        Ok(Response::Error(_)) => stream.failed("precondition-failed", false),
        Ok(_) => stream.failed("protocol-error", false),
        Err(error) => request_failed(&mut stream, error),
    }
}

fn emit_preview_countdown(
    stream: &mut EventStream,
    user: &str,
    include_preview: bool,
) -> Result<(), (&'static str, bool)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let mut countdown = 3;
    for _ in 0..12 {
        if CANCEL_REQUESTED.load(Ordering::SeqCst) {
            return Err(("user-cancelled", true));
        }
        let started = std::time::Instant::now();
        let sample = match cancellable_request(&Request::PreviewSample { user: user.into() }) {
            Ok(Response::Preview(sample)) => sample,
            Ok(Response::OperationError {
                code: OperationErrorCode::PreconditionFailed,
                retryable: true,
            }) => continue,
            Ok(Response::OperationError { code, retryable }) => {
                return Err((operation_error_code(code), retryable))
            }
            Ok(Response::Error(_)) => return Err(("precondition-failed", false)),
            Ok(_) => return Err(("protocol-error", false)),
            Err(crate::CancellableRequestError::Cancelled) => return Err(("user-cancelled", true)),
            Err(crate::CancellableRequestError::Timeout) => return Err(("timeout", true)),
            Err(crate::CancellableRequestError::Protocol) => return Err(("protocol-error", false)),
            Err(crate::CancellableRequestError::Unavailable) => {
                return Err(("daemon-unavailable", true))
            }
        };
        let bytes = STANDARD
            .decode(&sample.frame_jpeg_base64)
            .map_err(|_| ("invalid-preview", false))?;
        if bytes.len() > 128 * 1024
            || sample.width == 0
            || sample.height == 0
            || sample.width > 640
            || sample.height > 480
            || !matches!(sample.spectrum.as_str(), "ir" | "rgb")
            || sample.landmarks.len() != 478
            || sample
                .landmarks
                .iter()
                .flatten()
                .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
            || sample
                .face_box
                .iter()
                .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
            || sample.face_box[2] <= 0.0
            || sample.face_box[3] <= 0.0
            || sample.face_box[0] + sample.face_box[2] > 1.0
            || sample.face_box[1] + sample.face_box[3] > 1.0
        {
            return Err(("invalid-preview", false));
        }
        let decoded = image::load_from_memory_with_format(&bytes, image::ImageFormat::Jpeg)
            .map_err(|_| ("invalid-preview", false))?;
        if decoded.width() != sample.width || decoded.height() != sample.height {
            return Err(("invalid-preview", false));
        }
        let position = &sample.position;
        if position.guidance.len() > 160
            || position.guidance.chars().any(char::is_control)
            || position.quality > 100
        {
            return Err(("invalid-preview", false));
        }
        let position_data = json!({
            "face_detected": position.face,
            "centered": position.centered,
            "facing_camera": position.yaw_asym <= 0.22
                && (0.28..=0.72).contains(&position.pitch_frac),
            "well_lit": (55.0..=235.0).contains(&position.brightness),
            "ir_ready": position.ir_ok,
            "well_framed": position.well_framed,
            "quality": position.quality,
            "countdown": countdown,
            "guidance": position.guidance
        });
        let data = if include_preview {
            json!({
                "frame_jpeg_base64": sample.frame_jpeg_base64,
                "width": sample.width,
                "height": sample.height,
                "spectrum": sample.spectrum,
                "landmarks": sample.landmarks,
                "face_box": sample.face_box,
                "position": position_data
            })
        } else {
            json!({"position": position_data})
        };
        stream.emit("preview", false, Some(data), None);
        if position.well_framed {
            countdown -= 1;
            if countdown == 0 {
                return Ok(());
            }
        } else {
            countdown = 3;
        }
        let elapsed = started.elapsed();
        let minimum = std::time::Duration::from_millis(125);
        if elapsed < minimum {
            std::thread::sleep(minimum - elapsed);
        }
    }
    Err(("positioning-timeout", true))
}

fn preview_requested(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--preview=ir-jpeg")
}

fn cancellable_request(request: &Request) -> Result<Response, crate::CancellableRequestError> {
    crate::daemon_request_cancellable(request, || CANCEL_REQUESTED.load(Ordering::SeqCst))
}

fn operation_error_code(code: OperationErrorCode) -> &'static str {
    match code {
        OperationErrorCode::CameraBusy => "camera-busy",
        OperationErrorCode::NotAuthorized => "not-authorized",
        OperationErrorCode::Cancelled => "user-cancelled",
        OperationErrorCode::Timeout => "timeout",
        OperationErrorCode::PreconditionFailed => "precondition-failed",
        OperationErrorCode::HardwareUnavailable => "hardware-unavailable",
        OperationErrorCode::ProtocolError => "protocol-error",
        OperationErrorCode::OperationFailed => "operation-failed",
    }
}

fn request_failed(stream: &mut EventStream, error: crate::CancellableRequestError) -> ExitCode {
    match error {
        crate::CancellableRequestError::Cancelled => stream.cancelled(),
        crate::CancellableRequestError::Timeout => stream.failed("timeout", true),
        crate::CancellableRequestError::Protocol => stream.failed("protocol-error", false),
        crate::CancellableRequestError::Unavailable => stream.failed("daemon-unavailable", true),
    }
}

fn rollback_enrollment(
    user: &str,
    profile_id: &str,
    created: bool,
    added_scan_ids: &[String],
) -> bool {
    if created {
        return matches!(
            crate::daemon_request(&Request::DeleteProfileById {
                user: user.into(),
                profile_id: profile_id.into(),
            }),
            Ok(Response::ProfileMutation {
                operation: ProfileMutationKind::DeleteProfile,
                ..
            })
        );
    }
    for scan_id in added_scan_ids.iter().rev() {
        if !matches!(
            crate::daemon_request(&Request::DeleteScanById {
                user: user.into(),
                profile_id: profile_id.into(),
                scan_id: scan_id.clone(),
            }),
            Ok(Response::ProfileMutation {
                operation: ProfileMutationKind::DeleteScan,
                ..
            })
        ) {
            return false;
        }
    }
    true
}

fn event_usage(command: &'static str) -> ExitCode {
    let mut stream = EventStream::new(command);
    stream.failed("usage-error", false);
    ExitCode::from(2)
}

fn valid_event_args(args: &[String], root: &str, profile_required: bool) -> bool {
    if args.first().map(String::as_str) != Some(root) {
        return false;
    }
    let mut events = false;
    let mut preview = false;
    let mut fps = false;
    let mut size = false;
    let mut user = false;
    let mut profile = false;
    let mut index = if root == "auth" || root == "profiles" {
        2
    } else {
        1
    };
    while index < args.len() {
        match args[index].as_str() {
            "--events=jsonl" if !events => events = true,
            "--preview=ir-jpeg" if !preview => preview = true,
            "--preview-max-fps=8" if !fps => fps = true,
            "--preview-max-size=640x480" if !size => size = true,
            "--user" if !user => {
                user = true;
                let Some(value) = args.get(index + 1) else {
                    return false;
                };
                if value.is_empty() || value.starts_with('-') {
                    return false;
                }
                index += 1;
            }
            "--profile-id" if profile_required && !profile => {
                profile = true;
                let Some(value) = args.get(index + 1) else {
                    return false;
                };
                if !irlume_core::storage::valid_profile_id(value) {
                    return false;
                }
                index += 1;
            }
            _ => return false,
        }
        index += 1;
    }
    events && preview == fps && fps == size && (!profile_required || profile)
}

pub fn profiles_list(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.list";
    if !valid_profiles_list_args(args) {
        return emit(&failure(COMMAND, "usage-error", false), ExitCode::from(2));
    }
    let user = crate::user_arg(args);
    match crate::daemon_request(&Request::ListProfiles { user }) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            require_challenge,
            ..
        }) => match profiles_data(profiles, require_eyes_open, require_challenge) {
            Ok(data) => emit(&success(COMMAND, data), ExitCode::SUCCESS),
            Err(code) => emit(&failure(COMMAND, code, false), ExitCode::FAILURE),
        },
        Ok(Response::Error(_)) => emit(
            &failure(COMMAND, "operation-failed", false),
            ExitCode::FAILURE,
        ),
        Ok(_) => emit(
            &failure(COMMAND, "protocol-error", false),
            ExitCode::FAILURE,
        ),
        Err(_) => emit(
            &failure(COMMAND, "daemon-unavailable", true),
            ExitCode::FAILURE,
        ),
    }
}

pub fn profiles_delete(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.delete";
    let Some(parsed) = parse_profile_mutation_args(args, false) else {
        return emit(&failure(COMMAND, "usage-error", false), ExitCode::from(2));
    };
    let user = crate::user_arg(args);
    let request = match parsed.scan_id {
        Some(scan_id) => Request::DeleteScanById {
            user,
            profile_id: parsed.profile_id,
            scan_id,
        },
        None => Request::DeleteProfileById {
            user,
            profile_id: parsed.profile_id,
        },
    };
    emit_profile_mutation(COMMAND, request)
}

pub fn profiles_rename(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.rename";
    let Some(parsed) = parse_profile_mutation_args(args, true) else {
        return emit(&failure(COMMAND, "usage-error", false), ExitCode::from(2));
    };
    let user = crate::user_arg(args);
    let new_name = parsed.new_name.expect("rename parser requires a name");
    let request = match parsed.scan_id {
        Some(scan_id) => Request::RenameScanById {
            user,
            profile_id: parsed.profile_id,
            scan_id,
            new_name,
        },
        None => Request::RenameProfileById {
            user,
            profile_id: parsed.profile_id,
            new_name,
        },
    };
    emit_profile_mutation(COMMAND, request)
}

fn emit_profile_mutation(command: &'static str, request: Request) -> ExitCode {
    match crate::daemon_request(&request) {
        Ok(Response::ProfileMutation {
            operation,
            profile_id,
            profile_name_before,
            profile_name_after,
            scan_id,
            scan_name_before,
            scan_name_after,
            total_scans,
        }) => emit(
            &success(
                command,
                mutation_data(
                    operation,
                    profile_id,
                    profile_name_before,
                    profile_name_after,
                    scan_id,
                    scan_name_before,
                    scan_name_after,
                    total_scans,
                ),
            ),
            ExitCode::SUCCESS,
        ),
        Ok(Response::Error(_)) => emit(
            &failure(command, "operation-failed", false),
            ExitCode::FAILURE,
        ),
        Ok(_) => emit(
            &failure(command, "protocol-error", false),
            ExitCode::FAILURE,
        ),
        Err(_) => emit(
            &failure(command, "daemon-unavailable", true),
            ExitCode::FAILURE,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn mutation_data(
    operation: ProfileMutationKind,
    profile_id: String,
    profile_name_before: Option<String>,
    profile_name_after: Option<String>,
    scan_id: Option<String>,
    scan_name_before: Option<String>,
    scan_name_after: Option<String>,
    total_scans: Option<usize>,
) -> Value {
    let record = |profile_name: Option<String>, scan_name: Option<String>| {
        profile_name.map(|profile_name| {
            json!({
                "profile_id": profile_id,
                "profile_name": profile_name,
                "scan_id": scan_id,
                "scan_name": scan_name
            })
        })
    };
    let before = record(profile_name_before, scan_name_before);
    let after = record(profile_name_after, scan_name_after);
    let deleted = matches!(
        operation,
        ProfileMutationKind::DeleteProfile | ProfileMutationKind::DeleteScan
    );
    json!({
        "operation": operation,
        "profile_id": profile_id,
        "scan_id": scan_id,
        "before": before,
        "after": after,
        "total_scans": total_scans,
        "deleted": deleted,
        "mutated_other_profiles": false
    })
}

struct MutationArgs {
    profile_id: String,
    scan_id: Option<String>,
    new_name: Option<String>,
}

fn parse_profile_mutation_args(args: &[String], rename: bool) -> Option<MutationArgs> {
    let expected_subcommand = if rename { "rename" } else { "delete" };
    if args.first().map(String::as_str) != Some("profiles")
        || args.get(1).map(String::as_str) != Some(expected_subcommand)
    {
        return None;
    }
    let mut profile_id = None;
    let mut scan_id = None;
    let mut new_name = None;
    let mut saw_json = false;
    let mut saw_user = false;
    let mut index = 2;
    while index < args.len() {
        let (slot, validate_id): (&mut Option<String>, bool) = match args[index].as_str() {
            "--profile-id" if profile_id.is_none() => (&mut profile_id, true),
            "--scan-id" if scan_id.is_none() => (&mut scan_id, true),
            "--name" if rename && new_name.is_none() => (&mut new_name, false),
            "--user" if !saw_user => {
                saw_user = true;
                let user = args.get(index + 1)?;
                if user.is_empty() || user.starts_with('-') {
                    return None;
                }
                index += 2;
                continue;
            }
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
                continue;
            }
            _ => return None,
        };
        let value = args.get(index + 1)?;
        if value.is_empty() || value.starts_with('-') {
            return None;
        }
        if validate_id {
            let valid = if args[index] == "--profile-id" {
                irlume_core::storage::valid_profile_id(value)
            } else {
                irlume_core::storage::valid_scan_id(value)
            };
            if !valid {
                return None;
            }
        } else if value.trim() != value
            || value.chars().count() > 80
            || value.chars().any(char::is_control)
        {
            return None;
        }
        *slot = Some(value.clone());
        index += 2;
    }
    if !saw_json || profile_id.is_none() || rename != new_name.is_some() {
        return None;
    }
    Some(MutationArgs {
        profile_id: profile_id.expect("checked"),
        scan_id,
        new_name,
    })
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
) -> Result<Value, &'static str> {
    let mut output = Vec::with_capacity(profiles.len());
    for profile in profiles {
        if !irlume_core::storage::valid_profile_id(&profile.id)
            || profile.scans.len() != profile.scan_ids.len()
        {
            return Err("unsupported-daemon");
        }
        let mut scans = Vec::with_capacity(profile.scans.len());
        for (name, id) in profile.scans.into_iter().zip(profile.scan_ids) {
            if !irlume_core::storage::valid_scan_id(&id) {
                return Err("unsupported-daemon");
            }
            scans.push(json!({
                "scan_id": id,
                "display_name": name
            }));
        }
        output.push(json!({
            "profile_id": profile.id,
            "display_name": profile.name,
            "scans": scans
        }));
    }
    Ok(json!({
        "profiles": output,
        "require_eyes_open": require_eyes_open,
        "require_challenge": require_challenge
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_freezes_the_public_envelope_and_capabilities() {
        let document = serde_json::to_value(success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                "limits": { "max_profiles": 3 }
            }),
        ))
        .unwrap();

        assert_eq!(document["contract_version"], 1);
        assert_eq!(document["command"], "version");
        assert_eq!(document["ok"], true);
        assert_eq!(
            document["data"]["capabilities"],
            json!([
                "version-json",
                "profiles-json",
                "profile-mutations-json",
                "events-jsonl",
                "position-report",
                "preview-ir-jpeg"
            ])
        );
        assert!(document.get("error").is_none());
    }

    #[test]
    fn profile_listing_exposes_stored_opaque_ids() {
        let data = profiles_data(
            vec![ProfileSummary {
                id: "profile-0123456789abcdef0123456789abcdef".into(),
                name: "Face Profile 1".into(),
                scans: vec!["Scan 1".into()],
                scan_ids: vec!["scan-fedcba9876543210fedcba9876543210".into()],
            }],
            true,
            false,
        )
        .unwrap();

        assert_eq!(
            data["profiles"][0]["profile_id"],
            "profile-0123456789abcdef0123456789abcdef"
        );
        assert_eq!(data["profiles"][0]["display_name"], "Face Profile 1");
        assert_eq!(data["profiles"][0]["scans"][0]["display_name"], "Scan 1");
        assert_eq!(
            data["profiles"][0]["scans"][0]["scan_id"],
            "scan-fedcba9876543210fedcba9876543210"
        );
        assert_eq!(data["require_eyes_open"], true);
        assert_eq!(data["require_challenge"], false);
    }

    #[test]
    fn profile_listing_refuses_missing_or_misaligned_ids() {
        let profile = |scan_ids| ProfileSummary {
            id: "profile-0123456789abcdef0123456789abcdef".into(),
            name: "Primary".into(),
            scans: vec!["Scan 1".into()],
            scan_ids,
        };
        assert_eq!(
            profiles_data(vec![profile(vec![])], false, false).unwrap_err(),
            "unsupported-daemon"
        );
        let mut missing = profile(vec!["scan-fedcba9876543210fedcba9876543210".into()]);
        missing.id.clear();
        assert_eq!(
            profiles_data(vec![missing], false, false).unwrap_err(),
            "unsupported-daemon"
        );
    }

    #[test]
    fn mutation_args_require_safe_ids_json_and_bounded_names() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        let profile = "profile-0123456789abcdef0123456789abcdef";
        let scan = "scan-fedcba9876543210fedcba9876543210";
        assert!(parse_profile_mutation_args(
            &args(&[
                "profiles",
                "rename",
                "--profile-id",
                profile,
                "--scan-id",
                scan,
                "--name",
                "Glasses",
                "--json"
            ]),
            true
        )
        .is_some());
        assert!(parse_profile_mutation_args(
            &args(&["profiles", "delete", "--profile-id", profile, "--json"]),
            false
        )
        .is_some());
        assert!(parse_profile_mutation_args(
            &args(&["profiles", "delete", "--profile-id", "../unsafe", "--json"]),
            false
        )
        .is_none());
        assert!(parse_profile_mutation_args(
            &args(&[
                "profiles",
                "rename",
                "--profile-id",
                profile,
                "--name",
                " padded ",
                "--json"
            ]),
            true
        )
        .is_none());
    }

    #[test]
    fn errors_have_stable_codes_without_daemon_prose() {
        let document =
            serde_json::to_value(failure("profiles.list", "daemon-unavailable", true)).unwrap();

        assert_eq!(document["ok"], false);
        assert_eq!(document["error"]["code"], "daemon-unavailable");
        assert_eq!(document["error"]["retryable"], true);
        assert!(document.get("data").is_none());
    }

    #[test]
    fn maximum_preview_event_fits_the_desktop_line_budget() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let stream = EventStream::new("enroll");
        let event = stream.value(
            "preview",
            false,
            Some(json!({
                "frame_jpeg_base64": STANDARD.encode(vec![0_u8; 96 * 1024]),
                "width": 640,
                "height": 480,
                "spectrum": "ir",
                "landmarks": vec![[1.0_f32, 1.0_f32]; 478],
                "face_box": [0.0, 0.0, 1.0, 1.0],
                "position": {
                    "face_detected": true,
                    "centered": true,
                    "facing_camera": true,
                    "well_lit": true,
                    "ir_ready": true,
                    "well_framed": true,
                    "quality": 100,
                    "countdown": 3,
                    "guidance": "x".repeat(160)
                }
            })),
            None,
        );
        let line = serde_json::to_vec(&event).unwrap();
        assert!(
            line.len() < 256 * 1024,
            "maximum preview event is {} bytes",
            line.len()
        );
    }

    #[test]
    fn operation_error_codes_are_stable_and_exhaustive() {
        assert_eq!(
            operation_error_code(OperationErrorCode::CameraBusy),
            "camera-busy"
        );
        assert_eq!(
            operation_error_code(OperationErrorCode::NotAuthorized),
            "not-authorized"
        );
        assert_eq!(
            operation_error_code(OperationErrorCode::Cancelled),
            "user-cancelled"
        );
        assert_eq!(operation_error_code(OperationErrorCode::Timeout), "timeout");
        assert_eq!(
            operation_error_code(OperationErrorCode::PreconditionFailed),
            "precondition-failed"
        );
        assert_eq!(
            operation_error_code(OperationErrorCode::HardwareUnavailable),
            "hardware-unavailable"
        );
        assert_eq!(
            operation_error_code(OperationErrorCode::ProtocolError),
            "protocol-error"
        );
        assert_eq!(
            operation_error_code(OperationErrorCode::OperationFailed),
            "operation-failed"
        );
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
