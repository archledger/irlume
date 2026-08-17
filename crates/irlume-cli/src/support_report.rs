// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Privacy-bounded support report collection, rendering, and publication.

use irlume_common::artifact::SecureArtifact;
use irlume_common::diagnostics::{
    CaptureSchedule, CaptureScheduleSource, ProbeOutcome, ProbeRoleOutcome, ShareSafeEventKind,
    SupportProbeResult, SupportSnapshot, SupportUnavailable, UnavailableReason,
};
use irlume_common::{Request, Response};
use serde::Serialize;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const REPORT_SCHEMA: u32 = 1;
const DEFAULT_HISTORY_MS: u64 = 10 * 60 * 1_000;
const MAX_HISTORY_MS: u64 = 30 * 60 * 1_000;
const MAX_REPORT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectivePrivilege {
    Root,
    User,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckState {
    Pass,
    Warn,
    Fail,
    Unknown,
    Info,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckId {
    PlatformSupported,
    InstallChannel,
    DaemonReachable,
    TpmPresent,
    SecureBoot,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallChannel {
    FedoraCopr,
    LocalRpm,
    UbuntuPpa,
    LocalDeb,
    ArchPackage,
    Source,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) struct SupportCheck {
    pub id: CheckId,
    pub state: CheckState,
}

#[derive(Serialize)]
pub(crate) struct SupportReport {
    pub report_schema: u32,
    pub engine_version: &'static str,
    pub created_utc: String,
    pub effective_privilege: EffectivePrivilege,
    pub platform: &'static str,
    pub kernel_release: String,
    pub install_channel: InstallChannel,
    pub checks: Vec<SupportCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon: Option<SupportSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<SupportProbeResult>,
    pub unavailable: Vec<SupportUnavailable>,
}

pub(crate) fn parse_since(raw: Option<&str>) -> Result<Duration, &'static str> {
    let Some(raw) = raw else {
        return Ok(Duration::from_millis(DEFAULT_HISTORY_MS));
    };
    let (digits, multiplier) = if let Some(value) = raw.strip_suffix('s') {
        (value, 1_000_u64)
    } else if let Some(value) = raw.strip_suffix('m') {
        (value, 60_000_u64)
    } else if let Some(value) = raw.strip_suffix('h') {
        (value, 3_600_000_u64)
    } else {
        return Err("--since needs a whole-number suffix: s, m, or h");
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|_| "--since needs a positive whole number")?;
    if amount == 0 {
        return Err("--since must be greater than zero");
    }
    let milliseconds = amount
        .checked_mul(multiplier)
        .ok_or("--since is too large")?
        .min(MAX_HISTORY_MS);
    Ok(Duration::from_millis(milliseconds))
}

pub(crate) fn collect(since: Duration, probe: bool) -> SupportReport {
    let install_channel = match crate::commands::install_origin() {
        crate::commands::InstallOrigin::Copr => InstallChannel::FedoraCopr,
        crate::commands::InstallOrigin::LocalRpm(_) => InstallChannel::LocalRpm,
        crate::commands::InstallOrigin::Ppa => InstallChannel::UbuntuPpa,
        crate::commands::InstallOrigin::LocalDeb => InstallChannel::LocalDeb,
        crate::commands::InstallOrigin::ArchPkg => InstallChannel::ArchPackage,
        crate::commands::InstallOrigin::Source => InstallChannel::Source,
    };
    let platform = irlume_common::platform::distro_family().as_str();
    let mut checks = vec![
        SupportCheck {
            id: CheckId::PlatformSupported,
            state: if platform == "other" {
                CheckState::Warn
            } else {
                CheckState::Pass
            },
        },
        SupportCheck {
            id: CheckId::InstallChannel,
            state: CheckState::Info,
        },
        SupportCheck {
            id: CheckId::TpmPresent,
            state: if crate::tpm_device().is_some() {
                CheckState::Pass
            } else {
                CheckState::Fail
            },
        },
        SupportCheck {
            id: CheckId::SecureBoot,
            state: if !irlume_common::secureboot::secure_boot_present() {
                CheckState::Unknown
            } else if irlume_common::secureboot::is_secure_boot_enabled() {
                CheckState::Pass
            } else {
                CheckState::Warn
            },
        },
    ];
    let since_ms = u64::try_from(since.as_millis())
        .unwrap_or(u64::MAX)
        .min(MAX_HISTORY_MS);
    let response = crate::daemon_request(&if probe {
        Request::SupportProbe { since_ms }
    } else {
        Request::SupportSnapshot { since_ms }
    });
    let (daemon, probe_result, mut unavailable, daemon_state) = match response {
        Ok(Response::SupportSnapshot(snapshot)) => {
            (Some(*snapshot), None, Vec::new(), CheckState::Pass)
        }
        Ok(Response::SupportProbe(result)) => {
            let snapshot = result.snapshot.clone();
            (Some(snapshot), Some(*result), Vec::new(), CheckState::Pass)
        }
        Ok(Response::OperationError {
            code: irlume_common::OperationErrorCode::NotAuthorized,
            ..
        }) => (
            None,
            None,
            vec![SupportUnavailable {
                section: irlume_common::diagnostics::SupportSection::SupportProbe,
                reason: UnavailableReason::NotAuthorized,
            }],
            CheckState::Pass,
        ),
        Ok(_) | Err(_) => (
            None,
            None,
            vec![SupportUnavailable {
                section: irlume_common::diagnostics::SupportSection::Daemon,
                reason: UnavailableReason::DaemonUnavailable,
            }],
            CheckState::Unknown,
        ),
    };
    checks.push(SupportCheck {
        id: CheckId::DaemonReachable,
        state: daemon_state,
    });
    if daemon
        .as_ref()
        .is_some_and(|snapshot| snapshot.cameras().is_empty())
    {
        unavailable.push(SupportUnavailable {
            section: irlume_common::diagnostics::SupportSection::CameraContext,
            reason: UnavailableReason::CollectionFailed,
        });
    }
    if daemon
        .as_ref()
        .is_some_and(|snapshot| snapshot.capture().is_none())
    {
        unavailable.push(SupportUnavailable {
            section: irlume_common::diagnostics::SupportSection::CaptureSchedule,
            reason: UnavailableReason::CollectionFailed,
        });
    }
    SupportReport {
        report_schema: REPORT_SCHEMA,
        engine_version: env!("CARGO_PKG_VERSION"),
        created_utc: utc_timestamp(),
        effective_privilege: if effective_uid() == 0 {
            EffectivePrivilege::Root
        } else {
            EffectivePrivilege::User
        },
        platform,
        kernel_release: kernel_release(),
        install_channel,
        checks,
        daemon,
        probe: probe_result,
        unavailable,
    }
}

pub(crate) fn render_text(report: &SupportReport) -> Result<Vec<u8>, &'static str> {
    let mut body = String::new();
    writeln!(body, "IRLUME SUPPORT REPORT").unwrap();
    writeln!(body, "Privacy: inspect before sharing. This report contains no frames, templates, credentials, usernames, raw camera serials, raw device paths, or journal prose.").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "Report").unwrap();
    writeln!(body, "  schema: {}", report.report_schema).unwrap();
    writeln!(body, "  irlume: {}", report.engine_version).unwrap();
    writeln!(body, "  created UTC: {}", report.created_utc).unwrap();
    writeln!(
        body,
        "  privilege: {}",
        match report.effective_privilege {
            EffectivePrivilege::Root => "root",
            EffectivePrivilege::User => "user",
        }
    )
    .unwrap();
    writeln!(body).unwrap();
    writeln!(body, "Platform and installation").unwrap();
    writeln!(body, "  platform: {}", report.platform).unwrap();
    writeln!(body, "  kernel: {}", report.kernel_release).unwrap();
    writeln!(
        body,
        "  install channel: {}",
        install_channel_name(report.install_channel)
    )
    .unwrap();
    for check in &report.checks {
        writeln!(
            body,
            "  check {}: {}",
            check_id_name(check.id),
            check_state_name(check.state)
        )
        .unwrap();
    }

    writeln!(body).unwrap();
    writeln!(body, "Camera context").unwrap();
    match &report.daemon {
        Some(snapshot) if snapshot.cameras().is_empty() => {
            writeln!(body, "  no sanitized camera context retained").unwrap();
        }
        Some(snapshot) => {
            for camera in snapshot.cameras() {
                writeln!(
                    body,
                    "  {:04x}:{:04x} {:?} interface={} speed={}Mbps generation={} serial-present={}",
                    camera.vid,
                    camera.pid,
                    camera.role,
                    camera.interface_number,
                    camera.speed_millimbps / 1_000,
                    camera.lifecycle_generation,
                    camera.serial_present
                )
                .unwrap();
            }
        }
        None => writeln!(body, "  unavailable").unwrap(),
    }

    writeln!(body).unwrap();
    writeln!(body, "Capture schedule and qualification").unwrap();
    if let Some(probe) = &report.probe {
        writeln!(
            body,
            "  probe: {} via {} ({})",
            schedule_name(probe.schedule),
            schedule_source_name(probe.source),
            probe_outcome_name(probe.outcome)
        )
        .unwrap();
        writeln!(
            body,
            "  roles: RGB={} IR={}",
            role_outcome_name(probe.rgb),
            role_outcome_name(probe.ir)
        )
        .unwrap();
    } else if let Some(capture) = report.daemon.as_ref().and_then(SupportSnapshot::capture) {
        writeln!(
            body,
            "  current: {} via {}",
            schedule_name(capture.schedule),
            schedule_source_name(capture.source)
        )
        .unwrap();
        writeln!(body, "  qualification: {:?}", capture.qualification_state).unwrap();
    } else {
        writeln!(body, "  no current capture decision retained").unwrap();
    }

    writeln!(body).unwrap();
    writeln!(body, "Recent typed events").unwrap();
    match &report.daemon {
        Some(snapshot) if snapshot.events().is_empty() => writeln!(body, "  none").unwrap(),
        Some(snapshot) => {
            for event in snapshot.events() {
                writeln!(
                    body,
                    "  #{} age={}ms id={:?} operation={:?} {}",
                    event.sequence,
                    event.age_ms,
                    event.operation_id,
                    event.operation,
                    event_summary(&event.kind)
                )
                .unwrap();
            }
        }
        None => writeln!(body, "  unavailable").unwrap(),
    }

    writeln!(body).unwrap();
    writeln!(body, "Unavailable sections").unwrap();
    if report.unavailable.is_empty()
        && report
            .daemon
            .as_ref()
            .is_none_or(|snapshot| snapshot.unavailable().is_empty())
    {
        writeln!(body, "  none").unwrap();
    } else {
        for unavailable in report
            .unavailable
            .iter()
            .chain(report.daemon.iter().flat_map(|s| s.unavailable()))
        {
            writeln!(
                body,
                "  {:?}: {:?}",
                unavailable.section, unavailable.reason
            )
            .unwrap();
        }
    }
    writeln!(body).unwrap();
    writeln!(body, "Privacy checklist").unwrap();
    writeln!(body, "  [x] no images or biometric templates").unwrap();
    writeln!(body, "  [x] no credentials or account/profile names").unwrap();
    writeln!(
        body,
        "  [x] no raw device paths, serials, emitter payloads, or journals"
    )
    .unwrap();

    if body.len() as u64 > MAX_REPORT_BYTES.saturating_sub(96) {
        return Err("support report exceeds 1 MiB");
    }
    let digest = irlume_common::sha256_hex(body.as_bytes());
    writeln!(body, "SHA-256 (body): {digest}").unwrap();
    if body.len() as u64 > MAX_REPORT_BYTES {
        return Err("support report exceeds 1 MiB");
    }
    Ok(body.into_bytes())
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    let parsed = match parse_human_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("irlume support-report: {message}");
            return ExitCode::from(2);
        }
    };
    if parsed.probe && effective_uid() != 0 {
        eprintln!("irlume support-report: --probe requires root because it activates the camera and IR emitter");
        return ExitCode::from(2);
    }
    if parsed.probe {
        eprintln!("irlume support-report: probe requested; the camera and IR emitter may activate");
    }
    let report = collect(parsed.since, parsed.probe);
    let bytes = match render_text(&report) {
        Ok(bytes) => bytes,
        Err(message) => {
            eprintln!("irlume support-report: {message}");
            return ExitCode::FAILURE;
        }
    };
    let output = parsed.output.unwrap_or_else(default_output_path);
    let mut artifact = match SecureArtifact::create(&output, MAX_REPORT_BYTES) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("irlume support-report: {}: {error}", output.display());
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = artifact.write_chunk(&bytes) {
        eprintln!("irlume support-report: {}: {error}", output.display());
        return ExitCode::FAILURE;
    }
    match artifact.commit() {
        Ok(published) => {
            if let Some(warning) = published.durability_warning {
                eprintln!("irlume support-report: durability warning: {warning}");
            }
            println!("Support report created: {}", published.final_path.display());
            println!("Inspect it before sharing.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("irlume support-report: {}: {error}", output.display());
            ExitCode::FAILURE
        }
    }
}

struct HumanArgs {
    output: Option<PathBuf>,
    since: Duration,
    probe: bool,
}

fn parse_human_args(args: &[String]) -> Result<HumanArgs, &'static str> {
    if args.first().map(String::as_str) != Some("support-report") {
        return Err("invalid command");
    }
    let mut output = None;
    let mut since = None;
    let mut probe = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--probe" if !probe => {
                probe = true;
                index += 1;
            }
            "--output" if output.is_none() => {
                let value = args.get(index + 1).ok_or("--output requires a path")?;
                if value.starts_with('-') || value.is_empty() {
                    return Err("--output requires a path");
                }
                output = Some(PathBuf::from(value));
                index += 2;
            }
            value if value.starts_with("--output=") && output.is_none() => {
                let value = value.trim_start_matches("--output=");
                if value.is_empty() {
                    return Err("--output requires a path");
                }
                output = Some(PathBuf::from(value));
                index += 1;
            }
            "--since" if since.is_none() => {
                let value = args.get(index + 1).ok_or("--since requires a duration")?;
                since = Some(parse_since(Some(value))?);
                index += 2;
            }
            value if value.starts_with("--since=") && since.is_none() => {
                since = Some(parse_since(Some(value.trim_start_matches("--since=")))?);
                index += 1;
            }
            "--json" | "--contract" => {
                return Err("machine flags must use `support-report --json --contract 1`");
            }
            _ => {
                return Err(
                    "usage: irlume support-report [--output FILE.txt] [--since 10m] [--probe]",
                )
            }
        }
    }
    if output
        .as_deref()
        .is_some_and(|path| path.extension().and_then(|s| s.to_str()) != Some("txt"))
    {
        return Err("--output must end in .txt");
    }
    Ok(HumanArgs {
        output,
        since: since.unwrap_or(Duration::from_millis(DEFAULT_HISTORY_MS)),
        probe,
    })
}

fn default_output_path() -> PathBuf {
    PathBuf::from(format!("irlume-support-{}.txt", utc_filename_timestamp()))
}

fn effective_uid() -> u32 {
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "libc has no safe uid wrapper"
    )]
    unsafe {
        libc::geteuid()
    }
}

fn utc_timestamp() -> String {
    format_utc("%Y-%m-%dT%H:%M:%SZ").unwrap_or_else(|| "unknown".into())
}

fn utc_filename_timestamp() -> String {
    format_utc("%Y%m%d-%H%M%S").unwrap_or_else(|| "unknown-time".into())
}

fn format_utc(format: &str) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let seconds = libc::time_t::try_from(now.as_secs()).ok()?;
    let mut broken_down = std::mem::MaybeUninit::<libc::tm>::uninit();
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "validated libc pointers and buffer"
    )]
    let result = unsafe { libc::gmtime_r(&seconds, broken_down.as_mut_ptr()) };
    if result.is_null() {
        return None;
    }
    // SAFETY: `gmtime_r` returned this exact non-null destination pointer, so
    // it initialized the `tm` value before we read it.
    let broken_down = unsafe { broken_down.assume_init() };
    let format = std::ffi::CString::new(format).ok()?;
    let mut buffer = [0_u8; 32];
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "validated libc pointers and buffer"
    )]
    let written = unsafe {
        libc::strftime(
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            format.as_ptr(),
            &broken_down,
        )
    };
    (written > 0).then(|| String::from_utf8_lossy(&buffer[..written]).into_owned())
}

fn kernel_release() -> String {
    let mut name = std::mem::MaybeUninit::<libc::utsname>::uninit();
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "libc initializes utsname on success"
    )]
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return "unknown".into();
    }
    // SAFETY: `uname` returned success, which initializes the complete struct.
    let name = unsafe { name.assume_init() };
    // SAFETY: a successful `uname` supplies a NUL-terminated `release` array.
    let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) }.to_string_lossy();
    let sanitized: String = release
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || "._+-".contains(*character))
        .take(96)
        .collect();
    if sanitized.is_empty() {
        "unknown".into()
    } else {
        sanitized
    }
}

fn check_id_name(value: CheckId) -> &'static str {
    match value {
        CheckId::PlatformSupported => "platform_supported",
        CheckId::InstallChannel => "install_channel",
        CheckId::DaemonReachable => "daemon_reachable",
        CheckId::TpmPresent => "tpm_present",
        CheckId::SecureBoot => "secure_boot",
    }
}

fn check_state_name(value: CheckState) -> &'static str {
    match value {
        CheckState::Pass => "pass",
        CheckState::Warn => "warn",
        CheckState::Fail => "fail",
        CheckState::Unknown => "unknown",
        CheckState::Info => "info",
    }
}

fn install_channel_name(value: InstallChannel) -> &'static str {
    match value {
        InstallChannel::FedoraCopr => "fedora_copr",
        InstallChannel::LocalRpm => "local_rpm",
        InstallChannel::UbuntuPpa => "ubuntu_ppa",
        InstallChannel::LocalDeb => "local_deb",
        InstallChannel::ArchPackage => "arch_package",
        InstallChannel::Source => "source",
    }
}

fn schedule_name(value: CaptureSchedule) -> &'static str {
    match value {
        CaptureSchedule::Sequential => "sequential",
        CaptureSchedule::Concurrent => "concurrent",
    }
}

fn schedule_source_name(value: CaptureScheduleSource) -> &'static str {
    match value {
        CaptureScheduleSource::EnvironmentOverride => "environment_override",
        CaptureScheduleSource::StoredQualification => "stored_qualification",
        CaptureScheduleSource::SequentialDefault => "sequential_default",
        CaptureScheduleSource::RuntimeHealth => "runtime_health",
        CaptureScheduleSource::NoIrPair => "no_ir_pair",
    }
}

fn probe_outcome_name(value: ProbeOutcome) -> &'static str {
    match value {
        ProbeOutcome::Captured => "captured",
        ProbeOutcome::FallbackCaptured => "fallback_captured",
        ProbeOutcome::RgbOnlyCaptured => "rgb_only_captured",
        ProbeOutcome::Unavailable => "unavailable",
        ProbeOutcome::Failed => "failed",
    }
}

fn role_outcome_name(value: ProbeRoleOutcome) -> &'static str {
    match value {
        ProbeRoleOutcome::Captured => "captured",
        ProbeRoleOutcome::Missing => "missing",
        ProbeRoleOutcome::Failed => "failed",
    }
}

fn event_summary(value: &ShareSafeEventKind) -> String {
    match value {
        ShareSafeEventKind::LifecycleChanged { role, generation } => {
            format!("lifecycle_changed role={role:?} generation={generation}")
        }
        ShareSafeEventKind::CaptureScheduleSelected { schedule, source } => format!(
            "capture_schedule_selected schedule={} source={}",
            schedule_name(*schedule),
            schedule_source_name(*source)
        ),
        ShareSafeEventKind::QualificationChanged { state, reason } => {
            format!("qualification_changed state={state:?} reason={reason:?}")
        }
        ShareSafeEventKind::CaptureFallback { reason } => {
            format!("capture_fallback reason={reason:?}")
        }
        ShareSafeEventKind::OperationFinished { outcome } => {
            format!("operation_finished outcome={outcome:?}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_report() -> SupportReport {
        SupportReport {
            report_schema: 1,
            engine_version: "0.test",
            created_utc: "2026-08-17T12:00:00Z".into(),
            effective_privilege: EffectivePrivilege::User,
            platform: "arch",
            kernel_release: "6.12.1-test".into(),
            install_channel: InstallChannel::Source,
            checks: vec![SupportCheck {
                id: CheckId::DaemonReachable,
                state: CheckState::Unknown,
            }],
            daemon: None,
            probe: None,
            unavailable: vec![SupportUnavailable {
                section: irlume_common::diagnostics::SupportSection::Daemon,
                reason: UnavailableReason::DaemonUnavailable,
            }],
        }
    }

    #[test]
    fn support_report_is_inspectable_and_integrity_marked() {
        let text = String::from_utf8(render_text(&fixture_report()).unwrap()).unwrap();
        assert!(text.starts_with("IRLUME SUPPORT REPORT\nPrivacy:"));
        assert!(text.contains("Unavailable sections"));
        assert!(text.contains("SHA-256 (body):"));
        let (body, digest_line) = text.rsplit_once("SHA-256 (body): ").unwrap();
        assert_eq!(
            digest_line.trim(),
            irlume_common::sha256_hex(body.as_bytes())
        );
    }

    #[test]
    fn report_schema_has_no_arbitrary_doctor_detail_field() {
        let value = serde_json::to_value(fixture_report()).unwrap();
        let text = value.to_string();
        for forbidden in ["alice", "/dev/video9", "Face Profile 1", "detail"] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn since_is_bounded_and_requires_explicit_units() {
        assert_eq!(parse_since(Some("5m")).unwrap(), Duration::from_secs(300));
        assert_eq!(parse_since(Some("2h")).unwrap(), Duration::from_secs(1800));
        assert!(parse_since(Some("60")).is_err());
        assert!(parse_since(Some("0s")).is_err());
    }

    #[test]
    fn human_args_require_a_text_destination_and_reject_machine_flags() {
        assert!(parse_human_args(&["support-report".into()]).is_ok());
        assert!(parse_human_args(&[
            "support-report".into(),
            "--output".into(),
            "report.json".into()
        ])
        .is_err());
        assert!(parse_human_args(&["support-report".into(), "--json".into()]).is_err());
    }
}
