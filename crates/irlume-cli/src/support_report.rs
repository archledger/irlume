// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Privacy-bounded support report collection, rendering, and publication.

use irlume_common::artifact::SecureArtifact;
use irlume_common::diagnostics::{
    CaptureSchedule, CaptureScheduleSource, DigestToken, ExactStreamContract, OperationClass,
    ProbeOutcome, ProbeRoleOutcome, QualificationReason, QualificationState, RateShortfallEvidence,
    RateShortfallsByArm, RateShortfallsByRole, RuntimeViolationLabel, ShareSafeEventKind,
    SupportProbeResult, SupportSection, SupportSnapshot, SupportUnavailable, UnavailableReason,
};
use irlume_common::{Request, Response};
use serde::Serialize;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
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
    /// The nightly lanes (ADR-0037).
    FedoraCoprNightly,
    LocalRpm,
    UbuntuPpa,
    UbuntuPpaNightly,
    LocalDeb,
    ArchPackage,
    ArchGit,
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

/// The `platform_supported` state: a warning off the three supported
/// distribution families and NixOS. Decided on the family itself: its display
/// text is `other/unknown`, which the comparison with `"other"` this replaced
/// never matched, so an unsupported platform reported `pass`. NixOS is its own
/// supported platform, the flake's module (docs/NIXOS.md), although its family
/// is `Other`.
fn platform_check(family: &irlume_common::platform::DistroFamily, nixos: bool) -> CheckState {
    match family {
        irlume_common::platform::DistroFamily::Other if nixos => CheckState::Pass,
        irlume_common::platform::DistroFamily::Other => CheckState::Warn,
        irlume_common::platform::DistroFamily::Debian
        | irlume_common::platform::DistroFamily::Fedora
        | irlume_common::platform::DistroFamily::Arch => CheckState::Pass,
    }
}

/// The report's `platform` text and its `platform_supported` state, both from
/// one os-release text.
fn platform_facts(os_release: &str) -> (&'static str, CheckState) {
    let family = irlume_common::platform::distro_family_from(os_release);
    (
        family.as_str(),
        platform_check(&family, crate::nixos::is_nixos(os_release)),
    )
}

/// The HMAC input ahead of the daemon's 8 token bytes.
const REPORT_TOKEN_DOMAIN: &[u8] = b"irlume-support-report-token-v1\0";

/// A key drawn for one support report (ADR-0008, amendment 2026-11-12).
///
/// Each qualification and runtime context token of the report becomes the
/// first 8 bytes of HMAC-SHA-256 under this key, so equal tokens still
/// match within the report and two reports carry unrelated values. The key
/// is never stored, printed or put in the report, and its buffer is wiped
/// when it drops.
struct ReportTokenKey(zeroize::Zeroizing<[u8; 32]>);

impl ReportTokenKey {
    /// A new key from `rand::rng()`, the CSPRNG that `random_id` in
    /// `machine.rs` also uses.
    fn fresh() -> Self {
        use rand::Rng as _;
        let mut key = zeroize::Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(key.as_mut_slice());
        Self(key)
    }

    #[cfg(test)]
    fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// The report's value for one token from the daemon.
    fn token(&self, value: DigestToken) -> DigestToken {
        use hmac::{KeyInit as _, Mac as _};
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(self.0.as_slice())
            .expect("HMAC takes a key of any length");
        mac.update(REPORT_TOKEN_DOMAIN);
        mac.update(value.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        DigestToken::from_bytes(bytes)
    }

    /// Key each camera's qualification token and the capture section's
    /// qualification and runtime contexts. An absent token stays absent;
    /// the descriptor tokens stay as the daemon sent them.
    fn apply(&self, snapshot: &mut SupportSnapshot) {
        for camera in &mut snapshot.cameras {
            camera.qualification_token = camera.qualification_token.map(|value| self.token(value));
        }
        if let Some(capture) = snapshot.capture.as_mut() {
            capture.qualification_context =
                capture.qualification_context.map(|value| self.token(value));
            capture.runtime_context = capture.runtime_context.map(|value| self.token(value));
        }
    }

    /// Key a support reply: a snapshot, or a probe result's snapshot, which
    /// a probe report also copies into its daemon section. Other replies
    /// pass through unchanged.
    fn apply_to_reply(&self, reply: Response) -> Response {
        match reply {
            Response::SupportSnapshot(mut snapshot) => {
                self.apply(&mut snapshot);
                Response::SupportSnapshot(snapshot)
            }
            Response::SupportProbe(mut result) => {
                self.apply(&mut result.snapshot);
                Response::SupportProbe(result)
            }
            other => other,
        }
    }
}

pub(crate) fn collect(since: Duration, probe: bool) -> SupportReport {
    let install_channel = match crate::commands::install_origin() {
        crate::commands::InstallOrigin::Copr => InstallChannel::FedoraCopr,
        crate::commands::InstallOrigin::CoprNightly => InstallChannel::FedoraCoprNightly,
        crate::commands::InstallOrigin::LocalRpm(_) => InstallChannel::LocalRpm,
        crate::commands::InstallOrigin::Ppa => InstallChannel::UbuntuPpa,
        crate::commands::InstallOrigin::PpaNightly => InstallChannel::UbuntuPpaNightly,
        crate::commands::InstallOrigin::LocalDeb => InstallChannel::LocalDeb,
        crate::commands::InstallOrigin::ArchPkg => InstallChannel::ArchPackage,
        crate::commands::InstallOrigin::ArchGit => InstallChannel::ArchGit,
        crate::commands::InstallOrigin::Source => InstallChannel::Source,
    };
    // One reading of the system's os-release for the platform text and its
    // check: /etc/os-release, then /usr/lib/os-release, where
    // `distro_family()` reads /etc/os-release only. IRLUME_OS_RELEASE does
    // not apply: the report describes the host.
    let (platform, platform_state) =
        platform_facts(&crate::os_release::read_system().unwrap_or_default());
    let mut checks = vec![
        SupportCheck {
            id: CheckId::PlatformSupported,
            state: platform_state,
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
    // One key for every context token of this report, before a probe
    // result's snapshot is copied, so both copies carry the same values;
    // the key is a local of `collect` and is not kept.
    let token_key = ReportTokenKey::fresh();
    let response = response.map(|reply| token_key.apply_to_reply(reply));
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
                let ports = camera
                    .usb_port_chain
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(".");
                writeln!(
                    body,
                    "    transport: driver={} backend={} speed={}Mbps controller={} usb={}-{}",
                    camera.driver.as_str(),
                    camera.backend.as_str(),
                    camera.speed_millimbps / 1_000,
                    camera.controller.as_str(),
                    camera.usb_bus,
                    ports,
                )
                .unwrap();
                writeln!(
                    body,
                    "    tokens: descriptor={} qualification={}",
                    digest_token_text(camera.descriptor_token),
                    optional_digest_token_text(camera.qualification_token),
                )
                .unwrap();
                writeln!(
                    body,
                    "    requested: {}",
                    stream_contract_text(&camera.requested)
                )
                .unwrap();
                writeln!(
                    body,
                    "    accepted: {}",
                    stream_contract_text(&camera.accepted)
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
    } else {
        writeln!(body, "  no current capture decision retained").unwrap();
    }
    if let Some(capture) = report.daemon.as_ref().and_then(SupportSnapshot::capture) {
        writeln!(
            body,
            "  qualification: {} reason={}",
            qualification_state_name(capture.qualification_state),
            capture
                .qualification_reason
                .map(qualification_reason_name)
                .unwrap_or("none"),
        )
        .unwrap();
        writeln!(
            body,
            "  contexts: runtime={} qualification={} degradation={}",
            optional_digest_token_text(capture.runtime_context),
            optional_digest_token_text(capture.qualification_context),
            capture
                .runtime_degradation
                .map(runtime_violation_name)
                .unwrap_or("none"),
        )
        .unwrap();
        write_rate_shortfall_section(
            &mut body,
            "authoritative",
            capture.authoritative_rate_shortfalls.as_ref(),
        );
        write_rate_shortfall_section(
            &mut body,
            "latest-attempt",
            capture.latest_attempt_rate_shortfalls.as_ref(),
        );
    }

    writeln!(body).unwrap();
    writeln!(body, "Recent typed events").unwrap();
    match &report.daemon {
        Some(snapshot) => {
            if snapshot.events().is_empty() {
                writeln!(body, "  none").unwrap();
            }
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
            if withholds_other_accounts(snapshot) {
                writeln!(
                    body,
                    "  events of other accounts: withheld, a report run as root lists them"
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
    writeln!(body, "{}", authentication_checklist_line(report)).unwrap();

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
    let output = parsed.output.unwrap_or_else(default_output_path);
    match publish(collect(parsed.since, parsed.probe), &output) {
        Ok(path) => {
            println!("Support report created: {}", path.display());
            println!("Inspect it before sharing.");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("irlume support-report: {message}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn create_read_only_default() -> Result<PathBuf, String> {
    let output = default_output_path();
    publish(
        collect(Duration::from_millis(DEFAULT_HISTORY_MS), false),
        &output,
    )
}

fn publish(report: SupportReport, output: &Path) -> Result<PathBuf, String> {
    let bytes = render_text(&report).map_err(str::to_owned)?;
    let mut artifact = SecureArtifact::create(output, MAX_REPORT_BYTES)
        .map_err(|error| format!("{}: {error}", output.display()))?;
    artifact
        .write_chunk(&bytes)
        .map_err(|error| format!("{}: {error}", output.display()))?;
    let published = artifact
        .commit()
        .map_err(|error| format!("{}: {error}", output.display()))?;
    if let Some(warning) = published.durability_warning {
        eprintln!("irlume support-report: durability warning: {warning}");
    }
    Ok(published.final_path)
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

pub(crate) fn utc_filename_timestamp() -> String {
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
        InstallChannel::FedoraCoprNightly => "fedora_copr_nightly",
        InstallChannel::LocalRpm => "local_rpm",
        InstallChannel::UbuntuPpa => "ubuntu_ppa",
        InstallChannel::UbuntuPpaNightly => "ubuntu_ppa_nightly",
        InstallChannel::LocalDeb => "local_deb",
        InstallChannel::ArchPackage => "arch_package",
        InstallChannel::ArchGit => "arch_git",
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

fn digest_token_text(value: DigestToken) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn optional_digest_token_text(value: Option<DigestToken>) -> String {
    value.map_or_else(|| "none".into(), digest_token_text)
}

fn write_rate_shortfall_role(
    body: &mut String,
    arm: &str,
    role: &str,
    evidence: &RateShortfallEvidence,
) {
    let plural = if evidence.failure_count == 1 { "" } else { "s" };
    writeln!(
        body,
        "    {arm} {role}: {} shortfall{plural}, worst delivered {}/{} fps, required {}/{} fps, tolerance {}%, window {} deltas over {}us",
        evidence.failure_count,
        evidence.delivered_num,
        evidence.delivered_den,
        evidence.floor_num,
        evidence.floor_den,
        evidence.tolerance_percent,
        evidence.window_count,
        evidence.window_span_us,
    )
    .unwrap();
}

fn write_rate_shortfall_arm(body: &mut String, arm: &str, evidence: Option<&RateShortfallsByRole>) {
    let Some(evidence) = evidence else {
        writeln!(body, "    {arm}: legacy unknown").unwrap();
        return;
    };
    if evidence.rgb.is_none() && evidence.ir.is_none() {
        writeln!(body, "    {arm}: measured, no delivered-rate shortfalls").unwrap();
        return;
    }
    if let Some(rgb) = &evidence.rgb {
        write_rate_shortfall_role(body, arm, "RGB", rgb);
    }
    if let Some(ir) = &evidence.ir {
        write_rate_shortfall_role(body, arm, "IR", ir);
    }
}

fn write_rate_shortfall_section(
    body: &mut String,
    authority: &str,
    evidence: Option<&RateShortfallsByArm>,
) {
    let Some(evidence) = evidence else {
        writeln!(body, "  {authority} rate shortfalls: unavailable").unwrap();
        return;
    };
    writeln!(body, "  {authority} rate shortfalls").unwrap();
    write_rate_shortfall_arm(body, "sequential", evidence.sequential.as_ref());
    write_rate_shortfall_arm(body, "concurrent", evidence.concurrent.as_ref());
}

fn stream_contract_text(value: &ExactStreamContract) -> String {
    let fourcc = std::str::from_utf8(value.fourcc.as_bytes()).unwrap_or("????");
    format!(
        "{}x{} {} interval={}/{}",
        value.width,
        value.height,
        fourcc,
        value.interval.numerator.get(),
        value.interval.denominator.get(),
    )
}

fn qualification_state_name(value: QualificationState) -> &'static str {
    match value {
        QualificationState::QualifiedConcurrent => "qualified_concurrent",
        QualificationState::MeasuredSequential => "measured_sequential",
        QualificationState::UnqualifiedNoAuthority => "unqualified_no_authority",
        QualificationState::UnqualifiedContextChanged => "unqualified_context_changed",
        QualificationState::Inconclusive => "inconclusive",
        QualificationState::Unreadable => "unreadable",
        QualificationState::NoIrPair => "no_ir_pair",
    }
}

fn qualification_reason_name(value: QualificationReason) -> &'static str {
    match value {
        QualificationReason::ConcurrentUnavailable => "concurrent_unavailable",
        QualificationReason::DeliveredRateShortfall => "delivered_rate_shortfall",
        QualificationReason::SignalLoss => "signal_loss",
        QualificationReason::InvalidProvenance => "invalid_provenance",
        QualificationReason::NoStoredAuthority => "no_stored_authority",
        QualificationReason::ContextChanged => "context_changed",
        QualificationReason::IncompleteRounds => "incomplete_rounds",
        QualificationReason::DimScene => "dim_scene",
        QualificationReason::ContractDrift => "contract_drift",
        QualificationReason::MissingProvenance => "missing_provenance",
        QualificationReason::StoreUnreadable => "store_unreadable",
    }
}

fn runtime_violation_name(value: RuntimeViolationLabel) -> &'static str {
    match value {
        RuntimeViolationLabel::ConcurrentCaptureFailure => "concurrent_capture_failure",
        RuntimeViolationLabel::PairOpenFailure => "pair_open_failure",
        RuntimeViolationLabel::PairArmFailure => "pair_arm_failure",
        RuntimeViolationLabel::PairRateEstablishmentFailure => "pair_rate_establishment_failure",
        RuntimeViolationLabel::StreamRecovery => "stream_recovery",
        RuntimeViolationLabel::MissingRuntimeContract => "missing_runtime_contract",
        RuntimeViolationLabel::CameraGenerationChanged => "camera_generation_changed",
        RuntimeViolationLabel::StreamContractMismatch => "stream_contract_mismatch",
        RuntimeViolationLabel::DeliveredRateShortfall => "delivered_rate_shortfall",
        RuntimeViolationLabel::ContinuityLoss => "continuity_loss",
        RuntimeViolationLabel::ActiveIrMissing => "active_ir_missing",
        RuntimeViolationLabel::ConfirmedSignalLoss => "confirmed_signal_loss",
    }
}

/// Whether the daemon left other accounts' operations out of the recent
/// events: it marks recent events `NotAuthorized` for every reader but root.
/// An older daemon does not, and lists every account's.
fn withholds_other_accounts(snapshot: &SupportSnapshot) -> bool {
    snapshot.unavailable().iter().any(|unavailable| {
        unavailable.section == SupportSection::RecentEvents
            && unavailable.reason == UnavailableReason::NotAuthorized
    })
}

/// The privacy checklist's line for the authentication timeline: when the
/// recent events include authentications, whose they are, since their
/// times and outcomes (granted, denied, failed) are account history.
fn authentication_checklist_line(report: &SupportReport) -> &'static str {
    let Some(snapshot) = report.daemon.as_ref() else {
        return "  [x] no authentication times or outcomes";
    };
    let has = |class: OperationClass| {
        snapshot
            .events()
            .iter()
            .any(|event| event.operation == class)
    };
    if !has(OperationClass::Authentication) {
        // An irlumed from before this release labels keyring arms and token
        // releases, which are credential operations, as status events, and
        // does not withhold other accounts'. Without the withholding mark
        // the report cannot tell such a daemon from root's view of this
        // one, so status events are not taken as proof there are none.
        if has(OperationClass::Status) && !withholds_other_accounts(snapshot) {
            return "  [!] recent status events, which an older irlumed also uses for keyring \
                    arms and token releases: when each happened and its outcome";
        }
        return "  [x] no authentication times or outcomes";
    }
    if withholds_other_accounts(snapshot) {
        "  [!] this account's recent authentications: when each happened and its outcome"
    } else {
        "  [!] recent authentications of every account: when each happened and its outcome"
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
    use irlume_common::diagnostics::{
        CameraRoleLabel, CaptureStatus, DigestToken, ExactFraction, ExactStreamContract, FourCc,
        QualificationReason, QualificationState, RateShortfallEvidence, RateShortfallsByArm,
        RateShortfallsByRole, RuntimeViolationLabel, SafeLabel, SanitizedCameraContext,
    };

    /// An unsupported distribution warns; the three supported families and
    /// NixOS, whose family is `Other`, pass.
    #[test]
    fn platform_supported_warns_off_the_supported_families() {
        use irlume_common::platform::DistroFamily;
        assert!(matches!(
            platform_check(&DistroFamily::Other, false),
            CheckState::Warn
        ));
        assert!(matches!(
            platform_check(&DistroFamily::Other, true),
            CheckState::Pass
        ));
        for family in [
            DistroFamily::Debian,
            DistroFamily::Fedora,
            DistroFamily::Arch,
        ] {
            assert!(matches!(platform_check(&family, false), CheckState::Pass));
        }
    }

    /// The platform text and its check come from the same os-release text,
    /// whichever file it was read from (review on #1143).
    #[test]
    fn platform_facts_read_one_os_release_text() {
        let cases = [
            ("ID=debian\n", "Debian-family", true),
            ("ID=fedora\n", "Fedora-family", true),
            ("ID=arch\n", "Arch-family", true),
            ("NAME=NixOS\nID=nixos\n", "other/unknown", true),
            ("ID=opensuse-tumbleweed\n", "other/unknown", false),
            ("", "other/unknown", false),
        ];
        for (text, platform, passes) in cases {
            let (shown, state) = platform_facts(text);
            assert_eq!(shown, platform, "{text:?}");
            assert_eq!(matches!(state, CheckState::Pass), passes, "{text:?}");
            assert_eq!(matches!(state, CheckState::Warn), !passes, "{text:?}");
        }
    }

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

    fn fixture_camera_report_with_rate_shortfalls(
        authoritative_rate_shortfalls: Option<RateShortfallsByArm>,
        latest_attempt_rate_shortfalls: Option<RateShortfallsByArm>,
    ) -> SupportReport {
        let stream = ExactStreamContract {
            width: 640,
            height: 480,
            fourcc: FourCc::new(*b"YUYV").unwrap(),
            interval: ExactFraction::new(1, 30).unwrap(),
        };
        let camera = SanitizedCameraContext {
            vid: 0x046d,
            pid: 0x085e,
            role: CameraRoleLabel::Rgb,
            interface_number: 0,
            driver: SafeLabel::new("uvcvideo").unwrap(),
            backend: SafeLabel::new("uvc-v4l2").unwrap(),
            speed_millimbps: 5_000_000,
            controller: SafeLabel::new("0000:0d:00.3").unwrap(),
            usb_bus: 4,
            usb_port_chain: vec![2],
            lifecycle_generation: 3,
            serial_present: true,
            descriptor_token: DigestToken::from_bytes([0x12; 8]),
            qualification_token: Some(DigestToken::from_bytes([0x34; 8])),
            requested: stream.clone(),
            accepted: stream,
        };
        let capture = CaptureStatus {
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::StoredQualification,
            runtime_context: Some(DigestToken::from_bytes([0x56; 8])),
            qualification_state: QualificationState::MeasuredSequential,
            qualification_reason: Some(QualificationReason::DeliveredRateShortfall),
            qualification_context: Some(DigestToken::from_bytes([0x34; 8])),
            runtime_degradation: Some(RuntimeViolationLabel::DeliveredRateShortfall),
            authoritative_rate_shortfalls,
            latest_attempt_rate_shortfalls,
        };
        let mut report = fixture_report();
        report.daemon = Some(SupportSnapshot::bounded(
            42_000,
            60_000,
            Some(capture),
            vec![camera],
            Vec::new(),
            Vec::new(),
        ));
        report
    }

    fn fixture_camera_report() -> SupportReport {
        fixture_camera_report_with_rate_shortfalls(
            Some(RateShortfallsByArm {
                sequential: None,
                concurrent: Some(RateShortfallsByRole {
                    rgb: Some(RateShortfallEvidence {
                        role: CameraRoleLabel::Rgb,
                        failure_count: 4,
                        delivered_num: 10,
                        delivered_den: 1,
                        floor_num: 15,
                        floor_den: 1,
                        tolerance_percent: 98,
                        window_count: 30,
                        window_span_us: 3_000_000,
                    }),
                    ir: None,
                }),
            }),
            Some(RateShortfallsByArm {
                sequential: Some(RateShortfallsByRole::default()),
                concurrent: Some(RateShortfallsByRole {
                    rgb: None,
                    ir: Some(RateShortfallEvidence {
                        role: CameraRoleLabel::Ir,
                        failure_count: 1,
                        delivered_num: 14,
                        delivered_den: 1,
                        floor_num: 15,
                        floor_den: 1,
                        tolerance_percent: 98,
                        window_count: 30,
                        window_span_us: 3_000_000,
                    }),
                }),
            }),
        )
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
    fn human_report_includes_sanitized_topology_contracts_and_capture_authority() {
        let text = String::from_utf8(render_text(&fixture_camera_report()).unwrap()).unwrap();

        assert!(text.contains(
            "transport: driver=uvcvideo backend=uvc-v4l2 speed=5000Mbps controller=0000:0d:00.3 usb=4-2"
        ));
        assert!(text.contains("tokens: descriptor=1212121212121212 qualification=3434343434343434"));
        assert!(text.contains("requested: 640x480 YUYV interval=1/30"));
        assert!(text.contains("accepted: 640x480 YUYV interval=1/30"));
        assert!(text.contains("qualification: measured_sequential reason=delivered_rate_shortfall"));
        assert!(text.contains(
            "contexts: runtime=5656565656565656 qualification=3434343434343434 degradation=delivered_rate_shortfall"
        ));
        let rate_sections = concat!(
            "  authoritative rate shortfalls\n",
            "    sequential: legacy unknown\n",
            "    concurrent RGB: 4 shortfalls, worst delivered 10/1 fps, required 15/1 fps, tolerance 98%, window 30 deltas over 3000000us\n",
            "  latest-attempt rate shortfalls\n",
            "    sequential: measured, no delivered-rate shortfalls\n",
            "    concurrent IR: 1 shortfall, worst delivered 14/1 fps, required 15/1 fps, tolerance 98%, window 30 deltas over 3000000us",
        );
        assert!(text.contains(rate_sections));
        assert!(!text.contains("/dev/video"));
        assert!(!text.contains("raw-serial"));
    }

    #[test]
    fn human_report_distinguishes_legacy_unknown_rate_shortfall_arms() {
        let report = fixture_camera_report_with_rate_shortfalls(
            Some(RateShortfallsByArm::default()),
            Some(RateShortfallsByArm::default()),
        );
        let text = String::from_utf8(render_text(&report).unwrap()).unwrap();

        assert!(text.contains("authoritative rate shortfalls"));
        assert!(text.contains("sequential: legacy unknown"));
        assert!(text.contains("concurrent: legacy unknown"));
        assert!(text.contains("latest-attempt rate shortfalls"));
    }

    #[test]
    fn human_report_marks_absent_rate_shortfall_sections_unavailable() {
        let report = fixture_camera_report_with_rate_shortfalls(None, None);
        let text = String::from_utf8(render_text(&report).unwrap()).unwrap();

        assert!(text.contains("authoritative rate shortfalls: unavailable"));
        assert!(text.contains("latest-attempt rate shortfalls: unavailable"));
    }

    fn fixture_report_with_events(
        privilege: EffectivePrivilege,
        operations: &[OperationClass],
        unavailable: Vec<SupportUnavailable>,
    ) -> SupportReport {
        let events = operations
            .iter()
            .zip(1_u64..)
            .map(
                |(&operation, sequence)| irlume_common::diagnostics::ShareSafeEvent {
                    sequence,
                    age_ms: 1_000,
                    operation_id: irlume_common::diagnostics::OperationId::from_bytes(
                        [u8::try_from(sequence).unwrap(); 16],
                    ),
                    operation,
                    kind: ShareSafeEventKind::OperationFinished {
                        outcome: irlume_common::diagnostics::CategoricalOutcome::Denied,
                    },
                },
            )
            .collect();
        let mut report = fixture_report();
        report.effective_privilege = privilege;
        report.daemon = Some(SupportSnapshot::bounded(
            42_000,
            60_000,
            None,
            Vec::new(),
            events,
            unavailable,
        ));
        report
    }

    /// The privacy checklist names the authentication timeline when the
    /// recent events carry one, and whose it is: every account's in a
    /// report from root (or from an older daemon), only the account's own
    /// when the daemon withheld the others.
    #[test]
    fn privacy_checklist_names_the_authentication_timeline_it_contains() {
        let withheld = vec![SupportUnavailable {
            section: SupportSection::RecentEvents,
            reason: UnavailableReason::NotAuthorized,
        }];
        let render = |report: &SupportReport| {
            let text = String::from_utf8(render_text(report).unwrap()).unwrap();
            let checklist = text.split_once("Privacy checklist\n").unwrap().1.to_owned();
            (text, checklist)
        };

        let (text, checklist) = render(&fixture_report_with_events(
            EffectivePrivilege::Root,
            &[
                OperationClass::CameraDiagnostics,
                OperationClass::Authentication,
            ],
            Vec::new(),
        ));
        assert!(checklist.contains(
            "  [!] recent authentications of every account: when each happened and its outcome\n"
        ));
        assert!(!text.contains("events of other accounts: withheld"));

        let (text, checklist) = render(&fixture_report_with_events(
            EffectivePrivilege::User,
            &[OperationClass::Authentication],
            withheld.clone(),
        ));
        assert!(checklist.contains(
            "  [!] this account's recent authentications: when each happened and its outcome\n"
        ));
        assert!(text.contains(
            "Recent typed events\n  #1 age=1000ms id=OperationId(\"01010101010101010101010101010101\") operation=Authentication operation_finished outcome=Denied\n  events of other accounts: withheld, a report run as root lists them\n"
        ));

        let (text, checklist) = render(&fixture_report_with_events(
            EffectivePrivilege::User,
            &[OperationClass::Enrollment],
            withheld,
        ));
        assert!(checklist.contains("  [x] no authentication times or outcomes\n"));
        assert!(text.contains("events of other accounts: withheld"));

        let (_, checklist) = render(&fixture_report());
        assert!(checklist.contains("  [x] no authentication times or outcomes\n"));

        // Status events with no withholding mark may be an older daemon's
        // credential operations, so they are not taken as proof there are
        // none; with the mark they are status events only.
        let (_, checklist) = render(&fixture_report_with_events(
            EffectivePrivilege::User,
            &[OperationClass::Status],
            Vec::new(),
        ));
        assert!(
            checklist.contains("  [!] recent status events, which an older irlumed also uses"),
            "{checklist}"
        );
        assert!(!checklist.contains("[x] no authentication times or outcomes"));
        let (_, checklist) = render(&fixture_report_with_events(
            EffectivePrivilege::User,
            &[OperationClass::Status],
            vec![SupportUnavailable {
                section: SupportSection::RecentEvents,
                reason: UnavailableReason::NotAuthorized,
            }],
        ));
        assert!(checklist.contains("  [x] no authentication times or outcomes\n"));
    }

    #[test]
    fn report_schema_has_no_arbitrary_doctor_detail_field() {
        let value = serde_json::to_value(fixture_report()).unwrap();
        let text = value.to_string();
        for forbidden in ["alice", "/dev/video9", "Face Profile 1", "detail"] {
            assert!(!text.contains(forbidden));
        }
    }

    const FIXTURE_CONTROLLER: &str = "/devices/pci0000:00/0000:00:14.0";
    const FIXTURE_USB_DEVPATH: &str = "/devices/pci0000:00/0000:00:14.0/usb4/4-2";

    /// An RGB+IR pair context built through the camera crate's public
    /// constructors, as the daemon builds one from an opened pair.
    fn fixture_pair_context() -> irlume_camera::capture_qualification::QualificationContext {
        use irlume_camera::capture_qualification::{
            AcceptedStream, CameraEndpoint, ConnectionContext, ExactInterval, ExactRate,
            QualificationContext, QualifiedStreamRole, RequestedStream, StreamContract,
        };
        let endpoint = |role, interface_number, descriptor: &str| {
            CameraEndpoint::new(
                descriptor.repeat(32),
                0x046d,
                0x085e,
                None,
                interface_number,
                FIXTURE_USB_DEVPATH.into(),
                role,
                ConnectionContext::new(
                    FIXTURE_CONTROLLER.into(),
                    5_000_000,
                    "uvcvideo".into(),
                    "uvc-v4l2".into(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let stream = |role, fourcc: &str, height: u32, floor: ExactRate| {
            StreamContract::new(
                role,
                RequestedStream::new(
                    640,
                    height,
                    fourcc.into(),
                    ExactInterval::new(1, 30).unwrap(),
                )
                .unwrap(),
                AcceptedStream::new(
                    640,
                    height,
                    fourcc.into(),
                    1_280,
                    640 * height * 2,
                    0,
                    8,
                    1,
                    1,
                    0,
                    ExactInterval::new(1, 30).unwrap(),
                )
                .unwrap(),
                floor,
            )
            .unwrap()
        };
        QualificationContext::new(
            endpoint(QualifiedStreamRole::Rgb, 0, "ab"),
            endpoint(QualifiedStreamRole::Ir, 2, "cd"),
            stream(
                QualifiedStreamRole::Rgb,
                "YUYV",
                480,
                ExactRate::new(15, 2).unwrap(),
            ),
            stream(
                QualifiedStreamRole::Ir,
                "GREY",
                400,
                ExactRate::new(15, 1).unwrap(),
            ),
        )
        .unwrap()
    }

    /// The tokens a rendered report prints: each camera row's descriptor
    /// and qualification values, then the capture section's runtime and
    /// qualification values.
    struct PrintedTokens {
        descriptors: Vec<String>,
        qualifications: Vec<String>,
        runtime: String,
        capture_qualification: String,
    }

    fn printed_tokens(text: &str) -> PrintedTokens {
        let mut descriptors = Vec::new();
        let mut qualifications = Vec::new();
        let mut contexts = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("    tokens: descriptor=") {
                let (descriptor, qualification) = rest.split_once(" qualification=").unwrap();
                descriptors.push(descriptor.to_owned());
                qualifications.push(qualification.to_owned());
            } else if let Some(rest) = line.strip_prefix("  contexts: runtime=") {
                let (runtime, rest) = rest.split_once(" qualification=").unwrap();
                let (qualification, _) = rest.split_once(" degradation=").unwrap();
                assert!(contexts.is_none(), "one contexts line: {text}");
                contexts = Some((runtime.to_owned(), qualification.to_owned()));
            }
        }
        let (runtime, capture_qualification) = contexts.expect("a contexts line");
        PrintedTokens {
            descriptors,
            qualifications,
            runtime,
            capture_qualification,
        }
    }

    /// Two reports of one daemon snapshot, each keyed with a fresh key, as
    /// `collect` keys each report: within a report the two camera rows and
    /// the capture section carry one qualification value; between the
    /// reports every keyed value differs, and neither report carries the
    /// daemon's (ADR-0008, amendment 2026-11-12).
    #[test]
    fn report_tokens_match_within_a_report_and_differ_between_reports() {
        let context = fixture_pair_context();
        let context_key = context.runtime_key().unwrap();
        let cameras = context.diagnostic_camera_contexts(3, 3).unwrap();
        // The daemon's value today: the first 8 bytes of the pair's context
        // key, the same on both rows.
        let daemon_qualification = DigestToken::from_sha256_hex(&context_key).unwrap();
        assert!(cameras
            .iter()
            .all(|camera| camera.qualification_token == Some(daemon_qualification)));
        // Any runtime context does: the report keys the 8 bytes it is sent.
        let daemon_runtime = DigestToken::from_bytes([0x5a; 8]);
        let mut served = fixture_camera_report_with_rate_shortfalls(None, None)
            .daemon
            .unwrap();
        served.cameras = cameras.to_vec();
        let capture = served.capture.as_mut().unwrap();
        capture.qualification_context = cameras[0].qualification_token;
        capture.runtime_context = Some(daemon_runtime);

        let reports: Vec<(PrintedTokens, String, serde_json::Value)> = (0..2)
            .map(|_| {
                let mut snapshot = served.clone();
                ReportTokenKey::fresh().apply(&mut snapshot);
                let mut report = fixture_camera_report_with_rate_shortfalls(None, None);
                report.daemon = Some(snapshot);
                let text = String::from_utf8(render_text(&report).unwrap()).unwrap();
                let json = serde_json::to_string(&report).unwrap();
                for output in [&text, &json] {
                    // The report carries keyed values, not the served ones.
                    for absent in [
                        digest_token_text(daemon_qualification).as_str(),
                        context_key.as_str(),
                        digest_token_text(daemon_runtime).as_str(),
                    ] {
                        assert!(!output.contains(absent), "{absent} in {output}");
                    }
                    // The share-safe projection still holds no path.
                    for absent in ["/devices/", "/dev/video"] {
                        assert!(!output.contains(absent), "{absent} in {output}");
                    }
                }
                (
                    printed_tokens(&text),
                    text,
                    serde_json::from_str(&json).unwrap(),
                )
            })
            .collect();

        for (printed, text, json) in &reports {
            assert_eq!(
                printed.descriptors,
                [
                    digest_token_text(cameras[0].descriptor_token),
                    digest_token_text(cameras[1].descriptor_token),
                ],
                "descriptor tokens are the daemon's: {text}"
            );
            assert_eq!(
                printed.qualifications,
                [
                    printed.capture_qualification.clone(),
                    printed.capture_qualification.clone(),
                ],
                "{text}"
            );
            let daemon = &json["daemon"];
            for (row, camera) in daemon["cameras"].as_array().unwrap().iter().enumerate() {
                assert_eq!(camera["qualification_token"], printed.qualifications[row]);
                assert_eq!(camera["descriptor_token"], printed.descriptors[row]);
            }
            assert_eq!(
                daemon["capture"]["qualification_context"],
                printed.capture_qualification
            );
            assert_eq!(daemon["capture"]["runtime_context"], printed.runtime);
        }
        let (first, second) = (&reports[0].0, &reports[1].0);
        assert_ne!(first.capture_qualification, second.capture_qualification);
        assert_ne!(first.runtime, second.runtime);
    }

    /// A known answer for a fixed key: HMAC-SHA-256 over the domain string
    /// and the daemon's 8 bytes, cut to 8 bytes (values computed separately
    /// with Python's `hmac` and `hashlib`). Applied to a snapshot, it keys
    /// each qualification and runtime value from its own served value and
    /// leaves the descriptor's.
    #[test]
    fn report_token_key_gives_the_known_answers() {
        let key = ReportTokenKey::from_bytes_for_test([7; 32]);
        assert_eq!(
            digest_token_text(key.token(DigestToken::from_bytes([0x34; 8]))),
            "fcda260f0a840c2b"
        );
        assert_eq!(
            digest_token_text(key.token(DigestToken::from_bytes([0x56; 8]))),
            "b01f9ad8d0b2d5fb"
        );
        assert_eq!(
            digest_token_text(key.token(DigestToken::from_bytes([0x78; 8]))),
            "ac6b647e8cd3d729"
        );

        let mut report = fixture_camera_report();
        let snapshot = report.daemon.as_mut().unwrap();
        // A capture value other than the row's, so each is keyed from its own.
        snapshot.capture.as_mut().unwrap().qualification_context =
            Some(DigestToken::from_bytes([0x78; 8]));
        key.apply(snapshot);
        let text = String::from_utf8(render_text(&report).unwrap()).unwrap();
        assert!(
            text.contains("tokens: descriptor=1212121212121212 qualification=fcda260f0a840c2b"),
            "{text}"
        );
        assert!(
            text.contains("contexts: runtime=b01f9ad8d0b2d5fb qualification=ac6b647e8cd3d729 "),
            "{text}"
        );
    }

    /// A token the daemon did not send, as on an RGB-only host, is not
    /// made up: the report still prints `none`.
    #[test]
    fn report_token_key_leaves_an_absent_token_absent() {
        let mut report = fixture_camera_report_with_rate_shortfalls(None, None);
        let snapshot = report.daemon.as_mut().unwrap();
        snapshot.cameras[0].qualification_token = None;
        let capture = snapshot.capture.as_mut().unwrap();
        capture.qualification_context = None;
        capture.runtime_context = None;
        ReportTokenKey::fresh().apply(snapshot);

        let snapshot = report.daemon.as_ref().unwrap();
        assert_eq!(snapshot.cameras()[0].qualification_token, None);
        let capture = snapshot.capture().unwrap();
        assert_eq!(capture.qualification_context, None);
        assert_eq!(capture.runtime_context, None);
        let text = String::from_utf8(render_text(&report).unwrap()).unwrap();
        assert!(
            text.contains("tokens: descriptor=1212121212121212 qualification=none"),
            "{text}"
        );
        assert!(
            text.contains("contexts: runtime=none qualification=none "),
            "{text}"
        );
        let json = serde_json::to_string(&report).unwrap();
        for field in [
            "\"qualification_token\"",
            "\"qualification_context\"",
            "\"runtime_context\"",
        ] {
            assert!(!json.contains(field), "{field} in {json}");
        }
    }

    /// A probe reply's snapshot, which a probe report also copies into its
    /// daemon section, is keyed exactly as a snapshot reply is under the
    /// same key; other replies pass through.
    #[test]
    fn report_token_key_keys_a_probe_reply_like_a_snapshot_reply() {
        let key = ReportTokenKey::from_bytes_for_test([7; 32]);
        let served = fixture_camera_report().daemon.unwrap();
        let mut expected = served.clone();
        key.apply(&mut expected);
        assert_eq!(
            expected
                .capture()
                .unwrap()
                .runtime_context
                .map(digest_token_text)
                .as_deref(),
            Some("b01f9ad8d0b2d5fb")
        );

        let Response::SupportSnapshot(snapshot) =
            key.apply_to_reply(Response::SupportSnapshot(Box::new(served.clone())))
        else {
            panic!("a snapshot reply stays a snapshot reply");
        };
        assert_eq!(*snapshot, expected);

        let probe = SupportProbeResult {
            snapshot: served,
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::StoredQualification,
            outcome: ProbeOutcome::Captured,
            fallback_reason: None,
            rgb: ProbeRoleOutcome::Captured,
            ir: ProbeRoleOutcome::Captured,
        };
        let Response::SupportProbe(result) =
            key.apply_to_reply(Response::SupportProbe(Box::new(probe)))
        else {
            panic!("a probe reply stays a probe reply");
        };
        assert_eq!(result.snapshot, expected);
        assert!(matches!(key.apply_to_reply(Response::Pong), Response::Pong));
    }

    /// Removes a test's scratch directory when the test ends, whether it
    /// passed or failed.
    struct ScratchDir(PathBuf);

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `collect` twice in one process against a fake daemon, as the TUI
    /// collects one report after another: first without a probe, then with
    /// one. Each report carries its own keyed values, and neither carries
    /// the daemon's. In the probe report, the probe result's snapshot and
    /// the copy the report prints as its daemon section carry the same
    /// values. The text report prints only the copy, and `--json` never
    /// probes, so no command output shows the probe result's own snapshot.
    #[test]
    fn collect_draws_one_key_per_report_and_keys_a_probe_copy_with_it() {
        use std::io::{BufRead as _, Write as _};
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A random name, not the process ID: a run in another PID namespace
        // can get the same process ID. Short, as `sun_path` holds 108 bytes.
        let dir = std::env::temp_dir().join(format!(
            "irlume-support-report-{:08x}",
            rand::random::<u32>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _scratch = ScratchDir(dir.clone());
        let socket = dir.join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let served = fixture_camera_report().daemon.unwrap();
        let snapshot_reply = Response::SupportSnapshot(Box::new(served.clone()));
        let probe_reply = Response::SupportProbe(Box::new(SupportProbeResult {
            snapshot: served.clone(),
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::StoredQualification,
            outcome: ProbeOutcome::Captured,
            fallback_reason: None,
            rgb: ProbeRoleOutcome::Captured,
            ir: ProbeRoleOutcome::Captured,
        }));
        // IRLUME_SOCKET is process-wide: a request another test's worker
        // sends gets an error reply, and the server waits for the snapshot
        // request, then the probe request.
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut answered = 0;
            while answered < 2 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no snapshot and probe requests within 10 s"
                );
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fake daemon accept failed: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut line = String::new();
                let _ = std::io::BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
                let wanted = match (answered, serde_json::from_str::<Request>(&line)) {
                    (0, Ok(Request::SupportSnapshot { .. })) => Some(&snapshot_reply),
                    (1, Ok(Request::SupportProbe { .. })) => Some(&probe_reply),
                    _ => None,
                };
                let answer = match wanted {
                    Some(reply) => {
                        answered += 1;
                        reply.clone()
                    }
                    None => Response::Error("fake daemon: not the request under test".into()),
                };
                writeln!(stream, "{}", serde_json::to_string(&answer).unwrap()).unwrap();
            }
        });
        let previous = std::env::var_os("IRLUME_SOCKET");
        std::env::set_var("IRLUME_SOCKET", &socket);
        let first = collect(Duration::from_secs(60), false);
        let second = collect(Duration::from_secs(60), true);
        match previous {
            Some(value) => std::env::set_var("IRLUME_SOCKET", value),
            None => std::env::remove_var("IRLUME_SOCKET"),
        }
        server.join().unwrap();

        let (served_camera, served_capture) = (&served.cameras()[0], served.capture().unwrap());
        for report in [&first, &second] {
            let daemon = report.daemon.as_ref().expect("a daemon section");
            let camera = &daemon.cameras()[0];
            assert_eq!(camera.descriptor_token, served_camera.descriptor_token);
            assert!(camera.qualification_token.is_some());
            assert_ne!(
                camera.qualification_token,
                served_camera.qualification_token
            );
            let capture = daemon.capture().unwrap();
            assert_eq!(capture.qualification_context, camera.qualification_token);
            assert!(capture.runtime_context.is_some());
            assert_ne!(capture.runtime_context, served_capture.runtime_context);
        }
        assert!(first.probe.is_none());
        let probe = second.probe.as_ref().expect("the probe result");
        assert_eq!(Some(&probe.snapshot), second.daemon.as_ref());
        // The same served values give each report its own keyed values.
        let keyed = |report: &SupportReport| {
            let daemon = report.daemon.as_ref().unwrap();
            (
                daemon.cameras()[0].qualification_token,
                daemon.capture().unwrap().runtime_context,
            )
        };
        let (first_qualification, first_runtime) = keyed(&first);
        let (second_qualification, second_runtime) = keyed(&second);
        assert_ne!(first_qualification, second_qualification);
        assert_ne!(first_runtime, second_runtime);
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
