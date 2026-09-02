// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Detached signature verification for release-qualification artifacts.

#![allow(
    dead_code,
    reason = "production loading and selection consumers are implemented in later plan tasks"
)]

use std::{
    fmt,
    io::{Read as _, Write as _},
    os::{
        fd::AsRawFd as _,
        unix::fs::{
            DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use crate::release_qualification::{
    ReleaseQualificationArtifact, ReleaseQualificationError, MAX_RELEASE_QUALIFICATION_BYTES,
};

pub(crate) const ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT: &str =
    "F35053398E3C80FE20891B82C10B8492BD7F30C6";

const MAX_DETACHED_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_TRUSTED_PUBLIC_KEY_BYTES: usize = 64 * 1024;
const MAX_GPG_STATUS_BYTES: usize = 64 * 1024;
const DEFAULT_GPG_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_ARTIFACT_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseQualificationPaths {
    artifact: PathBuf,
    signature: PathBuf,
    trusted_key: PathBuf,
}

impl ReleaseQualificationPaths {
    pub(crate) fn system(artifact_name: &str) -> Result<Self, ReleaseSignatureError> {
        Self::under(Path::new("/usr"), artifact_name)
    }

    pub(crate) fn under(
        package_root: &Path,
        artifact_name: &str,
    ) -> Result<Self, ReleaseSignatureError> {
        if artifact_name.is_empty()
            || artifact_name.len() > MAX_ARTIFACT_NAME_BYTES
            || !artifact_name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
        {
            return Err(ReleaseSignatureError::InvalidArtifactName);
        }
        let share_root = package_root.join("share/irlume");
        let artifact = share_root
            .join("profile-qualifications")
            .join(format!("{artifact_name}.json"));
        Ok(Self {
            signature: artifact.with_extension("json.asc"),
            artifact,
            trusted_key: share_root.join("release-qualification-key.asc"),
        })
    }

    pub(crate) fn artifact(&self) -> &Path {
        &self.artifact
    }

    pub(crate) fn signature(&self) -> &Path {
        &self.signature
    }

    pub(crate) fn trusted_key(&self) -> &Path {
        &self.trusted_key
    }
}

pub(crate) trait DetachedSignatureVerifier {
    fn verify(
        &self,
        canonical_payload: &[u8],
        detached_signature: &[u8],
    ) -> Result<VerifiedSigner, ReleaseSignatureError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedSigner {
    fingerprint: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedReleaseQualification {
    artifact: ReleaseQualificationArtifact,
    artifact_sha256: String,
    signer_fingerprint: String,
}

impl VerifiedReleaseQualification {
    pub(crate) const fn artifact(&self) -> &ReleaseQualificationArtifact {
        &self.artifact
    }

    pub(crate) fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    pub(crate) fn signer_fingerprint(&self) -> &str {
        &self.signer_fingerprint
    }
}

pub(crate) fn verify_release_qualification_bytes(
    canonical_payload: &[u8],
    detached_signature: &[u8],
    now_unix: u64,
    verifier: &impl DetachedSignatureVerifier,
) -> Result<VerifiedReleaseQualification, ReleaseSignatureError> {
    if canonical_payload.len() > MAX_RELEASE_QUALIFICATION_BYTES {
        return Err(ReleaseSignatureError::ArtifactTooLarge);
    }
    if detached_signature.is_empty() {
        return Err(ReleaseSignatureError::SignatureMissing);
    }
    if detached_signature.len() > MAX_DETACHED_SIGNATURE_BYTES {
        return Err(ReleaseSignatureError::SignatureTooLarge);
    }

    let signer = verifier.verify(canonical_payload, detached_signature)?;
    if signer.fingerprint != ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT {
        return Err(ReleaseSignatureError::SignerUntrusted);
    }
    let artifact = ReleaseQualificationArtifact::from_canonical_json(canonical_payload)?;
    artifact.validate_at(now_unix)?;
    if artifact.signature().signer_fingerprint() != signer.fingerprint {
        return Err(ReleaseSignatureError::MetadataSignerMismatch);
    }
    Ok(VerifiedReleaseQualification {
        artifact,
        artifact_sha256: irlume_common::sha256_hex(canonical_payload),
        signer_fingerprint: signer.fingerprint,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseSignatureError {
    Artifact(ReleaseQualificationError),
    ArtifactMissing,
    ArtifactTooLarge,
    SignatureMissing,
    SignatureTooLarge,
    SignerUntrusted,
    MetadataSignerMismatch,
    InvalidSignature,
    InvalidConfiguration,
    TrustedKeyMissing,
    TrustedKeyTooLarge,
    Io,
    ProcessFailed,
    Timeout,
    StatusTooLarge,
    InvalidStatus,
    InvalidArtifactName,
    FileMissing,
    FileTooLarge,
    UnsafeFile,
}

impl From<ReleaseQualificationError> for ReleaseSignatureError {
    fn from(error: ReleaseQualificationError) -> Self {
        Self::Artifact(error)
    }
}

impl fmt::Display for ReleaseSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self {
            Self::Artifact(error) => return error.fmt(formatter),
            Self::ArtifactMissing => "release_qualification_missing",
            Self::ArtifactTooLarge => "release_qualification_too_large",
            Self::SignatureMissing => "release_qualification_signature_missing",
            Self::SignatureTooLarge => "release_qualification_signature_too_large",
            Self::SignerUntrusted => "release_qualification_signer_untrusted",
            Self::MetadataSignerMismatch => "release_qualification_signer_mismatch",
            Self::InvalidSignature => "release_qualification_signature_invalid",
            Self::InvalidConfiguration => "release_qualification_verifier_invalid",
            Self::TrustedKeyMissing => "release_qualification_key_missing",
            Self::TrustedKeyTooLarge => "release_qualification_key_too_large",
            Self::Io => "release_qualification_io_failed",
            Self::ProcessFailed => "release_qualification_verifier_failed",
            Self::Timeout => "release_qualification_verifier_timeout",
            Self::StatusTooLarge => "release_qualification_status_too_large",
            Self::InvalidStatus => "release_qualification_status_invalid",
            Self::InvalidArtifactName => "release_qualification_artifact_name_invalid",
            Self::FileMissing => "release_qualification_file_missing",
            Self::FileTooLarge => "release_qualification_file_too_large",
            Self::UnsafeFile => "release_qualification_file_unsafe",
        };
        formatter.write_str(category)
    }
}

impl std::error::Error for ReleaseSignatureError {}

#[cfg(test)]
pub(crate) struct FakeVerifier {
    result: Result<VerifiedSigner, ReleaseSignatureError>,
}

#[cfg(test)]
impl FakeVerifier {
    pub(crate) fn valid(fingerprint: &str) -> Self {
        Self {
            result: Ok(VerifiedSigner {
                fingerprint: fingerprint.to_owned(),
            }),
        }
    }

    pub(crate) fn invalid_signature() -> Self {
        Self {
            result: Err(ReleaseSignatureError::InvalidSignature),
        }
    }
}

#[cfg(test)]
impl DetachedSignatureVerifier for FakeVerifier {
    fn verify(
        &self,
        _canonical_payload: &[u8],
        _detached_signature: &[u8],
    ) -> Result<VerifiedSigner, ReleaseSignatureError> {
        self.result.clone()
    }
}

#[cfg(test)]
pub(crate) fn verified_release_fixture(
    baseline_id: &str,
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: crate::profile::CaptureSchedule,
    campaign_byte: u8,
    now_unix: u64,
) -> VerifiedReleaseQualification {
    verified_release_fixture_with_optional_descriptor(
        baseline_id,
        candidate_id,
        candidate_rgb_fps,
        candidate_ir_fps,
        candidate_schedule,
        campaign_byte,
        now_unix,
        None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn verified_release_fixture_with_descriptor(
    baseline_id: &str,
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: crate::profile::CaptureSchedule,
    campaign_byte: u8,
    now_unix: u64,
    rgb_descriptor_sha256: &str,
) -> VerifiedReleaseQualification {
    verified_release_fixture_with_optional_descriptor(
        baseline_id,
        candidate_id,
        candidate_rgb_fps,
        candidate_ir_fps,
        candidate_schedule,
        campaign_byte,
        now_unix,
        Some(rgb_descriptor_sha256),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn verified_release_fixture_with_optional_descriptor(
    baseline_id: &str,
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: crate::profile::CaptureSchedule,
    campaign_byte: u8,
    now_unix: u64,
    rgb_descriptor_sha256: Option<&str>,
) -> VerifiedReleaseQualification {
    assert!(now_unix > 1 && now_unix < u64::MAX - 604_800);
    let mut value = crate::release_qualification::fixture_artifact_value(baseline_id, candidate_id);
    for stream in ["requested_rgb", "accepted_rgb"] {
        value["candidate"][stream]["interval_denominator"] = serde_json::json!(candidate_rgb_fps);
    }
    for stream in ["requested_ir", "accepted_ir"] {
        value["candidate"][stream]["interval_denominator"] = serde_json::json!(candidate_ir_fps);
    }
    value["candidate"]["schedule"] = serde_json::to_value(candidate_schedule).unwrap();
    value["campaign_result_sha256"] = serde_json::json!(format!("{campaign_byte:02x}").repeat(32));
    if let Some(descriptor) = rgb_descriptor_sha256 {
        value["hardware_scope"]["rgb"]["descriptor_sha256"] = serde_json::json!(descriptor);
    }
    value["qualified_at_unix"] = serde_json::json!(now_unix - 1);
    value["expires_at_unix"] = serde_json::json!(now_unix + 604_800);
    let artifact: ReleaseQualificationArtifact = serde_json::from_value(value).unwrap();
    let canonical_payload = artifact.to_canonical_json().unwrap();
    verify_release_qualification_bytes(
        canonical_payload.as_bytes(),
        b"synthetic-signature",
        now_unix,
        &FakeVerifier::valid(ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT),
    )
    .unwrap()
}

pub(crate) struct GpgDetachedSignatureVerifier {
    executable_path: PathBuf,
    trusted_public_key: Vec<u8>,
    timeout: Duration,
    temp_root: PathBuf,
}

impl GpgDetachedSignatureVerifier {
    pub(crate) fn new(
        executable_path: PathBuf,
        trusted_public_key: Vec<u8>,
    ) -> Result<Self, ReleaseSignatureError> {
        Self::with_configuration(
            executable_path,
            trusted_public_key,
            DEFAULT_GPG_TIMEOUT,
            std::env::temp_dir(),
        )
    }

    fn with_configuration(
        executable_path: PathBuf,
        trusted_public_key: Vec<u8>,
        timeout: Duration,
        temp_root: PathBuf,
    ) -> Result<Self, ReleaseSignatureError> {
        if !executable_path.is_absolute() || timeout.is_zero() {
            return Err(ReleaseSignatureError::InvalidConfiguration);
        }
        if trusted_public_key.is_empty() {
            return Err(ReleaseSignatureError::TrustedKeyMissing);
        }
        if trusted_public_key.len() > MAX_TRUSTED_PUBLIC_KEY_BYTES {
            return Err(ReleaseSignatureError::TrustedKeyTooLarge);
        }
        Ok(Self {
            executable_path,
            trusted_public_key,
            timeout,
            temp_root,
        })
    }

    #[cfg(test)]
    fn with_timeout_and_temp_root_for_test(
        executable_path: PathBuf,
        trusted_public_key: Vec<u8>,
        timeout: Duration,
        temp_root: PathBuf,
    ) -> Result<Self, ReleaseSignatureError> {
        Self::with_configuration(executable_path, trusted_public_key, timeout, temp_root)
    }

    fn base_command(&self, home: &Path, status_path: &Path) -> Command {
        let mut command = Command::new(&self.executable_path);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .args([
                "--batch",
                "--no-options",
                "--no-tty",
                "--no-autostart",
                "--disable-dirmngr",
            ])
            .arg("--homedir")
            .arg(home)
            .arg("--status-file")
            .arg(status_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
}

impl DetachedSignatureVerifier for GpgDetachedSignatureVerifier {
    fn verify(
        &self,
        canonical_payload: &[u8],
        detached_signature: &[u8],
    ) -> Result<VerifiedSigner, ReleaseSignatureError> {
        if canonical_payload.len() > MAX_RELEASE_QUALIFICATION_BYTES {
            return Err(ReleaseSignatureError::ArtifactTooLarge);
        }
        if detached_signature.is_empty() {
            return Err(ReleaseSignatureError::SignatureMissing);
        }
        if detached_signature.len() > MAX_DETACHED_SIGNATURE_BYTES {
            return Err(ReleaseSignatureError::SignatureTooLarge);
        }

        let home = TemporaryGpgHome::create(&self.temp_root)?;
        let key_path = home.path().join("trusted-key.asc");
        let signature_path = home.path().join("detached-signature.asc");
        let status_path = home.path().join("status");
        write_private_file(&key_path, &self.trusted_public_key)?;
        write_private_file(&signature_path, detached_signature)?;
        write_private_file(&status_path, b"")?;

        let mut import = self.base_command(home.path(), &status_path);
        import.arg("--import").arg(&key_path).stdin(Stdio::null());
        run_child_without_input(&mut import, self.timeout)?;
        truncate_private_file(&status_path)?;

        let mut verify = self.base_command(home.path(), &status_path);
        verify
            .arg("--verify")
            .arg(&signature_path)
            .arg("-")
            .stdin(Stdio::piped());
        run_child_with_input(&mut verify, canonical_payload, self.timeout)?;
        let status = read_status_file(&status_path)?;
        parse_valid_signer(&status)
    }
}

pub(crate) fn verify_release_qualification_files(
    artifact_path: &Path,
    signature_path: &Path,
    trusted_key_path: &Path,
    executable_path: &Path,
    now_unix: u64,
) -> Result<VerifiedReleaseQualification, ReleaseSignatureError> {
    verify_release_qualification_files_with_owner(
        artifact_path,
        signature_path,
        trusted_key_path,
        executable_path,
        now_unix,
        0,
    )
}

#[cfg(test)]
pub(crate) fn verify_release_qualification_files_for_owner(
    artifact_path: &Path,
    signature_path: &Path,
    trusted_key_path: &Path,
    executable_path: &Path,
    now_unix: u64,
    expected_owner_uid: u32,
) -> Result<VerifiedReleaseQualification, ReleaseSignatureError> {
    verify_release_qualification_files_with_owner(
        artifact_path,
        signature_path,
        trusted_key_path,
        executable_path,
        now_unix,
        expected_owner_uid,
    )
}

fn verify_release_qualification_files_with_owner(
    artifact_path: &Path,
    signature_path: &Path,
    trusted_key_path: &Path,
    executable_path: &Path,
    now_unix: u64,
    expected_owner_uid: u32,
) -> Result<VerifiedReleaseQualification, ReleaseSignatureError> {
    let artifact = read_required_trusted_file(
        artifact_path,
        MAX_RELEASE_QUALIFICATION_BYTES,
        expected_owner_uid,
        ReleaseSignatureError::ArtifactMissing,
        ReleaseSignatureError::ArtifactTooLarge,
    )?;
    let signature = read_required_trusted_file(
        signature_path,
        MAX_DETACHED_SIGNATURE_BYTES,
        expected_owner_uid,
        ReleaseSignatureError::SignatureMissing,
        ReleaseSignatureError::SignatureTooLarge,
    )?;
    let trusted_key = read_required_trusted_file(
        trusted_key_path,
        MAX_TRUSTED_PUBLIC_KEY_BYTES,
        expected_owner_uid,
        ReleaseSignatureError::TrustedKeyMissing,
        ReleaseSignatureError::TrustedKeyTooLarge,
    )?;
    let verifier = GpgDetachedSignatureVerifier::new(executable_path.to_path_buf(), trusted_key)?;
    verify_release_qualification_bytes(&artifact, &signature, now_unix, &verifier)
}

fn read_required_trusted_file(
    path: &Path,
    max_bytes: usize,
    expected_owner_uid: u32,
    missing_error: ReleaseSignatureError,
    too_large_error: ReleaseSignatureError,
) -> Result<Vec<u8>, ReleaseSignatureError> {
    match read_trusted_file(path, max_bytes, expected_owner_uid) {
        Ok(bytes) if bytes.is_empty() => Err(missing_error),
        Ok(bytes) => Ok(bytes),
        Err(ReleaseSignatureError::FileMissing) => Err(missing_error),
        Err(ReleaseSignatureError::FileTooLarge) => Err(too_large_error),
        Err(error) => Err(error),
    }
}

fn read_trusted_file(
    path: &Path,
    max_bytes: usize,
    expected_owner_uid: u32,
) -> Result<Vec<u8>, ReleaseSignatureError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ENOENT) => ReleaseSignatureError::FileMissing,
            Some(libc::ELOOP) => ReleaseSignatureError::UnsafeFile,
            _ => ReleaseSignatureError::Io,
        })?;
    let metadata = file.metadata().map_err(|_| ReleaseSignatureError::Io)?;
    validate_trusted_file_metadata(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.mode(),
        expected_owner_uid,
    )?;
    if metadata.len() > max_bytes as u64 {
        return Err(ReleaseSignatureError::FileTooLarge);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReleaseSignatureError::Io)?;
    if bytes.len() > max_bytes {
        return Err(ReleaseSignatureError::FileTooLarge);
    }
    Ok(bytes)
}

fn validate_trusted_file_metadata(
    is_regular_file: bool,
    owner_uid: u32,
    mode: u32,
    expected_owner_uid: u32,
) -> Result<(), ReleaseSignatureError> {
    if !is_regular_file || owner_uid != expected_owner_uid || mode & 0o022 != 0 {
        return Err(ReleaseSignatureError::UnsafeFile);
    }
    Ok(())
}

struct TemporaryGpgHome {
    path: PathBuf,
}

impl TemporaryGpgHome {
    fn create(root: &Path) -> Result<Self, ReleaseSignatureError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("gpg-home-{}-{sequence}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ReleaseSignatureError::Io),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryGpgHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ReleaseSignatureError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ReleaseSignatureError::Io)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| ReleaseSignatureError::Io)?;
    file.write_all(bytes).map_err(|_| ReleaseSignatureError::Io)
}

fn truncate_private_file(path: &Path) -> Result<(), ReleaseSignatureError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ReleaseSignatureError::Io)?;
    let metadata = file.metadata().map_err(|_| ReleaseSignatureError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(ReleaseSignatureError::Io);
    }
    Ok(())
}

fn run_child_without_input(
    command: &mut Command,
    timeout: Duration,
) -> Result<(), ReleaseSignatureError> {
    let mut child = command
        .spawn()
        .map_err(|_| ReleaseSignatureError::ProcessFailed)?;
    let status = wait_for_child(&mut child, Instant::now() + timeout)?;
    if status.success() {
        Ok(())
    } else {
        Err(ReleaseSignatureError::ProcessFailed)
    }
}

fn run_child_with_input(
    command: &mut Command,
    payload: &[u8],
    timeout: Duration,
) -> Result<(), ReleaseSignatureError> {
    let mut child = command
        .spawn()
        .map_err(|_| ReleaseSignatureError::ProcessFailed)?;
    let Some(stdin) = child.stdin.take() else {
        terminate_and_reap(&mut child);
        return Err(ReleaseSignatureError::ProcessFailed);
    };
    if let Err(error) = set_nonblocking(stdin.as_raw_fd()) {
        terminate_and_reap(&mut child);
        return Err(error);
    }
    let deadline = Instant::now() + timeout;
    let (status, write_result) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || write_payload_until(stdin, payload, deadline));
        let status = wait_for_child(&mut child, deadline);
        if status.is_err() {
            terminate_and_reap(&mut child);
        }
        let write_result = writer
            .join()
            .unwrap_or(Err(ReleaseSignatureError::ProcessFailed));
        (status, write_result)
    });
    let status = status?;
    write_result?;
    if status.success() {
        Ok(())
    } else {
        Err(ReleaseSignatureError::ProcessFailed)
    }
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> Result<(), ReleaseSignatureError> {
    // SAFETY: `fd` is a live descriptor owned by the child-stdin handle. F_GETFL
    // and F_SETFL do not take ownership or dereference user pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(ReleaseSignatureError::Io);
    }
    // SAFETY: same live descriptor and integer flags established above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ReleaseSignatureError::Io);
    }
    Ok(())
}

fn write_payload_until(
    mut stdin: std::process::ChildStdin,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), ReleaseSignatureError> {
    let mut offset = 0;
    while offset < payload.len() {
        match stdin.write(&payload[offset..]) {
            Ok(0) => return Err(ReleaseSignatureError::ProcessFailed),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(ReleaseSignatureError::Timeout);
                }
                std::thread::sleep(PROCESS_POLL_INTERVAL);
            }
            Err(_) => return Err(ReleaseSignatureError::ProcessFailed),
        }
    }
    Ok(())
}

fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
) -> Result<ExitStatus, ReleaseSignatureError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(PROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                terminate_and_reap(child);
                return Err(ReleaseSignatureError::Timeout);
            }
            Err(_) => {
                terminate_and_reap(child);
                return Err(ReleaseSignatureError::ProcessFailed);
            }
        }
    }
}

fn terminate_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_status_file(path: &Path) -> Result<Vec<u8>, ReleaseSignatureError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ReleaseSignatureError::Io)?;
    let metadata = file.metadata().map_err(|_| ReleaseSignatureError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(ReleaseSignatureError::Io);
    }
    let mut status = Vec::with_capacity(MAX_GPG_STATUS_BYTES);
    std::io::Read::by_ref(&mut file)
        .take((MAX_GPG_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut status)
        .map_err(|_| ReleaseSignatureError::Io)?;
    if status.len() > MAX_GPG_STATUS_BYTES {
        return Err(ReleaseSignatureError::StatusTooLarge);
    }
    Ok(status)
}

fn parse_valid_signer(status: &[u8]) -> Result<VerifiedSigner, ReleaseSignatureError> {
    let text = std::str::from_utf8(status).map_err(|_| ReleaseSignatureError::InvalidStatus)?;
    let mut valid_fingerprint = None;
    let mut signature_failure = false;
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 2 || fields[0] != "[GNUPG:]" {
            return Err(ReleaseSignatureError::InvalidStatus);
        }
        match fields[1] {
            "VALIDSIG" => {
                let fingerprint = fields.get(2).ok_or(ReleaseSignatureError::InvalidStatus)?;
                if valid_fingerprint.replace(*fingerprint).is_some() {
                    return Err(ReleaseSignatureError::InvalidStatus);
                }
            }
            "BADSIG" | "ERRSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" | "NO_PUBKEY" => {
                signature_failure = true;
            }
            _ => {}
        }
    }
    if signature_failure {
        return Err(ReleaseSignatureError::InvalidSignature);
    }
    let fingerprint = valid_fingerprint.ok_or(ReleaseSignatureError::InvalidSignature)?;
    if fingerprint != ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT {
        return Err(ReleaseSignatureError::SignerUntrusted);
    }
    Ok(VerifiedSigner {
        fingerprint: fingerprint.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_qualification::{
        fixture_artifact_value, fixture_canonical_artifact, ReleaseQualificationArtifact,
        ReleaseQualificationError,
    };
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    const FIXED_NOW: u64 = 1_788_192_050;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "irlume-release-signature-{tag}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct FakeGpgSpec<'a> {
        verify_status: &'a str,
        import_exit: i32,
        verify_exit: i32,
        read_stdin: bool,
        sleep_verify: bool,
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    fn write_fake_gpg(root: &TestDir, name: &str, spec: FakeGpgSpec<'_>) -> (PathBuf, PathBuf) {
        let executable = root.path().join(name);
        let record = root.path().join("fake-gpg-record");
        let script = format!(
            "#!/bin/sh\n\
             record={}\n\
             status=\n\
             homedir=\n\
             mode=\n\
             want=\n\
             for arg in \"$@\"; do\n\
               /usr/bin/printf 'ARG=%s\\n' \"$arg\" >> \"$record\"\n\
               if [ \"$want\" = status ]; then status=$arg; want=; continue; fi\n\
               if [ \"$want\" = homedir ]; then homedir=$arg; want=; continue; fi\n\
               case \"$arg\" in\n\
                 --status-file) want=status ;;\n\
                 --homedir) want=homedir ;;\n\
                 --import) mode=import ;;\n\
                 --verify) mode=verify ;;\n\
               esac\n\
             done\n\
             if [ \"$mode\" = import ]; then\n\
               /usr/bin/printf '%s' '[GNUPG:] IMPORT_OK 1 synthetic\\n' > \"$status\"\n\
               exit {}\n\
             fi\n\
             for entry in \"$homedir\"/*; do\n\
               if [ -f \"$entry\" ]; then /usr/bin/printf 'FILE=%s\\n' \"${{entry##*/}}\" >> \"$record\"; fi\n\
             done\n\
             {}\n\
             {}\n\
             /usr/bin/printf '%s' {} > \"$status\"\n\
             exit {}\n",
            shell_quote(record.to_str().unwrap()),
            spec.import_exit,
            if spec.sleep_verify {
                "while :; do :; done"
            } else {
                ":"
            },
            if spec.read_stdin { "/bin/cat >/dev/null" } else { ":" },
            shell_quote(spec.verify_status),
            spec.verify_exit,
        );
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&executable)
            .unwrap();
        file.write_all(script.as_bytes()).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o700))
            .unwrap();
        (executable, record)
    }

    fn write_fixture_file(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .unwrap();
    }

    fn write_package_fixture(root: &TestDir, name: &str) -> ReleaseQualificationPaths {
        let paths = ReleaseQualificationPaths::under(root.path(), name).unwrap();
        write_fixture_file(paths.artifact(), &fixture_canonical_artifact(), 0o644);
        write_fixture_file(paths.signature(), b"synthetic-signature", 0o644);
        write_fixture_file(paths.trusted_key(), b"synthetic-public-key", 0o644);
        paths
    }

    fn assert_no_gpg_homes(root: &TestDir) {
        assert!(!std::fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("gpg-home-")
        }));
    }

    fn canonical_payload_from_value(value: serde_json::Value) -> Vec<u8> {
        let artifact: ReleaseQualificationArtifact = serde_json::from_value(value).unwrap();
        artifact.to_canonical_json().unwrap().into_bytes()
    }

    #[test]
    fn valid_signature_mints_opaque_release_evidence() {
        let payload = fixture_canonical_artifact();
        let verified = verify_release_qualification_bytes(
            &payload,
            b"synthetic-signature",
            FIXED_NOW,
            &FakeVerifier::valid(ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT),
        )
        .unwrap();
        assert_eq!(
            verified.artifact_sha256(),
            irlume_common::sha256_hex(&payload)
        );
        assert_eq!(
            verified.signer_fingerprint(),
            ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT
        );
        assert_eq!(
            verified.artifact().candidate_profile().id(),
            "candidate-15-15"
        );
    }

    #[test]
    fn wrong_short_or_modified_signature_authorizes_nothing() {
        for verifier in [
            FakeVerifier::valid("BD7F30C6"),
            FakeVerifier::valid("035053398E3C80FE20891B82C10B8492BD7F30C6"),
            FakeVerifier::invalid_signature(),
        ] {
            assert!(verify_release_qualification_bytes(
                &fixture_canonical_artifact(),
                b"synthetic-signature",
                FIXED_NOW,
                &verifier,
            )
            .is_err());
        }
    }

    #[test]
    fn missing_or_oversized_inputs_authorize_nothing() {
        let valid = FakeVerifier::valid(ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT);
        assert_eq!(
            verify_release_qualification_bytes(
                &fixture_canonical_artifact(),
                b"",
                FIXED_NOW,
                &valid,
            ),
            Err(ReleaseSignatureError::SignatureMissing),
        );
        assert_eq!(
            verify_release_qualification_bytes(
                &vec![b' '; 256 * 1024 + 1],
                b"synthetic-signature",
                FIXED_NOW,
                &valid,
            ),
            Err(ReleaseSignatureError::ArtifactTooLarge),
        );
        assert_eq!(
            verify_release_qualification_bytes(
                &fixture_canonical_artifact(),
                &vec![b'x'; 64 * 1024 + 1],
                FIXED_NOW,
                &valid,
            ),
            Err(ReleaseSignatureError::SignatureTooLarge),
        );
        assert_eq!(
            GpgDetachedSignatureVerifier::new(PathBuf::from("/synthetic/gpg"), Vec::new()).err(),
            Some(ReleaseSignatureError::TrustedKeyMissing),
        );
        assert_eq!(
            GpgDetachedSignatureVerifier::new(
                PathBuf::from("/synthetic/gpg"),
                vec![b'x'; MAX_TRUSTED_PUBLIC_KEY_BYTES + 1],
            )
            .err(),
            Some(ReleaseSignatureError::TrustedKeyTooLarge),
        );
    }

    #[test]
    fn noncanonical_or_metadata_mismatched_payload_authorizes_nothing() {
        let valid = FakeVerifier::valid(ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT);
        let pretty =
            serde_json::to_vec_pretty(&fixture_artifact_value("baseline-30-15", "candidate-15-15"))
                .unwrap();
        assert_eq!(
            verify_release_qualification_bytes(&pretty, b"synthetic-signature", FIXED_NOW, &valid,),
            Err(ReleaseSignatureError::Artifact(
                ReleaseQualificationError::Json
            )),
        );

        let mut mismatched = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        mismatched["signature"]["signer_fingerprint"] =
            serde_json::json!("A35053398E3C80FE20891B82C10B8492BD7F30C6");
        assert_eq!(
            verify_release_qualification_bytes(
                &canonical_payload_from_value(mismatched),
                b"synthetic-signature",
                FIXED_NOW,
                &valid,
            ),
            Err(ReleaseSignatureError::MetadataSignerMismatch),
        );

        let reordered =
            serde_json::to_vec(&fixture_artifact_value("baseline-30-15", "candidate-15-15"))
                .unwrap();
        assert_ne!(reordered, fixture_canonical_artifact());
        assert_eq!(
            verify_release_qualification_bytes(
                &reordered,
                b"synthetic-signature",
                FIXED_NOW,
                &valid,
            ),
            Err(ReleaseSignatureError::Artifact(
                ReleaseQualificationError::Json
            )),
        );
    }

    #[test]
    fn sibling_fixture_mints_only_through_byte_verification() {
        let verified = verified_release_fixture(
            "baseline-fixture",
            "candidate-fixture",
            24,
            12,
            crate::profile::CaptureSchedule::Sequential,
            0xa5,
            FIXED_NOW,
        );
        let candidate = verified.artifact().candidate_profile();
        assert_eq!(candidate.id(), "candidate-fixture");
        assert_eq!(
            verified.signer_fingerprint(),
            ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT
        );
    }

    #[test]
    fn not_yet_valid_or_expired_payload_authorizes_nothing() {
        let valid = FakeVerifier::valid(ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT);
        assert_eq!(
            verify_release_qualification_bytes(
                &fixture_canonical_artifact(),
                b"synthetic-signature",
                1_788_191_999,
                &valid,
            ),
            Err(ReleaseSignatureError::Artifact(
                ReleaseQualificationError::ArtifactNotYetValid
            )),
        );
        assert_eq!(
            verify_release_qualification_bytes(
                &fixture_canonical_artifact(),
                b"synthetic-signature",
                1_788_278_400,
                &valid,
            ),
            Err(ReleaseSignatureError::Artifact(
                ReleaseQualificationError::ArtifactExpired
            )),
        );
    }

    #[test]
    fn isolated_gpg_uses_direct_arguments_stdin_and_cleans_its_home() {
        let root = TestDir::new("success");
        let status = format!(
            "[GNUPG:] VALIDSIG {ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT} 2026-09-01 0 4 0 22 8 00 {ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT}\n"
        );
        let (executable, record) = write_fake_gpg(
            &root,
            "fake gpg with spaces",
            FakeGpgSpec {
                verify_status: &status,
                import_exit: 0,
                verify_exit: 0,
                read_stdin: true,
                sleep_verify: false,
            },
        );
        let verifier = GpgDetachedSignatureVerifier::with_timeout_and_temp_root_for_test(
            executable,
            b"synthetic-public-key".to_vec(),
            Duration::from_secs(1),
            root.path().to_owned(),
        )
        .unwrap();
        let signer = verifier
            .verify(&fixture_canonical_artifact(), b"synthetic-signature")
            .unwrap();
        assert_eq!(signer.fingerprint, ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT);

        let recorded = std::fs::read_to_string(record).unwrap();
        for required in [
            "ARG=--batch",
            "ARG=--no-options",
            "ARG=--no-tty",
            "ARG=--no-autostart",
            "ARG=--disable-dirmngr",
            "ARG=--homedir",
            "ARG=--status-file",
            "ARG=--import",
            "ARG=--verify",
            "ARG=-",
            "FILE=trusted-key.asc",
            "FILE=detached-signature.asc",
            "FILE=status",
        ] {
            assert!(recorded.lines().any(|line| line == required), "{required}");
        }
        let mut temporary_files: Vec<_> = recorded
            .lines()
            .filter_map(|line| line.strip_prefix("FILE="))
            .collect();
        temporary_files.sort_unstable();
        assert_eq!(
            temporary_files,
            ["detached-signature.asc", "status", "trusted-key.asc"]
        );
        assert!(!recorded.contains(&String::from_utf8(fixture_canonical_artifact()).unwrap()));
        assert_no_gpg_homes(&root);
    }

    #[test]
    fn gpg_status_requires_one_exact_validsig_and_successful_exit() {
        let cases = [
            (
                "goodsig-only",
                "[GNUPG:] GOODSIG BD7F30C6 synthetic\n".to_owned(),
                0,
                ReleaseSignatureError::InvalidSignature,
            ),
            (
                "short",
                "[GNUPG:] VALIDSIG BD7F30C6 rest\n".to_owned(),
                0,
                ReleaseSignatureError::SignerUntrusted,
            ),
            (
                "wrong",
                "[GNUPG:] VALIDSIG A35053398E3C80FE20891B82C10B8492BD7F30C6 rest\n".to_owned(),
                0,
                ReleaseSignatureError::SignerUntrusted,
            ),
            (
                "duplicate",
                format!(
                    "[GNUPG:] VALIDSIG {0} rest\n[GNUPG:] VALIDSIG {0} rest\n",
                    ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT
                ),
                0,
                ReleaseSignatureError::InvalidStatus,
            ),
            (
                "conflicting",
                format!(
                    "[GNUPG:] VALIDSIG {} rest\n[GNUPG:] BADSIG BD7F30C6 bad\n",
                    ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT
                ),
                0,
                ReleaseSignatureError::InvalidSignature,
            ),
            (
                "nonzero",
                format!(
                    "[GNUPG:] VALIDSIG {} rest\n",
                    ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT
                ),
                2,
                ReleaseSignatureError::ProcessFailed,
            ),
        ];
        for (tag, status, verify_exit, expected) in cases {
            let root = TestDir::new(tag);
            let (executable, _) = write_fake_gpg(
                &root,
                "fake-gpg",
                FakeGpgSpec {
                    verify_status: &status,
                    import_exit: 0,
                    verify_exit,
                    read_stdin: true,
                    sleep_verify: false,
                },
            );
            let verifier = GpgDetachedSignatureVerifier::with_timeout_and_temp_root_for_test(
                executable,
                b"synthetic-public-key".to_vec(),
                Duration::from_secs(1),
                root.path().to_owned(),
            )
            .unwrap();
            assert_eq!(
                verifier.verify(&fixture_canonical_artifact(), b"synthetic-signature"),
                Err(expected),
                "{tag}"
            );
            assert_no_gpg_homes(&root);
        }
    }

    #[test]
    fn gpg_rejects_import_failure_oversized_status_and_timeout() {
        let valid_status = format!(
            "[GNUPG:] VALIDSIG {} rest\n",
            ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT
        );
        let oversized_status = "x".repeat(64 * 1024 + 1);
        for (tag, spec, expected) in [
            (
                "import-failure",
                FakeGpgSpec {
                    verify_status: &valid_status,
                    import_exit: 2,
                    verify_exit: 0,
                    read_stdin: true,
                    sleep_verify: false,
                },
                ReleaseSignatureError::ProcessFailed,
            ),
            (
                "oversized-status",
                FakeGpgSpec {
                    verify_status: &oversized_status,
                    import_exit: 0,
                    verify_exit: 0,
                    read_stdin: true,
                    sleep_verify: false,
                },
                ReleaseSignatureError::StatusTooLarge,
            ),
            (
                "timeout",
                FakeGpgSpec {
                    verify_status: &valid_status,
                    import_exit: 0,
                    verify_exit: 0,
                    read_stdin: false,
                    sleep_verify: true,
                },
                ReleaseSignatureError::Timeout,
            ),
        ] {
            let root = TestDir::new(tag);
            let (executable, _) = write_fake_gpg(&root, "fake-gpg", spec);
            let verifier = GpgDetachedSignatureVerifier::with_timeout_and_temp_root_for_test(
                executable,
                b"synthetic-public-key".to_vec(),
                Duration::from_millis(75),
                root.path().to_owned(),
            )
            .unwrap();
            let payload = if tag == "timeout" {
                vec![b'x'; MAX_RELEASE_QUALIFICATION_BYTES]
            } else {
                fixture_canonical_artifact()
            };
            assert_eq!(
                verifier.verify(&payload, b"synthetic-signature"),
                Err(expected),
                "{tag}"
            );
            assert_no_gpg_homes(&root);
        }
    }

    #[test]
    fn release_paths_are_deterministic_and_labels_are_closed() {
        let root = Path::new("/opt/irlume-package");
        let paths = ReleaseQualificationPaths::under(root, "candidate_15-15").unwrap();
        assert_eq!(
            paths.artifact(),
            Path::new(
                "/opt/irlume-package/share/irlume/profile-qualifications/candidate_15-15.json"
            )
        );
        assert_eq!(
            paths.signature(),
            Path::new(
                "/opt/irlume-package/share/irlume/profile-qualifications/candidate_15-15.json.asc"
            )
        );
        assert_eq!(
            paths.trusted_key(),
            Path::new("/opt/irlume-package/share/irlume/release-qualification-key.asc")
        );
        assert_eq!(
            ReleaseQualificationPaths::system("candidate_15-15")
                .unwrap()
                .artifact(),
            Path::new("/usr/share/irlume/profile-qualifications/candidate_15-15.json")
        );
        for invalid in [
            "",
            ".",
            "Candidate",
            "candidate.json",
            "../candidate",
            "candidate/name",
            &"x".repeat(129),
        ] {
            assert_eq!(
                ReleaseQualificationPaths::under(root, invalid),
                Err(ReleaseSignatureError::InvalidArtifactName),
                "{invalid}"
            );
        }
    }

    #[test]
    fn synthetic_package_root_verifies_through_current_owner_seam() {
        let root = TestDir::new("package-success");
        let paths = write_package_fixture(&root, "candidate_15-15");
        let status = format!(
            "[GNUPG:] VALIDSIG {} rest\n",
            ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT
        );
        let (executable, _) = write_fake_gpg(
            &root,
            "fake-gpg",
            FakeGpgSpec {
                verify_status: &status,
                import_exit: 0,
                verify_exit: 0,
                read_stdin: true,
                sleep_verify: false,
            },
        );
        // SAFETY: geteuid has no preconditions or side effects.
        let owner_uid = unsafe { libc::geteuid() };
        let verified = verify_release_qualification_files_for_owner(
            paths.artifact(),
            paths.signature(),
            paths.trusted_key(),
            &executable,
            FIXED_NOW,
            owner_uid,
        )
        .unwrap();
        assert_eq!(
            verified.artifact_sha256(),
            irlume_common::sha256_hex(&fixture_canonical_artifact())
        );
    }

    #[test]
    fn trusted_file_loading_rejects_symlinks_unsafe_modes_and_bounds() {
        // SAFETY: geteuid has no preconditions or side effects.
        let owner_uid = unsafe { libc::geteuid() };

        let symlink_root = TestDir::new("package-symlink");
        let symlink_paths = write_package_fixture(&symlink_root, "candidate");
        std::fs::remove_file(symlink_paths.signature()).unwrap();
        std::os::unix::fs::symlink(symlink_paths.artifact(), symlink_paths.signature()).unwrap();
        assert_eq!(
            read_trusted_file(
                symlink_paths.signature(),
                MAX_DETACHED_SIGNATURE_BYTES,
                owner_uid,
            ),
            Err(ReleaseSignatureError::UnsafeFile),
        );

        for (tag, selected, source, max_bytes) in [
            (
                "artifact-symlink",
                "artifact",
                "signature",
                MAX_RELEASE_QUALIFICATION_BYTES,
            ),
            (
                "key-symlink",
                "key",
                "artifact",
                MAX_TRUSTED_PUBLIC_KEY_BYTES,
            ),
        ] {
            let root = TestDir::new(tag);
            let paths = write_package_fixture(&root, "candidate");
            let selected_path = match selected {
                "artifact" => paths.artifact(),
                "key" => paths.trusted_key(),
                _ => unreachable!(),
            };
            let source_path = match source {
                "artifact" => paths.artifact(),
                "signature" => paths.signature(),
                _ => unreachable!(),
            };
            std::fs::remove_file(selected_path).unwrap();
            std::os::unix::fs::symlink(source_path, selected_path).unwrap();
            assert_eq!(
                read_trusted_file(selected_path, max_bytes, owner_uid),
                Err(ReleaseSignatureError::UnsafeFile),
                "{tag}"
            );
        }

        let nonregular_root = TestDir::new("package-nonregular");
        let nonregular_paths = write_package_fixture(&nonregular_root, "candidate");
        std::fs::remove_file(nonregular_paths.artifact()).unwrap();
        std::fs::create_dir(nonregular_paths.artifact()).unwrap();
        assert_eq!(
            read_trusted_file(
                nonregular_paths.artifact(),
                MAX_RELEASE_QUALIFICATION_BYTES,
                owner_uid,
            ),
            Err(ReleaseSignatureError::UnsafeFile),
        );

        let mode_root = TestDir::new("package-mode");
        let mode_paths = write_package_fixture(&mode_root, "candidate");
        std::fs::set_permissions(
            mode_paths.artifact(),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert_eq!(
            read_trusted_file(
                mode_paths.artifact(),
                MAX_RELEASE_QUALIFICATION_BYTES,
                owner_uid,
            ),
            Err(ReleaseSignatureError::UnsafeFile),
        );

        let bound_root = TestDir::new("package-bound");
        let bound_paths = ReleaseQualificationPaths::under(bound_root.path(), "candidate").unwrap();
        write_fixture_file(
            bound_paths.artifact(),
            &vec![b'x'; MAX_RELEASE_QUALIFICATION_BYTES + 1],
            0o644,
        );
        assert_eq!(
            read_trusted_file(
                bound_paths.artifact(),
                MAX_RELEASE_QUALIFICATION_BYTES,
                owner_uid,
            ),
            Err(ReleaseSignatureError::FileTooLarge),
        );

        assert_eq!(
            read_trusted_file(
                mode_paths.signature(),
                MAX_DETACHED_SIGNATURE_BYTES,
                owner_uid.wrapping_add(1),
            ),
            Err(ReleaseSignatureError::UnsafeFile),
        );
    }

    #[test]
    fn production_metadata_policy_requires_root_and_no_group_or_world_write() {
        assert_eq!(validate_trusted_file_metadata(true, 0, 0o644, 0), Ok(()));
        assert_eq!(
            validate_trusted_file_metadata(true, 1000, 0o644, 0),
            Err(ReleaseSignatureError::UnsafeFile),
        );
        assert_eq!(
            validate_trusted_file_metadata(true, 0, 0o664, 0),
            Err(ReleaseSignatureError::UnsafeFile),
        );
        assert_eq!(
            validate_trusted_file_metadata(true, 0, 0o646, 0),
            Err(ReleaseSignatureError::UnsafeFile),
        );
        assert_eq!(
            validate_trusted_file_metadata(false, 0, 0o644, 0),
            Err(ReleaseSignatureError::UnsafeFile),
        );
    }
}
