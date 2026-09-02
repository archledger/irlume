// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::{
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    CampaignError, CanonicalDocument, Sha256Digest, SignerFingerprint, MAX_CAMPAIGN_DOCUMENT_BYTES,
};

pub const MAX_DETACHED_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_TRUSTED_PUBLIC_KEY_BYTES: usize = 256 * 1024;
const MAX_GPG_OUTPUT_BYTES: u64 = 64 * 1024;
const DEFAULT_GPG_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    PolicyAuthor,
    ProtocolAuthor,
    Operator,
    Evaluator,
    Reviewer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    OpenPgp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureMetadata {
    algorithm: SignatureAlgorithm,
    role: SignerRole,
    signer_fingerprint: SignerFingerprint,
}

impl SignatureMetadata {
    #[must_use]
    pub const fn new(role: SignerRole, signer_fingerprint: SignerFingerprint) -> Self {
        Self {
            algorithm: SignatureAlgorithm::OpenPgp,
            role,
            signer_fingerprint,
        }
    }

    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn role(&self) -> SignerRole {
        self.role
    }

    #[must_use]
    pub const fn signer_fingerprint(&self) -> &SignerFingerprint {
        &self.signer_fingerprint
    }
}

pub trait DetachedSignatureVerifier {
    /// Verifies one detached signature over exact canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a fixed campaign error when cryptographic verification fails or
    /// the signer cannot be represented as a full fingerprint.
    fn verify(
        &self,
        canonical_payload: &[u8],
        detached_signature: &[u8],
    ) -> Result<SignerFingerprint, CampaignError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified<T> {
    document: T,
    digest: Sha256Digest,
    signer: SignerFingerprint,
}

impl<T> Verified<T> {
    #[must_use]
    pub const fn document(&self) -> &T {
        &self.document
    }

    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    #[must_use]
    pub const fn signer(&self) -> &SignerFingerprint {
        &self.signer
    }
}

/// Verifies a canonical role-bound document and returns opaque authority.
///
/// # Errors
///
/// Returns a fixed campaign error for absent/oversized/invalid signatures,
/// signer or role mismatch, or invalid canonical document bytes.
pub fn verify_document<T: CanonicalDocument>(
    canonical_payload: &[u8],
    detached_signature: &[u8],
    expected_role: SignerRole,
    expected_signer: &SignerFingerprint,
    verifier: &impl DetachedSignatureVerifier,
) -> Result<Verified<T>, CampaignError> {
    if canonical_payload.len() > MAX_CAMPAIGN_DOCUMENT_BYTES {
        return Err(CampaignError::DocumentTooLarge);
    }
    if detached_signature.is_empty() {
        return Err(CampaignError::SignatureMissing);
    }
    if detached_signature.len() > MAX_DETACHED_SIGNATURE_BYTES {
        return Err(CampaignError::SignatureTooLarge);
    }
    let signer = verifier.verify(canonical_payload, detached_signature)?;
    if &signer != expected_signer {
        return Err(CampaignError::SignatureSignerMismatch);
    }
    let document = T::from_canonical_json(canonical_payload)?;
    let metadata = document.signature_metadata();
    if metadata.algorithm() != SignatureAlgorithm::OpenPgp {
        return Err(CampaignError::SignatureInvalid);
    }
    if metadata.role() != expected_role {
        return Err(CampaignError::SignatureRoleMismatch);
    }
    if metadata.signer_fingerprint() != &signer {
        return Err(CampaignError::SignatureSignerMismatch);
    }
    Ok(Verified {
        document,
        digest: Sha256Digest::of(canonical_payload),
        signer,
    })
}

pub struct GpgDetachedSignatureVerifier {
    executable_path: PathBuf,
    trusted_public_key: Vec<u8>,
    timeout: Duration,
    temp_root: PathBuf,
}

impl GpgDetachedSignatureVerifier {
    /// Creates an isolated verifier using an absolute GPG executable path.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerifierInvalid` for a relative executable path or an
    /// absent or oversized trusted public key.
    pub fn new(
        executable_path: PathBuf,
        trusted_public_key: Vec<u8>,
    ) -> Result<Self, CampaignError> {
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
    ) -> Result<Self, CampaignError> {
        if !executable_path.is_absolute()
            || !temp_root.is_absolute()
            || timeout.is_zero()
            || trusted_public_key.is_empty()
            || trusted_public_key.len() > MAX_TRUSTED_PUBLIC_KEY_BYTES
        {
            return Err(CampaignError::SignatureVerifierInvalid);
        }
        Ok(Self {
            executable_path,
            trusted_public_key,
            timeout,
            temp_root,
        })
    }

    fn command(&self, home: &Path, status: &Path, stderr: &Path) -> Result<Command, CampaignError> {
        let status = private_output_file(status)?;
        let stderr = private_output_file(stderr)?;
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
            .args(["--status-fd", "1"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(status))
            .stderr(Stdio::from(stderr));
        Ok(command)
    }
}

impl DetachedSignatureVerifier for GpgDetachedSignatureVerifier {
    fn verify(
        &self,
        canonical_payload: &[u8],
        detached_signature: &[u8],
    ) -> Result<SignerFingerprint, CampaignError> {
        if canonical_payload.len() > MAX_CAMPAIGN_DOCUMENT_BYTES {
            return Err(CampaignError::DocumentTooLarge);
        }
        if detached_signature.is_empty() {
            return Err(CampaignError::SignatureMissing);
        }
        if detached_signature.len() > MAX_DETACHED_SIGNATURE_BYTES {
            return Err(CampaignError::SignatureTooLarge);
        }

        let home = TemporaryGpgHome::create(&self.temp_root)?;
        let key_path = home.path().join("trusted-key.asc");
        let payload_path = home.path().join("canonical-document.json");
        let signature_path = home.path().join("detached-signature.asc");
        let status_path = home.path().join("status");
        let stderr_path = home.path().join("stderr");
        write_private_file(&key_path, &self.trusted_public_key)?;
        write_private_file(&payload_path, canonical_payload)?;
        write_private_file(&signature_path, detached_signature)?;

        let mut import = self.command(home.path(), &status_path, &stderr_path)?;
        import.arg("--import").arg(&key_path);
        run_child(&mut import, self.timeout, [&status_path, &stderr_path])?;

        let mut verify = self.command(home.path(), &status_path, &stderr_path)?;
        verify
            .arg("--verify")
            .arg(&signature_path)
            .arg(&payload_path);
        run_child(&mut verify, self.timeout, [&status_path, &stderr_path])?;
        let status = read_bounded_file(&status_path)?;
        parse_validsig_primary(&status)
    }
}

struct TemporaryGpgHome {
    path: PathBuf,
}

impl TemporaryGpgHome {
    fn create(root: &Path) -> Result<Self, CampaignError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("gpg-home-{}-{sequence}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(CampaignError::SignatureVerifierFailed),
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

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), CampaignError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| CampaignError::SignatureVerifierFailed)?;
    file.write_all(bytes)
        .map_err(|_| CampaignError::SignatureVerifierFailed)
}

fn private_output_file(path: &Path) -> Result<std::fs::File, CampaignError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| CampaignError::SignatureVerifierFailed)
}

fn run_child(
    command: &mut Command,
    timeout: Duration,
    output_paths: [&Path; 2],
) -> Result<(), CampaignError> {
    let mut child = command
        .spawn()
        .map_err(|_| CampaignError::SignatureVerifierFailed)?;
    let status = wait_for_child(&mut child, Instant::now() + timeout, output_paths)?;
    if status.success() {
        Ok(())
    } else {
        Err(CampaignError::SignatureVerifierFailed)
    }
}

fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
    output_paths: [&Path; 2],
) -> Result<ExitStatus, CampaignError> {
    loop {
        if output_paths.iter().any(|path| {
            std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > MAX_GPG_OUTPUT_BYTES)
        }) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CampaignError::SignatureInvalid);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                for path in output_paths {
                    ensure_bounded_file(path)?;
                }
                return Ok(status);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(PROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CampaignError::SignatureVerifierTimeout);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CampaignError::SignatureVerifierFailed);
            }
        }
    }
}

fn ensure_bounded_file(path: &Path) -> Result<(), CampaignError> {
    let metadata = std::fs::metadata(path).map_err(|_| CampaignError::SignatureVerifierFailed)?;
    if !metadata.is_file() || metadata.len() > MAX_GPG_OUTPUT_BYTES {
        return Err(CampaignError::SignatureInvalid);
    }
    Ok(())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, CampaignError> {
    ensure_bounded_file(path)?;
    std::fs::read(path).map_err(|_| CampaignError::SignatureVerifierFailed)
}

fn parse_validsig_primary(status: &[u8]) -> Result<SignerFingerprint, CampaignError> {
    let status = std::str::from_utf8(status).map_err(|_| CampaignError::SignatureInvalid)?;
    let mut valid = None;
    for line in status.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 2 || fields[0] != "[GNUPG:]" {
            return Err(CampaignError::SignatureInvalid);
        }
        if matches!(
            fields[1],
            "BADSIG" | "ERRSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" | "NO_PUBKEY"
        ) {
            return Err(CampaignError::SignatureInvalid);
        }
        if fields[1] != "VALIDSIG" {
            continue;
        }
        if valid.is_some() || fields.len() != 12 {
            return Err(CampaignError::SignatureInvalid);
        }
        SignerFingerprint::new(fields[2]).map_err(|_| CampaignError::SignatureInvalid)?;
        valid =
            Some(SignerFingerprint::new(fields[11]).map_err(|_| CampaignError::SignatureInvalid)?);
    }
    valid.ok_or(CampaignError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write as _,
        os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::canonical::private;

    const OPERATOR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const REVIEWER: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "irlume-qualification-signature-{tag}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    fn write_fake_gpg(
        root: &TestDir,
        status: &str,
        import_exit: i32,
        verify_exit: i32,
        sleep_verify: bool,
    ) -> (PathBuf, PathBuf) {
        let executable = root.path().join("fake gpg with spaces");
        let record = root.path().join("record");
        let script = format!(
            "#!/bin/sh\n\
             record={}\n\
             mode=\n\
             for arg in \"$@\"; do\n\
               /usr/bin/printf 'ARG=%s\\n' \"$arg\" >> \"$record\"\n\
               case \"$arg\" in --import) mode=import ;; --verify) mode=verify ;; esac\n\
             done\n\
             if [ \"$mode\" = import ]; then exit {}; fi\n\
             {}\n\
             /usr/bin/printf '%s' {}\n\
             exit {}\n",
            shell_quote(record.to_str().unwrap()),
            import_exit,
            if sleep_verify {
                "while :; do :; done"
            } else {
                ":"
            },
            shell_quote(status),
            verify_exit,
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

    fn assert_no_gpg_homes(root: &TestDir) {
        assert!(!std::fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("gpg-home-")
        }));
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureDocument {
        schema_version: u32,
        signature: SignatureMetadata,
    }

    impl private::Sealed for FixtureDocument {}

    impl CanonicalDocument for FixtureDocument {
        fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
            if bytes.len() > MAX_CAMPAIGN_DOCUMENT_BYTES {
                return Err(CampaignError::DocumentTooLarge);
            }
            let document: Self =
                serde_json::from_slice(bytes).map_err(|_| CampaignError::CanonicalInvalid)?;
            if serde_json::to_vec(&document).map_err(|_| CampaignError::CanonicalInvalid)? != bytes
            {
                return Err(CampaignError::CanonicalInvalid);
            }
            Ok(document)
        }

        fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
            serde_json::to_vec(self).map_err(|_| CampaignError::CanonicalInvalid)
        }

        fn signature_metadata(&self) -> &SignatureMetadata {
            &self.signature
        }
    }

    struct FakeVerifier(Result<SignerFingerprint, CampaignError>);

    impl DetachedSignatureVerifier for FakeVerifier {
        fn verify(
            &self,
            _canonical_payload: &[u8],
            _detached_signature: &[u8],
        ) -> Result<SignerFingerprint, CampaignError> {
            self.0.clone()
        }
    }

    fn fixture(role: SignerRole, fingerprint: &str) -> Vec<u8> {
        serde_json::to_vec(&FixtureDocument {
            schema_version: 1,
            signature: SignatureMetadata::new(
                role,
                SignerFingerprint::new(fingerprint).expect("valid fingerprint"),
            ),
        })
        .expect("canonical fixture")
    }

    #[test]
    fn signature_role_and_full_fingerprint_must_match() {
        let expected = SignerFingerprint::new(OPERATOR).unwrap();
        let valid = FakeVerifier(Ok(expected.clone()));
        let verified = verify_document::<FixtureDocument>(
            &fixture(SignerRole::Operator, OPERATOR),
            b"synthetic-signature",
            SignerRole::Operator,
            &expected,
            &valid,
        )
        .unwrap();
        assert_eq!(verified.signer(), &expected);

        assert_eq!(
            verify_document::<FixtureDocument>(
                &fixture(SignerRole::Reviewer, OPERATOR),
                b"synthetic-signature",
                SignerRole::Operator,
                &expected,
                &valid,
            ),
            Err(CampaignError::SignatureRoleMismatch),
        );
        assert_eq!(
            verify_document::<FixtureDocument>(
                &fixture(SignerRole::Operator, OPERATOR),
                b"synthetic-signature",
                SignerRole::Operator,
                &expected,
                &FakeVerifier(Ok(SignerFingerprint::new(REVIEWER).unwrap())),
            ),
            Err(CampaignError::SignatureSignerMismatch),
        );
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        assert_eq!(
            verify_document::<FixtureDocument>(
                &fixture(SignerRole::Operator, OPERATOR),
                b"synthetic-signature",
                SignerRole::Operator,
                &reviewer,
                &FakeVerifier(Ok(reviewer.clone())),
            ),
            Err(CampaignError::SignatureSignerMismatch),
        );
        assert_eq!(
            verify_document::<FixtureDocument>(
                &fixture(SignerRole::Operator, OPERATOR),
                b"synthetic-signature",
                SignerRole::Operator,
                &expected,
                &FakeVerifier(Err(CampaignError::SignatureInvalid)),
            ),
            Err(CampaignError::SignatureInvalid),
        );
    }

    #[test]
    fn signatures_are_present_and_bounded() {
        let expected = SignerFingerprint::new(OPERATOR).unwrap();
        let verifier = FakeVerifier(Ok(expected.clone()));
        let payload = fixture(SignerRole::Operator, OPERATOR);
        assert_eq!(
            verify_document::<FixtureDocument>(
                &payload,
                b"",
                SignerRole::Operator,
                &expected,
                &verifier,
            ),
            Err(CampaignError::SignatureMissing),
        );
        assert_eq!(
            verify_document::<FixtureDocument>(
                &payload,
                &vec![0; MAX_DETACHED_SIGNATURE_BYTES + 1],
                SignerRole::Operator,
                &expected,
                &verifier,
            ),
            Err(CampaignError::SignatureTooLarge),
        );
    }

    #[test]
    fn validsig_requires_one_primary_fingerprint() {
        let signing = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let status =
            format!("[GNUPG:] VALIDSIG {signing} 2026-09-02 1788321600 0 4 0 22 8 00 {OPERATOR}\n");
        assert_eq!(
            parse_validsig_primary(status.as_bytes()).unwrap(),
            SignerFingerprint::new(OPERATOR).unwrap(),
        );
        assert_eq!(
            parse_validsig_primary(format!("{status}{status}").as_bytes()),
            Err(CampaignError::SignatureInvalid),
        );
        assert_eq!(
            parse_validsig_primary(b"[GNUPG:] GOODSIG short text\n"),
            Err(CampaignError::SignatureInvalid),
        );
        assert_eq!(
            parse_validsig_primary(
                format!("[GNUPG:] VALIDSIG SHORT 2026-09-02 1788321600 0 4 0 22 8 00 {OPERATOR}\n")
                    .as_bytes(),
            ),
            Err(CampaignError::SignatureInvalid),
        );
        assert_eq!(
            parse_validsig_primary(
                format!("[GNUPG:] VALIDSIG {signing} 2026-09-02 1788321600 0 4 0 22 8 00 SHORT\n")
                    .as_bytes(),
            ),
            Err(CampaignError::SignatureInvalid),
        );
    }

    #[test]
    fn isolated_gpg_uses_direct_arguments_and_cleans_its_home() {
        let root = TestDir::new("success");
        let signing = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let status =
            format!("[GNUPG:] VALIDSIG {signing} 2026-09-02 1788321600 0 4 0 22 8 00 {OPERATOR}\n");
        let (executable, record) = write_fake_gpg(&root, &status, 0, 0, false);
        let verifier = GpgDetachedSignatureVerifier::with_configuration(
            executable,
            b"synthetic-public-key".to_vec(),
            Duration::from_secs(1),
            root.path().to_owned(),
        )
        .unwrap();
        assert_eq!(
            verifier
                .verify(b"canonical-payload", b"synthetic-signature")
                .unwrap(),
            SignerFingerprint::new(OPERATOR).unwrap(),
        );
        let recorded = std::fs::read_to_string(record).unwrap();
        for required in [
            "ARG=--batch",
            "ARG=--no-options",
            "ARG=--no-tty",
            "ARG=--no-autostart",
            "ARG=--disable-dirmngr",
            "ARG=--homedir",
            "ARG=--status-fd",
            "ARG=1",
            "ARG=--import",
            "ARG=--verify",
        ] {
            assert!(recorded.lines().any(|line| line == required), "{required}");
        }
        assert!(!recorded.contains("canonical-payload"));
        assert_no_gpg_homes(&root);
    }

    #[test]
    fn gpg_rejects_configuration_process_failure_status_overflow_and_timeout() {
        assert_eq!(
            GpgDetachedSignatureVerifier::new(PathBuf::from("gpg"), vec![1]).err(),
            Some(CampaignError::SignatureVerifierInvalid),
        );
        assert_eq!(
            GpgDetachedSignatureVerifier::new(PathBuf::from("/usr/bin/gpg"), Vec::new()).err(),
            Some(CampaignError::SignatureVerifierInvalid),
        );

        let valid = format!(
            "[GNUPG:] VALIDSIG {OPERATOR} 2026-09-02 1788321600 0 4 0 22 8 00 {OPERATOR}\n"
        );
        for (tag, status, import_exit, verify_exit, sleep, expected) in [
            (
                "import-failure",
                valid.clone(),
                2,
                0,
                false,
                CampaignError::SignatureVerifierFailed,
            ),
            (
                "verify-failure",
                valid.clone(),
                0,
                2,
                false,
                CampaignError::SignatureVerifierFailed,
            ),
            (
                "status-overflow",
                "x".repeat(64 * 1024 + 1),
                0,
                0,
                false,
                CampaignError::SignatureInvalid,
            ),
            (
                "timeout",
                valid.clone(),
                0,
                0,
                true,
                CampaignError::SignatureVerifierTimeout,
            ),
        ] {
            let root = TestDir::new(tag);
            let (executable, _) = write_fake_gpg(&root, &status, import_exit, verify_exit, sleep);
            let timeout = if sleep {
                Duration::from_millis(20)
            } else {
                Duration::from_secs(1)
            };
            let verifier = GpgDetachedSignatureVerifier::with_configuration(
                executable,
                b"synthetic-public-key".to_vec(),
                timeout,
                root.path().to_owned(),
            )
            .unwrap();
            assert_eq!(
                verifier.verify(b"canonical-payload", b"synthetic-signature"),
                Err(expected),
                "{tag}",
            );
            assert_no_gpg_homes(&root);
        }
    }
}
