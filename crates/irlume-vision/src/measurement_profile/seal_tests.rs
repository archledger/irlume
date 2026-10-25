// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::measurement_profile::observe::{
    observe_fixture_files, FixtureFile, FixtureScope, ObservationLimits, ObservedFixtureFiles,
};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn observed(data: &[&[u8]]) -> (tempfile::TempDir, ObservedFixtureFiles) {
    let (directory, files, _) = observed_with_fds(data);
    (directory, files)
}

fn observed_with_fds(data: &[&[u8]]) -> (tempfile::TempDir, ObservedFixtureFiles, Vec<RawFd>) {
    let directory = tempfile::tempdir().unwrap();
    let scope = FixtureScope {
        root: directory.path().to_owned(),
        expected_uid: fs::metadata(directory.path()).unwrap().uid(),
    };
    let mut descriptors = Vec::new();
    let files = data
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let path = directory.path().join(format!("fixture-{index}"));
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let file = File::open(&path).unwrap();
            descriptors.push(file.as_raw_fd());
            FixtureFile {
                file,
                declared_path: path,
            }
        })
        .collect();
    let result = observe_fixture_files(&scope, files, ObservationLimits::default()).unwrap();
    (directory, result, descriptors)
}

#[test]
fn sealing_refuses_empty_files() {
    let (_directory, files) = observed(&[b""]);
    assert_eq!(
        seal_observed_files(files).unwrap_err(),
        SealError::InvalidSize { file: 0 }
    );
}

#[test]
fn sealing_uses_observed_bytes_not_a_new_source_read() {
    let (directory, files) = observed(&[b"observed bytes"]);
    fs::write(directory.path().join("fixture-0"), b"changed source").unwrap();
    match seal_observed_files(files) {
        Ok(sealed) => {
            let mut bytes = [0; 14];
            sealed.files()[0]
                ._file
                .read_exact_at(&mut bytes, 0)
                .unwrap();
            assert_eq!(&bytes, b"observed bytes");
            assert_eq!(
                sealed.files()[0].observation().sha256,
                irlume_common::sha256_hex(&bytes)
            );
        }
        Err(error) => assert_eq!(error, SealError::Unsupported { file: 0 }),
    }
}

#[test]
#[ignore = "requires real memfd no-exec seals; run the named kernel gate"]
fn kernel_sealing_keeps_exact_bytes_and_all_required_seals() {
    let (_directory, files) = observed(&[b"one", b"two"]);
    let sealed = seal_observed_files(files).unwrap();
    assert_eq!(sealed.files().len(), 2);
    for (file, expected) in sealed.files().iter().zip([b"one", b"two"]) {
        let mut bytes = [0; 3];
        file._file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, expected);
        // SAFETY: the borrowed descriptor remains open; F_GET_SEALS has no pointer argument.
        let seals = unsafe { libc::fcntl(file._file.as_raw_fd(), libc::F_GET_SEALS) };
        for bit in [
            libc::F_SEAL_WRITE,
            libc::F_SEAL_GROW,
            libc::F_SEAL_SHRINK,
            libc::F_SEAL_EXEC,
            libc::F_SEAL_SEAL,
        ] {
            assert_ne!(seals & bit, 0);
        }
        assert_eq!(file._file.metadata().unwrap().mode() & 0o7777, 0o400);
        assert_ne!(
            fcntl(&file._file, libc::F_GETFD, 0).unwrap() & libc::FD_CLOEXEC,
            0
        );

        // The original memfd is O_RDWR: each refusal must come from seals,
        // not from a read-only descriptor or lack of pathname permission.
        assert_eq!(
            file._file.write_at(b"bad", 0).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        for length in [0, 4] {
            assert_eq!(
                file._file.set_len(length).unwrap_err().raw_os_error(),
                Some(libc::EPERM)
            );
        }
        assert_eq!(
            file._file
                .set_permissions(fs::Permissions::from_mode(0o500))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        // SAFETY: request a fresh mapping; do not dereference the result.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                3,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file._file.as_raw_fd(),
                0,
            )
        };
        let mapping_error = io::Error::last_os_error();
        if mapping != libc::MAP_FAILED {
            // SAFETY: release precisely the mapping returned above.
            assert_eq!(unsafe { libc::munmap(mapping, 3) }, 0);
        }
        assert_eq!(mapping, libc::MAP_FAILED);
        assert_eq!(mapping_error.raw_os_error(), Some(libc::EPERM));
        assert_eq!(file._file.metadata().unwrap().len(), 3);
        file._file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, expected);
    }
    assert_ne!(
        sealed.files()[0]._file.metadata().unwrap().ino(),
        sealed.files()[1]._file.metadata().unwrap().ino()
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Create(i32),
    SecondCreate,
    SecondRead,
    WriteZero,
    WriteTooLong,
    WriteError,
    WrongSize,
    Mode,
    AddSeals,
    GetSeals,
    MissingSeal(i32),
    Flags,
    MissingCloexec,
    Metadata,
    NonRegularMetadata,
    WrongMode,
    ReadError,
    ReadTooLong,
    EarlyEof,
    ExtraByte,
    Corrupt,
}

// The portable backend uses ordinary anonymous files. Only the explicit
// kernel test above qualifies real seal semantics; these tests inject faults.
struct TestIo {
    fault: Fault,
    created: Vec<RawFd>,
    calls: usize,
    short: bool,
    interrupt_write: bool,
    interrupt_read: bool,
}

impl TestIo {
    fn new(fault: Fault) -> Self {
        Self {
            fault,
            created: Vec::new(),
            calls: 0,
            short: false,
            interrupt_write: false,
            interrupt_read: false,
        }
    }
}

impl SealIo for TestIo {
    fn create(&mut self) -> io::Result<File> {
        match self.fault {
            Fault::Create(errno) => return Err(io::Error::from_raw_os_error(errno)),
            Fault::SecondCreate if self.created.len() == 1 => {
                return Err(io::ErrorKind::Other.into())
            }
            _ => {}
        }
        let file = tempfile::tempfile()?;
        self.created.push(file.as_raw_fd());
        Ok(file)
    }
    fn write(&mut self, file: &File, bytes: &[u8], offset: u64) -> io::Result<usize> {
        self.calls += 1;
        if std::mem::take(&mut self.interrupt_write) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        match self.fault {
            Fault::WriteZero => Ok(0),
            Fault::WriteTooLong => Ok(bytes.len() + 1),
            Fault::WriteError => Err(io::ErrorKind::PermissionDenied.into()),
            Fault::WrongSize => {
                file.write_at(&bytes[..1], offset)?;
                Ok(bytes.len())
            }
            _ => file.write_at(&bytes[..if self.short { 1 } else { bytes.len() }], offset),
        }
    }
    fn read(&mut self, file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        self.calls += 1;
        if std::mem::take(&mut self.interrupt_read) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        match self.fault {
            Fault::ReadError => return Err(io::ErrorKind::PermissionDenied.into()),
            Fault::SecondRead if self.created.len() == 2 => {
                return Err(io::ErrorKind::PermissionDenied.into())
            }
            Fault::ReadTooLong => return Ok(bytes.len() + 1),
            Fault::EarlyEof => return Ok(0),
            Fault::ExtraByte if offset == file.metadata()?.len() => {
                bytes[0] = 1;
                return Ok(1);
            }
            _ => {}
        }
        let limit = if self.short { 1 } else { bytes.len() };
        let count = file.read_at(&mut bytes[..limit], offset)?;
        if self.fault == Fault::Corrupt && count > 0 {
            bytes[0] ^= 1;
        }
        Ok(count)
    }
    fn mode(&mut self, file: &File) -> io::Result<()> {
        match self.fault {
            Fault::Mode => Err(io::ErrorKind::PermissionDenied.into()),
            Fault::WrongMode => Ok(()),
            _ => SystemIo.mode(file),
        }
    }
    fn add_seals(&mut self, _: &File) -> io::Result<()> {
        if self.fault == Fault::AddSeals {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    }
    fn seals(&mut self, _: &File) -> io::Result<i32> {
        match self.fault {
            Fault::GetSeals => Err(io::ErrorKind::PermissionDenied.into()),
            Fault::MissingSeal(bit) => Ok(REQUIRED_SEALS & !bit),
            _ => Ok(REQUIRED_SEALS),
        }
    }
    fn flags(&mut self, file: &File) -> io::Result<i32> {
        match self.fault {
            Fault::Flags => Err(io::ErrorKind::PermissionDenied.into()),
            Fault::MissingCloexec => Ok(0),
            _ => SystemIo.flags(file),
        }
    }
    fn metadata(&mut self, file: &File) -> io::Result<std::fs::Metadata> {
        match self.fault {
            Fault::Metadata => Err(io::ErrorKind::PermissionDenied.into()),
            Fault::NonRegularMetadata => tempfile::tempdir()?.path().metadata(),
            _ => file.metadata(),
        }
    }
}

#[test]
fn sealing_refuses_empty_batch_before_creating_files() {
    let (_directory, files) = observed(&[]);
    let mut io = TestIo::new(Fault::None);
    assert_eq!(
        seal_with(files, &mut io, IO_CALLS).unwrap_err(),
        SealError::InvalidCount
    );
    assert!(io.created.is_empty());
}

#[test]
fn sealing_accounts_for_short_and_interrupted_io() {
    let (_directory, files) = observed(&[b"one", b"two"]);
    let mut io = TestIo::new(Fault::None);
    io.short = true;
    io.interrupt_write = true;
    io.interrupt_read = true;
    let result = seal_with(files, &mut io, IO_CALLS).unwrap();
    assert_eq!(result.files().len(), 2);
    assert_eq!(io.calls, 16); // 12 byte transfers, 2 EOF probes, 2 interruptions.
}

#[test]
fn sealing_io_budget_is_batch_wide_and_counts_interruptions() {
    for (budget, expected_calls, fault_file) in [(0, 0, 0), (2, 2, 0), (3, 3, 1), (5, 5, 1)] {
        let (_directory, files) = observed(&[b"one", b"two"]);
        let mut io = TestIo::new(Fault::None);
        assert_eq!(
            seal_with(files, &mut io, budget).unwrap_err(),
            SealError::AttemptsExhausted { file: fault_file }
        );
        assert_eq!(io.calls, expected_calls);
    }
    let (_directory, files) = observed(&[b"one"]);
    let mut io = TestIo::new(Fault::None);
    io.interrupt_write = true;
    assert_eq!(
        seal_with(files, &mut io, 3).unwrap_err(),
        SealError::AttemptsExhausted { file: 0 }
    );
    assert_eq!(io.calls, 3);
}

#[test]
fn sealing_checks_each_required_seal_independently() {
    for bit in [
        libc::F_SEAL_WRITE,
        libc::F_SEAL_GROW,
        libc::F_SEAL_SHRINK,
        libc::F_SEAL_EXEC,
        libc::F_SEAL_SEAL,
    ] {
        let (_directory, files) = observed(&[b"one"]);
        let mut io = TestIo::new(Fault::MissingSeal(bit));
        assert_eq!(
            seal_with(files, &mut io, IO_CALLS).unwrap_err(),
            SealError::SealMismatch { file: 0 }
        );
    }
}

#[test]
fn sealing_refuses_failed_operations_and_mismatched_readbacks() {
    let cases = [
        (
            Fault::Create(libc::ENOSYS),
            SealError::Unsupported { file: 0 },
        ),
        (
            Fault::Create(libc::EINVAL),
            SealError::Unsupported { file: 0 },
        ),
        (
            Fault::Create(libc::EMFILE),
            SealError::CreateFailed { file: 0 },
        ),
        (Fault::WriteZero, SealError::WriteFailed { file: 0 }),
        (Fault::WriteTooLong, SealError::WriteFailed { file: 0 }),
        (Fault::WriteError, SealError::WriteFailed { file: 0 }),
        (Fault::WrongSize, SealError::MetadataMismatch { file: 0 }),
        (Fault::Mode, SealError::ModeFailed { file: 0 }),
        (Fault::AddSeals, SealError::SealFailed { file: 0 }),
        (Fault::GetSeals, SealError::SealFailed { file: 0 }),
        (Fault::Flags, SealError::MetadataMismatch { file: 0 }),
        (
            Fault::MissingCloexec,
            SealError::MetadataMismatch { file: 0 },
        ),
        (Fault::Metadata, SealError::MetadataMismatch { file: 0 }),
        (
            Fault::NonRegularMetadata,
            SealError::MetadataMismatch { file: 0 },
        ),
        (Fault::WrongMode, SealError::MetadataMismatch { file: 0 }),
        (Fault::ReadError, SealError::ReadFailed { file: 0 }),
        (Fault::ReadTooLong, SealError::ContentMismatch { file: 0 }),
        (Fault::EarlyEof, SealError::ContentMismatch { file: 0 }),
        (Fault::ExtraByte, SealError::ContentMismatch { file: 0 }),
        (Fault::Corrupt, SealError::ContentMismatch { file: 0 }),
    ];
    for (fault, expected) in cases {
        let (_directory, files) = observed(&[b"one"]);
        let error = seal_with(files, &mut TestIo::new(fault), IO_CALLS).unwrap_err();
        assert_eq!(error, expected, "fault: {fault:?}");
        assert!(!format!("{error:?} {error}").contains("fixture-0"));
    }
}

#[test]
fn sealing_debug_output_is_redacted() {
    let (_directory, files) = observed(&[b"private bytes"]);
    let result = seal_with(files, &mut TestIo::new(Fault::None), IO_CALLS).unwrap();
    let debug = format!("{result:?} {:?}", result.files()[0]);
    for private in [
        "fixture-0",
        "private bytes",
        &irlume_common::sha256_hex(b"private bytes"),
    ] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn sealing_size_limits_include_checked_aggregate_overflow() {
    assert_eq!(checked_total(0, HARD_FILE_BYTES, 0), Ok(HARD_FILE_BYTES));
    assert_eq!(
        checked_total(HARD_TOTAL_BYTES - 1, 1, 2),
        Ok(HARD_TOTAL_BYTES)
    );
    for (total, size) in [
        (0, 0),
        (0, HARD_FILE_BYTES + 1),
        (HARD_TOTAL_BYTES, 1),
        (u64::MAX, 1),
    ] {
        assert_eq!(
            checked_total(total, size, 4),
            Err(SealError::InvalidSize { file: 4 })
        );
    }
}

#[test]
fn sealing_checks_every_byte_across_chunk_and_file_boundaries() {
    let bytes: Vec<Vec<u8>> = [1, IO_BYTES - 1, IO_BYTES, IO_BYTES + 1, IO_BYTES * 2 + 11]
        .into_iter()
        .map(|size| (0..size).map(|i| (i % 251) as u8).collect())
        .collect();
    let views: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let (directory, observed) = observed(&views);
    let sealed = seal_with(observed, &mut TestIo::new(Fault::None), IO_CALLS).unwrap();
    drop(directory);
    for (file, expected) in sealed.files().iter().zip(bytes) {
        let mut actual = vec![0; expected.len()];
        file._file.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            file.observation().sha256,
            irlume_common::sha256_hex(&actual)
        );
    }
}

#[test]
fn sealing_closes_partial_output_in_isolated_child() {
    const TEST: &str = "measurement_profile::seal::tests::sealing_cleanup_child";
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--ignored"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cleanup child timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout
        .lines()
        .any(|line| line == format!("test {TEST} ... ok")));
    assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
}

#[test]
#[ignore = "exact-name child invoked by sealing_closes_partial_output_in_isolated_child"]
fn sealing_cleanup_child() {
    for fault in [
        Fault::SecondCreate,
        Fault::SecondRead,
        Fault::ReadError,
        Fault::WriteZero,
        Fault::None,
    ] {
        let (_directory, files, originals) = observed_with_fds(&[b"one", b"two"]);
        let mut io = TestIo::new(fault);
        let result = seal_with(files, &mut io, IO_CALLS);
        if fault == Fault::None {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
        assert_closed(&originals);
        drop(result);
        assert_closed(&io.created);
    }
}

fn assert_closed(descriptors: &[RawFd]) {
    for &fd in descriptors {
        // SAFETY: query a number only; this isolated child performs no opens
        // between the tested drop and these checks, preventing number reuse.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
}
