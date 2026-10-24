// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::measurement_profile::observe::{FixtureScope, ObservedFixtureFiles};
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fixture() -> (tempfile::TempDir, FixtureScope, File) {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let directory = File::open(&root).unwrap();
    let scope = FixtureScope {
        root,
        expected_uid: directory.metadata().unwrap().uid(),
    };
    (parent, scope, directory)
}

fn put(scope: &FixtureScope, name: &str, data: &[u8]) {
    let path = scope.root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn limits() -> AcquisitionLimits {
    AcquisitionLimits {
        observations: ObservationLimits {
            per_file_bytes: 32,
            total_bytes: 64,
            read_calls: 32,
        },
        open_attempts: 8,
    }
}

struct MockOpen {
    root: PathBuf,
    errors: VecDeque<i32>,
    calls: Vec<(Vec<u8>, u64, u64, u64, usize)>,
    returned: Vec<RawFd>,
}

impl MockOpen {
    fn new(scope: &FixtureScope) -> Self {
        Self {
            root: scope.root.clone(),
            errors: VecDeque::new(),
            calls: vec![],
            returned: vec![],
        }
    }
}

impl AcquisitionIo for MockOpen {
    fn openat2(
        &mut self,
        _directory: &File,
        path: &CStr,
        how: &libc::open_how,
        size: usize,
    ) -> io::Result<File> {
        self.calls.push((
            path.to_bytes().to_vec(),
            how.flags,
            how.mode,
            how.resolve,
            size,
        ));
        if let Some(error) = self.errors.pop_front() {
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
        }
        let path = OsString::from_vec(path.to_bytes().to_vec());
        let file = File::open(self.root.join(path))?;
        self.returned.push(file.as_raw_fd());
        Ok(file)
    }
}

#[test]
fn acquisition_passes_owned_files_to_observer() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"one");
    put(&scope, "nested/two", b"two");
    let mut io = MockOpen::new(&scope);
    let result = acquire_with(
        &scope,
        directory,
        &["one".into(), "nested/two".into()],
        limits(),
        &mut io,
    )
    .unwrap();
    assert_eq!(result.files()[0].bytes(), b"one");
    assert_eq!(result.files()[1].bytes(), b"two");
    assert_eq!(result.files()[0].observation().path, scope.root.join("one"));
    assert_eq!(io.calls.len(), 2);
}

#[test]
fn acquisition_preserves_original_path_spelling() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"one");
    let mut io = MockOpen::new(&scope);
    assert!(acquire_with(&scope, directory, &["one/.".into()], limits(), &mut io).is_err());
    assert_eq!(io.calls[0].0, b"one/.");
}

#[test]
fn acquisition_rejects_invalid_paths_before_open() {
    for path in [
        PathBuf::new(),
        "/absolute".into(),
        "../escape".into(),
        "sub/../../escape".into(),
        "a\0b".into(),
        PathBuf::from(OsString::from_vec(vec![0xff])),
    ] {
        let (_parent, scope, directory) = fixture();
        let mut io = MockOpen::new(&scope);
        assert_eq!(
            acquire_with(&scope, directory, &[path], limits(), &mut io).unwrap_err(),
            AcquisitionError::InvalidPath { file: 0 }
        );
        assert!(io.calls.is_empty());
    }
    let (_parent, scope, directory) = fixture();
    let mut io = MockOpen::new(&scope);
    let long = PathBuf::from("x".repeat(crate::measurement_profile::MAX_TEXT_BYTES));
    assert_eq!(
        acquire_with(&scope, directory, &[long], limits(), &mut io).unwrap_err(),
        AcquisitionError::InvalidPath { file: 0 }
    );
    assert!(io.calls.is_empty());
}

#[test]
fn acquisition_rejects_duplicate_and_empty_batches() {
    let (_parent, scope, directory) = fixture();
    let mut io = MockOpen::new(&scope);
    assert_eq!(
        acquire_with(&scope, directory, &[], limits(), &mut io).unwrap_err(),
        AcquisitionError::EmptyBatch
    );
    let directory = File::open(&scope.root).unwrap();
    assert_eq!(
        acquire_with(
            &scope,
            directory,
            &["one".into(), "one".into()],
            limits(),
            &mut io
        )
        .unwrap_err(),
        AcquisitionError::DuplicatePath { file: 1 }
    );
    assert!(io.calls.is_empty());
}

#[test]
fn acquisition_rejects_root_symlink_and_wrong_root() {
    let (parent, mut scope, directory) = fixture();
    let alias = parent.path().join("alias");
    symlink(&scope.root, &alias).unwrap();
    let mut io = MockOpen::new(&scope);
    scope.root = alias;
    assert_eq!(
        acquire_with(&scope, directory, &["one".into()], limits(), &mut io).unwrap_err(),
        AcquisitionError::RootRefused
    );
    let wrong = File::open(parent.path()).unwrap();
    scope.root = io.root.clone();
    assert_eq!(
        acquire_with(&scope, wrong, &["one".into()], limits(), &mut io).unwrap_err(),
        AcquisitionError::RootRefused
    );
    let directory = File::open(&scope.root).unwrap();
    scope.expected_uid = scope.expected_uid.wrapping_add(1);
    assert_eq!(
        acquire_with(&scope, directory, &["one".into()], limits(), &mut io).unwrap_err(),
        AcquisitionError::RootRefused
    );
    assert!(io.calls.is_empty());
}

struct RootChange {
    inner: MockOpen,
    point: Checkpoint,
    changed: bool,
    replace: bool,
}
impl AcquisitionIo for RootChange {
    fn openat2(
        &mut self,
        directory: &File,
        path: &CStr,
        how: &libc::open_how,
        size: usize,
    ) -> io::Result<File> {
        self.inner.openat2(directory, path, how, size)
    }
    fn checkpoint(&mut self, directory: &File, _file: usize, point: Checkpoint) {
        if self.changed || point != self.point {
            return;
        }
        self.changed = true;
        if self.replace {
            fs::rename(&self.inner.root, self.inner.root.with_file_name("old-root")).unwrap();
            fs::create_dir(&self.inner.root).unwrap();
            fs::set_permissions(&self.inner.root, fs::Permissions::from_mode(0o700)).unwrap();
        } else {
            directory
                .set_permissions(fs::Permissions::from_mode(0o750))
                .unwrap();
        }
    }
}

#[test]
fn acquisition_checks_root_at_every_checkpoint() {
    for point in [
        Checkpoint::BeforeOpen,
        Checkpoint::AfterOpen,
        Checkpoint::BeforeObserve,
        Checkpoint::AfterObserve,
    ] {
        for replace in [false, true] {
            let (_parent, scope, directory) = fixture();
            put(&scope, "one", b"one");
            let mut io = RootChange {
                inner: MockOpen::new(&scope),
                point,
                changed: false,
                replace,
            };
            assert_eq!(
                acquire_with(&scope, directory, &["one".into()], limits(), &mut io).unwrap_err(),
                AcquisitionError::RootChanged
            );
        }
    }
}

#[test]
fn acquisition_retry_budget_is_batch_wide() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"one");
    put(&scope, "two", b"two");
    let mut io = MockOpen::new(&scope);
    io.errors = [libc::EINTR, libc::EAGAIN, 0, libc::EAGAIN].into();
    let limit = AcquisitionLimits {
        open_attempts: 4,
        ..limits()
    };
    assert_eq!(
        acquire_with(
            &scope,
            directory,
            &["one".into(), "two".into()],
            limit,
            &mut io
        )
        .unwrap_err(),
        AcquisitionError::AttemptsExhausted { file: 1 }
    );
    assert_eq!(io.calls.len(), 4);
}

#[test]
fn acquisition_never_relaxes_flags_after_errors() {
    for error in [
        libc::ENOSYS,
        libc::EINVAL,
        libc::E2BIG,
        libc::EACCES,
        libc::ELOOP,
        libc::EXDEV,
    ] {
        let (_parent, scope, directory) = fixture();
        let mut io = MockOpen::new(&scope);
        io.errors.push_back(error);
        let result =
            acquire_with(&scope, directory, &["one".into()], limits(), &mut io).unwrap_err();
        if [libc::ENOSYS, libc::EINVAL, libc::E2BIG].contains(&error) {
            assert_eq!(result, AcquisitionError::Unsupported);
        } else {
            assert_eq!(result, AcquisitionError::OpenRefused { file: 0 });
        }
        assert_eq!(io.calls.len(), 1);
        let (_, flags, mode, resolve, size) = io.calls[0];
        assert_eq!(
            flags,
            (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64 | (1u64 << 32)
        );
        assert_eq!(
            resolve,
            libc::RESOLVE_BENEATH
                | libc::RESOLVE_NO_SYMLINKS
                | libc::RESOLVE_NO_MAGICLINKS
                | libc::RESOLVE_NO_XDEV
        );
        assert_eq!(mode, 0);
        assert_eq!(size, 24);
    }
}

#[test]
fn acquisition_open_how_matches_v0_abi() {
    assert_eq!(std::mem::size_of::<libc::open_how>(), 24);
    assert_eq!(std::mem::offset_of!(libc::open_how, flags), 0);
    assert_eq!(std::mem::offset_of!(libc::open_how, mode), 8);
    assert_eq!(std::mem::offset_of!(libc::open_how, resolve), 16);
    let how = make_how();
    assert_eq!(std::mem::size_of_val(&how.flags), 8);
    assert_eq!(std::mem::size_of_val(&how.mode), 8);
    assert_eq!(std::mem::size_of_val(&how.resolve), 8);
    assert_eq!(how.flags & (1u64 << 32), 1u64 << 32);
}

#[test]
fn acquisition_checks_returned_leaf_policy() {
    let (_parent, scope, directory) = fixture();
    let mut io = MockOpen::new(&scope);
    fs::create_dir(scope.root.join("directory")).unwrap();
    assert_eq!(
        acquire_with(&scope, directory, &["directory".into()], limits(), &mut io).unwrap_err(),
        AcquisitionError::LeafRefused { file: 0 }
    );
    put(&scope, "writable", b"x");
    fs::set_permissions(
        scope.root.join("writable"),
        fs::Permissions::from_mode(0o620),
    )
    .unwrap();
    let directory = File::open(&scope.root).unwrap();
    assert_eq!(
        acquire_with(&scope, directory, &["writable".into()], limits(), &mut io).unwrap_err(),
        AcquisitionError::LeafRefused { file: 0 }
    );
}

fn assert_closed(fd: RawFd) {
    // SAFETY: fcntl only queries an integer descriptor; a closed descriptor
    // returns EBADF. No unrelated descriptor is modified or closed.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
}

#[test]
fn acquisition_cleans_partial_files_on_failure() {
    run_cleanup_child("partial");
    run_cleanup_child("reuse");
}

fn cleanup_partial_files() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"one");
    let root_fd = directory.as_raw_fd();
    let mut io = MockOpen::new(&scope);
    io.errors = [0, libc::EACCES].into();
    assert_eq!(
        acquire_with(
            &scope,
            directory,
            &["one".into(), "two".into()],
            limits(),
            &mut io
        )
        .unwrap_err(),
        AcquisitionError::OpenRefused { file: 1 }
    );
    assert_closed(root_fd);
    assert_closed(io.returned[0]);
}

#[test]
fn acquisition_enforces_limits_before_syscalls() {
    for attempts in [0, 8193] {
        let (_parent, scope, directory) = fixture();
        let mut io = MockOpen::new(&scope);
        assert_eq!(
            acquire_with(
                &scope,
                directory,
                &["one".into()],
                AcquisitionLimits {
                    open_attempts: attempts,
                    ..limits()
                },
                &mut io
            )
            .unwrap_err(),
            AcquisitionError::InvalidLimits
        );
        assert!(io.calls.is_empty());
    }
    let (_parent, scope, directory) = fixture();
    let mut io = MockOpen::new(&scope);
    assert_eq!(
        acquire_with(
            &scope,
            directory,
            &vec![PathBuf::from("one"); 257],
            limits(),
            &mut io
        )
        .unwrap_err(),
        AcquisitionError::TooManyPaths
    );
    assert!(io.calls.is_empty());
    assert_eq!(AcquisitionLimits::default().open_attempts, 1024);
}

#[test]
fn acquisition_observer_refusal_drops_all_fds() {
    run_cleanup_child("observer-refusal");
}

fn cleanup_observer_refusal() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"oversized");
    let mut io = MockOpen::new(&scope);
    let mut limit = limits();
    limit.observations.per_file_bytes = 1;
    assert_eq!(
        acquire_with(&scope, directory, &["one".into()], limit, &mut io).unwrap_err(),
        AcquisitionError::Observation(ObservationError::FileTooLarge { file: 0 })
    );
    assert_closed(io.returned[0]);
}

#[test]
fn acquisition_errors_are_redacted_and_have_no_authority() {
    let (_parent, scope, directory) = fixture();
    let mut io = MockOpen::new(&scope);
    io.errors.push_back(libc::EACCES);
    let error = acquire_with(
        &scope,
        directory,
        &["private-name".into()],
        limits(),
        &mut io,
    )
    .unwrap_err();
    for output in [format!("{error:?}"), error.to_string()] {
        assert!(!output.contains("private-name"));
        assert!(!output.contains(scope.root.to_str().unwrap()));
    }
    let _: Option<ObservedFixtureFiles> = None;
}

#[test]
fn acquisition_rejects_root_alias_spellings() {
    for suffix in ["", "/", "/."] {
        let (parent, mut scope, directory) = fixture();
        let alias = parent.path().join("alias");
        symlink(&scope.root, &alias).unwrap();
        let mut io = MockOpen::new(&scope);
        scope.root = PathBuf::from(format!("{}{suffix}", alias.display()));
        assert_eq!(
            acquire_with(&scope, directory, &["one".into()], limits(), &mut io).unwrap_err(),
            AcquisitionError::RootRefused
        );
        assert!(io.calls.is_empty());
    }
}

struct LeafChange {
    inner: MockOpen,
    point: Checkpoint,
    changed: bool,
    replace_directory: bool,
}

impl AcquisitionIo for LeafChange {
    fn openat2(
        &mut self,
        directory: &File,
        path: &CStr,
        how: &libc::open_how,
        size: usize,
    ) -> io::Result<File> {
        self.inner.openat2(directory, path, how, size)
    }

    fn checkpoint(&mut self, _directory: &File, _file: usize, point: Checkpoint) {
        if self.changed || point != self.point {
            return;
        }
        self.changed = true;
        if self.replace_directory {
            fs::rename(
                self.inner.root.join("sub/inner"),
                self.inner.root.join("sub/old"),
            )
            .unwrap();
            fs::create_dir(self.inner.root.join("sub/inner")).unwrap();
        }
        let path = self.inner.root.join("sub/inner/one");
        fs::write(&path, b"two").unwrap();
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(12345)),
            )
            .unwrap();
    }
}

#[test]
fn acquisition_detects_intermediate_directory_replacement() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "sub/inner/one", b"one");
    let mut io = LeafChange {
        inner: MockOpen::new(&scope),
        point: Checkpoint::BeforeObserve,
        changed: false,
        replace_directory: true,
    };
    assert_eq!(
        acquire_with(
            &scope,
            directory,
            &["sub/inner/one".into()],
            limits(),
            &mut io
        )
        .unwrap_err(),
        AcquisitionError::Observation(ObservationError::DescriptorMismatch { file: 0 })
    );
}

#[test]
fn acquisition_detects_leaf_stamp_changes() {
    for point in [Checkpoint::BeforeObserve, Checkpoint::AfterObserve] {
        let (_parent, scope, directory) = fixture();
        put(&scope, "sub/inner/one", b"one");
        let mut io = LeafChange {
            inner: MockOpen::new(&scope),
            point,
            changed: false,
            replace_directory: false,
        };
        assert_eq!(
            acquire_with(
                &scope,
                directory,
                &["sub/inner/one".into()],
                limits(),
                &mut io
            )
            .unwrap_err(),
            AcquisitionError::LeafChanged { file: 0 }
        );
    }
}

#[test]
fn acquisition_closes_root_on_success() {
    run_cleanup_child("success");
}

fn cleanup_success() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"one");
    let fd = directory.as_raw_fd();
    let result = acquire_with(
        &scope,
        directory,
        &["one".into()],
        limits(),
        &mut MockOpen::new(&scope),
    )
    .unwrap();
    assert_closed(fd);
    assert_eq!(result.files()[0].bytes(), b"one");
}

// These assertions concern a descriptor *number after close*. Running another
// test in the same process could allocate that number between drop and fcntl.
// Keep the bodies in exact-name fresh children, not under a suite-wide lock.
fn run_cleanup_child(case: &str) {
    const TEST: &str = "measurement_profile::acquire::tests::acquisition_cleanup_child";
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--ignored"])
        .env("IRLUME_ACQUISITION_CLEANUP_CASE", case)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cleanup child exceeded the fixture timeout");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "cleanup case {case} failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.lines().any(|line| line == "running 1 test"));
    assert!(stdout
        .lines()
        .any(|line| line == format!("test {TEST} ... ok")));
    assert!(stdout
        .lines()
        .any(|line| { line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;") }));
}

#[test]
#[ignore = "exact-name child always invoked by the three named FD-cleanup parent tests"]
fn acquisition_cleanup_child() {
    match std::env::var("IRLUME_ACQUISITION_CLEANUP_CASE")
        .unwrap()
        .as_str()
    {
        "partial" => cleanup_partial_files(),
        "observer-refusal" => cleanup_observer_refusal(),
        "success" => cleanup_success(),
        "reuse" => demonstrate_descriptor_number_reuse(),
        _ => panic!("unknown cleanup child case"),
    }
}

fn demonstrate_descriptor_number_reuse() {
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"one");
    let path = scope.root.join("one");
    let file = File::open(&path).unwrap();
    let closed_number = file.as_raw_fd();
    drop(file);
    // No other test is running in this process. The next open reuses the
    // lowest available number, although the original File was truly closed.
    let replacement = File::open(&path).unwrap();
    assert_eq!(replacement.as_raw_fd(), closed_number);
    // SAFETY: query only; replacement owns and keeps this descriptor live.
    assert_ne!(unsafe { libc::fcntl(closed_number, libc::F_GETFD) }, -1);
    drop(replacement);
    assert_closed(closed_number);
    drop(directory);
}

#[test]
#[ignore = "requires Linux 7.2 OPENAT2_REGULAR; run through the explicit positive-kernel lane"]
fn kernel_acquisition_requires_regular_file_resolution() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "measurement_profile::acquire::tests::kernel_acquisition_child",
            "--ignored",
            "--nocapture",
        ])
        .env("IRLUME_ACQUISITION_CHILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("kernel acquisition child exceeded the fixture timeout");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "kernel acquisition failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
#[ignore = "child of the bounded explicit positive-kernel test, never run as a general ignored sweep"]
fn kernel_acquisition_child() {
    assert_eq!(std::env::var("IRLUME_ACQUISITION_CHILD").unwrap(), "1");
    let (_parent, scope, directory) = fixture();
    put(&scope, "one", b"real-wrapper");
    let result = acquire_and_observe(&scope, directory, &["one".into()], limits()).unwrap();
    assert_eq!(result.files()[0].bytes(), b"real-wrapper");
    fs::create_dir(scope.root.join("sub")).unwrap();
    symlink("one", scope.root.join("alias")).unwrap();
    symlink("sub", scope.root.join("directory-alias")).unwrap();
    let _socket = UnixListener::bind(scope.root.join("socket")).unwrap();
    let fifo = CString::new(scope.root.join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated pathname is inside this owned fixture root;
    // mkfifo creates no device and its mode is owner-only.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    for name in [
        "sub",
        "fifo",
        "socket",
        "alias",
        "directory-alias/file",
        "one/",
        "one/.",
    ] {
        let directory = File::open(&scope.root).unwrap();
        assert!(
            acquire_and_observe(&scope, directory, &[name.into()], limits()).is_err(),
            "accepted {name}"
        );
    }
}
