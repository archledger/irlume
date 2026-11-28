// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::handover::{run_fixture, Event, Order, Outcome};
use super::handover_tests::{valid_script, SCOPE};
use super::journal::record_intent;
use std::fs::{self, DirBuilder};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// A private fixture case directory, removed when the test that made it ends.
/// Child processes get only its path, so an interrupted child leaves it intact.
struct CaseDir(PathBuf);

impl std::ops::Deref for CaseDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for CaseDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The next free case directory under `base`. A directory left by an earlier
/// process with the same PID is skipped, never reused or removed.
fn create_case(base: &Path, next: &AtomicU64) -> CaseDir {
    for _ in 0..1024 {
        let id = next.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("book2-fixture-{}-{id}", process::id()));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return CaseDir(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("cannot create fixture case {}: {error}", path.display()),
        }
    }
    panic!("no free fixture case name under {}", base.display());
}

fn fresh_case() -> CaseDir {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    create_case(&std::env::temp_dir(), &NEXT)
}

fn assert_marker(case_dir: &Path) {
    let path = case_dir.join("attempt.hold");
    assert_eq!(fs::read(&path).unwrap(), b"stage-a-fixture-v1\n");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn marker_present_before_begin_phase() {
    let dir = fresh_case();
    let order = Order::RgbIrRgb;
    let mut phases = 0;
    let result = run_fixture(
        SCOPE,
        order,
        &valid_script(SCOPE, order),
        || record_intent(&dir).is_ok(),
        |event| {
            if matches!(event, Event::BeginPhase(_)) {
                assert_marker(&dir);
                phases += 1;
            }
        },
    );
    assert_eq!((result, phases), (Outcome::Complete, 3));
    assert_marker(&dir);
}

fn run_child(instruction: &str, case_dir: &Path) -> Output {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "journal_tests::child_exit_after_intent_keeps_attempt_closed",
            "--nocapture",
        ])
        .env("BOOK2_FIXTURE_CHILD", instruction)
        .env("BOOK2_FIXTURE_CASE", case_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("fixture subprocess timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn child_exit_after_intent_keeps_attempt_closed() {
    if let Ok(instruction) = std::env::var("BOOK2_FIXTURE_CHILD") {
        let path = PathBuf::from(std::env::var_os("BOOK2_FIXTURE_CASE").unwrap());
        let order = Order::IrRgbIr;
        if instruction == "interrupt" {
            run_fixture(
                SCOPE,
                order,
                &valid_script(SCOPE, order),
                || record_intent(&path).is_ok(),
                |event| {
                    assert_eq!(event, Event::IntentRecorded);
                    assert_marker(&path);
                    println!("intent synced");
                    io::stdout().flush().unwrap();
                    process::exit(73);
                },
            );
            panic!("intent not reached");
        }
        assert_eq!(instruction, "reopen");
        let mut fresh = SCOPE;
        fresh.attempt += 1;
        fresh.reservation += 1;
        assert_eq!(
            run_fixture(
                fresh,
                order,
                &valid_script(fresh, order),
                || record_intent(&path).is_ok(),
                |event| panic!("effect after reopen: {event:?}"),
            ),
            Outcome::Held
        );
        assert_marker(&path);
        println!("reopen held");
        return;
    }

    let path = fresh_case();
    let crashed = run_child("interrupt", &path);
    assert_eq!(crashed.status.code(), Some(73), "{crashed:?}");
    assert!(String::from_utf8_lossy(&crashed.stdout).contains("intent synced"));
    let reopened = run_child("reopen", &path);
    assert!(reopened.status.success(), "{reopened:?}");
    assert!(String::from_utf8_lossy(&reopened.stdout).contains("reopen held"));
    println!("child exited 73 after sync; fresh child held");
}

#[test]
fn case_directory_is_removed_when_its_test_ends() {
    let case = fresh_case();
    let path = case.to_path_buf();
    record_intent(&case).unwrap();
    assert!(path.join("attempt.hold").is_file());
    drop(case);
    assert!(!path.exists());
}

#[test]
fn stale_case_directory_from_an_earlier_process_is_skipped() {
    let base = fresh_case();
    let next = AtomicU64::new(0);
    let stale = base.join(format!("book2-fixture-{}-0", process::id()));
    DirBuilder::new().mode(0o700).create(&stale).unwrap();
    let case = create_case(&base, &next);
    assert_ne!(&*case, stale.as_path());
    assert!(stale.is_dir());
}

#[test]
fn occupied_or_unwritable_marker_never_starts() {
    let path = fresh_case();
    let marker = path.join("attempt.hold");
    fs::write(&marker, b"existing fixture intent").unwrap();
    let file = path.join("not-a-directory");
    fs::write(&file, b"not a directory").unwrap();
    let order = Order::RgbIrRgb;
    for case in [&*path, file.as_path()] {
        assert_eq!(
            run_fixture(
                SCOPE,
                order,
                &valid_script(SCOPE, order),
                || record_intent(case).is_ok(),
                |event| panic!("effect after intent failure: {event:?}"),
            ),
            Outcome::Held
        );
    }
    assert_eq!(fs::read(marker).unwrap(), b"existing fixture intent");
    assert_eq!(fs::read(file).unwrap(), b"not a directory");
}
