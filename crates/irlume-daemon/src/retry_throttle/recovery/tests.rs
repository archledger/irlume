use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
thread_local! { static TICK: std::cell::Cell<u64> = const { std::cell::Cell::new(100) }; }
static SERIAL: AtomicU64 = AtomicU64::new(0);
fn now() -> io::Result<Tick> {
    Ok(Tick {
        boot: "00000000-0000-0000-0000-000000000001".into(),
        nanos: TICK.get() * NANOS,
    })
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "irlume-reset-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
    fn store(&self) -> Store {
        Store {
            parent: self.0.clone(),
            // SAFETY: geteuid has no preconditions.
            owner: unsafe { libc::geteuid() },
        }
    }
    fn identity(&self) -> Account {
        Account {
            uid: 1234,
            name: "fixture".into(),
        }
    }
    fn open(&self) -> Recovery {
        Recovery::begin(self.store(), self.identity(), now, write_atomic_reporting).unwrap()
    }
    fn plant_face(&self) {
        let s = self.store();
        let d = s.lock().unwrap();
        let mut r = Record::empty(&self.identity());
        r.strikes = 4;
        s.commit(&d, &r, write_atomic_reporting).unwrap();
    }
    fn face(&self) -> Record {
        let s = self.store();
        let d = s.lock().unwrap();
        s.read(&d, &self.identity()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn reset_requires_verified_password_and_preserves_face_on_refusal() {
    let f = Fixture::new();
    f.plant_face();
    let gate = f.open();
    assert!(gate
        .reset(false, || true, || Err("wrong password"))
        .is_err());
    assert_eq!(f.face().strikes, 4);
    gate.reset(false, || true, || Ok(())).unwrap();
    assert_eq!(f.face().strikes, 0);
}

#[test]
fn cumulative_status_does_not_migrate_legacy_and_verified_reset_starts_epoch() {
    let _env = crate::test_support::env_read();
    let f = Fixture::new();
    {
        let gate = f.open();
        assert_eq!(
            gate.status().unwrap().face_budget.unsuccessful_requests,
            None
        );
        assert!(!f.0.join("retry/1234.json").exists());
    }
    f.plant_face();
    let before = std::fs::read(f.0.join("retry/1234.json")).unwrap();
    let gate = f.open();
    assert_eq!(
        gate.status().unwrap().face_budget.unsuccessful_requests,
        None
    );
    assert_eq!(std::fs::read(f.0.join("retry/1234.json")).unwrap(), before);
    gate.reset(false, || true, || Ok(())).unwrap();
    assert_eq!(
        gate.status().unwrap().face_budget.unsuccessful_requests,
        Some(0)
    );
    assert_eq!(f.face().version, 2);
}

#[test]
fn cumulative_face_exhaustion_does_not_exhaust_password_recovery() {
    let _env = crate::test_support::env_read();
    let f = Fixture::new();
    {
        let s = f.store();
        let d = s.lock().unwrap();
        let mut face = Record::reset(&f.identity());
        face.budget.as_mut().unwrap().unsuccessful_requests = FACE_LIMIT;
        s.commit(&d, &face, write_atomic_reporting).unwrap();
    }
    let gate = f.open();
    let status = gate.status().unwrap();
    assert!(status.face_budget.reset_required);
    assert!(!status.recovery_required);
    assert_eq!(status.recovery_failures, 0);
    gate.reset(false, || true, || Err("synthetic refusal"))
        .unwrap_err();
    assert_eq!(
        gate.status().unwrap().face_budget.unsuccessful_requests,
        Some(50)
    );
    gate.reset(false, || true, || Ok(())).unwrap();
    assert_eq!(
        gate.status().unwrap().face_budget.unsuccessful_requests,
        Some(0)
    );
}
#[test]
fn reset_admin_override_does_not_call_password_verifier() {
    let f = Fixture::new();
    f.plant_face();
    f.open()
        .reset(
            true,
            || true,
            || panic!("root override must not call verifier"),
        )
        .unwrap();
    assert_eq!(f.face().strikes, 0);
}
#[test]
fn cancelled_reset_does_not_clear_history() {
    let f = Fixture::new();
    f.plant_face();
    assert!(f
        .open()
        .reset(
            false,
            || false,
            || panic!("inactive request must not verify")
        )
        .is_err());
    assert_eq!(f.face().strikes, 4);
}

#[test]
fn reset_budget_survives_reopen_and_delays_every_attempt_after_five() {
    let f = Fixture::new();
    for n in 1..=50 {
        let gate = f.open();
        assert!(gate.reset(false, || true, || Err("wrong")).is_err());
        assert_eq!(gate.status().unwrap().recovery_failures, n);
        if n >= 5 {
            assert!(gate
                .reset(false, || true, || panic!("cooldown must block verifier"))
                .is_err());
            TICK.set(TICK.get() + 30);
        }
    }
    let gate = f.open();
    assert!(gate.status().unwrap().recovery_required);
    assert!(gate
        .reset(false, || true, || panic!("ceiling must block verifier"))
        .is_err());
    gate.reset(true, || true, || panic!("administrator override"))
        .unwrap();
    assert_eq!(gate.status().unwrap().recovery_failures, 0);
}
#[test]
fn interrupted_verifier_keeps_a_durable_charge() {
    let f = Fixture::new();
    f.plant_face();
    let gate = f.open();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = gate.reset(false, || true, || panic!("interrupted verifier"));
    }));
    assert!(result.is_err());
    drop(gate);
    assert_eq!(f.open().status().unwrap().recovery_failures, 1);
    assert_eq!(f.face().strikes, 4);
}
#[test]
fn face_and_recovery_operations_cannot_overlap() {
    let f = Fixture::new();
    let face = f.store().operation(&f.identity()).unwrap();
    assert!(Recovery::begin(f.store(), f.identity(), now, write_atomic_reporting).is_err());
    drop(face);
    let gate = f.open();
    assert!(f.store().operation(&f.identity()).is_err());
    drop(gate);
    assert!(f.store().operation(&f.identity()).is_ok());
}
fn fail_face(path: &Path, bytes: &[u8], mode: u32) -> io::Result<AtomicWrite> {
    if path.file_name().unwrap() == "1234.json" {
        return Err(io::Error::other("face write failed"));
    }
    write_atomic_reporting(path, bytes, mode)
}
#[test]
fn reset_write_failure_preserves_face_and_does_not_replenish_password_guesses() {
    let f = Fixture::new();
    f.plant_face();
    let gate = Recovery::begin(f.store(), f.identity(), now, fail_face).unwrap();
    assert!(gate.reset(false, || true, || Ok(())).is_err());
    assert_eq!(f.face().strikes, 4);
    assert_eq!(gate.status().unwrap().recovery_failures, 1);
}
#[test]
fn successful_password_with_expired_request_does_not_reset_face() {
    let f = Fixture::new();
    f.plant_face();
    let gate = f.open();
    let calls = std::cell::Cell::new(0);
    assert!(gate
        .reset(
            false,
            || {
                calls.set(calls.get() + 1);
                calls.get() < 3
            },
            || Ok(())
        )
        .is_err());
    assert_eq!(f.face().strikes, 4);
    assert_eq!(gate.status().unwrap().recovery_failures, 1);
}
#[test]
fn malformed_recovery_state_is_never_replaced_with_empty_history() {
    let f = Fixture::new();
    f.plant_face();
    let gate = f.open();
    let dir = gate.store.lock().unwrap();
    write_atomic_reporting(&gate.path(&dir), br#"{"version":99}"#, 0o600).unwrap();
    drop(dir);
    assert!(gate
        .reset(false, || true, || panic!("unsafe state must not verify"))
        .is_err());
    assert!(gate
        .reset(true, || true, || panic!("unsafe state must not verify"))
        .is_err());
    assert_eq!(f.face().strikes, 4);
}

#[test]
fn recovery_cooldown_rearms_after_reboot_without_replenishing_attempts() {
    let f = Fixture::new();
    let gate = f.open();
    for _ in 0..5 {
        assert!(gate.reset(false, || true, || Err("wrong")).is_err());
    }
    let dir = gate.store.lock().unwrap();
    let mut record = gate.read(&dir).unwrap();
    record.cooldown.as_mut().unwrap().boot_id = "00000000-0000-0000-0000-000000000002".into();
    gate.commit(&dir, &record).unwrap();
    drop(dir);
    let status = gate.status().unwrap();
    assert_eq!(status.recovery_failures, 5);
    assert_eq!(status.recovery_cooldown_seconds, 30);
    assert!(gate
        .reset(
            false,
            || true,
            || panic!("reboot must not permit immediate guessing")
        )
        .is_err());
}

fn fail_reservation(_: &Path, _: &[u8], _: u32) -> io::Result<AtomicWrite> {
    Err(io::Error::other("reservation write failed"))
}
#[test]
fn failed_durable_reservation_never_invokes_password_verifier() {
    let f = Fixture::new();
    f.plant_face();
    let gate = Recovery::begin(f.store(), f.identity(), now, fail_reservation).unwrap();
    assert!(gate
        .reset(
            false,
            || true,
            || panic!("unreserved guessing must not run")
        )
        .is_err());
    assert_eq!(f.face().strikes, 4);
    assert_eq!(gate.status().unwrap().recovery_failures, 0);
}

fn fail_cleared_recovery(path: &Path, bytes: &[u8], mode: u32) -> io::Result<AtomicWrite> {
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    if path.file_name().unwrap() == "1234.reset.json" && value["failures"] == 0 {
        return Err(io::Error::other("recovery reset failed"));
    }
    write_atomic_reporting(path, bytes, mode)
}
#[test]
fn torn_verified_reset_reports_uncertainty_and_retains_password_charge() {
    let f = Fixture::new();
    f.plant_face();
    let gate = Recovery::begin(f.store(), f.identity(), now, fail_cleared_recovery).unwrap();
    assert_eq!(gate.reset(false, || true, || Ok(())), Err(UNCONFIRMED));
    assert_eq!(f.face().strikes, 0);
    assert_eq!(gate.status().unwrap().recovery_failures, 1);
}

// A duplicate models the shared open file description inherited across fork.
// These tests never wait for another process to exec or hide contention in a retry.
#[test]
fn operation_owner_drop_releases_lock_while_duplicate_remains_open() {
    let f = Fixture::new();
    let operation = f.store().operation(&f.identity()).unwrap();
    let duplicate = operation.try_clone().unwrap();
    assert_eq!(
        f.store().operation(&f.identity()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(operation);
    let next = f
        .store()
        .operation(&f.identity())
        .expect("owner drop must unlock despite duplicate");
    // Closing an old, released description cannot unlock a new operation owner.
    drop(duplicate);
    assert_eq!(
        f.store().operation(&f.identity()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(next);
    assert!(f.store().operation(&f.identity()).is_ok());
}

#[test]
fn directory_owner_drop_and_unwind_release_lock_with_duplicate() {
    for unwind in [false, true] {
        let f = Fixture::new();
        let dir = f.store().lock().unwrap();
        let duplicate = dir.try_clone().unwrap();
        let contender = File::open(f.0.join("retry")).unwrap();
        // SAFETY: contender owns a valid, independently opened directory fd.
        let blocked = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(blocked, -1);
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        if unwind {
            assert!(std::panic::catch_unwind(move || {
                let _dir = dir;
                panic!("synthetic directory-owner unwind");
            })
            .is_err());
        } else {
            drop(dir);
        }
        // Nonblocking: a regression fails immediately instead of deadlocking.
        // SAFETY: contender still owns the same live descriptor.
        let acquired = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(acquired, 0, "directory owner did not release its flock");
        drop(duplicate);
    }
}

#[test]
fn recovery_owner_unwind_releases_lock_but_keeps_durable_charge_with_duplicate() {
    let f = Fixture::new();
    f.plant_face();
    let gate = f.open();
    let duplicate = gate._operation.try_clone().unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ = gate.reset(false, || true, || panic!("synthetic interrupted verifier"));
        }))
        .is_err()
    );
    let reopened = f.open();
    assert_eq!(reopened.status().unwrap().recovery_failures, 1);
    assert_eq!(f.face().strikes, 4);
    drop(duplicate);
}

#[test]
fn forked_child_dropping_operation_cannot_unlock_active_parent() {
    let f = Fixture::new();
    let operation = f.store().operation(&f.identity()).unwrap();
    let contender = File::open(f.0.join("retry/1234.operation")).unwrap();
    // SAFETY: after fork the child only drops the File/PID lock guard and calls
    // leaf libc syscalls; it never allocates, locks Rust state or unwinds, and
    // _exit skips inherited test/fixture destructors. The parent always reaps it.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", io::Error::last_os_error());
    if child == 0 {
        drop(operation);
        // SAFETY: inherited contender is live; flock is a nonblocking Linux
        // syscall and errno is thread-local. _exit does not run Rust destructors.
        unsafe {
            let result = libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB);
            let blocked = result == -1 && *libc::__errno_location() == libc::EWOULDBLOCK;
            libc::_exit(if blocked { 0 } else { 1 });
        }
    }
    let mut status = 0;
    loop {
        // SAFETY: status is writable, and child is the pid returned above.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        assert_eq!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::Interrupted
        );
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "child released the parent's live lock"
    );
    assert_eq!(
        f.store().operation(&f.identity()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(operation);
    assert!(f.store().operation(&f.identity()).is_ok());
}
