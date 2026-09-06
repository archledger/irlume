// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use irlume_auth::OutcomeKind as Kind;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

const BOOT: &str = "00000000-0000-4000-8000-000000000001";
const NEXT_BOOT: &str = "00000000-0000-4000-8000-000000000002";
const POLICY: Policy = Policy {
    limit: 3,
    seconds: 30,
};

fn now() -> io::Result<Tick> {
    Ok(Tick {
        boot: BOOT.into(),
        nanos: 100 * NANOS,
    })
}
fn later() -> io::Result<Tick> {
    Ok(Tick {
        boot: BOOT.into(),
        nanos: 131 * NANOS,
    })
}
fn reboot() -> io::Result<Tick> {
    Ok(Tick {
        boot: NEXT_BOOT.into(),
        nanos: NANOS,
    })
}
fn bad_clock() -> io::Result<Tick> {
    Err(io::Error::other("synthetic clock failure"))
}
fn bad_boot() -> io::Result<Tick> {
    Ok(Tick {
        boot: "invalid".into(),
        nanos: 0,
    })
}
fn overflow() -> io::Result<Tick> {
    Ok(Tick {
        boot: BOOT.into(),
        nanos: u64::MAX,
    })
}
fn before_rename(_: &Path, _: &[u8], _: u32) -> io::Result<AtomicWrite> {
    Err(io::Error::other("synthetic pre-publication failure"))
}
fn after_rename(path: &Path, bytes: &[u8], mode: u32) -> io::Result<AtomicWrite> {
    // Real atomic publication, then inject the writer's uncertain-durability
    // result at its boundary. This tests caller semantics, not kernel fsync faults.
    write_atomic_reporting(path, bytes, mode)?;
    Ok(AtomicWrite::VisibleNotDurable(io::Error::other(
        "synthetic fsync failure",
    )))
}

fn outcome(kind: Kind) -> irlume_auth::Outcome {
    let live = matches!(kind, Kind::Granted | Kind::BelowThreshold);
    irlume_auth::Outcome {
        granted: kind == Kind::Granted,
        live,
        score: if live { 0.5 } else { 0.0 },
        reason: "synthetic outcome; classify by type".into(),
        kind,
    }
}
fn account_one() -> Account {
    Account {
        uid: 1001,
        name: "synthetic-one".into(),
    }
}

struct Fixture {
    store: Store,
}
impl Fixture {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().join(format!(
            "irlume-retry-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        Self {
            store: Store {
                parent,
                // SAFETY: geteuid has no preconditions.
                owner: unsafe { libc::geteuid() },
            },
        }
    }
    fn path(&self) -> PathBuf {
        self.store.parent.join("retry/1001.json")
    }
    fn check(&self) -> bool {
        self.store
            .check(&account_one(), POLICY, now, write_atomic_reporting)
            .unwrap()
    }
    fn record(&self, kind: Kind) {
        self.store
            .record(
                &account_one(),
                POLICY,
                &outcome(kind),
                now,
                write_atomic_reporting,
            )
            .unwrap();
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.path()).unwrap()
    }
    fn saved(&self) -> Record {
        serde_json::from_slice(&self.bytes()).unwrap()
    }
    fn plant(&self, bytes: &[u8]) {
        let dir = self.store.lock().unwrap();
        write_atomic_reporting(&Store::path(&dir, &account_one()), bytes, 0o600).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.store.parent).unwrap();
    }
}

// Migrated original consent-throttle regressions: the real persistent store now
// replaces direct inspection/deletion of a process-local map.
#[test]
fn rate_throttle_outcome_classes_preserve_rejection_policy() {
    for (kind, limited) in [
        (Kind::Granted, false),
        (Kind::NoFace, false),
        (Kind::Uncertain, false),
        (Kind::SpoofNoIrFace, false),
        (Kind::GestureDeclined, false),
        (Kind::Spoof, true),
        (Kind::BelowThreshold, true),
        (Kind::OtherDeny, true),
    ] {
        let f = Fixture::new();
        let policy = Policy { limit: 1, ..POLICY };
        f.store
            .record(
                &account_one(),
                policy,
                &outcome(kind),
                now,
                write_atomic_reporting,
            )
            .unwrap();
        assert_eq!(
            f.store
                .check(&account_one(), policy, now, write_atomic_reporting)
                .unwrap(),
            limited,
            "{kind:?}"
        );
        if matches!(
            kind,
            Kind::NoFace | Kind::Uncertain | Kind::SpoofNoIrFace | Kind::GestureDeclined
        ) {
            assert!(
                !f.path().exists(),
                "ignored outcomes must not create records"
            );
        }
    }
}

#[test]
fn rate_throttle_cancellation_preserves_an_active_cooldown() {
    let f = Fixture::new();
    for _ in 0..3 {
        f.record(Kind::Spoof);
    }
    let before = f.bytes();
    assert!(f.saved().cooldown.is_some());
    f.record(Kind::GestureDeclined);
    assert!(f.check());
    assert_eq!(
        f.bytes(),
        before,
        "cancellation must neither extend nor clear cooldown"
    );
}

#[test]
fn rate_throttle_cancellation_does_not_add_or_clear_failures() {
    for live in [false, true] {
        let f = Fixture::new();
        f.record(Kind::BelowThreshold);
        f.record(Kind::BelowThreshold);
        let before = f.bytes();
        let decline = irlume_auth::Outcome {
            live,
            score: if live { 0.9 } else { 0.0 },
            ..outcome(Kind::GestureDeclined)
        };
        for _ in 0..6 {
            f.store
                .record(
                    &account_one(),
                    POLICY,
                    &decline,
                    now,
                    write_atomic_reporting,
                )
                .unwrap();
            assert!(!f.check());
            assert_eq!(f.bytes(), before);
        }
        f.record(Kind::BelowThreshold);
        assert!(f.check(), "cancellation must not clear prior strikes");
    }
}

#[test]
fn rate_throttle_trips_after_the_limit_and_resets_on_grant() {
    let f = Fixture::new();
    assert!(!f.check());
    f.record(Kind::Spoof);
    f.record(Kind::Spoof);
    assert!(!f.check());
    f.record(Kind::Spoof);
    assert!(f.check());
    f.record(Kind::Granted);
    assert!(!f.check());
    let absent = Fixture::new();
    for _ in 0..10 {
        absent.record(Kind::NoFace);
    }
    assert!(!absent.check());
    assert!(!absent.path().exists());
    f.record(Kind::Spoof);
    let before = f.bytes();
    let disabled = Policy { limit: 0, ..POLICY };
    for _ in 0..20 {
        f.store
            .record(
                &account_one(),
                disabled,
                &outcome(Kind::Spoof),
                bad_clock,
                before_rename,
            )
            .unwrap();
    }
    f.store
        .record(
            &account_one(),
            disabled,
            &outcome(Kind::Granted),
            bad_clock,
            before_rename,
        )
        .unwrap();
    assert!(!f
        .store
        .check(&account_one(), disabled, bad_clock, before_rename)
        .unwrap());
    assert_eq!(f.bytes(), before, "disable must retain history");
}

#[test]
fn rate_throttle_restart_preserves_recorded_cooldown() {
    let f = Fixture::new();
    f.record(Kind::Spoof);
    f.record(Kind::Spoof);
    let reopened = Store {
        parent: f.store.parent.clone(),
        owner: f.store.owner,
    };
    assert!(!reopened
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .unwrap());
    reopened
        .record(
            &account_one(),
            POLICY,
            &outcome(Kind::Spoof),
            now,
            write_atomic_reporting,
        )
        .unwrap();
    let before = f.bytes();
    drop(reopened);
    let restarted = Store {
        parent: f.store.parent.clone(),
        owner: f.store.owner,
    };
    assert!(restarted
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .unwrap());
    assert_eq!(
        f.bytes(),
        before,
        "same-boot reopen must not extend cooldown"
    );
}

#[test]
fn expiry_and_boot_change_are_durable_and_conservative() {
    let f = Fixture::new();
    f.record(Kind::Spoof);
    assert!(!f
        .store
        .check(&account_one(), POLICY, reboot, write_atomic_reporting)
        .unwrap());
    assert_eq!(f.saved().strikes, 1, "partial failures survive reboot");
    f.record(Kind::Spoof);
    f.record(Kind::Spoof);
    assert!(f
        .store
        .check(&account_one(), POLICY, reboot, write_atomic_reporting)
        .unwrap());
    let c = f.saved().cooldown.unwrap();
    assert_eq!(c.boot_id, NEXT_BOOT);
    assert_eq!(c.deadline_nanos, 31 * NANOS);
    assert_eq!(c.duration_nanos, 30 * NANOS);
    // Reboot re-arm must retain the original duration after a config change.
    assert!(f
        .store
        .check(
            &account_one(),
            Policy {
                seconds: 0,
                ..POLICY
            },
            reboot,
            write_atomic_reporting
        )
        .unwrap());
    assert_eq!(f.saved().cooldown.unwrap(), c);
    let f = Fixture::new();
    for _ in 0..3 {
        f.record(Kind::Spoof);
    }
    assert!(f
        .store
        .check(&account_one(), POLICY, later, before_rename)
        .is_err());
    assert!(
        f.saved().cooldown.is_some(),
        "failed expiry must not publish a reset"
    );
    assert!(!f
        .store
        .check(&account_one(), POLICY, later, write_atomic_reporting)
        .unwrap());
    assert!(f.saved().cooldown.is_none());
    assert_eq!(f.saved().strikes, 0);
}

#[test]
fn lowered_threshold_does_not_replenish_and_accounts_are_independent() {
    let f = Fixture::new();
    f.record(Kind::Spoof);
    f.record(Kind::Spoof);
    let other = Account {
        uid: 1002,
        name: "synthetic-two".into(),
    };
    assert!(!f
        .store
        .check(&other, POLICY, now, write_atomic_reporting)
        .unwrap());
    assert!(f
        .store
        .check(
            &account_one(),
            Policy { limit: 1, ..POLICY },
            now,
            write_atomic_reporting
        )
        .unwrap());
    assert!(!f
        .store
        .check(&other, POLICY, now, write_atomic_reporting)
        .unwrap());
    // Service/profile are deliberately not inputs: all paths key by account UID.
    let renamed = Account {
        name: "new-owner-of-uid".into(),
        ..account_one()
    };
    assert!(f
        .store
        .check(&renamed, POLICY, now, write_atomic_reporting)
        .is_err());
    assert!(f
        .store
        .record(
            &renamed,
            POLICY,
            &outcome(Kind::Granted),
            now,
            write_atomic_reporting
        )
        .is_err());
}

#[test]
fn invalid_records_never_become_empty_history() {
    let f = Fixture::new();
    f.record(Kind::Spoof);
    let valid = String::from_utf8(f.bytes()).unwrap();
    for bad in [
        "{".into(),
        "[]".into(),
        " ".repeat(4097),
        valid.replace("\"version\":1", "\"version\":2"),
        valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
        valid.replace("\"strikes\":1", "\"strikes\":1,\"unknown\":0"),
        valid.replace("\"uid\":1001", "\"uid\":1002"),
        valid.replace("synthetic-one", "different-user"),
        valid.replace("\"strikes\":1", "\"strikes\":-1"),
        valid.replace("\"strikes\":1", "\"strikes\":4294967296"),
    ] {
        f.plant(bad.as_bytes());
        assert!(
            f.store
                .check(&account_one(), POLICY, now, write_atomic_reporting)
                .is_err(),
            "{bad:.80}"
        );
        assert!(f
            .store
            .record(
                &account_one(),
                POLICY,
                &outcome(Kind::Granted),
                now,
                write_atomic_reporting
            )
            .is_err());
        assert_eq!(f.bytes(), bad.as_bytes());
    }
    f.plant(valid.as_bytes());
    assert!(!f.check(), "repaired state must be re-read");
}

#[test]
fn file_and_directory_trust_checks_reject_unsafe_state() {
    let f = Fixture::new();
    f.record(Kind::Spoof);
    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f
        .store
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let wrong_owner = Store {
        parent: f.store.parent.clone(),
        owner: f.store.owner.wrapping_add(1),
    };
    assert!(wrong_owner
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
    let target = f.store.parent.join("target");
    std::fs::rename(f.path(), &target).unwrap();
    symlink(&target, f.path()).unwrap();
    assert!(f
        .store
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
    assert!(f
        .store
        .record(
            &account_one(),
            POLICY,
            &outcome(Kind::Granted),
            now,
            write_atomic_reporting
        )
        .is_err());
    std::fs::remove_file(f.path()).unwrap();
    std::fs::hard_link(&target, f.path()).unwrap();
    assert!(f
        .store
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
    std::fs::remove_file(f.path()).unwrap();
    std::fs::create_dir(f.path()).unwrap();
    assert!(f
        .store
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
    std::fs::remove_dir(f.path()).unwrap();
    std::fs::set_permissions(
        f.store.parent.join("retry"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(f
        .store
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
    std::fs::remove_dir(f.store.parent.join("retry")).unwrap();
    symlink(&f.store.parent, f.store.parent.join("retry")).unwrap();
    assert!(f
        .store
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
}

#[test]
fn clocks_and_duration_overflow_fail_without_writing() {
    let f = Fixture::new();
    for clock in [bad_clock as Clock, bad_boot] {
        assert!(f
            .store
            .check(&account_one(), POLICY, clock, write_atomic_reporting)
            .is_err());
        assert!(f
            .store
            .record(
                &account_one(),
                POLICY,
                &outcome(Kind::Granted),
                clock,
                write_atomic_reporting
            )
            .is_err());
        assert!(!f.path().exists());
    }
    let threshold = Policy { limit: 1, ..POLICY };
    assert!(f
        .store
        .record(
            &account_one(),
            threshold,
            &outcome(Kind::Spoof),
            overflow,
            write_atomic_reporting
        )
        .is_err());
    assert!(f
        .store
        .record(
            &account_one(),
            Policy {
                limit: 1,
                seconds: u64::MAX
            },
            &outcome(Kind::Spoof),
            now,
            write_atomic_reporting
        )
        .is_err());
    assert!(!f.path().exists());
    for _ in 0..3 {
        f.record(Kind::Spoof);
    }
    let mut record = f.saved();
    record.cooldown.as_mut().unwrap().deadline_nanos = 200 * NANOS;
    f.plant(&serde_json::to_vec(&record).unwrap());
    assert!(f
        .store
        .check(&account_one(), POLICY, now, write_atomic_reporting)
        .is_err());
}

#[test]
fn publication_failure_preserves_the_actual_visible_state() {
    for writer in [before_rename as Writer, after_rename] {
        let f = Fixture::new();
        f.record(Kind::Spoof);
        assert!(f
            .store
            .record(&account_one(), POLICY, &outcome(Kind::Spoof), now, writer)
            .is_err());
        let expected = if std::ptr::fn_addr_eq(writer, before_rename as Writer) {
            1
        } else {
            2
        };
        assert_eq!(f.saved().strikes, expected);
        // The next operation re-reads and fsyncs the visible file, never a cache.
        assert!(!f.check());
        assert_eq!(f.saved().strikes, expected);
    }
}

#[test]
fn both_completion_paths_refuse_before_grant_or_secret_release_on_failed_commit() {
    for refuse in [
        crate::retry_verify_refusal as fn(&str) -> irlume_common::Response,
        crate::retry_unseal_refusal,
    ] {
        for writer in [before_rename as Writer, after_rename] {
            let f = Fixture::new();
            f.record(Kind::Spoof);
            let released = std::cell::Cell::new(false);
            let response = crate::recorded_face_response(
                || {
                    f.store
                        .record(&account_one(), POLICY, &outcome(Kind::Granted), now, writer)
                        .map_err(|_| UNAVAILABLE)
                },
                refuse,
                || {
                    released.set(true);
                    irlume_common::Response::Ok("synthetic completion".into())
                },
            );
            assert!(
                !released.get(),
                "no grant or password release after failed commit"
            );
            match response {
                irlume_common::Response::AuthResult {
                    granted,
                    declined_by_gesture,
                    refused_by_policy,
                    reason,
                    ..
                } => {
                    assert!(!granted);
                    assert!(!declined_by_gesture);
                    assert!(refused_by_policy);
                    assert_eq!(reason, UNAVAILABLE);
                }
                irlume_common::Response::Error(reason) => assert_eq!(reason, UNAVAILABLE),
                other => panic!("unexpected response {other:?}"),
            }
            // A successful commit permits the continuation and resets history.
            let response = crate::recorded_face_response(
                || {
                    f.store
                        .record(
                            &account_one(),
                            POLICY,
                            &outcome(Kind::Granted),
                            now,
                            write_atomic_reporting,
                        )
                        .map_err(|_| UNAVAILABLE)
                },
                refuse,
                || {
                    released.set(true);
                    irlume_common::Response::Ok("synthetic completion".into())
                },
            );
            assert!(matches!(response, irlume_common::Response::Ok(_)));
            assert!(released.get());
            assert_eq!(f.saved().strikes, 0);
        }
    }
}

#[test]
fn independent_process_reads_the_same_deadline() {
    const CHILD: &str = "IRLUME_RETRY_TEST_CHILD";
    let _guard = crate::test_support::env_read();
    if let Some(parent) = std::env::var_os(CHILD) {
        let store = Store {
            parent: parent.into(),
            // SAFETY: geteuid has no preconditions.
            owner: unsafe { libc::geteuid() },
        };
        assert!(store
            .check(&account_one(), POLICY, now, write_atomic_reporting)
            .unwrap());
        return;
    }
    let f = Fixture::new();
    for _ in 0..3 {
        f.record(Kind::Spoof);
    }
    let bytes = f.bytes();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("retry_throttle::tests::independent_process_reads_the_same_deadline")
        .arg("--exact")
        .env(CHILD, &f.store.parent)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(f.bytes(), bytes);
}

#[test]
fn explicit_linux_clock_has_valid_boot_and_monotonic_order() {
    let a = linux_clock().unwrap();
    let b = linux_clock().unwrap();
    assert!(valid_boot(&a.boot));
    assert_eq!(a.boot, b.boot);
    assert!(b.nanos >= a.nanos);
}

#[test]
fn concurrent_writers_do_not_lose_recorded_failures() {
    let f = Fixture::new();
    std::thread::scope(|scope| {
        for _ in 0..12 {
            let store = &f.store;
            scope.spawn(move || {
                store
                    .record(
                        &account_one(),
                        Policy {
                            limit: 100,
                            ..POLICY
                        },
                        &outcome(Kind::Spoof),
                        now,
                        write_atomic_reporting,
                    )
                    .unwrap()
            });
        }
    });
    assert_eq!(f.saved().strikes, 12);
}

#[test]
fn record_owner_and_nested_cooldown_schema_are_checked() {
    let f = Fixture::new();
    for _ in 0..3 {
        f.record(Kind::Spoof);
    }
    let dir = f.store.lock().unwrap();
    let wrong = Store {
        parent: f.store.parent.clone(),
        owner: f.store.owner.wrapping_add(1),
    };
    assert!(wrong.read(&dir, &account_one()).is_err());
    drop(dir);
    let valid = String::from_utf8(f.bytes()).unwrap();
    for bad in [
        valid.replace(
            "\"duration_nanos\":30000000000",
            "\"duration_nanos\":30000000000,\"extra\":1",
        ),
        valid.replace(
            "\"duration_nanos\":30000000000",
            "\"duration_nanos\":1,\"duration_nanos\":2",
        ),
        valid.replace(BOOT, "bad-boot"),
        valid.replace("\"strikes\":0", "\"strikes\":1"),
    ] {
        assert_ne!(bad, valid);
        f.plant(bad.as_bytes());
        assert!(f
            .store
            .check(&account_one(), POLICY, now, write_atomic_reporting)
            .is_err());
    }
}
