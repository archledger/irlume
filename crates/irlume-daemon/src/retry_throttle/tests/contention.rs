// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

const BUSY_REASON: &str = "face retry state is busy; use your password or try again later";

struct StateOverride(Option<std::ffi::OsString>);

impl StateOverride {
    // Every caller holds the process environment write guard through Drop.
    fn new(parent: &Path) -> Self {
        let previous = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", parent);
        Self(previous)
    }
}

impl Drop for StateOverride {
    fn drop(&mut self) {
        match &self.0 {
            Some(previous) => std::env::set_var("IRLUME_STATE_DIR", previous),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
    }
}

fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn saved_account(fixture: &Fixture, account: &Account) -> Record {
    let directory = fixture.store.lock().unwrap();
    fixture.store.read(&directory, account).unwrap()
}

#[test]
fn same_account_public_entry_reports_transient_contention() {
    if crate::test_support::isolated(
        "retry_throttle::tests::contention::same_account_public_entry_reports_transient_contention",
    ) {
        return;
    }
    let _env = crate::tests::env_lock();
    let fixture = Fixture::new();
    let _state = StateOverride::new(&fixture.store.parent);
    let uid = own_uid();
    let owner = FaceAttempt::for_account(Some(uid)).expect("first request reserves");
    let account = owner.account.clone();
    let path = fixture
        .store
        .parent
        .join("retry")
        .join(format!("{uid}.json"));
    let before = std::fs::read(&path).unwrap();

    let reason = FaceAttempt::for_account(Some(uid))
        .err()
        .expect("the contending request must remain refused");

    assert!(
        std::fs::read(&path).unwrap() == before,
        "contention must not rewrite or charge the record"
    );
    assert_eq!(
        saved_account(&fixture, &account)
            .budget
            .unwrap()
            .unsuccessful_requests,
        1
    );
    let conflict = fixture
        .store
        .operation(&account)
        .err()
        .expect("the first request still owns the operation");
    assert_eq!(conflict.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        reason, BUSY_REASON,
        "healthy contention is not broken retry state"
    );
    assert!(!reason.contains("administrator"));

    match crate::retry_verify_refusal(reason) {
        crate::Response::AuthResult {
            granted,
            refused_by_policy,
            reason: returned,
            cause,
            ..
        } => {
            assert!(!granted && refused_by_policy);
            assert_eq!(returned, BUSY_REASON);
            assert_eq!(cause, Some(irlume_common::OutcomeCause::RetryThrottled));
        }
        _ => panic!("busy verification must keep the existing refusal shape"),
    }
    assert!(matches!(
        crate::retry_unseal_refusal(reason),
        crate::Response::Error(returned) if returned == BUSY_REASON
    ));
    drop(owner);
}

#[test]
fn public_reservation_release_keeps_charge_and_other_accounts_independent() {
    if crate::test_support::isolated(
        "retry_throttle::tests::contention::public_reservation_release_keeps_charge_and_other_accounts_independent",
    ) {
        return;
    }
    let _env = crate::tests::env_lock();
    let fixture = Fixture::new();
    let _state = StateOverride::new(&fixture.store.parent);
    let uid = own_uid();
    let owner = FaceAttempt::for_account(Some(uid)).unwrap();
    let account = owner.account.clone();
    let other = FaceAttempt::begin(
        Store {
            parent: fixture.store.parent.clone(),
            owner: fixture.store.owner,
        },
        Account {
            uid: if uid == 1001 { 1002 } else { 1001 },
            name: "synthetic-other".into(),
        },
        POLICY,
        now,
        write_atomic_reporting,
    )
    .unwrap()
    .expect("a different account must not share the operation lock");
    drop(other);
    let conflict = fixture
        .store
        .operation(&account)
        .err()
        .expect("the first request still owns the operation");
    assert_eq!(conflict.kind(), io::ErrorKind::WouldBlock);

    drop(owner);

    assert!(fixture.store.operation(&account).is_ok());
    assert_eq!(
        saved_account(&fixture, &account)
            .budget
            .unwrap()
            .unsuccessful_requests,
        1,
        "release does not reset an unwritten grant"
    );
    let next = FaceAttempt::for_account(Some(uid)).expect("next request after release");
    assert_eq!(
        saved_account(&fixture, &account)
            .budget
            .unwrap()
            .unsuccessful_requests,
        2
    );
    drop(next);
}

#[test]
fn public_reservation_keeps_unsafe_state_unavailable_and_budget_limited() {
    if crate::test_support::isolated(
        "retry_throttle::tests::contention::public_reservation_keeps_unsafe_state_unavailable_and_budget_limited",
    ) {
        return;
    }
    let _env = crate::tests::env_lock();
    let fixture = Fixture::new();
    let _state = StateOverride::new(&fixture.store.parent);
    assert_eq!(FaceAttempt::for_account(None).err(), Some(UNAVAILABLE));
    let uid = own_uid();
    let attempt = FaceAttempt::for_account(Some(uid)).unwrap();
    let account = attempt.account.clone();
    drop(attempt);
    let path = fixture
        .store
        .parent
        .join("retry")
        .join(format!("{uid}.json"));
    let directory = fixture.store.lock().unwrap();
    let mut record = fixture.store.read(&directory, &account).unwrap();
    let budget = record.budget.as_mut().unwrap();
    budget.unsuccessful_requests = FACE_LIMIT;
    budget.pending = false;
    fixture
        .store
        .commit(&directory, &record, write_atomic_reporting)
        .unwrap();
    drop(directory);
    let before = std::fs::read(&path).unwrap();
    assert_eq!(FaceAttempt::for_account(Some(uid)).err(), Some(LIMITED));
    assert!(
        std::fs::read(&path).unwrap() == before,
        "a limited request must not add or erase history"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(FaceAttempt::for_account(Some(uid)).err(), Some(UNAVAILABLE));
    assert!(std::fs::read(&path).unwrap() == before);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    write_atomic_reporting(&path, b"{", 0o600).unwrap();
    assert_eq!(FaceAttempt::for_account(Some(uid)).err(), Some(UNAVAILABLE));
    assert!(std::fs::read(&path).unwrap() == b"{");
    assert!(fixture.store.operation(&account).is_ok());
}
