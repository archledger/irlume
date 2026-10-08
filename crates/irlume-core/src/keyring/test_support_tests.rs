// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::test_support::UnsealObserver;
use super::{envelope_path, unseal_password, unseal_secret};
use irlume_common::Error;
use std::ffi::OsString;
use std::path::PathBuf;

struct Sandbox {
    dir: PathBuf,
    previous: Option<OsString>,
}

impl Sandbox {
    // The caller holds ENV_LOCK through this guard and any joined threads.
    fn new(tag: &str) -> Self {
        let dir = PathBuf::from(crate::test_tmp_dir(tag));
        std::fs::create_dir(&dir).expect("create private keyring test directory");
        let previous = std::env::var_os("IRLUME_KEYRING_DIR");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        Self { dir, previous }
    }

    fn plant_malformed_envelope(&self) {
        std::fs::write(envelope_path("observer-user"), b"not a sealed envelope")
            .expect("write sandbox envelope");
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(previous) => std::env::set_var("IRLUME_KEYRING_DIR", previous),
            None => std::env::remove_var("IRLUME_KEYRING_DIR"),
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn observer_counts_real_failed_entries_without_changing_the_envelope() {
    let _env = crate::testenv::ENV_LOCK.lock().expect("env lock");
    let _no_tpm = crate::testenv::NoTpm::set();
    let sandbox = Sandbox::new("kr-observer-failure");
    let observer = UnsealObserver::install().expect("install observer");
    assert_eq!((observer.calls(), observer.successes()), (0, 0));

    assert!(matches!(
        unseal_secret("observer-user"),
        Err(Error::Policy(_))
    ));
    assert_eq!((observer.calls(), observer.successes()), (1, 0));

    sandbox.plant_malformed_envelope();
    let before = std::fs::read(envelope_path("observer-user")).unwrap();
    assert!(unseal_secret("observer-user").is_err());
    assert_eq!((observer.calls(), observer.successes()), (2, 0));
    // The convenience API delegates once to the same observed entry.
    assert!(unseal_password("observer-user").is_err());
    assert_eq!((observer.calls(), observer.successes()), (3, 0));
    assert_eq!(
        std::fs::read(envelope_path("observer-user")).unwrap(),
        before
    );
}

#[test]
fn observer_rejects_nested_install_and_starts_fresh_after_drop() {
    let _env = crate::testenv::ENV_LOCK.lock().expect("env lock");
    let _no_tpm = crate::testenv::NoTpm::set();
    let sandbox = Sandbox::new("kr-observer-drop");
    sandbox.plant_malformed_envelope();
    // Calls made without an observer must not leak into a later installation.
    assert!(unseal_secret("observer-user").is_err());
    let first = UnsealObserver::install().expect("first observer");
    assert_eq!((first.calls(), first.successes()), (0, 0));
    assert!(matches!(UnsealObserver::install(), Err(Error::Policy(_))));
    assert!(unseal_secret("observer-user").is_err());
    assert_eq!((first.calls(), first.successes()), (1, 0));
    drop(first);

    assert!(unseal_secret("observer-user").is_err());
    let second = UnsealObserver::install().expect("observer after drop");
    assert_eq!((second.calls(), second.successes()), (0, 0));
    assert!(unseal_secret("observer-user").is_err());
    assert_eq!((second.calls(), second.successes()), (1, 0));
}

#[test]
fn observer_is_not_inherited_and_each_thread_counts_its_own_calls() {
    let _env = crate::testenv::ENV_LOCK.lock().expect("env lock");
    let _no_tpm = crate::testenv::NoTpm::set();
    let sandbox = Sandbox::new("kr-observer-thread");
    sandbox.plant_malformed_envelope();
    let parent = UnsealObserver::install().expect("parent observer");
    assert!(unseal_secret("observer-user").is_err());

    let child_counts = std::thread::spawn(|| {
        assert!(unseal_secret("observer-user").is_err());
        let child = UnsealObserver::install().expect("independent child observer");
        assert_eq!((child.calls(), child.successes()), (0, 0));
        assert!(unseal_secret("observer-user").is_err());
        assert!(unseal_secret("observer-user").is_err());
        (child.calls(), child.successes())
    })
    .join()
    .expect("join observed thread");
    assert_eq!(child_counts, (2, 0));
    assert_eq!((parent.calls(), parent.successes()), (1, 0));
    assert!(unseal_secret("observer-user").is_err());
    assert_eq!((parent.calls(), parent.successes()), (2, 0));
}

#[test]
fn observer_unwind_removes_the_installation() {
    let result = std::panic::catch_unwind(|| {
        let _observer = UnsealObserver::install().expect("observer before unwind");
        panic!("exercise observer cleanup");
    });
    assert!(result.is_err());
    let observer = UnsealObserver::install().expect("observer after unwind");
    assert_eq!((observer.calls(), observer.successes()), (0, 0));
}
