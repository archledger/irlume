// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Observation-only counters for the current thread's real secret releases.
//! No envelope, secret, result or callback can be supplied through this module.

use irlume_common::{Error, Result};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[derive(Debug, Default)]
struct Counts {
    calls: Cell<usize>,
    successes: Cell<usize>,
}

thread_local! {
    static OBSERVER: RefCell<Option<Rc<Counts>>> = const { RefCell::new(None) };
}

/// Counts [`super::unseal_secret`] entries and successful returns until dropped.
/// Install on the thread that executes the call; other threads are independent.
/// This guard is neither `Send` nor `Sync`, and dropping it removes only its
/// own installation. Counters saturate at `usize::MAX`.
///
/// ```compile_fail
/// use irlume_core::keyring::test_support::UnsealObserver;
/// fn require_send<T: Send>() {}
/// require_send::<UnsealObserver>();
/// ```
///
/// ```compile_fail
/// use irlume_core::keyring::test_support::UnsealObserver;
/// fn require_sync<T: Sync>() {}
/// require_sync::<UnsealObserver>();
/// ```
#[derive(Debug)]
#[must_use = "keep the observer alive through the real unseal call"]
pub struct UnsealObserver {
    counts: Rc<Counts>,
}

impl UnsealObserver {
    /// Install zeroed counters on this thread without changing secret release.
    ///
    /// # Errors
    /// Returns [`Error::Policy`] if an observer is already installed, or the
    /// thread-local slot is unavailable or borrowed. A rejected installation
    /// leaves the existing observer intact.
    pub fn install() -> Result<Self> {
        OBSERVER
            .try_with(|slot| {
                let mut slot = slot.try_borrow_mut().map_err(|_| {
                    Error::Policy("keyring unseal observer slot is borrowed".into())
                })?;
                if slot.is_some() {
                    return Err(Error::Policy(
                        "a keyring unseal observer is already installed on this thread".into(),
                    ));
                }
                let counts = Rc::new(Counts::default());
                *slot = Some(Rc::clone(&counts));
                Ok(Self { counts })
            })
            .map_err(|_| Error::Policy("keyring unseal observer slot is unavailable".into()))?
    }

    /// Number of real [`super::unseal_secret`] entries during this installation.
    pub fn calls(&self) -> usize {
        self.counts.calls.get()
    }

    /// Number of those entries that successfully returned a real unsealed secret.
    pub fn successes(&self) -> usize {
        self.counts.successes.get()
    }
}

impl Drop for UnsealObserver {
    fn drop(&mut self) {
        // Teardown must also work during unwinding or thread-local destruction.
        let _ = OBSERVER.try_with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                if slot
                    .as_ref()
                    .is_some_and(|counts| Rc::ptr_eq(counts, &self.counts))
                {
                    *slot = None;
                }
            }
        });
    }
}

pub(super) fn record_call() {
    let _ = OBSERVER.try_with(|slot| {
        if let Ok(slot) = slot.try_borrow() {
            if let Some(counts) = slot.as_ref() {
                counts.calls.set(counts.calls.get().saturating_add(1));
            }
        }
    });
}

pub(super) fn record_success() {
    let _ = OBSERVER.try_with(|slot| {
        if let Ok(slot) = slot.try_borrow() {
            if let Some(counts) = slot.as_ref() {
                counts
                    .successes
                    .set(counts.successes.get().saturating_add(1));
            }
        }
    });
}
