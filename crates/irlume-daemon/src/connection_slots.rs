// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Connection slots: how many connections the daemon serves at once, and
//! how many of them one account may hold.
//!
//! A connection takes a slot at accept and gives it back when its thread
//! ends. Three limits apply:
//!
//! * a pool of [`TOTAL`] slots, which bounds threads and memory;
//! * [`ROOT_RESERVED`] slots at the top of that pool that only uid 0 may take,
//!   because the privileged PAM stacks (greeters, `sudo`, polkit) run as root
//!   and must stay answerable whatever other accounts do;
//! * at most [`PER_ACCOUNT`] slots for any one non-root uid, so the
//!   `TOTAL - ROOT_RESERVED` slots every non-root account shares cannot all be
//!   held by one of them. A lock screen that runs PAM as its user (the KDE
//!   lock screen) is served from that shared pool.
//!
//! Root has no per-account limit. A peer whose credentials cannot be read
//! counts against the non-root pool only; its connection ends at once
//! anyway, because `serve_until` needs those credentials.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// Connection threads the daemon runs at once. Well above any real client:
/// the greeter, the lock screen, a TUI and `sudo` together are a handful.
pub(crate) const TOTAL: usize = 64;

/// Slots of [`TOTAL`] that only root may take.
pub(crate) const ROOT_RESERVED: usize = 16;

/// Slots one non-root uid may hold at once.
///
/// The TUI keeps at most eight requests open: one of each of its seven
/// background loads and one operation or enrollment, and a refresh opens
/// four at once. PAM holds one connection at a time, a CLI command one, and
/// the KDE settings module runs at most two `irlume` commands. Most of these
/// are status requests answered on their connection thread within
/// milliseconds, so what an account holds at once is mostly its long
/// requests: an operation, a queued profile listing, a PAM request. Twelve
/// covers all of them open at once (the TUI's eight, PAM, the settings
/// module's two, a CLI command), and four accounts at the cap still fit in
/// the shared pool. A connection over the cap is answered "daemon busy",
/// which PAM treats as any other daemon error: it goes on to the password.
pub(crate) const PER_ACCOUNT: usize = 12;

/// Why a connection got no slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Every slot this peer may take is in use.
    PoolFull,
    /// This non-root uid already holds [`PER_ACCOUNT`] slots.
    AccountFull,
}

impl Refusal {
    /// The `Response::Error` text the refused client reads.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Refusal::PoolFull => "daemon busy: too many open connections",
            Refusal::AccountFull => "daemon busy: too many open connections from this user",
        }
    }
}

#[derive(Default)]
struct Held {
    all: usize,
    by_uid: HashMap<u32, usize>,
}

/// The slot counters, shared by the accept loop and every connection thread.
pub(crate) struct ConnectionSlots {
    total: usize,
    root_reserved: usize,
    per_account: usize,
    held: Mutex<Held>,
}

impl ConnectionSlots {
    /// The daemon's limits: [`TOTAL`], [`ROOT_RESERVED`], [`PER_ACCOUNT`].
    pub(crate) fn new() -> Self {
        Self::with_limits(TOTAL, ROOT_RESERVED, PER_ACCOUNT)
    }

    /// Explicit limits, for tests that fill a pool without opening 64
    /// sockets.
    pub(crate) fn with_limits(total: usize, root_reserved: usize, per_account: usize) -> Self {
        Self {
            total,
            root_reserved: root_reserved.min(total),
            per_account,
            held: Mutex::new(Held::default()),
        }
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        // Nothing panics under this lock, and a slot count must still come
        // back down if something ever did.
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take a slot for a peer of `uid` (`None`: its credentials could not be
    /// read). The slot is given back when the returned value drops, on
    /// return and on unwind alike.
    pub(crate) fn take(self: &Arc<Self>, uid: Option<u32>) -> Result<Slot, Refusal> {
        let mut held = self.held();
        let ceiling = if uid == Some(0) {
            self.total
        } else {
            self.total - self.root_reserved
        };
        if held.all >= ceiling {
            return Err(Refusal::PoolFull);
        }
        let account = uid.filter(|&u| u != 0);
        if let Some(uid) = account {
            let n = held.by_uid.entry(uid).or_insert(0);
            if *n >= self.per_account {
                return Err(Refusal::AccountFull);
            }
            *n += 1;
        }
        held.all += 1;
        Ok(Slot {
            slots: Arc::clone(self),
            account,
        })
    }

    #[cfg(test)]
    fn in_use(&self) -> (usize, usize) {
        let held = self.held();
        (held.all, held.by_uid.len())
    }
}

/// One taken slot. Dropping it gives the slot back.
///
/// A connection thread that panics must give its slot back too: a trailing
/// decrement never ran when `serve` unwound, so 64 panics over the daemon's
/// lifetime once pinned the count at the ceiling, and every later accept,
/// root's included, answered "daemon busy" until a restart. `Drop` runs on
/// unwind and on return alike.
pub(crate) struct Slot {
    slots: Arc<ConnectionSlots>,
    account: Option<u32>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.slots.held();
        held.all = held.all.saturating_sub(1);
        if let Some(uid) = self.account {
            if let Some(n) = held.by_uid.get_mut(&uid) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    held.by_uid.remove(&uid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: u32 = 4_100_001;
    const BOB: u32 = 4_100_002;

    fn take_n(slots: &Arc<ConnectionSlots>, uid: Option<u32>, n: usize) -> Vec<Slot> {
        (0..n)
            .map(|i| {
                slots
                    .take(uid)
                    .unwrap_or_else(|r| panic!("slot {i} for {uid:?} refused: {r:?}"))
            })
            .collect()
    }

    #[test]
    fn one_account_is_capped_while_other_accounts_and_root_are_served() {
        let slots = Arc::new(ConnectionSlots::with_limits(16, 4, 3));
        let alice = take_n(&slots, Some(ALICE), 3);
        assert_eq!(
            slots.take(Some(ALICE)).err(),
            Some(Refusal::AccountFull),
            "a fourth connection from one account must be refused"
        );
        let bob = take_n(&slots, Some(BOB), 3);
        let root = take_n(&slots, Some(0), 5);
        assert_eq!(slots.in_use(), (11, 2));

        // A slot the account gives back is its own to take again.
        drop(alice);
        let _alice = take_n(&slots, Some(ALICE), 3);
        drop((bob, root));
        assert_eq!(slots.in_use(), (3, 1));
    }

    #[test]
    fn several_accounts_fill_the_shared_pool_and_root_keeps_its_slots() {
        let slots = Arc::new(ConnectionSlots::with_limits(10, 4, 2));
        let mut held = Vec::new();
        for uid in [ALICE, BOB, BOB + 1] {
            held.extend(take_n(&slots, Some(uid), 2));
        }
        assert_eq!(slots.take(Some(BOB + 2)).err(), Some(Refusal::PoolFull));
        // Unidentified peers count as non-root.
        assert_eq!(slots.take(None).err(), Some(Refusal::PoolFull));
        held.extend(take_n(&slots, Some(0), 4));
        assert_eq!(slots.take(Some(0)).err(), Some(Refusal::PoolFull));
    }

    #[test]
    fn root_and_unidentified_peers_carry_no_account_count() {
        let slots = Arc::new(ConnectionSlots::with_limits(10, 2, 1));
        let _root = take_n(&slots, Some(0), 5);
        let _unknown = take_n(&slots, None, 3);
        assert_eq!(slots.in_use(), (8, 0));
    }

    #[test]
    fn a_panicking_connection_thread_gives_its_slot_back() {
        let slots = Arc::new(ConnectionSlots::with_limits(4, 0, 1));
        let slot = slots.take(Some(ALICE)).unwrap();
        let joined = std::thread::spawn(move || {
            let _slot = slot;
            panic!("connection thread panics");
        })
        .join();
        assert!(joined.is_err());
        assert_eq!(slots.in_use(), (0, 0));
        drop(slots.take(Some(ALICE)).unwrap());
    }
}
