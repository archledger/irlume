// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The account a per-account record belongs to.
//!
//! Records are stored by account name (`<user>.json`). The enrollment, the
//! sealed template key, the keyring envelope and the recovery envelope also
//! record the numeric uid of the account they were written for. A loader
//! compares that uid with the account's current uid:
//!
//! - an enrollment (or its template key) recorded for another uid reads as
//!   absent, so irlume treats the account as not enrolled and asks for
//!   `irlume enroll`, which writes a new enrollment and key;
//! - a sealed secret or recovery envelope recorded for another uid is not
//!   released;
//! - a record without a uid (written by an earlier release) is accepted, and
//!   its next write records the uid;
//! - when the current uid cannot be resolved, a record that carries a uid is
//!   not used (an error, never a release).
//!
//! A write records the account's current uid. When the lookup fails, it keeps
//! the uid the record carries, and a record that carries none is not written.
//! A write never changes the uid a record carries: when the name now resolves
//! to another uid, or to no account, the write is refused and nothing is
//! written. An enrollment loaded and then saved carries the uid of the
//! account its load was for (the uid its records record, or else the uid the
//! name resolved to at the load), so the save is refused, not rebound, when
//! the account changed in between.
//!
//! Nothing here deletes a record: an explicit enrollment or arm for the
//! account replaces it, and an administrator can move it away.
//!
//! Resolving a name goes through NSS. When irlumed already knows the uid for
//! a request, it registers it with [`remember`] so the record checks and
//! writes of that request use it instead of asking NSS again: a non-root
//! caller passes the daemon's gate only as the account itself, so its own uid
//! is the account's, and an authentication request resolves the account for
//! its retry record.

use irlume_common::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// What NSS says about an account name now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The name resolves to this uid.
    Uid(u32),
    /// NSS answered, and no account has this name.
    NoAccount,
    /// The lookup failed, so the answer is unknown.
    Unknown,
}

/// The current uid of `user`: a uid registered with [`remember`] for this
/// name if one is held, else an NSS lookup.
#[must_use]
pub fn resolve(user: &str) -> Resolution {
    remembered(user).unwrap_or_else(|| lookup(user))
}

fn lookup(user: &str) -> Resolution {
    let Ok(name) = std::ffi::CString::new(user) else {
        // No account name contains a NUL byte.
        return Resolution::NoAccount;
    };
    let mut size = 4096usize;
    loop {
        let mut buf = vec![0 as libc::c_char; size];
        // SAFETY: an all-zero `passwd` is a valid value for this plain C
        // struct; getpwnam_r fills it in on success.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call, `buf` is owned here and
        // `size` bytes long, and `result` points into `pwd` on success.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && size < 1 << 20 {
            size *= 4;
            continue;
        }
        return match (rc, result.is_null()) {
            (0, false) => Resolution::Uid(pwd.pw_uid),
            // POSIX: no entry is a zero return with a null result. A nonzero
            // return may also mean "not found" for some NSS modules, but it
            // cannot be told apart from a failed lookup, so it is unknown.
            (0, true) => Resolution::NoAccount,
            _ => Resolution::Unknown,
        };
    }
}

struct Remembered {
    id: u64,
    user: String,
    resolution: Resolution,
}

static REMEMBERED: Mutex<Vec<Remembered>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn remembered_list() -> std::sync::MutexGuard<'static, Vec<Remembered>> {
    REMEMBERED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn remembered(user: &str) -> Option<Resolution> {
    remembered_list()
        .iter()
        .rev()
        .find(|entry| entry.user == user)
        .map(|entry| entry.resolution)
}

/// A uid a caller resolved for one account, reused by [`resolve`] (and so by
/// every record check) until this guard drops.
#[must_use = "the uid is forgotten when the guard drops"]
pub struct RememberedUid {
    id: u64,
}

/// Register `uid` as `user`'s current uid until the returned guard drops.
///
/// For a caller that already knows the account's uid for a request (irlumed:
/// the uid its gate established for a non-root caller, or the one it resolved
/// for the retry record), so the record checks and writes of that request use
/// it and do not ask NSS again. Loader threads the request starts see it too.
/// The latest registration for a name wins.
pub fn remember(user: &str, uid: u32) -> RememberedUid {
    remember_resolution(user, Resolution::Uid(uid))
}

/// [`remember`] any resolution: tests stand in a missing account or a failed
/// lookup with it.
pub(crate) fn remember_resolution(user: &str, resolution: Resolution) -> RememberedUid {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    remembered_list().push(Remembered {
        id,
        user: user.to_owned(),
        resolution,
    });
    RememberedUid { id }
}

impl Drop for RememberedUid {
    fn drop(&mut self) {
        remembered_list().retain(|entry| entry.id != self.id);
    }
}

/// Whether a record may be used for the account it is stored under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// The record carries no uid (an earlier release wrote it): accepted.
    Unrecorded,
    /// The record carries the account's current uid.
    Current,
    /// The record carries `recorded`, and the account now has `current`
    /// (`None`: no account has this name now). Not used.
    Other { recorded: u32, current: Option<u32> },
    /// The record carries `recorded`, and the account's current uid could
    /// not be resolved. Not used.
    Unknown { recorded: u32 },
}

impl Owner {
    /// Whether the record may be used.
    #[must_use]
    pub fn usable(self) -> bool {
        matches!(self, Owner::Unrecorded | Owner::Current)
    }

    fn of(recorded: Option<u32>, resolution: impl FnOnce() -> Resolution) -> Self {
        let Some(recorded) = recorded else {
            return Owner::Unrecorded;
        };
        match resolution() {
            Resolution::Uid(current) if current == recorded => Owner::Current,
            Resolution::Uid(current) => Owner::Other {
                recorded,
                current: Some(current),
            },
            Resolution::NoAccount => Owner::Other {
                recorded,
                current: None,
            },
            Resolution::Unknown => Owner::Unknown { recorded },
        }
    }
}

/// The kinds of record that carry a uid, for messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// The face enrollment (`<user>.json`).
    Enrollment,
    /// The sealed template key the enrollment is encrypted under.
    TemplateKey,
    /// The keyring envelope of a login password or KDE wallet key.
    SealedSecret,
    /// The keyring envelope of a GNOME keyring token.
    KeyringToken,
    /// The recovery envelope of the template key.
    Recovery,
}

impl Record {
    fn noun(self) -> &'static str {
        match self {
            Record::Enrollment => "face enrollment",
            Record::TemplateKey => "template key",
            Record::SealedSecret => "sealed secret",
            Record::KeyringToken => "keyring token",
            Record::Recovery => "recovery envelope",
        }
    }

    fn next_step(self) -> &'static str {
        match self {
            Record::Enrollment | Record::TemplateKey => "run `irlume enroll` to enroll again",
            Record::SealedSecret => "run `irlume keyring arm` to arm keyring unlock again",
            // A re-arm reuses an armed token, so this one has to go first.
            Record::KeyringToken => {
                "remove it with `irlume keyring forget --force`, then run `irlume keyring arm`"
            }
            Record::Recovery => {
                "run `irlume enroll` to enroll again, then `irlume recovery setup` to set a new \
                 recovery passphrase"
            }
        }
    }
}

/// The message for a record that is not used, or `None` when it is.
#[must_use]
pub fn refusal_message(user: &str, record: Record, owner: Owner) -> Option<String> {
    let noun = record.noun();
    match owner {
        Owner::Unrecorded | Owner::Current => None,
        Owner::Other {
            recorded,
            current: Some(current),
        } => Some(format!(
            "the {noun} stored for '{user}' was recorded for uid {recorded}, but '{user}' is now \
             uid {current}, so it is not used; {}",
            record.next_step()
        )),
        Owner::Other {
            recorded,
            current: None,
        } => Some(format!(
            "the {noun} stored for '{user}' was recorded for uid {recorded}, but no account \
             named '{user}' exists now, so it is not used"
        )),
        Owner::Unknown { recorded } => Some(format!(
            "the {noun} stored for '{user}' was recorded for uid {recorded}, but the current \
             uid of '{user}' could not be resolved, so it is not used"
        )),
    }
}

/// One operation's view of `user`: resolves the account at most once, and
/// remembers whether a record was turned away as another account's.
pub(crate) struct Account<'a> {
    user: &'a str,
    resolution: Option<Resolution>,
    /// The refusal of a record written for another uid, once one was met.
    other: Option<String>,
}

impl<'a> Account<'a> {
    pub(crate) fn new(user: &'a str) -> Self {
        Self {
            user,
            resolution: None,
            other: None,
        }
    }

    fn resolution(&mut self) -> Resolution {
        let user = self.user;
        *self.resolution.get_or_insert_with(|| resolve(user))
    }

    pub(crate) fn owner(&mut self, recorded: Option<u32>) -> Owner {
        Owner::of(recorded, || self.resolution())
    }

    /// `Ok` when a record carrying `recorded` may be used; otherwise the
    /// refusal as an error.
    pub(crate) fn require(&mut self, record: Record, recorded: Option<u32>) -> Result<()> {
        let owner = self.owner(recorded);
        let Some(message) = refusal_message(self.user, record, owner) else {
            return Ok(());
        };
        if matches!(owner, Owner::Other { .. }) {
            self.other = Some(message.clone());
        }
        Err(Error::Policy(message))
    }

    /// Whether this operation turned a record away because it was written
    /// for another uid (not because the uid could not be resolved).
    pub(crate) fn found_other(&self) -> bool {
        self.other.is_some()
    }

    /// The uid this operation resolves the account to, resolving it now if no
    /// record check has yet; `None` for a name no account has, or when the
    /// lookup failed. After a load that passed its checks this is the uid
    /// its records belong to: the one they record, or, for records that
    /// record none, the one the name resolved to when they were loaded.
    pub(crate) fn current_uid(&mut self) -> Option<u32> {
        match self.resolution() {
            Resolution::Uid(uid) => Some(uid),
            Resolution::NoAccount | Resolution::Unknown => None,
        }
    }

    /// The uid a write of `record` records. `existing` is the uid the record
    /// already belongs to (`None` for a new record, or one an earlier release
    /// wrote): a write keeps it, and otherwise records the account's current
    /// uid. For a name no account has, a record without a uid records none.
    /// When the lookup fails, `existing` if the record carries a uid.
    ///
    /// # Errors
    /// - The record belongs to a uid and the name now resolves to another
    ///   uid, or to no account: recording the current uid would hand the
    ///   record to another account, so the write is refused before anything
    ///   is written.
    /// - The lookup failed and the record carries no uid: writing it would
    ///   leave a record that any later account of this name accepts, so the
    ///   write is refused before anything is written.
    pub(crate) fn uid_to_record(
        &mut self,
        record: Record,
        existing: Option<u32>,
    ) -> Result<Option<u32>> {
        match (self.resolution(), existing) {
            (Resolution::Uid(uid), None) => Ok(Some(uid)),
            (Resolution::Uid(uid), Some(recorded)) if uid == recorded => Ok(existing),
            (Resolution::Uid(uid), Some(recorded)) => {
                Err(self.changed_owner(record, recorded, Some(uid)))
            }
            (Resolution::NoAccount, Some(recorded)) => {
                Err(self.changed_owner(record, recorded, None))
            }
            (Resolution::NoAccount, None) | (Resolution::Unknown, Some(_)) => Ok(existing),
            (Resolution::Unknown, None) => Err(Error::Policy(format!(
                "the current uid of '{}' could not be resolved, so the {} was not written; \
                 try again when the account resolves",
                self.user,
                record.noun()
            ))),
        }
    }

    /// The refusal of a write of a record that belongs to `recorded` while
    /// the name now resolves to `current` (`None`: no account).
    fn changed_owner(&self, record: Record, recorded: u32, current: Option<u32>) -> Error {
        let (user, noun) = (self.user, record.noun());
        Error::Policy(match current {
            Some(current) => format!(
                "the {noun} of '{user}' belongs to uid {recorded}, but '{user}' is now uid \
                 {current}, so nothing was written; {}",
                record.next_step()
            ),
            None => format!(
                "the {noun} of '{user}' belongs to uid {recorded}, but no account named \
                 '{user}' exists now, so nothing was written"
            ),
        })
    }

    /// `Ok(None)` in place of this operation's refusal of a record written
    /// for another uid, logged with the next step: the caller then treats the
    /// account as having no such record. Every other error passes through.
    pub(crate) fn absent_if_other<T>(&self, result: Result<T>) -> Result<Option<T>> {
        match (result, &self.other) {
            (Ok(value), _) => Ok(Some(value)),
            (Err(Error::Policy(message)), Some(other)) if message == *other => {
                irlume_common::jout_notice!("irlume: {message}");
                Ok(None)
            }
            (Err(error), _) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_SUCH_USER: &str = "irlume-test-no-such-account";

    #[test]
    fn a_record_without_a_uid_is_accepted_without_a_lookup() {
        let owner = Owner::of(None, || panic!("no lookup for a record without a uid"));
        assert_eq!(owner, Owner::Unrecorded);
        assert!(owner.usable());
    }

    #[test]
    fn owner_compares_the_recorded_uid_with_the_resolution() {
        assert_eq!(
            Owner::of(Some(1001), || Resolution::Uid(1001)),
            Owner::Current
        );
        assert_eq!(
            Owner::of(Some(1001), || Resolution::Uid(1002)),
            Owner::Other {
                recorded: 1001,
                current: Some(1002)
            }
        );
        assert_eq!(
            Owner::of(Some(1001), || Resolution::NoAccount),
            Owner::Other {
                recorded: 1001,
                current: None
            }
        );
        assert_eq!(
            Owner::of(Some(1001), || Resolution::Unknown),
            Owner::Unknown { recorded: 1001 }
        );
        for unusable in [
            Owner::Other {
                recorded: 1,
                current: Some(2),
            },
            Owner::Other {
                recorded: 1,
                current: None,
            },
            Owner::Unknown { recorded: 1 },
        ] {
            assert!(!unusable.usable(), "{unusable:?}");
        }
    }

    #[test]
    fn refusals_name_the_uids_and_the_next_step() {
        let message = refusal_message(
            "alice",
            Record::Enrollment,
            Owner::Other {
                recorded: 1001,
                current: Some(1002),
            },
        )
        .unwrap();
        assert!(message.contains("uid 1001"), "{message}");
        assert!(message.contains("uid 1002"), "{message}");
        assert!(message.contains("irlume enroll"), "{message}");
        let message = refusal_message(
            "alice",
            Record::SealedSecret,
            Owner::Other {
                recorded: 1001,
                current: Some(1002),
            },
        )
        .unwrap();
        assert!(message.contains("irlume keyring arm"), "{message}");
        assert!(refusal_message("alice", Record::Enrollment, Owner::Current).is_none());
        assert!(refusal_message("alice", Record::Enrollment, Owner::Unrecorded).is_none());
        assert!(!message.contains('\u{2014}'));
    }

    #[test]
    fn a_remembered_uid_is_used_until_its_guard_drops() {
        // NSS reads the environment inside glibc: exclude the env writers.
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let user = "irlume-test-remembered-account";
        assert_eq!(resolve(user), Resolution::NoAccount);
        {
            let _first = remember(user, 4100);
            assert_eq!(resolve(user), Resolution::Uid(4100));
            {
                let _second = remember(user, 4200);
                assert_eq!(resolve(user), Resolution::Uid(4200), "the latest wins");
            }
            assert_eq!(resolve(user), Resolution::Uid(4100));
            assert_eq!(resolve("irlume-test-other-name"), Resolution::NoAccount);
        }
        assert_eq!(resolve(user), Resolution::NoAccount);
    }

    #[test]
    fn nss_resolves_root_and_reports_a_missing_name() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(lookup("root"), Resolution::Uid(0));
        assert_eq!(lookup(NO_SUCH_USER), Resolution::NoAccount);
        assert_eq!(lookup("a\0b"), Resolution::NoAccount);
    }

    #[test]
    fn an_account_resolves_once_and_writes_record_the_current_uid() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let user = "irlume-test-account-once";
        let _uid = remember(user, 4300);
        let mut account = Account::new(user);
        assert_eq!(
            account.uid_to_record(Record::Enrollment, None).unwrap(),
            Some(4300)
        );
        assert!(account.require(Record::Enrollment, Some(4300)).is_ok());
        assert!(!account.found_other());
        let error = account
            .require(Record::SealedSecret, Some(4301))
            .unwrap_err()
            .to_string();
        assert!(error.contains("uid 4301"), "{error}");
        assert!(account.found_other());

        // A name no account has: a record without a uid records none, and a
        // record that carries a uid is neither used nor written.
        let mut missing = Account::new(NO_SUCH_USER);
        assert_eq!(
            missing.uid_to_record(Record::Enrollment, None).unwrap(),
            None
        );
        let error = missing
            .uid_to_record(Record::Enrollment, Some(7))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("uid 7") && error.contains("no account named"),
            "{error}"
        );
        assert!(missing.require(Record::Enrollment, None).is_ok());
        assert!(missing.require(Record::Enrollment, Some(7)).is_err());
    }

    /// A write keeps the uid its record belongs to. When the name now
    /// resolves to another uid the write is refused rather than recording
    /// the new uid on the record, and the refusal names both uids and the
    /// next step. It is not a record turned away on a load, so it never
    /// reads as absent.
    #[test]
    fn a_write_never_changes_the_uid_a_record_carries() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let user = "irlume-test-account-owner-changed";
        let _now = remember(user, 4502);
        let mut account = Account::new(user);
        assert_eq!(
            account
                .uid_to_record(Record::Enrollment, Some(4502))
                .unwrap(),
            Some(4502)
        );
        let error = account
            .uid_to_record(Record::Enrollment, Some(4501))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("belongs to uid 4501")
                && error.contains("now uid 4502")
                && error.contains("nothing was written")
                && error.contains("irlume enroll"),
            "{error}"
        );
        assert!(!error.contains('\u{2014}'));
        assert!(!account.found_other());
        let error = account
            .uid_to_record(Record::SealedSecret, Some(4501))
            .unwrap_err()
            .to_string();
        assert!(error.contains("irlume keyring arm"), "{error}");
        assert_eq!(account.current_uid(), Some(4502));
    }

    /// When the lookup fails, a write keeps the uid its record carries, and
    /// a write of a record without one is refused: it would otherwise leave a
    /// record that a later account of the same name accepts.
    #[test]
    fn a_write_without_a_uid_to_record_is_refused_when_the_lookup_fails() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let user = "irlume-test-account-unknown";
        let _unknown = remember_resolution(user, Resolution::Unknown);
        let mut account = Account::new(user);
        assert_eq!(
            account
                .uid_to_record(Record::SealedSecret, Some(4400))
                .unwrap(),
            Some(4400)
        );
        let error = account
            .uid_to_record(Record::SealedSecret, None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("could not be resolved") && error.contains("sealed secret"),
            "{error}"
        );
        assert!(!error.contains('\u{2014}'));
    }
}
