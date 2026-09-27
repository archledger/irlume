// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Per-user template key: the AES-256-GCM key that [`crate::storage`] uses to
//! encrypt enrolled face templates at rest.
//!
//! The key is 32 random bytes, **TPM-sealed** (so `irlumed` can decrypt the
//! templates headlessly at the login greeter, no user interaction) and stored
//! root-only under `/var/lib/irlume/template-keys/<user>.json`. The same key may
//! also be **recovery-wrapped** under an Argon2id passphrase
//! ([`crate::recovery`]) and stored under `/var/lib/irlume/recovery/<user>.json`,
//! the manual backstop for when the TPM seal can no longer be satisfied
//! (Secure Boot off, TPM cleared, dbx/firmware PCR move, disk moved machines).
//!
//! Reliability note: like the keyring seal, the TPM-sealed key inherits PCR
//! fragility: after a dbx/firmware update the seal may stop unsealing, and face
//! auth then falls back to the password until `irlume recovery restore` (or a
//! re-enroll) re-binds the key to the current PCRs. Encrypting templates is the
//! security/reliability trade the operator opted into.

use crate::account::{Account, Record};
use crate::recovery::RecoveryEnvelope;
use crate::tpm;
use crate::{crypto, envelope::SealedEnvelope};
use irlume_common::{Error, Result};
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// The fallback goes through `state_dir()`, NOT the bare `STATE_DIR`
// constant, so one `IRLUME_STATE_DIR` moves the whole sandbox together.
// When these two resolved to the literal while the profile store honored
// the override, a sandboxed ROOT run reached back into live state: on
// 2026-08-05 a sandboxed `profiles forget-model` emptied the real
// /var/lib/irlume/template-keys and /var/lib/irlume/recovery, leaving an
// encrypted enrollment whose key no longer existed anywhere.
fn key_dir() -> PathBuf {
    std::env::var("IRLUME_TEMPLATE_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| irlume_common::state_dir().join("template-keys"))
}

fn recovery_dir() -> PathBuf {
    std::env::var("IRLUME_RECOVERY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| irlume_common::state_dir().join("recovery"))
}

/// Cross-process serialization for one user's enrollment, sealed key, and
/// recovery envelope. The lock pathname is stable and is never replaced or
/// removed; every acquisition opens it independently so Linux `flock` also
/// excludes sibling threads in this process.
pub(crate) struct UserStateLock(std::fs::File);

impl UserStateLock {
    pub(crate) fn acquire_read_only(user: &str) -> Result<Self> {
        Self::acquire_with_creation(user, false)
    }

    pub(crate) fn acquire(user: &str) -> Result<Self> {
        Self::acquire_with_creation(user, true)
    }

    fn acquire_with_creation(user: &str, create: bool) -> Result<Self> {
        let dir = key_dir().join(".locks");
        if create {
            let dir_existed = dir.try_exists().unwrap_or(false);
            std::fs::create_dir_all(&dir).map_err(|error| Error::Io(error.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if !dir_existed {
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| Error::Io(error.to_string()))?;
                }
            }
        }
        let path = dir.join(format!(
            "{}.lock",
            irlume_common::sha256_hex(user.as_bytes())
        ));
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(create)
            .create(create)
            .truncate(false);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options
            .open(&path)
            .map_err(|error| Error::Io(format!("open state lock {}: {error}", path.display())))?;
        if !file
            .metadata()
            .map_err(|error| Error::Io(error.to_string()))?
            .file_type()
            .is_file()
        {
            return Err(Error::Io(format!(
                "state lock is not a regular file: {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        // SAFETY: `file` owns this live descriptor and the returned guard keeps
        // it open for the whole state transaction.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(Error::Io(format!(
                "lock state transaction {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self(file))
    }
}

impl Drop for UserStateLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: the guard still owns a valid descriptor throughout Drop.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn key_path(user: &str) -> PathBuf {
    key_dir().join(format!("{user}.json"))
}

pub fn recovery_path(user: &str) -> PathBuf {
    recovery_dir().join(format!("{user}.json"))
}

/// Whether a TPM is present. When false, [`crate::storage`] keeps templates as
/// root-only plaintext (dev boxes / no-TPM hosts) instead of failing.
pub fn tpm_available() -> bool {
    #[cfg(test)]
    if let Some(present) = *TPM_PRESENT.lock().unwrap_or_else(|e| e.into_inner()) {
        return present;
    }
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

/// Test-only: what [`tpm_available`] answers, when a test has set it. The
/// swtpm lane reaches its TPM through `IRLUME_TCTI` and has no device node,
/// so a test of the TPM branch sets this instead. Taken under
/// `testenv::ENV_LOCK` and cleared by the test that set it.
#[cfg(test)]
pub(crate) static TPM_PRESENT: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

/// Whether a sealed template key exists for `user`.
pub fn has_key(user: &str) -> bool {
    key_path(user).exists()
}

/// Whether `user`'s sealed template key was recorded for another uid
/// ([`crate::account`]), as `account` resolves it; `false` when there is no
/// key or it cannot be read.
pub(crate) fn key_is_for_another_account(user: &str, account: &mut Account<'_>) -> bool {
    SealedEnvelope::load(&key_path(user))
        .is_ok_and(|env| matches!(account.owner(env.uid), crate::account::Owner::Other { .. }))
}

/// Whether `user`'s sealed template key records no uid while its recovery
/// envelope records one that `account` resolves as another account's. A
/// recovery setup wraps the key as it is and records the uid it was set up
/// for, so for a key an earlier release sealed without a uid the envelope
/// names the account the key belongs to. Only the envelope's `uid` field is
/// read; nothing is unwrapped. `false` when the key records a uid or cannot
/// be read, and when no recovery envelope can be read.
pub(crate) fn unbound_key_has_another_accounts_recovery(
    user: &str,
    account: &mut Account<'_>,
) -> bool {
    SealedEnvelope::load(&key_path(user)).is_ok_and(|env| env.uid.is_none())
        && load_recovery(user)
            .is_ok_and(|env| matches!(account.owner(env.uid), crate::account::Owner::Other { .. }))
}

/// Whether a recovery envelope exists for `user`.
pub fn has_recovery(user: &str) -> bool {
    recovery_path(user).exists()
}

/// The template key for `user`, generating and TPM-sealing a fresh one if none
/// exists. Used on the write path ([`crate::storage::save`]).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn ensure_key(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let _state = UserStateLock::acquire(user)?;
    ensure_key_unlocked(user)
}

/// A sealed key recorded for another uid is an error here: only an
/// enrollment write replaces it ([`ensure_enrollment_key_unlocked`]).
pub(crate) fn ensure_key_unlocked(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure_key_with(
        user,
        &mut Account::new(user),
        None,
        load_key_as,
        reseal_key_unlocked,
    )
    .map(|key| key.key)
}

/// Whether an unsealed template key is another account's by the records
/// coupled to it, given the user, the key and the enrollment write's view of
/// the account ([`crate::storage`] reads the enrollment under the key).
pub(crate) type KeyIsAnotherAccounts<'f> = &'f dyn Fn(&str, &[u8], &mut Account<'_>) -> bool;

/// The key an enrollment write encrypts under: [`ensure_key_unlocked`],
/// except that a sealed key recorded for another uid is replaced, and so is
/// one that `is_other` finds is another account's: it opens an enrollment
/// recorded for another uid (a key an earlier release sealed without a uid,
/// under which that account's enrollment recorded its own), or neither it
/// nor that enrollment records a uid and its recovery envelope records
/// another ([`unbound_key_has_another_accounts_recovery`]). The enrollment
/// written with it replaces that account's enrollment, so the account gets a
/// key of its own. Nothing else replaces it. The replacement is final only
/// once that enrollment is published: the write settles it with
/// [`WriteKey::settle`], which removes the replaced key's recovery envelope.
/// `account` is the enrollment write's view of the account, so the key is
/// chosen against the uid the enrollment is written for.
pub(crate) fn ensure_enrollment_key_unlocked(
    user: &str,
    account: &mut Account<'_>,
    is_other: KeyIsAnotherAccounts<'_>,
) -> Result<WriteKey> {
    ensure_key_with(
        user,
        account,
        Some(is_other),
        load_key_as,
        reseal_key_unlocked,
    )
}

/// The template key an enrollment write encrypts under.
pub(crate) struct WriteKey {
    key: Zeroizing<Vec<u8>>,
    /// The sealed key of another uid that this one replaced, set aside
    /// until the enrollment write under the new key is settled.
    replaced: Option<ReplacedKey>,
}

/// The envelope file of a template key sealed for another uid, as it was
/// before a new key replaced it.
struct ReplacedKey {
    user: String,
    envelope: Vec<u8>,
}

impl ReplacedKey {
    fn set_aside(user: &str) -> Result<Self> {
        let envelope = std::fs::read(key_path(user)).map_err(|e| Error::Io(e.to_string()))?;
        Ok(Self {
            user: user.to_owned(),
            envelope,
        })
    }

    /// Put the replaced key's envelope back in place of the new key.
    fn put_back(self, why: &str) -> Result<()> {
        irlume_common::write_0600_atomic(&key_path(&self.user), &self.envelope).map_err(|e| {
            Error::Io(format!(
                "{why}, and the template key it replaced could not be put back ({e}); its \
                 recovery envelope is kept"
            ))
        })
    }
}

impl WriteKey {
    /// A key the write uses as it is: nothing to settle.
    pub(crate) fn kept(key: Zeroizing<Vec<u8>>) -> Self {
        Self {
            key,
            replaced: None,
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.key
    }

    /// Whether this key replaces another uid's: the enrollment written under
    /// it replaces that account's enrollment.
    pub(crate) fn replaces_another(&self) -> bool {
        self.replaced.is_some()
    }

    /// Finish or undo a replacement by how the enrollment write under this
    /// key went (`published`: what the write made visible, `None` when it
    /// published nothing). Published and durable: the replaced key's
    /// recovery envelope, which can only restore that key, is removed. Not
    /// published: the replaced key goes back, so the failed write leaves the
    /// other account's key, enrollment and recovery envelope as they were.
    /// Visible but not durable: the new key stays and so does the recovery
    /// envelope, since a power loss may bring the replaced enrollment back.
    pub(crate) fn settle(self, published: Option<&irlume_common::AtomicWrite>) -> Result<()> {
        let Some(replaced) = self.replaced else {
            return Ok(());
        };
        match published {
            Some(irlume_common::AtomicWrite::Durable) => forget_recovery_unlocked(&replaced.user)
                .map_err(|e| {
                    Error::Io(format!(
                        "the enrollment of '{}' was saved under a new template key, but the \
                         recovery envelope of the replaced key could not be removed: {e}",
                        replaced.user
                    ))
                }),
            Some(irlume_common::AtomicWrite::VisibleNotDurable(_)) => Ok(()),
            None => replaced.put_back("the enrollment was not written"),
        }
    }
}

/// [`ensure_key_unlocked`] with the unseal (`load`) and the seal (`reseal`)
/// passed in. Only with `replace_other` (an enrollment write's
/// [`KeyIsAnotherAccounts`]) is a key replaced: one sealed for another uid,
/// or one that `replace_other` finds is another account's. It is set aside
/// first: a failed seal or round trip puts it back, and the enrollment write
/// settles the rest ([`WriteKey::settle`]).
pub(crate) fn ensure_key_with(
    user: &str,
    account: &mut Account<'_>,
    replace_other: Option<KeyIsAnotherAccounts<'_>>,
    mut load: impl FnMut(&str, &mut Account<'_>) -> Result<Zeroizing<Vec<u8>>>,
    reseal: impl FnOnce(&str, &[u8], Option<u32>) -> Result<()>,
) -> Result<WriteKey> {
    let mut replaced = None;
    if has_key(user) {
        match (load(user, account), replace_other) {
            (Ok(key), Some(is_other)) if is_other(user, &key, account) => {
                replaced = Some(ReplacedKey::set_aside(user)?);
            }
            (Ok(key), _) => return Ok(WriteKey::kept(key)),
            (Err(_), Some(_)) if account.found_other() => {
                replaced = Some(ReplacedKey::set_aside(user)?);
            }
            (Err(error), _) => return Err(error),
        }
    }
    let uid = account.uid_to_record(Record::TemplateKey, None)?;
    let key = crypto::generate_key();
    let sealed = reseal(user, &key, uid)
        .and_then(|()| load(user, account))
        .and_then(|persisted| {
            if persisted.as_slice() == key.as_slice() {
                Ok(persisted)
            } else {
                Err(Error::Policy(
                    "new template key failed persisted TPM round-trip; enrollment was not written"
                        .into(),
                ))
            }
        });
    match (sealed, replaced) {
        (Ok(key), replaced) => Ok(WriteKey { key, replaced }),
        (Err(error), Some(replaced)) => {
            replaced.put_back(&error.to_string())?;
            Err(error)
        }
        (Err(error), None) => Err(error),
    }
}

/// The unsealed template key as the TPM seam returns it: zeroized on drop.
pub type UnsealedKey = Zeroizing<Vec<u8>>;

/// The key resolver for reads: `user`'s existing template key, unsealed
/// read-only, or `None` on a host without a TPM. It never mints a key, never
/// rewrites the key envelope and never persists a storage root key, so a
/// read cannot create key state for an account whose key is gone (ADR-0024
/// §4.3). With no key sealed it fails before opening the TPM. Minting stays
/// on the write paths, under the user state lock ([`ensure_key`]).
///
/// # Errors
/// Returns an error when no key is sealed for `user`, or when the unseal
/// fails.
pub(crate) fn existing_key_read_only(user: &str) -> Result<Option<UnsealedKey>> {
    if !tpm_available() {
        return Ok(None);
    }
    load_key_read_only_unlocked(user).map(Some)
}

/// Lends the account template key to the readers of one authentication
/// request (ADR-0025). Implementations unseal at most once per request and
/// lend a borrow, never a copy.
pub trait TemplateKeySource {
    /// The key for `user`'s encrypted stores: `None` on a host without a
    /// TPM (encrypted stores then fail closed in the readers).
    ///
    /// # Errors
    /// Returns the unseal error when the key cannot be obtained.
    fn template_key(&mut self, user: &str) -> Result<Option<&[u8]>>;
}

/// One request's template key: adopted from the enrollment load when that
/// load unsealed, or unsealed lazily on the request's first encrypted read
/// (a legacy plaintext primary beside an encrypted secondary). Holds the one
/// memlocked `Zeroizing` allocation the unseal produced and drops it, and
/// so zeroizes it, with the request.
pub struct RequestTemplateKey {
    /// `Some` once the request resolved its key, even to "none available",
    /// bound to the account it was resolved for.
    resolved: Option<(String, Option<UnsealedKey>)>,
    unseals: usize,
    unseal: Box<Unsealer>,
}

/// Resolves the key for a user when the request first needs it.
type Unsealer = dyn FnMut(&str) -> Result<Option<UnsealedKey>> + Send;

impl Default for RequestTemplateKey {
    fn default() -> Self {
        Self::production()
    }
}

impl std::fmt::Debug for RequestTemplateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestTemplateKey")
            .field(
                "held",
                &self.resolved.as_ref().is_some_and(|(_, key)| key.is_some()),
            )
            .field("unseals", &self.unseals)
            .finish()
    }
}

impl RequestTemplateKey {
    /// A source that unseals read-only through the TPM when a key is first
    /// needed, and lends nothing on a host without a TPM.
    #[must_use]
    pub fn production() -> Self {
        Self::with_unsealer(existing_key_read_only)
    }

    /// A source with an injected unsealer (tests count and script it).
    pub fn with_unsealer(
        unseal: impl FnMut(&str) -> Result<Option<UnsealedKey>> + Send + 'static,
    ) -> Self {
        Self {
            resolved: None,
            unseals: 0,
            unseal: Box::new(unseal),
        }
    }

    /// Adopt the key another loader in this request already unsealed for
    /// `user`, so no later reader unseals again. `None` leaves the lazy
    /// path in place.
    pub fn adopt(&mut self, user: &str, key: Option<UnsealedKey>) {
        if key.is_some() {
            self.resolved = Some((user.to_owned(), key));
        }
    }

    /// Forget the key (zeroized on drop). Called when the request ends.
    pub fn clear(&mut self) {
        self.resolved = None;
        self.unseals = 0;
    }

    /// How many times this source unsealed through its unsealer.
    #[must_use]
    pub fn unseals(&self) -> usize {
        self.unseals
    }

    /// Whether a key is currently held.
    #[must_use]
    pub fn holds_key(&self) -> bool {
        self.resolved.as_ref().is_some_and(|(_, key)| key.is_some())
    }
}

impl TemplateKeySource for RequestTemplateKey {
    fn template_key(&mut self, user: &str) -> Result<Option<&[u8]>> {
        match &self.resolved {
            // One resolution per request, whatever it found: a host without
            // a TPM is not asked again either.
            Some((owner, _)) if owner == user => {}
            // A request serves one account. A store that names another
            // owner does not borrow this account's key; it fails closed as
            // the per-read resolution did.
            Some((owner, _)) => {
                return Err(Error::Policy(format!(
                    "the request holds '{owner}'s template key; '{user}'s store cannot borrow it"
                )));
            }
            None => {
                self.unseals += 1;
                let key = (self.unseal)(user)?;
                self.resolved = Some((user.to_owned(), key));
            }
        }
        Ok(self
            .resolved
            .as_ref()
            .and_then(|(_, key)| key.as_deref().map(Vec::as_slice)))
    }
}

/// Unseal the existing template key for `user`. Errors if none is sealed (the
/// caller must NOT generate one here; that would orphan already-encrypted data).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn load_key(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let _state = UserStateLock::acquire(user)?;
    load_key_unlocked(user)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyLoadPolicy {
    Upgrade,
    /// The normal unseal, never followed by a move to a stronger policy: an
    /// authentication request unseals the key at most once (ADR-0025), and
    /// the move round-trip unseals the new envelope.
    Keep,
    ReadOnly,
}

pub(crate) fn load_key_unlocked(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    load_key_as(user, &mut Account::new(user))
}

/// [`load_key_unlocked`], resolving the account through `account`.
pub(crate) fn load_key_as(user: &str, account: &mut Account<'_>) -> Result<Zeroizing<Vec<u8>>> {
    load_key_with(
        user,
        account,
        KeyLoadPolicy::Upgrade,
        tpm::unseal,
        tpm::stronger_tier_available_than,
        tpm::seal,
    )
}

/// The key for an authentication request: caller holds the user state lock.
/// Never moves the envelope to a stronger policy, which would unseal the key
/// a second time inside the request (ADR-0025); irlumed does that at startup
/// ([`move_to_stronger_policy`]). Resolves the account through `account`.
pub(crate) fn load_key_for_authentication_as(
    user: &str,
    account: &mut Account<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    load_key_with(
        user,
        account,
        KeyLoadPolicy::Keep,
        tpm::unseal,
        tpm::stronger_tier_available_than,
        tpm::seal,
    )
}

/// Move `user`'s template key to a strictly stronger TPM policy when one is
/// available: a signed Tier 1 envelope an earlier release wrote, or a literal
/// one after a pcrlock policy covering a firmware-measured PCR was
/// provisioned. irlumed calls this at startup, off every authentication
/// request. With nothing stronger available it reads only the envelope and
/// the policy files; otherwise it unseals the key once, seals it under the
/// ladder's policy (round-trip verified) and keeps the new envelope only if
/// it ranks higher. `Ok(true)` when the envelope moved.
///
/// # Errors
/// Returns the lock, envelope, unseal, seal or save error; the envelope is
/// then left as it was.
pub fn move_to_stronger_policy(user: &str) -> Result<bool> {
    if !has_key(user) {
        return Ok(false);
    }
    let _state = UserStateLock::acquire(user)?;
    move_with(
        user,
        tpm::unseal,
        tpm::stronger_tier_available_than,
        tpm::seal,
    )
}

/// [`move_to_stronger_policy`] with the TPM calls passed in. Unlike the
/// best-effort move in [`load_key_with`], a failed seal or save is an error,
/// so irlumed can say the key stayed where it was.
fn move_with(
    user: &str,
    unseal: impl FnOnce(&SealedEnvelope) -> Result<Zeroizing<Vec<u8>>>,
    stronger_tier_available: impl FnOnce(&SealedEnvelope) -> bool,
    seal: impl FnOnce(&[u8]) -> Result<SealedEnvelope>,
) -> Result<bool> {
    let path = key_path(user);
    let env = SealedEnvelope::load(&path)?;
    if !stronger_tier_available(&env) {
        return Ok(false);
    }
    // A key sealed for another uid is not unsealed, and not moved. A move
    // changes the policy only: a key an earlier release sealed without a uid
    // keeps none, since the name may no longer resolve to the account whose
    // enrollment the key opens; that enrollment's next write records it.
    Account::new(user).require(Record::TemplateKey, env.uid)?;
    let key = unseal(&env)?;
    let mut candidate = seal(&key)?;
    candidate.uid = env.uid;
    if candidate.strength_rank() <= env.strength_rank() {
        return Ok(false);
    }
    // Once the new envelope is visible the move happened, even when syncing
    // the directory failed: an error here must mean the old one is still in
    // place. A power loss may bring the old envelope back, which unseals too.
    if let irlume_common::AtomicWrite::VisibleNotDurable(e) = candidate.save_reporting(&path)? {
        eprintln!(
            "irlume: moved the template key of '{user}' to a stronger TPM policy, but syncing \
             its directory failed ({e}); after a power loss the previous envelope, which still \
             unseals, may come back"
        );
    }
    set_0600(&path);
    Ok(true)
}

/// Caller holds the existing user state lock. Never upgrades the envelope or
/// initializes a persistent TPM storage root key.
pub(crate) fn load_key_read_only_unlocked(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    load_key_read_only_as(user, &mut Account::new(user))
}

/// [`load_key_read_only_unlocked`], resolving the account through `account`.
pub(crate) fn load_key_read_only_as(
    user: &str,
    account: &mut Account<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    load_key_with(
        user,
        account,
        KeyLoadPolicy::ReadOnly,
        tpm::unseal_read_only,
        tpm::stronger_tier_available_than,
        tpm::seal,
    )
}

pub(crate) fn load_key_with(
    user: &str,
    account: &mut Account<'_>,
    policy: KeyLoadPolicy,
    unseal: impl FnOnce(&SealedEnvelope) -> Result<Zeroizing<Vec<u8>>>,
    stronger_tier_available: impl FnOnce(&SealedEnvelope) -> bool,
    seal: impl FnOnce(&[u8]) -> Result<SealedEnvelope>,
) -> Result<Zeroizing<Vec<u8>>> {
    let path = key_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!(
            "no template key sealed for '{user}'"
        )));
    }
    let env = SealedEnvelope::load(&path)?;
    // A key sealed for another uid is never unsealed (the account's
    // enrollment then reads as absent; see `storage`).
    account.require(Record::TemplateKey, env.uid)?;
    let key = unseal(&env)?;
    // Best-effort tier auto-upgrade (mirrors keyring::reseal_password): if a
    // strictly stronger policy is available than the one this key was sealed
    // under (pcrlock provisioned since, or a signed Tier 1 envelope from an
    // earlier release), re-seal the key to it with no re-enroll. Not on an
    // authentication request's load (`Keep`), since the ladder's round trip
    // unseals again. The check short-circuits to a no-op once the envelope is
    // already at the best policy. Never fail the load on it: the key unsealed
    // fine and the weaker envelope stays usable.
    // The move keeps the uid the key records, or none (see `move_with`).
    if policy == KeyLoadPolicy::Upgrade && stronger_tier_available(&env) {
        if let Ok(mut candidate) = seal(&key) {
            candidate.uid = env.uid;
            if candidate.strength_rank() > env.strength_rank() && candidate.save(&path).is_ok() {
                set_0600(&path);
            }
        }
    }
    Ok(key)
}

/// (Re-)seal `key` for `user` against the current TPM PCR policy and persist it.
/// Used at first enrollment and by recovery-restore to re-bind after a PCR move.
/// A re-seal keeps the uid the sealed key it overwrites records, and is
/// refused, with the key left as it is, when the account now resolves to
/// another uid or to no account ([`crate::account`]).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn reseal_key(user: &str, key: &[u8]) -> Result<()> {
    let _state = UserStateLock::acquire(user)?;
    // A key that cannot be read has no uid to keep, and is overwritten.
    let existing = SealedEnvelope::load(&key_path(user))
        .ok()
        .and_then(|env| env.uid);
    let uid = Account::new(user).uid_to_record(Record::TemplateKey, existing)?;
    reseal_key_unlocked(user, key, uid)
}

/// Seal `key` for `user`, recording `uid` as the account it belongs to.
fn reseal_key_unlocked(user: &str, key: &[u8], uid: Option<u32>) -> Result<()> {
    if key.len() != crypto::KEY_LEN {
        return Err(Error::Policy(format!(
            "template key must be {} bytes",
            crypto::KEY_LEN
        )));
    }
    let dir = key_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::Io(e.to_string()))?;
    let mut env = tpm::seal(key)?;
    env.uid = uid;
    env.save(&key_path(user))?;
    set_0600(&key_path(user));
    Ok(())
}

/// Erase `user`'s sealed template key (e.g. when their enrollment is deleted).
/// Idempotent. Does NOT touch the recovery envelope.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn forget_key(user: &str) -> Result<()> {
    let _state = UserStateLock::acquire(user)?;
    forget_key_unlocked(user)
}

pub(crate) fn forget_key_unlocked(user: &str) -> Result<()> {
    let path = key_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

// --- recovery passphrase backstop ------------------------------------------

/// Create (or replace) `user`'s recovery envelope: wrap the live template key
/// under `passphrase`. Requires a sealed template key to already exist.
/// A passphrase below the recovery floor
/// ([`crate::recovery::check_new_passphrase`]) is refused before any file is
/// read or written, so an existing envelope stays as it was.
///
/// The key is not wrapped for this account, and an existing envelope stays,
/// when the enrollment it opens records another uid, or when the key records
/// no uid, its enrollment records none, and the envelope it would replace
/// records another uid ([`crate::account`]).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn setup_recovery(user: &str, passphrase: &[u8]) -> Result<()> {
    crate::recovery::check_new_passphrase(passphrase)?;
    let _state = UserStateLock::acquire(user)?;
    setup_recovery_with(user, passphrase, load_key_as)
}

/// [`setup_recovery`] once the passphrase passed and the user state lock is
/// held, with the unseal passed in.
pub(crate) fn setup_recovery_with(
    user: &str,
    passphrase: &[u8],
    load: impl FnOnce(&str, &mut Account<'_>) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<()> {
    let mut account = Account::new(user);
    // `load` refuses a key sealed for another uid; one without a uid is
    // checked against the records coupled to it.
    let key_uid = SealedEnvelope::load(&key_path(user))
        .ok()
        .and_then(|env| env.uid);
    let key = load(user, &mut account)?;
    require_key_is_the_accounts(user, &key, key_uid, &mut account).map_err(|e| match e {
        Error::Policy(message) => Error::Policy(format!(
            "no recovery passphrase was set for '{user}': {message}"
        )),
        other => other,
    })?;
    let uid = account.uid_to_record(Record::Recovery, None)?;
    let mut env = crate::recovery::wrap(passphrase, &key)?;
    env.uid = uid;
    save_recovery(user, &env)
}

/// `Ok` when `key`, `user`'s template key recording `key_uid`, may be wrapped
/// in a recovery envelope for `account`; otherwise the refusal of the record
/// that shows it is another account's.
///
/// - The enrollment the key opens protects that enrollment's templates, so
///   one recorded for another uid refuses it, whatever the key records.
/// - A key an earlier release sealed records no uid. When its enrollment
///   records none either, the recovery envelope the write would replace
///   decides: it was set up for the key it wraps, so a uid it records names
///   that key's account. An envelope that records another uid is refused,
///   and so kept; once the account has enrolled again its enrollment
///   records the account's uid, and the envelope is replaced.
fn require_key_is_the_accounts(
    user: &str,
    key: &[u8],
    key_uid: Option<u32>,
    account: &mut Account<'_>,
) -> Result<()> {
    let enrollment_uid = crate::storage::stored_enrollment_uid(user, Some(key));
    account.require(Record::Enrollment, enrollment_uid)?;
    if key_uid.is_none() && enrollment_uid.is_none() {
        if let Ok(existing) = load_recovery(user) {
            account.require(Record::Recovery, existing.uid)?;
        }
    }
    Ok(())
}

/// Restore `user`'s template key from the recovery envelope using `passphrase`,
/// and re-seal it against the *current* TPM PCRs (healing a PCR move / TPM
/// clear / disk move). Errors on a wrong passphrase or a missing envelope,
/// and, with nothing sealed, when the recovery file, the key it overwrites
/// or the enrollment the restored key opens records another uid.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn restore_from_recovery(user: &str, passphrase: &[u8]) -> Result<()> {
    let _state = UserStateLock::acquire(user)?;
    restore_from_recovery_unlocked(user, passphrase)
}

pub(crate) fn restore_from_recovery_unlocked(user: &str, passphrase: &[u8]) -> Result<()> {
    restore_with(user, passphrase, reseal_key_unlocked)
}

/// [`restore_from_recovery_unlocked`] with the seal passed in.
pub(crate) fn restore_with(
    user: &str,
    passphrase: &[u8],
    reseal: impl FnOnce(&str, &[u8], Option<u32>) -> Result<()>,
) -> Result<()> {
    let path = recovery_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!(
            "no recovery passphrase set for '{user}'; run `irlume recovery setup`"
        )));
    }
    let env = load_recovery(user)?;
    // A recovery file, or the key it restores, written for another uid
    // restores nothing: it would re-seal that account's key for this one. A
    // recovery file from an earlier release records no uid, so the key's
    // own uid decides; a key that cannot be read has none to keep.
    let existing = SealedEnvelope::load(&key_path(user))
        .ok()
        .and_then(|key| key.uid);
    let mut account = Account::new(user);
    account.require(Record::Recovery, env.uid)?;
    account.require(Record::TemplateKey, existing)?;
    let uid = account.uid_to_record(Record::TemplateKey, env.uid.or(existing))?;
    let key = crate::recovery::unwrap(passphrase, &env)?;
    // The enrollment the restored key opens counts too: when neither the
    // recovery file nor the key records a uid, the enrollment may, and one
    // recorded for another uid means the key protects that account's
    // templates, so it is not sealed for this one.
    account
        .require(
            Record::Enrollment,
            crate::storage::stored_enrollment_uid(user, Some(&key)),
        )
        .map_err(|e| match e {
            Error::Policy(message) => Error::Policy(format!(
                "the template key of '{user}' was not restored: {message}"
            )),
            other => other,
        })?;
    reseal(user, &key, uid)
}

/// Erase `user`'s recovery envelope. Idempotent. An envelope recorded for
/// another uid is kept and the request refused: it was set up for the key it
/// wraps, and while it is there a recovery setup cannot wrap that key for
/// this account (see `setup_recovery`). Enrolling again, then a setup,
/// replaces it. Removals a write makes (a replaced key, a deleted enrollment)
/// go through `forget_recovery_unlocked`.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn forget_recovery(user: &str) -> Result<()> {
    let _state = UserStateLock::acquire(user)?;
    if let Ok(env) = load_recovery(user) {
        Account::new(user).require(Record::Recovery, env.uid)?;
    }
    forget_recovery_unlocked(user)
}

pub(crate) fn forget_recovery_unlocked(user: &str) -> Result<()> {
    let path = recovery_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(dead_code, reason = "test helper used by template_key tests")]
fn forget_key_unlocked_no_lock(user: &str) -> Result<()> {
    let path = key_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
fn forget_recovery_unlocked_no_lock(user: &str) -> Result<()> {
    let path = recovery_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

fn save_recovery(user: &str, env: &RecoveryEnvelope) -> Result<()> {
    let dir = recovery_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::Io(e.to_string()))?;
    let json = serde_json::to_vec_pretty(env).map_err(|e| Error::Protocol(e.to_string()))?;
    let path = recovery_path(user);
    // Atomic: replacing a recovery envelope must not corrupt the existing one on
    // a failed write; it is the last-resort backstop after a TPM seal breaks.
    irlume_common::write_0600_atomic(&path, &json).map_err(|e| Error::Io(e.to_string()))
}

fn load_recovery(user: &str) -> Result<RecoveryEnvelope> {
    let data = std::fs::read(recovery_path(user)).map_err(|e| Error::Io(e.to_string()))?;
    serde_json::from_slice(&data).map_err(|e| Error::Protocol(e.to_string()))
}

#[cfg(unix)]
fn set_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_0600(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolution that found no key is remembered: a host without a TPM
    /// is asked once per request, not once per encrypted read.
    #[test]
    fn a_request_asks_its_unsealer_at_most_once_even_when_no_key_exists() {
        let mut none = RequestTemplateKey::with_unsealer(|_| Ok(None));
        assert!(none.template_key("alice").unwrap().is_none());
        assert!(none.template_key("alice").unwrap().is_none());
        assert_eq!(none.unseals(), 1);
        assert!(!none.holds_key());

        let mut some = RequestTemplateKey::with_unsealer(|_| Ok(Some(Zeroizing::new(vec![9; 32]))));
        assert_eq!(some.template_key("alice").unwrap(), Some(&[9u8; 32][..]));
        assert_eq!(some.template_key("alice").unwrap(), Some(&[9u8; 32][..]));
        assert_eq!(some.unseals(), 1);
        some.clear();
        assert!(!some.holds_key());
        assert_eq!(some.unseals(), 0);
    }

    /// The held key belongs to one account: a store naming another owner
    /// cannot borrow it and fails closed, as per-read resolution did.
    #[test]
    fn a_held_key_is_never_lent_to_another_account() {
        let mut keys = RequestTemplateKey::with_unsealer(|_| Ok(Some(Zeroizing::new(vec![1; 32]))));
        keys.adopt("alice", Some(Zeroizing::new(vec![2; 32])));
        assert_eq!(keys.template_key("alice").unwrap(), Some(&[2u8; 32][..]));
        let error = keys.template_key("mallory").unwrap_err().to_string();
        assert!(
            error.contains("mallory") && error.contains("alice"),
            "{error}"
        );
        assert_eq!(
            keys.unseals(),
            0,
            "no unseal is attempted for the other account"
        );
        // The bound key stays available to its own account afterwards.
        assert_eq!(keys.template_key("alice").unwrap(), Some(&[2u8; 32][..]));
    }

    /// A sealed template key records the uid it was sealed for. A key
    /// recorded for another uid is refused before any unseal, and the
    /// startup move leaves it where it is; a key without a uid (an earlier
    /// release) and one recorded for the current uid unseal.
    #[test]
    fn a_template_key_sealed_for_another_uid_is_never_unsealed() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("key-uid"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);
        let user = "key-uid-owner";
        let write = |uid: Option<u32>| {
            let mut env: SealedEnvelope =
                serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#)
                    .unwrap();
            env.uid = uid;
            env.save(&key_path(user)).unwrap();
            std::fs::read(key_path(user)).unwrap()
        };
        let _now = crate::account::remember(user, 4102);

        let before = write(Some(4101));
        let mut account = Account::new(user);
        let error = load_key_with(
            user,
            &mut account,
            KeyLoadPolicy::Upgrade,
            |_| panic!("a key sealed for another uid must not be unsealed"),
            |_| panic!("nor probed for an upgrade"),
            |_| panic!("nor sealed again"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("uid 4101") && error.contains("uid 4102"),
            "{error}"
        );
        assert!(error.contains("irlume enroll"), "{error}");
        assert!(account.found_other());
        assert!(key_is_for_another_account(user, &mut Account::new(user)));
        assert!(move_with(
            user,
            |_| panic!("the startup move must not unseal it"),
            |_| true,
            |_| panic!("nor seal it again"),
        )
        .is_err());
        assert_eq!(std::fs::read(key_path(user)).unwrap(), before);

        for uid in [Some(4102), None] {
            write(uid);
            assert!(!key_is_for_another_account(user, &mut Account::new(user)));
            let key = load_key_with(
                user,
                &mut Account::new(user),
                KeyLoadPolicy::Keep,
                |_| Ok(Zeroizing::new(vec![3; 32])),
                |_| panic!("an authentication load does not probe upgrades"),
                |_| panic!("an authentication load does not seal"),
            )
            .unwrap();
            assert_eq!(key.as_slice(), &[3; 32], "{uid:?}");
        }
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A re-seal keeps the uid the sealed key records. When the name now
    /// resolves to another uid, or to no account, it is refused before any
    /// seal and the key file stays as it was: the key is not handed to the
    /// account that took the name.
    #[test]
    fn a_reseal_never_records_another_uid_on_a_key() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Never the host TPM, even if the check were missing.
        let _tpm = crate::testenv::NoTpm::set();
        let dir = PathBuf::from(crate::test_tmp_dir("key-uid-reseal"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);
        let user = "key-uid-reseal-owner";
        let mut env: SealedEnvelope =
            serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#).unwrap();
        env.uid = Some(4131);
        env.save(&key_path(user)).unwrap();
        let before = std::fs::read(key_path(user)).unwrap();
        {
            let _now = crate::account::remember(user, 4132);
            let error = reseal_key(user, &[1; crypto::KEY_LEN])
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("template key")
                    && error.contains("belongs to uid 4131")
                    && error.contains("now uid 4132"),
                "{error}"
            );
        }
        {
            let _gone =
                crate::account::remember_resolution(user, crate::account::Resolution::NoAccount);
            let error = reseal_key(user, &[1; crypto::KEY_LEN])
                .unwrap_err()
                .to_string();
            assert!(error.contains("no account named"), "{error}");
        }
        assert_eq!(std::fs::read(key_path(user)).unwrap(), before);
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A move to a stronger policy keeps a key an earlier release sealed
    /// without a uid unbound: the name may resolve to another account than
    /// the one whose enrollment the key opens. A key with a uid keeps it.
    #[test]
    fn the_startup_move_keeps_the_uid_a_key_records_or_none() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("key-uid-move"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);
        let user = "key-uid-move-owner";
        let legacy = r#"{"version":1,"pcrs":[7],"public":"","private":""}"#;
        serde_json::from_str::<SealedEnvelope>(legacy)
            .unwrap()
            .save(&key_path(user))
            .unwrap();
        let _now = crate::account::remember(user, 4111);
        let stronger = || {
            let mut stronger: SealedEnvelope = serde_json::from_str(legacy).unwrap();
            stronger.policy = crate::envelope::PolicyKind::PcrlockNv { nv_index: 1 };
            Ok(stronger)
        };
        assert!(move_with(
            user,
            |_| Ok(Zeroizing::new(vec![5; 32])),
            |_| true,
            |_| stronger()
        )
        .unwrap());
        assert_eq!(SealedEnvelope::load(&key_path(user)).unwrap().uid, None);
        let mut bound: SealedEnvelope = serde_json::from_str(legacy).unwrap();
        bound.uid = Some(4111);
        bound.save(&key_path(user)).unwrap();
        assert!(move_with(
            user,
            |_| Ok(Zeroizing::new(vec![5; 32])),
            |_| true,
            |_| stronger()
        )
        .unwrap());
        assert_eq!(
            SealedEnvelope::load(&key_path(user)).unwrap().uid,
            Some(4111)
        );
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A recovery file records the uid it was set up for; one recorded for
    /// another uid restores nothing and stays in place, even with the right
    /// passphrase. So does one whose account cannot be resolved.
    #[test]
    fn a_recovery_file_recorded_for_another_uid_restores_nothing() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Never the host TPM, even if the check were missing.
        let _tpm = crate::testenv::NoTpm::set();
        let rec = crate::test_tmp_dir("rec-uid");
        let tk = crate::test_tmp_dir("tk-uid");
        let _ = std::fs::remove_dir_all(&rec);
        let _ = std::fs::remove_dir_all(&tk);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &tk);
        let user = "rec-uid-owner";
        let key = crypto::generate_key();
        let mut env = crate::recovery::wrap(b"recovery passphrase", &key).unwrap();
        env.uid = Some(4201);
        save_recovery(user, &env).unwrap();
        let before = std::fs::read(recovery_path(user)).unwrap();

        {
            let _now = crate::account::remember(user, 4202);
            let error = restore_from_recovery(user, b"recovery passphrase")
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("recovery envelope") && error.contains("uid 4201"),
                "{error}"
            );
            assert!(error.contains("irlume recovery setup"), "{error}");
        }
        {
            let _unknown =
                crate::account::remember_resolution(user, crate::account::Resolution::Unknown);
            let error = restore_from_recovery(user, b"recovery passphrase")
                .unwrap_err()
                .to_string();
            assert!(error.contains("could not be resolved"), "{error}");
        }
        assert!(!has_key(user), "nothing was sealed");
        assert_eq!(std::fs::read(recovery_path(user)).unwrap(), before);

        std::env::remove_var("IRLUME_RECOVERY_DIR");
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        let _ = std::fs::remove_dir_all(&rec);
        let _ = std::fs::remove_dir_all(&tk);
    }

    /// A sandboxed run must not reach live cryptographic state. `IRLUME_STATE_DIR`
    /// moved the profile store but not these two directories, so a sandboxed ROOT
    /// `profiles forget-model` deleted the real template keys and recovery
    /// envelopes on 2026-08-05, leaving an encrypted enrollment nothing could
    /// open. Both fallbacks must land under the override.
    #[test]
    fn sandbox_override_contains_key_and_recovery_dirs() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let sandbox = crate::test_tmp_dir("sandbox-containment");
        // The per-directory overrides outrank IRLUME_STATE_DIR, so clear them or
        // this test passes for the wrong reason.
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &sandbox);

        let key = key_path("someuser");
        let rec = recovery_path("someuser");

        std::env::remove_var("IRLUME_STATE_DIR");

        assert!(
            key.starts_with(&sandbox),
            "template key escaped the sandbox: {}",
            key.display()
        );
        assert!(
            rec.starts_with(&sandbox),
            "recovery envelope escaped the sandbox: {}",
            rec.display()
        );
        assert!(!key.starts_with(irlume_common::STATE_DIR));
        assert!(!rec.starts_with(irlume_common::STATE_DIR));
    }

    #[test]
    fn read_only_key_load_preserves_envelope_while_normal_load_upgrades() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("readonly-key"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);
        let weak: SealedEnvelope =
            serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#).unwrap();
        weak.save(&key_path("alice")).unwrap();
        let before = std::fs::read(key_path("alice")).unwrap();
        let unseal = |_: &SealedEnvelope| Ok(Zeroizing::new(vec![42; 32]));
        let key = load_key_with(
            "alice",
            &mut Account::new("alice"),
            KeyLoadPolicy::ReadOnly,
            unseal,
            |_| panic!("read-only load must not probe upgrades"),
            |_| panic!("read-only load must not seal"),
        )
        .unwrap();
        assert_eq!(key.as_slice(), &[42; 32]);
        assert_eq!(std::fs::read(key_path("alice")).unwrap(), before);
        // An authentication request's load unseals once and never moves the
        // envelope, whose round trip would unseal it again (ADR-0025).
        let mut unseals = 0;
        let key = load_key_with(
            "alice",
            &mut Account::new("alice"),
            KeyLoadPolicy::Keep,
            |_: &SealedEnvelope| {
                unseals += 1;
                Ok(Zeroizing::new(vec![42; 32]))
            },
            |_| panic!("an authentication load must not probe upgrades"),
            |_| panic!("an authentication load must not seal"),
        )
        .unwrap();
        assert_eq!(key.as_slice(), &[42; 32]);
        assert_eq!(unseals, 1);
        assert_eq!(std::fs::read(key_path("alice")).unwrap(), before);
        let key = load_key_with(
            "alice",
            &mut Account::new("alice"),
            KeyLoadPolicy::Upgrade,
            unseal,
            |_| true,
            |key| {
                assert_eq!(key, &[42; 32]);
                let mut stronger: SealedEnvelope = serde_json::from_slice(&before).unwrap();
                stronger.policy = crate::envelope::PolicyKind::PcrlockNv { nv_index: 1 };
                Ok(stronger)
            },
        )
        .unwrap();
        assert_eq!(key.as_slice(), &[42; 32]);
        assert!(matches!(
            SealedEnvelope::load(&key_path("alice")).unwrap().policy,
            crate::envelope::PolicyKind::PcrlockNv { .. }
        ));
        assert_ne!(std::fs::read(key_path("alice")).unwrap(), before);
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn read_only_lock_requires_existing_lock_without_creating_state() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("readonly-lock"));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);
        assert!(UserStateLock::acquire_read_only("alice").is_err());
        assert!(!dir.exists());
        drop(UserStateLock::acquire("alice").unwrap());
        drop(UserStateLock::acquire_read_only("alice").unwrap());
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn independent_user_state_locks_serialize_threads() {
        use std::sync::mpsc;
        use std::time::Duration;

        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("template-state-lock"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);

        let first = UserStateLock::acquire("alice").unwrap();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _second = UserStateLock::acquire("alice").unwrap();
            acquired_tx.send(()).unwrap();
        });

        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "a second independent open must block on the same stable lock inode"
        );
        drop(first);
        acquired_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter must acquire after the first guard drops");
        waiter.join().unwrap();

        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The lock directory must exist with owner-only permissions when we
    /// create it; if it already existed we leave its mode alone.
    #[test]
    fn state_lock_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("template-state-lock-mode"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);

        let _guard = UserStateLock::acquire("alice").unwrap();
        let lock_dir = dir.join(".locks");
        let mode = std::fs::metadata(&lock_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "lock directory must be owner-only");

        drop(_guard);
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The override env vars are process-global; the crate-wide lock stops
    // cross-module races too (keyring tests mutate their own override).
    use crate::testenv::ENV_LOCK;

    #[test]
    fn paths_under_override_dirs() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", crate::test_tmp_dir("tk"));
        std::env::set_var("IRLUME_RECOVERY_DIR", crate::test_tmp_dir("rec"));
        assert_eq!(
            key_path("bob"),
            PathBuf::from(format!("{}/bob.json", crate::test_tmp_dir("tk")))
        );
        assert_eq!(
            recovery_path("bob"),
            PathBuf::from(format!("{}/bob.json", crate::test_tmp_dir("rec")))
        );
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// Recovery round-trip WITHOUT a TPM: seed a key file via wrap math directly
    /// to exercise setup/restore plumbing minus the TPM seal. The TPM-backed
    /// `load_key`/`reseal_key` path is covered by an ignored test.
    #[test]
    fn recovery_envelope_save_load_round_trip() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("rec-rt");
        std::env::set_var("IRLUME_RECOVERY_DIR", &dir);
        let _ = std::fs::remove_dir_all(&dir);
        let key = crypto::generate_key();
        let env = crate::recovery::wrap(b"pass-phrase-here", &key).unwrap();
        save_recovery("rt", &env).unwrap();
        assert!(has_recovery("rt"));
        let loaded = load_recovery("rt").unwrap();
        let got = crate::recovery::unwrap(b"pass-phrase-here", &loaded).unwrap();
        assert_eq!(&*got, &*key);
        forget_recovery_unlocked_no_lock("rt").unwrap();
        assert!(!has_recovery("rt"));
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// Full TPM-backed lifecycle: seal a key, recovery-wrap it, simulate a PCR
    /// move by forgetting the seal, then restore from the passphrase.
    /// The startup move reads only the envelope when nothing stronger is
    /// available, moves a key onto a stronger policy, keeps it where it is
    /// when the ladder did not reach one, and reports a failed seal instead
    /// of passing it off as nothing to do.
    #[test]
    fn the_startup_move_moves_skips_or_reports() {
        let _env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(crate::test_tmp_dir("move-with"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);
        let weak: SealedEnvelope =
            serde_json::from_str(r#"{"version":1,"pcrs":[7],"public":"","private":""}"#).unwrap();
        weak.save(&key_path("alice")).unwrap();
        let before = std::fs::read(key_path("alice")).unwrap();
        let unseal = |_: &SealedEnvelope| Ok(Zeroizing::new(vec![42; 32]));
        let stronger = |_: &[u8]| {
            let mut env: SealedEnvelope = serde_json::from_slice(&before).unwrap();
            env.policy = crate::envelope::PolicyKind::PcrlockNv { nv_index: 1 };
            Ok(env)
        };

        assert!(!move_with(
            "alice",
            |_| panic!("nothing stronger: no unseal"),
            |_| false,
            |_| panic!("nothing stronger: no seal"),
        )
        .unwrap());
        let same = |_: &[u8]| Ok(serde_json::from_slice::<SealedEnvelope>(&before).unwrap());
        assert!(!move_with("alice", unseal, |_| true, same).unwrap());
        assert_eq!(std::fs::read(key_path("alice")).unwrap(), before);
        assert!(move_with(
            "alice",
            unseal,
            |_| true,
            |_| Err(irlume_common::Error::Tpm("seal failed".into())),
        )
        .is_err());
        assert_eq!(std::fs::read(key_path("alice")).unwrap(), before);
        assert!(move_with("alice", unseal, |_| true, stronger).unwrap());
        assert!(matches!(
            SealedEnvelope::load(&key_path("alice")).unwrap().policy,
            crate::envelope::PolicyKind::PcrlockNv { .. }
        ));
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A template key on a weaker policy stays there through an
    /// authentication request's load, which unseals it once, and moves when
    /// irlumed starts: once, and not again when nothing stronger is left.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn the_template_key_moves_at_startup_not_during_authentication() {
        use crate::envelope::PolicyKind;
        let _g = ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("tk-move");
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &dir);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _pcrlock = crate::tpm::tests::PcrlockFixture::provision(0x0181_C113);

        let key = crypto::generate_key();
        crate::tpm::seal_with_pcrs(&key, &[7])
            .unwrap()
            .save(&key_path("mv"))
            .unwrap();
        let policy = || SealedEnvelope::load(&key_path("mv")).unwrap().policy;

        {
            let _state = UserStateLock::acquire("mv").unwrap();
            assert_eq!(
                &*load_key_for_authentication_as("mv", &mut Account::new("mv")).unwrap(),
                &*key
            );
        }
        assert_eq!(policy(), PolicyKind::PcrLiteral, "authentication moved it");

        assert!(move_to_stronger_policy("mv").unwrap(), "the startup move");
        assert!(
            matches!(policy(), PolicyKind::PcrlockNv { .. }),
            "got {:?}",
            policy()
        );
        assert!(
            !move_to_stronger_policy("mv").unwrap(),
            "nothing stronger left"
        );
        assert!(
            !move_to_stronger_policy("nobody").unwrap(),
            "no key, no move"
        );
        assert_eq!(&*load_key("mv").unwrap(), &*key, "still unseals");
        forget_key("mv").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
    }

    /// The sealed key and the recovery file record the account's uid. Once
    /// the account resolves to another uid neither is used, and a new
    /// enrollment's key replaces the key once that enrollment is published
    /// (and removes the recovery file, which can only restore the replaced
    /// key). A key an earlier release sealed without a uid unseals, and its
    /// next re-seal records the uid.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn tpm_a_template_key_records_its_uid_and_a_new_enrollment_replaces_it() {
        let _g = ENV_LOCK.lock().unwrap();
        let tk = crate::test_tmp_dir("tk-uid-tpm");
        let rec = crate::test_tmp_dir("rec-uid-tpm");
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &tk);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);
        let _ = std::fs::remove_dir_all(&tk);
        let _ = std::fs::remove_dir_all(&rec);
        let user = "uid-tpm";
        let recorded = || SealedEnvelope::load(&key_path(user)).unwrap().uid;

        let first = {
            let _a = crate::account::remember(user, 5101);
            let key = ensure_key(user).unwrap();
            assert_eq!(recorded(), Some(5101));
            setup_recovery(user, b"recovery passphrase").unwrap();
            assert_eq!(load_recovery(user).unwrap().uid, Some(5101));
            assert_eq!(&*load_key(user).unwrap(), &*key);
            key
        };
        let _b = crate::account::remember(user, 5102);
        let error = load_key(user).unwrap_err().to_string();
        assert!(error.contains("uid 5101"), "{error}");
        assert!(restore_from_recovery(user, b"recovery passphrase").is_err());
        // A recovery file from an earlier release, with no uid, does not move
        // the key either: the key's own uid decides.
        let written = load_recovery(user).unwrap();
        let mut legacy_recovery = load_recovery(user).unwrap();
        legacy_recovery.uid = None;
        save_recovery(user, &legacy_recovery).unwrap();
        let error = restore_from_recovery(user, b"recovery passphrase")
            .unwrap_err()
            .to_string();
        assert!(error.contains("uid 5101"), "{error}");
        assert_eq!(recorded(), Some(5101), "left as it was");
        save_recovery(user, &written).unwrap();
        assert!(setup_recovery(user, b"another passphrase").is_err());
        let error = reseal_key(user, &first).unwrap_err().to_string();
        assert!(error.contains("belongs to uid 5101"), "{error}");
        assert_eq!(recorded(), Some(5101), "left as it was");

        // Only an enrollment write replaces it, and only once the enrollment
        // under the new key is published: until then the recovery file
        // stays, and a write that published nothing puts the replaced key
        // back.
        assert!(ensure_key(user).is_err());
        assert_eq!(recorded(), Some(5101));
        assert!(has_recovery(user));
        let replace = || {
            let _state = UserStateLock::acquire(user).unwrap();
            // No enrollment here: only the key's own uid decides.
            ensure_enrollment_key_unlocked(user, &mut Account::new(user), &|_, _, _| false).unwrap()
        };
        let unpublished = replace();
        assert_eq!(recorded(), Some(5102));
        assert!(has_recovery(user), "kept until the enrollment is published");
        unpublished.settle(None).unwrap();
        assert_eq!(recorded(), Some(5101), "the replaced key goes back");
        assert!(has_recovery(user));
        let replacement = replace();
        let second = Zeroizing::new(replacement.as_slice().to_vec());
        assert_ne!(&*second, &*first, "the account gets a key of its own");
        replacement
            .settle(Some(&irlume_common::AtomicWrite::Durable))
            .unwrap();
        assert_eq!(recorded(), Some(5102));
        assert!(!has_recovery(user), "the replaced key's recovery file goes");

        let mut legacy = SealedEnvelope::load(&key_path(user)).unwrap();
        legacy.uid = None;
        legacy.save(&key_path(user)).unwrap();
        assert_eq!(&*load_key(user).unwrap(), &*second);
        reseal_key(user, &second).unwrap();
        assert_eq!(recorded(), Some(5102));

        forget_key(user).unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn tpm_key_and_recovery_lifecycle() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", crate::test_tmp_dir("tk-rt"));
        std::env::set_var("IRLUME_RECOVERY_DIR", crate::test_tmp_dir("rec-tpm"));
        let _ = std::fs::remove_dir_all(crate::test_tmp_dir("tk-rt"));
        let _ = std::fs::remove_dir_all(crate::test_tmp_dir("rec-tpm"));

        let k1 = ensure_key("rt").unwrap();
        assert!(has_key("rt"));
        // Stable across calls.
        assert_eq!(&*load_key("rt").unwrap(), &*k1);

        setup_recovery("rt", b"my recovery passphrase").unwrap();
        assert!(has_recovery("rt"));

        // Simulate seal loss (dbx move / TPM clear) and restore.
        forget_key("rt").unwrap();
        assert!(!has_key("rt"));
        restore_from_recovery("rt", b"my recovery passphrase").unwrap();
        assert!(has_key("rt"));
        assert_eq!(
            &*load_key("rt").unwrap(),
            &*k1,
            "restored key must match original"
        );

        // Only setting a passphrase has the floor: an envelope written under
        // a short one before it existed still restores.
        save_recovery("rt", &crate::recovery::wrap(b"1234", &k1).unwrap()).unwrap();
        assert!(setup_recovery("rt", b"1234").is_err());
        forget_key("rt").unwrap();
        restore_from_recovery("rt", b"1234").unwrap();
        assert_eq!(
            &*load_key("rt").unwrap(),
            &*k1,
            "an envelope under a short passphrase must still restore"
        );

        forget_key("rt").unwrap();
        forget_recovery("rt").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// A wrong recovery passphrase must fail the restore WITHOUT materialising a
    /// key file: a bogus key would let the daemon "unseal" garbage and silently
    /// destroy the encrypted templates. No TPM needed (unwrap fails before the
    /// re-seal), so this seeds the envelope directly via save_recovery.
    #[test]
    fn recovery_restore_rejects_wrong_passphrase() {
        let _g = ENV_LOCK.lock().unwrap();
        let rec = crate::test_tmp_dir("rec-wrongpass");
        let tk = crate::test_tmp_dir("tk-wrongpass");
        let _ = std::fs::remove_dir_all(&rec);
        let _ = std::fs::remove_dir_all(&tk);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &tk);

        let key = crypto::generate_key();
        let env = crate::recovery::wrap(b"correct horse battery", &key).unwrap();
        save_recovery("rt", &env).unwrap();

        let err = restore_from_recovery("rt", b"wrong passphrase").unwrap_err();
        // GCM auth failure surfaces as a decrypt error (Error::Policy), not a panic.
        let msg = format!("{err}");
        assert!(msg.contains("wrong recovery passphrase"), "got: {msg}");
        assert!(
            !has_key("rt"),
            "a failed restore must not create a key file"
        );

        forget_recovery("rt").unwrap();
        std::env::remove_var("IRLUME_RECOVERY_DIR");
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
    }

    /// Setting a recovery passphrase below the floor is refused before the
    /// state lock or any file is touched, so an envelope set earlier stays as
    /// it was; 12 characters pass the floor and reach the key lookup (no
    /// sealed key here, so no TPM is needed).
    #[test]
    fn setup_recovery_refuses_a_short_passphrase_and_keeps_the_envelope() {
        let _g = ENV_LOCK.lock().unwrap();
        let rec = crate::test_tmp_dir("rec-floor");
        let tk = crate::test_tmp_dir("tk-floor");
        let _ = std::fs::remove_dir_all(&rec);
        let _ = std::fs::remove_dir_all(&tk);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &tk);

        let env = crate::recovery::wrap(b"1234", &crypto::generate_key()).unwrap();
        save_recovery("rt", &env).unwrap();
        let before = std::fs::read(recovery_path("rt")).unwrap();

        for short in [&b""[..], b"elevenchars", "ééééééééééé".as_bytes()] {
            let err = setup_recovery("rt", short).unwrap_err();
            assert!(
                matches!(&err, Error::Policy(message) if message.contains("recovery passphrase")),
                "{short:?}: {err:?}"
            );
            assert_eq!(std::fs::read(recovery_path("rt")).unwrap(), before);
        }
        assert!(
            !std::path::Path::new(&tk).exists(),
            "a refused passphrase must not reach the state lock"
        );

        let err = setup_recovery("rt", b"twelve chars").unwrap_err();
        assert!(
            err.to_string().contains("no template key sealed for 'rt'"),
            "got: {err}"
        );
        assert_eq!(std::fs::read(recovery_path("rt")).unwrap(), before);

        let _ = std::fs::remove_dir_all(&rec);
        let _ = std::fs::remove_dir_all(&tk);
        std::env::remove_var("IRLUME_RECOVERY_DIR");
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
    }

    /// Restore with no envelope on disk errors with the guidance message rather
    /// than a bare not-found, so the greeter/CLI can tell the user what to do.
    #[test]
    fn recovery_restore_errors_without_envelope() {
        let _g = ENV_LOCK.lock().unwrap();
        let rec = crate::test_tmp_dir("rec-none");
        let _ = std::fs::remove_dir_all(&rec);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);

        let err = restore_from_recovery_unlocked("nobody", b"whatever").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no recovery passphrase set"), "got: {msg}");

        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// A truncated / hand-edited recovery file must error out of the JSON parse,
    /// never panic: a corrupt backstop should degrade to "use your password",
    /// not crash the daemon mid-login.
    #[test]
    fn recovery_restore_rejects_corrupt_envelope() {
        let _g = ENV_LOCK.lock().unwrap();
        let rec = crate::test_tmp_dir("rec-corrupt");
        let _ = std::fs::remove_dir_all(&rec);
        std::fs::create_dir_all(&rec).unwrap();
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);

        std::fs::write(recovery_path("rt"), b"{ not valid json ").unwrap();
        let err = restore_from_recovery_unlocked("rt", b"x").unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");

        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// The core recovery promise on real hardware: if the sealed key on disk can
    /// no longer be unsealed (here a bit-flip in the TPM-sealed private blob,
    /// standing in for a PCR move / dbx update), load_key FAILS (auth falls back
    /// to the password) and `recovery restore` heals it back to the ORIGINAL key
    /// so already-encrypted templates decrypt again.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn tpm_tampered_seal_falls_back_then_recovery_heals() {
        let _g = ENV_LOCK.lock().unwrap();
        let tk = crate::test_tmp_dir("tk-tamper");
        let rec = crate::test_tmp_dir("rec-tamper");
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &tk);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);
        let _ = std::fs::remove_dir_all(tk);
        let _ = std::fs::remove_dir_all(rec);

        let original = ensure_key("rt").unwrap();
        setup_recovery("rt", b"my recovery passphrase").unwrap();

        // Corrupt the sealed private blob so the TPM can no longer unseal it.
        let mut env = SealedEnvelope::load(&key_path("rt")).unwrap();
        assert!(!env.private.is_empty());
        env.private[0] ^= 0xff;
        env.save(&key_path("rt")).unwrap();
        assert!(load_key("rt").is_err(), "a tampered seal must not unseal");

        // Recovery heals it: unwrap under the passphrase, re-seal to current PCRs.
        restore_from_recovery("rt", b"my recovery passphrase").unwrap();
        assert_eq!(
            &*load_key("rt").unwrap(),
            &*original,
            "recovered key must match the original that encrypted the templates"
        );

        forget_key("rt").unwrap();
        forget_recovery("rt").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// On signed-UKI hardware, a template key an earlier release sealed under
    /// the signed Tier 1 policy moves to a bound policy (literal PCR 7, or
    /// pcrlock) the next time it is loaded outside an authentication request
    /// (irlumed's start, through [`move_to_stronger_policy`]), with no
    /// re-enroll. Companion to the keyring reseal upgrade.
    #[test]
    #[ignore = "requires a real TPM + fresh systemd signed-PCR artifacts (UKI/systemd-boot)"]
    fn load_key_moves_a_signed_seal_to_a_bound_policy() {
        use crate::crypto;
        use crate::envelope::PolicyKind;
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", crate::test_tmp_dir("tk-upg"));
        let _ = std::fs::remove_dir_all(crate::test_tmp_dir("tk-upg"));
        std::fs::create_dir_all(crate::test_tmp_dir("tk-upg")).unwrap();

        let key = crypto::generate_key();
        // Simulate an "old" seal under the signed policy earlier releases chose.
        crate::tpm::seal_authorized(&key)
            .unwrap()
            .save(&key_path("rt"))
            .unwrap();
        assert!(
            matches!(
                SealedEnvelope::load(&key_path("rt")).unwrap().policy,
                PolicyKind::Authorized { .. }
            ),
            "precondition: sealed at Tier 1"
        );
        // A load (what every match does) returns the key AND moves the seal.
        assert_eq!(&*load_key("rt").unwrap(), &*key);
        let env = SealedEnvelope::load(&key_path("rt")).unwrap();
        assert!(
            matches!(
                env.policy,
                PolicyKind::PcrLiteral | PolicyKind::PcrlockNv { .. }
            ),
            "should move to a bound policy, got {:?}",
            env.policy
        );
        assert_eq!(
            &*load_key("rt").unwrap(),
            &*key,
            "still loads after upgrade"
        );
        forget_key("rt").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
    }
}
