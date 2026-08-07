// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! TPM-sealed login password for keyring/wallet unlock.
//!
//! After a face login there is no typed password for `pam_gnome_keyring` /
//! `pam_kwallet` to unlock the wallet with. We bridge that gap: at setup the
//! user's login password is sealed in the TPM ([`tpm`]), and on a successful
//! live face match `irlumed` unseals it and hands it to the PAM module, which
//! sets it as `PAM_AUTHTOK` so the downstream keyring module unlocks the wallet.
//!
//! The sealed envelope is stored ROOT-ONLY under `/var/lib/irlume/keyring`
//! (override `IRLUME_KEYRING_DIR`), deliberately NOT in the user's home (where
//! the templates live), so the wrapped login secret is never under user control.
//! It is TPM-wrapped regardless, but defence in depth.

use crate::envelope::{SealedEnvelope, SecretKind};
use crate::tpm;
use irlume_common::{Error, Result};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Root-only directory for sealed-password envelopes.
// See the template-key note: the fallback must honor `IRLUME_STATE_DIR`, or a
// sandboxed root `keyring forget` deletes the live armed seal.
fn keyring_dir() -> PathBuf {
    std::env::var("IRLUME_KEYRING_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| irlume_common::state_dir().join("keyring"))
}

pub fn envelope_path(user: &str) -> PathBuf {
    keyring_dir().join(format!("{user}.json"))
}

/// Seal `password` for `user` so a later face login can release it. Overwrites
/// any existing sealed password (re-arming, e.g. after a password change).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn seal_password(user: &str, password: &[u8]) -> Result<()> {
    seal_secret(user, password, SecretKind::LoginPassword)
}

/// Seal `secret` for `user`, recording what it is.
///
/// The kind is stamped here rather than in [`tpm::seal`], which wraps bytes and
/// has no business knowing what they mean.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn seal_secret(user: &str, secret: &[u8], kind: SecretKind) -> Result<()> {
    if kind == SecretKind::GnomeKeyringToken {
        // Tokens are armed through [`arm_gnome_token`], which mints the bytes
        // and writes the password wrap in the same envelope. Accepting one here
        // would write a token envelope with no wrap, and the first PCR drift
        // would strand the keyring it was re-keyed to.
        return Err(Error::Protocol(
            "a GNOME keyring token is armed via arm_gnome_token, not sealed directly".into(),
        ));
    }
    if secret.is_empty() {
        // Keep the wording the login path has always used; the wallet key gets
        // its own so the message names what was actually empty.
        return Err(Error::Protocol(
            match kind {
                SecretKind::LoginPassword => "refusing to seal an empty password",
                SecretKind::KdeWalletKey => "refusing to seal an empty KDE wallet key",
                SecretKind::GnomeKeyringToken => unreachable!("refused above"),
            }
            .to_string(),
        ));
    }
    if kind == SecretKind::KdeWalletKey && secret.len() != crate::kwallet::KEY_LEN {
        // ksecretd reads exactly KEY_LEN bytes off the pipe. Sealing any other
        // length produces an envelope that can never open the wallet, and the
        // failure would not show up until a login.
        return Err(Error::Protocol(format!(
            "a KDE wallet key must be exactly {} bytes, got {}",
            crate::kwallet::KEY_LEN,
            secret.len()
        )));
    }
    let mut env = tpm::seal(secret)?;
    env.secret = kind;
    env.save(&envelope_path(user))
}

/// Length in bytes of entropy behind a GNOME keyring token; the token itself is
/// its lowercase-hex form (64 ASCII characters), because the keyring credential
/// is a string and hex survives every string channel it must cross (the control
/// socket, PAM data, the daemon wire) without escaping.
pub const GNOME_TOKEN_BYTES: usize = 32;

/// Mint a fresh keyring token: 256 bits from the OS RNG, hex-encoded.
fn mint_gnome_token() -> Zeroizing<String> {
    use rand::Rng;
    let mut raw = Zeroizing::new([0u8; GNOME_TOKEN_BYTES]);
    rand::rng().fill_bytes(&mut *raw);
    let mut out = Zeroizing::new(String::with_capacity(GNOME_TOKEN_BYTES * 2));
    for b in raw.iter() {
        use std::fmt::Write;
        // Infallible for String; expect() documents that rather than unwrap.
        write!(out, "{b:02x}").expect("writing hex to a String cannot fail");
    }
    out
}

/// Arm GNOME-keyring unlock for `user`: mint a token, seal it in the TPM, wrap
/// it under the VERIFIED login `password` (the recovery path for PCR drift),
/// save the envelope, and return the token so the caller can re-key the login
/// keyring to it.
///
/// Ordering is load-bearing: the envelope is durable BEFORE the caller re-keys
/// the keyring. A crash after this returns but before the re-key leaves the
/// keyring still keyed to the password (the envelope's token merely goes
/// unused until a re-arm); the other order would re-key the keyring to a token
/// that no longer exists anywhere, which is unrecoverable.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn arm_gnome_token(user: &str, password: &[u8]) -> Result<Zeroizing<String>> {
    if password.is_empty() {
        return Err(Error::Protocol(
            "refusing to arm a keyring token for an empty password".into(),
        ));
    }
    let token = mint_gnome_token();
    let mut env = tpm::seal(token.as_bytes())?;
    env.secret = SecretKind::GnomeKeyringToken;
    env.password_wrap = Some(crate::recovery::wrap(password, token.as_bytes())?);
    env.save(&envelope_path(user))?;
    Ok(token)
}

/// Re-arm an EXISTING token envelope, reusing its token.
///
/// Minting a fresh token here would be the trap: the login keyring's current
/// credential is the old token, so the caller's `CHANGE(password -> new)`
/// would be denied while the only copy of the old token had already been
/// overwritten, stranding the keyring permanently. Instead the existing token
/// is recovered (TPM seal first, password wrap second, so this also works
/// after PCR drift), the envelope is rebuilt against today's policy and
/// re-wrapped under the possibly-new password, and the SAME token is returned.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn rearm_gnome_token(user: &str, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let path = envelope_path(user);
    let env = SealedEnvelope::load(&path)?;
    if env.secret != SecretKind::GnomeKeyringToken {
        return Err(Error::Policy(format!(
            "'{user}' has a {} armed, not a keyring token",
            env.secret.describe()
        )));
    }
    let token = match tpm::unseal(&env) {
        Ok(t) => t,
        Err(unseal_err) => {
            let Some(wrap) = env.password_wrap.as_ref() else {
                return Err(Error::Policy(format!(
                    "keyring token for '{user}': TPM unseal failed ({unseal_err}) and the \
                     envelope has no password wrap; `irlume keyring forget --force` and re-arm"
                )));
            };
            crate::recovery::unwrap(password, wrap).map_err(|_| {
                Error::Policy(format!(
                    "keyring token for '{user}': TPM unseal failed ({unseal_err}) and this \
                     password does not open the recovery wrap; envelope left untouched"
                ))
            })?
        }
    };
    let mut fresh = tpm::seal(&token)?;
    fresh.secret = SecretKind::GnomeKeyringToken;
    fresh.password_wrap = Some(crate::recovery::wrap(password, &token)?);
    fresh.save(&path)?;
    Ok(token)
}

/// Derive the secret of `kind` that `user` should have sealed, from their
/// VERIFIED login password.
///
/// For [`SecretKind::KdeWalletKey`] this is PBKDF2 over the wallet salt in
/// `home`, matching what `pam_kwallet5` computes. Note what that implies after
/// a password change: the wallet is still keyed to the OLD derived key until
/// the user re-keys it in KWallet, so deriving from the new password yields a
/// key that does not open it. That is not a regression we introduce; it is
/// exactly what `pam_kwallet5` does with the new password, and the user fixes
/// it the same way, by changing the wallet password.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn derive_secret(
    kind: SecretKind,
    password: &[u8],
    home: Option<&std::path::Path>,
) -> Result<Zeroizing<Vec<u8>>> {
    match kind {
        // A login password needs no home, and demanding one would strand any
        // account NSS cannot resolve a home directory for.
        SecretKind::LoginPassword => Ok(Zeroizing::new(password.to_vec())),
        SecretKind::KdeWalletKey => match home {
            Some(h) => crate::kwallet::derive_for_home(password, h),
            None => Err(Error::Policy(
                "a KDE wallet key needs the user's home directory, and none could be resolved"
                    .into(),
            )),
        },
        // Random by construction. Every caller that wants "the secret this
        // password implies" must not exist for tokens; the reseal path handles
        // them through the envelope's password_wrap instead.
        SecretKind::GnomeKeyringToken => Err(Error::Policy(
            "a GNOME keyring token is random and cannot be derived from the password".into(),
        )),
    }
}

/// What kind of secret `user` currently has armed, if any.
pub fn sealed_kind(user: &str) -> Option<SecretKind> {
    SealedEnvelope::load(&envelope_path(user))
        .ok()
        .map(|e| e.secret)
}

/// Every sealed envelope on this machine, as `(user, kind)`.
///
/// Enumerates the ENVELOPE directory, not enrolled users: `keyring arm` does
/// not require an enrollment, so a user can hold a sealed token and never
/// appear in `storage::list_users()`.
///
/// Any unreadable or malformed envelope is an ERROR, never a skipped entry. A
/// destructive caller cannot assume the kind of an envelope it could not read,
/// and the difference between "no token here" and "could not tell" is the
/// difference between a safe teardown and erasing the only copy of the secret
/// a login keyring is encrypted under.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn list_sealed_kinds() -> Result<Vec<(String, SecretKind)>> {
    let dir = keyring_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        // A machine that never armed anything has no directory, which is a
        // real answer: nothing is sealed.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(format!("read {}: {e}", dir.display()))),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::Io(format!("read {}: {e}", dir.display())))?;
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let user = path
            .file_stem()
            .and_then(|x| x.to_str())
            .ok_or_else(|| {
                Error::Protocol(format!("unreadable envelope name: {}", path.display()))
            })?
            .to_string();
        let env = SealedEnvelope::load(&path)?;
        out.push((user, env.secret));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// A released secret together with what it is.
pub struct Unsealed {
    pub secret: Zeroizing<Vec<u8>>,
    pub kind: SecretKind,
}

/// Release `user`'s sealed secret from the TPM, and say what it is.
///
/// One envelope load produces both. Reading the bytes and then re-reading the
/// file for its kind is two observations of something a concurrent `keyring
/// arm` can replace between them, which would tag one envelope's bytes with
/// another's kind: a 56-byte wallet key routed into `PAM_AUTHTOK`, or a
/// password sent to the wallet daemon. It also removes the second read's
/// failure path, which collapsed "could not read the kind" into "login
/// password" and let an unreadable file authorise the wrong delivery.
///
/// Fails if none is armed or if the bound PCR policy is no longer satisfied
/// (e.g. Secure Boot config changed); the caller then falls back to the typed
/// password and the wallet stays locked until the user re-arms.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn unseal_secret(user: &str) -> Result<Unsealed> {
    let path = envelope_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!(
            "no sealed password for '{user}': run `irlume keyring arm`"
        )));
    }
    let env = SealedEnvelope::load(&path)?;
    let kind = env.secret;
    Ok(Unsealed {
        secret: tpm::unseal(&env)?,
        kind,
    })
}

/// Release `user`'s sealed secret, discarding what kind it is.
///
/// Only for callers that genuinely do not route on the kind. Anything that
/// delivers the secret somewhere must use [`unseal_secret`].
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn unseal_password(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    unseal_secret(user).map(|u| u.secret)
}

/// Outcome of [`reseal_password`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reseal {
    /// No sealed password is armed for this user; nothing was done. We never
    /// auto-arm from the login hook; arming stays an explicit `keyring arm`.
    NotArmed,
    /// The existing envelope already unseals to this exact password under the
    /// current PCR policy; left untouched (the steady-state on every login).
    Unchanged,
    /// The envelope was re-sealed against the current PCR policy. Either it no
    /// longer unsealed (PCRs moved: dbx/Secure Boot update) or the password
    /// differed (the user changed it). This is the self-heal.
    Resealed,
    /// The password and PCR policy were unchanged, but a stronger sealing tier
    /// became available (e.g. signed-PCR started working), so the envelope was
    /// re-sealed to that tier. Lets an existing arm climb to Tier 1 on the next
    /// login with no `keyring arm` from the user.
    Upgraded,
}

/// Self-heal: re-seal `user`'s login password against the *current* PCR policy,
/// but only when it's both armed and actually stale.
///
/// SAFETY CONTRACT: the caller MUST pass only a password that has been
/// VERIFIED correct (i.e. `pam_unix` accepted it). This function cannot tell a
/// genuine new password from a typo on its own; that guarantee comes from
/// WHERE it is called: the PAM **session** phase, which only runs after
/// authentication has already succeeded. (An earlier version called it from an
/// `optional` auth line that also ran after a FAILED password attempt, which let
/// a typo overwrite the good seal; that path has been deleted. Never call this
/// anywhere auth success is not already established.)
///
/// Given a verified password it writes nothing in the common case:
///   * not armed            -> `NotArmed` (never auto-arm)
///   * unseals to same `pw` -> `Unchanged` (PCRs still match, password same)
///   * unseal fails OR diff  -> reseal, `Resealed`
///
/// The "unseal fails" branch is what fixes a dbx/Secure-Boot update: the old
/// envelope's PCR7 policy no longer satisfies, so we rebind to today's PCRs
/// using the password the user just proved (via a successful login) they know.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn reseal_password(
    user: &str,
    password: &[u8],
    home: Option<&std::path::Path>,
) -> Result<Reseal> {
    if password.is_empty() {
        return Err(Error::Protocol(
            "refusing to reseal an empty password".into(),
        ));
    }
    if !has_sealed_password(user) {
        return Ok(Reseal::NotArmed);
    }
    // Reseal whatever kind is already armed. Deriving the wrong kind here would
    // quietly replace a working envelope with one that opens nothing, and the
    // damage would not show up until the next login. A LOAD error must
    // propagate rather than default the kind: defaulting an unreadable token
    // envelope to `LoginPassword` would overwrite it with a password seal
    // below, and the keyring it was re-keyed to would be stranded.
    let env = SealedEnvelope::load(&envelope_path(user))?;
    let kind = env.secret;
    if kind == SecretKind::GnomeKeyringToken {
        return reseal_token(user, password, env);
    }
    let secret = match derive_secret(kind, password, home) {
        Ok(s) => s,
        // A KDE wallet key cannot be derived without the salt. Leaving the
        // existing envelope alone is the safe outcome: it may still be valid,
        // and overwriting it on a machine where the salt has gone missing would
        // destroy a working arm.
        Err(e) => {
            return Err(Error::Policy(format!(
                "cannot reseal the {} for '{user}': {e}",
                kind.describe()
            )))
        }
    };
    let password = secret.as_slice();
    // If the current envelope still unseals to the same secret, there is nothing
    // to reseal for correctness; don't churn the TPM on every single login.
    if let Ok(current) = unseal_password(user) {
        if current.as_slice() == password {
            // One exception: if a strictly stronger sealing tier became
            // available since this envelope was written (e.g. signed-PCR now
            // works), climb to it. This is how an existing arm reaches Tier 1
            // after a fix/config change without the user re-arming. Only fires
            // when an upgrade is actually possible, and only adopts the new
            // envelope if the ladder genuinely produced a stronger tier (it
            // round-trip-verifies internally), so a machine already at its best
            // tier writes nothing.
            if let Ok(env) = SealedEnvelope::load(&envelope_path(user)) {
                if tpm::stronger_tier_available_than(&env.policy) {
                    let mut candidate = tpm::seal(password)?;
                    // Carry the kind across the upgrade. tpm::seal defaults it,
                    // so without this a tier climb would rewrite a wallet-key
                    // envelope as a login-password one and the next login would
                    // hand 56 bytes of key to pam_gnome_keyring as an AUTHTOK.
                    candidate.secret = kind;
                    if candidate.policy.strength_rank() > env.policy.strength_rank() {
                        candidate.save(&envelope_path(user))?;
                        return Ok(Reseal::Upgraded);
                    }
                }
            }
            return Ok(Reseal::Unchanged);
        }
    }
    seal_secret(user, password, kind)?;
    Ok(Reseal::Resealed)
}

/// The token half of [`reseal_password`]. A token cannot be re-derived, so the
/// self-heal runs through the envelope itself: the TPM seal and the password
/// wrap each recover the other.
///
///   * seal unseals, wrap opens under `password`  -> `Unchanged` (or the same
///     tier climb the password kinds get)
///   * seal unseals, wrap does not open           -> the user changed their
///     password; re-wrap under the new one, `Resealed`
///   * seal fails, wrap opens                     -> PCR drift; re-seal the
///     recovered token, `Resealed`
///   * both fail                                  -> error, envelope untouched:
///     it may still be the only copy of the token, and the caller's password,
///     though PAM-verified, may simply be newer than the wrap
fn reseal_token(user: &str, password: &[u8], env: SealedEnvelope) -> Result<Reseal> {
    match tpm::unseal(&env) {
        Ok(token) => {
            let wrap_current = env.password_wrap.as_ref().is_some_and(|w| {
                crate::recovery::unwrap(password, w).is_ok_and(|t| t.as_slice() == token.as_slice())
            });
            if !wrap_current {
                // Only the wrap is stale (password change, or an envelope
                // missing its wrap): refresh it and keep the seal as-is.
                let mut env = env;
                env.password_wrap = Some(crate::recovery::wrap(password, &token)?);
                env.save(&envelope_path(user))?;
                return Ok(Reseal::Resealed);
            }
            if tpm::stronger_tier_available_than(&env.policy) {
                let mut candidate = tpm::seal(&token)?;
                // tpm::seal knows nothing of kinds or wraps; dropping either
                // here would downgrade the envelope to a password seal (next
                // login routes the token into PAM_AUTHTOK) or amputate the
                // recovery path until the next password change.
                candidate.secret = SecretKind::GnomeKeyringToken;
                candidate.password_wrap = env.password_wrap.clone();
                if candidate.policy.strength_rank() > env.policy.strength_rank() {
                    candidate.save(&envelope_path(user))?;
                    return Ok(Reseal::Upgraded);
                }
            }
            Ok(Reseal::Unchanged)
        }
        Err(unseal_err) => {
            let Some(wrap) = env.password_wrap.as_ref() else {
                return Err(Error::Policy(format!(
                    "keyring token for '{user}': TPM unseal failed ({unseal_err}) and the \
                     envelope has no password wrap to recover from; run `irlume keyring arm`"
                )));
            };
            let token = crate::recovery::unwrap(password, wrap).map_err(|_| {
                Error::Policy(format!(
                    "keyring token for '{user}': TPM unseal failed ({unseal_err}) and this \
                     password does not open the recovery wrap (wrapped under an older \
                     password?); envelope left untouched"
                ))
            })?;
            let mut fresh = tpm::seal(&token)?;
            fresh.secret = SecretKind::GnomeKeyringToken;
            fresh.password_wrap = Some(crate::recovery::wrap(password, &token)?);
            fresh.save(&envelope_path(user))?;
            Ok(Reseal::Resealed)
        }
    }
}

/// Release `user`'s sealed GNOME keyring token to a caller who proves they
/// know the login password, for `keyring forget`'s re-key-back step.
///
/// The proof is the envelope's own password wrap: only the right password
/// opens it (AES-GCM authenticates), so no shadow lookup is needed, and it
/// works with the TPM seal broken, which is exactly when a disarm matters
/// most. Fails closed: a wrong password, a stale wrap (password changed with
/// no login since), and a non-token envelope are all refusals, each named.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn release_token_with_password(user: &str, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let path = envelope_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!("no sealed secret for '{user}'")));
    }
    let env = SealedEnvelope::load(&path)?;
    if env.secret != SecretKind::GnomeKeyringToken {
        return Err(Error::Policy(format!(
            "'{user}' has a {} armed, not a keyring token; nothing to release for a disarm",
            env.secret.describe()
        )));
    }
    let Some(wrap) = env.password_wrap.as_ref() else {
        return Err(Error::Policy(format!(
            "keyring token for '{user}' has no password wrap; cannot verify the password"
        )));
    };
    crate::recovery::unwrap(password, wrap).map_err(|_| {
        Error::Policy(
            "that password does not open the token's recovery wrap; if you changed your \
             password recently and have not logged in since, use the previous one"
                .into(),
        )
    })
}

/// Whether `user` has a sealed password armed.
pub fn has_sealed_password(user: &str) -> bool {
    envelope_path(user).exists()
}

/// Erase `user`'s sealed password (disarms keyring unlock). Idempotent.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn forget_password(user: &str) -> Result<()> {
    let path = envelope_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    /// The armed seal is live cryptographic state; a sandboxed root `keyring
    /// forget` must delete the sandbox copy, never `/var/lib/irlume/keyring`.
    #[test]
    fn sandbox_override_contains_keyring_dir() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let sandbox = crate::test_tmp_dir("sandbox-containment-kr");
        std::env::remove_var("IRLUME_KEYRING_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &sandbox);
        let env = envelope_path("someuser");
        std::env::remove_var("IRLUME_STATE_DIR");
        assert!(
            env.starts_with(&sandbox),
            "keyring envelope escaped the sandbox: {}",
            env.display()
        );
        assert!(!env.starts_with(irlume_common::STATE_DIR));
    }

    use super::*;

    #[test]
    fn envelope_path_under_keyring_dir() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_KEYRING_DIR", crate::test_tmp_dir("kr-test"));
        assert_eq!(
            envelope_path("alice"),
            PathBuf::from(format!("{}/alice.json", crate::test_tmp_dir("kr-test")))
        );
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// Full arm → unseal round-trip through the keyring layer on the real TPM.
    /// Ignored: needs /dev/tpmrm0.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn arm_and_unseal_roundtrip() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-rt");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);
        let pw = b"correct horse battery staple";
        seal_password("tester", pw).expect("seal");
        assert!(has_sealed_password("tester"));
        let got = unseal_password("tester").expect("unseal");
        assert_eq!(&*got, pw);
        forget_password("tester").expect("forget");
        assert!(!has_sealed_password("tester"));
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// On signed-UKI hardware, an envelope armed under a weaker tier auto-upgrades
    /// to Tier-1 on the next login-time reseal, with no `keyring arm` from the
    /// user. This is the migration path after signed-PCR started working.
    #[test]
    #[ignore = "requires a real TPM + fresh systemd signed-PCR artifacts (UKI/systemd-boot)"]
    fn reseal_auto_upgrades_weaker_tier_to_signed() {
        use crate::envelope::{PolicyKind, SealedEnvelope};
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-upgrade");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);
        let pw = b"correct horse battery staple";
        // Simulate an "old" arm under the weakest tier (literal PCR 7).
        tpm::seal_with_pcrs(pw, &[7])
            .unwrap()
            .save(&envelope_path("tester"))
            .unwrap();
        assert_eq!(
            SealedEnvelope::load(&envelope_path("tester"))
                .unwrap()
                .policy
                .strength_rank(),
            1,
            "precondition: sealed at Tier 3 (literal)"
        );
        // A login-time reseal with the same verified password upgrades the tier.
        assert_eq!(
            // A login-password envelope never reads `home`: derive_secret
            // returns the password unchanged.
            reseal_password("tester", pw, None).unwrap(),
            Reseal::Upgraded
        );
        let env = SealedEnvelope::load(&envelope_path("tester")).unwrap();
        assert!(
            matches!(env.policy, PolicyKind::Authorized { .. }),
            "should climb to Tier 1, got {:?}",
            env.policy
        );
        assert_eq!(&*unseal_password("tester").unwrap(), pw, "still unseals");
        forget_password("tester").unwrap();
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    #[test]
    fn a_wallet_key_must_be_exactly_the_length_ksecretd_reads() {
        // Caught before the TPM is involved, because a wrong-length seal is only
        // discoverable at a login otherwise: ksecretd blocks on a short key and
        // truncates a long one, and neither says anything.
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_KEYRING_DIR", crate::test_tmp_dir("kr-len"));
        for bad in [crate::kwallet::KEY_LEN - 1, crate::kwallet::KEY_LEN + 1] {
            assert!(
                seal_secret("lentest", &vec![7u8; bad], SecretKind::KdeWalletKey).is_err(),
                "{bad} bytes was accepted as a wallet key"
            );
        }
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// A wallet-key envelope must stay a wallet-key envelope across every path
    /// that rewrites it. Both rewrite sites in `reseal_password` build a fresh
    /// envelope via `tpm::seal`, which defaults the kind, so a missed stamp
    /// downgrades the envelope to `LoginPassword` and the next login hands 56
    /// bytes of raw key to `pam_gnome_keyring` as an `AUTHTOK`.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn resealing_preserves_the_secret_kind() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-kind");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);

        // A home with a real salt, so the wallet key can actually be derived.
        let home = std::path::PathBuf::from(crate::test_tmp_dir("kr-kind-home"));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(crate::kwallet::salt_path(&home).parent().unwrap()).unwrap();
        std::fs::write(
            crate::kwallet::salt_path(&home),
            [0x33u8; crate::kwallet::SALT_LEN],
        )
        .unwrap();

        let pw = b"a-login-password";
        let key = crate::kwallet::derive_for_home(pw, &home).expect("derive");

        // Seed at the WEAKEST tier on purpose. Sealing normally lands on this
        // machine's best tier, so the reseal returns Unchanged and the tier-climb
        // rewrite never runs: the assertion below then passes without observing
        // the path it names. Verified by breaking the stamp, which went unnoticed
        // until this seeding was added.
        let mut weak = tpm::seal_with_pcrs(&key, &[7]).expect("seal at Tier 3");
        weak.secret = SecretKind::KdeWalletKey;
        weak.save(&envelope_path("kindtest")).expect("arm");
        assert_eq!(sealed_kind("kindtest"), Some(SecretKind::KdeWalletKey));

        // Same password, weaker tier on disk -> the tier-climb rewrite.
        let first = reseal_password("kindtest", pw, Some(&home)).expect("reseal");
        assert_eq!(
            first,
            Reseal::Upgraded,
            "expected the tier-climb rewrite; without it this test cannot see \
             whether that path preserves the kind"
        );
        assert_eq!(
            sealed_kind("kindtest"),
            Some(SecretKind::KdeWalletKey),
            "the {first:?} path dropped the secret kind"
        );

        // A changed password takes the Resealed path, which rebuilds the
        // envelope from scratch.
        assert_eq!(
            reseal_password("kindtest", b"a-different-password", Some(&home)).unwrap(),
            Reseal::Resealed
        );
        assert_eq!(
            sealed_kind("kindtest"),
            Some(SecretKind::KdeWalletKey),
            "the Resealed path dropped the secret kind"
        );
        // And it holds the key derived from the NEW password, not the password.
        let expect = crate::kwallet::derive_for_home(b"a-different-password", &home).unwrap();
        assert_eq!(&*unseal_password("kindtest").unwrap(), &*expect);

        forget_password("kindtest").unwrap();
        let _ = std::fs::remove_dir_all(&home);
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    #[test]
    fn a_minted_token_is_64_hex_characters_and_never_repeats() {
        let a = mint_gnome_token();
        let b = mint_gnome_token();
        assert_eq!(a.len(), GNOME_TOKEN_BYTES * 2, "hex of 32 bytes");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "the token crosses string channels (control socket, PAM data); it must be \
             lowercase hex with nothing to escape: {a:?}"
        );
        assert_ne!(*a, *b, "two mints must not collide");
    }

    /// `seal_secret` is the generic path every other kind uses; a token must
    /// not be reachable through it, because that path writes no password wrap
    /// and the first PCR drift would then strand the re-keyed keyring with no
    /// way back.
    #[test]
    fn seal_secret_refuses_a_token_so_it_cannot_be_armed_without_a_wrap() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_KEYRING_DIR", crate::test_tmp_dir("kr-notoken"));
        let err = seal_secret("t", b"0123456789abcdef", SecretKind::GnomeKeyringToken)
            .expect_err("a token must not be sealable through the generic path");
        assert!(
            err.to_string().contains("arm_gnome_token"),
            "the error must name the right path: {err}"
        );
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// A token is random, so "the secret this password implies" has no answer.
    /// Returning the password itself here (the shape `LoginPassword` uses)
    /// would make `reseal` overwrite a live token envelope with the password,
    /// and the keyring keyed to that token would be unreachable.
    #[test]
    fn a_token_cannot_be_derived_from_a_password() {
        let err = derive_secret(SecretKind::GnomeKeyringToken, b"hunter2", None)
            .expect_err("a random token is not derivable");
        assert!(
            err.to_string().contains("random"),
            "the error must say why: {err}"
        );
    }

    /// The token self-heal matrix, which is the whole recovery story for a
    /// secret that cannot be re-derived. Each arm is checked by BREAKING one
    /// half of the envelope and asserting the other half recovers the SAME
    /// token: a reseal that produced a different token would be silent data
    /// loss (the keyring stays keyed to the old one).
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn a_token_envelope_heals_from_whichever_half_survives() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-token-heal");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);

        let pw = b"first-password";
        let token = arm_gnome_token("tok", pw).expect("arm");
        assert_eq!(
            sealed_kind("tok"),
            Some(SecretKind::GnomeKeyringToken),
            "arm must stamp the kind"
        );
        assert_eq!(
            &*unseal_password("tok").unwrap(),
            token.as_bytes(),
            "the sealed bytes are the token that was returned"
        );

        // 1. Both halves current -> nothing rewritten.
        assert_eq!(
            reseal_password("tok", pw, None).unwrap(),
            Reseal::Unchanged,
            "a healthy token envelope must not churn the TPM on every login"
        );

        // 2. Password changed: the seal still opens, the wrap does not. The
        //    token must survive and the wrap must be re-made under the new
        //    password (proved by unwrapping with it below).
        let newpw = b"second-password";
        assert_eq!(
            reseal_password("tok", newpw, None).unwrap(),
            Reseal::Resealed
        );
        assert_eq!(
            &*unseal_password("tok").unwrap(),
            token.as_bytes(),
            "a password change must NOT change the token: the keyring is keyed to it"
        );
        let env = SealedEnvelope::load(&envelope_path("tok")).unwrap();
        let wrap = env.password_wrap.as_ref().expect("wrap kept");
        assert_eq!(
            &*crate::recovery::unwrap(newpw, wrap).expect("wrap now opens with the new password"),
            token.as_bytes()
        );
        assert!(
            crate::recovery::unwrap(pw, wrap).is_err(),
            "the old password must no longer open the wrap"
        );

        // 3. PCR drift: replace the seal with one that cannot unseal, leaving
        //    the wrap intact. Recovery must come from the wrap and produce the
        //    same token, re-sealed against today's policy.
        let mut broken = SealedEnvelope::load(&envelope_path("tok")).unwrap();
        broken.private = vec![0u8; broken.private.len()];
        broken.save(&envelope_path("tok")).unwrap();
        assert!(
            unseal_password("tok").is_err(),
            "precondition: the seal must really be broken, or this arm proves nothing"
        );
        assert_eq!(
            reseal_password("tok", newpw, None).unwrap(),
            Reseal::Resealed,
            "a broken seal with a good wrap must heal"
        );
        assert_eq!(
            &*unseal_password("tok").unwrap(),
            token.as_bytes(),
            "healing must restore the SAME token, not mint a new one"
        );

        // 4. Both halves broken: refuse and leave the envelope alone. It may
        //    be the only copy of the token, and a wrong-password caller must
        //    not be able to destroy it.
        let mut broken = SealedEnvelope::load(&envelope_path("tok")).unwrap();
        broken.private = vec![0u8; broken.private.len()];
        broken.save(&envelope_path("tok")).unwrap();
        let before = std::fs::read(envelope_path("tok")).unwrap();
        assert!(
            reseal_password("tok", b"a-third-password", None).is_err(),
            "no path may claim success when neither half opens"
        );
        assert_eq!(
            std::fs::read(envelope_path("tok")).unwrap(),
            before,
            "a failed heal must not rewrite the envelope"
        );

        forget_password("tok").unwrap();
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// The tier-climb rewrite must carry BOTH the kind and the password wrap.
    ///
    /// Seeded at the weakest tier on purpose: sealing normally lands on this
    /// machine's best tier, so a reseal returns `Unchanged` and the climb
    /// never runs, which made a mutant that drops the wrap survive the heal
    /// test above. Losing the wrap here is silent until the PCRs move, and
    /// then the token is unrecoverable; losing the kind routes 64 bytes of
    /// token into `PAM_AUTHTOK` on the next login. This is #253's
    /// `resealing_preserves_the_secret_kind` trap, one field wider.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn a_tier_climb_keeps_both_the_kind_and_the_recovery_wrap() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-token-climb");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);

        let pw = b"climb-password";
        let token = mint_gnome_token();
        let mut weak = tpm::seal_with_pcrs(token.as_bytes(), &[7]).expect("seal at Tier 3");
        weak.secret = SecretKind::GnomeKeyringToken;
        weak.password_wrap = Some(crate::recovery::wrap(pw, token.as_bytes()).unwrap());
        weak.save(&envelope_path("climb")).expect("arm");
        assert_eq!(
            SealedEnvelope::load(&envelope_path("climb"))
                .unwrap()
                .policy
                .strength_rank(),
            1,
            "precondition: sealed at Tier 3, or the climb below never runs"
        );

        assert_eq!(
            reseal_password("climb", pw, None).unwrap(),
            Reseal::Upgraded,
            "expected the tier-climb rewrite; without it this test cannot see whether \
             that path preserves anything"
        );

        let env = SealedEnvelope::load(&envelope_path("climb")).unwrap();
        assert_eq!(
            env.secret,
            SecretKind::GnomeKeyringToken,
            "the climb dropped the secret kind"
        );
        let wrap = env
            .password_wrap
            .as_ref()
            .expect("the climb dropped the password wrap: PCR drift would now be fatal");
        assert_eq!(
            &*crate::recovery::unwrap(pw, wrap).expect("the carried wrap must still open"),
            token.as_bytes(),
            "the carried wrap must hold the same token"
        );
        assert_eq!(
            &*unseal_password("climb").unwrap(),
            token.as_bytes(),
            "and the new seal must still hold it too"
        );

        forget_password("climb").unwrap();
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// A re-arm must hand back the EXISTING token. Minting a fresh one would
    /// overwrite the only copy of the secret the login keyring is currently
    /// keyed to, and the caller's re-key from the password would then be
    /// denied, leaving the keyring permanently unreachable.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn rearming_reuses_the_existing_token_rather_than_minting() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-rearm");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);

        let pw = b"a-password";
        let first = arm_gnome_token("re", pw).expect("arm");
        let again = rearm_gnome_token("re", pw).expect("re-arm");
        assert_eq!(
            &*again,
            first.as_bytes(),
            "a re-arm handed back a DIFFERENT token; the keyring keyed to the first \
             one would be stranded"
        );

        // Even with the seal broken, the re-arm recovers via the wrap and
        // still yields the same token.
        let mut broken = SealedEnvelope::load(&envelope_path("re")).unwrap();
        broken.private = vec![0u8; broken.private.len()];
        broken.save(&envelope_path("re")).unwrap();
        assert_eq!(
            &*rearm_gnome_token("re", pw).expect("re-arm after drift"),
            first.as_bytes()
        );
        assert!(
            unseal_password("re").is_ok(),
            "the re-arm must leave a working seal behind"
        );

        // A wrong password cannot re-arm once the seal is broken: that is the
        // only proof of identity left.
        let mut broken = SealedEnvelope::load(&envelope_path("re")).unwrap();
        broken.private = vec![0u8; broken.private.len()];
        broken.save(&envelope_path("re")).unwrap();
        assert!(rearm_gnome_token("re", b"wrong-password").is_err());

        forget_password("re").unwrap();
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// The disarm release is the one place a token leaves the daemon on a
    /// password alone, so its gate has to hold in all three failure shapes.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn releasing_a_token_for_disarm_needs_the_right_password() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-disarm");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);

        assert!(
            release_token_with_password("nobody", b"pw").is_err(),
            "nothing armed"
        );

        seal_password("pwuser", b"pw").expect("arm a password envelope");
        let err = release_token_with_password("pwuser", b"pw")
            .expect_err("a password envelope has no token to release");
        assert!(err.to_string().contains("login password"), "{err}");

        let token = arm_gnome_token("tokuser", b"right-pw").expect("arm");
        assert!(release_token_with_password("tokuser", b"wrong-pw").is_err());
        assert_eq!(
            &*release_token_with_password("tokuser", b"right-pw").expect("correct password"),
            token.as_bytes()
        );

        // It must work with the TPM seal broken: that is exactly when a user
        // needs to disarm and get their keyring back.
        let mut broken = SealedEnvelope::load(&envelope_path("tokuser")).unwrap();
        broken.private = vec![0u8; broken.private.len()];
        broken.save(&envelope_path("tokuser")).unwrap();
        assert!(unseal_password("tokuser").is_err(), "precondition");
        assert_eq!(
            &*release_token_with_password("tokuser", b"right-pw")
                .expect("the wrap must work without the TPM"),
            token.as_bytes()
        );

        forget_password("pwuser").unwrap();
        forget_password("tokuser").unwrap();
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// reseal: NotArmed when nothing sealed, Unchanged when same pw still
    /// unseals, Resealed when the password differs. The PCR-moved -> Resealed
    /// branch can't be exercised without changing PCRs, but the differ branch
    /// hits the same reseal path. (Callers gate this on a verified password via
    /// the PAM session phase; see the SAFETY CONTRACT on `reseal_password`.)
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn reseal_only_when_stale() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("kr-reseal");
        std::env::set_var("IRLUME_KEYRING_DIR", &dir);
        let _ = std::fs::remove_dir_all(dir);

        // Not armed -> nothing happens.
        assert_eq!(
            reseal_password("rt", b"whatever", None).unwrap(),
            Reseal::NotArmed
        );

        seal_password("rt", b"first-password").expect("arm");
        // Same password still unseals under current PCRs -> no rewrite.
        assert_eq!(
            reseal_password("rt", b"first-password", None).unwrap(),
            Reseal::Unchanged
        );
        // Different password (simulates a password change) -> reseal.
        assert_eq!(
            reseal_password("rt", b"second-password", None).unwrap(),
            Reseal::Resealed
        );
        // And it now unseals to the new one.
        assert_eq!(&*unseal_password("rt").unwrap(), b"second-password");

        forget_password("rt").expect("forget");
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }
}
