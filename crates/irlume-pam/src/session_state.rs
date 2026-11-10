// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Transaction-local credentials and the one-shot session-delivery guard.

use irlume_common::{KeyringSecretKind, SecretBytes};
use pamsm::{Pam, PamData, PamError, PamLibExt};
use std::sync::{Arc, Mutex};

const STASH_KEY: &str = "pam_irlume_session_v1";

#[derive(PartialEq, Eq)]
struct Binding {
    user: String,
    service: String,
}

impl Binding {
    fn read(pamh: &Pam, user: &str) -> Result<Self, PamError> {
        let service = pamh.get_service()?.ok_or(PamError::SYSTEM_ERR)?;
        let service = service.to_str().map_err(|_| PamError::SYSTEM_ERR)?;
        if user.is_empty() || service.is_empty() {
            return Err(PamError::SYSTEM_ERR);
        }
        Ok(Self {
            user: user.to_owned(),
            service: service.to_owned(),
        })
    }
}

#[derive(Default)]
pub(super) struct Secrets {
    pub(super) released: Option<(SecretBytes, KeyringSecretKind)>,
    pub(super) password: Option<SecretBytes>,
}

#[derive(Default)]
struct State {
    binding: Option<Binding>,
    secrets: Secrets,
    consumed: bool,
}

// pamsm clones typed data on retrieval, so the slot is shared: the
// credentials exist once, and marking them consumed needs no further
// pam_set_data call.
#[derive(Clone, Default)]
struct Slot(Arc<Mutex<State>>);

impl PamData for Slot {}

fn existing(pamh: &Pam) -> Result<Option<Slot>, PamError> {
    // SAFETY: only Slot is registered under this private key. The returned
    // clone owns an Arc, with no borrow spanning a PAM mutation.
    match unsafe { pamh.retrieve_data::<Slot>(STASH_KEY) } {
        Ok(slot) => Ok(Some(slot)),
        Err(PamError::NO_MODULE_DATA) => Ok(None),
        Err(error) => Err(error),
    }
}

fn slot(pamh: &Pam) -> Result<Slot, PamError> {
    if let Some(slot) = existing(pamh)? {
        return Ok(slot);
    }
    let slot = Slot::default();
    // SAFETY: this private key is registered and retrieved only as Slot.
    unsafe { pamh.send_data(STASH_KEY, slot.clone()) }?;
    Ok(slot)
}

/// Discard credentials from the previous primary authentication attempt.
pub(super) fn reset(pamh: &Pam) -> Result<(), PamError> {
    if let Some(slot) = existing(pamh)? {
        *slot.0.lock().map_err(|_| PamError::SYSTEM_ERR)? = State::default();
    }
    Ok(())
}

pub(super) fn clear_password(pamh: &Pam) -> Result<(), PamError> {
    if let Some(slot) = existing(pamh)? {
        slot.0
            .lock()
            .map_err(|_| PamError::SYSTEM_ERR)?
            .secrets
            .password = None;
    }
    Ok(())
}

fn store(
    pamh: &Pam,
    user: &str,
    secret: SecretBytes,
    kind: Option<KeyringSecretKind>,
) -> Result<(), PamError> {
    let binding = Binding::read(pamh, user)?;
    let slot = slot(pamh)?;
    let mut state = slot.0.lock().map_err(|_| PamError::SYSTEM_ERR)?;
    if state.consumed || state.binding.as_ref().is_some_and(|old| old != &binding) {
        *state = State {
            consumed: true,
            ..State::default()
        };
        return Err(PamError::SYSTEM_ERR);
    }
    state.binding = Some(binding);
    match kind {
        Some(kind) => state.secrets.released = Some((secret, kind)),
        None => state.secrets.password = Some(secret),
    }
    Ok(())
}

pub(super) fn store_released(
    pamh: &Pam,
    user: &str,
    secret: &SecretBytes,
    kind: KeyringSecretKind,
) -> bool {
    store(pamh, user, secret.clone(), Some(kind)).is_ok()
}

pub(super) fn store_password(pamh: &Pam, user: &str, bytes: &[u8]) {
    let _ = store(pamh, user, SecretBytes::new(bytes.to_vec()), None);
}

/// Mark this session consumed before any reseal, request or delivery.
pub(super) fn take(pamh: &Pam, user: &str) -> Result<Option<Secrets>, PamError> {
    let slot = slot(pamh)?;
    let mut state = slot.0.lock().map_err(|_| PamError::SYSTEM_ERR)?;
    let previous = std::mem::replace(
        &mut *state,
        State {
            consumed: true,
            ..State::default()
        },
    );
    let binding = Binding::read(pamh, user)?;
    if previous.consumed || previous.binding.is_some_and(|old| old != binding) {
        return Ok(None);
    }
    Ok(Some(previous.secrets))
}

pub(super) fn close(pamh: &Pam) {
    if let Ok(Some(slot)) = existing(pamh) {
        if let Ok(mut state) = slot.0.lock() {
            *state = State {
                consumed: true,
                ..State::default()
            };
        }
    }
}
