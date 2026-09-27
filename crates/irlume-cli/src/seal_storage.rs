// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Guidance on what protects the secrets irlume seals in the TPM at rest:
//! an armed keyring secret, and the template key that protects the face
//! templates (docs/SECURITY_AT_REST.md, layer 3).
//!
//! A TPM seal binds the boot chain it measures, not the root filesystem.
//! Where irlume's state directory is not on encrypted storage, someone with
//! the machine can change the installed system offline (for example, add a
//! service that runs as root) and boot the unchanged boot chain: the PCRs
//! then match whatever the policy is, and the sealed secrets unseal on that
//! machine. A policy that does not cover the boot loader code (PCR 4) leaves
//! a second path: another operating system signed with the same keys
//! reproduces what it binds and can unseal the secrets directly, without
//! changing the installed system. PCRs 0 to 3 measure this machine's
//! firmware, which is the same whatever it boots, and PCR 5 its partition
//! table, so adding them to PCR 7 does not close that path. It is open under
//! the literal PCR 7 policy (Tier 3), an `IRLUME_PCRS` set without PCR 4, a
//! signed PCR 11 policy (Tier 1) from an earlier release, and a pcrlock
//! policy (Tier 2) without PCR 4, which systemd-pcrlock makes when the
//! binaries measured there are not locked. A pcrlock policy that covers
//! PCR 4 closes the second path, not the first.
//!
//! What protects the sealed secrets at rest is full-disk encryption unlocked
//! by a passphrase or PIN (a volume the TPM or a key file unlocks alone does
//! not count), or an integrity-verified root filesystem (dm-verity) that
//! covers everything the boot runs and reads configuration from, with its
//! root hash bound by a pcrlock policy or a signature, together with a
//! pcrlock policy that covers PCR 4: a verified root stops the offline
//! change, not the direct unseal. A pcrlock policy is worth having in
//! addition to encryption, not instead of it.
//!
//! [`guidance`] turns what is sealed, under which policy, and what the
//! storage probe found for the state directory into a warning, information
//! or nothing. `keyring arm` prints it after a successful arm ([`arm_note`]),
//! and doctor reports it as the `sealed-storage` check ([`check`]). The probe
//! sees dm-crypt only. It cannot show whether an encrypted volume asks for a
//! passphrase or unlocks from the TPM or a key file alone, so encrypted
//! storage under a policy another operating system may reproduce is still
//! reported, as information. It does not detect a verified root, a drive's
//! hardware encryption or a filesystem's own encryption.
//!
//! The daemon reports the keyring secret's policy and the PCRs it binds, not
//! the template key's. The template key goes through the same choice of
//! policy, so where this machine has no pcrlock policy that seals use it is
//! taken to be under the literal PCR policy, and otherwise under a policy
//! irlume cannot name, which may be one another operating system reproduces.

use crate::doctor_report::State;
use irlume_common::storage_encryption::StorageEncryption;
use irlume_common::{Request, Response};
use irlume_core::envelope::PolicyKind;
use std::path::Path;

/// Where the guidance sends the reader for the detail.
const DOC: &str = "docs/SECURITY_AT_REST.md";

/// PCR 4, the boot loader code: the firmware measures the boot loader and
/// the binaries it loads there, so another operating system changes it.
const BOOT_LOADER_PCR: u32 = 4;

/// The steps to a pcrlock policy that covers PCR 4. systemd-pcrlock leaves a
/// PCR out of its policy when it cannot match that PCR's measurements to
/// locked components, and it is installed outside `PATH`.
const PCRLOCK_STEPS: &str = "lock the boot components first \
                             (`/usr/lib/systemd/systemd-pcrlock lock-pe` for a boot loader, \
                             `lock-uki` for a unified kernel image), then run \
                             `/usr/lib/systemd/systemd-pcrlock make-policy`; existing seals move \
                             to it at their next reseal";

/// Whether `policy`, as the daemon names an envelope's policy
/// (`PolicyKind::describe`), is the literal PCR policy (Tier 3).
pub(crate) fn is_literal_pcr_policy(policy: &str) -> bool {
    policy == PolicyKind::PcrLiteral.describe()
}

/// Whether `policy` names a pcrlock policy (Tier 2), whatever its NV index.
fn is_pcrlock_policy(policy: &str) -> bool {
    policy
        .strip_prefix("pcrlock NV 0x")
        .and_then(|rest| rest.strip_suffix(" (Tier 2)"))
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .is_some_and(|nv_index| PolicyKind::PcrlockNv { nv_index }.describe() == policy)
}

/// Whether `policy` names the signed PCR policy (Tier 1) earlier releases
/// wrote.
fn is_signed_pcr_policy(policy: &str) -> bool {
    policy
        == PolicyKind::Authorized {
            pubkey_pem: String::new(),
            policy_ref: Vec::new(),
        }
        .describe()
}

/// An account's keyring secret, as the daemon describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyringSeal {
    /// No keyring secret is armed.
    NotArmed,
    /// A keyring secret is armed. `policy` is the daemon's name for its
    /// policy, `None` when it did not name one (an envelope it could not
    /// read); `pcrs` are the PCRs it binds, empty when not reported.
    Armed {
        policy: Option<String>,
        pcrs: Vec<u32>,
    },
    /// The daemon could not be asked, or did not answer with a description.
    Unknown,
}

/// What irlume has sealed in the TPM for one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sealed {
    pub(crate) keyring: KeyringSeal,
    /// Whether a sealed template key exists; `None` when the daemon could
    /// not say.
    pub(crate) template_key: Option<bool>,
    /// Whether this machine has a pcrlock policy that new seals use
    /// (`irlume_core::tpm::pcrlock_for_sealing`). The daemon does not report
    /// the template key's policy; without such a pcrlock policy it is the
    /// literal PCR policy.
    pub(crate) pcrlock_seals: bool,
}

/// The keyring secret a `KeyringMetadata` or `KeyringInfo` reply describes.
fn keyring_seal(reply: &Result<Response, String>) -> KeyringSeal {
    match reply {
        Ok(Response::KeyringInfo { armed: false, .. }) => KeyringSeal::NotArmed,
        Ok(Response::KeyringInfo {
            armed: true,
            policy,
            pcrs,
            ..
        }) => KeyringSeal::Armed {
            policy: policy.clone(),
            pcrs: pcrs.clone(),
        },
        _ => KeyringSeal::Unknown,
    }
}

/// What the daemon says about `user`'s keyring secret, asked through `ask`.
/// `KeyringMetadata` reads the envelope only. An irlumed from before 0.12.0
/// does not know it and answers "bad request"; then `KeyringInfo`, the older
/// request with the same reply, is asked instead (it also replays the live
/// PCRs). Any other failure is [`KeyringSeal::Unknown`].
pub(crate) fn keyring_seal_for(
    user: &str,
    mut ask: impl FnMut(&Request) -> Result<Response, String>,
) -> KeyringSeal {
    let reply = ask(&Request::KeyringMetadata {
        user: user.to_string(),
    });
    let reply = match &reply {
        Ok(Response::Error(error)) if error == "bad request" => ask(&Request::KeyringInfo {
            user: user.to_string(),
        }),
        _ => reply,
    };
    keyring_seal(&reply)
}

/// Whether a `RecoveryStatus` reply shows a sealed template key: an
/// encrypted store whose key still exists. `None` for any other reply.
pub(crate) fn template_key_sealed(reply: &Result<Response, String>) -> Option<bool> {
    match reply {
        Ok(Response::RecoveryStatus {
            encrypted,
            key_present,
            ..
        }) => Some(*encrypted && *key_present),
        _ => None,
    }
}

/// What is sealed, as the subject of a sentence.
struct Subject {
    /// Lower case, e.g. "the keyring secret".
    what: &'static str,
    plural: bool,
}

impl Subject {
    /// `None` when nothing is known to be sealed.
    fn of(sealed: &Sealed) -> Option<Self> {
        let keyring = matches!(sealed.keyring, KeyringSeal::Armed { .. });
        let template_key = sealed.template_key == Some(true);
        let what = match (keyring, template_key) {
            (false, false) => return None,
            (true, false) => "the keyring secret",
            (false, true) => "the template key that protects the face templates",
            (true, true) => {
                "the keyring secret and the template key that protects the face templates"
            }
        };
        Some(Subject {
            what,
            plural: keyring && template_key,
        })
    }

    fn verb(&self) -> &'static str {
        if self.plural {
            "are"
        } else {
            "is"
        }
    }

    fn pronoun(&self) -> &'static str {
        if self.plural {
            "them"
        } else {
            "it"
        }
    }

    /// `what` with its first letter in upper case, to start a sentence.
    fn sentence_start(&self) -> String {
        let mut chars = self.what.chars();
        chars.next().map_or_else(String::new, |first| {
            first.to_ascii_uppercase().to_string() + chars.as_str()
        })
    }
}

/// A sentence on one sealed secret's policy.
struct PolicyNote {
    text: String,
    /// Another operating system can reproduce what the policy binds, or
    /// that cannot be ruled out.
    reproducible: bool,
}

/// Who a policy sentence is about.
#[derive(Clone, Copy)]
struct Who {
    /// Starts the sentence, with its verb.
    subject: &'static str,
    /// What "can unseal" takes.
    object: &'static str,
}

const KEYRING: Who = Who {
    subject: "The keyring secret is",
    object: "the keyring secret",
};

/// The keyring secret and the template key under the same literal policy.
const BOTH: Who = Who {
    subject: "The keyring secret and the template key are",
    object: "both",
};

/// `pcrs` as "PCR 7" or "PCRs 0, 7".
fn pcr_list(pcrs: &[u32]) -> String {
    let list = pcrs
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let noun = if pcrs.len() == 1 { "PCR" } else { "PCRs" };
    format!("{noun} {list}")
}

/// What a policy that covers the boot loader (PCR 4) still leaves open: PCR 4
/// measures the boot loaders that run, not always what they load next.
const BOOT_LOADER_CAVEAT: &str = "the boot loader (PCR 4) closes a direct unseal only where \
     the boot loader also measures what it loads next, as a unified kernel image does; a GRUB \
     boot leaves the initrd and the kernel command line to PCRs 9 and 8, so another system \
     started through the same signed boot loaders can still reproduce";

/// The sentence for `who` sealed under the literal PCR policy over `pcrs`
/// (an empty list is the default, PCR 7). A set with PCR 4 binds the boot
/// loader, which is reproducible only where the boot loaders do not measure
/// what they load next; any other set is reproduced by another operating
/// system, signed with the same keys where the set includes PCR 7. Each is
/// treated as one that may be reproduced.
fn literal_binding(who: Who, pcrs: &[u32]) -> PolicyNote {
    let Who { subject, object } = who;
    let pcrs = if pcrs.is_empty() { &[7][..] } else { pcrs };
    let list = pcr_list(pcrs);
    let direct = format!("can unseal {object} directly, without changing the installed system");
    if pcrs.contains(&BOOT_LOADER_PCR) {
        return PolicyNote {
            text: format!(
                "{subject} sealed under a literal PCR policy over {list} (Tier 3, set by \
                 IRLUME_PCRS). Covering {BOOT_LOADER_CAVEAT} what it binds and unseal {object} \
                 directly."
            ),
            reproducible: true,
        };
    }
    // PCRs 0 to 3, 5 and 6: firmware, its configuration, option ROMs and the
    // partition table, which do not depend on the operating system booted.
    let firmware = pcrs.iter().any(|&pcr| pcr < 7);
    let os = pcrs.iter().any(|&pcr| pcr > 7);
    let text = match (firmware, pcrs.contains(&7), os) {
        (false, true, false) => format!(
            "{subject} sealed under the literal PCR 7 policy (Tier 3), which binds the Secure \
             Boot state only: another operating system signed with the same keys reproduces it \
             and {direct}."
        ),
        (false, true, true) => format!(
            "{subject} sealed under a literal PCR policy over {list} (Tier 3, set by \
             IRLUME_PCRS), which binds the Secure Boot state and values the operating system \
             extends itself: another operating system signed with the same keys reproduces them \
             and {direct}."
        ),
        (false, false, _) => format!(
            "{subject} sealed under a literal PCR policy over {list} (Tier 3, set by \
             IRLUME_PCRS), which binds only values the operating system extends itself: another \
             operating system reproduces them and {direct}."
        ),
        (true, true, _) => format!(
            "{subject} sealed under a literal PCR policy over {list} (Tier 3, set by \
             IRLUME_PCRS), which does not cover the boot loader (PCR 4): another operating \
             system signed with the same keys can reproduce them on this machine and unseal \
             {object} directly, without changing the installed system."
        ),
        (true, false, _) => format!(
            "{subject} sealed under a literal PCR policy over {list} (Tier 3, set by \
             IRLUME_PCRS), which covers neither the Secure Boot state nor the boot loader \
             (PCR 4): another operating system can reproduce them on this machine and unseal \
             {object} directly, without changing the installed system."
        ),
    };
    PolicyNote {
        text,
        reproducible: true,
    }
}

/// The sentence for a keyring secret sealed under a pcrlock policy over
/// `pcrs`. One that covers the boot loader (PCR 4) still gets the caveat on
/// what PCR 4 measures, as information.
fn pcrlock_binding(pcrs: &[u32]) -> Option<PolicyNote> {
    if pcrs.contains(&BOOT_LOADER_PCR) {
        return Some(PolicyNote {
            text: format!(
                "The keyring secret is sealed under a pcrlock policy (Tier 2) over {}. Covering \
                 {BOOT_LOADER_CAVEAT} what it binds and unseal the keyring secret directly.",
                pcr_list(pcrs)
            ),
            reproducible: true,
        });
    }
    let over = if pcrs.is_empty() {
        String::new()
    } else {
        format!(" over {}", pcr_list(pcrs))
    };
    let by = if pcrs.is_empty() || pcrs.contains(&7) {
        "another operating system signed with the same keys"
    } else {
        "another operating system"
    };
    Some(PolicyNote {
        text: format!(
            "The keyring secret is sealed under a pcrlock policy (Tier 2){over}, which does not \
             cover the boot loader (PCR 4): {by} can reproduce what it binds and unseal the \
             keyring secret directly, without changing the installed system. systemd-pcrlock \
             leaves a PCR out of its policy when it cannot match that PCR's measurements to \
             locked components."
        ),
        reproducible: true,
    })
}

/// The sentence for a keyring secret sealed under the signed PCR policy
/// (Tier 1) an earlier release wrote: any PCR values signed with the same key
/// satisfy it, and systemd's signature covers only PCR 11, which the
/// operating system extends itself.
fn signed_binding(pcrs: &[u32]) -> PolicyNote {
    let policy = if pcrs.is_empty() || pcrs == [11] {
        "a signed PCR 11 policy (Tier 1) from an earlier release, which binds only values the \
         operating system extends itself"
            .to_string()
    } else {
        format!(
            "a signed PCR policy over {} (Tier 1) from an earlier release, which any values \
             signed with the same key satisfy",
            pcr_list(pcrs)
        )
    };
    PolicyNote {
        text: format!(
            "The keyring secret is sealed under {policy}: another operating system signed with \
             the same keys can reproduce them and unseal the keyring secret directly, without \
             changing the installed system. A password login or `irlume keyring arm` reseals it \
             under a newer policy."
        ),
        reproducible: true,
    }
}

/// The sentence on the keyring secret's policy, `None` when there is
/// nothing to add: no keyring secret is armed, or it is sealed under a
/// pcrlock policy that covers the boot loader (PCR 4).
fn keyring_note(keyring: &KeyringSeal) -> Option<PolicyNote> {
    match keyring {
        KeyringSeal::Armed {
            policy: Some(policy),
            pcrs,
        } if is_literal_pcr_policy(policy) => Some(literal_binding(KEYRING, pcrs)),
        KeyringSeal::Armed {
            policy: Some(policy),
            pcrs,
        } if is_pcrlock_policy(policy) => pcrlock_binding(pcrs),
        KeyringSeal::Armed {
            policy: Some(policy),
            pcrs,
        } if is_signed_pcr_policy(policy) => Some(signed_binding(pcrs)),
        // Conservative: an unnamed or unrecognized policy may be one another
        // operating system reproduces.
        KeyringSeal::Armed { .. } => Some(PolicyNote {
            text: "irlume could not read which policy the keyring secret is sealed under; if it \
                   does not cover the boot loader (PCR 4), as the literal PCR 7 policy (Tier 3) \
                   does not, another operating system signed with the same keys can unseal it \
                   directly, without changing the installed system."
                .to_string(),
            reproducible: true,
        }),
        KeyringSeal::NotArmed | KeyringSeal::Unknown => None,
    }
}

/// The sentence on a sealed template key's policy, which the daemon does
/// not report. Without a pcrlock policy that seals use (`pcrlock_seals`), it
/// is the literal PCR policy; with one, the template key moves to it at
/// irlumed's next start, and that may not cover PCR 4 either. Either way it
/// is treated as one another operating system may reproduce.
fn template_key_note(pcrlock_seals: bool) -> PolicyNote {
    let text = if pcrlock_seals {
        "irlume does not report which policy the template key is sealed under; if it is the \
         literal PCR 7 policy (Tier 3), which it keeps until irlumed's next start after a \
         pcrlock policy is provisioned, or a pcrlock policy that does not cover the boot loader \
         (PCR 4), another operating system signed with the same keys can unseal it directly, \
         without changing the installed system."
    } else {
        "The template key goes through the same choice of policy, which on this machine, with \
         no pcrlock policy that seals use, is the literal PCR policy (Tier 3): unless \
         `IRLUME_PCRS` adds the boot loader (PCR 4), another operating system signed with the \
         same keys can reproduce what it binds and unseal the template key directly, without \
         changing the installed system."
    };
    PolicyNote {
        text: text.to_string(),
        reproducible: true,
    }
}

/// The sentences on the sealed secrets' policies, the keyring secret's
/// first. Where both are under the literal policy and the keyring secret's
/// set leaves out PCR 4, the same daemon sealed both with the same set, so
/// one sentence names both.
fn policy_notes(sealed: &Sealed) -> Vec<PolicyNote> {
    let template_key = sealed.template_key == Some(true);
    if template_key && !sealed.pcrlock_seals {
        if let KeyringSeal::Armed {
            policy: Some(policy),
            pcrs,
        } = &sealed.keyring
        {
            if is_literal_pcr_policy(policy) && !pcrs.contains(&BOOT_LOADER_PCR) {
                return vec![literal_binding(BOTH, pcrs)];
            }
        }
    }
    let mut notes: Vec<PolicyNote> = keyring_note(&sealed.keyring).into_iter().collect();
    if template_key {
        notes.push(template_key_note(sealed.pcrlock_seals));
    }
    notes
}

/// Guidance on what protects the sealed secrets at rest.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SealAdvice {
    /// The text shown after `keyring arm` and as the doctor detail.
    pub(crate) text: String,
    /// A warning: no dm-crypt layer was found under the state directory, or
    /// the storage could not be established. Otherwise information: it is on
    /// encrypted storage, whose unlock method the storage does not show, and
    /// a sealed secret's policy may be one another operating system
    /// reproduces.
    pub(crate) warn: bool,
}

/// The guidance for what `sealed` describes, given what the storage probe
/// found for `state_dir`: `None` when nothing is sealed. On encrypted
/// storage it is always information: the storage cannot show whether the
/// volume asks for a passphrase or PIN.
pub(crate) fn guidance(
    sealed: &Sealed,
    storage: StorageEncryption,
    state_dir: &Path,
) -> Option<SealAdvice> {
    let subject = Subject::of(sealed)?;
    let notes = policy_notes(sealed);
    let dir = state_dir.display();
    let storage = match storage {
        StorageEncryption::Encrypted => {
            let reproducible = notes
                .into_iter()
                .filter(|note| note.reproducible)
                .map(|note| note.text + " ")
                .collect::<String>();
            return Some(SealAdvice {
                text: format!(
                    "{reproducible}{dir} is on encrypted storage, which protects the sealed \
                     secrets at rest only if that volume asks for a passphrase or PIN to unlock; a \
                     volume the TPM or a key file unlocks alone does not count. A pcrlock policy \
                     (Tier 2) that covers the boot loader (PCR 4) is worth having in addition: \
                     {PCRLOCK_STEPS} ({DOC})."
                ),
                warn: false,
            });
        }
        StorageEncryption::NotEncrypted => format!(
            "irlume found no dm-crypt encryption under {dir} (it does not detect a drive's \
             hardware encryption or a filesystem's own)"
        ),
        StorageEncryption::Unknown => {
            format!("irlume could not confirm that {dir} is on encrypted storage")
        }
    };
    let pronoun = subject.pronoun();
    let notes = notes
        .into_iter()
        .map(|note| note.text + " ")
        .collect::<String>();
    Some(SealAdvice {
        text: format!(
            "{} {} sealed by the TPM, and {storage}. A TPM seal binds the boot chain it \
             measures, not the root filesystem: someone with this machine can change the \
             installed system offline (for example, add a service that runs as root) and boot \
             the unchanged boot chain, which still matches the PCR policy, to unseal {pronoun}. \
             {notes}What protects {pronoun} at rest is full-disk encryption unlocked by a \
             passphrase or PIN (a volume the TPM or a key file unlocks alone does not count), or \
             an integrity-verified root filesystem (dm-verity) that covers everything the boot \
             runs and reads configuration from, with its root hash bound by a pcrlock policy or \
             a signature, together with a pcrlock policy that covers the boot loader; irlume \
             does not detect a verified root, so this warning remains on such a system. A \
             pcrlock policy (Tier 2) that covers the boot loader (PCR 4) is worth having in \
             addition to encryption, not instead of it: {PCRLOCK_STEPS} ({DOC}).",
            subject.sentence_start(),
            subject.verb(),
        ),
        warn: true,
    })
}

/// irlumed's state directory: this process's `IRLUME_STATE_DIR` when it is
/// set, else the one irlumed's unit sets (a source install writes it into the
/// unit, not the shell), else the default. `None` when a unit file or drop-in
/// that could set it cannot be read: which directory irlumed uses is then
/// unknown, and so is its storage.
fn daemon_state_dir() -> Option<std::path::PathBuf> {
    if std::env::var_os("IRLUME_STATE_DIR").is_some() {
        return Some(irlume_common::state_dir());
    }
    match crate::uninstall::unit_env("IRLUME_STATE_DIR") {
        Ok(Some(dir)) => Some(dir),
        Ok(None) => Some(irlume_common::state_dir()),
        Err(_) => None,
    }
}

/// What stands for an unknown state directory in the guidance text.
const UNKNOWN_STATE_DIR: &str = "irlumed's state directory (its unit could not be read)";

/// The directory to name and the storage probe to use for irlumed's state
/// directory: an unknown directory is unknown storage, never the default's.
fn daemon_storage(
    probe: impl FnOnce(&Path) -> StorageEncryption,
) -> (std::path::PathBuf, StorageEncryption) {
    match daemon_state_dir() {
        Some(dir) => {
            let storage = probe(&dir);
            (dir, storage)
        }
        None => (UNKNOWN_STATE_DIR.into(), StorageEncryption::Unknown),
    }
}

/// [`guidance`] for irlumed's state directory ([`daemon_state_dir`]) on this
/// system's storage. The storage is probed only when something is sealed.
pub(crate) fn state_dir_guidance(sealed: &Sealed) -> Option<SealAdvice> {
    Subject::of(sealed)?;
    let (dir, storage) = daemon_storage(irlume_common::storage_encryption::path_encryption);
    guidance(sealed, storage, &dir)
}

/// The line `keyring arm` prints for `advice`: a warning, or a note for
/// information.
pub(crate) fn arm_note(advice: &SealAdvice) -> String {
    let label = if advice.warn { "WARNING" } else { "NOTE" };
    format!("[keyring] {label}: {}", advice.text)
}

/// Doctor's `sealed-storage` check for `user`: `warn` with the guidance
/// where no dm-crypt layer is found under the state directory (or that
/// cannot be established), `info` with it on encrypted storage (whose unlock
/// method the storage does not show) and when nothing is sealed, and
/// `unknown` when the daemon did not say what is sealed. `probe` answers for
/// `state_dir` and runs only when something is sealed.
pub(crate) fn check(
    user: &str,
    sealed: &Sealed,
    state_dir: &Path,
    probe: impl FnOnce(&Path) -> StorageEncryption,
) -> (State, String) {
    if Subject::of(sealed).is_none() {
        return if sealed.keyring == KeyringSeal::NotArmed && sealed.template_key == Some(false) {
            (
                State::Info,
                format!(
                    "nothing is sealed for {user}: no keyring secret is armed and no template \
                     key is sealed"
                ),
            )
        } else {
            (
                State::Unknown,
                format!("irlumed did not say what is sealed for {user}"),
            )
        };
    }
    match guidance(sealed, probe(state_dir), state_dir) {
        Some(advice) if advice.warn => (State::Warn, advice.text),
        Some(advice) => (State::Info, advice.text),
        // Not reached: something is sealed, so there is guidance.
        None => (
            State::Unknown,
            format!("irlumed did not say what is sealed for {user}"),
        ),
    }
}

/// [`check`] against irlumed's state directory ([`daemon_state_dir`]) and
/// this system's storage; an unknown directory is unknown storage.
pub(crate) fn state_dir_check(user: &str, sealed: &Sealed) -> (State, String) {
    let Some(dir) = daemon_state_dir() else {
        return check(user, sealed, Path::new(UNKNOWN_STATE_DIR), |_| {
            StorageEncryption::Unknown
        });
    };
    check(
        user,
        sealed,
        &dir,
        irlume_common::storage_encryption::path_encryption,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const DIR: &str = "/var/lib/irlume";
    const OFFLINE: &str = "someone with this machine can change the installed system offline";
    const DIRECT: &str = "another operating system signed with the same keys reproduces it";
    const REMEDY: &str = "full-disk encryption unlocked by a passphrase or PIN";
    const GRUB: &str = "a GRUB boot leaves the initrd and the kernel command line to PCRs 9 and 8";
    const VERITY: &str = "an integrity-verified root filesystem (dm-verity) that covers \
                          everything the boot runs and reads configuration from, with its root \
                          hash bound by a pcrlock policy or a signature, together with a pcrlock \
                          policy that covers the boot loader; irlume does not detect a verified \
                          root, so this warning remains on such a system";
    const IN_ADDITION: &str = "A pcrlock policy (Tier 2) that covers the boot loader (PCR 4) is \
                               worth having in addition to encryption, not instead of it";
    const STEPS: &str = "(`/usr/lib/systemd/systemd-pcrlock lock-pe` for a boot loader, \
                         `lock-uki` for a unified kernel image), then run \
                         `/usr/lib/systemd/systemd-pcrlock make-policy`";
    const TEMPLATE_KEY: &str = "the template key that protects the face templates";
    const TEMPLATE_LITERAL: &str = "The template key goes through the same choice of policy, \
                                    which on this machine, with no pcrlock policy that seals \
                                    use, is the literal PCR policy (Tier 3)";
    const TEMPLATE_UNNAMED: &str =
        "irlume does not report which policy the template key is sealed under";
    const UNNAMED: &str = "irlume could not read which policy the keyring secret";

    fn literal(pcrs: Vec<u32>) -> KeyringSeal {
        KeyringSeal::Armed {
            policy: Some(PolicyKind::PcrLiteral.describe()),
            pcrs,
        }
    }

    fn pcrlock_over(pcrs: Vec<u32>) -> KeyringSeal {
        KeyringSeal::Armed {
            policy: Some(PolicyKind::PcrlockNv { nv_index: 0x1a2b }.describe()),
            pcrs,
        }
    }

    /// A pcrlock policy that covers the boot loader (PCR 4).
    fn pcrlock() -> KeyringSeal {
        pcrlock_over(vec![0, 2, 4, 7])
    }

    fn signed(pcrs: Vec<u32>) -> KeyringSeal {
        KeyringSeal::Armed {
            policy: Some(
                PolicyKind::Authorized {
                    pubkey_pem: "-----BEGIN PUBLIC KEY-----".into(),
                    policy_ref: vec![1],
                }
                .describe(),
            ),
            pcrs,
        }
    }

    /// Sealed on a machine whose new seals use a pcrlock policy exactly when
    /// the keyring secret is under one.
    fn sealed(keyring: KeyringSeal, template_key: Option<bool>) -> Sealed {
        let pcrlock_seals = matches!(
            &keyring,
            KeyringSeal::Armed { policy: Some(policy), .. } if is_pcrlock_policy(policy)
        );
        Sealed {
            keyring,
            template_key,
            pcrlock_seals,
        }
    }

    fn advise(sealed: &Sealed, storage: StorageEncryption) -> Option<SealAdvice> {
        let advice = guidance(sealed, storage, Path::new(DIR));
        if let Some(advice) = &advice {
            assert!(
                !advice.text.contains('\u{2014}'),
                "em dash: {}",
                advice.text
            );
        }
        advice
    }

    fn warning(sealed: &Sealed, storage: StorageEncryption) -> String {
        let advice = advise(sealed, storage).expect("guidance");
        assert!(advice.warn, "{}", advice.text);
        advice.text
    }

    fn information(sealed: &Sealed) -> String {
        let advice = advise(sealed, StorageEncryption::Encrypted).expect("information");
        assert!(!advice.warn, "{}", advice.text);
        assert!(
            advice.text.contains(
                "/var/lib/irlume is on encrypted storage, which protects the sealed secrets at \
                 rest only if that volume asks for a passphrase or PIN to unlock"
            ) && advice.text.contains(STEPS),
            "{}",
            advice.text
        );
        assert!(!advice.text.contains(OFFLINE), "{}", advice.text);
        advice.text
    }

    const ALL_STORAGE: [StorageEncryption; 3] = [
        StorageEncryption::Encrypted,
        StorageEncryption::NotEncrypted,
        StorageEncryption::Unknown,
    ];

    #[test]
    fn nothing_sealed_gets_no_guidance() {
        for sealed in [
            sealed(KeyringSeal::NotArmed, Some(false)),
            sealed(KeyringSeal::NotArmed, None),
            sealed(KeyringSeal::Unknown, Some(false)),
            sealed(KeyringSeal::Unknown, None),
        ] {
            for storage in ALL_STORAGE {
                assert!(advise(&sealed, storage).is_none(), "{sealed:?} {storage:?}");
            }
            assert_eq!(state_dir_guidance(&sealed), None, "{sealed:?}");
        }
    }

    /// The template key goes through the same choice of policy as the
    /// keyring secret: without a pcrlock policy that seals use, it is the
    /// literal PCR policy and gets that point.
    #[test]
    fn a_template_key_alone_off_encrypted_storage_warns() {
        let text = warning(
            &sealed(KeyringSeal::NotArmed, Some(true)),
            StorageEncryption::NotEncrypted,
        );
        assert!(
            text.starts_with(
                "The template key that protects the face templates is sealed by the TPM, and \
                 irlume found no dm-crypt encryption under /var/lib/irlume (it does not detect \
                 a drive's hardware encryption or a filesystem's own)."
            ),
            "{text}"
        );
        assert!(
            text.contains(OFFLINE) && text.contains("to unseal it."),
            "{text}"
        );
        assert!(
            text.contains(TEMPLATE_LITERAL)
                && text.contains("unseal the template key directly, without changing the"),
            "{text}"
        );
        assert!(
            text.contains(REMEDY) && text.contains(VERITY) && text.contains(IN_ADDITION),
            "{text}"
        );
        assert!(text.contains(STEPS), "{text}");
        assert!(!text.contains("keyring"), "{text}");
        // A daemon that could not say what is armed does not hide it.
        assert_eq!(
            warning(
                &sealed(KeyringSeal::Unknown, Some(true)),
                StorageEncryption::NotEncrypted
            ),
            text
        );
    }

    #[test]
    fn a_template_key_is_information_on_encrypted_storage() {
        let text = information(&sealed(KeyringSeal::NotArmed, Some(true)));
        assert!(text.starts_with(TEMPLATE_LITERAL), "{text}");
        // Where seals use a pcrlock policy, its policy is not named.
        let text = information(&Sealed {
            keyring: KeyringSeal::NotArmed,
            template_key: Some(true),
            pcrlock_seals: true,
        });
        assert!(
            text.starts_with(TEMPLATE_UNNAMED)
                && text.contains("a pcrlock policy that does not cover the boot loader (PCR 4)"),
            "{text}"
        );
        // A keyring secret whose pcrlock policy covers PCR 4 adds its caveat
        // before the template key's.
        let both = information(&sealed(pcrlock(), Some(true)));
        assert!(
            both.starts_with("The keyring secret is sealed under a pcrlock policy (Tier 2)")
                && both.contains(GRUB)
                && both.ends_with(&text),
            "{both}"
        );
    }

    #[test]
    fn a_tier_3_keyring_secret_alone_off_encrypted_storage_warns_with_both_points() {
        let text = warning(
            &sealed(literal(vec![7]), Some(false)),
            StorageEncryption::NotEncrypted,
        );
        assert!(
            text.starts_with("The keyring secret is sealed by the TPM, and irlume found no"),
            "{text}"
        );
        assert!(!text.contains(TEMPLATE_KEY), "{text}");
        assert!(text.contains(OFFLINE), "{text}");
        assert!(
            text.contains("the literal PCR 7 policy (Tier 3)")
                && text.contains(DIRECT)
                && text.contains(
                    "can unseal the keyring secret directly, without changing the installed system"
                ),
            "{text}"
        );
        assert!(
            text.contains(REMEDY) && text.contains(IN_ADDITION),
            "{text}"
        );
        // The default set and an empty report read the same.
        assert_eq!(
            warning(
                &sealed(literal(Vec::new()), None),
                StorageEncryption::NotEncrypted
            ),
            text
        );
    }

    /// Sealed by the same daemon under the literal policy, both are named in
    /// one sentence.
    #[test]
    fn a_keyring_secret_and_a_template_key_are_named_together() {
        let text = warning(
            &sealed(literal(vec![7]), Some(true)),
            StorageEncryption::NotEncrypted,
        );
        assert!(
            text.starts_with(
                "The keyring secret and the template key that protects the face templates are \
                 sealed by the TPM"
            ),
            "{text}"
        );
        assert!(
            text.contains("to unseal them.") && text.contains("protects them at rest"),
            "{text}"
        );
        assert!(
            text.contains(
                "The keyring secret and the template key are sealed under the literal PCR 7 \
                 policy (Tier 3)"
            ) && text.contains(DIRECT)
                && text.contains("can unseal both directly"),
            "{text}"
        );
        assert!(!text.contains(TEMPLATE_LITERAL), "{text}");
        let text = information(&sealed(literal(vec![7, 11]), Some(true)));
        assert!(
            text.starts_with(
                "The keyring secret and the template key are sealed under a literal PCR policy \
                 over PCRs 7, 11"
            ),
            "{text}"
        );

        // A keyring set with PCR 4 is not taken for the template key's; it
        // carries the caveat on what PCR 4 measures.
        let text = warning(
            &sealed(literal(vec![4, 7]), Some(true)),
            StorageEncryption::NotEncrypted,
        );
        assert!(
            text.contains(
                "The keyring secret is sealed under a literal PCR policy over PCRs 4, 7 (Tier 3, \
                 set by IRLUME_PCRS). Covering the boot loader (PCR 4) closes a direct unseal \
                 only where"
            ) && text.contains(GRUB)
                && text.contains(TEMPLATE_LITERAL),
            "{text}"
        );
        let text = information(&sealed(literal(vec![4, 7]), Some(true)));
        assert!(
            text.starts_with(
                "The keyring secret is sealed under a literal PCR policy over PCRs 4, 7"
            ) && text.contains(TEMPLATE_LITERAL),
            "{text}"
        );
    }

    /// A pcrlock policy that covers PCR 4 does not close the offline change,
    /// and closes the direct unseal only where the boot loader measures what
    /// it loads next: it warns off encrypted storage and informs on it.
    #[test]
    fn a_pcrlock_keyring_secret_off_encrypted_storage_still_warns() {
        let text = warning(
            &sealed(pcrlock(), Some(false)),
            StorageEncryption::NotEncrypted,
        );
        assert!(text.contains(OFFLINE) && text.contains(REMEDY), "{text}");
        assert!(!text.contains("Tier 3") && text.contains(GRUB), "{text}");
        let info = advise(
            &sealed(pcrlock(), Some(false)),
            StorageEncryption::Encrypted,
        )
        .expect("information on encrypted storage");
        assert!(!info.warn && info.text.contains(GRUB), "{}", info.text);
    }

    /// systemd-pcrlock leaves out a PCR it cannot match to locked
    /// components; a pcrlock policy without PCR 4 is reproduced like the
    /// literal one.
    #[test]
    fn a_pcrlock_policy_without_the_boot_loader_is_reproducible() {
        for (pcrs, over, by) in [
            (
                vec![0, 2, 7],
                "a pcrlock policy (Tier 2) over PCRs 0, 2, 7, which does not cover the boot \
                 loader (PCR 4)",
                "another operating system signed with the same keys can reproduce",
            ),
            (
                vec![7],
                "a pcrlock policy (Tier 2) over PCR 7, which",
                "another operating system signed with the same keys can reproduce",
            ),
            (
                vec![0, 1, 2, 3, 5],
                "over PCRs 0, 1, 2, 3, 5, which",
                "(PCR 4): another operating system can reproduce",
            ),
            (
                Vec::new(),
                "a pcrlock policy (Tier 2), which does not cover",
                "another operating system signed with the same keys can reproduce",
            ),
        ] {
            let keyring = pcrlock_over(pcrs);
            let text = warning(
                &sealed(keyring.clone(), Some(false)),
                StorageEncryption::NotEncrypted,
            );
            assert!(
                text.contains(OFFLINE)
                    && text.contains(over)
                    && text.contains(by)
                    && text.contains("unseal the keyring secret directly")
                    && text.contains("systemd-pcrlock leaves a PCR out of its policy"),
                "{text}"
            );
            let text = information(&sealed(keyring, Some(false)));
            assert!(text.contains(over) && text.contains(by), "{text}");
        }
    }

    /// A signed PCR 11 policy (Tier 1) from an earlier release binds only
    /// what the operating system extends: reported on either storage.
    #[test]
    fn a_signed_pcr_11_keyring_secret_is_reproducible() {
        for pcrs in [vec![11], Vec::new()] {
            let text = warning(
                &sealed(signed(pcrs.clone()), Some(false)),
                StorageEncryption::NotEncrypted,
            );
            assert!(
                text.contains(OFFLINE)
                    && text.contains(
                        "The keyring secret is sealed under a signed PCR 11 policy (Tier 1) from \
                         an earlier release, which binds only values the operating system \
                         extends itself: another operating system signed with the same keys can \
                         reproduce them and unseal the keyring secret directly"
                    )
                    && text.contains("A password login or `irlume keyring arm` reseals it"),
                "{text}"
            );
            let text = information(&sealed(signed(pcrs), Some(false)));
            assert!(text.contains("signed PCR 11 policy (Tier 1)"), "{text}");
        }
        let text = information(&sealed(signed(vec![0, 7]), Some(false)));
        assert!(
            text.contains(
                "a signed PCR policy over PCRs 0, 7 (Tier 1) from an earlier release, which any \
                 values signed with the same key satisfy"
            ),
            "{text}"
        );
    }

    #[test]
    fn storage_that_cannot_be_established_warns() {
        let text = warning(
            &sealed(literal(vec![7]), Some(true)),
            StorageEncryption::Unknown,
        );
        assert!(
            text.contains("irlume could not confirm that /var/lib/irlume is on encrypted storage"),
            "{text}"
        );
        assert!(text.contains(OFFLINE) && text.contains(DIRECT), "{text}");
        warning(&sealed(pcrlock(), Some(true)), StorageEncryption::Unknown);
        warning(
            &sealed(KeyringSeal::NotArmed, Some(true)),
            StorageEncryption::Unknown,
        );
    }

    #[test]
    fn encrypted_storage_under_tier_3_is_information() {
        // The storage does not show whether the volume asks for a passphrase
        // or unlocks from the TPM or a key file, so the guidance stays.
        for template_key in [Some(true), Some(false), None] {
            let text = information(&sealed(literal(vec![7]), template_key));
            assert!(
                text.contains("the literal PCR 7 policy (Tier 3)") && text.contains(DIRECT),
                "{text}"
            );
            assert!(
                text.contains(
                    "A pcrlock policy (Tier 2) that covers the boot loader (PCR 4) is worth \
                     having in addition: lock the boot components first"
                ),
                "{text}"
            );
        }
    }

    /// An unknown state directory is unknown storage: it warns, naming the
    /// directory as unknown rather than the default's.
    #[test]
    fn an_unknown_state_directory_warns() {
        let sealed = sealed(literal(vec![7]), Some(true));
        let advice = guidance(
            &sealed,
            StorageEncryption::Unknown,
            Path::new(UNKNOWN_STATE_DIR),
        )
        .expect("guidance");
        assert!(advice.warn, "{}", advice.text);
        assert!(
            advice.text.contains(
                "irlume could not confirm that irlumed's state directory (its unit could not be \
                 read) is on encrypted storage"
            ),
            "{}",
            advice.text
        );
    }

    /// On encrypted storage the guidance is always information: the storage
    /// cannot show whether the volume asks for a passphrase, and a policy
    /// that covers the boot loader (PCR 4) carries the caveat on what PCR 4
    /// measures.
    #[test]
    fn encrypted_storage_under_a_policy_that_covers_the_boot_loader_is_information() {
        for sealed in [
            sealed(pcrlock(), Some(false)),
            sealed(pcrlock(), None),
            sealed(literal(vec![4, 7]), Some(false)),
            sealed(literal(vec![0, 2, 4, 7, 11]), None),
        ] {
            let advice =
                advise(&sealed, StorageEncryption::Encrypted).expect("information, not none");
            assert!(
                !advice.warn
                    && advice.text.contains(GRUB)
                    && advice
                        .text
                        .contains("only if that volume asks for a passphrase"),
                "{sealed:?}: {}",
                advice.text
            );
        }
    }

    /// PCRs 0 to 3 measure this machine's firmware, which is the same
    /// whatever it boots, and PCR 5 its partition table: without PCR 4 a
    /// literal set is reproduced by another operating system, which is
    /// named, and is information on encrypted storage.
    #[test]
    fn a_literal_firmware_set_without_the_boot_loader_is_reproducible() {
        for (pcrs, named, by) in [
            (
                vec![0, 7],
                "over PCRs 0, 7 (Tier 3, set by IRLUME_PCRS), which does not cover the boot \
                 loader (PCR 4)",
                "another operating system signed with the same keys can reproduce them on this \
                 machine",
            ),
            (
                vec![5, 7],
                "over PCRs 5, 7 (Tier 3, set by IRLUME_PCRS)",
                "another operating system signed with the same keys can reproduce them",
            ),
            (
                vec![2],
                "over PCR 2 (Tier 3, set by IRLUME_PCRS), which covers neither the Secure Boot \
                 state nor the boot loader (PCR 4)",
                "(PCR 4): another operating system can reproduce them on this machine",
            ),
        ] {
            let keyring = literal(pcrs);
            let text = warning(
                &sealed(keyring.clone(), Some(false)),
                StorageEncryption::NotEncrypted,
            );
            assert!(text.contains(OFFLINE) && text.contains(REMEDY), "{text}");
            assert!(
                text.contains(&format!(
                    "The keyring secret is sealed under a literal PCR policy {named}"
                )) && text.contains(by)
                    && text.contains("unseal the keyring secret directly"),
                "{text}"
            );
            let text = information(&sealed(keyring, Some(false)));
            assert!(text.contains(named) && text.contains(by), "{text}");
        }
    }

    /// A literal set with the boot loader (PCR 4) is still open to an
    /// offline change of the installed system: it warns, naming the set, with
    /// the caveat on what PCR 4 measures.
    #[test]
    fn a_literal_set_with_the_boot_loader_off_encrypted_storage_warns() {
        for (pcrs, named) in [
            (vec![4, 7], "over PCRs 4, 7 (Tier 3, set by IRLUME_PCRS)"),
            (
                vec![0, 4, 7, 11],
                "over PCRs 0, 4, 7, 11 (Tier 3, set by IRLUME_PCRS)",
            ),
            (vec![4], "over PCR 4 (Tier 3, set by IRLUME_PCRS)"),
        ] {
            let text = warning(
                &sealed(literal(pcrs), Some(false)),
                StorageEncryption::NotEncrypted,
            );
            assert!(text.contains(OFFLINE) && text.contains(REMEDY), "{text}");
            assert!(
                text.contains(&format!(
                    "The keyring secret is sealed under a literal PCR policy {named}. Covering the \
                     boot loader (PCR 4)"
                )) && text.contains(GRUB),
                "{text}"
            );
        }
    }

    /// An `IRLUME_PCRS` set another operating system reproduces is named,
    /// with that point, on either kind of storage.
    #[test]
    fn a_literal_os_set_names_its_pcrs() {
        for storage in ALL_STORAGE {
            let text = advise(&sealed(literal(vec![7, 11]), None), storage)
                .expect("guidance")
                .text;
            assert!(
                text.contains("over PCRs 7, 11 (Tier 3, set by IRLUME_PCRS)")
                    && text.contains("the Secure Boot state and values the operating system")
                    && text.contains("another operating system signed with the same keys"),
                "{text}"
            );
            let text = advise(&sealed(literal(vec![11]), None), storage)
                .expect("guidance")
                .text;
            assert!(
                text.contains("over PCR 11 (Tier 3, set by IRLUME_PCRS)")
                    && text.contains("another operating system reproduces them")
                    && !text.contains("Secure Boot"),
                "{text}"
            );
        }
    }

    /// Neither reply names the policy, or it is a name this client does not
    /// know, but something is sealed: the storage guidance still comes, and
    /// the keyring policy is treated as one another operating system may
    /// reproduce.
    #[test]
    fn a_seal_whose_policy_is_not_named_still_gets_the_guidance() {
        for policy in [None, Some("a future policy (Tier 0)".to_string())] {
            let unnamed = KeyringSeal::Armed {
                policy,
                pcrs: Vec::new(),
            };
            let text = warning(
                &sealed(unnamed.clone(), None),
                StorageEncryption::NotEncrypted,
            );
            assert!(
                text.contains(OFFLINE) && text.contains(UNNAMED) && text.contains(REMEDY),
                "{text}"
            );
            let text = information(&sealed(unnamed, None));
            assert!(text.starts_with(UNNAMED), "{text}");
        }
    }

    /// The arm prints the guidance with the label its kind calls for, on
    /// every host.
    #[test]
    fn the_arm_note_is_labelled_by_its_kind() {
        let advice = advise(
            &sealed(literal(vec![7]), None),
            StorageEncryption::Encrypted,
        )
        .expect("information");
        assert_eq!(
            arm_note(&advice),
            format!("[keyring] NOTE: {}", advice.text)
        );
        let advice = advise(
            &sealed(literal(vec![7]), None),
            StorageEncryption::NotEncrypted,
        )
        .expect("warning");
        assert_eq!(
            arm_note(&advice),
            format!("[keyring] WARNING: {}", advice.text)
        );
    }

    /// A daemon from before `KeyringMetadata` answers it "bad request"; the
    /// same question is then asked as `KeyringInfo`. Any other failure is
    /// not retried.
    #[test]
    fn keyring_metadata_falls_back_to_keyring_info_on_an_older_daemon() {
        let asked = RefCell::new(Vec::new());
        let keyring = keyring_seal_for("tester", |request| {
            asked.borrow_mut().push(request.clone());
            Ok(match request {
                Request::KeyringMetadata { .. } => Response::Error("bad request".into()),
                Request::KeyringInfo { .. } => Response::KeyringInfo {
                    armed: true,
                    policy: Some(PolicyKind::PcrLiteral.describe()),
                    pcrs: vec![7],
                    drifted: Some(false),
                    kind: None,
                },
                _ => Response::Error("unexpected".into()),
            })
        });
        assert_eq!(keyring, literal(vec![7]));
        assert!(
            matches!(
                asked.borrow().as_slice(),
                [
                    Request::KeyringMetadata { user: first },
                    Request::KeyringInfo { user: second },
                ] if first == "tester" && second == "tester"
            ),
            "{:?}",
            asked.borrow()
        );

        for (reply, want) in [
            (
                Ok(Response::KeyringInfo {
                    armed: false,
                    policy: None,
                    pcrs: Vec::new(),
                    drifted: None,
                    kind: None,
                }),
                KeyringSeal::NotArmed,
            ),
            (
                Ok(Response::Error("permission denied".into())),
                KeyringSeal::Unknown,
            ),
            (Err("irlumed is not running".into()), KeyringSeal::Unknown),
            (Ok(Response::Pong), KeyringSeal::Unknown),
        ] {
            let count = RefCell::new(0);
            let keyring = keyring_seal_for("tester", |_| {
                *count.borrow_mut() += 1;
                reply.clone()
            });
            assert_eq!(keyring, want, "{reply:?}");
            assert_eq!(*count.borrow(), 1, "{reply:?} was retried");
        }

        // Both older and newer requests refused: unknown.
        let keyring = keyring_seal_for("tester", |_| Ok(Response::Error("bad request".into())));
        assert_eq!(keyring, KeyringSeal::Unknown);
    }

    #[test]
    fn a_template_key_is_sealed_when_the_store_is_encrypted_and_its_key_exists() {
        let status = |encrypted, key_present| {
            template_key_sealed(&Ok(Response::RecoveryStatus {
                encrypted,
                recovery_set: false,
                tpm_present: true,
                key_present,
            }))
        };
        assert_eq!(status(true, true), Some(true));
        assert_eq!(status(true, false), Some(false));
        assert_eq!(status(false, false), Some(false));
        assert_eq!(template_key_sealed(&Err("down".into())), None);
        assert_eq!(
            template_key_sealed(&Ok(Response::Error("bad request".into()))),
            None
        );
    }

    #[test]
    fn the_doctor_check_states() {
        let never = |_: &Path| -> StorageEncryption { panic!("must not probe") };
        let dir = Path::new(DIR);
        let (state, detail) = check(
            "tester",
            &sealed(KeyringSeal::NotArmed, Some(false)),
            dir,
            never,
        );
        assert_eq!(state, State::Info);
        assert!(detail.contains("nothing is sealed for tester"), "{detail}");
        for sealed in [
            sealed(KeyringSeal::Unknown, None),
            sealed(KeyringSeal::Unknown, Some(false)),
            sealed(KeyringSeal::NotArmed, None),
        ] {
            let (state, detail) = check("tester", &sealed, dir, never);
            assert_eq!(state, State::Unknown, "{sealed:?}");
            assert!(detail.contains("irlumed did not say"), "{detail}");
        }

        let asked = RefCell::new(None);
        let (state, detail) = check(
            "tester",
            &sealed(pcrlock(), Some(false)),
            Path::new("/srv/irlume-state"),
            |path| {
                *asked.borrow_mut() = Some(path.to_path_buf());
                StorageEncryption::Encrypted
            },
        );
        assert_eq!(state, State::Info);
        assert!(
            detail.contains("/srv/irlume-state is on encrypted storage") && detail.contains(GRUB),
            "{detail}"
        );
        assert_eq!(
            asked.borrow().as_deref(),
            Some(Path::new("/srv/irlume-state"))
        );

        // Nothing on encrypted storage is a pass.
        let (state, _) = check("tester", &sealed(pcrlock(), None), dir, |_| {
            StorageEncryption::Encrypted
        });
        assert_eq!(state, State::Info);
        let unknown_keyring = sealed(KeyringSeal::Unknown, Some(true));
        let (state, detail) = check("tester", &unknown_keyring, dir, |_| {
            StorageEncryption::Encrypted
        });
        assert_eq!(state, State::Info);
        assert!(detail.starts_with(TEMPLATE_LITERAL), "{detail}");

        let tier_3 = sealed(literal(vec![7]), Some(true));
        let (state, detail) = check("tester", &tier_3, dir, |_| StorageEncryption::Encrypted);
        assert_eq!(state, State::Info);
        assert_eq!(
            Some(detail),
            advise(&tier_3, StorageEncryption::Encrypted).map(|advice| advice.text)
        );
        for storage in [StorageEncryption::NotEncrypted, StorageEncryption::Unknown] {
            let (state, detail) = check("tester", &tier_3, dir, |_| storage);
            assert_eq!(state, State::Warn);
            assert_eq!(
                Some(detail),
                advise(&tier_3, storage).map(|advice| advice.text)
            );
        }
    }

    #[test]
    fn each_policy_label_is_recognized_as_its_tier() {
        let literal = PolicyKind::PcrLiteral.describe();
        let signed = PolicyKind::Authorized {
            pubkey_pem: "key".into(),
            policy_ref: vec![1, 2],
        }
        .describe();
        let pcrlock =
            [0, 0x1a2b, u32::MAX].map(|nv_index| PolicyKind::PcrlockNv { nv_index }.describe());
        assert!(is_literal_pcr_policy("literal PolicyPCR (Tier 3)"));
        assert!(is_literal_pcr_policy(&literal));
        assert!(is_signed_pcr_policy("signed PolicyAuthorize (Tier 1)"));
        assert!(is_signed_pcr_policy(&signed));
        assert!(is_pcrlock_policy("pcrlock NV 0x1a2b (Tier 2)"));
        for pcrlock in &pcrlock {
            assert!(is_pcrlock_policy(pcrlock), "{pcrlock}");
            assert!(!is_literal_pcr_policy(pcrlock) && !is_signed_pcr_policy(pcrlock));
        }
        assert!(!is_literal_pcr_policy(&signed) && !is_pcrlock_policy(&signed));
        assert!(!is_signed_pcr_policy(&literal) && !is_pcrlock_policy(&literal));
        for other in [
            "",
            "pcrlock NV 0x (Tier 2)",
            "pcrlock NV 0xzz (Tier 2)",
            "pcrlock NV 0x1 (Tier 3)",
        ] {
            assert!(
                !is_literal_pcr_policy(other)
                    && !is_signed_pcr_policy(other)
                    && !is_pcrlock_policy(other),
                "{other}"
            );
        }
    }
}
