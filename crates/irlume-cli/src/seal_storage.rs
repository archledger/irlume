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
//! storage probes found under irlumed's directories and the installed
//! system into a warning, information or nothing. `keyring arm` prints it
//! after a successful arm ([`arm_note`]), and doctor reports it as the
//! `sealed-storage` check ([`check`]). The probe
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
use irlume_common::{Request, Response, StorageDirectory};
use irlume_core::envelope::PolicyKind;
use std::path::{Path, PathBuf};

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
/// is the one chosen when the key was sealed; with one, the template key
/// moves to it at irlumed's next start, and that may not cover PCR 4 either.
/// Either way it is treated as one another operating system may reproduce.
fn template_key_note(pcrlock_seals: bool) -> PolicyNote {
    let text = if pcrlock_seals {
        "irlume does not report which policy the template key is sealed under; if it is the \
         literal PCR 7 policy (Tier 3), which it keeps until irlumed's next start after a \
         pcrlock policy is provisioned, or a pcrlock policy that does not cover the boot loader \
         (PCR 4), another operating system signed with the same keys can unseal it directly, \
         without changing the installed system."
    } else {
        "The template key is sealed under the policy chosen when it was sealed: with no pcrlock \
         policy that seals use, the literal PCR policy (Tier 3) over PCR 7 or the PCRs \
         `IRLUME_PCRS` named then, or a signed PCR 11 policy (Tier 1) from an earlier release; \
         irlume does not report which, and a later `IRLUME_PCRS` does not move it. Unless that \
         policy covers the boot loader (PCR 4), another operating system signed with the same \
         keys can reproduce what it binds and unseal the template key directly, without \
         changing the installed system."
    };
    PolicyNote {
        text: text.to_string(),
        reproducible: true,
    }
}

/// The sentences on the sealed secrets' policies, the keyring secret's
/// first. Each is described on its own: a template key keeps the policy it
/// was sealed under until irlumed moves it to a stronger one, so the keyring
/// secret's PCR set says nothing about it.
fn policy_notes(sealed: &Sealed) -> Vec<PolicyNote> {
    let template_key = sealed.template_key == Some(true);
    let mut notes: Vec<PolicyNote> = keyring_note(&sealed.keyring).into_iter().collect();
    if template_key {
        notes.push(template_key_note(sealed.pcrlock_seals));
    }
    notes
}

/// The sentence, ending the guidance, on a secret irlumed could not say is
/// sealed or not while the other one is.
fn unknown_secret_note(sealed: &Sealed) -> String {
    let keyring = matches!(sealed.keyring, KeyringSeal::Armed { .. });
    let template_key = sealed.template_key == Some(true);
    if template_key && sealed.keyring == KeyringSeal::Unknown {
        " irlume could not learn from irlumed whether the keyring secret is armed as well; if \
         it is, what is said here about the storage applies to it too, under the policy it was \
         sealed with."
            .to_string()
    } else if keyring && sealed.template_key.is_none() {
        " irlume could not learn from irlumed whether a template key is sealed as well; if one \
         is, what is said here about the storage applies to it too, under the policy it was \
         sealed with, which irlume does not report."
            .to_string()
    } else {
        String::new()
    }
}

/// Guidance on what protects the sealed secrets at rest.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SealAdvice {
    /// The text shown after `keyring arm` and as the doctor detail.
    pub(crate) text: String,
    /// A warning: no dm-crypt layer was found under the directory probed, or
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
    let unknown = unknown_secret_note(sealed);
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
                    "{reproducible}{dir} and the installed system (/, /usr and /etc) are on \
                     encrypted storage, which protects the sealed secrets at rest only if those \
                     volumes ask for a passphrase or PIN to unlock; a volume the TPM or a key file \
                     unlocks alone does not count. What the boot reads before the volume is \
                     unlocked (the EFI system partition, an unencrypted /boot) is not encrypted \
                     and can be changed offline to capture the passphrase or PIN, whatever the \
                     TPM policy measures; Secure Boot verifying all of it (a signed unified \
                     kernel image) narrows this, and a GRUB configuration and initrd are not \
                     verified. A pcrlock policy \
                     (Tier 2) that covers the boot loader (PCR 4) is worth having in addition: \
                     {PCRLOCK_STEPS} ({DOC}).{unknown}"
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
             addition to encryption, not instead of it: {PCRLOCK_STEPS} ({DOC}).{unknown}",
            subject.sentence_start(),
            subject.verb(),
        ),
        warn: true,
    })
}

/// A directory as the older-daemon fallback can resolve it: the local
/// override, then systemd's value, then the default. A relative override
/// cannot establish the running daemon's path because its working directory
/// may differ from the CLI's.
fn daemon_dir(var: &str, default: Result<PathBuf, String>) -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os(var) {
        let path = PathBuf::from(value);
        return if path.is_absolute() {
            Ok(path)
        } else {
            Err(format!(
                "{var} is relative and irlumed's working directory is unknown"
            ))
        };
    }
    match crate::uninstall::daemon_env(var) {
        crate::uninstall::DaemonEnv::Set(dir) => Ok(dir),
        crate::uninstall::DaemonEnv::NotSet => default,
        crate::uninstall::DaemonEnv::Unknown => Err(format!(
            "systemd could not establish {var}; its environment sources or installed unit could not be resolved"
        )),
    }
}

/// The installed system's storage also matters because an offline change
/// to its executables or configuration can expose the sealed secrets.
const SYSTEM_DIRS: [&str; 3] = ["/", "/usr", "/etc"];
const KEYRING_DIR_NAME: &str = "keyring directory (IRLUME_KEYRING_DIR)";
const TEMPLATE_KEY_DIR_NAME: &str = "template-key directory (IRLUME_TEMPLATE_KEY_DIR)";

fn unknown_directory(path: &str, reason: String) -> StorageDirectory {
    StorageDirectory {
        path: path.to_string(),
        encryption: StorageEncryption::Unknown,
        reason: Some(reason),
    }
}

/// Resolve each secret directory independently, so an unresolved state
/// directory does not hide an explicit keyring or template-key override.
/// The shared probe leaves inaccessible directories unknown because their
/// unseen links or mounts may lead to another filesystem.
fn fallback_storage(
    sealed: &Sealed,
    dir: impl Fn(&str, Result<PathBuf, String>) -> Result<PathBuf, String>,
    mut probe: impl FnMut(&Path) -> StorageDirectory,
) -> Vec<StorageDirectory> {
    let state = dir("IRLUME_STATE_DIR", Ok(irlume_common::state_dir()));
    let mut dirs = Vec::new();
    for (needed, var, name, child) in [
        (
            sealed.keyring != KeyringSeal::NotArmed,
            "IRLUME_KEYRING_DIR",
            KEYRING_DIR_NAME,
            "keyring",
        ),
        (
            sealed.template_key != Some(false),
            "IRLUME_TEMPLATE_KEY_DIR",
            TEMPLATE_KEY_DIR_NAME,
            "template-keys",
        ),
    ] {
        if needed {
            let default = state.clone().map(|state| state.join(child));
            dirs.push(match dir(var, default) {
                Ok(path) => probe(&path),
                Err(reason) => unknown_directory(name, reason),
            });
        }
    }
    dirs.extend(SYSTEM_DIRS.map(|path| probe(Path::new(path))));
    dirs
}

/// A daemon answer is authoritative even when it reports unknown storage.
/// Only an unsupported request or an unavailable connection permits the
/// older CLI-side probe. Invalid replies and other daemon errors remain
/// unknown, rather than being replaced with this process's directories.
fn storage_for(
    sealed: &Sealed,
    ask: impl FnOnce(&Request) -> std::io::Result<Response>,
    fallback: impl FnOnce() -> Vec<StorageDirectory>,
) -> Vec<StorageDirectory> {
    let (keyring, template_key, mut system) = match ask(&Request::SealedStorage) {
        Ok(Response::SealedStorage {
            keyring,
            template_key,
            system,
        }) => (keyring, template_key, system),
        Ok(Response::Error(error)) if error == "bad request" => return fallback(),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            return fallback()
        }
        reply => {
            let reason = match reply {
                Ok(Response::Error(error)) => format!("irlumed could not report storage: {error}"),
                Err(error) => format!("irlumed's storage reply could not be read: {error}"),
                _ => "irlumed returned an unexpected storage reply".to_string(),
            };
            (
                unknown_directory(KEYRING_DIR_NAME, reason.clone()),
                unknown_directory(TEMPLATE_KEY_DIR_NAME, reason.clone()),
                SYSTEM_DIRS
                    .map(|path| unknown_directory(path, reason.clone()))
                    .to_vec(),
            )
        }
    };
    // All three installed-system paths are part of the response contract.
    // A partial answer cannot establish encryption of the installed system.
    for path in SYSTEM_DIRS {
        if !system.iter().any(|dir| dir.path == path) {
            system.push(unknown_directory(
                path,
                "irlumed omitted this installed-system directory from its storage reply".into(),
            ));
        }
    }
    let mut dirs = Vec::new();
    if sealed.keyring != KeyringSeal::NotArmed {
        dirs.push(keyring);
    }
    if sealed.template_key != Some(false) {
        dirs.push(template_key);
    }
    dirs.extend(system);
    dirs
}

/// The least protected directory decides: no dm-crypt found, then unknown,
/// then encrypted. Keep the other results so unknown paths retain their
/// explanations even when an unencrypted directory determines the warning.
fn least_protected(dirs: &[StorageDirectory]) -> Option<&StorageDirectory> {
    dirs.iter().min_by_key(|dir| match dir.encryption {
        StorageEncryption::NotEncrypted => 0,
        StorageEncryption::Unknown => 1,
        StorageEncryption::Encrypted => 2,
    })
}

/// Paths and probe errors can contain control characters from filesystem
/// names. Blank them before adding them to terminal guidance.
fn storage_text(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// `paths` as "a", "a and b" or "a, b and c".
fn and_list(paths: &[String]) -> String {
    match paths {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// [`guidance`] for the least protected of `dirs`, followed by why each
/// unknown one could not be established. A reason shared by several
/// directories, such as a daemon error that leaves all of them unknown, is
/// given once for all of them.
fn storage_guidance(sealed: &Sealed, dirs: &[StorageDirectory]) -> Option<SealAdvice> {
    let missing = unknown_directory(
        "irlumed's storage directories",
        "no storage results were returned".into(),
    );
    let directory = least_protected(dirs).unwrap_or(&missing);
    let path = storage_text(&directory.path);
    let mut advice = guidance(sealed, directory.encryption, Path::new(&path))?;
    let mut unknown: Vec<(&str, Vec<String>)> = Vec::new();
    for directory in dirs
        .iter()
        .filter(|dir| dir.encryption == StorageEncryption::Unknown)
    {
        let reason = directory
            .reason
            .as_deref()
            .unwrap_or("the probe did not report a reason");
        let path = storage_text(&directory.path);
        match unknown.iter_mut().find(|(shared, _)| *shared == reason) {
            Some((_, paths)) => paths.push(path),
            None => unknown.push((reason, vec![path])),
        }
    }
    for (reason, paths) in unknown {
        advice.text.push_str(&format!(
            " Storage under {} could not be established: {}.",
            and_list(&paths),
            storage_text(reason),
        ));
    }
    Some(advice)
}

/// Ask irlumed to inspect its own directories before trying the compatible
/// local fallback, whose environment may differ from the running daemon's.
fn sealed_storage(sealed: &Sealed) -> Vec<StorageDirectory> {
    storage_for(sealed, irlume_common::client::request, || {
        fallback_storage(
            sealed,
            daemon_dir,
            irlume_common::storage_encryption::directory_encryption,
        )
    })
}

/// Guidance uses the same daemon-owned directories after every seal and in
/// doctor. Storage is queried only when something is known to be sealed.
pub(crate) fn state_dir_guidance(sealed: &Sealed) -> Option<SealAdvice> {
    Subject::of(sealed)?;
    storage_guidance(sealed, &sealed_storage(sealed))
}

/// The line `keyring arm` prints for `advice`: a warning, or a note for
/// information.
pub(crate) fn arm_note(advice: &SealAdvice) -> String {
    let label = if advice.warn { "WARNING" } else { "NOTE" };
    format!("[keyring] {label}: {}", advice.text)
}

/// Doctor's `sealed-storage` check for `user`: `warn` with the guidance
/// where no dm-crypt layer is found under the directory probed (or that
/// cannot be established), `info` with it on encrypted storage (whose unlock
/// method the storage does not show) and when nothing is sealed, and
/// `unknown` when the daemon did not say what is sealed. `probe` runs only
/// when something is sealed.
pub(crate) fn check(
    user: &str,
    sealed: &Sealed,
    probe: impl FnOnce() -> Vec<StorageDirectory>,
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
    match storage_guidance(sealed, &probe()) {
        Some(advice) if advice.warn => (State::Warn, advice.text),
        Some(advice) => (State::Info, advice.text),
        // Not reached: something is sealed, so there is guidance.
        None => (
            State::Unknown,
            format!("irlumed did not say what is sealed for {user}"),
        ),
    }
}

/// [`check`] against the directories irlumed keeps what is sealed in
/// ([`sealed_storage`]) and this system's storage.
pub(crate) fn state_dir_check(user: &str, sealed: &Sealed) -> (State, String) {
    check(user, sealed, || sealed_storage(sealed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

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
    const TEMPLATE_LITERAL: &str = "The template key is sealed under the policy chosen when it \
                                    was sealed: with no pcrlock policy that seals use, the \
                                    literal PCR policy (Tier 3)";
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
                "/var/lib/irlume and the installed system (/, /usr and /etc) are on encrypted \
                 storage, which protects the sealed secrets at rest only if those volumes ask \
                 for a passphrase or PIN to unlock"
            ) && advice.text.contains(STEPS)
                && advice.text.contains(
                    "What the boot reads before the volume is unlocked (the EFI system \
                     partition, an unencrypted /boot) is not encrypted and can be changed \
                     offline to capture the passphrase or PIN, whatever the TPM policy measures"
                ),
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
        // A daemon that could not say what is armed does not hide it: the
        // warning says the keyring secret may be sealed as well.
        const MAYBE_KEYRING: &str = " irlume could not learn from irlumed whether the keyring \
                                     secret is armed as well; if it is, what is said here about \
                                     the storage applies to it too, under the policy it was \
                                     sealed with.";
        let unknown = warning(
            &sealed(KeyringSeal::Unknown, Some(true)),
            StorageEncryption::NotEncrypted,
        );
        assert!(unknown.ends_with(MAYBE_KEYRING), "{unknown}");
        assert_eq!(unknown.replace(MAYBE_KEYRING, ""), text);
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
                &sealed(literal(Vec::new()), Some(false)),
                StorageEncryption::NotEncrypted
            ),
            text
        );
        // A daemon that could not say whether a template key is sealed does
        // not hide it.
        let unknown = warning(
            &sealed(literal(vec![7]), None),
            StorageEncryption::NotEncrypted,
        );
        assert!(
            unknown.contains(
                "irlume could not learn from irlumed whether a template key is sealed as well; \
                 if one is, what is said here about the storage applies to it too, under the \
                 policy it was sealed with, which irlume does not report."
            ),
            "{unknown}"
        );
    }

    /// Both sealed: the subject names both, and each policy has its own
    /// sentence, since a template key keeps the policy it was sealed under
    /// when the keyring secret is armed under another set.
    #[test]
    fn a_keyring_secret_and_a_template_key_are_each_described() {
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
            text.contains("The keyring secret is sealed under the literal PCR 7 policy (Tier 3)")
                && text.contains(DIRECT)
                && text.contains("can unseal the keyring secret directly")
                && text.contains(TEMPLATE_LITERAL)
                && !text.contains("can unseal both directly"),
            "{text}"
        );
        let text = information(&sealed(literal(vec![7, 11]), Some(true)));
        assert!(
            text.starts_with(
                "The keyring secret is sealed under a literal PCR policy over PCRs 7, 11"
            ) && text.contains(TEMPLATE_LITERAL),
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

    #[test]
    fn incomplete_daemon_storage_keeps_the_missing_system_directory_unknown() {
        let sealed = sealed(literal(vec![7]), Some(false));
        let dirs = storage_for(
            &sealed,
            |_| {
                let Response::SealedStorage {
                    keyring,
                    template_key,
                    ..
                } = storage_reply()
                else {
                    unreachable!()
                };
                Ok(Response::SealedStorage {
                    keyring,
                    template_key,
                    system: Vec::new(),
                })
            },
            || panic!("an incomplete answer must not use local probes"),
        );
        let advice = storage_guidance(&sealed, &dirs).unwrap();
        assert!(advice.warn);
        for path in SYSTEM_DIRS {
            let directory = dirs.iter().find(|dir| dir.path == path).unwrap();
            assert_eq!(directory.encryption, StorageEncryption::Unknown);
            assert!(directory.reason.as_deref().unwrap().contains("omitted"));
        }
    }

    #[test]
    fn storage_guidance_blanks_control_characters_in_paths_and_reasons() {
        let dirs = vec![unknown_directory(
            "/state/\x1b[2Jkeys",
            "cannot\nresolve".into(),
        )];
        let advice = storage_guidance(&sealed(literal(vec![7]), Some(false)), &dirs).unwrap();
        assert!(!advice.text.chars().any(char::is_control));
        assert!(advice.text.contains("/state/ [2Jkeys"));
        assert!(advice.text.contains("cannot resolve"));
    }

    #[test]
    fn the_least_protected_directory_decides() {
        let dirs = [
            storage_directory("/enc/a", StorageEncryption::Encrypted),
            storage_directory("/plain/b", StorageEncryption::NotEncrypted),
            storage_directory("/unknown/c", StorageEncryption::Unknown),
        ];
        assert_eq!(least_protected(&dirs).unwrap().path, "/plain/b");
        assert_eq!(
            least_protected(&[dirs[0].clone(), dirs[2].clone()])
                .unwrap()
                .path,
            "/unknown/c"
        );
        assert_eq!(least_protected(&dirs[..1]).unwrap().path, "/enc/a");
        assert_eq!(least_protected(&[]), None);
    }

    #[test]
    fn each_sealed_secret_is_probed_where_it_is_kept() {
        for (keyring, template, expected) in [
            (literal(vec![7]), Some(false), vec!["/state/keyring"]),
            (
                KeyringSeal::NotArmed,
                Some(true),
                vec!["/override/templates"],
            ),
            (
                literal(vec![7]),
                None,
                vec!["/state/keyring", "/override/templates"],
            ),
        ] {
            let dirs = fallback_storage(
                &sealed(keyring, template),
                |var, default| match var {
                    "IRLUME_STATE_DIR" => Ok(PathBuf::from("/state")),
                    "IRLUME_TEMPLATE_KEY_DIR" => Ok(PathBuf::from("/override/templates")),
                    _ => default,
                },
                |path| storage_directory(path.to_str().unwrap(), StorageEncryption::Encrypted),
            );
            let paths: Vec<_> = dirs.iter().map(|dir| dir.path.as_str()).collect();
            let mut expected = expected;
            expected.extend(SYSTEM_DIRS);
            assert_eq!(paths, expected);
        }
    }

    #[test]
    fn a_relative_local_override_is_unknown_in_the_fallback() {
        let _guard = crate::testenv::ENV_LOCK.lock().unwrap();
        let previous = std::env::var_os("IRLUME_KEYRING_DIR");
        std::env::set_var("IRLUME_KEYRING_DIR", "relative-keyring");
        let answer = daemon_dir("IRLUME_KEYRING_DIR", Ok(PathBuf::from("/default/keyring")));
        match previous {
            Some(value) => std::env::set_var("IRLUME_KEYRING_DIR", value),
            None => std::env::remove_var("IRLUME_KEYRING_DIR"),
        }
        let reason = answer.expect_err("the daemon's working directory is unknown");
        assert!(reason.contains("IRLUME_KEYRING_DIR") && reason.contains("relative"));
    }

    fn storage_directory(
        path: &str,
        encryption: StorageEncryption,
    ) -> irlume_common::StorageDirectory {
        irlume_common::StorageDirectory {
            path: path.into(),
            encryption,
            reason: None,
        }
    }

    fn storage_reply() -> Response {
        Response::SealedStorage {
            keyring: storage_directory("/daemon/keyring", StorageEncryption::Encrypted),
            template_key: storage_directory(
                "/daemon/template-keys",
                StorageEncryption::NotEncrypted,
            ),
            system: SYSTEM_DIRS
                .iter()
                .map(|path| storage_directory(path, StorageEncryption::Encrypted))
                .collect(),
        }
    }

    #[test]
    fn daemon_storage_wins_and_only_sealed_directories_count() {
        for (keyring, template, expected) in [
            (literal(vec![7]), Some(false), "/daemon/keyring"),
            (KeyringSeal::NotArmed, Some(true), "/daemon/template-keys"),
            (literal(vec![7]), None, "/daemon/template-keys"),
        ] {
            let sealed = sealed(keyring, template);
            let dirs = storage_for(
                &sealed,
                |request| {
                    assert!(matches!(request, Request::SealedStorage));
                    Ok(storage_reply())
                },
                || {
                    panic!("the daemon's answer must take precedence over local environment and probes")
                },
            );
            assert_eq!(least_protected(&dirs).unwrap().path, expected);
            assert_eq!(
                dirs.len(),
                if sealed.template_key.is_none() { 5 } else { 4 }
            );
            assert!(dirs.iter().any(|dir| dir.path == "/usr"));
        }
    }

    #[test]
    fn an_unknown_daemon_probe_is_authoritative() {
        let sealed = sealed(literal(vec![7]), Some(false));
        let dirs = storage_for(
            &sealed,
            |_| {
                let Response::SealedStorage {
                    template_key,
                    system,
                    ..
                } = storage_reply()
                else {
                    unreachable!()
                };
                Ok(Response::SealedStorage {
                    keyring: unknown_directory(
                        "/daemon/keyring",
                        "mount information could not be read".into(),
                    ),
                    template_key,
                    system,
                })
            },
            || panic!("an unknown daemon result must not use local probes"),
        );
        let advice = storage_guidance(&sealed, &dirs).unwrap();
        assert!(advice.warn);
        assert!(advice.text.contains("/daemon/keyring"));
        assert!(advice.text.contains("mount information could not be read"));
    }

    #[test]
    fn old_or_unreachable_daemons_use_the_local_storage_fallback() {
        for reply in [
            Ok(Response::Error("bad request".into())),
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
        ] {
            let expected = vec![storage_directory(
                "/fallback/keyring",
                StorageEncryption::NotEncrypted,
            )];
            let dirs = storage_for(
                &sealed(literal(vec![7]), Some(false)),
                |_| reply,
                || expected.clone(),
            );
            assert_eq!(dirs, expected);
        }
    }

    #[test]
    fn other_daemon_errors_do_not_use_the_local_storage_fallback() {
        for reply in [
            Ok(Response::Error("permission denied".into())),
            Ok(Response::Error("bad request: policy refused".into())),
            Ok(Response::Error("storage unavailable".into())),
            Ok(Response::Ok("unexpected".into())),
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid reply",
            )),
        ] {
            let sealed = sealed(literal(vec![7]), Some(false));
            let dirs = storage_for(&sealed, |_| reply, || panic!("must not probe locally"));
            let advice = storage_guidance(&sealed, &dirs).unwrap();
            assert!(advice.warn);
            assert!(advice.text.contains("irlumed"), "{}", advice.text);
            assert!(dirs
                .iter()
                .all(|dir| dir.encryption == StorageEncryption::Unknown));
            assert!(dirs.iter().all(|dir| dir.reason.is_some()));
        }
    }

    /// A daemon error leaves every directory unknown for one reason, which
    /// the guidance states once for all of them; a reason that differs keeps
    /// its own sentence.
    #[test]
    fn a_reason_shared_by_several_directories_is_stated_once() {
        let sealed = sealed(literal(vec![7]), None);
        let busy = "daemon busy: too many open connections from this user";
        let mut dirs = storage_for(
            &sealed,
            |_| Ok(Response::Error(busy.into())),
            || panic!("must not probe locally"),
        );
        let advice = storage_guidance(&sealed, &dirs).unwrap();
        assert!(advice.warn);
        assert_eq!(advice.text.matches(busy).count(), 1, "{}", advice.text);
        assert!(
            advice.text.ends_with(
                " Storage under keyring directory (IRLUME_KEYRING_DIR), template-key directory \
                 (IRLUME_TEMPLATE_KEY_DIR), /, /usr and /etc could not be established: irlumed \
                 could not report storage: daemon busy: too many open connections from this \
                 user."
            ),
            "{}",
            advice.text
        );

        dirs[1].reason = Some("Permission denied (os error 13)".into());
        let advice = storage_guidance(&sealed, &dirs).unwrap();
        assert_eq!(advice.text.matches(busy).count(), 1, "{}", advice.text);
        for expected in [
            " Storage under keyring directory (IRLUME_KEYRING_DIR), /, /usr and /etc could not \
             be established: irlumed could not report storage: daemon busy",
            " Storage under template-key directory (IRLUME_TEMPLATE_KEY_DIR) could not be \
             established: Permission denied (os error 13).",
        ] {
            assert!(
                advice.text.contains(expected),
                "{expected}: {}",
                advice.text
            );
        }
    }

    #[test]
    fn unknown_directories_keep_their_names_and_reasons_when_plain_storage_wins() {
        let sealed = sealed(literal(vec![7]), Some(true));
        let dirs = vec![
            irlume_common::StorageDirectory {
                path: "keyring directory (IRLUME_KEYRING_DIR)".into(),
                encryption: StorageEncryption::Unknown,
                reason: Some("systemd could not establish IRLUME_KEYRING_DIR".into()),
            },
            irlume_common::StorageDirectory {
                path: "/daemon/template-keys".into(),
                encryption: StorageEncryption::Unknown,
                reason: Some("Permission denied (os error 13)".into()),
            },
            storage_directory("/usr", StorageEncryption::NotEncrypted),
        ];
        let advice = storage_guidance(&sealed, &dirs).unwrap();
        assert!(advice.warn);
        for expected in [
            "under /usr",
            "keyring directory (IRLUME_KEYRING_DIR)",
            "systemd could not establish IRLUME_KEYRING_DIR",
            "/daemon/template-keys",
            "Permission denied",
        ] {
            assert!(
                advice.text.contains(expected),
                "{expected}: {}",
                advice.text
            );
        }
    }

    #[test]
    fn fallback_resolves_each_secret_directory_independently() {
        let sealed = sealed(literal(vec![7]), Some(true));
        let dirs = fallback_storage(
            &sealed,
            |var, default| match var {
                "IRLUME_STATE_DIR" => Err("systemd could not establish IRLUME_STATE_DIR".into()),
                "IRLUME_KEYRING_DIR" => Ok(PathBuf::from("/explicit/keyring")),
                _ => default,
            },
            |path| storage_directory(path.to_str().unwrap(), StorageEncryption::Encrypted),
        );
        assert_eq!(dirs[0].path, "/explicit/keyring");
        assert_eq!(dirs[0].encryption, StorageEncryption::Encrypted);
        assert_eq!(
            dirs[1].path,
            "template-key directory (IRLUME_TEMPLATE_KEY_DIR)"
        );
        assert_eq!(dirs[1].encryption, StorageEncryption::Unknown);
        assert!(dirs[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("IRLUME_STATE_DIR"));
        assert_eq!(dirs.len(), 5);
    }

    #[test]
    fn fallback_keeps_unreachable_storage_unknown() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("irlume-seal-unreachable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("locked/keyring")).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(
                    self.0.join("locked"),
                    std::fs::Permissions::from_mode(0o700),
                );
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let keyring = root.join("locked/keyring");
        if std::fs::metadata(&keyring).is_ok() {
            return;
        }
        let dirs = fallback_storage(
            &sealed(literal(vec![7]), Some(false)),
            |var, default| {
                if var == "IRLUME_KEYRING_DIR" {
                    Ok(keyring.clone())
                } else {
                    default
                }
            },
            |path| {
                if path == keyring {
                    irlume_common::storage_encryption::directory_encryption(path)
                } else {
                    storage_directory(path.to_str().unwrap(), StorageEncryption::Encrypted)
                }
            },
        );
        assert_eq!(dirs[0].path, keyring.to_string_lossy());
        assert_eq!(dirs[0].encryption, StorageEncryption::Unknown);
        assert!(dirs[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("Permission denied"));
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
                        .contains("only if those volumes ask for a passphrase"),
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
                    && !text.contains("the Secure Boot state"),
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

    fn check_one(
        user: &str,
        sealed: &Sealed,
        state_dir: &Path,
        probe: impl FnOnce(&Path) -> StorageEncryption,
    ) -> (State, String) {
        check(user, sealed, || {
            vec![storage_directory(
                state_dir.to_str().unwrap(),
                probe(state_dir),
            )]
        })
    }

    #[test]
    fn the_doctor_check_states() {
        let never = |_: &Path| -> StorageEncryption { panic!("must not probe") };
        let dir = Path::new(DIR);
        let (state, detail) = check_one(
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
            let (state, detail) = check_one("tester", &sealed, dir, never);
            assert_eq!(state, State::Unknown, "{sealed:?}");
            assert!(detail.contains("irlumed did not say"), "{detail}");
        }

        let asked = RefCell::new(None);
        let (state, detail) = check_one(
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
            detail.contains("/srv/irlume-state and the installed system") && detail.contains(GRUB),
            "{detail}"
        );
        assert_eq!(
            asked.borrow().as_deref(),
            Some(Path::new("/srv/irlume-state"))
        );

        // Nothing on encrypted storage is a pass.
        let (state, _) = check_one("tester", &sealed(pcrlock(), None), dir, |_| {
            StorageEncryption::Encrypted
        });
        assert_eq!(state, State::Info);
        let unknown_keyring = sealed(KeyringSeal::Unknown, Some(true));
        let (state, detail) = check_one("tester", &unknown_keyring, dir, |_| {
            StorageEncryption::Encrypted
        });
        assert_eq!(state, State::Info);
        assert!(detail.starts_with(TEMPLATE_LITERAL), "{detail}");

        let tier_3 = sealed(literal(vec![7]), Some(true));
        let (state, detail) = check_one("tester", &tier_3, dir, |_| StorageEncryption::Encrypted);
        assert_eq!(state, State::Info);
        assert_eq!(
            Some(detail),
            advise(&tier_3, StorageEncryption::Encrypted).map(|advice| advice.text)
        );
        for storage in [StorageEncryption::NotEncrypted, StorageEncryption::Unknown] {
            let (state, detail) = check_one("tester", &tier_3, dir, |_| storage);
            assert_eq!(state, State::Warn);
            let expected = advise(&tier_3, storage).unwrap().text;
            assert!(detail.starts_with(&expected), "{detail}");
            if storage == StorageEncryption::Unknown {
                assert!(
                    detail.contains("the probe did not report a reason"),
                    "{detail}"
                );
            }
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
