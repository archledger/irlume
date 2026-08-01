// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The PAM lines irlume writes, and the module names it looks for.
//!
//! Text only: no parsing, no file access, no policy. Split out so the exact
//! bytes that land in a user's auth stack are reviewable in one place.

pub(super) const MODULE: &str = "pam_irlume.so";

pub(crate) const BACKUP: &str = ".pre-irlume";

pub(super) const CREATED_PREFIX: &str = "# irlume: created from ";

/// The one sentence that explains the on-demand trigger; shared so the status
/// line, the plan line, and docs/SETUP.md's mirror never drift apart.
pub(super) const ONDEMAND_HINT: &str = "leave the password empty and press Enter to use your face";

// Greeter block for a non-`@include` (Fedora `substack`) stack: a `success=1`
// jump over the password substack, plus the `PERMIT_LANDING` it lands on.
/// Jump-style face line for a submit-driven greeter we have NOT validated for the
/// on-demand probe (old GDM, unknown DM). `facefirst` is mandatory here: without
/// it the module runs the ACTIVE probe (`pam_get_authtok`), and a greeter that
/// blocks that probe until the user types means face never fires at all.
pub(super) const GREETER_UNSEAL_FACEFIRST_JUMP: &str =
    "auth       [success=1 default=ignore]   pam_irlume.so unseal facefirst";

/// The greeter/locker face line for any INCLUDE layout: Debian/Ubuntu
/// `@include common-auth` and Arch `auth include system-login` alike (a
/// `success=N` jump can't skip an include expansion, so this can't be the jump
/// form). Always `sufficient`: the same control works for EVERY DM's locker
/// (GDM and cosmic alike short-circuit on a warm unlock). Cold-login keyring
/// unlock is handled by the module's `kr` arg, NOT the control: on a cold login
/// the module returns IGNORE (having set the token), so `sufficient` continues to
/// pam_unix + pam_gnome_keyring; a warm lock returns SUCCESS and short-circuits.
/// `mode` is `facefirst` (GDM scan-immediately) or `ondemand` (empty-Enter). `kr`
/// adds the keyring-continue arg: true for greeters (cold login unlocks the
/// keyring), false for a separate warm lock service (keyring already open).
pub(super) fn include_greeter_line(mode: &str, kr: bool) -> String {
    let kr_arg = if kr { " kr" } else { "" };
    format!("auth       sufficient   pam_irlume.so unseal {mode}{kr_arg}")
}

/// Jump-style variant for a non-`@include` (e.g. Fedora) COSMIC stack.
pub(super) const GREETER_UNSEAL_COSMIC_JUMP: &str =
    "auth       [success=1 default=ignore]   pam_irlume.so unseal ondemand";

// Tagged so unwire strips OUR landing but never a foreign pam_permit.so the
// stack legitimately carries (the trailing `#…` is a PAM comment, ignored).
pub(super) const PERMIT_LANDING: &str =
    "auth       optional                     pam_permit.so   # irlume-landing";

pub(super) const RESEAL_AUTH: &str = "auth       optional                     pam_irlume.so reseal";

/// Post-auth login-keyring unlock for the FINGERPRINT path: runs after a trusted
/// factor succeeded; if no password is present (fingerprint login) it unseals
/// the TPM-sealed password and sets PAM_AUTHTOK so pam_gnome_keyring opens the
/// wallet. No-op when the keyring isn't armed or a password is already set.
pub(super) const KEYRING_UNSEAL: &str =
    "auth       optional                     pam_irlume.so keyring";

/// Tag on the gnome-keyring lines irlume ADDS to a fingerprint stack, so unwiring
/// removes exactly ours and never a keyring line the distro shipped. Linux-PAM
/// strips a trailing `#` comment before tokenizing (verified against
/// `pam_exec.so`: an argument survives, a trailing comment does not), so this is
/// invisible to the module — which matters here because gnome-keyring's
/// `parse_args` syslogs a warning for every option it does not recognize.
pub(super) const KEYRING_TAG: &str = "# irlume-keyring";

/// GDM's `gdm-fingerprint` stack carries NO keyring module at all (verified on
/// upstream `data/pam-redhat/gdm-fingerprint.pam` through GDM 50.0), so the
/// `KEYRING_UNSEAL` line above would set a token nothing reads. These are the
/// two halves gnome-keyring needs, added only when the stack has no consumer of
/// its own. The leading `-` is PAM's "do not complain if the module is missing",
/// so a machine without gnome-keyring installed is unaffected.
pub(super) const FP_GKR_AUTH: &str =
    "-auth      optional                     pam_gnome_keyring.so   # irlume-keyring";

pub(super) const FP_GKR_SESSION: &str =
    "-session   optional                     pam_gnome_keyring.so auto_start   # irlume-keyring";

pub(super) const RESEAL_SESSION: &str =
    "session    optional                     pam_irlume.so reseal";

/// The plain verify stanza, shared by `sudo` and polkit prompts (Bitwarden vault
/// unlock, pkexec, systemd unit control): no `unseal` (the daemon refuses
/// credential release for both classes anyway) and no mode arg (each surface runs
/// the PAM conversation as soon as it prompts, which IS the face-first trigger;
/// the daemon adds the forced consent gesture on top).
pub(super) const VERIFY_STANZA: &str = "auth       sufficient                   pam_irlume.so";

/// Login-keyring modules that CONSUME the password an `unseal` line releases.
/// KDE's kwallet-pam still installs `pam_kwallet5.so` under Plasma 6 (the
/// running provider process is `ksecretd`, but the PAM module kept the 5 in its
/// name); older Plasma and a few distros ship `pam_kwallet.so`. GNOME ships
/// `pam_gnome_keyring.so`.
pub(super) const KEYRING_CONSUMERS: &[&str] =
    &["pam_kwallet5.so", "pam_kwallet.so", "pam_gnome_keyring.so"];
