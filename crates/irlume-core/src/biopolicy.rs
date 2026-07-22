// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Tiered biometric decision policy (opt-in).
//!
//! Two axes decide what a face match is allowed to do:
//!   * **Tier**: the assurance of the modality that produced the match.
//!     `Secure` = an IR-verified match (irlume's cross-spectrum liveness gate
//!     ran), `Convenience` = RGB-only. (In practice irlume's liveness already
//!     requires IR for any grant, so a grant is normally `Secure`; the tier is
//!     kept explicit for correctness and future RGB-only fallbacks.)
//!   * **OperationClass**: what the PAM service is trying to do, derived from
//!     its service name.
//!
//! [`decide`] maps `(class, tier)` to an [`Action`]: release the sealed
//! credential (`Unseal`), only verify identity without releasing it (`Verify`),
//! or refuse (`Deny`). The headline rules: a credential is only released to a
//! `Secure`-tier match, a screen-unlock or polkit prompt never releases a
//! credential, and an unknown / remote service is always denied.
//!
//! This is pure logic with no I/O; the daemon consults it only when biopolicy
//! enforcement is enabled (default off; see the daemon), so it never changes
//! behaviour until an operator opts in.

/// Assurance tier of a face match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// RGB-only; no IR liveness behind the match.
    Convenience,
    /// IR-verified (cross-spectrum liveness ran).
    Secure,
}

/// What a PAM service is trying to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationClass {
    /// Unlocking a live session (KDE/GNOME lock screen): the wallet is already
    /// open, so no credential needs releasing.
    ScreenUnlock,
    /// A cold login at a display-manager greeter: releasing the sealed password
    /// lets the keyring/wallet open.
    Login,
    /// Privilege elevation (sudo/su): verify identity; no keyring.
    Elevation,
    /// A polkit prompt approving an action for an application (Bitwarden vault
    /// unlock, pkexec, systemd unit control). Verify-only, and the sealed
    /// credential is NEVER released to it: the polkit agent starts the PAM
    /// conversation the moment its dialog opens, with no user gesture, so this
    /// class must not be able to pull anything out of the TPM. The engine also
    /// forces the passive-liveness blink gate for it (see
    /// [`requires_consent_gesture`]).
    AppConsent,
    /// Remote access (sshd, etc.); face auth must never satisfy this.
    Remote,
    /// Unrecognised service; fail closed.
    Unknown,
}

/// What the daemon may do for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Match-only; do NOT release the sealed credential.
    Verify,
    /// Release the TPM-sealed credential (keyring unlock).
    Unseal,
    /// Refuse; cascade to the password.
    Deny,
}

/// Classify a PAM service name into an [`OperationClass`]. `warm` is true when a
/// user session is already active (so an ambiguous service that drives both a
/// cold greeter and a live lock screen is treated as a screen unlock).
pub fn classify(service: &str, warm: bool) -> OperationClass {
    let s = service.trim().to_ascii_lowercase();
    match s.as_str() {
        // Lock screens (live session).
        "kde" | "kde-fingerprint" | "kscreensaver" | "xscreensaver" | "gnome-screensaver"
        | "swaylock" | "i3lock" | "hyprlock" => OperationClass::ScreenUnlock,
        // Display-manager greeters (cold login), incl. GDM's separate
        // fingerprint login service (`gdm-fingerprint`), same login class.
        // `cosmic-greeter` (COSMIC / Pop!_OS) uses one service for both the cold
        // login and the live lock screen, so the warm/cold flag below is what
        // separates its login from its screen-unlock.
        "sddm" | "sddm-greeter" | "plasmalogin" | "gdm-password" | "gdm-fingerprint" | "gdm"
        | "gdm3" | "lightdm" | "login" | "greetd" | "ly" | "cosmic-greeter" => {
            if warm {
                OperationClass::ScreenUnlock
            } else {
                OperationClass::Login
            }
        }
        // Elevation.
        "sudo" | "sudo-i" | "su" | "su-l" | "doas" => OperationClass::Elevation,
        // polkit's agent helper hardcodes pam_start("polkit-1", ...); "polkit"
        // is kept for any downstream that renames the service file.
        "polkit-1" | "polkit" => OperationClass::AppConsent,
        // Remote / network: never satisfiable by face.
        "sshd" | "remote" | "cockpit" => OperationClass::Remote,
        _ => OperationClass::Unknown,
    }
}

/// The core gate: what is this `(class, tier)` allowed to do?
pub fn decide(class: OperationClass, tier: Tier) -> Action {
    match class {
        // Remote/unknown are never satisfiable by a face match.
        OperationClass::Remote | OperationClass::Unknown => Action::Deny,
        // A live-session unlock only needs identity, never a credential release.
        OperationClass::ScreenUnlock => Action::Verify,
        // A polkit approval only needs identity, and only from the IR tier: an
        // RGB-only match must not approve app actions (a printed photo held up
        // to a webcam would satisfy every polkit prompt in the session).
        OperationClass::AppConsent => match tier {
            Tier::Secure => Action::Verify,
            Tier::Convenience => Action::Deny,
        },
        // Credential-releasing operations require the Secure (IR) tier.
        OperationClass::Login | OperationClass::Elevation => match tier {
            Tier::Secure => Action::Unseal,
            Tier::Convenience => Action::Deny,
        },
    }
}

/// True for classes where a face grant must additionally pass the passive
/// blink gate even when the user's enrollment did not opt in. polkit agents
/// (KDE, GNOME Shell) start the PAM conversation as soon as their dialog
/// opens, so without this a face match completes with no user action at all;
/// requiring a natural blink guarantees a live person is looking at the
/// dialog that names what is being approved.
pub fn requires_consent_gesture(class: OperationClass) -> bool {
    matches!(class, OperationClass::AppConsent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_unlock_never_unseals() {
        assert_eq!(
            decide(classify("kde-fingerprint", true), Tier::Secure),
            Action::Verify
        );
    }

    #[test]
    fn cold_login_with_ir_unseals_but_rgb_only_denies() {
        assert_eq!(
            decide(classify("plasmalogin", false), Tier::Secure),
            Action::Unseal
        );
        assert_eq!(
            decide(classify("plasmalogin", false), Tier::Convenience),
            Action::Deny
        );
    }

    #[test]
    fn warm_greeter_is_a_screen_unlock() {
        assert_eq!(classify("plasmalogin", true), OperationClass::ScreenUnlock);
        assert_eq!(classify("plasmalogin", false), OperationClass::Login);
    }

    #[test]
    fn cosmic_greeter_logs_in_cold_and_unlocks_warm() {
        // COSMIC uses one `cosmic-greeter` service for both the cold login and
        // the live lock screen; the warm flag must split them, and a cold login
        // must reach Unseal on the Secure (IR) tier; else it classifies Unknown
        // and the daemon denies the face match.
        assert_eq!(classify("cosmic-greeter", false), OperationClass::Login);
        assert_eq!(
            classify("cosmic-greeter", true),
            OperationClass::ScreenUnlock
        );
        assert_eq!(
            decide(classify("cosmic-greeter", false), Tier::Secure),
            Action::Unseal
        );
    }

    #[test]
    fn gdm_fingerprint_is_a_login_service() {
        // GDM's separate fingerprint login service must classify as a login /
        // unlock class, else the keyring-unseal gate (ADR-0003) refuses it.
        assert_eq!(classify("gdm-fingerprint", false), OperationClass::Login);
        assert_eq!(
            classify("gdm-fingerprint", true),
            OperationClass::ScreenUnlock
        );
    }

    #[test]
    fn remote_and_unknown_always_deny() {
        assert_eq!(decide(classify("sshd", false), Tier::Secure), Action::Deny);
        assert_eq!(
            decide(classify("some-random-service", false), Tier::Secure),
            Action::Deny
        );
    }

    #[test]
    fn sudo_is_elevation() {
        assert_eq!(classify("sudo", false), OperationClass::Elevation);
        assert_eq!(
            decide(OperationClass::Elevation, Tier::Secure),
            Action::Unseal
        );
    }

    #[test]
    fn polkit_verifies_but_never_unseals() {
        // The B6 stance: a polkit prompt may be satisfied by a face match
        // (verify) but must never release the TPM-sealed credential, on any
        // tier, warm or cold.
        for warm in [false, true] {
            assert_eq!(classify("polkit-1", warm), OperationClass::AppConsent);
        }
        assert_eq!(
            decide(OperationClass::AppConsent, Tier::Secure),
            Action::Verify
        );
        assert_eq!(
            decide(OperationClass::AppConsent, Tier::Convenience),
            Action::Deny
        );
    }

    #[test]
    fn polkit_requires_the_consent_gesture_and_others_do_not() {
        assert!(requires_consent_gesture(classify("polkit-1", false)));
        for svc in ["sudo", "kde", "plasmalogin", "sshd", "nonsense"] {
            assert!(!requires_consent_gesture(classify(svc, false)), "{svc}");
        }
    }
}
