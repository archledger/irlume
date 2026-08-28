// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! What a PAM service name is, in one place.
//!
//! Three consumers used to keep their own hard-coded lists and had already
//! drifted (#362): `biopolicy::classify` in irlume-core decided the operation
//! class, `is_sudo_like` in irlume-auth decided the grace window, and
//! `irlume-pam` decided whether to tell the user which consent gesture to make.
//! `doas` was in the first and missing from the second, so it got the 15s login
//! window instead of the 5s elevation one.
//!
//! This lives in irlume-common rather than irlume-core because irlume-pam
//! depends only on common, and a table one of the three consumers cannot reach
//! is not a shared table.
//!
//! What this CANNOT do is make the set exhaustive: the key is a string, so no
//! compiler check can notice a service name some upstream package invents
//! tomorrow. What it does guarantee is that once a name is here, every consumer
//! gets its answer from the same row instead of three lists drifting apart.

/// What a service is, as far as any consumer needs to know.
///
/// Deliberately not tier-aware and not session-aware: the greeter
/// services that drive both a cold login and a live lock screen are separated
/// by session state, which only irlume-core tracks, so this reports the
/// ambiguity rather than guessing at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// A lock screen in an already-running session.
    ScreenUnlock,
    /// A display-manager greeter. Some of these also serve the live lock
    /// screen; the caller resolves that with session state.
    Greeter,
    /// Terminal privilege elevation.
    Elevation,
    /// An application asking for approval, via polkit.
    AppConsent,
    /// Remote or network access, never satisfiable by a face at this machine.
    Remote,
}

/// Every service name irlume recognises, with what it is.
///
/// Sourced, not guessed. The sudo/su/runuser names are the pam.d files util-linux
/// and sudo ship; `doas` is OpenDoas; `polkit-1` is what polkit's agent helper
/// passes to `pam_start`, and `polkit` is kept for any downstream that renames
/// the service file. Names nobody could show shipping somewhere are NOT added
/// here, because inventing plausible ones is how the three lists diverged.
///
/// `runuser` and `runuser-l` are present but note that standard util-linux
/// `runuser` starts a PAM transaction for account and session handling and
/// deliberately skips `pam_authenticate()`, so it does not normally reach an
/// irlume authentication at all.
pub const SERVICES: &[(&str, ServiceKind)] = &[
    // Lock screens (live session).
    ("kde", ServiceKind::ScreenUnlock),
    ("kde-fingerprint", ServiceKind::ScreenUnlock),
    ("kscreensaver", ServiceKind::ScreenUnlock),
    ("xscreensaver", ServiceKind::ScreenUnlock),
    ("gnome-screensaver", ServiceKind::ScreenUnlock),
    ("swaylock", ServiceKind::ScreenUnlock),
    ("i3lock", ServiceKind::ScreenUnlock),
    ("hyprlock", ServiceKind::ScreenUnlock),
    ("omarchy-lock-face", ServiceKind::ScreenUnlock),
    // The stock Omarchy lock's password lane: with the distro's autologin
    // default, this is where a cold boot actually prompts, and pam_irlume
    // wires into it with the polkit-style consent line.
    ("omarchy-lock-password", ServiceKind::ScreenUnlock),
    // Cinnamon's screensaver (Linux Mint and friends): a live-session screen
    // unlock. Live-validated on Mint 22.3: the dialog submits empty fields,
    // so the on-demand empty-Enter camera arm works there, the best lock UX
    // irlume has.
    ("cinnamon-screensaver", ServiceKind::ScreenUnlock),
    // Display-manager greeters (cold login), including GDM's separate
    // fingerprint login service, same login class.
    ("sddm", ServiceKind::Greeter),
    ("sddm-greeter", ServiceKind::Greeter),
    ("plasmalogin", ServiceKind::Greeter),
    ("gdm-password", ServiceKind::Greeter),
    ("gdm-fingerprint", ServiceKind::Greeter),
    ("gdm", ServiceKind::Greeter),
    ("gdm3", ServiceKind::Greeter),
    ("lightdm", ServiceKind::Greeter),
    ("login", ServiceKind::Greeter),
    ("greetd", ServiceKind::Greeter),
    ("ly", ServiceKind::Greeter),
    ("cosmic-greeter", ServiceKind::Greeter),
    // Elevation.
    ("sudo", ServiceKind::Elevation),
    ("sudo-i", ServiceKind::Elevation),
    ("su", ServiceKind::Elevation),
    ("su-l", ServiceKind::Elevation),
    ("runuser", ServiceKind::Elevation),
    ("runuser-l", ServiceKind::Elevation),
    ("doas", ServiceKind::Elevation),
    // Application consent.
    ("polkit-1", ServiceKind::AppConsent),
    ("polkit", ServiceKind::AppConsent),
    // Remote / network.
    ("sshd", ServiceKind::Remote),
    ("remote", ServiceKind::Remote),
    ("cockpit", ServiceKind::Remote),
];

/// Look a service name up, trimmed and case-folded the way every caller did
/// separately before. `None` is an unrecognised name, which every consumer
/// treats as its own most restrictive answer.
#[must_use]
pub fn classify(service: &str) -> Option<ServiceKind> {
    let s = service.trim().to_ascii_lowercase();
    SERVICES
        .iter()
        .find(|(name, _)| *name == s)
        .map(|(_, kind)| *kind)
}

impl ServiceKind {
    /// Whether a face attempt for this service needs an explicit conventional
    /// PAM response before it may reach the camera.
    #[must_use]
    pub fn requires_face_intent_confirmation(self) -> bool {
        matches!(self, Self::Elevation | Self::AppConsent)
    }

    /// Whether this service should get the SHORT grace window.
    ///
    /// Elevation and consent prompts are both "the user is already at the
    /// machine": a long window holds the camera and, for the KDE polkit agent
    /// which re-runs the stack up to three times, holds its dialog busy. An
    /// unrecognised name gets the long login window, which is what the caller's
    /// `None` branch does.
    #[must_use]
    pub fn wants_short_grace(self) -> bool {
        matches!(self, ServiceKind::Elevation | ServiceKind::AppConsent)
    }

    /// Whether this service uses app-consent decline semantics in PAM.
    /// A deliberate shake aborts polkit's attempt when its optional gesture is
    /// enabled; other services retain ordinary password fallback.
    #[must_use]
    pub fn wants_consent_instruction(self) -> bool {
        matches!(self, ServiceKind::AppConsent)
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, ServiceKind, SERVICES};

    /// A duplicate row would make the table's answer depend on its order, which
    /// is the ambiguity a single source of truth exists to remove.
    #[test]
    fn no_service_is_listed_twice() {
        let mut seen = std::collections::HashSet::new();
        for (name, _) in SERVICES {
            assert!(seen.insert(*name), "{name} appears more than once");
        }
    }

    /// Every row must already be normalised, or `classify` could never match it.
    #[test]
    fn every_row_is_stored_normalised() {
        for (name, _) in SERVICES {
            assert_eq!(*name, name.trim().to_ascii_lowercase(), "{name}");
            assert!(!name.is_empty());
        }
    }

    /// The lookup normalises what it is given, because PAM service strings have
    /// arrived with case and whitespace differences.
    #[test]
    fn lookup_is_case_and_whitespace_insensitive() {
        for probe in ["SUDO", " sudo ", "Sudo"] {
            assert_eq!(classify(probe), Some(ServiceKind::Elevation), "{probe}");
        }
    }

    /// Omarchy's lock shell drives face auth through a dedicated PAM service.
    /// It is a live-session screen unlock, not a cold-login greeter.
    #[test]
    fn omarchy_face_lock_is_screen_unlock() {
        assert_eq!(
            classify("omarchy-lock-face"),
            Some(ServiceKind::ScreenUnlock)
        );
    }

    /// The stock Omarchy lock's PASSWORD lane: with autologin as the distro
    /// default, this lane (not the greeter) is where a cold boot actually
    /// asks for credentials, so it classifies as ScreenUnlock exactly like
    /// the dedicated face service.
    #[test]
    fn omarchy_stock_lock_password_lane_is_screen_unlock() {
        assert_eq!(
            classify("omarchy-lock-password"),
            Some(ServiceKind::ScreenUnlock)
        );
    }

    /// Cinnamon's screensaver service (Mint): a live-session unlock, wired
    /// with the on-demand empty-Enter face arm.
    #[test]
    fn cinnamon_screensaver_is_screen_unlock() {
        assert_eq!(
            classify("cinnamon-screensaver"),
            Some(ServiceKind::ScreenUnlock)
        );
    }

    /// The divergence that prompted this: doas was Elevation for the policy and
    /// missing from the grace-window list, so it got the long window.
    #[test]
    fn doas_is_elevation_and_takes_the_short_window() {
        let kind = classify("doas").expect("doas is a recognised elevation service");
        assert_eq!(kind, ServiceKind::Elevation);
        assert!(kind.wants_short_grace());
    }

    /// App-consent decline semantics and short grace must agree for polkit,
    /// because the two used to be decided by separate hard-coded lists.
    #[test]
    fn app_consent_implies_both_the_short_window_and_the_instruction() {
        for (name, kind) in SERVICES {
            if *kind == ServiceKind::AppConsent {
                assert!(kind.wants_short_grace(), "{name}");
                assert!(kind.wants_consent_instruction(), "{name}");
            } else {
                assert!(
                    !kind.wants_consent_instruction(),
                    "{name}: only the consent path prompts for a gesture"
                );
            }
        }
    }

    /// Removing the optional gesture default must not remove the mandatory
    /// conventional-confirmation classification. Every privileged spelling in
    /// the shared table gets the same answer, while login, lock, and remote
    /// services never inherit the privileged prompt.
    #[test]
    fn only_privileged_services_require_face_intent_confirmation() {
        for (name, kind) in SERVICES {
            assert_eq!(
                kind.requires_face_intent_confirmation(),
                matches!(kind, ServiceKind::Elevation | ServiceKind::AppConsent),
                "{name}"
            );
        }
    }

    /// An unknown name must fail closed on every question the table answers.
    #[test]
    fn an_unknown_service_is_none_and_takes_no_shortcut() {
        assert_eq!(classify("some-service-invented-tomorrow"), None);
        assert_eq!(classify(""), None);
    }
}
