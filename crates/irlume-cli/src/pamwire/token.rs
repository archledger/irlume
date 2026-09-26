// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! What a GNOME keyring token needs from the login stacks.
//!
//! A token arm keys the account's login keyring to a random secret only
//! irlume holds, and one line delivers it: the `reseal` session line in the
//! login screen's PAM stack, which hands the token to gnome-keyring once the
//! session is open. Without that line every login leaves the keyring locked,
//! a typed password included, under a secret the user has never seen, and
//! only `irlume keyring forget` from inside a session gets it back.
//!
//! So an arm that would mint a token refuses where no login would deliver it
//! ([`token_delivery_refusal`]), and a disable that removes the line refuses
//! while a token is armed ([`tokens_a_disable_strands`]).

use super::*;

/// Whether a PAM stack carries irlume's `reseal` session line, active.
pub(super) fn delivers_tokens(content: &str) -> bool {
    content.lines().any(|line| {
        irlume_rule(line)
            .is_some_and(|rule| rule.phase == "session" && rule.args.contains(&"reseal"))
    })
}

/// Why a GNOME keyring token armed for `user` would never reach their keyring
/// at login, followed by what to do, or `None` when the active login screen
/// delivers it. Reads only world-readable files, so the arm can ask from the
/// user's own session before anything is sealed.
pub(crate) fn token_delivery_refusal(user: &str) -> Option<String> {
    delivery_refusal_with(
        active_display_manager().as_deref(),
        user,
        read_stack,
        autologin::autologin_source,
    )
}

/// The stack PAM reads for `service`: the `/etc/pam.d` file, else the vendor
/// copy. `None` when neither exists.
fn read_stack(service: &str) -> Result<Option<String>, String> {
    for dir in ["/etc/pam.d", "/usr/lib/pam.d"] {
        let path = Path::new(dir).join(service);
        match std::fs::read_to_string(&path) {
            Ok(text) => return Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Ok(None)
}

/// [`token_delivery_refusal`] with the login manager, the stack reader and the
/// autologin reader passed in.
fn delivery_refusal_with(
    dm: Option<&str>,
    user: &str,
    stack: impl Fn(&str) -> Result<Option<String>, String>,
    autologin: impl Fn(&str, &str) -> Result<Option<PathBuf>, String>,
) -> Option<String> {
    let unreadable = |what: String| {
        Some(format!(
            "irlume could not read {what}, so it cannot tell whether a login would deliver \
             a keyring token. Fix that, then arm again"
        ))
    };
    let Some(dm) = dm else {
        return Some(
            "irlume finds no active login manager here, and a keyring token is delivered \
             only through the login screen irlume wires. Arm once one is active"
                .to_string(),
        );
    };
    let (greeter, _) = dm_pam_services(dm);
    if !dm_wirable(dm) {
        return Some(format!(
            "irlume does not wire the {dm} login screen, and a keyring token is delivered \
             only through a login screen irlume wires"
        ));
    }
    match stack(greeter) {
        Ok(Some(text)) if delivers_tokens(&text) => {}
        Ok(_) => {
            return Some(format!(
                "the {greeter} login stack has no irlume session line, the line that hands a \
                 keyring token to the keyring at login, so every login would leave the keyring \
                 locked. Run `sudo irlume login enable --apply` first, then arm again"
            ))
        }
        Err(e) => return unreadable(e),
    }
    match autologin(dm, user) {
        Ok(None) => None,
        Ok(Some(path)) => Some(format!(
            "{dm} logs '{user}' in automatically ({}). An automatic login asks for nothing, \
             so irlume releases no token there and the keyring would stay locked. Turn \
             automatic login off, then arm again",
            path.display()
        )),
        Err(e) => unreadable(e),
    }
}

/// Whether the stack at `path` carries irlume's `reseal` line. One that
/// exists and cannot be read counts: it may carry one.
fn stack_delivers(path: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(text) => delivers_tokens(&text),
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// The token holders a run strands that leaves the stacks at `dropping`
/// without irlume's lines: every holder when one of them is on the login
/// path and delivers a token now, none otherwise.
pub(super) fn tokens_stranded_by(dropping: &[&str]) -> Result<Vec<String>, String> {
    tokens_stranded_with(
        removes_delivery(dropping, login_path_stacks().as_deref(), stack_delivers),
        crate::uninstall::root_sealed_token_holders,
    )
}

/// The stacks a login goes through: the active login manager's greeter and
/// its fingerprint service. `None` when no known login manager is active, so
/// every stack counts.
fn login_path_stacks() -> Option<Vec<String>> {
    let dm = active_display_manager()?;
    let (greeter, fingerprint) = dm_pam_services(&dm);
    if greeter == "(unknown)" {
        return None;
    }
    Some(
        std::iter::once(greeter)
            .chain(fingerprint)
            .map(|service| format!("/etc/pam.d/{service}"))
            .collect(),
    )
}

/// Whether leaving the stacks at `dropping` without irlume's lines removes a
/// delivery that matters: one of them delivers a token now and is on the
/// login path (`login_path`, or any when unknown). A stack of a login manager
/// that is not running delivers nothing to anyone.
fn removes_delivery(
    dropping: &[&str],
    login_path: Option<&[String]>,
    delivers: impl Fn(&str) -> bool,
) -> bool {
    dropping.iter().any(|path| {
        login_path.is_none_or(|stacks| stacks.iter().any(|stack| stack == path)) && delivers(path)
    })
}

/// The accounts whose GNOME keyring token a disable would leave with no
/// delivery: every token holder when some login stack carries irlume's
/// `reseal` line, none when no stack does. An envelope store that cannot be
/// read is an error, never "none", as in `irlume uninstall`.
pub(crate) fn tokens_a_disable_strands() -> Result<Vec<String>, String> {
    let all: Vec<&str> = GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .map(|s| s.etc)
        .collect();
    tokens_stranded_by(&all)
}

/// [`tokens_a_disable_strands`] for a rollback: every token holder when a
/// stack it restores carries irlume's `reseal` line now and would not after
/// (its recorded before-state lacks one, or the file did not exist). A stack
/// that exists and cannot be read counts as carrying one.
pub(crate) fn tokens_a_restore_strands<'a>(
    restores: impl IntoIterator<Item = (&'a Path, Option<&'a str>)>,
) -> Result<Vec<String>, String> {
    let login_path = login_path_stacks();
    let loses_one = restores.into_iter().any(|(path, before)| {
        let on_path = login_path
            .as_ref()
            .is_none_or(|stacks| stacks.iter().any(|stack| Path::new(stack) == path));
        let now = match std::fs::read_to_string(path) {
            Ok(text) => delivers_tokens(&text),
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        };
        on_path && now && !before.is_some_and(delivers_tokens)
    });
    tokens_stranded_with(loses_one, crate::uninstall::root_sealed_token_holders)
}

fn tokens_stranded_with(
    removes_delivery: bool,
    holders: impl FnOnce() -> Result<Vec<String>, String>,
) -> Result<Vec<String>, String> {
    if !removes_delivery {
        return Ok(Vec::new());
    }
    holders()
}

/// The lines a refused run prints: whose keyring, and the two ways on.
pub(super) fn stranded_lines(users: &[String]) -> [String; 2] {
    [
        format!(
            "[login] refusing: the login keyring of {} is keyed to an irlume-held token, and \
             this run removes the session line that delivers it. After it, the keyring would \
             stay locked at every login, a typed password included.",
            users.join(", ")
        ),
        "[login] Have each of these users run `irlume keyring forget` in their own session \
         first (it re-keys the keyring back to their password), or re-run with --force to go \
         ahead anyway."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIRED: &str = "auth     substack      password-auth\n\
        session  include       password-auth\n\
        session    optional                     pam_irlume.so reseal\n";

    fn never(_: &str, _: &str) -> Result<Option<PathBuf>, String> {
        Ok(None)
    }

    #[test]
    fn only_an_active_session_reseal_line_delivers() {
        assert!(delivers_tokens(WIRED));
        assert!(delivers_tokens(&format!(
            "session optional pam_irlume.so reseal\n{RESEAL_SESSION}\n"
        )));
        assert!(!delivers_tokens(
            "auth optional pam_irlume.so reseal\nsession include password-auth\n"
        ));
        assert!(!delivers_tokens("#session optional pam_irlume.so reseal\n"));
        assert!(!delivers_tokens(
            "session [default=ignore] pam_permit.so # irlume-inert reseal\n"
        ));
        assert!(!delivers_tokens("session optional pam_irlume.so\n"));
    }

    #[test]
    fn an_arm_needs_a_delivering_greeter_and_no_autologin() {
        let wired = |_: &str| Ok(Some(WIRED.to_string()));
        assert_eq!(
            delivery_refusal_with(Some("gdm"), "alice", wired, never),
            None
        );

        let refusal = delivery_refusal_with(None, "alice", wired, never).expect("no DM");
        assert!(refusal.contains("no active login manager"), "{refusal}");

        let refusal = delivery_refusal_with(Some("xdm"), "alice", wired, never).expect("unknown");
        assert!(refusal.contains("does not wire the xdm"), "{refusal}");

        // The default guided flow on main: arm before `login enable`.
        let unwired = |_: &str| Ok(Some("session include password-auth\n".to_string()));
        let refusal = delivery_refusal_with(Some("gdm"), "alice", unwired, never).expect("unwired");
        assert!(
            refusal.contains("gdm-password login stack has no irlume session line")
                && refusal.contains("sudo irlume login enable --apply"),
            "{refusal}"
        );
        let absent = |_: &str| Ok(None);
        assert!(delivery_refusal_with(Some("sddm"), "alice", absent, never).is_some());

        let broken = |_: &str| Err("/etc/pam.d/sddm: Permission denied".to_string());
        let refusal = delivery_refusal_with(Some("sddm"), "alice", broken, never).expect("unread");
        assert!(
            refusal.contains("could not read /etc/pam.d/sddm"),
            "{refusal}"
        );

        let automatic = |dm: &str, user: &str| {
            assert_eq!((dm, user), ("gdm", "alice"));
            Ok(Some(PathBuf::from("/etc/gdm/custom.conf")))
        };
        let refusal =
            delivery_refusal_with(Some("gdm"), "alice", wired, automatic).expect("autologin");
        assert!(
            refusal.contains("gdm logs 'alice' in automatically (/etc/gdm/custom.conf)"),
            "{refusal}"
        );
        let unknown = |_: &str, _: &str| Err("/etc/sddm.conf: Permission denied".to_string());
        let refusal =
            delivery_refusal_with(Some("sddm"), "alice", wired, unknown).expect("unknown");
        assert!(
            refusal.contains("could not read /etc/sddm.conf"),
            "{refusal}"
        );
    }

    #[test]
    fn only_a_stack_on_the_login_path_counts() {
        let delivers = |path: &str| path != "/etc/pam.d/quiet";
        let path = ["/etc/pam.d/gdm-password".to_string()];
        // Dropping an inactive login manager's stack strands nothing.
        assert!(!removes_delivery(
            &["/etc/pam.d/sddm"],
            Some(&path),
            delivers
        ));
        assert!(removes_delivery(
            &["/etc/pam.d/sddm", "/etc/pam.d/gdm-password"],
            Some(&path),
            delivers
        ));
        // With no login manager known, every stack counts.
        assert!(removes_delivery(&["/etc/pam.d/sddm"], None, delivers));
        assert!(!removes_delivery(&["/etc/pam.d/quiet"], None, delivers));
    }

    #[test]
    fn a_disable_strands_holders_only_when_a_stack_delivers() {
        let holders = || Ok(vec!["alice".to_string()]);
        assert_eq!(
            tokens_stranded_with(true, holders),
            Ok(vec!["alice".to_string()])
        );
        // Nothing to remove, so the store is not even read.
        let unread = || -> Result<Vec<String>, String> { panic!("store read") };
        assert_eq!(tokens_stranded_with(false, unread), Ok(Vec::new()));
        let broken = || Err("keyring: Permission denied".to_string());
        assert_eq!(
            tokens_stranded_with(true, broken),
            Err("keyring: Permission denied".to_string())
        );
        let [what, how] = stranded_lines(&["alice".to_string(), "bob".to_string()]);
        assert!(what.contains("keyring of alice, bob"), "{what}");
        assert!(
            how.contains("irlume keyring forget") && how.contains("--force"),
            "{how}"
        );
    }
}
