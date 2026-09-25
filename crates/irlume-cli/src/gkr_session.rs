// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The invoking session's gnome-keyring, as a GNOME keyring token needs it.
//!
//! Where no socket unit starts gnome-keyring (Fedora 43 and 44, for example),
//! `pam_gnome_keyring.so auto_start` starts `gnome-keyring-daemon --login` at
//! login. That daemon listens on its control socket at once but answers every
//! request DENIED until something sends it INITIALIZE. A GNOME session does
//! within seconds of login: its first Secret Service client activates
//! gnome-keyring over D-Bus, and the daemon then claims `org.gnome.keyring`.
//! A Plasma session does not, and the daemon exits after 120 s. So a
//! `--login` daemon of this uid while `org.gnome.keyring` has no owner is one
//! that nothing has initialized.
//!
//! `irlume keyring forget` initializes such a daemon the way a GNOME session
//! does when it refuses the change back ([`initialize_for_forget`]). A token
//! arm refuses there instead ([`token_arm_refusal`]): a token is only
//! delivered once a GNOME session initializes gnome-keyring, so a token armed
//! from this session would never unlock the keyring.
//!
//! D-Bus goes through `busctl --user --auto-start=no`, as in
//! [`crate::secrets`], and no secret goes near it. Only
//! [`initialize_for_forget`] starts a service.

use std::path::{Path, PathBuf};

/// The name gnome-keyring claims once it is initialized.
const KEYRING_BUS: &str = "org.gnome.keyring";
/// The Secret Service name, which gnome-keyring claims next.
const SECRETS_BUS: &str = "org.freedesktop.secrets";
/// How long `busctl` waits for the reply to `StartServiceByName`. The bus
/// itself may wait longer (dbus-daemon's session.conf allows 120 s, and
/// dbus-broker leaves it to the systemd job), so this is the bound `forget`
/// relies on. Activation normally answers within a second.
const START_TIMEOUT_SECS: u32 = 30;

/// Why a token arm stops in a session whose gnome-keyring the login screen
/// started and nothing initialized. Callers add what happened to the arm.
pub(crate) const NOT_A_GNOME_SESSION: &str =
    "gnome-keyring in this session was started by the login screen and nothing here has \
     initialized it, which a GNOME session does within seconds of login. So this is not a \
     GNOME session, and a GNOME keyring token cannot be delivered here: the login keyring \
     would stay locked at every login";

/// The credentials of the process listening on a Unix socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub(crate) pid: libc::pid_t,
    pub(crate) uid: libc::uid_t,
}

/// `SO_PEERCRED` of `stream`: for a connected client, the listener's
/// credentials when it called `listen`.
pub(crate) fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> std::io::Result<Peer> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream` keeps the fd open for the call, and `ucred` and `len`
    // are live out-parameters sized for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Peer {
        pid: ucred.pid,
        uid: ucred.uid,
    })
}

/// What these checks read from the session. [`Live`] reads the real one;
/// tests substitute a fake bus and control socket.
pub(crate) trait Session {
    /// The process listening on the gnome-keyring control socket, or `None`
    /// when nothing listens there.
    fn control_peer(&self) -> Option<Peer>;
    /// `/proc/<pid>/cmdline`: NUL-separated argv, which carries no secret
    /// (`--login` reads the password from stdin).
    fn cmdline(&self, pid: libc::pid_t) -> Option<Vec<u8>>;
    /// Whether `name` has an owner on the user bus; `None` when the bus
    /// could not be asked.
    fn has_owner(&self, name: &str) -> Option<bool>;
    /// The pid of `name`'s owner, or `None`.
    fn owner_pid(&self, name: &str) -> Option<u32>;
    /// `StartServiceByName(name)`, the one call here that starts anything.
    fn start_service(&self, name: &str) -> Result<(), String>;
}

/// The real session: the control socket under `runtime_dir`, `/proc` and
/// `busctl --user`.
pub(crate) struct Live {
    runtime_dir: PathBuf,
}

impl Live {
    /// The session of this process, or `None` without `XDG_RUNTIME_DIR`.
    pub(crate) fn from_env() -> Option<Self> {
        std::env::var_os("XDG_RUNTIME_DIR").map(|dir| Live {
            runtime_dir: PathBuf::from(dir),
        })
    }
}

impl Session for Live {
    fn control_peer(&self) -> Option<Peer> {
        // Connect and close without sending anything: gnome-keyring reads
        // nothing from a connection until its credentials byte arrives, and
        // logs nothing when it closes first.
        let path = irlume_common::gkr_wire::control_socket_path(&self.runtime_dir);
        let stream = std::os::unix::net::UnixStream::connect(path).ok()?;
        peer_credentials(&stream).ok()
    }

    fn cmdline(&self, pid: libc::pid_t) -> Option<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/cmdline")).ok()
    }

    fn has_owner(&self, name: &str) -> Option<bool> {
        let reply =
            crate::secrets::busctl_output_within(3, &bus_driver_call("NameHasOwner", name))?;
        parse_bool_reply(&reply)
    }

    fn owner_pid(&self, name: &str) -> Option<u32> {
        let reply = crate::secrets::busctl_output_within(
            3,
            &bus_driver_call("GetConnectionUnixProcessID", name),
        )?;
        parse_u32_reply(&reply)
    }

    fn start_service(&self, name: &str) -> Result<(), String> {
        let reply = crate::secrets::busctl_output_within(
            START_TIMEOUT_SECS,
            &[
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "StartServiceByName",
                "su",
                name,
                "0",
            ],
        )
        .ok_or_else(|| format!("the user bus did not start {name}"))?;
        // 1: started; 2: it already had an owner.
        match parse_u32_reply(&reply) {
            Some(1 | 2) => Ok(()),
            _ => Err(format!("unexpected reply to starting {name}")),
        }
    }
}

/// `busctl` arguments for a one-string-argument call to the bus driver.
fn bus_driver_call<'a>(method: &'a str, name: &'a str) -> [&'a str; 7] {
    [
        "call",
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        method,
        "s",
        name,
    ]
}

/// A `busctl call` reply of one boolean: `b true` or `b false`.
fn parse_bool_reply(reply: &str) -> Option<bool> {
    match reply.split_whitespace().collect::<Vec<_>>()[..] {
        ["b", "true"] => Some(true),
        ["b", "false"] => Some(false),
        _ => None,
    }
}

/// A `busctl call` reply of one `u32`, such as `u 1234`.
fn parse_u32_reply(reply: &str) -> Option<u32> {
    match reply.split_whitespace().collect::<Vec<_>>()[..] {
        ["u", n] => n.parse().ok(),
        _ => None,
    }
}

/// Whether `cmdline` is `gnome-keyring-daemon` started with `--login`, the
/// way `pam_gnome_keyring` starts it. A daemon from the socket unit or from
/// D-Bus activation has no `--login`. The flag stays in argv after
/// initialization, which is why initialization is read from the bus.
fn is_login_daemon(cmdline: &[u8]) -> bool {
    let mut argv = cmdline.split(|&b| b == 0).filter(|a| !a.is_empty());
    let Some(exe) = argv.next() else {
        return false;
    };
    let name = exe.rsplit(|&b| b == b'/').next().unwrap_or(exe);
    name == b"gnome-keyring-daemon" && argv.any(|a| a == b"--login")
}

/// The state of this session's gnome-keyring that decides both checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginDaemon {
    /// A `--login` daemon running as `me` while `org.gnome.keyring` has no
    /// owner: the login screen started it and nothing initialized it.
    Uninitialized { pid: libc::pid_t },
    /// Anything else: no daemon, another uid's, a socket-unit or initialized
    /// one, or a state that could not be read. Neither check acts on it.
    Other,
}

fn login_daemon(session: &impl Session, me: libc::uid_t) -> LoginDaemon {
    let Some(peer) = session.control_peer() else {
        return LoginDaemon::Other;
    };
    // gnome-keyring serves only its own uid, and an argv or bus reading about
    // another user's daemon says nothing about this user's keyring.
    if peer.uid != me {
        return LoginDaemon::Other;
    }
    if !session
        .cmdline(peer.pid)
        .is_some_and(|c| is_login_daemon(&c))
    {
        return LoginDaemon::Other;
    }
    match session.has_owner(KEYRING_BUS) {
        Some(false) => LoginDaemon::Uninitialized { pid: peer.pid },
        _ => LoginDaemon::Other,
    }
}

/// What [`initialize_for_forget`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Initialized {
    /// The daemon behind the control socket is initialized now; retry.
    Now,
    /// Not a login-started gnome-keyring waiting for initialization, so the
    /// refusal has another cause. Nothing was started.
    NotNeeded,
    /// gnome-keyring waits for initialization, but another process owns the
    /// Secret Service name, such as KDE's in a Plasma session. Initializing
    /// gnome-keyring there would put it in line for that name, so nothing
    /// was started.
    OtherProvider,
    /// gnome-keyring waits for initialization and it did not happen: the bus
    /// could not be read, the start failed, or the daemon behind the control
    /// socket did not claim `org.gnome.keyring`.
    Failed(String),
}

/// For `keyring forget` after gnome-keyring refused the change back: when
/// the refusal comes from a `--login` daemon that nothing initialized, and no
/// other Secret Service provider runs, ask the bus to start
/// `org.gnome.keyring` once, as a GNOME session's first keyring client does.
/// The activated `gnome-keyring-daemon --start` finds the running daemon and
/// initializes it, and the daemon then claims `org.gnome.keyring`, which is
/// checked before a retry.
pub(crate) fn initialize_for_forget(session: &impl Session, me: libc::uid_t) -> Initialized {
    let LoginDaemon::Uninitialized { pid } = login_daemon(session, me) else {
        return Initialized::NotNeeded;
    };
    let pid = u32::try_from(pid).ok();
    match session.has_owner(SECRETS_BUS) {
        Some(false) => {}
        Some(true) if pid.is_some() && session.owner_pid(SECRETS_BUS) == pid => {}
        Some(true) => return Initialized::OtherProvider,
        None => {
            return Initialized::Failed(format!(
                "could not read who owns {SECRETS_BUS} on the user bus"
            ))
        }
    }
    if let Err(e) = session.start_service(KEYRING_BUS) {
        return Initialized::Failed(e);
    }
    match session.owner_pid(KEYRING_BUS) {
        owner if owner.is_some() && owner == pid => Initialized::Now,
        Some(owner) => Initialized::Failed(format!(
            "{KEYRING_BUS} is owned by pid {owner}, not by the gnome-keyring behind the \
             control socket"
        )),
        None => Initialized::Failed(format!("{KEYRING_BUS} still has no owner")),
    }
}

/// Whether irlumed, asked for an arm without a forced kind, seals a GNOME
/// keyring token: the decision it makes from the account's passwd home and
/// whether the CLI sent a KDE wallet salt (`detect_kind`).
fn arms_a_token(home: Option<&Path>, has_wallet_salt: bool) -> bool {
    home.is_some_and(|home| {
        irlume_core::kwallet::detect_kind(home, has_wallet_salt)
            == irlume_core::envelope::SecretKind::GnomeKeyringToken
    })
}

/// The refusal for a token arm from this session, or `None`. Asked before
/// `SealPassword`, so a refused arm mints and seals nothing: the answer is
/// `None` unless irlumed would seal a token for `user` (the account's home
/// holds a GNOME login keyring and no KDE wallet salt was found), and the
/// session's gnome-keyring is a `--login` daemon that nothing initialized.
pub(crate) fn token_arm_refusal(
    user: &str,
    wallet_salt: Option<&irlume_common::WalletSalt>,
) -> Option<String> {
    let session = Live::from_env()?;
    // A KDE wallet salt never arms a token, so skip the passwd lookup.
    let token = wallet_salt.is_none()
        && arms_a_token(crate::bitwarden::passwd_home(user).as_deref(), false);
    token_arm_refusal_in(token, &session, crate::control_client_uid())
}

fn token_arm_refusal_in(token: bool, session: &impl Session, me: libc::uid_t) -> Option<String> {
    if !token {
        return None;
    }
    uninitialized_refusal(session, me)
}

/// [`NOT_A_GNOME_SESSION`] when this session's gnome-keyring is a `--login`
/// daemon that nothing initialized, else `None`. The check a token arm makes
/// once irlumed has sealed the token, before any re-key is sent.
pub(crate) fn session_refusal() -> Option<String> {
    uninitialized_refusal(&Live::from_env()?, crate::control_client_uid())
}

fn uninitialized_refusal(session: &impl Session, me: libc::uid_t) -> Option<String> {
    match login_daemon(session, me) {
        LoginDaemon::Uninitialized { .. } => Some(NOT_A_GNOME_SESSION.to_string()),
        LoginDaemon::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const ME: libc::uid_t = 4242;
    const DAEMON: libc::pid_t = 3100;
    const KSECRETD: u32 = 3300;
    /// argv of the daemon `pam_gnome_keyring auto_start` starts.
    const PAM_STARTED: &[u8] = b"/usr/bin/gnome-keyring-daemon\0--daemonize\0--login\0";
    /// argv of the daemon the socket unit starts, as on Debian or Arch.
    const SOCKET_UNIT: &[u8] = b"/usr/bin/gnome-keyring-daemon\0--foreground\0\
        --components=pkcs11,secrets\0--control-directory=/run/user/4242/keyring\0";

    /// A session with a fake control socket, `/proc` and user bus. Every bus
    /// call is recorded.
    struct Fake {
        peer: Option<Peer>,
        cmdline: Option<&'static [u8]>,
        /// Owner pid per name; a name that is absent has no owner. `None`:
        /// the bus cannot be asked.
        owners: RefCell<Option<Vec<(&'static str, u32)>>>,
        /// What a start of `org.gnome.keyring` does: `Some(pid)` makes that
        /// pid its owner, `None` fails.
        start_owner: Option<u32>,
        calls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn login_daemon() -> Self {
            Fake {
                peer: Some(Peer {
                    pid: DAEMON,
                    uid: ME,
                }),
                cmdline: Some(PAM_STARTED),
                owners: RefCell::new(Some(Vec::new())),
                start_owner: Some(DAEMON as u32),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn owned(self, name: &'static str, pid: u32) -> Self {
            self.owners.borrow_mut().as_mut().unwrap().push((name, pid));
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn started(&self) -> usize {
            self.calls()
                .iter()
                .filter(|c| c.starts_with("start"))
                .count()
        }
    }

    impl Session for Fake {
        fn control_peer(&self) -> Option<Peer> {
            self.peer
        }
        fn cmdline(&self, pid: libc::pid_t) -> Option<Vec<u8>> {
            assert_eq!(Some(pid), self.peer.map(|p| p.pid));
            self.cmdline.map(<[u8]>::to_vec)
        }
        fn has_owner(&self, name: &str) -> Option<bool> {
            self.calls.borrow_mut().push(format!("has_owner {name}"));
            let owners = self.owners.borrow();
            Some(owners.as_ref()?.iter().any(|(n, _)| *n == name))
        }
        fn owner_pid(&self, name: &str) -> Option<u32> {
            self.calls.borrow_mut().push(format!("owner_pid {name}"));
            let owners = self.owners.borrow();
            owners
                .as_ref()?
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, p)| *p)
        }
        fn start_service(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("start {name}"));
            let owner = self.start_owner.ok_or("activation failed")?;
            self.owners
                .borrow_mut()
                .as_mut()
                .unwrap()
                .push((KEYRING_BUS, owner));
            Ok(())
        }
    }

    #[test]
    fn only_a_login_started_daemon_of_this_user_counts() {
        assert!(is_login_daemon(PAM_STARTED));
        assert!(is_login_daemon(
            b"gnome-keyring-daemon\0--foreground\0--login\0"
        ));
        for other in [
            SOCKET_UNIT,
            b"/usr/bin/gnome-keyring-daemon\0--start\0--foreground\0--components=secrets\0",
            b"/usr/bin/python3\0gnome-keyring-daemon\0--login\0",
            b"/opt/gnome-keyring-daemon-wrapper\0--login\0",
            b"--login\0",
            b"",
        ] {
            assert!(
                !is_login_daemon(other),
                "{:?}",
                String::from_utf8_lossy(other)
            );
        }
    }

    #[test]
    fn a_login_daemon_is_uninitialized_while_its_bus_name_has_no_owner() {
        let fake = Fake::login_daemon();
        assert_eq!(
            login_daemon(&fake, ME),
            LoginDaemon::Uninitialized { pid: DAEMON }
        );
        let fake = Fake::login_daemon().owned(KEYRING_BUS, DAEMON as u32);
        assert_eq!(login_daemon(&fake, ME), LoginDaemon::Other);
        // A bus that cannot be asked proves nothing.
        let fake = Fake::login_daemon();
        *fake.owners.borrow_mut() = None;
        assert_eq!(login_daemon(&fake, ME), LoginDaemon::Other);
    }

    #[test]
    fn no_daemon_another_uid_or_a_socket_unit_daemon_is_left_alone_without_bus_calls() {
        let none = Fake {
            peer: None,
            ..Fake::login_daemon()
        };
        let foreign = Fake {
            peer: Some(Peer {
                pid: DAEMON,
                uid: ME + 1,
            }),
            ..Fake::login_daemon()
        };
        let socket_unit = Fake {
            cmdline: Some(SOCKET_UNIT),
            ..Fake::login_daemon()
        };
        let gone = Fake {
            cmdline: None,
            ..Fake::login_daemon()
        };
        for (case, fake) in [
            ("no control socket", none),
            ("another uid", foreign),
            ("socket unit", socket_unit),
            ("argv unreadable", gone),
        ] {
            assert_eq!(login_daemon(&fake, ME), LoginDaemon::Other, "{case}");
            assert_eq!(
                initialize_for_forget(&fake, ME),
                Initialized::NotNeeded,
                "{case}"
            );
            assert_eq!(uninitialized_refusal(&fake, ME), None, "{case}");
            assert!(fake.calls().is_empty(), "{case}: {:?}", fake.calls());
        }
    }

    #[test]
    fn forget_starts_gnome_keyring_once_and_checks_who_claimed_it() {
        let fake = Fake::login_daemon();
        assert_eq!(initialize_for_forget(&fake, ME), Initialized::Now);
        assert_eq!(
            fake.calls(),
            [
                "has_owner org.gnome.keyring",
                "has_owner org.freedesktop.secrets",
                "start org.gnome.keyring",
                "owner_pid org.gnome.keyring",
            ]
        );
        // The daemon already holding the Secret Service name is no reason to
        // stop.
        let fake = Fake::login_daemon().owned(SECRETS_BUS, DAEMON as u32);
        assert_eq!(initialize_for_forget(&fake, ME), Initialized::Now);
        assert_eq!(fake.started(), 1);
    }

    #[test]
    fn forget_never_starts_gnome_keyring_beside_another_secret_service() {
        let fake = Fake::login_daemon().owned(SECRETS_BUS, KSECRETD);
        assert_eq!(initialize_for_forget(&fake, ME), Initialized::OtherProvider);
        assert_eq!(fake.started(), 0, "{:?}", fake.calls());
    }

    #[test]
    fn forget_reports_a_start_that_did_not_initialize_the_control_socket_daemon() {
        let failed = Fake {
            start_owner: None,
            ..Fake::login_daemon()
        };
        assert!(matches!(
            initialize_for_forget(&failed, ME),
            Initialized::Failed(_)
        ));
        // Another process claimed the name: the daemon behind the control
        // socket is still waiting, so a retry would be refused again.
        let elsewhere = Fake {
            start_owner: Some(DAEMON as u32 + 7),
            ..Fake::login_daemon()
        };
        let Initialized::Failed(why) = initialize_for_forget(&elsewhere, ME) else {
            panic!("a foreign owner is not an initialized daemon");
        };
        assert!(why.contains("not by the gnome-keyring behind"), "{why}");
    }

    #[test]
    fn a_token_arm_is_refused_only_where_a_token_is_armed_and_never_delivered() {
        let uninitialized = Fake::login_daemon();
        let refusal = token_arm_refusal_in(true, &uninitialized, ME).expect("refused");
        assert!(refusal.contains("not a GNOME session"), "{refusal}");
        assert!(refusal.contains("started by the login screen"), "{refusal}");
        assert_eq!(uninitialized.started(), 0, "an arm never starts anything");

        // Initialized (a GNOME session), and no token to arm (a KDE wallet or
        // no GNOME keyring): no refusal, and the second asks nothing.
        let initialized = Fake::login_daemon().owned(KEYRING_BUS, DAEMON as u32);
        assert_eq!(token_arm_refusal_in(true, &initialized, ME), None);
        let other_kind = Fake::login_daemon();
        assert_eq!(token_arm_refusal_in(false, &other_kind, ME), None);
        assert!(other_kind.calls().is_empty(), "{:?}", other_kind.calls());
    }

    #[test]
    fn a_token_is_predicted_from_the_same_home_test_irlumed_makes() {
        let home = std::env::temp_dir().join(format!(
            "irlume-gkr-session-home-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(home.join(".local/share/keyrings")).unwrap();
        assert!(!arms_a_token(Some(&home), false), "no login keyring");
        std::fs::write(home.join(".local/share/keyrings/login.keyring"), b"x").unwrap();
        assert!(arms_a_token(Some(&home), false));
        assert!(
            !arms_a_token(Some(&home), true),
            "a KDE wallet sits beside it"
        );
        assert!(!arms_a_token(None, false), "no passwd home");
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn busctl_replies_parse_strictly() {
        assert_eq!(parse_bool_reply("b true\n"), Some(true));
        assert_eq!(parse_bool_reply("b false"), Some(false));
        assert_eq!(parse_u32_reply("u 1234\n"), Some(1234));
        for bad in [
            "",
            "b",
            "s \"true\"",
            "b true extra",
            "u",
            "u -1",
            "i 3",
            "u 1 2",
        ] {
            assert_eq!(parse_bool_reply(bad), None, "{bad}");
            assert_eq!(parse_u32_reply(bad), None, "{bad}");
        }
    }

    /// The live session asks `busctl --user --auto-start=no` exactly these
    /// questions, with the start given the longer timeout. Run in a child
    /// process so the fixture PATH cannot race other tests.
    #[test]
    fn live_bus_calls_never_auto_start_and_start_only_org_gnome_keyring() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "irlume-gkr-session-bus-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let busctl = dir.join("busctl");
        std::fs::write(
            &busctl,
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$IRLUME_TEST_BUSCTL_LOG"
case "$*" in
  "--user --timeout=3 --auto-start=no call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.gnome.keyring")
    printf 'b false\n' ;;
  "--user --timeout=3 --auto-start=no call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionUnixProcessID s org.freedesktop.secrets")
    printf 'u 77\n' ;;
  "--user --timeout=30 --auto-start=no call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName su org.gnome.keyring 0")
    printf 'u 1\n' ;;
  *) exit 64 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&busctl, std::fs::Permissions::from_mode(0o700)).unwrap();
        let log = dir.join("calls");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gkr_session::tests::live_bus_calls_child",
                "--nocapture",
            ])
            .env("PATH", &dir)
            .env("IRLUME_TEST_BUSCTL_LOG", &log)
            .output()
            .unwrap();
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        std::fs::remove_dir_all(&dir).unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("IRLUME_BUS_CHILD_OK"),
            "{stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(calls.lines().count(), 4, "{calls}");
    }

    #[test]
    fn live_bus_calls_child() {
        if std::env::var_os("IRLUME_TEST_BUSCTL_LOG").is_none() {
            return;
        }
        let live = Live {
            runtime_dir: PathBuf::from("/nonexistent-irlume-test-runtime"),
        };
        assert_eq!(live.control_peer(), None);
        assert_eq!(live.has_owner(KEYRING_BUS), Some(false));
        assert_eq!(live.owner_pid(SECRETS_BUS), Some(77));
        assert_eq!(live.start_service(KEYRING_BUS), Ok(()));
        // Anything else the fixture refuses, and a refusal is no answer.
        assert_eq!(live.has_owner(SECRETS_BUS), None);
        println!("IRLUME_BUS_CHILD_OK");
    }
}
