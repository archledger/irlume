// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Deadline-bounded passwd lookups, isolated from the authentication worker.
//!
//! One use: map a connecting peer's uid to the username it may act on, via NSS,
//! so LDAP/SSSD/systemd-homed users resolve too (the old hand-rolled
//! `/etc/passwd` parse missed them). Plain `getpwnam` shares a static buffer
//! and isn't safe under concurrent request handling, so we use the `_r`
//! variants with our own buffer.

use std::ffi::CString;
use std::process::Command;
use std::time::{Duration, Instant};

const HELPER_ARG: &str = "--internal-nss-lookup";
const REPLY_PREFIX: &str = "IRLUME_NSS_REPLY:";
// Each fresh check gets at most one second, including spawn and pipe reads.
// The helper collector also limits output and outstanding children/reaps.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
enum Query {
    Name(String),
    Uid(u32),
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Lookup {
    Found {
        uid: u32,
        name: Option<String>,
        home: Option<String>,
    },
    Absent,
    Unknown,
}

pub(crate) fn initialize() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        assert!(irlume_core::account::install_resolver(resolve_account));
    });
}

fn resolve_account(name: &str) -> irlume_core::account::Resolution {
    use irlume_core::account::Resolution;
    match lookup(Query::Name(name.into())) {
        Lookup::Found { uid, .. } => Resolution::Uid(uid),
        Lookup::Absent => Resolution::NoAccount,
        Lookup::Unknown => Resolution::Unknown,
    }
}

/// Private subprocess mode. Never starts a daemon, touches a stored secret,
/// or receives a socket request. The query selects native NSS by name or UID,
/// so a numeric account name cannot accidentally become a UID lookup.
pub(crate) fn run_helper() -> bool {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some(HELPER_ARG) {
        return false;
    }
    let query = args.next().filter(|s| s.len() <= 4096);
    let result = if args.next().is_none() {
        query
            .and_then(|s| serde_json::from_str::<Query>(&s).ok())
            .map(native_lookup)
            .unwrap_or(Lookup::Unknown)
    } else {
        Lookup::Unknown
    };
    write_reply(result);
    true
}

fn write_reply(result: Lookup) {
    if let Ok(json) = serde_json::to_string(&result) {
        println!("\n{REPLY_PREFIX}{json}");
    }
}

fn lookup(query: Query) -> Lookup {
    let deadline = Instant::now() + LOOKUP_TIMEOUT;
    let Ok(encoded) = serde_json::to_string(&query) else {
        return Lookup::Unknown;
    };
    if encoded.len() > 4096 {
        return Lookup::Unknown;
    }
    // /proc/self/exe retains this running image across a package replacement;
    // neither PATH nor the request chooses an executable.
    let mut command = Command::new("/proc/self/exe");
    #[cfg(not(test))]
    command.args([HELPER_ARG, &encoded]);
    #[cfg(test)]
    {
        command
            .args([
                "--ignored",
                "--exact",
                "users::tests::nss_lookup_child",
                "--nocapture",
            ])
            .env("IRLUME_TEST_NSS_QUERY", &encoded)
            .env_remove("IRLUME_TEST_NSS_STALL");
        LOOKUP_PROBE.with(|probe| {
            let (block, calls) = probe.get();
            probe.set((block, calls + 1));
            if block {
                command.env("IRLUME_TEST_NSS_STALL", "1");
            }
        });
    }
    observe(&query, &mut command, deadline)
}

fn observe(query: &Query, command: &mut Command, deadline: Instant) -> Lookup {
    let Ok(output) = irlume_common::process::output_until(command, deadline) else {
        return Lookup::Unknown;
    };
    if !output.status.success() {
        return Lookup::Unknown;
    }
    let Ok(text) = std::str::from_utf8(&output.stdout) else {
        return Lookup::Unknown;
    };
    let mut replies = text
        .lines()
        .filter_map(|line| line.strip_prefix(REPLY_PREFIX));
    let result = replies
        .next()
        .and_then(|s| serde_json::from_str::<Lookup>(s).ok());
    if replies.next().is_some() {
        return Lookup::Unknown;
    }
    match result {
        Some(Lookup::Found { uid, .. }) if matches!(query, Query::Uid(want) if *want != uid) => {
            Lookup::Unknown
        }
        Some(result) => result,
        None => Lookup::Unknown,
    }
}

/// Resolve a username to its uid via NSS. `None` if absent / un-encodable.
pub fn uid_for_name(name: &str) -> Option<u32> {
    match lookup(Query::Name(name.into())) {
        Lookup::Found { uid, .. } => Some(uid),
        Lookup::Absent | Lookup::Unknown => None,
    }
}

/// Resolve a uid to its username via NSS (reverse of [`uid_for_name`]). Used to
/// scope a non-root peer's 1:N identify to its own account. `None` if the uid
/// has no local/NSS account.
pub fn name_for_uid(uid: u32) -> Option<String> {
    match lookup(Query::Uid(uid)) {
        Lookup::Found { name, .. } => name,
        Lookup::Absent | Lookup::Unknown => None,
    }
}

/// Only for the existing bounded-queue history writer, never an authority or
/// worker check. Preserve its native lookup: a worker's short helper deadline
/// must not discard a queued attempt that can be filed after NSS recovers.
/// The writer is one fixed thread, so a stalled provider cannot grow threads.
pub(crate) fn name_for_record_writer(uid: u32) -> Option<String> {
    match native_lookup(Query::Uid(uid)) {
        Lookup::Found { name, .. } => name,
        Lookup::Absent | Lookup::Unknown => None,
    }
}

/// Resolve a username to its home directory via NSS.
///
/// Needed for the KDE wallet path: the wallet salt lives under the user's home,
/// and the derivation has to read the SAME file `pam_kwallet5` derives against.
/// Guessing `/home/<name>` would silently derive the wrong key for anyone whose
/// home is elsewhere, which is exactly the population (LDAP, systemd-homed) the
/// reentrant NSS lookups here exist to serve.
pub fn home_for_name(name: &str) -> Option<std::path::PathBuf> {
    #[cfg(test)]
    if let Some(home) = HOME_STAND_IN.with(|stand_in| {
        stand_in
            .borrow()
            .as_ref()
            .filter(|(account, _)| account == name)
            .map(|(_, home)| home.clone())
    }) {
        return Some(home);
    }
    match lookup(Query::Name(name.into())) {
        Lookup::Found {
            home: Some(home), ..
        } if !home.is_empty() => Some(home.into()),
        _ => None,
    }
}

// Called in the fresh helper process, or by the one existing history writer.
// No NSS call runs in a forked copy of the daemon without exec first.
fn native_lookup(query: Query) -> Lookup {
    let name = match &query {
        Query::Name(name) => match CString::new(name.as_str()) {
            Ok(name) => Some(name),
            Err(_) => return Lookup::Absent,
        },
        Query::Uid(_) => None,
    };
    let mut size = 4096;
    loop {
        let mut buf = vec![0 as libc::c_char; size];
        // SAFETY: passwd is a plain C struct; zero is valid before libc fills it.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        // SAFETY: pwd, result and the owned buffer are valid for the call;
        // the name, when used, is an owned NUL-terminated CString.
        let rc = unsafe {
            match (&query, &name) {
                (Query::Name(_), Some(name)) => libc::getpwnam_r(
                    name.as_ptr(),
                    &mut pwd,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                ),
                (Query::Uid(uid), _) => {
                    libc::getpwuid_r(*uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
                }
                _ => return Lookup::Unknown,
            }
        };
        if rc == libc::ERANGE && size < 1 << 20 {
            size *= 4;
            continue;
        }
        if rc != 0 {
            return Lookup::Unknown;
        }
        if result.is_null() {
            return Lookup::Absent;
        }
        // A UID lookup must not require a UTF-8 home or canonical name. The
        // corresponding string reader still refuses an unavailable field.
        let name = if pwd.pw_name.is_null() {
            None
        } else {
            // SAFETY: successful NSS supplies a NUL-terminated field in buf,
            // which remains alive through the copy.
            unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
                .to_str()
                .ok()
                .map(str::to_owned)
        };
        let home = if pwd.pw_dir.is_null() {
            None
        } else {
            // SAFETY: same successful lookup and live buffer as pw_name.
            unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
                .to_str()
                .ok()
                .map(str::to_owned)
        };
        return Lookup::Found {
            uid: pwd.pw_uid,
            name,
            home,
        };
    }
}

#[cfg(test)]
thread_local! {
    static LOOKUP_PROBE: std::cell::Cell<(bool, usize)> = const { std::cell::Cell::new((false, 0)) };
    /// An account and the home [`home_for_name`] reports for it on this
    /// thread while a test has set one, so a dispatch test can give the
    /// account a GNOME login keyring without reading or writing a real home.
    pub(crate) static HOME_STAND_IN: std::cell::RefCell<Option<(String, std::path::PathBuf)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn probe_provider<R>(blocked: bool, run: impl FnOnce() -> R) -> (R, usize) {
    struct Restore((bool, usize));
    impl Drop for Restore {
        fn drop(&mut self) {
            LOOKUP_PROBE.with(|probe| probe.set(self.0));
        }
    }
    let _restore = Restore(LOOKUP_PROBE.with(|probe| probe.replace((blocked, 0))));
    let result = run();
    (result, LOOKUP_PROBE.with(|probe| probe.get().1))
}

/// Translate the wire secret kind to the core one.
///
/// The two enums are deliberately separate: `irlume-common` carries the wire
/// form and cannot depend on `irlume-core`, which owns the on-disk form. This is
/// the single place they meet.
pub fn wire_to_core_kind(k: irlume_common::KeyringSecretKind) -> irlume_core::envelope::SecretKind {
    match k {
        irlume_common::KeyringSecretKind::LoginPassword => {
            irlume_core::envelope::SecretKind::LoginPassword
        }
        irlume_common::KeyringSecretKind::KdeWalletKey => {
            irlume_core::envelope::SecretKind::KdeWalletKey
        }
        irlume_common::KeyringSecretKind::GnomeKeyringToken => {
            irlume_core::envelope::SecretKind::GnomeKeyringToken
        }
    }
}

/// Translate the core secret kind to the wire one.
pub fn core_to_wire_kind(k: irlume_core::envelope::SecretKind) -> irlume_common::KeyringSecretKind {
    match k {
        irlume_core::envelope::SecretKind::LoginPassword => {
            irlume_common::KeyringSecretKind::LoginPassword
        }
        irlume_core::envelope::SecretKind::KdeWalletKey => {
            irlume_common::KeyringSecretKind::KdeWalletKey
        }
        irlume_core::envelope::SecretKind::GnomeKeyringToken => {
            irlume_common::KeyringSecretKind::GnomeKeyringToken
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "fresh NSS subprocess, invoked by the bounded lookup tests"]
    fn nss_lookup_child() {
        let _passwd = crate::test_support::env_read();
        if std::env::var("IRLUME_TEST_NSS_STALL").as_deref() == Ok("1") {
            loop {
                std::thread::park();
            }
        }
        let encoded = std::env::var("IRLUME_TEST_NSS_QUERY").expect("parent supplied query");
        write_reply(native_lookup(serde_json::from_str(&encoded).unwrap()));
    }

    #[test]
    fn blocked_provider_is_unknown_not_absent_and_later_lookups_recover() {
        let _passwd = crate::test_support::env_read();
        let started = Instant::now();
        let (result, calls) = probe_provider(true, || irlume_core::account::resolve_fresh("root"));
        assert_eq!(result, irlume_core::account::Resolution::Unknown);
        assert_eq!(calls, 1);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(
            resolve_account("root"),
            irlume_core::account::Resolution::Uid(0)
        );
        assert_eq!(
            resolve_account("irlume-no-such-nss-account"),
            irlume_core::account::Resolution::NoAccount
        );
    }

    #[test]
    fn helper_protocol_refuses_failure_corruption_duplicates_and_wrong_uid() {
        let _passwd = crate::test_support::env_read();
        for (body, status, expected) in [
            ("IRLUME_NSS_REPLY:\"Absent\"\n", "0", Lookup::Absent),
            ("IRLUME_NSS_REPLY:\"Unknown\"\n", "0", Lookup::Unknown),
            ("IRLUME_NSS_REPLY:\"Absent\"\n", "2", Lookup::Unknown),
            ("garbage", "0", Lookup::Unknown),
            (
                "IRLUME_NSS_REPLY:{\"Found\":{\"uid\":0,\"name\":null,\"home\":null}}\n",
                "0",
                Lookup::Found {
                    uid: 0,
                    name: None,
                    home: None,
                },
            ),
            (
                "IRLUME_NSS_REPLY:\"Absent\"\nIRLUME_NSS_REPLY:\"Absent\"\n",
                "0",
                Lookup::Unknown,
            ),
            (
                "IRLUME_NSS_REPLY:{\"Found\":{\"uid\":42,\"name\":\"root\",\"home\":\"/root\"}}\n",
                "0",
                Lookup::Unknown,
            ),
        ] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf '%s' \"$1\"; exit \"$2\"", "sh", body, status]);
            assert_eq!(
                observe(
                    &Query::Uid(0),
                    &mut command,
                    Instant::now() + LOOKUP_TIMEOUT
                ),
                expected
            );
        }
    }

    #[test]
    fn uid_and_name_round_trip_for_root_and_the_current_user() {
        // Shared guard: these resolve usernames, so they read `environ` inside
        // glibc and must exclude the environment writers in main.rs's tests,
        // which share this test binary (#380 review).
        let _passwd = crate::test_support::env_read();
        // root is uid 0 on every Linux, in both directions.
        assert_eq!(uid_for_name("root"), Some(0));
        assert_eq!(name_for_uid(0).as_deref(), Some("root"));
        // The uid running this test resolves to a name that resolves back.
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let me = unsafe { libc::geteuid() };
        let name = name_for_uid(me).expect("test uid must have an account");
        assert!(!name.is_empty());
        assert_eq!(uid_for_name(&name), Some(me));
    }

    #[test]
    fn absent_and_unencodable_users_resolve_to_none() {
        // Shared guard: these resolve usernames, so they read `environ` inside
        // glibc and must exclude the environment writers in main.rs's tests,
        // which share this test binary (#380 review).
        let _passwd = crate::test_support::env_read();
        assert_eq!(uid_for_name("no-such-user-irlume-test"), None);
        // Interior NUL cannot become a C string: None, not a panic.
        assert_eq!(uid_for_name("a\0b"), None);
        // 4294967294 = (uid_t)-2, the "nobody owns this" sentinel (used by
        // idmapped mounts); it must never resolve to an account name.
        assert_eq!(name_for_uid(4294967294), None);
    }
}
