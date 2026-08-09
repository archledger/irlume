// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Thread-safe passwd lookups via libc reentrant calls.
//!
//! One use: map a connecting peer's uid to the username it may act on, via NSS,
//! so LDAP/SSSD/systemd-homed users resolve too (the old hand-rolled
//! `/etc/passwd` parse missed them). Plain `getpwnam` shares a static buffer
//! and isn't safe under concurrent request handling, so we use the `_r`
//! variants with our own buffer.

use std::ffi::CString;

/// Resolve a username to its uid via NSS. `None` if absent / un-encodable.
pub fn uid_for_name(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers valid for the call; `buf` is sized and owned here;
    // `result` points into `pwd` on success.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(pwd.pw_uid)
}

/// Resolve a uid to its username via NSS (reverse of [`uid_for_name`]). Used to
/// scope a non-root peer's 1:N identify to its own account. `None` if the uid
/// has no local/NSS account.
pub fn name_for_uid(uid: u32) -> Option<String> {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: see `uid_for_name`.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success pw_name points into `buf`, a valid NUL-terminated C string.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    name.to_str().ok().map(|s| s.to_owned())
}

/// Resolve a username to its home directory via NSS.
///
/// Needed for the KDE wallet path: the wallet salt lives under the user's home,
/// and the derivation has to read the SAME file `pam_kwallet5` derives against.
/// Guessing `/home/<name>` would silently derive the wrong key for anyone whose
/// home is elsewhere, which is exactly the population (LDAP, systemd-homed) the
/// reentrant NSS lookups here exist to serve.
pub fn home_for_name(name: &str) -> Option<std::path::PathBuf> {
    let cname = CString::new(name).ok()?;
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: see `uid_for_name`.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success pw_dir points into `buf`, a valid NUL-terminated string.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    let s = dir.to_str().ok()?;
    if s.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(s))
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
