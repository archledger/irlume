//! Thread-safe passwd/group lookups via libc reentrant calls.
//!
//! Two uses: (a) resolve the `irlume` group so the socket can be `0660
//! root:irlume` instead of world-writable, and (b) map a connecting peer's uid
//! to the username it may act on, via NSS, so LDAP/SSSD/systemd-homed users
//! resolve too (the old hand-rolled `/etc/passwd` parse missed them). The
//! plain `getpwnam`/`getgrnam` share a static buffer and aren't safe under
//! concurrent request handling, so we use the `_r` variants with our own buffer.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

/// Resolve a username to its uid via NSS. `None` if absent / un-encodable.
pub fn uid_for_name(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
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

/// Resolve a group name to its gid via NSS. `None` if absent.
pub fn gid_for_group(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: see `uid_for_name`.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(grp.gr_gid)
}

/// `chown` a path, leaving uid/gid unchanged where `None`.
pub fn chown(path: &std::path::Path, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let uid = uid.unwrap_or(u32::MAX); // (uid_t)-1 == "no change"
    let gid = gid.unwrap_or(u32::MAX);
    // SAFETY: `cpath` is a valid NUL-terminated string for the call's duration.
    let rc = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_and_name_round_trip_for_root_and_the_current_user() {
        // root is uid 0 on every Linux, in both directions.
        assert_eq!(uid_for_name("root"), Some(0));
        assert_eq!(name_for_uid(0).as_deref(), Some("root"));
        // The uid running this test resolves to a name that resolves back.
        let me = unsafe { libc::geteuid() };
        let name = name_for_uid(me).expect("test uid must have an account");
        assert!(!name.is_empty());
        assert_eq!(uid_for_name(&name), Some(me));
    }

    #[test]
    fn absent_and_unencodable_users_resolve_to_none() {
        assert_eq!(uid_for_name("no-such-user-irlume-test"), None);
        // Interior NUL cannot become a C string: None, not a panic.
        assert_eq!(uid_for_name("a\0b"), None);
        // 4294967294 = (uid_t)-2, the "nobody owns this" sentinel (used by
        // idmapped mounts); it must never resolve to an account name.
        assert_eq!(name_for_uid(4294967294), None);
    }

    #[test]
    fn group_lookup_resolves_root_and_rejects_absent_groups() {
        // The root group is gid 0 on Linux (the socket-permission fallback
        // logic relies on a failed "irlume" lookup being None, not an error).
        assert_eq!(gid_for_group("root"), Some(0));
        assert_eq!(gid_for_group("no-such-group-irlume-test"), None);
        assert_eq!(gid_for_group("a\0b"), None);
    }

    #[test]
    fn chown_no_change_succeeds_and_bad_paths_error() {
        let dir = std::env::temp_dir().join(format!("irlume-chown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        std::fs::write(&f, b"x").unwrap();

        // None/None maps to (uid_t)-1/(gid_t)-1 = "no change": always allowed
        // on a file we own, even unprivileged.
        chown(&f, None, None).unwrap();
        // Re-asserting our own uid/gid is also a no-op chown and must succeed.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        chown(&f, Some(uid), Some(gid)).unwrap();
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(&f).unwrap();
        assert_eq!((md.uid(), md.gid()), (uid, gid));

        // A missing path surfaces the OS error instead of pretending success.
        assert!(chown(
            std::path::Path::new("/nonexistent/irlume-test/f"),
            None,
            None
        )
        .is_err());
        // A path with an interior NUL is rejected before touching libc.
        let nul_path = std::path::Path::new("has\0nul");
        let err = chown(nul_path, None, None).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
