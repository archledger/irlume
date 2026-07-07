//! Thread-safe passwd/group lookups via libc reentrant calls.
//!
//! Two uses: (a) resolve the `irlume` group so the socket can be `0660
//! root:irlume` instead of world-writable, and (b) map a connecting peer's uid
//! to the username it may act on — via NSS, so LDAP/SSSD/systemd-homed users
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
        libc::getpwnam_r(cname.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
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
    let rc = unsafe {
        libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
    };
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
        libc::getgrnam_r(cname.as_ptr(), &mut grp, buf.as_mut_ptr(), buf.len(), &mut result)
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
