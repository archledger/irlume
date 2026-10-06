// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Session-only cleanup of LightDM's private PAM view, after authentication.
//! No authentication or credential entry point is exported. LightDM 1.32's
//! session-child calls pam_open_session as root before forking/dropping uid.

use std::io;
use std::os::unix::fs::MetadataExt as _;

const VIEW: &str = "/run/irlume-lightdm/pam.d";
const SOURCE: &str = "/run/irlume-lightdm-source/etc";

fn identity(path: &str) -> io::Result<(u64, u64)> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted PAM view directory",
        ));
    }
    Ok((meta.dev(), meta.ino()))
}

/// Detach only irlume's PAM mount in a new namespace owned by this process.
/// Return false if this process is already outside the view.
///
/// # Errors
/// Refuses untrusted directories, missing privilege, failed namespace/mount
/// operations or a restored directory different from the host source bind.
pub fn detach_private_pam_view() -> io::Result<bool> {
    let view = identity(VIEW)?;
    if identity("/etc/pam.d")? != view {
        return Ok(false);
    }
    // SAFETY: geteuid has no pointer arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PAM view cleanup requires root",
        ));
    }
    let source = identity(SOURCE)?;
    // SAFETY: unshare takes flags only. The new namespace ensures that the
    // authentication daemon and other login children keep their protected view.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: root is a static NUL-terminated path. A slave tree cannot
    // propagate this process's unmount back to its parent namespace.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_SLAVE | libc::MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this static path was verified to be irlume's mounted directory.
    if unsafe { libc::umount2(c"/etc/pam.d".as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if identity("/etc/pam.d")? != source {
        return Err(io::Error::other(
            "PAM view did not restore the host directory",
        ));
    }
    // Remove the unit's source aliases as well as retained-module storage.
    // Keep this list aligned with packaging/lightdm/50-irlume-pam.conf.
    // The canonical host PAM directory was verified before its alias is removed.
    for path in [
        c"/run/irlume-lightdm-source/vendor",
        c"/run/irlume-lightdm-source/etc",
        c"/run/irlume-lightdm",
    ] {
        // SAFETY: these fixed NUL-terminated paths are the unit's dedicated
        // bindings. Only this process's new, nonpropagating namespace changes.
        if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } != 0 {
            let error = io::Error::last_os_error();
            // The vendor binding is optional; an already absent mount is clean.
            if !matches!(
                error.raw_os_error(),
                Some(libc::EINVAL) | Some(libc::ENOENT)
            ) {
                return Err(error);
            }
        }
    }
    Ok(true)
}

// Linux-PAM's public _pam_types.h: SUCCESS=0, SESSION_ERR=14.
// The generated control is [success=ignore default=die]: this operation
// contributes no success to session policy, and failure cannot launch a
// desktop trapped in a read-only authentication view.
#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    _handle: *mut libc::c_void,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    match std::panic::catch_unwind(detach_private_pam_view) {
        Ok(Ok(_)) => 0,
        _ => 14,
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _handle: *mut libc::c_void,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    0
}
