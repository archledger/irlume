// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::os::fd::AsRawFd as _;

pub fn root() -> bool {
    // SAFETY: getuid/geteuid take no pointers and have no failure convention.
    unsafe { libc::getuid() == 0 && libc::geteuid() == 0 }
}

pub fn disable_process_dumps() -> bool {
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limits points to the initialized platform rlimit ABI type.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } != 0 {
        return false;
    }
    // SAFETY: PR_SET_DUMPABLE takes a boolean scalar and no pointer arguments.
    unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) == 0
    }
}

pub fn quiet_dependencies() -> bool {
    let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") else {
        return false;
    };
    // SAFETY: null owns a live descriptor. Called before spawning worker threads.
    unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) >= 0 }
}
