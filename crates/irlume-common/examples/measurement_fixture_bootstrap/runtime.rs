// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::io::Read;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;

extern "C" {
    static environ: *const *const libc::c_char;
}

pub(super) type Result<T> = std::result::Result<T, &'static str>;

pub(super) fn stat(fd: i32) -> Result<libc::stat> {
    let mut result = MaybeUninit::uninit();
    // SAFETY: fstat initializes the valid output pointer on success.
    if unsafe { libc::fstat(fd, result.as_mut_ptr()) } != 0 {
        return Err("descriptor\n");
    }
    // SAFETY: successful fstat initialized result.
    Ok(unsafe { result.assume_init() })
}

pub(super) fn flags(fd: i32) -> Result<i32> {
    // SAFETY: F_GETFL has no pointer argument and does not take ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        Err("descriptor\n")
    } else {
        Ok(flags)
    }
}

pub(super) fn pipe(fd: i32) -> Result<libc::stat> {
    let metadata = stat(fd)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFIFO
        || flags(fd)? & libc::O_ACCMODE != libc::O_WRONLY
    {
        return Err("pipe-role\n");
    }
    Ok(metadata)
}

pub(super) fn environment_entries(entries: &[&[u8]], bootstrap: bool) -> bool {
    if bootstrap {
        entries == [b"PWD=/".as_slice()]
    } else {
        entries.is_empty()
    }
}

fn environment(bootstrap: bool) -> bool {
    let mut entries = Vec::with_capacity(2);
    // SAFETY: the C runtime provides a terminated environment pointer array.
    // These executables are single-threaded and never mutate the environment.
    // Read at most two entries: either already exceeds the accepted maximum.
    unsafe {
        if !environ.is_null() {
            for index in 0..2 {
                let value = *environ.add(index);
                if value.is_null() {
                    break;
                }
                entries.push(std::ffi::CStr::from_ptr(value).to_bytes());
            }
        }
    }
    environment_entries(&entries, bootstrap)
}

pub(super) fn posture(argv0: &str, bootstrap: bool) -> Result<()> {
    // SAFETY: identity queries have no memory or ownership preconditions.
    let identity = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
            libc::getpid(),
        )
    };
    if identity.0 == 0 || identity.0 != identity.1 || identity.2 != identity.3 || identity.4 != 1 {
        return Err("identity\n");
    }
    let mut args = std::env::args_os();
    if args.next().as_deref() != Some(std::ffi::OsStr::new(argv0))
        || args.next().is_some()
        || !environment(bootstrap)
    {
        return Err("argv-env\n");
    }
    // PWD is descriptive conformance only. Check the actual cwd separately.
    if std::env::current_dir()
        .map_err(|_| "cwd\n")?
        .as_os_str()
        .as_bytes()
        != b"/"
    {
        return Err("cwd\n");
    }
    let mut status = String::new();
    std::fs::File::open("/proc/self/status")
        .map_err(|_| "proc-status\n")?
        .take(8193)
        .read_to_string(&mut status)
        .map_err(|_| "proc-status\n")?;
    if status.len() > 8192 {
        return Err("proc-status\n");
    }
    for (key, expected) in [
        ("NoNewPrivs:", "1"),
        ("CapEff:", "0000000000000000"),
        ("CapPrm:", "0000000000000000"),
        ("CapAmb:", "0000000000000000"),
    ] {
        let mut fields = status.lines().filter_map(|line| line.strip_prefix(key));
        if fields.next().map(str::trim) != Some(expected) || fields.next().is_some() {
            return Err("posture\n");
        }
    }
    Ok(())
}
