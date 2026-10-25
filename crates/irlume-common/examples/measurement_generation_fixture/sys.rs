// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};

pub(super) type Result<T> = std::result::Result<T, (&'static str, i32)>;

pub(super) fn error(operation: &'static str) -> (&'static str, i32) {
    (
        operation,
        io::Error::last_os_error().raw_os_error().unwrap_or(0),
    )
}

pub(super) fn check(value: libc::c_long, operation: &'static str) -> Result<libc::c_long> {
    if value < 0 {
        Err(error(operation))
    } else {
        Ok(value)
    }
}

pub(super) fn fd(value: libc::c_long, operation: &'static str) -> Result<File> {
    let raw = i32::try_from(check(value, operation)?).map_err(|_| (operation, 0))?;
    // SAFETY: callers pass only fresh descriptors returned by successful syscalls.
    Ok(unsafe { File::from_raw_fd(raw) })
}

pub(super) fn mount(
    source: &CStr,
    target: &CStr,
    kind: &CStr,
    flags: libc::c_ulong,
    data: &CStr,
) -> Result<()> {
    check(
        // SAFETY: all pointers remain valid and NUL-terminated during this call.
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                kind.as_ptr(),
                flags,
                data.as_ptr().cast(),
            )
        } as _,
        "mount",
    )?;
    Ok(())
}

pub(super) fn private_namespace() -> Result<()> {
    // SAFETY: the fixture is single-threaded and already in its isolated user/PID namespace.
    check(unsafe { libc::unshare(libc::CLONE_NEWNS) } as _, "unshare")?;
    mount(c"none", c"/", c"none", libc::MS_REC | libc::MS_PRIVATE, c"")
        .map_err(|(_, errno)| ("private propagation", errno))
}

pub(super) fn pipe() -> Result<(File, File)> {
    let mut descriptors = [-1; 2];
    check(
        // SAFETY: space for both returned descriptors is valid.
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } as _,
        "pipe",
    )?;
    // SAFETY: pipe2 returned two fresh, uniquely owned descriptors.
    Ok(unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    })
}

pub(super) fn send(fd: RawFd, bytes: &[u8]) -> Result<()> {
    // SAFETY: bytes is initialized for its length; messages are <= PIPE_BUF.
    let count = check(
        unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) } as _,
        "send",
    )?;
    if count as usize != bytes.len() {
        return Err(("short send", 0));
    }
    Ok(())
}

pub(super) fn receive(fd: RawFd, bytes: &mut [u8]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut offset = 0;
    for _ in 0..128 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(("receive timeout", 0))?;
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(remaining.as_millis())
            .map_err(|_| ("timeout bound", 0))?
            .max(1);
        // SAFETY: poll points to exactly one initialized pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready == 0 {
            return Err(("receive timeout", 0));
        }
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error("poll"));
        }
        // SAFETY: the tail of bytes is writable for the requested length.
        let count = unsafe {
            libc::read(
                fd,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error("receive"));
        }
        if count == 0 {
            return Err(("early eof", 0));
        }
        offset += count as usize;
        if offset == bytes.len() {
            return Ok(());
        }
    }
    Err(("receive budget", 0))
}

pub(super) fn byte(fd: RawFd, expected: u8) -> Result<()> {
    let mut value = [0];
    receive(fd, &mut value)?;
    if value[0] != expected {
        return Err(("unexpected phase", 0));
    }
    Ok(())
}

pub(super) fn wait(pid: libc::pid_t, expected: i32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let mut status = 0;
        // SAFETY: this PID is an unreaped child owned by this fixture; status is writable.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            if status != expected {
                return Err(("child status", status));
            }
            return Ok(());
        }
        if result < 0 {
            return Err(error("waitpid"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Err(("wait timeout", 0))
}

pub(super) fn eof(file: &File) -> Result<()> {
    let mut buffer = [0u8];
    let mut pfd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: valid pollfd; at most a bounded 5 second wait.
    check(unsafe { libc::poll(&mut pfd, 1, 5000) } as _, "eof poll")?;
    // SAFETY: buffer is writable for one byte, fd remains owned.
    if unsafe { libc::read(file.as_raw_fd(), buffer.as_mut_ptr().cast(), 1) } != 0 {
        return Err(("missing eof", 0));
    }
    Ok(())
}
