// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod runtime;
use runtime::{flags, pipe, stat, Result};
use sha2::{Digest, Sha256};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const LIMIT: usize = 1024 * 1024;
const MAX_IO_ATTEMPTS: usize = 1024;
const SEALS: i32 = libc::F_SEAL_WRITE
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_EXEC
    | libc::F_SEAL_SEAL;
const FAULT: Option<&str> = option_env!("IRLUME_BOOTSTRAP_TEST");

struct Budget(usize);

impl Budget {
    fn call<T>(&mut self, operation: impl FnOnce() -> io::Result<T>) -> Result<io::Result<T>> {
        self.0 = self.0.checked_sub(1).ok_or("io-budget\n")?;
        Ok(operation())
    }
}

fn pin(value: Option<&str>) -> Result<[u8; 32]> {
    let value = value.ok_or("pin-missing\n")?.as_bytes();
    if value.len() != 64 {
        return Err("pin-invalid\n");
    }
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(value.chunks_exact(2)) {
        let digit = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err("pin-invalid\n"),
        };
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(result)
}

fn read_exact(
    mut data: &mut [u8],
    mut offset: u64,
    budget: &mut Budget,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> Result<()> {
    while !data.is_empty() {
        match budget.call(|| read(data, offset))? {
            Ok(0) => return Err("source-eof\n"),
            Ok(n) if n <= data.len() => {
                offset += n as u64;
                data = &mut data[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err("read\n"),
        }
    }
    Ok(())
}

fn write_all(
    mut data: &[u8],
    budget: &mut Budget,
    mut write: impl FnMut(&[u8]) -> io::Result<usize>,
) -> Result<()> {
    while !data.is_empty() {
        match budget.call(|| write(data))? {
            Ok(n) if n > 0 && n <= data.len() => data = &data[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err("write\n"),
        }
    }
    Ok(())
}

fn pread(fd: i32, data: &mut [u8], offset: u64) -> io::Result<usize> {
    // SAFETY: data is writable for its length; callers bound offsets to LIMIT.
    let n = unsafe { libc::pread(fd, data.as_mut_ptr().cast(), data.len(), offset as i64) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write(fd: i32, data: &[u8]) -> io::Result<usize> {
    // SAFETY: data is readable for its length; write does not retain the pointer.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn eof(fd: i32, offset: u64, budget: &mut Budget) -> Result<()> {
    loop {
        match budget.call(|| pread(fd, &mut [0; 1], offset))? {
            Ok(0) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err("source-size\n"),
        }
    }
}

fn source_size(metadata: &libc::stat) -> Result<usize> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("source-role\n");
    }
    match usize::try_from(metadata.st_size) {
        Ok(size) if size > 0 && size <= LIMIT => Ok(size),
        _ => Err("source-size\n"),
    }
}

fn unchanged(a: &libc::stat, b: &libc::stat) -> bool {
    (
        a.st_dev,
        a.st_ino,
        a.st_size,
        a.st_mtime,
        a.st_mtime_nsec,
        a.st_ctime,
        a.st_ctime_nsec,
    ) == (
        b.st_dev,
        b.st_ino,
        b.st_size,
        b.st_mtime,
        b.st_mtime_nsec,
        b.st_ctime,
        b.st_ctime_nsec,
    )
}

fn memfd() -> Result<OwnedFd> {
    // SAFETY: the name is NUL-terminated and no pointer outlives the syscall.
    let fd = unsafe {
        libc::memfd_create(
            c"fixture".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_EXEC,
        )
    };
    if fd < 0 {
        return Err("memfd\n");
    }
    // SAFETY: memfd_create returned a new uniquely owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn snapshot(source: i32, budget: &mut Budget) -> Result<OwnedFd> {
    let before = stat(source)?;
    let size = source_size(&before)?;
    let image = memfd()?;
    let mut buffer = [0; 65536];
    let mut offset = 0;
    while offset < size {
        let chunk = &mut buffer[..(size - offset).min(65536)];
        read_exact(chunk, offset as u64, budget, |b, at| pread(source, b, at))?;
        write_all(chunk, budget, |b| write(image.as_raw_fd(), b))?;
        offset += chunk.len();
    }
    eof(source, size as u64, budget)?;
    if !unchanged(&before, &stat(source)?) {
        return Err("source-changed\n");
    }
    // SAFETY: this changes only our new, uniquely owned memfd's mode.
    if unsafe { libc::fchmod(image.as_raw_fd(), 0o500) } != 0 {
        return Err("mode\n");
    }
    Ok(image)
}

fn seal(fd: i32, seals: i32) -> Result<()> {
    // SAFETY: F_ADD_SEALS takes a bitmask, not a pointer.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err("seal\n");
    }
    check_seals(fd)
}

fn check_seals(fd: i32) -> Result<()> {
    // SAFETY: F_GET_SEALS has no pointer argument.
    let readback = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if readback < 0 || readback & SEALS != SEALS {
        return Err("seal-readback\n");
    }
    Ok(())
}

fn hash(fd: i32, size: usize, budget: &mut Budget) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    let mut offset = 0;
    while offset < size {
        let chunk = &mut buffer[..(size - offset).min(65536)];
        read_exact(chunk, offset as u64, budget, |b, at| pread(fd, b, at))?;
        digest.update(&*chunk);
        offset += chunk.len();
    }
    eof(fd, size as u64, budget)?;
    Ok(digest.finalize().into())
}

fn elf_header(header: &[u8], size: usize) -> Result<(u64, u16)> {
    if header.len() != 64 || &header[..7] != b"\x7fELF\x02\x01\x01" {
        return Err("elf-header\n");
    }
    let u16_at = |at| u16::from_le_bytes([header[at], header[at + 1]]);
    if u16_at(16) != 2
        || u16_at(18) != 62
        || header[20..24] != [1, 0, 0, 0]
        || u16_at(52) != 64
        || u16_at(54) != 56
    {
        return Err("elf-profile\n");
    }
    // The length check above proves that each eight-byte field exists.
    let offset = u64::from_le_bytes(header[32..40].try_into().map_err(|_| "elf-header\n")?);
    let count = u16_at(56);
    if count == 0
        || count > 128
        || offset < 64
        || offset
            .checked_add(u64::from(count) * 56)
            .filter(|end| *end <= size as u64)
            .is_none()
    {
        return Err("elf-table\n");
    }
    Ok((offset, count))
}

fn inspect(fd: i32, size: usize, budget: &mut Budget) -> Result<()> {
    let mut header = [0; 64];
    read_exact(&mut header, 0, budget, |b, at| pread(fd, b, at))?;
    let (offset, count) = elf_header(&header, size)?;
    let mut load = false;
    for index in 0..count {
        let mut segment = [0; 56];
        read_exact(
            &mut segment,
            offset + u64::from(index) * 56,
            budget,
            |b, at| pread(fd, b, at),
        )?;
        match u32::from_le_bytes(segment[..4].try_into().map_err(|_| "elf-table\n")?) {
            2 | 3 => return Err("elf-dynamic\n"),
            1 => load = true,
            _ => {}
        }
    }
    if !load {
        return Err("elf-load\n");
    }
    Ok(())
}

fn close_high_fds() -> Result<()> {
    if matches!(FAULT, Some("sentinel" | "keep-fds")) {
        // --sync-fd is an explicit fixture test, not an extra normal FD role.
        // SAFETY: F_GETFD queries only the test sentinel without taking ownership.
        if unsafe { libc::fcntl(198, libc::F_GETFD) } < 0 {
            return Err("sentinel-missing\n");
        }
        diagnostic("sentinel-received\n");
    }
    if FAULT != Some("keep-fds") {
        // SAFETY: all descriptors >=3 belong to this isolated process; none are
        // retained by the single-threaded bootstrap at this point.
        if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } != 0 {
            return Err("close-range\n");
        }
    }
    if matches!(FAULT, Some("sentinel" | "keep-fds")) {
        // SAFETY: a descriptor query does not dereference pointers.
        if unsafe { libc::fcntl(198, libc::F_GETFD) } >= 0 {
            return Err("high-fd-leak\n");
        }
    }
    Ok(())
}

fn nonblocking(fd: i32) -> Result<()> {
    let flags = flags(fd)?;
    // SAFETY: F_SETFL takes integer flags, not a pointer.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("nonblocking\n");
    }
    Ok(())
}

fn sanitize() -> Result<()> {
    nonblocking(1)?;
    // SAFETY: F_SETFD takes flags, and clearing CLOEXEC intentionally inherits
    // the already-validated output pipe into the fixture.
    if unsafe { libc::fcntl(1, libc::F_SETFD, 0) } < 0 {
        return Err("inherit\n");
    }
    // SAFETY: the fixed NUL-terminated pathname names the isolated /dev/null.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if null < 0 {
        return Err("null\n");
    }
    // SAFETY: open returned a new uniquely owned descriptor, above stdio.
    let null = unsafe { OwnedFd::from_raw_fd(null) };
    let info = stat(null.as_raw_fd())?;
    if info.st_mode & libc::S_IFMT != libc::S_IFCHR || info.st_rdev != libc::makedev(1, 3) {
        return Err("null\n");
    }
    for destination in [0, 2] {
        // SAFETY: both targets are process-owned stdio descriptors. dup2 closes
        // the source FD0 and the diagnostic pipe, with no path re-resolution.
        if unsafe { libc::dup2(null.as_raw_fd(), destination) } < 0 {
            return Err("null\n");
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    // Dedicated compile-time fault variants exercise post-CRT descriptor loss.
    let close = match FAULT {
        Some("closed-stdio-0") => Some(0),
        Some("closed-stdio-1") => Some(1),
        Some("closed-stdio-2") => Some(2),
        _ => None,
    };
    if let Some(fd) = close {
        // SAFETY: this test variant closes only its own selected stdio slot.
        unsafe { libc::close(fd) };
    }
    let output = pipe(1)?;
    let error = pipe(2)?;
    if (output.st_dev, output.st_ino) == (error.st_dev, error.st_ino) {
        return Err("pipe-alias\n");
    }
    if flags(0)? & libc::O_ACCMODE != libc::O_RDONLY {
        return Err("source-role\n");
    }
    source_size(&stat(0)?)?;
    close_high_fds()?;
    runtime::posture("/bootstrap", true)?;
    let expected = pin(option_env!("IRLUME_FIXTURE_SHA256"))?;
    let mut budget = Budget(MAX_IO_ATTEMPTS);
    let image = snapshot(0, &mut budget)?;
    seal(
        image.as_raw_fd(),
        if FAULT == Some("missing-seal") {
            SEALS & !libc::F_SEAL_EXEC
        } else {
            SEALS
        },
    )?;
    let size = source_size(&stat(image.as_raw_fd())?)?;
    if hash(image.as_raw_fd(), size, &mut budget)? != expected {
        return Err("pin-mismatch\n");
    }
    inspect(image.as_raw_fd(), size, &mut budget)?;
    sanitize()?;
    let argv = [c"/fixture".as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    // SAFETY: the same verified sealed CLOEXEC descriptor is executed, with
    // NUL-terminated static strings and terminated pointer arrays.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            image.as_raw_fd(),
            c"".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    Err("exec\n")
}

fn diagnostic(message: &'static str) {
    if pipe(2).is_ok() && nonblocking(2).is_ok() {
        // One bounded, best-effort write: no blocking/retry or raw input.
        let _ = write(2, message.as_bytes());
    }
}

pub(super) fn main() {
    if let Err(error) = run() {
        diagnostic(error);
    }
    std::process::exit(77);
}

#[cfg(test)]
mod tests;
