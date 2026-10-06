// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private descriptor transport for the token-delivery helper.
//! Transport is not authorization: callers must authenticate the executable,
//! acquire/check the actual PAM locks, and retain the returned files through publication.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAX_FILES: usize = 16;
const ACK: u8 = 1;

#[repr(C)]
union Control {
    alignment: libc::cmsghdr,
    bytes: [u8; 256],
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid PAM lock handoff")
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "PAM lock handoff deadline expired",
        ))
    } else {
        Ok(remaining)
    }
}

fn retry(error: &io::Error, deadline: Instant) -> io::Result<()> {
    if !matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    ) {
        return Err(io::Error::new(error.kind(), error.to_string()));
    }
    std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(2)));
    Ok(())
}

/// Send references to the helper's held lock descriptions.
///
/// # Errors
/// Refuses invalid sets, closed peers, I/O errors and expired deadlines.
pub fn send(socket: &UnixStream, files: &[File], deadline: Instant) -> io::Result<()> {
    if files.is_empty() || files.len() > MAX_FILES {
        return Err(invalid());
    }
    send_packet(socket, files, deadline)
}

fn send_packet(socket: &UnixStream, files: &[File], deadline: Instant) -> io::Result<()> {
    let descriptors: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
    let bytes = std::mem::size_of_val(descriptors.as_slice());
    let size = u32::try_from(bytes).map_err(|_| invalid())?;
    // SAFETY: the bounded sizes cannot overflow either CMSG calculation.
    let (space, length) = unsafe {
        (
            libc::CMSG_SPACE(size) as usize,
            libc::CMSG_LEN(size) as usize,
        )
    };
    if space > std::mem::size_of::<Control>() {
        return Err(invalid());
    }
    let mut control = Control { bytes: [0; 256] };
    let mut ack = ACK;
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(ack).cast(),
        iov_len: 1,
    };
    // SAFETY: zero initializes a C message header; pointers are set before use.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = std::ptr::addr_of_mut!(control).cast();
    message.msg_controllen = space;
    // SAFETY: Control is cmsghdr-aligned and space includes the full header and
    // descriptor array. All source descriptors remain alive through sendmsg.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = length;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header),
            bytes,
        );
    }
    loop {
        remaining(deadline)?;
        // SAFETY: every message pointer references live, correctly sized data.
        let sent = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent == 1 {
            return Ok(());
        }
        if sent >= 0 {
            return Err(invalid());
        }
        retry(&io::Error::last_os_error(), deadline)?;
    }
}

/// Receive the private primary lock followed by legacy exclusion descriptions.
///
/// The primary must be a private regular file owned by `owner`. Legacy locks
/// can include public, foreign-owned or unlinked regular files and FIFOs after
/// migration. Their provenance is supplied by the trusted helper, not metadata.
///
/// # Errors
/// Refuses missing/malformed/truncated descriptors, invalid file metadata,
/// I/O errors and expired deadlines. Rejected descriptors are closed.
pub fn receive(socket: &UnixStream, owner: u32, deadline: Instant) -> io::Result<Vec<File>> {
    // SAFETY: MAX_FILES * sizeof(int) is small and cannot overflow CMSG_SPACE.
    let space = unsafe {
        libc::CMSG_SPACE((MAX_FILES * std::mem::size_of::<libc::c_int>()) as u32) as usize
    };
    if space > std::mem::size_of::<Control>() {
        return Err(invalid());
    }
    loop {
        remaining(deadline)?;
        let mut control = Control { bytes: [0; 256] };
        let mut ack = 0;
        let mut iov = libc::iovec {
            iov_base: std::ptr::addr_of_mut!(ack).cast(),
            iov_len: 1,
        };
        // SAFETY: zero initializes the C message header before setting pointers.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = std::ptr::addr_of_mut!(control).cast();
        message.msg_controllen = space;
        // SAFETY: buffers are live, aligned and sized as described by message.
        let got = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if got < 0 {
            retry(&io::Error::last_os_error(), deadline)?;
            continue;
        }
        let mut files = Vec::new();
        let mut valid =
            got == 1 && ack == ACK && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0;
        let mut headers = 0;
        // Parse all returned rights even on refusal, so their File owners close
        // them. Linux closes rights discarded by ancillary-buffer truncation.
        // SAFETY: recvmsg supplied control headers within our aligned buffer.
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            headers += 1;
            // SAFETY: header comes from CMSG_FIRSTHDR/NXTHDR within the live buffer.
            let h = unsafe { &*header };
            // SAFETY: zero data length cannot overflow CMSG_LEN.
            let prefix = unsafe { libc::CMSG_LEN(0) as usize };
            let offset = header as usize - message.msg_control as usize;
            if h.cmsg_len < prefix || h.cmsg_len > message.msg_controllen.saturating_sub(offset) {
                return Err(invalid());
            }
            if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                let bytes = h.cmsg_len - prefix;
                valid &= bytes % std::mem::size_of::<libc::c_int>() == 0;
                for index in 0..bytes / std::mem::size_of::<libc::c_int>() {
                    // SAFETY: the validated header length bounds each integer;
                    // read_unaligned does not assume payload alignment. Linux
                    // installs each received descriptor as a new owned fd.
                    let fd = unsafe {
                        std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        )
                    };
                    if fd < 0 {
                        return Err(invalid());
                    }
                    // SAFETY: this unique descriptor was installed by recvmsg and
                    // has not previously been adopted or closed in this process.
                    files.push(unsafe { File::from_raw_fd(fd) });
                }
            } else {
                valid = false;
            }
            // SAFETY: the current header's extent was validated against message.
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        if !valid || headers != 1 || files.is_empty() || files.len() > MAX_FILES {
            return Err(invalid());
        }
        for (index, file) in files.iter().enumerate() {
            let metadata = file.metadata()?;
            let accepted = if index == 0 {
                metadata.is_file()
                    && metadata.uid() == owner
                    && metadata.mode() & 0o077 == 0
                    && metadata.nlink() == 1
            } else {
                metadata.is_file() || metadata.file_type().is_fifo()
            };
            if !accepted {
                return Err(invalid());
            }
        }
        remaining(deadline)?;
        return Ok(files);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::time::Duration;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "irlume-pam-handoff-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn locked(&self) -> File {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.0.join("lock"))
                .unwrap();
            // SAFETY: file owns a live regular-file descriptor.
            let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            assert_eq!(locked, 0);
            file
        }
        fn excluded(&self) -> bool {
            let file = File::open(self.0.join("lock")).unwrap();
            // SAFETY: file is live; nonblocking flock never waits here.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                false
            } else {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                true
            }
        }
        /// Whether the fixture lock comes free, waiting out the kernel's
        /// teardown window. See [`flock_exclusive_when_released`].
        fn released(&self) -> bool {
            let file = File::open(self.0.join("lock")).unwrap();
            flock_exclusive_when_released(file.as_raw_fd()) == 0
        }
    }

    /// Acquire `LOCK_EX` on `fd` once the kernel has finished releasing the
    /// lock, or report failure after a bounded wait.
    ///
    /// A flock is released only when the last reference to its open file
    /// description drops, and a concurrent `Command::spawn` in this test binary
    /// briefly inherits every open descriptor: fork copies the fd table, and
    /// CLOEXEC closes the copy only at execve. A close that lands in that
    /// window releases its lock when the child execs, microseconds to
    /// milliseconds later, so a one-shot nonblocking acquire can observe
    /// `EWOULDBLOCK` for a lock that is already going away (measured 2059 of
    /// 350056 immediate rechecks while a spawner thread ran, 0 of 2000
    /// without one). A description that is actually leaked never frees and
    /// still fails the caller's assert after the wait.
    fn flock_exclusive_when_released(fd: std::os::fd::RawFd) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            // SAFETY: the caller owns the live descriptor; LOCK_NB never waits.
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 || Instant::now() >= deadline {
                return result;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn queued_lock_survives_sender_exit_and_releases_with_receiver() {
        let fixture = Fixture::new();
        let file = fixture.locked();
        let owner = file.metadata().unwrap().uid();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        send(&sender, &[file], deadline).unwrap();
        drop(sender);
        assert!(fixture.excluded(), "the queued description owns the flock");
        let received = receive(&receiver, owner, deadline).unwrap();
        assert_eq!(received.len(), 1);
        // SAFETY: the returned file owns its descriptor.
        let flags = unsafe { libc::fcntl(received[0].as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert!(fixture.excluded());
        drop(received);
        assert!(fixture.released());
    }

    #[test]
    fn rejected_owner_does_not_leak_a_received_lock() {
        let fixture = Fixture::new();
        let file = fixture.locked();
        let wrong = file.metadata().unwrap().uid().wrapping_add(1);
        let (sender, receiver) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        send(&sender, &[file], deadline).unwrap();
        assert!(receive(&receiver, wrong, deadline).is_err());
        assert!(
            fixture.released(),
            "rejection must close every received description"
        );
    }

    #[test]
    fn handoff_retains_unlinked_public_legacy_descriptions() {
        use std::os::unix::fs::PermissionsExt as _;
        let fixture = Fixture::new();
        let primary = fixture.locked();
        let owner = primary.metadata().unwrap().uid();
        let legacy_path = fixture.0.join("legacy");
        let legacy = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&legacy_path)
            .unwrap();
        legacy
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        // SAFETY: legacy owns its descriptor; this is a nonblocking lock.
        let locked = unsafe { libc::flock(legacy.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(locked, 0);
        let competitor = File::open(&legacy_path).unwrap();
        std::fs::remove_file(legacy_path).unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        send(&sender, &[primary, legacy], deadline).unwrap();
        drop(sender);
        let received = receive(&receiver, owner, deadline).unwrap();
        assert_eq!(received.len(), 2);
        // SAFETY: competitor is live; the nonblocking call cannot wait.
        let busy = unsafe { libc::flock(competitor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(busy, 0);
        drop(received);
        // The same live descriptor, after the guard is dropped. The retry
        // waits out the kernel teardown window the helper documents.
        let free = flock_exclusive_when_released(competitor.as_raw_fd());
        assert_eq!(free, 0);
        assert!(fixture.released());
    }

    #[test]
    fn handoff_retains_legacy_fifo_but_refuses_fifo_primary() {
        let fixture = Fixture::new();
        let primary = fixture.locked();
        let owner = primary.metadata().unwrap().uid();
        let path = fixture.0.join("fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: name is a valid terminated pathname in the owned fixture.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let fifo = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        send(&sender, &[primary, fifo.try_clone().unwrap()], deadline).unwrap();
        let received = receive(&receiver, owner, deadline).unwrap();
        assert_eq!(received.len(), 2);
        drop(received);
        send(&sender, &[fifo], deadline).unwrap();
        assert!(receive(&receiver, owner, deadline).is_err());
    }

    #[test]
    fn truncated_rights_are_rejected_and_all_received_locks_are_closed() {
        let fixture = Fixture::new();
        let file = fixture.locked();
        let owner = file.metadata().unwrap().uid();
        let files: Vec<_> = (0..MAX_FILES + 1)
            .map(|_| file.try_clone().unwrap())
            .collect();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(send(&sender, &files, deadline).is_err());
        send_packet(&sender, &files, deadline).unwrap();
        drop(files);
        drop(file);
        assert!(receive(&receiver, owner, deadline).is_err());
        assert!(fixture.released());
    }

    #[test]
    fn unexpected_ancillary_credentials_refuse_and_close_received_locks() {
        let fixture = Fixture::new();
        let file = fixture.locked();
        let owner = file.metadata().unwrap().uid();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let enabled: libc::c_int = 1;
        // SAFETY: receiver is live; enabled's actual extent is passed.
        let result = unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                std::ptr::addr_of!(enabled).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        assert_eq!(result, 0);
        let deadline = Instant::now() + Duration::from_secs(2);
        send(&sender, &[file], deadline).unwrap();
        assert!(receive(&receiver, owner, deadline).is_err());
        assert!(
            fixture.released(),
            "an extra control message must not leak rights"
        );
    }

    #[test]
    fn empty_or_silent_peers_never_prove_a_lock() {
        use std::io::Write as _;
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(&[ACK]).unwrap();
        assert!(receive(&receiver, 0, Instant::now() + Duration::from_secs(1)).is_err());
        let error = receive(&receiver, 0, Instant::now() + Duration::from_millis(20)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(sender);
        assert!(receive(&receiver, 0, Instant::now() + Duration::from_secs(1)).is_err());
    }
}
