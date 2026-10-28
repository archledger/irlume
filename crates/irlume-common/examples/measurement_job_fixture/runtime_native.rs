// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Concrete entry backend, linked but never executed by the source/build lane.
//! The C-ABI main avoids Rust lang_start's standard-FD repair and signal changes.

#[cfg(not(target_feature = "crt-static"))]
compile_error!("the manager entry requires static CRT linkage");

use super::*;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

const CGROUP2: u64 = 0x6367_7270;
const PROCFS: u64 = 0x9fa0;
const NSFS: u64 = 0x6e73_6673;
const NS_GET_USERNS: libc::c_int = 0xb701;
const NAMESPACES: [&str; 10] = [
    "user",
    "mnt",
    "pid",
    "net",
    "ipc",
    "uts",
    "cgroup",
    "time",
    "pid_for_children",
    "time_for_children",
];

fn error(operation: &'static str) -> Failure {
    // SAFETY: libc exposes the calling thread's errno location.
    failure(operation, unsafe { *libc::__errno_location() })
}

fn result(value: libc::c_long, operation: &'static str) -> Result<libc::c_long> {
    if value < 0 {
        Err(error(operation))
    } else {
        Ok(value)
    }
}

fn owned(raw: RawFd, operation: &'static str) -> Result<OwnedFd> {
    result(raw.into(), operation)?;
    // SAFETY: callers supply only a freshly returned successful descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn close(raw: RawFd) -> Result<()> {
    // SAFETY: ownership is consumed exactly once; never retry close after error.
    result(unsafe { libc::close(raw) }.into(), "entry-close").map(|_| ())
}

fn finish_fd<T>(fd: OwnedFd, outcome: Result<T>) -> Result<T> {
    let closed = close(fd.into_raw_fd());
    match outcome {
        Err(first) => Err(first),
        Ok(value) => closed.map(|()| value),
    }
}

fn open_at(parent: RawFd, path: &CStr, flags: i32) -> Result<OwnedFd> {
    // SAFETY: NUL-terminated pathname and scalar open flags; no ownership borrowed after return.
    owned(
        unsafe {
            libc::openat(
                parent,
                path.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        },
        "entry-open",
    )
}

fn path(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| failure("entry-path", 0))
}

fn stat(raw: RawFd) -> Result<libc::stat> {
    let mut value = MaybeUninit::uninit();
    // SAFETY: fstat initializes the live output on success.
    result(
        // SAFETY: live output storage; initialized by fstat on success.
        unsafe { libc::fstat(raw, value.as_mut_ptr()) }.into(),
        "entry-stat",
    )?;
    // SAFETY: successful fstat initialized value.
    Ok(unsafe { value.assume_init() })
}

fn identity(raw: RawFd) -> Result<FileId> {
    let s = stat(raw)?;
    Ok(FileId {
        device: s.st_dev,
        inode: s.st_ino,
    })
}

fn filesystem(raw: RawFd) -> Result<u64> {
    let mut value = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: successful fstatfs initializes the supplied output.
    result(
        // SAFETY: valid descriptor and live statfs output storage.
        unsafe { libc::fstatfs(raw, value.as_mut_ptr()) }.into(),
        "entry-statfs",
    )?;
    // SAFETY: output was initialized by successful fstatfs.
    Ok(unsafe { value.assume_init() }.f_type)
}

fn clock() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid writable timespec and fixed clock identifier.
    result(
        // SAFETY: fixed clock and writable timespec.
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) }.into(),
        "entry-clock",
    )?;
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(failure("entry-clock-value", 0));
    }
    (value.tv_sec as u64)
        .checked_mul(kernel::SECOND)
        .and_then(|v| v.checked_add(value.tv_nsec as u64))
        .ok_or(failure("entry-clock-overflow", 0))
}

fn before(reservation: Reservation, startup: bool) -> Result<u64> {
    let now = clock()?;
    let remaining = reservation.remaining(now)?;
    if startup && now >= reservation.origin() + 5 * kernel::SECOND {
        return Err(failure("entry-startup-expired", 0));
    }
    Ok(remaining)
}

fn read_fd(raw: RawFd, limit: usize, reservation: Reservation) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        before(reservation, true)?;
        let size = buffer.len().min(limit + 1 - data.len());
        // SAFETY: writable bounded buffer and descriptor retained throughout this call.
        let n = result(
            unsafe { libc::read(raw, buffer.as_mut_ptr().cast(), size) } as _,
            "entry-read",
        )? as usize;
        before(reservation, true)?;
        if n == 0 {
            return Ok(data);
        }
        data.extend_from_slice(&buffer[..n]);
        if data.len() > limit {
            return Err(failure("entry-read-size", 0));
        }
    }
}

fn read_path(name: &str, limit: usize, reservation: Reservation) -> Result<Vec<u8>> {
    let file = open_at(
        libc::AT_FDCWD,
        &path(name)?,
        libc::O_RDONLY | libc::O_NOFOLLOW,
    )?;
    let result = read_fd(file.as_raw_fd(), limit, reservation);
    finish_fd(file, result)
}

fn read_control(name: &CStr, reservation: Reservation) -> Result<String> {
    let file = open_at(3, name, libc::O_RDONLY | libc::O_NOFOLLOW)?;
    let result = read_fd(file.as_raw_fd(), 4096, reservation)
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| failure("entry-control-text", 0)));
    finish_fd(file, result)
}

fn expected_jobs(request: &Request) -> Result<FileId> {
    // Walk only fixed/validated components below the protected cgroup2 mount.
    // NOFOLLOW applies at every step; the final identity must equal inherited fd3.
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let mut directory = open_at(libc::AT_FDCWD, &path(CGROUP_MOUNT)?, flags)?;
    let observed = (|| {
        if filesystem(directory.as_raw_fd())? != CGROUP2 {
            return Err(failure("entry-cgroup-mount", 0));
        }
        for component in request.unit_path()[1..].split('/').chain(["jobs"]) {
            before(request.reservation, true)?;
            let child = open_at(directory.as_raw_fd(), &path(component)?, flags)?;
            let previous = std::mem::replace(&mut directory, child);
            finish_fd(previous, Ok(()))?;
            if filesystem(directory.as_raw_fd())? != CGROUP2 {
                return Err(failure("entry-cgroup-mount", 0));
            }
        }
        identity(directory.as_raw_fd())
    })();
    finish_fd(directory, observed)
}

fn path_id(name: &str, fs: Option<u64>) -> Result<FileId> {
    // Only fixed proc magic links/root paths are passed by this module.
    let file = open_at(libc::AT_FDCWD, &path(name)?, libc::O_RDONLY)?;
    let result = (|| {
        if fs.is_some_and(|wanted| filesystem(file.as_raw_fd()).ok() != Some(wanted)) {
            return Err(failure("entry-filesystem", 0));
        }
        identity(file.as_raw_fd())
    })();
    finish_fd(file, result)
}

fn socket_value(raw: RawFd, option: i32) -> Result<i32> {
    let mut value = 0_i32;
    let mut length = size_of::<i32>() as libc::socklen_t;
    // SAFETY: value/length are valid outputs of the documented integer socket options.
    result(
        // SAFETY: initialized length and writable integer output.
        unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        }
        .into(),
        "entry-socket-option",
    )?;
    if length as usize != size_of::<i32>() {
        return Err(failure("entry-socket-length", 0));
    }
    Ok(value)
}

fn fd_facts(raw: RawFd) -> Result<FdFacts> {
    let s = stat(raw)?;
    // SAFETY: F_GETFL takes no pointer or ownership argument.
    let flags = result(
        unsafe { libc::fcntl(raw, libc::F_GETFL) }.into(),
        "entry-fd-flags",
    )? as i32;
    let kind = match s.st_mode & libc::S_IFMT {
        libc::S_IFCHR if libc::major(s.st_rdev) == 1 && libc::minor(s.st_rdev) == 3 => FdKind::Null,
        libc::S_IFIFO => FdKind::Pipe,
        libc::S_IFDIR => FdKind::Directory,
        libc::S_IFSOCK
            if socket_value(raw, libc::SO_TYPE)? == libc::SOCK_STREAM
                && socket_value(raw, libc::SO_DOMAIN)? == libc::AF_UNIX =>
        {
            FdKind::UnixStream
        }
        _ => FdKind::Other,
    };
    let peer = if kind == FdKind::UnixStream {
        let mut value = MaybeUninit::<libc::ucred>::uninit();
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: valid ucred output and initialized output-buffer length.
        result(
            // SAFETY: initialized ucred length and writable output.
            unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    value.as_mut_ptr().cast(),
                    &mut length,
                )
            }
            .into(),
            "entry-peer",
        )?;
        if length as usize != size_of::<libc::ucred>() {
            return Err(failure("entry-peer-length", 0));
        }
        // SAFETY: successful complete getsockopt initialized the ucred.
        let value = unsafe { value.assume_init() };
        Some(Peer {
            pid: u32::try_from(value.pid).map_err(|_| failure("entry-peer-pid", 0))?,
            uid: value.uid,
            gid: value.gid,
        })
    } else {
        None
    };
    Ok(FdFacts {
        id: FileId {
            device: s.st_dev,
            inode: s.st_ino,
        },
        kind,
        readable: flags & libc::O_PATH == 0 && flags & libc::O_ACCMODE != libc::O_WRONLY,
        writable: flags & libc::O_PATH == 0 && flags & libc::O_ACCMODE != libc::O_RDONLY,
        nonblocking: flags & libc::O_NONBLOCK != 0,
        cgroup2: kind == FdKind::Directory && filesystem(raw)? == CGROUP2,
        peer,
    })
}

fn fd_inventory() -> Result<Vec<u32>> {
    let directory = open_at(
        libc::AT_FDCWD,
        c"/proc/self/fd",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )?;
    let raw = directory.into_raw_fd();
    // SAFETY: valid owned directory; fdopendir consumes raw only on success.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        let first = error("entry-fdopendir");
        let _ = close(raw);
        return Err(first);
    }
    let outcome = (|| {
        let mut fds = Vec::new();
        loop {
            // SAFETY: this thread owns the DIR stream and errno location.
            unsafe {
                *libc::__errno_location() = 0;
            }
            // SAFETY: stream remains open, with no concurrent readdir caller.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let e = error("entry-readdir");
                if e.errno != 0 {
                    return Err(e);
                }
                break;
            }
            // SAFETY: readdir returned a live record with a NUL-terminated name.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let value = std::str::from_utf8(name)
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or(failure("entry-fd-name", 0))?;
            if value != raw as u32 {
                fds.push(value);
            }
            if fds.len() > 5 {
                return Err(failure("entry-extra-fd", 0));
            }
        }
        fds.sort_unstable();
        Ok(fds)
    })();
    // SAFETY: consumes this module's unique DIR stream and its directory fd once.
    let closed = result(unsafe { libc::closedir(stream) }.into(), "entry-closedir");
    match outcome {
        Err(e) => Err(e),
        Ok(fds) => closed.map(|_| fds),
    }
}

fn namespaces(who: &str, owners: bool) -> Result<([FileId; 10], [FileId; 10])> {
    let mut ids = [FileId::default(); 10];
    let mut owner_ids = ids;
    for (index, name) in NAMESPACES.iter().enumerate() {
        let file = open_at(
            libc::AT_FDCWD,
            &path(&format!("/proc/{who}/ns/{name}"))?,
            libc::O_RDONLY,
        )?;
        let observed = (|| {
            if filesystem(file.as_raw_fd())? != NSFS {
                return Err(failure("entry-nsfs", 0));
            }
            ids[index] = identity(file.as_raw_fd())?;
            if owners && index != 0 {
                // SAFETY: NS_GET_USERNS returns a new owning-userns fd for a retained namespace fd.
                let owner = owned(
                    unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_USERNS) },
                    "entry-ns-owner",
                )?;
                let id = identity(owner.as_raw_fd());
                owner_ids[index] = finish_fd(owner, id)?;
            }
            Ok(())
        })();
        finish_fd(file, observed)?;
    }
    owner_ids[0] = ids[0];
    Ok((ids, owner_ids))
}

fn executable(reservation: Reservation) -> Result<[u8; 32]> {
    let file = open_at(libc::AT_FDCWD, c"/proc/self/exe", libc::O_RDONLY)?;
    let result = (|| {
        let before = stat(file.as_raw_fd())?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_uid != 0
            || before.st_mode & 0o6022 != 0
            || before.st_size <= 0
            || before.st_size > 32 * 1024 * 1024
        {
            return Err(failure("entry-executable", 0));
        }
        let bytes = read_fd(file.as_raw_fd(), 32 * 1024 * 1024, reservation)?;
        let after = stat(file.as_raw_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
            || bytes.len() as i64 != before.st_size
        {
            return Err(failure("entry-executable-changed", 0));
        }
        Ok(Sha256::digest(bytes).into())
    })();
    finish_fd(file, result)
}

fn parent_live(pid: u32) -> Result<bool> {
    // SAFETY: fixed syscall with a validated positive PID and zero flags.
    let descriptor = owned(
        result(
            unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) },
            "entry-parent-pidfd",
        )? as i32,
        "entry-parent-pidfd",
    )?;
    let mut poll = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: live one-element poll array, immediate observation only.
    let value = result(
        unsafe { libc::poll(&mut poll, 1, 0) }.into(),
        "entry-parent-poll",
    );
    // SAFETY: getppid takes no pointer or ownership arguments.
    let same_parent = unsafe { libc::getppid() } as u32 == pid;
    finish_fd(
        descriptor,
        value.map(|n| n == 0 && poll.revents == 0 && same_parent),
    )
}

fn wait_fd(fd: RawFd, events: i16, reservation: Reservation, startup: bool) -> Result<()> {
    let remaining = before(reservation, startup)?;
    let timeout = ((remaining.saturating_add(999_999)) / 1_000_000).min(10) as i32;
    let mut poll = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: writable one-element array and finite timeout.
    result(
        // SAFETY: one live pollfd and finite millisecond timeout.
        unsafe { libc::poll(&mut poll, 1, timeout) }.into(),
        "entry-poll",
    )?;
    before(reservation, startup)?;
    if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(failure("entry-poll-channel", 0));
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
enum Phase {
    Initial,
    Running,
    Completed,
    PreparingReport,
    Reporting,
    Closed,
}

struct Native {
    argv_ok: bool,
    ready: Option<Request>,
    phase: Phase,
}

impl Platform for Native {
    type Handle = OwnedFd;
    type Quarantine = kernel::Quarantine<OwnedFd>;
    fn now(&mut self) -> Result<u64> {
        clock()
    }
    fn read_request(&mut self, reservation: Reservation) -> Result<Vec<u8>> {
        if self.phase != Phase::Initial {
            return Err(failure("entry-phase", 0));
        }
        let facts = fd_facts(4)?;
        if facts.kind != FdKind::UnixStream
            || !facts.readable
            || !facts.writable
            || !facts.nonblocking
        {
            return Err(failure("entry-input-role", 0));
        }
        let mut bytes = vec![0; REQUEST_BYTES];
        let mut offset = 0;
        for _ in 0..1024 {
            before(reservation, true)?;
            if offset == bytes.len() {
                let mut extra = 0_u8;
                // SAFETY: one writable byte, peek only; no descriptor transfer is accepted.
                let n = unsafe {
                    libc::recv(
                        4,
                        (&mut extra as *mut u8).cast(),
                        1,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                if n == -1 && error("entry-extra").errno == libc::EAGAIN {
                    return Ok(bytes);
                }
                return Err(failure("entry-extra-or-closed", 0));
            }
            // SAFETY: remaining initialized writable buffer and fixed inherited input fd.
            let n =
                unsafe { libc::read(4, bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset) };
            if n > 0 {
                offset += n as usize;
            } else if n == 0 {
                return Err(failure("entry-input-eof", 0));
            } else {
                let e = error("entry-input");
                if !matches!(e.errno, libc::EINTR | libc::EAGAIN) {
                    return Err(e);
                }
                wait_fd(4, libc::POLLIN, reservation, true)?;
            }
        }
        Err(failure("entry-input-budget", 0))
    }
    fn observe(&mut self, request: &Request) -> Result<Facts> {
        if self.phase != Phase::Initial {
            return Err(failure("entry-phase", 0));
        }
        self.ready = None;
        let reservation = request.reservation;
        before(reservation, true)?;
        // SAFETY: a scalar aux-vector query; the C runtime has initialized it.
        // Secure-exec may repair standard fds before C main, so it is inadmissible.
        if unsafe { libc::getauxval(libc::AT_SECURE) } != 0 {
            return Err(failure("entry-secure-exec", 0));
        }
        let process = parse_status(&read_path("/proc/self/status", 16384, reservation)?)?;
        if process.threads != 1 || process.signals != [0; 3] {
            return Err(failure("entry-early-posture", 0));
        }
        let (current_ns, namespace_owners) = namespaces("self", true)?;
        let (initial_ns, _) = namespaces("1", false)?;
        let (parent_ns, _) = namespaces(&request.parent_pid.to_string(), false)?;
        let roots = [
            path_id("/proc/self/root", None)?,
            path_id("/proc/1/root", None)?,
            path_id(".", None)?,
        ];
        let procfs = path_id("/proc", Some(PROCFS)).is_ok();
        let boot = read_path("/proc/sys/kernel/random/boot_id", 64, reservation)?;
        let boot = std::str::from_utf8(&boot)
            .map_err(|_| failure("entry-boot-text", 0))?
            .trim_end_matches('\n');
        if boot != request.guest_boot_id {
            return Err(failure("entry-boot-id", 0));
        }
        let executable_sha256 = executable(reservation)?;
        let parent_live = parent_live(request.parent_pid)?;
        let manager = read_path("/proc/self/cgroup", 4096, reservation)?;
        let manager = std::str::from_utf8(&manager).map_err(|_| failure("entry-cgroup-text", 0))?;
        let manager_path = manager
            .strip_prefix("0::")
            .and_then(|s| s.strip_suffix('\n'))
            .filter(|s| !s.contains('\n'))
            .ok_or(failure("entry-cgroup-line", 0))?
            .to_owned();
        let mut link = [0_u8; 4096];
        // SAFETY: fixed proc magic link and full writable buffer.
        let n = result(
            unsafe {
                libc::readlink(
                    c"/proc/self/fd/3".as_ptr(),
                    link.as_mut_ptr().cast(),
                    link.len(),
                )
            } as _,
            "entry-cgroup-path",
        )? as usize;
        if n == link.len() {
            return Err(failure("entry-cgroup-path-size", 0));
        }
        let jobs_path = std::str::from_utf8(&link[..n])
            .map_err(|_| failure("entry-cgroup-path-text", 0))?
            .to_owned();
        let jobs_domain = read_control(c"cgroup.type", reservation)? == "domain\n";
        let jobs_empty = read_control(c"cgroup.procs", reservation)?
            .trim()
            .is_empty();
        let controllers = read_control(c"cgroup.subtree_control", reservation)?
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect();
        let children = read_path(
            &format!("/proc/self/task/{}/children", process.pid),
            4096,
            reservation,
        )?;
        let children = std::str::from_utf8(&children)
            .map_err(|_| failure("entry-children", 0))?
            .split_ascii_whitespace()
            .count();
        let proc_stat = read_path("/proc/self/stat", 4096, reservation)?;
        let proc_pid = std::str::from_utf8(&proc_stat)
            .ok()
            .and_then(|s| s.split_once(' '))
            .and_then(|(pid, _)| pid.parse().ok())
            .ok_or(failure("entry-proc-pid", 0))?;
        // SAFETY: musl's sigaction consists of integers, an integer mask and a
        // nullable restorer. All zero is valid; musl 1.2.3 only fills part of it.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        result(
            // SAFETY: query only, with fully initialized writable output.
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) }.into(),
            "entry-sigchld",
        )?;
        let auto_reap =
            action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0;
        let final_status = parse_status(&read_path("/proc/self/status", 16384, reservation)?)?;
        extern "C" {
            static environ: *const *const libc::c_char;
        }
        // SAFETY: the C runtime initialized environ; this single-threaded entry never mutates it.
        let env_empty = unsafe { environ.is_null() || (*environ).is_null() };
        // SAFETY: scalar identity queries with no ownership effects.
        let (pid, ppid) = unsafe { (libc::getpid(), libc::getppid()) };
        let facts = Facts {
            pid: pid as u32,
            parent_pid: ppid as u32,
            proc_pid,
            uids: final_status.uids,
            gids: final_status.gids,
            threads: final_status.threads,
            children,
            tracer: final_status.tracer,
            signals: final_status.signals,
            auto_reap,
            procfs,
            argv_ok: self.argv_ok,
            env_empty,
            parent_live,
            current_ns,
            initial_ns,
            parent_ns,
            namespace_owners,
            roots,
            boot_uuid: request.boot_uuid,
            executable_sha256,
            fds: [
                fd_facts(0)?,
                fd_facts(1)?,
                fd_facts(2)?,
                fd_facts(3)?,
                fd_facts(4)?,
            ],
            fd_inventory: fd_inventory()?,
            manager_path,
            jobs_path,
            expected_jobs: expected_jobs(request)?,
            jobs_domain,
            jobs_empty,
            controllers,
        };
        before(reservation, true)?;
        validate_facts(request, &facts)?;
        self.ready = Some(request.clone());
        Ok(facts)
    }
    fn execute(&mut self, request: &Request) -> Result<Transaction<OwnedFd, Self::Quarantine>> {
        before(request.reservation, true)?;
        if self.phase != Phase::Initial || self.ready.take().as_ref() != Some(request) {
            return Err(failure("entry-not-ready", 0));
        }
        self.phase = Phase::Running;
        // SAFETY: the protected boot caller guarantees initial namespace/ancestry,
        // exclusive topology and external recovery. observe verified one thread,
        // default signals, no children, exact nonaliased fds and namespace/view
        // correspondence. No fd-table mutation occurs between observe and here.
        // These two inherited fds are consumed once and never duplicated.
        let completion = unsafe {
            crate::sys::run(crate::sys::Input {
                parent: OwnedFd::from_raw_fd(3),
                evidence: OwnedFd::from_raw_fd(4),
                epoch: request.epoch,
                case: request.case,
                reserved_at: request.reservation.origin(),
                total_deadline: request.reservation.deadline(),
            })
        };
        self.phase = Phase::Completed;
        let reservation = completion.reservation();
        Ok(match completion {
            kernel::Completion::Clean {
                report, sentinel, ..
            } => Transaction::Clean {
                report,
                reservation,
                sentinel,
            },
            kernel::Completion::Quarantined(owner) => Transaction::Quarantined {
                report: owner.report.clone(),
                reservation,
                owner: Box::new(owner),
            },
        })
    }
    fn close_sentinel(&mut self, handle: OwnedFd) -> Result<()> {
        close(handle.into_raw_fd())
    }
    fn prepare_report(&mut self) -> Result<()> {
        if self.phase != Phase::Completed {
            return Err(failure("entry-phase", 0));
        }
        // Consume the phase before the fallible operation; failure cannot rearm M.
        self.phase = Phase::PreparingReport;
        // SAFETY: the musl sigaction representation is zero-valid.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_IGN;
        result(
            // SAFETY: initialized action, valid signal, no old-action output.
            // The native transaction is over, so children inherit no change.
            unsafe { libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()) }.into(),
            "entry-report-sigpipe",
        )?;
        self.phase = Phase::Reporting;
        Ok(())
    }
    fn write_report(&mut self, bytes: &[u8]) -> Result<usize> {
        if self.phase != Phase::Reporting {
            return Err(failure("entry-report-closed", 0));
        }
        // SAFETY: fixed verified nonblocking pipe and initialized bounded bytes.
        Ok(result(
            unsafe { libc::write(1, bytes.as_ptr().cast(), bytes.len()) } as _,
            "entry-report-write",
        )? as usize)
    }
    fn wait_report(&mut self, reservation: Reservation) -> Result<()> {
        if self.phase != Phase::Reporting {
            return Err(failure("entry-phase", 0));
        }
        wait_fd(1, libc::POLLOUT, reservation, false)
    }
    fn close_report(&mut self) -> Result<()> {
        if self.phase != Phase::Reporting {
            return Err(failure("entry-report-closed", 0));
        }
        self.phase = Phase::Closed;
        close(1)
    }
    fn confirm_quarantine(&mut self, reservation: Reservation) -> Result<()> {
        if self.phase != Phase::Closed {
            return Err(failure("entry-confirm-before-close", 0));
        }
        before(reservation, false)?;
        // SAFETY: signal only this single-threaded manager, retaining the owner
        // in drive's stack. The protected profile prohibits all other stop and
        // continue senders. E observes SIGSTOP, then drains every owned stream.
        // No fallible work follows successful signal send. Whether delivery has
        // already suspended us or occurs later, a returned/continued manager
        // only parks; E rejects continuation and we never send another stop.
        let stopped = unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
        result(stopped.into(), "entry-confirm-stop").map(|_| ())
    }
}

/// Concrete Rust-ABI entry retained for final-link inspection. Ordinary C main
/// supplies None, so no live observation or native call is enabled in R2b.
///
/// # Safety
/// With Some admission, argc/argv must be the live C-runtime arguments and the
/// caller must satisfy every Admission::from_protected_boot obligation.
#[no_mangle]
pub unsafe fn irlume_job_runtime_entry(
    argc: i32,
    argv: *const *const libc::c_char,
    admission: Option<&Admission>,
) -> ! {
    let argv_ok = if admission.is_some() && argc == 1 && !argv.is_null() {
        // SAFETY: protected caller supplies C-runtime arguments; argc is one.
        let first = unsafe { *argv };
        if first.is_null() {
            false
        } else {
            let expected = ENTRY_PATH.as_bytes();
            let mut matched = true;
            for i in 0..=expected.len() {
                // SAFETY: read stops at the first NUL; C argv[0] is a terminated string.
                let b = unsafe { *first.add(i) } as u8;
                if b == 0 {
                    matched &= i == expected.len();
                    break;
                }
                if i == expected.len() || b != expected[i] {
                    matched = false;
                    break;
                }
            }
            matched
        }
    } else {
        false
    };
    let mut platform = Native {
        argv_ok,
        ready: None,
        phase: Phase::Initial,
    };
    let outcome = drive(&mut platform, admission);
    match &outcome {
        RunOutcome::Exit { code, .. } => {
            // SAFETY: terminate without dropping any retained failed-cleanup fd or
            // running std cleanup after the final report; the kernel owns exit.
            unsafe { libc::_exit(*code) }
        }
        RunOutcome::Hold { .. } => loop {
            std::hint::black_box(&outcome);
            // SAFETY: no pointers; hold the full quarantine until E/G ends the VM.
            unsafe {
                libc::pause();
            }
        },
    }
}
