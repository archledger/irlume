// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Compiled only by the explicit, never-executed static-musl build driver.
//! Kernel calls can stall. The elapsed-time checks are not a hard I/O bound.

#[cfg(not(all(
    irlume_hw_evidence,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    target_feature = "crt-static"
)))]
compile_error!("job native backend requires explicit Linux x86-64 static-musl evidence build");

use super::kernel::bounds::{self, BoundCase};
use super::kernel::{
    self, failure, Case, Child, CloneRequest, Completion, Effects, Group, Kind, Read, Resources,
    Result, Transfer, Wait, Write, BUFFER, SECOND,
};
use std::ffi::CStr;
use std::mem::{align_of, offset_of, size_of};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

const CHILD_CLOSE_SLOTS: usize = Kind::ALL.len() - 1;

// Linux v7.2 include/uapi/linux/sched.h, pinned libc 0.2.191 x86-64 musl.
const _: () = {
    assert!(size_of::<libc::clone_args>() == 88);
    assert!(align_of::<libc::clone_args>() == 8);
    assert!(offset_of!(libc::clone_args, flags) == 0);
    assert!(offset_of!(libc::clone_args, pidfd) == 8);
    assert!(offset_of!(libc::clone_args, child_tid) == 16);
    assert!(offset_of!(libc::clone_args, parent_tid) == 24);
    assert!(offset_of!(libc::clone_args, exit_signal) == 32);
    assert!(offset_of!(libc::clone_args, stack) == 40);
    assert!(offset_of!(libc::clone_args, stack_size) == 48);
    assert!(offset_of!(libc::clone_args, tls) == 56);
    assert!(offset_of!(libc::clone_args, set_tid) == 64);
    assert!(offset_of!(libc::clone_args, set_tid_size) == 72);
    assert!(offset_of!(libc::clone_args, cgroup) == 80);
    assert!(libc::SYS_clone3 == 435);
    assert!(libc::SIGCHLD == 17);
    assert!(size_of::<libc::cmsghdr>() == 16);
    assert!(offset_of!(Rights, descriptors) == 16);
    assert!(size_of::<Rights>() == 24);
    assert!(
        bounds::SENTINEL_SEALS
            == libc::F_SEAL_SEAL
                | libc::F_SEAL_SHRINK
                | libc::F_SEAL_GROW
                | libc::F_SEAL_WRITE
                | libc::F_SEAL_EXEC
    );
};

#[repr(C)]
struct Rights {
    header: libc::cmsghdr,
    descriptors: [i32; 2],
}

impl Rights {
    fn empty() -> Self {
        // SAFETY: cmsghdr consists only of integer fields.
        Self {
            // SAFETY: a zero cmsghdr has valid integer field values.
            header: unsafe { std::mem::zeroed() },
            descriptors: [-1; 2],
        }
    }
}

/// Already-owned inputs from a future reviewed boot integration. This type is
/// inhabited for code generation; no repository entry constructs it at runtime.
pub struct Input {
    pub parent: OwnedFd,
    pub evidence: OwnedFd,
    pub epoch: u64,
    pub case: Case,
    pub reserved_at: u64,
    pub total_deadline: u64,
}

struct Native {
    parent: Option<OwnedFd>,
    evidence: Option<OwnedFd>,
    name: [u8; 21],
    job: Option<(u64, u64)>,
    leaf: Option<(u64, u64)>,
    worker: Option<(u64, u64)>,
    case: Case,
    work_cap: Option<u64>,
}

impl Native {
    fn name(&self) -> &CStr {
        // SAFETY: kernel::job_name fills 20 non-NUL ASCII bytes and one final NUL.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.name) }
    }
}

fn error(operation: &'static str) -> kernel::Failure {
    // SAFETY: Linux libc supplies this thread's live errno location.
    failure(operation, unsafe { *libc::__errno_location() })
}

fn check(value: libc::c_long, operation: &'static str) -> Result<libc::c_long> {
    if value < 0 {
        Err(error(operation))
    } else {
        Ok(value)
    }
}

fn descriptor(value: libc::c_int, operation: &'static str) -> Result<OwnedFd> {
    check(value.into(), operation)?;
    // SAFETY: only successful fresh fd-returning syscalls reach this helper.
    Ok(unsafe { OwnedFd::from_raw_fd(value) })
}

fn fd(resources: &Resources<OwnedFd>, kind: Kind) -> Result<RawFd> {
    resources
        .get(kind)
        .map(AsRawFd::as_raw_fd)
        .ok_or(failure("missing-fd", 0))
}

fn open(parent: RawFd, name: &CStr, flags: i32) -> Result<OwnedFd> {
    // SAFETY: name is NUL-terminated and parent is an owned directory.
    descriptor(
        unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        },
        "openat",
    )
}

fn identity(raw: RawFd) -> Result<(u64, u64)> {
    // SAFETY: stat is a plain C output structure; fstat initializes it on success.
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: value is writable and raw remains owned for this call.
    check(unsafe { libc::fstat(raw, &mut value) }.into(), "fstat")?;
    Ok((value.st_dev, value.st_ino))
}

fn cgroup(raw: RawFd) -> Result<()> {
    // SAFETY: statfs is a plain C output structure.
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: value is writable and raw is retained by its owner.
    check(unsafe { libc::fstatfs(raw, &mut value) }.into(), "fstatfs")?;
    if value.f_type != 0x6367_7270 {
        return Err(failure("not-cgroup2", 0));
    }
    Ok(())
}

fn read_file(parent: RawFd, name: &CStr) -> Result<([u8; BUFFER], usize)> {
    let file = open(parent, name, libc::O_RDONLY)?;
    let mut bytes = [0; BUFFER];
    // SAFETY: the owned file and writable fixed buffer span the read.
    let count = check(
        unsafe { libc::read(file.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) } as _,
        "read-control",
    )? as usize;
    if count == bytes.len() {
        return Err(failure("control-size", 0));
    }
    Ok((bytes, count))
}

fn read_complete(parent: RawFd, name: &CStr) -> Result<([u8; BUFFER], usize)> {
    let file = open(parent, name, libc::O_RDONLY)?;
    let mut bytes = [0; BUFFER];
    let mut offset = 0;
    loop {
        // SAFETY: owned descriptor and remaining writable buffer; size stays bounded.
        let count = check(
            unsafe {
                libc::read(
                    file.as_raw_fd(),
                    bytes[offset..].as_mut_ptr().cast(),
                    BUFFER - offset,
                )
            } as _,
            "read-complete",
        )? as usize;
        if count == 0 {
            return Ok((bytes, offset));
        }
        offset += count;
        if offset == BUFFER {
            return Err(failure("control-size", 0));
        }
    }
}

fn setting(parent: RawFd, name: &CStr, value: &[u8]) -> Result<()> {
    let file = open(parent, name, libc::O_WRONLY)?;
    // SAFETY: value is initialized and file remains owned throughout the write.
    let count = check(
        unsafe { libc::write(file.as_raw_fd(), value.as_ptr().cast(), value.len()) } as _,
        "write-limit",
    )? as usize;
    if count != value.len() {
        return Err(failure("limit-short", 0));
    }
    let (bytes, count) = read_file(parent, name)?;
    if bytes[..count]
        .strip_suffix(b"\n")
        .unwrap_or(&bytes[..count])
        != value.strip_suffix(b"\n").unwrap_or(value)
    {
        return Err(failure("limit-readback", 0));
    }
    Ok(())
}

fn clock() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is valid output storage; CLOCK_BOOTTIME includes suspend.
    check(
        // SAFETY: valid writable timespec and supported clock identifier.
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) }.into(),
        "clock-boottime",
    )?;
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(failure("clock-value", 0));
    }
    (value.tv_sec as u64)
        .checked_mul(SECOND)
        .and_then(|n| n.checked_add(value.tv_nsec as u64))
        .ok_or(failure("clock-overflow", 0))
}

impl Effects for Native {
    type Handle = OwnedFd;
    fn clock(&mut self) -> Result<u64> {
        clock()
    }

    fn prepare(&mut self) -> Result<()> {
        // SAFETY: scalar prctl arguments set this dedicated process's subreaper flag.
        check(
            // SAFETY: scalar-only operation on this dedicated M process.
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong, 0, 0, 0) }
                .into(),
            "subreaper-set",
        )?;
        let mut enabled: libc::c_int = 0;
        // SAFETY: the GET operation writes one c_int into live local storage.
        check(
            // SAFETY: enabled is writable for the returned c_int.
            unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut enabled, 0, 0, 0) }.into(),
            "subreaper-get",
        )?;
        if enabled != 1 {
            return Err(failure("subreaper-readback", 0));
        }
        // SAFETY: plain C output structure, initialized by successful sigaction.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: null new action only queries SIGCHLD; output is writable.
        check(
            // SAFETY: query only, with valid output storage.
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) }.into(),
            "sigchld",
        )?;
        if action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(failure("sigchld-autoreap", 0));
        }
        Ok(())
    }

    fn acquire(&mut self, kind: Kind, resources: &Resources<OwnedFd>) -> Result<OwnedFd> {
        match kind {
            Kind::Parent => {
                let parent = self.parent.take().ok_or(failure("parent-missing", 0))?;
                cgroup(parent.as_raw_fd())?;
                Ok(parent)
            }
            Kind::Evidence => self.evidence.take().ok_or(failure("evidence-missing", 0)),
            Kind::Sentinel => {
                // SAFETY: fixed C string and explicit data-only creation flags.
                // Initialization happens only after ownership transfers to M.
                descriptor(
                    unsafe {
                        libc::memfd_create(
                            c"irlume-job-custody".as_ptr(),
                            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_NOEXEC_SEAL,
                        )
                    },
                    "sentinel-create",
                )
            }
            Kind::Job => {
                let file = open(
                    fd(resources, Kind::Parent)?,
                    self.name(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                cgroup(file.as_raw_fd())?;
                let observed = identity(file.as_raw_fd())?;
                if self.job.is_some_and(|old| old != observed) {
                    return Err(failure("job-replaced", 0));
                }
                self.job = Some(observed);
                Ok(file)
            }
            Kind::Leaf | Kind::Worker => {
                let (name, expected) = if kind == Kind::Leaf {
                    (c"supervisor", &mut self.leaf)
                } else {
                    (c"worker", &mut self.worker)
                };
                let file = open(
                    fd(resources, Kind::Job)?,
                    name,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                let observed = identity(file.as_raw_fd())?;
                if expected.is_some_and(|old| old != observed) {
                    return Err(failure("leaf-replaced", 0));
                }
                *expected = Some(observed);
                let (bytes, count) = read_file(file.as_raw_fd(), c"cgroup.type")?;
                if &bytes[..count] != b"domain\n" {
                    return Err(failure("leaf-domain", 0));
                }
                let (bytes, count) = read_file(file.as_raw_fd(), c"cgroup.subtree_control")?;
                if bytes[..count].iter().any(|b| !b.is_ascii_whitespace()) {
                    return Err(failure("leaf-not-terminal", 0));
                }
                Ok(file)
            }
            Kind::Kill => open(fd(resources, Kind::Job)?, c"cgroup.kill", libc::O_WRONLY),
            Kind::Events => open(fd(resources, Kind::Job)?, c"cgroup.events", libc::O_RDONLY),
            Kind::Control | Kind::Peer => Err(failure("channel-acquire", 0)),
        }
    }

    fn mkdir(&mut self, group: Group, resources: &Resources<OwnedFd>) -> Result<()> {
        let (parent, name) = match group {
            Group::Job => (fd(resources, Kind::Parent)?, self.name()),
            Group::Leaf => (fd(resources, Kind::Job)?, c"supervisor"),
            Group::Worker => (fd(resources, Kind::Job)?, c"worker"),
        };
        // SAFETY: owned parent and fixed NUL-terminated child name. EEXIST refuses.
        check(
            // SAFETY: parent/name remain valid; no existing directory is adopted.
            unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) }.into(),
            "mkdirat",
        )?;
        Ok(())
    }

    fn configure(&mut self, resources: &Resources<OwnedFd>) -> Result<()> {
        let job = fd(resources, Kind::Job)?;
        let (bytes, count) = read_file(job, c"cgroup.type")?;
        if &bytes[..count] != b"domain\n" {
            return Err(failure("job-domain", 0));
        }
        let (bytes, count) = read_file(job, c"cgroup.procs")?;
        if bytes[..count].iter().any(|b| !b.is_ascii_whitespace()) {
            return Err(failure("job-not-empty", 0));
        }
        for (name, value) in [
            (c"pids.max", &b"32\n"[..]),
            (c"memory.max", b"134217728\n"),
            (c"memory.swap.max", b"0\n"),
            (c"cpu.max", b"100000 100000\n"),
        ] {
            setting(job, name, value)?;
        }
        // Parent controller delegation is a boot prerequisite. Never change it.
        let subtree = open(job, c"cgroup.subtree_control", libc::O_WRONLY)?;
        let value = b"+pids +memory +cpu\n";
        // SAFETY: a fixed complete controller request, with an owned destination.
        let count = check(
            // SAFETY: initialized bytes and retained writable control descriptor.
            unsafe { libc::write(subtree.as_raw_fd(), value.as_ptr().cast(), value.len()) } as _,
            "subtree-control",
        )?;
        if count as usize != value.len() {
            return Err(failure("subtree-short", 0));
        }
        let (bytes, count) = read_file(job, c"cgroup.subtree_control")?;
        let controllers =
            std::str::from_utf8(&bytes[..count]).map_err(|_| failure("subtree-readback", 0))?;
        if controllers.split_ascii_whitespace().count() != 3
            || ["cpu", "memory", "pids"].into_iter().any(|name| {
                !controllers
                    .split_ascii_whitespace()
                    .any(|value| value == name)
            })
        {
            return Err(failure("subtree-readback", 0));
        }
        Ok(())
    }

    fn channels(&mut self) -> Result<(OwnedFd, OwnedFd)> {
        let mut pair = [-1; 2];
        // SAFETY: valid storage for both returned descriptors.
        check(
            // SAFETY: pair has space for both distinct descriptors.
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                    pair.as_mut_ptr(),
                )
            }
            .into(),
            "socketpair",
        )?;
        // SAFETY: successful socketpair returned two distinct, newly owned fds.
        Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
    }

    fn handle_number(&self, handle: &OwnedFd) -> u64 {
        handle.as_raw_fd() as u64
    }

    fn birth(
        &mut self,
        request: CloneRequest,
        resources: &Resources<OwnedFd>,
        epoch: u64,
        deadline: u64,
    ) -> Result<Child<OwnedFd>> {
        if request != CloneRequest::new(fd(resources, Kind::Leaf)? as u64) {
            return Err(failure("clone-request", 0));
        }
        let mut slot: i32 = -1;
        let args = libc::clone_args {
            flags: request.flags,
            pidfd: (&mut slot as *mut i32) as u64,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: request.exit_signal,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: request.cgroup,
        };
        let mut inherited = [-1; CHILD_CLOSE_SLOTS];
        for (index, handle) in resources.child_closes().enumerate() {
            *inherited
                .get_mut(index)
                .ok_or(failure("child-close-capacity", 0))? = handle.as_raw_fd();
        }
        let peer = fd(resources, Kind::Peer)?;
        // SAFETY: exact pinned ABI, live pidfd output, retained directory and no
        // shared VM/files/thread flags. The unsafe entry requires one M thread.
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &args as *const libc::clone_args,
                size_of::<libc::clone_args>(),
            )
        };
        if result < 0 {
            // fork.c may write a reserved number then release it on failure.
            // Do not adopt or close slot on this path.
            return Err(error("clone3"));
        }
        if result == 0 {
            child(peer, &inherited, epoch, deadline, self.case);
        }
        let pidfd = if slot >= 0 {
            // SAFETY: successful clone3 installed this fresh pidfd in M only.
            Some(unsafe { OwnedFd::from_raw_fd(slot) })
        } else {
            None
        };
        Ok(Child {
            pid: result as u32,
            valid: result <= i32::MAX as i64 && pidfd.is_some(),
            pidfd,
        })
    }

    fn parked(&mut self, resources: &Resources<OwnedFd>, child: &Child<OwnedFd>) -> Result<()> {
        let (bytes, count) = read_file(fd(resources, Kind::Leaf)?, c"cgroup.procs")?;
        let expected = format!("{}\n", child.pid);
        if bytes[..count] != *expected.as_bytes() {
            return Err(failure("parked-membership", 0));
        }
        let (bytes, count) = read_file(fd(resources, Kind::Job)?, c"cgroup.procs")?;
        if bytes[..count].iter().any(|b| !b.is_ascii_whitespace()) {
            return Err(failure("manager-in-job", 0));
        }
        Ok(())
    }

    fn read(
        &mut self,
        kind: Read,
        resources: &Resources<OwnedFd>,
        offset: usize,
        output: &mut [u8],
    ) -> Result<usize> {
        if kind == Read::Population && self.case.bounds() == Some(BoundCase::WithheldPopulation) {
            return Err(failure("fixture-withheld-population", 0));
        }
        let value = match kind {
            Read::Population => {
                // SAFETY: retained control fd; bounded writable buffer and offset.
                unsafe {
                    libc::pread(
                        fd(resources, Kind::Events)?,
                        output.as_mut_ptr().cast(),
                        output.len(),
                        offset as libc::off_t,
                    )
                }
            }
            Read::Ready | Read::Complete | Read::Born | Read::Active => {
                // SAFETY: retained nonblocking channel and writable bounded buffer.
                unsafe {
                    libc::recv(
                        fd(resources, Kind::Control)?,
                        output.as_mut_ptr().cast(),
                        output.len(),
                        0,
                    )
                }
            }
        };
        let count = check(value as _, "read")? as usize;
        if kind == Read::Complete
            && self.case.bounds() == Some(BoundCase::LateRead)
            && offset + count == 9
        {
            let cap = self.work_cap.ok_or(failure("work-cap-missing", 0))?;
            for _ in 0..kernel::MAX_OPERATIONS {
                if clock()? >= cap {
                    return Ok(count);
                }
                // SAFETY: no fd array; finite delay for the explicit late-read control.
                check(
                    // SAFETY: no descriptor array, finite two-millisecond pause.
                    unsafe { libc::poll(std::ptr::null_mut(), 0, 2) }.into(),
                    "late-read-pause",
                )?;
            }
            return Err(failure("late-read-unreached", 0));
        }
        Ok(count)
    }

    fn write(&mut self, kind: Write, resources: &Resources<OwnedFd>, data: &[u8]) -> Result<usize> {
        let value = match kind {
            Write::Kill => {
                // SAFETY: exact owned J kill interface and initialized request bytes.
                unsafe { libc::write(fd(resources, Kind::Kill)?, data.as_ptr().cast(), data.len()) }
            }
            Write::Command => {
                // SAFETY: owned stream and initialized bytes; suppress SIGPIPE.
                unsafe {
                    libc::send(
                        fd(resources, Kind::Control)?,
                        data.as_ptr().cast(),
                        data.len(),
                        libc::MSG_NOSIGNAL,
                    )
                }
            }
        };
        Ok(check(value as _, kind.name())? as usize)
    }

    fn wait(&mut self, child: Option<&Child<OwnedFd>>, consume: bool) -> Result<Wait> {
        if child.is_none() && self.case.bounds() == Some(BoundCase::WithheldWait) {
            return Err(failure("fixture-withheld-wait", 0));
        }
        let (kind, id, extra) = if let Some(child) = child {
            (
                libc::P_PIDFD,
                child
                    .pidfd
                    .as_ref()
                    .ok_or(failure("pidfd-missing", 0))?
                    .as_raw_fd() as libc::id_t,
                0,
            )
        } else {
            (libc::P_ALL, 0, libc::__WALL)
        };
        // SAFETY: siginfo_t is C output storage, zeroed to distinguish no-result.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let options =
            libc::WEXITED | libc::WNOHANG | extra | if consume { 0 } else { libc::WNOWAIT };
        // SAFETY: exact libc four-argument waitid ABI, retained pidfd or exclusive
        // M child set, writable info. No blocking wait and no numeric-PID signal.
        if unsafe { libc::waitid(kind, id, &mut info, options) } < 0 {
            let error = error("waitid");
            return if error.errno == libc::ECHILD {
                Ok(Wait::NoChildren)
            } else {
                Err(error)
            };
        }
        // SAFETY: successful waitid initialized the SIGCHLD union fields.
        let pid = unsafe { info.si_pid() };
        if pid == 0 {
            return Ok(Wait::Pending);
        }
        // SAFETY: same initialized SIGCHLD record.
        Ok(Wait::Terminal {
            pid: pid as u32,
            code: info.si_code,
            // SAFETY: successful waitid initialized this SIGCHLD record.
            status: unsafe { info.si_status() },
        })
    }

    fn pause(&mut self, deadline: u64) -> Result<()> {
        if clock()? >= deadline {
            return Err(failure("expired", 0));
        }
        // SAFETY: zero fds permits a null pointer; finite 2 ms polling quantum.
        check(
            // SAFETY: no descriptor array, finite polling duration.
            unsafe {
                libc::poll(
                    std::ptr::null_mut(),
                    0,
                    if self.case.bounds().is_some() {
                        bounds::POLL_MS
                    } else {
                        2
                    },
                )
            }
            .into(),
            "poll",
        )?;
        Ok(())
    }

    fn remove(&mut self, group: Group, resources: &Resources<OwnedFd>) -> Result<()> {
        let (parent, name, expected) = match group {
            Group::Job => (fd(resources, Kind::Parent)?, self.name(), self.job),
            Group::Leaf => (fd(resources, Kind::Job)?, c"supervisor", self.leaf),
            Group::Worker => (fd(resources, Kind::Job)?, c"worker", self.worker),
        };
        let file = open(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if Some(identity(file.as_raw_fd())?) != expected {
            return Err(failure("remove-identity", 0));
        }
        // SAFETY: trusted exclusive parent, same retained object identity, fixed
        // child name. No recursive removal and no unowned cgroup is removed.
        check(
            // SAFETY: same checked identity under the exclusive owned parent.
            unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) }.into(),
            "rmdir",
        )?;
        Ok(())
    }

    fn close(&mut self, handle: OwnedFd) -> Result<()> {
        let raw = handle.into_raw_fd();
        // SAFETY: ownership is consumed once. Never retry a close error.
        check(unsafe { libc::close(raw) }.into(), "close")?;
        Ok(())
    }

    fn registration(
        &mut self,
        resources: &Resources<OwnedFd>,
        output: &mut [u8],
    ) -> Result<Transfer<OwnedFd>> {
        let mut rights = Rights::empty();
        let mut vector = libc::iovec {
            iov_base: output.as_mut_ptr().cast(),
            iov_len: output.len(),
        };
        // SAFETY: msghdr is a C integer/pointer aggregate; all used pointers follow.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut vector;
        header.msg_iovlen = 1;
        header.msg_control = (&mut rights as *mut Rights).cast();
        header.msg_controllen = size_of::<Rights>() as _;
        // SAFETY: all writable buffers and headers live across this nonblocking call.
        let count = check(
            unsafe {
                libc::recvmsg(
                    fd(resources, Kind::Control)?,
                    &mut header,
                    libc::MSG_CMSG_CLOEXEC,
                )
            } as _,
            "recvmsg",
        )? as usize;
        let mut handles = [None, None];
        let length = header.msg_controllen as usize;
        let mut valid = header.msg_flags & !libc::MSG_CMSG_CLOEXEC == 0;
        if length != 0 {
            // The pinned 24-byte buffer can contain one header and at most two
            // installed descriptors. Adopt the installed prefix before rejection.
            if length >= size_of::<libc::cmsghdr>()
                && rights.header.cmsg_level == libc::SOL_SOCKET
                && rights.header.cmsg_type == libc::SCM_RIGHTS
            {
                let payload_end = (rights.header.cmsg_len as usize)
                    .min(length)
                    .min(size_of::<Rights>());
                let payload = payload_end.saturating_sub(size_of::<libc::cmsghdr>());
                for (slot, raw) in handles
                    .iter_mut()
                    .zip(rights.descriptors)
                    .take(payload / size_of::<i32>())
                {
                    if raw >= 0 {
                        // SAFETY: successful recvmsg installed each SCM_RIGHTS fd
                        // as a new distinct owned descriptor in this process.
                        *slot = Some(unsafe { OwnedFd::from_raw_fd(raw) });
                    } else {
                        valid = false;
                    }
                }
                valid &= rights.header.cmsg_len as usize
                    == size_of::<libc::cmsghdr>() + size_of::<i32>()
                    && length == size_of::<Rights>();
            } else {
                valid = false;
            }
        }
        Ok(Transfer {
            count,
            handles,
            valid,
        })
    }

    fn worker_identity(
        &mut self,
        child: &Child<OwnedFd>,
        case: Case,
        descendant: u32,
    ) -> Result<()> {
        let raw = child
            .pidfd
            .as_ref()
            .ok_or(failure("worker-pidfd", 0))?
            .as_raw_fd();
        // SAFETY: statfs is plain output storage, initialized on successful fstatfs.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: raw is retained, fs is writable.
        check(
            // SAFETY: raw is retained and fs is writable C output storage.
            unsafe { libc::fstatfs(raw, &mut fs) }.into(),
            "pidfd-fstatfs",
        )?;
        if fs.f_type != 0x5049_4446 {
            return Err(failure("not-pidfs", 0));
        }
        let name = std::ffi::CString::new(format!("/proc/self/fdinfo/{raw}"))
            .map_err(|_| failure("fdinfo-name", 0))?;
        let (bytes, count) = read_complete(libc::AT_FDCWD, &name)?;
        kernel::pidfd_identity(&bytes[..count], child.pid)?;
        let mut poll = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, nonblocking observation only.
        check(unsafe { libc::poll(&mut poll, 1, 0) }.into(), "pidfd-poll")?;
        let expected = if case.shape() == 0 { 0 } else { libc::POLLIN };
        if poll.revents != expected {
            return Err(failure("worker-state", 0));
        }
        if case == Case::DoubleFork {
            // SAFETY: this fixed unreaped descendant belongs to the exclusive M
            // tree. This is observation, never numeric-PID signaling.
            let session = check(
                unsafe { libc::getsid(descendant as i32) }.into(),
                "worker-session",
            )?;
            if session != child.pid as i64 {
                return Err(failure("worker-session", 0));
            }
        }
        Ok(())
    }

    fn members(
        &mut self,
        resources: &Resources<OwnedFd>,
        supervisor: &[u32],
        worker: &[u32],
    ) -> Result<()> {
        for (kind, expected) in [
            (Kind::Job, &[][..]),
            (Kind::Leaf, supervisor),
            (Kind::Worker, worker),
        ] {
            let (bytes, count) = read_complete(fd(resources, kind)?, c"cgroup.procs")?;
            kernel::membership(&bytes[..count], expected)?;
        }
        Ok(())
    }

    fn place(&mut self, resources: &Resources<OwnedFd>, child: &Child<OwnedFd>) -> Result<()> {
        let control = open(
            fd(resources, Kind::Worker)?,
            c"cgroup.procs",
            libc::O_WRONLY,
        )?;
        let value = format!("{}\n", child.pid);
        // SAFETY: the fixed S never reaps B. M is its only possible reaper after
        // S loss and performs no consuming wait until placement ends/aborts.
        let count = check(
            unsafe { libc::write(control.as_raw_fd(), value.as_ptr().cast(), value.len()) } as _,
            "worker-place",
        )?;
        if count as usize != value.len() {
            return Err(failure("placement-short", 0));
        }
        Ok(())
    }

    fn signal(&mut self, child: &Child<OwnedFd>) -> Result<()> {
        let raw = child
            .pidfd
            .as_ref()
            .ok_or(failure("supervisor-pidfd", 0))?
            .as_raw_fd();
        // SAFETY: retained S pidfd, fixed SIGKILL, no siginfo and no fallback.
        check(
            // SAFETY: retained S pidfd, fixed signal, null siginfo and zero flags.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    raw,
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            "pidfd-send-signal",
        )?;
        Ok(())
    }

    fn oom_kills(&mut self, resources: &Resources<OwnedFd>) -> Result<[u64; 3]> {
        let mut counts = [0; 3];
        // These are the only cgroups in the fixed, exclusively owned topology.
        // Local counters avoid mount-dependent memory.events aggregation.
        for (kind, retained) in [Kind::Job, Kind::Leaf, Kind::Worker]
            .into_iter()
            .zip(&mut counts)
        {
            let (bytes, count) = read_complete(fd(resources, kind)?, c"memory.events.local")?;
            *retained = kernel::oom_count(&bytes[..count])?;
        }
        Ok(counts)
    }

    fn initialize_sentinel(&mut self, resources: &Resources<OwnedFd>, epoch: u64) -> Result<()> {
        let raw = fd(resources, Kind::Sentinel)?;
        let bytes = bounds::sentinel(epoch);
        // SAFETY: retained owned descriptor and initialized fixed public data.
        let count = check(
            unsafe { libc::write(raw, bytes.as_ptr().cast(), bytes.len()) } as _,
            "sentinel-write",
        )?;
        if count as usize != bytes.len() {
            return Err(failure("sentinel-short-write", 0));
        }
        let seals = bounds::SENTINEL_SEALS & !libc::F_SEAL_EXEC;
        // SAFETY: scalar fcntl request on the retained memfd; EXEC was set at creation.
        check(
            // SAFETY: retained memfd and a fixed scalar sealing mask.
            unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, seals) }.into(),
            "sentinel-seal",
        )?;
        Ok(())
    }

    fn verify_sentinel(
        &mut self,
        resources: &Resources<OwnedFd>,
        epoch: u64,
        after: bool,
    ) -> Result<()> {
        let raw = fd(resources, Kind::Sentinel)?;
        // SAFETY: stat is integer-only C output storage.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: retained descriptor and live writable stat storage.
        check(
            // SAFETY: retained descriptor and writable C stat output.
            unsafe { libc::fstat(raw, &mut stat) }.into(),
            "sentinel-stat",
        )?;
        // SAFETY: scalar query on the retained descriptor.
        let seals = check(
            unsafe { libc::fcntl(raw, libc::F_GET_SEALS) }.into(),
            "sentinel-get-seals",
        )?;
        let mut bytes = [0; bounds::SENTINEL_LEN + 1];
        // SAFETY: valid output slice and fixed nonnegative offset on the owned file.
        let count = check(
            unsafe { libc::pread(raw, bytes.as_mut_ptr().cast(), bytes.len(), 0) } as _,
            "sentinel-read",
        )? as usize;
        bounds::validate_sentinel(
            &bytes[..count],
            stat.st_size,
            stat.st_mode,
            seals as i32,
            epoch,
        )?;
        if after && self.case.bounds() == Some(BoundCase::WithheldSentinel) {
            return Err(failure("fixture-withheld-sentinel", 0));
        }
        Ok(())
    }

    fn arm_work(&mut self, cap: u64) -> Result<()> {
        if self.work_cap.is_some() || cap <= clock()? {
            return Err(failure("work-rearm-or-expired", 0));
        }
        self.work_cap = Some(cap);
        Ok(())
    }

    fn worker_terminal(&mut self, child: &Child<OwnedFd>) -> Result<bool> {
        let raw = child
            .pidfd
            .as_ref()
            .ok_or(failure("worker-pidfd", 0))?
            .as_raw_fd();
        let mut p = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: retained pidfd and one writable pollfd; this requires no parenthood.
        check(
            // SAFETY: one initialized pollfd and a zero timeout.
            unsafe { libc::poll(&mut p, 1, 0) }.into(),
            "worker-terminal-poll",
        )?;
        match p.revents {
            0 => Ok(false),
            libc::POLLIN => Ok(true),
            _ => Err(failure("worker-terminal-state", 0)),
        }
    }
}

fn child(
    peer: RawFd,
    inherited: &[RawFd; CHILD_CLOSE_SLOTS],
    epoch: u64,
    deadline: u64,
    case: Case,
) -> ! {
    for raw in inherited {
        if *raw >= 0 && *raw != peer {
            // SAFETY: these are this fork child's inherited copies. No retries.
            if unsafe { libc::close(*raw) } != 0 {
                child_exit(125);
            }
        }
    }
    for raw in 0..=2 {
        if raw != peer && !inherited.contains(&raw) {
            // SAFETY: only this child's standard descriptors; EBADF means absent.
            if unsafe { libc::close(raw) } != 0 && error("child-stdio-close").errno != libc::EBADF {
                child_exit(125);
            }
        }
    }
    if !child_send(peer, &kernel::message(1, epoch), deadline) {
        child_exit(125);
    }
    let mut input = [0; 9];
    let mut offset = 0;
    for _ in 0..kernel::MAX_OPERATIONS {
        if clock().map_or(true, |now| now >= deadline) {
            child_exit(124);
        }
        // SAFETY: retained child channel, bounded writable array tail.
        let count = unsafe {
            libc::recv(
                peer,
                input[offset..].as_mut_ptr().cast(),
                input.len() - offset,
                0,
            )
        };
        if count > 0 {
            offset += count as usize;
        } else if count == 0 || !matches!(error("child-read").errno, libc::EINTR | libc::EAGAIN) {
            child_exit(125);
        }
        if offset == input.len() {
            break;
        }
        child_pause();
    }
    if input != kernel::message(3, epoch) {
        child_exit(125);
    }
    if case != Case::SupervisorOnly {
        child_worker(peer, epoch, deadline, case);
    }
    if !child_send(peer, &kernel::message(2, epoch), deadline) {
        child_exit(125);
    }
    for _ in 0..kernel::MAX_OPERATIONS {
        if clock().map_or(true, |now| now >= deadline) {
            child_exit(124);
        }
        child_pause();
    }
    child_exit(124)
}

fn child_send(peer: RawFd, data: &[u8], deadline: u64) -> bool {
    let mut offset = 0;
    for _ in 0..kernel::MAX_OPERATIONS {
        if clock().map_or(true, |now| now >= deadline) {
            return false;
        }
        // SAFETY: live channel and initialized fixed array, no allocation/locks.
        let count = unsafe {
            libc::send(
                peer,
                data[offset..].as_ptr().cast(),
                data.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        if count > 0 {
            offset += count as usize;
        } else if count == 0 || !matches!(error("child-send").errno, libc::EINTR | libc::EAGAIN) {
            return false;
        }
        if offset == data.len() {
            return true;
        }
        child_pause();
    }
    false
}

fn child_park(deadline: u64) -> ! {
    for _ in 0..kernel::MAX_OPERATIONS {
        if clock().map_or(true, |now| now >= deadline) {
            child_exit(124);
        }
        child_pause();
    }
    child_exit(124)
}

fn child_clone() -> (libc::c_long, i32) {
    let mut pidfd = -1;
    // SAFETY: clone_args is an integer-only UAPI structure. Zero fields prohibit
    // shared VM/files, namespace changes and explicit placement for inherited B.
    let mut args: libc::clone_args = unsafe { std::mem::zeroed() };
    args.flags = 0x1000; // CLONE_PIDFD, no CLONE_INTO_CGROUP: inherit S's membership.
    args.pidfd = (&mut pidfd as *mut i32) as u64;
    args.exit_signal = libc::SIGCHLD as u64;
    // SAFETY: single-threaded fixed fork child, exact ABI and live output slot.
    let result = unsafe { libc::syscall(libc::SYS_clone3, &args, size_of::<libc::clone_args>()) };
    // An error's dirty output slot is not an owned descriptor.
    (result, pidfd)
}

fn child_read(raw: RawFd, output: &mut [u8], socket: bool, deadline: u64) -> bool {
    let mut offset = 0;
    for _ in 0..kernel::MAX_OPERATIONS {
        if clock().map_or(true, |now| now >= deadline) {
            return false;
        }
        // SAFETY: live socket/pipe and remaining writable slice. Both are nonblocking.
        let count = unsafe {
            if socket {
                libc::recv(
                    raw,
                    output[offset..].as_mut_ptr().cast(),
                    output.len() - offset,
                    0,
                )
            } else {
                libc::read(
                    raw,
                    output[offset..].as_mut_ptr().cast(),
                    output.len() - offset,
                )
            }
        };
        if count > 0 {
            offset += count as usize;
        } else if count == 0 || !matches!(error("child-read").errno, libc::EINTR | libc::EAGAIN) {
            return false;
        }
        if offset == output.len() {
            return true;
        }
        child_pause();
    }
    false
}

fn child_dead(pidfd: RawFd, deadline: u64) -> bool {
    for _ in 0..kernel::MAX_OPERATIONS {
        if clock().map_or(true, |now| now >= deadline) {
            return false;
        }
        let mut p = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: live owned pidfd and one writable pollfd, finite timeout.
        let result = unsafe { libc::poll(&mut p, 1, 2) };
        if result > 0 {
            return p.revents == libc::POLLIN;
        }
        if result < 0 && error("child-poll").errno != libc::EINTR {
            return false;
        }
    }
    false
}

fn child_rights(
    peer: RawFd,
    pidfd: RawFd,
    bytes: &[u8; kernel::WORKER_RECORD],
    deadline: u64,
) -> bool {
    let mut progress = kernel::RightsProgress::default();
    let mut rights = Rights::empty();
    rights.header.cmsg_len = (size_of::<libc::cmsghdr>() + size_of::<i32>()) as _;
    rights.header.cmsg_level = libc::SOL_SOCKET;
    rights.header.cmsg_type = libc::SCM_RIGHTS;
    rights.descriptors[0] = pidfd;
    for _ in 0..kernel::MAX_OPERATIONS {
        if clock().map_or(true, |now| now >= deadline) {
            return false;
        }
        let mut vector = libc::iovec {
            iov_base: bytes[progress.offset..].as_ptr().cast_mut().cast(),
            iov_len: bytes.len() - progress.offset,
        };
        // SAFETY: plain C message aggregate; active pointers are set below.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut vector;
        header.msg_iovlen = 1;
        if progress.send_rights() {
            header.msg_control = (&mut rights as *mut Rights).cast();
            header.msg_controllen = size_of::<Rights>() as _;
        }
        // SAFETY: all buffers stay valid; descriptor is retained; SIGPIPE is suppressed.
        let count = unsafe { libc::sendmsg(peer, &header, libc::MSG_NOSIGNAL) };
        if count > 0 {
            // The first positive send transferred the rights, even if its data
            // was partial. Every following send carries only remaining bytes.
            if progress.advance(count as usize).is_err() {
                return false;
            }
            if progress.offset == bytes.len() {
                return true;
            }
        } else if count == 0 || !matches!(error("child-sendmsg").errno, libc::EINTR | libc::EAGAIN)
        {
            return false;
        }
        child_pause();
    }
    false
}

fn child_worker(peer: RawFd, epoch: u64, deadline: u64, case: Case) -> ! {
    let mut pipe = [-1; 2];
    let mut work = [-1; 2];
    if case.bounds().is_some() {
        // SAFETY: writable pair output, fixed private nonblocking stream.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                work.as_mut_ptr(),
            )
        } != 0
        {
            child_exit(125);
        }
    }
    if case == Case::DoubleFork {
        // SAFETY: writable pair output; private nonblocking CLOEXEC pipe.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            child_exit(125);
        }
    }
    let (pid, pidfd) = child_clone();
    if pid < 0 {
        child_exit(125);
    }
    if pid == 0 {
        // SAFETY: B closes its inherited copy of S's sole M channel.
        if unsafe { libc::close(peer) } != 0 {
            child_exit(125);
        }
        if let Some(kind) = case.bounds() {
            close_child_fd(work[0]);
            bounds_child(work[1], epoch, deadline, kind);
        }
        if case == Case::DoubleFork {
            // SAFETY: B owns its inherited read end; it writes only the other end.
            if unsafe { libc::close(pipe[0]) } != 0 {
                child_exit(125);
            }
            // SAFETY: fixed non-group-leader B creates only its own session.
            if unsafe { libc::setsid() } < 0 {
                child_exit(125);
            }
            let (descendant, descendant_fd) = child_clone();
            if descendant < 0 {
                child_exit(125);
            }
            if descendant == 0 {
                // SAFETY: C drops its only inherited channel and performs no exec.
                if unsafe { libc::close(pipe[1]) } != 0 {
                    child_exit(125);
                }
                child_park(deadline);
            }
            if descendant > i32::MAX as i64 || descendant_fd < 0 {
                child_exit(125);
            }
            // SAFETY: successful clone installed this descriptor only in B.
            if unsafe { libc::close(descendant_fd) } != 0 {
                child_exit(125);
            }
            let bytes = (descendant as u32).to_le_bytes();
            // Four bytes fit atomically in an empty private nonblocking pipe.
            // SAFETY: owned write end and initialized fixed bytes.
            if unsafe { libc::write(pipe[1], bytes.as_ptr().cast(), bytes.len()) }
                != bytes.len() as isize
            {
                child_exit(125);
            }
            // SAFETY: B consumes this last owned channel exactly once.
            if unsafe { libc::close(pipe[1]) } != 0 {
                child_exit(125);
            }
            child_exit(0);
        }
        if case == Case::Zombie {
            child_exit(0);
        }
        child_park(deadline);
    }
    if pid > i32::MAX as i64 || pidfd < 0 {
        child_exit(125);
    }
    if case.bounds().is_some() {
        close_child_fd(work[1]);
        let mut ready = [0; 9];
        if !child_read(work[0], &mut ready, true, deadline) || ready != kernel::message(1, epoch) {
            child_exit(125);
        }
    }
    let mut descendant = 0;
    if case == Case::DoubleFork {
        // SAFETY: S drops its own write end so a failed B cannot conceal EOF.
        if unsafe { libc::close(pipe[1]) } != 0 {
            child_exit(125);
        }
        let mut bytes = [0; 4];
        if !child_read(pipe[0], &mut bytes, false, deadline) {
            child_exit(125);
        }
        descendant = u32::from_le_bytes(bytes);
        // SAFETY: S consumes its private read end after the bounded fixed record.
        if unsafe { libc::close(pipe[0]) } != 0 {
            child_exit(125);
        }
    }
    if case.shape() != 0 && !child_dead(pidfd, deadline) {
        child_exit(125);
    }
    let born = kernel::worker_message(4, epoch, pid as u32, descendant, case.shape());
    if !child_send(peer, &born, deadline) {
        child_exit(125);
    }
    let mut command = [0; 9];
    if !child_read(peer, &mut command, true, deadline) || command != kernel::message(5, epoch) {
        child_exit(125);
    }
    let delivery = kernel::worker_message(6, epoch, pid as u32, descendant, case.shape());
    if !child_rights(peer, pidfd, &delivery, deadline) {
        child_exit(125);
    }
    if let Some(kind) = case.bounds() {
        bounds_supervisor(peer, work[0], (pid as u32, pidfd), epoch, deadline, kind);
    }
    // SAFETY: S closes its clone-created pidfd copy, but NEVER reaps B. The
    // unreaped child stays numerically pinned through M's placement and abort.
    if unsafe { libc::close(pidfd) } != 0 {
        child_exit(125);
    }
    child_park(deadline)
}

fn close_child_fd(raw: RawFd) {
    // SAFETY: the fixed child branch passes one uniquely owned descriptor once.
    if unsafe { libc::close(raw) } != 0 {
        child_exit(125);
    }
}

fn bounds_child(work: RawFd, epoch: u64, deadline: u64, case: BoundCase) -> ! {
    if !child_send(work, &kernel::message(1, epoch), deadline) {
        child_exit(125);
    }
    let mut command = [0; 9];
    if !child_read(work, &mut command, true, deadline) || command != kernel::message(3, epoch) {
        child_exit(125);
    }
    if case == BoundCase::WorkerStall {
        if !child_send(work, &kernel::message(11, epoch), deadline) {
            child_exit(125);
        }
        child_park(deadline);
    }
    close_child_fd(work);
    child_exit(0)
}

fn child_success(pid: u32, pidfd: RawFd, deadline: u64) -> bool {
    if !child_dead(pidfd, deadline) {
        return false;
    }
    // SAFETY: plain C output storage for the successful wait query.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: S is B's parent, holds its pidfd, and observes without consuming.
    if unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return false;
    }
    // SAFETY: successful WEXITED query initialized these SIGCHLD fields.
    unsafe {
        info.si_pid() == pid as i32 && info.si_code == libc::CLD_EXITED && info.si_status() == 0
    }
}

fn bounds_supervisor(
    peer: RawFd,
    work: RawFd,
    child: (u32, RawFd),
    epoch: u64,
    deadline: u64,
    case: BoundCase,
) -> ! {
    let mut command = [0; 9];
    if !child_read(peer, &mut command, true, deadline) || command != kernel::message(7, epoch) {
        child_exit(125);
    }
    if case == BoundCase::WorkerStall
        && (!child_send(work, &kernel::message(3, epoch), deadline)
            || !child_read(work, &mut command, true, deadline)
            || command != kernel::message(11, epoch))
    {
        child_exit(125);
    }
    if !child_send(peer, &kernel::message(9, epoch), deadline)
        || !child_read(peer, &mut command, true, deadline)
        || command != kernel::message(10, epoch)
    {
        child_exit(125);
    }
    if matches!(case, BoundCase::SupervisorStall | BoundCase::WorkerStall) {
        child_park(deadline);
    }
    if !child_send(work, &kernel::message(3, epoch), deadline)
        || !child_success(child.0, child.1, deadline)
    {
        child_exit(125);
    }
    close_child_fd(work);
    close_child_fd(child.1); // No consuming wait: M adopts and reaps B during cleanup.
    if matches!(case, BoundCase::ExtensionFlood | BoundCase::OutputFlood) {
        let extension = kernel::message(12, epoch);
        let output = [0xff; 64];
        let bytes = if case == BoundCase::ExtensionFlood {
            &extension[..]
        } else {
            &output[..]
        };
        let mut sent = 0;
        for _ in 0..kernel::MAX_OPERATIONS {
            if clock().map_or(true, |now| now >= deadline) {
                child_exit(124);
            }
            if sent + bytes.len() > bounds::OUTPUT_LIMIT {
                break;
            }
            // SAFETY: live private stream and fixed initialized bytes; suppress SIGPIPE.
            let count =
                unsafe { libc::send(peer, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
            if count > 0 {
                sent += count as usize;
            } else if count == 0 || !matches!(error("flood-send").errno, libc::EINTR | libc::EAGAIN)
            {
                child_exit(125);
            }
            child_pause();
        }
        child_park(deadline);
    }
    let result_epoch = if case == BoundCase::Replay {
        if epoch == u64::MAX {
            epoch - 1
        } else {
            epoch + 1
        }
    } else {
        epoch
    };
    if !child_send(peer, &kernel::message(2, result_epoch), deadline) {
        child_exit(125);
    }
    child_park(deadline)
}

fn child_pause() {
    // SAFETY: finite sleep with no fd array; child never executes Rust destructors.
    unsafe {
        libc::poll(std::ptr::null_mut(), 0, 2);
    }
}

fn child_exit(status: i32) -> ! {
    // SAFETY: fork child must terminate without unwinding inherited owners.
    unsafe { libc::_exit(status) }
}

/// Compile-only native root; no normal example or controller invokes it.
///
/// # Safety
/// The caller must be the separately reviewed, surviving, single-threaded M,
/// outside J, with no unrelated children, no custom signal handlers and no
/// concurrent fd-table users. Parent is an exclusively controlled cgroup2
/// directory with delegated controllers, evidence an owned nonblocking E
/// channel outside J. No other actor may rename/move/attach within this subtree.
/// Inputs have distinct valid ownership. The caller must retain a returned
/// quarantine owner. No descriptors other than the inputs and standard streams
/// may be inherited from the boot integration. Standard streams close in S.
/// Arrange independent E/H rejection and VM recovery.
/// The procfs instance must represent M's initial PID namespace. No actor other
/// than this fixture may signal its children; OOM events invalidate a cut case.
/// reserved_at and total_deadline come from E's reservation in the same
/// CLOCK_BOOTTIME domain. The returned reservation also bounds finalization;
/// missing/expired metadata never permits a replacement budget.
pub unsafe fn run(input: Input) -> Completion<OwnedFd> {
    let Input {
        parent,
        evidence,
        epoch,
        case,
        reserved_at,
        total_deadline,
    } = input;
    let mut native = Native {
        parent: Some(parent),
        evidence: Some(evidence),
        name: kernel::job_name(epoch),
        job: None,
        leaf: None,
        worker: None,
        case,
        work_cap: None,
    };
    kernel::run_reserved(&mut native, epoch, case, reserved_at, total_deadline)
}
