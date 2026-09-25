// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Process plumbing for the waiter: the fork that lets the PAM session line
//! return while the waiter goes on, the waiter's descriptors and signals, and
//! its journal lines.

use std::ffi::CString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::waiter::{Event, Level, Status};

/// How long the parent waits for the waiter's first report. It leaves after
/// that whatever the waiter is doing, so the session line returns within
/// about a second.
pub(crate) const PARENT_REPORT_BUDGET: Duration = Duration::from_secs(1);

/// SIGALRM ends the waiter this long after its bound, whatever it is doing.
pub(crate) const ALARM_MARGIN: Duration = Duration::from_secs(30);

/// Where the status pipe sits in the waiter.
const STATUS_FD: libc::c_int = 3;

/// Set by SIGTERM, SIGHUP and SIGALRM. The waiter checks it at least every
/// [`crate::waiter::WAIT_SLICE`] and then returns normally, so the token is
/// wiped by its buffer's drop rather than left in memory by a default
/// signal death.
static STOP: AtomicBool = AtomicBool::new(false);

pub(crate) fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

extern "C" fn request_stop(_signal: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Route SIGTERM, SIGHUP and SIGALRM to the stop flag and arm SIGALRM as a
/// hard cap at `bound` plus [`ALARM_MARGIN`].
pub(crate) fn arm_stop(bound: Duration) -> Result<(), String> {
    for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGALRM] {
        // SAFETY: an all-zero `sigaction` is a valid value (no flags, empty
        // mask) that the fields below complete. The handler only stores to
        // an atomic, which is async-signal-safe.
        let rc = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = request_stop as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(format!(
                "installing the stop handler for signal {signal}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    let cap = u32::try_from((bound + ALARM_MARGIN).as_secs()).unwrap_or(u32::MAX);
    // SAFETY: `alarm` only schedules SIGALRM for this process, which the
    // handler above now catches.
    unsafe { libc::alarm(cap) };
    Ok(())
}

/// The waiter's end of the status pipe. Only the first report is written:
/// the parent reads one byte and leaves.
pub(crate) struct StatusPipe(Option<File>);

impl StatusPipe {
    pub(crate) fn report(&mut self, status: Status) {
        if let Some(mut pipe) = self.0.take() {
            // The parent may already be gone; SIGPIPE is ignored (the Rust
            // runtime sets that), so this is an ignorable EPIPE.
            let _ = pipe.write_all(&[status_byte(status)]);
        }
    }
}

fn status_byte(status: Status) -> u8 {
    match status {
        Status::Waiting => b'W',
        Status::Delivered => b'D',
        Status::Failed => b'F',
    }
}

/// What the parent learned from the waiter within [`PARENT_REPORT_BUDGET`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Delivered,
    Waiting,
    Failed,
    /// No report within the budget: the waiter is still connecting.
    Silent,
    /// The waiter closed the pipe without a report: it died.
    Vanished,
}

impl Verdict {
    /// The helper's exit status in PAM mode: 0 means delivered, or handed to
    /// the waiter.
    pub(crate) fn exit_code(self) -> u8 {
        match self {
            Verdict::Delivered | Verdict::Waiting | Verdict::Silent => 0,
            Verdict::Failed | Verdict::Vanished => 1,
        }
    }

    fn from_byte(byte: u8) -> Self {
        match byte {
            b'D' => Verdict::Delivered,
            b'W' => Verdict::Waiting,
            _ => Verdict::Failed,
        }
    }
}

/// Which side of the fork this is.
pub(crate) enum Forked {
    /// The parent, with the waiter's first report and its pid.
    Parent {
        verdict: Verdict,
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "the parent leaves at once; a test reaps it")
        )]
        waiter: libc::pid_t,
    },
    /// The detached waiter, with its end of the status pipe.
    Child(StatusPipe),
}

/// Fork the waiter.
///
/// Call it single-threaded and before any bus connection exists: the child
/// continues in ordinary Rust code, so no other thread may hold a lock at the
/// fork. In the child, the process has its own session, `/` as its working
/// directory, `/dev/null` as stdio, the status pipe at descriptor 3 and no
/// other descriptor, so nothing the login process leaked without
/// close-on-exec lives on in the waiter.
pub(crate) fn fork_waiter() -> Result<Forked, String> {
    let (read, write) = status_pipe()?;
    // SAFETY: the caller keeps the process single-threaded here (see the doc
    // above), so the child may go on running arbitrary code.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(read);
        return detach_child(write).map(Forked::Child);
    }
    drop(write);
    Ok(Forked::Parent {
        verdict: await_first_report(read, PARENT_REPORT_BUDGET),
        waiter: pid,
    })
}

fn status_pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` writes two descriptors into the array it is given.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!("status pipe: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: both descriptors were just created and are owned by nothing
    // else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn detach_child(write: OwnedFd) -> Result<StatusPipe, String> {
    let os = |what: &str| format!("{what}: {}", std::io::Error::last_os_error());
    // Park the pipe above the standard descriptors first, so moving
    // /dev/null onto 0 to 2 cannot close it.
    // SAFETY: F_DUPFD_CLOEXEC duplicates a descriptor this function owns.
    let parked = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if parked < 0 {
        return Err(os("parking the status pipe"));
    }
    drop(write);
    // SAFETY: setsid takes no arguments; a forked child is never a process
    // group leader, so it succeeds.
    if unsafe { libc::setsid() } < 0 {
        return Err(os("setsid"));
    }
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| format!("/dev/null: {e}"))?
        .into_raw_fd();
    for fd in 0..=2 {
        // SAFETY: dup2 onto a standard descriptor of this process.
        if unsafe { libc::dup2(null, fd) } < 0 {
            return Err(os("stdio to /dev/null"));
        }
    }
    if null > 2 {
        // SAFETY: `null` is this function's own descriptor, now duplicated.
        unsafe { libc::close(null) };
    }
    // SAFETY: dup2 of the parked pipe onto the status slot, then the parked
    // copy is closed; `parked` is at least 10, so never the slot itself.
    unsafe {
        if libc::dup2(parked, STATUS_FD) < 0 {
            return Err(os("moving the status pipe"));
        }
        libc::close(parked);
    }
    close_from(STATUS_FD + 1);
    // SAFETY: descriptor 3 now holds the status pipe, owned by nothing else.
    Ok(StatusPipe(Some(unsafe { File::from_raw_fd(STATUS_FD) })))
}

/// Close every descriptor from `first` up.
fn close_from(first: libc::c_int) {
    let first = libc::c_uint::try_from(first).unwrap_or(0);
    // SAFETY: close_range only closes this process's own descriptors; the
    // syscall form also works where libc has no wrapper.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first,
            libc::c_uint::MAX,
            0 as libc::c_uint,
        )
    };
    if rc == 0 {
        return;
    }
    // Kernels before 5.9 have no close_range: close what /proc lists.
    let open: Vec<libc::c_int> = std::fs::read_dir("/proc/self/fd")
        .map(|dir| {
            dir.filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
                .filter(|fd: &libc::c_int| libc::c_uint::try_from(*fd).is_ok_and(|fd| fd >= first))
                .collect()
        })
        .unwrap_or_default();
    for fd in open {
        // SAFETY: closing a descriptor number; the directory handle listed
        // among them is already closed, which makes that one call EBADF.
        unsafe { libc::close(fd) };
    }
}

/// The waiter's first report, or [`Verdict::Silent`] after `budget`.
fn await_first_report(read: OwnedFd, budget: Duration) -> Verdict {
    let deadline = Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Verdict::Silent;
        }
        let mut pfd = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        // SAFETY: one pollfd for a descriptor this function owns.
        let ready = unsafe { libc::poll(&mut pfd, 1, millis) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Verdict::Silent;
        }
        if ready == 0 {
            // The millisecond timeout rounds down, so check the deadline
            // again rather than trusting one poll.
            continue;
        }
        let mut byte = 0u8;
        // SAFETY: reads at most one byte into a local.
        let n = unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
        match n {
            1 => return Verdict::from_byte(byte),
            0 => return Verdict::Vanished,
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
            _ => return Verdict::Silent,
        }
    }
}

/// Open the journal connection: identifier `irlume-gkr-unlock`, the pid on
/// every line, facility authpriv.
pub(crate) fn open_journal() {
    // SAFETY: the identifier is a static C string; openlog keeps the pointer.
    unsafe {
        libc::openlog(
            c"irlume-gkr-unlock".as_ptr(),
            libc::LOG_PID,
            libc::LOG_AUTHPRIV,
        )
    };
}

/// Write one catalog line to the journal. This is the program's only syslog
/// call, and it takes an [`Event`], which holds numbers only.
pub(crate) fn journal(event: Event) {
    let priority = match event.level() {
        Level::Info => libc::LOG_INFO,
        Level::Notice => libc::LOG_NOTICE,
        Level::Warning => libc::LOG_WARNING,
    };
    let Ok(line) = CString::new(event.text()) else {
        return;
    };
    // SAFETY: a "%s" format with exactly one NUL-terminated string argument.
    unsafe { libc::syslog(libc::LOG_AUTHPRIV | priority, c"%s".as_ptr(), line.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_report_decides_the_parents_exit() {
        for (status, verdict, code) in [
            (Status::Waiting, Verdict::Waiting, 0),
            (Status::Delivered, Verdict::Delivered, 0),
            (Status::Failed, Verdict::Failed, 1),
        ] {
            assert_eq!(Verdict::from_byte(status_byte(status)), verdict);
            assert_eq!(verdict.exit_code(), code);
        }
        assert_eq!(Verdict::Silent.exit_code(), 0, "still connecting");
        assert_eq!(Verdict::Vanished.exit_code(), 1, "died without a report");
        assert_eq!(Verdict::from_byte(b'?'), Verdict::Failed);
    }

    #[test]
    fn the_parent_reads_the_first_byte_or_gives_up() {
        let (read, write) = status_pipe().unwrap();
        let mut pipe = StatusPipe(Some(File::from(write)));
        pipe.report(Status::Waiting);
        pipe.report(Status::Delivered);
        assert_eq!(
            await_first_report(read, Duration::from_millis(500)),
            Verdict::Waiting
        );

        let (read, write) = status_pipe().unwrap();
        let started = Instant::now();
        assert_eq!(
            await_first_report(read, Duration::from_millis(200)),
            Verdict::Silent
        );
        assert!(started.elapsed() >= Duration::from_millis(200));
        drop(write);

        let (read, write) = status_pipe().unwrap();
        drop(write);
        assert_eq!(
            await_first_report(read, Duration::from_millis(500)),
            Verdict::Vanished
        );
    }

    /// The program writes to syslog in exactly one place, and that place
    /// formats an [`Event`]. The needle is split so this test does not match
    /// itself.
    #[test]
    fn the_journal_is_written_in_one_place_from_an_event() {
        let needle = ["libc::", "syslog("].concat();
        let mut calls = 0;
        for src in [
            include_str!("main.rs"),
            include_str!("waiter.rs"),
            include_str!("bus.rs"),
            include_str!("detach.rs"),
        ] {
            calls += src.matches(&needle).count();
        }
        assert_eq!(calls, 1);
        let src = include_str!("detach.rs");
        let call = src.find(&needle).unwrap();
        let function = src[..call].rfind("pub(crate) fn ").unwrap();
        assert!(
            src[function..].starts_with("pub(crate) fn journal(event: Event)"),
            "the syslog call sits in `journal(event: Event)`"
        );
    }
}
