// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded output collection for short observation helpers.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_OUTPUT: usize = 64 * 1024;
const MAX_CHILDREN: usize = 32;
const MAX_INPUT: usize = 4096;
static BUDGET: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

/// Collect a short helper's output within one observation deadline.
///
/// Standard input is closed and combined output is limited to 64 KiB. On any
/// failure the direct child is killed and reaped by one shared polling reaper
/// if the kernel has not yet completed its exit. At most 32 children, including
/// pending reaps, are admitted per process. No unbounded wait occurs on the
/// caller. Callers retain control of executable, arguments and environment.
///
/// # Errors
/// Returns spawn/I/O errors, `TimedOut` on expiry, or `InvalidData` when output
/// exceeds the limit, or `WouldBlock` when the child budget is exhausted.
/// A nonzero helper exit is returned in `Output::status`.
pub fn output_until(command: &mut Command, deadline: Instant) -> io::Result<Output> {
    output_with_budget(
        command,
        deadline,
        Arc::clone(BUDGET.get_or_init(Default::default)),
    )
}

/// Collect helper output while supplying at most 4096 bytes through private stdin.
/// Input writes and output reads share one deadline; stdin closes after delivery.
///
/// # Errors
/// Returns the observation errors of [`output_until`], stdin write errors, or
/// `InvalidInput` if the request exceeds 4096 bytes.
pub fn output_with_input_until(
    command: &mut Command,
    input: &[u8],
    deadline: Instant,
) -> io::Result<Output> {
    output_with_budget_and_input(
        command,
        input,
        deadline,
        Arc::clone(BUDGET.get_or_init(Default::default)),
        None,
    )
}

fn output_with_budget(
    command: &mut Command,
    deadline: Instant,
    budget: Arc<AtomicUsize>,
) -> io::Result<Output> {
    output_with_budget_and_input(command, &[], deadline, budget, None)
}

/// Observe a short helper with an explicitly supplied stdin descriptor.
///
/// The caller owns the descriptor's input protocol and must arrange EOF or a
/// bounded exchange. Child observation/reaping and output limits are unchanged.
///
/// # Errors
/// Returns the spawn, output, resource-budget and deadline errors described by
/// [`output_until`]. No input data is placed in command-line arguments.
pub fn output_with_stdin_until(
    command: &mut Command,
    stdin: Stdio,
    deadline: Instant,
) -> io::Result<Output> {
    output_with_budget_and_input(
        command,
        &[],
        deadline,
        Arc::clone(BUDGET.get_or_init(Default::default)),
        Some(stdin),
    )
}

fn output_with_budget_and_input(
    command: &mut Command,
    mut input: &[u8],
    deadline: Instant,
    budget: Arc<AtomicUsize>,
    supplied_stdin: Option<Stdio>,
) -> io::Result<Output> {
    if input.len() > MAX_INPUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "helper input exceeded limit",
        ));
    }
    remaining(deadline)?;
    let permit = ChildPermit::acquire(budget)?;
    let reaper = Reaper::global()?;
    remaining(deadline)?;
    let child = command
        .stdin(supplied_stdin.unwrap_or_else(|| {
            if input.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            }
        }))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut owner = ObservedChild {
        child: Some(child),
        permit: Some(permit),
        reaper,
    };
    let child = owner
        .child
        .as_mut()
        .ok_or_else(|| io::Error::other("missing helper child"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing stderr pipe"))?;
    let mut stdin = child.stdin.take();
    if let Some(pipe) = &stdin {
        nonblocking(pipe)?;
    }
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    let mut status = None;
    loop {
        remaining(deadline)?;
        let mut progress = false;
        if let Some(pipe) = &mut stdin {
            match pipe.write(input) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "helper stdin closed",
                    ))
                }
                Ok(n) => {
                    input = &input[n..];
                    progress = true;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
            if input.is_empty() {
                stdin.take();
            }
        }
        if !out_eof {
            progress |= collect(&mut stdout, &mut out, err.len(), &mut out_eof)?;
        }
        if !err_eof {
            progress |= collect(&mut stderr, &mut err, out.len(), &mut err_eof)?;
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        remaining(deadline)?;
        if let Some(status) = status {
            if out_eof && err_eof {
                owner.child.take(); // try_wait has reaped this child.
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        if !progress {
            std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(5)));
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "helper observation deadline expired",
        ))
    } else {
        Ok(remaining)
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fd belongs to the live pipe; these calls only read/update its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same live descriptor, adding O_NONBLOCK preserves all other flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn collect(
    pipe: &mut impl Read,
    bytes: &mut Vec<u8>,
    other_len: usize,
    eof: &mut bool,
) -> io::Result<bool> {
    let mut chunk = [0u8; 4096];
    match pipe.read(&mut chunk) {
        Ok(0) => {
            *eof = true;
            Ok(false)
        }
        Ok(n) => {
            if bytes.len() + other_len + n > MAX_OUTPUT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "helper output exceeded limit",
                ));
            }
            bytes.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

struct ChildPermit(Arc<AtomicUsize>);

impl ChildPermit {
    fn acquire(budget: Arc<AtomicUsize>) -> io::Result<Self> {
        budget
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_CHILDREN).then_some(n + 1)
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "helper child budget exhausted")
            })?;
        Ok(Self(budget))
    }
}

impl Drop for ChildPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Default)]
struct Reaper {
    pending: Mutex<Vec<(Child, ChildPermit)>>,
    wake: Condvar,
}

impl Reaper {
    fn global() -> io::Result<Arc<Self>> {
        static REAPER: Mutex<Option<Arc<Reaper>>> = Mutex::new(None);
        Self::initialize(&REAPER, |worker| {
            std::thread::Builder::new()
                .name("irlume-helper-reaper".into())
                .spawn(move || worker.run())
                .map(|_| ())
        })
    }

    fn initialize(
        slot: &Mutex<Option<Arc<Reaper>>>,
        spawn: impl FnOnce(Arc<Reaper>) -> io::Result<()>,
    ) -> io::Result<Arc<Self>> {
        let mut initialized = slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(reaper) = &*initialized {
            return Ok(Arc::clone(reaper));
        }
        let reaper = Arc::new(Self::default());
        spawn(Arc::clone(&reaper))?;
        *initialized = Some(Arc::clone(&reaper));
        Ok(reaper)
    }

    fn run(&self) {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            while pending.is_empty() {
                pending = self.wake.wait(pending).unwrap_or_else(|e| e.into_inner());
            }
            // WNOHANG only. A child stuck in the kernel retains its permit;
            // later callers cannot accumulate more children or waiter threads.
            pending.retain_mut(|(child, _)| !matches!(child.try_wait(), Ok(Some(_))));
            pending = self
                .wake
                .wait_timeout(pending, Duration::from_millis(10))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

struct ObservedChild {
    child: Option<Child>,
    permit: Option<ChildPermit>,
    reaper: Arc<Reaper>,
}

impl Drop for ObservedChild {
    fn drop(&mut self) {
        if let (Some(mut child), Some(permit)) = (self.child.take(), self.permit.take()) {
            let _ = child.kill();
            if !matches!(child.try_wait(), Ok(Some(_))) {
                self.reaper
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((child, permit));
                self.reaper.wake.notify_one();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn supplied_stdin_socket_remains_bidirectional() {
        use std::net::Shutdown;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        parent.write_all(b"private query\n").unwrap();
        parent.shutdown(Shutdown::Write).unwrap();
        let child: OwnedFd = child.into();
        let output = output_with_stdin_until(
            Command::new("/bin/sh").args(["-c", "read -r request && printf '%s' \"$request\" >&0"]),
            Stdio::from(child),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
        let mut reply = String::new();
        parent.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "private query");
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn reaper_creation_retries_after_transient_thread_failure() {
        let slot = Mutex::new(None);
        let calls = std::cell::Cell::new(0);
        let first = Reaper::initialize(&slot, |_| {
            calls.set(calls.get() + 1);
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "synthetic resource pressure",
            ))
        });
        assert!(first.is_err());
        let second = Reaper::initialize(&slot, |_| {
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert!(
            second.is_ok(),
            "a transient failure must not disable future helpers"
        );
        assert_eq!(calls.get(), 2);
        assert!(Reaper::initialize(&slot, |_| panic!("already started")).is_ok());
    }

    #[test]
    fn private_stdin_rejects_oversize_input_before_spawn_and_bounds_stalled_helpers() {
        let error = output_with_input_until(
            &mut Command::new("/nonexistent/no-input-capacity"),
            &vec![b'x'; MAX_INPUT + 1],
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let started = Instant::now();
        let error = output_with_input_until(
            Command::new("/bin/sleep").arg("20"),
            &vec![b'x'; MAX_INPUT],
            started + Duration::from_millis(100),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn private_stdin_request_reaches_the_helper_without_argument_data() {
        let request = b"synthetic-private-account-query";
        let mut command = Command::new("/bin/cat");
        let output = output_with_input_until(
            &mut command,
            request,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, request);
        assert!(command.get_args().next().is_none());
    }

    #[test]
    fn exhausted_child_budget_refuses_before_spawning() {
        let budget = Arc::new(AtomicUsize::new(MAX_CHILDREN));
        let error = output_with_budget(
            &mut Command::new("/nonexistent/no-capacity"),
            Instant::now() + Duration::from_secs(1),
            Arc::clone(&budget),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(budget.load(Ordering::Acquire), MAX_CHILDREN);
    }

    #[test]
    fn child_capacity_returns_after_success_spawn_failure_and_timeout_reap() {
        let budget = Arc::new(AtomicUsize::new(0));
        output_with_budget(
            &mut Command::new("/bin/true"),
            Instant::now() + Duration::from_secs(2),
            Arc::clone(&budget),
        )
        .unwrap();
        assert_eq!(budget.load(Ordering::Acquire), 0);
        assert!(output_with_budget(
            &mut Command::new("/nonexistent/helper"),
            Instant::now() + Duration::from_secs(2),
            Arc::clone(&budget),
        )
        .is_err());
        assert_eq!(budget.load(Ordering::Acquire), 0);
        for _ in 0..3 {
            let error = output_with_budget(
                Command::new("/bin/sleep").arg("20"),
                Instant::now() + Duration::from_millis(100),
                Arc::clone(&budget),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
        let until = Instant::now() + Duration::from_secs(2);
        while budget.load(Ordering::Acquire) != 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            budget.load(Ordering::Acquire),
            0,
            "the shared reaper returns every permit"
        );
    }

    #[test]
    fn collects_both_streams_and_exit_status() {
        let output = output_until(
            Command::new("/bin/sh").args(["-c", "printf yes; printf no >&2; exit 7"]),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(output.stdout, b"yes");
        assert_eq!(output.stderr, b"no");
        assert_eq!(output.status.code(), Some(7));
    }

    #[test]
    fn stalled_helper_is_bounded_and_eventually_reaped() {
        let pid_file =
            std::env::temp_dir().join(format!("irlume-observed-child-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&pid_file);
        let start = Instant::now();
        let error = output_until(
            Command::new("/bin/sh")
                .args(["-c", "echo $$ > \"$1\"; exec sleep 20", "sh"])
                .arg(&pid_file),
            start + Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
        let pid: u32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::fs::remove_file(pid_file).unwrap();
        let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
        let reap_deadline = Instant::now() + Duration::from_secs(2);
        while proc.exists() && Instant::now() < reap_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!proc.exists(), "timed-out child must exit and be reaped");
    }

    #[test]
    fn excess_output_is_rejected() {
        let error = output_until(
            Command::new("/bin/sh").args(["-c", "exec head -c 70000 /dev/zero"]),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn expired_deadline_does_not_spawn() {
        // A spawn would return NotFound; the deadline must win first.
        let error = output_until(
            &mut Command::new("/nonexistent/observation-helper"),
            Instant::now(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
}
