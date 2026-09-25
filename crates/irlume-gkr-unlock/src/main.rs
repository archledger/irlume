// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Unlock a user's GNOME login keyring with their sealed keyring token (#250).
//!
//! On a token-armed account the login keyring is keyed to a random token, not
//! the login password, so after a face or fingerprint login (and after a typed
//! password login, whose password no longer opens it) something must hand the
//! token to `gnome-keyring-daemon`. That channel is the daemon's control
//! socket, `$XDG_RUNTIME_DIR/keyring/control`, with the `UNLOCK` operation:
//! the exact channel and operation `pam_gnome_keyring` itself uses.
//!
//! This exists as a separate program for the same reason `irlume-kwallet-init`
//! does: `pam_irlume` is loaded into sshd, login and every greeter, and it has
//! no privilege dropping. The control socket authenticates the peer's uid
//! (`gkr-pam-client.c` does its own seteuid dance for the same reason), so the
//! connection must be made AS the target user, and becoming the user
//! permanently in a short-lived helper keeps the module's blast radius
//! unchanged.
//!
//! The daemon may not be able to take the token yet. Where
//! `pam_gnome_keyring auto_start` starts gnome-keyring with `--login` and no
//! socket unit exists (Fedora 43 and 44), the daemon refuses every unlock
//! until the session's first Secret Service client initializes it, seconds
//! after the PAM session phase returns. So after the permanent drop to the
//! user this program forks a detached waiter, which delivers the token once
//! gnome-keyring is initialized ([`waiter`]), and the parent returns to PAM
//! within about a second.
//!
//! Invoked as `irlume-gkr-unlock [--foreground] [--timeout-secs N] <username>`
//! with the token on **stdin**, never in argv, which is world-readable through
//! `/proc`.
//!
//! - Without `--foreground` (the PAM session line): exit status 0 means the
//!   token was delivered, or handed to the waiter, which logs its outcome to
//!   the journal (`journalctl -t irlume-gkr-unlock`). 1 is a refusal or an
//!   error before the hand-off, printed to stderr, or a waiter that failed
//!   (for example stale) or died within its first second.
//! - With `--foreground` (tests and scripts): the same algorithm without the
//!   fork, logging to stderr and exiting with the outcome: 0 delivered, 1 a
//!   refusal or an error, 3 gave up (the time bound, or a signal), 4 stale (the
//!   login keyring is not keyed to this token), 5 no gnome-keyring in this
//!   session.
//! - `--timeout-secs N` shortens the 120 s bound. Like the other overrides it
//!   is refused when the process is privileged.
//!
//! 2 is a usage error.

mod bus;
mod detach;
mod waiter;

use irlume_common::gkr_wire::{self, Op};
use std::ffi::{CString, OsString};
use std::io::Read;
use std::os::fd::AsFd as _;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use waiter::{BusLost, Expect, Identity, Sent};
use zeroize::Zeroizing;

/// Ceiling on the token read from stdin. The armed token is 64 bytes of hex;
/// the margin tolerates a future longer format without accepting arbitrary
/// stream lengths from a confused caller.
const MAX_TOKEN_LEN: usize = 256;

/// Deadline for each control-socket connect, read and write. The daemon
/// imposes none, and a delivery that finds gnome-keyring already initialized
/// runs inside the PAM session phase, where an unbounded wait is a hung login.
/// Generous enough for a socket-activated daemon's cold start.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str =
    "usage: irlume-gkr-unlock [--foreground] [--timeout-secs N] <username>  (token on stdin)";

/// How the helper runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The PAM session line: fork the waiter and return.
    Pam,
    /// Tests and scripts: wait in this process and exit with the outcome.
    Foreground,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    mode: Mode,
    timeout_secs: Option<u64>,
    user: String,
}

fn main() -> std::process::ExitCode {
    // The session line's moment; delivery times are counted from here.
    let started = Instant::now();
    let args = match parse_args(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(why) => {
            eprintln!("irlume-gkr-unlock: {why}\n{USAGE}");
            return std::process::ExitCode::from(2);
        }
    };
    match run(&args, started) {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e) => {
            eprintln!("irlume-gkr-unlock: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let mut mode = Mode::Pam;
    let mut timeout_secs = None;
    let mut user = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--foreground") => mode = Mode::Foreground,
            Some("--timeout-secs") => {
                let value = args.next().ok_or("--timeout-secs needs a value")?;
                let secs = value
                    .to_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    .filter(|secs| (1..=waiter::WAITER_BOUND.as_secs()).contains(secs))
                    .ok_or_else(|| {
                        format!(
                            "--timeout-secs takes 1 to {}",
                            waiter::WAITER_BOUND.as_secs()
                        )
                    })?;
                timeout_secs = Some(secs);
            }
            Some(flag) if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            _ if user.is_none() => user = Some(arg.to_string_lossy().into_owned()),
            _ => return Err("more than one username".into()),
        }
    }
    Ok(Args {
        mode,
        timeout_secs,
        user: user.ok_or("no username")?,
    })
}

/// The waiter's bound. A shorter one is for the test harness only, so it is
/// refused under privilege, like the other overrides: see [`runtime_dir_for`].
fn waiter_bound(timeout_secs: Option<u64>, privileged: bool) -> Result<Duration, String> {
    match timeout_secs {
        None => Ok(waiter::WAITER_BOUND),
        Some(_) if privileged => {
            Err("--timeout-secs is for tests; refusing it in a privileged process".into())
        }
        Some(secs) => Ok(Duration::from_secs(secs).min(waiter::WAITER_BOUND)),
    }
}

fn run(args: &Args, started: Instant) -> Result<u8, String> {
    let bound = waiter_bound(args.timeout_secs, privileged())?;
    let target = prepare(&args.user)?;
    let plan = waiter::Plan {
        started,
        bound,
        uid: target.uid,
    };
    match args.mode {
        Mode::Foreground => {
            detach::arm_stop(bound)?;
            let mut world = System::new(&target, Sink::Stderr, None);
            Ok(waiter::run(&mut world, &target.token, &plan).exit_code())
        }
        // Single-threaded, and no bus connection exists yet: the fork's
        // precondition.
        Mode::Pam => match detach::fork_waiter()? {
            // The token is wiped when `target` drops, on return.
            detach::Forked::Parent { verdict, .. } => Ok(verdict.exit_code()),
            detach::Forked::Child(status) => {
                // mlock is not inherited across fork.
                irlume_common::memlock::lock_slice(&target.token);
                detach::open_journal();
                detach::arm_stop(bound)?;
                let mut world = System::new(&target, Sink::Journal, Some(status));
                Ok(waiter::run(&mut world, &target.token, &plan).exit_code())
            }
        },
    }
}

/// What the waiter needs, gathered before and across the privilege drop.
struct Target {
    token: Zeroizing<Vec<u8>>,
    uid: libc::uid_t,
    keyring: PathBuf,
    runtime_dir: PathBuf,
}

/// Read the token, find the user's keyring and runtime directory, become the
/// user for good, and harden the process that now holds the token.
fn prepare(user: &str) -> Result<Target, String> {
    // Read the token first, before any privilege change, so a malformed
    // invocation fails without side effects.
    let token = read_token_from_stdin()?;

    let pw = lookup_user(user)?;
    // Refuse when there is no login keyring to unlock.
    //
    // UNLOCK is not read-only: `unlock_or_create_login()` CREATES the login
    // keyring keyed to whatever secret it was handed when none exists
    // (gnome-keyring's `daemon/login/gkd-login.c`). Firing blind after the
    // user deleted their keyring would silently mint a new one whose password
    // is a 64-character random token they have never seen and no GNOME
    // interface can tell them. Unlocking an existing keyring is this program's
    // whole job; creating one is not. The waiter checks again before it sends.
    let keyring = login_keyring_path(&pw)?;
    if !keyring.exists() {
        return Err(format!(
            "{} does not exist; refusing to UNLOCK, which would CREATE a login keyring \
             keyed to the sealed token instead of unlocking one. Run `irlume keyring \
             forget` to disarm, or create the keyring first.",
            keyring.display()
        ));
    }
    let runtime_dir = runtime_dir_for(&pw)?;

    // EVERYTHING below runs as the target user: the daemon compares the
    // connecting peer's uid against its own, and root pathname work inside a
    // user-owned directory is the CVE-2018-10380 shape this codebase refuses
    // to repeat.
    drop_privileges(&pw)?;
    harden()?;
    Ok(Target {
        token,
        uid: pw.uid,
        keyring,
        runtime_dir,
    })
}

/// Keep the token out of reach of other processes running as the user, for
/// the up to two minutes the waiter may hold it: not dumpable (no ptrace and
/// no `/proc/<pid>/mem` for the same uid, whatever `fs.suid_dumpable` says),
/// no core file, and a name that says what it is.
fn harden() -> Result<(), String> {
    // SAFETY: PR_SET_DUMPABLE takes one integer argument and changes only
    // this process's own attribute.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) } != 0 {
        return Err(format!(
            "prctl(PR_SET_DUMPABLE): {}",
            std::io::Error::last_os_error()
        ));
    }
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the struct it is given; lowering a limit
    // needs no privilege.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        return Err(format!(
            "setrlimit(RLIMIT_CORE): {}",
            std::io::Error::last_os_error()
        ));
    }
    // The thread name is cosmetic (`ps`, `pgrep`), so a failure is ignored.
    // SAFETY: PR_SET_NAME reads a NUL-terminated string of at most 16 bytes.
    unsafe { libc::prctl(libc::PR_SET_NAME, c"irlume-gkr-wait".as_ptr()) };
    Ok(())
}

/// Where the waiter's log lines go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sink {
    /// The detached waiter: syslog, authpriv, identifier `irlume-gkr-unlock`.
    Journal,
    /// `--foreground`: stderr.
    Stderr,
}

/// The waiter's view of the real system.
struct System<'a> {
    target: &'a Target,
    control: PathBuf,
    control_dir: PathBuf,
    bus_path: PathBuf,
    bus: Option<bus::Bus>,
    sink: Sink,
    status: Option<detach::StatusPipe>,
}

impl<'a> System<'a> {
    fn new(target: &'a Target, sink: Sink, status: Option<detach::StatusPipe>) -> Self {
        System {
            target,
            control: gkr_wire::control_socket_path(&target.runtime_dir),
            control_dir: target.runtime_dir.join("keyring"),
            bus_path: bus_path(&target.runtime_dir),
            bus: None,
            sink,
            status,
        }
    }
}

impl waiter::World for System<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn stop_requested(&self) -> bool {
        detach::stop_requested()
    }

    fn keyring_exists(&self) -> bool {
        self.target.keyring.exists()
    }

    fn control_socket_exists(&self) -> bool {
        self.control.symlink_metadata().is_ok()
    }

    fn sleep(&mut self, pause: Duration) {
        std::thread::sleep(pause);
    }

    fn log(&mut self, event: waiter::Event) {
        match self.sink {
            Sink::Journal => detach::journal(event),
            Sink::Stderr => eprintln!("irlume-gkr-unlock: {}", event.text()),
        }
    }

    fn report(&mut self, status: waiter::Status) {
        if let Some(pipe) = &mut self.status {
            pipe.report(status);
        }
    }

    fn connect_bus(&mut self) -> Result<(), BusLost> {
        self.bus = Some(bus::Bus::connect(&self.bus_path)?);
        Ok(())
    }

    fn owner(&mut self) -> Result<Option<String>, BusLost> {
        self.bus.as_ref().ok_or(BusLost)?.owner()
    }

    fn next_owner_change(&mut self, timeout: Duration) -> Result<Option<Option<String>>, BusLost> {
        let change = self.bus.as_ref().ok_or(BusLost)?.next_owner_change(timeout);
        if change.is_err() {
            self.bus = None;
        }
        change
    }

    fn identify(&mut self, owner: &str) -> Identity {
        let Some(bus) = &self.bus else {
            return Identity::Gone;
        };
        let Some(owner_pid) = bus.pid_of(owner) else {
            return Identity::Gone;
        };
        match bus.control_directory(owner) {
            Some(dir) if same_directory(Path::new(&dir), &self.control_dir) => {
                Identity::Serves { owner_pid }
            }
            _ => Identity::Mismatch { owner_pid },
        }
    }

    fn send(&mut self, op: Op, args: &[&[u8]], expect: Expect) -> Sent {
        send_checked(&self.control, self.target.uid, op, args, expect)
    }
}

/// The user bus, beside the control socket in the uid-derived runtime
/// directory, so it inherits [`runtime_dir_for`]'s refusal of the environment
/// under privilege.
fn bus_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("bus")
}

/// Whether gnome-keyring's reported control directory is this user's.
fn same_directory(reported: &Path, ours: &Path) -> bool {
    match (reported.canonicalize(), ours.canonicalize()) {
        (Ok(reported), Ok(ours)) => reported == ours,
        _ => false,
    }
}

/// One control-socket request, sent only after the listener passed `expect`.
///
/// The check and the request share one connection, so the listener that was
/// checked is the one that receives the token.
fn send_checked(control: &Path, uid: u32, op: Op, args: &[&[u8]], expect: Expect) -> Sent {
    let Ok(mut stream) = connect_with_deadline(control) else {
        return Sent::Unreachable;
    };
    let Some((peer_pid, peer_uid)) = peer_credentials(&stream) else {
        return Sent::Unreachable;
    };
    if !expect.accepts(peer_pid, peer_uid, uid, |pid| is_user_manager(pid, uid)) {
        return Sent::PeerMismatch { peer_pid };
    }
    // The daemon applies NO timeout of its own to a control connection
    // (`gkd-control-server.c` drives the fd from the main loop with no timer),
    // and the socket may be a systemd listener whose daemon is still starting.
    if stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .is_err()
    {
        return Sent::Unreachable;
    }
    match gkr_wire::call(&mut stream, op, args) {
        Ok(result) => Sent::Answered { result, peer_pid },
        Err(_) => Sent::Unreachable,
    }
}

/// The pid and uid of the process that listens on the other end: the one
/// that called `listen()`, which for a socket-activated socket is the user's
/// systemd manager.
fn peer_credentials(stream: &UnixStream) -> Option<(u32, u32)> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED writes one `ucred` into the local it is given,
    // whose size is passed alongside.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    Some((u32::try_from(cred.pid).ok()?, cred.uid))
}

/// Whether `pid` is the user's systemd manager, the main process of
/// `user@<uid>.service`, which systemd keeps in that unit's `init.scope`.
fn is_user_manager(pid: u32, uid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|cgroup| cgroup_names_user_manager(&cgroup, uid))
}

/// Whether a `/proc/<pid>/cgroup` text places the process in
/// `user@<uid>.service/init.scope`, on the unified or the legacy hierarchy.
fn cgroup_names_user_manager(cgroup: &str, uid: u32) -> bool {
    let scope = format!("/user@{uid}.service/init.scope");
    cgroup.lines().any(|line| {
        line.splitn(3, ':')
            .nth(2)
            .is_some_and(|path| path.ends_with(&scope))
    })
}

/// Read and check the token on stdin.
///
/// `Stdin` would keep a second copy in its process-wide buffer, which nothing
/// wipes. An unbuffered `File` on a clone of the descriptor reads straight
/// into the buffer [`read_token`] wipes, and closes the clone when done.
fn read_token_from_stdin() -> Result<Zeroizing<Vec<u8>>, String> {
    let input = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| format!("reading the token from stdin: {e}"))?;
    read_token(std::fs::File::from(input))
}

/// Read one token of at most [`MAX_TOKEN_LEN`] printable bytes from `input`,
/// into a buffer that is wiped when it is dropped, on every return path.
fn read_token(mut input: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    // One allocation with room for a byte past the limit, which is how an
    // oversized token shows. It never grows, so no reallocation frees a
    // partial copy before the wipe.
    let mut token = Zeroizing::new(vec![0u8; MAX_TOKEN_LEN + 1]);
    // Best effort, as in irlume-kwallet-init: keep the pages out of swap and
    // core dumps before any token byte lands in them.
    irlume_common::memlock::lock_slice(&token);
    let mut len = 0;
    while len < token.len() {
        match input.read(&mut token[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("reading the token from stdin: {e}")),
        }
    }
    // Shrinks the length, not the allocation, so the wipe still covers every
    // byte read.
    token.truncate(len);
    if token.is_empty() {
        return Err("empty token on stdin".into());
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(format!("token longer than {MAX_TOKEN_LEN} bytes; refusing"));
    }
    // The keyring credential is a string; a token with a NUL or control bytes
    // is not one this program ever produced, so refuse it rather than let a
    // truncated comparison "succeed" somewhere downstream.
    if token.iter().any(|b| !b.is_ascii_graphic()) {
        return Err("token contains non-printable bytes; refusing".into());
    }
    Ok(token)
}

/// Connect to the control socket without ever blocking past [`IO_TIMEOUT`].
///
/// `UnixStream::connect` creates a BLOCKING socket and completes the connection
/// before any timeout can be installed, so setting read and write deadlines
/// afterwards leaves the connect itself unbounded. That matters here: a full
/// listen backlog, or a socket-activated unit whose service is wedged, blocks
/// the PAM session phase, which blocks the login.
fn connect_with_deadline(sock: &std::path::Path) -> Result<UnixStream, String> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = sock.as_os_str().as_bytes();
    if bytes.len() >= std::mem::size_of_val(&addr.sun_path) {
        return Err(format!("socket path too long: {}", sock.display()));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, b) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *b as libc::c_char;
    }

    // SAFETY: a fresh socket, wrapped in an owning UnixStream before any
    // fallible step so it cannot leak.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let stream = unsafe { UnixStream::from_raw_fd(fd) };

    // SAFETY: addr is fully initialised above; the length is its real size.
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(format!(
                "connect {}: {e} (no gnome-keyring-daemon control socket; is \
                 gnome-keyring installed and socket-activated?)",
                sock.display()
            ));
        }
        // In progress: wait for writability, bounded.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one descriptor this scope owns.
        let n = unsafe { libc::poll(&mut pfd, 1, IO_TIMEOUT.as_millis() as libc::c_int) };
        if n == 0 {
            return Err(format!(
                "connect {} timed out after {:?}",
                sock.display(),
                IO_TIMEOUT
            ));
        }
        if n < 0 {
            return Err(format!("poll: {}", std::io::Error::last_os_error()));
        }
        // Poll reports readiness, not success; the error is in SO_ERROR.
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: reading a fixed-size option into a matching local.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        // Read errno immediately: anything below could clobber it.
        let probe_errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if let Some(why) = pending_connect_failure(rc, err, probe_errno) {
            return Err(format!("connect {}: {why}", sock.display()));
        }
    }

    // Back to blocking, now that the read and write deadlines below apply.
    stream
        .set_nonblocking(false)
        .map_err(|e| format!("clearing non-blocking: {e}"))?;
    let _ = stream.as_raw_fd();
    Ok(stream)
}

/// Why a non-blocking connect that `poll` reported ready did not actually
/// connect, or `None` when it did.
///
/// `rc` is `getsockopt(SO_ERROR)`'s own return value, `so_error` the value it
/// wrote, `probe_errno` the errno at the moment it failed. Discarding `rc` is
/// the bug this exists to prevent: a failed `getsockopt` never touches the
/// out-parameter, so `so_error` keeps its initial 0 and every failed connect
/// reads as a success, handing the caller an unconnected socket it then tries
/// to unlock a keyring over. Fail closed, and keep the two causes apart: one
/// says the connect failed, the other says we could not find out.
fn pending_connect_failure(
    rc: libc::c_int,
    so_error: libc::c_int,
    probe_errno: libc::c_int,
) -> Option<String> {
    if rc != 0 {
        return Some(format!(
            "could not read SO_ERROR ({}), so whether the connect succeeded is unknown",
            std::io::Error::from_raw_os_error(probe_errno)
        ));
    }
    (so_error != 0).then(|| std::io::Error::from_raw_os_error(so_error).to_string())
}

/// The login keyring file, under the home NSS reports.
///
/// `$HOME` is deliberately not consulted: this may run as root with the login
/// stack's environment, where `$HOME` is root's or unset.
/// `IRLUME_GKR_HOME` overrides it under the same not-privileged rule as
/// [`runtime_dir_for`], so the harness can point at a throwaway home.
fn login_keyring_path(pw: &User) -> Result<PathBuf, String> {
    let home = match std::env::var_os("IRLUME_GKR_HOME") {
        Some(over) if !privileged() => PathBuf::from(over),
        Some(_) => {
            return Err(
                "IRLUME_GKR_HOME is set but this process is privileged; refusing to take \
                 the home directory from the environment"
                    .into(),
            )
        }
        None => PathBuf::from(&pw.home),
    };
    Ok(home.join(".local/share/keyrings/login.keyring"))
}

/// Whether this process holds privilege that the environment must not steer.
fn privileged() -> bool {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let (euid, uid) = unsafe { (libc::geteuid(), libc::getuid()) };
    euid == 0 || uid == 0
}

/// Where the target user's control socket lives.
///
/// Derived from the uid, NOT from `XDG_RUNTIME_DIR`. When this runs from the
/// PAM stack it runs as root, and the environment is the caller's: honouring
/// an inherited path there would let whoever controls that environment name
/// the socket this program writes the token to, which is a direct secret leak.
///
/// `IRLUME_GKR_RUNTIME_DIR` overrides it for the test harness, and ONLY when
/// this process is not privileged. An unprivileged process can already reach
/// everything its own uid can, so the override grants nothing; refusing it
/// under root keeps the production path environment-independent.
///
/// This is a deliberate divergence from `gkr-pam`, which prefers
/// `$GNOME_KEYRING_CONTROL` and only then falls back to `$XDG_RUNTIME_DIR`
/// (`get_control_file()` in `gkr-pam-module.c`). That module already runs
/// inside the user's own environment; this one runs as root with whatever
/// environment the login stack happened to carry, and honouring a variable
/// from there would let it name the socket a secret is written to. The
/// fallback path is what gnome-keyring's own systemd units bind
/// (`ListenStream=%t/keyring/control`), so the divergence only shows up on a
/// setup that relocates the socket by hand.
fn runtime_dir_for(pw: &User) -> Result<PathBuf, String> {
    let dir = runtime_dir_choice(
        std::env::var_os("IRLUME_GKR_RUNTIME_DIR"),
        privileged(),
        pw.uid,
    )?;
    if !dir.is_dir() {
        return Err(format!(
            "{} does not exist; the session is not far enough along for a keyring",
            dir.display()
        ));
    }
    Ok(dir)
}

/// [`runtime_dir_for`]'s choice of directory, before the check that it
/// exists: the override only when unprivileged, else the uid's own.
fn runtime_dir_choice(
    over: Option<OsString>,
    privileged: bool,
    uid: libc::uid_t,
) -> Result<PathBuf, String> {
    match over {
        Some(over) if !privileged => Ok(PathBuf::from(over)),
        Some(_) => Err(
            "IRLUME_GKR_RUNTIME_DIR is set but this process is privileged; refusing to \
             take the socket path from the environment"
                .into(),
        ),
        None => Ok(PathBuf::from(format!("/run/user/{uid}"))),
    }
}

/// Become the target user, permanently. Same order and same paranoia as
/// `irlume-kwallet-init`: groups and gid before uid, then verify the drop
/// took, because a drop that silently failed would leave the control-socket
/// connection coming from root and everything below running with privilege it
/// must not have.
fn drop_privileges(pw: &User) -> Result<(), String> {
    // Already the target user (the test harness, and any future caller that
    // runs in-session): there is nothing to drop, and `initgroups` would fail
    // with EPERM for an unprivileged process. Verified below either way, so
    // this cannot skip a drop that was actually needed.
    // SAFETY: getuid, geteuid, getgid and getegid take no arguments, read
    // only the calling process's own credentials, and are specified as
    // always succeeding, so none has a precondition for the caller to uphold.
    let already = unsafe { libc::getuid() } == pw.uid
        && unsafe { libc::geteuid() } == pw.uid
        && unsafe { libc::getgid() } == pw.gid
        && unsafe { libc::getegid() } == pw.gid;
    if already {
        return Ok(());
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::initgroups(pw.name.as_ptr(), pw.gid) } != 0 {
        return Err(format!("initgroups: {}", std::io::Error::last_os_error()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::setgid(pw.gid) } != 0 {
        return Err(format!("setgid: {}", std::io::Error::last_os_error()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::setuid(pw.uid) } != 0 {
        return Err(format!("setuid: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: getuid, geteuid, getgid and getegid take no arguments, read
    // only the calling process's own credentials, and are specified as
    // always succeeding, so none has a precondition for the caller to uphold.
    if unsafe { libc::getuid() } != pw.uid
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        || unsafe { libc::geteuid() } != pw.uid
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        || unsafe { libc::getgid() } != pw.gid
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        || unsafe { libc::getegid() } != pw.gid
    {
        return Err("privilege drop did not take effect".into());
    }
    Ok(())
}

struct User {
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: CString,
    /// Home directory, read from NSS rather than `$HOME`: this may run as root
    /// with the login stack's environment, where `$HOME` is not yet the user's.
    home: std::ffi::OsString,
}

fn lookup_user(user: &str) -> Result<User, String> {
    let cname = CString::new(user).map_err(|_| "username contains a NUL".to_string())?;
    // SAFETY: getpwnam returns a pointer into a static buffer, read before any
    // further libc call that could overwrite it.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return Err(format!("no such user: {user}"));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    if uid == 0 {
        return Err("refusing to unlock a keyring for uid 0".to_string());
    }
    // SAFETY: same static buffer as above, still valid; copied out immediately.
    let home = unsafe {
        let d = (*pw).pw_dir;
        if d.is_null() {
            return Err(format!("no home directory for {user}"));
        }
        std::ffi::OsString::from_vec(std::ffi::CStr::from_ptr(d).to_bytes().to_vec())
    };
    Ok(User {
        uid,
        gid,
        name: cname,
        home,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_common::gkr_wire::ControlResult;

    #[test]
    fn a_failed_so_error_probe_is_a_failed_connect_not_a_successful_one() {
        // The defect this pins: `getsockopt` writing nothing on failure leaves
        // the out-parameter at its initial 0, so a caller that reads only the
        // out-parameter treats "the probe failed" as "the connect succeeded"
        // and goes on to hand a keyring token to an unconnected socket.
        let why = pending_connect_failure(-1, 0, libc::EBADF)
            .expect("a failed SO_ERROR probe must not read as a connected socket");
        assert!(
            why.contains("could not read SO_ERROR"),
            "the two causes must stay apart in the message: {why}"
        );
    }

    #[test]
    fn a_probe_that_reports_a_connect_error_names_that_error() {
        let why = pending_connect_failure(0, libc::ECONNREFUSED, 0)
            .expect("ECONNREFUSED in SO_ERROR is a failed connect");
        assert_eq!(
            why,
            std::io::Error::from_raw_os_error(libc::ECONNREFUSED).to_string()
        );
        assert!(
            !why.contains("could not read SO_ERROR"),
            "a refused connect must not be reported as an unreadable probe: {why}"
        );
    }

    #[test]
    fn a_clean_probe_reporting_no_error_is_a_connected_socket() {
        assert!(pending_connect_failure(0, 0, 0).is_none());
    }

    /// A printable token with [`MARKER`] past offset 0, so a buffer that
    /// clears only its first byte on drop still counts as unwiped.
    const TOKEN: &[u8] = b"tok-irlume-wipe-check-5c1e";
    const MARKER: &[u8] = b"irlume-wipe-check-5c1e";
    /// Stdin bytes for the refused case: more than the limit plus the one
    /// byte read past it, so some must stay in the pipe.
    const OVERSIZED_LEN: usize = 300;
    /// No account has this name, so `prepare` stops at the user lookup, after
    /// it has read and checked the token and before any privilege change.
    const NO_SUCH_USER: &str = "irlume-test-no-such-user-5c1e";

    #[test]
    fn the_freed_block_check_sees_an_unwiped_copy() {
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            drop(std::hint::black_box(TOKEN.to_vec()));
        });
        assert_eq!(unwiped, 1, "the freed-block check is not installed");
    }

    /// The UNLOCK packet `gkr_wire::call` builds around the token is wiped
    /// before its memory is freed.
    #[test]
    fn the_unlock_packet_is_wiped_after_it_is_sent() {
        struct Daemon {
            sent: usize,
            reply: &'static [u8],
        }
        impl std::io::Write for Daemon {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.sent += buf.len();
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl std::io::Read for Daemon {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reply.read(buf)
            }
        }
        // Declared length 8, result 0 (OK).
        const OK_REPLY: &[u8] = &[0, 0, 0, 8, 0, 0, 0, 0];

        let mut daemon = Daemon {
            sent: 0,
            reply: OK_REPLY,
        };
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let result = gkr_wire::call(&mut daemon, Op::Unlock, &[TOKEN]);
            assert_eq!(result, Ok(ControlResult::Ok));
        });
        assert_eq!(unwiped, 0, "the UNLOCK packet was freed without a wipe");
        // The credentials byte, the 8-byte header and one length-prefixed
        // argument.
        assert_eq!(daemon.sent, 1 + 8 + 4 + TOKEN.len());
    }

    /// The token goes from the stdin pipe straight into a buffer that is
    /// wiped before it is freed, on the accepted path and on a refused one.
    /// Each case runs in a fresh process whose stdin is a pipe this test
    /// fills and closes.
    #[test]
    fn the_stdin_token_is_read_unbuffered_and_wiped() {
        use std::io::Write as _;
        let oversized: Vec<u8> = MARKER.iter().copied().cycle().take(OVERSIZED_LEN).collect();
        for (child, input) in [
            ("tests::token_stdin_child", TOKEN),
            ("tests::oversized_token_stdin_child", &oversized[..]),
        ] {
            let mut proc = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", child])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut pipe = proc.stdin.take().unwrap();
            pipe.write_all(input).unwrap();
            drop(pipe);
            let out = proc.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{child} failed:\n{stdout}");
            // An `--exact` name that matches nothing also exits 0.
            assert!(
                stdout.contains("test result: ok. 1 passed"),
                "{child} did not run:\n{stdout}"
            );
        }
    }

    #[test]
    fn read_token_keeps_the_checks_and_returns_a_wiping_buffer() {
        let token: Zeroizing<Vec<u8>> = read_token(TOKEN).expect("a printable token");
        assert_eq!(token.as_slice(), TOKEN);

        let limit = vec![b'a'; MAX_TOKEN_LEN];
        assert_eq!(
            read_token(&limit[..]).expect("at the limit").len(),
            MAX_TOKEN_LEN
        );

        let over = vec![b'a'; MAX_TOKEN_LEN + 1];
        let why = read_token(&over[..]).expect_err("one byte over the limit");
        assert!(why.contains("longer than 256 bytes"), "{why}");

        let why = read_token(&b""[..]).expect_err("no token");
        assert!(why.contains("empty token"), "{why}");

        for bad in [&b"tok\0en"[..], b"tok en", b"token\n"] {
            let why = read_token(bad).expect_err("non-printable byte");
            assert!(why.contains("non-printable"), "{why}");
        }
    }

    #[test]
    fn read_token_retries_an_interrupted_read_and_reports_a_failed_one() {
        /// Fails each read once with `kind`, then serves from `rest`.
        struct Flaky {
            kind: Option<std::io::ErrorKind>,
            rest: &'static [u8],
        }
        impl std::io::Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.kind.take() {
                    Some(kind) => Err(kind.into()),
                    None => self.rest.read(buf),
                }
            }
        }

        let token = read_token(Flaky {
            kind: Some(std::io::ErrorKind::Interrupted),
            rest: TOKEN,
        })
        .expect("an interrupted read is retried");
        assert_eq!(token.as_slice(), TOKEN);

        let why = read_token(Flaky {
            kind: Some(std::io::ErrorKind::BrokenPipe),
            rest: TOKEN,
        })
        .expect_err("a failed read is an error");
        assert!(why.starts_with("reading the token from stdin"), "{why}");
    }

    /// A pipe may hand the token over in pieces. One byte per read still
    /// gives the whole token in order, and the refusal comes after exactly
    /// one byte past the limit.
    #[test]
    fn read_token_joins_one_byte_reads() {
        /// Serves `rest` one byte per call.
        struct Trickle<'a> {
            rest: &'a [u8],
        }
        impl std::io::Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.rest.len().min(buf.len()).min(1);
                buf[..n].copy_from_slice(&self.rest[..n]);
                self.rest = &self.rest[n..];
                Ok(n)
            }
        }

        let mut input = Trickle { rest: TOKEN };
        let token = read_token(&mut input).expect("a printable token");
        assert_eq!(token.as_slice(), TOKEN);

        // Every printable byte in turn, so a byte out of place shows.
        let limit: Vec<u8> = (b'!'..=b'~').cycle().take(MAX_TOKEN_LEN).collect();
        let mut input = Trickle { rest: &limit };
        let token = read_token(&mut input).expect("at the limit");
        assert_eq!(token.as_slice(), &limit[..]);

        let over = vec![b'a'; OVERSIZED_LEN];
        let mut input = Trickle { rest: &over };
        let why = read_token(&mut input).expect_err("over the limit");
        assert!(why.contains("longer than 256 bytes"), "{why}");
        assert_eq!(input.rest.len(), OVERSIZED_LEN - (MAX_TOKEN_LEN + 1));
    }

    #[test]
    #[ignore = "fresh-exec child invoked by the_stdin_token_is_read_unbuffered_and_wiped"]
    fn token_stdin_child() {
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let why = refusal(prepare(NO_SUCH_USER));
            assert!(why.contains("no such user"), "{why}");
        });
        assert_eq!(unwiped, 0, "the token was freed without a wipe");
        assert_eq!(stdin_bytes_left(), 0);
    }

    #[test]
    #[ignore = "fresh-exec child invoked by the_stdin_token_is_read_unbuffered_and_wiped"]
    fn oversized_token_stdin_child() {
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let why = refusal(prepare(NO_SUCH_USER));
            assert!(why.contains("longer than 256 bytes"), "{why}");
        });
        assert_eq!(unwiped, 0, "the refused token was freed without a wipe");
        // Only the limit and the one byte past it leave the pipe. A buffered
        // reader would have drained the rest into memory nothing wipes.
        assert_eq!(stdin_bytes_left(), OVERSIZED_LEN - (MAX_TOKEN_LEN + 1));
    }

    /// The error of a `prepare` that must fail. `Target` has no `Debug`, on
    /// purpose: it holds the token.
    fn refusal(prepared: Result<Target, String>) -> String {
        match prepared {
            Ok(_) => panic!("prepare succeeded"),
            Err(why) => why,
        }
    }

    /// Bytes still unread in the stdin pipe.
    fn stdin_bytes_left() -> usize {
        let mut left: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int through this valid pointer; it
        // reads no bytes from the pipe and does not take the descriptor.
        let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::FIONREAD, &mut left) };
        assert_eq!(rc, 0, "FIONREAD: {}", std::io::Error::last_os_error());
        usize::try_from(left).expect("FIONREAD is never negative")
    }

    #[test]
    fn arguments_are_flags_then_one_user() {
        let parse = |args: &[&str]| parse_args(args.iter().map(OsString::from));
        assert_eq!(
            parse(&["alice"]),
            Ok(Args {
                mode: Mode::Pam,
                timeout_secs: None,
                user: "alice".into()
            })
        );
        assert_eq!(
            parse(&["--foreground", "--timeout-secs", "3", "alice"]),
            Ok(Args {
                mode: Mode::Foreground,
                timeout_secs: Some(3),
                user: "alice".into()
            })
        );
        for bad in [
            &[][..],
            &["--foreground"],
            &["alice", "bob"],
            &["--timeout-secs"],
            &["--timeout-secs", "0", "alice"],
            &["--timeout-secs", "121", "alice"],
            &["--timeout-secs", "x", "alice"],
            &["--wait", "alice"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must be a usage error");
        }
    }

    #[test]
    fn a_shorter_bound_is_refused_under_privilege() {
        assert_eq!(waiter_bound(None, true), Ok(waiter::WAITER_BOUND));
        assert_eq!(waiter_bound(None, false), Ok(waiter::WAITER_BOUND));
        assert_eq!(waiter_bound(Some(3), false), Ok(Duration::from_secs(3)));
        let why = waiter_bound(Some(3), true).expect_err("privileged");
        assert!(why.contains("refusing"), "{why}");
    }

    #[test]
    fn the_runtime_dir_and_bus_come_from_the_uid_under_privilege() {
        let dir = runtime_dir_choice(None, true, 1234).unwrap();
        assert_eq!(dir, Path::new("/run/user/1234"));
        assert_eq!(bus_path(&dir), Path::new("/run/user/1234/bus"));
        assert_eq!(
            gkr_wire::control_socket_path(&dir),
            Path::new("/run/user/1234/keyring/control")
        );
        let why = runtime_dir_choice(Some("/tmp/elsewhere".into()), true, 1234)
            .expect_err("an override under privilege");
        assert!(why.contains("refusing"), "{why}");
        assert_eq!(
            runtime_dir_choice(Some("/tmp/elsewhere".into()), false, 1234).unwrap(),
            Path::new("/tmp/elsewhere")
        );
    }

    #[test]
    fn only_the_user_managers_init_scope_counts_as_the_manager() {
        let manager = "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n";
        assert!(cgroup_names_user_manager(manager, 1000));
        assert!(!cgroup_names_user_manager(manager, 1001), "another user's");
        let legacy =
            "12:cpu:/\n1:name=systemd:/user.slice/user-1000.slice/user@1000.service/init.scope\n";
        assert!(cgroup_names_user_manager(legacy, 1000));
        for other in [
            "0::/user.slice/user-1000.slice/session-3.scope",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app.service",
            "0::/user.slice/user-1000.slice/user@1000.service/init.scope/nested",
            "0::/user.slice/user-1000.slice/user@10000.service/init.scope",
            "",
        ] {
            assert!(!cgroup_names_user_manager(other, 1000), "{other}");
        }
    }

    #[test]
    fn a_reported_control_directory_matches_through_symlinks_only_when_it_is_ours() {
        let root = std::env::temp_dir().join(format!("irlume-gkr-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("run/keyring")).unwrap();
        std::fs::create_dir_all(root.join("other/keyring")).unwrap();
        std::os::unix::fs::symlink(root.join("run"), root.join("link")).unwrap();
        let ours = root.join("run/keyring");
        assert!(same_directory(&root.join("link/keyring"), &ours));
        assert!(same_directory(&ours, &root.join("link/keyring")));
        assert!(!same_directory(&root.join("other/keyring"), &ours));
        assert!(!same_directory(&root.join("missing"), &ours));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The listener is checked on the connection that would carry the token,
    /// and a listener that fails the check receives nothing at all.
    #[test]
    fn the_control_listener_is_checked_before_anything_is_written() {
        use std::io::{Read as _, Write as _};
        let root = std::env::temp_dir().join(format!("irlume-gkr-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let sock = root.join("control");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let mut received = Vec::new();
            for _ in 0..2 {
                let (mut conn, _) = listener.accept().unwrap();
                // The credentials byte, then a packet whose first four
                // bytes give its length; answer OK once it is all here.
                let mut got = Vec::new();
                let mut buf = [0u8; 256];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                    if got.len() >= 5 {
                        let total = u32::from_be_bytes([got[1], got[2], got[3], got[4]]);
                        if got.len() > total as usize {
                            let _ = conn.write_all(&[0, 0, 0, 8, 0, 0, 0, 0]);
                            break;
                        }
                    }
                }
                received.push(got.len());
            }
            received
        });
        // SAFETY: getpid and getuid take no arguments and cannot fail.
        let (me, uid) = unsafe { (libc::getpid() as u32, libc::getuid()) };
        let refused = send_checked(
            &sock,
            uid,
            Op::Change,
            &[TOKEN, TOKEN],
            Expect::OwnerOrManager { owner_pid: me + 1 },
        );
        assert_eq!(refused, Sent::PeerMismatch { peer_pid: me });
        let answered = send_checked(
            &sock,
            uid,
            Op::Unlock,
            &[TOKEN],
            Expect::OwnerOrManager { owner_pid: me },
        );
        assert_eq!(
            answered,
            Sent::Answered {
                result: ControlResult::Ok,
                peer_pid: me
            }
        );
        let received = server.join().unwrap();
        assert_eq!(received[0], 0, "the refused listener got bytes");
        assert_eq!(received[1], 1 + 8 + 4 + TOKEN.len());
        assert_eq!(
            send_checked(
                &root.join("absent"),
                uid,
                Op::Unlock,
                &[TOKEN],
                Expect::AnyPeer
            ),
            Sent::Unreachable
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// PAM mode forks the waiter; the parent's copy of the token is wiped
    /// when the parent returns.
    #[test]
    fn the_parents_copy_of_the_token_is_wiped_after_the_fork() {
        let mut waiter = 0;
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let token = read_token(TOKEN).expect("a printable token");
            match detach::fork_waiter().expect("fork") {
                detach::Forked::Child(mut status) => {
                    status.report(waiter::Status::Waiting);
                    // SAFETY: the forked child leaves without running the
                    // test harness any further.
                    unsafe { libc::_exit(0) }
                }
                detach::Forked::Parent {
                    verdict,
                    waiter: pid,
                } => {
                    assert_eq!(verdict, detach::Verdict::Waiting);
                    waiter = pid;
                }
            }
            drop(token);
        });
        assert_eq!(unwiped, 0, "the parent's token was freed without a wipe");
        let mut status = 0;
        // SAFETY: reaps the one child this test forked.
        assert_eq!(unsafe { libc::waitpid(waiter, &mut status, 0) }, waiter);
    }

    /// SIGTERM while waiting: the wait returns, and the token is wiped by the
    /// ordinary drop instead of dying with the process. Runs in a fresh
    /// process, since it installs signal handlers.
    #[test]
    fn a_stop_signal_ends_the_wait_and_wipes_the_token() {
        let root = std::env::temp_dir().join(format!("irlume-gkr-stop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ready = root.join("ready");
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tests::stop_signal_child"])
            .env("IRLUME_TEST_READY_FILE", &ready)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "the child never started waiting");
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        // SAFETY: signals the child this test spawned and has not reaped.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "the stop was not clean:\n{stdout}");
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "the child did not run:\n{stdout}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    #[ignore = "fresh-exec child invoked by a_stop_signal_ends_the_wait_and_wipes_the_token"]
    fn stop_signal_child() {
        /// A world where gnome-keyring never shows up, on the real clock and
        /// the real stop flag.
        struct Idle {
            ready: PathBuf,
        }
        impl waiter::World for Idle {
            fn now(&self) -> Instant {
                Instant::now()
            }
            fn stop_requested(&self) -> bool {
                detach::stop_requested()
            }
            fn keyring_exists(&self) -> bool {
                true
            }
            fn control_socket_exists(&self) -> bool {
                true
            }
            fn sleep(&mut self, pause: Duration) {
                std::thread::sleep(pause);
            }
            fn log(&mut self, _: waiter::Event) {}
            fn report(&mut self, _: waiter::Status) {}
            fn connect_bus(&mut self) -> Result<(), BusLost> {
                Ok(())
            }
            fn owner(&mut self) -> Result<Option<String>, BusLost> {
                Ok(None)
            }
            fn next_owner_change(
                &mut self,
                timeout: Duration,
            ) -> Result<Option<Option<String>>, BusLost> {
                if !self.ready.exists() {
                    std::fs::write(&self.ready, b"").unwrap();
                }
                std::thread::sleep(timeout);
                Ok(None)
            }
            fn identify(&mut self, _: &str) -> Identity {
                unreachable!("no owner ever appears")
            }
            fn send(&mut self, _: Op, _: &[&[u8]], _: Expect) -> Sent {
                unreachable!("nothing is ever sent")
            }
        }

        let ready = PathBuf::from(std::env::var_os("IRLUME_TEST_READY_FILE").unwrap());
        let bound = Duration::from_secs(60);
        detach::arm_stop(bound).unwrap();
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let token = read_token(TOKEN).expect("a printable token");
            let plan = waiter::Plan {
                started: Instant::now(),
                bound,
                uid: 0,
            };
            let outcome = waiter::run(&mut Idle { ready }, &token, &plan);
            assert_eq!(outcome, waiter::Outcome::Stopped);
            drop(token);
        });
        assert_eq!(unwiped, 0, "the token was freed without a wipe");
    }

    /// The allocator of this test binary, which can find a secret in freed
    /// memory.
    ///
    /// It zero-fills every block it hands out. While [`count_unwiped`] runs
    /// on a thread, each block that thread frees is read as bytes and
    /// searched for a marker first; other threads and other times forward to
    /// `System` unchanged. Use `count_unwiped` only around code that frees
    /// byte buffers (`Vec<u8>`, `String`, `CString`): a typed write can leave
    /// padding bytes uninitialized, and those must not be read as `u8`.
    ///
    /// A copy of the module of the same name in `crates/irlume-pam/src/lib.rs`.
    mod freed_blocks {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        struct CheckFreed;

        #[global_allocator]
        static CHECK_FREED: CheckFreed = CheckFreed;

        thread_local! {
            static MARKER: Cell<Option<&'static [u8]>> = const { Cell::new(None) };
            static UNWIPED: Cell<usize> = const { Cell::new(0) };
        }

        /// Run `f` and count the blocks it frees that still hold `marker`.
        /// `f` must free only byte buffers (see the module doc).
        pub(super) fn count_unwiped(marker: &'static [u8], f: impl FnOnce()) -> usize {
            struct Disarm;
            impl Drop for Disarm {
                fn drop(&mut self) {
                    let _ = MARKER.try_with(|m| m.set(None));
                }
            }
            assert!(!marker.is_empty());
            UNWIPED.with(|n| n.set(0));
            MARKER.with(|m| m.set(Some(marker)));
            let disarm = Disarm;
            f();
            drop(disarm);
            UNWIPED.with(Cell::get)
        }

        // SAFETY: `alloc` returns `System.alloc_zeroed` for the same layout,
        // and `dealloc` returns the caller's pointer and layout to `System`
        // after reading the block, so `System`'s guarantees carry over. The
        // default `realloc` and `alloc_zeroed` go through these two.
        unsafe impl GlobalAlloc for CheckFreed {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                // SAFETY: `alloc_zeroed` has the contract the caller keeps
                // for `alloc`: a layout of non-zero size.
                unsafe { System.alloc_zeroed(layout) }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                if let Some(marker) = MARKER.try_with(Cell::get).ok().flatten() {
                    // SAFETY: `ptr` is a live block of `layout.size()` bytes
                    // from `alloc` above, read before it is freed. Every byte
                    // is initialized: `alloc` zero-filled the block, and while
                    // a marker is set the only blocks freed are byte buffers
                    // (see the module doc), whose writes are bytes with no
                    // padding.
                    let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                    if block.windows(marker.len()).any(|w| w == marker) {
                        let _ = UNWIPED.try_with(|n| n.set(n.get() + 1));
                    }
                }
                // SAFETY: the caller passes a block from `alloc` above, which
                // came from `System`, with the layout it was allocated with.
                unsafe { System.dealloc(ptr, layout) }
            }
        }
    }
}
