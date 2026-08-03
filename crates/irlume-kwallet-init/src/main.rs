// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Hand a KDE wallet key to `ksecretd` the way `pam_kwallet5` does.
//!
//! `ksecretd` accepts a wallet key exactly once, on a pipe, at startup:
//! `checkPamModule()` runs only when `PAM_KWALLET5_LOGIN` is set, reads
//! `KEY_LEN` bytes in `waitForHash()`, then blocks in `waitForEnvironment()`
//! until something connects to a listening socket and writes `KEY=VALUE` lines.
//! There is no way to hand it a key later: the `pamOpen` D-Bus method belongs to
//! the `kwalletd6` compatibility shim, which translates to the Secret Service,
//! and the Secret Service has no unlock-with-a-raw-hash operation.
//!
//! So this exists as a separate program rather than as code inside
//! `pam_irlume`. The module is loaded into sshd, login and every greeter, and it
//! has no `fork`, no `exec` and no privilege dropping today; this needs all
//! three plus a listening socket. Keeping that in a short-lived helper leaves
//! the module's own blast radius unchanged.
//!
//! Invoked as `irlume-kwallet-init <username>` with the key on **stdin**, never
//! in argv, which is world-readable through `/proc`.
//!
//! It is launched from the PAM process rather than from `irlumed` on purpose:
//! that places `ksecretd` in the session's cgroup, where `pam_kwallet5` puts it.
//! Spawned from the daemon it would live in `irlumed.service`, and restarting
//! irlume would take the user's wallet daemon down with it.

use irlume_common::kwallet_wire::{KEY_LEN, LOGIN_ENV, SOCKET_NAME};
use std::ffi::{CString, OsStr};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Binaries that understand `--pam-login`, most specific first.
///
/// On Fedora 44 the wallet daemon is `ksecretd`; `kwalletd6` there is the
/// Secret Service shim and rejects the option. Distributions still shipping the
/// older KWallet have it on `kwalletd6`/`kwalletd5`. `IRLUME_KSECRETD` overrides
/// the search, which is also how the tests point at a chosen binary.
const CANDIDATES: &[&str] = &[
    "/usr/bin/ksecretd",
    "/usr/bin/kwalletd6",
    "/usr/bin/kwalletd5",
];

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(user) = args.next() else {
        eprintln!("usage: irlume-kwallet-init <username>  (key on stdin)");
        return std::process::ExitCode::from(2);
    };
    let user = user.to_string_lossy().into_owned();

    match run(&user) {
        Ok(sock) => {
            // The PAM module needs this in the session environment so Plasma's
            // pam_kwallet_init can find the socket. Printed rather than assumed
            // so the module never has to duplicate the path construction.
            println!("{}", sock.display());
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("irlume-kwallet-init: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(user: &str) -> Result<PathBuf, String> {
    // Read the key first. If it is not exactly KEY_LEN bytes, stop before any
    // process is spawned: ksecretd blocks forever on a short key and silently
    // truncates a long one, so neither failure would be visible at a login.
    let mut key = vec![0u8; KEY_LEN];
    std::io::stdin()
        .read_exact(&mut key)
        .map_err(|e| format!("expected {KEY_LEN} bytes of wallet key on stdin: {e}"))?;
    let mut extra = [0u8; 1];
    if let Ok(1) = std::io::stdin().read(&mut extra) {
        return Err(format!("more than {KEY_LEN} bytes on stdin; refusing"));
    }

    let pw = lookup_user(user)?;
    let runtime_dir = PathBuf::from(format!("/run/user/{}", pw.uid));
    if !runtime_dir.is_dir() {
        return Err(format!(
            "{} does not exist; the session is not far enough along for a wallet",
            runtime_dir.display()
        ));
    }
    let sock_path = runtime_dir.join(SOCKET_NAME);
    let exe = wallet_daemon()?;

    let listener = bind_listener(&sock_path, &pw)?;
    let (read_fd, write_fd) = make_pipe()?;

    // SAFETY: between fork() and execve() the child runs in a single thread and
    // touches only async-signal-safe calls, which is the constraint fork()
    // imposes on a process that may be multi-threaded.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        unsafe { child_exec(&exe, &pw, read_fd, listener, &sock_path) };
        // child_exec only returns when execve failed.
        unsafe { libc::_exit(127) };
    }

    // Parent: hand over the key, then get out of the way. ksecretd goes on to
    // block in waitForEnvironment() until Plasma's pam_kwallet_init connects, so
    // we deliberately do NOT wait for it.
    unsafe {
        libc::close(read_fd);
        libc::close(listener);
    }
    write_all(write_fd, &key)?;
    unsafe { libc::close(write_fd) };
    Ok(sock_path)
}

struct User {
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: CString,
}

fn lookup_user(user: &str) -> Result<User, String> {
    let cname = CString::new(user).map_err(|_| "username contains a NUL".to_string())?;
    // SAFETY: getpwnam returns a pointer into a static buffer, read before any
    // further libc call that could overwrite it.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return Err(format!("no such user: {user}"));
    }
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    if uid == 0 {
        return Err("refusing to open a wallet for uid 0".to_string());
    }
    Ok(User {
        uid,
        gid,
        name: cname,
    })
}

fn wallet_daemon() -> Result<CString, String> {
    if let Some(over) = std::env::var_os("IRLUME_KSECRETD") {
        return CString::new(over.as_bytes()).map_err(|_| "IRLUME_KSECRETD has a NUL".into());
    }
    for c in CANDIDATES {
        if std::path::Path::new(c).is_file() {
            return CString::new(*c).map_err(|_| "candidate path has a NUL".to_string());
        }
    }
    Err(format!(
        "no wallet daemon found; looked for {}",
        CANDIDATES.join(", ")
    ))
}

/// Bind and listen on the handoff socket, owned by the target user.
fn bind_listener(path: &std::path::Path, pw: &User) -> Result<libc::c_int, String> {
    let bytes = path.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= std::mem::size_of_val(&addr.sun_path) {
        return Err(format!("socket path too long: {}", path.display()));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, b) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *b as libc::c_char;
    }

    // A stale socket from a previous session would make bind() fail with
    // EADDRINUSE. pam_kwallet5 replaces it the same way, and ksecretd uses
    // ReplaceExisting when PAM-launched (KDE BUG 509680), so the newest login
    // wins rather than colliding.
    let _ = std::fs::remove_file(path);

    // SAFETY: addr is fully initialised above and the length is the real size.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("bind {}: {e}", path.display()));
    }
    if unsafe { libc::listen(fd, 5) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("listen: {e}"));
    }
    // The connecting side is Plasma's pam_kwallet_init, running as the user.
    let cpath = CString::new(bytes).map_err(|_| "socket path has a NUL".to_string())?;
    if unsafe { libc::chown(cpath.as_ptr(), pw.uid, pw.gid) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("chown {}: {e}", path.display()));
    }
    Ok(fd)
}

fn make_pipe() -> Result<(libc::c_int, libc::c_int), String> {
    let mut fds = [0 as libc::c_int; 2];
    // Plain pipe(), not O_CLOEXEC: the read end must survive execve into
    // ksecretd, which is handed its number on the command line.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

/// Drop to the target user and become the wallet daemon.
///
/// # Safety
/// Must only be called in the child of a `fork()`, before any other work.
unsafe fn child_exec(
    exe: &CString,
    pw: &User,
    read_fd: libc::c_int,
    listen_fd: libc::c_int,
    sock_path: &std::path::Path,
) {
    // Order matters: supplementary groups and gid must go before setuid, or the
    // process no longer has the privilege to drop them.
    if libc::initgroups(pw.name.as_ptr(), pw.gid) != 0
        || libc::setgid(pw.gid) != 0
        || libc::setuid(pw.uid) != 0
    {
        libc::_exit(126);
    }
    // A failed drop that we did not notice would run the wallet daemon as root.
    if libc::getuid() != pw.uid || libc::geteuid() != pw.uid {
        libc::_exit(126);
    }

    // Detach the standard streams before exec. The wallet daemon outlives this
    // helper by design, and if it kept our stdout the caller would block: a
    // pipe or a `$(...)` capture waits for EVERY writer to close, not just the
    // process it started. Found by hanging exactly that way in the end-to-end
    // test. ksecretd logs to the journal regardless.
    let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
    if devnull >= 0 {
        libc::dup2(devnull, libc::STDIN_FILENO);
        libc::dup2(devnull, libc::STDOUT_FILENO);
        libc::dup2(devnull, libc::STDERR_FILENO);
        if devnull > libc::STDERR_FILENO {
            libc::close(devnull);
        }
    }

    // Both fds are passed by number, so they must not carry CLOEXEC.
    clear_cloexec(read_fd);
    clear_cloexec(listen_fd);

    let arg0 = exe.clone();
    let opt = CString::new("--pam-login").unwrap();
    let a_pipe = CString::new(read_fd.to_string()).unwrap();
    let a_sock = CString::new(listen_fd.to_string()).unwrap();
    let argv = [
        arg0.as_ptr(),
        opt.as_ptr(),
        a_pipe.as_ptr(),
        a_sock.as_ptr(),
        std::ptr::null(),
    ];

    // Without LOGIN_ENV, ksecretd never calls checkPamModule() and its argument
    // parser rejects --pam-login as an unknown option. Verified: it exits with
    // "Unknown option 'pam-login'" when the variable is absent.
    let login = CString::new(format!("{LOGIN_ENV}={}", sock_path.display())).unwrap();
    let runtime = CString::new(format!("XDG_RUNTIME_DIR=/run/user/{}", pw.uid)).unwrap();
    let home = CString::new(format!("HOME={}", home_of(pw.uid))).unwrap();
    let user = CString::new(format!(
        "USER={}",
        OsStr::from_bytes(pw.name.as_bytes()).to_string_lossy()
    ))
    .unwrap();
    // The rest of the session environment (bus address, display) arrives later
    // over the socket; ksecretd is written to wait for exactly that.
    let envp = [
        login.as_ptr(),
        runtime.as_ptr(),
        home.as_ptr(),
        user.as_ptr(),
        std::ptr::null(),
    ];

    libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
}

unsafe fn clear_cloexec(fd: libc::c_int) {
    let flags = libc::fcntl(fd, libc::F_GETFD);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }
}

fn home_of(uid: libc::uid_t) -> String {
    // SAFETY: read straight out of the static buffer before any other libc call.
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) }
        .to_string_lossy()
        .into_owned()
}

fn write_all(fd: libc::c_int, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("write to the wallet daemon: {e}"));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}
