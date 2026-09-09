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

use irlume_common::kwallet_wire::{KEY_LEN, LOGIN_ENV, SALT_ABSENT_EXIT, SALT_LEN, SOCKET_NAME};
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use zeroize::{Zeroize as _, Zeroizing};

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
    if user == "--read-salt" {
        let Some(user) = args.next() else {
            return std::process::ExitCode::from(2);
        };
        if args.next().is_some() {
            return std::process::ExitCode::from(2);
        }
        return match read_salt_mode(&user.to_string_lossy()) {
            Ok(salt) => match write_salt(salt.expose()) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(_) => std::process::ExitCode::FAILURE,
            },
            Err(SaltReadError::Absent) => std::process::ExitCode::from(SALT_ABSENT_EXIT as u8),
            Err(SaltReadError::Failed) => std::process::ExitCode::FAILURE,
        };
    }
    if args.next().is_some() {
        return std::process::ExitCode::from(2);
    }
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

fn write_salt(salt: &[u8]) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    write_salt_to(stdout.lock(), salt)
}

fn write_salt_to(mut out: impl Write, salt: &[u8]) -> std::io::Result<()> {
    out.write_all(salt)?;
    out.flush()
}

fn run(user: &str) -> Result<PathBuf, String> {
    // Read the key first. If it is not exactly KEY_LEN bytes, stop before any
    // process is spawned: ksecretd blocks forever on a short key and silently
    // truncates a long one, so neither failure would be visible at a login.
    let mut key = read_wallet_key_from_stdin()?;

    let pw = lookup_user(user)?;
    let runtime_dir = PathBuf::from(format!("/run/user/{}", pw.uid));
    if !runtime_dir.is_dir() {
        return Err(format!(
            "{} does not exist; the session is not far enough along for a wallet",
            runtime_dir.display()
        ));
    }
    let sock_path = runtime_dir.join(SOCKET_NAME);
    // Resolved while still privileged: after the drop below, a user-writable
    // PATH or a swapped file could change which program this becomes.
    let exe = wallet_daemon()?;

    // EVERYTHING below runs as the target user. Nothing after this point needs
    // privilege, and doing pathname work as root inside /run/user/<uid>, which
    // that user owns and can rename underneath us, is how KDE shipped
    // CVE-2018-10380: chown() follows a final symlink, so a socket path swapped
    // for a link to /etc/shadow between bind() and chown() hands the file to the
    // attacker. Dropping first removes the primitive rather than racing it.
    drop_privileges(&pw)?;

    let listener = bind_listener(&sock_path)?;
    let (read_fd, write_fd) = make_pipe()?;
    // Close-on-exec, so the child end closing is itself the signal that execve
    // succeeded. Without it the parent cannot tell a running wallet daemon from
    // one that died before exec, and it would report success either way.
    let (status_read, status_write) = make_status_pipe()?;

    // Resolved HERE, in the parent, so the child between fork() and execve()
    // does nothing but open/dup2/close/fcntl/execve on buffers that already
    // exist (#363).
    // It used to call getpwuid, format! and CString::new down there. This
    // process is single-threaded at the fork, which is why that never
    // deadlocked, but getpwuid goes through NSS (dlopen, allocation, locks) and
    // none of it is async-signal-safe, so the old SAFETY comment claimed a
    // property the code did not have and the correctness depended on nobody
    // ever adding a thread above.
    let plan = LaunchPlan::build(&exe, read_fd, listener, &sock_path)?;

    // SAFETY: the child touches only async-signal-safe calls, because
    // everything it needs was built above. `plan` outlives the fork, and its
    // pointer arrays borrow from CString buffers on the heap, which the child
    // inherits copy-on-write at the same addresses.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        unsafe {
            libc::close(status_read);
            libc::close(write_fd);
            // The parent alone writes the key to ksecretd. `fork` replicated
            // the allocation into this child but did not inherit its mlock;
            // wipe those bytes before either execve or the `_exit` failure
            // branch. Slice zeroization is allocation-free and does not run a
            // Vec destructor in the post-fork child.
            wipe_fork_child_key(&mut key);
            child_exec(&exe, read_fd, listener, &plan);
            // Only reached when execve failed. The byte distinguishes that from
            // the EOF a successful exec produces.
            let failed = [1u8];
            libc::write(status_write, failed.as_ptr() as *const libc::c_void, 1);
            libc::_exit(127);
        }
    }

    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::close(status_write);
        libc::close(read_fd);
        libc::close(listener);
    }

    // Wait for exec before claiming anything. Reporting success here is not
    // cosmetic: the caller exports PAM_KWALLET5_LOGIN on the strength of it, and
    // that variable makes pam_kwallet5 stand down. A false success therefore
    // leaves the wallet locked AND removes the fallback that would have opened
    // it.
    if let Err(e) = await_exec(status_read) {
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        unsafe {
            libc::close(write_fd)
        };
        return Err(e);
    }

    // Hand over the key, then get out of the way. ksecretd goes on to block in
    // waitForEnvironment() until Plasma's pam_kwallet_init connects, so we
    // deliberately do NOT wait for it to finish starting.
    write_all(write_fd, &key)?;
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::close(write_fd)
    };
    Ok(sock_path)
}

fn read_wallet_key_from_stdin() -> Result<Zeroizing<Vec<u8>>, String> {
    // Stdin's Read implementation retains a second copy in a global buffer.
    // An unbuffered File reads directly into our protected allocation; cloning
    // its descriptor preserves stdin ownership and closes the copy before fork.
    let input = std::fs::File::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| format!("expected {KEY_LEN} bytes of wallet key on stdin: {e}"))?,
    );
    read_wallet_key(input)
}

fn read_wallet_key(mut input: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    // Protect the allocation before input can place even a partial key in it.
    // The lock remains best effort so login behavior is unchanged when the
    // process lacks sufficient RLIMIT_MEMLOCK.
    irlume_common::memlock::lock_slice(&key);
    input
        .read_exact(&mut key)
        .map_err(|e| format!("expected {KEY_LEN} bytes of wallet key on stdin: {e}"))?;
    let mut extra = Zeroizing::new([0u8; 1]);
    if let Ok(1) = input.read(&mut *extra) {
        return Err(format!("more than {KEY_LEN} bytes on stdin; refusing"));
    }
    Ok(key)
}

fn wipe_fork_child_key(key: &mut [u8]) {
    key.zeroize();
}

/// Become the target user, permanently.
///
/// Order matters: supplementary groups and the gid must be set before the uid,
/// or the process no longer holds the privilege needed to drop them.
fn drop_privileges(pw: &User) -> Result<(), String> {
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
    // Checked rather than assumed: a drop that silently did not take would leave
    // every path below running as root, which is the whole thing being avoided.
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

fn make_status_pipe() -> Result<(libc::c_int, libc::c_int), String> {
    let mut fds = [0 as libc::c_int; 2];
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(format!("status pipe: {}", std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

/// Block until the child either execs (EOF, because the write end was
/// close-on-exec) or reports a pre-exec failure (one byte).
fn await_exec(status_fd: libc::c_int) -> Result<(), String> {
    let mut byte = 0u8;
    loop {
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let n = unsafe { libc::read(status_fd, &mut byte as *mut u8 as *mut libc::c_void, 1) };
        if n == 0 {
            #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
            unsafe {
                libc::close(status_fd)
            };
            return Ok(());
        }
        if n == 1 {
            #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
            unsafe {
                libc::close(status_fd)
            };
            return Err("the wallet daemon failed to start (exec did not happen)".into());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
            unsafe {
                libc::close(status_fd)
            };
            return Err(format!("reading the wallet daemon's start status: {e}"));
        }
    }
}

struct User {
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: CString,
    home: PathBuf,
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
    let (uid, gid, home) = unsafe {
        (
            (*pw).pw_uid,
            (*pw).pw_gid,
            std::ffi::CStr::from_ptr((*pw).pw_dir).to_bytes().to_vec(),
        )
    };
    if uid == 0 {
        return Err("refusing to open a wallet for uid 0".to_string());
    }
    Ok(User {
        uid,
        gid,
        name: cname,
        home: PathBuf::from(std::ffi::OsStr::from_bytes(&home)),
    })
}

const MAX_SALT_BYTES: u64 = 4096;
const SALT_RELPATH: &str = ".local/share/kwalletd/kdewallet.salt";

enum SaltReadError {
    Absent,
    Failed,
}

fn read_salt_mode(user: &str) -> Result<irlume_common::SecretBytes, SaltReadError> {
    let pw = lookup_salt_user(user, lookup_user)?;
    enter_user(&pw).map_err(|_| SaltReadError::Failed)?;
    read_salt_at(&pw.home.join(SALT_RELPATH))
}

fn lookup_salt_user(
    user: &str,
    lookup: impl FnOnce(&str) -> Result<User, String>,
) -> Result<User, SaltReadError> {
    if user.is_empty()
        || user.len() > 255
        || user.starts_with('-')
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
    {
        return Err(SaltReadError::Failed);
    }
    lookup(user).map_err(|_| SaltReadError::Failed)
}

fn read_salt_at(path: &std::path::Path) -> Result<irlume_common::SecretBytes, SaltReadError> {
    use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SaltReadError::Absent
            } else {
                SaltReadError::Failed
            }
        })?;
    let meta = file.metadata().map_err(|_| SaltReadError::Failed)?;
    if !meta.file_type().is_file() || meta.file_type().is_fifo() || meta.len() > MAX_SALT_BYTES {
        return Err(SaltReadError::Failed);
    }
    let mut raw = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_SALT_BYTES)
        .read_to_end(&mut raw)
        .map_err(|_| SaltReadError::Failed)?;
    if raw.len() < SALT_LEN {
        return Err(SaltReadError::Failed);
    }
    raw.truncate(SALT_LEN);
    Ok(irlume_common::SecretBytes::new(raw))
}

#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "libc credential queries have no Rust wrapper"
)]
fn enter_user(pw: &User) -> Result<(), String> {
    let (ruid, euid, rgid, egid) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if ruid == 0 && euid == 0 && rgid == 0 && egid == 0 {
        drop_privileges(pw)?;
    } else if ruid != pw.uid || euid != pw.uid || rgid != pw.gid || egid != pw.gid {
        return Err("mixed or wrong credentials".into());
    }
    clear_capabilities()?;
    verify_credentials(pw)
}

#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "Linux capability operations have no libc wrapper"
)]
fn clear_capabilities() -> Result<(), String> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err("could not clear capabilities".into());
    }
    Ok(())
}

#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "Linux credential and capability queries have no safe wrapper"
)]
fn verify_credentials(pw: &User) -> Result<(), String> {
    let mut uids = [0; 3];
    let mut gids = [0; 3];
    if unsafe { libc::getresuid(&mut uids[0], &mut uids[1], &mut uids[2]) } != 0
        || unsafe { libc::getresgid(&mut gids[0], &mut gids[1], &mut gids[2]) } != 0
        || uids != [pw.uid; 3]
        || gids != [pw.gid; 3]
    {
        return Err("saved credentials retained".into());
    }
    let fsuid = unsafe { libc::setfsuid(libc::uid_t::MAX) };
    let fsgid = unsafe { libc::setfsgid(libc::gid_t::MAX) };
    if fsuid as libc::uid_t != pw.uid || fsgid as libc::gid_t != pw.gid {
        return Err("filesystem credentials differ".into());
    }
    verify_groups(pw)?;
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0
        || data
            .iter()
            .any(|x| x.effective != 0 || x.permitted != 0 || x.inheritable != 0)
    {
        return Err("capabilities retained".into());
    }
    for capability in 0..64 {
        let held = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            )
        };
        if held > 0 {
            return Err("ambient capability retained".into());
        }
    }
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "libc group-list queries have no Rust wrapper"
)]
fn verify_groups(pw: &User) -> Result<(), String> {
    let mut count = 0;
    unsafe { libc::getgrouplist(pw.name.as_ptr(), pw.gid, std::ptr::null_mut(), &mut count) };
    if count <= 0 {
        return Err("account groups unavailable".into());
    }
    let mut expected = vec![0; count as usize];
    if unsafe { libc::getgrouplist(pw.name.as_ptr(), pw.gid, expected.as_mut_ptr(), &mut count) }
        < 0
    {
        return Err("account groups changed".into());
    }
    expected.truncate(count as usize);
    let actual_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if actual_count < 0 {
        return Err("process groups unavailable".into());
    }
    let mut actual = vec![0; actual_count as usize];
    if unsafe { libc::getgroups(actual_count, actual.as_mut_ptr()) } < 0 {
        return Err("process groups unavailable".into());
    }
    expected.sort_unstable();
    expected.dedup();
    actual.sort_unstable();
    actual.dedup();
    if actual != expected {
        return Err("supplementary groups differ".into());
    }
    Ok(())
}

/// Whether this process holds privilege that the environment must not steer.
/// The same check `irlume-gkr-unlock` applies to its two overrides.
fn privileged() -> bool {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let (euid, uid) = unsafe { (libc::geteuid(), libc::getuid()) };
    euid == 0 || uid == 0
}

fn wallet_daemon() -> Result<CString, String> {
    // The override names a binary this program EXECS while holding the
    // TPM-released wallet key. `secure_getenv` in the PAM parent does not cover
    // it: AT_SECURE is a property of one execve, and this helper is not setuid,
    // so its own AT_SECURE is 0 no matter how the parent was entered. The
    // sibling helper refuses its environment overrides when privileged and this
    // one, which is the one that execs, did not.
    if let Some(over) = std::env::var_os("IRLUME_KSECRETD") {
        if privileged() {
            return Err(
                "IRLUME_KSECRETD is ignored when running privileged; it names a \
                 binary this helper would exec while holding the wallet key"
                    .into(),
            );
        }
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

/// Bind and listen on the handoff socket.
///
/// Runs unprivileged, so the socket is created owned by the user and there is
/// no second pathname resolution to race. The previous version bound as root
/// and then chown()ed the path, which follows a final symlink and let the
/// directory's owner redirect it at any root-owned file.
fn bind_listener(path: &std::path::Path) -> Result<libc::c_int, String> {
    let bytes = path.as_os_str().as_bytes();
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
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
    // A real error here (a directory in the way, EACCES) must not be swallowed:
    // bind() would then fail with EADDRINUSE and the reason would be lost.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing the stale {}: {e}", path.display())),
    }

    // SAFETY: addr is fully initialised above and the length is the real size.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        unsafe {
            libc::close(fd)
        };
        return Err(format!("bind {}: {e}", path.display()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::listen(fd, 5) } < 0 {
        let e = std::io::Error::last_os_error();
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        unsafe {
            libc::close(fd)
        };
        return Err(format!("listen: {e}"));
    }
    Ok(fd)
}

fn make_pipe() -> Result<(libc::c_int, libc::c_int), String> {
    let mut fds = [0 as libc::c_int; 2];
    // Plain pipe(), not O_CLOEXEC: the read end must survive execve into
    // ksecretd, which is handed its number on the command line.
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

/// Everything `execve` needs, built in the PARENT before `fork`.
///
/// The child of a fork may call only async-signal-safe functions when the
/// parent is multi-threaded, and `getpwuid`, `format!` and `CString::new` are
/// none of those: `getpwuid` goes through NSS, which can `dlopen`, allocate and
/// take locks the child may inherit held. This helper is single-threaded at the
/// fork, so the previous version was not deadlocking, but it depended on that
/// staying true and on a SAFETY comment that was false as written (#363).
///
/// Self-referential by construction: `argv`/`envp` hold pointers into the
/// `CString`s beside them. That is sound because a `CString`'s bytes live on the
/// heap, so moving this struct moves the `Vec` headers and not the buffers the
/// pointers name. Nothing may push to or reallocate the owning vectors after
/// the pointers are taken, which is why they are private and built once.
struct LaunchPlan {
    _argv_owned: Vec<CString>,
    _envp_owned: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
}

impl LaunchPlan {
    fn build(
        exe: &CString,
        read_fd: libc::c_int,
        listen_fd: libc::c_int,
        sock_path: &std::path::Path,
    ) -> Result<Self, String> {
        // The drop already happened, so this is the target user's uid, which is
        // the one the wallet daemon must see.
        // SAFETY: getuid() cannot fail and touches no memory we own.
        let uid = unsafe { libc::getuid() };
        let cstr = |what: &str, v: String| {
            CString::new(v).map_err(|e| format!("{what} contains a NUL byte: {e}"))
        };

        let argv_owned = vec![
            exe.clone(),
            cstr("argv", "--pam-login".to_string())?,
            cstr("pipe fd", read_fd.to_string())?,
            cstr("socket fd", listen_fd.to_string())?,
        ];

        // Without LOGIN_ENV, ksecretd never calls checkPamModule() and its
        // argument parser rejects --pam-login as an unknown option. Verified: it
        // exits with "Unknown option 'pam-login'" when the variable is absent.
        //
        // The rest of the session environment (bus address, display) arrives
        // later over the socket; ksecretd is written to wait for exactly that.
        let envp_owned = vec![
            cstr(
                "wallet socket path",
                format!("{LOGIN_ENV}={}", sock_path.display()),
            )?,
            cstr("runtime dir", format!("XDG_RUNTIME_DIR=/run/user/{uid}"))?,
            cstr("home directory", format!("HOME={}", home_of(uid)))?,
            cstr("user name", format!("USER={}", name_of(uid)))?,
        ];

        let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|c| c.as_ptr()).collect();
        envp.push(std::ptr::null());

        Ok(Self {
            _argv_owned: argv_owned,
            _envp_owned: envp_owned,
            argv,
            envp,
        })
    }
}

/// The post-fork child: only `open`, `dup2`, `close`, `fcntl` and `execve`,
/// every one of them on the POSIX async-signal-safe list, all operating on
/// buffers [`LaunchPlan`] already built.
///
/// # Safety
///
/// Runs between `fork` and `execve`. Callers must not add anything here that
/// allocates, formats, panics or consults NSS.
unsafe fn child_exec(
    exe: &CString,
    read_fd: libc::c_int,
    listen_fd: libc::c_int,
    plan: &LaunchPlan,
) {
    // No privilege drop here: the parent already dropped, before it touched the
    // user-owned runtime directory at all.
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

    libc::execve(exe.as_ptr(), plan.argv.as_ptr(), plan.envp.as_ptr());
}

unsafe fn clear_cloexec(fd: libc::c_int) {
    let flags = libc::fcntl(fd, libc::F_GETFD);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }
}

fn name_of(uid: libc::uid_t) -> String {
    // SAFETY: read straight out of the static buffer before any other libc call.
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return String::new();
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
        .to_string_lossy()
        .into_owned()
}

fn home_of(uid: libc::uid_t) -> String {
    // SAFETY: read straight out of the static buffer before any other libc call.
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return String::new();
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) }
        .to_string_lossy()
        .into_owned()
}

fn write_all(fd: libc::c_int, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
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

#[cfg(test)]
mod tests {
    use super::{
        enter_user, lookup_salt_user, read_salt_at, read_wallet_key, verify_credentials,
        wipe_fork_child_key, write_salt_to, LaunchPlan, User, KEY_LEN, LOGIN_ENV, SALT_LEN,
    };
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt as _;

    #[test]
    #[ignore = "fresh-exec child invoked by wallet_stdin_does_not_buffer_key_bytes"]
    fn wallet_stdin_child() {
        let error = super::read_wallet_key_from_stdin().expect_err("oversized input must fail");
        assert!(error.contains("more than 56 bytes"));
        let mut remaining: libc::c_int = 0;
        // SAFETY: stdin is the parent-provided pipe and FIONREAD writes one int
        // through this valid pointer; it neither reads key bytes nor owns the fd.
        let result = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::FIONREAD, &mut remaining) };
        assert_eq!(result, 0);
        assert_eq!(
            remaining, 43,
            "only the key and one-byte probe may leave the pipe"
        );
    }

    #[test]
    fn wallet_stdin_does_not_buffer_key_bytes() {
        use std::io::Write as _;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tests::wallet_stdin_child"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(&[0x5a; 100]).unwrap();
        drop(input);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn wallet_key_input_is_exact_and_owned_by_a_wiping_buffer() {
        let exact = vec![0x41; KEY_LEN];
        let key: zeroize::Zeroizing<Vec<u8>> =
            read_wallet_key(std::io::Cursor::new(exact.clone())).unwrap();
        assert_eq!(&**key, &exact);

        let short = read_wallet_key(std::io::Cursor::new(vec![0x42; KEY_LEN - 1]))
            .expect_err("a partial key must fail");
        assert!(short.contains("expected 56 bytes"));

        let oversized = read_wallet_key(std::io::Cursor::new(vec![0x43; KEY_LEN + 1]))
            .expect_err("a 57th byte must fail");
        assert!(oversized.contains("more than 56 bytes"));

        struct FailedRead;
        impl std::io::Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic input failure"))
            }
        }
        let failed = read_wallet_key(FailedRead).expect_err("input errors must fail");
        assert!(failed.contains("synthetic input failure"));
    }

    #[test]
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "fork/pipe verify child-only zeroization and parent copy-on-write isolation"
    )]
    fn fork_child_wipes_its_key_without_changing_the_parent() {
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;

        let mut key = vec![0x5a; KEY_LEN];
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::close(fds[0]) };
            wipe_fork_child_key(&mut key);
            unsafe {
                libc::write(fds[1], key.as_ptr().cast(), key.len());
                libc::close(fds[1]);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let mut child_key = vec![0xff; KEY_LEN];
        reader.read_exact(&mut child_key).unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        assert_eq!(child_key, vec![0; KEY_LEN]);
        assert_eq!(key, vec![0x5a; KEY_LEN]);
    }

    #[test]
    #[ignore = "fresh-exec child invoked by salt_reader_boundaries"]
    fn salt_reader_child() {
        let path = std::env::var_os("IRLUME_TEST_SALT_PATH").expect("path");
        let expected = std::env::var("IRLUME_TEST_SALT_EXPECT").expect("expectation");
        match (read_salt_at(std::path::Path::new(&path)), expected.as_str()) {
            (Ok(salt), "ok") => assert_eq!(salt.expose(), &[7; SALT_LEN]),
            (Err(super::SaltReadError::Absent), "absent")
            | (Err(super::SaltReadError::Failed), "fail") => {}
            _ => panic!("unexpected salt-read result"),
        }
    }

    #[test]
    #[ignore = "fresh-exec child invoked by broken_reader_is_reported"]
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "pipe setup and ownership transfer require libc/raw-fd calls"
    )]
    fn salt_stdout_child() {
        use std::os::fd::FromRawFd as _;
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::close(fds[0]) }, 0);
        let writer = std::io::BufWriter::with_capacity(SALT_LEN * 2, unsafe {
            std::fs::File::from_raw_fd(fds[1])
        });
        let error = write_salt_to(writer, &[7; SALT_LEN]).expect_err("reader is closed");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn broken_reader_is_reported() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tests::salt_stdout_child"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn salt_lookup_accepts_the_daemons_machine_account_grammar_only() {
        let expected = User {
            uid: 123,
            gid: 456,
            name: CString::new("host$").unwrap(),
            home: "/synthetic/home".into(),
        };
        let found = lookup_salt_user("host$", |name| {
            assert_eq!(name, "host$");
            Ok(expected)
        })
        .unwrap_or_else(|_| panic!("a daemon-accepted machine account must reach NSS lookup"));
        assert_eq!(found.name.as_bytes(), b"host$");

        for invalid in ["bad/name", "bad\0name", "bad!name"] {
            assert!(
                lookup_salt_user(invalid, |_| panic!("invalid names must not reach NSS")).is_err()
            );
        }
    }

    fn child_result(path: &std::path::Path, expected: &str) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tests::salt_reader_child"])
            .env("IRLUME_TEST_SALT_PATH", path)
            .env("IRLUME_TEST_SALT_EXPECT", expected)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "mkfifo has no Rust standard-library wrapper"
    )]
    fn salt_reader_boundaries_run_in_fresh_processes() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let root = std::env::temp_dir().join(format!("irlume-salt-reader-{}", std::process::id()));
        let home = root.join("home");
        let outside = root.join("outside");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(outside.join("share/kwalletd")).unwrap();
        symlink(root.join("outside"), home.join(".local")).unwrap();
        let salt = outside.join("share/kwalletd/kdewallet.salt");
        let relocated_salt = home.join(".local/share/kwalletd/kdewallet.salt");
        std::fs::write(&salt, vec![7; SALT_LEN]).unwrap();
        child_result(&relocated_salt, "ok");
        std::fs::set_permissions(root.join("outside"), std::fs::Permissions::from_mode(0o0))
            .unwrap();
        child_result(&salt, "fail");
        std::fs::set_permissions(root.join("outside"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::write(&salt, vec![7; SALT_LEN - 1]).unwrap();
        child_result(&salt, "fail");
        std::fs::write(&salt, vec![7; 4097]).unwrap();
        child_result(&salt, "fail");
        std::fs::remove_file(&salt).unwrap();
        child_result(&salt, "absent");
        symlink("/dev/null", &salt).unwrap();
        child_result(&salt, "fail");
        std::fs::remove_file(&salt).unwrap();
        let c = CString::new(salt.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        child_result(&salt, "fail");
        std::fs::remove_file(&salt).unwrap();
        std::fs::create_dir(&salt).unwrap();
        child_result(&salt, "fail");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn credential_verifier_rejects_retained_or_wrong_identity() {
        let name = std::env::var("USER").unwrap();
        let current = super::lookup_user(&name).unwrap();
        enter_user(&current).expect("self mode must permanently normalize credentials");
        verify_credentials(&current).expect("ordinary login credentials are exact");
        let wrong = User {
            uid: current.uid.wrapping_add(1),
            gid: current.gid,
            name: current.name.clone(),
            home: current.home.clone(),
        };
        assert!(enter_user(&wrong).is_err());
    }

    /// Read back an argv/envp array the way `execve` would: pointers until NULL.
    ///
    /// # Safety
    /// `arr` must be a NUL-terminated array of valid C string pointers.
    unsafe fn read_back(arr: &[*const libc::c_char]) -> Vec<String> {
        let mut out = Vec::new();
        for &p in arr {
            if p.is_null() {
                break;
            }
            out.push(CStr::from_ptr(p).to_string_lossy().into_owned());
        }
        out
    }

    /// The plan the child execs must be complete and NUL-terminated, because
    /// the child can no longer build any of it (#363).
    #[test]
    fn the_plan_carries_a_terminated_argv_and_envp() {
        let exe = CString::new("/usr/bin/kwalletd6").unwrap();
        let plan = LaunchPlan::build(
            &exe,
            7,
            9,
            std::path::Path::new("/run/user/0/kwallet5.socket"),
        )
        .expect("plan builds");

        // SAFETY: both arrays were just built NUL-terminated by `build`.
        let (argv, envp) = unsafe { (read_back(&plan.argv), read_back(&plan.envp)) };

        assert_eq!(
            argv,
            ["/usr/bin/kwalletd6", "--pam-login", "7", "9"],
            "the fd numbers are passed positionally, so their order is the contract"
        );
        assert!(
            plan.argv.last().is_some_and(|p| p.is_null())
                && plan.envp.last().is_some_and(|p| p.is_null()),
            "execve reads until NULL; without it, it walks off the end"
        );
        // ksecretd rejects --pam-login as an unknown option when LOGIN_ENV is
        // absent, so its presence is load-bearing rather than cosmetic.
        assert!(
            envp.iter().any(|e| e.starts_with(&format!("{LOGIN_ENV}="))),
            "wallet socket path missing from envp: {envp:?}"
        );
        for key in ["XDG_RUNTIME_DIR=", "HOME=", "USER="] {
            assert!(
                envp.iter().any(|e| e.starts_with(key)),
                "{key} missing from envp: {envp:?}"
            );
        }
    }

    /// `argv`/`envp` must point at the `CString`s the plan OWNS, not at
    /// anything temporary.
    ///
    /// The first version of this test moved the plan into a `Box` and compared
    /// the strings read back before and after. That could not fail: if the
    /// pointers ever did dangle it would be reading freed memory, which
    /// typically still shows the old bytes, so it would have "proved"
    /// soundness by committing the undefined behaviour it was checking for
    /// (#363 review).
    ///
    /// Pointer IDENTITY is checkable without dereferencing anything. It catches
    /// the mistake that would actually be made here: building the arrays from a
    /// temporary rather than from the owned vectors. That a `CString`'s heap
    /// buffer does not move when the struct moves is a language guarantee, not
    /// something a test can establish.
    #[test]
    fn the_plans_pointers_name_the_strings_it_owns() {
        let exe = CString::new("/usr/bin/kwalletd6").unwrap();
        let plan = LaunchPlan::build(&exe, 3, 4, std::path::Path::new("/run/user/0/s.socket"))
            .expect("plan builds");

        assert_eq!(
            plan.argv.len(),
            plan._argv_owned.len() + 1,
            "one pointer per owned string, plus the NULL"
        );
        for (i, owned) in plan._argv_owned.iter().enumerate() {
            assert_eq!(plan.argv[i], owned.as_ptr(), "argv[{i}] left its owner");
        }
        for (i, owned) in plan._envp_owned.iter().enumerate() {
            assert_eq!(plan.envp[i], owned.as_ptr(), "envp[{i}] left its owner");
        }
    }
}
