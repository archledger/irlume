// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The lock every irlume path that changes PAM holds.
//!
//! It is `pam.lock` in [`crate::machine::ROOT_SESSION_DIR`], a directory only
//! root can write, at mode 0600, so no other account can open the file and
//! none can hold the lock. Releases before this one kept it at
//! [`LEGACY_PAM_LOCK`], which is still taken while one of them may be running
//! (see [`take_legacy_lock`]).

use std::fs::File;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Held for as long as a process is changing PAM. Released when dropped.
#[derive(Debug)]
pub(crate) struct PamLock {
    // Held for their Drop, which closes the descriptors and releases the locks.
    _file: File,
    _legacy: Option<File>,
}

/// The lock's file name in [`crate::machine::ROOT_SESSION_DIR`].
const LOCK_NAME: &str = "pam.lock";

/// Where releases before this one kept the PAM lock: `/run/lock`, which every
/// account can search, with the file at the default mode 0644.
pub(crate) const LEGACY_PAM_LOCK: &str = "/run/lock/irlume-pam.lock";

/// How long a PAM operation waits for a process holding [`LEGACY_PAM_LOCK`]
/// before it goes on without that lock. An earlier release holds it for one
/// `login` command or reconcile run; the longest of those load the SELinux
/// module and restart irlumed.
const LEGACY_WAIT: Duration = Duration::from_secs(60);

/// How often [`take_legacy_lock`] tries again while it waits.
const LEGACY_POLL: Duration = Duration::from_millis(100);

/// Take the exclusive lock every irlume path that changes PAM must hold.
///
/// Nothing serialised these before. `login apply`, `login rollback`, human
/// `login enable`/`disable`, and `reconcile` could all run at once, and the
/// combinations are not theoretical: the reconcile path unit fires when a PAM
/// file changes, which is exactly what the other three do. Two of them
/// interleaving produced a stack that was a mixture of both, and the record
/// written by either then described a machine state that never existed.
///
/// The lock covers the whole operation, not each write: revalidating a plan,
/// writing the prepared record, every PAM and sidecar write, and the confirming
/// record all have to be one indivisible unit, or the record still describes
/// something other than what is on disk.
///
/// `flock` is released by the kernel when the process exits however it exits, so
/// a killed irlume does not strand it. It does not exclude package managers or
/// an administrator with an editor: only irlume takes it, which is why every
/// path still re-checks the file it is about to write.
///
/// `IRLUME_PAM_LOCK` names another lock file for tests and containers, the same
/// way `IRLUME_STATE_DIR` overrides the state root; [`LEGACY_PAM_LOCK`] is then
/// left alone.
pub(crate) fn lock_pam() -> Result<PamLock, String> {
    let (path, legacy) = match std::env::var_os("IRLUME_PAM_LOCK") {
        Some(path) => (PathBuf::from(path), None),
        None => (
            Path::new(crate::machine::ROOT_SESSION_DIR).join(LOCK_NAME),
            Some(Path::new(LEGACY_PAM_LOCK)),
        ),
    };
    // The effective uid owns what this process creates, so it is the one the
    // directory and the lock are checked against: root for every caller that
    // changes PAM.
    // SAFETY: geteuid cannot fail and touches no memory.
    let uid = unsafe { libc::geteuid() };
    let lock = lock_pam_at(&path, legacy, uid, LEGACY_WAIT)?;
    super::files::sweep_abandoned_scratch();
    Ok(lock)
}

/// [`lock_pam`] with the lock, the legacy lock, the owning uid and the wait
/// for the legacy lock passed in, so tests can use a sandbox for each.
fn lock_pam_at(
    path: &Path,
    legacy: Option<&Path>,
    uid: u32,
    legacy_wait: Duration,
) -> Result<PamLock, String> {
    let file = open_lock(path, uid)?;
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is owned by `file`, which outlives the call and the guard.
    let busy = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0;
    if busy {
        // Said on stderr, because machine output is JSON on stdout. Then wait:
        // refusing outright would make the reconcile path unit give up exactly
        // when an apply is in flight, which is when it most needs to run after.
        // Only processes running as `uid` can open the lock, so the wait lasts
        // as long as one of them holds it; the reconcile unit's start timeout
        // bounds it there.
        let holder = processes(&lock_holders(&file))
            .map(|who| format!(" ({who})"))
            .unwrap_or_default();
        eprintln!("irlume: another irlume PAM operation{holder} is in progress, waiting for it…");
        // SAFETY: as above.
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            return Err(format!(
                "lock {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    let legacy = legacy.and_then(|legacy| take_legacy_lock(legacy, uid, legacy_wait));
    Ok(PamLock {
        _file: file,
        _legacy: legacy,
    })
}

/// Opens the lock at `path`, creating its directory at 0700 and the file at
/// 0600 when they are missing.
///
/// The directory must not be a symlink, must be owned by `uid` and must grant
/// no write permission to group or others, so no other account can create,
/// replace or remove an entry in it. The file is resolved through the open
/// directory descriptor, so it lands in the directory just checked; `O_NOFOLLOW`
/// refuses a symlink at its name and `O_NONBLOCK` keeps a FIFO there from
/// stalling the open. It must be a regular file owned by `uid`, and group and
/// other permissions are removed from one that has them, so no other account
/// can open it and hold the lock.
fn open_lock(path: &Path, uid: u32) -> Result<File, String> {
    let (Some(dir), Some(name)) = (
        path.parent().filter(|dir| !dir.as_os_str().is_empty()),
        path.file_name(),
    ) else {
        return Err(format!("{}: not a file in a directory", path.display()));
    };
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("create {}: {error}", dir.display())),
    }
    let dir_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|error| format!("open {}: {error}", dir.display()))?;
    let meta = dir_file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", dir.display()))?;
    if meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is owned by uid {} with mode {:o}; the PAM lock needs a directory \
             owned by uid {uid} that no other account can write",
            dir.display(),
            meta.uid(),
            meta.mode() & 0o7777
        ));
    }
    let at = Path::new("/proc/self/fd")
        .join(dir_file.as_raw_fd().to_string())
        .join(name);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&at)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?;
    if !meta.is_file() || meta.uid() != uid {
        return Err(format!(
            "{} is not a regular file owned by uid {uid}",
            path.display()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod {}: {error}", path.display()))?;
    }
    Ok(file)
}

/// Also take `path`, the lock releases before this one took, so a PAM operation
/// of one of them still running, as during a package upgrade, cannot interleave
/// with this one. `None` when there is nothing to take or it is not taken.
///
/// Only an existing regular file owned by `uid` is considered: one of those
/// releases, running as root, created it. A file another account created is not
/// one such a release can lock (where `/run/lock` is world-writable, as on
/// Debian and Ubuntu, the kernel's `protected_regular` setting refuses root's
/// open of it). The file is opened read-only, never created, and without
/// following a symlink, and group and other permissions are removed from it, so
/// an account that has not opened it by then cannot.
///
/// Any account could open the file before, so a process holding it is not
/// necessarily an irlume: it is waited for at most `wait`, named on stderr, and
/// the operation then goes on without this lock.
fn take_legacy_lock(path: &Path, uid: u32, wait: Duration) -> Option<File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != uid {
        return None;
    }
    if meta.mode() & 0o077 != 0 {
        // Best effort: the lock is taken either way.
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    let deadline = Instant::now() + wait;
    let mut waiting = false;
    loop {
        // SAFETY: the descriptor is owned by `file`, which outlives the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Some(file);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
            return None;
        }
        let by = || {
            processes(&lock_holders(&file))
                .map(|who| format!(" by {who}"))
                .unwrap_or_default()
        };
        let now = Instant::now();
        if now >= deadline {
            eprintln!(
                "irlume: {} is still held{}; going on without it",
                path.display(),
                by()
            );
            return None;
        }
        if !waiting {
            eprintln!(
                "irlume: {}, the PAM lock of earlier irlume releases, is held{}; \
                 waiting up to {} s for it…",
                path.display(),
                by(),
                wait.as_secs()
            );
            waiting = true;
        }
        std::thread::sleep(LEGACY_POLL.min(deadline - now));
    }
}

/// `process 1234` or `processes 1234, 5678`, or `None` for no processes.
fn processes(pids: &[u32]) -> Option<String> {
    match pids {
        [] => None,
        [pid] => Some(format!("process {pid}")),
        _ => Some(format!(
            "processes {}",
            pids.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The processes `/proc/locks` lists as holding a `flock` lock on `file`, or
/// none when that cannot be read.
fn lock_holders(file: &File) -> Vec<u32> {
    let (Ok(meta), Some(device), Ok(locks)) = (
        file.metadata(),
        superblock_device(file),
        std::fs::read_to_string("/proc/locks"),
    ) else {
        return Vec::new();
    };
    flock_holders(&locks, device, meta.ino())
}

/// The device number of the filesystem `file` is on, as `/proc/locks` gives it:
/// the superblock's, which `/proc/self/mountinfo` lists for the file's mount.
/// `stat` does not report it on every filesystem (btrfs gives each subvolume a
/// device of its own).
fn superblock_device(file: &File) -> Option<(u32, u32)> {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).ok()?;
    let mount = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))?
        .trim()
        .to_owned();
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    mountinfo.lines().find_map(|line| {
        // Mount id, parent id, then `major:minor`.
        let mut fields = line.split_whitespace();
        if fields.next()? != mount {
            return None;
        }
        let (major, minor) = fields.nth(1)?.split_once(':')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    })
}

/// The processes `locks`, in the format of `/proc/locks`, lists as holding a
/// `flock` lock on inode `ino` of the filesystem `device`.
///
/// A line such as `1: FLOCK  ADVISORY  WRITE 1234 00:1a:5678 0 EOF` gives the
/// holder's pid just before the device (major and minor in hex) and the inode.
/// A line with `->` is a process waiting for the lock, not holding it, and a
/// holder outside this PID namespace is listed as 0 or not at all.
fn flock_holders(locks: &str, device: (u32, u32), ino: u64) -> Vec<u32> {
    let wanted = format!("{:02x}:{:02x}:{ino}", device.0, device.1);
    let mut pids = Vec::new();
    for line in locks.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.contains(&"->") || !fields.contains(&"FLOCK") {
            continue;
        }
        let Some(at) = fields.iter().position(|field| *field == wanted) else {
            continue;
        };
        let pid = at
            .checked_sub(1)
            .and_then(|before| fields[before].parse::<u32>().ok())
            .filter(|&pid| pid != 0);
        if let Some(pid) = pid {
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
    }
    pids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, ChildStdin, Command, Stdio};

    fn uid() -> u32 {
        // SAFETY: geteuid cannot fail and touches no memory.
        unsafe { libc::geteuid() }
    }

    /// A private directory for one test, removed when dropped. Its mode is set
    /// explicitly, so the tests do not depend on the umask they run under.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("irlume-pamlock-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).expect("create the scratch directory");
            set_mode(&dir, 0o700);
            Self(dir)
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }

        /// A directory in the scratch area with `mode`.
        fn dir(&self, rel: &str, mode: u32) -> PathBuf {
            let dir = self.path(rel);
            std::fs::create_dir(&dir).expect("create a directory");
            set_mode(&dir, mode);
            dir
        }

        /// An empty file in the scratch area with `mode`.
        fn file(&self, rel: &str, mode: u32) -> PathBuf {
            let file = self.path(rel);
            std::fs::write(&file, "").expect("create a file");
            set_mode(&file, mode);
            file
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).expect("stat").mode() & 0o7777
    }

    /// Whether some process holds a lock on `path`: `flock -n` fails when it
    /// cannot take one. Asked of a separate process, because two opens in one
    /// process do not exclude each other the way two processes do.
    fn held(path: &Path) -> bool {
        !Command::new("flock")
            .arg("-n")
            .arg(path)
            .arg("true")
            .status()
            .expect("run flock")
            .success()
    }

    /// A `flock` process holding `path` until dropped. `-o` keeps the lock out
    /// of the `cat` it runs, so the lock is `flock`'s own and goes when `cat`
    /// ends at the end of its input.
    struct Holder {
        child: Child,
        input: Option<ChildStdin>,
    }

    impl Holder {
        fn new(path: &Path) -> Self {
            let mut child = Command::new("flock")
                .args(["-o", "-x"])
                .arg(path)
                .arg("cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .expect("run flock");
            let input = child.stdin.take();
            let holder = Self { child, input };
            let deadline = Instant::now() + Duration::from_secs(10);
            while !held(path) {
                assert!(
                    Instant::now() < deadline,
                    "flock never took {}",
                    path.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            holder
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }
    }

    impl Drop for Holder {
        fn drop(&mut self) {
            drop(self.input.take());
            let _ = self.child.wait();
        }
    }

    /// The directory is created 0700 and the lock 0600, so no other account can
    /// open the lock, and the lock excludes another process until it is dropped.
    #[test]
    fn creates_the_directory_0700_and_the_lock_0600() {
        let scratch = Scratch::new("create");
        let path = scratch.path("run/pam.lock");
        let lock = lock_pam_at(&path, None, uid(), Duration::ZERO).expect("take the lock");
        assert_eq!(mode(&scratch.path("run")), 0o700);
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(mode(&path), 0o600);
        assert!(held(&path), "the lock is held while the guard lives");
        drop(lock);
        assert!(!held(&path), "the lock was not released when dropped");
    }

    /// A lock file that group or others could open loses those permissions.
    #[test]
    fn removes_group_and_other_permissions_from_an_existing_lock() {
        let scratch = Scratch::new("tighten");
        scratch.dir("run", 0o700);
        let path = scratch.file("run/pam.lock", 0o644);
        let _lock = lock_pam_at(&path, None, uid(), Duration::ZERO).expect("take the lock");
        assert_eq!(mode(&path), 0o600);
    }

    /// A symlink at the lock's name is refused, and its target is neither
    /// created nor locked.
    #[test]
    fn refuses_a_symlink_at_the_lock() {
        let scratch = Scratch::new("symlink");
        scratch.dir("run", 0o700);
        let target = scratch.path("elsewhere");
        std::os::unix::fs::symlink(&target, scratch.path("run/pam.lock")).unwrap();
        let refused = lock_pam_at(&scratch.path("run/pam.lock"), None, uid(), Duration::ZERO);
        assert!(refused.is_err(), "a symlinked lock was taken");
        assert!(!target.exists(), "the symlink was followed");
    }

    /// A FIFO at the lock's name is refused at once. Opening one for writing
    /// waits for a reader, so without `O_NONBLOCK` this would never return.
    #[test]
    fn refuses_a_fifo_at_the_lock_without_waiting() {
        let scratch = Scratch::new("fifo");
        scratch.dir("run", 0o700);
        let path = scratch.path("run/pam.lock");
        let made = Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo failed");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(lock_pam_at(&path, None, uid(), Duration::ZERO).is_err());
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)),
            Ok(true),
            "a FIFO at the lock's name must be refused without blocking"
        );
    }

    /// A directory group or others can write, including a sticky one as `/tmp`
    /// is, or one reached through a symlink, is refused, and nothing is created
    /// in it.
    #[test]
    fn refuses_a_directory_other_accounts_can_write_or_a_symlinked_one() {
        let scratch = Scratch::new("dir");
        for loose in [0o770, 0o757, 0o777, 0o1777] {
            let dir = scratch.dir(&format!("loose-{loose:o}"), loose);
            let refused = lock_pam_at(&dir.join("pam.lock"), None, uid(), Duration::ZERO)
                .expect_err("a directory other accounts can write must be refused");
            assert!(refused.contains("no other account can write"), "{refused}");
            assert!(
                !dir.join("pam.lock").exists(),
                "{loose:o}: created the lock"
            );
        }
        let real = scratch.dir("real", 0o700);
        std::os::unix::fs::symlink(&real, scratch.path("link")).unwrap();
        let refused = lock_pam_at(&scratch.path("link/pam.lock"), None, uid(), Duration::ZERO);
        assert!(refused.is_err(), "a symlinked directory was used");
        assert!(!real.join("pam.lock").exists(), "the symlink was followed");
    }

    /// A directory another account owns is refused.
    #[test]
    fn refuses_a_directory_another_account_owns() {
        let scratch = Scratch::new("owner");
        let other = uid().wrapping_add(1);
        let refused = lock_pam_at(&scratch.path("run/pam.lock"), None, other, Duration::ZERO)
            .expect_err("a directory another account owns must be refused");
        assert!(
            refused.contains(&format!("owned by uid {other}")),
            "{refused}"
        );
        assert!(!scratch.path("run/pam.lock").exists());
    }

    /// The process holding a lock is found, so the waiting message can name it,
    /// and it is no longer named once it has let go.
    #[test]
    fn names_the_process_holding_a_lock() {
        let scratch = Scratch::new("holder");
        let path = scratch.file("pam.lock", 0o600);
        let file = File::open(&path).unwrap();
        let holder = Holder::new(&path);
        assert_eq!(lock_holders(&file), vec![holder.pid()]);
        assert_eq!(
            processes(&lock_holders(&file)),
            Some(format!("process {}", holder.pid()))
        );
        drop(holder);
        assert_eq!(lock_holders(&file), Vec::<u32>::new());
    }

    /// Only the holders of `flock` locks on the one file count: not a process
    /// waiting for the lock, a POSIX or OFD lock, another device or inode, or a
    /// holder outside this PID namespace.
    #[test]
    fn reads_the_holders_of_one_file_from_proc_locks() {
        let locks = "\
1: FLOCK  ADVISORY  WRITE 4242 00:1a:777 0 EOF
1: -> FLOCK  ADVISORY  WRITE 4343 00:1a:777 0 EOF
2: POSIX  ADVISORY  WRITE 4444 00:1a:777 0 EOF
3: FLOCK  ADVISORY  WRITE 4545 00:1b:777 0 EOF
4: FLOCK  ADVISORY  WRITE 4646 00:1a:7777 0 EOF
5: FLOCK  ADVISORY  READ 0 00:1a:777 0 EOF
6: OFDLCK ADVISORY  WRITE -1 00:1a:777 0 EOF
7: FLOCK  ADVISORY  READ 4747 00:1a:777 0 EOF
7: FLOCK  ADVISORY  READ 4747 00:1a:777 0 EOF
8: FLOCK  ADVISORY  WRITE 4848 103:1f4:777 0 EOF
";
        assert_eq!(flock_holders(locks, (0, 0x1a), 777), vec![4242, 4747]);
        assert_eq!(flock_holders(locks, (0x103, 0x1f4), 777), vec![4848]);
        assert_eq!(flock_holders(locks, (0, 0x1a), 77), Vec::<u32>::new());
        assert_eq!(processes(&[]), None);
        assert_eq!(
            processes(&[4242, 4747]),
            Some("processes 4242, 4747".to_owned())
        );
    }

    /// While a process holds the lock of earlier releases, a PAM operation waits
    /// for it and then holds that lock too, so an earlier release's operation
    /// still running during an upgrade and this one cannot interleave. The file
    /// loses its group and other permissions.
    #[test]
    fn waits_for_the_legacy_lock_and_then_holds_it() {
        let scratch = Scratch::new("legacy-wait");
        let legacy = scratch.file("irlume-pam.lock", 0o644);
        let holder = Holder::new(&legacy);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(700));
            drop(holder);
        });
        let started = Instant::now();
        let lock = lock_pam_at(
            &scratch.path("run/pam.lock"),
            Some(&legacy),
            uid(),
            Duration::from_secs(30),
        )
        .expect("take the lock");
        let waited = started.elapsed();
        release.join().unwrap();
        assert!(
            waited >= Duration::from_millis(500),
            "returned after {waited:?}, while the legacy lock was still held"
        );
        assert!(held(&legacy), "the legacy lock is held with the lock");
        assert_eq!(mode(&legacy), 0o600);
        drop(lock);
        assert!(
            !held(&legacy),
            "the legacy lock was not released when dropped"
        );
    }

    /// A process holding the legacy lock is waited for only as long as the
    /// limit: the operation then goes on, holding its own lock.
    #[test]
    fn stops_waiting_for_the_legacy_lock_at_the_limit() {
        let scratch = Scratch::new("legacy-limit");
        let legacy = scratch.file("irlume-pam.lock", 0o600);
        let holder = Holder::new(&legacy);
        let path = scratch.path("run/pam.lock");
        let started = Instant::now();
        let lock = lock_pam_at(&path, Some(&legacy), uid(), Duration::from_millis(300))
            .expect("take the lock");
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(300) && waited < Duration::from_secs(10),
            "waited {waited:?} for a limit of 300 ms"
        );
        assert!(held(&path), "the lock itself is held");
        drop(lock);
        drop(holder);
    }

    /// The legacy lock is left alone when it is missing (it is not created), a
    /// symlink (its target is not touched) or a file another account owns (not
    /// waited for, however long it is held, and not changed).
    #[test]
    fn leaves_a_missing_symlinked_or_foreign_legacy_lock_alone() {
        let scratch = Scratch::new("legacy-skip");
        let long = Duration::from_secs(30);
        let missing = scratch.path("missing.lock");
        assert!(take_legacy_lock(&missing, uid(), long).is_none());
        assert!(!missing.exists(), "a missing legacy lock was created");

        let target = scratch.file("target", 0o644);
        let link = scratch.path("link.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(take_legacy_lock(&link, uid(), long).is_none());
        assert_eq!(mode(&target), 0o644, "the symlink's target was changed");
        assert!(!held(&target), "the symlink's target was locked");

        let foreign = scratch.file("foreign.lock", 0o644);
        let holder = Holder::new(&foreign);
        let started = Instant::now();
        assert!(take_legacy_lock(&foreign, uid().wrapping_add(1), long).is_none());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited for a legacy lock another account owns"
        );
        assert_eq!(mode(&foreign), 0o644, "another account's file was changed");
        drop(holder);
    }
}
