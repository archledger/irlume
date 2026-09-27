// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The lock every irlume path that changes PAM holds.
//!
//! It is `pam.lock` in [`crate::machine::ROOT_SESSION_DIR`], a directory only
//! root can write, at mode 0600, so no other account can open the file and
//! none can hold the lock. Releases before this one kept it at
//! [`LEGACY_PAM_LOCK`], which is still taken while one of them may be running:
//! created when it is missing, and replaced by root's own file when another
//! account owns it (see [`take_legacy_lock`]).

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
    _legacy: Vec<File>,
}

/// The lock's file name in [`crate::machine::ROOT_SESSION_DIR`].
const LOCK_NAME: &str = "pam.lock";

/// Where releases before this one kept the PAM lock: `/run/lock`, which every
/// account can search, with the file at the default mode 0644.
const LEGACY_PAM_LOCK: &str = "/run/lock/irlume-pam.lock";

/// How long a PAM operation waits for a process holding [`LEGACY_PAM_LOCK`].
/// An earlier release holds it for one `login` command or reconcile run; the
/// longest of those load the SELinux module and restart irlumed. After that
/// the operation stops, or goes on without the lock when the holder cannot be
/// an earlier irlume (see [`take_legacy_lock`]).
const LEGACY_WAIT: Duration = Duration::from_secs(60);

/// How often [`take_legacy_lock`] tries again while it waits.
const LEGACY_POLL: Duration = Duration::from_millis(100);

/// How many times [`open_legacy_lock`] tries to create or open
/// [`LEGACY_PAM_LOCK`] when the name is removed between the two, and
/// [`claim_legacy_name`] tries to find a free name for its file or to put that
/// file at the name.
const LEGACY_OPEN_TRIES: usize = 8;

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
        let holder = lock_holders(&file)
            .and_then(|pids| processes(&pids))
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
    let legacy = match legacy {
        Some(legacy) => take_legacy_lock(legacy, uid, legacy_wait)?,
        None => Vec::new(),
    };
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
/// with this one. Returns the files whose lock this operation then holds, none
/// when there is nothing to take or it is not taken.
///
/// The file is opened, or created when it is missing, by [`open_legacy_lock`]:
/// one of those releases that has started but not yet reached its lock then
/// opens the same file and waits for this operation, where it would otherwise
/// create a file of its own and lock it while this operation runs. A file
/// another account owns is waited for as below while it keeps the name, and
/// only then replaced there by one of this operation's own, already locked
/// ([`replace_legacy_lock`]); any other file the replacement takes off the
/// name is waited for within the same `wait`.
///
/// Any account could open the file before, so a process holding it is not
/// necessarily an irlume: it is waited for at most `wait` and named on stderr.
/// If a process running as `uid` with the file open still holds it then, or
/// waits for it, it may be an earlier irlume changing PAM or about to, and the
/// operation stops with an error rather than write beside it. It stops too
/// when `/proc` cannot show that no holder or waiter is such a process (see
/// [`earlier_irlumes`]). Otherwise the holder is another account's process, or
/// one that has exited while another keeps the file open, and the operation
/// goes on without this lock.
fn take_legacy_lock(path: &Path, uid: u32, wait: Duration) -> Result<Vec<File>, String> {
    let deadline = Instant::now() + wait;
    let wait_for = |file| wait_for_legacy_lock(path, file, uid, wait, deadline);
    match open_legacy_lock(path, uid)? {
        LegacyLock::Own(file) => Ok(wait_for(file)?.into_iter().collect()),
        LegacyLock::Foreign(found) => replace_legacy_lock(path, &found, wait_for),
    }
}

/// The refusal for a symlink, FIFO, socket or device at the name of the lock of
/// earlier releases ([`open_legacy_lock`]).
fn not_a_lock_file(path: &Path, meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::FileTypeExt;
    let kind = meta.file_type();
    let what = if kind.is_symlink() {
        "a symlink"
    } else if kind.is_fifo() {
        "a FIFO"
    } else if kind.is_socket() {
        "a socket"
    } else if kind.is_dir() {
        "a directory"
    } else {
        "a device"
    };
    format!(
        "{} is {what}, not the lock file earlier releases use, and one of them may hold a lock \
         through it; remove it (`sudo rm {}`) and run this again",
        path.display(),
        path.display()
    )
}

/// What [`open_legacy_lock`] found at the name of the lock of earlier releases.
#[derive(Debug)]
enum LegacyLock {
    /// A regular file `uid` owns, or one just created, opened for reading.
    Own(File),
    /// Whatever another account owns at the name, opened with `O_PATH` and
    /// not followed, for [`replace_legacy_lock`].
    Foreign(File),
}

/// Opens `path`, the lock of earlier releases, the file one of them running now
/// would lock, creating it at 0600 when it is missing. A symlink or anything
/// else that is not a regular file, owned by `uid`, stops the operation.
///
/// It is created with `O_EXCL`, which neither follows a symlink nor opens a
/// file another process created first, in a directory created at 0755 when
/// missing, as those releases did. A file that exists is first opened with
/// `O_PATH` and without following a symlink, which does not wait and does not
/// open a FIFO or a socket, and only a regular file is then opened for reading,
/// here or by [`replace_legacy_lock`], through that descriptor, so it is the
/// file just checked. That open waits
/// while another process holds a write lease on the file, as the open of those
/// releases did, where an open that does not wait fails: the kernel asks the
/// holder to give the lease up and, after `/proc/sys/fs/lease-break-time` (45 s
/// by default), reduces it to a read lease, which does not delay a reader. No
/// write lease can be taken on the file while it is open. When the name is
/// removed between creating and opening it, creating it is tried again. Any
/// other error opening or creating it stops the operation, as it stopped those
/// releases.
///
/// A symlink `uid` owns, or a FIFO, a socket or a device, stops the
/// operation with the command that removes it: an earlier release opened the
/// name with an ordinary open, so it may have followed the symlink or opened
/// the FIFO and hold its lock, which this operation cannot take or wait for.
/// Only root can create one where `/run/lock` is root's alone, and only root
/// can remove one where every account can write it, since the directory is
/// sticky, so no account can make an operation stop this way.
///
/// Group and other permissions are removed from a file owned by `uid`, so an
/// account that has not opened it by then cannot. Whatever another account
/// owns at the name is returned as the `O_PATH` descriptor, not changed, for
/// [`replace_legacy_lock`], which waits for a regular file there and then puts
/// a file of this operation's own at the name, since that account can remove
/// its own at any time. A symlink is not followed, and `protected_symlinks`,
/// which systemd turns on, keeps an earlier release running as root from
/// following it either. A regular file is waited for, since where
/// `protected_regular` is off an earlier release running as root opens it and
/// locks it. That account can hold a lease on it and then its lock, and so
/// delay each operation by up to the lease break time and [`LEGACY_WAIT`], as
/// an account that opened the 0644 file of those releases can delay them; it
/// cannot stop one, since its process is not an earlier irlume (see
/// [`take_legacy_lock`]).
fn open_legacy_lock(path: &Path, uid: u32) -> Result<LegacyLock, String> {
    for _ in 0..LEGACY_OPEN_TRIES {
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path);
        let file = match created {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let found = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path);
                let found = match found {
                    Ok(found) => found,
                    // Removed since the create found it.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(format!("open {}: {error}", path.display())),
                };
                let meta = found
                    .metadata()
                    .map_err(|error| format!("stat {}: {error}", path.display()))?;
                if meta.uid() != uid {
                    return Ok(LegacyLock::Foreign(found));
                }
                if !meta.is_file() {
                    return Err(not_a_lock_file(path, &meta));
                }
                open_for_reading(path, &found)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let dir = path.parent().unwrap_or(Path::new("/"));
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o755)
                    .create(dir)
                    .map_err(|error| format!("create {}: {error}", dir.display()))?;
                continue;
            }
            Err(error) => return Err(format!("create {}: {error}", path.display())),
        };
        let meta = file
            .metadata()
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        if !meta.is_file() {
            return Err(not_a_lock_file(path, &meta));
        }
        if meta.uid() == uid && meta.mode() & 0o077 != 0 {
            // Best effort: the lock is taken either way.
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        return Ok(LegacyLock::Own(file));
    }
    Err(format!(
        "{} or its directory was removed each time it was opened, {LEGACY_OPEN_TRIES} times",
        path.display()
    ))
}

/// Opens `found`, a regular file opened with `O_PATH`, for reading, through
/// that descriptor. Without `O_NONBLOCK`, so a lease on the file is waited for
/// as [`open_legacy_lock`] says.
fn open_for_reading(path: &Path, found: &File) -> Result<File, String> {
    let at = Path::new("/proc/self/fd").join(found.as_raw_fd().to_string());
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(&at)
        .map_err(|error| format!("open {}: {error}", path.display()))
}

/// Takes the lock of earlier releases at `path` where another account owns
/// `found`, what is at the name, opened with `O_PATH`. Returns the files whose
/// lock this operation then holds.
///
/// A regular file there is waited for first, with `wait_for`, as
/// [`take_legacy_lock`] says, while it keeps the name: an earlier release that
/// opens `path` meanwhile opens that file and waits for its holder, and the
/// name is unchanged when the operation stops there or is killed. Only then
/// does [`claim_legacy_name`] put a file of this operation's own at the name.
/// A symlink, a FIFO or anything else there is not waited for.
fn replace_legacy_lock(
    path: &Path,
    found: &File,
    mut wait_for: impl FnMut(File) -> Result<Option<File>, String>,
) -> Result<Vec<File>, String> {
    let meta = found
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?;
    let mut held = Vec::new();
    if meta.is_file() {
        held.extend(wait_for(open_for_reading(path, found)?)?);
    }
    held.extend(claim_legacy_name(path, &meta, wait_for)?);
    Ok(held)
}

/// Puts a file of this operation's own, created at 0600 and locked, at `path`
/// in place of `found`, what another account owns there, so an earlier
/// release that opens `path` from then on waits for this operation. Returns
/// that file, then any other whose lock `wait_for` took.
///
/// In a directory every account can write, as `/run/lock` is on Debian and
/// Ubuntu, the sticky bit lets that account rename or remove its own file at
/// any time, even while this operation holds its lock; an earlier release
/// starting after that creates or opens another file at the name and locks it
/// while this operation runs. No account but root can rename or remove a file
/// root owns there, so this operation's file keeps the name. It is left there
/// afterwards, as a created legacy lock is.
///
/// The file is created beside `path` under a name of its own, with `O_EXCL`
/// and `O_NOFOLLOW`, and exchanged with the name in one step
/// (`RENAME_EXCHANGE`), so a file put at the name after `found` was opened is
/// taken off it rather than unlinked unseen. When the name is missing, the
/// file takes it only while nothing else does (`RENAME_NOREPLACE`), and when
/// something does, the exchange is tried again, up to [`LEGACY_OPEN_TRIES`]
/// times.
///
/// What comes out keeps the other name until the operation is past it. A
/// regular file other than `found`, such as one an earlier release created and
/// locked after `found` was removed, is waited for with `wait_for`, as `found`
/// was, and removed from the other name only once that succeeds, as anything
/// else that comes out is at once. When the wait stops the operation, or what
/// came out cannot be opened, it is exchanged back ([`put_back`]), so the name
/// leads again to the file an earlier release may hold. A process that opened
/// the name while this operation's file was there still takes that file when
/// the operation stops, and an operation killed during the wait leaves its
/// file at the name and what came out at the other; both need that account to
/// change the name between `found` being opened and the exchange.
///
/// When the file cannot take the name, as on a filesystem without
/// `RENAME_EXCHANGE`, it is removed and the operation stops, since `found`
/// would still be the lock at the name.
fn claim_legacy_name(
    path: &Path,
    found: &std::fs::Metadata,
    wait_for: impl FnOnce(File) -> Result<Option<File>, String>,
) -> Result<Vec<File>, String> {
    let (file, temp) = create_claim_file(path)?;
    let give_up = |why: String| -> Result<Vec<File>, String> {
        remove_claim_file(&temp, &file);
        Err(why)
    };
    let mut exchanged = None;
    for _ in 0..LEGACY_OPEN_TRIES {
        match exchange_with_name(&temp, path) {
            Ok(()) => {
                exchanged = Some(true);
                break;
            }
            // Removed since `found` was opened: take the name while it is free.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => {
                return give_up(format!(
                    "{} is another account's file, on a filesystem that cannot swap two \
                     files in one step (RENAME_EXCHANGE), so irlume cannot replace it with \
                     a file only root can move; not changed",
                    path.display()
                ));
            }
            Err(error) => return give_up(format!("replace {}: {error}", path.display())),
        }
        match super::files::renameat2_noreplace(&temp, path) {
            Ok(()) => {
                exchanged = Some(false);
                break;
            }
            // Something took the name meanwhile: exchange with that.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return give_up(format!("rename into {}: {error}", path.display())),
        }
    }
    let Some(exchanged) = exchanged else {
        return give_up(format!(
            "{} was removed and created again each time irlume tried to replace it, \
             {LEGACY_OPEN_TRIES} times",
            path.display()
        ));
    };
    if !exchanged {
        return Ok(vec![file]);
    }
    let waited = match came_out(path, &temp, found) {
        Ok(CameOut::Gone) => return Ok(vec![file]),
        Ok(CameOut::Done) => Ok(None),
        Ok(CameOut::Other(other)) => open_for_reading(path, &other).and_then(wait_for),
        Err(why) => Err(why),
    };
    match waited {
        Ok(other) => {
            remove_came_out(&temp);
            Ok(std::iter::once(file).chain(other).collect())
        }
        Err(why) => {
            put_back(path, &temp, &file);
            Err(why)
        }
    }
}

/// Creates the file [`claim_legacy_name`] puts at `path`, beside it under a
/// random name that no other file has, and locks it. Returns it with that name.
fn create_claim_file(path: &Path) -> Result<(File, PathBuf), String> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    for _ in 0..LEGACY_OPEN_TRIES {
        let temp = dir.join(format!(
            ".{name}.{}.{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp);
        match created {
            Ok(file) => {
                // SAFETY: the descriptor is owned by `file`, which outlives the
                // call.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    let error = std::io::Error::last_os_error();
                    remove_claim_file(&temp, &file);
                    return Err(format!("lock {}: {error}", temp.display()));
                }
                return Ok((file, temp));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("create {}: {error}", temp.display())),
        }
    }
    Err(format!(
        "no free name beside {} for a file to replace it, {LEGACY_OPEN_TRIES} times",
        path.display()
    ))
}

/// Swaps `temp` and `path` in one step (`RENAME_EXCHANGE`).
fn exchange_with_name(temp: &Path, path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(error) = before_exchange_for_test(path, temp) {
        return Err(error);
    }
    super::files::renameat2_exchange(temp, path)
}

/// Removes `temp` while it is still the name of `file`, this operation's own.
fn remove_claim_file(temp: &Path, file: &File) {
    let identity = |meta: std::fs::Metadata| (meta.dev(), meta.ino());
    let ours = file.metadata().ok().map(identity);
    if ours.is_some() && std::fs::symlink_metadata(temp).ok().map(identity) == ours {
        let _ = std::fs::remove_file(temp);
    }
}

/// What the exchange in [`claim_legacy_name`] took off the name, as
/// [`came_out`] finds it at the other name.
#[derive(Debug)]
enum CameOut {
    /// Nothing is there: its owner has moved it since.
    Gone,
    /// `found` itself, or not a regular file: nothing more to wait for.
    Done,
    /// A regular file other than `found`, opened with `O_PATH`.
    Other(File),
}

/// What the exchange in [`claim_legacy_name`] took off `path`, which is now at
/// `temp`, opened with `O_PATH` and not followed; it stays at `temp`. When it
/// cannot be opened, it may be a lock an earlier release holds, which cannot
/// then be waited for, and the operation stops.
fn came_out(path: &Path, temp: &Path, found: &std::fs::Metadata) -> Result<CameOut, String> {
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temp);
    let out = match opened {
        Ok(out) => out,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(CameOut::Gone),
        Err(error) => {
            return Err(format!(
                "open {}, taken off {}: {error}",
                temp.display(),
                path.display()
            ))
        }
    };
    let meta = out.metadata().map_err(|error| {
        format!(
            "stat {}, taken off {}: {error}",
            temp.display(),
            path.display()
        )
    })?;
    if meta.is_file() && (meta.dev(), meta.ino()) != (found.dev(), found.ino()) {
        Ok(CameOut::Other(out))
    } else {
        Ok(CameOut::Done)
    }
}

/// Removes what the exchange in [`claim_legacy_name`] took off the name from
/// `temp`, where it is. A directory, when another account put one at the name,
/// goes only when empty; nothing is followed or opened.
fn remove_came_out(temp: &Path) {
    let _ = std::fs::remove_file(temp).or_else(|_| std::fs::remove_dir(temp));
}

/// Exchanges `path`, where [`claim_legacy_name`] put this operation's `file`,
/// with `temp` again, where what it took off the name is, so the name leads to
/// that again, and then removes `file` from `temp`. When the exchange fails,
/// as when the owner of what came out has moved it since, `file` stays at the
/// name and whatever is at `temp` is removed, so the other name does not
/// outlast the operation.
fn put_back(path: &Path, temp: &Path, file: &File) {
    if super::files::renameat2_exchange(temp, path).is_ok() {
        remove_claim_file(temp, file);
    } else {
        remove_came_out(temp);
    }
}

/// Test-only: what another process does to a name, or the error the exchange
/// meets, just before [`claim_legacy_name`] exchanges its file with that name,
/// by the name it is armed for. Stays armed until disarmed.
#[cfg(test)]
type BeforeExchange = Box<dyn FnMut(&Path) -> Option<std::io::Error> + Send>;

#[cfg(test)]
static BEFORE_EXCHANGE: std::sync::Mutex<Vec<(PathBuf, BeforeExchange)>> =
    std::sync::Mutex::new(Vec::new());

/// Test-only: run what is armed for `path`, given the name of the file about
/// to be exchanged with it.
#[cfg(test)]
fn before_exchange_for_test(path: &Path, temp: &Path) -> Option<std::io::Error> {
    let mut armed = BEFORE_EXCHANGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (_, action) = armed.iter_mut().find(|(armed, _)| armed == path)?;
    action(temp)
}

/// Lock `file`, the lock of earlier releases at `path`, waiting until
/// `deadline`, `wait` after the wait began, for a process that holds it, as
/// [`take_legacy_lock`] says.
fn wait_for_legacy_lock(
    path: &Path,
    file: File,
    uid: u32,
    wait: Duration,
    deadline: Instant,
) -> Result<Option<File>, String> {
    let meta = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?;
    let mut waiting = false;
    loop {
        // SAFETY: the descriptor is owned by `file`, which outlives the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(file));
        }
        // Only contention is waited out. Any other failure (no lock left in
        // the kernel, a descriptor flock cannot lock) stops the operation
        // rather than letting it go on without the lock.
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => {}
            Some(libc::EINTR) => continue,
            _ => return Err(format!("lock {}: {error}", path.display())),
        }
        let by = || {
            lock_holders(&file)
                .and_then(|pids| processes(&pids))
                .map(|who| format!(" by {who}"))
                .unwrap_or_default()
        };
        let now = Instant::now();
        if now >= deadline {
            let verdict = earlier_irlumes(lock_users(&file), |pid| has_open_as(pid, uid, &meta));
            let detail = match verdict {
                Ok(own) if own.holders.is_empty() && own.waiters.is_empty() => {
                    eprintln!(
                        "irlume: {} is still held{}; no process holding or waiting for it runs \
                         as uid {uid} with it open, so none is an earlier irlume, and this \
                         operation goes on without it",
                        path.display(),
                        by()
                    );
                    return Ok(None);
                }
                Ok(own) => {
                    let mut detail = processes(&own.holders)
                        .map(|who| format!(" by {who}, running as uid {uid}"))
                        .unwrap_or_default();
                    if let Some(who) = processes(&own.waiters) {
                        let verb = if own.waiters.len() == 1 { "is" } else { "are" };
                        detail.push_str(&format!(
                            ", and {who}, running as uid {uid} with it open, {verb} waiting for it"
                        ));
                    }
                    detail
                }
                Err(why) => format!(", and {why}"),
            };
            return Err(format!(
                "{}, the PAM lock of earlier irlume releases, is still held after {} s{detail}; \
                 an earlier irlume may still be changing PAM, so try again once it has finished",
                path.display(),
                wait.as_secs()
            ));
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

/// Which of `users`, the processes `/proc/locks` lists as holding or waiting
/// for the lock of earlier releases (`None` when they cannot be read), may be
/// an earlier irlume, as `open_as` ([`has_open_as`]) tells. A waiter counts as
/// a holder does: it takes the lock once the holder lets go, which may be while
/// the operation that passed over that holder runs.
///
/// `Err` says why `/proc` cannot rule that out: the holders cannot be read,
/// none is listed (a holder outside this PID namespace is not), or what one of
/// them runs as or has open cannot be read. Only a process shown not to be one
/// is passed over; so is this process, which has the file open itself (a
/// pid `/proc/locks` still lists for an exited taker may since be reused).
fn earlier_irlumes(
    users: Option<LockUsers>,
    open_as: impl Fn(u32) -> Option<bool>,
) -> Result<LockUsers, String> {
    let users =
        users.ok_or_else(|| "the processes holding it cannot be read from /proc".to_owned())?;
    if users.holders.is_empty() {
        return Err("/proc/locks does not list the process holding it".to_owned());
    }
    let own = |pids: Vec<u32>| {
        let mut own = Vec::new();
        for pid in pids.into_iter().filter(|&pid| pid != std::process::id()) {
            match open_as(pid) {
                Some(true) => own.push(pid),
                Some(false) => {}
                None => {
                    return Err(format!(
                        "/proc cannot show what process {pid} runs as or has open"
                    ))
                }
            }
        }
        Ok(own)
    };
    Ok(LockUsers {
        holders: own(users.holders)?,
        waiters: own(users.waiters)?,
    })
}

/// Whether process `pid` runs as `uid`, by its real and effective uid, and has
/// the file `meta` describes open, as an earlier irlume holding its lock does:
/// `Some(false)` when it has exited, runs as another account or does not have
/// the file open, and `None` when `/proc` cannot show which.
///
/// `/proc/locks` goes on naming the process that took a lock after it has
/// exited while another keeps the file open, and a later process can be given
/// that number, so the number alone proves nothing. The real uid is checked
/// too, so a set-user-ID program another account runs does not count. What
/// cannot be read counts as settled only when the process has exited
/// ([`has_exited`]), since a `/proc` mount can also hide a process that runs.
fn has_open_as(pid: u32, uid: u32, meta: &std::fs::Metadata) -> Option<bool> {
    let unreadable = || has_exited(pid).then_some(false);
    let Some((real, effective)) = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| status_uids(&status))
    else {
        return unreadable();
    };
    if real != uid || effective != uid {
        return Some(false);
    }
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return unreadable();
    };
    let mut unread = false;
    for fd in fds {
        match fd.and_then(|fd| std::fs::metadata(fd.path())) {
            Ok(open) if open.dev() == meta.dev() && open.ino() == meta.ino() => return Some(true),
            Ok(_) => {}
            // Closed since the directory was read.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unread = true,
        }
    }
    if unread {
        unreadable()
    } else {
        Some(false)
    }
}

/// Whether no process `pid` exists any more: `kill` with signal 0 sends
/// nothing and fails with `ESRCH` only then, whatever `/proc` shows.
fn has_exited(pid: u32) -> bool {
    let Some(pid) = libc::pid_t::try_from(pid).ok().filter(|&pid| pid > 0) else {
        return false;
    };
    // SAFETY: signal 0 is never delivered; `kill` only looks the process up.
    let found = unsafe { libc::kill(pid, 0) } == 0;
    !found && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// The real and effective uid from the `Uid:` line of `/proc/<pid>/status`,
/// which lists the real, effective, saved and filesystem uid in that order.
fn status_uids(status: &str) -> Option<(u32, u32)> {
    let mut ids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace();
    Some((ids.next()?.parse().ok()?, ids.next()?.parse().ok()?))
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

/// The processes holding a `flock` lock on one file, and those waiting for one,
/// as `/proc/locks` lists them.
#[derive(Debug, Default, PartialEq)]
struct LockUsers {
    holders: Vec<u32>,
    waiters: Vec<u32>,
}

/// The processes `/proc/locks` lists as holding a `flock` lock on `file`, or
/// `None` when that, or the file's mount, cannot be read.
fn lock_holders(file: &File) -> Option<Vec<u32>> {
    lock_users(file).map(|users| users.holders)
}

/// The processes `/proc/locks` lists as holding a `flock` lock on `file` or
/// waiting for one, or `None` when that, or the file's mount, cannot be read.
fn lock_users(file: &File) -> Option<LockUsers> {
    let (Ok(meta), Some(device), Ok(locks)) = (
        file.metadata(),
        superblock_device(file),
        std::fs::read_to_string("/proc/locks"),
    ) else {
        return None;
    };
    Some(flock_users(&locks, device, meta.ino()))
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
/// `flock` lock on inode `ino` of the filesystem `device`, and those it lists as
/// waiting for one.
///
/// A line such as `1: FLOCK  ADVISORY  WRITE 1234 00:1a:5678 0 EOF` gives the
/// holder's pid just before the device (major and minor in hex) and the inode.
/// A line with `->` gives a process waiting for the lock the same way, and a
/// process outside this PID namespace is listed as 0 or not at all.
fn flock_users(locks: &str, device: (u32, u32), ino: u64) -> LockUsers {
    let wanted = format!("{:02x}:{:02x}:{ino}", device.0, device.1);
    let mut users = LockUsers::default();
    for line in locks.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if !fields.contains(&"FLOCK") {
            continue;
        }
        let Some(at) = fields.iter().position(|field| *field == wanted) else {
            continue;
        };
        let pid = at
            .checked_sub(1)
            .and_then(|before| fields[before].parse::<u32>().ok())
            .filter(|&pid| pid != 0);
        let pids = if fields.contains(&"->") {
            &mut users.waiters
        } else {
            &mut users.holders
        };
        if let Some(pid) = pid {
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
    }
    users
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

    fn ino(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).expect("stat").ino()
    }

    /// The names in `dir`, sorted.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("list a directory")
            .map(|entry| {
                entry
                    .expect("read a directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// Runs an action just before each exchange that would put the caller's
    /// file at a name another account's file had, until dropped.
    struct Armed(PathBuf);

    fn arm_before_exchange(
        path: &Path,
        action: impl FnMut(&Path) -> Option<std::io::Error> + Send + 'static,
    ) -> Armed {
        BEFORE_EXCHANGE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((path.to_path_buf(), Box::new(action)));
        Armed(path.to_path_buf())
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            BEFORE_EXCHANGE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .retain(|(armed, _)| *armed != self.0);
        }
    }

    /// [`take_legacy_lock`] for a file at `path` that another account owns,
    /// with the processes holding it or waiting for it checked against the
    /// caller's own uid, as an earlier irlume holding it would run as. A test
    /// cannot create a file another account owns, so the file is opened with
    /// another uid as the caller's, which makes it another account's.
    fn take_foreign(path: &Path, wait: Duration) -> Result<Vec<File>, String> {
        let deadline = Instant::now() + wait;
        let found = match open_legacy_lock(path, uid().wrapping_add(1))? {
            LegacyLock::Foreign(found) => found,
            other => panic!("{} was not another account's: {other:?}", path.display()),
        };
        replace_legacy_lock(path, &found, |file| {
            wait_for_legacy_lock(path, file, uid(), wait, deadline)
        })
    }

    /// The private names beside `path` that a file taking its name had.
    fn private_names(path: &Path) -> Vec<PathBuf> {
        let dir = path.parent().expect("a directory");
        let prefix = format!(".{}.", path.file_name().unwrap().to_string_lossy());
        entries(dir)
            .into_iter()
            .filter(|name| name.starts_with(&prefix))
            .map(|name| dir.join(name))
            .collect()
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

    /// Whether the lock on `path` is let go within 5 s. A child another test
    /// thread is starting holds a copy of each descriptor of this process until
    /// it runs its program, and the lock with it, so a release can take a
    /// moment to show; a lock never released still fails.
    fn released(path: &Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while held(path) {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
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

    /// A lock on `path` whose taker has exited: a shell opens the file, a
    /// `flock` it starts takes the lock on that descriptor and exits, and the
    /// `sleep` the shell becomes keeps the file open and the lock held until
    /// dropped. `/proc/locks` names the `flock` process, which no longer runs.
    struct OrphanedHolder(Child);

    impl OrphanedHolder {
        fn new(path: &Path) -> Self {
            let child = Command::new("sh")
                .args(["-c", "exec 9<\"$1\" && flock -x 9 && exec sleep 60", "sh"])
                .arg(path)
                .stdin(Stdio::null())
                .spawn()
                .expect("run sh");
            let holder = Self(child);
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
    }

    impl Drop for OrphanedHolder {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A `cat` process holding a write lease on `path` until dropped, as the
    /// account owning a file can take one. The lease is taken between fork and
    /// exec on a descriptor `cat` inherits, and `SIGIO`, which tells the holder
    /// an open is waiting for the lease, is ignored, so `cat` does not give the
    /// lease up: it goes when `cat` ends at the end of its input.
    struct LeaseHolder {
        child: Child,
        input: Option<ChildStdin>,
    }

    impl LeaseHolder {
        fn new(path: &Path) -> Self {
            use std::os::unix::ffi::OsStrExt as _;
            use std::os::unix::process::CommandExt as _;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("a path");
            let mut command = Command::new("cat");
            command.stdin(Stdio::piped()).stdout(Stdio::null());
            // SAFETY: the closure runs in the child between fork and exec and
            // calls only async-signal-safe functions (signal, open, fcntl) on a
            // path allocated before the fork. The descriptor it opens is left
            // open on purpose, for `cat` to inherit with the lease.
            unsafe {
                command.pre_exec(move || {
                    if libc::signal(libc::SIGIO, libc::SIG_IGN) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                    let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
                    if fd < 0 || libc::fcntl(fd, libc::F_SETLEASE, libc::F_WRLCK) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn().expect("take a write lease");
            let input = child.stdin.take();
            Self { child, input }
        }
    }

    impl Drop for LeaseHolder {
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
        assert!(released(&path), "the lock was not released when dropped");
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
        assert_eq!(lock_holders(&file), Some(vec![holder.pid()]));
        assert_eq!(
            lock_holders(&file).and_then(|pids| processes(&pids)),
            Some(format!("process {}", holder.pid()))
        );
        drop(holder);
        assert_eq!(lock_holders(&file), Some(Vec::new()));
    }

    /// Only `flock` locks on the one file count, with a process waiting for one
    /// apart from the holders: not a POSIX or OFD lock, another device or
    /// inode, or a process outside this PID namespace.
    #[test]
    fn reads_the_holders_and_waiters_of_one_file_from_proc_locks() {
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
        assert_eq!(
            flock_users(locks, (0, 0x1a), 777),
            LockUsers {
                holders: vec![4242, 4747],
                waiters: vec![4343],
            }
        );
        assert_eq!(
            flock_users(locks, (0x103, 0x1f4), 777),
            LockUsers {
                holders: vec![4848],
                waiters: Vec::new(),
            }
        );
        assert_eq!(flock_users(locks, (0, 0x1a), 77), LockUsers::default());
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
            released(&legacy),
            "the legacy lock was not released when dropped"
        );
    }

    /// A process running as the caller's uid with the legacy lock open, as an
    /// earlier irlume holding it is, that still holds it at the limit stops the
    /// operation with an error naming it, instead of letting it write beside
    /// that process. The operation's own lock is released with the error.
    #[test]
    fn refuses_at_the_limit_while_a_process_of_the_account_holds_the_legacy_lock() {
        let scratch = Scratch::new("legacy-limit");
        let legacy = scratch.file("irlume-pam.lock", 0o600);
        let holder = Holder::new(&legacy);
        let path = scratch.path("run/pam.lock");
        let started = Instant::now();
        let refused = lock_pam_at(&path, Some(&legacy), uid(), Duration::from_millis(300))
            .expect_err("went on beside a process of the account holding the legacy lock");
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(300) && waited < Duration::from_secs(10),
            "waited {waited:?} for a limit of 300 ms"
        );
        assert!(
            refused.contains(&format!("process {}", holder.pid())),
            "{refused}"
        );
        assert!(
            released(&path),
            "the lock itself was kept after the refusal"
        );
        drop(holder);
    }

    /// At the limit, a holder of the legacy lock that `/proc/locks` lists and
    /// shows runs as another account than the caller is passed over, since it
    /// cannot be an earlier irlume of the caller's: the operation goes on
    /// without the lock, which stays its holder's, and nothing the operation
    /// took is left on the file. A test cannot run a process as another
    /// account, so the holder runs as this one and the operation is given
    /// another account: the verdict asks only whether holder and caller are
    /// the same account, so it comes out the same either way. A holder that
    /// runs is listed in every PID namespace, unlike the exited taker the
    /// next test waits behind, so this side of the limit does not depend on
    /// where the test runs.
    #[test]
    fn goes_on_at_the_limit_when_the_listed_legacy_lock_holder_runs_as_another_account() {
        let scratch = Scratch::new("legacy-other-account");
        let legacy = scratch.file("irlume-pam.lock", 0o600);
        let holder = Holder::new(&legacy);
        let file = match open_legacy_lock(&legacy, uid()) {
            Ok(LegacyLock::Own(file)) => file,
            other => panic!("{} was not the caller's own: {other:?}", legacy.display()),
        };
        let probe = File::open(&legacy).unwrap();
        assert_eq!(
            lock_holders(&probe),
            Some(vec![holder.pid()]),
            "the holder is not listed, so its side of the limit cannot be forced"
        );
        let other = uid().wrapping_add(1);
        let limit = Duration::from_millis(300);
        let started = Instant::now();
        let past = wait_for_legacy_lock(&legacy, file, other, limit, started + limit)
            .expect("stopped beside a holder that runs as another account");
        let waited = started.elapsed();
        assert!(
            waited >= limit && waited < Duration::from_secs(10),
            "waited {waited:?} for a limit of 300 ms"
        );
        assert!(
            past.is_none(),
            "took the legacy lock although its holder still holds it"
        );
        assert!(
            held(&legacy),
            "the legacy lock was let go although its holder still holds it"
        );
        drop(holder);
        assert!(
            released(&legacy),
            "a lock the operation took was left on the legacy lock"
        );
    }

    /// At the limit over a legacy lock whose taker has exited while another
    /// process keeps the file open, the operation goes on only where
    /// `/proc/locks` still lists that taker, as the initial PID namespace
    /// does: a pid that has exited is not an earlier irlume, so the operation
    /// then holds its own lock alone while the orphaned lock stays held.
    /// Where the listing hides an exited taker, as outside the initial PID
    /// namespace, it lists no holder at all, and the operation stops with the
    /// refusal that says so, having let go of its own lock. Which of the two
    /// the listing answers is not this test's to choose, and a sample of it
    /// taken before the wait was once seen, under load in CI, to disagree
    /// with the reading at the deadline, so the side is taken from what the
    /// operation returns and only that side's invariants are checked.
    #[test]
    fn goes_on_or_stops_at_the_limit_by_whether_proc_locks_lists_the_orphaned_legacy_holder() {
        let scratch = Scratch::new("legacy-orphan");
        let legacy = scratch.file("irlume-pam.lock", 0o600);
        let holder = OrphanedHolder::new(&legacy);
        let path = scratch.path("run/pam.lock");
        let started = Instant::now();
        let taken = lock_pam_at(&path, Some(&legacy), uid(), Duration::from_millis(300));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(300) && waited < Duration::from_secs(10),
            "waited {waited:?} for a limit of 300 ms"
        );
        assert!(
            held(&legacy),
            "the orphaned lock was let go before its holder ended"
        );
        match taken {
            Ok(lock) => {
                assert!(held(&path), "the lock itself is held");
                drop(lock);
            }
            Err(refused) => {
                assert!(
                    refused.contains("does not list"),
                    "an exited taker this PID namespace hides was passed over: {refused}"
                );
                assert!(
                    released(&path),
                    "the lock itself was kept after the refusal"
                );
            }
        }
        drop(holder);
    }

    /// At the limit, a holder of the legacy lock, or a process waiting for it,
    /// is passed over only when `/proc` shows it is not an earlier irlume. When
    /// the holders cannot be read, none is listed, as for one outside this PID
    /// namespace, or what a holder or waiter runs as or has open cannot be
    /// read, the operation stops.
    #[test]
    fn stops_when_proc_cannot_rule_out_an_earlier_irlume_holding_the_legacy_lock() {
        let users = |holders: &[u32], waiters: &[u32]| {
            Some(LockUsers {
                holders: holders.to_vec(),
                waiters: waiters.to_vec(),
            })
        };
        let refused = earlier_irlumes(None, |_| Some(false))
            .expect_err("unreadable holders were passed over");
        assert!(refused.contains("cannot be read"), "{refused}");
        let refused = earlier_irlumes(users(&[], &[4242]), |_| Some(false))
            .expect_err("a holder /proc/locks does not list was passed over");
        assert!(refused.contains("does not list"), "{refused}");
        let refused = earlier_irlumes(users(&[4242, 4343], &[]), |pid| {
            (pid == 4242).then_some(false)
        })
        .expect_err("a holder /proc cannot show was passed over");
        assert!(refused.contains("process 4343"), "{refused}");
        let refused = earlier_irlumes(users(&[4242], &[4343]), |pid| {
            (pid == 4242).then_some(false)
        })
        .expect_err("a waiter /proc cannot show was passed over");
        assert!(refused.contains("process 4343"), "{refused}");

        assert_eq!(
            earlier_irlumes(users(&[4242, 4343], &[4444]), |pid| Some(pid == 4343)),
            Ok(LockUsers {
                holders: vec![4343],
                waiters: Vec::new(),
            })
        );
        assert_eq!(
            earlier_irlumes(users(&[4242], &[4343, 4444]), |pid| Some(pid == 4444)),
            Ok(LockUsers {
                holders: Vec::new(),
                waiters: vec![4444],
            })
        );
        assert_eq!(
            earlier_irlumes(users(&[4242], &[4343]), |_| Some(false)),
            Ok(LockUsers::default())
        );
        // This process, which has the file open, is never an earlier irlume.
        let me = std::process::id();
        assert_eq!(
            earlier_irlumes(users(&[me], &[me]), |_| Some(true)),
            Ok(LockUsers::default())
        );
    }

    /// A process is an earlier irlume holding the lock only while it runs as
    /// the account with the file open. One that has exited is not, and one
    /// whose open files cannot be read is left undecided.
    #[test]
    fn tells_what_a_legacy_lock_holder_runs_as_and_has_open() {
        let scratch = Scratch::new("open-as");
        let path = scratch.file("irlume-pam.lock", 0o600);
        let file = File::open(&path).unwrap();
        let meta = file.metadata().unwrap();
        let me = std::process::id();
        assert_eq!(has_open_as(me, uid(), &meta), Some(true));
        assert_eq!(has_open_as(me, uid().wrapping_add(1), &meta), Some(false));
        let closed = std::fs::metadata(scratch.file("closed", 0o600)).unwrap();
        assert_eq!(has_open_as(me, uid(), &closed), Some(false));

        let mut child = Command::new("true").spawn().expect("run true");
        let exited = child.id();
        child.wait().expect("wait for true");
        assert!(has_exited(exited));
        assert!(!has_exited(me));
        assert_eq!(has_open_as(exited, uid(), &meta), Some(false));

        // Process 1 runs as root, and an account that may not trace it cannot
        // list its open files.
        let init = std::fs::read_to_string("/proc/1/status")
            .ok()
            .and_then(|status| status_uids(&status));
        if uid() != 0 && init == Some((0, 0)) && std::fs::read_dir("/proc/1/fd").is_err() {
            assert_eq!(has_open_as(1, 0, &meta), None);
        }
    }

    /// The real and effective uid are the first two of the four on `Uid:`.
    #[test]
    fn reads_the_real_and_effective_uid_from_proc_status() {
        let status = "Name:\tsu\nUmask:\t0022\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(status_uids(status), Some((1000, 0)));
        assert_eq!(status_uids("Name:\tx\n"), None);
        assert_eq!(status_uids("Uid:\t0\n"), None);
    }

    /// A missing legacy lock is created at 0600, in a directory created when
    /// that is missing too, and held with the lock. A process that then opens
    /// it and waits for its lock, as an earlier release that started before
    /// this operation but reached its lock after does, runs only once the
    /// operation lets go.
    #[test]
    fn creates_a_missing_legacy_lock_and_holds_it() {
        let scratch = Scratch::new("legacy-create");
        let legacy = scratch.path("lock/irlume-pam.lock");
        let lock = lock_pam_at(
            &scratch.path("run/pam.lock"),
            Some(&legacy),
            uid(),
            Duration::from_secs(30),
        )
        .expect("take the lock");
        assert!(
            scratch.path("lock").is_dir(),
            "the directory was not created"
        );
        let meta = std::fs::symlink_metadata(&legacy).expect("the legacy lock was not created");
        assert!(meta.is_file());
        assert_eq!(meta.uid(), uid());
        assert_eq!(mode(&legacy), 0o600);
        assert!(held(&legacy), "the created legacy lock is not held");

        // `flock` opens the file with O_CREAT, as those releases did, and
        // waits for the lock.
        let mut earlier = Command::new("flock")
            .arg("-x")
            .arg(&legacy)
            .arg("true")
            .spawn()
            .expect("run flock");
        let probe = File::open(&legacy).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !lock_users(&probe).is_some_and(|users| users.waiters.contains(&earlier.id())) {
            assert!(
                earlier.try_wait().expect("poll flock").is_none(),
                "a later opener of the legacy lock did not wait for the operation"
            );
            assert!(Instant::now() < deadline, "flock never waited for the lock");
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(lock);
        let deadline = Instant::now() + Duration::from_secs(5);
        while earlier.try_wait().expect("poll flock").is_none() {
            assert!(
                Instant::now() < deadline,
                "the legacy lock was not released when dropped"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A legacy lock the caller owns that is not a regular file at its name
    /// stops the operation, naming the command that removes it: a symlink (its
    /// target is neither changed, locked nor created) or a FIFO (not opened,
    /// so nothing waits for a writer).
    #[test]
    fn refuses_a_symlinked_or_special_legacy_lock_it_owns() {
        let scratch = Scratch::new("legacy-special");
        let long = Duration::from_secs(30);
        let refused = |path: &Path, what: &str| {
            let error = take_legacy_lock(path, uid(), long).expect_err("must refuse");
            assert!(
                error.contains(&format!("is {what}, not the lock file"))
                    && error.contains(&format!("sudo rm {}", path.display())),
                "{error}"
            );
        };
        let target = scratch.file("target", 0o644);
        let link = scratch.path("link.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        refused(&link, "a symlink");
        assert_eq!(mode(&target), 0o644, "the symlink's target was changed");
        assert!(!held(&target), "the symlink's target was locked");
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());

        let absent = scratch.path("absent");
        let dangling = scratch.path("dangling.lock");
        std::os::unix::fs::symlink(&absent, &dangling).unwrap();
        refused(&dangling, "a symlink");
        assert!(!absent.exists(), "the symlink's target was created");

        let fifo = scratch.path("fifo.lock");
        let made = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo failed");
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(take_legacy_lock(&path, uid(), long).err());
        });
        let error = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a FIFO at the legacy lock's name must be refused without blocking")
            .expect("must refuse");
        assert!(error.contains("is a FIFO, not the lock file"), "{error}");
    }

    /// A symlink or a FIFO another account owns at the legacy lock's name is
    /// replaced by a file of the caller's own, created at 0600 and held, since
    /// that account can remove it at any time; it is not followed, opened or
    /// waited for. The symlink's target is neither changed, locked nor
    /// created, and no other name is left behind. A test cannot create a file
    /// another account owns, so the caller is given another uid, which makes
    /// the test's own files another account's.
    #[test]
    fn replaces_a_symlink_or_fifo_another_account_owns_at_the_legacy_lock() {
        let scratch = Scratch::new("legacy-foreign-special");
        let other = uid().wrapping_add(1);
        let long = Duration::from_secs(30);
        let target = scratch.file("target", 0o644);
        let link = scratch.path("link.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let taken = take_legacy_lock(&link, other, long).expect("take the legacy lock");
        assert_eq!(taken.len(), 1, "{taken:?}");
        assert!(
            std::fs::symlink_metadata(&link).unwrap().is_file(),
            "the symlink kept the name"
        );
        assert_eq!(mode(&link), 0o600);
        assert!(held(&link), "the file at the name is not held");
        assert_eq!(mode(&target), 0o644, "the symlink's target was changed");
        assert!(!held(&target), "the symlink's target was locked");
        drop(taken);

        let absent = scratch.path("absent");
        let dangling = scratch.path("dangling.lock");
        std::os::unix::fs::symlink(&absent, &dangling).unwrap();
        let taken = take_legacy_lock(&dangling, other, long).expect("take the legacy lock");
        assert_eq!(taken.len(), 1, "{taken:?}");
        assert!(std::fs::symlink_metadata(&dangling).unwrap().is_file());
        assert!(!absent.exists(), "the symlink's target was created");
        drop(taken);

        let fifo = scratch.path("fifo.lock");
        let made = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo failed");
        let (tx, rx) = std::sync::mpsc::channel();
        let name = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(take_legacy_lock(&name, other, long).map(|held| held.len()));
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)),
            Ok(Ok(1)),
            "a FIFO at the legacy lock's name must be replaced without blocking"
        );
        assert!(std::fs::symlink_metadata(&fifo).unwrap().is_file());
        assert_eq!(
            entries(&scratch.0),
            ["dangling.lock", "fifo.lock", "link.lock", "target"]
        );
    }

    /// A legacy lock another account owns is locked, and then taken off its
    /// name, unchanged, by a file of the caller's own, created at 0600, that
    /// takes the name in one rename and stays there after the lock is dropped.
    /// Both are held, and no other name is left behind; the other account's
    /// file is found again by a second name, a hard link made first. Its holder
    /// is waited for up to the limit; here that holder runs as another uid than
    /// the caller, so it is not an earlier irlume, and the operation then goes
    /// on, holding the file at the name.
    #[test]
    fn replaces_a_legacy_lock_another_account_owns_and_holds_both() {
        let scratch = Scratch::new("legacy-foreign");
        let other = uid().wrapping_add(1);
        let foreign = scratch.file("foreign.lock", 0o644);
        let kept = scratch.path("kept");
        std::fs::hard_link(&foreign, &kept).unwrap();
        let locked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (seen, probe) = (std::sync::Arc::clone(&locked), kept.clone());
        let armed = arm_before_exchange(&foreign, move |_| {
            seen.lock().unwrap().push(held(&probe));
            None
        });
        let taken =
            take_legacy_lock(&foreign, other, Duration::ZERO).expect("take the legacy lock");
        drop(armed);
        assert_eq!(
            *locked.lock().unwrap(),
            [true],
            "another account's file was not locked before it was replaced"
        );
        assert_eq!(taken.len(), 2, "{taken:?}");
        assert_ne!(
            ino(&foreign),
            ino(&kept),
            "another account's file kept the name"
        );
        let own = std::fs::symlink_metadata(&foreign).unwrap();
        assert!(own.is_file());
        assert_eq!(own.uid(), uid());
        assert_eq!(mode(&foreign), 0o600);
        assert!(held(&foreign), "the file at the name is not held");
        assert!(held(&kept), "another account's file is not held");
        assert_eq!(mode(&kept), 0o644, "another account's file was changed");
        assert_eq!(
            std::fs::metadata(&kept).unwrap().nlink(),
            1,
            "another account's file kept a name beside the lock"
        );
        assert_eq!(entries(&scratch.0), ["foreign.lock", "kept"]);
        drop(taken);
        assert!(released(&foreign), "the file at the name was not released");
        assert!(released(&kept), "another account's file was not released");
        assert_eq!(
            ino(&foreign),
            own.ino(),
            "the file at the name did not stay"
        );

        std::fs::rename(&kept, &foreign).unwrap();
        std::fs::hard_link(&foreign, &kept).unwrap();
        let holder = Holder::new(&kept);
        let started = Instant::now();
        let taken = take_legacy_lock(&foreign, other, Duration::from_millis(300));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(300) && waited < Duration::from_secs(10),
            "waited {waited:?} for a limit of 300 ms"
        );
        let taken = taken.expect("stopped at another account's process");
        assert_eq!(taken.len(), 1, "{taken:?}");
        assert_ne!(
            ino(&foreign),
            ino(&kept),
            "another account's file kept the name"
        );
        assert!(held(&foreign), "the file at the name is not held");
        assert_eq!(mode(&kept), 0o644, "another account's file was changed");
        drop(taken);
        drop(holder);
    }

    /// The name of a legacy lock another account owns can change between the
    /// file there being opened and the rename that replaces it, since that
    /// account can remove or rename its file at any time. Removed, the name is
    /// taken while nothing else has it, and the removed file is still held.
    /// Replaced by a new file, as an earlier release that has not yet locked
    /// it creates, that file comes off the name too and is held as well.
    /// Replaced by a symlink, nothing is followed. Each time the caller's file
    /// ends up at the name. Replaced by a file an earlier release created and
    /// locked, that file comes off the name and is waited for: its holder,
    /// running as the caller's uid with it open, stops the operation at the
    /// limit, and the file goes back to the name, where a second operation
    /// stops at it too. No other name is left behind.
    #[test]
    fn claims_the_legacy_name_when_it_changes_before_the_rename() {
        let scratch = Scratch::new("legacy-race");
        let other = uid().wrapping_add(1);

        let removed = scratch.file("removed.lock", 0o644);
        let kept = scratch.path("removed.kept");
        std::fs::hard_link(&removed, &kept).unwrap();
        let name = removed.clone();
        let armed = arm_before_exchange(&removed, move |_| {
            let _ = std::fs::remove_file(&name);
            None
        });
        let taken =
            take_legacy_lock(&removed, other, Duration::ZERO).expect("take the legacy lock");
        drop(armed);
        assert_eq!(taken.len(), 2, "{taken:?}");
        assert_eq!(mode(&removed), 0o600, "the free name was not taken");
        assert_ne!(ino(&removed), ino(&kept));
        assert!(held(&removed), "the file at the name is not held");
        assert!(held(&kept), "the removed file is not held");
        drop(taken);

        let created = scratch.file("created.lock", 0o644);
        let (name, moved) = (created.clone(), scratch.path("created.moved"));
        let armed = arm_before_exchange(&created, move |_| {
            let _ = std::fs::rename(&name, &moved);
            let _ = std::fs::write(&name, "");
            None
        });
        let taken =
            take_legacy_lock(&created, other, Duration::ZERO).expect("take the legacy lock");
        drop(armed);
        assert_eq!(taken.len(), 3, "{taken:?}");
        assert_eq!(mode(&created), 0o600, "the name was not taken");
        assert!(held(&created), "the file at the name is not held");
        assert!(
            held(&scratch.path("created.moved")),
            "the moved file is not held"
        );
        drop(taken);

        let linked = scratch.file("linked.lock", 0o644);
        let target = scratch.file("linked.target", 0o644);
        let (name, moved, to) = (linked.clone(), scratch.path("linked.moved"), target.clone());
        let armed = arm_before_exchange(&linked, move |_| {
            let _ = std::fs::rename(&name, &moved);
            let _ = std::os::unix::fs::symlink(&to, &name);
            None
        });
        let taken = take_legacy_lock(&linked, other, Duration::ZERO).expect("take the legacy lock");
        drop(armed);
        assert_eq!(taken.len(), 2, "{taken:?}");
        assert!(std::fs::symlink_metadata(&linked).unwrap().is_file());
        assert_eq!(mode(&linked), 0o600);
        assert_eq!(mode(&target), 0o644, "the symlink's target was changed");
        assert!(!held(&target), "the symlink's target was locked");
        drop(taken);

        let replaced = scratch.file("replaced.lock", 0o644);
        let moved = scratch.path("replaced.moved");
        let earlier = scratch.file("earlier", 0o600);
        let holder = Holder::new(&earlier);
        let earlier_ino = ino(&earlier);
        let (name, to) = (replaced.clone(), moved.clone());
        let armed = arm_before_exchange(&replaced, move |_| {
            let _ = std::fs::rename(&name, &to);
            let _ = std::fs::rename(&earlier, &name);
            None
        });
        let wait = Duration::from_millis(300);
        let refused = take_foreign(&replaced, wait)
            .expect_err("went on beside an earlier release holding the file it created");
        drop(armed);
        assert!(
            refused.contains(&format!("process {}", holder.pid())),
            "{refused}"
        );
        assert_eq!(
            ino(&replaced),
            earlier_ino,
            "the earlier release's file was not put back at the name"
        );
        assert!(!held(&moved), "the moved file stayed locked");
        let refused = take_foreign(&replaced, wait)
            .expect_err("a second operation went on beside the earlier release");
        assert!(
            refused.contains(&format!("process {}", holder.pid())),
            "{refused}"
        );
        assert_eq!(ino(&replaced), earlier_ino, "the name changed");
        drop(holder);

        assert_eq!(
            entries(&scratch.0),
            [
                "created.lock",
                "created.moved",
                "linked.lock",
                "linked.moved",
                "linked.target",
                "removed.kept",
                "removed.lock",
                "replaced.lock",
                "replaced.moved",
            ]
        );
    }

    /// When the operation stops after its file has taken the name of a legacy
    /// lock another account owns, what came off the name goes back to it and
    /// the operation's file is removed: here a file put at the name after the
    /// other account's was opened, which cannot be waited for. When the owner
    /// of that file has moved it off the other name meanwhile, the operation's
    /// file stays at the name. Either way no other name is left behind and
    /// nothing stays locked.
    #[test]
    fn puts_back_what_it_took_off_the_legacy_name_when_it_stops() {
        let scratch = Scratch::new("legacy-put-back");
        let foreign = scratch.path("foreign.lock");
        for moved_off in [false, true] {
            scratch.file("foreign.lock", 0o644);
            let later = scratch.file("later", 0o644);
            let later_ino = ino(&later);
            let (name, aside) = (foreign.clone(), scratch.path("foreign.aside"));
            let armed = arm_before_exchange(&foreign, move |_| {
                let _ = std::fs::rename(&name, &aside);
                let _ = std::fs::rename(&later, &name);
                None
            });
            let found = match open_legacy_lock(&foreign, uid().wrapping_add(1)) {
                Ok(LegacyLock::Foreign(found)) => found,
                other => panic!("not another account's: {other:?}"),
            };
            let (path, elsewhere) = (foreign.clone(), scratch.path("later.moved"));
            let refused = replace_legacy_lock(&foreign, &found, |file| {
                if file.metadata().unwrap().ino() != later_ino {
                    return Ok(Some(file));
                }
                if moved_off {
                    let [temp] = <[PathBuf; 1]>::try_from(private_names(&path))
                        .expect("the file that came off the name at its other name");
                    std::fs::rename(temp, &elsewhere).unwrap();
                }
                Err("cannot wait for it".to_owned())
            })
            .expect_err("went on past a file it could not wait for");
            drop(armed);
            assert_eq!(refused, "cannot wait for it");
            if moved_off {
                assert_ne!(ino(&foreign), later_ino, "the moved file came back");
                assert_eq!(mode(&foreign), 0o600, "the caller's file lost the name");
            } else {
                assert_eq!(
                    ino(&foreign),
                    later_ino,
                    "what came off the name was not put back"
                );
            }
            assert_eq!(
                private_names(&foreign),
                Vec::<PathBuf>::new(),
                "moved off: {moved_off}"
            );
            assert!(!held(&foreign), "moved off: {moved_off}: a lock was kept");
            for name in entries(&scratch.0) {
                std::fs::remove_file(scratch.path(&name)).unwrap();
            }
        }
    }

    /// Where the caller's file cannot take the name of a legacy lock another
    /// account owns, the operation stops, since that account's file would still
    /// be the lock there: on a filesystem without `RENAME_EXCHANGE`, at another
    /// error from the rename, and when the name is missing at each exchange and
    /// back before the rename that follows, which is tried a bounded number of
    /// times. Each time the file the caller created is removed, the other
    /// account's keeps its name unchanged, and nothing stays locked.
    #[test]
    fn stops_and_removes_its_file_when_it_cannot_take_the_legacy_name() {
        let scratch = Scratch::new("legacy-claim-fails");
        let other = uid().wrapping_add(1);
        let foreign = scratch.file("foreign.lock", 0o644);
        let before = ino(&foreign);
        let cases = [
            (libc::EINVAL, "RENAME_EXCHANGE".to_owned(), 1),
            (libc::EIO, format!("replace {}", foreign.display()), 1),
            (
                libc::ENOENT,
                format!("{LEGACY_OPEN_TRIES} times"),
                LEGACY_OPEN_TRIES,
            ),
        ];
        for (errno, says, tries) in cases {
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = std::sync::Arc::clone(&calls);
            let armed = arm_before_exchange(&foreign, move |_| {
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(std::io::Error::from_raw_os_error(errno))
            });
            let refused = take_legacy_lock(&foreign, other, Duration::ZERO)
                .expect_err("went on with another account's file at the name");
            drop(armed);
            assert!(refused.contains(&says), "{refused}");
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::Relaxed),
                tries,
                "{refused}"
            );
            assert_eq!(
                entries(&scratch.0),
                ["foreign.lock"],
                "errno {errno}: the file created to take the name was left behind"
            );
            assert_eq!(
                ino(&foreign),
                before,
                "another account's file lost the name"
            );
            assert_eq!(mode(&foreign), 0o644, "another account's file was changed");
            assert!(!held(&foreign), "errno {errno}: a lock was kept");
        }
    }

    /// A lock that fails for another reason than contention stops the
    /// operation instead of letting it go on without the lock.
    #[test]
    fn stops_when_the_legacy_lock_fails_for_another_reason() {
        use std::os::fd::FromRawFd;
        let scratch = Scratch::new("legacy-flock-error");
        let path = scratch.file("irlume-pam.lock", 0o600);
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid C string; the descriptor is handed to `File` below.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: `fd` is a fresh descriptor this test owns; flock on an
        // O_PATH descriptor fails with EBADF.
        let file = unsafe { File::from_raw_fd(fd) };
        let deadline = Instant::now() + Duration::from_millis(200);
        let error = wait_for_legacy_lock(&path, file, uid(), Duration::from_millis(200), deadline)
            .unwrap_err();
        assert!(
            error.starts_with(&format!("lock {}", path.display())),
            "{error}"
        );
    }

    /// A write lease on a legacy lock another account owns, which that account
    /// can take, does not stop the operation: opening the file waits for the
    /// lease to be given up, as the open of earlier releases did, and the lock
    /// is then taken. Here the holder gives it up after 700 ms; the open waits
    /// for one that does not only as long as the kernel's lease break time.
    /// The file keeps its name until then, and is replaced there only once the
    /// operation holds it.
    #[test]
    fn waits_for_a_lease_on_a_legacy_lock_another_account_owns() {
        let scratch = Scratch::new("legacy-lease");
        let foreign = scratch.file("foreign.lock", 0o644);
        let kept = scratch.path("kept");
        std::fs::hard_link(&foreign, &kept).unwrap();
        let before = ino(&foreign);
        let lease = LeaseHolder::new(&foreign);
        let name = foreign.clone();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(700));
            let kept_name = ino(&name) == before;
            drop(lease);
            kept_name
        });
        let started = Instant::now();
        let taken = take_legacy_lock(&foreign, uid().wrapping_add(1), Duration::from_secs(30));
        let waited = started.elapsed();
        assert!(
            release.join().unwrap(),
            "the leased file lost its name while the operation waited for the lease"
        );
        let taken = taken.expect("a lease on the legacy lock stopped the operation");
        assert_eq!(taken.len(), 2, "{taken:?}");
        assert!(
            waited >= Duration::from_millis(500) && waited < Duration::from_secs(30),
            "returned after {waited:?}, while the lease was held for 700 ms"
        );
        assert!(held(&foreign), "the file at the name is not held");
        assert!(held(&kept), "the leased file is not held");
        assert_eq!(mode(&kept), 0o644, "another account's file was changed");
        drop(taken);
        assert!(released(&kept), "the legacy lock was not released");
    }

    /// A legacy lock another account owns still stops the operation at the
    /// limit while a process running as the caller's uid with it open holds
    /// it, and it keeps its name: it is waited for before anything replaces
    /// it. A process that opens the name during the wait, as an earlier
    /// release reaching its lock then does, waits for that holder rather than
    /// for the operation, and goes on waiting once the operation has stopped;
    /// a second operation stops at the holder too. No other name is left
    /// behind.
    #[test]
    fn refuses_at_the_limit_while_the_account_holds_a_legacy_lock_another_owns() {
        let scratch = Scratch::new("legacy-foreign-limit");
        let foreign = scratch.file("foreign.lock", 0o644);
        let before = ino(&foreign);
        let holder = Holder::new(&foreign);
        let name = foreign.clone();
        let opener = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            Command::new("flock")
                .arg("-x")
                .arg(&name)
                .arg("true")
                .spawn()
                .expect("run flock")
        });
        let started = Instant::now();
        let refused = take_foreign(&foreign, Duration::from_millis(600))
            .expect_err("went on beside a process of the account holding the legacy lock");
        let waited = started.elapsed();
        let mut earlier = opener.join().unwrap();
        assert!(
            waited >= Duration::from_millis(600) && waited < Duration::from_secs(10),
            "waited {waited:?} for a limit of 600 ms"
        );
        assert!(
            refused.contains(&format!("process {}", holder.pid())),
            "{refused}"
        );
        assert_eq!(
            ino(&foreign),
            before,
            "another account's file lost its name"
        );
        assert_eq!(mode(&foreign), 0o644, "another account's file was changed");
        assert_eq!(entries(&scratch.0), ["foreign.lock"]);

        let probe = File::open(&foreign).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !lock_users(&probe).is_some_and(|users| users.waiters.contains(&earlier.id())) {
            assert!(
                earlier.try_wait().expect("poll flock").is_none(),
                "a process that opened the name during the wait did not wait for its holder"
            );
            assert!(Instant::now() < deadline, "flock never waited for the lock");
            std::thread::sleep(Duration::from_millis(20));
        }
        let refused = take_foreign(&foreign, Duration::from_millis(300))
            .expect_err("a second operation went on beside the holder");
        assert!(
            refused.contains(&format!("process {}", holder.pid())),
            "{refused}"
        );
        assert_eq!(
            ino(&foreign),
            before,
            "another account's file lost its name"
        );
        assert_eq!(entries(&scratch.0), ["foreign.lock"]);
        assert!(
            earlier.try_wait().expect("poll flock").is_none(),
            "a process that opened the name during the wait stopped waiting for its holder"
        );
        drop(holder);
        let deadline = Instant::now() + Duration::from_secs(5);
        while earlier.try_wait().expect("poll flock").is_none() {
            assert!(
                Instant::now() < deadline,
                "flock did not take the lock once its holder let go"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A process running as the caller's uid with the legacy lock open that
    /// waits for it at the limit stops the operation too, even when the holder
    /// is not an earlier irlume: the waiter takes the lock once the holder
    /// lets go, which may be while the operation runs. Here the holder has
    /// exited while another process keeps the file open, which `/proc/locks`
    /// lists only in the initial PID namespace; elsewhere it lists no holder,
    /// and the operation stops for that instead. Which of the two refusals
    /// that is does not depend on a sample of `/proc/locks` taken before the
    /// wait, which under load once disagreed with the reading at the
    /// deadline: the refusal itself says which, and only its invariants are
    /// checked.
    #[test]
    fn refuses_at_the_limit_while_a_process_of_the_account_waits_for_the_legacy_lock() {
        let scratch = Scratch::new("legacy-waiter");
        let legacy = scratch.file("irlume-pam.lock", 0o600);
        let holder = OrphanedHolder::new(&legacy);
        let mut waiter = Command::new("flock")
            .arg("-x")
            .arg(&legacy)
            .arg("true")
            .spawn()
            .expect("run flock");
        let probe = File::open(&legacy).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !lock_users(&probe)
            .unwrap_or_default()
            .waiters
            .contains(&waiter.id())
        {
            assert!(Instant::now() < deadline, "flock never waited for the lock");
            std::thread::sleep(Duration::from_millis(20));
        }
        let path = scratch.path("run/pam.lock");
        let refused = lock_pam_at(&path, Some(&legacy), uid(), Duration::from_millis(300))
            .expect_err("went on while a process of the account waits for the legacy lock");
        if !refused.contains("does not list") {
            assert!(
                refused.contains(&format!("process {}", waiter.id()))
                    && refused.contains("waiting for it"),
                "{refused}"
            );
        }
        drop(holder);
        let _ = waiter.wait();
    }
}
