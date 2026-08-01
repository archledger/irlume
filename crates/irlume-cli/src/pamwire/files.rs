// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Touching the filesystem safely: reading a stack, recording what a surface
//! looked like, restoring it, and holding the lock that serialises all of it.
//!
//! An auth stack is the one file on the machine a user cannot afford to have
//! half-written, so the write path stages to a scratch file and renames, and
//! every mutation runs under `lock_pam`. Kept apart from the rewriting logic so
//! that "what do we write" and "how do we write it without losing the file" can
//! be reviewed and tested separately.

use super::grammar::*;
use super::stanzas::*;
use super::{Svc, FP_GREETERS, GREETERS, LOCKSCREEN, POLKIT, SUDO};
use std::path::{Path, PathBuf};

pub(super) fn read(p: &str) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("read {p}: {e}"))
}

pub(super) fn file_has_module(p: &Path) -> bool {
    std::fs::read_to_string(p)
        .map(|c| content_has_module(&c))
        .unwrap_or(false)
}

pub(super) fn file_is_created_override(p: &Path) -> bool {
    std::fs::read_to_string(p)
        .map(|c| c.starts_with(CREATED_PREFIX))
        .unwrap_or(false)
}

/// A surface's current content digest, or `ABSENT`, or `unreadable`.
///
/// Three distinct answers on purpose. Folding "cannot read" into either of the
/// others would let a plan id stay stable across a state it could not actually
/// observe.
pub(crate) fn surface_state(path: &Path) -> String {
    // The backup as well as the live file. Wiring rebuilds from `.pre-irlume`
    // when one exists, so the content an apply produces depends on it: a backup
    // that changed between the plan and the apply changes the outcome while the
    // live file, and therefore the plan id, stayed identical. The consumer would
    // be shown one result and the machine would get another.
    let bak = PathBuf::from(format!("{}{BACKUP}", path.display()));
    format!("{} {}", surface_digest(path), surface_digest(&bak))
}

pub(crate) fn surface_digest(path: &Path) -> String {
    match crate::logintx::file_sha256(path) {
        Ok(Some(digest)) => digest,
        Ok(None) => crate::logintx::ABSENT.to_string(),
        Err(_) => "unreadable".to_string(),
    }
}

/// Whether irlume manages this path at all.
///
/// A transaction record names the paths a rollback will write, and nothing
/// previously checked that those were paths irlume had any business touching. A
/// record naming /etc/shadow with a correct digest rewrote it: verified, not
/// theorised. Only root can plant a record, and root can already write that
/// file, so it was not an escalation, but it made `login rollback` a
/// general-purpose write-anywhere-as-root primitive whose only gate was a
/// directory mode. Any future way to plant a record would then be total.
///
/// So the paths are checked against the surfaces irlume wires, plus their
/// `.pre-irlume` sidecars, and nothing else is restorable.
pub(crate) fn is_managed_path(path: &str) -> bool {
    let bare = path.strip_suffix(BACKUP).unwrap_or(path);
    // Built from the same lists the wiring uses, so a surface added there is
    // restorable without anyone remembering to update a second list.
    GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .map(|s| s.etc)
        .chain([LOCKSCREEN.etc, POLKIT.etc, SUDO])
        .any(|managed| managed == bare)
}

/// Put one surface back to the content recorded before a transaction.
///
/// Reuses the same atomic write the wiring path uses, so a restore lands the
/// way every other PAM write here does. The caller must have checked
/// `unchanged_since_apply` first; this does the write, not the decision.
///
/// `None` content means the file did not exist before, so it is removed rather
/// than written empty: an empty PAM file is not the same as an absent one, and
/// leaving one behind would shadow a vendor copy.
pub(crate) fn restore_surface(
    path: &Path,
    before: Option<&str>,
    metadata: Option<(u32, u32, u32)>,
) -> Result<(), String> {
    match before {
        Some(content) => {
            // The recorded mode and owner go on before the rename, not after.
            // Applying them afterwards published a PAM stack that was briefly
            // whatever the root umask produced, and on this path in particular
            // the file may have been REMOVED by apply, so there was nothing to
            // copy attributes from and the default was all it ever got.
            //
            // `None` keeps the old behaviour for records written before those
            // fields existed: the replacing file inherits the current one's
            // attributes rather than a guess.
            let attrs = metadata.or_else(|| {
                std::fs::symlink_metadata(path).ok().as_ref().map(|m| {
                    use std::os::unix::fs::MetadataExt as _;
                    use std::os::unix::fs::PermissionsExt as _;
                    (m.permissions().mode() & 0o7777, m.uid(), m.gid())
                })
            });
            write_atomic_inner(path, content, attrs)
        }
        None => {
            // The same refusal the replacing branch gets. Removing was a direct
            // `remove_file`, so a path recorded as previously absent that is now
            // a symlink was unlinked despite the claim that every write path
            // refuses one, and a multiply-linked file lost a name irlume cannot
            // put back.
            inspect_target(path)?;
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(format!("remove {}: {error}", path.display())),
            }
            // A deletion is a directory change like any other. Without this the
            // unlink could be lost to a power cut while the durable progress
            // note said the surface was done, so a resume would skip a file that
            // is still there.
            fsync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
        }
    }
}

/// Held for as long as a process is changing PAM. Released when dropped.
pub(crate) struct PamLock {
    _file: std::fs::File,
}

/// Where the PAM lock lives. `IRLUME_PAM_LOCK` overrides it for tests and
/// containers, the same way `IRLUME_STATE_DIR` overrides the state root.
pub(super) fn pam_lock_path() -> PathBuf {
    std::env::var_os("IRLUME_PAM_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock/irlume-pam.lock"))
}

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
pub(crate) fn lock_pam() -> Result<PamLock, String> {
    use std::os::unix::io::AsRawFd as _;
    let path = pam_lock_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is owned by `file`, which outlives the call and the guard.
    let busy = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0;
    if busy {
        // Said on stderr, because machine output is JSON on stdout. Then wait:
        // refusing outright would make the reconcile path unit give up exactly
        // when an apply is in flight, which is when it most needs to run after.
        eprintln!("irlume: another irlume PAM operation is in progress, waiting for it…");
        // SAFETY: as above.
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            return Err(format!(
                "lock {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    sweep_abandoned_scratch();
    Ok(PamLock { _file: file })
}

/// Remove scratch files a killed irlume left in `/etc/pam.d`.
///
/// A `SIGKILL` between creating the scratch file and renaming it skips every
/// cleanup path, so real hardware runs that interrupt an apply leave
/// `.sudo.irlume-new.1234.0.tmp` behind. PAM selects a stack by exact filename,
/// so a dotfile is never read as a service and this is litter rather than a
/// hazard, but it is irlume's litter, and it accumulates.
///
/// Done while holding the lock, which is what makes it safe: the name is one
/// only this module produces, and no other irlume can be mid-write. Nothing
/// outside that pattern is ever considered, because a cleanup that reasons about
/// what "looks unexpected" is how a harness in this project deleted a real
/// conffile.
pub(super) fn sweep_abandoned_scratch() {
    let dir = std::path::Path::new("/etc/pam.d");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') && name.contains(".irlume-") && name.ends_with(".tmp") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

// ---- file ops ----------------------------------------------------------------

pub(super) fn service_present(s: &Svc) -> Option<PathBuf> {
    if Path::new(s.etc).exists() {
        return Some(PathBuf::from(s.etc));
    }
    s.vendor
        .filter(|v| Path::new(v).exists())
        .map(|_| PathBuf::from(s.etc))
}

/// Test-only: replace a target during the window between the first look and the
/// rename, so the recheck has something to catch.
///
/// The window cannot be reached from outside (it is entirely inside one
/// function call), so a test that only sets up a symlink beforehand proves the
/// FIRST check, never the second. Without this, removing the pre-rename recheck
/// left every test green.
#[cfg(test)]
pub(super) fn swap_target_for_test(path: &Path) {
    let mut armed = SWAP_DURING_WRITE.lock().unwrap_or_else(|e| e.into_inner());
    if armed.as_deref() != Some(path) {
        return;
    }
    *armed = None;
    // A different inode under the same name: what an administrator, a package
    // or another writer does in that window.
    //
    // Written elsewhere and renamed over, NOT removed and recreated. Removing
    // frees the inode number, and a filesystem is free to hand the same one
    // straight back: this test passed locally and failed in CI for exactly that
    // reason. Both files exist at once here, so the numbers cannot coincide.
    let replacement = path.with_extension("irlume-swap-source");
    let _ = std::fs::write(&replacement, "SOMEONE ELSE'S FILE\n");
    let _ = std::fs::rename(&replacement, path);
}

#[cfg(test)]
pub(super) static SWAP_DURING_WRITE: std::sync::Mutex<Option<PathBuf>> =
    std::sync::Mutex::new(None);

/// What a PAM path is, for deciding whether irlume may replace it.
///
/// `None` means it does not exist, which is a legitimate state: apply removes an
/// override it created, and rollback recreates a file that was absent.
pub(super) type TargetState = Option<(u64, u64)>;

/// Establish that a PAM path is something irlume may replace, and identify it.
///
/// Two things are refused, and previously each was refused in one place or in
/// none:
///
/// - **A symlink.** Renaming over it REPLACES the link with a regular file, and
///   a rollback restores content rather than the link, so the conversion is
///   silent and permanent. Writing through it instead is no better: on Fedora
///   these point into `/etc/authselect` and on Debian into `/etc/alternatives`,
///   shared targets other tooling owns. `apply` checked this; human
///   enable/disable, reconcile and rollback did not, so one command refused a
///   file another would quietly convert.
/// - **More than one link to the inode.** A rename replaces one directory entry;
///   every other name for that inode keeps referring to the OLD content. PAM
///   then reads one inode while package tooling updates another. The link
///   topology is recorded nowhere, so irlume could not put it back, which makes
///   breaking it silently the wrong default.
///
/// The identity returned is the device and inode, which is what the caller
/// compares to decide the name still refers to the same file. That is the usual
/// answer and not a perfect one: a filesystem may hand the same inode number
/// back for a file created right after the old one was unlinked, so a
/// replacement can in principle wear the identity of what it replaced. irlume's
/// own paths cannot collide here because they hold the PAM lock; against an
/// external writer this narrows the window rather than closing it.
pub(super) fn inspect_target(path: &Path) -> Result<TargetState, String> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("stat {}: {e}", path.display())),
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink; irlume will not replace it with a regular file, because that \
             conversion cannot be undone and the target belongs to another tool \
             (authselect, alternatives)",
            path.display()
        ));
    }
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.nlink() > 1 {
        return Err(format!(
            "{} has {} hard links; replacing it would leave the other names referring to the \
             old content, and irlume does not record the link topology so it could not put \
             it back",
            path.display(),
            meta.nlink()
        ));
    }
    Ok(Some((meta.dev(), meta.ino())))
}

/// A scratch path in the same directory as `path`, unique to this call.
///
/// Every write here used to share one name per service, `.{service}.irlume.tmp`.
/// Two irlume processes writing the same PAM file would open that one inode and
/// interleave their bodies, and whichever renamed first published whatever was
/// in it: an atomic rename makes the NAME change indivisible, it does not make
/// concurrent production of the source safe. The PAM lock now keeps irlume's own
/// paths apart, and a unique name means a leftover from a killed run is never
/// adopted either.
pub(super) fn scratch_path(path: &Path, kind: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("pam");
    dir.join(format!(
        ".{fname}.irlume-{kind}.{}.{seq}.tmp",
        std::process::id()
    ))
}

/// Create the scratch file, never adopting one that is already there.
pub(super) fn create_scratch(tmp: &Path) -> Result<std::fs::File, String> {
    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
    };
    match open() {
        // Same pid and counter as a crashed earlier run. Drop it rather than
        // write into a file whose contents are somebody else's.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(tmp).map_err(|e| format!("remove {}: {e}", tmp.display()))?;
            open().map_err(|e| format!("create {}: {e}", tmp.display()))
        }
        other => other.map_err(|e| format!("create {}: {e}", tmp.display())),
    }
}

/// Make a directory durable, so an entry created in it survives a power loss.
pub(super) fn fsync_dir(dir: &Path) -> Result<(), String> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync {}: {e}", dir.display()))
}

/// Copy `path` to its `.pre-irlume` backup, atomically, if there is not one yet.
///
/// The copy used to go straight to the final name. A kill or an ENOSPC part way
/// through left a TRUNCATED file at `.pre-irlume`, and the next enable treats an
/// existing backup as the pristine origin to rebuild from, so a half-copied
/// stack became the authority for what the machine's PAM should contain. A
/// backup that only ever appears complete cannot be believed part way.
///
/// The destination is published with `hard_link`, which fails if the name
/// already exists rather than replacing it. An `exists()` test followed by a
/// rename would be the same check-then-act split this file has been bitten by
/// before, and would let a retry overwrite a good backup with the already-wired
/// content.
pub(super) fn backup(path: &Path) -> Result<(), String> {
    let bak = PathBuf::from(format!("{}{BACKUP}", path.display()));
    // The backup is held to the same standard as the stack it came from, and it
    // was not. `exists()` follows a symlink, so a `.pre-irlume` pointing
    // somewhere else was accepted and then used as the pristine origin a later
    // enable rebuilds from. A DANGLING one was worse: `exists()` said no, and the
    // publishing link then failed with EEXIST against the symlink's own name,
    // which read as "a backup is already there" when there was none at all.
    // A complete backup already there is left alone; it must not be replaced
    // with the now-wired content.
    if inspect_target(&bak)?.is_some() {
        return Ok(());
    }
    let contents = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    let tmp = scratch_path(path, "bak");
    let written = (|| -> Result<(), String> {
        use std::io::Write as _;
        let mut file = create_scratch(&tmp)?;
        file.write_all(&contents)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        apply_metadata(&tmp, &meta)?;
        // Before the link, so the name never points at bytes that are not there.
        file.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        // Fails with EEXIST if another run got there first, which is the answer
        // wanted: that backup is complete and this one is redundant.
        match std::fs::hard_link(&tmp, &bak) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
            Err(e) => return Err(format!("backup {}: {e}", path.display())),
        }
        fsync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
    })();
    let _ = std::fs::remove_file(&tmp);
    written
}

/// Copy mode and ownership onto a path.
pub(super) fn apply_metadata(path: &Path, meta: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(meta.mode() & 0o7777))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    std::os::unix::fs::chown(path, Some(meta.uid()), Some(meta.gid()))
        .map_err(|e| format!("chown {}: {e}", path.display()))
}

pub(super) fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let existing = std::fs::symlink_metadata(path).ok();
    write_atomic_inner(path, contents, existing.as_ref().map(mode_uid_gid))
}

pub(super) fn mode_uid_gid(meta: &std::fs::Metadata) -> (u32, u32, u32) {
    use std::os::unix::fs::MetadataExt as _;
    (meta.mode() & 0o7777, meta.uid(), meta.gid())
}

/// Replace `path` with `contents`, durably, carrying the given mode and owner.
///
/// Attributes are set on the scratch file BEFORE the rename, so the name never
/// resolves to a PAM file with the wrong mode or owner. Setting them afterwards
/// leaves a window in which the live stack is whatever the root process's umask
/// produced, and on the restore path the file did not exist to copy from at all.
///
/// `sync_all` before the rename and an fsync of `/etc/pam.d` after it: without
/// them a successful `close` says nothing about what survives a power loss, and
/// a PAM stack that comes back as a mixture of two versions is the failure this
/// whole module exists to avoid.
pub(super) fn write_atomic_inner(
    path: &Path,
    contents: &str,
    attrs: Option<(u32, u32, u32)>,
) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    // What the target is right now. A rename REPLACES whatever the name refers
    // to, so this has to be settled before anything is written, and confirmed
    // again before the name is taken over.
    let before = inspect_target(path)?;
    let tmp = scratch_path(path, "new");
    let result = (|| -> Result<(), String> {
        let mut file = create_scratch(&tmp)?;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        if let Some((mode, uid, gid)) = attrs {
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
                .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
            // Ownership needs privilege, which every caller that writes PAM has,
            // but an unusual filesystem can still refuse. A PAM file with the
            // wrong group is a real access change, so it is reported.
            std::os::unix::fs::chown(&tmp, Some(uid), Some(gid))
                .map_err(|e| format!("chown {}: {e}", tmp.display()))?;
        }
        file.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        drop(file);
        #[cfg(test)]
        swap_target_for_test(path);
        // Immediately before the name is taken over, not once at the start. The
        // first look and the rename are two moments, and what matters is what
        // the name refers to at the instant it is replaced.
        if inspect_target(path)? != before {
            return Err(format!(
                "{} changed while irlume was writing it, so it was left alone",
                path.display()
            ));
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))?;
        fsync_dir(&dir)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

// ---- SELinux (Fedora) --------------------------------------------------------
