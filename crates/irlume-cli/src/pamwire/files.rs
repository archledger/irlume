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
use super::{lock_surface_for, removal_orphans_service, Svc, FP_GREETERS, GREETERS, POLKIT, SUDO};
use std::path::{Path, PathBuf};

pub(super) fn read(p: &str) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("read {p}: {e}"))
}

/// A file's text, or `None` when it does not exist. Any other failure is an
/// error: a file that cannot be read is not an absent one.
pub(super) fn read_optional(p: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(p) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {e}", p.display())),
    }
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
    // The backup as well as the live file. The backup decides what a disable
    // does (restore it, or strip in place), so a backup that changed between
    // the plan and the apply changes the outcome while the live file, and
    // therefore the plan id, stayed identical. The consumer would be shown one
    // result and the machine would get another.
    let bak = PathBuf::from(format!("{}{BACKUP}", path.display()));
    format!("{} {}", surface_digest(path), surface_digest(&bak))
}

/// [`surface_state`] plus, for a service with a vendor path, the vendor file's
/// digest. The vendor file decides what happens to an override (and whether
/// one is created at all), so a vendor update between `plan` and `apply` is a
/// change to the machine the plan did not show. Covered for every surface with
/// a vendor path, override or not: when `/etc` is absent the vendor file alone
/// decides, and a uniform rule cannot miss a switch between the two.
pub(super) fn surface_state_for(svc: &Svc) -> String {
    let state = surface_state(Path::new(svc.etc));
    match svc.vendor {
        Some(vendor) => format!("{state} {}", surface_digest(Path::new(vendor))),
        None => state,
    }
}

pub(crate) fn surface_digest(path: &Path) -> String {
    match crate::logintx::file_sha256(path) {
        Ok(Some(digest)) => digest,
        Ok(None) => crate::logintx::ABSENT.to_string(),
        Err(_) => UNREADABLE.to_string(),
    }
}

/// What [`surface_digest`] says about a file that exists but cannot be read.
pub(crate) const UNREADABLE: &str = "unreadable";

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
    is_managed_path_for(
        irlume_common::platform::omarchy_present(),
        std::path::Path::new("/etc/pam.d/cinnamon-screensaver").exists(),
        path,
    )
}

/// Testable core of [`is_managed_path`], so the rollback test can pin the
/// KDE fallback without reading the host filesystem (the live call would
/// reject `/etc/pam.d/kde` on an Omarchy or Cinnamon box where the
/// dynamic chooser picks a different lock surface).
pub(crate) fn is_managed_path_for(omarchy: bool, cinnamon: bool, path: &str) -> bool {
    let bare = path.strip_suffix(BACKUP).unwrap_or(path);
    // Built from the same lists the wiring uses, so a surface added there is
    // restorable without anyone remembering to update a second list. The
    // lock surface goes through the same dynamic chooser the wiring walks.
    let (lock_svc, _) = lock_surface_for(omarchy, cinnamon);
    GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .map(|s| s.etc)
        .chain([lock_svc.etc, POLKIT.etc, SUDO.etc])
        .any(|managed| managed == bare)
}

/// Put one surface back to the content recorded before a transaction.
///
/// Reuses the same atomic write the wiring path uses, so a restore lands the
/// way every other PAM write here does. The caller must have checked
/// `unchanged_since_apply` first; this does the write, not the decision. A
/// file that already holds the recorded content is not written at all.
///
/// `None` content means the file did not exist before, so it is removed rather
/// than written empty: an empty PAM file is not the same as an absent one, and
/// leaving one behind would shadow a vendor copy.
pub(crate) fn restore_surface(
    path: &Path,
    before: Option<&str>,
    metadata: Option<(u32, u32, u32)>,
) -> Result<(), String> {
    restore_surface_with(path, before, metadata, &removal_orphans_service)
}

/// [`restore_surface`] with the test for "removing this leaves its service
/// with no PAM configuration" given, so a test can name surfaces under a
/// temporary root.
pub(crate) fn restore_surface_with(
    path: &Path,
    before: Option<&str>,
    metadata: Option<(u32, u32, u32)>,
    orphans: &dyn Fn(&Path) -> bool,
) -> Result<(), String> {
    match before {
        // A file that already holds the recorded bytes is left as it is, read
        // through the path as the digest a rollback checks is. That is every
        // surface the transaction did not write: one it refused (a symlink,
        // or one of several names for a file) and one it left alone because
        // it changed after the plan. Writing it anyway replaced the file with
        // a new one: on a link that is the replacement irlume refuses, so the
        // rollback stopped there and never reached the surfaces after it, and
        // on a regular file it put the recorded mode back over one set since
        // and dropped anything else attached to the old inode.
        Some(content) if std::fs::read(path).is_ok_and(|now| now == content.as_bytes()) => Ok(()),
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
            write_atomic_inner(path, content, attrs, None).map_err(String::from)
        }
        None => {
            // The same refusal the replacing branch gets. Removing was a direct
            // `remove_file`, so a path recorded as previously absent that is now
            // a symlink was unlinked despite the claim that every write path
            // refuses one, and a multiply-linked file lost a name irlume cannot
            // put back.
            inspect_target(path)?;
            // A file apply created from a vendor copy that has since gone is
            // now the service's only configuration; removing it would leave PAM
            // with nothing for the service but the denying `other` stack.
            if orphans(path) {
                return Err(format!(
                    "{} is now its service's only PAM configuration (the vendor copy it was \
                     made from is gone); not removed",
                    path.display()
                ));
            }
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
        if is_abandoned_scratch(name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Whether [`sweep_abandoned_scratch`] removes a file of this name.
pub(super) fn is_abandoned_scratch(name: &str) -> bool {
    name.starts_with('.') && name.contains(".irlume-") && name.ends_with(".tmp")
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

/// Test-only: the paths a hook below acts on, each once. A set rather than
/// one slot, so tests running on parallel threads, each arming a hook for
/// its own path, do not disarm each other's.
#[cfg(test)]
pub(super) type TestHook = std::sync::Mutex<Vec<PathBuf>>;

/// Test-only: make `hook` act once on `path`.
#[cfg(test)]
pub(super) fn arm(hook: &TestHook, path: &Path) {
    hook.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(path.to_path_buf());
}

/// Test-only: take `path` off `hook` if it has not acted.
#[cfg(test)]
pub(super) fn disarm(hook: &TestHook, path: &Path) {
    hook.lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|armed| armed != path);
}

/// Test-only: whether `hook` is armed for `path`, disarming it.
#[cfg(test)]
fn fires(hook: &TestHook, path: &Path) -> bool {
    let mut armed = hook.lock().unwrap_or_else(|e| e.into_inner());
    let at = armed.iter().position(|armed| armed == path);
    at.map(|at| armed.remove(at)).is_some()
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
    if !fires(&SWAP_DURING_WRITE, path) {
        return;
    }
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
pub(super) static SWAP_DURING_WRITE: TestHook = TestHook::new(Vec::new());

/// Test-only: rewrite a target IN PLACE (same file, new bytes) in the window
/// between [`remove_checked`]'s check and its removal, as an editor that
/// saves in place does.
#[cfg(test)]
pub(super) fn edit_target_for_test(path: &Path) {
    if !fires(&EDIT_DURING_REMOVE, path) {
        return;
    }
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"EDITED IN PLACE\n"));
}

#[cfg(test)]
pub(super) static EDIT_DURING_REMOVE: TestHook = TestHook::new(Vec::new());

/// Test-only: create a new file at a target [`remove_checked`] has just
/// renamed aside, as a writer arriving in that moment would.
#[cfg(test)]
pub(super) fn occupy_target_for_test(path: &Path) {
    if !fires(&OCCUPY_AFTER_ASIDE, path) {
        return;
    }
    let _ = std::fs::write(path, "A NEWER FILE\n");
}

#[cfg(test)]
pub(super) static OCCUPY_AFTER_ASIDE: TestHook = TestHook::new(Vec::new());

/// Test-only: fail the directory sync that follows the rename or unlink of
/// this path, as an I/O error there would, so a failure after the change is
/// reachable.
#[cfg(test)]
pub(super) static FAIL_SYNC_AFTER_CHANGE: TestHook = TestHook::new(Vec::new());

/// Make the change to `path` durable. A failure here comes after the change,
/// so it is reported as one that landed.
fn sync_after_change(path: &Path) -> Result<(), WriteError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(test)]
    if fires(&FAIL_SYNC_AFTER_CHANGE, path) {
        return Err(WriteError::landed(format!(
            "fsync {}: failed for the test",
            dir.display()
        )));
    }
    fsync_dir(dir).map_err(WriteError::landed)
}

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
/// through left a TRUNCATED file at `.pre-irlume`, and the next enable then
/// treated an existing backup as the pristine origin to rebuild from, so a half-copied
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
    // enable rebuilt from. A DANGLING one was worse: `exists()` said no, and the
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

/// Keep the current file as `<path>.pre-irlume` before `login enable --force`
/// rebuilds it, so the lines it drops are still on disk.
///
/// Published like [`backup`], through a scratch file and a hard link that
/// refuses to replace anything. Unlike `backup`, an existing copy is accepted
/// only when it holds exactly these bytes: a different one (a stale backup
/// from in-place wiring, left by a distribution upgrade) would otherwise be
/// kept while the caller reported the new copy.
pub(super) fn keep_copy(path: &Path) -> Result<(), String> {
    let bak = PathBuf::from(format!("{}{BACKUP}", path.display()));
    let contents = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let same_as_existing = || -> Result<(), String> {
        let existing = std::fs::read(&bak).map_err(|e| format!("read {}: {e}", bak.display()))?;
        if existing == contents {
            Ok(())
        } else {
            Err(format!(
                "{} already holds a different file; move it away and run again",
                bak.display()
            ))
        }
    };
    if inspect_target(&bak)?.is_some() {
        return same_as_existing();
    }
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    let tmp = scratch_path(path, "bak");
    let written = (|| -> Result<(), String> {
        use std::io::Write as _;
        let mut file = create_scratch(&tmp)?;
        file.write_all(&contents)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        apply_metadata(&tmp, &meta)?;
        file.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        match std::fs::hard_link(&tmp, &bak) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return same_as_existing(),
            Err(e) => return Err(format!("keep {}: {e}", bak.display())),
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

/// A PAM write or removal that did not complete.
#[derive(Debug)]
pub(super) struct WriteError {
    pub(super) message: String,
    /// The file had already been replaced or removed when this failed: only
    /// making that durable was left, so the change is irlume's. Otherwise
    /// irlume changed nothing at the path, and what is there is the file it
    /// found, or one another writer put there meanwhile, which a refusal
    /// keeps.
    pub(super) landed: bool,
}

impl WriteError {
    /// A failure after the file at the path was replaced or removed.
    fn landed(message: String) -> Self {
        Self {
            message,
            landed: true,
        }
    }
}

impl From<String> for WriteError {
    fn from(message: String) -> Self {
        Self {
            message,
            landed: false,
        }
    }
}

impl From<WriteError> for String {
    fn from(error: WriteError) -> Self {
        error.message
    }
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub(super) fn write_atomic(path: &Path, contents: &str) -> Result<(), WriteError> {
    let existing = std::fs::symlink_metadata(path).ok();
    write_atomic_inner(path, contents, existing.as_ref().map(mode_uid_gid), None)
}

/// [`write_atomic`], refusing when the file no longer holds `expected` at the
/// moment of the rename. The identity check alone misses an editor that saves
/// in place (same inode), and a write decided on the old bytes would then
/// replace the new ones. `None` expects nothing in particular (a file being
/// created is covered by the identity check).
pub(super) fn write_atomic_checked(
    path: &Path,
    contents: &str,
    expected: Option<&str>,
) -> Result<(), WriteError> {
    let existing = std::fs::symlink_metadata(path).ok();
    write_atomic_inner(
        path,
        contents,
        existing.as_ref().map(mode_uid_gid),
        expected.map(str::as_bytes),
    )
}

/// Delete `path` only while it holds exactly `expected`, with the checks every
/// write here makes: never through a symlink or one of several names. A
/// package manager or an editor that replaced the file after irlume read it
/// keeps its file, and an editor that saved in place keeps its save when the
/// save lands before the second check below.
///
/// The check and the removal act on one file. Checking the bytes at the path
/// and then unlinking the path are two moments, and the PAM lock does not
/// exclude other writers: a file renamed over the path between them was
/// deleted unseen. So the file is opened and checked through that open file,
/// then renamed to a private name in the same directory, and only that name
/// is unlinked, once it is known to be the same file still holding the same
/// bytes. A file that replaced it meanwhile is moved back, never over a newer
/// one, and the removal is refused.
///
/// What this cannot see: a writer that already had the file open when it was
/// renamed aside, and writes to it after the second check, writes into the
/// removed file. No removal built on unlinking a name can see that write; the
/// window is the one between the second check and the unlink.
///
/// `None` expects the file to be absent: nothing is removed, and a file that
/// appeared is left alone.
pub(super) fn remove_checked(path: &Path, expected: Option<&str>) -> Result<(), WriteError> {
    use std::io::{Read as _, Seek as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let changed = || {
        format!(
            "{} changed while irlume was reading it; not touched",
            path.display()
        )
    };
    // The refusals every write makes, with their own reasons.
    let Some(identity) = inspect_target(path)? else {
        return expected.map_or(Ok(()), |_| Err(changed().into()));
    };
    let Some(expected) = expected else {
        return Err(changed().into());
    };
    // No symlink is followed from here on: a path that became one since
    // fails to open.
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(changed().into()),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(changed().into()),
        Err(e) => return Err(format!("open {}: {e}", path.display()).into()),
    };
    let holds_expected = |file: &mut std::fs::File| -> Result<bool, String> {
        let meta = file
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        let mut bytes = Vec::new();
        file.rewind()
            .and_then(|()| file.read_to_end(&mut bytes))
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        Ok(meta.file_type().is_file()
            && meta.nlink() == 1
            && (meta.dev(), meta.ino()) == identity
            && bytes == expected.as_bytes())
    };
    if !holds_expected(&mut file)? {
        return Err(changed().into());
    }
    #[cfg(test)]
    swap_target_for_test(path);
    #[cfg(test)]
    edit_target_for_test(path);
    let aside = move_aside(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => changed(),
        _ => format!("rename {} aside: {e}", path.display()),
    })?;
    #[cfg(test)]
    occupy_target_for_test(path);
    // What was renamed is whatever held the name at that instant. Only the
    // file checked above, still holding the checked bytes, is removed: a
    // file renamed over the path since the check, or this one edited in
    // place before this second look, goes back where it was.
    let same_file =
        std::fs::symlink_metadata(&aside).is_ok_and(|meta| (meta.dev(), meta.ino()) == identity);
    let verdict = if same_file {
        holds_expected(&mut file)
    } else {
        Ok(false)
    };
    if verdict != Ok(true) {
        let why = verdict.err().unwrap_or_else(changed);
        return match put_back(&aside, path) {
            Ok(()) => Err(why.into()),
            Err(e) => Err(format!(
                "{} changed while irlume was removing it, and could not be put back ({e}); \
                 the file that was there is at {}",
                path.display(),
                aside.display()
            )
            .into()),
        };
    }
    // The checked file no longer has its name from here on, so a failure
    // now is one after the change.
    std::fs::remove_file(&aside)
        .map_err(|e| WriteError::landed(format!("rm {}: {e}", aside.display())))?;
    sync_after_change(path)
}

/// Rename `path` to a private name in its directory, hidden, unique to this
/// call and never an existing file's, and return that name. Not a scratch
/// name: the sweep of abandoned scratch files must never delete a file that
/// [`remove_checked`] could not put back.
fn move_aside(path: &Path) -> std::io::Result<PathBuf> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("pam");
    let mut attempts = 0;
    loop {
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let aside = dir.join(format!(
            ".{fname}.irlume-removing.{}.{seq}",
            std::process::id()
        ));
        let moved = match renameat2_noreplace(path, &aside) {
            // No RENAME_NOREPLACE on this filesystem. The name is this call's
            // own, so a plain rename replaces nothing unless a file left by an
            // earlier run has it, which is checked first.
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => {
                match std::fs::symlink_metadata(&aside) {
                    Ok(_) => Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists)),
                    Err(_) => std::fs::rename(path, &aside),
                }
            }
            other => other,
        };
        match moved {
            Ok(()) => return Ok(aside),
            // A leftover from an earlier run with the same process id.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempts < 8 => {
                attempts += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Rename `aside` back to `path`, failing rather than replacing a file that
/// took the name meanwhile. Without `RENAME_NOREPLACE` a hard link gives the
/// same refusal.
fn put_back(aside: &Path, path: &Path) -> std::io::Result<()> {
    match renameat2_noreplace(aside, path) {
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => {
            std::fs::hard_link(aside, path)?;
            std::fs::remove_file(aside)
        }
        other => other,
    }
}

/// `renameat2(2)` with `RENAME_NOREPLACE`: `EEXIST` when `to` exists.
fn renameat2_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    };
    let (from_c, to_c) = (c(from)?, c(to)?);
    // SAFETY: both pointers come from CStrings that live until the call
    // returns, and AT_FDCWD resolves them as rename(2) would.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
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
    expected: Option<&[u8]>,
) -> Result<(), WriteError> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    // What the target is right now. A rename REPLACES whatever the name refers
    // to, so this has to be settled before anything is written, and confirmed
    // again before the name is taken over.
    let before = inspect_target(path)?;
    let tmp = scratch_path(path, "new");
    let result = (|| -> Result<(), WriteError> {
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
        if inspect_target(path)? != before
            || expected.is_some_and(|want| std::fs::read(path).ok().as_deref() != Some(want))
        {
            return Err(format!(
                "{} changed while irlume was writing it, so it was left alone",
                path.display()
            )
            .into());
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))?;
        sync_after_change(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

// ---- SELinux (Fedora) --------------------------------------------------------
