// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded filesystem observations, not proof of what a running daemon loaded.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::super::autologin::{LIGHTDM_DROP_IN_DIRS, LIGHTDM_MAIN};

const MAX_ENTRIES: usize = 4096;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Keep dangling names: although LightDM skips them now, the running daemon
/// may have loaded their old targets. Ordering matches the standard file list.
pub(super) fn files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut count = 0;
    for dir in LIGHTDM_DROP_IN_DIRS {
        let dir = root.join(dir);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        let mut group = Vec::new();
        for entry in entries {
            count += 1;
            if count > MAX_ENTRIES {
                return Err("too many LightDM configuration entries".into());
            }
            let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
            // LightDM tries every name ending in ".conf", the bare name
            // included; Path::extension would miss ".conf".
            if path
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().ends_with(b".conf"))
            {
                group.push(path);
            }
        }
        group.sort();
        files.extend(group);
    }
    files.push(root.join(LIGHTDM_MAIN));
    Ok(files)
}

/// Do not block on a FIFO or read an unbounded configuration into memory.
pub(super) fn read(path: &Path) -> Result<Option<String>, String> {
    read_bytes(path, MAX_FILE_BYTES)?
        .map(|bytes| {
            String::from_utf8(bytes)
                .map_err(|_| format!("{}: configuration is not UTF-8", path.display()))
        })
        .transpose()
}

pub(super) fn read_bytes(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, String> {
    // Pin the resolved object without invoking a device's open operation.
    // Follow distro symlinks, then type-check before any normal open.
    let pinned = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    read_pinned(pinned, path, limit).map(Some)
}

fn read_pinned(pinned: File, path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let meta = pinned
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.len() > limit {
        return Err(format!("{}: not a bounded regular file", path.display()));
    }
    // Reopen the pinned regular inode, never the replaceable pathname.
    // Proc files can report length zero; take(limit + 1) bounds the read.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !opened.is_file() || (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
        return Err(format!("{}: pinned file identity changed", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{}: configuration too large", path.display()));
    }
    Ok(bytes)
}

/// Capture link inodes and resolved targets, using the nearest surviving
/// ancestor only for a missing target/path. Resolve components before
/// `..`: lexical normalization would change the meaning of a directory link.
/// Forty recursive resolutions bound cycles and adversarial link graphs.
pub(super) fn change_time(path: &Path) -> Result<Option<SystemTime>, String> {
    path_change(path, false, &mut 40)
}

fn path_change(
    path: &Path,
    missing_parent: bool,
    budget: &mut usize,
) -> Result<Option<SystemTime>, String> {
    if *budget == 0 {
        return Err("LightDM configuration symlink resolution limit".into());
    }
    *budget -= 1;
    if !path.is_absolute() || path.components().count() > 256 {
        return Err("LightDM configuration path is not bounded and absolute".into());
    }
    let mut current = PathBuf::new();
    let mut components = path.components();
    while let Some(component) = components.next() {
        if component == Component::ParentDir {
            current.pop();
        } else {
            current.push(component);
        }
        let meta = match std::fs::symlink_metadata(&current) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return if missing_parent {
                    current.pop();
                    std::fs::metadata(&current)
                        .map(|meta| timestamp(&meta))
                        .map_err(|e| format!("{}: {e}", current.display()))
                } else {
                    Ok(None)
                };
            }
            Err(e) => return Err(format!("{}: {e}", current.display())),
        };
        if meta.file_type().is_symlink() {
            let target =
                std::fs::read_link(&current).map_err(|e| format!("{}: {e}", current.display()))?;
            let target = if target.is_absolute() {
                target
            } else {
                current
                    .parent()
                    .ok_or("symlink has no parent")?
                    .join(target)
            };
            let resolved = if components.as_path().as_os_str().is_empty() {
                target
            } else {
                target.join(components.as_path())
            };
            let target_time = path_change(&resolved, true, budget)?;
            return Ok(timestamp(&meta).max(target_time));
        }
        if components.as_path().as_os_str().is_empty() {
            return Ok(timestamp(&meta));
        }
    }
    Ok(None)
}

fn timestamp(meta: &Metadata) -> Option<SystemTime> {
    let ctime = u64::try_from(meta.ctime()).ok().and_then(|secs| {
        let nanos = u32::try_from(meta.ctime_nsec())
            .ok()
            .filter(|n| *n < 1_000_000_000)?;
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
    });
    meta.modified().ok().max(ctime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reopening_a_pinned_regular_file_does_not_follow_a_replaced_name() {
        let path = std::env::temp_dir().join(format!(
            "irlume-lightdm-pinned-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup = Cleanup(path.clone());
        std::fs::write(&path, b"original").unwrap();
        let pinned = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(read_pinned(pinned, &path, 1024).unwrap(), b"original");
        assert_eq!(read_bytes(&path, 1024).unwrap().unwrap(), b"replacement");
    }
}
