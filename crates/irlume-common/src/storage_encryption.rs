// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Whether a path lives on encrypted block storage (dm-crypt).
//!
//! Best effort, read-only and never panics. Anything this cannot establish
//! reads [`StorageEncryption::Unknown`], never
//! [`StorageEncryption::Encrypted`].
//!
//! Resolution:
//!
//! 1. The path's `st_dev`. A filesystem on one block device (ext4, xfs)
//!    reports that device's number, found as `/sys/dev/block/MAJ:MIN`.
//! 2. Otherwise, as for btrfs, whose `st_dev` is an anonymous number, the
//!    mount that holds the path in `/proc/self/mountinfo` (the longest mount
//!    point containing it; the later entry on a tie, since it is mounted
//!    over the earlier) names its source device. That source is matched in
//!    sysfs without a stat of its `/dev` node: `/dev/mapper/<name>` by the
//!    device-mapper `dm/name`, another `/dev` path by the entry directly in
//!    `/dev` its links lead to. A btrfs filesystem can span several devices,
//!    so every device `/sys/fs/btrfs/<fsid>/devices` lists for it counts.
//! 3. The device stack below, in `/sys/class/block/<name>`: a device-mapper
//!    node whose `dm/uuid` names a cryptsetup encryption type
//!    (`CRYPT-LUKS2-...`, `CRYPT-PLAIN-...`) is dm-crypt; any other stacked
//!    device (LVM, md RAID, dm-verity, dm-integrity) is encrypted only when
//!    every device under its `slaves/` is; a partition is judged by the disk
//!    that holds it; a disk with nothing below it is not encrypted; a loop
//!    device, or a stacked device with nothing listed below it, is unknown.
//!
//! A self-encrypting drive's hardware encryption is not visible here and
//! reads as not encrypted.
//!
//! [`path_encryption`] reads the fixed system paths; `path_encryption_in`
//! takes the roots, so the tests run against fixture trees.

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Whether the block storage under a path is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageEncryption {
    /// Every block device under the path has a dm-crypt layer.
    Encrypted,
    /// At least one block device under the path has no dm-crypt layer.
    NotEncrypted,
    /// Could not be established: an unreadable or unexpected `/proc` or
    /// `/sys` entry, a mount source that is not a block device, a loop
    /// device, or a path that does not exist. A value a later release adds
    /// reads as this in an earlier client (`Response::SealedStorage`), so
    /// the reply keeps its other entries.
    #[serde(other)]
    Unknown,
}

/// Storage under a configured directory, without any account or secret data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDirectory {
    /// The configured directory, retained even when it cannot be resolved.
    /// A daemon reply to a non-root peer uses a logical label for its
    /// configured secret directories instead.
    pub path: String,
    /// Whether every block device beneath the directory is encrypted.
    pub encryption: StorageEncryption,
    /// Why an unknown result could not be established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Deepest device stack walked before giving up (a cycle in a broken sysfs
/// would otherwise recurse forever). Real stacks are 2 to 4 deep.
const MAX_DEPTH: u8 = 16;

/// cryptsetup's dm uuid types that are encryption. Its other `CRYPT-` types
/// (`VERITY`, `INTEGRITY`, `SUBDEV`) are integrity layers.
const CRYPT_TYPES: &[&str] = &[
    "LUKS1", "LUKS2", "PLAIN", "LOOPAES", "TCRYPT", "BITLK", "FVAULT2",
];

/// Where the probe reads. Only tests point it anywhere but `/`.
struct Roots {
    mountinfo: PathBuf,
    sys: PathBuf,
    dev: PathBuf,
}

impl Roots {
    fn system() -> Self {
        Roots {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            sys: PathBuf::from("/sys"),
            dev: PathBuf::from("/dev"),
        }
    }
}

/// Whether `path` lives on encrypted block storage, read from this process's
/// view of `/proc` and `/sys`.
pub fn path_encryption(path: &Path) -> StorageEncryption {
    path_encryption_in(path, &Roots::system())
}

/// Describe storage beneath a configured directory, resolving existing links
/// and using a missing directory's nearest existing parent when unambiguous.
/// Denied traversal stays unknown because an unseen link may lead elsewhere.
pub fn directory_encryption(path: &Path) -> StorageDirectory {
    directory_encryption_with(
        path,
        |at| fs::symlink_metadata(at),
        mount_between,
        path_encryption,
    )
}

fn directory_encryption_with(
    path: &Path,
    inspect: impl Fn(&Path) -> std::io::Result<fs::Metadata>,
    mount_between: impl FnOnce(&Path, &Path) -> Option<bool>,
    probe: impl FnOnce(&Path) -> StorageEncryption,
) -> StorageDirectory {
    let resolve = || -> Result<PathBuf, String> {
        if !path.is_absolute() {
            return Err("directory path is not absolute".into());
        }
        let mut at = path;
        loop {
            match inspect(at) {
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    at = at.parent().ok_or_else(|| {
                        "could not resolve an existing parent directory".to_string()
                    })?;
                }
                Err(error) => {
                    return Err(format!("could not resolve {}: {error}", at.display()));
                }
            }
        }
        let ancestor = fs::canonicalize(at)
            .map_err(|error| format!("could not resolve {}: {error}", at.display()))?;
        let metadata = fs::metadata(&ancestor)
            .map_err(|error| format!("could not read {}: {error}", ancestor.display()))?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", at.display()));
        }
        if at != path {
            let rest = path
                .strip_prefix(at)
                .map_err(|error| format!("could not resolve directory suffix: {error}"))?;
            // Only missing plain components can inherit their parent's storage.
            if !rest
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            {
                return Err("could not resolve non-plain directory components".into());
            }
            match mount_between(&ancestor, &ancestor.join(rest)) {
                Some(false) => {}
                Some(true) => {
                    return Err("a mount lies between the missing directory and its parent".into());
                }
                None => {
                    return Err("mount information for the missing directory is unavailable".into())
                }
            }
        }
        Ok(ancestor)
    };
    let result = match resolve() {
        Ok(resolved) => match probe(&resolved) {
            StorageEncryption::Unknown => Err(
                "block-storage encryption could not be established from the available device information"
                    .to_string(),
            ),
            encryption => Ok(encryption),
        },
        Err(reason) => Err(reason),
    };
    let (encryption, reason) = match result {
        Ok(encryption) => (encryption, None),
        Err(reason) => (StorageEncryption::Unknown, Some(reason)),
    };
    StorageDirectory {
        path: path.to_string_lossy().into_owned(),
        encryption,
        reason,
    }
}

fn path_encryption_in(path: &Path, roots: &Roots) -> StorageEncryption {
    let (Ok(real), Ok(meta)) = (fs::canonicalize(path), fs::metadata(path)) else {
        return StorageEncryption::Unknown;
    };
    let dev = meta.dev();
    classify(&real, libc::major(dev), libc::minor(dev), roots)
}

/// The encryption under canonical path `path`, whose `st_dev` is
/// `major:minor`.
fn classify(path: &Path, major: u32, minor: u32, roots: &Roots) -> StorageEncryption {
    // Major 0 is the kernel's anonymous-device range (btrfs, tmpfs, overlay,
    // network filesystems): no block device has that number.
    if major != 0 {
        if let Some(name) = name_of_dev(&roots.sys, major, minor) {
            return block_encryption(&roots.sys, &name, 0);
        }
    }
    let Ok(text) = fs::read_to_string(&roots.mountinfo) else {
        return StorageEncryption::Unknown;
    };
    let mounts = parse_mountinfo(&text);
    let Some(mount) = mount_holding(&mounts, path) else {
        return StorageEncryption::Unknown;
    };
    let Some(name) = source_device(roots, &mount.source) else {
        return StorageEncryption::Unknown;
    };
    if mount.fstype == "btrfs" {
        return match btrfs_members(&roots.sys, &name) {
            Some(members) => all_of(
                members
                    .iter()
                    .map(|member| block_encryption(&roots.sys, member, 0)),
            ),
            None => StorageEncryption::Unknown,
        };
    }
    block_encryption(&roots.sys, &name, 0)
}

/// The sysfs name of block device `major:minor`, if sysfs knows it.
fn name_of_dev(sys: &Path, major: u32, minor: u32) -> Option<String> {
    let real = fs::canonicalize(sys.join("dev/block").join(format!("{major}:{minor}"))).ok()?;
    plain_name(real.file_name()?)
}

/// A name that is one ordinary path component, so joining it cannot leave
/// the directory it is joined to.
fn plain_name(name: &OsStr) -> Option<String> {
    let name = name.to_str()?;
    let mut parts = Path::new(name).components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(_)), None) => Some(name.to_string()),
        _ => None,
    }
}

/// `Some(true)` when `path` exists, `Some(false)` when it does not, `None`
/// when that cannot be told.
fn present(path: &Path) -> Option<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Some(false),
        Err(_) => None,
    }
}

/// Encrypted only when every part is and there is at least one; one part
/// without encryption makes the whole not encrypted.
fn all_of(parts: impl IntoIterator<Item = StorageEncryption>) -> StorageEncryption {
    let mut any = false;
    let mut unknown = false;
    for part in parts {
        any = true;
        match part {
            StorageEncryption::NotEncrypted => return StorageEncryption::NotEncrypted,
            StorageEncryption::Unknown => unknown = true,
            StorageEncryption::Encrypted => {}
        }
    }
    if any && !unknown {
        StorageEncryption::Encrypted
    } else {
        StorageEncryption::Unknown
    }
}

/// Whether a device-mapper uuid names a cryptsetup encryption mapping.
fn is_crypt_uuid(uuid: &str) -> bool {
    uuid.strip_prefix("CRYPT-")
        .and_then(|rest| rest.split('-').next())
        .is_some_and(|kind| CRYPT_TYPES.contains(&kind))
}

/// Walk block device `name` and what it is stacked on.
fn block_encryption(sys: &Path, name: &str, depth: u8) -> StorageEncryption {
    if depth > MAX_DEPTH {
        return StorageEncryption::Unknown;
    }
    let Some(name) = plain_name(OsStr::new(name)) else {
        return StorageEncryption::Unknown;
    };
    let Ok(real) = fs::canonicalize(sys.join("class/block").join(&name)) else {
        return StorageEncryption::Unknown;
    };
    match present(&real.join("partition")) {
        // A partition's sysfs directory sits inside its disk's.
        Some(true) => {
            return match real.parent().and_then(Path::file_name).and_then(plain_name) {
                Some(disk) => block_encryption(sys, &disk, depth + 1),
                None => StorageEncryption::Unknown,
            };
        }
        Some(false) => {}
        None => return StorageEncryption::Unknown,
    }
    match fs::read_to_string(real.join("dm/uuid")) {
        Ok(uuid) if is_crypt_uuid(uuid.trim()) => return StorageEncryption::Encrypted,
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return StorageEncryption::Unknown,
    }
    let below = match fs::read_dir(real.join("slaves")) {
        Ok(entries) => {
            let mut names = Vec::new();
            for entry in entries {
                let Ok(entry) = entry else {
                    return StorageEncryption::Unknown;
                };
                let Some(slave) = plain_name(&entry.file_name()) else {
                    return StorageEncryption::Unknown;
                };
                names.push(slave);
            }
            names
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
        Err(_) => return StorageEncryption::Unknown,
    };
    if below.is_empty() {
        // A stacked or file-backed device with nothing listed below it
        // cannot be judged; anything else is a disk.
        let mut stacked = false;
        for marker in ["dm", "md", "loop"] {
            match present(&real.join(marker)) {
                Some(true) => stacked = true,
                Some(false) => {}
                None => return StorageEncryption::Unknown,
            }
        }
        return if stacked {
            StorageEncryption::Unknown
        } else {
            StorageEncryption::NotEncrypted
        };
    }
    all_of(
        below
            .iter()
            .map(|slave| block_encryption(sys, slave, depth + 1)),
    )
}

/// One `/proc/self/mountinfo` entry, the fields this needs.
#[derive(Debug, PartialEq, Eq)]
struct Mount {
    mount_point: PathBuf,
    fstype: String,
    source: String,
}

/// Parse mountinfo (proc(5)): field 5 is the mount point; after the `-`
/// separator come the filesystem type and the mount source. Lines that do
/// not have that shape are skipped.
fn parse_mountinfo(text: &str) -> Vec<Mount> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(sep) = fields.iter().skip(6).position(|f| *f == "-") else {
            continue;
        };
        let sep = sep + 6;
        let (Some(mount_point), Some(fstype), Some(source)) =
            (fields.get(4), fields.get(sep + 1), fields.get(sep + 2))
        else {
            continue;
        };
        mounts.push(Mount {
            mount_point: PathBuf::from(unescape(mount_point)),
            fstype: unescape(fstype),
            source: unescape(source),
        });
    }
    mounts
}

/// Undo mountinfo's octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash).
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &bytes[i + 1..i + 4];
            if digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                let value = digits
                    .iter()
                    .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a mount point lies below canonical `ancestor` on the way to
/// `path` (`path` itself included), read from this process's mountinfo;
/// `None` when that cannot be read. This checks whether a missing directory
/// can inherit its parent's storage. It does not resolve symlinks or establish
/// the storage of an existing directory the caller cannot reach.
pub fn mount_between(ancestor: &Path, path: &Path) -> Option<bool> {
    let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
    Some(mount_between_in(&parse_mountinfo(&text), ancestor, path))
}

fn mount_between_in(mounts: &[Mount], ancestor: &Path, path: &Path) -> bool {
    mounts.iter().any(|mount| {
        mount.mount_point != ancestor
            && mount.mount_point.starts_with(ancestor)
            && path.starts_with(&mount.mount_point)
    })
}

/// The mount that holds canonical `path`: the longest mount point containing
/// it, the later entry on a tie (mounted over the earlier).
fn mount_holding<'a>(mounts: &'a [Mount], path: &Path) -> Option<&'a Mount> {
    let mut best: Option<(&Mount, usize)> = None;
    for mount in mounts {
        if !path.starts_with(&mount.mount_point) {
            continue;
        }
        let depth = mount.mount_point.components().count();
        if best.is_none_or(|(_, d)| depth >= d) {
            best = Some((mount, depth));
        }
    }
    best.map(|(mount, _)| mount)
}

/// The sysfs name of the block device a mount source names, found without
/// a stat of any `/dev` node: irlumed's AppArmor profiles grant no block
/// node. A `/dev/mapper/<name>` source is the device-mapper device whose
/// `dm/name` reads `<name>`. Another `/dev` path is followed through its
/// symlinks (`/dev/disk/by-uuid/...` points at `../../nvme0n1p3`), which
/// reads the links and never stats their target, and names the device when
/// it resolves to an entry directly in `/dev` that `class/block` lists.
/// Anything else, a node in a subdirectory included, is not known.
fn source_device(roots: &Roots, source: &str) -> Option<String> {
    let rel = source.strip_prefix("/dev/")?;
    if let Some(mapper) = rel.strip_prefix("mapper/") {
        return dm_device_named(&roots.sys, mapper);
    }
    let node = fs::canonicalize(roots.dev.join(rel)).ok()?;
    if node.parent()? != fs::canonicalize(&roots.dev).ok()? {
        return None;
    }
    let name = plain_name(node.file_name()?)?;
    // Canonicalizing reads the class/block link only; it fails when the
    // entry is missing.
    fs::canonicalize(roots.sys.join("class/block").join(&name)).ok()?;
    Some(name)
}

/// The sysfs name of the device-mapper device called `mapper`: the one
/// `class/block` entry whose `dm/name` reads `mapper`. `None` when no entry
/// or more than one does, or when the listing or an entry's `dm/name`
/// cannot be read.
fn dm_device_named(sys: &Path, mapper: &str) -> Option<String> {
    let mapper = plain_name(OsStr::new(mapper))?;
    let mut found = None;
    for entry in fs::read_dir(sys.join("class/block")).ok()? {
        let entry = entry.ok()?;
        let name = plain_name(&entry.file_name())?;
        match fs::read_to_string(entry.path().join("dm/name")) {
            Ok(text) if text.strip_suffix('\n').unwrap_or(&text) == mapper => {
                if found.replace(name).is_some() {
                    return None;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    found
}

/// Every device of the btrfs filesystem that `name` belongs to, or `None`
/// when sysfs lists no btrfs filesystem with that device.
fn btrfs_members(sys: &Path, name: &str) -> Option<Vec<String>> {
    for fs_dir in fs::read_dir(sys.join("fs/btrfs")).ok()? {
        let devices = fs_dir.ok()?.path().join("devices");
        if present(&devices.join(name)) != Some(true) {
            continue;
        }
        let mut members = Vec::new();
        for entry in fs::read_dir(&devices).ok()? {
            members.push(plain_name(&entry.ok()?.file_name())?);
        }
        return Some(members);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn directory_probe_keeps_configured_path_and_resolves_symlinks() {
        let fx = Fixture::new("directory-symlink");
        let actual = fx.root.join("actual");
        fs::create_dir(&actual).unwrap();
        let link = fx.root.join("keyring");
        symlink(&actual, &link).unwrap();
        let observed = directory_encryption_with(
            &link,
            |path| fs::symlink_metadata(path),
            |_, _| panic!("an existing directory does not need a parent probe"),
            |path| {
                assert_eq!(path, actual.canonicalize().unwrap());
                Encrypted
            },
        );
        assert_eq!(observed.path, link.to_string_lossy());
        assert_eq!(observed.encryption, Encrypted);
        assert_eq!(observed.reason, None);
    }

    #[test]
    fn directory_probe_uses_the_nearest_parent_only_for_missing_directories() {
        let fx = Fixture::new("directory-missing");
        let dir = fx.root.join("missing/template-keys");
        let parent = fx.root.canonicalize().unwrap();
        let observed = directory_encryption_with(
            &dir,
            |path| fs::symlink_metadata(path),
            |ancestor, target| {
                assert_eq!(ancestor, parent);
                assert_eq!(target, parent.join("missing/template-keys"));
                Some(false)
            },
            |path| {
                assert_eq!(path, parent);
                NotEncrypted
            },
        );
        assert_eq!(observed.path, dir.to_string_lossy());
        assert_eq!(observed.encryption, NotEncrypted);
        assert_eq!(observed.reason, None);
    }

    #[test]
    fn directory_probe_does_not_ascend_after_permission_denied() {
        let dir = Path::new("/private/keyring");
        let observed = directory_encryption_with(
            dir,
            |path| {
                assert_eq!(path, dir, "a denied directory must not use its parent");
                Err(std::io::Error::from(ErrorKind::PermissionDenied))
            },
            |_, _| panic!("unreachable directories cannot be resolved through mountinfo"),
            |_| panic!("an unreachable directory cannot be probed"),
        );
        assert_eq!(observed.path, dir.to_string_lossy());
        assert_eq!(observed.encryption, Unknown);
        let reason = observed.reason.unwrap();
        assert!(reason.contains("/private/keyring"), "{reason}");
        assert!(reason.contains("permission denied"), "{reason}");
    }

    #[test]
    fn directory_probe_does_not_follow_the_parent_of_a_dangling_symlink() {
        let fx = Fixture::new("directory-dangling");
        let link = fx.root.join("keyring");
        symlink(fx.root.join("missing"), &link).unwrap();
        for dir in [&link, &link.join("child")] {
            let observed = directory_encryption_with(
                dir,
                |path| fs::symlink_metadata(path),
                |_, _| panic!("a dangling symlink has no resolved ancestor"),
                |_| panic!("a dangling symlink cannot be probed"),
            );
            assert_eq!(observed.encryption, Unknown);
            assert!(observed.reason.unwrap().contains("could not resolve"));
        }
    }

    #[test]
    fn directory_probe_explains_ambiguous_and_unavailable_storage() {
        let fx = Fixture::new("directory-unknown");
        let missing = fx.root.join("missing");
        for mount in [Some(true), None] {
            let observed = directory_encryption_with(
                &missing,
                |path| fs::symlink_metadata(path),
                |_, _| mount,
                |_| panic!("ambiguous parent storage cannot be used"),
            );
            assert_eq!(observed.encryption, Unknown);
            assert!(observed.reason.unwrap().contains("mount"));
        }
        let observed = directory_encryption_with(
            &fx.root,
            |path| fs::symlink_metadata(path),
            |_, _| panic!("an existing directory does not need a parent probe"),
            |_| Unknown,
        );
        assert_eq!(observed.encryption, Unknown);
        assert!(observed.reason.unwrap().contains("block-storage"));
        let relative = directory_encryption(Path::new("relative/keyring"));
        assert_eq!(relative.encryption, Unknown);
        assert!(relative.reason.unwrap().contains("absolute"));
    }

    #[test]
    fn a_mount_below_an_ancestor_on_the_way_to_a_path_is_found() {
        let mounts = parse_mountinfo(
            "22 1 253:0 / / rw - ext4 /dev/mapper/root rw\n\
             30 22 0:40 / /var/lib/irlume/keyring rw - tmpfs tmpfs rw\n\
             31 22 0:41 / /var/lib/other rw - tmpfs tmpfs rw\n",
        );
        let state = Path::new("/var/lib/irlume");
        assert!(mount_between_in(
            &mounts,
            state,
            Path::new("/var/lib/irlume/keyring")
        ));
        assert!(mount_between_in(
            &mounts,
            state,
            Path::new("/var/lib/irlume/keyring/x")
        ));
        assert!(!mount_between_in(
            &mounts,
            state,
            Path::new("/var/lib/irlume/template-keys")
        ));
        // The mount that holds the ancestor itself does not count.
        assert!(!mount_between_in(
            &mounts,
            Path::new("/"),
            Path::new("/etc")
        ));
        assert!(!mount_between_in(
            &mounts,
            Path::new("/var/lib/irlume/keyring"),
            Path::new("/var/lib/irlume/keyring/x")
        ));
    }

    use StorageEncryption::{Encrypted, NotEncrypted, Unknown};

    /// A fixture tree shaped like sysfs, `/dev` and a mountinfo file.
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("irlume-crypt-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            for dir in [
                "sys/class/block",
                "sys/dev/block",
                "sys/devices/pci/block",
                "sys/devices/virtual/block",
                "sys/fs/btrfs",
                "dev/mapper",
            ] {
                fs::create_dir_all(root.join(dir)).unwrap();
            }
            Fixture { root }
        }

        fn roots(&self) -> Roots {
            Roots {
                mountinfo: self.root.join("mountinfo"),
                sys: self.root.join("sys"),
                dev: self.root.join("dev"),
            }
        }

        /// Register the device directory `dir` as `name` and `majmin`.
        fn register(&self, dir: &Path, name: &str, majmin: &str) {
            symlink(dir, self.root.join("sys/class/block").join(name)).unwrap();
            symlink(dir, self.root.join("sys/dev/block").join(majmin)).unwrap();
            fs::write(self.root.join("dev").join(name), b"").unwrap();
        }

        fn disk(&self, name: &str, majmin: &str) {
            let dir = self.root.join("sys/devices/pci/block").join(name);
            fs::create_dir_all(dir.join("slaves")).unwrap();
            self.register(&dir, name, majmin);
        }

        fn partition(&self, disk: &str, name: &str, majmin: &str) {
            let dir = self
                .root
                .join("sys/devices/pci/block")
                .join(disk)
                .join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("partition"), b"3\n").unwrap();
            self.register(&dir, name, majmin);
        }

        /// A device-mapper node with `uuid` over `slaves`, and its
        /// `/dev/mapper/<mapper>` symlink.
        fn dm(&self, name: &str, majmin: &str, mapper: &str, uuid: &str, slaves: &[&str]) {
            let dir = self.root.join("sys/devices/virtual/block").join(name);
            fs::create_dir_all(dir.join("dm")).unwrap();
            fs::create_dir_all(dir.join("slaves")).unwrap();
            fs::write(dir.join("dm/uuid"), format!("{uuid}\n")).unwrap();
            fs::write(dir.join("dm/name"), format!("{mapper}\n")).unwrap();
            for slave in slaves {
                fs::write(dir.join("slaves").join(slave), b"").unwrap();
            }
            self.register(&dir, name, majmin);
            symlink(
                format!("../{name}"),
                self.root.join("dev/mapper").join(mapper),
            )
            .unwrap();
        }

        fn btrfs(&self, fsid: &str, members: &[&str]) {
            let devices = self.root.join("sys/fs/btrfs").join(fsid).join("devices");
            fs::create_dir_all(&devices).unwrap();
            for member in members {
                fs::write(devices.join(member), b"").unwrap();
            }
        }

        fn mountinfo(&self, text: &str) {
            fs::write(self.root.join("mountinfo"), text).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    const STATE: &str = "/var/lib/irlume";

    fn probe(fx: &Fixture, major: u32, minor: u32) -> StorageEncryption {
        classify(Path::new(STATE), major, minor, &fx.roots())
    }

    const LUKS_UUID: &str =
        "CRYPT-LUKS2-0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e-luks-0b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e";

    #[test]
    fn a_plain_partition_is_not_encrypted() {
        let fx = Fixture::new("plain");
        fx.disk("nvme0n1", "259:0");
        fx.partition("nvme0n1", "nvme0n1p3", "259:3");
        assert_eq!(probe(&fx, 259, 3), NotEncrypted);
        // A whole disk with no partition table reads the same.
        assert_eq!(probe(&fx, 259, 0), NotEncrypted);
    }

    #[test]
    fn a_dm_crypt_device_is_encrypted() {
        let fx = Fixture::new("dmcrypt");
        fx.disk("nvme0n1", "259:0");
        fx.partition("nvme0n1", "nvme0n1p3", "259:3");
        fx.dm("dm-0", "253:0", "luks-0b1c", LUKS_UUID, &["nvme0n1p3"]);
        assert_eq!(probe(&fx, 253, 0), Encrypted);
    }

    #[test]
    fn lvm_on_luks_is_encrypted_and_lvm_on_a_plain_partition_is_not() {
        let fx = Fixture::new("lvm");
        fx.disk("sda", "8:0");
        fx.partition("sda", "sda2", "8:2");
        fx.partition("sda", "sda3", "8:3");
        fx.dm("dm-0", "253:0", "luks-0b1c", LUKS_UUID, &["sda2"]);
        fx.dm("dm-1", "253:1", "vg-root", "LVM-abcdefAbcdef", &["dm-0"]);
        fx.dm("dm-2", "253:2", "vg2-var", "LVM-ghijklGhijkl", &["sda3"]);
        assert_eq!(probe(&fx, 253, 1), Encrypted);
        assert_eq!(probe(&fx, 253, 2), NotEncrypted);
        // A logical volume spanning an encrypted and a plain volume is not
        // encrypted as a whole.
        fx.dm(
            "dm-3",
            "253:3",
            "vg3-lv",
            "LVM-mnopqrMnopqr",
            &["dm-0", "sda3"],
        );
        assert_eq!(probe(&fx, 253, 3), NotEncrypted);
    }

    #[test]
    fn btrfs_is_resolved_through_mountinfo() {
        let fx = Fixture::new("btrfs");
        fx.disk("nvme0n1", "259:0");
        fx.partition("nvme0n1", "nvme0n1p3", "259:3");
        fx.dm("dm-0", "253:0", "luks-0b1c", LUKS_UUID, &["nvme0n1p3"]);
        fx.btrfs("6fdb3276-6661-41e1-9520-9bdbde1102ae", &["dm-0"]);
        // st_dev 0:37 appears nowhere in mountinfo (btrfs reports the
        // subvolume's anonymous number); the mount holding the path decides.
        fx.mountinfo(
            "43 1 0:35 /root / rw,relatime shared:1 - btrfs /dev/mapper/luks-0b1c rw,subvol=/root\n\
             52 43 0:25 / /proc rw,nosuid shared:13 - proc proc rw\n\
             62 43 0:35 /home /home rw,relatime shared:162 - btrfs /dev/mapper/luks-0b1c rw\n\
             67 43 0:54 / /tmp rw,nosuid,nodev shared:167 - tmpfs tmpfs rw\n",
        );
        assert_eq!(probe(&fx, 0, 37), Encrypted);
    }

    #[test]
    fn btrfs_on_a_plain_partition_is_not_encrypted() {
        let fx = Fixture::new("btrfs-plain");
        fx.disk("nvme0n1", "259:0");
        fx.partition("nvme0n1", "nvme0n1p3", "259:3");
        fx.btrfs("6fdb3276-6661-41e1-9520-9bdbde1102ae", &["nvme0n1p3"]);
        fx.mountinfo(
            "43 1 0:35 /root / rw,relatime shared:1 - btrfs /dev/nvme0n1p3 rw,subvol=/root\n",
        );
        assert_eq!(probe(&fx, 0, 37), NotEncrypted);
    }

    #[test]
    fn btrfs_counts_every_device_of_the_filesystem() {
        let fx = Fixture::new("btrfs-multi");
        fx.disk("sda", "8:0");
        fx.disk("sdb", "8:16");
        fx.dm("dm-0", "253:0", "luks-a", LUKS_UUID, &["sda"]);
        fx.dm("dm-1", "253:1", "luks-b", LUKS_UUID, &["sdb"]);
        fx.btrfs("0f0f", &["dm-0", "dm-1"]);
        fx.mountinfo("43 1 0:35 / / rw shared:1 - btrfs /dev/mapper/luks-a rw\n");
        assert_eq!(probe(&fx, 0, 37), Encrypted);
        // One plain member leaves part of the filesystem unencrypted.
        fx.disk("sdc", "8:32");
        fx.btrfs("0f0f", &["sdc"]);
        assert_eq!(probe(&fx, 0, 37), NotEncrypted);
    }

    #[test]
    fn btrfs_without_a_sysfs_listing_is_unknown() {
        let fx = Fixture::new("btrfs-unlisted");
        fx.disk("sda", "8:0");
        fx.dm("dm-0", "253:0", "luks-a", LUKS_UUID, &["sda"]);
        fx.mountinfo("43 1 0:35 / / rw shared:1 - btrfs /dev/mapper/luks-a rw\n");
        assert_eq!(probe(&fx, 0, 37), Unknown);
    }

    #[test]
    fn a_mapper_source_is_found_by_its_dm_name_without_a_dev_node() {
        let fx = Fixture::new("mapper-name");
        fx.disk("nvme0n1", "259:0");
        fx.partition("nvme0n1", "nvme0n1p3", "259:3");
        fx.dm("dm-0", "253:0", "luks-0b1c", LUKS_UUID, &["nvme0n1p3"]);
        fx.dm("dm-1", "253:1", "vg-root", "LVM-abcdefAbcdef", &["dm-0"]);
        fx.btrfs("6fdb3276-6661-41e1-9520-9bdbde1102ae", &["dm-0"]);
        // irlumed's AppArmor profiles grant no /dev block node, so the
        // lookup must succeed from sysfs alone.
        fs::remove_dir_all(fx.root.join("dev")).unwrap();
        let roots = fx.roots();
        assert_eq!(
            source_device(&roots, "/dev/mapper/luks-0b1c").as_deref(),
            Some("dm-0")
        );
        assert_eq!(
            source_device(&roots, "/dev/mapper/vg-root").as_deref(),
            Some("dm-1")
        );
        fx.mountinfo("43 1 0:35 /root / rw shared:1 - btrfs /dev/mapper/luks-0b1c rw\n");
        assert_eq!(probe(&fx, 0, 37), Encrypted);
        // A name that matches no device-mapper device, or is not one plain
        // name, resolves to nothing, and the storage stays unknown.
        for source in [
            "/dev/mapper/luks-0b1",
            "/dev/mapper/luks-0b1c-x",
            "/dev/mapper/dm-0",
            "/dev/mapper/control",
            "/dev/mapper/",
            "/dev/mapper/../nvme0n1p3",
            "/dev/mapper/a/luks-0b1c",
        ] {
            assert_eq!(source_device(&roots, source), None, "{source}");
        }
        fx.mountinfo("43 1 0:35 /root / rw shared:1 - btrfs /dev/mapper/luks-gone rw\n");
        assert_eq!(probe(&fx, 0, 37), Unknown);
        // Two devices with one name, which the kernel does not allow, and a
        // dm/name that cannot be read (a directory in its place) decide
        // nothing either.
        let other = fx.root.join("sys/devices/virtual/block/dm-1/dm/name");
        fs::write(&other, b"luks-0b1c\n").unwrap();
        assert_eq!(source_device(&roots, "/dev/mapper/luks-0b1c"), None);
        fs::remove_file(&other).unwrap();
        fs::create_dir(&other).unwrap();
        assert_eq!(source_device(&roots, "/dev/mapper/luks-0b1c"), None);
    }

    #[test]
    fn a_btrfs_filesystem_on_several_mapper_devices_resolves_without_a_dev_node() {
        let fx = Fixture::new("btrfs-mapper-multi");
        fx.disk("sda", "8:0");
        fx.disk("sdb", "8:16");
        fx.disk("sdc", "8:32");
        fx.dm("dm-0", "253:0", "luks-a", LUKS_UUID, &["sda"]);
        fx.dm("dm-1", "253:1", "luks-b", LUKS_UUID, &["sdb"]);
        fx.btrfs("0f0f", &["dm-0", "dm-1"]);
        fs::remove_dir_all(fx.root.join("dev")).unwrap();
        // btrfs names one member as the source; every member counts.
        fx.mountinfo("43 1 0:35 / / rw shared:1 - btrfs /dev/mapper/luks-b rw\n");
        assert_eq!(probe(&fx, 0, 37), Encrypted);
        // One plain member leaves part of the filesystem unencrypted.
        fx.btrfs("0f0f", &["sdc"]);
        assert_eq!(probe(&fx, 0, 37), NotEncrypted);
    }

    #[test]
    fn a_dev_path_names_the_block_device_its_links_lead_to() {
        let fx = Fixture::new("dev-path");
        fx.disk("nvme0n1", "259:0");
        fx.partition("nvme0n1", "nvme0n1p3", "259:3");
        fx.dm("dm-0", "253:0", "luks-0b1c", LUKS_UUID, &["nvme0n1p3"]);
        let dev = fx.root.join("dev");
        fs::create_dir_all(dev.join("disk/by-uuid")).unwrap();
        symlink("../../nvme0n1p3", dev.join("disk/by-uuid/6fdb3276")).unwrap();
        fs::create_dir_all(dev.join("vg")).unwrap();
        symlink("../dm-0", dev.join("vg/root")).unwrap();
        let roots = fx.roots();
        for (source, name) in [
            ("/dev/nvme0n1p3", "nvme0n1p3"),
            ("/dev/disk/by-uuid/6fdb3276", "nvme0n1p3"),
            ("/dev/dm-0", "dm-0"),
            ("/dev/vg/root", "dm-0"),
        ] {
            assert_eq!(
                source_device(&roots, source).as_deref(),
                Some(name),
                "{source}"
            );
        }
        // A plain partition, named through a link.
        fx.btrfs("6fdb3276-6661-41e1-9520-9bdbde1102ae", &["nvme0n1p3"]);
        fx.mountinfo("43 1 0:35 / / rw shared:1 - btrfs /dev/disk/by-uuid/6fdb3276 rw\n");
        assert_eq!(probe(&fx, 0, 37), NotEncrypted);
        // An entry sysfs does not list, one in a subdirectory, one outside
        // /dev, a missing one and a source outside /dev resolve to nothing.
        fs::write(dev.join("sdz"), b"").unwrap();
        fs::create_dir_all(dev.join("cciss")).unwrap();
        fs::write(dev.join("cciss/nvme0n1p3"), b"").unwrap();
        fs::create_dir_all(fx.root.join("outside")).unwrap();
        fs::write(fx.root.join("outside/nvme0n1p3"), b"").unwrap();
        symlink("../outside/nvme0n1p3", dev.join("escape")).unwrap();
        for source in [
            "/dev/sdz",
            "/dev/cciss/nvme0n1p3",
            "/dev/escape",
            "/dev/../outside/nvme0n1p3",
            "/dev/missing",
            "/dev/",
            "dev/nvme0n1p3",
            "rpool/irlume",
            "tmpfs",
        ] {
            assert_eq!(source_device(&roots, source), None, "{source}");
        }
        fx.mountinfo("43 1 0:35 / / rw shared:1 - btrfs /dev/cciss/nvme0n1p3 rw\n");
        assert_eq!(probe(&fx, 0, 37), Unknown);
    }

    #[test]
    fn unreadable_sysfs_is_unknown() {
        let fx = Fixture::new("unreadable");
        fx.disk("sda", "8:0");
        fx.dm("dm-0", "253:0", "luks-a", LUKS_UUID, &["sda"]);
        fx.mountinfo("43 1 0:35 / / rw shared:1 - ext4 /dev/mapper/luks-a rw\n");
        // No sysfs at all, then no mountinfo either.
        let mut roots = fx.roots();
        roots.sys = fx.root.join("absent");
        assert_eq!(classify(Path::new(STATE), 253, 0, &roots), Unknown);
        roots.mountinfo = fx.root.join("absent");
        assert_eq!(classify(Path::new(STATE), 0, 37, &roots), Unknown);
        // A dm/uuid that cannot be read (a directory in its place: file
        // modes do not stop root) is unknown, not a device without one.
        fx.dm("dm-1", "253:1", "vg-root", "LVM-x", &["dm-0"]);
        let uuid = fx.root.join("sys/devices/virtual/block/dm-1/dm/uuid");
        fs::remove_file(&uuid).unwrap();
        fs::create_dir(&uuid).unwrap();
        assert_eq!(probe(&fx, 253, 1), Unknown);
        // So is a slaves entry that is not a directory listing.
        let slaves = fx.root.join("sys/devices/pci/block/sda/slaves");
        fs::remove_dir_all(&slaves).unwrap();
        fs::write(&slaves, b"").unwrap();
        assert_eq!(
            probe(&fx, 253, 0),
            Encrypted,
            "dm-crypt is decided above sda"
        );
        assert_eq!(probe(&fx, 8, 0), Unknown);
    }

    #[test]
    fn integrity_layers_are_not_encryption() {
        let fx = Fixture::new("verity");
        fx.disk("sda", "8:0");
        fx.dm(
            "dm-0",
            "253:0",
            "root-verity",
            "CRYPT-VERITY-abcdef-root",
            &["sda"],
        );
        fx.dm("dm-1", "253:1", "data", "CRYPT-INTEGRITY-data", &["sda"]);
        fx.dm("dm-2", "253:2", "luks-a", LUKS_UUID, &["dm-1"]);
        assert_eq!(probe(&fx, 253, 0), NotEncrypted);
        assert_eq!(probe(&fx, 253, 1), NotEncrypted);
        assert_eq!(probe(&fx, 253, 2), Encrypted);
    }

    #[test]
    fn a_loop_device_or_an_empty_stack_is_unknown() {
        let fx = Fixture::new("loop");
        let dir = fx.root.join("sys/devices/virtual/block/loop0");
        fs::create_dir_all(dir.join("loop")).unwrap();
        fs::write(dir.join("loop/backing_file"), b"/srv/image\n").unwrap();
        fx.register(&dir, "loop0", "7:0");
        assert_eq!(probe(&fx, 7, 0), Unknown);
        fx.dm("dm-0", "253:0", "empty", "LVM-x", &[]);
        assert_eq!(probe(&fx, 253, 0), Unknown);
    }

    #[test]
    fn a_mount_source_that_is_not_a_block_device_is_unknown() {
        let fx = Fixture::new("tmpfs");
        fx.mountinfo(
            "43 1 0:35 / / rw shared:1 - tmpfs tmpfs rw\n\
             44 43 0:36 / /var/lib/irlume rw shared:2 - zfs rpool/irlume rw\n",
        );
        assert_eq!(probe(&fx, 0, 36), Unknown);
        fx.mountinfo("43 1 0:35 / / rw shared:1 - tmpfs tmpfs rw\n");
        assert_eq!(probe(&fx, 0, 35), Unknown);
        // A /dev source with no node behind it (as /dev/root can be).
        fx.mountinfo("43 1 0:35 / / rw shared:1 - ext4 /dev/root rw\n");
        assert_eq!(probe(&fx, 0, 35), Unknown);
    }

    #[test]
    fn the_longest_and_latest_mount_holds_the_path() {
        let mounts = parse_mountinfo(
            "1 0 0:1 / / rw - ext4 /dev/sda1 rw\n\
             2 1 0:2 / /var rw shared:5 master:1 - ext4 /dev/sda2 rw\n\
             3 1 0:3 / /var/lib/irlume\\040old rw - ext4 /dev/sda3 rw\n\
             4 2 0:4 / /var rw - xfs /dev/sda4 rw\n\
             not a mountinfo line\n",
        );
        assert_eq!(mounts.len(), 4);
        assert_eq!(mounts[2].mount_point, Path::new("/var/lib/irlume old"));
        assert_eq!(mounts[1].fstype, "ext4");
        assert_eq!(mounts[1].source, "/dev/sda2");
        let at = |p: &str| mount_holding(&mounts, Path::new(p)).map(|m| m.source.clone());
        assert_eq!(at("/var/lib/irlume").as_deref(), Some("/dev/sda4"));
        assert_eq!(at("/var/lib/irlume old/x").as_deref(), Some("/dev/sda3"));
        // Component-wise: /variable is not under /var.
        assert_eq!(at("/variable").as_deref(), Some("/dev/sda1"));
        assert_eq!(mount_holding(&mounts[1..2], Path::new("/etc")), None);
    }

    #[test]
    fn mountinfo_escapes_decode() {
        assert_eq!(unescape(r"/a\040b\011c\012d\134e"), "/a b\tc\nd\\e");
        assert_eq!(unescape(r"/trailing\04"), r"/trailing\04");
        assert_eq!(unescape(r"/not\999octal"), r"/not\999octal");
    }

    #[test]
    fn crypt_uuids_name_the_encryption_types_only() {
        assert!(is_crypt_uuid(LUKS_UUID));
        assert!(is_crypt_uuid("CRYPT-LUKS1-abc-name"));
        assert!(is_crypt_uuid("CRYPT-PLAIN-name"));
        assert!(!is_crypt_uuid("CRYPT-VERITY-abc-name"));
        assert!(!is_crypt_uuid("CRYPT-INTEGRITY-name"));
        assert!(!is_crypt_uuid("LVM-abc"));
        assert!(!is_crypt_uuid("mpath-abc"));
        assert!(!is_crypt_uuid(""));
    }

    #[test]
    fn a_missing_path_is_unknown() {
        let fx = Fixture::new("missing");
        assert_eq!(
            path_encryption_in(&fx.root.join("no-such-dir"), &fx.roots()),
            Unknown
        );
    }

    #[test]
    fn names_that_are_not_one_component_are_refused() {
        assert_eq!(plain_name(OsStr::new("dm-0")).as_deref(), Some("dm-0"));
        assert_eq!(plain_name(OsStr::new("..")), None);
        assert_eq!(plain_name(OsStr::new("a/b")), None);
        assert_eq!(plain_name(OsStr::new("")), None);
        let fx = Fixture::new("names");
        assert_eq!(block_encryption(&fx.root.join("sys"), "../x", 0), Unknown);
    }
}
