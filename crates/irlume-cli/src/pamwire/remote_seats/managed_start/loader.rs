// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! LightDM's configuration loader input closure as one digest, and the
//! remote-server policy those exact bytes give.
//!
//! The order and filters follow LightDM 1.32's `configuration.c` (shared
//! research record artifacts/irlume/2026-10-03-lightdm-managed-start): the
//! `lightdm/lightdm.conf.d` directory of each system data directory, in
//! reverse preference order, then of each system configuration directory,
//! also reversed, then `CONFIG_DIR/lightdm.conf.d`, then
//! `CONFIG_DIR/lightdm.conf`. Within a directory names sort by byte value and
//! every name ending in the case-sensitive suffix `.conf` is a candidate,
//! including the name `.conf`. Later assignments override earlier ones, and a
//! remote server is on only for the exact value `true`.
//!
//! The digest covers membership and absence as well as bytes, so two reads
//! with equal digests saw the same configuration. Anything this module cannot
//! read the way LightDM would (a candidate that is not a bounded regular
//! file, a line outside the strict key-file grammar, an unsupported
//! environment) is an error: the caller then records nothing rather than a
//! guess.

use std::ffi::OsStr;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use super::super::super::autologin::assignments;

/// Every candidate is a few kilobytes; anything near this is not one.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Bound on directory entries read across the whole closure.
const MAX_ENTRIES: usize = 4096;

/// Where LightDM looks, for one environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Profile {
    data_dirs: Vec<PathBuf>,
    config_dirs: Vec<PathBuf>,
    config_dir: PathBuf,
}

/// The configuration one read observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observed {
    /// Sixty-four lowercase hex digits over the whole input closure.
    pub(crate) digest: String,
    pub(crate) xdmcp_enabled: bool,
    pub(crate) vnc_enabled: bool,
}

impl Profile {
    /// GLib's default system directories and the distribution builds'
    /// `CONFIG_DIR`.
    pub(crate) fn standard() -> Self {
        Profile {
            data_dirs: vec!["/usr/local/share".into(), "/usr/share".into()],
            config_dirs: vec!["/etc/xdg".into()],
            config_dir: "/etc/lightdm".into(),
        }
    }

    /// The profile LightDM uses with these `XDG_DATA_DIRS` and
    /// `XDG_CONFIG_DIRS` values, or `None` when they name anything other
    /// than GLib's defaults. GLib uses its defaults for an unset or empty
    /// variable.
    pub(crate) fn from_environment(data: Option<&OsStr>, config: Option<&OsStr>) -> Option<Self> {
        let standard = Self::standard();
        (defaults(data, &standard.data_dirs) && defaults(config, &standard.config_dirs))
            .then_some(standard)
    }

    /// The directories LightDM reads, in load order, under `root`.
    fn directories(&self, root: &Path) -> Vec<PathBuf> {
        let suffix = Path::new("lightdm/lightdm.conf.d");
        self.data_dirs
            .iter()
            .rev()
            .chain(self.config_dirs.iter().rev())
            .map(|dir| under(root, &dir.join(suffix)))
            .chain(std::iter::once(under(
                root,
                &self.config_dir.join("lightdm.conf.d"),
            )))
            .collect()
    }

    fn main_file(&self, root: &Path) -> PathBuf {
        under(root, &self.config_dir.join("lightdm.conf"))
    }
}

fn under(root: &Path, absolute: &Path) -> PathBuf {
    root.join(absolute.strip_prefix("/").unwrap_or(absolute))
}

/// Whether a search-path variable leaves GLib on `default`: unset, empty, or
/// the same absolute directories in the same order, trailing slashes aside.
fn defaults(value: Option<&OsStr>, default: &[PathBuf]) -> bool {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return true;
    };
    let Some(text) = value.to_str() else {
        return false;
    };
    let entries: Vec<&str> = text.split(':').collect();
    entries.len() == default.len()
        && entries.iter().zip(default).all(|(entry, dir)| {
            let trimmed = entry.trim_end_matches('/');
            entry.starts_with('/') && Path::new(trimmed) == dir.as_path()
        })
}

/// Read LightDM's whole input closure under `root` for `profile`. With
/// `public`, every input must also be readable by any user, so an
/// unprivileged reader computes the same digest as root.
pub(crate) fn observe(root: &Path, profile: &Profile, public: bool) -> Result<Observed, String> {
    let mut digest = Sha256::new();
    digest.update(b"irlume-lightdm-loader-v1\n");
    let mut loaded = Vec::new();
    let mut entries = 0;
    let named = profile.directories(Path::new("/"));
    for (dir, name) in profile.directories(root).iter().zip(&named) {
        match std::fs::metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                digest.update(format!("dir\t{}\tmissing\n", name.display()));
                continue;
            }
            Err(e) => return Err(format!("{}: {e}", name.display())),
            Ok(meta) if !meta.is_dir() => {
                return Err(format!("{}: not a directory", name.display()));
            }
            Ok(_) => {}
        }
        if public {
            readable_by_anyone(dir, true).map_err(|e| format!("{}: {e}", name.display()))?;
        }
        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", name.display()))? {
            entries += 1;
            if entries > MAX_ENTRIES {
                return Err("too many LightDM configuration entries".into());
            }
            let file = entry
                .map_err(|e| format!("{}: {e}", name.display()))?
                .file_name();
            if file.as_bytes().ends_with(b".conf") {
                candidates.push(file);
            }
        }
        // strcmp order: byte by byte, as LightDM sorts.
        candidates.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        digest.update(format!(
            "dir\t{}\tpresent\t{}\n",
            name.display(),
            candidates.len()
        ));
        for file in candidates {
            let text = file
                .to_str()
                .filter(|text| !text.chars().any(char::is_control))
                .ok_or_else(|| format!("{}: unsupported file name", name.display()))?;
            let path = dir.join(text);
            let bytes = read_candidate(&path, public)
                .map_err(|e| format!("{}/{text}: {e}", name.display()))?
                .ok_or_else(|| format!("{}/{text}: disappeared while reading", name.display()))?;
            digest.update(format!("file\t{text}\t{}\n", fingerprint(&bytes)));
            loaded.push((name.join(text), bytes));
        }
    }
    let main_name = profile.main_file(Path::new("/"));
    match read_candidate(&profile.main_file(root), public)
        .map_err(|e| format!("{}: {e}", main_name.display()))?
    {
        None => digest.update(format!("main\t{}\tmissing\n", main_name.display())),
        Some(bytes) => {
            digest.update(format!(
                "main\t{}\t{}\n",
                main_name.display(),
                fingerprint(&bytes)
            ));
            loaded.push((main_name, bytes));
        }
    }
    let (mut xdmcp_enabled, mut vnc_enabled) = (false, false);
    for (path, bytes) in &loaded {
        let text =
            std::str::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8", path.display()))?;
        for (group, key, value) in
            assignments(text).map_err(|e| format!("{}: {e}", path.display()))?
        {
            // LightDM reads the cached value with trailing whitespace removed
            // and accepts only the exact text "true".
            let slot = match (group.as_str(), key.as_str()) {
                ("XDMCPServer", "enabled") => &mut xdmcp_enabled,
                ("VNCServer", "enabled") => &mut vnc_enabled,
                _ => continue,
            };
            *slot = value == "true";
        }
    }
    Ok(Observed {
        digest: hex(&digest.finalize()),
        xdmcp_enabled,
        vnc_enabled,
    })
}

/// The bytes of one candidate, following symlinks as LightDM does, or `None`
/// when nothing is there. Anything but a bounded regular file is refused, and
/// the descriptor read is checked to be the file that was examined.
fn read_candidate(path: &Path, public: bool) -> Result<Option<Vec<u8>>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return Err("not a bounded regular file".into());
    }
    if public {
        readable_by_anyone(path, false)?;
    }
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let opened: Metadata = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
        return Err("changed while being read".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("not a bounded regular file".into());
    }
    Ok(Some(bytes))
}

/// Whether a user with no special rights could read `path` the same way:
/// every directory on the way, through any symlink, grants others search,
/// and the object itself grants others read (and search for a directory).
fn readable_by_anyone(path: &Path, directory: bool) -> Result<(), String> {
    let mut chains = vec![path.canonicalize().map_err(|e| e.to_string())?];
    if let Some(parent) = path.parent() {
        chains.push(parent.canonicalize().map_err(|e| e.to_string())?);
    }
    for (index, chain) in chains.iter().enumerate() {
        for ancestor in chain.ancestors().skip(usize::from(index == 0)) {
            let mode = std::fs::metadata(ancestor)
                .map_err(|e| e.to_string())?
                .mode();
            if mode & 0o001 == 0 {
                return Err(format!(
                    "{} is not searchable by others",
                    ancestor.display()
                ));
            }
        }
    }
    let mode = std::fs::metadata(&chains[0])
        .map_err(|e| e.to_string())?
        .mode();
    let wanted = if directory { 0o005 } else { 0o004 };
    if mode & wanted != wanted {
        return Err("not readable by others".into());
    }
    Ok(())
}

fn fingerprint(bytes: &[u8]) -> String {
    format!("{}\t{}", hex(&Sha256::digest(bytes)), bytes.len())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "irlume-lightdm-loader-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Tree(path)
        }

        fn put(&self, relative: &str, text: &str) -> PathBuf {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            path
        }

        fn observe(&self) -> Result<Observed, String> {
            observe(&self.0, &Profile::standard(), false)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const XDMCP_ON: &str = "[XDMCPServer]\nenabled=true\n";
    const XDMCP_OFF: &str = "[XDMCPServer]\nenabled=false\n";

    #[test]
    fn the_standard_profile_reads_layers_in_lightdm_order() {
        let root = Path::new("/r");
        assert_eq!(
            Profile::standard().directories(root),
            vec![
                PathBuf::from("/r/usr/share/lightdm/lightdm.conf.d"),
                PathBuf::from("/r/usr/local/share/lightdm/lightdm.conf.d"),
                PathBuf::from("/r/etc/xdg/lightdm/lightdm.conf.d"),
                PathBuf::from("/r/etc/lightdm/lightdm.conf.d"),
            ]
        );
        assert_eq!(
            Profile::standard().main_file(root),
            PathBuf::from("/r/etc/lightdm/lightdm.conf")
        );
    }

    #[test]
    fn only_glib_default_environments_are_supported() {
        let standard = Some(Profile::standard());
        for (data, config) in [
            (None, None),
            (Some(""), Some("")),
            (Some("/usr/local/share/:/usr/share/"), Some("/etc/xdg")),
            (Some("/usr/local/share:/usr/share"), Some("/etc/xdg/")),
        ] {
            assert_eq!(
                Profile::from_environment(data.map(OsStr::new), config.map(OsStr::new)),
                standard,
                "{data:?} {config:?}"
            );
        }
        for (data, config) in [
            (Some("/opt/share:/usr/share"), None),
            (Some("/usr/share:/usr/local/share"), None),
            (None, Some("/etc/xdg:/opt/xdg")),
            (Some("relative:/usr/share"), None),
        ] {
            assert_eq!(
                Profile::from_environment(data.map(OsStr::new), config.map(OsStr::new)),
                None,
                "{data:?} {config:?}"
            );
        }
    }

    #[test]
    fn an_empty_closure_is_off_and_has_a_stable_digest() {
        let a = Tree::new("empty-a");
        let b = Tree::new("empty-b");
        let seen = a.observe().expect("observed");
        assert!(!seen.xdmcp_enabled && !seen.vnc_enabled);
        assert_eq!(seen.digest.len(), 64);
        assert!(seen
            .digest
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(
            seen,
            b.observe().unwrap(),
            "the digest names paths, not the root"
        );
    }

    #[test]
    fn later_layers_and_the_main_file_override_earlier_assignments() {
        let tree = Tree::new("override");
        tree.put("usr/share/lightdm/lightdm.conf.d/50-vendor.conf", XDMCP_ON);
        assert!(tree.observe().unwrap().xdmcp_enabled);
        tree.put("etc/lightdm/lightdm.conf.d/10-admin.conf", XDMCP_OFF);
        assert!(!tree.observe().unwrap().xdmcp_enabled);
        tree.put("etc/lightdm/lightdm.conf", XDMCP_ON);
        assert!(tree.observe().unwrap().xdmcp_enabled);
        tree.put("etc/lightdm/lightdm.conf", "[VNCServer]\nenabled=true\n");
        let seen = tree.observe().unwrap();
        assert!(!seen.xdmcp_enabled && seen.vnc_enabled);
    }

    #[test]
    fn names_sort_by_byte_and_the_last_assignment_wins() {
        let tree = Tree::new("sort");
        // Byte order puts "Z" before "a": a.conf is read last.
        tree.put("etc/lightdm/lightdm.conf.d/a.conf", XDMCP_OFF);
        tree.put("etc/lightdm/lightdm.conf.d/Z.conf", XDMCP_ON);
        assert!(!tree.observe().unwrap().xdmcp_enabled);
    }

    #[test]
    fn the_conf_suffix_is_case_sensitive_and_includes_the_bare_name() {
        let tree = Tree::new("suffix");
        tree.put("etc/lightdm/lightdm.conf.d/remote.CONF", XDMCP_ON);
        tree.put("etc/lightdm/lightdm.conf.d/remote.conf.bak", XDMCP_ON);
        assert!(!tree.observe().unwrap().xdmcp_enabled);
        tree.put("etc/lightdm/lightdm.conf.d/.conf", XDMCP_ON);
        assert!(
            tree.observe().unwrap().xdmcp_enabled,
            "LightDM loads a file named .conf"
        );
    }

    #[test]
    fn only_the_exact_value_true_turns_a_server_on() {
        let tree = Tree::new("boolean");
        for (value, on) in [
            ("true", true),
            ("true  ", true),
            ("TRUE", false),
            ("1", false),
            ("yes", false),
            ("on", false),
        ] {
            tree.put(
                "etc/lightdm/lightdm.conf",
                &format!("[XDMCPServer]\nenabled={value}\n"),
            );
            assert_eq!(tree.observe().unwrap().xdmcp_enabled, on, "{value:?}");
        }
    }

    #[test]
    fn content_membership_and_absence_each_change_the_digest() {
        let tree = Tree::new("digest");
        let empty = tree.observe().unwrap().digest;
        tree.put("etc/lightdm/lightdm.conf", "[LightDM]\n");
        let main = tree.observe().unwrap().digest;
        assert_ne!(empty, main, "a main file appearing");
        tree.put("etc/lightdm/lightdm.conf", "[LightDM]\n\n");
        let edited = tree.observe().unwrap().digest;
        assert_ne!(main, edited, "a byte change");
        std::fs::create_dir_all(tree.0.join("etc/xdg/lightdm/lightdm.conf.d")).unwrap();
        let directory = tree.observe().unwrap().digest;
        assert_ne!(edited, directory, "an empty directory appearing");
        tree.put("etc/xdg/lightdm/lightdm.conf.d/00.conf", "");
        let member = tree.observe().unwrap().digest;
        assert_ne!(directory, member, "an empty candidate appearing");
        tree.put("etc/xdg/lightdm/lightdm.conf.d/notes.txt", "");
        assert_eq!(
            member,
            tree.observe().unwrap().digest,
            "a non-candidate name is not read"
        );
    }

    #[test]
    fn symlinked_candidates_are_followed_like_lightdm() {
        let tree = Tree::new("symlink");
        let target = tree.put("elsewhere/remote.ini", XDMCP_ON);
        std::fs::create_dir_all(tree.0.join("etc/lightdm/lightdm.conf.d")).unwrap();
        symlink(
            &target,
            tree.0.join("etc/lightdm/lightdm.conf.d/remote.conf"),
        )
        .unwrap();
        let before = tree.observe().unwrap();
        assert!(before.xdmcp_enabled);
        std::fs::write(&target, XDMCP_OFF).unwrap();
        let after = tree.observe().unwrap();
        assert!(!after.xdmcp_enabled);
        assert_ne!(
            before.digest, after.digest,
            "the target's bytes are covered"
        );
    }

    #[test]
    fn inputs_lightdm_would_not_read_plainly_are_refused() {
        let tree = Tree::new("refuse");
        assert!(tree.observe().is_ok(), "the empty closure is readable");
        std::fs::create_dir_all(tree.0.join("etc/lightdm/lightdm.conf.d/dir.conf")).unwrap();
        assert!(
            tree.observe().is_err(),
            "a directory named like a candidate"
        );
        std::fs::remove_dir(tree.0.join("etc/lightdm/lightdm.conf.d/dir.conf")).unwrap();
        tree.put("etc/lightdm/lightdm.conf.d/bad.conf", "enabled=true\n");
        assert!(tree.observe().is_err(), "an assignment before any group");
        tree.put(
            "etc/lightdm/lightdm.conf.d/bad.conf",
            "[XDMCPServer]\nenabled[de]=true\n",
        );
        assert!(tree.observe().is_err(), "a key outside the strict grammar");
        std::fs::remove_file(tree.0.join("etc/lightdm/lightdm.conf.d/bad.conf")).unwrap();
        assert!(
            tree.observe().is_ok(),
            "the closure reads again once cleaned"
        );
        tree.put(
            "etc/lightdm/lightdm.conf.d/big.conf",
            &"#".repeat(MAX_FILE_BYTES as usize + 1),
        );
        assert!(tree.observe().is_err(), "an unbounded candidate");
        std::fs::remove_file(tree.0.join("etc/lightdm/lightdm.conf.d/big.conf")).unwrap();
        // A layer path that is a file, not a directory.
        std::fs::remove_dir_all(tree.0.join("etc/lightdm/lightdm.conf.d")).ok();
        std::fs::write(tree.0.join("etc/lightdm/lightdm.conf.d"), "").unwrap();
        assert!(tree.observe().is_err(), "a layer that is not a directory");
    }

    #[test]
    fn a_public_read_requires_every_input_to_be_world_readable() {
        let tree = Tree::new("public");
        let main = tree.put("etc/lightdm/lightdm.conf", XDMCP_OFF);
        assert!(observe(&tree.0, &Profile::standard(), true).is_ok());
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(observe(&tree.0, &Profile::standard(), true).is_err());
        assert!(observe(&tree.0, &Profile::standard(), false).is_ok());
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o644)).unwrap();
        let dir = tree.0.join("etc/lightdm/lightdm.conf.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(observe(&tree.0, &Profile::standard(), true).is_err());
    }
}
