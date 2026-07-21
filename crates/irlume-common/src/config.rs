// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Tiny `key=value` config files under the config dir (`/etc/irlume`, override
//! `IRLUME_CONFIG_DIR`), e.g. `cameras.conf`, `settings.conf`. Blank lines and
//! `#` comments are ignored. These hold operator-tunable knobs the setup flow
//! writes and the daemon reads; secrets never live here (those are sealed
//! envelopes elsewhere).

use std::path::PathBuf;

/// Default config root.
pub const CONFIG_ROOT: &str = "/etc/irlume";

fn config_root() -> PathBuf {
    std::env::var_os("IRLUME_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CONFIG_ROOT))
}

/// Absolute path to a config file under the config root.
pub fn config_path(file: &str) -> PathBuf {
    config_root().join(file)
}

/// Read a single key from a `key=value` file. Returns the trimmed value, or
/// `None` if the file is missing, the key is absent, or the value is empty.
pub fn read_kv(file: &str, key: &str) -> Option<String> {
    let path = config_path(file);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        // A present-but-unreadable config (classically a wrong SELinux label)
        // must NOT be ignored silently for the *daemon*: that sends it to
        // auto-detect and it can bind the wrong device. Make it loud (daemon
        // stderr ⇒ journald). But these files are deliberately root-only (0600),
        // so an *unprivileged* CLI caller hitting Permission denied is expected,
        // not a fault; the root daemon reads them fine. Warning there just
        // alarms new users into needlessly loosening permissions. So: stay loud
        // for root and for non-permission errors; stay quiet for the expected
        // EACCES an ordinary user gets.
        Err(e) => {
            let unprivileged_eacces =
                e.kind() == std::io::ErrorKind::PermissionDenied && unsafe { libc::geteuid() } != 0;
            if !unprivileged_eacces {
                eprintln!(
                    "irlume: WARNING: config {p} exists but is unreadable ({e}); key '{key}' \
                     ignored; check permissions / SELinux label (try: restorecon -v {p})",
                    p = path.display(),
                );
            }
            return None;
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Insert or update `key=value`, preserving every other line (including
/// comments) and dropping duplicate keys. Creates the file at 0600 if absent.
pub fn write_kv(file: &str, key: &str, val: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = config_path(file);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        let is_target = !trimmed.starts_with('#')
            && trimmed
                .split_once('=')
                .is_some_and(|(k, _)| k.trim() == key);
        if is_target {
            if !replaced {
                out.push_str(&format!("{key}={val}\n"));
                replaced = true;
            }
            continue; // drop duplicates
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        out.push_str(&format!("{key}={val}\n"));
    }

    std::fs::write(&path, out)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testenv;

    #[test]
    fn read_write_round_trip_preserves_comments() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        std::fs::write(
            config_path("cameras.conf"),
            "# header\n\n  rgb = /dev/video1 \nir=/dev/video3\n",
        )
        .unwrap();
        assert_eq!(
            read_kv("cameras.conf", "rgb").as_deref(),
            Some("/dev/video1")
        );
        assert_eq!(
            read_kv("cameras.conf", "ir").as_deref(),
            Some("/dev/video3")
        );
        assert_eq!(read_kv("cameras.conf", "missing"), None);

        // Update rgb, add a new key; comments + ir must survive.
        write_kv("cameras.conf", "rgb", "/dev/video9").unwrap();
        write_kv("cameras.conf", "fps", "30").unwrap();
        let text = std::fs::read_to_string(config_path("cameras.conf")).unwrap();
        assert!(text.contains("# header"));
        assert_eq!(
            read_kv("cameras.conf", "rgb").as_deref(),
            Some("/dev/video9")
        );
        assert_eq!(
            read_kv("cameras.conf", "ir").as_deref(),
            Some("/dev/video3")
        );
        assert_eq!(read_kv("cameras.conf", "fps").as_deref(), Some("30"));
        // No duplicate rgb line.
        assert_eq!(
            text.matches("rgb=").count() + text.matches("rgb ").count(),
            1
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_path_defaults_to_etc_irlume_without_the_override() {
        let _g = testenv::lock();
        std::env::remove_var("IRLUME_CONFIG_DIR");
        assert_eq!(
            config_path("cameras.conf"),
            PathBuf::from("/etc/irlume/cameras.conf")
        );
    }

    #[test]
    fn read_kv_skips_malformed_lines_and_empty_values() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-lines-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        std::fs::write(
            config_path("settings.conf"),
            "# comment with = sign\nnot a kv line\nempty=\nreal=value\n",
        )
        .unwrap();
        // A line without '=' and a commented '=' are both ignored.
        assert_eq!(read_kv("settings.conf", "not a kv line"), None);
        assert_eq!(read_kv("settings.conf", "# comment with "), None);
        // `key=` (empty value) reads as absent, not Some("").
        assert_eq!(read_kv("settings.conf", "empty"), None);
        assert_eq!(read_kv("settings.conf", "real").as_deref(), Some("value"));

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_config_reads_as_absent_not_a_crash() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-eperm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        // A directory where a file is expected: a non-NotFound, non-EACCES read
        // error (EISDIR). Takes the loud-warning branch and still yields None.
        std::fs::create_dir_all(config_path("weird.conf")).unwrap();
        assert_eq!(read_kv("weird.conf", "k"), None);

        // 0600-root-style file we cannot read: the expected unprivileged EACCES
        // is the quiet branch. Only meaningful when not running as root.
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let p = config_path("locked.conf");
            std::fs::write(&p, "k=v\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(read_kv("locked.conf", "k"), None);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_kv_collapses_preexisting_duplicate_keys() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        // A hand-edited file can carry the same key twice; an update must
        // leave exactly one line, holding the new value, and keep other keys.
        std::fs::write(
            config_path("cameras.conf"),
            "rgb=/dev/video0\nir=/dev/video2\nrgb=/dev/video4\n",
        )
        .unwrap();
        write_kv("cameras.conf", "rgb", "/dev/video8").unwrap();
        let text = std::fs::read_to_string(config_path("cameras.conf")).unwrap();
        assert_eq!(text.matches("rgb=").count(), 1);
        assert!(text.contains("rgb=/dev/video8"));
        assert_eq!(
            read_kv("cameras.conf", "ir").as_deref(),
            Some("/dev/video2")
        );

        // The file is (re)written 0600: these can hold device choices only the
        // operator should edit.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(config_path("cameras.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn third_party_pad_enable_then_disable_round_trips() {
        // The models feature persists its enabled state as this key: a model
        // name means enabled, an empty value means disabled. Locks in that
        // `write_kv(key, "")` reads back as None (not Some("")), which is what
        // `irlume models disable` and the daemon's enabled_name() rely on.
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-tp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        let key = crate::thirdparty::SETTINGS_KEY;
        assert_eq!(read_kv("settings.conf", key), None); // absent = disabled

        write_kv("settings.conf", key, "flir").unwrap(); // enable
        assert_eq!(read_kv("settings.conf", key).as_deref(), Some("flir"));

        write_kv("settings.conf", key, "").unwrap(); // disable
        assert_eq!(read_kv("settings.conf", key), None);

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
