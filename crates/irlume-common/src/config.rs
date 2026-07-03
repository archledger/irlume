//! Tiny `key=value` config files under the config dir (`/etc/irlume`, override
//! `IRLUME_CONFIG_DIR`) — e.g. `cameras.conf`, `settings.conf`. Blank lines and
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
        // not a fault — the root daemon reads them fine. Warning there just
        // alarms new users into needlessly loosening permissions. So: stay loud
        // for root and for non-permission errors; stay quiet for the expected
        // EACCES an ordinary user gets.
        Err(e) => {
            let unprivileged_eacces =
                e.kind() == std::io::ErrorKind::PermissionDenied && unsafe { libc::geteuid() } != 0;
            if !unprivileged_eacces {
                eprintln!(
                    "irlume: WARNING: config {p} exists but is unreadable ({e}); key '{key}' \
                     ignored — check permissions / SELinux label (try: restorecon -v {p})",
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
            && trimmed.split_once('=').is_some_and(|(k, _)| k.trim() == key);
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
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn read_write_round_trip_preserves_comments() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        std::fs::write(config_path("cameras.conf"), "# header\n\n  rgb = /dev/video1 \nir=/dev/video3\n").unwrap();
        assert_eq!(read_kv("cameras.conf", "rgb").as_deref(), Some("/dev/video1"));
        assert_eq!(read_kv("cameras.conf", "ir").as_deref(), Some("/dev/video3"));
        assert_eq!(read_kv("cameras.conf", "missing"), None);

        // Update rgb, add a new key; comments + ir must survive.
        write_kv("cameras.conf", "rgb", "/dev/video9").unwrap();
        write_kv("cameras.conf", "fps", "30").unwrap();
        let text = std::fs::read_to_string(config_path("cameras.conf")).unwrap();
        assert!(text.contains("# header"));
        assert_eq!(read_kv("cameras.conf", "rgb").as_deref(), Some("/dev/video9"));
        assert_eq!(read_kv("cameras.conf", "ir").as_deref(), Some("/dev/video3"));
        assert_eq!(read_kv("cameras.conf", "fps").as_deref(), Some("30"));
        // No duplicate rgb line.
        assert_eq!(text.matches("rgb=").count() + text.matches("rgb ").count(), 1);

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
