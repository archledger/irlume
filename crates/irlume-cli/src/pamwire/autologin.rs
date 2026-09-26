// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Whether a login manager logs an account in automatically.
//!
//! An automatic login runs no authentication, so pam_irlume releases nothing
//! at it, and a GNOME keyring token armed for that account would never reach
//! its keyring. A token arm asks here before anything is sealed.
//!
//! Each login manager's own files, read in the order it reads them, with the
//! last assignment winning as it does there. Login managers irlume has no
//! reader for answer "no".

use std::path::{Path, PathBuf};

/// The file that turns on automatic login of `user` for login manager `dm`,
/// or `None`. An error names a file that exists and could not be read: what
/// it says is unknown, and the caller decides what that means.
pub(super) fn autologin_source(dm: &str, user: &str) -> Result<Option<PathBuf>, String> {
    autologin_source_in(Path::new("/"), dm, user)
}

/// [`autologin_source`] under `root`, so tests can lay the files out.
pub(super) fn autologin_source_in(
    root: &Path,
    dm: &str,
    user: &str,
) -> Result<Option<PathBuf>, String> {
    match dm {
        // GDM reads one file, fixed at build time. Debian and Ubuntu build
        // it as gdm3, reading /etc/gdm3 (daemon.conf on Debian, custom.conf
        // on Ubuntu); the others read /etc/gdm/custom.conf. Where /etc/gdm3
        // exists, a /etc/gdm left behind by another build is not read.
        "gdm" | "gdm3" => {
            // A /etc/gdm3 this process cannot inspect (a link into a
            // directory it cannot search) says nothing about which build is
            // installed, and GDM, running as root, reads it all the same.
            let gdm3 = root.join("etc/gdm3");
            let debian = match std::fs::metadata(&gdm3) {
                Ok(meta) => meta.is_dir(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(e) => return Err(format!("{}: {e}", gdm3.display())),
            };
            let files: &[&str] = if debian {
                &["etc/gdm3/daemon.conf", "etc/gdm3/custom.conf"]
            } else {
                &["etc/gdm/custom.conf"]
            };
            for file in files {
                let path = root.join(file);
                if let Some(text) = read(&path)? {
                    if gdm_logs_in(&text, user) {
                        return Ok(Some(path));
                    }
                }
            }
            Ok(None)
        }
        // SDDM and its fork read the system drop-ins, then the admin's, each
        // in name order, then the main file (sddm's ConfigBase::load).
        "sddm" => last_user_in(
            root,
            &["usr/lib/sddm/sddm.conf.d", "etc/sddm.conf.d"],
            "etc/sddm.conf",
            user,
        ),
        "plasmalogin" => last_user_in(
            root,
            &[
                "usr/lib/plasmalogin/plasmalogin.conf.d",
                "etc/plasmalogin.conf.d",
            ],
            "etc/plasmalogin.conf",
            user,
        ),
        "lightdm" => lightdm_source(root, user),
        // greetd's `[initial_session]` starts once at boot without asking.
        // cosmic-greeter is greetd with its own configuration file.
        "greetd" => greetd_source(root, "etc/greetd/config.toml", user),
        "cosmic-greeter" => greetd_source(root, "etc/greetd/cosmic-greeter.toml", user),
        // ly: a flat `auto_login_user = …`, `null` when off. Its automatic
        // login runs through a service of its own (`ly-autologin`), which
        // irlume never wires.
        "ly" => {
            let path = root.join("etc/ly/config.ini");
            let Some(text) = read(&path)? else {
                return Ok(None);
            };
            let last = assignments(&text)
                .into_iter()
                .filter(|(section, key, _)| section.is_empty() && key == "auto_login_user")
                .map(|(_, _, value)| unquoted(&value).to_string())
                .next_back();
            let named = last.as_deref() == Some(user);
            Ok(named.then_some(path))
        }
        _ => Ok(None),
    }
}

/// A file's text, `None` when it does not exist.
pub(super) fn read(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The files in `dir` a login manager reads, in name order; none when the
/// directory does not exist. `conf_only` keeps LightDM's `*.conf` rule.
fn drop_ins(dir: &Path, conf_only: bool) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        if conf_only && path.extension().is_none_or(|ext| ext != "conf") {
            continue;
        }
        // Files only, following links as the login managers do. A link to
        // nothing is skipped, as they skip it; one whose target this process
        // cannot inspect is an error, since the login manager, running as
        // root, may well read it.
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => files.push(path),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    files.sort();
    Ok(files)
}

/// The `key=value` pairs of an INI-style file, each with its section. A `#`
/// or `;` starts a comment; SDDM also cuts a `#` inside a line, and an
/// account name has none, so every reader here does.
pub(super) fn assignments(text: &str) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.push((
                section.clone(),
                key.trim().to_string(),
                value.trim().to_string(),
            ));
        }
    }
    out
}

/// A value with one pair of surrounding quotes taken off, as the login
/// managers' INI readers do.
fn unquoted(value: &str) -> &str {
    let value = value.trim();
    ["\"", "'"]
        .iter()
        .find_map(|q| value.strip_prefix(q)?.strip_suffix(q))
        .unwrap_or(value)
}

/// A GKeyFile boolean, read leniently: a doubtful spelling counts as on,
/// because only a user match makes it matter.
pub(super) fn on(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

/// GDM's `[daemon]` automatic or timed login of `user`.
fn gdm_logs_in(text: &str, user: &str) -> bool {
    let mut values = std::collections::HashMap::new();
    for (section, key, value) in assignments(text) {
        if section == "daemon" {
            values.insert(key, value);
        }
    }
    let get = |key: &str| values.get(key).map(String::as_str).unwrap_or("");
    (on(get("AutomaticLoginEnable")) && get("AutomaticLogin") == user)
        || (on(get("TimedLoginEnable")) && get("TimedLogin") == user)
}

/// SDDM's `[Autologin] User=`, the last one read deciding.
fn last_user_in(
    root: &Path,
    dirs: &[&str],
    main: &str,
    user: &str,
) -> Result<Option<PathBuf>, String> {
    let mut files = Vec::new();
    for dir in dirs {
        files.extend(drop_ins(&root.join(dir), false)?);
    }
    files.push(root.join(main));
    let mut last: Option<(String, PathBuf)> = None;
    for path in files {
        let Some(text) = read(&path)? else { continue };
        for (section, key, value) in assignments(&text) {
            if section == "Autologin" && key == "User" {
                last = Some((unquoted(&value).to_string(), path.clone()));
            }
        }
    }
    Ok(last.and_then(|(value, path)| (value == user).then_some(path)))
}

/// LightDM's drop-in directories, in the order it reads them.
pub(super) const LIGHTDM_DROP_IN_DIRS: [&str; 4] = [
    "usr/share/lightdm/lightdm.conf.d",
    "usr/local/share/lightdm/lightdm.conf.d",
    "etc/xdg/lightdm/lightdm.conf.d",
    "etc/lightdm/lightdm.conf.d",
];

/// LightDM's main configuration file, read after every drop-in.
pub(super) const LIGHTDM_MAIN: &str = "etc/lightdm/lightdm.conf";

/// The files LightDM reads, in its order: the `*.conf` drop-ins of each
/// configuration directory, then the main file.
pub(super) fn lightdm_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for dir in LIGHTDM_DROP_IN_DIRS {
        files.extend(drop_ins(&root.join(dir), true)?);
    }
    files.push(root.join(LIGHTDM_MAIN));
    Ok(files)
}

/// LightDM's `autologin-user=` in any seat section, the last one read for
/// each section deciding.
fn lightdm_source(root: &Path, user: &str) -> Result<Option<PathBuf>, String> {
    let files = lightdm_files(root)?;
    let mut seats: std::collections::HashMap<String, (String, PathBuf)> =
        std::collections::HashMap::new();
    for path in files {
        let Some(text) = read(&path)? else { continue };
        for (section, key, value) in assignments(&text) {
            let seat = section.starts_with("Seat:") || section == "SeatDefaults";
            if seat && key == "autologin-user" {
                seats.insert(section, (value, path.clone()));
            }
        }
    }
    Ok(seats
        .into_values()
        .find_map(|(value, path)| (value == user).then_some(path)))
}

/// greetd's `initial_session` user. greetd reads its configuration with a
/// TOML parser, and so does this, so every spelling of the key (a table, a
/// dotted or quoted key, an inline table) and every string escape means here
/// what it means to greetd. A file greetd could not parse is an error.
fn greetd_source(root: &Path, file: &str, user: &str) -> Result<Option<PathBuf>, String> {
    let path = root.join(file);
    let Some(text) = read(&path)? else {
        return Ok(None);
    };
    let config: toml::Table =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let starts_as = config
        .get("initial_session")
        .and_then(|session| session.get("user"))
        .and_then(toml::Value::as_str)
        == Some(user);
    Ok(starts_as.then_some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Root(PathBuf);

    impl Root {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "irlume-autologin-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Root(dir)
        }

        fn put(&self, file: &str, text: &str) -> PathBuf {
            let path = self.0.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        }

        fn source(&self, dm: &str, user: &str) -> Result<Option<PathBuf>, String> {
            autologin_source_in(&self.0, dm, user)
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn gdm_automatic_and_timed_login_name_the_account() {
        let root = Root::new("gdm");
        assert_eq!(root.source("gdm", "alice"), Ok(None), "no file");
        let custom = root.put(
            "etc/gdm/custom.conf",
            "[daemon]\n# AutomaticLoginEnable=True\nAutomaticLoginEnable=True\n\
             AutomaticLogin=alice\n\n[security]\n",
        );
        assert_eq!(root.source("gdm", "alice"), Ok(Some(custom.clone())));
        assert_eq!(root.source("gdm", "bob"), Ok(None), "another account");
        root.put(
            "etc/gdm/custom.conf",
            "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=alice\n",
        );
        assert_eq!(root.source("gdm", "alice"), Ok(None), "turned off");
        root.put(
            "etc/gdm/custom.conf",
            "[security]\nAutomaticLoginEnable=true\nAutomaticLogin=alice\n",
        );
        assert_eq!(root.source("gdm", "alice"), Ok(None), "not [daemon]");
        // Debian's gdm3 reads daemon.conf; timed login counts too.
        root.put(
            "etc/gdm/custom.conf",
            "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=alice\n",
        );
        root.put("etc/gdm3/daemon.conf", "[daemon]\n");
        assert_eq!(
            root.source("gdm3", "alice"),
            Ok(None),
            "a /etc/gdm another build left is not read where /etc/gdm3 exists"
        );
        let debian = root.put(
            "etc/gdm3/daemon.conf",
            "[daemon]\nTimedLoginEnable = true\nTimedLogin = alice\n",
        );
        assert_eq!(root.source("gdm3", "alice"), Ok(Some(debian)));
        // Ubuntu's reads custom.conf there.
        root.put("etc/gdm3/daemon.conf", "[daemon]\n");
        let ubuntu = root.put(
            "etc/gdm3/custom.conf",
            "[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=alice\n",
        );
        assert_eq!(root.source("gdm", "alice"), Ok(Some(ubuntu)));
    }

    #[test]
    fn sddm_and_plasmalogin_take_the_last_user_they_read() {
        let root = Root::new("sddm");
        assert_eq!(root.source("sddm", "alice"), Ok(None), "no file");
        let system = root.put(
            "usr/lib/sddm/sddm.conf.d/10-vendor.conf",
            "[Autologin]\nUser=alice\nSession=plasma\n",
        );
        assert_eq!(root.source("sddm", "alice"), Ok(Some(system)));
        // The admin's drop-in is read later and clears it.
        root.put("etc/sddm.conf.d/kde_settings.conf", "[Autologin]\nUser=\n");
        assert_eq!(root.source("sddm", "alice"), Ok(None));
        // The main file is read last of all.
        let main = root.put("etc/sddm.conf", "[General]\n[Autologin]\nUser=alice # me\n");
        assert_eq!(root.source("sddm", "alice"), Ok(Some(main)));
        let quoted = root.put("etc/sddm.conf", "[Autologin]\nUser=\"alice\"\n");
        assert_eq!(root.source("sddm", "alice"), Ok(Some(quoted)));
        assert_eq!(root.source("sddm", "bob"), Ok(None));

        assert_eq!(
            root.source("plasmalogin", "alice"),
            Ok(None),
            "its own files"
        );
        let plasma = root.put(
            "etc/plasmalogin.conf.d/autologin.conf",
            "[Autologin]\nUser=alice\nSession=plasma.desktop\n",
        );
        assert_eq!(root.source("plasmalogin", "alice"), Ok(Some(plasma)));
    }

    #[test]
    fn lightdm_counts_any_seat_and_only_conf_drop_ins() {
        let root = Root::new("lightdm");
        root.put(
            "etc/lightdm/lightdm.conf.d/50-auto.conf.disabled",
            "[Seat:*]\nautologin-user=alice\n",
        );
        assert_eq!(root.source("lightdm", "alice"), Ok(None), "not a .conf");
        let conf = root.put(
            "usr/share/lightdm/lightdm.conf.d/50-auto.conf",
            "[Seat:*]\nautologin-user=alice\n",
        );
        assert_eq!(root.source("lightdm", "alice"), Ok(Some(conf)));
        root.put("etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=\n");
        assert_eq!(root.source("lightdm", "alice"), Ok(None), "cleared later");
        let seat0 = root.put(
            "etc/lightdm/lightdm.conf",
            "[Seat:*]\nautologin-user=\n[SeatDefaults]\nautologin-user=alice\n",
        );
        assert_eq!(root.source("lightdm", "alice"), Ok(Some(seat0)));
    }

    #[test]
    fn greetd_initial_session_names_the_account() {
        let root = Root::new("greetd");
        root.put(
            "etc/greetd/config.toml",
            "[default_session]\ncommand = \"tuigreet\"\nuser = \"greeter\"\n",
        );
        assert_eq!(
            root.source("greetd", "greeter"),
            Ok(None),
            "the greeter's own user"
        );
        let config = root.put(
            "etc/greetd/config.toml",
            "[default_session]\nuser = \"greeter\"\n\n[initial_session]\n\
             command = \"sway\"\nuser = \"alice\"\n",
        );
        assert_eq!(root.source("greetd", "alice"), Ok(Some(config)));
        assert_eq!(
            root.source("cosmic-greeter", "alice"),
            Ok(None),
            "its own file"
        );
        let cosmic = root.put(
            "etc/greetd/cosmic-greeter.toml",
            "[initial_session]\nuser = 'alice'\n",
        );
        assert_eq!(root.source("cosmic-greeter", "alice"), Ok(Some(cosmic)));
        // TOML's other spellings of the same key.
        for text in [
            "[\"initial_session\"]\nuser = \"alice\"\n",
            "[ 'initial_session' ]\n'user' = 'alice'\n",
            "initial_session.user = \"alice\"\n",
            "\"initial_session\".\"user\" = \"alice\"\n",
            "initial_session = { command = \"sway\", user = \"alice\" }\n",
        ] {
            let config = root.put("etc/greetd/config.toml", text);
            assert_eq!(root.source("greetd", "alice"), Ok(Some(config)), "{text}");
        }
        root.put(
            "etc/greetd/config.toml",
            "default_session.user = \"alice\"\ninitial_session = { user = \"bob\" }\n",
        );
        assert_eq!(root.source("greetd", "alice"), Ok(None));
        // A string escape, decoded as greetd decodes it.
        let escaped = root.put(
            "etc/greetd/config.toml",
            "initial_session.user = \"ali\\u0063e\"\n",
        );
        assert_eq!(root.source("greetd", "alice"), Ok(Some(escaped)));
        // A file greetd could not parse either.
        root.put(
            "etc/greetd/config.toml",
            "[initial_session\nuser = \"alice\"\n",
        );
        let answer = root.source("greetd", "alice");
        assert!(
            answer
                .as_ref()
                .is_err_and(|e| e.contains("etc/greetd/config.toml")),
            "{answer:?}"
        );
    }

    #[test]
    fn ly_names_its_automatic_login_user() {
        let root = Root::new("ly");
        assert_eq!(root.source("ly", "alice"), Ok(None), "no file");
        root.put(
            "etc/ly/config.ini",
            "# Automatic login\nauto_login_service = ly-autologin\nauto_login_user = null\n",
        );
        assert_eq!(root.source("ly", "alice"), Ok(None), "off");
        let config = root.put("etc/ly/config.ini", "auto_login_user = alice\n");
        assert_eq!(root.source("ly", "alice"), Ok(Some(config)));
        assert_eq!(root.source("ly", "bob"), Ok(None));
        // The last assignment is the one ly keeps.
        root.put(
            "etc/ly/config.ini",
            "auto_login_user = alice\nauto_login_user = null\n",
        );
        assert_eq!(root.source("ly", "alice"), Ok(None));
    }

    #[test]
    fn an_unreadable_file_is_an_error_not_a_no() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = Root::new("unreadable");
        // Root reads anything, so this cannot be shown to root.
        if crate::pamwire::effective_uid() == 0 {
            return;
        }
        let path = root.put("etc/sddm.conf", "[Autologin]\nUser=alice\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let answer = root.source("sddm", "alice");
        assert!(
            answer.as_ref().is_err_and(|e| e.contains("etc/sddm.conf")),
            "{answer:?}"
        );
        std::fs::remove_file(&path).unwrap();
        // A drop-in linking into a directory this process cannot enter.
        let hidden = root.put("private/autologin.conf", "[Autologin]\nUser=alice\n");
        let dropins = root.0.join("etc/sddm.conf.d");
        std::fs::create_dir_all(&dropins).unwrap();
        std::os::unix::fs::symlink(&hidden, dropins.join("autologin.conf")).unwrap();
        std::os::unix::fs::symlink(root.0.join("gone"), dropins.join("dangling.conf")).unwrap();
        assert_eq!(
            root.source("sddm", "alice"),
            Ok(Some(dropins.join("autologin.conf")))
        );
        let private = hidden.parent().unwrap();
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o000)).unwrap();
        let answer = root.source("sddm", "alice");
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            answer
                .as_ref()
                .is_err_and(|e| e.contains("sddm.conf.d/autologin.conf")),
            "{answer:?}"
        );
        assert_eq!(root.source("ly", "alice"), Ok(None), "no reader");
        // A /etc/gdm3 linked into a directory this process cannot search:
        // which GDM build reads what is unknown, so it is an error.
        let hidden = root.0.join("hidden");
        std::fs::create_dir_all(hidden.join("gdm3")).unwrap();
        std::fs::create_dir_all(root.0.join("etc")).unwrap();
        std::os::unix::fs::symlink(hidden.join("gdm3"), root.0.join("etc/gdm3")).unwrap();
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
        let answer = root.source("gdm3", "alice");
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(answer.is_err_and(|e| e.contains("etc/gdm3")));
    }
}
