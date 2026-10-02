// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Whether a login manager logs an account in automatically.
//!
//! An automatic login runs no authentication, so pam_irlume releases nothing
//! at it, and a GNOME keyring token armed for that account would never reach
//! its keyring. A token arm asks here before anything is sealed.
//!
//! Each login manager's own files and assignment rules. When the outcome
//! depends on an unknown daemon collation or parser version, refuse to guess.
//! Login managers irlume has no reader for answer "no".

use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// The file that turns on automatic login of `user` for login manager `dm`,
/// or `None`. An error identifies unreadable or ambiguous configuration;
/// the caller decides what that means.
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
                    if gdm_logs_in(&text, user).map_err(|e| format!("{}: {e}", path.display()))? {
                        return Ok(Some(path));
                    }
                }
            }
            Ok(None)
        }
        // System drop-ins, then the admin's, then the main file. Their Qt
        // collation need not match this CLI's locale or byte ordering.
        "sddm" => last_user_in(
            root,
            &["usr/lib/sddm/sddm.conf.d", "etc/sddm.conf.d"],
            "etc/sddm.conf",
            user,
            false,
        ),
        "plasmalogin" => last_user_in(
            root,
            &[
                "usr/lib/plasmalogin/plasmalogin.conf.d",
                "etc/plasmalogin.conf.d",
            ],
            "etc/plasmalogin.conf",
            user,
            true,
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
            let last = ini_assignments(&text, IniComments::Ly)
                .into_iter()
                .filter(|(section, key, _)| section.is_empty() && key == "auto_login_user")
                .map(|(_, _, value)| value)
                .next_back();
            let named = last.as_deref() == Some(user);
            Ok(named.then_some(path))
        }
        _ => Ok(None),
    }
}

/// A file's text, `None` when it does not exist.
pub(super) fn read(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Candidate files, in deterministic byte order; none when `dir` is absent.
/// LightDM consumes this order and `*.conf` filter. Qt callers use the files
/// as an unordered layer, since byte order does not establish Qt collation.
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
        // QDir::Files without QDir::Hidden excludes dotfiles. LightDM's
        // directory enumeration has no corresponding filter.
        if !conf_only && entry.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
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

/// GKeyFile-style assignments for GDM and LightDM. Hashes inside values
/// and group names are literal; quotes do not protect or remove them.
/// Only a plain-key, unescaped-value subset is supported. Malformed or
/// unsupported input is unknown, never a partial set of assignments: LightDM
/// discards a whole file on a GKeyFile load error, retaining earlier files.
pub(super) fn assignments(text: &str) -> Result<Vec<(String, String, String)>, String> {
    let mut section = None;
    let mut out = Vec::new();
    for (index, raw) in text.split_inclusive('\n').enumerate() {
        let invalid = || format!("unsupported or malformed GKeyFile line {}", index + 1);
        // GLib removes CR only when followed by LF. A bare CR at EOF can
        // invalidate the whole file, so do not normalize it into a valid header.
        let line = if let Some(line) = raw.strip_suffix('\n') {
            line.strip_suffix('\r').unwrap_or(line)
        } else {
            raw
        };
        let line = line.trim_start_matches([' ', '\t']);
        if line.contains('\0') {
            return Err(invalid());
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            let name = line
                .trim_end_matches([' ', '\t'])
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .filter(|s| {
                    !s.is_empty() && !s.contains(['[', ']']) && !s.chars().any(char::is_control)
                })
                .ok_or_else(invalid)?;
            section = Some(name.to_string());
        } else {
            let group = section.as_ref().ok_or_else(invalid)?;
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let key = key.trim_end_matches([' ', '\t']);
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                || value.contains('\\')
                || value.chars().any(|c| c.is_control() && c != '\t')
                || (key == "Encoding" && value.trim_start_matches([' ', '\t']) != "UTF-8")
            {
                return Err(invalid());
            }
            out.push((
                group.clone(),
                key.to_string(),
                value.trim_matches([' ', '\t']).to_string(),
            ));
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
enum IniComments {
    Inline,
    Ly,
}

fn ini_assignments(text: &str, comments: IniComments) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = match comments {
            IniComments::Inline => Cow::Borrowed(line.split('#').next().unwrap_or("")),
            IniComments::Ly => Cow::Owned(ly_uncommented(line)),
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
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

/// Ly's zigini parser removes the backslash immediately before a hash.
/// Quotes are ordinary value characters, not a way to escape comments.
fn ly_uncommented(line: &str) -> String {
    let mut value = String::new();
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        if ch != '#' {
            value.push(ch);
        } else if value.ends_with('\\') {
            value.pop();
            value.push('#');
            // ziglibs-ini resumes its comment scan one position beyond
            // the escaped hash after removing the preceding backslash.
            if let Some(next) = chars.next() {
                value.push(next);
            }
        } else {
            break;
        }
    }
    value
}

/// A GKeyFile boolean, read leniently: a doubtful spelling counts as on,
/// because only a user match makes it matter.
pub(super) fn on(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

/// GDM's `[daemon]` automatic or timed login of `user`.
fn gdm_logs_in(text: &str, user: &str) -> Result<bool, String> {
    let mut values = std::collections::HashMap::new();
    for (section, key, value) in assignments(text)? {
        if section == "daemon" {
            values.insert(key, value);
        }
    }
    let get = |key: &str| values.get(key).map(String::as_str).unwrap_or("");
    Ok(
        (on(get("AutomaticLoginEnable")) && get("AutomaticLogin") == user)
            || (on(get("TimedLoginEnable")) && get("TimedLogin") == user),
    )
}

/// Each directory is a priority layer. Without the daemon's Qt backend and
/// locale, conservatively consider every file as a potential last assignment.
/// Decide only when they agree about this account; a later layer replaces them.
fn last_user_in(
    root: &Path,
    dirs: &[&str],
    main: &str,
    user: &str,
    plasma: bool,
) -> Result<Option<PathBuf>, String> {
    // Keep the two parser interpretations separate, including absence of an
    // assignment. Each can inherit from or override a preceding layer.
    let mut candidates: [Vec<(String, PathBuf)>; 2] = [Vec::new(), Vec::new()];
    for dir in dirs {
        let mut layer = [Vec::new(), Vec::new()];
        for path in drop_ins(&root.join(dir), false)? {
            for (lane, value) in layer.iter_mut().zip(qt_users_in(&path, plasma, false)?) {
                if let Some(value) = value {
                    lane.push((value, path.clone()));
                }
            }
        }
        for (lane, next) in candidates.iter_mut().zip(layer) {
            if !next.is_empty() {
                *lane = next;
            }
        }
    }
    let main = root.join(main);
    for (lane, value) in candidates.iter_mut().zip(qt_users_in(&main, plasma, true)?) {
        if let Some(value) = value {
            *lane = vec![(value, main.clone())];
        }
    }
    let lanes = &candidates[..if plasma { 2 } else { 1 }];
    if let Some((_, path)) = lanes.iter().flatten().find(|(value, _)| value == user) {
        if lanes
            .iter()
            .any(|lane| lane.is_empty() || lane.iter().any(|(value, _)| value != user))
        {
            return Err(format!(
                "{}: autologin depends on the login manager's Qt collation or parser version",
                path.display()
            ));
        }
        return Ok(Some(path.clone()));
    }
    Ok(None)
}

fn qt_users_in(path: &Path, plasma: bool, main: bool) -> Result<[Option<String>; 2], String> {
    if plasma && main {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_symlink() => {
                // KConfig canonicalizes the main filename before deciding
                // whether to read global sources. Do not guess that source graph.
                return Err(format!(
                    "{}: unsupported Plasma Login configuration symlink",
                    path.display()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok([None, None]),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    let Some(text) = read(path)? else {
        return Ok([None, None]);
    };
    let user = |entries: Vec<(String, String, String)>| {
        entries
            .into_iter()
            .filter(|(section, key, _)| section == "Autologin" && key == "User")
            .map(|(_, _, value)| value)
            .next_back()
    };
    let legacy = user(ini_assignments(&text, IniComments::Inline));
    // Plasma 6.6 uses ConfigReader; 6.7.5 uses KConfig. Only carry alternatives
    // for the supported common grammar. Unsupported syntax could be immutable
    // and must fail immediately, even if a later ordinary file sets User.
    let current = if plasma {
        let entries = plain_plasma_assignments(&text).map_err(|e| {
            format!(
                "{}: unsupported Plasma Login configuration: {e}",
                path.display()
            )
        })?;
        user(entries)
    } else {
        None
    };
    Ok([legacy, current])
}

/// Plain-ASCII grammar with a 4096-byte line limit. Accept no
/// flags, nested/localized groups or keys, escapes, expansions, or directives.
/// This is a refusal boundary, not an implementation of KConfig's full parser.
fn plain_plasma_assignments(text: &str) -> Result<Vec<(String, String, String)>, String> {
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let plain_group = !line.starts_with('[')
            || line
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .is_some_and(|name| {
                    !name.is_empty()
                        && name
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
                });
        if !line.is_ascii() || line.len() > 4096 || line.contains(['\\', '$', '\0']) || !plain_group
        {
            return Err(format!("unsupported syntax on line {}", index + 1));
        }
    }
    assignments(text)
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
        for (section, key, value) in
            assignments(&text).map_err(|e| format!("{}: {e}", path.display()))?
        {
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
    fn malformed_gkeyfile_autologin_is_unknown() {
        let root = Root::new("malformed-gkeyfile-autologin");
        for (dm, file, group, key) in [
            ("gdm", "etc/gdm/custom.conf", "daemon", "AutomaticLogin"),
            (
                "lightdm",
                "etc/lightdm/lightdm.conf",
                "Seat:*",
                "autologin-user",
            ),
        ] {
            for malformed in [
                "[Other] # not a GKeyFile comment",
                "[Other",
                "[]",
                "not an assignment",
                "=empty key",
                "Encoding=not-UTF-8",
                "Nul=\0",
            ] {
                root.put(file, &format!("[{group}]\n{malformed}\n{key}=bob\n"));
                assert!(root.source(dm, "alice").is_err(), "{dm}: {malformed:?}");
            }
            let path = root.put(file, "");
            let mut invalid_utf8 = format!("[{group}]\n{key}=").into_bytes();
            invalid_utf8.push(0xff);
            std::fs::write(path, invalid_utf8).unwrap();
            assert!(root.source(dm, "alice").is_err(), "{dm}: invalid UTF-8");
        }
    }

    #[test]
    fn plasma_unsupported_syntax_is_not_agreement_or_overridable() {
        let root = Root::new("plasma-unsupported");
        root.put("etc/plasmalogin.conf", "[Autologin]\nUser=bob\n");
        for text in [
            "[Autologin][$i]\nUser=alice\n",
            "[Autologin]\nUser[$i]=alice\n",
            "[$i]\n[Autologin]\nUser=alice\n",
            "[Autologin]\nUser[$e]=${USER}\n",
            "[Autologin]\nUser=ali\\x63e\n",
            "[Auto\\x6cogin]\nUser=alice\n",
            "[Autologin]\nUs\\x65r=alice\n",
            "[Autologin]\nUser[en_US]=alice\n",
            "[Autologin]\nUser[$d]\n",
            "[Autologin][Nested]\nUser=alice\n",
        ] {
            // Qt includes extensionless supplemental files as well as .conf.
            root.put("usr/lib/plasmalogin/plasmalogin.conf.d/vendor", text);
            assert!(root.source("plasmalogin", "alice").is_err(), "{text:?}");
            assert!(root.source("plasmalogin", "bob").is_err(), "{text:?}");
        }
    }

    #[test]
    fn plasma_nonplain_sources_cannot_be_hidden_by_a_main_override() {
        let root = Root::new("plasma-nonplain-source");
        let main = root.put("etc/plasmalogin.conf", "[Autologin]\nUser=bob\n");
        let target = root.put("elsewhere/kdeglobals", "[Autologin][$i]\nUser=alice\n");
        let vendor = root.0.join("usr/lib/plasmalogin/plasmalogin.conf.d/vendor");
        std::fs::create_dir_all(vendor.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &vendor).unwrap();
        assert!(root.source("plasmalogin", "alice").is_err());
        // An ordinary drop-in alias has no KConfig main-file source routing.
        // Once its content is supported, the main file can override it.
        root.put("elsewhere/kdeglobals", "[Autologin]\nUser=alice\n");
        assert_eq!(root.source("plasmalogin", "alice"), Ok(None));
        assert_eq!(root.source("plasmalogin", "bob"), Ok(Some(main.clone())));
        std::fs::remove_file(&vendor).unwrap();
        // A canonical main path aliasing kdeglobals can alter KConfig's
        // source selection, even though Plasma requested NoGlobals.
        std::fs::remove_file(&main).unwrap();
        std::os::unix::fs::symlink(&target, &main).unwrap();
        assert!(root.source("plasmalogin", "alice").is_err());
        std::fs::remove_file(&main).unwrap();
        root.put("etc/plasmalogin.conf", "[Autologin]\nUser=bob\n");
        std::os::unix::fs::symlink("vendor", &vendor).unwrap();
        assert!(
            root.source("plasmalogin", "bob").is_err(),
            "unreadable source"
        );
    }

    #[test]
    fn plasma_supported_hash_alternatives_resolve_after_precedence() {
        let root = Root::new("plasma-hash-precedence");
        root.put(
            "usr/lib/plasmalogin/plasmalogin.conf.d/vendor",
            "[Autologin]\nUser=ops#1\n",
        );
        assert!(root.source("plasmalogin", "ops").is_err());
        assert!(root.source("plasmalogin", "ops#1").is_err());
        assert_eq!(root.source("plasmalogin", "bob"), Ok(None));
        let main = root.put("etc/plasmalogin.conf", "[Autologin]\nUser=bob\n");
        assert_eq!(root.source("plasmalogin", "bob"), Ok(Some(main)));
        assert_eq!(root.source("plasmalogin", "ops#1"), Ok(None));
        root.put("etc/plasmalogin.conf", "[General]\nTheme=plain\n");
        assert!(root.source("plasmalogin", "ops#1").is_err());
        let admin = root.put("etc/plasmalogin.conf.d/admin", "[Autologin]\nUser=alice\n");
        assert_eq!(root.source("plasmalogin", "alice"), Ok(Some(admin)));
        assert_eq!(root.source("plasmalogin", "ops"), Ok(None));
    }

    #[test]
    fn gkeyfile_hashes_are_literal_inside_values_and_group_names() {
        let root = Root::new("gkeyfile-hash");
        let gdm = root.put(
            "etc/gdm/custom.conf",
            "# comment\n[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=ops#1\n",
        );
        assert_eq!(root.source("gdm", "ops#1"), Ok(Some(gdm)));
        assert_eq!(root.source("gdm", "ops"), Ok(None));
        let lightdm = root.put(
            "etc/lightdm/lightdm.conf",
            "[Seat:seat#1]\nautologin-user=ops#1\n",
        );
        assert_eq!(root.source("lightdm", "ops#1"), Ok(Some(lightdm)));
        assert_eq!(root.source("lightdm", "ops"), Ok(None));
    }

    #[test]
    fn gkeyfile_quotes_do_not_escape_or_remove_hashes() {
        let root = Root::new("gkeyfile-quotes");
        for value in ["\"ops#1\"", "'ops#1'", "ops # trailing text"] {
            let path = root.put(
                "etc/lightdm/lightdm.conf",
                &format!("[Seat:*]\nautologin-user={value}\n"),
            );
            assert_eq!(root.source("lightdm", value), Ok(Some(path)), "{value}");
            assert_eq!(root.source("lightdm", "ops"), Ok(None), "{value}");
            assert_eq!(root.source("lightdm", "ops#1"), Ok(None), "{value}");
        }
    }

    #[test]
    fn lightdm_assignments_keep_hashes_for_remote_boolean_consumers() {
        let parsed =
            assignments("[XDMCPServer]\nenabled=true # literal\n[VNCServer]\nenabled=true\n")
                .unwrap();
        assert_eq!(parsed[0].2, "true # literal");
        assert!(!on(&parsed[0].2));
        assert!(on(&parsed[1].2));
    }

    #[test]
    fn sddm_quotes_are_literal_and_do_not_protect_hashes() {
        let root = Root::new("sddm-hash");
        for (value, expected) in [
            ("ops#1", "ops"),
            ("\"ops#1\"", "\"ops"),
            ("'ops#1'", "'ops"),
            ("ops\\#1", "ops\\"),
            ("\"alice\"", "\"alice\""),
        ] {
            let path = root.put("etc/sddm.conf", &format!("[Autologin]\nUser={value}\n"));
            assert_eq!(root.source("sddm", expected), Ok(Some(path)), "{value}");
            assert_eq!(root.source("sddm", "ops#1"), Ok(None), "{value}");
            assert_eq!(root.source("sddm", "alice"), Ok(None), "{value}");
        }
    }

    #[test]
    fn ly_escaped_hash_is_a_value_but_quotes_are_literal() {
        let root = Root::new("ly-hash");
        for (value, expected) in [
            ("ops\\#1", "ops#1"),
            ("ops#1", "ops"),
            ("\"ops#1\"", "\"ops"),
            ("\"ops\\#1\"", "\"ops#1\""),
        ] {
            let path = root.put("etc/ly/config.ini", &format!("auto_login_user={value}\n"));
            assert_eq!(root.source("ly", expected), Ok(Some(path)), "{value}");
        }
    }

    #[test]
    fn qt_order_sensitive_autologin_is_unknown_without_daemon_collation() {
        let root = Root::new("qt-order");
        for dm in ["sddm", "plasmalogin"] {
            root.put(
                &format!("etc/{dm}.conf.d/Z.conf"),
                "[Autologin]\nUser=alice\n",
            );
            root.put(
                &format!("etc/{dm}.conf.d/a.conf"),
                "[Autologin]\nUser=bob\n",
            );
            assert!(root.source(dm, "alice").is_err(), "{dm}");
            assert!(root.source(dm, "bob").is_err(), "{dm}");
            assert_eq!(root.source(dm, "carol"), Ok(None));
            // The main file decides irrespective of the drop-in comparator.
            let main = root.put(&format!("etc/{dm}.conf"), "[Autologin]\nUser=alice\n");
            assert_eq!(root.source(dm, "alice"), Ok(Some(main)));
            assert_eq!(root.source(dm, "bob"), Ok(None));
        }
    }

    #[test]
    fn qt_order_independent_layers_and_hidden_files() {
        let root = Root::new("qt-layers");
        for dm in ["sddm", "plasmalogin"] {
            root.put(
                &format!("etc/{dm}.conf.d/.hidden"),
                "[Autologin]\nUser=alice\n",
            );
            assert_eq!(
                root.source(dm, "alice"),
                Ok(None),
                "Qt excludes hidden files"
            );
            root.put(
                &format!("usr/lib/{dm}/{dm}.conf.d/Z.conf"),
                "[Autologin]\nUser=alice\n",
            );
            root.put(
                &format!("usr/lib/{dm}/{dm}.conf.d/a.conf"),
                "[Autologin]\nUser=bob\n",
            );
            let admin = root.put(
                &format!("etc/{dm}.conf.d/one.conf"),
                "[Autologin]\nUser=carol\n",
            );
            assert_eq!(root.source(dm, "carol"), Ok(Some(admin)));
            assert_eq!(root.source(dm, "alice"), Ok(None));
            root.put(
                &format!("etc/{dm}.conf.d/two.conf"),
                "[Autologin]\nUser=carol\n",
            );
            assert!(root.source(dm, "carol").unwrap().is_some());
        }
    }

    #[test]
    fn plasma_inline_hash_needs_a_parser_version() {
        let root = Root::new("plasma-parser");
        root.put("etc/plasmalogin.conf", "[Autologin]\nUser=ops#1\n");
        assert!(root.source("plasmalogin", "ops#1").is_err());
        assert!(root.source("plasmalogin", "ops").is_err());
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
        assert_eq!(root.source("sddm", "alice"), Ok(None));
        assert_eq!(root.source("sddm", "\"alice\""), Ok(Some(quoted)));
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
