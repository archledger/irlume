// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Conservative systemd disk-environment reader. This is not a snapshot of a
//! running process: EnvironmentFile is read by systemd at execution time.

use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_TEXT: u64 = 1024 * 1024;

fn whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn bare_cr(text: &str) -> bool {
    text.as_bytes()
        .iter()
        .enumerate()
        .any(|(i, c)| *c == b'\r' && text.as_bytes().get(i + 1) != Some(&b'\n'))
}

/// Regular files only, bounded even if a file grows while being read. Following
/// an envfile symlink is consistent with systemd. O_PATH pins its resolved
/// target without opening a device; reopen only a verified regular descriptor.
pub(super) fn read_text(path: &Path) -> Result<String, String> {
    read_text_with(path, || {})
}

fn read_text_with(path: &Path, after_pin: impl FnOnce()) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let read = || -> std::io::Result<String> {
        let target = std::fs::canonicalize(path)?;
        let pinned = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(target)?;
        if !pinned.metadata()?.is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        after_pin();
        let file = std::fs::File::open(super::fd_path(&pinned)?)?;
        let mut text = String::new();
        file.take(MAX_TEXT + 1).read_to_string(&mut text)?;
        if text.len() as u64 > MAX_TEXT || text.contains('\0') || bare_cr(&text) {
            return Err(std::io::Error::other(
                "invalid or oversized environment text",
            ));
        }
        Ok(text)
    };
    read().map_err(|e| format!("{}: {e}", super::terminal_safe(&path.display().to_string())))
}

/// Unit continuations insert a space; comment lines inside a continuation are
/// skipped. Envfile continuations use a different grammar (below).
fn service_lines(text: &str) -> Result<Vec<(String, String)>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.contains('\u{feff}') {
        return Err("unresolved BOM position in unit text".into());
    }
    let mut service = false;
    let mut pending = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim_start_matches(whitespace).starts_with(['#', ';']) {
            continue;
        }
        pending.push_str(line);
        if pending.chars().rev().take_while(|c| *c == '\\').count() % 2 == 1 {
            pending.pop();
            pending.push(' ');
            continue;
        }
        let line = pending.trim_matches(whitespace);
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err("malformed unit section header".into());
            }
            service = line == "[Service]";
        } else if service {
            if let Some((key, value)) = line.split_once('=') {
                out.push((
                    key.trim_matches(whitespace).into(),
                    value.trim_matches(whitespace).into(),
                ));
            }
        }
        pending.clear();
    }
    if service {
        if let Some((key, value)) = pending.trim_matches(whitespace).split_once('=') {
            out.push((
                key.trim_matches(whitespace).into(),
                value.trim_matches(whitespace).into(),
            ));
        }
    }
    Ok(out)
}

/// Decode unit words, not shell words: C escapes apply inside both quote kinds.
fn words(value: &str) -> Result<Vec<String>, String> {
    let mut chars = value.chars().peekable();
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escaped = match chars.next().ok_or("trailing unit escape")? {
                'a' => '\u{7}',
                'b' => '\u{8}',
                'f' => '\u{c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => '\u{b}',
                's' => ' ',
                '\\' => '\\',
                '"' => '"',
                '\'' => '\'',
                kind @ ('x' | 'u' | 'U' | '0'..='7') => {
                    let (radix, count, mut digits) = match kind {
                        'x' => (16, 2, String::new()),
                        'u' => (16, 4, String::new()),
                        'U' => (16, 8, String::new()),
                        n => (8, 2, n.to_string()),
                    };
                    for _ in 0..count {
                        digits.push(chars.next().ok_or("short unit escape")?);
                    }
                    // from_str_radix also accepts a leading '+', whereas
                    // systemd's unhexchar/unoctchar accept digits only.
                    if !digits.bytes().all(|b| {
                        if radix == 16 {
                            b.is_ascii_hexdigit()
                        } else {
                            matches!(b, b'0'..=b'7')
                        }
                    }) {
                        return Err("invalid digit in unit escape".into());
                    }
                    u32::from_str_radix(&digits, radix)
                        .ok()
                        // xNN and octal denote bytes, not Unicode scalars.
                        // Refuse non-ASCII byte escapes rather than re-encode
                        // their bytes as different UTF-8 path characters.
                        .filter(|n| !matches!(kind, 'x' | '0'..='7') || *n <= 0x7f)
                        .and_then(char::from_u32)
                        .filter(|c| *c != '\0')
                        .ok_or("invalid unit escape")?
                }
                _ => return Err("unsupported unit escape".into()),
            };
            word.push(escaped);
            started = true;
        } else if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if quote.is_none() && whitespace(c) {
            if started {
                out.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(c);
            started = true;
        }
    }
    if quote.is_some() {
        return Err("unterminated unit quote".into());
    }
    if started {
        out.push(word);
    }
    Ok(out)
}

// Only %% has no external context. Refuse other specifiers rather than guessing
// a host, credential, user, root-image or manager-dependent expansion.
fn specifiers(value: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '%' && chars.next() != Some('%') {
            return Err("unresolved systemd environment specifier".into());
        }
        out.push(c);
    }
    Ok(out)
}

#[cfg(test)]
pub(super) fn value(root: &Path, texts: &[String], var: &str) -> Result<Option<PathBuf>, String> {
    value_with(root, texts, var, |path, optional| {
        if optional
            && matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            Ok(None)
        } else {
            read_text(path).map(Some)
        }
    })
}

pub(super) const STORE_VARS: [&str; 4] = [
    "IRLUME_STATE_DIR",
    "IRLUME_KEYRING_DIR",
    "IRLUME_RECOVERY_DIR",
    "IRLUME_TEMPLATE_KEY_DIR",
];

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Disk {
    pub values: [Option<PathBuf>; 4],
    pub installed: bool,
    fingerprint: Vec<u8>,
}

/// Resolve every variable from the same unit texts and one read per envfile.
/// The digest includes all inputs, so revalidation detects a deployment even
/// when a changed file happens to select the same directories.
pub(super) fn snapshot(root: &Path) -> Result<Disk, String> {
    use sha2::{Digest, Sha256};
    let texts = super::unit_texts_under(root)?;
    let mut cache = std::collections::BTreeMap::new();
    let mut values = [None, None, None, None];
    for (index, var) in STORE_VARS.iter().enumerate() {
        values[index] = value_with(root, &texts, var, |path, optional| {
            if !cache.contains_key(path) {
                let text = if optional
                    && matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                {
                    None
                } else {
                    Some(read_text(path)?)
                };
                cache.insert(path.to_path_buf(), text);
            }
            let text = cache.get(path).cloned().flatten();
            if !optional && text.is_none() {
                return Err("required environment file is absent".into());
            }
            Ok(text)
        })?;
    }
    let bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(&(&texts, &cache)).map_err(|e| e.to_string())?);
    Ok(Disk {
        values,
        installed: !texts.is_empty(),
        fingerprint: Sha256::digest(&*bytes).to_vec(),
    })
}

fn value_with(
    root: &Path,
    texts: &[String],
    var: &str,
    mut read: impl FnMut(&Path, bool) -> Result<Option<String>, String>,
) -> Result<Option<PathBuf>, String> {
    let mut found = None;
    let mut files = Vec::new();
    let mut unsets = Vec::new();
    let mut passed = Vec::new();
    for text in texts {
        for (key, value) in service_lines(text)? {
            match key.as_str() {
                "Environment" => {
                    if value.is_empty() {
                        found = None;
                    }
                    for word in words(&value)? {
                        let word = specifiers(&word)?;
                        if let Some((name, value)) = word.split_once('=') {
                            if name == var {
                                found = Some(value.to_string());
                            }
                        }
                    }
                }
                "EnvironmentFile" => {
                    if value.is_empty() {
                        files.clear();
                    } else {
                        files.push(value);
                    }
                }
                "UnsetEnvironment" | "PassEnvironment" => {
                    let list = if key == "UnsetEnvironment" {
                        &mut unsets
                    } else {
                        &mut passed
                    };
                    if value.is_empty() {
                        list.clear();
                    }
                    for word in words(&value)? {
                        list.push(specifiers(&word)?);
                    }
                }
                _ => {}
            }
        }
    }
    for file in files {
        // EnvironmentFile is a single path, not a list of shell/unit words.
        let file = specifiers(&file)?;
        let (optional, name) = file
            .strip_prefix('-')
            .map_or((false, file.as_str()), |p| (true, p));
        if !name.starts_with('/') || name.contains(['*', '?', '[', ']', '\0']) {
            return Err("unresolved EnvironmentFile path or wildcard".into());
        }
        let path = root.join(name.trim_start_matches('/'));
        // Optional only excuses absence. An unreadable file could select a
        // store; unlike systemd's ignore_errors, the destructive guard refuses.
        if let Some(text) = read(&path, optional)? {
            if let Some(value) = env_file_value(&text, var)? {
                found = Some(value);
            }
        }
    }
    if unsets.iter().any(|unset| {
        unset == var
            || found
                .as_ref()
                .is_some_and(|v| *unset == format!("{var}={v}"))
    }) {
        return Ok(None);
    }
    if found.is_none() && passed.iter().any(|name| name == var) {
        return Err(format!("{var} is inherited from the service manager"));
    }
    found.map(|s| absolute(&s, var)).transpose()
}

pub(super) fn absolute(value: &str, var: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || value.chars().any(char::is_control)
        || path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(format!("{var} is not a resolved absolute directory"));
    }
    Ok(path)
}

/// Envfiles are not shell scripts: no substitutions, percent expansion or
/// inline comments. Quotes only start before the unquoted value starts.
fn env_file_value(text: &str, var: &str) -> Result<Option<String>, String> {
    if bare_cr(text) {
        return Err("bare carriage-return envfile lines are unresolved".into());
    }
    if text.chars().any(|c| {
        c == '\0'
            || c == '\u{feff}'
            || (0xfdd0..=0xfdef).contains(&(c as u32))
            || c as u32 & 0xffff >= 0xfffe
    }) {
        return Err("invalid character in environment file".into());
    }
    let mut chars = text.chars().peekable();
    let mut found = None;
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| whitespace(*c)) {
            chars.next();
        }
        if chars.peek().is_some_and(|c| matches!(c, '#' | ';')) {
            let mut escaped = false;
            for c in chars.by_ref() {
                if c == '\n' {
                    if escaped {
                        return Err(
                            "escaped envfile comment has different semantics before systemd 254"
                                .into(),
                        );
                    }
                    break;
                }
                escaped = c == '\\' && !escaped;
            }
            continue;
        }
        let mut key = String::new();
        let mut assignment = false;
        for c in chars.by_ref() {
            if c == '\n' {
                break;
            }
            if c == '=' {
                assignment = true;
                break;
            }
            key.push(c);
        }
        if !assignment {
            continue;
        }
        let mut value = String::new();
        let mut quote = None;
        let mut unquoted = false;
        let mut trailing = None;
        while let Some(c) = chars.next() {
            match quote {
                Some('\'') => {
                    if c == '\'' {
                        quote = None;
                    } else {
                        value.push(c);
                    }
                }
                Some('"') => {
                    if c == '"' {
                        quote = None;
                    } else if c == '\\' {
                        let next = chars.next().ok_or("trailing quoted envfile escape")?;
                        if next != '\n' {
                            if !matches!(next, '"' | '\\' | '$' | '`') {
                                value.push('\\');
                            }
                            value.push(next);
                        }
                    } else {
                        value.push(c);
                    }
                }
                _ => {
                    if c == '\n' {
                        break;
                    }
                    if !unquoted && matches!(c, '\'' | '"') {
                        quote = Some(c);
                    } else if c == '\\' {
                        let next = chars.next().ok_or("trailing envfile escape")?;
                        if next != '\n' {
                            value.push(next);
                        }
                        unquoted = true;
                        trailing = None;
                    } else if matches!(c, ' ' | '\t' | '\r') {
                        if unquoted {
                            trailing.get_or_insert(value.len());
                            value.push(c);
                        }
                    } else {
                        unquoted = true;
                        trailing = None;
                        value.push(c);
                    }
                }
            }
        }
        if quote.is_some() {
            return Err("unterminated environment file quote".into());
        }
        if let Some(at) = trailing {
            value.truncate(at);
        }
        if key.trim_end_matches(whitespace) == var {
            found = Some(value);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_review2_numeric_escapes_require_exact_ascii_digits() {
        for escape in [
            r"\u+0e9",
            r"\U+00000e9",
            r"\x+f",
            r"\0+7",
            r"\u0+e9",
            r"\U000+00e9",
            r"\u-0e9",
            r"\x-f",
            r"\08x",
            r"\u00g9",
        ] {
            let text = format!("[Service]\nEnvironment=IRLUME_KEYRING_DIR=/keys{escape}\n");
            assert!(
                value(Path::new("/"), &[text], "IRLUME_KEYRING_DIR").is_err(),
                "{escape}"
            );
            assert!(words(&format!("VAR={escape}")).is_err(), "{escape}");
        }
        assert_eq!(
            words(r"VAR=\u00e9\U000000e9\x2f\057\u002b\053 literal+plus").unwrap(),
            vec!["VAR=éé//++", "literal+plus"]
        );
    }

    #[test]
    fn environment_review_ambiguous_unit_headers_refuse() {
        for text in [
            "\u{feff}\u{feff}[Service]\nEnvironment=IRLUME_KEYRING_DIR=/wrong\n",
            "[Service] trailing\nEnvironment=IRLUME_KEYRING_DIR=/wrong\n",
            "# comment\n\u{feff}[Service]\nEnvironment=IRLUME_KEYRING_DIR=/wrong\n",
        ] {
            assert!(value(Path::new("/"), &[text.into()], "IRLUME_KEYRING_DIR").is_err());
        }
        assert_eq!(
            value(
                Path::new("/"),
                &["\u{feff}[Service]\nEnvironment=IRLUME_KEYRING_DIR=/right\n".into()],
                "IRLUME_KEYRING_DIR"
            )
            .unwrap(),
            Some("/right".into())
        );
    }

    #[test]
    fn environment_review_escaped_comment_refuses_version_ambiguous_assignments() {
        // v249 continues the comment; v254+ starts a new assignment. Refusal
        // is safe on both, without inferring the installed manager's version.
        for comment in ["# old", "; old"] {
            let text = format!("DIR=/old\n{comment}\\\nDIR=/new\n");
            assert!(env_file_value(&text, "DIR").is_err());
        }
        assert!(env_file_value("# comment\rDIR=/hidden\n", "DIR").is_err());
        assert_eq!(
            env_file_value("# comment\r\nDIR=/visible\r\n", "DIR").unwrap(),
            Some("/visible".into())
        );
        assert_eq!(
            env_file_value("DIR\u{a0}=/not-a-valid-name\n", "DIR").unwrap(),
            None
        );
    }

    #[test]
    fn environment_review_byte_escapes_are_not_unicode_scalars() {
        for text in [r"DIR=/caf\xc3\xa9", r"DIR=/caf\303\251", r"DIR=/bad\777"] {
            assert!(
                words(text).is_err(),
                "unsupported byte escape must refuse: {text}"
            );
        }
        assert_eq!(words(r"DIR=/caf\u00e9").unwrap(), vec!["DIR=/café"]);
    }

    #[test]
    fn environment_review_regular_file_is_pinned_before_replacement() {
        let dir = std::env::temp_dir().join(format!("irlume-review-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("env");
        std::fs::write(&path, "DIR=/original\n").unwrap();
        let result = read_text_with(&path, || {
            std::fs::rename(&path, dir.join("old")).unwrap();
            std::fs::write(&path, "DIR=/replacement\n").unwrap();
        });
        assert_eq!(result.unwrap(), "DIR=/original\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn environment_file_resets_optional_absence_and_unreadable_references() {
        let root =
            std::env::temp_dir().join(format!("irlume-envfile-resets-{}", std::process::id()));
        std::fs::create_dir_all(root.join("unreadable")).unwrap();
        std::fs::write(root.join("first"), "IRLUME_KEYRING_DIR=/first\n").unwrap();
        std::fs::write(root.join("last"), "IRLUME_KEYRING_DIR=/last\n").unwrap();
        let run = |text: &str| value(&root, &[format!("[Service]\n{text}")], "IRLUME_KEYRING_DIR");
        assert_eq!(run("EnvironmentFile=-/missing\n").unwrap(), None);
        assert!(run("EnvironmentFile=/missing\n").is_err());
        assert!(run("EnvironmentFile=-/unreadable\n").is_err());
        assert_eq!(run("EnvironmentFile=/unreadable\nEnvironmentFile=\nEnvironmentFile=/first\nEnvironmentFile=/last\nEnvironment=IRLUME_KEYRING_DIR=/inline\n").unwrap(), Some("/last".into()));
        assert_eq!(
            run("EnvironmentFile=/last\nUnsetEnvironment=IRLUME_KEYRING_DIR=/last\n").unwrap(),
            None
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn environment_unit_sections_continuations_escapes_and_unresolved_paths() {
        let run = |text: &str| value(Path::new("/"), &[text.into()], "IRLUME_KEYRING_DIR");
        assert_eq!(run("[Unit]\nEnvironment=IRLUME_KEYRING_DIR=/ignored\n[Service]\nEnvironment='IRLUME_KEYRING_DIR=/a\\x20b/%%' \\\n# intervening comment\nOTHER=1\n[Install]\nUnsetEnvironment=IRLUME_KEYRING_DIR\n").unwrap(), Some("/a b/%".into()));
        for text in [
            "Environment=IRLUME_KEYRING_DIR=%S/keys",
            "Environment=IRLUME_KEYRING_DIR=relative",
            "Environment=IRLUME_KEYRING_DIR=",
            "Environment=\"IRLUME_KEYRING_DIR=/unterminated",
            "EnvironmentFile=/some/*.env",
            "EnvironmentFile=\"/some/file\"",
            "PassEnvironment=IRLUME_KEYRING_DIR",
        ] {
            assert!(run(&format!("[Service]\n{text}\n")).is_err(), "{text}");
        }
        assert_eq!(
            run("[Service]\nPassEnvironment=IRLUME_KEYRING_DIR\nPassEnvironment=\n").unwrap(),
            None
        );
    }

    #[test]
    fn environment_file_values_preserve_shell_literals_and_multiline_quotes() {
        for (text, expected) in [
            ("DIR='a\nb'\n", "a\nb"),
            ("DIR=\"a\\\nb\\q\\$\\`\\\"\"\n", "ab\\q$`\""),
            ("DIR= a  b#c'$HOME'  \n", "a  b#c'$HOME'"),
            ("# comment\nDIR=/set\n", "/set"),
            ("ignored\n; comment\nDIR=first\nDIR=last", "last"),
        ] {
            assert_eq!(
                env_file_value(text, "DIR").unwrap().as_deref(),
                Some(expected),
                "{text:?}"
            );
        }
        assert!(env_file_value("DIR='unfinished", "DIR").is_err());
        assert!(env_file_value("DIR=/a\0other", "DIR").is_err());
    }
}
