// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Read the five scalar proc-map fields without splitting the pathname.
//! Provider installation directories may contain spaces. The explicit
//! deleted suffix remains a refusal in the loaded-as-hashed check.

pub(super) struct Mapping<'a> {
    pub(super) inode: &'a str,
    pub(super) path: &'a str,
    pub(super) deleted: bool,
    pub(super) executable: bool,
}

pub(super) fn mapping(line: &str) -> Option<Mapping<'_>> {
    let mut remaining = line.trim_start();
    let mut inode = "";
    let mut executable = false;
    for field in 0..5 {
        let end = remaining.find(char::is_whitespace)?;
        if field == 4 {
            inode = &remaining[..end];
        }
        if field == 1 {
            executable = remaining.as_bytes()[..end].get(2) == Some(&b'x');
        }
        remaining = remaining[end..].trim_start();
    }
    let remaining = remaining.trim_end();
    let (path, deleted) = remaining
        .strip_suffix(" (deleted)")
        .map_or((remaining, false), |path| (path, true));
    Some(Mapping {
        inode,
        path,
        deleted,
        executable,
    })
}
