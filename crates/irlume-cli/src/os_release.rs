// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The host's os-release file (os-release(5)), for every CLI path that
//! depends on the distribution: the NixOS checks in [`crate::nixos`] and the
//! release upgrade notices in [`crate::upgrade_notice`]. One file order, one
//! override and one parser, so the two can never disagree about the host.

/// Redirects the os-release file, for tests (docs/DEVELOPMENT.md "Sandbox
/// environment overrides").
pub(crate) const OS_RELEASE_ENV: &str = "IRLUME_OS_RELEASE";

/// This host's os-release text: the file `IRLUME_OS_RELEASE` names when set,
/// else `/etc/os-release`, then `/usr/lib/os-release` (os-release(5)).
///
/// # Errors
/// No such file can be read. A caller decides what an unknown release means.
pub(crate) fn read_host() -> std::io::Result<String> {
    match std::env::var_os(OS_RELEASE_ENV) {
        Some(path) => std::fs::read_to_string(path),
        None => std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release")),
    }
}

/// The value of `key` in os-release text. Values may be bare or quoted; as
/// in the shell syntax the format follows, a later assignment wins. `Err`
/// for a value that is empty or quoted on one side only.
pub(crate) fn field<'a>(os_release: &'a str, key: &str) -> Option<Result<&'a str, ()>> {
    os_release.lines().rev().find_map(|line| {
        let (name, value) = line.trim().split_once('=')?;
        if name != key {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        let quotes: &[char] = &['"', '\''];
        Some(
            if value.is_empty() || value.starts_with(quotes) || value.ends_with(quotes) {
                Err(())
            } else {
                Ok(value)
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEDORA_44: &str = "NAME=\"Fedora Linux\"\nVERSION=\"44 (Workstation Edition)\"\n\
                             ID=fedora\nVERSION_ID=44\nPLATFORM_ID=\"platform:f44\"\n\
                             VARIANT_ID=workstation\n";

    #[test]
    fn keys_match_whole_names_and_a_later_assignment_wins() {
        // VERSION_ID and PLATFORM_ID end in ID but are other keys.
        assert_eq!(field(FEDORA_44, "ID"), Some(Ok("fedora")));
        assert_eq!(field(FEDORA_44, "VERSION_ID"), Some(Ok("44")));
        assert_eq!(field("ID=debian\nID=fedora\n", "ID"), Some(Ok("fedora")));
        assert_eq!(field("# ID=fedora\n", "ID"), None);
    }

    #[test]
    fn quotes_are_stripped_and_an_empty_or_unbalanced_value_is_an_error() {
        for text in [
            "ID=nixos\n",
            "ID=\"nixos\"\n",
            "ID='nixos'\n",
            "  ID=nixos  \n",
        ] {
            assert_eq!(field(text, "ID"), Some(Ok("nixos")), "{text:?}");
        }
        for text in [
            "ID=\n",
            "ID=\"\"\n",
            "ID=\"nixos\n",
            "ID=nixos'\n",
            "ID=\"\n",
        ] {
            assert_eq!(field(text, "ID"), Some(Err(())), "{text:?}");
        }
        // A malformed later assignment still wins over a good earlier one.
        assert_eq!(field("ID=nixos\nID=\"\n", "ID"), Some(Err(())));
    }
}
