// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bind Debian-family GDM's configuration to the selected installed executable.
//! The package database is administrator-owned authority, not an OS-name hint.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Program {
    Systemctl,
    DpkgQuery,
    Md5sum,
}

impl Program {
    fn path(self) -> Result<PathBuf, String> {
        if self == Self::Systemctl {
            return irlume_common::platform::SystemCommand::Systemctl
                .path()
                .ok_or_else(|| "systemctl is unavailable".into());
        }
        let name = match self {
            Self::DpkgQuery => "dpkg-query",
            Self::Md5sum => "md5sum",
            Self::Systemctl => unreachable!(),
        };
        ["/usr/bin", "/bin"]
            .into_iter()
            .map(|dir| Path::new(dir).join(name))
            .find(|path| {
                std::fs::metadata(path)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
            .ok_or_else(|| format!("{name} is unavailable"))
    }
}

const UNIT_ARGS: &[&str] = &[
    "--system",
    "--no-pager",
    "--no-ask-password",
    "show",
    "display-manager.service",
    "--property=Id",
    "--property=LoadState",
    "--property=ExecStart",
];
const STATUS_FORMAT: &str =
    "${binary:Package}\n${db:Status-Status}\n${db:Status-Eflag}\n${source:Package}\n${Version}\n";

/// None means the selected unit does not execute Debian-family gdm3. An error
/// means it could not be established, and must never select a candidate file.
pub(super) fn custom_conf(root: &Path) -> Result<Option<PathBuf>, String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    observe(root, |program, args| {
        let mut command = Command::new(program.path()?);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("LANGUAGE", "C")
            .env("DPKG_COLORS", "never");
        let output = irlume_common::process::output_until(&mut command, deadline)
            .map_err(|e| format!("GDM package observation failed: {e}"))?;
        if !output.status.success() {
            return Err("GDM package observation command failed".into());
        }
        String::from_utf8(output.stdout).map_err(|_| "invalid GDM package observation text".into())
    })
}

pub(super) fn observe(
    root: &Path,
    mut run: impl FnMut(Program, &[String]) -> Result<String, String>,
) -> Result<Option<PathBuf>, String> {
    let unit_args: Vec<String> = UNIT_ARGS.iter().map(|s| (*s).into()).collect();
    let unit = run(Program::Systemctl, &unit_args)?;
    let executable = unit_executable(&unit)?;
    if executable != "/usr/sbin/gdm3" {
        return Ok(None);
    }
    let image = root.join("usr/sbin/gdm3");
    let before = image_signature(&image)?;
    let admin = format!("--admindir={}", root.join("var/lib/dpkg").display());
    let query = |tail: &[&str]| {
        std::iter::once(admin.clone())
            .chain(std::iter::once("--no-pager".into()))
            .chain(tail.iter().map(|s| (*s).into()))
            .collect::<Vec<String>>()
    };
    let owner_args = query(&["--search", executable]);
    let owner_text = run(Program::DpkgQuery, &owner_args)?;
    let owner = executable_owner(&owner_text, executable)?;
    let status_args = query(&["--show", &format!("--showformat={STATUS_FORMAT}"), owner]);
    let status = run(Program::DpkgQuery, &status_args)?;
    installed_package(&status, owner)?;
    let conffile_args = query(&["--control-show", owner, "conffiles"]);
    let conffiles = run(Program::DpkgQuery, &conffile_args)?;
    let selected = active_conffile(&conffiles)?;
    let sums_args = query(&["--control-show", owner, "md5sums"]);
    let sums = run(Program::DpkgQuery, &sums_args)?;
    let expected = executable_checksum(&sums)?;
    let actual = run(
        Program::Md5sum,
        &[
            "--zero".into(),
            "--".into(),
            image.to_string_lossy().into_owned(),
        ],
    )?;
    let expected_output = format!("{expected}  {}\0", image.display());
    if actual != expected_output {
        return Err("selected GDM executable differs from its installed package".into());
    }
    // Reject replacement, upgrades and unit changes during the observation.
    if image_signature(&image)? != before
        || run(Program::Systemctl, &unit_args)? != unit
        || run(Program::DpkgQuery, &owner_args)? != owner_text
        || run(Program::DpkgQuery, &status_args)? != status
        || run(Program::DpkgQuery, &conffile_args)? != conffiles
        || run(Program::DpkgQuery, &sums_args)? != sums
    {
        return Err("GDM installation changed during configuration selection".into());
    }
    Ok(Some(root.join(selected.trim_start_matches('/'))))
}

fn unit_executable(text: &str) -> Result<&str, String> {
    let mut fields = std::collections::HashMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("invalid GDM unit observation")?;
        if !matches!(key, "Id" | "LoadState" | "ExecStart") || fields.insert(key, value).is_some() {
            return Err("invalid GDM unit observation".into());
        }
    }
    if !matches!(fields.get("Id"), Some(&"gdm.service" | &"gdm3.service"))
        || fields.get("LoadState") != Some(&"loaded")
    {
        return Err("selected display-manager unit is not loaded GDM".into());
    }
    let start = fields.get("ExecStart").ok_or("GDM unit has no ExecStart")?;
    let (path, rest) = start
        .strip_prefix("{ path=")
        .and_then(|s| s.split_once(" ; argv[]="))
        .ok_or("unsupported GDM ExecStart")?;
    if !matches!(path, "/usr/sbin/gdm3" | "/usr/sbin/gdm" | "/usr/bin/gdm")
        || !rest.starts_with(&format!("{path} ; ignore_errors="))
        || !rest.ends_with(" }")
        || rest.contains("path=")
        || rest.contains('{')
        || rest.matches('}').count() != 1
    {
        return Err("unsupported GDM ExecStart".into());
    }
    Ok(path)
}

fn executable_owner<'a>(text: &'a str, executable: &str) -> Result<&'a str, String> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let (owner, path) = line
        .split_once(": ")
        .ok_or("no package owns the selected GDM executable")?;
    if path != executable
        || line.contains('\n')
        || !owner
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b":-".contains(&c))
        || owner.split(':').next() != Some("gdm3")
    {
        return Err("GDM executable ownership is ambiguous, diverted or unsupported".into());
    }
    Ok(owner)
}

fn installed_package(text: &str, owner: &str) -> Result<(), String> {
    let fields: Vec<&str> = text.lines().collect();
    if fields.len() != 5
        || fields[0] != owner
        || fields[1] != "installed"
        || fields[2] != "ok"
        || fields[3] != "gdm3"
        || fields[4].is_empty()
    {
        return Err("GDM package is not completely installed without errors".into());
    }
    Ok(())
}

fn active_conffile(text: &str) -> Result<&str, String> {
    let mut selected = None;
    for line in text.lines() {
        let line = line.trim_end();
        let (path, removed) = match line.strip_prefix("remove-on-upgrade") {
            Some(path) if path.starts_with(|c: char| c.is_ascii_whitespace()) => (
                path.trim_start_matches(|c: char| c.is_ascii_whitespace()),
                true,
            ),
            _ => (line, false),
        };
        if !path.starts_with('/') || path.contains(['\0', '\r']) {
            return Err("unsupported GDM conffiles record".into());
        }
        if !removed
            && matches!(path, "/etc/gdm3/daemon.conf" | "/etc/gdm3/custom.conf")
            && selected.replace(path).is_some()
        {
            return Err("GDM package declares ambiguous configuration files".into());
        }
    }
    selected.ok_or_else(|| "GDM package declares no supported active configuration file".into())
}

fn executable_checksum(text: &str) -> Result<&str, String> {
    let mut selected = None;
    for line in text.lines() {
        let Some((sum, path)) = line.split_once("  ") else {
            return Err("invalid GDM package checksum manifest".into());
        };
        if sum.len() != 32 || !sum.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid GDM package checksum manifest".into());
        }
        if path == "usr/sbin/gdm3" && selected.replace(sum).is_some() {
            return Err("duplicate GDM executable checksum".into());
        }
    }
    selected.ok_or_else(|| "GDM executable has no package checksum".into())
}

#[derive(PartialEq, Eq)]
struct ImageSignature {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn image_signature(path: &Path) -> Result<ImageSignature, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("GDM executable: {e}"))?;
    if !meta.is_file() || meta.len() > 16 * 1024 * 1024 || meta.permissions().mode() & 0o111 == 0 {
        return Err("GDM executable is not a supported regular executable".into());
    }
    Ok(ImageSignature {
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conffile_authority_excludes_removals_and_requires_one_active_path() {
        for (text, expected) in [
            (
                "/etc/gdm3/daemon.conf\n/etc/pam.d/gdm-password\n",
                "/etc/gdm3/daemon.conf",
            ),
            (
                "remove-on-upgrade /etc/gdm3/daemon.conf\n/etc/gdm3/custom.conf\n",
                "/etc/gdm3/custom.conf",
            ),
            (
                "remove-on-upgrade\t/etc/gdm3/custom.conf\n/etc/gdm3/daemon.conf\n",
                "/etc/gdm3/daemon.conf",
            ),
        ] {
            assert_eq!(active_conffile(text), Ok(expected), "{text:?}");
        }
        for text in [
            "",
            "/etc/gdm3/daemon.conf\n/etc/gdm3/custom.conf\n",
            "/etc/gdm3/custom.conf\n/etc/gdm3/custom.conf\n",
            "remove-on-upgrade /etc/gdm3/daemon.conf\n",
            "unknown-flag /etc/gdm3/daemon.conf\n",
            "/etc/gdm3/custom.conf remove-on-upgrade\n",
        ] {
            assert!(active_conffile(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn executable_ownership_does_not_accept_diversions_or_multiple_owners() {
        let path = "/usr/sbin/gdm3";
        assert_eq!(executable_owner("gdm3: /usr/sbin/gdm3\n", path), Ok("gdm3"));
        assert_eq!(
            executable_owner("gdm3:amd64: /usr/sbin/gdm3\n", path),
            Ok("gdm3:amd64")
        );
        for text in [
            "gdm3, replacement: /usr/sbin/gdm3\n",
            "local diversion from: /usr/sbin/gdm3\nlocal diversion to: /usr/sbin/gdm3.old\ngdm3: /usr/sbin/gdm3\n",
            "gdm3: /usr/sbin/not-gdm3\n",
            "replacement: /usr/sbin/gdm3\n",
            "gdm3: /usr/sbin/gdm3\ngdm3: /usr/sbin/gdm3\n",
        ] {
            assert!(executable_owner(text, path).is_err(), "{text:?}");
        }
    }

    #[test]
    fn retained_and_incomplete_package_records_are_not_installed_authority() {
        assert!(installed_package("gdm3\ninstalled\nok\ngdm3\n48.0-2\n", "gdm3").is_ok());
        for text in [
            "gdm3\nconfig-files\nok\ngdm3\n48.0-2\n",
            "gdm3\nhalf-configured\nok\ngdm3\n48.0-2\n",
            "gdm3\ninstalled\nreinstreq\ngdm3\n48.0-2\n",
            "gdm3\ninstalled\nok\nreplacement\n48.0-2\n",
            "gdm3\ninstalled\nok\ngdm3\n\n",
        ] {
            assert!(installed_package(text, "gdm3").is_err(), "{text:?}");
        }
    }

    #[test]
    fn selected_unit_must_name_one_plain_gdm_executable() {
        let unit = |start: &str| format!("Id=gdm.service\nLoadState=loaded\nExecStart={start}\n");
        assert_eq!(
            unit_executable(&unit(
                "{ path=/usr/sbin/gdm3 ; argv[]=/usr/sbin/gdm3 ; ignore_errors=no ; pid=42 ; }"
            )),
            Ok("/usr/sbin/gdm3")
        );
        for start in [
            "",
            "{ path=/usr/sbin/gdm3 ; argv[]=/usr/sbin/gdm3 --custom ; ignore_errors=no ; }",
            "{ path=/usr/local/sbin/gdm3 ; argv[]=/usr/local/sbin/gdm3 ; ignore_errors=no ; }",
            "{ path=/usr/sbin/gdm3 ; argv[]=/usr/sbin/gdm3 ; ignore_errors=no ; } { path=/bin/false ; }",
        ] {
            assert!(unit_executable(&unit(start)).is_err(), "{start}");
        }
    }
}
