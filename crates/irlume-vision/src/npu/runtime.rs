// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Provider-neutral administrator selection of a reviewed NPU runtime.

use super::CpuReason;
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Native loading requires a reviewed installation AND process-launch profile.
/// None has conformance evidence yet. File ownership, a reviewed C ABI name,
/// model certification and post-load hashes cannot authorize constructors.
/// Keep this closed until a separately reviewed profile covers loader search,
/// plugins/frontends/compiler/driver configuration, startup environment and
/// the binding's process-global first-provider lifetime. No environment or
/// machine setting may turn this refusal into an opt-in bypass.
pub(super) fn admit_loading() -> Result<(), CpuReason> {
    Err(CpuReason::LoadingNotAdmitted)
}

/// The administrator's `npu_library` value in machine settings.
#[derive(Clone, Copy, Debug)]
pub enum LibrarySetting<'a> {
    /// No settings file or no key; use standard system/source locations.
    Absent,
    /// The trimmed value, before validating the path.
    Value(&'a [u8]),
    /// The settings cannot represent one unambiguous value.
    Invalid,
    /// The settings file exists but cannot be read.
    Unreadable,
}

/// Read only `npu_library`. Duplicate keys and non-UTF-8 settings do not
/// silently select whichever provider happened to be first.
pub fn library_setting(bytes: &[u8]) -> LibrarySetting<'_> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return LibrarySetting::Invalid;
    };
    let mut value = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        // Recognize attempts at this exact key even when the assignment is
        // malformed. Unrelated keys with the same prefix remain unrelated.
        let key_token = line
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next();
        if key_token != Some("npu_library") {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            return LibrarySetting::Invalid;
        };
        if key.trim() != "npu_library" || value.is_some() {
            return LibrarySetting::Invalid;
        }
        value = Some(raw.trim().as_bytes());
    }
    value.map_or(LibrarySetting::Absent, LibrarySetting::Value)
}

/// Provider-independent runtime selection, read at daemon startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSelection {
    /// Search only the reviewed standard system and source-install roots.
    Automatic,
    /// One administrator-selected absolute library file.
    Library(PathBuf),
    /// An invalid authoritative selection; do not choose another provider.
    Rejected(&'static str),
}

impl RuntimeSelection {
    /// Read the administrator's environment override first, then machine
    /// settings. Invalid explicit values remain a refusal, not automatic.
    pub fn read(env: Option<&OsStr>, setting: LibrarySetting<'_>) -> Self {
        if let Some(env) = env {
            return env.to_str().map_or(
                Self::Rejected("the NPU library selection is not UTF-8"),
                Self::path,
            );
        }
        match setting {
            LibrarySetting::Absent => Self::Automatic,
            LibrarySetting::Value(bytes) => std::str::from_utf8(bytes).map_or(
                Self::Rejected("the NPU library selection is not UTF-8"),
                Self::path,
            ),
            LibrarySetting::Invalid => Self::Rejected("the NPU library settings are ambiguous"),
            LibrarySetting::Unreadable => Self::Rejected("the NPU library settings are unreadable"),
        }
    }

    fn path(value: &str) -> Self {
        let value = value.trim();
        if value.is_empty() || value.len() > 4096 || value.contains('\0') {
            return Self::Rejected("the NPU library selection is empty or invalid");
        }
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Self::Rejected("the NPU library selection must be absolute");
        }
        Self::Library(path)
    }
}

pub(super) struct Trust {
    owner: u32,
    boundary: PathBuf,
}

impl Default for Trust {
    fn default() -> Self {
        Self {
            owner: 0,
            boundary: PathBuf::from("/"),
        }
    }
}

fn trusted_metadata(owner: u32, mode: u32, expected: u32) -> bool {
    owner == expected && mode & 0o022 == 0
}

fn trusted_path(path: &Path, trust: &Trust) -> Result<(), CpuReason> {
    let refuse = || {
        CpuReason::IdentityUnreadable(
        "the NPU runtime must be in an administrator-owned installation without group/other writes".into(),
    )
    };
    if !path.is_absolute() || !path.starts_with(&trust.boundary) {
        return Err(refuse());
    }
    let boundary = fs::symlink_metadata(&trust.boundary).map_err(|_| refuse())?;
    if !boundary.is_dir() || !trusted_metadata(boundary.uid(), boundary.mode(), trust.owner) {
        return Err(refuse());
    }
    let mut resolved = trust.boundary.clone();
    let mut pending: VecDeque<_> = path
        .strip_prefix(&trust.boundary)
        .map_err(|_| refuse())?
        .components()
        .map(|part| part.as_os_str().to_owned())
        .collect();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            if resolved == trust.boundary || !resolved.pop() {
                return Err(refuse());
            }
            continue;
        }
        let next = resolved.join(part);
        let metadata = fs::symlink_metadata(&next).map_err(|_| refuse())?;
        if metadata.file_type().is_symlink() {
            links += 1;
            if metadata.uid() != trust.owner || links > 40 {
                return Err(refuse());
            }
            // Resolve one hop at a time: metadata/canonicalize on the full
            // path would skip intermediate link names and directories.
            // Relative targets and '..' start at this resolved parent.
            let target = fs::read_link(&next).map_err(|_| refuse())?;
            let remaining = if target.is_absolute() {
                resolved.clone_from(&trust.boundary);
                target.strip_prefix(&trust.boundary).map_err(|_| refuse())?
            } else {
                target.as_path()
            };
            for component in remaining.components().rev() {
                pending.push_front(component.as_os_str().to_owned());
            }
        } else {
            if !trusted_metadata(metadata.uid(), metadata.mode(), trust.owner)
                || (!pending.is_empty() && !metadata.is_dir())
            {
                return Err(refuse());
            }
            resolved = next;
        }
    }
    Ok(())
}

fn reviewed_name(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| {
            super::REVIEWED_OPENVINO_C_SONAMES.contains(&name)
                || matches!(
                    name,
                    "libopenvino_c.so.2026.2.0" | "libopenvino_c.so.2026.2.1"
                )
        })
}

fn validate_file(path: &Path, trust: &Trust) -> Result<PathBuf, CpuReason> {
    let canonical = path.canonicalize().map_err(|_| {
        CpuReason::RuntimeAbsent("the selected NPU C API library is absent or unreadable".into())
    })?;
    if !reviewed_name(&canonical) || !canonical.is_file() {
        return Err(CpuReason::RuntimeAbsent(
            "the selected NPU C API version has not been reviewed".into(),
        ));
    }
    trusted_path(path, trust)?;
    trusted_path(&canonical, trust)?;
    fs::File::open(&canonical).map_err(|_| {
        CpuReason::RuntimeAbsent("the selected NPU C API library cannot be read".into())
    })?;
    Ok(canonical)
}

fn resolve_selected(
    selection: &RuntimeSelection,
    dirs: &[&str],
    trust: &Trust,
) -> Result<PathBuf, CpuReason> {
    match selection {
        RuntimeSelection::Library(path) => validate_file(path, trust).map(|_| path.clone()),
        RuntimeSelection::Rejected(reason) => Err(CpuReason::IdentityUnreadable((*reason).into())),
        RuntimeSelection::Automatic => {
            for soname in super::REVIEWED_OPENVINO_C_SONAMES {
                for dir in dirs {
                    let path = Path::new(dir).join(soname);
                    // Only absence licenses trying another standard location.
                    // An existing untrusted selection fails rather than hides.
                    if !path.is_absolute() {
                        return Err(CpuReason::IdentityUnreadable(
                            "the NPU search directory must be absolute".into(),
                        ));
                    }
                    match fs::symlink_metadata(&path) {
                        Ok(_) => return validate_file(&path, trust).map(|_| path),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => {
                            return Err(CpuReason::IdentityUnreadable(format!(
                                "NPU library lookup {}: {error}",
                                path.display()
                            )))
                        }
                    }
                }
            }
            Err(CpuReason::RuntimeAbsent("no reviewed NPU C API library is installed in the standard system/source locations".into()))
        }
    }
}

#[derive(Debug)]
pub(super) struct ResolvedLibrary {
    pub canonical: PathBuf,
    pub selected: PathBuf,
}

pub(super) fn resolve_library(
    selection: &RuntimeSelection,
    dirs: &[&str],
    trust: &Trust,
) -> Result<ResolvedLibrary, CpuReason> {
    let selected = resolve_selected(selection, dirs, trust)?;
    let canonical = validate_file(&selected, trust)?;
    Ok(ResolvedLibrary {
        selected,
        canonical,
    })
}

#[cfg(test)]
fn resolve(
    selection: &RuntimeSelection,
    dirs: &[&str],
    trust: &Trust,
) -> Result<PathBuf, CpuReason> {
    resolve_library(selection, dirs, trust).map(|library| library.canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    #[test]
    fn absent_selection_is_automatic_and_environment_selects_any_provider() {
        assert_eq!(
            RuntimeSelection::read(None, LibrarySetting::Absent),
            RuntimeSelection::Automatic
        );
        assert_eq!(
            RuntimeSelection::read(
                Some(OsStr::new(
                    "/opt/upstream/runtime/lib/libopenvino_c.so.2621"
                )),
                LibrarySetting::Value(b"/usr/lib64/libopenvino_c.so.2620")
            ),
            RuntimeSelection::Library("/opt/upstream/runtime/lib/libopenvino_c.so.2621".into())
        );
    }

    #[test]
    fn invalid_explicit_values_do_not_turn_into_automatic_discovery() {
        for value in ["", "   ", "relative/libopenvino_c.so.2621", "/opt/lib\0.so"] {
            assert!(matches!(
                RuntimeSelection::read(Some(OsStr::new(value)), LibrarySetting::Absent),
                RuntimeSelection::Rejected(_)
            ));
        }
        let bad = OsString::from_vec(vec![0xff]);
        assert!(matches!(
            RuntimeSelection::read(Some(&bad), LibrarySetting::Absent),
            RuntimeSelection::Rejected(_)
        ));
    }

    #[test]
    fn machine_settings_preserve_absence_and_reject_ambiguity_or_unknown_reads() {
        assert!(matches!(
            library_setting(b"npu=on\n# a comment\n"),
            LibrarySetting::Absent
        ));
        assert!(matches!(
            library_setting(b" npu_library = /opt/provider/libopenvino_c.so.2621\n"),
            LibrarySetting::Value(b"/opt/provider/libopenvino_c.so.2621")
        ));
        assert!(matches!(
            library_setting(b"npu_library=/one\nnpu_library=/two\n"),
            LibrarySetting::Invalid
        ));
        assert!(matches!(
            RuntimeSelection::read(None, LibrarySetting::Unreadable),
            RuntimeSelection::Rejected(_)
        ));
    }

    fn fixture() -> (tempfile::TempDir, Trust) {
        let directory = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(directory.path()).unwrap().uid();
        let trust = Trust {
            owner,
            boundary: directory.path().to_path_buf(),
        };
        (directory, trust)
    }

    #[test]
    fn malformed_exact_library_keys_refuse_automatic_selection() {
        for line in [
            "npu_library",
            "npu_library: /opt/provider/libopenvino_c.so.2621",
            "npu_library /opt/provider/libopenvino_c.so.2621",
            "npu_library : = /opt/provider/libopenvino_c.so.2621",
        ] {
            for text in [line.to_owned(), format!("npu_library=/one\n{line}\n")] {
                let setting = library_setting(text.as_bytes());
                assert!(
                    matches!(
                        RuntimeSelection::read(None, setting),
                        RuntimeSelection::Rejected(_)
                    ),
                    "{text}"
                );
                assert_eq!(
                    RuntimeSelection::read(Some(OsStr::new("/override")), setting),
                    RuntimeSelection::Library("/override".into())
                );
            }
        }
        assert!(matches!(
            library_setting(b"npu_library_extra=x\n# npu_library\nnpu=on"),
            LibrarySetting::Absent
        ));
    }

    #[test]
    fn automatic_lookup_refuses_nonabsence_errors_before_lower_candidates() {
        let (directory, trust) = fixture();
        let loop_dir = directory.path().join("loop");
        symlink("loop", &loop_dir).unwrap();
        let good = directory.path().join("good");
        fs::create_dir(&good).unwrap();
        fs::write(good.join("libopenvino_c.so.2621"), b"fixture").unwrap();
        let error = fs::symlink_metadata(loop_dir.join("libopenvino_c.so.2621")).unwrap_err();
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(resolve(
            &RuntimeSelection::Automatic,
            &[loop_dir.to_str().unwrap(), good.to_str().unwrap()],
            &trust
        )
        .is_err());
        let missing = directory.path().join("missing");
        assert_eq!(
            resolve(
                &RuntimeSelection::Automatic,
                &[missing.to_str().unwrap(), good.to_str().unwrap()],
                &trust
            )
            .unwrap(),
            good.join("libopenvino_c.so.2621")
        );
    }

    #[test]
    fn unchanged_legacy_alias_keeps_exact_identity_and_canonical_load_path() {
        let (directory, trust) = fixture();
        let target = directory.path().join("libopenvino_c.so.2026.2.0");
        fs::write(&target, b"fixture").unwrap();
        let alias = directory.path().join("libopenvino_c.so.2620");
        symlink(&target, &alias).unwrap();
        let resolved = resolve_library(
            &RuntimeSelection::Automatic,
            &[directory.path().to_str().unwrap()],
            &trust,
        )
        .unwrap();
        let legacy = super::super::Identity {
            library: alias.display().to_string(),
            openvino_build: "build".into(),
            npu_plugin: "plugin".into(),
            driver_version: "driver".into(),
            compiler_version: "compiler".into(),
            architecture: "arch".into(),
            pci_id: "8086:643e".into(),
            firmware: "firmware".into(),
            configuration: super::super::COMPILE_CONFIGURATION.into(),
            libraries: "manifest".into(),
        };
        let mut discovered = legacy.clone();
        discovered.library = resolved.selected.display().to_string();
        assert_eq!(resolved.canonical, target);
        assert_eq!(legacy.digest(), discovered.digest());
    }

    #[test]
    fn an_explicit_reviewed_source_install_and_trusted_alias_resolve() {
        let (directory, trust) = fixture();
        let target = directory.path().join("libopenvino_c.so.2026.2.1");
        std::fs::write(&target, b"fixture").unwrap();
        let alias = directory.path().join("libopenvino_c.so.2621");
        symlink(&target, &alias).unwrap();
        assert_eq!(
            resolve(&RuntimeSelection::Library(alias), &[], &trust).unwrap(),
            target
        );
    }

    #[test]
    fn a_bad_explicit_install_never_chooses_another_present_runtime() {
        let (directory, trust) = fixture();
        let available = directory.path().join("libopenvino_c.so.2621");
        std::fs::write(available, b"fixture").unwrap();
        let missing =
            RuntimeSelection::Library(directory.path().join("missing/libopenvino_c.so.2621"));
        assert!(resolve(&missing, &[directory.path().to_str().unwrap()], &trust).is_err());
        let future = directory.path().join("libopenvino_c.so.9999");
        std::fs::write(&future, b"fixture").unwrap();
        assert!(resolve(&RuntimeSelection::Library(future), &[], &trust).is_err());
    }

    #[test]
    fn writable_files_or_ancestors_and_untrusted_alias_targets_are_refused() {
        let (directory, trust) = fixture();
        let file = directory.path().join("libopenvino_c.so.2621");
        std::fs::write(&file, b"fixture").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(resolve(&RuntimeSelection::Library(file.clone()), &[], &trust).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolve(&RuntimeSelection::Library(file), &[], &trust).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("libopenvino_c.so.2621");
        std::fs::write(&target, b"fixture").unwrap();
        let alias = directory.path().join("libopenvino_c.so.2621");
        std::fs::remove_file(&alias).unwrap();
        symlink(target, &alias).unwrap();
        assert!(resolve(&RuntimeSelection::Library(alias), &[], &trust).is_err());
    }

    #[test]
    fn library_alias_chain_validates_every_absolute_and_relative_hop() {
        for relative in [false, true] {
            let (directory, trust) = fixture();
            let secure = directory.path().join("secure");
            let intermediate = directory.path().join("intermediate");
            fs::create_dir(&secure).unwrap();
            fs::create_dir(&intermediate).unwrap();
            let file = secure.join("libopenvino_c.so.2026.2.1");
            fs::write(&file, b"fixture").unwrap();
            let hop = intermediate.join("alias");
            let selected = secure.join("libopenvino_c.so.2621");
            if relative {
                symlink("../secure/libopenvino_c.so.2026.2.1", &hop).unwrap();
                symlink("../intermediate/alias", &selected).unwrap();
            } else {
                symlink(&file, &hop).unwrap();
                symlink(&hop, &selected).unwrap();
            }
            let selection = RuntimeSelection::Library(selected);
            assert_eq!(resolve(&selection, &[], &trust).unwrap(), file);
            fs::set_permissions(&intermediate, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(resolve(&selection, &[], &trust).is_err());
            fs::set_permissions(&intermediate, fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(resolve(&selection, &[], &trust).unwrap(), file);
        }
    }

    #[test]
    fn directory_alias_chain_is_validated_before_remaining_components() {
        let (directory, trust) = fixture();
        let runtime = directory.path().join("runtime");
        let intermediate = directory.path().join("intermediate");
        fs::create_dir(&runtime).unwrap();
        fs::create_dir(&intermediate).unwrap();
        let file = runtime.join("libopenvino_c.so.2621");
        fs::write(&file, b"fixture").unwrap();
        let hop = intermediate.join("directory");
        symlink(&runtime, &hop).unwrap();
        let selected = directory.path().join("selected");
        symlink(&hop, &selected).unwrap();
        let selection = RuntimeSelection::Library(selected.join("libopenvino_c.so.2621"));
        assert_eq!(resolve(&selection, &[], &trust).unwrap(), file);
        fs::set_permissions(&intermediate, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(resolve(&selection, &[], &trust).is_err());
    }

    #[test]
    fn alias_hops_cannot_leave_the_trust_boundary_and_return() {
        let (directory, trust) = fixture();
        let outside = tempfile::tempdir().unwrap();
        let file = directory.path().join("libopenvino_c.so.2026.2.1");
        fs::write(&file, b"fixture").unwrap();
        let hop = outside.path().join("alias");
        symlink(&file, &hop).unwrap();
        let selected = directory.path().join("libopenvino_c.so.2621");
        symlink(hop, &selected).unwrap();
        assert!(resolve(&RuntimeSelection::Library(selected), &[], &trust).is_err());
    }

    #[test]
    fn parent_components_follow_resolved_directory_aliases() {
        let (directory, trust) = fixture();
        let installation = directory.path().join("installation");
        fs::create_dir(&installation).unwrap();
        fs::create_dir(installation.join("lib")).unwrap();
        let file = installation.join("libopenvino_c.so.2621");
        fs::write(&file, b"fixture").unwrap();
        let alias = directory.path().join("current");
        symlink("installation/lib", &alias).unwrap();
        let selection = RuntimeSelection::Library(alias.join("../libopenvino_c.so.2621"));
        assert_eq!(resolve(&selection, &[], &trust).unwrap(), file);
        fs::set_permissions(installation.join("lib"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolve(&selection, &[], &trust).is_err());
    }

    #[test]
    fn cyclic_missing_and_non_directory_alias_paths_are_refused() {
        let (directory, trust) = fixture();
        let selected = directory.path().join("libopenvino_c.so.2621");
        symlink("cycle", &selected).unwrap();
        symlink("libopenvino_c.so.2621", directory.path().join("cycle")).unwrap();
        assert!(resolve(&RuntimeSelection::Library(selected.clone()), &[], &trust).is_err());
        fs::remove_file(&selected).unwrap();
        symlink("missing", &selected).unwrap();
        assert!(resolve(&RuntimeSelection::Library(selected.clone()), &[], &trust).is_err());
        fs::remove_file(&selected).unwrap();
        fs::write(&selected, b"fixture").unwrap();
        assert!(resolve(
            &RuntimeSelection::Library(selected.join("../libopenvino_c.so.2621")),
            &[],
            &trust
        )
        .is_err());
    }

    #[test]
    fn administrator_ownership_is_required_independent_of_provider_name() {
        assert!(trusted_metadata(0, 0o755, 0));
        assert!(!trusted_metadata(1000, 0o755, 0));
        assert!(!trusted_metadata(0, 0o775, 0));
        assert!(!trusted_metadata(0, 0o777, 0));
    }
}
