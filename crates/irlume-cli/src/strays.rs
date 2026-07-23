// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Doctor check: stray files sitting next to the managed irlume binaries, and
//! hand-installed builds overlaying the packaged ones.
//!
//! Both come from the same workflow: installing a dev/branch build over a
//! package install, with a `cp irlume irlume.bak`-style backup first. The
//! backups accumulate (they outlive every later package update), and a stale
//! copy of `pam_irlume.so` sitting in the PAM module directory invites "which
//! module is actually loaded?" confusion during auth debugging. The overlay is
//! the dangerous half: the next package update silently replaces the
//! hand-installed binary, which has bitten this project before.
//!
//! Report-only by design. Deleting files the package manager does not own is
//! how backups made on purpose get destroyed; doctor names them and lets the
//! admin decide.

use crate::commands::InstallOrigin;

/// Where the managed binaries live. Deliberately NOT the running exe's
/// directory: a dev running `target/release/irlume doctor` would otherwise see
/// every cargo artifact next to the binary as a stray.
const BIN_DIRS: &[&str] = &["/usr/bin", "/usr/local/bin"];

/// PAM module directories across the packaged distro families (same list the
/// uninstaller sweeps).
const PAM_DIRS: &[&str] = &[
    "/usr/lib/security",
    "/usr/lib64/security",
    "/lib/security",
    "/lib/x86_64-linux-gnu/security",
];

/// Print doctor lines for stray irlume-named files and overlaid managed
/// binaries. Silent when everything is clean (matching the wiring-drift
/// check: doctor stays quiet unless something needs attention).
pub fn report(origin: &InstallOrigin) {
    report_strays();
    report_overlay(origin);
}

/// Stray = a file whose name starts with an irlume prefix, in a directory we
/// manage files in, that is not one of the managed names themselves and that
/// no package owns.
fn report_strays() {
    let mut strays: Vec<String> = Vec::new();
    for dir in BIN_DIRS {
        collect_strays(dir, "irlume", &["irlume", "irlumed"], &mut strays);
    }
    for dir in PAM_DIRS {
        collect_strays(dir, "pam_irlume", &["pam_irlume.so"], &mut strays);
    }
    // On merged-usr hosts two scanned directories can be the same place
    // (Arch: /usr/lib64 -> /usr/lib), listing one file under both names;
    // keep the first path per canonical target. Found in container E2E.
    let mut seen: Vec<std::path::PathBuf> = Vec::new();
    strays.retain(|p| {
        let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.into());
        if seen.contains(&canon) {
            return false;
        }
        seen.push(canon);
        true
    });
    // Only files no package owns are leftovers; a package-owned neighbour
    // (whatever it is) is some package's business, not ours.
    strays.retain(|p| !package_owns(p).unwrap_or(false));
    if strays.is_empty() {
        return;
    }
    let claim = if package_query_available() {
        "not owned by any package; "
    } else {
        ""
    };
    println!(
        "[doctor] ⚠ stray file(s) next to the managed irlume files ({claim}likely \
         backups\n     from a manual install; safe to remove once you no longer need them):"
    );
    for p in &strays {
        println!("       {p}");
    }
}

/// Push every regular file in `dir` whose name starts with `prefix` but is not
/// one of the `managed` names.
fn collect_strays(dir: &str, prefix: &str, managed: &[&str], out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // directory absent on this distro; nothing to scan
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_stray_name(name, prefix, managed) {
            continue;
        }
        // Only regular files: a directory or socket named irlume-something is
        // not a binary backup.
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            out.push(format!("{dir}/{name}"));
        }
    }
}

/// Name-level stray test, separated from the filesystem walk so it is unit
/// testable: prefix match minus the managed names.
fn is_stray_name(name: &str, prefix: &str, managed: &[&str]) -> bool {
    name.starts_with(prefix) && !managed.contains(&name)
}

/// Whether any package owns `path`. `None` when this host has no package
/// manager we know how to ask (then the stray wording drops the ownership
/// claim rather than asserting something unverified).
fn package_owns(path: &str) -> Option<bool> {
    use irlume_common::platform::{distro_family, DistroFamily};
    // Each of these exits non-zero when no package owns the path.
    let (prog, args): (&str, &[&str]) = match distro_family() {
        DistroFamily::Fedora => ("rpm", &["-qf", path]),
        DistroFamily::Debian => ("dpkg", &["-S", path]),
        DistroFamily::Arch => ("pacman", &["-Qo", path]),
        DistroFamily::Other => return None,
    };
    Some(
        std::process::Command::new(prog)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
    )
}

/// Whether this host has an ownership query at all (drives the wording of the
/// stray report).
fn package_query_available() -> bool {
    use irlume_common::platform::{distro_family, DistroFamily};
    distro_family() != DistroFamily::Other
}

/// Overlay = the package manager's verify says a managed binary's CONTENT no
/// longer matches the package (someone hand-installed over it). mtime-only
/// drift is ignored: it is what a `touch` or a backup-restore does and the
/// binary is still the packaged one.
fn report_overlay(origin: &InstallOrigin) {
    let (verify, reinstall): (&[&str], &str) = match origin {
        InstallOrigin::Copr | InstallOrigin::LocalRpm(_) => {
            (&["rpm", "-V", "irlume"], "sudo dnf reinstall irlume")
        }
        InstallOrigin::Ppa | InstallOrigin::LocalDeb => (
            &["dpkg", "--verify", "irlume"],
            "sudo apt install --reinstall irlume",
        ),
        InstallOrigin::ArchPkg => (&["pacman", "-Qkk", "irlume"], "sudo pacman -S irlume"),
        // No package to verify against; a source install IS the hand-install.
        InstallOrigin::Source => return,
    };
    let Some(out) = cmd_output_lossy(verify[0], &verify[1..]) else {
        return; // verify clean (no output) or tool failed: nothing to report
    };
    let modified = overlaid_paths(&out);
    if modified.is_empty() {
        return;
    }
    for path in &modified {
        println!(
            "[doctor] ⚠ {path} differs from the packaged file: a hand-installed build is\n     \
             overlaying the package, and the next package update will silently replace it.\n     \
             Restore the packaged build with: {reinstall}"
        );
    }
}

/// Parse a package-verify report (rpm -V / dpkg --verify / pacman -Qkk) down
/// to the managed irlume paths whose content changed.
///
/// rpm and dpkg share the attribute-column format: a 9-character flag string
/// where position 3 ('5') marks a digest mismatch, then an optional one-char
/// file-type marker (`c` config etc.), then the path; only failing files are
/// printed, and dpkg's only functional check IS the md5 digest (rpm(8) VERIFY
/// OPTIONS; dpkg(1) --verify). A line whose flags lack '5' is mtime/mode
/// drift only, and `missing` lines carry no flags at all. pacman -Qkk prints
/// `warning: pkg: /path (<Kind>)` per finding, on STDERR, with the summary
/// count on stdout (pacman(8) -k; src/pacman/check.c). Of its kinds, only
/// "… checksum mismatch" and "Size mismatch" mean the file content changed;
/// mtime/permission/owner drift does not make a file an overlay.
fn overlaid_paths(verify_output: &str) -> Vec<String> {
    const WATCHED: &[&str] = &["/irlume", "/irlumed", "/pam_irlume.so"];
    let mut hits = Vec::new();
    for line in verify_output.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        // pacman per-file shape: `warning: irlume: /path (Kind)`. (The stdout
        // summary line `irlume: N total files, …` has no absolute-path token,
        // so it can never match a watched name.)
        let (content_changed, path) = if toks.first() == Some(&"warning:") {
            let Some(path) = toks.get(2) else { continue };
            (
                line.contains("checksum mismatch") || line.contains("(Size mismatch)"),
                *path,
            )
        } else {
            // rpm/dpkg shape: flags first, path last (the file-type marker
            // between them is skipped by taking the final token).
            let (Some(flags), Some(path)) = (toks.first(), toks.last()) else {
                continue;
            };
            (flags.contains('5'), *path)
        };
        let watched = WATCHED.iter().any(|w| path.ends_with(w));
        if content_changed && watched && !hits.contains(&path.to_string()) {
            hits.push(path.to_string());
        }
    }
    hits
}

/// Run a command, returning its combined stdout+stderr when any was produced.
/// Both streams because pacman -Qkk reports per-file findings on stderr with
/// only the summary on stdout, while rpm/dpkg report on stdout. `None` for
/// clean (no output) or unrunnable. Exit codes are useless here: dpkg
/// --verify exits 0 even with failing files, so presence of parseable lines
/// is the only signal.
fn cmd_output_lossy(prog: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(prog).args(args).output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (!s.trim().is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::{collect_strays, is_stray_name, overlaid_paths};

    #[test]
    fn collect_finds_backup_files_but_not_managed_names_or_dirs() {
        let dir = std::env::temp_dir().join(format!("irlume-strays-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for f in [
            "irlume",
            "irlumed",
            "irlume.rpm-0.5.0",
            "irlumed.pre-gesture",
        ] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        // A directory with a stray-looking name is not a file backup.
        std::fs::create_dir_all(dir.join("irlume.d")).unwrap();

        let mut out = Vec::new();
        collect_strays(
            dir.to_str().unwrap(),
            "irlume",
            &["irlume", "irlumed"],
            &mut out,
        );
        out.sort();
        let expected: Vec<String> = ["irlume.rpm-0.5.0", "irlumed.pre-gesture"]
            .iter()
            .map(|f| dir.join(f).to_str().unwrap().to_string())
            .collect();
        assert_eq!(out, expected);

        // An absent directory is silently skipped, not an error.
        let mut none = Vec::new();
        collect_strays("/nonexistent-irlume-test-dir", "irlume", &[], &mut none);
        assert!(none.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stray_names_are_prefix_matches_minus_the_managed_set() {
        let managed = &["irlume", "irlumed"];
        assert!(is_stray_name("irlume.rpm-0.5.0", "irlume", managed));
        assert!(is_stray_name("irlumed.pre-gesture", "irlume", managed));
        assert!(is_stray_name("irlume.bak", "irlume", managed));
        assert!(!is_stray_name("irlume", "irlume", managed));
        assert!(!is_stray_name("irlumed", "irlume", managed));
        // Unrelated neighbours never match.
        assert!(!is_stray_name("iridium", "irlume", managed));
        assert!(!is_stray_name("pam_irlume.so", "irlume", managed)); // wrong dir class
        assert!(is_stray_name(
            "pam_irlume.so.rpm-0.5.0",
            "pam_irlume",
            &["pam_irlume.so"]
        ));
        assert!(!is_stray_name(
            "pam_irlume.so",
            "pam_irlume",
            &["pam_irlume.so"]
        ));
    }

    #[test]
    fn rpm_verify_flags_content_changes_only() {
        // Digest mismatch on a managed binary → reported.
        let digest = "S.5....T.    /usr/bin/irlumed\n";
        assert_eq!(overlaid_paths(digest), vec!["/usr/bin/irlumed"]);
        // mtime-only drift → not an overlay.
        let mtime = ".......T.    /usr/bin/irlume\n";
        assert!(overlaid_paths(mtime).is_empty());
        // Config-file marker between flags and path parses to the last token.
        let with_marker = "S.5....T.  c /usr/lib64/security/pam_irlume.so\n";
        assert_eq!(
            overlaid_paths(with_marker),
            vec!["/usr/lib64/security/pam_irlume.so"]
        );
        // A digest change on a file we don't watch is someone else's business.
        let other = "S.5....T.    /usr/share/irlume/models/x.onnx\n";
        assert!(overlaid_paths(other).is_empty());
    }

    #[test]
    fn dpkg_verify_shares_the_flag_column_shape() {
        let line = "??5??????   /usr/bin/irlume\n";
        assert_eq!(overlaid_paths(line), vec!["/usr/bin/irlume"]);
        let clean_style = "??.??????   /usr/bin/irlume\n";
        assert!(overlaid_paths(clean_style).is_empty());
    }

    #[test]
    fn pacman_qkk_flags_content_kinds_only() {
        // Real -Qkk shapes (stderr lines carry a `warning:` prefix; a content
        // edit emits checksum + mtime lines for the same file; dedup'd).
        let edit = "warning: irlume: /usr/bin/irlumed (SHA256 checksum mismatch)\n\
                    warning: irlume: /usr/bin/irlumed (Modification time mismatch)\n";
        assert_eq!(overlaid_paths(edit), vec!["/usr/bin/irlumed"]);
        assert_eq!(
            overlaid_paths("warning: irlume: /usr/bin/irlume (Size mismatch)\n"),
            vec!["/usr/bin/irlume"]
        );
        // Non-content drift is not an overlay.
        for kind in [
            "Modification time mismatch",
            "Permissions mismatch",
            "UID mismatch",
        ] {
            let line = format!("warning: irlume: /usr/bin/irlumed ({kind})\n");
            assert!(overlaid_paths(&line).is_empty(), "{kind}");
        }
        // The stdout summary line has no absolute-path token to match.
        let summary = "irlume: 312 total files, 1 altered file\n";
        assert!(overlaid_paths(summary).is_empty());
        // A missing mtree makes -Qkk print this to stdout; not an overlay.
        assert!(overlaid_paths("irlume: no mtree file\n").is_empty());
    }

    #[test]
    fn watched_suffix_must_be_a_whole_filename() {
        // `/usr/bin/foo-irlume` ends with "/irlume"? No: suffix check is on
        // the path, "/irlume" only matches when it is the final component.
        let line = "S.5....T.    /usr/bin/not-irlume\n";
        assert!(overlaid_paths(line).is_empty());
        let nested = "S.5....T.    /opt/x/irlume\n";
        assert_eq!(overlaid_paths(nested), vec!["/opt/x/irlume"]);
    }
}
