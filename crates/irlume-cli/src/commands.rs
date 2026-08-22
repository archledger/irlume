// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Extra operational CLI commands layered over the existing daemon protocol:
//! observability (`status`, `detect`, `identify`), diagnostics (`diag`,
//! `selinux`, `deps`), the safe manual re-bind (`reseal`), and the guided
//! `setup` wizard. These are thin orchestration over `irlumed` + local probes;
//! the daemon stays the only component that touches the camera / TPM / store.

use crate::{daemon_request, tpm_device, user_arg};
use irlume_common::{Request, Response};
use std::process::ExitCode;

/// `irlume update`: origin-aware updater. Detects how this install got onto
/// the system and updates through that same channel, never a different one:
/// repo-backed installs (Fedora Copr, Launchpad PPA) are upgraded in place by
/// running the package manager; release-asset and source installs get the
/// matching manual steps, plus a pointer to the dedicated repo where one
/// exists for the family. `--check` reports without running anything. No
/// network library is bundled; we shell out to curl and degrade gracefully.
/// The upstream-version part of a package version string ("0.10.0-1.fc44" →
/// "0.10.0"), for comparing the running binary against the package.
fn version_base(v: &str) -> &str {
    v.split(['-', '+']).next().unwrap_or(v)
}

pub fn update(args: &[String]) -> ExitCode {
    let check_only = args.iter().any(|a| a == "--check" || a == "-n");
    let origin = install_origin();
    // The version the package manager actually has installed (the source of
    // truth for "is a newer one out?"), not just this binary's compiled version
    // (which can differ from the package on a dev/overlaid box).
    let current = installed_version(&origin);
    println!("[update] installed: {current}");
    println!("[update] install method: {}", origin.describe());
    // A hand-installed/overlaid build (dev box) can run a binary newer than
    // the package. `installed:` above stays the package truth — it is what
    // the update replaces — but say so instead of letting the two versions
    // silently disagree (doctor's install-hygiene check has the detail).
    let bin = env!("CARGO_PKG_VERSION");
    if version_base(&current) != bin {
        println!(
            "[update] note: the running binary is {bin}, not the packaged {current}; the package version above is what updating replaces (see `irlume doctor`)"
        );
    }

    let release = latest_release();
    let latest = &release.tag;
    let newer = match latest {
        Some(tag) => {
            if version_gt(tag.trim_start_matches('v'), &current) {
                println!("[update] available: {tag}  →  a newer release is out.");
                true
            } else {
                println!("[update] up to date (latest release is {tag}).");
                false
            }
        }
        None => {
            println!("[update] couldn't reach the release feed (offline?). Not updating; the channel for this install:");
            false
        }
    };

    if !newer {
        // Nothing to run, but a release-asset install still gets the
        // switch-to-repo pointer so FUTURE updates are one command.
        match &origin {
            InstallOrigin::Copr => {
                println!("  updates come from the Copr: sudo dnf upgrade --refresh irlume")
            }
            InstallOrigin::Ppa => {
                println!("  updates come with the system: sudo apt update && sudo apt upgrade")
            }
            _ => {}
        }
        recommend_channel(&origin);
        return ExitCode::SUCCESS;
    }

    match &origin {
        InstallOrigin::Copr => {
            if check_only {
                println!("  would run: sudo dnf upgrade --refresh irlume");
            } else {
                println!("[update] updating from the Copr (the channel this was installed from):");
                return run_pkg_steps(&[&["dnf", "upgrade", "--refresh", "irlume"]]);
            }
        }
        InstallOrigin::Ppa => {
            if check_only {
                println!("  would run: sudo apt update && sudo apt install --only-upgrade irlume");
            } else {
                println!("[update] updating from the PPA (the channel this was installed from):");
                return run_pkg_steps(&[
                    &["apt", "update"],
                    &["apt", "install", "--only-upgrade", "irlume"],
                ]);
            }
        }
        InstallOrigin::LocalRpm(_) => {
            // A release may ship a standalone .rpm for direct download, but it's
            // Fedora-version-specific (fc44…) and its SELinux policy is a separate
            // Recommends that a local `dnf install ./x.rpm` won't auto-pull, so
            // the Copr stays the recommended Fedora channel (in-place upgrades +
            // the selinux subpackage pulled automatically). Point there.
            recommend_channel(&origin);
        }
        InstallOrigin::LocalDeb => {
            let ver = latest
                .as_deref()
                .unwrap_or("vVERSION")
                .trim_start_matches('v');
            let (deb_arch, _, _) = arch_names();
            println!("  Update the way it was installed (the new .deb from the release page):");
            release_asset_steps(
                &release.assets,
                ver,
                &format!("irlume_{ver}_{deb_arch}.deb"),
                "sudo apt install",
            );
            recommend_channel(&origin);
        }
        InstallOrigin::ArchPkg => {
            // The AUR package (aur.archlinux.org/packages/irlume, live since
            // 0.2.0) is the Arch channel; it builds from the signed release
            // tag. pacman cannot tell an AUR-helper install from a local
            // makepkg, so show both routes.
            println!("  Update from the AUR (builds the signed release tag):");
            println!("    yay -Syu irlume        # or: paru -Syu irlume");
            println!("  Without an AUR helper:");
            println!(
                "    git clone https://aur.archlinux.org/irlume.git && cd irlume && makepkg -si"
            );
            println!("  (local/source builds: makepkg -si  in packaging/arch/)");
        }
        InstallOrigin::Source => {
            println!("  Source install. Update the checkout at the tag:");
            println!(
                "    git -C <clone> fetch --tags && git checkout {}",
                latest.as_deref().unwrap_or("<latest>")
            );
            println!("    bash scripts/fetch-models.sh && cargo build --release && sudo bash scripts/install-host.sh --ort <libonnxruntime.so>");
        }
    }
    println!("  Release notes: https://github.com/archledger/irlume/releases");
    ExitCode::SUCCESS
}

/// How this irlume install got onto the system; decides the update channel.
pub enum InstallOrigin {
    /// Fedora Copr repo, the recommended Fedora channel.
    Copr,
    /// rpm-owned but not from the Copr (hand-built / local rpm). Carries
    /// dnf's `from_repo` string for display (may be empty or a history hash).
    LocalRpm(String),
    /// Launchpad PPA, the recommended Ubuntu channel.
    Ppa,
    /// dpkg-owned with no PPA source behind it (release-asset .deb).
    LocalDeb,
    /// pacman-owned (AUR or local makepkg).
    ArchPkg,
    /// Not owned by any package manager (source / dev install).
    Source,
}

impl InstallOrigin {
    pub fn describe(&self) -> String {
        match self {
            InstallOrigin::Copr => "Fedora Copr (archledger/irlume)".into(),
            InstallOrigin::LocalRpm(repo) if repo.is_empty() || repo.len() == 32 => {
                "local RPM (not from the Copr)".into()
            }
            InstallOrigin::LocalRpm(repo) => format!("RPM from repo `{repo}` (not the Copr)"),
            InstallOrigin::Ppa => "Launchpad PPA (ppa:archledger/irlume)".into(),
            InstallOrigin::LocalDeb => "local .deb (GitHub release asset)".into(),
            InstallOrigin::ArchPkg => "pacman package (AUR / makepkg)".into(),
            InstallOrigin::Source => "source / dev install (no package manager owns it)".into(),
        }
    }
}

/// Detect the install origin. Cheap local probes only: the owning package
/// manager, and for owned packages the repo it came from (dnf's `from_repo`,
/// apt's policy table).
pub fn install_origin() -> InstallOrigin {
    use irlume_common::platform::{distro_family, DistroFamily};
    match distro_family() {
        DistroFamily::Fedora => {
            if !cmd_ok("rpm", &["-q", "irlume"]) {
                return InstallOrigin::Source;
            }
            let repo = cmd_stdout(
                "dnf",
                &[
                    "repoquery",
                    "--installed",
                    "--qf",
                    "%{from_repo}\n",
                    "irlume",
                ],
            )
            .unwrap_or_default()
            .trim()
            .to_string();
            if is_copr_repo(&repo) {
                InstallOrigin::Copr
            } else {
                InstallOrigin::LocalRpm(repo)
            }
        }
        DistroFamily::Debian => {
            let status =
                cmd_stdout("dpkg-query", &["-W", "-f", "${Status}", "irlume"]).unwrap_or_default();
            if !status.contains("ok installed") {
                return InstallOrigin::Source;
            }
            let policy = cmd_stdout("apt-cache", &["policy", "irlume"]).unwrap_or_default();
            if policy.contains("ppa.launchpadcontent.net/archledger/irlume") {
                InstallOrigin::Ppa
            } else {
                InstallOrigin::LocalDeb
            }
        }
        DistroFamily::Arch => {
            if cmd_ok("pacman", &["-Qq", "irlume"]) {
                InstallOrigin::ArchPkg
            } else {
                InstallOrigin::Source
            }
        }
        DistroFamily::Other => InstallOrigin::Source,
    }
}

/// dnf5 `from_repo` for a Copr install looks like
/// `copr:copr.fedorainfracloud.org:archledger:irlume`.
fn is_copr_repo(repo: &str) -> bool {
    repo.starts_with("copr:") && repo.ends_with(":archledger:irlume")
}

/// Point release-asset installs at the dedicated repo for their family (when
/// one covers this system), so future updates arrive with the normal system
/// upgrade instead of a manual download.
fn recommend_channel(origin: &InstallOrigin) {
    match origin {
        InstallOrigin::LocalRpm(_) => {
            println!("  Recommended: Fedora's release channel is the Copr; switch once and");
            println!("  future updates arrive with plain `dnf upgrade`:");
            println!("    sudo dnf copr enable archledger/irlume");
            println!("    sudo dnf install irlume");
        }
        InstallOrigin::LocalDeb => {
            let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
            let Some(codename) = ubuntu_codename(&os) else {
                return; // Debian proper: the release .deb IS the channel.
            };
            match ppa_serves(&codename) {
                Some(true) => {
                    println!("  Recommended: Ubuntu's release channel is the PPA; switch once and");
                    println!("  future updates arrive with plain `apt upgrade`:");
                    println!("    sudo add-apt-repository ppa:archledger/irlume");
                    println!("    sudo apt install irlume");
                }
                Some(false) => {
                    println!("  The PPA carries only the current Ubuntu LTS; for `{codename}` the release");
                    println!("  .deb IS your update channel; re-run `irlume update` when a new one is out.");
                }
                None => {
                    println!("  If the PPA serves your Ubuntu series, switching makes future updates automatic:");
                    println!("    sudo add-apt-repository ppa:archledger/irlume && sudo apt install irlume");
                }
            }
        }
        _ => {}
    }
}

/// `VERSION_CODENAME` if this is Ubuntu (or an Ubuntu derivative that can use
/// PPAs), else None.
fn ubuntu_codename(os_release: &str) -> Option<String> {
    let field = |key: &str| -> String {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .unwrap_or_default()
    };
    let ubuntu = field("ID=") == "ubuntu" || field("ID_LIKE=").contains("ubuntu");
    if !ubuntu {
        return None;
    }
    let code = field("UBUNTU_CODENAME=");
    let code = if code.is_empty() {
        field("VERSION_CODENAME=")
    } else {
        code
    };
    (!code.is_empty()).then_some(code)
}

/// Does the PPA publish for this Ubuntu series? HTTP 200 on the series
/// Release file means yes. None = couldn't check (offline / no curl).
fn ppa_serves(codename: &str) -> Option<bool> {
    ppa_serves_via(std::process::Command::new("curl"), codename)
}

/// [`ppa_serves`] with the curl COMMAND injected. The seam exists for #194,
/// and it takes a `Command`, not a path, on purpose: tests once steered this
/// code through PATH + FAKE_CURL_MODE (racy: `set_var` is unsafe with any
/// concurrent env reader), and the first replacement wrote fake tool SCRIPTS
/// to disk, which raced every other test's fork on the write-open fd (exec
/// fails ETXTBSY while any inherited copy exists) and needed an unbounded
/// warm-up wait to paper over it. A `Command` is a value: tests hand in
/// `/bin/sh -c '...'`, nothing is written, nothing is ever exec'd that a
/// test created, so the whole class is unreachable rather than waited out.
fn ppa_serves_via(mut curl: std::process::Command, codename: &str) -> Option<bool> {
    // Whether the PPA has an actually-INSTALLABLE irlume for this Ubuntu series,
    // checked against the binary Packages index, NOT just a `Release` file. A
    // Release file lingers for a series long after its packages are deleted
    // (e.g. noble, whose builds were removed once its toolchain proved too old
    // to compile irlume), so probing Release alone would wrongly steer a
    // derivative user to a PPA that can't serve them. By design the PPA carries
    // only the current Ubuntu LTS; every older derivative uses the universal
    // .deb from the release page. Shells out (no bundled zlib): 404/empty →
    // false, an `irlume` entry present → true.
    let (_, _, ppa_arch) = arch_names();
    let url = format!(
        "https://ppa.launchpadcontent.net/archledger/irlume/ubuntu/dists/{codename}/main/binary-{ppa_arch}/Packages.gz"
    );
    // Distinguish an HTTP error (404 = series genuinely not served) from a
    // network/tooling failure (offline), so we never tell a CURRENT-LTS user
    // "the PPA doesn't serve you" just because they happen to be offline.
    let out = curl.args(["-fsS", "--max-time", "8", &url]).output().ok()?;
    match out.status.code() {
        Some(0) => gz_lists_irlume(&out.stdout),
        Some(22) => Some(false), // curl -f exits 22 on HTTP >= 400 (404) → not served
        _ => None,               // DNS/connect/timeout → couldn't tell
    }
}

/// Does a gzipped Debian `Packages` index list our package? Decompresses via
/// `gzip -dc` (no bundled zlib) and looks for a `Package: irlume` line. The
/// index is tiny (one package), so writing it to gzip's stdin can't deadlock.
fn gz_lists_irlume(gz: &[u8]) -> Option<bool> {
    use std::io::Write;
    let mut child = std::process::Command::new("gzip")
        .arg("-dc")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    // A failed or partial write is NOT "the package is absent": gzip would
    // decompress a truncated index and the answer would read as "the PPA does
    // not serve you", steering a current-LTS user away from their own archive.
    // Observed as a recurring CI failure on a loaded runner before this
    // distinction existed.
    let mut si = child.stdin.take()?;
    let wrote = si.write_all(gz).and_then(|()| si.flush());
    drop(si); // EOF to gzip
    let out = child.wait_with_output().ok()?;
    wrote.ok()?;
    if !out.status.success() {
        return None; // decompression failed; we cannot tell what it lists
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l == "Package: irlume"),
    )
}

/// Run each package-manager step with root: directly if we already are, else
/// through interactive sudo so dnf/apt keep their own transaction prompt (the
/// user still confirms the actual change). Stops at the first failure.
fn run_pkg_steps(steps: &[&[&str]]) -> ExitCode {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let root = unsafe { libc::geteuid() } == 0;
    for step in steps {
        let display = step.join(" ");
        println!("  $ {}{display}", if root { "" } else { "sudo " });
        let status = if root {
            std::process::Command::new(step[0])
                .args(&step[1..])
                .status()
        } else {
            std::process::Command::new("sudo").args(*step).status()
        };
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!("[update] `{display}` exited with {s}; stopping.");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("[update] couldn't run `{display}`: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    println!("[update] done.");
    ExitCode::SUCCESS
}

/// The version actually installed, from the owning package manager, the source
/// of truth for "is a newer one out?". Falls back to this binary's own compiled
/// version for source/dev installs (no package owns them). Package versions
/// carry distro suffixes (`…-1.fc44`, `…-0ppa1~resolute1`, `…-1`); `version_gt`
/// compares the numeric upstream prefix, so they still compare against a tag.
fn installed_version(origin: &InstallOrigin) -> String {
    use std::process::Command;
    installed_version_via(
        origin,
        Command::new("rpm"),
        Command::new("dpkg-query"),
        Command::new("pacman"),
    )
}

/// [`installed_version`] with the package-manager commands injected, the same
/// #194 seam as [`ppa_serves_via`]: values, not paths to files a test wrote.
fn installed_version_via(
    origin: &InstallOrigin,
    rpm: std::process::Command,
    dpkg_query: std::process::Command,
    pacman: std::process::Command,
) -> String {
    let pkg = match origin {
        InstallOrigin::Copr | InstallOrigin::LocalRpm(_) => {
            cmd_output(rpm, &["-q", "--qf", "%{VERSION}", "irlume"])
        }
        InstallOrigin::Ppa | InstallOrigin::LocalDeb => {
            cmd_output(dpkg_query, &["-W", "-f", "${Version}", "irlume"])
        }
        InstallOrigin::ArchPkg => {
            // `pacman -Q irlume` → "irlume 0.1.3-1"; take the version field.
            cmd_output(pacman, &["-Q", "irlume"])
                .and_then(|s| s.split_whitespace().nth(1).map(str::to_string))
        }
        InstallOrigin::Source => None,
    };
    pkg.map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

fn cmd_ok(prog: &str, args: &[&str]) -> bool {
    std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// [`cmd_stdout`] over an already-built `Command` (the #194 injection seam).
fn cmd_output(mut c: std::process::Command, args: &[&str]) -> Option<String> {
    let out = c
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn cmd_stdout(prog: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(prog)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Architecture names for (Debian `.deb`, pacman/tarball, PPA binary index),
/// derived from the arch THIS binary runs on: a native binary's compile-time
/// target arch is the machine's arch. Keeps the updater correct on arm64 etc.,
/// not just x86_64.
fn arch_names() -> (&'static str, &'static str, &'static str) {
    match std::env::consts::ARCH {
        "x86_64" => ("amd64", "x86_64", "amd64"),
        "aarch64" => ("arm64", "aarch64", "arm64"),
        "arm" => ("armhf", "armv7h", "armhf"),
        other => (other, other, other), // best effort for the unusual
    }
}

/// The latest GitHub release, fetched once: tag plus the file names of its
/// package assets (`.deb`/`.rpm`/pacman packages).
struct LatestRelease {
    /// e.g. "v0.5.0". None if curl is missing, offline, or the response can't
    /// be parsed; the caller degrades to just printing the update method.
    tag: Option<String>,
    /// Empty when offline or on an API hiccup; callers treat "empty" as
    /// "couldn't tell" and fall back to a best-effort URL rather than a false
    /// negative.
    assets: Vec<String>,
}

/// Best-effort fetch of the releases/latest API via curl, parsed for both the
/// tag and the asset names, so one call serves the whole `update` run.
fn latest_release() -> LatestRelease {
    latest_release_via(std::process::Command::new("curl"))
}

/// [`latest_release`] with curl injected, the #194 seam again.
fn latest_release_via(mut curl: std::process::Command) -> LatestRelease {
    let offline = LatestRelease {
        tag: None,
        assets: Vec::new(),
    };
    let Ok(out) = curl
        .args([
            "-fsSL",
            "--max-time",
            "8",
            "https://api.github.com/repos/archledger/irlume/releases/latest",
        ])
        .output()
    else {
        return offline;
    };
    if !out.status.success() {
        return offline;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    LatestRelease {
        tag: parse_release_tag(&body),
        assets: parse_package_assets(&body),
    }
}

/// Tiny scan for `"tag_name": "vX.Y.Z"`; avoids a JSON dependency for one field.
fn parse_release_tag(body: &str) -> Option<String> {
    let key = "\"tag_name\"";
    let i = body.find(key)?;
    let after = &body[i + key.len()..];
    let colon = after.find(':')?;
    let q1 = after[colon..].find('"')? + colon + 1;
    let q2 = after[q1..].find('"')? + q1;
    Some(after[q1..q2].to_string())
}

/// Scan every `"name": "…"` and keep the package-file-looking ones (the release
/// title is also a "name" but doesn't end in a package extension).
fn parse_package_assets(body: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest: &str = body;
    while let Some(i) = rest.find("\"name\":") {
        rest = &rest[i + 7..];
        let Some(q1) = rest.find('"') else { break };
        let after = &rest[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        let n = &after[..q2];
        if n.ends_with(".deb") || n.ends_with(".rpm") || n.ends_with(".pkg.tar.zst") {
            names.push(n.to_string());
        }
        rest = &after[q2..];
    }
    names
}

/// Print download+install steps for a release asset, but only if the running
/// architecture's asset actually exists on the release; else say so honestly
/// instead of printing a dead link.
fn release_asset_steps(assets: &[String], ver: &str, asset: &str, install_cmd: &str) {
    if assets.is_empty() || assets.iter().any(|a| a == asset) {
        println!(
            "    curl -fLO https://github.com/archledger/irlume/releases/download/v{ver}/{asset}"
        );
        println!("    {install_cmd} ./{asset}");
    } else {
        println!(
            "  No prebuilt package for this architecture ({}) on release v{ver}.",
            std::env::consts::ARCH
        );
        println!("  Build from source, or watch https://github.com/archledger/irlume/releases");
    }
}

/// True if dotted version `a` is strictly greater than `b` (numeric per field,
/// missing fields = 0). Pre-release suffixes are ignored (compared as the base).
fn version_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['.', '-'])
            .take_while(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let (x, y) = (
            va.get(i).copied().unwrap_or(0),
            vb.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x > y;
        }
    }
    false
}

const OK: &str = "\u{2705}";
const WARN: &str = "\u{26a0}";
const NO: &str = "\u{2717}";

/// Reachability: a Ping that returns true iff `irlumed` answered.
/// What a `Ping` established about the daemon.
///
/// This used to be a bare bool, and that lost the one distinction that matters:
/// a user whose uid could not open the socket was told "NOT reachable
/// (systemctl status irlumed)" and sent to inspect a service that was running
/// normally. EACCES and "nothing is listening" are different answers and get
/// different words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonReach {
    Running,
    /// Answering, but the engine is still loading models. The accept loop
    /// runs from the moment systemd hands over the socket and Ping gets
    /// `Response::Ok("starting")` until the engine is ready, so for a few
    /// seconds after every (re)start the daemon is neither up nor down.
    /// Reporting this as "down" sent users to restart a daemon that was
    /// seconds from ready, reopening the same window.
    Starting,
    /// The socket is there but this uid may not connect. Carries no information
    /// about whether the daemon is healthy, so never report it as "down".
    AccessDenied,
    /// Nothing is listening, or the reply was unusable.
    Down,
}

/// Classify one Ping outcome. Split from [`daemon_reach`] so the TUI can feed
/// it the short-budget `request_poll` its refresh thread requires while the
/// CLI keeps the full-budget `request`; both must read the answer the same
/// way or the two surfaces disagree about the same daemon.
pub(crate) fn classify_reach(r: std::io::Result<Response>) -> DaemonReach {
    match r {
        Ok(Response::Pong) => DaemonReach::Running,
        // Any non-Pong Ok means something speaking our protocol answered but
        // is not ready; today that is only the startup accept loop.
        Ok(Response::Ok(_)) => DaemonReach::Starting,
        Ok(_) => DaemonReach::Down,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => DaemonReach::AccessDenied,
        Err(_) => DaemonReach::Down,
    }
}

/// Probe the daemon. Goes through the shared client directly rather than
/// `daemon_request`, because the errno kind is the point here and the string
/// conversion throws it away.
pub(crate) fn daemon_reach() -> DaemonReach {
    classify_reach(irlume_common::client::request(&Request::Ping))
}

fn daemon_up() -> bool {
    daemon_reach() == DaemonReach::Running
}

/// `irlume status`: one-shot health dashboard. Always exits 0 (it reports state,
/// it doesn't gate anything); use `irlume detect` for script-friendly exit codes.
/// How many enrolled scans the CURRENTLY LOADED recognizer could match, summed
/// over every profile, or `None` when the daemon did not say.
///
/// A template only matches the recognizer that produced it. Reporting the raw
/// scan count as health lets a profile whose templates all belong to a model
/// that is no longer loaded read as ready while no face can authenticate.
/// `None` is deliberately not zero: a daemon older than the per-recognizer
/// counts sends an empty map, and treating that as "nothing usable" would tell
/// a healthy install to re-enroll.
fn usable_scans(profiles: &[irlume_common::ProfileSummary]) -> Option<usize> {
    profiles
        .iter()
        .map(
            |p| match (&p.live_recognizer, p.scans_by_recognizer.is_empty()) {
                (Some(live), false) => Some(p.scans_by_recognizer.get(live).copied().unwrap_or(0)),
                _ => None,
            },
        )
        .try_fold(0usize, |acc, n| n.map(|n| acc + n))
}

pub fn status(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    println!("irlume status for '{user}'");

    // Daemon + method.
    let reach = daemon_reach();
    println!(
        "  daemon        : {}",
        match reach {
            DaemonReach::Running => format!("running {OK}"),
            DaemonReach::Starting => format!("starting (loading models) {WARN}; retry shortly"),
            DaemonReach::AccessDenied => format!(
                "running, but this user may not connect {WARN} (EACCES on {})",
                irlume_common::client::socket_path().display()
            ),
            DaemonReach::Down => format!("NOT reachable {NO} (systemctl status irlumed)"),
        }
    );
    let method = irlume_core::policy::method();
    println!(
        "  auth method   : {:?}{}",
        method,
        if method.face_disabled() {
            " (face disabled)"
        } else {
            ""
        }
    );

    // Enrollment.
    match daemon_request(&Request::ListProfiles {
        user: user.clone(),
        // Human output: keep the daemon's prose, it is written to be read.
        structured_errors: false,
    }) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            ..
        }) => {
            if profiles.is_empty() {
                println!("  enrollment    : none {WARN} (run `irlume enroll`)");
            } else {
                let scans: usize = profiles.iter().map(|p| p.scans.len()).sum();
                println!(
                    "  enrollment    : {} profile(s), {scans} scan(s) {}",
                    profiles.len(),
                    if require_eyes_open { WARN } else { OK }
                );
                for p in &profiles {
                    println!("                  - {} ({} scan(s))", p.name, p.scans.len());
                }
                // A scan can only match the recognizer it was captured with, which is
                // what `scans_by_recognizer`'s own doc says: "how many scans" has no
                // single answer worth reporting on its own. The line above reports
                // exactly that number with a tick, so a profile whose templates all
                // belong to a recognizer that is no longer loaded (a third-party model
                // disabled, or swapped) read as healthy while no face could match.
                //
                // Silent when the daemon sent no counts at all: that is an older
                // daemon, and unknown is not zero.
                let usable = usable_scans(&profiles);
                if let Some(0) = usable {
                    if scans > 0 {
                        println!(
                            "                  {WARN} none of those scans belong to the recognizer \
                             that is loaded now, so no face can match: re-enable the model it was \
                             enrolled with, or run `irlume enroll` again"
                        );
                    }
                }
            }
            if require_eyes_open {
                println!(
                    "                  legacy policy blocks authentication; run: sudo irlume profiles eyes-open off --user {}",
                    crate::shell_single_quote(&user)
                );
            }
        }
        Ok(Response::Error(e)) => println!("  enrollment    : error: {e}"),
        _ => println!("  enrollment    : unknown (daemon unreachable)"),
    }

    // Keyring (TPM-sealed login password) + template encryption / recovery.
    // KeyringInfo adds the seal tier and drift; an older daemon answers it
    // with an error, so fall back to the plain armed bit.
    match daemon_request(&Request::KeyringInfo { user: user.clone() }) {
        Ok(Response::KeyringInfo {
            armed: true,
            policy,
            drifted,
            ..
        }) => {
            let tier = policy.map(|p| format!(", {p}")).unwrap_or_default();
            let drift = match drifted {
                Some(true) => format!(" PCR DRIFT {WARN} (re-run `irlume keyring arm`)"),
                _ => String::new(),
            };
            println!("  keyring unlock: armed {OK}{tier}{drift}");
        }
        Ok(Response::KeyringInfo { armed: false, .. }) => {
            println!("  keyring unlock: not armed (run `irlume keyring arm`)");
        }
        _ => match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
            Ok(Response::HasPassword(armed)) => println!(
                "  keyring unlock: {}",
                if armed {
                    format!("armed {OK}")
                } else {
                    "not armed (run `irlume keyring arm`)".into()
                }
            ),
            _ => println!("  keyring unlock: unknown"),
        },
    }
    if let Ok(Response::RecoveryStatus {
        encrypted,
        recovery_set,
        key_present,
        ..
    }) = daemon_request(&Request::RecoveryStatus { user: user.clone() })
    {
        println!(
            "  templates     : {}",
            match (encrypted, key_present) {
                (true, true) => format!("encrypted at rest {OK}"),
                // Reporting this as plaintext both understates the posture and
                // hides that the enrollment is gone.
                (true, false) => format!(
                    "encrypted, but the TEMPLATE KEY IS MISSING {WARN} \
                     (unreadable; re-enroll)"
                ),
                (false, _) => format!("plaintext {WARN} (run `irlume recovery setup`)"),
            }
        );
        println!(
            "  recovery pass : {}",
            if recovery_set {
                format!("set {OK}")
            } else {
                format!("not set {WARN}")
            }
        );
    }

    // Biopolicy enforcement (opt-in).
    println!(
        "  biopolicy     : {}",
        match irlume_common::config::enforce_biopolicy_visible() {
            Some(true) => format!("ENFORCING {OK} (operation-class gate)"),
            Some(false) => "off (default)".into(),
            None => "unknown: root-only setting, re-run with sudo".into(),
        }
    );

    // The credential-release gesture gate (DEFAULT OFF). Print it always: an
    // opt-in step the user may want to know is available shows where they look
    // for the current state. Off is the default, not a warning.
    println!(
        "  keyring gate  : {}",
        // The EFFECTIVE rule (per-service override first, then the global
        // gate), the same order the daemon applies; reading only the global
        // key said "off (default)" to a user whose per-service key required
        // the gesture.
        match irlume_common::config::credential_release_gesture_required_visible() {
            Some(true) => format!("gesture required {OK} (opt-in)"),
            Some(false) =>
                "off (default): the keyring releases after the face match with no nod".into(),
            None => "root-only setting (re-run with sudo)".into(),
        }
    );

    // Cameras. Ask the DAEMON first: it already holds these nodes and reports
    // the pair it selected, and classifying a node locally means OPENING it.
    // On a UVC module that answers EBUSY to a second open, `irlume status` run
    // during an enrollment fails that enrollment. That is #187, and the #300
    // fix covered the TUI but left this path enumerating: measured with strace,
    // `status` opened /dev/video0 through video3 with the daemon running.
    // Falling back to a local probe when the daemon is down is safe for the
    // same reason it is in the TUI: nothing else holds the cameras then, and it
    // is the only source of an answer.
    let (rgb, ir) = crate::camera_pair();
    println!("  cameras       : rgb={rgb} ir={ir}");

    // Fingerprint.
    let fp = irlume_fingerprint::device_name()
        .map(|n| format!("{n} {OK}"))
        .unwrap_or_else(|| {
            if irlume_fingerprint::available() {
                format!("present {OK}")
            } else {
                "none".into()
            }
        });
    println!("  fingerprint   : {fp}");

    ExitCode::SUCCESS
}

/// `irlume detect`: script-friendly install-state probe. Exit codes:
///   0  = ready    (daemon reachable AND the user is enrolled)
///   10 = partial  (installed but not ready: daemon down or not enrolled)
///   20 = absent   (irlumed is not installed)
/// Is the daemon binary on this machine, wherever the distro keeps it?
///
/// The FHS paths first, then `PATH`, which is how a Nix profile
/// (/run/current-system/sw/bin) and a home-manager install are found. Checked
/// only when the socket says nothing: a reachable daemon has already answered
/// the question.
fn irlumed_binary_present() -> bool {
    irlumed_binary_in(std::env::var_os("PATH").as_deref())
}

/// [`irlumed_binary_present`] with the search path passed in.
///
/// Split out so a test can hand it a directory instead of setting `PATH` for the
/// whole process. The harness runs tests in parallel, and a process-wide `PATH`
/// change breaks any concurrent test that spawns a program: this reached CI as a
/// package-origin test unwrapping a NotFound under the sanitizer's slower
/// interleaving, having passed locally on timing alone.
fn irlumed_binary_in(path: Option<&std::ffi::OsStr>) -> bool {
    const FHS: &[&str] = &[
        "/usr/local/bin/irlumed",
        "/usr/bin/irlumed",
        "/run/current-system/sw/bin/irlumed",
    ];
    if FHS.iter().any(|p| std::path::Path::new(p).exists()) {
        return true;
    }
    path.is_some_and(|paths| std::env::split_paths(paths).any(|d| d.join("irlumed").exists()))
}

pub fn detect(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    // A REACHABLE daemon is the strongest possible evidence of an install, so ask
    // that before looking for files. Two hardcoded paths decided this before, and
    // NixOS puts the binary in /nix/store with a link from
    // /run/current-system/sw/bin: a packaged, documented, fully working install
    // reported "absent: irlumed is not installed" and exit 20, the code that
    // tells an installer irlume is not on the machine at all.
    let reach = daemon_reach();
    let installed = reach != DaemonReach::Down || irlumed_binary_present();
    if !installed {
        println!("absent: irlumed is not installed");
        return ExitCode::from(20);
    }
    // Without socket access neither readiness nor enrollment is knowable, and
    // claiming "not enrolled" would be a guess. Report the real obstacle and
    // stay at 10 (partial): 0 would assert a readiness we cannot see.
    if reach == DaemonReach::AccessDenied {
        println!(
            "partial: cannot determine readiness; not permitted to connect to {} (EACCES). \
             The daemon may be running fine.",
            irlume_common::client::socket_path().display()
        );
        return ExitCode::from(10);
    }
    let up = reach == DaemonReach::Running;
    let enrolled = matches!(
        daemon_request(&Request::ListProfiles {
            user,
            structured_errors: false,
        }),
        Ok(Response::Enrollment { ref profiles, .. }) if !profiles.is_empty()
    );
    if up && enrolled {
        println!("ready: daemon running and a face is enrolled");
        ExitCode::SUCCESS
    } else {
        println!(
            "partial: installed but not ready ({}{})",
            if up { "daemon up" } else { "daemon down" },
            if enrolled {
                ", enrolled"
            } else {
                ", not enrolled"
            }
        );
        ExitCode::from(10)
    }
}

/// `irlume identify`: 1:N "who is this?" over a live capture (no claimed user).
pub fn identify(_args: &[String]) -> ExitCode {
    eprintln!("[identify] look at the camera…");
    match daemon_request(&Request::Identify) {
        Ok(Response::Identified {
            user: Some(u),
            profile,
            score,
            ..
        }) => {
            println!(
                "[identify] {u} (profile '{}', score {score:.3}) {OK}",
                profile.unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Ok(Response::Identified {
            user: None,
            live,
            reason,
            ..
        }) => {
            println!(
                "[identify] no match: {} ({reason})",
                if live {
                    "live face, not enrolled"
                } else {
                    "no live face"
                }
            );
            ExitCode::from(1)
        }
        Ok(Response::Error(e)) => {
            eprintln!("[identify] error: {e}");
            ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[identify] unexpected response: {other:?}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[identify] {e}");
            ExitCode::FAILURE
        }
    }
}

/// Print one root-readable TPM seal and its PCR-drift diagnosis. Missing and
/// permission-denied paths return false so the caller can use a daemon summary;
/// malformed or other unreadable files are reported here and return true.
fn print_seal_diagnostics(
    label: &str,
    path: &std::path::Path,
    healthy: &str,
    drift_fix: &str,
    corrupt_fix: &str,
) -> bool {
    let serialized = match std::fs::read_to_string(path) {
        Ok(serialized) => serialized,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return false;
        }
        Err(error) => {
            println!(
                "  {label:<14}: UNREADABLE {NO} (I/O error {:?}; seal health is unknown)",
                error.kind()
            );
            return true;
        }
    };
    let env = match serde_json::from_str::<irlume_core::envelope::SealedEnvelope>(&serialized) {
        Ok(env) => env,
        Err(_) => {
            println!("  {label:<14}: CORRUPT {NO} (envelope JSON is malformed; {corrupt_fix})");
            return true;
        }
    };
    println!("  {label:<14}: {} {OK}", path.display());
    println!(
        "    policy      : {}, bound PCRs {:?}",
        env.policy.describe(),
        env.pcrs
    );
    if env.pcr_values.is_empty() {
        println!(
            "    PCR drift   : unknown {WARN} (envelope has no recorded PCR snapshot; unseal was not tested)"
        );
        return true;
    }
    match irlume_core::tpm::diagnose_pcrs(&env) {
        Ok(drifted) if drifted.is_empty() => {
            println!("    PCR drift   : none {OK} ({healthy})");
        }
        Ok(drifted) => {
            println!(
                "    PCR drift   : DRIFTED at {drifted:?} {WARN}; unseal will FAIL; {drift_fix}"
            );
        }
        Err(error) => {
            println!(
                "    PCR drift   : could not replay PCRs ({error}); need TPM access (tss group / root)"
            );
        }
    }
    true
}

/// `irlume diag`: TPM seal / PCR-drift diagnostics (the dbx/firmware debugger).
/// The keyring credential and face-template key are independent seals and are
/// always reported separately. Needs root + TPM access to read their root-only
/// envelopes and replay PCRs; falls back to daemon summaries otherwise.
pub fn diag(args: &[String]) -> ExitCode {
    use irlume_common::secureboot;
    let user = user_arg(args);
    println!("irlume diag for '{user}'");

    // Trust anchors.
    match tpm_device() {
        Some(d) => println!("  TPM           : {d} {OK}"),
        None => println!("  TPM           : none {NO}"),
    }
    println!(
        "  boot mode     : {}",
        secureboot::detect_boot_mode().as_str()
    );
    if secureboot::is_secure_boot_enabled() {
        println!("  secure boot   : enabled {OK}");
    } else if secureboot::is_setup_mode() {
        println!("  secure boot   : SETUP MODE {WARN}");
    } else if secureboot::secure_boot_present() {
        println!("  secure boot   : disabled {WARN}");
    } else {
        println!("  secure boot   : not a UEFI boot");
    }
    println!(
        "  signed policy : {}",
        if irlume_core::pcrsig::signed_policy_available() {
            "PCR-11 signature present (Tier 1: kernel updates won't need re-seal)"
        } else {
            "none (no Tier 1 on this boot chain)"
        }
    );
    match irlume_core::tpm::pcrlock_provisioned() {
        Some(nv) => println!(
            "  pcrlock       : provisioned, NV 0x{nv:x} (Tier 2 candidate: an arm uses it only if it unseals on this boot, else falls back to literal PCR 7)"
        ),
        None => println!(
            "  pcrlock       : not provisioned (optional; `systemd-pcrlock make-policy` enables Tier 2, else seals use literal PCR 7)"
        ),
    }

    // These envelopes protect different things and can drift independently. A
    // healthy keyring seal says nothing about the template key that face auth
    // must unseal, which is the misleading single-row diagnosis #472 exposed.
    let keyring_path = irlume_core::keyring::envelope_path(&user);
    if !print_seal_diagnostics(
        "keyring seal",
        &keyring_path,
        "the keyring credential can unseal",
        "run `irlume keyring arm` or log in with the typed password to recover and re-bind it",
        "preserve the file and do not force-forget it",
    ) {
        match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
            Ok(Response::HasPassword(true)) => println!(
                "  keyring seal  : armed, but not readable here; run `sudo irlume diag` for PCR-drift detail"
            ),
            Ok(Response::HasPassword(false)) => {
                println!("  keyring seal  : not armed (run `irlume keyring arm`)")
            }
            Ok(_) => println!(
                "  keyring seal  : unknown (daemon returned an unexpected response)"
            ),
            Err(_) => println!("  keyring seal  : unknown (daemon unreachable)"),
        }
    }

    let template_path = irlume_core::template_key::key_path(&user);
    if !print_seal_diagnostics(
        "template seal",
        &template_path,
        "the face-template key can unseal",
        "run `irlume recovery restore`; without a recovery passphrase, re-enroll",
        "preserve the file; run `irlume recovery restore` if a recovery passphrase was set, otherwise re-enroll",
    ) {
        match daemon_request(&Request::RecoveryStatus { user: user.clone() }) {
            Ok(Response::RecoveryStatus {
                encrypted: true,
                key_present: false,
                recovery_set: true,
                ..
            }) => println!(
                "  template seal : MISSING {WARN} (recoverable: run `irlume recovery restore`)"
            ),
            Ok(Response::RecoveryStatus {
                encrypted: true,
                key_present: false,
                recovery_set: false,
                ..
            }) => println!(
                "  template seal : MISSING {NO} (encrypted templates cannot be opened; re-enroll)"
            ),
            Ok(Response::RecoveryStatus {
                encrypted: true,
                recovery_set,
                ..
            }) => println!(
                "  template seal : sealed, but not readable here; recovery passphrase {}; run `sudo irlume diag` for PCR-drift detail",
                if recovery_set { "set" } else { "NOT SET" }
            ),
            Ok(Response::RecoveryStatus {
                encrypted: false, ..
            }) => println!(
                "  template seal : not present (templates are plaintext at rest)"
            ),
            Ok(_) => println!(
                "  template seal : unknown (daemon returned an unexpected response)"
            ),
            Err(_) => println!("  template seal : unknown (daemon unreachable)"),
        }
    }
    ExitCode::SUCCESS
}

/// True when this system plausibly runs SELinux: the policy mountpoint
/// exists or the tooling is installed. Neither being true (plain Arch, most
/// minimal containers) means the module questions have no meaningful answer.
fn selinux_present() -> bool {
    if std::path::Path::new("/sys/fs/selinux").exists() {
        return true;
    }
    // Honor PATH (the integration tests inject a fake `semodule` there; a
    // real SELinux box also may not have it in the fixed /usr slots).
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join("semodule").exists() {
                return true;
            }
        }
    }
    false
}

/// `irlume selinux <status|load>`: manage the policy module that lets the
/// confined greeter (`xdm_t`) reach the daemon socket at login.
pub fn selinux(sub: Option<&str>, _args: &[String]) -> ExitCode {
    // Arch and most non-Fedora distros ship no SELinux at all: there is no
    // policy store and no semodule. On those hosts the old output ("unknown,
    // semodule needs root" plus a bare `ls -Z` filename with no label) read
    // like a broken setup instead of an inapplicable feature.
    if !selinux_present() {
        match sub {
            None | Some("status") => {
                println!("[selinux] SELinux is not present on this system; nothing to manage.");
                return ExitCode::SUCCESS;
            }
            Some("load") => {
                eprintln!(
                    "[selinux] SELinux is not present on this system; there is no policy to load."
                );
                return ExitCode::FAILURE;
            }
            _ => {}
        }
    }
    match sub {
        None | Some("status") => {
            // `semodule -l` needs root; as a normal user it returns nothing, so
            // an empty list ≠ "not loaded". The live socket label is a reliable
            // positive signal either way (only our type_transition sets it).
            let out = std::process::Command::new("semodule").args(["-l"]).output();
            let listed = out
                .as_ref()
                .map(|o| o.status.success() && !o.stdout.is_empty())
                .unwrap_or(false);
            let in_list = out
                .as_ref()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .any(|l| l.trim() == "irlume")
                })
                .unwrap_or(false);
            let label = std::process::Command::new("ls")
                .args(["-Z", irlume_common::SOCKET_PATH])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            let labeled = label.contains("irlume_runtime_t");
            let state = if in_list || labeled {
                format!("loaded {OK}")
            } else if !listed {
                format!("unknown {WARN} (run `sudo irlume selinux status`; semodule needs root)")
            } else {
                format!("not loaded {WARN} (run `sudo irlume selinux load`)")
            };
            println!("[selinux] module 'irlume': {state}");
            // `ls -Z` on a non-SELinux coreutils prints just the filename
            // (or "? path"); only a real label (contains ':') is information.
            if label.contains(':') {
                print!("[selinux] socket label: {label}");
            }
            ExitCode::SUCCESS
        }
        Some("load") => {
            // An explicit override wins outright, and a set-but-missing
            // override is an error rather than a silent fallback (this also
            // keeps the lookup testable on hosts where the packaged .pp
            // really exists).
            let pp = match std::env::var("IRLUME_SELINUX_PP") {
                Ok(p) => std::path::Path::new(&p).exists().then_some(p),
                Err(_) => [
                    // The irlume-selinux rpm's install location; without it a
                    // packaged install could not re-load after `login disable`.
                    "/usr/share/selinux/packages/irlume.pp",
                    "/usr/share/irlume/selinux/irlume.pp",
                    // Dev builds: the repo's own build output, resolved at
                    // COMPILE time. The old entry was the bare relative path
                    // "packaging/selinux/irlume.pp", which made `sudo irlume
                    // selinux load` install whatever .pp sat under the CALLER'S
                    // working directory as system policy.
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../packaging/selinux/irlume.pp"
                    ),
                ]
                .into_iter()
                .find(|p| std::path::Path::new(p).exists())
                .map(String::from),
            };
            let Some(pp) = pp else {
                eprintln!("[selinux] irlume.pp not found; build it: make -f /usr/share/selinux/devel/Makefile -C packaging/selinux irlume.pp");
                return ExitCode::FAILURE;
            };
            eprintln!("[selinux] semodule -i {pp} (needs root)…");
            let st = std::process::Command::new("semodule")
                .args(["-i", &pp])
                .status();
            match st {
                Ok(s) if s.success() => {
                    // Loading the module is half the job: the bound socket
                    // keeps its old label until the daemon rebinds, and under
                    // socket activation not even a restart relabels it. The
                    // shared sequence restarts and restorecons so the check
                    // that sent the user here passes afterwards; a failed
                    // half is reported as exactly that, not as done.
                    match crate::pamwire::relabel_daemon_socket() {
                        Ok(()) => {
                            println!(
                                "[selinux] loaded {OK}; irlumed restarted and the socket relabeled"
                            );
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!(
                                "[selinux] module loaded, but the socket relabel FAILED: {e}; \
                                 the greeter stays blocked until it succeeds"
                            );
                            ExitCode::FAILURE
                        }
                    }
                }
                Ok(s) => {
                    eprintln!("[selinux] semodule exited {s}");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("[selinux] could not run semodule: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("[selinux] unknown subcommand '{other}' (use: status | load)");
            // Usage error, not a runtime failure; see the note in logs::view.
            ExitCode::from(2)
        }
    }
}

/// `irlume deps`: verify the runtime dependencies are present.
/// Resolve a bundled model the way the daemon does: an explicit env path, the
/// packaged /usr/share/irlume/models, then a repo-relative models/ (dev). This is
/// why `doctor`/`deps` must NOT probe cwd-relative `models/` alone; a user runs
/// them from their home dir, where that path never resolves.
pub(crate) fn resolve_model(filename: &str, env_var: &str) -> Option<std::path::PathBuf> {
    resolve_model_candidate(filename, env_var)
        .filter(|c| c.readable)
        .map(|c| c.path)
}

/// The model file this process's search order lands on, for one stage.
///
/// A CANDIDATE, not a claim about the daemon: the daemon's service unit (and
/// any drop-in an administrator added) sets its own environment, which a shell
/// invocation of the CLI cannot observe. This is the same search order the
/// packaged configuration uses, so on a stock install the answer coincides
/// with what the daemon loads; the reporting layers say "candidate" and mean
/// it.
pub(crate) struct ModelCandidate {
    pub path: std::path::PathBuf,
    /// `"caller-env"` when this process's env var chose the path, `"shipped"`
    /// for the packaged/repo locations.
    pub origin: &'static str,
    /// Whether the candidate OPENED as a regular file. `Path::exists()` would
    /// accept a directory or an unreadable file that the daemon's actual
    /// `fs::read` would refuse, so presence is established the way the loader
    /// establishes it.
    pub readable: bool,
}

pub(crate) fn resolve_model_candidate(filename: &str, env_var: &str) -> Option<ModelCandidate> {
    let env = std::env::var_os(env_var)
        .map(|p| (std::path::PathBuf::from(p), "caller-env"))
        .into_iter();
    let bases = [
        "/usr/share/irlume/models",
        "/usr/lib/irlume/models",
        "models",
    ]
    .into_iter()
    .map(|base| (std::path::Path::new(base).join(filename), "shipped"));
    for (path, origin) in env.chain(bases) {
        let readable = match std::fs::File::open(&path) {
            // open() succeeds on a directory; the loader's fs::read would not.
            Ok(f) => f.metadata().map(|m| m.is_file()).unwrap_or(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            // Present but unreadable: this IS the path the search selects, so
            // report it with readable=false rather than falling through to a
            // later candidate the daemon would never reach.
            Err(_) => false,
        };
        return Some(ModelCandidate {
            path,
            origin,
            readable,
        });
    }
    None
}

/// `Some(true)` when the daemon reports models loaded (authoritative; it exits
/// at startup if they can't load); `None` when the daemon is unreachable.
pub(crate) fn daemon_models_loaded() -> Option<bool> {
    matches!(
        daemon_request(&Request::Health),
        Ok(Response::Health { .. })
    )
    .then_some(true)
}

/// The two required models as (filename, daemon-env-var) pairs.
pub(crate) const REQUIRED_MODELS: [(&str, &str); 2] = [
    ("glintr100.onnx", "IRLUME_MODEL"),
    ("face_detection_yunet_2023mar.onnx", "IRLUME_DET_MODEL"),
];

/// Whether onnxruntime is on disk anywhere irlume or a distro puts it. Pure over
/// `exists` so the path set is testable without a filesystem, matching
/// `configured_ort` in irlume-vision.
///
/// The distro paths alone are not enough: the irlume packages bundle their own
/// copy and hand `ORT_DYLIB_PATH` to the daemon through a unit drop-in, which a
/// bare CLI run never sees. Probing only /usr/lib* made `deps` report the
/// runtime missing on a machine where the package had installed it.
fn ort_on_disk(exists: impl Fn(&str) -> bool) -> bool {
    const DISTRO_ORTS: &[&str] = &[
        "/usr/lib64/libonnxruntime.so",
        "/usr/lib/libonnxruntime.so",
        "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
    ];
    DISTRO_ORTS
        .iter()
        .chain(irlume_common::PACKAGED_ORT_PATHS.iter())
        .any(|p| exists(p))
}

pub fn deps(_args: &[String]) -> ExitCode {
    let mut ok = true;
    let mut check = |label: &str, present: bool, hint: &str| {
        println!(
            "  {label:<14}: {}",
            if present {
                OK.to_string()
            } else {
                ok = false;
                format!("{NO} {hint}")
            }
        );
    };
    // The daemon can't load models or run without ONNX Runtime, so a running
    // daemon is proof onnxruntime is present; authoritative and cross-distro
    // (avoids false "missing" on Debian/Ubuntu multiarch, where the lib lives at
    // /usr/lib/x86_64-linux-gnu and the daemon's ORT_DYLIB_PATH env isn't in the
    // user's shell). Fall back to an explicit path or a well-known location.
    let loaded = daemon_models_loaded() == Some(true);
    let ort_env = std::env::var("ORT_DYLIB_PATH")
        .ok()
        .filter(|p| std::path::Path::new(p).exists());
    let ort_sys = ort_on_disk(|p| std::path::Path::new(p).exists());
    check(
        "onnxruntime",
        loaded || ort_env.is_some() || ort_sys,
        "install onnxruntime or set ORT_DYLIB_PATH",
    );
    for (f, env) in REQUIRED_MODELS {
        check(
            f,
            loaded || resolve_model(f, env).is_some(),
            "install the irlume package (or run from the repo)",
        );
    }
    check(
        "TPM",
        tpm_device().is_some(),
        "no /dev/tpmrm0 (sealing unavailable)",
    );
    let have_video = (0..10).any(|n| std::path::Path::new(&format!("/dev/video{n}")).exists());
    check("camera (v4l)", have_video, "no /dev/video* nodes");
    println!(
        "deps: {}",
        if ok {
            format!("all present {OK}")
        } else {
            format!("missing dependencies {WARN}")
        }
    );
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `irlume reseal`: safely re-bind the TPM-sealed login password to the CURRENT
/// PCR state (after a firmware / Secure Boot / kernel update that moved PCR 7).
/// This is the manual, verified path: you re-enter your login password, so a
/// stale seal can never be silently overwritten with a typo (the daemon's
/// automatic reseal only runs in the post-auth session phase for the same
/// reason). Functionally a re-arm against today's PCRs.
/// `irlume biopolicy <on|off|status>`: toggle the opt-in operation-class gate
/// (`enforce_biopolicy` in settings.conf). The daemon reads it live per request,
/// so no restart is needed. Reversible; the password is always the fallback,
/// so enabling it can restrict which services a face may satisfy but never
/// locks anyone out.
pub fn biopolicy(sub: Option<&str>, _args: &[String]) -> ExitCode {
    let visible = irlume_common::config::enforce_biopolicy_visible();
    match sub {
        None | Some("status") => {
            println!(
                "[biopolicy] operation-class gate: {}",
                match visible {
                    Some(true) => "ENFORCING",
                    Some(false) => "off (default)",
                    None => "unknown: root-only setting, re-run with sudo",
                }
            );
            ExitCode::SUCCESS
        }
        Some(v @ ("on" | "off")) => {
            if !crate::is_root() {
                eprintln!("[biopolicy] needs root: sudo irlume biopolicy {v}");
                return ExitCode::FAILURE;
            }
            let val = if v == "on" { "1" } else { "0" };
            match irlume_common::config::write_kv("settings.conf", "enforce_biopolicy", val) {
                Ok(()) => {
                    println!(
                        "[biopolicy] operation-class gate {} (takes effect on the next face auth; \
                         the password is always available).",
                        if v == "on" { "ENABLED" } else { "disabled" }
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("[biopolicy] could not update settings.conf: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("[biopolicy] usage: irlume biopolicy <on|off|status> (got '{other}')");
            ExitCode::from(2)
        }
    }
}

/// `irlume credential-release-challenge [<service>] <on|off|status>`: the
/// per-service head-gesture toggle, plus the global credential-release gate on
/// releasing the sealed login-keyring password (`credential_release_challenge` in
/// settings.conf). The daemon reads all of it live per request, so no restart is
/// needed.
///
/// The keyring gate DEFAULTS OFF: a greeter cold login and logout release the
/// keyring after the face match with no nod, because the gesture is INTENT, not
/// liveness (measured 2026-07-27, the gesture fired on a hand-held print 2 times
/// in 24, so it never stood between a photograph and the credential; the
/// cross-spectrum liveness and PAD cues do, and the typed password is always the
/// fallback). Turning any gesture on adds an experimental additional step;
/// disabling it cannot remove the mandatory keyboard confirmation on a
/// high-privilege service.
/// One service's effective head-gesture line, shared by the all-services
/// `status` and the per-service `<svc> status` so the two can never disagree.
fn print_service_gesture_status(tag: &str, svc: &str) {
    let privileged = irlume_common::pam_service::classify(svc)
        .is_some_and(irlume_common::pam_service::ServiceKind::requires_face_intent_confirmation);
    if privileged {
        println!("{tag} {svc}: Face confirmation: keyboard required");
    }
    let additional = if privileged {
        "Additional head gesture: "
    } else {
        ""
    };
    let key = format!("{}.{svc}", irlume_common::config::SERVICE_GESTURE_KEY);
    match irlume_common::config::observe_kv("settings.conf", &key) {
        // Per-service keys use `!falsy` (the daemon's `service_gesture`
        // reading), NOT the global `truthy`, so the display agrees with
        // what the engine does for this key.
        irlume_common::config::KvObservation::Value(v) => {
            if !irlume_common::config::falsy(&v) {
                if privileged {
                    println!("{tag} {svc}: {additional}on (experimental, explicit)");
                } else {
                    println!("{tag} {svc}: REQUIRED {OK} (explicit)");
                }
            } else {
                println!("{tag} {svc}: {additional}off (explicit)");
            }
        }
        irlume_common::config::KvObservation::Absent => {
            let required = match svc {
                // The keyring release falls back to the global gate,
                // which now defaults OFF.
                "credential_release" => irlume_common::config::credential_release_challenge(),
                // Every PAM service through the shared explicit-only helper.
                _ => irlume_common::config::service_gesture_required(svc),
            };
            if required {
                if privileged {
                    println!("{tag} {svc}: {additional}on (experimental, configured)");
                } else {
                    println!("{tag} {svc}: REQUIRED {OK} (default)");
                }
            } else {
                println!("{tag} {svc}: {additional}off (default)");
            }
        }
        irlume_common::config::KvObservation::Unknown(_) => {
            println!("{tag} {svc}: {additional}root-only setting, re-run with sudo");
        }
    }
}

pub fn credential_release_challenge(sub: Option<&str>, args: &[String]) -> ExitCode {
    const TAG: &str = "[credential-release-challenge]";
    match sub {
        None | Some("status") => {
            // The EFFECTIVE per-service policy, then the global credential-release
            // setting. An absent key reports its effective default, not a guess; an
            // unreadable root-only file says so rather than printing a state it
            // could not read (settings.conf is 0600, so an unprivileged `status`
            // sees Unknown, not the value).
            let services = ["sudo", "su", "doas", "polkit-1", "credential_release"];
            for svc in services {
                print_service_gesture_status(TAG, svc);
            }
            // Global credential-release-challenge fallback (DEFAULT OFF).
            match irlume_common::config::credential_release_challenge_visible() {
                Some(true) => {
                    println!("{TAG} global credential_release_challenge: REQUIRED {OK}")
                }
                Some(false) => {
                    println!("{TAG} global credential_release_challenge: off (default)")
                }
                None => println!(
                    "{TAG} global credential_release_challenge: root-only setting, re-run with sudo"
                ),
            }
            let policy = irlume_common::config::head_consent_policy();
            if matches!(
                policy,
                irlume_common::config::HeadConsentPolicy::LegacyClosure(_)
                    | irlume_common::config::HeadConsentPolicy::Misconfigured(_)
            ) {
                println!(
                    "{TAG} WARNING: {}. Required gates fall back to the password.",
                    policy.instruction("approve")
                );
            }
            ExitCode::SUCCESS
        }
        // Service-specific toggle: irlume credential-release-challenge sudo on|off
        // A flag mistyped before the verb is not a service: under root,
        // `--yes off` used to write `service_gesture.--yes=0` into the
        // root-only settings file, a junk key nothing reads. At 0.9.0 the
        // same argv was a clean usage error; keep it one.
        Some(svc) if svc.starts_with('-') => {
            eprintln!(
                "{TAG} usage: irlume credential-release-challenge [<service>] <on|off|status>"
            );
            ExitCode::from(2)
        }
        Some(svc) if svc != "on" && svc != "off" => {
            // `args` is the whole argv minus the program name (main.rs skips 1
            // and passes the full vector), so args[0] is the subcommand name,
            // args[1] is `svc` (this arm's `sub`), and the on/off token is
            // args[2]. Reading args[0] here matched the literal subcommand and
            // sent every `<service> on|off` to the usage arm (exit 2).
            let on_off = args.get(2).map(String::as_str);
            match on_off {
                Some(v @ ("on" | "off")) => {
                    if !crate::is_root() {
                        eprintln!(
                            "{TAG} needs root: sudo irlume credential-release-challenge {svc} {v}"
                        );
                        return ExitCode::FAILURE;
                    }
                    // A name irlume does not recognise still WRITES, because a
                    // hand-wired PAM service is a real thing and the daemon looks
                    // the key up by whatever name PAM passes. But a typo is far
                    // likelier than a custom stack, and it used to report success
                    // for a service that does not exist: `credential-release-
                    // challenge sudp off` printed "sudp: consent gesture off" and
                    // left a key nothing would ever read. Say which it is.
                    if irlume_common::pam_service::classify(svc).is_none()
                        && svc != "credential_release"
                    {
                        eprintln!(
                            "{TAG} note: '{svc}' is not a PAM service irlume knows \
                             (sudo, su, doas, sudo-i, su-l, runuser, polkit-1, or the \
                             special token credential_release). Writing it anyway: it takes \
                             effect only if a PAM stack really uses that service name."
                        );
                    }
                    let high_priv = irlume_common::pam_service::classify(svc).is_some_and(
                        irlume_common::pam_service::ServiceKind::requires_face_intent_confirmation,
                    );
                    let val = if v == "on" { "1" } else { "0" };
                    let key = format!("{}.{svc}", irlume_common::config::SERVICE_GESTURE_KEY);
                    match irlume_common::config::write_kv("settings.conf", &key, val) {
                        Ok(()) => {
                            if v == "on" && high_priv {
                                println!("{TAG} {svc}: Additional head gesture on (experimental)");
                                eprintln!(
                                    "{TAG} WARNING: the head classifier is not population-qualified and may reject valid attempts. Face confirmation: keyboard required."
                                );
                            } else if v == "off" && high_priv {
                                println!(
                                    "{TAG} {svc}: Additional head gesture off; keyboard confirmation remains required"
                                );
                            } else if v == "on" {
                                println!("{TAG} {svc}: head gesture REQUIRED {OK}");
                            } else {
                                println!("{TAG} {svc}: head gesture off");
                            }
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("{TAG} could not update settings.conf: {e}");
                            ExitCode::FAILURE
                        }
                    }
                }
                // The usage line has always promised `[<service>] <on|off|
                // status>`, and the TUI, setup and doctor all teach the
                // per-service status form, but this arm accepted only on/off:
                // the exact command four surfaces recommended exited 2.
                Some("status") => {
                    print_service_gesture_status(TAG, svc);
                    ExitCode::SUCCESS
                }
                _ => {
                    eprintln!("{TAG} usage: irlume credential-release-challenge [<service>] <on|off|status>");
                    ExitCode::from(2)
                }
            }
        }
        Some(v @ ("on" | "off")) => {
            // Global keyring-release gate. DEFAULT OFF, so `on` is the notable
            // action (it ADDS a deliberate step) and `off` just returns to the
            // default; neither needs a confirmation.
            if !crate::is_root() {
                eprintln!("{TAG} needs root: sudo irlume credential-release-challenge {v}");
                return ExitCode::FAILURE;
            }
            let val = if v == "on" { "1" } else { "0" };
            match irlume_common::config::write_kv(
                "settings.conf",
                irlume_common::config::CREDENTIAL_RELEASE_CHALLENGE_KEY,
                val,
            ) {
                Ok(()) => {
                    if v == "on" {
                        println!(
                            "{TAG} head gesture REQUIRED {OK}: releasing your keyring \
                             password now needs {} after the face match. Takes effect on the \
                             next face auth.",
                            irlume_common::config::head_consent_policy().instruction("approve")
                        );
                    } else {
                        println!(
                            "{TAG} temporal challenge off (the default): the keyring releases \
                             after the face match with no nod. Your typed password still works."
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{TAG} could not update settings.conf: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!(
                "{TAG} usage: irlume credential-release-challenge [<service>] <on|off|status> (got '{other}')"
            );
            ExitCode::from(2)
        }
    }
}

pub fn reseal(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    // Only meaningful if already armed (we never auto-arm from here).
    match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
        Ok(Response::HasPassword(false)) => {
            eprintln!("[reseal] '{user}' has no sealed secret; nothing to re-bind. Run `irlume keyring arm` to set one up.");
            return ExitCode::from(2);
        }
        Ok(Response::HasPassword(true)) => {}
        _ => {
            eprintln!("[reseal] daemon unreachable");
            return ExitCode::FAILURE;
        }
    }
    // A token envelope (#250) heals itself: the session-phase reseal re-seals
    // it from its password wrap on the next typed-password login. Re-arming it
    // here would mint a NEW token and hand it back for a keyring re-key this
    // command does not perform, stranding the keyring on the old one.
    if matches!(
        daemon_request(&Request::KeyringInfo { user: user.clone() }),
        Ok(Response::KeyringInfo {
            kind: Some(irlume_common::KeyringSecretKind::GnomeKeyringToken),
            ..
        })
    ) {
        println!(
            "[reseal] '{user}' is armed with a GNOME keyring token; it re-binds itself on \
             your next password login. To rebuild it from scratch, run `irlume keyring \
             forget` then `irlume keyring arm`."
        );
        return ExitCode::SUCCESS;
    }
    println!("[reseal] Re-binding '{user}'s sealed secret to the current TPM/PCR state.");
    let Some(pw) = prompt_login_password() else {
        return ExitCode::from(2);
    };
    let req = Request::SealPassword {
        kind: None, // let the daemon judge from what the user has
        user,
        // Copy the bytes out rather than moving the `String`: `Zeroizing` owns
        // the buffer and wipes it on drop, and `SecretBytes` wipes the copy.
        password: irlume_common::SecretBytes::new(pw.as_bytes().to_vec()),
    };
    match daemon_request(&req) {
        Ok(Response::PasswordSealed) => {
            println!("[reseal] re-bound to current PCRs {OK}; face unlock will release it again.");
            ExitCode::SUCCESS
        }
        Ok(other) => {
            eprintln!("[reseal] unexpected response: {other:?}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[reseal] failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Shared no-echo login-password prompt with a confirm step (catches typos that
/// would silently break wallet unlock). Falls back to a single piped stdin line
/// for scripts/tests. Returns `None` on mismatch / empty / read error.
///
/// Reads through [`crate::read_password`], so the password and its confirm copy
/// are both wiped on drop. Callers must keep the value inside the wrapper:
/// anything that leaves it, such as `to_string()` or `format!`, produces a
/// plain `String` that nothing wipes.
pub(crate) fn prompt_login_password() -> Option<zeroize::Zeroizing<String>> {
    // Sampled once, and used only to decide whether a confirm prompt makes
    // sense; `read_password` makes the same terminal/pipe split itself.
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let pw = crate::read_password("Login password: ")
        .map_err(|e| eprintln!("{e}"))
        .ok()?;
    // Confirm only on a terminal. On a pipe there is nothing to retype: a
    // second read would consume the NEXT line of the script's stdin and
    // compare the password against whatever happened to follow it.
    if interactive {
        let again = crate::read_password("Confirm login password: ")
            .map_err(|e| eprintln!("{e}"))
            .ok()?;
        if pw != again {
            eprintln!("passwords do not match; aborted (nothing changed).");
            return None;
        }
    }
    if pw.is_empty() {
        eprintln!("empty password; aborted.");
        return None;
    }
    Some(pw)
}

/// `irlume setup`: guided onboarding that ties the existing pieces together:
/// preflight → camera pick → enroll → keyring arm → recovery → fingerprint →
/// login wiring. Each step is opt-in (y/N) on a terminal. With stdin piped
/// this is the SCRIPTED path: every prompt takes its documented default, so
/// enrolment and keyring arming do proceed, which is what makes an unattended
/// `irlume setup` possible.
pub fn setup(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    println!("=== irlume setup for '{user}' ===\n");

    // 1. Preflight.
    println!("[1/7] Preflight");
    if !daemon_up() {
        eprintln!("  daemon not reachable; start it first: sudo systemctl enable --now irlumed");
        return ExitCode::FAILURE;
    }
    println!("  daemon running {OK}");
    let _ = deps(args);
    let (rgb, ir) = crate::camera_pair();
    println!("  cameras: rgb={rgb} ir={ir}");

    // 2. Enroll (reset if already enrolled and the user wants a clean start).
    println!("\n[2/7] Face enrollment");
    let enrolled = matches!(
        daemon_request(&Request::ListProfiles {
            user: user.clone(),
            structured_errors: false,
        }),
        Ok(Response::Enrollment { ref profiles, .. }) if !profiles.is_empty());
    if enrolled {
        println!("  already enrolled.");
        if yes_no(
            "  Re-enroll from scratch (wipes existing profiles)?",
            /* default_yes: */ false,
        ) {
            run_enroll(&user, true);
        }
    } else if yes_no("  Enroll your face now?", /* default_yes: */ true) {
        run_enroll(&user, false);
    }

    // 3. The print defence, offered here because the user has just enrolled the
    // face a printed photograph of it can currently impersonate. Default yes:
    // on the measurements this is the only cue that has ever refused that
    // attack, so the user should have to decline it rather than discover it.
    // The license and provenance are shown either way; irlume does not warrant
    // these weights and says so before fetching them (ADR-0001).
    // Anti-spoof coverage is shipped and default-on since ADR-0013 (ViT RGB
    // PAD + FLIR IR PAD in models-v1), so the old opt-in offer step is gone.
    println!("\n[4/7] Keyring unlock (face login opens your wallet)");
    if yes_no(
        "  Arm keyring unlock now (you'll enter your login password)?",
        /* default_yes: */ true,
    ) {
        if let Some(pw) = prompt_login_password() {
            match daemon_request(&Request::SealPassword {
                kind: None, // let the daemon judge from what the user has
                user: user.clone(),
                // `pw` has to outlive this request for the token branch below,
                // so the bytes are copied rather than moved. The old `.clone()`
                // here left a whole second password on the heap unwiped.
                password: irlume_common::SecretBytes::new(pw.as_bytes().to_vec()),
            }) {
                Ok(Response::PasswordSealed) => println!("  armed {OK}"),
                // GNOME token arm: the wizard runs in the user's session, so
                // it can finish the re-key exactly like `keyring arm`.
                Ok(Response::TokenSealed { token, minted }) => {
                    match crate::finish_token_arm(&user, pw.as_bytes(), token.expose(), minted) {
                        Ok(()) => println!("  armed with a keyring token {OK}"),
                        Err(e) => eprintln!("  arm failed: {e}"),
                    }
                }
                r => eprintln!("  arm failed: {r:?}"),
            }
        }
    }

    // 4. Recovery passphrase + template encryption.
    println!("\n[5/7] Recovery passphrase (encrypts templates; backstop for TPM/firmware changes)");
    if yes_no(
        "  Set a recovery passphrase now?",
        /* default_yes: */ true,
    ) {
        println!("  (run `irlume recovery setup`; it prompts for a separate recovery passphrase)");
    }

    // 5. Fingerprint.
    println!("\n[6/7] Fingerprint (optional companion factor)");
    match irlume_fingerprint::device_name() {
        Some(n) => {
            println!("  reader '{n}' present; manage with `irlume fingerprint add` / `enable`")
        }
        None => println!("  no fingerprint reader detected; skipping"),
    }

    // 6. Login wiring.
    println!("\n[7/7] PAM login wiring");
    println!("  preview the changes with `irlume login enable` (dry-run), then apply with");
    println!("  `sudo irlume login enable --apply` to wire greeters + lock screen.");
    println!("  once wired: at the greeter/lock, leave the password empty and press Enter");
    println!("  to use your face (typing a password never starts the camera).");

    println!("\n=== setup complete. Check `irlume status` any time. Troubleshoot with `irlume logs`. ===");
    ExitCode::SUCCESS
}

/// Enroll via the daemon (capture happens daemon-side; no camera contention).
fn run_enroll(user: &str, reset: bool) {
    eprintln!("  capturing: stay in frame, look at the camera…");
    // Same notice as `irlume enroll`: the daemon's one-time capture-mode
    // probe (#340) can hold this step for up to a minute before the scans.
    eprintln!(
        "  (a camera pair with no measured capture mode is measured first: one time, \
         up to a minute, the IR emitter fires)"
    );
    match daemon_request(&Request::Enroll {
        user: user.into(),
        profile: None,
        scans: None,
        reset,
    }) {
        Ok(Response::Enrolled {
            profile,
            created,
            total,
            ambient_lit,
            ..
        }) => {
            if let Some(n) = ambient_lit.filter(|&n| n > 0) {
                println!(
                    "  {n} scan(s) were lit mainly by the room, not provably by the IR \
                     emitter; dark-room login is unverified. Check it with the lights \
                     off: irlume identify"
                );
            }
            if created {
                println!("  enrolled '{profile}' with {total} scans {OK}");
            } else {
                println!(
                    "  this face is already enrolled as '{profile}'; added scans to it \
                     ({total} total) {OK}"
                );
            }
        }
        r => eprintln!("  enroll failed: {r:?}"),
    }
}

/// Minimal y/N prompt (default applied on empty input or a non-tty).
/// What `setup` should do about the third-party PAD cue on this machine.
///
fn yes_no(q: &str, default_yes: bool) -> bool {
    use std::io::{IsTerminal, Write};
    // No terminal takes the documented default. That is deliberate and covered
    // by `setup_walks_every_step_noninteractively`: `setup` is the SCRIPTED
    // onboarding path, so a piped run is expected to complete rather than stall
    // on a prompt nobody can answer. Commands where the default would be
    // destructive refuse instead: `models enable` refuses outright.
    if !std::io::stdin().is_terminal() {
        return default_yes;
    }
    print!("{q} [{}] ", if default_yes { "Y/n" } else { "y/N" });
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    use std::io::BufRead;
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return default_yes;
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    }
}

/// `irlume help` / no args: top-level command listing.
pub fn help() -> ExitCode {
    println!(
        "\
irlume - local face authentication

USAGE: irlume <command> [options]   (default user = $USER; override with --user U)

SETUP & STATUS
  tui                   guided setup + live dashboard (enroll & configure here)
  setup                 scripted onboarding (enroll, keyring, recovery, wiring)
  status                health dashboard (daemon, enrollment, keyring, cameras)
  detect                script probe; exit 0=ready / 10=partial / 20=absent
  doctor                platform / TPM / Secure Boot / camera / model checks
  support-report [--output FILE.txt] [--since 10m] [--probe]
  trace [record] [--duration 60s] [--output FILE.jsonl]
  trace explain FILE.jsonl [--output FILE.txt]
                        create a private 0600 report; default is read-only and
                        camera-free, while --probe is explicit and root-only
  deps                  verify runtime dependencies (onnxruntime, models, TPM)

ENROLLMENT & AUTH
  enroll [--name N] [--scans K] [--reset]   capture a face profile
  profiles [list|add-scan|rename|delete|forget-model|eyes-open off]   manage profiles
                        (one-release migration only: clears the retired gate;
                        it cannot be turned on, see issue #386)
  identify              1:N \"who is this?\" (all users as root; else scoped to you)
KEYRING / TPM
  keyring <arm|status|forget>     TPM-sealed secret so a login opens your wallet
                        (forget takes --force to erase without re-keying back)
  reseal                re-bind the sealed secret to current PCRs (after a
                        firmware/kernel update); safe, re-enters the password
  recovery <status|setup|restore|forget>   recovery passphrase + encryption
  diag                  TPM seal + PCR-drift diagnostics (run with sudo for detail)

SYSTEM INTEGRATION
  login <status|enable|disable|reconcile> [--with-sudo] [--with-polkit] [--apply]
                        PAM wiring: greeters, lock screen, sudo, and app prompts
                        (--with-polkit lets your face approve Bitwarden/pkexec);
                        reconcile re-applies it after a distro PAM regeneration and
                        applies immediately (no --apply; the self-heal unit runs it)
  logs [-f] [--since T]           the face-auth journal in one view (daemon, PAM, keyring)
  logs debug <on|off>             per-stage pipeline tracing in the daemon (sudo)
  fingerprint <status|add|verify|reset|enable|disable> [--fingerprint-only]
                        fprintd companion; enable = face OR fingerprint (both),
                        --fingerprint-only replaces face with fingerprint
  bitwarden <status|setup> [--apply]
                        install Bitwarden's biometric-unlock polkit action
                        (flatpak/native; snap is handled by snapd already)
  selinux <status|load>           SELinux module for the login greeter
  ir-setup [--dry-run]            configure the IR emitter (sudo; rarely needed,
                        and only ever run when you ask; it writes to the
                        camera, so --dry-run first)
  set-cameras <rgb> <ir>          persist the RGB+IR camera pair (sudo; the TUI
                        camera picker runs this for you)
  camera-tune [--rounds N]        measure whether this camera can stream RGB and
                        IR at once without dimming, and store the answer (sudo)
  camera-mode                     report the capture mode in force for the
                        auto-selected pair, and where that verdict came from
  models [list|add|enable|disable [name]]   opt-in third-party models, measured
                        and checksum-pinned. A PAD entry is a deny-only liveness
                        cue; a recognition entry REPLACES the RGB matcher at its
                        measured threshold. Fetched or user-supplied, never shipped
  biopolicy <on|off|status>       opt-in operation-class gate: restrict which
                        services a face may satisfy (advanced; password unaffected)
  credential-release-challenge [<service>] <on|off|status>
                        optional experimental head gesture: keep nodding to approve;
                        shake your head to decline. Named with a service (sudo, su,
                        doas, polkit-1) it adds or removes that service's gesture;
                        privileged face auth always keeps keyboard confirmation. Bare, it
                        sets the gate on releasing your keyring password, which
                        is OFF by default: a cold login and logout release it on
                        the face match alone
  update [--check]                update via the channel this was installed from
                        (Copr/PPA: runs it; .deb/pkg/source: shows the steps)
  uninstall [--keep-data] [--yes] un-wire PAM, stop the daemon, wipe enrolled
                        data, then show the package-removal command (sudo)
  version                         print the installed irlume version

MACHINE-READABLE OUTPUT (for desktop integrations; see docs/INTEGRATION.md)
  --json                on version, status, doctor, support-report, profiles list, models list,
                        login status, login plan/verify, auth test --events=jsonl:
                        one line of JSON on stdout, stable check ids and error
                        codes, nothing else printed
  --contract N          declare the contract version you implement; omitted
                        always means 1, and an unimplemented one is refused
                        before anything runs

  (developer/benchmark tools are hidden; set IRLUME_DEV=1 to enable them)
"
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod reach_tests {
    use super::{classify_reach, DaemonReach};
    use irlume_common::Response;

    /// The four Ping outcomes, each to its own state. The two that were
    /// collapsed before: `Ok("starting")` (the accept loop answers while
    /// models load) read as Down and earned a restart that reopened the
    /// window, and EACCES read as "not reachable" about a daemon that was
    /// running fine.
    #[test]
    fn ping_outcomes_classify_to_four_distinct_states() {
        assert_eq!(classify_reach(Ok(Response::Pong)), DaemonReach::Running);
        assert_eq!(
            classify_reach(Ok(Response::Ok("starting".into()))),
            DaemonReach::Starting
        );
        assert_eq!(
            classify_reach(Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied
            ))),
            DaemonReach::AccessDenied
        );
        assert_eq!(
            classify_reach(Err(std::io::Error::from(std::io::ErrorKind::TimedOut))),
            DaemonReach::Down
        );
        // A reply that is neither Pong nor Ok is an unusable answer, not a
        // starting daemon.
        assert_eq!(
            classify_reach(Ok(Response::Error("x".into()))),
            DaemonReach::Down
        );
    }
}

#[cfg(test)]
mod origin_tests {
    use super::ort_on_disk;
    use super::version_base;

    /// A packaged install puts onnxruntime somewhere no distro path covers and
    /// exports ORT_DYLIB_PATH to the daemon only, so with irlumed stopped `deps`
    /// used to print "install onnxruntime" on a machine that already had it.
    /// That is the exact moment a user runs `deps`, so the advice has to be right.
    #[test]
    fn deps_finds_onnxruntime_where_the_packages_put_it() {
        for packaged in irlume_common::PACKAGED_ORT_PATHS {
            assert!(
                ort_on_disk(|p| p == *packaged),
                "a package-installed runtime at {packaged} must count as present"
            );
        }
        assert!(
            ort_on_disk(|p| p == "/usr/lib64/libonnxruntime.so"),
            "a distro-installed runtime must still count"
        );
        assert!(
            !ort_on_disk(|_| false),
            "nothing on disk anywhere is still absent"
        );
    }

    use super::{
        arch_names, gz_lists_irlume, installed_version_via, is_copr_repo, latest_release_via,
        ppa_serves_via, ubuntu_codename, version_gt, InstallOrigin,
    };

    #[test]
    fn copr_from_repo_matches_only_our_project() {
        assert!(is_copr_repo(
            "copr:copr.fedorainfracloud.org:archledger:irlume"
        ));
        assert!(!is_copr_repo(
            "copr:copr.fedorainfracloud.org:archledger:linhello"
        ));
        assert!(!is_copr_repo("fedora"));
        assert!(!is_copr_repo("@commandline"));
        assert!(!is_copr_repo("")); // no dnf history record
        assert!(!is_copr_repo("6ecc2dfaa0dc41e5ad51e007707a786b")); // history hash
    }

    #[test]
    fn ubuntu_codename_from_os_release() {
        let ubuntu = "ID=ubuntu\nVERSION_CODENAME=resolute\nUBUNTU_CODENAME=resolute\n";
        assert_eq!(ubuntu_codename(ubuntu).as_deref(), Some("resolute"));
        // Derivative: ID_LIKE carries ubuntu, UBUNTU_CODENAME names the base series.
        let mint = "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=xia\nUBUNTU_CODENAME=noble\n";
        assert_eq!(ubuntu_codename(mint).as_deref(), Some("noble"));
        // Debian proper: PPAs don't apply.
        let debian = "ID=debian\nVERSION_CODENAME=trixie\n";
        assert_eq!(ubuntu_codename(debian), None);
    }

    /// gzip-compress `data` with the system gzip (the same tool the probe
    /// decompresses with, so the round trip is faithful).
    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut child = std::process::Command::new("gzip")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(data).unwrap();
        child.wait_with_output().unwrap().stdout
    }

    // Regression: e429106. ppa_serves probed the lingering dists Release file,
    // which returns 200 long after a series' packages are deleted; the probe
    // must key on an actual `Package: irlume` entry in the Packages index.
    #[test]
    fn gz_lists_irlume_needs_an_actual_package_entry() {
        assert_eq!(
            gz_lists_irlume(&gzip_bytes(
                b"Package: irlume\nVersion: 0.2.1\nArchitecture: amd64\n"
            )),
            Some(true)
        );
        assert_eq!(
            gz_lists_irlume(&gzip_bytes(b"")),
            Some(false),
            "an empty index is not served"
        );
        assert_eq!(
            gz_lists_irlume(&gzip_bytes(b"Package: linhello\nVersion: 1.0\n")),
            Some(false)
        );
        // A partial-name line must not count either (exact-line match).
        assert_eq!(
            gz_lists_irlume(&gzip_bytes(b"Package: irlume-selinux\n")),
            Some(false)
        );
        // Undecompressable input is "cannot tell", NOT "not served": reading
        // it as absence tells a current-LTS user their own archive does not
        // serve them, and it is what made this probe fail intermittently on a
        // loaded CI runner.
        assert_eq!(gz_lists_irlume(b"definitely not gzip data"), None);
    }

    /// A fake tool as a `Command`, not a file: `/bin/sh -c <script>`.
    ///
    /// This is what actually ends the #194 flake, and why the seams take
    /// `Command` values. The first fix wrote fake tool scripts to disk and
    /// exec'd them, which races every OTHER test's fork: a child forked while
    /// the script is write-open inherits that fd until its own exec closes it
    /// (CLOEXEC), and exec of the script fails ETXTBSY while any such copy
    /// exists (every captured flake payload was the spawn-Err fallback, never
    /// wrong content). A warm-up wait shrinks the window; only never writing
    /// an executable at all removes it. /bin/sh predates the test run, so
    /// nothing here can hold it write-open. The probes' appended production
    /// arguments land as the script's unused positional parameters.
    fn fake(script: &str) -> std::process::Command {
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }

    /// A tool whose spawn fails (the offline / not-installed shape).
    fn no_tool() -> std::process::Command {
        std::process::Command::new("/nonexistent-irlume-test-tool")
    }

    // Regression: 0a7ab5c + e429106 + ee54b23. One test so the PATH override
    // is mutated in a single place: (a) installed_version must report the
    // package manager's version, not this binary's compile-time one, on an
    // overlaid install; (b) ppa_serves must be true only when the Packages
    // index lists irlume, false on an empty index or HTTP 404; (c) a network
    // failure must be None (unknown), never "not served".
    #[test]
    fn version_base_strips_release_suffixes() {
        assert_eq!(version_base("0.10.0"), "0.10.0");
        assert_eq!(version_base("0.10.0-1.fc44"), "0.10.0");
        assert_eq!(version_base("0.10.0-0ppa1~resolute1"), "0.10.0");
        assert_eq!(version_base("0.7.0-2"), "0.7.0");
        // A distro "+" revision suffix also strips, so a 0.10.0+r1 local
        // package does not read as skewing from a 0.10.0 binary.
        assert_eq!(version_base("0.10.0+g1"), "0.10.0");
    }

    #[test]
    fn update_probes_query_the_package_manager_and_the_ppa_index() {
        // No PATH mutation, no FAKE_CURL_MODE, no ENV_LOCK, and no files: each
        // probe takes its tool as a Command PARAMETER (#194), and the fakes
        // are `/bin/sh -c`, so nothing executable is ever written. One fake
        // per behaviour replaces the mode variable.

        // (a) 0a7ab5c: the rpm-owned origins ask rpm, and its answer wins over
        // the running binary's own version.
        assert_eq!(
            installed_version_via(
                &InstallOrigin::Copr,
                fake("printf '9.9.9'"),
                no_tool(),
                no_tool()
            ),
            "9.9.9"
        );
        assert_ne!(env!("CARGO_PKG_VERSION"), "9.9.9");
        assert_eq!(
            installed_version_via(
                &InstallOrigin::LocalRpm(String::new()),
                fake("printf '9.9.9'"),
                no_tool(),
                no_tool()
            ),
            "9.9.9"
        );
        // Source installs have no owning package; the binary's version is the
        // documented fallback.
        assert_eq!(
            installed_version_via(
                &InstallOrigin::Source,
                fake("printf '9.9.9'"),
                no_tool(),
                no_tool()
            ),
            env!("CARGO_PKG_VERSION")
        );

        // (b) e429106: an index that lists irlume is served; a 200 with an
        // empty index (the lingering-Release case) is NOT.
        assert_eq!(
            ppa_serves_via(
                fake("printf 'Package: irlume\nVersion: 9.9.9\n' | gzip -c; exit 0"),
                "resolute"
            ),
            Some(true)
        );
        assert_eq!(
            ppa_serves_via(fake("printf '' | gzip -c; exit 0"), "noble"),
            Some(false)
        );
        // (b) a genuine HTTP 404 (curl -f exit 22) is "not served".
        assert_eq!(ppa_serves_via(fake("exit 22"), "trusty"), Some(false));
        // (c) ee54b23: offline / connect failure is unknown, never false.
        assert_eq!(ppa_serves_via(no_tool(), "resolute"), None);
    }

    #[test]
    fn version_gt_compares_numeric_fields_and_ignores_distro_suffixes() {
        assert!(version_gt("0.3.0", "0.2.9"));
        assert!(version_gt("0.10.0", "0.9.9"), "numeric, not lexicographic");
        assert!(version_gt("1.0", "0.9.9.9"));
        assert!(version_gt("0.2.1", "0.2"), "missing fields count as 0");
        assert!(!version_gt("0.2", "0.2.0"));
        assert!(!version_gt("0.2.1", "0.2.1"));
        // The real call is version_gt(release_tag, installed_version), where the
        // installed side may carry a distro suffix (dpkg "0.2.1-0ppa1~resolute1",
        // pacman "0.1.3-1"): a same-upstream tag must not read as newer, and the
        // next upstream tag must.
        assert!(!version_gt("0.2.1", "0.2.1-0ppa1~resolute1"));
        assert!(version_gt("0.2.2", "0.2.1-0ppa1~resolute1"));
        assert!(!version_gt("0.1.3", "0.1.3-1"));
        assert!(version_gt("0.1.4", "0.1.3-1"));
        // Pre-release tags compare as their base version.
        assert!(!version_gt("1.0.0-rc1", "1.0.0"));
        assert!(!version_gt("1.0.0", "1.0.0-rc1"));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn arch_names_map_x86_64_to_the_per_ecosystem_spellings() {
        assert_eq!(arch_names(), ("amd64", "x86_64", "amd64"));
    }

    #[test]
    fn ubuntu_codename_falls_back_to_version_codename() {
        // Older/derivative os-release files may lack UBUNTU_CODENAME entirely.
        let os = "ID=ubuntu\nVERSION_CODENAME=resolute\n";
        assert_eq!(ubuntu_codename(os).as_deref(), Some("resolute"));
    }

    // The release feed is scraped without a JSON dependency; pin what the
    // scanner keeps (package files) and what it must skip (the release title,
    // checksum files) plus the offline degradation to None/empty.
    #[test]
    fn release_feed_parsing_keeps_only_package_assets() {
        // Env-free and file-free like update_probes above (#194): the feed
        // fetcher takes its curl as a Command parameter.
        let body = r#"{"tag_name": "v9.9.9", "name": "irlume 9.9.9", "assets": [{"name": "irlume_9.9.9_amd64.deb"}, {"name": "irlume-9.9.9-1.fc44.x86_64.rpm"}, {"name": "irlume-9.9.9-1-x86_64.pkg.tar.zst"}, {"name": "SHA256SUMS"}]}"#;
        let rel = latest_release_via(fake(&format!("printf '%s' '{body}'")));
        assert_eq!(rel.tag.as_deref(), Some("v9.9.9"));
        assert_eq!(
            rel.assets,
            vec![
                "irlume_9.9.9_amd64.deb".to_string(),
                "irlume-9.9.9-1.fc44.x86_64.rpm".to_string(),
                "irlume-9.9.9-1-x86_64.pkg.tar.zst".to_string(),
            ],
            "the release title and SHA256SUMS are not package assets"
        );

        // Offline (curl connect failure): unknown, never a false answer.
        let rel = latest_release_via(fake("exit 7"));
        assert_eq!(rel.tag, None);
        assert!(rel.assets.is_empty());
    }

    // Regression: 40f0a4d. The pacman update arm pointed at the retired
    // irlume-VERSION-1-arch.pkg.tar.zst release asset, which no release since
    // 0.1.x attaches; the Arch channel is the AUR. The arm is println-only, so
    // this pins the source text: the needles are assembled at runtime so the
    // test's own source never satisfies (or trips) the checks.
    #[test]
    fn pacman_update_path_points_at_the_aur_not_the_retired_asset() {
        let src = include_str!("commands.rs");
        let aur_clone = format!("{}{}", "aur.archlinux.org/", "irlume.git");
        assert!(
            src.contains(&aur_clone),
            "the AUR clone URL must be offered"
        );
        let aur_helper = format!("{} {}", "yay", "-Syu irlume");
        assert!(
            src.contains(&aur_helper),
            "the AUR helper route must be offered"
        );
        let retired_asset = format!("irlume-{}-1-{}", "{ver}", "{pkg_arch}");
        assert!(
            !src.contains(&retired_asset),
            "the retired .pkg.tar.zst release asset must not be referenced"
        );
        let pacman_u = format!("{} {}", "pacman", "-U");
        assert!(
            !src.contains(&pacman_u),
            "no pacman local-file install of a downloaded asset"
        );
    }
}

/// The scan count irlume prints as health must be the count that can
/// actually match, and "the daemon did not say" must not read as zero.
#[test]
fn usable_scans_counts_only_the_loaded_recognizer() {
    let prof = |live: Option<&str>, counts: &[(&str, usize)], scans: usize| {
        irlume_common::ProfileSummary {
            name: "P".into(),
            scans: (0..scans).map(|i| format!("scan{i}")).collect(),
            scans_by_recognizer: counts.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            live_recognizer: live.map(str::to_string),
        }
    };

    // Every template belongs to the loaded space.
    assert_eq!(
        usable_scans(&[prof(Some("embed:a"), &[("embed:a", 11)], 11)]),
        Some(11)
    );
    // The templates belong to a recognizer that is no longer loaded: the
    // profile looks full and can match nothing. This is the case that used to
    // print "11 scan(s) ✅".
    assert_eq!(
        usable_scans(&[prof(Some("embed:b"), &[("embed:a", 11)], 11)]),
        Some(0)
    );
    // Summed across profiles, only the loaded space counting.
    assert_eq!(
        usable_scans(&[
            prof(Some("embed:a"), &[("embed:a", 3)], 3),
            prof(Some("embed:a"), &[("embed:a", 4), ("embed:b", 9)], 13),
        ]),
        Some(7)
    );
    // An older daemon sends no counts: unknown, not zero.
    assert_eq!(usable_scans(&[prof(Some("embed:a"), &[], 11)]), None);
    assert_eq!(usable_scans(&[prof(None, &[("embed:a", 11)], 11)]), None);
    // One silent profile makes the total unknown rather than an undercount.
    assert_eq!(
        usable_scans(&[
            prof(Some("embed:a"), &[("embed:a", 3)], 3),
            prof(None, &[], 5),
        ]),
        None
    );
}

/// `detect` must not decide "not installed" from a list of FHS paths.
///
/// NixOS keeps the binary in /nix/store and links it from
/// /run/current-system/sw/bin, so a packaged and documented install reported
/// `absent: irlumed is not installed` and exit 20, the code an installer
/// reads as "irlume is not on this machine".
#[test]
fn the_daemon_binary_is_found_wherever_the_distro_keeps_it() {
    // The search path is passed IN, never set on the process: the harness runs
    // tests in parallel, and a global PATH change breaks any concurrent test that
    // spawns a program. That is how this first failed in CI, as a package-origin
    // test unwrapping a NotFound under the sanitizer's slower interleaving.
    let dir = std::env::temp_dir().join(format!("irlume-detect-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // An empty search path leaves only the FHS answer, and this machine may
    // legitimately have one, so compare against that fact rather than assume.
    let fhs_present = [
        "/usr/local/bin/irlumed",
        "/usr/bin/irlumed",
        "/run/current-system/sw/bin/irlumed",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists());
    assert_eq!(irlumed_binary_in(Some(dir.as_os_str())), fhs_present);
    assert_eq!(irlumed_binary_in(None), fhs_present);

    // The Nix-shaped case: nowhere in FHS, but on the search path.
    std::fs::write(dir.join("irlumed"), b"#!/bin/sh\n").unwrap();
    assert!(
        irlumed_binary_in(Some(dir.as_os_str())),
        "a daemon on PATH (a Nix profile link) is installed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
