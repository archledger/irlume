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
pub fn update(args: &[String]) -> ExitCode {
    let check_only = args.iter().any(|a| a == "--check" || a == "-n");
    let origin = install_origin();
    // The version the package manager actually has installed (the source of
    // truth for "is a newer one out?"), not just this binary's compiled version
    // (which can differ from the package on a dev/overlaid box).
    let current = installed_version(&origin);
    println!("[update] installed: {current}");
    println!("[update] install method: {}", origin.describe());

    let latest = latest_release_tag();
    let newer = match &latest {
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
            println!("    git lfs pull && cargo build --release && sudo bash scripts/install-host.sh --ort <libonnxruntime.so>");
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
    let out = std::process::Command::new("curl")
        .args(["-fsS", "--max-time", "8", &url])
        .output()
        .ok()?;
    match out.status.code() {
        Some(0) => Some(gz_lists_irlume(&out.stdout)),
        Some(22) => Some(false), // curl -f exits 22 on HTTP >= 400 (404) → not served
        _ => None,               // DNS/connect/timeout → couldn't tell
    }
}

/// Does a gzipped Debian `Packages` index list our package? Decompresses via
/// `gzip -dc` (no bundled zlib) and looks for a `Package: irlume` line. The
/// index is tiny (one package), so writing it to gzip's stdin can't deadlock.
fn gz_lists_irlume(gz: &[u8]) -> bool {
    use std::io::Write;
    let Ok(mut child) = std::process::Command::new("gzip")
        .arg("-dc")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(gz); // si dropped here → EOF to gzip
    }
    let Ok(out) = child.wait_with_output() else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l == "Package: irlume")
}

/// Run each package-manager step with root: directly if we already are, else
/// through interactive sudo so dnf/apt keep their own transaction prompt (the
/// user still confirms the actual change). Stops at the first failure.
fn run_pkg_steps(steps: &[&[&str]]) -> ExitCode {
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
    let pkg = match origin {
        InstallOrigin::Copr | InstallOrigin::LocalRpm(_) => {
            cmd_stdout("rpm", &["-q", "--qf", "%{VERSION}", "irlume"])
        }
        InstallOrigin::Ppa | InstallOrigin::LocalDeb => {
            cmd_stdout("dpkg-query", &["-W", "-f", "${Version}", "irlume"])
        }
        InstallOrigin::ArchPkg => {
            // `pacman -Q irlume` → "irlume 0.1.3-1"; take the version field.
            cmd_stdout("pacman", &["-Q", "irlume"])
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

fn cmd_stdout(prog: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(prog)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Best-effort latest release tag from the GitHub API via curl. None if curl is
/// missing, offline, or the response can't be parsed; the caller degrades to
/// just printing the update method.
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

/// File names of the assets on the latest GitHub release (`.deb`/`.rpm`/pacman
/// packages). Empty when offline or on an API hiccup; callers treat "empty" as
/// "couldn't tell" and fall back to a best-effort URL rather than a false negative.
fn release_assets() -> Vec<String> {
    let Ok(out) = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "8",
            "https://api.github.com/repos/archledger/irlume/releases/latest",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let mut names = Vec::new();
    let mut rest: &str = &body;
    // Scan every "name": "…" and keep the package-file-looking ones (the release
    // title is also a "name" but doesn't end in a package extension).
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
fn release_asset_steps(ver: &str, asset: &str, install_cmd: &str) {
    let assets = release_assets();
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

fn latest_release_tag() -> Option<String> {
    let out = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "8",
            "https://api.github.com/repos/archledger/irlume/releases/latest",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    // Tiny scan for "tag_name": "vX.Y.Z"; avoids a JSON dependency for one field.
    let key = "\"tag_name\"";
    let i = body.find(key)?;
    let after = &body[i + key.len()..];
    let colon = after.find(':')?;
    let q1 = after[colon..].find('"')? + colon + 1;
    let q2 = after[q1..].find('"')? + q1;
    Some(after[q1..q2].to_string())
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
fn daemon_up() -> bool {
    matches!(daemon_request(&Request::Ping), Ok(Response::Pong))
}

/// `irlume status`: one-shot health dashboard. Always exits 0 (it reports state,
/// it doesn't gate anything); use `irlume detect` for script-friendly exit codes.
pub fn status(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    println!("irlume status for '{user}'");

    // Daemon + method.
    let up = daemon_up();
    println!(
        "  daemon        : {}",
        if up {
            format!("running {OK}")
        } else {
            format!("NOT reachable {NO} (systemctl status irlumed)")
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
    match daemon_request(&Request::ListProfiles { user: user.clone() }) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            require_challenge,
        }) if !profiles.is_empty() => {
            let scans: usize = profiles.iter().map(|p| p.scans.len()).sum();
            println!(
                "  enrollment    : {} profile(s), {scans} scan(s) {OK}{}{}",
                profiles.len(),
                if require_eyes_open {
                    " · eyes-open required"
                } else {
                    ""
                },
                if require_challenge {
                    " · passive blink liveness"
                } else {
                    ""
                }
            );
            for p in &profiles {
                println!("                  - {} ({} scan(s))", p.name, p.scans.len());
            }
        }
        Ok(Response::Enrollment { .. }) => {
            println!("  enrollment    : none {WARN} (run `irlume enroll`)")
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
        ..
    }) = daemon_request(&Request::RecoveryStatus { user: user.clone() })
    {
        println!(
            "  templates     : {}",
            if encrypted {
                format!("encrypted at rest {OK}")
            } else {
                format!("plaintext {WARN} (run `irlume recovery setup`)")
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
    let bio = irlume_common::config::read_kv("settings.conf", "enforce_biopolicy")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    println!(
        "  biopolicy     : {}",
        if bio {
            format!("ENFORCING {OK} (operation-class gate)")
        } else {
            "off (default)".into()
        }
    );

    // Cameras.
    let (rgb, ir) = irlume_camera::select_pair();
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
pub fn detect(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    let installed = ["/usr/local/bin/irlumed", "/usr/bin/irlumed"]
        .iter()
        .any(|p| std::path::Path::new(p).exists());
    if !installed {
        println!("absent: irlumed is not installed");
        return ExitCode::from(20);
    }
    let up = daemon_up();
    let enrolled = matches!(
        daemon_request(&Request::ListProfiles { user }),
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

/// `irlume diag`: TPM seal / PCR-drift diagnostics (the dbx/firmware debugger).
/// Needs root + TPM access to read the root-only envelope and replay PCRs; falls
/// back to a daemon-only summary otherwise.
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

    // Keyring envelope: policy kind, bound PCRs, drift (root + TPM only).
    let path = irlume_core::keyring::envelope_path(&user);
    match irlume_core::envelope::SealedEnvelope::load(&path) {
        Ok(env) => {
            let kind = env.policy.describe();
            println!("  seal envelope : {} {OK}", path.display());
            println!("  seal policy   : {kind}, bound PCRs {:?}", env.pcrs);
            match irlume_core::tpm::diagnose_pcrs(&env) {
                Ok(d) if d.is_empty() => println!("  PCR drift     : none {OK} (the seal still satisfies; face unlock will release the password)"),
                Ok(d) => println!("  PCR drift     : DRIFTED at {d:?} {WARN}; unseal will FAIL until you `irlume keyring arm` (or `irlume recovery restore`)"),
                Err(e) => println!("  PCR drift     : could not replay PCRs ({e}); need TPM access (tss group / root)"),
            }
        }
        Err(_) => {
            // No readable envelope: either not armed, or not root.
            match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
                Ok(Response::HasPassword(true)) =>
                    println!("  seal envelope : armed, but not readable here; run `sudo irlume diag` for PCR-drift detail"),
                Ok(Response::HasPassword(false)) =>
                    println!("  seal envelope : not armed (run `irlume keyring arm`)"),
                _ => println!("  seal envelope : unknown (daemon unreachable)"),
            }
        }
    }
    ExitCode::SUCCESS
}

/// `irlume selinux <status|load>`: manage the policy module that lets the
/// confined greeter (`xdm_t`) reach the daemon socket at login.
pub fn selinux(sub: Option<&str>, _args: &[String]) -> ExitCode {
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
            if !label.is_empty() {
                print!("[selinux] socket label: {label}");
            }
            ExitCode::SUCCESS
        }
        Some("load") => {
            let pp = [
                "packaging/selinux/irlume.pp",
                "/usr/share/irlume/selinux/irlume.pp",
            ]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
            let Some(pp) = pp else {
                eprintln!("[selinux] irlume.pp not found; build it: make -f /usr/share/selinux/devel/Makefile -C packaging/selinux irlume.pp");
                return ExitCode::FAILURE;
            };
            eprintln!("[selinux] semodule -i {pp} (needs root)…");
            let st = std::process::Command::new("semodule")
                .args(["-i", pp])
                .status();
            match st {
                Ok(s) if s.success() => {
                    println!("[selinux] loaded {OK}; restart irlumed so the socket relabels");
                    ExitCode::SUCCESS
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
            ExitCode::FAILURE
        }
    }
}

/// `irlume deps`: verify the runtime dependencies are present.
/// Resolve a bundled model the way the daemon does: an explicit env path, the
/// packaged /usr/share/irlume/models, then a repo-relative models/ (dev). This is
/// why `doctor`/`deps` must NOT probe cwd-relative `models/` alone; a user runs
/// them from their home dir, where that path never resolves.
pub(crate) fn resolve_model(filename: &str, env_var: &str) -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os(env_var) {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    for base in [
        "/usr/share/irlume/models",
        "/usr/lib/irlume/models",
        "models",
    ] {
        let p = std::path::Path::new(base).join(filename);
        if p.exists() {
            return Some(p);
        }
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
    let ort_sys = [
        "/usr/lib64/libonnxruntime.so",
        "/usr/lib/libonnxruntime.so",
        "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists());
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
pub fn reseal(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    // Only meaningful if already armed (we never auto-arm from here).
    match daemon_request(&Request::HasSealedPassword { user: user.clone() }) {
        Ok(Response::HasPassword(false)) => {
            eprintln!("[reseal] '{user}' has no sealed password; nothing to re-bind. Run `irlume keyring arm` to set one up.");
            return ExitCode::from(2);
        }
        Ok(Response::HasPassword(true)) => {}
        _ => {
            eprintln!("[reseal] daemon unreachable");
            return ExitCode::FAILURE;
        }
    }
    println!("[reseal] Re-binding '{user}'s sealed password to the current TPM/PCR state.");
    let Some(pw) = prompt_login_password() else {
        return ExitCode::from(2);
    };
    let req = Request::SealPassword {
        user,
        password: irlume_common::SecretBytes::new(pw.into_bytes()),
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
pub(crate) fn prompt_login_password() -> Option<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password("Login password: ").ok()?;
        let b = rpassword::prompt_password("Confirm login password: ").ok()?;
        if a != b {
            eprintln!("passwords do not match; aborted (nothing changed).");
            return None;
        }
        if a.is_empty() {
            eprintln!("empty password; aborted.");
            return None;
        }
        Some(a)
    } else {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).ok()?;
        let pw = line.trim_end_matches(['\n', '\r']).to_string();
        if pw.is_empty() {
            return None;
        }
        Some(pw)
    }
}

/// `irlume setup`: guided onboarding that ties the existing pieces together:
/// preflight → camera pick → enroll → keyring arm → recovery → fingerprint →
/// login wiring. Each step is opt-in (y/N); nothing destructive runs unprompted.
pub fn setup(args: &[String]) -> ExitCode {
    let user = user_arg(args);
    println!("=== irlume setup for '{user}' ===\n");

    // 1. Preflight.
    println!("[1/6] Preflight");
    if !daemon_up() {
        eprintln!("  daemon not reachable; start it first: sudo systemctl enable --now irlumed");
        return ExitCode::FAILURE;
    }
    println!("  daemon running {OK}");
    let _ = deps(args);
    let (rgb, ir) = irlume_camera::select_pair();
    println!("  cameras: rgb={rgb} ir={ir}");

    // 2. Enroll (reset if already enrolled and the user wants a clean start).
    println!("\n[2/6] Face enrollment");
    let enrolled = matches!(daemon_request(&Request::ListProfiles { user: user.clone() }),
        Ok(Response::Enrollment { ref profiles, .. }) if !profiles.is_empty());
    if enrolled {
        println!("  already enrolled.");
        if yes_no("  Re-enroll from scratch (wipes existing profiles)?", false) {
            run_enroll(&user, true);
        }
    } else if yes_no("  Enroll your face now?", true) {
        run_enroll(&user, false);
    }

    // 3. Keyring arm.
    println!("\n[3/6] Keyring unlock (face login opens your wallet)");
    if yes_no(
        "  Arm keyring unlock now (you'll enter your login password)?",
        true,
    ) {
        if let Some(pw) = prompt_login_password() {
            match daemon_request(&Request::SealPassword {
                user: user.clone(),
                password: irlume_common::SecretBytes::new(pw.into_bytes()),
            }) {
                Ok(Response::PasswordSealed) => println!("  armed {OK}"),
                r => eprintln!("  arm failed: {r:?}"),
            }
        }
    }

    // 4. Recovery passphrase + template encryption.
    println!("\n[4/6] Recovery passphrase (encrypts templates; backstop for TPM/firmware changes)");
    if yes_no("  Set a recovery passphrase now?", true) {
        println!("  (run `irlume recovery setup`; it prompts for a separate recovery passphrase)");
    }

    // 5. Fingerprint.
    println!("\n[5/6] Fingerprint (optional companion factor)");
    match irlume_fingerprint::device_name() {
        Some(n) => {
            println!("  reader '{n}' present; manage with `irlume fingerprint add` / `enable`")
        }
        None => println!("  no fingerprint reader detected; skipping"),
    }

    // 6. Login wiring.
    println!("\n[6/6] PAM login wiring");
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
    match daemon_request(&Request::Enroll {
        user: user.into(),
        profile: None,
        scans: None,
        reset,
    }) {
        Ok(Response::Ok(msg)) => println!("  {msg} {OK}"),
        r => eprintln!("  enroll failed: {r:?}"),
    }
}

/// Minimal y/N prompt (default applied on empty input or a non-tty).
fn yes_no(q: &str, default_yes: bool) -> bool {
    use std::io::{IsTerminal, Write};
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
  deps                  verify runtime dependencies (onnxruntime, models, TPM)

ENROLLMENT & AUTH
  enroll [--name N] [--scans K] [--reset]   capture a face profile
  profiles [list|add-scan|rename|delete|eyes-open|challenge <on|off>]   manage profiles
  identify              1:N \"who is this?\" (all users as root; else scoped to you)

KEYRING / TPM
  keyring <arm|status|forget>     TPM-sealed login password for wallet unlock
  reseal                re-bind the sealed password to current PCRs (after a
                        firmware/kernel update); safe, re-enters the password
  recovery <status|setup|restore|forget>   recovery passphrase + encryption
  diag                  TPM seal + PCR-drift diagnostics (run with sudo for detail)

SYSTEM INTEGRATION
  login <status|enable|disable> [--with-sudo] [--apply]   PAM wiring for greeters + lock screen
  logs [-f] [--since T]           the face-auth journal in one view (daemon, PAM, keyring)
  logs debug <on|off>             per-stage pipeline tracing in the daemon (sudo)
  fingerprint <status|add|enable|disable>   fprintd companion factor
  selinux <status|load>           SELinux module for the login greeter
  ir-setup [--dry-run]            auto-configure the IR emitter (sudo; rarely
                        needed; enroll auto-runs it when IR frames are dark)
  set-cameras <rgb> <ir>          persist the RGB+IR camera pair (sudo; the TUI
                        camera picker runs this for you)
  update [--check]                update via the channel this was installed from
                        (Copr/PPA: runs it; .deb/pkg/source: shows the steps)
  version                         print the installed irlume version

  (developer/benchmark tools are hidden; set IRLUME_DEV=1 to enable them)
"
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod origin_tests {
    use super::{is_copr_repo, ubuntu_codename};

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
}
