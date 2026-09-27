// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Run the CLI as namespace-root with a private fixed `/usr/bin`, so code that
/// deliberately ignores PATH cannot reach the host's privileged tools. Each
/// directory in `hidden` that exists on the host is covered by an empty tmpfs,
/// so a test can present a machine without what the host ships there (a PAM
/// service, say). Each `(source, destination)` in `binds` puts a test's own
/// directory at a fixed system path, writable, so the CLI works on fixture
/// PAM files where it looks for the real ones.
pub(crate) fn isolated_root_command(
    root: &Path,
    bin: &str,
    args: &[&str],
    tools: &[&str],
    hidden: &[&str],
    binds: &[(&Path, &str)],
) -> Command {
    namespace_command(root, bin, args, tools, hidden, binds, true)
}

/// [`isolated_root_command`] in the host's PID namespace, for a test whose
/// command must see a process the test started outside it: a Unix socket
/// peer's pid is reported as 0 across PID namespaces, and `/proc` shows
/// only the namespace's own processes.
#[allow(
    dead_code,
    reason = "cli_dispatch.rs shares this module and needs no host pid"
)]
pub(crate) fn isolated_root_command_with_host_pids(
    root: &Path,
    bin: &str,
    args: &[&str],
    tools: &[&str],
    hidden: &[&str],
    binds: &[(&Path, &str)],
) -> Command {
    namespace_command(root, bin, args, tools, hidden, binds, false)
}

/// Where the namespace sees the whole host root, read-only, while a missing
/// destination's parent is rebuilt ([`rebuild_parent`]).
const HOST_VIEW: &str = "/run/irlume-test-host";

/// Give the missing destinations under one host `parent` somewhere to be
/// created, without hiding anything else there.
///
/// A destination the host lacks (Debian and Ubuntu have no `/usr/lib/pam.d`)
/// cannot become a mount point under the read-only root. A directory built in
/// the sandbox is mounted over `parent`: one symlink per host entry, pointing
/// into the read-only view of the whole host root at [`HOST_VIEW`] (a host
/// symlink is copied with its own target, so a relative one such as
/// `../lib32/ld-linux.so.2` still resolves from `parent`, and a relative link
/// deeper in a host directory, which is reached through the view, climbs
/// within the view as it does on the host), a real
/// directory for each missing destination, and a real directory for each
/// later mount directly below `parent`, including a rebuilt parent nested in
/// this one, so that mount lands in the rebuilt parent rather than through a
/// symlink into the read-only host view. Re-binding every host entry instead
/// took three arguments per entry and exceeded bubblewrap's 9000 on hosts
/// whose `/usr/lib` holds thousands of entries (Arch, CachyOS).
fn rebuild_parent(
    command: &mut Command,
    root: &Path,
    parent: &Path,
    missing: &[&str],
    later: &[PathBuf],
) {
    assert!(parent != Path::new("/"), "a destination below a directory");
    let below_root = parent.strip_prefix("/").expect("an absolute destination");
    // The view reached from inside `parent`: bubblewrap 0.9 (Ubuntu 24.04)
    // creates later mount points before it pivots into the new root, where an
    // absolute link into /run resolves on the host and fails; a relative one
    // resolves inside the new root either way.
    let up: PathBuf = below_root.components().map(|_| "..").collect();
    let relative_view = up
        .join(HOST_VIEW.strip_prefix('/').expect("an absolute view"))
        .join(below_root);
    let built = root.join("namespace-parents").join(below_root);
    let _ = std::fs::remove_dir_all(&built);
    std::fs::create_dir_all(&built).expect("create the rebuilt parent");
    let mut real_dirs: Vec<std::ffi::OsString> = missing
        .iter()
        .map(|destination| {
            Path::new(destination)
                .file_name()
                .expect("a named destination")
                .to_owned()
        })
        .collect();
    for mount in later {
        if mount.parent() == Some(parent) {
            real_dirs.push(mount.file_name().expect("a named mount").to_owned());
        }
    }
    for entry in std::fs::read_dir(parent).expect("read the destination's parent") {
        let entry = entry.expect("a directory entry");
        let name = entry.file_name();
        if !real_dirs.contains(&name) {
            let target =
                std::fs::read_link(entry.path()).unwrap_or_else(|_| relative_view.join(&name));
            std::os::unix::fs::symlink(target, built.join(&name))
                .expect("link a host entry into the rebuilt parent");
        }
    }
    for name in &real_dirs {
        std::fs::create_dir_all(built.join(name)).expect("create a mount point");
    }
    command.args([
        "--ro-bind",
        built.to_str().unwrap(),
        parent.to_str().unwrap(),
    ]);
}

fn namespace_command(
    root: &Path,
    bin: &str,
    args: &[&str],
    tools: &[&str],
    hidden: &[&str],
    binds: &[(&Path, &str)],
    unshare_pid: bool,
) -> Command {
    let shell = std::fs::canonicalize("/bin/sh").expect("resolve /bin/sh for sandbox");
    let usr_bin = std::fs::canonicalize("/usr/bin").expect("resolve /usr/bin for sandbox");
    let bin_dir = std::fs::canonicalize("/bin").expect("resolve /bin for sandbox");
    let mut masked = Vec::new();
    for prefix in [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ] {
        // Bubblewrap refuses a mount whose destination spelling is a symlink.
        // Canonicalising also deduplicates usr-merge aliases onto the directory
        // they share. An absent optional prefix stays absent under the read-only
        // root and therefore needs no mount.
        if let Ok(canonical) = std::fs::canonicalize(prefix) {
            if canonical.is_dir() && !masked.contains(&canonical) {
                masked.push(canonical);
            }
        }
    }
    let mut command = Command::new("/usr/bin/bwrap");
    command
        .args([
            "--die-with-parent",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--ro-bind",
            "/",
            "/",
        ])
        .args(["--tmpfs", "/run"]);
    // The namespace's root gets an empty home of its own. The host's /root
    // belongs to a uid outside the namespace, so a command that looks for
    // per-account state there (uninstall and the login guards read every
    // account's ~/.local/share/irlume) would otherwise meet a permission
    // error no real root does, and refuse.
    if Path::new("/root").is_dir() {
        command.args(["--tmpfs", "/root"]);
    }
    if unshare_pid {
        command.arg("--unshare-pid");
    }
    // A bind to a destination the host lacks rebuilds its parent
    // (`rebuild_parent`), which would cover a hidden directory or an earlier
    // bind below that parent. Those parents go first, so the hidden
    // directories and the other binds land on top of them, and each rebuilt
    // parent keeps a real directory for every such mount directly below it.
    let (missing, present): (Vec<_>, Vec<_>) = binds
        .iter()
        .partition(|(_, destination)| !Path::new(destination).is_dir());
    // Same canonical spelling rule as the tool prefixes below; a directory the
    // host lacks is already absent under the read-only root.
    let mut hidden: Vec<PathBuf> = hidden
        .iter()
        .filter_map(|dir| std::fs::canonicalize(dir).ok())
        .filter(|canonical| canonical.is_dir())
        .collect();
    // Another account's home this user cannot list is emptied for the same
    // reason as /root: its owner is outside the namespace, and the sweep of
    // every account's ~/.local/share/irlume would meet the permission error
    // a root-squashed home gives real root, and refuse (CI runner images
    // ship such a home).
    for home in unreadable_account_homes() {
        if !hidden.contains(&home) {
            hidden.push(home);
        }
    }
    let mut parents: Vec<(&Path, Vec<&str>)> = Vec::new();
    for (_, destination) in &missing {
        let parent = Path::new(destination)
            .parent()
            .expect("a destination below /");
        match parents.iter_mut().find(|(p, _)| *p == parent) {
            Some((_, names)) => names.push(destination),
            None => parents.push((parent, vec![destination])),
        }
    }
    // An ancestor is rebuilt before a parent nested in it, and keeps a real
    // directory for it (`/etc` before `/etc/systemd` when both `/etc/pam.d`
    // and `/etc/systemd/system` are missing).
    parents.sort_by_key(|(parent, _)| parent.components().count());
    let later: Vec<PathBuf> = hidden
        .iter()
        .cloned()
        .chain(
            present
                .iter()
                .map(|(_, destination)| PathBuf::from(destination)),
        )
        .chain(masked.iter().cloned())
        .chain(parents.iter().map(|(parent, _)| parent.to_path_buf()))
        .collect();
    if !parents.is_empty() {
        command.args(["--ro-bind", "/", HOST_VIEW]);
    }
    for (parent, names) in &parents {
        rebuild_parent(&mut command, root, parent, names, &later);
    }
    for (source, destination) in &missing {
        command.args(["--bind", source.to_str().unwrap(), destination]);
    }
    for dir in &hidden {
        command.args(["--tmpfs", dir.to_str().unwrap()]);
    }
    for (source, destination) in &present {
        command.args(["--bind", source.to_str().unwrap(), destination]);
    }
    for prefix in masked {
        command.args(["--tmpfs", prefix.to_str().unwrap()]);
    }
    for destination in shell_bind_destinations(&usr_bin, &bin_dir) {
        command.args(["--ro-bind", shell.to_str().unwrap(), destination]);
    }
    for tool in tools {
        let fake = root.join("bin").join(tool);
        assert!(fake.is_file(), "missing sandbox fake: {}", fake.display());
        command
            .args(["--ro-bind", fake.to_str().unwrap()])
            .arg(format!("/usr/bin/{tool}"));
    }
    command.args(["--dev", "/dev"]);
    // A fresh procfs needs a PID namespace of its own; otherwise the host's
    // `/proc`, read-only under the root bind, stays in place.
    if unshare_pid {
        command.args(["--proc", "/proc"]);
    }
    command
        .args(["--bind", root.to_str().unwrap(), root.to_str().unwrap()])
        .args(["--chdir", root.join("work").to_str().unwrap(), "--", bin])
        .args(args)
        .env("PATH", "/usr/bin")
        .env("IRLUME_SOCKET", root.join("no-daemon.sock"))
        .env("IRLUME_CONFIG_DIR", root.join("cfg"))
        .env("IRLUME_STATE_DIR", root.join("state"))
        .env("IRLUME_KEYRING_DIR", root.join("keyring"))
        .env("IRLUME_METHOD_CONF", root.join("cfg").join("method"))
        .env_remove("IRLUME_DEV")
        .env_remove("IRLUME_CONSENT_GESTURE")
        .env_remove("ORT_DYLIB_PATH")
        .env_remove("IRLUME_MODEL")
        .env_remove("IRLUME_DET_MODEL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// The homes of the accounts uninstall sweeps (uid 1000 to 60000, as
/// `human_accounts_in` reads `/etc/passwd`) that this process cannot list.
fn unreadable_account_homes() -> Vec<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let mut homes: Vec<PathBuf> = Vec::new();
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let (Some(uid), Some(home)) = (fields.get(2), fields.get(5)) else {
            continue;
        };
        if !uid
            .parse::<u32>()
            .is_ok_and(|uid| (1000..=60000).contains(&uid))
        {
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(home) else {
            continue;
        };
        if canonical.is_dir()
            && canonical != Path::new("/")
            && std::fs::read_dir(&canonical)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
            && !homes.contains(&canonical)
        {
            homes.push(canonical);
        }
    }
    homes
}

/// Fixture scripts use `#!/bin/sh`. A split `/bin` needs its own restored
/// interpreter; usr-merge reaches the `/usr/bin/sh` bind through the alias.
pub(crate) fn shell_bind_destinations(usr_bin: &Path, bin: &Path) -> &'static [&'static str] {
    if usr_bin == bin {
        &["/usr/bin/sh"]
    } else {
        &["/usr/bin/sh", "/bin/sh"]
    }
}

/// Prove the namespace contains none of the resolver's closed command set when
/// no fixtures are supplied, and only fixture aliases when they are supplied.
pub(crate) fn assert_system_command_isolation(root: &Path, tools: &[&str]) {
    const CLOSED: [&str; 5] = [
        "loginctl",
        "gnome-shell",
        "semodule",
        "systemctl",
        "restorecon",
    ];
    let supplied = tools.join(" ");
    let script = format!(
        r#"
set -eu
for name in {}; do
    expected=0
    case " {} " in *" $name "*) expected=1;; esac
    found=0
    for dir in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /run/current-system/sw/bin; do
        candidate="$dir/$name"
        if [ -e "$candidate" ]; then
            [ "$expected" -eq 1 ]
            [ "$candidate" -ef "/usr/bin/$name" ]
            found=1
        fi
    done
    [ "$found" -eq "$expected" ]
done
for name in {}; do
    "/usr/bin/$name" >/dev/null
done
"#,
        CLOSED.join(" "),
        supplied,
        supplied,
    );
    let output = namespace_command(root, "/usr/bin/sh", &["-c", &script], tools, &[], &[], true)
        .output()
        .expect("spawn isolated command-path assertion");
    assert!(
        output.status.success(),
        "isolated command-path assertion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
