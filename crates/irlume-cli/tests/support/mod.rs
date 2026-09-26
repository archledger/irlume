// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::path::Path;
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

/// Bind `source` at `destination` inside the namespace.
///
/// A destination the host lacks (Debian and Ubuntu have no `/usr/lib/pam.d`)
/// cannot become a mount point under the read-only root. Its parent is then
/// covered by a tmpfs holding every host entry again, read-only, which gives
/// the destination somewhere to be created without hiding anything else.
fn bind_args(command: &mut Command, source: &Path, destination: &str) {
    let dest = Path::new(destination);
    if !dest.is_dir() {
        let parent = dest.parent().expect("a destination below /");
        let parent_str = parent.to_str().unwrap();
        command.args(["--tmpfs", parent_str]);
        for entry in std::fs::read_dir(parent).expect("read the destination's parent") {
            let path = entry.expect("a directory entry").path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let path_str = path.to_str().unwrap();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).expect("read a symlink");
                command.args(["--symlink", target.to_str().unwrap(), path_str]);
            } else if meta.is_dir() || meta.is_file() {
                command.args(["--ro-bind", path_str, path_str]);
            }
        }
    }
    command.args(["--bind", source.to_str().unwrap(), destination]);
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
    if unshare_pid {
        command.arg("--unshare-pid");
    }
    // A bind to a destination the host lacks re-mounts the parent's host
    // entries (`bind_args`), which would uncover a hidden directory or an
    // earlier bind below that parent. Those binds go first, so the hidden
    // directories and the other binds land on top of them.
    let (missing, present): (Vec<_>, Vec<_>) = binds
        .iter()
        .partition(|(_, destination)| !Path::new(destination).is_dir());
    for (source, destination) in missing {
        bind_args(&mut command, source, destination);
    }
    for dir in hidden {
        // Same canonical spelling rule as the tool prefixes below; a directory
        // the host lacks is already absent under the read-only root.
        if let Ok(canonical) = std::fs::canonicalize(dir) {
            if canonical.is_dir() {
                command.args(["--tmpfs", canonical.to_str().unwrap()]);
            }
        }
    }
    for (source, destination) in present {
        bind_args(&mut command, source, destination);
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
