use std::path::Path;
use std::process::{Command, Stdio};

/// Run the CLI as namespace-root with a private fixed `/usr/bin`, so code that
/// deliberately ignores PATH cannot reach the host's privileged tools.
pub(crate) fn isolated_root_command(
    root: &Path,
    bin: &str,
    args: &[&str],
    tools: &[&str],
) -> Command {
    namespace_command(root, bin, args, tools)
}

fn namespace_command(root: &Path, bin: &str, args: &[&str], tools: &[&str]) -> Command {
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
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--ro-bind",
            "/",
            "/",
        ])
        .args(["--tmpfs", "/run"]);
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
    command
        .args(["--dev", "/dev", "--proc", "/proc"])
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
    let output = namespace_command(root, "/usr/bin/sh", &["-c", &script], tools)
        .output()
        .expect("spawn isolated command-path assertion");
    assert!(
        output.status.success(),
        "isolated command-path assertion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
