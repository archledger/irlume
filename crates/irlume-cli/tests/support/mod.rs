// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const COVERAGE_DIR: &str = "llvm-profiles";

fn coverage_output_path(root: &Path, profile: &Path) -> std::io::Result<PathBuf> {
    let name = profile.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "missing LLVM profile filename",
        )
    })?;
    let directory = root.join(COVERAGE_DIR);
    std::fs::create_dir_all(&directory)?;
    // Separate test processes can also live in separate PID namespaces, with
    // identical PIDs. A nonce distinguishes every invocation while retaining
    // LLVM's %p/%m merge patterns. Collection refuses any accidental collision.
    let mut unique =
        std::ffi::OsString::from(format!("namespace-{:032x}-", rand::random::<u128>()));
    unique.push(name);
    Ok(directory.join(unique))
}

fn collect_coverage(root: &Path, profile: &Path) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let open_directory = |path: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
    };
    let root_fd = open_directory(root)?;
    let directory = PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        root_fd.as_raw_fd(),
        COVERAGE_DIR
    ));
    let directory_fd = match open_directory(&directory) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    // Keep reads and unlinks anchored to the validated directory, even if its
    // child-visible name is replaced. Never follow child-provided symlinks.
    let entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory_fd.as_raw_fd()))?;
    let destination = profile
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(destination)?;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "LLVM profile is not a regular file",
            ));
        }
        let mut source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(entry.path())?;
        if !source.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "LLVM profile changed to a non-regular file",
            ));
        }
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(entry.file_name()))?;
        // The fixture and coverage target may be on different filesystems.
        // Never overwrite another invocation's counters or delete the source
        // until its complete copy succeeded.
        std::io::copy(&mut source, &mut target)?;
        target.flush()?;
        std::fs::remove_file(entry.path())?;
    }
    std::fs::remove_dir(directory)
}

/// Preserve namespace profiles before deleting a completed fixture. The test
/// process keeps its inherited LLVM_PROFILE_FILE; only child commands override
/// it. cargo-llvm-cov collects *.profraw directly in that original directory.
pub(crate) fn remove_sandbox(root: &Path) -> std::io::Result<()> {
    let profiles_exist = match std::fs::symlink_metadata(root.join(COVERAGE_DIR)) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if profiles_exist {
        let profile = std::env::var_os("LLVM_PROFILE_FILE").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "LLVM_PROFILE_FILE removed before fixture cleanup",
            )
        })?;
        collect_coverage(root, Path::new(&profile))?;
    }
    std::fs::remove_dir_all(root)
}

/// Fail a successful test on cleanup errors, but preserve an existing panic
/// rather than aborting the test process with a second panic from Drop.
pub(crate) fn cleanup_sandbox(root: &Path) {
    if let Err(error) = remove_sandbox(root) {
        let message = format!("retained fixture {}: {error}", root.display());
        if std::thread::panicking() {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr().lock(), "{message}");
        } else {
            panic!("{message}");
        }
    }
}

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
    namespace_command(root, bin, args, tools, hidden, binds, Namespace::Private)
}

/// Private namespace with CAP_SYS_ADMIN in its own user namespace only, for
/// executing the session view-detachment module. The host root stays read-only.
#[allow(
    dead_code,
    reason = "only LightDM namespace tests use the mount capability"
)]
pub(crate) fn isolated_mount_root_command(
    root: &Path,
    bin: &str,
    args: &[&str],
    tools: &[&str],
    hidden: &[&str],
    binds: &[(&Path, &str)],
) -> Command {
    namespace_command(root, bin, args, tools, hidden, binds, Namespace::Mount)
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
    namespace_command(root, bin, args, tools, hidden, binds, Namespace::HostPids)
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
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A wholly absent parent has no host entries to preserve. A
            // dangling link, including an ancestor, must not become empty.
            for ancestor in parent.ancestors() {
                match std::fs::symlink_metadata(ancestor) {
                    Ok(_) => {
                        assert!(
                            ancestor.is_dir(),
                            "a directory ancestor, not a dangling link"
                        );
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("read the destination's ancestor: {error}"),
                }
            }
            None
        }
        Err(error) => panic!("read the destination's parent: {error}"),
    };
    for entry in entries.into_iter().flatten() {
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

enum Namespace {
    Private,
    HostPids,
    Mount,
}

fn namespace_command(
    root: &Path,
    bin: &str,
    args: &[&str],
    tools: &[&str],
    hidden: &[&str],
    binds: &[(&Path, &str)],
    mode: Namespace,
) -> Command {
    let unshare_pid = !matches!(mode, Namespace::HostPids);
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
        if parent.starts_with("/run") {
            // /run is already a fresh writable tmpfs. Rebuilding it from host
            // entries would hide that tmpfs behind a read-only parent bind.
            command.args(["--dir", parent.to_str().unwrap()]);
        } else {
            rebuild_parent(&mut command, root, parent, names, &later);
        }
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
    if matches!(mode, Namespace::Mount) {
        command.args(["--cap-add", "CAP_SYS_ADMIN"]);
    }
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env(
            "LLVM_PROFILE_FILE",
            coverage_output_path(root, Path::new(&profile))
                .expect("prepare private LLVM profile output"),
        );
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
        .env(
            "IRLUME_TEMPLATE_KEY_DIR",
            root.join("state").join("template-keys"),
        )
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
    let output = namespace_command(
        root,
        "/usr/bin/sh",
        &["-c", &script],
        tools,
        &[],
        &[],
        Namespace::Private,
    )
    .output()
    .expect("spawn isolated command-path assertion");
    assert!(
        output.status.success(),
        "isolated command-path assertion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(test)]
mod parent_tests {
    use super::*;

    #[test]
    fn coverage_names_do_not_collide_between_pid_namespaces() {
        const CHILD: &str = "IRLUME_TEST_COVERAGE_NAME_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let profile =
                coverage_output_path(Path::new(&root), Path::new("probe.profraw")).unwrap();
            println!(
                "profile-name:{}",
                profile.file_name().unwrap().to_str().unwrap()
            );
            println!("profile-pid:{}", std::process::id());
            return;
        }
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.0.join("work")).unwrap();
        let binary = std::env::current_exe().unwrap();
        let test = format!(
            "{}::coverage_names_do_not_collide_between_pid_namespaces",
            module_path!().split_once("::").unwrap().1
        );
        let mut names = Vec::new();
        let mut pids = Vec::new();
        for _ in 0..2 {
            let output = isolated_root_command(
                &fixture.0,
                binary.to_str().unwrap(),
                &["--exact", &test, "--nocapture"],
                &[],
                &[],
                &[],
            )
            .env(CHILD, fixture.0.join("names"))
            .output()
            .unwrap();
            assert!(output.status.success(), "{output:?}");
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("1 passed; 0 failed; 0 ignored"), "{text}");
            names.push(
                text.lines()
                    .find_map(|line| line.strip_prefix("profile-name:"))
                    .unwrap()
                    .to_owned(),
            );
            pids.push(
                text.lines()
                    .find_map(|line| line.strip_prefix("profile-pid:"))
                    .unwrap()
                    .to_owned(),
            );
        }
        assert_eq!(pids[0], pids[1], "the two namespaces must reuse their PID");
        assert_ne!(
            names[0], names[1],
            "different test processes need distinct profile names"
        );
    }

    #[test]
    fn instrumented_namespaces_keep_profiles_and_the_host_read_only() {
        let fixture = Fixture::new();
        let sandbox = fixture.0.join("sandbox");
        let destination = fixture.0.join("profiles");
        std::fs::create_dir_all(sandbox.join("work")).unwrap();
        std::fs::create_dir(&destination).unwrap();
        let source = fixture.0.join("probe.rs");
        let binary = fixture.0.join("probe");
        let outside = fixture.0.join("host-file");
        std::fs::write(&outside, "unchanged").unwrap();
        std::fs::write(
            &source,
            r#"
            fn main() {
                assert!(std::fs::write(std::env::args().nth(1).unwrap(), "changed").is_err());
                println!("instrumented child");
            }
        "#,
        )
        .unwrap();
        let built = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args(["-C", "instrument-coverage"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(built.status.success(), "{built:?}");
        let profile = destination.join("probe-%p-%m.profraw");
        for mode in [Namespace::Private, Namespace::HostPids, Namespace::Mount] {
            let output_path = coverage_output_path(&sandbox, &profile).unwrap();
            let output = namespace_command(
                &sandbox,
                binary.to_str().unwrap(),
                &[outside.to_str().unwrap()],
                &[],
                &[],
                &[],
                mode,
            )
            .env("LLVM_PROFILE_FILE", output_path)
            .output()
            .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            assert_eq!(output.stdout, b"instrumented child\n");
        }
        collect_coverage(&sandbox, &profile).unwrap();
        std::fs::remove_dir_all(&sandbox).unwrap();
        let profiles: Vec<_> = std::fs::read_dir(&destination).unwrap().collect();
        assert_eq!(profiles.len(), 3, "each invocation keeps its own counters");
        for profile in profiles {
            let profile = profile.unwrap();
            assert_eq!(profile.path().extension().unwrap(), "profraw");
            assert!(profile.metadata().unwrap().len() > 0);
        }
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "unchanged");
    }

    #[test]
    fn coverage_collection_refuses_collisions_and_keeps_source_bytes() {
        let fixture = Fixture::new();
        let sandbox = fixture.0.join("sandbox");
        let destination = fixture.0.join("profiles");
        std::fs::create_dir(&destination).unwrap();
        let profile = destination.join("probe.profraw");
        let source = coverage_output_path(&sandbox, &profile).unwrap();
        std::fs::write(&source, "new counters").unwrap();
        let existing = destination.join(source.file_name().unwrap());
        std::fs::write(&existing, "old counters").unwrap();
        assert!(collect_coverage(&sandbox, &profile).is_err());
        assert_eq!(std::fs::read_to_string(&source).unwrap(), "new counters");
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "old counters");
    }

    #[test]
    fn coverage_collection_refuses_non_regular_profiles() {
        let fixture = Fixture::new();
        let sandbox = fixture.0.join("sandbox");
        let profile = fixture.0.join("probe.profraw");
        let source = coverage_output_path(&sandbox, &profile).unwrap();
        let outside = fixture.0.join("outside");
        std::fs::write(&outside, "bounded fixture").unwrap();
        std::os::unix::fs::symlink(&outside, &source).unwrap();
        assert!(collect_coverage(&sandbox, &profile).is_err());
        assert!(source.is_symlink());
    }

    #[test]
    fn coverage_collection_never_follows_a_replaced_directory() {
        let fixture = Fixture::new();
        let sandbox = fixture.0.join("sandbox");
        let sibling = fixture.0.join("sibling");
        std::fs::create_dir(&sandbox).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        let counters = sibling.join("other.profraw");
        std::fs::write(&counters, "unrelated counters").unwrap();
        std::os::unix::fs::symlink(&sibling, sandbox.join(COVERAGE_DIR)).unwrap();
        assert!(collect_coverage(&sandbox, &fixture.0.join("report/probe.profraw")).is_err());
        assert_eq!(
            std::fs::read_to_string(counters).unwrap(),
            "unrelated counters"
        );
        assert!(!fixture.0.join("report/other.profraw").exists());
        assert!(sandbox.join(COVERAGE_DIR).is_symlink());
    }

    #[test]
    fn cleanup_failure_preserves_the_fixture_without_double_panic() {
        const CHILD: &str = "IRLUME_TEST_COVERAGE_CLEANUP_CHILD";
        const ROOT: &str = "IRLUME_TEST_COVERAGE_CLEANUP_ROOT";
        if let Some(mode) = std::env::var_os(CHILD) {
            struct Cleanup(PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    cleanup_sandbox(&self.0);
                }
            }
            let _cleanup = Cleanup(PathBuf::from(std::env::var_os(ROOT).unwrap()));
            if mode == "unwinding" {
                panic!("original assertion failure");
            }
            return;
        }
        let fixture = Fixture::new();
        let sandbox = fixture.0.join("sandbox");
        std::fs::create_dir_all(sandbox.join(COVERAGE_DIR)).unwrap();
        let counters = sandbox.join("retained.profraw");
        std::fs::write(&counters, "retained counters").unwrap();
        // A bounded, non-regular entry forces collection to fail. No global
        // environment mutation and no disk-filling or permission tricks.
        std::os::unix::fs::symlink(&counters, sandbox.join(COVERAGE_DIR).join("bad.profraw"))
            .unwrap();
        let test = format!(
            "{}::cleanup_failure_preserves_the_fixture_without_double_panic",
            module_path!().split_once("::").unwrap().1
        );
        for mode in ["normal", "unwinding"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--nocapture"])
                .env(CHILD, mode)
                .env(ROOT, &sandbox)
                .env(
                    "LLVM_PROFILE_FILE",
                    std::env::var_os("LLVM_PROFILE_FILE")
                        .unwrap_or_else(|| fixture.0.join("report/probe-%p-%m.profraw").into()),
                )
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(101),
                "test failure, not process abort: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("0 passed; 1 failed"),
                "{output:?}"
            );
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains("retained fixture"), "{error}");
            if mode == "unwinding" {
                assert!(error.contains("original assertion failure"), "{error}");
            }
            assert_eq!(
                std::fs::read_to_string(&counters).unwrap(),
                "retained counters"
            );
        }
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "irlume-parent-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn build(&self, parent: &Path) -> PathBuf {
            let destination = parent.join("child");
            rebuild_parent(
                &mut Command::new("/usr/bin/bwrap"),
                &self.0,
                parent,
                &[destination.to_str().unwrap()],
                &[],
            );
            self.0
                .join("namespace-parents")
                .join(parent.strip_prefix("/").unwrap())
        }
        fn refuses(&self, parent: &Path) {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.build(parent)
            }))
            .is_err());
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            cleanup_sandbox(&self.0);
        }
    }

    #[test]
    fn missing_parent_builds_a_real_destination_directory() {
        let fixture = Fixture::new();
        let built = fixture.build(&fixture.0.join("absent/deeper"));
        assert!(built.join("child").is_dir());
        assert!(!built.join("child").is_symlink());
    }

    #[test]
    fn existing_parent_keeps_its_neighbor_entries() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("existing");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("neighbor"), "keep\n").unwrap();
        let built = fixture.build(&parent);
        assert!(built.join("child").is_dir());
        assert!(built.join("neighbor").is_symlink());
        assert_eq!(
            std::fs::read_to_string(parent.join("neighbor")).unwrap(),
            "keep\n"
        );
    }

    #[test]
    fn dangling_parent_is_refused() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("dangling");
        std::os::unix::fs::symlink(fixture.0.join("absent"), &parent).unwrap();
        fixture.refuses(&parent);
    }

    #[test]
    fn dangling_parent_ancestor_is_refused() {
        let fixture = Fixture::new();
        let link = fixture.0.join("dangling");
        std::os::unix::fs::symlink(fixture.0.join("absent"), &link).unwrap();
        fixture.refuses(&link.join("child"));
    }

    #[test]
    fn non_directory_parent_is_refused() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("file");
        std::fs::write(&parent, "not a directory\n").unwrap();
        fixture.refuses(&parent);
    }
}
