// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Hold the CLI's authoritative PAM exclusion through token publication.

use std::fs::File;
use std::io;
use std::io::Write as _;
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MODE: &str = "--internal-token-delivery-lock-v1";
const PRIMARY: &str = "/run/irlume/pam.lock";
const BUDGET: Duration = Duration::from_secs(5);
const REFUSAL: &str = "GNOME token delivery could not be proved while holding the PAM lock; check login wiring and install matching irlume/irlumed binaries, then retry; nothing was sealed";

/// The files release only on drop, after the token's durable publication.
pub(super) struct Guard {
    _files: Vec<File>,
}

pub(super) fn acquire(user: &str) -> Result<Guard, &'static str> {
    let deadline = Instant::now() + BUDGET;
    #[cfg(test)]
    if let Some(path) = tests::HELPER_PATH.with(|path| path.borrow().clone()) {
        let mut command = tests::child_command(&path, "ok", user);
        let owner = std::fs::metadata(&path).map_err(|_| REFUSAL)?.uid();
        return observe(&mut command, user, &path, owner, deadline)
            .map(|files| Guard { _files: files })
            .map_err(|_| REFUSAL);
    }
    let helper = trusted_sibling().map_err(|_| REFUSAL)?;
    let mut command = Command::new(&helper.path);
    command
        .arg(MODE)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin:/run/current-system/sw/bin");
    let files =
        observe(&mut command, user, Path::new(PRIMARY), 0, deadline).map_err(|_| REFUSAL)?;
    // An upgrade can replace the sibling while the helper runs. Refuse if its
    // selected path no longer resolves to the same trusted installed image.
    if trusted_sibling().ok().as_ref() != Some(&helper) {
        return Err(REFUSAL);
    }
    Ok(Guard { _files: files })
}

#[derive(PartialEq, Eq)]
struct Image {
    path: PathBuf,
    // Metadata changes catch replacement and in-place package updates.
    dev: u64,
    ino: u64,
    len: u64,
    ctime: (i64, i64),
    mtime: (i64, i64),
}

fn trusted_sibling() -> io::Result<Image> {
    let running = std::env::current_exe()?;
    let helper = running.parent().ok_or_else(invalid)?.join("irlume");
    let resolved = helper.canonicalize()?;
    for path in helper.ancestors().chain(resolved.ancestors()) {
        let m = path.metadata()?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(invalid());
        }
    }
    let m = resolved.metadata()?;
    if !m.is_file() || m.mode() & 0o111 == 0 || m.mode() & 0o6000 != 0 {
        return Err(invalid());
    }
    Ok(Image {
        path: resolved,
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        ctime: (m.ctime(), m.ctime_nsec()),
        mtime: (m.mtime(), m.mtime_nsec()),
    })
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "untrusted token-delivery lock helper",
    )
}

fn observe(
    command: &mut Command,
    user: &str,
    primary: &Path,
    owner: u32,
    deadline: Instant,
) -> io::Result<Vec<File>> {
    if user.is_empty() || user.len() > 4096 || user.contains(['\0', '\n', '\r']) {
        return Err(invalid());
    }
    let (mut parent, child) = UnixStream::pair()?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(invalid)?;
    parent.set_write_timeout(Some(remaining))?;
    parent.write_all(user.as_bytes())?;
    parent.shutdown(Shutdown::Write)?;
    let child: OwnedFd = child.into();
    let result =
        irlume_common::process::output_with_stdin_until(command, Stdio::from(child), deadline);
    // Command retains its configured stdin after spawn. Close that reference
    // on every result, so a dead helper cannot leave the private peer alive.
    command.stdin(Stdio::null());
    let output = result?;
    if !output.status.success() {
        return Err(invalid());
    }
    let files = irlume_common::pam_lock_handoff::receive(&parent, owner, deadline)?;
    validate_primary(&files[0], primary, owner)?;
    Ok(files)
}

fn validate_primary(file: &File, path: &Path, owner: u32) -> io::Result<()> {
    let dir = path.parent().ok_or_else(invalid)?;
    let name = path.file_name().ok_or_else(invalid)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    let m = directory.metadata()?;
    if m.uid() != owner || m.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    let at = Path::new("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join(name);
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(at)?;
    let want = pinned.metadata()?;
    let got = file.metadata()?;
    if !want.is_file()
        || want.uid() != owner
        || want.mode() & 0o077 != 0
        || want.nlink() != 1
        || (want.dev(), want.ino()) != (got.dev(), got.ino())
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::time::Duration;

    thread_local! {
        pub(crate) static HELPER_PATH: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    }

    // A real subprocess and actual flock guard, replacing only the privileged
    // installed CLI boundary for software-TPM unit tests. The CLI parser and
    // normal disable are exercised separately by token_lock integration tests.
    pub(crate) struct HelperFixture(Fixture);
    impl HelperFixture {
        pub(crate) fn install() -> Self {
            let fixture = Fixture::new();
            fixture.file();
            HELPER_PATH.with(|path| {
                assert!(path.borrow().is_none());
                *path.borrow_mut() = Some(fixture.path());
            });
            Self(fixture)
        }
    }
    impl Drop for HelperFixture {
        fn drop(&mut self) {
            HELPER_PATH.with(|path| *path.borrow_mut() = None);
            assert!(
                !self.0.excluded(),
                "a returned operation must release its guard"
            );
        }
    }

    pub(super) fn child_command(path: &Path, mode: &str, account: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "token_delivery::tests::handoff_child",
                "--nocapture",
            ])
            .env("IRLUME_TEST_TOKEN_LOCK_PATH", path)
            .env("IRLUME_TEST_TOKEN_LOCK_MODE", mode)
            .env("IRLUME_TEST_TOKEN_ACCOUNT", account);
        command
    }

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "irlume-token-guard-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("pam.lock")
        }
        fn file(&self) -> File {
            std::fs::OpenOptions::new()
                .write(true)
                .read(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(self.path())
                .unwrap()
        }
        fn command(&self, mode: &str) -> Command {
            child_command(&self.path(), mode, "synthetic-account")
        }
        fn excluded(&self) -> bool {
            let file = self.file();
            // SAFETY: a live fixture descriptor; nonblocking flock cannot wait.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                false
            } else {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                true
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn publication_guard_retains_lock_after_helper_completion() {
        if crate::test_support::isolated(
            "token_delivery::tests::publication_guard_retains_lock_after_helper_completion",
        ) {
            return;
        }
        let _g = crate::test_support::env_read();
        let fixture = Fixture::new();
        let owner = fixture.file().metadata().unwrap().uid();
        let guard = observe(
            &mut fixture.command("ok"),
            "synthetic-account",
            &fixture.path(),
            owner,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(fixture.excluded());
        drop(guard);
        assert!(!fixture.excluded());
    }

    #[test]
    fn primary_identity_rejects_an_unrelated_private_file() {
        let fixture = Fixture::new();
        let file = fixture.file();
        let owner = file.metadata().unwrap().uid();
        validate_primary(&file, &fixture.path(), owner).unwrap();
        let unrelated = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.0.join("other"))
            .unwrap();
        assert!(validate_primary(&unrelated, &fixture.path(), owner).is_err());
        std::fs::rename(fixture.path(), fixture.0.join("retired")).unwrap();
        fixture.file();
        assert!(validate_primary(&file, &fixture.path(), owner).is_err());
    }

    #[test]
    fn helper_failure_and_silent_timeout_never_yield_a_guard() {
        let _g = crate::test_support::env_read();
        let fixture = Fixture::new();
        let owner = fixture.file().metadata().unwrap().uid();
        for mode in ["text", "failure-after-send", "silent"] {
            let result = observe(
                &mut fixture.command(mode),
                "synthetic-account",
                &fixture.path(),
                owner,
                Instant::now() + Duration::from_millis(300),
            );
            assert!(result.is_err(), "{mode}");
        }
        assert!(!fixture.excluded());
    }

    /// Every path the dynamic loader must see inside the private root before
    /// it can start a copied image: the image's ELF interpreter, the search
    /// directories its own and its dependencies' `DT_RPATH`/`DT_RUNPATH`
    /// name, and the resolved file behind each library name. The last part
    /// matters because a store can split one library across outputs behind a
    /// symlink (`libgcc_s.so.1` in the gcc output points into the libgcc
    /// output). Resolution mirrors the loader: each object's `DT_NEEDED`
    /// names are looked up in the search directories, and the objects found
    /// that way are inspected in turn until the closure stops growing. The
    /// interpreter is listed first; the binder groups the directories before
    /// the files so a file bind can land on top of the symlink a directory
    /// bind exposes.
    fn loader_inputs(image: &Path) -> Vec<PathBuf> {
        /// The interpreter, the `DT_NEEDED` names and the `DT_RPATH` /
        /// `DT_RUNPATH` directories of one ELF64 little-endian image.
        fn dynamic(
            bytes: &[u8],
            image: &Path,
        ) -> Option<(Option<PathBuf>, Vec<PathBuf>, Vec<PathBuf>)> {
            fn cstr(bytes: &[u8], start: usize) -> Option<PathBuf> {
                let rest = bytes.get(start..)?;
                let end = start + rest.iter().position(|&b| b == 0)?;
                std::str::from_utf8(bytes.get(start..end)?)
                    .ok()
                    .map(PathBuf::from)
            }

            // ELF64 little-endian headers; any other image is left to the
            // FHS binds above, exactly as before this walk existed.
            if bytes.len() < 0x40 || bytes[..4] != *b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
                return None;
            }
            let u16_at =
                |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
            let u64_at =
                |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
            let (phoff, phentsize, phnum) = (u64_at(0x20), u16_at(0x36), u16_at(0x38));
            let mut interp = None;
            let mut dynamic = None;
            let mut loads = Vec::new();
            for index in 0..phnum {
                let ph = phoff + index * phentsize;
                if ph + 0x38 > bytes.len() {
                    return None;
                }
                let p_type = u32::from_le_bytes(bytes[ph..ph + 4].try_into().unwrap());
                let (p_offset, p_vaddr, p_filesz) =
                    (u64_at(ph + 0x08), u64_at(ph + 0x10), u64_at(ph + 0x20));
                match p_type {
                    1 => loads.push((p_vaddr, p_offset, p_filesz)),
                    2 => dynamic = Some((p_offset, p_filesz)),
                    3 => interp = cstr(bytes, p_offset),
                    _ => {}
                }
            }
            let mut needed = Vec::new();
            let mut search = Vec::new();
            if let Some((dyn_offset, dyn_size)) = dynamic {
                // Dynamic entries pair a tag with a value; the string offsets
                // below refer to DT_STRTAB, itself a virtual address that the
                // PT_LOAD map turns back into a file offset.
                let mut strtab = None;
                let mut strings = Vec::new();
                let mut rpath = Vec::new();
                let mut offset = 0;
                while offset + 16 <= dyn_size {
                    let at = dyn_offset + offset;
                    if at + 16 > bytes.len() {
                        break;
                    }
                    let (tag, value) = (u64_at(at), u64_at(at + 8));
                    match tag {
                        0 => break,
                        1 => strings.push(value),
                        5 => strtab = Some(value),
                        15 | 29 => rpath.push(value),
                        _ => {}
                    }
                    offset += 16;
                }
                let origin_dir = image
                    .parent()
                    .map(|origin| origin.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let strings_at = strtab.and_then(|strtab| {
                    loads.iter().find_map(|(vaddr, file, filesz)| {
                        (*vaddr..*vaddr + *filesz)
                            .contains(&strtab)
                            .then_some(*file + (strtab - *vaddr))
                    })
                });
                if let Some(strings_at) = strings_at {
                    for entry in strings {
                        if let Some(name) = cstr(bytes, strings_at + entry) {
                            needed.push(name);
                        }
                    }
                    for entry in rpath {
                        let Some(entry) = cstr(bytes, strings_at + entry) else {
                            continue;
                        };
                        for dir in entry.to_string_lossy().split(':') {
                            // `$ORIGIN` is the image's own directory. The walk
                            // reads the host image, so this expands to the host
                            // path of the copy's source, which is what the
                            // loader needs bound to follow the same entry.
                            let dir = dir
                                .replace("${ORIGIN}", &origin_dir)
                                .replace("$ORIGIN", &origin_dir);
                            if dir.is_empty() {
                                continue;
                            }
                            let dir = PathBuf::from(dir);
                            if dir.exists() && !search.contains(&dir) {
                                search.push(dir);
                            }
                        }
                    }
                }
            }
            Some((interp, needed, search))
        }

        let mut inputs: Vec<PathBuf> = Vec::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut search: Vec<PathBuf> = Vec::new();
        let mut files: Vec<PathBuf> = Vec::new();
        let mut pending = vec![image.to_path_buf()];
        while let Some(object) = pending.pop() {
            let canonical = object.canonicalize().unwrap_or_else(|_| object.clone());
            if seen.contains(&canonical) {
                continue;
            }
            seen.push(canonical);
            let Ok(bytes) = std::fs::read(&object) else {
                continue;
            };
            let Some((interp, needed, dirs)) = dynamic(&bytes, &object) else {
                continue;
            };
            if let Some(interp) = interp {
                for path in [
                    interp.clone(),
                    interp.canonicalize().unwrap_or(interp.clone()),
                ] {
                    if !files.contains(&path) {
                        files.push(path);
                    }
                }
                pending.push(interp);
            }
            for dir in dirs {
                if !search.contains(&dir) {
                    search.push(dir.clone());
                }
                if !inputs.contains(&dir) {
                    inputs.push(dir);
                }
            }
            for name in needed {
                let Some(hit) = search
                    .iter()
                    .map(|dir| dir.join(&name))
                    .find(|hit| hit.exists())
                else {
                    continue;
                };
                if let Ok(target) = hit.canonicalize() {
                    if !files.contains(&target) {
                        files.push(target);
                    }
                }
                pending.push(hit);
            }
        }
        files.append(&mut inputs);
        files
    }

    #[test]
    fn installed_sibling_and_real_cli_helper_work_in_a_private_root() {
        use std::os::unix::fs::PermissionsExt as _;
        let _g = crate::test_support::env_read();
        let fixture = Fixture::new();
        let exe = std::env::current_exe().unwrap();
        // Instrumented Cargo builds can place this test outside debug/deps.
        // Their runner supplies the CLI's compiler-artifact executable receipt.
        // Keep the ordinary stable workspace build usable without an override.
        let cli = match std::env::var_os("IRLUME_TEST_CLI") {
            Some(path) => PathBuf::from(path),
            None => {
                let deps = exe.parent().unwrap();
                assert_eq!(
                    deps.file_name().unwrap(),
                    "deps",
                    "pass IRLUME_TEST_CLI from Cargo's compiler-artifact executable receipt"
                );
                deps.parent().unwrap().join("irlume")
            }
        };
        assert!(
            cli.is_file(),
            "build the matching workspace CLI before this integration test: {}",
            cli.display()
        );
        for dir in ["trusted", "pam", "units", "lock"] {
            std::fs::create_dir(fixture.0.join(dir)).unwrap();
        }
        std::fs::copy(&exe, fixture.0.join("trusted/irlumed")).unwrap();
        std::fs::copy(&cli, fixture.0.join("trusted/irlume")).unwrap();
        std::fs::copy("/usr/bin/true", fixture.0.join("trusted/success-only")).unwrap();
        for name in ["trusted/irlumed", "trusted/irlume", "trusted/success-only"] {
            std::fs::set_permissions(fixture.0.join(name), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        std::fs::write(
            fixture.0.join("pam/lightdm"),
            "session optional pam_irlume.so reseal\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/lightdm.service",
            fixture.0.join("units/display-manager.service"),
        )
        .unwrap();
        // A new root with root-owned ancestry, not a mount of host /: mapped
        // host uid 0 is nobody in a single-user namespace. Only libraries and
        // our synthetic files are visible. No PAM, bus, TPM or camera is bound.
        // The library trees bound are the FHS ones plus whatever the copied
        // images name for their own loading, so a store-linked image starts
        // here instead of failing execve before any assertion.
        let mut command = Command::new("/usr/bin/bwrap");
        command.args([
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--uid",
            "0",
            "--gid",
            "0",
            "--tmpfs",
            "/",
            "--ro-bind",
            "/usr/lib",
            "/usr/lib",
            "--symlink",
            "usr/lib",
            "/lib",
        ]);
        if Path::new("/usr/lib64").is_dir() {
            command.args([
                "--ro-bind",
                "/usr/lib64",
                "/usr/lib64",
                "--symlink",
                "usr/lib64",
                "/lib64",
            ]);
        }
        // The binds above cover a distro toolchain. An image linked against
        // somewhere else (the NixOS runner links against the store) names its
        // interpreter, its libraries and their search paths outside those
        // trees, and the kernel answers execve with ENOENT for an interpreter
        // the root does not contain. Bind every loader input of the three
        // copied images that the FHS roots do not already provide, read-only
        // and at its absolute path, so the sandbox stays "libraries and our
        // synthetic files" on every toolchain. A silent empty result would
        // only show up on such a host, so the interpreter is asserted below.
        let mut fhs = vec![PathBuf::from("/usr/lib"), PathBuf::from("/lib")];
        if Path::new("/usr/lib64").is_dir() {
            fhs.push(PathBuf::from("/usr/lib64"));
            fhs.push(PathBuf::from("/lib64"));
        }
        let mut inputs: Vec<PathBuf> = Vec::new();
        for image in [&exe, &cli, &PathBuf::from("/usr/bin/true")] {
            for input in loader_inputs(image) {
                if !fhs.iter().any(|root| input.starts_with(root)) && !inputs.contains(&input) {
                    inputs.push(input);
                }
            }
        }
        for input in inputs.iter().filter(|path| path.is_dir()) {
            command.arg("--ro-bind").arg(input).arg(input);
        }
        for input in inputs.iter().filter(|path| !path.is_dir()) {
            command.arg("--ro-bind").arg(input).arg(input);
        }
        command
            .args([
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--dir",
                "/tmp",
                "--dir",
                "/run/lock",
            ])
            .arg("--bind")
            .arg(fixture.0.join("trusted"))
            .arg("/trusted")
            .arg("--bind")
            .arg(fixture.0.join("pam"))
            .arg("/etc/pam.d")
            .arg("--bind")
            .arg(fixture.0.join("units"))
            .arg("/etc/systemd/system")
            .arg("--bind")
            .arg(fixture.0.join("lock"))
            .arg("/run/irlume")
            .args([
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin",
                "--",
                "/trusted/irlumed",
                "--ignored",
                "--exact",
                "token_delivery::tests::root_helper_child",
                "--nocapture",
            ]);
        assert!(
            loader_inputs(&exe)
                .first()
                .is_some_and(|interp| interp.is_file()),
            "the copied images are dynamically linked; the test binary must name its \
             ELF interpreter for the loader binds to cover it"
        );
        let output = irlume_common::process::output_until(
            &mut command,
            Instant::now() + Duration::from_secs(15),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "{output:?}"
        );
    }

    #[test]
    #[ignore = "private root child of the real installed-helper test"]
    fn root_helper_child() {
        use std::os::unix::fs::PermissionsExt as _;
        assert!(!Path::new("/dev/tpm0").exists());
        assert!(!Path::new("/dev/tpmrm0").exists());
        assert!(!Path::new("/dev/video0").exists());
        let guard = acquire("synthetic-account").unwrap();
        assert_eq!(
            guard._files.len(),
            2,
            "primary and legacy locks both transfer"
        );
        let competitor = File::open(PRIMARY).unwrap();
        // SAFETY: live descriptor; a nonblocking call cannot wait.
        let busy = unsafe { libc::flock(competitor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(busy, 0);
        drop(guard);
        // SAFETY: same live descriptor after publication guard drop.
        let free = unsafe { libc::flock(competitor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(free, 0);
        drop(competitor);
        std::fs::set_permissions("/trusted", std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            acquire("synthetic-account").is_err(),
            "writable executable ancestry must refuse"
        );
        std::fs::set_permissions("/trusted", std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename("/trusted/irlume", "/trusted/old-cli").unwrap();
        assert!(
            acquire("synthetic-account").is_err(),
            "missing installed helper must refuse"
        );
        std::fs::copy("/trusted/success-only", "/trusted/irlume").unwrap();
        assert!(
            acquire("synthetic-account").is_err(),
            "a successful older helper with no descriptor proof must refuse"
        );
    }

    #[test]
    #[ignore = "private child of the descriptor handoff regression"]
    fn handoff_child() {
        let path = std::env::var_os("IRLUME_TEST_TOKEN_LOCK_PATH").unwrap();
        let mode = std::env::var("IRLUME_TEST_TOKEN_LOCK_MODE").unwrap();
        // SAFETY: duplicate stdin into a unique owned fd without changing stdin.
        let fd = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(fd >= 0);
        // SAFETY: fd was successfully duplicated and is owned only here.
        let mut socket = UnixStream::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
        let mut input = String::new();
        socket.read_to_string(&mut input).unwrap();
        assert_eq!(input, std::env::var("IRLUME_TEST_TOKEN_ACCOUNT").unwrap());
        if mode == "text" {
            socket.write_all(&[1]).unwrap();
            return;
        }
        if mode == "silent" {
            loop {
                std::thread::park();
            }
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        // SAFETY: the fixture file is live, nonblocking flock cannot wait.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(locked, 0);
        irlume_common::pam_lock_handoff::send(
            &socket,
            &[file],
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        if mode == "failure-after-send" {
            std::process::exit(1);
        }
    }
}
