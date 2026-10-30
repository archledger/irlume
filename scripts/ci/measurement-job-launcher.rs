// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Private static bootstrap; not an installed executable or a VM admission gate.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("the private launcher supports Linux x86-64 only");

use std::ffi::{c_char, c_int, c_long, CStr, CString, OsString};
use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn execve(path: *const c_char, argv: *const *const c_char, env: *const *const c_char) -> c_int;
}

// Linux v7.2 include/uapi/linux/landlock.h. RESOLVE_UNIX needs ABI 9 or later
// (:329; Documentation/userspace-api/landlock.rst:761-763).
const LANDLOCK_ABI_RESOLVE_UNIX: c_long = 9;
const LANDLOCK_CREATE_RULESET_VERSION: c_long = 1 << 0; // :95
const LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON: c_long = 1 << 1; // :197
const LANDLOCK_RULE_PATH_BENEATH: c_long = 1; // :212
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9; // :411
const LANDLOCK_ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16; // :418
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0; // :492

// x86 uses include/uapi/asm-generic/fcntl.h (asm-generic/Kbuild:11).
const O_NOFOLLOW: c_int = 1 << 17; // fcntl.h:60
const O_CLOEXEC: c_int = 1 << 19; // fcntl.h:66
const O_PATH: c_int = 1 << 21; // fcntl.h:88
const S_IFMT: u32 = 0o170000; // include/uapi/linux/stat.h:9
const S_IFSOCK: u32 = 0o140000; // stat.h:10

/// First three members of `struct landlock_ruleset_attr` (landlock.h:50-66),
/// passed with size 24; the kernel zero-fills the rest (syscalls.c:237-240).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr`, packed (landlock.h:225-241).
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const PYTHON_FLAGS: [&str; 5] = ["-I", "-S", "-B", "-X", "pycache_prefix=/dev/null"];
// The host role's tree: this launcher is its manifest bootstrap member.
const TREE_LAUNCHER: &str = "/opt/irlume/launcher";

fn selected_path(path: &str, name: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && path.bytes().all(|byte| (32..127).contains(&byte))
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path.rsplit('/').next() == Some(name)
}

fn config_path(path: &str) -> bool {
    selected_path(path, "guardian-config.json")
}

fn request_path(path: &str) -> bool {
    selected_path(path, "host-request.json")
}

fn sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The runtime tree holding this launcher: its executable link without
/// `/opt/irlume/launcher`. A link that is not canonical, not printable ASCII,
/// names an unlinked file (proc(5) appends " (deleted)") or leaves no root
/// refuses, so the host role starts only the tree the launcher sits in.
fn tree_root(exe: &[u8]) -> Option<&str> {
    if exe.len() > 4096 || !exe.iter().all(|byte| (32..127).contains(byte)) {
        return None;
    }
    let exe = std::str::from_utf8(exe).ok()?;
    if exe.ends_with(" (deleted)") {
        return None;
    }
    let root = exe.strip_suffix(TREE_LAUNCHER)?;
    if !root.starts_with('/')
        || root
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(root)
}

fn python(interpreter: &str, script: &str, extra: &[&str]) -> Vec<String> {
    [interpreter]
        .into_iter()
        .chain(PYTHON_FLAGS)
        .chain([script])
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn arguments(input: &[OsString]) -> Result<(Vec<CString>, Option<CString>), ()> {
    selected(input, || {
        std::fs::read_link("/proc/self/exe")
            .ok()
            .map(|path| path.into_os_string())
    })
}

/// `exe` yields this process's executable link; only the host role reads it.
fn selected<F>(input: &[OsString], exe: F) -> Result<(Vec<CString>, Option<CString>), ()>
where
    F: FnOnce() -> Option<OsString>,
{
    if input.len() > 3 || input.iter().any(|arg| arg.as_bytes().len() > 4096) {
        return Err(());
    }
    let text: Vec<&str> = input
        .iter()
        .map(|arg| arg.to_str().ok_or(()))
        .collect::<Result<_, _>>()?;
    let mut control = None;
    let argv = match text.as_slice() {
        ["--guest"] => python(
            "/usr/bin/python3",
            "/opt/irlume/measurement-job-boot.py",
            &[],
        ),
        ["--guardian", path, digest] if config_path(path) && sha256_hex(digest) => {
            let folder = path.strip_suffix("guardian-config.json").ok_or(())?;
            control = Some(CString::new(format!("{folder}control.sock")).map_err(|_| ())?);
            python(
                "/usr/bin/python3",
                "/opt/irlume/measurement-job-guardian-native.py",
                &["--service", *path, *digest],
            )
        }
        ["--host", path, digest] if request_path(path) && sha256_hex(digest) => {
            // The tree's own loader, not the host's PT_INTERP, runs the tree's
            // python. The loader options select tree libraries only while
            // every needed name is a member; H's maps check refuses the rest.
            let link = exe().ok_or(())?;
            let root = tree_root(link.as_bytes()).ok_or(())?;
            let mut argv = vec![
                format!("{root}/lib64/ld-linux-x86-64.so.2"),
                "--inhibit-cache".to_owned(),
                "--library-path".to_owned(),
                format!("{root}/lib64"),
            ];
            argv.extend(python(
                &format!("{root}/usr/bin/python3"),
                &format!("{root}/opt/irlume/measurement-job-host.py"),
                &["--request", *path, *digest],
            ));
            argv
        }
        _ => return Err(()),
    };
    let argv = argv
        .into_iter()
        .map(|value| CString::new(value).map_err(|_| ()))
        .collect::<Result<_, _>>()?;
    Ok((argv, control))
}

fn require_abi(version: c_long) -> io::Result<()> {
    if version >= LANDLOCK_ABI_RESOLVE_UNIX {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

fn socket_node_ok(mode: u32) -> bool {
    mode & S_IFMT == S_IFSOCK && mode & 0o7777 == 0o600
}

/// Enforces a Landlock domain on this thread and its later descendants. Connects
/// and addressed sends to pathname servers created outside the domain resolve
/// only the `control` node (else EACCES), pathname binds fail with EACCES and
/// outside abstract servers with EPERM. Like any Landlock domain it also denies
/// `LANDLOCK_ACCESS_FS_REFER` (landlock.h:25-28, ruleset.h:299-305), so renames
/// and links across directories fail with EXDEV (fs.c:1194-1256). Both new
/// descriptors stay open for close_range.
fn confine(control: &CStr) -> io::Result<()> {
    // SAFETY: Linux x86-64 landlock_create_ruleset is syscall 444; with a NULL
    // attribute, size 0 and only the version flag it reads no memory and
    // returns the ABI version (security/landlock/syscalls.c:223-228).
    require_abi(unsafe {
        syscall(
            444,
            std::ptr::null::<RulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    })?;
    let attr = RulesetAttr {
        handled_access_fs: LANDLOCK_ACCESS_FS_RESOLVE_UNIX | LANDLOCK_ACCESS_FS_MAKE_SOCK,
        handled_access_net: 0,
        scoped: LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
    };
    // SAFETY: The kernel copies size_of::<RulesetAttr>() bytes from the live
    // struct and returns a new O_CLOEXEC descriptor (syscalls.c:237, 285-286).
    let ruleset = unsafe {
        syscall(
            444,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0_usize,
        )
    };
    if ruleset < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The path is NUL-terminated and outlives the call. O_PATH opens no
    // file content and O_NOFOLLOW keeps a final symlink as the opened node.
    let node = unsafe { open(control.as_ptr(), O_PATH | O_NOFOLLOW | O_CLOEXEC) };
    if node < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `node` is a descriptor just opened here; ManuallyDrop never closes
    // it, so close_range in replace() remains its only close.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(node) });
    if !socket_node_ok(file.metadata()?.mode()) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let rule = PathBeneathAttr {
        allowed_access: LANDLOCK_ACCESS_FS_RESOLVE_UNIX,
        parent_fd: node,
    };
    // SAFETY: landlock_add_rule is syscall 445; the kernel copies the 12-byte
    // packed rule from the live struct (syscalls.c:356-357) and both
    // descriptors are open.
    if unsafe {
        syscall(
            445,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule as *const PathBeneathAttr,
            0_usize,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: landlock_restrict_self is syscall 446 and reads only its integer
    // arguments. The launcher has one thread, so no TSYNC is needed; the
    // service's no_new_privs is the prerequisite (syscalls.c:542-544).
    if unsafe { syscall(446, ruleset, LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn replace(argv: &[CString], control: Option<&CStr>) -> io::Error {
    let Some(program) = argv.first() else {
        return io::Error::from(io::ErrorKind::InvalidInput);
    };
    let mut pointers: Vec<_> = argv.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let environment = [
        c"LC_ALL=C".as_ptr(),
        c"PATH=/usr/bin:/bin".as_ptr(),
        std::ptr::null(),
    ];
    if let Some(control) = control {
        if let Err(error) = confine(control) {
            return error;
        }
    }
    // SAFETY: This private function is called only by the standalone launcher,
    // after startup with valid/open inherited stdio and before the application
    // starts threads. The only descriptors it opens are confine()'s raw ruleset
    // and O_PATH descriptors, which nothing else closes. The command owns only
    // strings, not File/OwnedFd or pipe-backed Stdio values. No callbacks run.
    // Descriptors >=3 are deliberately discarded; 0..2 remain owned by the
    // invoking service.
    // Linux x86-64 close_range is syscall 436 and takes three unsigned arguments.
    if unsafe { syscall(436, 3_u32, u32::MAX, 0_u32) } != 0 {
        return io::Error::last_os_error();
    }
    // SAFETY: All argument strings and pointer arrays remain alive and unchanged;
    // each string is NUL-terminated and both pointer arrays have a NULL sentinel.
    // The path is the fixed absolute Python, or for the host role the tree's
    // absolute loader. execve never searches PATH or falls back to a shell, and
    // a successful call does not return.
    unsafe { execve(program.as_ptr(), pointers.as_ptr(), environment.as_ptr()) };
    io::Error::last_os_error()
}

fn main() {
    // Limit inspection to the accepted shape plus one rejection lookahead.
    // Rust 1.88 args_os eagerly copies the OS argv before this iterator limit;
    // the caller's fixed shape and enclosing service bound startup resources.
    let input: Vec<_> = std::env::args_os().skip(1).take(4).collect();
    if let Ok((argv, control)) = arguments(&input) {
        let _ = replace(&argv, control.as_deref());
    }
    // Do not log inherited variables, paths or a potentially sensitive argument.
    std::process::exit(77);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    fn values(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn link(path: &str) -> impl FnOnce() -> Option<OsString> + '_ {
        move || Some(OsString::from(path))
    }

    fn never() -> Option<OsString> {
        panic!("the executable link was read")
    }

    fn strings(plan: &[CString]) -> Vec<&str> {
        plan.iter().map(|value| value.to_str().unwrap()).collect()
    }

    #[test]
    fn fixed_roles_have_only_the_selected_python_arguments() {
        let (plan, control) = arguments(&values(&["--guest"])).unwrap();
        assert!(control.is_none());
        assert_eq!(
            strings(&plan),
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "-X",
                "pycache_prefix=/dev/null",
                "/opt/irlume/measurement-job-boot.py"
            ]
        );
    }

    #[test]
    fn guardian_has_a_fixed_entry_and_exact_service_transaction_arguments() {
        let digest = "a".repeat(64);
        let (plan, control) = arguments(&values(&[
            "--guardian",
            "/private/guardian-config.json",
            &digest,
        ]))
        .unwrap();
        assert_eq!(control.as_deref(), Some(c"/private/control.sock"));
        let actual: Vec<_> = plan.iter().map(|value| value.to_str().unwrap()).collect();
        assert_eq!(
            &actual[..6],
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "-X",
                "pycache_prefix=/dev/null"
            ]
        );
        assert_eq!(
            &actual[6..],
            [
                "/opt/irlume/measurement-job-guardian-native.py",
                "--service",
                "/private/guardian-config.json",
                &digest
            ]
        );
    }

    #[test]
    fn malformed_selector_path_and_extra_arguments_refuse() {
        let digest = "b".repeat(64);
        for args in [
            vec![],
            vec!["--unknown"],
            vec!["--host", "extra"],
            vec!["--guest", "extra"],
            vec!["--guardian"],
            vec![
                "--guardian",
                "/private/guardian-config.json",
                &digest,
                "extra",
            ],
        ] {
            assert!(arguments(&values(&args)).is_err(), "{args:?}");
        }
        for path in [
            "relative/guardian-config.json",
            "/a/../guardian-config.json",
            "/a/./guardian-config.json",
            "/a//guardian-config.json",
            "/a/not-guardian-config.json",
            "/a/guardian-config.json/",
            "/a\n/guardian-config.json",
            "/é/guardian-config.json",
        ] {
            assert!(
                arguments(&values(&["--guardian", path, &digest])).is_err(),
                "{path:?}"
            );
        }
        let long = format!("/{}/guardian-config.json", "a".repeat(4096));
        assert!(arguments(&values(&["--guardian", &long, &digest])).is_err());
    }

    #[test]
    fn malformed_digest_and_non_utf8_or_nul_arguments_refuse() {
        for digest in [
            String::new(),
            "A".repeat(64),
            "a".repeat(63),
            "g".repeat(64),
        ] {
            assert!(
                arguments(&values(&["--guardian", "/a/guardian-config.json", &digest])).is_err()
            );
        }
        for invalid in [
            OsString::from_vec(vec![0xff]),
            OsString::from_vec(b"--host\0".to_vec()),
        ] {
            assert!(arguments(&[invalid]).is_err());
        }
    }

    #[test]
    fn path_and_digest_length_boundaries_are_exact() {
        let digest = "0123456789abcdef".repeat(4);
        let mut path = "/a".repeat(2037);
        path.push('a');
        path.push_str("/guardian-config.json");
        assert_eq!(path.len(), 4096);
        assert!(arguments(&values(&["--guardian", &path, &digest])).is_ok());
        path.insert(1, 'a');
        assert_eq!(path.len(), 4097);
        assert!(arguments(&values(&["--guardian", &path, &digest])).is_err());
        let long_digest = "a".repeat(65);
        assert!(arguments(&values(&[
            "--guardian",
            "/a/guardian-config.json",
            &long_digest
        ]))
        .is_err());
    }

    #[test]
    fn guardian_control_socket_is_beside_the_config() {
        let digest = "d".repeat(64);
        for (path, socket) in [
            ("/guardian-config.json", c"/control.sock"),
            (
                "/run/irlume/attempt/guardian-config.json",
                c"/run/irlume/attempt/control.sock",
            ),
        ] {
            let (_, control) = arguments(&values(&["--guardian", path, &digest])).unwrap();
            assert_eq!(control.as_deref(), Some(socket), "{path}");
        }
    }

    #[test]
    fn host_execs_the_tree_loader_with_the_tree_python_and_entry() {
        let digest = "e".repeat(64);
        let request = "/run/user/1000/attempt/host-request.json";
        for (launcher, root) in [
            ("/t/opt/irlume/launcher", "/t"),
            (
                "/home/u/.cache/run 1/root/opt/irlume/launcher",
                "/home/u/.cache/run 1/root",
            ),
        ] {
            let (plan, control) =
                selected(&values(&["--host", request, &digest]), link(launcher)).unwrap();
            assert!(control.is_none(), "{launcher}");
            let expected = [
                format!("{root}/lib64/ld-linux-x86-64.so.2"),
                "--inhibit-cache".into(),
                "--library-path".into(),
                format!("{root}/lib64"),
                format!("{root}/usr/bin/python3"),
                "-I".into(),
                "-S".into(),
                "-B".into(),
                "-X".into(),
                "pycache_prefix=/dev/null".into(),
                format!("{root}/opt/irlume/measurement-job-host.py"),
                "--request".into(),
                request.into(),
                digest.clone(),
            ];
            assert_eq!(strings(&plan), expected, "{launcher}");
        }
    }

    #[test]
    fn host_root_is_the_launcher_path_without_opt_irlume_launcher() {
        for (path, root) in [
            ("/t/opt/irlume/launcher", "/t"),
            ("/a b/~x/opt/irlume/launcher", "/a b/~x"),
            (
                "/t/opt/irlume/launcher/opt/irlume/launcher",
                "/t/opt/irlume/launcher",
            ),
        ] {
            assert_eq!(tree_root(path.as_bytes()), Some(root), "{path}");
        }
        let mut path = "/".to_owned() + &"a".repeat(4075);
        path.push_str("/opt/irlume/launcher");
        assert_eq!(path.len(), 4096);
        assert!(tree_root(path.as_bytes()).is_some());
        path.insert(1, 'a');
        assert!(tree_root(path.as_bytes()).is_none());
        for path in [
            "",
            "/opt/irlume/launcher",
            "opt/irlume/launcher",
            "t/opt/irlume/launcher",
            "/t/opt/irlume/launcher (deleted)",
            "/t/opt/irlume/launcher/",
            "/t/opt/irlume/launcher2",
            "/t/opt/irlume/other",
            "/t/xopt/irlume/launcher",
            "/t/opt/irlume/x/launcher",
            "/t/x/irlume/launcher",
            "/t/opt/x/launcher",
            "/t/launcher",
            "/launcher",
            "//t/opt/irlume/launcher",
            "/t//opt/irlume/launcher",
            "/t/./opt/irlume/launcher",
            "/t/../opt/irlume/launcher",
            "/./opt/irlume/launcher",
            "/../opt/irlume/launcher",
            "/t\n/opt/irlume/launcher",
            "/t\x7f/opt/irlume/launcher",
            "/é/opt/irlume/launcher",
        ] {
            assert_eq!(tree_root(path.as_bytes()), None, "{path:?}");
        }
        assert_eq!(tree_root(b"/\xff/opt/irlume/launcher"), None);
    }

    #[test]
    fn host_request_shape_and_launcher_location_refuse() {
        let digest = "f".repeat(64);
        let good = "/private/host-request.json";
        for args in [
            vec!["--host"],
            vec!["--host", good],
            vec!["--host", good, &digest, "extra"],
            vec!["--host", "--request", good],
            vec!["--host", &digest, good],
        ] {
            assert!(selected(&values(&args), never).is_err(), "{args:?}");
        }
        for path in [
            "relative/host-request.json",
            "/a/../host-request.json",
            "/a/./host-request.json",
            "/a//host-request.json",
            "/a/guardian-config.json",
            "/a/not-host-request.json",
            "/a/host-request.json/",
            "/a/host-request.json.tmp",
            "/a\n/host-request.json",
            "/é/host-request.json",
        ] {
            assert!(
                selected(&values(&["--host", path, &digest]), never).is_err(),
                "{path:?}"
            );
        }
        for bad in [
            String::new(),
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ] {
            assert!(selected(&values(&["--host", good, &bad]), never).is_err());
        }
        for launcher in [
            "/launcher",
            "/opt/irlume/launcher",
            "/t/opt/irlume/launcher (deleted)",
            "/t/x/irlume/launcher",
            "/t/opt/irlume/launcher/",
        ] {
            assert!(
                selected(&values(&["--host", good, &digest]), link(launcher)).is_err(),
                "{launcher}"
            );
        }
        assert!(selected(&values(&["--host", good, &digest]), || None).is_err());
        let mut path = "/a".repeat(2036);
        path.push_str("/host-request.json");
        assert_eq!(path.len(), 4090);
        path.insert_str(1, "bcdef");
        assert_eq!(path.len(), 4095);
        path.insert(1, 'a');
        assert!(selected(
            &values(&["--host", &path, &digest]),
            link("/t/opt/irlume/launcher")
        )
        .is_ok());
        path.insert(1, 'a');
        assert!(selected(&values(&["--host", &path, &digest]), never).is_err());
    }

    #[test]
    fn only_the_host_role_reads_the_executable_link() {
        let digest = "a".repeat(64);
        assert!(selected(&values(&["--guest"]), never).is_ok());
        assert!(selected(
            &values(&["--guardian", "/private/guardian-config.json", &digest]),
            never
        )
        .is_ok());
        assert!(selected(&values(&["--host", "/private/other.json", &digest]), never).is_err());
    }

    #[test]
    fn landlock_requires_the_resolve_unix_abi() {
        for version in [-1, 0, 1, 6, 7, 8] {
            assert!(require_abi(version).is_err(), "{version}");
        }
        for version in [9, 10, 11] {
            assert!(require_abi(version).is_ok(), "{version}");
        }
    }

    #[test]
    fn control_socket_node_must_be_a_socket_with_mode_0600() {
        assert!(socket_node_ok(0o140600));
        for mode in [
            0o140644, 0o140700, 0o140400, 0o140000, 0o140666, 0o141600, 0o142600, 0o144600,
            0o100600, 0o120777, 0o120600, 0o040600, 0o010600, 0o020600, 0o060600,
        ] {
            assert!(!socket_node_ok(mode), "{mode:o}");
        }
    }

    #[test]
    fn landlock_attribute_layouts_match_the_kernel() {
        // First three members of landlock_ruleset_attr; the packed rule is 12
        // bytes (security/landlock/syscalls.c:105-117).
        assert_eq!(std::mem::size_of::<RulesetAttr>(), 24);
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
    }
}
