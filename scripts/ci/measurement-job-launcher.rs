// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Private static bootstrap; not an installed executable or a VM admission gate.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("the private launcher supports Linux x86-64 only");

use std::ffi::{c_char, c_int, c_long, CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn execve(path: *const c_char, argv: *const *const c_char, env: *const *const c_char) -> c_int;
}

fn config_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && path.bytes().all(|byte| (32..127).contains(&byte))
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path.rsplit('/').next() == Some("guardian-config.json")
}

fn arguments(input: &[OsString]) -> Result<Vec<CString>, ()> {
    if input.len() > 3 || input.iter().any(|arg| arg.as_bytes().len() > 4096) {
        return Err(());
    }
    let text: Vec<&str> = input
        .iter()
        .map(|arg| arg.to_str().ok_or(()))
        .collect::<Result<_, _>>()?;
    let (script, extra) = match text.as_slice() {
        ["--host"] => ("/opt/irlume/measurement-job-guardian-host.py", Vec::new()),
        ["--guest"] => ("/opt/irlume/measurement-job-boot.py", Vec::new()),
        ["--guardian", path, digest]
            if config_path(path)
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            (
                "/opt/irlume/measurement-job-guardian-native.py",
                vec!["--service", *path, *digest],
            )
        }
        _ => return Err(()),
    };
    [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        "-X",
        "pycache_prefix=/dev/null",
        script,
    ]
    .into_iter()
    .chain(extra)
    .map(|value| CString::new(value).map_err(|_| ()))
    .collect()
}

fn replace(argv: &[CString]) -> io::Error {
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
    // SAFETY: This private function is called only by the standalone launcher,
    // after startup with valid/open inherited stdio and before the application
    // starts threads or opens files. The command owns only strings,
    // not File/OwnedFd or pipe-backed Stdio values. No callbacks run. Descriptors
    // >=3 are deliberately discarded; 0..2 remain owned by the invoking service.
    // Linux x86-64 close_range is syscall 436 and takes three unsigned arguments.
    if unsafe { syscall(436, 3_u32, u32::MAX, 0_u32) } != 0 {
        return io::Error::last_os_error();
    }
    // SAFETY: All argument strings and pointer arrays remain alive and unchanged;
    // each string is NUL-terminated and both pointer arrays have a NULL sentinel.
    // The path is the fixed absolute Python entry. execve never searches PATH or
    // falls back to a shell, and a successful call does not return.
    unsafe { execve(program.as_ptr(), pointers.as_ptr(), environment.as_ptr()) };
    io::Error::last_os_error()
}

fn main() {
    // Limit inspection to the accepted shape plus one rejection lookahead.
    // Rust 1.88 args_os eagerly copies the OS argv before this iterator limit;
    // the caller's fixed shape and enclosing service bound startup resources.
    let input: Vec<_> = std::env::args_os().skip(1).take(4).collect();
    if let Ok(argv) = arguments(&input) {
        let _ = replace(&argv);
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

    #[test]
    fn fixed_roles_have_only_the_selected_python_arguments() {
        for (role, script) in [
            ("--host", "/opt/irlume/measurement-job-guardian-host.py"),
            ("--guest", "/opt/irlume/measurement-job-boot.py"),
        ] {
            let plan = arguments(&values(&[role])).unwrap();
            let actual: Vec<_> = plan.iter().map(|value| value.to_str().unwrap()).collect();
            assert_eq!(
                actual,
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-B",
                    "-X",
                    "pycache_prefix=/dev/null",
                    script
                ]
            );
        }
    }

    #[test]
    fn guardian_has_a_fixed_entry_and_exact_service_transaction_arguments() {
        let digest = "a".repeat(64);
        let plan = arguments(&values(&[
            "--guardian",
            "/private/guardian-config.json",
            &digest,
        ]))
        .unwrap();
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
}
