//! Actual helper + libpam tests. Explicit root-only synthetic fixture suite:
//! cargo test -p irlume-password-verify --test pam --no-run
//! sudo -n <test-binary> --ignored --nocapture
//! Requires cc, Linux-PAM headers and pam_wrapper; missing prerequisites FAIL.
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], secret: &[u8], fixture: Option<(&Path, &Path)>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_irlume-password-verify"));
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((wrapper, directory)) = fixture {
        command
            .env("LD_PRELOAD", wrapper)
            .env("PAM_WRAPPER", "1")
            .env("PAM_WRAPPER_SERVICE_DIR", directory);
    }
    let mut child = command.spawn().unwrap();
    // A rejected invocation can close the pipe before we finish writing.
    let _ = child.stdin.take().unwrap().write_all(secret);
    child.wait_with_output().unwrap()
}

#[test]
fn unprivileged_invocation_is_unavailable() {
    // SAFETY: getuid has no preconditions or borrowed memory.
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    let output = run(&["synthetic-user"], b"synthetic-test-password", None);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
#[ignore = "requires root, cc and pam_wrapper; private synthetic fixtures only"]
fn actual_pam_contract() {
    assert_eq!(
        // SAFETY: getuid has no preconditions or borrowed memory.
        unsafe { libc::getuid() },
        0,
        "run this synthetic fixture as root"
    );
    let wrapper = [
        "/usr/lib64/libpam_wrapper.so",
        "/usr/lib/x86_64-linux-gnu/libpam_wrapper.so",
    ]
    .into_iter()
    .map(Path::new)
    .find(|p| p.exists())
    .expect("pam_wrapper required");
    let temp = tempfile::tempdir().unwrap();
    let module = temp.path().join("fixture.so");
    assert!(Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixture.c"))
        .arg("-lpam")
        .arg("-o")
        .arg(&module)
        .status()
        .unwrap()
        .success());
    let service = temp.path().join("irlume-retry-reset");
    let cases: Vec<(&str, &[&str], Vec<u8>, i32)> = vec![
        (
            "normal",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            0,
        ),
        ("normal", &["synthetic-user"], b"wrong".to_vec(), 1),
        (
            "expired",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            1,
        ),
        (
            "change-required",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            1,
        ),
        (
            "no-prompt",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        (
            "echo",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        (
            "repeat",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        (
            "ignore-repeat",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        (
            "ignore-repeat-info",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        (
            "mutate",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        (
            "end-repeat",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        ("normal", &[], b"synthetic-test-password".to_vec(), 2),
        (
            "normal",
            &["synthetic-user", "other"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
        ("normal", &[""], b"synthetic-test-password".to_vec(), 2),
        ("normal", &["synthetic-user"], Vec::new(), 2),
        ("normal", &["synthetic-user"], vec![b'x'; 4097], 2),
        (
            "normal",
            &["synthetic-user"],
            b"synthetic-test-password\0".to_vec(),
            2,
        ),
        ("normal", &["synthetic-user"], vec![b'x'; 4096], 1),
        (
            "hang",
            &["synthetic-user"],
            b"synthetic-test-password".to_vec(),
            2,
        ),
    ];
    for (mode, args, secret, expected) in cases {
        std::fs::write(
            &service,
            format!(
                "auth required {} {mode}\naccount required {} {mode}\n",
                module.display(),
                module.display()
            ),
        )
        .unwrap();
        let output = run(args, &secret, Some((wrapper, temp.path())));
        assert_eq!(
            output.status.code(),
            Some(expected),
            "case {mode}, args {args:?}, input size {}",
            secret.len()
        );
        assert!(output.stdout.is_empty(), "stdout in {mode}");
        assert!(
            !output
                .stderr
                .windows(b"synthetic-test-password".len())
                .any(|s| s == b"synthetic-test-password"),
            "credential in stderr"
        );
    }
    // On oversized input, consume only the bounded 4097-byte rejection probe.
    // Retaining a duplicate read end lets us observe unread transport bytes
    // after the actual helper exits, without inspecting secret memory.
    let (mut sender, mut receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let input: std::os::fd::OwnedFd = receiver.try_clone().unwrap().into();
    let child = Command::new(env!("CARGO_BIN_EXE_irlume-password-verify"))
        .env_clear()
        .arg("synthetic-user")
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    sender.write_all(&[b'x'; 6000]).unwrap();
    sender.shutdown(std::net::Shutdown::Write).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let mut unread = Vec::new();
    std::io::Read::read_to_end(&mut receiver, &mut unread).unwrap();
    assert_eq!(
        unread.len(),
        6000 - 4097,
        "helper must not buffer beyond its rejection bound"
    );

    std::fs::write(service, "auth required /nonexistent/irlume-test-module.so\naccount required /nonexistent/irlume-test-module.so\n").unwrap();
    assert_eq!(
        run(
            &["synthetic-user"],
            b"synthetic-test-password",
            Some((wrapper, temp.path()))
        )
        .status
        .code(),
        Some(2)
    );
}
