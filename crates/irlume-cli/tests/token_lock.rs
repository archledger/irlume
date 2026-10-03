// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The real private CLI helper, with fixture PAM files and a private lock.

mod support;

use std::fs::File;
use std::io::Write as _;
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::{Duration, Instant};

struct RaceFixture(std::path::PathBuf);
impl RaceFixture {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let root =
            std::env::temp_dir().join(format!("irlume-token-race-{tag}-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        for dir in [
            "pam",
            "units/system",
            "state",
            "cfg",
            "keyring",
            "work",
            "bin",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/lightdm.service",
            root.join("units/system/display-manager.service"),
        )
        .unwrap();
        std::fs::write(root.join("pam/lightdm"), Self::STACK).unwrap();
        std::fs::write(root.join("bin/semodule"), "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(
            root.join("bin/semodule"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(
            root.join("units/system/irlumed.service"),
            "[Service]\nExecStart=/usr/bin/irlumed\n",
        )
        .unwrap();
        std::fs::write(root.join("bin/systemctl"), "#!/bin/sh\nif [ \"$1\" = show-environment ]; then exit 0; fi\nprintf '%s\\n' 'LoadState=loaded' 'ActiveState=inactive' 'MainPID=0' 'NeedDaemonReload=no' 'RootDirectory=' 'RootImage=' 'InvocationID=' 'ExecMainPID=0' 'ExecMainStartTimestampMonotonic=0'\n").unwrap();
        std::fs::set_permissions(
            root.join("bin/systemctl"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        Self(root)
    }
    const STACK: &'static str =
        "auth optional pam_irlume.so unseal ondemand\nsession optional pam_irlume.so reseal\n";
    fn command(&self, args: &[&str]) -> std::process::Command {
        support::assert_system_command_isolation(&self.0, &["semodule", "systemctl"]);
        let mut command = support::isolated_root_command(
            &self.0,
            env!("CARGO_BIN_EXE_irlume"),
            args,
            &["semodule", "systemctl"],
            &[
                "/usr/lib/pam.d",
                "/usr/share/lightdm",
                "/usr/local/share/lightdm",
                "/etc/xdg/lightdm",
                "/etc/lightdm",
            ],
            &[
                (&self.0.join("pam"), "/etc/pam.d"),
                (&self.0.join("units"), "/etc/systemd"),
            ],
        );
        command
            .env("IRLUME_PAM_LOCK", self.0.join("lock/pam.lock"))
            .env("IRLUME_OS_RELEASE", self.0.join("no-os-release"));
        command
    }
    fn arm_guard(&self) -> std::io::Result<Vec<File>> {
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent.write_all(b"synthetic-account").unwrap();
        parent.shutdown(Shutdown::Write).unwrap();
        let mut command = self.command(&["--internal-token-delivery-lock-v1"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let child: OwnedFd = child.into();
        let output = irlume_common::process::output_with_stdin_until(
            &mut command,
            Stdio::from(child),
            deadline,
        )
        .unwrap();
        drop(command);
        if !output.status.success() {
            return Err(std::io::Error::other("delivery refused"));
        }
        irlume_common::pam_lock_handoff::receive(
            &parent,
            std::fs::metadata(&self.0).unwrap().uid(),
            deadline,
        )
    }
}
impl Drop for RaceFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ChildOwner(std::process::Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn arm_first_holds_disable_until_the_envelope_is_visible() {
    let fixture = RaceFixture::new("arm-first");
    let guard = fixture.arm_guard().unwrap();
    let log = fixture.0.join("disable.log");
    let mut command = fixture.command(&["login", "disable", "--apply"]);
    command
        .stderr(File::create(&log).unwrap())
        .stdout(Stdio::null());
    let mut child = ChildOwner(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    // Synchronize on the actual lock wait diagnostic, not elapsed sleep.
    while !std::fs::read_to_string(&log)
        .unwrap()
        .contains("waiting for it")
    {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "disable escaped the held lock"
        );
        assert!(Instant::now() < deadline, "disable never reached the lock");
        std::thread::yield_now();
    }
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("pam/lightdm")).unwrap(),
        RaceFixture::STACK
    );
    // This is a synthetic kind-only envelope, as in the existing disable
    // fixture. TPM publication is covered by the daemon's software-TPM lane.
    let path = fixture.0.join("keyring/synthetic-account.json");
    let mut file = File::create(&path).unwrap();
    file.write_all(
        br#"{"version":1,"secret":"GnomeKeyringToken","pcrs":[],"public":"","private":""}"#,
    )
    .unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    drop(guard);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "disable did not finish after publication"
        );
        std::thread::yield_now();
    };
    assert!(!status.success());
    let error = std::fs::read_to_string(&log).unwrap();
    assert!(error.contains("keyed to an irlume-held token"), "{error}");
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("pam/lightdm")).unwrap(),
        RaceFixture::STACK
    );
}

#[test]
fn disable_first_makes_the_authoritative_arm_check_refuse() {
    let fixture = RaceFixture::new("disable-first");
    let output = irlume_common::process::output_until(
        &mut fixture.command(&["login", "disable", "--apply"]),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    let after = std::fs::read_to_string(fixture.0.join("pam/lightdm")).unwrap();
    assert!(
        !after
            .lines()
            .any(|line| !line.starts_with('#') && line.contains("pam_irlume.so reseal")),
        "{after}"
    );
    assert!(fixture.arm_guard().is_err());
    assert!(!fixture.0.join("keyring/synthetic-account.json").exists());
}

#[test]
fn helper_transfers_exclusion_only_after_proving_session_delivery() {
    let root =
        std::env::temp_dir().join(format!("irlume-token-lock-helper-{}", std::process::id()));
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    std::fs::create_dir(&root).unwrap();
    let _cleanup = Cleanup(root.clone());
    for dir in [
        "pam",
        "units/system",
        "state",
        "cfg",
        "keyring",
        "work",
        "bin",
    ] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::os::unix::fs::symlink(
        "/usr/lib/systemd/system/lightdm.service",
        root.join("units/system/display-manager.service"),
    )
    .unwrap();
    let owner = std::fs::metadata(&root).unwrap().uid();
    for (stack, accepted) in [
        ("session optional pam_irlume.so reseal\n", true),
        (
            "session sufficient pam_permit.so\nsession optional pam_irlume.so reseal\n",
            false,
        ),
        ("session required pam_unix.so\n", false),
    ] {
        std::fs::write(root.join("pam/lightdm"), stack).unwrap();
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent.write_all(b"synthetic-account").unwrap();
        parent.shutdown(Shutdown::Write).unwrap();
        let child: OwnedFd = child.into();
        support::assert_system_command_isolation(&root, &[]);
        let mut command = support::isolated_root_command(
            &root,
            env!("CARGO_BIN_EXE_irlume"),
            &["--internal-token-delivery-lock-v1"],
            &[],
            &[
                "/usr/lib/pam.d",
                "/usr/share/lightdm",
                "/usr/local/share/lightdm",
                "/etc/xdg/lightdm",
                "/etc/lightdm",
            ],
            &[
                (&root.join("pam"), "/etc/pam.d"),
                (&root.join("units"), "/etc/systemd"),
            ],
        );
        command.env("IRLUME_PAM_LOCK", root.join("lock/pam.lock"));
        let deadline = Instant::now() + Duration::from_secs(5);
        let output = irlume_common::process::output_with_stdin_until(
            &mut command,
            Stdio::from(child),
            deadline,
        )
        .unwrap();
        drop(command);
        assert_eq!(output.status.success(), accepted, "{output:?}");
        if accepted {
            let guard = irlume_common::pam_lock_handoff::receive(&parent, owner, deadline).unwrap();
            assert_eq!(guard.len(), 1, "the test override has no legacy lock");
            let competing = File::open(root.join("lock/pam.lock")).unwrap();
            // SAFETY: competing owns a live regular descriptor; the call cannot wait.
            let busy = unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            assert_ne!(busy, 0, "helper exit must not release the transferred lock");
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            drop(guard);
            // SAFETY: same live descriptor, now after the guard lifetime ends.
            let free = unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            assert_eq!(free, 0);
        } else {
            assert!(irlume_common::pam_lock_handoff::receive(&parent, owner, deadline).is_err());
        }
        assert_eq!(
            std::fs::read_to_string(root.join("pam/lightdm")).unwrap(),
            stack
        );
    }
}
