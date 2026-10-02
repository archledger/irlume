// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Safety removal uses fixture PAM/configuration in a root namespace. The
//! fake daemon can withhold or establish capabilities; no real devices are exposed.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

mod support;

const WIRED: &str = "#%PAM-1.0\nauth sufficient pam_irlume.so unseal ondemand kr\n@include common-auth\nauth optional pam_irlume.so reseal\n@include common-session\nsession optional pam_irlume.so reseal\n";

struct Bed {
    root: PathBuf,
    stop: Arc<AtomicBool>,
    requested_before_strip: Arc<AtomicBool>,
    caps_available: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Bed {
    fn new(tag: &str, marker: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "irlume-lightdm-enforce-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        for dir in [
            "pam",
            "vendor",
            "lightdm",
            "units/system",
            "cfg",
            "state",
            "keyring",
            "bin",
            "work",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("pam/lightdm"), WIRED).unwrap();
        std::fs::write(root.join("pam/common-auth"), "auth required pam_unix.so\n").unwrap();
        std::fs::write(
            root.join("pam/common-session"),
            "session required pam_unix.so\n",
        )
        .unwrap();
        std::fs::write(root.join("pam/sddm"), WIRED).unwrap();
        std::fs::write(
            root.join("lightdm/lightdm.conf"),
            "[XDMCPServer]\nenabled=true\n",
        )
        .unwrap();
        if marker {
            std::fs::write(
                root.join("state/login.wired"),
                "with_sudo=false\nwith_polkit=false\nwith_lock=false\n",
            )
            .unwrap();
        }
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/lightdm.service",
            root.join("units/system/display-manager.service"),
        )
        .unwrap();
        let listener = std::os::unix::net::UnixListener::bind(root.join("no-daemon.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requested_before_strip = Arc::new(AtomicBool::new(false));
        let caps_available = Arc::new(AtomicBool::new(false));
        let ready = caps_available.clone();
        let (done, early, pam) = (
            stop.clone(),
            requested_before_strip.clone(),
            root.join("pam/lightdm"),
        );
        let server = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                            .unwrap();
                        let mut request = String::new();
                        BufReader::new(&stream).read_line(&mut request).unwrap();
                        let text = match std::fs::read_to_string(&pam) {
                            Ok(text) => text,
                            // A vendor-only fixture has no machine override
                            // until the production enable creates it.
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                            Err(e) => panic!("read PAM fixture: {e}"),
                        };
                        if text.contains("pam_irlume.so unseal") {
                            early.store(true, Ordering::Relaxed);
                        }
                        let reply = if ready.load(Ordering::Relaxed) {
                            match serde_json::from_str::<irlume_common::Request>(&request).unwrap()
                            {
                                irlume_common::Request::Ping => irlume_common::Response::Pong,
                                irlume_common::Request::Health => irlume_common::Response::Health {
                                    tier: "secure".into(),
                                    rgb_dev: None,
                                    ir_dev: None,
                                    mesh: true,
                                    adapter: false,
                                    rgb_pad: None,
                                    ir_pad: None,
                                    version: String::new(),
                                    apparmor: None,
                                },
                                _ => irlume_common::Response::Error("unexpected request".into()),
                            }
                        } else {
                            irlume_common::Response::Error("capabilities unavailable".into())
                        };
                        writeln!(stream, "{}", serde_json::to_string(&reply).unwrap()).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        Self {
            root,
            stop,
            requested_before_strip,
            caps_available,
            server: Some(server),
        }
    }

    fn run(&self) -> std::process::Output {
        self.run_args(&["login", "reconcile"], &[])
    }

    fn run_args(&self, args: &[&str], tools: &[&str]) -> std::process::Output {
        support::assert_system_command_isolation(&self.root, tools);
        support::isolated_root_command(
            &self.root,
            env!("CARGO_BIN_EXE_irlume"),
            args,
            tools,
            &[
                "/usr/lib/pam.d",
                "/usr/share/lightdm",
                "/usr/share/omarchy",
                "/etc/xdg/lightdm",
            ],
            &[
                (&self.root.join("pam"), "/etc/pam.d"),
                (&self.root.join("lightdm"), "/etc/lightdm"),
                (&self.root.join("units"), "/etc/systemd"),
                (&self.root.join("vendor"), "/usr/lib/pam.d"),
            ],
        )
        .env("IRLUME_OS_RELEASE", self.root.join("no-os-release"))
        .env("IRLUME_PAM_LOCK", self.root.join("lock/pam.lock"))
        .output()
        .unwrap()
    }

    fn stack(&self) -> String {
        std::fs::read_to_string(self.root.join("pam/lightdm")).unwrap()
    }

    /// Use the production enable path to create a tracked vendor override.
    fn tracked_override(&self, remote: bool, vendor: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::remove_file(self.root.join("pam/lightdm")).unwrap();
        std::fs::write(self.root.join("vendor/lightdm"), vendor).unwrap();
        std::fs::write(
            self.root.join("lightdm/lightdm.conf"),
            format!("[XDMCPServer]\nenabled={remote}\n"),
        )
        .unwrap();
        self.caps_available.store(true, Ordering::Relaxed);
        let tools = ["semodule", "systemctl", "restorecon"];
        for tool in tools {
            let path = self.root.join("bin").join(tool);
            std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let output = self.run_args(&["login", "enable", "--apply"], &tools);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(self
            .stack()
            .starts_with("# irlume: created from /usr/lib/pam.d/lightdm;"));
        assert_tracked_vendor(&self.stack(), vendor);
        self.requested_before_strip.store(false, Ordering::Relaxed);
    }
}

impl Drop for Bed {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn remote_lightdm_is_stripped_before_unavailable_capabilities_with_or_without_marker() {
    for marker in [true, false] {
        let bed = Bed::new(if marker { "marked" } else { "adopt" }, marker);
        let output = bed.run();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            !bed.stack().contains("pam_irlume.so unseal"),
            "{}\n{output:?}",
            bed.stack()
        );
        assert!(
            !bed.requested_before_strip.load(Ordering::Relaxed),
            "queried the unavailable daemon before stripping"
        );
        assert!(bed.stack().contains("auth optional pam_irlume.so reseal\n"));
        assert!(bed
            .stack()
            .contains("session optional pam_irlume.so reseal\n"));
        assert_eq!(
            std::fs::read_to_string(bed.root.join("pam/sddm")).unwrap(),
            WIRED
        );
        let once = bed.stack();
        let second = bed.run();
        assert_eq!(second.status.code(), Some(1), "{second:?}");
        assert_eq!(bed.stack(), once, "repeat must not restore authority");
    }
}

#[test]
fn safety_removal_preserves_numeric_slots_password_and_existing_reseal_bytes() {
    let bed = Bed::new("jumps", true);
    let stack = "# jump over the existing face rule\nauth [success=1 default=ignore] pam_exec.so /fixture-policy\nauth [success=1 default=ignore] pam_irlume.so unseal ondemand kr\nauth substack common-auth\nauth optional pam_permit.so # irlume-landing\nauth optional pam_irlume.so keyring\nauth optional pam_irlume.so reseal\nsession optional pam_irlume.so reseal";
    std::fs::write(bed.root.join("pam/lightdm"), stack).unwrap();
    let output = bed.run();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let actual = bed.stack();
    let before: Vec<_> = stack.lines().collect();
    let after: Vec<_> = actual.lines().collect();
    assert_eq!(after.len(), before.len());
    for index in [0, 1, 3, 4, 6, 7] {
        assert_eq!(after[index], before[index], "line {index} changed");
    }
    for index in [2, 5] {
        assert!(
            after[index].contains("[default=ignore]"),
            "{}",
            after[index]
        );
        assert!(after[index].contains("pam_permit.so"), "{}", after[index]);
        assert!(!after[index].contains("pam_irlume.so"));
    }
    assert!(!actual.ends_with('\n'), "preserve the session line's bytes");
}

#[test]
fn safety_removal_does_not_add_reseal_or_restore_face_without_capabilities() {
    let bed = Bed::new("no-reseal", false);
    std::fs::write(
        bed.root.join("pam/lightdm"),
        "auth sufficient pam_irlume.so\nauth required pam_unix.so\n",
    )
    .unwrap();
    let output = bed.run();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!bed.stack().contains("pam_irlume.so"));
    assert!(!bed.stack().contains("reseal"));
    let stripped = bed.stack();
    std::fs::write(
        bed.root.join("lightdm/lightdm.conf"),
        "[XDMCPServer]\nenabled=false\n",
    )
    .unwrap();
    let output = bed.run();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(bed.stack(), stripped);
}

#[test]
fn safety_removal_observes_a_renamed_remote_configuration() {
    let bed = Bed::new("rename", true);
    std::fs::write(
        bed.root.join("lightdm/lightdm.conf"),
        "[XDMCPServer]\nenabled=false\n",
    )
    .unwrap();
    std::fs::write(
        bed.root.join("lightdm/new.conf"),
        "[VNCServer]\nenabled=true\n",
    )
    .unwrap();
    std::fs::rename(
        bed.root.join("lightdm/new.conf"),
        bed.root.join("lightdm/lightdm.conf"),
    )
    .unwrap();
    let output = bed.run();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!bed.stack().contains("pam_irlume.so unseal"));
}

#[test]
fn safety_removal_refuses_ambiguous_pam_without_changing_it() {
    for (tag, prefix) in [
        ("continued", "auth optional pam_exec.so /fixture \\\n"),
        ("unread", "auth\trequired\tpam_unix.so\r\n"),
    ] {
        let bed = Bed::new(tag, true);
        let stack = format!("{prefix}{WIRED}");
        std::fs::write(bed.root.join("pam/lightdm"), &stack).unwrap();
        let output = bed.run();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(bed.stack(), stack);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("cannot remove LightDM authentication authority"),
            "{output:?}"
        );
        assert!(!bed.requested_before_strip.load(Ordering::Relaxed));
    }
}

#[test]
fn safety_removal_refuses_shared_inode_or_symlink_without_replacing_it() {
    for symlink in [true, false] {
        let bed = Bed::new(if symlink { "symlink" } else { "hardlink" }, true);
        let path = bed.root.join("pam/lightdm");
        let target = bed.root.join("pam/original");
        std::fs::rename(&path, &target).unwrap();
        if symlink {
            std::os::unix::fs::symlink("original", &path).unwrap();
        } else {
            std::fs::hard_link(&target, &path).unwrap();
        }
        let output = bed.run();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(bed.stack(), WIRED);
        assert_eq!(std::fs::read_to_string(target).unwrap(), WIRED);
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink(),
            symlink
        );
        assert!(!bed.requested_before_strip.load(Ordering::Relaxed));
    }
}

#[test]
fn safety_removal_cannot_turn_an_explicit_ignore_denial_into_a_fallthrough() {
    let bed = Bed::new("ignore-denial", true);
    let stack = WIRED.replace(
        "auth sufficient",
        "auth [success=done ignore=die default=ignore]",
    );
    std::fs::write(bed.root.join("pam/lightdm"), &stack).unwrap();
    let output = bed.run();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        bed.stack(),
        stack,
        "neutralization must not remove an administrator's denial"
    );
    assert!(!bed.requested_before_strip.load(Ordering::Relaxed));
}

const VENDOR: &str =
    "#%PAM-1.0\n@include common-auth\naccount required pam_unix.so\n@include common-session\n";
const RESTRICTED_VENDOR: &str = "#%PAM-1.0\n@include common-auth\naccount required pam_unix.so\naccount requisite pam_access.so accessfile=/fixture/allow\n@include common-session\n";

fn assert_tracked_vendor(stack: &str, vendor: &str) {
    use sha2::{Digest as _, Sha256};
    let digest: String = Sha256::digest(vendor.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(
        stack.lines().any(|line| line
            == format!("# irlume: override v1 vendor-sha256={digest} body-sha256={digest}")),
        "{stack}"
    );
}

fn assert_reseal_only(stack: &str) {
    let rules: Vec<_> = stack
        .lines()
        .filter(|line| line.contains("pam_irlume.so"))
        .collect();
    assert_eq!(rules.len(), 2, "{stack}");
    assert!(rules[0]
        .split_whitespace()
        .eq(["auth", "optional", "pam_irlume.so", "reseal"]));
    assert!(rules[1]
        .split_whitespace()
        .eq(["session", "optional", "pam_irlume.so", "reseal"]));
}

#[test]
fn vendor_refresh_after_safety_strip_follows_capability_recovery_without_auth_restore() {
    let bed = Bed::new("vendor-after-strip", true);
    bed.tracked_override(false, VENDOR);
    assert!(bed.stack().contains("pam_irlume.so unseal"));
    std::fs::write(
        bed.root.join("lightdm/lightdm.conf"),
        "[XDMCPServer]\nenabled=true\n",
    )
    .unwrap();
    std::fs::write(bed.root.join("vendor/lightdm"), RESTRICTED_VENDOR).unwrap();
    bed.caps_available.store(false, Ordering::Relaxed);
    let unavailable = bed.run();
    assert_eq!(unavailable.status.code(), Some(1), "{unavailable:?}");
    let stripped = bed.stack();
    assert_reseal_only(&stripped);
    assert_tracked_vendor(&stripped, VENDOR);
    assert!(
        !stripped.contains("pam_access.so"),
        "refresh requires capabilities"
    );
    assert!(!bed.requested_before_strip.load(Ordering::Relaxed));

    bed.caps_available.store(true, Ordering::Relaxed);
    let output = bed.run();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let refreshed = bed.stack();
    assert!(
        refreshed.contains("account requisite pam_access.so accessfile=/fixture/allow\n"),
        "{refreshed}\n{output:?}"
    );
    assert_tracked_vendor(&refreshed, RESTRICTED_VENDOR);
    assert_reseal_only(&refreshed);
    let repeat = bed.run();
    assert_eq!(repeat.status.code(), Some(0), "{repeat:?}");
    assert_eq!(bed.stack(), refreshed);
}

#[test]
fn vendor_refresh_updates_an_already_reseal_only_remote_override() {
    let bed = Bed::new("vendor-reseal-only", true);
    bed.tracked_override(true, VENDOR);
    assert_reseal_only(&bed.stack());
    let unrelated = std::fs::read_to_string(bed.root.join("pam/sddm")).unwrap();
    std::fs::write(bed.root.join("vendor/lightdm"), RESTRICTED_VENDOR).unwrap();
    let output = bed.run();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let refreshed = bed.stack();
    assert!(
        refreshed.contains("account requisite pam_access.so accessfile=/fixture/allow\n"),
        "{refreshed}\n{output:?}"
    );
    assert_tracked_vendor(&refreshed, RESTRICTED_VENDOR);
    assert_reseal_only(&refreshed);
    assert_eq!(
        std::fs::read_to_string(bed.root.join("pam/sddm")).unwrap(),
        unrelated
    );
    assert_eq!(
        std::fs::read_to_string(bed.root.join("vendor/lightdm")).unwrap(),
        RESTRICTED_VENDOR
    );
}
