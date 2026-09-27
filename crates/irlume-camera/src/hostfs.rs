// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The host trees this crate reads, as one seam.
//!
//! Production resolves the real roots (`/dev`, `/sys`). Under `cfg(test)`
//! the same readers resolve whatever roots the running test installed and
//! REFUSE the real ones until a test says which it wants:
//! [`test::fixture_with`] (or [`test::empty_fixture`]) points every reader
//! at a temporary tree, and [`test::host`] is the explicit opt-in to the
//! real machine, reserved for the `#[ignore]`d hardware and v4l2loopback
//! lanes (plus this module's own self-test of the opt-in). A unit test that
//! reaches for the host's `/dev/video*`, `/dev/media*` or
//! `/sys/class/video4linux` without installing roots panics on the spot
//! instead of quietly probing a developer's camera: CI has no cameras, so
//! an unrouted test passes there by accident and opens real hardware on any
//! laptop that has one.
//!
//! The roots are thread-local so parallel tests stay isolated: each test
//! thread installs its own, and a thread that installs none gets the
//! refusal. One background thread reads these roots too (the lifecycle
//! monitor's initial snapshot, on the thread that spawned it); its quiet
//! loop never polls the trees, so only the spawning test thread's install
//! matters.

use std::path::PathBuf;

/// One resolution of the host roots: where `/dev` and `/sys` are right now.
/// Test-only: production has exactly one answer, built into the readers
/// below.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct HostRoots {
    dev: PathBuf,
    sys: PathBuf,
    /// Set only by [`test::host`]: the reader is deliberately looking at the
    /// real machine, so nothing is refused.
    is_host: bool,
}

#[cfg(test)]
thread_local! {
    static ROOTS: std::cell::RefCell<Option<HostRoots>> =
        const { std::cell::RefCell::new(None) };
}

/// The roots this thread reads, or the refusal. Test-only: production has
/// exactly one answer, built into the readers below.
///
/// # Panics
/// When the calling thread installed no roots. That is the guard: an
/// unrouted unit test fails here instead of reading the host's camera state.
#[cfg(test)]
fn installed() -> HostRoots {
    ROOTS.with(|roots| roots.borrow().clone().unwrap_or_else(|| refuse_unrouted()))
}

#[cfg(test)]
fn refuse_unrouted() -> ! {
    panic!(
        "irlume-camera unit test read a host tree (/dev or /sys) without installing roots; \
         install hostfs::test::empty_fixture() for a hermetic fixture, or \
         hostfs::test::host() for the ignored hardware lanes"
    )
}

pub(crate) fn dev_root() -> PathBuf {
    #[cfg(test)]
    return installed().dev;
    #[cfg(not(test))]
    PathBuf::from("/dev")
}

pub(crate) fn sys_root() -> PathBuf {
    #[cfg(test)]
    return installed().sys;
    #[cfg(not(test))]
    PathBuf::from("/sys")
}

/// `/sys/class/video4linux`, where the kernel lists every video node.
pub(crate) fn video_class_root() -> PathBuf {
    sys_root().join("class/video4linux")
}

/// `/sys/bus/usb/devices`, the USB device and interface listing.
pub(crate) fn usb_devices_root() -> PathBuf {
    sys_root().join("bus/usb/devices")
}

/// `/sys/bus/pci/devices`, the PCI device listing.
pub(crate) fn pci_devices_root() -> PathBuf {
    sys_root().join("bus/pci/devices")
}

/// `/sys/dev/char`, where a character device's major:minor resolves back to
/// its sysfs node.
pub(crate) fn sys_dev_char_root() -> PathBuf {
    sys_root().join("dev/char")
}

/// Gate for the "open this node and ask it something" probes
/// ([`crate::classify_node`] and friends): under test, a probe naming a
/// host camera node is a touch of real hardware and must carry the explicit
/// host opt-in. A fixture path, or any node that is not a camera node
/// (say `/dev/null`), passes unchanged.
///
/// # Panics
/// Under `cfg(test)`, when the calling thread installed no roots at all, or
/// installed a fixture and then probed a `/dev/video*`, `/dev/media*` or
/// `/dev/v4l-subdev*` path anyway.
pub(crate) fn check_probe(device: &str) {
    #[cfg(test)]
    {
        let roots = installed();
        if roots.is_host {
            return;
        }
        if names_host_camera_node(device) {
            panic!(
                "irlume-camera unit test probed {device}, a host camera node, under fixture \
                 roots; point the test at hostfs::test fixture paths, or install \
                 hostfs::test::host() for the ignored hardware lanes"
            );
        }
    }
    #[cfg(not(test))]
    let _ = device;
}

/// Whether `device` names a camera node under the real `/dev`. A path under
/// a fixture root never matches, which is exactly the distinction the probe
/// gate needs.
#[cfg(test)]
fn names_host_camera_node(device: &str) -> bool {
    let path = std::path::Path::new(device);
    path.starts_with("/dev/")
        .then(|| path.file_name())
        .flatten()
        .is_some_and(|name| {
            name.to_str().is_some_and(|name| {
                name.starts_with("video")
                    || name.starts_with("media")
                    || name.starts_with("v4l-subdev")
            })
        })
}

/// The test-side installers. [`fixture_with`] builds a tree,
/// [`empty_fixture`] is the camera-less machine, and [`host`] is the
/// explicit real-machine opt-in for the ignored hardware lanes; the readers
/// above refuse everything until one of them ran on this thread.
#[cfg(test)]
pub(crate) mod test {
    use super::HostRoots;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Fixture trees share the process id, so a counter keeps parallel tests
    /// from colliding on one directory name.
    static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

    /// A live fixture install. While alive, this thread's hostfs readers
    /// resolve the fixture's `dev` and `sys` trees; dropping it restores the
    /// previous roots and removes the tree.
    pub(crate) struct FixtureGuard {
        roots: HostRoots,
        previous: Option<HostRoots>,
    }

    impl FixtureGuard {
        /// The fixture `/dev`, for building node paths under it.
        pub(crate) fn dev(&self) -> &Path {
            &self.roots.dev
        }

        /// The fixture `/sys`, for building class, bus or device trees
        /// under it.
        pub(crate) fn sys(&self) -> &Path {
            &self.roots.sys
        }
    }

    impl Drop for FixtureGuard {
        fn drop(&mut self) {
            super::ROOTS.with(|roots| *roots.borrow_mut() = self.previous.take());
            let _ = std::fs::remove_dir_all(&self.roots.dev);
            let _ = std::fs::remove_dir_all(&self.roots.sys);
        }
    }

    /// A fresh fixture tree with `populate` given its empty `dev` and `sys`
    /// roots.
    pub(crate) fn fixture_with(populate: impl FnOnce(&Path, &Path)) -> FixtureGuard {
        let dir = std::env::temp_dir().join(format!(
            "irlume-hostfs-{}-{}",
            std::process::id(),
            FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let dev = dir.join("dev");
        let sys = dir.join("sys");
        std::fs::create_dir_all(&dev).expect("create the fixture dev root");
        std::fs::create_dir_all(&sys).expect("create the fixture sysfs root");
        populate(&dev, &sys);
        install(HostRoots {
            dev,
            sys,
            is_host: false,
        })
    }

    /// The machine with no camera: an empty `/dev` and an empty `/sys`.
    pub(crate) fn empty_fixture() -> FixtureGuard {
        fixture_with(|_, _| {})
    }

    /// The explicit opt-in to the real machine, for the `#[ignore]`d lanes
    /// whose subject is real hardware (v4l2loopback, UVC acceptance), either
    /// through the loopback helpers `loopback_pair` and `spare_device` or
    /// directly at the top of the test. The one non-ignored caller is this
    /// module's self-test of the opt-in, which reads no host tree. Sticky
    /// for the thread on purpose: those tests are the last thing their
    /// thread runs, and the host roots own nothing to clean up.
    pub(crate) fn host() {
        install_sticky(HostRoots {
            dev: PathBuf::from("/dev"),
            sys: PathBuf::from("/sys"),
            is_host: true,
        });
    }

    fn install(roots: HostRoots) -> FixtureGuard {
        let previous = super::ROOTS.with(|slot| slot.borrow_mut().replace(roots.clone()));
        FixtureGuard { roots, previous }
    }

    fn install_sticky(roots: HostRoots) {
        super::ROOTS.with(|slot| *slot.borrow_mut() = Some(roots));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    /// The panic text of a refused call, for asserting the guard names the
    /// seam a failing test must use.
    fn refusal_of<R>(call: impl FnOnce() -> R + std::panic::UnwindSafe) -> String {
        catch_unwind(call)
            .err()
            .and_then(|payload| {
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            })
            .unwrap_or_default()
    }

    /// The regression guard this module exists for: with nothing installed,
    /// every host-tree reader refuses rather than reading the machine the
    /// test happens to run on. A test that reaches one of these without
    /// installing roots fails here, on every machine, instead of opening a
    /// developer's cameras (CI has none, so before this seam such a test
    /// passed there by accident).
    #[test]
    fn root_readers_refuse_the_host_until_a_test_chooses_roots() {
        for refused in [
            refusal_of(dev_root),
            refusal_of(sys_root),
            refusal_of(video_class_root),
            refusal_of(usb_devices_root),
            refusal_of(pci_devices_root),
            refusal_of(sys_dev_char_root),
            refusal_of(|| {
                let _ = crate::video_node_paths();
            }),
        ] {
            assert!(
                refused.contains("without installing roots") && refused.contains("hostfs::test"),
                "the refusal must name the seam and the fix: {refused}"
            );
        }
    }

    /// An installed fixture is what every reader sees, and dropping the guard
    /// brings the refusal back, so one test's roots cannot leak into the next
    /// test on a reused thread.
    #[test]
    fn a_fixture_redirects_the_readers_and_its_drop_restores_the_refusal() {
        let guard = test::fixture_with(|dev, sys| {
            std::fs::write(dev.join("video0"), b"").unwrap();
            std::fs::create_dir_all(sys.join("class/video4linux")).unwrap();
        });
        assert!(dev_root().starts_with(guard.dev()));
        assert_eq!(video_class_root(), guard.sys().join("class/video4linux"));
        assert_eq!(
            crate::video_node_paths().paths,
            [guard.dev().join("video0").to_string_lossy().into_owned()]
        );
        drop(guard);
        assert!(
            refusal_of(video_class_root).contains("without installing roots"),
            "a dropped fixture must leave the refusal behind"
        );
    }

    /// Under a fixture, probing a node under the fixture (or a non-camera
    /// node like /dev/null) is fine, but a probe naming the host's
    /// `/dev/video*`, `/dev/media*` or `/dev/v4l-subdev*` refuses: that is
    /// the touch of real hardware this seam exists to prevent. Only the
    /// explicit host opt-in lifts it. Apart from the `test::host` call at
    /// the end of this test, which probes nothing but the gate, every call
    /// to it sits in an `#[ignore]`d hardware-lane test or in a helper only
    /// those tests use.
    #[test]
    fn probes_of_host_camera_nodes_need_the_explicit_host_opt_in() {
        let guard = test::empty_fixture();
        check_probe(&guard.dev().join("video0").to_string_lossy());
        check_probe("/dev/null");
        for host_node in ["/dev/video0", "/dev/media1", "/dev/v4l-subdev3"] {
            let refused = refusal_of(move || check_probe(host_node));
            assert!(
                refused.contains("host camera node"),
                "probing {host_node} must be refused under a fixture: {refused}"
            );
        }
        drop(guard);
        let refused = refusal_of(|| check_probe("/dev/null"));
        assert!(
            refused.contains("without installing roots"),
            "a probe with no roots at all must refuse: {refused}"
        );
        // The explicit opt-in, and nothing else, allows the host's camera
        // nodes. Sticky by design: it belongs to the ignored hardware lanes.
        test::host();
        check_probe("/dev/video0");
        check_probe("/dev/media1");
    }
}
