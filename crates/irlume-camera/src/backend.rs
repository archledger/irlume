// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Crate-private capture-backend ownership and operation routing.

use std::sync::{Arc, OnceLock};

use crate::{CameraPair, IrCamera, NodeScan, RgbCamera, Role};

/// One capture implementation owned by the process camera supervisor.
trait CameraBackend: Send + Sync + 'static {
    fn scan_nodes(&self) -> NodeScan;
    fn discover_nodes(&self) -> Vec<(String, Role)>;
    fn list_pairs(&self) -> Vec<CameraPair>;
    fn open_rgb(&self, device: &str) -> irlume_common::Result<RgbCamera>;
    fn open_ir(&self, device: &str) -> irlume_common::Result<IrCamera>;

    #[cfg(test)]
    fn has_exact_production_uvc_delegates(&self) -> bool {
        false
    }
}

/// Process component that owns camera backend instances and routes operations.
///
/// This foundation deliberately has no mutex, mutable inventory, cache, lease,
/// or lifecycle generation. Those would alter contention or hotplug behavior.
struct CameraSupervisor {
    backend: Arc<dyn CameraBackend>,
}

impl CameraSupervisor {
    fn new(backend: impl CameraBackend) -> Self {
        Self {
            backend: Arc::new(backend),
        }
    }

    #[cfg(test)]
    fn from_arc(backend: Arc<dyn CameraBackend>) -> Self {
        Self { backend }
    }

    fn scan_nodes(&self) -> NodeScan {
        self.backend.scan_nodes()
    }

    fn discover_nodes(&self) -> Vec<(String, Role)> {
        self.backend.discover_nodes()
    }

    fn list_pairs(&self) -> Vec<CameraPair> {
        self.backend.list_pairs()
    }

    fn open_rgb(&self, device: &str) -> irlume_common::Result<RgbCamera> {
        self.backend.open_rgb(device)
    }

    fn open_ir(&self, device: &str) -> irlume_common::Result<IrCamera> {
        self.backend.open_ir(device)
    }
}

/// Existing direct V4L2 backend for video-node-centric UVC cameras.
///
/// This delegates to the pre-existing direct functions without changing their
/// probing, pairing, negotiation, privacy, or emitter behavior.
type ScanNodes = fn() -> NodeScan;
type DiscoverNodes = fn() -> Vec<(String, Role)>;
type ListPairs = fn() -> Vec<CameraPair>;
type OpenRgb = fn(&str) -> irlume_common::Result<RgbCamera>;
type OpenIr = fn(&str) -> irlume_common::Result<IrCamera>;

fn production_scan_nodes() -> NodeScan {
    crate::uvc_scan(true)
}

fn production_discover_nodes() -> Vec<(String, Role)> {
    crate::uvc_discover_nodes()
}

fn production_list_pairs() -> Vec<CameraPair> {
    crate::uvc_list_pairs()
}

fn production_open_rgb(device: &str) -> irlume_common::Result<RgbCamera> {
    RgbCamera::open_uvc(device)
}

fn production_open_ir(device: &str) -> irlume_common::Result<IrCamera> {
    IrCamera::open_uvc(device)
}

#[derive(Clone, Copy)]
struct UvcV4l2Backend {
    scan_nodes: ScanNodes,
    discover_nodes: DiscoverNodes,
    list_pairs: ListPairs,
    open_rgb: OpenRgb,
    open_ir: OpenIr,
}

impl Default for UvcV4l2Backend {
    fn default() -> Self {
        Self {
            scan_nodes: production_scan_nodes,
            discover_nodes: production_discover_nodes,
            list_pairs: production_list_pairs,
            open_rgb: production_open_rgb,
            open_ir: production_open_ir,
        }
    }
}

impl CameraBackend for UvcV4l2Backend {
    fn scan_nodes(&self) -> NodeScan {
        (self.scan_nodes)()
    }

    fn discover_nodes(&self) -> Vec<(String, Role)> {
        (self.discover_nodes)()
    }

    fn list_pairs(&self) -> Vec<CameraPair> {
        (self.list_pairs)()
    }

    fn open_rgb(&self, device: &str) -> irlume_common::Result<RgbCamera> {
        (self.open_rgb)(device)
    }

    fn open_ir(&self, device: &str) -> irlume_common::Result<IrCamera> {
        (self.open_ir)(device)
    }

    #[cfg(test)]
    fn has_exact_production_uvc_delegates(&self) -> bool {
        std::ptr::fn_addr_eq(self.scan_nodes, production_scan_nodes as ScanNodes)
            && std::ptr::fn_addr_eq(
                self.discover_nodes,
                production_discover_nodes as DiscoverNodes,
            )
            && std::ptr::fn_addr_eq(self.list_pairs, production_list_pairs as ListPairs)
            && std::ptr::fn_addr_eq(self.open_rgb, production_open_rgb as OpenRgb)
            && std::ptr::fn_addr_eq(self.open_ir, production_open_ir as OpenIr)
    }
}

static DEFAULT_CAMERA_SUPERVISOR: OnceLock<CameraSupervisor> = OnceLock::new();

fn default_camera_supervisor() -> &'static CameraSupervisor {
    DEFAULT_CAMERA_SUPERVISOR.get_or_init(|| CameraSupervisor::new(UvcV4l2Backend::default()))
}

#[cfg(test)]
thread_local! {
    static TEST_BACKEND: std::cell::RefCell<Option<Arc<dyn CameraBackend>>> =
        const { std::cell::RefCell::new(None) };
}

/// Route one compatibility operation through the process supervisor.
fn with_camera_supervisor<T>(operation: impl FnOnce(&CameraSupervisor) -> T) -> T {
    #[cfg(test)]
    if let Some(backend) = TEST_BACKEND.with(|slot| slot.borrow().clone()) {
        return operation(&CameraSupervisor::from_arc(backend));
    }

    operation(default_camera_supervisor())
}

pub(crate) fn scan_nodes() -> NodeScan {
    with_camera_supervisor(CameraSupervisor::scan_nodes)
}

pub(crate) fn discover_nodes() -> Vec<(String, Role)> {
    with_camera_supervisor(CameraSupervisor::discover_nodes)
}

pub(crate) fn list_pairs() -> Vec<CameraPair> {
    with_camera_supervisor(CameraSupervisor::list_pairs)
}

pub(crate) fn open_rgb(device: &str) -> irlume_common::Result<RgbCamera> {
    with_camera_supervisor(|supervisor| supervisor.open_rgb(device))
}

pub(crate) fn open_ir(device: &str) -> irlume_common::Result<IrCamera> {
    with_camera_supervisor(|supervisor| supervisor.open_ir(device))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::{FailedAt, McCentric, Unreadable};

    struct TestBackendGuard(Option<Arc<dyn CameraBackend>>);

    impl Drop for TestBackendGuard {
        fn drop(&mut self) {
            let previous = self.0.take();
            TEST_BACKEND.with(|slot| *slot.borrow_mut() = previous);
        }
    }

    fn install_test_backend(backend: Arc<dyn CameraBackend>) -> TestBackendGuard {
        let previous = TEST_BACKEND.with(|slot| slot.borrow_mut().replace(backend));
        TestBackendGuard(previous)
    }

    #[derive(Clone)]
    struct RecordingBackend {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingBackend {
        fn record(&self, call: impl Into<String>) {
            self.calls
                .lock()
                .expect("recording lock poisoned")
                .push(call.into());
        }
    }

    impl CameraBackend for RecordingBackend {
        fn scan_nodes(&self) -> NodeScan {
            self.record("scan_nodes");
            NodeScan {
                classified: vec![("/dev/spy-scan".into(), Role::Rgb)],
                ..NodeScan::default()
            }
        }

        fn discover_nodes(&self) -> Vec<(String, Role)> {
            self.record("discover_nodes");
            vec![
                ("/dev/spy-ir".into(), Role::Ir),
                ("/dev/spy-rgb".into(), Role::Rgb),
            ]
        }

        fn list_pairs(&self) -> Vec<CameraPair> {
            self.record("list_pairs");
            vec![CameraPair {
                rgb: "/dev/spy-rgb".into(),
                ir: "/dev/spy-ir".into(),
                id: Some("1234:5678".into()),
                fixed: true,
            }]
        }

        fn open_rgb(&self, device: &str) -> irlume_common::Result<RgbCamera> {
            self.record(format!("open_rgb:{device}"));
            Err(irlume_common::Error::Hardware("spy RGB refusal".into()))
        }

        fn open_ir(&self, device: &str) -> irlume_common::Result<IrCamera> {
            self.record(format!("open_ir:{device}"));
            Err(irlume_common::Error::Hardware("spy IR refusal".into()))
        }
    }

    fn fixture_scan_nodes() -> NodeScan {
        NodeScan {
            classified: vec![
                ("/dev/fixture-rgb".into(), Role::Rgb),
                ("/dev/fixture-ir".into(), Role::Ir),
            ],
            unreadable: vec![Unreadable {
                path: "/dev/fixture-busy".into(),
                at: FailedAt::Open,
                errno: Some(libc::EBUSY),
                holder: Some("fixture-holder".into()),
            }],
            mc_centric: vec![(
                "/dev/fixture-mc".into(),
                McCentric {
                    driver: "fixture-driver".into(),
                    io_mc: true,
                    mplane_only: true,
                },
            )],
            listing_error: Some("fixture listing warning".into()),
        }
    }

    fn fixture_discover_nodes() -> Vec<(String, Role)> {
        vec![
            ("/dev/fixture-ir".into(), Role::Ir),
            ("/dev/fixture-rgb".into(), Role::Rgb),
        ]
    }

    fn fixture_list_pairs() -> Vec<CameraPair> {
        vec![
            CameraPair {
                rgb: "/dev/fixed-rgb".into(),
                ir: "/dev/fixed-ir".into(),
                id: Some("1111:2222".into()),
                fixed: true,
            },
            CameraPair {
                rgb: "/dev/usb-rgb".into(),
                ir: "/dev/usb-ir".into(),
                id: None,
                fixed: false,
            },
        ]
    }

    fn fixture_open_rgb(_: &str) -> irlume_common::Result<RgbCamera> {
        Err(irlume_common::Error::Hardware("fixture RGB".into()))
    }

    fn fixture_open_ir(_: &str) -> irlume_common::Result<IrCamera> {
        Err(irlume_common::Error::Hardware("fixture IR".into()))
    }

    #[test]
    fn public_camera_entrypoints_route_through_one_supervisor_backend() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let _guard = install_test_backend(Arc::new(RecordingBackend {
            calls: Arc::clone(&calls),
        }));

        assert_eq!(crate::scan_nodes().classified[0].0, "/dev/spy-scan");
        assert_eq!(
            crate::discover_nodes(),
            vec![
                ("/dev/spy-ir".into(), Role::Ir),
                ("/dev/spy-rgb".into(), Role::Rgb),
            ]
        );
        let pairs = crate::list_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].rgb, "/dev/spy-rgb");
        assert_eq!(pairs[0].ir, "/dev/spy-ir");
        assert_eq!(pairs[0].id.as_deref(), Some("1234:5678"));
        assert!(pairs[0].fixed);
        assert!(RgbCamera::open("/dev/spy-rgb")
            .err()
            .expect("spy RGB open must refuse")
            .to_string()
            .contains("spy RGB refusal"));
        assert!(IrCamera::open("/dev/spy-ir")
            .err()
            .expect("spy IR open must refuse")
            .to_string()
            .contains("spy IR refusal"));

        assert_eq!(
            *calls.lock().expect("recording lock poisoned"),
            [
                "scan_nodes",
                "discover_nodes",
                "list_pairs",
                "open_rgb:/dev/spy-rgb",
                "open_ir:/dev/spy-ir",
            ]
        );
    }

    #[test]
    fn uvc_adapter_preserves_complete_results_and_order() {
        let backend = UvcV4l2Backend {
            scan_nodes: fixture_scan_nodes,
            discover_nodes: fixture_discover_nodes,
            list_pairs: fixture_list_pairs,
            open_rgb: fixture_open_rgb,
            open_ir: fixture_open_ir,
        };

        let scan = backend.scan_nodes();
        assert_eq!(
            scan.classified,
            vec![
                ("/dev/fixture-rgb".into(), Role::Rgb),
                ("/dev/fixture-ir".into(), Role::Ir),
            ]
        );
        assert_eq!(scan.unreadable.len(), 1);
        assert_eq!(scan.unreadable[0].path, "/dev/fixture-busy");
        assert_eq!(scan.unreadable[0].at, FailedAt::Open);
        assert_eq!(scan.unreadable[0].errno, Some(libc::EBUSY));
        assert_eq!(scan.unreadable[0].holder.as_deref(), Some("fixture-holder"));
        assert_eq!(
            scan.mc_centric,
            vec![(
                "/dev/fixture-mc".into(),
                McCentric {
                    driver: "fixture-driver".into(),
                    io_mc: true,
                    mplane_only: true,
                },
            )]
        );
        assert_eq!(
            scan.listing_error.as_deref(),
            Some("fixture listing warning")
        );
        assert_eq!(backend.discover_nodes(), fixture_discover_nodes());

        let pairs = backend.list_pairs();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].rgb, "/dev/fixed-rgb");
        assert_eq!(pairs[0].ir, "/dev/fixed-ir");
        assert_eq!(pairs[0].id.as_deref(), Some("1111:2222"));
        assert!(pairs[0].fixed);
        assert_eq!(pairs[1].rgb, "/dev/usb-rgb");
        assert_eq!(pairs[1].ir, "/dev/usb-ir");
        assert_eq!(pairs[1].id, None);
        assert!(!pairs[1].fixed);

        assert!(backend
            .open_rgb("/dev/ignored")
            .err()
            .expect("fixture RGB open must refuse")
            .to_string()
            .contains("fixture RGB"));
        assert!(backend
            .open_ir("/dev/ignored")
            .err()
            .expect("fixture IR open must refuse")
            .to_string()
            .contains("fixture IR"));
    }

    #[test]
    fn default_supervisor_is_process_wide_and_uses_exact_uvc_delegates() {
        assert!(std::ptr::eq(
            default_camera_supervisor(),
            default_camera_supervisor()
        ));
        assert!(default_camera_supervisor()
            .backend
            .has_exact_production_uvc_delegates());
    }
}
