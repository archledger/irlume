// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! GPU groundwork tests (ADR-0033): the closed-admission refusal in every
//! build, and the ignored hardware measurements `gpu_hw_*` that collect
//! the discovery evidence a certification starts from. The hardware tests
//! need no camera, no daemon and no settings: they resolve the validated
//! provider, enumerate the GPU and read the identity, including firmware
//! where the reader permits.

mod gpu_groundwork_tests {
    use crate::npu::gpu::{self, Discovery, Firmware, Setting};

    /// The production entry refuses before dlopen, exactly as the NPU
    /// context does: no profile admits GPU loading yet.
    #[test]
    fn gpu_discovery_refuses_before_loading_in_production() {
        assert!(matches!(
            gpu::discover(&crate::npu::RuntimeSelection::Automatic),
            Discovery::NotAdmitted
        ));
    }

    /// The kill switch follows the NPU switch's semantics: absent allows,
    /// off values and malformed input disable, either source disabling
    /// wins (ADR-0033 section 8).
    #[test]
    fn gpu_switch_follows_the_npu_switch_semantics() {
        use std::ffi::OsStr;
        assert!(gpu::switch_allows(None, Setting::Absent));
        for off in ["0", "false", "no", "off", "", "maybe", "2"] {
            assert!(
                !gpu::switch_allows(None, Setting::Value(off.as_bytes())),
                "{off:?} must disable"
            );
        }
        for on in ["1", "true", "yes", "on", " ON "] {
            assert!(
                gpu::switch_allows(None, Setting::Value(on.as_bytes())),
                "{on:?} must leave admission to decide"
            );
        }
        assert!(gpu::switch_allows(Some(OsStr::new("on")), Setting::Absent));
        // Either source disabling wins.
        assert!(!gpu::switch_allows(
            Some(OsStr::new("on")),
            Setting::Value(b"off")
        ));
        assert!(!gpu::switch_allows(
            Some(OsStr::new("off")),
            Setting::Absent
        ));
        assert!(!gpu::switch_allows(None, Setting::Unreadable));

        fn value(text: &str) -> Setting<'_> {
            gpu::settings_conf_value(text.as_bytes())
        }
        assert!(matches!(value(""), Setting::Absent));
        assert!(matches!(value("gpu=on\n"), Setting::Value(b"on")));
        // Any line switching it off wins.
        assert!(matches!(value("gpu=on\ngpu=off\n"), Setting::Value(b"off")));
    }

    /// The firmware reader classifies a synthetic debugfs tree: one loaded
    /// pair, none, or several graphics nodes.
    #[test]
    fn gpu_firmware_reader_classifies_debugfs_trees() {
        let dir = tempfile::tempdir().unwrap();
        let dri = dir.path().join("dri");
        let write = |card: &str, guc: &str, huc: &str| {
            let uc = dri.join(card).join("gt0/uc");
            std::fs::create_dir_all(&uc).unwrap();
            std::fs::write(
                uc.join("guc_info"),
                format!("GuC firmware: i915/x_guc.bin\nstatus: RUNNING\nversion: found {guc}\n"),
            )
            .unwrap();
            std::fs::write(
                uc.join("huc_info"),
                format!("HuC firmware: i915/x_huc.bin\nstatus: RUNNING\nversion: found {huc}\n"),
            )
            .unwrap();
        };
        std::fs::create_dir_all(&dri).unwrap();
        assert_eq!(gpu::firmware(dir.path()), Firmware::Unreadable);
        write("128", "70.49.4", "7.9.3");
        assert_eq!(
            gpu::firmware(dir.path()),
            Firmware::Loaded {
                guc: "70.49.4".into(),
                huc: "7.9.3".into()
            }
        );
        // A bus-address symlink to the same node is the same GPU.
        std::os::unix::fs::symlink(dri.join("128"), dri.join("0000:00:02.0")).unwrap();
        assert_eq!(
            gpu::firmware(dir.path()),
            Firmware::Loaded {
                guc: "70.49.4".into(),
                huc: "7.9.3".into()
            }
        );
        // Two graphics nodes are ambiguous for a single-GPU placement.
        write("129", "70.49.4", "7.9.3");
        assert!(matches!(gpu::firmware(dir.path()), Firmware::Malformed(_)));
    }

    /// Ignored: needs the real debugfs and provider stack. Run as root for
    /// the firmware fields; a normal user records the unreadable firmware
    /// the ADR makes refuse placement. The provider resolves through the
    /// same validated selection as production: an installed reviewed soname
    /// automatically, or `IRLUME_NPU_LIBRARY` pointing at one.
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider and an Intel GPU"]
    fn gpu_hw_discovery_reports_one_gpu_or_the_refusal() {
        let selection = crate::npu::RuntimeSelection::read(
            std::env::var_os("IRLUME_NPU_LIBRARY").as_deref(),
            crate::npu::LibrarySetting::Absent,
        );
        match gpu::discover_admitted(&selection) {
            Discovery::Found(identity) => {
                assert!(!identity.full_name.is_empty());
                assert!(
                    identity.capabilities.contains("FP16"),
                    "{}",
                    identity.capabilities
                );
                println!(
                    "gpu identity: {} | {} | guc {:?} huc {:?} | via {}",
                    identity.full_name,
                    identity.capabilities,
                    match &identity.firmware {
                        Firmware::Loaded { guc, .. } => guc,
                        _ => "unreadable",
                    },
                    match &identity.firmware {
                        Firmware::Loaded { huc, .. } => huc,
                        _ => "unreadable",
                    },
                    identity.selected_library,
                );
            }
            Discovery::Absent => println!("no GPU on this host"),
            Discovery::MultipleGpus(devices) => println!("refused, multiple GPUs: {devices:?}"),
            Discovery::NotAdmitted => panic!("the admitted test entry must not refuse"),
            Discovery::Unavailable(why) => panic!("discovery failed: {why}"),
        }
    }
}
