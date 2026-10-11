// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! GPU groundwork tests (ADR-0033): the closed-admission refusal in every
//! build, and the ignored hardware measurements `gpu_hw_*` that collect
//! the discovery evidence a certification starts from. The hardware tests
//! need no camera, no daemon and no settings: they resolve the validated
//! provider, enumerate the GPU and read the identity, including firmware
//! where the reader permits.

mod gpu_groundwork_tests {
    use crate::gpu::Setting;
    use crate::npu::gpu::{self, Discovery, Firmware};
    use std::path::{Path, PathBuf};

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
        assert!(matches!(value("gpu=off\n"), Setting::Value(b"off")));
        for text in [
            "gpu=on\ngpu=on\n",
            "gpu=on\ngpu=off\n",
            "gpu=off\ngpu=off\n",
        ] {
            assert!(matches!(value(text), Setting::Duplicate), "{text:?}");
            assert!(!gpu::switch_allows(None, value(text)), "{text:?}");
        }
    }

    #[test]
    fn gpu_device_indices_discovery_refuses_multiple_before_identity_reads() {
        for (indices, expected) in [
            ("0 1", vec!["GPU.0", "GPU.1"]),
            ("0 1 2", vec!["GPU.0", "GPU.1", "GPU.2"]),
            ("0,1", vec!["GPU.0", "GPU.1"]),
            (" 0, 1\t2 ", vec!["GPU.0", "GPU.1", "GPU.2"]),
        ] {
            let discovery = gpu::discover_enumerated_gpu(indices, |_| {
                panic!("multiple GPUs must refuse before reading device properties")
            });
            let Discovery::MultipleGpus(devices) = discovery else {
                panic!("{indices:?} did not refuse as multiple GPUs: {discovery:?}");
            };
            assert_eq!(devices, expected);
        }
        assert!(matches!(
            gpu::discover_enumerated_gpu(" , \t", |_| panic!("absent GPU has no properties")),
            Discovery::Absent
        ));
    }

    #[test]
    fn gpu_device_indices_discovery_reads_the_single_explicit_device() {
        let discovery = gpu::discover_enumerated_gpu(" 7 ", |device| {
            assert_eq!(device, "GPU.7");
            Discovery::Found(gpu::Identity {
                selected_library: "fixture alias".into(),
                canonical_library: "fixture endpoint".into(),
                runtime_version: "fixture build".into(),
                full_name: device.into(),
                capabilities: "FP16".into(),
                firmware_node_pci: None,
                firmware: loaded_xe(),
            })
        });
        let Discovery::Found(identity) = discovery else {
            panic!("single device did not reach identity reading: {discovery:?}");
        };
        assert_eq!(identity.full_name, "GPU.7");
    }

    fn loaded_xe() -> Firmware {
        Firmware::Loaded {
            guc: "70.72.1".into(),
            huc: "9.4.13".into(),
        }
    }

    fn xe_report(controller: &str, version: Option<&str>) -> String {
        // xe_uc_fw_print always emits wanted, but found only for a nonzero
        // parsed version. N/A is the unsupported controller's status.
        let status = if version.is_some() { "RUNNING" } else { "N/A" };
        let mut report = format!(
            "{controller} firmware: xe/fixture.bin\n\tstatus: {status}\n\twanted release version 0.0.0\n"
        );
        if let Some(version) = version {
            report.push_str(&format!("\tfound release version {version}\n"));
        }
        report
    }

    fn write_xe_uc(node: &Path, gt: &str, guc: Option<&str>, huc: Option<&str>) -> PathBuf {
        let uc = node.join(gt).join("uc");
        std::fs::create_dir_all(&uc).unwrap();
        std::fs::write(uc.join("guc_info"), xe_report("GuC", guc)).unwrap();
        std::fs::write(uc.join("huc_info"), xe_report("HuC", huc)).unwrap();
        uc
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

    #[test]
    fn gpu_firmware_reader_walks_xe_tiles_and_gts() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("dri/128");
        for gt in ["tile0/gt0", "tile1/gt2", "tile4/gt9"] {
            write_xe_uc(&node, gt, Some("70.72.1"), Some("9.4.13"));
        }
        assert_eq!(gpu::firmware(dir.path()), loaded_xe());
    }

    #[test]
    fn gpu_firmware_reader_ignores_drm_global_and_client_entries() {
        let dir = tempfile::tempdir().unwrap();
        let dri = dir.path().join("dri");
        write_xe_uc(
            &dri.join("128"),
            "tile0/gt0",
            Some("70.72.1"),
            Some("9.4.13"),
        );
        std::fs::write(dri.join("bridges"), "global DRM info").unwrap();
        std::fs::create_dir(dri.join("client-21")).unwrap();
        std::os::unix::fs::symlink(dri.join("gone"), dri.join("client-99")).unwrap();
        assert_eq!(gpu::firmware(dir.path()), loaded_xe());
    }

    #[test]
    fn gpu_firmware_reader_accepts_normal_xe_guc_only_gt() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("dri/128");
        write_xe_uc(&node, "tile0/gt0", Some("70.72.1"), None);
        write_xe_uc(&node, "tile0/gt1", Some("70.72.1"), Some("9.4.13"));
        assert_eq!(gpu::firmware(dir.path()), loaded_xe());
    }

    #[test]
    fn gpu_firmware_reader_refuses_nodes_without_a_complete_pair() {
        for guc in [Some("70.72.1"), None] {
            let dir = tempfile::tempdir().unwrap();
            let node = dir.path().join("dri/128");
            write_xe_uc(&node, "tile0/gt0", guc, None);
            assert!(matches!(gpu::firmware(dir.path()), Firmware::Malformed(_)));
        }
    }

    #[test]
    fn gpu_firmware_reader_refuses_huc_only_gt() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("dri/128");
        write_xe_uc(&node, "tile0/gt0", Some("70.72.1"), Some("9.4.13"));
        write_xe_uc(&node, "tile1/gt2", None, Some("9.4.13"));
        assert!(matches!(
            gpu::firmware(dir.path()),
            Firmware::Malformed(why) if why.contains("HuC loaded without a GuC")
        ));
    }

    #[test]
    fn gpu_firmware_reader_refuses_conflicting_guc_only_gt() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("dri/128");
        write_xe_uc(&node, "tile0/gt0", Some("70.72.1"), Some("9.4.13"));
        write_xe_uc(&node, "tile1/gt2", Some("70.73.1"), None);
        assert!(matches!(
            gpu::firmware(dir.path()),
            Firmware::Malformed(why) if why.contains("conflicting firmware builds")
        ));
    }

    #[test]
    fn gpu_firmware_reader_refuses_conflicting_complete_pairs() {
        for (guc, huc) in [("70.73.1", "9.4.13"), ("70.72.1", "9.5.13")] {
            let dir = tempfile::tempdir().unwrap();
            let node = dir.path().join("dri/128");
            write_xe_uc(&node, "tile0/gt0", Some("70.72.1"), Some("9.4.13"));
            write_xe_uc(&node, "tile1/gt2", Some(guc), Some(huc));
            assert!(matches!(
                gpu::firmware(dir.path()),
                Firmware::Malformed(why) if why.contains("conflicting firmware builds")
            ));
        }
    }

    #[test]
    fn gpu_firmware_reader_preserves_directory_io_errors() {
        // ENOTDIR is deterministic even as root, unlike chmod-based tests.
        for broken in ["tile1", "tile1/gt2", "tile1/gt2/uc", "gt9"] {
            let dir = tempfile::tempdir().unwrap();
            let node = dir.path().join("dri/128");
            write_xe_uc(&node, "tile0/gt0", Some("70.72.1"), Some("9.4.13"));
            let path = node.join(broken);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "not a directory").unwrap();
            assert_eq!(gpu::firmware(dir.path()), Firmware::Unreadable, "{broken}");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dri"), "not a directory").unwrap();
        assert_eq!(gpu::firmware(dir.path()), Firmware::Unreadable);
    }

    #[test]
    fn gpu_firmware_reader_preserves_broken_node_alias_errors() {
        let dir = tempfile::tempdir().unwrap();
        let dri = dir.path().join("dri");
        write_xe_uc(
            &dri.join("128"),
            "tile0/gt0",
            Some("70.72.1"),
            Some("9.4.13"),
        );
        std::os::unix::fs::symlink(dri.join("missing"), dri.join("0000:00:03.0")).unwrap();
        assert_eq!(gpu::firmware(dir.path()), Firmware::Unreadable);
    }

    #[test]
    fn gpu_firmware_reader_preserves_controller_read_errors() {
        for controller in ["guc_info", "huc_info"] {
            for missing in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let node = dir.path().join("dri/128");
                write_xe_uc(&node, "tile0/gt0", Some("70.72.1"), Some("9.4.13"));
                let uc = write_xe_uc(&node, "tile1/gt2", Some("70.72.1"), None);
                let path = uc.join(controller);
                std::fs::remove_file(&path).unwrap();
                if !missing {
                    // Reading a directory as a controller yields EISDIR.
                    std::fs::create_dir(&path).unwrap();
                }
                assert_eq!(gpu::firmware(dir.path()), Firmware::Unreadable);
            }
        }
    }

    #[test]
    fn gpu_firmware_reader_refuses_malformed_controller_reports() {
        let malformed_reports = [
            "",
            "HuC firmware: xe/x.bin\nstatus: N/A\nwanted release version garbage\n",
            "HuC firmware: xe/x.bin\nstatus: N/A\nwanted release version 0.0.0\nfound release version garbage\n",
            "HuC firmware: xe/x.bin\nstatus: N/A\nwanted release version 0.0.0\nfound release version 9..13\n",
            "HuC firmware: xe/x.bin\nstatus: N/A\nwanted release version 0.0.0\nfound release version 9.4\n",
            "HuC firmware: xe/x.bin\nstatus: RUNNING\nwanted release version 0.0.0\nfound release version 9.4.13\nfound release version 9.4.13\n",
            "HuC firmware: xe/x.bin\nstatus: RUNNING\nwanted release version 0.0.0\n",
            "HuC firmware: xe/x.bin\nstatus: unknown\nwanted release version 0.0.0\nfound release version 9.4.13\n",
            "HuC firmware: xe/x.bin\nstatus: AVAILABLE\nwanted release version 0.0.0\nfound release version 9.4.13\n",
            "HuC firmware: xe/x.bin\nstatus: RUNNING\nwanted release version 0.0.0\nfound compatibility version 9.4.13\n",
            "HuC firmware: xe/x.bin\nstatus: RUNNING\nwanted release version 0.0.0\nfound release version 0.0.0\n",
            "HuC firmware: xe/x.bin\nstatus: RUNNING\nstatus:MISSING\nwanted release version 0.0.0\nfound release version 9.4.13\n",
            "HuC firmware: xe/x.bin\nstatus: RUNNING\nwanted release version 0.0.0\nfound release version 4294967296.4.13\n",
        ];
        for (controller, file) in [("GuC", "guc_info"), ("HuC", "huc_info")] {
            for report in malformed_reports {
                let dir = tempfile::tempdir().unwrap();
                let node = dir.path().join("dri/128");
                write_xe_uc(&node, "tile0/gt0", Some("70.72.1"), Some("9.4.13"));
                let uc = write_xe_uc(&node, "tile1/gt2", Some("70.72.1"), None);
                let report = report.replace("HuC", controller);
                std::fs::write(uc.join(file), &report).unwrap();
                assert!(
                    matches!(gpu::firmware(dir.path()), Firmware::Malformed(_)),
                    "malformed sibling report disappeared: {report:?}"
                );
            }
        }
    }

    #[test]
    fn gpu_firmware_reader_uses_i915_found_not_wanted_version() {
        let dir = tempfile::tempdir().unwrap();
        let uc = dir.path().join("dri/128/gt7/uc");
        std::fs::create_dir_all(&uc).unwrap();
        std::fs::write(
            uc.join("guc_info"),
            "GuC firmware: i915/x.bin\nstatus: RUNNING\nversion: wanted 70.99.0, found 70.49.4\n",
        )
        .unwrap();
        std::fs::write(
            uc.join("huc_info"),
            "HuC firmware: i915/x.bin\nstatus: TRANSFERRED\nversion: found 7.9.3\n",
        )
        .unwrap();
        assert_eq!(
            gpu::firmware(dir.path()),
            Firmware::Loaded {
                guc: "70.49.4".into(),
                huc: "7.9.3".into(),
            }
        );
    }

    #[test]
    fn gpu_firmware_reader_keeps_xe_release_build_not_compatibility() {
        let dir = tempfile::tempdir().unwrap();
        let uc = write_xe_uc(
            &dir.path().join("dri/128"),
            "tile0/gt0",
            Some("70.72.1.9"),
            Some("9.4.13.2"),
        );
        let mut report = xe_report("GuC", Some("70.72.1.9"));
        report.push_str("found compatibility version 1.2.3\n");
        std::fs::write(uc.join("guc_info"), report).unwrap();
        assert_eq!(
            gpu::firmware(dir.path()),
            Firmware::Loaded {
                guc: "70.72.1.9".into(),
                huc: "9.4.13.2".into(),
            }
        );
    }

    fn write_pci(sysfs: &Path, slot: &str, vendor: &str, device: &str) {
        let base = sysfs.join(slot);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("vendor"), format!("{vendor}\n")).unwrap();
        std::fs::write(base.join("device"), format!("{device}\n")).unwrap();
    }

    #[test]
    fn gpu_firmware_node_pci_uses_the_same_unique_node_not_the_first_bus_alias() {
        let dir = tempfile::tempdir().unwrap();
        let dri = dir.path().join("dri");
        let sysfs = dir.path().join("pci");
        write_xe_uc(
            &dri.join("128"),
            "tile0/gt0",
            Some("70.72.1"),
            Some("9.4.13"),
        );
        std::fs::create_dir(dri.join("0")).unwrap();
        std::os::unix::fs::symlink(dri.join("0"), dri.join("0000:00:01.0")).unwrap();
        std::os::unix::fs::symlink(dri.join("128"), dri.join("0000:00:02.0")).unwrap();
        write_pci(&sysfs, "0000:00:01.0", "0x1234", "0x5678");
        write_pci(&sysfs, "0000:00:02.0", "0x8086", "0x1234");
        assert_eq!(
            gpu::firmware_with_pci(dir.path(), &sysfs),
            (loaded_xe(), Some("0000:00:02.0 0x8086:0x1234".into()))
        );
    }

    #[test]
    fn gpu_firmware_node_pci_is_none_without_a_unique_readable_binding() {
        let dir = tempfile::tempdir().unwrap();
        let dri = dir.path().join("dri");
        let sysfs = dir.path().join("pci");
        write_xe_uc(
            &dri.join("128"),
            "tile0/gt0",
            Some("70.72.1"),
            Some("9.4.13"),
        );
        // Numeric debugfs nodes do not establish a PCI slot.
        assert_eq!(
            gpu::firmware_with_pci(dir.path(), &sysfs),
            (loaded_xe(), None)
        );
        std::os::unix::fs::symlink(dri.join("128"), dri.join("0000:00:02.0")).unwrap();
        // A known slot without readable sysfs IDs still establishes no PCI IDs.
        assert_eq!(
            gpu::firmware_with_pci(dir.path(), &sysfs),
            (loaded_xe(), None)
        );
        write_pci(&sysfs, "0000:00:02.0", "malformed", "0x1234");
        assert_eq!(
            gpu::firmware_with_pci(dir.path(), &sysfs),
            (loaded_xe(), None)
        );
        write_pci(&sysfs, "0000:00:02.0", "0x8086", "0x1234");
        // Two different bus aliases for one node are not a unique binding.
        std::os::unix::fs::symlink(dri.join("128"), dri.join("0001:00:02.0")).unwrap();
        assert_eq!(
            gpu::firmware_with_pci(dir.path(), &sysfs),
            (loaded_xe(), None)
        );
    }

    #[test]
    fn gpu_firmware_node_pci_is_none_when_firmware_nodes_are_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let sysfs = dir.path().join("pci");
        for slot in ["0000:00:02.0", "0000:00:03.0"] {
            write_xe_uc(
                &dir.path().join("dri").join(slot),
                "tile0/gt0",
                Some("70.72.1"),
                Some("9.4.13"),
            );
            write_pci(&sysfs, slot, "0x8086", "0x1234");
        }
        let (firmware, pci) = gpu::firmware_with_pci(dir.path(), &sysfs);
        assert!(matches!(firmware, Firmware::Malformed(_)));
        assert_eq!(pci, None);
    }

    /// Ignored: needs the real debugfs and provider stack. Run as root for
    /// the firmware fields: a Found result MUST carry loaded firmware, so an
    /// unreadable/malformed report fails this evidence harness. The provider
    /// resolves through the same validated selection as production: an
    /// installed reviewed soname automatically, or `IRLUME_NPU_LIBRARY`
    /// pointing at one.
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
                assert!(!identity.runtime_version.is_empty());
                assert!(
                    identity.capabilities.contains("FP16"),
                    "{}",
                    identity.capabilities
                );
                let Firmware::Loaded { guc, huc } = &identity.firmware else {
                    panic!(
                        "hardware discovery needs loaded firmware: {:?}",
                        identity.firmware
                    );
                };
                println!(
                    "gpu incomplete identity: {} | {} | runtime {} | guc {} huc {} | firmware-node PCI {:?} (plugin mapping unverified) | via {} -> {}",
                    identity.full_name,
                    identity.capabilities,
                    identity.runtime_version,
                    guc,
                    huc,
                    identity.firmware_node_pci,
                    identity.selected_library,
                    identity.canonical_library,
                );
            }
            Discovery::Absent => println!("no GPU on this host"),
            Discovery::MultipleGpus(devices) => println!("refused, multiple GPUs: {devices:?}"),
            Discovery::NotAdmitted => panic!("the admitted test entry must not refuse"),
            Discovery::Unavailable(why) => panic!("discovery failed: {why}"),
        }
    }
}
