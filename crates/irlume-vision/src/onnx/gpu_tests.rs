// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! GPU tests (ADR-0033): the closed-admission refusal, the
//! complete-identity parsers and binding rules, and the ignored hardware
//! measurements `gpu_hw_*` that collect the evidence a certification
//! starts from. The hardware tests need no camera, no daemon and no
//! settings: they resolve the validated provider, enumerate the GPU, bind
//! it to its render node and compile under the fixed configuration.

mod gpu_groundwork_tests {
    use crate::gpu::Setting;
    use crate::npu::gpu::{self, Discovery, Firmware, Identity, RenderNode};
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
            Discovery::Found(Box::new(fixture_identity(device)))
        });
        let Discovery::Found(identity) = discovery else {
            panic!("single device did not reach identity reading: {discovery:?}");
        };
        assert_eq!(identity.full_name, "GPU.7");
    }

    /// A complete identity with fixture values, so parser and digest tests
    /// share one construction site.
    fn fixture_identity(full_name: &str) -> Identity {
        Identity {
            selected_library: "fixture alias".into(),
            canonical_library: "fixture endpoint".into(),
            runtime_version: "2026.2".into(),
            runtime_build: "2026.2.1-21919-ede283a88e3".into(),
            gpu_plugin: "2026.2.1-21919-ede283a88e3".into(),
            full_name: full_name.into(),
            capabilities: "FP32 BIN FP16 INT8".into(),
            architecture: "GPU: vendor=0x8086 arch=v12.4.0".into(),
            execution_units: "24".into(),
            total_memory: "7125323776".into(),
            device_id: "0x46d1".into(),
            device_pci: "0000:00:02.0".into(),
            render_node: RenderNode {
                name: "renderD128".into(),
                pci: "0000:00:02.0".into(),
                vendor: "0x8086".into(),
                device: "0x46d1".into(),
            },
            firmware: loaded_xe(),
            loader: "opencl".into(),
            configuration: gpu::COMPILE_CONFIGURATION.to_owned(),
            libraries: "/fixture/libopenvino_c.so.2621 00\n".into(),
        }
    }

    /// The fixed compile configuration is the ADR-0033 section 2 contract:
    /// batch 1, the latency hint, and the precision the certification
    /// judges, named explicitly.
    #[test]
    fn gpu_compile_configuration_pins_the_adr0033_contract() {
        assert_eq!(
            gpu::COMPILE_CONFIGURATION,
            "batch=1;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=f16"
        );
    }

    /// `DEVICE_PCI_INFO` parses to the canonical sysfs address, and only
    /// that: reordered, truncated or out-of-range reports refuse instead
    /// of guessing a component.
    #[test]
    fn gpu_pci_reports_parse_to_canonical_addresses() {
        assert_eq!(
            gpu::plugin_pci("{domain: 0 bus: 0 device: 0x2 function: 0}"),
            Some("0000:00:02.0".into())
        );
        assert_eq!(
            gpu::plugin_pci("{domain: 1 bus: 0xa device: 0x1f function: 7}"),
            Some("0001:0a:1f.7".into())
        );
        // The plugin prints domain, bus and function as decimal: bus 10 is
        // 0x0a, not 0x10.
        assert_eq!(
            gpu::plugin_pci("{domain: 0 bus: 10 device: 0x2 function: 0}"),
            Some("0000:0a:02.0".into())
        );
        assert_eq!(
            gpu::plugin_pci("{domain: 16 bus: 0 device: 0x2 function: 0}"),
            Some("0010:00:02.0".into())
        );
        for malformed in [
            "",
            "{}",
            "{domain: 0 bus: 0 device: 0x2 }",
            "{bus: 0 domain: 0 device: 0x2 function: 0}",
            "{domain: 0 bus: 0 device: 0x100 function: 0}",
            "{domain: 0x10000 bus: 0 device: 0x2 function: 0}",
            "{domain: 0 bus: 0 device: 0x2 function: 8}",
            "{domain: 0 bus: 0 device: zz function: 0}",
            "{domain: 0 bus: 0x device: 0x2 function: 0}",
            "{domain: 0 bus: 0 device: 0x2 function: 0 function: 1}",
            "{domain: 0 bus: 0 device: 0x2 function: 0 extra}",
            "{domain: 0 bus: 0 device: 0x2 function: 0 2}",
        ] {
            assert_eq!(gpu::plugin_pci(malformed), None, "{malformed:?}");
        }
        assert_eq!(
            gpu::architecture_vendor("GPU: vendor=0x8086 arch=v12.4.0"),
            Some("0x8086".into())
        );
        assert_eq!(gpu::architecture_vendor("GPU: arch=v12.4.0"), None);
        assert_eq!(gpu::architecture_vendor("GPU: vendor=8086"), None);
    }

    /// A fixture DRM class: `renderD128/device` resolves to the PCI
    /// device directory the kernel links it to.
    fn fixture_drm(root: &Path, node: &str, pci: &str, vendor: &str, device: &str) {
        let target = root.join("pci").join(pci);
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("vendor"), format!("{vendor}\n")).unwrap();
        std::fs::write(target.join("device"), format!("{device}\n")).unwrap();
        let entry = root.join("drm").join(node);
        std::fs::create_dir_all(&entry).unwrap();
        std::os::unix::fs::symlink(&target, entry.join("device")).unwrap();
    }

    /// The render-node binding accepts only the one node at the plugin's
    /// address whose vendor and device ids the plugin also reported;
    /// foreign ids, a missing node and duplicates all refuse
    /// (ADR-0033 section 3).
    #[test]
    fn gpu_render_node_binding_refuses_mismatch_and_ambiguity() {
        let dir = tempfile::tempdir().unwrap();
        fixture_drm(dir.path(), "renderD128", "0000:00:02.0", "0x8086", "0x46d1");
        // An unrelated card node never joins the binding.
        std::fs::create_dir_all(dir.path().join("drm/card1")).unwrap();
        let bound =
            gpu::render_node(&dir.path().join("drm"), "0000:00:02.0", "0x8086", "0x46d1").unwrap();
        assert_eq!(
            bound,
            RenderNode {
                name: "renderD128".into(),
                pci: "0000:00:02.0".into(),
                vendor: "0x8086".into(),
                device: "0x46d1".into(),
            }
        );
        // The plugin's ids must match the node's sysfs attributes.
        let mismatch =
            gpu::render_node(&dir.path().join("drm"), "0000:00:02.0", "0x8086", "0x9999")
                .unwrap_err();
        assert!(mismatch.contains("the plugin"), "{mismatch}");
        // No node carries the plugin's address.
        let absent = gpu::render_node(&dir.path().join("drm"), "0000:00:09.0", "0x8086", "0x46d1")
            .unwrap_err();
        assert!(absent.contains("no render node"), "{absent}");
        // Two nodes at one address cannot name the plugin's device.
        fixture_drm(dir.path(), "renderD129", "0000:00:02.0", "0x8086", "0x46d1");
        let ambiguous =
            gpu::render_node(&dir.path().join("drm"), "0000:00:02.0", "0x8086", "0x46d1")
                .unwrap_err();
        assert!(ambiguous.contains("more than one"), "{ambiguous}");
        // A malformed id attribute is unreadable, not a partial binding.
        std::fs::write(dir.path().join("pci/0000:00:02.0/vendor"), "not-an-id\n").unwrap();
        assert!(
            gpu::render_node(&dir.path().join("drm"), "0000:00:02.0", "0x8086", "0x46d1",).is_err()
        );
    }

    /// The loader family comes from the mapped libraries, and both
    /// families mapped at once is an unresolvable identity.
    #[test]
    fn gpu_loader_stack_requires_exactly_one_family() {
        let line = |path: &str| format!("7f0000000000-7f0000001000 r-xp 00000000 00:23 1 {path}");
        let (family, _) = gpu::loader_stack(&line("/usr/lib/libOpenCL.so.1.0.0")).unwrap();
        assert_eq!(family, "opencl");
        let (family, _) = gpu::loader_stack(&line("/usr/lib/libze_loader.so.1")).unwrap();
        assert_eq!(family, "level-zero");
        assert!(gpu::loader_stack("").is_err());
        // A non-executable mapping of the loader is not the plugin's stack.
        let dormant = "7f0000000000-7f0000001000 r--p 00000000 00:23 1 /usr/lib/libOpenCL.so.1.0.0";
        assert!(gpu::loader_stack(dormant).is_err());
        let both = format!(
            "{}\n{}",
            line("/usr/lib/libOpenCL.so.1.0.0"),
            line("/usr/lib/libze_loader.so.1")
        );
        let error = gpu::loader_stack(&both).unwrap_err();
        assert!(error.contains("both"), "{error}");
    }

    /// A fixture stack: the C API, the core, the GPU plugin, an OpenCL
    /// loader and the two frontends beside the core, as the memory map
    /// lines of an enumerated process would name them.
    fn fixture_stack(dir: &Path) -> (String, Vec<(PathBuf, u64)>, PathBuf) {
        let mut mapped = Vec::new();
        let mut maps = String::new();
        let mut line = |path: &Path| {
            let inode = {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(path).unwrap().ino()
            };
            maps.push_str(&format!(
                "7f0000000000-7f0000001000 r-xp 00000000 00:23 {inode} {}\n",
                path.display()
            ));
            inode
        };
        for name in [
            "libopenvino_c.so.2621",
            "libopenvino.so.2621",
            "libopenvino_intel_gpu_plugin.so",
            "libOpenCL.so.1",
            "libigc.so.2.41.0",
        ] {
            let path = dir.join(name);
            std::fs::write(&path, format!("bytes of {name}")).unwrap();
            let inode = line(&path);
            mapped.push((path, inode));
        }
        for name in [
            "libopenvino_ir_frontend.so.2621",
            "libopenvino_onnx_frontend.so.2621",
        ] {
            std::fs::write(dir.join(name), format!("bytes of {name}")).unwrap();
        }
        // The process executable: mapped and executable, but excluded from
        // the manifest like the NPU execution inventory excludes it.
        let executable = dir.join("test-binary");
        std::fs::write(&executable, b"the test binary").unwrap();
        line(&executable);
        (maps, mapped, executable)
    }

    /// The GPU library inventory hashes every mapped executable library
    /// through one open file, requires the stack's members, and refuses
    /// when a mapped file is not the one that was hashed.
    #[test]
    fn gpu_library_inventory_hashes_and_verifies_the_gpu_stack() {
        let dir = tempfile::tempdir().unwrap();
        let (maps, mapped, executable) = fixture_stack(dir.path());
        let (manifest, hashed) = gpu::gpu_libraries(&maps, &executable).unwrap();
        for (path, _) in &mapped {
            let line = format!("{} ", path.display());
            assert!(manifest.contains(&line), "{line} missing from {manifest}");
        }
        assert!(hashed.len() >= mapped.len() + 3, "frontends join the set");
        assert!(
            !manifest.contains("test-binary"),
            "the executable stays out of the manifest: {manifest}"
        );
        assert!(
            hashed.iter().any(|library| library.path == executable),
            "the executable stays in the verified inventory"
        );
        // An executable that is not mapped refuses.
        let absent = dir.path().join("other-binary");
        let error = gpu::gpu_libraries(&maps, &absent).unwrap_err();
        assert!(error.contains("absent"), "{error}");
        // Every required member must be mapped; a stack without the plugin
        // or a loader refuses.
        for drop in ["libopenvino_intel_gpu_plugin.so", "libOpenCL.so.1"] {
            let pruned: String = maps
                .lines()
                .filter(|line| !line.contains(drop))
                .collect::<Vec<_>>()
                .join("\n");
            let error = gpu::gpu_libraries(&pruned, &executable).unwrap_err();
            assert!(
                error.contains("GPU plugin") || error.contains("loader"),
                "{drop}: {error}"
            );
        }
        // This test process has not enumerated a GPU, so its real map
        // refuses too: no member is present.
        let real = std::fs::read_to_string("/proc/self/maps").unwrap();
        let own = std::fs::read_link("/proc/self/exe").unwrap();
        assert!(gpu::gpu_libraries(&real, &own).is_err());
        // A mapped library replaced under the identity is a different
        // file: the inode kept no longer matches the map's.
        let plugin = dir.path().join("libopenvino_intel_gpu_plugin.so");
        let replaced = dir.path().join("replacement");
        std::fs::write(&replaced, "other bytes").unwrap();
        std::fs::rename(&replaced, &plugin).unwrap();
        let error = gpu::gpu_libraries(&maps, &executable).unwrap_err();
        assert!(error.contains("not the file that was hashed"), "{error}");
    }

    /// The digest binds every identity field: moving or changing text in
    /// any one of them produces a different digest, and identical fields
    /// produce the identical digest.
    #[test]
    fn gpu_identity_digest_binds_every_field() {
        let identity = fixture_identity("Intel(R) fixture GPU");
        let mut same = fixture_identity("Intel(R) fixture GPU");
        assert_eq!(identity.digest(), same.digest());
        let mut different = fixture_identity("Intel(R) other GPU");
        assert_ne!(identity.digest(), different.digest());
        same.render_node.pci = "0000:00:03.0".into();
        assert_ne!(identity.digest(), same.digest());
        different = fixture_identity("Intel(R) fixture GPU");
        different.libraries = "/fixture/other 11\n".into();
        assert_ne!(identity.digest(), different.digest());
        different = fixture_identity("Intel(R) fixture GPU");
        different.firmware = Firmware::Unreadable;
        assert_ne!(identity.digest(), different.digest());
        different = fixture_identity("Intel(R) fixture GPU");
        different.loader = "level-zero".into();
        assert_ne!(identity.digest(), different.digest());
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

    /// The shared hardware-lane setup: the validated provider selection and
    /// the real kernel sources.
    fn hw_selection() -> crate::npu::RuntimeSelection {
        crate::npu::RuntimeSelection::read(
            std::env::var_os("IRLUME_NPU_LIBRARY").as_deref(),
            crate::npu::LibrarySetting::Absent,
        )
    }

    /// Ignored: needs the real provider stack and an Intel GPU. Run as root
    /// so debugfs joins the identity: a Found result MUST carry the loaded
    /// firmware of the bound render node. The complete identity binds the
    /// plugin's PCI report, exactly one render node, the firmware node at
    /// the same address, one loader family and the hashed library manifest
    /// (ADR-0033 section 3).
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider and an Intel GPU"]
    fn gpu_hw_identity_binds_plugin_render_node_and_libraries() {
        match gpu::discover_admitted(&hw_selection()) {
            Discovery::Found(identity) => {
                assert!(!identity.full_name.is_empty());
                assert!(!identity.runtime_version.is_empty());
                assert!(!identity.runtime_build.is_empty());
                assert!(!identity.gpu_plugin.is_empty());
                assert!(
                    identity.capabilities.contains("FP16"),
                    "{}",
                    identity.capabilities
                );
                assert_eq!(
                    identity.render_node.pci, identity.device_pci,
                    "the render node and the plugin report one PCI address"
                );
                assert_eq!(
                    identity.render_node.vendor, "0x8086",
                    "the bound render node is the plugin's Intel device"
                );
                assert_eq!(
                    identity.render_node.device, identity.device_id,
                    "the bound render node carries the plugin's device id"
                );
                assert!(
                    identity.render_node.name.starts_with("renderD"),
                    "{}",
                    identity.render_node.name
                );
                let Firmware::Loaded { guc, huc } = &identity.firmware else {
                    panic!(
                        "hardware identity needs loaded firmware: {:?}",
                        identity.firmware
                    );
                };
                assert!(matches!(identity.loader.as_str(), "opencl" | "level-zero"));
                for member in [
                    "libopenvino_c.so.",
                    "libopenvino.so.",
                    "libopenvino_intel_gpu_plugin.so",
                ] {
                    assert!(
                        identity.libraries.contains(member),
                        "{member} missing from the manifest"
                    );
                }
                assert!(
                    identity.libraries.contains("libOpenCL.so")
                        || identity.libraries.contains("libze_loader.so."),
                    "the loader family is hashed"
                );
                println!(
                    "gpu identity: {} | {} | {} | EUs {} | mem {} | PCI {} as {} ({}) | guc {} huc {} | loader {} | plugin {} | runtime {} | digest {} | {} libraries | via {} -> {}",
                    identity.full_name,
                    identity.capabilities,
                    identity.architecture,
                    identity.execution_units,
                    identity.total_memory,
                    identity.device_pci,
                    identity.render_node.name,
                    identity.render_node.vendor,
                    guc,
                    huc,
                    identity.loader,
                    identity.gpu_plugin,
                    identity.runtime_build,
                    identity.digest(),
                    identity.libraries.lines().count(),
                    identity.selected_library,
                    identity.canonical_library,
                );
                for line in identity.libraries.lines() {
                    println!("  {line}");
                }
            }
            Discovery::Absent => println!("no GPU on this host"),
            Discovery::MultipleGpus(devices) => println!("refused, multiple GPUs: {devices:?}"),
            Discovery::NotAdmitted => panic!("the admitted test entry must not refuse"),
            Discovery::Unavailable(why) => panic!("discovery failed: {why}"),
        }
    }

    /// Ignored: needs the real provider stack, an Intel GPU and the shipped
    /// models (`IRLUME_NPU_TEST_MODELS` or `/usr/share/irlume/models`).
    /// Compiles the recognizer under the fixed configuration on the one
    /// GPU, requires OpenVINO to name that device as the execution device,
    /// checks the parity canary against the CPU reference on the fixed
    /// synthetic inputs, proves bit determinism per input, and requires the
    /// mapped-library check to still pass after the compile (the
    /// retirement trigger). Observation evidence for ADR-0033 section 5,
    /// not a certification: CERTIFIED stays empty.
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider, an Intel GPU and the models"]
    fn gpu_hw_compile_parity_and_retirement_under_the_fixed_configuration() {
        use super::super::npu_reference;
        let scratch = tempfile::tempdir().unwrap();
        let dir = std::env::var("IRLUME_NPU_TEST_MODELS")
            .unwrap_or_else(|_| "/usr/share/irlume/models".into());
        let path = Path::new(&dir).join("glintr100.onnx");
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        // The CPU reference session exists before the platform identity is
        // taken: anything the process maps afterwards must refuse (the
        // discipline the NPU platform runs under too).
        let mut cpu = crate::Embedder::load_from_memory(&bytes).expect("the CPU session builds");
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens with the fixed configuration");
        let identity = platform.identity().clone();
        println!(
            "identity digest {} (configuration {})",
            identity.digest(),
            identity.configuration
        );
        assert_eq!(identity.configuration, gpu::COMPILE_CONFIGURATION);
        let cache = scratch.path().join("gpu-cache");
        std::fs::create_dir_all(&cache).unwrap();
        let started = std::time::Instant::now();
        let (mut model, assignment) = platform
            .compile(&cache, &bytes)
            .expect("the recognizer compiles on the GPU");
        println!(
            "cold compile {:?}; OpenVINO assigned {assignment:?}",
            started.elapsed()
        );
        assert!(
            assignment == "GPU" || assignment.starts_with("GPU."),
            "assigned {assignment:?}"
        );
        assert!(platform.still_loaded_as_hashed().is_ok());
        let raw = |values: &[f32]| -> Vec<u8> {
            values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect()
        };
        let mut first: Vec<Option<Vec<f32>>> = vec![None; 4];
        for (k, seen) in first.iter_mut().enumerate() {
            let chip = npu_reference::chip(k);
            let reference = cpu
                .embed_preprocessed(&chip)
                .expect("the CPU reference answers");
            let answer = model.infer(&chip).expect("the GPU answers");
            assert_eq!(answer.len(), crate::EMBED_DIM);
            // Bit determinism per input, the premise the NPU digest relies on.
            let repeat = model.infer(&chip).expect("the GPU repeats");
            assert_eq!(
                raw(&answer),
                raw(&repeat),
                "input {k} answered differently the second time"
            );
            match seen.replace(answer.clone()) {
                None => {}
                Some(earlier) => assert_eq!(raw(&earlier), raw(&answer)),
            }
            let norm: f32 = answer.iter().map(|value| value * value).sum::<f32>().sqrt();
            assert!(norm.is_finite() && norm > 0.0);
            let cosine: f32 = answer
                .iter()
                .zip(&reference)
                .map(|(a, b)| a * b / norm)
                .sum();
            println!(
                "input {k}: cosine {cosine:.7}, digest {}",
                irlume_common::sha256_hex(&raw(&answer))
            );
            // The observed minihost band was 0.9995; the certified-NPU band
            // 0.99999+. The canary gate a certification sets is stricter
            // than this observation floor.
            assert!(cosine > 0.999, "input {k}: {cosine}");
        }
        // Distinct inputs keep distinct answers.
        assert_ne!(
            raw(&first[0].clone().unwrap()),
            raw(&first[1].clone().unwrap())
        );
        // The compile loaded the frontends; every mapped library is still
        // the file the identity hashed, the check whose failure retires.
        assert!(platform.still_loaded_as_hashed().is_ok());
        println!(
            "mapped libraries after compile: {}",
            identity.libraries.lines().count()
        );
    }
}
