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
    // The recorded-frame reader, the attack-directory rule and the
    // CPU-vs-accelerator drift statistics, shared with the NPU evidence
    // harness.
    use super::super::npu_tests::{is_attack, pnm, Stats};

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
    /// Write a maps string to a file the inventory can read and re-read.
    fn maps_file(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

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
        let maps = maps_file(dir.path(), "maps", &maps);
        let (manifest, hashed, loader) = gpu::gpu_libraries(&maps, &executable).unwrap();
        assert_eq!(loader, "opencl");
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
        let maps_text = std::fs::read_to_string(&maps).unwrap();
        for drop in ["libopenvino_intel_gpu_plugin.so", "libOpenCL.so.1"] {
            let pruned: String = maps_text
                .lines()
                .filter(|line| !line.contains(drop))
                .collect::<Vec<_>>()
                .join("\n");
            let pruned = maps_file(dir.path(), "pruned", &pruned);
            let error = gpu::gpu_libraries(&pruned, &executable).unwrap_err();
            assert!(
                error.contains("GPU plugin") || error.contains("loader"),
                "{drop}: {error}"
            );
        }
        // This test process has not enumerated a GPU, so its real map
        // refuses too: no member is present.
        let own = std::fs::read_link("/proc/self/exe").unwrap();
        assert!(gpu::gpu_libraries(Path::new("/proc/self/maps"), &own).is_err());
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

    /// The recognizer's weights, from the test override, an installed
    /// tree or the fetched repository tree, in that order.
    fn recognizer_bytes() -> Vec<u8> {
        let candidates = [
            std::env::var("IRLUME_NPU_TEST_MODELS")
                .map(|dir| PathBuf::from(dir).join("glintr100.onnx"))
                .ok(),
            Some(PathBuf::from("/usr/share/irlume/models/glintr100.onnx")),
            Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/glintr100.onnx")),
        ];
        let path = candidates
            .into_iter()
            .flatten()
            .find(|path| path.is_file())
            .unwrap_or_else(|| {
                panic!(
                    "glintr100.onnx is not in IRLUME_NPU_TEST_MODELS, /usr/share/irlume/models \
                     or the repository models/ tree (scripts/fetch-models.sh)"
                )
            });
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        // The evidence must name the exact model it measured: the SHA-256
        // is printed and, when the model root ships the pinned SHA256SUMS,
        // checked against it, so a stale or modified model file cannot
        // pose as the pinned recognizer.
        let digest = irlume_common::sha256_hex(&bytes);
        let sums = path.parent().unwrap().join("SHA256SUMS");
        if sums.is_file() {
            let pinned = std::fs::read_to_string(&sums)
                .unwrap_or_else(|error| panic!("{}: {error}", sums.display()));
            let expected = pinned
                .lines()
                .find_map(|line| {
                    line.split_whitespace().next().filter(|_| {
                        line.rsplit(['/', ' '])
                            .next()
                            .is_some_and(|n| n == "glintr100.onnx")
                    })
                })
                .unwrap_or_else(|| panic!("{} names no glintr100.onnx", sums.display()));
            assert_eq!(
                digest,
                expected,
                "{} is not the pinned glintr100.onnx",
                path.display()
            );
        } else {
            // The installed tree need not ship the sums; the repository's
            // tracked pin still names the one model this evidence may use.
            let repo_sums = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/SHA256SUMS");
            if repo_sums.is_file() {
                let pinned = std::fs::read_to_string(&repo_sums)
                    .unwrap_or_else(|error| panic!("{}: {error}", repo_sums.display()));
                let expected = pinned.lines().find_map(|line| {
                    let hash = line.split_whitespace().next()?;
                    line.rsplit(['/', ' '])
                        .next()
                        .filter(|name| *name == "glintr100.onnx")
                        .map(|_| hash.to_owned())
                });
                if let Some(expected) = expected {
                    assert_eq!(
                        digest,
                        expected,
                        "{} is not the pinned glintr100.onnx",
                        path.display()
                    );
                }
            }
            println!("unpinned model root: {} sha256 {digest}", path.display());
        }
        println!("recognizer {} sha256 {digest}", path.display());
        bytes
    }

    /// The recognizer's CPU reference session. BOTH hardware lanes build
    /// it before opening the GPU platform: the daemon's CPU sessions
    /// exist before an accelerator platform opens (the fixed
    /// initialization order the NPU identity already relies on), so the
    /// GPU inventory includes the CPU runtime in every execution order
    /// and one host yields one digest whether a lane runs alone or after
    /// its sibling. The weights are a prerequisite of both lanes; the
    /// repository tree satisfies it after scripts/fetch-models.sh.
    fn cpu_reference() -> crate::Embedder {
        let bytes = recognizer_bytes();
        crate::Embedder::load_from_memory(&bytes).expect("the CPU session builds")
    }

    /// Ignored: needs the real provider stack and an Intel GPU. Run as root
    /// so debugfs joins the identity: a Found result MUST carry the loaded
    /// firmware of the bound render node. The complete identity binds the
    /// plugin's PCI report, exactly one render node, the firmware node at
    /// the same address, one loader family and the hashed library manifest
    /// (ADR-0033 section 3).
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider, an Intel GPU and the recognizer weights"]
    fn gpu_hw_identity_binds_plugin_render_node_and_libraries() {
        // Same native-library baseline as the compile lane: the CPU
        // session first, then the platform (see cpu_reference).
        let _cpu = cpu_reference();
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
    #[ignore = "hardware: needs the validated OpenVINO provider, an Intel GPU and the recognizer weights"]
    fn gpu_hw_compile_parity_and_retirement_under_the_fixed_configuration() {
        use super::super::npu_reference;
        let scratch = tempfile::tempdir().unwrap();
        let bytes = recognizer_bytes();
        // The CPU reference session exists before the platform identity is
        // taken (see cpu_reference): anything the process maps afterwards
        // must refuse, the discipline the NPU platform runs under too.
        let mut cpu = cpu_reference();
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
        // The certification bundle's CPU half: the reference digest of the
        // same fixed inputs the GPU digests above cover.
        println!(
            "CPU reference digest {}",
            cpu.cpu_reference_digest().unwrap()
        );
    }

    /// A face found in one image, aligned and embedded on the CPU session
    /// and on the GPU platform, or skipped when no face is found.
    #[derive(Clone)]
    struct FaceProbe {
        cpu: crate::Embedding,
        gpu: Vec<f32>,
    }

    /// One L2-normalized embedding from the GPU's raw output, exactly as
    /// production normalizes the session output.
    fn gpu_norm_infer(gpu: &mut Box<dyn crate::npu::Infer>, data: &[f32]) -> Vec<f32> {
        let mut raw = gpu.infer(data).expect("the GPU recognizer answers");
        // A malformed output (wrong length) is not a drift measurement
        // waiting to happen: every cosine and score assumes EMBED_DIM.
        assert_eq!(
            raw.len(),
            crate::EMBED_DIM,
            "the GPU output is not the recognizer's embedding"
        );
        let norm: f32 = raw.iter().map(|value| value * value).sum::<f32>().sqrt();
        assert!(norm.is_finite() && norm > 0.0, "the GPU output has no norm");
        raw.iter_mut().for_each(|value| *value /= norm);
        raw
    }

    /// The mean of two normalized embeddings, renormalized, mirroring
    /// production `tta_mean`.
    fn tta_mean(a: &[f32], b: &[f32]) -> Vec<f32> {
        let mut out: Vec<f32> = a.iter().zip(b).map(|(x, y)| x + y).collect();
        let norm: f32 = out.iter().map(|value| value * value).sum::<f32>().sqrt();
        out.iter_mut().for_each(|value| *value /= norm);
        out
    }

    /// Embed one image's best face on both devices, plain or through the
    /// TTA pipeline production authenticates RGB with. Returns None only
    /// when no face is detectable or alignable; a device that fails to
    /// answer PANICS, so a measurement can never silently lose samples to
    /// an inference error.
    fn probe_both(
        detector: &mut crate::Detector,
        cpu: &mut crate::Embedder,
        gpu: &mut Box<dyn crate::npu::Infer>,
        rgb: &[u8],
        width: u32,
        height: u32,
        tta: bool,
    ) -> Option<FaceProbe> {
        let view = crate::align::RgbView {
            data: rgb,
            width,
            height,
        };
        let found = detector.detect(&view).ok()?;
        let face = found
            .into_iter()
            .filter(crate::detection_is_finite)
            .max_by(|a, b| a.score.total_cmp(&b.score))?;
        let chip = crate::align::align_to_arcface(&view, &face.landmarks).ok()?;
        let plain = crate::align::preprocess_arcface(&chip);
        let (cpu, gpu) = if tta {
            let cpu = cpu.embed_tta(&chip).expect("the CPU TTA embedding");
            let a = gpu_norm_infer(gpu, &plain);
            let flipped = crate::align::preprocess_arcface(&crate::align::flip_h(&chip));
            let b = gpu_norm_infer(gpu, &flipped);
            (cpu, tta_mean(&a, &b))
        } else {
            let cpu = cpu.embed_preprocessed(&plain).expect("the CPU embedding");
            (cpu, gpu_norm_infer(gpu, &plain))
        };
        Some(FaceProbe { cpu, gpu })
    }

    fn decode_image(path: &Path) -> Option<(Vec<u8>, u32, u32, bool)> {
        let raw = std::fs::read(path).ok()?;
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            // The PNM kind, not the extension, decides the modality, like
            // the NPU lane: a grayscale P5 under any name is IR.
            Some("pgm") | Some("ppm") => {
                let (kind, w, h, data) = pnm(&raw)?;
                let grayscale = kind == 'g';
                let rgb = if grayscale {
                    data.iter().flat_map(|&g| [g, g, g]).collect()
                } else {
                    data.to_vec()
                };
                Some((rgb, w, h, grayscale))
            }
            Some("jpg") | Some("jpeg") | Some("png") => {
                let img = image::open(path).ok()?.to_rgb8();
                let (w, h) = img.dimensions();
                Some((img.into_raw(), w, h, false))
            }
            _ => None,
        }
    }

    /// Real recorded frames, recognizer CPU vs GPU at the wired 0.55
    /// threshold, mirroring the NPU real-frames lane for the one
    /// GPU-eligible model: the PAD cues and the detector stay on the CPU
    /// (ADR-0033 section 5), so this lane tracks match decisions only.
    /// Measurement, not a certification: the drift and flips are reported
    /// against the section 7 directions and CERTIFIED stays empty.
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider, an Intel GPU, the recognizer weights and recorded evaluation frames"]
    fn gpu_hw_real_frames_track_cpu() {
        let scratch = tempfile::tempdir().unwrap();
        let bytes = recognizer_bytes();
        let mut cpu = cpu_reference();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens");
        let cache = scratch.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let (mut recognizer, assignment) = platform.compile(&cache, &bytes).unwrap();
        assert!(assignment == "GPU" || assignment.starts_with("GPU."));
        let detector_bytes =
            std::fs::read(model_path("face_detection_yunet_2023mar.onnx")).unwrap();
        let mut detector = crate::Detector::load_from_memory(&detector_bytes).unwrap();

        let root = PathBuf::from(
            std::env::var("IRLUME_NPU_EVAL_DIR")
                .unwrap_or_else(|_| format!("{}/irlume-suncal", std::env::var("HOME").unwrap())),
        );
        let mut dirs: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&root).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "flir-candidate") {
                    dirs.extend(
                        std::fs::read_dir(&path)
                            .unwrap()
                            .filter_map(Result::ok)
                            .map(|e| e.path())
                            .filter(|p| p.is_dir()),
                    );
                } else {
                    dirs.push(path);
                }
            }
        }
        dirs.sort();

        let (mut genuine_ir, mut attacks_ir) = (Stats::default(), Stats::default());
        let (mut genuine_rgb, mut attacks_rgb) = (Stats::default(), Stats::default());
        let mut cosine_min = f32::INFINITY;
        // Every decoded frame in one deterministic list, so a first pass
        // can establish each modality's genuine reference BEFORE any
        // attack is scored: an attack directory that sorts before the
        // first genuine directory still counts against the reference,
        // instead of being dropped.
        let mut corpus: Vec<(PathBuf, bool, bool)> = Vec::new(); // (file, attack, ir)
        let mut frames = 0usize;
        for dir in &dirs {
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            let attack = is_attack(&name);
            let mut files: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect();
            files.sort();
            for file in files {
                if let Some((.., grayscale)) = decode_image(&file) {
                    frames += 1;
                    corpus.push((file, attack, grayscale));
                }
            }
        }
        let mut reference: Option<Vec<f32>> = None;
        let mut reference_rgb: Option<Vec<f32>> = None;
        // Pass 1: the first genuine frame with a detectable face of each
        // modality becomes that modality's CPU template.
        let mut faces = 0usize;
        let mut probes: Vec<(FaceProbe, bool, bool)> = Vec::new();
        for (file, attack, ir) in &corpus {
            let (rgb, width, height, _) = decode_image(file).unwrap();
            let Some(probe) = probe_both(
                &mut detector,
                &mut cpu,
                &mut recognizer,
                &rgb,
                width,
                height,
                !ir,
            ) else {
                continue;
            };
            faces += 1;
            probes.push((probe, *attack, *ir));
        }
        for probe in &mut probes {
            if !probe.1 {
                let slot = if probe.2 {
                    &mut reference
                } else {
                    &mut reference_rgb
                };
                if slot.is_none() {
                    *slot = Some(probe.0.cpu.to_vec());
                }
            }
        }
        // Pass 2: score everything against its modality's template.
        for (probe, attack, ir) in &probes {
            let cosine: f32 = probe.cpu.iter().zip(&probe.gpu).map(|(x, y)| x * y).sum();
            cosine_min = cosine_min.min(cosine);
            let template = if *ir {
                reference.as_ref()
            } else {
                reference_rgb.as_ref()
            };
            let Some(template) = template else {
                continue; // no genuine reference of this modality at all
            };
            let score = |embedding: &[f32]| -> f32 {
                embedding.iter().zip(template).map(|(x, y)| x * y).sum()
            };
            let (cpu_score, gpu_score) = (score(&probe.cpu), score(&probe.gpu));
            let stats: &mut Stats = match (attack, ir) {
                (true, true) => &mut attacks_ir,
                (true, false) => &mut attacks_rgb,
                (false, true) => &mut genuine_ir,
                (false, false) => &mut genuine_rgb,
            };
            stats.add(cpu_score, gpu_score, 0.55);
        }
        assert!(platform.still_loaded_as_hashed().is_ok());
        // A vacuous run is not evidence: every arm must have samples.
        for (name, stats) in [
            ("genuine IR", &genuine_ir),
            ("IR attacks", &attacks_ir),
            ("genuine RGB", &genuine_rgb),
            ("RGB attacks", &attacks_rgb),
        ] {
            assert!(stats.n > 0, "the {name} arm measured no samples");
        }
        println!(
            "frames {frames}, with a face {faces}, directories {}",
            dirs.len()
        );
        println!(
            "{}",
            genuine_ir.line_as("recognizer genuine IR vs first frame at 0.55", "GPU")
        );
        println!(
            "{}",
            attacks_ir.line_as(
                "recognizer IR attacks vs first genuine IR frame at 0.55",
                "GPU"
            )
        );
        println!(
            "{}",
            genuine_rgb.line_as("recognizer genuine RGB vs first frame at 0.55", "GPU")
        );
        println!(
            "{}",
            attacks_rgb.line_as(
                "recognizer RGB attacks vs first genuine RGB frame at 0.55",
                "GPU"
            )
        );
        println!("recognizer CPU vs GPU embedding cosine, lowest {cosine_min:.6}");
        let new_grants: usize = [&attacks_ir, &attacks_rgb]
            .iter()
            .map(|s| s.flips - s.flips_down)
            .sum();
        let genuine_flips = genuine_ir.flips + genuine_rgb.flips;
        println!(
            "recognizer: genuine flips {genuine_flips}, new grants on presentation attacks {new_grants}; measurement only, CERTIFIED stays empty"
        );
    }

    /// The recognizer model file of `name` from the same roots as
    /// [`recognizer_bytes`].
    fn model_path(name: &str) -> PathBuf {
        [
            std::env::var("IRLUME_NPU_TEST_MODELS")
                .map(|dir| PathBuf::from(dir).join(name))
                .ok(),
            Some(PathBuf::from("/usr/share/irlume/models").join(name)),
            Some(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../models")
                    .join(name),
            ),
        ]
        .into_iter()
        .flatten()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{name} is not in the model roots"))
    }

    /// Every jpg/jpeg/png under `root`, recursively, sorted. A local
    /// walker keeps the evidence harness free of new dependencies.
    fn collect_images(root: &Path) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|ext| {
                        matches!(ext.to_ascii_lowercase().as_str(), "jpg" | "jpeg" | "png")
                    })
                {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, &mut out);
        out.sort();
        out
    }

    /// Recognition-corpus drift on the canonical LFW verification pairs
    /// and the impostor-only FairFace tree, scored CPU-template vs
    /// CPU-probe and CPU-template vs GPU-probe at the 0.55 threshold.
    /// This is the zero-effort-impostor half of the ADR-0022 section 7
    /// evidence the NPU certification judged, measured on the GPU
    /// identity; reported, not certified. The LFW pairs come from the
    /// corpus's own `pairs.csv` (the official verification protocol, with
    /// its is_same labels and resolved paths), never an invented pairing.
    /// Roots: `IRLUME_GPU_CORPORA_LFW` and `IRLUME_GPU_CORPORA_FAIRFACE`
    /// (default `~/datasets/lfw` and `~/datasets/fairface`), bounded by
    /// `IRLUME_GPU_CORPORA_PAIRS` (default 400 genuine pairs and 400
    /// impostor pairs) and `IRLUME_GPU_CORPORA_IMPOSTORS` (default 2600
    /// FairFace pairs). RGB probes run the TTA pipeline.
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider, an Intel GPU, the recognizer weights and the recognition corpora"]
    fn gpu_hw_recognition_corpora_drift() {
        let home = std::env::var("HOME").unwrap();
        let lfw_root = PathBuf::from(
            std::env::var("IRLUME_GPU_CORPORA_LFW")
                .unwrap_or_else(|_| format!("{home}/datasets/lfw")),
        );
        let fairface_root = PathBuf::from(
            std::env::var("IRLUME_GPU_CORPORA_FAIRFACE")
                .unwrap_or_else(|_| format!("{home}/datasets/fairface")),
        );
        let max_pairs: usize = std::env::var("IRLUME_GPU_CORPORA_PAIRS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(400);
        let max_impostors: usize = std::env::var("IRLUME_GPU_CORPORA_IMPOSTORS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2600);
        assert!(
            lfw_root.is_dir(),
            "the LFW root {} is missing (IRLUME_GPU_CORPORA_LFW)",
            lfw_root.display()
        );
        assert!(
            fairface_root.is_dir(),
            "the FairFace root {} is missing (IRLUME_GPU_CORPORA_FAIRFACE)",
            fairface_root.display()
        );

        let scratch = tempfile::tempdir().unwrap();
        let bytes = recognizer_bytes();
        let mut cpu = cpu_reference();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens");
        let cache = scratch.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let (mut recognizer, assignment) = platform.compile(&cache, &bytes).unwrap();
        assert!(assignment == "GPU" || assignment.starts_with("GPU."));
        let detector_bytes =
            std::fs::read(model_path("face_detection_yunet_2023mar.onnx")).unwrap();
        let mut detector = crate::Detector::load_from_memory(&detector_bytes).unwrap();

        // Embed each image at most once, whatever pairs reference it.
        let mut embedded: std::collections::HashMap<PathBuf, Option<FaceProbe>> =
            Default::default();
        let mut no_face = 0usize;
        let mut embed = |detector: &mut crate::Detector,
                         cpu: &mut crate::Embedder,
                         gpu: &mut Box<dyn crate::npu::Infer>,
                         path: &Path|
         -> Option<FaceProbe> {
            if let Some(cached) = embedded.get(path) {
                return cached.clone();
            }
            let result = decode_image(path).and_then(|(rgb, width, height, _grayscale)| {
                probe_both(detector, cpu, gpu, &rgb, width, height, true)
            });
            if result.is_none() {
                no_face += 1;
            }
            embedded.insert(path.to_path_buf(), result.clone());
            result
        };

        // The canonical pairs: pair_id,fold_id,fold_position,is_same,
        // image_a,image_b,image_a_path,image_b_path, paths relative to
        // the corpus's train/ tree.
        let pairs_csv = lfw_root.join("pairs.csv");
        let text = std::fs::read_to_string(&pairs_csv)
            .unwrap_or_else(|error| panic!("{}: {error}", pairs_csv.display()));
        let train = lfw_root.join("train");
        let (mut genuine, mut impostor_lfw) = (Stats::default(), Stats::default());
        let mut lfw_pairs_used = [0usize; 2];
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 8 {
                continue;
            }
            let is_same = fields[3] == "1";
            if lfw_pairs_used[usize::from(is_same)] >= max_pairs {
                continue;
            }
            let (a, b) = (train.join(fields[6]), train.join(fields[7]));
            if !a.is_file() || !b.is_file() {
                continue;
            }
            let (Some(template), Some(probe)) = (
                embed(&mut detector, &mut cpu, &mut recognizer, &a),
                embed(&mut detector, &mut cpu, &mut recognizer, &b),
            ) else {
                continue;
            };
            lfw_pairs_used[usize::from(is_same)] += 1;
            let cpu_score: f32 = template
                .cpu
                .iter()
                .zip(&probe.cpu)
                .map(|(x, y)| x * y)
                .sum();
            let gpu_score: f32 = template
                .cpu
                .iter()
                .zip(&probe.gpu)
                .map(|(x, y)| x * y)
                .sum();
            if is_same {
                genuine.add(cpu_score, gpu_score, 0.55);
            } else {
                impostor_lfw.add(cpu_score, gpu_score, 0.55);
            }
        }
        println!(
            "lfw pairs.csv: {} genuine, {} impostor pairs used",
            lfw_pairs_used[1], lfw_pairs_used[0]
        );

        // Impostor pairs, FairFace (impostor-only tree): consecutive files.
        let mut impostor_fairface = Stats::default();
        let fairface_files = collect_images(&fairface_root);
        for pair in fairface_files.windows(2) {
            if impostor_fairface.n >= max_impostors {
                break;
            }
            let (Some(template), Some(probe)) = (
                embed(&mut detector, &mut cpu, &mut recognizer, &pair[0]),
                embed(&mut detector, &mut cpu, &mut recognizer, &pair[1]),
            ) else {
                continue;
            };
            let cpu_score: f32 = template
                .cpu
                .iter()
                .zip(&probe.cpu)
                .map(|(x, y)| x * y)
                .sum();
            let gpu_score: f32 = template
                .cpu
                .iter()
                .zip(&probe.gpu)
                .map(|(x, y)| x * y)
                .sum();
            impostor_fairface.add(cpu_score, gpu_score, 0.55);
        }
        assert!(platform.still_loaded_as_hashed().is_ok());
        // A vacuous run is not evidence: both directions need samples.
        assert!(genuine.n > 0, "no genuine pairs were measured");
        assert!(impostor_lfw.n > 0, "no LFW impostor pairs were measured");
        assert!(
            impostor_fairface.n > 0,
            "no FairFace impostor pairs were measured"
        );
        println!("skipped images without a detectable face: {no_face}");
        println!("{}", genuine.line_as("genuine LFW pairs at 0.55", "GPU"));
        println!(
            "{}",
            impostor_lfw.line_as("impostor LFW pairs at 0.55", "GPU")
        );
        println!(
            "{}",
            impostor_fairface.line_as("impostor FairFace pairs at 0.55", "GPU")
        );
        let new_grants: usize = [&impostor_lfw, &impostor_fairface]
            .iter()
            .map(|s| s.flips - s.flips_down)
            .sum();
        println!(
            "impostor flips {} (new grants {new_grants}); measurement only, CERTIFIED stays empty",
            impostor_lfw.flips + impostor_fairface.flips
        );
    }

    /// The suspend/resume recheck a GPU certification requires, run as
    /// ONE process that spans the suspend: it opens the platform, records
    /// the digest baseline and the suspended-time baseline, then waits
    /// (`IRLUME_GPU_TEST_SUSPEND_WAIT_SECS`, default 600) for a real
    /// system suspend. A resume is proven only by growth of the
    /// CLOCK_BOOTTIME-minus-MONOTONIC reading beyond read granularity,
    /// the same proof production uses; when the clock grows, the
    /// reference inputs must reproduce their bits and the mapped-library
    /// inventory must still verify. No suspend within the window prints
    /// the baseline and asserts nothing; the lane never suspends the
    /// system itself, so the wait is the attended owner's action.
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider, an Intel GPU and the recognizer weights; the recheck arm waits for a real attended suspend"]
    fn gpu_hw_suspend_resume_recheck() {
        let wait_seconds: u64 = std::env::var("IRLUME_GPU_TEST_SUSPEND_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600);
        let scratch = tempfile::tempdir().unwrap();
        let bytes = recognizer_bytes();
        // The CPU session fixes the native-library baseline (see
        // cpu_reference); the recheck itself watches the GPU bits.
        let _cpu = cpu_reference();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens");
        let cache = scratch.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let (mut recognizer, _) = platform.compile(&cache, &bytes).unwrap();
        let raw = |values: &[f32]| -> Vec<u8> {
            values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect()
        };
        let baseline: Vec<String> = (0..3)
            .map(|k| {
                let answer = recognizer
                    .infer(&super::super::npu_reference::chip(k))
                    .expect("the GPU answers before the suspend");
                irlume_common::sha256_hex(&raw(&answer))
            })
            .collect();
        // The understating baseline and the overstating later reading can
        // only overstate a suspend, never hide one (npu::suspended).
        let clock_baseline = crate::npu::suspended(crate::npu::Bound::AtMost)
            .expect("the suspend clock is readable");
        println!(
            "digest baseline {baseline:?}; suspend now (attended) - waiting up to \
             {wait_seconds}s for the clock to grow"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_seconds);
        let mut resumed = false;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let now = crate::npu::suspended(crate::npu::Bound::AtLeast)
                .expect("the suspend clock is readable");
            // The same granularity production uses: growth below it is
            // read jitter, not a suspend.
            if now > clock_baseline + crate::npu::RESUME_GRANULARITY {
                resumed = true;
                break;
            }
        }
        if !resumed {
            println!("no suspend within {wait_seconds}s: no recheck claimed, nothing asserted");
            return;
        }
        for (k, expected) in baseline.iter().enumerate() {
            let answer = recognizer
                .infer(&super::super::npu_reference::chip(k))
                .expect("the GPU answers after the resume");
            assert_eq!(
                &irlume_common::sha256_hex(&raw(&answer)),
                expected,
                "input {k} changed across a real suspend"
            );
        }
        assert!(platform.still_loaded_as_hashed().is_ok());
        println!("post-resume bits and mapped inventory unchanged");
    }
}
