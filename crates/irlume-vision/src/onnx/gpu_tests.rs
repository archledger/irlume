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

    /// One model's bytes, verified against the committed artifact pins
    /// (ADR-0022 section 7.1), regardless of the selected model root.
    fn model_bytes(name: &str) -> Vec<u8> {
        let candidates = [
            std::env::var("IRLUME_NPU_TEST_MODELS")
                .map(|dir| PathBuf::from(dir).join(name))
                .ok(),
            Some(PathBuf::from("/usr/share/irlume/models").join(name)),
            Some(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../models")
                    .join(name),
            ),
        ];
        let path = candidates
            .into_iter()
            .flatten()
            .find(|path| path.is_file())
            .unwrap_or_else(|| panic!("{name} is not in the model roots"));
        model_bytes_at_path(name, &path)
    }

    // Model roots choose locations, not which artifact certification measures.
    const COMMITTED_MODEL_PINS: &str = include_str!("../../../../models/SHA256SUMS");

    fn committed_model_pin(name: &str) -> Option<&'static str> {
        COMMITTED_MODEL_PINS.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let hash = fields.next()?;
            (fields.next()? == name).then_some(hash)
        })
    }

    fn model_bytes_at_path(name: &str, path: &Path) -> Vec<u8> {
        let expected = committed_model_pin(name)
            .unwrap_or_else(|| panic!("{name} has no committed pin in models/SHA256SUMS"));
        let bytes =
            std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let digest = irlume_common::sha256_hex(&bytes);
        assert_eq!(
            digest,
            expected,
            "{name} from {} is not the pinned model (committed models/SHA256SUMS)",
            path.display()
        );
        println!("model {name} {} sha256 {digest}", path.display());
        bytes
    }

    #[test]
    fn gpu_model_pin_committed_manifest_has_unique_sha256_entries() {
        let mut names = std::collections::BTreeSet::new();
        for line in COMMITTED_MODEL_PINS.lines() {
            let mut fields = line.split_whitespace();
            let hash = fields.next().expect("committed pin has a digest");
            let name = fields.next().expect("committed pin has a model name");
            assert_eq!(hash.len(), 64, "{name} must have a SHA-256 digest");
            assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(fields.next().is_none(), "unexpected fields for {name}");
            assert!(names.insert(name), "duplicate committed pin for {name}");
            assert_eq!(committed_model_pin(name), Some(hash));
        }
        for name in [
            "glintr100.onnx",
            "face_detection_yunet_2023mar.onnx",
            "blaze_face_short_range.onnx",
            "face_landmark.onnx",
            "face_landmarks_detector.tflite",
        ] {
            assert!(
                names.contains(name),
                "{name} needs a committed artifact pin"
            );
        }
    }

    #[test]
    #[should_panic(expected = "is not the pinned model")]
    fn gpu_model_pin_rejects_replacement_with_matching_root_manifest() {
        let root = tempfile::tempdir().unwrap();
        let name = "glintr100.onnx";
        let bytes = b"replacement model, not the committed recognizer";
        let digest = irlume_common::sha256_hex(bytes);
        let path = root.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::write(
            root.path().join("SHA256SUMS"),
            format!("{digest}  {name}\n"),
        )
        .unwrap();
        model_bytes_at_path(name, &path);
    }

    #[test]
    #[should_panic(expected = "has no committed pin")]
    fn gpu_model_pin_rejects_missing_pin() {
        let root = tempfile::tempdir().unwrap();
        let name = "unlisted-model.onnx";
        let path = root.path().join(name);
        std::fs::write(&path, b"model without a committed pin").unwrap();
        model_bytes_at_path(name, &path);
    }

    #[test]
    #[should_panic(expected = "has no committed pin")]
    fn gpu_model_pin_rejects_unknown_model_despite_matching_root_manifest() {
        let root = tempfile::tempdir().unwrap();
        let name = "unlisted-model.onnx";
        let bytes = b"model without a committed pin";
        let digest = irlume_common::sha256_hex(bytes);
        let path = root.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::write(
            root.path().join("SHA256SUMS"),
            format!("{digest}  {name}\n"),
        )
        .unwrap();
        model_bytes_at_path(name, &path);
    }

    #[test]
    #[should_panic(expected = "is not the pinned model")]
    fn gpu_model_pin_rejects_mismatched_bytes_without_root_manifest() {
        let root = tempfile::tempdir().unwrap();
        let name = "glintr100.onnx";
        let path = root.path().join(name);
        std::fs::write(&path, b"replacement model, not the committed recognizer").unwrap();
        model_bytes_at_path(name, &path);
    }

    /// The recognizer's weights, from the test override, an installed
    /// tree or the fetched repository tree, in that order.
    fn recognizer_bytes() -> Vec<u8> {
        model_bytes("glintr100.onnx")
    }

    /// The recognizer's production CPU reference session.
    fn cpu_reference() -> crate::Embedder {
        let bytes = recognizer_bytes();
        crate::Embedder::load_from_memory(&bytes).expect("the CPU session builds")
    }

    /// Every hardware lane loads the same CPU models before GPU inventory
    /// capture, including the native TFLite library. Receipts still print
    /// their actual identity instead of assuming test order is harmless.
    fn hw_cpu_cascade() -> (crate::Embedder, DetectionCascade) {
        let cpu = cpu_reference();
        let cascade = DetectionCascade::load();
        (cpu, cascade)
    }

    fn report_hw_identity(lane: &str, identity: &Identity) {
        assert_eq!(identity.configuration, gpu::COMPILE_CONFIGURATION);
        println!(
            "{lane} identity digest {} (configuration {}), {} mapped libraries; CPU mesh {EVIDENCE_MESH_MODEL}",
            identity.digest(), identity.configuration, identity.libraries.lines().count()
        );
    }

    #[test]
    fn gpu_evidence_hardware_lanes_share_pre_inventory_setup() {
        let source = include_str!("gpu_tests.rs");
        for name in [
            "gpu_hw_identity_binds_plugin_render_node_and_libraries",
            "gpu_hw_compile_parity_and_retirement_under_the_fixed_configuration",
            "gpu_hw_real_frames_track_cpu",
            "gpu_hw_recognition_corpora_drift",
            "gpu_hw_suspend_resume_recheck",
        ] {
            let body = source
                .split(&format!("fn {name}()"))
                .nth(1)
                .unwrap()
                .split("\n    }")
                .next()
                .unwrap();
            let setup = body.find("hw_cpu_cascade()").expect(name);
            let inventory = body.find("gpu::").expect(name);
            assert!(
                setup < inventory,
                "{name} must load the same CPU models first"
            );
            assert!(
                body.contains("report_hw_identity("),
                "{name} must name its identity"
            );
        }
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
        let (_cpu, _cascade) = hw_cpu_cascade();
        match gpu::discover_admitted(&hw_selection()) {
            Discovery::Found(identity) => {
                report_hw_identity("discovery", &identity);
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
        let (mut cpu, _cascade) = hw_cpu_cascade();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens with the fixed configuration");
        let identity = platform.identity().clone();
        report_hw_identity("compile", &identity);
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
    /// The production detection cascade the evidence walks: the YuNet
    /// detector plus the BlazeFace/FaceMesh rescue irlume-auth arms
    /// behind it, every model pin-checked at load.
    const EVIDENCE_MESH_MODEL: &str = "face_landmarks_detector.tflite";

    struct DetectionCascade {
        detector: crate::Detector,
        blaze: crate::BlazeRescue,
        mesh: crate::FaceMesh,
        rescue_attempts: usize,
        rescued: usize,
        mesh_refusals: usize,
        alignment_refusals: usize,
    }

    impl DetectionCascade {
        fn load() -> Self {
            let detector_bytes = model_bytes("face_detection_yunet_2023mar.onnx");
            Self {
                detector: crate::Detector::load_from_memory(&detector_bytes).unwrap(),
                blaze: crate::BlazeRescue::load_from_memory(&model_bytes(
                    "blaze_face_short_range.onnx",
                ))
                .unwrap(),
                mesh: crate::FaceMesh::load_from_memory(&model_bytes(EVIDENCE_MESH_MODEL)).unwrap(),
                rescue_attempts: 0,
                rescued: 0,
                mesh_refusals: 0,
                alignment_refusals: 0,
            }
        }

        fn report(&self) {
            println!(
                "CPU cascade mesh {EVIDENCE_MESH_MODEL}: rescue attempts {}, rescued {}, \
                 geometric mesh refusals {}, alignment refusals {}",
                self.rescue_attempts, self.rescued, self.mesh_refusals, self.alignment_refusals
            );
        }
    }

    /// The recognizer's two devices for one probe.
    struct Devices<'a> {
        cpu: &'a mut crate::Embedder,
        gpu: &'a mut Box<dyn crate::npu::Infer>,
    }

    /// One decoded corpus image.
    struct Decoded {
        rgb: Vec<u8>,
        width: u32,
        height: u32,
        grayscale: bool,
    }

    /// The production detection cascade's rescue arm, mirroring
    /// irlume-auth's rescue_detect: after a YuNet miss, BlazeFace
    /// proposes a coarse box and FaceMesh refines it into the five
    /// alignment landmarks.
    fn rescue_detect(
        cascade: &mut DetectionCascade,
        view: &crate::align::RgbView<'_>,
    ) -> Option<crate::Detection> {
        cascade.rescue_attempts += 1;
        let result = rescue_from_results(
            cascade.blaze.detect_top(view),
            |bbox| cascade.mesh.landmarks(view, bbox, 0.25),
            &mut cascade.mesh_refusals,
        );
        cascade.rescued += usize::from(result.is_some());
        result
    }

    fn rescue_from_results(
        detected: irlume_common::Result<Option<([f32; 4], f32)>>,
        refine: impl FnOnce(&[f32; 4]) -> irlume_common::Result<Vec<(f32, f32)>>,
        geometric_refusals: &mut usize,
    ) -> Option<crate::Detection> {
        let (bbox, score) = detected.expect("the rescue detector answers")?;
        let lm = match refine(&bbox) {
            Ok(lm) => lm,
            // The current FaceMesh API reports its two geometric refusals
            // as Hardware strings. Production treats these as no usable
            // alignment; account for them separately, never as runtime
            // failures or silently undetectable faces. All other errors
            // refuse this measurement.
            Err(irlume_common::Error::Hardware(why))
                if why.starts_with("onnx: mesh refused detector box ")
                    || why.starts_with("onnx: mesh output refused: ") =>
            {
                *geometric_refusals += 1;
                return None;
            }
            Err(error) => panic!("the rescue mesh failed: {error}"),
        };
        assert!(
            lm.len() >= crate::MESH_N,
            "the rescue mesh output is malformed"
        );
        const LEFT_EYE_RING: [usize; 6] = [33, 160, 158, 133, 153, 144];
        const RIGHT_EYE_RING: [usize; 6] = [362, 385, 387, 263, 373, 380];
        let center = |idx: &[usize; 6]| {
            let (mut x, mut y) = (0.0f32, 0.0f32);
            for &i in idx {
                x += lm[i].0;
                y += lm[i].1;
            }
            (x / 6.0, y / 6.0)
        };
        let e1 = center(&LEFT_EYE_RING);
        let e2 = center(&RIGHT_EYE_RING);
        let (le, re) = if e1.0 <= e2.0 { (e1, e2) } else { (e2, e1) };
        let (m1, m2) = (lm[61], lm[291]);
        let (ml, mr) = if m1.0 <= m2.0 { (m1, m2) } else { (m2, m1) };
        Some(crate::Detection {
            bbox,
            score,
            landmarks: [le, re, lm[1], ml, mr],
        })
    }

    #[test]
    fn gpu_evidence_uses_the_default_production_mesh() {
        assert_eq!(EVIDENCE_MESH_MODEL, "face_landmarks_detector.tflite");
    }

    #[test]
    fn gpu_evidence_rescue_refuses_runtime_errors() {
        let error = || irlume_common::Error::Hardware("synthetic inference failure".into());
        assert!(std::panic::catch_unwind(|| {
            rescue_from_results(Err(error()), |_| panic!("no box to refine"), &mut 0);
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            rescue_from_results(
                Ok(Some(([0.0, 0.0, 10.0, 10.0], 0.9))),
                |_| Err(error()),
                &mut 0,
            );
        })
        .is_err());
        assert!(rescue_from_results(Ok(None), |_| panic!("no face to refine"), &mut 0).is_none());
        assert!(std::panic::catch_unwind(|| {
            rescue_from_results(
                Ok(Some(([0.0, 0.0, 10.0, 10.0], 0.9))),
                |_| Ok(Vec::new()),
                &mut 0,
            );
        })
        .is_err());
    }

    #[test]
    fn gpu_evidence_rescue_accounts_for_geometric_refusals() {
        for why in [
            "onnx: mesh refused detector box fixture",
            "onnx: mesh output refused: fixture",
        ] {
            let mut refused = 0;
            let result = rescue_from_results(
                Ok(Some(([0.0, 0.0, 10.0, 10.0], 0.9))),
                |_| Err(irlume_common::Error::Hardware(why.into())),
                &mut refused,
            );
            assert!(result.is_none());
            assert_eq!(refused, 1);
        }
    }

    fn probe_both(
        cascade: &mut DetectionCascade,
        devices: &mut Devices<'_>,
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
        // A detector runtime error fails the lane: an evidence run must
        // not lose frames to an inference failure it mistook for an
        // undetectable face.
        let found = cascade
            .detector
            .detect(&view)
            .expect("the detector answers");
        let face = found
            .into_iter()
            .filter(crate::detection_is_finite)
            .max_by(|a, b| a.score.total_cmp(&b.score))
            // The production cascade rescues a YuNet miss through
            // BlazeFace + FaceMesh before it gives up (irlume-auth's
            // rescue_detect); the evidence walks the same path.
            .or_else(|| rescue_detect(cascade, &view))?;
        let chip = match crate::align::align_to_arcface(&view, &face.landmarks) {
            Ok(chip) => chip,
            Err(_) => {
                cascade.alignment_refusals += 1;
                return None;
            }
        };
        let plain = crate::align::preprocess_arcface(&chip);
        let (cpu, gpu) = if tta {
            let cpu = devices.cpu.embed_tta(&chip).expect("the CPU TTA embedding");
            let a = gpu_norm_infer(devices.gpu, &plain);
            let flipped = crate::align::preprocess_arcface(&crate::align::flip_h(&chip));
            let b = gpu_norm_infer(devices.gpu, &flipped);
            (cpu, tta_mean(&a, &b))
        } else {
            let cpu = devices
                .cpu
                .embed_preprocessed(&plain)
                .expect("the CPU embedding");
            (cpu, gpu_norm_infer(devices.gpu, &plain))
        };
        Some(FaceProbe { cpu, gpu })
    }

    /// Ok(None) marks a non-image file the corpus walker may carry;
    /// a file with an image extension that cannot be read or decoded
    /// REFUSES the run instead of silently shrinking the corpus.
    fn decode_image(path: &Path) -> Result<Option<Decoded>, String> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        let Some(ext) = ext.as_deref() else {
            return Ok(None);
        };
        let raw = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        match ext {
            // The PNM kind, not the extension, decides the modality, like
            // the NPU lane: a grayscale P5 under any name is IR.
            "pgm" | "ppm" => {
                let Some((kind, w, h, data)) = pnm(&raw) else {
                    return Err(format!("{}: malformed PNM", path.display()));
                };
                let grayscale = kind == 'g';
                let rgb = if grayscale {
                    data.iter().flat_map(|&g| [g, g, g]).collect()
                } else {
                    data.to_vec()
                };
                Ok(Some(Decoded {
                    rgb,
                    width: w,
                    height: h,
                    grayscale,
                }))
            }
            "jpg" | "jpeg" | "png" => {
                let img = image::open(path)
                    .map_err(|error| format!("{}: {error}", path.display()))?
                    .to_rgb8();
                let (w, h) = img.dimensions();
                Ok(Some(Decoded {
                    rgb: img.into_raw(),
                    width: w,
                    height: h,
                    grayscale: false,
                }))
            }
            _ => Ok(None),
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
        let (mut cpu, mut cascade) = hw_cpu_cascade();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens");
        report_hw_identity("recorded frames", platform.identity());
        let cache = scratch.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let (mut recognizer, assignment) = platform.compile(&cache, &bytes).unwrap();
        assert!(assignment == "GPU" || assignment.starts_with("GPU."));

        let root = PathBuf::from(
            std::env::var("IRLUME_NPU_EVAL_DIR")
                .unwrap_or_else(|_| format!("{}/irlume-suncal", std::env::var("HOME").unwrap())),
        );
        let mut dirs: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&root).unwrap() {
            let entry = entry.unwrap_or_else(|error| panic!("{}: {error}", root.display()));
            let path = entry.path();
            if path
                .metadata()
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
                .is_dir()
            {
                if path.file_name().is_some_and(|n| n == "flir-candidate") {
                    dirs.extend(
                        std::fs::read_dir(&path)
                            .unwrap()
                            .map(|entry| {
                                entry
                                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
                                    .path()
                            })
                            .filter(|p| {
                                p.metadata()
                                    .unwrap_or_else(|error| panic!("{}: {error}", p.display()))
                                    .is_dir()
                            }),
                    );
                } else {
                    dirs.push(path);
                }
            }
        }
        dirs.sort();
        // Recorded sessions nest attack takes in subdirectories (for
        // example mn3-session/phone-replay-car); collect recursively and
        // preserve attack labels from both the session and nested takes.
        let mut sessions: Vec<(PathBuf, bool)> = Vec::new();
        for dir in &dirs {
            sessions.extend(collect_recorded_images(dir));
        }

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
        for (file, attack) in &sessions {
            if let Some(image) = decode_image(file).unwrap_or_else(|error| panic!("{error}")) {
                frames += 1;
                corpus.push((file.clone(), *attack, image.grayscale));
            }
        }
        let mut reference: Option<Vec<f32>> = None;
        let mut reference_rgb: Option<Vec<f32>> = None;
        // Pass 1: the first genuine frame with a detectable face of each
        // modality becomes that modality's CPU template.
        let mut faces = 0usize;
        let mut probes: Vec<(FaceProbe, bool, bool)> = Vec::new();
        for (file, attack, ir) in &corpus {
            let image = decode_image(file)
                .unwrap_or_else(|error| panic!("{error}"))
                .expect("the corpus was decoded once");
            let mut devices = Devices {
                cpu: &mut cpu,
                gpu: &mut recognizer,
            };
            let Some(probe) = probe_both(
                &mut cascade,
                &mut devices,
                &image.rgb,
                image.width,
                image.height,
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
        cascade.report();
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
        // The no-new-grants direction is the security gate itself
        // (ADR-0033 section 5): the test result must carry it, not the log.
        assert_eq!(
            new_grants, 0,
            "the GPU granted a presentation attack the CPU denied"
        );
    }

    /// Every jpg/jpeg/png/pgm/ppm under `root`, recursively, sorted. A local
    /// walker keeps the evidence harness free of new dependencies.
    fn collect_images(root: &Path) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let entries =
                std::fs::read_dir(dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
            for entry in entries {
                let entry = entry.unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
                let path = entry.path();
                let metadata = path
                    .metadata()
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                if metadata.is_dir() {
                    walk(&path, out);
                } else if path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|ext| {
                        matches!(
                            ext.to_ascii_lowercase().as_str(),
                            "jpg" | "jpeg" | "png" | "pgm" | "ppm"
                        )
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

    fn collect_recorded_images(session: &Path) -> Vec<(PathBuf, bool)> {
        let attack = is_attack(&session.file_name().unwrap().to_string_lossy());
        collect_images(session)
            .into_iter()
            .map(|file| {
                let nested_attack = file
                    .strip_prefix(session)
                    .expect("the collected image belongs to the session")
                    .parent()
                    .unwrap()
                    .components()
                    .any(|part| is_attack(&part.as_os_str().to_string_lossy()));
                (file, attack || nested_attack)
            })
            .collect()
    }

    #[test]
    fn gpu_evidence_walk_refuses_unreadable_directories() {
        let scratch = tempfile::tempdir().unwrap();
        let not_directory = scratch.path().join("not-directory");
        std::fs::write(&not_directory, b"synthetic input").unwrap();
        assert!(std::panic::catch_unwind(|| collect_images(&not_directory)).is_err());
        assert!(
            std::panic::catch_unwind(|| collect_images(&scratch.path().join("missing"))).is_err()
        );
    }

    const LFW_PAIRS_HEADER: &str =
        "pair_id,fold_id,fold_position,is_same,image_a,image_b,image_a_path,image_b_path";

    fn lfw_pairs(root: &Path) -> Vec<(bool, PathBuf, PathBuf)> {
        let csv = root.join("pairs.csv");
        let text = std::fs::read_to_string(&csv)
            .unwrap_or_else(|error| panic!("{}: {error}", csv.display()));
        let train = root.join("train");
        let mut pairs = Vec::new();
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some(LFW_PAIRS_HEADER),
            "{}: unknown LFW protocol",
            csv.display()
        );
        for (index, line) in lines.enumerate() {
            let fields: Vec<_> = line.split(',').collect();
            assert_eq!(
                fields.len(),
                8,
                "{}:{}: malformed pair",
                csv.display(),
                index + 2
            );
            let same = match fields[3] {
                "0" => false,
                "1" => true,
                _ => panic!("{}:{}: invalid pair label", csv.display(), index + 2),
            };
            for relative in [fields[6], fields[7]] {
                assert!(
                    !relative.is_empty()
                        && Path::new(relative)
                            .components()
                            .all(|part| matches!(part, std::path::Component::Normal(_))),
                    "{}:{}: invalid image path",
                    csv.display(),
                    index + 2
                );
            }
            let (a, b) = (train.join(fields[6]), train.join(fields[7]));
            for path in [&a, &b] {
                assert!(
                    path.metadata()
                        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
                        .is_file(),
                    "{}: not an image file",
                    path.display()
                );
            }
            pairs.push((same, a, b));
        }
        pairs
    }

    #[test]
    fn gpu_evidence_lfw_refuses_malformed_protocol_rows() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::create_dir(scratch.path().join("train")).unwrap();
        for name in ["a.jpg", "b.jpg"] {
            std::fs::write(scratch.path().join("train").join(name), b"synthetic input").unwrap();
        }
        for row in [
            "truncated",
            "1,0,0,unknown,a,b,a.jpg,b.jpg",
            "1,0,0,0,a,b,a.jpg,missing.jpg",
        ] {
            std::fs::write(
                scratch.path().join("pairs.csv"),
                format!("{LFW_PAIRS_HEADER}\n{row}\n"),
            )
            .unwrap();
            assert!(
                std::panic::catch_unwind(|| lfw_pairs(scratch.path())).is_err(),
                "{row}"
            );
        }
    }

    #[test]
    fn gpu_evidence_lfw_preserves_valid_protocol_pairs() {
        let scratch = tempfile::tempdir().unwrap();
        let train = scratch.path().join("train");
        std::fs::create_dir(&train).unwrap();
        for name in ["a.jpg", "b.jpg"] {
            std::fs::write(train.join(name), b"synthetic input").unwrap();
        }
        std::fs::write(
            scratch.path().join("pairs.csv"),
            format!("{LFW_PAIRS_HEADER}\n1,0,0,1,a,b,a.jpg,b.jpg\n2,0,1,0,b,a,b.jpg,a.jpg\n"),
        )
        .unwrap();
        assert_eq!(
            lfw_pairs(scratch.path()),
            vec![
                (true, train.join("a.jpg"), train.join("b.jpg")),
                (false, train.join("b.jpg"), train.join("a.jpg")),
            ]
        );
    }

    fn require_fairface_groups(groups: &[(String, Stats)]) {
        assert!(!groups.is_empty(), "no FairFace groups were measured");
        for (name, stats) in groups {
            assert!(stats.n > 0, "FairFace group {name} measured no samples");
        }
    }

    fn fairface_groups(root: &Path) -> Vec<(String, Vec<PathBuf>)> {
        let mut groups = Vec::new();
        for entry in
            std::fs::read_dir(root).unwrap_or_else(|error| panic!("{}: {error}", root.display()))
        {
            let entry = entry.unwrap_or_else(|error| panic!("{}: {error}", root.display()));
            if entry
                .path()
                .metadata()
                .unwrap_or_else(|error| panic!("{}: {error}", entry.path().display()))
                .is_dir()
            {
                let name = entry.file_name().to_string_lossy().into_owned();
                groups.push((name, collect_images(&entry.path())));
            }
        }
        groups.sort();
        groups
    }

    #[test]
    fn gpu_evidence_fairface_keeps_linked_group_directories() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("fairface");
        let linked = scratch.path().join("linked-inputs");
        std::fs::create_dir_all(root.join("ordinary")).unwrap();
        std::fs::create_dir(&linked).unwrap();
        std::fs::write(
            root.join("ordinary/frame.jpg"),
            b"synthetic collector input",
        )
        .unwrap();
        std::fs::write(linked.join("frame.jpg"), b"synthetic collector input").unwrap();
        std::os::unix::fs::symlink(&linked, root.join("linked")).unwrap();
        assert_eq!(
            fairface_groups(&root),
            vec![
                ("linked".into(), vec![root.join("linked/frame.jpg")]),
                ("ordinary".into(), vec![root.join("ordinary/frame.jpg")]),
            ]
        );
    }

    #[test]
    fn gpu_evidence_requires_samples_from_every_fairface_group() {
        let mut measured = Stats::default();
        measured.add(0.0, 0.0, 0.55);
        let groups = vec![
            ("measured".into(), measured),
            ("unmeasured".into(), Stats::default()),
        ];
        assert!(std::panic::catch_unwind(|| require_fairface_groups(&groups)).is_err());
        assert!(std::panic::catch_unwind(|| require_fairface_groups(&[])).is_err());
        let groups: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|name| {
                let mut stats = Stats::default();
                stats.add(0.0, 0.0, 0.55);
                (name.to_owned(), stats)
            })
            .collect();
        require_fairface_groups(&groups);
    }

    #[test]
    fn gpu_recorded_walk_includes_pnm_and_rgb_images() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        std::fs::create_dir(root.join("nested")).unwrap();
        let expected = [
            "genuine.PGM",
            "nested/attack.ppm",
            "nested/frame.JPEG",
            "nested/frame.jpg",
            "nested/frame.png",
        ]
        .map(|name| root.join(name));
        for path in &expected {
            std::fs::write(path, b"synthetic collector input").unwrap();
        }
        std::fs::write(root.join("notes.txt"), b"not an image").unwrap();
        assert_eq!(collect_images(root), expected);
    }

    #[test]
    fn gpu_recorded_walk_labels_nested_attacks_without_using_frame_names() {
        let scratch = tempfile::tempdir().unwrap();
        let session = scratch.path().join("mn3-session");
        let fixtures = [
            ("genuine/frame.png", false),
            ("genuine/screen-frame.png", false),
            ("phone-replay-car/frame.png", true),
            ("phone-replay-car-2/deeper/frame.png", true),
            ("spoof-print/frame.png", true),
        ];
        for (name, _) in fixtures {
            let path = session.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"synthetic collector input").unwrap();
        }
        let expected: Vec<_> = fixtures
            .into_iter()
            .map(|(name, attack)| (session.join(name), attack))
            .collect();
        assert_eq!(collect_recorded_images(&session), expected);

        let attack_session = scratch.path().join("spoof-print");
        std::fs::create_dir_all(attack_session.join("genuine")).unwrap();
        let path = attack_session.join("genuine/frame.png");
        std::fs::write(&path, b"synthetic collector input").unwrap();
        assert_eq!(collect_recorded_images(&attack_session), vec![(path, true)]);
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
        let (mut cpu, mut cascade) = hw_cpu_cascade();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens");
        report_hw_identity("recognition corpora", platform.identity());
        let cache = scratch.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let (mut recognizer, assignment) = platform.compile(&cache, &bytes).unwrap();
        assert!(assignment == "GPU" || assignment.starts_with("GPU."));

        // Embed each image at most once, whatever pairs reference it.
        let mut embedded: std::collections::HashMap<PathBuf, Option<FaceProbe>> =
            Default::default();
        let mut no_face = 0usize;
        let mut embed = |cascade: &mut DetectionCascade,
                         cpu: &mut crate::Embedder,
                         gpu: &mut Box<dyn crate::npu::Infer>,
                         path: &Path|
         -> Option<FaceProbe> {
            if let Some(cached) = embedded.get(path) {
                return cached.clone();
            }
            let result = match decode_image(path) {
                Ok(Some(image)) => {
                    let mut devices = Devices { cpu, gpu };
                    probe_both(
                        cascade,
                        &mut devices,
                        &image.rgb,
                        image.width,
                        image.height,
                        true,
                    )
                }
                Ok(None) => None,
                Err(error) => panic!("{error}"),
            };
            if result.is_none() {
                no_face += 1;
            }
            embedded.insert(path.to_path_buf(), result.clone());
            result
        };

        // The canonical pairs: pair_id,fold_id,fold_position,is_same,
        // image_a,image_b,image_a_path,image_b_path, paths relative to
        // the corpus's train/ tree.
        let (mut genuine, mut impostor_lfw) = (Stats::default(), Stats::default());
        let mut lfw_pairs_used = [0usize; 2];
        for (is_same, a, b) in lfw_pairs(&lfw_root) {
            if lfw_pairs_used[usize::from(is_same)] >= max_pairs {
                continue;
            }
            let (Some(template), Some(probe)) = (
                embed(&mut cascade, &mut cpu, &mut recognizer, &a),
                embed(&mut cascade, &mut cpu, &mut recognizer, &b),
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

        // Impostor pairs, FairFace (impostor-only tree), balanced across
        // its demographic group directories: mixed-population pairs would
        // understate the within-group risk (docs/FAIRNESS.md), and a
        // globally sorted walk would exhaust the alphabetically earliest
        // group before reaching the rest.
        let mut impostor_fairface = Stats::default();
        let groups = fairface_groups(&fairface_root);
        assert!(
            !groups.is_empty(),
            "the FairFace root has no group directories"
        );
        println!(
            "fairface groups: {}",
            groups
                .iter()
                .map(|(name, files)| format!("{name} {}", files.len()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let per_group = (max_impostors / groups.len()).max(1);
        let mut measured_groups = Vec::new();
        for (name, files) in &groups {
            let mut measured = 0usize;
            let mut group_stats = Stats::default();
            let mut skipped_pairs = 0usize;
            for pair in files.windows(2) {
                if measured >= per_group {
                    break;
                }
                let (Some(template), Some(probe)) = (
                    embed(&mut cascade, &mut cpu, &mut recognizer, &pair[0]),
                    embed(&mut cascade, &mut cpu, &mut recognizer, &pair[1]),
                ) else {
                    skipped_pairs += 1;
                    continue;
                };
                measured += 1;
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
                group_stats.add(cpu_score, gpu_score, 0.55);
            }
            println!(
                "FairFace group {name}: discovered {} images, skipped {skipped_pairs} pairs; {}",
                files.len(),
                group_stats.line_as("measured at 0.55", "GPU")
            );
            measured_groups.push((name.clone(), group_stats));
        }
        require_fairface_groups(&measured_groups);
        assert!(platform.still_loaded_as_hashed().is_ok());
        // A vacuous run is not evidence: both directions need samples.
        assert!(genuine.n > 0, "no genuine pairs were measured");
        assert!(impostor_lfw.n > 0, "no LFW impostor pairs were measured");
        assert!(
            impostor_fairface.n > 0,
            "no FairFace impostor pairs were measured"
        );
        println!("skipped images without a usable aligned face: {no_face}");
        cascade.report();
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
        // The no-new-grants direction is the security gate itself
        // (ADR-0033 section 5): the test result must carry it, not the log.
        assert_eq!(new_grants, 0, "the GPU granted an impostor the CPU denied");
    }

    // Evidence must not mistake delayed clock reads for a suspend. These
    // bounds are intentionally opposite to production's conservative
    // recheck trigger, where a delay may safely cause an extra recheck.
    const SUSPEND_PROOF_BASELINE_BOUND: crate::npu::Bound = crate::npu::Bound::AtLeast;
    const SUSPEND_PROOF_LATER_BOUND: crate::npu::Bound = crate::npu::Bound::AtMost;

    /// Only guaranteed growth beyond clock granularity proves a suspend.
    /// Delayed reads can hide growth here, but cannot invent proof of it.
    fn suspend_is_proven(
        baseline_upper: std::time::Duration,
        later_lower: std::time::Duration,
    ) -> bool {
        later_lower.saturating_sub(baseline_upper) > crate::npu::RESUME_GRANULARITY
    }

    #[test]
    fn gpu_suspend_proof_rejects_delayed_reads_without_suspend() {
        use crate::npu::Bound;
        use std::time::Duration;

        // Both clocks advance during preemption; their true difference
        // stays fixed, with or without an earlier suspend in this boot.
        for elapsed in [Duration::ZERO, Duration::from_secs(20)] {
            let read = |bound, delay| match bound {
                Bound::AtMost => elapsed.saturating_sub(delay),
                Bound::AtLeast => elapsed + delay,
            };
            let baseline = read(SUSPEND_PROOF_BASELINE_BOUND, Duration::from_millis(3));
            let later = read(SUSPEND_PROOF_LATER_BOUND, Duration::from_millis(5));
            assert!(
                !suspend_is_proven(baseline, later),
                "delayed reads with constant suspended time {elapsed:?} are not proof"
            );
        }
    }

    #[test]
    fn gpu_suspend_proof_requires_growth_beyond_uncertainty_and_granularity() {
        use crate::npu::Bound;
        use std::time::Duration;

        let elapsed = Duration::from_secs(20);
        let baseline_delay = Duration::from_millis(3);
        let later_delay = Duration::from_millis(5);
        let read = |bound, suspended: Duration, delay| match bound {
            Bound::AtMost => suspended.saturating_sub(delay),
            Bound::AtLeast => suspended + delay,
        };
        let baseline = read(SUSPEND_PROOF_BASELINE_BOUND, elapsed, baseline_delay);
        let boundary = baseline_delay + later_delay + crate::npu::RESUME_GRANULARITY;
        for (growth, proven) in [
            (crate::npu::RESUME_GRANULARITY, false),
            (boundary, false),
            (boundary + Duration::from_nanos(1), true),
            (Duration::from_secs(5), true),
        ] {
            let later = read(SUSPEND_PROOF_LATER_BOUND, elapsed + growth, later_delay);
            assert_eq!(
                suspend_is_proven(baseline, later),
                proven,
                "suspended-time growth {growth:?} with delayed reads"
            );
        }
    }

    /// The suspend/resume recheck a GPU certification requires, run as
    /// ONE process that spans the suspend: it opens the platform, records
    /// the digest baseline and the suspended-time baseline, then waits
    /// (`IRLUME_GPU_TEST_SUSPEND_WAIT_SECS`, default 600) for a real
    /// system suspend. Proof requires the later lower bound of
    /// CLOCK_BOOTTIME-minus-MONOTONIC to exceed its baseline upper bound
    /// by more than clock granularity. Unlike production's conservative
    /// recheck trigger, scheduling delays cannot produce false proof.
    /// Once proven, the reference inputs must reproduce their bits and
    /// the mapped-library inventory must still verify. Without proof,
    /// the lane returns without exercising the post-resume checks; that
    /// is inconclusive, not suspend certification evidence. A small
    /// suspend or delayed reads can leave the proof inconclusive. The
    /// lane never suspends the system itself.
    #[test]
    #[ignore = "hardware: needs the validated OpenVINO provider, an Intel GPU and the recognizer weights; the recheck arm waits for a real attended suspend"]
    fn gpu_hw_suspend_resume_recheck() {
        let wait_seconds: u64 = std::env::var("IRLUME_GPU_TEST_SUSPEND_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600);
        let scratch = tempfile::tempdir().unwrap();
        let bytes = recognizer_bytes();
        let (_cpu, _cascade) = hw_cpu_cascade();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default())
                .expect("the GPU platform opens");
        report_hw_identity("suspend recheck", platform.identity());
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
        // An upper baseline and a later lower bound prove minimum growth,
        // rather than a possible conservative recheck (npu::suspended).
        let clock_baseline_upper = crate::npu::suspended(SUSPEND_PROOF_BASELINE_BOUND)
            .expect("the suspend clock is readable");
        println!(
            "digest baseline {baseline:?}; suspended-time upper bound {clock_baseline_upper:?}; \
             waiting up to {wait_seconds}s for bounded proof of an attended system suspend"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_seconds);
        let mut resumed = false;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let clock_later_lower = crate::npu::suspended(SUSPEND_PROOF_LATER_BOUND)
                .expect("the suspend clock is readable");
            if suspend_is_proven(clock_baseline_upper, clock_later_lower) {
                resumed = true;
                break;
            }
        }
        if !resumed {
            println!(
                "no suspend proven within {wait_seconds}s: inconclusive; post-resume checks \
                 not exercised, suspend certification evidence still pending"
            );
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
        println!(
            "bounded clock growth proved suspend; post-resume bits and mapped inventory unchanged"
        );
    }
}
