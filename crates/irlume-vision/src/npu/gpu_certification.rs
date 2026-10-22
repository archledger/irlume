// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The GPU certification key and table (ADR-0033 amendment of 2026-10-22,
//! "the certification key binds the numerics set").
//!
//! Every library the GPU platform maps stays hashed in the exact
//! [`Identity`] (section 3), which still names caches, markers and
//! diagnostics. A certification entry instead keys on the numerics set:
//! the OpenVINO libraries, the compute runtime's drivers and gmmlib, and
//! the kernel compiler toolchain, by library name and content, independent
//! of the installation prefix. Every other mapped library must be on the
//! reviewed support list; its content goes into a separate digest the
//! entry records, and a live support digest that differs makes the engine
//! build reproduce an extended reference set before the GPU answers. A
//! mapped library on neither list refuses placement with its name.

use super::Identity;

/// Library names (the file name up to `.so`) of the numerics set: the
/// libraries that compile or run the recognizer's GPU program. One `*`
/// matches any run of characters. Adding a name is a reviewed change.
pub const NUMERICS: &[&str] = &[
    // OpenVINO: graph transformations, kernel selection and the GPU plugin
    // with its embedded kernel sources; every OpenVINO library is bound.
    "libopenvino",
    "libopenvino_c",
    "libopenvino_intel_gpu_plugin",
    "libopenvino_ir_frontend",
    "libopenvino_onnx_frontend",
    // The compute runtime's OpenCL and Level Zero drivers and its memory
    // library.
    "libigdrcl",
    "libze_intel_gpu",
    "libigdgmm",
    // The kernel compiler toolchain. Fedora's IGC and opencl-clang link
    // the system LLVM, clang and SPIR-V translator, so those are bound.
    "libigc",
    "libigdfcl",
    "libopencl-clang",
    "libclang-cpp",
    "libLLVM",
    "libLLVMSPIRVLib",
];

/// Library names of the support set: every other library the measured GPU
/// inventories map, none with a part in the recognizer's arithmetic
/// (docs/research/2026-10-22-gpu-certification-key.md). The daemon's own
/// dependencies join once its inventory under the real unit is measured;
/// until then they refuse like any unlisted library.
pub const SUPPORT: &[&str] = &[
    // C runtime and loader.
    "ld-linux-x86-64",
    "libc",
    "libm",
    "libdl",
    "libpthread",
    "librt",
    // C++ runtime and unwinder; Fedora maps libgcc_s by its versioned
    // file name (`libgcc_s-16-20260819.so.1`).
    "libstdc++",
    "libgcc_s",
    "libgcc_s-*",
    // Host threads and XML metadata.
    "libtbb",
    "libtbbmalloc",
    "libpugixml",
    // Lossless compression and the dependencies LLVM and libxml2 pull in.
    "libz",
    "libzstd",
    "liblzma",
    "libxml2",
    "libtinfo",
    "libedit",
    "libffi",
    // Used only for kernels with debug information, and for dumps.
    "liblldCommon",
    "liblldELF",
    "libSPIRV-Tools",
    // The ICD and Level Zero loaders forward calls to the driver.
    "libOpenCL",
    "libze_loader",
    // irlume's CPU-side runtimes, already bound by the entry's ONNX Runtime
    // version and CPU reference digest.
    "libonnxruntime",
    "libtensorflowlite_c",
];

/// The identity fields the key binds, by their [`Identity`] field-dump
/// names. Installation paths and the PCI position are left out so an entry
/// covers the same device, firmware and numerics content wherever it is
/// installed; the library manifest enters as the numerics set instead.
const KEY_FIELDS: &[&str] = &[
    "runtime_version",
    "runtime_build",
    "gpu_plugin",
    "full_name",
    "capabilities",
    "architecture",
    "execution_units",
    "device_id",
    "render_node.vendor",
    "render_node.device",
    "loader",
    "configuration",
    "firmware",
];

/// The identity fields the key leaves out, and why each is safe to leave.
#[cfg(test)]
const EXCLUDED_FIELDS: &[&str] = &[
    // Installation paths: the numerics set binds the content by name.
    "selected_library",
    "canonical_library",
    // PCI and DRM positions, not properties of the device.
    "device_pci",
    "render_node.name",
    "render_node.pci",
    // Replaced by the numerics manifest and the support digest.
    "libraries",
];

/// A mapped library whose name the lists do not classify, or two mapped
/// files sharing a file name: either keeps the GPU off until a review
/// settles it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// File names on neither list, sorted.
    Unclassified(Vec<String>),
    /// A file name mapped from two paths.
    Ambiguous(String),
    /// A manifest line that is not `ABSOLUTE-PATH SHA256`.
    Malformed,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unclassified(names) => write!(
                f,
                "mapped libraries on neither reviewed GPU list: {}",
                names.join(", ")
            ),
            Self::Ambiguous(name) => write!(f, "library {name} is mapped from two paths"),
            Self::Malformed => f.write_str("malformed GPU library manifest"),
        }
    }
}

/// The certification key of a live identity and the digest of its support
/// set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// Binds the device, firmware and configuration fields and the
    /// numerics set's content by file name.
    pub numerics_key: String,
    /// Binds the support set's content by file name.
    pub support_digest: String,
}

/// The library name of a file name: the part before `.so` when `.so` ends
/// the name or is followed by a version (`libLLVM.so.22.1` -> `libLLVM`,
/// `libigdrcl.so` -> `libigdrcl`).
fn library_name(file_name: &str) -> Option<&str> {
    let mut search = 0;
    while let Some(found) = file_name[search..].find(".so") {
        let at = search + found;
        let rest = &file_name[at + 3..];
        if at > 0 && (rest.is_empty() || rest.starts_with('.')) {
            return Some(&file_name[..at]);
        }
        search = at + 3;
    }
    None
}

/// `pattern` with `*` matching any run of characters, against `name`.
fn glob(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => {
            name.len() >= head.len() + tail.len()
                && name.starts_with(head)
                && glob_tail(tail, &name[head.len()..])
        }
    }
}

fn glob_tail(pattern: &str, name: &str) -> bool {
    // `pattern` follows a `*`: try every split point.
    (0..=name.len())
        .filter(|&i| name.is_char_boundary(i))
        .any(|i| glob(pattern, &name[i..]))
}

fn listed(list: &[&str], name: &str) -> bool {
    list.iter().any(|pattern| glob(pattern, name))
}

/// Length-prefixed SHA-256 over `parts`, tagged.
fn encode(tag: &str, parts: &[&str]) -> String {
    let mut encoded = tag.as_bytes().to_vec();
    encoded.push(0);
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part.as_bytes());
    }
    irlume_common::sha256_hex(&encoded)
}

/// Split a `path sha256` manifest into the numerics and support sets, each
/// as sorted `file-name sha256` lines.
fn classify(manifest: &str) -> Result<(String, String), KeyError> {
    let mut by_name = std::collections::BTreeMap::new();
    let mut unclassified = std::collections::BTreeSet::new();
    for line in manifest.lines() {
        let (path, hash) = line.rsplit_once(' ').ok_or(KeyError::Malformed)?;
        let path = std::path::Path::new(path);
        let file = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(KeyError::Malformed)?;
        if !path.is_absolute()
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(KeyError::Malformed);
        }
        if by_name.insert(file.to_owned(), hash.to_owned()).is_some() {
            return Err(KeyError::Ambiguous(file.to_owned()));
        }
        let numerics = library_name(file).is_some_and(|name| listed(NUMERICS, name));
        let support = library_name(file).is_some_and(|name| listed(SUPPORT, name));
        if !numerics && !support {
            unclassified.insert(file.to_owned());
        }
    }
    if !unclassified.is_empty() {
        return Err(KeyError::Unclassified(unclassified.into_iter().collect()));
    }
    let (mut numerics, mut support) = (String::new(), String::new());
    for (file, hash) in by_name {
        let set = if library_name(&file).is_some_and(|name| listed(NUMERICS, name)) {
            &mut numerics
        } else {
            &mut support
        };
        set.push_str(&file);
        set.push(' ');
        set.push_str(&hash);
        set.push('\n');
    }
    Ok((numerics, support))
}

impl Identity {
    /// The certification key and support digest of this identity
    /// (ADR-0033 amendment of 2026-10-22).
    ///
    /// # Errors
    ///
    /// When a mapped library is on neither list, a file name is mapped
    /// from two paths, or the manifest is malformed.
    pub fn certification_key(&self) -> Result<Key, KeyError> {
        let (numerics, support) = classify(&self.libraries)?;
        let fields = self.fields();
        let mut parts = Vec::with_capacity(2 * KEY_FIELDS.len() + 1);
        for name in KEY_FIELDS {
            // Every key field is an identity field (a test pins the lists);
            // a missing one fails closed instead of keying on less.
            let (_, value) = fields
                .iter()
                .find(|(field, _)| field == name)
                .ok_or(KeyError::Malformed)?;
            parts.push(*name);
            parts.push(value.as_ref());
        }
        parts.push(numerics.as_str());
        Ok(Key {
            numerics_key: encode("irlume-gpu-numerics-v1", &parts),
            support_digest: encode("irlume-gpu-support-v1", &[support.as_str()]),
        })
    }
}

/// How an entry witnessed the ADR-0022 section 7 runtime-suspend arm
/// (ADR-0033 amendment of 2026-10-22, "the runtime-suspend arm where the
/// driver holds the device").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWitness {
    /// A runtime suspend was observed with the model retained.
    ObservedRuntimeSuspend,
    /// The driver holds the device while a compute context exists, so no
    /// runtime suspend can occur with the model retained; the daemon
    /// retires the GPU if the bound device's runtime-suspended time ever
    /// grows.
    DriverHold,
}

/// One certified (recognizer, GPU numerics key, CPU reference) entry
/// (ADR-0033 section 5 and its amendments).
#[derive(Clone, Copy, Debug)]
pub struct Certification {
    /// SHA-256 of the model file, as in `models/SHA256SUMS`.
    pub model_sha256: &'static str,
    /// Which model it is.
    pub role: super::super::Role,
    /// [`Key::numerics_key`] of the certified platform.
    pub numerics_key: &'static str,
    /// The exact [`Identity::digest`] the evidence ran under. Recorded for
    /// the evidence trail; never matched.
    pub identity_digest: &'static str,
    /// The ONNX Runtime version of the CPU reference.
    pub onnx_runtime: &'static str,
    /// The wired thresholds that consume the output, by constant name.
    pub thresholds: &'static [(&'static str, f32)],
    /// The recognition decision fingerprint of irlume-auth.
    pub decision_fingerprint: &'static str,
    /// The decoded CPU outputs for the fixed reference inputs.
    pub fingerprint: &'static [f32],
    /// SHA-256 of the CPU session's raw output bits for the reference
    /// inputs.
    pub cpu_reference_digest: &'static str,
    /// SHA-256 of the GPU's raw output bits for the reference inputs.
    pub gpu_reference_digest: &'static str,
    /// [`Key::support_digest`] of the certified platform.
    pub support_digest: &'static str,
    /// SHA-256 of the GPU's raw output bits for the extended reference set,
    /// each input run twice; required when the live support digest
    /// differs.
    pub extended_reference_digest: &'static str,
    /// How the runtime-suspend arm was witnessed.
    pub runtime_witness: RuntimeWitness,
    /// Where the certification evidence is recorded.
    pub evidence: &'static str,
}

/// Every certified GPU entry. Empty until a certification passes every
/// ADR-0033 section 5 gate on real hardware.
pub const CERTIFIED: &[Certification] = &[];

/// An entry that certifies a live platform, and whether the support set
/// differs from the certified one.
#[derive(Clone, Copy, Debug)]
pub struct Matched<'t> {
    /// The entry.
    pub entry: &'t Certification,
    /// The live support digest differs: the engine build must reproduce
    /// [`Certification::extended_reference_digest`] before the GPU answers.
    pub extended_required: bool,
}

/// The entry of `table` certifying `model_sha256` on a platform with `key`
/// for `consumer`, if any.
pub fn certification_in<'t>(
    table: &'t [Certification],
    model_sha256: &str,
    key: &Key,
    consumer: &super::super::Consumer<'_>,
) -> Option<Matched<'t>> {
    table
        .iter()
        .find(|entry| {
            entry.model_sha256 == model_sha256
                && entry.numerics_key == key.numerics_key
                && entry.onnx_runtime == consumer.onnx_runtime
                && super::super::same_thresholds(entry.thresholds, consumer.thresholds)
                && entry.decision_fingerprint == consumer.decision_fingerprint
        })
        .map(|entry| Matched {
            entry,
            extended_required: entry.support_digest != key.support_digest,
        })
}

/// [`certification_in`] over the shipped [`CERTIFIED`] table.
pub fn certification(
    model_sha256: &str,
    key: &Key,
    consumer: &super::super::Consumer<'_>,
) -> Option<Matched<'static>> {
    certification_in(CERTIFIED, model_sha256, key, consumer)
}

#[cfg(test)]
mod tests {
    use super::super::{Firmware, RenderNode, COMPILE_CONFIGURATION};
    use super::*;

    const H0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn manifest(lines: &[(&str, &str)]) -> String {
        lines
            .iter()
            .map(|(path, hash)| format!("{path} {hash}\n"))
            .collect()
    }

    fn stack(prefix: &str, llvm: &str, libc: &str) -> String {
        manifest(&[
            (&format!("{prefix}/lib64/libopenvino.so.2026.2.1"), H0),
            (&format!("{prefix}/lib64/libopenvino_c.so.2026.2.1"), H0),
            (
                &format!("{prefix}/lib64/openvino-2026.2.1/libopenvino_intel_gpu_plugin.so"),
                H0,
            ),
            ("/usr/lib64/intel-opencl/libigdrcl.so", H0),
            ("/usr/lib64/libigc.so.2.41.9+0", H0),
            ("/usr/lib64/libLLVM.so.22.1", llvm),
            ("/usr/lib64/libc.so.6", libc),
            ("/usr/lib64/libgcc_s-16-20260819.so.1", H0),
            ("/usr/lib64/libz.so.1.3.1.zlib-ng", H0),
        ])
    }

    fn identity(libraries: String) -> Identity {
        Identity {
            selected_library: "/usr/lib64/libopenvino_c.so.2621".into(),
            canonical_library: "/usr/lib64/libopenvino_c.so.2026.2.1".into(),
            runtime_version: "2026.2".into(),
            runtime_build: "2026.2.1-000--".into(),
            gpu_plugin: "2026.2.1-000--".into(),
            full_name: "Intel(R) Arc(TM) Graphics (iGPU)".into(),
            capabilities: "FP32 BIN FP16 INT8".into(),
            architecture: "GPU: vendor=0x8086 arch=v20.4.4".into(),
            execution_units: "64".into(),
            total_memory: "30629335040".into(),
            device_id: "0x64a0".into(),
            device_pci: "0000:00:02.0".into(),
            render_node: RenderNode {
                name: "renderD128".into(),
                pci: "0000:00:02.0".into(),
                vendor: "0x8086".into(),
                device: "0x64a0".into(),
            },
            firmware: Firmware::Loaded {
                guc: "70.72.1".into(),
                huc: "9.4.13".into(),
            },
            loader: "opencl".into(),
            configuration: COMPILE_CONFIGURATION.to_owned(),
            libraries,
        }
    }

    #[test]
    fn library_names_stop_at_the_shared_object_suffix() {
        assert_eq!(library_name("libLLVM.so.22.1"), Some("libLLVM"));
        assert_eq!(library_name("libigdrcl.so"), Some("libigdrcl"));
        assert_eq!(library_name("libigc.so.2.41.9+0"), Some("libigc"));
        assert_eq!(library_name("libz.so.1.3.1.zlib-ng"), Some("libz"));
        assert_eq!(
            library_name("ld-linux-x86-64.so.2"),
            Some("ld-linux-x86-64")
        );
        assert_eq!(
            library_name("libgcc_s-16-20260819.so.1"),
            Some("libgcc_s-16-20260819")
        );
        assert_eq!(library_name("libsonic.so.0"), Some("libsonic"));
        assert_eq!(library_name("libfoo.socket"), None);
        assert_eq!(library_name(".so.1"), None);
        assert_eq!(library_name("libfoo"), None);
    }

    #[test]
    fn gpu_lists_are_disjoint_whole_library_names() {
        for numerics in NUMERICS {
            for support in SUPPORT {
                assert!(
                    !glob(numerics, support) && !glob(support, numerics),
                    "{numerics} and {support} overlap"
                );
            }
        }
        // Whole names: a short name never claims a longer one.
        for (name, other) in [
            ("libc", "libcrypto"),
            ("libm", "libmount"),
            ("libz", "libzstd"),
            ("libtbb", "libtbbmalloc"),
            ("libLLVM", "libLLVMSPIRVLib"),
        ] {
            assert!(!glob(name, other), "{name} claims {other}");
        }
        assert!(glob("libgcc_s-*", "libgcc_s-16-20260819"));
        assert!(!glob("libgcc_s-*", "libgcc_s"));
    }

    #[test]
    fn gpu_key_covers_every_identity_field_or_names_its_exclusion() {
        let identity = identity(stack("/usr", H0, H0));
        let names: Vec<_> = identity
            .fields()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        for name in &names {
            assert!(
                KEY_FIELDS.contains(name) ^ EXCLUDED_FIELDS.contains(name),
                "{name} must be bound or excluded, exactly once"
            );
        }
        for name in KEY_FIELDS.iter().chain(EXCLUDED_FIELDS) {
            assert!(names.contains(name), "{name} is not an identity field");
        }
    }

    #[test]
    fn gpu_key_ignores_support_content_and_install_prefix() {
        let base = identity(stack("/usr", H0, H0)).certification_key().unwrap();
        let relocated = identity(stack("/opt/irlume", H0, H0))
            .certification_key()
            .unwrap();
        assert_eq!(base, relocated, "the prefix binds nothing");
        let glibc_update = identity(stack("/usr", H0, H1)).certification_key().unwrap();
        assert_eq!(base.numerics_key, glibc_update.numerics_key);
        assert_ne!(base.support_digest, glibc_update.support_digest);
        // Positions and the unbound memory size do not move the key.
        let mut moved = identity(stack("/usr", H0, H0));
        moved.device_pci = "0000:01:00.0".into();
        moved.render_node.name = "renderD129".into();
        moved.render_node.pci = "0000:01:00.0".into();
        moved.total_memory = "1".into();
        assert_eq!(base, moved.certification_key().unwrap());
    }

    #[test]
    fn gpu_key_changes_with_numerics_content_and_every_key_field() {
        let base = identity(stack("/usr", H0, H0)).certification_key().unwrap();
        let llvm_update = identity(stack("/usr", H1, H0)).certification_key().unwrap();
        assert_ne!(base.numerics_key, llvm_update.numerics_key);
        assert_eq!(base.support_digest, llvm_update.support_digest);
        let mutations: [fn(&mut Identity); 13] = [
            |i| i.runtime_version = "2026.4".into(),
            |i| i.runtime_build = "2026.4.1".into(),
            |i| i.gpu_plugin = "2026.4.1".into(),
            |i| i.full_name = "other".into(),
            |i| i.capabilities = "FP32".into(),
            |i| i.architecture = "GPU: vendor=0x8086 arch=v12.3.0".into(),
            |i| i.execution_units = "80".into(),
            |i| i.device_id = "0xa7a1".into(),
            |i| i.render_node.vendor = "0x1002".into(),
            |i| i.render_node.device = "0xa7a1".into(),
            |i| i.loader = "level-zero".into(),
            |i| i.configuration = "batch=1".into(),
            |i| {
                i.firmware = Firmware::Loaded {
                    guc: "70.73.0".into(),
                    huc: "9.4.13".into(),
                }
            },
        ];
        for mutate in mutations {
            let mut changed = identity(stack("/usr", H0, H0));
            mutate(&mut changed);
            assert_ne!(
                base.numerics_key,
                changed.certification_key().unwrap().numerics_key
            );
        }
    }

    #[test]
    fn gpu_unclassified_library_refuses_with_its_name() {
        let mut libraries = stack("/usr", H0, H0);
        libraries.push_str(&format!("/usr/lib64/libcrypto.so.3 {H0}\n"));
        libraries.push_str(&format!("/usr/lib64/libMesaOpenCL.so.1 {H0}\n"));
        assert_eq!(
            identity(libraries).certification_key(),
            Err(KeyError::Unclassified(vec![
                "libMesaOpenCL.so.1".into(),
                "libcrypto.so.3".into()
            ]))
        );
        let mut ambiguous = stack("/usr", H0, H0);
        ambiguous.push_str(&format!("/opt/lib64/libc.so.6 {H1}\n"));
        assert_eq!(
            identity(ambiguous).certification_key(),
            Err(KeyError::Ambiguous("libc.so.6".into()))
        );
        for bad in [
            "relative/libc.so.6 0000\n".to_owned(),
            format!("relative/libc.so.6 {H0}\n"),
            format!("/usr/lib64/libc.so.6 {}\n", &H0[..63]),
            format!(
                "/usr/lib64/libc.so.6 {}\n",
                H0.to_uppercase().replace('0', "A")
            ),
            "no-space-here\n".to_owned(),
        ] {
            assert_eq!(identity(bad).certification_key(), Err(KeyError::Malformed));
        }
    }

    /// The 37 libraries the UX5406S identity lane mapped on 2026-10-22
    /// (Fedora 44, OpenVINO 2026.2.1, compute runtime 26.35.39758.11):
    /// every one classifies; 13 are numerics (the Level Zero driver of the
    /// list is not mapped under the OpenCL loader) and 24 support.
    #[test]
    fn the_measured_ux5406s_inventory_classifies() {
        let measured = [
            "/usr/lib64/intel-opencl/libigdrcl.so",
            "/usr/lib64/ld-linux-x86-64.so.2",
            "/usr/lib64/libLLVM.so.22.1",
            "/usr/lib64/libLLVMSPIRVLib.so.22.1",
            "/usr/lib64/libOpenCL.so.1.0.0",
            "/usr/lib64/libSPIRV-Tools.so",
            "/usr/lib64/libc.so.6",
            "/usr/lib64/libclang-cpp.so.22.1",
            "/usr/lib64/libdl.so.2",
            "/usr/lib64/libedit.so.0.0.78",
            "/usr/lib64/libffi.so.8.2.0",
            "/usr/lib64/libgcc_s-16-20260819.so.1",
            "/usr/lib64/libigc.so.2.41.9+0",
            "/usr/lib64/libigdfcl.so.2.41.9+0",
            "/usr/lib64/libigdgmm.so.12.10.0",
            "/usr/lib64/liblldCommon.so.22.1",
            "/usr/lib64/liblldELF.so.22.1",
            "/usr/lib64/liblzma.so.5.8.2",
            "/usr/lib64/libm.so.6",
            "/usr/lib64/libopencl-clang.so.22.1",
            "/usr/lib64/libopenvino.so.2026.2.1",
            "/usr/lib64/libopenvino_c.so.2026.2.1",
            "/usr/lib64/libopenvino_ir_frontend.so.2026.2.1",
            "/usr/lib64/libopenvino_onnx_frontend.so.2026.2.1",
            "/usr/lib64/libpthread.so.0",
            "/usr/lib64/libpugixml.so.1.16",
            "/usr/lib64/librt.so.1",
            "/usr/lib64/libstdc++.so.6.0.36",
            "/usr/lib64/libtbb.so.12.17",
            "/usr/lib64/libtbbmalloc.so.2.17",
            "/usr/lib64/libtinfo.so.6.6",
            "/usr/lib64/libxml2.so.2.12.10",
            "/usr/lib64/libz.so.1.3.1.zlib-ng",
            "/usr/lib64/libzstd.so.1.5.7",
            "/usr/lib64/openvino-2026.2.1/libopenvino_intel_gpu_plugin.so",
            "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1",
            "/usr/share/irlume/tflite/libtensorflowlite_c.so",
        ];
        let libraries: String = measured
            .iter()
            .map(|path| format!("{path} {H0}\n"))
            .collect();
        let (numerics, support) = classify(&libraries).unwrap();
        let names = |set: &str| -> Vec<String> {
            set.lines()
                .map(|line| line.split_once(' ').unwrap().0.to_owned())
                .collect()
        };
        assert_eq!(
            names(&numerics),
            [
                "libLLVM.so.22.1",
                "libLLVMSPIRVLib.so.22.1",
                "libclang-cpp.so.22.1",
                "libigc.so.2.41.9+0",
                "libigdfcl.so.2.41.9+0",
                "libigdgmm.so.12.10.0",
                "libigdrcl.so",
                "libopencl-clang.so.22.1",
                "libopenvino.so.2026.2.1",
                "libopenvino_c.so.2026.2.1",
                "libopenvino_intel_gpu_plugin.so",
                "libopenvino_ir_frontend.so.2026.2.1",
                "libopenvino_onnx_frontend.so.2026.2.1",
            ]
        );
        assert_eq!(names(&support).len(), 24);
        assert!(identity(libraries).certification_key().is_ok());
    }

    #[test]
    fn the_shipped_gpu_table_certifies_nothing() {
        assert_eq!(CERTIFIED.len(), 0);
        let key = identity(stack("/usr", H0, H0)).certification_key().unwrap();
        let consumer = super::super::super::Consumer {
            onnx_runtime: "1.28.1",
            thresholds: &[],
            decision_fingerprint: "x",
        };
        assert!(certification("model", &key, &consumer).is_none());
    }

    #[test]
    fn gpu_certification_matches_only_the_full_binding() {
        let key = identity(stack("/usr", H0, H0)).certification_key().unwrap();
        let numerics_key: &'static str = Box::leak(key.numerics_key.clone().into_boxed_str());
        let support_digest: &'static str = Box::leak(key.support_digest.clone().into_boxed_str());
        let entry = Certification {
            model_sha256: "model",
            role: super::super::super::Role::Recognizer,
            numerics_key,
            identity_digest: "evidence",
            onnx_runtime: "1.28.1",
            thresholds: &[("RECOGNITION", 0.55)],
            decision_fingerprint: "decision",
            fingerprint: &[],
            cpu_reference_digest: "cpu",
            gpu_reference_digest: "gpu",
            support_digest,
            extended_reference_digest: "extended",
            runtime_witness: RuntimeWitness::DriverHold,
            evidence: "fixture",
        };
        let table = [entry];
        let consumer = super::super::super::Consumer {
            onnx_runtime: "1.28.1",
            thresholds: &[("RECOGNITION", 0.55)],
            decision_fingerprint: "decision",
        };
        let matched = certification_in(&table, "model", &key, &consumer).unwrap();
        assert!(!matched.extended_required);
        // A support update keeps the entry and requires the extended set.
        let updated = identity(stack("/usr", H0, H1)).certification_key().unwrap();
        assert!(
            certification_in(&table, "model", &updated, &consumer)
                .unwrap()
                .extended_required
        );
        // Anything else misses.
        let numerics = identity(stack("/usr", H1, H0)).certification_key().unwrap();
        assert!(certification_in(&table, "model", &numerics, &consumer).is_none());
        assert!(certification_in(&table, "other", &key, &consumer).is_none());
        for consumer in [
            super::super::super::Consumer {
                onnx_runtime: "1.29.0",
                ..consumer
            },
            super::super::super::Consumer {
                thresholds: &[("RECOGNITION", 0.56)],
                ..consumer
            },
            super::super::super::Consumer {
                decision_fingerprint: "other",
                ..consumer
            },
        ] {
            assert!(certification_in(&table, "model", &key, &consumer).is_none());
        }
    }
}
