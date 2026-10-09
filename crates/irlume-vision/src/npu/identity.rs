// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Versioned content identity for equivalent provider installation layouts.

use super::Identity;
use std::collections::BTreeMap;
use std::path::Path;

impl Identity {
    /// A versioned execution qualification key independent of installation
    /// directory prefixes. The complete named library-content set and all
    /// hardware, firmware, version and compile-configuration fields remain
    /// binding. [`Self::digest`] still keys diagnostics, caches and legacy
    /// exact-identity entries (ADR-0022 provider-portability amendment). This
    /// low-level encoder uses the supplied `libraries` field; it does not prove
    /// inventory completeness. Live qualification uses [`super::Platform::execution_digest`]
    /// and the platform's separate executable inventory, never its legacy manifest.
    ///
    /// # Errors
    ///
    /// When the content manifest is empty, malformed or has two libraries
    /// with the same filename; ambiguity never inherits qualification.
    pub fn execution_digest(&self) -> Result<String, &'static str> {
        self.execution_digest_from_manifest(&self.libraries)
    }

    pub(super) fn execution_digest_from_manifest(
        &self,
        manifest: &str,
    ) -> Result<String, &'static str> {
        let mut libraries = BTreeMap::new();
        for line in manifest.lines() {
            let (path, hash) = line
                .rsplit_once(' ')
                .ok_or("invalid runtime-content manifest")?;
            let path = Path::new(path);
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("invalid runtime library name")?;
            if !path.is_absolute()
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || libraries.insert(name, hash).is_some()
            {
                return Err("ambiguous or invalid runtime-content manifest");
            }
        }
        if libraries.is_empty() {
            return Err("empty runtime-content manifest");
        }
        let mut manifest = String::new();
        for (name, hash) in libraries {
            manifest.push_str(name);
            manifest.push(' ');
            manifest.push_str(hash);
            manifest.push('\n');
        }
        let mut encoded = b"irlume-npu-execution-v2\0".to_vec();
        for field in [
            self.openvino_build.as_str(),
            self.npu_plugin.as_str(),
            self.driver_version.as_str(),
            self.compiler_version.as_str(),
            self.architecture.as_str(),
            self.pci_id.as_str(),
            self.firmware.as_str(),
            self.configuration.as_str(),
            manifest.as_str(),
        ] {
            encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
            encoded.extend_from_slice(field.as_bytes());
        }
        Ok(irlume_common::sha256_hex(&encoded))
    }
}
