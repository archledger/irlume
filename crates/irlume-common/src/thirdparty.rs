//! Catalog of OPTIONAL third-party models irlume can fetch on the operator's
//! own machine, but does not ship, mirror, or warrant.
//!
//! Why this lane exists (issue #4): some externally-trained PAD models carry a
//! real license on their weights but fail the shipped-stack bar in ADR-0001
//! (undocumented training data, non-reproducible training). Those may be
//! offered OPT-IN: the user sees the license and the provenance status, types
//! the model name to confirm, and irlume downloads the weights from the
//! publisher's own origin (never a mirror; irlume must not redistribute),
//! verifies the pinned sha256, and stores them under the state dir. Disabling
//! deletes the weights, so "no unwarranted bits at rest" stays checkable.
//!
//! A catalog entry is added only after the model is measured on real hardware
//! against the published attack species (see docs/pad-results/); the daemon
//! wires any entry here as a DENY-ONLY cue: it may reject a presentation, it
//! can never approve one the built-in gate rejected.

use std::path::PathBuf;

/// `settings.conf` key naming the enabled model (absent/empty = disabled).
pub const SETTINGS_KEY: &str = "third_party_pad";

/// Subdirectory of the state dir holding fetched third-party weights.
pub const SUBDIR: &str = "models-thirdparty";

pub struct ThirdPartyModel {
    /// Catalog name, what the user types to enable (`irlume models enable X`).
    pub name: &'static str,
    /// On-disk file name under the state subdir.
    pub file: &'static str,
    /// Direct download URL at the publisher's origin.
    pub url: &'static str,
    /// Pinned sha256 of the artifact; a fetched file that does not match is
    /// deleted, and the daemon refuses to load a file that stops matching.
    pub sha256: &'static str,
    pub license: &'static str,
    /// Honest provenance status, shown before the user confirms.
    pub provenance: &'static str,
    /// Decision threshold on the model's P(fake); measured basis in `summary`.
    pub threshold: f32,
    /// One-line measured result, with the repo doc that carries the details.
    pub summary: &'static str,
}

/// Every entry here has a measurement document in docs/pad-results/.
pub const CATALOG: &[ThirdPartyModel] = &[ThirdPartyModel {
    name: "flir",
    file: "flir.onnx",
    url: "https://modelscope.cn/api/v1/models/damo/cv_manual_face-liveness_flir/repo?FilePath=model.onnx&Revision=master",
    sha256: "df80cea7228b92562692e56aac965d35766c77399159798c552fb3c77b410c72",
    license: "MIT (Alibaba DAMO, ModelScope model card)",
    provenance: "training data undocumented by the publisher; not reproducible \
                 (fails ADR-0001 criteria 2-3, which is why it is opt-in)",
    threshold: 0.5,
    summary: "IR anti-spoof cue; measured 2026-07-17: catches the vinyl-print \
              species the built-in gate misses (122/123 attack frames, 2 \
              cameras) with 0/35 genuine flagged on the same camera \
              (docs/pad-results/2026-07-17-third-party-pad-candidates.md)",
}];

pub fn by_name(name: &str) -> Option<&'static ThirdPartyModel> {
    CATALOG.iter().find(|m| m.name == name)
}

/// Directory for fetched third-party weights: `$IRLUME_STATE_DIR` (sandbox
/// override) else `/var/lib/irlume`, plus [`SUBDIR`].
pub fn dir() -> PathBuf {
    let root = std::env::var_os("IRLUME_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(crate::STATE_DIR));
    root.join(SUBDIR)
}

/// On-disk path for a catalog entry.
pub fn model_path(m: &ThirdPartyModel) -> PathBuf {
    dir().join(m.file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_entries_are_well_formed() {
        for m in CATALOG {
            assert!(!m.name.is_empty() && m.name.chars().all(|c| c.is_ascii_alphanumeric()));
            assert_eq!(
                m.sha256.len(),
                64,
                "{}: sha256 must be 64 hex chars",
                m.name
            );
            assert!(m.sha256.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(
                m.url.starts_with("https://"),
                "{}: origin must be https",
                m.name
            );
            assert!(m.threshold > 0.0 && m.threshold < 1.0);
            assert!(m.file.ends_with(".onnx"));
            assert!(
                m.summary.contains("docs/pad-results/"),
                "{}: summary must cite the measurement doc",
                m.name
            );
        }
    }

    #[test]
    fn lookup_by_name() {
        assert!(by_name("flir").is_some());
        assert!(by_name("nope").is_none());
    }
}
