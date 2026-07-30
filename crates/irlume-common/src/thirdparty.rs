// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

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

use std::path::{Path, PathBuf};

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
    ///
    /// Set from where the two classes were actually MEASURED to sit, not from
    /// the publisher's default. A deny-only cue that fires in a score band
    /// neither genuine faces nor attacks were observed in is guessing, and it
    /// guesses against the user: every such fire costs a real login.
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
    // 2026-07-17 qualification measured genuine at median 0.0000 (offline
    // corpus 0.001-0.13) and the vinyl-print attack at medians 0.998-1.0000.
    // Nothing was observed between 0.13 and 0.99 in either class, so 0.5 sat in
    // an empty band and turned an out-of-distribution score into a denial. A
    // genuine face measured 0.702 there on 2026-07-27 and lost its keyring.
    //
    // 0.5 was never the publisher's figure: the ModelScope card states no
    // threshold at all, so it was a conventional binary default rather than an
    // upstream recommendation being honoured.
    //
    // Deliberately conservative rather than calibrated. A deny-only cue has
    // asymmetric harm (a false fire blocks a real login; a withheld veto only
    // forgoes an auxiliary check), so the operating point favours the user.
    // Re-measured at 0.9 on 2026-07-27 against the same vinyl banner: 6/6
    // presentations flagged, p_fake 0.941 / 0.956 / 0.995 / 0.999 / 0.999 /
    // 1.000. The attack FLOOR is 0.941, not the 0.998 the medians implied, so
    // the usable window on this hardware is 0.702 (highest genuine) to 0.941
    // (lowest attack). DO NOT raise this threshold toward 0.95 "to be safer":
    // that crosses the measured attack floor and drops a real detection.
    threshold: 0.9,
    summary: "IR anti-spoof cue; measured 2026-07-17: catches the vinyl-print \
              species the built-in gate misses (122/123 attack frames, 2 \
              cameras). Genuine-side failures are mapped, not absent: dim \
              strobe frames and direct sun \
              (docs/pad-results/2026-07-17-third-party-pad-candidates.md)",
}];

/// Highest P(fake) a genuine face was measured at during qualification
/// (offline corpus 0.001-0.13, live medians 0.0000).
///
/// A score above this but below the deny threshold is in the band neither class
/// occupied. The cue abstains there; this constant exists so the abstention can
/// be logged and counted rather than passing unnoticed.
pub const MEASURED_GENUINE_CEILING: f32 = 0.13;

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

/// Lowercase hex SHA-256 of `bytes`, re-exported at this path because the
/// model catalog's callers have always reached it here.
///
/// The implementation moved to the crate root once a second and third caller
/// appeared (login transactions, and the IR emitter's undo journal). Three
/// copies of a checksum is three chances for one of them to disagree with the
/// digests already written to disk.
pub use crate::sha256_hex;

/// Whether a fetched weight file is present and matches its pinned checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightState {
    /// No file at the expected path (not fetched, or disabled and deleted).
    Absent,
    /// File present and its SHA-256 matches the catalog pin.
    ChecksumOk,
    /// File present but its SHA-256 does not match; the daemon refuses to load
    /// it and the CLI reports tampering.
    ChecksumMismatch,
}

/// [`WeightState`] for a catalog entry at its on-disk path.
pub fn weight_state(m: &ThirdPartyModel) -> WeightState {
    weight_state_at(&model_path(m), m.sha256)
}

/// [`WeightState`] for an explicit path against an expected hex SHA-256. Split
/// out from [`weight_state`] so the check is testable without touching the
/// state dir.
pub fn weight_state_at(path: &Path, expected_sha256: &str) -> WeightState {
    match std::fs::read(path) {
        Ok(bytes) if sha256_hex(&bytes) == expected_sha256 => WeightState::ChecksumOk,
        Ok(_) => WeightState::ChecksumMismatch,
        Err(_) => WeightState::Absent,
    }
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

    #[test]
    fn sha256_hex_matches_known_vectors() {
        // NIST FIPS 180-4 examples.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn state_dir_env_override_moves_the_weights_dir() {
        let _g = crate::testenv::lock();
        std::env::remove_var("IRLUME_STATE_DIR");
        assert_eq!(
            dir(),
            Path::new("/var/lib/irlume").join("models-thirdparty"),
            "default weights dir must live under the system state dir"
        );
        let tmp = std::env::temp_dir().join(format!("irlume-tpdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("IRLUME_STATE_DIR", &tmp);
        assert_eq!(dir(), tmp.join(SUBDIR));

        let m = by_name("flir").unwrap();
        assert_eq!(model_path(m), tmp.join(SUBDIR).join("flir.onnx"));
        // Nothing fetched into the sandbox dir yet: Absent through the
        // state-dir-resolving wrapper too, not just weight_state_at.
        assert_eq!(weight_state(m), WeightState::Absent);
        // A fetched file that does not match the catalog pin is tampering.
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(model_path(m), b"not the pinned weights").unwrap();
        assert_eq!(weight_state(m), WeightState::ChecksumMismatch);

        std::env::remove_var("IRLUME_STATE_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn weight_state_reports_present_matching_and_tampered() {
        let tmp = std::env::temp_dir().join(format!("irlume-ws-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let file = tmp.join("w.onnx");
        let good = b"pretend these are model weights";
        let good_sha = sha256_hex(good);

        // Absent: nothing on disk yet.
        assert_eq!(weight_state_at(&file, &good_sha), WeightState::Absent);

        // Present and matching the pin.
        std::fs::write(&file, good).unwrap();
        assert_eq!(weight_state_at(&file, &good_sha), WeightState::ChecksumOk);

        // Present but the pin no longer matches (a swapped / tampered file):
        // the daemon must refuse it, so this stays distinct from ChecksumOk.
        std::fs::write(&file, b"different bytes entirely").unwrap();
        assert_eq!(
            weight_state_at(&file, &good_sha),
            WeightState::ChecksumMismatch
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
