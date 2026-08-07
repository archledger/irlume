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
//! against the published attack species (see docs/pad-results/). Every entry
//! names its pipeline [`Stage`], and only an OPEN stage can be installed or
//! wired. Two stages are open: PAD, whose entries the daemon wires as a
//! DENY-ONLY cue (it may reject a presentation, never approve one the
//! built-in gate rejected; measurements in docs/pad-results/), and
//! RECOGNITION, whose entries replace the RGB matcher at their measured
//! threshold with every IR matching path disabled (measurements in
//! docs/recognition-results/).

use std::path::{Path, PathBuf};

/// `settings.conf` key naming the enabled PAD model (absent/empty = disabled).
pub const SETTINGS_KEY: &str = "third_party_pad";

/// `settings.conf` key naming the enabled third-party RECOGNIZER (absent/empty
/// = the shipped recognizer). Separate keys per stage: one key naming entries
/// of two different stages would make "what is enabled" ambiguous the day two
/// stages are open at once.
pub const RECOGNIZER_SETTINGS_KEY: &str = "third_party_recognizer";

/// `settings.conf` key naming the enabled third-party DETECTOR (absent/empty
/// = the shipped YuNet + short-range rescue). A detection entry replaces the
/// RESCUE slot only: YuNet stays primary, and the third-party model runs
/// when YuNet finds no face, which is the deny-safe seat (a rescue failure
/// is a non-detection, never a grant).
pub const DETECTOR_SETTINGS_KEY: &str = "third_party_detector";

/// The stage-appropriate settings key for a catalog entry.
pub const fn settings_key_for(stage: Stage) -> &'static str {
    match stage {
        Stage::Pad => SETTINGS_KEY,
        Stage::Recognition => RECOGNIZER_SETTINGS_KEY,
        Stage::Detection => DETECTOR_SETTINGS_KEY,
        // No key exists for stages with no wiring; the installer refuses
        // closed stages long before this matters, and giving them a real key
        // here would silently enable whatever wiring later reads it.
        Stage::Landmarks => "third_party_unwired",
    }
}

/// Why a settings value cannot be used as the third-party recognizer.
#[derive(Debug, PartialEq, Eq)]
pub enum RecognizerRefusal {
    /// The name is not in the catalog.
    NotInCatalog,
    /// The entry exists but is not a recognition-stage model.
    WrongStage(&'static str),
    /// The recognition stage is not open to third-party models.
    StageClosed,
}

/// Decide whether a catalog lookup result may be wired as THE recognizer.
///
/// Pure so the refusals are testable with fixture entries; the daemon composes
/// this with [`by_name`], the pin check, and the file read. The stage-open
/// check is here rather than trusted to the installer because the settings key
/// is root-editable text the installer never saw.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn recognizer_override(
    entry: Option<&ThirdPartyModel>,
) -> Result<&ThirdPartyModel, RecognizerRefusal> {
    stage_override(entry, Stage::Recognition)
}

/// [`recognizer_override`] for the detection stage: may this entry be wired
/// as the RESCUE detector?
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn detector_override(
    entry: Option<&ThirdPartyModel>,
) -> Result<&ThirdPartyModel, RecognizerRefusal> {
    stage_override(entry, Stage::Detection)
}

/// The shared decision behind the per-stage overrides: catalog membership,
/// the right stage, and that stage actually open. Pure for the same reason
/// as ever; the per-stage wrappers exist so a call site cannot pass the
/// wrong stage for the slot it is wiring.
fn stage_override(
    entry: Option<&ThirdPartyModel>,
    want: Stage,
) -> Result<&ThirdPartyModel, RecognizerRefusal> {
    let Some(entry) = entry else {
        return Err(RecognizerRefusal::NotInCatalog);
    };
    if entry.stage != want {
        return Err(RecognizerRefusal::WrongStage(entry.stage.as_str()));
    }
    if !want.open() {
        return Err(RecognizerRefusal::StageClosed);
    }
    Ok(entry)
}

/// The pipeline stage a catalog model plugs into.
///
/// Stages are opened to third-party models one at a time (#276), because their
/// failure modes are not equal. A bad PAD model can only false-deny: it is
/// wired deny-only, and every false fire falls back to the password. A bad
/// recognizer authenticates strangers while the legitimate user's own logins
/// keep working, so nothing surfaces the problem; detection and landmarks sit
/// between (most failures deny safely, but bad landmarks feed confident wrong
/// numbers into the liveness cues). The named-but-closed variants exist so the
/// catalog, the CLI, and the reporting all speak the same stage vocabulary
/// before those stages open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Face detection. Not open to third-party models.
    Detection,
    /// Dense landmarks (mesh). Not open: the mesh feeds the liveness cues, and
    /// bad landmarks produce confident numbers from the wrong pixels rather
    /// than an error.
    Landmarks,
    /// The recognizer/embedder. Open only for entries with a measured,
    /// artifact-specific RGB threshold under the split-source protocol
    /// (#276): population FAR from public datasets replayed through irlume's
    /// own pipeline, live genuine floors on this project's cameras. A
    /// third-party recognizer runs RGB-only; every IR matching path is
    /// disabled because no entry carries IR-side measurements.
    Recognition,
    /// Presentation-attack detection (liveness). Open for deny-only cues, so
    /// the worst a bad model does is cost retries or the password.
    Pad,
}

impl Stage {
    /// Every stage, in pipeline order. Callers that report on the stage set must
    /// iterate this rather than spelling stages out, or they go stale the moment
    /// one opens (doctor claimed "the pad stage only today" through the release
    /// that opened recognition).
    pub const ALL: [Stage; 4] = [
        Stage::Detection,
        Stage::Landmarks,
        Stage::Recognition,
        Stage::Pad,
    ];

    /// Stable lowercase name, used in CLI output and the machine API.
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Detection => "detection",
            Stage::Landmarks => "landmarks",
            Stage::Recognition => "recognition",
            Stage::Pad => "pad",
        }
    }

    /// Whether irlume can wire a third-party model at this stage today.
    ///
    /// The installer refuses to place weights for a closed stage and the
    /// daemon refuses to wire them, so adding a catalog entry can never outrun
    /// the safety analysis that opens its stage. PAD opened first (deny-only
    /// wiring); recognition opened 2026-08-05 with the split-source threshold
    /// protocol and the stage-4 wiring (#276, #279) — its entries run
    /// RGB-only, with IR matching, fusion, and dark login disabled because no
    /// entry carries IR-side measurements.
    /// Detection STAYS CLOSED, and the 2026-08-05 measurement is why the
    /// reason is now specific rather than absent. That corpus (512 frames,
    /// docs/pad-results/2026-08-05-fullrange-threshold.md) established an
    /// operating point for full-range BlazeFace: at 0.55, 61 of 291
    /// exposure-usable genuine frames fall below threshold and the highest
    /// empty-scene score is 0.5293, 0.0207 under it.
    ///
    /// It does NOT establish authentication safety, because the rescue slot
    /// is GRANT-CAPABLE: `rescue_detect` fills `rgb_top` when YuNet finds
    /// nothing, and that box is aligned, embedded, matched, and can reach a
    /// grant (#299 review corrected the opposite claim). A detector that
    /// accepts presentations YuNet declines therefore widens the path the
    /// daemon already warns about, that the built-in gate does not stop a
    /// life-size print without the opt-in PAD cue. Opening this stage needs
    /// an end-to-end corpus of prints, screens, and other faces measured on
    /// frames where YuNet returns nothing.
    pub const fn open(self) -> bool {
        matches!(self, Stage::Pad | Stage::Recognition)
    }
}

/// Subdirectory of the state dir holding fetched third-party weights.
pub const SUBDIR: &str = "models-thirdparty";

#[derive(Debug)]
pub struct ThirdPartyModel {
    /// Catalog name, what the user types to enable (`irlume models enable X`).
    pub name: &'static str,
    /// The pipeline stage this model plugs into. Only entries whose stage is
    /// [`Stage::open`] can be installed or wired; the field exists on every
    /// entry so a future measured-but-not-yet-wirable model can be documented
    /// in the catalog without becoming loadable by accident.
    pub stage: Stage,
    /// On-disk file name under the state subdir.
    pub file: &'static str,
    /// Direct download URL at the publisher's origin, or `None` when irlume
    /// will not fetch it for you.
    ///
    /// `None` is not a lesser tier of evidence: an entry is in this catalog
    /// only because irlume measured it, and the threshold and pin below carry
    /// the same weight either way. It means the licence makes fetching the
    /// user's business rather than irlume's, so the file arrives via
    /// `irlume models add <name> <path>` and is checked against `sha256`
    /// exactly as a downloaded one is.
    pub url: Option<&'static str>,
    /// Pinned sha256 of the artifact; a fetched file that does not match is
    /// deleted, and the daemon refuses to load a file that stops matching.
    pub sha256: &'static str,
    pub license: &'static str,
    /// Honest provenance status, shown before the user confirms.
    pub provenance: &'static str,
    /// Decision threshold, in the stage's own unit: P(fake) for a PAD cue,
    /// the RGB cosine match threshold for a recognizer. Measured basis in
    /// `summary`.
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
    stage: Stage::Pad,
    file: "flir.onnx",
    url: Some("https://modelscope.cn/api/v1/models/damo/cv_manual_face-liveness_flir/repo?FilePath=model.onnx&Revision=master"),
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
},
ThirdPartyModel {
    name: "buffalo",
    stage: Stage::Recognition,
    file: "w600k_r50.onnx",
    // Bring-your-own: the InsightFace model zoo licenses all models for
    // non-commercial research use only, so obtaining the file is the user's
    // decision. Extract w600k_r50.onnx from the publisher's official
    // buffalo_l.zip (github.com/deepinsight/insightface, release v0.7) and
    // install with `sudo irlume models add buffalo <path>`.
    url: None,
    sha256: "4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43",
    license: "non-commercial research only (InsightFace model zoo)",
    provenance: "trained on WebFace600K, scraped from the web without subject \
                 consent (fails ADR-0001 for shipping, which is why it is \
                 bring-your-own)",
    // 0.55, split-source protocol (#276): worst FairFace group 4.02e-4 there,
    // parity with the shipped stack's worst group at its own operating point
    // (AuraFace@0.55: 4.17e-4); LFW 4e-5, SFHQ 5.7e-5; live genuine floors
    // 0.685 (Zenbook, side lamp) and 0.793 (BRIO) with production-shaped
    // best-of-N clearing 0.55 at every frame where RGB detected at all. 0.60
    // was REJECTED: its cross-condition margin measured zero (side-lamp
    // production-shaped minimum 0.553). Do not raise this without re-running
    // the floor sessions; do not lower it without re-running the FAR legs.
    threshold: 0.55,
    summary: "replacement RGB recognizer; measured 2026-08-05: LFW EER 3.9% vs \
              shipped 4.2%; at the 0.55 operating point the demographic spread \
              is 3.9x vs the shipped 6.1x with worst-group FAR at parity, and \
              the worst-served group SHIFTS to Middle Eastern; RGB-only (IR \
              matching, fusion and dark login disabled: unmeasured for this \
              model) (docs/recognition-results/2026-08-05-buffalo-l.md)",
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
    crate::state_dir().join(SUBDIR)
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
            // A fetchable entry must name an https origin; a bring-your-own
            // entry names none, and both must still carry a pin, because the
            // pin is how irlume knows WHICH model is loaded rather than
            // trusting whatever file appeared in the directory.
            if let Some(url) = m.url {
                assert!(
                    url.starts_with("https://"),
                    "{}: origin must be https",
                    m.name
                );
            }
            assert!(m.threshold > 0.0 && m.threshold < 1.0);
            // Two runtimes exist since #295: ONNX entries run on
            // onnxruntime, .tflite entries unconverted on the bundled TFLite
            // runtime. Anything else has no loader and must not be listed.
            assert!(
                m.file.ends_with(".onnx") || m.file.ends_with(".tflite"),
                "{}: no runtime loads '{}'",
                m.name,
                m.file
            );
            // Every entry's stage must be open: a closed-stage entry cannot
            // be installed or wired, so listing one would be documentation
            // pretending to be a catalog. If a measured-but-unwirable entry
            // is ever wanted, delete this and re-verify the refusals.
            assert!(
                m.stage.open(),
                "{}: a closed-stage entry landed; verify the install/wire refusals cover it",
                m.name
            );
            // The summary must cite the stage's own results directory.
            let results_dir = match m.stage {
                Stage::Pad => "docs/pad-results/",
                Stage::Recognition => "docs/recognition-results/",
                Stage::Detection | Stage::Landmarks => "docs/",
            };
            assert!(
                m.summary.contains(results_dir),
                "{}: summary must cite its measurement doc under {results_dir}",
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
    fn detector_override_refuses_everything_but_an_open_detection_entry() {
        use super::*;
        assert_eq!(
            detector_override(None).unwrap_err(),
            RecognizerRefusal::NotInCatalog
        );
        let pad = by_name("flir");
        assert_eq!(
            detector_override(pad).unwrap_err(),
            RecognizerRefusal::WrongStage("pad")
        );
        // No catalog entry has the detection stage while it is closed, so
        // the open-stage arm is exercised with a fixture: the wiring is
        // dormant, not absent, and this pins the refusal that keeps it so.
        let mut fixture = ThirdPartyModel {
            name: "fixture-det",
            stage: Stage::Detection,
            file: "fixture-det.tflite",
            url: None,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            license: "fixture",
            provenance: "fixture",
            threshold: 0.55,
            summary: "fixture",
        };
        assert_eq!(
            detector_override(Some(&fixture)).unwrap_err(),
            RecognizerRefusal::StageClosed,
            "a detection entry must be refused while the stage is closed"
        );
        fixture.stage = Stage::Pad;
        assert_eq!(
            detector_override(Some(&fixture)).unwrap_err(),
            RecognizerRefusal::WrongStage("pad")
        );
    }

    #[test]
    fn recognizer_override_refuses_everything_but_an_open_recognition_entry() {
        let fixture = |stage: Stage| ThirdPartyModel {
            name: "fixture",
            stage,
            file: "fixture.onnx",
            url: None,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            license: "fixture",
            provenance: "fixture",
            threshold: 0.6,
            summary: "fixture",
        };
        // Unknown name.
        assert_eq!(
            recognizer_override(None).unwrap_err(),
            RecognizerRefusal::NotInCatalog
        );
        // A PAD entry must never be wired as the recognizer, whatever the
        // settings key says: it is a different kind of model entirely.
        let pad = fixture(Stage::Pad);
        assert_eq!(
            recognizer_override(Some(&pad)).unwrap_err(),
            RecognizerRefusal::WrongStage("pad")
        );
        // The stage is open (flipped 2026-08-05 with the first measured
        // entry), so a recognition entry resolves.
        let rec = fixture(Stage::Recognition);
        assert_eq!(recognizer_override(Some(&rec)).unwrap().name, "fixture");
        // And the real catalog entry resolves end to end.
        assert_eq!(
            recognizer_override(by_name("buffalo")).unwrap().name,
            "buffalo"
        );
        assert_eq!(by_name("buffalo").unwrap().threshold, 0.55);
    }

    #[test]
    fn settings_keys_are_per_stage_and_distinct() {
        assert_eq!(settings_key_for(Stage::Pad), SETTINGS_KEY);
        assert_eq!(
            settings_key_for(Stage::Recognition),
            RECOGNIZER_SETTINGS_KEY
        );
        assert_ne!(SETTINGS_KEY, RECOGNIZER_SETTINGS_KEY);
        // Unwired stages get a key nothing reads, not one of the real ones.
        for s in [Stage::Detection, Stage::Landmarks] {
            assert_ne!(settings_key_for(s), SETTINGS_KEY);
            assert_ne!(settings_key_for(s), RECOGNIZER_SETTINGS_KEY);
        }
    }

    #[test]
    fn open_stages_are_pad_and_recognition_only() {
        // The stage gate for #276/#295: PAD opened first (deny-only),
        // recognition 2026-08-05 with the measured split-source protocol.
        // DETECTION STAYS CLOSED even though its candidate is measured and
        // its wiring exists: the rescue slot feeds the grant path, so an
        // operating-point corpus of genuine and empty frames is not the
        // evidence that stage needs (#299 review). Landmarks stays closed
        // for the cue-feeding reason. Opening a stage is a deliberate act
        // that must change this test alongside the wiring.
        assert!(Stage::Pad.open());
        assert!(Stage::Recognition.open());
        for closed in [Stage::Detection, Stage::Landmarks] {
            assert!(!closed.open(), "{} must stay closed", closed.as_str());
        }
        // as_str is machine-API vocabulary: lowercase, stable.
        for s in [
            Stage::Detection,
            Stage::Landmarks,
            Stage::Recognition,
            Stage::Pad,
        ] {
            assert!(s.as_str().chars().all(|c| c.is_ascii_lowercase()));
        }
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
