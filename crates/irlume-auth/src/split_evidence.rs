// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Test-support evidence scripts for whole-call split rows (ADR-0032 step 5).
//!
//! Whole-daemon tests (`irlume-daemon`, another crate) cannot reach the
//! `#[cfg(test)]` capture-injection twins, so the daemon-reachable seam is
//! thread-local script state consulted inside the production split paths,
//! behind the `test-support` cargo feature that dependents enable under
//! `[dev-dependencies]` only. Shipped builds contain no registry, no install
//! function and no hook behavior: without the feature both consult functions
//! below return `Ok(None)` unconditionally.
//!
//! Scripts carry post-inference-shaped, synthetic-numeric evidence only:
//! embedding batches shaped like the private `CapturedScan` output and
//! `Assessment` values shaped like the unit-test `compatible_pair` helper
//! builds. No face images, frames, models or biometric fixtures are
//! involved. A script never decides an outcome: it supplies evidence content,
//! while routing, admission, leases, revalidation, the grant boundary, grant
//! arms, delivery and accounting all run for real. In particular a scripted
//! `split_pair` provenance bit alone grants nothing; the five live-state
//! conjuncts of `split_grant_refusal` still have to hold.
//!
//! Installation is RAII and thread-bound (mirroring the camera split-trust
//! admission): dropping the guard revokes its own script by id, unwind
//! included. Installations stack newest-last and consultation uses the
//! newest live installation, so an inner install shadows an outer one until
//! its guard drops and reveals it again. Consulting without an installed
//! script falls through to the real path. An installed script with an
//! invalid operation, a key mismatch or no remaining items fails closed;
//! exhausted installations stay registered (failing closed) until their
//! guard drops. Scripts never silently reuse an item or fall back to real
//! capture. Every consumption is recorded for row assertions.
//!
//! PAD-history rule: each scripted consumption primes exactly one full vote
//! window (`VIT_PAD_VOTE_N` copies of the evidence's own score), so the
//! decision window always equals the current evidence regardless of earlier
//! history; appending mirrors real capture, and the existing clear sites
//! run unchanged around scripted attempts.

#[cfg(feature = "test-support")]
use irlume_camera::lease::CameraOperationKind;
use irlume_camera::lease::CameraOperationSession;
use irlume_common::split_key::SplitPairKey;
#[cfg(feature = "test-support")]
use std::cell::RefCell;
#[cfg(feature = "test-support")]
use std::rc::Rc;

/// One synthetic enrollment scan, shaped exactly like the private
/// `CapturedScan` the hook maps it into: unit-vector embeddings plus
/// scalar capture facts. No image content of any kind.
#[derive(Clone, Debug, PartialEq)]
pub struct SyntheticScan {
    /// RGB-face embedding (unit vector in tests, so probes match by cosine).
    pub rgb: Vec<f32>,
    /// IR-face embedding, when the synthetic capture has IR.
    pub ir: Option<Vec<f32>>,
    /// IR center/edge brightness ratio at capture.
    pub center_edge_ratio: f32,
    /// Mean IR face brightness at capture (0-255 grey).
    pub brightness: f32,
    /// Head pitch fraction at capture.
    pub pitch: f32,
    /// Room share of the lit-frame brightness, if observed.
    pub ambient_share: Option<f32>,
}

/// What the evidence log records: script consumptions only, never decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(feature = "test-support")]
pub enum EvidenceEvent {
    /// One capture batch consumed by a split enrollment loop.
    CaptureBatchConsumed { scans: usize },
    /// One scripted assessment consumed by a split authenticate attempt.
    AssessmentConsumed,
}

#[cfg(feature = "test-support")]
use std::collections::VecDeque;

#[cfg(feature = "test-support")]
thread_local! {
    static CAPTURE_SCRIPTS: RefCell<VecDeque<CaptureScript>> = const { RefCell::new(VecDeque::new()) };
    static ASSESSMENT_SCRIPTS: RefCell<VecDeque<AssessmentScript>> = const { RefCell::new(VecDeque::new()) };
    static EVIDENCE_LOG: RefCell<Vec<EvidenceEvent>> = const { RefCell::new(Vec::new()) };
    static NEXT_SCRIPT_ID: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
}

#[cfg(feature = "test-support")]
fn next_script_id() -> u64 {
    NEXT_SCRIPT_ID.with(|next| {
        let id = next.get();
        next.set(id + 1);
        id
    })
}

#[cfg(feature = "test-support")]
struct CaptureScript {
    id: u64,
    key: SplitPairKey,
    batches: std::collections::VecDeque<Vec<SyntheticScan>>,
}

#[cfg(feature = "test-support")]
struct AssessmentScript {
    id: u64,
    key: SplitPairKey,
    items: std::collections::VecDeque<super::Assessment>,
}

/// Installing a script revokes exactly that script on drop, unwind
/// included. The token is `!Send`, so a script cannot move threads;
/// consumption on another thread sees no script and falls through to the
/// real path. Nested installs are independent: dropping one guard removes
/// only its own script wherever it sits in its registry.
#[cfg(feature = "test-support")]
pub struct EvidenceGuard {
    target: GuardTarget,
    _thread: std::marker::PhantomData<Rc<()>>,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardTarget {
    Capture(u64),
    Assessment(u64),
}

#[cfg(feature = "test-support")]
impl EvidenceGuard {
    /// The registry id of the installed script, for asserting removal order
    /// without constructing a lease. Test-support builds only.
    pub fn script_id(&self) -> u64 {
        match self.target {
            GuardTarget::Capture(id) | GuardTarget::Assessment(id) => id,
        }
    }
}

/// The installed script ids in registry order, capture then assessment.
/// Test-support builds only; lets rows assert installation and removal
/// without constructing a camera lease.
#[cfg(feature = "test-support")]
pub fn installed_script_ids() -> (Vec<u64>, Vec<u64>) {
    let capture =
        CAPTURE_SCRIPTS.with(|scripts| scripts.borrow().iter().map(|script| script.id).collect());
    let assessment = ASSESSMENT_SCRIPTS
        .with(|scripts| scripts.borrow().iter().map(|script| script.id).collect());
    (capture, assessment)
}

#[cfg(feature = "test-support")]
impl Drop for EvidenceGuard {
    fn drop(&mut self) {
        match self.target {
            GuardTarget::Capture(id) => {
                CAPTURE_SCRIPTS.with(|scripts| {
                    let mut scripts = scripts.borrow_mut();
                    if let Some(position) = scripts.iter().position(|script| script.id == id) {
                        scripts.remove(position);
                    }
                });
            }
            GuardTarget::Assessment(id) => {
                ASSESSMENT_SCRIPTS.with(|scripts| {
                    let mut scripts = scripts.borrow_mut();
                    if let Some(position) = scripts.iter().position(|script| script.id == id) {
                        scripts.remove(position);
                    }
                });
            }
        }
    }
}

#[cfg(feature = "test-support")]
fn record(event: EvidenceEvent) {
    EVIDENCE_LOG.with(|log| log.borrow_mut().push(event));
}

/// The consumption record for row assertions (leases present, zero opens,
/// script untouched on early refusal).
#[cfg(feature = "test-support")]
pub fn evidence_events() -> Vec<EvidenceEvent> {
    EVIDENCE_LOG.with(|log| log.borrow().clone())
}

/// Cleared by test setup between rows; explicit so no row can mistake a
/// previous row's consumptions for its own.
#[cfg(feature = "test-support")]
pub fn clear_evidence_log() {
    EVIDENCE_LOG.with(|log| log.borrow_mut().clear());
}

/// Install capture batches bound to one retained pair key, one per split
/// enrollment loop call. Consumption requires the installed split key to
/// equal this key. An absent installation falls through to real capture
/// (`Ok(None)`); an exhausted installation stays registered and fails the
/// loop closed until its guard drops.
#[cfg(feature = "test-support")]
pub fn install_capture_script(
    key: SplitPairKey,
    batches: Vec<Vec<SyntheticScan>>,
) -> EvidenceGuard {
    let id = next_script_id();
    CAPTURE_SCRIPTS.with(|scripts| {
        scripts.borrow_mut().push_back(CaptureScript {
            id,
            key,
            batches: batches.into(),
        });
    });
    EvidenceGuard {
        target: GuardTarget::Capture(id),
        _thread: std::marker::PhantomData,
    }
}

/// Install scripted assessments bound to one routed pair key. Consumption
/// requires the installed split key to equal this key. An absent
/// installation falls through (`Ok(None)`); an exhausted installation
/// stays registered and fails closed until its guard drops.
#[cfg(feature = "test-support")]
pub fn install_assessment_script(
    key: SplitPairKey,
    items: Vec<super::Assessment>,
) -> EvidenceGuard {
    let id = next_script_id();
    ASSESSMENT_SCRIPTS.with(|scripts| {
        scripts.borrow_mut().push_back(AssessmentScript {
            id,
            key,
            items: items.into(),
        });
    });
    EvidenceGuard {
        target: GuardTarget::Assessment(id),
        _thread: std::marker::PhantomData,
    }
}

/// A unit-vector synthetic scan: embeddings that probes match by cosine,
/// twin scalar facts, no image content. Mirrors the twin `scan()` shaping
/// without seeded randomness, so published templates match `probe(cosine)`
/// at exactly that cosine.
#[cfg(feature = "test-support")]
pub fn synthetic_scan() -> SyntheticScan {
    let mut unit = vec![0.0; irlume_vision::EMBED_DIM];
    unit[0] = 1.0;
    SyntheticScan {
        rgb: unit.clone(),
        ir: Some(unit),
        center_edge_ratio: 1.3,
        brightness: 90.0,
        pitch: 0.5,
        ambient_share: None,
    }
}

/// A scripted split assessment shaped like the unit-test `compatible_pair`
/// helper builds: probe embeddings at the given cosines, live PAD facts,
/// sequential posture from an explicit synthetic skew, split provenance set.
/// No face content; scores come from the caller's cosines, never a model.
#[cfg(feature = "test-support")]
pub fn scripted_assessment(
    rgb_cosine: f32,
    ir_cosine: f32,
    live: bool,
    skew_ms: u64,
) -> super::Assessment {
    use irlume_liveness::{FaceBox, Verdict};
    let mut probe = [0.0; irlume_vision::EMBED_DIM];
    probe[0] = rgb_cosine;
    probe[1] = (1.0 - rgb_cosine * rgb_cosine).max(0.0).sqrt();
    let mut ir_probe = [0.0; irlume_vision::EMBED_DIM];
    ir_probe[0] = ir_cosine;
    ir_probe[1] = (1.0 - ir_cosine * ir_cosine).max(0.0).sqrt();
    let face = Some(FaceBox {
        cx: 0.5,
        cy: 0.5,
        score: 0.9,
    });
    super::Assessment {
        verdict: if live { Verdict::Live } else { Verdict::Spoof },
        deny_cause: irlume_liveness::DenyCause::Other,
        reason: "synthetic split evidence".into(),
        embedding: Some(probe),
        ir_embedding: Some(ir_probe.to_vec()),
        signals: irlume_liveness::Signals {
            rgb_face: face,
            ir_face: face,
            ir_face_brightness: 35.0,
            ir_center_edge_ratio: 1.3,
            ir_eye_glint: None,
            head_yaw_asym: 0.0,
            head_pitch_frac: 0.5,
            rgb_face_brightness: 130.0,
            rgb_specular_frac: 0.0,
            rgb_moire_score: 0.0,
            ir_ambient: 0.0,
            ir_ceiling_known: false,
            face_frac: 1.0,
            ir_saturated_frac: None,
            ir_persistent_saturated_frac: None,
        },
        ir_center_edge_ratio: 1.3,
        ir_brightness: 35.0,
        ir_ambient_share: None,
        rgb_frame_mean: 120.0,
        shipped_ir_fake: None,
        rgb_pad: super::PadEvidence::Score(0.1),
        ir_pad: super::PadEvidence::Score(0.1),
        sequential_pair: super::pair_admitted_sequentially(
            std::time::Duration::from_millis(skew_ms),
            true,
        ),
        split_pair: true,
    }
}

#[cfg(feature = "test-support")]
fn script_exhausted(what: &str) -> irlume_common::Error {
    irlume_common::Error::Hardware(format!("split evidence script exhausted: no {what} left"))
}

#[cfg(feature = "test-support")]
fn script_mismatch(what: &str) -> irlume_common::Error {
    irlume_common::Error::Hardware(format!("split evidence script refused: {what}"))
}

/// Consult the capture script for a split enrollment loop. No installed
/// script falls through to real capture (`Ok(None)`); an installed script
/// with anything but the installed complete key, a non-split or
/// non-Enrollment operation, or no batch left fails the loop closed.
pub(crate) fn take_capture_batch(
    operation: &CameraOperationSession,
    installed: Option<SplitPairKey>,
) -> irlume_common::Result<Option<Vec<super::CapturedScan>>> {
    #[cfg(not(feature = "test-support"))]
    {
        let _ = (operation, installed);
        Ok(None)
    }
    #[cfg(feature = "test-support")]
    {
        let batch = CAPTURE_SCRIPTS.with(|scripts| {
            let mut scripts = scripts.borrow_mut();
            let Some(script) = scripts.back_mut() else {
                return Ok(None);
            };
            if !(operation.lease().is_split_pair()
                && operation.lease().operation() == CameraOperationKind::Enrollment
                && Some(&script.key) == installed.as_ref())
            {
                return Err(script_mismatch(
                    "capture script needs the installed split key on a live split Enrollment operation",
                ));
            }
            let Some(batch) = script.batches.pop_front() else {
                return Err(script_exhausted("capture batches"));
            };
            Ok(Some(batch))
        })?;
        let Some(batch) = batch else {
            return Ok(None);
        };
        record(EvidenceEvent::CaptureBatchConsumed { scans: batch.len() });
        Ok(Some(
            batch
                .into_iter()
                .map(|scan| super::CapturedScan {
                    rgb: scan.rgb,
                    ir: scan.ir,
                    center_edge_ratio: scan.center_edge_ratio,
                    brightness: scan.brightness,
                    pitch: scan.pitch,
                    ambient_share: scan.ambient_share,
                })
                .collect(),
        ))
    }
}

/// Consult the assessment script for a split authenticate attempt, before
/// any native capture or open. No installed script falls through to the
/// real path (`Ok(None)`); an installed script with anything but the
/// installed complete key, a non-split or non-Authentication operation, or
/// no item left fails closed without consuming. A hit returns evidence for
/// the shared `authenticate_assessment` path (attempt facts, grant
/// boundary, arms, delivery, accounting), skipping capture, detection,
/// inference and materialization, whose outputs the script already carries
/// in post-inference shape.
pub(crate) fn take_assessment(
    operation: &CameraOperationSession,
    installed: Option<SplitPairKey>,
) -> irlume_common::Result<Option<super::Assessment>> {
    #[cfg(not(feature = "test-support"))]
    {
        let _ = (operation, installed);
        Ok(None)
    }
    #[cfg(feature = "test-support")]
    {
        let assessment = ASSESSMENT_SCRIPTS.with(|scripts| {
            let mut scripts = scripts.borrow_mut();
            let Some(script) = scripts.back_mut() else {
                return Ok(None);
            };
            if !(operation.lease().is_split_pair()
                && operation.lease().operation() == CameraOperationKind::Authentication
                && Some(&script.key) == installed.as_ref())
            {
                return Err(script_mismatch(
                    "assessment script needs the installed split key on a live split Authentication operation",
                ));
            }
            let Some(assessment) = script.items.pop_front() else {
                return Err(script_exhausted("assessments"));
            };
            Ok(Some(assessment))
        })?;
        if assessment.is_some() {
            record(EvidenceEvent::AssessmentConsumed);
        }
        Ok(assessment)
    }
}

/// Contract tests for the synthetic builders. Run with the feature:
/// `cargo test -p irlume-auth --features test-support split_evidence`.
/// Without it this module holds no builders and the tests do not compile
/// in, which is itself the isolation property.
#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;

    #[test]
    fn synthetic_scan_is_a_unit_vector_pair_with_twin_scalars() {
        let scan = synthetic_scan();
        assert_eq!(scan.rgb.len(), irlume_vision::EMBED_DIM);
        assert_eq!(scan.rgb[0], 1.0);
        assert!(scan.rgb[1..].iter().all(|v| *v == 0.0));
        assert_eq!(scan.ir, Some(scan.rgb.clone()));
        assert_eq!(
            (
                scan.center_edge_ratio,
                scan.brightness,
                scan.pitch,
                scan.ambient_share
            ),
            (1.3, 90.0, 0.5, None)
        );
    }

    #[test]
    fn scripted_assessment_carries_scores_posture_and_provenance() {
        let assessment = scripted_assessment(0.9, 0.8, true, 500);
        assert!(assessment.split_pair);
        // Below the concurrent ceiling the skew helper alone would not
        // admit sequential posture; split provenance carries it anyway.
        assert!(!assessment.sequential_pair);
        assert!(assessment.sequential_posture());
        let dot = |probe: &[f32]| probe[0];
        assert!((dot(assessment.embedding.as_ref().unwrap()) - 0.9).abs() < 1e-6);
        assert!((dot(assessment.ir_embedding.as_ref().unwrap()) - 0.8).abs() < 1e-6);
    }

    #[test]
    fn install_drop_revokes_without_consuming() {
        clear_evidence_log();
        {
            let _guard = install_capture_script(
                SplitPairKey::parse_canonical(
                    "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
                )
                .unwrap(),
                vec![vec![synthetic_scan()]],
            );
            assert!(evidence_events().is_empty());
        }
        assert!(evidence_events().is_empty());
    }

    #[test]
    fn nested_installs_revoke_only_their_own_script() {
        use irlume_common::split_key::SplitPairKey as Key;
        let key = || {
            Key::parse_canonical(
                "split1;1234:0001:rgb|0000:00:14.0|usb2|8;1234:0002:ir|0000:00:14.0|usb2|5",
            )
            .unwrap()
        };
        clear_evidence_log();
        let outer = install_capture_script(key(), vec![vec![synthetic_scan()]]);
        let inner = install_capture_script(key(), vec![vec![synthetic_scan()]]);
        assert_eq!(
            installed_script_ids(),
            (vec![outer.script_id(), inner.script_id()], vec![]),
            "installations stack in order"
        );
        // Dropping the non-top guard removes only its own script while the
        // newer installation stays live.
        drop(outer);
        assert_eq!(
            installed_script_ids(),
            (vec![inner.script_id()], vec![]),
            "non-top removal reveals the newer script"
        );
        drop(inner);
        assert_eq!(
            installed_script_ids(),
            (vec![], vec![]),
            "all guards dropped leaves no scripts"
        );
        assert!(evidence_events().is_empty());
    }
}
