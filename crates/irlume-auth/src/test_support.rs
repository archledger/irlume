// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Current-thread assessed inputs for split request tests. This fixture grants
//! no camera admission and decides no outcome. Its caller must hold the real
//! retained split entry and operation; ordinary and diagnostic capture cannot
//! use it. Raw PAD evidence is not a prequalified vote or grant.

use crate::{Assessment, Engine, PadEvidence, Signals, Verdict};
use irlume_camera::contracts::StreamRole;
use irlume_camera::lease::{
    split_trust_admitted, CameraOperationKind, CameraOperationSession, SplitLeaseRequest,
};
use irlume_common::{Error, Result};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

/// Raw output of one PAD assessment. Pending belongs to real vote qualification.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PadInput {
    /// No PAD assessment was performed for this modality.
    NotApplicable,
    /// The required model was unavailable.
    Unavailable,
    /// Inference failed or returned a nonfinite value.
    InferenceFailed,
    /// Raw model score, before deny-only settlement and vote qualification.
    Score(f32),
}

impl PadInput {
    fn evidence(self) -> PadEvidence {
        match self {
            Self::NotApplicable => PadEvidence::NotApplicable,
            Self::Unavailable => PadEvidence::Unavailable,
            Self::InferenceFailed => PadEvidence::InferenceFailed,
            Self::Score(score) if score.is_finite() => PadEvidence::Score(score),
            Self::Score(_) => PadEvidence::InferenceFailed,
        }
    }
}

/// Make an empty, non-Live assessment with raw private PAD fields. Tests must
/// explicitly supply synthetic public signals, embeddings and provenance.
/// Does not accumulate votes, load an enrollment or decide an outcome.
#[must_use]
pub fn assessment(rgb_pad: PadInput, ir_pad: PadInput) -> Assessment {
    let ir_pad = ir_pad.evidence();
    Assessment {
        verdict: Verdict::Uncertain,
        reason: "empty synthetic assessment".into(),
        deny_cause: irlume_liveness::DenyCause::Other,
        embedding: None,
        ir_embedding: None,
        signals: Signals::default(),
        ir_center_edge_ratio: 0.0,
        ir_brightness: 0.0,
        ir_ambient_share: None,
        rgb_frame_mean: 0.0,
        shipped_ir_fake: match ir_pad {
            PadEvidence::Score(score) => Some(score),
            _ => None,
        },
        rgb_pad: rgb_pad.evidence(),
        ir_pad,
        sequential_pair: false,
        split_pair: false,
    }
}

/// Immutable context of one attempted callback, from the retained real entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssessmentContext {
    /// Both original sides, supervisor and publication revision.
    pub expected: SplitLeaseRequest,
    /// The declared and independently admitted trust kind.
    pub kind: CameraOperationKind,
    /// Zero-based callback index; never restarted by an authentication retry.
    pub index: usize,
}

type Assessor = dyn FnMut(&AssessmentContext) -> Result<Assessment>;

struct Fixture {
    expected: SplitLeaseRequest,
    kind: CameraOperationKind,
    assess: RefCell<Box<Assessor>>,
    calls: Cell<usize>,
    contexts: RefCell<Vec<AssessmentContext>>,
}

thread_local! {
    static INSTALLED: RefCell<Option<Rc<Fixture>>> = const { RefCell::new(None) };
}

/// Removes its current-thread fixture on drop, including unwind. The owned Rc
/// makes this guard neither Send nor Sync. Install on the Engine worker thread.
#[must_use = "the fixture is removed when this guard drops"]
pub struct Guard {
    fixture: Rc<Fixture>,
}

impl Guard {
    /// Install one callback scoped to an exact split expectation and trust kind.
    /// The camera fixture must independently admit that kind on this thread.
    /// Callback errors, including explicit script exhaustion, never fall back
    /// to a camera or reuse an earlier result. The callback supplies no Outcome.
    ///
    /// # Errors
    /// Refuses non-trust or unadmitted kinds, nested installation, a borrowed
    /// fixture slot or unavailable thread-local storage.
    pub fn install(
        expected: SplitLeaseRequest,
        kind: CameraOperationKind,
        assess: impl FnMut(&AssessmentContext) -> Result<Assessment> + 'static,
    ) -> Result<Self> {
        if !matches!(
            kind,
            CameraOperationKind::Enrollment | CameraOperationKind::Authentication
        ) || !split_trust_admitted(kind)
        {
            return Err(refusal(
                "assessment fixture needs independently admitted split trust",
            ));
        }
        let fixture = Rc::new(Fixture {
            expected,
            kind,
            assess: RefCell::new(Box::new(assess)),
            calls: Cell::new(0),
            contexts: RefCell::new(Vec::new()),
        });
        INSTALLED
            .try_with(|slot| {
                let mut slot = slot
                    .try_borrow_mut()
                    .map_err(|_| refusal("assessment fixture slot is borrowed"))?;
                if slot.is_some() {
                    return Err(refusal("an assessment fixture is already installed"));
                }
                *slot = Some(Rc::clone(&fixture));
                Ok(())
            })
            .map_err(|_| refusal("assessment fixture thread-local storage is unavailable"))??;
        Ok(Self { fixture })
    }

    /// Number of callback invocations, including ones returning an error.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.fixture.calls.get()
    }

    /// Original retained context for each callback; contains no assessed data.
    ///
    /// # Panics
    /// Panics if internal observation storage is still mutably borrowed.
    #[must_use]
    pub fn contexts(&self) -> Vec<AssessmentContext> {
        self.fixture.contexts.borrow().clone()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = INSTALLED.try_with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                if slot
                    .as_ref()
                    .is_some_and(|installed| Rc::ptr_eq(installed, &self.fixture))
                {
                    *slot = None;
                }
            }
        });
    }
}

fn refusal(reason: &str) -> Error {
    Error::Hardware(reason.into())
}

fn installed() -> Result<Option<Rc<Fixture>>> {
    INSTALLED
        .try_with(|slot| {
            slot.try_borrow()
                .map(|slot| slot.as_ref().map(Rc::clone))
                .map_err(|_| refusal("assessment fixture slot is borrowed"))
        })
        .map_err(|_| refusal("assessment fixture thread-local storage is unavailable"))?
}

fn validate(fixture: &Fixture, engine: &Engine, operation: &CameraOperationSession) -> Result<()> {
    let (expected, kind) = engine
        .retained_split_assessment_context()
        .ok_or_else(|| refusal("assessment fixture has no active retained split entry"))?;
    if expected != fixture.expected
        || kind != fixture.kind
        || !split_trust_admitted(kind)
        || !operation.lease().is_split_pair()
        || operation.lease().operation() != kind
    {
        return Err(refusal(
            "assessment fixture does not match the original split context",
        ));
    }
    operation
        .lease()
        .validate()
        .map_err(crate::lease_unavailable)?;
    for (side, role) in [
        (&expected.rgb, StreamRole::Rgb),
        (&expected.ir, StreamRole::Ir),
    ] {
        let binding = operation
            .lease()
            .frame_binding(&side.endpoint, role)
            .map_err(crate::lease_unavailable)?;
        if binding.camera_instance_id().as_str() != side.instance_id
            || binding.generation().get() != side.generation
        {
            return Err(refusal(
                "assessment fixture operation holds another incarnation",
            ));
        }
    }
    Ok(())
}

/// Sample the current-thread fixture under the original real split operation.
/// This is an assessment-only boundary for fixture controls; it decides nothing
/// and does not settle PAD scores. No installed fixture returns None. Every
/// installed-fixture failure returns Some(Err), with no physical fallback.
///
/// # Errors
/// Refuses a mismatched or closed retained entry, stale/wrong lease, reentrant
/// callback, callback error/exhaustion, or a fixture removed during the callback.
///
/// # Panics
/// Propagates a panic from the installed callback; its caller-owned Guard still
/// removes the fixture when that scope unwinds.
pub fn assess_installed(
    engine: &Engine,
    operation: &CameraOperationSession,
) -> Option<Result<Assessment>> {
    let fixture = match installed() {
        Ok(Some(fixture)) => fixture,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    Some((|| {
        validate(&fixture, engine, operation)?;
        let mut assess = fixture
            .assess
            .try_borrow_mut()
            .map_err(|_| refusal("assessment fixture callback is already running"))?;
        let index = fixture.calls.get();
        let next = index
            .checked_add(1)
            .ok_or_else(|| refusal("assessment fixture call count exhausted"))?;
        let context = AssessmentContext {
            expected: fixture.expected.clone(),
            kind: fixture.kind,
            index,
        };
        fixture
            .contexts
            .try_borrow_mut()
            .map_err(|_| refusal("assessment fixture observations are borrowed"))?
            .push(context.clone());
        fixture.calls.set(next);
        let result = assess(&context);
        drop(assess);
        if !installed()?
            .as_ref()
            .is_some_and(|current| Rc::ptr_eq(current, &fixture))
        {
            return Err(refusal(
                "assessment fixture was removed during its callback",
            ));
        }
        validate(&fixture, engine, operation)?;
        result
    })())
}

impl Engine {
    /// Fixture-specific orchestration stays with its feature owner. The real
    /// qualification/finish boundary is unchanged; None leaves the ordinary
    /// returning capture-owner path intact, including its held-pair flag.
    pub(super) fn fixture_authentication(
        &mut self,
        enrollment: &irlume_core::storage::Enrollment,
        purpose: crate::AuthenticationPurpose,
        service: Option<&str>,
        operation: &CameraOperationSession,
        held_pair_failed: Option<&mut bool>,
        diagnostics: &dyn irlume_common::diagnostics::DiagnosticSink,
    ) -> Option<Result<crate::Outcome>> {
        let prepared = match self.fixture_assessment(operation) {
            Ok(Some(assessment)) => self
                .prepare_assessed_pair_authentication(assessment)
                .map_err(crate::CapturePathError::from),
            Err(error) => Err(crate::CapturePathError::from(error)),
            Ok(None) => return None,
        };
        if prepared.is_ok() {
            self.arm_finalization();
        }
        Some(self.finish_pair_authentication(
            enrollment,
            purpose,
            service,
            prepared,
            held_pair_failed,
            diagnostics,
        ))
    }

    /// Assessment substitution only. The enclosing real capture loop owns the
    /// operation and its cancellation/retry policy. No account or machine
    /// authority is refreshed here; drift reaches the real late boundaries.
    pub(super) fn fixture_assessment(
        &mut self,
        operation: &CameraOperationSession,
    ) -> Result<Option<Assessment>> {
        self.check_request_active()?;
        let Some(result) = assess_installed(self, operation) else {
            return Ok(None);
        };
        let mut assessment = result?;
        self.check_request_active()?;
        assessment.shipped_ir_fake = match assessment.ir_pad {
            PadEvidence::Score(score) => Some(score),
            _ => None,
        };
        let (verdict, reason, cause) = crate::settle_ir_pad(
            assessment.verdict,
            assessment.reason,
            assessment.deny_cause,
            assessment.shipped_ir_fake,
        );
        // Production evaluates the RGB cue only for a post-IR-PAD Live RGB
        // face. A scripted non-Live/no-face sample cannot contribute a vote.
        if verdict != Verdict::Live || assessment.signals.rgb_face.is_none() {
            assessment.rgb_pad = PadEvidence::NotApplicable;
        }
        (assessment.verdict, assessment.reason, assessment.deny_cause) =
            self.settle_rgb_pad(verdict, reason, cause, assessment.rgb_pad);
        Ok(Some(assessment))
    }
}
