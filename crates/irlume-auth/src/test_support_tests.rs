// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// These real-entry consumers deliberately precede the assessment interception.
// The validator must witness their runtime failures before wiring the seam.

use super::*;
use crate::test_support::{assess_installed, assessment, Guard as AssessmentGuard, PadInput};
use irlume_camera::lease::{CameraOperationKind, SplitLeaseRequest};
use irlume_camera::test_support::{Call, Camera, Endpoint, Guard as CameraGuard};
use irlume_common::split_key::SplitDomain;
use irlume_common::split_schema::{AuthorizationRecord, SideFields};
use std::{cell::Cell, ffi::OsString, path::PathBuf, rc::Rc, time::Duration};

const USER: &str = "split-assessment-support";
const RGB: &str = "/dev/irlume-assessment-fixture-rgb";
const IR: &str = "/dev/irlume-assessment-fixture-ir";

struct Fixture {
    dir: PathBuf,
    saved: Vec<(&'static str, Option<OsString>)>,
    camera: CameraGuard,
    _no_tpm: irlume_core::template_key::test_support::TpmPresence,
}

impl Fixture {
    fn new() -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let dir = std::env::temp_dir().join(format!(
            "irlume-assessment-support-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        assert!(!dir.exists(), "fixture directory already exists");
        std::fs::create_dir_all(&dir).unwrap();
        let keys = [
            "IRLUME_CONFIG_DIR",
            "IRLUME_STATE_DIR",
            "IRLUME_METHOD_CONF",
            "IRLUME_TEMPLATE_KEY_DIR",
            "IRLUME_TCTI",
            "IRLUME_RGB_DEVICE",
            "IRLUME_IR_DEVICE",
            "IRLUME_FORCE_NO_IR",
            "IRLUME_CAMERA_REQUIRE_FIXED",
            "IRLUME_FORBID_EXTERNAL_CAMERAS",
            "IRLUME_GRACE_MS",
            "IRLUME_SEQUENTIAL_CAPTURE",
        ];
        let saved = keys
            .iter()
            .map(|&key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_METHOD_CONF", dir.join("method.conf"));
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", dir.join("template-keys"));
        std::env::set_var("IRLUME_TCTI", "device:/nonexistent/irlume-assessment-tpm");
        for key in &keys[5..] {
            std::env::remove_var(key);
        }
        let camera = CameraGuard::install(&[
            Self::camera("rgb", "1234:0001:rgb", 8, RGB, *b"YUYV"),
            Self::camera("ir", "1234:0002:ir", 5, IR, *b"GREY"),
        ])
        .unwrap();
        let side = |identity: &str, path: &str, port| SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::Usb2,
            ports: vec![port],
        };
        irlume_common::split_publish::publish_split(
            &[AuthorizationRecord {
                rgb: side("1234:0001:rgb", RGB, 8),
                ir: side("1234:0002:ir", IR, 5),
            }],
            None,
        )
        .unwrap();
        Self {
            dir,
            saved,
            camera,
            _no_tpm: no_tpm,
        }
    }

    fn camera(name: &str, identity: &str, port: u8, path: &str, format: [u8; 4]) -> Camera {
        Camera {
            topology: format!("/devices/assessment-support/{name}"),
            identity: identity.into(),
            fixed: true,
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::Usb2,
            ports: vec![port],
            endpoints: vec![Endpoint {
                path: path.into(),
                formats: vec![format],
            }],
        }
    }

    fn expected(&self) -> SplitLeaseRequest {
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let irlume_common::split_publish::SplitReadState::Valid { records, .. } = snapshot.split()
        else {
            panic!("valid fixture publication")
        };
        irlume_camera::connected_pairs_with_split(records)
            .split_pairs
            .remove(0)
            .lease_request()
    }

    fn choice(
        &self,
    ) -> (
        irlume_common::split_wire::SplitMutationGuard,
        irlume_common::split_publish::Published,
    ) {
        let expected = self.expected();
        let side =
            |side: irlume_camera::SplitSideExpectation| irlume_common::split_wire::SplitSideGuard {
                instance_id: side.instance_id,
                generation: side.generation,
                endpoint: side.endpoint,
            };
        let snapshot = irlume_common::split_publish::read_camera_selection();
        let irlume_common::config::SplitConfObservation::Reference {
            generation, digest, ..
        } = snapshot.observation().split.clone()
        else {
            panic!("fixture publication reference")
        };
        (
            irlume_common::split_wire::SplitMutationGuard {
                supervisor_id: expected.supervisor_id,
                revision: expected.revision,
                rgb: side(expected.rgb),
                ir: side(expected.ir),
            },
            irlume_common::split_publish::Published { generation, digest },
        )
    }

    fn primary(&self) -> PathBuf {
        self.dir.join(format!("{USER}.json"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sample() -> Assessment {
    sample_with_pad(PadInput::Score(0.1), PadInput::Score(0.1))
}

fn sample_with_pad(rgb: PadInput, ir: PadInput) -> Assessment {
    let mut sample = assessment(rgb, ir);
    let mut direction = [0.0; EMBED_DIM];
    direction[0] = 1.0;
    sample.embedding = Some(direction);
    sample.ir_embedding = Some(direction.to_vec());
    sample.verdict = Verdict::Live;
    sample.reason = "synthetic assessed sample".into();
    sample.signals.rgb_face = Some(irlume_liveness::FaceBox {
        cx: 0.5,
        cy: 0.5,
        score: 0.9,
    });
    sample.signals.ir_face = sample.signals.rgb_face;
    sample.signals.rgb_face_brightness = 130.0;
    sample.ir_brightness = 90.0;
    sample.ir_center_edge_ratio = 1.3;
    sample.rgb_frame_mean = 120.0;
    sample.split_pair = true;
    sample.sequential_pair = false;
    sample
}

#[test]
fn whole_entry_enrollment_publishes_from_scripted_assessments() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new();
    let _admission = fixture
        .camera
        .admit_split_trust(&[CameraOperationKind::Enrollment]);
    let counts = fixture.camera.lease_counts_observer();
    let script = AssessmentGuard::install(
        fixture.expected(),
        CameraOperationKind::Enrollment,
        move |context| {
            assert!(
                context.index < 5,
                "one admitted scan needs only its five PAD samples"
            );
            assert_eq!(counts(), (2, 0));
            Ok(sample())
        },
    )
    .unwrap();
    let (guard, publication) = fixture.choice();
    let (result, binding) = {
        let mut request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        let binding = request.prepared_enrollment_binding().unwrap();
        (
            request.enroll_split_prepared(USER, Some("Synthetic Profile".into()), 1, false, &()),
            binding,
        )
    };
    let restored = shared.engine.camera_selection.is_none();
    drop(shared);
    assert!(
        result.is_ok(),
        "whole enrollment entry failed; error={:?}; script calls={}",
        result.as_ref().err().map(ToString::to_string),
        script.calls()
    );
    assert_eq!(script.calls(), 5);
    let stored = irlume_core::storage::load_unmoved(USER).unwrap().unwrap();
    assert_eq!(stored.camera_binding, Some(binding));
    assert_eq!(stored.profiles.len(), 1);
    assert_eq!(stored.profiles[0].scans.len(), 1);
    assert_eq!(
        fixture.camera.calls(),
        vec![Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind: CameraOperationKind::Enrollment,
        }]
    );
    assert_eq!(fixture.camera.lease_counts_observer()(), (0, 0));
    assert!(restored);
}

#[test]
fn whole_entry_authentication_grants_after_real_pad_retries() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new();
    let (guard, publication) = fixture.choice();
    let binding = {
        let request = shared
            .engine
            .prepare_split_enrollment_camera(&guard, &publication)
            .unwrap();
        request.prepared_enrollment_binding().unwrap()
    };
    let mut enrollment = Enrollment::new(USER);
    let mut scan = scan512(1, true, None);
    scan.rgb = sample().embedding.unwrap().to_vec();
    scan.ir = Some(scan.rgb.clone());
    scan.embed_space = Some(shared.engine.embed_space().into());
    scan.ir_space = Some(shared.engine.ir_space().into());
    enrollment.camera_binding = Some(binding);
    enrollment.profiles.push(FaceProfile {
        name: "Synthetic Profile".into(),
        scans: vec![scan],
        ir_calib: None,
        ir_calibs: Default::default(),
    });
    std::fs::write(fixture.primary(), serde_json::to_vec(&enrollment).unwrap()).unwrap();
    let _admission = fixture
        .camera
        .admit_split_trust(&[CameraOperationKind::Authentication]);
    let counts = fixture.camera.lease_counts_observer();
    let script = AssessmentGuard::install(
        fixture.expected(),
        CameraOperationKind::Authentication,
        move |context| {
            assert!(
                context.index < 5,
                "the real fifth PAD sample settles the match"
            );
            assert_eq!(counts(), (2, 0));
            Ok(sample())
        },
    )
    .unwrap();
    let result = shared
        .engine
        .authenticate_for_in_window_with_policy_preparing_delivering(
            USER,
            Some("login"),
            AuthenticationPurpose::Verify,
            AuthenticationWindow::new(15_000),
            irlume_common::config::FaceSensorPolicy::Dual,
            &(),
            &mut |_, _| Ok(()),
            &mut |_, _| {},
        );
    let restored = shared.engine.camera_selection.is_none();
    drop(shared);
    assert!(
        matches!(result, Ok(ref outcome) if outcome.granted && outcome.reason.contains("ir-fallback")),
        "whole authentication entry did not grant through IR identity; error={:?}; script calls={}",
        result.as_ref().err().map(ToString::to_string),
        script.calls()
    );
    assert_eq!(script.calls(), 5);
    assert_eq!(
        fixture.camera.calls(),
        vec![Call::Lease {
            endpoints: vec![RGB.into(), IR.into()],
            kind: CameraOperationKind::Authentication,
        }]
    );
    assert_eq!(fixture.camera.lease_counts_observer()(), (0, 0));
    assert!(restored);
}

#[test]
fn support_factory_starts_empty_and_nonfinite_pad_is_failed() {
    let sample = assessment(PadInput::Score(f32::NAN), PadInput::Score(f32::INFINITY));
    assert_eq!(sample.verdict, Verdict::Uncertain);
    assert!(sample.embedding.is_none() && sample.ir_embedding.is_none());
    assert!(!sample.split_pair && !sample.sequential_pair);
    assert_eq!(sample.rgb_pad, PadEvidence::InferenceFailed);
    assert_eq!(sample.ir_pad, PadEvidence::InferenceFailed);
}

#[test]
fn support_guard_rejects_nested_install_and_closes_on_unwind_and_other_threads() {
    let _env = env_guard();
    let _shared = shared();
    let fixture = Fixture::new();
    let expected = fixture.expected();
    let kind = CameraOperationKind::Enrollment;
    assert!(AssessmentGuard::install(expected.clone(), kind, |_| Ok(sample())).is_err());
    let _admission = fixture.camera.admit_split_trust(&[kind]);
    let guard = AssessmentGuard::install(expected.clone(), kind, |_| Ok(sample())).unwrap();
    assert!(AssessmentGuard::install(expected.clone(), kind, |_| Ok(sample())).is_err());
    let other_expected = expected.clone();
    std::thread::spawn(move || {
        assert!(AssessmentGuard::install(other_expected, kind, |_| Ok(sample())).is_err());
        let camera = CameraGuard::install(&[
            Fixture::camera("rgb", "1234:0001:rgb", 8, RGB, *b"YUYV"),
            Fixture::camera("ir", "1234:0002:ir", 5, IR, *b"GREY"),
        ])
        .unwrap();
        let _admission = camera.admit_split_trust(&[kind]);
        // The parent has a live fixture, but this admitted thread's slot is empty.
        let _guard =
            AssessmentGuard::install(expected_for_thread(), kind, |_| Ok(sample())).unwrap();
    })
    .join()
    .unwrap();
    drop(guard);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = AssessmentGuard::install(expected.clone(), kind, |_| Ok(sample())).unwrap();
        panic!("synthetic fixture unwind");
    }))
    .is_err());
    let _guard = AssessmentGuard::install(expected, kind, |_| Ok(sample())).unwrap();
}

fn expected_for_thread() -> SplitLeaseRequest {
    let side = |identity: &str, endpoint: &str, port| SideFields {
        identity: identity.into(),
        path: endpoint.into(),
        controller: "0000:00:14.0".into(),
        domain: SplitDomain::Usb2,
        ports: vec![port],
    };
    irlume_camera::connected_pairs_with_split(&[AuthorizationRecord {
        rgb: side("1234:0001:rgb", RGB, 8),
        ir: side("1234:0002:ir", IR, 5),
    }])
    .split_pairs
    .remove(0)
    .lease_request()
}

#[test]
fn support_boundary_requires_original_context_and_propagates_script_exhaustion() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new();
    let expected = fixture.expected();
    let kind = CameraOperationKind::Enrollment;
    let _admission = fixture.camera.admit_split_trust(&[kind]);
    let (guard, publication) = fixture.choice();
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    request
        .enter_split_trust(crate::request_preparation::SplitTrustEntry::Enrollment)
        .unwrap();
    let operation = request
        .acquire_account_camera(&[RGB, IR], kind, Duration::from_secs(1))
        .unwrap();
    let mut wrong = expected.clone();
    wrong.ir.generation += 1;
    let script =
        AssessmentGuard::install(wrong, kind, |_| panic!("wrong context called script")).unwrap();
    assert!(assess_installed(&request, &operation).unwrap().is_err());
    assert_eq!(script.calls(), 0);
    drop(script);
    let used = Rc::new(Cell::new(false));
    let callback_used = Rc::clone(&used);
    let script = AssessmentGuard::install(expected.clone(), kind, move |_| {
        if callback_used.replace(true) {
            Err(irlume_common::Error::Hardware(
                "assessment script exhausted".into(),
            ))
        } else {
            Ok(sample())
        }
    })
    .unwrap();
    assert!(assess_installed(&request, &operation).unwrap().is_ok());
    let error = assess_installed(&request, &operation)
        .unwrap()
        .err()
        .unwrap();
    assert!(error.to_string().contains("script exhausted"));
    assert_eq!(script.calls(), 2);
    assert_eq!(script.contexts()[0].expected, expected);
    drop(script);
    assert!(assess_installed(&request, &operation).is_none());
    request.leave_split_trust();
}

fn under_enrollment_operation(
    test: impl FnOnce(&Fixture, &mut Engine, Rc<irlume_camera::lease::CameraOperationSession>),
) {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new();
    let kind = CameraOperationKind::Enrollment;
    let _admission = fixture.camera.admit_split_trust(&[kind]);
    let (guard, publication) = fixture.choice();
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    request
        .enter_split_trust(crate::request_preparation::SplitTrustEntry::Enrollment)
        .unwrap();
    let operation = Rc::new(
        request
            .acquire_account_camera(&[RGB, IR], kind, Duration::from_secs(1))
            .unwrap(),
    );
    test(&fixture, &mut request, Rc::clone(&operation));
    request.leave_split_trust();
    drop(operation);
    drop(request);
    assert_eq!(fixture.camera.lease_counts_observer()(), (0, 0));
    assert!(shared.engine.camera_selection.is_none());
}

#[test]
fn support_evaluated_callback_error_and_panic_remove_guard_without_fallback() {
    under_enrollment_operation(|fixture, request, operation| {
        let script =
            AssessmentGuard::install(fixture.expected(), CameraOperationKind::Enrollment, |_| {
                Err(irlume_common::Error::Hardware(
                    "synthetic callback failure".into(),
                ))
            })
            .unwrap();
        let result = operation
            .run(|| assess_installed(request, &operation))
            .unwrap()
            .unwrap();
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("synthetic callback failure"));
        assert_eq!(script.calls(), 1);
        drop(script);
        assert!(assess_installed(request, &operation).is_none());
        let called = Rc::new(Cell::new(0));
        let callback_called = Rc::clone(&called);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _script = AssessmentGuard::install(
                fixture.expected(),
                CameraOperationKind::Enrollment,
                move |_| {
                    callback_called.set(callback_called.get() + 1);
                    panic!("synthetic assessed callback panic");
                },
            )
            .unwrap();
            let _ = operation.run(|| assess_installed(request, &operation));
        }));
        assert!(panicked.is_err());
        assert_eq!(
            called.get(),
            1,
            "the panic came from the evaluated callback"
        );
        assert!(assess_installed(request, &operation).is_none());
        let script =
            AssessmentGuard::install(fixture.expected(), CameraOperationKind::Enrollment, |_| {
                Ok(sample())
            })
            .unwrap();
        assert!(operation
            .run(|| assess_installed(request, &operation))
            .unwrap()
            .unwrap()
            .is_ok());
        assert_eq!(script.calls(), 1);
        assert_eq!(fixture.camera.lease_counts_observer()(), (2, 0));
        assert!(fixture
            .camera
            .calls()
            .iter()
            .all(|call| matches!(call, Call::Lease { .. })));
    });
}

#[test]
fn support_evaluated_callback_reentry_is_refused_before_another_sample() {
    under_enrollment_operation(|fixture, request, operation| {
        // Own a second real Engine in the callback so no borrowed Engine or
        // forged operation escapes into the 'static script. Both evaluators
        // use the one actual lease; the nested entry acquires no second lease.
        let mut nested_engine = Engine::load(
            &model_path("face_detection_yunet_2023mar.onnx"),
            &model_path("glintr100.onnx"),
        )
        .unwrap();
        let (guard, publication) = fixture.choice();
        let callback_operation = Rc::clone(&operation);
        let script = AssessmentGuard::install(
            fixture.expected(),
            CameraOperationKind::Enrollment,
            move |_| {
                let mut nested =
                    nested_engine.prepare_split_enrollment_camera(&guard, &publication)?;
                nested
                    .enter_split_trust(crate::request_preparation::SplitTrustEntry::Enrollment)?;
                let result =
                    assess_installed(&nested, &callback_operation).expect("installed fixture");
                nested.leave_split_trust();
                result
            },
        )
        .unwrap();
        let result = operation
            .run(|| assess_installed(request, &operation))
            .unwrap()
            .unwrap();
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("callback is already running"));
        assert_eq!(script.calls(), 1);
        assert_eq!(fixture.camera.lease_counts_observer()(), (2, 0));
    });
}

#[test]
fn support_admission_loss_under_the_held_lease_consumes_no_sample() {
    let _env = env_guard();
    let mut shared = shared();
    let fixture = Fixture::new();
    let kind = CameraOperationKind::Enrollment;
    let admission = fixture.camera.admit_split_trust(&[kind]);
    let script = AssessmentGuard::install(fixture.expected(), kind, |_| {
        panic!("lost admission called script")
    })
    .unwrap();
    let (guard, publication) = fixture.choice();
    let mut request = shared
        .engine
        .prepare_split_enrollment_camera(&guard, &publication)
        .unwrap();
    request
        .enter_split_trust(crate::request_preparation::SplitTrustEntry::Enrollment)
        .unwrap();
    let operation = request
        .acquire_account_camera(&[RGB, IR], kind, Duration::from_secs(1))
        .unwrap();
    assert_eq!(fixture.camera.lease_counts_observer()(), (2, 0));
    drop(admission);
    assert!(operation
        .run(|| assess_installed(&request, &operation))
        .unwrap()
        .unwrap()
        .is_err());
    assert_eq!(script.calls(), 0);
    request.leave_split_trust();
    drop(operation);
    drop(request);
    assert_eq!(fixture.camera.lease_counts_observer()(), (0, 0));
}

#[test]
fn support_endpoint_invalidation_during_callback_refuses_both_sides() {
    for endpoint in [RGB, IR] {
        under_enrollment_operation(|fixture, request, operation| {
            let invalidate = fixture.camera.endpoint_invalidation_observer(endpoint);
            let script = AssessmentGuard::install(
                fixture.expected(),
                CameraOperationKind::Enrollment,
                move |_| {
                    invalidate();
                    Ok(sample())
                },
            )
            .unwrap();
            let mut inner_refused = false;
            let result = operation.run(|| {
                let inner = assess_installed(request, &operation).expect("installed fixture");
                inner_refused = inner.is_err();
                assert!(
                    inner_refused,
                    "the fixture post-check must refuse before the operation returns"
                );
                inner
            });
            // The fixture's post-check and the real operation's post-check both
            // refuse the invalid original side. Neither can yield a sample.
            assert!(result.is_err());
            assert!(
                inner_refused,
                "the operation post-check must not mask a missing fixture check"
            );
            assert_eq!(script.calls(), 1);
            assert!(fixture
                .camera
                .calls()
                .iter()
                .all(|call| matches!(call, Call::Lease { .. })));
        });
    }
}

#[test]
fn pad_ir_settlement_preserves_the_original_deny_only_truth_table() {
    use irlume_liveness::DenyCause;
    for verdict in [Verdict::Live, Verdict::Uncertain, Verdict::Spoof] {
        for score in [
            None,
            Some(IR_PAD_THRESHOLD - 0.01),
            Some(IR_PAD_THRESHOLD),
            Some(IR_PAD_THRESHOLD + 0.01),
            Some(f32::NAN),
            Some(f32::INFINITY),
            Some(f32::NEG_INFINITY),
        ] {
            let expected_downgrade =
                verdict == Verdict::Live && matches!(score, Some(p) if p >= IR_PAD_THRESHOLD);
            let (actual, reason, cause) = settle_ir_pad(
                verdict,
                "original decision".into(),
                DenyCause::NoIrFace,
                score,
            );
            assert_eq!(
                actual,
                if expected_downgrade {
                    Verdict::Spoof
                } else {
                    verdict
                }
            );
            assert_eq!(
                reason,
                if expected_downgrade {
                    "IR PAD cue flags a spoof; use your password"
                } else {
                    "original decision"
                }
            );
            assert_eq!(
                cause,
                if expected_downgrade {
                    DenyCause::Other
                } else {
                    DenyCause::NoIrFace
                }
            );
        }
    }
}

#[test]
fn pad_rgb_settlement_preserves_the_original_vote_truth_table() {
    use irlume_liveness::DenyCause;
    let _env = env_guard();
    let mut shared = shared();
    for verdict in [Verdict::Live, Verdict::Uncertain, Verdict::Spoof] {
        for prefix in [0, 3, 4] {
            for pad in [
                PadEvidence::NotApplicable,
                PadEvidence::Unavailable,
                PadEvidence::InferenceFailed,
                PadEvidence::Pending,
                PadEvidence::Score(0.0),
                PadEvidence::Score(VIT_PAD_THRESHOLD),
                PadEvidence::Score(1.0),
                PadEvidence::Score(f32::NAN),
                PadEvidence::Score(f32::INFINITY),
            ] {
                shared.engine.vit_scores.clear();
                for _ in 0..prefix {
                    assert!(!shared.engine.vit_pad_votes_deny(VIT_PAD_THRESHOLD));
                }
                let finite_score = matches!(pad, PadEvidence::Score(p) if p.is_finite());
                // Four threshold-equal preceding scores make the first full
                // median deny for any finite fifth score. Earlier windows abstain.
                let deny = finite_score && prefix == 4;
                let (actual, reason, cause) = shared.engine.settle_rgb_pad(
                    verdict,
                    "original decision".into(),
                    DenyCause::ExposureUnmeasurable,
                    pad,
                );
                assert_eq!(actual, if deny { Verdict::Spoof } else { verdict });
                assert_eq!(
                    reason,
                    if deny {
                        "RGB PAD cue flags a spoof; use your password"
                    } else {
                        "original decision"
                    }
                );
                assert_eq!(
                    cause,
                    if deny {
                        DenyCause::Other
                    } else {
                        DenyCause::ExposureUnmeasurable
                    }
                );
                assert_eq!(
                    shared.engine.vit_scores.len(),
                    prefix + usize::from(finite_score)
                );
            }
        }
    }
    shared.engine.vit_scores.clear();
}

#[test]
fn support_raw_pad_samples_require_five_votes_and_fail_closed_on_model_errors() {
    under_enrollment_operation(|fixture, request, operation| {
        request.vit_scores.clear();
        let script =
            AssessmentGuard::install(fixture.expected(), CameraOperationKind::Enrollment, |_| {
                Ok(sample())
            })
            .unwrap();
        for index in 0..5 {
            let mut assessed = operation
                .run(|| request.fixture_assessment(&operation))
                .unwrap()
                .unwrap()
                .unwrap();
            request.qualify_rgb_pad_evidence(&mut assessed);
            assert_eq!(
                assessed.rgb_pad,
                if index < 4 {
                    PadEvidence::Pending
                } else {
                    PadEvidence::Score(0.1)
                }
            );
            assert_eq!(request.vit_scores.len(), index + 1);
        }
        assert_eq!(script.calls(), 5);
        drop(script);
        for ir_failure in [false, true] {
            for bad in [
                PadInput::NotApplicable,
                PadInput::Unavailable,
                PadInput::InferenceFailed,
                PadInput::Score(f32::NAN),
                PadInput::Score(f32::INFINITY),
            ] {
                request.vit_scores.clear();
                let script = AssessmentGuard::install(
                    fixture.expected(),
                    CameraOperationKind::Enrollment,
                    move |_| {
                        Ok(if ir_failure {
                            sample_with_pad(PadInput::Score(0.1), bad)
                        } else {
                            sample_with_pad(bad, PadInput::Score(0.1))
                        })
                    },
                )
                .unwrap();
                let mut assessed = operation
                    .run(|| request.fixture_assessment(&operation))
                    .unwrap()
                    .unwrap()
                    .unwrap();
                request.qualify_rgb_pad_evidence(&mut assessed);
                let refusal = pad_policy_refusal(
                    PadRequirements::RgbAndIr,
                    assessed.rgb_pad,
                    assessed.ir_pad,
                )
                .unwrap();
                assert_eq!(refusal.kind, OutcomeKind::RuntimeUnavailable);
                assert_eq!(request.vit_scores.len(), usize::from(ir_failure));
                assert_eq!(script.calls(), 1);
            }
        }
        request.vit_scores.clear();
    });
}

#[test]
fn support_adapter_suppresses_rgb_votes_after_ir_spoof_nonlive_and_no_rgb_face() {
    for case in ["ir-spoof", "uncertain", "spoof", "no-rgb-face"] {
        under_enrollment_operation(|fixture, request, operation| {
            request.vit_scores.clear();
            for _ in 0..4 {
                assert!(!request.vit_pad_votes_deny(0.1));
            }
            let before = request.vit_scores.clone();
            let script = AssessmentGuard::install(
                fixture.expected(),
                CameraOperationKind::Enrollment,
                move |_| {
                    let mut assessed = sample_with_pad(
                        PadInput::Score(0.1),
                        PadInput::Score(if case == "ir-spoof" {
                            IR_PAD_THRESHOLD
                        } else {
                            0.1
                        }),
                    );
                    match case {
                        "uncertain" => assessed.verdict = Verdict::Uncertain,
                        "spoof" => assessed.verdict = Verdict::Spoof,
                        "no-rgb-face" => assessed.signals.rgb_face = None,
                        _ => {}
                    }
                    Ok(assessed)
                },
            )
            .unwrap();
            let mut assessed = operation
                .run(|| request.fixture_assessment(&operation))
                .unwrap()
                .unwrap()
                .unwrap();
            // Assert before qualification clears a non-Live/non-scored ring:
            // that cleanup must not hide an erroneously appended fifth vote.
            assert_eq!(
                request.vit_scores, before,
                "{case}: adapter appended a vote"
            );
            assert_eq!(assessed.rgb_pad, PadEvidence::NotApplicable, "{case}");
            assert_eq!(
                assessed.verdict,
                match case {
                    "ir-spoof" | "spoof" => Verdict::Spoof,
                    "uncertain" => Verdict::Uncertain,
                    _ => Verdict::Live,
                },
                "{case}"
            );
            if case == "ir-spoof" {
                assert_eq!(
                    assessed.reason,
                    "IR PAD cue flags a spoof; use your password"
                );
            }
            assert_eq!(script.calls(), 1);
            request.qualify_rgb_pad_evidence(&mut assessed);
            assert!(
                request.vit_scores.is_empty(),
                "{case}: qualification clears unusable evidence"
            );
        });
    }
}

#[test]
fn support_adapter_checks_evaluated_cancellation_and_expired_deadline() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    for cancel_in_callback in [false, true] {
        under_enrollment_operation(|fixture, request, operation| {
            let cancelled = Arc::new(AtomicBool::new(!cancel_in_callback));
            let signal = Arc::clone(&cancelled);
            let previous = request.request_cancelled.take();
            request.set_request_cancel_signal(Arc::new(move || signal.load(Ordering::SeqCst)));
            let script = AssessmentGuard::install(
                fixture.expected(),
                CameraOperationKind::Enrollment,
                move |_| {
                    cancelled.store(true, Ordering::SeqCst);
                    Ok(sample())
                },
            )
            .unwrap();
            let result = operation.run(|| request.fixture_assessment(&operation));
            request.request_cancelled = previous;
            let error = result.unwrap().err().expect("cancelled assessment refused");
            assert!(matches!(error, irlume_common::Error::Preempted(_)));
            assert_eq!(script.calls(), usize::from(cancel_in_callback));
            assert_eq!(fixture.camera.lease_counts_observer()(), (2, 0));
        });
    }
    under_enrollment_operation(|fixture, request, operation| {
        let script =
            AssessmentGuard::install(fixture.expected(), CameraOperationKind::Enrollment, |_| {
                panic!("expired deadline called assessment script")
            })
            .unwrap();
        let previous = request
            .authentication_deadline
            .replace(std::time::Instant::now());
        let scope = crate::authentication_window::Scope {
            engine: request,
            previous,
        };
        let result = operation.run(|| scope.engine.fixture_assessment(&operation));
        drop(scope);
        let error = result.unwrap().err().expect("expired assessment refused");
        assert!(matches!(error, irlume_common::Error::DeadlineExpired));
        assert_eq!(script.calls(), 0);
        assert_eq!(fixture.camera.lease_counts_observer()(), (2, 0));
    });
}
