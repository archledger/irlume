// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ADR-0024 Phase 2 engine wiring: a secondary-camera attempt pins its
//! group, matches against exactly that group's scoped view, and re-valid
//!ates BOTH stores at the grant-decision boundary. No camera is opened:
//! the pin seam is `Engine::resolve_attempt_enrollment` with caller-supplied
//! live identities. Snapshot-specific tests exercise the production resolver
//! against retained primary bytes; the boundary seam is the same
//! `authenticate_qualified_assessment` the capture paths end in.

use super::super::tests::{env_guard, unit};
use super::*;
use super::{pad_matching_fixture, shared};
use irlume_core::multi_camera::authz::{
    AuthorizationVia, EnrollmentAuthorization, EnrollmentOperation, GroupPairRef,
};
use irlume_core::multi_camera::{
    save_secondary, secondary_store_path, CameraGroupId, GroupPair, SecondaryGroup,
    SecondaryProfileScans, SecondaryStore, SECONDARY_STORE_VERSION,
};
use irlume_core::storage::{CameraBinding, Enrollment, FaceScan};
use std::cell::Cell;

fn mint(
    user: &str,
    operation: EnrollmentOperation,
) -> irlume_core::multi_camera::authz::EnrollmentAuthorization {
    EnrollmentAuthorization::mint(
        user.into(),
        operation,
        1_000_000,
        900,
        "auth-test".into(),
        AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .expect("mint")
}

fn add_desk_operation() -> EnrollmentOperation {
    EnrollmentOperation::AddGroup {
        group: "cam-046d-desk".into(),
        pair: GroupPairRef {
            rgb: Some("046d:desk".into()),
            ir: Some("046d:desk".into()),
        },
    }
}

/// The `publish_camera_group` transaction's authorized profile payload.
fn desk_profile_payload() -> SecondaryProfileScans {
    let (enr, _) = pad_matching_fixture(0.2, false);
    SecondaryProfileScans {
        ir_calibs: Default::default(),
        profile: "fixture".into(),
        scans: vec![enr.profiles[0].scans[0].clone()],
    }
}

/// Sandboxes `IRLUME_STATE_DIR` and `IRLUME_CONFIG_DIR` for one test (the env
/// guard is held for the test's life) and plants plaintext primaries at the
/// exact path the coordinator resolves. Raw bytes, never `storage::save`: the
/// pin digests the exact primary bytes, and the TPM must stay out of unit
/// tests. The config dir goes too because camera-selection observation reads
/// `cameras.conf` first: pointed at the host's real `/etc/irlume`, a root-only
/// file there reads as Unreadable and fails every request before the behavior
/// under test runs.
struct Sandbox {
    dir: std::path::PathBuf,
    /// Keeps the TPM out for the sandbox's life: on a host with /dev/tpm* the
    /// device-node probe would otherwise seal stores with the real TPM.
    _no_tpm: irlume_core::template_key::test_support::TpmPresence,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let no_tpm = irlume_core::template_key::test_support::TpmPresence::force(false);
        let dir = std::env::temp_dir().join(format!("irlume-mc2-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        Self {
            dir,
            _no_tpm: no_tpm,
        }
    }

    fn primary_path(&self, user: &str) -> std::path::PathBuf {
        self.dir.join(format!("{user}.json"))
    }

    fn write_primary(&self, user: &str, enr: &Enrollment) -> Vec<u8> {
        let bytes = serde_json::to_vec(enr).expect("serialize primary");
        std::fs::write(self.primary_path(user), &bytes).expect("plant primary");
        bytes
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        std::env::remove_var("IRLUME_STATE_DIR");
        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn desk_pair() -> (Option<String>, Option<String>) {
    (Some("046d:desk".into()), Some("046d:desk".into()))
}

fn laptop_pair() -> (Option<String>, Option<String>) {
    (Some("046d:lap".into()), Some("046d:lap".into()))
}

fn split_desk_key() -> irlume_common::split_key::SplitPairKey {
    irlume_common::split_key::SplitPairKey::parse_canonical(
        "split1;046d:desk|0000:00:14.0|usb2|8;046d:desk-ir|0000:00:14.0|usb2|5",
    )
    .expect("synthetic split key")
}

#[test]
fn identity_only_binding_check_refuses_split_even_when_both_ids_match() {
    let live: (Option<String>, Option<String>) =
        (Some("046d:desk".into()), Some("046d:desk-ir".into()));
    let ordinary = CameraBinding::Ordinary {
        rgb: live.0.clone(),
        ir: live.1.clone(),
    };
    assert_eq!(binding_mismatch_for(&ordinary, &live), None);

    let split = CameraBinding::Split(split_desk_key());
    for live in [live, (None, None)] {
        let reason = binding_mismatch_for(&split, &live).expect("identity-only split refusal");
        assert!(
            reason.contains("split") && reason.contains("disabled"),
            "{reason}"
        );
    }
}

/// A one-group store bound to `primary_bytes`, pair `pair`, one profile
/// `profile` carrying `scans`.
fn desk_store(
    user: &str,
    primary_bytes: &[u8],
    pair: &str,
    profile: &str,
    scans: Vec<FaceScan>,
) -> SecondaryStore {
    SecondaryStore {
        format_version: SECONDARY_STORE_VERSION,
        owner: user.into(),
        generation: 1,
        primary_snapshot_sha256: irlume_common::sha256_hex(primary_bytes),
        groups: vec![SecondaryGroup {
            id: CameraGroupId::new("desk".into()).unwrap(),
            pair: GroupPair::Ordinary {
                rgb: Some(pair.into()),
                ir: Some(pair.into()),
            },
            profiles: vec![SecondaryProfileScans {
                ir_calibs: Default::default(),
                profile: profile.into(),
                scans,
            }],
        }],
    }
}

/// Primary bound to the laptop pair + a desk group carrying the fixture's
/// own scans: the granting assessment then grants on the scoped data too.
fn pinned_fixture(sandbox: &Sandbox) -> (Enrollment, Assessment) {
    let (mut enr, assessment) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    let bytes = sandbox.write_primary("pad-contract", &enr);
    let scans = enr.profiles[0].scans.clone();
    save_secondary(
        &secondary_store_path("pad-contract"),
        &desk_store("pad-contract", &bytes, "046d:desk", "fixture", scans),
    )
    .expect("save secondary");
    (enr, assessment)
}

fn assess(e: &mut Engine, enr: &Enrollment, a: Assessment) -> Outcome {
    // No IR flip: the shared engine is RGB-only (IRLUME_FORCE_NO_IR) and
    // the fixture's evidence is RGB-only, so the RGB arm decides.
    let out = e
        .authenticate_qualified_assessment(enr, AuthenticationPurpose::Verify, None, a, &())
        .expect("assessment returns");
    // The shared engine outlives this test: never leak a pin into the next
    // one's direct assessment call (production clears at attempt entry).
    e.begin_attempt();
    out
}

#[test]
fn a_secondary_pair_pins_its_group_and_grants_from_scoped_data_only() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("pin-grant");
    let (enr, assessment) = pinned_fixture(&sandbox);

    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect("the desk pair pins the desk group");
    assert!(s.engine.secondary_attempt.is_some(), "pin recorded");
    // Scoped: the bridge carries the GROUP pair and only the group's scans.
    assert_eq!(
        resolved.camera_binding,
        Some(CameraBinding::Ordinary {
            rgb: Some("046d:desk".into()),
            ir: Some("046d:desk".into())
        })
    );
    assert_eq!(resolved.profiles.len(), 1);
    assert_eq!(resolved.profiles[0].name, "fixture");
    assert_eq!(resolved.profiles[0].scans.len(), 1);
    // Nothing drifted: the boundary passes and the granting assessment
    // grants on the scoped data.
    let out = assess(&mut s.engine, &resolved, assessment);
    assert!(out.granted, "scoped grant must succeed: {}", out.reason);
}

#[test]
fn snapshot_secondary_resolution_retains_scope_and_grant_boundary() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("snapshot-pin-grant");
    let (enr, assessment) = pinned_fixture(&sandbox);
    let bytes = std::fs::read(sandbox.primary_path("pad-contract")).unwrap();
    s.engine.begin_attempt();
    let resolved = s
        .engine
        .resolve_attempt_snapshot(
            "pad-contract",
            irlume_core::storage::PrimarySnapshot {
                enrollment: enr,
                key: None,
                bytes,
            },
            &desk_pair(),
        )
        .unwrap();
    let context = s
        .engine
        .secondary_attempt
        .as_ref()
        .expect("actual snapshot resolver retained pin");
    assert_eq!(context.store_index(), 0);
    assert_eq!(
        resolved.camera_binding,
        Some(GroupPair::Ordinary {
            rgb: desk_pair().0,
            ir: desk_pair().1
        })
    );
    assert!(assess(&mut s.engine, &resolved, assessment).granted);
}

#[test]
fn snapshot_resolution_preserves_primary_policy_before_secondary_bridge() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("snapshot-policy");
    let (mut enr, _) = pinned_fixture(&sandbox);
    enr.require_eyes_open = true;
    let bytes = sandbox.write_primary("pad-contract", &enr);
    let store = desk_store(
        "pad-contract",
        &bytes,
        "046d:desk",
        "fixture",
        enr.profiles[0].scans.clone(),
    );
    save_secondary(&secondary_store_path("pad-contract"), &store).unwrap();
    s.engine.begin_attempt();
    let refusal = s
        .engine
        .resolve_attempt_snapshot(
            "pad-contract",
            irlume_core::storage::PrimarySnapshot {
                enrollment: enr,
                key: None,
                bytes,
            },
            &desk_pair(),
        )
        .unwrap_err();
    assert!(refusal.reason.contains("require-eyes-open") && refusal.reason.contains("retired"));
    assert!(s.engine.secondary_attempt.is_none());
    s.engine.begin_attempt();
}

#[test]
fn snapshot_primary_fallback_keeps_recognizer_and_binding_refusals() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("snapshot-fallback");
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = None;
    for scan in &mut enr.profiles[0].scans {
        scan.embed_space = Some("other-recognizer".into());
    }
    let bytes = sandbox.write_primary("pad-contract", &enr);
    s.engine.begin_attempt();
    let refusal = s
        .engine
        .resolve_attempt_snapshot(
            "pad-contract",
            irlume_core::storage::PrimarySnapshot {
                enrollment: enr,
                key: None,
                bytes,
            },
            &desk_pair(),
        )
        .unwrap_err();
    assert_eq!(refusal.kind, OutcomeKind::SetupUnavailable);
    assert!(refusal.reason.contains("current recognition model"));
    let (enr, _) = pinned_fixture(&sandbox);
    let bytes = std::fs::read(sandbox.primary_path("pad-contract")).unwrap();
    let refusal = s
        .engine
        .resolve_attempt_snapshot(
            "pad-contract",
            irlume_core::storage::PrimarySnapshot {
                enrollment: enr,
                key: None,
                bytes,
            },
            &(Some("unknown-rgb".into()), Some("unknown-ir".into())),
        )
        .unwrap_err();
    assert_eq!(refusal.cause, Some(OutcomeCause::NotEnrolledOnThisCamera));
    assert!(s.engine.secondary_attempt.is_none());
    s.engine.begin_attempt();
}

#[test]
fn a_primary_attempt_is_unchanged_by_a_present_secondary_store() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("primary-untouched");
    let (enr, assessment) = pinned_fixture(&sandbox);
    let expected_binding = enr.camera_binding.clone();
    let expected_profiles = enr.profiles.len();

    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &laptop_pair())
        .expect("the primary pair keeps today's path");
    assert!(s.engine.secondary_attempt.is_none(), "no pin on primary");
    assert_eq!(
        resolved.camera_binding, expected_binding,
        "the primary enrollment is returned unchanged"
    );
    assert_eq!(resolved.profiles.len(), expected_profiles);
    // And the store's presence cannot change the assessment outcome.
    let out = assess(&mut s.engine, &resolved, assessment);
    assert!(out.granted, "{}", out.reason);
}

#[test]
fn identity_only_attempt_resolution_never_aliases_a_split_binding() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("split-identity-only");
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Split(split_desk_key()));
    sandbox.write_primary("pad-contract", &enr);
    let live = (Some("046d:desk".into()), Some("046d:desk-ir".into()));

    s.engine.begin_attempt();
    let refusal = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &live)
        .expect_err("split primary cannot match identity-only input");
    assert!(!refusal.granted && !refusal.live);
    assert_eq!(refusal.cause, Some(OutcomeCause::NotEnrolledOnThisCamera));
    assert!(refusal.reason.contains("split") && refusal.reason.contains("disabled"));
    assert!(s.engine.secondary_attempt.is_none());

    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    let bytes = sandbox.write_primary("pad-contract", &enr);
    let mut store = desk_store(
        "pad-contract",
        &bytes,
        "046d:desk",
        "fixture",
        enr.profiles[0].scans.clone(),
    );
    store.groups[0].pair = GroupPair::Split(split_desk_key());
    save_secondary(&secondary_store_path("pad-contract"), &store).expect("save split group");
    let refusal = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &live)
        .expect_err("split group cannot match identity-only input");
    assert!(!refusal.granted && !refusal.live);
    assert_eq!(refusal.cause, Some(OutcomeCause::NotEnrolledOnThisCamera));
    assert!(s.engine.secondary_attempt.is_none());
    s.engine.begin_attempt();
}

#[test]
fn an_unknown_pair_keeps_todays_binding_refusal() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("unknown-pair");
    let (enr, _) = pinned_fixture(&sandbox);

    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let refusal = s
        .engine
        .resolve_attempt_enrollment(
            "pad-contract",
            enr,
            &(Some("dead:beef".into()), Some("dead:beef".into())),
        )
        .expect_err("no group and no primary match must refuse");
    assert!(!refusal.granted);
    assert!(
        refusal.reason.contains("camera changed since enrollment"),
        "{}",
        refusal.reason
    );
    assert!(s.engine.secondary_attempt.is_none());
}

#[test]
fn a_stale_secondary_activation_refuses_instead_of_pinning() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("stale-store");
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    let _bytes = sandbox.write_primary("pad-contract", &enr);
    // Bound to OTHER primary bytes: digest mismatch = inactive (§1.1).
    let stale = desk_store(
        "pad-contract",
        b"different-primary",
        "046d:desk",
        "fixture",
        enr.profiles[0].scans.clone(),
    );
    save_secondary(&secondary_store_path("pad-contract"), &stale).expect("save");

    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let refusal = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect_err("a stale store must never pin");
    assert!(!refusal.granted);
    assert!(
        refusal.reason.contains("camera changed since enrollment"),
        "{}",
        refusal.reason
    );
    assert!(s.engine.secondary_attempt.is_none());
}

#[test]
fn a_primary_rewrite_mid_attempt_refuses_the_grant_at_the_boundary() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("mid-rewrite");
    let (enr, assessment) = pinned_fixture(&sandbox);
    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect("pin");

    // Mid-attempt: a legacy writer replaces the primary while the secondary
    // generation is unchanged - the acceptance-matrix row, engine-level.
    std::fs::write(sandbox.primary_path("pad-contract"), b"legacy-rewrite").expect("rewrite");

    let out = assess(&mut s.engine, &resolved, assessment);
    assert!(!out.granted, "a drifted boundary must not grant");
    assert!(
        out.reason
            .contains("primary snapshot changed during the attempt"),
        "{}",
        out.reason
    );
}

#[test]
fn a_revoked_group_refuses_the_grant_at_the_boundary() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("revoked");
    let (enr, assessment) = pinned_fixture(&sandbox);
    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect("pin");

    // Revocation by publication: a new generation without the desk group.
    let mut revoked = desk_store(
        "pad-contract",
        b"irrelevant",
        "046d:desk",
        "fixture",
        vec![],
    );
    revoked.generation = 2;
    revoked.groups.clear();
    save_secondary(&secondary_store_path("pad-contract"), &revoked).expect("publish removal");

    let out = assess(&mut s.engine, &resolved, assessment);
    assert!(!out.granted);
    assert!(
        out.reason.contains("generation changed during the attempt")
            || out.reason.contains("no longer present"),
        "{}",
        out.reason
    );
}

#[test]
fn begin_attempt_clears_any_residue_from_a_previous_attempt() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("residue");
    let (enr, _) = pinned_fixture(&sandbox);
    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let _resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect("pin");
    assert!(s.engine.secondary_attempt.is_some());
    s.engine.begin_attempt();
    assert!(
        s.engine.secondary_attempt.is_none(),
        "a stale pin must never influence the next attempt"
    );
}

#[test]
fn group_calibrations_reach_ir_matching_through_the_bridge() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("calib-bridge");
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    let bytes = sandbox.write_primary("pad-contract", &enr);

    // A desk group with a paired raw-IR scan and a FITTED calibration for
    // the running recognizer: the bridge must carry the group's own
    // calibration into the profile map so ir_match_in runs the calibrated
    // protocol on the group's templates.
    let mut scan = enr.profiles[0].scans[0].clone();
    scan.ir = Some(scan.rgb.clone());
    scan.ir_space = Some("raw".into());
    // Fit on 512-D pairs aligned with the shipped embedding width (MIN_FIT_PAIRS = 3)
    // so the calibration is dimensionally valid for `apply` and small on disk.
    let base = scan.rgb.clone();
    let mut ir_set = Vec::new();
    let mut rgb_set = Vec::new();
    for k in 0..3 {
        let mut v = base.clone();
        v[0] += 0.01 * k as f32;
        ir_set.push(unit(v.clone()));
        v[1] += 0.02 * k as f32;
        rgb_set.push(unit(v));
    }
    let calib = irlume_core::calib::fit(&ir_set, &rgb_set).expect("fit needs >= MIN_FIT_PAIRS");
    let mut store = desk_store("pad-contract", &bytes, "046d:desk", "fixture", vec![scan]);
    store.groups[0].profiles[0]
        .ir_calibs
        .insert(s.engine.embed_space.clone(), calib);
    save_secondary(&secondary_store_path("pad-contract"), &store).expect("save");

    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect("pin");
    let probe = resolved.profiles[0].scans[0].rgb.clone();
    let matched = ir_match_in("raw", &s.engine.embed_space, false, &resolved, &probe);
    assert_eq!(matched.n_templates, 1, "the group's IR template scores");
    assert!(
        matched.centroid.is_some(),
        "the group's own calibration must drive the calibrated protocol"
    );
    // Shared-engine hygiene: clear the pin this test created.
    s.engine.begin_attempt();
}

fn mint_now(
    user: &str,
    operation: EnrollmentOperation,
) -> irlume_core::multi_camera::authz::EnrollmentAuthorization {
    EnrollmentAuthorization::mint(
        user.into(),
        operation,
        now_unix(),
        900,
        "auth-test".into(),
        AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .expect("mint at the real clock")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[test]
fn publish_camera_group_publishes_under_the_exact_authorized_scope() {
    let _g = env_guard();
    let s = shared();
    let sandbox = Sandbox::new("publish-add");
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    let bytes = sandbox.write_primary("pad-contract", &enr);
    let authz = mint("pad-contract", add_desk_operation());
    let pair = GroupPair::Ordinary {
        rgb: Some("046d:desk".into()),
        ir: Some("046d:desk".into()),
    };

    let published = publish_camera_group(
        "pad-contract",
        &pair,
        "cam-046d-desk",
        &desk_profile_payload(),
        &enr,
        &authz,
        1_000_300,
    )
    .expect("publishes");
    assert_eq!(published, "cam-046d-desk");

    let store = irlume_core::multi_camera::load_secondary(&secondary_store_path("pad-contract"))
        .expect("load")
        .expect("present");
    assert_eq!(store.generation, 1, "first publication bumps to 1");
    assert_eq!(
        store.primary_snapshot_sha256,
        irlume_common::sha256_hex(&bytes),
        "the store binds to the CURRENT primary bytes"
    );
    let group = store
        .group_for_pair(Some("046d:desk"), Some("046d:desk"))
        .expect("group");
    assert_eq!(group.id.as_str(), "cam-046d-desk");
    assert_eq!(group.profiles[0].profile, "fixture");
    assert_eq!(group.profiles[0].scans.len(), 1);

    // The store is the transaction's own evidence: a pin made BEFORE this
    // publication would refuse at its boundary on the generation bump
    // (proven by the removal test below); this test pins nothing.
    drop(s);
}

#[test]
fn publish_camera_group_requires_the_exact_split_operation_and_key() {
    use irlume_common::split_key::SplitDomain;

    let _g = env_guard();
    let sandbox = Sandbox::new("publish-split-scope");
    let (enr, _) = pad_matching_fixture(0.2, false);
    let bytes = sandbox.write_primary("pad-contract", &enr);
    let key = split_desk_key();
    let pair = GroupPair::Split(key.clone());
    let authorization = mint(
        "pad-contract",
        EnrollmentOperation::AddSplitGroup {
            group: "cam-046d-desk".into(),
            pair: key.clone(),
        },
    );
    let ordinary = GroupPair::Ordinary {
        rgb: Some("046d:desk".into()),
        ir: Some("046d:desk-ir".into()),
    };
    let mut drifted = vec![("class", ordinary)];
    for side in ["rgb", "ir"] {
        for field in ["controller", "domain", "ports", "identity"] {
            let mut changed = key.clone();
            let unit = if side == "rgb" {
                &mut changed.rgb
            } else {
                &mut changed.ir
            };
            match field {
                "controller" => unit.controller = "0000:00:15.0".into(),
                "domain" => unit.domain = SplitDomain::SuperSpeed,
                "ports" => unit.ports = vec![10],
                "identity" => unit.identity = "046d:other".into(),
                _ => unreachable!("closed fixture fields"),
            }
            drifted.push((field, GroupPair::Split(changed)));
        }
    }
    let swapped = irlume_common::split_key::SplitPairKey {
        rgb: key.ir.clone(),
        ir: key.rgb.clone(),
    };
    drifted.push(("roles", GroupPair::Split(swapped)));

    for (field, changed) in drifted {
        let refusal = publish_camera_group(
            "pad-contract",
            &changed,
            "cam-046d-desk",
            &desk_profile_payload(),
            &enr,
            &authorization,
            1_000_300,
        )
        .expect_err("split authorization must refuse drift");
        assert!(
            refusal.to_string().contains("another operation"),
            "{field}: {refusal}"
        );
        assert!(
            !secondary_store_path("pad-contract").exists(),
            "{field}: nothing published"
        );
    }

    // An ordinary operation carrying the same identities cannot publish split.
    let ordinary_authorization = mint(
        "pad-contract",
        EnrollmentOperation::AddGroup {
            group: "cam-046d-desk".into(),
            pair: GroupPairRef {
                rgb: Some("046d:desk".into()),
                ir: Some("046d:desk-ir".into()),
            },
        },
    );
    let refusal = publish_camera_group(
        "pad-contract",
        &pair,
        "cam-046d-desk",
        &desk_profile_payload(),
        &enr,
        &ordinary_authorization,
        1_000_300,
    )
    .expect_err("ordinary scope cannot authorize split");
    assert!(
        refusal.to_string().contains("another operation"),
        "{refusal}"
    );
    assert!(!secondary_store_path("pad-contract").exists());

    let published = publish_camera_group(
        "pad-contract",
        &pair,
        "cam-046d-desk",
        &desk_profile_payload(),
        &enr,
        &authorization,
        1_000_300,
    )
    .expect("exact whole split operation publishes synthetic data");
    assert_eq!(published, "cam-046d-desk");
    let store = irlume_core::multi_camera::load_secondary(&secondary_store_path("pad-contract"))
        .unwrap()
        .unwrap();
    assert_eq!(store.generation, 1);
    assert_eq!(
        store.primary_snapshot_sha256,
        irlume_common::sha256_hex(&bytes)
    );
    assert_eq!(store.groups.len(), 1);
    assert_eq!(store.groups[0].pair, pair);
    assert_eq!(store.groups[0].id.as_str(), "cam-046d-desk");
}

#[test]
fn guarded_group_publication_refuses_exact_primary_bytes_or_authorization_drift_after_preparation()
{
    let _g = env_guard();
    for drift in [
        "before-prepare-bytes",
        "after-prepare-bytes",
        "after-prepare-expiry",
    ] {
        let sandbox = Sandbox::new(drift);
        let (enr, _) = pad_matching_fixture(0.2, false);
        let before = sandbox.write_primary("pad-contract", &enr);
        let pair = GroupPair::Split(split_desk_key());
        let authorization = mint(
            "pad-contract",
            EnrollmentOperation::add_group("cam-046d-desk".into(), &pair),
        );
        let payload = desk_profile_payload();
        let primary_path = irlume_core::multi_camera::primary_enrollment_path("pad-contract");
        let rewrite = || {
            let mut semantically_equal = before.clone();
            semantically_equal.push(b'\n');
            std::fs::write(&primary_path, &semantically_equal).unwrap();
        };
        if drift == "before-prepare-bytes" {
            rewrite();
        }
        let prepared_called = Cell::new(false);
        let published_called = Cell::new(false);
        let result = publish_camera_group_preparing_with(
            CameraGroupPublication {
                user: "pad-contract",
                pair: &pair,
                group_id: "cam-046d-desk",
                profile: &payload,
                start_enr: &enr,
                start_primary_sha256: &irlume_common::sha256_hex(&before),
                authorization: &authorization,
                now_unix: 1_000_300,
            },
            |path, next, digest| {
                let prepared =
                    irlume_core::multi_camera::commit::prepare_with_intent(path, next, digest)?;
                prepared_called.set(true);
                if drift == "after-prepare-bytes" {
                    rewrite();
                }
                Ok(prepared)
            },
            |prepared| {
                published_called.set(true);
                prepared
                    .publish()
                    .map_err(|error| irlume_common::Error::Protocol(error.to_string()))
            },
            || {
                if drift == "after-prepare-expiry" {
                    2_000_000
                } else {
                    1_000_300
                }
            },
        );
        assert!(
            result.is_err(),
            "{drift}: publication accepted changed authority"
        );
        assert_eq!(
            published_called.get(),
            drift != "before-prepare-bytes",
            "late account admission belongs inside the consuming publication callback"
        );
        assert_eq!(prepared_called.get(), drift != "before-prepare-bytes");
        let path = secondary_store_path("pad-contract");
        assert!(!path.exists());
        assert!(!irlume_core::multi_camera::commit::intent_path_for(&path).exists());
    }
}

#[test]
fn guarded_group_publication_preserves_a_concurrent_secondary_write_after_preparation() {
    let _g = env_guard();
    let sandbox = Sandbox::new("secondary-preparation-race");
    let (enr, _) = pad_matching_fixture(0.2, false);
    let primary = sandbox.write_primary("pad-contract", &enr);
    let pair = GroupPair::Split(split_desk_key());
    let authorization = mint(
        "pad-contract",
        EnrollmentOperation::add_group("cam-046d-desk".into(), &pair),
    );
    let path = secondary_store_path("pad-contract");
    let concurrent = desk_store(
        "pad-contract",
        &primary,
        "046d:concurrent",
        "fixture",
        enr.profiles[0].scans.clone(),
    );
    let expected = serde_json::to_vec(&concurrent).unwrap();
    let result = publish_camera_group_preparing_with(
        CameraGroupPublication {
            user: "pad-contract",
            pair: &pair,
            group_id: "cam-046d-desk",
            profile: &desk_profile_payload(),
            start_enr: &enr,
            start_primary_sha256: &irlume_common::sha256_hex(&primary),
            authorization: &authorization,
            now_unix: 1_000_300,
        },
        |path, next, digest| {
            let prepared =
                irlume_core::multi_camera::commit::prepare_with_intent(path, next, digest)?;
            // A real cooperative publisher completes while key preparation's
            // account lock is absent, before the final publication admission.
            irlume_core::multi_camera::commit::publish_with_intent(path, &concurrent, digest)?;
            Ok(prepared)
        },
        |prepared| prepared.publish(),
        || 1_000_300,
    );
    assert!(
        result.is_err(),
        "stale prepared addition overwrote a concurrent group"
    );
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    assert!(!irlume_core::multi_camera::commit::intent_path_for(&path).exists());
    assert_eq!(
        std::fs::read(sandbox.primary_path("pad-contract")).unwrap(),
        primary
    );
}

#[test]
fn guarded_group_publication_holds_account_lock_through_consuming_callback() {
    let _g = env_guard();
    let sandbox = Sandbox::new("account-publication-lock");
    let (enr, _) = pad_matching_fixture(0.2, false);
    let primary = sandbox.write_primary("pad-contract", &enr);
    // The normal passive loader creates the real stable account lock.
    irlume_core::storage::load_unmoved("pad-contract")
        .unwrap()
        .unwrap();
    let key_dir = irlume_core::template_key::key_dir();
    let lock = key_dir.join(".locks").join(format!(
        "{}.lock",
        irlume_common::sha256_hex(b"pad-contract")
    ));
    let try_writer = || {
        std::process::Command::new("flock")
            .args(["--exclusive", "--nonblock"])
            .arg(&lock)
            .arg("true")
            .status()
            .expect("fixture flock probe")
            .code()
    };
    assert_eq!(try_writer(), Some(0), "healthy unlocked control");
    let pair = GroupPair::Split(split_desk_key());
    let authorization = mint(
        "pad-contract",
        EnrollmentOperation::add_group("cam-046d-desk".into(), &pair),
    );
    let result = publish_camera_group_with(
        CameraGroupPublication {
            user: "pad-contract",
            pair: &pair,
            group_id: "cam-046d-desk",
            profile: &desk_profile_payload(),
            start_enr: &enr,
            start_primary_sha256: &irlume_common::sha256_hex(&primary),
            authorization: &authorization,
            now_unix: 1_000_300,
        },
        |prepared| {
            assert_eq!(
                try_writer(),
                Some(1),
                "account writer entered before publication"
            );
            prepared.publish()
        },
        || 1_000_300,
    );
    result.unwrap();
    assert_eq!(
        try_writer(),
        Some(0),
        "publication released the account lock"
    );
    assert!(secondary_store_path("pad-contract").exists());
}

#[test]
fn guarded_group_publication_refuses_account_drift_after_preparation() {
    let _g = env_guard();
    let sandbox = Sandbox::new("account-preparation-race");
    let (enr, _) = pad_matching_fixture(0.2, false);
    let primary = sandbox.write_primary("pad-contract", &enr);
    let pair = GroupPair::Split(split_desk_key());
    let authorization = mint(
        "pad-contract",
        EnrollmentOperation::add_group("cam-046d-desk".into(), &pair),
    );
    let drift = std::cell::RefCell::new(None);
    let result = publish_camera_group_preparing_with(
        CameraGroupPublication {
            user: "pad-contract",
            pair: &pair,
            group_id: "cam-046d-desk",
            profile: &desk_profile_payload(),
            start_enr: &enr,
            start_primary_sha256: &irlume_common::sha256_hex(&primary),
            authorization: &authorization,
            now_unix: 1_000_300,
        },
        |path, next, digest| {
            let prepared =
                irlume_core::multi_camera::commit::prepare_with_intent(path, next, digest)?;
            *drift.borrow_mut() = Some(irlume_core::account::remember("pad-contract", 424242));
            Ok(prepared)
        },
        |prepared| prepared.publish(),
        || 1_000_300,
    );
    assert!(result.unwrap_err().to_string().contains("account changed"));
    let path = secondary_store_path("pad-contract");
    assert!(!path.exists() && !irlume_core::multi_camera::commit::intent_path_for(&path).exists());
}

#[test]
fn publish_camera_group_distinguishes_split_locations_and_ordinary_aliases() {
    let _g = env_guard();
    let sandbox = Sandbox::new("publish-split-lookup");
    let (enr, _) = pad_matching_fixture(0.2, false);
    let bytes = sandbox.write_primary("pad-contract", &enr);
    let ordinary = GroupPair::Ordinary {
        rgb: Some("046d:desk".into()),
        ir: Some("046d:desk-ir".into()),
    };
    let store = SecondaryStore {
        format_version: SECONDARY_STORE_VERSION,
        owner: "pad-contract".into(),
        generation: 1,
        primary_snapshot_sha256: irlume_common::sha256_hex(&bytes),
        groups: vec![SecondaryGroup {
            id: CameraGroupId::new("cam-046d-desk".into()).unwrap(),
            pair: ordinary.clone(),
            profiles: vec![desk_profile_payload()],
        }],
    };
    save_secondary(&secondary_store_path("pad-contract"), &store).expect("save ordinary alias");
    let key = split_desk_key();
    let split = GroupPair::Split(key.clone());
    publish_camera_group(
        "pad-contract",
        &split,
        "cam-046d-desk-2",
        &desk_profile_payload(),
        &enr,
        &mint(
            "pad-contract",
            EnrollmentOperation::AddSplitGroup {
                group: "cam-046d-desk-2".into(),
                pair: key.clone(),
            },
        ),
        1_000_300,
    )
    .expect("ordinary alias is a different credential class");

    let refusal = publish_camera_group(
        "pad-contract",
        &split,
        "cam-046d-desk-3",
        &desk_profile_payload(),
        &enr,
        &mint(
            "pad-contract",
            EnrollmentOperation::AddSplitGroup {
                group: "cam-046d-desk-3".into(),
                pair: key.clone(),
            },
        ),
        1_000_300,
    )
    .expect_err("an exact split duplicate must refuse");
    assert!(
        refusal.to_string().contains("already enrolled"),
        "{refusal}"
    );
    let after_refusal =
        irlume_core::multi_camera::load_secondary(&secondary_store_path("pad-contract"))
            .unwrap()
            .unwrap();
    assert_eq!(after_refusal.generation, 2, "duplicate publishes nothing");
    assert_eq!(after_refusal.groups.len(), 2);

    let mut moved = key;
    moved.rgb.ports = vec![10];
    let moved_pair = GroupPair::Split(moved.clone());
    publish_camera_group(
        "pad-contract",
        &moved_pair,
        "cam-046d-desk-3",
        &desk_profile_payload(),
        &enr,
        &mint(
            "pad-contract",
            EnrollmentOperation::AddSplitGroup {
                group: "cam-046d-desk-3".into(),
                pair: moved,
            },
        ),
        1_000_300,
    )
    .expect("a distinct location requires and accepts its own exact operation");
    let store = irlume_core::multi_camera::load_secondary(&secondary_store_path("pad-contract"))
        .unwrap()
        .unwrap();
    assert_eq!(store.generation, 3);
    assert_eq!(store.groups.len(), 3);
    assert_eq!(store.groups[0].pair, ordinary);
    assert_eq!(store.groups[1].pair, split);
    assert_eq!(store.groups[2].pair, moved_pair);
}

#[test]
fn publish_camera_group_refuses_a_primary_change_during_capture() {
    let _g = env_guard();
    let sandbox = Sandbox::new("publish-changed");
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    let _bytes = sandbox.write_primary("pad-contract", &enr);
    // A legacy rewrite lands between capture and publication.
    let mut rewritten = enr.clone();
    rewritten.profiles[0].scans[0].name = "renamed".into();
    std::fs::write(
        sandbox.primary_path("pad-contract"),
        serde_json::to_vec(&rewritten).expect("serialize"),
    )
    .expect("rewrite");

    let refused = publish_camera_group(
        "pad-contract",
        &GroupPair::Ordinary {
            rgb: Some("046d:desk".into()),
            ir: Some("046d:desk".into()),
        },
        "cam-046d-desk",
        &desk_profile_payload(),
        &enr,
        &mint("pad-contract", add_desk_operation()),
        1_000_300,
    )
    .expect_err("a changed primary must not publish");
    assert!(
        refused.to_string().contains("changed during capture"),
        "{refused}"
    );
    assert!(
        irlume_core::multi_camera::load_secondary(&secondary_store_path("pad-contract"))
            .expect("load")
            .is_none(),
        "nothing was published"
    );
}

#[test]
fn publish_camera_group_refuses_wrong_scope_or_taken_pair() {
    let _g = env_guard();
    let sandbox = Sandbox::new("publish-scope");
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    let _bytes = sandbox.write_primary("pad-contract", &enr);
    let pair = GroupPair::Ordinary {
        rgb: Some("046d:desk".into()),
        ir: Some("046d:desk".into()),
    };

    // A wrongly-scoped authorization (different pair) publishes nothing.
    let wrong_pair = mint(
        "pad-contract",
        EnrollmentOperation::AddGroup {
            group: "cam-046d-desk".into(),
            pair: GroupPairRef {
                rgb: Some("046d:other".into()),
                ir: None,
            },
        },
    );
    let refused = publish_camera_group(
        "pad-contract",
        &pair,
        "cam-046d-desk",
        &desk_profile_payload(),
        &enr,
        &wrong_pair,
        1_000_300,
    )
    .expect_err("wrong scope must refuse");
    assert!(
        refused.to_string().contains("another operation"),
        "{refused}"
    );

    // A store that already holds the pair refuses the concurrent add.
    let mut occupied = SecondaryStore {
        format_version: SECONDARY_STORE_VERSION,
        owner: "pad-contract".into(),
        generation: 4,
        primary_snapshot_sha256: irlume_common::sha256_hex(b"stale-does-not-matter"),
        groups: vec![SecondaryGroup {
            id: CameraGroupId::new("cam-046d-desk".into()).unwrap(),
            pair: pair.clone(),
            profiles: vec![desk_profile_payload()],
        }],
    };
    save_secondary(&secondary_store_path("pad-contract"), &occupied).expect("save");
    let refused = publish_camera_group(
        "pad-contract",
        &pair,
        "cam-046d-desk-2",
        &desk_profile_payload(),
        &enr,
        &mint(
            "pad-contract",
            EnrollmentOperation::AddGroup {
                group: "cam-046d-desk-2".into(),
                pair: GroupPairRef {
                    rgb: Some("046d:desk".into()),
                    ir: Some("046d:desk".into()),
                },
            },
        ),
        1_000_300,
    )
    .expect_err("an occupied pair must refuse");
    assert!(
        refused.to_string().contains("already enrolled"),
        "{refused}"
    );
    occupied.generation = 4;
    let reloaded =
        irlume_core::multi_camera::load_secondary(&secondary_store_path("pad-contract")).unwrap();
    assert_eq!(reloaded.expect("present").generation, 4, "untouched");
}

#[test]
fn add_camera_group_refuses_before_the_camera_opens() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("add-preflight");

    // No primary enrollment: refuse outright.
    let refused = s
        .engine
        .add_camera_group_observed(
            "nobody",
            None,
            10,
            &mint("nobody", add_desk_operation()),
            |_det| true,
            &(),
            &(),
        )
        .expect_err("not enrolled");
    assert!(refused.to_string().contains("is not enrolled"), "{refused}");

    // An ambiguous profile set must name its profile.
    let (mut enr, _) = pad_matching_fixture(0.2, false);
    enr.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    enr.profiles.push(enr.profiles[0].clone());
    enr.profiles[1].name = "Second".into();
    let bytes = sandbox.write_primary("pad-contract", &enr);
    let refused = s
        .engine
        .add_camera_group_observed(
            "pad-contract",
            None,
            10,
            &mint("pad-contract", add_desk_operation()),
            |_det| true,
            &(),
            &(),
        )
        .expect_err("ambiguous profile");
    assert!(
        refused.to_string().contains("multiple face profiles"),
        "{refused}"
    );

    // An unknown profile name refuses.
    let refused = s
        .engine
        .add_camera_group_observed(
            "pad-contract",
            Some("missing".into()),
            10,
            &mint("pad-contract", add_desk_operation()),
            |_det| true,
            &(),
            &(),
        )
        .expect_err("unknown profile");
    assert!(
        refused.to_string().contains("no face profile named"),
        "{refused}"
    );
    assert_eq!(
        std::fs::read(sandbox.primary_path("pad-contract")).unwrap(),
        bytes,
        "refused profile selection leaves the primary enrollment untouched"
    );

    // A single-profile enrollment passes the profile gate but the shared
    // engine's cameras carry no USB identity: a group cannot bind.
    let (mut single, _) = pad_matching_fixture(0.2, false);
    single.camera_binding = Some(CameraBinding::Ordinary {
        rgb: laptop_pair().0,
        ir: laptop_pair().1,
    });
    std::fs::write(
        sandbox.primary_path("pad-single"),
        serde_json::to_vec(&single).expect("serialize"),
    )
    .expect("plant");
    let refused = s
        .engine
        .add_camera_group_observed(
            "pad-single",
            None,
            10,
            &mint("pad-single", add_desk_operation()),
            |_det| true,
            &(),
            &(),
        )
        .expect_err("identityless pair");
    assert!(refused.to_string().contains("no USB identity"), "{refused}");
    assert!(s.engine.secondary_attempt.is_none());
    s.engine.begin_attempt();
}

/// Refused add-camera requests must not move the primary's sealed key before
/// profile, pair, and authorization checks decide whether to publish.
#[test]
fn add_camera_group_loads_the_primary_without_moving_its_key() {
    let source = include_str!("../lib.rs");
    let method = source
        .split_once("pub fn add_camera_group_observed(")
        .expect("add-camera engine entry exists")
        .1
        .split_once("/// Removes one secondary camera group")
        .expect("add-camera method ends before remove-camera")
        .0;
    assert!(method.contains("storage::load_unmoved(user)?"));
    assert!(!method.contains("storage::load(user)?"));
}

#[test]
fn remove_camera_group_publishes_revocation_and_invalidates_pins() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("remove");
    let (enr, _) = pinned_fixture(&sandbox);
    // Attempt entry, as production does before resolving.
    s.engine.begin_attempt();
    let resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect("pin the desk group first");

    let authz = EnrollmentAuthorization::mint(
        "pad-contract".into(),
        EnrollmentOperation::RemoveGroup {
            group: "desk".into(),
        },
        now_unix(),
        900,
        "auth-test".into(),
        AuthorizationVia::ElevatedPeer { uid: 0 },
    )
    .expect("mint at the real clock");
    s.engine
        .remove_camera_group("pad-contract", "desk", &authz)
        .expect("removal publishes");

    let store = irlume_core::multi_camera::load_secondary(&secondary_store_path("pad-contract"))
        .expect("load")
        .expect("present");
    assert_eq!(store.generation, 2, "removal bumps the generation");
    assert!(store.groups.is_empty(), "the group is gone");

    // The pinned attempt from BEFORE the removal now refuses at its grant
    // boundary: revocation invalidates in-flight use (§4.2).
    let (mut enr2, _) = pad_matching_fixture(0.2, true);
    let _ = &mut enr2;
    let out = s
        .engine
        .authenticate_qualified_assessment(
            &resolved,
            AuthenticationPurpose::Verify,
            None,
            pad_matching_fixture(0.2, false).1,
            &(),
        )
        .expect("assessment");
    assert!(!out.granted, "a removed group must not grant");
    assert!(
        out.reason.contains("generation changed during the attempt"),
        "{}",
        out.reason
    );
    s.engine.begin_attempt();
}

#[test]
fn remove_camera_group_refuses_wrong_scope_and_unknown_groups() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("remove-refusals");
    let _ = pinned_fixture(&sandbox);

    // Wrongly-scoped authorization (a different group id).
    let refused = s
        .engine
        .remove_camera_group(
            "pad-contract",
            "desk",
            &mint_now(
                "pad-contract",
                EnrollmentOperation::RemoveGroup {
                    group: "lobby".into(),
                },
            ),
        )
        .expect_err("wrong scope");
    assert!(
        refused.to_string().contains("another operation"),
        "{refused}"
    );

    // Correctly scoped but the group does not exist.
    let refused = s
        .engine
        .remove_camera_group(
            "pad-contract",
            "nonexistent",
            &mint_now(
                "pad-contract",
                EnrollmentOperation::RemoveGroup {
                    group: "nonexistent".into(),
                },
            ),
        )
        .expect_err("unknown group");
    assert!(refused.to_string().contains("no camera group"), "{refused}");
    s.engine.begin_attempt();
}
