//! ADR-0024 Phase 2 engine wiring: a secondary-camera attempt pins its
//! group, matches against exactly that group's scoped view, and re-valid
//!ates BOTH stores at the grant-decision boundary. No camera is opened:
//! the pin seam is `Engine::resolve_attempt_enrollment` with caller-supplied
//! live identities - exactly what the sequencing core calls after the
//! enrollment load - and the boundary seam is the same
//! `authenticate_qualified_assessment` the capture paths end in.

use super::super::tests::{env_guard, unit};
use super::*;
use super::{pad_matching_fixture, shared};
use irlume_core::multi_camera::{
    save_secondary, secondary_store_path, CameraGroupId, GroupPair, SecondaryGroup,
    SecondaryProfileScans, SecondaryStore, SECONDARY_STORE_VERSION,
};
use irlume_core::storage::{CameraBinding, Enrollment, FaceScan};

/// Sandboxes `IRLUME_STATE_DIR` for one test (the env guard is held for the
/// test's life) and plants plaintext primaries at the exact path the
/// coordinator resolves. Raw bytes, never `storage::save`: the pin digests
/// the exact primary bytes, and the TPM must stay out of unit tests.
struct Sandbox {
    dir: std::path::PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("irlume-mc2-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        Self { dir }
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
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn desk_pair() -> (Option<String>, Option<String>) {
    (Some("046d:desk".into()), Some("046d:desk".into()))
}

fn laptop_pair() -> (Option<String>, Option<String>) {
    (Some("046d:lap".into()), Some("046d:lap".into()))
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
            pair: GroupPair {
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
    enr.camera_binding = Some(CameraBinding {
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

    let resolved = s
        .engine
        .resolve_attempt_enrollment("pad-contract", enr, &desk_pair())
        .expect("the desk pair pins the desk group");
    assert!(s.engine.secondary_attempt.is_some(), "pin recorded");
    // Scoped: the bridge carries the GROUP pair and only the group's scans.
    assert_eq!(
        resolved.camera_binding,
        Some(CameraBinding {
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
fn a_primary_attempt_is_unchanged_by_a_present_secondary_store() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("primary-untouched");
    let (enr, assessment) = pinned_fixture(&sandbox);
    let expected_binding = enr.camera_binding.clone();
    let expected_profiles = enr.profiles.len();

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
fn an_unknown_pair_keeps_todays_binding_refusal() {
    let _g = env_guard();
    let mut s = shared();
    let sandbox = Sandbox::new("unknown-pair");
    let (enr, _) = pinned_fixture(&sandbox);

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
    enr.camera_binding = Some(CameraBinding {
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
    enr.camera_binding = Some(CameraBinding {
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
