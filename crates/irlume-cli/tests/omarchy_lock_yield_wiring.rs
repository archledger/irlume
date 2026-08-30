// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! #607: the stock Omarchy lock lane yields to the dedicated face lane.
//!
//! The yield, the reclaim, and the intent marker's write sites sit on apply
//! paths no behavioral test can drive (root, the real /etc/pam.d). Their
//! decision cores are unit-tested in `pamwire::tests`; this file pins the
//! WIRING of those cores the way `attempt_situation_wiring.rs` pins the
//! situation wire: against the source, with whitespace flattened so rustfmt
//! cannot break the needles.

use std::path::Path;

fn pamwire_src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pamwire.rs"))
        .expect("read pamwire.rs")
}

fn machine_src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/machine.rs"))
        .expect("read machine.rs")
}

fn production(text: &str) -> &str {
    &text[..text.find("\nmod tests").expect("tests module exists")]
}

fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Both want funnels (the plan walk and the apply) must suppress the stock
/// lane through the SAME predicate; a plan that walked a different set than
/// the apply would describe changes that never happen.
#[test]
fn both_want_funnels_yield_the_stock_lane_through_one_predicate() {
    let text = flat(production(&pamwire_src()));
    assert!(
        text.contains("&lock_wire, face_lock && !stock_lane_yielded(),"),
        "walk_surfaces must yield the lock surface"
    );
    assert!(
        text.contains("&lock_wire, want_face_lock && !stock_lane_yielded(),"),
        "the apply path must yield the lock surface through the same predicate"
    );
    assert_eq!(
        text.matches("& !stock_lane_yielded(),").count(),
        2,
        "exactly the two want funnels suppress the lock surface"
    );
}

/// The marker records the intent exactly at the enable write, beside the
/// observed facts; the disable write (which removes the marker) carries no
/// intent; and the machine API mirrors the human path.
#[test]
fn the_intent_is_recorded_beside_the_observed_facts() {
    let text = flat(production(&pamwire_src()));
    assert!(
        text.contains("face_lock_intent: marker_face_lock_intent(want_face_lock),"),
        "the enable marker write records the yield intent"
    );
    let machine = flat(production(&machine_src()));
    assert!(
        machine.contains("face_lock_intent: crate::pamwire::marker_face_lock_intent("),
        "the machine apply path records the same intent"
    );
}

/// Reconcile and reconcile_needed read the lane facts through both pure cores
/// and veto the intact early-return with them, so the self-heal repairs BOTH
/// directions (lane gone reclaims, lane appeared yields) and the TUI Repair
/// offer cannot disagree with the unit's own decision.
#[test]
fn reconcile_repairs_both_lane_directions_and_agrees_with_the_tui() {
    let text = flat(production(&pamwire_src()));
    assert!(
        text.contains("let reclaim = lane_reclaim_for(face_lock_intent, omarchy, face_lane_present, stock_wired);"),
        "reconcile evaluates the posted reclaim read"
    );
    assert!(
        text.contains("&& !reclaim && !lane_yield"),
        "both lane regressions veto the intact early-return"
    );
    // The want probe stays lazy: the closure form is what keeps the daemon
    // roundtrip off the common intact path.
    assert!(
        text.contains("lane_yield_for(omarchy, face_lane_present, stock_wired, with_lock, || { wants().face_lock })"),
        "reconcile's lane-yield want is read lazily"
    );
    // reconcile_needed slices the RAW text (flattening destroys the newline
    // the region boundaries key on), then flattens the region.
    let src = pamwire_src();
    let raw = production(&src);
    let needed = raw
        .find("pub(crate) fn reconcile_needed()")
        .expect("exists");
    let needed_end = raw[needed..]
        .find("\npub(crate) fn ")
        .map(|o| needed + o)
        .expect("another function follows reconcile_needed");
    let needed_flat = flat(&raw[needed..needed_end]);
    assert!(
        needed_flat.contains(
            "lane_reclaim_for(face_lock_intent, omarchy, face_lane_present, stock_wired)"
        ) && needed_flat
            .contains("lane_yield_for(omarchy, face_lane_present, stock_wired, with_lock,"),
        "reconcile_needed appends both lane conditions"
    );
}

/// The apply says WHY no lock line appears while yielding; the wording names
/// the dedicated lane so the omitted surface reads as deliberate.
#[test]
fn the_apply_prints_the_yield_notice() {
    let text = flat(production(&pamwire_src()));
    assert!(
        text.contains("if lock_lane_yielded {"),
        "the apply guards its yield notice on the live yield"
    );
    assert!(
        text.contains("let lock_lane_yielded = want_face_lock && stock_lane_yielded();"),
        "the notice fires only when face-on-lock was wanted and suppressed"
    );
}
