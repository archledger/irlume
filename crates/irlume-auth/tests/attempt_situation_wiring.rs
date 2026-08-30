// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Every failed authentication attempt emits one situation line (#616 step 2).
//!
//! The situation line is journal-only reporting: it must never gate, score,
//! or retry anything, and it must fire exactly once per FAILED attempt (a
//! granted attempt says nothing). The emission point is the grace-retry loop
//! where "one attempt" is defined, over a facts snapshot the attempt set
//! after its assessment. No behavioural test can drive a full attempt without
//! cameras, so this pins the wiring the way `no_probe_on_the_auth_path.rs`
//! pins the probe rule: against the source, in `irlume-cli`'s
//! `camera_authority.rs` idiom.

use std::path::Path;

#[test]
fn every_failed_attempt_emits_exactly_one_situation_line() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let text = std::fs::read_to_string(&src).expect("read irlume-auth/src/lib.rs");

    // The snapshot is set where the assessment binds, so every Outcome the
    // attempt returns reads facts from THIS attempt, never a stale one.
    let once_start = text
        .find("    fn authenticate_once(")
        .expect("authenticate_once exists");
    let once_end = text[once_start..]
        .find("\n    fn ")
        .map(|offset| once_start + offset)
        .expect("another method follows authenticate_once");
    let once = &text[once_start..once_end];
    let snapshot = once
        .find("last_attempt_facts")
        .expect("the attempt stores its facts snapshot");
    let assessment_bound = once
        .find("Ok(assessment) => assessment")
        .expect("the assessment binds before the snapshot");
    assert!(snapshot > assessment_bound);

    // The emission lives in the retry loop, guarded by !out.granted, so a
    // grant never logs a situation and every failure logs exactly one.
    let loop_start = text
        .find("    fn authentication_attempt_loop(")
        .expect("the grace-retry loop exists");
    let loop_end = text[loop_start..]
        .find("\n    fn authenticate_once(")
        .map(|offset| loop_start + offset)
        .expect("authenticate_once follows the loop");
    let retry_loop = &text[loop_start..loop_end];
    let guard = retry_loop
        .find("if !out.granted {")
        .expect("the loop guards the emission on a failed outcome");
    let emission = retry_loop[guard..]
        .find("attempt_situation_line")
        .expect("the loop emits the situation line inside the guard");
    assert!(emission < retry_loop[guard..].len());
    // And exactly one emission site in the production code: the line must
    // not be doubled anywhere else. The in-file unit tests call it too, so
    // the count is taken over the production region only.
    let production = &text[..text.find("\nmod tests").expect("tests module exists")];
    assert_eq!(
        production.matches("attempt_situation_line(").count(),
        2,
        "attempt_situation_line must appear exactly twice in production code: its \
         definition and the single emission site"
    );
}

/// #616 step 3: the FINAL failed attempt's situation must be readable from
/// the engine, because the daemon puts it on the wire and pam_irlume turns
/// it into action wording at the prompt. The store happens under the SAME
/// `!out.granted` guard that journals the line, so the wire can never
/// disagree with the journal about what the situation was, and a granted
/// final attempt clears it so a stale label can never reach a prompt.
#[test]
fn the_final_failed_attempts_situation_is_exposed_for_the_prompt() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let text = std::fs::read_to_string(&src).expect("read irlume-auth/src/lib.rs");

    // The engine keeps the classified situation beside the facts snapshot.
    assert!(
        text.contains("    last_attempt_situation: Option<AttemptSituation>,"),
        "the engine must store the classified situation for the wire"
    );

    // The store and the clear both live in the retry loop: set under the
    // failed-attempt guard that emits the journal line, cleared on a grant.
    // Whitespace-flattened so rustfmt's line wrapping cannot break the
    // needles.
    let loop_start = text
        .find("    fn authentication_attempt_loop(")
        .expect("the grace-retry loop exists");
    let loop_end = text[loop_start..]
        .find("\n    fn authenticate_once(")
        .map(|offset| loop_start + offset)
        .expect("authenticate_once follows the loop");
    let retry_loop = &text[loop_start..loop_end];
    let flat = retry_loop.split_whitespace().collect::<Vec<_>>().join(" ");
    let guard = flat
        .find("if !out.granted {")
        .expect("the loop guards the emission on a failed outcome");
    let store = flat[guard..]
        .find("self.last_attempt_situation = Some(auth_attempt_situation(")
        .expect("the guard stores the classified situation for the wire");
    // And it stores before the guard closes: the next statement after the
    // store must still be inside the guard (the else-clear follows the
    // guard's close, never the store).
    let guard_close = flat[guard..]
        .find("} else {")
        .expect("the guard closes with an else for the grant clear");
    assert!(store < guard_close, "the store sits inside the guard");
    assert!(
        flat.contains("self.last_attempt_situation = None;"),
        "a granted final attempt must clear the stored situation"
    );

    // Exactly one public getter in production: the label the daemon wires.
    let production = &text[..text.find("\nmod tests").expect("tests module exists")];
    assert_eq!(
        production
            .matches("pub fn last_attempt_situation_label")
            .count(),
        1,
        "exactly one public situation getter may exist"
    );
}
