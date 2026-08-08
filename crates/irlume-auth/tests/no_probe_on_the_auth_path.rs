// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Authentication never runs the capture-mode PROBE.
//!
//! Issue #100 asks irlume to choose a camera's capture mode on its own, and
//! states the one rule that makes automating it safe: "Never during an
//! authentication. Calibration holds the camera for tens of seconds. Firing it
//! mid-login turns a working login into a failure, which is the exact class of
//! problem this is meant to prevent."
//!
//! The automatic switch obeys that by inferring from captures that already
//! happened and writing one config key, never by measuring. Nothing about that
//! is self-enforcing, though: the failure mode is a NEW call site added later by
//! someone who reaches for `measure_contention` because it is right there in the
//! re-export list. No behavioural test would notice, because the probe needs a
//! camera and CI has none. So this pins the rule instead, in the idiom of
//! `irlume-cli`'s `camera_authority.rs`.

use std::path::Path;

/// The probe entry points that hold the camera for the length of a measurement.
const PROBES: [&str; 3] = [
    "measure_contention",
    "measure_contention_with_progress",
    "measure_contention_impl",
];

/// A line that only NAMES a probe rather than calling one: the `pub use`
/// re-export that hands it to the daemon, and any comment or doc comment
/// explaining why the auth path does not use it.
fn names_without_calling(line: &str, in_reexport: bool) -> bool {
    let t = line.trim_start();
    in_reexport || t.starts_with("//") || t.starts_with("/*") || t.starts_with('*')
}

#[test]
fn the_authentication_path_never_runs_the_capture_mode_probe() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let text = std::fs::read_to_string(&src).expect("read irlume-auth/src/lib.rs");

    let mut in_reexport = false;
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut mentions = 0usize;

    for (n, line) in text.lines().enumerate() {
        scanned += 1;
        // The one block allowed to name every probe: it re-exports them for the
        // daemon's `camera-tune` request, which is a deliberate, user-initiated
        // measurement and not part of authenticating anyone.
        if line.contains("pub use irlume_camera::{") {
            in_reexport = true;
        }
        let hit = PROBES.iter().any(|p| line.contains(p));
        if hit {
            mentions += 1;
            if !names_without_calling(line, in_reexport) {
                offenders.push(format!("{}:{}: {}", src.display(), n + 1, line.trim()));
            }
        }
        if in_reexport && line.contains("};") {
            in_reexport = false;
        }
    }

    // A scanner that silently read nothing would pass this test forever.
    assert!(
        scanned > 1000,
        "expected to scan the whole file, saw {scanned} lines"
    );
    assert!(
        mentions > 0,
        "the probe names vanished from this crate; if they were renamed, update PROBES \
         or this test stops guarding anything"
    );
    assert!(
        offenders.is_empty(),
        "the authentication path must never run the capture-mode probe: it holds the camera \
         for the length of a measurement, and #100 forbids that mid-login. The automatic \
         switch infers from captures that already happened instead. Offending call sites:\n{}",
        offenders.join("\n")
    );
}
