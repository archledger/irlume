// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Fail-fast startup for non-shippable hardware-evidence builds (ADR-0022).

use std::io::Write;
use std::time::Duration;

/// Terminate with status 1 if a shipped program contains evidence code.
///
/// Call before any other startup action, passing the program's aggregate
/// build marker, never a runtime setting. A false marker has no side effects.
/// A true marker cannot return to a caller that ignores a result. The fixed
/// diagnostic is best-effort; blocked or closed stderr cannot prevent
/// termination. No diagnostic thread is started for a normal build.
pub fn refuse_evidence_startup(marked: bool) {
    if marked {
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        if std::thread::Builder::new()
            .name("evidence-refusal".into())
            .spawn(move || {
                let _ = std::io::stderr().write_all(
                    b"irlume: refusing to run a hardware-evidence build as a shipped component\n",
                );
                let _ = sent.send(());
            })
            .is_ok()
        {
            // Never join a diagnostic writer that can be blocked by its peer.
            let _ = received.recv_timeout(Duration::from_millis(20));
        }
        std::process::exit(1);
    }
}
