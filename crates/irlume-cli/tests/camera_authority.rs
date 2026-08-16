//! While the daemon runs, it is the authority on cameras; nobody else opens a
//! video node to find out what it is.
//!
//! Classifying a `/dev/video*` node means OPENING it. On a UVC module that
//! answers EBUSY to a second open, doing that while the daemon streams fails
//! the user's enrollment, and nothing in the logs names the cause. That is
//! issue #187. #300 fixed the TUI and left three CLI callers enumerating:
//! measured with strace, `irlume status` and `status --json` each opened
//! /dev/video0 through video3 with the daemon running, and `setup` probed in
//! its preflight and then enrolled seconds later on the nodes it had just
//! touched.
//!
//! The behavioral proof lives in cli.rs (a fake daemon reporting device paths
//! that exist on no machine, so seeing them proves the answer came over the
//! socket). This one pins the RULE, because the failure mode is a NEW call
//! site added later, which no existing behavioral test would notice.

use std::path::Path;

/// Whether this probe is deliberately exempt.
///
/// The exemption is a marker written AT the call site rather than a list kept
/// here, so the reason sits next to the code and a reader of that code sees it.
/// `// the one permitted probe` marks an accessor's daemon-silent fallback;
/// `// deliberate camera probe:` marks a caller that is about to use the node.
fn allowed(line: &str, preceding: &str) -> bool {
    line.contains("// the one permitted probe")
        || preceding.contains("// deliberate camera probe:")
        || preceding.contains("// the one permitted probe")
}

/// Files where a direct probe is the point rather than a mistake.
fn exempt_file(file: &str) -> bool {
    // Dev capture tools open the camera they are about to record from, so
    // resolving a node is the first step of using it, not a lookup.
    matches!(
        file,
        "blinkcap.rs" | "pad.rs" | "suncal.rs" | "capture.rs" | "calibrate.rs"
    )
}

#[test]
fn no_cli_surface_classifies_a_video_node_behind_the_daemons_back() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut scanned = 0usize;

    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            if exempt_file(&name) {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            scanned += 1;
            let mut in_test_mod = false;
            for (n, line) in text.lines().enumerate() {
                // Tests construct whatever they like; they never touch real /dev.
                if line.trim_start().starts_with("mod tests") {
                    in_test_mod = true;
                }
                if in_test_mod {
                    continue;
                }
                let probes = line.contains("irlume_camera::select_pair")
                    || line.contains("irlume_camera::capabilities");
                if !probes || line.trim_start().starts_with("//") {
                    continue;
                }
                // Look back a few lines: the marker sits in the comment block
                // above the call, where the reasoning belongs.
                let start = n.saturating_sub(4);
                let preceding = text
                    .lines()
                    .skip(start)
                    .take(n - start)
                    .collect::<Vec<_>>()
                    .join("\n");
                if allowed(line, &preceding) {
                    continue;
                }
                offenders.push(format!("{}:{}: {}", name, n + 1, line.trim()));
            }
        }
    }

    assert!(
        scanned > 5,
        "scanned only {scanned} files; the walker is broken, not the code"
    );
    assert!(
        offenders.is_empty(),
        "these classify a video node by opening it, which races the daemon and \
         is EBUSY on strict UVC modules (#187). Use crate::camera_pair() or \
         crate::caps(), which ask the daemon and keep one cached fallback, or \
         add the site to `allowed()` with a reason:\n  {}",
        offenders.join("\n  ")
    );
}
