//! Every state path must honor the `IRLUME_STATE_DIR` sandbox override.
//!
//! The behavioral tests in `template_key.rs` and `keyring.rs` pin the three
//! resolvers that exist today. This one pins the *rule*, so a new state
//! subdirectory added later cannot reintroduce the escape: on 2026-08-05 a
//! sandboxed root `profiles forget-model` emptied the live
//! /var/lib/irlume/template-keys and /var/lib/irlume/recovery, because those two
//! resolvers built from the bare `STATE_DIR` constant while the profile store
//! used the override-aware accessor. The enrollment survived encrypted with its
//! key deleted, which is unrecoverable.

use std::path::Path;

/// Files allowed to build a path from the bare constant, each with a reason.
fn allowed(file: &str) -> Option<&'static str> {
    match file {
        // Defines both the constant and the accessor.
        "lib.rs" => Some("declares STATE_DIR and state_dir()"),
        // Has its own override-aware resolver with a HOME fallback; the constant
        // is only its last resort.
        "storage.rs" => Some("own state_dir() reads IRLUME_STATE_DIR first"),
        _ => None,
    }
}

#[test]
fn no_state_path_is_built_from_the_bare_constant() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf();

    let mut offenders = Vec::new();
    let mut scanned = 0usize;

    for crate_dir in std::fs::read_dir(&root).expect("read crates/") {
        let src = crate_dir.expect("entry").path().join("src");
        if !src.is_dir() {
            continue;
        }
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir") {
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
                let text = std::fs::read_to_string(&path).expect("read source");
                scanned += 1;
                for (n, line) in text.lines().enumerate() {
                    // The escape shape: wrapping the constant in a PathBuf, which
                    // is what you do right before `.join(...)` a state subdir.
                    if line.contains("PathBuf::from(irlume_common::STATE_DIR)")
                        || line.contains("PathBuf::from(crate::STATE_DIR)")
                    {
                        if allowed(&name).is_some() {
                            continue;
                        }
                        offenders.push(format!(
                            "{}:{}: {}",
                            path.strip_prefix(&root).unwrap_or(&path).display(),
                            n + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }

    assert!(
        scanned > 20,
        "scanned only {scanned} files; the walker is broken, not the code"
    );
    assert!(
        offenders.is_empty(),
        "these build a state path from the bare STATE_DIR constant, so \
         IRLUME_STATE_DIR will not contain them. Use irlume_common::state_dir() \
         instead, or add the file to `allowed()` with a reason:\n  {}",
        offenders.join("\n  ")
    );
}
