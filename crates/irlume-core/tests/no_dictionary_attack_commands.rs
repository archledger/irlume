// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ADR-0034 §2: irlume stays out of the TPM's dictionary-attack (DA)
//! budget. It never resets or retunes the lockout, which would need the
//! lockout authorization irlume never holds, and it defines no NV counter.
//! The lockout and its counter are shared by every user of the TPM: disk
//! unlock PINs and Windows Hello on a dual-boot machine depend on them.
//!
//! The pinned tss-esapi has no safe wrapper for `TPM2_DictionaryAttackLockReset`
//! or `TPM2_DictionaryAttackParameters`, so a call would go through the raw
//! `Esys_` bindings; this scans every crate's sources for those, for the NV
//! increment command, and for the counter index type.

use std::path::Path;

/// What irlume's sources must never name (ADR-0034 §2).
const FORBIDDEN: [&str; 8] = [
    "Esys_DictionaryAttackLockReset",
    "Esys_DictionaryAttackParameters",
    "dictionary_attack_lock_reset",
    "dictionary_attack_parameters",
    "Esys_NV_Increment",
    "nv_increment",
    "NvIndexType::Counter",
    "TPM2_NT_COUNTER",
];

#[test]
fn no_crate_resets_the_lockout_or_defines_an_nv_counter() {
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
                let text = std::fs::read_to_string(&path).expect("read source");
                scanned += 1;
                for (n, line) in text.lines().enumerate() {
                    for name in FORBIDDEN {
                        if line.contains(name) {
                            offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                        }
                    }
                }
            }
        }
    }
    assert!(scanned > 100, "the scan read only {scanned} files");
    assert!(
        offenders.is_empty(),
        "ADR-0034 §2 forbids these:\n{}",
        offenders.join("\n")
    );
}
