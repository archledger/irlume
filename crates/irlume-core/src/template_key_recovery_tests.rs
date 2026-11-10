// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;

const USER: &str = "recovery-inspection-fixture";
const UID: u32 = 6821;
const PASSPHRASE: &[u8] = b"synthetic recovery passphrase";
const KEY_A: &[u8; 32] = &[11; 32];
const KEY_B: &[u8; 32] = &[22; 32];

struct Sandbox {
    root: PathBuf,
    vars: Vec<(&'static str, Option<OsString>)>,
    _account: crate::account::RememberedUid,
    _tpm: crate::testenv::NoTpm,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Sandbox {
    fn new() -> Self {
        let lock = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = PathBuf::from(crate::test_tmp_dir("recovery-inspection"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mut vars = Vec::new();
        for (name, path) in [
            ("IRLUME_STATE_DIR", root.clone()),
            ("IRLUME_TEMPLATE_KEY_DIR", root.join("keys")),
            ("IRLUME_RECOVERY_DIR", root.join("recovery")),
        ] {
            vars.push((name, std::env::var_os(name)));
            fs::create_dir_all(&path).unwrap();
            std::env::set_var(name, path);
        }
        Self {
            root,
            vars,
            _account: crate::account::remember(USER, UID),
            _tpm: crate::testenv::NoTpm::set(),
            _lock: lock,
        }
    }

    fn recovery(&self, key: &[u8]) {
        let mut env = crate::recovery::wrap(PASSPHRASE, key).unwrap();
        env.uid = Some(UID);
        save_recovery(USER, &env).unwrap();
    }

    fn primary(&self, key: &[u8], version: u32) {
        let mut enrollment = crate::storage::Enrollment::new(USER);
        enrollment.uid = Some(UID);
        let data = crate::storage::serialize_enrollment(&enrollment, Some(key)).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&data).unwrap();
        value["version"] = version.into();
        if version == 2 {
            value.as_object_mut().unwrap().remove("key_id");
        }
        fs::write(
            crate::storage::profile_path(USER),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    fn seal(&self, key: &[u8], uid: u32) {
        // Syntactically valid envelope with synthetic private bytes. The
        // restore preflight reads metadata only and must never unseal it.
        let value = serde_json::json!({
            "version": 1, "uid": uid, "pcrs": [7],
            "public": "", "private": STANDARD.encode(key)
        });
        fs::write(key_path(USER), serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            SealedEnvelope::load(&key_path(USER)).unwrap().uid,
            Some(uid)
        );
    }

    fn secondary(&self, key: Option<&[u8]>, owner: &str) {
        let plain = serde_json::json!({
            "format_version": 1, "owner": owner, "generation": 1,
            "primary_snapshot_sha256": "a".repeat(64), "groups": []
        });
        let value = match key {
            Some(key) => serde_json::json!({
                "format_version": 2, "key_id": irlume_common::sha256_hex(key),
                "enc": STANDARD.encode(crypto::encrypt(key, &serde_json::to_vec(&plain).unwrap()).unwrap())
            }),
            None => plain,
        };
        let path = crate::multi_camera::secondary_store_path(USER);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn snapshot(&self) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        [
            key_path(USER),
            recovery_path(USER),
            crate::storage::profile_path(USER),
            crate::multi_camera::secondary_store_path(USER),
        ]
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).ok();
            (path, bytes)
        })
        .collect()
    }

    fn refused_unchanged(&self, passphrase: &[u8]) -> String {
        let before = self.snapshot();
        let called = Cell::new(false);
        let result = restore_with(USER, passphrase, |user, _, _| {
            called.set(true);
            fs::write(key_path(user), b"synthetic replacing seal").unwrap();
            Ok(())
        });
        let refusal = result.expect_err("the restore must be refused").to_string();
        assert!(!called.get(), "refusal must happen before reseal");
        assert_eq!(self.snapshot(), before, "refusal changed stored bytes");
        refusal
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        for (name, previous) in self.vars.drain(..) {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stale_wrap_cannot_replace_current(version: u32) {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    sandbox.primary(KEY_B, version);
    sandbox.seal(KEY_B, UID);
    sandbox.refused_unchanged(PASSPHRASE);
}

#[test]
fn stale_wrap_cannot_replace_key_for_current_v2_enrollment() {
    stale_wrap_cannot_replace_current(2);
}

#[test]
fn stale_wrap_cannot_replace_key_for_current_v3_enrollment() {
    stale_wrap_cannot_replace_current(3);
}

#[test]
fn matching_recovery_restores_with_missing_or_unreadable_tpm_seal() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_B);
    for version in [2, 3] {
        sandbox.primary(KEY_B, version);
        sandbox.secondary(Some(KEY_B), USER);
        for broken_seal in [false, true] {
            let _ = fs::remove_file(key_path(USER));
            if broken_seal {
                fs::write(key_path(USER), b"broken synthetic seal").unwrap();
            }
            let before = sandbox.snapshot();
            let called = Cell::new(false);
            restore_with(USER, PASSPHRASE, |_, key, uid| {
                called.set(true);
                assert_eq!(key, KEY_B);
                assert_eq!(uid, Some(UID));
                Ok(())
            })
            .unwrap();
            assert!(called.get());
            assert_eq!(sandbox.snapshot(), before, "inspection is read-only");
        }
    }
}

#[test]
fn secondary_store_must_also_authenticate_even_if_primary_is_absent() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    sandbox.secondary(Some(KEY_B), USER);
    sandbox.refused_unchanged(PASSPHRASE);
    sandbox.primary(KEY_A, 3);
    sandbox.refused_unchanged(PASSPHRASE);
}

#[test]
fn matching_key_digest_does_not_substitute_for_gcm_authentication() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    sandbox.primary(KEY_B, 3);
    let path = crate::storage::profile_path(USER);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["key_id"] = irlume_common::sha256_hex(KEY_A).into();
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    let refusal = sandbox.refused_unchanged(PASSPHRASE);
    assert!(refusal.contains("decryption failed"), "{refusal}");
}

#[test]
fn malformed_truncated_and_wrong_owner_enrollments_preserve_state() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    let path = crate::storage::profile_path(USER);
    for data in [b"{".to_vec(), b"not json".to_vec(), b"{}".to_vec()] {
        fs::write(&path, data).unwrap();
        sandbox.refused_unchanged(PASSPHRASE);
    }
    let mut enrollment = crate::storage::Enrollment::new("somebody-else");
    enrollment.uid = Some(UID);
    fs::write(
        &path,
        crate::storage::serialize_enrollment(&enrollment, Some(KEY_A)).unwrap(),
    )
    .unwrap();
    let refusal = sandbox.refused_unchanged(PASSPHRASE);
    assert!(refusal.contains("belongs to another account"), "{refusal}");
    enrollment.user = USER.into();
    enrollment.uid = Some(UID + 1);
    fs::write(
        &path,
        crate::storage::serialize_enrollment(&enrollment, Some(KEY_A)).unwrap(),
    )
    .unwrap();
    let refusal = sandbox.refused_unchanged(PASSPHRASE);
    assert!(refusal.contains("was not restored"), "{refusal}");
}

#[test]
fn unreadable_primary_is_not_absent_and_legacy_plaintext_remains_supported() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    let path = crate::storage::profile_path(USER);
    std::os::unix::fs::symlink(sandbox.root.join("missing-primary"), &path).unwrap();
    sandbox.refused_unchanged(PASSPHRASE);
    fs::remove_file(&path).unwrap();
    for legacy in [false, true] {
        let value = if legacy {
            serde_json::json!({"user": USER, "templates": []})
        } else {
            serde_json::to_value(crate::storage::Enrollment::new(USER)).unwrap()
        };
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        sandbox.secondary(None, USER);
        restore_with(USER, PASSPHRASE, |_, key, _| {
            assert_eq!(key, KEY_A);
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn malformed_recovery_wrong_passphrase_and_non_template_payload_preserve_state() {
    let sandbox = Sandbox::new();
    sandbox.primary(KEY_A, 3);
    fs::write(key_path(USER), b"synthetic existing seal").unwrap();
    sandbox.recovery(KEY_A);
    sandbox.refused_unchanged(b"wrong passphrase");
    for data in [b"{".to_vec(), b"{}".to_vec(), vec![b' '; 4097]] {
        fs::write(recovery_path(USER), data).unwrap();
        sandbox.refused_unchanged(PASSPHRASE);
    }
    sandbox.recovery(&[9; 31]);
    sandbox.refused_unchanged(PASSPHRASE);
}

#[test]
fn absent_enrollment_still_requires_exactly_one_template_key() {
    let sandbox = Sandbox::new();
    assert!(!crate::storage::profile_path(USER).exists());
    assert!(!crate::multi_camera::secondary_store_path(USER).exists());
    for len in [31, 33, 64] {
        sandbox.recovery(&vec![9; len]);
        sandbox.refused_unchanged(PASSPHRASE);
    }
    sandbox.recovery(KEY_A);
    let called = Cell::new(false);
    restore_with(USER, PASSPHRASE, |user, key, _| {
        called.set(true);
        assert_eq!(user, USER);
        assert_eq!(key, KEY_A);
        Ok(())
    })
    .unwrap();
    assert!(
        called.get(),
        "the valid key must reach the same injected sealer"
    );
}

#[test]
fn wrong_recovery_or_seal_uid_and_unsupported_cost_preserve_state() {
    let sandbox = Sandbox::new();
    sandbox.primary(KEY_A, 3);
    sandbox.recovery(KEY_A);
    let mut env = load_recovery(USER).unwrap();
    env.uid = Some(UID + 1);
    save_recovery(USER, &env).unwrap();
    sandbox.refused_unchanged(PASSPHRASE);
    env.uid = Some(UID);
    // One step off the supported cost; `recovery_limits_tests` checks that
    // the refusal comes before any key derivation.
    env.m_cost += 1;
    save_recovery(USER, &env).unwrap();
    sandbox.refused_unchanged(PASSPHRASE);
    sandbox.recovery(KEY_A);
    let mut padded = fs::read(recovery_path(USER)).unwrap();
    padded.resize(4097, b' ');
    fs::write(recovery_path(USER), padded).unwrap();
    sandbox.refused_unchanged(PASSPHRASE);
    sandbox.recovery(KEY_A);
    let seal = serde_json::json!({
        "version": 1, "uid": UID + 1, "pcrs": [7], "public": "", "private": ""
    });
    fs::write(key_path(USER), serde_json::to_vec(&seal).unwrap()).unwrap();
    sandbox.refused_unchanged(PASSPHRASE);
}

#[test]
fn corrupt_or_foreign_secondary_preserves_every_file() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    sandbox.primary(KEY_A, 3);
    let path = crate::multi_camera::secondary_store_path(USER);
    sandbox.secondary(Some(KEY_A), "another-account");
    sandbox.refused_unchanged(PASSPHRASE);
    for data in [
        b"{".to_vec(),
        b"{}".to_vec(),
        br#"{"format_version":99}"#.to_vec(),
    ] {
        fs::write(&path, data).unwrap();
        sandbox.refused_unchanged(PASSPHRASE);
    }
    sandbox.secondary(Some(KEY_B), USER);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["key_id"] = irlume_common::sha256_hex(KEY_A).into();
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    sandbox.refused_unchanged(PASSPHRASE);
    // Valid GCM is insufficient if the decrypted store fails its schema.
    let invalid = serde_json::json!({
        "format_version": 2, "key_id": irlume_common::sha256_hex(KEY_A),
        "enc": STANDARD.encode(crypto::encrypt(KEY_A, b"{}").unwrap())
    });
    fs::write(path, serde_json::to_vec(&invalid).unwrap()).unwrap();
    sandbox.refused_unchanged(PASSPHRASE);
}

#[test]
fn malformed_authenticated_primary_and_unknown_version_preserve_state() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    let path = crate::storage::profile_path(USER);
    for version in [2, 3, 4] {
        let value = serde_json::json!({
            "version": version, "key_id": irlume_common::sha256_hex(KEY_A),
            "enc": STANDARD.encode(crypto::encrypt(KEY_A, b"{}").unwrap())
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        sandbox.refused_unchanged(PASSPHRASE);
    }
}

#[test]
fn absent_stores_still_allow_legacy_unbound_recovery() {
    let _sandbox = Sandbox::new();
    let envelope = crate::recovery::wrap(b"1234", KEY_A).unwrap();
    save_recovery(USER, &envelope).unwrap();
    let called = Cell::new(false);
    restore_with(USER, b"1234", |_, key, uid| {
        called.set(true);
        assert_eq!(key, KEY_A);
        assert_eq!(uid, Some(UID));
        Ok(())
    })
    .unwrap();
    assert!(called.get());
}

#[test]
fn oversized_and_special_stores_refuse_before_reseal() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    for (path, limit) in [
        (
            crate::storage::profile_path(USER),
            crate::storage::RECOVERY_PRIMARY_MAX_BYTES,
        ),
        (
            crate::multi_camera::secondary_store_path(USER),
            crate::multi_camera::MAX_STORE_BYTES as u64,
        ),
    ] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Sparse files: no content is written and no cryptographic work runs.
        let file = fs::File::create(&path).unwrap();
        let too_large = format!("larger than {limit} bytes");
        for (len, over) in [(limit + 1, true), (limit, false)] {
            file.set_len(len).unwrap();
            let called = Cell::new(false);
            let error = restore_with(USER, PASSPHRASE, |_, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();
            assert!(!called.get());
            assert_eq!(error.contains(&too_large), over, "{len}: {error}");
            assert!(error.contains(&path.display().to_string()), "{error}");
            assert_eq!(file.metadata().unwrap().len(), len);
        }
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        sandbox.refused_unchanged(PASSPHRASE);
        fs::remove_dir(&path).unwrap();
    }
}

#[test]
fn a_refusal_names_the_store_and_its_path() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    let refusal = || {
        restore_with(USER, PASSPHRASE, |_, _, _| Ok(()))
            .unwrap_err()
            .to_string()
    };
    sandbox.secondary(Some(KEY_B), USER);
    let path = crate::multi_camera::secondary_store_path(USER);
    assert_eq!(
        refusal(),
        format!(
            "policy: added-camera store {}: the recovery file holds a different template key",
            path.display()
        )
    );
    fs::remove_file(&path).unwrap();
    sandbox.primary(KEY_B, 3);
    let path = crate::storage::profile_path(USER);
    assert_eq!(
        refusal(),
        format!(
            "policy: stored enrollment {}: the recovery file holds a different template key",
            path.display()
        )
    );
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(
        refusal(),
        format!(
            "io: stored enrollment {}: not a regular file",
            path.display()
        )
    );
}

/// Embedding-sized values with full `f32` precision, so most serialize with
/// eight or nine significant digits.
fn floats(state: &mut u32, count: usize) -> Vec<f32> {
    (0..count)
        .map(|_| {
            *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (*state >> 8) as f32 / 134_217_728.0 - 0.0625
        })
        .collect()
}

/// Every profile, with every scan and a calibration in each of four
/// recognizer spaces: the bound the added-camera store sets per profile.
fn full_enrollment() -> crate::storage::Enrollment {
    use crate::storage::{FaceProfile, FaceScan, MAX_PROFILES, MAX_SCANS_PER_PROFILE};
    const DIM: usize = 512;
    let calibration = |state: &mut u32| crate::calib::IrCalibration {
        m: (0..DIM)
            .map(|_| floats(state, MAX_SCANS_PER_PROFILE))
            .collect(),
        n_rows: (0..MAX_SCANS_PER_PROFILE)
            .map(|_| floats(state, DIM))
            .collect(),
        lambda: 0.05,
        fitted_pairs: MAX_SCANS_PER_PROFILE,
    };
    let mut state = 1;
    let mut enrollment = crate::storage::Enrollment::new(USER);
    enrollment.uid = Some(UID);
    for profile in 0..MAX_PROFILES {
        let mut scans = Vec::new();
        let mut ir_calibs = BTreeMap::new();
        for space in 0..crate::multi_camera::MAX_CALIB_SPACES_PER_PROFILE_GROUP {
            let embed_space = format!(
                "embed:{}",
                irlume_common::sha256_hex(format!("recognizer {space}").as_bytes())
            );
            for scan in 0..MAX_SCANS_PER_PROFILE {
                scans.push(FaceScan {
                    name: format!("scan-{scan:02}"),
                    rgb: floats(&mut state, DIM),
                    ir: Some(floats(&mut state, DIM)),
                    ir_space: Some(crate::storage::IR_RAW_SPACE.into()),
                    embed_space: Some(embed_space.clone()),
                    ir_center_edge_ratio: 1.234_567_9,
                    ir_brightness: 123.456_79,
                    pitch: -12.345_679,
                    captured_at: Some(1_800_000_000),
                });
            }
            ir_calibs.insert(embed_space, calibration(&mut state));
        }
        enrollment.profiles.push(FaceProfile {
            name: format!("profile-{profile}"),
            scans,
            ir_calib: Some(calibration(&mut state)),
            ir_calibs,
        });
    }
    enrollment
}

#[test]
fn a_full_primary_fits_the_restore_read_bound() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    let enrollment = full_enrollment();
    let path = crate::storage::profile_path(USER);
    for key in [Some(KEY_A.as_slice()), None] {
        let data = crate::storage::serialize_enrollment(&enrollment, key).unwrap();
        let len = data.len() as u64;
        // Over the added-camera store's bound, within this store's own.
        assert!(len > crate::multi_camera::MAX_STORE_BYTES as u64, "{len}");
        assert!(len <= crate::storage::RECOVERY_PRIMARY_MAX_BYTES, "{len}");
        fs::write(&path, data).unwrap();
        let before = sandbox.snapshot();
        let called = Cell::new(false);
        restore_with(USER, PASSPHRASE, |_, key, uid| {
            called.set(true);
            assert_eq!(key, KEY_A);
            assert_eq!(uid, Some(UID));
            Ok(())
        })
        .unwrap();
        assert!(called.get());
        assert_eq!(sandbox.snapshot(), before, "inspection is read-only");
    }
}

#[test]
fn recovery_reader_accepts_4096_bytes_but_refuses_4097() {
    let _sandbox = Sandbox::new();
    let path = recovery_path(USER);
    fs::write(&path, vec![b' '; 4096]).unwrap();
    assert_eq!(read_recovery_file(&path).unwrap().len(), 4096);
    fs::write(&path, vec![b' '; 4097]).unwrap();
    assert!(read_recovery_file(&path).is_err());
}

#[test]
fn a_symlinked_store_is_refused_without_being_followed() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    sandbox.primary(KEY_A, 3);
    sandbox.secondary(Some(KEY_A), USER);
    restore_with(USER, PASSPHRASE, |_, _, _| Ok(())).unwrap();
    let target = sandbox.root.join("linked-store");
    for (store, path) in [
        ("stored enrollment", crate::storage::profile_path(USER)),
        (
            "added-camera store",
            crate::multi_camera::secondary_store_path(USER),
        ),
    ] {
        fs::rename(&path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            sandbox.refused_unchanged(PASSPHRASE),
            format!(
                "io: {store} {}: a symbolic link, not followed",
                path.display()
            )
        );
        fs::remove_file(&path).unwrap();
        fs::rename(&target, &path).unwrap();
    }
}

#[test]
fn a_fifo_in_a_store_path_is_refused_without_blocking() {
    let sandbox = Sandbox::new();
    sandbox.recovery(KEY_A);
    for (store, path) in [
        ("stored enrollment", crate::storage::profile_path(USER)),
        (
            "added-camera store",
            crate::multi_camera::secondary_store_path(USER),
        ),
    ] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let c_fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c_fifo` is a valid NUL-terminated path, alive for the call.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = restore_with(USER, PASSPHRASE, |_, _, _| Ok(()));
            let _ = tx.send(outcome.map_err(|e| e.to_string()));
        });
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("reading a FIFO must not block");
        assert_eq!(
            outcome,
            Err(format!(
                "io: {store} {}: not a regular file",
                path.display()
            ))
        );
        fs::remove_file(&path).unwrap();
    }
}
