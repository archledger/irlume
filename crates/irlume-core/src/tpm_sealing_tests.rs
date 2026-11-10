// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

#[test]
fn sealing_inputs_are_borrowed_and_create_sessions_are_parent_salted() {
    const SALTED_CREATE: &str = "with_session(ctx,Some(*srk),SessionType::Hmac,|ctx,session|{\
         ctx.execute_with_session(Some(session),|ctx|{\
         ctx.create(*srk,tmpl,None,Some(sensitive),None,None)";
    let source = include_str!("tpm.rs");
    for signature in [
        "pub fn seal_with_pcrs(",
        "pub(crate) fn seal_authorized(",
        "fn seal_pcrlock(",
    ] {
        let after_signature = source.split_once(signature).unwrap().1;
        // rustfmt puts a top-level item's closing brace alone in column 0.
        let function = after_signature.split_once("\n}\n").unwrap().0;
        let body = function.split_once('{').unwrap().1;
        assert!(
            body.trim_start()
                .starts_with("let sensitive = SensitiveData::try_from(secret).map_err(tpm_err)?;"),
            "{signature}: check the borrowed input before any work"
        );
        assert_eq!(
            body.matches("ctx.create(").count(),
            1,
            "{signature}: exactly one Create in the function"
        );
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            compact.contains(SALTED_CREATE),
            "{signature}: Create runs directly inside a session salted with its parent"
        );
    }
    // The helper encrypts the session's parameters exactly when it is salted.
    let helper = source.split_once("fn with_session<T>(").unwrap().1;
    let helper = helper.split_once("\n}\n").unwrap().0;
    for needle in [
        "SymmetricDefinition::AES_128_CFB",
        "let encrypted = salt.is_some();",
        ".with_decrypt(encrypted)",
        ".with_encrypt(encrypted)",
    ] {
        assert!(helper.contains(needle), "with_session: {needle}");
    }
}

fn oversized_secret_error() -> String {
    tpm_err(tss_esapi::Error::WrapperError(
        tss_esapi::WrapperErrorKind::WrongParamSize,
    ))
    .to_string()
}

#[test]
fn oversized_literal_secret_is_rejected_before_tpm_work() {
    let _lock = crate::testenv::ENV_LOCK.lock().unwrap();
    let _no_tpm = crate::testenv::NoTpm::set();
    assert_eq!(SensitiveData::MAX_SIZE, 256);
    let secret = Zeroizing::new([0x5a; 257]);
    let error = seal_with_pcrs(secret.as_slice(), &[7]).unwrap_err();
    assert_eq!(error.to_string(), oversized_secret_error());
}

#[test]
fn oversized_pcrlock_secret_is_rejected_before_policy_work() {
    let _lock = crate::testenv::ENV_LOCK.lock().unwrap();
    let _no_tpm = crate::testenv::NoTpm::set();
    let secret = Zeroizing::new([0x5a; 257]);
    let error = seal_with_pcrlock(secret.as_slice(), 0x0181_c0de).unwrap_err();
    assert_eq!(error.to_string(), oversized_secret_error());
}

#[test]
fn oversized_authorized_secret_is_rejected_before_policy_work() {
    let _lock = crate::testenv::ENV_LOCK.lock().unwrap();
    let _no_tpm = crate::testenv::NoTpm::set();
    let secret = Zeroizing::new([0x5a; 257]);
    let error = seal_authorized(secret.as_slice()).unwrap_err();
    assert_eq!(error.to_string(), oversized_secret_error());
}

#[test]
fn maximum_literal_secret_reaches_tpm_work() {
    let _lock = crate::testenv::ENV_LOCK.lock().unwrap();
    let _no_tpm = crate::testenv::NoTpm::set();
    let context_error = open_context().err().unwrap().to_string();
    let secret = Zeroizing::new([0x5a; 256]);
    assert_eq!(
        seal_with_pcrs(secret.as_slice(), &[7])
            .unwrap_err()
            .to_string(),
        context_error
    );
}
