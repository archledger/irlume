// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ADR-0036 Phase 2 tests: the profile's templates and policies, the
//! result rules, and on a swtpm of its own, the whole check against EK
//! certificates the test provisions.

use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::structures::NvPublicBuilder;

use super::*;
use crate::ek_cert::test_pki::{self, Ca, Key};

fn digest(alg: NameAlg, parts: &[&[u8]]) -> Vec<u8> {
    let data = parts.concat();
    match alg {
        NameAlg::Sha256 => sha2::Sha256::digest(&data).to_vec(),
        NameAlg::Sha384 => sha2::Sha384::digest(&data).to_vec(),
        NameAlg::Sha512 => sha2::Sha512::digest(&data).to_vec(),
    }
}

// --- the profile's policies and templates ------------------------------------

#[test]
fn the_ek_policy_digests_are_the_profiles() {
    // Credential Profile A.2: PolicyA = PolicySecret(TPM_RH_ENDORSEMENT)
    // with an empty policyRef; PolicyC = PolicyAuthorizeNV over the policy
    // index I-1, I-2 or I-3 (their Names, Table 20); PolicyB = PolicyOR(A, C).
    for (alg, index_name) in [
        (NameAlg::Sha256, "000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f"),
        (
            NameAlg::Sha384,
            "000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c",
        ),
        (
            NameAlg::Sha512,
            "000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560",
        ),
    ] {
        let zero = vec![0u8; alg.digest_len()];
        let secret = digest(alg, &[&zero, &0x0000_0151u32.to_be_bytes(), &0x4000_000Bu32.to_be_bytes()]);
        let a = digest(alg, &[&secret]);
        let c = digest(alg, &[&zero, &0x0000_0192u32.to_be_bytes(), &hex(index_name)]);
        let b = digest(alg, &[&zero, &0x0000_0171u32.to_be_bytes(), &a, &c]);
        let policies = policies(alg);
        assert_eq!((policies.a, policies.b, policies.c), (a, b, c), "{alg:?}");
    }
}

#[test]
fn the_default_templates_are_the_profiles() {
    let zeros = |n: usize| "00".repeat(n);
    let expected = [
        (
            Slot::L1,
            format!(
                "0001000b000300b20020{POLICY_A_SHA256}000600800043001008000000000001 00{}",
                zeros(256)
            ),
        ),
        (
            Slot::L2,
            format!(
                "0023000b000300b20020{POLICY_A_SHA256}00060080004300100003001000 20{}0020{}",
                zeros(32),
                zeros(32)
            ),
        ),
        (
            Slot::H1,
            format!("0001000b000300f20020{POLICY_B_SHA256}0006008000430010080000000000 0000"),
        ),
        (
            Slot::H2,
            format!("0023000b000300f20020{POLICY_B_SHA256}0006008000430010000300100000 0000"),
        ),
        (
            Slot::H3,
            format!("0023000c000300f20030{POLICY_B_SHA384}0006010000430010000400100000 0000"),
        ),
        (
            Slot::H4,
            format!("0023000d000300f20040{POLICY_B_SHA512}0006010000430010000500100000 0000"),
        ),
        (
            Slot::H6,
            format!("0001000c000300f20030{POLICY_B_SHA384}00060100004300100c0000000000 0000"),
        ),
        (
            Slot::H7,
            format!("0001000c000300f20030{POLICY_B_SHA384}0006010000430010100000000000 0000"),
        ),
    ];
    for (slot, hex_text) in expected {
        let template = slot.default_template().unwrap();
        assert_eq!(
            template.marshall().unwrap(),
            hex(&hex_text.replace(' ', "")),
            "{slot:?}"
        );
    }
}

#[test]
fn only_the_assigned_storage_ek_certificates_are_judged_and_the_others_named() {
    let judged: Vec<u32> = JUDGED.iter().map(|(index, _)| *index).collect();
    assert_eq!(
        judged,
        [
            0x01C0_0002,
            0x01C0_000A,
            0x01C0_0012,
            0x01C0_0014,
            0x01C0_0016,
            0x01C0_0018,
            0x01C0_001C,
            0x01C0_001E
        ]
    );
    for (index, kind) in [
        (0x01C0_001A, Some(SkippedKind::Sm2)),
        (0x01C0_0032, Some(SkippedKind::Signing)),
        (0x01C0_005C, Some(SkippedKind::Signing)),
        (0x01C0_007A, Some(SkippedKind::Signing)),
        (0x01C0_0040, Some(SkippedKind::FirmwareLimited)),
        (0x01C0_0046, Some(SkippedKind::FirmwareLimited)),
        (0x01C0_0060, Some(SkippedKind::MlKem)),
        (0x01C0_006A, Some(SkippedKind::MlKem)),
        // Templates, nonces, the Automotive Thin Profile range, the chain
        // indices, the policy indices: none is a certificate irlume names.
        (0x01C0_0003, None),
        (0x01C0_0004, None),
        (0x01C0_0013, None),
        (0x01C0_0020, None),
        (0x01C0_0100, None),
        (0x01C0_7F01, None),
        (0x01C0_7F02, None),
    ] {
        assert_eq!(skipped_kind(index), kind, "{index:#010x}");
    }
    assert_eq!(
        (
            Slot::L1.nonce_index(0x01C0_0002),
            Slot::L1.template_index(0x01C0_0002)
        ),
        (Some(0x01C0_0003), 0x01C0_0004)
    );
    assert_eq!(
        (
            Slot::L2.nonce_index(0x01C0_000A),
            Slot::L2.template_index(0x01C0_000A)
        ),
        (Some(0x01C0_000B), 0x01C0_000C)
    );
    assert_eq!(
        (
            Slot::H3.nonce_index(0x01C0_0016),
            Slot::H3.template_index(0x01C0_0016)
        ),
        (None, 0x01C0_0017)
    );
}

#[test]
fn a_low_range_nonce_fills_the_unique_field_as_the_profile_says() {
    let rsa = with_nonce(Slot::L1.default_template().unwrap(), &[1, 2, 3]).unwrap();
    let Public::Rsa { unique, .. } = &rsa else {
        panic!("RSA")
    };
    let mut expected = vec![1, 2, 3];
    expected.resize(256, 0);
    assert_eq!(unique.value(), expected.as_slice());

    let ecc = with_nonce(Slot::L2.default_template().unwrap(), &[9; 5]).unwrap();
    let Public::Ecc { unique, .. } = &ecc else {
        panic!("ECC")
    };
    let mut x = vec![9; 5];
    x.resize(32, 0);
    assert_eq!(
        (unique.x().value(), unique.y().value()),
        (x.as_slice(), [0u8; 32].as_slice())
    );

    assert!(with_nonce(Slot::L1.default_template().unwrap(), &[0; 257]).is_err());
    assert!(with_nonce(Slot::L2.default_template().unwrap(), &[0; 33]).is_err());
}

#[test]
fn a_template_with_bytes_after_it_is_refused() {
    let bytes = Slot::L2.default_template().unwrap().marshall().unwrap();
    assert_eq!(
        unmarshal_exactly(&bytes).unwrap(),
        Slot::L2.default_template().unwrap()
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(unmarshal_exactly(&longer).is_err());
}

// --- the result rules ----------------------------------------------------------

fn certificate(state: EndorsementState) -> EndorsementCertificate {
    certificate_result(0x01C0_0002, Slot::L1, state, String::new())
}

#[test]
fn the_worst_evidence_decides_and_an_unjudged_certificate_keeps_pass_away() {
    use EndorsementState::{Info, Pass, Unknown, Warn};
    let cases: [(&[EndorsementState], &[u32], EndorsementState); 8] = [
        (&[], &[], Info),
        (&[Pass], &[], Pass),
        (&[Pass, Unknown], &[], Pass),
        (&[Unknown], &[], Unknown),
        (&[Pass, Warn], &[], Warn),
        (&[Unknown, Warn], &[], Warn),
        (&[Pass], &[0x01C0_001E], Unknown),
        (&[Pass, Warn], &[0x01C0_001E], Warn),
    ];
    for (states, not_judged, expected) in cases {
        let certificates: Vec<_> = states.iter().map(|s| certificate(*s)).collect();
        assert_eq!(
            overall(&certificates, not_judged),
            expected,
            "{states:?} {not_judged:?}"
        );
    }
}

#[test]
fn only_the_tpm_refusing_the_credential_is_evidence() {
    let rc = |raw: u32| tss_esapi::Error::Tss2Error(Tss2ResponseCode::from(raw));
    let credential = [7u8; 32];
    assert!(matches!(
        classify(
            Ok(Digest::try_from(credential.to_vec()).unwrap()),
            &credential
        ),
        SameTpm::Passed
    ));
    assert!(matches!(
        classify(Ok(Digest::try_from(vec![8u8; 32]).unwrap()), &credential),
        SameTpm::Failed(_)
    ));
    // TPM_RC_INTEGRITY on credentialBlob; TPM_RC_VALUE on the secret.
    for refused in [0x1DF, 0x2C4] {
        assert!(
            matches!(classify(Err(rc(refused)), &credential), SameTpm::Failed(_)),
            "{refused:#x}"
        );
    }
    // TPM_RC_VALUE elsewhere, TPM_RC_LOCKOUT, TPM_RC_AUTH_UNAVAILABLE,
    // TPM_RC_POLICY_FAIL on the EK's session, TPM_RC_OBJECT_MEMORY, TPM_RC_RETRY.
    for unjudged in [0x1C4, 0x921, 0x12F, 0xA9D, 0x902, 0x922] {
        assert!(
            matches!(classify(Err(rc(unjudged)), &credential), SameTpm::NotRun(_)),
            "{unjudged:#x}"
        );
    }
    assert_eq!(parameter_number(Tss2ResponseCode::from(0x2C4)), Some(2));
    assert_eq!(parameter_number(Tss2ResponseCode::from(0x1DF)), Some(1));
    assert_eq!(parameter_number(Tss2ResponseCode::from(0x921)), None);
    // A session-numbered format-one code is not a parameter.
    assert_eq!(parameter_number(Tss2ResponseCode::from(0xA9D)), None);
}

// --- on a swtpm of its own -------------------------------------------------------

/// The TPM the tests provision: a swtpm of its own, since they create
/// platform NV indices, persist endorsement primaries and change the
/// endorsement authorization. Undoes all three when dropped.
struct OwnSwtpm {
    _env: std::sync::MutexGuard<'static, ()>,
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    dir: String,
    defined: Vec<u32>,
    persisted: Vec<u32>,
    endorsement_auth: bool,
}

impl OwnSwtpm {
    fn new(name: &str) -> Self {
        assert!(
            std::env::var("IRLUME_TCTI").is_ok_and(|tcti| tcti.starts_with("swtpm:")),
            "this test writes NV indices: run it on swtpm, never on a real TPM"
        );
        assert_eq!(
            std::env::var("IRLUME_TEST_OWN_SWTPM").as_deref(),
            Ok("1"),
            "this test provisions platform NV indices: give it a swtpm of its own"
        );
        let env = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = crate::test_tmp_dir(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // No recorded DA-exempt key: the check finds the original storage
        // key read-only, as on a machine before ADR-0034's key is persisted.
        let previous = vec![("IRLUME_STATE_DIR", std::env::var_os("IRLUME_STATE_DIR"))];
        std::env::set_var("IRLUME_STATE_DIR", &dir);
        Self {
            _env: env,
            previous,
            dir,
            defined: Vec::new(),
            persisted: Vec::new(),
            endorsement_auth: false,
        }
    }

    fn ctx(&self) -> TpmContext {
        open_context().expect("the swtpm")
    }

    fn manufacturer(&self) -> u32 {
        self.ctx()
            .get_tpm_property(PropertyTag::Manufacturer)
            .unwrap()
            .unwrap()
    }

    /// The EK `template` derives, as its certificate would state it.
    fn ek(&self, template: Public) -> EkPublicKey {
        let mut ctx = self.ctx();
        let created = ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
            })
            .unwrap();
        ctx.flush_context(created.key_handle.into()).unwrap();
        public_key(&created.out_public).unwrap()
    }

    /// Persist the EK `template` derives at `handle`, as a provisioning tool
    /// does, and return its key.
    fn persist(&mut self, template: Public, handle: u32) -> EkPublicKey {
        let mut ctx = self.ctx();
        let created = ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
            })
            .unwrap();
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                created.key_handle.into(),
                Persistent::Persistent(PersistentTpmHandle::new(handle).unwrap()),
            )
        })
        .unwrap();
        self.persisted.push(handle);
        ctx.flush_context(created.key_handle.into()).unwrap();
        public_key(&created.out_public).unwrap()
    }

    /// Define `index` as the platform does for EK credentials and write
    /// `data` to it.
    fn provision(&mut self, index: u32, data: &[u8]) {
        let mut ctx = self.ctx();
        let attributes = NvIndexAttributesBuilder::new()
            .with_pp_write(true)
            .with_pp_read(true)
            .with_owner_read(true)
            .with_auth_read(true)
            .with_no_da(true)
            .with_platform_create(true)
            .build()
            .unwrap();
        let public = NvPublicBuilder::new()
            .with_nv_index(NvIndexTpmHandle::new(index).unwrap())
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attributes)
            .with_data_area_size(data.len())
            .build()
            .unwrap();
        let nv = ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.nv_define_space(Provision::Platform, None, public)
            })
            .unwrap();
        self.defined.push(index);
        for (i, chunk) in data.chunks(512).enumerate() {
            let offset = u16::try_from(i * 512).unwrap();
            ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.nv_write(
                    NvAuth::Platform,
                    nv,
                    MaxNvBuffer::try_from(chunk.to_vec()).unwrap(),
                    offset,
                )
            })
            .unwrap();
        }
    }

    fn remove(&mut self, index: u32) {
        let mut ctx = self.ctx();
        let object = ctx
            .tr_from_tpm_public(TpmHandle::NvIndex(NvIndexTpmHandle::new(index).unwrap()))
            .unwrap();
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.nv_undefine_space(Provision::Platform, NvIndexHandle::from(object))
        })
        .unwrap();
        self.defined.retain(|defined| *defined != index);
    }

    fn set_endorsement_auth(&mut self, set: bool) {
        let mut ctx = self.ctx();
        let secret = Auth::try_from(b"endorsement".to_vec()).unwrap();
        if !set {
            ctx.tr_set_auth(ObjectHandle::Endorsement, secret).unwrap();
        }
        let new = if set {
            Auth::try_from(b"endorsement".to_vec()).unwrap()
        } else {
            Auth::default()
        };
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.hierarchy_change_auth(AuthHandle::Endorsement, new)
        })
        .unwrap();
        self.endorsement_auth = set;
    }
}

impl Drop for OwnSwtpm {
    fn drop(&mut self) {
        if self.endorsement_auth {
            self.set_endorsement_auth(false);
        }
        for index in self.defined.clone() {
            self.remove(index);
        }
        let mut ctx = self.ctx();
        for handle in self.persisted.drain(..) {
            let persistent = PersistentTpmHandle::new(handle).unwrap();
            let object = ctx
                .tr_from_tpm_public(TpmHandle::Persistent(persistent))
                .unwrap();
            ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.evict_control(Provision::Owner, object, Persistent::Persistent(persistent))
            })
            .unwrap();
        }
        for (var, value) in self.previous.drain(..) {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn test_ca() -> (Ca, Ca) {
    let root = test_pki::root("Test TPM Vendor Root CA", Key::p384(1));
    let issuing = test_pki::intermediate("Test TPM EK CA", Key::p256(2), &root);
    (root, issuing)
}

fn anchors_of(roots: &[&Ca], intermediates: &[&Ca]) -> Anchors {
    test_pki::anchors(roots, intermediates)
}

fn run_check(anchors: &Anchors) -> EndorsementReport {
    endorsement_report(anchors, &mut || true)
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_rsa_and_ecc_certificates_pass_with_their_ca_and_are_unknown_without() {
    let mut tpm = OwnSwtpm::new("endorsement-pass");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    // L-1: RSA-OAEP, PolicySecret. H-3: ECDH on P-384, PolicySecret and
    // PolicyOR, SHA-384 and AES-256.
    for slot in [Slot::L1, Slot::H3] {
        let ek = tpm.ek(slot.default_template().unwrap());
        let index = JUDGED.iter().find(|(_, s)| *s == slot).unwrap().0;
        tpm.provision(
            index,
            &test_pki::ek_certificate_for(&ek, &issuing, manufacturer),
        );
    }
    let report = run_check(&anchors_of(&[&root], &[&issuing]));
    assert_eq!(report.state, EndorsementState::Pass, "{report:#?}");
    assert_eq!(report.certificates.len(), 2);
    for certificate in &report.certificates {
        assert_eq!(
            certificate.state,
            EndorsementState::Pass,
            "{certificate:#?}"
        );
        let tpm = certificate.tpm.as_ref().unwrap();
        assert_eq!(
            (tpm.manufacturer, tpm.model.as_str()),
            (manufacturer, "swtpm")
        );
        assert_eq!(certificate.chain.len(), 2, "the issuing CA and the root");
    }
    assert_eq!(
        (
            report.certificates[0].key.as_str(),
            report.certificates[1].key.as_str()
        ),
        ("RSA 2048", "ECC NIST P-384")
    );

    // With only irlume's vendor list, the test CA is unknown, never "not
    // genuine".
    let report = run_check(Anchors::shipped());
    assert_eq!(report.state, EndorsementState::Unknown, "{report:#?}");
    assert!(report
        .certificates
        .iter()
        .all(|c| c.state == EndorsementState::Unknown));
    assert!(
        report.certificates[0]
            .detail
            .contains("not in irlume's list"),
        "{report:#?}"
    );
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_a_certificate_for_another_key_warns() {
    let mut tpm = OwnSwtpm::new("endorsement-mismatch");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    // The L-2 EK's certificate stored at the L-1 index: its key is not the
    // one the L-1 template derives.
    let other = tpm.ek(Slot::L2.default_template().unwrap());
    tpm.provision(
        0x01C0_0002,
        &test_pki::ek_certificate_for(&other, &issuing, manufacturer),
    );
    let report = run_check(&anchors_of(&[&root], &[&issuing]));
    assert_eq!(report.state, EndorsementState::Warn, "{report:#?}");
    assert!(report.certificates[0]
        .detail
        .contains("not for this TPM's endorsement key"));
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_a_credential_bound_to_another_key_is_refused_by_the_tpm() {
    let tpm = OwnSwtpm::new("endorsement-integrity");
    for slot in [Slot::L1, Slot::H3] {
        let mut ctx = tpm.ctx();
        let created = ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create_primary(
                    Hierarchy::Endorsement,
                    slot.default_template().unwrap(),
                    None,
                    None,
                    None,
                    None,
                )
            })
            .unwrap();
        let ek = EkObject {
            handle: created.key_handle,
            transient: true,
            public: created.out_public,
        };
        let name_alg =
            NameAlg::from_tpm_alg(u16::from(ek.public.name_hashing_algorithm())).unwrap();
        let key = public_key(&ek.public).unwrap();
        let symmetric = if slot == Slot::L1 {
            EkSymmetric::Aes128Cfb
        } else {
            EkSymmetric::Aes256Cfb
        };
        let target = EkTarget {
            name_alg,
            symmetric,
            key: &key,
        };
        let mut always = || true;
        let mut run = Run {
            ctx: &mut ctx,
            before_command: &mut always,
        };
        let (storage, _, flush) = read_only_storage_key(run.ctx).unwrap();
        // Bound to a Name the storage key does not have.
        let mut wrong_name = run.ctx.read_public(storage).unwrap().1.value().to_vec();
        *wrong_name.last_mut().unwrap() ^= 1;
        let made =
            tpm_credential::make_credential(&target, &wrong_name, &[5; 32], &mut rand::rng())
                .unwrap();
        let session = run
            .ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::Null,
                hashing(name_alg),
            )
            .unwrap()
            .unwrap();
        let route = if slot == Slot::L1 {
            PolicyRoute::Secret
        } else {
            PolicyRoute::SecretOr
        };
        let outcome = satisfy_and_activate(
            &mut run,
            &ek,
            storage,
            session,
            &made,
            &policies(name_alg),
            route,
        );
        let _ = run.ctx.flush_context(SessionHandle::from(session).into());
        let Ok(Err(SessionStep::Activate(e))) = outcome else {
            panic!("the TPM should refuse the credential");
        };
        assert!(
            matches!(classify(Err(e), &[5; 32]), SameTpm::Failed(why) if why.contains("TPM_RC_INTEGRITY"))
        );
        if flush {
            let _ = run.ctx.flush_context(storage.into());
        }
        let _ = run.ctx.flush_context(ek.handle.into());
    }
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_with_the_endorsement_authorization_set_nothing_is_tried() {
    let mut tpm = OwnSwtpm::new("endorsement-auth");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    let ek = tpm.ek(Slot::L1.default_template().unwrap());
    tpm.provision(
        0x01C0_0002,
        &test_pki::ek_certificate_for(&ek, &issuing, manufacturer),
    );
    let anchors = anchors_of(&[&root], &[&issuing]);

    tpm.set_endorsement_auth(true);
    let mut commands = 0;
    let report = endorsement_report(&anchors, &mut || {
        commands += 1;
        true
    });
    assert_eq!(report.state, EndorsementState::Unknown);
    assert!(
        report
            .stopped
            .as_deref()
            .unwrap()
            .contains("authorization is set"),
        "{report:#?}"
    );
    assert!(report.certificates.is_empty());
    assert_eq!(commands, 3, "three property reads, nothing else");

    // Cleared in the same boot, the next check runs the test.
    tpm.set_endorsement_auth(false);
    assert_eq!(run_check(&anchors).state, EndorsementState::Pass);
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_a_low_range_template_and_nonce_derive_the_certified_ek() {
    let mut tpm = OwnSwtpm::new("endorsement-nonce");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    let nonce = [0xA5, 0x5A, 0x01, 0x02];
    let template = Slot::L1.default_template().unwrap();
    let with = tpm.ek(with_nonce(template.clone(), &nonce).unwrap());
    let without = tpm.ek(template.clone());
    assert_ne!(with, without, "the nonce makes another EK");
    tpm.provision(0x01C0_0004, &template.marshall().unwrap());
    tpm.provision(0x01C0_0003, &nonce);
    tpm.provision(
        0x01C0_0002,
        &test_pki::ek_certificate_for(&with, &issuing, manufacturer),
    );
    let report = run_check(&anchors_of(&[&root], &[&issuing]));
    assert_eq!(report.state, EndorsementState::Pass, "{report:#?}");
    // Without the nonce index, the default template derives another key.
    tpm.remove(0x01C0_0003);
    assert_eq!(
        run_check(&anchors_of(&[&root], &[&issuing])).state,
        EndorsementState::Warn
    );
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_a_persistent_ek_with_the_certified_key_is_used() {
    let mut tpm = OwnSwtpm::new("endorsement-persistent");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    // A persistent EK from a template the TPM no longer records (its nonce
    // is not in NV), behind another endorsement primary: only finding it
    // by its key gives the certified EK.
    let template = Slot::L1.default_template().unwrap();
    let persisted = tpm.persist(with_nonce(template.clone(), &[0x5A]).unwrap(), 0x8101_0002);
    assert_ne!(persisted, tpm.ek(template));
    tpm.persist(Slot::L2.default_template().unwrap(), 0x8101_0001);
    tpm.provision(
        0x01C0_0002,
        &test_pki::ek_certificate_for(&persisted, &issuing, manufacturer),
    );
    let report = run_check(&anchors_of(&[&root], &[&issuing]));
    assert_eq!(report.state, EndorsementState::Pass, "{report:#?}");
    // The persistent objects stay.
    let mut ctx = tpm.ctx();
    let (data, _) = ctx
        .get_capability(CapabilityType::Handles, EK_PERSISTENT.0, 8)
        .unwrap();
    let CapabilityData::Handles(list) = data else {
        panic!("handles")
    };
    let handles: Vec<u32> = list.into_inner().into_iter().map(u32::from).collect();
    assert_eq!(handles, [0x8101_0001, 0x8101_0002]);
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_the_chain_indices_supply_the_issuing_ca() {
    let mut tpm = OwnSwtpm::new("endorsement-chain");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    let ek = tpm.ek(Slot::L1.default_template().unwrap());
    tpm.provision(
        0x01C0_0002,
        &test_pki::ek_certificate_for(&ek, &issuing, manufacturer),
    );
    let only_root = anchors_of(&[&root], &[]);
    assert_eq!(run_check(&only_root).state, EndorsementState::Unknown);
    // The CA split across two chain indices.
    let (first, second) = issuing.der.split_at(100);
    tpm.provision(0x01C0_0100, first);
    tpm.provision(0x01C0_0101, second);
    let report = run_check(&only_root);
    assert_eq!(report.state, EndorsementState::Pass, "{report:#?}");
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_a_fifth_storage_certificate_is_named_and_keeps_pass_away() {
    let mut tpm = OwnSwtpm::new("endorsement-five");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    for slot in [Slot::L1, Slot::L2, Slot::H1, Slot::H2, Slot::H3] {
        let ek = tpm.ek(slot.default_template().unwrap());
        let index = JUDGED.iter().find(|(_, s)| *s == slot).unwrap().0;
        tpm.provision(
            index,
            &test_pki::ek_certificate_for(&ek, &issuing, manufacturer),
        );
    }
    let report = run_check(&anchors_of(&[&root], &[&issuing]));
    assert_eq!(report.certificates.len(), 4);
    assert!(
        report
            .certificates
            .iter()
            .all(|c| c.state == EndorsementState::Pass),
        "{report:#?}"
    );
    assert_eq!(report.not_judged, [0x01C0_0016]);
    assert_eq!(report.state, EndorsementState::Unknown);
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_other_indices_are_never_taken_for_a_certificate() {
    let mut tpm = OwnSwtpm::new("endorsement-other");
    let (_, issuing) = test_ca();
    // A signing EK's certificate, and data at a policy index.
    tpm.provision(0x01C0_0032, &issuing.der);
    tpm.provision(0x01C0_7F02, &[0x00, 0x0b, 1, 2, 3]);
    let report = run_check(Anchors::shipped());
    assert_eq!(report.state, EndorsementState::Info, "{report:#?}");
    assert!(report.certificates.is_empty());
    assert_eq!(
        report.skipped,
        [SkippedCertificate {
            index: 0x01C0_0032,
            kind: SkippedKind::Signing,
        }]
    );
}

#[test]
#[ignore = "needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_endorsement_stops_before_the_next_command_once_the_deadline_passes() {
    let mut tpm = OwnSwtpm::new("endorsement-deadline");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    let ek = tpm.ek(Slot::L1.default_template().unwrap());
    tpm.provision(
        0x01C0_0002,
        &test_pki::ek_certificate_for(&ek, &issuing, manufacturer),
    );
    let anchors = anchors_of(&[&root], &[&issuing]);
    let mut all = 0;
    assert_eq!(
        endorsement_report(&anchors, &mut || {
            all += 1;
            true
        })
        .state,
        EndorsementState::Pass
    );
    // Every cut-off point, from before the first command to before the last.
    for allowed in [0, 3, all / 2, all - 1] {
        let mut asked = 0;
        let report = endorsement_report(&anchors, &mut || {
            asked += 1;
            asked <= allowed
        });
        assert_eq!(
            report.state,
            EndorsementState::Unknown,
            "{allowed}: {report:#?}"
        );
        assert!(
            report
                .stopped
                .as_deref()
                .unwrap()
                .contains("ran out of time"),
            "{allowed}"
        );
        assert_eq!(asked, allowed + 1, "no command after the deadline");
    }
}

/// In dictionary-attack lockout, the EK's policy still works, as it asks
/// for no authValue: under ADR-0034's DA-exempt key both policy routes
/// pass. Known only by the original key, which is not exempt, the test is
/// not run. Its own swtpm, as the lockout lasts 1000 s and irlume never
/// ends one (ADR-0034 section 2).
#[test]
#[ignore = "puts the TPM in lockout: needs a swtpm of its own (IRLUME_TEST_OWN_SWTPM=1 with scripts/with-swtpm.sh); CI runs it so"]
fn tpm_lockout_the_endorsement_check_runs_only_under_the_da_exempt_key() {
    let mut tpm = OwnSwtpm::new("endorsement-lockout");
    let manufacturer = tpm.manufacturer();
    let (root, issuing) = test_ca();
    for slot in [Slot::L1, Slot::H3] {
        let ek = tpm.ek(slot.default_template().unwrap());
        let index = JUDGED.iter().find(|(_, s)| *s == slot).unwrap().0;
        tpm.provision(
            index,
            &test_pki::ek_certificate_for(&ek, &issuing, manufacturer),
        );
    }
    let anchors = anchors_of(&[&root], &[&issuing]);
    let dirs = crate::tpm::tests::StateDirs::new("endorsement-lockout-state");
    // An envelope makes irlumed's start persist the DA-exempt key.
    dirs.store(
        "alice",
        &crate::tpm::seal_with_pcrs(b"an envelope", &[]).expect("seal"),
    );
    assert!(matches!(
        crate::storage_key::ensure_at_start().expect("the step"),
        Some(crate::storage_key::Outcome::Persisted { .. })
    ));
    let (handle, name) = crate::storage_key::recorded_key().expect("recorded");
    let mut ctx = tpm.ctx();
    let key = da_exempt_key_at(&mut ctx, handle, &name, true)
        .expect("probe")
        .expect("the DA-exempt key");
    crate::tpm::tests::fail_until_lockout(&mut ctx, key);
    drop(ctx);
    assert!(lockout_state().expect("lockout state").in_lockout);

    let report = run_check(&anchors);
    assert_eq!(report.state, EndorsementState::Pass, "{report:#?}");
    assert_eq!(report.certificates.len(), 2);

    // Without the record, only the original key is known.
    let empty = crate::test_tmp_dir("endorsement-lockout-unrecorded");
    let _ = std::fs::remove_dir_all(&empty);
    std::fs::create_dir_all(&empty).unwrap();
    std::env::set_var("IRLUME_STATE_DIR", &empty);
    let report = run_check(&anchors);
    let _ = std::fs::remove_dir_all(&empty);
    assert_eq!(report.state, EndorsementState::Unknown, "{report:#?}");
    assert_eq!(report.certificates.len(), 2);
    for certificate in &report.certificates {
        assert_eq!(certificate.state, EndorsementState::Unknown);
        assert!(
            certificate
                .detail
                .contains("dictionary-attack lockout, and irlume's storage key is not exempt"),
            "{certificate:#?}"
        );
    }
    assert!(lockout_state().expect("lockout state").in_lockout);
}
