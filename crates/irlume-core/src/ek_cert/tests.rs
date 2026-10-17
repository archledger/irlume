// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ADR-0036 Phase 1 acceptance tests: generated chains, the EK certificate
//! profile, the NV readers and the shipped anchors' own consistency.

use rsa::traits::PublicKeyParts;

use super::test_pki::*;
use super::*;

/// "STM " as a TCG vendor ID.
const MFR: u32 = 0x5354_4D20;

fn verify(leaf: &[u8], tpm_chain: &[&[u8]], anchors: &Anchors) -> ChainVerdict {
    EkCertificate::from_der(leaf)
        .unwrap()
        .verify(tpm_chain, anchors, MFR)
}

/// A standard three-level ECDSA chain: P-384 root, P-256 intermediate.
fn ecdsa_chain() -> (Ca, Ca) {
    let root = root("Test ECC Root CA", Key::p384(1));
    let issuing = intermediate("Test ECC EK CA 01", Key::p256(2), &root);
    (root, issuing)
}

fn assert_refused(verdict: ChainVerdict, expected: Refusal) {
    assert_eq!(verdict, ChainVerdict::Refused(expected));
}

fn leaf_refused(verdict: ChainVerdict, expected: LeafProblem) {
    assert_refused(verdict, Refusal::Leaf(expected));
}

// --- chains that verify -----------------------------------------------------

#[test]
fn an_ecdsa_chain_verifies_to_its_root() {
    let (root, issuing) = ecdsa_chain();
    let leaf = ek(Key::p256(3), &issuing);
    let ChainVerdict::Verified(chain) = verify(&leaf, &[], &anchors(&[&root], &[&issuing])) else {
        panic!("the chain should verify");
    };
    assert_eq!(
        chain.tpm,
        TpmIdentity {
            manufacturer: MFR,
            model: "ST33HTPHAHD4".into(),
            version: "id:00490004".into(),
        }
    );
    assert_eq!(chain.tpm.firmware_version_1(), Some(0x0049_0004));
    let path: Vec<(&str, CertificateSource)> = chain
        .path
        .iter()
        .map(|link| (link.name.as_str(), link.source))
        .collect();
    assert_eq!(
        path,
        [
            ("the EK certificate", CertificateSource::Leaf),
            ("CN=Test ECC EK CA 01", CertificateSource::Listed),
            ("CN=Test ECC Root CA", CertificateSource::Root),
        ]
    );
}

#[test]
fn an_rsa_chain_verifies_to_its_root() {
    let root = root("Test RSA Root CA", Key::rsa(0));
    let issuing = intermediate("Test RSA EK CA 01", Key::rsa(1), &root);
    let leaf = ek(Key::rsa(2), &issuing);
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        ChainVerdict::Verified(_)
    ));
}

#[test]
fn rsa_pss_and_sha384_and_mixed_key_types_verify() {
    let root = root("Test RSA Root CA", Key::rsa(0));
    let issuing = intermediate("Test ECC under RSA", Key::p256(4), &root);
    // The intermediate is signed with RSA-PSS by the RSA root.
    let mut spec = ca_spec("Test ECC under RSA", Key::p256(4), Some(&root.key));
    spec.exts.set(SKI, false, octet(&Key::p256(4).key_id()));
    let pss_issuing = Ca {
        der: issue(&spec, &root.name, &root.key, Some(pss_sha256_alg(32))),
        name: spec.subject.clone(),
        key: Key::p256(4),
    };
    let leaf = ek(Key::p256(5), &issuing);
    for (label, ca) in [("PKCS#1", &issuing), ("PSS", &pss_issuing)] {
        assert!(
            matches!(
                verify(&leaf, &[], &anchors(&[&root], &[ca])),
                ChainVerdict::Verified(_)
            ),
            "through the {label}-signed CA"
        );
    }
    // SHA-384 with an RSA issuer.
    let mut spec = ek_spec(Key::rsa(2), &root);
    spec.exts.set(AKI, false, aki(&root.key.key_id()));
    let leaf = issue(
        &spec,
        &root.name,
        &root.key,
        Some(rsa_alg("1.2.840.113549.1.1.12")),
    );
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[])),
        ChainVerdict::Verified(_)
    ));
}

#[test]
fn a_p521_root_signing_with_sha384_verifies_but_not_with_sha256() {
    let root = root("Test P-521 Root CA", Key::p521(6));
    let issuing = intermediate("Test P-384 Leaf CA", Key::p384(7), &root);
    let leaf = ek(Key::p256(8), &issuing);
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        ChainVerdict::Verified(_)
    ));
    let spec = ca_spec("Test P-384 Leaf CA", Key::p384(7), Some(&root.key));
    let weak = Ca {
        der: issue(
            &spec,
            &root.name,
            &root.key,
            Some(ecdsa_alg("1.2.840.10045.4.3.2")),
        ),
        name: spec.subject,
        key: Key::p384(7),
    };
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&weak])),
        ChainVerdict::Unverifiable(Unverifiable::Algorithm { .. })
    ));
}

#[test]
fn an_expired_certificate_still_verifies_and_reports_its_end_date() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let issuing = intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, |spec| {
        spec.not_before = "100101000000Z";
        spec.not_after = "200101000000Z";
    });
    let leaf = ek_with(Key::p256(3), &issuing, |spec| {
        spec.not_after = "210101000000Z"
    });
    let ChainVerdict::Verified(chain) = verify(&leaf, &[], &anchors(&[&root], &[&issuing])) else {
        panic!("expired certificates still verify");
    };
    // 2021-01-01 and 2020-01-01, both in the past.
    assert_eq!(chain.path[0].not_after, 1_609_459_200);
    assert_eq!(chain.path[1].not_after, 1_577_836_800);
}

#[test]
fn the_tpm_chain_indices_supply_an_intermediate_irlume_does_not_list() {
    let (root, issuing) = ecdsa_chain();
    let leaf = ek(Key::p256(3), &issuing);
    let only_root = anchors(&[&root], &[]);
    assert!(matches!(
        verify(&leaf, &[], &only_root),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
    let ChainVerdict::Verified(chain) = verify(&leaf, &[issuing.der.as_slice()], &only_root) else {
        panic!("the intermediate from NV completes the chain");
    };
    assert_eq!(chain.path[1].source, CertificateSource::TpmChain);
}

#[test]
fn a_same_named_ca_with_another_key_is_passed_over() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let old = intermediate("Test ECC EK CA 01", Key::p256(9), &root);
    let new = intermediate("Test ECC EK CA 01", Key::p256(2), &root);
    let leaf = ek(Key::p256(3), &new);
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&old, &new])),
        ChainVerdict::Verified(_)
    ));
    // Without key identifiers the other key's failing signature only means
    // that CA did not sign it.
    let leaf = ek_with(Key::p256(3), &new, |spec| {
        spec.exts.remove(AKI);
    });
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&old, &new])),
        ChainVerdict::Verified(_)
    ));
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&old])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
}

#[test]
fn a_sha1_link_is_unverifiable_unless_another_path_verifies() {
    let root = root("Test RSA Root CA", Key::rsa(0));
    let spec = ca_spec("Test RSA EK CA 01", Key::rsa(1), Some(&root.key));
    let sha1 = Ca {
        der: issue(
            &spec,
            &root.name,
            &root.key,
            Some(rsa_alg("1.2.840.113549.1.1.5")),
        ),
        name: spec.subject.clone(),
        key: Key::rsa(1),
    };
    let leaf = ek(Key::rsa(2), &sha1);
    assert_eq!(
        verify(&leaf, &[], &anchors(&[&root], &[&sha1])),
        ChainVerdict::Unverifiable(Unverifiable::Algorithm {
            certificate: "CN=Test RSA EK CA 01".into(),
            algorithm: "sha1WithRSAEncryption".into(),
        })
    );
    // The same CA re-issued with SHA-256 gives a second path that verifies.
    let sha256 = Ca {
        der: issue(&spec, &root.name, &root.key, None),
        ..sha1.clone()
    };
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&sha1, &sha256])),
        ChainVerdict::Verified(_)
    ));
    // A SHA-1 signature on the EK certificate itself.
    let mut spec = ek_spec(Key::rsa(2), &root);
    spec.exts.set(AKI, false, aki(&root.key.key_id()));
    let leaf = issue(
        &spec,
        &root.name,
        &root.key,
        Some(rsa_alg("1.2.840.113549.1.1.5")),
    );
    assert_eq!(
        verify(&leaf, &[], &anchors(&[&root], &[])),
        ChainVerdict::Unverifiable(Unverifiable::Algorithm {
            certificate: "the EK certificate".into(),
            algorithm: "sha1WithRSAEncryption".into(),
        })
    );
}

#[test]
fn a_root_irlume_does_not_list_is_unverifiable() {
    let (root, issuing) = ecdsa_chain();
    let other = self::root("Some Other Root", Key::p384(10));
    let leaf = ek(Key::p256(3), &issuing);
    assert_eq!(
        verify(&leaf, &[], &anchors(&[&other], &[&issuing])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed {
            issuer: "CN=Test ECC Root CA".into(),
        })
    );
    // Not even the issuing CA is known.
    assert_eq!(
        verify(&leaf, &[], &anchors(&[&root], &[])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed {
            issuer: "CN=Test ECC EK CA 01".into(),
        })
    );
}

// --- chains that are refused ------------------------------------------------

#[test]
fn a_broken_signature_is_refused() {
    let (root, issuing) = ecdsa_chain();
    let mut leaf = ek(Key::p256(3), &issuing);
    // Change one byte of the model text inside the signed part.
    let at = leaf.windows(4).position(|w| w == b"ST33").unwrap();
    leaf[at] = b'X';
    assert_refused(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        Refusal::Signature {
            certificate: "the EK certificate".into(),
            issuer: "CN=Test ECC EK CA 01".into(),
        },
    );
}

#[test]
fn a_ca_without_ca_true_or_basic_constraints_is_refused() {
    let root = root("Test ECC Root CA", Key::p384(1));
    for edit in [
        (|spec: &mut Spec| {
            spec.exts.set(BC, true, bc(false, None));
        }) as fn(&mut Spec),
        |spec| {
            spec.exts.remove(BC);
        },
    ] {
        let issuing = intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, edit);
        let leaf = ek(Key::p256(3), &issuing);
        assert_refused(
            verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
            Refusal::NotACa {
                certificate: "CN=Test ECC EK CA 01".into(),
            },
        );
    }
}

#[test]
fn a_ca_without_key_cert_sign_is_refused() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let issuing = intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, |spec| {
        spec.exts.set(KU, true, ku(KeyUsages::CRLSign));
    });
    let leaf = ek(Key::p256(3), &issuing);
    assert_refused(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        Refusal::NoCertSign {
            certificate: "CN=Test ECC EK CA 01".into(),
        },
    );
}

#[test]
fn a_path_length_constraint_is_enforced() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let policy = intermediate_with("Test Policy CA", Key::p256(11), &root, |spec| {
        spec.exts.set(BC, true, bc(true, Some(0)));
    });
    let issuing = intermediate("Test ECC EK CA 01", Key::p256(2), &policy);
    let leaf = ek(Key::p256(3), &issuing);
    assert_refused(
        verify(&leaf, &[], &anchors(&[&root], &[&policy, &issuing])),
        Refusal::PathLength {
            certificate: "CN=Test ECC EK CA 01".into(),
        },
    );
    // pathlen 1 leaves room for the issuing CA.
    let policy = intermediate_with("Test Policy CA", Key::p256(11), &root, |spec| {
        spec.exts.set(BC, true, bc(true, Some(1)));
    });
    let issuing = intermediate("Test ECC EK CA 01", Key::p256(2), &policy);
    let leaf = ek(Key::p256(3), &issuing);
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&policy, &issuing])),
        ChainVerdict::Verified(_)
    ));
}

#[test]
fn an_issuing_ca_whose_extended_key_usage_excludes_ek_certificates_is_refused() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let with_eku = |ids: &'static [&'static str]| {
        intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, move |spec| {
            spec.exts.set(EKU, false, eku(ids));
        })
    };
    let server_auth = with_eku(&["1.3.6.1.5.5.7.3.1"]);
    let leaf = ek(Key::p256(3), &server_auth);
    assert_refused(
        verify(&leaf, &[], &anchors(&[&root], &[&server_auth])),
        Refusal::CaPurpose {
            certificate: "CN=Test ECC EK CA 01".into(),
        },
    );
    let allowed: [&'static [&'static str]; 3] = [
        &[EK_CERTIFICATE],
        &["2.5.29.37.0"],
        &["1.3.6.1.5.5.7.3.1", EK_CERTIFICATE],
    ];
    for ids in allowed {
        let issuing = with_eku(ids);
        let leaf = ek(Key::p256(3), &issuing);
        assert!(
            matches!(
                verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
                ChainVerdict::Verified(_)
            ),
            "{ids:?}"
        );
    }
}

#[test]
fn a_leaf_that_is_not_an_ek_certificate_is_refused() {
    let (root, issuing) = ecdsa_chain();
    let anchors = anchors(&[&root], &[&issuing]);
    let refused =
        |edit: fn(&mut Spec), key: Key| verify(&ek_with(key, &issuing, edit), &[], &anchors);

    leaf_refused(
        refused(
            |s| {
                s.exts.set(BC, true, bc(true, None));
            },
            Key::p256(3),
        ),
        LeafProblem::IsCa,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.remove(BC);
            },
            Key::p256(3),
        ),
        LeafProblem::BasicConstraints,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(BC, false, bc(false, None));
            },
            Key::p256(3),
        ),
        LeafProblem::BasicConstraints,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(KU, true, ku(KeyUsages::KeyEncipherment));
            },
            Key::p256(3),
        ),
        LeafProblem::KeyUsageWrong,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(KU, true, ku(KeyUsages::KeyAgreement));
            },
            Key::rsa(2),
        ),
        LeafProblem::KeyUsageWrong,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(KU, false, ku(KeyUsages::KeyAgreement));
            },
            Key::p256(3),
        ),
        LeafProblem::KeyUsageMissing,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.remove(KU);
            },
            Key::p256(3),
        ),
        LeafProblem::KeyUsageMissing,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(EKU, false, eku(&["1.3.6.1.5.5.7.3.2"]));
            },
            Key::p256(3),
        ),
        LeafProblem::Purpose,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.remove(SAN);
            },
            Key::p256(3),
        ),
        LeafProblem::NoAlternativeName,
    );
    leaf_refused(
        refused(
            |s| {
                let san = s.exts.0.iter().find(|e| e.0 == SAN).unwrap().2.clone();
                s.exts.set(SAN, false, san);
            },
            Key::p256(3),
        ),
        LeafProblem::AlternativeNameNotCritical,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts
                    .set(SAN, true, tpm_san(None, Some("M"), Some("id:00010002")));
            },
            Key::p256(3),
        ),
        LeafProblem::NoManufacturer,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(
                    SAN,
                    true,
                    tpm_san(Some("STM"), Some("M"), Some("id:00010002")),
                );
            },
            Key::p256(3),
        ),
        LeafProblem::NoManufacturer,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(
                    SAN,
                    true,
                    tpm_san(Some("id:494E5443"), Some("M"), Some("id:00010002")),
                );
            },
            Key::p256(3),
        ),
        LeafProblem::ManufacturerDiffers {
            certificate: 0x494E_5443,
            tpm: MFR,
        },
    );
    leaf_refused(
        refused(
            |s| {
                s.exts.set(
                    SAN,
                    true,
                    tpm_san(Some("id:53544D20"), None, Some("id:00010002")),
                );
            },
            Key::p256(3),
        ),
        LeafProblem::NoModel,
    );
    leaf_refused(
        refused(
            |s| {
                s.exts
                    .set(SAN, true, tpm_san(Some("id:53544D20"), Some("M"), None));
            },
            Key::p256(3),
        ),
        LeafProblem::NoVersion,
    );
    leaf_refused(
        refused(
            |s| {
                let name = seq(&[
                    set(&[seq(&[oid_der("2.23.133.2.1"), utf8("id:53544D20")])]),
                    set(&[seq(&[oid_der("2.23.133.2.1"), utf8("id:494E5443")])]),
                    set(&[seq(&[oid_der("2.23.133.2.2"), utf8("M")])]),
                    set(&[seq(&[oid_der("2.23.133.2.3"), utf8("id:00010002")])]),
                ]);
                s.exts.set(SAN, true, seq(&[tlv(0xa4, &name)]));
            },
            Key::p256(3),
        ),
        LeafProblem::ConflictingAttributes,
    );
    // A subject makes a non-critical alternative name fine.
    let leaf = ek_with(Key::p256(3), &issuing, |s| {
        s.subject = name("TPM 0001");
        let san = s.exts.0.iter().find(|e| e.0 == SAN).unwrap().2.clone();
        s.exts.set(SAN, false, san);
    });
    assert!(matches!(
        verify(&leaf, &[], &anchors),
        ChainVerdict::Verified(_)
    ));
    // The profile's own example: one RDN per attribute, here in a single
    // multi-valued RDN instead; both are read.
    let leaf = ek_with(Key::p256(3), &issuing, |s| {
        let name = seq(&[set(&[
            seq(&[oid_der("2.23.133.2.1"), utf8("id:53544D20")]),
            seq(&[oid_der("2.23.133.2.2"), utf8("M")]),
            seq(&[oid_der("2.23.133.2.3"), utf8("id:00010002")]),
        ])]);
        s.exts.set(SAN, true, seq(&[tlv(0xa4, &name)]));
    });
    assert!(matches!(
        verify(&leaf, &[], &anchors),
        ChainVerdict::Verified(_)
    ));
}

#[test]
fn a_profile_problem_on_an_unlisted_chain_is_unknown_not_refused() {
    let (_, issuing) = ecdsa_chain();
    let leaf = ek_with(Key::p256(3), &issuing, |s| {
        s.exts.set(BC, true, bc(true, None));
    });
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[], &[&issuing])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
}

#[test]
fn critical_extensions_irlume_does_not_process_and_constraints_are_unknown() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let unknown = intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, |spec| {
        spec.exts.set("1.3.6.1.4.1.99999.1", true, octet(b"x"));
    });
    let leaf = ek(Key::p256(3), &unknown);
    assert_eq!(
        verify(&leaf, &[], &anchors(&[&root], &[&unknown])),
        ChainVerdict::Unverifiable(Unverifiable::CriticalExtension {
            certificate: "CN=Test ECC EK CA 01".into(),
            extension: "1.3.6.1.4.1.99999.1".into(),
        })
    );
    // Not critical: ignored.
    let ignored = intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, |spec| {
        spec.exts.set("1.3.6.1.4.1.99999.1", false, octet(b"x"));
    });
    assert!(matches!(
        verify(
            &ek(Key::p256(3), &ignored),
            &[],
            &anchors(&[&root], &[&ignored])
        ),
        ChainVerdict::Verified(_)
    ));
    // Name constraints, even non-critical, are not implemented.
    let constrained = intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, |spec| {
        spec.exts.set("2.5.29.30", false, seq(&[]));
    });
    assert_eq!(
        verify(
            &ek(Key::p256(3), &constrained),
            &[],
            &anchors(&[&root], &[&constrained])
        ),
        ChainVerdict::Unverifiable(Unverifiable::Constraints {
            certificate: "CN=Test ECC EK CA 01".into(),
        })
    );
    // A critical extension on the EK certificate itself.
    let (root, issuing) = ecdsa_chain();
    let leaf = ek_with(Key::p256(3), &issuing, |s| {
        s.exts.set("2.5.29.9", true, seq(&[]));
    });
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        ChainVerdict::Unverifiable(Unverifiable::CriticalExtension { .. })
    ));
}

#[test]
fn a_critical_certificate_policies_extension_is_processed() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let issuing = intermediate_with("Test ECC EK CA 01", Key::p256(2), &root, |spec| {
        spec.exts
            .set("2.5.29.32", true, seq(&[seq(&[oid_der("1.2.3.4")])]));
    });
    assert!(matches!(
        verify(
            &ek(Key::p256(3), &issuing),
            &[],
            &anchors(&[&root], &[&issuing])
        ),
        ChainVerdict::Verified(_)
    ));
}

#[test]
fn an_unsupported_ek_key_is_unknown() {
    let (root, issuing) = ecdsa_chain();
    let spec = ek_spec(Key::p256(3), &issuing);
    let ed25519 = seq(&[seq(&[oid_der("1.3.101.112")]), bit_string(&[7; 32])]);
    let mut fields = vec![explicit(0, &int(&[2])), int(&[1])];
    fields.push(issuing.key.default_alg());
    fields.push(issuing.name.clone());
    fields.push(seq(&[utc_time(spec.not_before), utc_time(spec.not_after)]));
    fields.push(spec.subject.clone());
    fields.push(ed25519);
    fields.push(explicit(3, &spec.exts.encode()));
    let tbs = seq(&fields);
    let alg = issuing.key.default_alg();
    let leaf = seq(&[
        tbs.clone(),
        alg.clone(),
        bit_string(&issuing.key.sign(&alg, &tbs)),
    ]);
    let cert = EkCertificate::from_der(&leaf).unwrap();
    assert_eq!(cert.public_key(), None);
    assert_eq!(
        cert.verify(&[], &anchors(&[&root], &[&issuing]), MFR),
        ChainVerdict::Unverifiable(Unverifiable::LeafKey)
    );
}

#[test]
fn a_cycle_of_cross_signed_cas_ends() {
    let a_key = Key::p256(20);
    let b_key = Key::p256(21);
    let a_spec = ca_spec("Test CA A", a_key.clone(), Some(&b_key));
    let b_spec = ca_spec("Test CA B", b_key.clone(), Some(&a_key));
    let a = Ca {
        der: issue(&a_spec, &name("Test CA B"), &b_key, None),
        name: name("Test CA A"),
        key: a_key,
    };
    let b = Ca {
        der: issue(&b_spec, &name("Test CA A"), &a.key, None),
        name: name("Test CA B"),
        key: b_key,
    };
    let leaf = ek(Key::p256(3), &a);
    let root = root("Unrelated Root", Key::p384(1));
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&a, &b])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
}

#[test]
fn the_ek_public_key_is_read_from_the_certificate() {
    let (_, issuing) = ecdsa_chain();
    let key = Key::p256(3);
    let cert = EkCertificate::from_der(&ek(key.clone(), &issuing)).unwrap();
    let Key::P256(signing) = &key else {
        unreachable!()
    };
    let point = signing.verifying_key().to_sec1_point(false);
    assert_eq!(
        cert.public_key(),
        Some(&EkPublicKey::Ecc {
            curve: EccCurve::NistP256,
            x: point.as_bytes()[1..33].to_vec(),
            y: point.as_bytes()[33..].to_vec(),
        })
    );
    let Key::Rsa(rsa) = Key::rsa(2) else {
        unreachable!()
    };
    let cert = EkCertificate::from_der(&ek(Key::rsa(2), &issuing)).unwrap();
    assert_eq!(
        cert.public_key(),
        Some(&EkPublicKey::Rsa {
            modulus: rsa.n_bytes().to_vec(),
            exponent: 65537,
        })
    );
}

// --- NV contents ------------------------------------------------------------

#[test]
fn an_nv_certificate_is_read_without_its_trailing_bytes_or_header() {
    let (_, issuing) = ecdsa_chain();
    let cert = ek(Key::p256(3), &issuing);

    let mut index = cert.clone();
    index.extend_from_slice(&[0xff; 37]);
    assert_eq!(certificate_in_nv(&index), Ok(cert.as_slice()));

    let mut wrapped = vec![0x10, 0x01, 0x00];
    wrapped.extend_from_slice(&u16::try_from(cert.len()).unwrap().to_be_bytes());
    wrapped.extend_from_slice(&cert);
    wrapped.extend_from_slice(&[0x00; 11]);
    assert_eq!(certificate_in_nv(&wrapped), Ok(cert.as_slice()));
    assert!(EkCertificate::from_der(certificate_in_nv(&wrapped).unwrap()).is_ok());

    // A header that declares more than the index holds.
    let mut overrun = vec![0x10, 0x01, 0x00];
    overrun.extend_from_slice(&u16::try_from(cert.len() + 1).unwrap().to_be_bytes());
    overrun.extend_from_slice(&cert);
    assert_eq!(
        certificate_in_nv(&overrun),
        Err(NvCertificateError::HeaderOverrun {
            declared: cert.len() + 1,
            available: cert.len(),
        })
    );
    // A header shorter than the certificate it wraps.
    let mut short = vec![0x10, 0x01, 0x00];
    short.extend_from_slice(&u16::try_from(cert.len() - 1).unwrap().to_be_bytes());
    short.extend_from_slice(&cert);
    assert_eq!(certificate_in_nv(&short), Err(NvCertificateError::NotDer));

    assert_eq!(certificate_in_nv(&[]), Err(NvCertificateError::NotDer));
    assert_eq!(
        certificate_in_nv(&[0xff; 64]),
        Err(NvCertificateError::NotDer)
    );
    assert_eq!(
        certificate_in_nv(&cert[..cert.len() - 1]),
        Err(NvCertificateError::NotDer)
    );
}

#[test]
fn the_chain_indices_are_split_into_every_certificate() {
    let (root, issuing) = ecdsa_chain();
    let policy = intermediate("Test Policy CA", Key::p256(11), &root);
    // Index 1 holds the issuing CA and the start of the policy CA, index 2
    // the rest of it and padding; joined in index order.
    let mut joined = issuing.der.clone();
    joined.extend_from_slice(&policy.der);
    let split = issuing.der.len() + 40;
    let (index1, index2) = joined.split_at(split);
    let mut index2 = index2.to_vec();
    index2.extend_from_slice(&[0xff; 16]);
    let joined = [index1, &index2].concat();
    assert_eq!(
        chain_certificates(&joined),
        vec![issuing.der.as_slice(), policy.der.as_slice()]
    );
    assert!(chain_certificates(&[]).is_empty());
    assert!(chain_certificates(&[0x00; 8]).is_empty());
    // A certificate cut short ends the list.
    assert_eq!(
        chain_certificates(&joined[..joined.len() - 30]),
        vec![issuing.der.as_slice()]
    );
}

#[test]
fn a_chain_certificate_that_does_not_parse_is_skipped() {
    let (root, issuing) = ecdsa_chain();
    let leaf = ek(Key::p256(3), &issuing);
    let junk = seq(&[int(&[1])]);
    assert!(matches!(
        verify(
            &leaf,
            &[junk.as_slice(), issuing.der.as_slice()],
            &anchors(&[&root], &[])
        ),
        ChainVerdict::Verified(_)
    ));
}

// --- the shipped anchors ----------------------------------------------------

fn manifest() -> Vec<serde_json::Value> {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../tpm-ek-anchors/manifest.json")).unwrap();
    assert_eq!(manifest["format"], 1);
    manifest["certificates"].as_array().unwrap().clone()
}

#[test]
fn every_shipped_certificate_parses_and_matches_the_manifest() {
    let entries = manifest();
    assert!(entries.len() > 200, "{} certificates", entries.len());
    assert_eq!(shipped::SHIPPED.len(), entries.len());
    let anchors = Anchors::shipped();
    assert_eq!(
        anchors.root_count() + anchors.intermediate_count(),
        entries.len()
    );

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tpm-ek-anchors");
    let mut on_disk = std::collections::BTreeSet::new();
    for vendor in std::fs::read_dir(&dir).unwrap() {
        let vendor = vendor.unwrap();
        if !vendor.file_type().unwrap().is_dir() {
            continue;
        }
        for file in std::fs::read_dir(vendor.path()).unwrap() {
            let file = file.unwrap();
            on_disk.insert(format!(
                "{}/{}",
                vendor.file_name().to_str().unwrap(),
                file.file_name().to_str().unwrap()
            ));
        }
    }
    let mut listed = std::collections::BTreeSet::new();
    for (entry, anchor) in entries.iter().zip(shipped::SHIPPED) {
        let file = entry["file"].as_str().unwrap();
        listed.insert(file.to_owned());
        let bytes = std::fs::read(dir.join(file)).unwrap();
        let sha: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(entry["sha256"], sha, "{file}");
        assert_eq!(
            anchor.der,
            bytes.as_slice(),
            "shipped.rs is in manifest order: {file}"
        );
        let role = if anchor.role == AnchorRole::Root {
            "root"
        } else {
            "intermediate"
        };
        assert_eq!(entry["role"], role, "{file}");
        let parsed = Parsed::new(anchor.der).unwrap_or_else(|e| panic!("{file}: {e}"));
        // A root is self-signed; a self-issued intermediate (a key
        // rollover) is possible.
        if role == "root" {
            assert!(parsed.self_issued(), "{file}");
        }
        assert!(
            entry["url"].as_str().unwrap().starts_with("https://"),
            "{file}"
        );
    }
    assert_eq!(
        on_disk, listed,
        "the directory holds exactly the manifest's files"
    );
}

#[test]
fn every_shipped_intermediate_chains_to_a_shipped_root() {
    let anchors = Anchors::shipped();
    let pool: Vec<(&Parsed, CertificateSource)> = anchors
        .intermediates
        .iter()
        .map(|c| (c, CertificateSource::Listed))
        .chain(anchors.roots.iter().map(|c| (c, CertificateSource::Root)))
        .collect();
    for ca in &anchors.intermediates {
        let mut search = PathSearch::new(&pool, ca);
        search.extend(&mut Vec::new(), ca);
        let verified = search.paths.iter().any(|path| {
            let chain: Vec<(&Parsed, CertificateSource)> =
                std::iter::once((ca, CertificateSource::Listed))
                    .chain(path.iter().map(|&i| pool[i]))
                    .collect();
            matches!(judge_path(&chain, None), PathResult::Verified(None))
        });
        assert!(
            verified,
            "{} does not chain to a shipped root",
            name_text(ca.subject())
        );
    }
    // Every root signed itself; a root's own signature is never relied on,
    // and some older ones use SHA-1, which link_check does not accept.
    let mut checked = 0;
    for root in &anchors.roots {
        if let Ok(link) = link_check(root, root) {
            assert!(link.verify(root), "{}", name_text(root.subject()));
            checked += 1;
        }
    }
    assert!(
        checked * 2 > anchors.root_count(),
        "{checked} of {} roots",
        anchors.root_count()
    );
}

#[test]
fn issuer_names_match_across_string_types_case_and_spacing() {
    let root = root("Test ECC Root CA", Key::p384(1));
    let issuing = intermediate("Test  ECC EK CA 01", Key::p256(2), &root);
    // The EK certificate names its issuer in PrintableString, upper case and
    // with single spaces; the CA's subject is UTF8String.
    let printable = seq(&[set(&[seq(&[
        oid_der("2.5.4.3"),
        tlv(0x13, b" TEST ECC EK CA 01"),
    ])])]);
    let spec = ek_spec(Key::p256(3), &issuing);
    let leaf = issue(&spec, &printable, &issuing.key, None);
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        ChainVerdict::Verified(_)
    ));
    // A different name is still a different CA.
    let other = seq(&[set(&[seq(&[
        oid_der("2.5.4.3"),
        tlv(0x13, b"Test ECC EK CA 02"),
    ])])]);
    let leaf = issue(&spec, &other, &issuing.key, None);
    assert!(matches!(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
}

#[test]
fn a_certificate_forged_in_a_shipped_cas_name_is_refused() {
    // An emulator's EK certificate that claims ST's issuing CA, down to its
    // key identifier, but is signed with another key.
    let shipped = Anchors::shipped();
    let st = shipped
        .intermediates
        .iter()
        .find(|c| name_text(c.subject()).starts_with("CN=STM TPM EK Intermediate CA 05,"))
        .expect("ST's RSA intermediate 05 is shipped");
    let claimed = Ca {
        der: st.der.clone(),
        name: st.subject().to_der().unwrap(),
        key: Key::rsa(1),
    };
    let mut spec = ek_spec(Key::rsa(2), &claimed);
    spec.exts
        .set(AKI, false, aki(&st.subject_key_id().unwrap()));
    let forged = issue(&spec, &claimed.name, &claimed.key, None);
    assert_refused(
        EkCertificate::from_der(&forged)
            .unwrap()
            .verify(&[], shipped, MFR),
        Refusal::Signature {
            certificate: "the EK certificate".into(),
            issuer: name_text(st.subject()),
        },
    );
    // Without the key identifier it cannot be tied to that CA's key.
    spec.exts.remove(AKI);
    let forged = issue(&spec, &claimed.name, &claimed.key, None);
    assert!(matches!(
        EkCertificate::from_der(&forged)
            .unwrap()
            .verify(&[], shipped, MFR),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
}

#[test]
fn many_same_named_cas_in_the_chain_indices_end_within_the_search_budget() {
    // Forty CAs that all carry one name and issue each other, without key
    // identifiers: each is a candidate issuer for every other, and none
    // leads to a root. Without a budget the search would try about 40^6
    // paths.
    let cluster = name("Test Loop CA");
    let mut cas = Vec::new();
    for seed in 0..40u8 {
        let key = Key::p256(100 + seed);
        let mut spec = ca_spec("Test Loop CA", key.clone(), None);
        spec.exts.remove(SKI);
        let signer = Key::p256(100 + (seed + 1) % 40);
        cas.push(issue(&spec, &cluster, &signer, None));
    }
    let loop_ca = Ca {
        der: cas[0].clone(),
        name: cluster.clone(),
        key: Key::p256(100),
    };
    let leaf = ek_with(Key::p256(3), &loop_ca, |spec| {
        spec.exts.remove(AKI);
    });
    let chain: Vec<&[u8]> = cas.iter().map(Vec::as_slice).collect();
    let root = root("Test ECC Root CA", Key::p384(1));
    let started = std::time::Instant::now();
    assert!(matches!(
        verify(&leaf, &chain, &anchors(&[&root], &[])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
}

#[test]
fn forged_chain_index_certificates_neither_hide_nor_refuse_a_genuine_path() {
    let (root, issuing) = ecdsa_chain();
    let leaf = ek(Key::p256(3), &issuing);
    // Forty forged CAs in the chain indices, each named like the EK
    // certificate's issuer and claiming the listed root, more than the
    // path budget holds.
    let forged: Vec<Vec<u8>> = (0..40u8)
        .map(|seed| {
            let key = Key::p256(150 + seed);
            let mut spec = ca_spec("Test ECC EK CA 01", key, Some(&root.key));
            // No key identifier of its own: a candidate by name alone.
            spec.exts.remove(SKI);
            // Signed by another key, so the forged link fails.
            issue(&spec, &root.name, &Key::p384(seed + 50), None)
        })
        .collect();
    let chain: Vec<&[u8]> = forged.iter().map(Vec::as_slice).collect();
    assert!(matches!(
        verify(&leaf, &chain, &anchors(&[&root], &[&issuing])),
        ChainVerdict::Verified(_)
    ));
    // With the genuine CA not listed, a forged chain index certificate that
    // even carries the right key identifiers makes the path unknown, not
    // refused.
    let mut spec = ca_spec("Test ECC EK CA 01", Key::p256(9), Some(&root.key));
    spec.exts.set(SKI, false, octet(&issuing.key.key_id()));
    let impostor = issue(&spec, &root.name, &root.key, None);
    assert!(matches!(
        verify(&leaf, &[impostor.as_slice()], &anchors(&[&root], &[])),
        ChainVerdict::Unverifiable(Unverifiable::IssuerNotListed { .. })
    ));
}

#[test]
fn a_critical_extended_key_usage_on_the_ek_certificate_is_refused() {
    let (root, issuing) = ecdsa_chain();
    let leaf = ek_with(Key::p256(3), &issuing, |s| {
        s.exts.set(EKU, true, eku(&[EK_CERTIFICATE]));
    });
    leaf_refused(
        verify(&leaf, &[], &anchors(&[&root], &[&issuing])),
        LeafProblem::PurposeCritical,
    );
}

#[test]
fn chain_index_paths_under_one_listed_ca_do_not_hide_a_second_listed_ca() {
    // Two listed CAs share the EK certificate's issuer name; the EK
    // certificate has no authority key identifier, so both are candidates,
    // and the first is not its issuer. Forty chain-index certificates
    // carrying the root's name reach the root by name below the first CA,
    // more paths than the budget holds.
    let root = root("Test ECC Root CA", Key::p384(1));
    let wrong = intermediate("Test ECC EK CA 01", Key::p256(9), &root);
    let right = intermediate("Test ECC EK CA 01", Key::p256(2), &root);
    let leaf = ek_with(Key::p256(3), &right, |spec| {
        spec.exts.remove(AKI);
    });
    let forged: Vec<Vec<u8>> = (0..40u8)
        .map(|seed| {
            let mut spec = ca_spec("Test ECC Root CA", Key::p256(150 + seed), None);
            spec.exts.remove(SKI);
            issue(&spec, &root.name, &Key::p384(seed + 50), None)
        })
        .collect();
    let chain: Vec<&[u8]> = forged.iter().map(Vec::as_slice).collect();
    assert!(matches!(
        verify(&leaf, &chain, &anchors(&[&root], &[&wrong, &right])),
        ChainVerdict::Verified(_)
    ));
}

#[test]
fn rsa_encryption_parameters_other_than_null_make_the_key_unreadable() {
    let root = root("Test RSA Root CA", Key::rsa(0));
    let Key::Rsa(rsa) = Key::rsa(2) else {
        unreachable!()
    };
    let rsa_key = bit_string(&seq(&[int(&rsa.n_bytes()), int(&rsa.e_bytes())]));
    let leaf_with = |algorithm: Vec<u8>| {
        let spec = ek_spec(Key::rsa(2), &root);
        let mut fields = vec![explicit(0, &int(&[2])), int(&[1])];
        fields.push(root.key.default_alg());
        fields.push(root.name.clone());
        fields.push(seq(&[utc_time(spec.not_before), utc_time(spec.not_after)]));
        fields.push(spec.subject.clone());
        fields.push(seq(&[algorithm, rsa_key.clone()]));
        fields.push(explicit(3, &spec.exts.encode()));
        let tbs = seq(&fields);
        let alg = root.key.default_alg();
        seq(&[
            tbs.clone(),
            alg.clone(),
            bit_string(&root.key.sign(&alg, &tbs)),
        ])
    };
    let anchors = anchors(&[&root], &[]);
    // NULL, and absent, are both read.
    for algorithm in [
        seq(&[oid_der("1.2.840.113549.1.1.1"), null()]),
        seq(&[oid_der("1.2.840.113549.1.1.1")]),
    ] {
        assert!(matches!(
            verify(&leaf_with(algorithm), &[], &anchors),
            ChainVerdict::Verified(_)
        ));
    }
    let odd = leaf_with(seq(&[oid_der("1.2.840.113549.1.1.1"), int(&[0])]));
    assert_eq!(EkCertificate::from_der(&odd).unwrap().public_key(), None);
    assert_eq!(
        verify(&odd, &[], &anchors),
        ChainVerdict::Unverifiable(Unverifiable::LeafKey)
    );
}

#[test]
fn an_ek_key_outside_the_accepted_sizes_or_off_its_curve_is_unknown() {
    let (root, issuing) = ecdsa_chain();
    let anchors = anchors(&[&root], &[&issuing]);
    let leaf_with_key = |spki: Vec<u8>| {
        let spec = ek_spec(Key::p256(3), &issuing);
        let mut fields = vec![explicit(0, &int(&[2])), int(&[1])];
        fields.push(issuing.key.default_alg());
        fields.push(issuing.name.clone());
        fields.push(seq(&[utc_time(spec.not_before), utc_time(spec.not_after)]));
        fields.push(spec.subject.clone());
        fields.push(spki);
        fields.push(explicit(3, &spec.exts.encode()));
        let tbs = seq(&fields);
        let alg = issuing.key.default_alg();
        seq(&[
            tbs.clone(),
            alg.clone(),
            bit_string(&issuing.key.sign(&alg, &tbs)),
        ])
    };
    // A 1024-bit RSA modulus (odd, top bit set).
    let mut modulus = vec![0xc3; 128];
    modulus[127] = 0x01;
    let rsa1024 = seq(&[
        seq(&[oid_der("1.2.840.113549.1.1.1"), null()]),
        bit_string(&seq(&[int(&modulus), int(&[0x01, 0x00, 0x01])])),
    ]);
    // A P-256 point that is not on the curve.
    let mut point = vec![0x04];
    point.extend_from_slice(&[0x11; 64]);
    let off_curve = seq(&[
        seq(&[oid_der("1.2.840.10045.2.1"), oid_der("1.2.840.10045.3.1.7")]),
        bit_string(&point),
    ]);
    for spki in [rsa1024, off_curve] {
        let leaf = leaf_with_key(spki);
        assert_eq!(EkCertificate::from_der(&leaf).unwrap().public_key(), None);
        assert_eq!(
            verify(&leaf, &[], &anchors),
            ChainVerdict::Unverifiable(Unverifiable::LeafKey)
        );
    }
}

#[test]
fn a_self_issued_key_rollover_ca_chains_to_the_old_root() {
    // The vendor rolls its root to a new key under the same name and links
    // the new key to the old root with a self-issued certificate signed by
    // the old key.
    let old_root = root("Test ECC Root CA", Key::p384(1));
    let new_key = Key::p384(30);
    let spec = ca_spec("Test ECC Root CA", new_key.clone(), Some(&old_root.key));
    let rollover = Ca {
        der: issue(&spec, &old_root.name, &old_root.key, None),
        name: spec.subject.clone(),
        key: new_key,
    };
    let issuing = intermediate("Test ECC EK CA 02", Key::p256(31), &rollover);
    let leaf = ek(Key::p256(3), &issuing);
    let ChainVerdict::Verified(chain) =
        verify(&leaf, &[], &anchors(&[&old_root], &[&rollover, &issuing]))
    else {
        panic!("the rollover certificate links the new key to the old root");
    };
    assert_eq!(chain.path.len(), 4);
    assert!(Parsed::new(&rollover.der).unwrap().self_issued());
}

#[test]
fn names_that_differ_only_by_unicode_case_folding_match() {
    let fold = |text: &str| canonical_name(&Name::from_der(&name(text)).unwrap());
    assert_eq!(fold("Straße CA"), fold("STRASSE ca"));
    assert_eq!(fold("ΣΟΦΟΣ CA"), fold("σοφος CA"));
    assert_ne!(fold("Test CA 01"), fold("Test CA 02"));
}

#[test]
fn pss_with_mgf1_hash_parameters_other_than_null_is_not_accepted() {
    let sha256 = seq(&[oid_der("2.16.840.1.101.3.4.2.1"), null()]);
    let odd_sha256 = seq(&[oid_der("2.16.840.1.101.3.4.2.1"), int(&[1])]);
    let pss = |mgf_hash: &[u8]| {
        seq(&[
            oid_der("1.2.840.113549.1.1.10"),
            seq(&[
                explicit(0, &sha256),
                explicit(
                    1,
                    &seq(&[oid_der("1.2.840.113549.1.1.8"), mgf_hash.to_vec()]),
                ),
                explicit(2, &int(&[32])),
            ]),
        ])
    };
    let read = |der: Vec<u8>| scheme(&AlgorithmIdentifierOwned::from_der(&der).unwrap());
    assert_eq!(read(pss(&sha256)), Ok(Scheme::RsaPss(HashAlg::Sha256, 32)));
    assert!(read(pss(&odd_sha256)).is_err());
}
